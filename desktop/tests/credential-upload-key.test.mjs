// Actual frontend controller/bridge with bounded synthetic DATA and promises.
// No private vault, native startup, tool, key, filesystem, account or network.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { NEW_UPLOAD_KEY_DECLARATION, parseUploadKeyStatus, uploadKeyRequestFits } from '../src/credentialUploadKey.ts';
import { createNativeApi } from '../src/bridge.ts';

const context = { revision: 1, projectId: 'inert-project', platform: 'android', stage: 'candidate', purpose: 'signing' };
const available = { available: true, reason: 'none' };
const unavailable = { available: false, reason: 'unqualified' };
const reference = { vaultId: '1'.repeat(32), generationId: '2'.repeat(32), recordId: '3'.repeat(32), revisionId: '4'.repeat(32), revisionCounter: 1 };
const createRequest = () => ({ contextRevision: 1, expectedStatusRevision: 2, declaration: NEW_UPLOAD_KEY_DECLARATION });
function record(patch = {}) {
  return { recordId: reference.recordId, revision: 1, kind: 'android-keystore', availability: 'unassigned', storage: 'encrypted', label: null, payloadState: 'not-checked', ...patch };
}
function assets(revision = 1, patch = {}) {
  return { schemaVersion: 3, statusRevision: revision, mode: 'encrypted',
    persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { ...available },
    modes: { session: { ...available }, encrypted: { ...available } }, context: { ...context },
    operation: null, records: [], assignments: [], ...patch };
}
function operation(patch = {}) {
  return { operationId: 7, operation: 'generate-upload-key', phase: 'admitting', reason: 'none', source: 'not-run', settlement: 'pending',
    storageOutcome: null, selectionToken: null, assessment: null, preview: null, ...patch };
}
function status(revision = 1, patch = {}) {
  return { schemaVersion: 1, assets: assets(revision), capability: { ...available }, setup: 'required', plan: 'unavailable', operation: null, saved: null, ...patch };
}
function running(revision = 3, patch = {}) {
  return status(revision, { assets: assets(revision, { operation: operation() }), setup: 'attempted', plan: 'recovery-required',
    operation: { operationId: 7, phase: 'generating', reason: 'none' }, ...patch });
}
function saved(revision = 4, patch = {}) {
  return running(revision, { assets: assets(revision, { operation: operation({ phase: 'idle', settlement: 'known',
    storageOutcome: { effect: 'known-applied', durability: 'confirmed', cleanup: 'known' } }), records: [record()] }),
    operation: { operationId: 7, phase: 'saved', reason: 'none' }, saved: { ...reference }, ...patch });
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 16; i += 1) await Promise.resolve(); }
function harness(t, otherOperationReason = () => null) {
  let project = { project: { id: context.projectId, name: 'Inert project' }, draft: { schemaVersion: 1 }, revision: 1, baselineGeneration: 1 };
  let current = assets(0), event;
  const calls = [];
  const pending = (command, args) => { const work = deferred(); calls.push({ command, args, ...work }); return work.promise; };
  const api = { mode: 'native', subscribeAssets: async (listener) => { event = listener; return () => {}; },
    assetStatus: async () => structuredClone(current), setAssetContext: (args) => pending('context', args),
    uploadKeyStatus: (args) => pending('status', args), prepareUploadKey: (args) => pending('setup', args), createUploadKey: (args) => pending('create', args),
    prepareCredential: (args) => pending('assess', args), commitAsset: (args) => pending('commit', args), bindAsset: (args) => pending('bind', args),
    exportCredentialBackup: (args) => pending('backup', args), discardAsset: (args) => pending('discard', args),
  };
  const controller = new AssetSessionController(() => project, () => 100, otherOperationReason);
  controller.setScope({ platform: 'android', stage: 'candidate', purpose: 'signing' });
  t.after(() => controller.dispose());
  return { api, controller, calls, last: (command) => calls.filter((call) => call.command === command).at(-1),
    emit: (value) => { current = structuredClone(value); event(value); },
    reply: (command, value) => { current = structuredClone(value.assets ?? value); calls.filter((call) => call.command === command).at(-1).resolve(value); },
    changeProject: () => { project = { ...project, revision: project.revision + 1 }; },
  };
}
async function ready(h) {
  await h.controller.connect(h.api); h.controller.submitContext(); await settle();
  h.reply('context', assets()); await settle(); assert.equal(h.controller.getSnapshot().contextCurrent, true);
}
async function checked(h, value = status()) {
  const original = h.controller.checkUploadKeyStatus(); await settle(); h.reply('status', value); await original;
}
async function prepared(h, plan = 'confirm-application-history') {
  await ready(h); await checked(h);
  assert.equal(h.controller.prepareUploadKey(h.controller.getSnapshot()), true);
  h.reply('setup', status(2, { setup: 'ready', plan })); await settle();
}
function create(h) {
  assert.equal(h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true), true);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), true);
}
function noAutomaticWork(h) {
  assert.equal(h.calls.filter((call) => ['assess', 'commit', 'bind', 'backup'].includes(call.command)).length, 0);
}

test('closed requests accept only context, current revision and the explicit fixed declaration', () => {
  assert.equal(uploadKeyRequestFits('upload_key_create', createRequest()), true);
  for (const command of ['upload_key_status', 'upload_key_prepare']) {
    assert.equal(uploadKeyRequestFits(command, { contextRevision: 1 }), true);
    assert.equal(uploadKeyRequestFits(command, createRequest()), false);
  }
  for (const extra of ['path', 'password', 'fields', 'tool', 'applicationId', 'recordId', 'replace', 'confirmed'])
    assert.equal(uploadKeyRequestFits('upload_key_create', { ...createRequest(), [extra]: 'inert-refused' }), false);
  for (const bad of [0, -1, 1.5, '2', null, 0xffff_ffff]) {
    assert.equal(uploadKeyRequestFits('upload_key_create', { ...createRequest(), expectedStatusRevision: bad }), false);
    assert.equal(uploadKeyRequestFits('upload_key_prepare', { contextRevision: bad }), false);
  }
  for (const bad of [true, false, '', 'existing-app', null])
    assert.equal(uploadKeyRequestFits('upload_key_create', { ...createRequest(), declaration: bad }), false);
  let read = false;
  assert.equal(uploadKeyRequestFits('upload_key_prepare', { get contextRevision() { read = true; return 1; } }), false);
  assert.equal(read, false);
});

test('saved DTO requires the full distinct reference, current stored row and explicit original publication', () => {
  assert.deepEqual(parseUploadKeyStatus(saved()), saved());
  for (const change of [
    (s) => { s.saved.revisionId = s.saved.recordId; }, (s) => { s.saved.generationId = s.saved.vaultId; },
    (s) => { s.saved.revisionCounter = 0; }, (s) => { s.saved.revisionCounter = 2; }, (s) => { s.saved.password = 'inert-refused'; },
    (s) => { s.saved = null; }, (s) => { s.operation.phase = 'generating'; }, (s) => { s.operation.operationId = 9; },
    (s) => { s.assets.operation.operation = 'commit'; }, (s) => { s.assets.operation.settlement = 'unknown'; },
    (s) => { s.assets.operation.storageOutcome.durability = 'unknown'; }, (s) => { s.assets.operation.storageOutcome = null; },
    (s) => { s.assets.operation.reason = 'user-cancelled'; }, (s) => { s.assets.records[0].availability = 'mutation-pending'; },
    (s) => { s.capability = { ...unavailable }; }, (s) => { s.assets.context.platform = 'ios'; },
  ]) {
    const value = saved(); change(value); assert.throws(() => parseUploadKeyStatus(value));
  }
  const justIdle = saved(); justIdle.operation.phase = 'finishing'; justIdle.saved = null;
  assert.equal(parseUploadKeyStatus(justIdle).saved, null);
  assert.equal(parseAssetStatus({ ...running().assets, mode: 'session', persistence: null }), null);
});

test('bridge uses exactly three fixed native commands and refuses extra/private arguments before invoke', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return status(); });
  const input = createRequest();
  await api.uploadKeyStatus({ contextRevision: 1 }); await api.prepareUploadKey({ contextRevision: 1 }); await api.createUploadKey(input);
  input.expectedStatusRevision = 99;
  assert.deepEqual(calls, [
    { command: 'upload_key_status', args: { contextRevision: 1 } }, { command: 'upload_key_prepare', args: { contextRevision: 1 } },
    { command: 'upload_key_create', args: createRequest() },
  ]);
  await assert.rejects(api.createUploadKey({ ...createRequest(), password: 'inert-refused' }));
  await assert.rejects(api.prepareUploadKey({ contextRevision: 1, root: 'inert-refused' }));
  assert.equal(calls.length, 3);
});

test('connect and status never initialize native state or generate; old optional APIs stay unavailable', async (t) => {
  const h = harness(t); await ready(h); await checked(h);
  assert.deepEqual(h.calls.map((call) => call.command), ['context', 'status']);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  noAutomaticWork(h);
  const old = harness(t); delete old.api.uploadKeyStatus; delete old.api.prepareUploadKey; delete old.api.createUploadKey;
  await ready(old); await old.controller.checkUploadKeyStatus();
  assert.equal(old.controller.prepareUploadKey(old.controller.getSnapshot()), false);
  assert.match(old.controller.uploadKeySnapshot().error, /unavailable/u);
  assert.deepEqual(old.calls.map((call) => call.command), ['context']);
});

test('writable vault qualification alone never enables new generation', async (t) => {
  const h = harness(t); await ready(h); await checked(h, status(1, { capability: { ...unavailable } }));
  assert.equal(h.controller.prepareUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true), false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.calls.some((call) => ['setup', 'create'].includes(call.command)), false);
});

test('explicit setup is single-flight, never checks the declaration or creates a key automatically', async (t) => {
  const h = harness(t); await ready(h); await checked(h);
  const original = h.controller.getSnapshot();
  assert.equal(h.controller.prepareUploadKey(original), true);
  assert.equal(h.controller.prepareUploadKey(original), false);
  assert.equal(h.controller.getSnapshot().originPending, true);
  assert.equal(h.controller.discard(), false);
  h.reply('setup', status(2, { setup: 'ready', plan: 'confirm-application-history' })); await settle();
  assert.equal(h.controller.canConfirmUploadKey(h.controller.getSnapshot()), true);
  assert.equal(h.controller.uploadKeySnapshot().confirmed, false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.calls.filter((call) => call.command === 'setup').length, 1); noAutomaticWork(h);
});

test('reuse, required existing key, conflict and interrupted plans cannot be overridden by checking a box', async (t) => {
  for (const plan of ['reuse-ready', 'assessment-needed', 'select-existing', 'existing-key-required', 'conflict', 'recovery-required']) {
    const h = harness(t); await prepared(h, plan);
    assert.equal(h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true), false);
    assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
    assert.equal(h.calls.some((call) => call.command === 'create'), false); noAutomaticWork(h);
  }
});

test('declaration is bound to the current status revision and a stale rendered view cannot create', async (t) => {
  const h = harness(t); await prepared(h);
  assert.equal(Object.isFrozen(h.controller.uploadKeySnapshot().status.assets.context), true);
  assert.throws(() => { h.controller.uploadKeySnapshot().status.assets.statusRevision = 900; });
  h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true);
  const checkedView = h.controller.getSnapshot(); h.emit(assets(3));
  assert.equal(h.controller.uploadKeySnapshot().confirmed, false);
  assert.equal(h.controller.createNewUploadKey(checkedView), false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.calls.some((call) => call.command === 'create'), false);
});

test('create is spent before invoke; double click and cancellation of a previous step are refused', async (t) => {
  const h = harness(t); await prepared(h); create(h);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.controller.discard(), false);
  assert.deepEqual(h.last('create').args, createRequest());
  assert.equal(h.calls.filter((call) => call.command === 'create').length, 1);
  h.reply('create', running()); await settle();
  assert.equal(h.controller.discard(), true);
  assert.equal(h.last('discard').args, 7);
  h.reply('discard', running(4, { assets: assets(4, { operation: operation({ phase: 'stopping', reason: 'user-cancelled' }) }) }).assets);
  await settle(); noAutomaticWork(h);
});

test('unsynchronized project change and another original operation veto create before invoke', async (t) => {
  const h = harness(t); await prepared(h); h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true);
  const before = h.controller.getSnapshot(); h.changeProject();
  assert.equal(h.controller.createNewUploadKey(before), false);
  assert.equal(h.calls.some((call) => call.command === 'create'), false);
  await settle(); if (h.last('context') !== h.calls[0]) { h.reply('context', assets(3, { context: { ...context, revision: 2 } })); await settle(); }
  let busy = null; const other = harness(t, () => busy); await prepared(other);
  other.controller.confirmNewUploadKey(other.controller.getSnapshot(), true); busy = 'Another original owns this project.';
  assert.equal(other.controller.createNewUploadKey(other.controller.getSnapshot()), false);
  assert.equal(other.calls.some((call) => call.command === 'create'), false);
});

test('reentrant project retirement, scope ABA and disposal between busy publication and invoke send nothing', async (t) => {
  for (const action of ['setup', 'create']) for (const retire of ['project', 'scope-aba', 'dispose']) {
    const h = harness(t);
    if (action === 'setup') { await ready(h); await checked(h); }
    else { await prepared(h); h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true); }
    const before = h.calls.filter((call) => call.command === action).length;
    let fired = false;
    const unsubscribe = h.controller.subscribe(() => {
      if (fired || h.controller.getSnapshot().busy !== (action === 'setup' ? 'prepare-upload-key' : 'generate-upload-key')) return;
      fired = true;
      if (retire === 'project') h.changeProject(); // No sync hook to rescue the handoff.
      else if (retire === 'scope-aba') {
        h.controller.setScope({ platform: 'ios', stage: 'candidate', purpose: 'signing' });
        h.controller.setScope({ platform: 'android', stage: 'candidate', purpose: 'signing' });
      } else h.controller.dispose();
    });
    const view = h.controller.getSnapshot();
    assert.equal(action === 'setup' ? h.controller.prepareUploadKey(view) : h.controller.createNewUploadKey(view), true);
    unsubscribe(); await settle(); assert.equal(fired, true);
    assert.equal(h.calls.filter((call) => call.command === action).length, before);
    assert.equal(h.controller.uploadKeySnapshot().uncertain, true);
    noAutomaticWork(h);
    h.controller.dispose();
    // Join any inert context promise queued by the ABA subscriber, not a
    // setup/create call. Disposed original ownership prevents further work.
    for (const call of h.calls.filter((call) => call.command === 'context')) call.resolve(assets(9));
    await settle();
  }
});

test('reentrant peer admission or native status replacement vetoes upload-only dispatch', async (t) => {
  for (const action of ['setup', 'create']) for (const retire of ['peer', 'status']) {
    let peer = null;
    const h = harness(t, () => peer);
    if (action === 'setup') { await ready(h); await checked(h); }
    else { await prepared(h); h.controller.confirmNewUploadKey(h.controller.getSnapshot(), true); }
    const before = h.calls.filter((call) => call.command === action).length;
    let fired = false;
    const unsubscribe = h.controller.subscribe(() => {
      if (fired || h.controller.getSnapshot().busy !== (action === 'setup' ? 'prepare-upload-key' : 'generate-upload-key')) return;
      fired = true;
      if (retire === 'peer') peer = 'Another original now owns this project.';
      else h.emit(assets(8));
    });
    const view = h.controller.getSnapshot();
    assert.equal(action === 'setup' ? h.controller.prepareUploadKey(view) : h.controller.createNewUploadKey(view), true);
    unsubscribe(); await settle(); assert.equal(fired, true);
    assert.equal(h.calls.filter((call) => call.command === action).length, before);
    assert.equal(h.controller.uploadKeySnapshot().uncertain, true);
    noAutomaticWork(h);
  }
});

test('lost create acknowledgement stays uncertain after completed-looking status and never re-arms', async (t) => {
  const h = harness(t); await prepared(h); create(h);
  h.last('create').reject({ code: 'native-unavailable', message: 'inert raw error must not be retained' }); await settle();
  await h.controller.checkStatus(); await checked(h, saved(4));
  assert.equal(h.controller.uploadKeySnapshot().uncertain, true);
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.controller.prepareUploadKey(h.controller.getSnapshot()), false);
  assert.doesNotMatch(h.controller.uploadKeySnapshot().error ?? '', /inert raw/u);
  assert.equal(h.calls.filter((call) => call.command === 'create').length, 1);
});

test('overtaking status cannot replace own acknowledgement; a delayed own reply pins only the same original', async (t) => {
  const h = harness(t); await prepared(h); create(h);
  h.emit(saved(4).assets); await checked(h, saved(4));
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  h.reply('create', running(3)); await settle();
  assert.equal(h.controller.getSnapshot().status.statusRevision, 4);
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), true);
  noAutomaticWork(h);
});

test('producer return, Idle, storage success and a row count without native saved proof are never completion', async (t) => {
  const h = harness(t); await prepared(h); create(h);
  const notPublished = saved(3, { operation: { operationId: 7, phase: 'finishing', reason: 'none' }, saved: null });
  h.reply('create', notPublished); await settle();
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  noAutomaticWork(h);
});

test('healthy retirement pending is not failure and only later genuine saved projection can complete', async (t) => {
  const h = harness(t); await prepared(h); create(h); h.reply('create', running()); await settle();
  const pending = running(4, {
    assets: assets(4, { operation: operation({ phase: 'stopping', settlement: 'pending', reason: 'none' }) }),
    operation: { operationId: 7, phase: 'finishing', reason: 'none' },
  });
  await checked(h, pending);
  assert.equal(h.controller.uploadKeySnapshot().uncertain, false);
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  await checked(h, saved(5));
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), true);
  assert.equal(h.calls.filter((call) => call.command === 'create').length, 1);
  noAutomaticWork(h);
});

test('unknown original settlement is absorbing even after a later known-looking result', async (t) => {
  const h = harness(t); await prepared(h); create(h);
  const unknown = running(3, { assets: assets(3, { operation: operation({ phase: 'unknown', settlement: 'unknown', reason: 'cleanup-unknown' }) }),
    operation: { operationId: 7, phase: 'recovery-required', reason: 'cleanup-unknown' } });
  h.reply('create', unknown); await settle(); await checked(h, saved(4));
  assert.equal(h.controller.getSnapshot().blocked, true);
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
  assert.equal(h.calls.filter((call) => call.command === 'create').length, 1);
});

test('saved item remains new/unassigned and navigation does not assign, back up, regenerate or cancel', async (t) => {
  const h = harness(t); await prepared(h); create(h); h.reply('create', saved(3)); await settle();
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), true);
  assert.deepEqual(h.controller.getSnapshot().status.assignments, []);
  assert.equal(h.controller.getSnapshot().status.records[0].availability, 'unassigned');
  assert.equal(h.controller.getSnapshot().reviewReady, false); noAutomaticWork(h);
  const before = h.controller.getSnapshot(); h.changeProject();
  assert.equal(h.controller.uploadKeySaved(before), false);
  const calls = h.calls.length; h.controller.dispose();
  assert.equal(h.controller.createNewUploadKey(before), false); assert.equal(h.calls.length, calls);
});

test('foreign operation and changed stored revision retire completion instead of adopting another result', async (t) => {
  const h = harness(t); await prepared(h); create(h); h.reply('create', saved(3)); await settle();
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), true);
  h.emit(assets(4, { operation: saved().assets.operation, records: [record({ revision: 2 })] }));
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  const foreign = saved(5); foreign.operation.operationId = 8; foreign.assets.operation.operationId = 8;
  await checked(h, foreign);
  assert.equal(h.controller.uploadKeySaved(h.controller.getSnapshot()), false);
  assert.equal(h.controller.uploadKeySnapshot().uncertain, true);
  assert.equal(h.controller.createNewUploadKey(h.controller.getSnapshot()), false);
});
