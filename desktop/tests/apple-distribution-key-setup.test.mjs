// Complete controller/parser modules with inert promises and comparison DATA.
// No native owner, private key, certificate, provider, file or vault is used.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { createAppleProvisioningApi } from '../src/appleProvisioningNative.ts';
import { APPLE_PROVISIONING_EVENT, appleProvisioningContext, appleProvisioningConsent, appleProvisioningProgress,
  parseAppleProvisioningRequest, parseAppleProvisioningStatus, encodeAppleProvisioningRequest } from '../src/appleProvisioningProtocol.ts';
import { appleDistributionKeyInputBase, retainedAppleDistributionKeyInput, parseAppleDistributionKeyResult,
  parseAppleDistributionKeySavedReference, appleDistributionKeyResultCopy } from '../src/appleDistributionKeySetupProtocol.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';

const clone = value => structuredClone(value);
const id = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'f'.repeat(32) });
const saved = () => ({ vaultId: '1'.repeat(32), generationId: '2'.repeat(32), recordId: '3'.repeat(32), revisionId: '4'.repeat(32), revisionCounter: 1 });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const project = () => ({ projectId: '_fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
  dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null });
function assets(p12 = false) {
  const scope = { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'provisioning' };
  const kinds = p12 ? ['asc-p8', 'apple-p12'] : ['asc-p8'];
  return { mode: 'native', scope, contextCurrent: true, busy: null, updatingContext: false, observationFailed: false,
    blocked: false, originPending: false, entryGeneration: 1,
    status: { schemaVersion: 3, statusRevision: 1, mode: 'encrypted',
      persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { available: true, reason: 'none' },
      modes: { encrypted: { available: true, reason: 'none' }, session: { available: true, reason: 'none' } }, operation: null,
      context: { revision: 3, projectId: '_fixture', ...scope },
      assignments: kinds.map((kind, i) => ({ kind, recordId: (i ? 'd' : 'c').repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' })),
      records: kinds.map((kind, i) => ({ kind, recordId: (i ? 'd' : 'c').repeat(32), revision: 4,
        availability: 'assigned', storage: 'encrypted', label: null, payloadState: 'assessed' })) } };
}
const request = (mode = 'key-review') => ({ ...appleDistributionKeyInputBase(project(), assets()), mode,
  reference: mode === 'key-review' ? null : id('1'), newApplication: false, displayName: 'Existing App' });
const status = (revision = 1, operation = null, availability = operation && operation.phase !== 'terminal' ? 'busy' : 'available') =>
  ({ schemaVersion: 1, statusRevision: revision, availability, operation });
const operation = (input, digit = '1') => ({ ...id(digit), context: appleProvisioningContext(clone(input)), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const result = (mode = 'key-review', decision = mode === 'key-review' ? 'prepare-review' : 'produced',
  reason = mode === 'key-review' ? 'local-key-required' : 'producer-returned') => ({ schemaVersion: 1, scope: 'local-ios-distribution-key',
  mode, decision, reason, saved: false, certificateRequested: false, credentialReady: false });
const complete = (op, value = result(op.context.mode)) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result: value });
const cancelled = op => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null });
const unknown = op => ({ ...clone(op), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null });
function mutation(value = assets()) {
  const a = clone(value); a.contextCurrent = false; a.status.persistence.state = 'mutating';
  a.status.operation = { operationId: 5, operation: 'prepare-apple-distribution-key', phase: 'mutating', reason: 'none', source: 'captured',
    settlement: 'pending', storageOutcome: { effect: 'not-started', durability: 'not-run', cleanup: 'pending' }, selectionToken: null, assessment: null, preview: null };
  for (const row of a.status.assignments) row.availability = 'unavailable';
  return a;
}
function harness(t, withP12 = false) {
  let p = project(), a = assets(withP12), native = status(), now = 100, peer = null;
  const calls = [], readQueue = [], listeners = [];
  const call = (kind, value) => { const row = { kind, request: clone(value), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native', subscribe: async receive => { const row = { receive, closed: false }; listeners.push(row); return () => { row.closed = true; }; },
    status: () => readQueue.shift()?.promise ?? Promise.resolve(clone(native)),
    prepare: value => call('prepare', value), start: value => call('start', value), cancel: value => call('cancel', value) };
  const controller = new AppleProvisioningController({ project: () => p, assets: () => a, otherOperationReason: () => peer, now: () => now });
  controller.setVisible(true); controller.setDisplayName('Existing App');
  const ready = controller.connect(api); t.after(() => controller.dispose());
  return { controller, api, ready, calls, readQueue,
    get state() { return controller.getSnapshot(); }, get assets() { return clone(a); }, get project() { return clone(p); },
    reply(row, value) { native = clone(value); row.resolve(clone(value)); },
    emit(value) { native = clone(value); for (const row of listeners) if (!row.closed) row.receive(clone(value)); },
    replaceAssets(value, notify = true) { a = value; if (notify) controller.syncProject(); },
    replaceProject(value, notify = true) { p = value; if (notify) controller.syncProject(); },
    peer(value) { peer = value; }, time(value) { now = value; } };
}
async function prepared(h, mode = 'key-review', digit = '1', revision = 2) {
  await h.ready; const work = h.controller.prepare(mode), call = h.calls.at(-1);
  assert.equal(call?.kind, 'prepare'); const op = operation(call.request, digit);
  h.reply(call, status(revision, op)); await work;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function reviewed(h) {
  const op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration);
  h.reply(h.calls.at(-1), status(3, complete(op))); await work;
  assert.deepEqual(h.state.keyReviewReference, id('1')); return op;
}
async function cancelPrepared(h, op, revision) {
  const work = h.controller.cancel(); const call = h.calls.at(-1); assert.equal(call?.kind, 'cancel');
  h.reply(call, status(revision, cancelled(op))); await work;
}

test('only two local-key modes use the original RAW4, with exact P8-only requests and distinct consents', async () => {
  const calls = [], events = [];
  const api = createAppleProvisioningApi('native', async (command, bytes) => { calls.push([command, JSON.parse(new TextDecoder().decode(bytes))]); return status(); },
    async (event, _listener) => { events.push(event); return () => {}; });
  assert.equal(createAppleProvisioningApi('preview', () => { throw Error('must not invoke'); }), null);
  for (const mode of ['key-review', 'key-prepare']) {
    const r = request(mode); assert.ok(parseAppleProvisioningRequest(r));
    assert.equal(appleProvisioningConsent(mode), `local-ios-${mode}-v1`);
    await api.prepare(r); await api.start({ ...id('1'), consentVersion: appleProvisioningConsent(mode) });
    for (const extra of ['privateKey', 'csr', 'nativeJoined', 'savePermit', 'vaultInventory', 'p12RecordId', 'p12RecordRevision']) {
      assert.equal(parseAppleProvisioningRequest({ ...r, [extra]: 'not-authority' }), null);
    }
    assert.equal(parseAppleProvisioningRequest({ ...r, newApplication: true }), null);
  }
  for (const mode of ['key-recover', 'certificate-review', 'certificate-create', 'certificate-reconcile']) {
    assert.equal(parseAppleProvisioningRequest({ ...request(), mode }), null);
    assert.equal(encodeAppleProvisioningRequest('start_apple_provisioning', { ...id('1'), consentVersion: `local-ios-${mode}-v1` }), null);
  }
  assert.equal(parseAppleProvisioningRequest({ ...request(), reference: id('1') }), null);
  assert.equal(parseAppleProvisioningRequest({ ...request('key-prepare'), reference: null }), null);
  await api.status(); await api.cancel(id('1')); const off = await api.subscribe(() => {}); off();
  assert.deepEqual([...new Set(calls.map(([command]) => command))].sort(),
    ['apple_provisioning_status', 'cancel_apple_provisioning', 'prepare_apple_provisioning', 'start_apple_provisioning'].sort());
  assert.deepEqual(events, [APPLE_PROVISIONING_EVENT]);
});

test('closed result pairs never upgrade produced DATA to a saved key, CSR or certificate approval', () => {
  const pairs = [['prepare-review', 'local-key-required'], ['recover-existing-key', 'existing-key'], ['recover-existing-key', 'existing-certificate'],
    ['reuse-existing-identity', 'existing-certificate'], ['bundle-required', 'bundle-registration-required'], ['blocked', 'account-pending'], ['blocked', 'inventory-unavailable']];
  for (const [decision, reason] of pairs) assert.ok(parseAppleDistributionKeyResult(result('key-review', decision, reason), 'key-review'));
  assert.ok(parseAppleDistributionKeyResult(result('key-prepare'), 'key-prepare'));
  for (const [mode, decision, reason] of [['key-review', 'produced', 'producer-returned'], ['key-prepare', 'prepare-review', 'local-key-required'],
    ['key-review', 'recover-existing-key', 'inventory-unavailable'], ['key-review', 'blocked', 'existing-certificate']]) {
    assert.equal(parseAppleDistributionKeyResult(result(mode, decision, reason), mode), null);
  }
  for (const name of ['saved', 'certificateRequested', 'credentialReady']) {
    assert.equal(parseAppleDistributionKeyResult({ ...result('key-prepare'), [name]: true }, 'key-prepare'), null);
  }
  for (const extra of ['csr', 'privateKey', 'savedKey', 'recordCount', 'nativeJoined']) {
    assert.equal(parseAppleDistributionKeyResult({ ...result(), [extra]: 'untrusted' }, 'key-review'), null);
  }
  let read = 0; const getter = result(); Object.defineProperty(getter, 'decision', { enumerable: true, get() { read++; return 'prepare-review'; } });
  assert.equal(parseAppleDistributionKeyResult(getter, 'key-review'), null); assert.equal(read, 0);
  assert.match(appleDistributionKeyResultCopy(result('key-prepare'), null, 'complete').title, /not confirmed/);
});

test('savedKey is an exact NEW full reference only on known-terminal key-prepare, with original disposition preserved', () => {
  const op = operation(request('key-prepare'));
  for (const [outcome, reason] of [['complete', 'none'], ['cancelled', 'cancelled'], ['timed-out', 'timed-out'], ['failed', 'command-incomplete'], ['refused', 'query-prerequisites']]) {
    const done = { ...complete(op), outcome, reason, result: outcome === 'complete' ? result('key-prepare') : null, savedKey: saved() };
    assert.ok(parseAppleProvisioningStatus(status(4, done)), outcome);
    if (outcome !== 'complete') assert.match(appleDistributionKeyResultCopy(null, saved(), outcome).title, /stopped/);
  }
  const done = { ...complete(op), savedKey: saved() };
  for (const change of [{ revisionCounter: 2 }, { revisionCounter: 0 }, { recordId: 'c'.repeat(32) }, { vaultId: '0'.repeat(32) },
    { revisionId: '1'.repeat(32) }, { privateKey: 'not-authority' }]) {
    assert.equal(parseAppleProvisioningStatus(status(4, { ...done, savedKey: { ...saved(), ...change } })), null);
  }
  assert.ok(parseAppleDistributionKeySavedReference(saved()));
  for (const invalid of [{ ...op, savedKey: saved() }, { ...unknown(op), savedKey: saved() },
    { ...complete(operation(request())), savedKey: saved() }, { ...done, savedKey: null }, { ...done, savedKey: undefined },
    { ...cancelled(op), result: result('key-prepare'), savedKey: saved() }, { ...done, savedProfile: saved() }]) {
    assert.equal(parseAppleProvisioningStatus(status(4, invalid)), null);
  }
  const withdrawn = clone(done); delete withdrawn.savedKey;
  assert.equal(appleProvisioningProgress(done, withdrawn), true);
  assert.equal(appleProvisioningProgress(withdrawn, done), false);
  assert.equal(appleProvisioningProgress(done, { ...done, savedKey: { ...saved(), recordId: '5'.repeat(32) } }), false);
});

test('key input is current encrypted P8 in the dedicated scope, never an old Store/Signing/P12 loan or a record-count permission', () => {
  assert.ok(parseAssetStatus(assets().status)); assert.ok(appleDistributionKeyInputBase(project(), assets()));
  const withP12 = appleDistributionKeyInputBase(project(), assets(true));
  assert.ok(withP12); assert.equal(Object.hasOwn(withP12, 'p12RecordId'), false);
  for (const change of ['store', 'signing', 'full', 'android', 'ci', 'missing-mode', 'wrong-stage', 'session', 'missing-p8', 'duplicate',
    'unavailable', 'row-revision', 'context-revision', 'pending-context', 'dirty', 'saving', 'snapshot', 'version', 'locked']) {
    const a = assets(), p = project();
    if (['store', 'signing', 'full'].includes(change)) { a.scope.purpose = change; a.status.context.purpose = change; }
    if (change === 'android') { a.scope.platform = 'android'; a.status.context.platform = 'android'; }
    if (change === 'ci') { a.scope.executionMode = 'github'; a.status.context.executionMode = 'github'; }
    if (change === 'missing-mode') delete a.status.context.executionMode;
    if (change === 'wrong-stage') { a.scope.stage = 'production'; a.status.context.stage = 'production'; }
    if (change === 'session') a.status.mode = 'session';
    if (change === 'missing-p8') a.status.assignments = [];
    if (change === 'duplicate') a.status.assignments.push(clone(a.status.assignments[0]));
    if (change === 'unavailable') a.status.assignments[0].availability = 'unavailable';
    if (change === 'row-revision') a.status.records[0].revision++;
    if (change === 'context-revision') a.status.context.revision++;
    if (change === 'pending-context') a.updatingContext = true;
    if (change === 'dirty') p.dirtyDraft = true;
    if (change === 'saving') p.saveRecoveryRequired = true;
    if (change === 'snapshot') p.snapshotPending = true;
    if (change === 'version') p.versionPending = true;
    if (change === 'locked') a.status.persistence.state = 'locked';
    assert.equal(appleDistributionKeyInputBase(p, a), null, change);
  }
  const existing = assets(); existing.status.records.push({ recordId: '8'.repeat(32), revision: 1, kind: 'apple-distribution-key',
    availability: 'unassigned', storage: 'encrypted', label: null, payloadState: 'not-checked' });
  assert.ok(parseAssetStatus(existing.status));
  assert.deepEqual(appleDistributionKeyInputBase(project(), existing), appleDistributionKeyInputBase(project(), assets()));
});

test('actual key Asset operation names remain encrypted-only, nonmanual, and retained correlation never admits another action', () => {
  const a = mutation(), original = appleDistributionKeyInputBase(project(), assets());
  assert.ok(parseAssetStatus(a.status)); assert.equal(appleDistributionKeyInputBase(project(), a), null);
  assert.deepEqual(retainedAppleDistributionKeyInput(project(), a, original), original);
  for (const change of ['other', 'future-use', 'unknown', 'late', 'p8', 'context', 'locked']) {
    const bad = clone(a);
    if (change === 'other') bad.status.operation.operation = 'apple-profile-setup';
    if (change === 'future-use') bad.status.operation.operation = 'use-apple-distribution-key';
    if (change === 'unknown') bad.status.operation.settlement = 'unknown';
    if (change === 'late') bad.status.operation.settlement = 'late-known';
    if (change === 'p8') { bad.status.assignments[0].recordRevision++; bad.status.records[0].revision++; }
    if (change === 'context') bad.status.context.revision++;
    if (change === 'locked') bad.status.persistence.state = 'locked';
    assert.equal(retainedAppleDistributionKeyInput(project(), bad, original), null, change);
  }
  for (const kind of ['prepare-apple-distribution-key', 'use-apple-distribution-key']) {
    const s = clone(a.status); s.operation.operation = kind;
    if (kind.startsWith('use')) { s.operation.phase = 'admitting'; s.operation.storageOutcome = null; }
    assert.ok(parseAssetStatus(s));
    const picking = clone(s); picking.operation.phase = 'picking'; assert.equal(parseAssetStatus(picking), null);
    const manual = clone(s); manual.operation.selectionToken = 'e'.repeat(32); assert.equal(parseAssetStatus(manual), null);
    const session = clone(s); session.mode = 'session'; session.persistence = null; session.records.forEach(row => row.storage = 'session');
    assert.equal(parseAssetStatus(session), null);
  }
});

test('mount, status, input changes and wizard visibility never start generation; key check does not require P12', async t => {
  const h = harness(t); await h.ready; h.controller.syncProject(); h.controller.setVisible(false); h.controller.setVisible(true); await h.controller.checkStatus();
  assert.equal(h.calls.length, 0); assert.equal(h.state.keyReviewReason, null); assert.notEqual(h.state.profileReviewReason, null);
  await h.controller.prepare('key-prepare'); assert.equal(h.calls.length, 0);
  const op = await prepared(h); assert.equal(h.calls[0].request.mode, 'key-review'); assert.equal(Object.hasOwn(h.calls[0].request, 'p12RecordId'), false);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(row => row.kind === 'start').length, 0);
  await cancelPrepared(h, op, 3);
});

test('only the joined original Start and post-invoke terminal read publish the one-use key review, never an event or early read', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  h.emit(status(4, complete(op))); await h.controller.checkStatus();
  assert.equal(h.state.keyReviewReference, null); assert.equal(h.state.keyResult, null);
  const read = deferred(); h.readQueue.push(read); call.resolve(status(3, { ...op, phase: 'running', intentUsable: false })); await flush();
  assert.equal(h.state.keyReviewReference, null); assert.equal(h.state.reading, true);
  read.resolve(status(4, complete(op))); await work;
  assert.deepEqual(h.state.keyReviewReference, id('1')); assert.equal(h.state.keyPrepareReason, null);
  const creation = h.controller.prepare('key-prepare'), row = h.calls.at(-1);
  await h.controller.prepare('key-prepare'); assert.equal(h.calls.filter(c => c.kind === 'prepare').length, 2);
  assert.deepEqual(row.request.reference, id('1')); assert.equal(h.state.keyReviewReference, null);
  const next = operation(row.request, '2'); h.reply(row, status(5, next)); await creation;
  assert.equal(h.state.consent.acknowledged, false);
  await h.controller.start(next.operationId, next.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 1);
  await cancelPrepared(h, next, 6);
});

test('review expiry is original startedAt plus 300 seconds, never renewed by reads, and bounds the separate create consent', async t => {
  const h = harness(t); await reviewed(h); h.time(290000); await h.controller.checkStatus();
  assert.equal(h.state.keyPrepareReason, null);
  const op = await prepared(h, 'key-prepare', '2', 4); assert.equal(h.state.consent.acknowledged, false);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true); h.time(300100);
  const attempted = h.controller.start(op.operationId, op.ownerGeneration);
  assert.equal(h.calls.filter(row => row.kind === 'start').length, 1); await attempted;
  assert.notEqual(h.state.startReason, null); await cancelPrepared(h, op, 5);
  const expired = harness(t); await reviewed(expired); expired.time(300100); await expired.controller.checkStatus();
  assert.equal(expired.state.keyReviewReference, null); await expired.controller.prepare('key-prepare');
  assert.equal(expired.calls.filter(row => row.kind === 'prepare').length, 1);
  const reconnected = harness(t); await reviewed(reconnected); await reconnected.controller.connect({ ...reconnected.api });
  assert.equal(reconnected.state.keyReviewReference, null); assert.equal(reconnected.state.keyResult, null);
  await reconnected.controller.prepare('key-prepare'); assert.equal(reconnected.calls.filter(row => row.kind === 'prepare').length, 1);
});

test('notification-time cancellation, source ABA, scope, peer and connection changes prevent the exact key Prepare handoff', async t => {
  for (const mode of ['key-review', 'key-prepare']) for (const change of ['cancel', 'p8-aba', 'project-aba', 'scope-aba', 'raw-source', 'peer', 'display', 'hidden', 'connection', 'dispose']) {
    const h = harness(t); if (mode === 'key-prepare') await reviewed(h); else await h.ready;
    const before = h.calls.filter(row => row.kind === 'prepare').length; let once = false;
    const off = h.controller.subscribe(() => {
      if (once) return; once = true;
      if (change === 'cancel') void h.controller.cancel();
      if (change === 'p8-aba') { const old = h.assets, next = h.assets; next.status.assignments[0].recordRevision++; next.status.records[0].revision++; h.replaceAssets(next); h.replaceAssets(old); }
      if (change === 'project-aba') { const old = h.project; h.replaceProject({ ...old, observationGeneration: 4 }); h.replaceProject(old); }
      if (change === 'scope-aba') { const old = h.assets, next = h.assets; next.scope.purpose = 'store'; next.status.context.purpose = 'store'; h.replaceAssets(next); h.replaceAssets(old); }
      if (change === 'raw-source') h.replaceProject({ ...h.project, draftRevision: 2 }, false);
      if (change === 'peer') h.peer('Another original owns the project.');
      if (change === 'display') h.controller.setDisplayName('Different App');
      if (change === 'hidden') h.controller.setVisible(false);
      if (change === 'connection') void h.controller.connect({ ...h.api });
      if (change === 'dispose') h.controller.dispose();
    });
    await h.controller.prepare(mode); off(); await flush();
    assert.equal(h.calls.filter(row => row.kind === 'prepare').length, before, `${mode}/${change}`);
    assert.equal(h.state.consent, null, `${mode}/${change}`);
  }
});

test('same started key survives only its own temporary Asset unavailability and reports actual saved DATA after all UI callers join', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'key-prepare', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(row => row.kind === 'start').length, 2);
  h.replaceAssets(mutation()); assert.equal(h.state.cancelRequested, false); assert.equal(h.state.historical, false);
  await h.controller.prepare('key-review'); assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 2);
  const done = { ...complete(op), savedKey: saved() };
  h.emit(status(6, done)); assert.equal(h.state.savedKey, null); assert.equal(h.state.keyResult, null);
  h.replaceAssets(assets()); h.reply(call, status(6, done)); await work;
  assert.deepEqual({ ...h.state.savedKey }, saved()); assert.equal(h.state.keyResult.saved, false);
  assert.equal(h.state.keyTerminalRead, true); assert.equal(h.state.retained, false); assert.equal(h.state.keyReviewReference, null);
  assert.match(appleDistributionKeyResultCopy(h.state.keyResult, h.state.savedKey, 'complete').detail, /not an Apple certificate/);
  const withdrawn = clone(done); delete withdrawn.savedKey; h.emit(status(7, withdrawn));
  assert.equal(h.state.savedKey, null); assert.equal(h.state.issue, null);
});

test('a different P8 revision cancels the started key original and cannot turn its late result into a current review', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'key-prepare', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  const changed = h.assets; changed.status.assignments[0].recordRevision++; changed.status.records[0].revision++;
  h.replaceAssets(changed); const cancel = h.calls.at(-1);
  assert.equal(cancel.kind, 'cancel'); assert.deepEqual(cancel.request, id('2')); assert.equal(h.state.consent, null);
  h.reply(cancel, status(6, cancelled(op))); await flush();
  start.resolve(status(5, { ...op, phase: 'stopping', intentUsable: false, reason: 'cancelled' })); await work;
  assert.equal(h.state.historical, true); assert.equal(h.state.keyReviewReference, null); assert.equal(h.state.savedKey, null);
  await h.controller.prepare('key-prepare'); assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 2);
});

test('cancelled-with-saved-key stays cancelled and historical; no second generation or automatic assignment', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'key-prepare', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  const cancelling = h.controller.cancel(), cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
  const done = { ...cancelled(op), savedKey: saved() };
  h.reply(cancel, status(6, done)); await cancelling; assert.equal(h.state.savedKey, null);
  start.resolve(status(5, { ...op, phase: 'stopping', intentUsable: false, reason: 'cancelled' })); await work;
  assert.equal(h.state.status.operation.outcome, 'cancelled'); assert.equal(h.state.keyResult, null);
  assert.deepEqual({ ...h.state.savedKey }, saved()); assert.equal(h.state.historical, true); assert.equal(h.state.keyReviewReference, null);
  const copy = appleDistributionKeyResultCopy(null, h.state.savedKey, h.state.status.operation.outcome);
  assert.match(copy.title, /stopped/); assert.match(copy.detail, /not complete normally/);
  await h.controller.prepare('key-prepare'); assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 2);
  assert.equal(h.state.status.operation.result, null);
});

test('lost original Start and cleanup-unknown stay absorbing despite later saved/terminal data or reconnect', async t => {
  for (const kind of ['lost', 'unknown']) {
    const h = harness(t); await reviewed(h); const op = await prepared(h, 'key-prepare', '2', 4);
    h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
    const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
    if (kind === 'lost') start.reject(Error('INERT-PRIVATE-DETAIL'));
    else h.reply(start, status(5, unknown(op), 'cleanup-unknown'));
    await flush(); const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
    h.reply(cancel, status(6, kind === 'lost' ? { ...cancelled(op), savedKey: saved() } : unknown(op), kind === 'lost' ? 'available' : 'cleanup-unknown'));
    await work; await flush();
    assert.ok(h.state.issue); assert.ok(h.state.retained); assert.equal(h.state.savedKey, null); assert.equal(h.state.keyReviewReference, null);
    assert.equal(JSON.stringify(h.state).includes('INERT-PRIVATE-DETAIL'), false);
    await h.controller.prepare('key-review'); await h.controller.prepare('key-prepare'); await h.controller.connect({ ...h.api });
    assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 2); assert.ok(h.state.issue);
  }
});

test('a consumed review is not restored after lost Prepare, and a failed prior source cannot be hidden by another input family', async t => {
  const h = harness(t, true); await reviewed(h);
  const work = h.controller.prepare('key-prepare'), call = h.calls.at(-1);
  assert.deepEqual(call.request.reference, id('1')); assert.equal(h.state.keyReviewReference, null);
  call.reject(Error('INERT-LOST-PREPARE')); await work;
  assert.ok(h.state.issue); assert.equal(h.state.keyReviewReference, null);
  await h.controller.prepare('key-prepare'); await h.controller.prepare('profile-review');
  assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 2); assert.ok(h.state.retained);
});

test('a settled explicit family switch preserves profile P8+P12 shape and consumes no key or signing approval', async t => {
  const h = harness(t, true); await reviewed(h);
  assert.equal(Object.hasOwn(h.calls[0].request, 'p12RecordId'), false);
  const work = h.controller.prepare('profile-review'), call = h.calls.at(-1);
  assert.equal(call.kind, 'prepare'); assert.equal(call.request.p12RecordId, 'd'.repeat(32)); assert.equal(call.request.mode, 'profile-review');
  assert.equal(h.state.keyReviewReference, null);
  const op = operation(call.request, '2'); h.reply(call, status(4, op)); await work;
  assert.equal(h.state.consent.mode, 'profile-review'); assert.equal(h.state.consent.acknowledged, false);
  await h.controller.prepare('key-review'); assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 2);
  await cancelPrepared(h, op, 5);
});

test('reuse/recovery, absent bundle and failed inventory results never offer generation or claim a usable certificate', async t => {
  for (const [decision, reason] of [['recover-existing-key', 'existing-key'], ['reuse-existing-identity', 'existing-certificate'],
    ['bundle-required', 'bundle-registration-required'], ['blocked', 'inventory-unavailable'], ['blocked', 'account-pending']]) {
    const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
    const work = h.controller.start(op.operationId, op.ownerGeneration);
    h.reply(h.calls.at(-1), status(3, complete(op, result('key-review', decision, reason)))); await work;
    assert.equal(h.state.keyReviewReference, null); assert.notEqual(h.state.keyPrepareReason, null); assert.equal(h.state.savedKey, null);
    await h.controller.prepare('key-prepare'); assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 1);
    assert.ok(appleDistributionKeyResultCopy(h.state.keyResult, null, 'complete'));
  }
});
