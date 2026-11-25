// Actual existing Asset/permission controllers; promises and public DATA only.
// No IPC, native Load, vault, crypto, credential, picker or receipt is acquired.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { AgentUploadKeyAccessController } from '../src/agentUploadKeyAccessController.ts';
import { agentUploadKeySelection, parseAgentUploadKeyAccess, parseAgentUploadKeySelection, createAgentUploadKeyAccessPort } from '../src/agentUploadKeyAccess.ts';
import { agentUploadKeyReuseOptions, parseAgentUploadKeyPrepared } from '../src/agentUploadKeyReuse.ts';

const id = c => c.repeat(32), record = { recordId: id('c'), expectedRevision: 1 };
const scope = { platform: 'android', stage: 'candidate', purpose: 'signing', executionMode: 'local' };
const context = { revision: 1, projectId: 'inert-reuse-project', ...scope }, available = { available: true, reason: 'none' };
const row = (patch = {}) => ({ recordId: id('c'), revision: 1, kind: 'android-keystore', storage: 'encrypted',
  availability: 'unassigned', label: null, payloadState: 'not-checked', ...patch });
const status = (n = 1, patch = {}) => ({ schemaVersion: 3, statusRevision: n, mode: 'encrypted',
  persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { ...available },
  modes: { session: { ...available }, encrypted: { ...available } }, backup: { available: false, reason: 'unqualified' },
  context: { ...context }, records: [row()], assignments: [], operation: null, ...patch });
function assessment() { return { schemaVersion: 1, policyVersion: 'credential-policy-v1', kind: 'android-keystore',
  context: { ...scope }, applicability: { state: 'required', reason: 'selected' }, state: 'configured', identity: 'not-applicable',
  fields: [['file', 'ANDROID_KEYSTORE_BASE64'], ['storePassword', 'ANDROID_KEYSTORE_PASSWORD'], ['keyAlias', 'ANDROID_KEY_ALIAS'], ['keyPassword', 'ANDROID_KEY_PASSWORD']]
    .map(([field, requirement]) => ({ id: field, requirement: `MOBILE_RELEASE_${requirement}`, presence: 'supplied', state: 'configured', issues: [],
      checks: [{ scope: field === 'file' ? 'jks-header' : 'value-admission', outcome: field === 'file' ? 'asserted-pass' : 'passed' }] })),
  assurance: { basis: 'supplied-input-only', scalarValuesProcessed: true, fileObservationsProcessed: true, selectedFilesRead: false,
    keyringAccessed: false, storageWritesPerformed: false, projectCodeExecuted: false, sourceCustody: 'not-established',
    nativeValidation: 'not-run', serviceValidation: 'not-run', releaseReadiness: 'unknown' } }; }
const preview = (n = 2, patch = {}) => status(n, { records: [row({ payloadState: 'assessed' })], operation: {
  operationId: 7, operation: 'prepare', phase: 'preview', reason: 'none', source: 'captured', settlement: 'known',
  storageOutcome: null, selectionToken: null, assessment: assessment(), preview: { token: id('a'), action: 'bind', expiresInMs: 10_000,
    subject: { type: 'record', kind: 'android-keystore', change: 'assign', recordId: id('c'), recordRevision: 1 } } }, ...patch });
const prepared = (patch = {}) => ({ assetOperationId: 7, statusRevision: 2, contextRevision: 1, recordId: id('c'), expectedRevision: 1,
  previewToken: id('a'), remainingMs: 10_000, ...patch });
const empty = () => ({ schemaVersion: 1, serviceInstance: null, projectId: null, grantId: null, kind: null, requestId: null,
  enabled: false, remainingMs: 0, consumed: false });
const access = (patch = {}) => ({ schemaVersion: 1, serviceInstance: id('b'), projectId: id('a'), grantId: id('d'), kind: 'prepare-existing',
  requestId: null, enabled: true, remainingMs: 299_000, consumed: false, ...patch });
const completed = (patch = {}) => access({ requestId: id('e'), enabled: false, remainingMs: 0, consumed: true, prepared: prepared(), ...patch });
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 24; ++i) await Promise.resolve(); }
async function fixture(t) {
  let project = { project: { id: context.projectId, name: 'Inert project' }, draft: { schemaVersion: 1 }, revision: 1, baselineGeneration: 1 };
  let current = status(0), event, now = 100, holdReads = false, nonce = 'd', port;
  const source = { port: null, peer: null }, assetCalls = [], permissionCalls = [];
  const call = (list, command, input) => { const d = deferred(); list.push({ command, input, ...d }); return d.promise; };
  const api = { mode: 'native', assetStatus: () => holdReads ? call(assetCalls, 'read') : Promise.resolve(current),
    subscribeAssets: async fn => { event = fn; return () => {}; }, setAssetContext: value => call(assetCalls, 'context', value),
    prepareCredential: value => call(assetCalls, 'assess', value), bindAsset: value => call(assetCalls, 'bind', value),
    createUploadKey: value => call(assetCalls, 'generate', value), discardAsset: value => call(assetCalls, 'discard', value) };
  const assets = new AssetSessionController(() => project, () => now, () => source.peer);
  assets.setScope(scope); await assets.connect(api); assets.submitContext(); await flush();
  assert.equal(assetCalls.at(-1).command, 'context');
  current = status(); assetCalls.at(-1).resolve(current); await flush();
  assert.equal(assets.getSnapshot().contextCurrent, true); assert.ok(parseAssetStatus(preview()));
  holdReads = true;
  port = { status: () => call(permissionCalls, 'status'), allow: value => call(permissionCalls, 'allow', value),
    revoke: value => call(permissionCalls, 'revoke', value) };
  source.port = port; const nativeSession = {};
  const make = () => new AgentUploadKeyAccessController({ current: () => ({ port: source.port, nativeSession,
    projectId: context.projectId, project, assets: assets.getSnapshot(), generateReady: false, blockedReason: source.peer }),
    prepareExisting: r => assets.prepareExistingForCli(r), now: () => now, nonce: () => id(nonce) });
  let controller = make(); const controllers = [controller];
  const off = assets.subscribe(() => controller.syncContext());
  t.after(async () => { controllers.forEach(c => c.dispose()); assets.dispose(); off();
    for (const c of [...assetCalls, ...permissionCalls]) c.reject({ code: 'inert_closed' });
    await Promise.all(controllers.map(c => c.whenSettled())); });
  return { assets, api, source, assetCalls, permissionCalls, port,
    get controller() { return controller; }, last: () => permissionCalls.at(-1), read: () => assetCalls.filter(c => c.command === 'read').at(-1),
    reads: () => assetCalls.filter(c => c.command === 'read'), emit: value => { current = value; event(value); },
    time: value => { now = value; }, nonce: value => { nonce = value; },
    changeProject: () => { project = { ...project, revision: project.revision + 1 }; assets.syncProject(); },
    remount: () => { controller.dispose(); controller = make(); controllers.push(controller); },
  };
}
function choose(h) {
  assert.equal(h.controller.setKind('prepare-existing'), true);
  assert.equal(h.controller.setAcknowledged(true), false, 'there is no automatic record choice');
  assert.equal(h.controller.setPrepareRecord(record), true);
  assert.equal(h.controller.setAcknowledged(true), true); assert.equal(h.controller.allowReason(), null);
}
async function allowed(h, value = access()) { choose(h); const p = h.controller.allow(); assert.equal(h.last().command, 'allow'); h.last().resolve(value); await p; }
function unowned(h) { assert.equal(h.assets.getSnapshot().reviewReady, false); assert.equal(h.assets.getSnapshot().intent, null); }
function noNativeAction(h) { assert.ok(h.assetCalls.every(c => c.command === 'context' || c.command === 'read'), 'no second Prepare, Bind, generator or picker'); }
async function correlate(h, value = completed()) {
  const check = h.controller.check(); h.last().resolve(value); await flush();
  assert.equal(h.read()?.command, 'read'); unowned(h);
  h.read().resolve(preview()); await check;
}

test('closed prepare selection and optional compact MAIN reply cannot carry secrets, Bind or a new grant', async () => {
  const selection = { kind: 'prepare-existing', ...record }, calls = [];
  assert.deepEqual(parseAgentUploadKeySelection(selection), selection);
  assert.deepEqual(parseAgentUploadKeyAccess(empty()), empty());
  assert.deepEqual(parseAgentUploadKeyPrepared(prepared()), prepared());
  assert.ok(parseAgentUploadKeyAccess(completed()));
  for (const value of [access({ prepared: prepared() }), completed({ kind: 'bind-reviewed' }), completed({ prepared: null }),
    completed({ prepared: prepared({ remainingMs: 0 }) }), completed({ prepared: prepared({ remainingMs: 300_001 }) }),
    completed({ prepared: { ...prepared(), key: 'forbidden' } })]) assert.equal(parseAgentUploadKeyAccess(value), null);
  const port = createAgentUploadKeyAccessPort(async (command, bytes) => { calls.push({ command, body: JSON.parse(new TextDecoder().decode(bytes)), bytes: bytes.length }); return empty(); });
  await port.allow({ projectId: context.projectId, consentId: id('d'), contextRevision: 1, expectedStatusRevision: 1, selection });
  assert.equal(calls.length, 1); assert.equal(calls[0].body.consentVersion, 'agent-android-upload-key-prepare-once-v1');
  assert.ok(calls[0].bytes + 96 <= 1024);
  for (const key of ['fields', 'password', 'path', 'generate', 'autoBind', 'kindOverride']) assert.equal(parseAgentUploadKeySelection({ ...selection, [key]: true }), null);
  let read = false; const getter = { ...prepared() }; Object.defineProperty(getter, 'previewToken', { enumerable: true, get() { read = true; return id('a'); } });
  assert.equal(parseAgentUploadKeyPrepared(getter), null); assert.equal(read, false);
});

test('only an explicit exact encrypted Android row is selectable; backup qualification is not borrowed', async t => {
  const h = await fixture(t), a = h.assets.getSnapshot();
  assert.equal(a.status.backup.available, false);
  assert.equal(agentUploadKeyReuseOptions(a).length, 1);
  assert.equal(agentUploadKeySelection(a, 'prepare-existing', false, 100, null), null);
  assert.ok(agentUploadKeySelection(a, 'prepare-existing', false, 100, record));
  for (const records of [[row(), row()], [row({ kind: 'asc-p8' })], [row({ storage: 'session' })], [row({ availability: 'mutation-pending' })]]) {
    const changed = { ...a, status: { ...a.status, records } };
    assert.equal(agentUploadKeyReuseOptions(changed).length, 0);
  }
  for (const changed of [{ ...a, contextCurrent: false }, { ...a, observationFailed: true }, { ...a, originPending: true },
    { ...a, status: { ...a.status, context: { ...context, executionMode: 'github' } } }]) assert.equal(agentUploadKeyReuseOptions(changed).length, 0);
  noNativeAction(h);
});

test('one original Allow and joined current Load reply enable only an ordinary review; Bind needs separate returned withdrawal and consent', async t => {
  const h = await fixture(t); await allowed(h);
  h.emit(preview()); unowned(h);
  await correlate(h); assert.equal(h.assets.getSnapshot().reviewReady, true);
  assert.equal(h.assets.getSnapshot().intent.change, 'assign');
  assert.equal(h.controller.setKind('bind-reviewed'), false);
  const withdraw = h.controller.revoke(); assert.equal(h.controller.setKind('bind-reviewed'), false);
  const value = completed(); delete value.prepared; // Native omits the comparison on Revoke.
  h.last().resolve(value);
  await withdraw;
  assert.equal(h.controller.getSnapshot().unknown, false);
  assert.equal(h.assets.getSnapshot().reviewReady, true);
  noNativeAction(h);
});

test('separate exact Revoke acknowledgment preserves the correlated review and permits a fresh unchecked Bind consent', async t => {
  const h = await fixture(t); await allowed(h); h.emit(preview()); await correlate(h);
  const revoke = h.controller.revoke(), value = completed(); delete value.prepared;
  h.last().resolve(value); await revoke;
  assert.equal(h.controller.getSnapshot().unknown, false); assert.equal(h.assets.getSnapshot().reviewReady, true);
  assert.equal(h.controller.setKind('bind-reviewed'), true); assert.equal(h.controller.getSnapshot().acknowledged, false);
  h.nonce('f'); assert.equal(h.controller.setAcknowledged(true), true);
  const bind = h.controller.allow(); assert.equal(h.last().input.selection.kind, 'bind-reviewed');
  h.last().resolve(access({ grantId: id('f'), kind: 'bind-reviewed' })); await bind;
  assert.equal(h.permissionCalls.filter(c => c.command === 'allow').length, 2); noNativeAction(h);
});

test('event before Allow return is not an origin; the same original consumed reply still needs its later Asset read', async t => {
  const h = await fixture(t); choose(h); const allow = h.controller.allow();
  h.emit(preview()); unowned(h); assert.equal(await h.controller.check(), false);
  h.last().resolve(completed()); await flush();
  assert.equal(h.reads().length, 1); unowned(h);
  h.read().resolve(preview()); await allow;
  assert.equal(h.assets.getSnapshot().reviewReady, true); noNativeAction(h);
});

test('an already-running Asset read is joined then followed by one genuinely post-stamp read, never coalesced as origin', async t => {
  const h = await fixture(t); await allowed(h);
  const old = h.assets.checkStatus(); await flush(); const first = h.read();
  const check = h.controller.check(); h.last().resolve(completed()); await flush();
  assert.equal(h.reads().length, 1); unowned(h);
  first.resolve(preview()); await old; await flush();
  assert.equal(h.reads().length, 2); unowned(h);
  assert.notEqual(h.read(), first); h.read().resolve(preview()); await check;
  assert.equal(h.assets.getSnapshot().reviewReady, true); noNativeAction(h);
});

test('unsolicited and remounted status cannot reconstruct a private Prepare attempt', async t => {
  for (const prior of [false, true]) {
    const h = await fixture(t); if (prior) { await allowed(h); h.remount(); }
    h.emit(preview()); const check = h.controller.check(); h.last().resolve(completed()); await check;
    unowned(h); assert.equal(h.reads().length, 0); noNativeAction(h);
  }
});

test('lost Allow stays Unknown through a correct stamp and exact withdrawal; no automatic reread or Prepare', async t => {
  const h = await fixture(t); choose(h); const allow = h.controller.allow(); h.last().reject({ code: 'inert_lost_reply' }); await allow;
  h.emit(preview()); const check = h.controller.check(); h.last().resolve(completed()); await check;
  const revoke = h.controller.revoke(), value = completed(); delete value.prepared; h.last().resolve(value); await revoke;
  assert.equal(h.controller.getSnapshot().unknown, true); unowned(h); assert.equal(h.reads().length, 0);
  assert.equal(await h.controller.allow(), false); noNativeAction(h);
});

test('reentrant original Allow publication cannot send after project, API, peer or selection ABA', async t => {
  for (const cut of ['project', 'api', 'peer', 'selection']) {
    const h = await fixture(t); choose(h); let fired = false;
    const off = h.controller.subscribe(() => { if (!fired && h.controller.getSnapshot().pending === 'allow') {
      fired = true;
      if (cut === 'project') h.changeProject();
      if (cut === 'api') h.source.port = { ...h.port };
      if (cut === 'peer') h.source.peer = 'Other original';
      if (cut === 'selection') { h.assets.setScope({ ...scope, purpose: 'full' }); h.assets.setScope(scope); }
    } });
    assert.equal(await h.controller.allow(), false); off();
    assert.equal(h.permissionCalls.length, 0); unowned(h); noNativeAction(h);
  }
});

test('reentrant fresh-read publication rechecks the original before native status send', async t => {
  const h = await fixture(t); await allowed(h); h.emit(preview());
  let fired = false;
  const off = h.assets.subscribe(() => { if (!fired && h.assets.getSnapshot().observing) { fired = true; h.source.peer = 'Other original'; } });
  const check = h.controller.check(); h.last().resolve(completed()); await check; off();
  assert.equal(fired, true); assert.equal(h.reads().length, 0); unowned(h); noNativeAction(h);
});

test('source or API drift while the actual fresh read is pending cannot adopt its late reply', async t => {
  for (const cut of ['project', 'api', 'revoke']) {
    const h = await fixture(t); await allowed(h); h.emit(preview());
    const check = h.controller.check(); h.last().resolve(completed()); await flush();
    assert.equal(h.reads().length, 1);
    if (cut === 'project') h.changeProject();
    if (cut === 'api') { h.source.port = null; h.controller.syncContext(); h.source.port = h.port; h.controller.syncContext(); }
    if (cut === 'revoke') { const revoke = h.controller.revoke(); const v = completed(); delete v.prepared; h.last().resolve(v); await revoke; }
    h.read().resolve(preview()); await check;
    unowned(h); noNativeAction(h);
  }
});

test('native read subscribers cannot change the project or revoke between the final matching read and review publication', async t => {
  for (const cut of ['project', 'revoke']) {
    const h = await fixture(t); await allowed(h);
    const check = h.controller.check(); h.last().resolve(completed()); await flush();
    let action = null, fired = false;
    const off = h.assets.subscribe(() => { if (!fired && h.assets.getSnapshot().status?.operation?.operationId === 7) {
      fired = true; if (cut === 'project') h.changeProject(); else action = h.controller.revoke();
    } });
    h.read().resolve(preview()); await flush();
    if (action) { const v = completed(); delete v.prepared; h.last().resolve(v); await action; }
    await check; off(); assert.equal(fired, true); unowned(h); noNativeAction(h);
  }
});

test('stale context, wrong original or token does not turn a returned status into the selected review', async t => {
  for (const patch of [{ contextRevision: 2 }, { assetOperationId: 8 }, { previewToken: id('f') }, { expectedRevision: 2 }]) {
    const h = await fixture(t); await allowed(h); h.emit(preview());
    const check = h.controller.check(); h.last().resolve(completed({ prepared: prepared(patch) })); await flush();
    h.read()?.resolve(preview()); await check; unowned(h); noNativeAction(h);
  }
});

test('review ceiling is original and cannot be renewed by an equal or later permission/status reply', async t => {
  const h = await fixture(t); await allowed(h); h.time(200); h.emit(preview()); await correlate(h);
  const deadline = h.assets.getSnapshot().previewDeadline;
  h.time(300); h.emit(preview(3));
  const check = h.controller.check(); h.last().resolve(completed({ prepared: prepared({ remainingMs: 20_000 }) })); await check;
  assert.equal(h.assets.getSnapshot().previewDeadline, deadline);
  assert.equal(h.controller.getSnapshot().access.prepared.remainingMs, 10_000);
  assert.equal(h.reads().length, 1);
  h.time(deadline);
  assert.equal(agentUploadKeySelection(h.assets.getSnapshot(), 'bind-reviewed', false, deadline), null); noNativeAction(h);
});

test('delayed permission stamps cannot promote a review after the original call-anchored end', async t => {
  for (const kind of ['allow', 'status']) {
    const h = await fixture(t);
    if (kind === 'status') await allowed(h);
    const started = kind === 'allow' ? 100 : 600;
    h.time(started);
    if (kind === 'allow') choose(h);
    const original = kind === 'allow' ? h.controller.allow() : h.controller.check();
    // A READ-clipped native stamp was sampled with only one second left;
    // the original Allow/Check response takes half that time to arrive.
    h.time(started + 500);
    h.last().resolve(completed({ prepared: prepared({ remainingMs: 1000 }) }));
    await flush();
    assert.equal(h.reads().length, 1, 'retain one genuinely later Asset read');
    unowned(h);
    // That read samples the live preview before its actual end, but its own
    // reply arrives afterwards. Receipt-time countdowns must not revive it.
    h.time(started + 900);
    const sampled = preview(); sampled.operation.preview.expiresInMs = 100;
    h.time(started + 1050);
    h.read().resolve(sampled); await original;
    unowned(h);
    assert.equal(h.controller.getSnapshot().unknown, false, 'expiry is not an invented lost return');
    assert.equal(h.reads().length, 1); noNativeAction(h);
  }
});

test('a missing fresh-read reply remains original pending even after returned Revoke, not a join or retry', async t => {
  const h = await fixture(t); await allowed(h); h.emit(preview());
  const check = h.controller.check(); h.last().resolve(completed()); await flush();
  let joined = false; void h.controller.whenSettled().then(() => { joined = true; });
  const revoke = h.controller.revoke(); const v = completed(); delete v.prepared; h.last().resolve(v); await revoke; await flush();
  assert.equal(joined, false); unowned(h); assert.equal(await h.controller.check(), false);
  h.read().resolve(preview()); await check; await flush(); assert.equal(joined, true); unowned(h); noNativeAction(h);
});
