// Existing controller and RAW adapter, inert DATA/Promises only. No private
// P12/key/password, native owner, file picker, provider or storage execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { createAppleProvisioningApi } from '../src/appleProvisioningNative.ts';
import { appleProvisioningContext, appleProvisioningConsent, appleProvisioningProgress,
  parseAppleProvisioningRequest, parseAppleProvisioningStatus } from '../src/appleProvisioningProtocol.ts';
import { appleP12InputBase, retainedAppleP12Input, parseAppleP12Result, parseAppleP12SavedReference, appleP12Copy } from '../src/appleP12SetupProtocol.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';

const clone = value => structuredClone(value);
const identity = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'f'.repeat(32) });
const key = { recordId: 'd'.repeat(32), recordRevision: 1 };
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const project = () => ({ projectId: '_p12_fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
  dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null });
function assets(bound = false) {
  const scope = { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'provisioning' };
  return { mode: 'native', scope, contextCurrent: true, busy: null, updatingContext: false, observationFailed: false,
    blocked: false, originPending: false, entryGeneration: 1,
    status: { schemaVersion: 3, statusRevision: 1, mode: 'encrypted',
      persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { available: true, reason: 'none' },
      modes: { encrypted: { available: true, reason: 'none' }, session: { available: true, reason: 'none' } }, operation: null,
      context: { revision: 3, projectId: '_p12_fixture', ...scope },
      assignments: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' },
        ...(bound ? [{ kind: 'apple-p12', recordId: 'e'.repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' }] : [])],
      records: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), revision: 4, availability: 'assigned', storage: 'encrypted', label: null, payloadState: 'assessed' },
        { kind: 'apple-distribution-key', recordId: key.recordId, revision: 1, availability: 'unassigned', storage: 'encrypted', label: null, payloadState: 'not-checked' },
        ...(bound ? [{ kind: 'apple-p12', recordId: 'e'.repeat(32), revision: 4, availability: 'assigned', storage: 'encrypted', label: null, payloadState: 'assessed' }] : [])] } };
}
const sourceRef = () => ({ vaultId: '1'.repeat(32), generationId: '2'.repeat(32), recordId: 'e'.repeat(32), revisionId: '3'.repeat(32), revisionCounter: 4 });
const savedRef = () => ({ vaultId: '1'.repeat(32), generationId: '2'.repeat(32), recordId: '8'.repeat(32), revisionId: '9'.repeat(32), revisionCounter: 1 });
const request = (mode = 'p12-review', bound = mode === 'p12-reuse') => ({ ...appleP12InputBase(project(), assets(bound), key),
  mode, reference: mode === 'p12-review' ? null : identity('1'), newApplication: false, displayName: 'Fixture App' });
const status = (revision = 1, operation = null, availability = operation && operation.phase !== 'terminal' ? 'busy' : 'available') =>
  ({ schemaVersion: 1, statusRevision: revision, availability, operation });
const operation = (input, digit = '1') => ({ ...identity(digit), context: appleProvisioningContext(clone(input)),
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
function result(mode = 'p12-review', decision = mode === 'p12-save' ? 'assembled' : mode === 'p12-reuse' ? 'reused' : 'assemble-review') {
  const reason = { 'assemble-review': 'new-package-review', 'reuse-review': 'current-package-review', assembled: 'producer-returned', reused: 'existing-package', blocked: 'account-pending' }[decision];
  const hashes = { certificateSha256: '4'.repeat(64), publicKeySha256: '5'.repeat(64) };
  return { schemaVersion: 1, scope: 'local-ios-p12-setup', mode, decision, reason,
    certificateId: decision === 'blocked' ? null : '_certificate',
    certificateSha256: decision === 'blocked' ? null : hashes.certificateSha256,
    publicKeySha256: decision === 'blocked' ? null : hashes.publicKeySha256,
    output: decision === 'assembled' ? { frameBytes: 184, frameSha256: '6'.repeat(64), p12Bytes: 100, p12Sha256: '7'.repeat(64), ...hashes } : null,
    reused: ['reuse-review', 'reused'].includes(decision) ? { sourceP12: sourceRef(), p12Sha256: '7'.repeat(64), ...hashes, policyAckSha256: 'a'.repeat(64) } : null,
    p12Saved: false, profileSaved: false, credentialReady: false, revocationChecked: false };
}
const complete = (op, value = result(op.context.mode)) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result: value });
const cancelled = op => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null });
const unknown = op => ({ ...clone(op), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null });
function usingKey(input = assets(), name = 'assemble-apple-p12') {
  const a = clone(input); a.contextCurrent = false; a.busy = name;
  a.status.operation = { operationId: 5, operation: name, phase: name === 'assemble-apple-p12' ? 'mutating' : 'admitting', reason: 'none', source: 'captured',
    settlement: 'pending', storageOutcome: name === 'assemble-apple-p12' ? { effect: 'known-applied', durability: 'unknown', cleanup: 'pending' } : null,
    selectionToken: null, assessment: null, preview: null };
  for (const row of a.status.assignments) row.availability = 'unavailable';
  return a;
}
function harness(t, bound = false) {
  let p = project(), a = assets(bound), native = status(), now = 100, peer = null;
  const calls = [], reads = [], listeners = [];
  const call = (kind, value) => { const row = { kind, request: clone(value), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native', subscribe: async receive => { const row = { receive, closed: false }; listeners.push(row); return () => { row.closed = true; }; },
    status: () => reads.shift()?.promise ?? Promise.resolve(clone(native)), prepare: value => call('prepare', value),
    start: value => call('start', value), cancel: value => call('cancel', value) };
  const controller = new AppleProvisioningController({ project: () => p, assets: () => a, otherOperationReason: () => peer, now: () => now });
  controller.setVisible(true); controller.setDisplayName('Fixture App'); const ready = controller.connect(api);
  t.after(() => controller.dispose());
  return { controller, api, ready, calls, reads, listeners,
    get state() { return controller.getSnapshot(); }, get assets() { return clone(a); }, get project() { return clone(p); },
    select() { controller.selectCertificateKey(key.recordId, key.recordRevision); },
    reply(row, value) { native = clone(value); row.resolve(clone(value)); },
    emit(value) { native = clone(value); for (const row of listeners) if (!row.closed) row.receive(clone(value)); },
    replaceAssets(value, notify = true) { a = value; if (notify) controller.syncProject(); },
    replaceProject(value, notify = true) { p = value; if (notify) controller.syncProject(); },
    time(value) { now = value; }, peer(value) { peer = value; } };
}
async function prepared(h, mode = 'p12-review', digit = '1', revision = 2) {
  await h.ready; const count = h.calls.length, work = h.controller.prepare(mode), call = h.calls.at(-1);
  assert.equal(h.calls.length, count + 1); assert.equal(call.kind, 'prepare'); const op = operation(call.request, digit);
  h.reply(call, status(revision, op)); await work;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function started(h, op, value, revision) {
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration); h.reply(h.calls.at(-1), status(revision, value)); await work;
}
async function reviewed(h, value = result()) {
  await h.ready; h.select(); const op = await prepared(h); await started(h, op, complete(op, value), 3); return op;
}

test('P12 modes use only existing RAW4; absent P12 keys are required-null in Prepare and omitted only in native context', async () => {
  const calls = [], api = createAppleProvisioningApi('native', async (command, bytes) => { calls.push([command, JSON.parse(new TextDecoder().decode(bytes))]); return status(); }, async () => () => {});
  assert.equal(createAppleProvisioningApi('preview', () => { throw Error('no invoke'); }), null);
  for (const mode of ['p12-review', 'p12-reuse', 'p12-save']) {
    const r = request(mode); assert.ok(parseAppleProvisioningRequest(r)); await api.prepare(r);
    assert.equal(appleProvisioningConsent(mode), `local-ios-${mode}-v1`);
    assert.ok(parseAppleProvisioningStatus(status(2, operation(r))));
    await api.start({ ...identity('1'), consentVersion: appleProvisioningConsent(mode) });
    for (const field of ['password', 'privateKey', 'p12Bytes', 'fullRef', 'savedP12', 'nativeJoined', 'token']) assert.equal(parseAppleProvisioningRequest({ ...r, [field]: 'not-authority' }), null);
  }
  assert.equal(calls.length, 6);
  const r = request(), { p12RecordId: _id, p12RecordRevision: _revision, ...missing } = r;
  assert.equal(parseAppleProvisioningRequest(missing), null);
  assert.equal(parseAppleProvisioningRequest({ ...r, p12RecordRevision: 1 }), null);
  assert.equal(parseAppleProvisioningStatus(status(2, { ...operation(r), context: { ...appleProvisioningContext(r), p12RecordId: null, p12RecordRevision: null } })), null);
  assert.equal(parseAppleProvisioningRequest({ ...request('p12-save'), p12RecordId: 'e'.repeat(32), p12RecordRevision: 4 }), null);
  assert.equal(parseAppleProvisioningRequest({ ...request('p12-reuse'), p12RecordId: null, p12RecordRevision: null }), null);
});

test('closed results keep source revisions, selected reuse and public output separate from a NEW saved reference', () => {
  for (const [r, v] of [[request(), result()], [request('p12-review', true), result('p12-review', 'reuse-review')],
    [request('p12-reuse'), result('p12-reuse')], [request('p12-save'), result('p12-save')], [request(), result('p12-review', 'blocked')]]) assert.ok(parseAppleP12Result(v, r));
  assert.equal(parseAppleP12SavedReference(sourceRef()), null); assert.ok(parseAppleP12SavedReference(savedRef()));
  assert.equal(parseAppleP12Result(result(), request('p12-review', true)), null);
  assert.equal(parseAppleP12Result(result(), { ...request(), p12RecordRevision: undefined }), null);
  assert.equal(parseAppleP12Result(result('p12-review', 'reuse-review'), request()), null);
  const reuse = result('p12-reuse'); reuse.reused.sourceP12.recordId = 'a'.repeat(32); assert.equal(parseAppleP12Result(reuse, request('p12-reuse')), null);
  const bad = result('p12-save'); bad.output.frameBytes--; assert.equal(parseAppleP12Result(bad, request('p12-save')), null);
  for (const field of ['p12Saved', 'profileSaved', 'credentialReady', 'revocationChecked']) assert.equal(parseAppleP12Result({ ...result(), [field]: true }, request()), null);
  let getter = false; const hostile = { ...result() }; Object.defineProperty(hostile, 'certificateId', { enumerable: true, get() { getter = true; return 'bad'; } });
  assert.equal(parseAppleP12Result(hostile, request()), null); assert.equal(getter, false);
});

test('Asset relay admits only the native assemble enum with original save phases and no manual preview or session mode', () => {
  const raw = usingKey().status; assert.ok(parseAssetStatus(raw));
  for (const phase of ['selected', 'preview', 'picking', 'assessing']) assert.equal(parseAssetStatus({ ...raw, operation: { ...raw.operation, phase } }), null);
  assert.equal(parseAssetStatus({ ...raw, operation: { ...raw.operation, selectionToken: '1'.repeat(32) } }), null);
  assert.equal(parseAssetStatus({ ...raw, mode: 'session', persistence: null }), null);
  assert.equal(parseAssetStatus({ ...raw, operation: { ...raw.operation, operation: 'assemble-any-key' } }), null);
});

test('reuse derives only current bound P12; unavailable assignment never falls back to assembly or a stored-row selection', () => {
  const a = assets(true); assert.equal(appleP12InputBase(project(), a, key).p12RecordRevision, 4);
  const storedOnly = clone(a); storedOnly.status.assignments.pop(); storedOnly.status.records.at(-1).availability = 'unassigned';
  assert.equal(appleP12InputBase(project(), storedOnly, key).p12RecordId, null);
  a.status.assignments.at(-1).availability = 'unavailable'; assert.equal(appleP12InputBase(project(), a, key), null);
  const changed = assets(true); changed.status.records.at(-1).revision++; assert.equal(appleP12InputBase(project(), changed, key), null);
  assert.equal(appleP12InputBase({ ...project(), dirtyDraft: true }, assets(), key), null);
  assert.equal(appleP12InputBase(project(), assets(), null), null);
});

test('same retained native assemble/use operations correlate only already-started inputs, never new admission', () => {
  for (const [mode, bound, name] of [['p12-save', false, 'assemble-apple-p12'], ['p12-reuse', true, 'use-apple-distribution-key']]) {
    const original = appleP12InputBase(project(), assets(bound), key), active = usingKey(assets(bound), name);
    assert.equal(appleP12InputBase(project(), active, key), null);
    assert.deepEqual(retainedAppleP12Input(project(), active, key, original, mode), original);
    active.status.operation.phase = 'unknown'; assert.equal(retainedAppleP12Input(project(), active, key, original, mode), null);
  }
  assert.equal(retainedAppleP12Input(project(), usingKey(), key, appleP12InputBase(project(), assets(), key), 'p12-review'), null);
});

test('actual controller waits for original Start return and subsequent status even when terminal event/read arrives first', async t => {
  const h = harness(t); await h.ready; h.select(); assert.equal(h.calls.length, 0);
  await h.controller.prepare('p12-save'); assert.equal(h.calls.length, 0);
  const op = await prepared(h); await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.length, 1);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1), terminal = status(3, complete(op));
  h.emit(terminal); await h.controller.checkStatus();
  assert.equal(h.state.p12ReviewReference, null); assert.equal(h.state.p12Result, null); assert.equal(h.state.retained, true);
  h.reply(call, terminal); await work; assert.deepEqual(h.state.p12ReviewReference, identity('1'));
  assert.equal(h.state.retained, false); assert.equal(h.calls.length, 2);
});

test('joined reuse review continues only exact existing P12, never new save; completion does not assign or create a saved marker', async t => {
  const h = harness(t, true); await reviewed(h, result('p12-review', 'reuse-review'));
  await h.controller.prepare('p12-save'); assert.equal(h.calls.length, 2);
  const op = await prepared(h, 'p12-reuse', '2', 4); assert.deepEqual(h.calls.at(-1).request.reference, identity('1'));
  assert.equal(h.calls.at(-1).request.p12RecordRevision, 4);
  await started(h, op, complete(op, result('p12-reuse')), 5);
  assert.equal(h.state.savedP12, null); assert.equal(h.state.p12Result.decision, 'reused'); assert.equal(h.state.p12ReviewReference, null);
});

test('original review age caps separate save consent and cannot be renewed by Check', async t => {
  const h = harness(t); await reviewed(h); h.time(299900); await h.controller.checkStatus();
  const op = await prepared(h, 'p12-save', '2', 4); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  h.time(300100); await h.controller.start(op.operationId, op.ownerGeneration);
  assert.equal(h.calls.filter(c => c.kind === 'start').length, 1); assert.ok(h.state.startReason);
});

test('P12/key/source drift and synchronous ABA retire the exact review before any save Prepare', async t => {
  const h = harness(t); await reviewed(h); const old = h.assets;
  let once = true; const off = h.controller.subscribe(() => {
    if (!once) return; once = false; h.replaceAssets(assets(true)); h.replaceAssets(old);
  });
  await h.controller.prepare('p12-save'); off(); assert.equal(h.calls.length, 2); assert.equal(h.state.p12ReviewReference, null);
  const h2 = harness(t, true); await reviewed(h2, result('p12-review', 'reuse-review'));
  const a = h2.assets; a.status.assignments.at(-1).recordRevision++; a.status.records.at(-1).revision++; h2.replaceAssets(a);
  await h2.controller.prepare('p12-reuse'); assert.equal(h2.calls.length, 2);
  const h3 = harness(t); await reviewed(h3); const keyChanged = h3.assets; keyChanged.status.records[1].revision++;
  h3.replaceAssets(keyChanged); await h3.controller.prepare('p12-save'); assert.equal(h3.calls.length, 2);
  const h4 = harness(t); await reviewed(h4); h4.replaceProject({ ...h4.project, baselineGeneration: h4.project.baselineGeneration + 1 });
  await h4.controller.prepare('p12-save'); assert.equal(h4.calls.length, 2);
});

test('saved P12 in an early terminal event cannot publish success before the same save invocation and final read return', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'p12-save', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  const terminal = status(5, { ...complete(op), savedP12: savedRef() });
  h.emit(terminal); await h.controller.checkStatus();
  assert.equal(h.state.savedP12, null); assert.equal(h.state.p12Result, null); assert.equal(h.state.requestPending, true);
  h.reply(call, terminal); await work;
  assert.deepEqual(clone(h.state.savedP12), savedRef()); assert.equal(h.state.p12Result.decision, 'assembled');
  assert.equal(h.state.retained, false); assert.equal(h.state.p12ReviewReference, null);
});

test('original save survives credential busy projection; context retirement keeps original Check/Cancel and pending invocation', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'p12-save', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true); const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  h.replaceAssets(usingKey()); assert.equal(h.state.historical, false); assert.equal(h.state.requestPending, true);
  h.replaceProject({ ...h.project, projectId: '_other' }); await flush();
  assert.equal(h.state.retained, true); assert.ok(h.calls.some(c => c.kind === 'cancel')); assert.equal(h.state.canRead, true);
  const stop = h.calls.find(c => c.kind === 'cancel'); h.reply(call, status(5, cancelled(op))); h.reply(stop, status(5, cancelled(op)));
  await work; await flush(); assert.equal(h.state.savedP12, null); assert.equal(h.state.p12ReviewReference, null);
});

test('lost save acknowledgement and actual Unknown retain the original owner and cannot restore review or accept a saved marker', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'p12-save', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true); const work = h.controller.start(op.operationId, op.ownerGeneration);
  h.emit(status(5, unknown(op), 'cleanup-unknown')); h.calls.find(c => c.kind === 'start' && c.request.operationId === op.operationId).reject(Error('lost'));
  await work; assert.ok(h.state.issue); assert.equal(h.state.retained, true); assert.equal(h.state.savedP12, null);
  const count = h.calls.length; await h.controller.prepare('p12-save'); assert.equal(h.calls.length, count);
  let connected = false; await h.controller.connect({ ...h.api, subscribe: async () => { connected = true; return () => {}; } });
  assert.equal(connected, false); assert.equal(h.state.canRead, true);
  assert.equal(parseAppleProvisioningStatus(status(6, { ...unknown(op), savedP12: savedRef() }, 'cleanup-unknown')), null);
});

test('known cancellation may preserve a genuinely saved P12 but result/output alone never becomes saved or ready', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'p12-save', '2', 4);
  await started(h, op, { ...cancelled(op), savedP12: savedRef() }, 5);
  assert.deepEqual(clone(h.state.savedP12), savedRef()); assert.equal(h.state.p12Result, null);
  assert.match(appleP12Copy(null, h.state.savedP12, 'cancelled').title, /stopped/);
  assert.match(appleP12Copy(result('p12-save'), null, 'complete').title, /not confirmed/);
  assert.equal(parseAppleProvisioningStatus(status(6, { ...complete(op, result('p12-save', 'blocked')), savedP12: savedRef() })), null);
  assert.ok(parseAppleProvisioningStatus(status(6, complete(op)))); // optional/withdrawn metadata, not a success claim
  assert.equal(parseAppleProvisioningStatus(status(6, { ...complete(operation(request('p12-reuse')), result('p12-reuse')), savedP12: savedRef() })), null);
});

test('terminal saved metadata can only withdraw, never appear late, change reference, or rewrite original result', () => {
  const op = complete(operation(request('p12-save'))), saved = { ...op, savedP12: savedRef() };
  assert.ok(parseAppleProvisioningStatus(status(3, saved))); assert.equal(appleProvisioningProgress(saved, op), true);
  assert.equal(appleProvisioningProgress(op, saved), false);
  assert.equal(appleProvisioningProgress(saved, { ...saved, savedP12: { ...savedRef(), recordId: 'a'.repeat(32) } }), false);
  assert.equal(appleProvisioningProgress(saved, { ...op, result: result('p12-save', 'blocked') }), false);
});
