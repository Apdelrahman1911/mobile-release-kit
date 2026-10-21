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
import { appleP12FingerprintView, applyAppleP12Fingerprint } from '../src/appleP12Fingerprint.ts';
import { initialWorkspace, isDirty, reviewFresh, workspaceReducer } from '../src/drafts.ts';
import { getValue } from '../src/catalog.ts';

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

const fingerprintPath = 'ios.distributionCertificateSha256', fingerprint = 'ab'.repeat(32);
function fingerprintResult(mode) {
  const value = result(mode); value.certificateSha256 = fingerprint;
  if (value.output) value.output.certificateSha256 = fingerprint;
  return value;
}
// The existing Apple promise fixture above plus the actual workspace reducer.
// This only models App's synchronous retirement -> reducer -> sync ordering;
// there is no settings writer, fake save result or extra execution owner.
function settingsDraft(h, ios = { enabled: true, bundleId: 'com.example.fixture' }) {
  const projectId = h.project.projectId, selected = { id: projectId, name: 'Fixture', path: '/inert/p12-fingerprint' };
  const snapshot = { root: selected.path, observedAt: '2026-10-21T00:00:00Z', observationScope: 'single-request-non-atomic',
    config: { state: 'format-valid', path: 'release/mobile-release.json', content: clone(h.project.savedConfig),
      data: { ios, android: { enabled: false }, source: { candidateBranch: 'main' } }, issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
      gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' }, issues: [] };
  const d = { workspace: workspaceReducer(initialWorkspace, { type: 'select', project: selected }),
    service: {}, epoch: 1, preview: false, reason: null, commits: [],
    catalog: { fields: [{ path: fingerprintPath, input: 'text' }] } };
  d.reduce = action => { const old = d.workspace; d.workspace = workspaceReducer(old, action); return old !== d.workspace; };
  d.reduce({ type: 'snapshot-start', projectId, requestId: 1 });
  d.reduce({ type: 'snapshot-done', projectId, requestId: 1, snapshot, observedAt: 1 });
  d.context = () => ({ controller: h.controller, session: d.workspace.projects[d.workspace.selectedId] ?? null,
    catalog: d.catalog, service: d.service, epoch: d.epoch, preview: d.preview, reason: d.reason });
  d.sync = () => { const s = d.context().session; h.replaceProject({ ...h.project, projectId: s.project.id,
    draftRevision: s.revision, baselineGeneration: s.baselineGeneration, observationGeneration: s.observationGeneration,
    savedConfig: s.savedConfigContent, dirtyDraft: isDirty(s), snapshotPending: s.snapshotRequest !== null,
    saveRecoveryRequired: s.saveRecoveryRequired || s.saveRecoveryNeedsReload }); };
  d.commit = action => { d.commits.push(action); h.controller.beforeWorkspaceAction();
    const changed = d.reduce(action); if (changed) d.sync(); return changed; };
  d.view = () => appleP12FingerprintView(d.context());
  d.sync(); return d;
}
async function savedFingerprint(h) {
  await reviewed(h, fingerprintResult('p12-review'));
  const op = await prepared(h, 'p12-save', '2', 4);
  await started(h, op, { ...complete(op, fingerprintResult('p12-save')), savedP12: savedRef() }, 5);
  return op;
}

test('fingerprint explicit handoff edits one empty field with the real reducer; baseline, reviews and Save remain separate', async t => {
  for (const empty of [undefined, '']) {
    const h = harness(t); await h.ready;
    const d = settingsDraft(h, { enabled: true, bundleId: 'com.example.fixture', ...(empty === undefined ? {} : { distributionCertificateSha256: empty }) });
    await savedFingerprint(h);
    let s = d.context().session;
    d.reduce({ type: 'review-start', projectId: s.project.id, binding: { id: 1, revision: s.revision, baselineGeneration: s.baselineGeneration } });
    d.reduce({ type: 'review-done', projectId: s.project.id, requestId: 1, result: { fields: [{ path: fingerprintPath, state: 'optional' }] } });
    s = d.context().session; assert.equal(reviewFresh(s), true);
    const view = d.view(), callCount = h.calls.length, stateBefore = h.state;
    assert.equal(view.certificateSha256, fingerprint); assert.ok(view.edit); assert.equal(d.commits.length, 0);
    assert.equal(h.state, stateBefore, 'render does not sync, invalidate or invoke anything');
    assert.equal(applyAppleP12Fingerprint(view.edit, d.context, d.commit), true);
    const after = d.context().session;
    assert.equal(getValue(after.draft, fingerprintPath), fingerprint);
    assert.equal(after.draft.ios.bundleId, s.draft.ios.bundleId); assert.equal(after.draft.android, s.draft.android);
    assert.equal(after.baseline, s.baseline); assert.equal(after.snapshot, s.snapshot); assert.equal(after.savedConfigContent, s.savedConfigContent);
    assert.equal(after.revision, s.revision + 1); assert.equal(after.baselineGeneration, s.baselineGeneration);
    assert.equal(after.review, s.review); assert.equal(reviewFresh(after), false); assert.equal(after.lastSave, null);
    assert.equal(after.reviewRequest, null); assert.equal(after.validationRequest, null); assert.equal(isDirty(after), true);
    assert.equal(d.commits.length, 1); assert.equal(d.commits[0].type, 'edit'); assert.equal(d.commits[0].expectedSession, s);
    assert.equal(h.calls.length, callCount, 'no new native operation, Review, Save or assignment');
    assert.equal(h.state.historical, true, 'ordinary edit intentionally retires the old Apple comparison');
    assert.equal(applyAppleP12Fingerprint(view.edit, d.context, d.commit), false); assert.equal(d.commits.length, 1);
  }
});

test('fingerprint never overwrites equal, conflicting, malformed or non-string existing settings', async t => {
  for (const value of [fingerprint, fingerprint.toUpperCase(), Array(32).fill('AB').join(':'),
    'cd'.repeat(32), ` ${fingerprint}`, `${fingerprint}\n`, ' ', 'AB:CD', null, 17, [], {}]) {
    const h = harness(t); await h.ready; const d = settingsDraft(h, { enabled: true, distributionCertificateSha256: value });
    await savedFingerprint(h); const before = d.context().session, view = d.view();
    assert.equal(view.edit, null); assert.equal(view.certificateSha256, fingerprint); assert.ok(view.reason);
    if ([fingerprint, fingerprint.toUpperCase(), Array(32).fill('AB').join(':')].includes(value)) assert.match(view.reason, /already/);
    assert.equal(d.context().session, before); assert.deepEqual(getValue(before.draft, fingerprintPath), value); assert.equal(d.commits.length, 0);
  }
});

test('fingerprint needs actual Start return and final read; event output or known-cancel saved metadata is not a source', async t => {
  const h = harness(t); await h.ready; const d = settingsDraft(h);
  await reviewed(h, fingerprintResult('p12-review')); assert.equal(d.view().edit, null);
  const op = await prepared(h, 'p12-save', '2', 4); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  const terminal = status(5, { ...complete(op, fingerprintResult('p12-save')), savedP12: savedRef() });
  h.emit(terminal); await h.controller.checkStatus();
  assert.equal(d.view().certificateSha256, null); assert.equal(d.view().edit, null); assert.equal(d.commits.length, 0);
  h.reply(call, terminal); await work; assert.ok(d.view().edit);
  const h2 = harness(t); await h2.ready; const d2 = settingsDraft(h2); await reviewed(h2);
  const cancelledOp = await prepared(h2, 'p12-save', '2', 4); await started(h2, cancelledOp, { ...cancelled(cancelledOp), savedP12: savedRef() }, 5);
  assert.ok(h2.state.savedP12); assert.equal(d2.view().certificateSha256, null); assert.equal(d2.view().edit, null);
});

test('fingerprint output without a saved reference, withdrawal and Unknown cannot supply a draft edit', async t => {
  const h = harness(t); await h.ready; const d = settingsDraft(h); await reviewed(h);
  const op = await prepared(h, 'p12-save', '2', 4); await started(h, op, complete(op, fingerprintResult('p12-save')), 5);
  assert.equal(d.view().certificateSha256, null); assert.equal(d.view().edit, null);
  const h2 = harness(t); await h2.ready; const d2 = settingsDraft(h2), saved = await savedFingerprint(h2), edit = d2.view().edit;
  h2.emit(status(6, complete(saved, fingerprintResult('p12-save'))));
  assert.equal(d2.view().certificateSha256, null); assert.equal(applyAppleP12Fingerprint(edit, d2.context, d2.commit), false);
  const h3 = harness(t); await h3.ready; const d3 = settingsDraft(h3), original = await savedFingerprint(h3), before = d3.view().edit;
  h3.emit(status(6, unknown(original), 'cleanup-unknown'));
  assert.equal(d3.view().edit, null); assert.equal(applyAppleP12Fingerprint(before, d3.context, d3.commit), false); assert.equal(d3.commits.length, 0);
});

test('fingerprint explicit click syncs unnotified project and asset drift rather than trusting an old snapshot', async t => {
  for (const change of [h => h.replaceProject({ ...h.project, observationGeneration: h.project.observationGeneration + 1 }, false),
    h => { const a = h.assets; a.status.records[1].revision++; h.replaceAssets(a, false); }]) {
    const h = harness(t); await h.ready; const d = settingsDraft(h); await savedFingerprint(h);
    const edit = d.view().edit, before = h.state; change(h);
    assert.equal(h.state, before); assert.ok(d.view().edit, 'render is only a provisional comparison');
    assert.equal(applyAppleP12Fingerprint(edit, d.context, d.commit), false);
    assert.equal(h.state.historical, true); assert.equal(d.commits.length, 0);
  }
});

test('fingerprint pending manual read, retired connection and historical result stay comparison-only', async t => {
  const h = harness(t); await h.ready; const d = settingsDraft(h); await savedFingerprint(h);
  const original = clone(h.state.status), edit = d.view().edit, poll = deferred(); h.reads.push(poll);
  const work = h.controller.checkStatus(); assert.equal(h.state.reading, true); assert.equal(d.view().edit, null);
  assert.equal(applyAppleP12Fingerprint(edit, d.context, d.commit), false);
  poll.resolve(original); await work; assert.ok(d.view().edit);
  h.controller.beforeWorkspaceAction(); assert.equal(h.state.historical, true); assert.equal(d.view().certificateSha256, fingerprint); assert.equal(d.view().edit, null);
  h.controller.beginConnection(); assert.equal(d.view().edit, null); assert.equal(d.commits.length, 0);
});

test('fingerprint click rematches synchronous status, cancellation, peer and project/service ABA notifications', async t => {
  for (const change of [
    (h, _d) => h.controller.cancel(),
    (h, _d) => { const a = h.assets; h.replaceAssets(assets(true)); h.replaceAssets(a); },
    (h, _d) => h.emit({ ...clone(h.state.status), statusRevision: h.state.status.statusRevision + 1 }),
    (_h, d) => { d.service = {}; }, (_h, d) => { d.epoch++; },
    (_h, d) => { d.reason = 'Wait for the original configuration save.'; },
    (_h, d) => { d.reduce({ type: 'select', project: { id: '_other', name: 'Other', path: '/inert/other' } }); d.reduce({ type: 'switch', projectId: '_p12_fixture' }); d.epoch++; },
    (_h, d) => { d.reduce({ type: 'edit', projectId: '_p12_fixture', path: 'ios.bundleId', value: 'com.example.newer' }); },
  ]) {
    const h = harness(t); await h.ready; const d = settingsDraft(h); await savedFingerprint(h); const edit = d.view().edit;
    let once = true; const off = h.controller.subscribe(() => { if (!once) return; once = false; change(h, d); });
    assert.equal(applyAppleP12Fingerprint(edit, d.context, d.commit), false); off(); await flush();
    assert.equal(d.commits.length, 0); assert.equal(getValue(d.context().session.draft, fingerprintPath), undefined);
  }
});

test('fingerprint expectedSession rejects a newer draft created during ordinary edit retirement', async t => {
  const h = harness(t); await h.ready; const d = settingsDraft(h); await savedFingerprint(h); const edit = d.view().edit;
  let once = true; const off = h.controller.subscribe(() => {
    if (!once || !h.state.historical) return; once = false;
    d.reduce({ type: 'edit', projectId: '_p12_fixture', path: fingerprintPath, value: 'cd'.repeat(32) });
  });
  assert.equal(applyAppleP12Fingerprint(edit, d.context, d.commit), false); off();
  assert.equal(d.commits.length, 1, 'attempted ordinary action still goes through the reducer');
  assert.equal(getValue(d.context().session.draft, fingerprintPath), 'cd'.repeat(32));
  assert.notEqual(d.context().session, edit.context.session); assert.equal(d.context().session.lastSave, null);
});

test('fingerprint refuses dirty, stale, missing or recovering Settings and unsupported parent/catalog without changing data', async t => {
  for (const change of [
    d => { d.preview = true; }, d => { d.service = null; }, d => { d.catalog = { fields: [] }; },
    d => { d.reason = 'An original operation is unconfirmed.'; }, d => { d.epoch = Number.MAX_SAFE_INTEGER; },
    d => d.reduce({ type: 'edit', projectId: '_p12_fixture', path: 'ios.bundleId', value: 'com.example.other' }),
    d => d.reduce({ type: 'snapshot-start', projectId: '_p12_fixture', requestId: 2 }),
    d => d.reduce({ type: 'git-local-intent', projectId: '_p12_fixture' }),
    d => { d.context().session.saveRecoveryRequired = true; }, d => { d.context().session.saveRecoveryNeedsReload = true; },
    d => { d.context().session.sourceChanged = true; }, d => { d.context().session.snapshot.root = '/inert/foreign'; },
    d => { d.context().session.savedConfigContent = { bytes: 100, sha256: 'b'.repeat(64) }; },
    d => { const s = d.context().session; d.reduce({ type: 'review-start', projectId: s.project.id, binding: { id: 1, revision: s.revision, baselineGeneration: s.baselineGeneration } }); },
    d => { const s = d.context().session; d.reduce({ type: 'review-start', projectId: s.project.id, binding: { id: 1, revision: s.revision, baselineGeneration: s.baselineGeneration } });
      d.reduce({ type: 'review-done', projectId: s.project.id, requestId: 1, result: { fields: [{ path: fingerprintPath, state: 'forbidden' }] } }); },
  ]) {
    const h = harness(t); await h.ready; const d = settingsDraft(h); await savedFingerprint(h);
    const edit = d.view().edit; assert.ok(edit); change(d); const before = clone(d.context().session.draft);
    assert.equal(d.view().edit, null); assert.equal(applyAppleP12Fingerprint(edit, d.context, d.commit), false);
    assert.deepEqual(d.context().session.draft, before); assert.equal(d.commits.length, 0);
  }
  const h = harness(t); await h.ready; const d = settingsDraft(h, 'unsupported parent'); await savedFingerprint(h);
  assert.equal(d.view().edit, null); assert.equal(d.context().session.draft.ios, 'unsupported parent');
});
