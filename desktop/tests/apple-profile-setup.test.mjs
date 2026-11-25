// Actual controller/parsers with inert promises and comparison DATA only.
// No native owner, key, provider, file picker or cryptographic call is made.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { appleProvisioningContext, appleProvisioningConsent, appleProvisioningProgress,
  encodeAppleProvisioningRequest, parseAppleProvisioningRequest, parseAppleProvisioningStatus } from '../src/appleProvisioningProtocol.ts';
import { APPLE_PROFILE_LIMITATIONS, appleProfileInputBase, retainedAppleProfileInput,
  parseAppleProfileSetupResult, appleProfileResultCopy } from '../src/appleProfileSetup.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';

const clone = value => structuredClone(value);
const id = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'f'.repeat(32) });
const saved = () => ({ vaultId: '1'.repeat(32), generationId: '2'.repeat(32), recordId: '3'.repeat(32), revisionId: '4'.repeat(32), revisionCounter: 1 });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const project = () => ({ projectId: '_fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
  dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null });
function assets() {
  const scope = { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'provisioning' };
  return { mode: 'native', scope, contextCurrent: true, busy: null, updatingContext: false, observationFailed: false,
    blocked: false, originPending: false, entryGeneration: 1,
    status: { schemaVersion: 3, statusRevision: 1, mode: 'encrypted',
      persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { available: true, reason: 'none' },
      modes: { encrypted: { available: true, reason: 'none' }, session: { available: true, reason: 'none' } }, operation: null,
      context: { revision: 3, projectId: '_fixture', ...scope },
      assignments: ['asc-p8', 'apple-p12'].map((kind, i) => ({ kind, recordId: (i ? 'd' : 'c').repeat(32), recordRevision: 4,
        contextRevision: 3, availability: 'available' })),
      records: ['asc-p8', 'apple-p12'].map((kind, i) => ({ kind, recordId: (i ? 'd' : 'c').repeat(32), revision: 4,
        availability: 'assigned', storage: 'encrypted', label: null, payloadState: 'assessed' })) } };
}
const request = (mode = 'profile-review') => ({ ...appleProfileInputBase(project(), assets()), mode,
  reference: mode === 'profile-review' ? null : id('1'), newApplication: false, displayName: 'Existing App' });
const status = (revision = 1, operation = null, availability = operation && operation.phase !== 'terminal' ? 'busy' : 'available') =>
  ({ schemaVersion: 1, statusRevision: revision, availability, operation });
const operation = (input, digit = '1') => ({ ...id(digit), context: appleProvisioningContext(clone(input)), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const result = (mode = 'profile-review', decision = 'reuse-available', reason = 'reuse-existing-profile') => ({ schemaVersion: 1,
  scope: 'local-ios-profile-setup', mode, decision, reason, bundleId: 'example.test',
  profileResourceId: decision === 'download-returned' ? 'profile-1' : null,
  profileUuid: decision === 'download-returned' ? '12345678-1234-1234-1234-123456789ABC' : null,
  saved: false, credentialReady: false, cancellationRequested: false, limitations: [...APPLE_PROFILE_LIMITATIONS] });
const complete = (op, value = result(op.context.mode)) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result: value });
const cancelled = op => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null });
function harness(t) {
  let p = project(), a = assets(), native = status(), now = 100;
  const calls = [], readQueue = [], listeners = [];
  const call = (kind, value) => { const row = { kind, request: clone(value), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native', subscribe: async receive => { const entry = { receive, closed: false }; listeners.push(entry); return () => { entry.closed = true; }; },
    status: () => readQueue.shift()?.promise ?? Promise.resolve(clone(native)), prepare: value => call('prepare', value),
    start: value => call('start', value), cancel: value => call('cancel', value) };
  const controller = new AppleProvisioningController({ project: () => p, assets: () => a, otherOperationReason: () => null, now: () => now });
  controller.setVisible(true); controller.setDisplayName('Existing App');
  const ready = controller.connect(api); t.after(() => controller.dispose());
  return { controller, api, ready, calls, readQueue,
    get state() { return controller.getSnapshot(); }, get assets() { return a; },
    reply(row, value) { native = clone(value); row.resolve(clone(value)); },
    emit(value) { native = clone(value); for (const row of listeners) if (!row.closed) row.receive(clone(value)); },
    replaceAssets(value) { a = value; controller.syncProject(); }, replaceProject(patch) { p = { ...p, ...patch }; controller.syncProject(); },
    time(value) { now = value; } };
}
async function prepared(h, mode = 'profile-review', digit = '1', revision = 2) {
  await h.ready; const work = h.controller.prepare(mode), call = h.calls.at(-1);
  assert.equal(call?.kind, 'prepare'); const op = operation(call.request, digit);
  h.reply(call, status(revision, op)); await work;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function reviewed(h, choice = 'reuse') {
  const op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration);
  h.reply(h.calls.at(-1), status(3, complete(op, choice === 'reuse' ? result() : result('profile-review', 'create-available', 'profile-create-review'))));
  await work; assert.deepEqual(h.state.profileReviewReference, id('1')); return op;
}

test('profile request is closed, requires P12 and has separate consent on the existing four commands', () => {
  for (const mode of ['profile-review', 'profile-reuse', 'profile-create', 'profile-reconcile']) {
    assert.ok(parseAppleProvisioningRequest(request(mode)));
    assert.ok(encodeAppleProvisioningRequest('start_apple_provisioning', { ...id('1'), consentVersion: appleProvisioningConsent(mode) }));
    assert.equal(appleProvisioningConsent(mode), `local-ios-${mode}-v1`);
    const absent = request(mode); delete absent.p12RecordId; assert.equal(parseAppleProvisioningRequest(absent), null);
  }
  const old = request(); old.mode = 'review'; assert.equal(parseAppleProvisioningRequest(old), null);
  delete old.p12RecordId; delete old.p12RecordRevision; assert.ok(parseAppleProvisioningRequest(old));
  for (const extra of ['privateKey', 'profileContent', 'nativeJoined', 'savePermit', 'accountRef']) {
    assert.equal(parseAppleProvisioningRequest({ ...request(), [extra]: 'not-authority' }), null);
  }
  assert.equal(parseAppleProvisioningRequest({ ...request('profile-create'), newApplication: true }), null);
});

test('profile result cannot turn provider data into saved/assigned readiness; exact NEW reference is separate', () => {
  assert.ok(parseAppleProfileSetupResult(result(), 'profile-review'));
  assert.ok(parseAppleProfileSetupResult({ ...result(), bundleId: '-app.example-' }, 'profile-review'));
  for (const field of ['saved', 'credentialReady']) assert.equal(parseAppleProfileSetupResult({ ...result(), [field]: true }, 'profile-review'), null);
  assert.equal(parseAppleProfileSetupResult({ ...result(), certificateContent: 'untrusted' }, 'profile-review'), null);
  assert.equal(parseAppleProfileSetupResult(result('profile-create', 'reuse-available'), 'profile-create'), null);
  const op = complete(operation(request('profile-create')), result('profile-create', 'download-returned', 'profile-returned'));
  assert.ok(parseAppleProvisioningStatus(status(4, op)));
  assert.ok(parseAppleProvisioningStatus(status(4, { ...op, savedProfile: saved() })));
  for (const change of [{ revisionCounter: 2 }, { recordId: 'c'.repeat(32) }, { recordId: 'd'.repeat(32) }, { revisionId: '1'.repeat(32) }]) {
    assert.equal(parseAppleProvisioningStatus(status(4, { ...op, savedProfile: { ...saved(), ...change } })), null);
  }
  const wrong = complete(operation(request()), result()); wrong.savedProfile = saved();
  assert.equal(parseAppleProvisioningStatus(status(4, wrong)), null);
  assert.match(appleProfileResultCopy(op.result, null).title, /not confirmed/);
  assert.match(appleProfileResultCopy(op.result, saved()).detail, /not assigned automatically/);
  const before = { ...op, savedProfile: saved() };
  assert.equal(appleProvisioningProgress(before, op), true);
  assert.equal(appleProvisioningProgress(op, before), false);
});

test('dedicated provisioning scope requires current encrypted P8 and P12; old scope and metadata cannot substitute', () => {
  assert.ok(parseAssetStatus(assets().status)); assert.ok(appleProfileInputBase(project(), assets()));
  for (const change of ['session', 'store', 'signing', 'missing-p12', 'unavailable', 'duplicate', 'wrong-record', 'dirty']) {
    const a = assets(), p = project();
    if (change === 'session') a.status.mode = 'session';
    if (change === 'store' || change === 'signing') { a.scope.purpose = change; a.status.context.purpose = change; }
    if (change === 'missing-p12') a.status.assignments.pop();
    if (change === 'unavailable') a.status.assignments[1].availability = 'unavailable';
    if (change === 'duplicate') a.status.assignments.push(clone(a.status.assignments[1]));
    if (change === 'wrong-record') a.status.records[1].revision++;
    if (change === 'dirty') p.dirtyDraft = true;
    assert.equal(appleProfileInputBase(p, a), null, change);
  }
});

test('original profile Asset mutation is comparison-only, not a new admission or a different key match', () => {
  const a = assets(), original = appleProfileInputBase(project(), a);
  a.contextCurrent = false; a.status.persistence.state = 'mutating';
  a.status.operation = { operationId: 5, operation: 'apple-profile-setup', phase: 'mutating', reason: 'none', source: 'captured',
    settlement: 'pending', storageOutcome: { effect: 'not-started', durability: 'not-run', cleanup: 'pending' }, selectionToken: null, assessment: null, preview: null };
  for (const row of a.status.assignments) row.availability = 'unavailable';
  assert.ok(parseAssetStatus(a.status)); assert.equal(appleProfileInputBase(project(), a), null);
  assert.deepEqual(retainedAppleProfileInput(project(), a, original), original);
  for (const change of ['other', 'unknown', 'key', 'context']) {
    const b = clone(a);
    if (change === 'other') b.status.operation.operation = 'import-backup';
    if (change === 'unknown') b.status.operation.settlement = 'unknown';
    if (change === 'key') { b.status.assignments[1].recordRevision++; b.status.records[1].revision++; }
    if (change === 'context') b.status.context.revision++;
    assert.equal(retainedAppleProfileInput(project(), b, original), null, change);
  }
});

test('exact review choice is usable only after Start reply and an original post-invoke terminal read', async t => {
  const h = harness(t), op = await prepared(h); assert.notEqual(h.state.reviewReason, null);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  h.emit(status(4, complete(op))); assert.equal(h.state.profileReviewReference, null); assert.equal(h.state.profileResult, null);
  const read = deferred(); h.readQueue.push(read); call.resolve(status(3, { ...op, phase: 'running', intentUsable: false })); await flush();
  assert.equal(h.state.profileReviewReference, null); assert.equal(h.state.reading, true);
  read.resolve(status(4, complete(op))); await work;
  assert.deepEqual(h.state.profileReviewReference, id('1')); assert.equal(h.state.profileReuseReason, null); assert.notEqual(h.state.profileCreateReason, null);
  await h.controller.prepare('profile-create'); assert.equal(h.calls.filter(c => c.kind === 'prepare').length, 1);
  const reuse = await prepared(h, 'profile-reuse', '2', 5);
  assert.equal(h.state.profileReviewReference, null); assert.equal(h.state.consent.acknowledged, false);
  assert.deepEqual(h.calls.at(-1).request.reference, id('1'));
  await h.controller.start(reuse.operationId, reuse.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 1);
});

test('same started profile survives its own temporary assignment unavailability, then reports separate saved DATA', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'profile-reuse', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  const a = assets(); a.contextCurrent = false; a.status.persistence.state = 'mutating';
  a.status.operation = { operationId: 5, operation: 'apple-profile-setup', phase: 'mutating', settlement: 'pending' };
  for (const row of a.status.assignments) row.availability = 'unavailable';
  h.replaceAssets(a);
  assert.equal(h.state.cancelRequested, false); assert.equal(h.state.historical, false);
  assert.equal(h.calls.filter(c => c.kind === 'cancel').length, 0);
  const done = complete(op, result('profile-reuse', 'download-returned', 'profile-returned')); done.savedProfile = saved();
  h.replaceAssets(assets()); h.reply(call, status(5, done)); await work;
  assert.deepEqual({ ...h.state.savedProfile }, saved()); assert.equal(h.state.profileResult.credentialReady, false);
  assert.equal(h.state.profileReviewReference, null); assert.equal(h.state.retained, false);
  const withdrawn = clone(done); delete withdrawn.savedProfile;
  h.emit(status(6, withdrawn)); assert.equal(h.state.savedProfile, null); assert.equal(h.state.issue, null);
  h.emit(status(7, { ...withdrawn, savedProfile: undefined })); // undefined is not a valid native omission.
  assert.equal(h.state.issue, 'protocol');
});

test('changed P12 cancels the actual started original and cannot publish a current review', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  const changed = assets(); changed.status.assignments[1].recordRevision++; changed.status.records[1].revision++;
  h.replaceAssets(changed); const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel'); assert.equal(h.state.consent, null);
  h.reply(cancel, status(4, cancelled(op))); await flush(); call.resolve(status(3, { ...op, phase: 'running', intentUsable: false })); await work;
  assert.equal(h.state.profileReviewReference, null); assert.equal(h.state.historical, true);
});

test('unconfirmed profile request permits only a separate same-reference read, never another POST choice', async t => {
  const h = harness(t); await reviewed(h, 'create'); const op = await prepared(h, 'profile-create', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  assert.equal(call.request.consentVersion, 'local-ios-profile-create-v1');
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 2);
  h.reply(call, status(5, complete(op, result('profile-create', 'creation-unconfirmed', 'provider-unconfirmed')))); await work;
  assert.equal(h.state.profileReconcileReason, null); assert.notEqual(h.state.profileCreateReason, null);
  const read = await prepared(h, 'profile-reconcile', '3', 6); assert.deepEqual(h.calls.at(-1).request.reference, id('2'));
  h.controller.acknowledge(read.operationId, read.ownerGeneration, true);
  const running = h.controller.start(read.operationId, read.ownerGeneration);
  h.reply(h.calls.at(-1), status(7, complete(read, result('profile-reconcile', 'comparison-only', 'not-returned')))); await running;
  assert.equal(h.state.savedProfile, null); assert.equal(h.state.profileReviewReference, null); assert.notEqual(h.state.profileCreateReason, null);
  assert.match(appleProfileResultCopy(h.state.profileResult, null).detail, /cannot confirm/);
});

test('lost original Start is absorbing despite later terminal DATA and does not leak error text', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  call.reject(new Error('INERT-PRIVATE-ERROR')); await flush();
  h.reply(h.calls.at(-1), status(4, cancelled(op))); await flush(); await work;
  assert.ok(h.state.issue); assert.ok(h.state.retained); assert.equal(h.state.profileResult, null);
  await h.controller.prepare('profile-review'); await h.controller.connect({ ...h.api });
  assert.equal(h.calls.filter(c => c.kind === 'prepare').length, 1); assert.ok(h.state.issue);
  assert.equal(JSON.stringify(h.state).includes('INERT-PRIVATE-ERROR'), false);
});

test('synchronous cancellation during profile Prepare publication cannot renew the original intent', async t => {
  const h = harness(t); await h.ready; let once = false;
  const off = h.controller.subscribe(() => { if (!once) { once = true; void h.controller.cancel(); } });
  await h.controller.prepare('profile-review'); off();
  assert.equal(h.calls.length, 0); assert.equal(h.state.cancelRequested, true); assert.equal(h.state.consent, null);
});
