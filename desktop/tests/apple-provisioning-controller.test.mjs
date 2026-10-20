// Real controller/local saved-input helper with synthetic API promises and
// comparison/status DATA. No native account, key, journal or process call.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { APPLE_PROVISIONING_LIMITATIONS, appleProvisioningContext } from '../src/appleProvisioningProtocol.ts';

const copy = value => structuredClone(value);
const id = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'f'.repeat(32) });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const project = () => ({ projectId: 'fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
  dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null });
const assets = () => ({ mode: 'native', scope: { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'store' },
  contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false, entryGeneration: 1,
  status: { mode: 'session', capability: { available: true }, modes: { session: { available: true } }, operation: null,
    context: { revision: 3, projectId: 'fixture', executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'store' },
    assignments: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' }],
    records: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), revision: 4, availability: 'assigned' }] } });
const status = (revision = 1, operation = null, availability = operation && operation.phase !== 'terminal' ? 'busy' : 'available') =>
  ({ schemaVersion: 1, statusRevision: revision, availability, operation });
const operation = (request, digit = '1') => ({ ...id(digit), context: appleProvisioningContext(copy(request)), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const result = (mode, observation = 'not-returned', decision = mode === 'reconcile' ? 'comparison-only' : 'review-required') =>
  ({ schemaVersion: 1, scope: 'local-ios-bundle-provisioning', mode, observation, decision, attempt: null,
    comparison: mode === 'reconcile' ? 'not-returned' : null, limitations: [...APPLE_PROVISIONING_LIMITATIONS] });
const complete = (op, value = result(op.context.mode)) => ({ ...copy(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result: value });
const cancelled = op => ({ ...copy(op), phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null });
function harness(t, initial = status()) {
  let p = project(), a = assets(), native = copy(initial), now = 100, other = null;
  const calls = [], reads = [], readQueue = [], listeners = [];
  const call = (kind, request) => { const row = { kind, request: copy(request), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native',
    subscribe: async receive => { const row = { receive, closed: false }; listeners.push(row); return () => { row.closed = true; }; },
    status: () => { reads.push(copy(native)); return readQueue.shift()?.promise ?? Promise.resolve(copy(native)); },
    prepare: request => call('prepare', request), start: request => call('start', request), cancel: request => call('cancel', request) };
  const controller = new AppleProvisioningController({ project: () => p, assets: () => a, otherOperationReason: () => other, now: () => now });
  controller.setVisible(true); controller.setDisplayName('Explicit new app');
  const ready = controller.connect(api); t.after(() => controller.dispose());
  return { controller, api, calls, reads, listeners, readQueue, ready,
    get state() { return controller.getSnapshot(); }, get native() { return copy(native); }, get assets() { return a; },
    reply(row, value) { native = copy(value); row.resolve(copy(value)); },
    emit(value) { native = copy(value); for (const row of listeners) if (!row.closed) row.receive(copy(value)); },
    nativeStatus(value) { native = copy(value); },
    replaceProject(patch) { p = { ...p, ...patch }; controller.syncProject(); },
    replaceAssets(value) { a = value; controller.syncProject(); },
    time(value) { now = value; }, other(value) { other = value; } };
}
async function prepared(h, mode = 'review', digit = '1', revision = 2) {
  await h.ready; const work = h.controller.prepare(mode), call = h.calls.at(-1);
  assert.equal(call?.kind, 'prepare'); const op = operation(call.request, digit);
  h.reply(call, status(revision, op)); await work; assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function reviewed(h) {
  const op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1); assert.equal(call.kind, 'start');
  h.reply(call, status(3, complete(op))); await work; assert.ok(h.state.reviewReference); assert.equal(h.state.result.decision, 'review-required'); return op;
}

test('status/mount/preview do not prepare local state or contact Apple; unavailable stays unavailable', async t => {
  const h = harness(t, status(1, null, 'runtime-unqualified')); await h.ready;
  await h.controller.checkStatus(); await h.controller.prepare('review'); assert.equal(h.calls.length, 0);
  assert.match(h.state.reviewReason, /unavailable/); assert.equal(h.state.canRead, true);
  const noPort = new AppleProvisioningController({ project, assets, otherOperationReason: () => null });
  noPort.setVisible(true); noPort.setDisplayName('name'); await noPort.connect(null); await noPort.prepare('review');
  assert.equal(noPort.getSnapshot().native, false); noPort.dispose();
});

test('idle status read remains reciprocally owned until its actual response joins', async t => {
  const h = harness(t); await h.ready;
  const original = deferred(); h.readQueue.push(original);
  const work = h.controller.checkStatus();
  assert.equal(h.state.reading, true); assert.equal(h.state.retained, true);
  assert.notEqual(h.controller.ownerReason(), null); // The actual App reconnect gate uses this method.
  assert.equal(h.state.issue, null); assert.equal(h.listeners[0].closed, false);
  await h.controller.prepare('review'); assert.equal(h.calls.length, 0);
  original.resolve(status()); await work;
  assert.equal(h.state.reading, false); assert.equal(h.state.retained, false);
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.state.issue, null);
  // Once the original read really returns, ordinary reconnect remains usable.
  h.controller.beginConnection();
  const oldReads = h.reads.length;
  assert.equal(h.state.canRead, false);
  await h.controller.checkStatus(); assert.equal(h.reads.length, oldReads);
  await h.controller.connect({ ...h.api });
  assert.equal(h.state.issue, null); assert.equal(h.state.initialized, true);
  assert.equal(h.listeners[0].closed, true); assert.equal(h.calls.length, 0);
});

test('actual saved/P8 helper gates dirty/version/wrong-platform and missing assignment', async t => {
  const h = harness(t); await h.ready; assert.equal(h.state.reviewReason, null);
  h.replaceProject({ dirtyDraft: true }); await h.controller.prepare('review'); assert.equal(h.calls.length, 0);
  h.replaceProject({ dirtyDraft: false, versionPending: true }); await h.controller.prepare('review'); assert.equal(h.calls.length, 0);
  h.replaceProject({ versionPending: false }); const android = assets(); android.scope.platform = 'android'; android.status.context.platform = 'android';
  h.replaceAssets(android); await h.controller.prepare('review'); assert.equal(h.calls.length, 0); assert.equal(h.state.ios, false);
  const missing = assets(); missing.status.assignments = []; h.replaceAssets(missing); await h.controller.prepare('review'); assert.equal(h.calls.length, 0);
  h.replaceAssets(assets()); h.other('Another original operation is retained.'); await h.controller.prepare('review'); assert.equal(h.calls.length, 0);
});

test('each exact intent needs its own unchecked consent; no Start replay or wrong-ID use', async t => {
  const h = harness(t), op = await prepared(h);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.length, 1);
  h.controller.acknowledge('9'.repeat(32), op.ownerGeneration, true); assert.equal(h.state.consent.acknowledged, false);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration); const start = h.calls.at(-1);
  assert.equal(start.request.consentVersion, 'local-ios-bundle-review-v1'); assert.equal(h.state.consent, null);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 1);
  h.reply(start, status(3, complete(op, result('review', 'found', 'reuse')))); await work;
  assert.equal(h.state.reviewReference, null); assert.match(h.state.registerReason, /reuse-first review/); assert.equal(h.state.result.decision, 'reuse');
});

test('peer-owner projection refresh does not reset an intent or require changed saved bytes', async t => {
  const h = harness(t); await h.ready;
  h.other('Another original is retained.'); h.controller.syncProject();
  assert.equal(h.state.reviewReason, 'Another original is retained.');
  h.other(null); h.controller.syncProject(); assert.equal(h.state.reviewReason, null);
  const op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  h.other('Another original is retained.'); h.controller.syncProject();
  assert.equal(h.state.startReason, 'Another original is retained.');
  assert.equal(h.state.consent.acknowledged, true);
  h.other(null); h.controller.syncProject(); assert.equal(h.state.startReason, null);
  assert.deepEqual(h.state.consent, { ...id('1'), mode: 'review', acknowledged: true });
  assert.equal(h.calls.length, 1);
});

test('new-application declaration and registration consent are distinct from read consent', async t => {
  const h = harness(t), review = await reviewed(h);
  await h.controller.prepare('register'); assert.equal(h.calls.filter(c => c.kind === 'prepare').length, 1);
  h.controller.setNewApplication(true); const op = await prepared(h, 'register', '2', 4);
  const request = h.calls.at(-1).request; assert.deepEqual(request.reference, id('1')); assert.equal(request.newApplication, true);
  assert.equal(h.state.reviewReference, null); assert.equal(h.state.consent.acknowledged, false);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true); const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  assert.equal(call.request.consentVersion, 'local-ios-bundle-register-v1'); assert.notEqual(call.request.operationId, review.operationId);
  const value = result('register', 'found', 'registration-confirmed'); value.attempt = { operationId: op.operationId, action: 'register_bundle_id', status: 'succeeded',
    reason: 'provider_resource_confirmed', retryAllowed: false, credentialReady: false, cancellationRequested: false };
  h.reply(call, status(5, complete(op, value))); await work;
  assert.equal(h.state.result.attempt.credentialReady, false); assert.equal(h.state.reviewReference, null);
  await h.controller.prepare('register'); assert.equal(h.calls.filter(c => c.kind === 'start').length, 2);
});

test('terminal event before Start reply does not settle request or expose a registration review', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  h.emit(status(4, complete(op))); assert.equal(h.state.requestPending, true); assert.equal(h.state.result, null); assert.equal(h.state.reviewReference, null);
  const post = deferred(); h.readQueue.push(post);
  start.resolve(status(3, { ...op, phase: 'running', intentUsable: false })); await flush();
  assert.equal(h.state.requestPending, false); assert.equal(h.state.reading, true); assert.equal(h.state.result, null);
  post.resolve(status(4, complete(op))); await work; assert.ok(h.state.reviewReference); assert.equal(h.state.result.decision, 'review-required');
});

test('a status read begun before invoke settlement cannot become the post-invoke terminal proof', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  const oldRead = deferred(); h.readQueue.push(oldRead); const reading = h.controller.checkStatus();
  h.reply(start, status(4, complete(op))); await flush(); assert.equal(h.state.result, null);
  const fresh = deferred(); h.readQueue.push(fresh); oldRead.resolve(status(4, complete(op))); await reading; await flush();
  assert.equal(h.state.result, null); assert.equal(h.state.reading, true);
  fresh.resolve(status(4, complete(op))); await work; assert.ok(h.state.reviewReference);
});

test('delayed Prepare survives context change and terminal cancellation; never auto-starts', async t => {
  const h = harness(t); await h.ready; const work = h.controller.prepare('review'), call = h.calls.at(-1), op = operation(call.request);
  h.replaceProject({ observationGeneration: 4 }); h.emit(status(2, op)); const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
  h.reply(cancel, status(3, cancelled(op))); await flush(); assert.equal(h.state.requestPending, true); assert.equal(h.state.consent, null);
  call.resolve(status(2, op)); await work; assert.equal(h.state.requestPending, false); assert.equal(h.state.historical, true);
  assert.equal(h.calls.filter(c => c.kind === 'start').length, 0); assert.equal(h.state.consent, null);
});

test('same-byte observation/key-entry/name changes invalidate original consent and review', async t => {
  for (const change of ['observation', 'entry', 'name']) {
    const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
    if (change === 'observation') h.replaceProject({ observationGeneration: 4 });
    else if (change === 'entry') { const next = assets(); next.entryGeneration = 2; h.replaceAssets(next); }
    else h.controller.setDisplayName('Different explicit name');
    assert.equal(h.state.consent, null); const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
    h.reply(cancel, status(3, cancelled(op))); await flush();
    await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 0);
  }
});

test('failed/lost invoke keeps unknown despite terminal event and does not leak raw errors', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  start.reject(new Error('PRIVATE-ERROR-MARKER-not-a-real-secret')); await flush();
  const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel'); h.reply(cancel, status(4, cancelled(op))); await flush(); await work;
  assert.ok(h.state.issue); assert.ok(h.controller.ownerReason()); assert.equal(h.state.reviewReference, null); assert.equal(h.state.result, null);
  assert.equal(JSON.stringify(h.state).includes('PRIVATE-ERROR-MARKER'), false);
  await h.controller.prepare('review'); await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 1);
  await h.controller.connect({ ...h.api }); assert.ok(h.state.issue); assert.ok(h.controller.ownerReason());
});

test('same-revision contradiction and foreign replacement cannot adopt another operation', async t => {
  const h = harness(t), op = await prepared(h);
  const bad = copy(h.native); bad.operation.context.displayName = 'contradiction'; h.emit(bad);
  assert.equal(h.state.issue, 'protocol'); assert.equal(h.state.consent, null);
  const cancel = h.calls.at(-1); h.reply(cancel, status(3, cancelled(op))); await flush();
  h.emit(status(4, { ...op, ...id('9'), phase: 'running', intentUsable: false }));
  assert.ok(h.state.issue); await h.controller.start('9'.repeat(32), op.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 0);
});

test('read-only reconciliation retains exact prior registration and never produces a retry/readiness grant', async t => {
  const h = harness(t); await reviewed(h); h.controller.setNewApplication(true); const op = await prepared(h, 'register', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true); const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  const value = result('register', 'inconclusive', 'registration-unconfirmed'); value.attempt = { operationId: op.operationId, action: 'register_bundle_id', status: 'unknown',
    reason: 'provider_outcome_unknown', retryAllowed: false, credentialReady: false, cancellationRequested: false };
  h.reply(start, status(5, complete(op, value))); await work; assert.equal(h.state.reconcileReason, null);
  const reconcile = await prepared(h, 'reconcile', '3', 6); assert.deepEqual(h.calls.at(-1).request.reference, id('2'));
  h.controller.acknowledge(reconcile.operationId, reconcile.ownerGeneration, true); const read = h.controller.start(reconcile.operationId, reconcile.ownerGeneration), call = h.calls.at(-1);
  assert.equal(call.request.consentVersion, 'local-ios-bundle-reconcile-v1'); h.reply(call, status(7, complete(reconcile))); await read;
  assert.equal(h.state.result.comparison, 'not-returned'); assert.equal(h.state.reviewReference, null); assert.deepEqual(h.state.registrationReference, id('2'));
  assert.notEqual(h.state.registerReason, null);
});

test('native Unknown stays absorbing; original cancel/status remain reachable without another mutation', async t => {
  const h = harness(t), op = await prepared(h); h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  const unknown = { ...op, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null };
  h.reply(start, status(3, unknown, 'cleanup-unknown')); await flush(); const cancel = h.calls.at(-1);
  assert.equal(cancel.kind, 'cancel'); h.reply(cancel, status(3, unknown, 'cleanup-unknown')); await flush(); await work;
  assert.equal(h.state.issue, 'cleanup-unknown'); assert.equal(h.state.canRead, true); assert.ok(h.state.retained);
  await h.controller.prepare('reconcile'); assert.equal(h.calls.filter(c => c.kind === 'prepare').length, 1);
  assert.equal(h.state.result, null); assert.equal(h.state.reviewReference, null);
  h.controller.beginConnection();
  assert.equal(h.state.canRead, true); // Retiring a port cannot hide a retained original Unknown.
  const oldReads = h.reads.length;
  await h.controller.checkStatus(); assert.equal(h.reads.length, oldReads + 1);
  assert.equal(h.state.issue, 'cleanup-unknown'); assert.ok(h.state.retained);
});

test('consent deadline uses original pre-Prepare instant, not delayed response/status time', async t => {
  const h = harness(t); await h.ready; const work = h.controller.prepare('review'), call = h.calls.at(-1), op = operation(call.request);
  h.time(60101); h.reply(call, status(2, op)); await work; assert.equal(h.state.consent, null);
  const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel'); h.reply(cancel, status(3, cancelled(op))); await flush();
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(c => c.kind === 'start').length, 0);
});

test('disposing during retained Prepare keeps original port/listener and cancels late discovered intent', async t => {
  const h = harness(t); await h.ready; const work = h.controller.prepare('review'), call = h.calls.at(-1), op = operation(call.request);
  h.controller.dispose(); assert.equal(h.listeners[0].closed, false);
  h.emit(status(2, op)); const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
  h.reply(cancel, status(3, cancelled(op))); await flush(); assert.equal(h.state.requestPending, true); assert.equal(h.listeners[0].closed, false);
  call.resolve(status(2, op)); await work; await flush();
  assert.equal(h.calls.filter(c => c.kind === 'start').length, 0); assert.equal(h.listeners[0].closed, true);
});
