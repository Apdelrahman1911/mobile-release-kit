// Complete original controller/protocol with synthetic API promises only.
// Historical rows are not native settlement or permission to call Apple.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { APPLE_PROVISIONING_LIMITATIONS, appleProvisioningContext, parseAppleProvisioningStatus,
  parseAppleRecoveryHistory } from '../src/appleProvisioningProtocol.ts';

const copy = value => structuredClone(value);
const id = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'e'.repeat(32) });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 30; i++) await Promise.resolve(); };
const history = () => ({ schemaVersion: 1, scope: 'local-ios-bundle-attempts', hiddenUnresolved: 0,
  attempts: [{ reference: id('a'), displayName: 'Original 🍎 name', observedAt: '2026-10-19T12:34:56.123456+00:00',
    status: 'unknown', reason: 'provider_outcome_unknown', nativeSettlement: 'pending', cancellationRequested: false }] });
const result = mode => ({ schemaVersion: 1, scope: 'local-ios-bundle-provisioning', mode, observation: 'inconclusive',
  decision: mode === 'review' ? 'blocked' : 'comparison-only', attempt: null, comparison: mode === 'review' ? null : 'inconclusive',
  limitations: [...APPLE_PROVISIONING_LIMITATIONS] });
const status = (revision = 1, operation = null) => ({ schemaVersion: 1, statusRevision: revision,
  availability: operation && operation.phase !== 'terminal' ? 'busy' : 'available', operation });
const operation = (request, digit = '1') => ({ ...id(digit), context: appleProvisioningContext(copy(request)),
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const complete = (op, rows = null) => ({ ...copy(op), phase: 'terminal', intentUsable: false,
  outcome: 'complete', reason: 'none', result: result(op.context.mode), recovery: copy(rows) });

function harness(t) {
  let project = { projectId: 'fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
    savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
    savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
    dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null };
  let assets = { mode: 'native', scope: { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'store' },
    contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false, entryGeneration: 1,
    status: { mode: 'session', capability: { available: true }, modes: { session: { available: true } }, operation: null,
      context: { revision: 3, projectId: 'fixture', executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'store' },
      assignments: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' }],
      records: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), revision: 4, availability: 'assigned' }] } };
  let native = status(), receiver = null;
  const calls = [], reads = [], readQueue = [];
  const invoke = (kind, request) => { const row = { kind, request: copy(request), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native', subscribe: async callback => { receiver = callback; return () => { receiver = null; }; },
    status: () => { reads.push(copy(native)); return readQueue.shift()?.promise ?? Promise.resolve(copy(native)); },
    prepare: request => invoke('prepare', request), start: request => invoke('start', request),
    cancel: async request => { calls.push({ kind: 'cancel', request: copy(request) }); return copy(native); } };
  const controller = new AppleProvisioningController({ project: () => project, assets: () => assets, otherOperationReason: () => null, now: () => 100 });
  controller.setVisible(true); controller.setDisplayName('Current review name');
  const ready = controller.connect(api); t.after(() => controller.dispose());
  return { controller, ready, calls, reads, readQueue,
    get state() { return controller.getSnapshot(); }, get native() { return copy(native); },
    reply(row, value) { native = copy(value); row.resolve(copy(value)); },
    emit(value) { native = copy(value); receiver?.(copy(value)); },
    changeKey() { assets = copy(assets); assets.entryGeneration++; assets.status.context.revision++;
      assets.status.assignments[0].recordRevision++; assets.status.assignments[0].contextRevision++;
      assets.status.records[0].revision++; controller.syncProject(); },
    changeProject() { project = { ...project, observationGeneration: project.observationGeneration + 1, draftRevision: project.draftRevision + 1 }; controller.syncProject(); } };
}
async function reviewStarted(h) {
  await h.ready;
  const prepared = h.controller.prepare('review'), call = h.calls.at(-1), op = operation(call.request);
  h.reply(call, status(2, op)); await prepared;
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration);
  return { op, work, call: h.calls.at(-1) };
}
async function reviewed(h, rows = history()) {
  const started = await reviewStarted(h);
  h.reply(started.call, status(3, complete(started.op, rows))); await started.work;
  assert.ok(h.state.previousAttempts); assert.equal(h.state.reviewReference, null);
  return started.op;
}

test('historical codec is bounded, token-free and preserves every recorded uncertainty', () => {
  const original = history(), parsed = parseAppleRecoveryHistory(original);
  assert.equal(parsed?.attempts[0].nativeSettlement, 'pending');
  for (const patch of [{ accountRef: 'f'.repeat(64) }, { path: '/not-read' }, { hiddenUnresolved: -1 }, { hiddenUnresolved: 32 },
    { schemaVersion: 2 }, { scope: 'current-account-authority' }, { retryAllowed: true }]) {
    assert.equal(parseAppleRecoveryHistory({ ...original, ...patch }), null);
  }
  for (const patch of [{ displayName: '' }, { displayName: 'x'.repeat(129) }, { observedAt: '2026-02-30T01:02:03+00:00' },
    { observedAt: '2026-10-19T12:34:56.000000+00:00' }, { observedAt: '2026-10-19T12:34:56Z' },
    { nativeSettlement: 'recovered' }, { credentialReady: true }, { responseResourceId: 'PRIVATE' }]) {
    const bad = history(); Object.assign(bad.attempts[0], patch); assert.equal(parseAppleRecoveryHistory(bad), null);
  }
  const duplicate = history(); duplicate.attempts.push(copy(duplicate.attempts[0])); assert.equal(parseAppleRecoveryHistory(duplicate), null);
  const full = history(); full.attempts = Array.from({ length: 32 }, (_, index) => ({ ...history().attempts[0],
    reference: { ...id('a'), operationId: (index + 1).toString(16).padStart(32, '0') }, displayName: '🍎'.repeat(128) }));
  assert.equal(parseAppleRecoveryHistory(full)?.attempts.length, 32);
  full.attempts.push(history().attempts[0]); assert.equal(parseAppleRecoveryHistory(full), null);
  assert.equal(original.attempts[0].nativeSettlement, 'pending');
});

test('a new controller explicitly selects a recorded attempt then uses only existing Reconcile consent', async t => {
  const h = harness(t); await h.ready;
  assert.equal(h.calls.length, 0); assert.equal(h.state.registrationReference, null);
  await reviewed(h);
  assert.equal(h.state.previousAttempts.attempts[0].displayName, 'Original 🍎 name');
  assert.equal(h.state.registrationReference, null); // No automatic row choice.
  const work = h.controller.continuePrevious(...Object.values(id('a'))), call = h.calls.at(-1);
  assert.equal(call.kind, 'prepare'); assert.equal(call.request.mode, 'reconcile');
  assert.equal(call.request.newApplication, false); assert.deepEqual(call.request.reference, id('a'));
  assert.equal(call.request.displayName, 'Original 🍎 name'); assert.equal(call.request.projectId, 'fixture');
  assert.equal(call.request.recordId, 'c'.repeat(32));
  await h.controller.continuePrevious(...Object.values(id('a'))); assert.equal(h.calls.length, 3);
  const op = operation(call.request, '2'); h.reply(call, status(4, op)); await work;
  assert.equal(h.state.consent.acknowledged, false);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.length, 3);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const readback = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  assert.equal(start.request.consentVersion, 'local-ios-bundle-reconcile-v1');
  h.reply(start, status(5, complete(op))); await readback;
  h.controller.setNewApplication(true); await h.controller.prepare('register');
  assert.equal(h.calls.length, 4); assert.equal(h.state.reviewReference, null);
  assert.equal(h.state.result.comparison, 'inconclusive');
});

test('reentrant cancellation cannot renew the selected continuation during any publication before Prepare', async t => {
  for (const publication of [2, 3, 4]) {
    const h = harness(t); await reviewed(h);
    let count = 0, cancellation = null;
    const off = h.controller.subscribe(() => {
      count++;
      if (count === publication) { off(); cancellation = h.controller.cancel(); }
    });
    // 1: current-source refresh; 2: own invalidation; 3: selected display DATA;
    // 4: existing Prepare's current-source refresh. None is a new user intent.
    await h.controller.continuePrevious(...Object.values(id('a')));
    assert.ok(cancellation); await cancellation; await flush(); off();
    assert.equal(h.calls.length, 2); // Only the already joined Review calls.
    assert.equal(h.state.registrationReference, null);
    assert.equal(h.state.cancelRequested, true);
    assert.equal(h.state.consent, null); assert.equal(h.state.issue, null);
  }
});

test('terminal event cannot offer history before original Start and its post-invoke status read return', async t => {
  const h = harness(t), started = await reviewStarted(h);
  const terminal = status(3, complete(started.op, history()));
  h.emit(terminal); assert.equal(h.state.previousAttempts, null);
  await h.controller.continuePrevious(...Object.values(id('a'))); assert.equal(h.calls.length, 2);
  const read = deferred(); h.readQueue.push(read);
  h.reply(started.call, terminal); await flush();
  assert.equal(h.state.reading, true); assert.equal(h.state.previousAttempts, null);
  read.resolve(terminal); await started.work;
  assert.equal(h.state.previousAttempts?.attempts.length, 1);
});

test('unperformed or ambiguous selection never picks an account row automatically', async t => {
  const h = harness(t), rows = history();
  rows.attempts.push({ ...copy(rows.attempts[0]), reference: id('b'), status: 'failed', reason: 'provider_rejected_request', nativeSettlement: 'known' });
  rows.hiddenUnresolved = 1;
  await reviewed(h, rows);
  assert.equal(h.state.previousAttempts.attempts.length, 2); assert.equal(h.state.previousAttempts.hiddenUnresolved, 1);
  await h.controller.continuePrevious('f'.repeat(32), 'e'.repeat(32));
  await h.controller.continuePrevious(id('a').operationId, 'f'.repeat(32));
  assert.equal(h.calls.length, 2); assert.equal(h.state.registrationReference, null);
});

test('account or saved-context changes invalidate both list selection and late old replies', async t => {
  for (const change of ['changeKey', 'changeProject']) {
    const h = harness(t); await reviewed(h);
    const old = h.native; h[change]();
    assert.equal(h.state.previousAttempts, null);
    h.emit(old); await flush();
    await h.controller.continuePrevious(...Object.values(id('a')));
    assert.equal(h.calls.length, 2); assert.equal(h.state.registrationReference, null);
  }
});

test('an outstanding status invocation prevents continuing from a previously visible list', async t => {
  const h = harness(t); await reviewed(h);
  const read = deferred(); h.readQueue.push(read); const pending = h.controller.checkStatus();
  assert.equal(h.state.previousAttempts, null); assert.notEqual(h.controller.ownerReason(), null);
  await h.controller.continuePrevious(...Object.values(id('a'))); assert.equal(h.calls.length, 2);
  read.resolve(h.native); await pending;
  assert.equal(h.state.previousAttempts?.attempts.length, 1);
});

test('missing history and early/contradictory metadata cannot imply an empty account or registration permission', async t => {
  const h = harness(t), started = await reviewStarted(h);
  const missing = complete(started.op); h.reply(started.call, status(3, missing)); await started.work;
  assert.equal(h.state.previousAttempts, null);
  await h.controller.continuePrevious(...Object.values(id('a'))); assert.equal(h.calls.length, 2);
  const full = complete(started.op, history());
  assert.ok(parseAppleProvisioningStatus(status(3, full)));
  for (const patch of [{ phase: 'running' }, { outcome: 'unknown' }, { outcome: 'failed' }, { reason: 'cleanup-unknown' }]) {
    assert.equal(parseAppleProvisioningStatus(status(3, { ...copy(full), ...patch })), null);
  }
  const contradictory = copy(full); contradictory.result.decision = 'review-required'; contradictory.result.observation = 'not-returned';
  assert.equal(parseAppleProvisioningStatus(status(3, contradictory)), null);
});

test('a newer native context change may withdraw history, never replace or revive it', async t => {
  const h = harness(t); await reviewed(h);
  const old = h.native, withdrawn = copy(old);
  withdrawn.statusRevision++; withdrawn.operation.recovery = null;
  h.emit(withdrawn); await flush();
  assert.equal(h.state.issue, null); assert.equal(h.state.previousAttempts, null);
  await h.controller.continuePrevious(...Object.values(id('a'))); assert.equal(h.calls.length, 2);
  h.emit(old); await flush(); // Late lower-revision publication cannot restore it.
  assert.equal(h.state.issue, null); assert.equal(h.state.previousAttempts, null);
  const revived = copy(old); revived.statusRevision = withdrawn.statusRevision + 1;
  h.emit(revived); await flush();
  assert.equal(h.state.issue, 'protocol'); assert.equal(h.state.previousAttempts, null);

  const unchangedRevision = harness(t); await reviewed(unchangedRevision);
  const contradictory = unchangedRevision.native; contradictory.operation.recovery = null;
  unchangedRevision.emit(contradictory); await flush();
  assert.equal(unchangedRevision.state.issue, 'protocol');
});

test('unknown original cleanup stays absorbing despite a later history-shaped result', async t => {
  const h = harness(t), started = await reviewStarted(h);
  const unknown = status(3, { ...started.op, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null, recovery: null });
  unknown.availability = 'cleanup-unknown'; h.reply(started.call, unknown); await started.work; await flush();
  assert.equal(h.state.issue, 'cleanup-unknown'); assert.equal(h.state.previousAttempts, null);
  h.emit(status(4, complete(started.op, history()))); await flush();
  await h.controller.continuePrevious(...Object.values(id('a')));
  assert.equal(h.calls.filter(row => row.kind === 'prepare').length, 1);
  assert.equal(h.state.previousAttempts, null); assert.equal(h.state.retained, true);
});
