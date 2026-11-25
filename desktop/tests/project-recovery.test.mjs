// Inert DTO/controller/mock-IPC tests. No real project, native run, worker,
// process, signing material or Store is accessed. These are not native receipts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { ProjectRecoveryController, projectRecoveryOwnerReason } from '../src/projectRecoveryController.ts';
import { PROJECT_RECOVERY_CONSENT, PROJECT_RECOVERY_EVENT, PROJECT_RECOVERY_LIMITATIONS, copyProjectRecoveryRequest,
  encodeProjectRecoveryRequest, parseProjectRecoveryStatus, recoveryEligible } from '../src/projectRecoveryProtocol.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), SESSION = 'c'.repeat(32), NEXT = 'd'.repeat(32);
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 16; i++) await Promise.resolve(); };
function observed(quiescence = 'original', state = 'pending') {
  return { status: state, session: ['pending', 'cleanup-only'].includes(state) ? SESSION : null,
    roles: state === 'pending' ? ['android-services'] : [], quiescence };
}
function request(action = 'inspect') { return { projectId: 'project-1', draftRevision: 0, baselineGeneration: 0, action }; }
function context(action = 'inspect', review = null) { return { ...request(action), review }; }
function operation(options = {}) {
  return { operationId: OP, ownerGeneration: OWNER, context: context(), phase: 'awaiting-consent', intentUsable: true,
    outcome: null, reason: 'none', result: null, effect: null, ...options };
}
function status(revision = 0, op = null, availability = 'available') {
  return { schemaVersion: 1, statusRevision: revision, availability, operation: op };
}
function complete(op, observation = observed()) {
  return { ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none',
    effect: op.context.action === 'inspect' ? 'inspection' : 'recovery-attempted',
    result: { schemaVersion: 1, scope: 'project-build-inputs-only', action: op.context.action,
      observation: op.context.action === 'inspect' ? clone(observation) : null,
      recoveredSession: op.context.action === 'recover' ? op.context.review.session : null,
      limitations: [...PROJECT_RECOVERY_LIMITATIONS] } };
}
function harness(t, initial = status()) {
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'project-1', name: 'Inert project', path: '/never-opened' } });
  let registry = clone(initial), now = 10, other = null;
  const calls = [], listeners = [];
  const api = {
    mode: 'native',
    subscribeProjectRecovery: async (receive) => { const row = { receive, closed: false }; listeners.push(row); return () => { row.closed = true; }; },
    projectRecoveryStatus: async () => clone(registry),
    prepareProjectRecovery: (input) => { const call = { kind: 'prepare', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    startProjectRecovery: (input) => { const call = { kind: 'start', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelProjectRecovery: (operationId, ownerGeneration) => { const call = { kind: 'cancel', input: { operationId, ownerGeneration }, ...deferred() }; calls.push(call); return call.promise; },
  };
  const controller = new ProjectRecoveryController({ selectedProject: () => workspace.projects[workspace.selectedId] ?? null,
    otherOperationReason: () => other, now: () => now });
  controller.syncProject(); controller.setVisible(true);
  t.after(() => controller.dispose());
  return { controller, calls, listeners, api, ready: controller.connect(api),
    get state() { return controller.getSnapshot(); },
    emit(value) { registry = clone(value); listeners.at(-1)?.receive(clone(value)); },
    reply(call, value) { registry = clone(value); call.resolve(clone(value)); },
    clock(value) { now = value; }, other(value) { other = value; },
    dispatch(action) { controller.beforeWorkspaceAction(action); workspace = workspaceReducer(workspace, action); controller.syncProject(); },
  };
}
async function inspect(h, observation = observed()) {
  await h.ready;
  assert.equal(h.controller.prepareReason('inspect'), null);
  void h.controller.prepare('inspect');
  const preparing = h.calls.at(-1); assert.equal(preparing.kind, 'prepare');
  const op = operation({ context: { ...preparing.input, review: null } });
  h.reply(preparing, status(1, op, 'busy')); await flush();
  const starting = h.calls.at(-1); assert.equal(starting.kind, 'start');
  assert.equal(starting.input.consentVersion, PROJECT_RECOVERY_CONSENT);
  h.reply(starting, status(2, { ...op, phase: 'running', intentUsable: false }, 'busy')); await flush();
  h.emit(status(3, complete(op, observation))); await flush();
  assert.equal(h.state.status.operation.outcome, 'complete');
  assert.equal(h.state.originalUnconfirmed, false);
  return op;
}
async function review(h) {
  assert.equal(h.controller.prepareReason('recover'), null);
  const previous = clone(h.state.status.operation.result.observation);
  void h.controller.prepare('recover');
  const preparing = h.calls.at(-1); assert.equal(preparing.kind, 'prepare');
  assert.deepEqual(Object.keys(preparing.input).sort(), ['action', 'baselineGeneration', 'draftRevision', 'projectId']);
  const op = operation({ operationId: NEXT, context: { ...preparing.input, review: previous } });
  h.reply(preparing, status(4, op, 'busy')); await flush();
  assert.equal(h.state.consent.acknowledged, false);
  assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1); // Inspect only.
  return op;
}

test('raw closed IPC rejects private stamps, source paths, accessors and execution fields before serialization', () => {
  const input = request('recover');
  assert.deepEqual(JSON.parse(new TextDecoder().decode(encodeProjectRecoveryRequest('prepare_project_recovery', input))), input);
  let reads = 0;
  const accessor = { ...input, get action() { reads++; return 'recover'; } };
  const toJSON = { ...input, toJSON() { reads++; return input; } };
  const inherited = Object.assign(Object.create({ extra: true }), input);
  for (const bad of [accessor, toJSON, inherited, { ...input, draftRevision: -0 }, { ...input, action: 'force' },
    ...['session', 'review', 'reviewStamp', 'path', 'root', 'command', 'manual', 'environment'].map((key) => ({ ...input, [key]: 'UNTRUSTED' }))])
    assert.equal(copyProjectRecoveryRequest('prepare_project_recovery', bad), null);
  assert.equal(reads, 0);
  assert.equal(encodeProjectRecoveryRequest('project_recovery_status', { projectId: 'project-1' }), null);
  assert.equal(encodeProjectRecoveryRequest('start_project_recovery', { operationId: OP, ownerGeneration: OWNER, consentVersion: 'saved-offline-android-v1' }), null);
});

test('native bridge sends four raw commands and preview never produces a recovery receipt', async () => {
  const calls = []; let event, receive;
  const api = createNativeApi('native', async (command, body) => {
    assert.ok(body instanceof Uint8Array);
    calls.push([command, JSON.parse(new TextDecoder().decode(body))]); return status();
  }, async (name, listener) => { event = name; receive = listener; return () => {}; });
  await api.prepareProjectRecovery(request());
  await api.startProjectRecovery({ operationId: OP, ownerGeneration: OWNER, consentVersion: PROJECT_RECOVERY_CONSENT });
  await api.projectRecoveryStatus(); await api.cancelProjectRecovery(OP, OWNER);
  assert.deepEqual(calls.map(([command]) => command), ['prepare_project_recovery', 'start_project_recovery', 'project_recovery_status', 'cancel_project_recovery']);
  let current; await api.subscribeProjectRecovery((value) => { current = value; });
  assert.equal(event, PROJECT_RECOVERY_EVENT); receive({ ...status(), privatePath: 'UNTRUSTED' }); assert.equal(current, null);
  for (const name of ['prepareProjectRecovery', 'startProjectRecovery', 'projectRecoveryStatus', 'cancelProjectRecovery', 'subscribeProjectRecovery'])
    await assert.rejects(previewApi[name](), (error) => error.code === 'project_recovery_unavailable');
});

test('result contract distinguishes none, operator, metadata-only cleanup and unsettled or cross-session data', () => {
  for (const value of ['none', 'original', 'operator']) {
    const data = observed(value), parsed = parseProjectRecoveryStatus(status(1, complete(operation(), data)));
    assert.ok(parsed); assert.equal(recoveryEligible(parsed.operation.result.observation), value !== 'none');
  }
  assert.ok(parseProjectRecoveryStatus(status(1, complete(operation(), observed('original', 'cleanup-only')))));
  const op = operation({ context: context('recover', observed()) });
  const valid = status(1, complete(op)); assert.ok(parseProjectRecoveryStatus(valid));
  for (const mutate of [
    (x) => { x.operation.result.recoveredSession = NEXT; },
    (x) => { x.operation.context.review.quiescence = 'none'; },
    (x) => { x.operation.reviewStamp = 'd'.repeat(64); },
    (x) => { x.operation.result.limitations.pop(); },
    (x) => { x.operation.phase = 'running'; },
    (x) => { x.operation.effect = 'inspection'; },
    (x) => { x.operation.result.scope = 'all-project-state'; },
  ]) { const value = clone(valid); mutate(value); assert.equal(parseProjectRecoveryStatus(value), null); }
  const failed = { ...op, phase: 'terminal', intentUsable: false, outcome: 'failed', reason: 'project-conflict', result: null, effect: 'recovery-attempted' };
  assert.ok(parseProjectRecoveryStatus(status(2, failed)));
  const unknown = { ...failed, phase: 'unknown', outcome: 'unknown', reason: 'cleanup-unknown', effect: null };
  assert.ok(parseProjectRecoveryStatus(status(2, unknown, 'cleanup-unknown')));
});

test('Inspect is one owned read, recovery requires fresh unchecked review and Start is consumed once', async (t) => {
  const h = harness(t); await inspect(h);
  assert.equal(h.state.project.snapshotPending, false); // No saved config is required for recovery.
  const op = await review(h);
  assert.ok(h.controller.runReason());
  void h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.at(-1).kind, 'prepare');
  h.controller.setAcknowledged(op.operationId, op.ownerGeneration, true);
  void h.controller.start(op.operationId, op.ownerGeneration);
  void h.controller.start(op.operationId, op.ownerGeneration);
  const call = h.calls.at(-1); assert.equal(call.kind, 'start');
  assert.equal(h.calls.filter((item) => item.kind === 'start').length, 2);
  assert.equal(h.state.consent, null); assert.ok(projectRecoveryOwnerReason(h.state));
  h.reply(call, status(5, { ...op, phase: 'running', intentUsable: false }, 'busy')); await flush();
  h.controller.setVisible(false); assert.ok(projectRecoveryOwnerReason(h.state));
  h.emit(status(6, complete(op))); await flush();
  assert.equal(projectRecoveryOwnerReason(h.state), null);
  h.controller.setVisible(true); assert.ok(h.controller.prepareReason('recover')); // New inspection required.
});

test('none or busy never offers Recover; prior operator data is labelled without manufacturing finality', async (t) => {
  const none = harness(t); await inspect(none, observed('none')); assert.match(none.controller.prepareReason('recover'), /missing/);
  void none.controller.prepare('recover'); assert.equal(none.calls.length, 2);
  const busy = harness(t); await inspect(busy, observed('none', 'busy')); assert.ok(busy.controller.prepareReason('recover'));
  const operator = harness(t); await inspect(operator, observed('operator')); const op = await review(operator);
  assert.equal(op.context.review.quiescence, 'operator'); assert.equal(operator.state.consent.acknowledged, false);
});

test('review expiry is capped by original inspection, not renewed by a late recovery Prepare or status', async (t) => {
  const h = harness(t); await inspect(h);
  h.clock(299_999); await review(h);
  assert.equal(h.state.consent.deadline, 300_010);
  h.clock(300_010); await h.controller.checkStatus();
  assert.equal(h.state.consent, null);
  assert.equal(h.calls.at(-1).kind, 'cancel');
  assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
});

test('workspace intent retires recovery before any reducer result and retains the original Cancel', async (t) => {
  const h = harness(t); await inspect(h); await review(h);
  h.dispatch({ type: 'snapshot-failed', projectId: 'project-1', requestId: 999, error: { code: 'inert', message: 'inert', retryable: false } });
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  assert.ok(projectRecoveryOwnerReason(h.state));
  assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
});

test('a lost Prepare reply can be cancelled from original status but can never authorize recovery Start', async (t) => {
  const h = harness(t); await inspect(h);
  const reviewed = clone(h.state.status.operation.result.observation);
  void h.controller.prepare('recover');
  const call = h.calls.at(-1), op = operation({ operationId: NEXT, context: { ...call.input, review: reviewed } });
  h.emit(status(4, op, 'busy')); await flush();
  assert.equal(h.state.consent, null); assert.equal(h.state.originalUnconfirmed, true);
  assert.equal(h.controller.cancel(), true); assert.equal(h.controller.cancel(), false);
  h.reply(call, status(4, op, 'busy')); await flush();
  assert.equal(h.state.consent, null); assert.equal(h.calls.filter((item) => item.kind === 'start').length, 1);
});

test('partial failure and unconfirmed finality cannot reset the original owner or become a successful retry', async (t) => {
  const h = harness(t); await inspect(h); const op = await review(h);
  h.controller.setAcknowledged(op.operationId, op.ownerGeneration, true);
  void h.controller.start(op.operationId, op.ownerGeneration);
  const call = h.calls.at(-1);
  call.reject({ code: 'lost-response', message: 'PRIVATE' }); await flush();
  assert.ok(projectRecoveryOwnerReason(h.state)); assert.equal(h.state.consent, null);
  h.emit(status(5, { ...op, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' }, 'cleanup-unknown'));
  assert.equal(h.state.nativeBlocked, true); assert.ok(h.controller.prepareReason('inspect'));
  const subscriptions = h.listeners.length;
  h.controller.beginConnection(); await h.controller.connect({ ...h.api });
  assert.equal(h.listeners.length, subscriptions); assert.ok(projectRecoveryOwnerReason(h.state));

  for (const late of ['reject', 'malformed']) {
    const h = harness(t); await h.ready;
    const firstPreparing = h.controller.prepare('inspect'), firstCall = h.calls.at(-1);
    assert.equal(firstCall.kind, 'prepare');
    const first = operation({ context: { ...firstCall.input, review: null } });
    h.reply(firstCall, status(1, first, 'busy')); await flush();
    const firstStart = h.calls.at(-1); assert.equal(firstStart.kind, 'start');
    h.reply(firstStart, status(2, { ...first, phase: 'running', intentUsable: false }, 'busy')); await firstPreparing;
    assert.equal(h.state.status.operation.phase, 'running');
    assert.equal(h.controller.cancel(), true);
    const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
    assert.deepEqual(cancel.input, { operationId: first.operationId, ownerGeneration: first.ownerGeneration });
    const settled = { ...first, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' };
    h.emit(status(3, settled)); await flush();
    assert.deepEqual(clone(h.state.status.operation), settled);
    assert.equal(h.state.integrityFailed, false); assert.equal(h.state.nativeBlocked, false);
    assert.equal(h.controller.prepareReason('inspect'), null);
    // A second explicit Inspect is sufficient: no fabricated recovery eligibility.
    const nextPreparing = h.controller.prepare('inspect'), nextCall = h.calls.at(-1);
    assert.equal(nextCall.kind, 'prepare');
    const next = operation({ operationId: NEXT, ownerGeneration: '1'.repeat(32), context: { ...nextCall.input, review: null } });
    h.reply(nextCall, status(4, next, 'busy')); await flush();
    const nextStart = h.calls.at(-1); assert.equal(nextStart.kind, 'start');
    h.reply(nextStart, status(5, { ...next, phase: 'running', intentUsable: false }, 'busy')); await nextPreparing;
    assert.equal(h.state.status.operation.operationId, next.operationId);
    assert.equal(h.state.status.operation.ownerGeneration, next.ownerGeneration);
    assert.equal(h.state.status.operation.phase, 'running');
    assert.equal(h.state.historical, false); assert.equal(h.state.error, null);
    const current = clone(h.state);
    if (late === 'reject') cancel.reject({ code: 'lost-response', message: 'PRIVATE OLD CANCEL' });
    else cancel.resolve({ schemaVersion: 999 });
    await flush();
    assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1,
      'A stale Cancel completion must not dispatch Cancel for B');
    assert.deepEqual(clone(h.state), current);
    assert.deepEqual(h.calls.filter((call) => call.kind === 'cancel').map((call) => call.input),
      [{ operationId: first.operationId, ownerGeneration: first.ownerGeneration }]);
    h.emit(status(6, complete(next))); await flush();
    assert.equal(h.state.status.operation.phase, 'terminal');
    assert.equal(h.state.originalUnconfirmed, false);
  }

  for (const completion of ['valid', 'reject', 'malformed']) {
    const h = harness(t); await inspect(h); const original = await review(h);
    assert.equal(h.controller.cancel(), true);
    const cancel = h.calls.at(-1); assert.equal(cancel.kind, 'cancel');
    const settled = { ...original, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' };
    if (completion === 'valid') h.reply(cancel, status(5, settled));
    else if (completion === 'reject') cancel.reject({ code: 'lost-response', message: 'PRIVATE CURRENT CANCEL' });
    else cancel.resolve({ schemaVersion: 999 });
    await flush();
    assert.equal(h.state.consent, null);
    assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
    if (completion === 'valid') {
      assert.deepEqual(clone(h.state.status.operation), settled);
      assert.equal(h.state.error, null); assert.equal(h.state.integrityFailed, false);
    } else {
      assert.equal(h.state.observationIssue, completion === 'reject' ? 'bridge' : 'protocol');
      assert.equal(h.state.integrityFailed, completion === 'malformed');
      assert.equal(h.state.nativeBlocked, completion === 'malformed');
      assert.ok(!JSON.stringify(h.state).includes('PRIVATE'));
      h.emit(status(5, settled)); await flush();
    }
  }
});

test('conflicting native revisions and provisional results are rejected before returning UI consent', async (t) => {
  const h = harness(t); await inspect(h);
  const changed = clone(h.state.status); changed.operation.result.observation.quiescence = 'operator';
  h.emit(changed);
  assert.equal(h.state.integrityFailed, true); assert.ok(h.controller.prepareReason('recover'));
  const provisional = harness(t); await provisional.ready;
  provisional.emit(status(1, { ...complete(operation()), phase: 'running', outcome: null }));
  assert.equal(provisional.state.integrityFailed, true); assert.equal(provisional.state.consent, null);
});
