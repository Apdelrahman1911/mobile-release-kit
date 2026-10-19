// Inert RAW transport and original-Promise custody only. No native EditOwner,
// source files, Python, timers, Store requests, React, filesystem or GUI tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ProjectIdentityNativeController, createProjectIdentityApi, encodeProjectIdentityRequest,
  PROJECT_IDENTITY_EVENT } from '../src/projectIdentityNative.ts';
import { ProjectIdentityController } from '../src/projectIdentityController.ts';
import { IDENTITY_NEW_WARNING, parseIdentityOwnerSnapshot } from '../src/projectIdentity.ts';

const WIN = 'a'.repeat(32), SID = 'b'.repeat(32), REV = 'c'.repeat(32), PLAN = 'd'.repeat(32);
const OLD = 'com.example.original', NEW = 'com.example.separate';
const selection = { platform: 'android', target: ':app', project: null, continuity: 'unknown' };
const context = () => ({ projectId: 'project-1', selection: structuredClone(selection), contextEpoch: 1, preview: false, blocked: false });
const locations = [{ path: 'app/build.gradle.kts', line: 1, column: 1, role: 'android-application-id' },
  { path: 'release/mobile-release.json', line: 1, column: 1, role: 'saved-identity' }];
const analysis = () => ({ schemaVersion: 1, kind: 'project-identity', revision: REV, selection: structuredClone(selection),
  state: 'supported', identity: OLD, configuredIdentity: OLD, identityStatus: 'unverified', configurations: ['release'],
  locations: structuredClone(locations), diagnostics: [], nextStep: 'Review the selected app ID.',
  scope: 'recognized-literal-source-only', buildVerificationRequired: true });
const preview = (id = NEW) => ({ schemaVersion: 1, kind: 'project-identity-preview', revision: REV,
  selection: structuredClone(selection), intent: 'new-application', state: 'change',
  changes: locations.map((v) => ({ ...v, beforeId: OLD, afterId: id })), warnings: [IDENTITY_NEW_WARNING],
  invalidations: ['credential-assessments-and-assignments', 'prepared-release-plans', 'candidate-identity-revision'],
  retainVersionReservations: true, buildVerificationRequired: true });
const recovery = () => ({ schemaVersion: 1, kind: 'project-identity-recovery', state: 'recoverable', reason: 'none',
  action: 'rollback', transactionId: 'e'.repeat(32), desiredIdentity: NEW,
  files: [{ path: 'app/build.gradle.kts', action: 'restore_original', beforeBytes: 10, afterBytes: 12 }],
  help: 'Review the original interrupted change.', privateCleanup: { fileCount: 1, directoryCount: 1, scope: 'inspected-owned-journal-only' },
  retainVersionReservations: true });
function projection(phase = 'editing', intent = 'edit', overrides = {}) {
  const opened = phase !== 'opening', prepared = !['opening', 'editing', 'preparing'].includes(phase);
  return { domain: 'project_identity', intent, projectId: 'project-1', sessionId: SID, ownerGeneration: WIN, phase,
    reviewRemainingMs: 1000, checkout: opened ? { revision: REV, view: intent === 'edit' ? analysis() : recovery() } : null,
    prepared: prepared ? { revision: REV, planToken: PLAN, view: intent === 'edit' ? preview() : recovery() } : null,
    diagnostic: null, applySubmitted: ['applying', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: intent === 'edit' ? 'committed' : 'rolled_back', journal: 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: phase === 'unknown' ? 'cleanup_unknown' : 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending',
    lateSettled: false, ...overrides };
}
function status(revision = 0, p = null, overrides = {}) {
  const value = { schemaVersion: 1, domain: 'project_identity', windowGeneration: WIN, statusRevision: revision,
    capability: { available: true, reason: 'available' }, active: p && !['final', 'unknown'].includes(p.phase) ? p : null,
    lastTerminal: p && ['final', 'unknown'].includes(p.phase) ? p : null, ...overrides };
  assert.ok(parseIdentityOwnerSnapshot({ busy: false, status: value }), 'The inert fixture must fit the actual existing parser');
  return value;
}
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 15; i += 1) await Promise.resolve(); };
function harness({ subscribePending = false, invokeHook, currentHook, submittedHook, offHook } = {}) {
  const calls = [], submitted = [], outcomes = [], subscription = deferred(); let event, offCount = 0, current = context(), blocked = null;
  const api = createProjectIdentityApi('native', (command, raw) => {
    assert.ok(raw instanceof Uint8Array);
    const work = deferred(), call = { command, args: JSON.parse(new TextDecoder().decode(raw)), ...work };
    calls.push(call); invokeHook?.(call);
    return work.promise;
  }, (name, callback) => {
    assert.equal(name, PROJECT_IDENTITY_EVENT); event = callback;
    return subscribePending ? subscription.promise : Promise.resolve(() => { offCount++; offHook?.(); });
  });
  let owner;
  owner = new ProjectIdentityNativeController(api, { current: () => { currentHook?.(owner); return current; },
    otherOperationReason: () => blocked, onMutationSubmitted: (id, intent) => { submitted.push([id, intent]); submittedHook?.(id, intent); }, onOutcome: (p) => outcomes.push(p) });
  const ui = new ProjectIdentityController(() => current, owner); ui.subscribe(() => {});
  return { api, owner, ui, calls, submitted, outcomes, subscription, get offCount() { return offCount; },
    emit(value) { event(value); }, change(next) { current = next; }, block(value) { blocked = value; },
    async ready() { assert.equal(owner.connect(), true); await flush(); assert.equal(calls[0].command, 'project_identity_status'); calls[0].resolve(status()); await flush(); },
    async open() { assert.equal(ui.analyze(), true); calls.at(-1).resolve(status(1, projection())); await flush(); },
    async review() {
      await this.open(); assert.equal(ui.setIntent('new-application'), true); assert.equal(ui.setDesiredIdentity(NEW), true);
      assert.equal(ui.acknowledgeNewApplication(true), true); assert.equal(ui.prepare(), true);
      calls.at(-1).resolve(status(2, projection('reviewing'))); await flush(); assert.equal(ui.getSnapshot().reviewCurrent, true);
    },
    count(command) { return calls.filter((c) => c.command === command).length; } };
}

test('exact five RAW commands and one event use closed edit/recover shapes; preview and missing listener are unavailable', async () => {
  const calls = []; let subscribed;
  const api = createProjectIdentityApi('native', (name, body) => { calls.push([name, JSON.parse(new TextDecoder().decode(body))]); return Promise.resolve('inert'); },
    (name) => { subscribed = name; return Promise.resolve(() => {}); });
  const open = { intent: 'edit', projectId: 'project-1', selection: { platform: 'android', target: ':app', project: null } };
  await api.open(open); open.selection.target = ':changed';
  await api.open({ intent: 'recover', projectId: 'project-1' });
  await api.prepare({ intent: 'edit', sessionId: SID, revision: REV, desiredIdentity: NEW, identityIntent: 'new-application' });
  await api.prepare({ intent: 'recover', sessionId: SID, revision: REV });
  for (const intent of ['edit', 'recover']) await api.apply({ intent, sessionId: SID, revision: REV, planToken: PLAN });
  await api.close({ sessionId: SID }); await api.status(); await api.subscribe(() => {});
  assert.deepEqual(new Set(calls.map(([c]) => c)), new Set(['project_identity_open', 'project_identity_prepare', 'project_identity_apply', 'project_identity_close', 'project_identity_status']));
  assert.equal(calls[0][1].selection.target, ':app'); assert.equal(Object.hasOwn(calls[0][1].selection, 'continuity'), false);
  assert.equal(calls[2][1].identityIntent, 'new-application'); assert.equal(calls[3][1].intent, 'recover');
  assert.deepEqual(calls.at(-1), ['project_identity_status', {}]); assert.equal(subscribed, PROJECT_IDENTITY_EVENT);
  assert.equal(createProjectIdentityApi('preview', () => { assert.fail('no invocation'); }, () => {}), null);
  assert.equal(createProjectIdentityApi('native', () => { assert.fail('no invocation'); }), null);
});

test('closed request copies reject continuity authority, unknown keys, getters, invalid roots/tokens and non-DATA', () => {
  const valid = { intent: 'edit', projectId: 'project-1', selection: { platform: 'android', target: ':app', project: null } };
  let getters = 0;
  for (const mutate of [
    (v) => { v.selection.continuity = 'unknown'; }, (v) => { v.root = '/inert/not-a-selected-root'; },
    (v) => { v.selection.target = ':../other'; }, (v) => { v.projectId = 'p'.repeat(65); },
    (v) => { v.selection.project = 'app.xcodeproj'; }, (v) => { v[Symbol('hidden')] = 1; },
    (v) => Object.defineProperty(v, 'projectId', { enumerable: true, get() { getters++; return 'project-1'; } }),
    (v) => Object.defineProperty(v, 'hidden', { value: true }), (v) => { v.selection.self = v; },
  ]) { const v = structuredClone(valid); mutate(v); assert.equal(encodeProjectIdentityRequest('project_identity_open', v), null); }
  assert.equal(getters, 0);
  assert.equal(encodeProjectIdentityRequest('project_identity_apply', { intent: 'edit', sessionId: SID, revision: REV, planToken: REV }), null);
  assert.equal(encodeProjectIdentityRequest('project_identity_status', { projectId: 'project-1' }), null);
  assert.equal(encodeProjectIdentityRequest('project_identity_close', { sessionId: SID, force: true }), null);
  const h = harness(), malicious = { selection };
  Object.defineProperty(malicious, 'projectId', { enumerable: true, get() { getters++; return 'project-1'; } });
  assert.equal(h.owner.analyze(malicious), false); assert.equal(getters, 0); assert.equal(h.calls.length, 0);
});

test('subscription precedes initial status, coalesces reads and cannot initialize authority from events alone', async () => {
  const h = harness({ subscribePending: true });
  assert.equal(h.calls.length, 0); assert.equal(h.owner.connect(), true); assert.equal(h.owner.checkStatus(), false);
  h.emit(status()); assert.equal(h.owner.getSnapshot().status, null); assert.equal(h.ui.analyze(), false); assert.equal(h.calls.length, 0);
  h.subscription.resolve(() => {}); await flush(); assert.equal(h.calls[0].command, 'project_identity_status');
  h.calls[0].resolve(status(1, null, { capability: { available: false, reason: 'runtime_unqualified' } })); await flush();
  assert.equal(h.owner.getState().initialized, true); assert.equal(h.owner.getState().pendingCount, 0); assert.equal(h.ui.analyze(), false);
});

test('real UI controller admits one original RAW review and explicit Apply without inventing native progress', async () => {
  const h = harness(); await h.ready(); await h.review();
  assert.deepEqual(h.calls[1].args, { intent: 'edit', projectId: 'project-1', selection: { platform: 'android', target: ':app', project: null } });
  assert.deepEqual(h.calls[2].args, { intent: 'edit', sessionId: SID, revision: REV, desiredIdentity: NEW, identityIntent: 'new-application' });
  assert.equal(h.ui.apply(), false); assert.equal(h.ui.acknowledgeReview(true), true); assert.equal(h.ui.apply(), true);
  const sent = h.calls.at(-1); assert.deepEqual(sent.args, { sessionId: SID, revision: REV, planToken: PLAN, intent: 'edit' });
  assert.equal(h.owner.getState().pendingCount, 1); assert.equal(h.owner.getState().original.phase, 'reviewing');
  assert.equal(h.ui.apply(), false); assert.deepEqual(h.submitted, [['project-1', 'edit']]);
  sent.resolve(status(3, projection('applying'))); await flush(); assert.ok(h.owner.ownerReason());
  h.emit(status(4, projection('final'))); assert.equal(h.ui.getSnapshot().result, 'saved');
  assert.equal(h.owner.ownerReason(), null); assert.equal(h.outcomes.length, 1);
});

test('native Existing stays visible and preserve-only under Unknown syntax context; changed project or target still refuses', async () => {
  const existing = projection(); existing.checkout.view.selection.continuity = 'existing';
  const h = harness(); await h.ready(); assert.equal(h.ui.analyze(), true);
  h.calls.at(-1).resolve(status(1, existing)); await flush();
  assert.equal(h.ui.getSnapshot().context.selection.continuity, 'unknown'); // No context/authority adoption.
  assert.equal(h.ui.getSnapshot().analysis.selection.continuity, 'existing');
  assert.equal(h.ui.getSnapshot().analysis.identityStatus, 'unverified');
  assert.equal(h.ui.getSnapshot().actions.prepare, true);
  assert.equal(h.ui.getSnapshot().canChooseNew, false); assert.equal(h.ui.setIntent('new-application'), false);
  assert.equal(h.owner.prepare({ sessionId: SID, revision: REV, desiredIdentity: NEW, intent: 'new-application' }), false);
  assert.equal(h.ui.prepare(), true);
  assert.deepEqual(h.calls.at(-1).args, { intent: 'edit', sessionId: SID, revision: REV, desiredIdentity: OLD, identityIntent: 'preserve' });
  const kept = { ...preview(OLD), selection: structuredClone(existing.checkout.view.selection), intent: 'preserve',
    state: 'unchanged', changes: [], warnings: [], invalidations: [] };
  const prepared = { revision: REV, planToken: PLAN, view: kept };
  h.calls.at(-1).resolve(status(2, projection('reviewing', 'edit', { checkout: existing.checkout, prepared }))); await flush();
  assert.equal(h.ui.getSnapshot().reviewCurrent, true); assert.equal(h.ui.apply(), false);
  assert.equal(h.ui.acknowledgeReview(true), true); assert.equal(h.ui.apply(), true);
  h.calls.at(-1).resolve(status(3, projection('final', 'edit', { checkout: existing.checkout, prepared,
    coreOutcome: { effect: 'unchanged', journal: 'not_created', resources: 'settled', reason: 'none' } }))); await flush();
  assert.equal(h.ui.getSnapshot().result, 'unchanged'); assert.equal(h.count('project_identity_open'), 1);

  for (const changed of [{ ...context(), projectId: 'project-2' },
    { ...context(), selection: { ...selection, target: ':another' } }]) {
    const stale = harness(); await stale.ready(); assert.equal(stale.ui.analyze(), true);
    stale.calls.at(-1).resolve(status(1, existing)); await flush();
    stale.change(changed); stale.ui.sync();
    assert.equal(stale.ui.getSnapshot().analysis, null); assert.equal(stale.ui.prepare(), false);
    assert.equal(stale.owner.prepare({ sessionId: SID, revision: REV, desiredIdentity: OLD, intent: 'preserve' }), false);
    assert.equal(stale.count('project_identity_prepare'), 0);
  }
});

test('reentrant listeners and context getters can retire a latched admission before the actual invocation', async () => {
  const h = harness(); await h.ready(); let retired = false;
  h.owner.subscribe(() => { if (!retired && h.owner.getState().pendingCount) { retired = true; h.owner.beforeContextIntent(); } });
  assert.equal(h.ui.analyze(), false); assert.equal(h.count('project_identity_open'), 0); assert.equal(h.owner.getState().pendingCount, 0);
  let checks = 0, armed = false;
  const reentrant = harness({ currentHook: (owner) => { if (armed && ++checks === 2) owner.beforeContextIntent(); } });
  await reentrant.ready(); armed = true;
  assert.equal(reentrant.owner.analyze({ projectId: 'project-1', selection }), false);
  assert.equal(reentrant.count('project_identity_open'), 0);
});

test('pending Open keeps both original promises while explicit status finds its ID and Close is sent once', async () => {
  const h = harness(); await h.ready(); assert.equal(h.ui.analyze(), true); const open = h.calls.at(-1);
  assert.equal(h.owner.canRequestClose(), true);
  assert.equal(h.owner.requestClose(), true); assert.equal(h.owner.canRequestClose(), false); assert.equal(h.count('project_identity_close'), 0);
  assert.equal(h.owner.checkStatus(), true); assert.equal(h.owner.getState().pendingCount, 2);
  h.calls.at(-1).resolve(status(1, projection('opening'))); await flush(); const close = h.calls.at(-1);
  assert.equal(close.command, 'project_identity_close'); assert.deepEqual(close.args, { sessionId: SID });
  assert.equal(h.owner.getState().pendingCount, 2);
  close.resolve(status(2, projection('final', 'edit', { checkout: null, prepared: null, applySubmitted: false, coreOutcome: null, nativeReason: 'discarded' })));
  await flush(); assert.equal(h.owner.getState().pendingCount, 1); assert.ok(h.owner.ownerReason());
  open.resolve(status(1, projection('editing'))); await flush();
  assert.equal(h.owner.getState().pendingCount, 0); assert.equal(h.owner.getState().original.phase, 'final');
  assert.equal(h.count('project_identity_close'), 1); assert.equal(h.count('project_identity_open'), 1);
});

test('a lost Open never retries or attaches a foreign project; explicit original status/close remain available', async () => {
  const h = harness(); await h.ready(); assert.equal(h.owner.canRequestClose(), false);
  assert.equal(h.ui.analyze(), true); h.calls.at(-1).reject(Error('PRIVATE synthetic exception'));
  await flush(); assert.equal(h.owner.getState().issue, 'unconfirmed'); assert.equal(h.calls.length, 2);
  assert.equal(h.ui.analyze(), false); assert.equal(h.owner.checkStatus(), true);
  h.calls.at(-1).resolve(status(1, projection('editing', 'edit', { projectId: 'project-2' }))); await flush();
  assert.equal(h.owner.getState().original, null); assert.equal(h.owner.getState().projectId, 'project-1');
  assert.equal(h.owner.getState().status.active.projectId, 'project-2'); // native summary only, not attached authority
  assert.equal(h.owner.discard({ sessionId: SID }), false); assert.ok(h.owner.ownerReason());
  assert.equal(h.count('project_identity_open'), 1); assert.equal(h.count('project_identity_close'), 0);
  assert.equal(JSON.stringify(h.owner.getState()).includes('PRIVATE'), false);
});

test('App invalidation after real Apply handoff retires consent without cancelling or releasing the original request', async () => {
  const h = harness({ submittedHook: () => {
    assert.equal(h.calls.at(-1).command, 'project_identity_apply');
    assert.equal(h.owner.getState().pendingCount, 1);
    h.owner.beforeContextIntent(); h.change({ ...context(), contextEpoch: 2, blocked: true }); h.ui.retire();
  } });
  await h.ready(); await h.review(); h.ui.acknowledgeReview(true); assert.equal(h.ui.apply(), true);
  assert.equal(h.count('project_identity_close'), 0); assert.equal(h.owner.getState().pendingCount, 1);
  h.calls.at(-1).resolve(status(3, projection('final'))); await flush();
  assert.equal(h.owner.getState().original.coreOutcome.effect, 'committed'); assert.equal(h.owner.getState().pendingCount, 0);
  assert.equal(h.count('project_identity_apply'), 1); assert.equal(h.count('project_identity_close'), 0);
});

test('native finality may arrive before an Apply reply; late transport rejection cannot erase it or free that Promise early', async () => {
  const h = harness(); await h.ready(); await h.review(); h.ui.acknowledgeReview(true); assert.equal(h.ui.apply(), true);
  const apply = h.calls.at(-1); h.emit(status(3, projection('final')));
  assert.equal(h.owner.getState().pendingCount, 1); assert.ok(h.owner.ownerReason()); assert.equal(h.outcomes.length, 1);
  apply.reject(Error('PRIVATE late error')); await flush();
  assert.equal(h.owner.getState().issue, null); assert.equal(h.owner.getState().original.phase, 'final');
  assert.equal(h.owner.getState().pendingCount, 0); assert.equal(h.ui.getSnapshot().result, 'saved');
  assert.equal(h.count('project_identity_apply'), 1);
});

test('current-native revisions keep timer minima and reject a different valid prepared identity or immutable receipt', async () => {
  const h = harness(); await h.ready(); await h.review();
  h.emit(status(2, projection('reviewing', 'edit', { reviewRemainingMs: 10 })));
  h.emit(status(2, projection('reviewing', 'edit', { reviewRemainingMs: 1000 })));
  assert.equal(h.owner.getState().original.reviewRemainingMs, 10);
  const wrong = projection('reviewing'); wrong.prepared.view = preview('com.example.wrong');
  h.emit(status(3, wrong)); assert.equal(h.owner.getState().issue, 'protocol');
  assert.equal(h.owner.getState().original.prepared.view.changes[0].afterId, NEW); assert.equal(h.ui.apply(), false);
  const done = harness(); await done.ready(); await done.review(); done.ui.acknowledgeReview(true); done.ui.apply();
  done.calls.at(-1).resolve(status(3, projection('final'))); await flush();
  done.emit(status(4, projection('final', 'edit', { coreOutcome: { effect: 'rolled_back', journal: 'clean', resources: 'settled', reason: 'filesystem_error' } })));
  assert.equal(done.owner.getState().issue, 'protocol'); assert.equal(done.owner.getState().original.coreOutcome.effect, 'committed');
});

test('Unknown, late settlement and native generation loss never create renewed consent or a replacement connection', async () => {
  const h = harness(); await h.ready(); await h.review(); h.ui.acknowledgeReview(true); h.ui.apply();
  const unknown = status(3, projection('unknown'), { capability: { available: false, reason: 'cleanup_unknown' } });
  h.calls.at(-1).resolve(unknown); await flush();
  h.emit(status(4, projection('unknown', 'edit', { lateSettled: true }), { capability: { available: false, reason: 'cleanup_unknown' } }));
  assert.equal(h.owner.getState().issue, 'cleanup-unknown'); assert.equal(h.ui.getSnapshot().result, null);
  assert.equal(h.owner.connect(), false); assert.equal(h.ui.apply(), false); assert.equal(h.owner.requestClose(), false);
  assert.equal(h.owner.checkStatus(), true); h.calls.at(-1).resolve(status(1, null, { windowGeneration: 'f'.repeat(32) })); await flush();
  assert.ok(h.owner.ownerReason()); assert.equal(h.count('project_identity_open'), 1); assert.equal(h.count('project_identity_apply'), 1);
  const fresh = harness(); await fresh.ready(); await fresh.open();
  fresh.emit(status(2, null, { windowGeneration: 'f'.repeat(32) }));
  assert.equal(fresh.owner.getState().issue, 'generation-changed'); assert.equal(fresh.ui.prepare(), false);
});

test('context/ABA retirement closes only the original pre-Apply review; submitted Apply survives a later project switch', async () => {
  const h = harness(); await h.ready(); await h.open();
  h.owner.beforeContextIntent(); h.change({ ...context(), projectId: 'project-2', contextEpoch: 2 });
  assert.equal(h.calls.at(-1).command, 'project_identity_close'); assert.equal(h.ui.prepare(), false);
  assert.equal(h.owner.analyze({ projectId: 'project-2', selection }), false);
  const sent = harness(); await sent.ready(); await sent.review(); sent.ui.acknowledgeReview(true); sent.ui.apply(); const apply = sent.calls.at(-1);
  sent.owner.beforeContextIntent(); sent.change({ ...context(), projectId: 'project-2', contextEpoch: 2 }); sent.ui.retire();
  assert.equal(sent.count('project_identity_close'), 0);
  apply.resolve(status(3, projection('final'))); await flush();
  assert.equal(sent.ui.getSnapshot().result, null); assert.equal(sent.outcomes[0].projectId, 'project-1');
  assert.equal(sent.owner.getState().original.phase, 'final');
});

test('malformed status and synchronous invocation loss stay unconfirmed without raw errors or admission-shaped success', async () => {
  const h = harness(); await h.ready(); await h.review(); h.ui.acknowledgeReview(true); h.ui.apply();
  h.calls.at(-1).resolve({ schemaVersion: 1, success: true }); await flush();
  assert.equal(h.owner.getState().issue, 'protocol'); assert.equal(h.ui.getSnapshot().result, null); assert.equal(h.ui.apply(), false);
  let throwing = false;
  const lost = harness({ invokeHook: () => { if (throwing) throw Error('PRIVATE synchronous bridge exception'); } });
  await lost.ready(); throwing = true;
  assert.equal(lost.ui.analyze(), false); assert.equal(lost.owner.getState().issue, 'unconfirmed'); assert.ok(lost.owner.ownerReason());
  assert.equal(lost.count('project_identity_open'), 1); assert.equal(lost.ui.analyze(), false);
  assert.match(lost.ui.getSnapshot().message, /could not|couldn't|could not|confirm/i);
  assert.equal(JSON.stringify(lost.owner.getState()).includes('PRIVATE'), false);
});

test('recovery uses separate original revision/intent and the same UI explicit consent, never a normal Apply or draft save', async () => {
  const h = harness(); await h.ready(); assert.equal(h.ui.inspectRecovery(), true);
  assert.deepEqual(h.calls.at(-1).args, { intent: 'recover', projectId: 'project-1' });
  h.calls.at(-1).resolve(status(1, projection('editing', 'recover'))); await flush();
  assert.equal(h.ui.prepareRecovery(), true); assert.deepEqual(h.calls.at(-1).args, { sessionId: SID, revision: REV, intent: 'recover' });
  h.calls.at(-1).resolve(status(2, projection('reviewing', 'recover'))); await flush();
  assert.equal(h.ui.recover(), false); assert.equal(h.ui.acknowledgeReview(true), true); assert.equal(h.ui.recover(), true);
  assert.deepEqual(h.calls.at(-1).args, { sessionId: SID, revision: REV, planToken: PLAN, intent: 'recover' });
  h.calls.at(-1).resolve(status(3, projection('final', 'recover'))); await flush();
  assert.equal(h.ui.getSnapshot().result, 'recovered'); assert.deepEqual(h.submitted, [['project-1', 'recover']]);
});

test('failed original unlisten latches uncertainty after disposal and cannot be treated as a safe rebind', async () => {
  const h = harness({ offHook: () => { throw Error('PRIVATE inert unlisten failure'); } });
  await h.ready(); assert.equal(h.owner.ownerReason(), null);
  const before = h.owner.getState(), count = h.calls.length;
  h.ui.dispose(); h.owner.dispose();
  assert.notEqual(h.owner.getState(), before); assert.equal(h.owner.getState().issue, 'unconfirmed');
  assert.ok(h.owner.ownerReason()); assert.equal(h.owner.getState().pendingCount, 0);
  assert.equal(h.owner.checkStatus(), false); assert.equal(h.owner.connect(), false);
  assert.equal(h.calls.length, count); assert.equal(h.offCount, 1);
  assert.equal(JSON.stringify(h.owner.getState()).includes('PRIVATE'), false);
});

test('disposal retires display/consent but owns both original Open and Close promises until they settle', async () => {
  const h = harness(); await h.ready(); h.ui.analyze(); const open = h.calls.at(-1);
  h.owner.dispose(); assert.equal(h.owner.getState().pendingCount, 1); assert.equal(h.offCount, 0);
  h.emit(status(1, projection('opening'))); const close = h.calls.at(-1); assert.equal(close.command, 'project_identity_close');
  const ended = status(2, projection('final', 'edit', { checkout: null, prepared: null, applySubmitted: false, coreOutcome: null, nativeReason: 'discarded' }));
  close.resolve(ended); await flush(); assert.equal(h.owner.getState().pendingCount, 1); assert.equal(h.offCount, 0);
  open.resolve(ended); await flush(); assert.equal(h.owner.getState().pendingCount, 0); assert.equal(h.offCount, 1);
  assert.equal(h.owner.checkStatus(), false); assert.equal(h.ui.analyze(), false);
});
