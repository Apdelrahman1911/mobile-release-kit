// Inert RAW/Promise/controller tests. No native Session, filesystem, process,
// Store request or joined-finality receipt is manufactured by these fixtures.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AGENT_IDENTITY_ACTION_CONSENT, AgentIdentityActionController, createAgentIdentityActionApi,
  encodeIdentityActionRequest, parseIdentityActionStatus } from '../src/agentIdentityActions.ts';
import { ProjectIdentityNativeController, bindAgentIdentityApi, createAgentIdentityApi, createProjectIdentityApi } from '../src/projectIdentityNative.ts';
import { ProjectIdentityController } from '../src/projectIdentityController.ts';
import { IDENTITY_NEW_WARNING, parseIdentityOwnerSnapshot } from '../src/projectIdentity.ts';

const WIN = '1'.repeat(32), SID = '2'.repeat(32), REV = '3'.repeat(32), PLAN = '4'.repeat(32);
const INSTANCE = '5'.repeat(32), PROJECT = '6'.repeat(32), INTENT = '7'.repeat(32);
const OLD = 'com.example.original', NEW = 'com.example.different';
const target = { platform: 'android', target: ':app', project: null };
const selection = { ...target, continuity: 'unknown' };
const locations = [{ path: 'app/build.gradle.kts', line: 7, column: 3, role: 'android-application-id' },
  { path: 'release/mobile-release.json', line: 2, column: 4, role: 'saved-identity' }];
const change = () => ({ selection: { ...target }, desiredIdentity: NEW, identityIntent: 'new-application' });
const proposal = () => ({ runtimeId: 'project-1', request: { serviceInstance: INSTANCE, projectId: PROJECT, intentId: INTENT, expectedObservationRevision: 1, change: change() } });
const analysis = () => ({ schemaVersion: 1, kind: 'project-identity', revision: REV, selection: { ...selection }, state: 'supported', identity: OLD, configuredIdentity: OLD,
  identityStatus: 'unverified', configurations: ['release'], locations: structuredClone(locations), diagnostics: [], nextStep: 'Review the recognized app ID.',
  scope: 'recognized-literal-source-only', buildVerificationRequired: true });
const preview = (next = NEW) => ({ schemaVersion: 1, kind: 'project-identity-preview', revision: REV, selection: { ...selection }, intent: 'new-application', state: 'change',
  changes: locations.map(row => ({ ...row, beforeId: OLD, afterId: next })), warnings: [IDENTITY_NEW_WARNING],
  invalidations: ['credential-assessments-and-assignments', 'prepared-release-plans', 'candidate-identity-revision'], retainVersionReservations: true, buildVerificationRequired: true });
function projection(phase = 'editing', override = {}) {
  return { domain: 'project_identity', intent: 'edit', projectId: 'project-1', sessionId: SID, ownerGeneration: WIN, phase, reviewRemainingMs: 10_000,
    checkout: { revision: REV, view: analysis() }, prepared: ['editing', 'preparing'].includes(phase) ? null : { revision: REV, planToken: PLAN, view: preview() },
    diagnostic: null, applySubmitted: ['applying', 'final', 'unknown'].includes(phase), coreOutcome: phase === 'final'
      ? { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: phase === 'unknown' ? 'cleanup_unknown' : 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false, ...override };
}
function ownerStatus(revision = 0, p = null) {
  const s = { schemaVersion: 1, domain: 'project_identity', windowGeneration: WIN, statusRevision: revision, capability: { available: true, reason: 'available' },
    active: p && !['final', 'unknown'].includes(p.phase) ? p : null, lastTerminal: p && ['final', 'unknown'].includes(p.phase) ? p : null };
  assert.ok(parseIdentityOwnerSnapshot({ busy: false, status: s })); return s;
}
function actionStatus(overrides = {}) {
  const s = { origin: { serviceInstance: INSTANCE, projectId: PROJECT, intentId: INTENT }, change: change(), original: { operationId: SID, ownerGeneration: WIN, revision: REV },
    prepare: 'not-requested', start: 'not-requested', permissionLive: true, remainingMs: 10_000, cancelRequested: false, unconfirmed: false,
    observation: { statusRevision: 1, state: 'running', settlement: 'pending', applySubmitted: false, review: null, effect: null, journal: null },
    doNotReplay: true, historyMustBeQueried: true, ...overrides };
  assert.ok(parseIdentityActionStatus(s)); return s;
}
function preparedStatus(overrides = {}) {
  return actionStatus({ prepare: 'submitted', observation: { statusRevision: 2, state: 'prepared', settlement: 'pending', applySubmitted: false,
    review: { planToken: PLAN, beforeIdentity: OLD, afterIdentity: NEW, changes: structuredClone(locations), unchanged: false, newApplicationWarning: true,
      buildVerificationRequired: true, retainVersionReservations: true }, effect: null, journal: null }, ...overrides });
}
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function harness({ afterInvoke, retireOnApply = false, mutableApi = false } = {}) {
  let emit, epoch = 1, blocked = false, connection = {}, api, actions, context = { projectId: 'project-1', selection: { ...selection }, contextEpoch: 1, preview: false, blocked: false };
  const calls = [], mutations = [], request = proposal();
  const invoke = (command, body) => { assert.ok(body instanceof Uint8Array); const d = deferred(), c = { command, args: JSON.parse(new TextDecoder().decode(body)), ...d };
    calls.push(c); afterInvoke?.(c); return c.promise; };
  const base = createProjectIdentityApi('native', invoke, (_name, listener) => { emit = listener; return Promise.resolve(() => {}); });
  const bound = bindAgentIdentityApi(base, createAgentIdentityApi('native', invoke), request); assert.ok(bound);
  const native = new ProjectIdentityNativeController(bound, { current: () => context, otherOperationReason: () => blocked ? 'Busy' : null,
    onMutationSubmitted: (p, intent) => { mutations.push([p, intent]); if (retireOnApply) { actions.beforeContextIntent(); epoch++; context.contextEpoch++; native.beforeContextIntent(); editor.retire(); } } });
  const editor = new ProjectIdentityController(() => context, native); editor.subscribe(() => {});
  api = createAgentIdentityActionApi('native', invoke);
  if (mutableApi) api = { ...api };
  const source = () => ({ api, connection, proposal: request, native, editor, epoch, projectId: context.projectId, blocked });
  actions = new AgentIdentityActionController(source);
  return { calls, native, editor, actions, mutations, source,
    async read() { assert.equal(native.connect(), true); await flush(); calls.at(-1).resolve(ownerStatus()); await flush();
      assert.equal(editor.analyze(), true); assert.equal(calls.at(-1).command, 'review_agent_identity'); calls.at(-1).resolve(ownerStatus(1, projection())); await flush();
      assert.equal(editor.setIntent('new-application'), true); assert.equal(editor.setDesiredIdentity(NEW), true); actions.sync(); },
    acknowledgeNew() { assert.equal(editor.acknowledgeNewApplication(true), true); actions.sync(); },
    allow() { assert.equal(actions.acknowledge(true), true); assert.equal(actions.allow(), true); return calls.at(-1); },
    async allowed() { this.acknowledgeNew(); const call = this.allow(); assert.equal(call.command, 'allow_agent_identity_action'); call.resolve(actionStatus()); await flush(); actions.sync(); },
    emit(s) { emit(s); actions.sync(); },
    retire() { actions.beforeContextIntent(); epoch++; context.contextEpoch++; native.beforeContextIntent(); editor.retire(); },
    block(v) { blocked = v; context.blocked = v; actions.sync(); },
    replaceApi(next) { api = next; connection = {}; actions.sync(); },
    replaceMethods(fn) { api.allow = fn; api.status = fn; api.revoke = fn; },
    bumpEpoch() { epoch++; actions.sync(); },
    async finishAll() { for (const c of calls) c.resolve(null); await flush(); },
  };
}

test('three exact RAW permission calls have no preview fallback or caller-supplied change/root', async () => {
  const calls = [], api = createAgentIdentityActionApi('native', (c, raw) => { calls.push([c, JSON.parse(new TextDecoder().decode(raw))]); return Promise.resolve(null); });
  assert.equal(calls.length, 0);
  await api.allow({ intentId: INTENT, sessionId: SID, revision: REV, acknowledgeNewApplication: true, consentVersion: AGENT_IDENTITY_ACTION_CONSENT });
  await api.status(INTENT); await api.revoke(INTENT);
  assert.deepEqual(calls.map(c => c[0]), ['allow_agent_identity_action', 'agent_identity_action_status', 'revoke_agent_identity_action']);
  assert.equal(createAgentIdentityActionApi('preview', () => assert.fail('never')), null);
  let getterReads = 0;
  for (const v of [{ intentId: INTENT, root: '/not-authority' }, { intentId: '0'.repeat(32) }, { get intentId() { getterReads++; return INTENT; } }, { intentId: INTENT, [Symbol('hidden')]: true }]) {
    assert.equal(encodeIdentityActionRequest('agent_identity_action_status', v), null);
  }
  assert.equal(getterReads, 0);
  assert.equal(encodeIdentityActionRequest('apply_agent_identity', {}), null);
  assert.equal(encodeIdentityActionRequest('allow_agent_identity_action', { ...calls[0][1], desiredIdentity: NEW }), null);
  assert.equal(encodeIdentityActionRequest('allow_agent_identity_action', { ...calls[0][1], consentVersion: 'old-proposal-consent' }), null);
});

test('bounded status keeps unknown/recovery/noop distinct and rejects authority or contradictory success', () => {
  const valid = preparedStatus(), parsed = parseIdentityActionStatus(valid); assert.ok(parsed); assert.ok(Object.isFrozen(parsed.observation.review.changes));
  valid.observation.review.changes[0].path = 'changed'; assert.equal(parsed.observation.review.changes[0].path, locations[0].path);
  for (const mutate of [v => { v.credential = 'not-a-private-fixture'; }, v => { v.remainingMs = 900_001; }, v => { v.permissionLive = false; },
    v => { v.original.operationId = '0'.repeat(32); }, v => { v.observation.state = 'succeeded'; }, v => { v.observation.review.retainVersionReservations = false; },
    v => { v.observation.review.changes.push({ ...v.observation.review.changes[0] }); }, v => { v.observation.review.changes[0].path = '../foreign'; },
    v => { v.observation.review.changes[0].role = 'ios-bundle-id'; }, v => { v.observation.review.changes = Array(66).fill(locations[0]); },
    v => { v.prepare = 'not-requested'; }, v => { v.prepare = 'unconfirmed'; },
    v => { v.observation.settlement = 'settled'; v.observation.effect = 'unknown'; v.observation.journal = 'unknown'; },
    v => { v.observation.review.beforeIdentity = 'x'.repeat(256); }]) { const v = preparedStatus(); mutate(v); assert.equal(parseIdentityActionStatus(v), null); }
  const unknown = preparedStatus({ permissionLive: false, remainingMs: 0, unconfirmed: true });
  Object.assign(unknown.observation, { state: 'unknown', settlement: 'unknown', effect: 'unknown', journal: 'unknown' }); assert.ok(parseIdentityActionStatus(unknown));
  const recovery = structuredClone(unknown); recovery.unconfirmed = false; recovery.start = 'submitted';
  Object.assign(recovery.observation, { state: 'recovery-required', settlement: 'settled', effect: 'committed', journal: 'recovery_required', applySubmitted: true }); assert.ok(parseIdentityActionStatus(recovery));
  const noop = structuredClone(recovery); noop.change.desiredIdentity = OLD;
  Object.assign(noop.observation, { state: 'succeeded', effect: 'unchanged', journal: 'not_created' });
  Object.assign(noop.observation.review, { afterIdentity: OLD, changes: [], unchanged: true, newApplicationWarning: false }); assert.ok(parseIdentityActionStatus(noop));
});

test('read access/proposal and seeded draft never delegate without source/new-app/exact-change acknowledgement', async () => {
  const h = harness(); assert.equal(h.actions.allow(), false); assert.equal(h.calls.length, 0);
  await h.read(); assert.equal(h.actions.acknowledge(true), false); assert.equal(h.actions.allow(), false);
  h.acknowledgeNew(); assert.equal(h.actions.getSnapshot().canAllow, false);
  assert.equal(h.actions.acknowledge(true), true); assert.equal(h.actions.getSnapshot().canAllow, true);
  h.editor.setDesiredIdentity('com.example.other'); h.actions.sync(); assert.equal(h.actions.getSnapshot().reviewed, false); assert.equal(h.actions.allow(), false);
  assert.equal(h.calls.filter(c => c.command === 'allow_agent_identity_action').length, 0); await h.finishAll();
});

test('one allowed proposal accepts original external Prepare/Apply observations without a second GUI Apply', async () => {
  const h = harness({ retireOnApply: true }); await h.read(); await h.allowed();
  assert.equal(h.actions.allow(), false); assert.equal(h.native.prepare({ sessionId: SID, revision: REV, desiredIdentity: NEW, intent: 'new-application' }), false);
  h.emit(ownerStatus(2, projection('reviewing'))); assert.equal(h.native.getState().issue, null);
  assert.equal(h.editor.getSnapshot().preview.changes[0].afterId, NEW); assert.equal(h.editor.getSnapshot().actions.apply, false);
  assert.equal(h.native.apply({ sessionId: SID, revision: REV, planToken: PLAN }), false);
  assert.equal(h.actions.check(), true); h.calls.at(-1).resolve(preparedStatus()); await flush();
  h.emit(ownerStatus(3, projection('applying'))); assert.deepEqual(h.mutations, [['project-1', 'edit']]);
  assert.equal(h.native.getState().closeRequested, false); assert.equal(h.calls.some(c => c.command === 'project_identity_close' || c.command === 'apply_agent_identity' || c.command === 'prepare_agent_identity' || c.command === 'revoke_agent_identity_action'), false);
  h.emit(ownerStatus(4, projection('final'))); assert.equal(h.native.getState().issue, null); assert.equal(h.native.getState().pendingCount, 0);
  assert.equal(h.actions.check(), true);
  const final = preparedStatus({ start: 'submitted', permissionLive: false, remainingMs: 0 });
  Object.assign(final.observation, { statusRevision: 4, state: 'succeeded', settlement: 'settled', applySubmitted: true, effect: 'committed', journal: 'clean' });
  h.calls.at(-1).resolve(final); await flush(); assert.match(h.actions.getSnapshot().message, /finished/);
  assert.equal(h.actions.getSnapshot().status.historyMustBeQueried, true); assert.equal(h.mutations.length, 1); await h.finishAll();
});

test('changed original preview is still rejected by the existing native controller', async () => {
  const h = harness(); await h.read(); await h.allowed();
  h.emit(ownerStatus(2, projection('reviewing', { prepared: { revision: REV, planToken: PLAN, view: preview('com.example.foreign') } })));
  assert.equal(h.native.getState().issue, 'protocol'); assert.equal(h.editor.getSnapshot().actions.apply, false); await h.finishAll();
});

test('Revoke immediately overlaps pending Allow, retaining both original promises in either response order', async () => {
  for (const revokeFirst of [false, true]) {
    const h = harness(); await h.read(); h.acknowledgeNew(); const allow = h.allow();
    assert.equal(h.actions.revoke(), true); const stop = h.calls.at(-1); assert.equal(stop.command, 'revoke_agent_identity_action');
    assert.equal(h.actions.getSnapshot().pending, 2); assert.equal(h.actions.allow(), false);
    const stopped = actionStatus({ permissionLive: false, remainingMs: 0, cancelRequested: true });
    (revokeFirst ? stop : allow).resolve(revokeFirst ? stopped : actionStatus()); await flush();
    assert.equal(h.actions.getSnapshot().pending, 1); assert.equal(h.actions.getSnapshot().canAllow, false);
    (revokeFirst ? allow : stop).resolve(revokeFirst ? actionStatus() : stopped); await flush();
    assert.equal(h.actions.getSnapshot().pending, 0); assert.equal(h.actions.getSnapshot().status.permissionLive, false);
    assert.equal(h.actions.getSnapshot().status.cancelRequested, true); assert.equal(h.actions.allow(), false); await h.finishAll();
  }
});

test('reentrant context/ABA or Revoke before permission handoff cannot send Allow', async () => {
  for (const action of ['epoch', 'retire', 'revoke', 'blocked']) {
    const h = harness(); await h.read(); h.acknowledgeNew(); assert.equal(h.actions.acknowledge(true), true);
    let once = false;
    h.actions.subscribe(() => { if (!once && h.actions.getSnapshot().claimed) { once = true;
      if (action === 'epoch') h.bumpEpoch(); else if (action === 'retire') h.retire(); else if (action === 'revoke') h.actions.revoke(); else h.block(true); } });
    assert.equal(h.actions.allow(), false); assert.equal(h.calls.some(c => c.command === 'allow_agent_identity_action'), false);
    assert.equal(h.actions.getSnapshot().claimed, true); assert.equal(h.actions.allow(), false); await h.finishAll();
  }
});

test('Allow reply after real connection replacement cannot revive permission or retarget Stop', async () => {
  const h = harness(); await h.read(); h.acknowledgeNew(); const old = h.allow();
  let foreign = 0; const replacement = createAgentIdentityActionApi('native', () => { foreign++; return Promise.resolve(null); }); h.replaceApi(replacement);
  old.resolve(actionStatus()); await flush(); assert.equal(foreign, 0);
  const stop = h.calls.at(-1); assert.equal(stop.command, 'revoke_agent_identity_action');
  stop.resolve(actionStatus({ permissionLive: false, remainingMs: 0, cancelRequested: true })); await flush();
  assert.equal(h.actions.getSnapshot().canAllow, false); assert.equal(h.actions.getSnapshot().status.permissionLive, false); await h.finishAll();
});

test('original permission methods stay captured through in-place API replacement', async () => {
  const h = harness({ mutableApi: true }); await h.read(); h.acknowledgeNew();
  let foreign = 0; h.replaceMethods(() => { foreign++; return Promise.resolve(null); });
  const allow = h.allow(); assert.equal(allow.command, 'allow_agent_identity_action');
  assert.equal(h.actions.revoke(), true); const stop = h.calls.at(-1);
  assert.equal(stop.command, 'revoke_agent_identity_action'); assert.equal(foreign, 0);
  stop.resolve(actionStatus({ permissionLive: false, remainingMs: 0, cancelRequested: true }));
  allow.resolve(actionStatus()); await flush();
  assert.equal(h.actions.check(), true); assert.equal(h.calls.at(-1).command, 'agent_identity_action_status');
  h.calls.at(-1).resolve(actionStatus({ permissionLive: false, remainingMs: 0, cancelRequested: true })); await flush();
  assert.equal(foreign, 0); await h.finishAll();
});

test('lost/malformed Allow acknowledgement stays unknown and cannot be retried or cleared by null status', async () => {
  for (const failure of ['rejected', 'malformed']) {
    const h = harness(); await h.read(); h.acknowledgeNew(); const call = h.allow();
    if (failure === 'rejected') call.reject(new Error('must not display raw')); else call.resolve({ success: true });
    await flush(); assert.equal(h.actions.getSnapshot().attention, true); assert.match(h.actions.getSnapshot().message, /Do not repeat/);
    assert.equal(h.actions.allow(), false); assert.equal(h.actions.check(), true); h.calls.at(-1).resolve(null); await flush();
    assert.equal(h.actions.getSnapshot().attention, true); assert.doesNotMatch(h.actions.getSnapshot().message, /must not display raw/);
    assert.equal(h.actions.revoke(), true); h.calls.at(-1).resolve(null); await flush(); assert.equal(h.actions.getSnapshot().attention, true); await h.finishAll();
  }
});

test('native Unknown and recovery remain visible, never converted into success by permission/data replies', async () => {
  for (const state of ['unknown', 'recovery-required']) {
    const h = harness(); await h.read(); await h.allowed(); assert.equal(h.actions.check(), true);
    const s = preparedStatus({ permissionLive: false, remainingMs: 0, prepare: 'submitted', start: 'submitted' });
    Object.assign(s.observation, { state, settlement: state === 'unknown' ? 'unknown' : 'settled', applySubmitted: true,
      effect: state === 'unknown' ? 'unknown' : 'committed', journal: state === 'unknown' ? 'unknown' : 'recovery_required' });
    h.calls.at(-1).resolve(s); await flush(); assert.equal(h.actions.getSnapshot().attention, true);
    assert.match(h.actions.getSnapshot().message, state === 'unknown' ? /could not be confirmed/ : /needs recovery/); assert.equal(h.actions.allow(), false); await h.finishAll();
  }
});

test('same revision contradiction, original/preview replacement and permission resurrection are refused', async () => {
  for (const mutate of [s => { s.original.ownerGeneration = '8'.repeat(32); }, s => { s.observation.statusRevision = 1; s.observation.state = 'prepared'; },
    s => { s.observation.review.changes.reverse(); }, s => { s.remainingMs = 20_000; }]) {
    const h = harness(); await h.read(); await h.allowed(); assert.equal(h.actions.check(), true); const s = preparedStatus(); mutate(s);
    h.calls.at(-1).resolve(s); await flush(); assert.equal(h.actions.getSnapshot().attention, true); await h.finishAll();
  }
});

test('preview-only and published app source cannot obtain new-app delegation', async () => {
  const h = harness(); await h.read(); h.acknowledgeNew(); h.block(true); assert.equal(h.actions.acknowledge(true), false); assert.equal(h.actions.allow(), false);
  const k = harness(); await k.read(); const p = projection(); p.checkout.view.selection.continuity = 'existing'; p.checkout.view.identityStatus = 'approved';
  // Changed same-checkout DATA is rejected by the original manager as drift,
  // rather than treating a new-app UI toggle as published-identity authority.
  k.emit(ownerStatus(2, p)); assert.equal(k.actions.allow(), false); assert.equal(k.native.getState().issue, 'protocol');
  await h.finishAll(); await k.finishAll();
});
