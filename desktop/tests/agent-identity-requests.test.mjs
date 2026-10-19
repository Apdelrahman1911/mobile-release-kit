// Closed DATA/RAW transport and the existing original-Promise UI controller.
// No native window, EditOwner, filesystem, process, credentials or Store work.
import assert from 'node:assert/strict';
import test from 'node:test';
import { bindAgentIdentityApi, createAgentIdentityApi, encodeAgentIdentityRequest,
  parseAgentIdentityGuiStatus, createProjectIdentityApi, ProjectIdentityNativeController } from '../src/projectIdentityNative.ts';
import { ProjectIdentityController } from '../src/projectIdentityController.ts';
import { IDENTITY_NEW_WARNING } from '../src/projectIdentity.ts';

const INSTANCE = 'a'.repeat(32), INTENT = 'b'.repeat(32), PROJECT = 'c'.repeat(32);
const SID = 'd'.repeat(32), REV = 'e'.repeat(32), PLAN = 'f'.repeat(32), WIN = '1'.repeat(32);
const OLD = 'com.example.original', NEW = 'com.example.separate';
const target = () => ({ platform: 'android', target: ':app', project: null });
const proposal = () => ({ runtimeId: 'project-1', request: { serviceInstance: INSTANCE, intentId: INTENT,
  projectId: PROJECT, expectedObservationRevision: 3, change: { selection: target(), desiredIdentity: NEW, identityIntent: 'new-application' } } });
const row = (overrides = {}) => ({ serviceInstance: INSTANCE, projectId: PROJECT, intentId: INTENT, state: 'queued',
  operationId: null, originalLinkRetained: false, historyMustBeQueried: false, ...overrides });
const gui = () => ({ lease: { enabled: true, remainingMs: 900_000, projectId: PROJECT }, pending: proposal(), requests: [row()] });
const opened = () => ({ intent: 'edit', projectId: 'project-1', selection: target() });
const prepared = () => ({ intent: 'edit', sessionId: SID, revision: REV, desiredIdentity: NEW, identityIntent: 'new-application' });
const apply = () => ({ intent: 'edit', sessionId: SID, revision: REV, planToken: PLAN });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 18; n++) await Promise.resolve(); };

function ports(hook) {
  const calls = []; let event;
  const invoke = (command, body) => {
    assert.ok(body instanceof Uint8Array); assert.ok(body.byteLength <= 4096);
    const original = deferred();
    const call = { command, args: JSON.parse(new TextDecoder().decode(body)), ...original };
    calls.push(call); hook?.(call); return original.promise;
  };
  const base = createProjectIdentityApi('native', invoke, (_name, listener) => { event = listener; return Promise.resolve(() => {}); });
  const agent = createAgentIdentityApi('native', invoke);
  return { calls, base, agent, emit: (value) => event(value), bound: (p = proposal()) => bindAgentIdentityApi(base, agent, p) };
}

test('seven closed native commands queue/review DATA; no preview or generic-command fallback', () => {
  const p = ports();
  assert.equal(p.calls.length, 0);
  const operations = [p.agent.status(), p.agent.allow('project-1'), p.agent.revoke(), p.agent.decline(INTENT),
    p.agent.review(INTENT), p.agent.prepare({ intentId: INTENT, sessionId: SID, revision: REV, acknowledgeNewApplication: true }),
    p.agent.apply({ intentId: INTENT, sessionId: SID, revision: REV, planToken: PLAN, reviewed: true })];
  assert.deepEqual(p.calls.map((v) => v.command), ['agent_identity_status', 'allow_agent_identity', 'revoke_agent_identity',
    'decline_agent_identity', 'review_agent_identity', 'prepare_agent_identity', 'apply_agent_identity']);
  for (let i = 0; i < operations.length; i++) { assert.equal(operations[i], p.calls[i].promise); p.calls[i].resolve(null); }
  assert.equal(createAgentIdentityApi('preview', () => assert.fail('no invocation')), null);
  assert.equal(encodeAgentIdentityRequest('execute', {}), null);
});

test('closed RAW inputs reject caller roots, continuity, secrets, duplicate authority and implicit acknowledgements', () => {
  for (const [command, value] of [
    ['allow_agent_identity', { projectId: 'project-1', root: '/not-authority' }],
    ['allow_agent_identity', { projectId: '/project-1' }],
    ['review_agent_identity', { intentId: INTENT, window: 'main' }],
    ['review_agent_identity', { intentId: '0'.repeat(32) }],
    ['prepare_agent_identity', { intentId: INTENT, sessionId: SID, revision: REV }],
    ['prepare_agent_identity', { intentId: INTENT, sessionId: SID, revision: REV, acknowledgeNewApplication: true, desiredIdentity: NEW }],
    ['apply_agent_identity', { intentId: INTENT, sessionId: SID, revision: REV, planToken: REV, reviewed: true }],
    ['apply_agent_identity', { intentId: INTENT, sessionId: SID, revision: REV, planToken: PLAN }],
    ['revoke_agent_identity', { credential: 'not-a-credential-fixture' }],
    ['agent_identity_status', { padding: 'x'.repeat(4097) }],
  ]) assert.equal(encodeAgentIdentityRequest(command, value), null);
  let reads = 0;
  const getter = { get intentId() { reads++; return INTENT; } };
  assert.equal(encodeAgentIdentityRequest('review_agent_identity', getter), null);
  assert.equal(reads, 0);
});

test('GUI observations are bounded immutable DATA, never native settlement or a history ACK', () => {
  const input = gui(), output = parseAgentIdentityGuiStatus(input);
  assert.ok(output); input.pending.request.change.desiredIdentity = 'com.example.changed';
  assert.equal(output.pending.request.change.desiredIdentity, NEW);
  assert.ok(Object.isFrozen(output.pending.request.change.selection));
  assert.ok(Object.isFrozen(output.requests[0]));
  for (const mutation of [
    (v) => { v.lease.remainingMs = 900_001; },
    (v) => { v.lease.enabled = false; },
    (v) => { v.pending.request.change.selection.continuity = 'unknown'; },
    (v) => { v.pending.request.expectedObservationRevision = 0; },
    (v) => { v.pending.request.serviceInstance = '0'.repeat(32); },
    (v) => { v.requests[0].state = 'succeeded'; },
    (v) => { v.requests[0].operationId = SID; },
    (v) => { v.requests[0].originalLinkRetained = true; },
    (v) => { v.requests.push({ ...v.requests[0] }); },
    (v) => { v.requests = Array.from({ length: 33 }, () => row()); },
  ]) { const value = gui(); mutation(value); assert.equal(parseAgentIdentityGuiStatus(value), null); }
  const lost = { lease: { enabled: false, remainingMs: 0, projectId: null }, pending: null,
    requests: [row({ state: 'original-sid-available', operationId: SID, historyMustBeQueried: true, originalLinkRetained: false })] };
  const observed = parseAgentIdentityGuiStatus(lost);
  assert.ok(observed); assert.equal(observed.requests[0].state, 'original-sid-available');
  assert.equal(observed.requests[0].historyMustBeQueried, true);
  assert.equal(Object.hasOwn(observed.requests[0], 'settled'), false);
});

test('binding sends nothing until explicit original Open, rejects changed selection and cannot replay lost Open ACK', async () => {
  const p = ports(), binding = p.bound(); assert.ok(binding); assert.equal(p.calls.length, 0);
  assert.throws(() => binding.open({ ...opened(), projectId: 'project-2' }));
  assert.throws(() => binding.open({ ...opened(), selection: { ...target(), target: ':other' } }));
  assert.equal(p.calls.length, 0);
  const original = binding.open(opened());
  assert.equal(p.calls.length, 1); assert.equal(original, p.calls[0].promise);
  assert.deepEqual(p.calls[0].args, { intentId: INTENT }); assert.equal(p.calls[0].command, 'review_agent_identity');
  assert.throws(() => binding.open(opened()));
  p.calls[0].reject(new Error('inert lost acknowledgement')); await assert.rejects(original);
  assert.throws(() => binding.open(opened())); assert.equal(p.calls.length, 1);
});

test('same immutable proposal is checked before every renderer Prepare and uses the fixed intent-only native body', () => {
  const p = ports(), input = proposal(), binding = p.bound(input);
  input.request.change.desiredIdentity = 'com.example.changed'; input.request.change.selection.target = ':changed';
  assert.throws(() => binding.prepare(prepared())); assert.throws(() => binding.apply(apply()));
  binding.open(opened()); p.calls[0].resolve(null);
  assert.throws(() => binding.prepare({ ...prepared(), desiredIdentity: 'com.example.changed' }));
  assert.throws(() => binding.prepare({ ...prepared(), identityIntent: 'preserve' }));
  assert.throws(() => binding.prepare({ ...prepared(), arbitrary: true }));
  binding.prepare(prepared());
  assert.deepEqual(p.calls.at(-1).args, { intentId: INTENT, sessionId: SID, revision: REV, acknowledgeNewApplication: true });
  assert.equal(p.calls.at(-1).command, 'prepare_agent_identity'); p.calls.at(-1).resolve(null);
  binding.apply(apply());
  assert.deepEqual(p.calls.at(-1).args, { intentId: INTENT, sessionId: SID, revision: REV, planToken: PLAN, reviewed: true });
  assert.equal(p.calls.at(-1).command, 'apply_agent_identity'); p.calls.at(-1).resolve(null);
});

test('captured original Status/Close and separate explicit GUI Recovery survive proposal permission loss', () => {
  const p = ports(), binding = p.bound();
  assert.throws(() => { p.agent.review = () => assert.fail('must retain original transport'); });
  // Frozen APIs cannot be replaced; use the original bound transport instead.
  assert.equal(Object.isFrozen(p.agent), true);
  p.agent.revoke(); assert.equal(p.calls.at(-1).command, 'revoke_agent_identity');
  p.calls.at(-1).resolve({ lease: { enabled: false, remainingMs: 0, projectId: null }, pending: null, requests: [] });
  binding.status(); assert.equal(p.calls.at(-1).command, 'project_identity_status'); p.calls.at(-1).resolve(null);
  binding.close({ sessionId: SID }); assert.equal(p.calls.at(-1).command, 'project_identity_close'); p.calls.at(-1).resolve(null);
  binding.open({ intent: 'recover', projectId: 'project-1' });
  assert.deepEqual(p.calls.at(-1).args, { intent: 'recover', projectId: 'project-1' }); p.calls.at(-1).resolve(null);
  binding.prepare({ intent: 'recover', sessionId: SID, revision: REV });
  assert.equal(p.calls.at(-1).command, 'project_identity_prepare'); p.calls.at(-1).resolve(null);
  binding.apply({ intent: 'recover', sessionId: SID, revision: REV, planToken: PLAN });
  assert.equal(p.calls.at(-1).command, 'project_identity_apply'); p.calls.at(-1).resolve(null);
  assert.equal(p.calls.some((v) => v.command.startsWith('review_agent') || v.command.startsWith('apply_agent')), false);
});

const locations = () => [{ path: 'app/build.gradle.kts', line: 1, column: 1, role: 'android-application-id' },
  { path: 'release/mobile-release.json', line: 1, column: 1, role: 'saved-identity' }];
const selection = () => ({ ...target(), continuity: 'unknown' });
const analysis = () => ({ schemaVersion: 1, kind: 'project-identity', revision: REV, selection: selection(), state: 'supported',
  identity: OLD, configuredIdentity: OLD, identityStatus: 'unverified', configurations: ['release'], locations: locations(),
  diagnostics: [], nextStep: 'Review the app ID.', scope: 'recognized-literal-source-only', buildVerificationRequired: true });
const preview = () => ({ schemaVersion: 1, kind: 'project-identity-preview', revision: REV, selection: selection(),
  intent: 'new-application', state: 'change', changes: locations().map((v) => ({ ...v, beforeId: OLD, afterId: NEW })),
  warnings: [IDENTITY_NEW_WARNING], invalidations: ['credential-assessments-and-assignments', 'prepared-release-plans', 'candidate-identity-revision'],
  retainVersionReservations: true, buildVerificationRequired: true });
const projection = (phase) => ({ domain: 'project_identity', intent: 'edit', projectId: 'project-1', sessionId: SID,
  ownerGeneration: WIN, phase, reviewRemainingMs: 1000, checkout: { revision: REV, view: analysis() },
  prepared: ['reviewing', 'applying'].includes(phase) ? { revision: REV, planToken: PLAN, view: preview() } : null,
  diagnostic: null, applySubmitted: phase === 'applying', coreOutcome: null, nativeReason: 'none', nativeFinality: 'pending', lateSettled: false });
const status = (revision = 0, phase = null) => ({ schemaVersion: 1, domain: 'project_identity', windowGeneration: WIN,
  statusRevision: revision, capability: { available: true, reason: 'available' }, active: phase ? projection(phase) : null, lastTerminal: null });

test('actual shared renderer controller requires source read, separate new-app ACK and exact preview ACK before Apply', async () => {
  const p = ports(), context = { projectId: 'project-1', selection: selection(), contextEpoch: 1, preview: false, blocked: false };
  const original = new ProjectIdentityNativeController(p.bound(), { current: () => context });
  const ui = new ProjectIdentityController(() => context, original); ui.subscribe(() => {});
  assert.equal(original.connect(), true); await flush();
  assert.equal(p.calls.length, 1); assert.equal(p.calls[0].command, 'project_identity_status');
  p.calls[0].resolve(status()); await flush();
  assert.equal(p.calls.length, 1, 'connecting never accepts/opens a proposal');
  assert.equal(ui.analyze(), true); assert.equal(p.calls.at(-1).command, 'review_agent_identity');
  p.calls.at(-1).resolve(status(1, 'editing')); await flush();
  // Same explicit DATA seed as App; neither acknowledgement is restored.
  assert.equal(ui.setIntent('new-application'), true); assert.equal(ui.setDesiredIdentity(NEW), true);
  assert.equal(ui.getSnapshot().newApplicationAcknowledged, false);
  assert.equal(ui.prepare(), false); assert.equal(p.calls.length, 2);
  assert.equal(ui.acknowledgeNewApplication(true), true); assert.equal(ui.prepare(), true);
  assert.equal(p.calls.at(-1).command, 'prepare_agent_identity');
  p.calls.at(-1).resolve(status(2, 'reviewing')); await flush();
  assert.equal(ui.getSnapshot().reviewCurrent, true); assert.equal(ui.apply(), false);
  assert.equal(ui.acknowledgeReview(true), true); assert.equal(ui.apply(), true);
  assert.equal(p.calls.at(-1).command, 'apply_agent_identity');
  assert.equal(ui.apply(), false, 'the actual original controller retains one Apply promise');
  p.calls.at(-1).resolve(status(3, 'applying')); await flush();
  assert.equal(ui.getSnapshot().session.nativeFinality, 'pending', 'returned DATA is not native finality');
});

test('bound adapter rejects getter/unknown fields without reading proposed replacement values or dispatch', () => {
  const p = ports(), binding = p.bound(); let reads = 0;
  const request = { ...opened(), get selection() { reads++; return target(); } };
  assert.throws(() => binding.open(request)); assert.equal(reads, 0); assert.equal(p.calls.length, 0);
  const poisoned = proposal(); Object.defineProperty(poisoned.request.change, 'desiredIdentity', { enumerable: true, get() { reads++; return NEW; } });
  assert.equal(p.bound(poisoned), null); assert.equal(reads, 0);
});
