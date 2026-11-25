// Whole original controllers with synthetic DATA/ports only. No native tools,
// credentials, Keychain, provider, process or qualification is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { IOSArchiveController, iosArchiveOwnerReason } from '../src/iosArchive.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { copyIOSArchiveRequest, parseIOSArchiveStatus, IOS_SIGNING_CHECK_CONSENT,
  IOS_SIGNING_CHECK_SCOPE, IOS_SIGNING_CHECK_LIMITATIONS, iosArchiveModeAvailability } from '../src/iosArchiveProtocol.ts';

const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };
const CONFIG = { bytes: 512, sha256: 'c'.repeat(64) }, VERSION = { bytes: 40, sha256: 'd'.repeat(64) };
const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32);
const ASSURANCE = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const MODES = { unsigned: true, signed: true, recovery: true, signingCheck: true }; // DATA only.
function policy(optional = []) {
  return { teamId: 'A1B2C3D4E5', distributionCertificateSha256: 'e'.repeat(64),
    assignments: ['apple-p12', 'apple-profile', ...optional].map((kind, i) => ({ kind,
      recordId: String(i + 1).repeat(32), recordRevision: i + 1, contextRevision: 3 })) };
}
function request() { return { projectId: 'p1', draftRevision: 2, baselineGeneration: 3, savedConfig: clone(CONFIG),
  savedVersion: { ...VERSION, source: 'release/version.properties', name: '1.2.3', build: 42 }, signing: policy(), action: 'check-signing' }; }
function operation(input = request(), patch = {}) {
  return { operationId: OP, ownerGeneration: OWNER, context: { ...clone(input), platform: 'ios', operation: 'ios-signing-inputs-check' },
    phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null, ...patch };
}
const status = (revision = 0, op = null, modes = MODES) => ({ schemaVersion: 2, statusRevision: revision, availability: 'available', modeCapabilities: clone(modes), operation: op });
function complete(op) {
  const checks = ['signing-material', 'profile-material', ...(op.context.signing.assignments.some((r) => r.kind === 'ios-firebase') ? ['firebase-material'] : [])]
    .map((check) => ({ check, status: 'PASS' }));
  return { ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', stage: 'checking-inputs',
    activity: { stage: 'checking-inputs', findings: checks },
    disposition: { snapshot: 'not-created', work: 'not-created', output: 'not-created', relativeDirectory: null },
    result: { schemaVersion: 1, scope: IOS_SIGNING_CHECK_SCOPE, checkedAt: '2026-10-20T10:20:30Z', usedConfig: clone(op.context.savedConfig),
      usedVersion: clone(op.context.savedVersion), usedSigning: clone(op.context.signing), checks: clone(checks), limitations: [...IOS_SIGNING_CHECK_LIMITATIONS] } };
}
function snapshot(firebase = false) {
  return { root: '/inert/not-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(CONFIG), issues: [], data: {
      ios: { enabled: true, bundleId: 'org.example.inert', teamId: policy().teamId, distributionCertificateSha256: policy().distributionCertificateSha256 },
      services: { iosFirebase: firebase ? 'required' : 'disabled' }, version: { source: 'release/version.properties', nameKey: 'NAME', buildKey: 'BUILD' } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(ASSURANCE), issues: [] };
}
function assets(optional = []) {
  const assignments = policy(optional).assignments;
  return { mode: 'native', scope: { platform: 'ios', stage: 'candidate', purpose: 'signing' }, contextCurrent: true,
    busy: null, updatingContext: false, observing: false, observationFailed: false, blocked: false, originPending: false,
    status: { schemaVersion: 3, statusRevision: 7, mode: 'session', persistence: null, capability: { available: true, reason: 'none' },
      modes: { session: { available: true, reason: 'none' }, encrypted: { available: true, reason: 'none' } },
      context: { revision: 3, projectId: 'p1', platform: 'ios', stage: 'candidate', purpose: 'signing' },
      operation: { operationId: 9, operation: 'bind', phase: 'idle', reason: 'none', settlement: 'known' },
      records: assignments.map((r) => ({ kind: r.kind, recordId: r.recordId, revision: r.recordRevision, availability: 'assigned' })),
      assignments: assignments.map((r) => ({ ...r, availability: 'available' })) } };
}
async function harness(t, { modes = MODES, firebase = false, optional = ['project-read-token'] } = {}) {
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert', path: '/inert/not-opened' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  workspace = workspaceReducer(workspace, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot: snapshot(firebase), observedAt: 1 });
  let registry = status(0, null, modes), material = assets(optional), clock = 10, versionCall;
  const calls = [], selected = () => workspace.projects.p1;
  const version = new ReleaseVersionController(selected);
  version.setConnection({ mode: 'native', observeReleaseVersion: () => { versionCall = deferred(); return versionCall.promise; } }, {
    runtime: { state: 'available', mode: 'installed', reason: null },
    capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject();
  let listener;
  const api = { mode: 'native', subscribeIOSArchive: async (callback) => { listener = callback; return () => { listener = null; }; },
    iosArchiveStatus: async () => clone(registry),
    prepareIOSArchive: (input) => { const call = { kind: 'prepare', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    startIOSArchive: (input) => { const call = { kind: 'start', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelIOSArchive: (operationId, ownerGeneration) => { const call = { kind: 'cancel', input: { operationId, ownerGeneration }, ...deferred() }; calls.push(call); return call.promise; } };
  const controller = new IOSArchiveController({ selectedProject: selected, releaseVersion: version.getSnapshot,
    assetSession: () => material, otherOperationReason: () => null, now: () => clock });
  const unsubscribe = version.subscribe(controller.syncReleaseVersion);
  controller.setArchiveMode('signing-check'); controller.syncProject(); controller.setVisible(true);
  await controller.connect(api);
  controller.versionIntent(); const reading = version.read();
  assert.ok(versionCall);
  versionCall.resolve({ schemaVersion: 2, source: 'release/version.properties', version: { name: '1.2.3', build: 42 },
    savedConfig: clone(selected().savedConfigContent), savedVersion: clone(VERSION), observationScope: 'single-request-non-atomic', assurance: clone(ASSURANCE) });
  await reading; controller.syncProject();
  t.after(() => { unsubscribe(); controller.dispose(); version.dispose(); });
  return { controller, calls, api, get state() { return controller.getSnapshot(); }, get material() { return material; },
    setMaterial(value) { material = value; controller.syncProject(); }, setClock(value) { clock = value; },
    emit(value) { registry = clone(value); listener?.(clone(value)); },
    async reviewed() {
      const preparing = controller.prepare(); assert.equal(calls.at(-1)?.kind, 'prepare');
      const op = operation(calls.at(-1).input); registry = status(1, op, modes); calls.at(-1).resolve(clone(registry)); await preparing;
      assert.ok(controller.getSnapshot().consent); return op;
    } };
}

test('new request is closed and cannot borrow a build token or select native tools', () => {
  assert.ok(copyIOSArchiveRequest('prepare_ios_archive', request()));
  for (const field of ['path', 'argv', 'openssl', 'signingCheck', 'certificateBinding']) {
    assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { ...request(), [field]: true }), null);
  }
  const token = request(); token.signing = policy(['project-read-token']);
  assert.equal(copyIOSArchiveRequest('prepare_ios_archive', token), null);
  for (const action of [null, 'inspect', 'check']) assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { ...request(), action }), null);
  assert.ok(copyIOSArchiveRequest('start_ios_archive', { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_SIGNING_CHECK_CONSENT }));
  assert.equal(copyIOSArchiveRequest('start_ios_archive', { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_SIGNING_CHECK_CONSENT, confirmation: 'idle' }), null);
});

test('public result is exact historical check data, never an artifact, private key or readiness', () => {
  const value = status(2, complete(operation())); assert.ok(parseIOSArchiveStatus(value));
  for (const field of ['archive', 'certificateBinding', 'releaseReady', 'profileContent', 'privateKey']) {
    const wrong = clone(value); wrong.operation.result[field] = true; assert.equal(parseIOSArchiveStatus(wrong), null);
  }
  for (const phase of ['running', 'stopping', 'unknown']) {
    const wrong = clone(value); wrong.operation.phase = phase; assert.equal(parseIOSArchiveStatus(wrong), null);
  }
  for (const field of ['usedConfig', 'usedVersion']) {
    const wrong = clone(value); wrong.operation.result[field].sha256 = 'f'.repeat(64); assert.equal(parseIOSArchiveStatus(wrong), null);
  }
  const wrong = clone(value); wrong.operation.result.usedSigning.assignments[0].recordRevision++;
  assert.equal(parseIOSArchiveStatus(wrong), null);
  for (const stamp of ['2023-02-29T00:00:00Z', '0000-01-01T00:00:00Z', '2026-10-20T12:00:60Z']) {
    const bad = clone(value); bad.operation.result.checkedAt = stamp; assert.equal(parseIOSArchiveStatus(bad), null);
  }
});

test('old native capability does not enable the separate check mode', async (t) => {
  const modes = { unsigned: true, signed: true, recovery: true };
  assert.equal(iosArchiveModeAvailability(parseIOSArchiveStatus(status(0, null, modes)), 'ios-signing-inputs-check'), 'runtime-unqualified');
  const h = await harness(t, { modes }); await h.controller.prepare(); assert.equal(h.calls.length, 0);
  assert.match(h.controller.prepareReason(), /qualification/);
});

test('same controller reviews without Xcode and excludes even stale unrelated build token', async (t) => {
  const h = await harness(t);
  const material = clone(h.material); material.status.assignments.at(-1).availability = 'unavailable'; h.setMaterial(material);
  assert.equal(h.state.project.selection, null); assert.equal(h.state.project.inputIssue, null);
  assert.equal(h.controller.prepareReason(), null);
  const op = await h.reviewed();
  assert.deepEqual(op.context.signing.assignments.map((r) => r.kind), ['apple-p12', 'apple-profile']);
  assert.equal(h.state.consent.binding.selection, null); assert.equal(h.state.consent.deadline, 60_010);
  assert.equal(h.calls[0].input.action, 'check-signing');
  h.controller.cancel(); const cancel = h.calls.at(-1); cancel.resolve(status(2, { ...op, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' })); await flush();
});

test('one explicit check consent sends one original Start and retains pending invocation', async (t) => {
  const h = await harness(t), op = await h.reviewed();
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((r) => r.kind === 'start').length, 0);
  h.controller.setAcknowledged(OP, OWNER, true);
  const starting = h.controller.start(OP, OWNER); await h.controller.start(OP, OWNER);
  assert.equal(h.calls.filter((r) => r.kind === 'start').length, 1);
  assert.equal(h.calls.at(-1).input.consentVersion, IOS_SIGNING_CHECK_CONSENT); assert.ok(iosArchiveOwnerReason(h.state));
  const result = status(2, complete(op)); h.calls.at(-1).resolve(result); await starting;
  assert.equal(h.state.status.operation.result.scope, IOS_SIGNING_CHECK_SCOPE); assert.equal(h.state.consent, null);
});

test('original one-minute review is not renewed by status', async (t) => {
  const h = await harness(t), op = await h.reviewed(); h.controller.setAcknowledged(OP, OWNER, true);
  h.setClock(60_011); await h.controller.checkStatus(); assert.equal(h.state.consent, null);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((r) => r.kind === 'start').length, 0);
  const cancel = h.calls.find((r) => r.kind === 'cancel'); assert.ok(cancel);
  cancel.resolve(status(2, { ...op, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' })); await flush();
});

test('changing exact assignment retires review and never lends replacement input to old Start', async (t) => {
  const h = await harness(t), op = await h.reviewed(); h.controller.setAcknowledged(OP, OWNER, true);
  const material = clone(h.material); material.status.assignments[0].recordRevision++; h.setMaterial(material);
  assert.equal(h.state.consent, null); await h.controller.start(OP, OWNER);
  assert.equal(h.calls.filter((r) => r.kind === 'start').length, 0);
  h.calls.at(-1).resolve(status(2, { ...op, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'context-changed' })); await flush();
});

test('lost Start ACK and native unknown keep original controls without retry or result', async (t) => {
  const h = await harness(t), op = await h.reviewed(); h.controller.setAcknowledged(OP, OWNER, true);
  const starting = h.controller.start(OP, OWNER); h.calls.at(-1).reject(new Error('private text must not escape')); await starting;
  h.emit(status(3, { ...op, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' }));
  assert.ok(iosArchiveOwnerReason(h.state)); assert.equal(h.state.status.operation.result, null); assert.equal(h.state.consent, null);
  assert.equal(h.controller.canCheckStatus(), true); await h.controller.prepare(); await h.controller.start(OP, OWNER);
  assert.equal(h.calls.filter((r) => r.kind === 'start').length, 1);
  assert.equal(JSON.stringify(h.state).includes('private text'), false);
  for (const call of h.calls.filter((r) => r.kind === 'cancel')) call.resolve(clone(h.state.status)); await flush();
});

test('saved-required Firebase must be assigned, optional stale Firebase is not borrowed', async (t) => {
  const missing = await harness(t, { firebase: true, optional: [] });
  await missing.controller.prepare(); assert.equal(missing.calls.length, 0); assert.match(missing.state.signing.issue, /Firebase/);
  const present = await harness(t, { firebase: true, optional: ['ios-firebase', 'project-read-token'] });
  assert.equal(present.controller.prepareReason(), null); assert.deepEqual(present.state.signing.policy.assignments.map((r) => r.kind), ['apple-p12', 'apple-profile', 'ios-firebase']);
  const optional = await harness(t, { optional: ['ios-firebase'] });
  const material = clone(optional.material); material.status.assignments.at(-1).availability = 'unavailable'; optional.setMaterial(material);
  assert.equal(optional.controller.prepareReason(), null); assert.equal(optional.state.signing.policy.assignments.length, 2);
});
