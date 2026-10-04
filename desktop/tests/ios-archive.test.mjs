// Inert renderer DATA/controllers and fixed bridge requests only. Invented
// statuses never prove Xcode execution, file custody, native finality or gate
// qualification. No process, network or native picker is started here.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { IOSArchiveController, iosArchiveOwnerReason, iosArchiveHelp, iosArchiveInputHelp,
  iosArchiveSelectionHelp, iosArchiveOutputHelp, iosArchiveCancelHelp, iosSigningHelp, iosRecoveryHelp } from '../src/iosArchive.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { IOS_ARCHIVE_CONSENT, IOS_ARCHIVE_COUNTER_MAX, IOS_ARCHIVE_EVENT, IOS_ARCHIVE_LIMITATIONS, IOS_ARCHIVE_SCOPE,
  IOS_SIGNED_ARCHIVE_CONSENT, IOS_SIGNED_ARCHIVE_SCOPE, IOS_SIGNED_ARCHIVE_LIMITATIONS, IOS_RECOVERY_CONSENT,
  IOS_ACCOUNT_RECOVERY_CONFIRMATION, IOS_PROJECT_RECOVERY_CONFIRMATION, IOS_RECOVERY_LIMITATIONS,
  copyIOSArchiveRequest, encodeIOSArchiveRequest, parseIOSArchiveStatus, parseIOSSigningPolicy, iosArchiveOperationProgress,
  iosArchiveError, iosArchiveModeAvailability, IOS_ARCHIVE_STATUS_VERSION } from '../src/iosArchiveProtocol.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), OTHER = 'c'.repeat(32);
const CONFIG = { bytes: 512, sha256: 'd'.repeat(64) }, NEW_CONFIG = { bytes: 524, sha256: 'e'.repeat(64) };
const VERSION = { bytes: 41, sha256: 'f'.repeat(64) };
const P12 = '1'.repeat(32), PROFILE = '2'.repeat(32), FIREBASE = '3'.repeat(32), TOKEN = '4'.repeat(32);
const ACCOUNT_SESSION = '5'.repeat(32), PROJECT_SESSION = '6'.repeat(32);
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 16; n++) await Promise.resolve(); };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const info = { runtime: { state: 'available', mode: 'installed', reason: null },
  capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } };
function selection(patch = {}) { return { containerKind: 'project', container: 'ios/Inert.xcodeproj', scheme: 'Inert',
  configuration: 'Release', bundleId: 'org.example.inert', symbolsPolicy: 'required', preparationConfigured: false, ...patch }; }
function snapshot({ config = CONFIG, source = 'release/version.properties', ios = {} } = {}) {
  return { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(config), issues: [],
      data: { ios: { enabled: true, project: 'ios/Inert.xcodeproj', scheme: 'Inert', bundleId: 'org.example.inert',
        archiveConfiguration: 'Release', symbols: { policy: 'required' }, ...ios }, version: { source, nameKey: 'NAME', buildKey: 'BUILD' } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(assurance), issues: [] };
}
function workspace(savedSnapshot = snapshot()) {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert iOS project', path: '/inert/never-forwarded' } });
  if (savedSnapshot === null) return value;
  value = workspaceReducer(value, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  return workspaceReducer(value, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot: savedSnapshot, observedAt: 1 });
}
function observation(project, patch = {}) {
  return { schemaVersion: 2, source: project.snapshot.config.data.version.source, version: { name: '1.2.3', build: 42 },
    savedConfig: clone(project.savedConfigContent), savedVersion: clone(VERSION), observationScope: 'single-request-non-atomic', assurance: clone(assurance), ...patch };
}
const request = () => ({ projectId: 'p1', draftRevision: 2, baselineGeneration: 3, savedConfig: clone(CONFIG),
  savedVersion: { ...VERSION, source: 'release/version.properties', name: '1.2.3', build: 42 } });
const context = (input) => ({ ...clone(input), platform: 'ios', operation: input.recovery ? 'ios-local-recovery' : input.signing ? 'ios-signed-export' : 'ios-unsigned-archive' });
const operation = (input = request(), patch = {}) => ({ operationId: OP, ownerGeneration: OWNER, context: context(input), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null,
  ...(input.recovery ? { report: null } : { disposition: null, result: null }), ...patch });
// Explicit invented controller inputs, never derived from an operation or used
// as native/macOS qualification evidence.
const ALL_TEST_MODES = Object.freeze({ unsigned: true, signed: true, recovery: true });
const UNSIGNED_ONLY = Object.freeze({ unsigned: true, signed: false, recovery: false });
const NO_MODES = Object.freeze({ unsigned: false, signed: false, recovery: false });
const status = (revision = 0, op = null, availability = 'available', modes = ALL_TEST_MODES) => ({
  schemaVersion: IOS_ARCHIVE_STATUS_VERSION, statusRevision: revision, availability, modeCapabilities: { ...modes }, operation: op,
});
const running = (op, stage = 'archiving') => ({ ...clone(op), phase: 'running', intentUsable: false, stage });
const terminal = (op, outcome = 'cancelled', reason = outcome) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome, reason });
function completed(op, selected = selection()) {
  const directory = `.mobile-release/desktop-ios-archive/${op.operationId}`;
  const zero = { outcome: 'exited', exitCode: 0 };
  return { ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', stage: 'disposing-work',
    activity: { stage: 'disposing-work', selection: clone(selected), commands: { 'xcode-version': clone(zero), 'ios-sdk': clone(zero),
      prepare: selected.preparationConfigured ? clone(zero) : { outcome: 'not-configured', exitCode: null }, archive: clone(zero) },
      findings: [{ check: 'archive-identity', status: 'PASS' }, { check: 'archive-dsym', status: 'PASS' }] },
    disposition: { snapshot: 'removed', work: 'removed', output: 'retained-local-result', relativeDirectory: directory },
    result: { schemaVersion: 1, scope: IOS_ARCHIVE_SCOPE, usedConfig: clone(op.context.savedConfig), usedVersion: clone(op.context.savedVersion),
      archive: directory + '/archive.xcarchive', entries: 10, bytes: 1000, limitations: [...IOS_ARCHIVE_LIMITATIONS] } };
}
function signingPolicy(optional = []) {
  const kinds = [['apple-p12', P12], ['apple-profile', PROFILE], ...optional.map((kind) => [kind, kind === 'ios-firebase' ? FIREBASE : TOKEN])];
  return { teamId: 'A1B2C3D4E5', distributionCertificateSha256: 'e'.repeat(64),
    assignments: kinds.map(([kind, recordId], index) => ({ kind, recordId, recordRevision: index + 1, contextRevision: 3 })) };
}
function signedSnapshot(ios = {}) {
  const { teamId, distributionCertificateSha256 } = signingPolicy();
  return snapshot({ ios: { teamId, distributionCertificateSha256, symbols: { policy: 'retain' }, ...ios } });
}
function assetState(optional = []) {
  const assignments = signingPolicy(optional).assignments;
  return { mode: 'native', scope: { platform: 'ios', stage: 'candidate', purpose: 'signing' }, contextCurrent: true,
    busy: null, updatingContext: false, observing: false, observationFailed: false, blocked: false, error: null, previewDeadline: null,
    entryGeneration: 1, selectionKind: null, cancelledOperationId: null, originPending: false, intent: null, reviewReady: false,
    status: { schemaVersion: 3, statusRevision: 7, mode: 'session', persistence: null, capability: { available: true, reason: 'none' },
      modes: { session: { available: true, reason: 'none' }, encrypted: { available: true, reason: 'none' } },
      context: { revision: 3, projectId: 'p1', platform: 'ios', stage: 'candidate', purpose: 'signing' },
      operation: { operationId: 9, operation: 'bind', phase: 'idle', reason: 'none', source: 'captured', settlement: 'known', storageOutcome: null, selectionToken: null, assessment: null, preview: null },
      records: assignments.map((row) => ({ kind: row.kind, recordId: row.recordId, revision: row.recordRevision, availability: 'assigned', storage: 'session', label: null, payloadState: 'assessed' })),
      assignments: assignments.map((row) => ({ ...row, availability: 'available' })) } };
}
function vaultAssetState(optional = []) {
  const value = assetState(optional);
  value.status.mode = 'encrypted';
  value.status.persistence = { state: 'unlocked', reason: 'none', keyAccess: 'read-write' };
  for (const record of value.status.records) record.storage = 'encrypted';
  return value;
}
function signedCompleted(op, selected = selection({ symbolsPolicy: 'retain' })) {
  const value = completed(op, selected);
  value.activity.commands.export = { outcome: 'exited', exitCode: 0 };
  value.activity.findings = ['signing-material', 'profile-material', 'artifact-correspondence', 'ipa-structure', 'ipa-profile', 'ipa-entitlements', 'ipa-signer',
    ...(op.context.signing.assignments.some((row) => row.kind === 'ios-firebase') ? ['firebase-material'] : [])].map((check) => ({ check, status: 'PASS' }));
  value.result = { ...value.result, scope: IOS_SIGNED_ARCHIVE_SCOPE, limitations: [...IOS_SIGNED_ARCHIVE_LIMITATIONS],
    ipa: `.mobile-release/desktop-ios-archive/${op.operationId}/export/Inert.ipa`, ipaBytes: 128,
    pairing: { nativePaths: 2, nativeIdentities: 2, presentSymbolSlices: 1 } };
  return value;
}
const recoveryRequest = (action = 'inspect', session = action === 'account' ? ACCOUNT_SESSION : PROJECT_SESSION) =>
  ({ projectId: 'p1', recovery: action === 'inspect' ? { action } : { action, session } });
function recoveryCompleted(op, patch = {}) {
  const action = op.context.recovery.action;
  return { ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', stage: 'disposing-work',
    activity: { stage: 'disposing-work' }, report: { schemaVersion: 1, scope: 'local-ios-recovery',
      account: action === 'inspect' ? { status: 'pending', session: ACCOUNT_SESSION, next: 'ordinary' } : action === 'account' ? { status: 'recovered', session: op.context.recovery.session, next: 'none' } : null,
      project: action === 'inspect' ? { status: 'cleanup-only', session: PROJECT_SESSION, next: 'ordinary' } : action === 'project' ? { status: 'recovered', session: op.context.recovery.session, next: 'none' } : null,
      limitations: [...IOS_RECOVERY_LIMITATIONS] }, ...patch };
}
function harness(t, { initial = status(), listenGate = null, completeVersion = true, savedSnapshot = snapshot(), assets = null } = {}) {
  let state = workspace(savedSnapshot), registry = clone(initial), clock = 10, other = null, versionOverride, currentAssets = clone(assets);
  const calls = [], reads = [], subscriptions = [], versionCalls = [], order = [];
  const selected = () => state.selectedId ? state.projects[state.selectedId] : null;
  const version = new ReleaseVersionController(selected);
  version.setConnection({ mode: 'native', observeReleaseVersion: (projectId) => {
    const call = { projectId, ...deferred() }; versionCalls.push(call); return call.promise;
  } }, info); version.syncProject();
  const api = { mode: 'native',
    subscribeIOSArchive: async (callback) => {
      order.push('subscribe'); const row = { callback, closed: false }; subscriptions.push(row);
      if (listenGate) await listenGate.promise;
      return () => { row.closed = true; };
    },
    iosArchiveStatus: async () => { order.push('status'); reads.push(clone(registry)); return clone(registry); },
    prepareIOSArchive: (input) => { const call = { kind: 'prepare', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    startIOSArchive: (input) => { const call = { kind: 'start', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelIOSArchive: (operationId, ownerGeneration) => { const call = { kind: 'cancel', input: { operationId, ownerGeneration }, ...deferred() }; calls.push(call); return call.promise; },
  };
  const controller = new IOSArchiveController({ selectedProject: selected,
    releaseVersion: () => versionOverride === undefined ? version.getSnapshot() : versionOverride,
    assetSession: () => currentAssets,
    otherOperationReason: () => typeof other === 'function' ? other() : other, now: () => clock });
  // Same synchronous lifetime wiring required in App; not a late React effect.
  const unsubscribeVersion = version.subscribe(controller.syncReleaseVersion);
  controller.syncProject(); controller.setVisible(true);
  const readVersion = async (value = observation(selected())) => {
    controller.versionIntent(); const before = versionCalls.length, done = version.read();
    assert.equal(versionCalls.length, before + 1); versionCalls.at(-1).resolve(clone(value)); await done;
  };
  const connected = controller.connect(api);
  const ready = connected.then(async () => { if (completeVersion) await readVersion(); });
  t.after(() => { unsubscribeVersion(); controller.dispose(); version.dispose(); });
  return { api, controller, version, calls, reads, subscriptions, versionCalls, order, ready, readVersion,
    get state() { return controller.getSnapshot(); }, get workspace() { return state; }, get project() { return selected(); },
    get versionState() { return version.getSnapshot(); },
    get assets() { return currentAssets; },
    setAssets(value) { currentAssets = clone(value); controller.syncAssetSession(); },
    overrideVersion(value) { versionOverride = value; controller.syncReleaseVersion(); },
    replace(project) { state = { ...state, projects: { ...state.projects, [project.project.id]: project } }; version.syncProject(); controller.syncProject(); },
    dispatch(action) {
      controller.beforeWorkspaceAction(action); version.beforeWorkspaceAction(action);
      const next = workspaceReducer(state, action); if (next === state) return;
      state = next; version.syncProject(); controller.syncProject();
    },
    other(value) { other = value; }, clock(value) { clock = value; },
    emit(value) { registry = clone(value); subscriptions.at(-1)?.callback(clone(value)); },
    reply(call, value) { registry = clone(value); call.resolve(clone(value)); },
  };
}
async function reviewed(h, patch = {}) {
  await h.ready;
  const preparing = h.controller.prepare(), call = h.calls.at(-1); assert.equal(call.kind, 'prepare');
  const op = operation(call.input, patch); h.reply(call, status((h.state.status?.statusRevision ?? 0) + 1, op)); await preparing;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
function start(h, op) {
  h.controller.setAcknowledged(op.operationId, op.ownerGeneration, true);
  const done = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1); assert.equal(call.kind, 'start'); return { call, done };
}
async function reviewedRecovery(h, action = 'inspect', inspected = null, patch = {}) {
  await h.ready; h.controller.setVisible(false); h.controller.setRecoveryVisible(true);
  const count = h.calls.length, preparing = h.controller.prepareRecovery(action, inspected), call = h.calls.at(-1);
  assert.equal(h.calls.length, count + 1); assert.equal(call.kind, 'prepare');
  const op = operation(call.input, patch); h.reply(call, status((h.state.status?.statusRevision ?? 0) + 1, op)); await preparing;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function inspectedRecovery(h, patch = {}) {
  const op = await reviewedRecovery(h), sent = start(h, op), complete = recoveryCompleted(op, patch);
  h.reply(sent.call, status(2, complete)); await sent.done;
  assert.equal(h.state.historical, false); assert.equal(h.state.status.operation.outcome, complete.outcome); return complete;
}

test('native Status requires closed per-mode data; capability observations cannot enter requests', () => {
  const good = status(1, null, 'available', UNSIGNED_ONLY);
  assert.deepEqual(clone(parseIOSArchiveStatus(good)), good);
  for (const modes of [null, {}, [], { unsigned: true, signed: false }, { ...UNSIGNED_ONLY, signed: 1 },
    { ...UNSIGNED_ONLY, recovery: 'false' }, { ...UNSIGNED_ONLY, all: true }])
    assert.equal(parseIOSArchiveStatus({ ...good, modeCapabilities: modes }), null);
  const missing = clone(good); delete missing.modeCapabilities;
  assert.equal(parseIOSArchiveStatus(missing), null);
  assert.equal(parseIOSArchiveStatus({ ...good, schemaVersion: 1 }), null);
  assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { ...request(), modeCapabilities: ALL_TEST_MODES }), null);
  assert.equal(iosArchiveModeAvailability(good, 'ios-unsigned-archive'), 'available');
  assert.equal(iosArchiveModeAvailability(good, 'ios-signed-export'), 'runtime-unqualified');
  assert.equal(iosArchiveModeAvailability(good, 'ios-local-recovery'), 'runtime-unqualified');
  for (const availability of ['shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform'])
    assert.equal(iosArchiveModeAvailability(status(1, null, availability, ALL_TEST_MODES), 'ios-signed-export'), availability);
});

test('unsigned availability never offers signed Review or recovery Inspect; explicit modes remain separate', async (t) => {
  const h = harness(t, { initial: status(0, null, 'available', UNSIGNED_ONLY), savedSnapshot: signedSnapshot(), assets: assetState() });
  await h.ready;
  assert.equal(h.controller.prepareReason(), null);
  h.controller.setArchiveMode('signed'); assert.equal(h.state.signing.issue, null);
  assert.match(h.controller.prepareReason(), /disabled.*native qualification/);
  await h.controller.prepare(); assert.equal(h.calls.length, 0);
  h.controller.setVisible(false); h.controller.setRecoveryVisible(true);
  assert.match(h.controller.recoveryReason(), /disabled.*native qualification/);
  await h.controller.prepareRecovery(); assert.equal(h.calls.length, 0);
  h.emit(status(1, null, 'available', { unsigned: false, signed: false, recovery: true }));
  assert.equal(h.controller.recoveryReason(), null);
  h.controller.setRecoveryVisible(false); h.controller.setVisible(true);
  assert.ok(h.controller.prepareReason());
  h.emit(status(2, null, 'available', { unsigned: false, signed: true, recovery: false }));
  assert.equal(h.controller.prepareReason(), null);
  h.controller.setArchiveMode('unsigned'); assert.ok(h.controller.prepareReason());
  h.controller.setArchiveMode('signed');
  const preparing = h.controller.prepare(), call = h.calls.at(-1), op = operation(call.input);
  assert.equal(call.kind, 'prepare'); assert.equal(op.context.operation, 'ios-signed-export');
  h.reply(call, status(3, op, 'busy', { unsigned: false, signed: true, recovery: false })); await preparing;
  assert.ok(h.state.consent);
  h.controller.cancel(); h.reply(h.calls.at(-1), status(4, terminal(op), 'available', NO_MODES)); await flush();
});

test('mode loss blocks unstarted consent without rearming from stale or same-revision data', async (t) => {
  const h = harness(t, { savedSnapshot: signedSnapshot(), assets: assetState() }); await h.ready;
  h.controller.setArchiveMode('signed'); const op = await reviewed(h);
  h.controller.setAcknowledged(OP, OWNER, true);
  h.emit(status(2, op, 'busy', UNSIGNED_ONLY));
  assert.match(h.controller.startReason(), /disabled.*native qualification/);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0);
  h.emit(status(1, op, 'busy', ALL_TEST_MODES));
  assert.equal(h.state.status.statusRevision, 2); assert.equal(h.state.status.modeCapabilities.signed, false);
  assert.equal(h.state.integrityFailed, false); assert.ok(h.controller.canCancel());
  h.controller.cancel(); h.reply(h.calls.at(-1), status(3, terminal(op), 'available', NO_MODES)); await flush();
  const conflict = harness(t); await conflict.ready;
  conflict.emit(status(0, null, 'available', UNSIGNED_ONLY));
  assert.ok(conflict.state.integrityFailed); assert.equal(conflict.calls.length, 0);
});

test('mode loss never hides a running original Status or Cancel or invents its finality', async (t) => {
  const h = harness(t, { savedSnapshot: signedSnapshot(), assets: assetState() }); await h.ready;
  h.controller.setArchiveMode('signed'); const op = await reviewed(h), sent = start(h, op);
  const active = running(op, 'validating-signing');
  h.reply(sent.call, status(2, active, 'busy')); await sent.done;
  h.emit(status(3, active, 'busy', NO_MODES)); await h.controller.checkStatus();
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.nativeBlocked, false);
  assert.equal(h.state.status.operation.phase, 'running'); assert.equal(h.state.status.operation.outcome, null);
  assert.ok(h.controller.canCheckStatus()); assert.ok(h.controller.canCancel()); assert.ok(iosArchiveOwnerReason(h.state));
  h.controller.setVisible(false); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 0);
  assert.equal(h.controller.cancel(), true);
  assert.deepEqual(h.calls.at(-1).input, { operationId: OP, ownerGeneration: OWNER });
  h.reply(h.calls.at(-1), status(4, terminal(active), 'available', NO_MODES)); await flush();
  assert.equal(h.state.status.operation.outcome, 'cancelled'); assert.equal(iosArchiveOwnerReason(h.state), null);
});

test('four raw requests stay closed and domain-local; no tools, malformed signing or deadline may be supplied', () => {
  const input = request(), copied = copyIOSArchiveRequest('prepare_ios_archive', input);
  assert.deepEqual(clone(copied), input); assert.notEqual(copied.savedVersion, input.savedVersion);
  const decode = (raw) => JSON.parse(new TextDecoder().decode(raw));
  assert.deepEqual(decode(encodeIOSArchiveRequest('prepare_ios_archive', input)), input);
  for (const key of ['root', 'native', 'toolchain', 'argv', 'environment', 'timeout', 'signing', 'credentials', 'draft', 'artifactValidation'])
    assert.equal(encodeIOSArchiveRequest('prepare_ios_archive', { ...request(), [key]: 'not allowed' }), null, key);
  const begin = { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_ARCHIVE_CONSENT };
  assert.deepEqual(decode(encodeIOSArchiveRequest('start_ios_archive', begin)), begin);
  assert.equal(encodeIOSArchiveRequest('start_ios_archive', { ...begin, consentVersion: 'saved-android-build-inspect-v2' }), null);
  assert.equal(encodeIOSArchiveRequest('start_android_build', begin), null);
  assert.deepEqual(decode(encodeIOSArchiveRequest('cancel_ios_archive', { operationId: OP, ownerGeneration: OWNER })), { operationId: OP, ownerGeneration: OWNER });
  assert.deepEqual(decode(encodeIOSArchiveRequest('ios_archive_status', {})), {});
  for (const value of [-0, -1, true, 1.5, IOS_ARCHIVE_COUNTER_MAX + 1]) {
    assert.equal(encodeIOSArchiveRequest('prepare_ios_archive', { ...request(), draftRevision: value }), null);
    assert.equal(parseIOSArchiveStatus(status(value)), null);
  }
});

test('descriptors, serialization hooks, cycles and private error text never enter renderer state', () => {
  let effects = 0;
  const getter = { ...request(), get savedVersion() { effects++; return VERSION; } };
  const serialized = { ...request(), toJSON() { effects++; return request(); } };
  const cycle = request(); cycle.savedConfig = cycle;
  for (const value of [getter, serialized, cycle, Object.assign(Object.create({ inherited: true }), request())])
    assert.equal(copyIOSArchiveRequest('prepare_ios_archive', value), null);
  assert.equal(parseIOSArchiveStatus({ ...status(), get operation() { effects++; return completed(operation()); } }), null);
  assert.equal(effects, 0);
  assert.ok(!JSON.stringify(iosArchiveError({ code: 'ios_archive_protocol', message: 'PRIVATE FILE CONTENT' })).includes('PRIVATE'));
});

test('only native terminal finality publishes exact unsigned result and unused-prepare marker', () => {
  const complete = completed(operation()); assert.ok(parseIOSArchiveStatus(status(1, complete)));
  const mutate = [
    (op) => { op.phase = 'running'; op.outcome = null; }, (op) => { op.phase = 'unknown'; op.outcome = 'unknown'; op.reason = 'cleanup-unknown'; },
    (op) => { op.result.scope = 'signed-ipa'; }, (op) => { op.result.archive = '/inert/another.xcarchive'; },
    (op) => { op.result.usedVersion.sha256 = '0'.repeat(64); }, (op) => { op.disposition.snapshot = 'unknown'; },
    (op) => { op.activity.findings[1].status = 'FAIL'; }, (op) => { op.activity.findings = []; },
    (op) => { op.result.entries = 100001; }, (op) => { op.result.bytes = 8 * 1024 ** 3 + 1; },
    (op) => { op.result.limitations.pop(); }, (op) => { op.activity.commands.archive.exitCode = 1; },
  ];
  for (const update of mutate) { const op = clone(complete); update(op); assert.equal(parseIOSArchiveStatus(status(1, op)), null); }
  for (const [outcome, exitCode] of [['unknown', null], ['not-dispatched', null], ['exited', 0]]) {
    const op = clone(complete); op.activity.commands.prepare = { outcome, exitCode }; assert.equal(parseIOSArchiveStatus(status(1, op)), null);
  }
  assert.ok(parseIOSArchiveStatus(status(1, completed(operation(), selection({ preparationConfigured: true })))));
  const unknown = operation(request(), { phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' });
  assert.ok(parseIOSArchiveStatus(status(1, unknown, 'cleanup-unknown')));
  assert.equal(iosArchiveOperationProgress(unknown, complete), false);
  const foreign = operation(); foreign.context.platform = 'android'; assert.equal(parseIOSArchiveStatus(status(1, foreign)), null);
});

test('saved snapshot wins over dirty draft; complete saved-version observation binds exact review', async (t) => {
  const h = harness(t); await h.ready;
  h.dispatch({ type: 'edit', projectId: 'p1', path: 'ios.scheme', value: 'UnsavedScheme' });
  const draft = h.project.draft, baseline = h.project.baseline;
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
  h.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 2, observedAt: 2,
    snapshot: snapshot({ config: NEW_CONFIG, ios: { workspace: 'ios/Workspace.xcworkspace', scheme: 'SavedScheme', prepareCommand: ['/usr/bin/false'] } }) });
  await h.controller.prepare(); assert.equal(h.calls.length, 0);
  await h.readVersion(); const op = await reviewed(h);
  assert.ok(isDirty(h.project)); assert.equal(h.project.draft, draft); assert.equal(h.project.baseline, baseline);
  assert.equal(h.state.consent.binding.selection.scheme, 'SavedScheme'); assert.equal(h.state.consent.binding.selection.containerKind, 'workspace');
  assert.equal(h.state.consent.binding.selection.preparationConfigured, true);
  assert.deepEqual(Object.keys(h.calls[0].input).sort(), ['baselineGeneration', 'draftRevision', 'projectId', 'savedConfig', 'savedVersion']);
  assert.deepEqual(h.calls[0].input.savedConfig, NEW_CONFIG);
  assert.deepEqual(h.calls[0].input.savedVersion, { ...VERSION, source: 'release/version.properties', name: '1.2.3', build: 42 });
  assert.equal(op.context.platform, 'ios'); assert.equal(h.state.consent.acknowledged, false);
});

test('partial, stale or foreign saved-version responses never authorize prepare', async (t) => {
  const h = harness(t); await h.ready; const original = clone(h.versionState);
  const mutations = [
    (v) => { v.pending = clone(v.resultBinding); }, (v) => { v.stale = true; }, (v) => { v.error = { code: 'busy' }; },
    (v) => { v.result.schemaVersion = 1; }, (v) => { delete v.result.savedVersion; }, (v) => { delete v.result.assurance; },
    (v) => { v.result.assurance.toolsProbed = true; }, (v) => { v.result.observationScope = 'atomic'; },
    (v) => { v.result.savedConfig.sha256 = '0'.repeat(64); }, (v) => { v.result.source = 'release/other.properties'; },
    (v) => { v.resultBinding.observationGeneration++; }, (v) => { v.resultBinding.requestId++; },
    (v) => { v.resultBinding.connectionGeneration++; }, (v) => { v.resultBinding.selectionGeneration++; },
  ];
  for (const update of mutations) { const version = clone(original); update(version); h.overrideVersion(version); await h.controller.prepare(); assert.equal(h.calls.length, 0); }
  h.overrideVersion(undefined); await reviewed(h);
});

test('subscribe before Status; unchecked review sends exactly one Start and survives page navigation after start', async (t) => {
  const h = harness(t), op = await reviewed(h); assert.deepEqual(h.order.slice(0, 2), ['subscribe', 'status']);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.length, 1);
  const sent = start(h, op); await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
  h.controller.setVisible(false); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 0);
  h.reply(sent.call, status(2, running(op), 'busy')); await sent.done;
  assert.ok(iosArchiveOwnerReason(h.state)); assert.ok(h.controller.canCancel());
  h.emit(status(3, completed(op))); assert.equal(h.state.status.operation.outcome, 'complete');
  assert.equal(h.state.status.operation.result.archive, `.mobile-release/desktop-ios-archive/${OP}/archive.xcarchive`);
  assert.equal(iosArchiveOwnerReason(h.state), null);
});

test('a new version read retires consent synchronously; a late Prepare reply cannot rearm it', async (t) => {
  const h = harness(t); await h.ready;
  const preparing = h.controller.prepare(), call = h.calls.at(-1);
  const version = h.version.read(); assert.equal(h.state.consent, null);
  const op = operation(call.input); h.reply(call, status(1, op)); await preparing;
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.reply(h.calls.at(-1), status(2, terminal(op, 'cancelled', 'context-changed'))); await flush();
  h.versionCalls.at(-1).resolve(observation(h.project)); await version;
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 0);
});

test('expired review and selection churn retain original cancel rather than renewing consent', async (t) => {
  const h = harness(t), op = await reviewed(h);
  h.controller.setAcknowledged(OP, OWNER, true); h.clock(300010); await h.controller.checkStatus();
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 0);
  h.controller.selectionIntent(); h.controller.selectionIntent(); assert.equal(h.calls.filter((entry) => entry.kind === 'cancel').length, 1);
  h.reply(h.calls.at(-1), status(2, terminal(op))); await flush();
});

test('original failure, unknown or lost Start acknowledgement cannot become implicit retry permission', async (t) => {
  const h = harness(t), op = await reviewed(h), sent = start(h, op);
  sent.call.reject({ code: 'arbitrary', message: 'PRIVATE COMPILER OUTPUT' }); await sent.done;
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
  h.reply(h.calls.at(-1), status(2, operation(op.context, { context: op.context, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' }), 'cleanup-unknown'));
  await flush(); assert.ok(h.state.nativeBlocked); assert.ok(iosArchiveOwnerReason(h.state));
  h.controller.beginConnection(); await h.controller.connect({ ...h.api }); assert.equal(h.subscriptions.length, 1);
  h.emit(status(3, completed(op))); assert.ok(h.state.integrityFailed); assert.equal(h.state.status.operation.outcome, 'unknown');
  assert.ok(!JSON.stringify(h.state).includes('PRIVATE'));
});

test('a lost Prepare reply can settle only its observed original terminal, never acquire consent', async (t) => {
  for (const observeBeforeLoss of [false, true]) {
    const h = harness(t); await h.ready;
    const preparing = h.controller.prepare(), call = h.calls.at(-1), op = operation(call.input);
    if (observeBeforeLoss) h.emit(status(1, op, 'busy'));
    call.reject({ code: 'bridge-reply-lost' }); await preparing;
    assert.equal(h.state.consent, null);
    assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 0);
    h.emit(status(2, terminal(op, 'refused', 'intent-expired')));
    await h.controller.checkStatus();
    assert.equal(h.state.pending, null);
    assert.equal(h.state.originalUnconfirmed, false);
    assert.equal(h.state.consent, null);
    assert.equal(h.state.nativeBlocked, false);
    assert.equal(h.state.integrityFailed, false);
    assert.equal(iosArchiveOwnerReason(h.state), null);
    await h.controller.start(OP, OWNER);
    assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 0);
  }
});

test('same revision conflict and unsolicited different owner fail closed', async (t) => {
  const h = harness(t), op = await reviewed(h);
  h.emit(status(1, { ...op, intentUsable: false })); assert.ok(h.state.integrityFailed); assert.equal(h.state.consent, null);
  const other = harness(t); await other.ready;
  other.emit(status(1, operation(request(), { operationId: OTHER })));
  assert.ok(other.state.integrityFailed); assert.equal(other.calls.filter((entry) => entry.kind === 'start').length, 0);
});

test('reciprocal operation admission blocks prepare without a fake self-busy condition', async (t) => {
  const h = harness(t); await h.ready;
  h.other('Android original is running'); await h.controller.prepare(); assert.equal(h.calls.length, 0);
  h.other(null); const op = await reviewed(h);
  h.controller.setAcknowledged(OP, OWNER, true); assert.equal(h.controller.startReason(), null);
  h.other('Credential session is still active'); await h.controller.start(OP, OWNER);
  assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0);
  assert.ok(op.intentUsable);
});

test('signed public policy binds ordered unique current revisions without admitting private/native fields', () => {
  for (const optional of [[], ['ios-firebase'], ['project-read-token'], ['ios-firebase', 'project-read-token']]) {
    const input = { ...request(), signing: signingPolicy(optional) };
    assert.deepEqual(clone(copyIOSArchiveRequest('prepare_ios_archive', input)), input);
    assert.ok(parseIOSArchiveStatus(status(1, operation(input))));
    const changed = operation(input); changed.context.operation = 'ios-unsigned-archive';
    assert.equal(parseIOSArchiveStatus(status(1, changed)), null);
  }
  const base = signingPolicy(['ios-firebase', 'project-read-token']);
  for (const mutate of [
    (p) => { p.teamId = 'a1b2c3d4e5'; }, (p) => { p.distributionCertificateSha256 = 'E'.repeat(64); },
    (p) => { p.assignments.reverse(); }, (p) => { p.assignments.shift(); }, (p) => { p.assignments[1].kind = 'apple-p12'; },
    (p) => { p.assignments[1].recordId = p.assignments[0].recordId; }, (p) => { p.assignments[1].contextRevision++; },
    (p) => { p.assignments[0].recordRevision = 0; }, (p) => { p.assignments[0].contextRevision = 0; },
    (p) => { p.assignments[0].recordRevision = IOS_ARCHIVE_COUNTER_MAX + 1; },
    (p) => { p.assignments[0].file = 'PRIVATE_CANARY'; }, (p) => { p.password = 'PRIVATE_CANARY'; },
    (p) => { p.nativeValidation = 'verified'; }, (p) => { p.assignments = null; },
  ]) { const value = clone(base); mutate(value); assert.equal(parseIOSSigningPolicy(value), null); }
  for (const signing of [null, {}, 'PRIVATE_CANARY']) assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { ...request(), signing }), null);
  for (const field of ['signingTools', 'signingContext', 'material', 'password', 'privateKey', 'profile', 'native', 'recovery'])
    assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { ...request(), signing: base, [field]: null }), null, field);
  const begin = { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_SIGNED_ARCHIVE_CONSENT };
  assert.deepEqual(clone(copyIOSArchiveRequest('start_ios_archive', begin)), begin);
  assert.equal(copyIOSArchiveRequest('start_ios_archive', { ...begin, confirmation: IOS_ACCOUNT_RECOVERY_CONFIRMATION }), null);
});

test('signed IPA projection requires exact core findings, export, pairing and native terminal finality', () => {
  for (const optional of [[], ['ios-firebase']]) {
    const complete = signedCompleted(operation({ ...request(), signing: signingPolicy(optional) }));
    assert.ok(parseIOSArchiveStatus(status(1, complete)));
    for (const mutate of [
      (op) => { op.phase = 'running'; op.outcome = null; },
      (op) => { op.phase = 'unknown'; op.outcome = 'unknown'; op.reason = 'cleanup-unknown'; },
      (op) => { op.activity.commands.export.exitCode = 1; }, (op) => { delete op.activity.commands.export; },
      (op) => { op.activity.findings.pop(); }, (op) => { op.activity.findings[0].status = 'CONFIGURED'; },
      (op) => { op.activity.findings[1] = clone(op.activity.findings[0]); },
      (op) => { op.activity.selection.symbolsPolicy = 'required'; },
      (op) => { op.result.scope = IOS_ARCHIVE_SCOPE; }, (op) => { op.result.ipaBytes = 0; },
      (op) => { op.result.ipaBytes = 4 * 1024 ** 3 + 1; }, (op) => { op.result.pairing.nativeIdentities = 0; },
      (op) => { op.result.pairing.presentSymbolSlices = 100001; }, (op) => { op.result.pairing.rawPath = 'PRIVATE_CANARY'; },
      (op) => { op.result.limitations = [...IOS_ARCHIVE_LIMITATIONS]; }, (op) => { op.result.usedConfig.sha256 = '0'.repeat(64); },
      (op) => { op.result.ipa = op.result.ipa.replace(OP, OTHER); }, (op) => { op.result.ipa = op.result.ipa.replace('Inert.ipa', '../Inert.ipa'); },
      (op) => { op.result.ipa = op.result.ipa.replace('Inert.ipa', 'x:Inert.ipa'); },
      (op) => { op.result.ipa = op.result.ipa.replace('Inert.ipa', 'é'.repeat(126) + '.ipa'); },
      (op) => { op.disposition.work = 'unknown'; }, (op) => { op.lifetime = { complete: true }; },
    ]) { const changed = clone(complete); mutate(changed); assert.equal(parseIOSArchiveStatus(status(1, changed)), null); }
    const early = running(complete, 'materializing-signing'); early.activity = null; early.disposition = null; early.result = null; early.outcome = null;
    assert.ok(parseIOSArchiveStatus(status(1, early)));
    const unsigned = operation(); unsigned.stage = 'validating-signing'; unsigned.phase = 'running'; unsigned.intentUsable = false;
    assert.equal(parseIOSArchiveStatus(status(1, unsigned)), null);
  }
});

test('signed controller binds only saved public policy and exact idle assigned session metadata; unchanged rereads preserve review', async (t) => {
  const optional = ['ios-firebase', 'project-read-token'];
  const h = harness(t, { savedSnapshot: signedSnapshot({ distributionCertificateSha256: Array(32).fill('EE').join(':') }), assets: assetState(optional) });
  await h.ready; assert.equal(h.controller.setArchiveMode('signed'), true);
  const op = await reviewed(h), original = h.state.consent;
  assert.equal(op.context.operation, 'ios-signed-export'); assert.deepEqual(h.calls[0].input.signing, signingPolicy(optional));
  assert.doesNotMatch(JSON.stringify(h.calls[0].input), /password|privateKey|profileBytes|signingTools|root/);
  const reread = clone(h.assets); reread.observing = true; reread.status.statusRevision++;
  h.setAssets(reread); assert.equal(h.state.consent, original);
  h.controller.setAcknowledged(OP, OWNER, true); assert.equal(h.controller.startReason(), null);
  const sent = start(h, op); assert.deepEqual(sent.call.input, { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_SIGNED_ARCHIVE_CONSENT });
  assert.equal(h.controller.setArchiveMode('unsigned'), false);
  h.controller.setVisible(false); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 0);
  h.reply(sent.call, status(2, signedCompleted(op))); await sent.done;
  assert.equal(h.state.status.operation.result.scope, IOS_SIGNED_ARCHIVE_SCOPE); assert.equal(iosArchiveOwnerReason(h.state), null);
});

test('eligible encrypted read-write assignments use the same signed owner and private-free request as memory assignments', async (t) => {
  const optional = ['ios-firebase', 'project-read-token'];
  const assets = vaultAssetState(optional); assert.deepEqual(parseAssetStatus(assets.status), assets.status);
  const h = harness(t, { savedSnapshot: signedSnapshot(), assets }); await h.ready;
  assert.equal(h.controller.setArchiveMode('signed'), true); const op = await reviewed(h);
  assert.deepEqual(h.calls[0].input.signing, signingPolicy(optional));
  assert.doesNotMatch(JSON.stringify(h.calls[0].input), /password|privateKey|profileBytes|vaultKey|signingTools/);
  h.controller.setAcknowledged(OP, OWNER, true); assert.equal(h.controller.startReason(), null);
  const sent = start(h, op); assert.deepEqual(sent.call.input, { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_SIGNED_ARCHIVE_CONSENT });
  h.reply(sent.call, status(2, signedCompleted(op))); await sent.done;
  assert.equal(h.state.status.operation.result.scope, IOS_SIGNED_ARCHIVE_SCOPE);
});

test('encrypted Lock, read-only, eligibility loss and stale context retire late signed preparation without rearming Start', async (t) => {
  for (const mutate of [
    (a) => { a.status.persistence = { state: 'locked', reason: 'none', keyAccess: 'locked' }; a.status.context = null; a.status.records = []; a.status.assignments = []; },
    (a) => { a.status.persistence = { state: 'interrupted', reason: 'vault-interrupted', keyAccess: 'read-only' }; },
    (a) => { a.status.modes.encrypted = { available: false, reason: 'unqualified' }; },
    (a) => { a.contextCurrent = false; },
  ]) {
    const h = harness(t, { savedSnapshot: signedSnapshot(), assets: vaultAssetState() }); await h.ready; h.controller.setArchiveMode('signed');
    const preparing = h.controller.prepare(), call = h.calls.at(-1), before = h.state.contextGeneration;
    const changed = clone(h.assets); mutate(changed); h.setAssets(changed);
    assert.ok(h.state.contextGeneration > before); assert.equal(h.state.consent, null);
    const op = operation(call.input); h.reply(call, status(1, op)); await preparing;
    assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
    await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 0);
    h.reply(h.calls.at(-1), status(2, terminal(op, 'cancelled', 'context-changed'))); await flush();
  }
});

test('signed preparation refuses absent, stale, foreign, pending and partially available assignment sources', async (t) => {
  const h = harness(t, { savedSnapshot: signedSnapshot(), assets: assetState(['ios-firebase']) });
  await h.ready; h.controller.setArchiveMode('signed');
  for (const mutate of [
    (a) => { a.mode = 'preview'; }, (a) => { a.contextCurrent = false; }, (a) => { a.blocked = true; },
    (a) => { a.observationFailed = true; }, (a) => { a.originPending = true; }, (a) => { a.busy = 'bind'; },
    (a) => { a.updatingContext = true; }, (a) => { a.scope.purpose = 'full'; }, (a) => { a.scope.stage = 'production'; },
    (a) => { a.status.mode = 'closed'; }, (a) => { a.status.capability.available = false; },
    (a) => { a.status.context.projectId = 'p2'; }, (a) => { a.status.context.platform = 'android'; },
    (a) => { a.status.context.purpose = 'full'; }, (a) => { a.status.context.stage = 'production'; },
    (a) => { a.status.operation.phase = 'preview'; }, (a) => { a.status.operation.settlement = 'unknown'; },
    (a) => { a.status.assignments.shift(); }, (a) => { a.status.assignments[0].contextRevision++; },
    (a) => { a.status.assignments[0].recordRevision++; }, (a) => { a.status.assignments[0].availability = 'unavailable'; },
    (a) => { a.status.records[0].availability = 'mutation-pending'; },
    (a) => { a.status.assignments[2].availability = 'unavailable'; },
  ]) {
    const value = assetState(['ios-firebase']); mutate(value); h.setAssets(value);
    assert.ok(h.state.signing.issue); await h.controller.prepare(); assert.equal(h.calls.length, 0);
  }
  h.setAssets(null); await h.controller.prepare(); assert.equal(h.calls.length, 0);
  h.setAssets(assetState()); assert.equal(h.state.signing.issue, null); await reviewed(h);
});

test('signed dirty drafts never become signing context while original unsigned saved-input behavior is retained', async (t) => {
  const h = harness(t, { savedSnapshot: signedSnapshot(), assets: assetState() });
  await h.ready; h.controller.setArchiveMode('signed');
  h.dispatch({ type: 'edit', projectId: 'p1', path: 'ios.teamId', value: 'Z9Y8X7W6V5' }); await h.readVersion();
  await h.controller.prepare(); assert.equal(h.calls.length, 0); assert.match(h.state.signing.issue, /unsaved draft/);
  h.controller.setArchiveMode('unsigned'); const op = await reviewed(h);
  assert.equal(op.context.operation, 'ios-unsigned-archive'); assert.equal(Object.hasOwn(h.calls[0].input, 'signing'), false);
  assert.equal(h.project.draft.ios.teamId, 'Z9Y8X7W6V5');
});

test('assignment, context, session mutation and mode changes synchronously retire late signed Prepare without rearming Start', async (t) => {
  for (const change of [
    (h) => { const a = clone(h.assets); a.status.assignments[0].recordRevision++; h.setAssets(a); },
    (h) => { const a = clone(h.assets); a.contextCurrent = false; h.setAssets(a); },
    (h) => { const a = clone(h.assets); a.busy = 'choose-file'; h.setAssets(a); },
    (h) => { const a = clone(h.assets); a.originPending = true; h.setAssets(a); },
    (h) => { h.controller.setArchiveMode('unsigned'); },
  ]) {
    const h = harness(t, { savedSnapshot: signedSnapshot(), assets: assetState() }); await h.ready; h.controller.setArchiveMode('signed');
    const preparing = h.controller.prepare(), call = h.calls.at(-1), before = h.state.contextGeneration;
    change(h); assert.ok(h.state.contextGeneration > before); assert.equal(h.state.consent, null);
    const op = operation(call.input); h.reply(call, status(1, op)); await preparing;
    assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
    await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 0);
    h.reply(h.calls.at(-1), status(2, terminal(op, 'cancelled', 'context-changed'))); await flush();
  }
});

test('recovery requests are a disjoint closed union with exact actions and fixed Start confirmations', () => {
  for (const action of ['inspect', 'account', 'project']) {
    const input = recoveryRequest(action); assert.deepEqual(clone(copyIOSArchiveRequest('prepare_ios_archive', input)), input);
    assert.ok(parseIOSArchiveStatus(status(1, operation(input))));
    for (const key of ['draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'signing', 'native', 'manual', 'security', 'root'])
      assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { ...input, [key]: null }), null, key);
  }
  for (const recovery of [{ action: 'inspect', session: ACCOUNT_SESSION }, { action: 'inspect', session: null }, { action: 'account' },
    { action: 'project', session: 'not-a-token' }, { action: 'manual', session: ACCOUNT_SESSION }, { action: 'account', session: ACCOUNT_SESSION, manual: false }])
    assert.equal(copyIOSArchiveRequest('prepare_ios_archive', { projectId: 'p1', recovery }), null);
  const begin = { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_RECOVERY_CONSENT };
  for (const confirmation of [undefined, IOS_ACCOUNT_RECOVERY_CONFIRMATION, IOS_PROJECT_RECOVERY_CONFIRMATION]) {
    const input = { ...begin, ...(confirmation === undefined ? {} : { confirmation }) };
    assert.deepEqual(clone(copyIOSArchiveRequest('start_ios_archive', input)), input);
  }
  for (const confirmation of [null, true, 'yes', 'manual', ACCOUNT_SESSION]) assert.equal(copyIOSArchiveRequest('start_ios_archive', { ...begin, confirmation }), null);
});

test('recovery reports are terminal observations with exact sessions and never expose archive or material data', () => {
  for (const action of ['inspect', 'account', 'project']) {
    const complete = recoveryCompleted(operation(recoveryRequest(action))); assert.ok(parseIOSArchiveStatus(status(1, complete)));
    for (const mutate of [
      (op) => { op.phase = 'running'; op.outcome = null; },
      (op) => { op.phase = 'unknown'; op.outcome = 'unknown'; op.reason = 'cleanup-unknown'; },
      (op) => { op.report.limitations.reverse(); }, (op) => { op.report.scope = IOS_SIGNED_ARCHIVE_SCOPE; },
      (op) => { op.activity.commands = {}; }, (op) => { op.activity.selection = null; },
      (op) => { op.disposition = null; }, (op) => { op.result = null; }, (op) => { op.context.savedVersion = null; },
      (op) => { op.report = null; }, (op) => { op.stage = 'archiving'; },
      (op) => { op.report[action === 'project' ? 'project' : 'account'].session = null; },
      (op) => { op.report[action === 'project' ? 'project' : 'account'].next = 'force'; },
    ]) { const changed = clone(complete); mutate(changed); assert.equal(parseIOSArchiveStatus(status(1, changed)), null); }
    if (action !== 'inspect') {
      const foreign = clone(complete); foreign.report[action].session = OTHER; assert.equal(parseIOSArchiveStatus(status(1, foreign)), null);
      const extra = clone(complete); extra.report[action === 'project' ? 'account' : 'project'] = { status: 'idle', session: null, next: 'none' };
      assert.equal(parseIOSArchiveStatus(status(1, extra)), null);
    }
  }
  const inspect = recoveryCompleted(operation(recoveryRequest()));
  for (const row of [
    { status: 'idle', session: null, next: 'none' }, { status: 'busy', session: null, next: 'wait' },
    { status: 'conflict', session: ACCOUNT_SESSION, next: 'preserve' }, { status: 'manual-required', session: ACCOUNT_SESSION, next: 'manual' },
    { status: 'pending', session: ACCOUNT_SESSION, next: 'manual' },
  ]) { const value = clone(inspect); value.report.account = row; assert.ok(parseIOSArchiveStatus(status(1, value))); }
  for (const row of [{ status: 'recovered', session: ACCOUNT_SESSION, next: 'none' }, { status: 'cleanup-only', session: ACCOUNT_SESSION, next: 'ordinary' },
    { status: 'idle', session: ACCOUNT_SESSION, next: 'none' }, { status: 'busy', session: null, next: 'ordinary' }]) {
    const value = clone(inspect); value.report.account = row; assert.equal(parseIOSArchiveStatus(status(1, value)), null);
  }
  const halted = clone(inspect); halted.outcome = 'failed'; halted.reason = 'recovery-attention';
  halted.report.account = { status: 'busy', session: null, next: 'wait' }; halted.report.project = { status: 'not-inspected', session: null, next: 'preserve' };
  assert.ok(parseIOSArchiveStatus(status(1, halted)));
});

test('recovery can inspect without saved configuration/version/draft and separately confirms only its own finalized exact session', async (t) => {
  for (const action of ['account', 'project']) {
    const h = harness(t, { savedSnapshot: null, completeVersion: false });
    const report = await inspectedRecovery(h); assert.equal(h.versionCalls.length, 0);
    assert.deepEqual(h.calls[0].input, recoveryRequest());
    assert.deepEqual(h.calls[1].input, { operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_RECOVERY_CONSENT });
    assert.equal(h.state.project.savedConfig, null); assert.equal(h.state.project.savedVersion, null);
    assert.equal(h.controller.recoveryReason(action, report), null);
    const changed = clone(report); changed.report[action].session = OTHER;
    await h.controller.prepareRecovery(action, changed); assert.equal(h.calls.length, 2);
    const op = await reviewedRecovery(h, action, report, { operationId: OTHER });
    assert.deepEqual(h.calls[2].input, recoveryRequest(action));
    await h.controller.start(OTHER, OWNER); assert.equal(h.calls.length, 3);
    const sent = start(h, op); await h.controller.start(OTHER, OWNER);
    assert.equal(h.calls.filter((call) => call.kind === 'start').length, 2);
    assert.deepEqual(sent.call.input, { operationId: OTHER, ownerGeneration: OWNER, consentVersion: IOS_RECOVERY_CONSENT,
      confirmation: action === 'account' ? IOS_ACCOUNT_RECOVERY_CONFIRMATION : IOS_PROJECT_RECOVERY_CONFIRMATION });
    h.controller.setRecoveryVisible(false); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 0);
    h.reply(sent.call, status(4, recoveryCompleted(op))); await sent.done;
    assert.equal(h.state.status.operation.report[action].status, 'recovered'); assert.equal(iosArchiveOwnerReason(h.state), null);
  }
});

test('recovery retains stopped and non-grant inspection reports without offering their ordinary actions', async (t) => {
  for (const [outcome, reason, eligible] of [
    ['timed-out', 'timed-out', false], ['failed', 'command-incomplete', false],
    ['refused', 'runtime-unavailable', false], ['cancelled', 'cancelled', false],
    ['complete', 'none', true], ['failed', 'recovery-attention', true], ['refused', 'recovery-attention', true],
  ]) {
    const h = harness(t, { savedSnapshot: null, completeVersion: false });
    const report = await inspectedRecovery(h, { outcome, reason });
    assert.equal(h.state.historical, false); assert.equal(h.state.integrityFailed, false);
    assert.deepEqual(clone(h.state.status.operation), report); assert.equal(h.controller.recoveryReason(), null);
    for (const action of ['account', 'project']) {
      if (eligible) assert.equal(h.controller.recoveryReason(action, report), null);
      else {
        assert.match(h.controller.recoveryReason(action, report), /did not grant ordinary recovery/);
        await h.controller.prepareRecovery(action, report); assert.equal(h.calls.length, 2);
        assert.deepEqual(clone(h.state.status.operation.report), report.report);
      }
    }
  }
});

test('recovery refuses old, foreign, busy, conflicting or manual reports instead of adopting their displayed sessions', async (t) => {
  const foreign = recoveryCompleted(operation(recoveryRequest()));
  const observed = harness(t, { initial: status(2, foreign), savedSnapshot: null, completeVersion: false });
  await observed.ready; observed.controller.setRecoveryVisible(true);
  await observed.controller.prepareRecovery('account', foreign); assert.equal(observed.calls.length, 0);
  for (const row of [{ status: 'busy', session: null, next: 'wait' }, { status: 'conflict', session: ACCOUNT_SESSION, next: 'preserve' },
    { status: 'manual-required', session: ACCOUNT_SESSION, next: 'manual' }, { status: 'pending', session: ACCOUNT_SESSION, next: 'manual' }]) {
    const h = harness(t, { savedSnapshot: null, completeVersion: false });
    const report = await inspectedRecovery(h, { report: { ...foreign.report, account: row } });
    await h.controller.prepareRecovery('account', report); assert.equal(h.calls.length, 2); assert.ok(h.controller.recoveryReason('account', report));
  }
  const stale = harness(t, { savedSnapshot: null, completeVersion: false }), report = await inspectedRecovery(stale);
  stale.controller.selectionIntent(); await stale.controller.prepareRecovery('project', report); assert.equal(stale.calls.length, 2);
});

test('recovery lost Start and Unknown keep original ownership while hidden or expired unused reviews retire once', async (t) => {
  const h = harness(t, { savedSnapshot: null, completeVersion: false }), op = await reviewedRecovery(h), sent = start(h, op);
  sent.call.reject({ code: 'lost', message: 'PRIVATE_CANARY' }); await sent.done;
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.reply(h.calls.at(-1), status(2, terminal(op, 'unknown', 'cleanup-unknown'), 'cleanup-unknown')); await flush();
  await h.controller.prepareRecovery(); await h.controller.start(OP, OWNER);
  h.controller.beginConnection(); await h.controller.connect({ ...h.api });
  assert.equal(h.calls.filter((call) => call.kind === 'prepare').length, 1); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
  assert.equal(h.subscriptions.length, 1); assert.equal(h.state.nativeBlocked, true); assert.doesNotMatch(JSON.stringify(h.state), /PRIVATE_CANARY/);
  for (const retire of [(h) => h.controller.setRecoveryVisible(false), (h) => h.clock(300010)]) {
    const next = harness(t, { savedSnapshot: null, completeVersion: false }), review = await reviewedRecovery(next);
    retire(next); await next.controller.checkStatus(); await next.controller.start(OP, OWNER);
    assert.equal(next.state.consent, null); assert.equal(next.calls.filter((call) => call.kind === 'cancel').length, 1);
    assert.equal(next.calls.filter((call) => call.kind === 'start').length, 0);
    next.reply(next.calls.at(-1), status(2, terminal(review))); await flush();
  }
});

test('native bridge sends only Raw requests; preview never provides fabricated execution', async () => {
  const calls = [], listeners = [];
  const api = createNativeApi('native', async (command, body) => { calls.push({ command, body }); return status(); },
    async (event, callback) => { listeners.push({ event, callback }); return () => {}; });
  await api.prepareIOSArchive(request()); await api.startIOSArchive({ operationId: OP, ownerGeneration: OWNER, consentVersion: IOS_ARCHIVE_CONSENT });
  await api.iosArchiveStatus(); await api.cancelIOSArchive(OP, OWNER);
  assert.deepEqual(calls.map((call) => call.command), ['prepare_ios_archive', 'start_ios_archive', 'ios_archive_status', 'cancel_ios_archive']);
  assert.ok(calls.every((call) => call.body instanceof Uint8Array));
  let observed; await api.subscribeIOSArchive((value) => { observed = value; }); assert.equal(listeners[0].event, IOS_ARCHIVE_EVENT);
  listeners[0].callback({ protocol: 'mrk-ios-archive/1', kind: 'terminal' }); assert.equal(observed, null);
  for (const name of ['prepareIOSArchive', 'startIOSArchive', 'iosArchiveStatus', 'cancelIOSArchive', 'subscribeIOSArchive'])
    await assert.rejects(previewApi[name](), (error) => error.code === 'ios_archive_unavailable');
});

test('actual app shares status/cancel and retirement; each important archive choice has practical guidance', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  for (const literal of ['iosArchiveControllerRef.current?.beforeWorkspaceAction(action)', 'iosArchiveControllerRef.current?.syncProject()',
    'iosArchive.beginConnection()', 'iosArchive.connect(connection)', 'iosArchive.syncReleaseVersion()', 'iosArchive.selectionIntent()',
    'iosArchive.setSelectionPending(true)', 'iosArchive.setSelectionPending(false)', '<IOSArchiveResultView', '<IOSArchive state={iosArchiveState}',
    'assetSession: assetSession.getSnapshot', 'assetSession.subscribe(() => iosArchive.syncAssetSession())', 'iosArchive.setRecoveryVisible', '<IOSRecovery state={iosArchiveState}'])
    assert.ok(app.includes(literal), literal);
  assert.match(app, /preflightBusy\(\) \?\? androidBusy\(\) \?\? iosBusy\(\)/);
  const component = readFileSync(new URL('../src/components/IOSArchive.tsx', import.meta.url), 'utf8');
  for (const action of ['observe-version', 'review', 'acknowledge', 'start', 'cancel'])
    assert.ok(component.includes(`data-mrk-ios-archive-action="${action}"`));
  for (const help of [iosArchiveHelp, iosArchiveInputHelp, iosArchiveSelectionHelp, iosArchiveOutputHelp, iosArchiveCancelHelp, iosSigningHelp, iosRecoveryHelp])
    for (const field of ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure']) assert.ok(help[field]?.length, `${help.label}: ${field}`);
  assert.ok(component.includes('controller.prepareRecovery(')); assert.ok(component.includes('controller.setArchiveMode('));
  assert.ok(component.includes("iosArchiveModeAvailability(state.status, signed ? 'ios-signed-export' : 'ios-unsigned-archive')"));
  assert.ok(component.includes("iosArchiveModeAvailability(state.status, 'ios-local-recovery')"));
  assert.match(iosSigningHelp.format, /ios.teamId.*ios.distributionCertificateSha256.*password write-only/);
  assert.match(iosRecoveryHelp.failure, /live Unknown stays owned.*manual recheck is not supported/);
});
