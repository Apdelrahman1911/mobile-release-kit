// Inert controlled-promise/controller/bridge and source-contract tests only.
// Authored, not executed during staging. All saved bytes, digests, native states
// and command observations are invented DATA, not process/tool/file custody or
// qualification. Real ReleaseVersionController is used with a fake passive API.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { AndroidBuildController, androidBuildOwnerReason, androidBuildHelp, androidBuildInputHelp, androidBuildOutputHelp, androidBuildCancelHelp, androidBuildSignatureHelp } from '../src/androidBuild.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { ANDROID_BUILD_CONSENT, ANDROID_BUILD_SIGNED_CONSENT, ANDROID_BUILD_CORE_STATUSES, ANDROID_BUILD_EVENT, ANDROID_BUILD_LIMITATIONS,
  ANDROID_BUILD_SCOPE, ANDROID_BUILD_TOOLCHAIN_PROFILE } from '../src/androidBuildProtocol.ts';
import { ANDROID_TOOL_SERVICE_CONSENT, ANDROID_TOOL_REGISTRATION_CONSENT, parseAndroidToolRegistrationStatus } from '../src/androidToolRegistration.ts';
import { parseAndroidToolchainCatalogStatus } from '../src/androidToolchainCatalogProtocol.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), OTHER = 'c'.repeat(32);
const CONFIG = { bytes: 512, sha256: 'd'.repeat(64) }, NEW_CONFIG = { bytes: 524, sha256: 'e'.repeat(64) };
const VERSION = { bytes: 41, sha256: 'f'.repeat(64) };
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 16; n++) await Promise.resolve(); };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const info = { runtime: { state: 'available', mode: 'development', reason: null },
  capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } };
function snapshot({ config = CONFIG, module = ':app', applicationId = 'org.example.app', source = 'release/version.properties', variant = 'release', uploadCertificateSha256 } = {}) {
  return { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(config), issues: [],
      data: { android: { enabled: true, module, applicationId, variant, ...(uploadCertificateSha256 === undefined ? {} : { uploadCertificateSha256 }) }, version: { source, nameKey: 'NAME', buildKey: 'BUILD' } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(assurance), issues: [] };
}
function workspace() {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert Android project', path: '/inert/never-forwarded' } });
  value = workspaceReducer(value, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  return workspaceReducer(value, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot: snapshot(), observedAt: 1 });
}
function observation(project, patch = {}) {
  return { schemaVersion: 2, source: project.snapshot.config.data.version.source, version: { name: '1.2.3', build: 42 },
    savedConfig: clone(project.savedConfigContent), savedVersion: clone(VERSION), observationScope: 'single-request-non-atomic', assurance: clone(assurance), ...patch };
}
const context = (request) => ({ ...clone(request), platform: 'android', operation: request.signing ? 'android-build-sign' : 'android-build-inspect' });
const operation = (input, patch = {}) => ({ operationId: OP, ownerGeneration: OWNER, context: context(input), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null, ...patch });
const status = (revision = 0, op = null, availability = 'available') => ({ schemaVersion: 1, statusRevision: revision, availability, operation: op });
const running = (op, stage = 'building') => ({ ...clone(op), phase: 'running', intentUsable: false, stage });
const terminal = (op, outcome = 'cancelled', reason = outcome) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome, reason });
function completed(op, selection = { module: ':app', variant: 'release', applicationId: 'org.example.app', task: ':app:bundleRelease' }) {
  const findings = [{ ordinal: 0, check: 'aab-structure', status: 'FAIL' }];
  const summary = { total: 1, shown: 1, omitted: 0, counts: Object.fromEntries(ANDROID_BUILD_CORE_STATUSES.map((key) => [key, key === 'FAIL' ? 1 : 0])) };
  const command = { outcome: 'exited', exitCode: 0 };
  const result = { schemaVersion: 1, scope: ANDROID_BUILD_SCOPE, usedConfig: clone(op.context.savedConfig), usedVersion: clone(op.context.savedVersion), artifactValidation: clone(op.context.artifactValidation),
    selection: clone(selection), toolchainProfile: ANDROID_BUILD_TOOLCHAIN_PROFILE, command: clone(command), findings: clone(findings), summary: clone(summary),
    artifacts: [{ logicalName: 'android-aab', platform: 'android', kind: 'aab', fileName: 'app-release.aab', size: 1024, sha256: '0'.repeat(64),
      architectures: ['arm64-v8a'], unknownAbi: false, freshness: 'not-established' }],
    assurances: { structure: 'failed', nativeManifest: 'not-checked', applicationVersion: 'not-established',
      signature: op.context.artifactValidation.mode === 'upload-signature' ? 'not-checked' : 'not-inspected',
      signer: op.context.artifactValidation.mode === 'upload-signature' ? 'not-checked' : 'not-inspected',
      toolkitSigning: 'not-requested', storeOperation: 'not-requested', sourceBinding: 'not-established', releaseReadiness: 'not-assessed' }, limitations: ANDROID_BUILD_LIMITATIONS.map((item) => item === 'artifact-signer-not-inspected' && op.context.artifactValidation.mode === 'upload-signature' ? 'upload-signature-check-not-store-enrollment' : item) };
  return { ...terminal(op, 'complete', 'none'), stage: 'disposing-work', activity: { stage: 'disposing-work', selection, command, findings, summary },
    disposition: { work: 'removed', artifacts: 'retained-local-result' }, result };
}
const TOOL_A = { instance: '1'.repeat(32), ownerUid: 501, catalogGeneration: 1,
  recordSha256: '2'.repeat(64), inventorySha256: '3'.repeat(64), osProviderSha256: '4'.repeat(64) };
const TOOL_B = { ...TOOL_A, instance: '5'.repeat(32), recordSha256: '6'.repeat(64) };
function signingAssets() {
  const scope = { platform: 'android', stage: 'candidate', purpose: 'signing' };
  return { mode: 'native', scope, contextCurrent: true, busy: null, updatingContext: false, observing: false, observationFailed: false,
    blocked: false, error: null, previewDeadline: null, entryGeneration: 1, selectionKind: null, cancelledOperationId: null,
    originPending: false, intent: null, reviewReady: false, status: { schemaVersion: 3, statusRevision: 1, mode: 'session', persistence: null,
      capability: { available: true, reason: 'none' }, modes: { session: { available: true, reason: 'none' }, encrypted: { available: false, reason: 'unsupported-platform' } },
      context: { ...scope, projectId: 'p1', revision: 2 }, operation: null,
      records: [{ recordId: OTHER, revision: 1, kind: 'android-keystore', availability: 'assigned', storage: 'session', label: null, payloadState: 'assessed' }],
      assignments: [{ kind: 'android-keystore', recordId: OTHER, recordRevision: 1, contextRevision: 2, availability: 'available' }] } };
}
async function savedSigningPolicy(h) {
  await h.ready;
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
  h.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 2,
    snapshot: snapshot({ uploadCertificateSha256: 'Ab'.repeat(32) }), observedAt: 2 });
  await h.readVersion();
}
const toolEntry = (selection, verified) => ({ instance: selection.instance, occupants: 1,
  status: verified ? 'verified-this-session' : 'recovery-required',
  versions: { jdkVendor: 'Example', jdkVersion: '17.0.12', gradleVersion: '8.10', agpVersion: '8.7',
    sdkPlatform: 'android-35', sdkBuildToolsVersion: '35.0.0' },
  recovery: verified ? null : { catalogGeneration: selection.catalogGeneration, instance: selection.instance,
    recordSha256: selection.recordSha256, inventorySha256: selection.inventorySha256, osProviderSha256: selection.osProviderSha256 },
  selection: verified ? clone(selection) : null });
const catalogStatus = (patch = {}) => ({ schemaVersion: 1, statusRevision: 0, catalogGeneration: 0, operationId: null,
  availability: 'unsupported-platform', phase: 'idle', reason: 'not-inspected', entries: [], selected: null, ...patch });
function readyCatalog(patch = {}) {
  // One current session proof, never two verified copies. Other metadata
  // remains recovery-required DATA and cannot itself authorize Choose.
  const verified = patch.selected ?? TOOL_A;
  const value = catalogStatus({ statusRevision: 1, catalogGeneration: 1, operationId: '7'.repeat(32),
    availability: 'available', phase: 'ready', reason: 'none',
    entries: [toolEntry(TOOL_A, verified.instance === TOOL_A.instance), toolEntry(TOOL_B, verified.instance === TOOL_B.instance)], ...patch });
  assert.ok(parseAndroidToolchainCatalogStatus(value), 'Synthetic catalog must satisfy the current closed row/session contract');
  return value;
}
function harness(t, { initial = status(), initialCatalog = catalogStatus(), initialService = null, initialRegistration = null, initialAssets = null, sourceSelections = [], listenGate = null, completeVersion = true } = {}) {
  let state = workspace(), registry = clone(initial), catalogRegistry = clone(initialCatalog), clock = 10, other = null, versionOverride;
  const calls = [], reads = [], subscriptions = [], versionCalls = [], order = [], catalogCalls = [], catalogSubscriptions = [];
  const serviceCalls = [], serviceSubscriptions = [], registrationCalls = [], registrationSubscriptions = [];
  let serviceRegistry = clone(initialService), registrationRegistry = clone(initialRegistration);
  let assets = clone(initialAssets);
  const selected = () => state.selectedId ? state.projects[state.selectedId] : null;
  const version = new ReleaseVersionController(selected);
  version.setConnection({ mode: 'native', observeReleaseVersion: (projectId) => {
    const call = { projectId, ...deferred() }; versionCalls.push(call); return call.promise;
  } }, info); version.syncProject();
  const api = { mode: 'native',
    subscribeAndroidToolchainCatalog: async (callback) => {
      const row = { callback, closed: false }; catalogSubscriptions.push(row);
      return () => { row.closed = true; };
    },
    androidToolchainCatalogStatus: async () => clone(catalogRegistry),
    refreshAndroidToolchainCatalog: () => { const call = { kind: 'catalog-refresh', ...deferred() }; catalogCalls.push(call); return call.promise; },
    selectAndroidToolchain: (input) => { const call = { kind: 'catalog-select', input: clone(input), ...deferred() }; catalogCalls.push(call); return call.promise; },
    cancelAndroidToolchainCatalog: (input) => { const call = { kind: 'catalog-cancel', input: clone(input), ...deferred() }; catalogCalls.push(call); return call.promise; },
    subscribeAndroidBuild: async (callback) => {
      order.push('subscribe'); const row = { callback, closed: false }; subscriptions.push(row);
      if (listenGate) await listenGate.promise;
      return () => { row.closed = true; };
    },
    androidBuildStatus: async () => { order.push('status'); reads.push(clone(registry)); return clone(registry); },
    prepareAndroidBuild: (input) => { const call = { kind: 'prepare', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    startAndroidBuild: (input) => { const call = { kind: 'start', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelAndroidBuild: (operationId, ownerGeneration) => { const call = { kind: 'cancel', input: { operationId, ownerGeneration }, ...deferred() }; calls.push(call); return call.promise; },
  };
  const serviceRequest = (kind, input) => { const call = { kind, input: clone(input), ...deferred() }; serviceCalls.push(call); return call.promise; };
  if (initialService !== null || initialRegistration !== null) {
    Object.assign(api, {
      androidToolSourcesStatus: async () => ({ schemaVersion: 1, statusRevision: sourceSelections.length ? 1 : 0,
        sourceGeneration: sourceSelections.length ? 1 : 0, projectId: sourceSelections.length ? 'p1' : null,
        availability: 'available', phase: sourceSelections.length ? 'selected' : 'idle', reason: 'not-inspected',
        operation: sourceSelections.length ? { operationId: 1, sourceGeneration: 1, role: sourceSelections.at(-1).role } : null,
        selections: clone(sourceSelections), inspection: 'not-run', protectedCopy: 'not-created' }),
      chooseAndroidToolSource: (input) => serviceRequest('unexpected-picker', input),
      cancelAndroidToolSource: (input) => serviceRequest('unexpected-picker-cancel', input),
      subscribeAndroidToolSources: async () => () => {},
    });
  }
  if (initialService !== null) {
    Object.assign(api, {
      androidToolServiceStatus: async () => clone(serviceRegistry),
      checkAndroidToolService: (input) => serviceRequest('check', input),
      requestAndroidToolServiceRegistration: (input) => serviceRequest('request-registration', input),
      openAndroidToolServiceApprovalSettings: (input) => serviceRequest('open-approval-settings', input),
      cancelAndroidToolService: (input) => serviceRequest('cancel', input),
      subscribeAndroidToolService: async (callback) => {
        const row = { callback, closed: false }; serviceSubscriptions.push(row); return () => { row.closed = true; };
      },
    });
  }
  if (initialRegistration !== null) {
    const registrationRequest = (kind, input) => { const call = { kind, input: clone(input), ...deferred() }; registrationCalls.push(call); return call.promise; };
    Object.assign(api, {
      androidToolRegistrationStatus: async () => clone(registrationRegistry),
      inspectAndroidToolSources: (input) => registrationRequest('inspect', input),
      registerAndroidToolSources: (input) => registrationRequest('register', input),
      cancelAndroidToolRegistration: (input) => registrationRequest('cancel', input),
      subscribeAndroidToolRegistration: async (callback) => {
        const row = { callback, closed: false }; registrationSubscriptions.push(row); return () => { row.closed = true; };
      },
    });
  }
  const controller = new AndroidBuildController({ selectedProject: selected,
    releaseVersion: () => versionOverride === undefined ? version.getSnapshot() : versionOverride,
    assetSession: () => assets,
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
  return { api, controller, version, calls, reads, subscriptions, versionCalls, order, ready, readVersion, catalogCalls, catalogSubscriptions,
    serviceCalls, serviceSubscriptions, registrationCalls, registrationSubscriptions,
    replyRegistration(call, value) {
      assert.ok(parseAndroidToolRegistrationStatus(value), 'Synthetic registration must satisfy the closed status contract');
      registrationRegistry = clone(value); call.resolve(clone(value));
    },
    setAssets(value) { assets = clone(value); controller.syncAssetSession(); },
    emitService(value) { serviceRegistry = clone(value); serviceSubscriptions.at(-1)?.callback(clone(value)); },
    replyService(call, value) { serviceRegistry = clone(value); call.resolve(clone(value)); },
    emitCatalog(value) { catalogRegistry = clone(value); catalogSubscriptions.at(-1)?.callback(clone(value)); },
    replyCatalog(call, value) { catalogRegistry = clone(value); call.resolve(clone(value)); },
    get state() { return controller.getSnapshot(); }, get workspace() { return state; }, get project() { return selected(); },
    get versionState() { return version.getSnapshot(); },
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
  const preparing = h.controller.prepare(), call = h.calls.at(-1);
  assert.equal(call?.kind, 'prepare', h.controller.prepareReason() ?? 'Expected the original Prepare invocation');
  const op = operation(call.input, patch); h.reply(call, status((h.state.status?.statusRevision ?? 0) + 1, op)); await preparing;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
function start(h, op) {
  h.controller.setAcknowledged(op.operationId, op.ownerGeneration, true);
  const done = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1); assert.equal(call.kind, 'start'); return { call, done };
}

test('current completed snapshot wins over dirty draft and retained old baseline; both observations bind the one request', async (t) => {
  const h = harness(t); await h.ready;
  h.dispatch({ type: 'edit', projectId: 'p1', path: 'android.module', value: ':unsaved' });
  const draft = h.project.draft, baseline = h.project.baseline;
  const current = snapshot({ config: NEW_CONFIG, module: ':current', applicationId: 'org.current.app', source: 'release/current-version.env', variant: 'production' });
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
  h.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 2, snapshot: current, observedAt: 2 });
  assert.equal(h.project.baseline, baseline); assert.equal(h.project.draft, draft); assert.ok(isDirty(h.project));
  await h.controller.prepare(); assert.equal(h.calls.length, 0); // Old v2 cannot accompany the new snapshot.
  await h.readVersion(observation(h.project, { version: { name: '4.5.6-rc+7', build: 84 } }));
  const op = await reviewed(h), consent = h.state.consent;
  assert.deepEqual(h.calls[0].input.savedConfig, NEW_CONFIG);
  assert.deepEqual(h.calls[0].input.savedVersion, { ...VERSION, source: 'release/current-version.env', name: '4.5.6-rc+7', build: 84 });
  assert.deepEqual(Object.keys(h.calls[0].input).sort(), ['artifactValidation', 'baselineGeneration', 'draftRevision', 'projectId', 'savedConfig', 'savedVersion']);
  assert.deepEqual(consent.binding.selection, { module: ':current', variant: 'production', applicationId: 'org.current.app' });
  assert.equal(consent.binding.observationGeneration, h.project.observationGeneration);
  assert.equal(consent.binding.versionObservation.readEpoch, h.versionState.readEpoch);
  assert.equal(consent.binding.versionObservation.observationGeneration, h.project.observationGeneration);
  const sent = start(h, op); h.reply(sent.call, status(2, completed(op, { ...consent.binding.selection, task: ':current:bundleProduction' }))); await sent.done;
  assert.equal(h.state.status.operation.result.summary.counts.FAIL, 1); assert.equal(h.state.historical, false);
  assert.equal(h.project.draft, draft); assert.equal(h.project.baseline, baseline);
});

test('repeated prior terminal event and racing Status reply do not bind an old selection to the next Prepare', async (t) => {
  const h = harness(t), first = await reviewed(h), sent = start(h, first);
  const prior = status(2, completed(first));
  h.reply(sent.call, prior); await sent.done;
  assert.equal(h.state.status.operation.result.selection.module, ':app');
  const selected = { module: ':next', variant: 'production', applicationId: 'org.next.app' };
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
  h.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 2,
    snapshot: snapshot({ config: NEW_CONFIG, ...selected }), observedAt: 2 });
  await h.readVersion();
  const repeat = deferred(); h.api.androidBuildStatus = () => repeat.promise;
  const checking = h.controller.checkStatus(); await flush(); // Status request precedes the new Prepare.
  const preparing = h.controller.prepare(), call = h.calls.at(-1);
  assert.equal(call.kind, 'prepare'); assert.deepEqual(h.state.project.selection, selected);
  h.emit(prior); // This explicitly allowed duplicate still describes :app.
  repeat.resolve(clone(prior)); await checking; // Same receive branch, from a late Status response.
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.nativeBlocked, false);
  assert.equal(h.state.pending, 'prepare'); assert.equal(h.state.consent, null);
  assert.equal(h.state.status.operation.operationId, OP);
  assert.equal(h.calls.filter((entry) => entry.kind === 'cancel').length, 0);
  const next = operation(call.input, { operationId: OTHER, ownerGeneration: '1'.repeat(32) });
  h.reply(call, status(3, next)); await preparing;
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.nativeBlocked, false);
  assert.equal(h.state.pending, null); assert.equal(h.state.consent.operationId, OTHER);
  assert.deepEqual(h.state.consent.binding.selection, selected);
  assert.equal(h.state.consent.acknowledged, false);
  assert.equal(h.calls.filter((entry) => entry.kind === 'prepare').length, 2);
  assert.equal(h.calls.filter((entry) => entry.kind === 'start').length, 1);
});

test('complete observe-v2 and every snapshot/read generation must match; a partial or stale same-name response is rejected', async (t) => {
  const h = harness(t); await h.ready; const original = clone(h.versionState);
  const mutations = [
    (v) => { v.pending = clone(v.resultBinding); }, (v) => { v.stale = true; }, (v) => { v.error = { code: 'busy', message: 'PRIVATE', retryable: false }; },
    (v) => { v.result.schemaVersion = 1; }, (v) => { delete v.result.savedVersion; }, (v) => { delete v.result.assurance; },
    (v) => { v.result.assurance.toolsProbed = true; }, (v) => { v.result.observationScope = 'atomic'; },
    (v) => { v.result.savedConfig.sha256 = '0'.repeat(64); }, (v) => { v.result.source = 'release/other.properties'; },
    (v) => { v.resultBinding.observationGeneration--; }, (v) => { v.resultBinding.readEpoch--; }, (v) => { v.resultBinding.requestId++; },
    (v) => { v.resultBinding.connectionGeneration++; }, (v) => { v.resultBinding.selectionGeneration++; },
    (v) => { v.resultBinding.draftRevision++; }, (v) => { v.project.observationGeneration++; }, (v) => { v.generationLost = true; },
  ];
  for (const mutate of mutations) {
    const view = clone(original); mutate(view); h.overrideVersion(view); await h.controller.prepare();
    assert.equal(h.calls.length, 0); assert.equal(h.state.project.savedVersion, null);
  }
  h.overrideVersion(undefined); assert.equal(h.state.project.inputIssue, null);
  const good = h.project;
  for (const patch of [{ snapshotRequest: 88 }, { snapshotError: { code: 'busy', message: 'inert', retryable: false } },
    { snapshotPredatesSave: true }, { savedConfigContent: null }, { snapshot: null }]) {
    h.replace({ ...good, ...patch }); await h.controller.prepare(); assert.equal(h.calls.length, 0);
  }
});

test('new same-byte version read retires consent synchronously, before reply; status cannot restore the old review', async (t) => {
  const h = harness(t), op = await reviewed(h); h.controller.setAcknowledged(OP, OWNER, true);
  const previousEpoch = h.state.consent.binding.versionObservation.readEpoch;
  // Deliberately start the fake passive read directly: its synchronous pending
  // subscription must still retire consent, even without the explicit hook.
  const read = h.version.read(); assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  assert.equal(h.state.project.versionPending, true); assert.equal(h.state.project.savedVersion, null);
  h.versionCalls.at(-1).resolve(observation(h.project)); await read;
  assert.ok(h.versionState.readEpoch > previousEpoch); assert.equal(h.state.project.inputIssue, null);
  h.emit(status(2, op)); h.controller.setAcknowledged(OP, OWNER, true); await h.controller.start(OP, OWNER);
  assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
});

test('a late Prepare reply uses its original identity only to stop after input retirement; event observation is not consent', async (t) => {
  const h = harness(t); await h.ready; const preparing = h.controller.prepare(), call = h.calls[0], op = operation(call.input);
  h.emit(status(1, op)); assert.equal(h.state.consent, null);
  h.controller.setAcknowledged(OP, OWNER, true); await h.controller.start(OP, OWNER); assert.equal(h.calls.length, 1);
  h.controller.versionIntent(); // Even a blocked/no-op read intent burns the review.
  h.reply(call, status(1, op)); await preparing;
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  assert.deepEqual(h.calls.at(-1).input, { operationId: OP, ownerGeneration: OWNER }); assert.equal(h.state.historical, true);
});

test('no-op edit/save/refresh/selection intent retires before the reducer and never revives acknowledgement', async (t) => {
  for (const action of [{ type: 'edit', projectId: 'p1', path: 'android.enabled', value: true }, { type: 'config-save-intent', projectId: 'p1' },
    { type: 'snapshot-failed', projectId: 'p1', requestId: 999, error: { code: 'busy', message: 'inert', retryable: false } }, { type: 'switch', projectId: 'absent' }]) {
    const h = harness(t), op = await reviewed(h); h.controller.setAcknowledged(OP, OWNER, true);
    h.controller.beforeWorkspaceAction(action); assert.equal(h.state.consent, null);
    h.dispatch(action); h.controller.cancel(); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
    h.reply(h.calls.at(-1), status(2, terminal(op, 'cancelled', 'context-changed'))); await flush();
    h.emit(status(1, op)); await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0);
  }
});

test('one Start is consumed before handoff, and a lost reply never permits replay or implicit retry', async (t) => {
  const h = harness(t), op = await reviewed(h);
  assert.deepEqual(h.order.slice(0, 2), ['subscribe', 'status']);
  h.controller.setAcknowledged(OTHER, OWNER, true); assert.equal(h.state.consent.acknowledged, false);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0);
  const sent = start(h, op); assert.equal(h.state.consent, null);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
  let reads = 0; sent.call.reject({ get message() { reads++; return 'PRIVATE'; } }); await sent.done;
  assert.equal(reads, 0); assert.ok(androidBuildOwnerReason(h.state)); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
  h.emit(status(3, terminal(op))); await h.controller.checkStatus();
  assert.equal(h.state.originalUnconfirmed, false); assert.equal(h.state.consent, null);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);

  // Native terminal A does not let its delayed Cancel reply act on new B.
  for (const late of ['reject', 'malformed']) {
    const h = harness(t), first = await reviewed(h), initial = start(h, first);
    h.reply(initial.call, status(2, running(first))); await initial.done;
    assert.equal(h.controller.cancel(), true);
    const cancel = h.calls.at(-1);
    assert.equal(cancel.kind, 'cancel');
    assert.deepEqual(cancel.input, { operationId: first.operationId, ownerGeneration: first.ownerGeneration });
    // Terminal must preserve the last observed running stage, not regress to consent's null stage.
    const settled = terminal(running(first));
    h.emit(status(3, settled)); await flush();
    assert.deepEqual(clone(h.state.status.operation), settled);
    assert.equal(h.state.integrityFailed, false);
    assert.equal(h.state.nativeBlocked, false);
    assert.equal(h.controller.prepareReason(), null);
    const next = await reviewed(h, { operationId: OTHER, ownerGeneration: '1'.repeat(32) });
    const sent = start(h, next);
    h.reply(sent.call, status(5, running(next))); await sent.done;
    assert.equal(h.state.historical, false);
    assert.equal(h.state.error, null);
    const current = clone(h.state);
    if (late === 'reject') cancel.reject({ code: 'bridge-reply-lost', message: 'PRIVATE OLD CANCEL' });
    else cancel.resolve({ schemaVersion: 999 });
    await flush();
    assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1,
      'A stale Cancel completion must not dispatch Cancel for B');
    assert.deepEqual(clone(h.state), current);
    assert.deepEqual(h.calls.filter((call) => call.kind === 'cancel').map((call) => call.input),
      [{ operationId: first.operationId, ownerGeneration: first.ownerGeneration }]);
    assert.equal(h.state.status.operation.operationId, next.operationId);
    assert.equal(h.state.status.operation.ownerGeneration, next.ownerGeneration);
    assert.equal(h.state.status.operation.phase, 'running');
    assert.equal(h.state.integrityFailed, false);
    assert.equal(h.state.nativeBlocked, false);
    h.emit(status(6, completed(next))); await flush();
    assert.equal(h.state.status.operation.phase, 'terminal');
  }

  // The still-current claim keeps its ordinary settlement/refusal behavior.
  for (const completion of ['valid', 'reject', 'malformed']) {
    const h = harness(t), original = await reviewed(h);
    assert.equal(h.controller.cancel(), true);
    const cancel = h.calls.at(-1);
    assert.equal(cancel.kind, 'cancel');
    if (completion === 'valid') h.reply(cancel, status(2, terminal(original)));
    else if (completion === 'reject') cancel.reject({ code: 'bridge-reply-lost', message: 'PRIVATE CURRENT CANCEL' });
    else cancel.resolve({ schemaVersion: 999 });
    await flush();
    assert.equal(h.state.consent, null);
    assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
    if (completion === 'valid') {
      assert.equal(h.state.status.operation.phase, 'terminal');
      assert.equal(h.state.error, null);
      assert.equal(h.state.integrityFailed, false);
    } else {
      assert.equal(h.state.observationIssue, completion === 'reject' ? 'bridge' : 'protocol');
      assert.equal(h.state.integrityFailed, completion === 'malformed');
      assert.equal(h.state.nativeBlocked, completion === 'malformed');
      assert.ok(!JSON.stringify(h.state).includes('PRIVATE'));
      h.emit(status(2, terminal(original))); await flush();
    }
  }
});

test('synchronous saved-pair replacement vetoes unsent Prepare/consumed Start before their backend calls', async (t) => {
  for (const phase of ['prepare', 'start']) {
    const h = harness(t); await h.ready;
    if (phase === 'start') { await reviewed(h); h.controller.setAcknowledged(OP, OWNER, true); }
    let changed = false;
    const off = h.controller.subscribe(() => {
      if (!changed && h.state.pending === phase) {
        changed = true; const view = clone(h.versionState); view.result.version.build++;
        // Changed bytes/name/build cannot exploit a stale render; replacing the
        // observation reference synchronously retires even if hashes match.
        h.overrideVersion(view);
      }
    });
    if (phase === 'prepare') await h.controller.prepare(); else await h.controller.start(OP, OWNER);
    off(); assert.equal(h.calls.filter((call) => call.kind === phase).length, 0);
    assert.equal(h.state.consent, null);
    if (phase === 'start') assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
  }
});

test('leaving an unstarted review cancels it, while started work keeps global Status/Cancel and truthful output disposition', async (t) => {
  const unstarted = harness(t); await reviewed(unstarted); unstarted.controller.setVisible(false); unstarted.controller.setVisible(true);
  assert.equal(unstarted.state.consent, null); assert.equal(unstarted.calls.filter((call) => call.kind === 'cancel').length, 1);
  const h = harness(t), op = await reviewed(h), sent = start(h, op);
  h.reply(sent.call, status(2, running(op))); await sent.done;
  h.controller.setVisible(false); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 0);
  assert.ok(androidBuildOwnerReason(h.state)); assert.equal(h.controller.canCancel(), true);
  assert.equal(h.controller.cancel(), true); assert.equal(h.controller.cancel(), false);
  assert.equal(h.state.status.operation.phase, 'running'); // Click/Promise submission is not settlement.
  const retained = completed(op); Object.assign(retained, { outcome: 'failed', reason: 'work-retained', result: null });
  retained.disposition = { work: 'retained-work', artifacts: 'retained-incomplete' };
  h.reply(h.calls.at(-1), status(3, retained)); await flush();
  assert.equal(h.state.status.operation.outcome, 'failed'); assert.equal(h.state.status.operation.disposition.work, 'retained-work');
  assert.equal(h.state.status.operation.result, null); assert.equal(h.state.consent, null);
});

test('equal-revision contradictions, stage regression, foreign replacement and unknown cannot overwrite retained original state', async (t) => {
  for (const fault of ['same-revision', 'stage', 'foreign', 'unknown']) {
    const h = harness(t), op = await reviewed(h), sent = start(h, op);
    h.reply(sent.call, status(2, running(op, 'capturing'))); await sent.done;
    if (fault === 'same-revision') h.emit(status(2, running(op, 'capturing'), 'shutdown'));
    if (fault === 'stage') h.emit(status(3, running(op, 'building')));
    if (fault === 'foreign') h.emit(status(3, { ...completed(op), operationId: OTHER }));
    if (fault === 'unknown') {
      h.emit(status(3, { ...running(op, 'capturing'), phase: 'unknown', outcome: 'unknown', reason: 'cleanup-unknown' }, 'cleanup-unknown'));
      h.emit(status(4, completed(op))); assert.equal(h.state.status.operation.phase, 'unknown');
    }
    assert.equal(h.state.consent, null); assert.equal(h.state.nativeBlocked, true); assert.ok(androidBuildOwnerReason(h.state));
    assert.equal(h.state.status.operation.result, null); h.controller.beginConnection();
    let adopted = 0; await h.controller.connect({ ...h.api, subscribeAndroidBuild: async () => { adopted++; return () => {}; } });
    assert.equal(adopted, 0);
  }
});

test('expiry is absolute and late subscription/disposal never manufactures cleanup or replaces the original observer', async (t) => {
  const h = harness(t), op = await reviewed(h), deadline = h.state.consent.deadline;
  h.clock(deadline - 1); await h.controller.checkStatus(); assert.equal(h.state.consent.deadline, deadline);
  h.clock(deadline); h.controller.setAcknowledged(OP, OWNER, true); assert.equal(h.state.consent, null);
  h.emit(status(2, op)); await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0);
  const gate = deferred(), pending = harness(t, { listenGate: gate, completeVersion: false });
  assert.equal(pending.reads.length, 0); pending.controller.dispose(); gate.resolve(); await pending.ready;
  assert.equal(pending.subscriptions[0].closed, true); assert.equal(pending.reads.length, 0);
  const active = harness(t), original = await reviewed(active), sent = start(active, original);
  active.reply(sent.call, status(2, running(original))); await sent.done;
  active.controller.dispose(); assert.equal(active.subscriptions[0].closed, false);
  // A native terminal retains the last reached stage; it does not regress the
  // already-observed running stage back to the unstarted intent's null stage.
  active.emit(status(3, terminal(running(original)))); assert.equal(active.subscriptions[0].closed, true);
});

test('unqualified/competing states and startup observations cannot become frontend force-enable paths', async (t) => {
  for (const availability of ['runtime-unqualified', 'toolchain-unqualified', 'unsupported-platform']) {
    const h = harness(t, { initial: status(0, null, availability) }); await h.ready; await h.controller.prepare(); assert.equal(h.calls.length, 0);
  }
  const h = harness(t); await h.ready; h.other('Original sibling operation owns its native slot.');
  await h.controller.prepare(); assert.equal(h.calls.length, 0);
  const preview = new AndroidBuildController({ selectedProject: () => h.project, releaseVersion: () => h.versionState, otherOperationReason: () => null });
  t.after(() => preview.dispose()); preview.setVisible(true); preview.syncProject(); await preview.connect(previewApi); await preview.prepare();
  assert.equal(preview.getSnapshot().status, null); assert.match(preview.prepareReason(), /Browser preview/);
});

test('actual native bridge sends four raw copied Android bodies, rejects bad callbacks/status and never invokes unavailable or preview backends', async () => {
  const calls = [], gate = deferred(); let event, callback, reply = status();
  const api = createNativeApi('native', async (command, raw) => {
    assert.ok(raw instanceof Uint8Array); const body = JSON.parse(new TextDecoder().decode(raw)); calls.push({ command, body });
    if (command === 'prepare_android_build') await gate.promise;
    return clone(reply);
  }, async (name, receive) => { event = name; callback = receive; return () => {}; });
  const input = { projectId: 'p1', draftRevision: 1, baselineGeneration: 1, savedConfig: clone(CONFIG),
    savedVersion: { ...VERSION, source: 'release/version.properties', name: '1.2.3', build: 42 },
    artifactValidation: { mode: 'structure-and-version', uploadCertificateSha256: null } };
  const before = clone(input), prepare = api.prepareAndroidBuild(input); input.savedVersion.build++; input.savedConfig.sha256 = '0'.repeat(64);
  gate.resolve(); await prepare;
  await api.startAndroidBuild({ operationId: OP, ownerGeneration: OWNER, consentVersion: ANDROID_BUILD_CONSENT });
  await api.androidBuildStatus(); await api.cancelAndroidBuild(OP, OWNER);
  assert.deepEqual(calls.map((call) => call.command), ['prepare_android_build', 'start_android_build', 'android_build_status', 'cancel_android_build']);
  assert.deepEqual(calls[0].body, before); assert.deepEqual(calls[2].body, {});
  let observed; await api.subscribeAndroidBuild((value) => { observed = value; }); assert.equal(event, ANDROID_BUILD_EVENT);
  callback({ ...status(), privateOutput: 'PRIVATE' }); assert.equal(observed, null);
  const count = calls.length;
  await assert.rejects(api.prepareAndroidBuild({ ...before, native: { argv: ['PRIVATE'] } }), (error) => error.code === 'android_build_invalid');
  assert.equal(calls.length, count);
  reply = { ...status(), extra: true }; await assert.rejects(api.androidBuildStatus(), (error) => error.code === 'android_build_protocol');
  let invoked = 0, listened = 0;
  const unavailable = createNativeApi('unavailable', async () => { invoked++; return status(); }, async () => { listened++; return () => {}; });
  for (const port of [unavailable, previewApi]) {
    for (const [method, args] of [['prepareAndroidBuild', [before]], ['startAndroidBuild', [{ operationId: OP, ownerGeneration: OWNER, consentVersion: ANDROID_BUILD_CONSENT }]],
      ['androidBuildStatus', []], ['cancelAndroidBuild', [OP, OWNER]], ['subscribeAndroidBuild', [() => {}]]]) {
      await assert.rejects(port[method](...args), (error) => error.code === 'android_build_unavailable');
    }
  }
  assert.equal(invoked, 0); assert.equal(listened, 0);
});

test('component shares native-terminal-only output with Artifacts and provides real input/output/cancel help, not a file action', async (t) => {
  const source = readFileSync(new URL('../src/components/AndroidBuild.tsx', import.meta.url), 'utf8');
  assert.match(source, /export function AndroidBuildResultView/);
  assert.match(source, /state\.mode !== 'native' \|\| op\?\.phase !== 'terminal' \|\| op\.outcome !== 'complete'/);
  assert.match(source, /<AndroidBuildResultView state=\{state\}/);
  assert.match(source, /if \(compact && !owned\) return null/); assert.match(source, /controller\.canCancel\(\)/);
  assert.match(source, /controller\.versionIntent\(\); onReadVersion\(\)/);
  assert.match(source, /post-run bytes may be reused\/stale/); assert.match(source, /signer is not inspected/);
  assert.doesNotMatch(source, /(?:window\.open|href=|download=|controller\.dispose\()/);
  for (const help of [androidBuildHelp, androidBuildInputHelp, androidBuildOutputHelp, androidBuildCancelHelp, androidBuildSignatureHelp]) {
    for (const key of ['label', 'what', 'why', 'where', 'format', 'failure', 'requiredWhen']) assert.ok(help[key].length > 12, `${help.label}.${key}`);
  }
  assert.match(androidBuildInputHelp.what, /observe-v2/);
  assert.match(androidBuildOutputHelp.failure, /Ordinary inspection completion may contain FAIL/);
  assert.match(androidBuildOutputHelp.failure, /local signing requires all final checks to pass/);
  assert.match(androidBuildCancelHelp.failure, /Unknown cleanup is sticky/);

  // The ordinary visible identity comes only from the controller's parsed
  // current Status, not the displayed project, a result field or test props.
  const details = source.slice(source.indexOf('function AndroidBuildDetails('), source.indexOf('// Shared by Releases'));
  assert.match(details, /const op = state\.status\?\.operation, consent = state\.consent/);
  assert.match(details, /state\.mode !== 'native' \|\| !op \|\| state\.historical \|\| state\.integrityFailed \|\| state\.nativeBlocked/);
  assert.match(details, /\|\| state\.originalUnconfirmed\) return null/);
  assert.match(details, /review && \(op\.phase !== 'awaiting-consent' \|\| !op\.intentUsable \|\| !consent/);
  assert.match(details, /consent\.operationId !== op\.operationId \|\| consent\.ownerGeneration !== op\.ownerGeneration/);
  assert.match(details, /role="group" aria-label="Build details"/);
  assert.ok(details.includes('<p>{`Build operation ID: ${op.operationId}`}</p>'));
  assert.ok(details.includes('<p>{`Build owner generation: ${op.ownerGeneration}`}</p>'));
  assert.doesNotMatch(details, /(?:controller\.|result\.|project\.|operationId:|ownerGeneration:|aria-hidden|data-testid)/);
  assert.equal((source.match(/<AndroidBuildDetails state=\{state\}(?: review)? \/>/g) ?? []).length, 3);
  const resultView = source.slice(source.indexOf('export function AndroidBuildResultView'), source.indexOf('export function AndroidBuild({'));
  assert.equal((resultView.match(/<AndroidBuildDetails state=\{state\} \/>/g) ?? []).length, 1);
  const review = source.slice(source.indexOf('aria-label="Confirm this saved Android-build intent"'), source.indexOf('{state.error &&'));
  assert.equal((review.match(/<AndroidBuildDetails state=\{state\} review \/>/g) ?? []).length, 1);
  const originalStatus = source.slice(source.indexOf('aria-label="Original Android build status"'), source.indexOf('Leaving Releases keeps a started run'));
  assert.equal((originalStatus.match(/<AndroidBuildDetails state=\{state\} \/>/g) ?? []).length, 1);

  // Existing real controller and protocol, with inert native replies. Review,
  // running and terminal data preserve the same pair; foreign IDs/generations
  // and saved-context changes cannot be presented as a current identity.
  for (const fault of [null, 'operation', 'generation', 'saved-context']) {
    const h = harness(t); await h.ready;
    assert.equal(h.state.status.operation, null);
    const original = await reviewed(h), reviewedState = h.state;
    assert.deepEqual([reviewedState.status.operation.operationId, reviewedState.status.operation.ownerGeneration], [OP, OWNER]);
    assert.deepEqual([reviewedState.consent.operationId, reviewedState.consent.ownerGeneration], [OP, OWNER]);
    assert.equal(reviewedState.status.operation.phase, 'awaiting-consent');
    assert.equal(reviewedState.status.operation.intentUsable, true);
    for (const key of ['historical', 'integrityFailed', 'nativeBlocked', 'originalUnconfirmed']) assert.equal(reviewedState[key], false);
    const sent = start(h, original);
    assert.equal(h.state.consent, null); assert.equal(h.state.originalUnconfirmed, true);
    h.reply(sent.call, status(2, running(original))); await sent.done;
    assert.equal(h.state.originalUnconfirmed, false);
    assert.deepEqual([h.state.status.operation.operationId, h.state.status.operation.ownerGeneration], [OP, OWNER]);
    if (fault === 'operation' || fault === 'generation') {
      const changed = completed(original); changed[fault === 'operation' ? 'operationId' : 'ownerGeneration'] = OTHER;
      h.emit(status(3, changed));
      assert.equal(h.state.nativeBlocked, true); assert.equal(h.state.integrityFailed, true);
      assert.equal(h.state.status.operation.result, null);
      assert.deepEqual([h.state.status.operation.operationId, h.state.status.operation.ownerGeneration], [OP, OWNER]);
    } else {
      h.emit(status(3, completed(original)));
      assert.equal(h.state.status.operation.outcome, 'complete'); assert.ok(h.state.status.operation.result);
      assert.deepEqual([h.state.status.operation.operationId, h.state.status.operation.ownerGeneration], [OP, OWNER]);
      assert.equal(h.state.historical, false);
      if (fault === 'saved-context') {
        h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
        assert.equal(h.state.historical, true);
        assert.ok(h.state.status.operation.result, 'Retain the original result, without relabelling it current.');
      }
    }
    assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
  }
});


test('upload signature starts off, requires a saved public certificate and binds its literal completed observation', async (t) => {
  const h = harness(t); await h.ready;
  assert.equal(h.state.verifyUploadSignature, false);
  h.controller.setVerifyUploadSignature(true);
  assert.match(h.controller.prepareReason(), /uploadCertificateSha256/);
  await h.controller.prepare(); assert.equal(h.calls.length, 0);
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
  h.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 2,
    snapshot: snapshot({ config: NEW_CONFIG, uploadCertificateSha256: 'aB'.repeat(32) }), observedAt: 2 });
  await h.readVersion();
  const op = await reviewed(h);
  assert.deepEqual(h.calls[0].input.artifactValidation, { mode: 'upload-signature', uploadCertificateSha256: 'aB'.repeat(32) });
  const sent = start(h, op), done = completed(op);
  const findings = [['aab-structure', 'PASS'], ['aab-manifest', 'PASS'], ['signature', 'PASS'], ['signer', 'PASS']]
    .map(([check, status], ordinal) => ({ ordinal, check, status }));
  const summary = { total: 4, shown: 4, omitted: 0, counts: Object.fromEntries(ANDROID_BUILD_CORE_STATUSES.map((key) => [key, key === 'PASS' ? 4 : 0])) };
  Object.assign(done.activity, { findings: clone(findings), summary: clone(summary) });
  Object.assign(done.result, { findings, summary });
  Object.assign(done.result.assurances, { structure: 'passed', nativeManifest: 'passed', applicationVersion: 'native-checked',
    signature: 'passed', signer: 'matches-saved-upload-certificate' });
  h.reply(sent.call, status(2, done)); await sent.done;
  assert.equal(h.state.status.operation.result.assurances.signer, 'matches-saved-upload-certificate');
  assert.equal(h.state.historical, false);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((call) => call.kind === 'start').length, 1);
});

test('changing inspection mode retires an unstarted review once; switching back or Status cannot renew consent', async (t) => {
  const h = harness(t), op = await reviewed(h);
  assert.deepEqual(op.context.artifactValidation, { mode: 'structure-and-version', uploadCertificateSha256: null });
  h.controller.setAcknowledged(OP, OWNER, true);
  h.controller.setVerifyUploadSignature(true);
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.controller.setVerifyUploadSignature(false); h.emit(status(2, op));
  h.controller.setAcknowledged(OP, OWNER, true); await h.controller.start(OP, OWNER);
  assert.equal(h.calls.filter((call) => call.kind === 'start').length, 0);
  assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
  assert.deepEqual(clone(h.state.status.operation.context.artifactValidation), op.context.artifactValidation);
});

test('late Prepare after mode change is only an original to cancel, and changed saved certificate retires review', async (t) => {
  const h = harness(t); await h.ready;
  const pending = h.controller.prepare(), call = h.calls[0], op = operation(call.input);
  h.controller.setVerifyUploadSignature(true);
  h.reply(call, status(1, op)); await pending;
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  const g = harness(t); await g.ready;
  g.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 2 });
  g.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 2,
    snapshot: snapshot({ config: NEW_CONFIG, uploadCertificateSha256: 'ab'.repeat(32) }), observedAt: 2 });
  await g.readVersion(); g.controller.setVerifyUploadSignature(true); const original = await reviewed(g);
  const changed = clone(g.project); changed.snapshot.config.data.android.uploadCertificateSha256 = 'cd'.repeat(32);
  g.replace(changed); // Even repeated digest/counter DATA cannot conceal a changed displayed field.
  assert.equal(g.state.consent, null); assert.equal(g.calls.at(-1).kind, 'cancel');
  g.emit(status(2, original)); await g.controller.start(OP, OWNER);
  assert.equal(g.calls.filter((item) => item.kind === 'start').length, 0);
  assert.equal(g.state.status.operation.context.artifactValidation.uploadCertificateSha256, 'ab'.repeat(32));
});

test('signature help distinguishes upload and Play signing certificates without credential import or signing', () => {
  assert.match(androidBuildSignatureHelp.where, /Upload key certificate/);
  assert.match(androidBuildSignatureHelp.where, /App signing key certificate/);
  assert.match(androidBuildSignatureHelp.format, /64 hexadecimal characters without colons/);
  assert.match(androidBuildSignatureHelp.what, /does not sign or upload/);
  const source = readFileSync(new URL('../src/components/AndroidBuild.tsx', import.meta.url), 'utf8');
  assert.match(source, /Also verify upload signature/);
  assert.match(source, /Signature integrity:/); assert.match(source, /Saved upload certificate:/);
  assert.match(source, /controller.setVerifyUploadSignature/);
});

test('prerequisite guidance distinguishes an unqualified gate from a missing SDK and limits Tools diagnostics', () => {
  assert.match(androidBuildHelp.what, /user-installed JDK and Android SDK/);
  assert.match(androidBuildHelp.what, /selected protected Gradle and pinned bundletool/);
  assert.match(androidBuildHelp.what, /installs no tools and accepts no licenses/);
  assert.match(androidBuildHelp.where, /Environment Requirements/);
  assert.match(androidBuildHelp.format, /only Git, Java and Javac/);
  assert.match(androidBuildHelp.format, /do not inspect the SDK/);
  assert.match(androidBuildHelp.format, /Gradle readiness or authorize a build/);
  for (const state of ['Missing', 'unselected', 'unsupported', 'not inspected', 'unqualified']) assert.ok(androidBuildHelp.failure.includes(state));
  assert.match(androidBuildHelp.failure, /closed native gate does not mean your SDK is missing/);
});

test('Mac tool selection is explicit DATA and changing it retires the saved build review', async (t) => {
  const h = harness(t, { initialCatalog: readyCatalog() }); await h.ready;
  assert.match(h.controller.prepareReason(), /Choose a registered/);
  await h.controller.prepare(); assert.equal(h.calls.length, 0);
  const choosing = h.controller.selectToolchain(TOOL_A.instance, TOOL_A.recordSha256);
  const selected = h.catalogCalls.at(-1);
  assert.equal(selected.kind, 'catalog-select');
  assert.deepEqual(selected.input, { schemaVersion: 1, catalogGeneration: 1, instance: TOOL_A.instance,
    recordSha256: TOOL_A.recordSha256, inventorySha256: TOOL_A.inventorySha256, osProviderSha256: TOOL_A.osProviderSha256 });
  h.replyCatalog(selected, readyCatalog({ statusRevision: 2, selected: TOOL_A })); await choosing;
  const op = await reviewed(h);
  assert.deepEqual(h.state.consent.binding.toolchainSelection, TOOL_A);
  h.emitCatalog(readyCatalog({ statusRevision: 3, selected: TOOL_B }));
  assert.equal(h.state.consent, null);
  assert.equal(h.calls.at(-1).kind, 'cancel');
  assert.deepEqual(h.calls.at(-1).input, { operationId: op.operationId, ownerGeneration: op.ownerGeneration });
  h.reply(h.calls.at(-1), status(4, terminal(op))); await flush();
  assert.equal(h.state.pending, null);
});

test('lost catalog reply and Unknown retain the original observer, cancel target and application exclusion', async (t) => {
  const h = harness(t, { initialCatalog: catalogStatus({ availability: 'available' }) }); await h.ready;
  const refreshing = h.controller.refreshCatalog(), call = h.catalogCalls.at(-1);
  assert.equal(h.state.catalogUnconfirmed, true);
  const identity = { catalogGeneration: 1, operationId: '7'.repeat(32) };
  h.emitCatalog(catalogStatus({ statusRevision: 1, ...identity, availability: 'busy', phase: 'reading', reason: 'none' }));
  // Event identifies native custody; the original request promise is still
  // pending, so it cannot confirm its reply or release the retained observer.
  assert.equal(h.state.catalogUnconfirmed, true); assert.equal(h.state.catalogPending, 'refresh');
  assert.equal(h.catalogSubscriptions[0].closed, false); assert.equal(h.subscriptions[0].closed, false);
  assert.ok(androidBuildOwnerReason(h.state));
  h.emitCatalog(catalogStatus({ statusRevision: 2, ...identity, availability: 'cleanup-unknown', phase: 'unknown', reason: 'cleanup-unknown' }));
  assert.ok(h.state.nativeBlocked);
  h.controller.beginConnection();
  assert.equal(h.catalogSubscriptions[0].closed, false);
  assert.equal(h.subscriptions[0].closed, false);
  const cancelling = h.catalogCalls.at(-1);
  assert.equal(cancelling.kind, 'catalog-cancel'); assert.deepEqual(cancelling.input, { schemaVersion: 1, ...identity });
  call.reject({ code: 'lost_reply' }); await refreshing;
  h.replyCatalog(cancelling, catalogStatus({ statusRevision: 2, ...identity, availability: 'cleanup-unknown', phase: 'unknown', reason: 'cleanup-unknown' }));
  await flush(); assert.ok(h.controller.catalogActionReason()); assert.ok(h.state.nativeBlocked);
});

test('a Mac result from another tool selection cannot become the reviewed build result', async (t) => {
  const h = harness(t, { initialCatalog: readyCatalog({ selected: TOOL_A }) }), op = await reviewed(h);
  const started = start(h, op);
  h.reply(started.call, status(2, { ...op, phase: 'starting', intentUsable: false }));
  await started.done;
  const result = completed(op);
  result.result.schemaVersion = 2; result.result.toolchainProfile = 'android-registered-macos-arm64-v1';
  result.result.toolchainSelection = clone(TOOL_B);
  h.emit(status(3, result));
  assert.equal(h.state.integrityFailed, true);
  assert.equal(h.state.status.operation.result, null);
});

const serviceIdle = (patch = {}) => ({ schemaVersion: 1, statusRevision: 0, setupGeneration: 0,
  availability: 'available', prerequisite: 'service-unavailable', phase: 'idle', reason: 'service-unavailable',
  operation: null, observation: null, ...patch });
function servicePending(call, sourceGeneration = 0) {
  return serviceIdle({ statusRevision: 1 + 2 * call.input.setupGeneration, setupGeneration: call.input.setupGeneration + 1,
    availability: 'busy', phase: ({ check: 'checking', 'request-registration': 'requesting', 'open-approval-settings': 'opening-settings' })[call.kind], reason: 'none',
    operation: { operationId: String(call.input.setupGeneration + 1).repeat(32), setupGeneration: call.input.setupGeneration + 1,
      sourceGeneration, action: call.kind, context: clone(call.input.context) } });
}
function serviceComplete(pending, { state = 'enabled', phase = 'complete', reason = 'none', observation = true } = {}) {
  const action = pending.operation.action, mutation = action !== 'check';
  return { ...clone(pending), statusRevision: pending.statusRevision + 1, availability: 'available', phase, reason,
    prerequisite: state === 'enabled' ? 'ready' : state === 'requires-approval' ? 'approval-required' : 'service-unavailable',
    observation: observation ? { state, outcome: action === 'check' ? 'observed' : action === 'request-registration' ? 'registration-requested' : 'settings-requested',
      mutationEntered: mutation, mutationReturned: mutation, mutationUncertain: false, nativeSettled: true } : null };
}

test('source-independent setup keeps one-use system consent separate from check, approval, copy and pending invoke', async (t) => {
  const h = harness(t, { initialService: serviceIdle() }); await h.ready;
  assert.equal(h.state.toolSources.selections.length, 0); assert.equal(h.controller.serviceActionReason(), null);
  await h.controller.requestAndroidToolServiceRegistration(); assert.equal(h.serviceCalls.length, 0);
  const checking = h.controller.checkAndroidToolService(), check = h.serviceCalls[0];
  assert.equal(check.kind, 'check'); assert.equal(check.input.consentVersion, undefined);
  const pending = servicePending(check), done = serviceComplete(pending, { state: 'requires-approval' });
  h.emitService(pending); h.emitService(done);
  assert.equal(h.state.servicePending, 'check'); // Event completion does not settle this original invoke.
  assert.ok(androidBuildOwnerReason(h.state)); assert.equal(h.state.serviceConsent, null);
  h.replyService(check, done); await checking;
  assert.equal(h.state.servicePending, null); assert.equal(h.state.registrationConsent, null);
  h.controller.setServiceRegistrationAcknowledged(1, true); assert.ok(h.state.serviceConsent);
  const requesting = h.controller.requestAndroidToolServiceRegistration(), request = h.serviceCalls[1];
  assert.equal(request.input.consentVersion, ANDROID_TOOL_SERVICE_CONSENT);
  assert.equal(request.input.registrationAcknowledged, true); assert.equal(request.input.licenseAcknowledged, undefined);
  assert.equal(h.state.serviceConsent, null);
  await h.controller.requestAndroidToolServiceRegistration(); await h.controller.chooseToolSource('jdk'); await h.controller.refreshCatalog();
  assert.equal(h.serviceCalls.length, 2); assert.equal(h.catalogCalls.length, 0); assert.equal(h.calls.length, 0);
  h.replyService(request, serviceComplete(servicePending(request))); await requesting;
  assert.equal(h.state.serviceConsent, null); assert.equal(h.state.registrationConsent, null);
  assert.ok(h.controller.serviceRegistrationReason()); // Completion did not renew either consent.
});

test('service setup accepts a partial picker census, but missing shipping identity remains a real prerequisite', async (t) => {
  const partial = harness(t, { initialService: serviceIdle(), sourceSelections: [{ role: 'jdk', displayName: 'Example.jdk' }] });
  await partial.ready;
  assert.equal(partial.controller.serviceActionReason(), null);
  const checking = partial.controller.checkAndroidToolService(), call = partial.serviceCalls[0];
  partial.replyService(call, serviceComplete(servicePending(call, 1))); await checking;
  assert.equal(partial.state.toolService.operation.sourceGeneration, 1);
  const missing = harness(t, { initialService: serviceIdle({ prerequisite: 'signing-unavailable', reason: 'signing-unavailable' }) });
  await missing.ready;
  assert.match(missing.controller.serviceActionReason(), /publisher/);
  missing.controller.setServiceRegistrationAcknowledged(0, true);
  await missing.controller.checkAndroidToolService(); await missing.controller.requestAndroidToolServiceRegistration();
  assert.equal(missing.serviceCalls.length, 0); assert.equal(missing.state.serviceConsent, null);
});

test('lost service reply never retries; later exact original observation supplies only bounded status/cancel', async (t) => {
  const h = harness(t, { initialService: serviceIdle() }); await h.ready;
  h.controller.setServiceRegistrationAcknowledged(0, true);
  const requesting = h.controller.requestAndroidToolServiceRegistration(), call = h.serviceCalls[0];
  call.reject({ message: '/private/framework/error-not-for-display' }); await requesting;
  assert.equal(h.state.serviceUnconfirmed, true); assert.equal(h.state.serviceConsent, null);
  await h.controller.checkToolServiceStatus(); await h.controller.requestAndroidToolServiceRegistration();
  assert.equal(h.state.serviceUnconfirmed, true); assert.equal(h.serviceCalls.length, 1);
  const pending = servicePending(call); h.emitService(pending); await flush();
  const cancel = h.serviceCalls[1]; assert.equal(cancel.kind, 'cancel');
  assert.deepEqual(cancel.input, { schemaVersion: 1, operationId: pending.operation.operationId, setupGeneration: 1 });
  assert.equal(h.controller.cancelToolService(), false);
  h.replyService(cancel, serviceComplete(pending, { state: 'unavailable', phase: 'cancelled', reason: 'cancelled', observation: false }));
  await flush(); await h.controller.checkToolServiceStatus();
  assert.equal(h.state.serviceError, null); assert.equal(h.state.toolService.phase, 'cancelled');
  assert.equal(h.state.serviceConsent, null); assert.equal(h.serviceCalls.length, 2);
});

test('service original survives project/dispose changes until both exact invoke and cancellation settle', async (t) => {
  const h = harness(t, { initialService: serviceIdle() }); await h.ready;
  const checking = h.controller.checkAndroidToolService(), call = h.serviceCalls[0];
  h.dispatch({ type: 'select', project: { id: 'p2', name: 'Other inert project', path: '/inert/other' } });
  h.controller.dispose(); assert.equal(h.serviceSubscriptions[0].closed, false);
  const pending = servicePending(call); h.emitService(pending); await flush();
  const cancel = h.serviceCalls[1]; assert.equal(cancel.kind, 'cancel');
  h.replyService(cancel, serviceComplete(pending, { state: 'unavailable', phase: 'refused', reason: 'context-changed', observation: false }));
  await flush(); assert.equal(h.serviceSubscriptions[0].closed, false);
  call.reject({ code: 'reply_lost' }); await checking; await flush();
  assert.equal(h.serviceSubscriptions[0].closed, true); assert.equal(h.subscriptions[0].closed, true);
});

test('foreign service action and terminal regression cannot replace the retained original or target foreign Cancel', async (t) => {
  const h = harness(t, { initialService: serviceIdle() }); await h.ready;
  const checking = h.controller.checkAndroidToolService(), call = h.serviceCalls[0], pending = servicePending(call);
  h.emitService(pending);
  const foreign = clone(pending); foreign.statusRevision++; foreign.operation.operationId = 'f'.repeat(32);
  h.emitService(foreign); await flush();
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.toolService.operation.operationId, pending.operation.operationId);
  assert.equal(h.serviceCalls[1].input.operationId, pending.operation.operationId);
  h.replyService(call, serviceComplete(pending)); await checking;
  h.replyService(h.serviceCalls[1], serviceComplete(pending, { state: 'unavailable', phase: 'cancelled', reason: 'cancelled', observation: false }));
  await flush(); assert.equal(h.state.integrityFailed, true); assert.equal(h.state.serviceConsent, null);
  assert.equal(h.serviceCalls.length, 2);
  const g = harness(t, { initialService: serviceIdle() }); await g.ready;
  const finishing = g.controller.checkAndroidToolService(), original = g.serviceCalls[0];
  const active = servicePending(original), finished = serviceComplete(active);
  g.replyService(original, finished); await finishing;
  g.emitService({ ...active, statusRevision: finished.statusRevision + 1 });
  assert.equal(g.state.integrityFailed, true); assert.equal(g.state.toolService.phase, 'complete');
  assert.equal(g.serviceCalls.length, 1); // A regressed event cannot create a new Cancel target.
});

test('signing stays default-off, requires current assets and forces final signature validation with separate one-use consent', async (t) => {
  const h = harness(t, { initialCatalog: readyCatalog({ selected: TOOL_A }), initialAssets: signingAssets() });
  await savedSigningPolicy(h);
  assert.equal(h.state.buildMode, 'unsigned'); assert.equal(h.state.verifyUploadSignature, false);
  h.controller.setBuildMode('signed'); h.controller.setVerifyUploadSignature(false);
  assert.equal(h.controller.prepareReason(), null);
  const op = await reviewed(h);
  assert.equal(op.context.operation, 'android-build-sign');
  assert.equal(op.context.artifactValidation.mode, 'upload-signature');
  assert.deepEqual(op.context.signing.assignments, [{ kind: 'android-keystore', recordId: OTHER, recordRevision: 1, contextRevision: 2 }]);
  const { call, done } = start(h, op);
  assert.equal(call.input.consentVersion, ANDROID_BUILD_SIGNED_CONSENT);
  h.controller.setBuildMode('unsigned'); assert.equal(h.state.buildMode, 'signed');
  await h.controller.start(op.operationId, op.ownerGeneration);
  assert.equal(h.calls.filter(row => row.kind === 'start').length, 1);
  h.reply(call, status(2, terminal(op))); await done;
  assert.equal(h.state.consent, null);
});

test('current signing assignment changes retire consent synchronously rather than donating a different record to Start', async (t) => {
  const h = harness(t, { initialCatalog: readyCatalog({ selected: TOOL_A }), initialAssets: signingAssets() });
  await savedSigningPolicy(h); h.controller.setBuildMode('signed'); const op = await reviewed(h);
  h.controller.setAcknowledged(op.operationId, op.ownerGeneration, true);
  const changed = signingAssets(); changed.status.records[0].revision++; changed.status.assignments[0].recordRevision++;
  h.setAssets(changed);
  assert.equal(h.state.consent, null);
  await h.controller.start(op.operationId, op.ownerGeneration); await flush();
  assert.equal(h.calls.filter(row => row.kind === 'start').length, 0);
  const cancel = h.calls.find(row => row.kind === 'cancel'); assert.ok(cancel);
  h.reply(cancel, status(2, terminal(op, 'cancelled', 'context-changed'))); await flush();
  for (const mutate of [x => { x.contextCurrent = false; }, x => { x.status.assignments[0].availability = 'unavailable'; },
    x => { x.status.context.projectId = 'other'; }, x => { x.status.mode = 'encrypted'; x.status.persistence = { state: 'locked', keyAccess: 'locked', reason: 'none' }; }]) {
    const blocked = signingAssets(); mutate(blocked); h.setAssets(blocked);
    assert.ok(h.state.signing.issue); assert.equal(h.state.signing.selection, null);
  }
});

test('signed-mode service preparation remains unsigned and material-free even before credentials or fingerprint exist', async (t) => {
  const h = harness(t, { initialService: serviceIdle() }); await h.ready;
  h.controller.setBuildMode('signed'); assert.ok(h.controller.prepareReason());
  assert.equal(h.controller.serviceActionReason(), null);
  const checking = h.controller.checkAndroidToolService(), call = h.serviceCalls[0];
  assert.equal(call.kind, 'check'); assert.equal(call.input.context.signing, undefined);
  assert.deepEqual(call.input.context.artifactValidation, { mode: 'structure-and-version', uploadCertificateSha256: null });
  h.replyService(call, serviceComplete(servicePending(call))); await checking;
  assert.equal(h.calls.length, 0);
});


test('source setup uses its unsigned context through inspection and explicit copy consent, independently of signed build prerequisites', async (t) => {
  for (const mode of ['unsigned', 'unsigned-upload-signature', 'signed']) {
    const h = harness(t, { initialCatalog: readyCatalog({ selected: TOOL_A }),
      initialRegistration: { schemaVersion: 1, statusRevision: 0, registrationGeneration: 0,
        availability: 'available', prerequisite: 'ready', phase: 'idle', reason: 'not-inspected',
        operation: null, review: null, report: null },
      sourceSelections: ['jdk', 'sdk', 'gradle'].map(role => ({ role, displayName: 'Example-' + role })) });
    if (mode === 'unsigned-upload-signature') await savedSigningPolicy(h); else await h.ready;
    h.controller.setBuildMode(mode === 'signed' ? 'signed' : 'unsigned');
    h.controller.setVerifyUploadSignature(mode === 'unsigned-upload-signature');
    if (mode === 'signed') {
      assert.equal(h.project.snapshot.config.data.android.uploadCertificateSha256, undefined);
      assert.equal(h.state.signing.selection, null); assert.ok(h.controller.prepareReason());
      await h.controller.prepare(); assert.equal(h.calls.length, 0);
    }
    assert.equal(h.controller.inspectToolSourcesReason(), null, mode);
    const inspecting = h.controller.inspectToolSources(), inspect = h.registrationCalls[0];
    assert.equal(inspect?.kind, 'inspect', mode + ': inspection must actually reach the adapter');
    assert.equal(Object.hasOwn(inspect.input.context, 'signing'), false);
    assert.deepEqual(inspect.input.context.artifactValidation, mode === 'unsigned-upload-signature'
      ? { mode: 'upload-signature', uploadCertificateSha256: 'Ab'.repeat(32) }
      : { mode: 'structure-and-version', uploadCertificateSha256: null });
    const op = { operationId: OP, registrationGeneration: 1, sourceGeneration: 1,
      kind: 'inspection', context: clone(inspect.input.context) };
    const review = { schemaVersion: 1, statusRevision: 1, registrationGeneration: 1,
      availability: 'available', prerequisite: 'ready', phase: 'review', reason: 'none', operation: op,
      review: { reviewId: OTHER, sourceGeneration: 1, context: clone(inspect.input.context),
        consentVersion: ANDROID_TOOL_REGISTRATION_CONSENT, licenseAcknowledgmentRequired: true,
        sources: ['jdk', 'sdk', 'gradle'].map(role => ({ role, version: '17.0.1', logicalBytes: 1,
          files: 1, entries: 1, aliases: 0, complete: true, compatibility: 'compatible' })) }, report: null };
    h.replyRegistration(inspect, review); await inspecting;
    assert.equal(h.state.registrationConsent?.acknowledged, false, mode + ': finalized review must remain usable');
    assert.ok(h.controller.registerToolSourcesReason());
    await h.controller.registerToolSources(OP, 1, OTHER); assert.equal(h.registrationCalls.length, 1);
    h.controller.setRegistrationAcknowledged(OP, 1, OTHER, true);
    assert.equal(h.controller.registerToolSourcesReason(), null);
    const registering = h.controller.registerToolSources(OP, 1, OTHER), copy = h.registrationCalls[1];
    assert.equal(copy?.kind, 'register'); assert.deepEqual(copy.input.context, inspect.input.context);
    assert.equal(copy.input.consentVersion, ANDROID_TOOL_REGISTRATION_CONSENT);
    assert.equal(copy.input.licenseAcknowledged, true); assert.equal(copy.input.reviewId, OTHER);
    assert.equal(h.state.registrationConsent, null);
    // Settle the fake adapter with a refusal, not a fictitious protected copy.
    h.replyRegistration(copy, { ...review, statusRevision: 2, registrationGeneration: 2,
      phase: 'refused', reason: 'registration-refused', review: null,
      operation: { ...op, operationId: OWNER, registrationGeneration: 2, kind: 'registration' } });
    await registering;
    assert.equal(h.state.integrityFailed, false); assert.equal(h.state.registrationPending, null);
    assert.equal(h.state.toolRegistration.phase, 'refused'); assert.equal(h.state.registrationConsent, null);
    if (mode === 'signed') { assert.ok(h.controller.prepareReason()); await h.controller.prepare(); }
    assert.equal(h.calls.length, 0); assert.equal(h.serviceCalls.length, 0);
    h.controller.dispose();
    assert.ok(h.registrationSubscriptions.every(row => row.closed));
  }
});
