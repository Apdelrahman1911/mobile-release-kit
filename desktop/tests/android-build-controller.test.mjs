// Inert controlled-promise/controller/bridge and source-contract tests only.
// Authored, not executed during staging. All saved bytes, digests, native states
// and command observations are invented DATA, not process/tool/file custody or
// qualification. Real ReleaseVersionController is used with a fake passive API.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { AndroidBuildController, androidBuildOwnerReason, androidBuildHelp, androidBuildInputHelp, androidBuildOutputHelp, androidBuildCancelHelp } from '../src/androidBuild.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { ANDROID_BUILD_CONSENT, ANDROID_BUILD_CORE_STATUSES, ANDROID_BUILD_EVENT, ANDROID_BUILD_LIMITATIONS,
  ANDROID_BUILD_SCOPE, ANDROID_BUILD_TOOLCHAIN_PROFILE } from '../src/androidBuildProtocol.ts';

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
function snapshot({ config = CONFIG, module = ':app', applicationId = 'org.example.app', source = 'release/version.properties', variant = 'release' } = {}) {
  return { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(config), issues: [],
      data: { android: { enabled: true, module, applicationId, variant }, version: { source, nameKey: 'NAME', buildKey: 'BUILD' } } },
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
const context = (request) => ({ ...clone(request), platform: 'android', operation: 'android-build-inspect' });
const operation = (input, patch = {}) => ({ operationId: OP, ownerGeneration: OWNER, context: context(input), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null, ...patch });
const status = (revision = 0, op = null, availability = 'available') => ({ schemaVersion: 1, statusRevision: revision, availability, operation: op });
const running = (op, stage = 'building') => ({ ...clone(op), phase: 'running', intentUsable: false, stage });
const terminal = (op, outcome = 'cancelled', reason = outcome) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome, reason });
function completed(op, selection = { module: ':app', variant: 'release', applicationId: 'org.example.app', task: ':app:bundleRelease' }) {
  const findings = [{ ordinal: 0, check: 'aab-structure', status: 'FAIL' }];
  const summary = { total: 1, shown: 1, omitted: 0, counts: Object.fromEntries(ANDROID_BUILD_CORE_STATUSES.map((key) => [key, key === 'FAIL' ? 1 : 0])) };
  const command = { outcome: 'exited', exitCode: 0 };
  const result = { schemaVersion: 1, scope: ANDROID_BUILD_SCOPE, usedConfig: clone(op.context.savedConfig), usedVersion: clone(op.context.savedVersion),
    selection: clone(selection), toolchainProfile: ANDROID_BUILD_TOOLCHAIN_PROFILE, command: clone(command), findings: clone(findings), summary: clone(summary),
    artifacts: [{ logicalName: 'android-aab', platform: 'android', kind: 'aab', fileName: 'app-release.aab', size: 1024, sha256: '0'.repeat(64),
      architectures: ['arm64-v8a'], unknownAbi: false, freshness: 'not-established' }],
    assurances: { structure: 'failed', nativeManifest: 'not-checked', applicationVersion: 'not-established', signer: 'not-inspected',
      toolkitSigning: 'not-requested', storeOperation: 'not-requested', sourceBinding: 'not-established', releaseReadiness: 'not-assessed' }, limitations: [...ANDROID_BUILD_LIMITATIONS] };
  return { ...terminal(op, 'complete', 'none'), stage: 'disposing-work', activity: { stage: 'disposing-work', selection, command, findings, summary },
    disposition: { work: 'removed', artifacts: 'retained-local-result' }, result };
}
function harness(t, { initial = status(), listenGate = null, completeVersion = true } = {}) {
  let state = workspace(), registry = clone(initial), clock = 10, other = null, versionOverride;
  const calls = [], reads = [], subscriptions = [], versionCalls = [], order = [];
  const selected = () => state.selectedId ? state.projects[state.selectedId] : null;
  const version = new ReleaseVersionController(selected);
  version.setConnection({ mode: 'native', observeReleaseVersion: (projectId) => {
    const call = { projectId, ...deferred() }; versionCalls.push(call); return call.promise;
  } }, info); version.syncProject();
  const api = { mode: 'native',
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
  const controller = new AndroidBuildController({ selectedProject: selected,
    releaseVersion: () => versionOverride === undefined ? version.getSnapshot() : versionOverride,
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
  assert.deepEqual(Object.keys(h.calls[0].input).sort(), ['baselineGeneration', 'draftRevision', 'projectId', 'savedConfig', 'savedVersion']);
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
    savedVersion: { ...VERSION, source: 'release/version.properties', name: '1.2.3', build: 42 } };
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

test('component shares native-terminal-only output with Artifacts and provides real input/output/cancel help, not a file action', () => {
  const source = readFileSync(new URL('../src/components/AndroidBuild.tsx', import.meta.url), 'utf8');
  assert.match(source, /export function AndroidBuildResultView/);
  assert.match(source, /state\.mode !== 'native' \|\| op\?\.phase !== 'terminal' \|\| op\.outcome !== 'complete'/);
  assert.match(source, /<AndroidBuildResultView state=\{state\}/);
  assert.match(source, /if \(compact && !owned\) return null/); assert.match(source, /controller\.canCancel\(\)/);
  assert.match(source, /controller\.versionIntent\(\); onReadVersion\(\)/);
  assert.match(source, /post-run bytes may be reused\/stale/); assert.match(source, /signer is not inspected/);
  assert.doesNotMatch(source, /(?:window\.open|href=|download=|controller\.dispose\()/);
  for (const help of [androidBuildHelp, androidBuildInputHelp, androidBuildOutputHelp, androidBuildCancelHelp]) {
    for (const key of ['label', 'what', 'why', 'where', 'format', 'failure', 'requiredWhen']) assert.ok(help[key].length > 12, `${help.label}.${key}`);
  }
  assert.match(androidBuildInputHelp.what, /observe-v2/); assert.match(androidBuildOutputHelp.failure, /Complete may contain FAIL/);
  assert.match(androidBuildCancelHelp.failure, /Unknown cleanup is sticky/);
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
