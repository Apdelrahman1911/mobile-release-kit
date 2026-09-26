// Inert renderer DATA/controllers and fixed bridge requests only. Invented
// statuses never prove Xcode execution, file custody, native finality or gate
// qualification. No process, network or native picker is started here.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { IOSArchiveController, iosArchiveOwnerReason, iosArchiveHelp, iosArchiveInputHelp,
  iosArchiveSelectionHelp, iosArchiveOutputHelp, iosArchiveCancelHelp } from '../src/iosArchive.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { IOS_ARCHIVE_CONSENT, IOS_ARCHIVE_COUNTER_MAX, IOS_ARCHIVE_EVENT, IOS_ARCHIVE_LIMITATIONS, IOS_ARCHIVE_SCOPE,
  copyIOSArchiveRequest, encodeIOSArchiveRequest, parseIOSArchiveStatus, iosArchiveOperationProgress, iosArchiveError } from '../src/iosArchiveProtocol.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), OTHER = 'c'.repeat(32);
const CONFIG = { bytes: 512, sha256: 'd'.repeat(64) }, NEW_CONFIG = { bytes: 524, sha256: 'e'.repeat(64) };
const VERSION = { bytes: 41, sha256: 'f'.repeat(64) };
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
function workspace() {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert iOS project', path: '/inert/never-forwarded' } });
  value = workspaceReducer(value, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  return workspaceReducer(value, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot: snapshot(), observedAt: 1 });
}
function observation(project, patch = {}) {
  return { schemaVersion: 2, source: project.snapshot.config.data.version.source, version: { name: '1.2.3', build: 42 },
    savedConfig: clone(project.savedConfigContent), savedVersion: clone(VERSION), observationScope: 'single-request-non-atomic', assurance: clone(assurance), ...patch };
}
const request = () => ({ projectId: 'p1', draftRevision: 2, baselineGeneration: 3, savedConfig: clone(CONFIG),
  savedVersion: { ...VERSION, source: 'release/version.properties', name: '1.2.3', build: 42 } });
const context = (input) => ({ ...clone(input), platform: 'ios', operation: 'ios-unsigned-archive' });
const operation = (input = request(), patch = {}) => ({ operationId: OP, ownerGeneration: OWNER, context: context(input), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null, ...patch });
const status = (revision = 0, op = null, availability = 'available') => ({ schemaVersion: 1, statusRevision: revision, availability, operation: op });
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
function harness(t, { initial = status(), listenGate = null, completeVersion = true } = {}) {
  let state = workspace(), registry = clone(initial), clock = 10, other = null, versionOverride;
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

test('four raw requests stay closed and domain-local; no tools, signing or deadline may be supplied', () => {
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
    'iosArchive.setSelectionPending(true)', 'iosArchive.setSelectionPending(false)', '<IOSArchiveResultView', '<IOSArchive state={iosArchiveState}'])
    assert.ok(app.includes(literal), literal);
  assert.match(app, /preflightBusy\(\) \?\? androidBusy\(\) \?\? iosBusy\(\)/);
  const component = readFileSync(new URL('../src/components/IOSArchive.tsx', import.meta.url), 'utf8');
  for (const action of ['observe-version', 'review', 'acknowledge', 'start', 'cancel'])
    assert.ok(component.includes(`data-mrk-ios-archive-action="${action}"`));
  for (const help of [iosArchiveHelp, iosArchiveInputHelp, iosArchiveSelectionHelp, iosArchiveOutputHelp, iosArchiveCancelHelp])
    for (const field of ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure']) assert.ok(help[field]?.length, `${help.label}: ${field}`);
});
