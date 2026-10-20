// Closed comparison DATA and original controlled-promise controller checks.
// No native grant, tool, process, filesystem, credential or build is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AGENT_ANDROID_BUILD_CONSENT, AgentAndroidBuildPermission, copyAndroidBuildApproval,
  createAgentAndroidBuildApi, encodeAndroidBuildAccessRequest, parseAndroidBuildAccess } from '../src/agentAndroidBuild.ts';
import { canObserveAgentAndroidBuild } from '../src/agentAndroidBuildOrigin.ts';
import { AndroidBuildController } from '../src/androidBuild.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { androidBuildOperationProgress, copyAndroidBuildRequest, parseAndroidBuildStatus } from '../src/androidBuildProtocol.ts';
import { parseAndroidToolchainCatalogStatus } from '../src/androidToolchainCatalogProtocol.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';

const id = (c) => c.repeat(32), clone = structuredClone;
const ORIGIN = { serviceInstance: id('a'), projectId: id('b'), requestId: id('c') };
const CONFIG = { bytes: 512, sha256: 'd'.repeat(64) };
const VERSION = { source: 'release/version.properties', bytes: 41, sha256: 'f'.repeat(64), name: '1.2.3', build: 42 };
const TOOLS = { instance: id('1'), ownerUid: 501, catalogGeneration: 1,
  recordSha256: '2'.repeat(64), inventorySha256: '3'.repeat(64), osProviderSha256: '4'.repeat(64) };
const approval = () => ({ input: { projectId: 'p1', draftRevision: 0, baselineGeneration: 1, savedConfig: clone(CONFIG),
  savedVersion: clone(VERSION), artifactValidation: { mode: 'structure-and-version', uploadCertificateSha256: null } }, toolchainSelection: clone(TOOLS) });
const enabled = () => ({ enabled: true, remainingMs: 900_000, projectId: ORIGIN.projectId, observationRevision: 7, consumed: false });
const disabled = () => ({ enabled: false, remainingMs: 0, projectId: null, observationRevision: null, consumed: false });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 18; n++) await Promise.resolve(); };
function port() {
  const calls = [];
  const api = Object.fromEntries(['allow', 'status', 'revoke'].map((kind) => [kind, (value) => {
    const call = { kind, value, ...deferred() }; calls.push(call); return call.promise;
  }]));
  return { api, calls };
}
function permission(p = port()) { const controller = new AgentAndroidBuildPermission(); controller.bind(p.api, approval()); return { ...p, controller }; }
const status = (revision = 0, operation = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation });
const operation = (patch = {}, input = approval().input) => ({ operationId: id('d'), ownerGeneration: id('e'),
  context: { ...clone(input), platform: 'android', operation: 'android-build-inspect' },
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null,
  agentAndroidBuild: clone(ORIGIN), ...patch });
const terminal = (patch = {}) => operation({ phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', ...patch });
const unmarked = (op) => { const result = clone(op); delete result.agentAndroidBuild; return result; };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function snapshot() {
  return { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(CONFIG), issues: [],
      data: { android: { enabled: true, module: ':app', applicationId: 'org.example.app', variant: 'release' },
        version: { source: VERSION.source, nameKey: 'NAME', buildKey: 'BUILD' } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(assurance), issues: [] };
}
function workspace() {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'DATA Android project', path: '/inert/never-forwarded' } });
  value = workspaceReducer(value, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  return workspaceReducer(value, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot: snapshot(), observedAt: 1 });
}
function catalog() {
  const result = { schemaVersion: 1, statusRevision: 1, catalogGeneration: 1, operationId: id('7'), availability: 'available',
    phase: 'ready', reason: 'none', selected: clone(TOOLS), entries: [{ instance: TOOLS.instance, occupants: 1,
      status: 'verified-this-session', recovery: null, selection: clone(TOOLS),
      versions: { jdkVendor: 'Example', jdkVersion: '17.0.12', gradleVersion: '8.10', agpVersion: '8.7', sdkPlatform: 'android-35', sdkBuildToolsVersion: '35.0.0' } }] };
  assert.ok(parseAndroidToolchainCatalogStatus(result)); return result;
}
async function nativeView(t, initial = status()) {
  let state = workspace(), current = clone(initial), listener, catalogListener; const calls = [], versionCalls = [];
  const selected = () => state.projects.p1;
  const version = new ReleaseVersionController(selected);
  version.setConnection({ mode: 'native', observeReleaseVersion: () => { const call = deferred(); versionCalls.push(call); return call.promise; } },
    { runtime: { state: 'available', mode: 'development', reason: null }, capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject();
  const api = { mode: 'native',
    subscribeAndroidBuild: async (fn) => { listener = fn; return () => { listener = null; }; },
    androidBuildStatus: async () => clone(current),
    subscribeAndroidToolchainCatalog: async (fn) => { catalogListener = fn; return () => { catalogListener = null; }; },
    androidToolchainCatalogStatus: async () => catalog(),
    prepareAndroidBuild: (input) => { const call = { kind: 'prepare', input, ...deferred() }; calls.push(call); return call.promise; },
    startAndroidBuild: (input) => { const call = { kind: 'start', input, ...deferred() }; calls.push(call); return call.promise; },
    cancelAndroidBuild: (operationId, ownerGeneration) => { calls.push({ kind: 'cancel', operationId, ownerGeneration });
      current = status(current.statusRevision + 1, { ...current.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' });
      return Promise.resolve(clone(current)); },
  };
  const controller = new AndroidBuildController({ selectedProject: selected, releaseVersion: () => version.getSnapshot(), otherOperationReason: () => null, now: () => 100 });
  const unsubscribeVersion = version.subscribe(controller.syncReleaseVersion);
  controller.syncProject(); controller.setVisible(true); await controller.connect(api);
  controller.versionIntent(); const reading = version.read(); assert.equal(versionCalls.length, 1);
  versionCalls[0].resolve({ schemaVersion: 2, source: VERSION.source, version: { name: VERSION.name, build: VERSION.build },
    savedConfig: clone(CONFIG), savedVersion: { bytes: VERSION.bytes, sha256: VERSION.sha256 },
    observationScope: 'single-request-non-atomic', assurance: clone(assurance) }); await reading;
  t.after(() => { unsubscribeVersion(); controller.dispose(); version.dispose(); });
  return { controller, calls, get project() { return selected(); },
    emit(value) { assert.ok(parseAndroidBuildStatus(value)); current = clone(value); listener?.(clone(value)); },
    reply(call, value) { assert.ok(parseAndroidBuildStatus(value)); current = clone(value); call.resolve(clone(value)); },
    emitCatalog(value) { catalogListener?.(clone(value)); },
    dispatch(action) { controller.beforeWorkspaceAction(action); version.beforeWorkspaceAction(action);
      state = workspaceReducer(state, action); version.syncProject(); controller.syncProject(); } };
}

test('exact saved pair and full catalog selection enter only the three named permission commands', async () => {
  const calls = [], api = createAgentAndroidBuildApi('native', async (command, raw) => {
    assert.ok(raw instanceof Uint8Array && raw.length <= 4096);
    calls.push({ command, value: JSON.parse(new TextDecoder().decode(raw)) }); return disabled();
  });
  await api.allow(approval()); await api.status(); await api.revoke();
  assert.deepEqual(calls.map((c) => c.command), ['allow_agent_android_build', 'agent_android_build_access', 'revoke_agent_android_build']);
  assert.deepEqual(calls[0].value, { ...approval(), consentVersion: AGENT_ANDROID_BUILD_CONSENT });
  for (const extra of ['root', 'command', 'window', 'operationId', 'executable', 'environment'])
    assert.equal(encodeAndroidBuildAccessRequest('allow_agent_android_build', { ...calls[0].value, [extra]: 'not-authority' }), null);
  assert.equal(encodeAndroidBuildAccessRequest('shell', {}), null);
  assert.equal(createAgentAndroidBuildApi('preview', () => assert.fail('no fallback')), null);
});

test('signing, candidate retention and signature inspection cannot use the build-inspect START permission', () => {
  for (const change of [
    (a) => { a.input.signing = { mode: 'local-upload-key', assignments: [] }; },
    (a) => { a.input.operation = 'android-candidate-inputs'; a.input.action = 'create'; },
    (a) => { a.input.artifactValidation = { mode: 'upload-signature', uploadCertificateSha256: 'a'.repeat(64) }; },
    (a) => { delete a.toolchainSelection.osProviderSha256; },
    (a) => { a.toolchainSelection.path = '/never-authority'; },
    (a) => { a.input.savedVersion.bytes = 65537; },
  ]) { const a = approval(); change(a); assert.equal(copyAndroidBuildApproval(a), null); }
  const a = approval(), safe = copyAndroidBuildApproval(a); assert.ok(safe); a.input.savedVersion.name = 'changed';
  assert.equal(safe.input.savedVersion.name, VERSION.name); assert.ok(Object.isFrozen(safe.input.savedVersion));
  assert.ok(Object.isFrozen(safe.toolchainSelection));
});

test('approval copy is bounded and never calls getters or serialization hooks', async () => {
  let reads = 0, invocations = 0;
  const a = approval(); Object.defineProperty(a.input, 'savedConfig', { enumerable: true, get() { reads++; return CONFIG; } });
  const api = createAgentAndroidBuildApi('native', async () => { invocations++; return disabled(); });
  await assert.rejects(api.allow(a)); assert.equal(reads, 0); assert.equal(invocations, 0);
  const b = approval(); b.toJSON = () => { reads++; return approval(); }; assert.equal(copyAndroidBuildApproval(b), null);
  assert.equal(parseAndroidBuildAccess({ ...enabled(), get consumed() { reads++; return false; } }), null);
  assert.equal(reads, 0);
});

test('permission observations cannot disguise consumed, overlong or unbound grants as enabled', () => {
  const raw = enabled(), copied = parseAndroidBuildAccess(raw); raw.remainingMs = 0;
  assert.equal(copied.remainingMs, 900_000); assert.ok(Object.isFrozen(copied));
  for (const extra of [{ remainingMs: 900_001 }, { consumed: true }, { observationRevision: 0 }, { projectId: id('0') }, { enabled: false }, { remainingMs: -0 }])
    assert.equal(parseAndroidBuildAccess({ ...enabled(), ...extra }), null);
  assert.ok(parseAndroidBuildAccess({ ...enabled(), enabled: false, remainingMs: 0, consumed: true }));
});

test('Allow samples current saved version, catalog and busy state before dispatch', async () => {
  const p = port(); let current = { api: p.api, project: approval(), blocked: false };
  const c = new AgentAndroidBuildPermission(() => current); c.syncContext(); c.acknowledge(true);
  current = { ...current, project: approval() }; current.project.input.savedVersion.build++;
  await c.allow(); assert.equal(p.calls.length, 0); assert.equal(c.getState().acknowledged, false);
  c.acknowledge(true); current.project.toolchainSelection.catalogGeneration++;
  await c.allow(); assert.equal(p.calls.length, 0);
  c.acknowledge(true); current = { ...current, blocked: true }; await c.allow(); assert.equal(p.calls.length, 0);
  current = { ...current, blocked: false }; const work = c.allow(); assert.deepEqual(clone(p.calls[0].value), current.project);
  p.calls[0].resolve(enabled()); await work;
});

test('reentrant Revoke before native Allow invocation cannot recreate permission', async () => {
  const p = permission(); let revoked = false, revoking;
  const unsubscribe = p.controller.subscribe((state) => {
    if (state.pending === 'allow' && !revoked) { revoked = true; revoking = p.controller.revoke(); }
  });
  p.controller.acknowledge(true); const allowing = p.controller.allow();
  assert.deepEqual(p.calls.map((call) => call.kind), ['revoke']);
  p.calls[0].resolve(disabled()); await revoking; await allowing; unsubscribe();
  assert.deepEqual(p.calls.map((call) => call.kind), ['revoke']); assert.equal(p.controller.getState().access.enabled, false);
});

test('status-only reconnect retains its original API until actual Revoke even after rebinding', async () => {
  const p = permission(), next = port(); const reading = p.controller.status();
  p.controller.bind(next.api, approval()); p.calls[0].resolve(enabled()); await reading;
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(next.calls.length, 0);
  const revoking = p.controller.revoke(); assert.deepEqual(p.calls.map((c) => c.kind), ['status', 'revoke']);
  p.calls[1].resolve(disabled()); await revoking;
  p.controller.acknowledge(true); const allowing = p.controller.allow(); assert.equal(next.calls[0].kind, 'allow');
  next.calls[0].resolve(enabled()); await allowing;
});

test('lost Allow ACK and changed inputs remain uncertain; status DATA cannot clear that uncertainty', async () => {
  const p = permission(); p.controller.acknowledge(true); const allowing = p.controller.allow();
  p.calls[0].reject(new Error('sensitive-not-rendered')); await allowing;
  const reading = p.controller.status(); p.calls[1].resolve(disabled()); await reading;
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(p.calls.length, 2); assert.equal(p.controller.getState().uncertain, true);
  assert.ok(!JSON.stringify(p.controller.getState()).includes('sensitive-not-rendered'));
  const revoking = p.controller.revoke(); p.calls[2].resolve(disabled()); await revoking;
  p.controller.acknowledge(true); const again = p.controller.allow(); const changed = approval(); changed.input.savedVersion.build++;
  p.controller.bind(p.api, changed); p.calls[3].resolve(enabled()); await again;
  assert.equal(p.controller.getState().uncertain, true);
});

test('saturated UI epoch still revokes original permission and suppresses its late Allow ACK', async () => {
  const p = permission(); p.controller.acknowledge(true); const allowing = p.controller.allow();
  p.controller.epoch = Number.MAX_SAFE_INTEGER; const revoking = p.controller.revoke();
  p.calls[1].resolve(disabled()); await revoking; p.calls[0].resolve(enabled()); await allowing;
  assert.equal(p.controller.getState().access.enabled, false); p.controller.acknowledge(true); await p.controller.allow(); assert.equal(p.calls.length, 2);
});

test('native origin is closed inspect-only DATA and cannot enter GUI Prepare or mutate a same-ID observation', () => {
  const a = operation(), b = operation({ phase: 'running', intentUsable: false, stage: 'building' });
  assert.ok(parseAndroidBuildStatus(status(1, a))); assert.ok(androidBuildOperationProgress(a, b));
  assert.equal(androidBuildOperationProgress(a, unmarked(b)), false);
  for (const change of [
    (v) => { v.agentAndroidBuild.requestId = id('0'); }, (v) => { v.agentAndroidBuild.window = 'main'; },
    (v) => { v.agentAndroidBuild = null; },
    (v) => { v.context.artifactValidation = { mode: 'upload-signature', uploadCertificateSha256: 'a'.repeat(64) }; },
    (v) => { v.context.operation = 'android-build-sign'; },
  ]) { const bad = operation(); change(bad); assert.equal(parseAndroidBuildStatus(status(1, bad)), null); }
  assert.equal(copyAndroidBuildRequest('prepare_android_build', { ...approval().input, agentAndroidBuild: ORIGIN }), null);
});

test('same saved reader/catalog controller supplies preapproval and invalidates it on selection drift', async (t) => {
  const h = await nativeView(t); const a = h.controller.agentBuildApproval(); assert.ok(a, h.controller.prepareReason());
  assert.deepEqual(clone(a.input.savedConfig), CONFIG); assert.deepEqual(clone(a.input.savedVersion), VERSION); assert.deepEqual(a.toolchainSelection, TOOLS);
  const cleared = catalog(); cleared.statusRevision++; cleared.selected = null;
  assert.ok(parseAndroidToolchainCatalogStatus(cleared)); h.emitCatalog(cleared);
  assert.equal(h.controller.agentBuildApproval(), null); assert.equal(h.calls.length, 0);
});

test('CLI Prepared adopts observe/STOP only after prior native terminal; GUI never fabricates Start consent', async (t) => {
  const old = unmarked(terminal({ operationId: id('1'), ownerGeneration: id('2') }));
  const h = await nativeView(t, status(2, old)); h.emit(status(3, operation()));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  assert.deepEqual({ ...h.controller.getSnapshot().status.operation.agentAndroidBuild }, ORIGIN);
  assert.equal(h.controller.getSnapshot().consent, null); assert.equal(h.controller.getSnapshot().historical, true);
  await h.controller.start(id('d'), id('e')); assert.equal(h.calls.length, 0);
  assert.equal(h.controller.cancel(), true); await flush();
  assert.deepEqual(h.calls, [{ kind: 'cancel', operationId: id('d'), ownerGeneration: id('e') }]);
  assert.equal(h.controller.getSnapshot().status.operation.phase, 'terminal');
});

test('active or unknown native originals and unmarked foreign IDs cannot be replaced by CLI DATA', async (t) => {
  for (const old of [operation({ operationId: id('1'), ownerGeneration: id('2'), phase: 'running', intentUsable: false }),
    operation({ operationId: id('1'), ownerGeneration: id('2'), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' })]) {
    assert.equal(canObserveAgentAndroidBuild(status(2, old), status(3, operation()), false), false);
    const h = await nativeView(t, status(2, old)); h.emit(status(3, operation()));
    assert.equal(h.controller.getSnapshot().integrityFailed, true); assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  }
  const h = await nativeView(t, status(2, unmarked(terminal({ operationId: id('1'), ownerGeneration: id('2') }))));
  h.emit(status(3, unmarked(operation()))); assert.equal(h.controller.getSnapshot().integrityFailed, true);
});

test('pending GUI Prepare defers CLI display until the actual pre-admission refusal returns', async (t) => {
  const h = await nativeView(t, status(2, unmarked(terminal({ operationId: id('1'), ownerGeneration: id('2') }))));
  const preparing = h.controller.prepare(); assert.equal(h.calls[0].kind, 'prepare');
  h.emit(status(3, operation())); assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  h.calls[0].reject({ code: 'android_build_busy' }); await preparing;
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('d'));
  assert.equal(h.controller.getSnapshot().consent, null); assert.equal(h.calls.length, 1);
});

test('actual GUI Start return is retained after terminal before a CLI request may take display', async (t) => {
  const h = await nativeView(t); const preparing = h.controller.prepare(), call = h.calls[0];
  const gui = unmarked(operation({ operationId: id('1'), ownerGeneration: id('2') }, call.input));
  h.reply(call, status(1, gui)); await preparing;
  h.controller.setAcknowledged(id('1'), id('2'), true); const starting = h.controller.start(id('1'), id('2')); assert.equal(h.calls[1].kind, 'start');
  h.emit(status(3, { ...gui, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' }));
  h.emit(status(4, operation())); assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  h.calls[1].resolve(status(2, { ...gui, phase: 'starting', intentUsable: false })); await starting;
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('d')); assert.equal(h.controller.getSnapshot().integrityFailed, false);
  await h.controller.start(id('d'), id('e')); assert.equal(h.calls.length, 2);
});
