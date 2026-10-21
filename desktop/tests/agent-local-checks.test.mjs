// Closed DATA and original-Promise/controller tests. No native grant, source
// read, project code, child process, service filesystem or credential is used.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AGENT_LOCAL_CHECK_CONSENT, AgentLocalCheckPermission, createAgentLocalCheckApi,
  encodeLocalCheckAccessRequest, parseLocalCheckAccess, parseMainLocalCheckAccess } from '../src/agentLocalChecks.ts';
import { canObserveAgentLocalCheck } from '../src/agentLocalCheckOrigin.ts';
import { OfflinePreflightController } from '../src/offlinePreflight.ts';
import { OFFLINE_LIMITATIONS, OFFLINE_CORE_STATUSES, offlineOperationProgress, parseOfflinePreflightStatus,
  copyOfflinePreflightRequest } from '../src/offlinePreflightProtocol.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';

const id = (c) => c.repeat(32), clone = structuredClone;
const ORIGIN = { serviceInstance: id('a'), projectId: id('b'), requestId: id('c') };
const PROJECT = { projectId: 'project-1', draftRevision: 4, baselineGeneration: 3 };
const CONFIG = { bytes: 42, sha256: 'f'.repeat(64) };
const enabled = () => ({ enabled: true, remainingMs: 900_000, projectId: ORIGIN.projectId, observationRevision: 7, consumed: false });
const disabled = () => ({ enabled: false, remainingMs: 0, projectId: null, observationRevision: null, consumed: false });
const mainEnabled = (permissionRevision = '8') => ({ ...enabled(), permissionRevision });
const mainDisabled = (permissionRevision = '7') => ({ ...disabled(), permissionRevision });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 18; n++) await Promise.resolve(); };
function port() {
  const calls = [];
  const api = Object.fromEntries(['allow', 'status', 'revoke'].map((kind) => [kind, (value, expectedPermissionRevision) => {
    const call = { kind, value, expectedPermissionRevision, ...deferred() }; calls.push(call); return call.promise;
  }]));
  return { api, calls };
}
function permission(p = port()) {
  const controller = new AgentLocalCheckPermission(); controller.bind(p.api, PROJECT); return { ...p, controller };
}
async function check(p, revision = '7', controller = p.controller) {
  const index = p.calls.length, reading = controller.status();
  assert.equal(p.calls.length, index + 1); assert.equal(p.calls[index].kind, 'status');
  p.calls[index].resolve(mainDisabled(revision)); await reading;
}
function context(operation = 'local-project-checks') { return { ...PROJECT, savedConfig: clone(CONFIG), platform: 'android', operation }; }
function operation(patch = {}) { return { operationId: id('d'), ownerGeneration: id('e'), context: context(), phase: 'starting',
  intentUsable: false, outcome: null, reason: 'none', result: null, agentLocalCheck: clone(ORIGIN), ...patch }; }
function status(revision = 0, op = null) { return { schemaVersion: 1, statusRevision: revision, availability: 'available', operation: op }; }
function terminal(patch = {}) { return operation({ phase: 'terminal', outcome: 'cancelled', reason: 'cancelled', ...patch }); }
function workspace() {
  let state = workspaceReducer(initialWorkspace, { type: 'select', project: { id: PROJECT.projectId, name: 'DATA project', path: '/never-opened' } });
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: PROJECT.projectId, requestId: 1 });
  return workspaceReducer(state, { type: 'snapshot-done', projectId: PROJECT.projectId, requestId: 1, observedAt: 1,
    snapshot: { root: '/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
      config: { path: 'release/mobile-release.json', state: 'format-valid', data: { android: { enabled: true } }, content: clone(CONFIG), issues: [] },
      discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
      assurance: { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
        gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' }, issues: [] } });
}
async function nativeView(t, initial = status()) {
  let current = clone(initial), listener; const calls = [], state = workspace();
  const api = { mode: 'native',
    subscribeOfflinePreflight: async (fn) => { listener = fn; return () => { listener = null; }; },
    offlinePreflightStatus: async () => clone(current),
    prepareOfflinePreflight: (input) => { const call = { kind: 'prepare', input, ...deferred() }; calls.push(call); return call.promise; },
    startOfflinePreflight: (input) => { const call = { kind: 'start', input, ...deferred() }; calls.push(call); return call.promise; },
    cancelOfflinePreflight: (operationId, ownerGeneration) => { calls.push({ kind: 'cancel', operationId, ownerGeneration });
      current = status(current.statusRevision + 1, { ...current.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null });
      return Promise.resolve(clone(current)); },
  };
  const controller = new OfflinePreflightController({ selectedProject: () => state.projects[PROJECT.projectId], otherOperationReason: () => null, now: () => 100 });
  controller.syncProject(); controller.setVisible(true); await controller.connect(api);
  t.after(() => controller.dispose());
  return { controller, calls, emit(value) { current = clone(value); listener?.(clone(value)); },
    reply(call, value) { current = clone(value); call.resolve(clone(value)); } };
}

test('three named RAW permission commands do not accept paths, execution payloads or preview fallback', async () => {
  const calls = [];
  const api = createAgentLocalCheckApi('native', async (command, raw) => {
    assert.ok(raw instanceof Uint8Array && raw.length < 1024);
    calls.push({ command, value: JSON.parse(new TextDecoder().decode(raw)) }); return mainDisabled();
  });
  await api.allow(PROJECT, '7'); await api.status(); await api.revoke();
  assert.deepEqual(calls.map((c) => c.command), ['allow_agent_local_check', 'agent_local_check_access', 'revoke_agent_local_check']);
  assert.deepEqual(calls[0].value, { ...PROJECT, consentVersion: AGENT_LOCAL_CHECK_CONSENT, expectedPermissionRevision: '7' });
  await assert.rejects(api.allow(PROJECT)); assert.equal(calls.length, 3);
  for (const field of ['root', 'command', 'operationId', 'window', 'savedConfig', 'executable']) {
    assert.equal(encodeLocalCheckAccessRequest('allow_agent_local_check', { ...calls[0].value, [field]: 'not-authority' }), null);
  }
  assert.equal(encodeLocalCheckAccessRequest('shell', {}), null);
  assert.equal(createAgentLocalCheckApi('preview', () => assert.fail('no fallback')), null);
});

test('permission request and response copies never evaluate getters or serialization hooks', async () => {
  let reads = 0, invocations = 0;
  const getter = { get projectId() { reads++; return PROJECT.projectId; }, draftRevision: 4, baselineGeneration: 3 };
  const api = createAgentLocalCheckApi('native', async () => { invocations++; return mainDisabled(); });
  await assert.rejects(api.allow(getter, '7'));
  const c = new AgentLocalCheckPermission(); c.bind(api, getter); c.acknowledge(true); await c.allow();
  assert.equal(parseLocalCheckAccess({ ...enabled(), get consumed() { reads++; return false; } }), null);
  assert.equal(parseMainLocalCheckAccess({ ...mainEnabled(), get permissionRevision() { reads++; return '7'; } }), null);
  assert.equal(reads, 0); assert.equal(invocations, 0);
});

test('permission observations are bounded, immutable and cannot disguise consumed or stale leases as enabled', () => {
  const raw = enabled(), copied = parseLocalCheckAccess(raw); raw.remainingMs = 0;
  assert.equal(copied.remainingMs, 900_000); assert.ok(Object.isFrozen(copied));
  for (const extra of [{ remainingMs: 900_001 }, { remainingMs: -0 }, { consumed: true }, { projectId: id('0') },
    { observationRevision: 0 }, { observationRevision: Number.MAX_SAFE_INTEGER + 1 }, { enabled: false }, { root: '/not-authority' }]) {
    assert.equal(parseLocalCheckAccess({ ...enabled(), ...extra }), null);
  }
  const consumed = parseLocalCheckAccess({ ...enabled(), enabled: false, remainingMs: 0, consumed: true });
  assert.ok(consumed?.consumed); assert.equal(consumed.enabled, false);
});

test('Allow samples event-time scope and busy state, not a stale rendered checkbox', async () => {
  const p = port(); let current = { api: p.api, project: PROJECT, blocked: false };
  const c = new AgentLocalCheckPermission(() => current); c.syncContext(); await check(p, '7', c); c.acknowledge(true);
  current = { ...current, project: { ...PROJECT, draftRevision: 5 } };
  await c.allow(); assert.equal(p.calls.length, 1); assert.equal(c.getState().acknowledged, false);
  await check(p, '9', c); c.acknowledge(true); current = { ...current, blocked: true }; await c.allow(); assert.equal(p.calls.length, 2);
  current = { ...current, blocked: false }; const work = c.allow();
  assert.deepEqual(p.calls[2].value, current.project); assert.equal(p.calls[2].expectedPermissionRevision, '9');
  p.calls[2].resolve(mainEnabled('10')); await work;
});

test('Revoke races the original pending Allow and survives reconnect without adopting its late ACK', async () => {
  const p = permission(), next = port(); await check(p); p.controller.acknowledge(true); const allow = p.controller.allow();
  p.controller.bind(next.api, PROJECT); const revoke = p.controller.revoke();
  assert.deepEqual(p.calls.map((c) => c.kind), ['status', 'allow', 'revoke']); assert.equal(next.calls.length, 0);
  p.calls[2].resolve(mainDisabled('9')); await revoke; p.calls[1].resolve(mainEnabled()); await allow;
  assert.equal(p.controller.getState().access.enabled, false); assert.equal(p.controller.getState().uncertain, false);
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(next.calls.length, 0);
  await check(next, '9', p.controller); p.controller.acknowledge(true); const fresh = p.controller.allow();
  assert.equal(next.calls.length, 2); next.calls[1].resolve(mainEnabled('10')); await fresh;
});

test('a synchronous permission subscriber can Revoke before Allow dispatch without recreating consent afterward', async () => {
  const p = permission(); await check(p); let revoked = false, revoking;
  const unsubscribe = p.controller.subscribe((state) => {
    if (state.pending === 'allow' && !revoked) { revoked = true; revoking = p.controller.revoke(); }
  });
  p.controller.acknowledge(true); const allowing = p.controller.allow();
  assert.equal(revoked, true);
  assert.deepEqual(p.calls.map((call) => call.kind), ['status', 'revoke']);
  p.calls[1].resolve(mainDisabled('8')); await revoking; await allowing; unsubscribe();
  assert.deepEqual(p.calls.map((call) => call.kind), ['status', 'revoke']);
  assert.equal(p.controller.getState().access.enabled, false);
  assert.equal(p.controller.getState().pending, null);
  assert.equal(p.controller.getState().uncertain, false);
});

test('a status-only reconnect retains the original API across rebind until its actual Revoke returns', async () => {
  const p = permission(), next = port(); const reading = p.controller.status();
  p.controller.bind(next.api, PROJECT); p.calls[0].resolve(mainEnabled()); await reading;
  assert.equal(p.controller.getState().access.enabled, true);
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(next.calls.length, 0);
  const revoking = p.controller.revoke();
  assert.deepEqual(p.calls.map((call) => call.kind), ['status', 'revoke']);
  assert.equal(next.calls.length, 0);
  p.calls[1].resolve(mainDisabled('9')); await revoking;
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(next.calls.length, 0);
  await check(next, '9', p.controller); p.controller.acknowledge(true); const allowing = p.controller.allow();
  assert.deepEqual(next.calls.map((call) => call.kind), ['status', 'allow']);
  next.calls[1].resolve(mainEnabled('10')); await allowing;
});

test('saturated UI epoch still revokes the original and ignores a pending status ACK', async () => {
  const p = permission(); p.controller.epoch = Number.MAX_SAFE_INTEGER;
  const read = p.controller.status(), revoke = p.controller.revoke();
  assert.deepEqual(p.calls.map((c) => c.kind), ['status', 'revoke']);
  p.calls[1].resolve(mainDisabled('9')); await revoke; p.calls[0].resolve(mainEnabled()); await read;
  assert.equal(p.controller.getState().access.enabled, false);
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(p.calls.length, 2);
});

test('lost Allow ACK remains uncertain across status; only positive original Revoke clears permission uncertainty', async () => {
  const p = permission(); await check(p); p.controller.acknowledge(true); const first = p.controller.allow();
  p.calls[1].reject(new Error('not-rendered-sensitive-error')); await first;
  assert.equal(p.controller.getState().uncertain, true);
  const read = p.controller.status(); p.calls[2].resolve(mainDisabled('8')); await read;
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(p.calls.length, 3);
  assert.equal(p.controller.getState().uncertain, true);
  const revoke = p.controller.revoke(); p.calls[3].resolve(mainDisabled('9')); await revoke;
  assert.equal(p.controller.getState().uncertain, false);
  assert.ok(!JSON.stringify(p.controller.getState()).includes('sensitive-error'));
});

test('MAIN permission revisions are canonical u64 strings without changing the shared five-field parser', () => {
  for (const revision of ['0', '7', '9007199254740993', '18446744073709551615']) {
    const parsed = parseMainLocalCheckAccess(mainDisabled(revision));
    assert.equal(parsed.permissionRevision, revision); assert.ok(Object.isFrozen(parsed));
  }
  for (const revision of [undefined, 7, '', '00', '01', '+1', '-1', '1.0', '1\n', '18446744073709551616']) {
    assert.equal(parseMainLocalCheckAccess({ ...disabled(), permissionRevision: revision }), null);
    assert.equal(encodeLocalCheckAccessRequest('allow_agent_local_check', { ...PROJECT,
      consentVersion: AGENT_LOCAL_CHECK_CONSENT, expectedPermissionRevision: revision }), null);
  }
  assert.equal(parseMainLocalCheckAccess(disabled()), null);
  assert.equal(parseLocalCheckAccess(mainDisabled()), null);
  assert.ok(parseLocalCheckAccess(disabled()));
});

test('Allow requires a genuine Check and consumes its stamp without transparently refreshing consent', async () => {
  const p = permission(); p.controller.acknowledge(true); await p.controller.allow();
  assert.equal(p.calls.length, 0); assert.equal(p.controller.canAllow(), false);
  await check(p, '7'); p.controller.acknowledge(true); const allow = p.controller.allow();
  assert.deepEqual(p.calls.map((c) => c.kind), ['status', 'allow']);
  assert.equal(p.calls[1].expectedPermissionRevision, '7');
  p.calls[1].resolve(mainEnabled()); await allow;
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(p.calls.length, 2);
  await check(p, '8'); p.controller.acknowledge(true);
  await check(p, '9'); // A fresh observation is not the old acknowledgement.
  await p.controller.allow(); assert.equal(p.calls.length, 4); assert.equal(p.controller.canAllow(), false);
});

test('a queued native Allow keeps its original Check after Revoke returns before native dispatch', async () => {
  let revision = 0; const delayed = deferred(), calls = [];
  const api = { status: async () => { calls.push('status'); return mainDisabled(String(revision)); },
    allow: async (_project, expected) => { calls.push(['allow', expected]); await delayed.promise;
      if (expected !== String(revision)) throw new Error('stale permission');
      revision++; return mainEnabled(String(revision)); },
    revoke: async () => { calls.push('revoke'); revision++; return mainDisabled(String(revision)); } };
  const p = permission({ api }); await p.controller.status(); p.controller.acknowledge(true);
  const allow = p.controller.allow(); await p.controller.revoke(); delayed.resolve(); await allow;
  assert.deepEqual(calls, ['status', ['allow', '0'], 'revoke']);
  assert.equal(revision, 1); assert.equal(p.controller.getState().access.enabled, false);
  p.controller.acknowledge(true); await p.controller.allow(); assert.equal(calls.length, 3);
});

test('Revoke during Check return context publication cannot retain or acknowledge the old stamp', async () => {
  const p = port(); let current = { api: p.api, project: PROJECT, blocked: false }, revoking, revoked = false;
  const c = new AgentLocalCheckPermission(() => current); c.syncContext();
  const read = c.status();
  const unsubscribe = c.subscribe((state) => {
    if (state.pending === 'status' && current.project.draftRevision === 5 && !revoked) {
      revoked = true; revoking = c.revoke();
    }
  });
  current = { ...current, project: { ...PROJECT, draftRevision: 5 } };
  p.calls[0].resolve(mainEnabled('7')); await read;
  assert.equal(revoked, true); assert.deepEqual(p.calls.map((call) => call.kind), ['status', 'revoke']);
  p.calls[1].resolve(mainDisabled('8')); await revoking; unsubscribe();
  c.acknowledge(true); await c.allow(); assert.equal(p.calls.length, 2);
  assert.equal(c.getState().access.enabled, false); assert.equal(c.canAllow(), false);
});

test('native Projection marker is closed/local-only and cannot enter Prepare or change a same-ID observation', () => {
  const a = operation(), next = operation({ phase: 'running' });
  assert.ok(parseOfflinePreflightStatus(status(2, a))); assert.ok(offlineOperationProgress(a, next));
  const ordinary = operation(); delete ordinary.agentLocalCheck;
  assert.ok(parseOfflinePreflightStatus(status(2, ordinary)));
  assert.equal(offlineOperationProgress(a, ordinary), false);
  for (const mutation of [(v) => { v.agentLocalCheck.requestId = id('0'); }, (v) => { v.agentLocalCheck.command = 'arbitrary'; },
    (v) => { v.agentLocalCheck = null; }, (v) => { v.context.operation = 'offline-preflight'; }]) {
    const bad = operation(); mutation(bad); assert.equal(parseOfflinePreflightStatus(status(2, bad)), null);
  }
  assert.equal(copyOfflinePreflightRequest('prepare_offline_preflight', { ...PROJECT, savedConfig: CONFIG, agentLocalCheck: ORIGIN }), null);
});

test('native local check after genuine prior terminal adopts display and exact STOP only, never GUI execution', async (t) => {
  const previous = terminal({ operationId: id('1'), ownerGeneration: id('2') }); delete previous.agentLocalCheck;
  const h = await nativeView(t, status(2, previous)); h.emit(status(3, operation()));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  assert.deepEqual({ ...h.controller.getSnapshot().status.operation.agentLocalCheck }, ORIGIN);
  assert.equal(h.controller.getSnapshot().consent, null); assert.equal(h.controller.getSnapshot().historical, true);
  await h.controller.start(id('d'), id('e')); assert.equal(h.calls.length, 0);
  assert.equal(h.controller.cancel(), true); await flush();
  assert.deepEqual(h.calls, [{ kind: 'cancel', operationId: id('d'), ownerGeneration: id('e') }]);
  assert.equal(h.controller.getSnapshot().status.operation.phase, 'terminal');
});

test('active/unknown original or unmarked foreign IDs cannot be replaced by a new CLI observation', async (t) => {
  for (const old of [operation({ operationId: id('1'), ownerGeneration: id('2'), phase: 'running' }),
    operation({ operationId: id('1'), ownerGeneration: id('2'), phase: 'unknown', outcome: 'unknown', reason: 'cleanup-unknown' })]) {
    assert.equal(canObserveAgentLocalCheck(status(2, old), status(3, operation()), false), false);
    const h = await nativeView(t, status(2, old)); h.emit(status(3, operation()));
    assert.equal(h.controller.getSnapshot().integrityFailed, true);
    assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  }
  const old = terminal({ operationId: id('1'), ownerGeneration: id('2') }), unmarked = operation(); delete unmarked.agentLocalCheck;
  const h = await nativeView(t, status(2, old)); h.emit(status(3, unmarked));
  assert.equal(h.controller.getSnapshot().integrityFailed, true);
});

test('GUI Prepare still pending defers CLI display until its genuine pre-admission refusal returns', async (t) => {
  const old = terminal({ operationId: id('1'), ownerGeneration: id('2') }); delete old.agentLocalCheck;
  const h = await nativeView(t, status(2, old)); const preparing = h.controller.prepare();
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0].kind, 'prepare');
  h.emit(status(3, operation()));
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  h.calls[0].reject({ code: 'offline_preflight_busy' }); await preparing;
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('d'));
  assert.equal(h.controller.getSnapshot().consent, null); assert.equal(h.calls.length, 1);
});

test('GUI Start return remains retained even after original terminal; deferred CLI status cannot trigger Start again', async (t) => {
  const h = await nativeView(t); const preparing = h.controller.prepare(), call = h.calls[0];
  const gui = operation({ operationId: id('1'), ownerGeneration: id('2'), context: { ...call.input, platform: 'android', operation: 'offline-preflight' },
    phase: 'awaiting-consent', intentUsable: true }); delete gui.agentLocalCheck;
  h.reply(call, status(1, gui)); await preparing;
  h.controller.setAcknowledged(id('1'), id('2'), true); const starting = h.controller.start(id('1'), id('2'));
  assert.equal(h.calls[1].kind, 'start');
  const ended = { ...gui, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' };
  h.emit(status(3, ended)); h.emit(status(4, operation()));
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  h.calls[1].resolve(status(2, { ...gui, phase: 'starting', intentUsable: false })); await starting;
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('d'));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  await h.controller.start(id('d'), id('e')); assert.equal(h.calls.length, 2);
});

test('a completed local-check report preserves negative findings and never changes the original scope to release preflight', () => {
  const counts = Object.fromEntries(OFFLINE_CORE_STATUSES.map((key) => [key, key === 'FAIL' ? 1 : 0]));
  const report = { schemaVersion: 1, scope: 'saved-local-android-project-checks', usedConfig: clone(CONFIG),
    findings: [{ ordinal: 0, check: 'configured-project-check', message: 'configured-project-check', status: 'FAIL', projectCheckIndex: 0 }],
    summary: { total: 1, shown: 1, omitted: 0, counts }, limitations: [...OFFLINE_LIMITATIONS] };
  const s = parseOfflinePreflightStatus(status(5, terminal({ outcome: 'complete', reason: 'none', result: report })));
  assert.equal(s.operation.result.summary.counts.FAIL, 1); assert.equal(s.operation.outcome, 'complete');
  report.scope = 'saved-offline-android-no-core-build';
  assert.equal(parseOfflinePreflightStatus(status(5, terminal({ outcome: 'complete', reason: 'none', result: report }))), null);
});
