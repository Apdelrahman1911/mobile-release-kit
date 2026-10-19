// Closed public DATA and the actual two renderer controllers over inert ports.
// No gh process, credential, picker, native owner, HTTP, timer, DOM or build
// qualification is exercised. The clock only advances explicit fake callbacks.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { GitHubConnectionController } from '../src/githubConnectionController.ts';
import { GitHubGhEntryController } from '../src/githubGhEntryController.ts';
import { createGitHubGhApi, encodeGitHubGhRequest, githubGhFailure, parseGitHubGhRequest,
  parseGitHubGhResult, parseGitHubGhStatus } from '../src/githubGhEntryProtocol.ts';
import { GITHUB_WORKFLOWS } from '../src/githubSetupProtocol.ts';

const HELP = JSON.parse(readFileSync(new URL('../../src/mobile_release/api/data/github-connection-v1.json', import.meta.url), 'utf8'));
const CONTEXT = { documentId: 'document-a', projectId: 'project-a', projectGeneration: 1, repository: 'Owner/App' };
const REQUEST = { projectId: 'project-a', repository: 'Owner/App', selectedLogin: 'Owner', expectedDocumentRevision: 7, expectedConnectionRevision: 1 };
const HTTP = { sessionId: 'session-a', operationId: 'connect-a' };
const TIME = '2026-10-19T12:00:00Z'; const EXPIRY = '2026-10-19T13:00:00Z';
const clone = (value) => structuredClone(value);
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 16; i++) await Promise.resolve(); }
function fact(value = null) { return { state: value === null ? 'not-observed' : 'observed', value, observedAt: value === null ? null : TIME, reason: value === null ? 'not-connected' : 'none' }; }
function idle(revision = 1, available = true) {
  return { schemaVersion: 1, revision,
    capability: { readOnlySessionAvailable: available, reason: available ? 'none' : 'unqualified', deviceLogin: 'publisher-unconfigured', storage: 'session-only' },
    session: null, operation: null, account: fact(), repository: fact(), automation: fact(),
    facts: { remoteMutationAvailable: false, dispatchAvailable: false, repositoryActionsSettingsObservation: 'not-run', environmentObservation: 'not-run',
      secretObservation: 'not-run', variableObservation: 'not-run', protectionObservation: 'not-run', runnerObservation: 'not-run', templateCompatibility: 'unknown', releaseReadiness: 'unknown' } };
}
function checking(revision = 2) {
  return { ...idle(revision), session: { id: HTTP.sessionId, projectId: CONTEXT.projectId, targetRepository: CONTEXT.repository, state: 'checking', expiresAt: EXPIRY },
    operation: { id: HTTP.operationId, kind: 'connect', phase: 'running', reason: 'none' } };
}
function connected(revision = 3) {
  return { ...checking(revision), session: { ...checking().session, state: 'connected' }, operation: { ...checking().operation, phase: 'settled' },
    account: fact({ id: '11', login: 'Owner' }), repository: fact({ id: '22', fullName: 'Owner/App', defaultBranch: 'main', visibility: 'private', archived: false,
      permissions: { pull: 'reported-allowed', push: 'reported-denied', admin: 'unknown' } }),
    automation: fact({ coverage: 'complete', workflows: GITHUB_WORKFLOWS.map(({ id }, i) => ({ id, remoteId: String(i + 100), presence: 'listed', state: 'active' })) }) };
}
function auth(phase = 'idle', patch = {}) {
  const active = phase !== 'idle';
  return { schemaVersion: 1, documentRevision: 7, connectionRevision: 1, available: true,
    operationId: active ? 'auth-a' : null, projectId: active ? CONTEXT.projectId : null, repository: active ? CONTEXT.repository : null,
    selectedLogin: active ? 'Owner' : null, phase, reason: phase === 'cleanup-unknown' ? 'cleanup-unknown' : ['failed', 'stopping'].includes(phase) ? 'cancelled' : 'none',
    http: null, ...patch };
}
const handoff = () => ({ schemaVersion: 1, operationId: 'auth-a', outcome: 'http-handoff', connection: checking() });
const noHttp = (patch = {}) => ({ schemaVersion: 1, operationId: 'auth-a', outcome: 'no-http', auth: auth('failed', patch) });
const unknown = () => ({ schemaVersion: 1, operationId: 'auth-a', outcome: 'unknown', auth: auth('cleanup-unknown') });
function fakeClock() {
  const pending = new Map(); let serial = 0;
  return { schedule(fn) { const id = ++serial; pending.set(id, fn); return id; }, cancel(id) { pending.delete(id); },
    tick() { const first = pending.entries().next().value; if (!first) return false; pending.delete(first[0]); first[1](); return true; },
    get count() { return pending.size; } };
}
async function harness({ available = true, authAvailable = true } = {}) {
  const calls = [], connectionCalls = [], listeners = new Set(), timer = fakeClock(); let nativeConnection = idle(1, available);
  const port = { mode: 'native', subscribe: async (listener) => { listeners.add(listener); return () => listeners.delete(listener); },
    status: async () => clone(nativeConnection),
    refresh: (request) => { const d = deferred(); connectionCalls.push({ name: 'refresh', request, ...d }); return d.promise; },
    disconnect: (request) => { const d = deferred(); connectionCalls.push({ name: 'disconnect', request, ...d }); return d.promise; } };
  const api = createGitHubGhApi('native', (name, raw) => {
    assert.ok(raw instanceof Uint8Array); assert.ok(raw.length + name.length + 32 <= 1024);
    const d = deferred(); calls.push({ name, request: JSON.parse(new TextDecoder().decode(raw)), ...d });
    h.onInvoke?.(name); return d.promise;
  });
  let entry;
  const connection = new GitHubConnectionController(() => h.blocked ?? entry?.ownerReason() ?? null);
  const h = { api, port, apiNow: api, portNow: port, connection, calls, connectionCalls, timer, blocked: null, onInvoke: null,
    get state() { return entry.getSnapshot(); }, get connectionState() { return connection.getSnapshot(); },
    count(name) { return calls.filter((c) => c.name === name).length; }, last(name) { return calls.filter((c) => c.name === name).at(-1); },
    publish(value) { nativeConnection = clone(value); for (const listener of [...listeners]) listener(clone(value)); },
    setContext(value) { entry.beforeContextIntent(); connection.setContext(value); entry.syncContext(); },
    async read(value = auth('idle', { available: authAvailable, reason: authAvailable ? 'none' : 'runtime-unavailable' })) {
      assert.equal(entry.checkStatus(), true); h.last('github_auth_status').resolve(value); await flush();
    },
  };
  connection.setContext(CONTEXT); connection.setHelp(HELP); await connection.attach(port);
  entry = new GitHubGhEntryController(connection, { current: () => ({ api: h.apiNow, port: h.portNow,
    context: connection.getSnapshot().context, blocked: h.blocked }) }, timer); h.entry = entry;
  assert.equal(entry.attach(api, port), true); entry.setLogin('Owner');
  return h;
}
async function ready(options) { const h = await harness(options); await h.read(); return h; }

// Native byte decoder is tested separately by its author; these tests ensure
// the only renderer transport matches it and cannot widen into PAT/process I/O.
test('exact RAW three-command bridge, closed native shapes and inert preview', async () => {
  const calls = []; const api = createGitHubGhApi('native', async (name, bytes) => { calls.push({ name, value: JSON.parse(new TextDecoder().decode(bytes)) }); return null; });
  await api.status(); await api.connect(REQUEST); await api.cancel({ operationId: 'auth-a' });
  assert.deepEqual(calls.map((c) => c.name), ['github_auth_status', 'github_auth_connect', 'github_auth_cancel']);
  assert.deepEqual(calls.map((c) => c.value), [{}, REQUEST, { operationId: 'auth-a' }]);
  assert.equal(createGitHubGhApi('preview', () => { throw Error('must not call'); }), null);
  assert.ok(parseGitHubGhRequest({ ...REQUEST, selectedLogin: 'a--b' }));
  for (const patch of [{ selectedLogin: '-user' }, { selectedLogin: 'user\n' }, { selectedLogin: 'é' }, { selectedLogin: 'x'.repeat(40) },
    { expectedDocumentRevision: 0 }, { expectedConnectionRevision: true }, { expectedConnectionRevision: 0xffff_ffff }, { repository: 'Owner/App\n' },
    { path: '/inert' }, { token: 'INERT_SENTINEL' }, { authority: true }]) assert.equal(parseGitHubGhRequest({ ...REQUEST, ...patch }), null);
  assert.equal(encodeGitHubGhRequest('github_auth_cancel', { operationId: 'auth-a', expectedDocumentRevision: 7 }), null);
  assert.equal(encodeGitHubGhRequest('github_auth_run', {}), null);
  for (const phase of ['idle', 'picking', 'running', 'checking-identity', 'stopping', 'settled', 'failed', 'cleanup-unknown']) assert.ok(parseGitHubGhStatus(auth(phase)));
  assert.ok(parseGitHubGhStatus(auth('stopping', { reason: 'cleanup-unknown' })));
  assert.ok(parseGitHubGhStatus(auth('idle', { documentRevision: 0xffff_ffff })));
  assert.ok(parseGitHubGhResult(handoff())); assert.ok(parseGitHubGhResult(noHttp())); assert.ok(parseGitHubGhResult(unknown()));
  assert.equal(parseGitHubGhResult({ ...handoff(), connection: connected() }), null, 'historical checking admission, not manufactured Connected');
  for (const patch of [{ http: HTTP }, { phase: 'stopping' }, { reason: 'cleanup-unknown' }]) assert.equal(parseGitHubGhResult(noHttp(patch)), null);
});

test('malformed/accessor/private shape cannot become status or native refusal', () => {
  let getters = 0; const value = auth(); Object.defineProperty(value, 'token', { enumerable: true, get() { getters++; return 'INERT_SENTINEL'; } });
  assert.equal(parseGitHubGhStatus(value), null); assert.equal(getters, 0);
  const input = { ...REQUEST }; Object.defineProperty(input, 'path', { enumerable: true, get() { getters++; return '/inert'; } });
  assert.equal(parseGitHubGhRequest(input), null); assert.equal(getters, 0);
  const failure = {}; Object.defineProperty(failure, 'code', { get() { getters++; return 'github_connection_refused_busy'; } });
  assert.equal(githubGhFailure(failure).notAdmitted, false); assert.equal(getters, 0);
  assert.equal(githubGhFailure({ code: 'github_connection_refused_cleanup_unknown' }).notAdmitted, false);
  assert.equal(githubGhFailure({ admission: 'not-admitted', message: 'INERT_SENTINEL' }).notAdmitted, false);
  for (const patch of [{ command: 'exec' }, { operationId: 'bad\n' }, { http: { ...HTTP, token: 'INERT_SENTINEL' } }, { phase: 'connected' }, { documentRevision: -1 }])
    assert.equal(parseGitHubGhStatus(auth('picking', patch)), null);
});

test('manual username has no side effects; both genuine native gates and current comparisons remain required', async () => {
  const h = await harness(); assert.equal(h.calls.length, 0); assert.equal(h.entry.setLogin('Other'), true); assert.equal(h.calls.length, 0);
  assert.equal(h.entry.connect(), false); assert.match(h.entry.startReason(), /availability/);
  await h.read(); assert.equal(h.entry.startReason(), null); h.blocked = 'Another original task is active.';
  assert.equal(h.entry.connect(), false); h.blocked = null; h.publish(idle(2)); assert.match(h.entry.startReason(), /connection status/);
  assert.equal(h.entry.connect(), false); assert.equal(h.count('github_auth_connect'), 0);
  for (const options of [{ available: false }, { authAvailable: false }]) {
    const blocked = await ready(options); assert.equal(blocked.entry.connect(), false); assert.equal(blocked.count('github_auth_connect'), 0);
  }
  const missingHelp = await ready(); missingHelp.connection.setHelp(null); assert.equal(missingHelp.entry.connect(), false);
});

test('actual Connect is latched before invoke; newer HTTP event wins while original gh reply remains owned', async () => {
  const h = await ready();
  h.onInvoke = (name) => { if (name === 'github_auth_connect') {
    assert.equal(h.connectionState.busy, 'connect'); assert.equal(h.state.pendingCount, 1);
    h.publish(checking()); h.publish(connected());
  } };
  assert.equal(h.entry.connect(), true); assert.equal(h.count('github_auth_connect'), 1);
  assert.deepEqual(h.last('github_auth_connect').request, REQUEST); assert.equal(h.connectionState.status.revision, 3);
  assert.equal(h.connectionState.status.account.value.login, 'Owner'); assert.equal(h.connectionState.busy, 'connect');
  assert.equal(h.entry.connect(), false); assert.equal(h.connection.canConnect(), false);
  h.last('github_auth_connect').resolve(handoff()); await flush();
  assert.equal(h.connectionState.status.revision, 3); assert.equal(h.connectionState.busy, null);
  assert.ok(h.entry.ownerReason(), 'historical handoff alone does not claim capture cleanup');
  await h.read(auth('settled', { connectionRevision: 3, http: HTTP }));
  assert.equal(h.entry.ownerReason(), null); assert.equal(h.state.login, 'Owner');
  assert.equal(h.connectionState.status.facts.releaseReadiness, 'unknown');
});

test('serial equal-revision phase checks and queued Stop retain both pending originals', async () => {
  const h = await ready(); h.entry.connect();
  assert.equal(h.entry.checkStatus(), true); const overtaking = h.last('github_auth_status');
  assert.equal(h.entry.checkStatus(), false); assert.equal(h.entry.requestCancel(), true); assert.equal(h.count('github_auth_cancel'), 0);
  overtaking.resolve(auth()); await flush(); assert.equal(h.connectionState.busy, 'connect');
  await h.read(auth('picking')); assert.equal(h.count('github_auth_cancel'), 1);
  assert.deepEqual(h.last('github_auth_cancel').request, { operationId: 'auth-a' });
  assert.equal(h.state.pendingCount, 2); assert.equal(h.entry.requestCancel(), false);
  h.last('github_auth_cancel').resolve(auth('stopping')); await flush();
  assert.equal(h.state.original.phase, 'stopping');
  await h.read(auth('failed')); assert.equal(h.connectionState.busy, 'connect', 'status alone cannot discharge the Connect latch');
  assert.equal(h.state.pendingCount, 1); h.last('github_auth_connect').resolve(noHttp()); await flush();
  assert.equal(h.entry.ownerReason(), null); assert.equal(h.connectionState.busy, null); assert.equal(h.state.login, 'Owner');
  assert.equal(h.count('github_auth_connect'), 1); assert.equal(h.count('github_auth_cancel'), 1);
});

test('only exact typed joined no-HTTP retires its Connect; read failure does not lose draft or native proof', async () => {
  const h = await ready(); h.entry.connect(); await h.read({ malformed: true });
  assert.equal(h.state.issue, 'unconfirmed'); assert.equal(h.connectionState.busy, 'connect');
  h.last('github_auth_connect').resolve(noHttp()); await flush();
  assert.equal(h.state.issue, null); assert.equal(h.entry.ownerReason(), null); assert.equal(h.connectionState.busy, null);
  assert.equal(h.connectionState.error, 'cancelled'); assert.equal(h.state.login, 'Owner'); assert.equal(h.entry.connect(), false);
  assert.equal(h.timer.tick(), true); await flush(); assert.equal(h.count('github_auth_status'), 2, 'scheduled poll does not run after original terminal');
  await h.connection.checkStatus(); await h.read(auth('failed')); assert.equal(h.entry.startReason(), null);
  assert.equal(h.count('github_auth_connect'), 1, 'new connection always needs another explicit click');
  for (const value of [noHttp({ projectId: 'foreign-project' }), noHttp({ selectedLogin: 'Other' }), unknown(), { outcome: 'no-http' }]) {
    const other = await ready(); other.entry.connect(); other.last('github_auth_connect').resolve(value); await flush();
    assert.ok(other.entry.ownerReason()); assert.equal(other.connectionState.busy, 'connect'); assert.equal(other.entry.connect(), false);
  }
});

test('lost invoke plus idle/failed status cannot invent no-admission; exact native pre-admission errors are bounded', async () => {
  const h = await ready(); h.entry.connect(); h.last('github_auth_connect').reject({ message: 'INERT_PRIVATE_DIAGNOSTIC' }); await flush();
  assert.equal(h.state.issue, 'unconfirmed'); await h.read(auth()); assert.equal(h.connectionState.busy, 'connect');
  await h.read(auth('failed')); assert.equal(h.state.issue, 'unconfirmed'); assert.equal(h.entry.connect(), false);
  assert.equal(JSON.stringify(h.state).includes('INERT_PRIVATE'), false);
  const refused = await ready(); await refused.read(auth('failed', { operationId: 'previous-auth' })); refused.entry.connect();
  await refused.read(auth('failed', { operationId: 'previous-auth' })); assert.equal(refused.state.issue, null, 'old retained status may overtake new admission');
  await refused.read({ malformed: true }); refused.last('github_auth_connect').reject({ code: 'github_connection_refused_busy' }); await flush();
  assert.equal(refused.connectionState.busy, null); assert.equal(refused.entry.ownerReason(), null); assert.equal(refused.state.failure, 'busy');
  const contradiction = await ready(); contradiction.entry.connect(); await contradiction.read(auth('picking'));
  contradiction.last('github_auth_connect').reject({ code: 'github_connection_refused_busy' }); await flush();
  assert.equal(contradiction.connectionState.busy, 'connect'); assert.ok(contradiction.entry.ownerReason(), 'already observed native admission cannot become a refusal');
});

test('auth no-HTTP conflicts with an observed HTTP admission and cannot clear that original', async () => {
  const h = await ready(); h.entry.connect(); h.publish(checking());
  h.last('github_auth_connect').resolve(noHttp()); await flush();
  assert.equal(h.connectionState.busy, 'connect'); assert.equal(h.connectionState.blocked, true);
  assert.equal(h.connection.canDisconnect(), true); assert.equal(h.entry.connect(), false);
});

test('native cleanup Unknown remains sticky; exact Stop is available and never masquerades as completion', async () => {
  const h = await ready(); h.entry.connect(); await h.read(auth('cleanup-unknown'));
  assert.equal(h.state.issue, 'cleanup-unknown'); assert.equal(h.entry.canCancel(), true);
  const original = h.state.original;
  await h.read(auth('failed')); await h.read(auth('settled', { http: HTTP, documentRevision: 9 }));
  assert.equal(h.state.original, original); assert.equal(h.entry.canCancel(), true, 'later ordinary status cannot end the unknown original or hide Stop');
  assert.equal(h.entry.requestCancel(), true); assert.equal(h.count('github_auth_cancel'), 1);
  h.last('github_auth_cancel').resolve(auth('failed')); h.last('github_auth_connect').resolve(handoff()); await flush();
  await h.read(auth('settled', { http: HTTP }));
  assert.equal(h.state.issue, 'cleanup-unknown'); assert.equal(h.entry.connect(), false); assert.equal(h.entry.attach(null, null), false);
  assert.equal(h.state.original, original); assert.equal(h.state.pendingCount, 0); assert.equal(h.count('github_auth_connect'), 1);
  const observed = await ready(); await observed.read(auth('cleanup-unknown', { projectId: 'old-project' }));
  const oldOriginal = observed.state.original;
  observed.setContext(null); await observed.read(auth('failed', { projectId: 'old-project' }));
  assert.equal(observed.state.original, oldOriginal); assert.equal(observed.entry.canCancel(), true);
  observed.entry.requestCancel(); assert.deepEqual(observed.last('github_auth_cancel').request, { operationId: 'auth-a' });
  observed.last('github_auth_cancel').resolve(auth('failed', { projectId: 'old-project' })); await flush();
  assert.equal(observed.state.original, oldOriginal); assert.ok(observed.entry.ownerReason()); assert.equal(observed.state.pendingCount, 0);
});

test('context/API/ABA changes retain old picker and user draft; late joined refusal cannot become fresh eligibility', async () => {
  const h = await ready(); h.entry.connect();
  h.setContext({ ...CONTEXT, projectId: 'project-b', projectGeneration: 2 }); h.apiNow = createGitHubGhApi('native', () => { throw Error('new port must not run'); });
  assert.equal(h.entry.attach(h.apiNow, h.port), false); h.apiNow = h.api; h.setContext(CONTEXT);
  assert.equal(h.state.login, 'Owner'); assert.equal(h.state.status, null); assert.equal(h.state.cancelRequested, true);
  h.last('github_auth_connect').resolve(noHttp()); await flush();
  assert.equal(h.connectionState.busy, null); assert.equal(h.entry.ownerReason(), null); assert.equal(h.state.status, null);
  assert.equal(h.entry.connect(), false); assert.equal(h.count('github_auth_connect'), 1);
  const read = await harness(); read.entry.checkStatus(); const pending = read.last('github_auth_status');
  read.setContext({ ...CONTEXT, projectGeneration: 2 }); read.setContext(CONTEXT);
  assert.equal(read.entry.attach(null, null), false); pending.resolve(auth()); await flush();
  assert.equal(read.state.status, null); assert.equal(read.entry.connect(), false);
  const observed = await ready(); await observed.read(auth('picking', { projectId: 'previous-project' }));
  observed.apiNow = null; observed.entry.syncContext(); assert.equal(observed.entry.attach(null, null), false);
  await observed.read(auth('settled', { projectId: 'previous-project' }));
  assert.equal(observed.entry.ownerReason(), null, 'explicit original Status can settle a retained old-port observation');
  assert.equal(observed.state.status, null, 'old-port settlement never enables the new current view');
});

test('HTTP retirement before late gh reply retains the exact observer, then accepts historical DATA without revival', async () => {
  const h = await ready(); h.entry.connect(); h.publish(checking()); h.setContext(null);
  assert.equal(h.connectionCalls.length, 1); assert.deepEqual(h.connectionCalls[0].request, { sessionId: HTTP.sessionId });
  h.connectionCalls[0].resolve(idle(4)); await flush();
  assert.equal(h.connectionState.retirementPending, true); assert.equal(h.state.pendingCount, 1);
  h.last('github_auth_connect').resolve(handoff()); await flush();
  assert.equal(h.connectionState.retirementPending, false); assert.equal(h.connectionState.busy, null);
  assert.equal(h.connectionState.status?.session ?? null, null); assert.equal(h.connectionCalls.length, 1);
  await h.read(auth('settled', { http: HTTP, connectionRevision: 4 }));
  assert.equal(h.state.pendingCount, 1, 'the original queued Cancel reply is still retained independently');
  h.last('github_auth_cancel').resolve(auth('settled', { http: HTTP, connectionRevision: 4 })); await flush();
  assert.equal(h.entry.ownerReason(), null); assert.equal(h.state.context, null); assert.equal(h.entry.connect(), false);
});

test('reentrant intent or other-owner admission before actual invoke prevents every unsent request', async () => {
  for (const stage of ['connection-latch', 'auth-latch']) {
    const h = await ready(); let once = false;
    const off = (stage === 'connection-latch' ? h.connection : h.entry).subscribe(() => {
      if (once || (stage === 'connection-latch' ? h.connectionState.busy !== 'connect' : h.state.pendingCount !== 1)) return;
      once = true; if (stage === 'connection-latch') h.setContext(null); else h.blocked = 'Another original task';
    });
    assert.equal(h.entry.connect(), false); off(); assert.equal(h.count('github_auth_connect'), 0);
    assert.equal(h.state.pendingCount, 0); assert.equal(h.connectionState.busy, null); assert.equal(h.state.issue, null);
  }
});

test('descriptor reentrancy retires consent but original typed response still settles only its retained work', async () => {
  const h = await ready(); h.entry.connect(); let once = false;
  const value = new Proxy(noHttp(), { getOwnPropertyDescriptor(target, key) {
    if (!once) { once = true; h.setContext({ ...CONTEXT, projectId: 'project-b', projectGeneration: 2 }); }
    return Reflect.getOwnPropertyDescriptor(target, key);
  } });
  h.last('github_auth_connect').resolve(value); await flush();
  assert.equal(h.state.context.projectId, 'project-b'); assert.equal(h.state.status, null); assert.equal(h.connectionState.busy, null);
  assert.equal(h.entry.connect(), false); h.setContext(CONTEXT); assert.equal(h.state.login, 'Owner');
});

test('bounded passive polling never extends expiry, retries Connect or releases pending originals on disposal', async () => {
  const h = await ready(); h.entry.connect();
  for (let n = 0; n < 70; n++) {
    assert.equal(h.timer.tick(), true); h.last('github_auth_status').resolve(auth('picking')); await flush();
  }
  assert.equal(h.timer.tick(), false); assert.equal(h.count('github_auth_status'), 71); assert.equal(h.count('github_auth_connect'), 1);
  assert.ok(h.entry.ownerReason()); assert.equal(h.state.pendingCount, 1);
  h.entry.dispose(); assert.equal(h.count('github_auth_cancel'), 1); assert.equal(h.state.pendingCount, 2); assert.equal(h.entry.attach(null, null), false);
  h.last('github_auth_cancel').resolve(auth('failed')); h.last('github_auth_connect').resolve(noHttp()); await flush();
  assert.equal(h.state.pendingCount, 0); assert.equal(h.entry.ownerReason(), null); assert.equal(h.timer.count, 0);
});
