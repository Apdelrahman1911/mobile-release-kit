// One inert G1 leaf: closed DATA, fake-port promises and fixed shipped SOURCE.
// No native owner, token collection, HTTP/TLS, timer, subprocess, DOM or browser.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { GITHUB_WORKFLOWS } from '../src/githubSetupProtocol.ts';
import { GitHubConnectionController } from '../src/githubConnectionController.ts';
import { GITHUB_CONNECTION_ENTRY_AVAILABLE, connectionProgress, githubConnectionRequestFits,
  parseGitHubConnectionHelp, parseGitHubConnectionStatus } from '../src/githubConnectionProtocol.ts';

const HELP = JSON.parse(readFileSync(new URL('../../src/mobile_release/api/data/github-connection-v1.json', import.meta.url), 'utf8'));
const TIME = '2026-09-17T12:00:00Z'; const EXPIRY = '2026-09-17T13:00:00Z';
const SECRET = 'INERT_PRIVATE_TOKEN_MUST_NOT_ESCAPE';
const CONTEXT = { documentId: 'document-a', projectId: 'project-a', projectGeneration: 1, repository: 'Owner/App' };
const clone = (value) => structuredClone(value);
function fact(value = null) { return { state: value === null ? 'not-observed' : 'observed', value, observedAt: value === null ? null : TIME, reason: value === null ? 'not-connected' : 'none' }; }
function idle(revision = 1) {
  return { schemaVersion: 1, revision,
    capability: { readOnlySessionAvailable: false, reason: 'unqualified', deviceLogin: 'publisher-unconfigured', storage: 'session-only' },
    session: null, operation: null, account: fact(), repository: fact(), automation: fact(),
    facts: { remoteMutationAvailable: false, dispatchAvailable: false, repositoryActionsSettingsObservation: 'not-run', environmentObservation: 'not-run',
      secretObservation: 'not-run', variableObservation: 'not-run', protectionObservation: 'not-run', runnerObservation: 'not-run', templateCompatibility: 'unknown', releaseReadiness: 'unknown' } };
}
function connected(revision = 2, operationId = 'connect-a') {
  return { ...idle(revision), capability: { ...idle().capability, readOnlySessionAvailable: true, reason: 'none' },
    session: { id: 'session-a', projectId: 'project-a', targetRepository: 'Owner/App', state: 'connected', expiresAt: EXPIRY },
    operation: { id: operationId, kind: operationId === 'connect-a' ? 'connect' : 'refresh', phase: 'settled', reason: 'none' },
    account: fact({ id: '11', login: 'Owner' }),
    repository: fact({ id: '22', fullName: 'Owner/App', defaultBranch: 'main', visibility: 'private', archived: false,
      permissions: { pull: 'reported-allowed', push: 'reported-denied', admin: 'unknown' } }),
    automation: fact({ coverage: 'complete', workflows: GITHUB_WORKFLOWS.map(({ id }, i) => ({ id, remoteId: String(100 + i), presence: 'listed', state: 'active' })) }) };
}
function staleFacts(value, reason = 'stale') {
  const status = clone(value);
  for (const key of ['account', 'repository', 'automation']) if (status[key].value) { status[key].state = 'stale'; status[key].reason = reason; }
  return status;
}
function checking(revision = 3) {
  const value = staleFacts(connected(revision, 'refresh-a'));
  value.session.state = 'checking'; value.operation.phase = 'running'; return value;
}
function retiring(revision = 4) {
  const value = staleFacts(connected(revision), 'cancelled'); value.session.state = 'disconnecting';
  value.operation = { id: 'disconnect-a', kind: 'disconnect', phase: 'running', reason: 'none' }; return value;
}
function unknown(revision = 5) {
  const value = staleFacts(retiring(revision), 'cleanup-unknown'); value.session.state = 'cleanup-unknown';
  value.operation.phase = 'cleanup-unknown'; value.operation.reason = 'cleanup-unknown';
  value.capability.readOnlySessionAvailable = false; value.capability.reason = 'cleanup-unknown'; return value;
}
function deferred() { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 10; i += 1) await Promise.resolve(); }
function harness({ registry = connected(), mode = 'native', subscribeGate = null } = {}) {
  const calls = []; const reads = []; const subscriptions = [];
  let current = clone(registry); let unlistened = 0;
  const port = {
    mode,
    subscribe: async (listener) => {
      calls.push({ kind: 'subscribe' }); const row = { listener, active: true }; subscriptions.push(row);
      if (subscribeGate) await subscribeGate.promise;
      return () => { row.active = false; unlistened += 1; };
    },
    status: () => { calls.push({ kind: 'status' }); return reads.length ? reads.shift().promise : Promise.resolve(clone(current)); },
    refresh: (args) => { const work = deferred(); calls.push({ kind: 'refresh', args: clone(args), ...work }); return work.promise; },
    disconnect: (args) => { const work = deferred(); calls.push({ kind: 'disconnect', args: clone(args), ...work }); return work.promise; },
  };
  const controller = new GitHubConnectionController(); controller.setContext(CONTEXT); controller.setHelp(HELP);
  return { port, controller, calls, subscriptions,
    get state() { return controller.getSnapshot(); }, get unlistened() { return unlistened; },
    count: (kind) => calls.filter((v) => v.kind === kind).length,
    last: (kind) => calls.filter((v) => v.kind === kind).at(-1),
    publish: (value) => { current = clone(value); for (const row of subscriptions) if (row.active) row.listener(clone(value)); },
    retain: (value) => { current = clone(value); },
    deferRead: () => { const value = deferred(); reads.push(value); return value; },
  };
}
async function attached(options) { const h = harness(options); await h.controller.attach(h.port); return h; }

test('closed status graph requires explicit nulls, nonlossy IDs and false remote gates', () => {
  assert.ok(parseGitHubConnectionStatus(idle())); assert.ok(parseGitHubConnectionStatus(connected()));
  assert.ok(parseGitHubConnectionStatus(unknown()));
  const unownedCleanup = idle(); unownedCleanup.capability.reason = 'cleanup-unknown'; assert.equal(parseGitHubConnectionStatus(unownedCleanup), null);
  const cases = [
    (v) => { delete v.session; }, (v) => { delete v.operation; }, (v) => { delete v.account.value; },
    (v) => { delete v.account.observedAt; }, (v) => { v.token = SECRET; }, (v) => { v.capability.storage = 'plaintext'; },
    (v) => { v.facts.remoteMutationAvailable = true; }, (v) => { v.facts.dispatchAvailable = true; },
    (v) => { v.facts.repositoryActionsObservation = 'not-run'; delete v.facts.repositoryActionsSettingsObservation; },
    (v) => { v.revision = true; }, (v) => { v.revision = 0; }, (v) => { v.revision = 0x1_0000_0000; },
    (v) => { v.account.value.id = 11; }, (v) => { v.account.value.id = '01'; },
    (v) => { v.repository.value.id = '18446744073709551616'; }, (v) => { v.session.id = 'a\n'; },
    (v) => { v.session.expiresAt = null; }, (v) => { v.session.expiresAt = '2025-02-29T00:00:00Z'; },
    (v) => { v.account.value.login = 'name\u0085'; }, (v) => { v.account.value.login = 'name\u202e'; },
    (v) => { v.account.value.login = '\ud800'; }, (v) => { v.repository.value.defaultBranch = 'é'.repeat(513); },
    (v) => { v.repository.value.fullName = 'Owner/Replacement'; },
  ];
  for (const change of cases) { const value = connected(); change(value); assert.equal(parseGitHubConnectionStatus(value), null); }
  const max = connected(); max.account.value.id = '18446744073709551615'; assert.ok(parseGitHubConnectionStatus(max));
  const input = connected(); const decoded = parseGitHubConnectionStatus(input); input.account.value.login = SECRET;
  assert.equal(decoded.account.value.login, 'Owner');
});

test('exotic/cyclic input and accessors refuse before reading private fields', () => {
  let getterCalls = 0; const getter = connected();
  Object.defineProperty(getter, 'unexpected', { enumerable: true, get() { getterCalls += 1; return SECRET; } });
  assert.equal(parseGitHubConnectionStatus(getter), null); assert.equal(getterCalls, 0);
  const cycle = connected(); cycle.extra = cycle; assert.equal(parseGitHubConnectionStatus(cycle), null);
  const hidden = connected(); Object.defineProperty(hidden, 'hidden', { value: SECRET }); assert.equal(parseGitHubConnectionStatus(hidden), null);
  const sparse = connected(); sparse.automation.value.workflows = Array(4); assert.equal(parseGitHubConnectionStatus(sparse), null);
});

test('Fact state/value/time and four-row coverage are cross-field invariants', () => {
  const cases = [
    (v) => { v.account.state = 'not-observed'; }, (v) => { v.account.observedAt = null; },
    (v) => { v.account.reason = 'forbidden'; }, (v) => { v.repository.value = null; v.repository.state = 'unavailable'; v.repository.observedAt = null; v.repository.reason = 'forbidden'; },
    (v) => { v.repository.state = 'stale'; v.repository.reason = 'stale'; },
    (v) => { v.automation.value.workflows.reverse(); }, (v) => { v.automation.value.workflows[0].remoteId = null; },
    (v) => { v.automation.value.workflows[1].remoteId = v.automation.value.workflows[0].remoteId; },
    (v) => { v.automation.value.workflows[0] = { ...v.automation.value.workflows[0], presence: 'unknown', remoteId: null, state: 'unknown' }; },
    (v) => { v.automation.value.coverage = 'limited'; v.automation.value.workflows[0] = { ...v.automation.value.workflows[0], presence: 'not-listed', remoteId: null, state: 'unknown' }; },
    (v) => { v.session.state = 'cleanup-unknown'; }, (v) => { v.session.state = 'checking'; },
  ];
  for (const change of cases) { const value = connected(); change(value); assert.equal(parseGitHubConnectionStatus(value), null); }
  const limited = connected(); limited.automation.value.coverage = 'limited';
  limited.automation.value.workflows[1] = { ...limited.automation.value.workflows[1], presence: 'unknown', remoteId: null, state: 'unknown' };
  assert.ok(parseGitHubConnectionStatus(limited));
});

test('closed command validator never returns a private object, accepts no extra route or whitespace token', () => {
  const args = { projectId: 'project-a', repository: 'Owner/App', token: SECRET };
  assert.equal(githubConnectionRequestFits('github_connection_connect_token', args), true);
  assert.equal(githubConnectionRequestFits('github_connection_status', {}), true);
  assert.equal(githubConnectionRequestFits('github_connection_refresh', { sessionId: 's', expectedRevision: 1 }), true);
  assert.equal(githubConnectionRequestFits('github_connection_disconnect', { sessionId: 's' }), true);
  for (const token of ['', 'x\n', ' x', 'x ', '\t', '\u0085', 'é', 'x'.repeat(4097)])
    assert.equal(githubConnectionRequestFits('github_connection_connect_token', { ...args, token }), false);
  assert.equal(githubConnectionRequestFits('github_connection_connect_token', { ...args, token: '!'.repeat(4096) }), true);
  for (const extra of ['url', 'host', 'saveToken', 'scope', 'force', 'header'])
    assert.equal(githubConnectionRequestFits('github_connection_connect_token', { ...args, [extra]: SECRET }), false);
  assert.equal(githubConnectionRequestFits('github_connection_status', { token: SECRET }), false);
  assert.equal(githubConnectionRequestFits('github_connection_connect_token', { ...args, repository: 'Owner/App\n' }), false);
  assert.equal(githubConnectionRequestFits('github_connection_refresh', { sessionId: 's', expectedRevision: true }), false);
  for (const name of ['github_connection_dispatch', 'github_connection_device_login', 'github_connection_refresh_token'])
    assert.equal(githubConnectionRequestFits(name, {}), false);
});

test('immutable equal revisions, identities, expiry and absorbing cleanup reject contradictions', () => {
  const old = connected(); const reordered = Object.fromEntries(Object.entries(old).reverse());
  assert.equal(connectionProgress(old, reordered), true);
  for (const change of [
    (v) => { v.account.value.login = 'Contradictory same revision'; },
    (v) => { v.revision += 1; v.account.value.id = '12'; },
    (v) => { v.revision += 1; v.repository.value.id = '23'; },
    (v) => { v.revision += 1; v.session.id = 'replacement'; },
    (v) => { v.revision += 1; v.session.expiresAt = '2026-09-17T14:00:00Z'; },
  ]) { const next = clone(old); change(next); assert.equal(connectionProgress(old, next), false); }
  assert.equal(connectionProgress(unknown(), connected(6)), false);
  assert.equal(connectionProgress(retiring(), connected(6)), false);
  const regressed = connected(4); regressed.operation.phase = 'running';
  assert.equal(connectionProgress(old, regressed), false);
});

test('fixed core help is closed and unavailable/previous help never enables entry', async () => {
  assert.ok(parseGitHubConnectionHelp(HELP));
  const bad = clone(HELP); bad.inputs[1].requiredness = 'optional'; assert.equal(parseGitHubConnectionHelp(bad), null);
  const h = await attached(); assert.equal(h.state.helpState, 'current');
  h.controller.setHelp({ token: SECRET }); assert.equal(h.state.helpState, 'previous');
  assert.equal(h.controller.canRefresh(), false); assert.equal(h.controller.canDisconnect(), true);
  assert.equal(JSON.stringify(h.state).includes(SECRET), false);
  assert.equal(GITHUB_CONNECTION_ENTRY_AVAILABLE, false);
});

test('subscribe precedes first status; preview has no fallback or secret method', async () => {
  const h = await attached(); assert.deepEqual(h.calls.slice(0, 2).map((c) => c.kind), ['subscribe', 'status']);
  assert.equal(h.controller.canRefresh(), true); assert.equal(Object.isFrozen(h.state.status.account.value), true);
  const preview = await attached({ mode: 'preview' }); await preview.controller.checkStatus();
  assert.equal(preview.calls.length, 0); assert.equal(preview.controller.refresh(), false); assert.equal(preview.controller.disconnect(), false);
  assert.equal('connectToken' in preview.controller, false);
  const source = readFileSync(new URL('../src/components/GitHubConnection.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /type=["']password|dangerouslySetInnerHTML|\bfetch\(|\binvoke\(|window\.open|localStorage/);
  assert.match(source, /Connect · unavailable/);
});

test('Busy refuses a second Refresh but not retained Status or immediate Disconnect', async () => {
  const h = await attached(); assert.equal(h.controller.refresh(), true); assert.equal(h.controller.refresh(), false);
  assert.deepEqual(h.last('refresh').args, { sessionId: 'session-a', expectedRevision: 2 });
  h.publish(checking()); await h.controller.checkStatus();
  assert.equal(h.count('status'), 2); assert.equal(h.count('refresh'), 1); assert.equal(h.controller.canDisconnect(), true);
  assert.equal(h.controller.disconnect(), true); assert.deepEqual(h.last('disconnect').args, { sessionId: 'session-a' });
  assert.equal(h.controller.disconnect(), false);
  h.last('refresh').resolve(connected(4, 'refresh-a')); await flush();
  assert.equal(h.state.busy, 'disconnect'); assert.equal(h.state.retirementPending, true);
  h.publish(connected(5, 'refresh-a')); assert.notEqual(h.state.status?.session?.state, 'connected');
  h.last('disconnect').resolve(retiring()); await flush();
  h.publish(idle(7)); assert.equal(h.state.retirementPending, false); assert.equal(h.state.busy, null);
  h.publish(connected(8, 'refresh-a')); assert.equal(h.state.status.session, null); assert.equal(h.controller.canRefresh(), false);
  for (const retirement of ['dispose', 'context', 'disconnect', 'help', 'new-revision', 'cleanup']) {
    const original = await attached(); let retired = false;
    const stop = original.controller.subscribe(() => {
      if (retired || original.state.busy !== 'refresh') return;
      retired = true;
      if (retirement === 'dispose') original.controller.dispose();
      else if (retirement === 'context') original.controller.setContext(null);
      else if (retirement === 'disconnect') original.controller.disconnect();
      else if (retirement === 'help') original.controller.setHelp(null);
      else original.publish(retirement === 'cleanup' ? unknown() : connected(3));
    });
    assert.equal(original.controller.refresh(), false, retirement);
    stop(); await flush();
    assert.equal(original.count('refresh'), 0, `retired before invocation: ${retirement}`);
    if (['dispose', 'context', 'disconnect'].includes(retirement)) assert.equal(original.count('disconnect'), 1, retirement);
    else assert.equal(original.state.busy, null, retirement);
  }
});

test('lost Refresh reply is fixed uncertainty, never retry; Status and Disconnect still work', async () => {
  const h = await attached(); h.controller.refresh(); h.last('refresh').reject(new Error(SECRET)); await flush();
  assert.equal(h.state.uncertain, true); assert.equal(h.state.error, 'response-invalid');
  h.retain(connected(4, 'refresh-a')); await h.controller.checkStatus();
  assert.equal(h.state.uncertain, true); assert.equal(h.controller.refresh(), false); assert.equal(h.count('refresh'), 1);
  assert.equal(h.controller.disconnect(), true); assert.equal(JSON.stringify(h.state).includes(SECRET), false);
});

test('a newer event suppresses both old Status success and old Status error', async () => {
  const h = await attached(); const first = h.deferRead(); const read = h.controller.checkStatus(); await flush();
  h.publish(connected(3)); first.resolve(idle(1)); await read;
  assert.equal(h.state.status.revision, 3); assert.equal(h.state.error, null);
  const second = h.deferRead(); const next = h.controller.checkStatus(); await flush();
  h.publish(connected(4)); second.reject(new Error(SECRET)); await next;
  assert.equal(h.state.status.revision, 4); assert.equal(h.state.error, null);
  const third = h.deferRead(); const malformed = h.controller.checkStatus(); await flush();
  h.publish(connected(5)); third.resolve({ token: SECRET }); await malformed;
  assert.equal(h.state.status.revision, 5); assert.equal(h.state.error, null); assert.equal(h.state.blocked, false);
  assert.equal(JSON.stringify(h.state).includes(SECRET), false);
});

test('original account and repository IDs remain pinned across unavailable facts', async () => {
  for (const field of ['account', 'repository']) {
    const h = await attached(); const unavailable = checking();
    for (const name of ['account', 'repository', 'automation'])
      unavailable[name] = { state: 'unavailable', value: null, observedAt: null, reason: 'network-unavailable' };
    h.publish(unavailable); assert.equal(h.state.error, null);
    const replacement = connected(4, 'refresh-a'); replacement[field].value.id = '99'; h.publish(replacement);
    assert.equal(h.state.status.revision, 3); assert.equal(h.state.blocked, true); assert.equal(h.state.error, 'target-changed');
    assert.equal(h.controller.canRefresh(), false); assert.equal(h.controller.canDisconnect(), true);
  }
});

test('own reply can bind a refresh already overtaken by its matching settled event', async () => {
  const h = await attached(); h.controller.refresh();
  h.publish(connected(4, 'refresh-a')); assert.equal(h.state.busy, 'refresh');
  h.last('refresh').resolve(checking(3)); await flush();
  assert.equal(h.state.status.revision, 4); assert.equal(h.state.busy, null); assert.equal(h.controller.canRefresh(), true);
});

test('project/target away-and-back invalidates old successes, errors and subscription callbacks', async () => {
  for (const failure of [false, true]) {
    const h = await attached(); const oldEvent = h.subscriptions[0].listener;
    const original = h.deferRead(); const read = h.controller.checkStatus(); await flush();
    h.controller.setContext({ ...CONTEXT, repository: 'Owner/Other', projectGeneration: 2 });
    h.controller.setContext({ ...CONTEXT, projectGeneration: 3 });
    oldEvent(connected(500));
    if (failure) original.reject(new Error(SECRET)); else original.resolve(connected(600));
    await read; await flush();
    assert.equal(h.state.status, null); assert.equal(h.state.retirementPending, true);
    assert.equal(h.count('disconnect'), 1); assert.equal(h.controller.canRefresh(), false);
    assert.equal(JSON.stringify(h.state).includes(SECRET), false);
  }
});

test('late subscription teardown cannot detach a replacement service or publish its error', async () => {
  const gate = deferred(); const old = harness({ subscribeGate: gate }); const next = harness({ registry: idle() });
  const firstAttach = old.controller.attach(old.port); await flush();
  await old.controller.attach(next.port); gate.resolve(); await firstAttach;
  assert.equal(old.unlistened, 1); assert.equal(old.count('status'), 0);
  assert.equal(next.count('status'), 1); assert.equal(old.state.status.session, null);
  old.subscriptions[0].listener(connected(999)); assert.equal(old.state.status.session, null);
  old.controller.dispose(); assert.equal(next.unlistened, 1);
});

test('cleanup-unknown and equal-revision contradictions stay blocked after late success', async () => {
  const h = await attached(); h.controller.disconnect(); h.last('disconnect').resolve(retiring()); await flush();
  h.publish(unknown()); assert.equal(h.state.blocked, true); assert.equal(h.controller.canRefresh(), false);
  h.publish(connected(6)); assert.equal(h.state.status.session.state, 'cleanup-unknown');
  await h.controller.checkStatus(); assert.equal(h.state.blocked, true); assert.equal(h.controller.disconnect(), false);
  const second = await attached(); const conflict = connected(); conflict.account.value.login = 'Different'; second.publish(conflict);
  assert.equal(second.state.blocked, true); second.publish(connected(3)); assert.equal(second.state.blocked, true);
  for (const field of ['repository', 'automation']) {
    for (const state of ['unavailable', 'stale']) {
      const value = connected(3);
      for (const name of ['repository', 'automation']) {
        value[name].state = state; value[name].reason = 'network-unavailable';
        if (state === 'unavailable') { value[name].value = null; value[name].observedAt = null; }
      }
      assert.ok(parseGitHubConnectionStatus(value));
      value[field].reason = 'cleanup-unknown'; assert.equal(parseGitHubConnectionStatus(value), null);
      const original = await attached(); original.publish(value);
      assert.equal(original.state.blocked, true); assert.equal(original.state.error, 'response-invalid');
      assert.equal(original.controller.canRefresh(), false);
      original.publish(connected(4)); assert.equal(original.controller.canRefresh(), false);
    }
  }
});

test('expiry is native status, not a renderer clock or renewal; disposal only requests retirement', async () => {
  const h = await attached(); const expired = staleFacts(connected(3), 'expired'); expired.session.state = 'expired';
  h.publish(expired); await h.controller.checkStatus(); await h.controller.checkStatus();
  assert.equal(h.state.status.session.expiresAt, EXPIRY); assert.equal(h.controller.canRefresh(), false);
  assert.equal(h.controller.canDisconnect(), true); h.controller.dispose();
  assert.equal(h.count('disconnect'), 1); assert.equal(h.unlistened, 1);
  h.last('disconnect').reject(new Error(SECRET)); await flush();
  assert.equal(JSON.stringify(h.state).includes(SECRET), false);
  const queued = await attached();
  const count = queued.count('status');
  const read = queued.controller.checkStatus(); queued.controller.dispose(); await read;
  assert.equal(queued.count('status'), count, 'a retired queued read must not invoke the old port');
  assert.equal(queued.count('disconnect'), 1);
});
