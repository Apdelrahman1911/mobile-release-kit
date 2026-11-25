// Inert DATA and deferred original IPC only. No HTTP, native owner or browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubActivityController } from '../src/githubActivityController.ts';
import { ACTIVITY_EVENT, activityError, activityLink, createGitHubActivityPort, encodeActivityRequest,
  parseActivitySelection, parseActivityStatus } from '../src/githubActivityProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const clone = structuredClone, sha = 'a'.repeat(40), timestamp = '2026-10-20T12:00:00Z';
const target = () => ({ projectBinding: 'f'.repeat(64), repository: 'example/application', accountId: '7', repositoryId: '9' });
const selection = () => ({ kind: 'overview', branch: null });
function connection() {
  return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'example/application' },
    status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'example/application', state: 'connected' },
      account: { state: 'observed', value: { id: '7', login: 'example' } },
      repository: { state: 'observed', value: { id: '9', fullName: 'example/application' } } },
    busy: null, uncertain: false, blocked: false, retirementPending: false, observing: false, error: null };
}
const section = (rows = [], total = rows.length) => ({ state: 'read', reason: 'none', coverage: total === rows.length ? 'complete' : 'windowed', total, rows });
const pull = () => ({ id: '31', number: '3', title: 'Example change', state: 'open', draft: false, headSha: sha,
  headBranch: 'feature/example', headRepository: 'example/application', baseSha: 'b'.repeat(40), baseBranch: 'main', updatedAt: timestamp });
const run = () => ({ id: '40', attempt: 2, name: 'Example workflow', status: 'completed', conclusion: 'skipped', headSha: sha,
  headBranch: 'feature/example', headRepository: 'example/application', event: 'push', createdAt: timestamp, updatedAt: timestamp });
const overview = () => ({ kind: 'overview', branchHead: null, pullRequests: section([pull()], null), workflowRuns: section([run()], 4) });
function idle(revision = 1) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, result: null }; }
function operation(phase = 'running', revision = 2, reason = 'none', selected = selection(), id = 'activity-a') {
  return { ...idle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
    operation: { id, projectId: 'project-a', target: target(), selection: selected, phase, reason } };
}
function done(revision = 3, selected = selection(), data = overview(), id = 'activity-a') {
  return { ...operation('settled', revision, 'none', selected, id), result: { target: target(), selection: selected, observedAt: timestamp, data } };
}
function prDone() {
  return done(3, { kind: 'pull-request', number: '3' }, { kind: 'pull-request', pullRequest: pull(),
    changedFiles: section([{ path: 'app/Main.kt', change: 'modified', additions: 2, deletions: 1 }]),
    reviews: section([{ id: '50', reviewer: 'example-reviewer', state: 'APPROVED', commitSha: 'b'.repeat(40), submittedAt: timestamp }], null),
    commitStatuses: section(), checkRuns: section(), headChecked: true });
}
function deferred() {
  let resolve, reject; const d = { ended: false };
  d.promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  d.resolve = v => { d.ended = true; resolve(v); }; d.reject = e => { d.ended = true; reject(e); }; return d;
}
async function flush() { for (let i = 0; i < 18; i++) await Promise.resolve(); }
const harnesses = [];
function harness() {
  let current = idle(), view = connection(), listener = null, peer = null, detached = 0;
  const calls = [], h = { deferredStatus: false, unlistenThrows: false, readOverride: null };
  const call = (kind, args) => { const d = deferred(); Object.assign(d, { kind, args: clone(args) }); calls.push(d); return d.promise; };
  const port = { mode: 'native', subscribe: async f => { listener = f; return () => {
    if (h.unlistenThrows) throw Error('INERT PRIVATE DETAIL'); listener = null; detached++;
  }; }, status: () => { if (h.deferredStatus) return call('status', {}); calls.push({ kind: 'status', ended: true }); return Promise.resolve(clone(current)); },
    read: args => h.readOverride ? h.readOverride(args) : call('read', args), cancel: args => call('cancel', args) };
  const controller = new GitHubActivityController(() => view, () => typeof peer === 'function' ? peer() : peer);
  Object.assign(h, { port, controller, calls, count: k => calls.filter(c => c.kind === k).length, last: k => calls.filter(c => c.kind === k).at(-1),
    emit(s) { current = clone(s); listener?.(clone(s)); }, rawEmit(s) { listener?.(s); }, retain(s) { current = clone(s); },
    respond(k, s) { current = clone(s); this.last(k).resolve(clone(s)); }, context(v) { view = v; controller.syncContext(); }, peer(v) { peer = v; },
    currentConnection: () => view });
  Object.defineProperties(h, { state: { get: () => controller.getSnapshot() }, detached: { get: () => detached } });
  harnesses.push(h); return h;
}
async function attached() { const h = harness(); h.controller.connect(h.port); await flush(); return h; }
async function ready() { const h = await attached(); h.controller.read(); h.respond('read', done()); await flush(); assert.ok(h.controller.currentResult()); return h; }
test.afterEach(async () => {
  // End only the inert Promises made by this test. This is NOT native finality.
  for (const h of harnesses.splice(0)) {
    for (const c of h.calls) if (!c.ended) c.reject({ code: 'fixture-ended' });
    await flush(); h.controller.dispose();
    for (const c of h.calls) if (!c.ended) c.reject({ code: 'fixture-ended' });
    await flush();
  }
});

test('closed metadata parser distinguishes bounded permission gaps and no-checks from approval', () => {
  for (const s of [idle(), done(), prDone(), operation('cleanup-unknown', 5, 'cleanup-unknown')]) assert.ok(parseActivityStatus(s));
  const gap = prDone(); gap.result.data.checkRuns = { state: 'unavailable', reason: 'forbidden', coverage: 'unknown', total: null, rows: [] };
  assert.ok(parseActivityStatus(gap));
  for (const change of [s => s.result.data.approved = true, s => s.result.data.checkRuns.passed = true,
    s => s.result.data.changedFiles.rows[0].patch = 'INERT PRIVATE', s => s.result.data.pullRequest.url = 'https://other.invalid',
    s => s.result.selection.number = '4', s => s.result.target.repositoryId = '10', s => s.operation.phase = 'running',
    s => s.result.data.reviews.rows.push(clone(s.result.data.reviews.rows[0])), s => s.result.data.reviews.coverage = 'complete',
    s => s.result.data.commitStatuses.total = true]) {
    const s = prDone(); change(s); assert.equal(parseActivityStatus(s), null);
  }
  const raw = done(); let read = 0;
  Object.defineProperty(raw, 'result', { enumerable: true, get() { read++; return null; } });
  assert.equal(parseActivityStatus(raw), null); assert.equal(read, 0);
  assert.equal(parseActivitySelection({ kind: 'rerun', runId: '40', attempt: 2 }), null);
  assert.equal(parseActivitySelection({ kind: 'overview', branch: '../main' }), null);
  const foreign = done(); foreign.operation.selection.branch = foreign.result.selection.branch = 'feature/example'; foreign.result.data.branchHead = sha;
  foreign.result.data.workflowRuns.rows[0].headRepository = 'example-fork/application';
  assert.equal(parseActivityStatus(foreign), null); // Same branch text is not this repository's branch.
});

test('actual composed bridge emits exactly three RAW commands; preview does not acquire a route', async () => {
  const calls = [], events = [];
  const api = createNativeApi('native', async (name, raw) => { calls.push([name, raw]); return idle(); }, async name => { events.push(name); return () => {}; });
  const port = api.githubActivity; assert.ok(port);
  await port.status(); await port.read({ sessionId: 'session-a', projectId: 'project-a', expectedRevision: 1, expectedConnectionRevision: 12, selection: selection() });
  await port.cancel({ operationId: 'activity-a' }); await port.subscribe(() => {});
  assert.deepEqual(calls.map(c => c[0]), ['github_activity_status', 'github_activity_read', 'github_activity_cancel']);
  assert.deepEqual(events, [ACTIVITY_EVENT]);
  for (const [, raw] of calls) { assert.ok(raw instanceof Uint8Array); assert.ok(raw.length <= 1024); }
  assert.equal(createGitHubActivityPort('preview', () => assert.fail('preview invoked'), async () => {}), null);
  assert.equal(createGitHubActivityPort('native', () => assert.fail('unlistened invoked'), null), null);
  assert.equal(previewApi.githubActivity, undefined);
  for (const body of [{ ...JSON.parse(new TextDecoder().decode(calls[1][1])), token: 'INERT' }, { repository: 'other/app' }])
    assert.equal(encodeActivityRequest('github_activity_read', body), null);
});

test('links use only canonical admitted coordinates/numeric IDs and error parsing invokes no getter', () => {
  assert.equal(activityLink('example/application', 'pull', '3'), 'https://github.com/example/application/pull/3');
  assert.equal(activityLink('example/application', 'run', '40'), 'https://github.com/example/application/actions/runs/40');
  for (const repo of ['https://github.com/example/app', 'example/app?x', 'example/app.git', 'example/../other']) assert.equal(activityLink(repo, 'pull', '3'), null);
  assert.equal(activityLink('example/application', 'pull', '3/evil'), null);
  let read = 0; const error = { get code() { read++; return 'github_activity_refused_busy'; } };
  assert.equal(activityError(error).notAdmitted, false); assert.equal(read, 0);
});

test('mount, context, branch drafts and status do not start a remote read', async () => {
  const h = await attached(); h.controller.setBranch('feature/example'); h.controller.syncContext(); h.controller.checkStatus(); await flush();
  assert.equal(h.count('read'), 0); assert.equal(h.state.branchDraft, 'feature/example');
  h.peer('An original local task is active'); h.controller.read(); assert.equal(h.count('read'), 0);
  h.peer(null); const c = connection(); c.status.repository.state = 'unavailable'; h.context(c); h.controller.read(); assert.equal(h.count('read'), 0);
});

test('event before original reply never drops that Promise; historical reply cannot rewind the result', async () => {
  const h = await attached(); h.controller.read(); h.emit(operation()); h.emit(done());
  assert.equal(h.state.pending, true); assert.equal(h.controller.currentResult(), null); assert.ok(h.controller.ownerReason());
  h.respond('read', operation()); await flush();
  assert.equal(h.state.pending, false); assert.equal(h.state.status.revision, 3); assert.ok(h.controller.currentResult());
});

test('original status and Stop are independently retained while read reply is pending', async () => {
  const h = await attached(); h.controller.read(); h.emit(operation()); h.deferredStatus = true; h.controller.checkStatus(); h.controller.cancel();
  assert.equal(h.count('read'), 1); assert.equal(h.count('status'), 2); assert.equal(h.count('cancel'), 1);
  h.emit(operation('settled', 4, 'cancelled')); h.respond('cancel', operation('stopping', 3, 'cancelled')); await flush();
  assert.equal(h.state.pending, true); assert.ok(h.controller.ownerReason());
  h.last('status').resolve(operation()); h.last('read').resolve(operation()); await flush();
  assert.equal(h.state.pending, false); assert.equal(h.controller.ownerReason(), null); assert.equal(h.state.error, 'cancelled');
});

test('context/API/away-and-back invalidation keeps original controls and refuses stale row actions', async () => {
  const h = await ready(), old = h.controller.currentResult();
  const original = connection(), other = connection(); other.context.projectId = 'project-b'; h.context(other); h.context(original);
  assert.equal(h.controller.currentResult(), null); h.controller.readSelection(old, { kind: 'pull-request', number: '3' }); assert.equal(h.count('read'), 1);
  h.controller.read(); h.emit(operation('running', 4, 'none', selection(), 'activity-b'));
  const replacement = harness(); h.controller.connect(replacement.port); await flush();
  assert.equal(h.detached, 0); assert.equal(replacement.count('status'), 0); assert.equal(h.count('cancel'), 1);
  h.respond('read', operation('running', 4, 'none', selection(), 'activity-b')); h.respond('cancel', operation('settled', 5, 'cancelled', selection(), 'activity-b')); await flush();
  assert.equal(h.detached, 1); assert.equal(replacement.count('status'), 1); assert.equal(h.controller.currentResult(), null);
});

test('only exact still-current overview rows choose detail reads, and private draft survives refusal', async () => {
  const h = await ready(), old = h.controller.currentResult();
  h.controller.readSelection(clone(old), { kind: 'pull-request', number: '3' });
  h.controller.readSelection(old, { kind: 'workflow-run', runId: '40', attempt: 3 }); assert.equal(h.count('read'), 1);
  h.controller.readSelection(old, { kind: 'pull-request', number: '3' }); assert.equal(h.count('read'), 2);
  const s = prDone(); s.revision = 5; s.operation.id = 'activity-b'; h.respond('read', s); await flush();
  assert.equal(h.controller.currentResult().data.kind, 'pull-request');
  h.controller.setBranch('feature/example'); h.controller.read(); h.last('read').reject({ code: 'github_activity_refused_target_changed' }); await flush();
  assert.equal(h.state.branchDraft, 'feature/example'); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false);
  assert.match(h.controller.readReason(), /status/); assert.equal(h.count('read'), 3);
});

test('lost acknowledgement and cleanup Unknown stay absorbing; late status cannot erase original Stop', async () => {
  const h = await attached(); h.controller.read(); h.last('read').reject(new Error('INERT PRIVATE TRANSPORT DETAIL')); await flush();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentResult(), null);
  h.emit(operation()); assert.equal(h.controller.canCancel(), true); h.controller.cancel(); assert.equal(h.count('cancel'), 1);
  h.respond('cancel', operation('settled', 4, 'cancelled')); h.emit(done(5)); await flush();
  assert.equal(h.state.uncertain, true); assert.ok(h.controller.ownerReason()); h.controller.read(); assert.equal(h.count('read'), 1);
  const observed = await attached(); observed.emit(operation('cleanup-unknown', 2, 'cleanup-unknown')); const retained = observed.state.status;
  observed.emit(done(3)); assert.strictEqual(observed.state.status, retained); assert.equal(observed.controller.canCancel(), true);
  observed.controller.cancel(); observed.respond('cancel', operation('settled', 4, 'cancelled')); await flush();
  assert.strictEqual(observed.state.status, retained); assert.equal(observed.state.error, 'cleanup-unknown');
});

test('malformed reply and contradictory terminal evidence retain uncertainty instead of another read', async () => {
  const h = await attached(); h.controller.read(); h.respond('read', { ...done(), token: 'INERT' }); await flush();
  assert.equal(h.state.uncertain, true); assert.ok(h.controller.ownerReason());
  const settled = await ready(), changed = done(4); changed.result.data.workflowRuns.rows[0].conclusion = 'success'; settled.emit(changed);
  assert.equal(settled.state.uncertain, true); assert.equal(settled.controller.currentResult(), null);
});

test('listener reentrancy rechecks context, connection revision, peer and pre-invoke cancellation', async () => {
  for (const effect of [h => h.controller.beforeWorkspaceAction(), h => h.currentConnection().status.revision++,
    h => h.peer('another owner'), h => h.controller.cancel()]) {
    const h = await attached(); let used = false;
    h.controller.subscribe(() => { if (!used && h.state.pending) { used = true; effect(h); } });
    h.controller.read(); assert.equal(h.count('read'), 0); assert.equal(h.state.pending, false);
  }
  const h = await attached(); h.controller.subscribe(() => { throw Error('INERT render failure'); });
  h.controller.read(); assert.equal(h.count('read'), 1); h.respond('read', done()); await flush(); assert.ok(h.controller.currentResult());
});

test('entry throw/non-Promise is uncertain, never ordinary no-admission', async () => {
  for (const invoke of [() => { throw { code: 'github_activity_refused_busy' }; }, () => done()]) {
    const h = await attached(); h.readOverride = invoke; h.controller.read(); await flush();
    assert.equal(h.state.uncertain, true); assert.equal(h.state.pending, true); assert.ok(h.controller.ownerReason());
  }
});

test('Stop requested before operation ID is sent once after the exact original ID arrives', async () => {
  const h = await attached(); h.controller.read(); assert.equal(h.controller.canCancel(), true); h.controller.cancel();
  assert.equal(h.count('cancel'), 0); assert.equal(h.controller.canCancel(), false);
  h.emit(operation()); assert.equal(h.count('cancel'), 1); assert.equal(h.last('cancel').args.operationId, 'activity-a');
  h.respond('read', operation()); h.respond('cancel', operation('settled', 3, 'cancelled')); await flush();
  assert.equal(h.state.pending, false); assert.equal(h.count('read'), 1); assert.equal(h.count('cancel'), 1);
});

test('idle status owns rebind until joined; failed status invalidates result freshness but not draft', async () => {
  const h = await ready(); h.deferredStatus = true; h.controller.checkStatus(); assert.ok(h.controller.ownerReason());
  h.last('status').reject({ code: 'lost-status' }); await flush(); assert.equal(h.controller.currentResult(), null); assert.match(h.controller.readReason(), /status/);
  h.controller.setBranch('main'); h.controller.checkStatus(); const next = harness(); h.controller.connect(next.port);
  assert.equal(h.detached, 0); assert.equal(next.count('status'), 0);
  h.last('status').resolve(done()); await flush(); assert.equal(h.detached, 1); assert.equal(next.count('status'), 1); assert.equal(h.state.branchDraft, 'main');
});

test('disposal retains pending originals and listener-close failure blocks replacement', async () => {
  const h = await attached(); h.controller.read(); h.emit(operation()); h.controller.dispose(); assert.equal(h.detached, 0);
  assert.equal(h.count('cancel'), 1); h.respond('read', operation()); h.respond('cancel', operation('settled', 3, 'cancelled')); await flush();
  assert.equal(h.detached, 1); assert.equal(h.controller.currentResult(), null);
  const idleOwner = await attached(); idleOwner.unlistenThrows = true; const next = harness(); idleOwner.controller.connect(next.port); await flush();
  assert.equal(next.count('status'), 0); assert.equal(idleOwner.state.uncertain, true); assert.ok(idleOwner.controller.ownerReason()); assert.equal(idleOwner.controller.canCheck(), false);
});

test('descriptor reentrancy cannot publish current data for a retired original context', async () => {
  const h = await attached(); h.controller.read(); let retired = false;
  const value = new Proxy(done(), { getOwnPropertyDescriptor(object, key) {
    if (!retired) { retired = true; h.controller.beforeWorkspaceAction(); }
    return Reflect.getOwnPropertyDescriptor(object, key);
  } });
  h.last('read').resolve(value); await flush();
  assert.equal(h.controller.currentResult(), null); assert.equal(h.state.pending, false); assert.equal(h.count('read'), 1);
});
