// Inert closed public DATA and controlled original promises only. This file
// executes no Git, Python, filesystem/native operation, credentials or network.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GitReadController } from '../src/gitReadController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { createGitReadApi, gitReadRequest, parseGitReadStatus, parseGitReadStartResult } from '../src/gitReadProtocol.ts';

const REV = 'a'.repeat(64), REF = 'b'.repeat(64), HEAD = '1'.repeat(40), PATH = 'src/Main.kt';
const clone = (v) => structuredClone(v);
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };
const observe = () => ({ kind: 'observe', expectedRevision: null, paths: [], staged: false });
const diffAction = (paths = [PATH], staged = false) => ({ kind: 'diff', expectedRevision: REV, paths, staged });
const historyAction = () => ({ kind: 'history', expectedRevision: REV, paths: [], staged: false });
const observation = () => ({ observation: { revision: REV, head: HEAD, branch: 'refs/heads/demo', unborn: false, detached: false,
  changes: [{ path: PATH, index: ' ', worktree: 'M', kind: 'file', conflict: false }], remotes: ['origin'], restrictions: [] }, referenceRevision: REF,
  tracking: { state: 'complete', remote: 'origin', mergeRef: 'refs/heads/demo', localRef: 'refs/remotes/origin/demo', head: HEAD, ahead: 1, behind: 0 }, basis: 'local-refs-no-fetch' });
const history = () => ({ revision: REV, referenceRevision: REF, head: HEAD, commits: [{ oid: HEAD, parents: [], committedAt: 1000 }], hasMore: false,
  shallow: false, withheld: ['message', 'author', 'email', 'signature'], basis: 'local-refs-no-fetch' });
const operation = (phase = 'running', action = observe(), extra = {}) => ({ operationId: 'git-read-1',
  context: { projectId: 'project-a', generation: 7, revision: 'document-4' }, action, phase,
  outcome: phase === 'settled' ? 'ok' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : null,
  reason: phase === 'cleanup-unknown' ? 'unknown' : null,
  result: phase === 'settled' ? action.kind === 'observe' ? observation() : action.kind === 'history' ? history() :
    { revision: REV, staged: action.staged, paths: action.paths, text: '+ synthetic changed line\n', withheld: null } : null, ...extra });
const status = (op = null, extra = {}) => ({ schemaVersion: 1, documentRevision: 4, available: true, operation: op, ...extra });
const started = (args, value) => ({ schemaVersion: 1, admission: 'started', request: args, status: value, reason: null });
const refused = (args, value = status(), reason = 'stale-observation') => ({ schemaVersion: 1, admission: 'refused', request: args, status: value, reason });
function harness() {
  const calls = [];
  const api = Object.fromEntries(['start', 'status', 'cancel'].map((kind) => [kind, (raw) => {
    assert.ok(raw instanceof Uint8Array); const d = deferred(), args = JSON.parse(new TextDecoder().decode(raw));
    calls.push({ kind, raw, args, ...d, resolve: (value) => d.resolve(kind === 'start' && !Object.hasOwn(value, 'admission') ? started(args, value) : value) }); return d.promise;
  }]));
  let binding = { api, session: {}, projectId: 'project-a', epoch: 0, blocked: null };
  const controller = new GitReadController({ current: () => binding });
  controller.syncContext();
  const repository = new GitRepositoryController('project-a', controller.port('project-a'));
  return { api, controller, repository, calls, get state() { return controller.getSnapshot(); }, get binding() { return binding; },
    context: (change) => { binding = { ...binding, ...change }; controller.syncContext(); },
    last: (kind) => calls.filter((c) => c.kind === kind).at(-1), count: (kind) => calls.filter((c) => c.kind === kind).length };
}
async function checked(h = harness(), value = status()) { const p = h.controller.checkStatus(); h.last('status').resolve(value); await p; return h; }
async function complete(h, pending, action = observe(), operationId = 'git-read-1') {
  h.last('start').resolve(status(operation('running', action, { operationId }))); await flush();
  const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled', action, { operationId }))); await p; await pending;
}
async function observed(h) { h ??= await checked(); const p = h.repository.refresh(); await complete(h, p); return h; }
const draft = (h) => { h.repository.editDraft('message', 'Unsent local draft'); h.repository.editDraft('authorName', 'Fixture'); h.repository.editDraft('authorEmail', 'fixture@example.invalid'); };

// These statuses are syntax fixtures, never native admission/finality evidence.
test('three RAW commands are closed and preview has no invoke route', async () => {
  const calls = [], invoke = async (...args) => { calls.push(args); return status(); };
  assert.equal(createGitReadApi('preview', invoke), null); assert.equal(createGitReadApi('fixture', invoke), null);
  const port = createGitReadApi('native', invoke);
  for (const [name, args] of [['status', {}], ['start', { projectId: 'project-a', expectedDocumentRevision: 4, action: observe() }], ['cancel', { operationId: 'git-read-1' }]]) {
    const raw = gitReadRequest(name, args); const before = raw.slice(); await port[name](raw); raw.fill(0);
    assert.equal(calls.at(-1)[0], `git_read_${name}`); assert.deepEqual(calls.at(-1)[1], before);
  }
  for (const args of [{ projectId: 'project-a', expectedDocumentRevision: 0, action: observe() },
    { projectId: 'project-a', expectedDocumentRevision: 4, action: { ...observe(), path: '/not-a-renderer-source' } },
    { projectId: 'project-a', expectedDocumentRevision: 4, action: diffAction(['../outside']) },
    { projectId: 'project-a', expectedDocumentRevision: 4, action: diffAction(['b', 'a']) },
    { projectId: 'project-a', expectedDocumentRevision: 4, action: diffAction(['a', 'a']) }]) assert.equal(gitReadRequest('start', args), null);
  assert.equal(gitReadRequest('status', { path: '/not-allowed' }), null);
  assert.equal(gitReadRequest('cancel', { operationId: 'git-read-1', retry: true }), null);
  await assert.rejects(port.status(new Uint8Array(1024))); assert.equal(calls.length, 3);
});

test('status parser clones closed bounded DATA and rejects private fields, getters and false tracking/history', () => {
  const raw = status(operation('settled')), parsed = parseGitReadStatus(raw);
  assert.ok(parsed); raw.operation.result.tracking.ahead = 99; assert.equal(parsed.operation.result.tracking.ahead, 1);
  assert.ok(Object.isFrozen(parsed.operation.result.observation.changes[0]));
  let getters = 0; const bad = status(); Object.defineProperty(bad, 'available', { enumerable: true, get() { getters++; return true; } });
  assert.equal(parseGitReadStatus(bad), null); assert.equal(getters, 0);
  for (const mutate of [(s) => { s.secret = 'not-allowed'; }, (s) => { s.operation.result.basis = 'fresh-online'; },
    (s) => { s.operation.result.tracking.state = 'detached'; }, (s) => { s.operation.result.tracking.ahead = 10001; },
    (s) => { s.operation.result.tracking.localRef = null; }, (s) => { s.operation.phase = 'running'; },
    (s) => { s.operation.context.generation = -1; }, (s) => { s.operation.outcome = 'connected'; }]) {
    const s = status(operation('settled')); mutate(s); assert.equal(parseGitReadStatus(s), null);
  }
  assert.ok(parseGitReadStatus(status(operation('settled', historyAction()))));
  for (const mutate of [(s) => { s.operation.result.commits[0].message = 'not-allowed'; },
    (s) => { s.operation.result.commits[0].committedAt = Number.MAX_SAFE_INTEGER + 1; },
    (s) => { s.operation.result.commits[0].parents = [HEAD]; }, (s) => { s.operation.result.hasMore = true; },
    (s) => { s.operation.result.head = '2'.repeat(40); }, (s) => { s.operation.result.withheld = []; }]) {
    const s = status(operation('settled', historyAction())); mutate(s); assert.equal(parseGitReadStatus(s), null);
  }
});

test('idle check never reads files; unavailable and peer-owned contexts cannot start', async () => {
  const h = harness(); assert.equal(h.calls.length, 0); assert.equal(await h.repository.refresh(), false);
  await checked(h, status(null, { available: false })); assert.equal(await h.repository.refresh(), false);
  assert.equal(h.count('start'), 0); h.context({ blocked: 'Another original task is active.' });
  assert.equal(await h.controller.checkStatus(), false); assert.equal(h.count('status'), 1);
});

test('real repository controller consumes only a settled original observation and keeps local draft', async () => {
  const h = await checked(); draft(h); const pending = h.repository.refresh();
  assert.equal(h.repository.hasWriter(), false); assert.ok(h.controller.ownerReason());
  assert.deepEqual(h.last('start').args, { projectId: 'project-a', expectedDocumentRevision: 4, action: observe() });
  h.last('start').resolve(status(operation())); await flush();
  assert.equal(h.repository.getSnapshot().observation, null); assert.equal(h.repository.getSnapshot().busy, 'observe');
  const checking = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await checking; await pending;
  assert.equal(h.repository.getSnapshot().observation.revision, REV); assert.equal(h.state.observation.tracking.ahead, 1);
  assert.equal(h.repository.getSnapshot().draft.message, 'Unsent local draft'); assert.equal(h.controller.ownerReason(), null);
  assert.equal(h.repository.prepareReason('commit'), 'unavailable');
});

test('terminal status first cannot release the still-pending original Start promise or rewind on late start', async () => {
  const h = await checked(); let ended = false; const pending = h.repository.refresh().then(() => { ended = true; });
  const checking = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await checking;
  assert.equal(ended, false); assert.ok(h.controller.ownerReason()); assert.equal(h.state.observation, null);
  h.last('start').resolve(status(operation())); await pending;
  assert.equal(h.state.original.phase, 'settled'); assert.equal(h.state.observation.observation.revision, REV); assert.equal(h.controller.ownerReason(), null);
});

test('pending Start, serial status and independent exact Stop each keep original promise custody', async () => {
  const h = await checked(), pending = h.repository.refresh();
  const first = h.controller.checkStatus(); assert.equal(await h.controller.checkStatus(), false);
  h.last('status').resolve(status(operation())); await first;
  const next = h.controller.checkStatus(), cancel = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: 'git-read-1' }); assert.equal(await h.controller.cancel(), false);
  h.last('status').resolve(status(operation('settled', observe(), { outcome: 'cancelled', reason: 'authorization', result: null }))); await next;
  h.last('start').resolve(status(operation())); await flush(); assert.ok(h.controller.ownerReason());
  h.last('cancel').resolve(status(operation('stopping'))); await cancel; await pending;
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.state.original.outcome, 'cancelled'); assert.equal(h.state.observation, null);
});

test('lost Start reply is not no-admission; only fresh matching original status can settle it', async () => {
  const h = await checked(), pending = h.repository.refresh();
  h.last('start').reject(new Error('PRIVATE_SYNTHETIC_ERROR')); await flush();
  assert.equal(h.state.issue, 'acknowledgement-missing'); assert.ok(h.controller.ownerReason());
  assert.equal(h.count('start'), 1); assert.equal(JSON.stringify(h.state).includes('PRIVATE_SYNTHETIC_ERROR'), false);
  const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await p; await pending;
  assert.equal(h.repository.getSnapshot().observation.revision, REV); assert.equal(h.count('start'), 1);
});

test('lost reply after exact terminal requires fresh same terminal and ignores object-key ordering', async () => {
  const h = await checked(), pending = h.repository.refresh();
  const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await p;
  h.last('start').reject(new Error('lost handoff')); await flush(); assert.ok(h.controller.ownerReason());
  const ordered = (v) => Array.isArray(v) ? v.map(ordered) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).reverse().map(([k, v]) => [k, ordered(v)])) : v;
  const next = h.controller.checkStatus(); h.last('status').resolve(ordered(status(operation('settled')))); await next; await pending;
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.repository.getSnapshot().blocked, null);
});

test('actual cleanup Unknown pins evidence and unsent Stop despite later ordinary replies', async () => {
  for (const observedOnly of [false, true]) {
    const h = await checked(); const pending = observedOnly ? null : h.repository.refresh();
    const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('cleanup-unknown'))); await p;
    const original = h.state.original; assert.equal(h.controller.canCancel(), true);
    const later = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await later;
    assert.strictEqual(h.state.original, original); assert.equal(h.controller.canCancel(), true);
    const stopped = h.controller.cancel(); h.last('cancel').resolve(status(operation('settled'))); await stopped;
    if (pending) { h.last('start').resolve(status(operation('settled'))); await pending; }
    assert.strictEqual(h.state.original, original); assert.equal(h.state.uncertain, true); assert.ok(h.controller.ownerReason());
    assert.equal(await h.repository.refresh(), false); assert.equal(h.count('start'), observedOnly ? 0 : 1);
  }
});

test('foreign ID, native generation, project, action or terminal contradiction blocks without adopting DATA', async () => {
  for (const mutate of [(o) => { o.operationId = 'another-original'; }, (o) => { o.context.generation++; },
    (o) => { o.context.projectId = 'project-b'; }, (o) => { o.context.revision = 'document-5'; },
    (o) => { o.action = historyAction(); o.result = history(); }]) {
    const h = await checked(), pending = h.repository.refresh(); h.last('start').resolve(status(operation())); await flush();
    const p = h.controller.checkStatus(), other = operation('settled'); mutate(other); h.last('status').resolve(status(other)); await p; await pending;
    assert.equal(h.state.uncertain, true); assert.ok(h.controller.ownerReason()); assert.equal(h.repository.getSnapshot().observation, null);
  }
  const h = await checked(), pending = h.repository.refresh();
  const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await p;
  h.last('start').resolve(status(operation('settled', observe(), { outcome: 'refused', reason: 'stale-observation', result: null }))); await pending;
  assert.equal(h.state.uncertain, true); assert.equal(h.state.original.outcome, 'ok'); assert.equal(h.state.observation, null);
});

test('project/API/session/epoch ABA cannot adopt a late original, and old project port never retargets', async () => {
  for (const change of [{ projectId: 'project-b', epoch: 1 }, { api: {}, epoch: 1 }, { session: {}, epoch: 1 }, { epoch: 1 }]) {
    const h = await checked(); draft(h); const pending = h.repository.refresh(), old = h.binding;
    h.context(change); h.context({ ...old, epoch: 2 });
    h.last('start').resolve(status(operation())); await flush();
    const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await p; await pending;
    assert.equal(h.state.observation, null); assert.equal(h.repository.getSnapshot().stale, true);
    assert.equal(h.repository.getSnapshot().draft.message, 'Unsent local draft'); assert.equal(h.controller.ownerReason(), null);
  }
  const h = await observed(); h.context({ session: {}, epoch: 1 }); await checked(h);
  assert.equal(await h.repository.refresh(), false); assert.equal(h.repository.getSnapshot().issue, 'inactive'); assert.equal(h.count('start'), 1);
});

test('context change while idle parsing cannot publish old status or errors', async () => {
  const h = harness(), p = h.controller.checkStatus(); let entered = false;
  const value = new Proxy(status(), { getOwnPropertyDescriptor(target, key) {
    if (!entered) { entered = true; h.context({ projectId: 'project-b', epoch: 1 }); }
    return Reflect.getOwnPropertyDescriptor(target, key);
  } });
  h.last('status').resolve(value); await p;
  assert.equal(h.state.status, null); assert.equal(h.state.issue, null); assert.equal(h.count('start'), 0);
});

test('synchronous context/peer change before invoke is a branded local decline, not fabricated native settlement', async () => {
  for (const change of [{ projectId: 'project-b', epoch: 1 }, { blocked: 'Peer took original authority.' }]) {
    const h = await checked(); let done = false;
    const off = h.controller.subscribe(() => { if (done || !h.controller.ownerReason()) return; done = true; h.context(change); });
    await h.repository.refresh(); off();
    assert.equal(h.count('start'), 0); assert.equal(h.controller.ownerReason(), null); assert.equal(h.repository.getSnapshot().blocked, null);
  }
});

test('malformed/lost idle observation is unavailable, while malformed original keeps status/Stop reachable', async () => {
  const h = await checked(); const p = h.controller.checkStatus(); h.last('status').resolve({ available: true }); await p;
  assert.equal(h.state.status, null); assert.equal(await h.repository.refresh(), false);
  await checked(h); const pending = h.repository.refresh(); h.last('start').resolve(status(operation())); await flush();
  const first = h.controller.checkStatus(); h.last('status').resolve({ malformed: true }); await first;
  assert.equal(h.state.issue, 'acknowledgement-missing'); assert.equal(h.controller.canCancel(), true);
  const next = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await next; await pending;
  assert.equal(h.controller.ownerReason(), null);
});

test('selected diff is exact and metadata History never grants remote freshness or writes', async () => {
  const h = await observed(); draft(h); h.repository.select(PATH, true);
  let pending = h.repository.preview(false); assert.deepEqual(h.last('start').args.action, diffAction());
  await complete(h, pending, diffAction(), 'git-read-2');
  assert.equal(h.repository.getSnapshot().diff.text, '+ synthetic changed line\n');
  pending = h.controller.readHistory('project-a', REV); await complete(h, pending, historyAction(), 'git-read-3');
  assert.equal(h.state.history.basis, 'local-refs-no-fetch'); assert.deepEqual(h.state.history.withheld, ['message', 'author', 'email', 'signature']);
  assert.equal(h.repository.hasWriter(), false); assert.equal(h.repository.getSnapshot().draft.message, 'Unsent local draft');
});

test('a previous settled read cannot be mistaken for a new original Start', async () => {
  const h = await checked(harness(), status(operation('settled'))), pending = h.repository.refresh();
  const p = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled'))); await p;
  assert.equal(h.repository.getSnapshot().observation, null); assert.ok(h.controller.ownerReason());
  h.last('start').resolve(status(operation('running', observe(), { operationId: 'git-read-2' }))); await flush();
  const next = h.controller.checkStatus(); h.last('status').resolve(status(operation('settled', observe(), { operationId: 'git-read-2' }))); await next; await pending;
  assert.equal(h.state.original.operationId, 'git-read-2'); assert.equal(h.controller.ownerReason(), null);
});

test('final callback context change cannot hand stale DATA to the real repository consumer', async () => {
  const h = await checked(); draft(h); let replaced = false;
  const off = h.controller.subscribe(() => {
    if (replaced || !h.state.observation) return; replaced = true;
    // This deliberately does NOT invalidate the GitRepositoryController. The
    // adapter must recheck its own binding after synchronous render callbacks.
    h.context({ projectId: 'project-b', epoch: 1 });
  });
  const pending = h.repository.refresh(); await complete(h, pending); off();
  assert.equal(h.repository.getSnapshot().observation, null); assert.equal(h.repository.getSnapshot().blocked, null);
  assert.equal(h.repository.getSnapshot().draft.message, 'Unsent local draft'); assert.equal(h.state.stale, true);
});

test('retained history cannot be labelled as this project after service or project context replacement', async () => {
  const h = await observed(); const pending = h.controller.readHistory('project-a', REV); await complete(h, pending, historyAction(), 'git-read-2');
  assert.equal(h.state.historyCurrent, true); const original = h.state.history;
  h.context({ session: {}, epoch: 1 });
  assert.equal(h.state.historyCurrent, false); assert.strictEqual(h.state.history, original);
});


test('clean native stale refusal discharges only the exact never-admitted request after all promises settle', async () => {
  const h = await checked(); draft(h); const pending = h.repository.refresh();
  const checking = h.controller.checkStatus();
  h.last('start').resolve(refused(h.last('start').args, status(null, { documentRevision: 5 }))); await flush();
  assert.ok(h.controller.ownerReason()); assert.equal(h.repository.getSnapshot().busy, 'observe');
  h.last('status').resolve(status()); await checking; await pending;
  assert.equal(h.repository.getSnapshot().blocked, null); assert.equal(h.repository.getSnapshot().issue, 'stale-observation');
  assert.equal(h.repository.getSnapshot().draft.message, 'Unsent local draft'); assert.equal(h.controller.ownerReason(), null);
  assert.equal(h.state.status, null); assert.equal(h.count('start'), 1); assert.equal(await h.repository.refresh(), false);
  await checked(h, status(null, { documentRevision: 5 })); assert.equal(h.controller.readReason('project-a'), null);
  assert.equal(h.count('start'), 1); // Checking permission never resubmits a read.
});

test('closed no-admission cannot discharge a foreign request, malformed response or an already seen original', async () => {
  assert.ok(parseGitReadStartResult(refused({ projectId: 'project-a', expectedDocumentRevision: 4, action: observe() })));
  for (const extra of [{ nativeFinality: 'settled' }, { reason: 'unknown' }, { admission: 'no-effect' }]) {
    assert.equal(parseGitReadStartResult({ ...refused({ projectId: 'project-a', expectedDocumentRevision: 4, action: observe() }), ...extra }), null);
  }
  for (const change of [(r) => { r.request.projectId = 'foreign'; }, (r) => { r.request.expectedDocumentRevision++; },
    (r) => { r.request.action = historyAction(); }, (r) => { r.status.extra = true; }]) {
    const h = await checked(); void h.repository.refresh(); const r = refused(clone(h.last('start').args)); change(r);
    h.last('start').resolve(r); await flush(); assert.ok(h.controller.ownerReason()); assert.equal(h.state.uncertain, true);
    assert.equal(await h.repository.refresh(), false); assert.equal(h.count('start'), 1);
  }
  const h = await checked(), pending = h.repository.refresh(), checking = h.controller.checkStatus();
  h.last('status').resolve(status(operation())); await checking;
  h.last('start').resolve(refused(h.last('start').args)); await pending;
  assert.ok(h.controller.ownerReason()); assert.equal(h.state.uncertain, true); assert.equal(h.controller.canCancel(), true);
});

test('a clean declined request cannot discard an older native original disclosed by that same reply', async () => {
  const h = await checked(), pending = h.repository.refresh();
  const previous = operation('running', observe(), { operationId: 'old-native-read', context: { projectId: 'foreign', generation: 1, revision: 'document-1' } });
  h.context({ projectId: 'project-b', epoch: 1 });
  h.last('start').resolve(refused(h.last('start').args, status(previous), 'busy')); await pending;
  assert.equal(h.state.original.operationId, 'old-native-read'); assert.ok(h.controller.ownerReason());
  const stopping = h.controller.cancel(); assert.deepEqual(h.last('cancel').args, { operationId: 'old-native-read' });
  h.last('cancel').resolve(status({ ...previous, phase: 'settled', outcome: 'cancelled', reason: 'authorization', result: null })); await stopping;
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.state.status, null); assert.equal(h.state.observation, null);
});
