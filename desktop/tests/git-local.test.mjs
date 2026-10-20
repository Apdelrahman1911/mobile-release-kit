import assert from 'node:assert/strict';
import test from 'node:test';
import { createGitLocalApi, gitLocalRequest, parseGitLocalStatus, parseGitLocalStartResult } from '../src/gitLocalProtocol.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';

const hash = 'a'.repeat(64), index = 'b'.repeat(64), digest = 'c'.repeat(64), head = 'd'.repeat(40);
const decode = (bytes) => JSON.parse(new TextDecoder().decode(bytes));
const context = (projectId = 'project-1', revision = 1) => ({ projectId, generation: 1, revision: `document-${revision}` });
const action = (kind = 'stage', paths = ['app.txt']) => ({ kind, expectedRevision: hash, paths: kind === 'commit' ? [] : paths });
const observation = () => ({ revision: hash, head, branch: 'refs/heads/main', unborn: false, detached: false,
  changes: [{ path: 'app.txt', index: 'M', worktree: 'M', kind: 'file', conflict: false },
    { path: 'other.txt', index: 'A', worktree: ' ', kind: 'file', conflict: false }], remotes: [], restrictions: [] });
const idle = (operation = null, review = null, documentRevision = 1) => ({ schemaVersion: 1, documentRevision, available: true, review, operation });
const operation = (id, phase = 'prepare', kind = 'stage', extra = {}) => ({ operationId: id, context: context(), phase,
  action: action(kind), stage: 'running', outcome: null, reason: null, result: null, ...extra });
function prepared(id = 'review-1', kind = 'stage', paths = kind === 'commit' ? ['app.txt', 'other.txt'] : ['app.txt']) {
  const a = action(kind);
  return { reviewId: id, context: context(), action: a,
    review: { action: kind, expectedRevision: hash, paths, wholeIndex: kind === 'commit', head, branch: 'refs/heads/main', expectedIndex: index, reviewDigest: digest },
    diff: { revision: hash, staged: kind !== 'stage', paths, text: '-before\n+after\n', withheld: null } };
}
const preparedStatus = (id = 'prepare-1', p = prepared()) => idle(operation(id, 'prepare', p.action.kind,
  { stage: 'settled', outcome: 'ok', result: { review: p.review, diff: p.diff } }), p);
const request = (phase, kind = 'stage', reviewId = 'review-1') => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? action(kind) : null, reviewId: phase === 'apply' ? reviewId : null });
const started = (status, r) => ({ schemaVersion: 1, admission: 'started', request: r, status, reason: null });
const refused = (r, status = idle(), reason = 'stale-observation') => ({ schemaVersion: 1, admission: 'refused', request: r, status, reason });
function applied(id = 'apply-1', kind = 'stage', state = 'succeeded') {
  const intent = { action: kind, expectedRevision: hash, expectedRef: 'refs/heads/main', expectedHead: head, expectedIndex: index,
    candidateIndex: kind === 'commit' ? null : 'e'.repeat(64), candidateCommit: kind === 'commit' ? 'f'.repeat(40) : null };
  const result = { operationId: id, action: kind, state, settlement: 'settled', reason: state === 'succeeded' ? null :
    state === 'recovery-required' ? 'recovery-required' : 'command-failed', observation: state === 'succeeded' ?
      { ...observation(), revision: '1'.repeat(64), head: kind === 'commit' ? intent.candidateCommit : head } : null,
    intent: state === 'failed' ? null : intent };
  return idle(operation(id, 'apply', kind, { stage: 'settled', outcome: 'ok', result }));
}
function deferred() { let resolve, reject; const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; }); return { promise, resolve, reject }; }
async function harness(options = {}) {
  const queues = Object.fromEntries(['prepare', 'apply', 'discard', 'status', 'cancel'].map((k) => [k, []])), calls = [], submissions = [];
  const api = Object.fromEntries(Object.keys(queues).map((kind) => [kind, (raw) => {
    assert.ok(raw instanceof Uint8Array); const body = decode(raw); calls.push({ kind, body });
    const next = queues[kind].shift(); return typeof next === 'function' ? next(body) : Promise.resolve(next);
  }]));
  const repository = new GitRepositoryController('project-1', { projectId: 'project-1', observe: async () => observation(), diff: async (r) =>
    ({ revision: hash, staged: r.staged, paths: [...r.paths].sort(), text: 'bounded diff', withheld: null }) });
  await repository.refresh(); repository.select('app.txt', true);
  repository.editDraft('message', 'Explain the fixture change'); repository.editDraft('authorName', 'Fixture Author'); repository.editDraft('authorEmail', 'author@example.invalid');
  let binding = { api, session: {}, projectId: 'project-1', epoch: 0, repository, blocked: null };
  const controller = new GitLocalController({ current: () => binding, onMutationSubmitted: (projectId) => {
    submissions.push(projectId);
    if (options.invalidate !== false) { repository.invalidate(); binding = { ...binding, epoch: binding.epoch + 1 }; controller.beforeContextIntent(); }
    options.onSubmitted?.();
  } });
  controller.syncContext();
  const h = { controller, repository, api, queues, calls, submissions, get binding() { return binding; }, set binding(v) { binding = v; },
    queue: (kind, value) => queues[kind].push(value) };
  assert.equal(calls.length, 0);
  h.queue('status', idle()); await controller.checkStatus();
  return h;
}
async function prepare(h, kind = 'stage') {
  const p = prepared('review-1', kind);
  h.queue('prepare', started(idle(operation('prepare-1', 'prepare', kind)), request('prepare', kind)));
  assert.equal(await h.controller.prepare(kind), true);
  h.queue('status', preparedStatus('prepare-1', p)); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), null);
  return p;
}

test('closed five RAW commands preserve private commit input but never put it into public status', async () => {
  const calls = [], api = createGitLocalApi('native', (name, raw) => { calls.push({ name, raw }); return Promise.resolve(idle()); });
  assert.equal(createGitLocalApi('preview', () => assert.fail()), null);
  const bodies = { prepare: { projectId: 'project-1', expectedDocumentRevision: 1, action: { ...action('commit'), message: 'A literal message', identity: { name: 'Fixture', email: 'f@example.invalid' } } },
    apply: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' }, discard: { reviewId: 'review-1' }, status: {}, cancel: { operationId: 'apply-1' } };
  for (const [name, body] of Object.entries(bodies)) {
    const raw = gitLocalRequest(name, body); assert.ok(raw instanceof Uint8Array); await api[name](raw);
    assert.deepEqual(decode(calls.at(-1).raw), body); assert.equal(calls.at(-1).name, `git_local_${name}`); assert.notEqual(calls.at(-1).raw, raw);
  }
  assert.equal(gitLocalRequest('status', { path: '/not-accepted' }), null);
  assert.equal(gitLocalRequest('prepare', { ...bodies.prepare, token: 'not-an-endpoint' }), null);
  assert.equal(gitLocalRequest('apply', { ...bodies.apply, message: 'substitution' }), null);
  assert.equal(gitLocalRequest('execute', {}), null);
  assert.equal(parseGitLocalStatus({ ...preparedStatus(), message: 'private draft' }), null);
  assert.equal(JSON.stringify(parseGitLocalStatus(preparedStatus())).includes('author@'), false);
});

test('input grammar uses literal bounded author/message, sorted UTF-8 paths, exact IDs and limits', () => {
  const body = { projectId: '_project', expectedDocumentRevision: 1, action: { ...action(), message: null, identity: null } };
  assert.ok(gitLocalRequest('prepare', body));
  for (const paths of [[], ['../file'], ['/absolute'], ['.git/config'], ['b', 'a'], ['a', 'a'], ['a\\b'], Array.from({ length: 65 }, (_, i) => `p${String(i).padStart(2, '0')}`)])
    assert.equal(gitLocalRequest('prepare', { ...body, action: { ...body.action, paths } }), null);
  assert.ok(gitLocalRequest('prepare', { ...body, action: { ...body.action, paths: ['\uE000', '\u{10000}'] } }));
  for (const projectId of ['project.1', 'project:1', 'x'.repeat(65), 'project\n']) assert.equal(gitLocalRequest('prepare', { ...body, projectId }), null);
  for (const expectedDocumentRevision of [0, -1, 1.5, 0xffffffff]) assert.equal(gitLocalRequest('prepare', { ...body, expectedDocumentRevision }), null);
  const commit = { ...action('commit'), message: 'literal\nmessage', identity: { name: 'Fixture', email: 'f@example.invalid' } };
  assert.ok(gitLocalRequest('prepare', { ...body, action: commit }));
  for (const message of [' ', 'x\r\ny', 'x'.repeat(4097), 'é'.repeat(2049)]) assert.equal(gitLocalRequest('prepare', { ...body, action: { ...commit, message } }), null);
  for (const email of ['missing', 'a@b@c', 'a @b', '@b', 'a@']) assert.equal(gitLocalRequest('prepare', { ...body, action: { ...commit, identity: { name: 'Fixture', email } } }), null);
});

test('strict immutable status separates nested result from native review/finality, rejects getters and mismatches', () => {
  const value = preparedStatus(), parsed = parseGitLocalStatus(value); assert.ok(parsed); value.review.review.paths[0] = 'changed';
  assert.equal(parsed.review.review.paths[0], 'app.txt'); assert.ok(Object.isFrozen(parsed.review.review.paths));
  const historical = preparedStatus(); historical.review = null; assert.ok(parseGitLocalStatus(historical));
  const premature = preparedStatus(); premature.operation.stage = 'running'; assert.equal(parseGitLocalStatus(premature), null);
  const wrongDiff = preparedStatus(); wrongDiff.review.diff.staged = true; assert.equal(parseGitLocalStatus(wrongDiff), null);
  const wrongCore = applied(); wrongCore.operation.result.operationId = 'other'; assert.equal(parseGitLocalStatus(wrongCore), null);
  assert.ok(parseGitLocalStatus(applied('apply-1', 'stage', 'recovery-required')));
  const getter = {}; Object.defineProperty(getter, 'schemaVersion', { enumerable: true, get() { assert.fail('getter executed'); } });
  assert.equal(parseGitLocalStatus(getter), null);
  assert.equal(parseGitLocalStartResult({ ...started(idle(), request('prepare')), admission: 'started' }), null);
  assert.equal(gitLocalRequest('status', new Proxy({}, { ownKeys() { throw new Error('private text'); } })), null);
});

test('prepare uses the real repository selection; review is unusable until original prepare AND status promises settle', async () => {
  const h = await harness(), start = deferred(), read = deferred();
  h.queue('prepare', () => start.promise); const sending = h.controller.prepare('stage');
  h.queue('status', () => read.promise); const checking = h.controller.checkStatus();
  read.resolve(preparedStatus()); await checking;
  assert.equal(h.controller.getSnapshot().pending, 1); assert.equal(h.controller.reviewReason(), 'busy'); assert.equal(h.controller.approve(true), false);
  const historical = preparedStatus(); historical.review = null;
  start.resolve(started(historical, request('prepare'))); await sending;
  assert.equal(h.controller.getSnapshot().original.stage, 'settled'); assert.equal(h.controller.reviewReason(), null);
  assert.deepEqual(h.calls.find((c) => c.kind === 'prepare').body.action, { ...action(), message: null, identity: null });
  assert.equal(h.submissions.length, 0);
});

test('commit reviews every staged file, retains exact local draft and rejects a selected-subset review', async () => {
  const h = await harness(); await prepare(h, 'commit');
  assert.deepEqual(h.controller.getSnapshot().review.prepared.review.paths, ['app.txt', 'other.txt']);
  assert.deepEqual(h.calls.find((c) => c.kind === 'prepare').body.action.paths, []);
  assert.equal(h.controller.getSnapshot().review.draft, h.repository.getSnapshot().draft);
  const other = await harness(), p = prepared('review-1', 'commit', ['app.txt']);
  other.queue('prepare', started(preparedStatus('prepare-1', p), request('prepare', 'commit'))); await other.controller.prepare('commit');
  assert.equal(other.controller.getSnapshot().uncertain, true); assert.equal(other.controller.getSnapshot().review, null);
});

test('approval is exact and one use; real Apply invalidates read eligibility without adopting its result or replacing draft', async () => {
  const h = await harness(); await prepare(h); const draft = h.repository.getSnapshot().draft, files = h.repository.getSnapshot().observation;
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter((c) => c.kind === 'apply').length, 0);
  assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), request('apply'))); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1).body, { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' });
  assert.deepEqual(h.submissions, ['project-1']); assert.equal(h.repository.getSnapshot().draft, draft);
  assert.equal(h.repository.getSnapshot().observation, files); assert.equal(h.repository.getSnapshot().stale, true);
  assert.equal(h.controller.ownerReason(), null); assert.equal(await h.controller.apply(), false);
});

test('draft, selection, observation and context ABA all retire approval while keeping the unused review and draft', async () => {
  for (const mutate of [
    (h) => { const value = h.repository.getSnapshot().draft.message; h.repository.editDraft('message', 'changed'); h.repository.editDraft('message', value); },
    (h) => { h.repository.select('app.txt', false); h.repository.select('app.txt', true); },
    (h) => { h.repository.invalidate(); },
    (h) => { const old = h.binding; h.binding = { ...old, projectId: 'project-2', epoch: 1 }; h.controller.syncContext(); h.binding = { ...old, epoch: 2 }; h.controller.syncContext(); },
  ]) {
    const h = await harness(); await prepare(h); h.controller.approve(true); mutate(h);
    assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(await h.controller.apply(), false);
    assert.ok(h.controller.getSnapshot().review); assert.equal(h.controller.canDiscard(), true);
    assert.equal(h.calls.filter((c) => c.kind === 'apply').length, 0);
  }
});

test('synchronous listener veto happens before invoke; same-owner invalidation after invocation cannot abort its receipt', async () => {
  const h = await harness(); await prepare(h); h.controller.approve(true);
  let once = true; h.controller.subscribe(() => { if (once && h.controller.getSnapshot().submitted) { once = false; h.binding = { ...h.binding, blocked: 'Other original owner' }; } });
  assert.equal(await h.controller.apply(), false); assert.equal(h.submissions.length, 0); assert.equal(h.calls.filter((c) => c.kind === 'apply').length, 0);
  assert.ok(h.controller.getSnapshot().review);
  const next = await harness(); await prepare(next); next.controller.approve(true);
  next.queue('apply', started(applied(), request('apply'))); await next.controller.apply();
  assert.equal(next.controller.getSnapshot().original.outcome, 'ok'); assert.equal(next.controller.getSnapshot().uncertain, false);
});

test('synchronous throw and non-Promise after Apply entry still invalidate eligibility and retain uncertainty', async () => {
  for (const reply of [() => { throw new Error('private command text'); }, () => ({ status: 'not a Promise' })]) {
    const h = await harness(); await prepare(h); h.controller.approve(true); h.queue('apply', reply);
    assert.equal(await h.controller.apply(), true); assert.deepEqual(h.submissions, ['project-1']);
    assert.equal(h.repository.getSnapshot().stale, true); assert.equal(h.controller.getSnapshot().uncertain, true);
    assert.ok(h.controller.ownerReason()); assert.equal(await h.controller.apply(), false);
    assert.equal(JSON.stringify(h.controller.getSnapshot()).includes('private command text'), false);
  }
});

test('exact pre-admission refusal retires only its request; lost/malformed acknowledgement does not', async () => {
  const h = await harness(); h.queue('prepare', refused(request('prepare'))); await h.controller.prepare('stage');
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.controller.getSnapshot().issue, 'stale-observation');
  assert.equal(h.repository.getSnapshot().stale, true); assert.equal(h.controller.prepareReason('stage'), 'stale-observation');
  assert.equal(h.calls.filter((c) => c.kind === 'prepare').length, 1);
  for (const reply of [() => Promise.reject(new Error('lost')), { admitted: false }, refused({ ...request('prepare'), projectId: 'foreign' })]) {
    const other = await harness(); other.queue('prepare', reply); await other.controller.prepare('stage');
    assert.ok(other.controller.ownerReason()); assert.equal(other.controller.getSnapshot().uncertain, true);
    other.queue('status', idle()); await other.controller.checkStatus();
    assert.ok(other.controller.ownerReason()); assert.equal(other.calls.filter((c) => c.kind === 'prepare').length, 1);
  }
});

test('refused Apply never rearms consent; only its genuine unused review can be closed', async () => {
  const h = await harness({ invalidate: false }); await prepare(h); h.controller.approve(true);
  h.queue('apply', refused(request('apply'), preparedStatus())); await h.controller.apply();
  assert.ok(h.controller.getSnapshot().review); assert.equal(h.controller.reviewReason(), 'already-used'); assert.equal(h.controller.canDiscard(), true);
  h.queue('discard', idle(preparedStatus().operation)); await h.controller.discard();
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.controller.ownerReason(), null); assert.equal(h.submissions.length, 1);
});

test('terminal status before Apply reply preserves original Promise and independent exact Stop', async () => {
  const h = await harness(); await prepare(h); h.controller.approve(true); const pending = deferred();
  h.queue('apply', () => pending.promise); const sent = h.controller.apply();
  h.queue('status', idle(operation('apply-1', 'apply'))); await h.controller.checkStatus();
  h.binding = { ...h.binding, api: {}, session: {}, projectId: 'project-2', epoch: h.binding.epoch + 1 }; h.controller.syncContext();
  const cancel = deferred(); h.queue('cancel', () => cancel.promise); const stopping = h.controller.cancel();
  assert.equal(h.controller.getSnapshot().pending, 2); assert.deepEqual(h.calls.at(-1).body, { operationId: 'apply-1' });
  h.queue('status', applied()); await h.controller.checkStatus(); assert.ok(h.controller.ownerReason());
  cancel.resolve(applied()); await stopping; assert.ok(h.controller.ownerReason());
  pending.resolve(started(idle(operation('apply-1', 'apply')), request('apply'))); await sent;
  assert.equal(h.controller.getSnapshot().original.stage, 'settled'); assert.equal(h.controller.ownerReason(), null);
});

test('project/API changes preserve original status/unused-review Close port and forbid stale review use', async () => {
  const h = await harness(); h.queue('prepare', started(idle(operation('prepare-1')), request('prepare'))); await h.controller.prepare('stage');
  h.binding = { ...h.binding, api: Object.freeze({ status: () => assert.fail('replacement port used') }), session: {}, projectId: 'project-2', epoch: 2 };
  h.controller.syncContext(); h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.canDiscard(), true);
  h.queue('discard', idle(preparedStatus().operation)); await h.controller.discard();
  assert.equal(h.calls.at(-1).kind, 'discard'); assert.equal(h.controller.ownerReason(), null);
});

test('navigation retirement during Prepare never makes its late review current even if the visible project stays the same', async () => {
  const h = await harness(), d = deferred(); h.queue('prepare', () => d.promise); const reading = h.controller.prepare('stage');
  h.controller.beforeContextIntent(); h.controller.syncContext();
  d.resolve(started(preparedStatus(), request('prepare'))); await reading;
  assert.ok(h.controller.getSnapshot().review); assert.equal(h.controller.reviewReason(), 'review-changed');
  assert.equal(h.controller.canDiscard(), true); assert.equal(h.controller.approve(true), false);
});

test('actual cleanup Unknown pins sent and observed-only evidence through late status/cancel/Start', async () => {
  for (const observed of [false, true]) {
    const h = await harness(); const pending = deferred(); let originalCall;
    if (!observed) { h.queue('prepare', () => pending.promise); originalCall = h.controller.prepare('stage'); }
    const unknown = idle(operation('prepare-1', 'prepare', 'stage', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' }));
    h.queue('status', unknown); await h.controller.checkStatus(); const original = h.controller.getSnapshot().original;
    h.queue('status', preparedStatus()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, original);
    assert.equal(h.controller.canCancel(), true); h.queue('cancel', preparedStatus()); await h.controller.cancel();
    if (originalCall) { pending.resolve(started(preparedStatus(), request('prepare'))); await originalCall; }
    assert.equal(h.controller.getSnapshot().original, original); assert.equal(h.controller.getSnapshot().review, null);
    assert.equal(h.controller.getSnapshot().uncertain, true); assert.ok(h.controller.ownerReason()); assert.equal(h.controller.getSnapshot().pending, 0);
  }
});

test('core recovery remains blocked even with native settled success and later ordinary status', async () => {
  const h = await harness(); await prepare(h); h.controller.approve(true);
  h.queue('apply', started(applied('apply-1', 'stage', 'recovery-required'), request('apply'))); await h.controller.apply();
  const original = h.controller.getSnapshot().original; assert.equal(h.controller.getSnapshot().recovery, true);
  h.queue('status', applied()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, original); assert.ok(h.controller.ownerReason());
});

test('historical prepare result without native Prepared never enables Apply; observed-only review is close-only', async () => {
  const h = await harness(), historical = preparedStatus(); historical.review = null;
  h.queue('prepare', started(historical, request('prepare'))); await h.controller.prepare('stage');
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.controller.ownerReason(), null);
  h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.approve(true), false); assert.equal(h.controller.canDiscard(), true);
});

test('discard loss preserves review; only original status absence after actual call return can close it', async () => {
  const h = await harness(); await prepare(h); const draft = h.repository.getSnapshot().draft;
  h.queue('discard', () => Promise.reject(new Error('lost close'))); await h.controller.discard();
  assert.ok(h.controller.getSnapshot().review); assert.equal(h.controller.canDiscard(), false); assert.equal(h.controller.getSnapshot().uncertain, true);
  h.queue('status', idle(preparedStatus().operation)); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.controller.ownerReason(), null); assert.equal(h.repository.getSnapshot().draft, draft);
});

test('idle status cannot publish across descriptor reentrancy or context ABA; in-flight read blocks ordinary work', async () => {
  const h = await harness(), d = deferred(); h.queue('status', () => d.promise); const read = h.controller.checkStatus();
  assert.ok(h.controller.ownerReason()); assert.equal(h.controller.prepareReason('stage'), 'busy');
  let once = true; const value = new Proxy(idle(), { getOwnPropertyDescriptor(target, property) {
    if (once) { once = false; h.binding = { ...h.binding, epoch: h.binding.epoch + 1 }; h.controller.syncContext(); }
    return Reflect.getOwnPropertyDescriptor(target, property);
  } });
  d.resolve(value); await read; assert.equal(h.controller.getSnapshot().status, null); assert.equal(h.controller.ownerReason(), null);
});

test('terminal contradictions preserve completed original evidence after the Start promise has joined', async () => {
  const h = await harness(); await prepare(h); h.controller.approve(true); h.queue('apply', started(applied(), request('apply'))); await h.controller.apply();
  const original = h.controller.getSnapshot().original, bad = applied('apply-1', 'stage', 'failed');
  h.queue('status', bad); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, original);
  assert.equal(h.controller.getSnapshot().uncertain, true); assert.ok(h.controller.ownerReason());
});
