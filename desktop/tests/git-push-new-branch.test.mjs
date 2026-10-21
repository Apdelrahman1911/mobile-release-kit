import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { gitLocalRequest, parseGitLocalStatus, parseGitLocalStartResult, sameGitLocalAction, gitLocalIntentMatchesReview } from '../src/gitLocalProtocol.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { parseGitHubConnectionStatus } from '../src/githubConnectionProtocol.ts';
import { gitPushAccount, gitPushActionFor, gitConnectionBlocksSavedWork } from '../src/gitPushSelection.ts';
import { isGitPushAction, isGitPushReview, GIT_PUSH_EFFECT_LABELS } from '../src/gitPushProtocol.ts';
import { GitHubActivityController } from '../src/githubActivityController.ts';
import { parseActivityStatus } from '../src/githubActivityProtocol.ts';
import { startGitPushReadback } from '../src/gitPushRecovery.ts';
import { GIT_PUSH_ZERO, isGitPushNewBranchAction, isGitPushNewBranchReview, isGitPushNewBranchIntent, isGitPushNewBranchMutation, gitPushNewBranchActionFor } from '../src/gitPushNewBranchProtocol.ts';

// Same original fixture pattern as git-push.test.mjs, using the actual retained
// controllers with only inert original API promises. No suite is imported. No process,
// Git repository, token, provider, native proof or DOM is created by these tests.
const revision = 'a'.repeat(64), references = 'b'.repeat(64), index = 'c'.repeat(64), head = 'd'.repeat(40), old = GIT_PUSH_ZERO, reviewDigest = 'f'.repeat(64);
const sha = s => createHash('sha256').update(s).digest('hex');
const decode = raw => JSON.parse(new TextDecoder().decode(raw));
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const action = () => ({ kind: 'push-new-branch', expectedRevision: revision, expectedReferenceRevision: references, remote: null,
  localRef: 'refs/heads/work', remoteRef: 'refs/heads/work', oldOid: old, newOid: head, connectionSessionId: 'session-1', expectedConnectionRevision: 12 });
const observation = () => ({ revision, head, branch: 'refs/heads/work', unborn: false, detached: false,
  changes: [{ path: 'app.txt', index: 'M', worktree: 'M', kind: 'file', conflict: false }], remotes: ['origin'], restrictions: [] });
const tracking = () => ({ state: 'not-configured', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null });
const review = () => ({ action: 'push-new-branch', remote: null, repository: 'Example/App', accountId: '7', repositoryId: '9', login: 'Example',
  branch: 'refs/heads/work', head, upstreamRef: 'refs/heads/work', expectedRemoteOid: old, trackingRef: null, commits: [head],
  expectedRevision: revision, expectedReferenceRevision: references, expectedIndex: index, basis: 'first-publication-no-upstream',
  withheld: ['messages', 'authors', 'emails', 'signatures', 'objects'], reviewDigest });
const intent = () => ({ action: 'push-new-branch', reviewDigest, expectedRevision: revision, expectedReferenceRevision: references, expectedIndex: index,
  remote: null, repository: 'Example/App', accountId: '7', repositoryId: '9', localRef: 'refs/heads/work', remoteRef: 'refs/heads/work',
  oldOid: old, newOid: head, commitsSha256: sha(head + '\n') });
const status = (operation = null, prepared = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: prepared, operation });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(), stage: 'running', outcome: null, reason: null, result: null, ...extra });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r } }), prepared(r));
const request = (phase = 'prepare', a = action()) => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? a : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (s, phase = 'prepare', a = action()) => ({ schemaVersion: 1, admission: 'started', request: request(phase, a), status: s, reason: null });
const result = (state = 'succeeded', effectPhase = 'remote-returned') => ({ operationId: 'apply-1', action: 'push-new-branch', state, settlement: 'settled',
  reason: state === 'succeeded' ? null : 'recovery-required', observation: null, intent: intent(), effectPhase,
  retainedPaths: state === 'succeeded' ? [] : ['mrk-git-original/mrk-git-push-fixture'] });
const applied = (r = result()) => status(operation('apply', { stage: 'settled', outcome: 'ok', result: r }));
function connection() {
  const fact = value => ({ state: value === null ? 'not-observed' : 'observed', value, observedAt: value === null ? null : '2026-10-20T12:00:00Z', reason: value === null ? 'not-connected' : 'none' });
  const s = { schemaVersion: 1, revision: 12, capability: { readOnlySessionAvailable: true, reason: 'none', deviceLogin: 'publisher-unconfigured', storage: 'session-only' },
    session: { id: 'session-1', projectId: 'project-1', targetRepository: 'Example/App', state: 'connected', expiresAt: '2026-10-20T13:00:00Z' },
    operation: { id: 'connection-1', kind: 'connect', phase: 'settled', reason: 'none' }, account: fact({ id: '7', login: 'Example' }),
    repository: fact({ id: '9', fullName: 'Example/App', defaultBranch: 'main', visibility: 'private', archived: false,
      permissions: { pull: 'reported-allowed', push: 'reported-allowed', admin: 'unknown' } }), automation: fact(null),
    facts: { remoteMutationAvailable: false, dispatchAvailable: false, repositoryActionsSettingsObservation: 'not-run', environmentObservation: 'not-run',
      secretObservation: 'not-run', variableObservation: 'not-run', protectionObservation: 'not-run', runnerObservation: 'not-run', templateCompatibility: 'unknown', releaseReadiness: 'unknown' } };
  assert.ok(parseGitHubConnectionStatus(s));
  return { mode: 'native', context: { documentId: 'document-1', projectId: 'project-1', projectGeneration: 1, repository: 'Example/App' },
    status: s, retained: null, help: null, helpState: 'missing', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null };
}
const pending = new Set();
function deferred() {
  let yes, no; const d = { promise: new Promise((resolve, reject) => { yes = resolve; no = reject; }) };
  d.resolve = value => { pending.delete(d); yes(value); }; d.reject = error => { pending.delete(d); no(error); }; pending.add(d); return d;
}
test.afterEach(async () => {
  for (const d of [...pending]) d.reject(new Error('inert fixture ending'));
  for (let i = 0; i < 12; i++) await Promise.resolve();
});
function port(names, calls) {
  const queues = Object.fromEntries(names.map(n => [n, []]));
  return { queue: (name, value) => queues[name].push(value), api: Object.fromEntries(names.map(name => [name, raw => {
    assert.ok(raw instanceof Uint8Array); const body = decode(raw); calls.push({ name, body });
    assert.ok(queues[name].length, `missing inert ${name} reply`); const value = queues[name].shift();
    return typeof value === 'function' ? value(body) : Promise.resolve(value);
  }])) };
}
async function fixture(options = {}) {
  const calls = [], reads = [], submissions = [], p = port(['prepare', 'apply', 'discard', 'status', 'cancel'], calls), rp = port(['start', 'status', 'cancel'], reads);
  let controller = null, binding, epoch = 0; const session = {};
  const connectedGate = scope => options.composedAdmission && binding &&
    gitConnectionBlocksSavedWork(binding.pushConnection, binding.projectId, scope) ? 'Finish the original Connection.' : null;
  const reader = new GitReadController({ current: () => ({ api: rp.api, session, projectId: binding?.projectId ?? 'project-1', epoch,
    blocked: controller?.ownerReason() ?? binding?.blocked ?? connectedGate('git-read') }) });
  reader.syncContext(); rp.queue('status', { schemaVersion: 1, documentRevision: 1, available: true, operation: null }); await reader.checkStatus();
  const repository = new GitRepositoryController('project-1', reader.port('project-1'));
  const readAction = { kind: 'observe', expectedRevision: null, paths: [], staged: false };
  const read = { schemaVersion: 1, admission: 'started', request: { projectId: 'project-1', expectedDocumentRevision: 1, action: readAction }, reason: null,
    status: { schemaVersion: 1, documentRevision: 1, available: true, operation: { operationId: 'read-1', context: context(), action: readAction,
      phase: 'settled', outcome: 'ok', reason: null, result: { observation: { ...observation(), ...options.observation }, referenceRevision: references, basis: 'local-refs-no-fetch',
        tracking: options.tracking ?? tracking() } } } };
  assert.ok(parseGitReadStartResult(read)); rp.queue('start', read); assert.equal(await repository.refresh(), true);
  repository.select('app.txt', true); repository.editDraft('message', 'Keep this local commit draft'); repository.editBranchName('future');
  const selectedConnection = connection();
  binding = { api: p.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null,
    pushConnection: selectedConnection, fetchConnection: selectedConnection };
  controller = new GitLocalController({ current: scope => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked ?? connectedGate(scope) }),
    onMutationSubmitted: projectId => { submissions.push(projectId); epoch++; binding = { ...binding, epoch };
      repository.invalidate(); reader.beforeContextIntent(); controller.beforeContextIntent(); } });
  controller.syncContext(); p.queue('status', status()); await controller.checkStatus();
  return { controller, repository, reader, calls, reads, submissions, queue: p.queue, get binding() { return binding; },
    async refreshRead() {
      reader.syncContext();
      rp.queue('status', { schemaVersion: 1, documentRevision: 1, available: true, operation: null });
      assert.equal(await reader.checkStatus(), true);
      const fresh = structuredClone(read); fresh.status.operation.operationId = 'read-2';
      rp.queue('start', fresh); return repository.refresh();
    },
    change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h, r = review()) {
  const s = preparedStatus(r); assert.ok(parseGitLocalStartResult(started(s)));
  h.queue('prepare', started(s)); assert.equal(await h.controller.preparePushNewBranch(), true); assert.equal(h.controller.reviewReason(), null);
}

const ordinaryAction = () => ({ ...action(), kind: 'push', remote: 'origin', oldOid: 'e'.repeat(40) });
const ordinaryReview = () => ({ ...review(), action: 'push', remote: 'origin', expectedRemoteOid: 'e'.repeat(40),
  trackingRef: 'refs/remotes/origin/work', basis: 'existing-configured-upstream' });

test('create-only RAW requires explicit kind and null source fields; ordinary Push stays nonzero', () => {
  const a = action(), body = { projectId: 'project-1', expectedDocumentRevision: 1, action: a };
  assert.ok(isGitPushNewBranchAction(a)); assert.deepEqual(decode(gitLocalRequest('prepare', body)), body);
  assert.ok(isGitPushAction(ordinaryAction())); assert.ok(isGitPushReview(ordinaryReview(), ordinaryAction()));
  assert.equal(isGitPushAction(a), false); assert.equal(isGitPushNewBranchAction(ordinaryAction()), false);
  assert.equal(isGitPushAction({ ...ordinaryAction(), oldOid: old }), false);
  assert.equal(sameGitLocalAction(a, ordinaryAction()), false);
  for (const change of [{ kind: 'push' }, { remote: 'origin' }, { remoteRef: 'refs/heads/other' }, { oldOid: head },
    { newOid: old }, { connectionSessionId: 'session-2', expectedConnectionRevision: 0 }, { localRef: 'refs/tags/v1' }])
    assert.equal(isGitPushNewBranchAction({ ...a, ...change }), false);
  for (const key of Object.keys(a)) { const value = { ...a }; delete value[key]; assert.equal(isGitPushNewBranchAction(value), false); }
  for (const key of ['token', 'url', 'force', 'forceWithLease', 'paths', 'argv', 'hooks', 'identity', 'message', 'setUpstream'])
    assert.equal(gitLocalRequest('prepare', { ...body, action: { ...a, [key]: null } }), null);
});

test('whole-history review and candidate are bounded and cannot cross ordinary/create-only kind', () => {
  const r = review(), i = intent(); assert.ok(isGitPushNewBranchReview(r, action()));
  assert.ok(isGitPushNewBranchIntent(i, action())); assert.ok(gitLocalIntentMatchesReview(i, r));
  const commits = Array.from({ length: 63 }, (_, n) => (n + 1).toString(16).padStart(40, '0')).concat(head);
  assert.ok(isGitPushNewBranchReview({ ...r, commits }, action()));
  for (const change of [{ commits: [] }, { commits: [...commits, head] }, { commits: [head, head] }, { commits: [old, head] },
    { commits: ['1'.repeat(40)] }, { remote: 'origin' }, { trackingRef: 'refs/remotes/origin/work' }, { basis: 'existing-configured-upstream' },
    { action: 'push' }, { expectedRemoteOid: 'e'.repeat(40) }, { diff: null }, { token: 'INERT' }])
    assert.equal(isGitPushNewBranchReview({ ...r, ...change }, action()), false);
  for (const key of ['remote', 'trackingRef']) { const value = { ...r }; delete value[key]; assert.equal(isGitPushNewBranchReview(value, action()), false); }
  for (const change of [{ action: 'push' }, { remote: 'origin' }, { oldOid: 'e'.repeat(40) }, { newOid: old }, { remoteRef: 'refs/heads/other' }])
    assert.equal(isGitPushNewBranchIntent({ ...i, ...change }, action()), false);
  assert.equal(gitLocalIntentMatchesReview(i, ordinaryReview()), false);
  assert.equal(gitLocalIntentMatchesReview({ ...i, action: 'push', remote: 'origin', oldOid: 'e'.repeat(40) }, r), false);
  let reads = 0; const value = { ...r }; Object.defineProperty(value, 'login', { enumerable: true, get() { reads++; return 'Example'; } });
  assert.equal(isGitPushNewBranchReview(value, action()), false); assert.equal(reads, 0);
});

test('public first-publication terminal is correlated and never publishes private diff or local adoption', () => {
  assert.ok(parseGitLocalStatus(preparedStatus())); assert.ok(parseGitLocalStatus(applied()));
  const leaked = preparedStatus(); leaked.operation.result.diff = null; assert.equal(parseGitLocalStatus(leaked), null);
  for (const change of [{ action: 'push' }, { intent: null }, { observation: observation() }, { effectPhase: 'send-consumed' },
    { retainedPaths: ['mrk-git-push-fixture'] }, { reason: 'remote-rejected' }])
    assert.equal(isGitPushNewBranchMutation({ ...result(), ...change }, action(), 'apply-1'), false);
  for (const phase of Object.keys(GIT_PUSH_EFFECT_LABELS))
    assert.ok(isGitPushNewBranchMutation(result('recovery-required', phase), action(), 'apply-1'));
  for (const paths of [['/tmp/file'], ['mrk-git-a/../mrk-git-push-b'], ['mrk-git-a/mrk-git-push-b/extra'], ['mrk-git-push-a', 'mrk-git-push-b']])
    assert.equal(isGitPushNewBranchMutation({ ...result('recovery-required'), retainedPaths: paths }, action(), 'apply-1'), false);
});

test('unconfigured attached observation selects only create-kind and never invents tracking or starts a read', async () => {
  const h = await fixture(), local = h.reader.getSnapshot().observation, account = gitPushAccount(h.binding.pushConnection, 'project-1');
  assert.deepEqual(gitPushNewBranchActionFor(local, account), action()); assert.equal(gitPushActionFor(local, account), null);
  assert.equal(h.controller.preparePushNewBranchReason(), null); assert.equal(h.controller.preparePushReason(), 'push-history');
  assert.deepEqual(h.reads.map(c => c.name), ['status', 'start']); assert.equal(h.calls.some(c => c.name === 'prepare'), false);
  for (const t of [{ state: 'complete', remote: 'origin', mergeRef: 'refs/heads/work', localRef: 'refs/remotes/origin/work', head: 'e'.repeat(40), ahead: 1, behind: 0 },
    { ...tracking(), state: 'gone', remote: 'origin', mergeRef: 'refs/heads/work', localRef: 'refs/remotes/origin/work' }]) {
    assert.equal(gitPushNewBranchActionFor({ ...local, tracking: t }, account), null);
    const linked = await fixture({ tracking: t }); assert.equal(await linked.controller.preparePushNewBranch(), false);
    assert.equal(linked.calls.some(c => c.name === 'prepare'), false);
  }
  for (const change of [{ unborn: true, head: null }, { detached: true, branch: null }])
    assert.equal(gitPushNewBranchActionFor({ ...local, observation: { ...local.observation, ...change } }, account), null);
  h.reader.beforeContextIntent(); assert.equal(h.controller.preparePushNewBranchReason(), 'push-read-required');
});

test('composed idle Connection permits explicit first review then one Apply, not local/CLI writes or other peers', async () => {
  const h = await fixture({ composedAdmission: true }), before = h.repository.getSnapshot(), read = h.reader.getSnapshot().observation;
  assert.equal(h.controller.prepareReason('stage'), 'busy'); assert.equal(h.controller.prepareReason('commit'), 'busy');
  assert.equal(h.controller.preparePushNewBranchReason(), null);
  h.change({ blocked: 'Original peer remains pending.' }); assert.equal(h.controller.preparePushNewBranchReason(), 'busy');
  h.change({ blocked: null }); await prepare(h); assert.equal(await h.controller.apply(), false);
  assert.equal(h.controller.approve(true), true); h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.map(c => c.name), ['status', 'prepare', 'apply']); assert.deepEqual(h.calls[1].body.action, action());
  assert.deepEqual(h.calls[2].body, { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' });
  for (const key of ['draft', 'branchDraft', 'switchDraft', 'renameDraft', 'selected', 'observation'])
    assert.equal(h.repository.getSnapshot()[key], before[key]);
  assert.equal(h.repository.getSnapshot().stale, true); assert.equal(h.reader.getSnapshot().observation, read);
  assert.deepEqual(h.reads.map(c => c.name), ['status', 'start']); assert.deepEqual(h.submissions, ['project-1']);
  assert.equal(h.controller.getSnapshot().original.result.observation, null);
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});

test('first publication retains actual Prepare and Apply promises after early terminal status', async () => {
  const h = await fixture(), p = deferred(); h.queue('prepare', () => p.promise); const preparing = h.controller.preparePushNewBranch();
  h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().pending, 1); assert.equal(h.controller.approve(true), false);
  assert.equal(await h.controller.apply(), false); p.resolve(started(preparedStatus())); await preparing;
  assert.equal(h.controller.approve(true), true); const d = deferred(); h.queue('apply', () => d.promise); const applying = h.controller.apply();
  h.queue('status', applied()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().pending, 1); assert.ok(h.controller.ownerReason()); assert.equal(await h.controller.apply(), false);
  d.resolve(started(applied(), 'apply')); await applying;
  assert.equal(h.controller.getSnapshot().pending, 0); assert.equal(h.controller.ownerReason(), null);
  assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});

test('new-kind retained capture rejects reentrant account loss and scalar-identical account ABA', async () => {
  const h = await fixture({ composedAdmission: true }); let lost = false;
  const off = h.controller.subscribe(() => { if (!lost && h.controller.ownerReason()) { lost = true; h.change({ pushConnection: null }); } });
  assert.equal(await h.controller.preparePushNewBranch(), false); off(); assert.equal(h.calls.some(c => c.name === 'prepare'), false);
  const apply = await fixture(); await prepare(apply); apply.controller.approve(true); let changed = false;
  const stop = apply.controller.subscribe(() => { if (!changed && apply.controller.getSnapshot().submitted) { changed = true; apply.change({ pushConnection: null }); } });
  assert.equal(await apply.controller.apply(), false); stop(); assert.equal(apply.calls.some(c => c.name === 'apply'), false);
  const aba = await fixture(); await prepare(aba); aba.controller.approve(true); const original = aba.binding.pushConnection;
  aba.change({ pushConnection: connection() }); aba.change({ pushConnection: original });
  assert.equal(aba.controller.reviewReason(), 'review-changed'); assert.equal(await aba.controller.apply(), false);
});

test('ordinary or foreign review cannot become first-publication authority even after genuine request', async () => {
  for (const value of [preparedStatus({ ...review(), accountId: '8' }),
    status({ ...operation(), action: ordinaryAction(), stage: 'settled', outcome: 'ok', result: { review: ordinaryReview() } },
      { reviewId: 'review-1', context: context(), action: ordinaryAction(), review: ordinaryReview() })]) {
    assert.ok(parseGitLocalStatus(value)); const h = await fixture(); h.queue('prepare', started(value)); await h.controller.preparePushNewBranch();
    assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(h.controller.approve(true), false); assert.equal(await h.controller.apply(), false);
  }
  const cold = await fixture(); cold.queue('status', preparedStatus()); await cold.controller.checkStatus();
  assert.equal(cold.controller.reviewReason(), 'review-changed'); assert.equal(cold.controller.approve(true), false);
});

test('lost first-publication reply keeps original Status and Stop without reconnect or second send', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true); h.queue('apply', () => Promise.reject(new Error('inert lost reply')));
  await h.controller.apply(); assert.equal(h.controller.getSnapshot().uncertain, true);
  h.change({ api: null, session: {}, projectId: 'other' }); assert.equal(await h.controller.preparePushNewBranch(), false);
  h.queue('status', status(operation('apply'))); await h.controller.checkStatus();
  h.queue('cancel', status(operation('apply', { stage: 'stopping' }))); assert.equal(await h.controller.cancel(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'cancel', body: { operationId: 'apply-1' } });
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});

const drain = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function activityResult(id = 'activity-1', tip = head, revision = 2) {
  const target = { projectBinding: '9'.repeat(64), repository: 'Example/App', accountId: '7', repositoryId: '9' };
  const selection = { kind: 'overview', branch: 'work' };
  const section = () => ({ state: 'read', reason: 'none', coverage: 'complete', total: 0, rows: [] });
  return { schemaVersion: 1, revision, sessionId: 'session-1', available: true, reason: 'none',
    operation: { id, projectId: 'project-1', target, selection, phase: 'settled', reason: 'none' },
    result: { target, selection, observedAt: '2026-10-20T12:05:00Z',
      data: { kind: 'overview', branchHead: tip, pullRequests: section(), workflowRuns: section() } } };
}
async function activityFixture(h, otherPeer = () => null) {
  const calls = [], replies = []; let listener = null;
  const idle = { schemaVersion: 1, revision: 1, sessionId: 'session-1', available: true, reason: 'none', operation: null, result: null };
  const controller = new GitHubActivityController(() => h.binding.pushConnection,
    selected => h.controller.pushActivityReason(selected) ?? otherPeer());
  const api = { mode: 'native', status: () => { calls.push({ name: 'status' }); return Promise.resolve(idle); },
    read: body => { calls.push({ name: 'read', body }); assert.ok(replies.length, 'missing inert Activity reply');
      const value = replies.shift(); return typeof value === 'function' ? value(body) : Promise.resolve(value); },
    cancel: body => { calls.push({ name: 'cancel', body }); return Promise.reject({ code: 'github_activity_refused_busy' }); },
    subscribe: f => { listener = f; return Promise.resolve(() => { listener = null; }); } };
  controller.connect(api); await drain();
  return { controller, calls, queue: value => replies.push(value), emit: value => { assert.ok(parseActivityStatus(value)); listener(value); } };
}
async function recovery(h) {
  await prepare(h); h.controller.approve(true);
  h.queue('apply', started(applied(result('recovery-required', 'send-consumed')), 'apply'));
  await h.controller.apply();
}
test('first-publication readback requires joined original Apply, never cold status or early return', async () => {
  const cold = await fixture(); cold.queue('status', applied(result('recovery-required', 'send-consumed'))); await cold.controller.checkStatus();
  assert.equal(cold.controller.pushReadbackSource(), null);
  const h = await fixture(); await prepare(h); h.controller.approve(true); const d = deferred();
  h.queue('apply', () => d.promise); const original = h.controller.apply();
  h.queue('status', applied(result('recovery-required', 'send-consumed'))); await h.controller.checkStatus();
  assert.equal(h.controller.pushReadbackSource(), null);
  d.resolve(started(applied(result('recovery-required', 'send-consumed')), 'apply')); await original;
  assert.equal(h.controller.pushReadbackSource().review.action, 'push-new-branch');
  assert.equal(h.controller.pushActivityReason({ kind: 'overview', branch: 'work' }), null);
  assert.ok(h.controller.pushActivityReason({ kind: 'overview', branch: 'other' }));
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});

test('fresh Activity match/mismatch is read DATA only; missing or denied is never zero/absence success', async () => {
  for (const [tip, comparison] of [[head, 'matches-intended'], ['1'.repeat(40), 'other'], [null, null]]) {
    const h = await fixture(); await recovery(h); const a = await activityFixture(h), original = h.controller.getSnapshot().original;
    a.queue(activityResult('activity-1', tip)); const readback = startGitPushReadback(h.controller, a.controller); assert.ok(readback); await drain();
    assert.equal(readback.result()?.comparison ?? null, comparison);
    assert.deepEqual(a.calls.at(-1).body.selection, { kind: 'overview', branch: 'work' });
    assert.equal(h.controller.getSnapshot().original, original); assert.equal(h.controller.getSnapshot().recovery, true);
    assert.equal(await h.controller.apply(), false); a.controller.dispose(); await drain();
  }
  for (const reason of ['not-found-or-inaccessible', 'forbidden']) {
    const h = await fixture(); await recovery(h); const a = await activityFixture(h), value = activityResult();
    value.operation.reason = reason; value.result = null; a.queue(value);
    const readback = startGitPushReadback(h.controller, a.controller); assert.ok(readback); await drain();
    assert.equal(readback.result(), null); assert.equal(h.controller.getSnapshot().recovery, true);
    a.controller.dispose(); await drain();
  }
});

test('new-kind recovery rejects earlier Activity, account ABA and native Unknown without releasing publication', async () => {
  const h = await fixture(), a = await activityFixture(h); a.queue(activityResult('old-read', '1'.repeat(40)));
  a.controller.read({ kind: 'overview', branch: 'work' }); await drain(); await recovery(h);
  const d = deferred(); a.queue(() => d.promise); const readback = startGitPushReadback(h.controller, a.controller); assert.ok(readback);
  assert.equal(readback.result(), null); const terminal = activityResult('new-read', head, 3); a.emit(terminal);
  assert.equal(readback.result(), null); d.resolve(terminal); await drain(); assert.equal(readback.result().comparison, 'matches-intended');
  const originalAccount = h.binding.pushConnection; h.change({ pushConnection: connection() }); h.change({ pushConnection: originalAccount });
  assert.equal(readback.result(), null); assert.equal(h.controller.pushReadbackSource(), null); a.controller.dispose(); await drain();
  for (const value of [status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })),
    applied({ ...result('failed', 'not-sent'), intent: null, reason: 'cleanup-unknown', retainedPaths: [] })]) {
    const u = await fixture(); await prepare(u); u.controller.approve(true); u.queue('apply', started(value, 'apply')); await u.controller.apply();
    const before = u.controller.getSnapshot().original; u.queue('status', applied()); await u.controller.checkStatus();
    assert.equal(u.controller.getSnapshot().original, before); assert.equal(u.controller.getSnapshot().uncertain, true);
    assert.equal(u.controller.pushReadbackSource(), null); assert.equal(await u.controller.preparePushNewBranch(), false);
    assert.equal(await u.controller.apply(), false);
  }
});
