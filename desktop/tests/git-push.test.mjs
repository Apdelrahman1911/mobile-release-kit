import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { gitLocalRequest, parseGitLocalStatus, parseGitLocalStartResult, sameGitLocalAction, gitLocalIntentMatchesReview } from '../src/gitLocalProtocol.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { parseGitHubConnectionStatus } from '../src/githubConnectionProtocol.ts';
import { gitPushAccount, sameGitPushAccount, gitPushActionFor, gitConnectionBlocksSavedWork } from '../src/gitPushSelection.ts';
import { isGitPushAction, isGitPushReview, isGitPushIntent, isGitPushMutation, gitPushIssueHelp, GIT_PUSH_EFFECT_LABELS } from '../src/gitPushProtocol.ts';
import { GitHubActivityController } from '../src/githubActivityController.ts';
import { parseActivityStatus } from '../src/githubActivityProtocol.ts';
import { startGitPushReadback } from '../src/gitPushRecovery.ts';

// Actual retained controllers, inert original API promises only. No process,
// Git repository, token, provider, native proof or DOM is created by these tests.
const revision = 'a'.repeat(64), references = 'b'.repeat(64), index = 'c'.repeat(64), head = 'd'.repeat(40), old = 'e'.repeat(40), reviewDigest = 'f'.repeat(64);
const sha = s => createHash('sha256').update(s).digest('hex');
const decode = raw => JSON.parse(new TextDecoder().decode(raw));
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const action = () => ({ kind: 'push', expectedRevision: revision, expectedReferenceRevision: references, remote: 'origin',
  localRef: 'refs/heads/work', remoteRef: 'refs/heads/main', oldOid: old, newOid: head, connectionSessionId: 'session-1', expectedConnectionRevision: 12 });
const observation = () => ({ revision, head, branch: 'refs/heads/work', unborn: false, detached: false,
  changes: [{ path: 'app.txt', index: 'M', worktree: 'M', kind: 'file', conflict: false }], remotes: ['origin'], restrictions: [] });
const tracking = () => ({ state: 'complete', remote: 'origin', mergeRef: 'refs/heads/main', localRef: 'refs/remotes/origin/main', head: old, ahead: 1, behind: 0 });
const review = () => ({ action: 'push', remote: 'origin', repository: 'Example/App', accountId: '7', repositoryId: '9', login: 'Example',
  branch: 'refs/heads/work', head, upstreamRef: 'refs/heads/main', expectedRemoteOid: old, trackingRef: 'refs/remotes/origin/main', commits: [head],
  expectedRevision: revision, expectedReferenceRevision: references, expectedIndex: index, basis: 'existing-configured-upstream',
  withheld: ['messages', 'authors', 'emails', 'signatures', 'objects'], reviewDigest });
const intent = () => ({ action: 'push', reviewDigest, expectedRevision: revision, expectedReferenceRevision: references, expectedIndex: index,
  remote: 'origin', repository: 'Example/App', accountId: '7', repositoryId: '9', localRef: 'refs/heads/work', remoteRef: 'refs/heads/main',
  oldOid: old, newOid: head, commitsSha256: sha(head + '\n') });
const status = (operation = null, prepared = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: prepared, operation });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(), stage: 'running', outcome: null, reason: null, result: null, ...extra });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r } }), prepared(r));
const request = (phase = 'prepare', a = action()) => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? a : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (s, phase = 'prepare', a = action()) => ({ schemaVersion: 1, admission: 'started', request: request(phase, a), status: s, reason: null });
const result = (state = 'succeeded', effectPhase = 'remote-returned') => ({ operationId: 'apply-1', action: 'push', state, settlement: 'settled',
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
  h.queue('prepare', started(s)); assert.equal(await h.controller.preparePush(), true); assert.equal(h.controller.reviewReason(), null);
}

test('composed Connection gate exempts only idle matching Git scopes, never saved work or another peer', () => {
  const idle = connection(), scopes = ['git-read', 'git-status', 'git-fetch', 'git-push'];
  assert.equal(gitConnectionBlocksSavedWork(idle, 'project-1'), true);
  for (const scope of scopes) assert.equal(gitConnectionBlocksSavedWork(idle, 'project-1', scope), false);
  for (const mutate of [v => { v.observing = true; }, v => { v.blocked = true; }, v => { v.uncertain = true; },
    v => { v.busy = 'refresh'; }, v => { v.retirementPending = true; }, v => { v.mode = 'preview'; },
    v => { v.context.projectId = 'foreign'; }, v => { v.context.repository = 'Other/App'; },
    v => { v.status.session.projectId = 'foreign'; }, v => { v.status.session.state = 'expired'; },
    v => { v.status.account.state = 'stale'; }, v => { v.status.repository.state = 'unavailable'; },
    v => { v.status.repository.value.fullName = 'Other/App'; }, v => { v.status.operation.phase = 'running'; },
    v => { v.retained = v.status; v.status = null; }]) {
    const value = connection(); mutate(value);
    for (const scope of scopes) assert.equal(gitConnectionBlocksSavedWork(value, 'project-1', scope), true);
  }
  // The old history-only branch is unchanged; Git scopes do not select it.
  assert.equal(gitConnectionBlocksSavedWork(idle, 'project-1', 'history-read'), false);
  assert.equal(gitConnectionBlocksSavedWork({ ...idle, uncertain: true }, 'project-1', 'history-read'), true);
  const disconnected = { ...idle, status: null, retained: null };
  assert.equal(gitConnectionBlocksSavedWork(disconnected, 'project-1'), false);
});

test('composed idle Connection reaches original Push status Review and Apply but not stage or commit', async () => {
  const h = await fixture({ composedAdmission: true });
  assert.deepEqual(h.calls.map(c => c.name), ['status']);
  assert.equal(h.controller.prepareReason('stage'), 'busy');
  assert.equal(h.controller.prepareReason('commit'), 'busy');
  assert.equal(h.controller.preparePushReason(), null);
  h.change({ blocked: 'Original history read is still pending.' });
  assert.equal(h.controller.preparePushReason(), 'busy');
  assert.equal(h.controller.canCheck(), false);
  h.change({ blocked: null });
  await prepare(h); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.map(c => c.name), ['status', 'prepare', 'apply']);
  assert.equal(h.controller.getSnapshot().original.result.state, 'succeeded');
});

test('composed Observe then Connect Fetch and fresh Observe use same controllers without an automatic read', async () => {
  const h = await fixture({ composedAdmission: true });
  // fixture's first original Observe precedes installing the selected session.
  assert.deepEqual(h.reads.map(c => c.name), ['status', 'start']);
  h.repository.editFetchDraft('remote', 'origin'); h.repository.editFetchDraft('branch', 'main');
  const a = { kind: 'fetch', expectedRevision: revision, expectedReferenceRevision: references,
    remote: 'origin', reference: 'refs/heads/main', connectionSessionId: 'session-1', expectedConnectionRevision: 12 };
  const r = { action: 'fetch', remote: 'origin', repository: 'Example/App', reference: 'refs/heads/main', targetRef: 'refs/remotes/origin/main',
    expectedTarget: old, candidateRefOid: head, expectedRevision: revision, expectedReferenceRevision: references, head, branch: 'refs/heads/work',
    expectedIndex: index, accountId: '7', repositoryId: '9', login: 'Example', reviewDigest };
  const o = phase => ({ ...operation(phase), action: a });
  const prepared = status({ ...o('prepare'), stage: 'settled', outcome: 'ok', result: { review: r, diff: null } },
    { reviewId: 'review-1', context: context(), action: a, review: r });
  assert.ok(parseGitLocalStartResult(started(prepared, 'prepare', a)));
  assert.equal(h.controller.prepareFetchReason(), null);
  h.queue('prepare', started(prepared, 'prepare', a)); assert.equal(await h.controller.prepareFetch(), true);
  assert.equal(h.controller.reviewReason(), null); assert.equal(h.controller.approve(true), true);
  const i = { action: 'fetch', reviewDigest, expectedRevision: revision, expectedReferenceRevision: references,
    expectedRef: 'refs/heads/work', expectedHead: head, expectedIndex: index, targetRef: 'refs/remotes/origin/main',
    expectedTarget: old, candidateRefOid: head, packOid: '1'.repeat(40), packSha256: '2'.repeat(64), packBytes: 100,
    indexSha256: '3'.repeat(64), indexBytes: 50 };
  const completed = status({ ...o('apply'), stage: 'settled', outcome: 'ok', result: {
    operationId: 'apply-1', action: 'fetch', state: 'succeeded', settlement: 'settled', reason: null,
    observation: null, intent: i, effectPhase: 'ref-published', retainedPaths: [] } });
  assert.ok(parseGitLocalStartResult(started(completed, 'apply', a)));
  h.queue('apply', started(completed, 'apply', a)); assert.equal(await h.controller.apply(), true);
  assert.equal(h.repository.getSnapshot().stale, true);
  assert.deepEqual(h.reads.map(c => c.name), ['status', 'start']);
  assert.equal(h.controller.ownerReason(), null);
  assert.equal(await h.refreshRead(), true);
  assert.deepEqual(h.reads.map(c => c.name), ['status', 'start', 'status', 'start']);
  assert.equal(h.reader.getSnapshot().original.operationId, 'read-2');
  assert.equal(h.repository.getSnapshot().stale, false);
});

test('composed scope is rechecked after reentrant publication and retained status never retargets', async () => {
  const h = await fixture({ composedAdmission: true });
  let veto = false;
  const off = h.controller.subscribe(() => {
    if (!veto && h.controller.getSnapshot().pending) { veto = true; h.change({ blocked: 'Original history pending' }); }
  });
  const before = h.calls.length;
  await h.controller.checkStatus(); off();
  assert.equal(h.calls.length, before); // no-attempt status send repeats git-status + peers.
  h.change({ blocked: null });
  let drift = false;
  const stop = h.controller.subscribe(() => {
    if (!drift && h.controller.getSnapshot().pending) {
      drift = true; h.change({ pushConnection: { ...h.binding.pushConnection, observing: true } });
    }
  });
  assert.equal(await h.controller.preparePush(), false); stop();
  assert.equal(h.calls.some(c => c.name === 'prepare'), false);
  const original = await fixture({ composedAdmission: true }); await prepare(original);
  original.change({ blocked: 'Unrelated owner now pending', pushConnection: { ...original.binding.pushConnection, retirementPending: true } });
  assert.equal(original.controller.reviewReason(), 'review-changed');
  original.queue('status', preparedStatus()); assert.equal(await original.controller.checkStatus(), true);
  assert.equal(original.calls.at(-1).name, 'status'); // same retained original, no new admission.
  assert.equal(original.controller.approve(true), false);
});

test('Push RAW binds the existing refs old/new/account; no token URL force hook command or implicit staging', () => {
  const body = { projectId: 'project-1', expectedDocumentRevision: 1, action: action() };
  assert.deepEqual(decode(gitLocalRequest('prepare', body)), body);
  for (const field of ['token', 'url', 'force', 'forceWithLease', 'paths', 'argv', 'hooks', 'identity', 'message', 'all', 'tags', 'setUpstream'])
    assert.equal(gitLocalRequest('prepare', { ...body, action: { ...action(), [field]: null } }), null);
  for (const field of Object.keys(action())) { const a = action(); delete a[field]; assert.equal(isGitPushAction(a), false); }
  for (const change of [{ oldOid: '0'.repeat(40) }, { newOid: old }, { localRef: 'main' }, { remoteRef: 'refs/tags/v1' }, { remote: '-origin' },
    { remoteRef: 'refs/heads/é' }, { remoteRef: 'refs/heads/a.lock' }, { connectionSessionId: 'session:1' }, { expectedConnectionRevision: 0 }, { expectedConnectionRevision: 0xffffffff }])
    assert.equal(isGitPushAction({ ...action(), ...change }), false);
  for (const field of ['remote', 'localRef', 'remoteRef', 'oldOid', 'newOid', 'connectionSessionId', 'expectedConnectionRevision'])
    assert.equal(sameGitLocalAction(action(), { ...action(), [field]: field === 'expectedConnectionRevision' ? 13 : 'different' }), false);
});
test('bounded complete reviewed commits and exact original intent reject additional authority and getters', () => {
  assert.ok(isGitPushReview(review(), action())); assert.ok(isGitPushIntent(intent(), action())); assert.ok(gitLocalIntentMatchesReview(intent(), review()));
  for (const change of [{ commits: [] }, { commits: [old, head] }, { commits: [head, head] }, { commits: ['1'.repeat(40)] },
    { commits: Array(65).fill(head) }, { trackingRef: 'refs/heads/main' }, { basis: 'latest-remote' }, { token: 'INERT' },
    { expectedRemoteOid: head }, { withheld: ['messages', 'authors', 'emails', 'signatures', 'objects', 'extra'] }])
    assert.equal(isGitPushReview({ ...review(), ...change }, action()), false);
  for (const change of [{ oldOid: head }, { remoteRef: 'refs/heads/other' }, { repository: 'Other/App' }, { accountId: '8' },
    { repositoryId: '10' }, { expectedIndex: '1'.repeat(64) }, { reviewDigest: '2'.repeat(64) }])
    assert.equal(gitLocalIntentMatchesReview({ ...intent(), ...change }, review()), false);
  let reads = 0; const v = review(); Object.defineProperty(v, 'login', { enumerable: true, get() { reads++; return 'Example'; } });
  assert.equal(isGitPushReview(v, action()), false); assert.equal(reads, 0);
});
test('public Push review has no private diff/receipt and success requires remote-returned with no retained work', () => {
  assert.ok(parseGitLocalStatus(preparedStatus())); assert.ok(parseGitLocalStatus(applied()));
  const privateShape = preparedStatus(); privateShape.operation.result.diff = null; assert.equal(parseGitLocalStatus(privateShape), null);
  for (const change of [{ intent: null }, { effectPhase: 'send-consumed' }, { observation: observation() }, { retainedPaths: ['mrk-git-push-fixture'] }, { reason: 'remote-rejected' }])
    assert.equal(isGitPushMutation({ ...result(), ...change }, action(), 'apply-1'), false);
  for (const phase of Object.keys(GIT_PUSH_EFFECT_LABELS)) assert.ok(isGitPushMutation(result('recovery-required', phase), action(), 'apply-1'));
  for (const retainedPaths of [['/tmp/file'], ['../file'], ['.git/config'], ['mrk-git-a/mrk-git-push-b/extra'], ['mrk-git-a/../mrk-git-push-b'],
    ['mrk-git-push-a/mrk-git-push-b'], ['mrk-git-/mrk-git-push-b'], ['mrk-git-push-a', 'mrk-git-push-b']])
    assert.equal(isGitPushMutation({ ...result('recovery-required'), retainedPaths }, action(), 'apply-1'), false);
});
test('current connected observed account requires explicit reported pull/push and nonarchived exact repository', () => {
  const c = connection(), a = gitPushAccount(c, 'project-1'); assert.ok(a); assert.ok(sameGitPushAccount(a, c, 'project-1'));
  assert.equal(sameGitPushAccount(a, connection(), 'project-1'), false);
  for (const mutate of [v => { v.mode = 'preview'; }, v => { v.blocked = true; }, v => { v.uncertain = true; }, v => { v.busy = 'refresh'; },
    v => { v.retirementPending = true; }, v => { v.context.projectId = 'project-2'; }, v => { v.status.session.state = 'expired'; },
    v => { v.status.repository.value.archived = true; }, v => { v.status.repository.value.permissions.pull = 'unknown'; },
    v => { v.status.repository.value.permissions.push = 'unknown'; }, v => { v.status.repository.value.permissions.push = 'reported-denied'; },
    v => { v.status.repository.value.fullName = 'Other/App'; }, v => { v.status.account.state = 'stale'; }]) {
    const v = connection(); mutate(v); assert.equal(gitPushAccount(v, 'project-1'), null);
  }
});
test('complete cached upstream and outgoing commits required; no automatic refresh fetch or branch query', async () => {
  const h = await fixture(); assert.equal(h.controller.preparePushReason(), null);
  assert.deepEqual(h.reads.map(c => c.name), ['status', 'start']); assert.equal(h.reads[1].body.action.kind, 'observe');
  assert.equal(h.calls.some(c => c.name === 'prepare'), false);
  const local = h.reader.getSnapshot().observation, a = gitPushAccount(h.binding.pushConnection, 'project-1');
  for (const t of [{ ...tracking(), behind: 1 }, { ...tracking(), ahead: 0 }, { ...tracking(), ahead: 65 }, { ...tracking(), head },
    { ...tracking(), state: 'shallow', ahead: null, behind: null }, { ...tracking(), localRef: 'refs/remotes/other/main' }])
    assert.equal(gitPushActionFor({ ...local, tracking: t }, a), null);
  for (const t of [{ ...tracking(), behind: 1 }, { ...tracking(), ahead: 0 }, { ...tracking(), state: 'limit', ahead: null, behind: null }]) {
    const other = await fixture({ tracking: t }); assert.equal(other.controller.preparePushReason(), 'push-history');
    assert.equal(await other.controller.preparePush(), false); assert.equal(other.calls.some(c => c.name === 'prepare'), false);
  }
  h.reader.beforeContextIntent(); assert.equal(h.controller.preparePushReason(), 'push-read-required');
});
test('explicit Review then one Apply preserves unrelated staging and all drafts, no automatic local ref adoption', async () => {
  const h = await fixture(), before = h.repository.getSnapshot(), read = h.reader.getSnapshot().observation, reads = h.reads.length;
  await prepare(h); assert.equal(await h.controller.apply(), false); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'apply', body: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' } });
  for (const key of ['draft', 'branchDraft', 'switchDraft', 'renameDraft', 'selected', 'observation']) assert.equal(h.repository.getSnapshot()[key], before[key]);
  assert.equal(h.repository.getSnapshot().stale, true); assert.equal(h.reader.getSnapshot().observation, read); assert.equal(h.reads.length, reads);
  assert.deepEqual(h.submissions, ['project-1']); assert.equal(h.controller.getSnapshot().original.result.observation, null);
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});
test('same pending Prepare is retained when status reports its joined review before original reply returns', async () => {
  const h = await fixture(), d = deferred(); h.queue('prepare', () => d.promise); const original = h.controller.preparePush();
  assert.equal(h.controller.getSnapshot().pending, 1); h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), 'busy'); assert.equal(h.controller.approve(true), false);
  d.resolve(started(preparedStatus())); await original; assert.equal(h.controller.reviewReason(), null);
  assert.equal(h.calls.filter(c => c.name === 'prepare').length, 1); assert.equal(h.calls.some(c => c.name === 'apply'), false);
});
test('pending Apply cannot release on terminal status before its original promise; no second Apply', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true); const d = deferred();
  h.queue('apply', () => d.promise); const original = h.controller.apply(); h.queue('status', applied()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().pending, 1); assert.ok(h.controller.ownerReason()); assert.equal(await h.controller.apply(), false);
  d.resolve(started(applied(), 'apply')); await original; assert.equal(h.controller.getSnapshot().pending, 0); assert.equal(h.controller.ownerReason(), null);
});
test('lost Apply reply preserves original status and Stop on old port, never replay or implicit reconnect', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true); h.queue('apply', () => Promise.reject(new Error('inert lost reply')));
  await h.controller.apply(); assert.equal(h.controller.getSnapshot().uncertain, true); h.change({ api: null, session: {}, projectId: 'other' });
  assert.equal(await h.controller.preparePush(), false); assert.equal(await h.controller.apply(), false);
  h.queue('status', status(operation('apply'))); await h.controller.checkStatus();
  h.queue('cancel', status(operation('apply', { stage: 'stopping' }))); assert.equal(await h.controller.cancel(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'cancel', body: { operationId: 'apply-1' } }); assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});
test('partial send and native Unknown remain absorbing despite later successful status DATA', async () => {
  for (const kind of ['recovery', 'native-unknown', 'contradictory-cleanup']) {
    const h = await fixture(); await prepare(h); h.controller.approve(true);
    const value = kind === 'native-unknown' ? status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })) :
      applied(kind === 'recovery' ? result('recovery-required', 'send-entered') : { ...result('failed', 'not-sent'), intent: null, reason: 'cleanup-unknown', retainedPaths: [] });
    assert.ok(parseGitLocalStatus(value)); h.queue('apply', started(value, 'apply')); await h.controller.apply(); const original = h.controller.getSnapshot().original;
    h.queue('status', applied()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, original);
    assert.equal(await h.controller.preparePush(), false); assert.equal(await h.controller.apply(), false);
    assert.equal(kind === 'recovery' ? h.controller.getSnapshot().recovery : h.controller.getSnapshot().uncertain, true);
  }
});
test('observed-only review is close-only and original account/read/context ABA retires copied consent', async () => {
  const observed = await fixture(); observed.queue('status', preparedStatus()); await observed.controller.checkStatus();
  assert.equal(observed.controller.reviewReason(), 'review-changed'); assert.equal(observed.controller.approve(true), false);
  observed.change({ api: null, session: {}, projectId: 'other' }); observed.queue('discard', status(preparedStatus().operation)); await observed.controller.discard();
  assert.equal(observed.calls.at(-1).name, 'discard');
  for (const change of [h => h.change({ pushConnection: connection() }), h => h.change({ epoch: 1 }), h => h.change({ session: {} }),
    h => h.change({ projectId: 'project-2' }), h => h.reader.beforeContextIntent()]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true); change(h);
    assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(await h.controller.apply(), false); assert.equal(h.calls.some(c => c.name === 'apply'), false);
  }
  const h = await fixture(); await prepare(h); const old = h.binding.pushConnection; h.change({ pushConnection: connection() }); h.change({ pushConnection: old });
  assert.equal(h.controller.reviewReason(), 'review-changed'); let events = 0; const off = h.controller.subscribe(() => events++);
  h.controller.syncContext(); h.controller.syncContext(); off(); assert.equal(events, 0);
});
test('current account changes do not globally invalidate ordinary local staging review', async () => {
  const h = await fixture(), a = { kind: 'stage', expectedRevision: revision, paths: ['app.txt'] };
  const r = { action: 'stage', expectedRevision: revision, paths: ['app.txt'], wholeIndex: false, head, branch: 'refs/heads/work', expectedIndex: index, reviewDigest };
  const diff = { revision, staged: false, paths: ['app.txt'], text: '-before\n+after\n', withheld: null };
  const o = { ...operation(), action: a, stage: 'settled', outcome: 'ok', result: { review: r, diff } };
  const s = status(o, { reviewId: 'review-1', context: context(), action: a, review: r, diff }); assert.ok(parseGitLocalStatus(s));
  h.queue('prepare', started(s, 'prepare', a)); assert.equal(await h.controller.prepare('stage'), true); h.change({ pushConnection: null });
  assert.equal(h.controller.reviewReason(), null); assert.equal(h.controller.approve(true), true);
});
test('reentrant listener account loss before Prepare sends nothing; same event cut protects Apply', async () => {
  const h = await fixture(); let changed = false; const off = h.controller.subscribe(() => {
    if (!changed && h.controller.ownerReason()) { changed = true; h.change({ pushConnection: null }); }
  });
  assert.equal(await h.controller.preparePush(), false); off(); assert.equal(h.calls.some(c => c.name === 'prepare'), false);
  const other = await fixture(); await prepare(other); other.controller.approve(true); let lost = false;
  const offApply = other.controller.subscribe(() => { if (!lost && other.controller.getSnapshot().submitted) { lost = true; other.change({ pushConnection: null }); } });
  assert.equal(await other.controller.apply(), false); offApply(); assert.equal(other.calls.some(c => c.name === 'apply'), false);
});
test('wrong account review or operation correlation is Unknown and cannot lend original review', async () => {
  for (const s of [preparedStatus({ ...review(), accountId: '8' }), { ...preparedStatus(), operation: { ...preparedStatus().operation, context: { ...context(), projectId: 'project-2' } } }]) {
    const h = await fixture(); h.queue('prepare', started(s)); await h.controller.preparePush();
    assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(h.controller.approve(true), false); assert.equal(await h.controller.apply(), false);
  }
});
test('help distinguishes committed content, stale upstream and unknown send without a force/retry instruction', () => {
  assert.match(gitPushIssueHelp('push-history'), /no reset or force/); assert.match(gitPushIssueHelp('push-upstream'), /new branch/);
  assert.match(gitPushIssueHelp('network-unavailable'), /do not blindly retry/); assert.equal(gitPushIssueHelp('caller-supplied-command'), null);
});

const drain = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
function activityResult(id = 'activity-1', tip = head, revision = 2) {
  const target = { projectBinding: '9'.repeat(64), repository: 'Example/App', accountId: '7', repositoryId: '9' };
  const selection = { kind: 'overview', branch: 'main' };
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
test('Push readback requires the actual Apply and returned original promise, not cold status or an early terminal', async () => {
  const cold = await fixture(); cold.queue('status', applied(result('recovery-required', 'send-consumed'))); await cold.controller.checkStatus();
  assert.equal(cold.controller.pushReadbackSource(), null);
  const h = await fixture(); await prepare(h); h.controller.approve(true); const d = deferred();
  h.queue('apply', () => d.promise); const original = h.controller.apply();
  h.queue('status', applied(result('recovery-required', 'send-consumed'))); await h.controller.checkStatus();
  assert.equal(h.controller.pushReadbackSource(), null);
  d.resolve(started(applied(result('recovery-required', 'send-consumed')), 'apply')); await original;
  assert.ok(h.controller.pushReadbackSource()); assert.ok(h.controller.ownerReason());
  assert.equal(h.controller.pushActivityReason({ kind: 'overview', branch: 'main' }), null);
  for (const selection of [undefined, { kind: 'overview', branch: null }, { kind: 'overview', branch: 'other' }, { kind: 'pull-request', number: '1' }])
    assert.ok(h.controller.pushActivityReason(selection));
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter(v => v.name === 'apply').length, 1);
});
test('the existing Activity owner performs a separate exact branch GET and never clears Push recovery', async () => {
  for (const [tip, comparison] of [[head, 'matches-intended'], [old, 'still-old'], ['1'.repeat(40), 'other']]) {
    const h = await fixture(); await recovery(h); const a = await activityFixture(h), before = h.controller.getSnapshot().original;
    a.queue(activityResult('activity-1', tip)); const readback = startGitPushReadback(h.controller, a.controller);
    assert.ok(readback); assert.equal(readback.result(), null); await drain();
    assert.deepEqual(readback.result(), { comparison, tip, observedAt: '2026-10-20T12:05:00Z' });
    assert.deepEqual(a.calls.at(-1), { name: 'read', body: { sessionId: 'session-1', projectId: 'project-1', expectedRevision: 1,
      expectedConnectionRevision: 12, selection: { kind: 'overview', branch: 'main' } } });
    assert.equal(h.controller.getSnapshot().original, before); assert.equal(h.controller.getSnapshot().recovery, true);
    assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter(v => v.name === 'apply').length, 1);
    a.controller.dispose(); await drain();
  }
});
test('an earlier Activity result and a new early terminal never substitute for the new original read return', async () => {
  const h = await fixture(), a = await activityFixture(h);
  a.queue(activityResult('activity-old', old)); a.controller.read({ kind: 'overview', branch: 'main' }); await drain();
  assert.equal(a.controller.currentResult().data.branchHead, old);
  await recovery(h); const d = deferred(); a.queue(() => d.promise);
  const readback = startGitPushReadback(h.controller, a.controller); assert.ok(readback); assert.equal(readback.result(), null);
  const next = activityResult('activity-new', head, 3); a.emit(next);
  assert.equal(readback.result(), null); assert.equal(a.controller.getSnapshot().pending, true);
  d.resolve(next); await drain(); assert.equal(readback.result().comparison, 'matches-intended');
  a.queue(activityResult('activity-unrelated', old, 4)); a.controller.read({ kind: 'overview', branch: 'main' }); await drain();
  assert.equal(readback.result(), null); // Even an identical branch on a later request is not this original read.
  a.controller.dispose(); await drain();
});
test('reentrant source loss before the Activity call sends no read and account ABA never restores its comparison', async () => {
  const h = await fixture(); await recovery(h); const a = await activityFixture(h); let lost = false;
  const stop = a.controller.subscribe(() => { if (!lost && a.controller.getSnapshot().pending) { lost = true; h.change({ epoch: 3 }); } });
  assert.equal(startGitPushReadback(h.controller, a.controller), null); stop();
  assert.equal(a.calls.filter(v => v.name === 'read').length, 0); assert.equal(h.controller.pushReadbackSource(), null);
  const other = await fixture(); await recovery(other); const b = await activityFixture(other), d = deferred(); b.queue(() => d.promise);
  const readback = startGitPushReadback(other.controller, b.controller), originalAccount = other.binding.pushConnection;
  assert.ok(readback); other.change({ pushConnection: connection() }); other.change({ pushConnection: originalAccount });
  assert.equal(readback.current(), false); d.resolve(activityResult()); await drain();
  assert.equal(readback.result(), null); assert.equal(other.controller.pushReadbackSource(), null);
  a.controller.dispose(); b.controller.dispose(); await drain();
});
test('native Unknown and unrelated pending owners remain blocking rather than receive a read exemption', async () => {
  for (const terminal of [status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })),
    applied({ ...result('failed', 'not-sent'), intent: null, reason: 'cleanup-unknown', retainedPaths: [] })]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true); h.queue('apply', started(terminal, 'apply')); await h.controller.apply();
    const a = await activityFixture(h); assert.equal(startGitPushReadback(h.controller, a.controller), null);
    assert.equal(a.calls.filter(v => v.name === 'read').length, 0); assert.equal(h.controller.getSnapshot().uncertain, true);
    a.controller.dispose(); await drain();
  }
  const h = await fixture(); await recovery(h); const a = await activityFixture(h, () => 'Unrelated original remains pending');
  assert.equal(startGitPushReadback(h.controller, a.controller), null); assert.equal(a.calls.filter(v => v.name === 'read').length, 0);
  a.controller.dispose(); await drain();
});
test('missing/inaccessible, wrong account/repository/branch and lost read replies are never old-tip success', async () => {
  for (const kind of ['not-found-or-inaccessible', 'forbidden', 'account', 'repository', 'branch', 'lost']) {
    const h = await fixture(); await recovery(h); const a = await activityFixture(h), value = activityResult();
    if (kind === 'not-found-or-inaccessible' || kind === 'forbidden') { value.operation.reason = kind; value.result = null; }
    else if (kind === 'account') value.operation.target.accountId = '8';
    else if (kind === 'repository') value.operation.target.repositoryId = '10';
    else if (kind === 'branch') value.operation.selection.branch = 'other';
    assert.ok(parseActivityStatus(value));
    a.queue(kind === 'lost' ? () => Promise.reject(new Error('inert lost read return')) : value);
    const readback = startGitPushReadback(h.controller, a.controller); assert.ok(readback); await drain();
    assert.equal(readback.result(), null); assert.equal(h.controller.getSnapshot().recovery, true);
    assert.equal(h.calls.filter(v => v.name === 'apply').length, 1); assert.equal(await h.controller.apply(), false);
    a.controller.dispose(); await drain();
  }
});
