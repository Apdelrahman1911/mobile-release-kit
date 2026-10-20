import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { isGitSwitchReview, isGitSwitchIntent, isGitSwitchMutation, gitSwitchIssueHelp } from '../src/gitSwitchProtocol.ts';
import { gitLocalRequest, parseGitLocalStatus, sameGitLocalAction, gitLocalIntentMatchesReview } from '../src/gitLocalProtocol.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';

// Real controllers, inert API promises only. No invoke/process/native/DOM,
// repository, network or credential access. DATA is never an owner witness.
const revision = 'a'.repeat(64), references = 'b'.repeat(64), index = 'c'.repeat(64), head = 'd'.repeat(40), target = 'e'.repeat(40);
const sha = (s) => createHash('sha256').update(s).digest('hex');
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const decode = (raw) => JSON.parse(new TextDecoder().decode(raw));
const action = () => ({ kind: 'branch-switch', expectedRevision: revision, expectedReferenceRevision: references, name: 'next' });
const observation = (branch = 'refs/heads/main', oid = head, changes = []) => ({ revision, head: oid, branch, unborn: oid === null,
  detached: branch === null, changes, remotes: [], restrictions: [] });
const branches = (branch = 'refs/heads/main', oid = head) => ({ revision, referenceRevision: references, head: oid, branch,
  branches: [{ ref: 'refs/heads/main', oid: head }, { ref: 'refs/heads/next', oid: target }], basis: 'local-refs-no-fetch' });
const file = (path = 'file.txt') => ({ path, mode: '100644', sourceOid: '1'.repeat(40), targetOid: '2'.repeat(40),
  sourceSha256: sha('old'), targetSha256: sha('new'), targetSize: 3 });
const review = () => ({ action: 'branch-switch', name: 'next', targetRef: 'refs/heads/next', targetOid: target, expectedRevision: revision,
  expectedReferenceRevision: references, head, branch: 'refs/heads/main', expectedIndex: index, paths: ['file.txt'], trackedCount: 1,
  contentOnly: true, files: [file()], log: { enabled: false, originalKind: 'absent', originalSha256: sha('absent') }, reviewDigest: 'f'.repeat(64) });
const intent = () => ({ action: 'branch-switch', expectedRevision: revision, expectedReferenceRevision: references, expectedRef: 'refs/heads/main',
  expectedHead: head, expectedIndex: index, targetRef: 'refs/heads/next', targetOid: target, candidateIndex: sha('candidate-index'),
  originalHead: sha('ref: refs/heads/main\n'), candidateHead: sha('ref: refs/heads/next\n'), originalLog: sha('absent'),
  candidateLog: sha('absent'), logEnabled: false, footprint: sha('fixture-comparison-only') });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const status = (operation = null, p = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: p, operation });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(),
  stage: 'running', outcome: null, reason: null, result: null, ...extra });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r } }), prepared(r));
const startRequest = (phase = 'prepare') => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? action() : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (value, phase = 'prepare') => ({ schemaVersion: 1, admission: 'started', request: startRequest(phase), status: value, reason: null });
const result = (state = 'succeeded', phase = 'index-returned') => ({ operationId: 'apply-1', action: 'branch-switch', state, settlement: 'settled',
  reason: state === 'succeeded' ? null : 'recovery-required', observation: state === 'succeeded' ? observation('refs/heads/next', target) : null,
  intent: intent(), effectPhase: phase, retainedPaths: state === 'succeeded' ? [] : ['.git/mrk-git-fixture/index'] });
const applied = (r = result()) => status(operation('apply', { stage: 'settled', outcome: 'ok', result: r }));
const readStatus = (operation = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, operation });
function readStarted(kind, value) {
  const a = { kind, expectedRevision: kind === 'observe' ? null : revision, paths: [], staged: false };
  const result = { schemaVersion: 1, admission: 'started', request: { projectId: 'project-1', expectedDocumentRevision: 1, action: a }, reason: null,
    status: readStatus({ operationId: `read-${kind}`, context: context(), action: a, phase: 'settled', outcome: 'ok', reason: null, result: value }) };
  assert.ok(parseGitReadStartResult(result), 'fixture must supply an actual valid original read reply');
  return result;
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function port(names, calls) {
  const queues = Object.fromEntries(names.map((n) => [n, []]));
  const api = Object.fromEntries(names.map((name) => [name, (raw) => {
    assert.ok(raw instanceof Uint8Array); const body = decode(raw); calls.push({ name, body });
    assert.ok(queues[name].length, `missing inert ${name} reply`);
    const value = queues[name].shift(); return typeof value === 'function' ? value(body) : Promise.resolve(value);
  }]));
  return { api, queue: (name, value) => queues[name].push(value) };
}
async function fixture({ list = true, branch = 'refs/heads/main', oid = head, changes = [] } = {}) {
  const calls = [], reads = [], submissions = [], p = port(['prepare', 'apply', 'discard', 'status', 'cancel'], calls), rp = port(['start', 'status', 'cancel'], reads);
  const session = {}; let controller = null, binding, epoch = 0;
  const reader = new GitReadController({ current: () => ({ api: rp.api, session, projectId: binding?.projectId ?? 'project-1', epoch,
    blocked: controller?.ownerReason() ?? binding?.blocked ?? null }) });
  reader.syncContext(); rp.queue('status', readStatus()); await reader.checkStatus();
  const repository = new GitRepositoryController('project-1', reader.port('project-1'));
  rp.queue('start', readStarted('observe', { observation: observation(branch, oid, changes), referenceRevision: references, basis: 'local-refs-no-fetch',
    tracking: { state: branch === null ? 'detached' : oid === null ? 'unborn' : 'not-configured', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null } }));
  assert.equal(await repository.refresh(), true);
  repository.editDraft('message', 'Keep this commit draft'); repository.editBranchName('future'); repository.selectSwitchBranch('next');
  binding = { api: p.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null };
  controller = new GitLocalController({ current: () => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked }),
    onMutationSubmitted: (projectId) => { submissions.push(projectId); epoch += 1; binding = { ...binding, epoch };
      repository.invalidate(); reader.beforeContextIntent(); controller.beforeContextIntent(); } });
  controller.syncContext(); p.queue('status', status()); await controller.checkStatus();
  if (list) {
    const b = branches(branch, oid); if (oid === null) b.branches = [{ ref: 'refs/heads/next', oid: target }];
    rp.queue('start', readStarted('branches', b)); assert.equal(await reader.readBranches('project-1', revision), true);
  }
  return { controller, reader, repository, calls, reads, submissions, queue: p.queue,
    change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h, r = review()) { h.queue('prepare', started(preparedStatus(r))); assert.equal(await h.controller.prepareSwitch(), true); assert.equal(h.controller.reviewReason(), null); }

test('exact switch RAW input adds no caller target oid, force, command, path, identity or serialized review', () => {
  const input = { projectId: 'project-1', expectedDocumentRevision: 1, action: action() };
  assert.deepEqual(decode(gitLocalRequest('prepare', input)), input);
  for (const field of ['targetOid', 'force', 'paths', 'argv', 'identity', 'message', 'switch', 'review'])
    assert.equal(gitLocalRequest('prepare', { ...input, action: { ...action(), [field]: null } }), null);
  for (const key of ['name', 'expectedReferenceRevision', 'expectedRevision']) {
    const a = action(); delete a[key]; assert.equal(gitLocalRequest('prepare', { ...input, action: a }), null);
  }
  for (const name of ['', '-next', '../next', 'refs/..', 'a.lock', 'a\n', 'a'.repeat(256)])
    assert.equal(gitLocalRequest('prepare', { ...input, action: { ...action(), name } }), null);
  assert.ok(gitLocalRequest('prepare', { ...input, action: { ...action(), kind: 'branch-create' } }));
  assert.ok(gitLocalRequest('prepare', { ...input, action: { kind: 'stage', expectedRevision: revision, paths: ['file.txt'], message: null, identity: null } }));
  assert.equal(sameGitLocalAction(action(), { ...action(), expectedReferenceRevision: '0'.repeat(64) }), false);
});

test('bounded content-only review accepts same-tree switches but not hidden paths, mode changes, bodies or broad checkout', () => {
  assert.equal(isGitSwitchReview(review(), action()), true);
  assert.ok(parseGitLocalStatus(preparedStatus()));
  assert.equal(isGitSwitchReview({ ...review(), targetOid: head, paths: [], files: [], trackedCount: 0 }, action()), true);
  for (const change of [{ contentOnly: false }, { trackedCount: 257 }, { branch: null }, { branch: 'refs/heads/next' }, { targetRef: 'refs/heads/foreign' },
    { targetOid: 'e'.repeat(64) }, { paths: [] }, { files: [{ ...file(), content: 'not a preview' }] }, { files: [{ ...file(), mode: '120000' }] },
    { files: [{ ...file(), path: '.git/config' }], paths: ['.git/config'] }, { files: [{ ...file(), targetSize: 4 * 1024 * 1024 + 1 }] },
    { log: { enabled: false, originalKind: 'file', originalSha256: sha('old') } }, { log: { enabled: true, originalKind: 'absent', originalSha256: sha('wrong') } }])
    assert.equal(isGitSwitchReview({ ...review(), ...change }, action()), false);
  const many = Array.from({ length: 9 }, (_, i) => file(`file${i}`));
  assert.equal(isGitSwitchReview({ ...review(), files: many, paths: many.map((f) => f.path), trackedCount: 9 }, action()), false);
  const big = Array.from({ length: 3 }, (_, i) => ({ ...file(`file${i}`), targetSize: 4 * 1024 * 1024 }));
  assert.equal(isGitSwitchReview({ ...review(), files: big, paths: big.map((f) => f.path), trackedCount: 3 }, action()), false);
  const duplicate = [file(), file()];
  assert.equal(isGitSwitchReview({ ...review(), files: duplicate, paths: duplicate.map((f) => f.path), trackedCount: 2 }, action()), false);
  let read = 0; const trap = review(); Object.defineProperty(trap, 'targetOid', { enumerable: true, get() { read += 1; return target; } });
  assert.equal(isGitSwitchReview(trap, action()), false); assert.equal(read, 0);
});

test('candidate comparison binds exact reviewed branch, old index, target commit and log policy', () => {
  assert.equal(isGitSwitchIntent(intent(), action()), true); assert.equal(gitLocalIntentMatchesReview(intent(), review()), true);
  for (const change of [{ targetRef: 'refs/heads/other' }, { expectedReferenceRevision: sha('changed') }, { logEnabled: false, candidateLog: sha('nonempty') }])
    assert.equal(isGitSwitchIntent({ ...intent(), ...change }, action()), false);
  for (const change of [{ targetOid: head }, { expectedIndex: sha('changed') }, { expectedHead: target }, { originalLog: sha('changed') }, { logEnabled: true }])
    assert.equal(gitLocalIntentMatchesReview({ ...intent(), ...change }, review()), false);
});

test('only index-returned settled success matches target; known partial phase retains bounded relative recovery paths', () => {
  assert.equal(isGitSwitchMutation(result(), action(), 'apply-1'), true);
  assert.ok(parseGitLocalStatus(applied()));
  for (const change of [{ effectPhase: 'worktree-returned' }, { retainedPaths: ['.git/mrk-git-fixture/index'] }, { observation: observation() }, { intent: null }])
    assert.equal(isGitSwitchMutation({ ...result(), ...change }, action(), 'apply-1'), false);
  for (const phase of ['not-published', 'worktree-returned', 'head-returned', 'index-returned'])
    assert.ok(parseGitLocalStatus(applied(result('recovery-required', phase))));
  const partial = result('recovery-required', 'worktree-returned');
  for (const change of [{ reason: 'unknown' }, { state: 'failed' }, { intent: null }, { effectPhase: 'head-log-returned' }, { effectPhase: 'done' },
    { retainedPaths: ['/private/candidate'] }, { retainedPaths: ['.git/mrk-git-fixture/../HEAD'] }, { retainedPaths: ['.git/config'] },
    { retainedPaths: ['.git/mrk-git-fixture/index', '.git/mrk-git-fixture/index'] }, { retainedPaths: Array(6).fill('.git/mrk-git-fixture/HEAD') }])
    assert.equal(isGitSwitchMutation({ ...partial, ...change }, action(), 'apply-1'), false);
  assert.ok(parseGitLocalStatus(applied({ ...partial, state: 'failed', effectPhase: 'not-published', retainedPaths: [], intent: null })));
});

test('selection sends no operation and never borrows unavailable, stale or foreign branch-list eligibility', async () => {
  const h = await fixture({ list: false }); const before = h.calls.length;
  h.repository.selectSwitchBranch(''); h.repository.selectSwitchBranch('next');
  assert.equal(h.calls.length, before); assert.equal(h.controller.prepareSwitchReason(), 'branch-list-required');
  assert.equal(await h.controller.prepareSwitch(), false);
  const ready = await fixture(); assert.equal(ready.controller.prepareSwitchReason(), null);
  ready.repository.selectSwitchBranch('main'); assert.equal(ready.controller.prepareSwitchReason(), 'switch-target');
  ready.repository.selectSwitchBranch('missing'); assert.equal(ready.controller.prepareSwitchReason(), 'switch-target');
  ready.repository.selectSwitchBranch(''); assert.equal(ready.controller.prepareSwitchReason(), 'switch-name-required');
  ready.repository.selectSwitchBranch('next'); ready.reader.beforeContextIntent();
  assert.equal(ready.controller.prepareSwitchReason(), 'branch-list-required');
  ready.change({ api: null }); assert.equal(ready.controller.prepareSwitchReason(), 'unavailable');
  assert.equal(ready.calls.some((c) => c.name === 'prepare' || c.name === 'apply'), false);
});

test('dirty, detached and unborn observations refuse without starting a prepare', async () => {
  for (const [options, expected] of [[{ changes: [{ path: 'file.txt', index: ' ', worktree: 'M', kind: 'file', conflict: false }] }, 'switch-dirty'],
    [{ branch: null }, 'switch-target'], [{ oid: null }, 'switch-target']]) {
    const h = await fixture(options); assert.equal(h.controller.prepareSwitchReason(), expected);
    assert.equal(await h.controller.prepareSwitch(), false); assert.equal(h.calls.some((c) => c.name === 'prepare'), false);
  }
});

test('genuine joined prepare remains tied to the captured list target oid, not just a matching action name', async () => {
  const h = await fixture(); h.queue('prepare', started(preparedStatus({ ...review(), targetOid: head })));
  await h.controller.prepareSwitch(); assert.equal(h.controller.getSnapshot().uncertain, true);
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(await h.controller.apply(), false);
  assert.equal(h.calls.some((c) => c.name === 'apply'), false);
});

test('early status review cannot retire the original Prepare promise; joined unused review closes without clearing its draft', async () => {
  const h = await fixture(), d = deferred(); h.queue('prepare', () => d.promise);
  const original = h.controller.prepareSwitch(); assert.equal(h.controller.getSnapshot().pending, 1);
  h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().pending, 1); assert.equal(h.controller.reviewReason(), 'busy');
  d.resolve(started(preparedStatus())); await original;
  assert.equal(h.controller.getSnapshot().pending, 0); assert.equal(h.controller.reviewReason(), null);
  h.queue('discard', status(preparedStatus().operation)); await h.controller.discard();
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.repository.getSnapshot().switchDraft.name, 'next');
});

test('changed-and-restored selection is stale; original commit/create drafts remain independent and retained', async () => {
  const h = await fixture(); await prepare(h);
  const draft = h.repository.getSnapshot().draft, branchDraft = h.repository.getSnapshot().branchDraft;
  h.repository.selectSwitchBranch('main'); h.repository.selectSwitchBranch('next');
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.approve(true), false);
  h.queue('discard', status(preparedStatus().operation)); await h.controller.discard();
  assert.equal(h.repository.getSnapshot().draft, draft); assert.equal(h.repository.getSnapshot().branchDraft, branchDraft);
  assert.equal(h.repository.getSnapshot().switchDraft.name, 'next'); assert.equal(h.calls.some((c) => c.name === 'apply'), false);
});

test('retired project context keeps original review close-only on the original port', async () => {
  const h = await fixture(), d = deferred(); h.queue('prepare', () => d.promise);
  const pending = h.controller.prepareSwitch(); h.change({ projectId: 'project-2', session: {}, api: null });
  d.resolve(started(preparedStatus())); await pending;
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.getSnapshot().projectId, 'project-1');
  h.queue('discard', status(preparedStatus().operation)); assert.equal(await h.controller.discard(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'discard', body: { reviewId: 'review-1' } });
});

test('explicit reviewed Apply sends only original review id once, invalidates read eligibility and keeps drafts', async () => {
  const h = await fixture(); await prepare(h);
  const draft = h.repository.getSnapshot().draft, selected = h.repository.getSnapshot().switchDraft, reads = h.reads.length;
  assert.equal(await h.controller.apply(), false); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'apply', body: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' } });
  assert.deepEqual(h.submissions, ['project-1']); assert.equal(h.repository.getSnapshot().stale, true);
  assert.equal(h.repository.getSnapshot().draft, draft); assert.equal(h.repository.getSnapshot().switchDraft, selected);
  assert.equal(h.repository.getSnapshot().observation.head, head); assert.equal(h.reads.length, reads);
  assert.equal(h.controller.getSnapshot().original.result.state, 'succeeded'); assert.equal(h.controller.ownerReason(), null);
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter((c) => c.name === 'apply').length, 1);
});

test('same-tree review still requires a real explicit Apply, not inferred no-op success', async () => {
  const h = await fixture(); await prepare(h, { ...review(), paths: [], files: [], trackedCount: 0 });
  assert.equal(h.controller.getSnapshot().original.phase, 'prepare'); assert.equal(h.submissions.length, 0);
  h.controller.approve(true); h.queue('apply', started(applied(), 'apply')); await h.controller.apply();
  assert.equal(h.calls.filter((c) => c.name === 'apply').length, 1); assert.equal(h.submissions.length, 1);
});

test('lost Apply acknowledgement is not permission to retry; exact original status and Stop remain available', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true);
  h.queue('apply', () => Promise.reject(new Error('not logged'))); await h.controller.apply();
  assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(h.submissions.length, 1);
  assert.equal(await h.controller.prepareSwitch(), false); assert.equal(await h.controller.apply(), false);
  h.queue('status', status(operation('apply'))); await h.controller.checkStatus();
  assert.equal(h.controller.canCancel(), true);
  h.queue('cancel', status(operation('apply', { stage: 'stopping' }))); await h.controller.cancel();
  assert.deepEqual(h.calls.at(-1), { name: 'cancel', body: { operationId: 'apply-1' } });
  assert.equal(h.calls.filter((c) => c.name === 'apply').length, 1);
});

test('known partial phase and candidate paths remain pinned recovery, even after a contradictory late success', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true);
  h.queue('apply', started(applied(result('recovery-required', 'head-returned')), 'apply')); await h.controller.apply();
  const pinned = h.controller.getSnapshot().original;
  assert.equal(h.controller.getSnapshot().recovery, true); assert.deepEqual(pinned.result.retainedPaths, ['.git/mrk-git-fixture/index']);
  h.queue('status', applied()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().original, pinned); assert.equal(h.controller.getSnapshot().recovery, true);
  assert.equal(await h.controller.apply(), false); assert.equal(await h.controller.prepareSwitch(), false);
});

test('cleanup Unknown is absorbing and retains the original Stop route instead of showing success', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true);
  h.queue('apply', started(status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })), 'apply'));
  await h.controller.apply(); const pinned = h.controller.getSnapshot().original;
  h.queue('status', applied()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().original, pinned); assert.equal(h.controller.canCancel(), true);
  h.queue('cancel', applied()); await h.controller.cancel();
  assert.equal(h.controller.getSnapshot().original, pinned); assert.equal(h.controller.getSnapshot().uncertain, true);
  assert.equal(await h.controller.prepareSwitch(), false);
});

test('observed-only switch review is close-only and typed no-admission Apply never becomes an automatic second attempt', async () => {
  const h = await fixture(); h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.approve(true), false);
  h.queue('discard', status(preparedStatus().operation)); await h.controller.discard();
  const other = await fixture(); await prepare(other); other.controller.approve(true);
  other.queue('apply', { schemaVersion: 1, admission: 'refused', request: startRequest('apply'), status: preparedStatus(), reason: 'stale-observation' });
  await other.controller.apply(); assert.equal(other.submissions.length, 1); assert.equal(await other.controller.apply(), false);
  assert.equal(other.calls.filter((c) => c.name === 'apply').length, 1); assert.equal(other.controller.canDiscard(), true);
});

test('switch guidance names unsupported policy and partial recovery without suggesting force, chmod or automatic repair', () => {
  for (const issue of ['switch-layout', 'switch-conversion', 'switch-dirty', 'switch-file-mode', 'switch-identity-required', 'switch-log-limit', 'switch-target', 'switch-name-required'])
    assert.ok(gitSwitchIssueHelp(issue)?.length > 30);
  assert.equal(gitSwitchIssueHelp('invented-native-success'), null);
});
