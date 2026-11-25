import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { isGitRenameReview, isGitRenameIntent, isGitRenameMutation, gitRenameIssueHelp } from '../src/gitRenameProtocol.ts';
import { gitLocalRequest, parseGitLocalStatus, sameGitLocalAction, gitLocalIntentMatchesReview } from '../src/gitLocalProtocol.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';

// Existing real controllers + inert native API promises. No native invocation,
// process, Git repository, filesystem, Store, credentials or DOM qualification.
const revision = 'a'.repeat(64), references = 'b'.repeat(64), index = 'c'.repeat(64), head = 'd'.repeat(40);
const sha = (s) => createHash('sha256').update(s).digest('hex');
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const decode = (raw) => JSON.parse(new TextDecoder().decode(raw));
const action = () => ({ kind: 'branch-rename', expectedRevision: revision, expectedReferenceRevision: references, name: 'next' });
const observation = (branch = 'refs/heads/main', oid = head, changes = []) => ({ revision, head: oid, branch, unborn: oid === null,
  detached: branch === null, changes, remotes: [], restrictions: [] });
const branchList = (branch = 'refs/heads/main', oid = head) => ({ revision, referenceRevision: references, head: oid, branch,
  branches: oid === null ? [] : [{ ref: 'refs/heads/main', oid: head }], basis: 'local-refs-no-fetch' });
const review = () => ({ action: 'branch-rename', name: 'next', targetRef: 'refs/heads/next', expectedRevision: revision,
  expectedReferenceRevision: references, head, branch: 'refs/heads/main', expectedIndex: index, configMoved: true, logging: true,
  originalConfig: sha('private config not sent'), originalLog: sha('private branch log not sent'), originalHeadLog: sha('private head log not sent'), reviewDigest: 'f'.repeat(64) });
const intent = () => ({ action: 'branch-rename', expectedRevision: revision, expectedReferenceRevision: references, expectedRef: 'refs/heads/main',
  expectedHead: head, expectedIndex: index, targetRef: 'refs/heads/next', expectedTargetAbsent: true, originalConfig: review().originalConfig,
  candidateConfig: sha('candidate config'), originalLog: review().originalLog, candidateLog: sha('candidate log'),
  originalHeadLog: review().originalHeadLog, candidateHeadLog: sha('candidate head log'), configMoved: true, logging: true });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const status = (operation = null, p = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: p, operation });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(),
  stage: 'running', outcome: null, reason: null, result: null, ...extra });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r } }), prepared(r));
const startRequest = (phase = 'prepare') => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? action() : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (value, phase = 'prepare') => ({ schemaVersion: 1, admission: 'started', request: startRequest(phase), status: value, reason: null });
const result = (state = 'succeeded', effectPhase = 'config-returned') => ({ operationId: 'apply-1', action: 'branch-rename', state, settlement: 'settled',
  reason: state === 'succeeded' ? null : 'recovery-required', observation: state === 'succeeded' ? observation('refs/heads/next') : null,
  intent: intent(), effectPhase, retainedPaths: state === 'succeeded' ? [] : ['.git/mrk-git-fixture/index'] });
const applied = (r = result()) => status(operation('apply', { stage: 'settled', outcome: 'ok', result: r }));
const readStatus = (operation = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, operation });
function readStarted(kind, value) {
  const a = { kind, expectedRevision: kind === 'observe' ? null : revision, paths: [], staged: false };
  const r = { schemaVersion: 1, admission: 'started', request: { projectId: 'project-1', expectedDocumentRevision: 1, action: a }, reason: null,
    status: readStatus({ operationId: `read-${kind}`, context: context(), action: a, phase: 'settled', outcome: 'ok', reason: null, result: value }) };
  assert.ok(parseGitReadStartResult(r)); return r;
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function port(names, calls) {
  const queues = Object.fromEntries(names.map((n) => [n, []]));
  return { queue: (n, value) => queues[n].push(value), api: Object.fromEntries(names.map((name) => [name, (raw) => {
    assert.ok(raw instanceof Uint8Array); const body = decode(raw); calls.push({ name, body });
    assert.ok(queues[name].length, `missing inert ${name} reply`); const value = queues[name].shift();
    return typeof value === 'function' ? value(body) : Promise.resolve(value);
  }])) };
}
async function fixture({ list = true, branch = 'refs/heads/main', oid = head, changes = [], extraBranches = [] } = {}) {
  const calls = [], reads = [], submissions = [], p = port(['prepare', 'apply', 'discard', 'status', 'cancel'], calls), rp = port(['start', 'status', 'cancel'], reads);
  const session = {}; let controller = null, binding, epoch = 0;
  const reader = new GitReadController({ current: () => ({ api: rp.api, session, projectId: binding?.projectId ?? 'project-1', epoch,
    blocked: controller?.ownerReason() ?? binding?.blocked ?? null }) });
  reader.syncContext(); rp.queue('status', readStatus()); await reader.checkStatus();
  const repository = new GitRepositoryController('project-1', reader.port('project-1'));
  rp.queue('start', readStarted('observe', { observation: observation(branch, oid, changes), referenceRevision: references, basis: 'local-refs-no-fetch',
    tracking: { state: branch === null ? 'detached' : oid === null ? 'unborn' : 'not-configured', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null } }));
  assert.equal(await repository.refresh(), true); repository.editDraft('message', 'Keep this draft'); repository.editBranchName('future');
  repository.selectSwitchBranch('kept-switch'); repository.editRenameName('next');
  binding = { api: p.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null };
  controller = new GitLocalController({ current: () => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked }),
    onMutationSubmitted: (projectId) => { submissions.push(projectId); epoch += 1; binding = { ...binding, epoch };
      repository.invalidate(); reader.beforeContextIntent(); controller.beforeContextIntent(); } });
  controller.syncContext(); p.queue('status', status()); await controller.checkStatus();
  if (list) { const b = branchList(branch, oid); b.branches.push(...extraBranches); b.branches.sort((a, b) => a.ref < b.ref ? -1 : a.ref > b.ref ? 1 : 0);
    rp.queue('start', readStarted('branches', b)); assert.equal(await reader.readBranches('project-1', revision), true); }
  return { controller, reader, repository, calls, reads, submissions, queue: p.queue,
    change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h, r = review()) { h.queue('prepare', started(preparedStatus(r))); assert.equal(await h.controller.prepareRename(), true); assert.equal(h.controller.reviewReason(), null); }

test('rename RAW has no old-ref path, force, private config, user identity or supplied candidate', () => {
  const value = { projectId: 'project-1', expectedDocumentRevision: 1, action: action() };
  assert.deepEqual(decode(gitLocalRequest('prepare', value)), value);
  for (const key of ['oldName', 'oldRef', 'root', 'argv', 'paths', 'force', 'identity', 'message', 'config', 'rename', 'review'])
    assert.equal(gitLocalRequest('prepare', { ...value, action: { ...action(), [key]: null } }), null);
  for (const key of ['name', 'expectedRevision', 'expectedReferenceRevision']) { const a = action(); delete a[key]; assert.equal(gitLocalRequest('prepare', { ...value, action: a }), null); }
  for (const name of ['', '-next', '../next', 'a.lock', 'a\n', 'a'.repeat(256)]) assert.equal(gitLocalRequest('prepare', { ...value, action: { ...action(), name } }), null);
  assert.equal(sameGitLocalAction(action(), { ...action(), expectedReferenceRevision: sha('changed') }), false);
  assert.ok(gitLocalRequest('prepare', { ...value, action: { kind: 'stage', expectedRevision: revision, paths: ['a'], message: null, identity: null } }));
});
test('review is closed and source-bound, including same parent, missing logs, no accessor execution', () => {
  assert.ok(isGitRenameReview(review(), action())); assert.ok(parseGitLocalStatus(preparedStatus()));
  for (const update of [{ branch: null }, { branch: 'refs/heads/group/main' }, { branch: 'refs/heads/NEXT' }, { targetRef: 'refs/heads/other' },
    { logging: false }, { configMoved: null }, { config: 'not a preview' }, { originalHeadLog: null }, { expectedReferenceRevision: sha('changed') }])
    assert.equal(isGitRenameReview({ ...review(), ...update }, action()), false);
  assert.ok(isGitRenameReview({ ...review(), logging: false, originalLog: sha('absent'), originalHeadLog: sha('absent') }, action()));
  let read = 0; const trap = review(); Object.defineProperty(trap, 'head', { enumerable: true, get() { read += 1; return head; } });
  assert.equal(isGitRenameReview(trap, action()), false); assert.equal(read, 0);
});
test('candidate retains reviewed commit/index/config/log policy and cannot rewrite an absent branch section', () => {
  assert.ok(isGitRenameIntent(intent(), action())); assert.ok(gitLocalIntentMatchesReview(intent(), review()));
  for (const update of [{ expectedHead: 'e'.repeat(40) }, { expectedIndex: sha('changed') }, { originalConfig: sha('changed') },
    { originalLog: sha('changed') }, { originalHeadLog: sha('changed') }])
    assert.equal(gitLocalIntentMatchesReview({ ...intent(), ...update }, review()), false);
  assert.equal(isGitRenameIntent({ ...intent(), configMoved: false }, action()), false);
  assert.equal(isGitRenameIntent({ ...intent(), expectedTargetAbsent: false }, action()), false);
  assert.equal(isGitRenameIntent({ ...intent(), logging: false }, action()), false);
});
test('only final metadata step succeeds; partial phase and relative candidate paths never mean cleanup', () => {
  assert.ok(isGitRenameMutation(result(), action(), 'apply-1')); assert.ok(parseGitLocalStatus(applied()));
  for (const change of [{ effectPhase: 'ref-returned' }, { effectPhase: 'head-returned' }, { observation: observation() },
    { observation: observation('refs/heads/next', 'e'.repeat(40)) }, { intent: null }, { retainedPaths: ['.git/mrk-git-fixture/index'] }])
    assert.equal(isGitRenameMutation({ ...result(), ...change }, action(), 'apply-1'), false);
  for (const phase of ['not-published', 'new-log-returned', 'old-log-returned', 'ref-returned', 'head-log-returned', 'head-returned', 'config-returned'])
    assert.ok(parseGitLocalStatus(applied(result('recovery-required', phase))));
  const partial = result('recovery-required', 'ref-returned');
  for (const change of [{ reason: 'unknown' }, { state: 'failed' }, { intent: null }, { effectPhase: 'index-returned' }, { retainedPaths: ['.git/config'] },
    { retainedPaths: ['/private/candidate'] }, { retainedPaths: ['.git/mrk-git-x/../index'] }, { retainedPaths: Array(2).fill('.git/mrk-git-x/index') }])
    assert.equal(isGitRenameMutation({ ...partial, ...change }, action(), 'apply-1'), false);
  const noConfig = { ...intent(), configMoved: false, candidateConfig: intent().originalConfig };
  assert.ok(isGitRenameMutation({ ...result(), effectPhase: 'head-returned', intent: noConfig }, action(), 'apply-1'));
});
test('typing is local only; unavailable, stale or missing branch list cannot nominate a rename', async () => {
  const h = await fixture({ list: false }), count = h.calls.length; h.repository.editRenameName(''); h.repository.editRenameName('next');
  assert.equal(h.calls.length, count); assert.equal(h.controller.prepareRenameReason(), 'branch-list-required'); assert.equal(await h.controller.prepareRename(), false);
  const ready = await fixture(); ready.reader.beforeContextIntent(); assert.equal(ready.controller.prepareRenameReason(), 'branch-list-required');
  ready.change({ api: null }); assert.equal(ready.controller.prepareRenameReason(), 'unavailable');
});
test('same-parent current branch only; no detached, unborn, case collision or replacing existing target', async () => {
  for (const options of [{ branch: null }, { oid: null }]) { const h = await fixture(options); assert.equal(h.controller.prepareRenameReason(), 'rename-layout'); }
  const h = await fixture();
  for (const name of ['MAIN', 'main', 'group/next']) { h.repository.editRenameName(name); assert.equal(h.controller.prepareRenameReason(), 'rename-target'); }
  h.repository.editRenameName(''); assert.equal(h.controller.prepareRenameReason(), 'rename-name-required');
  for (const ref of ['refs/heads/next', 'refs/heads/NEXT', 'refs/heads/next/sub']) {
    const h = await fixture({ extraBranches: [{ ref, oid: head }] }); assert.equal(h.controller.prepareRenameReason(), 'rename-target');
    assert.equal(await h.controller.prepareRename(), false); assert.equal(h.calls.some((v) => v.name === 'prepare'), false);
  }
});
test('dirty and staged work are allowed but preserved; one explicit Apply keeps original owner and invalidates reads', async () => {
  const changes = [{ path: 'a.txt', index: 'M', worktree: 'M', kind: 'file', conflict: false }], h = await fixture({ changes });
  assert.equal(h.controller.prepareRenameReason(), null); await prepare(h);
  const before = h.repository.getSnapshot(), reads = h.reads.length;
  assert.equal(await h.controller.apply(), false); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'apply', body: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' } });
  const after = h.repository.getSnapshot(); for (const key of ['draft', 'branchDraft', 'switchDraft', 'renameDraft', 'observation']) assert.equal(after[key], before[key]);
  assert.equal(after.stale, true); assert.equal(h.reads.length, reads); assert.deepEqual(h.submissions, ['project-1']);
  assert.equal(h.controller.getSnapshot().original.result.state, 'succeeded'); assert.equal(h.controller.ownerReason(), null);
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter((v) => v.name === 'apply').length, 1);
});
test('changed-and-restored name retires consent, while close retains every project draft', async () => {
  const h = await fixture(); await prepare(h); const before = h.repository.getSnapshot();
  h.repository.editRenameName('other'); h.repository.editRenameName('next');
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.approve(true), false);
  h.queue('discard', status(preparedStatus().operation)); assert.equal(await h.controller.discard(), true);
  for (const key of ['draft', 'branchDraft', 'switchDraft']) assert.equal(h.repository.getSnapshot()[key], before[key]);
  assert.equal(h.repository.getSnapshot().renameDraft.name, 'next'); assert.equal(h.calls.some((v) => v.name === 'apply'), false);
});
test('reentrant name or context changes before handoff prevent native Prepare and Apply', async () => {
  const h = await fixture(); let changed = false;
  const off = h.controller.subscribe(() => { if (!changed && h.controller.getSnapshot().pending) { changed = true; h.repository.editRenameName('other'); } });
  assert.equal(await h.controller.prepareRename(), false); off(); assert.equal(h.calls.some((v) => v.name === 'prepare'), false);
  const ready = await fixture(); await prepare(ready); ready.controller.approve(true); let swapped = false;
  const stop = ready.controller.subscribe(() => { if (!swapped && ready.controller.getSnapshot().pending) { swapped = true; ready.change({ epoch: 1 }); } });
  assert.equal(await ready.controller.apply(), false); stop(); assert.equal(ready.calls.some((v) => v.name === 'apply'), false); assert.deepEqual(ready.submissions, []);
});
test('early settled DATA cannot release an original pending Prepare; wrong returned branch is not adopted', async () => {
  const h = await fixture(), d = deferred(); h.queue('prepare', () => d.promise); const original = h.controller.prepareRename();
  h.queue('status', preparedStatus()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().pending, 1); assert.equal(h.controller.reviewReason(), 'busy');
  d.resolve(started(preparedStatus())); await original; assert.equal(h.controller.reviewReason(), null);
  const wrong = await fixture(); wrong.queue('prepare', started(preparedStatus({ ...review(), head: 'e'.repeat(40) })));
  await wrong.controller.prepareRename(); assert.equal(wrong.controller.getSnapshot().uncertain, true); assert.equal(wrong.controller.getSnapshot().review, null);
});
test('lost Apply ACK never retries and preserves exact original Check and Stop', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true);
  h.queue('apply', () => Promise.reject(new Error('not logged'))); await h.controller.apply();
  assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(await h.controller.prepareRename(), false); assert.equal(await h.controller.apply(), false);
  h.queue('status', status(operation('apply'))); await h.controller.checkStatus(); assert.equal(h.controller.canCancel(), true);
  h.queue('cancel', status(operation('apply', { stage: 'stopping' }))); await h.controller.cancel();
  assert.deepEqual(h.calls.at(-1), { name: 'cancel', body: { operationId: 'apply-1' } }); assert.equal(h.calls.filter((v) => v.name === 'apply').length, 1);
});
test('partial rename and cleanup Unknown pin evidence instead of accepting contradictory late success', async () => {
  for (const unknown of [false, true]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true);
    const value = unknown ? status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })) : applied(result('recovery-required', 'ref-returned'));
    h.queue('apply', started(value, 'apply')); await h.controller.apply(); const pinned = h.controller.getSnapshot().original;
    h.queue('status', applied()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, pinned);
    assert.equal(unknown ? h.controller.getSnapshot().uncertain : h.controller.getSnapshot().recovery, true);
    assert.equal(await h.controller.apply(), false); assert.equal(await h.controller.prepareRename(), false);
  }
});
test('observed-only review is close-only and clear manual fallback never offers force or reset', async () => {
  const h = await fixture(); h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.approve(true), false);
  h.queue('discard', status(preparedStatus().operation)); await h.controller.discard(); assert.equal(h.controller.getSnapshot().review, null);
  for (const reason of ['rename-layout', 'rename-target', 'rename-config', 'rename-log', 'rename-log-missing', 'rename-identity-required', 'rename-packed', 'rename-name-required'])
    assert.ok(gitRenameIssueHelp(reason)?.length > 30);
  assert.equal(gitRenameIssueHelp('invented-ready'), null);
});
