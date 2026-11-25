import assert from 'node:assert/strict';
import test from 'node:test';
import { isGitBranches, gitBranchName, gitBranchDraftFits, branchIntentMatchesReview } from '../src/gitBranchesProtocol.ts';
import { gitReadRequest, parseGitReadStatus } from '../src/gitReadProtocol.ts';
import { gitLocalRequest, parseGitLocalStatus, parseGitLocalStartResult } from '../src/gitLocalProtocol.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';

// Inert ports only. No invoke, filesystem/process/provider/credential/native
// work; the real controller Promise and correlation paths are exercised.
const revision = 'a'.repeat(64), references = 'b'.repeat(64), index = 'c'.repeat(64), head = 'd'.repeat(40), digest = 'e'.repeat(64);
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const decode = (v) => JSON.parse(new TextDecoder().decode(v));
const action = () => ({ kind: 'branch-create', expectedRevision: revision, expectedReferenceRevision: references, name: 'next' });
const observation = (branch = 'refs/heads/main', oid = head) => ({ revision, head: oid, branch, unborn: oid === null, detached: branch === null,
  changes: [{ path: 'file.txt', index: 'M', worktree: 'M', kind: 'file', conflict: false }], remotes: [], restrictions: [] });
const branches = (branch = 'refs/heads/main', oid = head) => ({ revision, referenceRevision: references, head: oid, branch,
  branches: oid === null ? [] : [{ ref: 'refs/heads/main', oid: head }], basis: 'local-refs-no-fetch' });
const review = () => ({ action: 'branch-create', name: 'next', targetRef: 'refs/heads/next', expectedRevision: revision,
  expectedReferenceRevision: references, head, branch: 'refs/heads/main', expectedIndex: index, reviewDigest: digest });
const intent = () => ({ action: 'branch-create', expectedRevision: revision, expectedReferenceRevision: references, expectedRef: 'refs/heads/main',
  expectedHead: head, expectedIndex: index, targetRef: 'refs/heads/next', expectedTargetAbsent: true, candidateRefOid: head });
const prepared = () => ({ reviewId: 'review-1', context: context(), action: action(), review: review() });
const localStatus = (operation = null, p = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: p, operation });
const localOperation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(),
  stage: 'running', outcome: null, reason: null, result: null, ...extra });
const preparedStatus = () => localStatus(localOperation('prepare', { stage: 'settled', outcome: 'ok', result: { review: review() } }), prepared());
const startRequest = (phase = 'prepare') => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? action() : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (status, request = startRequest()) => ({ schemaVersion: 1, admission: 'started', request, status, reason: null });
function applied(state = 'succeeded') {
  return localStatus(localOperation('apply', { stage: 'settled', outcome: 'ok', result: {
    operationId: 'apply-1', action: 'branch-create', state, settlement: 'settled', reason: state === 'succeeded' ? null : 'recovery-required',
    observation: state === 'succeeded' ? observation() : null, intent: intent(),
  } }));
}
const readStatus = (operation = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, operation });
function readStarted(kind = 'branches', result = branches(), phase = 'settled') {
  const a = { kind, expectedRevision: kind === 'observe' ? null : revision, paths: [], staged: false };
  return { schemaVersion: 1, admission: 'started', request: { projectId: 'project-1', expectedDocumentRevision: 1, action: a }, reason: null,
    status: readStatus({ operationId: `read-${kind}`, context: context(), action: a, phase,
      outcome: phase === 'settled' ? 'ok' : null, reason: null, result: phase === 'settled' ? result : null }) };
}
function deferred() { let resolve, reject; const promise = new Promise((ok, no) => { resolve = ok; reject = no; }); return { promise, resolve, reject }; }
function port(names, calls) {
  const queues = Object.fromEntries(names.map((name) => [name, []]));
  const api = Object.fromEntries(names.map((name) => [name, (raw) => {
    assert.ok(raw instanceof Uint8Array); const body = decode(raw); calls.push({ name, body });
    assert.ok(queues[name].length, `missing inert ${name} reply`);
    const value = queues[name].shift(); return typeof value === 'function' ? value(body) : Promise.resolve(value);
  }]));
  return { api, queue: (name, value) => queues[name].push(value) };
}
async function harness({ readBranches = true, branch = 'refs/heads/main', oid = head } = {}) {
  const calls = [], readCalls = [], submissions = [], localPort = port(['prepare', 'apply', 'discard', 'status', 'cancel'], calls);
  const readPort = port(['start', 'status', 'cancel'], readCalls);
  let controller = null, binding, epoch = 0;
  const session = {};
  const reader = new GitReadController({ current: () => ({ api: readPort.api, session, projectId: binding?.projectId ?? 'project-1', epoch,
    blocked: controller?.ownerReason() ?? binding?.blocked ?? null }) });
  reader.syncContext(); readPort.queue('status', readStatus()); await reader.checkStatus();
  const repository = new GitRepositoryController('project-1', reader.port('project-1'));
  const observed = observation(branch, oid);
  readPort.queue('start', readStarted('observe', { observation: observed, referenceRevision: references, basis: 'local-refs-no-fetch',
    tracking: { state: branch === null ? 'detached' : oid === null ? 'unborn' : 'not-configured', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null } }));
  assert.equal(await repository.refresh(), true);
  repository.editBranchName('next'); repository.select('file.txt', true);
  repository.editDraft('message', 'Keep this draft');
  binding = { api: localPort.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null };
  controller = new GitLocalController({ current: () => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked }),
    onMutationSubmitted: (projectId) => {
      submissions.push(projectId); epoch += 1; binding = { ...binding, epoch }; repository.invalidate();
      reader.beforeContextIntent(); controller.beforeContextIntent();
    } });
  controller.syncContext(); localPort.queue('status', localStatus()); await controller.checkStatus();
  if (readBranches) { readPort.queue('start', readStarted('branches', branches(branch, oid))); assert.equal(await reader.readBranches('project-1', revision), true); }
  return { controller, reader, repository, calls, readCalls, submissions, queue: localPort.queue, readQueue: readPort.queue,
    get binding() { return binding; }, change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h) { h.queue('prepare', started(preparedStatus())); assert.equal(await h.controller.prepareBranch(), true); assert.equal(h.controller.reviewReason(), null); }

test('branch commands use the existing RAW routes and exact tagged fields without widening old file requests', () => {
  const input = { projectId: 'project-1', expectedDocumentRevision: 1, action: action() };
  assert.deepEqual(decode(gitLocalRequest('prepare', input)), input);
  for (const field of ['paths', 'identity', 'message', 'startPoint', 'force', 'argv', 'upstream'])
    assert.equal(gitLocalRequest('prepare', { ...input, action: { ...action(), [field]: null } }), null);
  for (const field of ['expectedRevision', 'expectedReferenceRevision', 'name']) {
    const invalid = action(); delete invalid[field]; assert.equal(gitLocalRequest('prepare', { ...input, action: invalid }), null);
  }
  const old = { kind: 'stage', expectedRevision: revision, paths: ['file.txt'], message: null, identity: null };
  assert.ok(gitLocalRequest('prepare', { ...input, action: old })); delete old.identity;
  assert.equal(gitLocalRequest('prepare', { ...input, action: old }), null);
  const list = { projectId: 'project-1', expectedDocumentRevision: 1, action: { kind: 'branches', expectedRevision: revision, paths: [], staged: false } };
  assert.deepEqual(decode(gitReadRequest('start', list)), list);
  for (const [key, value] of [['expectedRevision', null], ['paths', ['file.txt']], ['staged', true], ['fetch', false]])
    assert.equal(gitReadRequest('start', { ...list, action: { ...list.action, [key]: value } }), null);
});

test('branch name drafts can be incomplete but admitted names are finite and literal', () => {
  for (const name of ['next', 'release-1.2', 'existing/next']) assert.equal(gitBranchName(name), true);
  for (const name of ['', '-next', 'a..b', 'a.lock', 'a/.x', 'a//b', 'a/', 'a@{b', 'a b', 'a\n', 'é', 'a'.repeat(256), Array(17).fill('a').join('/')])
    assert.equal(gitBranchName(name), false);
  assert.equal(gitBranchDraftFits('existing/'), true); assert.equal(gitBranchDraftFits(''), true);
  assert.equal(gitBranchDraftFits('é'.repeat(128)), false); assert.equal(gitBranchDraftFits('x\n'), false);
});

test('list DATA is bounded complete sorted and bound to current branch and observation', () => {
  const good = branches(); assert.equal(isGitBranches(good, revision), true);
  for (const change of [{ revision: references }, { head: 'f'.repeat(40) }, { branch: 'refs/heads/missing' }, { basis: 'remote' }, { url: 'not accepted' },
    { branches: [good.branches[0], good.branches[0]] }, { branches: [{ ref: 'refs/tags/main', oid: head }] },
    { branches: [good.branches[0], { ref: 'refs/heads/z', oid: 'a'.repeat(64) }] },
    { branch: null, branches: Array.from({ length: 257 }, (_, n) => ({ ref: `refs/heads/b${String(n).padStart(3, '0')}`, oid: head })) }])
    assert.equal(isGitBranches({ ...good, ...change }, revision), false);
  assert.equal(isGitBranches(branches('refs/heads/main', null), revision), true);
  assert.equal(isGitBranches({ ...branches('refs/heads/main', null), branch: null }, revision), false);
  const getter = {}; Object.defineProperty(getter, 'revision', { enumerable: true, get() { assert.fail('getter executed'); } });
  assert.equal(isGitBranches(getter, revision), false);
});

test('native branch status has no fabricated diff and old file/branch tags cannot be mixed', () => {
  assert.ok(parseGitLocalStatus(preparedStatus())); assert.ok(parseGitLocalStartResult(started(preparedStatus())));
  for (const change of [{ diff: null }, { paths: [] }]) {
    const value = preparedStatus(); Object.assign(value.review, change); assert.equal(parseGitLocalStatus(value), null);
  }
  for (const change of [{ name: 'other' }, { targetRef: 'refs/heads/other' }, { head: null }, { expectedReferenceRevision: 'f'.repeat(64) }]) {
    const value = preparedStatus(); Object.assign(value.review.review, change); assert.equal(parseGitLocalStatus(value), null);
  }
  const invalid = preparedStatus(); invalid.operation.result.diff = null; assert.equal(parseGitLocalStatus(invalid), null);
  const parsed = parseGitLocalStatus(preparedStatus()); assert.ok(Object.isFrozen(parsed.review.review));
  assert.equal(Object.hasOwn(parsed.review, 'diff'), false);
});

test('branch success preserves reviewed HEAD/current branch and exact candidate reference intent', () => {
  assert.ok(parseGitLocalStatus(applied())); assert.equal(branchIntentMatchesReview(intent(), review()), true);
  for (const change of [{ expectedTargetAbsent: false }, { candidateRefOid: 'f'.repeat(40) }, { targetRef: 'refs/heads/other' },
    { expectedReferenceRevision: 'f'.repeat(64) }, { candidateCommit: null }, { candidateIndex: null }]) {
    const value = applied(); Object.assign(value.operation.result.intent, change); assert.equal(parseGitLocalStatus(value), null);
  }
  for (const change of [{ head: 'f'.repeat(40) }, { branch: 'refs/heads/next' }]) {
    const value = applied(); Object.assign(value.operation.result.observation, change); assert.equal(parseGitLocalStatus(value), null);
  }
});

test('actual reader requires a new explicit list and no mounting or name typing sends a command', async () => {
  const h = await harness({ readBranches: false }), before = h.calls.length;
  assert.equal(h.controller.prepareBranchReason(), 'branch-list-required');
  h.repository.editBranchName('new-name'); assert.equal(h.calls.length, before);
  h.readQueue('start', readStarted()); assert.equal(await h.reader.readBranches('project-1', revision), true);
  assert.equal(h.controller.prepareBranchReason(), null);
  assert.equal(h.reader.getSnapshot().branches.basis, 'local-refs-no-fetch');
  assert.deepEqual(h.readCalls.at(-1).body.action, { kind: 'branches', expectedRevision: revision, paths: [], staged: false });
});

test('one real controller review waits for all original prepare/status Promises before Apply', async () => {
  const h = await harness(), start = deferred(), status = deferred();
  h.queue('prepare', () => start.promise); const sending = h.controller.prepareBranch();
  h.queue('status', () => status.promise); const checking = h.controller.checkStatus();
  status.resolve(preparedStatus()); await checking;
  assert.equal(h.controller.getSnapshot().pending, 1); assert.equal(h.controller.reviewReason(), 'busy');
  assert.equal(h.controller.approve(true), false);
  const historical = preparedStatus(); historical.review = null; start.resolve(started(historical)); await sending;
  assert.equal(h.controller.reviewReason(), null); assert.equal(Object.hasOwn(h.controller.getSnapshot().review.prepared, 'diff'), false);
  assert.deepEqual(h.calls.find((c) => c.name === 'prepare').body.action, action());
});

test('Apply keeps drafts/current observation, invalidates read eligibility and never auto-switches or rereads', async () => {
  const h = await harness(); await prepare(h);
  const branchDraft = h.repository.getSnapshot().branchDraft, draft = h.repository.getSnapshot().draft, files = h.repository.getSnapshot().observation;
  const reads = h.readCalls.length;
  assert.equal(await h.controller.apply(), false); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), startRequest('apply'))); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1).body, { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' });
  assert.deepEqual(h.submissions, ['project-1']); assert.equal(h.repository.getSnapshot().branchDraft, branchDraft);
  assert.equal(h.repository.getSnapshot().draft, draft); assert.equal(h.repository.getSnapshot().observation, files);
  assert.equal(h.reader.getSnapshot().branchesCurrent, false); assert.equal(h.repository.getSnapshot().stale, true);
  assert.equal(h.readCalls.length, reads); assert.equal(h.controller.ownerReason(), null); assert.equal(await h.controller.apply(), false);
});

test('branch-name ABA retires approval while unrelated checkbox or commit-message edits do not alter the ref review', async () => {
  const h = await harness(); await prepare(h); h.controller.approve(true);
  h.repository.select('file.txt', false); h.repository.editDraft('message', 'Unrelated draft change');
  assert.equal(h.controller.reviewReason(), null);
  h.repository.editBranchName('changed'); h.repository.editBranchName('next');
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(await h.controller.apply(), false);
  assert.equal(h.controller.canDiscard(), true); assert.equal(h.calls.filter((c) => c.name === 'apply').length, 0);
});

test('new observation, retired list or project context invalidates branch review without losing draft or original close', async () => {
  for (const mutate of [(h) => h.repository.invalidate(), (h) => h.reader.beforeContextIntent(),
    (h) => h.change({ projectId: 'project-2', epoch: 1 })]) {
    const h = await harness(); await prepare(h); const name = h.repository.getSnapshot().branchDraft;
    h.controller.approve(true); mutate(h);
    assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.repository.getSnapshot().branchDraft, name);
    assert.equal(h.controller.canDiscard(), true); assert.equal(await h.controller.apply(), false);
  }
});

test('listener veto before branch invocation causes no write; post-entry throw remains unknown', async () => {
  const h = await harness(); let once = true;
  h.controller.subscribe(() => { if (once && h.controller.getSnapshot().pending) { once = false; h.binding.blocked = 'Other original owner'; } });
  assert.equal(await h.controller.prepareBranch(), false); assert.equal(h.calls.filter((c) => c.name === 'prepare').length, 0);
  const next = await harness(); await prepare(next); next.controller.approve(true);
  next.queue('apply', () => { throw new Error('private command error'); }); assert.equal(await next.controller.apply(), true);
  assert.equal(next.controller.getSnapshot().uncertain, true); assert.deepEqual(next.submissions, ['project-1']);
  assert.equal(JSON.stringify(next.controller.getSnapshot()).includes('private command error'), false);
  assert.equal(await next.controller.apply(), false);
});

test('lost prepare ACK never becomes retry and known cleanup Unknown pins original against later success', async () => {
  const h = await harness(); h.queue('prepare', () => Promise.reject(new Error('lost'))); await h.controller.prepareBranch();
  assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(await h.controller.prepareBranch(), false);
  const unknown = localStatus(localOperation('prepare', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' }));
  h.queue('status', unknown); await h.controller.checkStatus(); const original = h.controller.getSnapshot().original;
  h.queue('status', preparedStatus()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, original);
  assert.equal(h.controller.canCancel(), true); h.queue('cancel', preparedStatus()); await h.controller.cancel();
  assert.equal(h.controller.getSnapshot().original, original); assert.equal(h.controller.getSnapshot().review, null);
  assert.ok(h.controller.ownerReason()); assert.equal(h.controller.getSnapshot().pending, 0);
});

test('native branch refusal is actionable, core recovery is absorbing, and neither starts another request', async () => {
  const h = await harness(); const refused = localStatus(localOperation('prepare', { stage: 'settled', outcome: 'refused', reason: 'branch-identity-required' }));
  h.queue('prepare', started(refused)); await h.controller.prepareBranch();
  assert.equal(h.controller.getSnapshot().issue, 'branch-identity-required'); assert.equal(h.controller.ownerReason(), null);
  assert.equal(h.calls.filter((c) => c.name === 'prepare').length, 1);
  const next = await harness(); await prepare(next); next.controller.approve(true);
  next.queue('apply', started(applied('recovery-required'), startRequest('apply'))); await next.controller.apply();
  const original = next.controller.getSnapshot().original; next.queue('status', applied()); await next.controller.checkStatus();
  assert.equal(next.controller.getSnapshot().original, original); assert.equal(next.controller.getSnapshot().recovery, true);
  assert.equal(await next.controller.apply(), false);
});

test('historic native result without Prepared is not applicable; a reattached branch review is close-only', async () => {
  const h = await harness(), historical = preparedStatus(); historical.review = null;
  h.queue('prepare', started(historical)); await h.controller.prepareBranch();
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.controller.ownerReason(), null);
  h.queue('status', preparedStatus()); await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.canDiscard(), true);
  h.queue('discard', historical); await h.controller.discard(); assert.equal(h.controller.getSnapshot().review, null);
  assert.equal(h.repository.getSnapshot().branchDraft.name, 'next');
});

test('foreign review/intent original index mismatch is never accepted as this branch operation', async () => {
  const h = await harness(), foreign = preparedStatus(); foreign.review.review.head = 'f'.repeat(40); foreign.operation.result.review.head = 'f'.repeat(40);
  h.queue('prepare', started(foreign)); await h.controller.prepareBranch(); assert.equal(h.controller.getSnapshot().uncertain, true);
  const next = await harness(); await prepare(next); next.controller.approve(true);
  const wrong = applied(); wrong.operation.result.intent.expectedIndex = 'f'.repeat(64);
  next.queue('apply', started(wrong, startRequest('apply'))); await next.controller.apply();
  assert.equal(next.controller.getSnapshot().uncertain, true); assert.ok(next.controller.ownerReason());
});

test('unborn refuses creation and detached review keeps the same detached source', async () => {
  const unborn = await harness({ oid: null }); assert.equal(unborn.controller.prepareBranchReason(), 'unborn-head');
  const detached = await harness({ branch: null }); assert.equal(detached.controller.prepareBranchReason(), null);
  const p = preparedStatus(); p.review.review.branch = null; p.operation.result.review.branch = null;
  detached.queue('prepare', started(p)); await detached.controller.prepareBranch(); assert.equal(detached.controller.reviewReason(), null);
  detached.controller.approve(true); const result = applied(); result.operation.result.intent.expectedRef = null;
  result.operation.result.observation.branch = null; result.operation.result.observation.detached = true;
  detached.queue('apply', started(result, startRequest('apply'))); await detached.controller.apply();
  assert.equal(detached.controller.getSnapshot().original.result.observation.branch, null);
  assert.equal(detached.repository.getSnapshot().observation.branch, null);
});

test('read cleanup Unknown cannot publish a branch list from a later ordinary success', async () => {
  const h = await harness({ readBranches: false }); h.readQueue('start', readStarted('branches', null, 'running'));
  const reading = h.reader.readBranches('project-1', revision);
  await new Promise((resolve) => setImmediate(resolve));
  const unknown = readStarted().status; unknown.operation.phase = 'cleanup-unknown'; unknown.operation.outcome = 'cleanup-unknown';
  unknown.operation.reason = 'unknown'; unknown.operation.result = null;
  assert.ok(parseGitReadStatus(unknown)); h.readQueue('status', unknown); await h.reader.checkStatus();
  assert.equal(await reading, false); const original = h.reader.getSnapshot().original;
  h.readQueue('status', readStarted().status); await h.reader.checkStatus();
  assert.equal(h.reader.getSnapshot().original, original); assert.equal(h.reader.getSnapshot().branches, null);
  assert.notEqual(h.controller.prepareBranchReason(), null);
});
