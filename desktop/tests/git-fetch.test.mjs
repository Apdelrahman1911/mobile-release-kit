// Actual GitLocal/GitRead/repository controllers with inert original IPC promises.
// No Git process, credential, filesystem, HTTP, native joins or DOM is exercised.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { gitLocalRequest, parseGitLocalStatus, parseGitLocalStartResult, sameGitLocalAction, gitLocalIntentMatchesReview, gitLocalPreparedResult } from '../src/gitLocalProtocol.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { parseGitHubConnectionStatus } from '../src/githubConnectionProtocol.ts';
import { gitFetchAccount, sameGitFetchAccount } from '../src/gitFetchSelection.ts';
import { isGitFetchAction, isGitFetchReview, isGitFetchIntent, isGitFetchMutation, gitFetchIssueHelp, GIT_FETCH_EFFECT_LABELS } from '../src/gitFetchProtocol.ts';

const revision = 'a'.repeat(64), references = 'b'.repeat(64), index = 'c'.repeat(64), head = 'd'.repeat(40);
const oldTip = 'e'.repeat(40), newTip = 'f'.repeat(40), packOid = '1'.repeat(40), reviewDigest = '2'.repeat(64);
const decode = raw => JSON.parse(new TextDecoder().decode(raw));
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const action = () => ({ kind: 'fetch', expectedRevision: revision, expectedReferenceRevision: references,
  remote: 'origin', reference: 'refs/heads/main', connectionSessionId: 'session-1', expectedConnectionRevision: 12 });
const observation = () => ({ revision, head, branch: 'refs/heads/work', unborn: false, detached: false,
  changes: [{ path: 'app.txt', index: 'M', worktree: 'M', kind: 'file', conflict: false }], remotes: ['origin'], restrictions: [] });
const review = () => ({ action: 'fetch', remote: 'origin', repository: 'Example/App', reference: 'refs/heads/main', targetRef: 'refs/remotes/origin/main',
  expectedTarget: oldTip, candidateRefOid: newTip, expectedRevision: revision, expectedReferenceRevision: references, head, branch: 'refs/heads/work',
  expectedIndex: index, accountId: '7', repositoryId: '9', login: 'Example', reviewDigest });
const intent = () => ({ action: 'fetch', reviewDigest, expectedRevision: revision, expectedReferenceRevision: references,
  expectedRef: 'refs/heads/work', expectedHead: head, expectedIndex: index, targetRef: 'refs/remotes/origin/main', expectedTarget: oldTip, candidateRefOid: newTip,
  packOid, packSha256: '3'.repeat(64), packBytes: 100, indexSha256: '4'.repeat(64), indexBytes: 50 });
const status = (operation = null, prepared = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: prepared, operation });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(),
  stage: 'running', outcome: null, reason: null, result: null, ...extra });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r, diff: null } }), prepared(r));
const request = (phase = 'prepare', a = action()) => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? a : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (s, phase = 'prepare', a = action()) => ({ schemaVersion: 1, admission: 'started', request: request(phase, a), status: s, reason: null });
const result = (state = 'succeeded', effectPhase = 'ref-published') => ({ operationId: 'apply-1', action: 'fetch', state, settlement: 'settled',
  reason: state === 'succeeded' ? null : 'recovery-required', observation: null, intent: intent(), effectPhase,
  retainedPaths: state === 'succeeded' ? [] : [`objects/pack/pack-${packOid}.keep`] });
const applied = (r = result()) => status(operation('apply', { stage: 'settled', outcome: 'ok', result: r }));
function connection() {
  const fact = value => ({ state: value === null ? 'not-observed' : 'observed', value, observedAt: value === null ? null : '2026-10-20T12:00:00Z', reason: value === null ? 'not-connected' : 'none' });
  const s = { schemaVersion: 1, revision: 12, capability: { readOnlySessionAvailable: true, reason: 'none', deviceLogin: 'publisher-unconfigured', storage: 'session-only' },
    session: { id: 'session-1', projectId: 'project-1', targetRepository: 'Example/App', state: 'connected', expiresAt: '2026-10-20T13:00:00Z' },
    operation: { id: 'connection-1', kind: 'connect', phase: 'settled', reason: 'none' }, account: fact({ id: '7', login: 'Example' }),
    repository: fact({ id: '9', fullName: 'Example/App', defaultBranch: 'main', visibility: 'private', archived: false,
      permissions: { pull: 'reported-allowed', push: 'unknown', admin: 'unknown' } }), automation: fact(null),
    facts: { remoteMutationAvailable: false, dispatchAvailable: false, repositoryActionsSettingsObservation: 'not-run', environmentObservation: 'not-run',
      secretObservation: 'not-run', variableObservation: 'not-run', protectionObservation: 'not-run', runnerObservation: 'not-run', templateCompatibility: 'unknown', releaseReadiness: 'unknown' } };
  assert.ok(parseGitHubConnectionStatus(s));
  return { mode: 'native', context: { documentId: 'document-1', projectId: 'project-1', projectGeneration: 1, repository: 'Example/App' },
    status: s, retained: null, help: null, helpState: 'missing', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null };
}
const pending = new Set();
function deferred() {
  let yes, no; const d = { ended: false, promise: new Promise((resolve, reject) => { yes = resolve; no = reject; }) };
  d.resolve = value => { d.ended = true; pending.delete(d); yes(value); };
  d.reject = error => { d.ended = true; pending.delete(d); no(error); }; pending.add(d); return d;
}
test.afterEach(async () => {
  for (const d of [...pending]) d.reject(new Error('inert test ended'));
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
async function fixture({ draft = true } = {}) {
  const calls = [], reads = [], submissions = [], p = port(['prepare', 'apply', 'discard', 'status', 'cancel'], calls), rp = port(['start', 'status', 'cancel'], reads);
  let controller = null, binding, epoch = 0; const session = {};
  const reader = new GitReadController({ current: () => ({ api: rp.api, session, projectId: binding?.projectId ?? 'project-1', epoch,
    blocked: controller?.ownerReason() ?? binding?.blocked ?? null }) });
  reader.syncContext(); rp.queue('status', { schemaVersion: 1, documentRevision: 1, available: true, operation: null }); await reader.checkStatus();
  const repository = new GitRepositoryController('project-1', reader.port('project-1'));
  const readAction = { kind: 'observe', expectedRevision: null, paths: [], staged: false };
  const read = { schemaVersion: 1, admission: 'started', request: { projectId: 'project-1', expectedDocumentRevision: 1, action: readAction }, reason: null,
    status: { schemaVersion: 1, documentRevision: 1, available: true, operation: { operationId: 'read-1', context: context(), action: readAction,
      phase: 'settled', outcome: 'ok', reason: null, result: { observation: observation(), referenceRevision: references, basis: 'local-refs-no-fetch',
        tracking: { state: 'not-configured', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null } } } } };
  assert.ok(parseGitReadStartResult(read)); rp.queue('start', read); assert.equal(await repository.refresh(), true);
  repository.select('app.txt', true); repository.editDraft('message', 'Keep local commit text'); repository.editBranchName('future');
  if (draft) { repository.editFetchDraft('remote', 'origin'); repository.editFetchDraft('branch', 'main'); }
  binding = { api: p.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null, fetchConnection: connection() };
  controller = new GitLocalController({ current: () => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked }),
    onMutationSubmitted: projectId => { submissions.push(projectId); epoch++; binding = { ...binding, epoch };
      repository.invalidate(); reader.beforeContextIntent(); controller.beforeContextIntent(); } });
  controller.syncContext(); p.queue('status', status()); await controller.checkStatus();
  return { controller, repository, reader, calls, reads, submissions, queue: p.queue, get binding() { return binding; },
    change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h, r = review()) {
  const s = preparedStatus(r); assert.ok(parseGitLocalStartResult(started(s)));
  h.queue('prepare', started(s)); assert.equal(await h.controller.prepareFetch(), true);
  assert.equal(h.controller.reviewReason(), r.expectedTarget === r.candidateRefOid ? 'fetch-up-to-date' : null);
}

test('Fetch uses the same closed RAW Prepare/Apply, no token URL force argv or extra query', () => {
  const body = { projectId: 'project-1', expectedDocumentRevision: 1, action: action() };
  assert.deepEqual(decode(gitLocalRequest('prepare', body)), body); assert.ok(isGitFetchAction(action()));
  for (const field of ['token', 'url', 'force', 'prune', 'paths', 'argv', 'identity', 'message', 'all', 'tags'])
    assert.equal(gitLocalRequest('prepare', { ...body, action: { ...action(), [field]: null } }), null);
  for (const change of [{ remote: '-origin' }, { remote: 'https://github.com/Example/App' }, { reference: 'main' }, { reference: 'refs/heads/../main' },
    { reference: 'refs/tags/v1' }, { reference: 'refs/heads/é' }, { reference: 'refs/heads/a.lock' }, { connectionSessionId: 'session:1' }, { expectedConnectionRevision: 0 }, { expectedConnectionRevision: 0xffffffff }])
    assert.equal(isGitFetchAction({ ...action(), ...change }), false);
  for (const field of ['remote', 'reference', 'connectionSessionId', 'expectedConnectionRevision']) { const a = action(); delete a[field]; assert.equal(isGitFetchAction(a), false); }
  assert.equal(sameGitLocalAction(action(), { ...action(), expectedConnectionRevision: 13 }), false);
  assert.equal(sameGitLocalAction(action(), { ...action(), connectionSessionId: 'session-2' }), false);
});
test('joined Fetch result requires null diff while Prepared stays review-only on the actual controller', async () => {
  const native = preparedStatus();
  assert.deepEqual(Object.keys(native.review).sort(), ['action', 'context', 'review', 'reviewId']);
  assert.deepEqual(gitLocalPreparedResult(native.review), native.operation.result);
  assert.ok(parseGitLocalStatus(native)); assert.ok(parseGitLocalStartResult(started(native)));
  const h = await fixture(); await prepare(h);
  assert.equal(h.controller.getSnapshot().uncertain, false);
  assert.deepEqual(gitLocalPreparedResult(h.controller.getSnapshot().review.prepared), native.operation.result);
  assert.equal(h.controller.getSnapshot().review.approved, false);
  assert.equal(h.calls.some(c => c.name === 'apply'), false);
  for (const edit of [s => { delete s.operation.result.diff; },
    ...[undefined, false, '', {}, []].map(diff => s => { s.operation.result.diff = diff; }),
    s => { s.operation.result.extra = null; }, s => { s.review.diff = null; },
    s => { s.review.extra = null; }]) {
    const invalid = preparedStatus(); edit(invalid);
    assert.equal(parseGitLocalStatus(invalid), null); assert.equal(parseGitLocalStartResult(started(invalid)), null);
    const bad = await fixture(); bad.queue('prepare', started(invalid)); await bad.controller.prepareFetch();
    assert.equal(bad.controller.getSnapshot().uncertain, true);
    assert.equal(bad.controller.getSnapshot().review, null); assert.equal(bad.controller.approve(true), false);
    assert.equal(await bad.controller.apply(), false); assert.equal(bad.calls.some(c => c.name === 'apply'), false);
  }
});
test('review and candidate bindings are complete, nonsecret and reject accessors/unknown fields', () => {
  assert.ok(isGitFetchReview(review(), action())); assert.ok(isGitFetchIntent(intent(), action())); assert.ok(gitLocalIntentMatchesReview(intent(), review()));
  for (const change of [{ targetRef: 'refs/heads/main' }, { remote: 'upstream' }, { expectedReferenceRevision: '5'.repeat(64) },
    { candidateRefOid: '0'.repeat(40) }, { repository: 'https://github.com/Example/App' }, { login: '-invalid' }, { accountId: '0' }, { token: 'INERT' }])
    assert.equal(isGitFetchReview({ ...review(), ...change }, action()), false);
  for (const change of [{ expectedIndex: '5'.repeat(64) }, { candidateRefOid: '6'.repeat(40) }, { expectedHead: oldTip },
    { expectedRef: 'refs/heads/other' }, { reviewDigest: '6'.repeat(64) }, { expectedTarget: null }])
    assert.equal(gitLocalIntentMatchesReview({ ...intent(), ...change }, review()), false);
  for (const change of [{ packBytes: 0 }, { packBytes: 32 * 1024 * 1024 + 1 }, { indexBytes: 1.1 }, { expectedTarget: newTip }, { packOid: '0'.repeat(40) }])
    assert.equal(isGitFetchIntent({ ...intent(), ...change }, action()), false);
  let reads = 0; const value = review(); Object.defineProperty(value, 'login', { enumerable: true, get() { reads++; return 'Example'; } });
  assert.equal(isGitFetchReview(value, action()), false); assert.equal(reads, 0);
});
test('all seven effect phases stay diagnostics; success has no fresh observation or retained files', () => {
  assert.ok(isGitFetchMutation(result(), action(), 'apply-1')); assert.ok(parseGitLocalStatus(applied()));
  for (const phase of Object.keys(GIT_FETCH_EFFECT_LABELS)) assert.ok(isGitFetchMutation(result('recovery-required', phase), action(), 'apply-1'));
  for (const change of [{ observation: observation() }, { intent: null }, { effectPhase: 'objects-linked' }, { reason: 'fetch-up-to-date' }, { retainedPaths: ['mrk-git-fetch-x'] }])
    assert.equal(isGitFetchMutation({ ...result(), ...change }, action(), 'apply-1'), false);
  const partial = result('recovery-required', 'ref-send-entered');
  for (const paths of [['.git/config'], ['/private/file'], ['objects/pack/../config'], [`objects/pack/pack-${oldTip}.pack`], ['mrk-git-fetch-x', 'mrk-git-fetch-x'],
    ['mrk-git-fetch-z', 'mrk-git-fetch-a'], Array.from({ length: 6 }, (_, i) => `mrk-git-fetch-${i}`)])
    assert.equal(isGitFetchMutation({ ...partial, retainedPaths: paths }, action(), 'apply-1'), false);
  assert.ok(isGitFetchMutation({ ...partial, intent: null, effectPhase: 'not-published', retainedPaths: ['mrk-git-fetch-fixture'] }, action(), 'apply-1'));
});
test('manual remote/branch draft and current selected account are required without automatic read or selection', async () => {
  const h = await fixture({ draft: false }), count = h.calls.length, reads = h.reads.length;
  assert.deepEqual(h.repository.getSnapshot().fetchDraft, { remote: '', branch: '' }); assert.equal(h.controller.prepareFetchReason(), 'fetch-selection-required');
  h.repository.editFetchDraft('remote', 'upstream'); h.repository.editFetchDraft('branch', 'main'); assert.equal(h.controller.prepareFetchReason(), 'fetch-selection-required');
  h.repository.editFetchDraft('remote', 'origin'); assert.equal(h.controller.prepareFetchReason(), null);
  assert.equal(h.calls.length, count); assert.equal(h.reads.length, reads); assert.equal(h.reads.some(c => c.body.action?.kind === 'branches'), false);
  for (const edit of [{ mode: 'preview' }, { busy: 'refresh' }, { uncertain: true }, { observing: true }, { retirementPending: true }, { blocked: true }])
    assert.equal(gitFetchAccount({ ...connection(), ...edit }, 'project-1'), null);
  const a = gitFetchAccount(h.binding.fetchConnection, 'project-1'); assert.ok(a); assert.equal(sameGitFetchAccount(a, connection(), 'project-1'), false);
  h.change({ fetchConnection: null }); assert.equal(h.controller.prepareFetchReason(), 'fetch-connection-required');
  h.change({ fetchConnection: connection() }); h.reader.beforeContextIntent(); assert.equal(h.controller.prepareFetchReason(), 'fetch-read-required');
});
test('explicit review then one Apply preserves all drafts and leaves fetched remote facts unadopted', async () => {
  const h = await fixture(), before = h.repository.getSnapshot(), oldRead = h.reader.getSnapshot().observation, reads = h.reads.length;
  await prepare(h); assert.equal(await h.controller.apply(), false); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'apply', body: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' } });
  for (const key of ['draft', 'branchDraft', 'switchDraft', 'renameDraft', 'fetchDraft', 'selected', 'observation']) assert.equal(h.repository.getSnapshot()[key], before[key]);
  assert.equal(h.repository.getSnapshot().stale, true); assert.equal(h.reader.getSnapshot().observation, oldRead); assert.equal(h.reader.getSnapshot().stale, true);
  assert.equal(h.reads.length, reads); assert.deepEqual(h.submissions, ['project-1']); assert.equal(h.controller.ownerReason(), null);
  assert.equal(h.controller.getSnapshot().original.result.observation, null); assert.equal(await h.controller.apply(), false);
  assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
});
test('equal-tip native review is close-only, never an Apply or future-current claim', async () => {
  const h = await fixture(); await prepare(h, { ...review(), expectedTarget: newTip });
  assert.equal(h.controller.approve(true), false); assert.equal(await h.controller.apply(), false); assert.equal(h.controller.canDiscard(), true);
  h.queue('discard', status(preparedStatus({ ...review(), expectedTarget: newTip }).operation)); await h.controller.discard();
  assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.calls.some(c => c.name === 'apply'), false);
  assert.equal(h.repository.getSnapshot().fetchDraft.branch, 'main');
});
test('account/session/project/read and draft ABA retire Fetch consent without repeated render publications', async () => {
  for (const change of [h => h.change({ fetchConnection: connection() }), h => h.change({ epoch: 1 }), h => h.change({ session: {} }),
    h => h.change({ projectId: 'project-2' }), h => h.reader.beforeContextIntent(), h => {
      h.repository.editFetchDraft('branch', 'other'); h.repository.editFetchDraft('branch', 'main');
    }]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true); change(h);
    assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(h.controller.approve(true), false); assert.equal(await h.controller.apply(), false);
    assert.equal(h.calls.some(c => c.name === 'apply'), false);
  }
  const h = await fixture(); await prepare(h); h.controller.approve(true); const old = h.binding.fetchConnection;
  h.change({ fetchConnection: connection() }); h.change({ fetchConnection: old }); assert.equal(h.controller.reviewReason(), 'review-changed');
  let publishes = 0; const off = h.controller.subscribe(() => publishes++); h.controller.syncContext(); h.controller.syncContext(); off(); assert.equal(publishes, 0);
});
test('ordinary local file review survives only an account change; Fetch adds no global account gate', async () => {
  const h = await fixture(), a = { kind: 'stage', expectedRevision: revision, paths: ['app.txt'] };
  const r = { action: 'stage', expectedRevision: revision, paths: ['app.txt'], wholeIndex: false, head, branch: 'refs/heads/work', expectedIndex: index, reviewDigest };
  const diff = { revision, staged: false, paths: ['app.txt'], text: '-before\n+after\n', withheld: null };
  const p = { reviewId: 'review-1', context: context(), action: a, review: r, diff };
  const s = status(operation('prepare', { action: a, stage: 'settled', outcome: 'ok', result: { review: r, diff } }), p);
  assert.ok(parseGitLocalStatus(s)); h.queue('prepare', started(s, 'prepare', a)); await h.controller.prepare('stage'); assert.equal(h.controller.reviewReason(), null);
  h.controller.approve(true); h.change({ fetchConnection: null }); assert.equal(h.controller.reviewReason(), null); assert.equal(h.controller.getSnapshot().review.approved, true);
});
test('reentrant listener changes before actual Prepare/Apply veto invocation and preserve newer drafts', async () => {
  for (const phase of ['prepare', 'apply']) for (const kind of ['account', 'draft', 'peer']) {
    const h = await fixture(); if (phase === 'apply') { await prepare(h); h.controller.approve(true); }
    let changed = false; const off = h.controller.subscribe(() => {
      if (!changed && h.controller.getSnapshot().pending) { changed = true;
        if (kind === 'account') h.change({ fetchConnection: connection() });
        else if (kind === 'peer') h.change({ blocked: 'Original peer owns work.' });
        else h.repository.editFetchDraft('branch', 'new-local-draft');
      }
    });
    assert.equal(await (phase === 'prepare' ? h.controller.prepareFetch() : h.controller.apply()), false); off();
    assert.equal(h.calls.some(c => c.name === phase), false); assert.deepEqual(h.submissions, []);
    if (kind === 'draft') assert.equal(h.repository.getSnapshot().fetchDraft.branch, 'new-local-draft');
  }
});
test('returned account/repository and complete action mismatch cannot become a usable review', async () => {
  for (const edit of [s => s.review.review.accountId = s.operation.result.review.accountId = '8',
    s => s.review.review.repositoryId = s.operation.result.review.repositoryId = '10',
    s => s.review.review.login = s.operation.result.review.login = 'Other',
    s => s.review.review.repository = s.operation.result.review.repository = 'Other/App',
    s => s.review.action.expectedConnectionRevision = 13,
    s => s.operation.action.connectionSessionId = 'session-2']) {
    const h = await fixture(), s = structuredClone(preparedStatus()); edit(s); h.queue('prepare', started(s)); await h.controller.prepareFetch();
    assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.controller.approve(true), false);
  }
});
test('terminal status never drops pending Prepare/Status/Stop originals or permits a replacement API', async () => {
  const h = await fixture(), start = deferred(); h.queue('prepare', () => start.promise); const sending = h.controller.prepareFetch();
  h.queue('status', status(operation())); await h.controller.checkStatus(); assert.equal(h.controller.canCancel(), true);
  const check = deferred(), stop = deferred(); h.queue('status', () => check.promise); const checking = h.controller.checkStatus();
  h.queue('cancel', () => stop.promise); const stopping = h.controller.cancel();
  const replacement = port(['prepare', 'apply', 'discard', 'status', 'cancel'], []); h.change({ api: replacement.api, session: {}, projectId: 'project-2' });
  check.resolve(preparedStatus()); await checking; assert.equal(h.controller.getSnapshot().pending, 2); assert.ok(h.controller.ownerReason());
  assert.equal(h.controller.reviewReason(), 'busy'); assert.equal(await h.controller.prepareFetch(), false);
  stop.resolve(status(operation('prepare', { stage: 'stopping' }))); await stopping; assert.equal(h.controller.getSnapshot().pending, 1);
  start.resolve(started(preparedStatus())); await sending; assert.equal(h.controller.getSnapshot().pending, 0); assert.equal(h.controller.reviewReason(), 'review-changed');
  h.queue('discard', status(preparedStatus().operation)); await h.controller.discard(); assert.equal(h.calls.at(-1).name, 'discard');
});
test('clean pre-admission refusal is distinct from lost, thrown and non-Promise Apply acknowledgements', async () => {
  const refused = await fixture(); refused.queue('prepare', { schemaVersion: 1, admission: 'refused', request: request(), status: status(), reason: 'stale-observation' });
  await refused.controller.prepareFetch(); assert.equal(refused.controller.ownerReason(), null); assert.equal(refused.repository.getSnapshot().stale, true);
  assert.equal(refused.controller.getSnapshot().issue, 'stale-observation');
  for (const reply of [() => Promise.reject(new Error('INERT PRIVATE DETAIL')), () => { throw new Error('INERT PRIVATE DETAIL'); }, () => null]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true); h.queue('apply', reply); await h.controller.apply();
    assert.equal(h.controller.getSnapshot().uncertain, true); assert.deepEqual(h.submissions, ['project-1']); assert.equal(h.repository.getSnapshot().stale, true);
    assert.equal(await h.controller.prepareFetch(), false); assert.equal(await h.controller.apply(), false);
    h.queue('status', status(operation('apply'))); await h.controller.checkStatus(); assert.equal(h.controller.canCancel(), true);
    h.queue('cancel', status(operation('apply', { stage: 'stopping' }))); await h.controller.cancel();
    assert.deepEqual(h.calls.at(-1), { name: 'cancel', body: { operationId: 'apply-1' } }); assert.equal(h.calls.filter(c => c.name === 'apply').length, 1);
    assert.equal(JSON.stringify(h.controller.getSnapshot()).includes('INERT PRIVATE'), false);
  }
});
test('partial publication and either cleanup Unknown representation pin originals through late replies', async () => {
  const representations = [applied(result('recovery-required', 'objects-linked')),
    status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })),
    applied({ ...result('failed', 'ref-send-entered'), reason: 'cleanup-unknown' }),
    applied({ ...result('failed', 'ref-send-entered'), reason: 'unknown' })];
  for (const s of representations) for (const observedOnly of [false, true]) {
    const h = await fixture();
    if (observedOnly) { h.queue('status', s); await h.controller.checkStatus(); }
    else { await prepare(h); h.controller.approve(true); h.queue('apply', started(s, 'apply')); await h.controller.apply(); }
    const pinned = h.controller.getSnapshot().original; assert.ok(h.controller.ownerReason());
    h.queue('status', applied()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, pinned);
    assert.equal(await h.controller.prepareFetch(), false); assert.equal(await h.controller.apply(), false);
    if (h.controller.getSnapshot().uncertain) { assert.equal(h.controller.canCancel(), true); h.queue('cancel', applied()); await h.controller.cancel();
      assert.equal(h.controller.getSnapshot().original, pinned); assert.equal(h.controller.getSnapshot().uncertain, true); }
    else assert.equal(h.controller.getSnapshot().recovery, true);
  }
});
test('fetch fallback explains access and preservation without authorizing reset or synthetic freshness', () => {
  for (const reason of ['fetch-remote', 'fetch-layout', 'fetch-identity-required', 'fetch-ref-parent', 'fetch-read-required',
    'fetch-connection-required', 'fetch-selection-required', 'fetch-up-to-date', 'not-found-or-inaccessible', 'cleanup-unknown']) assert.ok(gitFetchIssueHelp(reason)?.length > 30);
  assert.equal(gitFetchIssueHelp('ready-to-release'), null);
});
