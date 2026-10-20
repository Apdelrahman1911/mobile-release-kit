import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { isGitInitAction, isGitInitReview, isGitInitIntent, isGitInitMutation, gitInitIssueHelp } from '../src/gitInitProtocol.ts';
import { createGitLocalApi, gitLocalRequest, parseGitLocalStatus, sameGitLocalAction, gitLocalIntentMatchesReview } from '../src/gitLocalProtocol.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';

// Actual existing UI coordination with inert native Promises only. These DATA
// fixtures do not qualify Git, filesystem absence, native owners or finality.
const revision = 'a'.repeat(64), digest = 'b'.repeat(64), head = 'd'.repeat(40);
const sha = (v) => createHash('sha256').update(v).digest('hex');
const decode = (raw) => JSON.parse(new TextDecoder().decode(raw));
const action = () => ({ kind: 'initialize' });
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const review = () => ({ action: 'initialize', expectedRevision: revision, initialBranch: 'main', objectFormat: 'sha1', reviewDigest: digest });
const intent = () => ({ action: 'initialize', expectedRevision: revision, initialBranch: 'main', objectFormat: 'sha1',
  candidateManifest: 'c'.repeat(64), candidateHead: sha('ref: refs/heads/main\n'), candidateConfig: 'e'.repeat(64) });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const status = (operation = null, r = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, operation, review: r });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(),
  stage: 'running', outcome: null, reason: null, result: null, ...extra });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r } }), prepared(r));
const request = (phase = 'prepare') => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? action() : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (s, phase = 'prepare') => ({ schemaVersion: 1, admission: 'started', request: request(phase), status: s, reason: null });
const result = (state = 'succeeded') => ({ operationId: 'apply-1', action: 'initialize', state, settlement: 'settled',
  reason: state === 'succeeded' ? null : 'recovery-required', observation: null, intent: intent() });
const applied = (r = result()) => status(operation('apply', { stage: 'settled', outcome: 'ok', result: r }));
const observation = () => ({ revision, head, branch: 'refs/heads/main', unborn: false, detached: false,
  changes: [], remotes: [], restrictions: [] });
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function fixture({ checked = true, available = true, observed = false, observeResult = observation } = {}) {
  const calls = [], reads = [], submitted = [], queues = Object.fromEntries(['prepare', 'apply', 'discard', 'status', 'cancel'].map((v) => [v, []]));
  const api = Object.fromEntries(Object.keys(queues).map((name) => [name, (raw) => {
    assert.ok(raw instanceof Uint8Array); const body = decode(raw); calls.push({ name, body });
    assert.ok(queues[name].length, `missing inert ${name} response`); const next = queues[name].shift();
    return typeof next === 'function' ? next(body) : Promise.resolve(next);
  }]));
  const repository = new GitRepositoryController('project-1', { projectId: 'project-1',
    observe: async () => { reads.push('observe'); return observeResult(); }, diff: async () => assert.fail('no diff for initialization') });
  repository.editDraft('message', 'Keep my local draft'); repository.editBranchName('later');
  repository.editRenameName('future-name'); repository.selectSwitchBranch('future-switch');
  if (observed) await repository.refresh();
  let binding = { api, session: {}, projectId: 'project-1', repository, epoch: 0, blocked: null };
  const controller = new GitLocalController({ current: () => binding, onMutationSubmitted: (id) => {
    submitted.push(id); repository.invalidate(); binding = { ...binding, epoch: binding.epoch + 1 }; controller.beforeContextIntent();
  } });
  controller.syncContext(); assert.equal(calls.length, 0);
  const h = { controller, repository, calls, reads, submitted, api, queue: (name, v) => queues[name].push(v),
    change(v) { binding = { ...binding, ...v }; controller.syncContext(); },
    get binding() { return binding; } };
  if (checked) { h.queue('status', { ...status(), available }); await controller.checkStatus(); }
  return h;
}
async function prepare(h) {
  h.queue('prepare', started(preparedStatus())); assert.equal(await h.controller.prepareInitialize(), true);
  assert.equal(h.controller.reviewReason(), null); return h.controller.getSnapshot().review;
}

test('initialize uses exactly the existing five RAW commands with no claimed absence, revision, path or branch input', async () => {
  const body = { projectId: 'project-1', expectedDocumentRevision: 1, action: action() };
  assert.deepEqual(decode(gitLocalRequest('prepare', body)), body); assert.ok(isGitInitAction(action()));
  for (const key of ['expectedRevision', 'initialBranch', 'root', 'path', 'tool', 'force', 'template', 'candidate', 'gitAbsent', 'identity', 'message', 'remote']) {
    const v = { ...action(), [key]: null };
    assert.equal(isGitInitAction(v), false); assert.equal(gitLocalRequest('prepare', { ...body, action: v }), null);
  }
  assert.equal(sameGitLocalAction(action(), action()), true);
  assert.equal(sameGitLocalAction(action(), { kind: 'stage', expectedRevision: revision, paths: ['a'] }), false);
  const calls = [], port = createGitLocalApi('native', (name, raw) => { calls.push({ name, body: decode(raw) }); return Promise.resolve(status()); });
  const values = { prepare: body, apply: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' },
    status: {}, cancel: { operationId: 'apply-1' }, discard: { reviewId: 'review-1' } };
  for (const [name, value] of Object.entries(values)) { await port[name](gitLocalRequest(name, value)); assert.equal(calls.at(-1).name, `git_local_${name}`); }
  assert.equal(createGitLocalApi('preview', () => assert.fail()), null);
});
test('closed native review and exact candidate exclude fabricated Git observations and private metadata', () => {
  assert.ok(isGitInitReview(review(), action())); assert.ok(isGitInitIntent(intent(), action()));
  assert.ok(parseGitLocalStatus(preparedStatus())); assert.ok(parseGitLocalStatus(applied()));
  assert.ok(gitLocalIntentMatchesReview(intent(), review()));
  for (const extra of [{ initialBranch: 'other' }, { objectFormat: 'sha256' }, { expectedRevision: null }, { head: null }, { expectedIndex: revision }, { privatePath: '/tmp/new' }])
    assert.equal(isGitInitReview({ ...review(), ...extra }, action()), false);
  for (const extra of [{ candidateHead: revision }, { candidateConfig: null }, { candidateManifest: null }, { argv: [] }, { candidatePath: '.private' }])
    assert.equal(isGitInitIntent({ ...intent(), ...extra }, action()), false);
  for (const extra of [{ observation: observation() }, { intent: null }, { reason: 'unknown' }, { settlement: 'unknown' }, { config: 'private text' }])
    assert.equal(isGitInitMutation({ ...result(), ...extra }, action(), 'apply-1'), false);
  assert.equal(gitLocalIntentMatchesReview({ ...intent(), expectedRevision: 'f'.repeat(64) }, review()), false);
  const getter = {}; Object.defineProperty(getter, 'kind', { enumerable: true, get() { assert.fail('getter executed'); } });
  assert.equal(isGitInitAction(getter), false);
  const decoded = parseGitLocalStatus(preparedStatus()); assert.ok(Object.isFrozen(decoded.review.review));
});
test('no implicit check, Prepare or Git read; unavailable, busy and existing repositories cannot initialize', async () => {
  const h = await fixture({ checked: false }); assert.equal(h.controller.prepareInitializeReason(), 'unavailable');
  assert.equal(await h.controller.prepareInitialize(), false); assert.equal(h.calls.length, 0); assert.equal(h.reads.length, 0);
  h.queue('status', status()); await h.controller.checkStatus();
  assert.equal(h.controller.prepareInitializeReason(), null); assert.equal(h.controller.prepareReason('stage'), 'no-observation');
  for (const v of [{ api: null }, { session: null }, { projectId: 'different' }, { blocked: 'Another original operation.' }]) {
    const h = await fixture(); h.change(v); assert.notEqual(h.controller.prepareInitializeReason(), null);
    assert.equal(await h.controller.prepareInitialize(), false); assert.equal(h.calls.some((v) => v.name === 'prepare'), false);
  }
  const absent = await fixture({ available: false }); assert.equal(absent.controller.prepareInitializeReason(), 'unavailable');
  const existing = await fixture({ observed: true }); assert.equal(existing.controller.prepareInitializeReason(), 'git-already-present');
  existing.repository.invalidate(); assert.equal(existing.controller.prepareInitializeReason(), 'git-already-present');
});
test('a failed original Git read with unknown custody is never converted into absence', async () => {
  const h = await fixture({ observeResult: () => { throw new Error('inert lost read'); } });
  assert.equal(await h.repository.refresh(), true); // Original read entered; its result is not success.
  assert.equal(h.repository.getSnapshot().blocked, 'unknown');
  assert.equal(h.controller.prepareInitializeReason(), 'unknown'); assert.equal(await h.controller.prepareInitialize(), false);
  assert.equal(h.calls.some((v) => v.name === 'prepare'), false);
});
test('explicit native review and unchecked Apply share original owner; drafts stay and no observation is manufactured', async () => {
  const h = await fixture(), before = h.repository.getSnapshot(); await prepare(h);
  assert.deepEqual(h.calls.at(-1), { name: 'prepare', body: { projectId: 'project-1', expectedDocumentRevision: 1, action: action() } });
  assert.equal(await h.controller.apply(), false); assert.equal(h.controller.approve(true), true);
  h.queue('apply', started(applied(), 'apply')); assert.equal(await h.controller.apply(), true);
  assert.deepEqual(h.calls.at(-1), { name: 'apply', body: { projectId: 'project-1', expectedDocumentRevision: 1, reviewId: 'review-1' } });
  assert.deepEqual(h.submitted, ['project-1']); assert.equal(h.reads.length, 0);
  const after = h.repository.getSnapshot(); for (const k of ['draft', 'branchDraft', 'renameDraft', 'switchDraft', 'selected']) assert.equal(after[k], before[k]);
  assert.equal(after.observation, null); assert.equal(after.stale, true);
  assert.equal(h.controller.getSnapshot().original.result.state, 'succeeded'); assert.equal(h.controller.ownerReason(), null);
  assert.equal(await h.controller.apply(), false); assert.equal(h.calls.filter((v) => v.name === 'apply').length, 1);
});
test('changed-and-restored source view, draft and active state retire the same consent without discarding it', async () => {
  for (const mutate of [(h) => h.repository.invalidate(),
    (h) => { h.repository.editDraft('message', 'changed'); h.repository.editDraft('message', 'Keep my local draft'); },
    (h) => { h.repository.setActive(false); h.repository.setActive(true); },
    (h) => { h.change({ epoch: 1 }); h.change({ epoch: 0 }); }]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true); mutate(h);
    assert.equal(h.controller.reviewReason(), 'review-changed'); assert.equal(await h.controller.apply(), false);
    assert.equal(h.controller.getSnapshot().review.prepared.reviewId, 'review-1');
    h.queue('discard', status(preparedStatus().operation)); assert.equal(await h.controller.discard(), true);
    assert.equal(h.controller.getSnapshot().review, null); assert.equal(h.calls.some((v) => v.name === 'apply'), false);
  }
});
test('synchronous publication reentry cannot dispatch a stale Prepare or Apply', async () => {
  for (const phase of ['prepare', 'apply']) for (const mutate of [
    (h) => h.repository.invalidate(), (h) => h.change({ epoch: 1 }), (h) => h.change({ api: { ...h.api } }), (h) => h.change({ blocked: 'peer admitted' })]) {
    const h = await fixture(); if (phase === 'apply') { await prepare(h); h.controller.approve(true); }
    let changed = false;
    const off = h.controller.subscribe(() => { if (!changed && h.controller.getSnapshot().pending) { changed = true; mutate(h); } });
    assert.equal(await (phase === 'prepare' ? h.controller.prepareInitialize() : h.controller.apply()), false); off();
    assert.equal(h.calls.some((v) => v.name === phase), false);
    assert.deepEqual(h.submitted, []);
  }
});
test('early native review DATA never releases an original pending Prepare Promise', async () => {
  const h = await fixture(), d = deferred(); h.queue('prepare', () => d.promise); const original = h.controller.prepareInitialize();
  h.queue('status', preparedStatus()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().pending, 1);
  assert.equal(h.controller.reviewReason(), 'busy'); assert.equal(h.controller.approve(true), false);
  d.resolve(started(preparedStatus())); await original; assert.equal(h.controller.reviewReason(), null);
});
test('early Apply result or context switch never disposes its pending original call', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true);
  const d = deferred(); h.queue('apply', () => d.promise); const original = h.controller.apply();
  h.change({ projectId: 'project-2', epoch: 2 }); h.queue('status', applied()); await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().pending, 1); assert.notEqual(h.controller.ownerReason(), null);
  d.resolve(started(applied(), 'apply')); await original; assert.equal(h.controller.getSnapshot().pending, 0);
  assert.equal(h.controller.getSnapshot().original.context.projectId, 'project-1'); assert.equal(h.submitted.length, 1);
});
test('mismatched candidate or malformed response is not adopted or retried', async () => {
  for (const value of [{ ...applied(), operation: { ...applied().operation, result: { ...result(), intent: { ...intent(), expectedRevision: 'f'.repeat(64) } } } },
    { ...applied(), operation: { ...applied().operation, result: { ...result(), observation: observation() } } }]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true); h.queue('apply', started(value, 'apply')); await h.controller.apply();
    assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(await h.controller.apply(), false);
    assert.equal(await h.controller.prepareInitialize(), false); assert.equal(h.calls.filter((v) => v.name === 'apply').length, 1);
  }
});
test('lost Apply ACK retains exact original Check and Stop with no new initialization', async () => {
  const h = await fixture(); await prepare(h); h.controller.approve(true);
  h.queue('apply', () => Promise.reject(new Error('inert transport loss'))); await h.controller.apply();
  assert.equal(h.controller.getSnapshot().uncertain, true); assert.equal(await h.controller.prepareInitialize(), false);
  h.queue('status', status(operation('apply'))); await h.controller.checkStatus(); assert.equal(h.controller.canCancel(), true);
  h.queue('cancel', status(operation('apply', { stage: 'stopping' }))); await h.controller.cancel();
  assert.deepEqual(h.calls.at(-1), { name: 'cancel', body: { operationId: 'apply-1' } }); assert.equal(h.calls.filter((v) => v.name === 'apply').length, 1);
});
test('cleanup Unknown and metadata recovery are absorbing even after a contradictory late success', async () => {
  for (const unknown of [true, false]) {
    const h = await fixture(); await prepare(h); h.controller.approve(true);
    const value = unknown ? status(operation('apply', { stage: 'cleanup-unknown', outcome: 'cleanup-unknown', reason: 'unknown' })) : applied(result('recovery-required'));
    h.queue('apply', started(value, 'apply')); await h.controller.apply(); const pinned = h.controller.getSnapshot().original;
    h.queue('status', applied()); await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().original, pinned);
    assert.equal(unknown ? h.controller.getSnapshot().uncertain : h.controller.getSnapshot().recovery, true);
    assert.equal(await h.controller.prepareInitialize(), false); assert.equal(await h.controller.apply(), false);
  }
});
test('known preadmission refusal and observed-only review stay distinct from authorization', async () => {
  const h = await fixture(); h.queue('prepare', { schemaVersion: 1, admission: 'refused', request: request(), status: status(), reason: 'stale-observation' });
  await h.controller.prepareInitialize(); assert.equal(h.controller.ownerReason(), null); assert.equal(h.controller.getSnapshot().uncertain, false);
  h.queue('status', preparedStatus()); await h.controller.checkStatus(); assert.equal(h.controller.reviewReason(), 'review-changed');
  assert.equal(h.controller.approve(true), false); assert.equal(await h.controller.apply(), false);
  h.queue('discard', status(preparedStatus().operation)); assert.equal(await h.controller.discard(), true); assert.equal(h.controller.getSnapshot().review, null);
  for (const reason of ['git-already-present', 'git-init-layout', 'git-init-candidate']) assert.ok(gitInitIssueHelp(reason)?.length > 40);
  assert.equal(gitInitIssueHelp('invented-ready'), null);
});
