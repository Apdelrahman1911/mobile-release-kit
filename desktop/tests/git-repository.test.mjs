// Inert public DATA and controlled promises only. No Git, user repositories,
// credentials, native admission/settlement, sockets, DOM or platform evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { GIT_ISSUE_HELP, gitDraftFieldFits, parseGitApplyReceipt, parseGitDiff, parseGitFailure,
  parseGitObservation, parseGitPlan } from '../src/gitRepositoryProtocol.ts';

const A = 'src/App.kt', B = 'docs/guide.md';
const REV = 'a'.repeat(64), NEXT = 'b'.repeat(64), HEAD = '1'.repeat(40), BRANCH = 'refs/heads/demo';
const DRAFT = { message: 'Describe the synthetic changes', authorName: 'Fixture Author', authorEmail: 'fixture@example.invalid' };
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 10; i += 1) await Promise.resolve(); };
const change = (path, index = ' ', worktree = 'M') => ({ path, index, worktree, kind: 'file', conflict: false });
const observation = (changes = [change(A), change(B, 'M', ' ')], revision = REV) => ({
  revision, head: HEAD, branch: BRANCH, unborn: false, detached: false, changes, remotes: ['origin'], restrictions: [],
});
let sequence = 0;
const plan = (action, paths, original = observation(), extra = {}) => ({
  planId: 'git-plan-' + (++sequence).toString(16).padStart(32, '0'), action, paths: clone(paths),
  expectedRevision: original.revision, head: original.head, branch: original.branch, wholeIndex: action === 'commit', ...extra,
});
const diff = (paths, staged = false, revision = REV, extra = {}) => ({ revision, paths: clone(paths), staged,
  text: 'diff --git a/src/App.kt b/src/App.kt\n--- a/src/App.kt\n+++ b/src/App.kt\n-demo before\n+demo after\n', withheld: null, ...extra });
const receipt = (selected, { nativeFinality = 'settled', state = 'succeeded', operationId = 'fixture-operation', ...extra } = {}) => {
  const intent = { action: selected.action, expectedRevision: selected.expectedRevision, expectedRef: selected.branch,
    expectedHead: selected.head, expectedIndex: '3'.repeat(64), candidateIndex: selected.action === 'commit' ? null : '4'.repeat(64),
    candidateCommit: selected.action === 'commit' ? '2'.repeat(40) : null };
  return { planId: selected.planId, nativeFinality, result: { operationId, action: selected.action, state,
    settlement: state === 'unknown' ? 'unknown' : 'settled', reason: state === 'succeeded' ? null : state === 'failed' ? 'command-failed' : state,
    observation: state === 'succeeded' ? observation([], NEXT) : null, intent: state === 'failed' ? null : intent }, ...extra };
};

function harness({ writer = true, available = true, portProject = 'project-a' } = {}) {
  const calls = [];
  const request = (kind, args) => { const pending = deferred(); calls.push({ kind, args, ...pending }); return pending.promise; };
  const mutations = Object.fromEntries(['prepareStage', 'prepareUnstage', 'prepareCommit', 'applyStage', 'applyUnstage', 'applyCommit',
    'discardPlan', 'readOriginalStatus'].map((kind) => [kind, (args) => request(kind, args)]));
  const port = { projectId: portProject, observe: () => request('observe', {}), diff: (args) => request('diff', args), ...(writer ? { mutations } : {}) };
  const controller = new GitRepositoryController('project-a', available ? port : null);
  return { controller, calls, get state() { return controller.getSnapshot(); },
    last: (kind) => calls.filter((call) => call.kind === kind).at(-1), count: (kind) => calls.filter((call) => call.kind === kind).length };
}
async function observed(h = harness(), value = observation()) {
  const pending = h.controller.refresh(); h.last('observe').resolve(value); await pending; return h;
}
function edit(h, values = DRAFT) { for (const [field, value] of Object.entries(values)) h.controller.editDraft(field, value); }
async function reviewed(h, action = 'stage', options = {}) {
  if (action === 'commit') edit(h);
  else if (!h.state.selected.length) h.controller.select(A, true);
  const original = h.state.observation;
  const paths = action === 'commit' ? original.changes.filter((row) => ![' ', '?', '!'].includes(row.index)).map((row) => row.path) : [...h.state.selected];
  const selected = plan(action, paths, original, options.plan);
  const pending = h.controller.prepare(action);
  h.last('prepare' + action[0].toUpperCase() + action.slice(1)).resolve(selected);
  await flush();
  if (h.state.busy === 'review') h.last('diff').resolve(diff(paths, action !== 'stage', original.revision, options.diff));
  await pending;
  return selected;
}

test('closed observation DATA rejects getters, extra private fields, malformed paths and contradictory flags', () => {
  const raw = observation(), parsed = parseGitObservation(raw);
  assert.ok(parsed); assert.ok(Object.isFrozen(parsed.changes)); assert.ok(Object.isFrozen(parsed.changes[0]));
  raw.changes[0].path = 'changed-after-admission'; assert.equal(parsed.changes[0].path, A);
  let reads = 0;
  const accessor = observation(); Object.defineProperty(accessor, 'revision', { enumerable: true, get() { reads += 1; return REV; } });
  assert.equal(parseGitObservation(accessor), null); assert.equal(reads, 0);
  for (const mutate of [(v) => { v.remoteUrls = ['https://invalid.example']; }, (v) => { v.unborn = true; },
    (v) => { v.detached = true; }, (v) => { v.head = null; v.branch = null; v.unborn = true; v.detached = true; },
    (v) => { v.changes[0].path = '../outside'; }, (v) => { v.changes[0].path = '/absolute'; },
    (v) => { v.changes[0].path = 'a/.git/config'; }, (v) => { v.changes[0].path = 'a\\b'; },
    (v) => { v.changes[0].index = 'MM'; }, (v) => { v.changes[0].kind = ['file']; }, (v) => { v.changes[0].conflict = true; },
    (v) => { v.changes.push(clone(v.changes[0])); }, (v) => { v.restrictions = ['run-hooks']; },
    (v) => { v.remotes = ['origin', 'origin']; }, (v) => { v.revision += '\n'; }]) {
    const value = observation(); mutate(value); assert.equal(parseGitObservation(value), null);
  }
  assert.ok(parseGitObservation({ ...observation(), head: null, unborn: true }));
  assert.ok(parseGitObservation({ ...observation(), branch: null, detached: true }));
});

test('diff and plan bounds retain withholding and whole-index commit semantics', () => {
  assert.ok(parseGitDiff(diff([A])));
  assert.ok(parseGitDiff(diff([A], false, REV, { text: null, withheld: 'untracked' })));
  for (const changes of [{ text: 'x'.repeat(256 * 1024 + 1) }, { text: 'x\x1b' }, { text: null },
    { withheld: 'sensitive-content' }, { text: null, withheld: ['untracked'] }, { paths: [A, A] }, { staged: 'false' }])
    assert.equal(parseGitDiff(diff([A], false, REV, changes)), null);
  assert.ok(parseGitPlan(plan('commit', [A, B])));
  assert.equal(parseGitPlan(plan('commit', [A], observation(), { wholeIndex: false })), null);
  assert.equal(parseGitPlan(plan('stage', [A], observation(), { wholeIndex: true })), null);
  assert.equal(parseGitPlan(plan('commit', [A], observation(), { branch: null })), null);
  assert.equal(parseGitPlan(plan('stage', Array.from({ length: 65 }, (_, i) => `src/${i}.kt`))), null);
  assert.equal(gitDraftFieldFits('message', 'é'.repeat(2049)), false);
  assert.equal(gitDraftFieldFits('message', 'line one\nline two'), true);
  assert.equal(gitDraftFieldFits('authorName', 'line one\nline two'), false);
});

test('core success and original native settlement are separately represented, never inferred', () => {
  const selected = plan('stage', [A]);
  assert.ok(parseGitApplyReceipt(receipt(selected)));
  assert.ok(parseGitApplyReceipt(receipt(selected, { nativeFinality: 'pending' })));
  assert.ok(parseGitApplyReceipt(receipt(selected, { nativeFinality: 'unknown' })));
  assert.ok(parseGitApplyReceipt({ planId: selected.planId, nativeFinality: 'pending', result: null }));
  assert.equal(parseGitApplyReceipt({ planId: selected.planId, nativeFinality: 'settled', result: null }), null);
  assert.equal(parseGitApplyReceipt({ ...receipt(selected), nativeFinality: ['settled'] }), null);
  for (const change of [{ settlement: 'unknown' }, { intent: null }, { observation: null }, { reason: 'unknown' }, { state: 'cancelled' }]) {
    const value = receipt(selected); Object.assign(value.result, change); assert.equal(parseGitApplyReceipt(value), null);
  }
  const unknown = receipt(selected, { state: 'unknown' }); unknown.result.settlement = 'settled';
  assert.equal(parseGitApplyReceipt(unknown), null);
});

test('unavailable, read-only and mismatched-project ports cannot fabricate writer availability', async () => {
  for (const options of [{ available: false }, { portProject: 'project-b' }]) {
    const h = harness(options); assert.equal(await h.controller.refresh(), false); assert.equal(h.calls.length, 0);
    assert.equal(h.controller.hasWriter(), false);
  }
  const h = await observed(harness({ writer: false })); edit(h); h.controller.select(A, true);
  assert.equal(h.controller.prepareReason('stage'), 'unavailable'); assert.equal(await h.controller.prepare('commit'), false);
  assert.equal(h.calls.length, 1); assert.equal(h.state.projectId, 'project-a');
});

test('refresh, external invalidation and project switching keep local commit drafts and never auto-read', async () => {
  const h = await observed(); edit(h); h.controller.select(A, true);
  h.controller.invalidate(); h.controller.setActive(false); h.controller.setActive(true);
  assert.deepEqual(h.state.draft, DRAFT); assert.deepEqual(h.state.selected, [A]); assert.equal(h.count('observe'), 1);
  await observed(h, observation([change(A), change('src/New.kt')], NEXT));
  assert.deepEqual(h.state.draft, DRAFT); assert.deepEqual(h.state.selected, [A]); assert.equal(h.state.stale, false);
});

test('an observation that returns after invalidation cannot revive a current preview', async () => {
  const h = harness(), pending = h.controller.refresh();
  h.controller.invalidate(); h.last('observe').resolve(observation()); await pending;
  assert.equal(h.state.observation, null); assert.equal(h.state.stale, true); assert.equal(h.state.busy, null);
  await observed(h); assert.equal(h.state.observation.revision, REV);
});

test('stage/unstage review uses exact selected paths and frozen revision, never blanket staging', async () => {
  for (const action of ['stage', 'unstage']) {
    const h = await observed(); h.controller.select(A, true);
    const selected = await reviewed(h, action);
    assert.deepEqual(h.last('prepare' + action[0].toUpperCase() + action.slice(1)).args, { paths: [A], expectedRevision: REV });
    assert.deepEqual(h.last('diff').args, { paths: [A], expectedRevision: REV, staged: action === 'unstage' });
    assert.equal(h.controller.applyReason(selected.planId), null); assert.equal(h.state.review.plan.wholeIndex, false);
    assert.equal(h.calls.some((call) => call.kind.startsWith('apply')), false);
  }
});

test('whole-index commit review includes staged changes outside selection and retains exact message/author', async () => {
  const h = await observed(harness(), observation([change(A, 'M', 'M'), change(B, 'A', ' ')]));
  h.controller.select(A, true); const selected = await reviewed(h, 'commit');
  assert.deepEqual(h.state.review.plan.paths, [A, B]); assert.equal(selected.wholeIndex, true);
  assert.deepEqual(h.last('prepareCommit').args, { ...DRAFT, expectedRevision: REV });
  assert.deepEqual(h.last('diff').args, { paths: [A, B], expectedRevision: REV, staged: true });
  h.controller.editDraft('message', 'A later local draft');
  assert.equal(h.state.review.draft.message, DRAFT.message); assert.equal(h.state.draft.message, 'A later local draft');
  assert.equal(h.controller.applyReason(selected.planId), 'review-changed');
  assert.equal(await h.controller.applyReviewed(selected.planId), false); assert.equal(h.count('applyCommit'), 0);
});

test('a commit response that omits any unrelated staged path is rejected before diff or apply', async () => {
  const h = await observed(harness(), observation([change(A, 'M'), change(B, 'A', ' ')])); edit(h);
  const pending = h.controller.prepare('commit'); h.last('prepareCommit').resolve(plan('commit', [A])); await pending;
  assert.equal(h.state.blocked, 'response-invalid'); assert.equal(h.count('diff'), 0); assert.equal(h.count('applyCommit'), 0);
});

test('external revision drift invalidates reviews permanently until explicit unused-plan discard', async () => {
  const h = await observed(), selected = await reviewed(h); edit(h);
  h.controller.invalidate(); await observed(h); // Even unchanged bytes do not undo an explicit invalidation.
  assert.equal(h.state.review.stale, true); assert.equal(await h.controller.applyReviewed(selected.planId), false);
  const closing = h.controller.discardReview(selected.planId); h.last('discardPlan').resolve({ discarded: true }); await closing;
  assert.equal(h.state.review, null); assert.deepEqual(h.state.draft, DRAFT); assert.equal(h.state.attempt, null);
  const next = await reviewed(h); assert.notEqual(next.planId, selected.planId); assert.equal(h.controller.applyReason(next.planId), null);
});

test('late prepared plans remain stale and retained across selection, draft and project changes', async () => {
  for (const changeDuring of ['selection', 'draft', 'project']) {
    const h = await observed(harness(), observation([change(A, 'M'), change(B, 'M', ' ')]));
    const action = changeDuring === 'draft' ? 'commit' : 'stage'; edit(h); h.controller.select(A, true);
    const pending = h.controller.prepare(action);
    if (changeDuring === 'selection') h.controller.select(B, true);
    else if (changeDuring === 'draft') { h.controller.editDraft('message', 'Changed'); h.controller.editDraft('message', DRAFT.message); }
    else h.controller.setActive(false);
    h.last('prepare' + action[0].toUpperCase() + action.slice(1)).resolve(plan(action, action === 'commit' ? [A, B] : [A]));
    await pending;
    assert.ok(h.state.review); assert.equal(h.state.review.stale, true); assert.equal(h.count('diff'), 0); assert.equal(h.count('discardPlan'), 0);
    assert.deepEqual(h.state.draft, DRAFT);
  }
});

test('ordinary diff read cannot escape its selected paths, staging mode or expected revision', async () => {
  for (const mismatch of [{ paths: [B] }, { staged: true }, { revision: NEXT }]) {
    const h = await observed(); h.controller.select(A, true);
    const pending = h.controller.preview(false); h.last('diff').resolve(diff([A], false, REV, mismatch)); await pending;
    assert.equal(h.state.diff, null); assert.equal(h.state.blocked, 'response-invalid');
  }
  const h = await observed(); h.controller.select(A, true);
  const pending = h.controller.preview(false); h.controller.clearSelection(); h.last('diff').resolve(diff([A])); await pending;
  assert.equal(h.state.diff, null); assert.equal(h.state.blocked, null);
});

test('native withheld untracked preview remains explicit, not fake content or secret-scan authority', async () => {
  const h = await observed(harness(), observation([change(A, '?', '?')]));
  const selected = await reviewed(h, 'stage', { diff: { text: null, withheld: 'untracked' } });
  assert.equal(h.state.review.preview.text, null); assert.equal(h.state.review.preview.withheld, 'untracked');
  assert.equal(h.controller.applyReason(selected.planId), null); // Native prepare, not this UI, checks staging policy.
});

test('synchronous listeners cannot submit after changing project or reviewed draft before handoff', async () => {
  for (const target of ['project', 'draft']) {
    const h = await observed(), selected = await reviewed(h, 'commit');
    const unsubscribe = h.controller.subscribe(() => {
      if (h.state.attempt?.phase !== 'sending') return;
      unsubscribe();
      if (target === 'project') h.controller.setActive(false); else h.controller.editDraft('message', 'Later unsent draft');
    });
    assert.equal(await h.controller.applyReviewed(selected.planId), false);
    assert.equal(h.count('applyCommit'), 0); assert.equal(h.state.attempt, null); assert.equal(h.state.review.stale, true);
  }
});

test('core success with pending native cleanup does not authorize another mutation', async () => {
  const h = await observed(), selected = await reviewed(h);
  const applying = h.controller.applyReviewed(selected.planId);
  assert.equal(h.controller.canCheckOriginalStatus(), false); // Original promise remains owned; no overlapping observer races.
  assert.equal(await h.controller.applyReviewed(selected.planId), false);
  h.last('applyStage').resolve(receipt(selected, { nativeFinality: 'pending' })); await applying;
  assert.equal(h.state.attempt.phase, 'awaiting-status'); assert.equal(h.state.stale, true); assert.equal(h.count('applyStage'), 1);
  await observed(h); assert.equal(h.controller.prepareReason('stage'), 'already-used');
  const checking = h.controller.checkOriginalStatus(); assert.deepEqual(h.last('readOriginalStatus').args, { planId: selected.planId });
  h.last('readOriginalStatus').resolve(receipt(selected)); await checking;
  assert.equal(h.state.attempt.phase, 'settled'); assert.equal(h.state.stale, true); assert.equal(h.count('applyStage'), 1);
  await observed(h); assert.equal(h.controller.prepareReason('stage'), null); // Only a NEW explicit review, never the submitted plan.
  assert.equal(await h.controller.applyReviewed(selected.planId), false);
});

test('lost apply reply retains original plan; later source observation alone cannot settle or retry', async () => {
  const h = await observed(), selected = await reviewed(h); edit(h);
  const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').reject(new Error('SYNTHETIC_PRIVATE_DIAGNOSTIC')); await applying;
  assert.equal(h.state.attempt.phase, 'awaiting-status'); assert.equal(h.state.attempt.review.plan.planId, selected.planId);
  assert.equal(h.state.review, null); assert.equal(h.state.issue, 'acknowledgement-missing');
  await observed(h, observation([change(A)], NEXT));
  assert.equal(h.state.attempt.phase, 'awaiting-status'); assert.equal(await h.controller.prepare('stage'), false);
  assert.equal(await h.controller.discardReview(selected.planId), false); assert.equal(h.count('discardPlan'), 0); assert.equal(h.count('applyStage'), 1);
  assert.deepEqual(h.state.draft, DRAFT); assert.equal(JSON.stringify(h.state).includes('SYNTHETIC_PRIVATE_DIAGNOSTIC'), false);
});

test('actual native/core unknown is absorbing even after later success-shaped original status', async () => {
  for (const final of [receipt, (selected) => receipt(selected, { state: 'unknown' })]) {
    const h = await observed(), selected = await reviewed(h);
    const applying = h.controller.applyReviewed(selected.planId);
    h.last('applyStage').resolve({ ...final(selected), nativeFinality: 'unknown' }); await applying;
    assert.equal(h.state.attempt.phase, 'unknown'); assert.equal(h.state.blocked, 'unknown');
    const checking = h.controller.checkOriginalStatus(); h.last('readOriginalStatus').resolve(receipt(selected)); await checking;
    assert.equal(h.state.attempt.phase, 'unknown'); assert.equal(await h.controller.refresh(), false);
    assert.equal(await h.controller.applyReviewed(selected.planId), false); assert.equal(h.count('applyStage'), 1);
  }
});

test('recovery-required with known settlement retains evidence and never becomes a fresh write', async () => {
  const h = await observed(), selected = await reviewed(h);
  const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').resolve(receipt(selected, { state: 'recovery-required' })); await applying;
  assert.equal(h.state.attempt.phase, 'recovery-required'); assert.equal(h.state.blocked, 'recovery-required');
  const checking = h.controller.checkOriginalStatus(); h.last('readOriginalStatus').resolve(receipt(selected)); await checking;
  assert.equal(h.state.attempt.phase, 'recovery-required'); assert.equal(h.count('applyStage'), 1);
});

test('original status reporting unknown cleanup cannot later unlock the submitted action', async () => {
  const h = await observed(), selected = await reviewed(h);
  const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').reject(new Error('synthetic lost reply')); await applying;
  const checking = h.controller.checkOriginalStatus();
  h.last('readOriginalStatus').reject({ reason: 'command-failed', nativeFinality: 'unknown' }); await checking;
  assert.equal(h.state.attempt.phase, 'unknown'); assert.equal(h.state.blocked, 'unknown');
  const later = h.controller.checkOriginalStatus(); h.last('readOriginalStatus').resolve(receipt(selected)); await later;
  assert.equal(h.state.attempt.phase, 'unknown'); assert.equal(h.count('applyStage'), 1);
});

test('wrong plan/action/intent/operation responses cannot replace the original submitted binding', async () => {
  for (const mutate of [(v) => { v.planId = 'git-plan-' + 'f'.repeat(32); }, (v) => { v.result.action = 'unstage'; v.result.intent.action = 'unstage'; },
    (v) => { v.result.intent.expectedRevision = NEXT; }, (v) => { v.result.intent.expectedRef = 'refs/heads/other'; },
    (v) => { v.result.operationId = 'replacement-operation'; }, (v) => { v.result.intent.candidateIndex = 'f'.repeat(64); }]) {
    const h = await observed(), selected = await reviewed(h), applying = h.controller.applyReviewed(selected.planId);
    h.last('applyStage').resolve(receipt(selected, { nativeFinality: 'pending' })); await applying;
    const checking = h.controller.checkOriginalStatus(), wrong = receipt(selected); mutate(wrong);
    h.last('readOriginalStatus').resolve(wrong); await checking;
    assert.equal(h.state.attempt.phase, 'unknown'); assert.equal(h.state.attempt.review.plan.planId, selected.planId);
    assert.equal(h.state.blocked, 'response-invalid'); assert.equal(h.count('applyStage'), 1);
  }
});

test('late settled apply is retained for original project but cannot refresh a switched-away view or overwrite drafts', async () => {
  const h = await observed(), selected = await reviewed(h, 'commit');
  const applying = h.controller.applyReviewed(selected.planId);
  h.controller.setActive(false); h.controller.editDraft('message', 'Newer local draft');
  h.last('applyCommit').resolve(receipt(selected)); await applying;
  assert.equal(h.state.attempt.phase, 'settled'); assert.equal(h.state.attempt.review.draft.message, DRAFT.message);
  assert.equal(h.state.draft.message, 'Newer local draft'); assert.equal(h.state.projectId, 'project-a');
  assert.equal(h.state.observation.revision, REV); assert.equal(h.state.stale, true);
});

test('settled failed result is not success and never triggers an automatic retry', async () => {
  const h = await observed(), selected = await reviewed(h);
  const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').resolve(receipt(selected, { state: 'failed' })); await applying;
  assert.equal(h.state.attempt.phase, 'settled'); assert.equal(h.state.attempt.receipt.result.state, 'failed');
  assert.equal(h.state.stale, true); assert.equal(h.count('applyStage'), 1); assert.equal(h.count('prepareStage'), 1);
  assert.equal(await h.controller.applyReviewed(selected.planId), false);
});

test('terminal core failure cannot become success or change evidence after native settlement', async () => {
  for (const changed of ['state', 'reason']) {
    const h = await observed(), selected = await reviewed(h);
    const original = receipt(selected, { nativeFinality: 'pending', state: 'failed' });
    const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').resolve(original); await applying;
    const retained = h.state.attempt.receipt;
    const later = clone(original); later.nativeFinality = 'settled';
    if (changed === 'state') later.result = receipt(selected).result;
    else later.result.reason = 'locked';
    assert.ok(parseGitApplyReceipt(later)); // Well-shaped is not original-result continuity.
    const checking = h.controller.checkOriginalStatus(); h.last('readOriginalStatus').resolve(later); await checking;
    assert.equal(h.state.attempt.receipt, retained); assert.equal(h.state.attempt.receipt.result.state, 'failed');
    assert.equal(h.state.attempt.phase, 'unknown'); assert.equal(h.state.blocked, 'response-invalid');
    assert.equal(h.state.observation.revision, REV); assert.equal(h.state.stale, true);
    assert.equal(await h.controller.prepare('stage'), false); assert.equal(h.count('applyStage'), 1);
  }
});

test('terminal core success cannot replace its original intent or post-observation', async () => {
  for (const changed of ['intent', 'observation']) {
    const h = await observed(), selected = await reviewed(h);
    const original = receipt(selected, { nativeFinality: 'pending' });
    const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').resolve(original); await applying;
    const retained = h.state.attempt.receipt, later = clone(original); later.nativeFinality = 'settled';
    if (changed === 'intent') later.result.intent.candidateIndex = 'f'.repeat(64);
    else later.result.observation.remotes = ['another-remote'];
    assert.ok(parseGitApplyReceipt(later));
    const checking = h.controller.checkOriginalStatus(); h.last('readOriginalStatus').resolve(later); await checking;
    assert.equal(h.state.attempt.receipt, retained); assert.equal(h.state.attempt.phase, 'unknown');
    assert.equal(h.state.blocked, 'response-invalid'); assert.equal(h.state.observation.revision, REV);
    assert.equal(h.count('applyStage'), 1);
  }
});

test('unchanged terminal core failure permits only separate native settlement progress', async () => {
  const h = await observed(), selected = await reviewed(h);
  const original = receipt(selected, { nativeFinality: 'pending', state: 'failed' });
  const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').resolve(original); await applying;
  const reordered = Object.fromEntries(Object.entries(clone(original.result)).reverse());
  const checking = h.controller.checkOriginalStatus();
  h.last('readOriginalStatus').resolve({ planId: selected.planId, nativeFinality: 'settled', result: reordered }); await checking;
  assert.equal(h.state.attempt.phase, 'settled'); assert.deepEqual(h.state.attempt.receipt.result, original.result);
  assert.equal(h.state.issue, 'command-failed'); assert.equal(h.state.stale, true); assert.equal(h.count('applyStage'), 1);
});

test('one in-flight request and listener exceptions cannot abandon original work', async () => {
  const h = await observed(); h.controller.select(A, true);
  const pending = h.controller.prepare('stage'); assert.equal(await h.controller.prepare('stage'), false);
  assert.equal(h.count('prepareStage'), 1);
  const selected = plan('stage', [A]); h.last('prepareStage').resolve(selected); await flush(); h.last('diff').resolve(diff([A])); await pending;
  const unsubscribe = h.controller.subscribe(() => { throw new Error('synthetic render failure'); });
  const applying = h.controller.applyReviewed(selected.planId); h.last('applyStage').resolve(receipt(selected)); await applying; unsubscribe();
  assert.equal(h.state.attempt.phase, 'settled'); assert.equal(h.state.busy, null);
});

test('unknown read/preparation/discard failures retain state, never expose errors or offer implicit retry', async () => {
  const h = harness(); let read = 0;
  const rejection = {}; Object.defineProperty(rejection, 'message', { enumerable: true, get() { read += 1; return 'SYNTHETIC_PRIVATE_DIAGNOSTIC'; } });
  assert.equal(parseGitFailure(rejection), null);
  const reading = h.controller.refresh(); h.last('observe').reject(rejection); await reading;
  assert.equal(read, 0); assert.equal(h.state.blocked, 'unknown'); assert.equal(await h.controller.refresh(), false);
  assert.equal(h.count('observe'), 1);
  for (const kind of ['prepareStage', 'discardPlan']) {
    const h = await observed(); edit(h); h.controller.select(A, true);
    let pending;
    if (kind === 'discardPlan') { const selected = await reviewed(h); pending = h.controller.discardReview(selected.planId); }
    else pending = h.controller.prepare('stage');
    h.last(kind).reject(new Error('SYNTHETIC_PRIVATE_DIAGNOSTIC')); await pending;
    assert.equal(h.state.blocked, 'unknown'); assert.deepEqual(h.state.draft, DRAFT); assert.equal(h.count(kind), 1);
    assert.equal(JSON.stringify(h.state).includes('SYNTHETIC_PRIVATE_DIAGNOSTIC'), false);
    if (kind === 'discardPlan') assert.ok(h.state.review?.stale);
  }
});

test('exact settled read refusals provide plain guidance without turning raw rejections into authority', async () => {
  const h = await observed(), pending = h.controller.refresh();
  h.last('observe').reject({ reason: 'required-hooks', nativeFinality: 'settled' }); await pending;
  assert.equal(h.state.issue, 'required-hooks'); assert.equal(h.state.blocked, null); assert.equal(h.state.stale, true);
  assert.match(GIT_ISSUE_HELP[h.state.issue], /not bypass/);
  assert.equal(parseGitFailure({ reason: 'required-hooks', nativeFinality: 'settled', retryable: true }), null);
});

test('selection stays explicit and bounded; a missing selected file is never silently substituted', async () => {
  const rows = Array.from({ length: 65 }, (_, i) => change(`src/File${i}.kt`));
  const h = await observed(harness(), observation(rows));
  for (let i = 0; i < 64; i += 1) assert.equal(h.controller.select(rows[i].path, true), true);
  assert.equal(h.controller.select(rows[64].path, true), false); assert.equal(h.state.selected.length, 64);
  await observed(h, observation([], NEXT));
  assert.equal(h.controller.selectionReason(), 'selection-changed'); assert.equal(h.state.selected.length, 64);
  h.controller.clearSelection(); assert.equal(h.controller.selectionReason(), 'no-selection');
});
