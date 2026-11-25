import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { isGitFastForwardReview, isGitFastForwardIntent, isGitFastForwardMutation, gitFastForwardIssueHelp } from '../src/gitFastForwardProtocol.ts';
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
const action = () => ({ kind: 'fast-forward', expectedRevision: revision, expectedReferenceRevision: references, targetRef: 'refs/remotes/origin/main', targetOid: target });
const observation = (branch = 'refs/heads/main', oid = head, changes = []) => ({ revision, head: oid, branch, unborn: oid === null,
  detached: branch === null, changes, remotes: [], restrictions: [] });
const file = (path = 'file.txt') => ({ path, mode: '100644', sourceOid: '1'.repeat(40), targetOid: '2'.repeat(40),
  sourceSha256: sha('old'), targetSha256: sha('new'), targetSize: 3 });
const review = () => ({ action: 'fast-forward', targetRef: 'refs/remotes/origin/main', targetOid: target, expectedRevision: revision,
  expectedReferenceRevision: references, head, branch: 'refs/heads/main', expectedIndex: index, paths: ['file.txt'], trackedCount: 1,
  contentOnly: true, basis: 'local-refs-no-fetch', files: [file()], headLog: { enabled: false, originalKind: 'absent', originalSha256: sha('absent') }, branchLog: { enabled: false, originalKind: 'absent', originalSha256: sha('absent') }, reviewDigest: 'f'.repeat(64) });
const intent = () => ({ action: 'fast-forward', expectedRevision: revision, expectedReferenceRevision: references, expectedRef: 'refs/heads/main',
  expectedHead: head, expectedIndex: index, targetRef: 'refs/remotes/origin/main', targetOid: target, candidateIndex: sha('candidate-index'),
  originalHead: sha('ref: refs/heads/main\n'), originalHeadLog: sha('absent'), originalBranchLog: sha('absent'),
  headLogEnabled: false, branchLogEnabled: false, footprint: sha('fixture-comparison-only') });
const prepared = (r = review()) => ({ reviewId: 'review-1', context: context(), action: action(), review: r });
const status = (operation = null, p = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: p, operation });
const operation = (phase = 'prepare', extra = {}) => ({ operationId: `${phase}-1`, context: context(), phase, action: action(),
  stage: 'running', outcome: null, reason: null, result: null, ...extra });
const preparedStatus = (r = review()) => status(operation('prepare', { stage: 'settled', outcome: 'ok', result: { review: r } }), prepared(r));
const startRequest = (phase = 'prepare') => ({ phase, projectId: 'project-1', expectedDocumentRevision: 1,
  action: phase === 'prepare' ? action() : null, reviewId: phase === 'apply' ? 'review-1' : null });
const started = (value, phase = 'prepare') => ({ schemaVersion: 1, admission: 'started', request: startRequest(phase), status: value, reason: null });
const result = (state = 'succeeded', phase = 'ref-returned') => ({ operationId: 'apply-1', action: 'fast-forward', state, settlement: 'settled',
  reason: state === 'succeeded' ? null : 'recovery-required', observation: state === 'succeeded' ? observation('refs/heads/main', target) : null,
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
const tracked = (updates = {}) => ({ state: 'complete', remote: 'origin', mergeRef: 'refs/heads/main', localRef: 'refs/remotes/origin/main', head: target, ahead: 0, behind: 1, ...updates });
async function fixture({ branch = 'refs/heads/main', oid = head, changes = [], tracking = null, restrictions = [] } = {}) {
  const calls = [], reads = [], submissions = [], p = port(['prepare', 'apply', 'discard', 'status', 'cancel'], calls), rp = port(['start', 'status', 'cancel'], reads);
  const session = {}; let controller = null, binding, epoch = 0;
  const reader = new GitReadController({ current: () => ({ api: rp.api, session, projectId: binding?.projectId ?? 'project-1', epoch,
    blocked: controller?.ownerReason() ?? binding?.blocked ?? null }) });
  reader.syncContext(); rp.queue('status', readStatus()); await reader.checkStatus();
  const repository = new GitRepositoryController('project-1', reader.port('project-1'));
  rp.queue('start', readStarted('observe', { observation: { ...observation(branch, oid, changes), restrictions }, referenceRevision: references, basis: 'local-refs-no-fetch',
    tracking: tracking ?? (branch === null || oid === null ? { state: branch === null ? 'detached' : 'unborn', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null } : tracked()) }));
  assert.equal(await repository.refresh(), true);
  repository.editDraft('message', 'Keep this commit draft'); repository.editBranchName('future'); repository.selectSwitchBranch('next');
  binding = { api: p.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null };
  controller = new GitLocalController({ current: () => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked }),
    onMutationSubmitted: (projectId) => { submissions.push(projectId); epoch += 1; binding = { ...binding, epoch };
      repository.invalidate(); reader.beforeContextIntent(); controller.beforeContextIntent(); } });
  controller.syncContext(); p.queue('status', status()); await controller.checkStatus();
  return { controller, reader, repository, calls, reads, submissions, queue: p.queue,
    change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h, r = review()) { h.queue('prepare', started(preparedStatus(r))); assert.equal(await h.controller.prepareFastForward(), true); assert.equal(h.controller.reviewReason(), null); }

test('fast-forward RAW binds both revisions and explicit cached ref/oid without fetch or command authority', () => {
  const v={projectId:'project-1',expectedDocumentRevision:1,action:action()};
  assert.deepEqual(decode(gitLocalRequest('prepare',v)),v);
  for(const key of ['fetch','force','name','paths','message','identity','argv','review'])
    assert.equal(gitLocalRequest('prepare',{...v,action:{...action(),[key]:null}}),null);
  for(const key of ['expectedRevision','expectedReferenceRevision','targetRef','targetOid']) {
    const a=action();delete a[key];assert.equal(gitLocalRequest('prepare',{...v,action:a}),null);
  }
  for(const targetRef of ['refs/heads/main','refs/remotes/origin/HEAD','refs/remotes/main','refs/remotes/x/a.lock','refs/remotes/x/../a'])
    assert.equal(gitLocalRequest('prepare',{...v,action:{...action(),targetRef}}),null);
  assert.equal(sameGitLocalAction(action(),{...action(),targetOid:head}),false);
  assert.equal(sameGitLocalAction(action(),{kind:'branch-switch',name:'main',expectedRevision:revision,expectedReferenceRevision:references}),false);
});
test('closed content-only review and candidate bind old branch, target and both log policies', () => {
  assert.equal(isGitFastForwardReview(review(),action()),true);assert.ok(parseGitLocalStatus(preparedStatus()));
  assert.equal(isGitFastForwardReview({...review(),files:[],paths:[]},action()),true);
  for(const change of [{targetOid:head},{basis:'remote-current'},{contentOnly:false},{branch:null},{paths:[]},{trackedCount:257},
    {files:[{...file(),content:'private'}]},{files:[{...file(),mode:'120000'}]}, {headLog:{enabled:false,originalKind:'file',originalSha256:sha('old')}}])
    assert.equal(isGitFastForwardReview({...review(),...change},action()),false);
  assert.equal(isGitFastForwardIntent(intent(),action()),true);assert.equal(gitLocalIntentMatchesReview(intent(),review()),true);
  for(const change of [{expectedHead:target},{expectedIndex:sha('changed')},{originalBranchLog:sha('changed')},{branchLogEnabled:true},{targetOid:head}])
    assert.equal(gitLocalIntentMatchesReview({...intent(),...change},review()),false);
  let reads=0;const trap=review();Object.defineProperty(trap,'targetOid',{enumerable:true,get(){reads++;return target;}});
  assert.equal(isGitFastForwardReview(trap,action()),false);assert.equal(reads,0);
});
test('only ref-returned succeeds on same symbolic branch; partial phases are recovery not no-effect', () => {
  assert.equal(isGitFastForwardMutation(result(),action(),'apply-1'),true);assert.ok(parseGitLocalStatus(applied()));
  for(const change of [{effectPhase:'index-returned'},{effectPhase:'worktree-returned'},{observation:observation('refs/heads/other',target)},
    {observation:observation()},{intent:null},{retainedPaths:['.git/mrk-git-fixture/index']}])
    assert.equal(isGitFastForwardMutation({...result(),...change},action(),'apply-1'),false);
  for(const phase of ['not-published','worktree-returned','index-returned','ref-returned']) assert.ok(parseGitLocalStatus(applied(result('recovery-required',phase))));
  const partial=result('recovery-required','index-returned');
  for(const change of [{state:'failed'},{reason:'unknown'},{retainedPaths:['.git/mrk-git-fixture/HEAD']},{retainedPaths:['/private/candidate']},
    {retainedPaths:['.git/mrk-git-fixture/../config']},{intent:null},{effectPhase:'done'}])
    assert.equal(isGitFastForwardMutation({...partial,...change},action(),'apply-1'),false);
});
test('only same current complete cached upstream enables review, without Branches or Fetch calls', async () => {
  const h=await fixture();assert.equal(h.controller.prepareFastForwardReason(),null);
  assert.deepEqual(h.reads.map((x)=>x.name),['status','start']);assert.equal(h.reads[1].body.action.kind,'observe');
  assert.equal(h.calls.some((x)=>x.name==='prepare'||x.name==='apply'),false);
  h.reader.beforeContextIntent();assert.equal(h.controller.prepareFastForwardReason(),'ff-observation-required');
  assert.equal(await h.controller.prepareFastForward(),false);
  h.change({api:null});assert.equal(h.controller.prepareFastForwardReason(),'unavailable');
});
test('diverged, equal, incomplete, dirty, detached and unsupported observations send no Prepare', async () => {
  for(const [options,reason] of [[{tracking:tracked({ahead:1})},'ff-not-descendant'],[{tracking:tracked({behind:0})},'ff-not-descendant'],
    [{tracking:tracked({state:'shallow',ahead:null,behind:null})},'ff-not-descendant'],
    [{tracking:tracked({state:'limit',ahead:null,behind:null})},'ff-not-descendant'],
    [{changes:[{path:'file.txt',index:' ',worktree:'M',kind:'file',conflict:false}]},'switch-dirty'],
    [{branch:null},'ff-target'],[{oid:null},'ff-target']]) {
    const h=await fixture(options);assert.equal(h.controller.prepareFastForwardReason(),reason);
    assert.equal(await h.controller.prepareFastForward(),false);assert.equal(h.calls.some((x)=>x.name==='prepare'),false);
  }
});
test('original pending Prepare is retained even if status reports terminal review first', async () => {
  const h=await fixture(),d=deferred();h.queue('prepare',()=>d.promise);const pending=h.controller.prepareFastForward();
  assert.equal(h.controller.getSnapshot().pending,1);h.queue('status',preparedStatus());await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(),'busy');assert.equal(h.controller.approve(true),false);
  d.resolve(started(preparedStatus()));await pending;assert.equal(h.controller.reviewReason(),null);
  assert.equal(h.calls.filter((c)=>c.name==='prepare').length,1);assert.equal(h.calls.some((c)=>c.name==='apply'),false);
});
test('explicit reviewed Apply uses original review once, preserves branch and makes old observations stale', async () => {
  const h=await fixture();await prepare(h);const draft=h.repository.getSnapshot().draft;
  assert.equal(await h.controller.apply(),false);assert.equal(h.controller.approve(true),true);
  h.queue('apply',started(applied(),'apply'));assert.equal(await h.controller.apply(),true);
  assert.deepEqual(h.calls.at(-1),{name:'apply',body:{projectId:'project-1',expectedDocumentRevision:1,reviewId:'review-1'}});
  assert.equal(h.controller.getSnapshot().original.result.observation.branch,'refs/heads/main');
  assert.equal(h.repository.getSnapshot().stale,true);assert.equal(h.repository.getSnapshot().draft,draft);
  assert.deepEqual(h.submissions,['project-1']);assert.equal(await h.controller.apply(),false);
  assert.equal(h.calls.filter((c)=>c.name==='apply').length,1);
});
test('observed-only or retired current source review remains close-only on its original port', async () => {
  const h=await fixture();h.queue('status',preparedStatus());await h.controller.checkStatus();
  assert.equal(h.controller.reviewReason(),'review-changed');assert.equal(h.controller.approve(true),false);
  h.queue('discard',status(preparedStatus().operation));await h.controller.discard();
  const other=await fixture();await prepare(other);other.reader.beforeContextIntent();
  assert.equal(other.controller.reviewReason(),'review-changed');assert.equal(other.controller.approve(true),false);
  other.change({projectId:'other-project',session:{},api:null});
  other.queue('discard',status(preparedStatus().operation));assert.equal(await other.controller.discard(),true);
  assert.deepEqual(other.calls.at(-1),{name:'discard',body:{reviewId:'review-1'}});
});
test('lost Apply ACK cannot replay, status and exact original Stop remain usable', async () => {
  const h=await fixture();await prepare(h);h.controller.approve(true);h.queue('apply',()=>Promise.reject(new Error('not logged')));
  await h.controller.apply();assert.equal(h.controller.getSnapshot().uncertain,true);assert.equal(await h.controller.apply(),false);
  assert.equal(await h.controller.prepareFastForward(),false);h.queue('status',status(operation('apply')));await h.controller.checkStatus();
  h.queue('cancel',status(operation('apply',{stage:'stopping'})));await h.controller.cancel();
  assert.deepEqual(h.calls.at(-1),{name:'cancel',body:{operationId:'apply-1'}});assert.equal(h.calls.filter((c)=>c.name==='apply').length,1);
});
test('partial publication and Unknown are absorbing despite contradictory later success', async () => {
  for(const unknown of [false,true]) {
    const h=await fixture();await prepare(h);h.controller.approve(true);
    h.queue('apply',started(unknown?status(operation('apply',{stage:'cleanup-unknown',outcome:'cleanup-unknown',reason:'unknown'})):
      applied(result('recovery-required','index-returned')),'apply'));await h.controller.apply();const original=h.controller.getSnapshot().original;
    h.queue('status',applied());await h.controller.checkStatus();assert.equal(h.controller.getSnapshot().original,original);
    assert.equal(await h.controller.prepareFastForward(),false);assert.equal(await h.controller.apply(),false);
    assert.equal(unknown?h.controller.getSnapshot().uncertain:h.controller.getSnapshot().recovery,true);
  }
});
test('same-tree fast-forward is not automatically applied or called a no-op', async () => {
  const h=await fixture();await prepare(h,{...review(),paths:[],files:[]});assert.equal(h.submissions.length,0);
  assert.equal(h.controller.getSnapshot().original.phase,'prepare');assert.equal(h.controller.approve(true),true);
  h.queue('apply',started(applied(),'apply'));await h.controller.apply();assert.equal(h.calls.filter((c)=>c.name==='apply').length,1);
});
