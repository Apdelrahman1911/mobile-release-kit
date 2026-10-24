import assert from 'node:assert/strict';
import test from 'node:test';
import { isGitUpstreamAction, isGitUpstreamReview, isGitUpstreamIntent, isGitUpstreamMutation, upstreamParents } from '../src/gitUpstreamProtocol.ts';
import { gitLocalRequest, parseGitLocalStatus, sameGitLocalAction, gitLocalIntentMatchesReview } from '../src/gitLocalProtocol.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { copyGitRepositoryApproval, parseGitRepositoryAccess, createGitRepositoryPermissionApi, GitRepositoryPermission } from '../src/service_git_repository_permission.ts';
import { gitRepositoryPermissionContext, gitRepositoryPermissionEffect } from '../src/gitRepositoryPermissionSelection.ts';

// Actual original controllers + inert returned API promises only. No process,
// native source/ACK/FS custody, Git, network, credentials or UI automation.
const revision='a'.repeat(64), references='b'.repeat(64), index='c'.repeat(64), head='d'.repeat(40), target='e'.repeat(40);
const context=()=>({projectId:'project-1',generation:1,revision:'document-1'});
const decode=raw=>JSON.parse(new TextDecoder().decode(raw));
const action=()=>({kind:'set-upstream',expectedRevision:revision,expectedReferenceRevision:references,branch:'refs/heads/main',head,remote:'origin',repository:'example/project',identity:null});
const observation=(branch='refs/heads/main',oid=head,changes=[])=>({revision,head:oid,branch,unborn:oid===null,detached:branch===null,changes,remotes:[],restrictions:[]});
const additions=()=>[{key:'remote.origin.url',value:'https://github.com/example/project.git'},
  {key:'remote.origin.fetch',value:'+refs/heads/*:refs/remotes/origin/*'},
  {key:'branch.main.remote',value:'origin'},{key:'branch.main.merge',value:'refs/heads/main'}];
const review=()=>({action:'set-upstream',remote:'origin',repository:'example/project',expectedRevision:revision,expectedReferenceRevision:references,
  branch:'refs/heads/main',head,expectedIndex:index,originalConfig:'1'.repeat(64),additions:additions(),
  missingDirectories:upstreamParents('origin','refs/heads/main'),unchanged:false,reviewDigest:'f'.repeat(64)});
const intent=()=>({action:'set-upstream',expectedRevision:revision,expectedReferenceRevision:references,expectedRef:'refs/heads/main',expectedHead:head,
  expectedIndex:index,originalConfig:'1'.repeat(64),candidateConfig:'2'.repeat(64),remote:'origin',repository:'example/project',
  missingDirectories:review().missingDirectories,workingSha256:'3'.repeat(64),configChanged:true});
const prepared=(r=review())=>({reviewId:'review-1',context:context(),action:action(),review:r});
const status=(operation=null,p=null)=>({schemaVersion:1,documentRevision:1,available:true,review:p,operation});
const operation=(phase='prepare',extra={})=>({operationId:`${phase}-1`,context:context(),phase,action:action(),stage:'running',outcome:null,reason:null,result:null,...extra});
const preparedStatus=(r=review())=>status(operation('prepare',{stage:'settled',outcome:'ok',result:{review:r}}),prepared(r));
const startRequest=(phase='prepare')=>({phase,projectId:'project-1',expectedDocumentRevision:1,action:phase==='prepare'?action():null,reviewId:phase==='apply'?'review-1':null});
const started=(value,phase='prepare')=>({schemaVersion:1,admission:'started',request:startRequest(phase),status:value,reason:null});
const result=(state='succeeded',effectPhase='config-returned')=>({operationId:'apply-1',action:'set-upstream',state,settlement:'settled',
  reason:state==='succeeded'?null:'recovery-required',observation:null,intent:intent(),effectPhase,
  retainedPaths:state==='succeeded'?[]:['.git/config'],retainedCandidate:state!=='succeeded'});
const applied=(r=result())=>status(operation('apply',{stage:'settled',outcome:'ok',result:r}));
const readStatus=(operation=null)=>({schemaVersion:1,documentRevision:1,available:true,operation});
function readStarted(kind,value){const a={kind,expectedRevision:kind==='observe'?null:revision,paths:[],staged:false};
 const reply={schemaVersion:1,admission:'started',request:{projectId:'project-1',expectedDocumentRevision:1,action:a},reason:null,
 status:readStatus({operationId:`read-${kind}`,context:context(),action:a,phase:'settled',outcome:'ok',reason:null,result:value})};
 assert.ok(parseGitReadStartResult(reply));return reply;}
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
  repository.editUpstreamDraft('repository', 'example/project'); repository.editDraft('message', 'Keep this commit draft'); repository.editBranchName('future'); repository.selectSwitchBranch('next');
  binding = { api: p.api, session, projectId: 'project-1', epoch, repository, reader, blocked: null };
  controller = new GitLocalController({ current: () => ({ ...binding, blocked: reader.ownerReason() ?? binding.blocked }),
    onMutationSubmitted: (projectId) => { submissions.push(projectId); epoch += 1; binding = { ...binding, epoch };
      repository.invalidate(); reader.beforeContextIntent(); controller.beforeContextIntent(); } });
  controller.syncContext(); p.queue('status', status()); await controller.checkStatus();
  return { controller, reader, repository, calls, reads, submissions, queue: p.queue,
    change(update) { binding = { ...binding, ...update }; controller.syncContext(); } };
}
async function prepare(h,r=review()){h.queue('prepare',started(preparedStatus(r)));assert.equal(await h.controller.prepareUpstream(),true);}

test('local upstream RAW is exact and contains no URL override, HTTP, automatic identity or tracking OID',()=>{
 const request={projectId:'project-1',expectedDocumentRevision:1,action:action()};
 assert.deepEqual(decode(gitLocalRequest('prepare',request)),request);
 for(const key of ['url','token','force','fetch','push','setUpstream','argv','paths','targetOid'])
  assert.equal(gitLocalRequest('prepare',{...request,action:{...action(),[key]:null}}),null);
 for(const change of [{identity:undefined},{identity:{name:'A',email:''}},{remote:'../origin'},{remote:'origin.url'},
  {repository:'https://github.com/example/project.git'},{repository:'example/project/'},{branch:null},{head:'0'.repeat(40)}])
  assert.equal(isGitUpstreamAction({...action(),...change}),false);
 assert.equal(sameGitLocalAction(action(),{...action(),remote:'other'}),false);
 let reads=0;const trap=action();Object.defineProperty(trap,'repository',{enumerable:true,get(){reads++;return 'example/project';}});
 assert.equal(isGitUpstreamAction(trap),false);assert.equal(reads,0);
});
test('closed review binds exact complete additions and canonical parent subset, never unrelated config',()=>{
 assert.ok(isGitUpstreamReview(review(),action()));assert.ok(parseGitLocalStatus(preparedStatus()));
 for(const patch of [{remote:'other'},{additions:[additions()[0]]},{additions:[...additions(),{key:'core.hooksPath',value:'x'}]},
  {missingDirectories:['refs/heads']},{missingDirectories:[...review().missingDirectories].reverse()},{unchanged:true},{rawConfig:'not public'}])
  assert.equal(isGitUpstreamReview({...review(),...patch},action()),false);
 const unchanged={...review(),additions:[],missingDirectories:[],unchanged:true};assert.ok(isGitUpstreamReview(unchanged,action()));
 const identity={name:'Local Name',email:'local@example.test'}, a={...action(),identity};
 assert.ok(isGitUpstreamReview({...review(),additions:[...additions(),{key:'user.name',value:identity.name},{key:'user.email',value:identity.email}]},a));
 assert.equal(isGitUpstreamReview({...review(),additions:[{key:'user.name',value:'Guessed'}]},a),false);
});
test('public candidate hides private paths/stats and known partial phases do not become success or refreshed source',()=>{
 assert.ok(isGitUpstreamIntent(intent(),action()));assert.ok(gitLocalIntentMatchesReview(intent(),review()));
 for(const patch of [{working:{}},{expectedIndex:'9'.repeat(64)},{configChanged:false},{missingDirectories:[]}])
  assert.equal(isGitUpstreamIntent({...intent(),...patch},action())&&gitLocalIntentMatchesReview({...intent(),...patch},review()),false);
 assert.ok(isGitUpstreamMutation(result(),action(),'apply-1'));assert.ok(parseGitLocalStatus(applied()));
 for(const patch of [{observation:observation()},{retainedCandidate:true},{retainedPaths:['.git/mrk-git-secret/index']},{effectPhase:'directories-returned'},
  {intent:null},{token:'private'}])assert.equal(isGitUpstreamMutation({...result(),...patch},action(),'apply-1'),false);
 for(const phase of ['not-published','directories-returned','config-returned'])assert.ok(parseGitLocalStatus(applied(result('recovery-required',phase))));
 assert.equal(isGitUpstreamMutation({...result('recovery-required'),reason:'unknown'},action(),'apply-1'),false);
});
test('existing current source and explicit complete draft are needed; local review does not connect or fetch',async()=>{
 const h=await fixture();assert.equal(h.controller.prepareUpstreamReason(),null);
 assert.deepEqual(h.reads.map(x=>x.name),['status','start']);assert.equal(h.calls.filter(x=>x.name==='prepare').length,0);
 h.repository.editUpstreamDraft('repository','');assert.equal(await h.controller.prepareUpstream(),false);
 h.repository.editUpstreamDraft('repository','example/project');h.repository.editUpstreamDraft('email','one@example.test');
 assert.equal(h.controller.prepareUpstreamReason(),'upstream-draft-required');
 h.repository.editUpstreamDraft('email','');h.change({blocked:'Original GitHub connection is active.'});
 assert.equal(await h.controller.prepareUpstream(),false);assert.equal(h.calls.filter(x=>x.name==='prepare').length,0);
});
test('original pending Prepare survives terminal Status and prevents early Apply',async()=>{
 const h=await fixture(),d=deferred();h.queue('prepare',()=>d.promise);const pending=h.controller.prepareUpstream();
 h.queue('status',preparedStatus());await h.controller.checkStatus();assert.equal(h.controller.getSnapshot().pending,1);
 assert.equal(h.controller.approve(true),false);assert.equal(await h.controller.apply(),false);
 d.resolve(started(preparedStatus()));await pending;assert.equal(h.controller.reviewReason(),null);
 assert.equal(h.calls.filter(x=>x.name==='prepare').length,1);
});
test('explicit one-use Apply keeps drafts and requires separate fresh Observe/Fetch afterward',async()=>{
 const h=await fixture();await prepare(h);const draft=h.repository.getSnapshot().upstreamDraft;
 assert.equal(await h.controller.apply(),false);assert.equal(h.controller.approve(true),true);
 h.queue('apply',started(applied(),'apply'));assert.equal(await h.controller.apply(),true);
 assert.equal(h.repository.getSnapshot().upstreamDraft,draft);assert.equal(h.repository.getSnapshot().stale,true);
 assert.equal(h.controller.getSnapshot().original.result.observation,null);assert.deepEqual(h.submissions,['project-1']);
 assert.equal(await h.controller.apply(),false);assert.equal(h.calls.filter(x=>x.name==='apply').length,1);
 assert.equal(h.reads.filter(x=>x.name==='start').length,1);
});
test('an unchanged complete review is Close-only; no consent, Apply or automatic refresh',async()=>{
 const h=await fixture(),r={...review(),additions:[],missingDirectories:[],unchanged:true};await prepare(h,r);
 assert.equal(h.controller.reviewReason(),'upstream-unchanged');assert.equal(h.controller.approve(true),false);
 assert.equal(await h.controller.apply(),false);h.queue('discard',status(preparedStatus(r).operation));
 assert.equal(await h.controller.discard(),true);assert.equal(h.calls.filter(x=>x.name==='apply').length,0);
});
test('draft ABA and changed project make old review close-only on its original port',async()=>{
 const h=await fixture();await prepare(h);h.repository.editUpstreamDraft('remote','other');h.repository.editUpstreamDraft('remote','origin');
 assert.equal(h.controller.reviewReason(),'review-changed');assert.equal(h.controller.approve(true),false);
 h.change({api:null,session:{},projectId:'different-project'});h.queue('discard',status(preparedStatus().operation));
 assert.equal(await h.controller.discard(),true);assert.equal(h.calls.at(-1).name,'discard');
});
test('reentrant context edit before native handoff sends no Prepare',async()=>{
 const h=await fixture();let changed=false;const remove=h.controller.subscribe(()=>{
  if(!changed&&h.controller.getSnapshot().pending){changed=true;h.repository.editUpstreamDraft('remote','other');}
 });
 assert.equal(await h.controller.prepareUpstream(),false);remove();assert.equal(changed,true);
 assert.equal(h.calls.filter(x=>x.name==='prepare').length,0);
});
test('lost Apply ACK and partial directory publication are retained, never repeated or cleared by later success',async()=>{
 for(const lost of [true,false]){const h=await fixture();await prepare(h);h.controller.approve(true);
  h.queue('apply',lost?()=>Promise.reject(new Error('inert lost return')):started(applied(result('recovery-required','directories-returned')),'apply'));
  await h.controller.apply();assert.equal(await h.controller.prepareUpstream(),false);assert.equal(await h.controller.apply(),false);
  if(lost){h.queue('status',status(operation('apply')));await h.controller.checkStatus();h.queue('cancel',status(operation('apply',{stage:'stopping'})));await h.controller.cancel();
   assert.deepEqual(h.calls.at(-1),{name:'cancel',body:{operationId:'apply-1'}});
  }else{h.queue('status',applied());await h.controller.checkStatus();assert.equal(h.controller.getSnapshot().recovery,true);}
  assert.equal(h.calls.filter(x=>x.name==='apply').length,1);
 }
});
test('existing LOCAL permission family carries exact upstream and never accepts Fetch/Push or guessed identity',async()=>{
 const selected={projectId:'project-1',expectedDocumentRevision:1,readOperationId:'read-observe',action:action()};
 assert.ok(copyGitRepositoryApproval(selected));assert.equal(copyGitRepositoryApproval({...selected,readOperationId:null}),null);
 for(const kind of ['fetch','push','push-new-branch'])assert.equal(copyGitRepositoryApproval({...selected,action:{...action(),kind}}),null);
 const access={permissionRevision:'1',enabled:true,remainingMs:900000,consumed:false,projectId:'1'.repeat(32),grantId:'2'.repeat(32),selection:{action:action(),selectionSha256:'3'.repeat(64)}};
 assert.ok(parseGitRepositoryAccess(access));const calls=[];
 const api=createGitRepositoryPermissionApi('native',async(command,raw)=>{calls.push([command,decode(raw)]);return access;});
 await api.allow(selected,'1');assert.equal(calls[0][0],'allow_agent_git_repository');
 assert.deepEqual(calls[0][1],{...selected,expectedPermissionRevision:'1',consentVersion:'agent-local-git-repository-once-v1'});
 assert.equal(createGitRepositoryPermissionApi('preview',()=>assert.fail()),null);
});
test('local permission uses same current read/draft witness and reentrant change withdraws unsent Allow',async()=>{
 const h=await fixture(),calls=[],api={status:async()=>null,revoke:async()=>null,allow:async()=>{calls.push('allow');return null;}};
 const current=()=>gitRepositoryPermissionContext('set-upstream',{api,session:api,projectId:'project-1',epoch:0,repository:h.repository,reader:h.reader,local:h.controller,blocked:null});
 assert.equal(current().reason,null);assert.match(gitRepositoryPermissionEffect(current().project.action),/No network/);
 const permission=new GitRepositoryPermission(()=>current());permission.chooseKind('set-upstream');permission.syncContext();permission.acknowledge(true);
 h.repository.editUpstreamDraft('remote','other');h.repository.editUpstreamDraft('remote','origin');permission.syncContext();
 assert.equal(permission.getState().acknowledged,false);await permission.allow();assert.deepEqual(calls,[]);
 h.reader.beforeContextIntent();assert.equal(current().blocked,true);assert.equal(current().project,null);
});
