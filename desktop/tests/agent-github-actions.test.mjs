// Inert DATA and deferred original promises only. No provider/IPC/native entry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { GITHUB_ACTION_KINDS, parseAgentGithubActionAccess, parseGithubActionSelection, parseGithubActionStatus, createAgentGithubActionPort, githubActionCommands } from '../src/agentGithubActionAccess.ts';
import { GitHubRepositoryCreateController } from '../src/githubRepositoryCreateController.ts';
import { GitHubPullRequestController } from '../src/githubPullRequestController.ts';
import { GitHubActionsRetryController } from '../src/githubActionsRetryController.ts';
import { repositoryCreateConfirmation, parseRepositoryCreateStatus } from '../src/githubRepositoryCreateProtocol.ts';
import { pullRequestConfirmation, parsePullRequestStatus } from '../src/githubPullRequestProtocol.ts';
import { actionsRetryConfirmation, parseActionsRetryStatus } from '../src/githubActionsRetryProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';

const copy=structuredClone,hex=(c,n=32)=>c.repeat(n),consentId=hex('b'),scope={projectBinding:hex('d',64),repository:'owner/app',accountId:'11',repositoryId:'22'};
const prefixes={'repository-create':'repository-create-','draft-pr-create':'github-pull-request-','failed-jobs-retry':'github-actions-retry-'};
const draft={base:'main',head:'feature/example',title:'Explain the change',body:'Tested locally.'};
const run={id:'31',attempt:2,name:'Release checks',workflowId:'51',workflowPath:'.github/workflows/checks.yml',status:'completed',conclusion:'failure',headSha:hex('2',40),headBranch:'testing',headRepository:'owner/app',headRepositoryId:'22',event:'push',createdAt:'2026-10-20T20:00:00Z',updatedAt:'2026-10-20T20:01:00Z'};
function fixtureData(kind){
  let target,prepared;
  if(kind==='repository-create'){
    target={projectBinding:scope.projectBinding,repository:scope.repository,accountId:scope.accountId,accountLogin:'owner',ownerKind:'user',visibility:'private',marker:hex('a')};
    prepared={target,ownerId:'11',membership:'self',repositoryObservation:'not-found-or-inaccessible',creationPermission:'not-proven',autoInit:false,confirmation:repositoryCreateConfirmation(target)};
  }else if(kind==='draft-pr-create'){
    target={scope,intent:{base:draft.base,head:draft.head,marker:hex('a'),titleSha256:hex('e',64),bodySha256:hex('f',64)}};
    prepared={target,baseSha:hex('1',40),headSha:hex('2',40),comparison:{aheadBy:1,behindBy:0,totalCommits:1,reportedFiles:8,coverage:'windowed',files:[{path:'app/Main.kt',change:'modified'}]},draft:true,creationPermission:'not-proven',confirmation:pullRequestConfirmation(target)};
  }else{
    target={scope,selection:{runId:run.id,attempt:run.attempt,headSha:run.headSha,marker:hex('a')}};
    prepared={target,accountLogin:'owner',run,retryPermission:'not-proven',confirmation:actionsRetryConfirmation(target,run)};
  }
  const idle=(revision=1)=>({schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,pending:[],observed:null,...(kind==='repository-create'?{}:{acknowledged:kind==='draft-pr-create'?null:false})});
  const review=()=>({...idle(3),operation:{id:prefixes[kind]+'1',projectId:'project-a',kind:'prepare',target,phase:'settled',reason:'none',effect:'none'},consent:{id:consentId,expiresAt:'2026-10-20T20:03:00Z',prepared}});
  const final=()=>{
    const state={...idle(5),operation:{id:prefixes[kind]+'2',projectId:'project-a',kind:kind==='failed-jobs-retry'?'retry':'create',target,phase:'settled',reason:'none',effect:kind==='failed-jobs-retry'?'accepted':'created-observed'}};
    if(kind==='repository-create')state.observed={id:'33',fullName:'owner/app',ownerId:'11',visibility:'private',url:'https://github.com/owner/app'};
    else if(kind==='draft-pr-create')state.acknowledged=state.observed={id:'31',number:'3',url:'https://github.com/owner/app/pull/3'};
    else{state.acknowledged=true;state.observed={...run,attempt:3,status:'queued',conclusion:null};}
    return state;
  };
  const parser=kind==='repository-create'?parseRepositoryCreateStatus:kind==='draft-pr-create'?parsePullRequestStatus:parseActionsRetryStatus;
  assert.ok(parser(review()));assert.ok(parser(final()));
  const {workflowId,workflowPath,headRepositoryId,...activityRun}=run;
  return {idle,review,final,parser,activity:{revision:19,observation:{target:scope,observedAt:'2026-10-20T20:01:00Z',selection:{kind:'workflow-run',runId:'31',attempt:2},data:{kind:'workflow-run',attemptChecked:true,run:activityRun,jobs:{state:'read',reason:'none',coverage:'complete',total:1,rows:[{id:'71',name:'Checks',status:'completed',conclusion:'failure'}]}}}}};
}
function deferred(){let resolve,reject;const d={ended:false};d.promise=new Promise((y,n)=>{resolve=y;reject=n;});d.resolve=v=>{d.ended=true;resolve(v);};d.reject=e=>{d.ended=true;reject(e);};return d;}
async function flush(){for(let i=0;i<24;i++)await Promise.resolve();}
const retained=[];
async function fixture(kind='repository-create',ready=true){
  const data=fixtureData(kind);let current=data.idle(),listener=null,peer=null;
  let connection={mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'owner/app'},
    status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'owner/app',state:'connected'},account:{state:'observed',value:{id:'11',login:'owner'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app',defaultBranch:'main'}}},busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false,error:null};
  const calls=[],h={deferStatus:false};
  const call=(kind,args)=>{const d=deferred();Object.assign(d,{kind,args:copy(args)});calls.push(d);return d.promise;};
  const port={mode:'native',subscribe:async f=>{listener=f;return()=>{listener=null;};},status:()=>h.deferStatus?call('status',{}):Promise.resolve(copy(current))};
  for(const k of ['prepare','create','start','pending','reconcile','cancel','discard'])port[k]=args=>call(k,args);
  const controller=kind==='repository-create'?new GitHubRepositoryCreateController(()=>connection,()=>peer):kind==='draft-pr-create'?new GitHubPullRequestController(()=>connection,()=>peer):new GitHubActionsRetryController(()=>connection,()=>data.activity,()=>peer);
  Object.assign(h,{kind,data,port,controller,calls,connection:()=>connection,changeConnection(v){connection=v;controller.syncContext();},emit(v){current=copy(v);listener?.(copy(v));},respond(k,v){current=copy(v);calls.filter(x=>x.kind===k).at(-1).resolve(copy(v));},retain(v){current=copy(v);},setPeer(v){peer=v;},move(){connection={...connection,context:{...connection.context,projectGeneration:2}};controller.syncContext();}});
  retained.push(h);controller.connect(port);await flush();
  if(kind==='draft-pr-create')for(const [k,v]of Object.entries(draft))controller.setDraft(k,v);
  if(ready){controller.prepare();h.respond('prepare',data.review());await flush();assert.ok(controller.agentSelection());}
  return h;
}
function requestStatus(h,patch={}){
  return {origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review:{kind:h.kind,sessionId:'session-a',consentId,expectedRevision:3,preparedSha256:hex('c',64)},revision:7,state:'complete',settlement:'settled',operationId:prefixes[h.kind]+'2',reason:'none',effect:h.kind==='failed-jobs-retry'?'accepted':'created-observed',neverAdmitted:false,doNotReplay:true,...patch};
}
function access(h,status=null,patch={}){
  return {permissionRevision:'1',serviceInstance:hex('2'),projectId:hex('1'),grantId:hex('3'),review:requestStatus(h).review,enabled:status===null,remainingMs:status===null?100000:0,consumed:status!==null,pending:status!==null&&status.settlement!=='settled',unknown:status?.state==='unknown',status,...patch};
}
async function permission(h){
  const calls=[],native={};for(const name of ['access','allow','request','revoke'])native[name]=(arg,revision)=>{const d=deferred();Object.assign(d,{kind:'permission-'+name,args:copy(arg),revision});calls.push(d);h.calls.push(d);return d.promise;};
  let peer=null,epoch={},c;
  c=new AgentGithubActionAccessController({current:()=>({port:native,nativeSession:h,projectId:'project-a',epoch,preview:false,
    blockedReason:peer??(c?.peerSelection()&&h.controller.agentSelected(c.peerSelection())?null:h.controller.ownerReason()),reviews:[h.controller.agentSelection()].filter(Boolean)}),
    syncOriginal:()=>h.controller.syncContext(),delegate:r=>h.controller.delegatePrepared(r)});
  if(h.kind!=='repository-create')c.choose(h.kind);c.syncContext();
  const p={controller:c,calls,last:k=>calls.filter(x=>x.kind==='permission-'+k).at(-1),count:k=>calls.filter(x=>x.kind==='permission-'+k).length,peer(v){peer=v;c.syncContext();},move(){epoch={};c.syncContext();}};
  h.permission=p;const check=c.check();p.last('access').resolve({permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,status:null});await check;return p;
}
test.afterEach(async()=>{for(const h of retained.splice(0)){for(const call of h.calls)if(!call.ended)call.reject({code:'fixture-ended'});await flush();h.permission?.controller.dispose();h.controller.dispose();for(const call of h.calls)if(!call.ended)call.reject({code:'fixture-ended'});await flush();}});

test('closed codec keeps kind-specific effects, exact IDs/nulls and bounded no-replay output',async()=>{
  for(const kind of ['repository-create','draft-pr-create','failed-jobs-retry']){const h=await fixture(kind);assert.ok(parseAgentGithubActionAccess(access(h)));assert.ok(parseGithubActionStatus(requestStatus(h)));
    for(const change of [s=>delete s.operationId,s=>s.doNotReplay=false,s=>s.origin.token='INERT',s=>s.review.kind='workflow-dispatch',s=>s.operationId='repository-create-0',s=>s.neverAdmitted=true]){const s=requestStatus(h);change(s);assert.equal(parseGithubActionStatus(s),null);}
    const s=requestStatus(h,{effect:kind==='failed-jobs-retry'?'created-observed':'accepted'});assert.equal(parseGithubActionStatus(s),null);
  }
  let gets=0;const raw={kind:'repository-create',sessionId:'s',consentId,expectedRevision:1};Object.defineProperty(raw,'kind',{enumerable:true,get(){gets++;return 'repository-create';}});
  assert.equal(parseGithubActionSelection(raw),null);assert.equal(gets,0);
});
test('actual composed bridge has four raw metadata-only methods and no preview capability',async()=>{
  const calls=[],api=createNativeApi('native',async(name,body)=>{calls.push([name,JSON.parse(new TextDecoder().decode(body))]);return null;},async()=>()=>{});
  const s={kind:'repository-create',sessionId:'session-a',consentId,expectedRevision:3},q={projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')};
  await api.agentGithubAction.access();await api.agentGithubAction.allow(s,'0');await api.agentGithubAction.request(q);await api.agentGithubAction.revoke();
  assert.deepEqual(calls.map(c=>c[0]),['agent_github_action_access','allow_agent_github_action','agent_github_action_request_status','revoke_agent_github_action']);
  assert.equal(calls[1][1].consentVersion,'agent-repository-create-once-v1');assert.equal(calls[1][1].expectedPermissionRevision,'0');
  assert.throws(()=>api.agentGithubAction.allow({...s,url:'https://example.invalid'},'0'));
  assert.equal(createNativeApi('preview',()=>assert.fail(),null).agentGithubAction,null);
  assert.equal(calls.length,4);
});
for(const kind of ['repository-create','draft-pr-create','failed-jobs-retry']){
  test(`${kind}: genuine returned Prepare is required; event-before-return cannot delegate`,async()=>{
    const h=await fixture(kind,false);h.controller.prepare();h.emit(h.data.review());assert.equal(h.controller.agentSelection(),null);
    assert.equal(h.controller.delegatePrepared({kind,sessionId:'session-a',consentId,expectedRevision:3}),null);
    h.respond('prepare',h.data.review());await flush();assert.ok(h.controller.agentSelection());
  });
  test(`${kind}: Allow calls once after exact own-review exemption; ordinary GUI mutation remains unavailable`,async()=>{
    const h=await fixture(kind),p=await permission(h);assert.equal(p.controller.consentReason(),null);assert.equal(p.controller.acknowledge(true),true);
    const promise=p.controller.allow();assert.equal(p.count('allow'),1);assert.equal(h.controller.agentSelection(),null);
    h.controller.setConfirmed(true);if(kind==='failed-jobs-retry')h.controller.retry();else h.controller.create();
    assert.equal(h.calls.filter(x=>['create','start'].includes(x.kind)).length,0);assert.ok(h.controller.canDiscard());
    assert.equal(await p.controller.allow(),false);p.last('allow').resolve(access(h));assert.equal(await promise,true);assert.equal(p.controller.getSnapshot().unknown,false);
    assert.equal(githubActionCommands(p.controller.getSnapshot().access,null)[0],`mrk github-submit ${hex('1')} ${hex('2')} ${hex('3')} --reviewed`);
  });
}
test('conflicting peer veto performs zero Allow, without creating permission or dropping the review',async()=>{
  const h=await fixture(),p=await permission(h);p.peer('Other original native work is still pending');assert.ok(p.controller.consentReason());assert.equal(p.controller.acknowledge(true),false);
  assert.equal(await p.controller.allow(),false);assert.equal(p.count('allow'),0);assert.ok(h.controller.agentSelection());
});
test('synchronous delegation listener changing peer closes exact unsubmitted original; never rewinds it',async()=>{
  const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);let changed=false;
  const stop=h.controller.subscribe(()=>{if(!changed&&h.controller.agentSelection()===null){changed=true;p.peer('A conflicting peer appeared');}});
  assert.equal(await p.controller.allow(),false);stop();assert.equal(p.count('allow'),0);assert.equal(h.calls.filter(x=>x.kind==='discard').length,1);
  h.respond('discard',{...h.data.review(),revision:4,consent:null});await flush();assert.equal(h.controller.agentSelection(),null);assert.equal(h.controller.ownerReason(),null);
});
test('late successful Allow cannot resurrect a pre-call Revoke; no second origin replaces outstanding callers',async()=>{
  const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();const revoke=p.controller.revoke();
  assert.equal(p.count('allow'),1);assert.equal(p.count('revoke'),1);assert.equal(await p.controller.allow(),false);
  p.last('revoke').resolve(access(h,null,{enabled:false,remainingMs:0}));await revoke;
  p.last('allow').resolve(access(h));await allow;assert.equal(p.controller.getSnapshot().access.enabled,false);assert.equal(p.controller.getSnapshot().withdrawn,true);
  assert.ok(h.controller.ownerReason());
});
test('lost Allow remains absorbing through known Revoke/readback and never exposes ordinary Create',async()=>{
  const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').reject(new Error('INERT private detail'));await allow;
  assert.equal(p.controller.getSnapshot().unknown,true);assert.equal(await p.controller.allow(),false);assert.equal(h.controller.agentSelection(),null);
  const revoke=p.controller.revoke();p.last('revoke').resolve(access(h,null,{enabled:false,remainingMs:0}));await revoke;
  assert.equal(p.controller.getSnapshot().unknown,true);assert.ok(h.controller.ownerReason());assert.equal(p.count('allow'),1);
});
test('service final before native Check return never releases original; reconnect uses exact retained Query not latest lease',async()=>{
  const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').resolve(access(h));await allow;
  const progress=requestStatus(h,{revision:5,state:'running',settlement:'pending',effect:'potentially-applied'});
  const first=p.controller.check();p.last('access').resolve(access(h,progress));await flush();p.last('request').resolve(progress);await first;
  h.emit(h.data.final());const final=requestStatus(h);h.deferStatus=true;
  const check=p.controller.check();assert.equal(p.count('access'),2);assert.deepEqual(p.last('request').args,final.origin);p.last('request').resolve(final);await check;
  assert.ok(h.controller.ownerReason());assert.equal(h.calls.filter(x=>x.kind==='status'&&!x.ended).length,1);
  const revoke=p.controller.revoke();p.last('revoke').resolve(access(h,final));await revoke;
  h.respond('status',h.data.final());await flush();assert.equal(h.controller.ownerReason(),null);assert.equal(p.controller.ownerReason(),null);
  assert.equal(p.count('allow'),1);assert.equal(p.count('access'),2);
});
test('pre-arm NeverAdmitted requires original Close plus joined native Check; no fabricated mutation retirement',async()=>{
  const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').resolve(access(h));await allow;
  const final=requestStatus(h,{state:'refused',reason:'native-refused',operationId:null,effect:'not-sent',neverAdmitted:true});
  const check=p.controller.check();p.last('access').resolve(access(h,final));await flush();p.last('request').resolve(final);await check;await flush();assert.ok(h.controller.ownerReason());
  h.controller.discardReview();h.respond('discard',{...h.data.review(),revision:4,consent:null});await flush();h.controller.checkStatus();await flush();
  assert.equal(h.controller.ownerReason(),null);assert.equal(h.calls.filter(x=>x.kind==='create').length,0);
});
test('service history Unknown and foreign final cannot clear retained original even with a native final event',async()=>{
  for(const malformed of [false,true]){const h=await fixture(),p=await permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').resolve(access(h));await allow;
    h.emit(h.data.final());const bad=malformed?requestStatus(h,{grantId:hex('9')}):requestStatus(h,{state:'unknown',settlement:'unknown',reason:'history-unavailable'});
    const check=p.controller.check();p.last('access').resolve(access(h,bad));await check;
    assert.equal(p.controller.getSnapshot().unknown,true);assert.ok(h.controller.ownerReason());assert.equal(await p.controller.allow(),false);
  }
});

// Reuse the same inert original-controller fixture; no second test owner.
export { fixture, fixtureData, flush, deferred, consentId, draft, run, hex };
