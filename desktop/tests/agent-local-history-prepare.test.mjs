// Actual permission + ordinary History controllers and closed codecs.
// Inert ports only: no journal, Keychain, native operation or provider action.
import assert from 'node:assert/strict';
import test from 'node:test';
import {AgentLocalHistoryController} from '../src/agentLocalHistoryController.ts';
import {LocalReleaseHistoryController,localHistoryRequest} from '../src/localReleaseHistory.ts';
import {parseAgentLocalHistoryAccess,parseLocalHistoryReview,localHistoryDelegateConsent,createAgentLocalHistoryPort,localHistoryCommands} from '../src/agentLocalHistoryProtocol.ts';
import {parseLocalHistoryPreparation,validLocalHistoryPreparation,validLocalHistorySelection} from '../src/agentLocalHistoryPreparation.ts';
const A='a'.repeat(32),B='b'.repeat(32),P='1'.repeat(32),S='2'.repeat(32),Q='3'.repeat(32),G='4'.repeat(32),R='5'.repeat(32),H='a'.repeat(64),C='b'.repeat(40);
const U='12345678-1234-4234-8234-123456789abc',V='23456789-1234-4234-8234-123456789abc';
const origin=()=>({projectId:P,serviceInstance:S,requestId:Q});
const selection=(kind='verify',platform)=>({kind,...(platform?{platform}:{}),...(['enroll','verify'].includes(kind)?{}:kind.startsWith('review-stage-')||kind==='review-external-readiness'?{stageOperationId:V}:{candidateOperationId:U})});
const review=(s=selection(),revision=2)=>({...s,operationId:A,ownerGeneration:B,statusRevision:revision});
const comparison=(extra={},s=selection())=>({runtimeProjectId:'runtime-p1',request:{origin:origin(),selection:s,revision:4,phase:'prepared',settlement:'settled',reason:'none',review:review(s,1),remainingMs:200000,...extra},live:extra.phase&&extra.phase!=='prepared'?null:review(s)});
const access=(preparation=null,extra={})=>({permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,reviewId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,requestId:null,status:null,preparation,...extra});
const allowed=r=>access(null,{permissionRevision:'1',serviceInstance:S,projectId:P,grantId:G,reviewId:R,review:r,enabled:true,remainingMs:150000});
const all=()=>[selection('enroll'),selection(),...['review-inputs','review-prepared','review-execution','review-reconcile'].flatMap(k=>[selection(k),selection(k,'ios')]),selection('review-recovery'),...['review-stage-prepared','review-stage-execution'].flatMap(k=>[selection(k,'android'),selection(k,'ios')]),selection('review-external-readiness','ios')];
const clone=v=>structuredClone(v),deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};},flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
async function fixture(){
 let project='runtime-p1',epoch={},session={},now=100,peer=null,published,permission,current=access(comparison());const calls=[];
 const ordinary=new LocalReleaseHistoryController({projectId:()=>project,otherOperationReason:()=>peer,delegationReason:()=>permission?.ownerReason()??null,now:()=>now});
 let native={schemaVersion:1,statusRevision:0,availability:'available',operation:null};
 const api={mode:'native',subscribeLocalReleaseHistory:async f=>{published=f;return()=>{};},localReleaseHistoryStatus:async()=>clone(native),prepareLocalReleaseHistory:async()=>{calls.push(['gui-prepare']);throw Error('not requested');},startLocalReleaseHistory:async()=>{calls.push(['gui-start']);throw Error('not authorized');},cancelLocalReleaseHistory:async()=>{calls.push(['gui-cancel']);return clone(native);}};
 await ordinary.connect(api);ordinary.syncProject();
 const port={status:async q=>{calls.push(['check',q]);return clone(current);},allow:async(r,rev,q)=>{calls.push(['allow',r,rev,q]);return allowed(r);},revoke:async()=>{calls.push(['revoke']);return access(null,{permissionRevision:'1'});}};
 permission=new AgentLocalHistoryController({current:()=>({port,nativeSession:session,projectId:project,epoch,preview:false,reviews:ordinary.delegationReview()?[ordinary.delegationReview()]:[],blockedReason:peer}),delegate:r=>{calls.push(['delegate']);return ordinary.delegatePrepared(r);},preparationReason:r=>ordinary.cliPreparationReason(r),now:()=>now});
 return{permission,ordinary,port,calls,reply:v=>current=v,time:n=>now=n,peer:v=>peer=v,change:()=>{epoch={};permission.syncContext();},project:v=>{project=v;epoch={};ordinary.syncProject();permission.syncContext();},session:()=>{session={};permission.syncContext();},emit:()=>{native={schemaVersion:1,statusRevision:2,availability:'available',operation:{operationId:A,ownerGeneration:B,context:localHistoryRequest('runtime-p1','verify'),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null}};published(clone(native));},close:()=>{permission.dispose();ordinary.dispose();}};
}

test('History Prepare has exactly sixteen native shapes, old absence bytes and strict UUID/newline/material rejection',()=>{
 assert.equal(all().length,16);
 for(const s of all()){assert.ok(validLocalHistorySelection(s));assert.ok(parseLocalHistoryReview(review(s)));assert.ok(parseLocalHistoryPreparation(comparison({},s)));}
 for(const s of [{kind:'verify',platform:null},{kind:'enroll',candidateOperationId:U},selection('review-inputs','android'),selection('review-recovery','ios'),selection('review-external-readiness','android'),selection('review-stage-prepared'),{kind:'abandon-inputs',candidateOperationId:U},{...selection('review-inputs'),candidateOperationId:U+'\n'}])assert.equal(validLocalHistorySelection(s),false);
 for(const change of [c=>c.runtimeProjectId+='\n',c=>c.request.origin.projectId+='\n',c=>c.live.operationId+='\n',c=>c.request.nativeReady=true,c=>c.live.material={},c=>c.request.selection.root='/inert',c=>c.request.remainingMs=300001,c=>c.request.phase='complete',c=>delete c.runtimeProjectId]){const c=comparison();change(c);assert.equal(parseLocalHistoryPreparation(c),null);}
 const before={kind:'verify',operationId:A,ownerGeneration:B,statusRevision:2};assert.equal(JSON.stringify(parseLocalHistoryReview(before)),JSON.stringify(before));
 let hit=0;const bad=comparison();Object.defineProperty(bad,'live',{enumerable:true,get(){hit++;return review();}});assert.equal(parseLocalHistoryPreparation(bad),null);assert.equal(hit,0);
});
test('same three MAIN commands carry exact query and mode consent, never selected material or automatic CLI Start',async()=>{
 const calls=[],port=createAgentLocalHistoryPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return access();});
 await port.status();await port.status(origin());
 for(const s of all())await port.allow(review(s),'0',origin());
 await port.revoke();assert.deepEqual(calls[0],['agent_local_history_access',{}]);assert.deepEqual(calls[1],['agent_local_history_access',origin()]);
 assert.equal(new Set(calls.slice(2,-1).map(v=>v[1].consentVersion)).size,16);
 for(const [n,b]of calls.slice(2,-1)){assert.equal(n,'allow_agent_local_history');assert.deepEqual(b.preparationOrigin,origin());assert.deepEqual(Object.keys(b),['expectedPermissionRevision','kind','operationId','ownerGeneration','expectedStatusRevision','consentVersion','preparationOrigin']);}
 assert.equal(localHistoryDelegateConsent(review(selection('review-reconcile'))),'agent-local-history-android-reconcile-files-once-v1');
 assert.equal(localHistoryDelegateConsent(review(selection('review-recovery'))),'agent-local-history-android-recovery-files-once-v1');
 for(const q of [null,{requestId:Q},{...origin(),projectId:P+'\n'},{...origin(),source:'/no'}]){await assert.rejects(port.status(q));await assert.rejects(port.allow(review(),'0',q));}
 assert.deepEqual(localHistoryCommands(access(comparison())),[`mrk local-history-status ${P} ${S} ${Q}`,`mrk local-history-cancel ${P} ${S} ${Q}`]);
});
test('genuine explicit Check then unchecked separate Allow uses same comparison without a fake GUI Attempt or auto Start',async()=>{
 const h=await fixture();try{h.emit();assert.equal(h.ordinary.delegationReview(),null);assert.equal(h.permission.acknowledge(true),false);assert.equal(await h.permission.allow(),false);
  assert.equal(h.calls.length,0);await h.permission.status();assert.equal(h.permission.getSnapshot().acknowledged,false);assert.ok(h.permission.getSnapshot().review);assert.equal(h.permission.allowReason(),'Confirm permission for this one exact local-history review.');
  await h.ordinary.start();assert.equal(h.calls.filter(c=>c[0]==='gui-start').length,0);
  assert.equal(h.permission.acknowledge(true),true);assert.equal(await h.permission.allow(),true);
  const call=h.calls.find(c=>c[0]==='allow');assert.equal(call[2],'0');assert.deepEqual(clone(call[3]),origin());assert.equal(h.calls.filter(c=>c[0]==='delegate'||c[0]==='gui-start'||c[0]==='gui-prepare').length,0);
  assert.equal(h.permission.getSnapshot().unknown,false);assert.match(h.permission.ownerReason(),/one-use permission/);assert.equal(await h.permission.allow(),false);
 }finally{h.close();}
});
test('queued or constructed-but-unjoined preparation never grants review; later explicit exact Check can observe actual ready',async()=>{
 const h=await fixture();try{h.reply(access(comparison({phase:'queued',settlement:'pending',review:null,remainingMs:0,revision:1})));await h.permission.status();assert.equal(h.permission.getSnapshot().unknown,false);assert.equal(h.permission.acknowledge(true),false);
  h.time(30000);h.reply(access(comparison({phase:'preparing',settlement:'pending',remainingMs:0,revision:2})));await h.permission.status();assert.equal(h.permission.acknowledge(true),false);
  h.time(50000);h.reply(access(comparison({revision:5})));await h.permission.status();assert.equal(h.permission.acknowledge(true),true);assert.deepEqual(h.calls.filter(c=>c[0]==='check').slice(1).map(c=>clone(c[1])),[origin(),origin()]);
  assert.equal(h.calls.some(c=>c[0]==='allow'),false);
 }finally{h.close();}
});
test('registered runtime and stable service IDs cannot be conflated or silently switched',async()=>{
 for(const mismatch of [P,'runtime-other']){const h=await fixture();try{const c=comparison();c.runtimeProjectId=mismatch;h.reply(access(c));await h.permission.status();assert.equal(h.permission.acknowledge(true),false);assert.equal(await h.permission.allow(),false);}finally{h.close();}}
 const h=await fixture();try{await h.permission.status();assert.equal(h.permission.acknowledge(true),true);h.project('runtime-other');h.project('runtime-p1');assert.equal(await h.permission.allow(),false);assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);}finally{h.close();}
});
test('original Check start and prior native deadline bound comparison, later Checks do not renew and always consume ACK',async()=>{
 const h=await fixture();try{const d=deferred();h.port.status=()=>d.promise;const call=h.permission.status();h.time(70100);d.resolve(access(comparison({remainingMs:200000})));await call;assert.equal(h.permission.acknowledge(true),false);
  h.port.status=async()=>access(comparison({remainingMs:300000,revision:5}));await h.permission.status();assert.equal(h.permission.acknowledge(true),false);
 }finally{h.close();}
 const g=await fixture();try{g.reply(access(comparison({remainingMs:5000})));await g.permission.status();assert.equal(g.permission.acknowledge(true),true);g.time(2100);g.reply(access(comparison({remainingMs:200000,revision:5})));await g.permission.status();assert.equal(g.permission.getSnapshot().acknowledged,false);g.time(5200);assert.equal(g.permission.acknowledge(true),false);}finally{g.close();}
});
test('post-publication Allow rechecks epoch, exact review, peers, disposal and independent Revoke before invoking',async()=>{
 for(const change of [h=>h.change(),h=>h.session(),h=>h.project('other'),h=>h.peer('busy peer'),h=>h.permission.dispose(),h=>void h.permission.revoke()]){const h=await fixture();try{await h.permission.status();h.permission.acknowledge(true);let fired=false;const off=h.permission.subscribe(()=>{if(!fired&&h.permission.getSnapshot().pending==='allow'){fired=true;change(h);}});
   assert.equal(await h.permission.allow(),false);await h.permission.whenSettled();off();assert.equal(h.calls.some(c=>c[0]==='allow'),false);
  }finally{h.close();}}
});
test('exact old lookup survives coalesced replacement only through original known cancellation; wrong missing and Unknown remain fenced',async()=>{
 for(const replacement of [()=>access(),()=>{const c=comparison();c.request.origin.requestId=R;return access(c);},()=>access(comparison({phase:'unknown',settlement:'unknown',reason:'cleanup-unknown',remainingMs:0,revision:5}))]){const h=await fixture();try{await h.permission.status();h.reply(replacement());await h.permission.status();assert.equal(h.permission.getSnapshot().unknown,true);h.reply(access(comparison({phase:'cancelled',settlement:'settled',reason:'permission-revoked',remainingMs:0,revision:6})));await h.permission.status();assert.equal(h.permission.getSnapshot().unknown,true);}finally{h.close();}}
 const h=await fixture();try{await h.permission.status();h.reply(access(comparison({phase:'cancelled',settlement:'settled',reason:'permission-revoked',remainingMs:0,revision:5})));await h.permission.status();assert.equal(h.permission.getSnapshot().unknown,false);assert.equal(h.permission.ownerReason(),null);const c=comparison();c.request.origin.requestId=R;h.reply(access(c));await h.permission.status();assert.equal(h.calls.at(-1)[1],undefined);assert.equal(h.permission.getSnapshot().preparation.request.origin.requestId,R);}finally{h.close();}
});
test('lost Allow and late positive reply after Revoke keep actual original promises and never rearm or manufacture GUI finality',async()=>{
 const h=await fixture();try{await h.permission.status();h.port.allow=async()=>{throw Error('lost inert return');};h.permission.acknowledge(true);assert.equal(await h.permission.allow(),true);assert.equal(h.permission.getSnapshot().unknown,true);h.reply(access(comparison()));await h.permission.status();assert.equal(h.permission.getSnapshot().unknown,true);assert.equal(await h.permission.allow(),false);}finally{h.close();}
 const g=await fixture();try{await g.permission.status();const d=deferred();g.port.allow=()=>d.promise;g.permission.acknowledge(true);const pending=g.permission.allow();await flush();await g.permission.revoke();let returned=false;const join=g.permission.whenSettled().then(()=>returned=true);await flush();assert.equal(returned,false);d.resolve(allowed(review()));await pending;await join;assert.equal(g.permission.getSnapshot().access.enabled,false);assert.equal(g.permission.getSnapshot().acknowledged,false);assert.equal(g.calls.some(c=>c[0]==='gui-start'),false);}finally{g.close();}
});
const files=(s=selection('review-prepared'))=>({kind:'prepared',operationId:s.candidateOperationId??s.stageOperationId,candidateSha256:H,intentSha256:H,receiptSha256:null,sourceCommit:C,sourceTree:C,application:'dev.example.app',version:{name:'1.2',build:12},destination:{channel:'internal',releaseStatus:'completed',automaticRelease:null},stage:null,candidateOperationId:null,predecessorOperationId:null,predecessorReceiptSha256:null,executionReceiptSha256:null,observation:'current-prepared-files-only',priorFinality:'not-established'});
const completed=(s=selection('review-prepared'),f=files(s))=>{const r=review(s),status={origin:origin(),grantId:G,reviewId:R,revision:3,review:r,state:'complete',settlement:'settled',reason:'none',operation:{operationId:A,ownerGeneration:B,statusRevision:3},outcome:'complete',result:{enrolled:true,headSequence:5,history:[{operationId:f.operationId,phase:'prepared',recoveryRequired:true}],candidateInputs:null,reviewedFiles:f,limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary']}};return access(null,{permissionRevision:'1',serviceInstance:S,projectId:P,grantId:G,reviewId:R,review:r,consumed:true,requestId:Q,status});};
test('new current-file result is bounded lineage DATA, never Store authority or imported successful projection',()=>{
 const good=completed();assert.ok(parseAgentLocalHistoryAccess(good));
 for(const change of [a=>a.status.result.reviewedFiles.priorFinality='confirmed',a=>a.status.result.reviewedFiles.authorizationId=Q,a=>a.status.result.reviewedFiles.sourceCommit+='\n',a=>a.status.result.reviewedFiles.destination.channel='production',a=>a.status.result.history[0].phase='execute-pending',a=>a.status.result.reviewedFiles.receiptSha256=H,a=>a.status.result.headSequence=4,a=>a.status.result.reviewedFiles.application='x'.repeat(256),a=>delete a.status.result.reviewedFiles]){const a=clone(good);change(a);assert.equal(parseAgentLocalHistoryAccess(a),null);}
 const s=selection('review-stage-prepared','android'),f=files(s);Object.assign(f,{stage:'external-testing',candidateOperationId:U,predecessorOperationId:U,predecessorReceiptSha256:H,destination:{channel:'qa-beta',releaseStatus:'completed',automaticRelease:null}});const stage=completed(s,f);stage.status.result.headSequence=9;assert.ok(parseAgentLocalHistoryAccess(stage));f.predecessorOperationId=V;assert.equal(parseAgentLocalHistoryAccess(completed(s,f)),null);
 const unknown=comparison({phase:'unknown',settlement:'unknown',reason:'cleanup-unknown',remainingMs:0});assert.ok(validLocalHistoryPreparation(unknown.request));unknown.request.phase='prepared';assert.equal(validLocalHistoryPreparation(unknown.request),false);
});
