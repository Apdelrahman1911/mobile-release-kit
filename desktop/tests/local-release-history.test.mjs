// Inert bridge observations: no Keychain, native processes, filesystem or Stores.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalReleaseHistoryController, localHistoryRequest, localHistoryOwnerReason } from '../src/localReleaseHistory.ts';
import { parseLocalHistoryStatus, encodeLocalHistoryRequest, LOCAL_HISTORY_CONSENT } from '../src/localReleaseHistoryProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
const A='a'.repeat(32),B='b'.repeat(32),UUID='12345678-1234-4234-8234-123456789abc';
const copy=v=>structuredClone(v);
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const op=request=>({operationId:A,ownerGeneration:B,context:copy(request),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const terminal=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});
async function fixture(){let projectId='p1',now=100,listener,latest=status(),cancel=0,start=0,prepareGate=null,other=null;
 const controller=new LocalReleaseHistoryController({projectId:()=>projectId,otherOperationReason:()=>other,now:()=>now});
 const api={mode:'native',subscribeLocalReleaseHistory:async f=>{listener=f;return()=>{};},localReleaseHistoryStatus:async()=>latest,
 prepareLocalReleaseHistory:async request=>{if(prepareGate)await prepareGate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalReleaseHistory:async request=>{start++;assert.equal(request.consentVersion,LOCAL_HISTORY_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
 cancelLocalReleaseHistory:async(a,b)=>{assert.equal(a,A);assert.equal(b,B);cancel++;latest=status(latest.statusRevision+1,terminal(latest.operation));return copy(latest);}};
 await controller.connect(api);controller.syncProject();
 return{controller,api,counts:()=>({start,cancel}),project:id=>{projectId=id;controller.syncProject();},time:v=>now=v,busy:v=>other=v,defer:()=>{let release;prepareGate=new Promise(r=>release=r);return release;},emit:v=>{latest=v;listener(copy(v));},latest:()=>copy(latest)};
}
test('exact local request, finite history, and raw IPC reject private or contradictory output',async()=>{
 const request=localHistoryRequest('p1','enroll');assert.deepEqual(copy(request),{projectId:'p1',executionMode:'local',action:'enroll'});
 assert.equal(localHistoryRequest(null,'verify'),null);
 assert.equal(encodeLocalHistoryRequest('prepare_local_release_history',{...request,executionMode:'github'}),null);
 assert.equal(encodeLocalHistoryRequest('prepare_local_release_history',{...request,key:'private'}),null);
 let getter=0;const unsafe={};Object.defineProperty(unsafe,'operationId',{enumerable:true,get(){getter++;return A;}});assert.equal(encodeLocalHistoryRequest('cancel_local_release_history',unsafe),null);assert.equal(getter,0);
 const complete={...op(request),phase:'terminal',intentUsable:false,outcome:'complete',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:2,history:[{operationId:UUID,phase:'prepared',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary']}};
 assert.ok(parseLocalHistoryStatus(status(1,complete)));
 for(const mutate of [r=>r.history[0].recoveryRequired=false,r=>r.history.push(copy(r.history[0])),r=>r.headSequence=514,r=>r.headSequence=1,r=>r.history[0].operationId=UUID.toUpperCase(),r=>r.history[0].path='/private',r=>r.limitations.pop(),r=>r.enrolled=false]){const bad=copy(complete);mutate(bad.result);assert.equal(parseLocalHistoryStatus(status(1,bad)),null);}
 const contradictory=copy(complete);contradictory.reason='protocol-error';assert.equal(parseLocalHistoryStatus(status(1,contradictory)),null);
 const calls=[];const api=createNativeApi('native',async(command,body)=>{calls.push([command,body]);return status();},async()=>()=>{});
 await api.prepareLocalReleaseHistory(request);assert.equal(calls[0][0],'prepare_local_release_history');assert.ok(calls[0][1] instanceof Uint8Array);assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0][1])),copy(request));
 const preview=createNativeApi('preview',async()=>{assert.fail('preview cannot call native');});await assert.rejects(()=>preview.prepareLocalReleaseHistory(request));
});
test('enroll and verify are separate one-use consent; project change stops original',async()=>{
 const h=await fixture();try{h.emit(status(1,terminal({...op(localHistoryRequest('earlier-project','verify')),operationId:'c'.repeat(32)})));assert.equal(h.controller.getSnapshot().historical,true);assert.equal(h.controller.prepareReason(),null);h.controller.setAction('enroll');await h.controller.prepare();assert.equal(h.latest().operation.context.action,'enroll');h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().start,1);h.project('p2');await Promise.resolve();assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().historical,true);}finally{h.controller.dispose();}
});
test('late prepare after project change, explicit cancel, or navigation cannot create new consent',async()=>{
 for(const retire of [h=>h.project('p2'),h=>h.controller.cancel(),h=>h.controller.setVisible(false)]){
  const h=await fixture();try{const release=h.defer();const pending=h.controller.prepare();retire(h);release();await pending;await Promise.resolve();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
 }
});
test('expired consent, pending selection and another owner prevent Start',async()=>{
 for(const change of [h=>h.time(60101),h=>h.controller.setSelectionPending(true),h=>h.busy('Other original operation')]){
  const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);change(h);await h.controller.start();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);}finally{h.controller.dispose();}
 }
});
test('unknown cleanup and conflicting revisions remain blocking after refresh',async()=>{
 for(const conflict of [false,true]){
  const h=await fixture();try{await h.controller.prepare();const old=h.latest();h.emit(status(old.statusRevision+(conflict?0:1),{...old.operation,phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown',result:null}));await h.controller.checkStatus();assert.ok(localHistoryOwnerReason(h.controller.getSnapshot()));assert.equal(h.controller.getSnapshot().blocked,true);h.controller.acknowledge(true);await h.controller.start();assert.equal(h.counts().start,0);}finally{h.controller.dispose();}
 }
});
test('failed cancellation retains original and only explicit retry sends another cancellation',async()=>{
 const h=await fixture();try{await h.controller.prepare();let reject,calls=0;const original=h.api.cancelLocalReleaseHistory;
 h.api.cancelLocalReleaseHistory=(a,b)=>{assert.equal(a,A);assert.equal(b,B);calls++;return calls===1?new Promise((_,r)=>reject=r):original(a,b);};
 const pending=h.controller.cancel();await h.controller.cancel();assert.equal(calls,1);reject(new Error('inert failure'));await pending;await Promise.resolve();
 h.controller.invalidate();await h.controller.checkStatus();assert.equal(calls,1);assert.ok(localHistoryOwnerReason(h.controller.getSnapshot()));
 await h.controller.cancel();assert.equal(calls,2);assert.equal(h.controller.getSnapshot().status.operation.phase,'terminal');assert.equal(h.controller.getSnapshot().blocked,true);
 }finally{h.controller.dispose();}
});

const candidate=()=>({operationId:UUID,candidateSha256:'a'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:12},files:[{fileName:'app-release.aab',bytes:1073741824,sha256:'d'.repeat(64)},{fileName:'store-metadata.zip',bytes:536870912,sha256:'e'.repeat(64)},{fileName:'validation-report.json',bytes:65536,sha256:'f'.repeat(64)}],observation:'current-bundle-only',priorCreateFinality:'not-established'});
function inputHistory(request,phase='inputs-ready'){
 return {...op(request),operationId:'c'.repeat(32),phase:'terminal',intentUsable:false,outcome:'complete',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:3,history:[{operationId:UUID,phase,recoveryRequired:phase!=='settled-failure'}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],...(request.action==='review-inputs'||request.action==='abandon-inputs'?{candidateInputs:phase==='inputs-ready'?candidate():null}:{})}};
}
test('candidate history uses exact action grammar and current-bundle-only result, never ordinary verification authority',()=>{
 const request=localHistoryRequest('p1','review-inputs',UUID);
 assert.equal(localHistoryRequest('p1','review-inputs'),null);
 assert.equal(encodeLocalHistoryRequest('prepare_local_release_history',{projectId:'p1',executionMode:'local',action:'verify',candidateOperationId:UUID}),null);
 assert.equal(localHistoryRequest('p1','review-inputs',UUID.replace('4234','1234')),null);
 const complete=inputHistory(request);assert.ok(parseLocalHistoryStatus(status(1,complete)));
 for(const mutate of [r=>r.candidateInputs.applicationId='_bad.app',r=>r.candidateInputs.applicationId='dev._bad',r=>r.candidateInputs.priorCreateFinality='complete',r=>r.candidateInputs.operationId='99999999-1234-4234-8234-123456789abc',r=>r.candidateInputs.files.reverse(),r=>r.candidateInputs.files[0].bytes++,r=>r.candidateInputs.sourceCommit='not-a-commit',r=>r.candidateInputs.files[0].path='/tmp/private',r=>r.candidateInputs=null,r=>r.history[0].phase='prepared']){
  const bad=copy(complete);mutate(bad.result);assert.equal(parseLocalHistoryStatus(status(1,bad)),null);
 }
 const old=inputHistory(localHistoryRequest('p1','verify'));old.result.candidateInputs=candidate();assert.equal(parseLocalHistoryStatus(status(1,old)),null);
 for(const phase of ['inputs-pending','settled-failure'])assert.ok(parseLocalHistoryStatus(status(1,inputHistory(request,phase))));
 const abandon=localHistoryRequest('p1','abandon-inputs',UUID);
 assert.ok(parseLocalHistoryStatus(status(1,inputHistory(abandon,'settled-failure'))));
 assert.equal(parseLocalHistoryStatus(status(1,inputHistory(abandon,'inputs-pending'))),null);
});
test('candidate review and abandonment bind consent to the selected original and preserve ordinary history behavior',async()=>{
 for(const action of ['review-inputs','abandon-inputs']){
  const h=await fixture();try{
   h.emit(status(1,inputHistory(localHistoryRequest('p1','verify'))));
   assert.equal(h.controller.selectCandidate(action,UUID),true);await h.controller.prepare();
   assert.equal(h.latest().operation.context.candidateOperationId,UUID);
   let called=0;h.api.startLocalReleaseHistory=async request=>{called++;assert.equal(request.consentVersion,'local-android-candidate-inputs-v1');return status(3,{...h.latest().operation,phase:'running',intentUsable:false});};
   h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(called,1);
  }finally{h.controller.dispose();}
 }
});
test('candidate selection cannot follow an older project or prepared intent into another action',async()=>{
 const h=await fixture();try{
  h.emit(status(1,inputHistory(localHistoryRequest('earlier','verify'))));assert.equal(h.controller.selectCandidate('review-inputs',UUID),false);
  h.emit(status(2,inputHistory(localHistoryRequest('p1','verify'))));assert.equal(h.controller.selectCandidate('review-inputs','99999999-1234-4234-8234-123456789abc'),false);
  assert.equal(h.controller.selectCandidate('review-inputs',UUID),true);await h.controller.prepare();h.controller.acknowledge(true);
  h.controller.setSelectionPending(true);h.project('p2');h.controller.setSelectionPending(false);await h.controller.start();
  assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);assert.deepEqual(copy(h.controller.getSnapshot().request),{projectId:'p2',executionMode:'local',action:'verify'});
 }finally{h.controller.dispose();}
});

test('abandonment requires the latest history operation, unlike read-only review',async()=>{
 const h=await fixture();try{
  const earlier=inputHistory(localHistoryRequest('p1','verify'));
  const later='99999999-1234-4234-8234-123456789abc';
  earlier.result.headSequence=4;earlier.result.history.push({operationId:later,phase:'inputs-pending',recoveryRequired:true});
  h.emit(status(1,earlier));assert.equal(h.controller.selectCandidate('abandon-inputs',UUID),false);
  assert.equal(h.controller.selectCandidate('review-inputs',UUID),true);
  const result=inputHistory(localHistoryRequest('p1','abandon-inputs',UUID),'settled-failure');
  result.result.headSequence=4;result.result.history.push({operationId:later,phase:'inputs-pending',recoveryRequired:true});
  assert.equal(parseLocalHistoryStatus(status(2,result)),null);
 }finally{h.controller.dispose();}
});

const prepared=()=>({operationId:UUID,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),storePreconditionSha256:'c'.repeat(64),sourceCommit:'d'.repeat(40),sourceTree:'e'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:12},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T12:34:56Z',limitations:['non-publishing','prepare-not-execute','temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic'],observation:'current-prepared-files-only',priorPrepareFinality:'not-established'});
function preparedHistory(request){const result=inputHistory(request,'prepared');result.result.headSequence=5;if(request.action==='review-prepared')result.result.preparedIntent=prepared();return result;}
test('prepared review has exact current-files-only grammar and cannot impersonate Prepare or another operation',()=>{
 const request=localHistoryRequest('p1','review-prepared',UUID);
 assert.deepEqual(copy(request),{projectId:'p1',executionMode:'local',action:'review-prepared',candidateOperationId:UUID});
 assert.ok(encodeLocalHistoryRequest('prepare_local_release_history',request));
 assert.equal(localHistoryRequest('p1','review-prepared'),null);
 const complete=preparedHistory(request);assert.ok(parseLocalHistoryStatus(status(1,complete)));
 for(const mutate of [r=>r.headSequence=4,r=>r.history[0].phase='prepare-pending',r=>r.history[0].phase='execute-pending',r=>r.preparedIntent=null,r=>delete r.preparedIntent,r=>r.candidateInputs=null,r=>r.preparedIntent.operationId='99999999-1234-4234-8234-123456789abc',r=>r.preparedIntent.candidateSha256='bad',r=>r.preparedIntent.sourceTree='f'.repeat(64),r=>r.preparedIntent.version.build=0,r=>r.preparedIntent.version.name='bad name',r=>r.preparedIntent.destination.channel='production',r=>r.preparedIntent.destination.releaseStatus='draft',r=>r.preparedIntent.observedAt='2026-02-30T12:34:56Z',r=>r.preparedIntent.priorPrepareFinality='complete',r=>r.preparedIntent.observation='current-bundle-only',r=>r.preparedIntent.limitations.pop(),r=>r.preparedIntent.path='/private/account',r=>r.preparedIntent.applicationId='dev._bad']){
  const bad=copy(complete);mutate(bad.result);assert.equal(parseLocalHistoryStatus(status(1,bad)),null);
 }
 let getter=0;const unsafe=copy(complete);Object.defineProperty(unsafe.result.preparedIntent,'intentSha256',{enumerable:true,get(){getter++;return 'b'.repeat(64);}});assert.equal(parseLocalHistoryStatus(status(1,unsafe)),null);assert.equal(getter,0);
 for(const action of ['verify','review-inputs','abandon-inputs']){const bad=copy(complete);bad.context=localHistoryRequest('p1',action,UUID);assert.equal(parseLocalHistoryStatus(status(1,bad)),null);}
});
test('prepared rows alone select read-only review and use original candidate consent once, including earlier same-project operations',async()=>{
 const h=await fixture();try{
  for(const [index,phase] of ['inputs-ready','prepare-pending','execute-pending','settled-failure'].entries()){
   const value=preparedHistory(localHistoryRequest('p1','verify'));value.result.history[0]={operationId:UUID,phase,recoveryRequired:phase!=='settled-failure'};h.emit(status(index+1,value));assert.equal(h.controller.selectCandidate('review-prepared',UUID),false);
  }
  const ready=preparedHistory(localHistoryRequest('p1','verify'));ready.result.headSequence=6;ready.result.history.push({operationId:'99999999-1234-4234-8234-123456789abc',phase:'inputs-pending',recoveryRequired:true});h.emit(status(5,ready));
  assert.equal(h.controller.selectCandidate('abandon-inputs',UUID),false);assert.equal(h.controller.selectCandidate('review-inputs',UUID),false);assert.equal(h.controller.selectCandidate('review-prepared',UUID),true);
  await h.controller.prepare();let calls=0,finish;const returned=new Promise(resolve=>{finish=resolve;});
  h.api.startLocalReleaseHistory=async request=>{calls++;assert.equal(request.consentVersion,'local-android-candidate-inputs-v1');assert.deepEqual([request.operationId,request.ownerGeneration],[A,B]);return returned;};
  h.controller.acknowledge(true);const pending=h.controller.start();
  h.emit(status(7,{...h.latest().operation,phase:'running',intentUsable:false}));
  await h.controller.start();assert.equal(calls,1);assert.equal(h.counts().cancel,0);assert.equal(h.controller.getSnapshot().status.operation.phase,'running');assert.equal(h.controller.getSnapshot().historical,false);
  finish(status(8,{...preparedHistory(h.latest().operation.context),operationId:A}));await pending;await h.controller.start();
  assert.equal(calls,1);assert.equal(h.counts().cancel,0);assert.equal(h.controller.getSnapshot().historical,false);assert.equal(h.controller.getSnapshot().status.operation.result.preparedIntent.priorPrepareFinality,'not-established');
 }finally{h.controller.dispose();}
});
test('prepared review rejects stale project selection and retires pending consent before any Start',async()=>{
 for(const change of [h=>h.project('p2'),h=>h.controller.setSelectionPending(true),h=>h.controller.setVisible(false)]){
  const h=await fixture();try{
   h.emit(status(1,preparedHistory(localHistoryRequest('earlier','verify'))));assert.equal(h.controller.selectCandidate('review-prepared',UUID),false);
   h.emit(status(2,preparedHistory(localHistoryRequest('p1','verify'))));assert.equal(h.controller.selectCandidate('review-prepared',UUID),true);
   await h.controller.prepare();h.controller.acknowledge(true);change(h);await h.controller.start();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().historical,true);
  }finally{h.controller.dispose();}
 }
});
