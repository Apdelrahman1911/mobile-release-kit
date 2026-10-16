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
