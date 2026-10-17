// Inert native-port tests; no Store, filesystem, credential or process operations.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStoreReconcileController, localStoreReconcileRequest, localStoreReconcileOwnerReason } from '../src/localStoreReconcile.ts';
import { encodeLocalStoreReconcileRequest, parseLocalStoreReconcileStatus, STORE_RECONCILE_CONSENT, STORE_RECOVERY_CONSENT, IOS_STORE_RECONCILE_CONSENT, reconcileRequestContext } from '../src/localStoreReconcileProtocol.ts';
import { encodeLocalStorePrepareRequest, parseLocalStorePrepareStatus } from '../src/localStorePrepareProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),U='12345678-1234-4234-8234-123456789abc',V='23456789-1234-4234-8234-123456789abc';
const copy=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},selection:{module:'app',variant:'release',applicationId:'dev.example.app'},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false});
const assets=()=>({mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:C,revision:4,availability:'assigned'}]}});
const prepared=()=>({operationId:U,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),storePreconditionSha256:'c'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:00:00Z',limitations:['non-publishing','prepare-not-execute','temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic'],observation:'current-prepared-files-only',priorPrepareFinality:'not-established'});
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const history=()=>({mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:status(1,{operationId:C,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-reconcile',candidateOperationId:U},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:6,history:[{operationId:U,phase:'execute-pending',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],preparedIntent:prepared()}})});
const op=request=>({operationId:A,ownerGeneration:B,context:reconcileRequestContext(copy(request)),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const cancelled=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});
const complete=o=>({...o,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:o.context.settlement?'local-android-recovery-settlement':'local-android-store-reconcile',headSequence:o.context.settlement?7:6,reconciliationReceipt:{operationId:U,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),receiptSha256:'d'.repeat(64),authorizationId:V,sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:01:00Z',result:'reconciled',observation:'current-internal-target-only',priorExecutionFinality:'not-established',limitations:['non-publishing','not-retry-permission','old-evidence-preserved','saved-inputs-not-atomic']}}});
async function fixture(ios=false){let p=project(),a=ios?iosAssets():assets(),h=ios?iosHistory():history(),now=100,listener,latest=status(),starts=0,cancels=0,prepares=0,gate=null,other=null;
 const controller=new LocalStoreReconcileController({project:()=>p,assets:()=>a,history:()=>h,otherOperationReason:()=>other,now:()=>now});
 const api={mode:'native',subscribeLocalStoreReconcile:async f=>{listener=f;return()=>{};},localStoreReconcileStatus:async()=>latest,
 prepareLocalStoreReconcile:async request=>{prepares++;if(gate)await gate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStoreReconcile:async request=>{starts++;assert.equal(request.consentVersion,latest.operation.context.platform==='ios'?IOS_STORE_RECONCILE_CONSENT:latest.operation.context.settlement?STORE_RECOVERY_CONSENT:STORE_RECONCILE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
 cancelLocalStoreReconcile:async(x,y)=>{assert.equal(x,A);assert.equal(y,B);cancels++;latest=status(latest.statusRevision+1,cancelled(latest.operation));return copy(latest);}};
 await controller.connect(api);controller.syncProject();
 return{controller,api,counts:()=>({starts,cancels,prepares}),change:fn=>{fn(p,a,h);controller.syncProject();},time:v=>now=v,busy:v=>other=v,defer:()=>{let release;gate=new Promise(r=>release=r);return release;},emit:v=>{latest=v;listener(copy(v));},latest:()=>copy(latest)};
}

import { LocalReleaseHistoryController } from '../src/localReleaseHistory.ts';
import { parseLocalHistoryStatus } from '../src/localReleaseHistoryProtocol.ts';
test('no automatic Start; queued double Start retains the same running original and completion',async()=>{
 const h=await fixture();try{assert.equal(h.controller.prepareReason(),null);assert.deepEqual(h.counts(),{starts:0,cancels:0,prepares:0});await h.controller.prepare();assert.equal(h.counts().starts,0);h.controller.acknowledge(true);
  let release,originalStarts=0;h.api.startLocalStoreReconcile=request=>{originalStarts++;assert.equal(request.consentVersion,STORE_RECONCILE_CONSENT);h.emit(status(2,{...h.latest().operation,phase:'running',intentUsable:false}));return new Promise(r=>release=r);};
  const first=h.controller.start();const running=h.latest();let duplicate=0;const original=h.api.startLocalStoreReconcile;h.api.startLocalStoreReconcile=(...a)=>{duplicate++;return original(...a);};
  await h.controller.start();assert.equal(duplicate,0);assert.equal(h.counts().cancels,0);assert.equal(h.controller.getSnapshot().historical,false);
  release(status(3,complete(running.operation)));await first;await h.controller.start();assert.equal(duplicate,0);assert.equal(originalStarts,1);assert.equal(h.counts().cancels,0);assert.ok(h.controller.getSnapshot().status.operation.result);assert.equal(localStoreReconcileOwnerReason(h.controller.getSnapshot()),null);
 }finally{h.controller.dispose();}
});
test('late Prepare reply after picker or navigation is cancelled once, never started',async()=>{
 for(const retire of [h=>h.controller.setSelectionPending(true),h=>h.controller.setVisible(false),h=>h.controller.cancel()]){
  const h=await fixture();try{const release=h.defer(),first=h.controller.prepare();retire(h);await h.controller.prepare();release();await first;await Promise.resolve();assert.deepEqual(h.counts(),{starts:0,cancels:1,prepares:1});assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
 }
});
test('unknown cleanup and conflicting status revision stay blocked after refresh and repeated Start',async()=>{
 for(const conflict of [false,true]){const h=await fixture();try{await h.controller.prepare();const old=h.latest();h.emit(status(old.statusRevision+(conflict?0:1),{...old.operation,phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown'}));await h.controller.checkStatus();assert.ok(localStoreReconcileOwnerReason(h.controller.getSnapshot()));h.controller.acknowledge(true);await h.controller.start();assert.equal(h.counts().starts,0);}finally{h.controller.dispose();}}
});
test('failed Cancel is not automatically retried and no private rejection leaks to the UI',async()=>{
 const h=await fixture();try{await h.controller.prepare();let reject,n=0;const original=h.api.cancelLocalStoreReconcile;h.api.cancelLocalStoreReconcile=(...args)=>{n++;return n===1?new Promise((_,r)=>reject=r):original(...args);};
  await h.controller.cancel();await h.controller.cancel();assert.equal(n,1);reject(new Error('SECRET_SENTINEL'));await new Promise(r=>setImmediate(r));h.controller.invalidate();await h.controller.checkStatus();assert.equal(n,1);assert.ok(localStoreReconcileOwnerReason(h.controller.getSnapshot()));assert.doesNotMatch(h.controller.getSnapshot().error,/SECRET_SENTINEL/);await h.controller.cancel();assert.equal(n,2);assert.equal(h.controller.getSnapshot().blocked,true);
 }finally{h.controller.dispose();}
});
test('a completed receipt cannot substitute a different reviewed application or source',async()=>{
 const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();const bad=complete(h.latest().operation);bad.result.reconciliationReceipt.sourceTree='f'.repeat(40);h.emit(status(h.latest().statusRevision+1,bad));assert.equal(h.controller.getSnapshot().blocked,true);assert.equal(h.controller.getSnapshot().status.operation.result,null);}finally{h.controller.dispose();}
});

test('reconnection cannot discard a retained original; disposal consumes late identity by original Cancel',async()=>{
 const first=await fixture();try{await first.controller.prepare();first.controller.beginConnection();let subscribed=0;await first.controller.connect({...first.api,subscribeLocalStoreReconcile:async()=>{subscribed++;return()=>{};}});assert.equal(subscribed,0);assert.equal(first.controller.getSnapshot().blocked,true);assert.equal(first.counts().cancels,1);}finally{first.controller.dispose();}
 const late=await fixture();const release=late.defer(),pending=late.controller.prepare();late.controller.dispose();release();await pending;await Promise.resolve();assert.equal(late.counts().cancels,1);assert.equal(late.counts().starts,0);assert.equal(late.controller.getSnapshot().consentUntil,null);
});

test('restart readback derives context only from current latest reviewed execution, without Android tooling',()=>{
 const request=localStoreReconcileRequest(project(),assets(),history());assert.ok(request);assert.equal(Object.hasOwn(request,'toolchainSelection'),false);
 for(const phase of ['execute-pending','settled-success','settled-failure','reconciliation-required']){const h=history();h.status.operation.result.history[0]={operationId:U,phase,recoveryRequired:!phase.startsWith('settled-')};assert.ok(localStoreReconcileRequest(project(),assets(),h));}
 for(const mutate of [(p,a,h)=>h.historical=true,(p,a,h)=>h.status.operation.context.action='review-prepared',(p,a,h)=>h.status.operation.result.history[0].phase='prepared',(p,a,h)=>h.status.operation.result.history.push({operationId:V,phase:'execute-pending',recoveryRequired:true}),(p,a,h)=>h.status.operation.result.headSequence=5,(p,a,h)=>h.status.operation.result.preparedIntent.priorPrepareFinality='passed',p=>p.savedVersion.build++,(p,a)=>a.status.assignments[0].recordRevision++,(p,a)=>a.status.context.executionMode='github',p=>p.dirtyDraft=true,p=>p.selection.applicationId='other.app']){const p=project(),a=assets(),h=history();mutate(p,a,h);assert.equal(localStoreReconcileRequest(p,a,h),null);}
});
test('fresh readback IPC and receipt reject Execute grants, tools, retry claims and stale bindings',async()=>{
 const request=localStoreReconcileRequest(project(),assets(),history());assert.ok(encodeLocalStoreReconcileRequest('prepare_local_store_reconcile',request));
 for(const extra of [{toolchainSelection:{}},{authorizationId:V},{recover:true},{executionMode:'github'}])assert.equal(encodeLocalStoreReconcileRequest('prepare_local_store_reconcile',{...request,...extra}),null);
 for(const consentVersion of ['local-android-store-execute-v1','local-android-store-prepare-v1','local-android-candidate-inputs-v1'])assert.equal(encodeLocalStoreReconcileRequest('start_local_store_reconcile',{operationId:A,ownerGeneration:B,consentVersion}),null);
 const good=complete(op(request));assert.ok(parseLocalStoreReconcileStatus(status(1,good)));
 for(const mutate of [o=>o.result.reconciliationReceipt.result='accepted',o=>o.result.reconciliationReceipt.observation='current-execution-files-only',o=>o.result.reconciliationReceipt.priorExecutionFinality='passed',o=>o.result.reconciliationReceipt.limitations=['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic'],o=>o.result.reconciliationReceipt.authorizationId=A,o=>o.result.reconciliationReceipt.candidateSha256='e'.repeat(64),o=>o.result.reconciliationReceipt.intentSha256='e'.repeat(64),o=>o.result.reconciliationReceipt.version.build++,o=>o.result.reconciliationReceipt.observedAt='2026-02-30T20:01:00Z',o=>o.result.reconciliationReceipt.retryAllowed=true,o=>o.result.headSequence=5,o=>o.result.headSequence=514,o=>o.context.operation='local-store-execute']){const bad=copy(good);mutate(bad);assert.equal(parseLocalStoreReconcileStatus(status(1,bad)),null);}
 let event;const calls=[];const api=createNativeApi('native',async(command,body)=>{calls.push([command,body]);return status();},async(name)=>{event=name;return()=>{};});await api.prepareLocalStoreReconcile(request);await api.subscribeLocalStoreReconcile(()=>{});assert.equal(calls[0][0],'prepare_local_store_reconcile');assert.equal(event,'local-store-reconcile-state-changed');
 for(const method of ['prepareLocalStoreReconcile','startLocalStoreReconcile','localStoreReconcileStatus','cancelLocalStoreReconcile','subscribeLocalStoreReconcile'])await assert.rejects(()=>previewApi[method](request),e=>e.code==='local_store_reconcile_unavailable');
});
test('review-reconcile History is current-last only and cannot weaken ordinary prepared review',async()=>{
 const current=history().status;assert.ok(parseLocalHistoryStatus(current));
 const changed=copy(current);changed.operation.context.action='review-prepared';assert.equal(parseLocalHistoryStatus(changed),null);
 const ctl=new LocalReleaseHistoryController({projectId:()=> 'p1',otherOperationReason:()=>null});try{await ctl.connect({mode:'native',subscribeLocalReleaseHistory:async()=>()=>{},localReleaseHistoryStatus:async()=>current});ctl.syncProject();await ctl.checkStatus();
 // Initial displayed operation is older than the controller request: select Verify first.
 const verified=copy(current);verified.operation.context={projectId:'p1',executionMode:'local',action:'verify'};delete verified.operation.result.preparedIntent;
 await ctl.connect({mode:'native',subscribeLocalReleaseHistory:async()=>()=>{},localReleaseHistoryStatus:async()=>verified});ctl.syncProject();assert.equal(ctl.selectCandidate('review-reconcile',U),true);assert.equal(ctl.getSnapshot().request.action,'review-reconcile');
 }finally{ctl.dispose();}
});
test('changed head, saved version or Google assignment retires readback consent before network start',async()=>{
 for(const change of [h=>h.change(p=>p.savedVersion.sha256='e'.repeat(64)),h=>h.change((_p,a)=>{a.status.context.revision++;a.status.assignments[0].contextRevision++;}),h=>h.change((_p,_a,s)=>s.status.operation.result.headSequence++),h=>h.time(60101),h=>h.busy('Other original owner')]){const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);change(h);await h.controller.start();assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);}finally{h.controller.dispose();}}
});


test('recovery checkpoint uses a distinct closed context, scope and current-last eligibility',()=>{
 const request=localStoreReconcileRequest(project(),assets(),history(),true);assert.equal(request.settlement,'record-current-target');
 assert.ok(encodeLocalStoreReconcileRequest('prepare_local_store_reconcile',request));
 const value=complete(op(request));assert.ok(parseLocalStoreReconcileStatus(status(1,value)));
 const refused={...op(request),phase:'terminal',intentUsable:false,outcome:'refused',reason:'recovery-settle-unavailable'};assert.ok(parseLocalStoreReconcileStatus(status(1,refused)));
 assert.equal(parseLocalStoreReconcileStatus(status(1,{...refused,reason:'reconcile-unavailable'})),null);
 const ordinary=localStoreReconcileRequest(project(),assets(),history());assert.equal(parseLocalStoreReconcileStatus(status(1,{...refused,context:reconcileRequestContext(ordinary)})),null);
 assert.equal(parseLocalStoreReconcileStatus(status(1,{...refused,reason:'unexpected-private-message'})),null);
 for(const change of [v=>delete v.context.settlement,v=>v.context.operation='local-store-reconcile',v=>v.context.settlement=null,v=>v.result.scope='local-android-store-reconcile',v=>v.result.headSequence=6,v=>v.result.reconciliationReceipt.priorExecutionFinality='complete']){
  const bad=copy(value);change(bad);assert.equal(parseLocalStoreReconcileStatus(status(1,bad)),null);
 }
 for(const settlement of [null,true,'repair-old-execution'])assert.equal(encodeLocalStoreReconcileRequest('prepare_local_store_reconcile',{...request,settlement}),null);
 for(const phase of ['execute-pending','settled-failure','reconciliation-required']){const h=history();h.status.operation.result.history[0]={operationId:U,phase,recoveryRequired:phase!=='settled-failure'};assert.ok(localStoreReconcileRequest(project(),assets(),h,true));}
 const h=history();h.status.operation.result.history[0]={operationId:U,phase:'settled-success',recoveryRequired:false};assert.equal(localStoreReconcileRequest(project(),assets(),h,true),null);assert.ok(localStoreReconcileRequest(project(),assets(),h));
 const full=history();full.status.operation.result.headSequence=513;assert.equal(localStoreReconcileRequest(project(),assets(),full,true),null);assert.ok(localStoreReconcileRequest(project(),assets(),full));
});
test('record recovery stays explicit and cannot change mode during the original pending or running action',async()=>{
 const h=await fixture();try{
  assert.equal(h.controller.getSnapshot().settlement,false);assert.equal(h.controller.setSettlement(true),true);assert.equal(h.counts().prepares,0);
  const release=h.defer(),pending=h.controller.prepare();assert.equal(h.controller.setSettlement(false),false);release();await pending;
  assert.equal(h.controller.getSnapshot().status.operation.context.operation,'local-store-recovery-settle');
  assert.equal(h.controller.setSettlement(false),false);assert.equal(h.counts().starts,0);h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().starts,1);assert.equal(h.counts().cancels,0);
  h.emit(status(h.latest().statusRevision+1,complete(h.latest().operation)));assert.ok(h.controller.getSnapshot().status.operation.result);assert.equal(h.controller.getSnapshot().historical,false);
  assert.equal(h.controller.setSettlement(false),true);assert.equal(h.controller.getSnapshot().historical,true);assert.equal(h.counts().starts,1);
 }finally{h.controller.dispose();}
});
test('recovery successor uses the original reviewed head and late cancelled Prepare never restores consent',async()=>{
 for(const wrongHead of [true,false]){const h=await fixture();try{h.controller.setSettlement(true);
  if(wrongHead){await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();const result=complete(h.latest().operation);result.result.headSequence=8;h.emit(status(h.latest().statusRevision+1,result));assert.equal(h.controller.getSnapshot().blocked,true);assert.equal(h.controller.getSnapshot().status.operation.result,null);}
  else{const release=h.defer(),pending=h.controller.prepare();await h.controller.cancel();assert.equal(h.controller.setSettlement(false),false);release();await pending;await Promise.resolve();assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);assert.equal(h.controller.getSnapshot().consentUntil,null);}
 }finally{h.controller.dispose();}}
});

// Actual Reconcile controller and wire; native/provider boundaries stay inert.
function iosAssets(){const a=assets();a.scope.platform=a.status.context.platform='ios';a.status.assignments[0].kind=a.status.records[0].kind='asc-p8';return a;}
function iosHistory(){const h=history(),p=h.status.operation.result.preparedIntent;h.status.operation.context.platform='ios';delete p.applicationId;p.bundleId='org.example.ios-app';p.appStoreAppId='0012345';p.destination={channel:'testflight-internal'};p.limitations[2]='current-asc-snapshot-may-change';return h;}
function iosComplete(o){const v=complete(o),r=v.result.reconciliationReceipt;v.result.scope='local-ios-store-reconcile';delete r.applicationId;r.bundleId='org.example.ios-app';r.appStoreAppId='0012345';r.destination={channel:'testflight-internal'};r.observation='current-internal-build-only';return v;}
test('iOS readback has exact ASC current-last context, no Android selection or settlement authority',()=>{
 const p=project();delete p.selection;const request=localStoreReconcileRequest(p,iosAssets(),iosHistory());assert.ok(request);assert.equal(request.platform,'ios');assert.equal(request.confirmation,'candidate:ios:1.2.3:42');assert.ok(encodeLocalStoreReconcileRequest('prepare_local_store_reconcile',request));
 for(const extra of [{platform:null},{platform:'android'},{settlement:null},{settlement:'record-current-target'},{toolchainSelection:{}},{developerDirectory:'/Applications/Xcode.app/Contents/Developer'}])assert.equal(encodeLocalStoreReconcileRequest('prepare_local_store_reconcile',{...request,...extra}),null);
 assert.equal(localStoreReconcileRequest(p,iosAssets(),iosHistory(),true),null);
 for(const mutate of [(p,a,h)=>delete h.status.operation.context.platform,(p,a)=>a.status.assignments[0].kind='google-service-account',(p,a)=>a.scope.platform='android',(p,a,h)=>h.status.operation.result.history.push({operationId:V,phase:'execute-pending',recoveryRequired:true}),p=>p.savedVersion.build++]){const p=project(),a=iosAssets(),h=iosHistory();mutate(p,a,h);assert.equal(localStoreReconcileRequest(p,a,h),null);}
});
test('iOS readback receipt is exact16 current processed-build observation, not retry or recovery',()=>{
 const good=iosComplete(op(localStoreReconcileRequest(project(),iosAssets(),iosHistory())));assert.ok(parseLocalStoreReconcileStatus(status(1,good)));assert.equal(Object.keys(good.result.reconciliationReceipt).length,16);
 for(const mutate of [o=>o.result.scope='local-android-store-reconcile',o=>o.result.reconciliationReceipt.applicationId='org.example.app',o=>o.result.reconciliationReceipt.appStoreAppId=123,o=>o.result.reconciliationReceipt.bundleId='invalid..bundle',o=>o.result.reconciliationReceipt.destination.channel='testflight-external',o=>o.result.reconciliationReceipt.observation='current-internal-target-only',o=>o.result.reconciliationReceipt.result='processing',o=>o.result.reconciliationReceipt.priorExecutionFinality='complete',o=>o.result.reconciliationReceipt.observedAt='2026-02-30T20:01:00Z',o=>o.context.settlement='record-current-target',o=>o.context.operation='local-store-recovery-settle']){const bad=copy(good);mutate(bad);assert.equal(parseLocalStoreReconcileStatus(status(1,bad)),null);}
});
test('iOS readback uses retained consent, starts once and binds current source and both app identifiers',async()=>{
 for(const field of [null,'bundleId','appStoreAppId','sourceTree']){const h=await fixture(true);try{assert.equal(h.controller.prepareReason(),null);assert.equal(h.controller.setSettlement(true),false);await h.controller.prepare();assert.equal(h.counts().starts,0);h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().starts,1);assert.equal(h.counts().cancels,0);const done=iosComplete(h.latest().operation);if(field)done.result.reconciliationReceipt[field]=field==='bundleId'?'other.app':field==='appStoreAppId'?'999':'f'.repeat(40);h.emit(status(h.latest().statusRevision+1,done));assert.equal(h.controller.getSnapshot().blocked,!!field);assert.equal(!!h.controller.getSnapshot().status.operation.result,!field);}finally{h.controller.dispose();}}
});
test('iOS readback scope, saved version and ASC changes retire original once; missing keys keep Apple guidance',async()=>{
 for(const change of [(p,a)=>a.scope.platform='android',(p,a)=>a.status.context.revision++,(p,a,h)=>h.status.operation.result.headSequence++,p=>p.savedVersion.sha256='e'.repeat(64)]){const h=await fixture(true);try{await h.controller.prepare();h.controller.acknowledge(true);h.change(change);await h.controller.start();assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);}finally{h.controller.dispose();}}
 const h=await fixture(true);try{h.change((p,a)=>a.status.assignments=[]);assert.equal(h.controller.getSnapshot().platform,'ios');assert.equal(h.controller.getSnapshot().request,null);assert.match(h.controller.prepareReason(),/App Store Connect/);await h.controller.prepare();assert.equal(h.counts().prepares,0);}finally{h.controller.dispose();}
});
test('iOS History readback selection keeps platform and never unlocks Apple recovery',async()=>{
 const value=iosHistory().status;assert.ok(parseLocalHistoryStatus(value));const verified=copy(value);verified.operation.context={projectId:'p1',executionMode:'local',action:'verify'};delete verified.operation.result.preparedIntent;
 const controller=new LocalReleaseHistoryController({projectId:()=> 'p1',otherOperationReason:()=>null});controller.syncProject();try{await controller.connect({mode:'native',subscribeLocalReleaseHistory:async()=>()=>{},localReleaseHistoryStatus:async()=>verified});controller.syncProject();controller.setInputPlatform('ios');assert.equal(controller.selectCandidate('review-recovery',U),false);assert.equal(controller.selectCandidate('review-reconcile',U),true);assert.equal(controller.getSnapshot().request.platform,'ios');assert.equal(controller.getSnapshot().request.action,'review-reconcile');}finally{controller.dispose();}
});

test('iOS-only workspace reaches readback through actual saved-version observation without an Android selection',async()=>{
 const {localStoreProjectObservation}=await import('../src/localStorePreflight.ts');const {ReleaseVersionController}=await import('../src/releaseVersion.ts');const {initialWorkspace,workspaceReducer}=await import('../src/drafts.ts');const {AndroidBuildController}=await import('../src/androidBuild.ts');
 const assurance={basis:'static-text',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'},config={bytes:100,sha256:'a'.repeat(64)},source='release/version.properties';
 const snapshot={root:'/inert/never-opened',observedAt:'',observationScope:'single-request-non-atomic',config:{path:'release/mobile-release.json',state:'format-valid',content:copy(config),issues:[],data:{ios:{enabled:true,bundleId:'org.example.ios-app'},version:{source}}},discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance:copy(assurance),issues:[]};
 let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p1',name:'iOS only',path:'/inert/never-opened'}});workspace=workspaceReducer(workspace,{type:'snapshot-start',projectId:'p1',requestId:1});workspace=workspaceReducer(workspace,{type:'snapshot-done',projectId:'p1',requestId:1,snapshot,observedAt:1});const session=workspace.projects.p1;
 const version=new ReleaseVersionController(()=>session),android=new AndroidBuildController({selectedProject:()=>session,releaseVersion:version.getSnapshot,otherOperationReason:()=>null});
 const observation={schemaVersion:2,source,version:{name:'1.2.3',build:42},savedConfig:copy(config),savedVersion:{bytes:40,sha256:'b'.repeat(64)},observationScope:'single-request-non-atomic',assurance:copy(assurance)};
 version.setConnection({mode:'native',observeReleaseVersion:async()=>copy(observation)},{runtime:{state:'available',mode:'installed',reason:null},capabilities:{methods:[{method:'release.version.observe',available:true,reason:''}]}});version.syncProject();
 const controller=new LocalStoreReconcileController({project:()=>localStoreProjectObservation(session,version.getSnapshot()),assets:iosAssets,history:iosHistory,otherOperationReason:()=>null});let latest=status(),starts=0,cancels=0;
 const unlisten=version.subscribe(controller.syncProject);
 try{
  await controller.connect({mode:'native',subscribeLocalStoreReconcile:async()=>()=>{},localStoreReconcileStatus:async()=>latest,prepareLocalStoreReconcile:async request=>{assert.equal(request.platform,'ios');latest=status(1,op(request));return copy(latest);},startLocalStoreReconcile:async()=>{starts++;throw Error('must not start after version re-read');},cancelLocalStoreReconcile:async()=>{cancels++;latest=status(2,cancelled(latest.operation));return copy(latest);}});
  controller.syncProject();assert.equal(controller.getSnapshot().request,null);await version.read();android.syncProject();assert.ok(android.getSnapshot().project.inputIssue);assert.equal(localStoreReconcileRequest(android.getSnapshot().project,iosAssets(),iosHistory()),null);
  assert.equal(controller.getSnapshot().request.platform,'ios');assert.equal(controller.getSnapshot().request.confirmation,'candidate:ios:1.2.3:42');assert.equal(controller.prepareReason(),null);
  await controller.prepare();controller.acknowledge(true);await version.read();await Promise.resolve();await controller.start();assert.equal(starts,0);assert.equal(cancels,1);assert.equal(controller.getSnapshot().consentUntil,null);
 }finally{unlisten();controller.dispose();version.dispose();android.dispose();}
});


test('known cancellation of retained Android recovery refreshes idle iOS readback without another selection event',async()=>{
 const h=await fixture();try{assert.equal(h.controller.setSettlement(true),true);await h.controller.prepare();h.controller.acknowledge(true);
  h.change((p,a,history)=>{Object.assign(a,iosAssets());Object.assign(history,iosHistory());});
  await Promise.resolve();await Promise.resolve();
  assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);assert.equal(h.controller.getSnapshot().settlement,false);assert.equal(h.controller.getSnapshot().platform,'ios');assert.equal(h.controller.getSnapshot().request.platform,'ios');assert.equal(h.controller.prepareReason(),null);assert.equal(h.controller.getSnapshot().consentUntil,null);
 }finally{h.controller.dispose();}
});
