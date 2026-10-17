// Inert native-port tests; no Store, filesystem, credential or process operations.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStoreExecuteController, localStoreExecuteRequest, localStoreExecuteOwnerReason } from '../src/localStoreExecute.ts';
import { encodeLocalStoreExecuteRequest, parseLocalStoreExecuteStatus, STORE_EXECUTE_CONSENT } from '../src/localStoreExecuteProtocol.ts';
import { encodeLocalStorePrepareRequest, parseLocalStorePrepareStatus } from '../src/localStorePrepareProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),U='12345678-1234-4234-8234-123456789abc',V='23456789-1234-4234-8234-123456789abc';
const copy=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},selection:{module:'app',variant:'release',applicationId:'dev.example.app'},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false});
const assets=()=>({mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:C,revision:4,availability:'assigned'}]}});
const prepared=()=>({operationId:U,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),storePreconditionSha256:'c'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:00:00Z',limitations:['non-publishing','prepare-not-execute','temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic'],observation:'current-prepared-files-only',priorPrepareFinality:'not-established'});
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const history=()=>({mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:status(1,{operationId:C,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-prepared',candidateOperationId:U},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:5,history:[{operationId:U,phase:'prepared',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],preparedIntent:prepared()}})});
const selection=()=>({instance:A,ownerUid:501,catalogGeneration:1,recordSha256:'a'.repeat(64),inventorySha256:'b'.repeat(64),osProviderSha256:'c'.repeat(64)});
const tools=()=>({mode:'native',catalogListening:true,catalogReadPending:false,selectionPending:false,catalogStatus:{schemaVersion:1,statusRevision:1,catalogGeneration:1,operationId:B,availability:'available',phase:'ready',reason:'none',selected:selection(),entries:[{instance:A,occupants:3,status:'verified-this-session',versions:{jdkVendor:'Temurin',jdkVersion:'21',gradleVersion:'8.10',agpVersion:'8.7',sdkPlatform:'35',sdkBuildToolsVersion:'35.0.0'},recovery:null,selection:selection()}]},status:null});
const op=request=>({operationId:A,ownerGeneration:B,context:{...copy(request),platform:'android',operation:'local-store-execute'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const cancelled=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});
const complete=o=>({...o,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-android-store-execute',headSequence:7,executionReceipt:{operationId:U,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),receiptSha256:'d'.repeat(64),authorizationId:V,sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:01:00Z',result:'accepted',limitations:['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic']}}});
async function fixture(){let p=project(),a=assets(),h=history(),t=tools(),now=100,listener,latest=status(),starts=0,cancels=0,prepares=0,gate=null,other=null;
 const controller=new LocalStoreExecuteController({project:()=>p,assets:()=>a,history:()=>h,tools:()=>t,otherOperationReason:()=>other,now:()=>now});
 const api={mode:'native',subscribeLocalStoreExecute:async f=>{listener=f;return()=>{};},localStoreExecuteStatus:async()=>latest,
 prepareLocalStoreExecute:async request=>{prepares++;if(gate)await gate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStoreExecute:async request=>{starts++;assert.equal(request.consentVersion,STORE_EXECUTE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
 cancelLocalStoreExecute:async(x,y)=>{assert.equal(x,A);assert.equal(y,B);cancels++;latest=status(latest.statusRevision+1,cancelled(latest.operation));return copy(latest);}};
 await controller.connect(api);controller.syncProject();
 return{controller,api,counts:()=>({starts,cancels,prepares}),change:fn=>{fn(p,a,h,t);controller.syncProject();},time:v=>now=v,busy:v=>other=v,defer:()=>{let release;gate=new Promise(r=>release=r);return release;},emit:v=>{latest=v;listener(copy(v));},latest:()=>copy(latest)};
}
test('Execute comparison requires current last prepared review, matching saved inputs, local Google and selected protected tools',()=>{
 const good=localStoreExecuteRequest(project(),assets(),history(),tools());assert.ok(good);assert.deepEqual(copy(good.toolchainSelection),selection());assert.equal(good.intentSha256,prepared().intentSha256);
 const mutations=[(p)=>p.savedVersion.build++,(p)=>p.selection.applicationId='other.app',(p)=>p.dirtyDraft=true,(_p,a)=>a.status.context.executionMode='github',(_p,a)=>a.scope.stage='production',(_p,a)=>a.status.context.stage='production',(_p,a)=>a.status.assignments[0].recordRevision++,(_p,_a,h)=>h.historical=true,(_p,_a,h)=>h.status.operation.context.projectId='p2',(_p,_a,h)=>h.status.operation.context.action='review-inputs',(_p,_a,h)=>h.status.operation.result.history.push({operationId:V,phase:'inputs-ready',recoveryRequired:true}),(_p,_a,h)=>h.status.operation.result.history[0].phase='execute-pending',(_p,_a,h)=>h.status.operation.result.preparedIntent.priorPrepareFinality='passed',(_p,_a,_h,t)=>t.catalogListening=false,(_p,_a,_h,t)=>t.catalogReadPending=true,(_p,_a,_h,t)=>t.catalogStatus.availability='busy',(_p,_a,_h,t)=>t.catalogStatus.selected=null,(_p,_a,_h,t)=>t.catalogIssue=true,(_p,_a,_h,t)=>t.selectionPending=true,(_p,_a,_h,t)=>t.nativeBlocked=true];
 for(const mutate of mutations){const p=project(),a=assets(),h=history(),t=tools();mutate(p,a,h,t);assert.equal(localStoreExecuteRequest(p,a,h,t),null);}
});
test('Execute IPC is bounded and separate from Prepare, CI, recovery and renderer authorization',async()=>{
 const request=localStoreExecuteRequest(project(),assets(),history(),tools());
 assert.ok(encodeLocalStoreExecuteRequest('prepare_local_store_execute',request));assert.equal(encodeLocalStorePrepareRequest('prepare_local_store_prepare',request),null);
 for(const patch of [{executionMode:'github'},{authorizationId:V},{recover:true},{intentSha256:'A'.repeat(64)},{confirmation:'production:android:1.2.3:42'},{toolchainSelection:{...selection(),ownerUid:0}},{toolchainSelection:{...selection(),path:'/private/key'}}])assert.equal(encodeLocalStoreExecuteRequest('prepare_local_store_execute',{...request,...patch}),null);
 for(const consentVersion of ['local-android-store-prepare-v1','local-android-store-access-v1','local-android-candidate-inputs-v1'])assert.equal(encodeLocalStoreExecuteRequest('start_local_store_execute',{operationId:A,ownerGeneration:B,consentVersion}),null);
 let calls=0;const getter={};Object.defineProperty(getter,'operationId',{enumerable:true,get(){calls++;return A;}});assert.equal(encodeLocalStoreExecuteRequest('cancel_local_store_execute',getter),null);assert.equal(calls,0);
 let event;const actual=[];const api=createNativeApi('native',async(command,body)=>{actual.push([command,body]);return status();},async(name)=>{event=name;return()=>{};});
 await api.prepareLocalStoreExecute(request);await api.subscribeLocalStoreExecute(()=>{});assert.equal(event,'local-store-execute-state-changed');assert.equal(actual[0][0],'prepare_local_store_execute');assert.deepEqual(JSON.parse(new TextDecoder().decode(actual[0][1])),copy(request));
 await assert.rejects(()=>createNativeApi('preview',async()=>assert.fail('no preview dispatch')).prepareLocalStoreExecute(request));
 for(const method of ['prepareLocalStoreExecute','startLocalStoreExecute','localStoreExecuteStatus','cancelLocalStoreExecute','subscribeLocalStoreExecute']) await assert.rejects(()=>previewApi[method](request),e=>e.code==='local_store_execute_unavailable');
});
test('exact current execution result keeps all receipt bindings and excludes old Prepare result or authority claims',()=>{
 const good=complete(op(localStoreExecuteRequest(project(),assets(),history(),tools())));assert.ok(parseLocalStoreExecuteStatus(status(1,good)));assert.equal(parseLocalStorePrepareStatus(status(1,good)),null);
 const reconciled=copy(good);reconciled.result.executionReceipt.result='reconciled';assert.ok(parseLocalStoreExecuteStatus(status(1,reconciled)));
 // Native public retirement also maps these original owner losses to cancelled;
 // the core's narrower stop enum must not erase that legitimate public result.
 for(const reason of ['cancelled','context-changed','document-lost','shutdown'])assert.ok(parseLocalStoreExecuteStatus(status(1,{...good,outcome:'cancelled',reason,result:null})));
 for(const [outcome,reason] of [['failed','none'],['refused','none'],['cancelled','none'],['timed-out','none'],['cancelled','execute-unavailable'],['cancelled','timed-out'],['timed-out','cancelled'],['failed','cleanup-unknown']])assert.equal(parseLocalStoreExecuteStatus(status(1,{...good,outcome,reason,result:null})),null);
 assert.ok(parseLocalStoreExecuteStatus(status(1,{...good,outcome:'timed-out',reason:'timed-out',result:null})));
 assert.ok(parseLocalStoreExecuteStatus(status(1,{...good,outcome:'failed',reason:'execute-unavailable',result:null})));

 for(const mutate of [o=>o.result.headSequence=6,o=>o.result.headSequence=514,o=>o.result.executionReceipt.operationId=V,o=>o.result.executionReceipt.candidateSha256='d'.repeat(64),o=>o.result.executionReceipt.intentSha256='d'.repeat(64),o=>o.result.executionReceipt.version.build++,o=>o.result.executionReceipt.version.build=42.5,o=>o.result.executionReceipt.authorizationId=A,o=>o.result.executionReceipt.sourceCommit='a'.repeat(39),o=>o.result.executionReceipt.destination.channel='production',o=>o.result.executionReceipt.applicationId='1bad.app',o=>o.result.executionReceipt.observedAt='2026-02-30T20:01:00Z',o=>o.result.executionReceipt.limitations.pop(),o=>o.result.executionReceipt.privateKey='SECRET_SENTINEL',o=>o.result.executionReceipt.result='already_present',o=>o.result.preparedIntent=prepared(),o=>o.reason='prepare-unavailable',o=>o.reason='none-from-unknown',o=>o.phase='running',o=>o.result=null]){
  const bad=copy(good);mutate(bad);assert.equal(parseLocalStoreExecuteStatus(status(1,bad)),null);
 }
 for(const key of Object.keys(good.result.executionReceipt)){const bad=copy(good);delete bad.result.executionReceipt[key];assert.equal(parseLocalStoreExecuteStatus(status(1,bad)),null);}
});
test('no automatic Start; queued double Start retains the same running original and completion',async()=>{
 const h=await fixture();try{assert.equal(h.controller.prepareReason(),null);assert.deepEqual(h.counts(),{starts:0,cancels:0,prepares:0});await h.controller.prepare();assert.equal(h.counts().starts,0);h.controller.acknowledge(true);
  let release,originalStarts=0;h.api.startLocalStoreExecute=request=>{originalStarts++;assert.equal(request.consentVersion,STORE_EXECUTE_CONSENT);h.emit(status(2,{...h.latest().operation,phase:'running',intentUsable:false}));return new Promise(r=>release=r);};
  const first=h.controller.start();const running=h.latest();let duplicate=0;const original=h.api.startLocalStoreExecute;h.api.startLocalStoreExecute=(...a)=>{duplicate++;return original(...a);};
  await h.controller.start();assert.equal(duplicate,0);assert.equal(h.counts().cancels,0);assert.equal(h.controller.getSnapshot().historical,false);
  release(status(3,complete(running.operation)));await first;await h.controller.start();assert.equal(duplicate,0);assert.equal(originalStarts,1);assert.equal(h.counts().cancels,0);assert.ok(h.controller.getSnapshot().status.operation.result);assert.equal(localStoreExecuteOwnerReason(h.controller.getSnapshot()),null);
 }finally{h.controller.dispose();}
});
test('late Prepare reply after picker or navigation is cancelled once, never started',async()=>{
 for(const retire of [h=>h.controller.setSelectionPending(true),h=>h.controller.setVisible(false),h=>h.controller.cancel()]){
  const h=await fixture();try{const release=h.defer(),first=h.controller.prepare();retire(h);await h.controller.prepare();release();await first;await Promise.resolve();assert.deepEqual(h.counts(),{starts:0,cancels:1,prepares:1});assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
 }
});
test('saved config, Google assignment, history head and actual tool choice changes retire current consent',async()=>{
 for(const change of [h=>h.change(p=>p.savedConfig.sha256='e'.repeat(64)),h=>h.change(p=>p.savedVersion.sha256='e'.repeat(64)),h=>h.change((_p,a)=>{a.status.context.revision++;a.status.assignments[0].contextRevision++;}),h=>h.change((_p,_a,s)=>s.status.operation.result.headSequence++),h=>h.change((_p,_a,s)=>s.status.operation.result.preparedIntent.intentSha256='f'.repeat(64)),h=>h.change((_p,_a,_h,t)=>{t.catalogStatus.selected.recordSha256='e'.repeat(64);t.catalogStatus.entries[0].selection.recordSha256='e'.repeat(64);}),h=>h.time(60101),h=>h.busy('Another original owner')]){
  const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);change(h);await h.controller.start();assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);}finally{h.controller.dispose();}
 }
 const h=await fixture();try{h.controller.setSelectionPending(true);h.controller.syncProject();assert.equal(h.controller.getSnapshot().request,null);h.controller.setSelectionPending(false);assert.ok(h.controller.getSnapshot().request);}finally{h.controller.dispose();}
});
test('unknown cleanup and conflicting status revision stay blocked after refresh and repeated Start',async()=>{
 for(const conflict of [false,true]){const h=await fixture();try{await h.controller.prepare();const old=h.latest();h.emit(status(old.statusRevision+(conflict?0:1),{...old.operation,phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown'}));await h.controller.checkStatus();assert.ok(localStoreExecuteOwnerReason(h.controller.getSnapshot()));h.controller.acknowledge(true);await h.controller.start();assert.equal(h.counts().starts,0);}finally{h.controller.dispose();}}
});
test('failed Cancel is not automatically retried and no private rejection leaks to the UI',async()=>{
 const h=await fixture();try{await h.controller.prepare();let reject,n=0;const original=h.api.cancelLocalStoreExecute;h.api.cancelLocalStoreExecute=(...args)=>{n++;return n===1?new Promise((_,r)=>reject=r):original(...args);};
  await h.controller.cancel();await h.controller.cancel();assert.equal(n,1);reject(new Error('SECRET_SENTINEL'));await new Promise(r=>setImmediate(r));h.controller.invalidate();await h.controller.checkStatus();assert.equal(n,1);assert.ok(localStoreExecuteOwnerReason(h.controller.getSnapshot()));assert.doesNotMatch(h.controller.getSnapshot().error,/SECRET_SENTINEL/);await h.controller.cancel();assert.equal(n,2);assert.equal(h.controller.getSnapshot().blocked,true);
 }finally{h.controller.dispose();}
});
test('a completed receipt cannot substitute a different reviewed application or source',async()=>{
 const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();const bad=complete(h.latest().operation);bad.result.executionReceipt.sourceTree='f'.repeat(40);h.emit(status(h.latest().statusRevision+1,bad));assert.equal(h.controller.getSnapshot().blocked,true);assert.equal(h.controller.getSnapshot().status.operation.result,null);}finally{h.controller.dispose();}
});

test('reconnection cannot discard a retained original; disposal consumes late identity by original Cancel',async()=>{
 const first=await fixture();try{await first.controller.prepare();first.controller.beginConnection();let subscribed=0;await first.controller.connect({...first.api,subscribeLocalStoreExecute:async()=>{subscribed++;return()=>{};}});assert.equal(subscribed,0);assert.equal(first.controller.getSnapshot().blocked,true);assert.equal(first.counts().cancels,1);}finally{first.controller.dispose();}
 const late=await fixture();const release=late.defer(),pending=late.controller.prepare();late.controller.dispose();release();await pending;await Promise.resolve();assert.equal(late.counts().cancels,1);assert.equal(late.counts().starts,0);assert.equal(late.controller.getSnapshot().consentUntil,null);
});
