// Inert native-port observations only. No account, native process or Store calls.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason, localStoreProjectObservation } from '../src/localStorePreflight.ts';
import { parseLocalStoreStatus, encodeLocalStoreRequest, STORE_CONSENT, APPLE_STORE_CONSENT } from '../src/localStorePreflightProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32);
const copy=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false});
const assets=()=>({mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:C,revision:4,availability:'assigned'}]}});
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const op=request=>({operationId:A,ownerGeneration:B,context:{...copy(request),platform:request.platform??'android',operation:'local-store-preflight'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const terminal=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});
function appleAssets(){const a=assets();a.scope.platform='ios';a.status.context.platform='ios';a.status.assignments[0].kind='asc-p8';a.status.records[0].kind='asc-p8';return a;}
async function fixture(platform='android'){let currentAssets=platform==='ios'?appleAssets():assets(),now=100,listener,latest=status(),cancel=0,start=0,prepareGate=null;
 const controller=new LocalStorePreflightController({project,assets:()=>currentAssets,otherOperationReason:()=>null,now:()=>now});
 const api={mode:'native',subscribeLocalStorePreflight:async f=>{listener=f;return()=>{};},localStorePreflightStatus:async()=>latest,
 prepareLocalStorePreflight:async request=>{if(prepareGate)await prepareGate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStorePreflight:async request=>{start++;assert.equal(request.consentVersion,latest.operation.context.platform==='ios'?APPLE_STORE_CONSENT:STORE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
 cancelLocalStorePreflight:async(a,b)=>{assert.equal(a,A);assert.equal(b,B);cancel++;latest=status(latest.statusRevision+1,terminal(latest.operation));return copy(latest);}};
 await controller.connect(api);controller.syncProject();
 return{controller,api,counts:()=>({start,cancel}),platform:value=>{currentAssets=value==='ios'?appleAssets():assets();controller.syncProject();},mode:()=>{currentAssets=assets();currentAssets.status.context.executionMode='github';controller.syncProject();},time:v=>now=v,defer:()=>{let release;prepareGate=new Promise(r=>release=r);return release;},emit:v=>{latest=v;listener(copy(v));},latest:()=>copy(latest)};
}
test('local request is separate from GitHub credentials and only finite safe output reaches raw IPC',async()=>{
 const p=project(),a=assets(),request=localStoreRequest(p,a);assert.ok(request);assert.equal(Object.hasOwn(request,'credentials'),false);
 for(const mutate of [x=>x.status.context.executionMode='github',x=>x.status.assignments[0].recordRevision++,x=>x.contextCurrent=false,x=>x.blocked=true,x=>x.status.assignments.push(copy(x.status.assignments[0]))]){const bad=assets();mutate(bad);assert.equal(localStoreRequest(p,bad),null);}
 let getter=0;const unsafe={};Object.defineProperty(unsafe,'operationId',{enumerable:true,get(){getter++;return A;}});assert.equal(encodeLocalStoreRequest('cancel_local_store_preflight',unsafe),null);assert.equal(getter,0);
 const complete={...op(request),phase:'terminal',intentUsable:false,outcome:'complete',result:{schemaVersion:1,scope:'local-android-store-access-no-publishing',findings:[{check:'store-access',status:'FAIL'}],limitations:['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic']}};
 assert.ok(parseLocalStoreStatus(status(1,complete)));const bad=copy(complete);bad.result.findings[0].message='private response';assert.equal(parseLocalStoreStatus(status(1,bad)),null);
 const calls=[];const api=createNativeApi('native',async(command,body)=>{calls.push([command,body]);return status();},async()=>()=>{});
 await api.prepareLocalStorePreflight(request);assert.equal(calls[0][0],'prepare_local_store_preflight');assert.ok(calls[0][1] instanceof Uint8Array);assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0][1])),JSON.parse(JSON.stringify(request)));
});
test('one-use consent starts once; context mode switch stops actual original and clears local eligibility',async()=>{
 const h=await fixture();try{assert.equal(h.controller.prepareReason(),null);await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().start,1);assert.equal(h.counts().cancel,0);h.mode();await Promise.resolve();assert.equal(h.controller.getSnapshot().request,null);assert.equal(h.counts().cancel,1);}finally{h.controller.dispose();}
});
test('delayed prepare after context change is cancelled, never offered fresh consent',async()=>{
 const h=await fixture();try{const release=h.defer();const pending=h.controller.prepare();h.mode();release();await pending;await Promise.resolve();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
});
test('expired consent cannot start and unknown cleanup remains blocking after status refresh',async()=>{
 const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);h.time(60101);await h.controller.start();assert.equal(h.counts().start,0);
  const old=h.latest();h.emit(status(old.statusRevision+1,{...old.operation,phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown',result:null}));
  await h.controller.checkStatus();assert.ok(localStoreOwnerReason(h.controller.getSnapshot()));assert.equal(h.controller.getSnapshot().blocked,true);
 }finally{h.controller.dispose();}
});

test('failed cancellation allows one explicit exact-original retry without an automatic loop or clearing unknown ownership',async()=>{
 const h=await fixture();try{
  await h.controller.prepare();let reject,calls=0;const original=h.api.cancelLocalStorePreflight;
  h.api.cancelLocalStorePreflight=(a,b)=>{assert.equal(a,A);assert.equal(b,B);calls++;return calls===1?new Promise((_,r)=>reject=r):original(a,b);};
  const pending=h.controller.cancel();await h.controller.cancel();assert.equal(calls,1);
  reject(new Error('inert transport failure'));await pending;
  assert.equal(h.controller.getSnapshot().blocked,true);assert.equal(h.controller.getSnapshot().unconfirmed,true);
  h.controller.invalidate();const old=h.latest();h.emit(status(old.statusRevision+1,old.operation));await Promise.resolve();
  assert.equal(calls,1);assert.ok(localStoreOwnerReason(h.controller.getSnapshot()));
  await h.controller.cancel();assert.equal(calls,2);assert.equal(h.counts().cancel,1);
  assert.equal(h.controller.getSnapshot().status.operation.phase,'terminal');
  assert.equal(h.controller.getSnapshot().blocked,true);assert.ok(localStoreOwnerReason(h.controller.getSnapshot()));
  await h.controller.cancel();assert.equal(calls,2);
 }finally{h.controller.dispose();}
});

test('Apple access uses only its assigned P8 and exact platform-bound request and result',async()=>{
 const request=localStoreRequest(project(),appleAssets());assert.equal(request.platform,'ios');assert.equal(Object.hasOwn(request,'privateKey'),false);
 const bytes=encodeLocalStoreRequest('prepare_local_store_preflight',request);assert.ok(bytes);assert.equal(JSON.parse(new TextDecoder().decode(bytes)).platform,'ios');
 for(const platform of ['android','macos',null])assert.equal(encodeLocalStoreRequest('prepare_local_store_preflight',{...request,platform}),null);
 for(const mutate of [a=>a.status.assignments[0].kind='google-service-account',a=>a.status.records[0].kind='google-service-account',a=>a.scope.platform='android',a=>a.status.context.executionMode='github']){const a=appleAssets();mutate(a);assert.equal(localStoreRequest(project(),a),null);}
 const complete={...op(request),phase:'terminal',intentUsable:false,outcome:'complete',result:{schemaVersion:1,scope:'local-ios-store-access-no-publishing',findings:[{check:'credential-format',status:'PASS'},{check:'store-access',status:'FAIL'}],limitations:['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic']}};
 assert.ok(parseLocalStoreStatus(status(1,complete)));const bad=copy(complete);bad.result.scope='local-android-store-access-no-publishing';assert.equal(parseLocalStoreStatus(status(1,bad)),null);
 for(const consentVersion of [APPLE_STORE_CONSENT,STORE_CONSENT])assert.ok(encodeLocalStoreRequest('start_local_store_preflight',{operationId:A,ownerGeneration:B,consentVersion}));
 assert.equal(encodeLocalStoreRequest('start_local_store_preflight',{operationId:A,ownerGeneration:B,consentVersion:'local-ios-store-upload-v1'}),null);
});
test('Apple consent starts once and a platform change cancels only the original check',async()=>{
 const h=await fixture('ios');try{assert.equal(h.controller.prepareReason(),null);await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().start,1);assert.equal(h.counts().cancel,0);h.platform('android');await Promise.resolve();assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().consentUntil,null);assert.equal(h.controller.getSnapshot().platform,'android');}finally{h.controller.dispose();}
 const delayed=await fixture('ios');try{const release=delayed.defer(),pending=delayed.controller.prepare();delayed.platform('android');release();await pending;await Promise.resolve();assert.equal(delayed.counts().start,0);assert.equal(delayed.counts().cancel,1);assert.equal(delayed.controller.getSnapshot().consentUntil,null);}finally{delayed.controller.dispose();}
 const cancelled=await fixture('ios');try{const release=cancelled.defer(),pending=cancelled.controller.prepare();await cancelled.controller.cancel();release();await pending;await Promise.resolve();assert.equal(cancelled.counts().start,0);assert.equal(cancelled.counts().cancel,1);assert.equal(cancelled.controller.getSnapshot().consentUntil,null);}finally{cancelled.controller.dispose();}
});
test('Store saved-source observation needs no Android or Xcode selection and refuses stale version bindings',async()=>{
 const assurance={basis:'static-text',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'};
 const config={bytes:100,sha256:'a'.repeat(64)},source='release/version.properties';
 const snapshot={root:'/inert/never-opened',observedAt:'',observationScope:'single-request-non-atomic',config:{path:'release/mobile-release.json',state:'format-valid',content:copy(config),issues:[],data:{ios:{enabled:true,bundleId:'dev.example.ios'},version:{source}}},discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance:copy(assurance),issues:[]};
 let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p1',name:'iOS only',path:'/inert/never-opened'}});
 workspace=workspaceReducer(workspace,{type:'snapshot-start',projectId:'p1',requestId:1});workspace=workspaceReducer(workspace,{type:'snapshot-done',projectId:'p1',requestId:1,snapshot,observedAt:1});
 const session=workspace.projects.p1,version=new ReleaseVersionController(()=>session);
 const observation={schemaVersion:2,source,version:{name:'1.2.3',build:42},savedConfig:copy(config),savedVersion:{bytes:40,sha256:'b'.repeat(64)},observationScope:'single-request-non-atomic',assurance:copy(assurance)};
 version.setConnection({mode:'native',observeReleaseVersion:async()=>copy(observation)},{runtime:{state:'available',mode:'installed',reason:null},capabilities:{methods:[{method:'release.version.observe',available:true,reason:''}]}});version.syncProject();
 try{assert.ok(localStoreProjectObservation(session,version.getSnapshot()).inputIssue);await version.read();const state=version.getSnapshot(),ready=localStoreProjectObservation(session,state);assert.equal(ready.inputIssue,null);assert.ok(localStoreRequest(ready,appleAssets()));
  for(const change of [v=>v.stale=true,v=>v.selectionPending=true,v=>v.resultBinding.readEpoch++,v=>v.resultBinding.connectionGeneration++,v=>v.result.source='release/other.properties',v=>v.result.savedConfig.sha256='c'.repeat(64),v=>v.project.observationGeneration++]){const bad=copy(state);change(bad);assert.ok(localStoreProjectObservation(session,bad).inputIssue);}
  const changed=copy(session);changed.snapshotRequest=2;assert.equal(localStoreRequest(localStoreProjectObservation(changed,state),appleAssets()),null);
 }finally{version.dispose();}
});
