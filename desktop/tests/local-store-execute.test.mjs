// Inert native-port tests; no Store, filesystem, credential or process operations.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStoreExecuteController, localStoreExecuteRequest, localStoreExecuteOwnerReason } from '../src/localStoreExecute.ts';
import { encodeLocalStoreExecuteRequest, parseLocalStoreExecuteStatus, STORE_EXECUTE_CONSENT, IOS_STORE_EXECUTE_CONSENT } from '../src/localStoreExecuteProtocol.ts';
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
const op=request=>({operationId:A,ownerGeneration:B,context:{...copy(request),platform:request.platform??'android',operation:'local-store-execute'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const cancelled=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});
const complete=o=>({...o,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-android-store-execute',headSequence:7,executionReceipt:{operationId:U,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),receiptSha256:'d'.repeat(64),authorizationId:V,sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:01:00Z',result:'accepted',limitations:['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic']}}});
async function fixture(ios=false){let p=project(),a=ios?iosAssets():assets(),h=ios?iosHistory():history(),t=ios?null:tools(),now=100,listener,latest=status(),starts=0,cancels=0,prepares=0,gate=null,other=null;
 const controller=new LocalStoreExecuteController({project:()=>p,assets:()=>a,history:()=>h,tools:()=>t,otherOperationReason:()=>other,now:()=>now});
 const api={mode:'native',subscribeLocalStoreExecute:async f=>{listener=f;return()=>{};},localStoreExecuteStatus:async()=>latest,
 prepareLocalStoreExecute:async request=>{prepares++;if(gate)await gate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStoreExecute:async request=>{starts++;assert.equal(request.consentVersion,ios?IOS_STORE_EXECUTE_CONSENT:STORE_EXECUTE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
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

// iOS reuses the actual controller/ports; only the native boundary is inert.
function iosAssets(){const a=assets();a.scope.platform=a.status.context.platform='ios';a.status.assignments[0].kind=a.status.records[0].kind='asc-p8';return a;}
function iosHistory(){const h=history(),p=h.status.operation.result.preparedIntent;h.status.operation.context.platform='ios';delete p.applicationId;p.bundleId='org.example.ios-app';p.appStoreAppId='0012345';p.destination={channel:'testflight-internal'};p.limitations[2]='current-asc-snapshot-may-change';return h;}
function iosComplete(o){const v=complete(o),r=v.result.executionReceipt;v.result.scope='local-ios-store-execute';delete r.applicationId;r.bundleId='org.example.ios-app';r.appStoreAppId='0012345';r.destination={channel:'testflight-internal'};return v;}
test('iOS Execute uses exact ASC and prepared platform without Android selection or caller Xcode paths',()=>{
 const p=project();delete p.selection;const good=localStoreExecuteRequest(p,iosAssets(),iosHistory(),null);assert.ok(good);assert.equal(good.platform,'ios');assert.equal(good.confirmation,'candidate:ios:1.2.3:42');assert.equal(Object.hasOwn(good,'toolchainSelection'),false);
 assert.ok(encodeLocalStoreExecuteRequest('prepare_local_store_execute',good));
 for(const patch of [{platform:null},{platform:'android'},{toolchainSelection:selection()},{toolchainSelection:null},{developerDirectory:'/Applications/Xcode.app/Contents/Developer'},{confirmation:'candidate:android:1.2.3:42'},{recover:true}])assert.equal(encodeLocalStoreExecuteRequest('prepare_local_store_execute',{...good,...patch}),null);
 for(const mutate of [(p,a,h)=>delete h.status.operation.context.platform,(p,a)=>a.status.assignments[0].kind='google-service-account',(p,a)=>a.status.context.platform='android',(p,a)=>a.scope.platform='android',(p,a,h)=>h.status.operation.result.preparedIntent.destination.channel='testflight-external',(p)=>p.savedVersion.build++]){const p=project(),a=iosAssets(),h=iosHistory();mutate(p,a,h);assert.equal(localStoreExecuteRequest(p,a,h,null),null);}
});
test('iOS Execute receipt is exact platform14, never a processed-state or previous-tail assertion',()=>{
 const good=iosComplete(op(localStoreExecuteRequest(project(),iosAssets(),iosHistory(),null)));assert.ok(parseLocalStoreExecuteStatus(status(1,good)));
 for(const mutate of [o=>o.result.scope='local-android-store-execute',o=>o.result.executionReceipt.applicationId='org.example.app',o=>o.result.executionReceipt.appStoreAppId=12345,o=>o.result.executionReceipt.appStoreAppId='123x',o=>o.result.executionReceipt.bundleId='org..app',o=>o.result.executionReceipt.destination.channel='testflight-external',o=>o.result.executionReceipt.autoNotifyEnabled=false,o=>o.result.executionReceipt.result='processing',o=>o.result.executionReceipt.priorExecutionFinality='complete',o=>o.result.executionReceipt.observedAt='2026-02-30T20:00:00Z',o=>o.context.platform='android']){const bad=copy(good);mutate(bad);assert.equal(parseLocalStoreExecuteStatus(status(1,bad)),null);}
 for(const key of Object.keys(good.result.executionReceipt)){const bad=copy(good);delete bad.result.executionReceipt[key];assert.equal(parseLocalStoreExecuteStatus(status(1,bad)),null);}
 const reconciled=copy(good);reconciled.result.executionReceipt.result='reconciled';assert.ok(parseLocalStoreExecuteStatus(status(1,reconciled)));
});
test('iOS Execute uses retained iOS consent, starts once, and binds returned app/source to its prepared review',async()=>{
 for(const field of [null,'bundleId','appStoreAppId','sourceCommit']){const h=await fixture(true);try{assert.equal(h.controller.prepareReason(),null);await h.controller.prepare();assert.equal(h.counts().starts,0);h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().starts,1);assert.equal(h.counts().cancels,0);const done=iosComplete(h.latest().operation);if(field)done.result.executionReceipt[field]=field==='bundleId'?'other.app':field==='appStoreAppId'?'999':'f'.repeat(40);h.emit(status(h.latest().statusRevision+1,done));assert.equal(h.controller.getSnapshot().blocked,!!field);assert.equal(!!h.controller.getSnapshot().status.operation.result,!field);}finally{h.controller.dispose();}}
});
test('iOS Execute scope change and late Prepare retire original once without granting upload or recovery',async()=>{
 for(const change of [(p,a)=>{a.scope.platform='android';},(p,a)=>{a.status.context.revision++;},(p,a,h)=>{h.status.operation.result.headSequence++;},(p)=>{p.savedVersion.sha256='e'.repeat(64);}]){const h=await fixture(true);try{await h.controller.prepare();h.controller.acknowledge(true);h.change(change);await h.controller.start();assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);}finally{h.controller.dispose();}}
 const h=await fixture(true);try{const release=h.defer(),pending=h.controller.prepare();h.controller.setSelectionPending(true);release();await pending;await Promise.resolve();assert.equal(h.counts().starts,0);assert.equal(h.counts().cancels,1);assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
});

test('iOS-only workspace reaches Execute through actual saved-version observation without an Android selection',async()=>{
 const {localStoreProjectObservation}=await import('../src/localStorePreflight.ts');const {ReleaseVersionController}=await import('../src/releaseVersion.ts');const {initialWorkspace,workspaceReducer}=await import('../src/drafts.ts');const {AndroidBuildController}=await import('../src/androidBuild.ts');
 const assurance={basis:'static-text',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'},config={bytes:100,sha256:'a'.repeat(64)},source='release/version.properties';
 const snapshot={root:'/inert/never-opened',observedAt:'',observationScope:'single-request-non-atomic',config:{path:'release/mobile-release.json',state:'format-valid',content:copy(config),issues:[],data:{ios:{enabled:true,bundleId:'org.example.ios-app'},version:{source}}},discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance:copy(assurance),issues:[]};
 let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p1',name:'iOS only',path:'/inert/never-opened'}});workspace=workspaceReducer(workspace,{type:'snapshot-start',projectId:'p1',requestId:1});workspace=workspaceReducer(workspace,{type:'snapshot-done',projectId:'p1',requestId:1,snapshot,observedAt:1});const session=workspace.projects.p1;
 const version=new ReleaseVersionController(()=>session),android=new AndroidBuildController({selectedProject:()=>session,releaseVersion:version.getSnapshot,otherOperationReason:()=>null});
 const observation={schemaVersion:2,source,version:{name:'1.2.3',build:42},savedConfig:copy(config),savedVersion:{bytes:40,sha256:'b'.repeat(64)},observationScope:'single-request-non-atomic',assurance:copy(assurance)};
 version.setConnection({mode:'native',observeReleaseVersion:async()=>copy(observation)},{runtime:{state:'available',mode:'installed',reason:null},capabilities:{methods:[{method:'release.version.observe',available:true,reason:''}]}});version.syncProject();
 const controller=new LocalStoreExecuteController({project:()=>localStoreProjectObservation(session,version.getSnapshot()),assets:iosAssets,history:iosHistory,tools:()=>null,otherOperationReason:()=>null});let latest=status(),starts=0,cancels=0;
 const unlisten=version.subscribe(controller.syncProject);
 try{
  await controller.connect({mode:'native',subscribeLocalStoreExecute:async()=>()=>{},localStoreExecuteStatus:async()=>latest,prepareLocalStoreExecute:async request=>{assert.equal(request.platform,'ios');latest=status(1,op(request));return copy(latest);},startLocalStoreExecute:async()=>{starts++;throw Error('must not start after version re-read');},cancelLocalStoreExecute:async()=>{cancels++;latest=status(2,cancelled(latest.operation));return copy(latest);}});
  controller.syncProject();assert.equal(controller.getSnapshot().request,null);await version.read();android.syncProject();assert.ok(android.getSnapshot().project.inputIssue);assert.equal(localStoreExecuteRequest(android.getSnapshot().project,iosAssets(),iosHistory(),null),null);
  assert.equal(controller.getSnapshot().request.platform,'ios');assert.equal(controller.getSnapshot().request.confirmation,'candidate:ios:1.2.3:42');assert.equal(controller.prepareReason(),null);
  await controller.prepare();controller.acknowledge(true);await version.read();await Promise.resolve();await controller.start();assert.equal(starts,0);assert.equal(cancels,1);assert.equal(controller.getSnapshot().consentUntil,null);
 }finally{unlisten();controller.dispose();version.dispose();android.dispose();}
});

test('iOS Execute missing credential keeps iOS guidance without granting a request or upload',async()=>{
 const h=await fixture(true);try{h.change((p,a)=>{a.status.assignments=[];});assert.equal(h.controller.getSnapshot().platform,'ios');assert.equal(h.controller.getSnapshot().request,null);assert.ok(h.controller.prepareReason());await h.controller.prepare();assert.equal(h.counts().prepares,0);h.change((p,a)=>{a.scope.platform='android';a.status.context.platform='android';});assert.equal(h.controller.getSnapshot().platform,'android');assert.equal(h.controller.getSnapshot().request,null);}finally{h.controller.dispose();}
});
