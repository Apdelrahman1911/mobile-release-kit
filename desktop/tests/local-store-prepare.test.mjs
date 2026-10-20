// Inert native-port tests only: no filesystem, Keychain, process or Store calls.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStorePrepareController, localStorePrepareRequest, localStorePrepareOwnerReason } from '../src/localStorePrepare.ts';
import { encodeLocalStorePrepareRequest, parseLocalStorePrepareRequest, parseLocalStorePrepareStatus, STORE_PREPARE_CONSENT, IOS_STORE_PREPARE_CONSENT } from '../src/localStorePrepareProtocol.ts';
import { localStoreRequest } from '../src/localStorePreflight.ts';
import { parseLocalStoreRequest } from '../src/localStorePreflightProtocol.ts';
import { PAIRED_VERSIONS_QUERY, PAIRED_VERSIONS_CONSENT } from '../src/pairedStoreVersions.ts';
import { createNativeApi } from '../src/bridge.ts';

const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),UUID='12345678-1234-4234-8234-123456789abc';
const copy=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false});
const assets=()=>({mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:C,revision:4,availability:'assigned'}]}});
const candidate=()=>({operationId:UUID,candidateSha256:'a'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},files:[{fileName:'app-release.aab',bytes:100,sha256:'d'.repeat(64)},{fileName:'store-metadata.zip',bytes:100,sha256:'e'.repeat(64)},{fileName:'validation-report.json',bytes:100,sha256:'f'.repeat(64)}],observation:'current-bundle-only',priorCreateFinality:'not-established'});
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const history=()=>({mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:status(1,{operationId:C,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-inputs',candidateOperationId:UUID},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:3,history:[{operationId:UUID,phase:'inputs-ready',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],candidateInputs:candidate()}})});
const op=request=>({operationId:A,ownerGeneration:B,context:{...copy(request),platform:request.platform??'android',operation:'local-store-prepare'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const terminal=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});
const complete=o=>({...o,phase:'terminal',intentUsable:false,outcome:'complete',result:{schemaVersion:1,scope:'local-android-store-prepare',headSequence:5,preparedIntent:{operationId:UUID,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),storePreconditionSha256:'c'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:00:00Z',limitations:['non-publishing','prepare-not-execute','temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic']}}});
async function fixture(ios=false){let p=project(),a=ios?iosAssets():assets(),h=ios?iosHistory():history(),now=100,listener,latest=status(),cancel=0,start=0,prepareGate=null,other=null;
 const controller=new LocalStorePrepareController({project:()=>p,assets:()=>a,history:()=>h,otherOperationReason:()=>other,now:()=>now});
 const api={mode:'native',subscribeLocalStorePrepare:async f=>{listener=f;return()=>{};},localStorePrepareStatus:async()=>latest,
 prepareLocalStorePrepare:async request=>{if(prepareGate)await prepareGate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStorePrepare:async request=>{start++;assert.equal(request.consentVersion,ios?IOS_STORE_PREPARE_CONSENT:STORE_PREPARE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
 cancelLocalStorePrepare:async(x,y)=>{assert.equal(x,A);assert.equal(y,B);cancel++;latest=status(latest.statusRevision+1,terminal(latest.operation));return copy(latest);}};
 await controller.connect(api);controller.syncProject();
 return{controller,api,counts:()=>({start,cancel}),change:mutate=>{mutate(p,a,h);controller.syncProject();},time:v=>now=v,busy:v=>other=v,defer:()=>{let release;prepareGate=new Promise(r=>release=r);return release;},emit:v=>{latest=v;listener(copy(v));},latest:()=>copy(latest)};
}
test('Prepare uses only the current reviewed ready candidate, full saved inputs and local Google assignment',()=>{
 const request=localStorePrepareRequest(project(),assets(),history());assert.ok(request);
 assert.deepEqual(copy(request.savedVersion),project().savedVersion);assert.deepEqual(copy(request.savedConfig),project().savedConfig);
 assert.equal(request.confirmation,'candidate:android:1.2.3:42');assert.equal(request.candidateOperationId,UUID);
 for(const mutate of [(_p,_a,h)=>h.historical=true,(_p,_a,h)=>h.blocked=true,(_p,_a,h)=>h.status.operation.context.projectId='other',(_p,_a,h)=>h.status.operation.context.action='verify',(_p,_a,h)=>h.status.operation.result.history[0].phase='prepared',(_p,_a,h)=>h.status.operation.result.history.push({operationId:'23456789-1234-4234-8234-123456789abc',phase:'inputs-ready',recoveryRequired:true}),p=>p.savedVersion.build++,(_p,a)=>a.status.context.executionMode='github',(_p,a)=>a.status.context.stage='production',(_p,a)=>a.scope.stage='production',(_p,a)=>a.status.assignments[0].recordRevision++]){
  const p=project(),a=assets(),h=history();mutate(p,a,h);assert.equal(localStorePrepareRequest(p,a,h),null);
 }
});
test('raw IPC stays distinct from access/execute authority and result is exact public candidate-bound DATA',async()=>{
 const request=localStorePrepareRequest(project(),assets(),history()),good=complete(op(request));
 assert.ok(parseLocalStorePrepareStatus(status(1,good)));
 for(const mutate of [v=>v.result.preparedIntent.operationId='23456789-1234-4234-8234-123456789abc',v=>v.result.preparedIntent.candidateSha256='d'.repeat(64),v=>v.result.preparedIntent.version.build++,v=>v.result.preparedIntent.destination.channel='production',v=>v.result.preparedIntent.account='private',v=>v.result.preparedIntent.observedAt='2026-02-30T20:00:00Z',v=>v.result.preparedIntent.limitations.pop(),v=>v.reason='prepare-unavailable',v=>v.phase='running']){
  const bad=copy(good);mutate(bad);assert.equal(parseLocalStorePrepareStatus(status(1,bad)),null);
 }
 for(const extra of [{executionMode:'github'},{authorizationId:UUID},{confirmation:'production:android:1.2.3:42'}])assert.equal(encodeLocalStorePrepareRequest('prepare_local_store_prepare',{...request,...extra}),null);
 assert.equal(encodeLocalStorePrepareRequest('start_local_store_prepare',{operationId:A,ownerGeneration:B,consentVersion:'local-android-store-access-v1'}),null);
 let getter=0;const unsafe={};Object.defineProperty(unsafe,'operationId',{enumerable:true,get(){getter++;return A;}});assert.equal(encodeLocalStorePrepareRequest('cancel_local_store_prepare',unsafe),null);assert.equal(getter,0);
 const calls=[];const api=createNativeApi('native',async(command,body)=>{calls.push([command,body]);return status();},async()=>()=>{});
 await api.prepareLocalStorePrepare(request);assert.equal(calls[0][0],'prepare_local_store_prepare');assert.ok(calls[0][1] instanceof Uint8Array);assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0][1])),copy(request));
 await assert.rejects(()=>createNativeApi('preview',async()=>assert.fail('preview cannot call native')).prepareLocalStorePrepare(request));
});
test('one-use preparation starts once and only positively complete candidate summary is returned',async()=>{
 const h=await fixture();try{assert.equal(h.controller.prepareReason(),null);assert.equal(h.controller.getSnapshot().applicationId,'dev.example.app');await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().start,1);assert.equal(h.counts().cancel,0);const running=h.latest();h.emit(status(running.statusRevision+1,complete(running.operation)));assert.equal(h.controller.getSnapshot().status.operation.result.headSequence,5);assert.equal(localStorePrepareOwnerReason(h.controller.getSnapshot()),null);await h.controller.start();assert.equal(h.counts().start,1);}finally{h.controller.dispose();}
});
test('valid paired inventory cannot become a candidate Prepare or Start operation',async()=>{
 const candidateRequest=localStorePrepareRequest(project(),assets(),history());assert.ok(candidateRequest);
 const h=await fixture();let prepareCalls=0,startCalls=0,paired;
 try{
  h.change((p,a)=>{
   p.versionPlatforms=['android','ios'];
   Object.assign(a.scope,{platform:'both',purpose:'version-inventory'});
   Object.assign(a.status.context,{platform:'both',purpose:'version-inventory'});
   a.status.assignments.push({kind:'asc-p8',recordId:'d'.repeat(32),recordRevision:4,contextRevision:3,availability:'available'});
   a.status.records.push({kind:'asc-p8',recordId:'d'.repeat(32),revision:4,availability:'assigned'});
   paired=localStoreRequest(p,a);
  });
  assert.ok(paired);assert.ok(parseLocalStoreRequest(paired));
  assert.equal(paired.platform,'both');assert.equal(paired.query,PAIRED_VERSIONS_QUERY);
  for(const extra of [{platform:'both'},{query:PAIRED_VERSIONS_QUERY},{iosRecord:paired.iosRecord},paired]){
   const invalid={...candidateRequest,...extra};
   assert.equal(parseLocalStorePrepareRequest(invalid),null);
   assert.equal(encodeLocalStorePrepareRequest('prepare_local_store_prepare',invalid),null);
  }
  assert.equal(encodeLocalStorePrepareRequest('start_local_store_prepare',{operationId:A,ownerGeneration:B,consentVersion:PAIRED_VERSIONS_CONSENT}),null);
  h.api.prepareLocalStorePrepare=async()=>{prepareCalls++;throw Error('paired inventory must not prepare a Store release');};
  h.api.startLocalStorePrepare=async()=>{startCalls++;throw Error('paired inventory must not start a Store release');};
  assert.equal(h.controller.getSnapshot().request,null);
  await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();
  assert.equal(prepareCalls,0);assert.equal(startCalls,0);assert.equal(h.counts().cancel,0);
 }finally{h.controller.dispose();}
});
test('late consent after explicit cancel, selection, or navigation is retired before the identity reply',async()=>{
 for(const retire of [h=>h.controller.cancel(),h=>h.controller.setSelectionPending(true),h=>h.controller.setVisible(false)]){
  const h=await fixture();try{const release=h.defer(),pending=h.controller.prepare();retire(h);release();await pending;await Promise.resolve();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
 }
});
test('saved-byte changes, candidate/head changes, expired consent and other owners prevent Start',async()=>{
 for(const change of [h=>h.change(p=>p.savedConfig.sha256='c'.repeat(64)),h=>h.change(p=>p.savedVersion.sha256='c'.repeat(64)),h=>h.change((_p,_a,s)=>s.status.operation.result.headSequence++),h=>h.change((_p,_a,s)=>s.status.operation.result.candidateInputs.candidateSha256='c'.repeat(64)),h=>h.time(60101),h=>h.busy('Another original operation')]){
  const h=await fixture();try{await h.controller.prepare();h.controller.acknowledge(true);change(h);await h.controller.start();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);}finally{h.controller.dispose();}
 }
 const h=await fixture();try{h.controller.setSelectionPending(true);h.controller.syncProject();assert.equal(h.controller.getSnapshot().request,null);assert.ok(h.controller.prepareReason());h.controller.setSelectionPending(false);assert.ok(h.controller.getSnapshot().request);}finally{h.controller.dispose();}
});
test('unknown cleanup and conflicting revisions retain original ownership after status refresh',async()=>{
 for(const conflict of [false,true]){
  const h=await fixture();try{await h.controller.prepare();const old=h.latest();h.emit(status(old.statusRevision+(conflict?0:1),{...old.operation,phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown',result:null}));await h.controller.checkStatus();assert.ok(localStorePrepareOwnerReason(h.controller.getSnapshot()));assert.equal(h.controller.getSnapshot().blocked,true);h.controller.acknowledge(true);await h.controller.start();assert.equal(h.counts().start,0);}finally{h.controller.dispose();}
 }
});
test('failed cancellation is retained and only explicit retry sends another cancellation',async()=>{
 const h=await fixture();try{await h.controller.prepare();let reject,calls=0;const original=h.api.cancelLocalStorePrepare;
  h.api.cancelLocalStorePrepare=(a,b)=>{assert.equal(a,A);assert.equal(b,B);calls++;return calls===1?new Promise((_,r)=>reject=r):original(a,b);};
  const pending=h.controller.cancel();await h.controller.cancel();assert.equal(calls,1);reject(new Error('inert failure'));await pending;await Promise.resolve();
  h.controller.invalidate();await h.controller.checkStatus();assert.equal(calls,1);assert.ok(localStorePrepareOwnerReason(h.controller.getSnapshot()));
  await h.controller.cancel();assert.equal(calls,2);assert.equal(h.controller.getSnapshot().status.operation.phase,'terminal');assert.equal(h.controller.getSnapshot().blocked,true);
 }finally{h.controller.dispose();}
});

test('a valid iOS input review never becomes a Play preparation from matching common fields',async()=>{
 const {parseLocalHistoryStatus}=await import('../src/localReleaseHistoryProtocol.ts');
 const h=history(),value=h.status.operation.result.candidateInputs;
 delete value.applicationId;value.bundleId='org.example.app';value.files[0].fileName='export/App.ipa';
 value.archive={directory:'archive.xcarchive',entries:4,bytes:500,sha256:'e'.repeat(64)};
 h.status.operation.context.platform='ios';assert.ok(parseLocalHistoryStatus(h.status));
 assert.equal(localStorePrepareRequest(project(),assets(),h),null);
 const controller=new LocalStorePrepareController({project,assets,history:()=>h,otherOperationReason:()=>null});
 try{controller.syncProject();assert.equal(controller.getSnapshot().request,null);assert.equal(controller.getSnapshot().applicationId,null);}finally{controller.dispose();}
});

function iosAssets(){const a=assets();a.scope.platform='ios';a.status.context.platform='ios';a.status.assignments[0].kind=a.status.records[0].kind='asc-p8';return a;}
function iosHistory(){const h=history(),v=h.status.operation.result.candidateInputs;delete v.applicationId;v.bundleId='org.example.ios-app';v.files[0].fileName='export/App.ipa';v.archive={directory:'archive.xcarchive',entries:4,bytes:500,sha256:'e'.repeat(64)};h.status.operation.context.platform='ios';return h;}
function iosComplete(o){const c=complete(o),v=c.result.preparedIntent;delete v.applicationId;v.bundleId='org.example.ios-app';v.appStoreAppId='0012345';v.destination={channel:'testflight-internal'};v.limitations[2]='current-asc-snapshot-may-change';c.result.scope='local-ios-store-prepare';return c;}
test('iOS Prepare needs matching current iOS review, ASC assignment and saved inputs; IPC is explicitly scoped',async()=>{
 const request=localStorePrepareRequest(project(),iosAssets(),iosHistory());assert.ok(request);assert.equal(request.platform,'ios');assert.equal(request.confirmation,'candidate:ios:1.2.3:42');
 const calls=[],api=createNativeApi('native',async(command,body)=>{calls.push([command,body]);return status();},async()=>()=>{});
 await api.prepareLocalStorePrepare(request);assert.equal(calls[0][0],'prepare_local_store_prepare');assert.ok(calls[0][1] instanceof Uint8Array);assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0][1])),copy(request));
 for(const mutate of [(_p,a)=>a.status.assignments[0].kind='google-service-account',(_p,a)=>a.status.records[0].kind='google-service-account',(_p,a)=>a.scope.platform='android',(_p,a)=>a.status.context.stage='production',(_p,a)=>a.status.assignments[0].recordRevision++,(_p,_a,h)=>delete h.status.operation.context.platform,(_p,_a,h)=>h.historical=true,(_p,_a,h)=>h.status.operation.result.candidateInputs=candidate(),p=>p.savedVersion.build++]){
  const p=project(),a=iosAssets(),h=iosHistory();mutate(p,a,h);assert.equal(localStorePrepareRequest(p,a,h),null);
 }
 for(const extra of [{platform:undefined},{platform:null},{platform:'android'},{confirmation:'candidate:android:1.2.3:42'},{authorizationId:UUID}])assert.equal(encodeLocalStorePrepareRequest('prepare_local_store_prepare',{...request,...extra}),null);
});
test('iOS prepared12 result is exact platform-bound DATA and preserves decimal app ID spelling',()=>{
 const request=localStorePrepareRequest(project(),iosAssets(),iosHistory()),good=iosComplete(op(request));assert.ok(parseLocalStorePrepareStatus(status(1,good)));assert.equal(parseLocalStorePrepareStatus(status(1,good)).operation.result.preparedIntent.appStoreAppId,'0012345');
 for(const mutate of [v=>v.context.platform='android',v=>v.result.scope='local-android-store-prepare',v=>v.result.headSequence=4,v=>v.result.preparedIntent.applicationId='org.example.app',v=>delete v.result.preparedIntent.appStoreAppId,v=>v.result.preparedIntent.appStoreAppId=123,v=>v.result.preparedIntent.appStoreAppId='1'.repeat(21),v=>v.result.preparedIntent.appStoreAppId='１２',v=>v.result.preparedIntent.bundleId='org._bad',v=>v.result.preparedIntent.bundleId='1org.app',v=>v.result.preparedIntent.destination.releaseStatus='completed',v=>v.result.preparedIntent.limitations[2]='temporary-edit-may-expire',v=>v.result.preparedIntent.observedAt='2026-02-30T20:00:00Z',v=>v.result.preparedIntent.version.build++,v=>v.result.preparedIntent.candidateSha256='d'.repeat(64),v=>v.result.preparedIntent.operationId='99999999-1234-4234-8234-123456789abc',v=>v.phase='running']){
  const bad=copy(good);mutate(bad);assert.equal(parseLocalStorePrepareStatus(status(1,bad)),null);
 }
 const zero=copy(good);zero.result.preparedIntent.appStoreAppId='0';assert.ok(parseLocalStorePrepareStatus(status(1,zero)));
 const android=complete(op(localStorePrepareRequest(project(),assets(),history())));android.result.preparedIntent=copy(good.result.preparedIntent);assert.equal(parseLocalStorePrepareStatus(status(1,android)),null);
});
test('same Prepare controller uses distinct iOS consent once, then accepts only its original completed result',async()=>{
 const h=await fixture(true);try{assert.equal(h.controller.prepareReason(),null);assert.equal(h.controller.getSnapshot().applicationId,'org.example.ios-app');await h.controller.prepare();assert.equal(h.controller.getSnapshot().historical,false);h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().start,1);assert.equal(h.counts().cancel,0);const running=h.latest();h.emit(status(running.statusRevision+1,iosComplete(running.operation)));assert.equal(h.controller.getSnapshot().status.operation.result.scope,'local-ios-store-prepare');assert.equal(localStorePrepareOwnerReason(h.controller.getSnapshot()),null);}finally{h.controller.dispose();}
});
test('iOS original consent retires on platform switch, candidate drift, timeout and pending selection',async()=>{
 for(const retire of [h=>h.change((_p,a,s)=>{Object.assign(a,assets());Object.assign(s,history());}),h=>h.change((_p,_a,s)=>s.status.operation.result.candidateInputs.candidateSha256='d'.repeat(64)),h=>h.time(60101),h=>h.controller.setSelectionPending(true)]){
  const h=await fixture(true);try{await h.controller.prepare();h.controller.acknowledge(true);retire(h);await h.controller.start();await Promise.resolve();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);assert.equal(h.controller.getSnapshot().consentUntil,null);}finally{h.controller.dispose();}
 }
 const h=await fixture(true);try{const release=h.defer(),pending=h.controller.prepare();h.controller.setVisible(false);release();await pending;await Promise.resolve();assert.equal(h.counts().start,0);assert.equal(h.counts().cancel,1);}finally{h.controller.dispose();}
});
test('iOS prepared review never becomes Android Execute or Reconcile from matching shared fields',async()=>{
 const {localStoreExecuteRequest}=await import('../src/localStoreExecute.ts');const {localStoreReconcileRequest}=await import('../src/localStoreReconcile.ts');const {parseLocalHistoryStatus}=await import('../src/localReleaseHistoryProtocol.ts');
 const h=iosHistory(),value=iosComplete(op(localStorePrepareRequest(project(),iosAssets(),h))).result.preparedIntent;
 h.status.operation.context.action='review-prepared';h.status.operation.result.headSequence=5;h.status.operation.result.history[0].phase='prepared';delete h.status.operation.result.candidateInputs;h.status.operation.result.preparedIntent={...value,observation:'current-prepared-files-only',priorPrepareFinality:'not-established'};
 assert.ok(parseLocalHistoryStatus(h.status));
 const selection={instance:A,ownerUid:501,catalogGeneration:1,recordSha256:'a'.repeat(64),inventorySha256:'b'.repeat(64),osProviderSha256:'c'.repeat(64)};
 const tools={mode:'native',catalogListening:true,catalogReadPending:false,selectionPending:false,catalogStatus:{schemaVersion:1,statusRevision:1,catalogGeneration:1,operationId:B,availability:'available',phase:'ready',reason:'none',selected:selection,entries:[{instance:A,occupants:3,status:'verified-this-session',versions:{jdkVendor:'Temurin',jdkVersion:'21',gradleVersion:'8.10',agpVersion:'8.7',sdkPlatform:'35',sdkBuildToolsVersion:'35.0.0'},recovery:null,selection}]},status:null};
 const p=project();p.selection={module:'app',variant:'release',applicationId:'dev.example.app'};
 const android=copy(h);delete android.status.operation.context.platform;android.status.operation.result.preparedIntent={...complete(op(localStorePrepareRequest(project(),assets(),history()))).result.preparedIntent,observation:'current-prepared-files-only',priorPrepareFinality:'not-established'};
 assert.ok(localStoreExecuteRequest(p,assets(),android,tools));
 p.selection.applicationId=value.bundleId;
 assert.equal(localStoreExecuteRequest(p,iosAssets(),h,tools).platform,'ios');assert.equal(localStoreExecuteRequest(p,assets(),h,tools),null);
 const reconciled=copy(android);reconciled.status.operation.context.action='review-reconcile';reconciled.status.operation.result.headSequence=6;reconciled.status.operation.result.history[0].phase='execute-pending';p.selection.applicationId='dev.example.app';assert.ok(localStoreReconcileRequest(p,assets(),reconciled));
 assert.equal(localStoreReconcileRequest(p,iosAssets(),reconciled),null);assert.equal(localStoreReconcileRequest(p,iosAssets(),h),null);
});

test('iOS-only workspace reaches Prepare through actual saved-version observation without an Android selection',async()=>{
 const {localStoreProjectObservation}=await import('../src/localStorePreflight.ts');const {ReleaseVersionController}=await import('../src/releaseVersion.ts');const {initialWorkspace,workspaceReducer}=await import('../src/drafts.ts');const {AndroidBuildController}=await import('../src/androidBuild.ts');
 const assurance={basis:'static-text',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'},config={bytes:100,sha256:'a'.repeat(64)},source='release/version.properties';
 const snapshot={root:'/inert/never-opened',observedAt:'',observationScope:'single-request-non-atomic',config:{path:'release/mobile-release.json',state:'format-valid',content:copy(config),issues:[],data:{ios:{enabled:true,bundleId:'org.example.ios-app'},version:{source}}},discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance:copy(assurance),issues:[]};
 let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p1',name:'iOS only',path:'/inert/never-opened'}});workspace=workspaceReducer(workspace,{type:'snapshot-start',projectId:'p1',requestId:1});workspace=workspaceReducer(workspace,{type:'snapshot-done',projectId:'p1',requestId:1,snapshot,observedAt:1});const session=workspace.projects.p1;
 const version=new ReleaseVersionController(()=>session),android=new AndroidBuildController({selectedProject:()=>session,releaseVersion:version.getSnapshot,otherOperationReason:()=>null});
 const observation={schemaVersion:2,source,version:{name:'1.2.3',build:42},savedConfig:copy(config),savedVersion:{bytes:40,sha256:'b'.repeat(64)},observationScope:'single-request-non-atomic',assurance:copy(assurance)};
 version.setConnection({mode:'native',observeReleaseVersion:async()=>copy(observation)},{runtime:{state:'available',mode:'installed',reason:null},capabilities:{methods:[{method:'release.version.observe',available:true,reason:''}]}});version.syncProject();
 const controller=new LocalStorePrepareController({project:()=>localStoreProjectObservation(session,version.getSnapshot()),assets:iosAssets,history:iosHistory,otherOperationReason:()=>null});let latest=status(),starts=0,cancels=0;
 const unlisten=version.subscribe(controller.syncProject);
 try{
  await controller.connect({mode:'native',subscribeLocalStorePrepare:async()=>()=>{},localStorePrepareStatus:async()=>latest,prepareLocalStorePrepare:async request=>{assert.equal(request.platform,'ios');latest=status(1,op(request));return copy(latest);},startLocalStorePrepare:async()=>{starts++;throw Error('must not start after version re-read');},cancelLocalStorePrepare:async()=>{cancels++;latest=status(2,terminal(latest.operation));return copy(latest);}});
  controller.syncProject();assert.equal(controller.getSnapshot().request,null);await version.read();android.syncProject();assert.ok(android.getSnapshot().project.inputIssue);assert.equal(localStorePrepareRequest(android.getSnapshot().project,iosAssets(),iosHistory()),null);
  assert.equal(controller.getSnapshot().request.platform,'ios');assert.equal(controller.getSnapshot().request.confirmation,'candidate:ios:1.2.3:42');assert.equal(controller.prepareReason(),null);
  await controller.prepare();controller.acknowledge(true);await version.read();await Promise.resolve();await controller.start();assert.equal(starts,0);assert.equal(cancels,1);assert.equal(controller.getSnapshot().consentUntil,null);
 }finally{unlisten();controller.dispose();version.dispose();android.dispose();}
});
