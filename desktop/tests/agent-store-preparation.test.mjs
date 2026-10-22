// Real public codecs/controllers with inert DATA and retained promises only.
// No IPC, credentials, Store, native admission, synthetic joins or UI automation.
import assert from 'node:assert/strict';
import test from 'node:test';
import {parseStorePreparationInput,storePreparationInput,storePreparationSelection,parseStorePreparationStatus,parseStorePreparationAccess,createStorePreparationPort,storePreparationCommands,storePreparationPeerReason,storePreparationStage,storePreparationPreparesIntent,storePreparationExecutesCandidate,storePreparationNativeOperation,storePreparationKinds,storePreparationConsent,storePreparationRelease,storePreparationLifecycleEffect} from '../src/agentStorePreparation.ts';
import {StorePreparationController} from '../src/agentStorePreparationController.ts';
import {LocalStorePreflightController,localStoreOwnerReason} from '../src/localStorePreflight.ts';
import {LocalStorePrepareController,localStorePrepareOwnerReason} from '../src/localStorePrepare.ts';
import {LocalStoreExecuteController,localStoreExecuteOwnerReason} from '../src/localStoreExecute.ts';
import {parseLocalStoreExecuteRequest} from '../src/localStoreExecuteProtocol.ts';
import {storeReleaseLimitations,storeReleaseTarget,storeReleaseFromContext} from '../src/agentStoreRelease.ts';
import {LocalStoreReconcileController,localStoreReconcileOwnerReason} from '../src/localStoreReconcile.ts';
import {parseLocalStoreReconcileRequest,reconcileRequestContext} from '../src/localStoreReconcileProtocol.ts';
import {STAGE_PREPARE_LIMITS,STAGE_EXECUTE_LIMITS,nativeStageOperationId} from '../src/localStoreStageProtocol.ts';
import {parseLocalHistoryStatus} from '../src/localReleaseHistoryProtocol.ts';
const id=c=>c.repeat(32),A=id('a'),B=id('b'),P=id('1'),S=id('2'),G=id('3'),R=id('4'),Q=id('5'),START=id('6'),H='c'.repeat(64),UUID='12345678-1234-4234-8234-123456789abc';
const clone=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:H},savedVersion:{bytes:40,sha256:H,source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false,versionPlatforms:['android','ios']});
function assets(platform='android') { const scope={executionMode:'local',platform,stage:'candidate',purpose:platform==='both'?'version-inventory':'store'},pairs=platform==='both'?[['google-service-account',R],['asc-p8',A]]:[[platform==='ios'?'asc-p8':'google-service-account',R]];
 return {mode:'native',scope,contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',...scope},operation:null,assignments:pairs.map(([kind,recordId])=>({kind,recordId,recordRevision:4,contextRevision:3,availability:'available'})),records:pairs.map(([kind,recordId])=>({kind,recordId,revision:4,availability:'assigned'}))}};
}
const nativeStatus=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const history=()=>({mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:nativeStatus(1,{operationId:R,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-inputs',candidateOperationId:UUID},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:3,history:[{operationId:UUID,phase:'inputs-ready',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],candidateInputs:{operationId:UUID,candidateSha256:H,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},files:[{fileName:'app-release.aab',bytes:100,sha256:H},{fileName:'store-metadata.zip',bytes:100,sha256:H},{fileName:'validation-report.json',bytes:100,sha256:H}],observation:'current-bundle-only',priorCreateFinality:'not-established'}}})});
function iosHistory(){const h=history(),v=h.status.operation.result.candidateInputs;delete v.applicationId;v.bundleId='org.example.ios-app';v.files[0].fileName='export/App.ipa';v.archive={directory:'archive.xcarchive',entries:4,bytes:500,sha256:H};h.status.operation.context.platform='ios';return h;}
const STAGES=['android-external-testing','ios-external-testing','android-production-submit','ios-production-submit'];
const UPLOADS=['android-candidate-upload','ios-candidate-upload'];
const LIFECYCLE=['android-external-testing-execute','ios-external-testing-execute','android-production-submit-execute','ios-production-submit-execute','android-current-internal','ios-current-internal','android-recovery-settlement','ios-external-readiness'];
const EXTERNAL='22345678-1234-4234-8234-123456789abc',PRODUCTION='32345678-1234-4234-8234-123456789abc';
function uploadFixture(kind){
 const ios=kind.startsWith('ios'),saved={...project(),...(ios?{}:{selection:{module:'app',variant:'release',applicationId:'dev.example.app'}})},selected=assets(ios?'ios':'android');
 const preparedIntent={operationId:UUID,candidateSha256:H,intentSha256:'d'.repeat(64),storePreconditionSha256:'e'.repeat(64),sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),
  ...(ios?{bundleId:'org.example.ios-app',appStoreAppId:'0012345'}:{applicationId:'dev.example.app'}),version:{name:'1.2.3',build:42},destination:ios?{channel:'testflight-internal'}:{channel:'internal',releaseStatus:'completed'},
  observedAt:'2026-10-16T20:00:00Z',limitations:['non-publishing','prepare-not-execute',ios?'current-asc-snapshot-may-change':'temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic'],observation:'current-prepared-files-only',priorPrepareFinality:'not-established'};
 const currentHistory={mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:nativeStatus(1,{operationId:R,ownerGeneration:B,
  context:{projectId:'p1',executionMode:'local',action:'review-prepared',candidateOperationId:UUID,...(ios?{platform:'ios'}:{})},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',
  result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:5,history:[{operationId:UUID,phase:'prepared',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],preparedIntent}})};
 const selection={instance:A,ownerUid:501,catalogGeneration:1,recordSha256:'a'.repeat(64),inventorySha256:'b'.repeat(64),osProviderSha256:'c'.repeat(64)};
 const tools=ios?null:{mode:'native',catalogListening:true,catalogReadPending:false,selectionPending:false,catalogStatus:{schemaVersion:1,statusRevision:1,catalogGeneration:1,operationId:B,availability:'available',phase:'ready',reason:'none',selected:clone(selection),
  entries:[{instance:A,occupants:3,status:'verified-this-session',versions:{jdkVendor:'Temurin',jdkVersion:'21',gradleVersion:'8.10',agpVersion:'8.7',sdkPlatform:'35',sdkBuildToolsVersion:'35.0.0'},recovery:null,selection:clone(selection)}]},status:null};
 return{saved,selected,currentHistory,tools};
}
// Same current source/assigned-record/history DATA shape as the original stage
// controller fixtures. These values never stand in for native authentication.
function stageFixture(kind) {
 const stage=storePreparationStage(kind),platform=kind.startsWith('ios')?'ios':'android',production=stage==='production-submit';
 const saved={...project(),iosDemoRequired:false},selected=assets(platform);
 selected.scope.stage=production?'production':'external-testing';selected.status.context.stage=selected.scope.stage;
 if(platform==='ios')for(const [recordKind,c] of [['apple-review-contact','e'],['operation-commitment','f']]){
  selected.status.assignments.push({kind:recordKind,recordId:id(c),recordRevision:4,contextRevision:3,availability:'available'});
  selected.status.records.push({kind:recordKind,recordId:id(c),revision:4,availability:'assigned'});
 }
 const receipt={operationId:production?EXTERNAL:UUID,candidateSha256:H,intentSha256:'d'.repeat(64),receiptSha256:'f'.repeat(64),authorizationId:'42345678-1234-4234-8234-123456789abc',
  sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),version:{name:'1.2.3',build:42},observedAt:'2026-10-17T00:00:00Z',result:'accepted',
  observation:'current-execution-files-only',priorExecutionFinality:'not-established',
  limitations:production?[...STAGE_EXECUTE_LIMITS]:['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic'],
  ...(platform==='ios'?{bundleId:'org.example.ios-app',appStoreAppId:'0012345',destination:{channel:production?'testflight-external':'testflight-internal'}}:
   {applicationId:'dev.example.app',destination:{channel:production?'Closed testing team':'internal',releaseStatus:'completed'}}),
  ...(production?{stage:'external-testing',candidateOperationId:UUID,predecessorOperationId:UUID,predecessorReceiptSha256:'e'.repeat(64),state:'available-to-testers'}:{})};
 const context={projectId:'p1',executionMode:'local',...(production?{platform,action:'review-stage-execution',stageOperationId:EXTERNAL}:{action:'review-execution',candidateOperationId:UUID,...(platform==='ios'?{platform}:{})})};
 const currentHistory={mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:nativeStatus(1,{operationId:R,ownerGeneration:B,context,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',
  result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:production?11:7,history:[{operationId:UUID,phase:'settled-success',recoveryRequired:false},...(production?[{operationId:EXTERNAL,phase:'settled-success',recoveryRequired:false}]:[])],
   limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],executionReceipt:receipt}})};
 return{saved,selected,currentHistory};
}
// Reuse the same parsed current History/source shapes as the original lifecycle
// controllers. No fixture receipt is a native retirement or provider witness.
function lifecycleFixture(kind){
 const r=storePreparationRelease(kind);assert.ok(r);
 if(r.kind==='execute'){
  const intentKind=kind.replace(/-execute$/,''),f=stageFixture(intentKind),p=f.currentHistory.status.operation.result.executionReceipt;
  const stage=r.mode,operationId=stage==='external-testing'?EXTERNAL:PRODUCTION;
  const prepared={operationId,stage,candidateOperationId:UUID,candidateSha256:H,predecessorOperationId:p.operationId,predecessorReceiptSha256:p.receiptSha256,
   intentSha256:'d'.repeat(64),storePreconditionSha256:'e'.repeat(64),sourceCommit:p.sourceCommit,sourceTree:p.sourceTree,version:p.version,observedAt:p.observedAt,
   limitations:[...STAGE_PREPARE_LIMITS],observation:'current-prepared-files-only',priorPrepareFinality:'not-established',
   ...(r.platform==='ios'?{bundleId:p.bundleId,appStoreAppId:p.appStoreAppId,destination:stage==='external-testing'?{channel:'testflight-external'}:{channel:'app-store-review',automaticRelease:false}}:
    {applicationId:p.applicationId,destination:stage==='external-testing'?{channel:'Closed testing team',releaseStatus:'completed'}:{channel:'production',releaseStatus:'draft'}})};
  const old=f.currentHistory.status.operation;
  f.currentHistory.status=nativeStatus(1,{...old,context:{projectId:'p1',executionMode:'local',platform:r.platform,action:'review-stage-prepared',stageOperationId:operationId},
   result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:stage==='external-testing'?9:13,
    history:[...old.result.history,{operationId,phase:'prepared',recoveryRequired:true}],limitations:old.result.limitations,preparedIntent:prepared}});
  return f;
 }
 if(r.mode==='external-readiness'){
  const f=stageFixture('ios-production-submit');f.selected.scope.stage='external-testing';f.selected.status.context.stage='external-testing';return f;
 }
 const f=uploadFixture(`${r.platform}-candidate-upload`),op=f.currentHistory.status.operation;
 op.context.action='review-reconcile';op.result.headSequence=6;op.result.history[0].phase='execute-pending';f.tools=null;return f;
}
const input=(kind='android-access')=>{if(storePreparationRelease(kind)||storePreparationExecutesCandidate(kind)||storePreparationStage(kind)){const f=storePreparationRelease(kind)?lifecycleFixture(kind):storePreparationExecutesCandidate(kind)?uploadFixture(kind):stageFixture(kind);return storePreparationInput(kind,f.saved,f.selected,f.currentHistory,f.tools??null);}return storePreparationInput(kind,project(),assets(kind.startsWith('ios')?'ios':kind==='paired-versions'?'both':'android'),kind==='ios-candidate'?iosHistory():history());};
const review=()=>({reviewId:A,operation:{operationId:A,ownerGeneration:B,statusRevision:3}});
const stageReview=kind=>{const operationId=(storePreparationStage(kind)==='production-submit'?PRODUCTION:EXTERNAL).replaceAll('-','');return{reviewId:operationId,operation:{operationId,ownerGeneration:B,statusRevision:3}};};
const origin=()=>({projectId:P,serviceInstance:S,requestId:Q});
const status=(kind='android-access',more={})=>{const r=storePreparationStage(kind)?stageReview(kind):review();return{schemaVersion:1,origin:origin(),prepareGrantId:G,selectionId:R,revision:4,selection:storePreparationSelection(input(kind)),phase:'prepared',settlement:'pending',reason:'none',prepared:r,operation:r.operation,startGrantId:null,prepareReturned:true,startSubmitted:false,outcome:null,result:null,doNotReplay:true,...more};};
const empty=()=>({permissionRevision:'0',schemaVersion:1,serviceInstance:null,projectId:null,permission:null,grantId:null,reviewId:null,selection:null,requestId:null,enabled:false,consumed:false,pending:false,unknown:false,remainingMs:0,status:null});
const granted=(kind='android-access')=>({permissionRevision:'1',schemaVersion:1,serviceInstance:S,projectId:P,permission:'prepare',grantId:G,reviewId:R,selection:storePreparationSelection(input(kind)),requestId:null,enabled:true,consumed:false,pending:false,unknown:false,remainingMs:290000,status:null});
function observed(s,armed=false){return {permissionRevision:s.startGrantId?'2':'1',schemaVersion:1,serviceInstance:S,projectId:P,permission:s.startGrantId?'start':'prepare',grantId:s.startGrantId??G,reviewId:s.startGrantId?s.prepared.reviewId:R,selection:s.selection,requestId:s.origin.requestId,enabled:armed,consumed:s.startGrantId?s.startSubmitted:true,pending:s.settlement!=='settled',unknown:s.phase==='unknown',remainingMs:armed?280000:0,status:s};}
const ios=()=>({observation:'observed',coverage:'asc-ios-current-inventory/1',revision:H,counts:{builds:0,buildUploads:0,appStoreVersions:1},maxBuild:0,marketingVersion:'2.0.0',historicalUniqueness:'not-established'});
const android=()=>({observation:'observed',coverage:'play-android-current-inventory/1',revision:H,counts:{tracks:2,releases:2,versionCodes:3,bundles:0,apks:1},maxBuild:40,marketingVersion:null,temporaryEdit:'deleted',historicalUniqueness:'not-established'});
const uploadResult=kind=>({kind:'ordinary',report:{kind:'execute',release:{mode:'candidate-upload',headSequence:7,operationId:UUID,candidateOperationId:UUID,candidateSha256:H,intentSha256:'d'.repeat(64),receiptSha256:'e'.repeat(64),basis:null,target:kind.startsWith('ios')?'testflight-internal':'play-internal',result:'accepted',state:null,limitations:[...storeReleaseLimitations('candidate-upload')]}}});
const lifecycleResult=kind=>{const r=storePreparationRelease(kind),s=storePreparationSelection(input(kind)),{stageOperationId,...release}=s.release;return{kind:'ordinary',report:{kind:r.kind,release:{...release,headSequence:({
 'external-testing':11,'production-submit':15,'current-internal':6,'recovery-settlement':7,'external-readiness':12})[r.mode],operationId:stageOperationId??s.candidate.operationId,candidateOperationId:s.candidate.operationId,candidateSha256:s.candidate.sha256,receiptSha256:'e'.repeat(64),target:storeReleaseTarget(r.mode,r.platform),
 result:r.kind==='execute'?'accepted':r.mode==='external-readiness'?'ready':'reconciled',state:r.mode==='external-readiness'?'available-to-testers':r.kind==='reconcile'?null:r.platform==='ios'?'submitted-for-review':r.mode==='production-submit'?'draft':'available-to-testers',limitations:[...storeReleaseLimitations(r.mode)]}}};};
const result=(kind='android-access')=>storePreparationRelease(kind)?lifecycleResult(kind):storePreparationExecutesCandidate(kind)?uploadResult(kind):kind.endsWith('-versions')?{kind:'current-versions',inventory:kind==='paired-versions'?{platform:'both',android:android(),ios:ios()}:kind==='ios-versions'?{platform:'ios',current:ios()}:{platform:'android',current:android()}}:{kind:'ordinary',report:{kind:'access-check',findings:[{check:'store-access',status:'FAIL'}],limitations:['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic']}};
const final=(kind='android-access')=>status(kind,{revision:9,phase:'final',settlement:'settled',operation:{...review().operation,statusRevision:8},startGrantId:START,startSubmitted:true,outcome:'complete',result:result(kind)});
const stageFinal=kind=>{const s=status(kind),stage=s.selection.later.stage,c=s.selection.candidate,ios=kind.startsWith('ios');return{...s,revision:9,phase:'final',settlement:'settled',operation:{...s.operation,statusRevision:8},startGrantId:START,startSubmitted:true,outcome:'complete',result:{kind:'stage-prepare',report:{platform:ios?'ios':'android',stage,
 operationId:nativeStageOperationId(s.operation.operationId),headSequence:stage==='external-testing'?9:13,candidateOperationId:c.operationId,candidateSha256:c.sha256,...s.selection.later,
 intentSha256:'d'.repeat(64),storePreconditionSha256:'e'.repeat(64),destination:ios?(stage==='external-testing'?{channel:'testflight-external'}:{channel:'app-store-review',automaticRelease:false}):stage==='external-testing'?{channel:'🧪'.repeat(100),releaseStatus:'completed'}:{channel:'production',releaseStatus:'draft'},limitations:[...STAGE_PREPARE_LIMITS]}}};};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
function harness(kind='android-access') {
 const calls=[],method=kind=>(...args)=>{const d=deferred();calls.push({kind,args,...d});return d.promise;};
 const port={status:method('status'),allowPrepare:method('prepare'),allowStart:method('start'),revoke:method('revoke')};let now=100;
 let context={port,nativeSession:{},epoch:{},projectId:'p1',preview:false,input:input(kind),blockedReason:null};
 const controller=new StorePreparationController({current:()=>context,now:()=>now});controller.choose(kind);
 return {controller,calls,port,set:v=>context={...context,...v},time:v=>now=v,last:k=>calls.filter(v=>v.kind===k).at(-1)};
}
async function allow(h,kind='android-access'){if(!h.controller.getSnapshot().access)await check(h,empty());assert.equal(h.controller.acknowledge(true),true);const p=h.controller.allow();h.last('prepare').resolve(granted(kind));await p;}
async function check(h,v){const p=h.controller.status();h.last('status').resolve(v);await p;}

test('seven inputs use actual saved request parsers; Both requires same live two-record context',()=>{
 for(const k of ['android-access','ios-access','android-candidate','ios-candidate','android-versions','ios-versions','paired-versions'])assert.ok(input(k),k);
 const both=input('paired-versions');assert.equal(both.prepare.platform,'both');assert.equal(both.prepare.iosRecord.recordId,A);
 for(const change of [v=>v.status.assignments[1].contextRevision++,v=>v.status.records[0].revision++,v=>v.status.assignments.pop(),v=>v.scope.purpose='store']){const a=assets('both');change(a);assert.equal(storePreparationInput('paired-versions',project(),a,null),null);}
 assert.equal(storePreparationInput('paired-versions',{...project(),versionPlatforms:['android']},assets('both'),null),null);
 assert.equal(storePreparationInput('android-versions',project(),assets('both'),null),null);
 assert.equal(storePreparationInput('android-access',{...project(),dirtyDraft:true},assets(),null),null);
 for(const patch of [{kind:'execute'},{kind:'paired-versions'},{token:'forbidden'}])assert.equal(parseStorePreparationInput({...input(),...patch}),null);
 const candidate=input('android-candidate');assert.ok(candidate);const stage=clone(candidate);stage.prepare.stage='external';assert.equal(parseStorePreparationInput(stage),null);
});
test('fixed port emits only original typed Prepare and a later separately consented Start',async()=>{
 const calls=[],p=createStorePreparationPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null;});
 await p.allowPrepare(input('paired-versions'),'0');assert.equal(calls[0][0],'allow_agent_store_prepare');assert.equal(calls[0][1].consentVersion,'agent-store-native-prepare-once-v1');assert.deepEqual(calls[0][1].prepare,clone(input('paired-versions').prepare));
 await p.allowStart(status('paired-versions'),'1');assert.equal(calls[1][0],'allow_agent_store_preparation_start');assert.equal(calls[1][1].consentVersion,'agent-paired-current-versions-edit-once-v1');assert.deepEqual(Object.keys(calls[1][1]).sort(),['consentVersion','expectedPermissionRevision','origin','review']);
 await assert.rejects(p.allowStart(status('paired-versions',{prepareReturned:false})));await assert.rejects(p.allowStart(status('paired-versions',{startGrantId:START})));assert.equal(calls.length,2);
});
test('required-null closure and exact permission phase/grant correlations reject cross-use',()=>{
 assert.ok(parseStorePreparationAccess(granted()));assert.ok(parseStorePreparationAccess(observed(status())));
 const armed=observed(status('android-access',{revision:5,startGrantId:START}),true);assert.ok(parseStorePreparationAccess(armed));
 for(const change of [v=>delete v.status.startGrantId,v=>v.permission='prepare',v=>v.grantId=G,v=>v.status.prepareReturned=false,v=>v.consumed=true,v=>v.pending=false,v=>v.status.privateKey='forbidden']){const v=clone(armed);change(v);assert.equal(parseStorePreparationAccess(v),null);}
 const missing=status();delete missing.result;assert.equal(parseStorePreparationStatus(missing),null);
 assert.equal(parseStorePreparationStatus({...final(),operation:null}),null);
});
test('current summaries are typed DATA; inconclusive complete is not fabricated observed inventory',()=>{
 for(const kind of ['android-versions','ios-versions','paired-versions'])assert.ok(parseStorePreparationStatus(final(kind)));
 const partial=final('paired-versions');partial.result.inventory.android={observation:'temporary-edit-unconfirmed',coverage:'play-android-current-inventory/1',revision:null,counts:null,maxBuild:null,marketingVersion:null,temporaryEdit:'unconfirmed',historicalUniqueness:'not-established'};
 const parsed=parseStorePreparationStatus(partial);assert.ok(parsed);assert.equal(parsed.result.inventory.android.observation,'temporary-edit-unconfirmed');
 for(const change of [v=>v.result.inventory.android.temporaryEdit='unconfirmed',v=>v.result.inventory.ios.counts.builds=401,v=>delete v.result.inventory.ios,v=>v.selection.kind='android-versions',v=>v.result.inventory.authorizesReservation=true]){const v=final('paired-versions');change(v);assert.equal(parseStorePreparationStatus(v),null);}
 const failedFinding=parseStorePreparationStatus(final());assert.equal(failedFinding.result.report.findings[0].status,'FAIL');
});
test('Prepare permission alone never starts or manufactures a returned native Prepared',async()=>{
 const h=harness();await allow(h);assert.deepEqual(h.calls.map(v=>v.kind),['status','prepare']);assert.ok(h.controller.allowReason());
 await check(h,observed(status('android-access',{phase:'preparing',prepareReturned:false})));assert.ok(h.controller.consentReason());assert.equal(await h.controller.allow(),false);
 await check(h,observed(status('android-access',{revision:5})));assert.equal(h.controller.consentReason(),null);assert.equal(h.controller.acknowledge(true),true);
 const p=h.controller.allow();assert.equal(h.last('start').args[0].prepared.reviewId,A);assert.equal(h.calls.filter(c=>c.kind==='prepare').length,1);
 h.last('start').resolve(observed(status('android-access',{revision:6,startGrantId:START}),true));await p;assert.ok(h.controller.allowReason());
 assert.match(storePreparationCommands(h.controller.getSnapshot().access)[0],/^mrk store-start /);
});
test('cold status cannot recreate Start authority even with identical prepared IDs',async()=>{
 const h=harness();await check(h,observed(status()));assert.match(h.controller.consentReason(),/not the current returned preparation/);assert.equal(h.controller.acknowledge(true),false);assert.equal(await h.controller.allow(),false);
});
test('original Allow return is retained through native-looking status and disposal',async()=>{
 const h=harness();await check(h,empty());h.controller.acknowledge(true);const p=h.controller.allow();let returned=false;const wait=h.controller.whenSettled().then(()=>returned=true);
 assert.equal(await h.controller.status(),false);await flush();assert.equal(returned,false);assert.ok(h.controller.ownerReason());
 h.controller.dispose();h.last('prepare').resolve(observed(status()));await p;await wait;assert.equal(returned,true);assert.equal(h.controller.getSnapshot().access.grantId,null);assert.deepEqual(h.calls.map(v=>v.kind),['status','prepare']);
});
test('listener reentry before invocation prevents a stale Prepare or Start',async()=>{
 for(const start of [false,true]){const h=harness();if(start){await allow(h);await check(h,observed(status()));}else await check(h,empty());
  h.controller.acknowledge(true);const remove=h.controller.subscribe(()=>{if(h.controller.getSnapshot().pending)h.set({epoch:{}});});
  assert.equal(await h.controller.allow(),false);remove();assert.equal(h.calls.filter(c=>c.kind=== (start?'start':'prepare')).length,start?0:0);
 }
});
test('lost Prepare/Start replies retain original IDs and forbid replay despite later success DATA',async()=>{
 for(const start of [false,true]){const h=harness();if(start){await allow(h);await check(h,observed(status()));}else await check(h,empty());h.controller.acknowledge(true);const p=h.controller.allow();h.last(start?'start':'prepare').reject(Error('inert lost original reply'));await p;
  assert.equal(h.controller.getSnapshot().unknown,true);await check(h,observed(final()));assert.equal(h.controller.getSnapshot().unknown,true);assert.equal(await h.controller.allow(),false);
 }
});
test('Revoke can run while Allow returns but its generation prevents late rearming',async()=>{
 const h=harness();await check(h,empty());h.controller.acknowledge(true);const p=h.controller.allow(),stop=h.controller.revoke();let finished=false;const wait=h.controller.whenSettled().then(()=>finished=true);
 h.last('revoke').resolve({...granted(),enabled:false,remainingMs:0});await stop;await flush();assert.equal(finished,false);
 h.last('prepare').resolve(granted());await p;await wait;assert.equal(h.controller.getSnapshot().access.enabled,false);assert.equal(h.controller.peer(),null);assert.ok(h.controller.consentReason());
});
test('context/port drift retains original controls and requires fresh explicit consent',async()=>{
 const h=harness();await allow(h);await check(h,observed(status()));h.set({epoch:{},nativeSession:{},port:{status(){assert.fail('replacement status');},allowPrepare(){assert.fail('replacement prepare');},allowStart(){assert.fail('replacement start');},revoke(){assert.fail('replacement revoke');}}});h.controller.syncContext();assert.ok(h.controller.allowReason());
 await check(h,observed(status('android-access',{revision:5})));const p=h.controller.revoke();h.last('revoke').resolve(observed(status('android-access',{revision:6,phase:'stopping',reason:'permission-revoked'})));await p;assert.equal(h.controller.getSnapshot().stale,true);
});
test('equal original countdown only decreases and old grant/status cannot reopen it',async()=>{
 const h=harness();await allow(h);h.time(1100);await check(h,{...granted(),remainingMs:290000});assert.equal(h.controller.remainingSeconds(),289);
 h.time(2000);await check(h,observed(status()));const changed=observed(status());changed.status.revision=3;await check(h,changed);assert.equal(h.controller.getSnapshot().unknown,true);
});
test('real final triple-cut projection permits a new explicit Prepare, not automatic replay',async()=>{
 const h=harness();await allow(h);await check(h,observed(status()));await check(h,observed(final()));assert.equal(h.controller.ownerReason(),null);assert.equal(h.calls.filter(c=>c.kind==='prepare').length,1);
 assert.equal(h.controller.acknowledge(true),true);const p=h.controller.allow();h.last('prepare').resolve({...granted(),permissionRevision:'3',grantId:id('7'),reviewId:id('8')});await p;assert.equal(h.controller.getSnapshot().unknown,false);assert.equal(h.calls.filter(c=>c.kind==='prepare').length,2);
});

async function mounted(kind='android-access'){
 const domain=storePreparationRelease(kind),upload=storePreparationExecutesCandidate(kind)||domain?.kind==='execute',reconcile=domain?.kind==='reconcile',{saved,selected,currentHistory,tools}=domain?lifecycleFixture(kind):upload?uploadFixture(kind):storePreparationStage(kind)?stageFixture(kind):{saved:project(),selected:assets(),currentHistory:history()};let latest=nativeStatus(),listener,permission=null;const calls=[];
 const candidate=storePreparationPreparesIntent(kind),source={project:()=>saved,assets:()=>selected,history:()=>currentHistory,tools:()=>tools??null,otherOperationReason:()=>permission?.ownerReason()??null,now:()=>100};
 const original=reconcile?new LocalStoreReconcileController(source):upload?new LocalStoreExecuteController(source):candidate?new LocalStorePrepareController(source):new LocalStorePreflightController(source);
 const suffix=reconcile?'LocalStoreReconcile':upload?'LocalStoreExecute':candidate?'LocalStorePrepare':'LocalStorePreflight';let pendingPrepare=null;
 const api={mode:'native',[`subscribe${suffix}`]:async f=>{listener=f;return()=>{};},[suffix[0].toLowerCase()+suffix.slice(1)+'Status']:async()=>clone(latest),[`prepare${suffix}`]:async()=>{calls.push('gui-prepare');return pendingPrepare?.promise??clone(latest);},[`start${suffix}`]:async()=>{calls.push('gui-start');return clone(latest);},[`cancel${suffix}`]:async()=>{calls.push('gui-cancel');return clone(latest);}};
 await original.connect(api);original.syncProject();if(domain?.mode==='recovery-settlement')assert.equal(original.setSettlement(true),true);if(domain?.mode==='external-readiness')assert.equal(original.setExternalReadiness(true),true);const h=harness(kind);const epoch={},nativeSession={};
 permission=new StorePreparationController({current:()=>{const peer=permission?.peer(),reason=reconcile?localStoreReconcileOwnerReason(original.getSnapshot()):upload?localStoreExecuteOwnerReason(original.getSnapshot()):candidate?localStorePrepareOwnerReason(original.getSnapshot()):localStoreOwnerReason(original.getSnapshot());return{port:h.port,epoch,nativeSession,projectId:'p1',preview:false,input:storePreparationInput(kind,saved,selected,currentHistory,tools??null),blockedReason:storePreparationPeerReason(peer?.input??null,peer?.review??null,original.getSnapshot(),reason)};},now:()=>100});permission.choose(kind);h.controller=permission;
 return{...h,original,callsNative:calls,emit:()=>{const request=input(kind).prepare,r=storePreparationStage(kind)?stageReview(kind):review();latest=nativeStatus(3,{operationId:r.operation.operationId,ownerGeneration:B,context:reconcile?reconcileRequestContext(request):{...clone(request),platform:request.platform??'android',operation:storePreparationNativeOperation(kind)},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});listener(clone(latest));},defer:()=>pendingPrepare=deferred(),close:()=>{original.dispose();permission.dispose();}};
}
test('actual two-controller composition permits only same service-created Prepared; GUI has no Attempt or timer',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['android-access','android-candidate']){const h=await mounted(kind);await allow(h,kind);h.emit();assert.ok(h.original.getSnapshot().status.operation);await check(h,observed(status(kind)));
  assert.equal(h.controller.consentReason(),null);assert.equal(h.original.canStart? h.original.canStart():false,false);assert.deepEqual(h.callsNative,[]);h.original.setVisible(false);t.mock.timers.tick(300001);await flush();assert.deepEqual(h.callsNative,[]);
  assert.equal(h.controller.acknowledge(true),true);const p=h.controller.allow();h.last('start').resolve(observed(status(kind,{revision:5,startGrantId:START}),true));await p;assert.deepEqual(h.callsNative,[]);h.close();
 }
});
test('same-looking prepared DATA cannot bypass an actual GUI pending caller or a foreign context',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const h=await mounted();const d=h.defer();const pending=h.original.prepare();h.emit();assert.ok(h.original.getSnapshot().pending);
 const snap=h.original.getSnapshot();assert.equal(storePreparationPeerReason(input(),review(),snap,'busy'),'busy');
 d.resolve(nativeStatus(4,snap.status.operation));await pending;
 const safe={...h.original.getSnapshot(),pending:null,callersPending:0,acknowledged:false,consentUntil:null,blocked:false,unconfirmed:false};
 assert.equal(storePreparationPeerReason(input(),review(),safe,'busy'),null);const foreign=clone(safe);foreign.status.operation.context.recordRevision++;assert.equal(storePreparationPeerReason(input(),review(),foreign,'busy'),'busy');h.close();
});

// A current-looking row with the same public input is still a different grant.
test('unused original Prepare grant cannot adopt a foreign same-input preparation',async()=>{
 const h=harness();await allow(h);
 const foreign=status('android-access',{prepareGrantId:id('7'),selectionId:id('8')});
 const access={...observed(foreign),grantId:id('7'),reviewId:id('8')};
 assert.ok(parseStorePreparationAccess(access));await check(h,access);
 assert.equal(h.controller.getSnapshot().unknown,true);assert.equal(h.controller.getSnapshot().access.grantId,G);
 assert.equal(h.controller.peer(),null);assert.equal(h.controller.acknowledge(true),false);assert.equal(await h.controller.allow(),false);
 assert.equal(h.calls.filter(c=>c.kind==='start').length,0);
 // The genuine same-row Prepare -> separately granted Start transition stays usable.
 const same=harness();await allow(same);await check(same,observed(status()));
 assert.equal(same.controller.acknowledge(true),true);const entered=same.controller.allow();
 same.last('start').resolve(observed(status('android-access',{revision:5,startGrantId:START}),true));await entered;
 assert.equal(same.controller.getSnapshot().unknown,false);assert.equal(same.calls.filter(c=>c.kind==='start').length,1);
 h.controller.dispose();same.controller.dispose();
});

test('later four use original current stage/history and actual supplemental assignment policy',()=>{
 for(const kind of STAGES){
  const f=stageFixture(kind);assert.ok(parseLocalHistoryStatus(f.currentHistory.status),kind);
  const v=storePreparationInput(kind,f.saved,f.selected,f.currentHistory);assert.ok(v,kind);assert.ok(storePreparationPreparesIntent(kind));
  const s=storePreparationSelection(v);assert.equal(s.later.stage,storePreparationStage(kind));assert.equal(s.candidate.operationId,UUID);
  assert.equal(s.later.predecessorOperationId,s.later.stage==='external-testing'?UUID:EXTERNAL);
  for(const change of [v=>delete v.prepare.stage,v=>delete v.prepare.platform,v=>delete v.prepare.predecessorReceiptSha256,
   v=>v.prepare.stageOperationId=EXTERNAL,v=>v.kind=kind.startsWith('ios')?'ios-candidate':'android-candidate',v=>v.prepare.confirmation='candidate:android:1.2.3:42']){
    const bad=clone(v);change(bad);assert.equal(parseStorePreparationInput(bad),null);
  }
  for(const change of [f=>f.currentHistory.historical=true,f=>f.saved.savedVersion.build++,f=>f.selected.status.assignments[0].recordRevision++,
   f=>f.currentHistory.status.operation.result.history.at(-1).phase='settled-failure',f=>f.selected.status.context.stage='candidate']){
    const bad=stageFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory),null);
  }
  if(kind.startsWith('ios')){
   for(const change of [f=>delete f.saved.iosDemoRequired,f=>f.saved.iosDemoRequired=true,f=>f.selected.status.assignments.splice(1,1),f=>f.selected.status.records[1].revision++]){
    const bad=stageFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory),null);
   }
   const demo=stageFixture(kind);demo.saved.iosDemoRequired=true;
   demo.selected.status.assignments.push({kind:'apple-review-demo',recordId:id('d'),recordRevision:7,contextRevision:3,availability:'available'});
   demo.selected.status.records.push({kind:'apple-review-demo',recordId:id('d'),revision:7,availability:'assigned'});
   assert.equal(storePreparationInput(kind,demo.saved,demo.selected,demo.currentHistory).prepare.supplementalAssignments.reviewDemo.recordRevision,7);
   demo.saved.iosDemoRequired=false;assert.equal(storePreparationInput(kind,demo.saved,demo.selected,demo.currentHistory),null);
  }
 }
 // Old seven keep no new field, not a newly serialized null default.
 for(const kind of ['android-access','ios-access','android-candidate','ios-candidate','android-versions','ios-versions','paired-versions']){
  const s=status(kind);assert.equal(Object.hasOwn(s.selection,'later'),false);s.selection.later=null;assert.equal(parseStorePreparationStatus(s),null);
 }
});

test('later reports preserve native UUID4 lineage and nonpublishing limits without ordinary cross-use',()=>{
 for(const kind of STAGES){
  const s=stageFinal(kind),parsed=parseStorePreparationStatus(s);assert.ok(parsed,kind);assert.equal(parsed.result.kind,'stage-prepare');
  assert.deepEqual(parsed.result.report.limitations,STAGE_PREPARE_LIMITS);assert.ok(JSON.stringify(s).length<8192);
  for(const change of [v=>delete v.selection.later,v=>v.selection.later=null,v=>v.selection.later.stage='candidate',
   v=>v.result.report.predecessorReceiptSha256='b'.repeat(64),v=>v.result.report.operationId=UUID,
   v=>v.result.report.headSequence=8,v=>v.result.report.headSequence=512,v=>v.result.report.limitations=['non-publishing'],
   v=>v.result.report.destination.channel='internal',v=>v.result.report.privateKey='not-public',v=>v.result={kind:'ordinary',report:result().report},
   v=>{v.prepared.operation.operationId=A;v.operation.operationId=A;}]){
    const bad=clone(s);change(bad);assert.equal(parseStorePreparationStatus(bad),null,`${kind}/${change}`);
  }
  const other=clone(s);other.selection.kind=kind.startsWith('ios')?'ios-candidate':'android-candidate';delete other.selection.later;
  assert.equal(parseStorePreparationStatus(other),null);
  const wrongUuid=clone(s);wrongUuid.result.report.operationId=wrongUuid.result.report.operationId.replace('-4234-','-3234-');assert.equal(parseStorePreparationStatus(wrongUuid),null);
 }
 const tooLong=stageFinal('android-external-testing');tooLong.result.report.destination.channel+='🧪';assert.equal(parseStorePreparationStatus(tooLong),null);
});

test('four later Start consents remain separate fixed calls and cannot borrow an old candidate approval',async()=>{
 const calls=[],port=createStorePreparationPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null;});
 const consents=new Set();
 for(const kind of STAGES){
  await port.allowPrepare(input(kind),'0');assert.equal(calls.at(-1)[0],'allow_agent_store_prepare');assert.equal(calls.at(-1)[1].consentVersion,'agent-store-native-prepare-once-v1');
  await port.allowStart(status(kind),'1');assert.equal(calls.at(-1)[0],'allow_agent_store_preparation_start');assert.equal(calls.at(-1)[1].consentVersion,storePreparationConsent(kind));
  assert.deepEqual(Object.keys(calls.at(-1)[1]).sort(),['consentVersion','expectedPermissionRevision','origin','review']);consents.add(calls.at(-1)[1].consentVersion);
  const noReturn=status(kind,{prepareReturned:false});await assert.rejects(port.allowStart(noReturn));
 }
 assert.equal(consents.size,4);assert.equal(calls.length,8);
 for(const old of ['android-candidate','ios-candidate','android-access','ios-access'])assert.equal(consents.has(storePreparationConsent(old)),false);
});

test('later same-original two-controller flow preserves GUI exclusion and supplemental currentness',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of STAGES){
  const h=await mounted(kind);await allow(h,kind);h.emit();assert.ok(h.original.getSnapshot().status.operation,kind);
  await check(h,observed(status(kind)));assert.equal(h.controller.consentReason(),null);
  assert.equal(h.original.getSnapshot().acknowledged,false);assert.equal(h.original.getSnapshot().consentUntil,null);
  assert.equal(h.original.agentPreparedMatches(stageReview(kind).operation,3),false);
  h.original.setVisible(false);t.mock.timers.tick(300001);await flush();assert.deepEqual(h.callsNative,[]);
  h.controller.acknowledge(true);const p=h.controller.allow();assert.equal(h.last('start').args[0].prepared.reviewId,stageReview(kind).reviewId);
  h.last('start').resolve(observed(status(kind,{revision:5,startGrantId:START}),true));await p;assert.deepEqual(h.callsNative,[]);h.close();
 }
 // Only the public selection is unchanged by a contact revision. The captured
 // full native Prepare input still invalidates this controller's consent.
 const h=harness('ios-production-submit');await allow(h,'ios-production-submit');await check(h,observed(status('ios-production-submit')));
 const changed=clone(input('ios-production-submit'));changed.prepare.supplementalAssignments.reviewContact.recordRevision++;
 assert.deepEqual(clone(storePreparationSelection(changed)),clone(storePreparationSelection(input('ios-production-submit'))));
 h.set({input:changed});h.controller.syncContext();assert.ok(h.controller.consentReason());assert.equal(h.controller.acknowledge(true),false);assert.equal(await h.controller.allow(),false);
 assert.equal(h.calls.filter(c=>c.kind==='start').length,0);h.controller.dispose();
});

test('shared Store revision pins original returned Prepare and Start permission separately with no implicit Check',async()=>{
 const h=harness('ios-production-submit');
 assert.equal(h.controller.acknowledge(true),false);assert.equal(await h.controller.allow(),false);assert.equal(h.calls.length,0);
 await check(h,{...empty(),permissionRevision:'7'});assert.equal(h.controller.acknowledge(true),true);
 const prepare=h.controller.allow();assert.equal(h.last('prepare').args[1],'7');h.last('prepare').resolve({...granted('ios-production-submit'),permissionRevision:'8'});await prepare;
 await check(h,{...observed(status('ios-production-submit')),permissionRevision:'8'});assert.equal(h.controller.acknowledge(true),true);
 const start=h.controller.allow();assert.equal(h.last('start').args[1],'8');h.last('start').resolve({...observed(status('ios-production-submit',{revision:5,startGrantId:START}),true),permissionRevision:'9'});await start;
 assert.equal(h.controller.getSnapshot().unknown,false);assert.deepEqual(h.calls.map(v=>v.kind),['status','prepare','status','start']);h.controller.dispose();
 const calls=[],p=createStorePreparationPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return empty();});
 for(const revision of [undefined,null,0,'00','1\n','18446744073709551616']){
  assert.equal(parseStorePreparationAccess({...empty(),permissionRevision:revision}),null);
  await assert.rejects(p.allowPrepare(input(),revision));await assert.rejects(p.allowStart(status(),revision));
 }
 await p.allowPrepare(input(),'7');await p.allowStart(status(),'8');assert.deepEqual(calls.map(v=>v[1].expectedPermissionRevision),['7','8']);
});

test('candidate upload inputs require the original current prepared intent and platform material context',()=>{
 for(const kind of UPLOADS){
  const f=uploadFixture(kind),v=input(kind);assert.ok(parseLocalHistoryStatus(f.currentHistory.status));assert.ok(v,kind);
  assert.ok(parseLocalStoreExecuteRequest(v.prepare));assert.equal(storePreparationNativeOperation(kind),'local-store-execute');
  assert.equal(storePreparationPreparesIntent(kind),false);assert.equal(v.prepare.candidateOperationId,UUID);assert.equal(v.prepare.intentSha256,'d'.repeat(64));
  assert.equal(v.prepare.confirmation,`candidate:${kind.startsWith('ios')?'ios':'android'}:1.2.3:42`);
  for(const change of [f=>f.currentHistory.historical=true,f=>f.currentHistory.status.operation.result.history[0].phase='execute-pending',
   f=>f.currentHistory.status.operation.result.preparedIntent.priorPrepareFinality='complete',f=>f.currentHistory.status.operation.context.projectId='another',
   f=>f.saved.savedVersion.build++,f=>f.saved.dirtyDraft=true,f=>f.selected.status.assignments[0].recordRevision++,f=>f.selected.status.context.stage='production']){
    const bad=uploadFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory,bad.tools),null);
  }
  assert.equal(storePreparationInput(kind,f.saved,f.selected,kind.startsWith('ios')?iosHistory():history(),f.tools),null);
  if(kind.startsWith('ios')){
   assert.equal(Object.hasOwn(v.prepare,'toolchainSelection'),false);
   assert.equal(parseStorePreparationInput({kind,prepare:{...v.prepare,toolchainSelection:null}}),null);
  }else{
   assert.equal(v.prepare.toolchainSelection.instance,A);
   for(const change of [f=>delete f.saved.selection,f=>f.saved.selection.applicationId='other.app',f=>f.tools=null,
    f=>f.tools.catalogListening=false,f=>f.tools.catalogReadPending=true,f=>f.tools.catalogStatus.selected=null,f=>f.tools.selectionPending=true]){
     const bad=uploadFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory,bad.tools),null);
   }
  }
 }
});

test('eleven old selections omit Execute while new candidate upload cannot borrow later or Reconcile input',()=>{
 assert.equal(storePreparationKinds.length,21);
 for(const kind of storePreparationKinds.filter(k=>!storePreparationExecutesCandidate(k)&&!storePreparationRelease(k))){
  const s=status(kind);assert.equal(Object.hasOwn(s.selection,'execute'),false);assert.equal(JSON.stringify(s.selection).includes('execute'),false);
  s.selection.execute=null;assert.equal(parseStorePreparationStatus(s),null);
 }
 for(const kind of UPLOADS){
  const s=status(kind);assert.ok(parseStorePreparationStatus(s));assert.deepEqual(s.selection.execute,{intentSha256:'d'.repeat(64)});
  for(const change of [v=>delete v.selection.execute,v=>v.selection.execute=null,v=>v.selection.execute.intentSha256='not-a-digest',
   v=>v.selection.later={stage:'external-testing',predecessorOperationId:UUID,predecessorReceiptSha256:H},v=>v.selection.kind=kind.startsWith('ios')?'ios-candidate':'android-candidate']){
    const bad=clone(s);change(bad);assert.equal(parseStorePreparationStatus(bad),null);
  }
  for(const change of [v=>delete v.prepare.intentSha256,v=>v.prepare.intentSha256=null,v=>v.prepare.authorizationId=EXTERNAL,
   v=>v.prepare.confirmation='external-testing:android:1.2.3:42',v=>v.prepare.action='external-readiness',v=>v.prepare.settlement='record-current-target',
   v=>v.kind=kind.startsWith('ios')?'ios-candidate':'android-candidate',v=>v.kind=kind.startsWith('ios')?'android-candidate-upload':'ios-candidate-upload']){
    const bad=clone(input(kind));change(bad);assert.equal(parseStorePreparationInput(bad),null);
  }
  const stageKind=kind.startsWith('ios')?'ios-external-testing':'android-external-testing';
  const later={...clone(input(stageKind).prepare),stageOperationId:EXTERNAL,intentSha256:'d'.repeat(64)};
  assert.ok(parseLocalStoreExecuteRequest(later));assert.equal(parseStorePreparationInput({kind,prepare:later}),null);
 }
});

test('candidate upload reporting binds historical UUID and intent without treating Prepared ID or status as authority',()=>{
 for(const kind of UPLOADS){
  const s=final(kind),p=parseStorePreparationStatus(s);assert.ok(p,kind);assert.equal(p.prepared.operation.operationId,A);
  assert.equal(p.result.report.release.operationId,UUID);assert.notEqual(p.result.report.release.operationId.replaceAll('-',''),A);
  assert.deepEqual(p.result.report.release.limitations,storeReleaseLimitations('candidate-upload'));assert.ok(JSON.stringify(p).length<8192);
  for(const change of [v=>v.result.report.kind='candidate-prepare',v=>v.result.report.release.mode='current-internal',
   v=>v.result.report.release.intentSha256='b'.repeat(64),v=>v.result.report.release.operationId=EXTERNAL,v=>v.result.report.release.candidateOperationId=EXTERNAL,
   v=>v.result.report.release.basis={operationId:UUID,receiptSha256:H},v=>v.result.report.release.state='available-to-testers',v=>v.result.report.release.target='production',
   v=>v.result.report.release.authorizationId=EXTERNAL,v=>v.result.report.release.limitations=['publicly-released'],v=>v.result.report.release.headSequence=6,
   v=>v.selection.kind=kind.startsWith('ios')?'ios-candidate':'android-candidate']){
    const bad=clone(s);change(bad);assert.equal(parseStorePreparationStatus(bad),null);
  }
  const repaired=clone(s);repaired.result.report.release.result='reconciled';assert.ok(parseStorePreparationStatus(repaired)); // fixed core vocabulary, not a retry grant.
  const cold=harness(kind);assert.equal(cold.controller.acknowledge(true),false);assert.equal(cold.calls.length,0);cold.controller.dispose();
 }
});

test('candidate upload requires actual Prepare return then fresh checked Start consent and retains lost Start',async()=>{
 const calls=[],port=createStorePreparationPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null;});
 for(const kind of UPLOADS){
  await port.allowPrepare(input(kind),'7');assert.equal(calls.at(-1)[1].consentVersion,'agent-store-native-prepare-once-v1');
  await port.allowStart(status(kind),'8');assert.equal(calls.at(-1)[1].consentVersion,`agent-${kind.startsWith('ios')?'ios':'android'}-store-execute-candidate-upload-once-v1`);
  assert.deepEqual(Object.keys(calls.at(-1)[1]).sort(),['consentVersion','expectedPermissionRevision','origin','review']);
  assert.equal(calls.at(-1)[1].review.operation.operationId,A);assert.equal(calls.at(-1)[1].expectedPermissionRevision,'8');
  const h=harness(kind);await allow(h,kind);assert.deepEqual(h.calls.map(v=>v.kind),['status','prepare']);
  await check(h,observed(status(kind,{phase:'preparing',prepareReturned:false})));assert.equal(h.controller.acknowledge(true),false);assert.equal(await h.controller.allow(),false);
  await check(h,observed(status(kind,{revision:5})));assert.equal(h.controller.acknowledge(true),true);
  const start=h.controller.allow();assert.equal(h.last('start').args[1],'1');h.last('start').reject(Error('inert original Start reply lost'));await start;
  assert.equal(h.controller.getSnapshot().unknown,true);await check(h,observed(final(kind)));assert.equal(h.controller.getSnapshot().unknown,true);
  assert.equal(await h.controller.allow(),false);assert.equal(h.calls.filter(c=>c.kind==='start').length,1);h.controller.dispose();
 }
 assert.equal(calls.length,4);
});

test('candidate upload actual Execute peer stays unowned by GUI and rechecks full credential and tool comparison',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of UPLOADS){
  const h=await mounted(kind);await allow(h,kind);h.emit();await check(h,observed(status(kind)));
  assert.equal(h.controller.consentReason(),null);assert.equal(h.original.agentPreparedMatches(review().operation,3),false);
  assert.equal(h.original.getSnapshot().acknowledged,false);assert.equal(h.original.getSnapshot().consentUntil,null);
  h.original.setVisible(false);t.mock.timers.tick(300001);await flush();assert.deepEqual(h.callsNative,[]);
  const safe=h.original.getSnapshot();assert.equal(storePreparationPeerReason(input(kind),review(),safe,'busy'),null);
  for(const change of [v=>v.status.operation.context.recordRevision++,v=>v.status.operation.operationId=B,v=>v.pending=true,v=>v.acknowledged=true]){
   const bad=clone(safe);change(bad);assert.equal(storePreparationPeerReason(input(kind),review(),bad,'busy'),'busy');
  }
  assert.equal(h.controller.acknowledge(true),true);const start=h.controller.allow();h.last('start').resolve(observed(status(kind,{revision:5,startGrantId:START}),true));await start;
  assert.deepEqual(h.callsNative,[]);h.close();
  for(const change of [v=>v.prepare.recordRevision++,v=>v.prepare.credentialContextRevision++,...(kind.startsWith('ios')?[]:[v=>v.prepare.toolchainSelection.catalogGeneration++])]){
   const current=harness(kind);await allow(current,kind);await check(current,observed(status(kind)));current.controller.acknowledge(true);
   const next=clone(input(kind));change(next);assert.deepEqual(clone(storePreparationSelection(next)),clone(storePreparationSelection(input(kind))));
   current.set({input:next});current.controller.syncContext();assert.equal(current.controller.acknowledge(true),false);assert.equal(await current.controller.allow(),false);
   assert.equal(current.calls.filter(c=>c.kind==='start').length,0);current.controller.dispose();
  }
 }
});

// Eight additional fixed shapes; existing factories remain the only renderer
// eligibility source. Original native material/currentness is a separate cut.
test('lifecycle eight use actual stage or Reconcile factories and refuse stale lineage or unsupported transforms',()=>{
 for(const kind of LIFECYCLE){
  const f=lifecycleFixture(kind),r=storePreparationRelease(kind);assert.ok(parseLocalHistoryStatus(f.currentHistory.status),kind);
  const v=storePreparationInput(kind,f.saved,f.selected,f.currentHistory,null);assert.ok(v,kind);
  assert.deepEqual(clone(r.kind==='execute'?parseLocalStoreExecuteRequest(v.prepare):parseLocalStoreReconcileRequest(v.prepare)),clone(v.prepare));
  const c=r.kind==='reconcile'?reconcileRequestContext(v.prepare):{...v.prepare,operation:'local-store-execute'};
  assert.deepEqual(clone(storePreparationSelection(v).release),clone(storeReleaseFromContext(c,r.kind)));
  assert.equal(Object.hasOwn(v.prepare,'toolchainSelection'),false);
  for(const extra of [{toolchainSelection:null},{uploadSelection:{}},{authorizationId:UUID},{token:'not-allowed'}])assert.equal(parseStorePreparationInput({kind,prepare:{...v.prepare,...extra}}),null,kind);
  for(const change of [f=>f.currentHistory.historical=true,f=>f.currentHistory.status.operation.context.projectId='foreign',f=>f.saved.savedVersion.build++,
   f=>f.selected.status.context.revision++,f=>f.selected.status.records[0].revision++,f=>f.currentHistory.status.operation.result.history.at(-1).phase='preparing']){
   const bad=lifecycleFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory,null),null,kind);
  }
  if(kind==='android-current-internal'||kind==='android-recovery-settlement'){
   for(const change of [f=>delete f.saved.selection,f=>f.saved.selection.applicationId='wrong.app']){const bad=lifecycleFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory,null),null);}
  }
  if(kind==='android-recovery-settlement'){
   for(const change of [f=>f.currentHistory.status.operation.result.history.at(-1).phase='settled-success',f=>f.currentHistory.status.operation.result.headSequence=513]){const bad=lifecycleFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory),null);}
  }
  if(kind==='ios-external-readiness'){
   for(const change of [f=>f.currentHistory.status.operation.result.headSequence=509,f=>f.currentHistory.status.operation.result.history.at(-1).phase='execute-pending',f=>f.selected.status.assignments.splice(1,1),f=>f.saved.iosDemoRequired=true]){const bad=lifecycleFixture(kind);change(bad);assert.equal(storePreparationInput(kind,bad.saved,bad.selected,bad.currentHistory),null);}
  }
 }
 const settlement=clone(input('android-recovery-settlement'));settlement.kind='ios-current-internal';settlement.prepare.platform='ios';settlement.prepare.confirmation='candidate:ios:1.2.3:42';assert.equal(parseStorePreparationInput(settlement),null);
 const readiness=clone(input('ios-external-readiness'));readiness.kind='android-current-internal';readiness.prepare.platform='android';assert.equal(parseStorePreparationInput(readiness),null);
 const stage=clone(input('ios-external-testing-execute'));stage.kind='ios-external-testing';assert.equal(parseStorePreparationInput(stage),null);
});
test('lifecycle present-only release tuples preserve old thirteen and require every inner null and exact mode',()=>{
 for(const kind of storePreparationKinds.filter(k=>!storePreparationRelease(k))){
  const s=status(kind);assert.equal(Object.hasOwn(s.selection,'release'),false);s.selection.release=null;assert.equal(parseStorePreparationStatus(s),null);
 }
 for(const kind of LIFECYCLE){
  const s=status(kind);assert.ok(parseStorePreparationStatus(s),kind);assert.ok(JSON.stringify(s).length<8192);
  assert.equal(Object.hasOwn(s.selection,'later'),false);assert.equal(Object.hasOwn(s.selection,'execute'),false);
  for(const change of [v=>delete v.selection.release,v=>v.selection.release=null,v=>delete v.selection.release.basis,v=>delete v.selection.release.stageOperationId,
   v=>v.selection.release.mode='candidate-upload',v=>v.selection.release.private='not-allowed',v=>v.selection.later=null,v=>v.selection.execute=null,
   v=>v.selection.kind=kind.startsWith('ios')?'ios-candidate-upload':'android-candidate-upload']){
   const bad=clone(s);change(bad);assert.equal(parseStorePreparationStatus(bad),null,kind);
  }
  if(s.selection.release.basis){const bad=clone(s);bad.selection.release.basis.operationId=PRODUCTION;assert.equal(parseStorePreparationStatus(bad),null);}
  else {const bad=clone(s);bad.selection.release.stageOperationId=EXTERNAL;assert.equal(parseStorePreparationStatus(bad),null);}
 }
});
test('lifecycle receipt DATA preserves original candidate stage basis and never grants earlier finality or availability',()=>{
 for(const kind of LIFECYCLE){
  const s=final(kind),r=storePreparationRelease(kind),parsed=parseStorePreparationStatus(s);assert.ok(parsed,kind);
  assert.equal(parsed.result.report.kind,r.kind);assert.deepEqual(parsed.result.report.release.limitations,storeReleaseLimitations(r.mode));
  assert.notEqual(parsed.result.report.release.operationId.replaceAll('-',''),s.prepared.operation.operationId);
  for(const change of [v=>v.result.report.kind=r.kind==='execute'?'reconcile':'execute',v=>v.result.report.release.operationId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
   v=>v.result.report.release.intentSha256='0'.repeat(64),v=>v.result.report.release.headSequence=5,v=>v.result.report.release.priorExecutionFinality='complete',
   v=>v.result.report.release.limitations=[],v=>v.result.report.release.state='released',v=>v.prepareReturned=false]){
   const bad=clone(s);change(bad);assert.equal(parseStorePreparationStatus(bad),null,kind);
  }
  if(s.result.report.release.basis){const bad=clone(s);bad.result.report.release.basis.receiptSha256='0'.repeat(64);assert.equal(parseStorePreparationStatus(bad),null);}
  if(kind==='android-production-submit-execute')assert.equal(parsed.result.report.release.state,'draft');
  if(r.mode==='recovery-settlement'||r.mode==='external-readiness')assert.ok(parsed.result.report.release.limitations.includes('local-checkpoint-not-prior-finality'));
 }
});
test('lifecycle Start has eight separate fixed consents and explicit effects after a separately returned Prepare',async()=>{
 const calls=[],port=createStorePreparationPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null;}),consents=new Set();
 for(const kind of LIFECYCLE){
  await port.allowPrepare(input(kind),'7');assert.equal(calls.at(-1)[1].consentVersion,'agent-store-native-prepare-once-v1');assert.equal(calls.at(-1)[1].expectedPermissionRevision,'7');
  await port.allowStart(status(kind),'8');assert.equal(calls.at(-1)[0],'allow_agent_store_preparation_start');assert.equal(calls.at(-1)[1].consentVersion,storePreparationConsent(kind));
  assert.equal(calls.at(-1)[1].expectedPermissionRevision,'8');assert.deepEqual(Object.keys(calls.at(-1)[1]).sort(),['consentVersion','expectedPermissionRevision','origin','review']);
  consents.add(calls.at(-1)[1].consentVersion);await assert.rejects(port.allowStart(status(kind,{prepareReturned:false}),'8'));
  assert.ok(storePreparationLifecycleEffect(kind));assert.ok(!storePreparationExecutesCandidate(kind)&&!storePreparationPreparesIntent(kind));
 }
 assert.equal(consents.size,8);assert.equal(calls.length,16);
 assert.match(storePreparationLifecycleEffect('android-production-submit-execute'),/draft.*not served/);
 assert.match(storePreparationLifecycleEffect('ios-production-submit-execute'),/manual release/);
 assert.match(storePreparationLifecycleEffect('android-current-internal'),/temporary uncommitted edit.*invalidate/);
 assert.match(storePreparationLifecycleEffect('android-recovery-settlement'),/old files and fences.*unknown owner.*retry/);
 assert.match(storePreparationLifecycleEffect('ios-external-readiness'),/No upload, notification or resubmission/);
});
test('actual Execute and Reconcile peers keep returned Prepare then fresh Start and retain lost caller',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of LIFECYCLE){
  const h=await mounted(kind);await allow(h,kind);h.emit();await check(h,observed(status(kind)));
  assert.equal(h.controller.consentReason(),null,kind);assert.equal(h.original.getSnapshot().acknowledged,false);assert.deepEqual(h.callsNative,[]);
  h.original.setVisible(false);t.mock.timers.tick(300001);await flush();assert.deepEqual(h.callsNative,[]);
  assert.equal(h.controller.acknowledge(true),true);const start=h.controller.allow();assert.equal(h.last('start').args[1],'1');
  // A native-looking terminal cannot replace this original caller's return.
  let joined=false;const wait=h.controller.whenSettled().then(()=>joined=true);await flush();assert.equal(joined,false);assert.equal(await h.controller.status(),false);
  h.last('start').reject(Error('inert lost original lifecycle Start reply'));await start;await wait;
  assert.equal(h.controller.getSnapshot().unknown,true);await check(h,observed(final(kind)));assert.equal(h.controller.getSnapshot().unknown,true);
  assert.equal(await h.controller.allow(),false);assert.equal(h.calls.filter(c=>c.kind==='start').length,1);assert.deepEqual(h.callsNative,[]);h.close();
 }
});
test('lifecycle peer matching never hides a real GUI caller or changed full credential comparison',async()=>{
 for(const kind of LIFECYCLE){
  const h=await mounted(kind),d=h.defer(),gui=h.original.prepare();h.emit();assert.ok(h.original.getSnapshot().pending,kind);
  const snap=h.original.getSnapshot();assert.equal(storePreparationPeerReason(input(kind),review(),snap,'busy'),'busy');
  d.resolve(nativeStatus(4,snap.status.operation));await gui;
  const idle={...h.original.getSnapshot(),pending:false,callersPending:0,acknowledged:false,consentUntil:null,blocked:false,unconfirmed:false};
  assert.equal(storePreparationPeerReason(input(kind),review(),idle,'busy'),null,kind);
  const foreign=clone(idle);foreign.status.operation.context.recordRevision++;assert.equal(storePreparationPeerReason(input(kind),review(),foreign,'busy'),'busy');
  if(kind==='android-recovery-settlement'){const wrong=clone(idle);wrong.status.operation.context.operation='local-store-reconcile';assert.equal(storePreparationPeerReason(input(kind),review(),wrong,'busy'),'busy');}
  h.close();
  const current=harness(kind);await allow(current,kind);await check(current,observed(status(kind)));assert.equal(current.controller.acknowledge(true),true);
  const changed=clone(input(kind));changed.prepare.credentialContextRevision++;assert.deepEqual(clone(storePreparationSelection(changed)),clone(storePreparationSelection(input(kind))));
  current.set({input:changed});current.controller.syncContext();assert.equal(await current.controller.allow(),false);assert.equal(current.calls.filter(c=>c.kind==='start').length,0);current.controller.dispose();
 }
});
