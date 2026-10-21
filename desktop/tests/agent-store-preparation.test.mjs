// Real public codecs/controllers with inert DATA and retained promises only.
// No IPC, credentials, Store, native admission, synthetic joins or UI automation.
import assert from 'node:assert/strict';
import test from 'node:test';
import {parseStorePreparationInput,storePreparationInput,storePreparationSelection,parseStorePreparationStatus,parseStorePreparationAccess,createStorePreparationPort,storePreparationCommands,storePreparationPeerReason} from '../src/agentStorePreparation.ts';
import {StorePreparationController} from '../src/agentStorePreparationController.ts';
import {LocalStorePreflightController,localStoreOwnerReason} from '../src/localStorePreflight.ts';
import {LocalStorePrepareController,localStorePrepareOwnerReason} from '../src/localStorePrepare.ts';
const id=c=>c.repeat(32),A=id('a'),B=id('b'),P=id('1'),S=id('2'),G=id('3'),R=id('4'),Q=id('5'),START=id('6'),H='c'.repeat(64),UUID='12345678-1234-4234-8234-123456789abc';
const clone=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:H},savedVersion:{bytes:40,sha256:H,source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false,versionPlatforms:['android','ios']});
function assets(platform='android') { const scope={executionMode:'local',platform,stage:'candidate',purpose:platform==='both'?'version-inventory':'store'},pairs=platform==='both'?[['google-service-account',R],['asc-p8',A]]:[[platform==='ios'?'asc-p8':'google-service-account',R]];
 return {mode:'native',scope,contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',...scope},operation:null,assignments:pairs.map(([kind,recordId])=>({kind,recordId,recordRevision:4,contextRevision:3,availability:'available'})),records:pairs.map(([kind,recordId])=>({kind,recordId,revision:4,availability:'assigned'}))}};
}
const nativeStatus=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const history=()=>({mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:nativeStatus(1,{operationId:R,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-inputs',candidateOperationId:UUID},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:3,history:[{operationId:UUID,phase:'inputs-ready',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],candidateInputs:{operationId:UUID,candidateSha256:H,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},files:[{fileName:'app-release.aab',bytes:100,sha256:H},{fileName:'store-metadata.zip',bytes:100,sha256:H},{fileName:'validation-report.json',bytes:100,sha256:H}],observation:'current-bundle-only',priorCreateFinality:'not-established'}}})});
function iosHistory(){const h=history(),v=h.status.operation.result.candidateInputs;delete v.applicationId;v.bundleId='org.example.ios-app';v.files[0].fileName='export/App.ipa';v.archive={directory:'archive.xcarchive',entries:4,bytes:500,sha256:H};h.status.operation.context.platform='ios';return h;}
const input=(kind='android-access')=>storePreparationInput(kind,project(),assets(kind.startsWith('ios')?'ios':kind==='paired-versions'?'both':'android'),kind==='ios-candidate'?iosHistory():history());
const review=()=>({reviewId:A,operation:{operationId:A,ownerGeneration:B,statusRevision:3}});
const origin=()=>({projectId:P,serviceInstance:S,requestId:Q});
const status=(kind='android-access',more={})=>({schemaVersion:1,origin:origin(),prepareGrantId:G,selectionId:R,revision:4,selection:storePreparationSelection(input(kind)),phase:'prepared',settlement:'pending',reason:'none',prepared:review(),operation:review().operation,startGrantId:null,prepareReturned:true,startSubmitted:false,outcome:null,result:null,doNotReplay:true,...more});
const empty=()=>({schemaVersion:1,serviceInstance:null,projectId:null,permission:null,grantId:null,reviewId:null,selection:null,requestId:null,enabled:false,consumed:false,pending:false,unknown:false,remainingMs:0,status:null});
const granted=(kind='android-access')=>({schemaVersion:1,serviceInstance:S,projectId:P,permission:'prepare',grantId:G,reviewId:R,selection:storePreparationSelection(input(kind)),requestId:null,enabled:true,consumed:false,pending:false,unknown:false,remainingMs:290000,status:null});
function observed(s,armed=false){return {schemaVersion:1,serviceInstance:S,projectId:P,permission:s.startGrantId?'start':'prepare',grantId:s.startGrantId??G,reviewId:s.startGrantId?A:R,selection:s.selection,requestId:s.origin.requestId,enabled:armed,consumed:s.startGrantId?s.startSubmitted:true,pending:s.settlement!=='settled',unknown:s.phase==='unknown',remainingMs:armed?280000:0,status:s};}
const ios=()=>({observation:'observed',coverage:'asc-ios-current-inventory/1',revision:H,counts:{builds:0,buildUploads:0,appStoreVersions:1},maxBuild:0,marketingVersion:'2.0.0',historicalUniqueness:'not-established'});
const android=()=>({observation:'observed',coverage:'play-android-current-inventory/1',revision:H,counts:{tracks:2,releases:2,versionCodes:3,bundles:0,apks:1},maxBuild:40,marketingVersion:null,temporaryEdit:'deleted',historicalUniqueness:'not-established'});
const result=(kind='android-access')=>kind.endsWith('-versions')?{kind:'current-versions',inventory:kind==='paired-versions'?{platform:'both',android:android(),ios:ios()}:kind==='ios-versions'?{platform:'ios',current:ios()}:{platform:'android',current:android()}}:{kind:'ordinary',report:{kind:'access-check',findings:[{check:'store-access',status:'FAIL'}],limitations:['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic']}};
const final=(kind='android-access')=>status(kind,{revision:9,phase:'final',settlement:'settled',operation:{...review().operation,statusRevision:8},startGrantId:START,startSubmitted:true,outcome:'complete',result:result(kind)});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
function harness(kind='android-access') {
 const calls=[],method=kind=>(...args)=>{const d=deferred();calls.push({kind,args,...d});return d.promise;};
 const port={status:method('status'),allowPrepare:method('prepare'),allowStart:method('start'),revoke:method('revoke')};let now=100;
 let context={port,nativeSession:{},epoch:{},projectId:'p1',preview:false,input:input(kind),blockedReason:null};
 const controller=new StorePreparationController({current:()=>context,now:()=>now});controller.choose(kind);
 return {controller,calls,port,set:v=>context={...context,...v},time:v=>now=v,last:k=>calls.filter(v=>v.kind===k).at(-1)};
}
async function allow(h,kind='android-access'){assert.equal(h.controller.acknowledge(true),true);const p=h.controller.allow();h.last('prepare').resolve(granted(kind));await p;}
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
 await p.allowPrepare(input('paired-versions'));assert.equal(calls[0][0],'allow_agent_store_prepare');assert.equal(calls[0][1].consentVersion,'agent-store-native-prepare-once-v1');assert.deepEqual(calls[0][1].prepare,clone(input('paired-versions').prepare));
 await p.allowStart(status('paired-versions'));assert.equal(calls[1][0],'allow_agent_store_preparation_start');assert.equal(calls[1][1].consentVersion,'agent-paired-current-versions-edit-once-v1');assert.deepEqual(Object.keys(calls[1][1]).sort(),['consentVersion','origin','review']);
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
 const h=harness();await allow(h);assert.equal(h.calls.length,1);assert.ok(h.controller.allowReason());
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
 const h=harness();h.controller.acknowledge(true);const p=h.controller.allow();let returned=false;const wait=h.controller.whenSettled().then(()=>returned=true);
 assert.equal(await h.controller.status(),false);await flush();assert.equal(returned,false);assert.ok(h.controller.ownerReason());
 h.controller.dispose();h.last('prepare').resolve(observed(status()));await p;await wait;assert.equal(returned,true);assert.equal(h.controller.getSnapshot().access,null);assert.equal(h.calls.length,1);
});
test('listener reentry before invocation prevents a stale Prepare or Start',async()=>{
 for(const start of [false,true]){const h=harness();if(start){await allow(h);await check(h,observed(status()));}
  h.controller.acknowledge(true);const remove=h.controller.subscribe(()=>{if(h.controller.getSnapshot().pending)h.set({epoch:{}});});
  assert.equal(await h.controller.allow(),false);remove();assert.equal(h.calls.filter(c=>c.kind=== (start?'start':'prepare')).length,start?0:0);
 }
});
test('lost Prepare/Start replies retain original IDs and forbid replay despite later success DATA',async()=>{
 for(const start of [false,true]){const h=harness();if(start){await allow(h);await check(h,observed(status()));}h.controller.acknowledge(true);const p=h.controller.allow();h.last(start?'start':'prepare').reject(Error('inert lost original reply'));await p;
  assert.equal(h.controller.getSnapshot().unknown,true);await check(h,observed(final()));assert.equal(h.controller.getSnapshot().unknown,true);assert.equal(await h.controller.allow(),false);
 }
});
test('Revoke can run while Allow returns but its generation prevents late rearming',async()=>{
 const h=harness();h.controller.acknowledge(true);const p=h.controller.allow(),stop=h.controller.revoke();let finished=false;const wait=h.controller.whenSettled().then(()=>finished=true);
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
 assert.equal(h.controller.acknowledge(true),true);const p=h.controller.allow();h.last('prepare').resolve({...granted(),grantId:id('7'),reviewId:id('8')});await p;assert.equal(h.controller.getSnapshot().unknown,false);assert.equal(h.calls.filter(c=>c.kind==='prepare').length,2);
});

async function mounted(kind='android-access'){
 const saved=project(),selected=assets(),currentHistory=history();let latest=nativeStatus(),listener,permission=null;const calls=[];
 const candidate=kind==='android-candidate',original=candidate?new LocalStorePrepareController({project:()=>saved,assets:()=>selected,history:()=>currentHistory,otherOperationReason:()=>permission?.ownerReason()??null,now:()=>100}):new LocalStorePreflightController({project:()=>saved,assets:()=>selected,otherOperationReason:()=>permission?.ownerReason()??null,now:()=>100});
 const suffix=candidate?'LocalStorePrepare':'LocalStorePreflight';let pendingPrepare=null;
 const api={mode:'native',[`subscribe${suffix}`]:async f=>{listener=f;return()=>{};},[suffix[0].toLowerCase()+suffix.slice(1)+'Status']:async()=>clone(latest),[`prepare${suffix}`]:async()=>{calls.push('gui-prepare');return pendingPrepare?.promise??clone(latest);},[`start${suffix}`]:async()=>{calls.push('gui-start');return clone(latest);},[`cancel${suffix}`]:async()=>{calls.push('gui-cancel');return clone(latest);}};
 await original.connect(api);original.syncProject();const h=harness(kind);const epoch={},nativeSession={};
 permission=new StorePreparationController({current:()=>{const peer=permission?.peer(),reason=candidate?localStorePrepareOwnerReason(original.getSnapshot()):localStoreOwnerReason(original.getSnapshot());return{port:h.port,epoch,nativeSession,projectId:'p1',preview:false,input:storePreparationInput(kind,saved,selected,currentHistory),blockedReason:storePreparationPeerReason(peer?.input??null,peer?.review??null,original.getSnapshot(),reason)};},now:()=>100});permission.choose(kind);h.controller=permission;
 return{...h,original,callsNative:calls,emit:()=>{const request=input(kind).prepare;latest=nativeStatus(3,{operationId:A,ownerGeneration:B,context:{...clone(request),platform:request.platform??'android',operation:candidate?'local-store-prepare':'local-store-preflight'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});listener(clone(latest));},defer:()=>pendingPrepare=deferred(),close:()=>{original.dispose();permission.dispose();}};
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
