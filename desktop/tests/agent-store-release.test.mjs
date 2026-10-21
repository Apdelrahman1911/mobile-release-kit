// Actual existing controllers/closed codecs, inert ports and clocks only.
// No child process, network, Store, credential, filesystem or native calls.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentStoreAccessController } from '../src/agentStoreAccessController.ts';
import { parseStoreReview, parseAgentStoreAccess, storeConsent, storeCommands, storeReviewFromState, createAgentStoreAccessPort } from '../src/agentStoreAccess.ts';
import { storeReleaseFromContext, storeReleaseLimitations, storeReleaseTarget, storeEffectText, storeSelectedPeerReason } from '../src/agentStoreRelease.ts';
import { LocalStoreExecuteController, localStoreExecuteOwnerReason } from '../src/localStoreExecute.ts';
import { LocalStoreReconcileController, localStoreReconcileOwnerReason } from '../src/localStoreReconcile.ts';
import { reconcileRequestContext } from '../src/localStoreReconcileProtocol.ts';
import { STAGE_PREPARE_LIMITS, STAGE_EXECUTE_LIMITS } from '../src/localStoreStageProtocol.ts';
import { parseLocalHistoryStatus } from '../src/localReleaseHistoryProtocol.ts';

const A='a'.repeat(32), B='b'.repeat(32), C='c'.repeat(32), P='1'.repeat(32), S='2'.repeat(32), G='3'.repeat(32), R='4'.repeat(32), Q='5'.repeat(32);
const U='12345678-1234-4234-8234-123456789abc', E='22345678-1234-4234-8234-123456789abc', V='32345678-1234-4234-8234-123456789abc', AUTH='42345678-1234-4234-8234-123456789abc';
const H='d'.repeat(64), clone=v=>structuredClone(v), flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const cases=()=>['android','ios'].flatMap(platform=>[['execute',platform,'candidate-upload'],['execute',platform,'external-testing'],['execute',platform,'production-submit'],['reconcile',platform,'current-internal']]).concat([['reconcile','android','recovery-settlement'],['reconcile','ios','external-readiness']]);
function review(kind='execute',platform='android',mode='candidate-upload') {
 const staged=['external-testing','production-submit','external-readiness'].includes(mode),stage=mode==='production-submit'?V:E;
 return {kind,platform,operationId:A,ownerGeneration:B,statusRevision:3,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),name:'1.2.3',build:42},candidate:{operationId:U,sha256:'a'.repeat(64)},
  release:{mode,intentSha256:'b'.repeat(64),stageOperationId:staged?stage:null,basis:staged?{operationId:mode==='external-testing'?U:E,receiptSha256:H}:null}};
}
function result(r) {
 const mode=r.release.mode;
 return {kind:r.kind,release:{mode,headSequence:mode==='production-submit'?15:mode==='external-testing'?11:mode==='external-readiness'?12:mode==='current-internal'?6:7,
  operationId:r.release.stageOperationId??r.candidate.operationId,candidateOperationId:r.candidate.operationId,candidateSha256:r.candidate.sha256,intentSha256:r.release.intentSha256,receiptSha256:'f'.repeat(64),basis:clone(r.release.basis),
  target:storeReleaseTarget(mode,r.platform),result:r.kind==='execute'?'accepted':mode==='external-readiness'?'ready':'reconciled',
  state:mode==='external-testing'||mode==='external-readiness'?'available-to-testers':mode==='production-submit'?(r.platform==='android'?'draft':'pending-developer-release'):null,limitations:[...storeReleaseLimitations(mode)]}};
}
const empty=()=>({permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,reviewId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const access=r=>({permissionRevision:'1',serviceInstance:S,projectId:P,grantId:G,reviewId:R,review:clone(r),enabled:true,remainingMs:200000,consumed:false,pending:false,unknown:false,requestId:null,status:null});
function completed(r,patch={}) {
 const status={origin:{projectId:P,serviceInstance:S,requestId:Q},grantId:G,reviewId:R,revision:8,review:clone(r),state:'complete',settlement:'settled',reason:'none',operation:{operationId:A,ownerGeneration:B,statusRevision:4},outcome:'complete',result:result(r),...patch};
 return {...access(r),enabled:false,remainingMs:0,consumed:true,requestId:Q,pending:status.settlement!=='settled',unknown:status.state==='unknown',status};
}

test('all ten exact mode/platform reviews and unique consents retain one three-call port',async()=>{
 const calls=[],port=createAgentStoreAccessPort(async(name,bytes)=>{calls.push([name,JSON.parse(new TextDecoder().decode(bytes))]);assert.ok(bytes.length<=1024);return empty();});
 const consents=new Set();
 for(const [kind,platform,mode] of cases()) {
  const r=parseStoreReview(review(kind,platform,mode));assert.ok(r,`${kind}/${platform}/${mode}`);assert.ok(Object.isFrozen(r.release));
  const consent=storeConsent(r);assert.equal(consent,`agent-${platform}-store-${kind}-${mode}-once-v1`);assert.ok(!consents.has(consent));consents.add(consent);
  await port.allow(r,'0');const [name,body]=calls.at(-1);assert.equal(name,'allow_agent_store');assert.deepEqual(Object.keys(body),['expectedPermissionRevision','kind','operationId','ownerGeneration','expectedStatusRevision','consentVersion']);assert.equal(body.consentVersion,consent);
  assert.deepEqual(storeCommands(access(r)),[`mrk store-submit ${P} ${S} ${G} ${R} --reviewed`]);
 }
 assert.equal(calls.length,10);await port.status();await port.revoke();assert.deepEqual(calls.slice(-2),[['agent_store_access',{}],['revoke_agent_store',{}]]);
});
test('old two byte shapes never acquire release fields or cross-mode consent',()=>{
 for(const kind of ['access-check','candidate-prepare'])for(const platform of ['android','ios']) {
  const r=review(kind,platform);delete r.release;if(kind==='access-check')r.candidate=null;
  assert.ok(parseStoreReview(r));assert.equal(Object.keys(parseStoreReview(r)).length,8);assert.equal(parseStoreReview({...r,release:null}),null);assert.equal(parseStoreReview({...r,kind:'execute'}),null);
  assert.equal(storeConsent(r),`agent-${platform}-store-${kind==='access-check'?'access':'candidate-prepare'}-once-v1`);
 }
 for(const [kind,platform,mode] of [['execute','android','current-internal'],['reconcile','android','external-readiness'],['reconcile','ios','recovery-settlement'],['candidate-prepare','android','candidate-upload']])assert.equal(parseStoreReview(review(kind,platform,mode)),null);
});
test('release lineage nulls, complete small bound and hostile accessors are checked before use',()=>{
 for(const row of cases()) {
  const r=review(...row);r.savedVersion.name='v'.repeat(64);r.savedVersion.build=2100000000;r.savedConfig.bytes=524288;r.savedVersion.bytes=65536;r.statusRevision=0xfffffffe;
  assert.ok(parseStoreReview(r));assert.ok(JSON.stringify(r).length<=2048);
  for(const key of ['mode','intentSha256','stageOperationId','basis']){const v=clone(r);delete v.release[key];assert.equal(parseStoreReview(v),null);}
  for(const patch of [{intentSha256:'A'.repeat(64)},{stageOperationId:U},{credential:'private'},null]){const v=clone(r);v.release=patch===null?null:{...v.release,...patch};assert.equal(parseStoreReview(v),null);}
 }
 let called=0;const r=review();Object.defineProperty(r.release,'intentSha256',{enumerable:true,get(){called++;return H;}});assert.equal(parseStoreReview(r),null);assert.equal(called,0);
 const cyc=review();cyc.release.basis=cyc;assert.equal(parseStoreReview(cyc),null);
});
test('all complete mode reports keep redacted real states and reject forged finality or bindings',()=>{
 for(const row of cases()) {
  const r=review(...row),a=completed(r);assert.ok(parseAgentStoreAccess(a),row.join('/'));assert.ok(JSON.stringify(a).length<8192);
  for(const [key,value] of [['candidateSha256','e'.repeat(64)],['intentSha256','e'.repeat(64)],['receiptSha256','A'.repeat(64)],['headSequence',0],['headSequence',514],['state','released'],['limitations',[]],['destination',{channel:'public'}],['retryAllowed',true]]) {
   const v=clone(a);v.status.result.release[key]=value;assert.equal(parseAgentStoreAccess(v),null,`${row}/${key}`);
  }
  const pending=completed(r,{state:'finishing',settlement:'pending',outcome:null,result:null});assert.ok(parseAgentStoreAccess(pending));assert.equal(pending.status.result,null);
  const unknown=completed(r,{state:'unknown',settlement:'unknown',outcome:'unknown',reason:'cleanup-unknown',result:null});assert.ok(parseAgentStoreAccess(unknown));assert.deepEqual(storeCommands(unknown),[`mrk store-status ${P} ${S} ${Q}`,`mrk store-cancel ${P} ${S} ${Q}`]);
 }
 for(const state of ['submitted-for-review','in-review','approved','pending-developer-release']){const r=review('execute','ios','production-submit'),v=completed(r);v.status.result.release.state=state;assert.ok(parseAgentStoreAccess(v));v.status.result.release.result='ready';assert.equal(parseAgentStoreAccess(v),null);}
});
test('semantic target copy does not invent Android external track or promise public release',()=>{
 const external=review('execute','android','external-testing');assert.match(storeEffectText(external),/configured external-testing track/);assert.equal(storeReleaseTarget(external.release.mode,'android'),'configured-play-external');
 assert.match(storeEffectText(review('execute','android','production-submit')),/draft is not served/);
 assert.match(storeEffectText(review('execute','ios','production-submit')),/manual release/);
 assert.match(storeEffectText(review('reconcile','ios','external-readiness')),/not earlier execution finality/);
 assert.match(storeEffectText(review('reconcile','android','recovery-settlement')),/cannot clear a live unknown/);
});

const nativeStatus=(n=0,operation=null)=>({schemaVersion:1,statusRevision:n,availability:'available',operation});
function inputs(kind,platform,mode) {
 const stage=mode==='production-submit'?'production':['external-testing','external-readiness'].includes(mode)?'external-testing':'candidate';
 const project={projectId:'p1',draftRevision:1,baselineGeneration:2,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},selection:{module:'app',variant:'release',applicationId:'dev.example.app'},iosDemoRequired:false,inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false};
 const credential=platform==='ios'?'asc-p8':'google-service-account';
 const assets={mode:'native',scope:{executionMode:'local',platform,stage,purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform,stage,purpose:'store'},operation:null,assignments:[{kind:credential,recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:credential,recordId:C,revision:4,availability:'assigned'}]}};
 if(platform==='ios'&&stage!=='candidate')for(const [kind,id] of [['apple-review-contact','e'],['operation-commitment','f']]){assets.status.assignments.push({kind,recordId:id.repeat(32),recordRevision:4,contextRevision:3,availability:'available'});assets.status.records.push({kind,recordId:id.repeat(32),revision:4,availability:'assigned'});}
 let prepared={operationId:U,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),storePreconditionSha256:'c'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),version:{name:'1.2.3',build:42},observedAt:'2026-10-17T00:00:00Z',limitations:['non-publishing','prepare-not-execute',platform==='ios'?'current-asc-snapshot-may-change':'temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic'],observation:'current-prepared-files-only',priorPrepareFinality:'not-established',
  ...(platform==='ios'?{bundleId:'org.example.ios-app',appStoreAppId:'0012345',destination:{channel:'testflight-internal'}}:{applicationId:'dev.example.app',destination:{channel:'internal',releaseStatus:'completed'}})};
 let action=kind==='execute'?'review-prepared':'review-reconcile',head=kind==='execute'?5:6,phase=kind==='execute'?'prepared':'execute-pending',key='preparedIntent';
 if(stage!=='candidate') {
  const production=mode==='production-submit';
  Object.assign(prepared,{operationId:production?V:E,stage:production?'production-submit':'external-testing',candidateOperationId:U,predecessorOperationId:production?E:U,predecessorReceiptSha256:H,limitations:[...STAGE_PREPARE_LIMITS],
   destination:platform==='ios'?(production?{channel:'app-store-review',automaticRelease:false}:{channel:'testflight-external'}):{channel:production?'production':'qa-beta',releaseStatus:production?'draft':'completed'}});
  action='review-stage-prepared';head=production?13:9;
  if(mode==='external-readiness') {
   delete prepared.storePreconditionSha256;delete prepared.priorPrepareFinality;
   Object.assign(prepared,{receiptSha256:'f'.repeat(64),authorizationId:AUTH,result:'accepted',state:'available-to-testers',limitations:[...STAGE_EXECUTE_LIMITS],observation:'current-execution-files-only',priorExecutionFinality:'not-established'});
   action='review-stage-execution';head=11;phase='settled-success';key='executionReceipt';
  }
 }
 const context={projectId:'p1',executionMode:'local',action,platform,...(stage==='candidate'?{candidateOperationId:U}:{stageOperationId:prepared.operationId})};
 // Existing candidate Android history has the original omitted-platform ABI;
 // only iOS and later-stage history carry the explicit platform field.
 if(stage==='candidate'&&platform==='android')delete context.platform;
 const history={mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:nativeStatus(1,{operationId:C,ownerGeneration:B,context,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:head,history:[{operationId:prepared.operationId,phase,recoveryRequired:phase!=='settled-success'}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],[key]:prepared}})};
 assert.ok(parseLocalHistoryStatus(history.status),`${kind}/${platform}/${mode} original history fixture`);
 const selection={instance:A,ownerUid:501,catalogGeneration:1,recordSha256:'a'.repeat(64),inventorySha256:'b'.repeat(64),osProviderSha256:'c'.repeat(64)};
 const tools={mode:'native',catalogListening:true,catalogReadPending:false,selectionPending:false,catalogStatus:{schemaVersion:1,statusRevision:1,catalogGeneration:1,operationId:B,availability:'available',phase:'ready',reason:'none',selected:selection,entries:[{instance:A,occupants:3,status:'verified-this-session',versions:{jdkVendor:'Temurin',jdkVersion:'21',gradleVersion:'8.10',agpVersion:'8.7',sdkPlatform:'35',sdkBuildToolsVersion:'35.0.0'},recovery:null,selection}]},status:null};
 return {project,assets,history,tools};
}
async function original(kind='execute',platform='android',mode='candidate-upload') {
 const i=inputs(kind,platform,mode),calls=[],epoch={},nativeSession={};let now=100,latest=nativeStatus(),listener,permission=null,prepareWait=null,peer=()=>null,store=empty();
 const source={project:()=>i.project,assets:()=>i.assets,history:()=>i.history,tools:()=>i.tools,otherOperationReason:()=>permission?.ownerReason()??peer(),now:()=>now};
 const ctl=kind==='execute'?new LocalStoreExecuteController(source):new LocalStoreReconcileController(source),suffix=kind==='execute'?'LocalStoreExecute':'LocalStoreReconcile',reason=kind==='execute'?localStoreExecuteOwnerReason:localStoreReconcileOwnerReason;
 const api={mode:'native',[`subscribe${suffix}`]:async f=>{listener=f;return()=>{};},[suffix[0].toLowerCase()+suffix.slice(1)+'Status']:async()=>clone(latest),
  [`prepare${suffix}`]:async request=>{calls.push('prepare');const context=kind==='execute'?{...clone(request),platform:request.platform??'android',operation:'local-store-execute'}:reconcileRequestContext(request);latest=nativeStatus(latest.statusRevision+1,{operationId:A,ownerGeneration:B,context,phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});listener(clone(latest));if(prepareWait)await prepareWait;return clone(latest);},
  [`start${suffix}`]:async()=>{calls.push('gui-start');return clone(latest);},
  [`cancel${suffix}`]:async(a,b)=>{assert.equal(a,A);assert.equal(b,B);calls.push('cancel');latest=nativeStatus(latest.statusRevision+1,{...latest.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});return clone(latest);}};
 await ctl.connect(api);ctl.syncProject();if(mode==='recovery-settlement')assert.equal(ctl.setSettlement(true),true);if(mode==='external-readiness')assert.equal(ctl.setExternalReadiness(true),true);
 assert.equal(ctl.prepareReason(),null,`${kind}/${platform}/${mode} eligibility`);
 const port={status:async()=>{calls.push('status');return clone(store);},allow:async r=>{calls.push('allow');store=access(r);return clone(store);},revoke:async()=>{calls.push('revoke');store={...store,enabled:false,remainingMs:0};return clone(store);}};
 permission=new AgentStoreAccessController({current:()=>{const r=storeReviewFromState(ctl.getSnapshot(),kind,'p1');return{port,nativeSession,epoch,projectId:'p1',preview:false,reviews:r?[r]:[],blockedReason:peer()??storeSelectedPeerReason(permission?.peerReview()??null,kind,ctl,reason(ctl.getSnapshot()))};},delegate:r=>ctl.delegatePrepared(r,r.statusRevision),now:()=>now});
 permission.choose(kind);const unlisten=ctl.subscribe(()=>permission.syncContext());
 return {ctl,permission,port,calls,i,reason:()=>reason(ctl.getSnapshot()),time:v=>now=v,busy:fn=>{peer=fn;},defer:()=>{const d=deferred();prepareWait=d.promise;return d;},
  running:()=>{latest=nativeStatus(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});listener(clone(latest));},bad:()=>listener({invalid:true}),
  changed:()=>{i.project.draftRevision++;ctl.syncProject();},latest:()=>clone(latest),setStore:v=>store=v,
  close:async()=>{unlisten();await ctl.cancel();ctl.dispose();permission.dispose();await flush();}};
}
async function prepare(h){await h.ctl.prepare();await h.permission.status();h.permission.syncContext();const r=h.permission.getSnapshot().review;assert.ok(r);return r;}

test('real original controllers reach all ten modes and one actual Allow despite own Prepared busy',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const row of cases()) {const h=await original(...row);try{
  const r=await prepare(h);assert.equal(r.release.mode,row[2]);assert.ok(h.reason());assert.equal(h.permission.consentReason(),null);
  assert.equal(h.permission.acknowledge(true),true);assert.equal(await h.permission.allow(),true);assert.deepEqual(h.calls,['prepare','status','allow']);
  assert.equal(h.ctl.getSnapshot().consentUntil,null);assert.equal(storeReviewFromState(h.ctl.getSnapshot(),row[0],'p1'),null);
  assert.equal(h.permission.choose(row[0]==='execute'?'reconcile':'execute'),false);assert.equal(await h.permission.allow(),false);assert.equal(h.calls.filter(x=>x==='allow').length,1);
  if(row[2]==='external-testing'&&row[1]==='android')assert.equal(h.ctl.getSnapshot().prepared.destination.channel,'qa-beta');
 }finally{await h.close();}}
});
test('returned Prepare promise, not early event or consent publication, authorizes delegation',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['execute','reconcile']) {const h=await original(kind,'android',kind==='execute'?'candidate-upload':'current-internal');try{
  const d=h.defer(),p=h.ctl.prepare();await flush();assert.equal(h.latest().operation.phase,'awaiting-consent');assert.equal(h.ctl.agentPreparedMatches({operationId:A,ownerGeneration:B},h.latest().statusRevision),false);assert.equal(h.permission.acknowledge(true),false);
  let reentrant=0;const off=h.ctl.subscribe(()=>{if(h.ctl.getSnapshot().consentUntil!==null&&h.ctl.getSnapshot().pending){reentrant++;assert.equal(h.ctl.delegatePrepared({operationId:A,ownerGeneration:B},h.latest().statusRevision),null);}});
  d.resolve();await p;off();assert.ok(reentrant>0);h.permission.syncContext();await h.permission.status();assert.equal(h.permission.acknowledge(true),true);assert.equal(await h.permission.allow(),true);
 }finally{await h.close();}}
});
test('delegated timer and hidden tab cannot stop native running work; context still stops same original',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['execute','reconcile']) {const h=await original(kind,'ios',kind==='execute'?'candidate-upload':'current-internal');try{
  await prepare(h);h.permission.acknowledge(true);assert.equal(await h.permission.allow(),true);h.running();h.ctl.setVisible(false);h.time(70000);t.mock.timers.tick(70000);await flush();
  h.ctl.acknowledge(true);await h.ctl.start();assert.deepEqual(h.calls,['prepare','status','allow']);h.changed();await flush();assert.deepEqual(h.calls,['prepare','status','allow','cancel']);
 }finally{await h.close();}}
});
test('ordinary unstarted reviews retain timer and tab-hidden cancellation',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['execute','reconcile'])for(const cut of ['timer','hide']) {const h=await original(kind,'android',kind==='execute'?'candidate-upload':'current-internal');try{
  await prepare(h);if(cut==='timer'){h.time(70000);t.mock.timers.tick(70000);}else h.ctl.setVisible(false);await flush();assert.deepEqual(h.calls,['prepare','status','cancel']);assert.equal(h.permission.acknowledge(true),false);
 }finally{await h.close();}}
});
test('an actual conflicting Prepared or unknown peer is never hidden by selected-kind exemption',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const selected=await original(),peer=await original('reconcile','android','current-internal');
 try{await prepare(selected);await prepare(peer);selected.busy(peer.reason);assert.ok(selected.permission.consentReason());assert.equal(selected.permission.acknowledge(true),false);assert.equal(await selected.permission.allow(),false);peer.bad();await flush();assert.ok(selected.permission.consentReason());assert.deepEqual(selected.calls,['prepare','status']);}
 finally{await selected.close();await peer.close();}
});
test('post-delegation listeners recheck original context, revoke generation and every peer before sole Allow',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['execute','reconcile'])for(const cut of ['revoke','context','peer']) {const h=await original(kind,'android',kind==='execute'?'candidate-upload':'current-internal');try{
  await prepare(h);h.permission.acknowledge(true);let once=false;
  const off=h.ctl.subscribe(()=>{if(!once&&h.ctl.getSnapshot().consentUntil===null){once=true;if(cut==='revoke')void h.permission.revoke();else if(cut==='context')h.changed();else h.busy(()=> 'other original');}});
  assert.equal(await h.permission.allow(),false);await h.permission.whenSettled();off();assert.equal(h.calls.filter(x=>x==='allow').length,0);h.ctl.setVisible(false);h.time(70000);t.mock.timers.tick(70000);await h.ctl.start();assert.equal(h.calls.filter(x=>x==='gui-start').length,0);assert.equal(h.ctl.getSnapshot().consentUntil,null);
 }finally{await h.close();}}
});
test('lost Allow and late revoke never restore GUI Start or discard original caller',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const cut of ['lost','late-revoke']) {const h=await original('reconcile','ios','external-readiness');try{
  const r=await prepare(h),d=deferred();h.port.allow=()=>{h.calls.push('allow');return d.promise;};h.permission.acknowledge(true);const p=h.permission.allow();
  let joined=false;const wait=h.permission.whenSettled().then(()=>{joined=true;});if(cut==='late-revoke')await h.permission.revoke();await flush();assert.equal(joined,false);
  if(cut==='lost')d.reject(Error('inert lost reply'));else d.resolve(access(r));await p;await wait;assert.equal(h.permission.getSnapshot().unknown,cut==='lost');assert.ok(!h.permission.getSnapshot().access?.enabled);
  h.ctl.setVisible(false);h.time(70000);t.mock.timers.tick(70000);await h.ctl.start();assert.equal(h.calls.filter(x=>x==='allow').length,1);assert.equal(h.calls.filter(x=>x==='gui-start').length,0);assert.equal(h.ctl.getSnapshot().consentUntil,null);
 }finally{await h.close();}}
});
test('same selected native result does not settle a still-returning permission caller or authorize replay',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const h=await original();try{
  const r=await prepare(h);h.permission.acknowledge(true);await h.permission.allow();h.setStore(completed(r));const d=deferred();h.port.status=()=>{h.calls.push('status');return d.promise;};const p=h.permission.status();let joined=false;const done=h.permission.whenSettled().then(()=>{joined=true;});await flush();assert.equal(joined,false);assert.equal(h.permission.choose('reconcile'),false);
  d.resolve(completed(r));await p;await done;assert.equal(h.permission.getSnapshot().access.status.state,'complete');assert.deepEqual(storeCommands(h.permission.getSnapshot().access),[`mrk store-status ${P} ${S} ${Q}`,`mrk store-cancel ${P} ${S} ${Q}`]);assert.equal(h.calls.filter(x=>x==='allow').length,1);
 }finally{await h.close();}
});
test('comparison helper is initialization-safe and never excludes a DATA-only or wrong original',()=>{
 const r=review();assert.equal(storeSelectedPeerReason(null,'execute',null,'busy'),'busy');assert.equal(storeSelectedPeerReason(r,'execute',null,'busy'),'busy');
 let calls=0;const original={agentPreparedMatches(id,revision){calls++;return id.operationId===A&&revision===3;}};
 assert.equal(storeSelectedPeerReason(r,'reconcile',original,'busy'),'busy');assert.equal(calls,0);assert.equal(storeSelectedPeerReason(r,'execute',original,'busy'),null);
 assert.equal(storeSelectedPeerReason({...r,statusRevision:4},'execute',original,'busy'),'busy');
});
