// Inert native-port tests only: no filesystem, Keychain, process or Store calls.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStorePrepareController, localStorePrepareRequest, localStorePrepareOwnerReason } from '../src/localStorePrepare.ts';
import { encodeLocalStorePrepareRequest, parseLocalStorePrepareStatus, STORE_PREPARE_CONSENT } from '../src/localStorePrepareProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';

const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),UUID='12345678-1234-4234-8234-123456789abc';
const copy=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false});
const assets=()=>({mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:C,revision:4,availability:'assigned'}]}});
const candidate=()=>({operationId:UUID,candidateSha256:'a'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},files:[{fileName:'app-release.aab',bytes:100,sha256:'d'.repeat(64)},{fileName:'store-metadata.zip',bytes:100,sha256:'e'.repeat(64)},{fileName:'validation-report.json',bytes:100,sha256:'f'.repeat(64)}],observation:'current-bundle-only',priorCreateFinality:'not-established'});
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const history=()=>({mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:status(1,{operationId:C,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-inputs',candidateOperationId:UUID},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:3,history:[{operationId:UUID,phase:'inputs-ready',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],candidateInputs:candidate()}})});
const op=request=>({operationId:A,ownerGeneration:B,context:{...copy(request),platform:'android',operation:'local-store-prepare'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const terminal=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});
const complete=o=>({...o,phase:'terminal',intentUsable:false,outcome:'complete',result:{schemaVersion:1,scope:'local-android-store-prepare',headSequence:5,preparedIntent:{operationId:UUID,candidateSha256:'a'.repeat(64),intentSha256:'b'.repeat(64),storePreconditionSha256:'c'.repeat(64),sourceCommit:'b'.repeat(40),sourceTree:'c'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},destination:{channel:'internal',releaseStatus:'completed'},observedAt:'2026-10-16T20:00:00Z',limitations:['non-publishing','prepare-not-execute','temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic']}}});
async function fixture(){let p=project(),a=assets(),h=history(),now=100,listener,latest=status(),cancel=0,start=0,prepareGate=null,other=null;
 const controller=new LocalStorePrepareController({project:()=>p,assets:()=>a,history:()=>h,otherOperationReason:()=>other,now:()=>now});
 const api={mode:'native',subscribeLocalStorePrepare:async f=>{listener=f;return()=>{};},localStorePrepareStatus:async()=>latest,
 prepareLocalStorePrepare:async request=>{if(prepareGate)await prepareGate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStorePrepare:async request=>{start++;assert.equal(request.consentVersion,STORE_PREPARE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
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
