// Inert native-port observations only. No account, native process or Store calls.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason } from '../src/localStorePreflight.ts';
import { parseLocalStoreStatus, encodeLocalStoreRequest, STORE_CONSENT } from '../src/localStorePreflightProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32);
const copy=v=>structuredClone(v);
const project=()=>({projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:40,sha256:'b'.repeat(64),source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false});
const assets=()=>({mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:C,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:C,revision:4,availability:'assigned'}]}});
const status=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
const op=request=>({operationId:A,ownerGeneration:B,context:{...copy(request),platform:'android',operation:'local-store-preflight'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});
const terminal=o=>({...o,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});
async function fixture(){let currentAssets=assets(),now=100,listener,latest=status(),cancel=0,start=0,prepareGate=null;
 const controller=new LocalStorePreflightController({project,assets:()=>currentAssets,otherOperationReason:()=>null,now:()=>now});
 const api={mode:'native',subscribeLocalStorePreflight:async f=>{listener=f;return()=>{};},localStorePreflightStatus:async()=>latest,
 prepareLocalStorePreflight:async request=>{if(prepareGate)await prepareGate;latest=status(latest.statusRevision+1,op(request));return copy(latest);},
 startLocalStorePreflight:async request=>{start++;assert.equal(request.consentVersion,STORE_CONSENT);latest=status(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});return copy(latest);},
 cancelLocalStorePreflight:async(a,b)=>{assert.equal(a,A);assert.equal(b,B);cancel++;latest=status(latest.statusRevision+1,terminal(latest.operation));return copy(latest);}};
 await controller.connect(api);controller.syncProject();
 return{controller,api,counts:()=>({start,cancel}),mode:()=>{currentAssets=assets();currentAssets.status.context.executionMode='github';controller.syncProject();},time:v=>now=v,defer:()=>{let release;prepareGate=new Promise(r=>release=r);return release;},emit:v=>{latest=v;listener(copy(v));},latest:()=>copy(latest)};
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
 const h=await fixture();try{assert.equal(h.controller.prepareReason(),null);await h.controller.prepare();h.controller.acknowledge(true);await h.controller.start();await h.controller.start();assert.equal(h.counts().start,1);h.mode();await Promise.resolve();assert.equal(h.controller.getSnapshot().request,null);assert.equal(h.counts().cancel,1);}finally{h.controller.dispose();}
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
