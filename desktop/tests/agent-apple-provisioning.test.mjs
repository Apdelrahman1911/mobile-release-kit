// Real Apple + permission controllers and closed DATA codec. No native, key,
// provider, filesystem, IPC, or private retirement proof is manufactured here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { AgentAppleProvisioningController } from '../src/agentAppleProvisioningController.ts';
import { appleCliModes, appleCliConsent, appleCliEffect, parseAppleCliReview, parseAppleCliStatus, parseAppleCliAccess, createAppleCliPort, appleCliCommands } from '../src/agentAppleProvisioning.ts';
import { APPLE_PROVISIONING_LIMITATIONS, appleProvisioningContext } from '../src/appleProvisioningProtocol.ts';

const clone = v => structuredClone(v), id = c => c.repeat(32);
const wait = () => { let resolve, reject; const promise = new Promise((a,b) => {resolve=a;reject=b;}); return {promise,resolve,reject}; };
const flush = async () => { for(let i=0;i<35;i++) await Promise.resolve(); };
const review = (mode='review') => ({mode,operationId:id('1'),ownerGeneration:id('f'),statusRevision:2,
  savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:30,sha256:'b'.repeat(64),name:'1.2.3',build:4}});
const empty = () => ({serviceInstance:null,projectId:null,grantId:null,reviewId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const allowed = (r=review(), nonce=id('4')) => ({serviceInstance:id('8'),projectId:id('9'),grantId:nonce,reviewId:r.operationId,review:clone(r),enabled:true,remainingMs:250000,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const row = (r=review(), mode='running', revision=1, nonce=id('4')) => ({origin:{projectId:id('9'),serviceInstance:id('8'),requestId:id('5')},grantId:nonce,reviewId:r.operationId,revision,review:clone(r),state:mode,
  settlement:mode==='unknown'?'unknown':mode==='complete'||mode==='cancelled'?'settled':'pending',reason:mode==='unknown'?'cleanup-unknown':mode==='cancelled'?'user-cancelled':'none',
  operation:{operationId:r.operationId,ownerGeneration:r.ownerGeneration,statusRevision:3},outcome:mode==='unknown'?'unknown':mode==='complete'?'complete':mode==='cancelled'?'cancelled':null,
  result:mode==='complete'?{decision:r.mode==='key-recover'?'compared':r.mode==='key-review'?'prepare-review':'review-required',comparison:null,attempt:null,certificateId:null,certificateSha256:null,doNotReplay:true,credentialReady:false}:null,recordAtCompletion:null});
const withRow = s => ({...allowed(s.review,s.grantId),enabled:false,remainingMs:0,consumed:true,pending:s.settlement!=='settled',unknown:s.state==='unknown',requestId:s.origin.requestId,status:clone(s)});
const nativeStatus = (revision, operation=null) => ({schemaVersion:1,statusRevision:revision,availability:operation&&operation.phase!=='terminal'?'busy':'available',operation});
function fixture(t, family='bundle') {
  let p={projectId:'fixture',draftRevision:1,baselineGeneration:2,observationGeneration:3,
    savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{source:'release/version.properties',bytes:30,sha256:'b'.repeat(64),name:'1.2.3',build:4},
    dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false,inputIssue:null};
  const scope={executionMode:'local',platform:'ios',stage:'candidate',purpose:family==='key'||family==='recover'?'provisioning':'store'};
  let assets={mode:'native',scope,contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,entryGeneration:1,
    status:{schemaVersion:3,statusRevision:1,mode:'encrypted',persistence:{state:'unlocked',reason:'none',keyAccess:'read-write'},capability:{available:true,reason:'none'},
      modes:{session:{available:true},encrypted:{available:true}},operation:null,context:{revision:3,projectId:'fixture',...scope},
      assignments:[{kind:'asc-p8',recordId:id('c'),recordRevision:4,contextRevision:3,availability:'available'}],
      records:[{kind:'asc-p8',recordId:id('c'),revision:4,availability:'assigned',storage:'encrypted',label:null,payloadState:'assessed'}]}};
  if(family==='recover')assets.status.records.push({kind:'apple-distribution-key',recordId:id('d'),revision:1,availability:'unassigned',storage:'encrypted',label:null,payloadState:'not-checked'});
  let current=nativeStatus(1), now=100, peer=null, epoch={}, service={}, preview=false;
  let access=empty(), queryStatus=null, allowWait=null, queryWait=null, revokeWait=null, nonce=id('4'), nextOperation=1;
  const calls=[], listeners=[], reads=[], promises=[];
  const savePromise=p=>{promises.push(p);return p;};
  const api={mode:'native',subscribe:async receive=>{listeners.push(receive);return()=>{const i=listeners.indexOf(receive);if(i>=0)listeners.splice(i,1);};},
    status:()=>{reads.push(clone(current));return Promise.resolve(clone(current));},
    prepare:input=>{calls.push(['prepare',clone(input)]);current=nativeStatus(current.statusRevision+1,{operationId:id(String(nextOperation++)),ownerGeneration:id('f'),context:appleProvisioningContext(clone(input)),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null,recovery:null});return Promise.resolve(clone(current));},
    start:input=>{calls.push(['start',input]);return Promise.resolve(clone(current));},
    cancel:input=>{calls.push(['cancel',input]);if(current.operation?.phase!=='terminal'&&current.operation?.phase!=='unknown')current=nativeStatus(current.statusRevision+1,{...current.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});return Promise.resolve(clone(current));}};
  const controller=new AppleProvisioningController({project:()=>p,assets:()=>assets,otherOperationReason:()=>peer,now:()=>now});
  controller.setVisible(true);controller.setDisplayName('Explicit app');const ready=controller.connect(api);
  const port={access:async()=>{calls.push(['access']);return clone(access);},allow:(r,n)=>{calls.push(['allow',clone(r),n]);access=allowed(r,n);return allowWait?savePromise(allowWait.promise):Promise.resolve(clone(access));},
    request:q=>{calls.push(['query',clone(q)]);return queryWait?savePromise(queryWait.promise):Promise.resolve(clone(queryStatus));},
    revoke:n=>{calls.push(['revoke',n]);access={...access,enabled:false,remainingMs:0};return revokeWait?savePromise(revokeWait.promise):Promise.resolve(clone(access));}};
  const permission=new AgentAppleProvisioningController({current:()=>({port,nativeSession:service,projectId:p.projectId,epoch,preview,blockedReason:peer,review:controller.delegationReview()}),
    syncOriginal:controller.syncProject,delegate:controller.delegatePrepared,nonce:()=>nonce});
  t.after(async()=>{for(const pending of [allowWait,queryWait,revokeWait])pending?.reject(new Error('fixture closed'));await Promise.allSettled(promises);await permission.whenSettled();permission.dispose();controller.dispose();await flush();});
  return {controller,permission,ready,calls,reads,api,port,
    get state(){return controller.getSnapshot();},get native(){return clone(current);},get access(){return clone(access);},get view(){return permission.getSnapshot();},
    async prepared(mode=family==='recover'?'key-recover':family==='key'?'key-review':'review'){await ready;if(family==='recover')controller.selectCertificateKey(id('d'),1);await controller.prepare(mode);permission.syncContext();assert.ok(controller.delegationReview());return controller.delegationReview();},
    async allow(){permission.acknowledge(true);assert.equal(permission.allowReason(),null);await permission.allow();},
    grant(v){access=clone(v);},row(v){queryStatus=clone(v);access=withRow(v);},
    complete(){const op=current.operation;const result=op.context.mode==='key-recover'?{schemaVersion:1,scope:'local-ios-distribution-key',mode:'key-recover',decision:'compared',reason:'stored-key-checked',saved:false,certificateRequested:false,credentialReady:false}:op.context.mode==='key-review'?{schemaVersion:1,scope:'local-ios-distribution-key',mode:'key-review',decision:'prepare-review',reason:'local-key-required',saved:false,certificateRequested:false,credentialReady:false}:
      {schemaVersion:1,scope:'local-ios-bundle-provisioning',mode:'review',observation:'not-returned',decision:'review-required',attempt:null,comparison:null,limitations:[...APPLE_PROVISIONING_LIMITATIONS]};
      current=nativeStatus(current.statusRevision+1,{...op,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result});for(const l of [...listeners])l(clone(current));},
    emit(value){current=clone(value);for(const l of [...listeners])l(clone(current));},
    change(patch){p={...p,...patch};controller.syncProject();permission.syncContext();},peer(v){peer=v;},time(v){now=v;},nonce(v){nonce=v;},epoch(){epoch={};permission.syncContext();},preview(){preview=true;permission.syncContext();},
    holdAllow(){return allowWait=wait();},holdQuery(){return queryWait=wait();},holdRevoke(){return revokeWait=wait();},
    keyRevision(value){assets=clone(assets);assets.status.records.find(r=>r.kind==='apple-distribution-key').revision=value;controller.syncProject();permission.syncContext();},
    mutateKey(){assets=clone(assets);assets.contextCurrent=false;assets.status.persistence.state='mutating';assets.status.operation={operationId:5,operation:'prepare-apple-distribution-key',phase:'mutating',reason:'none',source:'captured',settlement:'pending',storageOutcome:{effect:'not-started',durability:'not-run',cleanup:'pending'},selectionToken:null,assessment:null,preview:null};for(const a of assets.status.assignments)a.availability='unavailable';controller.syncProject();},
  };
}

test('all sixteen exact modes have bounded IDs-only review and separate consent; no invented P12 reconcile',()=>{
  assert.equal(appleCliModes.length,16);for(const mode of appleCliModes){assert.ok(parseAppleCliReview(review(mode)));assert.equal(appleCliConsent(mode),`agent-apple-${mode}-once-v1`);}
  for(const mode of ['key-restore','p12-reconcile','prepare','certificate-rotate'])assert.equal(parseAppleCliReview(review(mode)),null);
  assert.equal(parseAppleCliReview({...review(),privateKey:'not allowed'}),null);
});
test('KeyRecover report is compared only with no NEW reference, issuer result or next-step authority',()=>{
  const value=row(review('key-recover'),'complete');assert.ok(parseAppleCliStatus(value));assert.ok(parseAppleCliAccess(withRow(value)));
  for(const decision of ['produced','blocked','comparison-only','reused','assembled'])assert.equal(parseAppleCliStatus({...value,result:{...value.result,decision}}),null);
  for(const [field,data] of [['comparison','same-response'],['attempt',{operationId:id('1'),status:'succeeded',cancellationRequested:false}],['certificateId','existing'],['certificateSha256','a'.repeat(64)],['credentialReady',true],['doNotReplay',false],['recoverySha256','a'.repeat(64)]]){
    assert.equal(parseAppleCliStatus({...value,result:{...value.result,[field]:data}}),null,field);
  }
  const saved={kind:'apple-distribution-key',reference:{vaultId:id('1'),generationId:id('2'),recordId:id('3'),revisionId:id('4'),revisionCounter:1}};
  assert.equal(parseAppleCliStatus({...value,recordAtCompletion:saved}),null);
  assert.equal(parseAppleCliStatus({...value,review:review('key-prepare')}),null);
  assert.match(appleCliEffect('key-recover'),/may append a local verification association/);
  assert.match(appleCliEffect('key-recover'),/Earlier setup history and unrelated uncertainty remain/);
});
test('strict status/access refuses getters, overbounds, foreign IDs, false saved/ref/finality and missing nullable fields',()=>{
  const s=row();assert.ok(parseAppleCliStatus(s));assert.ok(parseAppleCliAccess(withRow(s)));let called=0;
  const evil={...s};Object.defineProperty(evil,'state',{enumerable:true,get(){called++;return 'running';}});assert.equal(parseAppleCliStatus(evil),null);assert.equal(called,0);
  for(const bad of [{...s,reviewId:id('7')},{...s,result:{x:'a'.repeat(9000)}},{...s,state:'complete',settlement:'pending'},
    {...s,recordAtCompletion:{kind:'apple-p12',reference:{vaultId:id('1'),generationId:id('2'),recordId:id('3'),revisionId:id('4'),revisionCounter:1}}}])assert.equal(parseAppleCliStatus(bad),null);
  const missing=clone(s);delete missing.recordAtCompletion;assert.equal(parseAppleCliStatus(missing),null);
  assert.equal(parseAppleCliAccess({...allowed(),reviewId:id('7')}),null);
});
test('RAW facade has only fixed permission calls; commands take retained public IDs, never material',async()=>{
  const calls=[];const p=createAppleCliPort(async(name,bytes)=>{calls.push([name,JSON.parse(new TextDecoder().decode(bytes))]);return {};});
  await p.access();await p.allow(review(),id('4'));await p.request(row().origin);await p.revoke(id('4'));
  assert.deepEqual(calls.map(c=>c[0]),['agent_apple_provisioning_access','allow_agent_apple_provisioning','agent_apple_provisioning_request_status','revoke_agent_apple_provisioning']);
  assert.deepEqual(Object.keys(calls[1][1]),['consentId','mode','operationId','ownerGeneration','expectedStatusRevision','consentVersion']);
  assert.match(appleCliCommands(allowed())[0],/^mrk apple-provisioning-submit .* --reviewed$/);assert.equal(appleCliCommands({...allowed(),enabled:false,remainingMs:0}).length,0);
  await p.allow(review('key-recover'),id('6'));
  assert.equal(calls.at(-1)[1].consentVersion,'agent-apple-key-recover-once-v1');
  assert.equal(calls.at(-1)[1].mode,'key-recover');
  assert.deepEqual(Object.keys(calls.at(-1)[1]),Object.keys(calls[1][1]));
});
test('genuine Prepare delegates exactly once, blocks ordinary Start without fabricating GUI Start, and needs both original final reads',async t=>{
  const h=fixture(t),r=await h.prepared();await h.allow();assert.equal(h.state.consent,null);await h.controller.start(r.operationId,r.ownerGeneration);assert.equal(h.calls.filter(c=>c[0]==='start').length,0);
  h.row(row(r));h.complete();await flush();assert.equal(h.state.result,null);assert.equal(h.state.reviewReference,null);assert.ok(h.controller.ownerReason());
  await h.permission.check();assert.equal(h.state.result,null);
  h.row(row(r,'complete',2));const d=h.holdQuery(),work=h.permission.check();await flush();assert.equal(h.state.result,null);assert.equal(h.view.pending,'check');
  d.resolve(row(r,'complete',2));await work;assert.equal(h.state.result?.decision,'review-required');assert.deepEqual(h.state.reviewReference,{operationId:r.operationId,ownerGeneration:r.ownerGeneration});
  assert.ok(h.calls.filter(c=>c[0]==='query').every(c=>c[1].requestId===id('5')));assert.equal(h.view.pending,null);assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);
});
test('delegated key retains the original mutating Asset comparison without pretending GUI Start returned',async t=>{
  const h=fixture(t,'key'),r=await h.prepared();await h.allow();h.mutateKey();assert.equal(h.state.issue,null);assert.equal(h.state.historical,false);
  h.complete();await flush();assert.equal(h.state.keyTerminalRead,false);h.row(row(r,'complete',1));await h.permission.check();assert.equal(h.state.keyTerminalRead,true);assert.ok(h.state.keyReviewReference);
});
test('selected original KeyRecover delegates Start only and waits for native read plus original service history',async t=>{
  const h=fixture(t,'recover'),r=await h.prepared();
  const selection=h.calls.find(c=>c[0]==='prepare')[1];assert.equal(selection.mode,'key-recover');assert.equal(selection.reference,null);assert.equal(selection.keyRecordId,id('d'));assert.equal(selection.keyRecordRevision,1);
  await h.allow();await h.controller.start(r.operationId,r.ownerGeneration);assert.equal(h.calls.filter(c=>c[0]==='start').length,0);
  h.row(row(r));h.complete();await flush();assert.equal(h.state.keyResult,null);assert.equal(h.state.keyTerminalRead,false);
  await h.permission.check();assert.equal(h.state.keyResult,null);
  h.row(row(r,'complete',2));const d=h.holdQuery(),w=h.permission.check();await flush();assert.equal(h.state.keyTerminalRead,false);d.resolve(row(r,'complete',2));await w;
  assert.equal(h.state.keyTerminalRead,true);assert.equal(h.state.keyResult.decision,'compared');assert.equal(h.state.savedKey,null);
  assert.equal(h.state.keyReviewReference,null);assert.equal(h.state.certificateReviewReference,null);assert.equal(h.state.p12ReviewReference,null);
  assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);assert.equal(h.calls.filter(c=>c[0]==='prepare').length,1);
  await h.controller.prepare('certificate-create');assert.equal(h.calls.filter(c=>c[0]==='prepare').length,1);
});
test('KeyRecover changed selected key and lost original permission never regenerate or become a new grant',async t=>{
  for(const cut of ['key','lost']){const h=fixture(t,'recover');await h.prepared();
    if(cut==='key'){h.permission.acknowledge(true);h.keyRevision(2);await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);}
    else{const d=h.holdAllow();h.permission.acknowledge(true);const w=h.permission.allow();d.reject(new Error('inert lost KeyRecover permission'));await w;assert.equal(h.view.unknown,true);await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);}
    assert.equal(h.state.keyResult,null);assert.equal(h.state.savedKey,null);assert.equal(h.calls.filter(c=>c[0]==='start').length,0);
  }
});
test('follow-on freshness uses delegation time, never late Status receipt time',async t=>{
  const h=fixture(t),r=await h.prepared();h.time(500);await h.allow();h.time(300501);h.complete();h.row(row(r,'complete'));await h.permission.check();assert.equal(h.state.result?.decision,'review-required');assert.equal(h.state.reviewReference,null);
});
test('native event cannot finish an outstanding Allow; original promises survive cancellation',async t=>{
  const h=fixture(t),r=await h.prepared(),d=h.holdAllow();h.permission.acknowledge(true);const work=h.permission.allow();await flush();assert.equal(h.view.pending,'allow');
  h.complete();await flush();assert.equal(h.state.result,null);assert.ok(h.permission.checkReason());
  const revoke=h.permission.revoke();await revoke;assert.equal(h.view.withdrawn,true);assert.equal(h.view.pending,'allow');
  d.resolve(allowed(r));await work;assert.equal(h.view.revoked,true);assert.equal(h.view.access.enabled,false);assert.equal(h.state.result,null);
});
test('lost Allow is absorbing unconfirmed, no automatic Submit/Start or review restoration',async t=>{
  const h=fixture(t);await h.prepared();const d=h.holdAllow();h.permission.acknowledge(true);const work=h.permission.allow();d.reject(new Error('lost'));await work;
  assert.equal(h.view.unknown,true);assert.ok(h.state.issue);await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);assert.equal(h.calls.filter(c=>c[0]==='start').length,0);
});
test('reentrant original context/peer change before Allow never sends or overwrites a newer consent',async t=>{
  const h=fixture(t);await h.prepared();h.permission.acknowledge(true);let once=true;const off=h.permission.subscribe(()=>{if(once&&h.view.pending==='allow'){once=false;h.peer('another owner');}});
  await h.permission.allow();off();assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);assert.ok(h.controller.delegationReview()===null);assert.equal(h.view.pending,null);
});
test('delegation notification refuses reentrant ordinary Start on the same prepared intent',async t=>{
  const h=fixture(t),r=await h.prepared();let once=true;const off=h.controller.subscribe(()=>{if(once&&!h.state.consent&&h.state.retained){once=false;void h.controller.start(r.operationId,r.ownerGeneration);}});
  await h.allow();off();assert.equal(h.calls.filter(c=>c[0]==='start').length,0);assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);
});
test('unconsumed known withdrawal closes only through exact Access then actual original native read',async t=>{
  const h=fixture(t);await h.prepared();await h.allow();await h.permission.revoke();await h.controller.cancel();assert.ok(h.controller.ownerReason());await h.permission.check();assert.equal(h.controller.ownerReason(),null);assert.equal(h.state.reviewReference,null);assert.equal(h.state.result,null);
});
test('final A is queried by exact retained address even if latest permission metadata could become B',async t=>{
  const h=fixture(t),r=await h.prepared();await h.allow();h.row(row(r));await h.permission.check();h.complete();const final=row(r,'complete',2);h.row(final);await h.permission.check();
  const next={...review(),operationId:id('2')};h.grant(allowed(next,id('6')));await h.permission.check();assert.equal(h.view.status.review.operationId,r.operationId);assert.equal(h.view.unknown,false);assert.equal(h.calls.at(-1)[0],'query');
});
test('new prepared B needs exact returned withdrawal of A; consumed status is not Revoke acknowledgment',async t=>{
  const h=fixture(t),r=await h.prepared();await h.allow();h.complete();h.row(row(r,'complete'));await h.permission.check();
  await h.controller.prepare('review');h.permission.syncContext();assert.ok(h.permission.consentReason());const d=h.holdRevoke(),w=h.permission.revoke();await flush();assert.ok(h.permission.consentReason());d.resolve({...withRow(row(r,'complete')),enabled:false,remainingMs:0});await w;
  h.nonce(id('6'));h.permission.acknowledge(true);assert.equal(h.permission.allowReason(),null);await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='allow').length,2);
});
test('foreign/unknown original status cannot settle native controller or authorize the next step',async t=>{
  const h=fixture(t),r=await h.prepared();await h.allow();h.complete();const unknown=row(r,'unknown');h.row(unknown);await h.permission.check();assert.equal(h.view.unknown,true);assert.equal(h.state.reviewReference,null);assert.ok(h.state.issue);
});
test('context ABA after delegation preserves exact controls but cannot turn final history into current review',async t=>{
  const h=fixture(t),r=await h.prepared();await h.allow();h.change({observationGeneration:4});h.change({observationGeneration:3});await flush();
  const cancelled=row(r,'cancelled');cancelled.operation.statusRevision=h.native.statusRevision;h.row(cancelled);await h.permission.check();assert.equal(h.state.reviewReference,null);assert.equal(h.state.historical,true);assert.equal(h.controller.ownerReason(),null);
});
test('browser preview and a displayed old result cannot create a delegation review',async t=>{
  const h=fixture(t);await h.prepared();h.preview();h.permission.acknowledge(true);await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);h.time(60101);assert.equal(h.controller.delegationReview(),null);
});

test('peer veto after delegated-origin publication closes the real unused Prepared, not a fabricated Allow return',async t=>{
  const h=fixture(t);await h.prepared();let once=true;const off=h.controller.subscribe(()=>{if(once&&!h.state.consent&&h.state.retained){once=false;h.peer('new owner');}});
  await h.allow();off();await flush();assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);assert.equal(h.calls.filter(c=>c[0]==='start').length,0);
  assert.equal(h.calls.filter(c=>c[0]==='cancel').length,1);assert.equal(h.controller.ownerReason(),null);assert.equal(h.permission.ownerReason(),null);assert.equal(h.state.reviewReference,null);
});
