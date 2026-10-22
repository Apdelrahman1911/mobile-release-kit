// Actual original frontend controllers with inert API promises and bounded
// public DATA only. No Host, credential, provider, IPC or native finality proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { AgentApplePreparationController } from '../src/agentApplePreparationController.ts';
import { AgentAppleProvisioningController } from '../src/agentAppleProvisioningController.ts';
import { appleCliModes } from '../src/agentAppleProvisioning.ts';
import { APPLE_PREPARATION_EVENT, applePreparationCommands, applePreparationSelection, createApplePreparationPort, parseApplePreparationAccess, parseApplePreparationStatus } from '../src/agentApplePreparation.ts';
import { APPLE_PROVISIONING_LIMITATIONS, appleProvisioningContext } from '../src/appleProvisioningProtocol.ts';

const id=c=>c.repeat(32),clone=v=>structuredClone(v);
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<40;i++)await Promise.resolve();};
const query={projectId:id('9'),serviceInstance:id('8'),requestId:id('5')};
const review=(mode='review')=>({mode,operationId:id('1'),ownerGeneration:id('f'),statusRevision:2,savedConfig:{bytes:100,sha256:'a'.repeat(64)},savedVersion:{bytes:30,sha256:'b'.repeat(64),name:'1.2.3',build:4}});
const row=(phase='queued',revision=1,mode='review')=>({origin:clone(query),grantId:id('4'),scopeId:id('6'),mode,revision,phase,
  settlement:phase==='unknown'?'unknown':['prepared','refused'].includes(phase)?'settled':'pending',reason:phase==='unknown'?'cleanup-unknown':phase==='refused'?'native-refused':'none',
  prepared:phase==='prepared'?review(mode):null,usable:phase==='prepared',handedOff:false});
const access=(status,mode='review')=>({serviceInstance:id('8'),projectId:id('9'),grantId:id('4'),scopeId:id('6'),mode:status?.mode??mode,enabled:status===null,remainingMs:status===null?250000:0,status:clone(status)});
const empty=()=>({serviceInstance:null,projectId:null,grantId:null,scopeId:null,mode:null,enabled:false,remainingMs:0,status:null});
const nativeStatus=(revision=1,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:operation&&operation.phase!=='terminal'?'busy':'available',operation});
function fixture(t,mode='review'){
  let project={projectId:'fixture',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:'a'.repeat(64)},
    savedVersion:{source:'release/version.properties',bytes:30,sha256:'b'.repeat(64),name:'1.2.3',build:4},dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false,inputIssue:null};
  const assets={mode:'native',scope:{executionMode:'local',platform:'ios',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,entryGeneration:1,
    status:{mode:'session',capability:{available:true},modes:{session:{available:true}},operation:null,context:{revision:3,projectId:'fixture',executionMode:'local',platform:'ios',stage:'candidate',purpose:'store'},
      assignments:[{kind:'asc-p8',recordId:id('c'),recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'asc-p8',recordId:id('c'),revision:4,availability:'assigned'}]}};
  if(mode==='key-recover'){
    assets.scope.purpose=assets.status.context.purpose='provisioning';
    Object.assign(assets.status,{schemaVersion:3,statusRevision:1,mode:'encrypted',persistence:{state:'unlocked',reason:'none',keyAccess:'read-write'}});
    assets.status.modes.encrypted={available:true};
    Object.assign(assets.status.records[0],{storage:'encrypted',label:null,payloadState:'assessed'});
    assets.status.records.push({kind:'apple-distribution-key',recordId:id('d'),revision:1,availability:'unassigned',storage:'encrypted',label:null,payloadState:'not-checked'});
  }
  let current=nativeStatus(),grant=empty(),status=null,selection=null,epoch={},service={},peer=null,preview=false,now=100;
  let allowWait=null,revokeWait=null,queryWait=null,readWait=null,callWait=null;
  const calls=[],nativeListeners=[],events=[],pending=[];
  const held=w=>{pending.push(w);return w.promise;};
  const api={mode:'native',subscribe:async f=>{nativeListeners.push(f);return()=>{nativeListeners.splice(nativeListeners.indexOf(f),1);};},
    status:()=>{calls.push(['native-read']);const r=readWait;readWait=null;return r?held(r):Promise.resolve(clone(current));},
    prepare:r=>{calls.push(['ordinary-prepare',clone(r)]);return Promise.resolve(clone(current));},
    prepareDelegated:q=>{calls.push(['native-prepare',clone(q)]);callWait=deferred();return held(callWait);},
    start:r=>{calls.push(['native-start',clone(r)]);complete();return Promise.resolve(clone(current));},
    cancel:r=>{calls.push(['native-cancel',clone(r)]);if(current.operation)current=nativeStatus(current.statusRevision+1,{...current.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',result:null});return Promise.resolve(clone(current));}};
  const controller=new AppleProvisioningController({project:()=>project,assets:()=>assets,otherOperationReason:()=>peer,now:()=>now});
  controller.setVisible(true);controller.setDisplayName('Selected app');const connected=controller.connect(api);
  const port={subscribe:async f=>{events.push(f);return()=>{events.splice(events.indexOf(f),1);};},access:async()=>{calls.push(['access']);return clone(grant);},
    allow:(s,n)=>{calls.push(['allow',clone(s),n]);selection=clone(s);grant=access(null,mode);return allowWait?held(allowWait):Promise.resolve(clone(grant));},
    request:q=>{calls.push(['query',clone(q)]);return queryWait?held(queryWait):Promise.resolve(clone(status));},
    revoke:n=>{calls.push(['revoke',n]);grant={...grant,enabled:false,remainingMs:0};return revokeWait?held(revokeWait):Promise.resolve(clone(grant));}};
  const permission=new AgentApplePreparationController({current:()=>({port,session:service,epoch,projectId:project.projectId,preview,blockedReason:peer}),
    syncOriginal:controller.syncProject,selection:controller.preparationSelection,reserve:controller.reservePreparation,nonce:()=>id('4')});
  let startGrant=null,startRow=null;
  const startPort={access:async()=>clone(startGrant),allow:async(r,n)=>{calls.push(['start-allow',clone(r),n]);startGrant={serviceInstance:id('8'),projectId:id('9'),grantId:n,reviewId:r.operationId,review:clone(r),enabled:true,remainingMs:200000,consumed:false,pending:false,unknown:false,requestId:null,status:null};return clone(startGrant);},
    request:async q=>{calls.push(['start-query',clone(q)]);return clone(startRow);},revoke:async()=>({...startGrant,enabled:false,remainingMs:0})};
  const startPermission=new AgentAppleProvisioningController({current:()=>({port:startPort,nativeSession:service,projectId:project.projectId,epoch,preview,blockedReason:peer,review:controller.delegationReview()}),
    syncOriginal:controller.syncProject,delegate:controller.delegatePrepared,nonce:()=>id('7')});
  function complete(){const op=current.operation;current=nativeStatus(current.statusRevision+1,{...op,phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',
    result:mode==='key-recover'?{schemaVersion:1,scope:'local-ios-distribution-key',mode:'key-recover',decision:'compared',reason:'stored-key-checked',saved:false,certificateRequested:false,credentialReady:false}:
      {schemaVersion:1,scope:'local-ios-bundle-provisioning',mode:'review',observation:'not-returned',decision:'review-required',attempt:null,comparison:null,limitations:[...APPLE_PROVISIONING_LIMITATIONS]}});for(const f of [...nativeListeners])f(clone(current));}
  function setRow(v){status=clone(v);grant={...access(status,mode),enabled:false,remainingMs:0};}
  t.after(async()=>{for(const w of pending)w.reject(new Error('inert fixture closed'));await Promise.allSettled(pending.map(w=>w.promise));await flush();await permission.whenSettled();await startPermission.whenSettled();permission.dispose();startPermission.dispose();controller.dispose();await flush();});
  return {controller,permission,startPermission,api,port,calls,
    get view(){return permission.getSnapshot();},get state(){return controller.getSnapshot();},get native(){return clone(current);},get selection(){return clone(selection);},
    async ready(){await connected;await permission.whenSettled();if(mode==='key-recover')controller.selectCertificateKey(id('d'),1);permission.setMode(mode);permission.syncContext();assert.ok(permission.getSnapshot().selection);},
    async allow(){permission.acknowledge(true);assert.equal(permission.allowReason(),null);assert.equal(await permission.allow(),true);},
    queue(){setRow(row('queued',1,mode));},setRow,emit(v){setRow(v);for(const f of [...events])f(clone(v));},
    replyPrepare(){assert.ok(callWait);current=nativeStatus(2,{operationId:id('1'),ownerGeneration:id('f'),context:appleProvisioningContext(selection),phase:'awaiting-consent',intentUsable:false,outcome:null,reason:'none',result:null,recovery:null});callWait.resolve(clone(current));},
    replyNoPreparation(){assert.ok(callWait);callWait.resolve(clone(current));},losePrepare(){callWait.reject(new Error('lost original'));},
    joined(){current=nativeStatus(3,{...current.operation,intentUsable:true});setRow(row('prepared',3,mode));},
    emitNative(value){current=clone(value);for(const f of [...nativeListeners])f(clone(current));},
    async prepared(){await this.ready();await this.allow();this.queue();const w=permission.check();await flush();assert.equal(calls.filter(c=>c[0]==='native-prepare').length,1);this.replyPrepare();await w;this.joined();await permission.check();return controller.delegationReview();},
    finishDelegated(){const r=controller.delegationReview()??startGrant.review;complete();startRow={origin:{...query,requestId:id('2')},grantId:id('7'),reviewId:r.operationId,revision:2,review:clone(r),state:'complete',settlement:'settled',reason:'none',operation:{operationId:r.operationId,ownerGeneration:r.ownerGeneration,statusRevision:current.statusRevision},outcome:'complete',
      result:{decision:mode==='key-recover'?'compared':'review-required',comparison:null,attempt:null,certificateId:null,certificateSha256:null,doNotReplay:true,credentialReady:false},recordAtCompletion:null};startGrant={...startGrant,enabled:false,remainingMs:0,consumed:true,pending:false,requestId:id('2'),status:clone(startRow)};},
    holdAllow(){return allowWait=deferred();},holdRevoke(){return revokeWait=deferred();},holdQuery(){return queryWait=deferred();},holdRead(){return readWait=deferred();},
    project(p){project={...project,...p};controller.syncProject();permission.syncContext();},peer(v){peer=v;},time(v){now=v;},epoch(){epoch={};permission.syncContext();},replaceService(){service={};permission.syncContext();},preview(){preview=true;permission.syncContext();},
    keyRevision(value){assets.status.records.find(r=>r.kind==='apple-distribution-key').revision=value;controller.syncProject();permission.syncContext();},
  };
}

test('Prepare status has exactly sixteen modes and bounded redacted DATA, never Start authority',()=>{
  assert.equal(appleCliModes.length,16);
  for(const mode of appleCliModes){const s=row('prepared');s.mode=mode;s.prepared.mode=mode;assert.ok(parseApplePreparationStatus(s));}
  for(const mode of ['key-restore','p12-reconcile','rotate','prepare'])assert.equal(parseApplePreparationStatus({...row(),mode}),null);
  for(const delta of [{usable:true},{phase:'prepared'},{prepared:review()},{settlement:'settled'},{privateKey:'x'},{revision:-0}])assert.equal(parseApplePreparationStatus({...row(),...delta}),null);
  const s=row('prepared');assert.equal(parseApplePreparationStatus({...s,prepared:{...s.prepared,mode:'key-review'}}),null);
  assert.equal(parseApplePreparationStatus({...s,handedOff:true}),null);assert.ok(parseApplePreparationStatus({...s,handedOff:true,usable:false}));
});
test('strict new codec refuses getters/unknown properties and mismatched access without invoking a getter',()=>{
  let touched=0;const s=row();Object.defineProperty(s,'mode',{enumerable:true,get(){touched++;return 'review';}});
  assert.equal(parseApplePreparationStatus(s),null);assert.equal(touched,0);
  assert.ok(parseApplePreparationAccess(empty()));assert.ok(parseApplePreparationAccess(access(null)));
  for(const delta of [{remainingMs:300001},{scopeId:id('a')},{mode:'key-review'},{enabled:true},{status:{...row(),x:'a'.repeat(13000)}}])assert.equal(parseApplePreparationAccess({...access(row()),...delta}),null);
});
test('Prepare port uses existing fixed RAW commands; CLI command carries only scalar addresses',async()=>{
  const calls=[];let event;const p=createApplePreparationPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return{};},async(e)=>{event=e;return()=>{};});
  await p.access();await p.request(query);await p.revoke(id('4'));await p.subscribe(()=>{});
  assert.equal(event,APPLE_PREPARATION_EVENT);assert.deepEqual(calls.map(c=>c[0]),['agent_apple_provisioning_access','agent_apple_provisioning_request_status','revoke_agent_apple_provisioning']);
  assert.deepEqual(calls[1][1],{intent:'agent-apple-prepare',origin:query});assert.equal(applePreparationCommands(access(null))[0],`mrk apple-provisioning-prepare ${id('9')} ${id('8')} ${id('4')} ${id('6')} --reviewed`);
  assert.equal(applePreparationCommands(access(row())).length,2);assert.equal(applePreparationSelection({mode:'review',path:'/anything'}),null);
});
test('Allow alone starts nothing; exact queued request uses the genuine MAIN API once',async t=>{
  const h=fixture(t);await h.ready();await h.allow();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,0);assert.ok(h.controller.ownerReason());
  await h.controller.prepare('review');assert.equal(h.calls.filter(c=>c[0]==='ordinary-prepare').length,0);
  h.queue();const w=h.permission.check();await flush();assert.deepEqual(h.calls.find(c=>c[0]==='native-prepare')[1],query);assert.equal(h.state.requestPending,true);
  h.replyPrepare();await w;assert.equal(h.state.consent,null);assert.equal(h.controller.delegationReview(),null);
  h.joined();await h.permission.check();assert.ok(h.state.consent);assert.equal(h.state.consent.acknowledged,false);assert.ok(h.controller.delegationReview());
  await h.permission.check();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,1);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
});
test('completed delegated Prepare hands the exact original to ordinary explicit Start, never auto-Start',async t=>{
  const h=fixture(t),r=await h.prepared();assert.ok(r);await h.controller.start(r.operationId,r.ownerGeneration);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
  h.controller.acknowledge(r.operationId,r.ownerGeneration,true);await h.controller.start(r.operationId,r.ownerGeneration);
  assert.equal(h.calls.filter(c=>c[0]==='native-start').length,1);assert.equal(h.state.result?.decision,'review-required');
  await h.permission.revoke();assert.equal(h.calls.filter(c=>c[0]==='native-cancel').length,0);assert.equal(h.state.result?.decision,'review-required');
});
test('completed Prepare needs independent Start delegation Allow and original Start history, without GUI impersonation',async t=>{
  const h=fixture(t),r=await h.prepared();h.startPermission.syncContext();h.startPermission.acknowledge(true);assert.equal(h.startPermission.allowReason(),null);await h.startPermission.allow();
  assert.equal(h.calls.filter(c=>c[0]==='start-allow').length,1);assert.equal(h.state.consent,null);await h.controller.start(r.operationId,r.ownerGeneration);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
  h.finishDelegated();assert.equal(h.state.result,null);await h.startPermission.check();assert.equal(h.state.result?.decision,'review-required');
  await h.permission.revoke();assert.equal(h.calls.filter(c=>c[0]==='native-cancel').length,0);
});
test('KeyRecover selected null-reference Prepare remains separate from explicit ordinary Start',async t=>{
  const h=fixture(t,'key-recover');await h.ready();const s=h.view.selection;
  assert.equal(s.mode,'key-recover');assert.equal(s.reference,null);assert.equal(s.keyRecordId,id('d'));assert.equal(s.keyRecordRevision,1);
  for(const delta of [{reference:{operationId:id('1'),ownerGeneration:id('f')}},{keyRecordId:null},{keyRecordRevision:0},{newApplication:true}])assert.equal(applePreparationSelection({...s,...delta}),null);
  await h.allow();h.queue();const w=h.permission.check();await flush();assert.deepEqual(h.calls.find(c=>c[0]==='native-prepare')[1],query);
  assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);h.replyPrepare();await w;assert.equal(h.controller.delegationReview(),null);
  h.joined();await h.permission.check();const r=h.controller.delegationReview();assert.equal(r.mode,'key-recover');
  await h.controller.start(r.operationId,r.ownerGeneration);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
  h.controller.acknowledge(r.operationId,r.ownerGeneration,true);await h.controller.start(r.operationId,r.ownerGeneration);
  assert.equal(h.calls.find(c=>c[0]==='native-start')[1].consentVersion,'local-ios-key-recover-v1');
  assert.equal(h.state.keyResult.decision,'compared');assert.equal(h.state.savedKey,null);assert.equal(h.state.keyReviewReference,null);assert.equal(h.state.certificateReviewReference,null);
  await h.permission.revoke();assert.equal(h.calls.filter(c=>c[0]==='native-cancel').length,0);
});
test('KeyRecover CLI Prepare then separate Start grant never fabricates GUI Start or a saved key',async t=>{
  const h=fixture(t,'key-recover'),r=await h.prepared();h.startPermission.syncContext();h.startPermission.acknowledge(true);await h.startPermission.allow();
  assert.equal(h.calls.find(c=>c[0]==='start-allow')[1].mode,'key-recover');assert.equal(h.state.consent,null);
  h.finishDelegated();assert.equal(h.state.keyTerminalRead,false);assert.equal(h.state.keyResult,null);await h.startPermission.check();
  assert.equal(h.state.keyTerminalRead,true);assert.equal(h.state.keyResult.decision,'compared');assert.equal(h.state.savedKey,null);
  assert.equal(h.state.keyReviewReference,null);assert.equal(h.state.certificateReviewReference,null);assert.equal(h.state.p12ReviewReference,null);
  await h.controller.start(r.operationId,r.ownerGeneration);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
  await h.permission.revoke();assert.equal(h.calls.filter(c=>c[0]==='native-cancel').length,0);
});
test('KeyRecover Prepare event is not original return; changed key and lost caller cannot authorize another action',async t=>{
  const h=fixture(t,'key-recover');await h.ready();await h.allow();h.queue();const w=h.permission.check();await flush();
  h.emit(row('prepared',3,'key-recover'));await flush();assert.equal(h.state.requestPending,true);assert.equal(h.state.consent,null);assert.equal(h.controller.delegationReview(),null);
  h.losePrepare();await w;await flush();await h.permission.whenSettled();assert.ok(h.state.issue);assert.ok(h.controller.ownerReason());assert.equal(h.state.consent,null);assert.equal(h.state.keyResult,null);assert.equal(h.state.savedKey,null);
  await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,1);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
  const changed=fixture(t,'key-recover');await changed.ready();await changed.allow();changed.keyRevision(2);changed.queue();await changed.permission.check();
  assert.equal(changed.calls.filter(c=>c[0]==='native-prepare').length,0);assert.equal(changed.state.consent,null);
});
test('Prepared event and history before actual RAW return cannot give consent or settle the caller',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.queue();const w=h.permission.check();await flush();
  h.emit(row('prepared',3));await flush();assert.equal(h.state.requestPending,true);assert.equal(h.state.consent,null);assert.equal(h.controller.delegationReview(),null);
  h.replyPrepare();h.joined();await w;await flush();await h.permission.whenSettled();assert.ok(h.state.consent);assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,1);
});
test('returned RAW without history and history without matching native read remain unusable',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.queue();const w=h.permission.check();await flush();h.replyPrepare();await w;
  h.setRow(row('finishing',2));await h.permission.check();assert.equal(h.state.consent,null);assert.equal(h.controller.delegationReview(),null);
  h.setRow(row('prepared',3));await h.permission.check();assert.equal(h.state.consent,null);assert.equal(h.controller.delegationReview(),null);
});
test('post-history native status read must actually return before consent is offered',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.queue();const w=h.permission.check();await flush();h.replyPrepare();await w;h.joined();
  const d=h.holdRead(),checking=h.permission.check();await flush();assert.equal(h.state.reading,true);assert.equal(h.state.consent,null);d.resolve(h.native);await checking;assert.ok(h.state.consent);
});
test('queued before Allow return waits for that exact original and does not create a second caller',async t=>{
  const h=fixture(t);await h.ready();const d=h.holdAllow();h.permission.acknowledge(true);const w=h.permission.allow();await flush();h.emit(row());await flush();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,0);
  d.resolve(access(row()));await w;await flush();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,1);h.replyPrepare();h.joined();await flush();await h.permission.whenSettled();
});
test('lost Allow/RAW/query remain Unknown and never replay Prepare or restore previous consent',async t=>{
  for(const cut of ['allow','raw','query']){const h=fixture(t);await h.ready();
    if(cut==='allow'){const d=h.holdAllow();h.permission.acknowledge(true);const w=h.permission.allow();d.reject(new Error('lost'));await w;}
    else{await h.allow();h.queue();if(cut==='query'){const d=h.holdQuery(),w=h.permission.check();d.reject(new Error('lost'));await w;}else{const w=h.permission.check();await flush();h.losePrepare();await w;}}
    assert.ok(h.state.issue);assert.equal(h.state.consent,null);await h.permission.allow();assert.equal(h.calls.filter(c=>c[0]==='allow').length,1);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
  }
});
test('revoke before first queued native call allows only its known no-Host refusal return',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.queue();await h.permission.revoke();await flush();
  assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,1);h.replyNoPreparation();await flush();await h.permission.whenSettled();
  h.setRow(row('refused',3));await h.permission.check();assert.equal(h.state.issue,null);assert.equal(h.state.consent,null);assert.equal(h.controller.ownerReason(),null);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
});
test('reentrant peer veto after reservation prevents Allow and disposes only unsubmitted metadata',async t=>{
  const h=fixture(t);await h.ready();let once=true;const off=h.controller.subscribe(()=>{if(once&&h.controller.ownerReason()){once=false;h.peer('foreign owner');}});
  h.permission.acknowledge(true);await h.permission.allow();off();assert.equal(h.calls.filter(c=>c[0]==='allow').length,0);assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,0);assert.equal(h.controller.ownerReason(),null);
});
test('project ABA, service replacement and preview after scope Allow cannot dispatch on new context',async t=>{
  for(const cut of ['aba','service','preview']){const h=fixture(t);await h.ready();await h.allow();
    if(cut==='aba'){h.project({observationGeneration:4});h.project({observationGeneration:3});}else if(cut==='service')h.replaceService();else h.preview();
    h.queue();await h.permission.check();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,0);assert.equal(h.state.consent,null);
  }
});
test('native connection cannot be replaced while an exact unused preparation scope remains retained',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.controller.beginConnection();assert.ok(h.controller.ownerReason());assert.equal(h.controller.preparationSelection('review'),null);
  h.queue();await h.permission.check();assert.equal(h.calls.filter(c=>c[0]==='native-prepare').length,0);
});
test('service status cannot redirect old query to a foreign operation, mode, scope or lower revision',async t=>{
  for(const cut of ['operation','mode','scope','revision']){const h=fixture(t);await h.prepared();let s=row('prepared',4);
    if(cut==='operation')s.prepared.operationId=id('3');else if(cut==='mode'){s.mode='key-review';s.prepared.mode='key-review';}else if(cut==='scope')s.scopeId=id('a');else s.revision=1;
    h.setRow(s);await h.permission.check();assert.equal(h.view.unknown,true);assert.ok(h.state.issue);assert.equal(h.state.consent,null);
  }
});
test('original local consent deadline is not renewed by a late completed preparation status',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.queue();const w=h.permission.check();await flush();h.replyPrepare();await w;h.time(60200);h.joined();await h.permission.check();
  assert.equal(h.state.consent,null);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);assert.equal(h.calls.filter(c=>c[0]==='native-cancel').length,1);
});
test('one unpublished transition never permits a second false-to-true or changes ordinary progress',async t=>{
  const h=fixture(t);await h.prepared();const before=h.native;
  h.emitNative(nativeStatus(4,{...before.operation,intentUsable:false}));
  h.emitNative(nativeStatus(5,{...before.operation,intentUsable:true}));
  assert.ok(h.state.issue);assert.equal(h.state.consent,null);assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);
});
test('Prepare consent is clipped to its original scope anchor, not a late native reply',async t=>{
  const h=fixture(t);await h.ready();await h.allow();h.time(299900);h.queue();const w=h.permission.check();await flush();h.replyPrepare();await w;h.joined();await h.permission.check();
  assert.ok(h.state.consent);h.controller.acknowledge(id('1'),id('f'),true);h.time(300101);await h.controller.start(id('1'),id('f'));
  assert.equal(h.calls.filter(c=>c[0]==='native-start').length,0);assert.notEqual(h.state.startReason,null);
});
