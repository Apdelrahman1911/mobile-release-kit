// Inert protocol/port/controllers only. No CLI, IPC, Store, provider or native calls.
import assert from 'node:assert/strict';
import test from 'node:test';
import {parseStoreReview,parseAgentStoreAccess,storeReviewFromState,storeConsent,storeCommands,createAgentStoreAccessPort} from '../src/agentStoreAccess.ts';
import {AgentStoreAccessController} from '../src/agentStoreAccessController.ts';
import {LocalStorePreflightController} from '../src/localStorePreflight.ts';
import {LocalStorePrepareController} from '../src/localStorePrepare.ts';
const A='a'.repeat(32),B='b'.repeat(32),P='1'.repeat(32),S='2'.repeat(32),G='3'.repeat(32),R='4'.repeat(32),Q='5'.repeat(32);
const H='c'.repeat(64),UUID='12345678-1234-4234-8234-123456789abc';
const limits=['non-publishing','no-project-commands','no-build-or-signing','no-release-readiness','point-in-time-account-access','saved-inputs-not-atomic'];
const clone=v=>structuredClone(v);
const review=(kind='access-check',platform='android')=>({kind,platform,operationId:A,ownerGeneration:B,statusRevision:3,savedConfig:{bytes:100,sha256:H},savedVersion:{bytes:40,sha256:H,name:'1.2.3',build:42},candidate:kind==='access-check'?null:{operationId:UUID,sha256:H}});
const empty=()=>({permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,reviewId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const access=(r=review(),extra={})=>({permissionRevision:'1',serviceInstance:S,projectId:P,grantId:G,reviewId:R,review:r,enabled:true,remainingMs:200000,consumed:false,pending:false,unknown:false,requestId:null,status:null,...extra});
const result=r=>r.kind==='access-check'?{kind:r.kind,findings:[{check:'store-access',status:'FAIL'}],limitations:limits}:{kind:r.kind,headSequence:5,operationId:UUID,candidateSha256:H,intentSha256:H,storePreconditionSha256:H,limitations:['non-publishing','prepare-not-execute',r.platform==='ios'?'current-asc-snapshot-may-change':'temporary-edit-may-expire','current-bundle-not-historical-finality','saved-inputs-not-atomic']};
const status=(r=review(),extra={})=>({origin:{projectId:P,serviceInstance:S,requestId:Q},grantId:G,reviewId:R,revision:2,review:r,state:'running',settlement:'pending',reason:'none',operation:{operationId:A,ownerGeneration:B,statusRevision:4},outcome:null,result:null,...extra});
const used=(r=review(),extra={})=>{const s=status(clone(r),extra);return access(r,{enabled:false,remainingMs:0,consumed:true,pending:s.settlement!=='settled',unknown:s.state==='unknown',requestId:Q,status:s});};
const done=(r=review())=>used(r,{state:'complete',settlement:'settled',outcome:'complete',result:result(r)});
const unknown=(r=review())=>used(r,{state:'unknown',settlement:'unknown',outcome:'unknown',reason:'cleanup-unknown'});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<6;i++)await Promise.resolve();};
function harness(reviews=[review()]){const calls=[];const method=kind=>(...args)=>{const d=deferred();calls.push({kind,args,...d});return d.promise;};
 const port={status:method('status'),allow:method('allow'),revoke:method('revoke')};let now=100,context={port,nativeSession:{},projectId:'p1',epoch:{},preview:false,reviews,blockedReason:null};
 const c=new AgentStoreAccessController({current:()=>context,delegate:()=>()=>true,now:()=>now});return{c,calls,port,set:v=>{context={...context,...v};},time:n=>now=n,last:k=>calls.filter(c=>c.kind===k).at(-1)};}
async function allow(h,r=review()){if(!h.c.getSnapshot().access)await check(h,empty());assert.equal(h.c.acknowledge(true),true);const p=h.c.allow();h.last('allow').resolve(access(r));await p;}
async function check(h,a){const p=h.c.status();h.last('status').resolve(a);await p;}

test('closed reviews use exact supported kinds/platforms, nullable candidate and bounded version',()=>{
 for(const kind of ['access-check','candidate-prepare'])for(const platform of ['android','ios']){const r=parseStoreReview(review(kind,platform));assert.ok(r);assert.ok(Object.isFrozen(r));assert.match(storeConsent(r),new RegExp(`^agent-${platform}-store-`));}
 for(const patch of [{kind:'execute'},{platform:'both'},{statusRevision:0},{statusRevision:0xffffffff},{candidate:{operationId:UUID,sha256:H}},{source:'/private/path'},{operationId:'0'.repeat(32)}])assert.equal(parseStoreReview({...review(),...patch}),null);
 const m=review();delete m.candidate;assert.equal(parseStoreReview(m),null);const bad=review('candidate-prepare');bad.candidate=null;assert.equal(parseStoreReview(bad),null);
 let getters=0;const g=review();Object.defineProperty(g,'operationId',{enumerable:true,get(){getters++;return A;}});assert.equal(parseStoreReview(g),null);assert.equal(getters,0);
});
test('strict access mirrors pending/triple-cut terminal/unknown and exact nonsecret reports',()=>{
 for(const r of [review(),review('candidate-prepare','ios')])for(const v of [empty(),access(r),used(r),done(r),unknown(r)])assert.ok(parseAgentStoreAccess(v));
 for(const mutate of [v=>delete v.status,v=>v.remainingMs=-0,v=>v.remainingMs=300001,v=>v.grantId=null,v=>v.token='forbidden',v=>v.enabled=false]){const v=access();mutate(v);assert.equal(parseAgentStoreAccess(v),null);}
 for(const mutate of [v=>v.status.origin.requestId=A,v=>v.status.review.savedVersion.build++,v=>v.status.result.account='forbidden',v=>v.status.result.findings.push({check:'store-access',status:'UNKNOWN'}),v=>v.status.outcome='unknown',v=>v.status.settlement='pending']){const v=done();mutate(v);assert.equal(parseAgentStoreAccess(v),null);}
 assert.equal(parseAgentStoreAccess(used(review(),{state:'complete',outcome:'complete',result:result(review())})),null);
 assert.equal(parseAgentStoreAccess(unknown()).status.result,null);
});
test('RAW3 contain only prepared IDs/consent; CLI commands are IDs and never automatically submitted',async()=>{
 const calls=[],p=createAgentStoreAccessPort(async(n,b)=>{assert.ok(b instanceof Uint8Array);assert.ok(b.length<=1024);calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return empty();});
 await p.status();await p.allow(review(),'0');await p.revoke();assert.deepEqual(calls,[['agent_store_access',{}],['allow_agent_store',{expectedPermissionRevision:'0',kind:'access-check',operationId:A,ownerGeneration:B,expectedStatusRevision:3,consentVersion:'agent-android-store-access-once-v1'}],['revoke_agent_store',{}]]);
 await assert.rejects(p.allow({...review(),kind:'execute'}));assert.equal(calls.length,3);
 assert.deepEqual(storeCommands(access()),[`mrk store-submit ${P} ${S} ${G} ${R} --reviewed`]);assert.deepEqual(storeCommands(used()),[`mrk store-status ${P} ${S} ${Q}`,`mrk store-cancel ${P} ${S} ${Q}`]);assert.deepEqual(storeCommands(empty()),[]);
});
test('actual Store statusRevision and strict basic context project the review, never query/Both/later',()=>{
 const r=review(),c={projectId:'p1',platform:'android',executionMode:'local',operation:'local-store-preflight',savedConfig:r.savedConfig,savedVersion:{...r.savedVersion,source:'release/version.properties'},recordId:R,recordRevision:1};
 const s={mode:'native',pending:false,callersPending:false,blocked:false,unconfirmed:false,historical:false,consentUntil:60000,status:{statusRevision:3,operation:{operationId:A,ownerGeneration:B,phase:'awaiting-consent',intentUsable:true,context:c}}};
 assert.deepEqual(clone(storeReviewFromState(s,'access-check','p1')),r);assert.equal(storeReviewFromState(s,'access-check','p2'),null);
 for(const patch of [{query:'current-versions'},{platform:'both'},{later:{}},{stage:'production'},{iosRecord:{recordId:R}},{executionMode:'github'}]){const v=clone(s);Object.assign(v.status.operation.context,patch);assert.equal(storeReviewFromState(v,'access-check','p1'),null);}
 for(const patch of [{pending:true},{callersPending:true},{unconfirmed:true},{historical:true},{consentUntil:null},{mode:'preview'}])assert.equal(storeReviewFromState({...s,...patch},'access-check','p1'),null);
 const p=clone(s);p.status.operation.context={...c,operation:'local-store-prepare',candidateOperationId:UUID,candidateSha256:H};assert.deepEqual(clone(storeReviewFromState(p,'candidate-prepare','p1')),review('candidate-prepare'));
});
test('mounting/status never grants; Allow requires exact manual review and one confirmation',async()=>{
 const h=harness([]);h.c.syncContext();assert.equal(await h.c.allow(),false);assert.equal(h.calls.length,0);await check(h,empty());assert.equal(h.c.acknowledge(true),false);
 h.set({reviews:[review()]});h.c.syncContext();assert.equal(await h.c.allow(),false);await allow(h);assert.ok(h.c.ownerReason());assert.equal(await h.c.allow(),false);assert.equal(h.calls.filter(c=>c.kind==='allow').length,1);
});
test('one permission is shared across kinds; changing selection removes consent',async()=>{
 const h=harness([review(),review('candidate-prepare','ios')]);await check(h,empty());assert.equal(h.c.acknowledge(true),true);assert.equal(h.c.choose('candidate-prepare'),true);assert.equal(await h.c.allow(),false);await allow(h,review('candidate-prepare','ios'));assert.equal(h.c.choose('access-check'),false);assert.equal(h.last('allow').args[0].kind,'candidate-prepare');
});
test('own pending is latched before listeners and reentrant context/peer/revoke prevents later Allow handoff',async()=>{
 for(const change of [h=>h.set({epoch:{}}),h=>h.set({blockedReason:'peer'}),h=>void h.c.revoke()]){const h=harness();await check(h,empty());h.c.acknowledge(true);let changed=false;
 h.c.subscribe(()=>{if(!changed&&h.c.getSnapshot().pending==='allow'){changed=true;change(h);}});
 assert.equal(await h.c.allow(),false);assert.equal(h.calls.filter(c=>c.kind==='allow').length,0);
 if(h.last('revoke')){h.last('revoke').resolve(empty());await h.c.whenSettled();}
 }
});
test('revoke overtakes a pending Allow, keeps both original promises and cannot accept late resurrected permission',async()=>{
 const h=harness();await check(h,empty());h.c.acknowledge(true);const a=h.c.allow();const old=h.last('allow');const off=h.c.revoke();h.last('revoke').resolve(empty());await off;
 let settled=false;const done=h.c.whenSettled().then(()=>{settled=true;});await flush();assert.equal(settled,false);assert.ok(h.c.ownerReason());old.resolve(access());await a;await done;assert.equal(h.c.getSnapshot().access.grantId,null);assert.equal(h.c.getSnapshot().acknowledged,false);
});
test('lost Allow and failed Revoke are absorbing unknown; later empty status is not cleanup',async()=>{
 for(const which of ['allow','revoke']){const h=harness();if(which==='revoke')await allow(h);else {await check(h,empty());h.c.acknowledge(true);}const p=h.c[which]();h.last(which).reject(Error('inert lost reply'));await p;assert.equal(h.c.getSnapshot().unknown,true);await check(h,empty());assert.equal(h.c.getSnapshot().unknown,true);assert.equal(await h.c.allow(),false);}
});
test('consumed/finishing report does not settle until native triple-cut public terminal; FAIL finding is not release readiness',async()=>{
 const h=harness();await allow(h);await check(h,used());assert.ok(h.c.ownerReason());await check(h,used(review(),{state:'finishing',revision:3}));assert.ok(h.c.ownerReason());const d=done();d.status.revision=4;await check(h,d);assert.equal(h.c.ownerReason(),null);assert.equal(h.c.getSnapshot().access.status.result.findings[0].status,'FAIL');
});
test('unknown status remains pinned when later matching complete result arrives',async()=>{
 const h=harness();await allow(h);await check(h,unknown());const original=h.c.getSnapshot().access;await check(h,done());assert.equal(h.c.getSnapshot().access,original);assert.equal(h.c.getSnapshot().unknown,true);
});
test('mismatched same-grant identity, request regression or pending-grant replacement is unknown',async()=>{
 for(const change of [a=>a.reviewId=A,a=>{a.grantId=A;a.status.grantId=A;},a=>a.status.revision=1]){const h=harness();await allow(h);await check(h,used());const next=used();change(next);await check(h,next);assert.equal(h.c.getSnapshot().unknown,true);}
});
test('context change retains original port for Status/Revoke and never calls replacement',async()=>{
 const h=harness();await allow(h);h.set({nativeSession:{},epoch:{},projectId:'p2',port:{status(){assert.fail('new status');},allow(){assert.fail('new allow');},revoke(){assert.fail('new revoke');}}});h.c.syncContext();assert.equal(h.c.getSnapshot().stale,true);
 await check(h,access());const r=h.c.revoke();h.last('revoke').resolve(access(review(),{enabled:false,remainingMs:0}));await r;assert.equal(h.c.getSnapshot().access.enabled,false);assert.equal(h.c.getSnapshot().stale,true);
});
test('local remaining display never extends native expiry and does not revoke/renew automatically',async()=>{
 const h=harness();await allow(h);h.time(200101);assert.equal(h.c.remainingSeconds(),0);assert.ok(h.c.ownerReason());assert.deepEqual(h.calls.map(v=>v.kind),['status','allow']);h.time(1);assert.equal(h.c.remainingSeconds(),null);
});
test('disposal does not discard pending caller or manufacture native cancellation/finality',async()=>{
 const h=harness();await check(h,empty());h.c.acknowledge(true);const p=h.c.allow();h.c.dispose();let done=false;const w=h.c.whenSettled().then(()=>{done=true;});await flush();assert.equal(done,false);assert.deepEqual(h.calls.map(v=>v.kind),['status','allow']);h.last('allow').resolve(access());await p;await w;assert.equal(done,true);assert.equal(h.c.getSnapshot().access.grantId,null);
});

// Same real two original controllers; only their native ports and clock are inert.
async function originalStore(kind){
 const project={projectId:'p1',draftRevision:1,baselineGeneration:2,observationGeneration:3,savedConfig:{bytes:100,sha256:H},savedVersion:{bytes:40,sha256:H,source:'release/version.properties',name:'1.2.3',build:42},inputIssue:null,dirtyDraft:false,snapshotPending:false,versionPending:false,saveRecoveryRequired:false};
 const assets={mode:'native',scope:{executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},contextCurrent:true,busy:null,updatingContext:false,observationFailed:false,blocked:false,originPending:false,status:{mode:'session',capability:{available:true},modes:{session:{available:true}},context:{revision:3,projectId:'p1',executionMode:'local',platform:'android',stage:'candidate',purpose:'store'},operation:null,assignments:[{kind:'google-service-account',recordId:R,recordRevision:4,contextRevision:3,availability:'available'}],records:[{kind:'google-service-account',recordId:R,revision:4,availability:'assigned'}]}};
 const nativeStatus=(n,operation)=>({schemaVersion:1,statusRevision:n,availability:'available',operation});
 const history={mode:'native',historical:false,pending:false,blocked:false,unconfirmed:false,status:nativeStatus(1,{operationId:R,ownerGeneration:B,context:{projectId:'p1',executionMode:'local',action:'review-inputs',candidateOperationId:UUID},phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:3,history:[{operationId:UUID,phase:'inputs-ready',recoveryRequired:true}],limitations:['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'],candidateInputs:{operationId:UUID,candidateSha256:H,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),applicationId:'dev.example.app',version:{name:'1.2.3',build:42},files:[{fileName:'app-release.aab',bytes:100,sha256:H},{fileName:'store-metadata.zip',bytes:100,sha256:H},{fileName:'validation-report.json',bytes:100,sha256:H}],observation:'current-bundle-only',priorCreateFinality:'not-established'}}})};
 let now=100,latest=nativeStatus(0,null),listener,permission=null,prepareWait=null;const calls=[];
 const source={project:()=>project,assets:()=>assets,history:()=>history,otherOperationReason:()=>permission?.ownerReason()??null,now:()=>now};
 const original=kind==='access-check'?new LocalStorePreflightController(source):new LocalStorePrepareController(source);
 const suffix=kind==='access-check'?'LocalStorePreflight':'LocalStorePrepare';const api={mode:'native',
  [`subscribe${suffix}`]:async f=>{listener=f;return()=>{};},
  [suffix[0].toLowerCase()+suffix.slice(1)+'Status']:async()=>latest,
  [`prepare${suffix}`]:async r=>{latest=nativeStatus(latest.statusRevision+1,{operationId:A,ownerGeneration:B,context:{...clone(r),platform:r.platform??'android',operation:kind==='access-check'?'local-store-preflight':'local-store-prepare'},phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});listener(clone(latest));if(prepareWait)await prepareWait;return clone(latest);},
  [`start${suffix}`]:async()=>{calls.push('gui-start');return latest;},
  [`cancel${suffix}`]:async(a,b)=>{assert.equal(a,A);assert.equal(b,B);calls.push('cancel');latest=nativeStatus(latest.statusRevision+1,{...latest.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});return clone(latest);}};
 await original.connect(api);original.syncProject();const epoch={},nativeSession={};
 const port={status:async()=>empty(),revoke:async()=>empty(),allow:async r=>{calls.push('allow');return access(r);}};
 permission=new AgentStoreAccessController({current:()=>{const r=storeReviewFromState(original.getSnapshot(),kind,'p1');return{port,nativeSession,epoch,projectId:'p1',preview:false,reviews:r?[r]:[],blockedReason:null};},delegate:r=>original.delegatePrepared(r,r.statusRevision),now:()=>now});
 permission.choose(kind);
 return{original,permission,calls,port,time:v=>now=v,defer:()=>{const d=deferred();prepareWait=d.promise;return d;},latest:()=>latest,
  running:()=>{latest=nativeStatus(latest.statusRevision+1,{...latest.operation,phase:'running',intentUsable:false});listener(clone(latest));},
  changed:()=>{project.draftRevision++;original.syncProject();},close:()=>{original.dispose();permission.dispose();}};
}
test('actual two controllers delegate only returned Prepare; one Allow clears GUI timer/hide not native work/context STOP',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['access-check','candidate-prepare']){const h=await originalStore(kind);try{
  await h.original.prepare();h.permission.syncContext();await h.permission.status();assert.ok(h.permission.getSnapshot().review);assert.equal(h.permission.acknowledge(true),true);assert.equal(await h.permission.allow(),true);assert.deepEqual(h.calls,['allow']);
  assert.equal(h.original.getSnapshot().consentUntil,null);assert.equal(storeReviewFromState(h.original.getSnapshot(),kind,'p1'),null);
  h.running();h.original.setVisible(false);h.time(70000);t.mock.timers.tick(70000);await flush();assert.deepEqual(h.calls,['allow']);
  h.original.acknowledge(true);await h.original.start();assert.deepEqual(h.calls,['allow']);
  h.changed();await flush();assert.deepEqual(h.calls,['allow','cancel']);
 }finally{h.close();}}
});
test('ordinary unstarted attempts retain GUI timer/hide cancellation and cannot delegate on a still-returning Prepare',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['access-check','candidate-prepare'])for(const mode of ['timer','hide','pending']){const h=await originalStore(kind);try{
  if(mode==='pending'){const d=h.defer(),p=h.original.prepare();await flush();assert.equal(h.original.getSnapshot().status.operation.phase,'awaiting-consent');assert.equal(h.original.delegatePrepared({operationId:A,ownerGeneration:B},h.latest().statusRevision),null);assert.equal(h.permission.acknowledge(true),false);d.resolve();await p;}
  else{await h.original.prepare();if(mode==='timer'){h.time(70000);t.mock.timers.tick(70000);}else h.original.setVisible(false);await flush();assert.deepEqual(h.calls,['cancel']);}
 }finally{h.close();}}
});
test('post-delegate listener revocation prevents sole Allow call; failed call never restores GUI Start/timer',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['access-check','candidate-prepare'])for(const mode of ['revoke-listener','failed-allow']){const h=await originalStore(kind);try{
  await h.original.prepare();h.permission.syncContext();await h.permission.status();h.permission.acknowledge(true);let once=false;
  if(mode==='failed-allow')h.port.allow=async()=>{h.calls.push('allow');throw new Error('inert lost reply');};
  const unlisten=h.original.subscribe(()=>{if(mode==='revoke-listener'&&!once&&h.original.getSnapshot().consentUntil===null){once=true;void h.permission.revoke();}});
  assert.equal(await h.permission.allow(),mode==='failed-allow');await h.permission.whenSettled();
  const expected=mode==='failed-allow'?['allow']:[];assert.deepEqual(h.calls,expected);assert.equal(h.permission.getSnapshot().unknown,mode==='failed-allow');
  unlisten();h.original.setVisible(false);h.time(70000);t.mock.timers.tick(70000);await h.original.start();assert.deepEqual(h.calls,expected);
  assert.equal(h.original.getSnapshot().consentUntil,null);await h.original.cancel();assert.deepEqual(h.calls,[...expected,'cancel']);
 }finally{h.close();}}
});

test('shared Store revision uses original Check, no implicit refresh, and exact one-use Allow response',async()=>{
 for(const returned of ['9007199254740994','9007199254740993']){const h=harness();
  assert.equal(h.c.acknowledge(true),false);assert.equal(await h.c.allow(),false);assert.equal(h.calls.length,0);
  await check(h,{...empty(),permissionRevision:'9007199254740993'});assert.equal(h.c.acknowledge(true),true);
  const pending=h.c.allow();assert.equal(h.last('allow').args[1],'9007199254740993');assert.deepEqual(h.calls.map(v=>v.kind),['status','allow']);
  h.last('allow').resolve(access(review(),{permissionRevision:returned}));await pending;
  assert.equal(h.c.getSnapshot().unknown,returned==='9007199254740993');assert.equal(await h.c.allow(),false);h.c.dispose();
 }
 for(const value of [undefined,null,0,'00','1\n','18446744073709551616'])assert.equal(parseAgentStoreAccess({...empty(),permissionRevision:value}),null);
 const calls=[],p=createAgentStoreAccessPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return empty();});
 await assert.rejects(p.allow(review()));await p.allow(review(),'7');assert.equal(calls.length,1);assert.equal(calls[0][1].expectedPermissionRevision,'7');
});
