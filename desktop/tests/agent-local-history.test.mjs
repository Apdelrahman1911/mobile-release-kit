// Actual controllers and closed codecs; inert native/permission ports only.
// No Keychain, local journal, filesystem, installed CLI or provider execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AgentLocalHistoryController } from '../src/agentLocalHistoryController.ts';
import { parseLocalHistoryReview, parseAgentLocalHistoryAccess, localHistoryDelegateConsent, createAgentLocalHistoryPort, localHistoryCommands } from '../src/agentLocalHistoryProtocol.ts';
import { LocalReleaseHistoryController, localHistoryOwnerReason, localHistoryRequest } from '../src/localReleaseHistory.ts';
const A='a'.repeat(32),B='b'.repeat(32),P='1'.repeat(32),S='2'.repeat(32),G='3'.repeat(32),R='4'.repeat(32),Q='5'.repeat(32),H='c'.repeat(64);
const UUID='12345678-1234-4234-8234-123456789abc',limits=['no-store-authority','no-build-or-publishing','keychain-intact-rollback-boundary'];
const copy=v=>structuredClone(v),flush=async()=>{for(let i=0;i<8;i++)await Promise.resolve();};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const review=(kind='verify',platform)=>({kind,operationId:A,ownerGeneration:B,statusRevision:1,...(platform?{platform}:{}),...(kind==='review-inputs'?{candidateOperationId:UUID}:{})});
const empty=()=>({permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,reviewId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const access=(r=review(),extra={})=>({permissionRevision:'1',serviceInstance:S,projectId:P,grantId:G,reviewId:R,review:r,enabled:true,remainingMs:200000,consumed:false,pending:false,unknown:false,requestId:null,status:null,...extra});
const report=(r=review(),phase='inputs-ready')=>({enrolled:true,headSequence:2,history:r.kind==='review-inputs'?[{operationId:UUID,phase,recoveryRequired:phase!=='settled-failure'}]:[],candidateInputs:r.kind==='review-inputs'&&phase==='inputs-ready'?{operationId:UUID,candidateSha256:H,sourceCommit:'a'.repeat(40),sourceTree:'b'.repeat(40),application:'dev.example.app',version:{name:'1.2',build:123},files:[{fileName:r.platform?'export/app.ipa':'app-release.aab',bytes:100,sha256:H},{fileName:'store-metadata.zip',bytes:100,sha256:H},{fileName:'validation-report.json',bytes:100,sha256:H}],archive:r.platform?{directory:'archive.xcarchive',entries:1,bytes:100,sha256:H}:null,observation:'current-bundle-only',priorCreateFinality:'not-established'}:null,limitations:limits});
const used=(r=review(),extra={})=>{const status={origin:{projectId:P,serviceInstance:S,requestId:Q},grantId:G,reviewId:R,revision:2,review:r,state:'running',settlement:'pending',reason:'none',operation:{operationId:A,ownerGeneration:B,statusRevision:2},outcome:null,result:null,...extra};return access(r,{enabled:false,remainingMs:0,consumed:true,pending:status.settlement!=='settled',unknown:status.state==='unknown',requestId:Q,status});};
const done=(r=review(),phase)=>used(r,{state:'complete',settlement:'settled',outcome:'complete',result:report(r,phase)});
const unknown=(r=review())=>used(r,{state:'unknown',settlement:'unknown',outcome:'unknown',reason:'cleanup-unknown'});
const native=(revision=0,operation=null)=>({schemaVersion:1,statusRevision:revision,availability:'available',operation});
async function fixture(){
 let project='p1',epoch={},session={},now=100,other=null,waitPrepare=null,listener,permission=null,latest=native();const calls=[];
 const original=new LocalReleaseHistoryController({projectId:()=>project,otherOperationReason:()=>other,delegationReason:()=>permission?.ownerReason()??null,now:()=>now});
 const api={mode:'native',subscribeLocalReleaseHistory:async f=>{listener=f;return()=>calls.push('unlisten');},localReleaseHistoryStatus:async()=>copy(latest),
  prepareLocalReleaseHistory:async request=>{calls.push('prepare');latest=native(latest.statusRevision+1,{operationId:A,ownerGeneration:B,context:copy(request),phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',result:null});listener(copy(latest));if(waitPrepare)await waitPrepare;return copy(latest);},
  startLocalReleaseHistory:async()=>{calls.push('gui-start');return copy(latest);},
  cancelLocalReleaseHistory:async(a,b)=>{assert.deepEqual([a,b],[A,B]);calls.push('cancel');latest=native(latest.statusRevision+1,{...latest.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'});return copy(latest);}};
 const port={status:async()=>empty(),allow:async r=>{calls.push('allow');return access(r);},revoke:async()=>{calls.push('revoke');return empty();}};
 await original.connect(api);original.syncProject();
 permission=new AgentLocalHistoryController({current:()=>{const r=original.delegationReview();return{port,nativeSession:session,epoch,projectId:project,preview:false,reviews:r?[r]:[],blockedReason:other};},delegate:r=>original.delegatePrepared(r),now:()=>now});
 return{original,permission,api,port,calls,time:n=>now=n,project:id=>{project=id;epoch={};original.syncProject();permission.syncContext();},epoch:()=>{epoch={};permission.syncContext();},busy:r=>other=r,session:()=>{session={};permission.syncContext();},deferPrepare:()=>{const d=deferred();waitPrepare=d.promise;return d;},emit:v=>{latest=copy(v);listener(copy(v));},latest:()=>copy(latest),close:()=>{original.dispose();permission.dispose();}};
}
async function prepare(h,kind='verify'){h.original.setAction(kind);await h.original.prepare();h.permission.syncContext();assert.ok(h.permission.getSnapshot().review);}
async function allow(h){if(!h.permission.getSnapshot().access)await h.permission.status();assert.equal(h.permission.acknowledge(true),true);assert.equal(await h.permission.allow(),true);}
async function check(h,a){h.port.status=async()=>a;assert.equal(await h.permission.status(),true);}

test('closed three-action review keeps native omitted Android/platformless grammar and no material inputs',()=>{
 for(const r of [review('enroll'),review(),review('review-inputs'),review('review-inputs','ios')]){assert.ok(parseLocalHistoryReview(r));assert.ok(Object.isFrozen(parseLocalHistoryReview(r)));assert.match(localHistoryDelegateConsent(r),/^agent-local-history-/);}
 for(const r of [{...review(),platform:'android'},{...review(),platform:null},{...review(),candidateOperationId:null},{...review('review-inputs'),platform:null},{...review('review-inputs'),candidateOperationId:UUID.replace('4234','1234')},{...review(),kind:'abandon-inputs'},{...review(),path:'/inert'},{...review(),statusRevision:0},{...review(),operationId:'0'.repeat(32)},{...review(),operationId:A+'\n'},{...review('review-inputs'),candidateOperationId:UUID+'\n'}])assert.equal(parseLocalHistoryReview(r),null);
 let getter=0;const unsafe=review();Object.defineProperty(unsafe,'kind',{enumerable:true,get(){getter++;return'verify';}});assert.equal(parseLocalHistoryReview(unsafe),null);assert.equal(getter,0);
});
test('bounded result is local evidence only; pending/failure input rows never fabricate bundle or prior finality',()=>{
 for(const r of [review('enroll'),review(),review('review-inputs'),review('review-inputs','ios')])for(const v of [empty(),access(r),used(r),done(r),unknown(r)])assert.ok(parseAgentLocalHistoryAccess(v));
 for(const phase of ['inputs-pending','settled-failure'])assert.ok(parseAgentLocalHistoryAccess(done(review('review-inputs'),phase)));
 for(const mutate of [a=>a.status.result.candidateInputs.priorCreateFinality='complete',a=>a.status.result.candidateInputs.sourceCommit+='\n',a=>a.status.result.candidateInputs.application+='\n',a=>a.status.result.candidateInputs.version.name+='\n',a=>a.status.result.candidateInputs.candidateSha256+='\n',a=>a.status.result.history[0].recoveryRequired=false,a=>a.status.result.history[0].phase='prepared',a=>a.status.result.headSequence=1,a=>a.status.result.history.push(copy(a.status.result.history[0])),a=>a.status.result.candidateInputs.files.reverse(),a=>a.status.result.candidateInputs.archive={},a=>a.status.origin.projectId=A,a=>a.status.result.rawJournal='not public',a=>a.status.result=null]){const a=done(review('review-inputs'));mutate(a);assert.equal(parseAgentLocalHistoryAccess(a),null);}
 const bad=access();delete bad.status;assert.equal(parseAgentLocalHistoryAccess(bad),null);assert.equal(parseAgentLocalHistoryAccess({...access(),remainingMs:300001}),null);
});
test('fixed RAW commands send only original review IDs and mode consent; emitted CLI is scalar, never automatic',async()=>{
 const calls=[],port=createAgentLocalHistoryPort(async(name,bytes)=>{calls.push([name,JSON.parse(new TextDecoder().decode(bytes))]);return empty();});
 for(const r of [review('enroll'),review(),review('review-inputs'),review('review-inputs','ios')])await port.allow(r,'0');
 assert.deepEqual(calls.map(v=>v[1].consentVersion),['agent-local-history-enroll-once-v1','agent-local-history-verify-once-v1','agent-local-history-android-inputs-once-v1','agent-local-history-ios-inputs-once-v1']);
 assert.deepEqual(Object.keys(calls[2][1]),['expectedPermissionRevision','kind','operationId','ownerGeneration','expectedStatusRevision','consentVersion']);
 await port.status();await port.revoke();assert.deepEqual(calls.slice(-2),[['agent_local_history_access',{}],['revoke_agent_local_history',{}]]);
 await assert.rejects(port.allow({...review(),kind:'abandon-inputs'}));assert.equal(calls.length,6);
 assert.deepEqual(localHistoryCommands(access()),[`mrk local-history-submit ${P} ${S} ${G} ${R} --reviewed`]);assert.deepEqual(localHistoryCommands(used()),[`mrk local-history-status ${P} ${S} ${Q}`,`mrk local-history-cancel ${P} ${S} ${Q}`]);
});
test('real History Prepare must return; awaiting event or cold identical status cannot be delegated',async()=>{
 const h=await fixture();try{
  assert.equal(h.calls.length,0);const d=h.deferPrepare(),p=h.original.prepare();await flush();
  assert.equal(h.latest().operation.phase,'awaiting-consent');assert.equal(h.original.delegationReview(),null);assert.equal(h.permission.acknowledge(true),false);assert.equal(await h.permission.allow(),false);
  d.resolve();await p;assert.ok(h.original.delegationReview());
  const cold=await fixture();try{cold.emit(h.latest());assert.equal(cold.original.delegationReview(),null);assert.equal(cold.permission.acknowledge(true),false);}finally{cold.close();}
 }finally{h.close();}
});
test('actual History selects Android/iOS candidate from returned history before explicit review; enrollment remains platformless',async()=>{
 for(const platform of ['android','ios']){const h=await fixture();try{
  h.emit(native(1,{operationId:R,ownerGeneration:B,context:localHistoryRequest('p1','verify'),phase:'terminal',intentUsable:false,outcome:'complete',reason:'none',result:{schemaVersion:1,scope:'local-release-history',enrolled:true,headSequence:2,history:[{operationId:UUID,phase:'inputs-ready',recoveryRequired:true}],limitations:limits}}));
  assert.equal(h.original.setInputPlatform(platform),true);assert.equal(h.original.selectCandidate('review-inputs',UUID),true);await h.original.prepare();const r=h.original.delegationReview();assert.equal(r.kind,'review-inputs');assert.equal(r.platform,platform==='ios'?'ios':undefined);assert.equal(r.candidateOperationId,UUID);
 }finally{h.close();}}
 const h=await fixture();try{await prepare(h,'enroll');assert.equal(h.original.delegationReview().kind,'enroll');}finally{h.close();}
});
test('actual delegated original survives old GUI60s timer and tab hide but never gains GUI Start or ignores context Stop',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const kind of ['enroll','verify']){const h=await fixture();try{
  await prepare(h,kind);await allow(h);h.emit(native(2,{...h.latest().operation,phase:'running',intentUsable:false}));
  h.original.setVisible(false);h.time(70000);t.mock.timers.tick(70000);await flush();await h.original.start();assert.deepEqual(h.calls,['prepare','allow']);assert.equal(h.original.getSnapshot().consentUntil,null);
  h.project('p2');await flush();assert.deepEqual(h.calls,['prepare','allow','cancel']);assert.ok(h.permission.ownerReason());
 }finally{h.close();}}
});
test('ordinary History still cancels on hide/deadline and expired review is never delegable',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});
 for(const change of [h=>h.original.setVisible(false),h=>{h.time(60101);t.mock.timers.tick(60001);}]){const h=await fixture();try{await prepare(h);change(h);await flush();assert.equal(h.original.delegationReview(),null);assert.deepEqual(h.calls,['prepare','cancel']);}finally{h.close();}}
});
test('actual Allow and delegate publications recheck context, ABA, peer, disposal and revoke before any native permission call',async()=>{
 for(const point of ['permission','delegate'])for(const change of [h=>h.project('p2'),h=>{h.original.beforeWorkspaceAction();h.epoch();},h=>h.busy('retained peer'),h=>h.session(),h=>h.permission.dispose(),h=>void h.permission.revoke()]){const h=await fixture();try{
  await prepare(h);await h.permission.status();h.permission.acknowledge(true);let once=false;
  const unsub=(point==='permission'?h.permission:h.original).subscribe(()=>{if(!once&&(point==='permission'?h.permission.getSnapshot().pending==='allow':h.original.getSnapshot().consentUntil===null)){once=true;change(h);}});
  assert.equal(await h.permission.allow(),false);await h.permission.whenSettled();unsub();assert.equal(h.calls.includes('allow'),false);assert.equal(h.calls.includes('gui-start'),false);
 }finally{h.close();}}
});
test('lost Allow keeps delegated Attempt without replay; explicit original status/cancel remain usable',async()=>{
 const h=await fixture();try{await prepare(h);h.port.allow=async()=>{h.calls.push('allow');throw Error('inert lost reply');};await allow(h);assert.equal(h.permission.getSnapshot().unknown,true);
  await check(h,empty());assert.equal(h.permission.getSnapshot().unknown,true);assert.equal(await h.permission.allow(),false);h.original.setVisible(false);await h.original.start();assert.equal(h.calls.includes('cancel'),false);assert.equal(h.calls.includes('gui-start'),false);
  await h.original.checkStatus();await h.original.cancel();assert.equal(h.calls.filter(v=>v==='cancel').length,1);
 }finally{h.close();}
});
test('Revoke keeps same pending Allow until real return; late enabled reply cannot restore permission',async()=>{
 const h=await fixture();try{await prepare(h);const d=deferred();h.port.allow=()=>d.promise;await h.permission.status();h.permission.acknowledge(true);const pending=h.permission.allow();await flush();await h.permission.revoke();
  let returned=false;const joined=h.permission.whenSettled().then(()=>returned=true);await flush();assert.equal(returned,false);assert.ok(h.permission.ownerReason());d.resolve(access());await pending;await joined;assert.equal(h.permission.getSnapshot().access.grantId,null);assert.equal(h.permission.getSnapshot().acknowledged,false);
 }finally{h.close();}
});
test('consumed and native terminal are not caller/history finality; original native invoke count survives terminal event',async()=>{
 const h=await fixture();try{await prepare(h);await allow(h);await check(h,used());assert.ok(h.permission.ownerReason());await check(h,used(review(),{revision:3,state:'finishing'}));assert.ok(h.permission.ownerReason());
  const d=deferred();h.api.localReleaseHistoryStatus=()=>d.promise;const pending=h.original.checkStatus();h.emit(native(2,{...h.latest().operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled'}));assert.equal(h.original.hasPendingGuiSubmission(),true);assert.ok(localHistoryOwnerReason(h.original.getSnapshot()));
  d.resolve(h.latest());await pending;assert.equal(h.original.hasPendingGuiSubmission(),false);const a=done();a.status.revision=4;await check(h,a);assert.equal(h.permission.ownerReason(),null);assert.equal(h.permission.getSnapshot().access.status.result.enrolled,true);
 }finally{h.close();}
});
test('Unknown and pending-request identity conflicts never adopt a successful-looking replacement',async()=>{
 for(const change of [a=>{a.status.origin.requestId=A;a.requestId=A;},a=>a.status.revision=1,a=>a.reviewId=A]){const h=await fixture();try{await prepare(h);await allow(h);await check(h,used());const a=used();change(a);await check(h,a);assert.equal(h.permission.getSnapshot().unknown,true);await check(h,done());assert.equal(h.permission.getSnapshot().unknown,true);}finally{h.close();}}
});
test('delayed Allow and later Check countdown anchor to same call start, never response time or renewal',async()=>{
 const h=await fixture();try{await prepare(h);const d=deferred();h.port.allow=()=>d.promise;await h.permission.status();h.permission.acknowledge(true);const allowCall=h.permission.allow();h.time(20100);d.resolve(access(review(),{remainingMs:10000}));await allowCall;assert.equal(h.permission.remainingSeconds(),0);
  h.time(30000);await check(h,access(review(),{remainingMs:100000}));assert.equal(h.permission.remainingSeconds(),0);assert.ok(h.permission.ownerReason());assert.equal(h.calls.filter(v=>v==='gui-start').length,0);
 }finally{h.close();}
});
test('disposed permission keeps real original caller; parent cancellation retains original API/listener',async()=>{
 const h=await fixture();await prepare(h);const d=deferred();h.port.allow=()=>d.promise;await h.permission.status();h.permission.acknowledge(true);const call=h.permission.allow();h.permission.dispose();let joined=false;const j=h.permission.whenSettled().then(()=>joined=true);await flush();assert.equal(joined,false);d.resolve(access());await call;await j;assert.equal(h.permission.getSnapshot().access.grantId,null);h.original.dispose();await flush();assert.equal(h.calls.filter(v=>v==='cancel').length,1);
});

// MAIN revision is comparison DATA, not a replacement CLI grant or native join.
test('MAIN permission revision is exact canonical u64 DATA, required by codec and fixed Allow port',async()=>{
 const {validStorePermissionRevision,nextStorePermissionRevision}=await import('../src/agentStorePermissionRevision.ts');
 for(const revision of ['0','1','9007199254740993','18446744073709551615']){
  assert.equal(validStorePermissionRevision(revision),true);assert.ok(parseAgentLocalHistoryAccess({...empty(),permissionRevision:revision}));
 }
 assert.equal(nextStorePermissionRevision('9007199254740993'),'9007199254740994');assert.equal(nextStorePermissionRevision('18446744073709551615'),null);
 const calls=[],port=createAgentLocalHistoryPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return empty();});
 for(const revision of [undefined,null,0,1n,'','00','01','+1','1.0','1e1','1\n',' 1','18446744073709551616']){
  assert.equal(validStorePermissionRevision(revision),false);assert.equal(parseAgentLocalHistoryAccess({...empty(),permissionRevision:revision}),null);
  await assert.rejects(port.allow(review(),revision));
 }
 const absent=empty();delete absent.permissionRevision;assert.equal(parseAgentLocalHistoryAccess(absent),null);assert.equal(calls.length,0);
 await port.allow(review(),'9007199254740993');assert.equal(calls[0][1].expectedPermissionRevision,'9007199254740993');
 assert.deepEqual(localHistoryCommands(access()),[`mrk local-history-submit ${P} ${S} ${G} ${R} --reviewed`]);
});
test('MAIN permission revision waits for original Check return and pins it before Allow publication without refresh',async()=>{
 const h=await fixture();try{await prepare(h);let reads=0;const checked=deferred();h.port.status=()=>{reads++;return checked.promise;};
  assert.equal(h.permission.acknowledge(true),false);assert.equal(await h.permission.allow(),false);assert.equal(reads,0);
  const call=h.permission.status();assert.equal(h.permission.acknowledge(true),false);checked.resolve({...empty(),permissionRevision:'9007199254740993'});await call;
  assert.equal(h.permission.acknowledge(true),true);let seen=null,readDuring;
  h.port.allow=async(r,expected)=>{seen=expected;return access(r,{permissionRevision:'9007199254740994'});};
  const off=h.permission.subscribe(()=>{if(h.permission.getSnapshot().pending==='allow'&&!readDuring)readDuring=h.permission.status();});
  assert.equal(await h.permission.allow(),true);off();assert.equal(await readDuring,false);
  assert.equal(seen,'9007199254740993');assert.equal(reads,1);assert.equal(h.permission.getSnapshot().unknown,false);
 }finally{h.close();}
});
test('MAIN permission revision remains original through delayed Allow and an earlier Revoke',async()=>{
 const h=await fixture();try{await prepare(h);let revision=0n,seen;const beforeNativeCut=deferred();
  h.port.status=async()=>({...empty(),permissionRevision:revision.toString()});await h.permission.status();
  h.port.allow=(r,expected)=>{seen=expected;return beforeNativeCut.promise.then(()=>{if(expected!==revision.toString())throw Error('inert stale native cut');revision++;return access(r,{permissionRevision:revision.toString()});});};
  h.port.revoke=async()=>{revision++;return{...empty(),permissionRevision:revision.toString()};};
  h.permission.acknowledge(true);const pending=h.permission.allow();assert.equal(seen,'0');await h.permission.revoke();assert.equal(revision,1n);
  let joined=false;const returned=h.permission.whenSettled().then(()=>joined=true);await flush();assert.equal(joined,false);
  beforeNativeCut.resolve();await pending;await returned;assert.equal(revision,1n);assert.equal(h.permission.getSnapshot().access.permissionRevision,'1');assert.equal(h.permission.getSnapshot().access.enabled,false);
  assert.equal(await h.permission.allow(),false); // Never rebase and replay this attempted Prepared.
 }finally{h.close();}
});
test('MAIN permission revision exhaustion and context replacement never admit a fresh Allow without Check',async()=>{
 for(const revision of ['0','18446744073709551615']){const h=await fixture();try{await prepare(h);await check(h,{...empty(),permissionRevision:revision});
  if(revision==='0'){assert.equal(h.permission.acknowledge(true),true);h.session();}else assert.match(h.permission.consentReason(),/cannot be renewed/);
  assert.equal(h.permission.acknowledge(true),false);assert.equal(await h.permission.allow(),false);assert.equal(h.calls.includes('allow'),false);
  assert.equal(h.permission.revokeReason(),null);
 }finally{h.close();}}
});
