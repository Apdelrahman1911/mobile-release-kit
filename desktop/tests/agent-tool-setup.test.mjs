// Inert DATA/fake-port tests. No native tool, source picker, download, service
// registration or actual permission is created by these fixtures.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  TOOL_SETUP_KINDS, copyToolSetupInput, createAgentToolSetupPort,
  parseAgentToolSetupAccess, parseToolSetupReview, parseToolSetupStatus,
  toolSetupCommands, toolSetupConsent,
} from '../src/agentToolSetup.ts';
import { AgentToolSetupController } from '../src/agentToolSetupController.ts';
import { TOOL_ACQUISITION_CONSENT } from '../src/toolAcquisitionProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import capability from '../src-tauri/capabilities/main.json' with { type: 'json' };

const ID = n => n.toString(16).padStart(32, '0');
const PROJECT=ID(1), INSTANCE=ID(2), GRANT=ID(3), REVIEW=ID(4), REQUEST=ID(5), OP=ID(6), OWNER=ID(7);
const clone = value => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; };
const flush = async () => { for(let i=0;i<30;i++)await Promise.resolve(); };
const review = (kind='doctor') => ({kind,platform:'android',draftRevision:2,baselineGeneration:3,
  prepared:['inspect-requirements','acquire-missing'].includes(kind)?{operationId:OP,ownerGeneration:OWNER,statusRevision:1}:null,
  sources:kind.includes('sources')?{registrationGeneration:0,sourceGeneration:1,reviewId:kind==='register-reviewed-sources'?REVIEW:null}:null,
  ...(kind==='acquire-reviewed-missing'?{acquisition:{operationId:ID(8),ownerGeneration:ID(9),requirementsSha256:'a'.repeat(64),
    missing:['android-build-tools'],compatible:['jdk','android-platform','gradle']}}:{})});
const empty = () => ({serviceInstance:null,projectId:null,grantId:null,reviewId:null,review:null,
  enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const access = (r=review()) => ({serviceInstance:INSTANCE,projectId:PROJECT,grantId:GRANT,reviewId:REVIEW,review:clone(r),
  enabled:true,remainingMs:300000,consumed:false,pending:false,unknown:false,requestId:null,status:null});
const queued = (r=review()) => ({origin:{projectId:PROJECT,serviceInstance:INSTANCE,requestId:REQUEST},grantId:GRANT,reviewId:REVIEW,revision:1,
  review:clone(r),state:'queued',settlement:'pending',reason:'none',operation:null,outcome:null,result:null});
const complete = (r=review()) => ({...queued(r),revision:2,state:'complete',settlement:'settled',
  operation:r.sources?{operationId:OP,ownerGeneration:null,registrationGeneration:1}:{operationId:OP,ownerGeneration:OWNER,registrationGeneration:null},
  outcome:'complete',result:{kind:r.kind,checks:[{check:'git',status:'failed'}]}});
const consumed = s => ({...access(s.review),enabled:false,remainingMs:0,consumed:true,pending:s.settlement!=='settled',unknown:s.state==='unknown',requestId:REQUEST,status:clone(s)});
const input = (r=review()) => ({projectId:'project-1',review:clone(r),doctorDraft:r.kind==='doctor'?{android:{enabled:true},example:0.5}:null,
  sourceContext:null,nativeConsent:r.prepared?TOOL_ACQUISITION_CONSENT:null,licenseAcknowledged:false});

function harness(t) {
  const r=review(),session={},epoch={},calls=[],reads=[];
  let now=100, latest=empty(), allowed=null, queried=null, stopped=null, contextEpoch=epoch, blocked=null, pinCurrent=true, nativeReturned=true, nonce=3;
  let delegateHook=null, prepareHook=null;
  const port={
    access:async()=>{calls.push({kind:'access'});return clone(latest);},
    allow:(id,body)=>{calls.push({kind:'allow',id,body:clone(body)});return allowed?.promise??Promise.resolve({...access(body.review),grantId:id});},
    revoke:id=>{calls.push({kind:'revoke',id});return stopped?.promise??Promise.resolve({...access(r),enabled:false,remainingMs:0});},
    requestStatus:query=>{calls.push({kind:'status',query:clone(query)});return queried?.promise??Promise.resolve(clone(latest.status));},
  };
  const source={current:()=>({port,nativeSession:session,projectId:'project-1',epoch:contextEpoch,preview:false,reviews:[clone(r)],blockedReason:blocked}),
    now:()=>now,nonce:()=>ID(nonce++),prepareReason:()=>null,
    prepareRequirements:async()=>{calls.push({kind:'prepare'});await prepareHook?.();},
    delegate:rv=>{calls.push({kind:'delegate'});const result={input:input(rv),current:()=>pinCurrent,
      readAfterReturned:async status=>{reads.push(clone(status));return nativeReturned;}};delegateHook?.();return result;},
  };
  const c=new AgentToolSetupController(source);t.after(()=>c.dispose());
  return {c,calls,reads,r,port,source,
    get state(){return c.getSnapshot();},
    latest(v){latest=clone(v);},allowGate(v){allowed=v;},statusGate(v){queried=v;},revokeGate(v){stopped=v;},
    now(v){now=v;},epoch(v){contextEpoch=v;c.syncContext();},blocked(v){blocked=v;},pin(v){pinCurrent=v;},native(v){nativeReturned=v;},
    delegateHook(v){delegateHook=v;},prepareHook(v){prepareHook=v;},
  };
}
async function allow(h){assert.equal(h.c.acknowledge(true),true);assert.equal(await h.c.allow(),true);}

test('five closed reviews require explicit nullable fields and refuse cross-kind/counter/private extras',()=>{
  for(const kind of TOOL_SETUP_KINDS){const r=review(kind);assert.deepEqual(clone(parseToolSetupReview(r)),r);
    for(const key of ['kind','platform','draftRevision','baselineGeneration','prepared','sources']){const bad=clone(r);delete bad[key];assert.equal(parseToolSetupReview(bad),null,key);}
    assert.equal(parseToolSetupReview({...r,path:'/not-authority'}),null);
  }
  assert.ok(parseToolSetupReview({...review(),platform:'ios'}));
  for(const bad of [{...review('inspect-requirements'),platform:'ios'}, {...review(),draftRevision:0xffff_ffff},
    {...review(),baselineGeneration:-0}, {...review(),prepared:review('inspect-requirements').prepared},
    {...review('register-reviewed-sources'),sources:{...review('register-reviewed-sources').sources,reviewId:null}},
    {...review('inspect-picked-sources'),sources:{...review('inspect-picked-sources').sources,reviewId:REVIEW}}])assert.equal(parseToolSetupReview(bad),null);
  let getters=0;const accessor={...review(),get sources(){getters++;return null;}};assert.equal(parseToolSetupReview(accessor),null);assert.equal(getters,0);
});

test('status and access correlate all IDs and native families; complete is not tool readiness',()=>{
  const done=complete();assert.ok(parseToolSetupStatus(done));assert.equal(done.result.checks[0].status,'failed');
  for(const bad of [{...done,operation:null},{...done,result:{kind:'doctor',checks:[{check:'git',status:'ok',path:'private'}]}},
    {...done,reason:'unavailable'},{...done,settlement:'pending'},{...done,unbounded:'x'.repeat(8192)}])assert.equal(parseToolSetupStatus(bad),null);
  const a=consumed(done);assert.ok(parseAgentToolSetupAccess(a));
  for(const bad of [{...a,requestId:ID(8)},{...a,grantId:ID(8)},{...a,projectId:ID(8)}, {...a,pending:true},
    {...a,unknown:true},{...a,status:{...done,review:review('acquire-missing')}}, {...access(),remainingMs:300001}])assert.equal(parseAgentToolSetupAccess(bad),null);
  assert.ok(parseAgentToolSetupAccess({...access(),enabled:false,remainingMs:0,pending:true})); // unused native approval can still be returning
  assert.deepEqual(toolSetupCommands(access()),[`mrk tool-setup-submit ${PROJECT} ${INSTANCE} ${GRANT} ${REVIEW} --reviewed`]);
  assert.equal(toolSetupCommands(a)[0],`mrk tool-setup-status ${PROJECT} ${INSTANCE} ${REQUEST}`);
});

test('draft is an immutable bounded copy; non-DATA and hidden execution overrides never encode',async()=>{
  const raw=input(),copy=copyToolSetupInput(raw);assert.ok(copy);raw.doctorDraft.android.enabled=false;
  assert.equal(copy.doctorDraft.android.enabled,true);assert.equal(Object.isFrozen(copy.doctorDraft),true);
  let reads=0;const getter={...input(),get doctorDraft(){reads++;return {};}};
  for(const bad of [getter,{...input(),argv:[]},{...input(),doctorDraft:{large:'x'.repeat(512*1024)}},
    {...input(),nativeConsent:'injected'},{...input(),sourceContext:{}},{...input(),licenseAcknowledged:true}])assert.equal(copyToolSetupInput(bad),null);
  assert.equal(reads,0);
  const calls=[],port=createAgentToolSetupPort(async(name,bytes)=>{calls.push({name,body:JSON.parse(new TextDecoder().decode(bytes))});return {};});
  await port.allow(GRANT,input());await port.access();await port.revoke(GRANT);await port.requestStatus(queued().origin);
  assert.deepEqual(calls.map(c=>c.name),['allow_agent_tool_setup','agent_tool_setup_access','revoke_agent_tool_setup','agent_tool_setup_request_status']);
  assert.equal(calls[0].body.consentVersion,toolSetupConsent('doctor'));assert.equal(calls[0].body.doctorDraft.example,0.5);
  for(const call of [()=>port.allow('0'.repeat(32),input()),()=>port.allow(GRANT,getter),()=>port.requestStatus({...queued().origin,kind:'doctor'})])await assert.rejects(call);
  assert.equal(calls.length,4);assert.equal(reads,0);
});

test('real optional native bridge has exactly four local-main ACL commands; preview cannot delegate',async()=>{
  const calls=[],api=createNativeApi('native',async(name,bytes)=>{calls.push({name,bytes});return empty();});
  await api.agentToolSetup.access();await api.agentToolSetup.allow(GRANT,input());
  await api.agentToolSetup.revoke(GRANT);await api.agentToolSetup.requestStatus(queued().origin);
  assert.equal(calls.length,4);assert.ok(calls.every(c=>c.bytes instanceof Uint8Array));
  const allowed=capability.permissions.filter(s=>s.includes('agent-tool-setup'));
  assert.deepEqual(new Set(allowed),new Set(calls.map(c=>'allow-'+c.name.replaceAll('_','-'))));
  assert.equal(allowed.length,4);assert.deepEqual(capability.windows,['main']);
  assert.equal(createNativeApi('preview',async()=>{assert.fail('no preview invoke');}).agentToolSetup,null);
});

test('Allow retains the original invocation and never calls a native Start or repeats while pending',async t=>{
  const h=harness(t),gate=deferred();h.allowGate(gate);h.c.acknowledge(true);const first=h.c.allow();
  assert.equal(h.state.pending,'allow');assert.equal(await h.c.allow(),false);assert.equal(h.calls.filter(c=>c.kind==='allow').length,1);
  assert.ok(h.c.ownerReason());gate.resolve(access());assert.equal(await first,true);
  assert.equal(h.state.access.enabled,true);assert.ok(h.c.ownerReason());assert.equal(h.reads.length,0);
});

test('unused withdrawal waits the original reply and a genuinely fresh native read',async t=>{
  const h=harness(t);await allow(h);h.native(false);
  assert.equal(await h.c.revoke(),true);assert.ok(h.c.ownerReason());assert.equal(h.state.nativeReadJoined,false);assert.equal(h.reads.length,1);
  h.native(true);h.latest({...access(),enabled:false,remainingMs:0});await h.c.check();
  assert.equal(h.state.nativeReadJoined,true);assert.equal(h.c.ownerReason(),null);assert.equal(h.reads.length,2);
});

test('reentrant withdrawal before Allow tombstones the new nonce, not an older grant',async t=>{
  const h=harness(t);let revoking=null;
  h.c.subscribe(()=>{if(h.state.pending==='allow'&&!revoking){revoking=h.c.revoke();}});
  h.c.acknowledge(true);assert.equal(await h.c.allow(),false);await revoking;
  assert.equal(h.calls.filter(c=>c.kind==='allow').length,0);assert.deepEqual(h.calls.filter(c=>c.kind==='revoke'),[{kind:'revoke',id:GRANT}]);
  assert.equal(h.state.unknown,false);assert.equal(h.c.ownerReason(),null);
});

test('post-delegation context loss before invoke keeps the UI original, never fabricates no-native retirement',async t=>{
  const h=harness(t);h.native(false);h.delegateHook(()=>h.blocked('Another original arrived.'));h.c.acknowledge(true);
  assert.equal(await h.c.allow(),false);assert.equal(h.calls.filter(c=>c.kind==='allow').length,0);assert.ok(h.c.ownerReason());
  await h.c.check();assert.equal(h.state.nativeReadJoined,false);assert.equal(h.calls.filter(c=>c.kind==='access').length,0);
  h.native(true);await h.c.check();assert.equal(h.c.ownerReason(),null);assert.equal(h.state.nativeReadJoined,true);
});

test('lost Allow is absorbing and later empty access never authorizes another submission',async t=>{
  const h=harness(t),gate=deferred();h.allowGate(gate);h.c.acknowledge(true);const first=h.c.allow();gate.reject(new Error('inert lost reply'));await first;
  assert.equal(h.state.unknown,true);h.latest(empty());await h.c.check();assert.equal(h.state.unknown,true);
  assert.equal(h.c.acknowledge(true),false);assert.equal(await h.c.allow(),false);assert.equal(h.reads.length,0);
});

test('consumed request checks its exact original even if the shared access view moves to another row',async t=>{
  const h=harness(t);await allow(h);h.latest(consumed(queued()));await h.c.check();
  assert.equal(h.state.access.status.state,'queued');const gate=deferred();h.statusGate(gate);
  h.latest({...access(),grantId:ID(20),reviewId:ID(21)});const checking=h.c.check();
  assert.deepEqual(h.calls.at(-1),{kind:'status',query:queued().origin});assert.equal(h.state.nativeReadJoined,false);
  gate.resolve(complete());await checking;assert.equal(h.state.nativeReadJoined,true);assert.equal(h.c.ownerReason(),null);
  assert.deepEqual(h.reads,[complete()]);assert.equal(h.state.access.grantId,GRANT);
});

test('service settled DATA alone cannot release a failed or pending original native read',async t=>{
  const h=harness(t);await allow(h);h.native(false);h.latest(consumed(complete()));await h.c.check();
  assert.equal(h.state.access.status.settlement,'settled');assert.equal(h.state.nativeReadJoined,false);assert.ok(h.c.ownerReason());
  h.native(true);await h.c.check();assert.equal(h.state.nativeReadJoined,true);
});

test('wrong original IDs and backwards status revisions remain unknown',async t=>{
  for(const corrupt of [a=>({...a,grantId:ID(20)}),a=>({...a,review:{...a.review,draftRevision:10}})]){
    const h=harness(t);await allow(h);h.latest(corrupt(access()));await h.c.check();assert.equal(h.state.unknown,true);assert.equal(h.reads.length,0);
  }
  const h=harness(t);await allow(h);h.latest(consumed({...queued(),revision:4}));await h.c.check();
  h.latest(consumed({...queued(),revision:3}));await h.c.check();assert.equal(h.state.unknown,true);
});

test('displayed remaining lifetime uses call start, never late receipt time',async t=>{
  const h=harness(t),gate=deferred();h.allowGate(gate);h.c.acknowledge(true);const first=h.c.allow();
  h.now(5100);gate.resolve({...access(),remainingMs:10000});await first;assert.equal(h.c.remainingSeconds(),5);
  h.now(10100);assert.equal(h.c.remainingSeconds(),0);h.now(99);assert.equal(h.c.remainingSeconds(),null);
});

test('review/context edits retire checkbox; no copied old input follows a new epoch',async t=>{
  const h=harness(t);h.c.acknowledge(true);h.epoch({});assert.equal(h.state.acknowledged,false);
  assert.equal(await h.c.allow(),false);assert.equal(h.calls.length,0);
});

test('Advanced Prepare uses one real owner callback without disabling its own call or starting a later phase',async t=>{
  const h=harness(t);const gate=deferred();h.prepareHook(async()=>{assert.equal(h.c.toolPreparePeerReason(),null);assert.ok(h.c.ownerReason());await gate.promise;});
  const flow=h.c.prepareRequirements();assert.equal(h.state.pending,'prepare');assert.equal(await h.c.prepareRequirements(),false);
  gate.resolve();assert.equal(await flow,true);assert.deepEqual(h.calls,[{kind:'prepare'}]);
});

test('Advanced Prepare rematches its original after pending listeners before the fresh owner capture',async t=>{
  for(const cut of ['project','epoch','api','session','dispose','eligibility','eligibility-reentry']){
    const h=harness(t);let entered=false;
    h.c.subscribe(()=>{
      if(entered||h.state.pending!=='prepare')return;entered=true;
      const before=h.source.current;
      if(cut==='dispose')h.c.dispose();
      else if(cut==='eligibility')h.source.prepareReason=()=>'A different original now blocks Prepare.';
      else if(cut==='eligibility-reentry')h.source.prepareReason=()=>{
        h.source.current=()=>({...before(),projectId:'project-2'});return null;
      };
      else h.source.current=()=>({...before(),...({
        project:{projectId:'project-2'},epoch:{epoch:{}},api:{port:{...h.port}},session:{nativeSession:{}},
      }[cut])});
    });
    assert.equal(await h.c.prepareRequirements(),false,cut);
    await h.c.whenSettled();
    assert.equal(entered,true,cut);assert.deepEqual(h.calls,[],cut);
    assert.equal(h.state.pending,null,cut);assert.equal(h.state.unknown,false,cut);
  }
});

test('Stop and Allow responses are separate originals; a late Allow cannot revive the revoked permission',async t=>{
  const h=harness(t),gate=deferred();h.allowGate(gate);h.c.acknowledge(true);const allowing=h.c.allow();
  await h.c.revoke();assert.equal(h.state.nativeReadJoined,false);assert.ok(h.c.ownerReason());
  gate.resolve(access());await allowing;assert.equal(h.state.access.enabled,false);assert.equal(h.state.nativeReadJoined,false);
  h.latest({...access(),enabled:false,remainingMs:0});await h.c.check();assert.equal(h.c.ownerReason(),null);assert.equal(h.state.nativeReadJoined,true);
});
