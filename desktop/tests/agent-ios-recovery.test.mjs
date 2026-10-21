// Inert original controllers/RAW codecs/Workspace reducer. No native recovery,
// account, files, tool, key, provider or qualification is exercised here.
import assert from 'node:assert/strict';
import test from 'node:test';
import {IOSArchiveController} from '../src/iosArchive.ts';
import {AgentIOSArchivePermission, createAgentIOSArchiveApi, copyIOSArchiveApproval,
  encodeIOSArchiveAccessRequest, AGENT_IOS_ARCHIVE_CONSENT} from '../src/agentIOSArchive.ts';
import {AGENT_IOS_RECOVERY_CONSENT, ACCOUNT_CONFIRMATION, PROJECT_CONFIRMATION,
  copyIOSRecoveryApproval, parseIOSRecoveryAccess} from '../src/agentIOSRecovery.ts';
import {parseBuildPermissionAccess} from '../src/agentBuildPermissionProtocol.ts';
import {parseIOSArchiveStatus, IOS_RECOVERY_LIMITATIONS} from '../src/iosArchiveProtocol.ts';
import {initialWorkspace, workspaceReducer} from '../src/drafts.ts';

const id=c=>c.repeat(32), clone=structuredClone;
const ORIGIN={projectId:id('a'),serviceInstance:id('b'),requestId:id('c')};
const INSPECTION={operationId:id('d'),ownerGeneration:id('e')};
const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};};
const flush=async()=>{for(let i=0;i<12;i++)await Promise.resolve();};
const selected=action=>({projectId:'p1',recovery:action==='inspect'?{action}:{action,inspection:clone(INSPECTION)}});
const access=(patch={})=>({enabled:false,remainingMs:0,projectId:null,observationRevision:null,consumed:false,permissionRevision:'0',...patch});
const marker=()=>({origin:clone(ORIGIN),inspection:clone(INSPECTION)});
const acknowledged=()=>access({recoveryInspection:marker()});
const activeAccess=(revision='1')=>access({enabled:true,remainingMs:800000,projectId:ORIGIN.projectId,observationRevision:7,permissionRevision:revision});
const status=(revision=0,operation=null,patch={})=>({schemaVersion:2,statusRevision:revision,availability:'available',
  modeCapabilities:{unsigned:true,signed:true,recovery:true,signingCheck:false},operation,...patch});
const operation=(patch={})=>({...INSPECTION,context:{projectId:'p1',platform:'ios',operation:'ios-local-recovery',recovery:{action:'inspect'}},
  phase:'awaiting-consent',intentUsable:true,outcome:null,reason:'none',stage:null,activity:null,report:null,
  agentIosArchive:clone(ORIGIN),...patch});
const complete=(patch={})=>operation({phase:'terminal',intentUsable:false,outcome:'complete',stage:'disposing-work',activity:{stage:'disposing-work'},
  report:{schemaVersion:1,scope:'local-ios-recovery',account:{status:'pending',session:id('f'),next:'ordinary'},
    project:{status:'cleanup-only',session:id('1'),next:'ordinary'},limitations:[...IOS_RECOVERY_LIMITATIONS]},...patch});

async function setup(t,initial=status()) {
  let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p1',name:'DATA recovery',path:'/inert/never-opened'}});
  let current=clone(initial), listener, blocked=false, other=null, permissionApi;
  const calls=[],gui=[];
  const native={mode:'native',subscribeIOSArchive:async fn=>{listener=fn;return()=>{listener=null;};},
    iosArchiveStatus:async()=>clone(current),
    prepareIOSArchive:input=>{const call={kind:'prepare',input,...deferred()};gui.push(call);return call.promise;},
    startIOSArchive:input=>{const call={kind:'start',input,...deferred()};gui.push(call);return call.promise;},
    cancelIOSArchive:async(operationId,ownerGeneration)=>{gui.push({kind:'cancel',operationId,ownerGeneration});
      if(current.operation&&current.operation.phase!=='terminal')current=status(current.statusRevision+1,
        {...current.operation,phase:'terminal',intentUsable:false,outcome:'cancelled',reason:'cancelled',stage:null,activity:null,report:null});
      return clone(current);},
  };
  const controller=new IOSArchiveController({selectedProject:()=>workspace.selectedId?workspace.projects[workspace.selectedId]:null,
    releaseVersion:()=>null,otherOperationReason:()=>other,now:()=>100});
  controller.syncProject();controller.setRecoveryVisible(true);await controller.connect(native);
  const api=createAgentIOSArchiveApi('native',(command,raw)=>{assert.ok(raw instanceof Uint8Array&&raw.length<=4096);
    const call={command,input:JSON.parse(new TextDecoder().decode(raw)),...deferred()};calls.push(call);return call.promise;});
  permissionApi=api;
  // SAME App callback: actual returned comparison is only input to the
  // controller's original project/inspection gates, never a native witness.
  const permission=new AgentIOSArchivePermission(()=>({api:permissionApi,
    project:controller.agentArchiveApproval(permission.acknowledgedInspection()),blocked}));
  const sync=()=>permission.syncContext();
  const unsubscribe=controller.subscribe(sync);
  t.after(async()=>{unsubscribe();controller.dispose();await flush();});
  return {controller,permission,api,calls,gui,native,
    get state(){return controller.getSnapshot();},
    emit(value){assert.ok(parseIOSArchiveStatus(value),'strict native DATA fixture');current=clone(value);listener?.(clone(value));},
    replyGui(call,value){assert.ok(parseIOSArchiveStatus(value));current=clone(value);call.resolve(clone(value));},
    choose(action){const ok=controller.selectAgentRecovery(action,permission.acknowledgedInspection());permission.syncContext();return ok;},
    async check(value=access()){const n=calls.length,done=permission.status();assert.equal(calls.length,n+1);calls.at(-1).resolve(clone(value));await done;},
    async allow(value=activeAccess()){permission.acknowledge(true);const n=calls.length,done=permission.allow();assert.equal(calls.length,n+1);calls.at(-1).resolve(clone(value));await done;},
    blocked(value){blocked=value;permission.syncContext();},other(value){other=value;permission.syncContext();},
    replaceApi(value){permissionApi=value;permission.syncContext();},
    dispatch(action){controller.beforeWorkspaceAction(action);workspace=workspaceReducer(workspace,action);controller.syncProject();permission.syncContext();},
  };
}

test('recovery MAIN grammar is configless, scalar inspection IDs and action-specific confirmation only',()=>{
  for(const action of ['inspect','account','project']) {
    const approval=selected(action);assert.deepEqual(clone(copyIOSArchiveApproval(approval)),approval);
    const expected={...approval,expectedPermissionRevision:'0',consentVersion:AGENT_IOS_RECOVERY_CONSENT,
      ...(action==='inspect'?{}:{confirmation:action==='account'?ACCOUNT_CONFIRMATION:PROJECT_CONFIRMATION})};
    assert.deepEqual(JSON.parse(new TextDecoder().decode(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',expected))),expected);
    for(const consentVersion of [AGENT_IOS_ARCHIVE_CONSENT,'agent-saved-ios-signed-export-v1','local-ios-recovery-v1'])
      assert.equal(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',{...expected,consentVersion}),null);
    for(const field of ['input','session','root','privateKey','signing','savedConfig','force'])
      assert.equal(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',{...expected,[field]:'not-authority'}),null);
    assert.equal(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',{...expected,confirmation:null}),null);
    if(action!=='inspect') {const bad=clone(expected);delete bad.confirmation;assert.equal(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',bad),null);}
  }
  for(const recovery of [{action:'inspect',inspection:INSPECTION},{action:'account'},{action:'project',inspection:null},
    {action:'account',inspection:{...INSPECTION,operationId:'0'.repeat(32)}},{action:'account',inspection:INSPECTION,session:id('f')},{action:'manual'}])
    assert.equal(copyIOSRecoveryApproval({projectId:'p1',recovery}),null);
});
test('recovery copying refuses getters and oversized/foreign access; old MAIN parser stays closed',()=>{
  let read=0;const value=selected('account');Object.defineProperty(value.recovery,'inspection',{enumerable:true,get(){read++;return INSPECTION;}});
  assert.equal(copyIOSRecoveryApproval(value),null);assert.equal(read,0);
  assert.equal(copyIOSRecoveryApproval({...selected('inspect'),projectId:'x'.repeat(4097)}),null);
  const good=acknowledged();assert.ok(parseIOSRecoveryAccess(good));assert.equal(parseBuildPermissionAccess(good),null);
  assert.deepEqual(clone(parseIOSRecoveryAccess(access())),access());
  for(const patch of [{recoveryInspection:null},{recoveryInspection:{...marker(),nativeJoined:true}},
    {recoveryInspection:{...marker(),inspection:{...INSPECTION,session:id('f')}}},{permissionRevision:'01'},
    {recoveryInspection:{...marker(),origin:{...ORIGIN,requestId:'0'.repeat(32)}}},{unknown:true}])
    assert.equal(parseIOSRecoveryAccess({...good,...patch}),null);
  const copied=copyIOSRecoveryApproval(selected('project'));assert.ok(Object.isFrozen(copied.recovery.inspection));
});
test('configless explicit Inspect uses existing permission RAW and never invokes GUI Prepare/Start',async t=>{
  const h=await setup(t);assert.equal(h.state.project.savedConfig,null);assert.equal(h.state.project.savedVersion,null);
  assert.equal(h.choose('inspect'),true);assert.ok(h.controller.prepareReason());
  h.permission.acknowledge(true);await h.permission.allow();assert.equal(h.calls.length,0,'actual Access reply required');
  await h.check();assert.equal(h.permission.getState().acknowledged,false);await h.allow();
  assert.deepEqual(h.calls[1].input,{...selected('inspect'),consentVersion:AGENT_IOS_RECOVERY_CONSENT,expectedPermissionRevision:'0'});
  assert.deepEqual(h.gui,[]);assert.equal(h.permission.getState().acknowledged,false);
});
test('delegated native events are observe/STOP only and terminal does not replace caller/history acknowledgment',async t=>{
  const h=await setup(t);h.choose('inspect');h.emit(status(1,operation()));
  assert.equal(h.state.consent,null);assert.ok(h.controller.startReason());assert.equal(h.choose('account'),false);
  h.emit(status(2,operation({phase:'running',intentUsable:false,stage:'recovering-account'})));
  h.emit(status(3,complete()));assert.equal(h.state.historical,true);assert.equal(h.choose('account'),false);
  await h.check(access({consumed:true}));assert.equal(h.choose('project'),false);
  assert.match(h.controller.agentRecoveryReason('account'),/caller\/history returns/);
  assert.equal(h.state.consent,null);assert.deepEqual(h.gui,[]);
});
test('same returned inspection permits only separately selected/confirmed Account or Project restore',async t=>{
  for(const action of ['account','project']) {
    const h=await setup(t);h.choose('inspect');h.emit(status(1,complete()));
    await h.check(acknowledged());assert.equal(h.choose(action),true);
    assert.deepEqual(clone(h.controller.agentArchiveApproval(h.permission.acknowledgedInspection())),selected(action));
    assert.equal(h.permission.getState().acknowledged,false);await h.allow();
    const sent=h.calls.at(-1).input;
    assert.equal(sent.confirmation,action==='account'?ACCOUNT_CONFIRMATION:PROJECT_CONFIRMATION);
    assert.deepEqual(sent.recovery,selected(action).recovery);assert.equal(Object.hasOwn(sent.recovery,'session'),false);
    assert.equal(sent.consentVersion,AGENT_IOS_RECOVERY_CONSENT);assert.deepEqual(h.gui,[]);
    assert.equal(h.state.consent,null,'CLI origin does not become GUI Start consent');
  }
});
test('refresh retains only its already returned same-context comparison; changed/lost reply cannot rearm restore',async t=>{
  const h=await setup(t);h.choose('inspect');h.emit(status(1,complete()));await h.check(acknowledged());h.choose('account');
  const read=h.permission.status();h.permission.syncContext();assert.equal(h.permission.canAllow(),false);
  h.calls.at(-1).resolve(acknowledged());await read;assert.ok(h.controller.agentArchiveApproval(h.permission.acknowledgedInspection()));
  const lost=h.permission.status();h.calls.at(-1).reject(new Error('inert lost return'));await lost;
  assert.equal(h.permission.acknowledgedInspection(),null);assert.equal(h.controller.agentArchiveApproval(h.permission.acknowledgedInspection()),null);
  assert.equal(h.choose('inspect'),true);await h.check(acknowledged());assert.equal(h.choose('account'),true);
  await h.check(access());assert.equal(h.controller.agentArchiveApproval(h.permission.acknowledgedInspection()),null);
});
test('foreign operation/generation/origin marker and manual/busy/conflicting rows never authorize restore',async t=>{
  for(const field of ['operationId','ownerGeneration','projectId','serviceInstance','requestId']) {
    const h=await setup(t);h.choose('inspect');h.emit(status(1,complete()));const wrong=acknowledged();
    if(field in wrong.recoveryInspection.inspection)wrong.recoveryInspection.inspection[field]=id('9');else wrong.recoveryInspection.origin[field]=id('9');
    await h.check(wrong);assert.equal(h.choose('account'),false,field);assert.deepEqual(h.gui,[]);
  }
  for(const row of [{status:'busy',session:id('f'),next:'wait'},{status:'manual-required',session:id('f'),next:'manual'},
    {status:'conflict',session:id('f'),next:'preserve'}]) {
    const h=await setup(t);h.choose('inspect');const op=complete();op.report.account=row;h.emit(status(1,op));await h.check(acknowledged());
    assert.equal(h.choose('account'),false);assert.equal(h.choose('project'),true);
  }
});
test('project/API ABA and a newer inspection cannot replace the selected original',async t=>{
  const h=await setup(t);h.choose('inspect');h.emit(status(1,complete()));await h.check(acknowledged());h.choose('account');
  h.dispatch({type:'select',project:{id:'p2',name:'Other DATA',path:'/inert/other'}});
  h.dispatch({type:'select',project:{id:'p1',name:'DATA recovery',path:'/inert/never-opened'}});
  assert.equal(h.controller.agentArchiveApproval(h.permission.acknowledgedInspection()),null);assert.equal(h.choose('account'),false);
  const next=complete({operationId:id('2'),ownerGeneration:id('3'),agentIosArchive:{...ORIGIN,requestId:id('4')}});
  h.emit(status(2,next));await h.check(acknowledged());assert.equal(h.choose('account'),false);
  const h2=await setup(t);h2.choose('inspect');h2.emit(status(1,complete()));await h2.check(acknowledged());
  h2.replaceApi({status:async()=>acknowledged(),allow:async()=>activeAccess(),revoke:async()=>access()});
  assert.equal(h2.permission.acknowledgedInspection(),null);assert.equal(h2.choose('account'),false);
});
test('known failed inspection is comparison-only; STOP and Unknown never become follow-on permission',async t=>{
  for(const [outcome,reason,expected] of [['failed','recovery-attention',true],['refused','recovery-attention',true],
    ['cancelled','cancelled',false],['failed','command-failed',false]]) {
    const h=await setup(t);h.choose('inspect');h.emit(status(1,complete({outcome,reason})));await h.check(acknowledged());
    assert.equal(h.choose('account'),expected,reason);assert.deepEqual(h.gui,[]);
  }
  const h=await setup(t);h.choose('inspect');h.emit(status(1,operation({phase:'unknown',intentUsable:false,outcome:'unknown',reason:'cleanup-unknown'})));
  await h.check(acknowledged());assert.equal(h.choose('account'),false);assert.equal(h.choose('inspect'),false);assert.equal(h.state.consent,null);
});
test('reentrant selection or Revoke before Allow send cannot use retained inspection comparison',async t=>{
  const h=await setup(t);h.choose('inspect');h.emit(status(1,complete()));await h.check(acknowledged());h.choose('account');
  let once=false;const off=h.permission.subscribe(s=>{if(s.pending==='allow'&&!once){once=true;h.controller.selectionIntent();}});
  h.permission.acknowledge(true);await h.permission.allow();off();assert.equal(h.calls.length,1,'no Allow after original context invalidation');
  const r=await setup(t);r.choose('inspect');r.emit(status(1,complete()));await r.check(acknowledged());r.choose('project');
  let stopped,seen=false;const un=r.permission.subscribe(s=>{if(s.pending==='allow'&&!seen){seen=true;stopped=r.permission.revoke();}});
  r.permission.acknowledge(true);const allowing=r.permission.allow();assert.equal(r.calls.at(-1).command,'revoke_agent_ios_archive');
  r.calls.at(-1).resolve(access({permissionRevision:'1'}));await stopped;await allowing;un();
  assert.equal(r.calls.filter(c=>c.command==='allow_agent_ios_archive').length,0);assert.equal(r.permission.acknowledgedInspection(),null);
});
test('late/lost Allow keeps original promise; Revoke ACK does not manufacture its return or a new restore',async t=>{
  for(const lost of [false,true]) {
    const h=await setup(t);h.choose('inspect');h.emit(status(1,complete()));await h.check(acknowledged());h.choose('account');
    h.permission.acknowledge(true);const allowing=h.permission.allow(),call=h.calls.at(-1);assert.equal(call.command,'allow_agent_ios_archive');
    const stopping=h.permission.revoke();h.calls.at(-1).resolve(access({permissionRevision:'1'}));await stopping;
    assert.equal(h.permission.getState().pending,'allow');assert.equal(h.permission.canAllow(),false);
    if(lost)call.reject(new Error('inert lost original'));else call.resolve(activeAccess());await allowing;
    assert.equal(h.permission.acknowledgedInspection(),null);assert.equal(h.permission.getState().acknowledged,false);assert.deepEqual(h.gui,[]);
  }
});
test('original GUI Prepare caller remains retained despite a delegated terminal event',async t=>{
  const h=await setup(t);const preparing=h.controller.prepareRecovery('inspect');assert.equal(h.gui.length,1);
  h.emit(status(1,complete()));assert.equal(h.state.pending,'prepare');assert.equal(h.choose('inspect'),false);
  const ordinary=operation();delete ordinary.agentIosArchive;h.replyGui(h.gui[0],status(2,ordinary));await preparing;
  assert.equal(h.permission.acknowledgedInspection(),null);assert.equal(h.state.consent!==null||h.state.nativeBlocked,true);
  assert.equal(h.calls.length,0);
});
