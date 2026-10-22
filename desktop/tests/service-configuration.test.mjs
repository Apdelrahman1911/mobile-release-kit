// Inert actual controller/bridge/reducer tests. No native process, files,
// credentials, provider, synthetic native authority or claimed real joins.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ConfigEditController } from '../src/configEditController.ts';
import { configurationOwnerReason } from '../src/configEdit.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { createConfigurationApi, parseConfigurationStatus, changedConfiguration, settingsFromConfig, configurationChange, configurationSettings, CONFIGURATION_CONSENT } from '../src/serviceConfigurationProtocol.ts';
const ids = {instance:'1'.repeat(32),project:'2'.repeat(32),request:'3'.repeat(32),session:'4'.repeat(32),window:'5'.repeat(32),revision:'6'.repeat(32),plan:'7'.repeat(32)};
const origin = {serviceInstance:ids.instance,projectId:ids.project,requestId:ids.request};
const original = {sessionId:ids.session,ownerGeneration:ids.window,revision:ids.revision};
const BASE = {schemaVersion:1,source:{candidateBranch:'main',productionBranch:'production'},android:{enabled:true,module:':app',variant:'release',applicationId:'example.fixture'},ios:{enabled:false},commands:{sentinel:'not exported'}};
const CHANGE = {kind:'source',candidateBranch:'candidate',productionBranch:'production'};
const AFTER = changedConfiguration(BASE, CHANGE);
const assurance = {basis:'schema-policy',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'};
const validation = {valid:true,state:'format-valid',issues:[],requirements:[],assurance};
const files = [{path:'release/mobile-release.json',action:'replace',beforeBytes:240,afterBytes:260},{path:'.gitignore',action:'append',beforeBytes:130,afterBytes:147}];
const summary = (base,path) => {const value=path.split('.').reduce((v,k)=>v?.[k],base);return Array.isArray(value)?{present:true,type:'array',count:value.length}:{present:true,type:'string'};};
const view = (paths=['source.candidateBranch'],base=BASE,after=AFTER) => ({schemaVersion:1,files:structuredClone(files),createReleaseDirectory:false,rewritesConfigFormatting:true,ignoreAdditions:['.mobile-release/'],preview:{schemaVersion:1,validation:structuredClone(validation),assurance:structuredClone(assurance),comparison:{baseProvided:true,kind:'compare',state:'complete',semanticallyChanged:true,counts:{added:0,changed:paths.length,removed:0},changes:paths.map(path=>({path,operation:'change',before:summary(base,path),after:summary(after,path)})),unreviewedCount:0},fields:paths.map(path=>({path,state:'optional',present:true,reason:'Inert selected setting.'}))}});
const review = (base=BASE,after=AFTER) => ({planToken:ids.plan,nativeStatusRevision:5,before:settingsFromConfig(base),after:settingsFromConfig(after),files:structuredClone(files),createReleaseDirectory:false,rewritesConfigFormatting:true,ignoreAdditions:['.mobile-release/']});
function row(phase='queued-read', extra={},base=BASE) {const read=['queued-read','opening'].includes(phase);return {schemaVersion:1,origin:structuredClone(origin),revision:1,runtimeProjectId:'project-a',phase,operationId:read?null:ids.session,ownerGeneration:read?null:ids.window,original:read?null:structuredClone(original),settings:read?null:settingsFromConfig(base),change:null,review:null,permissionLive:false,remainingMs:0,applyConsumed:false,cancelRequested:false,result:null,doNotReplay:true,...extra};}
const status = (revision, request) => ({serviceInstance:ids.instance,revision,request});
function owner(phase, extra={},base=BASE,change=CHANGE) {return {projectId:'project-a',sessionId:ids.session,ownerGeneration:ids.window,phase,reviewRemainingMs:900000,checkout:phase==='opening'?null:{revision:ids.revision,base:structuredClone(base)},prepared:['reviewing','applying','final'].includes(phase)?{revision:ids.revision,planToken:ids.plan,draftRevision:0,baselineGeneration:0,view:view(change.kind==='metadata'?['metadata.root','metadata.androidLocales','metadata.iosLocales']:undefined,base,changedConfiguration(base,change))}:null,applySubmitted:['applying','final'].includes(phase),coreOutcome:phase==='final'?{effect:'committed',journal:'clean',resources:'settled',reason:'none'}:null,nativeReason:'none',nativeFinality:phase==='final'?'settled':'pending',lateSettled:false,...extra};}
const native = (revision, active=null, lastTerminal=null) => ({schemaVersion:1,windowGeneration:ids.window,statusRevision:revision,capability:{available:true,reason:'available'},active,lastTerminal});
function loaded(base=BASE) {let w=workspaceReducer(initialWorkspace,{type:'select',project:{id:'project-a',name:'App',path:'/inert/not-opened'}});w=workspaceReducer(w,{type:'snapshot-start',projectId:'project-a',requestId:1});return workspaceReducer(w,{type:'snapshot-done',projectId:'project-a',requestId:1,observedAt:1,snapshot:{root:'/inert/not-opened',observedAt:'',observationScope:'single-request-non-atomic',config:{content:null,path:'release/mobile-release.json',state:'format-valid',data:structuredClone(base),issues:[]},discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance:{...assurance,basis:'static-text'},issues:[]}});}
const flush = async () => {for(let n=0;n<20;n++)await Promise.resolve();};
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function fixture(base=BASE,change=CHANGE) {
 const after=changedConfiguration(base,change);
 const model={row:(phase,extra)=>row(phase,extra,base),owner:(phase,extra)=>owner(phase,extra,base,change),review:()=>review(base,after)};
 let w=loaded(base), ns=native(1), ss=status(1,null), nfn=()=>{}, sfn=()=>{}, revision=1, peer=null;
 const calls=[], saves=[];let custom=null, allowCustom=null, revokeCustom=null;
 let controller;
 const dispatch = action => {controller.beforeWorkspaceAction(action);w=workspaceReducer(w,action);controller.syncDraft();};
 const service = {status:async()=>ss,subscribe:async(fn)=>{sfn=fn;return()=>{};},allow:async(a)=>{calls.push(['allow',structuredClone(a)]);if(allowCustom)return allowCustom(a);const r={...ss.request,permissionLive:true,remainingMs:10000,revision:ss.request.revision+1};ss=status(++revision,r);return ss;},revoke:async(q)=>{calls.push(['revoke',structuredClone(q)]);if(revokeCustom)return revokeCustom(q);const r={...ss.request,phase:ss.request.operationId?'stopping':'refused',permissionLive:false,remainingMs:0,cancelRequested:true,revision:ss.request.revision+1};ss=status(++revision,r);return ss;},continue:async(q,step)=>{calls.push([step,structuredClone(q)]);if(custom)return custom(q,step);ns=step==='read'?native(2,model.owner('opening')):step==='prepare'?native(4,model.owner('preparing')):native(6,model.owner('applying'));return ns;}};
 const api={mode:'native',agentConfiguration:service,subscribeConfigEdit:async(fn)=>{nfn=fn;return()=>{};},configEditStatus:async()=>ns};
 controller=new ConfigEditController({project:id=>w.projects[id]??null,selectedProject:()=>w.selectedId?w.projects[w.selectedId]??null:null,otherEditReason:()=>peer,
 onConfirmedSave:()=>assert.fail('Delegation is not a GUI save attempt'),onDelegatedSave:receipt=>{saves.push(receipt);dispatch({type:'delegated-config-save-final',projectId:receipt.request.runtimeProjectId,receipt});}});
 return {controller,service,api,calls,saves,dispatch,get workspace(){return w;},get request(){return ss.request;},get native(){return ns;},set peer(value){peer=value;},set custom(fn){custom=fn;},set allowCustom(fn){allowCustom=fn;},set revokeCustom(fn){revokeCustom=fn;},
 emitNative(s){ns=s;nfn(s);},emit(r){ss=status(++revision,{...r,revision});sfn(ss);},async start(){await controller.connect(api);},
 async reviewing(){await this.start();this.emit(model.row());await flush();this.emitNative(native(3,model.owner('editing')));this.emit(model.row('opened'));this.emit(model.row('queued-prepare',{change}));await flush();this.emitNative(native(5,model.owner('reviewing')));this.emit(model.row('reviewing',{change,review:model.review()}));await flush();},
 async allowed(){await this.reviewing();assert.equal(controller.agent.allowReason(),null);controller.agent.acknowledge(true);await controller.agent.allow();assert.equal(this.calls.filter(x=>x[0]==='allow').length,1);},
 async applying(){await this.allowed();this.emit(model.row('queued-apply',{change,review:model.review(),applyConsumed:true}));await flush();},
 finishCancelled(){this.emitNative(native(7,null,model.owner('final',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}})));this.emit(model.row('final',{change,review:model.review(),cancelRequested:true,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}}));},
 finish(){this.emitNative(native(7,null,model.owner('final')));this.emit(model.row('final',{change,review:model.review(),applyConsumed:true,settings:settingsFromConfig(after),result:{effect:'committed',journal:'clean',cancelled:false,applySubmitted:true}}));}};
}
test('closed required-null schema, bounds, privacy, result truth and only selected groups',()=>{
 const good=status(2,row('reviewing',{change:CHANGE,review:review()}));assert.ok(parseConfigurationStatus(good));
 for(const k of ['operationId','ownerGeneration','original','settings','change','review','result']){const v=structuredClone(good);delete v.request[k];assert.equal(parseConfigurationStatus(v),null,k);}
 for(const mutate of [v=>v.request.token='not admitted',v=>v.request.settings.android.applicationId='not disclosed',v=>v.request.review.files[1].path='.git/config',v=>v.request.permissionLive=true,v=>v.request.result={effect:'committed',journal:'clean',cancelled:false,applySubmitted:true},v=>v.request.change={kind:'android',module:':app',variant:'release',enabled:true},v=>v.request.change={kind:'ios',container:{kind:'workspace',path:'../App.xcworkspace'},scheme:'App',archiveConfiguration:'Release'}]){const v=structuredClone(good);mutate(v);assert.equal(parseConfigurationStatus(v),null);}
 assert.deepEqual(AFTER.commands,BASE.commands);assert.equal(AFTER.android.applicationId,BASE.android.applicationId);
 assert.equal(JSON.stringify(good).includes('sentinel'),false);
});
test('same raw native handlers and exact one-use permission payload, no preview port',async()=>{
 const calls=[],value=status(1,null);const api=createConfigurationApi('native',async(name,bytes)=>{calls.push([name,JSON.parse(new TextDecoder().decode(bytes))]);return name.endsWith('config_edit')?native(1):value;},async()=>()=>{});
 assert.equal(createConfigurationApi('preview',async()=>assert.fail(),async()=>()=>{}),null);
 await api.status();await api.status(origin);await api.continue(origin,'read');await api.continue(origin,'prepare');await api.continue(origin,'apply');await api.revoke(origin);
 assert.deepEqual(calls.map(x=>x[0]),['agent_configuration_status','agent_configuration_status','open_config_edit','prepare_config_edit','apply_config_edit','revoke_agent_configuration']);
 assert.deepEqual(calls[0][1],{});assert.deepEqual(calls[1][1],origin);assert.deepEqual(calls[2][1],{intent:'agent-configuration',origin});assert.deepEqual(calls[5][1],origin);
});
test('READ drives only real main-window Open/Prepare and no automatic Allow or Apply',async()=>{
 const f=fixture();await f.reviewing();assert.deepEqual(f.calls.map(x=>x[0]),['read','prepare']);assert.equal(f.controller.agent.getSnapshot().acknowledged,false);assert.equal(f.saves.length,0);
 assert.equal(f.controller.getSnapshot().attempt,null);assert.match(configurationOwnerReason(f.controller.getSnapshot(),'project-a'),/CLI|configuration/);
});
test('unconfigured READ service is a read-only unavailable probe, not an ordinary save blockade',async()=>{
 const f=fixture();f.service.status=async()=>{throw Error('inert service unavailable');};await f.start();
 assert.equal(f.controller.agent.getSnapshot().unknown,false);assert.equal(f.controller.agent.getSnapshot().pending,null);
 assert.equal(configurationOwnerReason(f.controller.getSnapshot(),'project-a'),null);assert.equal(f.calls.length,0);assert.equal(f.saves.length,0);
 assert.match(f.controller.agent.getSnapshot().message,/READ access/);
});
test('peer busy and dirty forms cannot authorize writes; READ does not erase a draft',async()=>{
 const f=fixture();await f.start();f.peer='Another original is pending';f.emit(row());await flush();assert.equal(f.calls.length,0);
 f.peer=null;f.controller.syncDraft();await flush();assert.equal(f.calls[0][0],'read');
 const dirty=fixture();dirty.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'unsaved'});await dirty.reviewing();
 const prior=dirty.workspace.projects['project-a'];assert.match(dirty.controller.agent.allowReason(),/clean/);dirty.controller.agent.acknowledge(true);await dirty.controller.agent.allow();assert.equal(dirty.calls.some(x=>x[0]==='allow'),false);assert.equal(dirty.workspace.projects['project-a'],prior);
});
test('completed original CLI save adopts both baseline and draft only for exact clean session',async()=>{
 const f=fixture();await f.applying();assert.equal(f.calls.filter(x=>x[0]==='apply').length,1);assert.equal(f.saves.length,0);f.finish();await flush();
 assert.equal(f.saves.length,1);const s=f.workspace.projects['project-a'];assert.equal(s.baseline.source.candidateBranch,'candidate');assert.equal(s.draft.source.candidateBranch,'candidate');assert.equal(isDirty(s),false);assert.equal(s.savedConfigContent,null);assert.equal(s.snapshotPredatesSave,true);assert.deepEqual(s.draft.commands,BASE.commands);
 f.finish();await flush();assert.equal(f.saves.length,1);
});
test('later dirty or ABA form preserves exact values and records actual completed save as conflict',async()=>{
 for(const aba of [false,true]){const f=fixture();await f.applying();f.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'newer'});if(aba)f.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'main'});
 const prior=f.workspace.projects['project-a'];f.finish();await flush();assert.equal(f.saves.length,1);const s=f.workspace.projects['project-a'];assert.equal(s.draft,prior.draft);assert.equal(s.baseline,prior.baseline);assert.equal(s.lastSave.resultingBaselineGeneration,null);assert.equal(s.sourceChanged,true);}
});
test('reentrant Allow publication edit and revoke retire consent before native invocation',async()=>{
 for(const action of ['edit','revoke']){const f=fixture();await f.reviewing();let once=false;const off=f.controller.agent.subscribe(()=>{if(!once&&f.controller.agent.getSnapshot().pending==='allow'){once=true;if(action==='edit')f.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'changed'});else void f.controller.agent.revoke();}});
 f.controller.agent.acknowledge(true);await f.controller.agent.allow();await flush();off();assert.equal(f.calls.some(x=>x[0]==='allow'),false);assert.equal(f.calls.some(x=>x[0]==='apply'),false);assert.equal(f.calls.filter(x=>x[0]==='revoke').length,1);}
});
test('reentrant Apply publication sees original project/epoch, no GUI repeat of the Apply',async()=>{
 const f=fixture();await f.allowed();let once=false;f.controller.agent.subscribe(()=>{if(!once&&f.controller.agent.getSnapshot().pending==='apply'){once=true;f.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'unsaved'});}});
 f.emit(row('queued-apply',{change:CHANGE,review:review(),applyConsumed:true}));await flush();assert.equal(f.calls.some(x=>x[0]==='apply'),false);assert.equal(f.calls.filter(x=>x[0]==='revoke').length,1);
});
test('original native return is retained despite earlier complete status/event',async()=>{
 const f=fixture();await f.allowed();const pending=deferred();f.custom=()=>pending.promise;f.emit(row('queued-apply',{change:CHANGE,review:review(),applyConsumed:true}));await flush();f.finish();await flush();assert.equal(f.saves.length,0);assert.equal(f.controller.agent.getSnapshot().pending,'apply');
 pending.resolve(native(7,null,owner('final')));await flush();assert.equal(f.saves.length,1);assert.equal(f.controller.agent.getSnapshot().pending,null);
});
test('lost Allow acknowledgement is absorbing and cannot replay through status refresh',async()=>{
 const f=fixture();await f.reviewing();f.allowCustom=async()=>{throw Error('inert lost reply');};f.controller.agent.acknowledge(true);await f.controller.agent.allow();assert.equal(f.controller.agent.getSnapshot().unknown,true);
 f.controller.agent.acknowledge(true);await f.controller.agent.allow();await f.controller.agent.check();assert.equal(f.calls.filter(x=>x[0]==='allow').length,1);assert.equal(f.calls.some(x=>x[0]==='apply'),false);
});
test('lost native Apply return retains Unknown despite later optimistic DATA and never resends',async()=>{
 const f=fixture();await f.allowed();f.custom=async()=>{throw Error('inert lost original return');};f.emit(row('queued-apply',{change:CHANGE,review:review(),applyConsumed:true}));await flush();assert.equal(f.controller.agent.getSnapshot().unknown,true);f.finish();await flush();assert.equal(f.saves.length,0);assert.equal(f.calls.filter(x=>x[0]==='apply').length,1);
});
test('malformed or changed preview, service replacement and original Unknown cannot mint permission',async()=>{
 for(const mutate of [r=>r.review.after.source.candidateBranch='changed',r=>r.original.revision='9'.repeat(32),r=>r.phase='unknown']){const f=fixture();await f.reviewing();const value=structuredClone(f.request);mutate(value);f.emit(value);assert.equal(f.controller.agent.getSnapshot().unknown,true);f.controller.agent.acknowledge(true);await f.controller.agent.allow();assert.equal(f.calls.some(x=>x[0]==='allow'),false);}
 const f=fixture();await f.reviewing();f.controller.agent.receive({serviceInstance:'8'.repeat(32),revision:100,request:null});assert.equal(f.controller.agent.getSnapshot().unknown,true);
});
test('read/prepare preinvoke source ABA retires that continuation without opening a replacement',async()=>{
 const f=fixture();await f.start();let once=false;f.controller.agent.subscribe(()=>{if(!once&&f.controller.agent.getSnapshot().pending==='read'){once=true;f.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'away'});f.dispatch({type:'edit',projectId:'project-a',path:'source.candidateBranch',value:'main'});}});
 f.emit(row());await flush();assert.equal(f.calls.some(x=>x[0]==='read'),false);f.controller.syncDraft();await flush();assert.equal(f.calls.some(x=>x[0]==='read'),false);
});
test('STOP overlaps pending Allow, retains both calls, and remains available after selection drift',async()=>{
 const f=fixture();await f.reviewing();const allow=deferred(),stop=deferred();f.allowCustom=()=>allow.promise;f.revokeCustom=()=>stop.promise;f.controller.agent.acknowledge(true);const a=f.controller.agent.allow();await flush();const b=f.controller.agent.revoke();await flush();
 assert.equal(f.controller.agent.getSnapshot().pending,'allow');assert.equal(f.controller.agent.getSnapshot().revokePending,true);
 stop.resolve(status(100,row('stopping',{revision:100,change:CHANGE,review:review(),cancelRequested:true})));await b;assert.equal(f.controller.agent.getSnapshot().pending,'allow');
 allow.resolve(status(99,row('reviewing',{revision:99,change:CHANGE,review:review(),permissionLive:true,remainingMs:100})));await a;assert.equal(f.controller.agent.getSnapshot().status.request.cancelRequested,true);assert.equal(f.calls.filter(x=>x[0]==='allow').length,1);assert.equal(f.calls.filter(x=>x[0]==='revoke').length,1);
});
test('same issued permission never lengthens or revives from delayed equal-revision replies',async()=>{
 const f=fixture();await f.reviewing();assert.equal(f.controller.agent.getSnapshot().status.request.remainingMs,0);
 f.controller.agent.acknowledge(true);await f.controller.agent.allow();const issued=f.controller.agent.getSnapshot().status;
 assert.equal(issued.request.permissionLive,true);assert.equal(issued.request.remainingMs,10000);
 f.controller.agent.receive({...issued,request:{...issued.request,remainingMs:40}});
 f.controller.agent.receive(issued);assert.equal(f.controller.agent.getSnapshot().status.request.remainingMs,40);
 f.controller.agent.receive({...issued,request:{...issued.request,remainingMs:0,permissionLive:false}});
 f.controller.agent.receive(issued);await f.controller.agent.check();
 assert.equal(f.controller.agent.getSnapshot().status.request.remainingMs,0);assert.equal(f.controller.agent.getSnapshot().status.request.permissionLive,false);
 assert.equal(f.controller.agent.getSnapshot().unknown,false);assert.equal(f.calls.filter(x=>x[0]==='allow').length,1);
});
test('native saved event requires the matching retired service result and cannot outrun Unknown',async()=>{
 const f=fixture();await f.applying();f.emitNative(native(7,null,owner('final')));await flush();assert.equal(f.saves.length,0);
 f.emit(row('final',{origin:{...origin,requestId:'8'.repeat(32)},change:CHANGE,review:review(),applyConsumed:true,settings:settingsFromConfig(AFTER),result:{effect:'committed',journal:'clean',cancelled:false,applySubmitted:true}}));await flush();assert.equal(f.saves.length,0);
 f.finish();await flush();assert.equal(f.saves.length,1);
 const unknown=fixture();await unknown.applying();unknown.emitNative(native(7,null,owner('final')));await flush();assert.equal(unknown.saves.length,0);
 unknown.emit(row('unknown',{change:CHANGE,review:review(),applyConsumed:true}));await flush();assert.equal(unknown.saves.length,0);assert.equal(unknown.controller.agent.getSnapshot().unknown,true);
 const nativeUnknown=fixture();await nativeUnknown.applying();nativeUnknown.emitNative(native(7,null,owner('unknown',{prepared:owner('final').prepared,applySubmitted:true,nativeReason:'caller_lost',nativeFinality:'unknown',lateSettled:true,coreOutcome:owner('final').coreOutcome})));
 nativeUnknown.emit(row('final',{change:CHANGE,review:review(),applyConsumed:true,settings:settingsFromConfig(AFTER),result:{effect:'committed',journal:'clean',cancelled:false,applySubmitted:true}}));await flush();assert.equal(nativeUnknown.saves.length,0);
});
test('known pre-Apply cancellation waits both original calls then permits a distinct reviewed request',async()=>{
 const f=fixture();await f.reviewing();const allow=deferred(),stop=deferred(),prior=f.controller.agent.getSnapshot().status;
 f.allowCustom=()=>allow.promise;f.revokeCustom=()=>stop.promise;f.controller.agent.acknowledge(true);const a=f.controller.agent.allow();await flush();const b=f.controller.agent.revoke();await flush();
 f.emit(row('stopping',{change:CHANGE,review:review(),cancelRequested:true}));f.finishCancelled();const stopped=f.controller.agent.getSnapshot().status;
 const nextOrigin={...origin,requestId:'8'.repeat(32)},nextSession='9'.repeat(32),nextPlan='a'.repeat(32);
 const nextRow=(phase,extra={})=>{const r=row(phase,{origin:nextOrigin,...extra});return r.original?{...r,operationId:nextSession,original:{...r.original,sessionId:nextSession}}:r;};
 const nextOwner=phase=>{const p=owner(phase);return {...p,sessionId:nextSession,prepared:p.prepared&&{...p.prepared,planToken:nextPlan}};};
 const nextReview={...review(),planToken:nextPlan,nativeStatusRevision:11};
 f.custom=async(_q,step)=>step==='read'?native(8,nextOwner('opening')):native(10,nextOwner('preparing'));
 f.emit(nextRow());await flush();assert.equal(f.calls.filter(x=>x[0]==='read').length,1);assert.equal(f.controller.agent.getSnapshot().pending,'allow');assert.equal(f.controller.agent.getSnapshot().revokePending,true);
 allow.resolve({...prior,revision:prior.revision+1,request:{...prior.request,revision:prior.request.revision+1,permissionLive:true,remainingMs:10000}});await a;
 assert.equal(f.calls.filter(x=>x[0]==='read').length,1);assert.equal(f.controller.agent.getSnapshot().revokePending,true);
 stop.resolve(stopped);await b;await flush();assert.equal(f.calls.filter(x=>x[0]==='read').length,2);assert.equal(f.saves.length,0);
 f.emitNative(native(9,nextOwner('editing')));f.emit(nextRow('opened'));f.emit(nextRow('queued-prepare',{change:CHANGE}));await flush();f.emitNative(native(11,nextOwner('reviewing')));f.emit(nextRow('reviewing',{change:CHANGE,review:nextReview}));await flush();
 assert.equal(f.controller.agent.getSnapshot().unknown,false);assert.equal(f.controller.agent.allowReason(),null);
 f.allowCustom=null;f.revokeCustom=null;f.controller.agent.acknowledge(true);await f.controller.agent.allow();assert.equal(f.calls.filter(x=>x[0]==='allow').length,2);
 await f.controller.agent.revoke();assert.deepEqual(f.calls.filter(x=>x[0]==='revoke').at(-1)[1],nextOrigin);assert.equal(f.calls.some(x=>x[0]==='apply'),false);
});
test('pre-Apply approval is retained for unmatched, pending, Unknown or lost original completion',async()=>{
 for(const cut of ['service-pending','native-pending','native-unknown','service-unknown','lost-allow','lost-stop']){
  const f=fixture();
  if(cut==='lost-allow'){await f.reviewing();f.allowCustom=async()=>{throw Error('inert lost Allow');};f.controller.agent.acknowledge(true);await f.controller.agent.allow();}
  else await f.allowed();
  if(cut==='lost-stop')f.revokeCustom=async()=>{throw Error('inert lost STOP');};
  await f.controller.agent.revoke();
  if(cut==='service-pending')f.emitNative(native(7,null,owner('final',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}})));
  else if(cut==='native-pending')f.emit(row('final',{change:CHANGE,review:review(),cancelRequested:true,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}}));
  else if(cut==='native-unknown'){f.emitNative(native(7,null,owner('unknown',{prepared:owner('reviewing').prepared,nativeReason:'cancelled',nativeFinality:'unknown',lateSettled:true,coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}})));f.emit(row('final',{change:CHANGE,review:review(),cancelRequested:true,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}}));}
  else {if(cut==='service-unknown')f.emit(row('unknown',{change:CHANGE,review:review(),cancelRequested:true}));f.finishCancelled();}
  await flush();const reads=f.calls.filter(x=>x[0]==='read').length;
  f.emit(row('queued-read',{origin:{...origin,requestId:'8'.repeat(32)}}));await flush();
  assert.equal(f.calls.filter(x=>x[0]==='read').length,reads,cut);assert.match(f.controller.agent.allowReason(),/retained original permission/,cut);assert.equal(f.saves.length,0,cut);
 }
});
test('explicit Check retrieves a coalesced old final without replacing latest or repeating the original',async()=>{
 const f=fixture();await f.allowed();await f.controller.agent.revoke();
 const oldFinal=row('final',{revision:f.request.revision+1,change:CHANGE,review:review(),cancelRequested:true,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}});
 f.emitNative(native(7,null,owner('final',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}})));
 const nextOrigin={...origin,requestId:'8'.repeat(32)},nextSession='9'.repeat(32),nextPlan='a'.repeat(32);
 const nextRow=(phase,extra={})=>{const r=row(phase,{origin:nextOrigin,...extra});return r.original?{...r,operationId:nextSession,original:{...r.original,sessionId:nextSession}}:r;};
 const nextOwner=phase=>{const p=owner(phase);return {...p,sessionId:nextSession,prepared:p.prepared&&{...p.prepared,planToken:nextPlan}};};
 const nextReview={...review(),planToken:nextPlan,nativeStatusRevision:11};
 f.custom=async(_q,step)=>step==='read'?native(8,nextOwner('opening')):native(10,nextOwner('preparing'));
 f.emit(nextRow());await flush(); // No old service Final is ever delivered to receive().
 const latest=f.controller.agent.getSnapshot().status,reply=deferred(),queries=[];
 f.service.status=async q=>{queries.push(q?structuredClone(q):null);return q?reply.promise:latest;};
 assert.equal(f.calls.filter(x=>x[0]==='read').length,1);assert.match(f.controller.agent.allowReason(),/retained original permission/);
 const checking=f.controller.agent.check();await flush();
 assert.deepEqual(queries,[null,origin]);assert.equal(f.controller.agent.getSnapshot().pending,'check');
 assert.deepEqual({...f.controller.agent.getSnapshot().status.request.origin},nextOrigin);assert.equal(f.calls.filter(x=>x[0]==='read').length,1);
 reply.resolve(status(latest.revision,oldFinal));await checking;await flush();
 assert.equal(f.controller.agent.getSnapshot().unknown,false);assert.deepEqual({...f.controller.agent.getSnapshot().status.request.origin},nextOrigin);
 assert.equal(f.calls.filter(x=>x[0]==='read').length,2);assert.equal(f.saves.length,0);assert.equal(f.calls.some(x=>x[0]==='apply'),false);
 f.emitNative(native(9,nextOwner('editing')));f.emit(nextRow('opened'));f.emit(nextRow('queued-prepare',{change:CHANGE}));await flush();
 f.emitNative(native(11,nextOwner('reviewing')));f.emit(nextRow('reviewing',{change:CHANGE,review:nextReview}));await flush();
 assert.equal(f.controller.agent.allowReason(),null);f.controller.agent.acknowledge(true);await f.controller.agent.allow();
 assert.equal(f.calls.filter(x=>x[0]==='allow').length,2);await f.controller.agent.revoke();
 assert.deepEqual(f.calls.filter(x=>x[0]==='revoke').at(-1)[1],nextOrigin);assert.equal(f.saves.length,0);
});
test('exact old inspection keeps pending and fails closed for missing, foreign or Unknown replies',async()=>{
 for(const cut of ['pending','missing','wrong-request','wrong-project','wrong-service','wrong-original','changed-review','unknown']){
  const f=fixture();await f.allowed();await f.controller.agent.revoke();
  const oldFinal=row('final',{revision:f.request.revision+1,change:CHANGE,review:review(),cancelRequested:true,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}});
  f.emitNative(native(7,null,owner('final',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}})));
  const nextOrigin={...origin,requestId:'8'.repeat(32)};f.emit(row('queued-read',{origin:nextOrigin}));await flush();
  const latest=f.controller.agent.getSnapshot().status;let selected=structuredClone(oldFinal),count=0;
  if(cut==='pending'||cut==='unknown'){selected.phase=cut==='pending'?'stopping':'unknown';selected.result=null;}
  if(cut==='missing')selected=null;
  if(cut==='wrong-request')selected.origin.requestId='f'.repeat(32);
  if(cut==='wrong-project')selected.origin.projectId='f'.repeat(32);
  if(cut==='wrong-service')selected.origin.serviceInstance='f'.repeat(32);
  if(cut==='wrong-original')selected.original.revision='f'.repeat(32);
  if(cut==='changed-review')selected.review.planToken='f'.repeat(32);
  f.service.status=async q=>{count++;if(!q)return latest;assert.deepEqual({...q},origin);return {...status(latest.revision,selected),serviceInstance:selected?.origin.serviceInstance??ids.instance};};
  await f.controller.agent.check();await flush();assert.equal(count,2,cut);assert.equal(f.calls.filter(x=>x[0]==='read').length,1,cut);
  assert.deepEqual({...f.controller.agent.getSnapshot().status.request.origin},nextOrigin,cut);assert.equal(f.saves.length,0,cut);
  assert.equal(f.controller.agent.getSnapshot().unknown,cut!=='pending',cut);
  if(cut==='pending'){
   selected=oldFinal;f.custom=async()=>native(8, {...owner('opening'),sessionId:'9'.repeat(32)});
   await f.controller.agent.check();await flush();assert.equal(count,4);assert.equal(f.calls.filter(x=>x[0]==='read').length,2);assert.equal(f.controller.agent.getSnapshot().unknown,false);
  }
 }
});
test('disposed original Check retains its exact pending reply without resuming a later request',async()=>{
 const f=fixture();await f.allowed();await f.controller.agent.revoke();
 const oldFinal=row('final',{revision:f.request.revision+1,change:CHANGE,review:review(),cancelRequested:true,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}});
 f.emitNative(native(7,null,owner('final',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}})));
 f.emit(row('queued-read',{origin:{...origin,requestId:'8'.repeat(32)}}));await flush();
 const latest=f.controller.agent.getSnapshot().status,reply=deferred();let queries=0;
 f.service.status=async q=>{queries++;return q?reply.promise:latest;};f.revokeCustom=async()=>latest;
 const checking=f.controller.agent.check();await flush();assert.equal(queries,2);
 f.controller.dispose();await flush();assert.equal(f.controller.agent.getSnapshot().pending,'check');
 reply.resolve(status(latest.revision,oldFinal));await checking;await flush();
 assert.equal(f.calls.filter(x=>x[0]==='read').length,1);assert.equal(f.calls.some(x=>x[0]==='apply'),false);assert.equal(f.saves.length,0);
});

const listing = () => ({root:'store/metadata',androidLocales:['en-US'],iosLocales:[]});
const listingBase = () => ({...structuredClone(BASE),metadata:listing(),services:{androidFirebase:'disabled',iosFirebase:'required'}});
const listingChange = () => ({kind:'metadata',root:'store/資料',androidLocales:['fr','zh-Hant-TW','es-419'],iosLocales:['en']});
test('metadata closed change uses exact core path and locale policy without enabling platforms',()=>{
 const base=listingBase(),change=listingChange(),next=changedConfiguration(base,change);
 assert.ok(next,'the bounded metadata group must reach the existing editor');
 assert.deepEqual(next.metadata,{root:change.root,androidLocales:change.androidLocales,iosLocales:change.iosLocales});
 for(const key of Object.keys(base).filter(k=>k!=='metadata'))assert.deepEqual(next[key],base[key],key);
 assert.equal(next.ios.enabled,false);assert.deepEqual(base.metadata,listing());
 for(const root of ['store/資料',' store ','store/meta:data','a/'.repeat(20)+'listing','😀'.repeat(300)]){
  assert.equal(configurationChange({...change,root}),true,root);
 }
 for(const root of ['', ' ', '\u0085', '\u001c', '\u3000', '../listing','/listing','C:listing','store//listing','store/./listing','store/../listing','store\\listing','store/','bad\nname','bad\rname','bad\0name','a'.repeat(513),'\ud800']){
  assert.equal(configurationChange({...change,root}),false,JSON.stringify(root));
 }
 for(const locale of ['en','eng','zh-Hant','zh-Hant-TW','es-419','abc-Latn-001'])assert.equal(configurationChange({...change,androidLocales:[locale]}),true,locale);
 for(const locales of [['en','en'],['EN'],['en-us'],['en_US'],['en-US-extra'],['en\n'],['e'],['abcd'],[null],Array.from({length:33},(_,n)=>`en-${String(n).padStart(3,'0')}`)])assert.equal(configurationChange({...change,androidLocales:locales}),false,JSON.stringify(locales));
 const all=Array.from({length:33},(_,n)=>`abc-Latn-${String(n).padStart(3,'0')}`);
 assert.equal(configurationChange({...change,androidLocales:all.slice(0,16),iosLocales:all.slice(16,32)}),true,'32 total fits this bounded CLI profile');
 assert.equal(configurationChange({...change,androidLocales:all.slice(0,17),iosLocales:all.slice(17)}),false,'17+16 is outside the profile even though each array is below 32');
 for(const bad of [{...change,root:null},{...change,enabled:true},{...change,androidLocales:null},{...change,iosLocales:undefined}])assert.equal(configurationChange(bad),false);
 assert.equal(changedConfiguration(base,{...change,androidLocales:[]}),null,'enabled Android cannot lose its last locale');
 const disabled={...base,android:{...base.android,enabled:false}};
 assert.deepEqual(changedConfiguration(disabled,{...change,androidLocales:[],iosLocales:[]}).metadata,{root:change.root,androidLocales:[],iosLocales:[]});
 const ios={...base,ios:{enabled:true,project:'App.xcodeproj',scheme:'App',archiveConfiguration:'Release'}};
 ios.metadata.iosLocales=['en'];assert.equal(changedConfiguration(ios,{...change,iosLocales:[]}),null);
});
test('unrepresentable metadata is omitted not defaulted and cannot break the original three groups',()=>{
 const variants=[undefined,null,{...listing(),unknown:'must not project'},{...listing(),root:'../no'},
  {...listing(),androidLocales:Array.from({length:33},(_,n)=>`en-${String(n).padStart(3,'0')}`)},
  {...listing(),root:'😀'.repeat(512)}];
 for(const metadata of variants){
  const base={...listingBase(),ios:{enabled:true,project:'App.xcodeproj',scheme:'App',archiveConfiguration:'Release'}};
  if(metadata===undefined)delete base.metadata;else base.metadata=metadata;
  const projected=settingsFromConfig(base);assert.ok(projected);assert.equal(Object.hasOwn(projected,'metadata'),false);
  for(const change of [CHANGE,{kind:'android',module:':mobile',variant:'release'},{kind:'ios',container:{kind:'workspace',path:'App.xcworkspace'},scheme:'Mobile',archiveConfiguration:'Release'}]){
   const next=changedConfiguration(base,change);assert.ok(next);assert.deepEqual(next.metadata,base.metadata);
  }
  assert.equal(changedConfiguration(base,listingChange()),null,'omission cannot authorize a new metadata value');
 }
 const base=listingBase(),projected=settingsFromConfig(base);assert.deepEqual(projected.metadata,listing());
 projected.metadata.androidLocales.push('fr');assert.deepEqual(base.metadata,listing(),'projection must not alias the original arrays');
 const old=settingsFromConfig(BASE);assert.equal(configurationSettings(old),true);
 for(const value of [null,{}, {...listing(),extra:false}])assert.equal(configurationSettings({...old,metadata:value}),false);
});
test('metadata request requires its real paired preview and keeps all existing public bounds',()=>{
 const base=listingBase(),change=listingChange(),after=changedConfiguration(base,change);assert.ok(after);
 const r=review(base,after),good=status(2,row('reviewing',{change,review:r},base));assert.ok(parseConfigurationStatus(good));
 assert.ok(new TextEncoder().encode(JSON.stringify(change)).length<=2048);
 for(const mutate of [v=>delete v.request.review.before.metadata,v=>delete v.request.review.after.metadata,
  v=>v.request.review.after.metadata.root='another',v=>v.request.review.after.source.candidateBranch='another',
  v=>v.request.settings.metadata=null,v=>v.request.change.candidate='not allowed']){
  const bad=structuredClone(good);mutate(bad);assert.equal(parseConfigurationStatus(bad),null);
 }
});
test('metadata actual controller keeps separate consent and both original finality cuts before adoption',async()=>{
 const base=listingBase(),change=listingChange(),after=changedConfiguration(base,change);assert.ok(after);
 const f=fixture(base,change);await f.reviewing();
 assert.deepEqual(f.calls.map(x=>x[0]),['read','prepare']);assert.equal(f.controller.agent.getSnapshot().acknowledged,false);
 assert.deepEqual(structuredClone(f.controller.agent.getSnapshot().status.request.review.before.metadata),listing());
 assert.equal(f.controller.agent.allowReason(),null);f.controller.agent.acknowledge(true);await f.controller.agent.allow();
 const apply=deferred();f.custom=async()=>apply.promise;
 f.emit(row('queued-apply',{change,review:review(base,after),applyConsumed:true},base));await flush();
 assert.equal(f.calls.filter(x=>x[0]==='apply').length,1);
 f.finish();await flush();assert.equal(f.saves.length,0,'events cannot return the original Apply caller');
 apply.resolve(native(7,null,owner('final',{},base,change)));await flush();
 assert.equal(f.saves.length,1);assert.deepEqual(f.workspace.projects['project-a'].baseline.metadata,after.metadata);
 assert.deepEqual(f.workspace.projects['project-a'].baseline.services,base.services);assert.equal(f.workspace.projects['project-a'].baseline.ios.enabled,false);
 f.finish();await flush();assert.equal(f.saves.length,1);assert.equal(f.calls.filter(x=>x[0]==='apply').length,1);
});
test('metadata actual controller preserves dirty or ABA forms and never adopts a changed original',async()=>{
 const base=listingBase(),change=listingChange(),after=changedConfiguration(base,change);assert.ok(after);
 for(const restore of [false,true]){
  const f=fixture(base,change);await f.reviewing();f.controller.agent.acknowledge(true);
  f.dispatch({type:'edit',projectId:'project-a',path:'metadata.root',value:'unsaved'});
  if(restore)f.dispatch({type:'edit',projectId:'project-a',path:'metadata.root',value:base.metadata.root});
  const prior=f.workspace.projects['project-a'];assert.equal(f.controller.agent.getSnapshot().acknowledged,false,'edit/restore must retire the old acknowledgement');
  if(!restore)f.controller.agent.acknowledge(true); // Even a fresh acknowledgement cannot authorize a dirty form.
  await f.controller.agent.allow();
  assert.equal(f.calls.some(x=>x[0]==='allow'),false);assert.equal(f.workspace.projects['project-a'],prior);
 }
 const f=fixture(base,change);await f.applying();
 f.emit(row('unknown',{change,review:review(base,after),applyConsumed:true},base));f.finish();await flush();
 assert.equal(f.saves.length,0);assert.equal(f.controller.agent.getSnapshot().unknown,true);assert.equal(f.calls.filter(x=>x[0]==='apply').length,1);
});
