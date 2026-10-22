// Inert actual-parent/reducer and held-Promise tests. No file publication,
// provider, process, native receipt, signing or installation is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { GITHUB_WORKFLOWS } from '../src/githubSetupProtocol.ts';
import { initialWorkspace, workspaceReducer, isDirty } from '../src/drafts.ts';
import { GitHubWorkflowEditController } from '../src/githubWorkflowEditController.ts';
import { currentWorkflowApplyBinding, githubWorkflowEditReducer } from '../src/githubWorkflowEdit.ts';
import { parseGitHubWorkflowEditStatus } from '../src/githubWorkflowEditProtocol.ts';
import { parseWorkflowEditAgentStatus, createWorkflowEditAgentApi, WORKFLOW_EDIT_CONSENT, WORKFLOW_EDIT_EVENT } from '../src/serviceWorkflowEditProtocol.ts';
const ID={window:'1'.repeat(32),session:'2'.repeat(32),revision:'3'.repeat(32),plan:'4'.repeat(32)};
const repository='example/toolkit',sha='a'.repeat(40);
// Display-only bounded DATA, not actual generated YAML/hash or native receipts.
function plan(actions=['create','create','create','create']) {
 const files=GITHUB_WORKFLOWS.map(({id,path},i)=>{
  const content=`inert caller ${i}\n`,generated={content,byteLength:Buffer.byteLength(content),sha256:String(i+1).repeat(64)};
  if(actions[i]==='update'){const before=`inert previous ${i}\n`,previous={content:before,byteLength:Buffer.byteLength(before),sha256:String(i+5).repeat(64)};
   return{id,path,action:'update',observed:{state:'present',byteLength:previous.byteLength,sha256:previous.sha256},generated,previous};}
  return{id,path,action:actions[i],observed:actions[i]==='create'?{state:'absent'}:{state:'present',byteLength:generated.byteLength,sha256:generated.sha256},generated};
 });
 return{schemaVersion:1,files,createDirectories:actions.every(a=>a==='create')?['.github','.github/workflows']:[],
  templateSet:{coreVersion:'0.3.0',resourceVersion:1,resourceSha256:'b'.repeat(64)},tooling:{repository,sha,schemaReference:`https://raw.githubusercontent.com/${repository}/${sha}/schemas/project.schema.json`,state:'format-only'}};
}
function owner(phase='opening',p=plan()) {
 const prepared=['reviewing','applying','finalizing','final','unknown'].includes(phase);
 return{domain:'github_workflows',projectId:'p',sessionId:ID.session,ownerGeneration:ID.window,phase,reviewRemainingMs:900000,
  checkout:phase==='opening'?null:{revision:ID.revision,observed:p.files.map(f=>({id:f.id,...f.observed}))},
  prepared:prepared?{revision:ID.revision,planToken:ID.plan,draftRevision:1,baselineGeneration:0,view:structuredClone(p)}:null,
  conflict:null,applySubmitted:['applying','finalizing','final','unknown'].includes(phase),
  coreOutcome:phase==='final'?{effect:'committed',journal:'clean',resources:'settled',reason:'none'}:null,
  nativeReason:'none',nativeFinality:phase==='final'?'settled':phase==='unknown'?'unknown':'pending',lateSettled:false};
}
function status(revision=0,p=null){return{schemaVersion:1,domain:'github_workflows',windowGeneration:ID.window,statusRevision:revision,capability:{available:true,reason:'available'},active:p&&p.phase!=='final'?p:null,lastTerminal:p&&p.phase==='final'?p:null};}
const ORIGIN={projectId:'5'.repeat(32),serviceInstance:'6'.repeat(32),requestId:'7'.repeat(32)};
const ORIGINAL={sessionId:ID.session,ownerGeneration:ID.window,revision:ID.revision};
function review(p=plan()){return{planToken:ID.plan,nativeStatusRevision:2,draftRevision:1,baselineGeneration:0,
 files:p.files.map(f=>({id:f.id,action:f.action,observed:f.observed.state==='absent'?null:{byteLength:f.observed.byteLength,sha256:f.observed.sha256},generated:{byteLength:f.generated.byteLength,sha256:f.generated.sha256}})),
 createdDirectories:p.createDirectories.length,coreVersion:p.templateSet.coreVersion,resourceVersion:p.templateSet.resourceVersion,resourceSha256:p.templateSet.resourceSha256,toolingRepository:repository,toolingSha:sha};}
function compact(phase='queued-open',revision=1,extra={}) {
 const withOriginal=!['queued-open','opening'].includes(phase),withReview=['reviewing','queued-apply','applying','final','unknown'].includes(phase);
 return{serviceInstance:ORIGIN.serviceInstance,request:{schemaVersion:1,origin:structuredClone(ORIGIN),runtimeProjectId:'p',revision,phase,
  settlement:phase==='final'?'settled':phase==='unknown'?'unknown':'pending',original:withOriginal?structuredClone(ORIGINAL):null,review:withReview?review():null,
  permissionAvailable:false,permissionConsumed:['queued-apply','applying','final'].includes(phase),remainingMs:['final','unknown'].includes(phase)?0:900000,cancelRequested:false,
  result:phase==='final'?{effect:'committed',journal:'clean',applySubmitted:true,cancelled:false}:null,doNotReplay:true,...extra}};
}
const tick=async()=>{for(let i=0;i<28;i++)await Promise.resolve();};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
async function harness({cold=false}={}) {
 let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p',name:'Inert',path:'/inert/p'}});
 workspace=workspaceReducer(workspace,{type:'new-draft',projectId:'p',draft:{schemaVersion:1}});
 const setup={mode:'native',serviceGeneration:1,selectionGeneration:1,coordinateGeneration:1,project:{projectId:'p',draftRevision:1,baselineGeneration:0,hasDraft:true},inputs:{toolingRepository:repository,toolingSha:sha}};
 let native=status(),latest={serviceInstance:ORIGIN.serviceInstance,request:null},event,serviceEvent,holdNativeRead=false,holdServiceRead=false;
 const rows=new Map(),calls=[],pending=[],completions=[];
 const call=(label,...args)=>{calls.push([label,...args]);const d=deferred();pending.push({label,...d});return d.promise;};
 const agent={
  status:async(q)=>{calls.push(['agent-status',q]);if(cold)throw Error('cold optional Host');if(holdServiceRead){const d=deferred();pending.push({label:'agent-status',...d});return d.promise;}return q?rows.get(q.requestId)??{serviceInstance:ORIGIN.serviceInstance,request:null}:latest;},
  subscribe:async(fn)=>{serviceEvent=fn;return()=>{};},
  allow:args=>call('allow',args), revoke:q=>call('revoke',q),
  open:(q,input)=>call('agent-open',q,input),prepare:(q,input)=>call('agent-prepare',q,input),apply:(q,s,t)=>call('agent-apply',q,s,t),
 };
 const api={mode:'native',agentWorkflowEdit:agent,
  subscribeGitHubWorkflowEdit:async(fn)=>{event=fn;return()=>{};},
  githubWorkflowEditStatus:async()=>{calls.push(['native-status']);if(holdNativeRead){const d=deferred();pending.push({label:'native-status',...d});return d.promise;}return native;},
  openGitHubWorkflowEdit:(...a)=>call('gui-open',...a),prepareGitHubWorkflowEdit:(...a)=>call('gui-prepare',...a),applyGitHubWorkflowEdit:(...a)=>call('gui-apply',...a),closeGitHubWorkflowEdit:(...a)=>call('discard',...a),openGitHubWorkflowRecovery:(...a)=>call('gui-recovery-open',...a),prepareGitHubWorkflowRecovery:(...a)=>call('gui-recovery-prepare',...a),applyGitHubWorkflowRecovery:(...a)=>call('gui-recovery-apply',...a)};
 const controller=new GitHubWorkflowEditController({selectedProject:()=>workspace.projects[workspace.selectedId]??null,setup:()=>setup,otherEditReason:()=>null});
 const handled=new Set();controller.subscribe(()=>{const a=controller.getSnapshot().attempt;if(a?.handled&&!handled.has(a.binding)){handled.add(a.binding);completions.push(a);}});
 await controller.connect(api);
 const svc=(s,emit=true)=>{assert.ok(parseWorkflowEditAgentStatus(s),'compact fixture obeys the real closed decoder');latest=s;if(s.request)rows.set(s.request.origin.requestId,s);if(emit)serviceEvent(s);};
 const emit=(n,p)=>{native=status(n,p);assert.ok(parseGitHubWorkflowEditStatus(native),'native fixture obeys original decoder');event(native);};
 const settle=(label,value,reject=false)=>{const i=pending.findIndex(p=>p.label===label);assert.notEqual(i,-1,`original ${label} caller exists`);const p=pending.splice(i,1)[0];p[reject?'reject':'resolve'](value);};
 return{controller,agent,api,setup,calls,pending,completions,svc,emit,settle,project:()=>workspace.projects.p,
  reply:(label,n,p)=>{native=status(n,p);settle(label,native);},count:label=>calls.filter(c=>c[0]===label).length,
  holdNativeRead:v=>{holdNativeRead=v;},holdServiceRead:v=>{holdServiceRead=v;},
  dispatch:a=>{controller.beforeWorkspaceAction(a);workspace=workspaceReducer(workspace,a);controller.syncContext();},
  restoreProject:p=>{workspace={...workspace,projects:{...workspace.projects,p}};controller.syncContext();},
  dispose:()=>controller.dispose()};
}
async function prepared(h) {
 h.svc(compact());await tick();assert.equal(h.count('agent-open'),1);
 h.svc(compact('opened',2));h.reply('agent-open',1,owner('editing'));await tick();assert.equal(h.count('agent-prepare'),1);
 h.svc(compact('reviewing',4));h.reply('agent-prepare',2,owner('reviewing'));await tick();
 assert.equal(h.controller.agent.getSnapshot().checked,false,'events/Prepare do not acknowledge a fresh Check');
}
async function allowed(h) {
 await prepared(h);await h.controller.agent.check();assert.equal(h.controller.agent.allowReason(),null);
 h.controller.agent.acknowledge(true);const work=h.controller.agent.allow();await tick();assert.equal(h.count('allow'),1);
 const granted=compact('reviewing',5,{permissionAvailable:true});h.svc(granted);h.settle('allow',granted);await work;
 assert.equal(h.count('agent-apply'),0,'permission alone does not submit Apply');
 h.svc(compact('queued-apply',6));await tick();assert.equal(h.count('agent-apply'),1);
}

test('Workflow compact codec and actual bridge keep exact RAW facet, bounds, required nulls and recovery exclusion',async()=>{
 for(const s of [compact(),compact('opened',2),compact('reviewing',4),compact('final',8)])assert.ok(parseWorkflowEditAgentStatus(s));
 for(const mutate of [s=>delete s.request.original,s=>s.request.path='/private',s=>s.request.review.files.reverse(),s=>s.request.review.toolingSha='main',s=>s.request.review.nativeStatusRevision=0xffffffff,s=>s.request.origin.requestId='0'.repeat(32),s=>s.request.phase='recover',s=>{s.request.permissionAvailable=true;s.request.permissionConsumed=true;},s=>s.serviceInstance='8'.repeat(32)]){
  const s=compact('reviewing',4);mutate(s);assert.equal(parseWorkflowEditAgentStatus(s),null);
 }
 const access=compact();Object.defineProperty(access.request,'origin',{get(){throw Error('must not invoke');},enumerable:true});assert.equal(parseWorkflowEditAgentStatus(access),null);
 const large=compact();large.request.runtimeProjectId='a'.repeat(17000);assert.equal(parseWorkflowEditAgentStatus(large),null);
 const calls=[];let event;const api=createNativeApi('native',async(command,input)=>{calls.push([command,input]);return command.startsWith('github_workflow_edit_')?status():compact();},async(name,fn)=>{event=[name,fn];return()=>{};});
 assert.ok(api.agentWorkflowEdit);await api.agentWorkflowEdit.subscribe(()=>{});assert.equal(event[0],WORKFLOW_EDIT_EVENT);
 await api.agentWorkflowEdit.status();assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0][1])),{origin:null});
 const input={projectId:'p',toolingRepository:repository,toolingSha:sha,draftRevision:1,baselineGeneration:0};
 await api.agentWorkflowEdit.open(ORIGIN,input);assert.equal(calls[1][0],'github_workflow_edit_open');assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[1][1])),{agentWorkflowEdit:true,origin:ORIGIN,input});
 await api.agentWorkflowEdit.prepare(ORIGIN,{sessionId:ID.session,revision:ID.revision,draft:{schemaVersion:1},toolingRepository:repository,toolingSha:sha,draftRevision:1,baselineGeneration:0});await api.agentWorkflowEdit.apply(ORIGIN,ID.session,ID.plan);
 const length=calls.length;await assert.rejects(api.agentWorkflowEdit.open(ORIGIN,{projectId:'p',intent:'recover'}));assert.equal(calls.length,length);
 await assert.rejects(api.agentWorkflowEdit.allow({origin:ORIGIN,original:ORIGINAL,planToken:ID.plan,expectedNativeStatusRevision:2,expectedRequestRevision:4,consentVersion:'other'}));assert.equal(calls.length,length);
 assert.equal(createWorkflowEditAgentApi('preview',()=>{throw Error('no preview call');}),null);
});

test('real parent holds Open and Prepare callers independently of events, then Check/ack grants one exact Apply',async()=>{
 const h=await harness();try{
 h.svc(compact());await tick();assert.equal(h.count('agent-open'),1);assert.equal(h.controller.start(),false);assert.equal(h.controller.inspectRecovery(),false);
 h.emit(1,owner('editing'));h.svc(compact('opened',2));await tick();assert.equal(h.count('agent-prepare'),0,'Opened event is not Open caller return');
 h.reply('agent-open',1,owner('editing'));await tick();assert.equal(h.count('agent-prepare'),1);
 h.emit(2,owner('reviewing'));h.svc(compact('reviewing',4));await h.controller.agent.check();
 assert.notEqual(h.controller.agent.allowReason(),null);h.controller.agent.acknowledge(true);await h.controller.agent.allow();assert.equal(h.count('allow'),0);
 h.reply('agent-prepare',2,owner('reviewing'));await tick();await h.controller.agent.check();assert.equal(h.controller.agent.allowReason(),null);
 const linkedState=h.controller.getSnapshot();assert.equal(githubWorkflowEditReducer(linkedState,{type:'agent-unentered',binding:linkedState.attempt.binding}),linkedState,'an opened native original cannot take the unentered retirement arm');
 const gui=currentWorkflowApplyBinding(h.controller.getSnapshot());assert.ok(gui);assert.equal(h.controller.apply(gui),false);
 h.controller.agent.acknowledge(true);const before=h.count('agent-status'),allow=h.controller.agent.allow();await tick();assert.equal(h.count('agent-status'),before,'Allow never refreshes the acknowledged revision');
 assert.deepEqual(structuredClone(h.calls.find(c=>c[0]==='allow')[1]),{origin:ORIGIN,original:ORIGINAL,planToken:ID.plan,expectedNativeStatusRevision:2,expectedRequestRevision:4,consentVersion:WORKFLOW_EDIT_CONSENT});
 h.svc(compact('queued-apply',6));await tick();assert.equal(h.count('agent-apply'),0,'queue event still waits actual Allow caller');
 h.settle('allow',compact('reviewing',5,{permissionAvailable:true}));await allow;await tick();assert.equal(h.count('agent-apply'),1);
 assert.deepEqual(structuredClone(h.calls.find(c=>c[0]==='agent-apply').slice(1)),[ORIGIN,ID.session,ID.plan]);assert.ok(isDirty(h.project()));assert.equal(h.project().baseline,null);
 }finally{h.dispose();}
});

test('native Final, compact persisted Final and actual Apply return are all required before original handled, without draft adoption',async()=>{
 const h=await harness();try{await allowed(h);h.emit(4,owner('final'));h.svc(compact('final',8));await tick();
 assert.equal(h.controller.getSnapshot().attempt.handled,false);assert.equal(h.completions.length,0);assert.equal(h.controller.retainsDraft('p'),true);
 h.reply('agent-apply',4,owner('final'));await tick();assert.equal(h.controller.getSnapshot().attempt.handled,true);assert.equal(h.completions.length,1);
 assert.equal(h.project().baseline,null);assert.ok(isDirty(h.project()));assert.equal(h.count('agent-apply'),1);
 }finally{h.dispose();}
 const h2=await harness();try{await allowed(h2);h2.reply('agent-apply',4,owner('final'));await tick();assert.equal(h2.completions.length,0,'native reply without persisted service history remains held');h2.svc(compact('final',8));await tick();assert.equal(h2.completions.length,1);}finally{h2.dispose();}
});

test('exact old Final is reconciled before discovering a coalesced next queue; Unknown cannot release it',async()=>{
 const h=await harness();try{await allowed(h);
 const next=compact('queued-open',1,{origin:{...ORIGIN,requestId:'8'.repeat(32)}});
 h.svc(compact('final',8),false);h.svc(next);h.reply('agent-apply',4,owner('final'));await tick();assert.equal(h.completions.length,0);
 h.holdServiceRead(true);const check=h.controller.agent.check();await tick();h.settle('agent-status',compact('final',8));await tick();
 assert.equal(h.completions.length,0,'the exact original is known but this Check still owns its actual latest-read caller');assert.equal(h.controller.retainsDraft('p'),true);
 h.holdServiceRead(false);h.settle('agent-status',next);await check;await tick();assert.equal(h.completions.length,1);
 const reads=h.calls.filter(c=>c[0]==='agent-status');assert.equal(reads.at(-2)[1].requestId,ORIGIN.requestId);assert.equal(reads.at(-1)[1],undefined);
 assert.equal(h.count('agent-open'),2,'new request opens once only after original completion');
 }finally{h.dispose();}
 const u=await harness();try{await prepared(u);u.svc(compact('unknown',8));u.svc(compact('queued-open',1,{origin:{...ORIGIN,requestId:'8'.repeat(32)}}));await u.controller.agent.check();assert.equal(u.count('agent-open'),1);assert.equal(u.controller.agent.getSnapshot().unknown,true);}finally{u.dispose();}
});

test('Check waits a preexisting native read return and then performs a genuinely later read',async()=>{
 const h=await harness();try{await prepared(h);h.holdNativeRead(true);const first=h.controller.checkStatus();await tick();const before=h.count('native-status');const check=h.controller.agent.check();await tick();assert.equal(h.count('native-status'),before);assert.notEqual(h.controller.agent.allowReason(),null);
 h.holdNativeRead(false);h.settle('native-status',status(2,owner('reviewing')));await first;await check;
 assert.equal(h.count('native-status'),before+1);assert.equal(h.controller.agent.allowReason(),null);
 }finally{h.dispose();}
 const initial=await harness();try{initial.holdNativeRead(true);initial.svc(compact(),false);const checked=initial.controller.agent.check();await tick();
 const originalEnd=initial.controller.agent.observedEnd.end;assert.equal(initial.count('agent-open'),0);initial.holdNativeRead(false);initial.settle('native-status',status());await checked;await tick();
 assert.equal(initial.count('agent-open'),1);assert.equal(initial.controller.agent.hold.end,originalEnd,'waiting for the original native read never restarts the observed READ endpoint');
 }finally{initial.dispose();}
});

test('reentrant draft or explicit revoke after Check cannot refresh or send the old acknowledgement',async()=>{
 for(const change of [h=>h.controller.agent.revoke(),h=>h.dispatch({type:'edit',projectId:'p',path:'name',value:'new'}),h=>{h.setup.coordinateGeneration++;h.controller.syncContext();}]){
 const h=await harness();try{await prepared(h);await h.controller.agent.check();h.controller.agent.acknowledge(true);let once=false;
 const unsub=h.controller.subscribe(()=>{if(!once&&h.controller.agent.getSnapshot().pending==='allow'){once=true;change(h);}});
 await h.controller.agent.allow();await tick();unsub();assert.equal(h.count('allow'),0);assert.equal(h.count('agent-apply'),0);assert.equal(h.controller.agent.getSnapshot().acknowledged,false);
 }finally{h.dispose();}}
});

test('late Allow return after Revoke and replaced API/project ABA cannot enter delegated Apply',async()=>{
 const h=await harness();try{await prepared(h);await h.controller.agent.check();h.controller.agent.acknowledge(true);const w=h.controller.agent.allow();await tick();void h.controller.agent.revoke();h.svc(compact('queued-apply',6));h.settle('allow',compact('reviewing',5,{permissionAvailable:true}));await w;await tick();assert.equal(h.count('agent-apply'),0);assert.equal(h.count('allow'),1);await h.controller.agent.allow();assert.equal(h.count('allow'),1);}finally{h.dispose();}
 for(const replace of [h=>{h.api.agentWorkflowEdit={...h.agent};h.controller.syncContext();},h=>{const p=h.project();h.restoreProject({...p});h.restoreProject(p);}]){
  const h=await harness();try{await prepared(h);await h.controller.agent.check();h.controller.agent.acknowledge(true);replace(h);await h.controller.agent.allow();await tick();assert.equal(h.count('allow'),0);assert.equal(h.controller.agent.getSnapshot().acknowledged,false);}finally{h.dispose();}
 }
});

test('reentrant pre-Open cancellation keeps the genuine unclaimed Refused until history Final, without inventing a native session',async()=>{
 const h=await harness();try{let once=false;const unsub=h.controller.subscribe(()=>{if(!once&&h.controller.getSnapshot().attempt){once=true;h.controller.requestClose();}});
 h.svc(compact());await tick();unsub();assert.equal(h.count('agent-open'),0);assert.equal(h.count('revoke'),1);
 const refused=compact('refused',3,{original:null,review:null,cancelRequested:true,remainingMs:0});h.settle('revoke',refused);await tick();assert.equal(h.controller.agent.busyReason()!==null,true);assert.equal(h.controller.getSnapshot().attempt.sessionId,null);
 h.svc(compact('final',4,{original:null,review:null,permissionConsumed:false,cancelRequested:true,result:{effect:'not_started',journal:'not_created',applySubmitted:false,cancelled:true}}));await tick();assert.equal(h.controller.getSnapshot().attempt,null);assert.equal(h.controller.agent.busyReason(),null);assert.equal(h.completions.length,0);
 }finally{h.dispose();}
 const old=await harness();try{
 assert.equal(old.controller.start(),true);old.reply('gui-open',1,owner('editing'));await tick();old.reply('gui-prepare',2,owner('reviewing'));await tick();
 assert.equal(old.controller.apply(currentWorkflowApplyBinding(old.controller.getSnapshot())),true);old.reply('gui-apply',3,owner('final'));await tick();
 const retained=old.controller.getSnapshot().attempt;assert.equal(retained.handled,true);let once=false;
 const unsub=old.controller.subscribe(()=>{if(!once&&old.controller.agent.getSnapshot().pending==='open'){once=true;void old.controller.agent.revoke();}});
 old.svc(compact());await tick();unsub();assert.equal(old.count('agent-open'),0);old.settle('revoke',compact('refused',3,{original:null,review:null,cancelRequested:true,remainingMs:0}));await tick();
 old.svc(compact('final',4,{original:null,review:null,permissionConsumed:false,cancelRequested:true,result:{effect:'not_started',journal:'not_created',applySubmitted:false,cancelled:true}}));await tick();
 assert.equal(old.controller.agent.getSnapshot().unknown,false);assert.equal(old.controller.agent.busyReason(),null);assert.equal(old.controller.getSnapshot().attempt,retained,'unrelated already-handled native history is not this unentered request');assert.equal(old.completions.length,1);
 }finally{old.dispose();}
});

test('lost Open, Prepare, Allow or Apply caller is absorbing even when native/service terminal DATA arrives',async()=>{
 for(const step of ['agent-open','agent-prepare','allow','agent-apply']){
  const h=await harness();try{
   if(step==='agent-open'){h.svc(compact());await tick();}
   else if(step==='agent-prepare'){h.svc(compact());await tick();h.svc(compact('opened',2));h.reply('agent-open',1,owner('editing'));await tick();}
   else if(step==='allow'){await prepared(h);await h.controller.agent.check();h.controller.agent.acknowledge(true);void h.controller.agent.allow();await tick();}
   else await allowed(h);
   h.settle(step,Error('lost original'),true);await tick();assert.equal(h.controller.agent.getSnapshot().unknown,true);
   if(step==='agent-apply'){h.emit(4,owner('final'));h.svc(compact('final',8));await tick();assert.equal(h.completions.length,0);}
   const count=h.count(step);await h.controller.agent.check();await h.controller.agent.allow();assert.equal(h.count(step),count);assert.equal(h.controller.start(),false);
  }finally{h.dispose();}
 }
});

test('stale/cross-source preview and native window mismatch never authorize a plan from compact DATA',async()=>{
 for(const mutate of [r=>r.original.revision='9'.repeat(32),r=>r.review.planToken='9'.repeat(32),r=>r.review.nativeStatusRevision=3,r=>{r.review.files[0].generated.sha256='9'.repeat(64);}]){
  const h=await harness();try{h.svc(compact());await tick();h.svc(compact('opened',2));h.reply('agent-open',1,owner('editing'));await tick();
   const bad=structuredClone(compact('reviewing',4));mutate(bad.request);h.svc(bad);h.reply('agent-prepare',2,owner('reviewing'));await tick();await h.controller.agent.check();h.controller.agent.acknowledge(true);await h.controller.agent.allow();assert.equal(h.count('allow'),0);
  }finally{h.dispose();}
 }
});

test('cold optional service and a foreign selected request never hijack ordinary Workflow or recovery',async()=>{
 const h=await harness({cold:true});try{assert.equal(h.controller.agent.getSnapshot().unknown,false);assert.equal(h.controller.agent.busyReason(),null);assert.equal(h.controller.startReason(),null);assert.equal(h.controller.start(),true);assert.equal(h.count('gui-open'),1);assert.equal(h.count('agent-open'),0);}finally{h.dispose();}
 const h2=await harness();try{h2.svc(compact('queued-open',1,{runtimeProjectId:'other'}));await tick();assert.equal(h2.count('agent-open'),0);assert.equal(h2.controller.inspectRecovery(),true);assert.equal(h2.count('gui-recovery-open'),1);assert.equal(h2.calls.find(c=>c[0]==='gui-recovery-open')[1],'p');}finally{h2.dispose();}
});

test('original metadata-only Open and one full Prepare keep the unsaved draft and exact mixed before/after review',async()=>{
 const h=await harness();try {
 const original=h.project(),mixed=plan(['create','update','preserve','update']);
 h.svc(compact());await tick();
 const open=h.calls.find(c=>c[0]==='agent-open');assert.equal(open[1].projectId,ORIGIN.projectId);assert.equal(open[2].projectId,'p');assert.notEqual(open[1].projectId,open[2].projectId);
 assert.deepEqual(Object.keys(open[2]).sort(),['baselineGeneration','draftRevision','projectId','toolingRepository','toolingSha'].sort());
 h.svc(compact('opened',2));h.reply('agent-open',1,owner('editing',mixed));await tick();
 const prepare=h.calls.find(c=>c[0]==='agent-prepare');assert.deepEqual(prepare[2].draft,original.draft);assert.equal(prepare[2].revision,ID.revision);assert.equal(prepare[2].toolingSha,sha);
 h.svc(compact('reviewing',4,{review:review(mixed)}));h.reply('agent-prepare',2,owner('reviewing',mixed));await tick();await h.controller.agent.check();assert.equal(h.controller.agent.allowReason(),null);
 assert.equal(h.project(),original);assert.ok(isDirty(original));assert.equal(h.count('gui-prepare'),0);
 }finally{h.dispose();}
});

test('new compact protocol refuses final line endings and invented recovery/file data without invoking transport',async()=>{
 for(const mutate of [s=>s.request.origin.requestId+='\n',s=>s.request.runtimeProjectId+='\n',s=>s.request.review.toolingSha+='\n',s=>s.request.review.toolingRepository+='\n',s=>s.request.review.coreVersion+='\n',s=>s.request.review.files[0].generated.sha256+='\n',s=>s.request.review.files[0].path='/private/file',s=>s.request.review.files[0].previous={content:'secret'}]){
  const s=compact('reviewing',4);mutate(s);assert.equal(parseWorkflowEditAgentStatus(s),null);
 }
 let sent=0;const api=createWorkflowEditAgentApi('native',async()=>{sent++;return compact();},async()=>()=>{});
 const open={projectId:'p',draftRevision:1,baselineGeneration:0,toolingRepository:repository,toolingSha:sha};
 for(const input of [{...open,draft:{}},{...open,projectId:'p\n'},{...open,toolingSha:sha+'\n'},{...open,intent:'recover'}])await assert.rejects(api.open(ORIGIN,input));
 assert.equal(sent,0);
});

test('same-revision countdown and stale Check never renew the original acknowledged comparison',async()=>{
 const h=await harness();try{await prepared(h);await h.controller.agent.check();h.controller.agent.acknowledge(true);assert.equal(h.controller.agent.getSnapshot().acknowledged,true);
 await h.controller.agent.check();assert.equal(h.controller.agent.getSnapshot().acknowledged,false);await h.controller.agent.allow();assert.equal(h.count('allow'),0);
 h.controller.agent.acknowledge(true);const allow=h.controller.agent.allow();await tick();const granted=compact('reviewing',5,{permissionAvailable:true,remainingMs:1000});h.svc(granted);h.settle('allow',granted);await allow;
 h.svc(compact('reviewing',5,{permissionAvailable:false,remainingMs:0}));h.svc(compact('reviewing',5,{permissionAvailable:true,remainingMs:800000}));
 const r=h.controller.agent.getSnapshot().status.request;assert.equal(r.remainingMs,0);assert.equal(r.permissionAvailable,false);assert.equal(h.count('agent-apply'),0);
 }finally{h.dispose();}
});

test('reentrant queued Apply intent preserves the original draft and stops before native send',async()=>{
 const h=await harness();try{await prepared(h);await h.controller.agent.check();h.controller.agent.acknowledge(true);const a=h.controller.agent.allow();await tick();const granted=compact('reviewing',5,{permissionAvailable:true});h.svc(granted);h.settle('allow',granted);await a;
 let once=false;const unsub=h.controller.subscribe(()=>{if(!once&&h.controller.getSnapshot().attempt?.applyClaimed){once=true;h.controller.requestClose();}});
 h.svc(compact('queued-apply',6));await tick();unsub();assert.equal(h.count('agent-apply'),0);assert.equal(h.count('revoke'),1);assert.ok(isDirty(h.project()));assert.equal(h.project().baseline,null);
 }finally{h.dispose();}
});
