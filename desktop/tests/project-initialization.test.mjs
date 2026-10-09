// Inert DTOs and original-promise scripts only. No native, disk mutation, DOM,
// toolkit generation, credential, network, process or filesystem-authority test.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { GITHUB_WORKFLOWS } from '../src/githubSetupProtocol.ts';
import { initialWorkspace, workspaceReducer, isDirty, retainedEditAttention } from '../src/drafts.ts';
import { initializationRequestFits, initializationView, initializationRecoveryView, parseProjectInitializationStatus, normalInitializationResult, normalInitializationRecovery, initializationProjectionProgress } from '../src/projectInitializationProtocol.ts';
import { currentInitializationApplyBinding, currentInitializationRecoveryBinding, confirmedInitializationResult, initializationRetainsDraft, initializationRecoveryContextRows } from '../src/projectInitialization.ts';
import { ProjectInitializationController } from '../src/projectInitializationController.ts';
const ID={window:'1'.repeat(32),session:'2'.repeat(32),revision:'3'.repeat(32),plan:'4'.repeat(32)};
const repository='example/toolkit',sha='a'.repeat(40);
const assurance={basis:'schema-policy',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'};
function plan(metadata=1){
 const workflows=GITHUB_WORKFLOWS.map((row,index)=>({...row,content:`inert caller ${index}\n`,byteLength:15,sha256:'a'.repeat(64)}));
 const paths=[['configuration','release/mobile-release.json',100],['gitignore','.gitignore',20],...workflows.map(row=>['workflow',row.path,row.byteLength]),...Array.from({length:metadata},(_,i)=>['metadata',`metadata/${String(i).padStart(3,'0')}.txt`,0])];
 const files=paths.map(([kind,path,afterBytes],index)=>({index,kind,path,action:'create',beforeBytes:null,afterBytes}));
 const parents=[...new Set(files.flatMap(row=>{const p=row.path.split('/');return p.slice(0,-1).map((_,i)=>p.slice(0,i+1).join('/'));}))].sort((a,b)=>a.split('/').length-b.split('/').length||(a<b?-1:a>b?1:0));
 return {schemaVersion:1,kind:'project-initialization',files,directoryCount:parents.length,createDirectories:parents,
 configurationPreview:{schemaVersion:1,validation:{valid:true,state:'format-valid',issues:[],requirements:[],assurance:structuredClone(assurance)},comparison:{baseProvided:false,kind:'proposed-create',state:'complete',semanticallyChanged:true,counts:{added:0,changed:0,removed:0},changes:[],unreviewedCount:0},fields:[],assurance:structuredClone(assurance)},
 workflows,ignoreAdditions:['.mobile-release/'],templateSet:{coreVersion:'0.3.0',resourceVersion:1,resourceSha256:'b'.repeat(64)},tooling:{repository,sha,schemaReference:`https://raw.githubusercontent.com/${repository}/${sha}/schemas/project.schema.json`,state:'format-only'}};
}
function owner(phase='opening',p=plan()){
 const prepared=['reviewing','applying','finalizing','final','unknown'].includes(phase);
 return {domain:'project_initialization',intent:'initialize',projectId:'p',sessionId:ID.session,ownerGeneration:ID.window,phase,reviewRemainingMs:900000,
 checkout:phase==='opening'?null:{intent:'initialize',revision:ID.revision,draftRevision:1,baselineGeneration:0,observed:{schemaVersion:1,fileCount:p.files.length,directoryCount:p.directoryCount}},
 prepared:prepared?{intent:'initialize',revision:ID.revision,planToken:ID.plan,draftRevision:1,baselineGeneration:0,view:p}:null,conflict:null,applySubmitted:['applying','finalizing','final','unknown'].includes(phase),
 coreOutcome:phase==='final'?{effect:'committed',journal:'clean',resources:'settled',reason:'none'}:null,nativeReason:'none',nativeFinality:phase==='final'?'settled':phase==='unknown'?'unknown':'pending',lateSettled:false};
}
function status(revision=0,p=null){return{schemaVersion:1,domain:'project_initialization',windowGeneration:ID.window,statusRevision:revision,capability:{available:true,reason:'available'},active:p&&p.phase!=='final'?p:null,lastTerminal:p&&p.phase==='final'?p:null};}
function recovery(action='rollback'){
 const p=plan();return{schemaVersion:1,kind:'project-initialization-recovery',state:'recoverable',reason:'none',action,transactionId:'5'.repeat(32),context:{configuration:{byteLength:100,sha256:'a'.repeat(64)},templateSet:p.templateSet,tooling:p.tooling},
 files:p.files.map(row=>({index:row.index,kind:row.kind,path:row.path,before:null,after:{byteLength:row.afterBytes,sha256:'a'.repeat(64),mode:0o644},effect:action==='rollback'?'remove_new':action==='committed_cleanup'?'keep_committed':'preserve'})),privateCleanup:{fileCount:10,directoryCount:3,scope:'inspected-owned-journal-only'}};
}
function recoveryOwner(phase='reviewing',action='rollback'){
 const p=owner(phase),view=recovery(action);p.intent='recover';p.checkout={intent:'recover',revision:ID.revision,recovery:view};p.prepared={intent:'recover',revision:ID.revision,planToken:ID.plan,recovery:structuredClone(view)};
 if(phase==='final')p.coreOutcome={effect:action==='committed_cleanup'?'committed':action==='preparing_cleanup'?'not_started':'rolled_back',journal:'clean',resources:'settled',reason:'none'};return p;
}
const tick=async()=>{for(let n=0;n<12;n++)await Promise.resolve();};
async function harness(){
 let workspace=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p',name:'Inert',path:'/inert/p'}});
 workspace=workspaceReducer(workspace,{type:'new-draft',projectId:'p',draft:{schemaVersion:1}});
 const setup={mode:'native',serviceGeneration:1,selectionGeneration:1,coordinateGeneration:1,project:{projectId:'p',draftRevision:1,baselineGeneration:0,hasDraft:true},inputs:{toolingRepository:repository,toolingSha:sha}};
 const calls=[],pending=[];let event;let current=status();let applied=0;
 const api={mode:'native',subscribeProjectInitialization:async(fn)=>{calls.push(['subscribe']);event=fn;return()=>calls.push(['unlisten']);},projectInitializationStatus:async()=>{calls.push(['status']);return current;}};
 for(const [name,label] of [['openProjectInitialization','open'],['prepareProjectInitialization','prepare'],['applyProjectInitialization','apply'],['discardProjectInitialization','discard']])api[name]=(...args)=>{calls.push([label,...args]);return new Promise((resolve,reject)=>pending.push({label,resolve,reject}));};
 const completions=[];const controller=new ProjectInitializationController({selectedProject:()=>workspace.projects[workspace.selectedId]??null,setup:()=>setup,otherEditReason:()=>null,onApplyIntent:projectId=>{applied++;workspace=workspaceReducer(workspace,{type:'initialization-intent',projectId});},onConfirmed:completion=>{completions.push(completion);workspace=workspaceReducer(workspace,{type:'initialization-final',projectId:'p',completion});}});
 await controller.connect(api);
 return{controller,setup,calls,pending,completions,project:()=>workspace.projects.p,workspace:()=>workspace,applied:()=>applied,dispatch:(a)=>{controller.beforeWorkspaceAction(a);workspace=workspaceReducer(workspace,a);controller.syncContext();},emit:(n,p)=>{current=status(n,p);event(current);},reply:(label,n,p)=>{current=status(n,p);const i=pending.findIndex(x=>x.label===label);assert.notEqual(i,-1);pending.splice(i,1)[0].resolve(current);},dispose:()=>controller.dispose()};
}
async function reviewed(h){assert.equal(h.controller.startReason(),null);assert.equal(h.controller.start(),true);assert.equal(h.controller.start(),false);h.reply('open',1,owner('editing'));await tick();const proposal=owner('reviewing');assert.ok(parseProjectInitializationStatus(status(2,proposal)),'fresh native review fixture satisfies the closed contract');h.reply('prepare',2,proposal);await tick();assert.ok(currentInitializationApplyBinding(h.controller.getSnapshot()));}

test('initialization closed requests and complete inventory preserve limits, intent and private data boundaries',()=>{
 const request={projectId:'p',intent:'initialize',draft:{schemaVersion:1},toolingRepository:repository,toolingSha:sha,draftRevision:1,baselineGeneration:0};
 assert.equal(initializationRequestFits('project_initialization_open',request),true);
 // Transport bounds do not qualify toolkit coordinates; core owns pin validation.
 assert.equal(initializationRequestFits('project_initialization_open',{...request,toolingSha:'main'}),true);
 const unqualified=plan();unqualified.tooling.sha='main';assert.equal(initializationView(unqualified),false);
 for(const change of [{root:'/tmp'}, {intent:'recover'}, {draftRevision:0xffff_ffff}])assert.equal(initializationRequestFits('project_initialization_open',{...request,...change}),false);
 assert.equal(initializationRequestFits('project_initialization_open',{projectId:'p',intent:'recover'}),true);
 assert.equal(initializationRequestFits('project_initialization_prepare',{sessionId:ID.session,revision:ID.revision,intent:'initialize',draft:{}}),false);
 assert.equal(initializationView(plan()),true);assert.equal(initializationView(plan(250)),true);assert.equal(initializationView(plan(251)),false);
 const retainedAssurance=structuredClone(assurance);
 for(const mutate of [p=>p.files[6].content='private',p=>p.files[6].sha256='a'.repeat(64),p=>p.files[6].action='append',p=>p.files[6].afterBytes=1,p=>p.files[6].path='../outside',p=>p.files[6].path='release/mobile-release.json',p=>p.files[0].action='replace',p=>p.files[0].beforeBytes=3,p=>p.workflows[0].byteLength++,p=>p.createDirectories.reverse(),p=>p.directoryCount++,p=>p.configurationPreview.assurance.credentialsRead=true]){const p=plan();mutate(p);assert.equal(initializationView(p),false);}
 assert.deepEqual(assurance,retainedAssurance,'negative DTO mutations stay inside that plan, not subsequent tests');
 assert.notEqual(plan().configurationPreview.assurance,assurance);
 const ignore=plan();ignore.files[1].afterBytes=1024*1024;assert.equal(initializationView(ignore),true);ignore.files[1].afterBytes++;assert.equal(initializationView(ignore),false);
 const getter=plan();Object.defineProperty(getter,'files',{get(){throw Error('must not invoke');},enumerable:true});assert.equal(initializationView(getter),false);
 for(const mutate of [p=>p.domain='github_workflows',p=>p.intent='recover',p=>p.prepared.baselineGeneration++,p=>p.applySubmitted=true,p=>p.nativeFinality='settled']){const p=owner('reviewing');mutate(p);assert.equal(parseProjectInitializationStatus(status(2,p)),null);}
});

test('initialization original controller freezes Open, sends one Apply, and never fabricates a saved baseline',async()=>{
 const h=await harness();try{
 assert.deepEqual(h.calls.slice(0,2).map(x=>x[0]),['subscribe','status']);await reviewed(h);
 const open=h.calls.find(x=>x[0]==='open')[1];assert.deepEqual(Object.keys(open).sort(),['projectId','intent','draft','toolingRepository','toolingSha','draftRevision','baselineGeneration'].sort());
 assert.deepEqual(h.calls.find(x=>x[0]==='prepare').slice(1),[ID.session,ID.revision,'initialize']);
 const binding=currentInitializationApplyBinding(h.controller.getSnapshot());assert.equal(h.controller.apply(binding),true);assert.equal(h.controller.apply(binding),false);assert.equal(h.applied(),1);
 h.emit(3,owner('finalizing'));assert.equal(confirmedInitializationResult(h.controller.getSnapshot()),null);assert.equal(isDirty(h.project()),true);
 h.reply('apply',4,owner('final'));await tick();assert.equal(confirmedInitializationResult(h.controller.getSnapshot()),'initialized');assert.equal(h.completions.length,1);assert.equal(isDirty(h.project()),true);assert.equal(h.project().baseline,null);assert.equal(h.project().baselineGeneration,0);assert.equal(h.project().lastSave,null);assert.equal(h.project().snapshotPredatesSave,true);
 const completed=h.project();h.dispatch({type:'initialization-final',projectId:'p',completion:h.completions[0]});assert.equal(h.project(),completed);
 }finally{h.dispose();}
});

test('initialization draft, toolkit, selection and cancellation retire consent without lost-result retry',async()=>{
 for(const change of [h=>h.dispatch({type:'edit',projectId:'p',path:'name',value:'new'}),h=>{h.setup.inputs.toolingSha='b'.repeat(40);h.setup.coordinateGeneration++;h.controller.syncContext();},h=>h.controller.selectionIntent(),h=>h.controller.snapshotIntent(),h=>h.controller.setVisible(false)]){
  const h=await harness();try{await reviewed(h);const token=currentInitializationApplyBinding(h.controller.getSnapshot());change(h);assert.equal(h.controller.apply(token),false);assert.equal(h.calls.filter(x=>x[0]==='discard').length,1);assert.equal(h.calls.filter(x=>x[0]==='apply').length,0);assert.ok(h.project().draft);}finally{h.dispose();}
 }
 const h=await harness();try{await reviewed(h);const token=currentInitializationApplyBinding(h.controller.getSnapshot());assert.equal(h.controller.apply(token),true);h.dispatch({type:'edit',projectId:'p',path:'name',value:'new'});h.reply('apply',4,owner('final'));await tick();assert.equal(h.project().draft.name,'new');assert.equal(isDirty(h.project()),true);assert.equal(h.project().baseline,null);assert.equal(h.calls.filter(x=>x[0]==='apply').length,1);}finally{h.dispose();}
 const lost=await harness();try{await reviewed(lost);assert.equal(lost.controller.apply(currentInitializationApplyBinding(lost.controller.getSnapshot())),true);lost.pending.find(x=>x.label==='apply').reject({code:'transport'});await tick();assert.equal(lost.calls.filter(x=>x[0]==='apply').length,1);assert.equal(lost.controller.start(),false);assert.equal(initializationRetainsDraft(lost.controller.getSnapshot(),'p'),true);}finally{lost.dispose();}
});

test('initialization recovery is a new intent with closed inspected effects and no draft import or marker success',async()=>{
 for(const action of ['rollback','preparing_cleanup','committed_cleanup','rolled_back_cleanup']){assert.equal(initializationRecoveryView(recovery(action)),true);const p=recoveryOwner('final',action);assert.ok(parseProjectInitializationStatus(status(5,p)));assert.equal(normalInitializationRecovery(p),true);assert.equal(normalInitializationResult(p),null);}
 const context=recovery();assert.deepEqual(initializationRecoveryContextRows(context),[
  {label:'Stored configuration bytes',value:'100'}, {label:'Stored configuration SHA-256',value:'a'.repeat(64)},
  {label:'Template core version',value:'0.3.0'}, {label:'Template resource version',value:'1'}, {label:'Template resource SHA-256',value:'b'.repeat(64)},
  {label:'Toolkit repository',value:repository}, {label:'Toolkit full commit',value:sha},
  {label:'Pinned configuration schema',value:`https://raw.githubusercontent.com/${repository}/${sha}/schemas/project.schema.json`}, {label:'Toolkit verification',value:'format-only'}]);
 assert.deepEqual(initializationRecoveryContextRows({...context,state:'conflict',context:null}),[]);
 const observed=recovery();observed.files[2].before={byteLength:1024*1024,sha256:'c'.repeat(64),mode:0o644};observed.files[2].after=null;observed.files[2].effect='preserve';
 assert.equal(initializationRecoveryView(observed),true);observed.files[2].before.byteLength++;assert.equal(initializationRecoveryView(observed),false);
 const ignored=recovery();ignored.files[1].after.byteLength=1024*1024;assert.equal(initializationRecoveryView(ignored),true);ignored.files[1].after.byteLength++;assert.equal(initializationRecoveryView(ignored),false);
 const full=recovery();full.privateCleanup.directoryCount=257;assert.equal(initializationRecoveryView(full),true);full.privateCleanup.directoryCount=258;assert.equal(initializationRecoveryView(full),false);
 const suffix=recovery('committed_cleanup');suffix.files=[];suffix.privateCleanup={fileCount:2,directoryCount:1,scope:'inspected-owned-journal-only'};assert.equal(initializationRecoveryView(suffix),true);suffix.privateCleanup.fileCount=1;assert.equal(initializationRecoveryView(suffix),false);
 const wrong=recovery();wrong.files[0].before={byteLength:3,sha256:'a'.repeat(64),mode:0o644};wrong.files[0].effect='restore_original';assert.equal(initializationRecoveryView(wrong),false);
 const h=await harness();try{
 const draft=structuredClone(h.project().draft);h.setup.inputs.toolingSha='';assert.equal(h.controller.inspectRecovery(),true);assert.deepEqual(h.calls.find(x=>x[0]==='open')[1],{projectId:'p',intent:'recover'});
 const opened=recoveryOwner('editing');opened.prepared=null;opened.applySubmitted=false;h.reply('open',1,opened);await tick();h.reply('prepare',2,recoveryOwner());await tick();const binding=currentInitializationRecoveryBinding(h.controller.getSnapshot());assert.ok(binding);assert.equal(h.controller.recover(binding),true);assert.equal(h.controller.recover(binding),false);h.reply('apply',3,recoveryOwner('final'));await tick();assert.deepEqual(h.project().draft,draft);assert.equal(h.project().baseline,null);assert.equal(h.completions.length,0);
 }finally{h.dispose();}
 const failed=owner('unknown');failed.coreOutcome={effect:'committed',journal:'recovery_required',resources:'unknown',reason:'custody_unknown'};const late={...failed,lateSettled:true};assert.equal(initializationProjectionProgress(failed,late),true);assert.equal(initializationProjectionProgress(failed,owner('final')),false);assert.equal(normalInitializationResult(late),null);
});

test('initialization bridge retains exact command/event domain and refuses previews and cross-domain data',async()=>{
 const calls=[];let callback;const api=createNativeApi('native',async(command,args)=>{calls.push([command,args]);return status();},async(event,fn)=>{calls.push([event]);callback=fn;return()=>{};});
 let seen;await api.subscribeProjectInitialization(value=>seen=value);callback(status());assert.deepEqual(seen,status());assert.equal(calls[0][0],'project-initialization-state-changed');
 await api.openProjectInitialization({projectId:'p',intent:'recover'});assert.equal(calls[1][0],'project_initialization_open');
 await assert.rejects(api.prepareProjectInitialization(ID.session,ID.revision,'other'),e=>e.code==='ProjectInitializationRequestInvalid');assert.equal(calls.length,2);
 const bad=createNativeApi('native',async()=>({...status(),domain:'github_workflows'}));await assert.rejects(bad.projectInitializationStatus(),e=>e.code==='ProjectInitializationStatusInvalid');
 const rows=retainedEditAttention({},[],[],[],[],[{projectId:'p'}]);assert.deepEqual(rows,[{projectId:'p',projectName:null,domain:'Project initialization',page:'dashboard'}]);
});

test('initialization conflict, native unknown and status replay never regain consent or clear retained attention',async()=>{
 const h=await harness();try{
  assert.equal(h.controller.start(),true);h.reply('open',1,owner('editing'));await tick();
  const refused=owner('final');refused.prepared=null;refused.applySubmitted=false;refused.conflict={schemaVersion:1,reason:'existing_targets_differ',files:[{kind:'configuration',path:'release/mobile-release.json',beforeBytes:20}]};refused.coreOutcome={effect:'not_started',journal:'not_created',resources:'settled',reason:'none'};
  for(const size of [16385,1024*1024]){const large=structuredClone(refused);large.conflict.files=[{kind:'workflow',path:GITHUB_WORKFLOWS[0].path,beforeBytes:size}];assert.ok(parseProjectInitializationStatus(status(2,large)));}
  const oversized=structuredClone(refused);oversized.conflict.files=[{kind:'workflow',path:GITHUB_WORKFLOWS[0].path,beforeBytes:1024*1024+1}];assert.equal(parseProjectInitializationStatus(status(2,oversized)),null);
  refused.conflict.files=[{kind:'workflow',path:GITHUB_WORKFLOWS[0].path,beforeBytes:1024*1024}];
  h.reply('prepare',2,refused);await tick();assert.equal(h.controller.getSnapshot().observationIssue,null);assert.equal(h.calls.some(row=>row[0]==='apply'),false);assert.equal(confirmedInitializationResult(h.controller.getSnapshot()),null);assert.equal(h.project().baseline,null);
 }finally{h.dispose();}
 const u=await harness();try{
  await reviewed(u);const confirmation=currentInitializationApplyBinding(u.controller.getSnapshot());assert.equal(u.controller.apply(confirmation),true);
  const uncertain=owner('unknown');uncertain.coreOutcome={effect:'unknown',journal:'unknown',resources:'unknown',reason:'custody_unknown'};uncertain.nativeReason='cleanup_unknown';u.emit(3,uncertain);
  u.emit(4,{...uncertain,lateSettled:true});assert.equal(u.controller.start(),false);assert.equal(u.controller.apply(confirmation),false);assert.equal(u.controller.getSnapshot().nativeBlocked,true);
  u.emit(2,owner('reviewing'));assert.equal(u.controller.getSnapshot().nativeBlocked,true);assert.equal(confirmedInitializationResult(u.controller.getSnapshot()),null);assert.equal(u.completions.length,0);
 }finally{u.dispose();}
});
