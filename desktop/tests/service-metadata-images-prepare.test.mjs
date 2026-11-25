// Genuine existing controller/Choose→Open→Prepare and Apply facade; inert ports only.
// No picker, image decoding, subprocess, file copy, Store or native receipt.
import assert from 'node:assert/strict';
import test from 'node:test';
import catalog from '../../src/mobile_release/api/data/metadata-images-v1.json' with { type:'json' };
import help from '../../src/mobile_release/api/data/metadata-image-help-v1.json' with { type:'json' };
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { MetadataImagesController, currentMetadataImagesApplyBinding, metadataImagesOwnerReason } from '../src/metadataImagesController.ts';
import { parseImagesAgentAccess, parseImagesAgentRevoked, createMetadataImagesAgentApi, METADATA_IMAGES_AGENT_CONSENT } from '../src/serviceMetadataImagesProtocol.ts';

import { parseImagesPreparationStatus, createImagesPrepareApi } from '../src/serviceMetadataImagesPrepareProtocol.ts';
const cleanups=[];test.afterEach(async()=>{for(const h of cleanups.splice(0))h.controller.dispose();await flush();});

const id = n => n.repeat(32), clone = v => structuredClone(v);
const I = {window:id('a'),session:id('b'),revision:id('c'),plan:id('d'),selection:id('e'),operation:id('f'),item:id('1'),
  service:id('2'),project:id('3'),grant:id('4'),request:id('5'),nonce:id('6')};
const config = {schemaVersion:1,metadata:{root:'release/store',androidLocales:['en-US','fr-FR']},android:{enabled:true},ios:{enabled:false}};
const digest = {byteLength:4,sha256:'9'.repeat(64)}, summary = {...digest,format:'png',width:1080,height:1920,headerChecked:true};
const baseline = {config:digest,ignore:digest,inventorySha256:'8'.repeat(64)};
const before={...summary,sha256:'4'.repeat(64)};
const view = (replace=false) => {const folder='release/store/android/en-US/images/phoneScreenshots';return {kind:'import',policy:'metadata-images-v1',platform:'android',locale:'en-US',assetType:'phoneScreenshots',metadataRoot:'release/store',folder,
 files:[{itemId:I.item,displayName:'01.png',path:folder+'/01.png',action:replace?'replace':'preserve',before:clone(before),selected:clone(summary),after:clone(replace?summary:before),canReplace:true,issues:[]},
 {itemId:id('7'),displayName:'02.png',path:folder+'/02.png',action:'create',before:null,selected:clone(summary),after:clone(summary),canReplace:false,issues:[]}],
 existing:[{path:folder+'/01.png',summary:clone(before)}],finalOrder:[folder+'/01.png',folder+'/02.png'],valid:true,issues:[],
 assurance:{localCopyOnly:true,sourceFilesUnchanged:true,storeContacted:false,fullDecode:false,contentApproved:false,storeAccepted:false}};};
const publicCatalog = () => ({schemaVersion:1,policy:'metadata-images-v1',platforms:[{id:'android',label:'Android'},{id:'ios',label:'iOS'}],types:clone(catalog.types),
  limits:{maxFiles:10,maxFileBytes:10485760,maxBatchBytes:25165824,maxTransactionBytes:67108864,maxDimension:16384,maxPixels:67108864,formats:['png','jpeg']},help:clone(help.fields)});
const deferred = () => {let resolve,reject; const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};};
const flush = async () => {for(let i=0;i<40;i++)await Promise.resolve();};
const origin = () => ({serviceInstance:I.service,projectId:I.project,requestId:I.request});
const empty = () => ({schemaVersion:1,serviceInstance:I.service,projectId:null,grantId:null,nonce:null,review:null,live:false,remainingMs:0,request:null});
function project() {
  let w=workspaceReducer(initialWorkspace,{type:'select',project:{id:'p',name:'Inert project',path:'/never-read'}});
  w=workspaceReducer(w,{type:'snapshot-start',projectId:'p',requestId:1});
  const snapshot={root:'/never-read',observedAt:'',observationScope:'single-request-non-atomic',
    config:{content:null,path:'release/mobile-release.json',state:'format-valid',data:clone(config),issues:[]},
    discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},
    assurance:{basis:'static-text',projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'},issues:[]};
  w=workspaceReducer(w,{type:'snapshot-done',projectId:'p',requestId:1,snapshot,observedAt:0});return w;
}
function frame(domain,revision,active=null,lastTerminal=null) {return{schemaVersion:1,domain,windowGeneration:I.window,statusRevision:revision,
  capability:{available:true,reason:'available'},active,lastTerminal};}
function selected(token=I.selection){return{operationId:I.operation,projectId:'p',platform:'android',locale:'en-US',assetType:'phoneScreenshots',phase:'selected',reason:'none',
  settlement:'known',selectionToken:token,items:[{itemId:I.item,displayName:'01.png',...digest},{itemId:id('7'),displayName:'02.png',...digest}]};}
function owner(phase='editing',request=null,extra={}) {return{domain:'metadata_images',projectId:'p',sessionId:I.session,ownerGeneration:I.window,phase,reviewRemainingMs:900000,
  applySubmitted:['applying','finalizing','final'].includes(phase),nativeReason:'none',nativeFinality:phase==='final'?'settled':'pending',lateSettled:false,
  coreOutcome:phase==='final'?{effect:'committed',journal:'clean',resources:'settled',reason:'none'}:null,
  details:{intent:'import',checkout:{revision:I.revision,baseline:clone(baseline),view:view()},prepared:request?{revision:I.revision,planToken:I.plan,
    draftRevision:request.draftRevision,baselineGeneration:request.baselineGeneration,view:view(request.choices[0].replaceExisting)}:null},...extra};}
function review(statusRevision=2) {return{original:{sessionId:I.session,ownerGeneration:I.window,revision:I.revision,planToken:I.plan,draftRevision:1,baselineGeneration:1},
  nativeStatusRevision:statusRevision,platform:'android',locale:'en-US',assetType:'phoneScreenshots',fileCount:2,createCount:1,replaceCount:1,preserveCount:0,
  selectedBytes:8,preparedSha256:'7'.repeat(64)};}
function access(nonce=I.nonce){return{schemaVersion:1,serviceInstance:I.service,projectId:I.project,grantId:I.grant,nonce,review:review(),live:true,remainingMs:60000,request:null};}
function request(a,phase='queued',revision=1) {return{schemaVersion:1,origin:origin(),grantId:a.grantId,revision,phase,
  settlement:phase==='final'?'settled':phase==='unknown'?'unknown':'pending',review:clone(a.review),cancelRequested:false,
  result:phase==='final'?{effect:'committed',journal:'clean',cancelled:false,applySubmitted:true,completed:true}:null,doNotReplay:true};}
async function harness(gates={}) {
  let workspace=project(), selectionFrame=frame('metadata_images_selection',0), editFrame=frame('metadata_images',0), prepared=null,
    a=empty(), ps=null, prepListener, latest=null, selectionListener, editListener, agentListener, clock=100, other=null;
  const calls=[], off=[];
  const record=(kind,args)=>calls.push({kind,args:clone(args)});
  const setOwner=(p,revision=editFrame.statusRevision+1,emit=true)=>{editFrame=frame('metadata_images',revision,p.phase==='final'?null:p,p.phase==='final'?p:null);
    if(emit)editListener(clone(editFrame));return clone(editFrame);};
  const agent={
    subscribe:async(fn)=>{agentListener=fn;return()=>off.push('agent');},
    allow:async(args)=>{record('allow',args);a={...access(args.nonce),review:{...review(),original:clone(args.original),nativeStatusRevision:args.statusRevision}};
      const response=clone(a);if(gates.allow)await gates.allow.promise;return response;},
    revoke:async(nonce)=>{record('revoke',{nonce});if(gates.revoke)await gates.revoke.promise;
      if(a.nonce===nonce)a={...a,live:false,remainingMs:0};return{nonce,access:clone(a)};},
    status:async(q)=>{record('agent-status',q??null);if(gates.status)return gates.status.promise;
      if(q&&a.request?.origin.requestId!==q.requestId)throw new Error('old missing');return clone(a);},
    apply:async(q)=>{record('agent-apply',q);setOwner(owner('applying',prepared));if(gates.apply)return gates.apply.promise;return clone(editFrame);},
  };
  const preparation={
    subscribe:async(fn)=>{prepListener=fn;return()=>off.push('preparation');},
    status:async(q)=>{record('prep-status',q??null);if(gates.prepStatus)return gates.prepStatus(q,ps,latest);return clone(q?ps:latest??ps);},
    inspect:async(q,o)=>{record('inspect',{q,o});ps={...readStatus('editing'),origin:clone(q),revision:3,observation:observed(o)};
      if(gates.inspect){prepListener(clone(ps));await gates.inspect.promise;}return clone(ps);},
    prepare:async(q)=>{record('delegated-prepare',q);prepared=clone(controller.getSnapshot().attempt.prepareRequest);
      ps={...ps,phase:'reviewing',revision:8,review:{...review(2),original:{...review().original,draftRevision:1}}};
      const response=setOwner(owner('reviewing',prepared),2);prepListener(clone(ps));
      if(gates.delegatedPrepare)await gates.delegatedPrepare.promise;return response;},
    cancel:async(q)=>{record('prep-cancel',q);if(gates.prepCancel)return gates.prepCancel.promise;
      if(ps.phase==='transferred'||ps.phase==='final')return clone(ps);
      const claimed=controller.getSnapshot().attempt?.prepareClaimed;
      ps={...ps,revision:ps.revision+1,phase:claimed?'stopping':'final',settlement:claimed?'pending':'settled',remainingMs:0,cancelRequested:true,
        result:claimed?null:{prepared:false,transferred:false,gui:false}};return clone(ps);},
  };
  const api={mode:'native',agent,preparation,metadataImagesCatalog:async()=>publicCatalog(),
    subscribeMetadataImagesSelection:async(fn)=>{selectionListener=fn;return()=>off.push('selection');},
    subscribeMetadataImagesEdit:async(fn)=>{editListener=fn;return()=>off.push('edit');},
    metadataImagesSelectionStatus:async()=>clone(selectionFrame),metadataImagesEditStatus:async()=>clone(editFrame),
    chooseMetadataImages:async(args)=>{record('choose',args);selectionFrame=frame('metadata_images_selection',1,null,selected());return clone(selectionFrame);},
    openMetadataImagesEdit:async(args)=>{record('open',args);selectionFrame=frame('metadata_images_selection',2,null,selected(null));selectionListener(clone(selectionFrame));
      editFrame=frame('metadata_images',1,owner());return clone(editFrame);},
    prepareMetadataImagesEdit:async(args)=>{record('prepare',args);prepared=clone(args);const result=setOwner(owner('reviewing',prepared),2);
      if(gates.prepare)await gates.prepare.promise;return result;},
    applyMetadataImagesEdit:async(sessionId,planToken)=>{record('gui-apply',{sessionId,planToken});return setOwner(owner('applying',prepared));},
    closeMetadataImagesEdit:async(sessionId)=>{record('close',{sessionId});if(gates.close)return gates.close.promise;
      return setOwner(owner('final',prepared,{applySubmitted:false,nativeReason:'cancelled',reviewRemainingMs:0,
        coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}}));},
    cancelMetadataImagesSelection:async(id)=>{record('cancel',{id});return clone(selectionFrame);},openMetadataImagesRecovery:async()=>{throw new Error('not used');},
  };
  const controller=new MetadataImagesController({selectedProject:()=>workspace.projects[workspace.selectedId]??null,otherOperationReason:()=>other,now:()=>clock});
  await controller.connect(api);controller.setVisible(true);controller.selectAssetType('phoneScreenshots');
  if(gates.profile!==false)assert.equal(controller.setCliPreparation(true),true);
  assert.equal(controller.choose(),true);await flush();
  const h={controller,api,calls,off,agent:controller.agent,get state(){return controller.getSnapshot();},get access(){return clone(a);},
    prep:controller.preparation,get prepStatus(){return clone(ps);},
    read:async()=>{ps=readStatus();prepListener(clone(ps));await flush();},
    prepareViaCli:async()=>{ps={...ps,revision:4,phase:'queued-prepare',choices:[{itemId:I.item,replaceExisting:true},{itemId:id('7'),replaceExisting:false}]};prepListener(clone(ps));await flush();},
    prepEmit:next=>{ps=clone(next);prepListener(clone(ps));},latest:next=>{latest=clone(next);prepListener(clone(next));},
    count:(kind)=>calls.filter(c=>c.kind===kind).length,last:(kind)=>calls.filter(c=>c.kind===kind).at(-1),
    advance:n=>clock+=n,block:v=>{other=v;},
    emit:a2=>{a=clone(a2);agentListener(clone(a));},native:(phase,extra={})=>setOwner(owner(phase,prepared,extra)),
    dispatch:action=>{controller.beforeWorkspaceAction(action);workspace=workspaceReducer(workspace,action);controller.syncProject();},
    sameWorkspace:()=>{const a={type:'snapshot-done',projectId:'p',requestId:999,snapshot:{},observedAt:0};controller.beforeWorkspaceAction(a);controller.syncProject();},
  };
  cleanups.push(h);return h;
}


function observed(original={sessionId:I.session,ownerGeneration:I.window,revision:I.revision,nativeStatusRevision:1,baselineGeneration:1}) {
 return {original,platform:'android',locale:'en-US',assetType:'phoneScreenshots',openedSha256:'8'.repeat(64),items:[
 {itemId:I.item,displayName:'01.png',selectedBytes:4,selectedSha256:digest.sha256,beforeSha256:before.sha256,canReplace:true,replaceExisting:false},
 {itemId:id('7'),displayName:'02.png',selectedBytes:4,selectedSha256:digest.sha256,beforeSha256:null,canReplace:false,replaceExisting:false}]};
}
function readStatus(phase='queued-read'){return {schemaVersion:1,origin:origin(),runtimeProjectId:'p',revision:1,phase,settlement:'pending',observation:null,choices:null,review:null,remainingMs:60000,cancelRequested:false,result:null,doNotReplay:true};}

test('read and choices use only captured IDs and a canonical compact original; closed protocol and RAW routes',async()=>{
 const s={...readStatus('editing'),observation:observed()};assert.ok(parseImagesPreparationStatus(s));
 for(const change of [x=>delete x.observation.items[0].beforeSha256,x=>x.paths=['/secret'],x=>x.observation.items[0].displayName='../a.png',
  x=>x.observation.items[1].itemId=I.item,x=>x.observation.items[1].canReplace=true,x=>x.observation.openedSha256='a'.repeat(64)+'\n',
  x=>x.choices=[{itemId:I.item,replaceExisting:false}],x=>x.review=review(),x=>x.remainingMs=900001,x=>x.runtimeProjectId='other/path']){
  const v=clone(s);change(v);assert.equal(parseImagesPreparationStatus(v),null);
 }
 let called=0;const getter=clone(s);Object.defineProperty(getter,'phase',{enumerable:true,get(){called++;return 'editing';}});
 assert.equal(parseImagesPreparationStatus(getter),null);assert.equal(called,0);
 const calls=[];const api=createImagesPrepareApi('native',async(c,b)=>{calls.push([c,JSON.parse(new TextDecoder().decode(b))]);return s;},async()=>()=>{});
 await api.status(origin());await api.inspect(origin(),s.observation.original);await api.cancel(origin());
 assert.deepEqual(calls.map(x=>x[0]),['agent_metadata_images_prepare_status','agent_metadata_images_inspect','agent_metadata_images_prepare_cancel']);
 assert.deepEqual(calls[1][1],{origin:origin(),original:s.observation.original});assert.equal(createImagesPrepareApi('preview',()=>{}),undefined);
});

test('profile is captured before real Choose/Open; old Editing cannot be retrofitted or stopped by read refusal',async()=>{
 const ordinary=await harness({profile:false});assert.equal('cliPreparation' in ordinary.last('open').args,false);
 assert.equal(ordinary.controller.setCliPreparation(true),false);await ordinary.read();
 assert.equal(ordinary.count('inspect'),0);assert.equal(ordinary.count('prep-cancel'),1);assert.equal(ordinary.count('close'),0);
 assert.equal(ordinary.state.attempt.prepareClaimed,false);assert.equal(ordinary.controller.prepare(),true);await flush();assert.equal(ordinary.count('prepare'),1);
 const h=await harness();assert.equal(h.last('open').args.cliPreparation,true);assert.equal(h.controller.setCliPreparation(false),false);
});

test('actual existing Open followed by READ IDs and one atomic CLI choice Prepare still needs separate Apply',async()=>{
 const h=await harness();await h.read();assert.equal(h.count('inspect'),1);assert.equal(h.prepStatus.phase,'editing',JSON.stringify({request:h.prep.getSnapshot(),calls:h.calls,state:h.state.error,remaining:h.controller.remainingReviewMs()}));
 assert.equal(h.count('prepare'),0);assert.equal(h.count('delegated-prepare'),0);assert.equal(h.state.attempt.draftRevision,0);
 await h.prepareViaCli();assert.equal(h.count('delegated-prepare'),1);assert.equal(h.count('prepare'),0);
 assert.deepEqual(h.state.attempt.prepareRequest.choices,[{itemId:I.item,replaceExisting:true},{itemId:id('7'),replaceExisting:false}]);
 assert.equal(h.state.attempt.draftRevision,1);assert.equal(h.state.attempt.projection.details.prepared.view.files[0].action,'replace');
 assert.equal(h.count('allow'),0);assert.equal(h.count('agent-apply'),0);assert.equal(h.agent.canAllow(),true);
 await h.agent.allow();assert.equal(h.count('allow'),1);assert.equal(h.count('agent-apply'),0);
 h.prepEmit({...h.prepStatus,phase:'transferred',revision:10,remainingMs:0});
 const a=h.access;h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();assert.equal(h.count('agent-apply'),1);
 h.prep.cancel();await flush();assert.equal(h.count('prep-cancel'),0);assert.equal(h.count('agent-apply'),1);
});

test('original inspection and Prepare promises, not early native events, gate proposal dispatch and Allow',async()=>{
 const inspect=deferred(),prepare=deferred();const h=await harness({inspect,delegatedPrepare:prepare});await h.read();
 assert.equal(h.count('inspect'),1);await h.prepareViaCli();assert.equal(h.count('delegated-prepare'),0);
 inspect.resolve();await flush();assert.equal(h.count('delegated-prepare'),1);assert.equal(h.agent.canAllow(),false);
 await h.agent.allow();assert.equal(h.count('allow'),0);assert.equal(h.prep.hasPendingCalls(),true);
 prepare.resolve();await flush();assert.equal(h.agent.canAllow(),true);assert.equal(h.prep.hasPendingCalls(),false);
});

test('changed or ABA original draft is preserved; inspection does not attach native STOP',async()=>{
 for(const aba of [false,true]){const h=await harness();await h.read();
  assert.equal(h.controller.setReplacement(I.item,true),true);if(aba)assert.equal(h.controller.setReplacement(I.item,false),true);
  await h.prepareViaCli();assert.equal(h.count('delegated-prepare'),0);assert.equal(h.count('close'),0);
  assert.equal(h.state.attempt.draftRevision,aba?2:1);assert.equal(h.state.attempt.choices[0].replaceExisting,!aba);
 }
});

test('reentrant pending/read and adopted-choices publications recheck exact original before native invocation',async()=>{
 for(const cut of ['inspect','prepare','adopt']){const h=await harness();if(cut!=='inspect')await h.read();let once=true;
  const off=(cut==='adopt'?h.controller:h.prep).subscribe(()=>{
   const ready=cut==='adopt'?h.state.attempt?.prepareClaimed:h.prep.getSnapshot().pending;
   if(once&&ready){once=false;h.block('other original peer');}
  });
  if(cut==='inspect')await h.read();else await h.prepareViaCli();off();
  assert.equal(h.count(cut==='inspect'?'inspect':'delegated-prepare'),0,cut);assert.equal(h.count('agent-apply'),0,cut);
 }
});

test('inspection original start clips a delayed reply; events and Check do not renew that end',async()=>{
 const inspect=deferred();const h=await harness({inspect});await h.read();h.advance(60001);inspect.resolve();await flush();
 assert.equal(h.count('prep-cancel'),1);await h.prepareViaCli();assert.equal(h.count('delegated-prepare'),0);
 assert.equal(h.count('close'),0);
});

test('native final/coalesced next cannot replace an outstanding original Prepare caller',async()=>{
 const prepare=deferred();const h=await harness({delegatedPrepare:prepare});await h.read();await h.prepareViaCli();
 h.native('final',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}});
 const final={...h.prepStatus,phase:'final',settlement:'settled',revision:12,remainingMs:0,result:{prepared:true,transferred:false,gui:false}};h.prepEmit(final);
 const next={...readStatus(),origin:{...origin(),requestId:id('8')}};h.latest(next);await flush();
 assert.deepEqual(h.last('prep-status').args,origin());assert.equal(h.prep.hasPendingCalls(),true);assert.equal(h.count('inspect'),1);
 prepare.resolve();await flush();await h.prep.check();await flush();
 assert.equal(h.prep.getSnapshot().status.origin.requestId,id('8'));assert.equal(h.count('inspect'),1); // no current new Choose/Open, so row-only refusal
});

test('unknown, null old reply and lost Prepare never enable another invocation or native status adoption',async()=>{
 for(const kind of ['unknown','null','lost']){const gate=kind==='lost'?deferred():null;const gates=gate?{delegatedPrepare:gate}:{};
  const h=await harness(gates);await h.read();await h.prepareViaCli();
  if(kind==='unknown')h.prepEmit({...h.prepStatus,phase:'unknown',settlement:'unknown',revision:11});
  else if(kind==='null'){gates.prepStatus=()=>null;await h.prep.check();}
  else{gate.reject(new Error('lost original'));await flush();}
  h.latest({...readStatus(),origin:{...origin(),requestId:id('8')}});await h.prep.check();await flush();
  assert.equal(h.count('delegated-prepare'),1,kind);assert.equal(h.agent.canAllow(),false,kind);assert.equal(h.prep.retains(),true,kind);
 }
});
