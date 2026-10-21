// Actual existing image controller + closed permission facet, inert ports only.
// No picker, image decoding, subprocess, file copy, Store or native receipt.
import assert from 'node:assert/strict';
import test from 'node:test';
import catalog from '../../src/mobile_release/api/data/metadata-images-v1.json' with { type:'json' };
import help from '../../src/mobile_release/api/data/metadata-image-help-v1.json' with { type:'json' };
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { MetadataImagesController, currentMetadataImagesApplyBinding, metadataImagesOwnerReason } from '../src/metadataImagesController.ts';
import { parseImagesAgentAccess, parseImagesAgentRevoked, createMetadataImagesAgentApi, METADATA_IMAGES_AGENT_CONSENT } from '../src/serviceMetadataImagesProtocol.ts';

const id = n => n.repeat(32), clone = v => structuredClone(v);
const I = {window:id('a'),session:id('b'),revision:id('c'),plan:id('d'),selection:id('e'),operation:id('f'),item:id('1'),
  service:id('2'),project:id('3'),grant:id('4'),request:id('5'),nonce:id('6')};
const config = {schemaVersion:1,metadata:{root:'release/store',androidLocales:['en-US','fr-FR']},android:{enabled:true},ios:{enabled:false}};
const digest = {byteLength:4,sha256:'9'.repeat(64)}, summary = {...digest,format:'png',width:1080,height:1920,headerChecked:true};
const baseline = {config:digest,ignore:digest,inventorySha256:'8'.repeat(64)};
const view = () => ({kind:'import',policy:'metadata-images-v1',platform:'android',locale:'en-US',assetType:'phoneScreenshots',metadataRoot:'release/store',
  folder:'release/store/android/en-US/images/phoneScreenshots',files:[{itemId:I.item,displayName:'01.png',path:'release/store/android/en-US/images/phoneScreenshots/01.png',
    action:'create',before:null,selected:clone(summary),after:clone(summary),canReplace:false,issues:[]}],existing:[],
  finalOrder:['release/store/android/en-US/images/phoneScreenshots/01.png'],valid:true,issues:[],
  assurance:{localCopyOnly:true,sourceFilesUnchanged:true,storeContacted:false,fullDecode:false,contentApproved:false,storeAccepted:false}});
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
  settlement:'known',selectionToken:token,items:[{itemId:I.item,displayName:'01.png',...digest}]};}
function owner(phase='editing',request=null,extra={}) {return{domain:'metadata_images',projectId:'p',sessionId:I.session,ownerGeneration:I.window,phase,reviewRemainingMs:900000,
  applySubmitted:['applying','finalizing','final'].includes(phase),nativeReason:'none',nativeFinality:phase==='final'?'settled':'pending',lateSettled:false,
  coreOutcome:phase==='final'?{effect:'committed',journal:'clean',resources:'settled',reason:'none'}:null,
  details:{intent:'import',checkout:{revision:I.revision,baseline:clone(baseline),view:view()},prepared:request?{revision:I.revision,planToken:I.plan,
    draftRevision:request.draftRevision,baselineGeneration:request.baselineGeneration,view:view()}:null},...extra};}
function review(statusRevision=2) {return{original:{sessionId:I.session,ownerGeneration:I.window,revision:I.revision,planToken:I.plan,draftRevision:0,baselineGeneration:1},
  nativeStatusRevision:statusRevision,platform:'android',locale:'en-US',assetType:'phoneScreenshots',fileCount:1,createCount:1,replaceCount:0,preserveCount:0,
  selectedBytes:4,preparedSha256:'7'.repeat(64)};}
function access(nonce=I.nonce){return{schemaVersion:1,serviceInstance:I.service,projectId:I.project,grantId:I.grant,nonce,review:review(),live:true,remainingMs:60000,request:null};}
function request(a,phase='queued',revision=1) {return{schemaVersion:1,origin:origin(),grantId:a.grantId,revision,phase,
  settlement:phase==='final'?'settled':phase==='unknown'?'unknown':'pending',review:clone(a.review),cancelRequested:false,
  result:phase==='final'?{effect:'committed',journal:'clean',cancelled:false,applySubmitted:true,completed:true}:null,doNotReplay:true};}
async function harness(gates={}) {
  let workspace=project(), selectionFrame=frame('metadata_images_selection',0), editFrame=frame('metadata_images',0), prepared=null,
    a=empty(), selectionListener, editListener, agentListener, clock=100, other=null;
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
  const api={mode:'native',agent,metadataImagesCatalog:async()=>publicCatalog(),
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
  assert.equal(controller.choose(),true);await flush();assert.equal(controller.prepare(),true);await flush();
  const h={controller,api,calls,off,agent:controller.agent,get state(){return controller.getSnapshot();},get access(){return clone(a);},
    count:(kind)=>calls.filter(c=>c.kind===kind).length,last:(kind)=>calls.filter(c=>c.kind===kind).at(-1),
    advance:n=>clock+=n,block:v=>{other=v;},
    emit:a2=>{a=clone(a2);agentListener(clone(a));},native:(phase,extra={})=>setOwner(owner(phase,prepared,extra)),
    dispatch:action=>{controller.beforeWorkspaceAction(action);workspace=workspaceReducer(workspace,action);controller.syncProject();},
    sameWorkspace:()=>{const a={type:'snapshot-done',projectId:'p',requestId:999,snapshot:{},observedAt:0};controller.beforeWorkspaceAction(a);controller.syncProject();},
  };
  return h;
}

test('closed compact protocol pairs exact origin/review/counts/finality and rejects private data/accessors',()=>{
  const a=access();assert.ok(parseImagesAgentAccess(a));assert.ok(parseImagesAgentRevoked({nonce:I.nonce,access:a}));
  assert.ok(parseImagesAgentAccess({...a,live:false,remainingMs:0,request:request(a,'final',4)}));
  for(const change of [v=>delete v.nonce,v=>v.paths=['/never'],v=>v.review.original.draftRevision=0xffffffff,
    v=>v.review.fileCount=2,v=>v.review.selectedBytes=25165825,v=>v.review.preparedSha256='bad',
    v=>v.review.assetType='../path',v=>v.review.original.planToken=v.review.original.revision,
    v=>v.remainingMs=0,v=>v.request=request(v,'queued'),v=>v.serviceInstance='0'.repeat(32)]){
    const bad=clone(a);change(bad);assert.equal(parseImagesAgentAccess(bad),null);
  }
  let getters=0;const bad=clone(a);Object.defineProperty(bad,'live',{enumerable:true,get(){getters++;return true;}});
  assert.equal(parseImagesAgentAccess(bad),null);assert.equal(getters,0);
  const badFinal={...a,live:false,remainingMs:0,request:request(a,'final',4)};
  badFinal.request.result.effect='unchanged';badFinal.request.result.journal='not_created';assert.equal(parseImagesAgentAccess(badFinal),null);
});

test('bridge uses only three raw permission calls and the existing Apply arm; no picker or image content',async()=>{
  const calls=[];const a=access();const api=createMetadataImagesAgentApi('native',async(command,raw)=>{assert.ok(raw instanceof Uint8Array);
    const value=JSON.parse(new TextDecoder().decode(raw));calls.push({command,value});return command==='revoke_agent_metadata_images'?{nonce:I.nonce,access:a}:a;
  },async()=>()=>{});
  assert.equal(createMetadataImagesAgentApi('preview',()=>{},()=>{}),undefined);
  await api.status(origin());await api.allow({projectId:'p',original:a.review.original,statusRevision:2,nonce:I.nonce,consent:METADATA_IMAGES_AGENT_CONSENT});await api.revoke(I.nonce);
  assert.deepEqual(calls.map(c=>c.command),['agent_metadata_images_status','allow_agent_metadata_images_apply','revoke_agent_metadata_images']);
  assert.deepEqual(calls[0].value,origin());assert.equal('files' in calls[1].value,false);assert.equal('preparedSha256' in calls[1].value,false);
});

test('child Prepared before original Prepare return cannot enable Allow; exact return does',async()=>{
  const prepare=deferred();const h=await harness({prepare});assert.ok(h.state.attempt.projection.details.prepared);
  assert.equal(h.state.callerPending,true);assert.equal(h.agent.canAllow(),false);await h.agent.allow();assert.equal(h.count('allow'),0);
  prepare.resolve();await flush();assert.equal(h.state.callerPending,false);assert.equal(h.agent.canAllow(),true);
  await h.agent.allow();assert.equal(h.count('allow'),1);assert.equal(h.count('agent-apply'),0);
});

test('only explicit returned Allow dispatches same queued CLI original once; cold or event-before-Allow-return cannot',async()=>{
  const allow=deferred();const h=await harness({allow});const work=h.agent.allow();await flush();const a=h.access;
  h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();assert.equal(h.count('agent-apply'),0);
  allow.resolve();await work;await flush();assert.equal(h.count('agent-apply'),1);assert.deepEqual(h.last('agent-apply').args,origin());
  h.emit({...a,live:false,remainingMs:0,request:request(a,'applying',4)});await flush();assert.equal(h.count('agent-apply'),1);
  const cold=await harness();cold.emit({...access(),live:false,remainingMs:0,request:request(access())});await flush();assert.equal(cold.count('agent-apply'),0);
});

test('Allow pending subscriber navigation/revoke/ABA and peer change cannot send permission',async()=>{
  for(const cut of ['navigation','aba','revoke','peer']){
    const h=await harness();let once=true;const off=h.agent.subscribe(()=>{if(once&&h.agent.getSnapshot().pending){once=false;
      if(cut==='navigation')h.controller.setVisible(false);else if(cut==='aba')h.sameWorkspace();else if(cut==='revoke')void h.agent.revoke();else h.block('peer original');}});
    await h.agent.allow();await flush();off();assert.equal(h.count('allow'),0,cut);assert.equal(h.count('agent-apply'),0,cut);
  }
});

test('Apply pending publication rechecks current project/peer before sole existing Apply command',async()=>{
  for(const cut of ['aba','peer']){
    const h=await harness();await h.agent.allow();let once=true;
    const off=h.agent.subscribe(()=>{if(once&&h.agent.getSnapshot().access?.request&&h.agent.getSnapshot().pending){once=false;
      if(cut==='aba')h.sameWorkspace();else h.block('new peer');}});
    const a=h.access;h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();off();
    assert.equal(h.count('agent-apply'),0,cut);assert.equal(h.count('revoke'),1,cut);assert.ok(h.agent.retains());
  }
});

test('native and service Final before real Apply return keep original caller/API/listeners',async()=>{
  const apply=deferred();const h=await harness({apply});await h.agent.allow();const a=h.access;
  h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();const final=h.native('final');
  h.emit({...a,live:false,remainingMs:0,request:request(a,'final',5)});await flush();
  assert.equal(h.agent.retains(),true);assert.equal(h.state.callerPending,true);assert.match(metadataImagesOwnerReason(h.state),/retained/);
  assert.equal(h.controller.choose(),false);apply.resolve(final);await flush();assert.equal(h.state.callerPending,false);assert.equal(h.agent.retains(),false);
  assert.equal(h.count('agent-apply'),1);
});

test('lost Allow stays one original, exact Revoke only, no regrant and no queued auto-Apply',async()=>{
  const allow=deferred();const h=await harness({allow});const work=h.agent.allow();await flush();allow.reject(new Error('lost'));
  await work;await flush();assert.equal(h.count('revoke'),1);await h.agent.allow();assert.equal(h.count('allow'),1);
  const a=h.access;h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();assert.equal(h.count('agent-apply'),0);
  assert.equal(h.agent.retains(),true);
});

test('same grant countdown decreases only; delayed Allow/status cannot renew an expired allowance',async()=>{
  const h=await harness();await h.agent.allow();const a=h.access;h.advance(1000);h.emit({...a,remainingMs:500});
  assert.equal(h.agent.getSnapshot().access.remainingMs,500);h.emit({...a,remainingMs:60000});assert.equal(h.agent.getSnapshot().access.remainingMs,500);
  h.advance(501);h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();assert.equal(h.count('agent-apply'),0);assert.equal(h.count('revoke'),1);
});

test('delayed original Allow reply cannot move a shorter READ deadline to receipt time',async()=>{
  const allow=deferred();const h=await harness({allow});const work=h.agent.allow();await flush();
  const a=h.access;assert.equal(a.remainingMs,60000);h.advance(60001);allow.resolve();await work;await flush();
  assert.equal(h.agent.getSnapshot().access.live,false);assert.equal(h.agent.getSnapshot().access.remainingMs,0);
  h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();
  assert.equal(h.count('agent-apply'),0);assert.equal(h.count('revoke'),1);assert.equal(h.agent.retains(),true);
});

test('delayed original Check reply clips the READ deadline at that call start and keeps expired authority closed',async()=>{
  const status=deferred();const h=await harness({status});await h.agent.allow();const a=h.access;h.advance(1000);
  const work=h.agent.check();await flush();assert.equal(h.count('agent-status'),1);
  h.advance(501);status.resolve({...a,remainingMs:500});await work;await flush();
  assert.equal(h.agent.getSnapshot().access.live,false);assert.equal(h.agent.getSnapshot().access.remainingMs,0);
  h.emit({...a,remainingMs:60000});assert.equal(h.agent.getSnapshot().access.live,false);
  h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();
  assert.equal(h.count('agent-apply'),0);assert.equal(h.count('revoke'),1);assert.equal(h.agent.retains(),true);
});

test('scheduled Apply rechecks the latest same request deadline phase and cancellation after its pending publication',async()=>{
  for(const cut of ['expired','cancelled','admitting']){
    const h=await harness();await h.agent.allow();const a=h.access;let once=true;
    const off=h.agent.subscribe(()=>{if(once&&h.agent.getSnapshot().access?.request&&h.agent.getSnapshot().pending){once=false;
      if(cut==='expired')h.advance(60001);
      else h.emit({...a,live:false,remainingMs:0,request:{...request(a,cut==='admitting'?'admitting':'queued',2),cancelRequested:cut==='cancelled'}});
    }});
    h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();off();
    assert.equal(h.count('agent-apply'),0,cut);assert.equal(h.count('revoke'),1,cut);assert.equal(h.agent.retains(),true,cut);
  }
});

test('ordinary GUI competes only with unused allowance; a consumed CLI row never enables GUI replay',async()=>{
  const h=await harness();await h.agent.allow();const b=currentMetadataImagesApplyBinding(h.state);h.controller.acknowledge(true);
  assert.equal(h.controller.apply(b),true);await flush();assert.equal(h.count('gui-apply'),1);assert.equal(h.count('agent-apply'),0);
  const a=h.access;h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();assert.equal(h.count('agent-apply'),0);
  const cli=await harness();await cli.agent.allow();const c=cli.access;cli.emit({...c,live:false,remainingMs:0,request:request(c)});
  cli.controller.acknowledge(true);assert.equal(cli.controller.apply(currentMetadataImagesApplyBinding(cli.state)),false);await flush();assert.equal(cli.count('gui-apply'),0);
});

test('unknown/cross-origin status never frees or replaces original and Check addresses retained origin',async()=>{
  const h=await harness();await h.agent.allow();const a=h.access;h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();
  h.emit({...a,live:false,remainingMs:0,request:request(a,'unknown',6)});h.native('final');await h.agent.check();
  assert.deepEqual(h.last('agent-status').args,origin());assert.equal(h.agent.retains(),true);assert.equal(h.agent.getSnapshot().unknown,true);
  const other=request(a,'final',7);other.origin.requestId=id('8');h.emit({...a,live:false,remainingMs:0,request:other});
  assert.equal(h.count('agent-apply'),1);assert.equal(h.agent.retains(),true);
});

test('Dispose cannot retire image or permission listeners while original Apply/Close/Revoke remain pending',async()=>{
  const apply=deferred(),close=deferred(),revoke=deferred();const h=await harness({apply,close,revoke});await h.agent.allow();const a=h.access;
  h.emit({...a,live:false,remainingMs:0,request:request(a)});await flush();h.controller.dispose();await flush();assert.deepEqual(h.off,[]);
  const final=frame('metadata_images',4,null,owner('final',h.state.attempt.prepareRequest));apply.resolve(final);close.resolve(final);revoke.resolve();await flush();
  assert.deepEqual([...h.off].sort(),['agent','edit','selection']);assert.equal(h.count('agent-apply'),1);assert.equal(h.count('revoke'),1);
});
