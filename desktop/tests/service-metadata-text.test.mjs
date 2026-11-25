// Actual controller/API/reducer tests with inert DTOs and retained promises.
// No native process, source files, Store, ownership or join receipts are made.
import assert from 'node:assert/strict';
import test from 'node:test';
import {createHash} from 'node:crypto';
import guide from '../../src/mobile_release/api/data/metadata-text-help-v1.json' with {type:'json'};
import {initialWorkspace,workspaceReducer,isDirty} from '../src/drafts.ts';
import {MetadataTextEditController,metadataOwnerReason} from '../src/metadataTextEditController.ts';
import {METADATA_TEXT_IDS,metadataTextDirty} from '../src/metadataText.ts';
import {parseMetadataTextEditStatus,parseMetadataTextObservation} from '../src/metadataTextProtocol.ts';
import {createMetadataServiceApi,parseMetadataServiceStatus,metadataServicePreviewMatches,METADATA_TEXT_CONSENT} from '../src/serviceMetadataTextProtocol.ts';
const ID={instance:'1'.repeat(32),project:'2'.repeat(32),request:'3'.repeat(32),session:'4'.repeat(32),window:'5'.repeat(32),revision:'6'.repeat(32),plan:'7'.repeat(32)};
const origin={serviceInstance:ID.instance,projectId:ID.project,requestId:ID.request};
const original={sessionId:ID.session,ownerGeneration:ID.window,revision:ID.revision};
const BASE={schemaVersion:1,metadata:{root:'release/store',androidLocales:['en-US','fr-FR'],iosLocales:['en-US']},android:{enabled:true},ios:{enabled:true}};
const assurance=basis=>({basis,projectCodeExecuted:false,toolsProbed:false,credentialsRead:false,gitObserved:false,storeContacted:false,writesPerformed:false,releaseReadiness:'unknown'});
const digest=text=>({byteLength:Buffer.byteLength(text),sha256:createHash('sha256').update(text).digest('hex')});
const clone=structuredClone;
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};};
const flush=async()=>{for(let n=0;n<32;n++)await Promise.resolve();};
const equalData=(a,b)=>assert.deepEqual(JSON.parse(JSON.stringify(a)),JSON.parse(JSON.stringify(b)));
function observed(platform='android',locale='en-US',values){
 values??=platform==='android'?['Hello','Public summary','A complete public description.']:['Public description','useful,local','https://example.invalid/privacy','https://example.invalid/support','Public release notes'];
 const fields=METADATA_TEXT_IDS[platform].map((id,i)=>values[i]===null?{id,path:`release/store/${platform}/${locale}/${id}`,state:'absent'}:{id,path:`release/store/${platform}/${locale}/${id}`,state:'present',text:values[i],...digest(values[i])});
 return{schemaVersion:1,platform,locale,metadataRoot:'release/store',observationScope:'single-request-non-atomic',baseline:{config:digest(JSON.stringify(BASE)),fields:fields.map(f=>f.state==='absent'?{id:f.id,state:'absent'}:{id:f.id,state:'present',byteLength:f.byteLength,sha256:f.sha256})},fields,assurance:assurance('static-text')};
}
function proposed(platform='android'){return METADATA_TEXT_IDS[platform].map((id,i)=>({id,text:observed(platform).fields[i].text+(id==='full_description.txt'||id==='description.txt'?' Now with an update.':'')}));}
function view(platform='android',locale='en-US',input=proposed(platform),load=observed(platform,locale)){
 const files=input.map((f,i)=>({id:f.id,path:load.fields[i].path,before:load.fields[i].state==='absent'?{state:'absent'}:{state:'present',text:load.fields[i].text,...digest(load.fields[i].text)},after:{text:f.text,...digest(f.text)},action:load.fields[i].state==='absent'?'create':load.fields[i].text===f.text?'preserve':'replace',lineEndingsChanged:false}));
 return{schemaVersion:1,platform,locale,metadataRoot:'release/store',files,createDirectories:[],validation:{schemaVersion:1,platform,valid:true,state:'format-valid',fields:input.map(f=>({id:f.id,valid:true,characterCount:[...f.text].length,limit:f.id==='title.txt'?30:f.id==='short_description.txt'?80:f.id==='keywords.txt'?100:f.id.endsWith('_url.txt')?2048:4000,issues:[]})),assurance:assurance('schema-policy')}};
}
function row(phase='queued-read',extra={}){return{schemaVersion:1,origin:clone(origin),revision:1,runtimeProjectId:'project-a',platform:'android',locale:'en-US',phase,observation:null,original:null,proposalSha256:null,review:null,permissionLive:false,remainingMs:0,applyConsumed:false,cancelRequested:false,result:null,doNotReplay:true,...extra};}
const status=(revision,request)=>({serviceInstance:ID.instance,revision,request});
function native(revision=1,active=null,lastTerminal=null){return{schemaVersion:1,domain:'metadata_text',windowGeneration:ID.window,statusRevision:revision,capability:{available:true,reason:'available'},active,lastTerminal};}
function projection(phase,platform='android',extra={}){return{domain:'metadata_text',projectId:'project-a',sessionId:ID.session,ownerGeneration:ID.window,platform,locale:'en-US',phase,reviewRemainingMs:900000,checkout:phase==='opening'?null:{revision:ID.revision,metadataRoot:'release/store',baseline:observed(platform).baseline},prepared:['reviewing','applying','final'].includes(phase)?{revision:ID.revision,planToken:ID.plan,draftRevision:0,baselineGeneration:0,view:view(platform)}:null,applySubmitted:['applying','final'].includes(phase),coreOutcome:phase==='final'?{effect:'committed',journal:'clean',resources:'settled',reason:'none'}:null,nativeReason:'none',nativeFinality:phase==='final'?'settled':'pending',lateSettled:false,...extra};}
function review(owner,revision){return{planToken:ID.plan,nativeStatusRevision:revision,proposalSha256:'8'.repeat(64),files:owner.prepared.view.files.map(f=>({id:f.id,action:f.action,beforeBytes:f.before.state==='absent'?null:f.before.byteLength,afterBytes:f.after.byteLength,afterSha256:f.after.sha256}))};}
function workspace(){let w=workspaceReducer(initialWorkspace,{type:'select',project:{id:'project-a',name:'App',path:'/inert-never-opened'}});w=workspaceReducer(w,{type:'snapshot-start',projectId:'project-a',requestId:1});return workspaceReducer(w,{type:'snapshot-done',projectId:'project-a',requestId:1,observedAt:0,snapshot:{root:'/inert-never-opened',observedAt:'',observationScope:'single-request-non-atomic',config:{content:null,path:'release/mobile-release.json',state:'format-valid',data:clone(BASE),issues:[]},discovery:{state:'unverified',partial:false,hints:{},scan:{entries:0,sourceFiles:0,sourceBytes:0,excludedEntries:0},limits:{}},assurance:assurance('static-text'),issues:[]}});}
function fixture(platform='android'){
 let w=workspace(),ns=native(),ss=status(1,null),nativeListener=()=>{},serviceListener=()=>{},peer=null;
 let loadCustom=null,callCustom=null,allowCustom=null,revokeCustom=null,boundaryCustom=null;const calls=[],boundaries=[],old=new Map();let controller;
 const emitNative=(v)=>{assert.ok(parseMetadataTextEditStatus(v),'valid inert native DTO');ns=v;nativeListener(v);};
 const emit=(r)=>{const next={...r,revision:r.revision??((ss.request?.revision??0)+1)};ss=status(ss.revision+1,next);assert.ok(parseMetadataServiceStatus(ss),'valid inert service DTO');old.set(next.origin.requestId,ss);serviceListener(ss);return ss;};
 const change=(phase,extra={})=>emit({...ss.request,phase,revision:(ss.request?.revision??0)+1,observation:null,...extra});
 const service={subscribe:async(fn)=>{serviceListener=fn;return()=>{};},status:async(q)=>q?(old.get(q.requestId)??status(ss.revision,null)):ss,
 load:async(q)=>{calls.push(['read',clone(q)]);if(loadCustom)return loadCustom(q);const result=observed(platform);change('loaded',{observation:result});return result;},
 continue:async(q,step)=>{calls.push([step,clone(q)]);if(callCustom)return callCustom(q,step);const phase=step==='open'?'editing':step==='prepare'?'reviewing':'applying';const p=projection(phase,platform);emitNative(native(ns.statusRevision+1,p,ns.lastTerminal));if(step==='open')change('opened',{original:clone(original)});if(step==='prepare')change('reviewing',{review:review(p,ns.statusRevision)});if(step==='apply')change('applying');return ns;},
 allow:async(a)=>{calls.push(['allow',clone(a)]);if(allowCustom)return allowCustom(a);return change('reviewing',{permissionLive:true,remainingMs:60000});},
 revoke:async(q)=>{calls.push(['revoke',clone(q)]);if(revokeCustom)return revokeCustom(q);return change(ss.request.original?'stopping':'refused',{cancelRequested:true,permissionLive:false,remainingMs:0});}};
 const api={mode:'native',agentMetadataText:service,subscribeMetadataTextEdit:async(fn)=>{nativeListener=fn;return()=>{};},metadataTextEditStatus:async()=>ns,
 observeMetadataText:async(a)=>{calls.push(['gui-load',a]);return observed(a.platform,a.locale);}};
 controller=new MetadataTextEditController({selectedProject:()=>w.projects[w.selectedId]??null,otherEditReason:()=>peer,onRecoveryBoundary:id=>{boundaries.push(id);boundaryCustom?.(id);}});
 const info={runtime:{state:'available',mode:'development',reason:null},capabilities:{methods:[{method:'metadata.text.observe',available:true,reason:''},{method:'metadata.text.validate',available:true,reason:''}]}};
 controller.beginConnection();controller.setConnection(api,info);controller.setHelp(guide);
 if(platform==='ios'){const selected=controller.getSnapshot().choices.find(c=>c.platform==='ios'&&c.locale==='en-US');controller.selectContext(selected.key);}
 return{controller,service,api,calls,boundaries,emit,emitNative,change,get state(){return controller.agent.getSnapshot();},get request(){return ss.request;},get native(){return ns;},get workspace(){return w;},set peer(v){peer=v;},set loadCustom(v){loadCustom=v;},set callCustom(v){callCustom=v;},set allowCustom(v){allowCustom=v;},set revokeCustom(v){revokeCustom=v;},set boundaryCustom(v){boundaryCustom=v;},
 dispatch(a){controller.beforeWorkspaceAction(a);w=workspaceReducer(w,a);controller.syncProject();},
 async start(){await controller.connect(api);},async loaded(){await this.start();emit(row('queued-read',{platform}));await flush();},async reviewing(){await this.loaded();change('queued-prepare',{proposalSha256:'8'.repeat(64)});await flush();},async allowed(){await this.reviewing();assert.equal(controller.agent.allowReason(),null);controller.agent.acknowledge(true);await controller.agent.allow();},async applying(){await this.allowed();change('queued-apply',{permissionLive:false,remainingMs:0,applyConsumed:true});await flush();},
 finish(extra={}){const p=projection('final',platform,extra);emitNative(native(ns.statusRevision+1,null,p));return change('final',{result:{effect:p.coreOutcome.effect,journal:p.coreOutcome.journal,cancelled:p.nativeReason!=='none',applySubmitted:p.applySubmitted},permissionLive:false,remainingMs:0});}};
}
test('bridge uses same four original metadata commands and three fixed access calls with IDs only',async()=>{
 const calls=[];const api=createMetadataServiceApi('native',async(c,bytes)=>{calls.push([c,JSON.parse(new TextDecoder().decode(bytes))]);if(c==='metadata_text_observe')return observed();if(c.startsWith('metadata_text_edit'))return native();return status(1,null);},async()=>()=>{});
 for(const step of['open','prepare','apply'])await api.continue(origin,step);await api.load(origin);await api.status();await api.revoke(origin);
 equalData(calls[0],['metadata_text_edit_open',{intent:'agent-metadata-text',origin}]);equalData(calls[3],['metadata_text_observe',{intent:'agent-metadata-text',origin}]);
 assert.equal(calls.length,6);assert.equal(createMetadataServiceApi('preview',()=>assert.fail()),null);
});
test('strict public parser preserves complete 4000-character iOS lists and rejects partial/path/private DTOs',()=>{
 const values=['😀'.repeat(4000),'words','https://example.invalid/privacy','https://example.invalid/support','x'.repeat(4000)];const o=observed('ios','en-US',values);assert.ok(parseMetadataTextObservation(o));
 const s=status(2,row('loaded',{platform:'ios',observation:o}));const parsed=parseMetadataServiceStatus(s);assert.ok(parsed);assert.equal(parsed.request.observation.fields[0].text,values[0]);
 for(const edit of[v=>{delete v.request.observation;},v=>{v.request.observation.fields.pop();},v=>{v.request.path='/foreign';},v=>{v.request.review={};},v=>{v.request.observation.fields[0].password='private';},v=>{v.request.phase='unknown';},v=>{v.request.original={...original,root:'/fake'};}]){const bad=clone(s);edit(bad);assert.equal(parseMetadataServiceStatus(bad),null);}
 const getter=clone(s);Object.defineProperty(getter.request,'observation',{enumerable:true,get(){assert.fail('getter not executed');}});assert.equal(parseMetadataServiceStatus(getter),null);
});
test('real selected parent runs Load to full native preview and explicit one-use Apply without adopting a draft',async()=>{
 for(const platform of['android','ios']){const f=fixture(platform);const session=f.workspace.projects['project-a'];await f.allowed();assert.equal(f.state.unknown,false);assert.ok(metadataServicePreviewMatches(f.request,f.native.active));assert.equal(f.calls.filter(c=>c[0]==='read').length,1);assert.equal(f.calls.filter(c=>c[0]==='open').length,1);assert.equal(f.calls.filter(c=>c[0]==='prepare').length,1);assert.equal(f.calls.filter(c=>c[0]==='apply').length,0);assert.equal(f.calls.find(c=>c[0]==='allow')[1].consentVersion,METADATA_TEXT_CONSENT);
 f.change('queued-apply',{permissionLive:false,remainingMs:0,applyConsumed:true});await flush();assert.equal(f.calls.filter(c=>c[0]==='apply').length,1);f.finish();await flush();assert.equal(f.state.unknown,false);assert.match(f.state.message,/save settled/);assert.equal(f.controller.getSnapshot().edit.attempt,null);assert.equal(f.workspace.projects['project-a'],session);assert.equal(isDirty(session),false);assert.deepEqual(f.boundaries,['project-a']);await f.controller.agent.allow();assert.equal(f.calls.filter(c=>c[0]==='allow').length,1);}
});
test('original native/service final before Apply promise cannot release pending or start replacement',async()=>{
 const f=fixture();await f.allowed();const pending=deferred();f.callCustom=(_q,step)=>step==='apply'?pending.promise:assert.fail();f.change('queued-apply',{applyConsumed:true,permissionLive:false,remainingMs:0});await flush();assert.equal(f.state.pending,'apply');f.finish();await flush();assert.equal(f.state.pending,'apply');assert.match(metadataOwnerReason(f.controller.getSnapshot(),'project-a'),/original CLI/);assert.doesNotMatch(f.state.message??'',/save settled/);pending.resolve(f.native);await flush();assert.equal(f.state.pending,null);assert.equal(f.state.unknown,false);assert.match(f.state.message,/save settled/);
});
test('lost Apply reply keeps original Unknown after positive events and never replays',async()=>{
 const f=fixture();await f.allowed();f.callCustom=async()=>{throw new Error('inert lost reply');};f.change('queued-apply',{applyConsumed:true,permissionLive:false,remainingMs:0});await flush();assert.equal(f.state.unknown,true);f.finish();await f.controller.agent.check();assert.equal(f.state.unknown,true);assert.equal(f.calls.filter(c=>c[0]==='apply').length,1);assert.doesNotMatch(f.state.message??'',/save settled/);
});
test('missing Load reply and changed fresh Open baseline refuse progression without reloading',async()=>{
 const lost=fixture();lost.loadCustom=async()=>{throw new Error('inert lost public Load');};await lost.loaded();await lost.controller.agent.check();assert.equal(lost.state.unknown,true);assert.equal(lost.calls.filter(c=>c[0]==='read').length,1);assert.equal(lost.calls.filter(c=>c[0]==='open').length,0);
 const f=fixture();await f.loaded();f.callCustom=async(_q,step)=>{assert.equal(step,'open');const p=projection('editing');p.checkout.metadataRoot='release/changed';f.emitNative(native(2,p));f.change('opened',{original});return f.native;};f.change('queued-prepare',{proposalSha256:'8'.repeat(64)});await flush();assert.equal(f.calls.filter(c=>c[0]==='read').length,1);assert.equal(f.calls.filter(c=>c[0]==='prepare').length,0);assert.notEqual(f.controller.agent.allowReason(),null);
});
test('every reentrant Allow boundary rechecks original locale, source, peer and native preview',async()=>{
 for(const action of['locale','peer','expire','hide']){const f=fixture();await f.reviewing();assert.equal(f.controller.agent.allowReason(),null);f.controller.agent.acknowledge(true);let changed=false;f.controller.agent.subscribe(()=>{if(changed||f.state.pending!=='allow')return;changed=true;if(action==='locale')f.controller.selectContext(f.controller.getSnapshot().choices.find(c=>c.locale==='fr-FR').key);if(action==='peer')f.peer='Other edit';if(action==='expire'){const p=clone(f.native.active);p.reviewRemainingMs=0;f.emitNative(native(f.native.statusRevision+1,p));}if(action==='hide')f.controller.setVisible(false);});await f.controller.agent.allow();await flush();assert.equal(f.calls.filter(c=>c[0]==='allow').length,0,action);assert.equal(f.calls.filter(c=>c[0]==='revoke').length,1,action);}
});
test('lost Allow permits only exact STOP and a late grant cannot revive it',async()=>{
 const f=fixture();await f.reviewing();const pending=deferred();f.allowCustom=()=>pending.promise;f.controller.agent.acknowledge(true);const allow=f.controller.agent.allow();await flush();const before=clone(f.request);await f.controller.agent.revoke();pending.resolve(status(f.state.status.revision-1,{...before,permissionLive:true,remainingMs:60000}));await allow;assert.equal(f.calls.filter(c=>c[0]==='allow').length,1);assert.equal(f.calls.filter(c=>c[0]==='revoke').length,1);assert.notEqual(f.controller.agent.allowReason(),null);assert.equal(f.calls.filter(c=>c[0]==='apply').length,0);
 const g=fixture();await g.reviewing();g.allowCustom=async()=>{throw new Error('lost');};g.controller.agent.acknowledge(true);await g.controller.agent.allow();assert.equal(g.state.unknown,true);await g.controller.agent.revoke();assert.equal(g.state.unknown,true);equalData(g.calls.find(c=>c[0]==='revoke')[1],origin);
});
test('known cancelled committed effect remains cancelled and dirty locale drafts survive refusal',async()=>{
 const f=fixture();await f.applying();f.finish({nativeReason:'cancelled',coreOutcome:{effect:'committed',journal:'clean',resources:'settled',reason:'cancelled'}});await flush();assert.equal(f.state.unknown,false);assert.doesNotMatch(f.state.message,/save settled/);assert.match(f.state.message,/without a confirmed/);
 const dirty=fixture();await dirty.start();await dirty.controller.load();dirty.controller.editField(dirty.controller.getSnapshot().selectedKey,'full_description.txt','Keep my unsaved local draft');const entry=dirty.controller.selectedEntry();assert.ok(metadataTextDirty(entry));dirty.emit(row());await flush();assert.equal(dirty.calls.filter(c=>c[0]==='read').length,0);assert.equal(dirty.controller.selectedEntry(),entry);assert.equal(dirty.controller.selectedEntry().fields.find(x=>x.id==='full_description.txt').text,'Keep my unsaved local draft');
});
test('same-revision countdown can decrease without renewing or allowing identity contradictions',async()=>{
 const f=fixture();await f.allowed();const s=clone(f.state.status);s.request.remainingMs=20;f.controller.agent.receive(s);assert.equal(f.state.unknown,false);const older=clone(s);older.request.remainingMs=60000;f.controller.agent.receive(older);assert.equal(f.state.status.request.remainingMs,20);const bad=clone(s);bad.request.review.planToken='f'.repeat(32);f.controller.agent.receive(bad);assert.equal(f.state.unknown,true);
});
test('coalesced original final is queried by exact ID before a new Load can continue',async()=>{
 const f=fixture();await f.allowed();await f.controller.agent.revoke();const oldRequest=clone(f.request);const final=projection('final','android',{applySubmitted:false,nativeReason:'cancelled',coreOutcome:{effect:'not_started',journal:'not_created',resources:'settled',reason:'cancelled'}});f.emitNative(native(f.native.statusRevision+1,null,final));
 const nextOrigin={...origin,requestId:'9'.repeat(32)};f.emit(row('queued-read',{origin:nextOrigin,revision:f.request.revision+1}));await flush();assert.equal(f.calls.filter(c=>c[0]==='read').length,1);
 const queries=[];const latest=f.state.status;f.service.status=async q=>{queries.push(q?clone(q):null);return q?status(latest.revision,{...oldRequest,phase:'final',revision:oldRequest.revision+1,result:{effect:'not_started',journal:'not_created',cancelled:true,applySubmitted:false}}):latest;};
 await f.controller.agent.check();await flush();equalData(queries,[null,origin]);assert.equal(f.state.unknown,false);assert.equal(f.calls.filter(c=>c[0]==='read').length,2);equalData(f.calls.filter(c=>c[0]==='read')[1][1],nextOrigin);
});
test('edit invalidation cannot overwrite a reentrant newer same-field other-field or restored draft',async()=>{
 for(const action of['same-field','other-field','edit-restore','locale','connection']){
  const f=fixture();await f.start();await f.controller.load();const key=f.controller.getSnapshot().selectedKey;
  f.emit(row());await flush();const before=f.controller.selectedEntry();let entered=false,newer=null;
  f.controller.agent.subscribe(()=>{
   if(entered)return;entered=true;
   if(action==='same-field')assert.equal(f.controller.editField(key,'full_description.txt','Newer listener text'),true);
   if(action==='other-field')assert.equal(f.controller.editField(key,'title.txt','Newer title'),true);
   if(action==='edit-restore'){
    assert.equal(f.controller.editField(key,'full_description.txt','Temporary listener edit'),true);
    assert.equal(f.controller.editField(key,'full_description.txt',before.fields[2].text),true);
   }
   if(action==='locale')assert.equal(f.controller.selectContext(f.controller.getSnapshot().choices.find(c=>c.locale==='fr-FR').key),true);
   if(action==='connection')f.controller.beginConnection();
   newer=f.controller.getSnapshot().entries[key];
  });
  assert.equal(f.controller.editField(key,'full_description.txt','Older outer edit'),false,action);
  assert.equal(entered,true,action);assert.equal(f.controller.getSnapshot().entries[key],newer,action);
  assert.notEqual(newer.fields[2].text,'Older outer edit',action);
  if(action==='edit-restore'){assert.equal(newer.revision,before.revision+2);assert.equal(newer.fields[2].text,before.fields[2].text);}
  await flush();assert.equal(f.calls.filter(c=>c[0]==='revoke').length,1,action);equalData(f.calls.find(c=>c[0]==='revoke')[1],origin);
 }
});
test('Apply boundary permits only its own stale marking of the same clean draft and baseline',async()=>{
 const f=fixture();await f.start();await f.controller.load();const before=f.controller.selectedEntry();await f.allowed();
 assert.equal(f.controller.selectedEntry(),before);f.change('queued-apply',{permissionLive:false,remainingMs:0,applyConsumed:true});await flush();
 assert.equal(f.calls.filter(c=>c[0]==='apply').length,1);assert.equal(f.calls.filter(c=>c[0]==='revoke').length,0);
 const after=f.controller.selectedEntry();assert.notEqual(after,before);assert.equal(after.fields,before.fields);assert.equal(after.baseline,before.baseline);
 assert.equal(after.revision,before.revision);assert.equal(after.baselineGeneration,before.baselineGeneration);assert.equal(after.observationGeneration,before.observationGeneration);
 assert.equal(after.stale,true);assert.equal(after.observationPredatesSave,true);f.finish();await flush();assert.equal(f.state.unknown,false);assert.match(f.state.message,/save settled/);
});
test('Apply rechecks the same original after both parent publications and the recovery callback',async()=>{
 for(const boundary of['first-publication','stale-publication','callback'])for(const action of['draft','edit-restore','locale','project','peer','revoke','hide','expire']){
  const f=fixture();await f.start();await f.controller.load();const key=f.controller.getSnapshot().selectedKey;await f.allowed();
  const before=f.controller.selectedEntry();let fired=false,published=0;
  const change=()=>{
   if(fired)return;fired=true;
   if(action==='draft')assert.equal(f.controller.editField(key,'full_description.txt','Newer boundary draft'),true);
   if(action==='edit-restore'){
    assert.equal(f.controller.editField(key,'full_description.txt','Temporary boundary draft'),true);
    assert.equal(f.controller.editField(key,'full_description.txt',before.fields[2].text),true);
   }
   if(action==='locale')assert.equal(f.controller.selectContext(f.controller.getSnapshot().choices.find(c=>c.locale==='fr-FR').key),true);
   if(action==='project')f.dispatch({type:'select',project:{id:'project-other',name:'Other',path:'/inert-other-never-opened'}});
   if(action==='peer')f.peer='Another original operation';
   if(action==='revoke')void f.controller.agent.revoke();
   if(action==='hide')f.controller.setVisible(false);
   if(action==='expire'){const p=clone(f.native.active);p.reviewRemainingMs=0;f.emitNative(native(f.native.statusRevision+1,p));}
  };
  if(boundary==='callback')f.boundaryCustom=change;
  else f.controller.subscribe(()=>{if(fired||f.state.pending!=='apply')return;published++;if(published===(boundary==='first-publication'?1:2))change();});
  f.change('queued-apply',{permissionLive:false,remainingMs:0,applyConsumed:true});await flush();
  const label=`${boundary}/${action}`;assert.equal(fired,true,label);assert.equal(f.calls.filter(c=>c[0]==='apply').length,0,label);
  assert.equal(f.calls.filter(c=>c[0]==='revoke').length,1,label);equalData(f.calls.find(c=>c[0]==='revoke')[1],origin);
  assert.doesNotMatch(f.state.message??'',/save settled/,label);
  const after=f.controller.getSnapshot().entries[key];
  if(action==='draft')assert.equal(after.fields[2].text,'Newer boundary draft',label);
  if(action==='edit-restore'){assert.equal(after.revision,before.revision+2,label);assert.equal(after.fields[2].text,before.fields[2].text,label);}
 }
});
