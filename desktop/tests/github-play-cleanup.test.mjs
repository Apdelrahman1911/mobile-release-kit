// Inert complete modules and original deferred IPC only: no HTTP, Store edit,
// native service, workflow execution, credentials or actual candidate files.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubPlayCleanupController } from '../src/githubPlayCleanupController.ts';
import { createGitHubPlayCleanupPort, encodePlayCleanupRequest, parsePlayCleanupStatus,
  playCleanupConfirmation, playCleanupError, PLAY_CLEANUP_EVENT } from '../src/githubPlayCleanupProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';

const copy=structuredClone,marker='a'.repeat(32),consentId='b'.repeat(32),AT=Date.parse('2026-10-21T12:00:00Z');
const UUID='11111111-1111-4111-8111-111111111111',ATTEMPT='22222222-2222-4222-8222-222222222222';
function connection(){return {mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'owner/app'},
  status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'owner/app',state:'connected'},
    account:{state:'observed',value:{id:'11',login:'owner'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app'}}},
  busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false,error:null};}
function workspace(){const project={id:'project-a',name:'Inert project',path:'/inert-not-opened'};
  let w=workspaceReducer(initialWorkspace,{type:'select',project});w=workspaceReducer(w,{type:'snapshot-start',projectId:project.id,requestId:1});
  return workspaceReducer(w,{type:'snapshot-done',projectId:project.id,requestId:1,observedAt:AT,
    snapshot:{config:{state:'format-valid',data:{android:{enabled:true},github:{repository:'owner/app'}},content:{bytes:64,sha256:'1'.repeat(64)}}}});}
function target(){return {scope:{projectBinding:'d'.repeat(64),repository:'owner/app',accountId:'11',repositoryId:'22'},
  toolingRepository:'Apdelrahman1911/mobile-release-kit',toolingSha:'e'.repeat(40),marker};}
function prepared(){const p={target:target(),accountLogin:'owner',branch:'testing',sourceSha:'1'.repeat(40),sourceTree:'2'.repeat(40),savedConfigSha256:'3'.repeat(64),
  workflowId:'51',callerSha256:'4'.repeat(64),authority:{projectId:'c'.repeat(32),repository:'owner/app',repositoryId:'22',ledgerId:UUID,genesisSha256:'5'.repeat(64),protectedBranch:true},
  checkpoint:{sequence:1,headSha256:'6'.repeat(64),commit:'7'.repeat(40)},ledgerBlob:'8'.repeat(40),journalBlob:'9'.repeat(40),journalSha256:'a'.repeat(64),journalRevision:2,
  candidate:{candidateId:UUID,attemptId:ATTEMPT,requestSha256:'b'.repeat(64),localProjectId:'c'.repeat(32),platform:'android',
    source:{commit:'d'.repeat(40),tree:'e'.repeat(40),ref:'refs/heads/testing',configurationSha256:'f'.repeat(64),versionSha256:'1'.repeat(64)},
    identityRevision:'2'.repeat(64),baseVersion:{name:'1.2.3',build:7},capsuleSha256:'3'.repeat(64)}};
  return {...p,confirmation:playCleanupConfirmation(p)};}
function idle(revision=1){return {schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,pending:[],observed:null,acknowledged:false,agentAccess:null};}
function operation(kind,phase,revision,reason='none',effect=kind==='dispatch'?'not-sent':'none',t=target()){
  return {...idle(revision),available:phase==='settled',reason:phase==='settled'?'none':phase==='cleanup-unknown'?'cleanup-unknown':'busy',
    operation:{id:`${kind}-a`,projectId:'project-a',kind,target:t,phase,reason,effect}};}
function review(revision=3){return {...operation('prepare','settled',revision),consent:{id:consentId,expiresAt:'2026-10-21T12:02:00Z',prepared:prepared(),agentAllowed:false}};}
function allowed(revision=4,remainingMs=119000){const s=review(revision);s.consent.agentAllowed=true;
  s.agentAccess={serviceInstance:'d'.repeat(32),projectId:'e'.repeat(32),consentId,enabled:remainingMs>0,remainingMs};return s;}
function acknowledged(revision=6,kind='dispatch'){return {...operation(kind,'settled',revision,'none','acknowledged-unconfirmed'),acknowledged:true};}
function pending(revision=8,ack=false){return {...operation('pending','settled',revision),pending:[{prepared:prepared(),claimed:true,acknowledged:ack}]};}
function observed(revision=10,tuple='not-present'){return {...operation('observe','settled',revision,'none','observed-unconfirmed'),pending:pending().pending,
  observed:{counterCommit:'1'.repeat(40),journalSha256:'2'.repeat(64),journalRevision:3,pendingTuple:tuple,assurance:'later-journal-read-not-cleanup-proof'}};}
function closed(revision=5){return operation('prepare','settled',revision);}
function deferred(){let yes,no;const d={ended:false};d.promise=new Promise((resolve,reject)=>{yes=resolve;no=reject;});d.resolve=v=>{d.ended=true;yes(v);};d.reject=e=>{d.ended=true;no(e);};return d;}
async function flush(){for(let i=0;i<22;i++)await Promise.resolve();}
const harnesses=[];
function harness(){let current=idle(),view=connection(),w=workspace(),listener=null,peer=null,detached=0,now=AT;
  const calls=[],h={deferredStatus:false,unlistenThrows:false};
  const request=(kind,args)=>{const d=deferred();Object.assign(d,{kind,args:copy(args)});calls.push(d);return d.promise;};
  const port={mode:'native',subscribe:async f=>{listener=f;return()=>{if(h.unlistenThrows)throw Error('INERT');listener=null;detached++;};},
    status:()=>{if(h.deferredStatus)return request('status',{});calls.push({kind:'status',ended:true});return Promise.resolve(copy(current));}};
  for(const kind of ['prepare','start','pending','observe','allowAgent','discard','cancel'])port[kind]=a=>request(kind,a);
  const controller=new GitHubPlayCleanupController(()=>view,()=>w.projects[w.selectedId]??null,()=>typeof peer==='function'?peer():peer,()=>now);
  Object.assign(h,{port,controller,calls,count:k=>calls.filter(c=>c.kind===k).length,last:k=>calls.filter(c=>c.kind===k).at(-1),
    emit(s){current=copy(s);listener?.(copy(s));},rawEmit(s){listener?.(s);},retain(s){current=copy(s);},
    respond(k,s){current=copy(s);this.last(k).resolve(copy(s));},context(v){view=v;controller.syncContext();},peer(v){peer=v;},
    currentConnection:()=>view,project:()=>w.projects[w.selectedId],time(v){now=v;},replaceProject(v){w={...w,projects:{...w.projects,[w.selectedId]:v}};controller.syncContext();},
    edit(a){controller.beforeWorkspaceAction();w=workspaceReducer(w,{projectId:'project-a',...a});controller.syncContext();}});
  Object.defineProperties(h,{state:{get:()=>controller.getSnapshot()},detached:{get:()=>detached}});harnesses.push(h);return h;}
async function attached(){const h=harness();h.controller.connect(h.port);await flush();return h;}
async function ready(){const h=await attached();h.controller.prepare();h.respond('prepare',review());await flush();assert.ok(h.controller.currentConsent());return h;}
test.afterEach(async()=>{for(const h of harnesses.splice(0)){h.controller.dispose();for(let n=0;n<4;n++){for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();}
  assert.ok(h.calls.every(c=>c.ended),'every fake original invocation returned or rejected');}});

test('closed DATA preserves candidate, counter, acknowledgement and later observation as separate facts',()=>{
  for(const s of [idle(),review(),allowed(),pending(),acknowledged(),observed(),observed(10,'same-claimed'),
    operation('dispatch','cleanup-unknown',5,'cleanup-unknown','potentially-applied'),
    {...acknowledged(10,'observe'),operation:{...acknowledged(10,'observe').operation,reason:'cancelled'}}])assert.ok(parsePlayCleanupStatus(s));
  assert.match(prepared().confirmation,/does not reserve a version or build, sign or release/);
  assert.match(prepared().confirmation,/mutable/);assert.match(prepared().confirmation,/does not prove cleanup or identify a run/);
  for(const change of [s=>delete s.agentAccess,s=>s.done=true,s=>s.consent.prepared.confirmation+='changed',s=>s.consent.prepared.candidate.editId='INERT',
    s=>s.consent.prepared.candidate.platform='ios',s=>s.consent.prepared.candidate.baseVersion.build=0,s=>s.consent.prepared.candidate.localProjectId='c'.repeat(31)+'\n',
    s=>s.consent.prepared.accountLogin='owner\n',s=>s.consent.prepared.branch='../main',s=>s.consent.prepared.candidate.source.ref='refs/heads/main',
    s=>s.consent.prepared.authority.repositoryId='99',s=>s.consent.prepared.authority.protectedBranch=false,
    s=>s.consent.prepared.checkpoint.sequence=0,s=>s.consent.prepared.journalRevision=Number.MAX_SAFE_INTEGER+1,
    s=>s.consent.prepared.target.toolingRepository='other/tool',s=>s.consent.prepared.candidate.attemptId=UUID.replace('4111','1111')]){
    const s=review();change(s);assert.equal(parsePlayCleanupStatus(s),null);}
  for(const change of [s=>s.consent.agentAllowed=false,s=>s.agentAccess=null,s=>s.agentAccess.consentId='f'.repeat(32),s=>s.agentAccess.projectId='project-a',
    s=>s.agentAccess.remainingMs=120001,s=>s.agentAccess.enabled=false,s=>s.agentAccess.token='INERT']){const s=allowed();change(s);assert.equal(parsePlayCleanupStatus(s),null);}
  for(const change of [s=>s.acknowledged=false,s=>s.operation.phase='running',s=>s.operation.kind='prepare']){const s=acknowledged();change(s);assert.equal(parsePlayCleanupStatus(s),null);}
  const bad=observed();bad.observed.assurance='cleanup-complete';assert.equal(parsePlayCleanupStatus(bad),null);
  const duplicate=pending();duplicate.pending.push(copy(duplicate.pending[0]));assert.equal(parsePlayCleanupStatus(duplicate),null);
  let getters=0;const getter=idle();Object.defineProperty(getter,'consent',{enumerable:true,get(){getters++;return null;}});assert.equal(parsePlayCleanupStatus(getter),null);assert.equal(getters,0);
  assert.equal(parsePlayCleanupStatus({...idle(),diagnostic:'x'.repeat(192*1024)}),null);
});

test('native adapter has only eight bounded RAW commands and no renderer candidate, edit ID or target inputs',async()=>{
  const calls=[],events=[],port=createGitHubPlayCleanupPort('native',async(n,b)=>{calls.push([n,b]);return idle();},async n=>{events.push(n);return()=>{};});
  const base={sessionId:'session-a',expectedRevision:1},start={...base,consentId,confirm:true};
  await port.status();await port.prepare({...base,expectedConnectionRevision:12});await port.start(start);await port.pending({...base,expectedConnectionRevision:12});
  await port.observe({...base,marker});await port.allowAgent(start);await port.discard({...base,consentId});await port.cancel({operationId:'dispatch-a'});await port.subscribe(()=>{});
  assert.deepEqual(calls.map(c=>c[0]),['status','prepare','start','pending','observe','allow_agent','discard','cancel'].map(v=>`github_play_cleanup_${v}`));
  assert.deepEqual(events,[PLAY_CLEANUP_EVENT]);for(const[,b]of calls){assert.ok(b instanceof Uint8Array);assert.ok(b.length<=1024);}
  for(const field of ['candidateId','editId','capsule','token','root','url','repository','branch','accountId','serviceInstance','marker','force'])
    assert.equal(encodePlayCleanupRequest('github_play_cleanup_prepare',{...base,expectedConnectionRevision:12,[field]:'INERT'}),null);
  for(const name of ['start','allow_agent'])assert.equal(encodePlayCleanupRequest(`github_play_cleanup_${name}`,{...start,confirm:false}),null);
  for(const name of ['run','retry','delete','release','reconcile'])assert.equal(encodePlayCleanupRequest(`github_play_cleanup_${name}`,{}),null);
  assert.equal(createGitHubPlayCleanupPort('preview',()=>assert.fail(),null),null);assert.equal(createGitHubPlayCleanupPort('native',()=>assert.fail(),null),null);
  let callsGetter=0;assert.equal(playCleanupError({get code(){callsGetter++;return 'github_play_cleanup_refused_busy';}}).notAdmitted,false);assert.equal(callsGetter,0);
});

test('actual composed bridge installs the closed native event/port only; preview gets no cleanup writer',async()=>{
  const calls=[],events=[],api=createNativeApi('native',async(n,b)=>{calls.push([n,b]);return idle();},async n=>{events.push(n);return()=>{};});
  assert.ok(api.githubPlayCleanup);await api.githubPlayCleanup.prepare({sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12});await api.githubPlayCleanup.subscribe(()=>{});
  assert.equal(calls[0][0],'github_play_cleanup_prepare');assert.ok(calls[0][1] instanceof Uint8Array);assert.deepEqual(events,[PLAY_CLEANUP_EVENT]);
  assert.equal(previewApi.githubPlayCleanup,undefined);assert.equal(createNativeApi('native',()=>assert.fail(),null).githubPlayCleanup,null);
});

test('mount and Check do not prepare, load history, delegate or send; dirty/stale saved source refuses',async()=>{
  const h=await attached();h.controller.checkStatus();await flush();assert.equal(h.count('status'),2);
  for(const k of ['prepare','pending','observe','allowAgent','start'])assert.equal(h.count(k),0);
  h.edit({type:'edit',path:'android.enabled',value:false});h.controller.prepare();assert.equal(h.count('prepare'),0);assert.match(h.controller.prepareReason(),/save.*Settings/i);
  h.edit({type:'config-save-intent'});h.controller.prepare();assert.equal(h.count('prepare'),0);assert.match(h.controller.prepareReason(),/current saved project/);
  const g=await attached();g.peer('Original build still active');g.controller.prepare();assert.equal(g.count('prepare'),0);
  g.peer(null);g.emit({...idle(2),available:false,reason:'unqualified'});g.controller.prepare();assert.equal(g.count('prepare'),0);
});

test('only joined original Prepare grants separate unchecked cleanup consent, not a terminal event',async()=>{
  const h=await attached();h.controller.prepare();assert.deepEqual(h.last('prepare').args,{sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12});
  h.emit(review());assert.equal(h.state.pending,true);assert.equal(h.controller.currentConsent(),null);
  h.controller.setConfirmed(true);h.controller.dispatch();h.controller.allowAgent();assert.equal(h.count('start'),0);assert.equal(h.count('allowAgent'),0);
  h.respond('prepare',operation('prepare','running',2));await flush();assert.ok(h.controller.currentConsent());assert.equal(h.state.confirmed,false);
  h.controller.dispatch();assert.equal(h.count('start'),0);h.controller.setConfirmed(true);h.controller.dispatch();h.controller.dispatch();assert.equal(h.count('start'),1);
  assert.deepEqual(h.last('start').args,{sessionId:'session-a',expectedRevision:3,consentId,confirm:true});assert.equal(h.state.confirmed,false);
  h.respond('start',acknowledged());await flush();assert.equal(h.state.pending,false);assert.equal(h.state.status.acknowledged,true);assert.equal(h.state.status.observed,null);
  assert.equal(h.state.status.operation.effect,'acknowledged-unconfirmed');assert.equal(h.count('observe'),0);assert.equal(h.count('pending'),0);
});

test('cold or historical consent cannot become a new GUI approval or fabricated agent handoff',async()=>{
  for(const s of [review(),allowed()]){const h=harness();h.retain(s);h.controller.connect(h.port);await flush();
    assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.currentAgentAccess(),null);h.controller.setConfirmed(true);h.controller.dispatch();h.controller.allowAgent();
    assert.equal(h.count('start'),0);assert.equal(h.count('allowAgent'),0);assert.equal(h.controller.canDiscard(),true);}
});

test('Allow is explicit one-use delegation, joined before handoff; GUI Start cannot reuse it',async()=>{
  const h=await ready();h.controller.allowAgent();assert.equal(h.count('allowAgent'),0);h.controller.setConfirmed(true);h.controller.allowAgent();
  assert.equal(h.count('allowAgent'),1);h.emit(allowed());assert.equal(h.controller.currentAgentAccess(),null);assert.equal(h.state.allowing,true);
  h.controller.dispatch();h.controller.allowAgent();assert.equal(h.count('start'),0);assert.equal(h.count('allowAgent'),1);
  h.respond('allowAgent',allowed());await flush();assert.deepEqual(copy(h.controller.currentAgentAccess()),allowed().agentAccess);
  assert.equal(h.controller.currentConsent(),null);h.controller.setConfirmed(true);h.controller.dispatch();assert.equal(h.count('start'),0);
  h.controller.discardReview();assert.deepEqual(h.last('discard').args,{sessionId:'session-a',expectedRevision:4,consentId});h.respond('discard',closed());await flush();
  assert.equal(h.controller.currentAgentAccess(),null);assert.equal(h.controller.ownerReason(),null);assert.equal(h.count('prepare'),1);
});

test('CLI may consume before Allow invoke returns; old returned snapshot never restores permission',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.emit(allowed());
  h.emit(operation('dispatch','running',5,'none','potentially-applied'));assert.equal(h.state.allowing,true);
  h.last('allowAgent').resolve(allowed());await flush();assert.equal(h.state.uncertain,false);assert.equal(h.state.allowing,false);
  assert.equal(h.state.status.operation.kind,'dispatch');assert.equal(h.state.status.consent,null);assert.equal(h.controller.currentAgentAccess(),null);
  assert.ok(h.controller.ownerReason());h.controller.cancel();assert.deepEqual(h.last('cancel').args,{operationId:'dispatch-a'});
  h.respond('cancel',acknowledged(7));await flush();assert.equal(h.count('start'),0);
});

test('same-revision cleanup countdown decreases on event and Check, but delayed reads never renew it',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.respond('allowAgent',allowed());await flush();
  h.emit(allowed(4,118000));assert.equal(h.state.uncertain,false);assert.equal(h.controller.currentAgentAccess()?.remainingMs,118000);
  h.deferredStatus=true;h.controller.checkStatus();const older=h.last('status');
  h.emit(allowed(4,117000));assert.equal(h.controller.currentAgentAccess(),null,'original Check still awaits its own return');
  older.resolve(allowed(4,118000));await flush();assert.equal(h.state.uncertain,false);assert.equal(h.controller.currentAgentAccess()?.remainingMs,117000);
  h.controller.checkStatus();h.respond('status',allowed(4,116000));await flush();
  assert.equal(h.state.status.revision,4);assert.equal(h.controller.currentAgentAccess()?.remainingMs,116000);
  h.emit(allowed(4,119000));assert.equal(h.controller.currentAgentAccess()?.remainingMs,116000);
  assert.equal(h.count('allowAgent'),1);assert.equal(h.count('start'),0);assert.equal(h.state.uncertain,false);
});

test('same-revision cleanup Allow snapshot arrives after a lower countdown event without renewal',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.emit(allowed(4,117000));
  assert.equal(h.state.allowing,true);assert.equal(h.controller.currentAgentAccess(),null);
  h.last('allowAgent').resolve(allowed(4,119000));await flush();
  assert.equal(h.state.allowing,false);assert.equal(h.state.uncertain,false);assert.equal(h.controller.currentAgentAccess()?.remainingMs,117000);
  assert.equal(h.state.status.consent.expiresAt,review().consent.expiresAt);assert.equal(h.controller.currentConsent(),null);
  h.time(AT+120000);assert.equal(h.controller.currentAgentAccess(),null,'original absolute review expiry remains final');
  assert.equal(h.count('allowAgent'),1);assert.equal(h.count('start'),0);
});

test('same-revision cleanup changes other than countdown remain contradictory and Unknown stays absorbing',async()=>{
  for(const change of [s=>s.agentAccess.serviceInstance='f'.repeat(32),s=>s.agentAccess.projectId='f'.repeat(32),
    s=>{s.consent.id='f'.repeat(32);s.agentAccess.consentId=s.consent.id;},s=>{s.agentAccess.enabled=false;s.agentAccess.remainingMs=0;},
    s=>s.consent.expiresAt='2026-10-21T12:03:00Z',s=>{s.available=false;s.reason='busy';}]){
    const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.respond('allowAgent',allowed());await flush();
    const altered=allowed(4,118000);change(altered);assert.ok(parsePlayCleanupStatus(altered),'the closed DATA shape alone is valid');
    h.emit(altered);assert.equal(h.state.uncertain,true);assert.equal(h.controller.currentAgentAccess(),null);
    h.emit(allowed(4,117000));assert.equal(h.state.uncertain,true);assert.equal(h.controller.currentAgentAccess(),null);
    assert.equal(h.count('allowAgent'),1);assert.equal(h.count('start'),0);
  }
});

test('expiry is original and unrenewed by Check, remaining-time update or local approval',async()=>{
  const h=await ready();h.time(AT+120000);h.controller.setConfirmed(true);h.controller.dispatch();h.controller.allowAgent();assert.equal(h.count('start'),0);assert.equal(h.count('allowAgent'),0);
  h.controller.checkStatus();await flush();assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.canDiscard(),true);
  const g=await ready();g.controller.setConfirmed(true);g.controller.allowAgent();g.respond('allowAgent',allowed());await flush();
  g.emit(allowed(5,100000));assert.ok(g.controller.currentAgentAccess());g.time(AT+120001);assert.equal(g.controller.currentAgentAccess(),null);
  g.emit(allowed(6,110000));assert.equal(g.state.uncertain,true,'same grant countdown may not increase');
});

test('reentrant source/account/API/approval/expiry changes veto both Start and Allow before invoke',async()=>{
  for(const action of ['dispatch','allowAgent'])for(const change of ['project','same-bytes-source','saved-intent','account','api','aba','peer','revision','approval','expiry','close','unknown']){
    const h=await ready();h.controller.setConfirmed(true);let used=false;const off=h.controller.subscribe(()=>{if(used||!h.state.pending&&!h.state.allowing)return;used=true;
      if(change==='project'){const v=connection();v.context.projectId='project-b';h.context(v);}
      if(change==='same-bytes-source')h.replaceProject(copy(h.project()));if(change==='saved-intent')h.edit({type:'config-save-intent'});
      if(change==='account'){const v=connection();v.status.account.value.id='99';h.context(v);}if(change==='api')h.controller.connect(null);
      if(change==='aba'){h.context({...connection(),context:null});h.context(connection());}if(change==='peer')h.peer('Different original');
      if(change==='revision')h.currentConnection().status.revision++;if(change==='approval')h.controller.setConfirmed(false);if(change==='expiry')h.time(AT+120000);
      if(change==='close')action==='allowAgent'?h.controller.discardReview():h.controller.cancel();if(change==='unknown')h.emit({malformed:true});});
    h.controller[action]();off();assert.equal(h.count(action==='dispatch'?'start':'allowAgent'),0,`${action}/${change}`);
  }
});

test('reentrant Prepare publication and peer callback cannot select another saved source',async()=>{
  for(const viaPeer of [false,true]){const h=await attached();let used=false;
    const change=()=>{if(!used&&h.state.pending){used=true;h.replaceProject(copy(h.project()));}return null;};
    const off=viaPeer?()=>{}:h.controller.subscribe(change);if(viaPeer)h.peer(change);h.controller.prepare();off();assert.equal(h.count('prepare'),0);}
});

test('lost Allow retains unknown but can withdraw exactly its original consent after a fresh Check',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.last('allowAgent').reject(Error('INERT transport loss'));await flush();
  assert.equal(h.state.uncertain,true);assert.equal(h.state.allowing,true);assert.equal(h.controller.currentAgentAccess(),null);
  h.retain(allowed());h.controller.checkStatus();await flush();assert.equal(h.state.uncertain,true);assert.equal(h.state.status.revision,3);
  h.controller.discardReview();assert.deepEqual(h.last('discard').args,{sessionId:'session-a',expectedRevision:4,consentId});
  h.respond('discard',closed());await flush();assert.equal(h.state.uncertain,true);assert.equal(h.controller.canDiscard(),false);
  h.controller.connect(null);assert.equal(h.detached,0);h.controller.prepare();h.controller.allowAgent();h.controller.dispatch();assert.equal(h.count('allowAgent'),1);assert.equal(h.count('start'),0);
});

test('lost Allow learns only matching Dispatch Stop identity; no later success or foreign target clears unknown',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.last('allowAgent').reject(Error('INERT'));await flush();
  const foreign=operation('dispatch','running',5,'none','potentially-applied');foreign.operation.target.scope.accountId='99';h.emit(foreign);assert.equal(h.controller.canCancel(),false);
  h.emit(operation('dispatch','running',6,'none','potentially-applied'));assert.equal(h.controller.canCancel(),true);
  h.controller.cancel();assert.deepEqual(h.last('cancel').args,{operationId:'dispatch-a'});h.respond('cancel',acknowledged(7));await flush();assert.equal(h.state.uncertain,true);
  assert.equal(h.state.status.acknowledged,false);assert.equal(h.count('start'),0);
});

test('known stale refusal is not lost Start, but it never restores consumed review or auto-retries',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.dispatch();h.last('start').reject({code:'github_play_cleanup_refused_target_changed'});await flush();
  assert.equal(h.state.uncertain,false);assert.equal(h.state.pending,false);assert.equal(h.controller.currentConsent(),null);assert.match(h.controller.dispatchReason(),/Check/);
  h.retain(closed(4));h.controller.checkStatus();await flush();h.controller.dispatch();assert.equal(h.count('start'),1);assert.equal(h.count('prepare'),1);
  const g=await ready();g.controller.setConfirmed(true);g.controller.dispatch();g.last('start').reject({code:'unrecognized'});await flush();
  assert.equal(g.state.uncertain,true);g.emit(acknowledged());g.controller.dispatch();assert.equal(g.count('start'),1);assert.equal(g.state.status.acknowledged,false);
});

test('synchronous throw or missing Promise after entering a command remains uncertain even with typed code',async()=>{
  for(const action of ['prepare','dispatch','allowAgent'])for(const how of ['throw','nonpromise']){const h=action==='prepare'?await attached():await ready();
    const portMethod=action==='dispatch'?'start':action;let called=0;h.port[portMethod]=()=>{called++;if(how==='throw')throw {code:'github_play_cleanup_refused_busy'};return idle();};
    h.controller.setConfirmed(true);h.controller[action]();assert.equal(called,1);assert.equal(h.state.uncertain,true,`${action}/${how}`);
    h.controller[action]();assert.equal(called,1);}
});

test('known expired Close waits a new Check; older poll/events cannot reopen it, lost Close remains unknown',async()=>{
  const h=await ready();h.deferredStatus=true;h.controller.checkStatus();const old=h.last('status');h.controller.discardReview();
  h.last('discard').reject({code:'github_play_cleanup_refused_consent_expired'});await flush();assert.equal(h.controller.canDiscard(),false);
  old.resolve(review());await flush();h.emit(review());assert.equal(h.controller.canDiscard(),false);
  h.controller.checkStatus();h.respond('status',closed(4));await flush();assert.equal(h.controller.ownerReason(),null);assert.equal(h.count('discard'),1);
  const g=await ready();g.controller.discardReview();g.last('discard').reject(Error('INERT'));await flush();g.emit(closed());assert.equal(g.state.uncertain,true);assert.ok(g.controller.ownerReason());
});

test('known refused withdrawal after lost Allow can use a later exact Check, never a foreign consent',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.last('allowAgent').reject(Error('INERT'));await flush();h.controller.discardReview();
  h.last('discard').reject({code:'github_play_cleanup_refused_consent_expired'});await flush();assert.equal(h.controller.canDiscard(),false);
  const foreign=allowed(4);foreign.consent.id='f'.repeat(32);foreign.agentAccess.consentId=foreign.consent.id;h.retain(foreign);h.controller.checkStatus();await flush();assert.equal(h.controller.canDiscard(),false);
  h.retain(allowed(5));h.controller.checkStatus();await flush();assert.equal(h.controller.canDiscard(),true);h.controller.discardReview();
  assert.equal(h.last('discard').args.consentId,consentId);assert.equal(h.last('discard').args.expectedRevision,5);assert.equal(h.state.uncertain,true);
});

test('Status and Stop actual invocations retain port/listener after terminal event and navigation',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.dispatch();h.emit(operation('dispatch','running',4,'none','potentially-applied'));
  h.deferredStatus=true;h.controller.checkStatus();const read=h.last('status');h.controller.cancel();const stop=h.last('cancel');
  h.controller.connect(null);h.emit(acknowledged(6));h.last('start').resolve(acknowledged(6));await flush();assert.equal(h.state.pending,false);assert.ok(h.controller.ownerReason());assert.equal(h.detached,0);
  read.resolve(acknowledged(6));await flush();assert.equal(h.detached,0);stop.resolve(acknowledged(6));await flush();assert.equal(h.detached,1);
});

test('Allow and Close invocations survive early withdrawal and dispose until each actual return',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();const allow=h.last('allowAgent');h.emit(allowed());
  h.controller.discardReview();const close=h.last('discard');h.emit(closed());h.controller.dispose();assert.equal(h.detached,0);
  allow.resolve(allowed());await flush();assert.equal(h.detached,0);close.resolve(closed());await flush();assert.equal(h.detached,1);assert.equal(h.count('start'),0);
});

test('unknown cleanup and contradictory terminal DATA are absorbing and preserve exact original Stop',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.dispatch();h.emit(operation('dispatch','cleanup-unknown',5,'cleanup-unknown','potentially-applied'));
  h.last('start').resolve(acknowledged(6));await flush();assert.equal(h.state.uncertain,true);assert.equal(h.state.status.operation.phase,'cleanup-unknown');h.controller.cancel();assert.equal(h.last('cancel').args.operationId,'dispatch-a');
  const g=await ready();const changed=review(4);changed.consent.prepared.accountLogin='other';g.emit(changed);assert.equal(g.state.uncertain,true);
});

test('history is explicit and exact returned-row bound; later journal absence never becomes cleanup proof or retry',async()=>{
  const h=await attached();h.controller.loadPending();assert.equal(h.count('prepare'),0);assert.equal(h.count('observe'),0);h.respond('pending',pending());await flush();
  const row=h.state.status.pending[0];h.controller.observe(copy(row));assert.equal(h.count('observe'),0,'copied/old row cannot select a current replacement');
  h.controller.observe(row);assert.deepEqual(h.last('observe').args,{sessionId:'session-a',expectedRevision:8,marker});h.respond('observe',observed());await flush();
  assert.equal(h.state.status.operation.effect,'observed-unconfirmed');assert.equal(h.state.status.acknowledged,false);assert.equal(h.controller.currentConsent(),null);
  assert.equal(h.count('start'),0);assert.equal(h.count('prepare'),0);assert.equal(h.count('allowAgent'),0);assert.equal(h.count('pending'),1);
});

test('history row replacement or context drift during synchronous admission blocks Observe before invoke',async()=>{
  for(const cause of ['row','project','source']){const h=await attached();h.controller.loadPending();h.respond('pending',pending());await flush();const row=h.state.status.pending[0];let used=false;
    const off=h.controller.subscribe(()=>{if(used||!h.state.pending)return;used=true;if(cause==='row')h.emit(pending(9));
      if(cause==='project')h.context({...connection(),context:null});if(cause==='source')h.replaceProject(copy(h.project()));});
    h.controller.observe(row);off();assert.equal(h.count('observe'),0,cause);}
});

test('delegated handoff is withdrawn by source/connection ABA; status alone cannot remint approval',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.allowAgent();h.respond('allowAgent',allowed());await flush();assert.ok(h.controller.currentAgentAccess());
  h.context({...connection(),context:null});h.context(connection());h.controller.checkStatus();await flush();assert.equal(h.controller.currentAgentAccess(),null);
  assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.canDiscard(),true);h.controller.setConfirmed(true);h.controller.dispatch();assert.equal(h.count('start'),0);
});

test('listener teardown failure does not silently reconnect a fresh native port',async()=>{
  const h=await attached();h.unlistenThrows=true;h.controller.connect(null);assert.equal(h.state.uncertain,true);h.controller.connect({...h.port});
  assert.equal(h.count('status'),1);assert.ok(h.controller.ownerReason());
});

// Reuse these inert original fixtures for the typed future-tag facet.
export { attached,harness,review,allowed,prepared,target,idle,operation,pending,flush };
