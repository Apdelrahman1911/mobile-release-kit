// Inert complete-module DATA and deferred original IPC. No HTTP, jobs, tokens,
// native service, journal files or workflow execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubActionsRetryController } from '../src/githubActionsRetryController.ts';
import { createGitHubActionsRetryPort, encodeActionsRetryRequest, parseActionsRetryStatus,
  actionsRetryConfirmation, actionsRetryError, ACTIONS_RETRY_EVENT } from '../src/githubActionsRetryProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const copy=structuredClone,marker='a'.repeat(32),consentId='b'.repeat(32);
function connection(){return {mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'owner/app'},
  status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'owner/app',state:'connected'},
    account:{state:'observed',value:{id:'11',login:'owner'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app'}}},
  busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false,error:null};}
function target(selection=true,attempt=2){return {scope:{projectBinding:'d'.repeat(64),repository:'owner/app',accountId:'11',repositoryId:'22'},
  selection:selection?{runId:'31',attempt,headSha:'2'.repeat(40),marker}:null};}
function run(attempt=2){return {id:'31',attempt,name:'Release checks',workflowId:'51',workflowPath:'.github/workflows/checks.yml',status:'completed',conclusion:'failure',
  headSha:'2'.repeat(40),headBranch:'testing',headRepository:'owner/app',headRepositoryId:'22',event:'push',createdAt:'2026-10-20T20:00:00Z',updatedAt:'2026-10-20T20:01:00Z'};}
function prepared(attempt=2){const t=target(true,attempt),r=run(attempt);return {target:t,accountLogin:'owner',run:r,retryPermission:'not-proven',confirmation:actionsRetryConfirmation(t,r)};}
function activity(attempt=2){const {workflowId,workflowPath,headRepositoryId,...r}=run(attempt);return {revision:19,observation:{target:target().scope,observedAt:'2026-10-20T20:01:00Z',selection:{kind:'workflow-run',runId:r.id,attempt},
  data:{kind:'workflow-run',attemptChecked:true,run:r,jobs:{state:'read',reason:'none',coverage:'complete',total:1,rows:[{id:'71',name:'Unit checks',status:'completed',conclusion:'failure'}]}}}};}
function idle(revision=1){return {schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,pending:[],observed:null,acknowledged:false};}
function operation(kind,phase,revision,reason='none',effect=kind==='retry'?'not-sent':'none',t=target(kind!=='pending')){
  return {...idle(revision),available:phase==='settled',reason:phase==='settled'?'none':phase==='cleanup-unknown'?'cleanup-unknown':'busy',
    operation:{id:`${kind}-a`,projectId:'project-a',kind,target:t,phase,reason,effect}};
}
function review(revision=3){return {...operation('prepare','settled',revision),consent:{id:consentId,expiresAt:'2026-10-20T20:03:00Z',prepared:prepared()}};}
function accepted(revision=5,kind='retry'){return {...operation(kind,'settled',revision,'none','accepted'),acknowledged:true,observed:{...run(3),status:'queued',conclusion:null}};}
function pending(revision=7,acknowledged=false){return {...operation('pending','settled',revision),pending:[{prepared:prepared(),claimed:true,acknowledged}]};}
function deferred(){let yes,no;const d={ended:false};d.promise=new Promise((resolve,reject)=>{yes=resolve;no=reject;});d.resolve=v=>{d.ended=true;yes(v);};d.reject=e=>{d.ended=true;no(e);};return d;}
async function flush(){for(let i=0;i<18;i++)await Promise.resolve();}
const harnesses=[];
function harness(){let current=idle(),view=connection(),picked=activity(),listener=null,peer=null,detached=0;
  const calls=[],h={deferredStatus:false,unlistenThrows:false};
  const request=(kind,args)=>{const d=deferred();Object.assign(d,{kind,args:copy(args)});calls.push(d);return d.promise;};
  const port={mode:'native',subscribe:async f=>{listener=f;return ()=>{if(h.unlistenThrows)throw Error('INERT');listener=null;detached++;};},
    status:()=>{if(h.deferredStatus)return request('status',{});calls.push({kind:'status',ended:true});return Promise.resolve(copy(current));}};
  for(const kind of ['prepare','start','pending','reconcile','discard','cancel'])port[kind]=args=>request(kind,args);
  const controller=new GitHubActionsRetryController(()=>view,()=>picked,()=>typeof peer==='function'?peer():peer);
  Object.assign(h,{port,controller,calls,count:k=>calls.filter(c=>c.kind===k).length,last:k=>calls.filter(c=>c.kind===k).at(-1),
    emit(s){current=copy(s);listener?.(copy(s));},rawEmit(s){listener?.(s);},retain(s){current=copy(s);},activity(v){picked=v;},
    respond(k,s){current=copy(s);this.last(k).resolve(copy(s));},context(v){view=v;controller.syncContext();},peer(v){peer=v;},currentConnection:()=>view});
  Object.defineProperties(h,{state:{get:()=>controller.getSnapshot()},detached:{get:()=>detached}});harnesses.push(h);return h;
}
async function attached(){const h=harness();h.controller.connect(h.port);await flush();return h;}
async function ready(){const h=await attached();h.controller.prepare();h.respond('prepare',review());await flush();assert.ok(h.controller.currentConsent());return h;}
test.afterEach(async()=>{for(const h of harnesses.splice(0)){for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();h.controller.dispose();for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();}});

test('closed status distinguishes accepted request, latest attempt and unknown attribution without a CAS claim',()=>{
  const advanced={...operation('reconcile','settled',9,'unattributed','advanced-unattributed'),observed:run(3)};
  const unconfirmed={...operation('retry','settled',5,'network-unavailable','accepted-unconfirmed'),acknowledged:true};
  for(const s of [idle(),review(),accepted(),pending(),advanced,unconfirmed,operation('retry','cleanup-unknown',5,'cleanup-unknown','potentially-applied')])assert.ok(parseActionsRetryStatus(s));
  assert.match(prepared().confirmation,/dependent jobs/);assert.match(prepared().confirmation,/latest attempt/);assert.match(prepared().confirmation,/publish or change external services/);
  for(const change of [s=>s.consent.prepared.retryPermission='granted',s=>s.consent.prepared.confirmation+='wrong',s=>s.consent.prepared.run.workflowId='',s=>s.consent.prepared.target.selection.headSha='0'.repeat(40),
    s=>s.consent.prepared.run.headRepositoryId='23',s=>s.consent.prepared.run.conclusion='success',s=>s.consent.prepared.run.logs='INERT']){const s=review();change(s);assert.equal(parseActionsRetryStatus(s),null);}
  for(const change of [s=>s.acknowledged=false,s=>s.observed=null,s=>s.observed.id='32',s=>s.observed.headSha='0'.repeat(40),s=>s.observed.attempt=1,s=>s.operation.phase='running']){const s=accepted();change(s);assert.equal(parseActionsRetryStatus(s),null);}
  const p=pending();p.pending.push(copy(p.pending[0]));assert.equal(parseActionsRetryStatus(p),null);
  let gets=0;const raw=idle();Object.defineProperty(raw,'consent',{enumerable:true,get(){gets++;return null;}});assert.equal(parseActionsRetryStatus(raw),null);assert.equal(gets,0);
  assert.equal(parseActionsRetryStatus({...idle(),private:'x'.repeat(200*1024)}),null);
});

test('native adapter emits only seven bounded RAW commands; no URL, token, head, marker or path submission',async()=>{
  const calls=[],events=[],port=createGitHubActionsRetryPort('native',async(name,raw)=>{calls.push([name,raw]);return idle();},async name=>{events.push(name);return ()=>{};});
  const base={sessionId:'session-a',expectedRevision:1};
  await port.status();await port.prepare({...base,expectedConnectionRevision:12,activityRevision:19,runId:'31',attempt:2});await port.start({...base,consentId,confirm:true});
  await port.pending({...base,expectedConnectionRevision:12});await port.reconcile({...base,marker});await port.discard({...base,consentId});await port.cancel({operationId:'retry-a'});await port.subscribe(()=>{});
  assert.deepEqual(calls.map(c=>c[0]),['status','prepare','start','pending','reconcile','discard','cancel'].map(v=>`github_actions_retry_${v}`));assert.deepEqual(events,[ACTIONS_RETRY_EVENT]);
  for(const[,raw]of calls){assert.ok(raw instanceof Uint8Array);assert.ok(raw.length<=1024);}
  assert.equal(createGitHubActionsRetryPort('preview',()=>assert.fail(),null),null);assert.equal(createGitHubActionsRetryPort('native',()=>assert.fail(),null),null);
  for(const key of ['token','url','root','repository','accountId','headSha','marker','expectedProviderAttempt','force','debug'])assert.equal(encodeActionsRetryRequest('github_actions_retry_prepare',{...base,expectedConnectionRevision:12,activityRevision:19,runId:'31',attempt:2,[key]:'INERT'}),null);
  for(const attempt of [0,1001,1.5])assert.equal(encodeActionsRetryRequest('github_actions_retry_prepare',{...base,expectedConnectionRevision:12,activityRevision:19,runId:'31',attempt}),null);
  assert.equal(encodeActionsRetryRequest('github_actions_retry_start',{...base,consentId,confirm:false}),null);
  for(const suffix of ['dispatch','all','force','job','delete'])assert.equal(encodeActionsRetryRequest(`github_actions_retry_${suffix}`,{}),null);
  let gets=0;assert.equal(actionsRetryError({get code(){gets++;return 'github_actions_retry_refused_busy';}}).notAdmitted,false);assert.equal(gets,0);
  assert.deepEqual(actionsRetryError({code:'github_actions_retry_refused_target_changed'}),{reason:'target-changed',notAdmitted:true});
});

test('actual composed bridge installs only the native typed port and fixed event, not a preview writer',async()=>{
  const calls=[],events=[];const api=createNativeApi('native',async(name,raw)=>{calls.push([name,raw]);return idle();},async(name)=>{events.push(name);return ()=>{};});
  const port=api.githubActionsRetry;assert.ok(port);await port.status();await port.prepare({sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12,activityRevision:19,runId:'31',attempt:2});await port.subscribe(()=>{});
  assert.deepEqual(calls.map(v=>v[0]),['github_actions_retry_status','github_actions_retry_prepare']);assert.deepEqual(events,[ACTIONS_RETRY_EVENT]);assert.ok(calls[1][1] instanceof Uint8Array);
  assert.equal(previewApi.githubActionsRetry,undefined);assert.equal(createNativeApi('native',()=>assert.fail(),null).githubActionsRetry,null);
});

test('mount and status never prepare/retry; only actual selected failed attempt and account permit Review',async()=>{
  const h=await attached();assert.equal(h.count('status'),1);assert.equal(h.count('prepare'),0);h.controller.checkStatus();await flush();assert.equal(h.count('start'),0);
  for(const mutate of [a=>a.observation.selection.attempt++,a=>a.observation.data.run.conclusion='success',a=>a.observation.data.run.status='in_progress',a=>a.observation.target.repositoryId='88',a=>a.revision=0]){
    const a=activity();mutate(a);h.activity(a);h.controller.prepare();assert.equal(h.count('prepare'),0);
  }
  h.activity(activity());const c=connection();c.status.account={state:'unavailable',value:null};h.context(c);h.controller.prepare();assert.equal(h.count('prepare'),0);
  h.context(connection());h.peer('Original build pending');h.controller.prepare();assert.equal(h.count('prepare'),0);h.peer(null);h.controller.prepare();
  assert.deepEqual(h.last('prepare').args,{sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12,activityRevision:19,runId:'31',attempt:2});
});

test('own Prepare retirement of Activity is not a source change; separate exact confirmation remains one use',async()=>{
  const h=await attached();h.controller.prepare();h.activity(null);h.respond('prepare',review());await flush();assert.ok(h.controller.currentConsent());
  h.controller.retry();assert.equal(h.count('start'),0);h.controller.setConfirmed(true);h.controller.retry();h.controller.retry();assert.equal(h.count('start'),1);
  assert.deepEqual(h.last('start').args,{sessionId:'session-a',expectedRevision:3,consentId,confirm:true});assert.equal(h.state.confirmed,false);
  h.respond('start',accepted());await flush();assert.equal(h.state.pending,false);assert.equal(h.state.status.acknowledged,true);assert.equal(h.state.status.observed.attempt,3);assert.equal(h.currentConnection().status.revision,12);
});

test('terminal event cannot release original Start promise or grant review until its own reply settles',async()=>{
  const h=await attached();h.controller.prepare();h.emit(review());assert.equal(h.state.pending,true);assert.equal(h.controller.currentConsent(),null);
  h.controller.setConfirmed(true);h.controller.retry();assert.equal(h.count('start'),0);h.respond('prepare',operation('prepare','running',2));await flush();assert.ok(h.controller.currentConsent());assert.equal(h.state.status.revision,3);
});

test('reentrant original Activity replacement and revision change veto Review before native handoff',async()=>{
  for(const mode of ['same-bytes-new-observation','revision','selection','missing']){const h=await attached();let used=false;const off=h.controller.subscribe(()=>{if(used||!h.state.pending)return;used=true;
    const a=activity();if(mode==='revision')a.revision++;if(mode==='selection')a.observation.data.run.attempt++;h.activity(mode==='missing'?null:a);});
    h.controller.prepare();off();assert.equal(h.count('prepare'),0,mode);assert.equal(h.state.pending,false);}
});

test('reentrant project/API/ABA/peer/revision/approval/Stop cannot consume approval for a different original',async()=>{
  for(const change of ['project','api','aba','peer','revision','approval','stop','unknown']){const h=await ready();h.controller.setConfirmed(true);let used=false;const off=h.controller.subscribe(()=>{if(used||!h.state.pending)return;used=true;
    if(change==='project'){const c=connection();c.context.projectId='project-b';h.context(c);}if(change==='api')h.controller.connect(null);
    if(change==='aba'){h.context({...connection(),context:null});h.context(connection());}if(change==='peer')h.peer('Other original');if(change==='revision')h.currentConnection().status.revision++;
    if(change==='approval')h.controller.setConfirmed(false);if(change==='stop')h.controller.cancel();if(change==='unknown')h.emit({wrong:true});});
    h.controller.retry();off();assert.equal(h.count('start'),0,change);assert.equal(h.state.pending,false,change);}
});

test('early Stop retains original invocation, queues once on real ID and never accepts late approval',async()=>{
  const h=await attached();h.controller.prepare();h.controller.cancel();h.controller.beforeWorkspaceAction();assert.equal(h.count('cancel'),0);
  h.emit(operation('prepare','running',2));h.emit(operation('prepare','running',2));assert.equal(h.count('cancel'),1);
  h.respond('prepare',review());await flush();assert.equal(h.controller.currentConsent(),null);h.respond('cancel',review());await flush();h.controller.discardReview();h.respond('discard',operation('prepare','settled',4));await flush();
  assert.equal(h.controller.ownerReason(),null);assert.equal(h.count('start'),0);
});

test('only exact unmatched asynchronous not-admitted refusal releases entry, not lost/throw/thenable/after-event',async()=>{
  const h=await attached();h.controller.prepare();h.last('prepare').reject({code:'github_actions_retry_refused_target_changed'});await flush();assert.equal(h.state.pending,false);assert.equal(h.state.uncertain,false);assert.match(h.controller.prepareReason(),/Check/);
  for(const mode of ['lost','throw','thenable','matched-refusal']){const x=await ready();x.controller.setConfirmed(true);
    if(mode==='throw')x.port.start=()=>{throw {code:'github_actions_retry_refused_busy'};};if(mode==='thenable')x.port.start=()=>({then(){assert.fail('No assimilation');}});
    x.controller.retry();if(mode==='matched-refusal')x.emit(operation('retry','running',4,'none','potentially-applied'));
    if(mode==='lost'||mode==='matched-refusal')x.last('start').reject({code:mode==='lost'?'reply-lost':'github_actions_retry_refused_busy'});await flush();assert.equal(x.state.pending,true,mode);assert.equal(x.state.uncertain,true,mode);
    x.emit(accepted());assert.equal(x.state.pending,true);assert.ok(x.controller.retryReason());
  }
});

test('unknown POST remains fenced after read-only advancement; a 201 receipt is not invented',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.retry();h.respond('start',operation('retry','settled',5,'network-unavailable','potentially-applied'));await flush();
  assert.equal(h.state.pending,false);assert.ok(h.controller.prepareReason());h.controller.loadPending();h.respond('pending',pending());await flush();h.controller.reconcile('0'.repeat(32));assert.equal(h.count('reconcile'),0);
  h.controller.reconcile(marker);assert.deepEqual(h.last('reconcile').args,{sessionId:'session-a',expectedRevision:7,marker});
  h.respond('reconcile',{...operation('reconcile','settled',9,'unattributed','advanced-unattributed'),pending:pending().pending,observed:run(3)});await flush();
  h.activity(activity(3));assert.equal(h.state.status.acknowledged,false);assert.equal(h.state.error,'unattributed');assert.ok(h.controller.prepareReason());h.controller.prepare();assert.equal(h.count('prepare'),1);
});

test('acknowledged earlier attempt permits a genuinely newer explicit review, never replay of the same attempt',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.retry();h.respond('start',accepted());await flush();assert.ok(h.controller.prepareReason());
  h.activity(activity(3));assert.equal(h.controller.prepareReason(),null);h.controller.prepare();assert.equal(h.count('prepare'),2);assert.equal(h.last('prepare').args.attempt,3);
  const x=await attached();x.controller.loadPending();x.respond('pending',pending(3,true));await flush();assert.ok(x.controller.prepareReason());x.activity(activity(3));assert.equal(x.controller.prepareReason(),null);
});

test('201 remains acknowledged if later readback fails; no successful job/release is inferred',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.retry();h.respond('start',{...operation('retry','settled',5,'network-unavailable','accepted-unconfirmed'),acknowledged:true});await flush();
  assert.equal(h.state.status.acknowledged,true);assert.equal(h.state.status.observed,null);assert.equal(h.state.error,'network-unavailable');assert.ok(h.controller.prepareReason());h.activity(activity(3));assert.equal(h.controller.prepareReason(),null);
});

test('foreign session/account/repository/run/source/attempt/marker and contradictory terminal cannot authorize',async()=>{
  for(const change of ['project','session','repository','account','repositoryId','run','head','attempt','marker']){const h=await ready();h.controller.setConfirmed(true);h.controller.retry();const s=accepted();
    if(change==='project')s.operation.projectId='project-b';if(change==='session')s.sessionId='session-b';if(change==='repository')s.operation.target.scope.repository='owner/other';
    if(change==='account')s.operation.target.scope.accountId='44';if(change==='repositoryId')s.operation.target.scope.repositoryId='44';if(change==='run')s.operation.target.selection.runId=s.observed.id='32';
    if(change==='head')s.operation.target.selection.headSha=s.observed.headSha='0'.repeat(40);if(change==='attempt')s.operation.target.selection.attempt=3;if(change==='marker')s.operation.target.selection.marker='0'.repeat(32);
    h.respond('start',s);await flush();assert.equal(h.state.pending,true,change);assert.equal(h.state.uncertain,true,change);}
  const h=await ready();h.controller.setConfirmed(true);h.controller.retry();h.respond('start',accepted());await flush();const before=h.state.status,s=accepted(6);s.observed.attempt=4;h.emit(s);assert.equal(h.state.uncertain,true);assert.strictEqual(h.state.status,before);
});

test('old original status/start/stop promises remain owned across navigation and API replacement',async()=>{
  const h=await attached();h.controller.prepare();h.emit(operation('prepare','running',2));h.deferredStatus=true;h.controller.checkStatus();const replacement=harness();h.controller.connect(replacement.port);
  assert.equal(h.count('cancel'),1);assert.equal(h.detached,0);assert.equal(replacement.count('status'),0);const stopped=operation('prepare','settled',4,'cancelled');h.emit(stopped);h.respond('cancel',stopped);await flush();assert.ok(h.controller.ownerReason());
  h.last('prepare').resolve(operation('prepare','running',2));await flush();assert.equal(h.detached,0);h.last('status').resolve(operation('prepare','running',2));await flush();assert.equal(h.detached,1);assert.equal(replacement.count('status'),1);assert.equal(h.controller.currentConsent(),null);
});

test('Close expiry is a known refusal requiring a fresh original Check; a lost Close remains uncertain',async()=>{
  const h=await ready();h.deferredStatus=true;h.controller.checkStatus();const earlier=h.last('status');h.controller.discardReview();h.last('discard').reject({code:'github_actions_retry_refused_consent_expired'});await flush();
  assert.equal(h.state.uncertain,false);assert.equal(h.controller.canDiscard(),false);h.emit(review());earlier.resolve(review());await flush();assert.equal(h.controller.canDiscard(),false);h.controller.discardReview();assert.equal(h.count('discard'),1);
  h.emit(operation('prepare','settled',4));assert.ok(h.controller.ownerReason());h.deferredStatus=false;h.controller.checkStatus();await flush();assert.equal(h.controller.ownerReason(),null);
  const x=await ready();x.controller.discardReview();x.last('discard').reject(Error('INERT'));await flush();assert.equal(x.state.uncertain,true);x.emit(operation('prepare','settled',4));assert.ok(x.controller.ownerReason());
});

test('uncertain cleanup stays absorbing and original Stop remains available after disposal',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.retry();h.last('start').reject(Error('INERT'));await flush();h.controller.dispose();h.emit(operation('retry','running',4,'none','potentially-applied'));
  assert.equal(h.detached,0);assert.equal(h.count('cancel'),1);h.respond('cancel',accepted());await flush();assert.equal(h.detached,0);assert.equal(h.state.uncertain,true);assert.ok(h.controller.ownerReason());
  const x=await ready();x.controller.setConfirmed(true);x.controller.retry();x.emit(operation('retry','cleanup-unknown',5,'cleanup-unknown','potentially-applied'));const retained=x.state.status;x.emit(accepted(6));assert.strictEqual(x.state.status,retained);assert.equal(x.controller.canCancel(),true);
});

test('failed status, reentrant parsing and listener errors cannot install or promote another original',async()=>{
  const h=await attached();h.deferredStatus=true;h.controller.checkStatus();h.last('status').reject(Error('INERT'));await flush();assert.match(h.controller.prepareReason(),/Check/);
  const s=review();let once=false;h.rawEmit(new Proxy(s,{ownKeys(v){if(!once){once=true;h.controller.beforeWorkspaceAction();}return Reflect.ownKeys(v);}}));assert.equal(h.controller.currentConsent(),null);h.controller.retry();assert.equal(h.count('start'),0);
  const x=await attached();x.controller.subscribe(()=>{throw Error('INERT RENDER');});x.controller.prepare();x.respond('prepare',operation('prepare','settled',3,'forbidden'));await flush();assert.equal(x.state.pending,false);x.unlistenThrows=true;const replacement=harness();x.controller.connect(replacement.port);await flush();assert.equal(x.state.uncertain,true);assert.equal(replacement.count('status'),0);
});
