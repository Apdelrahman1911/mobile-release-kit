// Inert complete-module/bridge DATA and deferred original IPC only. No GitHub,
// tokens, native services, repository changes or real journal files.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubPullRequestController } from '../src/githubPullRequestController.ts';
import { createGitHubPullRequestPort, encodePullRequestRequest, parsePullRequestDraft, parsePullRequestStatus,
  pullRequestConfirmation, pullRequestError, PULL_REQUEST_EVENT } from '../src/githubPullRequestProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const copy=structuredClone,marker='a'.repeat(32),consentId='b'.repeat(32);
const draft=()=>({base:'main',head:'feature/example',title:'Explain the change',body:'Tested locally.\nPlease review.'});
function connection(){return {mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'owner/app'},
  status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'owner/app',state:'connected'},
    account:{state:'observed',value:{id:'11',login:'owner'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app',defaultBranch:'main'}}},
  busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false,error:null};}
function target(intent=true){return {scope:{projectBinding:'d'.repeat(64),repository:'owner/app',accountId:'11',repositoryId:'22'},
  intent:intent?{base:'main',head:'feature/example',marker,titleSha256:'e'.repeat(64),bodySha256:'f'.repeat(64)}:null};}
function prepared(){const t=target();return {target:t,baseSha:'1'.repeat(40),headSha:'2'.repeat(40),
  comparison:{aheadBy:1,behindBy:0,totalCommits:1,reportedFiles:8,coverage:'windowed',files:[{path:'app/Main.kt',change:'modified'}]},
  draft:true,creationPermission:'not-proven',confirmation:pullRequestConfirmation(t)};}
const ack=()=>({id:'31',number:'3',url:'https://github.com/owner/app/pull/3'});
function idle(revision=1){return {schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,pending:[],observed:null,acknowledged:null};}
function operation(kind,phase,revision,reason='none',effect=kind==='create'?'not-sent':'none',t=target(kind!=='pending')){
  return {...idle(revision),available:phase==='settled',reason:phase==='settled'?'none':phase==='cleanup-unknown'?'cleanup-unknown':'busy',
    operation:{id:`${kind}-a`,projectId:'project-a',kind,target:t,phase,reason,effect}};
}
function review(revision=3){return {...operation('prepare','settled',revision),consent:{id:consentId,expiresAt:'2026-10-20T20:02:00Z',prepared:prepared()}};}
function observed(revision=5,kind='create'){return {...operation(kind,'settled',revision,'none','created-observed'),acknowledged:ack(),observed:ack()};}
function pending(revision=7){return {...operation('pending','settled',revision),pending:[{prepared:prepared(),claimed:true,acknowledged:null}]};}
function deferred(){let yes,no;const d={ended:false};d.promise=new Promise((resolve,reject)=>{yes=resolve;no=reject;});d.resolve=v=>{d.ended=true;yes(v);};d.reject=e=>{d.ended=true;no(e);};return d;}
async function flush(){for(let i=0;i<18;i++)await Promise.resolve();}
const harnesses=[];
function harness(){let current=idle(),view=connection(),listener=null,peer=null,detached=0;
  const calls=[],h={deferredStatus:false,unlistenThrows:false};
  const request=(kind,args)=>{const d=deferred();Object.assign(d,{kind,args:copy(args)});calls.push(d);return d.promise;};
  const port={mode:'native',subscribe:async f=>{listener=f;return ()=>{if(h.unlistenThrows)throw Error('INERT PRIVATE');listener=null;detached++;};},
    status:()=>{if(h.deferredStatus)return request('status',{});calls.push({kind:'status',ended:true});return Promise.resolve(copy(current));}};
  for(const kind of ['prepare','create','pending','reconcile','discard','cancel'])port[kind]=args=>request(kind,args);
  const controller=new GitHubPullRequestController(()=>view,()=>typeof peer==='function'?peer():peer);
  Object.assign(h,{port,controller,calls,count:k=>calls.filter(c=>c.kind===k).length,last:k=>calls.filter(c=>c.kind===k).at(-1),
    emit(s){current=copy(s);listener?.(copy(s));},rawEmit(s){listener?.(s);},retain(s){current=copy(s);},
    respond(k,s){current=copy(s);this.last(k).resolve(copy(s));},context(v){view=v;controller.syncContext();},peer(v){peer=v;},currentConnection:()=>view});
  Object.defineProperties(h,{state:{get:()=>controller.getSnapshot()},detached:{get:()=>detached}});harnesses.push(h);return h;
}
async function attached(fill=true){const h=harness();h.controller.connect(h.port);await flush();if(fill)for(const [k,v]of Object.entries(draft()))h.controller.setDraft(k,v);return h;}
async function ready(){const h=await attached();h.controller.prepare();h.respond('prepare',review());await flush();assert.ok(h.controller.currentConsent());return h;}
test.afterEach(async()=>{for(const h of harnesses.splice(0)){for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();h.controller.dispose();for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();}});

test('closed redacted statuses keep partial comparison, permission and acknowledged/observed axes distinct',()=>{
  const unconfirmed={...operation('create','settled',5,'network-unavailable','acknowledged-unconfirmed'),acknowledged:ack()};
  const found={...operation('reconcile','settled',9,'unattributed','found-unattributed'),observed:ack()};
  for(const s of [idle(),review(),pending(),observed(),unconfirmed,found,operation('create','cleanup-unknown',5,'cleanup-unknown','potentially-applied')])assert.ok(parsePullRequestStatus(s));
  for(const change of [s=>s.consent.prepared.draft=false,s=>s.consent.prepared.creationPermission='granted',s=>s.consent.prepared.comparison.coverage='complete',
    s=>s.consent.prepared.comparison.files[0].patch='INERT PRIVATE',s=>s.consent.prepared.confirmation+=' changed',s=>s.consent.prepared.target.intent.body='INERT PRIVATE',
    s=>s.consent.prepared.comparison.files.push(copy(s.consent.prepared.comparison.files[0]))]){const s=review();change(s);assert.equal(parsePullRequestStatus(s),null);}
  for(const change of [s=>s.acknowledged=null,s=>s.observed=null,s=>s.operation.phase='running',s=>s.observed.url='https://other.invalid',s=>s.observed.id='32']){const s=observed();change(s);assert.equal(parsePullRequestStatus(s),null);}
  const p=pending();p.pending.push(copy(p.pending[0]));assert.equal(parsePullRequestStatus(p),null);
  p.pending.pop();p.operation.target=target();assert.equal(parsePullRequestStatus(p),null);
  let gets=0;const raw=idle();Object.defineProperty(raw,'consent',{enumerable:true,get(){gets++;return null;}});assert.equal(parsePullRequestStatus(raw),null);assert.equal(gets,0);
});

test('actual composed bridge emits seven bounded RAW commands and no alternate/write capabilities',async()=>{
  const calls=[],events=[],api=createNativeApi('native',async(name,raw)=>{calls.push([name,raw]);return idle();},async name=>{events.push(name);return ()=>{};});
  const port=api.githubPullRequest;assert.ok(port);const base={sessionId:'session-a',expectedRevision:1};
  await port.status();await port.prepare({...base,expectedConnectionRevision:12,draft:draft()});await port.create({...base,consentId,confirm:true});
  await port.pending({...base,expectedConnectionRevision:12});await port.reconcile({...base,marker});await port.discard({...base,consentId});await port.cancel({operationId:'create-a'});await port.subscribe(()=>{});
  assert.deepEqual(calls.map(c=>c[0]),['status','prepare','create','pending','reconcile','discard','cancel'].map(v=>`github_pull_request_${v}`));assert.deepEqual(events,[PULL_REQUEST_EVENT]);
  for(const [name,raw]of calls){assert.ok(raw instanceof Uint8Array);assert.ok(raw.length<=(name.endsWith('_prepare')?16*1024:1024));}
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[1][1])).draft,draft());
  assert.equal(createGitHubPullRequestPort('preview',()=>assert.fail(),null),null);assert.equal(createGitHubPullRequestPort('native',()=>assert.fail(),null),null);assert.equal(previewApi.githubPullRequest,undefined);
  for(const key of ['token','root','url','repository','accountId','force','draftPullRequest'])assert.equal(encodePullRequestRequest('github_pull_request_prepare',{...base,expectedConnectionRevision:12,draft:draft(),[key]:'INERT'}),null);
  assert.equal(encodePullRequestRequest('github_pull_request_create',{...base,consentId,confirm:false}),null);
  for(const name of ['merge','push','rerun','ready','delete'])assert.equal(encodePullRequestRequest(`github_pull_request_${name}`,{}),null);
});

test('draft parser preserves valid Unicode/exact text, refuses control/marker/branch injection and error getters',()=>{
  const d={...draft(),title:'Résumé 🧪',body:'First line\n第二行'};assert.deepEqual({...parsePullRequestDraft(d)},d);
  for(const patch of [{base:d.head},{head:'refs/heads/a'},{head:'https://github.com/a/b'},{title:'   '},{body:'\u202ehidden'},{body:'<!-- mrk-draft-pr:123 -->'},{title:'é'.repeat(129)},{body:'x'.repeat(4097)}])assert.equal(parsePullRequestDraft({...d,...patch}),null);
  let gets=0;assert.equal(pullRequestError({get code(){gets++;return 'github_pull_request_refused_busy';}}).notAdmitted,false);assert.equal(gets,0);
  assert.deepEqual(pullRequestError({code:'github_pull_request_refused_target_changed'}),{reason:'target-changed',notAdmitted:true});
  assert.equal(pullRequestError({message:'INERT PRIVATE',notAdmitted:true}).notAdmitted,false);
});

test('mount/status/branch edits do not prepare or create; unknown repository and peer block explicitly',async()=>{
  const h=await attached(false);assert.deepEqual(h.state.draft,{base:'',head:'',title:'',body:''});assert.equal(h.count('status'),1);assert.equal(h.count('prepare'),0);
  for(const[k,v]of Object.entries(draft()))h.controller.setDraft(k,v);h.controller.checkStatus();await flush();assert.equal(h.count('create'),0);
  const c=connection();c.status.repository={state:'unavailable',value:null};h.context(c);h.controller.prepare();assert.equal(h.count('prepare'),0);
  h.context(connection());h.peer('Original build is pending');h.controller.prepare();assert.equal(h.count('prepare'),0);
  h.peer(null);h.controller.prepare();assert.deepEqual(h.last('prepare').args,{sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12,draft:draft()});
});

test('fresh joined exact review needs separate confirmation; one-use Create never changes connection or pushes',async()=>{
  const h=await ready();h.controller.create();assert.equal(h.count('create'),0);assert.ok(h.controller.ownerReason());
  h.controller.setConfirmed(true);h.controller.create();h.controller.create();assert.equal(h.count('create'),1);assert.equal(h.state.confirmed,false);
  assert.deepEqual(h.last('create').args,{sessionId:'session-a',expectedRevision:3,consentId,confirm:true});
  h.respond('create',observed());await flush();assert.equal(h.state.pending,false);assert.equal(h.state.uncertain,false);assert.equal(h.state.status.acknowledged.id,'31');
  assert.equal(h.currentConnection().status.revision,12);h.controller.prepare();h.controller.create();assert.equal(h.count('prepare'),1);assert.equal(h.count('create'),1);
});

test('terminal event first retains Start Promise; older coherent status cannot rewind or grant early approval',async()=>{
  const h=await attached();h.controller.prepare();h.emit(review());assert.equal(h.state.pending,true);assert.equal(h.controller.currentConsent(),null);
  h.controller.setConfirmed(true);h.controller.create();assert.equal(h.count('create'),0);
  h.respond('prepare',operation('prepare','running',2));await flush();assert.equal(h.state.status.revision,3);assert.ok(h.controller.currentConsent());
  h.deferredStatus=true;h.controller.checkStatus();h.controller.discardReview();h.respond('discard',operation('prepare','settled',4));await flush();assert.ok(h.controller.ownerReason());
  h.last('status').resolve(review());await flush();assert.equal(h.state.status.revision,4);assert.equal(h.state.uncertain,false);assert.equal(h.controller.ownerReason(),null);
});

test('branch/title/body edits keep local draft, retire exact review and preserve original Close',async()=>{
  for(const field of ['base','head','title','body']){const h=await ready();h.controller.setConfirmed(true);h.controller.setDraft(field,field==='body'?'':'new-value');
    assert.equal(h.controller.currentConsent(),null);assert.equal(h.state.confirmed,false);h.controller.create();assert.equal(h.count('create'),0);assert.ok(h.controller.canDiscard());
    h.controller.discardReview();h.respond('discard',operation('prepare','settled',4));await flush();assert.equal(h.controller.ownerReason(),null);assert.equal(h.state.draft[field],field==='body'?'':'new-value');}
});

test('reentrant project/API/ABA/draft/peer/revision/approval/Stop changes veto before the sole native handoff',async()=>{
  for(const change of ['project','api','aba','draft','peer','revision','approval','stop','unknown']){
    const h=await ready();h.controller.setConfirmed(true);let used=false;const off=h.controller.subscribe(()=>{if(used||!h.state.pending)return;used=true;
      if(change==='project'){const c=connection();c.context.projectId='project-b';h.context(c);}if(change==='api')h.controller.connect(null);
      if(change==='aba'){h.context({...connection(),context:null});h.context(connection());}if(change==='draft')h.controller.setDraft('title','Different');
      if(change==='peer')h.peer('Another original');if(change==='revision')h.currentConnection().status.revision++;if(change==='approval')h.controller.setConfirmed(false);
      if(change==='stop')h.controller.cancel();if(change==='unknown')h.emit({wrong:true});});
    h.controller.create();off();assert.equal(h.count('create'),0,change);assert.equal(h.state.pending,false,change);
  }
});

test('early Stop and workspace invalidation queue exactly original Stop without adopting late review',async()=>{
  const h=await attached();h.controller.prepare();h.controller.cancel();h.controller.beforeWorkspaceAction();assert.equal(h.count('cancel'),0);
  h.emit(operation('prepare','running',2));h.emit(operation('prepare','running',2));assert.equal(h.count('cancel'),1);
  h.respond('prepare',review());await flush();assert.equal(h.controller.currentConsent(),null);assert.ok(h.controller.ownerReason());
  h.respond('cancel',review());await flush();h.controller.discardReview();h.respond('discard',operation('prepare','settled',4));await flush();
  assert.equal(h.controller.ownerReason(),null);assert.equal(h.count('create'),0);assert.deepEqual(h.state.draft,draft());
});

test('known unmatched pre-admission refusal is not lost/throw/thenable or a refusal after original event',async()=>{
  const clean=await attached();clean.controller.prepare();clean.last('prepare').reject({code:'github_pull_request_refused_target_changed'});await flush();
  assert.equal(clean.state.pending,false);assert.equal(clean.state.uncertain,false);assert.match(clean.controller.prepareReason(),/Check/);assert.deepEqual(clean.state.draft,draft());
  for(const mode of ['lost','throw','thenable','matched-refusal']){const h=await ready();h.controller.setConfirmed(true);
    if(mode==='throw')h.port.create=()=>{throw {code:'github_pull_request_refused_busy'};};if(mode==='thenable')h.port.create=()=>({then(){assert.fail('No assimilation');}});
    h.controller.create();if(mode==='matched-refusal')h.emit(operation('create','running',4,'none','potentially-applied'));
    if(mode==='lost'||mode==='matched-refusal')h.last('create').reject({code:mode==='lost'?'reply-lost':'github_pull_request_refused_busy'});await flush();
    assert.equal(h.state.pending,true,mode);assert.equal(h.state.uncertain,true,mode);h.emit(observed());assert.equal(h.state.pending,true,mode);assert.ok(h.controller.createReason());
  }
});

test('joined potentially sent result uses only Pending/Reconcile; marker match never becomes created proof',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.create();h.respond('create',operation('create','settled',5,'network-unavailable','potentially-applied'));await flush();
  assert.equal(h.state.pending,false);assert.match(h.controller.prepareReason(),/previous attempt/);h.controller.prepare();assert.equal(h.count('prepare'),1);
  h.controller.loadPending();h.respond('pending',pending());await flush();h.controller.reconcile('0'.repeat(32));assert.equal(h.count('reconcile'),0);
  h.controller.reconcile(marker);assert.deepEqual(h.last('reconcile').args,{sessionId:'session-a',expectedRevision:7,marker});
  const found={...operation('reconcile','settled',9,'unattributed','found-unattributed'),pending:pending().pending,observed:ack()};h.respond('reconcile',found);await flush();
  assert.equal(h.state.status.acknowledged,null);assert.equal(h.state.error,'unattributed');h.controller.create();h.controller.prepare();assert.equal(h.count('create'),1);assert.equal(h.count('prepare'),1);
});

test('acknowledged creation retained even when final readback fails; not silently presented as observed success',async()=>{
  const h=await ready();h.controller.setConfirmed(true);h.controller.create();h.respond('create',{...operation('create','settled',5,'branches-changed','acknowledged-unconfirmed'),acknowledged:ack()});await flush();
  assert.equal(h.state.status.observed,null);assert.equal(h.state.status.acknowledged.id,'31');assert.equal(h.state.error,'branches-changed');assert.ok(h.controller.prepareReason());
});

test('absorbing native or lost Unknown preserves terminal evidence and unsent original Stop',async()=>{
  for(const sent of [true,false]){const h=sent?await ready():await attached();if(sent){h.controller.setConfirmed(true);h.controller.create();}
    const unknown=operation('create','cleanup-unknown',5,'cleanup-unknown','potentially-applied');h.emit(unknown);const retained=h.state.status;
    h.emit(observed(6));assert.strictEqual(h.state.status,retained);assert.equal(h.controller.canCancel(),true);h.controller.cancel();assert.equal(h.count('cancel'),1);
    h.respond('cancel',observed(7));if(sent)h.respond('create',observed(6));await flush();assert.strictEqual(h.state.status,retained);assert.equal(h.state.uncertain,true);assert.ok(h.controller.ownerReason());
  }
});

test('foreign source/session/branch/marker/hash and contradictory terminal evidence cannot authorize a current result',async()=>{
  for(const change of ['project','session','repository','account','repositoryId','head','marker','textHash']){const h=await ready();h.controller.setConfirmed(true);h.controller.create();const s=observed();
    if(change==='project')s.operation.projectId='project-b';if(change==='session')s.sessionId='session-b';if(change==='repository'){s.operation.target.scope.repository='owner/other';s.acknowledged.url=s.observed.url='https://github.com/owner/other/pull/3';}
    if(change==='account')s.operation.target.scope.accountId='44';if(change==='repositoryId')s.operation.target.scope.repositoryId='44';if(change==='head')s.operation.target.intent.head='different';
    if(change==='marker')s.operation.target.intent.marker='0'.repeat(32);if(change==='textHash')s.operation.target.intent.titleSha256='0'.repeat(64);
    h.respond('create',s);await flush();assert.equal(h.state.pending,true,change);assert.equal(h.state.uncertain,true,change);assert.equal(h.controller.currentConsent(),null);
  }
  const h=await ready();h.controller.setConfirmed(true);h.controller.create();h.respond('create',observed());await flush();const old=h.state.status,changed=observed(6);changed.acknowledged.id=changed.observed.id='44';h.emit(changed);assert.equal(h.state.uncertain,true);assert.strictEqual(h.state.status,old);
});

test('original Start/Status/Stop promises survive navigation and port replacement independently',async()=>{
  const h=await attached();h.controller.prepare();h.emit(operation('prepare','running',2));h.deferredStatus=true;h.controller.checkStatus();
  const replacement=harness();h.controller.connect(replacement.port);assert.equal(h.count('cancel'),1);assert.equal(h.detached,0);assert.equal(replacement.count('status'),0);
  const stopped=operation('prepare','settled',4,'cancelled');h.emit(stopped);h.respond('cancel',stopped);await flush();assert.ok(h.controller.ownerReason());
  h.last('prepare').resolve(operation('prepare','running',2));await flush();assert.equal(h.detached,0);h.last('status').resolve(operation('prepare','running',2));await flush();
  assert.equal(h.detached,1);assert.equal(replacement.count('status'),1);assert.deepEqual(h.state.draft,draft());assert.equal(h.controller.currentConsent(),null);
});

test('unused review and original Close remain owned after context change, with no private text lost',async()=>{
  const h=await ready(),replacement=harness();h.controller.connect(replacement.port);await flush();assert.equal(h.detached,0);assert.equal(h.controller.currentConsent(),null);
  assert.equal(h.controller.canDiscard(),true);h.controller.discardReview();assert.equal(h.last('discard').args.sessionId,'session-a');assert.equal(h.detached,0);
  h.respond('discard',operation('prepare','settled',4));await flush();assert.equal(h.detached,1);assert.equal(replacement.count('status'),1);assert.deepEqual(h.state.draft,draft());
});

test('expired native Close refusal requires fresh Check, unlike lost or synchronous Close acknowledgement',async()=>{
  for(const reason of ['consent_expired','target_changed']){const h=await ready();h.deferredStatus=true;h.controller.checkStatus();const earlier=h.last('status');
    h.controller.discardReview();h.last('discard').reject({code:`github_pull_request_refused_${reason}`});await flush();
    assert.equal(h.state.uncertain,false);assert.equal(h.state.error,reason.replaceAll('_','-'));assert.equal(h.controller.canDiscard(),false);assert.ok(h.controller.ownerReason());
    h.emit(review());earlier.resolve(review());await flush();assert.equal(h.controller.canDiscard(),false);assert.ok(h.controller.ownerReason());
    h.controller.discardReview();assert.equal(h.count('discard'),1);h.controller.prepare();assert.equal(h.count('prepare'),1);
    h.emit(operation('prepare','settled',4));assert.ok(h.controller.ownerReason());h.deferredStatus=false;h.controller.checkStatus();await flush();
    assert.equal(h.controller.ownerReason(),null);assert.deepEqual(h.state.draft,draft());}
  for(const mode of ['lost','throw']){const x=await ready();if(mode==='throw')x.port.discard=()=>{throw {code:'github_pull_request_refused_consent_expired'};};
    x.controller.discardReview();if(mode==='lost')x.last('discard').reject(Error('INERT PRIVATE'));await flush();
    assert.equal(x.state.uncertain,true,mode);assert.equal(x.controller.canDiscard(),false);x.emit(operation('prepare','settled',4));assert.ok(x.controller.ownerReason());assert.equal(x.state.uncertain,true);assert.deepEqual(x.state.draft,draft());}
});

test('failed or reentrant status reads cannot enable fresh action and dispose retains unknown original',async()=>{
  const h=await attached();h.deferredStatus=true;h.controller.checkStatus();h.last('status').reject(Error('INERT PRIVATE'));await flush();assert.match(h.controller.prepareReason(),/Check/);assert.equal(h.state.error,'response-invalid');
  const current=review();let once=false;const raw=new Proxy(current,{ownKeys(v){if(!once){once=true;h.controller.beforeWorkspaceAction();}return Reflect.ownKeys(v);}});
  h.rawEmit(raw);assert.equal(h.controller.currentConsent(),null);h.controller.create();assert.equal(h.count('create'),0);
  const x=await ready();x.controller.setConfirmed(true);x.controller.create();x.last('create').reject(Error('INERT PRIVATE'));await flush();x.controller.dispose();x.emit(operation('create','running',4,'none','potentially-applied'));
  assert.equal(x.detached,0);assert.equal(x.count('cancel'),1);x.respond('cancel',observed());await flush();assert.equal(x.detached,0);assert.equal(x.state.uncertain,true);
});

test('listener failure never orphans an original and unlisten failure never installs a replacement',async()=>{
  const h=await attached();h.controller.subscribe(()=>{throw Error('INERT RENDER');});h.controller.prepare();assert.equal(h.count('prepare'),1);
  h.respond('prepare',operation('prepare','settled',3,'forbidden'));await flush();assert.equal(h.state.pending,false);assert.equal(h.state.error,'forbidden');
  h.unlistenThrows=true;const replacement=harness();h.controller.connect(replacement.port);await flush();assert.equal(h.state.uncertain,true);assert.equal(replacement.count('status'),0);assert.ok(h.controller.ownerReason());
});
