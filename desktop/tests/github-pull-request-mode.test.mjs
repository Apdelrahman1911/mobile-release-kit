// Actual codecs/controllers with only inert DATA and deferred original calls.
// No GitHub, credential, native service, subprocess, timer or journal entry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubPullRequestController } from '../src/githubPullRequestController.ts';
import { parsePullRequestDraft, parsePullRequestStatus, pullRequestConfirmation, encodePullRequestRequest } from '../src/githubPullRequestProtocol.ts';
import { pullRequestMode, pullRequestModeFields, pullRequestModeLabel } from '../src/githubPullRequestMode.ts';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { createAgentGithubActionPort, parseGithubActionSelection, parseGithubActionStatus, parseAgentGithubActionAccess } from '../src/agentGithubActionAccess.ts';

const copy=structuredClone,hex=(c,n=32)=>c.repeat(n),marker=hex('a'),consentId=hex('b');
const draft=(ready=false)=>({base:'main',head:'feature/example',title:'Explain the change',body:'Tested locally.',...pullRequestModeFields(ready?'ready-for-review':'draft')});
function target(ready=false,intent=true){return {scope:{projectBinding:hex('d',64),repository:'owner/app',accountId:'11',repositoryId:'22'},
  intent:intent?{base:'main',head:'feature/example',marker,titleSha256:hex('e',64),bodySha256:hex('f',64),...pullRequestModeFields(ready?'ready-for-review':'draft')}:null};}
function prepared(ready=false){const t=target(ready);return {target:t,baseSha:hex('1',40),headSha:hex('2',40),
  comparison:{aheadBy:1,behindBy:0,totalCommits:1,reportedFiles:8,coverage:'windowed',files:[{path:'app/Main.kt',change:'modified'}]},
  draft:!ready,creationPermission:'not-proven',confirmation:pullRequestConfirmation(t)};}
const idle=(revision=1)=>({schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,pending:[],observed:null,acknowledged:null});
function operation(ready,kind,phase,revision,reason='none',effect=kind==='create'?'not-sent':'none'){
  return {...idle(revision),available:phase==='settled',reason:phase==='settled'?'none':phase==='cleanup-unknown'?'cleanup-unknown':'busy',
    operation:{id:`github-pull-request-${kind==='prepare'?1:kind==='create'?2:3}`,projectId:'project-a',kind,target:target(ready,kind!=='pending'),phase,reason,effect}};
}
const review=ready=>({...operation(ready,'prepare','settled',3),consent:{id:consentId,expiresAt:'2026-10-21T20:03:00Z',prepared:prepared(ready)}});
const ack=()=>({id:'31',number:'3',url:'https://github.com/owner/app/pull/3'});
const final=ready=>({...operation(ready,'create','settled',5,'none','created-observed'),acknowledged:ack(),observed:ack()});
function connection(){return {mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'owner/app'},
  status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'owner/app',state:'connected'},
    account:{state:'observed',value:{id:'11',login:'owner'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app',defaultBranch:'main'}}},
  busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false,error:null};}
function deferred(){let resolve,reject;const d={ended:false};d.promise=new Promise((y,n)=>{resolve=y;reject=n;});
  d.resolve=v=>{d.ended=true;resolve(v);};d.reject=e=>{d.ended=true;reject(e);};return d;}
async function flush(){for(let i=0;i<24;i++)await Promise.resolve();}
const retained=[];
async function fixture(ready=true,returned=true){let current=idle(),listener=null,peer=null;
  const view=connection(),calls=[],h={ready,deferStatus:false};
  const call=(kind,args)=>{const d=deferred();Object.assign(d,{kind,args:copy(args)});calls.push(d);return d.promise;};
  const port={mode:'native',subscribe:async f=>{listener=f;return()=>{listener=null;};},status:()=>h.deferStatus?call('status',{}):Promise.resolve(copy(current))};
  for(const kind of ['prepare','create','pending','reconcile','discard','cancel'])port[kind]=args=>call(kind,args);
  const controller=new GitHubPullRequestController(()=>view,()=>peer);
  Object.assign(h,{port,controller,calls,count:k=>calls.filter(c=>c.kind===k).length,last:k=>calls.filter(c=>c.kind===k).at(-1),
    emit(s){current=copy(s);listener?.(copy(s));},respond(k,s){current=copy(s);this.last(k).resolve(copy(s));},peer(v){peer=v;}});
  retained.push(h);controller.connect(port);await flush();
  for(const[k,v]of Object.entries(draft()))controller.setDraft(k,v);
  if(ready)controller.setCreationMode('ready-for-review');
  if(returned){controller.prepare();h.respond('prepare',review(ready));await flush();assert.ok(controller.currentConsent());}
  return h;
}
function status(h,patch={}){return {origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),
  review:{kind:h.ready?'pr-create':'draft-pr-create',sessionId:'session-a',consentId,expectedRevision:3,preparedSha256:hex('c',64)},
  revision:7,state:'complete',settlement:'settled',operationId:'github-pull-request-2',reason:'none',effect:'created-observed',neverAdmitted:false,doNotReplay:true,...patch};}
function access(h,s=null,patch={}){return {serviceInstance:hex('2'),projectId:hex('1'),grantId:hex('3'),review:status(h).review,
  enabled:s===null,remainingMs:s===null?100000:0,consumed:s!==null,pending:s!==null&&s.settlement!=='settled',unknown:s?.state==='unknown',status:s,...patch};}
function permission(h){const calls=[],native={};
  for(const name of ['access','allow','request','revoke'])native[name]=arg=>{const d=deferred();Object.assign(d,{kind:'permission-'+name,args:copy(arg)});calls.push(d);h.calls.push(d);return d.promise;};
  let peer=null,epoch={},c;
  c=new AgentGithubActionAccessController({current:()=>({port:native,nativeSession:h,projectId:'project-a',epoch,preview:false,
    blockedReason:peer??(c?.peerSelection()&&h.controller.agentSelected(c.peerSelection())?null:h.controller.ownerReason()),reviews:[h.controller.agentSelection()].filter(Boolean)}),
    syncOriginal:()=>h.controller.syncContext(),delegate:r=>h.controller.delegatePrepared(r)});
  c.choose(h.ready?'pr-create':'draft-pr-create');c.syncContext();
  const p={controller:c,last:k=>calls.filter(x=>x.kind==='permission-'+k).at(-1),count:k=>calls.filter(x=>x.kind==='permission-'+k).length,
    peer(v){peer=v;c.syncContext();},move(){epoch={};c.syncContext();}};h.permission=p;return p;
}
test.afterEach(async()=>{for(const h of retained.splice(0)){
  for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();h.permission?.controller.dispose();h.controller.dispose();
  for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();assert.ok(h.calls.every(c=>c.ended));
}});

test('legacy Draft canonical input stays field-for-field unchanged; only explicit Ready extends it',()=>{
  const old=draft();assert.deepEqual({...parsePullRequestDraft(old)},old);assert.equal(pullRequestMode(old),'draft');
  assert.equal(pullRequestModeLabel(old),'Draft');assert.equal(Object.hasOwn(old,'creationMode'),false);
  const base={sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12,draft:old};
  assert.deepEqual(JSON.parse(new TextDecoder().decode(encodePullRequestRequest('github_pull_request_prepare',base))),base);
  assert.equal(prepared().confirmation,'Create a draft pull request in owner/app from feature/example into main with the text you reviewed? Existing GitHub workflows may run. No code is pushed or merged. This does not authorize a release. Stopping cannot undo a sent request.');
  assert.deepEqual({...parsePullRequestDraft(draft(true))},draft(true));assert.ok(parsePullRequestStatus(review(true)));
  assert.equal(pullRequestModeLabel(draft(true)),'Ready for review');assert.match(prepared(true).confirmation,/Reviewers may be notified/);
});

test('bare false, cross-mode confirmation, null/unknown fields and getters cannot become Ready consent',()=>{
  for(const value of [null,undefined,false,true,'draft','ready','',{},[]]){
    assert.equal(parsePullRequestDraft({...draft(),creationMode:value}),null);
    const s=review(true);s.consent.prepared.target.intent.creationMode=value;assert.equal(parsePullRequestStatus(s),null);
  }
  for(const change of [s=>s.consent.prepared.draft=true,s=>delete s.consent.prepared.target.intent.creationMode,
    s=>s.consent.prepared.confirmation=prepared().confirmation,s=>s.consent.prepared.target.intent.token='INERT']){
    const s=review(true);change(s);assert.equal(parsePullRequestStatus(s),null);
  }
  const old=review();old.consent.prepared.draft=false;assert.equal(parsePullRequestStatus(old),null);
  let gets=0;const raw=draft();Object.defineProperty(raw,'creationMode',{enumerable:true,get(){gets++;return 'ready-for-review';}});
  assert.equal(parsePullRequestDraft(raw),null);assert.equal(gets,0);
  assert.throws(()=>pullRequestModeFields('other'));
});

test('Ready event before actual Prepare return cannot authorize Create or delegation; returned review sends once',async()=>{
  const h=await fixture(true,false);h.controller.prepare();assert.deepEqual(h.last('prepare').args.draft,draft(true));
  h.emit(review(true));assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.agentSelection(),null);
  h.controller.setConfirmed(true);h.controller.create();assert.equal(h.count('create'),0);
  h.respond('prepare',operation(true,'prepare','running',2));await flush();assert.ok(h.controller.currentConsent());
  h.controller.setConfirmed(true);h.controller.create();h.controller.create();assert.equal(h.count('create'),1);
  assert.deepEqual(h.last('create').args,{sessionId:'session-a',expectedRevision:3,consentId,confirm:true});
  h.respond('create',final(true));await flush();assert.equal(h.controller.getSnapshot().pending,false);assert.equal(h.controller.getSnapshot().status.observed.id,'31');
});

test('mode edits including ABA invalidate the returned original without rearming or losing Close',async()=>{
  const h=await fixture(false);h.controller.setConfirmed(true);h.controller.setCreationMode('ready-for-review');h.controller.setCreationMode('draft');
  assert.deepEqual(h.controller.getSnapshot().draft,draft());assert.equal(h.controller.currentConsent(),null);assert.equal(h.controller.getSnapshot().confirmed,false);
  h.controller.create();h.controller.prepare();assert.equal(h.count('create'),0);assert.equal(h.count('prepare'),1);assert.ok(h.controller.canDiscard());
  h.controller.discardReview();h.respond('discard',{...review(),revision:4,consent:null});await flush();assert.equal(h.controller.ownerReason(),null);
});

test('changing mode during Prepare queues only its original Stop and never adopts a late differently selected review',async()=>{
  const h=await fixture(false,false);h.controller.prepare();h.controller.setCreationMode('ready-for-review');h.controller.setCreationMode('draft');
  assert.equal(h.count('cancel'),0);h.emit(operation(false,'prepare','running',2));h.emit(operation(false,'prepare','running',2));assert.equal(h.count('cancel'),1);
  h.respond('prepare',review());await flush();assert.equal(h.controller.currentConsent(),null);assert.ok(h.controller.ownerReason());
  h.respond('cancel',review());await flush();h.controller.discardReview();h.respond('discard',{...review(),revision:4,consent:null});await flush();
  assert.equal(h.controller.ownerReason(),null);assert.equal(h.count('create'),0);
});

test('prior potentially sent branch-pair fence is mode-blind in both directions',async()=>{
  for(const ready of [false,true]){
    const h=await fixture(ready);h.controller.setConfirmed(true);h.controller.create();
    h.respond('create',operation(ready,'create','settled',5,'network-unavailable','potentially-applied'));await flush();
    h.controller.setCreationMode(ready?'draft':'ready-for-review');assert.match(h.controller.prepareReason(),/previous attempt/);
    h.controller.prepare();assert.equal(h.count('prepare'),1);h.controller.loadPending();
    const pending={...operation(false,'pending','settled',7),pending:[{prepared:prepared(ready),claimed:true,acknowledged:null}]};
    h.respond('pending',pending);await flush();assert.match(h.controller.prepareReason(),/previous attempt/);h.controller.prepare();assert.equal(h.count('prepare'),1);
  }
});

test('reentrant mode change at Create publication vetoes the actual handoff and preserves the selected text',async()=>{
  const h=await fixture();h.controller.setConfirmed(true);let once=false;
  const off=h.controller.subscribe(()=>{if(!once&&h.controller.getSnapshot().pending){once=true;h.controller.setCreationMode('draft');}});
  h.controller.create();off();assert.equal(h.count('create'),0);assert.equal(h.controller.getSnapshot().pending,false);
  assert.equal(h.controller.getSnapshot().draft.title,draft().title);assert.equal(h.controller.currentConsent(),null);assert.ok(h.controller.canDiscard());
});

test('both actual returned modes select distinct CLI consent; Ready cannot delegate through old Draft kind',async()=>{
  for(const ready of [false,true]){
    const h=await fixture(ready),selection=h.controller.agentSelection(),kind=ready?'pr-create':'draft-pr-create';assert.equal(selection.kind,kind);
    assert.equal(h.controller.delegatePrepared({...selection,kind:ready?'draft-pr-create':'pr-create'}),null);
    assert.ok(h.controller.agentSelection());const p=permission(h);assert.equal(p.controller.consentReason(),null);assert.equal(p.controller.acknowledge(true),true);
    const allow=p.controller.allow();assert.equal(p.count('allow'),1);assert.deepEqual(p.last('allow').args,selection);assert.equal(h.controller.agentSelection(),null);
    h.controller.setConfirmed(true);h.controller.create();assert.equal(h.count('create'),0);assert.equal(await p.controller.allow(),false);
    p.last('allow').resolve(access(h));assert.equal(await allow,true);assert.ok(parseAgentGithubActionAccess(access(h)));
  }
});

test('actual metadata-only Allow port emits distinct Ready consent while preserving old Draft bytes',async()=>{
  const sent=[],port=createAgentGithubActionPort(async(name,raw)=>{sent.push([name,JSON.parse(new TextDecoder().decode(raw))]);return null;});
  for(const kind of ['draft-pr-create','pr-create']){
    const selection={kind,sessionId:'session-a',consentId,expectedRevision:3};assert.ok(parseGithubActionSelection(selection));await port.allow(selection);
    assert.deepEqual(sent.at(-1),['allow_agent_github_action',{selection,consentVersion:kind==='pr-create'?'agent-pr-create-once-v1':'agent-draft-pr-create-once-v1'}]);
  }
  for(const extra of ['token','path','url','body','creationMode'])assert.throws(()=>port.allow({kind:'pr-create',sessionId:'session-a',consentId,expectedRevision:3,[extra]:'INERT'}));
  assert.equal(sent.length,2);
});

test('Ready own-review exemption never suppresses a conflicting peer or a reentrant veto after delegation',async()=>{
  const h=await fixture(),p=permission(h);p.peer('Other original remains live');assert.equal(p.controller.acknowledge(true),false);
  assert.equal(await p.controller.allow(),false);assert.equal(p.count('allow'),0);assert.ok(h.controller.agentSelection());p.peer(null);p.controller.acknowledge(true);
  let once=false;const off=h.controller.subscribe(()=>{if(!once&&h.controller.agentSelection()===null){once=true;p.peer('Different original entered');}});
  assert.equal(await p.controller.allow(),false);off();assert.equal(p.count('allow'),0);assert.equal(h.count('discard'),1);
  h.respond('discard',{...review(true),revision:4,consent:null});await flush();assert.equal(h.controller.agentSelection(),null);assert.equal(h.controller.ownerReason(),null);
});

test('lost Ready Allow remains absorbing through mode edits and known Revoke; no second grant or GUI Create',async()=>{
  const h=await fixture(),p=permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').reject(Error('INERT private failure'));await allow;
  h.controller.setCreationMode('draft');assert.equal(p.controller.getSnapshot().unknown,true);assert.equal(await p.controller.allow(),false);
  const revoke=p.controller.revoke();p.last('revoke').resolve(access(h,null,{enabled:false,remainingMs:0}));await revoke;
  h.controller.setConfirmed(true);h.controller.create();assert.equal(h.count('create'),0);assert.ok(h.controller.ownerReason());assert.equal(p.count('allow'),1);assert.equal(p.controller.getSnapshot().unknown,true);
});

test('Ready service final still waits same original native Check return; wrong mode output cannot free it',async()=>{
  const h=await fixture(),p=permission(h);p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').resolve(access(h));await allow;
  const progress=status(h,{revision:5,state:'running',settlement:'pending',effect:'potentially-applied'});
  const first=p.controller.check();p.last('access').resolve(access(h,progress));await flush();p.last('request').resolve(progress);await first;
  h.emit(final(true));h.deferStatus=true;const done=status(h);assert.ok(parseGithubActionStatus(done));
  const check=p.controller.check();p.last('request').resolve(done);await check;assert.ok(h.controller.ownerReason());assert.equal(h.count('status'),1);
  const revoke=p.controller.revoke();p.last('revoke').resolve(access(h,done));await revoke;h.respond('status',final(true));await flush();
  assert.equal(h.controller.ownerReason(),null);assert.equal(p.controller.ownerReason(),null);assert.equal(p.count('allow'),1);
  const other=await fixture();other.controller.setConfirmed(true);other.controller.create();other.respond('create',final(false));await flush();
  assert.equal(other.controller.getSnapshot().uncertain,true);assert.equal(other.controller.getSnapshot().pending,true);assert.ok(other.controller.ownerReason());
});

test('Ready actual acknowledgement remains distinct from unresolved readback and never authorizes another mode',async()=>{
  const h=await fixture();h.controller.setConfirmed(true);h.controller.create();
  h.respond('create',{...operation(true,'create','settled',5,'branches-changed','acknowledged-unconfirmed'),acknowledged:ack()});await flush();
  assert.equal(h.controller.getSnapshot().status.acknowledged.id,'31');assert.equal(h.controller.getSnapshot().status.observed,null);
  h.controller.setCreationMode('draft');h.controller.prepare();h.controller.create();assert.equal(h.count('prepare'),1);assert.equal(h.count('create'),1);
});
