// Complete existing controllers + inert original Promises/DTOs only. No browser,
// HTTP, filesystem journal, runtime, credentials, timers or native finality.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubActivityController } from '../src/githubActivityController.ts';
import { GitHubPullRequestController } from '../src/githubPullRequestController.ts';
import { parsePullRequestStatus, pullRequestConfirmation } from '../src/githubPullRequestProtocol.ts';
import { encodeGitHubBrowserRequest, browserRequestReturned, browserFailure, readPullRequestCompletion } from '../src/githubPullRequestManagement.ts';
import { createNativeApi } from '../src/bridge.ts';

const copy=structuredClone,marker='a'.repeat(32),consentId='b'.repeat(32),time='2026-10-20T12:00:00Z';
const draft=()=>({base:'main',head:'feature/example',title:'Explain the change',body:'Tested locally.'});
const connection=()=>({mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'owner/app'},
  status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'owner/app',state:'connected'},
    account:{state:'observed',value:{id:'11',login:'owner'}},repository:{state:'observed',value:{id:'22',fullName:'owner/app'}}},
  busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false});
const scope=()=>({projectBinding:'d'.repeat(64),repository:'owner/app',accountId:'11',repositoryId:'22'});
const target=()=>({scope:scope(),intent:{base:'main',head:'feature/example',marker,titleSha256:'e'.repeat(64),bodySha256:'f'.repeat(64)}});
const prepared=()=>({target:target(),baseSha:'1'.repeat(40),headSha:'2'.repeat(40),comparison:{aheadBy:1,behindBy:0,totalCommits:1,reportedFiles:0,coverage:'windowed',files:[]},
  draft:true,creationPermission:'not-proven',confirmation:pullRequestConfirmation(target())});
const ack=()=>({id:'31',number:'3',url:'https://github.com/owner/app/pull/3'});
const prIdle=()=>({schemaVersion:1,revision:1,sessionId:'session-a',available:true,reason:'none',operation:null,consent:null,pending:[],observed:null,acknowledged:null});
function prDone(kind='create',revision=5,effect='created-observed') {
  return {...prIdle(),revision,operation:{id:`${kind}-${revision}`,projectId:'project-a',kind,target:kind==='pending'?{scope:scope(),intent:null}:target(),phase:'settled',reason:'none',effect},
    ...(kind==='prepare'?{consent:{id:consentId,expiresAt:time,prepared:prepared()}}:kind==='pending'?{}:{acknowledged:ack(),observed:ack()})};
}
const row=closed=>({prepared:prepared(),claimed:true,acknowledged:ack(),...(closed?{closed:{id:'31',number:'3',closedAt:time,merged:true}}:{})});
const actIdle=()=>({schemaVersion:1,revision:1,sessionId:'session-a',available:true,reason:'none',operation:null,result:null});
const section=()=>({state:'read',reason:'none',coverage:'complete',total:0,rows:[]});
function actDone(revision=3,number='3') {
  const selection={kind:'pull-request',number};
  return {...actIdle(),revision,operation:{id:`read-${revision}`,projectId:'project-a',target:scope(),selection,phase:'settled',reason:'none'},
    result:{target:scope(),selection,observedAt:time,data:{kind:'pull-request',pullRequest:{id:'31',number,title:'Current details',state:'open',draft:false,headSha:'2'.repeat(40),
      headBranch:'feature/example',headRepository:'owner/app',baseSha:'1'.repeat(40),baseBranch:'main',updatedAt:time},
      changedFiles:section(),reviews:section(),commitStatuses:section(),checkRuns:section(),headChecked:true}}};
}
const sent={state:'request-sent',browserVisibility:'unconfirmed'};
function deferred(){let yes,no;const d={ended:false};d.promise=new Promise((r,j)=>{yes=r;no=j;});d.resolve=v=>{d.ended=true;yes(v);};d.reject=e=>{d.ended=true;no(e);};return d;}
async function flush(){for(let i=0;i<18;i++)await Promise.resolve();}
const retained=[];
async function harness(){
  const h={view:connection(),calls:[],prCurrent:prIdle(),actCurrent:actIdle(),prListener:null,actListener:null,detached:{pr:0,act:0},peer:null};
  const request=(owner,kind,args)=>{const d=Object.assign(deferred(),{owner,kind,args:copy(args)});h.calls.push(d);return d.promise;};
  const port=owner=>({mode:'native',subscribe:async f=>{h[owner+'Listener']=f;return()=>{h[owner+'Listener']=null;h.detached[owner]++;};},
    status:()=>Promise.resolve(copy(h[owner+'Current'])),openBrowser:a=>request(owner,'browser',a),
    ...Object.fromEntries((owner==='pr'?['prepare','create','pending','reconcile','discard','cancel']:['read','cancel']).map(kind=>[kind,args=>request(owner,kind,args)]))});
  h.prPort=port('pr');h.actPort=port('act');
  h.pr=new GitHubPullRequestController(()=>h.view,()=>h.peer??h.act?.ownerReason()??null);
  h.act=new GitHubActivityController(()=>h.view,()=>h.peer??h.pr.ownerReason());
  h.last=(owner,kind)=>h.calls.filter(v=>v.owner===owner&&v.kind===kind).at(-1);
  h.count=(owner,kind)=>h.calls.filter(v=>v.owner===owner&&v.kind===kind).length;
  h.emit=(owner,status)=>{h[owner+'Current']=copy(status);h[owner+'Listener']?.(copy(status));};
  h.respond=(owner,kind,status)=>{h[owner+'Current']=copy(status);h.last(owner,kind).resolve(copy(status));};
  h.context=v=>{h.view=v;h.pr.syncContext();h.act.syncContext();};
  retained.push(h);h.pr.connect(h.prPort);h.act.connect(h.actPort);await flush();
  for(const[k,v]of Object.entries(draft()))h.pr.setDraft(k,v);
  return h;
}
async function reviewed(){const h=await harness();h.pr.prepare();h.respond('pr','prepare',prDone('prepare',3,'none'));await flush();assert.ok(h.pr.currentConsent());return h;}
async function created(){const h=await reviewed();h.pr.setConfirmed(true);h.pr.create();h.respond('pr','create',prDone());await flush();assert.ok(h.pr.currentCompletion());return h;}
async function activityReady(){const h=await harness();h.act.read({kind:'pull-request',number:'3'});h.respond('act','read',actDone());await flush();assert.ok(h.act.currentResult());return h;}
test.afterEach(async()=>{for(const h of retained.splice(0)){
  for(const c of h.calls)if(!c.ended)c.reject({code:'inert-fixture-ended'});await flush();h.pr.dispose();h.act.dispose();
  for(const c of h.calls)if(!c.ended)c.reject({code:'inert-fixture-ended'});await flush();assert.ok(h.calls.every(c=>c.ended));
}});

test('actual composed ports share one closed RAW browser command; no URL/account/argv or visible-success output',async()=>{
  const calls=[],api=createNativeApi('native',async(name,bytes)=>{calls.push([name,bytes]);return sent;},async()=>()=>{});
  const b={sessionId:'session-a',expectedRevision:3,expectedConnectionRevision:12};
  await api.githubActivity.openBrowser({...b,kind:'activity-pull-request',operationId:'read-a',page:'files'});
  await api.githubPullRequest.openBrowser({...b,kind:'comparison',consentId});
  await api.githubPullRequest.openBrowser({...b,kind:'created-pull-request',operationId:'create-a',page:'conversation'});
  assert.deepEqual(calls.map(v=>v[0]),Array(3).fill('github_browser_open'));
  assert.ok(calls.every(v=>v[1] instanceof Uint8Array&&v[1].length<1024));
  const good=JSON.parse(new TextDecoder().decode(calls[0][1]));
  for(const name of ['url','repository','number','token','argv','account'])assert.equal(encodeGitHubBrowserRequest({...good,[name]:'INERT'}),null);
  assert.equal(encodeGitHubBrowserRequest({...good,page:'merge'}),null);
  assert.ok(browserRequestReturned(sent));assert.equal(browserRequestReturned({...sent,browserVisibility:'visible'}),false);
  let gets=0;const raw={get state(){gets++;return 'request-sent';},browserVisibility:'unconfirmed'};
  assert.equal(browserRequestReturned(raw),false);assert.equal(browserFailure({get code(){gets++;return 'github_browser_unavailable';}}),'unconfirmed');assert.equal(gets,0);
});

test('closed history stays optional and strictly acknowledged; never unknown/unsent or Create success',()=>{
  const pending={...prDone('pending',7,'none'),pending:[row(false)]};assert.ok(parsePullRequestStatus(pending));
  pending.pending=[row(true)];assert.ok(parsePullRequestStatus(pending));
  for(const patch of [{closed:null},{claimed:false},{acknowledged:null},{resumeWrite:true},{closed:{...row(true).closed,id:'99'}}])
    assert.equal(parsePullRequestStatus({...pending,pending:[{...row(true),...patch}]}),null);
  const closed=prDone('reconcile',9,'closed-confirmed');assert.ok(parsePullRequestStatus(closed));
  for(const patch of [{kind:'create'},{phase:'running'},{reason:'network-unavailable'}])assert.equal(parsePullRequestStatus({...closed,operation:{...closed.operation,...patch}}),null);
  assert.equal(parsePullRequestStatus({...closed,acknowledged:null}),null);
});

test('created-PR handoff waits for original invoke, then uses the existing selected-PR Activity read only',async()=>{
  const h=await reviewed();h.pr.setConfirmed(true);h.pr.create();h.emit('pr',prDone());
  assert.equal(h.pr.currentCompletion(),null);assert.equal(h.count('act','read'),0);assert.equal(h.count('pr','browser'),0);
  h.respond('pr','create',prDone());await flush();const receipt=h.pr.currentCompletion();
  assert.deepEqual(Object.keys(receipt).sort(),['context','status']);
  readPullRequestCompletion(h.pr,h.act,receipt);assert.equal(h.count('act','read'),1);
  assert.deepEqual(h.last('act','read').args.selection,{kind:'pull-request',number:'3'});
  h.respond('act','read',actDone());await flush();assert.equal(h.act.currentResult().data.pullRequest.draft,false);
  assert.equal(h.count('pr','create'),1);assert.equal(h.count('pr','browser'),0);
});

test('handoff rechecks draft, context/ABA, API and peer after synchronous listener notifications',async()=>{
  for(const change of ['draft','project','aba','port','peer']){
    const h=await created(),receipt=h.pr.currentCompletion();let used=false;
    const off=h.act.subscribe(()=>{if(used||!h.act.getSnapshot().pending)return;used=true;
      if(change==='draft')h.pr.setDraft('title','New local text');
      if(change==='project'){const c=connection();c.context.projectId='project-b';h.context(c);}
      if(change==='aba'){h.context({...connection(),context:null});h.context(connection());}
      if(change==='port')h.pr.connect(null);if(change==='peer')h.peer='Original local work';
    });
    readPullRequestCompletion(h.pr,h.act,receipt);off();assert.equal(h.count('act','read'),0,change);
    assert.equal(h.count('pr','create'),1);assert.equal(h.count('pr','browser'),0);
  }
});

test('refresh preserves selected PR and never uses an old/copied result or terminal event as completed read',async()=>{
  const h=await activityReady(),r=h.act.currentResult();h.act.refreshResult(copy(r));assert.equal(h.count('act','read'),1);
  h.act.refreshResult(r);assert.equal(h.count('act','read'),2);assert.deepEqual(h.last('act','read').args.selection,{kind:'pull-request',number:'3'});
  h.emit('act',actDone(5));assert.equal(h.act.currentResult(),null);h.act.openPullRequest(r,'files');assert.equal(h.count('act','browser'),0);
  h.respond('act','read',actDone(5));await flush();assert.equal(h.act.currentResult().selection.kind,'pull-request');
  h.act.openPullRequest(h.act.currentResult(),'files');assert.equal(h.count('act','browser'),1);h.last('act','browser').resolve(sent);await flush();
  assert.equal(h.act.getSnapshot().browserState,'request-sent');assert.equal(h.act.getSnapshot().uncertain,false);
});

test('same original browser promise blocks peers/rebind; status stays reachable and late reply cannot adopt new context',async()=>{
  const h=await activityReady();h.act.openPullRequest(h.act.currentResult(),'conversation');
  assert.equal(h.act.getSnapshot().browserPending,true);assert.ok(h.act.ownerReason());h.pr.prepare();assert.equal(h.count('pr','prepare'),0);
  assert.ok(h.act.canCheck());h.act.checkStatus();await flush();h.act.connect(null);h.act.dispose();
  assert.equal(h.detached.act,0);h.last('act','browser').resolve(sent);await flush();
  assert.equal(h.detached.act,1);assert.equal(h.act.getSnapshot().browserPending,false);assert.notEqual(h.act.getSnapshot().browserState,'request-sent');
});

test('native comparison selector keeps exact unused review; explicit Close remains on original during browser request',async()=>{
  const h=await reviewed(),review=h.pr.currentConsent();h.pr.openComparison(review);
  assert.deepEqual(h.last('pr','browser').args,{kind:'comparison',consentId,sessionId:'session-a',expectedRevision:3,expectedConnectionRevision:12});
  assert.equal(h.pr.getSnapshot().confirmed,false);h.pr.create();assert.equal(h.count('pr','create'),0);
  assert.ok(h.pr.canCheck());assert.ok(h.pr.canDiscard());h.pr.discardReview();
  const closedReview={...prDone('prepare',4,'none'),consent:null};closedReview.operation.id='prepare-3';h.respond('pr','discard',closedReview);await flush();
  assert.ok(h.pr.ownerReason());h.last('pr','browser').resolve(sent);await flush();
  assert.equal(h.pr.getSnapshot().browserState,'stale');assert.equal(h.pr.ownerReason(),null);assert.deepEqual(h.pr.getSnapshot().draft,draft());
});

test('browser listener and response parser reentrancy refuse stale targets; failures are not native finality',async()=>{
  const h=await reviewed(),review=h.pr.currentConsent();let once=false;
  const off=h.pr.subscribe(()=>{if(!once&&h.pr.getSnapshot().browserPending){once=true;h.pr.setDraft('body','Keep this newer draft');}});
  h.pr.openComparison(review);off();assert.equal(h.count('pr','browser'),0);assert.equal(h.pr.getSnapshot().draft.body,'Keep this newer draft');
  const a=await activityReady();a.act.openPullRequest(a.act.currentResult(),'files');
  const raw=new Proxy(sent,{getOwnPropertyDescriptor(object,key){a.act.beforeWorkspaceAction();return Object.getOwnPropertyDescriptor(object,key);}});
  a.last('act','browser').resolve(raw);await flush();assert.notEqual(a.act.getSnapshot().browserState,'request-sent');
  const b=await created();b.pr.openCompletedPullRequest(b.pr.currentCompletion(),'conversation');b.last('pr','browser').reject({message:'INERT PRIVATE path/token'});await flush();
  assert.equal(b.pr.getSnapshot().browserState,'unconfirmed');assert.equal(b.pr.getSnapshot().uncertain,false);
  assert.ok(b.pr.currentCompletion());assert.equal(JSON.stringify(b.pr.getSnapshot()).includes('INERT PRIVATE'),false);
  b.pr.openCompletedPullRequest(b.pr.currentCompletion(),'conversation');assert.equal(b.count('pr','browser'),1);
});

test('closed reconcile requires fresh saved-attempt read before a new review; no automatic approval or unknown bypass',async()=>{
  const h=await harness();h.pr.loadPending();h.respond('pr','pending',{...prDone('pending',3,'none'),pending:[row(false)]});await flush();
  assert.match(h.pr.prepareReason(),/previous attempt/);h.pr.reconcile(marker);
  h.respond('pr','reconcile',{...prDone('reconcile',5,'closed-confirmed'),pending:[row(false)]});await flush();
  assert.ok(h.pr.currentCompletion());assert.match(h.pr.prepareReason(),/previous attempt/);
  h.pr.loadPending();h.respond('pr','pending',{...prDone('pending',7,'none'),pending:[row(true)]});await flush();
  assert.equal(h.pr.prepareReason(),null);h.pr.create();assert.equal(h.count('pr','create'),0);h.pr.prepare();assert.equal(h.count('pr','prepare'),1);
  h.respond('pr','prepare',prDone('prepare',9,'none'));await flush();assert.equal(h.pr.getSnapshot().confirmed,false);
  const old=h.pr.currentConsent();h.pr.openComparison(copy(old));assert.equal(h.count('pr','browser'),0);
});

test('historical/unknown creation data cannot furnish a current action or clear the original attempt',async()=>{
  const h=await reviewed();h.pr.setConfirmed(true);h.pr.create();h.last('pr','create').reject({code:'lost-reply'});await flush();
  h.emit('pr',prDone());assert.equal(h.pr.currentCompletion(),null);assert.ok(h.pr.getSnapshot().pending);assert.ok(h.pr.getSnapshot().uncertain);
  assert.equal(h.count('act','read'),0);assert.equal(h.count('pr','browser'),0);
  const good=await created(),old=good.pr.currentCompletion();good.context({...connection(),context:null});good.context(connection());
  readPullRequestCompletion(good.pr,good.act,old);good.pr.openCompletedPullRequest(old,'files');
  assert.equal(good.count('act','read'),0);assert.equal(good.count('pr','browser'),0);assert.deepEqual(good.pr.getSnapshot().draft,draft());
});
