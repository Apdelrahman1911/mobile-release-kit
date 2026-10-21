// Actual codecs/controllers, inert DATA and original deferred Promises only.
// No HTTP, service, credentials, native receipt, subprocess or timer is entered.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubActivityController } from '../src/githubActivityController.ts';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { createAgentGithubActionPort, parseAgentGithubActionAccess, parseGithubActionSelection,
  parseGithubActionStatus, githubActionCommands } from '../src/agentGithubActionAccess.ts';
import { permissionRevision, parseGithubActivitySnapshot, GITHUB_ACTIVITY_NOTICE } from '../src/githubActivityDelegation.ts';

const copy=structuredClone,hex=(c,n=32)=>c.repeat(n),stamp='2026-10-21T12:00:00Z';
const selection=()=>({kind:'activity-overview',sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12});
const reference=()=>({...selection(),accountId:'7',repositoryId:'9'});
const section=(rows=[],total=rows.length)=>({state:'read',reason:'none',coverage:total===rows.length?'complete':'windowed',total,rows});
const snapshot=()=>({accountId:'7',repositoryId:'9',observedAt:stamp,pullRequests:section([{number:'3',state:'open',draft:true}],null),
  workflowRuns:section([{id:'40',attempt:2,status:'completed',conclusion:'failure'}],4)});
const empty=(revision='0')=>({permissionRevision:revision,serviceInstance:null,projectId:null,grantId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,status:null});
function status(patch={}){return {origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review:reference(),
  revision:7,state:'complete',settlement:'settled',operationId:'github-activity-40',reason:'none',effect:'none',neverAdmitted:false,doNotReplay:true,snapshot:snapshot(),...patch};}
function noncomplete(patch={}){const s=status({...patch});delete s.snapshot;return s;}
function access(s=null,patch={}){return {permissionRevision:'1',serviceInstance:hex('2'),projectId:hex('1'),grantId:hex('3'),review:reference(),
  enabled:s===null,remainingMs:s===null?120000:0,consumed:s!==null,pending:s!==null&&s.settlement!=='settled',unknown:s?.state==='unknown',status:s,...patch};}
function connection(){return {mode:'native',context:{documentId:'doc-a',projectId:'project-a',projectGeneration:1,repository:'example/application'},
  status:{revision:12,session:{id:'session-a',projectId:'project-a',targetRepository:'example/application',state:'connected'},
    account:{state:'observed',value:{id:'7',login:'example'}},repository:{state:'observed',value:{id:'9',fullName:'example/application'}}},
  busy:null,uncertain:false,blocked:false,retirementPending:false,observing:false,error:null};}
const idle=(revision=1)=>({schemaVersion:1,revision,sessionId:'session-a',available:true,reason:'none',operation:null,result:null});
function activityPhase(phase,revision,id='github-activity-40'){return {...idle(revision),available:phase==='settled',reason:phase==='settled'?'none':'busy',
  operation:{id,projectId:'project-a',target:{projectBinding:hex('f',64),repository:'example/application',accountId:'7',repositoryId:'9'},
    selection:{kind:'overview',branch:null},phase,reason:'none'}};}
function deferred(kind,args,revision){let yes,no;const d={kind,args:copy(args),revision,ended:false};
  d.promise=new Promise((a,b)=>{yes=a;no=b;});d.resolve=v=>{d.ended=true;yes(copy(v));};d.reject=e=>{d.ended=true;no(e);};return d;}
async function flush(){for(let i=0;i<24;i++)await Promise.resolve();}
const retained=[];
async function fixture({check=true,permission='0',statusDeferred=false}={}){
  let view=connection(),epoch={},peer=null,listener=null,current=idle(),apiEpoch={};const calls=[];
  const call=(kind,args,revision)=>{const d=deferred(kind,args,revision);calls.push(d);return d.promise;};
  const h={statusDeferred};
  const port={mode:'native',subscribe:async f=>{listener=f;return()=>{listener=null;};},status:()=>h.statusDeferred?call('activity-status',{}):Promise.resolve(copy(current)),
    read:v=>call('activity-read',v),cancel:v=>call('activity-cancel',v)};
  const activity=new GitHubActivityController(()=>view,()=>peer);
  const permissionPort=Object.fromEntries(['access','allow','request','revoke'].map(k=>[k,(a,r)=>call(k,a,r)]));
  const main=new AgentGithubActionAccessController({syncOriginal:()=>activity.syncContext(),delegate:s=>activity.delegateOverview(s),
    current:()=>({port:permissionPort,nativeSession:apiEpoch,projectId:'project-a',epoch,preview:false,
      blockedReason:peer??activity.ownerReason(),reviews:[activity.agentSelection()].filter(Boolean)})});
  Object.assign(h,{activity,main,calls,port,permissionPort,count:k=>calls.filter(c=>c.kind===k).length,last:k=>calls.filter(c=>c.kind===k).at(-1),
    emit(v){current=copy(v);listener?.(copy(v));main.syncContext();},peer(v){peer=v;main.syncContext();},
    move(fn){fn(view);activity.syncContext();main.syncContext();},contextEpoch(){epoch={};main.syncContext();},apiEpoch(){apiEpoch={};main.syncContext();},
    async checked(revision='0'){const p=main.check();this.last('access').resolve(empty(revision));await p;},
  });
  retained.push(h);activity.connect(port);await flush();assert.equal(main.choose('activity-overview'),true);main.syncContext();
  if(check)await h.checked(permission);return h;
}
async function allowed(h,revision='1'){assert.equal(h.main.acknowledge(true),true);const p=h.main.allow();assert.equal(h.count('allow'),1);
  h.last('allow').resolve(access(null,{permissionRevision:revision}));assert.equal(await p,true);assert.equal(h.main.getSnapshot().unknown,false);return p;}
async function observed(h,s){const p=h.main.check();h.last('access').resolve(access(s));await flush();if(s.settlement!=='unknown')h.last('request').resolve(s);await p;}
test.afterEach(async()=>{for(const h of retained.splice(0)){
  for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();h.main.dispose();h.activity.dispose();
  for(const c of h.calls)if(!c.ended)c.reject({code:'fixture-ended'});await flush();assert.ok(h.calls.every(c=>c.ended));
}});

test('Activity uses genuine joined metadata and permission Access without a provider Read or fake Prepared',async()=>{
  const h=await fixture({check:false,statusDeferred:true});assert.equal(h.activity.agentSelection(),null);
  h.emit(idle());assert.equal(h.activity.agentSelection(),null); // Event cannot join the original Status caller.
  h.last('activity-status').resolve(idle());await flush();h.main.syncContext();assert.deepEqual(h.activity.agentSelection(),selection());
  assert.match(h.main.consentReason(),/Check/);assert.equal(h.main.acknowledge(true),false);await h.checked();
  await allowed(h);assert.deepEqual(h.last('allow').args,selection());assert.equal(h.last('allow').revision,'0');
  assert.equal(h.count('activity-read'),0);assert.equal(h.activity.getSnapshot().pending,false);assert.equal(h.activity.currentResult(),null);
  assert.deepEqual(githubActionCommands(h.main.getSnapshot().access,null),[`mrk github-submit ${hex('1')} ${hex('2')} ${hex('3')} --reviewed`]);
});

test('MAIN Allow encodes the original full-u64 revision and a separate read-only consent; old consent/status cannot upgrade',async()=>{
  const calls=[],port=createAgentGithubActionPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null;});
  await port.allow(selection(),'18446744073709551614');
  assert.deepEqual(calls,[['allow_agent_github_action',{selection:selection(),consentVersion:'agent-activity-overview-once-v1',expectedPermissionRevision:'18446744073709551614'}]]);
  for(const revision of [undefined,null,0,-0,'00','+1','1.0','18446744073709551616','18446744073709551615'])assert.throws(()=>port.allow(selection(),revision));
  for(const field of ['consentId','preparedSha256','marker','branch','token','url'])assert.equal(parseGithubActionSelection({...selection(),[field]:'INERT'}),null);
  assert.equal(parseAgentGithubActionAccess({...empty(),permissionRevision:0}),null);
  const noRevision=empty();delete noRevision.permissionRevision;assert.equal(parseAgentGithubActionAccess(noRevision),null);
  assert.equal(parseGithubActionStatus({...status(),permissionRevision:'1'}),null);
  for(const kind of ['repository-create','draft-pr-create','pr-create','failed-jobs-retry','setup-publish','setup-reconcile'])
    assert.equal(parseGithubActionSelection({...selection(),kind}),null);
  assert.ok(permissionRevision('0'));assert.ok(permissionRevision('18446744073709551615'));assert.match(GITHUB_ACTIVITY_NOTICE,/No jobs, logs or artifacts/);
  // Canonical DATA rejects every final, leading or embedded line terminator before BigInt.
  for(const separator of ['\n','\r','\u2028','\u2029'])for(const malformed of [`0${separator}`,`12${separator}`,`${separator}12`,`1${separator}2`]){
    assert.equal(permissionRevision(malformed),false,JSON.stringify(malformed));
    assert.equal(parseAgentGithubActionAccess(empty(malformed)),null);
    assert.throws(()=>port.allow(selection(),malformed));
    const s=status();s.review.accountId=malformed;s.snapshot.accountId=malformed;
    assert.equal(parseGithubActionStatus(s),null);
    for(const [sectionName,field] of [['pullRequests','number'],['workflowRuns','id']]){
      const compact=snapshot();compact[sectionName].rows[0][field]=malformed;
      assert.equal(parseGithubActivitySnapshot(compact,reference()),null);
    }
  }
  assert.equal(calls.length,1); // No invalid original stamp reaches raw Allow.
});

test('compact complete thirty-plus-thirty rows remain historical and optional denial is not an empty successful section',()=>{
  const s=status();s.snapshot.pullRequests=section(Array.from({length:30},(_,i)=>({number:String(18446744073709551615n-BigInt(i)),state:'open',draft:false})),null);
  s.snapshot.workflowRuns=section(Array.from({length:30},(_,i)=>({id:String(18446744073709551615n-BigInt(i)),attempt:1000,status:'completed',conclusion:'action_required'})),2147483647);
  assert.ok(parseGithubActionStatus(s));assert.ok(parseAgentGithubActionAccess(access(s)));assert.ok(new TextEncoder().encode(JSON.stringify(access(s))).length<8192);
  const gap=status();gap.snapshot.pullRequests={state:'unavailable',reason:'forbidden',coverage:'unknown',total:null,rows:[]};assert.ok(parseGithubActionStatus(gap));
  for(const mutate of [v=>v.snapshot.pullRequests.rows.push(copy(v.snapshot.pullRequests.rows[0])),v=>v.snapshot.workflowRuns.rows[0].token='INERT',
    v=>v.snapshot.workflowRuns.rows[0].attempt=1001,v=>v.snapshot.accountId='8',v=>v.snapshot.observedAt='2026-02-30T12:00:00Z',
    v=>v.snapshot.workflowRuns.rows[0].status='queued',v=>v.snapshot.pullRequests.rows[0].title='INERT',v=>v.effect='potentially-applied',
    v=>v.snapshot.pullRequests.coverage='complete',v=>v.review.consentId=hex('a'),v=>delete v.snapshot]){
    const invalid=status();mutate(invalid);assert.equal(parseGithubActionStatus(invalid),null);
  }
  const tooMany=copy(s);tooMany.snapshot.pullRequests.rows.push({number:'1',state:'open',draft:true});assert.equal(parseGithubActionStatus(tooMany),null);
  const denied=copy(gap);denied.snapshot.pullRequests.coverage='complete';assert.equal(parseGithubActionStatus(denied),null);
  let reads=0;const raw=snapshot();Object.defineProperty(raw,'observedAt',{enumerable:true,get(){reads++;return stamp;}});
  assert.equal(parseGithubActivitySnapshot(raw,reference()),null);assert.equal(reads,0);
});

test('joined permission observation is immutable across notify/reentry and cannot rearm from late status',async()=>{
  const h=await fixture({permission:'9007199254740993'});assert.equal(h.main.acknowledge(true),true);
  let observed=false;const off=h.main.subscribe(()=>{if(h.main.getSnapshot().pending==='allow'&&!observed){observed=true;h.main.check();}});
  await allowed(h,'9007199254740994');off();assert.equal(h.last('allow').revision,'9007199254740993');assert.equal(h.count('access'),1);
  assert.equal(await h.main.allow(),false);assert.equal(h.count('allow'),1);
  const max=await fixture({permission:'18446744073709551615'});assert.match(max.main.consentReason(),/exhausted/);
  assert.equal(max.main.acknowledge(true),false);assert.equal(await max.main.allow(),false);assert.equal(max.count('allow'),0);
});

test('concurrent revoke retains both original callers; late Allow never creates a replacement permission',async()=>{
  const h=await fixture();h.main.acknowledge(true);const pending=h.main.allow();assert.equal(h.last('allow').revision,'0');
  const stopping=h.main.revoke();assert.equal(h.count('revoke'),1);assert.equal(await h.main.allow(),false);
  h.last('revoke').resolve(access(null,{permissionRevision:'2',enabled:false,remainingMs:0}));await stopping;
  h.last('allow').resolve(access());await pending;
  assert.equal(h.main.getSnapshot().withdrawn,true);assert.equal(h.main.getSnapshot().access.enabled,false);assert.equal(h.count('allow'),1);
  assert.equal(h.activity.currentResult(),null);
});

test('old metadata, changing account/root/API and conflicting GUI peer refuse before any Allow or GUI stop',async()=>{
  for(const change of [h=>h.move(v=>{v.context.projectGeneration++;v.status.revision++;}),h=>h.move(v=>{v.status.account.value.id='8';v.status.revision++;}),
    h=>h.move(v=>v.status.revision++),h=>h.contextEpoch(),h=>h.apiEpoch(),h=>h.peer('A live original write review exists')]){
    const h=await fixture();h.main.acknowledge(true);change(h);
    const attempt=h.main.allow();assert.equal(h.count('allow'),0);assert.equal(await attempt,false);assert.equal(h.count('activity-cancel'),0);assert.equal(h.count('activity-read'),0);
  }
});

test('synchronous Allow-entry context or peer change cannot send and does not claim a fabricated Activity attempt',async()=>{
  for(const change of [h=>h.contextEpoch(),h=>h.peer('Another actual owner won')]){
    const h=await fixture();h.main.acknowledge(true);let once=false;
    const off=h.main.subscribe(()=>{if(!once&&h.main.getSnapshot().pending==='allow'){once=true;change(h);}});
    assert.equal(await h.main.allow(),false);off();assert.equal(h.count('allow'),0);assert.equal(h.count('activity-read'),0);
    assert.equal(h.count('activity-cancel'),0);assert.equal(h.activity.getSnapshot().pending,false);
  }
});

test('only the original request Query returns the historical snapshot; later Activity events never become its BoundResult',async()=>{
  const h=await fixture();await allowed(h);
  const running=noncomplete({revision:5,state:'running',settlement:'pending'});await observed(h,running);
  h.emit(activityPhase('settled',3));h.emit(activityPhase('running',4,'github-activity-41')); // a later GUI owner, not this request
  const count=h.count('activity-status'),check=h.main.check();assert.deepEqual(h.last('request').args,status().origin);
  assert.equal(h.main.getSnapshot().status.state,'running');h.last('request').resolve(status());await check;
  assert.equal(h.main.getSnapshot().status.snapshot.workflowRuns.rows[0].id,'40');assert.equal(h.activity.currentResult(),null);
  assert.equal(h.count('activity-status'),count);assert.ok(h.activity.ownerReason());assert.equal(h.count('activity-read'),0);
  const revoke=h.main.revoke();h.last('revoke').resolve(access(status(),{permissionRevision:'2'}));await revoke;
  assert.equal(h.main.ownerReason(),null);assert.ok(h.activity.ownerReason()); // only the presentation link retired
});

test('lost Allow, service history Unknown, foreign snapshot and missing success data remain absorbing without resend',async()=>{
  const lost=await fixture();lost.main.acknowledge(true);const p=lost.main.allow();lost.last('allow').reject(Error('INERT SECRET'));await p;
  assert.equal(lost.main.getSnapshot().unknown,true);assert.equal(await lost.main.allow(),false);assert.equal(lost.count('allow'),1);
  assert.equal(JSON.stringify(lost.main.getSnapshot()).includes('INERT SECRET'),false);
  for(const s of [noncomplete({state:'unknown',settlement:'unknown',reason:'history-unavailable'}),{...status(),grantId:hex('9')},noncomplete()]){
    const h=await fixture();await allowed(h);const check=h.main.check();h.last('access').resolve(access(s));await check;
    assert.equal(h.main.getSnapshot().unknown,true);assert.equal(await h.main.allow(),false);assert.equal(h.count('allow'),1);assert.equal(h.count('activity-read'),0);
  }
});

test('genuine pre-entry refusal remains Effect none, and GUI winner is not discarded or labelled a failed provider read',async()=>{
  const h=await fixture();await allowed(h);
  const refused=noncomplete({state:'refused',reason:'native-refused',operationId:null,neverAdmitted:true});assert.ok(parseGithubActionStatus(refused));
  assert.equal(parseGithubActionStatus({...refused,effect:'not-sent'}),null);await observed(h,refused);
  const revoke=h.main.revoke();h.last('revoke').resolve(access(refused,{permissionRevision:'2'}));await revoke;
  assert.equal(h.main.getSnapshot().unknown,false);assert.equal(h.main.ownerReason(),null);
  assert.equal(h.count('activity-read'),0);assert.equal(h.count('activity-cancel'),0);assert.equal(h.activity.currentResult(),null);
});
