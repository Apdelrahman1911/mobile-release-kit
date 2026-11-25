// Actual controller/ports with finite inert promises. No source/Store/provider.
import test from 'node:test';
import assert from 'node:assert/strict';
import { VersionReserveController } from '../src/versionReserveController.ts';
import { parseReserveReviewStatus, createReserveReviewPort } from '../src/versionReserveReview.ts';
const SERVICE='1'.repeat(32),PROJECT='2'.repeat(32),REQUEST='3'.repeat(32),ID='a'.repeat(32);
const origin={projectId:PROJECT,serviceInstance:SERVICE,requestId:REQUEST};
const options={reference:'refs/heads/main',increment:'build',newCandidate:false,acknowledgeLimitations:true};
const row=(phase='queued',revision=1,extra={})=>({schemaVersion:1,origin,runtimeProjectId:'project-1',options,revision,phase,
  settlement:['review-ready','refused'].includes(phase)?'settled':phase==='unknown'?'unknown':'pending',operationId:['queued','refused'].includes(phase)?null:ID,
  review:phase==='review-ready'?{id:ID,revision:2}:null,remainingMs:phase==='review-ready'?110000:0,
  reason:phase==='unknown'?'cleanup-unknown':phase==='refused'?'native-refused':null,doNotReplay:true,...extra});
const frame=(phase='reviewed',revision=2,extra={})=>({schemaVersion:1,revision,projectId:'project-1',operationId:ID,phase,reason:'none',
  review:phase==='reviewed'?{id:ID,reference:options.reference,increment:options.increment,newCandidate:options.newCandidate}:null,reservation:null,...extra});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return{promise,resolve,reject}};
const flush=async()=>{for(let i=0;i<24;i++)await Promise.resolve()};
function rig(){
  const calls=[];let listener=null;
  const method=kind=>(...args)=>{const d=deferred(),call={kind,args,...d,done:false};calls.push(call);return d.promise};
  const reviewPort={status:method('read'),cancel:method('stop'),review:method('delegated'),subscribe:async cb=>{listener=cb;return()=>{listener=null}}};
  const port={status:method('status'),review:method('gui-review'),cancel:method('gui-stop'),reserve:method('reserve')};
  const cliAccessPort={status:method('access'),allow:method('allow'),revoke:method('revoke')};
  let context={port,reviewPort,cliAccessPort,nativeSession:{},projectId:'project-1',preview:false,blockedReason:null,editor:null};
  const c=new VersionReserveController({current:()=>context});
  const last=kind=>calls.filter(c=>c.kind===kind&&!c.done).at(-1);
  const resolve=(kind,v)=>{const call=last(kind);assert.ok(call,kind);call.done=true;call.resolve(v);return call};
  return{c,calls,port,reviewPort,last,resolve,emit:v=>listener?.(v),set:v=>{context={...context,...v}},enable:()=>c.setEnabled(true)};
}
async function queued(h){await flush();h.resolve('read',row());await flush();}
async function ready(h){h.enable();await queued(h);h.resolve('delegated',frame());await flush();h.resolve('read',row('review-ready',4));await flush();h.resolve('read',row('review-ready',4));await flush();}

test('closed metadata accepts phases but rejects source/grants/duplicate-shape and required-null ambiguity',()=>{
  for(const phase of ['queued','reading','finishing','review-ready','refused','stopping','unknown'])assert.ok(parseReserveReviewStatus(row(phase)),phase);
  const missing=row();delete missing.review;
  for(const v of [missing,row('queued',1,{nativeAuthority:true}),row('review-ready',2,{review:{id:ID,revision:0}}),row('review-ready',2,{remainingMs:120001}),row('reading',2,{settlement:'settled'}),row('queued',1,{options:{...options,floor:7}}),row('queued',1,{options:{...options,futureTag:null}}),row('queued',1,{origin:{...origin,requestId:'0'.repeat(32)}}),row('queued',1,{revision:-0})])assert.equal(parseReserveReviewStatus(v),null);
  let reads=0;const getter=row();Object.defineProperty(getter,'options',{enumerable:true,get(){reads++;return options}});assert.equal(parseReserveReviewStatus(getter),null);assert.equal(reads,0);
});
test('fixed real MAIN port sends only closed origin, never proposed fields or source',async()=>{
  const calls=[],port=createReserveReviewPort(async(n,b)=>{assert.ok(b.length+96<=1024);calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null},async()=>()=>{});
  await port.status(null);await port.status(origin);await port.review(origin);await port.cancel(origin);
  assert.deepEqual(calls,[['agent_version_reserve_review_status',{origin:null}],['agent_version_reserve_review_status',{origin}],['version_reserve_review',{intent:'agent-version-reserve-review',origin}],['cancel_agent_version_reserve_review',{origin}]]);
  await assert.rejects(port.review({...origin,reference:'refs/heads/evil'}));assert.equal(calls.length,4);
});
test('manual default refuses proposal without touching the form or starting native Review',async()=>{
  const h=rig(),form=h.c.getSnapshot().options;await queued(h);assert.equal(h.c.getSnapshot().enabled,false);assert.equal(h.last('delegated'),undefined);assert.equal(h.c.getSnapshot().options,form);
  h.resolve('stop',row('refused',2));await flush();h.resolve('read',row('refused',2));await flush();h.resolve('read',row('refused',2));await flush();assert.equal(h.c.getSnapshot().unknown,false);h.c.dispose();
});
test('cold unavailable service read cannot poison the ordinary manual or explicit GUI flow',async()=>{
  const h=rig();await flush();const read=h.last('read');read.done=true;read.reject({code:'cli_access_unavailable'});await flush();
  assert.equal(h.c.cliReview.getSnapshot().unknown,false);assert.equal(h.c.ownerReason(),null);
  assert.equal(h.enable(),true);assert.equal(h.c.configure(options),true);const ordinary=h.c.review();
  assert.deepEqual(h.last('gui-review').args,['project-1',options]);h.resolve('gui-review',frame());await ordinary;
  assert.equal(h.c.getSnapshot().unknown,false);assert.equal(h.last('delegated'),undefined);assert.equal(h.last('reserve'),undefined);h.c.dispose();
});
test('genuine proposal enters original Review exactly once, keeps form, and needs separate explicit Reserve consent',async()=>{
  const h=rig();h.enable();const form=h.c.getSnapshot().options;await queued(h);assert.deepEqual(h.last('delegated').args,[origin]);assert.equal(h.c.getSnapshot().options,form);assert.equal(h.last('reserve'),undefined);
  h.resolve('delegated',frame());await flush();assert.ok(h.c.reserveReason()); // actual native metadata/caller not yet reconciled
  h.resolve('read',row('review-ready',4));await flush();h.resolve('read',row('review-ready',4));await flush();
  assert.equal(h.c.getSnapshot().unknown,false);assert.equal(h.c.reserveReason(),null);assert.equal(h.c.getSnapshot().options,form);
  assert.equal(h.c.cliAccess.setAcknowledged(true),false);
  const check=h.c.cliAccess.check();h.resolve('access',{allowRevision:'0000000000000000',serviceInstance:null,projectId:null,grantId:null,reviewId:null,reviewRevision:null,enabled:false,remainingMs:0,consumed:false,requestId:null,completedOperationId:null});await check;
  assert.equal(h.c.cliAccess.setAcknowledged(true),true);const allow=h.c.cliAccess.allow();assert.deepEqual(h.last('allow').args,['project-1',ID,2,'0000000000000000']);
  h.resolve('allow',{allowRevision:'0000000000000001',serviceInstance:SERVICE,projectId:PROJECT,grantId:'4'.repeat(32),reviewId:ID,reviewRevision:2,enabled:true,remainingMs:90000,consumed:false,requestId:null,completedOperationId:null});await allow;
  assert.equal(h.calls.filter(c=>c.kind==='delegated').length,1);assert.equal(h.last('reserve'),undefined);h.c.dispose();
});
test('native reviewed metadata before actual MAIN return cannot release caller or upgrade permission',async()=>{
  const h=rig();h.enable();await queued(h);h.emit(row('review-ready',4));await flush();h.resolve('read',row('review-ready',4));await flush();
  assert.ok(h.c.ownerReason());assert.equal(h.c.cliAccess.setAcknowledged(true),false);assert.equal(await h.c.reserve(),false);
  h.resolve('delegated',frame());await flush();h.resolve('read',row('review-ready',4));await flush();h.resolve('read',row('review-ready',4));await flush();assert.equal(h.c.reserveReason(),null);h.c.dispose();
});
test('read event alone and cold ready metadata never manufacture a private reviewed intent',async()=>{
  const h=rig();h.enable();await flush();h.resolve('read',row('review-ready',4));await flush();assert.equal(h.last('delegated'),undefined);assert.ok(h.c.reserveReason());assert.equal(h.c.cliAccess.setAcknowledged(true),false);h.c.dispose();
});
test('dirty/project/service and reentrant intent changes veto before native invoke and keep values',async()=>{
  for(const change of [h=>h.set({blockedReason:'dirty saved inputs'}),h=>h.set({projectId:'other'}),h=>h.set({nativeSession:{}}),h=>h.c.beforeContextIntent()]){
    const h=rig();h.enable();const form=h.c.getSnapshot().options;let once=false;
    h.c.subscribe(()=>{if(!once&&h.c.cliReview.getSnapshot().status?.phase==='queued'){once=true;change(h)}});
    await queued(h);assert.equal(h.last('delegated'),undefined);assert.ok(h.last('stop'));assert.equal(h.c.getSnapshot().options,form);h.c.dispose();h.resolve('stop',row('refused',2));await flush();
  }
});
test('known unentered native refusal cancels exact queued entry; no silent rearm or pending forever',async()=>{
  const h=rig();h.enable();await queued(h);const call=h.last('delegated');call.done=true;call.reject({code:'version_reserve_not_started'});await flush();assert.ok(h.last('stop'));h.resolve('stop',row('refused',2));await flush();h.resolve('read',row('refused',2));await flush();h.resolve('read',row('refused',2));await flush();assert.equal(h.c.getSnapshot().unknown,false);assert.equal(h.calls.filter(c=>c.kind==='delegated').length,1);h.c.dispose();
});
test('coalesced next request is found only after exact old caller and native outcome, once',async()=>{
  const h=rig();h.enable();await queued(h);const next={...origin,requestId:'5'.repeat(32)};
  h.emit(row('queued',1,{origin:next}));await flush();assert.deepEqual(h.last('read').args,[origin]);h.resolve('read',row('reading',2));await flush();assert.equal(h.calls.filter(c=>c.kind==='delegated').length,1);
  h.resolve('delegated',frame('refused',2,{reason:'source-refused'}));await flush();assert.deepEqual(h.last('read').args,[origin]);h.resolve('read',row('refused',3,{operationId:ID}));await flush();assert.deepEqual(h.last('read').args,[null]);h.resolve('read',row('queued',1,{origin:next}));await flush();assert.deepEqual(h.last('delegated').args,[next]);assert.equal(h.calls.filter(c=>c.kind==='delegated').length,2);h.c.dispose();h.resolve('delegated',frame('refused',3,{reason:'source-refused'}));await flush();
});
test('lost/unknown metadata never switches to later origin or replays the earlier Review',async()=>{
  const h=rig();h.enable();await queued(h);h.emit(row('queued',1,{origin:{...origin,requestId:'5'.repeat(32)}}));await flush();h.resolve('read',row('unknown',3));await flush();h.resolve('delegated',frame('cleanup-unknown',3,{reason:'cleanup-unknown'}));await flush();assert.deepEqual(h.last('read').args,[origin]);h.resolve('read',row('unknown',3));await flush();assert.equal(h.last('read'),undefined);assert.equal(h.calls.filter(c=>c.kind==='delegated').length,1);assert.ok(h.c.ownerReason());h.c.dispose();
});
