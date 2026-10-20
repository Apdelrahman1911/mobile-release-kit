// Inert raw DATA/controlled promises, not native/provider/allocation proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createVersionReservePort, parseVersionReserveStatus, parseReserveOptions, reserveBranch } from '../src/versionReserve.ts';
import { VersionReserveController } from '../src/versionReserveController.ts';
const ID = 'a'.repeat(32), RID = 'b'.repeat(32), candidate = 'c'.repeat(8)+'-'+ 'c'.repeat(4)+'-4ccc-8ccc-'+ 'c'.repeat(12);
const options = { reference: 'refs/heads/main', increment: 'patch', newCandidate: false, acknowledgeLimitations: true };
const reserved = { id: RID, candidateId: candidate, name: '1.2.4', build: 8 };
const frame = (phase, revision = 1, extra = {}) => ({ schemaVersion: 1, revision, projectId: phase === 'idle' ? null : 'project-1',
  operationId: phase === 'idle' ? null : phase === 'reserving' || phase === 'reserved' ? RID : ID, phase,
  reason: phase === 'refused' ? 'reservation-refused' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'none',
  review: phase === 'reviewed' ? { id: ID, reference: options.reference, increment: options.increment, newCandidate: false } : null,
  reservation: phase === 'reserved' ? reserved : null, ...extra });
const deferred = () => { let resolve, reject; const promise = new Promise((a,b) => { resolve=a; reject=b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i=0;i<12;i++) await Promise.resolve(); };
function setup() {
  const calls=[], edits=[];
  const port = Object.fromEntries(['status','review','reserve','cancel'].map((kind)=>[kind,(...args)=>{const d=deferred();calls.push({kind,args,...d});return d.promise;}]));
  const editor={reservedOpenReason:()=>null,openReserved:(v)=>{edits.push(v);return true;}};
  let context={port,nativeSession:{},projectId:'project-1',preview:false,blockedReason:null,editor};
  const c=new VersionReserveController({current:()=>context});
  return {c,port,calls,edits,context:()=>context,set:(v)=>{context={...context,...v};},last:(k)=>calls.filter(x=>x.kind===k).at(-1),
    ready:()=>{c.setEnabled(true);c.configure(options);}};
}
async function reviewed(h) { h.ready(); const p=h.c.review(); h.last('review').resolve(frame('reviewed')); await p; }
async function allocation(h) { await reviewed(h); const p=h.c.reserve();h.last('reserve').resolve(frame('reserved',2));await p; }

test('manual default and absent native gate cause zero effects', async()=>{
  const h=setup();assert.equal(h.c.getSnapshot().enabled,false);assert.equal(await h.c.review(),false);h.c.syncContext();assert.equal(h.calls.length,0);
  h.ready();h.set({port:null});h.c.syncContext();assert.equal(await h.c.review(),false);assert.equal(h.c.edit(),false);assert.equal(h.calls.length,0);
});
test('fixed port emits only four raw commands; no input can choose candidate/source/token',async()=>{
  const calls=[],port=createVersionReservePort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return {};});
  await port.status();await port.review('project-1',options);await port.reserve('project-1',ID);await port.cancel(RID);
  assert.deepEqual(calls.map(x=>x[0]),['version_reserve_status','version_reserve_review','version_reserve_start','version_reserve_cancel']);
  assert.deepEqual(calls[1][1],{projectId:'project-1',...options});
  await assert.rejects(port.review('project-1',{...options,source:{},token:'not-a-token'}));assert.equal(calls.length,4);
  assert.equal(parseReserveOptions({...options,acknowledgeLimitations:false}),null);
  for(const ref of ['refs/tags/v1','refs/heads/a/../b','refs/heads/a.lock','refs/heads//x','refs/heads/main\n']) assert.equal(reserveBranch(ref),false);
});
test('strict status rejects malformed, contradictory, accessor and bounded-array data',()=>{
  for(const phase of ['idle','reading','reviewed','reserving','reserved','refused','cleanup-unknown']) assert.ok(parseVersionReserveStatus(frame(phase,phase==='idle'?0:1)),phase);
  for(const invalid of [frame('reserved',1,{reason:'reservation-refused'}),frame('reserved',1,{reservation:{...reserved,build:2_100_000_001}}),
    frame('reserved',1,{reservation:{...reserved,name:'1.2.4\n'}}),frame('reviewed',1,{review:null}),frame('reserved',1,{token:'not-secret'}),
    frame('idle',0,{reservation:reserved}),frame('reviewed',1,{revision:0xffff_ffff})])assert.equal(parseVersionReserveStatus(invalid),null);
  let called=0;const raw=frame('reserved');Object.defineProperty(raw,'reservation',{enumerable:true,get(){called++;return reserved;}});
  assert.equal(parseVersionReserveStatus(raw),null);assert.equal(called,0);assert.equal(parseVersionReserveStatus(Array(100000)),null);
});
test('explicit review reserve and editor handoff are separate single-use actions',async()=>{
  const h=setup();await allocation(h);assert.equal(h.calls.length,2);assert.equal(h.edits.length,0);assert.equal(h.c.ownerReason(),null);
  assert.equal(h.c.editReason(),null);assert.equal(h.c.edit(),true);assert.deepEqual(h.edits,[reserved]);assert.equal(h.c.edit(),false);
  assert.equal(h.calls.length,2); // editor original owns its eventual Open/Prepare/Apply, not this controller
});
test('status cannot mint reviewed or reserved intent; policy change retires original intent',async()=>{
  const h=setup();h.ready();let p=h.c.check();h.last('status').resolve(frame('reviewed'));await p;assert.notEqual(h.c.reserveReason(),null);
  p=h.c.check();h.last('status').resolve(frame('reserved',2));await p;assert.notEqual(h.c.editReason(),null);
  p=h.c.review();h.last('review').resolve(frame('reviewed',3));await p;assert.equal(h.c.reserveReason(),null);
  h.c.configure({...options,increment:'major'});assert.notEqual(h.c.reserveReason(),null);
});
test('configured changes and explicit new candidate never silently re-reserve',async()=>{
  const h=setup();await allocation(h);assert.equal(h.c.configure({...options,increment:'minor'}),true);assert.equal(h.c.edit(),false);
  assert.equal(h.calls.length,2);assert.equal(await h.c.reserve(),false);assert.equal(h.c.getSnapshot().options.newCandidate,false);
});
test('subscriber retirement, same-project ABA, peer arrival veto review before native invoke',async()=>{
  for(const change of [h=>h.c.beforeContextIntent(),h=>{h.set({projectId:'elsewhere'});h.c.syncContext();h.set({projectId:'project-1'});h.c.syncContext();},h=>h.set({blockedReason:'another owner'})]){
    const h=setup();h.ready();let once=false;h.c.subscribe(()=>{if(!once&&h.c.getSnapshot().pending){once=true;change(h);}});
    assert.equal(await h.c.review(),false);assert.equal(h.calls.length,0);
  }
});
test('late result across context/API change stays stale; old promise and Stop remain original',async()=>{
  const h=setup();h.ready();const review=h.c.review();assert.ok(h.c.ownerReason());
  let check=h.c.check();h.last('status').resolve(frame('reading'));await check;
  const other={status:()=>{throw Error('new host called');},review:()=>{},reserve:()=>{},cancel:()=>{throw Error('new host called');}};
  h.set({port:other,nativeSession:{},projectId:'project-2'});h.c.beforeContextIntent();h.c.syncContext();
  const stop=h.c.stop();assert.deepEqual(h.last('cancel').args,[ID]);h.last('cancel').resolve(frame('reading',2));await stop;
  let joined=false;h.c.whenSettled().then(()=>joined=true);await flush();assert.equal(joined,false);
  h.last('review').resolve(frame('reviewed',3));await review;await flush();assert.equal(joined,true);assert.equal(h.c.getSnapshot().stale,true);assert.notEqual(h.c.reserveReason(),null);
});
test('unknown ACK never automatically reserves again; later status cannot erase unknown',async()=>{
  const h=setup();await reviewed(h);const p=h.c.reserve();h.last('reserve').reject(Error('private details omitted'));await p;
  assert.equal(h.c.getSnapshot().unknown,true);assert.equal(await h.c.reserve(),false);
  const read=h.c.check();h.last('status').resolve(frame('reserved',2));await read;assert.equal(h.c.getSnapshot().unknown,true);assert.equal(h.c.edit(),false);assert.equal(h.calls.filter(x=>x.kind==='reserve').length,1);
  assert.ok(!JSON.stringify(h.c.getSnapshot()).includes('private details'));
});
test('original known not-started code does not claim a reservation or erase prior data',async()=>{
  const h=setup();h.ready();const p=h.c.review();h.last('review').reject({code:'version_reserve_not_started',message:'not displayed'});await p;
  assert.equal(h.c.getSnapshot().unknown,false);assert.equal(h.c.getSnapshot().stale,true);assert.equal(h.c.getSnapshot().status,null);assert.equal(h.c.edit(),false);
});
test('response descriptor reentrancy and late disposal cannot publish usable reservation',async()=>{
  for(const dispose of [false,true]){
    const h=setup();await reviewed(h);const p=h.c.reserve();let once=false;
    const response=new Proxy(frame('reserved',2),{ownKeys(t){if(!once){once=true;dispose?h.c.dispose():h.c.beforeContextIntent();}return Reflect.ownKeys(t);}});
    h.last('reserve').resolve(response);await p;assert.equal(h.c.edit(),false);assert.equal(h.c.getSnapshot().stale,true);
  }
});
test('editor handoff notification reentrancy vetoes invoke and retains reservation DATA',async()=>{
  const h=setup();await allocation(h);h.c.subscribe(()=>{if(h.c.getSnapshot().editHandedOff)h.set({blockedReason:'foreign work'});});
  assert.equal(h.c.edit(),false);assert.equal(h.edits.length,0);assert.deepEqual(h.c.getSnapshot().status.reservation,reserved);
});

test('joined native review refusal remains a refusal, not a lost ACK or automatic retry', async()=>{
  const h=setup();h.ready();const p=h.c.review();h.last('review').resolve(frame('refused',2,{reason:'source-refused'}));await p;
  assert.equal(h.c.getSnapshot().unknown,false);assert.equal(h.c.ownerReason(),null);assert.notEqual(h.c.reserveReason(),null);
  assert.equal(h.calls.length,1);assert.equal(h.edits.length,0);
});
