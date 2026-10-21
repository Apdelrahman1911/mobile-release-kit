// DATA/controlled promises only. No native or provider outcome is simulated as proof.
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseVersionEditAccess, createVersionEditAgentApi, VERSION_EDIT_CONSENT} from '../src/serviceVersionEditProtocol.ts';
import {ServiceVersionEditController} from '../src/serviceVersionEditController.ts';
const id=n=>n.repeat(32), hash=n=>n.repeat(64);
const review={original:{sessionId:id('1'),ownerGeneration:id('2'),revision:id('3'),planToken:id('4')},nativeStatusRevision:7,name:'1.2',build:'8',source:'public/version.properties',beforeBytes:21,beforeSha256:hash('a'),afterBytes:22,afterSha256:hash('b'),candidateId:null};
const empty={schemaVersion:1,serviceInstance:null,projectId:null,grantId:null,nonce:null,review:null,live:false,remainingMs:0,request:null};
const access=(nonce=id('5'))=>({...empty,serviceInstance:id('6'),projectId:id('7'),grantId:id('8'),nonce,review:structuredClone(review),live:true,remainingMs:800000});
const origin={projectId:id('7'),serviceInstance:id('6'),requestId:id('9')};
const pending=a=>({...a,live:false,remainingMs:0,request:{schemaVersion:1,origin,grantId:a.grantId,revision:1,phase:'queued',settlement:'pending',review:structuredClone(a.review),cancelRequested:false,result:null,doNotReplay:true}});
const flush=async()=>{for(let i=0;i<15;i++)await Promise.resolve();};
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return{promise,resolve};};

test('version delegation strict bounded comparison, required nulls and native owner field closure',()=>{
 assert.ok(parseVersionEditAccess(empty));assert.ok(parseVersionEditAccess(access()));assert.ok(parseVersionEditAccess(pending(access())));
 for(const change of [a=>{delete a.review.candidateId;},a=>{a.review.original.revision+='\n';},a=>{a.review.source='../file';},a=>{a.review.beforeBytes=65537;},a=>{a.review.name='x'.repeat(65);},a=>{a.review.build='8\n';},a=>{a.secret='x';},a=>{a.review.file='raw';},a=>{a.live=false;},a=>{a.remainingMs=900001;},a=>{a.review.candidateId='x';}]){
  const a=access();change(a);assert.equal(parseVersionEditAccess(a),null);
 }
 const huge=access();huge.review.name='x'.repeat(17000);assert.equal(parseVersionEditAccess(huge),null);
 let reads=0;assert.equal(parseVersionEditAccess({...empty,get nonce(){reads++;return null;}}),null);assert.equal(reads,0);
 const parsed=parseVersionEditAccess(access());assert.ok(Object.isFrozen(parsed.review.original));
 const a=pending(access());a.request.phase='final';assert.equal(parseVersionEditAccess(a),null);
});

test('fixed native commands use RAW existing Apply route and never accept a free path',async()=>{
 const calls=[];const invoke=async(cmd,arg)=>{calls.push([cmd,JSON.parse(new TextDecoder().decode(arg))]);return empty;};
 const api=createVersionEditAgentApi('native',invoke,async()=>()=>{});assert.ok(api);assert.equal(createVersionEditAgentApi('preview',invoke),null);
 await api.status();await api.revoke(id('a'));
 assert.deepEqual(calls,[['agent_version_edit_status',{}],['revoke_agent_version_edit',{nonce:id('a') }]]);
 await assert.rejects(()=>api.apply(origin));assert.deepEqual(calls.at(-1),['release_version_edit_apply',{intent:'agent-version-edit',origin}]);
});

test('pre-notification revoke/currentness cuts send zero Allow and exact original nonce',async()=>{
 for(const kind of ['revoke','change']){
  let current=true,calls=0,revokes=[],a=null;const api={subscribe:async()=>()=>{},allow:async input=>{calls++;return a=access(input.nonce);},revoke:async nonce=>{revokes.push(nonce);return a??empty;},status:async()=>a??empty};
  const c=new ServiceVersionEditController(()=>({projectId:'native-project',api,review,current:()=>current,live:()=>current,apply:async()=>{throw Error('never');}}));await c.connect(api);
  let fired=false;c.subscribe(()=>{if(!fired&&c.getSnapshot().busy){fired=true;if(kind==='revoke')c.revoke();else{current=false;c.sourceChanged();}}});await c.allow();await flush();
  assert.equal(calls,0);assert.equal(revokes.length,1);c.dispose();
 }
});

test('terminal metadata alone never substitutes original native final or Apply return',async()=>{
 let a,applies=0;const work=deferred();const api={subscribe:async()=>()=>{},allow:async v=>a=access(v.nonce),revoke:async()=>({...a,live:false,remainingMs:0}),status:async()=>a};
 const c=new ServiceVersionEditController(()=>({projectId:'native',api,review,current:()=>true,live:()=>true,apply:()=>{applies++;return work.promise;}}));await c.connect(api);await c.allow();c.observe(pending(a));await flush();assert.equal(applies,1);
 const terminal=pending(a);terminal.request={...terminal.request,revision:2,phase:'final',settlement:'settled',result:{effect:'committed',journal:'clean',cancelled:false,applySubmitted:true}};c.observe(terminal);assert.equal(c.retains(),true);
 c.nativeFinal(id('b'),id('2'),true);assert.equal(c.retains(),true);c.nativeFinal(id('1'),id('2'),true);assert.equal(c.retains(),true);
 work.resolve();await flush();assert.equal(c.retains(),false);c.observe(terminal);assert.equal(applies,1);c.dispose();
});

test('native exact old final is retained before a coalesced request; unknown never releases',async()=>{
 for(const settled of [true,false]){
  let a,calls=0;const api={subscribe:async()=>()=>{},allow:async v=>a=access(v.nonce),revoke:async()=>({...a,live:false,remainingMs:0}),status:async()=>a};
  const c=new ServiceVersionEditController(()=>({projectId:'native',api,review,current:()=>true,live:()=>true,apply:async()=>{calls++;}}));await c.connect(api);await c.allow();c.nativeFinal(id('1'),id('2'),settled);
  const old=pending(a);old.request.phase=settled?'final':'unknown';old.request.settlement=settled?'settled':'unknown';old.request.result=settled?{effect:'not-started',journal:'not-created',cancelled:true,applySubmitted:false}:null;c.observe(old);await flush();
  assert.equal(calls,0);assert.equal(c.retains(),!settled);c.dispose();
 }
});

test('Advanced review checkbox comparison changes with the original plan, hash or values',()=>{
 let current=structuredClone(review);const api={};const c=new ServiceVersionEditController(()=>({projectId:'native',api,review:current,current:()=>true,live:()=>true,apply:async()=>{}}));
 const key=c.approvalKey();assert.equal(key,c.approvalKey());
 for(const change of [r=>r.original.planToken=id('a'),r=>r.nativeStatusRevision++,r=>r.afterSha256=hash('c'),r=>r.build='9']){
  current=structuredClone(review);change(current);assert.notEqual(c.approvalKey(),key);
 }
 c.dispose();
});
