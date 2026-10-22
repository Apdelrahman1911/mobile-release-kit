// Actual original controllers/codec, SAME existing inert fixture ports. No
// native/provider/Host/Store receipt, process or remote mutation is exercised.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import * as preflight from './github-preflight.test.mjs';
import * as release from './github-release.test.mjs';
import * as counter from './version-counter-setup.test.mjs';
import {GITHUB_DISPATCH_KINDS,parseGithubDispatchSelection,parseGithubDispatchReference,parseGithubDispatchSnapshot,
 githubDispatchHash,githubDispatchPreparedHash,githubDispatchRecordHash,githubDispatchEffect} from '../src/githubDispatchDelegation.ts';
import {parseGithubActionStatus,parseAgentGithubActionAccess,sameGithubActionSelection,createAgentGithubActionPort} from '../src/agentGithubActionAccess.ts';
import {AgentGithubActionAccessController} from '../src/agentGithubActionAccessController.ts';
const copy=structuredClone,hex=(c,n=32)=>c.repeat(n),marker=hex('d'),sha=hex('a',40);
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const sorted=v=>Array.isArray(v)?v.map(sorted):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sorted(v[k])])):v;
const base={sessionId:'session-a',expectedRevision:1},choice={stage:'candidate',candidateRunId:null,externalRunId:null,recoveryRunId:null,originalSourceSha:null,originalVersion:null};
const selections=[
 {kind:'preflight-prepare',...base,expectedConnectionRevision:12,branch:'release/ui',platform:'android'},
 {kind:'preflight-dispatch',...base,consentId:marker,confirm:true}, {kind:'preflight-pending',...base},
 {kind:'preflight-observe',...base,marker,observe:'track',runId:'44'},
 {kind:'release-prepare',...base,expectedConnectionRevision:12,branch:'release/ui',platform:'android',selection:choice},
 {kind:'release-dispatch',...base,consentId:marker,confirm:true,confirmation:'candidate:android:2.0.0:99'},
 {kind:'release-pending',...base},{kind:'release-observe',...base,marker,observe:'reconcile',runId:null},
 {kind:'counter-prepare',...base,expectedConnectionRevision:12,base:'main',purpose:'version-counter'},
 {kind:'counter-create',...base,consentId:marker,confirm:true},{kind:'publication-pending',...base,expectedConnectionRevision:12},
 {kind:'counter-reconcile',...base,marker}];
function reference(s,original){const b={kind:s.kind,sessionId:s.sessionId,expectedRevision:s.expectedRevision};
 if(s.kind.endsWith('-prepare')||s.kind.endsWith('-pending'))return {...b,requestSha256:githubDispatchHash(parseGithubDispatchSelection(s))};
 if('consentId'in s)return {...b,consentId:s.consentId,preparedSha256:githubDispatchPreparedHash(original)};
 return {...b,marker:s.marker,recordSha256:githubDispatchRecordHash(original),...('observe'in s?{observe:s.observe,runId:s.runId}:{})};}
function resultPrepared(p){return {type:'prepared',marker:p.target.marker,preparedSha256:githubDispatchPreparedHash(p),sourceSha:p.sourceSha??p.baseCommit,platform:p.target.platform??null,stage:p.target.selection?.stage??null};}
function status(s,original,result,operationId,effect='none'){return {origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review:reference(s,original),revision:7,state:'complete',settlement:'settled',operationId,reason:'none',effect,neverAdmitted:false,doNotReplay:true,...(result?{result}:{})};}
function access(s,original,st=null){return {permissionRevision:'1',serviceInstance:hex('2'),projectId:hex('1'),grantId:hex('3'),review:reference(s,original),enabled:st===null,remainingMs:st===null?100000:0,consumed:st!==null,pending:false,unknown:false,status:st};}
const selection=(h,k)=>h.controller.dispatchSelection?h.controller.dispatchSelection(k):h.controller.agentSelection(k);
const emptyAccess={permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,status:null};
function named(s,family,n=1){s=copy(s);s.operation.id=`github-${family}-${n}`;return s;}
async function configured(f){const h=await f.attached();h.controller.setBranch('release/ui');h.controller.setPlatform('android');h.controller.setStage?.('candidate');return h;}
// The shared permission controller still owns its actual Allow/Check promises.
async function permission(t,h,kind,original){const calls=[];let peer=null;let c;
 const port=Object.fromEntries(['access','allow','request','revoke'].map(k=>[k,(...args)=>{const d=preflight.deferred();calls.push({kind:k,args,...d});return d.promise;}]));
 c=new AgentGithubActionAccessController({current:()=>({port,nativeSession:h,projectId:'project-a',epoch:h,preview:false,
  blockedReason:peer??(c?.peerSelection()&&h.controller.agentSelected(c.peerSelection())?null:h.state.delegating?'original retained':null),reviews:GITHUB_DISPATCH_KINDS.map(k=>selection(h,k)).filter(Boolean)}),
  syncOriginal:()=>h.controller.syncContext(),delegate:s=>h.controller.delegatePrepared(s)});
 t.after(async()=>{for(const d of calls)d.reject({code:'inert-end'});await preflight.flush();c.dispose();h.controller.dispose();for(const d of h.calls)d.reject?.({code:'inert-end'});await preflight.flush();});
 assert.equal(c.choose(kind),true);const checked=c.check();calls.at(-1).resolve(emptyAccess);await checked;
 return {c,calls,last:k=>calls.filter(v=>v.kind===k).at(-1),peer(v){peer=v;c.syncContext();},async allow(){assert.equal(c.consentReason(),null);assert.equal(c.acknowledge(true),true);const s=c.getSnapshot().review;assert.ok(s);const pending=c.allow();assert.equal(calls.filter(v=>v.kind==='allow').length,1);calls.at(-1).resolve(access(s,original));assert.equal(await pending,true);assert.equal(c.getSnapshot().unknown,false);return s;}};
}

test('twelve exact MAIN selections preserve separate confirmation and hashes; no CLI/private argument widening',async()=>{
 assert.deepEqual(selections.map(s=>s.kind),GITHUB_DISPATCH_KINDS.filter(k=>k!=='setup-prepare'));const calls=[];const port=createAgentGithubActionPort(async(n,b)=>{calls.push([n,JSON.parse(new TextDecoder().decode(b))]);return null;});
 for(const s of selections){assert.ok(parseGithubDispatchSelection(s),s.kind);await port.allow(s,'0');const sent=calls.at(-1)[1];assert.equal(sent.consentVersion,`agent-${s.kind}-once-v1`);assert.equal(sent.expectedPermissionRevision,'0');
  for(const k of ['token','root','ledgerId','projectId','workflow','force','url'])assert.equal(parseGithubDispatchSelection({...s,[k]:'INERT'}),null);}
 const r=reference(selections[0]);assert.ok(parseGithubDispatchReference(r));assert.equal(parseGithubDispatchSelection(r),null);assert.equal(parseGithubDispatchReference(selections[0]),null);
 assert.equal(sameGithubActionSelection(r,selections[0]),true);assert.equal(sameGithubActionSelection(r,{...selections[0],branch:'different'}),false);
 for(const v of [{...selections[3],runId:null},{...selections[7],runId:'44'},{...selections[8],purpose:'setup-pr'},{...selections[5],confirmation:''},{...selections[1],confirm:false}])assert.equal(parseGithubDispatchSelection(v),null);
 assert.equal(githubDispatchEffect('counter-reconcile','counter-observed'),true);assert.equal(githubDispatchEffect('counter-reconcile','potentially-applied'),false);assert.equal(githubDispatchEffect('release-prepare','accepted'),false);
});
test('bounded SHA comparison uses exact native declaration ordering, not frontend property order or public authority',()=>{
 for(const v of [null,{},'abc','x'.repeat(300),{x:'\u2028/é',a:[1,null]}])assert.equal(githubDispatchHash(v),hash(v));
 for(const f of [preflight,release,counter]){const p=f.prepared();assert.equal(githubDispatchPreparedHash(p),githubDispatchPreparedHash(sorted(p)));}
 // Preflight and Counter fixtures deliberately use the actual native field order.
 assert.equal(githubDispatchPreparedHash(preflight.prepared()),hash(preflight.prepared()));
 assert.equal(githubDispatchPreparedHash(counter.prepared()),hash(counter.prepared()));
 const s=copy(selections[4]);s.selection=Object.fromEntries(Object.entries(s.selection).reverse());assert.equal(githubDispatchHash(parseGithubDispatchSelection(s)),hash(selections[4]));
 assert.throws(()=>githubDispatchHash('x'.repeat(16385)));
});
test('single bounded compact result rejects 65th/duplicate rows, explicit null abuse and cross-family effects',()=>{
 const rows=Array.from({length:64},(_,n)=>({marker:(n+1).toString(16).padStart(32,'0'),runId:'18446744073709551615',purpose:'preflight'}));
 const s=status(selections[2],null,{type:'pending',rows},'github-preflight-1');assert.ok(parseGithubActionStatus(s));assert.ok(parseAgentGithubActionAccess(access(selections[2],null,s)));assert.ok(Buffer.byteLength(JSON.stringify(access(selections[2],null,s)))<8192);
 assert.equal(parseGithubActionStatus({...s,result:{type:'pending',rows:[...rows,rows[0]]}}),null);assert.equal(parseGithubDispatchSnapshot({type:'pending',rows:[rows[0],rows[0]]},'preflight-pending'),null);
 assert.equal(parseGithubDispatchSnapshot({type:'pending',rows},'publication-pending'),null);assert.equal(parseGithubActionStatus({...s,snapshot:{}}),null);assert.equal(parseGithubActionStatus({...s,state:'running',settlement:'pending'}),null);
 let getters=0;const raw={...selections[0]};Object.defineProperty(raw,'branch',{enumerable:true,get(){getters++;return 'main';}});assert.equal(parseGithubDispatchSelection(raw),null);assert.equal(getters,0);
});
for(const [family,f] of [['preflight',preflight],['release',release]]){
 test(`${family}: real shared Allow and service return still need a later joined native read; Prepared is not dispatch consent`,async(t)=>{
  const h=await configured(f),p=await permission(t,h,`${family}-prepare`),s=await p.allow();assert.equal(h.count('prepare'),0);assert.equal(h.state.delegating,true);
  const view=named(f.review(),family),st=status(s,null,resultPrepared(view.prepared),view.operation.id);assert.ok(parseGithubActionStatus(st));
  h.emit(view);await h.controller.checkStatus();assert.equal(h.controller.currentPrepared(),null);assert.equal(h.state.delegating,true);
  const checking=p.c.check();p.last('access').resolve(access(s,null,st));await preflight.flush();p.last('request').resolve(st);await checking;
  const native=h.api[`github${family==='preflight'?'Preflight':'Release'}Status`],d=f.deferred();h.api[`github${family==='preflight'?'Preflight':'Release'}Status`]=()=>d.promise;
  const reading=h.controller.checkStatus();await f.flush();assert.equal(h.controller.currentPrepared(),null);d.resolve(view);await reading;h.api[`github${family==='preflight'?'Preflight':'Release'}Status`]=native;
  assert.equal(h.state.delegating,false);assert.ok(h.controller.currentPrepared());assert.equal(h.controller.agentSelection(`${family}-dispatch`),null);assert.equal(h.count('dispatch'),0);
  h.controller.setConfirmed(true);if(family==='release')h.controller.setConfirmation(view.prepared.confirmation);assert.ok(h.controller.agentSelection(`${family}-dispatch`));
 });
 test(`${family}: delegated Pending needs an explicit original row; Observe spends no dispatch and cannot select another run`,async(t)=>{
  const h=await configured(f),s=h.controller.agentSelection(`${family}-pending`),d=h.controller.delegatePrepared(s);assert.ok(d?.current());d.allowReturned();
  const view=named({...f.operation('pending','settled',3),pending:[{prepared:f.prepared(),runId:'44'}]},family),st=status(s,null,{type:'pending',rows:[{marker,runId:'44',purpose:family}]},view.operation.id);
  d.observe(st);h.emit(view);await h.controller.checkStatus();assert.equal(d.released(),true);assert.equal(h.controller.agentSelection(`${family}-observe`),null);
  assert.equal(h.controller.selectRecordForAgent(marker),true);const observe=h.controller.agentSelection(`${family}-observe`);assert.equal(observe.runId,'44');assert.equal(h.controller.agentSelected({...observe,runId:'45'}),false);
  const od=h.controller.delegatePrepared(observe);od.allowReturned();const final=named(f.observed(5),family,2),of=status(observe,view.pending[0],{type:'observed',marker,runId:'44',attempt:1,status:'queued',conclusion:null},final.operation.id);
  od.observe(of);h.emit(final);await h.controller.checkStatus();assert.equal(od.released(),true);assert.equal(h.count('dispatch'),0);assert.equal(h.count('track'),0);h.controller.dispose();
 });
 test(`${family}: lost Allow and post-delegation context ABA cannot revive an original Prepared`,async(t)=>{
  const h=await configured(f),p=await permission(t,h,`${family}-prepare`);p.c.acknowledge(true);const call=p.c.allow();p.last('allow').reject(new Error('inert lost reply'));await call;
  const view=named(f.review(),family);h.emit(view);await h.controller.checkStatus();assert.equal(p.c.getSnapshot().unknown,true);assert.equal(h.controller.currentPrepared(),null);assert.equal(await p.c.allow(),false);
  const other=await configured(f),sel=other.controller.agentSelection(`${family}-prepare`),d=other.controller.delegatePrepared(sel);d.allowReturned();other.context({...f.connection(),context:null});other.context(f.connection());
  d.observe(status(sel,null,resultPrepared(view.prepared),view.operation.id));other.emit(view);await other.controller.checkStatus();assert.equal(other.controller.currentPrepared(),null);other.controller.dispose();
 });
 test(`${family}: ordinary producer call and lost acknowledgement retain original observer until actual post-return read`,async()=>{
  const h=await configured(f);h.controller.prepare();h.emit(f.review());await h.controller.checkStatus();assert.equal(h.state.pending,true);assert.equal(h.controller.currentPrepared(),null);assert.equal(h.controller.agentSelection(`${family}-dispatch`),null);
  h.last('prepare').reject(new Error('inert lost Prepare'));await f.flush();h.emit(f.review());assert.equal(h.state.pending,true);await h.controller.checkStatus();assert.equal(h.state.pending,false);assert.ok(h.controller.currentPrepared());h.controller.dispose();
 });
}
test('Counter Prepare reuses actual saved-source witness; generated private review needs a separate Create selection',async(t)=>{
 const h=await counter.fixture(t),p=await permission(t,h,'counter-prepare'),s=await p.allow(),view=named(counter.review(),'publication');
 const st=status(s,null,{...resultPrepared(view.consent.prepared),marker:view.consent.id},view.operation.id);assert.ok(parseGithubActionStatus(st));h.emit(view);await h.controller.checkStatus();assert.equal(h.controller.currentConsent(),null);
 const c=p.c.check();p.last('access').resolve(access(s,null,st));await counter.flush();p.last('request').resolve(st);await c;await h.controller.checkStatus();assert.ok(h.controller.currentConsent());assert.equal(h.controller.dispatchSelection('counter-create'),null);
 h.controller.setConfirmed(true);assert.ok(h.controller.dispatchSelection('counter-create'));assert.equal(h.count('publish'),0);assert.equal(h.count('prepare'),0);
});
test('Counter local Pending remains a separate producer from its GET-only successor and never grants Create',async(t)=>{
 const h=await counter.fixture(t),s=h.controller.dispatchSelection('publication-pending'),d=h.controller.delegatePrepared(s);assert.ok(d?.current());d.allowReturned();
 const row=counter.pending(),view=named({...counter.operation('pending','settled',3),pending:[row]},'publication');const st=status(s,null,{type:'pending',rows:[{marker,runId:null,purpose:'counter'}]},view.operation.id);
 d.observe(st);h.emit(view);await h.controller.checkStatus();assert.equal(d.released(),true);assert.equal(h.controller.dispatchSelection('counter-reconcile'),null);
 assert.equal(h.controller.selectCounterRecordForAgent(marker),true);const sel=h.controller.dispatchSelection('counter-reconcile');assert.ok(sel);assert.equal(h.controller.dispatchSelection('counter-create'),null);
 const next=h.controller.delegatePrepared(sel);next.allowReturned();const final=named(counter.observed(5,'reconcile'),'publication',2);next.observe(status(sel,row,{type:'counter',marker,commitSha:final.counter.commit,ledgerId:final.counter.ledgerId,genesisSha256:final.counter.genesisSha256},final.operation.id,'counter-observed'));
 h.emit(final);await h.controller.checkStatus();assert.equal(next.released(),true);assert.equal(h.count('publish'),0);h.controller.dispose();
});
test('Counter delegated saved-source change and reentrant peer veto retain exact originals without a false Prepare',async(t)=>{
 const h=await counter.fixture(t),p=await permission(t,h,'counter-prepare');p.c.acknowledge(true);let changed=false;
 h.controller.subscribe(()=>{if(!changed&&h.state.delegating){changed=true;p.peer('other original');}});assert.equal(await p.c.allow(),false);assert.equal(p.calls.filter(c=>c.kind==='allow').length,0);await h.controller.checkStatus();assert.equal(h.count('prepare'),0);
 const q=await counter.fixture(t),s=q.controller.dispatchSelection('counter-prepare'),d=q.controller.delegatePrepared(s);d.allowReturned();q.controller.versionIntent();
 const view=named(counter.review(),'publication');d.observe(status(s,null,{...resultPrepared(view.consent.prepared),marker:view.consent.id},view.operation.id));q.emit(view);await q.controller.checkStatus();assert.equal(q.controller.currentConsent(),null);assert.equal(q.count('publish'),0);
 for(const c of q.calls)c.reject?.({code:'inert-end'});q.controller.dispose();await counter.flush();
});

for(const [family,f] of [['preflight',preflight],['release',release],['counter',counter]]) {
 test(`${family}: separately confirmed existing Prepared delegates one mutation; no original GUI send or status-derived retry`,async(t)=>{
  const h=family==='counter'?await f.ready(t):await f.ready();
  h.controller.setConfirmed(true);if(family==='release')h.controller.setConfirmation(f.prepared().confirmation);
  const k=family==='counter'?'counter-create':`${family}-dispatch`,s=selection(h,k),original=family==='counter'?h.controller.currentConsent().prepared:h.controller.currentPrepared();assert.ok(s);
  const p=await permission(t,h,k,original);const allowed=await p.allow();assert.equal(h.controller.agentSelected({...allowed,expectedRevision:allowed.expectedRevision+1}),false);
  if(family==='counter')h.controller.publish();else h.controller.dispatch();assert.equal(h.count(family==='counter'?'publish':'dispatch'),0);
  const view=named(family==='counter'?f.observed():f.dispatchResult(),family==='counter'?'publication':family,2);
  const result=family==='counter'?{type:'counter',marker:s.consentId,commitSha:view.counter.commit,ledgerId:view.counter.ledgerId,genesisSha256:view.counter.genesisSha256}:null;
  const st=status(s,original,result,view.operation.id,family==='counter'?'counter-observed':'accepted');assert.ok(parseGithubActionStatus(st));
  h.emit(view);await h.controller.checkStatus();assert.equal(h.state.delegating,true);
  const check=p.c.check();p.last('access').resolve(access(s,original,st));await f.flush();p.last('request').resolve(st);await check;await h.controller.checkStatus();
  assert.equal(h.state.delegating,false);assert.equal(selection(h,k),null);assert.equal(h.count(family==='counter'?'publish':'dispatch'),0);
 });
}
