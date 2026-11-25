// Real controller/codec methods with the existing inert Publication ports.
// These DATA results do not establish a native/provider/FS/HTTP receipt.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as publication from './github-publication.test.mjs';
import * as counter from './version-counter-setup.test.mjs';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { createAgentGithubActionPort, parseGithubActionStatus, parseAgentGithubActionAccess, sameGithubActionSelection } from '../src/agentGithubActionAccess.ts';
import { GITHUB_DISPATCH_KINDS, parseGithubDispatchSelection, parseGithubDispatchReference, parseGithubDispatchSnapshot, githubDispatchHash, githubSetupPreparedHash, githubDispatchPreparedHash, githubDispatchEffect } from '../src/githubDispatchDelegation.ts';
import { parsePublicationStatus } from '../src/githubPublicationProtocol.ts';

const copy=structuredClone, id=n=>String(n).repeat(32);
const input={kind:'setup-prepare',sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12,base:'release/setup'};
const sha=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const sorted=v=>Array.isArray(v)?v.map(sorted):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sorted(v[k])])):v;
const named=(s,n=1)=>{s=copy(s);s.operation.id=`github-publication-${n}`;return s;};
const empty={permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,status:null};
function reference(s,p){return s.kind==='setup-publish'?{kind:s.kind,sessionId:s.sessionId,consentId:s.consentId,expectedRevision:s.expectedRevision,preparedSha256:githubSetupPreparedHash(p)}:
  {kind:s.kind,sessionId:s.sessionId,expectedRevision:s.expectedRevision,requestSha256:githubDispatchHash(parseGithubDispatchSelection(s))};}
function complete(s,view){const c=view.consent;return {origin:{projectId:id(1),serviceInstance:id(2),requestId:id(4)},grantId:id(3),review:reference(s),revision:7,state:'complete',settlement:'settled',operationId:view.operation.id,
  reason:'none',effect:'none',neverAdmitted:false,doNotReplay:true,result:{type:'prepared',marker:c.id,preparedSha256:githubSetupPreparedHash(c.prepared),sourceSha:c.prepared.baseCommit,platform:null,stage:null}};}
function access(s,status=null,p){return {permissionRevision:'1',serviceInstance:id(2),projectId:id(1),grantId:id(3),review:reference(s,p),enabled:status===null,remainingMs:status===null?100000:0,consumed:status!==null,pending:false,unknown:false,status};}
async function permission(t,h){
  const calls=[];let peer=null,c;
  const port=Object.fromEntries(['access','allow','request','revoke'].map(k=>[k,(...args)=>{const d=publication.deferred();calls.push({kind:k,args,...d});return d.promise;}]));
  c=new AgentGithubActionAccessController({current:()=>({port,nativeSession:h,projectId:'project-a',epoch:h,preview:false,
    blockedReason:peer??(c?.peerSelection()&&h.controller.agentSelected(c.peerSelection())?null:h.state.delegating?'Original retained':null),
    reviews:[h.controller.dispatchSelection('setup-prepare'),h.controller.agentSelection('setup-publish')].filter(Boolean)}),
    syncOriginal:()=>h.controller.syncContext(),delegate:s=>h.controller.delegatePrepared(s)});
  t.after(async()=>{for(const q of calls)q.reject(new Error('inert end'));await publication.flush();c.dispose();h.controller.dispose();for(const q of h.calls)q.reject?.(new Error('inert end'));await publication.flush();});
  assert.equal(c.choose('setup-prepare'),true);const checking=c.check();calls.at(-1).resolve(empty);await checking;
  return {c,calls,last:k=>calls.filter(q=>q.kind===k).at(-1),peer(v){peer=v;c.syncContext();},
    async allow(){assert.equal(c.acknowledge(true),true);const s=c.getSnapshot().review;const p=c.allow();assert.equal(calls.filter(q=>q.kind==='allow').length,1);calls.at(-1).resolve(access(s));assert.equal(await p,true);return s;},
    async observed(s,st){const p=c.check();calls.at(-1).resolve(access(s,st));await publication.flush();assert.equal(calls.at(-1).kind,'request');calls.at(-1).resolve(st);await p;}};
}

test('SetupPrepare has exact purpose-absent MAIN bytes and a separate ID-only one-use grant',async()=>{
  assert.equal(GITHUB_DISPATCH_KINDS.length,13);assert.equal(GITHUB_DISPATCH_KINDS.filter(k=>k==='setup-prepare').length,1);
  const s=parseGithubDispatchSelection(sorted(input));assert.deepEqual(s,input);
  assert.equal(JSON.stringify(s),'{'+'"kind":"setup-prepare","sessionId":"session-a","expectedRevision":1,"expectedConnectionRevision":12,"base":"release/setup"}');
  assert.equal(githubDispatchHash(s),sha(input));assert.ok(parseGithubDispatchReference(reference(s)));
  assert.equal(sameGithubActionSelection(reference(s),s),true);assert.equal(sameGithubActionSelection(reference(s),{...s,base:'changed'}),false);
  for(const [key,value] of [['purpose',null],['purpose','version-counter'],['purpose','setup-pr'],['token','inert'],['home','inert'],['files',[]],['url','https://invalid.invalid'],['confirm',true]])assert.equal(parseGithubDispatchSelection({...s,[key]:value}),null);
  const calls=[],port=createAgentGithubActionPort(async(name,body)=>{calls.push([name,JSON.parse(new TextDecoder().decode(body))]);return null;});
  await port.allow(s,'0');assert.deepEqual(calls,[['allow_agent_github_action',{selection:input,consentVersion:'agent-setup-prepare-once-v1',expectedPermissionRevision:'0'}]]);
  assert.equal(githubDispatchEffect('setup-prepare','none'),true);for(const e of ['accepted','potentially-applied','draft-pr-observed','counter-observed'])assert.equal(githubDispatchEffect('setup-prepare',e),false);
});

test('large five-file comparison preserves native field order and old small-hash bounds',()=>{
  const p=publication.prepared();p.files=p.files.map((f,i)=>({...f,before:'x'.repeat(i?16384:65536),after:'x'.repeat(i?16384:65536)}));
  p.files[0].after='é\n"\\\u2028'+p.files[0].after.slice(10);assert.ok(parsePublicationStatus({...publication.review(),consent:{...publication.review().consent,prepared:p}}));
  assert.ok(Buffer.byteLength(JSON.stringify(p))>250000);assert.equal(githubSetupPreparedHash(p),sha(p));assert.equal(githubSetupPreparedHash(sorted(p)),sha(p));
  const changed=copy(p);changed.files[4].after='y'+changed.files[4].after.slice(1);assert.notEqual(githubSetupPreparedHash(changed),sha(p));
  assert.throws(()=>githubDispatchHash(p));assert.throws(()=>githubDispatchHash('x'.repeat(16385)));assert.equal(githubDispatchPreparedHash(counter.prepared()),sha(counter.prepared()));
  assert.throws(()=>githubSetupPreparedHash(counter.prepared()));assert.throws(()=>githubSetupPreparedHash({...p,purpose:null}));
  const excessive=copy(p);excessive.files[0].after='x'.repeat(65537);assert.throws(()=>githubSetupPreparedHash(excessive));
  const escaped=copy(p);escaped.files.forEach((f,i)=>{f.before='\u0001'.repeat(i?16384:65536);f.after=f.before;});assert.throws(()=>githubSetupPreparedHash(escaped));
});

test('real Allow makes no GUI Prepare call; service finality then joined native Status adopts ordinary saved:null only',async(t)=>{
  const h=await publication.attached(),p=await permission(t,h),s=await p.allow(),view=named(publication.review()),st=complete(s,view);
  assert.ok(parseGithubActionStatus(st));assert.ok(parseAgentGithubActionAccess(access(s,st)));assert.ok(Buffer.byteLength(JSON.stringify(access(s,st)))<8192);
  assert.equal(h.count('prepare'),0);assert.equal(h.count('publish'),0);h.emit(view);await h.controller.checkStatus();assert.equal(h.controller.currentConsent(),null);
  await p.observed(s,st);const d=publication.deferred(),original=h.api.githubPublicationStatus;h.api.githubPublicationStatus=()=>d.promise;
  const read=h.controller.checkStatus();await publication.flush();assert.equal(h.controller.currentConsent(),null);assert.equal(h.state.delegating,true);d.resolve(view);await read;h.api.githubPublicationStatus=original;
  assert.ok(h.controller.currentConsent());assert.equal(h.state.delegating,false);assert.equal(h.state.confirmed,false);h.controller.publish();assert.equal(h.count('publish'),0);
  assert.equal(h.controller.dispatchSelection('counter-create'),null);assert.equal(h.controller.dispatchSelection('setup-prepare'),null);
  // Finish the old permission's existing Revoke control before a new Check;
  // successful preparation alone does not auto-rearm the shared controller.
  p.c.syncContext();assert.equal(p.c.choose('setup-publish'),false);const revoke=p.c.revoke();p.last('revoke').resolve({...empty,permissionRevision:'2'});assert.equal(await revoke,true);assert.ok(h.controller.currentConsent());
  assert.equal(p.c.choose('setup-publish'),true);assert.notEqual(p.c.consentReason(),null);assert.equal(await p.c.allow(),false);
  const checking=p.c.check();p.last('access').resolve({...empty,permissionRevision:'2'});await checking;assert.equal(p.c.acknowledge(true),true);
  const publish=p.c.getSnapshot().review,allow=p.c.allow();assert.equal(p.calls.filter(q=>q.kind==='allow').length,2);p.last('allow').resolve({...access(publish,null,view.consent.prepared),permissionRevision:'3'});assert.equal(await allow,true);
  assert.equal(publish.kind,'setup-publish');assert.equal(h.count('publish'),0); // only ID submit may later enter the native publisher
});

test('ordinary compact/native purpose, source, hash and operation mismatches never adopt a review',async()=>{
  for(const fault of ['hash','source','operation','counter']){
    const h=await publication.attached(),s=h.controller.dispatchSelection('setup-prepare'),d=h.controller.delegatePrepared(s),view=named(publication.review()),st=complete(s,view);d.allowReturned();
    if(fault==='hash')st.result.preparedSha256='f'.repeat(64);if(fault==='source')st.result.sourceSha='f'.repeat(40);if(fault==='operation')st.operationId='github-publication-2';
    d.observe(st);h.emit(fault==='counter'?named(counter.review()):view);await h.controller.checkStatus();assert.equal(h.controller.currentConsent(),null,fault);assert.equal(d.released(),false,fault);assert.equal(h.count('publish'),0);
    h.controller.dispose();for(const c of h.calls)c.reject?.(new Error('inert end'));await publication.flush();
  }
});

test('lost Allow and a reentrant peer veto keep the original permission and never issue a replacement',async(t)=>{
  const h=await publication.attached(),p=await permission(t,h);assert.equal(p.c.acknowledge(true),true);const call=p.c.allow();p.last('allow').reject(new Error('inert lost Allow'));await call;
  assert.equal(p.c.getSnapshot().unknown,true);assert.equal(await p.c.allow(),false);h.emit(named(publication.review()));await h.controller.checkStatus();assert.equal(h.controller.currentConsent(),null);assert.equal(p.calls.filter(q=>q.kind==='allow').length,1);
  const other=await publication.attached(),q=await permission(t,other);let once=true;const off=other.controller.subscribe(()=>{if(once&&other.state.delegating){once=false;q.peer('inert other original');}});
  q.c.acknowledge(true);assert.equal(await q.c.allow(),false);off();assert.equal(q.calls.filter(c=>c.kind==='allow').length,0);assert.equal(other.count('prepare'),0);
});

test('base/account/Counter changes cannot adopt late ordinary preparation or bypass independent source gates',async()=>{
  for(const drift of ['base','account','purpose']){
    const h=await publication.attached(),s=h.controller.dispatchSelection('setup-prepare'),d=h.controller.delegatePrepared(s),view=named(publication.review());d.allowReturned();
    if(drift==='base')h.controller.setBase('other');if(drift==='purpose')h.controller.setPurpose('version-counter');if(drift==='account'){const c=publication.connection();c.status.account.value.id='12';h.context(c);}
    d.observe(complete(s,view));h.emit(view);await h.controller.checkStatus();assert.equal(h.controller.currentConsent(),null,drift);assert.equal(h.count('publish'),0);assert.equal(h.controller.dispatchSelection('counter-create'),null);
    h.controller.dispose();for(const c of h.calls)c.reject?.(new Error('inert end'));await publication.flush();
  }
});

test('original Stop is retained through its Promise return and never yields a new Prepare or Publish',async()=>{
  const h=await publication.attached(),s=h.controller.dispatchSelection('setup-prepare'),d=h.controller.delegatePrepared(s);d.allowReturned();h.emit(named(publication.operation('prepare','running',2)));h.controller.cancel();h.controller.cancel();
  assert.equal(h.count('cancel'),1);assert.equal(h.last('cancel').args,'github-publication-1');assert.equal(h.state.cancelling,true);assert.equal(h.controller.dispatchSelection('setup-prepare'),null);
  const final=named(publication.operation('prepare','settled',3,'cancelled'));h.emit(final);await h.controller.checkStatus();assert.equal(h.state.cancelling,true);
  h.respond('cancel',final);await publication.flush();assert.equal(h.state.cancelling,false);assert.equal(h.controller.currentConsent(),null);assert.equal(h.count('prepare'),0);assert.equal(h.count('publish'),0);h.controller.dispose();
});

test('SetupPrepare result is historical read DATA, never Counter completion or another action grant',()=>{
  const view=named(publication.review()),s=complete(input,view);assert.ok(parseGithubDispatchSnapshot(s.result,'setup-prepare'));
  for(const changed of [{...s,effect:'potentially-applied'},{...s,result:{...s.result,platform:'android'}},{...s,result:{...s.result,stage:'candidate'}},{...s,result:{type:'counter',marker:publication.consentId,commitSha:'a'.repeat(40),ledgerId:'inert',genesisSha256:'b'.repeat(64)}}])assert.equal(parseGithubActionStatus(changed),null);
  assert.equal(sameGithubActionSelection(s.review,{kind:'setup-publish',sessionId:input.sessionId,expectedRevision:input.expectedRevision,consentId:publication.consentId}),false);
});
