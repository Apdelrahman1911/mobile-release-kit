// The existing real controllers and deferred caller fixture; all facts are
// inert DATA. No provider, IPC, filesystem, native receipt or qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fixture, fixtureData, flush, deferred, consentId, draft, run, hex } from './agent-github-actions.test.mjs';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { parseGithubActionSelection, parseGithubActionStatus, parseAgentGithubActionAccess, createAgentGithubActionPort, sameGithubActionSelection, GITHUB_ACTION_KINDS } from '../src/agentGithubActionAccess.ts';
import { GITHUB_OPERATION_KINDS, parseGithubOperationSelection, parseGithubOperationSnapshot, githubOperationPreparedHash, githubOperationRecord, githubOperationRecordHash } from '../src/githubOperationDelegation.ts';
import { githubDispatchHash } from '../src/githubDispatchDelegation.ts';
import { pullRequestConfirmation } from '../src/githubPullRequestProtocol.ts';
import { actionsRetryConfirmation } from '../src/githubActionsRetryProtocol.ts';
const copy=structuredClone,families=[['repository-create','repository'],['draft-pr-create','pr'],['failed-jobs-retry','failed-jobs']];
const empty={permissionRevision:'0',serviceInstance:null,projectId:null,grantId:null,review:null,enabled:false,remainingMs:0,consumed:false,pending:false,unknown:false,status:null};
function reference(s,record=null){const base={kind:s.kind,sessionId:s.sessionId,expectedRevision:s.expectedRevision};return 'marker'in s?{...base,marker:s.marker,recordSha256:githubOperationRecordHash(record)}:{...base,requestSha256:githubDispatchHash(s)};}
function result(h,kind,native,selected,record=null){
 const review=reference(selected,record),phase=kind.endsWith('-prepare')?'prepared':kind.endsWith('-pending')?'pending':'reconciled';
 let output;if(phase==='prepared')output={type:'operation',phase,consentId:native.consent.id,preparedSha256:githubOperationPreparedHash(native.consent.prepared),next:h.kind};
 else if(phase==='pending')output={type:'operation',phase,rows:native.pending.map(githubOperationRecord)};
 else output={type:'operation',phase,marker:selected.marker,effect:native.operation.effect,observed:native.observed?(h.kind==='repository-create'?{target:'repository',id:native.observed.id}:h.kind==='draft-pr-create'?{target:'pr',id:native.observed.id,number:native.observed.number}:{target:'failed-jobs',runId:native.observed.id,attempt:native.observed.attempt}):null};
 const status={origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review,revision:7,state:native.operation.reason==='none'?'complete':'refused',settlement:'settled',operationId:native.operation.id,reason:native.operation.reason==='none'?'none':'native-refused',effect:native.operation.effect,neverAdmitted:false,doNotReplay:true,result:output};
 assert.ok(parseGithubActionStatus(status),'closed original service result');return status;
}
function access(selection,status=null,record=null,patch={}){const value={permissionRevision:'1',serviceInstance:hex('2'),projectId:hex('1'),grantId:hex('3'),review:status?.review??reference(selection,record),enabled:status===null,remainingMs:status===null?100000:0,consumed:status!==null,pending:status!==null&&status.settlement!=='settled',unknown:status?.state==='unknown',status,...patch};assert.ok(parseAgentGithubActionAccess(value));return value;}
async function permission(h,kind){
 const calls=[],native={};for(const name of ['access','allow','request','revoke'])native[name]=(arg,revision)=>{const d=deferred();Object.assign(d,{kind:'permission-'+name,args:copy(arg),revision});calls.push(d);h.calls.push(d);return d.promise;};
 let peer=null,c;const epoch={};c=new AgentGithubActionAccessController({current:()=>({port:native,nativeSession:h,projectId:'project-a',epoch,preview:false,blockedReason:peer??(c?.peerSelection()&&h.controller.agentSelected(c.peerSelection())?null:h.controller.ownerReason()),reviews:[...GITHUB_OPERATION_KINDS.map(k=>h.controller.agentSelection(k)),h.controller.agentSelection()].filter(Boolean)}),syncOriginal:()=>h.controller.syncContext(),delegate:r=>h.controller.delegatePrepared(r)});
 c.choose(kind);c.syncContext();const p={controller:c,last:k=>calls.filter(x=>x.kind==='permission-'+k).at(-1),count:k=>calls.filter(x=>x.kind==='permission-'+k).length,peer(v){peer=v;c.syncContext();}};h.permission=p;
 const check=c.check();p.last('access').resolve(empty);await check;return p;
}
function pending(h,count=32){
 const value=copy(h.data.review());value.consent=null;value.operation.kind='pending';
 if(h.kind==='draft-pr-create')value.operation.target.intent=null;else if(h.kind==='failed-jobs-retry')value.operation.target.selection=null;
 value.pending=Array.from({length:count},(_,n)=>{const p=copy(h.data.review().consent.prepared),marker=n.toString(16).padStart(32,'0');if(h.kind==='repository-create'){p.target.marker=marker;p.confirmation=h.data.review().consent.prepared.confirmation;}else if(h.kind==='draft-pr-create'){p.target.intent.marker=marker;p.confirmation=pullRequestConfirmation(p.target);}else{p.target.selection.marker=marker;p.target.selection.runId=String(31+n);p.run.id=String(31+n);p.confirmation=actionsRetryConfirmation(p.target,p.run);}
 return {prepared:p,claimed:false,acknowledged:h.kind==='failed-jobs-retry'?false:null};});
 assert.ok(h.data.parser(value),'all original Pending rows valid');return value;
}
function delegate(h,kind){const selected=h.controller.agentSelection(kind);assert.ok(selected,kind);const d=h.controller.delegatePrepared(selected);assert.ok(d);assert.equal(d.current(),true);d.allowReturned();return{selected,d};}

// Every old mutation encoding remains unchanged. The new private input cannot
// leak through service rows, result fields or CLI arguments.
test('operation: all nine strict input/reference forms retain original PR modes and ID-only CLI',async()=>{
 assert.equal(new Set(GITHUB_ACTION_KINDS).size,GITHUB_ACTION_KINDS.length);
 for(const kind of GITHUB_OPERATION_KINDS)assert.ok(GITHUB_ACTION_KINDS.includes(kind));
 for(const [old,prefix]of families){const h=await fixture(old,false);for(const phase of ['prepare','pending']){const s=h.controller.agentSelection(`${prefix}-${phase}`);assert.ok(parseGithubActionSelection(s));const r=reference(s);assert.ok(sameGithubActionSelection(r,s));assert.equal(JSON.stringify(r).includes('Tested locally.'),false);assert.equal(sameGithubActionSelection(r,{...s,expectedRevision:s.expectedRevision+1}),false);for(const k of ['token','url','root','confirm','prepared'])assert.equal(parseGithubActionSelection({...s,[k]:'INERT'}),null);}
 const s={kind:`${prefix}-reconcile`,sessionId:'session-a',expectedRevision:1,marker:hex('a')};assert.ok(parseGithubOperationSelection(s));assert.equal(parseGithubOperationSelection({...s,record:{}}),null);}
 let gets=0;const raw={sessionId:'session-a',expectedRevision:1};Object.defineProperty(raw,'kind',{enumerable:true,get(){gets++;return'pr-prepare';}});assert.equal(parseGithubActionSelection(raw),null);assert.equal(gets,0);
});
test('operation: full private PR fits original16KiB modes with canonical hash and separate consent',async()=>{
 const calls=[],port=createAgentGithubActionPort(async(name,body)=>{calls.push([name,body]);return null;});
 for(const ready of [false,true]){const raw={kind:'pr-prepare',sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:2,draft:{base:'b'.repeat(200),head:'h'.repeat(200),title:'é'.repeat(128),body:'"\\\n'.repeat(1365)+'x',...(ready?{creationMode:'ready-for-review'}:{})}};
 const s=parseGithubActionSelection(raw);assert.ok(s);await port.allow(s,'8');assert.ok(calls.at(-1)[1].length>4096&&calls.at(-1)[1].length<=16896);const sent=JSON.parse(new TextDecoder().decode(calls.at(-1)[1]));assert.equal(sent.consentVersion,'agent-pr-prepare-once-v1');assert.equal(sent.expectedPermissionRevision,'8');assert.equal(githubDispatchHash(s),createHash('sha256').update(JSON.stringify(s)).digest('hex'));
 assert.equal(parseGithubActionSelection({...raw,draft:{...raw.draft,creationMode:null}}),null);assert.equal(parseGithubActionSelection({...raw,draft:{...raw.draft,body:'x'.repeat(4097)}}),null);}
 assert.equal(calls.length,2);
});
for(const [old,prefix]of families){
 test(`operation: ${prefix} service-final and native event never substitute for original Status caller`,async()=>{
  const h=await fixture(old,false),{selected,d}=delegate(h,`${prefix}-prepare`),native=h.data.review();h.deferStatus=true;h.emit(native);assert.equal(h.controller.agentSelection(),null);
  d.observe(result(h,selected.kind,native,selected));assert.equal(d.released(),false);assert.equal(h.calls.filter(c=>c.kind==='prepare').length,0);assert.equal(h.calls.filter(c=>c.kind==='status'&&!c.ended).length,1);
  h.respond('status',native);await flush();assert.equal(d.released(),true);assert.equal(h.controller.agentSelection().kind,old);assert.equal(h.calls.filter(c=>['create','start'].includes(c.kind)).length,0);
 });
 test(`operation: ${prefix} cold native prepared or public pending cannot manufacture private continuation`,async()=>{
  const h=await fixture(old,false);h.emit(h.data.review());h.controller.checkStatus();await flush();assert.equal(h.controller.agentSelection(),null);assert.equal(h.controller.delegatePrepared({kind:old,sessionId:'session-a',expectedRevision:3,consentId}),null);
  const p=await fixture(old,false),rows=pending(p);p.emit(rows);p.controller.checkStatus();await flush();assert.equal(p.controller.selectRecordForAgent(githubOperationRecord(rows.pending[0]).marker),false);assert.equal(p.controller.agentSelection(`${prefix}-reconcile`),null);
 });
 test(`operation: ${prefix} complete full32 Pending and original exact row select Reconcile without replay`,async()=>{
  const h=await fixture(old,false),{selected,d}=delegate(h,`${prefix}-pending`),native=pending(h);h.retain(native);const final=result(h,selected.kind,native,selected);d.observe(final);await flush();assert.equal(d.released(),true);assert.equal(final.result.rows.length,32);assert.ok(new TextEncoder().encode(JSON.stringify(final)).length<=8192);
  const row=native.pending[31],marker=githubOperationRecord(row).marker;assert.equal(h.controller.selectRecordForAgent(marker),true);const sel=h.controller.agentSelection(`${prefix}-reconcile`);assert.ok(sel);const next=h.controller.delegatePrepared(sel);assert.ok(next);next.allowReturned();
  const rec={...native,revision:4,operation:{...native.operation,id:native.operation.id.replace(/1$/,'2'),kind:'reconcile',target:row.prepared.target,reason:'unresolved',effect:'unresolved'}};assert.ok(h.data.parser(rec));h.retain(rec);next.observe(result(h,sel.kind,rec,sel,row));await flush();assert.equal(next.released(),true);assert.equal(h.calls.filter(c=>['prepare','create','start','reconcile'].includes(c.kind)).length,0);
 });
 test(`operation: ${prefix} failed history remains retained despite original native success and later positive DATA`,async()=>{
  const h=await fixture(old,false),{selected,d}=delegate(h,`${prefix}-prepare`),native=h.data.review();h.retain(native);const final=result(h,selected.kind,native,selected),unknown={...final,state:'unknown',settlement:'unknown',reason:'history-unavailable'};delete unknown.result;d.observe(unknown);d.observe(final);h.controller.checkStatus();await flush();assert.equal(d.released(),false);assert.equal(h.controller.agentSelection(),null);assert.ok(h.controller.ownerReason());
 });
}
test('operation: repository uses verified account without pretending selected repository is observed',async()=>{
 const h=await fixture('repository-create',false),c=copy(h.connection());c.status.repository={state:'unavailable',value:null};h.changeConnection(c);assert.ok(h.controller.agentSelection('repository-prepare'));assert.ok(h.controller.agentSelection('repository-pending'));
 c.status.account={state:'unavailable',value:null};h.changeConnection(c);assert.equal(h.controller.agentSelection('repository-prepare'),null);
});
test('operation: PR ready-for-review is original mode and only its matching next kind is eligible',async()=>{
 const h=await fixture('draft-pr-create',false);h.controller.setCreationMode('ready-for-review');const {selected,d}=delegate(h,'pr-prepare');assert.equal(selected.draft.creationMode,'ready-for-review');
 const native=h.data.review();native.operation.target.intent.creationMode='ready-for-review';native.consent.prepared.target.intent.creationMode='ready-for-review';native.consent.prepared.draft=false;native.consent.prepared.confirmation=pullRequestConfirmation(native.consent.prepared.target);assert.ok(h.data.parser(native));h.retain(native);const final=result(h,'pr-prepare',native,selected);final.result.next='pr-create';d.observe(final);await flush();assert.equal(d.released(),true);assert.equal(h.controller.agentSelection().kind,'pr-create');
});
test('operation: original draft and Activity identity cannot be rebound by equal-looking status',async()=>{
 const h=await fixture('draft-pr-create',false),{selected,d}=delegate(h,'pr-prepare');h.controller.setDraft('body','Changed');h.controller.setDraft('body',draft.body);assert.equal(d.current(),false);const native=h.data.review();h.retain(native);d.observe(result(h,'pr-prepare',native,selected));await flush();assert.equal(h.controller.agentSelection(),null);
 const r=await fixture('failed-jobs-retry',false),q=delegate(r,'failed-jobs-prepare');r.data.activity={...r.data.activity,revision:20};assert.equal(q.d.current(),false);assert.equal(r.calls.filter(c=>c.kind==='start').length,0);
});
test('operation: maximum rows validate all fields without slicing or laundering closed/ACK state',()=>{
 const rows=Array.from({length:32},(_,i)=>({marker:i.toString(16).padStart(32,'0'),recordSha256:hex('a',64),claimed:true,acknowledged:true,closed:false})),raw={type:'operation',phase:'pending',rows};assert.ok(parseGithubOperationSnapshot(raw,'pr-pending'));assert.equal(parseGithubOperationSnapshot({...raw,rows:[...rows,rows[0]]},'pr-pending'),null);const dup=copy(raw);dup.rows[31]=dup.rows[0];assert.equal(parseGithubOperationSnapshot(dup,'pr-pending'),null);const bad=copy(raw);bad.rows[0].claimed=false;assert.equal(parseGithubOperationSnapshot(bad,'pr-pending'),null);bad.rows[0]={...rows[0],closed:true};assert.ok(parseGithubOperationSnapshot(bad,'pr-pending'));assert.equal(parseGithubOperationSnapshot(bad,'repository-pending'),null);
 for(const observed of [undefined,{}, {target:'pr',id:31,number:'3'},{target:'pr',id:'01',number:'3'}])assert.equal(parseGithubOperationSnapshot({type:'operation',phase:'reconciled',marker:hex('a'),effect:'found-unattributed',observed},'pr-reconcile'),null);
 assert.ok(parseGithubOperationSnapshot({type:'operation',phase:'reconciled',marker:hex('a'),effect:'found-unattributed',observed:{target:'pr',id:'18446744073709551615',number:'3'}},'pr-reconcile'));
});
test('operation: actual permission controller requires completed old Revoke/Check before fresh Create Allow',async()=>{
 const h=await fixture('repository-create',false),selected=h.controller.agentSelection('repository-prepare'),p=await permission(h,'repository-prepare');assert.equal(p.controller.acknowledge(true),true);const allow=p.controller.allow();assert.equal(p.count('allow'),1);p.last('allow').resolve(access(selected));await allow;
 const native=h.data.review();h.retain(native);const final=result(h,selected.kind,native,selected);const check=p.controller.check();p.last('access').resolve(access(selected,final));await flush();p.last('request').resolve(final);await check;await flush();assert.ok(h.controller.agentSelection());assert.ok(p.controller.ownerReason());
 p.controller.choose('repository-create');assert.equal(await p.controller.allow(),false);assert.equal(p.count('allow'),1);
 const revoke=p.controller.revoke();p.last('revoke').resolve(access(selected,final));await revoke;await flush();assert.equal(p.controller.ownerReason(),null);assert.ok(h.controller.agentSelection());
 p.controller.choose('repository-create');const fresh=p.controller.check();p.last('access').resolve(access(selected,final,null,{permissionRevision:'2'}));await fresh;assert.equal(p.controller.acknowledge(true),true);const create=p.controller.allow();assert.equal(p.count('allow'),2);assert.equal(p.last('allow').args.kind,'repository-create');p.last('allow').reject({code:'inert-do-not-enter'});await create;assert.equal(h.calls.filter(c=>c.kind==='create').length,0);
});
test('operation: reentrant peer change before Allow sends nothing and cannot discard a foreign native review',async()=>{
 const h=await fixture('repository-create',false),p=await permission(h,'repository-prepare');assert.equal(p.controller.acknowledge(true),true);let fired=false;const stop=h.controller.subscribe(()=>{if(!fired&&h.controller.agentSelection('repository-prepare')===null){fired=true;p.peer('Other original entered');}});assert.equal(await p.controller.allow(),false);stop();await flush();assert.equal(p.count('allow'),0);assert.equal(h.calls.filter(c=>['prepare','discard','create'].includes(c.kind)).length,0);
});
test('operation: lost Allow and genuine never-admitted/unused closures are distinct',async()=>{
 const h=await fixture('repository-create',false),p=await permission(h,'repository-prepare');p.controller.acknowledge(true);const allow=p.controller.allow();p.last('allow').reject(new Error('inert lost reply'));await allow;assert.equal(p.controller.getSnapshot().unknown,true);assert.ok(h.controller.ownerReason());assert.equal(h.controller.agentSelection(),null);
 const n=await fixture('repository-create',false),selected=n.controller.agentSelection('repository-prepare'),d=n.controller.delegatePrepared(selected);d.notSubmitted();await flush();assert.equal(d.released(),true);assert.equal(n.calls.filter(c=>c.kind==='prepare').length,0);
});
test('operation: historical Reconcile effects remain exact non-success DATA, never a successful result',()=>{
 for(const [old,prefix]of families){
  const review={kind:`${prefix}-reconcile`,sessionId:'session-a',expectedRevision:3,marker:hex('a'),recordSha256:hex('c',64)};
  const base={origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review,revision:7,state:'cancelled',settlement:'settled',operationId:(old==='repository-create'?'repository-create-':old==='draft-pr-create'?'github-pull-request-':'github-actions-retry-')+'2',reason:'user-cancelled',effect:'none',neverAdmitted:false,doNotReplay:true};
  for(const effect of ['potentially-applied','acknowledged-unconfirmed','accepted-unconfirmed']){
   const allowed=effect==='potentially-applied'||effect==='acknowledged-unconfirmed'&&prefix==='pr'||effect==='accepted-unconfirmed'&&prefix==='failed-jobs';
   for(const state of ['finishing','refused','cancelled'])assert.equal(!!parseGithubActionStatus({...base,state,settlement:state==='finishing'?'pending':'settled',effect}),allowed,`${prefix}/${state}/${effect}`);
   const result={type:'operation',phase:'reconciled',marker:hex('a'),effect,observed:null};
   assert.equal(parseGithubOperationSnapshot(result,review.kind),null);
   assert.equal(parseGithubActionStatus({...base,state:'complete',reason:'none',effect,result}),null);
   assert.equal(parseGithubActionStatus({...base,review:{kind:`${prefix}-prepare`,sessionId:'session-a',expectedRevision:3,requestSha256:hex('c',64)},effect}),null);
  }
 }
});
for(const [old,prefix,effect]of [['draft-pr-create','pr','acknowledged-unconfirmed'],['failed-jobs-retry','failed-jobs','accepted-unconfirmed']]){
 test(`operation: ${prefix} historical ACK cancellation keeps actual caller and permission retirement without false Unknown`,async()=>{
  const h=await fixture(old,false),q=delegate(h,`${prefix}-pending`),native=pending(h,1),row=native.pending[0];
  row.claimed=true;row.acknowledged=copy(h.data.final().acknowledged);assert.ok(h.data.parser(native));
  h.retain(native);q.d.observe(result(h,q.selected.kind,native,q.selected));await flush();assert.equal(q.d.released(),true);
  assert.equal(h.controller.selectRecordForAgent(githubOperationRecord(row).marker),true);
  const selected=h.controller.agentSelection(`${prefix}-reconcile`),p=await permission(h,`${prefix}-reconcile`);
  assert.ok(selected);assert.equal(p.controller.acknowledge(true),true);const allow=p.controller.allow();p.last('allow').resolve(access(selected,null,row));await allow;
  const rec={...native,revision:4,acknowledged:copy(row.acknowledged),operation:{...native.operation,id:native.operation.id.replace(/1$/,'2'),kind:'reconcile',target:row.prepared.target,reason:'cancelled',effect}};
  assert.ok(h.data.parser(rec),'the actual old native historical-ACK shape');
  const final={origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review:reference(selected,row),revision:7,state:'cancelled',settlement:'settled',operationId:rec.operation.id,reason:'user-cancelled',effect,neverAdmitted:false,doNotReplay:true};
  assert.ok(parseGithubActionStatus(final));assert.equal(Object.hasOwn(final,'result'),false);
  const finishing={...final,revision:6,state:'finishing',settlement:'pending'};
  const first=p.controller.check();p.last('access').resolve(access(selected,finishing,row));await flush();p.last('request').resolve(finishing);await first;
  assert.equal(p.controller.getSnapshot().unknown,false);assert.ok(h.controller.ownerReason());
  h.deferStatus=true;h.retain(rec);const check=p.controller.check();p.last('request').resolve(final);await check;await flush();
  assert.equal(p.controller.getSnapshot().unknown,false);assert.equal(p.controller.getSnapshot().status.effect,effect);assert.ok(h.controller.ownerReason());
  h.emit(rec);assert.ok(h.controller.ownerReason(),'native event is not original Status caller return');
  const revoke=p.controller.revoke();p.last('revoke').resolve(access(selected,final,row,{permissionRevision:'2'}));await revoke;
  assert.ok(h.controller.ownerReason());h.respond('status',rec);await flush();
  assert.equal(p.controller.getSnapshot().unknown,false);assert.equal(h.controller.getSnapshot().uncertain,false);
  assert.equal(h.controller.ownerReason(),null);assert.equal(p.controller.ownerReason(),null);assert.equal(h.controller.agentSelection(),null);
  assert.equal(h.calls.filter(c=>['prepare','create','start','reconcile'].includes(c.kind)).length,0);
 });
}
