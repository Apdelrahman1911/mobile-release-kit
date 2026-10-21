// Closed DATA and controlled promises only. No native consent, Git, filesystem,
// secret, process, installed transport or GUI observation is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GIT_INDEX_CONSENT, GitIndexPermission, copyGitIndexApproval, createGitIndexApi, parseGitIndexAccess } from '../src/service_git_permission.ts';
const id=c=>c.repeat(32);
const approval=()=>({projectId:'project-1',expectedDocumentRevision:1,readOperationId:'git-read-1',action:'stage',paths:['app/a','app/b']});
const empty=()=>({permissionRevision:'0',enabled:false,remainingMs:0,consumed:false,projectId:null,grantId:null,selection:null});
const enabled=()=>({permissionRevision:'0',enabled:true,remainingMs:900000,consumed:false,projectId:id('a'),grantId:id('b'),selection:{summary:{action:'stage',repositoryRevision:'c'.repeat(64),pathCount:2,selectionSha256:'d'.repeat(64)},paths:['app/a','app/b']}});
function defer(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};}
function port(){const calls=[];const api=Object.fromEntries(['allow','status','revoke'].map(kind=>[kind,(input,expectedPermissionRevision)=>{const v={kind,input,expectedPermissionRevision,...defer()};calls.push(v);return v.promise;}]));return{api,calls};}
function controller(p=port()){let context={api:p.api,project:approval(),blocked:false};const c=new GitIndexPermission(action=>({...context,project:context.project&&{...context.project,action}}));c.syncContext();return{...p,c,set:v=>{context=v;}};}
async function checked(c, calls, revision = '0') {
  const before = calls.length, pending = c.status();
  assert.equal(calls.length, before + 1); assert.equal(calls[before].kind, 'status');
  c.acknowledge(true); assert.equal(c.getState().acknowledged, false);
  calls[before].resolve({ ...empty(), permissionRevision: revision }); await pending;
  assert.equal(c.getState().pending, null); assert.equal(c.getState().acknowledged, false);
}

test('closed action/path consent preserves exact selection and rejects authority fields/getters',()=>{
 const a=approval();assert.deepEqual(copyGitIndexApproval(a),a);assert.equal(copyGitIndexApproval({...a,command:'commit'}),null);
 for(const paths of [[],['b','a'],['a','a'],['../secret'],['a/.git/index'],['a\\b'],['a\nb'],['a\ud800']])assert.equal(copyGitIndexApproval({...a,paths}),null);
 let touched=false;const v={...a};Object.defineProperty(v,'paths',{get(){touched=true;return['a'];},enumerable:true});assert.equal(copyGitIndexApproval(v),null);assert.equal(touched,false);
 assert.equal(copyGitIndexApproval({...a,action:'commit'}),null);
});
test('paths use actual UTF8/scalar order rather than JS UTF16',()=>{
 const good={...approval(),paths:['\ue000','\u{10000}']};assert.ok(copyGitIndexApproval(good));assert.equal(copyGitIndexApproval({...good,paths:[...good.paths].reverse()}),null);
});
test('access is explicit bounded scope DATA, never counts-as-native-readiness',()=>{
 assert.ok(parseGitIndexAccess(enabled()));assert.ok(parseGitIndexAccess(empty()));
 for(const change of [{remainingMs:900001},{enabled:true,consumed:true},{grantId:null},{selectedReady:true},{projectId:'0'.repeat(32)}])assert.equal(parseGitIndexAccess({...enabled(),...change}),null);
 const v=enabled();v.selection.summary.pathCount=1;assert.equal(parseGitIndexAccess(v),null);
});
test('only native mode and the three exact raw permission commands are invoked',async()=>{
 const calls=[];const api=createGitIndexApi('native',async(command,raw)=>{calls.push({command,value:JSON.parse(new TextDecoder().decode(raw))});return command==='revoke_agent_git_index'?empty():enabled();});
 assert.equal(createGitIndexApi('preview',()=>{throw Error('called');}),null);await api.allow(approval(), '0');assert.equal(calls[0].command,'allow_agent_git_index');assert.equal(calls[0].value.consentVersion,GIT_INDEX_CONSENT);
 await api.status();await api.revoke();assert.deepEqual(calls.slice(1).map(v=>v.command),['agent_git_index_access','revoke_agent_git_index']);
 await assert.rejects(api.allow({...approval(),paths:['..']}, '0'));assert.equal(calls.length,3);
});
test('no acknowledgement/read grant substitutes for explicit one-use Allow',async()=>{
 const {c,calls}=controller();await c.allow();assert.equal(calls.length,0);await checked(c, calls); c.acknowledge(true);const p=c.allow();assert.equal(calls[1].kind,'allow');calls[1].resolve(enabled());await p;assert.equal(c.getState().access.enabled,true);assert.equal(c.getState().acknowledged,false);
});
test('reentrant Revoke notification prevents fresh Allow after the original STOP',async()=>{
 const {c,calls}=controller();let stop;const unsubscribe=c.subscribe(s=>{if(s.pending==='allow'&&!stop){stop=c.revoke();}});await checked(c, calls); c.acknowledge(true);const run=c.allow();assert.deepEqual(calls.map(v=>v.kind),['status','revoke']);calls[1].resolve(empty());await stop;await run;unsubscribe();assert.equal(c.getState().access.enabled,false);
});
test('status-only original survives rebinding and Revoke targets that old connection',async()=>{
 const old=port(),fresh=port();const {c,set}=controller(old);const pending=c.status();set({api:fresh.api,project:approval(),blocked:false});c.syncContext();old.calls[0].resolve(enabled());await pending;
 c.acknowledge(true);await c.allow();assert.equal(fresh.calls.length,0);const stop=c.revoke();assert.equal(old.calls[1].kind,'revoke');assert.equal(fresh.calls.length,0);old.calls[1].resolve(empty());await stop;
});
test('same original late Allow after Revoke cannot resurrect permission',async()=>{
 const {c,calls}=controller();await checked(c, calls); c.acknowledge(true);const allow=c.allow();const stop=c.revoke();assert.equal(calls.length,3);calls[2].resolve(empty());await stop;calls[1].resolve(enabled());await allow;assert.equal(c.getState().access.enabled,false);
});
test('selection changes or unknown reply do not silently issue another permission',async()=>{
 const {c,calls,set,api}=controller();await checked(c, calls); c.acknowledge(true);const pending=c.allow();set({api,project:{...approval(),paths:['different']},blocked:false});c.syncContext();calls[1].resolve(enabled());await pending;assert.equal(c.getState().uncertain,true);
 c.acknowledge(true);await c.allow();assert.equal(calls.length,2);const stop=c.revoke();calls[2].reject(Error('unknown close'));await stop;assert.equal(c.getState().uncertain,true);
});

test('MAIN revision is canonical in all four exact API codecs without changing approval or CLI shapes', async () => {
 const {createGitCommitApi,parseGitCommitAccess}=await import('../src/service_git_commit_permission.ts');
 const {createGitRepositoryPermissionApi,parseGitRepositoryAccess}=await import('../src/service_git_repository_permission.ts');
 const {createGitRemotePermissionApi,parseGitRemoteAccess}=await import('../src/service_git_remote_permission.ts');
 const init={projectId:'project-1',expectedDocumentRevision:1,readOperationId:null,action:{kind:'initialize'}};
 const fetch={...init,readOperationId:'git-read-1',action:{kind:'fetch',expectedRevision:'a'.repeat(64),expectedReferenceRevision:'b'.repeat(64),remote:'origin',reference:'refs/heads/main',connectionSessionId:'session-1',expectedConnectionRevision:1}};
 const commit={projectId:'project-1',expectedDocumentRevision:1,readOperationId:'git-read-1',message:'Reviewed',authorName:'Fixture',authorEmail:'a@example.invalid'};
 const c=enabled();c.selection.summary.action='commit';
 const common={enabled:true,remainingMs:1,consumed:false,projectId:id('a'),grantId:id('b'),permissionRevision:'9007199254740994'};
 const cases=[
  [parseGitIndexAccess,createGitIndexApi,approval(),enabled()],
  [parseGitCommitAccess,createGitCommitApi,commit,c],
  [parseGitRepositoryAccess,createGitRepositoryPermissionApi,init,{...common,selection:{action:init.action,selectionSha256:'c'.repeat(64)}}],
  [parseGitRemoteAccess,createGitRemotePermissionApi,fetch,{...common,selection:{action:fetch.action,account:{accountId:'1',login:'Example',repositoryId:'2',repository:'Example/App'},selectionSha256:'c'.repeat(64)}}],
 ];
 const invalid=[undefined,null,0,1,1.5,'','00','01','-0','+1','1e2',' 1','1 ','0\n','12\r','12\u2028','12\u2029','18446744073709551616',[],{}];
 for(const [parse,make,request,reply] of cases){
  for(const revision of ['0','9007199254740993','18446744073709551615'])assert.equal(parse({...empty(),permissionRevision:revision})?.permissionRevision,revision);
  const old=empty();delete old.permissionRevision;assert.equal(parse(old),null);
  for(const permissionRevision of invalid)assert.equal(parse({...empty(),permissionRevision}),null);
  const calls=[];const api=make('native',async(command,raw)=>{calls.push({command,body:JSON.parse(new TextDecoder().decode(raw))});return reply;});
  await api.allow(request,'9007199254740993');assert.equal(calls[0].body.expectedPermissionRevision,'9007199254740993');
  assert.equal(Object.hasOwn(request,'expectedPermissionRevision'),false);
  for(const invalidStamp of invalid)await assert.rejects(api.allow(request,invalidStamp));
  await assert.rejects(api.allow({...request,expectedPermissionRevision:'0'},'9007199254740993'));
  assert.equal(calls.length,1);
 }
});

test('joined Check clears old and in-flight acknowledgement; only a fresh explicit checkbox may Allow',async()=>{
 const {c,calls}=controller();c.acknowledge(true);assert.equal(c.canAllow(),false);await c.allow();assert.equal(calls.length,0);
 await checked(c,calls,'0');c.acknowledge(true);assert.equal(c.canAllow(),true);
 const refresh=c.status();assert.equal(c.getState().acknowledged,false);c.acknowledge(true);assert.equal(c.getState().acknowledged,false);
 let attempted=false;const off=c.subscribe(s=>{if(s.pending==='status'&&s.access?.permissionRevision==='1'&&!attempted){attempted=true;c.acknowledge(true);}});
 // An external Off is represented only as returned comparison DATA here. The
 // real native counter transition is separately exercised by Book/Doc tests.
 calls[1].resolve({...empty(),permissionRevision:'1'});await refresh;off();assert.equal(attempted,true);
 assert.equal(c.getState().acknowledged,false);assert.equal(c.canAllow(),false);await c.allow();assert.equal(calls.length,2);
 c.acknowledge(true);const allowing=c.allow();assert.equal(calls[2].expectedPermissionRevision,'1');calls[2].resolve({...enabled(),permissionRevision:'2'});await allowing;
 assert.equal(c.getState().access.enabled,true);c.acknowledge(true);await c.allow();assert.equal(calls.length,3,'Allow response is never a new checked origin');
});

test('original full-u64 checked pin is consumed before listeners and cannot be replaced by a reentrant Check',async()=>{
 const {c,calls}=controller();await checked(c,calls,'9007199254740993');c.acknowledge(true);
 let checkedAgain,notified=false;const off=c.subscribe(s=>{if(s.pending==='allow'&&!notified){notified=true;checkedAgain=c.status();c.acknowledge(true);}});
 const allowing=c.allow();assert.equal(calls.length,2);assert.equal(calls[1].kind,'allow');assert.equal(calls[1].expectedPermissionRevision,'9007199254740993');
 assert.equal(c.getState().acknowledged,false);await checkedAgain;calls[1].reject(Error('inert lost original Allow'));await allowing;off();
 assert.equal(c.getState().uncertain,true);await checked(c,calls,'9007199254740994');assert.equal(c.getState().uncertain,true);
 c.acknowledge(true);await c.allow();assert.equal(calls.length,3,'status neither clears Unknown nor retries the original');
});

test('same-byte context ABA withdraws a checked origin even when its counter remains equal',async()=>{
 const {c,calls,api,set}=controller();await checked(c,calls,'0');c.acknowledge(true);
 set({api,project:{...approval(),paths:['different']},blocked:false});c.syncContext();
 set({api,project:approval(),blocked:false});c.syncContext();c.acknowledge(true);await c.allow();assert.equal(calls.length,1);
 await checked(c,calls,'0');c.acknowledge(true);const allowing=c.allow();assert.equal(calls[2].expectedPermissionRevision,'0');
 calls[2].resolve({...enabled(),permissionRevision:'1'});await allowing;
});

test('both original promise return orders keep a stopped Allow fenced and cannot rearm from its reply',async()=>{
 for(const first of ['allow','revoke']){
  const {c,calls}=controller();await checked(c,calls,'0');c.acknowledge(true);const allowing=c.allow(),stopping=c.revoke();
  if(first==='allow'){calls[1].resolve({...enabled(),permissionRevision:'1'});await allowing;assert.equal(c.getState().revokePending,true);}
  else{calls[2].resolve({...empty(),permissionRevision:'2'});await stopping;assert.equal(c.getState().pending,'allow');}
  c.acknowledge(true);await c.allow();assert.equal(calls.length,3);
  if(first==='allow'){calls[2].resolve({...empty(),permissionRevision:'2'});await stopping;}
  else{calls[1].resolve({...enabled(),permissionRevision:'1'});await allowing;}
  assert.equal(c.getState().access.enabled,false);assert.equal(c.getState().pending,null);assert.equal(c.getState().revokePending,false);
  c.acknowledge(true);await c.allow();assert.equal(calls.length,3,'Stop result also requires another explicit Check');
 }
});

test('MAX or malformed returned revision never permits Allow but never disables original Stop',async()=>{
 for(const revision of ['18446744073709551615',undefined,'0\n']){
  const {c,calls}=controller();const read=c.status();calls[0].resolve({...empty(),permissionRevision:revision});await read;c.acknowledge(true);await c.allow();assert.equal(calls.length,1);
  const stopping=c.revoke();assert.equal(calls[1].kind,'revoke');calls[1].reject(Error('inert exhausted or unknown native result'));await stopping;
  assert.equal(c.getState().uncertain,true);assert.equal(c.getState().revokePending,false);
 }
});

test('maximum supported path/draft and fixed Remote request keep existing raw envelope limits',async()=>{
 const paths=Array.from({length:64},(_,i)=>`${String(i).padStart(2,'0')}/${'a'.repeat(255)}/${'b'.repeat(255)}/${'c'.repeat(255)}/${'d'.repeat(252)}`);
 assert.ok(paths.every(p=>p.length===1023));
 let raw;const api=createGitIndexApi('native',async(_,bytes)=>{raw=bytes;return enabled();});
 await api.allow({...approval(),projectId:'p'.repeat(64),readOperationId:'r'.repeat(96),expectedDocumentRevision:0xfffffffe,paths},'18446744073709551615');
 assert.ok(raw.length+96<=96*1024);assert.equal(JSON.parse(new TextDecoder().decode(raw)).paths.length,64);
 const {createGitCommitApi}=await import('../src/service_git_commit_permission.ts');
 const commit=createGitCommitApi('native',async(_,bytes)=>{raw=bytes;const r=enabled();r.selection.summary.action='commit';return r;});
 await commit.allow({projectId:'p'.repeat(64),expectedDocumentRevision:0xfffffffe,readOperationId:'r'.repeat(96),message:'x'.repeat(4096),authorName:'a'.repeat(128),authorEmail:`${'a'.repeat(127)}@${'b'.repeat(126)}`},'18446744073709551615');
 assert.ok(raw.length+96<=96*1024);
});
