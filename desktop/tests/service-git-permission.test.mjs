// Closed DATA and controlled promises only. No native consent, Git, filesystem,
// secret, process, installed transport or GUI observation is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GIT_INDEX_CONSENT, GitIndexPermission, copyGitIndexApproval, createGitIndexApi, parseGitIndexAccess } from '../src/service_git_permission.ts';
const id=c=>c.repeat(32);
const approval=()=>({projectId:'project-1',expectedDocumentRevision:1,readOperationId:'git-read-1',action:'stage',paths:['app/a','app/b']});
const empty=()=>({enabled:false,remainingMs:0,consumed:false,projectId:null,grantId:null,selection:null});
const enabled=()=>({enabled:true,remainingMs:900000,consumed:false,projectId:id('a'),grantId:id('b'),selection:{summary:{action:'stage',repositoryRevision:'c'.repeat(64),pathCount:2,selectionSha256:'d'.repeat(64)},paths:['app/a','app/b']}});
function defer(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return{promise,resolve,reject};}
function port(){const calls=[];const api=Object.fromEntries(['allow','status','revoke'].map(kind=>[kind,input=>{const v={kind,input,...defer()};calls.push(v);return v.promise;}]));return{api,calls};}
function controller(p=port()){let context={api:p.api,project:approval(),blocked:false};const c=new GitIndexPermission(action=>({...context,project:context.project&&{...context.project,action}}));c.syncContext();return{...p,c,set:v=>{context=v;}};}
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
 assert.equal(createGitIndexApi('preview',()=>{throw Error('called');}),null);await api.allow(approval());assert.equal(calls[0].command,'allow_agent_git_index');assert.equal(calls[0].value.consentVersion,GIT_INDEX_CONSENT);
 await api.status();await api.revoke();assert.deepEqual(calls.slice(1).map(v=>v.command),['agent_git_index_access','revoke_agent_git_index']);
 await assert.rejects(api.allow({...approval(),paths:['..']}));assert.equal(calls.length,3);
});
test('no acknowledgement/read grant substitutes for explicit one-use Allow',async()=>{
 const {c,calls}=controller();await c.allow();assert.equal(calls.length,0);c.acknowledge(true);const p=c.allow();assert.equal(calls[0].kind,'allow');calls[0].resolve(enabled());await p;assert.equal(c.getState().access.enabled,true);assert.equal(c.getState().acknowledged,false);
});
test('reentrant Revoke notification prevents fresh Allow after the original STOP',async()=>{
 const {c,calls}=controller();let stop;const unsubscribe=c.subscribe(s=>{if(s.pending==='allow'&&!stop){stop=c.revoke();}});c.acknowledge(true);const run=c.allow();assert.deepEqual(calls.map(v=>v.kind),['revoke']);calls[0].resolve(empty());await stop;await run;unsubscribe();assert.equal(c.getState().access.enabled,false);
});
test('status-only original survives rebinding and Revoke targets that old connection',async()=>{
 const old=port(),fresh=port();const {c,set}=controller(old);const pending=c.status();set({api:fresh.api,project:approval(),blocked:false});c.syncContext();old.calls[0].resolve(enabled());await pending;
 c.acknowledge(true);await c.allow();assert.equal(fresh.calls.length,0);const stop=c.revoke();assert.equal(old.calls[1].kind,'revoke');assert.equal(fresh.calls.length,0);old.calls[1].resolve(empty());await stop;
});
test('same original late Allow after Revoke cannot resurrect permission',async()=>{
 const {c,calls}=controller();c.acknowledge(true);const allow=c.allow();const stop=c.revoke();assert.equal(calls.length,2);calls[1].resolve(empty());await stop;calls[0].resolve(enabled());await allow;assert.equal(c.getState().access.enabled,false);
});
test('selection changes or unknown reply do not silently issue another permission',async()=>{
 const {c,calls,set,api}=controller();c.acknowledge(true);const pending=c.allow();set({api,project:{...approval(),paths:['different']},blocked:false});c.syncContext();calls[0].resolve(enabled());await pending;assert.equal(c.getState().uncertain,true);
 c.acknowledge(true);await c.allow();assert.equal(calls.length,1);const stop=c.revoke();calls[1].reject(Error('unknown close'));await stop;assert.equal(c.getState().uncertain,true);
});
