// Actual controllers and fixed inert promises/bytes only; no Git, native owner,
// credential, filesystem, provider or installed qualification is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GIT_REMOTE_CONSENT, GitRemotePermission, copyGitRemoteApproval, parseGitRemoteAccess, createGitRemotePermissionApi, gitRemotePermissionContext } from '../src/service_git_remote_permission.ts';
import { parseGitIndexAccess } from '../src/service_git_permission.ts';
import { parseGitRepositoryAccess } from '../src/service_git_repository_permission.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';
import { parseGitHubConnectionStatus } from '../src/githubConnectionProtocol.ts';
const revision='a'.repeat(64), references='b'.repeat(64), head='d'.repeat(40), old='e'.repeat(40);
const actions=()=>[{kind:'fetch',expectedRevision:revision,expectedReferenceRevision:references,remote:'origin',reference:'refs/heads/main',connectionSessionId:'session-1',expectedConnectionRevision:12},
 {kind:'push',expectedRevision:revision,expectedReferenceRevision:references,remote:'origin',localRef:'refs/heads/work',remoteRef:'refs/heads/main',oldOid:old,newOid:head,connectionSessionId:'session-1',expectedConnectionRevision:12}];
const approval=(a=actions()[0])=>({projectId:'project-1',expectedDocumentRevision:1,readOperationId:'read-1',action:a});
const empty=()=>({permissionRevision:'0',enabled:false,remainingMs:0,consumed:false,projectId:null,grantId:null,selection:null});
const allowed=(a=actions()[0])=>({permissionRevision:'0',enabled:true,remainingMs:900000,consumed:false,projectId:'1'.repeat(32),grantId:'2'.repeat(32),selection:{action:a,account:{accountId:'7',login:'Example',repositoryId:'9',repository:'Example/App'},selectionSha256:'3'.repeat(64)}});
const observation=()=>({revision,head,branch:'refs/heads/work',unborn:false,detached:false,changes:[],remotes:['origin'],restrictions:[]});
const observed=()=>({observation:observation(),referenceRevision:references,basis:'local-refs-no-fetch',tracking:{state:'complete',remote:'origin',mergeRef:'refs/heads/main',localRef:'refs/remotes/origin/main',head:old,ahead:1,behind:0}});
const newBranch=()=>({...actions()[1],kind:'push-new-branch',remote:null,remoteRef:'refs/heads/work',oldOid:'0'.repeat(40)});
const unconfigured=()=>({...observed(),observation:{...observation(),remotes:[]},tracking:{state:'not-configured',remote:null,mergeRef:null,localRef:null,head:null,ahead:null,behind:null}});
const context=()=>({projectId:'project-1',generation:1,revision:'document-1'});
const readStatus=(operation=null)=>({schemaVersion:1,documentRevision:1,available:true,operation});
const localStatus=()=>({schemaVersion:1,documentRevision:1,available:true,review:null,operation:null});
function readReply(value=observed(),operationId='read-1') {const action={kind:'observe',expectedRevision:null,paths:[],staged:false};const v={schemaVersion:1,admission:'started',request:{projectId:'project-1',expectedDocumentRevision:1,action},reason:null,status:readStatus({operationId,context:context(),action,phase:'settled',outcome:'ok',reason:null,result:value})};assert.ok(parseGitReadStartResult(v));return v;}
function connection() {
  const fact = value => ({ state: value === null ? 'not-observed' : 'observed', value, observedAt: value === null ? null : '2026-10-20T12:00:00Z', reason: value === null ? 'not-connected' : 'none' });
  const s = { schemaVersion: 1, revision: 12, capability: { readOnlySessionAvailable: true, reason: 'none', deviceLogin: 'publisher-unconfigured', storage: 'session-only' },
    session: { id: 'session-1', projectId: 'project-1', targetRepository: 'Example/App', state: 'connected', expiresAt: '2026-10-20T13:00:00Z' },
    operation: { id: 'connection-1', kind: 'connect', phase: 'settled', reason: 'none' }, account: fact({ id: '7', login: 'Example' }),
    repository: fact({ id: '9', fullName: 'Example/App', defaultBranch: 'main', visibility: 'private', archived: false,
      permissions: { pull: 'reported-allowed', push: 'reported-allowed', admin: 'unknown' } }), automation: fact(null),
    facts: { remoteMutationAvailable: false, dispatchAvailable: false, repositoryActionsSettingsObservation: 'not-run', environmentObservation: 'not-run',
      secretObservation: 'not-run', variableObservation: 'not-run', protectionObservation: 'not-run', runnerObservation: 'not-run', templateCompatibility: 'unknown', releaseReadiness: 'unknown' } };
  assert.ok(parseGitHubConnectionStatus(s));
  return { mode: 'native', context: { documentId: 'document-1', projectId: 'project-1', projectGeneration: 1, repository: 'Example/App' },
    status: s, retained: null, help: null, helpState: 'missing', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function rawPort(names) {
  const calls = [], queues = Object.fromEntries(names.map(name => [name, []]));
  return { calls, queue: (name, value) => queues[name].push(value), api: Object.fromEntries(names.map(name => [name, raw => {
    assert.ok(raw instanceof Uint8Array); const body = JSON.parse(new TextDecoder().decode(raw)); calls.push({ name, body });
    assert.ok(queues[name].length, `no inert ${name} reply was queued`); const next = queues[name].shift();
    return typeof next === 'function' ? next(body) : Promise.resolve(next);
  }])) };
}
function permissionPort() {
  const calls = [];
  return { calls, api: Object.fromEntries(['status', 'allow', 'revoke'].map(kind => [kind, (input, expectedPermissionRevision) => {
    const call = { kind, input, expectedPermissionRevision, ...deferred() }; calls.push(call); return call.promise;
  }])) };
}
async function fixture({ value=observed(), connected=connection() }={}) {
 const reads=rawPort(['start','status','cancel']),writes=rawPort(['prepare','apply','discard','status','cancel']),grant=permissionPort();
 let source={api:grant.api,session:{},projectId:'project-1',epoch:0,repository:null,reader:null,local:null,connection:connected,blocked:null};
 const reader=new GitReadController({current:()=>({api:reads.api,session:source.session,projectId:source.projectId,epoch:source.epoch,blocked:source.local?.ownerReason()??source.blocked})});source.reader=reader;reader.syncContext();
 const repository=new GitRepositoryController('project-1',reader.port('project-1'));source.repository=repository;
 const local=new GitLocalController({current:()=>({...source,api:writes.api,fetchConnection:source.connection,pushConnection:source.connection,blocked:reader.ownerReason()??source.blocked}),onMutationSubmitted:()=>assert.fail('permission must never submit a mutation')});source.local=local;local.syncContext();
 reads.queue('status',readStatus());await reader.checkStatus();reads.queue('start',readReply(value));assert.equal(await repository.refresh(),true);
 repository.editFetchDraft('remote','origin');repository.editFetchDraft('branch','main');writes.queue('status',localStatus());await local.checkStatus();
 const controller=new GitRemotePermission(kind=>gitRemotePermissionContext(kind,source));for(const c of [repository,reader,local])c.subscribe(()=>controller.syncContext());controller.syncContext();
 return {controller,grant,reads,writes,reader,repository,local,source:()=>source,change(update,sync=true){source={...source,...update};if(sync)controller.syncContext();}};
}
async function checked(c, calls, revision = '0') {
  const before = calls.length, pending = c.status();
  assert.equal(calls.length, before + 1); assert.equal(calls[before].kind, 'status');
  c.acknowledge(true); assert.equal(c.getState().acknowledged, false);
  calls[before].resolve({ ...empty(), permissionRevision: revision }); await pending;
  assert.equal(c.getState().pending, null); assert.equal(c.getState().acknowledged, false);
}

test('Remote approval and Access are closed, bounded and never local permission or authority',()=>{
 for(const a of actions()){assert.deepEqual(copyGitRemoteApproval(approval(a)),approval(a));assert.deepEqual(parseGitRemoteAccess(allowed(a)),allowed(a));assert.equal(parseGitIndexAccess(allowed(a)),null);assert.equal(parseGitRepositoryAccess(allowed(a)),null);
  for(const field of ['force','token','url','argv','absent','setUpstream'])assert.equal(copyGitRemoteApproval(approval({...a,[field]:true})),null);
 }
 assert.deepEqual(parseGitRemoteAccess(empty()),empty());
 for(const v of [{...approval(),readOperationId:null},{...approval(),readOperationId:'bad\n'},{...approval(),projectId:'bad\n'},approval({...actions()[1],oldOid:'0'.repeat(40)}),approval({...actions()[0],connectionSessionId:'a'.repeat(65)}),approval({...actions()[0],kind:'push-new-branch'})])assert.equal(copyGitRemoteApproval(v),null);
 for(const change of [{remainingMs:900001},{remainingMs:-0},{remainingMs:0},{consumed:true},{projectId:null},{nativeReady:true},{selection:{...allowed().selection,account:{...allowed().selection.account,accountId:'18446744073709551616'}}},{selection:{...allowed().selection,token:'fake'}}])assert.equal(parseGitRemoteAccess({...allowed(),...change}),null);
 let touched=false;const getter=approval();Object.defineProperty(getter,'action',{enumerable:true,get(){touched=true;return actions()[0];}});assert.equal(copyGitRemoteApproval(getter),null);assert.equal(touched,false);
});
test('exact RAW calls use separate Fetch/Push consent and mismatched replies stay unconfirmed',async()=>{
 const calls=[];let reply=empty();const api=createGitRemotePermissionApi('native',async(command,raw)=>{assert.ok(raw instanceof Uint8Array);calls.push({command,body:JSON.parse(new TextDecoder().decode(raw))});return reply;});
 assert.equal(createGitRemotePermissionApi('preview',()=>assert.fail()),null);
 for(const a of actions()){reply=allowed(a);assert.deepEqual(await api.allow(approval(a), '0'),reply);assert.deepEqual(calls.at(-1),{command:'allow_agent_git_remote',body:{...approval(a),expectedPermissionRevision:'0',consentVersion:GIT_REMOTE_CONSENT[a.kind]}});}
 reply=allowed(actions()[1]);await assert.rejects(api.allow(approval(actions()[0]), '0'));reply=empty();await api.status();await api.revoke();assert.deepEqual(calls.slice(-2).map(v=>v.command),['agent_git_remote_access','revoke_agent_git_remote']);
 assert.deepEqual(calls.slice(-2).map(v=>v.body),[{},{}]);
});
test('existing source controllers select Fetch draft and current committed Push without auto calls',async()=>{
 const h=await fixture();assert.deepEqual(h.controller.getContext().project,approval());assert.equal(h.grant.calls.length,0);h.controller.chooseKind('push');assert.deepEqual(h.controller.getContext().project,approval(actions()[1]));
 assert.equal(h.writes.calls.filter(c=>c.name==='prepare'||c.name==='apply').length,0);await h.controller.allow();assert.equal(h.grant.calls.length,0);
 await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);const pending=h.controller.allow();assert.equal(h.grant.calls.length,2);assert.equal(h.grant.calls[1].input.action.kind,'push');h.grant.calls[1].resolve(allowed(actions()[1]));await pending;
 assert.equal(h.controller.getState().acknowledged,false);assert.equal(h.local.getSnapshot().original,null);
});
test('stale or incomplete account, source, tracking, peer or context cannot substitute for current review',async()=>{
 for(const mutate of [v=>{v.uncertain=true;},v=>{v.status.account.state='stale';},v=>{v.status.session.state='expired';},v=>{v.status.repository.value.permissions.push='unknown';},v=>{v.context.projectId='foreign';}]){
  const c=connection();mutate(c);const h=await fixture({connected:c});h.controller.chooseKind('push');assert.equal(h.controller.getContext().project,null);h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,0);
 }
 for(const tracking of [{state:'shallow',remote:'origin',mergeRef:'refs/heads/main',localRef:'refs/remotes/origin/main',head:old,ahead:null,behind:null},{...observed().tracking,behind:1},{...observed().tracking,ahead:0}]){
  const h=await fixture({value:{...observed(),tracking}});h.controller.chooseKind('push');assert.equal(h.controller.getContext().project,null);
 }
 const h=await fixture();h.change({blocked:'Another original task is live.'});assert.equal(h.controller.getContext().project,null);h.change({blocked:null});h.repository.invalidate();assert.equal(h.controller.getContext().project,null);
});
test('actual terminal-before-Start-return remains pending and cannot authorize an agent',async()=>{
 const h=await fixture(),d=deferred(),reply=readReply(observed(),'read-next');h.reads.queue('start',()=>d.promise);const read=h.repository.refresh();h.reads.queue('status',reply.status);await h.reader.checkStatus();
 assert.equal(h.reader.getSnapshot().original.phase,'settled');assert.equal(h.reader.getSnapshot().busy,true);h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,0);
 d.resolve(reply);assert.equal(await read,true);assert.equal(h.controller.getState().acknowledged,false);assert.equal(h.controller.getContext().project.readOperationId,'read-next');
});
test('synchronous source/account ABA, action change or peer after Allow notification causes zero handoffs',async()=>{
 for(const kind of ['draft','account','mode','peer','epoch']){const h=await fixture();let changed=false;h.controller.subscribe(s=>{if(s.pending==='allow'&&!changed){changed=true;
  if(kind==='draft'){h.repository.editFetchDraft('branch','other');h.repository.editFetchDraft('branch','main');}
  else if(kind==='account'){const old=h.source().connection;h.change({connection:connection()});h.change({connection:old});}
  else if(kind==='mode'){h.controller.chooseKind('push');h.controller.chooseKind('fetch');}
  else if(kind==='peer')h.change({blocked:'Original owner still running.'});else h.change({epoch:1});
 }});await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,1,kind);assert.equal(h.controller.getState().pending,null);assert.equal(h.controller.getState().acknowledged,false);}
});
test('independent Stop retains its original API and both promises across a service change',async()=>{
 const h=await fixture(),fresh=permissionPort();await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);const allow=h.controller.allow();h.change({api:fresh.api,session:{},epoch:1});const stop=h.controller.revoke();assert.deepEqual(h.grant.calls.map(c=>c.kind),['status','allow','revoke']);assert.equal(fresh.calls.length,0);
 h.grant.calls[2].resolve(empty());await stop;assert.equal(h.controller.getState().pending,'allow');h.controller.acknowledge(true);await h.controller.allow();assert.equal(fresh.calls.length,0);
 h.grant.calls[1].resolve(allowed());await allow;assert.equal(h.controller.getState().access.enabled,false);assert.equal(h.controller.getState().pending,null);
});
test('reentrant revoke happens before new Allow and lost ACK stays sticky after status',async()=>{
 const a=await fixture();let stopping;a.controller.subscribe(s=>{if(s.pending==='allow'&&!stopping)stopping=a.controller.revoke();});await checked(a.controller, a.grant.calls); a.controller.acknowledge(true);const allow=a.controller.allow();assert.deepEqual(a.grant.calls.map(c=>c.kind),['status','revoke']);a.grant.calls[1].resolve(empty());await stopping;await allow;
 const h=await fixture();await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);const lost=h.controller.allow();h.grant.calls[1].reject(new Error('inert lost ACK'));await lost;assert.equal(h.controller.getState().uncertain,true);
 const read=h.controller.status();h.grant.calls[2].resolve({...allowed(),enabled:false,remainingMs:0,consumed:true});await read;assert.equal(h.controller.getState().uncertain,true);h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,3);
 assert.equal(h.local.getSnapshot().original,null);assert.equal(h.writes.calls.filter(c=>c.name==='apply'||c.name==='prepare').length,0);
});

test('create-only permission requires explicit new kind and null alias, never old-grant or absence flags',()=>{
 const a=newBranch();assert.deepEqual(copyGitRemoteApproval(approval(a)),approval(a));assert.deepEqual(parseGitRemoteAccess(allowed(a)),allowed(a));
 assert.equal(parseGitIndexAccess(allowed(a)),null);assert.equal(parseGitRepositoryAccess(allowed(a)),null);
 const missing={...a};delete missing.remote;assert.equal(copyGitRemoteApproval(approval(missing)),null);
 for(const delta of [{kind:'push'},{remote:'origin'},{oldOid:old},{newOid:'0'.repeat(40)},{remoteRef:'refs/heads/other'},
  {setUpstream:true},{absenceConfirmed:true},{force:false},{url:'https://github.com/other/repo'},{token:'not-a-token'}]){
  assert.equal(copyGitRemoteApproval(approval({...a,...delta})),null);assert.equal(parseGitRemoteAccess(allowed({...a,...delta})),null);
 }
 assert.notEqual(GIT_REMOTE_CONSENT[a.kind],GIT_REMOTE_CONSENT.push);assert.notEqual(GIT_REMOTE_CONSENT[a.kind],GIT_REMOTE_CONSENT.fetch);
 assert.deepEqual(Object.keys(GIT_REMOTE_CONSENT),['fetch','push','push-new-branch']);
});
test('create-only uses the same RAW Allow with separate consent and cannot accept an ordinary reply',async()=>{
 const calls=[];let reply=allowed(newBranch());const api=createGitRemotePermissionApi('native',async(command,raw)=>{
  calls.push({command,body:JSON.parse(new TextDecoder().decode(raw))});return reply;
 });
 await api.allow(approval(newBranch()), '0');assert.deepEqual(calls,[{command:'allow_agent_git_remote',body:{...approval(newBranch()),expectedPermissionRevision:'0',consentVersion:'agent-git-push-new-branch-once-v1'}}]);
 for(const a of actions()){reply=allowed(a);await assert.rejects(api.allow(approval(newBranch()), '0'));}
 reply=allowed(newBranch());for(const a of actions())await assert.rejects(api.allow(approval(a), '0'));
 const before=calls.length;const missing={...newBranch()};delete missing.remote;
 await assert.rejects(api.allow(approval(missing), '0'));assert.equal(calls.length,before);
});
test('actual unconfigured source needs explicit create-kind and unchecked separate consent without starting Git',async()=>{
 const h=await fixture({value:unconfigured()});assert.equal(h.controller.getContext().project,null);
 h.controller.chooseKind('push');assert.equal(h.controller.getContext().project,null);
 h.controller.acknowledge(true);h.controller.chooseKind('push-new-branch');assert.equal(h.controller.getState().acknowledged,false);
 assert.deepEqual(h.controller.getContext().project,approval(newBranch()));assert.equal(h.controller.getContext().account.repository,'Example/App');
 const before=h.repository.getSnapshot();await h.controller.allow();assert.equal(h.grant.calls.length,0);
 await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);const allowing=h.controller.allow();assert.equal(h.grant.calls.length,2);
 assert.deepEqual(h.grant.calls[1].input,approval(newBranch()));h.grant.calls[1].resolve(allowed(newBranch()));await allowing;
 assert.equal(h.controller.getState().acknowledged,false);assert.equal(h.repository.getSnapshot(),before);
 assert.equal(h.local.getSnapshot().original,null);assert.deepEqual(h.writes.calls.map(c=>c.name),['status']);
 assert.deepEqual(h.reads.calls.map(c=>c.name),['status','start']);
});
test('new-kind source refuses configured, unborn, detached, stale account and peer states',async()=>{
 const values=[observed(),{...unconfigured(),observation:{...unconfigured().observation,unborn:true,head:null},tracking:{...unconfigured().tracking,state:'unborn'}},
  {...unconfigured(),observation:{...unconfigured().observation,detached:true,branch:null},tracking:{...unconfigured().tracking,state:'detached'}}];
 for(const value of values){const h=await fixture({value});h.controller.chooseKind('push-new-branch');
  assert.equal(h.controller.getContext().project,null);h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,0);}
 for(const mutate of [v=>{v.uncertain=true;},v=>{v.status.session.state='expired';},v=>{v.status.repository.value.permissions.push='unknown';},v=>{v.context.projectId='other';}]){
  const connected=connection();mutate(connected);const h=await fixture({value:unconfigured(),connected});h.controller.chooseKind('push-new-branch');
  assert.equal(h.controller.getContext().project,null);h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,0);
 }
 const h=await fixture({value:unconfigured()});h.controller.chooseKind('push-new-branch');h.change({blocked:'Original peer is running.'});
 assert.equal(h.controller.getContext().project,null);h.change({blocked:null});h.repository.invalidate();assert.equal(h.controller.getContext().project,null);
});
test('new-kind terminal read before original invoke return never unlocks Allow',async()=>{
 const h=await fixture({value:unconfigured()});h.controller.chooseKind('push-new-branch');const d=deferred(),reply=readReply(unconfigured(),'read-new-next');
 h.reads.queue('start',()=>d.promise);const original=h.repository.refresh();h.reads.queue('status',reply.status);await h.reader.checkStatus();
 assert.equal(h.reader.getSnapshot().original.phase,'settled');assert.equal(h.reader.getSnapshot().busy,true);
 h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,0);
 d.resolve(reply);assert.equal(await original,true);assert.equal(h.controller.getState().acknowledged,false);
 assert.equal(h.controller.getContext().project.readOperationId,'read-new-next');
});
test('new-kind reentrant mode, account ABA, peer and epoch changes consume consent before any handoff',async()=>{
 for(const changedKind of ['mode','account','peer','epoch']){
  const h=await fixture({value:unconfigured()});h.controller.chooseKind('push-new-branch');let changed=false;
  h.controller.subscribe(s=>{if(s.pending==='allow'&&!changed){changed=true;
   if(changedKind==='mode'){h.controller.chooseKind('push');h.controller.chooseKind('push-new-branch');}
   else if(changedKind==='account'){const old=h.source().connection;h.change({connection:connection()});h.change({connection:old});}
   else if(changedKind==='peer')h.change({blocked:'Peer still running.'});else h.change({epoch:1});
  }});
  await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,1,changedKind);
  assert.equal(h.controller.getState().pending,null);assert.equal(h.controller.getState().acknowledged,false);
 }
});
test('new-kind lost Allow remains original and consumed Status cannot mint a repeat or Apply',async()=>{
 const h=await fixture({value:unconfigured()});h.controller.chooseKind('push-new-branch');await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);
 const original=h.controller.allow();h.grant.calls[1].reject(new Error('inert lost create-only ACK'));await original;
 assert.equal(h.controller.getState().uncertain,true);const checking=h.controller.status();
 h.grant.calls[2].resolve({...allowed(newBranch()),enabled:false,remainingMs:0,consumed:true});await checking;
 assert.equal(h.controller.getState().uncertain,true);h.controller.acknowledge(true);await h.controller.allow();assert.equal(h.grant.calls.length,3);
 assert.equal(h.local.getSnapshot().original,null);assert.deepEqual(h.writes.calls.map(c=>c.name),['status']);
});
test('new-kind Stop keeps original Allow API and promise across replacement and never upgrades its reply',async()=>{
 const h=await fixture({value:unconfigured()});h.controller.chooseKind('push-new-branch');await checked(h.controller, h.grant.calls); h.controller.acknowledge(true);
 const original=h.controller.allow(),fresh=permissionPort();h.change({api:fresh.api,session:{},epoch:1});const stopping=h.controller.revoke();
 assert.deepEqual(h.grant.calls.map(c=>c.kind),['status','allow','revoke']);assert.equal(fresh.calls.length,0);
 h.grant.calls[2].resolve(empty());await stopping;assert.equal(h.controller.getState().pending,'allow');
 h.controller.chooseKind('push');h.controller.chooseKind('push-new-branch');h.controller.acknowledge(true);await h.controller.allow();assert.equal(fresh.calls.length,0);
 h.grant.calls[1].resolve(allowed(newBranch()));await original;assert.equal(h.controller.getState().pending,null);
 assert.equal(h.controller.getState().access.enabled,false);assert.equal(fresh.calls.length,0);
});
