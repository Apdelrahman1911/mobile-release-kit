// Pure bounded DATA/RAW command assertions, no native or provider execution.
import test from 'node:test';
import assert from 'node:assert/strict';
import {parseVersionPreparation,createVersionPrepareApi} from '../src/serviceVersionPrepareProtocol.ts';
const q={projectId:'1'.repeat(32),serviceInstance:'2'.repeat(32),requestId:'3'.repeat(32)};
const queued=()=>({schemaVersion:1,origin:q,runtimeProjectId:'native-p',selection:{kind:'manual',values:{name:'1.2',build:'8'}},revision:1,phase:'queued',settlement:'pending',
  original:null,checkout:null,proposed:null,review:null,applyRequest:null,guiOwned:false,cancelRequested:false,result:null,doNotReplay:true});
test('preparation DATA is closed/required-null/bounded and never a scalar reservation handoff',()=>{
  const d=queued();assert.ok(parseVersionPreparation(d));assert.ok(Object.isFrozen(parseVersionPreparation(d).selection.values));
  for(const mutate of [v=>delete v.original,v=>delete v.runtimeProjectId,v=>v.selection.reservationId='4'.repeat(32),v=>v.selection.values.name='x'.repeat(65),
    v=>v.selection.values.build='8\n',v=>v.selection={kind:'reserved',candidateId:'11111111-2222-3333-4444-555555555555'},v=>v.root='/x',
    v=>v.phase='reviewing',v=>v.phase='final',v=>v.guiOwned=true&& (v.applyRequest={...q,requestId:'4'.repeat(32)}),v=>v.original={sessionId:'5'.repeat(32),ownerGeneration:'6'.repeat(32),ready:true}]) {
    const bad=structuredClone(d);mutate(bad);assert.equal(parseVersionPreparation(bad),null);
  }
  const reserved=queued();reserved.selection={kind:'reserved',reservationId:'4'.repeat(32)};assert.ok(parseVersionPreparation(reserved));
  let invoked=0;const getter={get schemaVersion(){invoked++;return 1;}};assert.equal(parseVersionPreparation(getter),null);assert.equal(invoked,0);
  assert.equal(parseVersionPreparation({...d,extra:'x'.repeat(8193)}),null);
});
test('new fixed RAW continuations contain origin/counters only; status never falls back to latest',async()=>{
  const calls=[];const api=createVersionPrepareApi(async(command,args)=>{calls.push({command,args:JSON.parse(new TextDecoder().decode(args))});return null;});
  assert.equal(await api.status(q),null);assert.equal(await api.status(),null);assert.equal(await api.cancel(q),null);
  await assert.rejects(api.open(q));await assert.rejects(api.prepare(q,2,3));
  assert.deepEqual(calls,[{command:'agent_version_edit_status',args:{intent:'preparation',origin:q}},
    {command:'agent_version_edit_status',args:{intent:'preparation',origin:null}},
    {command:'revoke_agent_version_edit',args:{intent:'agent-version-prepare',origin:q}},
    {command:'release_version_edit_open',args:{intent:'agent-version-prepare',origin:q}},
    {command:'release_version_edit_prepare',args:{intent:'agent-version-prepare',origin:q,draftRevision:2,baselineGeneration:3}}]);
});
