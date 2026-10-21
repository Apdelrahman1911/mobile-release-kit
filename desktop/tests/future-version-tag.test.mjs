// Real shared controllers/closed parsers and retained inert promises only.
// No repository, native owner, network, tag creation or provider receipt.
import test from 'node:test';
import assert from 'node:assert/strict';
import * as h from './github-play-cleanup.test.mjs';
import * as reserve from './version-reserve.test.mjs';
import { parsePlayCleanupStatus, encodePlayCleanupRequest, playCleanupConfirmation } from '../src/githubPlayCleanupProtocol.ts';
import { parseReserveOptions, parseVersionReserveStatus } from '../src/versionReserve.ts';
import { futureVersionTag } from '../src/futureVersionTag.ts';
import { versionTagSelection, versionTagCandidate } from '../src/githubVersionTagProtocol.ts';
const selection={candidateId:'11111111-1111-4111-8111-111111111111',rowSha256:'a'.repeat(64),finalCommit:'1'.repeat(40)};
const futureTag='refs/tags/release-1.2';
function tagged(source=h.review()){
  const v=structuredClone(source),p=v.consent.prepared;
  p.target.versionTag={...selection};v.operation.target=structuredClone(p.target);
  p.candidate={candidateId:selection.candidateId,rowSha256:selection.rowSha256,platform:'ios',
    source:{...p.candidate.source,configurationSha256:p.savedConfigSha256},identityRevision:p.savedConfigSha256,
    baseVersion:{name:'1.2',build:7},version:{name:'1.2',build:8},futureTag};
  for(const key of ['journalBlob','journalSha256','journalRevision'])delete p[key];
  p.confirmation=playCleanupConfirmation(p);
  if(v.agentAccess)v.agentAccess.purpose='version-tag';return v;
}
async function ready(){const f=await h.attached();f.controller.configureVersionTag(selection);f.controller.prepare();
  f.respond('prepare',tagged());await h.flush();assert.ok(f.controller.currentConsent());return f;}

test('future tag grammar and typed prepared preserve branch B, exact F, version and old shapes',()=>{
  assert.ok(parsePlayCleanupStatus(h.review()));assert.ok(parsePlayCleanupStatus(tagged()));assert.ok(parsePlayCleanupStatus(tagged(h.allowed())));
  for(const ref of [futureTag,'refs/tags/v1/a'])assert.equal(futureVersionTag(ref),true);
  for(const ref of ['refs/heads/main','refs/tags/a.lock','refs/tags/a/../b','refs/tags/v1\n','refs/tags//a'])assert.equal(futureVersionTag(ref),false);
  const good=tagged();assert.match(good.consent.prepared.confirmation,/branch-triggered/);assert.match(good.consent.prepared.confirmation,/other automation/);
  for(const mutate of [s=>s.consent.prepared.journalBlob=null,s=>s.consent.prepared.target.versionTag=null,
    s=>s.consent.prepared.candidate.source.ref=futureTag,s=>s.consent.prepared.target.versionTag.finalCommit='9'.repeat(40),
    s=>s.consent.prepared.candidate.version.name='1.2-beta',s=>s.consent.prepared.candidate.version.build=10000,
    s=>s.consent.prepared.confirmation+=' changed']){const v=tagged();mutate(v);assert.equal(parsePlayCleanupStatus(v),null);}
  const wrong=tagged(h.allowed());delete wrong.agentAccess.purpose;assert.equal(parsePlayCleanupStatus(wrong),null);
  for(const suffix of ['\n','\r\n','\u2028','\u2029']){
    assert.equal(versionTagSelection({...selection,candidateId:selection.candidateId+suffix}),false);
    for(const field of ['candidateId','baseVersion','version']){
      const v=tagged(),p=v.consent.prepared;
      if(field==='candidateId')p.candidate.candidateId=p.target.versionTag.candidateId=selection.candidateId+suffix;
      else p.candidate[field].name+=suffix;
      v.operation.target=structuredClone(p.target);p.confirmation=playCleanupConfirmation(p);
      assert.equal(versionTagCandidate(p.candidate),false,`${field} ${JSON.stringify(suffix)}`);
      assert.equal(parsePlayCleanupStatus(v),null); // Matching IDs/confirmation cannot hide malformed DATA.
    }
  }
});
test('same eight RAW calls keep Pending discovery separate from exact Prepare and one-use purpose',()=>{
  const base={sessionId:'session-a',expectedRevision:1,expectedConnectionRevision:12};
  const decode=(name,args)=>{const bytes=encodePlayCleanupRequest(name,args);assert.ok(bytes);return JSON.parse(new TextDecoder().decode(bytes));};
  assert.deepEqual(decode('github_play_cleanup_prepare',{...base,versionTag:selection}),{...base,versionTag:selection});
  assert.deepEqual(decode('github_play_cleanup_pending',{...base,purpose:'version-tag'}),{...base,purpose:'version-tag'});
  assert.equal(encodePlayCleanupRequest('github_play_cleanup_prepare',{...base,purpose:'version-tag'}),null);
  assert.equal(encodePlayCleanupRequest('github_play_cleanup_pending',{...base,versionTag:selection,purpose:'version-tag'}),null);
  for(const suffix of ['\n','\r\n'])assert.equal(encodePlayCleanupRequest('github_play_cleanup_prepare',{
    ...base,versionTag:{...selection,candidateId:selection.candidateId+suffix}}),null);
  for(const purpose of ['push',null])assert.equal(encodePlayCleanupRequest('github_play_cleanup_start',{sessionId:'session-a',expectedRevision:2,consentId:'b'.repeat(32),confirm:true,purpose}),null);
});
test('manual tag selection causes no request and reentrant draft ABA vetoes original Prepare',async()=>{
  const f=await h.attached();const before=f.calls.length;f.controller.configureVersionTag(selection);assert.equal(f.calls.length,before);
  let once=false;const off=f.controller.subscribe(()=>{if(!once&&f.state.pending){once=true;f.controller.configureVersionTag({...selection,finalCommit:'2'.repeat(40)});f.controller.configureVersionTag(selection);}});
  f.controller.prepare();off();assert.equal(f.count('prepare'),0);assert.equal(f.count('start'),0);
});
test('joined typed review delegates only once after original Allow returns; ACK never creates tag',async()=>{
  const f=await ready();f.controller.allowAgent();assert.equal(f.count('allowAgent'),0);
  f.controller.setConfirmed(true);f.controller.allowAgent();assert.equal(f.last('allowAgent').args.purpose,'version-tag');
  f.emit(tagged(h.allowed()));assert.equal(f.controller.currentAgentAccess(),null);
  f.respond('allowAgent',tagged(h.allowed()));await h.flush();assert.equal(f.controller.currentAgentAccess().purpose,'version-tag');
  f.controller.allowAgent();f.controller.dispatch();assert.equal(f.count('allowAgent'),1);assert.equal(f.count('start'),0);
});
test('tag Allow reentry and lost ACK preserve original no-replay even after changing purpose',async()=>{
  const a=await ready();a.controller.setConfirmed(true);let once=false;const off=a.controller.subscribe(()=>{if(!once&&a.state.allowing){once=true;a.controller.configureVersionTag(null);}});
  a.controller.allowAgent();off();assert.equal(a.count('allowAgent'),0);
  const f=await ready();f.controller.setConfirmed(true);f.controller.allowAgent();f.last('allowAgent').reject(Error('inert lost ACK'));await h.flush();
  f.controller.configureVersionTag(null);f.controller.prepare();f.controller.allowAgent();f.controller.dispatch();
  assert.equal(f.state.uncertain,true);assert.equal(f.count('prepare'),1);assert.equal(f.count('allowAgent'),1);assert.equal(f.count('start'),0);
});
test('purpose-only Pending finds original typed rows without selecting a new tag or granting Apply',async()=>{
  const f=await h.attached();f.controller.configureVersionTag({candidateId:'',rowSha256:'',finalCommit:''});f.controller.loadPending();
  assert.equal(f.last('pending').args.purpose,'version-tag');assert.equal(f.last('pending').args.versionTag,undefined);
  const p=tagged().consent.prepared,s=h.operation('pending','settled',3,'none','none',{...h.target(),purpose:'version-tag'});
  s.pending=[{prepared:p,claimed:true,acknowledged:false}];f.respond('pending',s);await h.flush();
  assert.equal(f.state.uncertain,false);assert.equal(f.state.status.pending.length,1);assert.equal(f.controller.currentConsent(),null);
  f.controller.dispatch();assert.equal(f.count('start'),0);assert.equal(f.count('prepare'),0);
});
test('future-tag Reserve uses original branch and exact T echo, separate single editor handoff',async()=>{
  const f=reserve.setup();f.ready();f.c.configure({...reserve.options,futureTag});
  const first=f.c.review();assert.equal(f.last('review').args[1].reference,'refs/heads/main');assert.equal(f.last('review').args[1].futureTag,futureTag);
  f.last('review').resolve(reserve.frame('reviewed',1,{review:{...reserve.frame('reviewed').review,futureTag}}));await first;
  const running=f.c.reserve();const value={...reserve.reserved,futureTag};f.last('reserve').resolve(reserve.frame('reserved',2,{reservation:value}));await running;
  assert.equal(f.c.getSnapshot().unknown,false);assert.equal(f.edits.length,0);assert.equal(f.c.edit(),true);assert.deepEqual(f.edits,[value]);assert.equal(f.c.edit(),false);
  assert.equal(f.calls.length,2);
});
test('future-tag Reserve rejects null/tag-source/changed echo; status alone never mints review',async()=>{
  assert.equal(parseReserveOptions({...reserve.options,futureTag:null}),null);
  assert.equal(parseReserveOptions({...reserve.options,reference:futureTag,futureTag}),null);
  assert.equal(parseVersionReserveStatus(reserve.frame('reserved',2,{reservation:{...reserve.reserved,futureTag:'refs/heads/main'}})),null);
  const f=reserve.setup();f.ready();f.c.configure({...reserve.options,futureTag});const p=f.c.review();
  f.last('review').resolve(reserve.frame('reviewed',1,{review:{...reserve.frame('reviewed').review,futureTag:'refs/tags/other'}}));await p;
  assert.notEqual(f.c.reserveReason(),null);assert.equal(f.calls.filter(c=>c.kind==='reserve').length,0);
});
