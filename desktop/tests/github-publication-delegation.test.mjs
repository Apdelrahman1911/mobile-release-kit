// Actual publication controller and the EXISTING inert IPC fixture. No provider,
// native consent, process retirement, durable history or filesystem is simulated.
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseGithubPublicationSelection, parseGithubPublicationReference, sameGithubPublicationSelection,
  sameGithubPublicationReference, githubPublicationEffect } from '../src/githubPublicationDelegation.ts';
import { githubPublicationOwnerReason } from '../src/githubPublicationController.ts';
import { parsePublicationStatus } from '../src/githubPublicationProtocol.ts';
import { connection, pending, operation, review, draftResult, deferred, flush, attached, ready, marker, consentId } from './github-publication.test.mjs';

const publish = () => ({ kind: 'setup-publish', sessionId: 'session-a', expectedRevision: 3, consentId });
const reconcile = () => ({ kind: 'setup-reconcile', sessionId: 'session-a', expectedRevision: 3, marker });
const loaded = (revision = 3) => ({ ...operation('pending', 'settled', revision), pending: [pending()] });
async function readReady() { const h = await attached(); h.controller.loadPending(); h.respond('pending', loaded()); await flush(); return h; }

test('publication permission references keep native consent and original-intent hashes in distinct closed shapes', () => {
  for (const [selection, hash] of [[publish(), 'preparedSha256'], [reconcile(), 'recordSha256']]) {
    const reference = { ...selection, [hash]: 'a'.repeat(64) };
    assert.deepEqual(structuredClone(parseGithubPublicationSelection(selection)), selection);
    assert.deepEqual(structuredClone(parseGithubPublicationReference(reference)), reference);
    assert.equal(parseGithubPublicationSelection(reference), null); // native hash is not Allow input
    assert.equal(parseGithubPublicationReference(selection), null);
    assert.equal(sameGithubPublicationSelection(selection, structuredClone(selection)), true);
    assert.equal(sameGithubPublicationReference(reference, { ...reference, [hash]: 'b'.repeat(64) }), false);
    for (const field of ['root', 'path', 'token', 'prepared', 'source', 'projectId', 'purpose', 'create', 'force']) {
      assert.equal(parseGithubPublicationSelection({ ...selection, [field]: 'INERT' }), null);
    }
  }
  assert.equal(sameGithubPublicationSelection(publish(), reconcile()), false);
  assert.equal(parseGithubPublicationSelection({ ...reconcile(), consentId: marker }), null);
  assert.equal(parseGithubPublicationSelection({ ...publish(), marker: consentId }), null);
  assert.equal(parseGithubPublicationReference({ ...reconcile(), preparedSha256: 'a'.repeat(64) }), null);
  assert.equal(parseGithubPublicationReference({ ...publish(), recordSha256: 'a'.repeat(64) }), null);
});

test('publication reference grammar rejects line endings, oversized fields, accessors and counter or foreign grant kinds', () => {
  for (const base of [publish(), reconcile()]) {
    for (const field of ['sessionId', base.kind === 'setup-publish' ? 'consentId' : 'marker']) {
      for (const suffix of ['\n', '\r\n', '\u2028', '\u2029', ' ', '\0']) assert.equal(parseGithubPublicationSelection({ ...base, [field]: base[field] + suffix }), null);
    }
    for (const revision of [0, -0, -1, 3.1, NaN, Infinity, 0xffff_ffff]) assert.equal(parseGithubPublicationSelection({ ...base, expectedRevision: revision }), null);
    for (const kind of ['version-counter', 'repository-create', 'draft-pr-create', 'pr-create', 'failed-jobs-retry', null]) assert.equal(parseGithubPublicationSelection({ ...base, kind }), null);
    assert.equal(parseGithubPublicationSelection({ ...base, sessionId: 'a'.repeat(65) }), null);
  }
  let getters = 0; const v = publish(); Object.defineProperty(v, 'consentId', { enumerable: true, get() { getters++; return consentId; } });
  assert.equal(parseGithubPublicationSelection(v), null); assert.equal(getters, 0);
  const ref = { ...reconcile(), recordSha256: 'a'.repeat(64) };
  for (const value of ['A'.repeat(64), 'a'.repeat(64) + '\n', null, '']) assert.equal(parseGithubPublicationReference({ ...ref, recordSha256: value }), null);
});

test('read-only delegation preserves historical observations without mutation GO or created/counter receipt promotion', () => {
  for (const effect of ['none', 'unresolved', 'branch-observed', 'draft-pr-observed']) assert.equal(githubPublicationEffect('setup-reconcile', effect), true);
  for (const effect of ['not-sent', 'potentially-applied', 'created-observed', 'counter-observed', 'accepted', null]) assert.equal(githubPublicationEffect('setup-reconcile', effect), false);
  for (const effect of ['not-sent', 'potentially-applied', 'draft-pr-observed']) assert.equal(githubPublicationEffect('setup-publish', effect), true);
  for (const effect of ['none', 'unresolved', 'branch-observed', 'created-observed', 'counter-observed']) assert.equal(githubPublicationEffect('setup-publish', effect), false);
});

for (const kind of ['prepare', 'publish', 'pending', 'reconcile']) {
  test(`ordinary ${kind} retains its actual caller across terminal event and earlier Status`, async () => {
    const h = kind === 'publish' ? await ready() : kind === 'reconcile' ? await readReady() : await attached();
    if (kind === 'prepare') h.controller.prepare();
    else if (kind === 'publish') { h.controller.setConfirmed(true); h.controller.publish(); }
    else if (kind === 'pending') h.controller.loadPending();
    else h.controller.reconcile(marker);
    const terminal = kind === 'prepare' ? review() : kind === 'pending' ? loaded() : draftResult(5, kind);
    assert.equal(h.count(kind), 1); h.emit(terminal); await h.controller.checkStatus();
    assert.equal(h.state.pending, true); assert.ok(githubPublicationOwnerReason(h.state));
    assert.equal(h.controller.currentConsent(), null); assert.equal(h.controller.currentPending(marker), null);
    assert.equal(h.count('discard'), 0);
    h.respond(kind, operation(kind, 'running', terminal.revision - 1, 'none', kind === 'publish' ? 'potentially-applied' : 'none'));
    await flush(); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false);
    assert.equal(h.state.status.revision, terminal.revision);
    if (kind === 'prepare') assert.ok(h.controller.currentConsent());
    if (kind === 'pending') assert.deepEqual(h.controller.currentPending(marker), pending());
  });
}

test('lost original Pending ACK needs a fresh post-return Status; a previously begun read or event cannot mint its row witness', async () => {
  const h = await attached(); h.controller.loadPending();
  const d = deferred(), ordinaryRead = h.api.githubPublicationStatus;
  h.api.githubPublicationStatus = () => d.promise;
  const reading = h.controller.checkStatus(); await flush();
  h.last('pending').reject(new Error('INERT lost original return')); await flush();
  h.emit(loaded()); d.resolve(loaded()); await reading;
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentPending(marker), null);
  h.controller.loadPending(); h.controller.reconcile(marker); assert.equal(h.count('pending'), 1); assert.equal(h.count('reconcile'), 0);
  h.api.githubPublicationStatus = ordinaryRead; await h.controller.checkStatus();
  assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false); assert.deepEqual(h.controller.currentPending(marker), pending());
});

test('cold or event-shaped Pending rows are display DATA, never an original delegation reference', async () => {
  const h = await attached(); const s = loaded(); assert.ok(parsePublicationStatus(s));
  h.emit(s); await h.controller.checkStatus();
  assert.equal(h.state.status.pending.length, 1); assert.equal(h.controller.currentPending(marker), null); assert.equal(h.count('pending'), 0);
  h.controller.loadPending(); const next = loaded(5); next.operation.id = 'pending-b';
  h.respond('pending', next); await flush(); assert.deepEqual(h.controller.currentPending(marker), pending());
});

test('joined pending witness compares the entire original row, not just marker or latest status', async () => {
  const h = await readReady(); assert.ok(h.controller.currentPending(marker));
  const changed = loaded(4); changed.pending[0].confirmed.pull = '99'; assert.ok(parsePublicationStatus(changed));
  h.emit(changed); assert.equal(h.controller.currentPending(marker), null);
  h.emit(loaded(5)); await h.controller.checkStatus(); assert.equal(h.controller.currentPending(marker), null); // equal old bytes do not restore original identity
  assert.equal(h.count('pending'), 1); assert.equal(h.count('reconcile'), 0);
});

test('account/source/API ABA and reentrant workspace invalidation cannot revive the joined original Pending selection', async () => {
  for (const change of ['account', 'workspace', 'api']) {
    const h = await readReady(); assert.ok(h.controller.currentPending(marker));
    if (change === 'account') { const c = connection(); c.status.account.value.id = '99'; h.context(c); h.context(connection()); }
    else if (change === 'workspace') { h.controller.beforeWorkspaceAction(); }
    else { await h.controller.connect(null); await h.controller.connect(h.api); }
    await h.controller.checkStatus(); assert.equal(h.controller.currentPending(marker), null);
    assert.equal(h.count('pending'), 1); assert.equal(h.count('reconcile'), 0);
  }
  const h = await attached(); let once = false;
  h.controller.subscribe(() => { if (!once && h.state.status?.pending.length) { once = true; h.controller.beforeWorkspaceAction(); } });
  h.controller.loadPending(); h.respond('pending', loaded()); await flush();
  assert.equal(h.controller.currentPending(marker), null); assert.equal(h.state.pending, false);
});

test('disposed ordinary read keeps original observer until its real return and never grants a late row', async () => {
  const h = await attached(); h.controller.loadPending(); h.controller.dispose(); h.emit(loaded()); await flush();
  assert.equal(h.detached, 0); assert.equal(h.controller.currentPending(marker), null);
  h.respond('pending', loaded()); await flush(); assert.equal(h.detached, 1); assert.equal(h.controller.currentPending(marker), null);
});

test('service replacement retains an already-started Status caller before detaching its original observer', async () => {
  const h = await attached(); const d = deferred();
  h.api.githubPublicationStatus = () => d.promise;
  const reading = h.controller.checkStatus(); await flush();
  await h.controller.connect(null); assert.equal(h.detached, 0);
  d.resolve(loaded()); await reading; assert.equal(h.detached, 1);
  assert.equal(h.controller.currentPending(marker), null); assert.equal(h.count('pending'), 0);
});

test('original cleanup-unknown cannot be released or converted to a pending-row witness by later success DATA', async () => {
  const h = await attached(); h.controller.loadPending();
  h.respond('pending', operation('pending', 'cleanup-unknown', 3, 'cleanup-unknown')); await flush();
  h.emit(loaded(4)); await h.controller.checkStatus();
  assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentPending(marker), null);
  h.controller.loadPending(); h.controller.reconcile(marker); assert.equal(h.count('pending'), 1); assert.equal(h.count('reconcile'), 0);
});

test('CLI row selection is explicit, uses the actual joined Pending row and sends no extra native command', async () => {
  const h = await readReady();
  assert.equal(h.controller.agentSelection('setup-reconcile'), null);
  assert.equal(h.controller.selectPendingForAgent(marker), true);
  const selection = h.controller.agentSelection('setup-reconcile');
  assert.deepEqual(selection, reconcile());
  assert.deepEqual(h.controller.selectedPendingForAgent(), pending());
  await h.controller.checkStatus();
  assert.deepEqual(h.controller.agentSelection('setup-reconcile'), selection);
  for (const name of ['prepare', 'publish', 'reconcile', 'discard']) assert.equal(h.count(name), 0);
  assert.equal(h.count('pending'), 1);
  h.controller.beforeWorkspaceAction();
  assert.equal(h.controller.selectedPendingForAgent(), null);
  assert.equal(h.controller.agentSelection('setup-reconcile'), null);
});

test('CLI selection cannot turn cold rows, an outstanding Status or reentrant source change into authority', async () => {
  const cold = await attached(); cold.emit(loaded()); await cold.controller.checkStatus();
  assert.equal(cold.controller.selectPendingForAgent(marker), false);
  const h = await readReady(); const d = deferred();
  h.api.githubPublicationStatus = () => d.promise;
  const reading = h.controller.checkStatus(); await flush();
  assert.equal(h.controller.selectPendingForAgent(marker), false);
  assert.equal(h.controller.agentSelection('setup-reconcile'), null);
  d.resolve(loaded()); await reading;
  let once = false;
  h.controller.subscribe(() => { if (!once && h.controller.selectedPendingForAgent()) { once = true; h.controller.beforeWorkspaceAction(); } });
  assert.equal(h.controller.selectPendingForAgent(marker), false);
  assert.equal(h.controller.agentSelection('setup-reconcile'), null);
  assert.equal(h.count('reconcile'), 0);
});

test('CLI Publish selection requires the actual returned ordinary five-file review, not approval or event DATA', async () => {
  const h = await attached(); h.controller.prepare(); h.emit(review());
  assert.equal(h.controller.agentSelection('setup-publish'), null);
  h.respond('prepare', review()); await flush();
  assert.deepEqual(h.controller.agentSelection('setup-publish'), publish());
  assert.equal(h.state.confirmed, false);
  assert.equal(h.count('publish'), 0);
  h.controller.setPurpose('version-counter');
  assert.equal(h.controller.agentSelection('setup-publish'), null);
  assert.equal(h.controller.agentSelection('setup-reconcile'), null);
});

// Real shared permission/controller methods with explicitly inert IPC; no
// fake session or service-history receipt is given to native code.
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { createAgentGithubActionPort, parseGithubActionSelection, parseGithubActionStatus,
  parseAgentGithubActionAccess, GITHUB_ACTION_KINDS } from '../src/agentGithubActionAccess.ts';
const hex=(c,n=32)=>c.repeat(n);
function reference(selection) { return {...selection,[selection.kind==='setup-publish'?'preparedSha256':'recordSha256']:hex('a',64)}; }
function cliStatus(selection, patch={}) {return {origin:{projectId:hex('1'),serviceInstance:hex('2'),requestId:hex('4')},grantId:hex('3'),review:reference(selection),revision:7,
  state:'complete',settlement:'settled',operationId:'github-publication-42',reason:'none',effect:'draft-pr-observed',neverAdmitted:false,doNotReplay:true,...patch};}
function cliAccess(selection,status=null,patch={}) {return {serviceInstance:hex('2'),projectId:hex('1'),grantId:hex('3'),review:reference(selection),enabled:!status,remainingMs:status?0:90000,consumed:!!status,
  pending:!!status&&status.settlement!=='settled',unknown:status?.settlement==='unknown',status,...patch};}
function permission(h,kind) {
  const calls=[],nativeSession={},epoch={};let peer=null;
  const port=Object.fromEntries(['access','allow','request','revoke'].map(k=>[k,(value)=>{const d=deferred();calls.push({kind:k,value,...d});return d.promise;} ]));
  const controller=new AgentGithubActionAccessController({syncOriginal:()=>h.controller.syncContext(),delegate:s=>h.controller.delegatePrepared(s),
    current:()=>({port,nativeSession,projectId:'project-a',epoch,preview:false,blockedReason:peer,reviews:[h.controller.agentSelection(kind)].filter(Boolean)})});
  assert.equal(controller.choose(kind),true);
  return {controller,calls,port,peer(v){peer=v;},last:k=>calls.filter(c=>c.kind===k).at(-1),count:k=>calls.filter(c=>c.kind===k).length};
}
async function forCli(kind) {const h=kind==='setup-publish'?await ready():await readReady();if(kind==='setup-reconcile')assert.equal(h.controller.selectPendingForAgent(marker),true);return h;}
function nativeFinal(kind) {const s=draftResult(5,kind==='setup-publish'?'publish':'reconcile');s.operation.id='github-publication-42';return s;}
async function grant(h,p,kind) {const selection=h.controller.agentSelection(kind);assert.equal(p.controller.acknowledge(true),true);const work=p.controller.allow();assert.equal(p.count('allow'),1);
  p.last('allow').resolve(cliAccess(selection));await work;assert.equal(p.controller.getSnapshot().unknown,false);return selection;}
async function sharedFinal(p,selection,status=cliStatus(selection)) {const work=p.controller.check();p.last('access').resolve(cliAccess(selection,status));await flush();if(status.settlement!=='unknown')p.last('request').resolve(status);await work;}

test('shared publication codec keeps both strict shapes and GET-only effects without inheriting old mutation fallbacks',async()=>{
  assert.deepEqual(GITHUB_ACTION_KINDS,['repository-create','draft-pr-create','pr-create','failed-jobs-retry','setup-publish','setup-reconcile']);
  const calls=[],port=createAgentGithubActionPort(async(name,body)=>{calls.push([name,JSON.parse(new TextDecoder().decode(body))]);return null;});
  for(const selection of [publish(),reconcile()]) {
    assert.ok(parseGithubActionSelection(selection));assert.ok(parseGithubActionStatus(cliStatus(selection)));assert.ok(parseAgentGithubActionAccess(cliAccess(selection)));
    await port.allow(selection);assert.deepEqual(calls.at(-1)[1],{selection,consentVersion:`agent-${selection.kind}-once-v1`});
    for(const effect of ['created-observed','accepted','counter-observed','acknowledged-unconfirmed'])assert.equal(parseGithubActionStatus(cliStatus(selection,{effect})),null);
    for(const field of ['token','files','root','purpose'])assert.equal(parseGithubActionSelection({...selection,[field]:'INERT'}),null);
  }
  for(const effect of ['none','unresolved','branch-observed'])assert.ok(parseGithubActionStatus(cliStatus(reconcile(),{effect})));
  for(const effect of ['not-sent','potentially-applied'])assert.equal(parseGithubActionStatus(cliStatus(reconcile(),{effect})),null);
  const refusal=cliStatus(reconcile(),{state:'refused',reason:'native-refused',operationId:null,effect:'none',neverAdmitted:true});assert.ok(parseGithubActionStatus(refusal));
  assert.equal(parseGithubActionStatus({...refusal,effect:'not-sent'}),null);
});
for(const kind of ['setup-publish','setup-reconcile']) {
  test(`${kind} shared Allow cannot start native work or replace the original, and real history return still needs later original Status`,async()=>{
    const h=await forCli(kind),p=permission(h,kind),selection=await grant(h,p,kind);
    assert.equal(h.state.delegating,true);assert.equal(h.controller.agentSelection(kind),null);assert.ok(h.controller.startReason());
    h.controller.setConfirmed(true);h.controller.publish();h.controller.reconcile(marker);assert.equal(h.count('publish'),0);assert.equal(h.count('reconcile'),0);
    assert.equal(await p.controller.allow(),false);h.emit(nativeFinal(kind));await h.controller.checkStatus();
    assert.equal(h.state.delegating,true); // event/earlier native Status is not service history
    await sharedFinal(p,selection);assert.equal(h.state.delegating,true);
    await h.controller.checkStatus();assert.equal(h.state.delegating,false);assert.equal(h.controller.agentSelection(kind),null);
    assert.equal(p.count('allow'),1);
  });
  test(`${kind} pending Allow and pre-history Status cannot retroactively close after terminal events`,async()=>{
    const h=await forCli(kind),p=permission(h,kind),selection=h.controller.agentSelection(kind);
    p.controller.acknowledge(true);const allow=p.controller.allow();h.emit(nativeFinal(kind));
    const d=deferred(),old=h.api.githubPublicationStatus;h.api.githubPublicationStatus=()=>d.promise;
    const reading=h.controller.checkStatus();await flush();p.last('allow').resolve(cliAccess(selection));await allow;
    await sharedFinal(p,selection);d.resolve(nativeFinal(kind));await reading;assert.equal(h.state.delegating,true);
    h.api.githubPublicationStatus=old;await h.controller.checkStatus();assert.equal(h.state.delegating,false);
  });
  test(`${kind} lost Allow and history Unknown stay absorbing despite known native final and Revoke`,async()=>{
    const h=await forCli(kind),p=permission(h,kind),selection=h.controller.agentSelection(kind);
    p.controller.acknowledge(true);const work=p.controller.allow();p.last('allow').reject(new Error('INERT private'));await work;
    h.emit(nativeFinal(kind));await h.controller.checkStatus();assert.equal(h.state.uncertain,true);assert.equal(h.state.delegating,true);assert.equal(p.controller.getSnapshot().unknown,true);
    const revoke=p.controller.revoke();p.last('revoke').resolve(cliAccess(selection,null,{enabled:false,remainingMs:0}));await revoke;
    assert.equal(h.state.delegating,true);assert.equal(await p.controller.allow(),false);assert.equal(JSON.stringify(p.controller.getSnapshot()).includes('INERT private'),false);
  });
}
test('reconcile unused permission requires genuine returned revoke/check plus a later same-row Status; no fabricated Consent',async()=>{
  const h=await forCli('setup-reconcile'),p=permission(h,'setup-reconcile'),selection=await grant(h,p,'setup-reconcile');
  const revoke=p.controller.revoke();p.last('revoke').resolve(cliAccess(selection,null,{enabled:false,remainingMs:0}));await revoke;
  await h.controller.checkStatus();assert.equal(h.state.delegating,true);
  const check=p.controller.check();p.last('access').resolve(cliAccess(selection,null,{enabled:false,remainingMs:0}));await check;
  assert.equal(h.state.delegating,true);await h.controller.checkStatus();assert.equal(h.state.delegating,false);
  assert.equal(h.state.status.consent,null);assert.equal(h.count('reconcile'),0);assert.equal(h.count('discard'),0);
});
test('publication handoff latches before reentrant peer/source changes and performs no Allow or duplicate native action',async()=>{
  for(const kind of ['setup-publish','setup-reconcile']) {
    const h=await forCli(kind),p=permission(h,kind);p.controller.acknowledge(true);let once=false;
    h.controller.subscribe(()=>{if(!once&&h.state.delegating){once=true;p.peer('Other owner');h.controller.beforeWorkspaceAction();}});
    assert.equal(await p.controller.allow(),false);assert.equal(p.count('allow'),0);assert.equal(h.count('publish'),0);assert.equal(h.count('reconcile'),0);assert.equal(h.controller.agentSelection(kind),null);
    if(kind==='setup-publish'){h.respond('discard',operation('prepare','settled',4));await flush();}
    await h.controller.checkStatus();assert.equal(h.state.delegating,false);
  }
});
test('reconcile final must match original operation and full effect; late equal row or foreign final never releases it',async()=>{
  const h=await forCli('setup-reconcile'),p=permission(h,'setup-reconcile'),selection=await grant(h,p,'setup-reconcile');
  const foreign=nativeFinal('setup-reconcile');foreign.operation.id='github-publication-43';h.emit(foreign);await sharedFinal(p,selection);await h.controller.checkStatus();assert.equal(h.state.delegating,true);
  const b=await forCli('setup-reconcile'),q=permission(b,'setup-reconcile'),s=await grant(b,q,'setup-reconcile');
  b.emit(nativeFinal('setup-reconcile'));await sharedFinal(q,s,cliStatus(s,{state:'unknown',settlement:'unknown',reason:'history-unavailable'}));
  await b.controller.checkStatus();assert.equal(b.state.uncertain,true);assert.equal(b.state.delegating,true);
});
