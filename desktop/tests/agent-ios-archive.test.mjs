// Closed comparison DATA and original controlled-promise controller checks.
// No native grant, tool, process, filesystem, credential or build is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AGENT_IOS_ARCHIVE_CONSENT, AgentIOSArchivePermission, copyIOSArchiveApproval,
  createAgentIOSArchiveApi, encodeIOSArchiveAccessRequest, parseIOSArchiveAccess } from '../src/agentIOSArchive.ts';
import { canObserveAgentIOSArchive } from '../src/agentIOSArchiveOrigin.ts';
import { IOSArchiveController } from '../src/iosArchive.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { iosArchiveOperationProgress, copyIOSArchiveRequest, parseIOSArchiveStatus } from '../src/iosArchiveProtocol.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';

const id = (c) => c.repeat(32), clone = structuredClone;
const ORIGIN = { serviceInstance: id('a'), projectId: id('b'), requestId: id('c') };
const CONFIG = { bytes: 512, sha256: 'd'.repeat(64) };
const VERSION = { source: 'release/version.properties', bytes: 41, sha256: 'f'.repeat(64), name: '1.2.3', build: 42 };
const approval = () => ({ input: { projectId: 'p1', draftRevision: 0, baselineGeneration: 1, savedConfig: clone(CONFIG),
  savedVersion: clone(VERSION) } });
const enabled = () => ({ enabled: true, remainingMs: 900_000, projectId: ORIGIN.projectId, observationRevision: 7, consumed: false });
const disabled = () => ({ enabled: false, remainingMs: 0, projectId: null, observationRevision: null, consumed: false });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 18; n++) await Promise.resolve(); };
function port() {
  const calls = [];
  const api = Object.fromEntries(['allow', 'status', 'revoke'].map((kind) => [kind, (value) => {
    const call = { kind, value, ...deferred() }; calls.push(call); return call.promise;
  }]));
  return { api, calls };
}
function permission(p = port()) { const controller = new AgentIOSArchivePermission(); controller.bind(p.api, approval()); return { ...p, controller }; }
const status = (revision = 0, operation = null) => ({ schemaVersion: 2, statusRevision: revision, availability: 'available', modeCapabilities:{unsigned:true,signed:false,recovery:false,signingCheck:false}, operation });
const operation = (patch = {}, input = approval().input) => ({ operationId: id('d'), ownerGeneration: id('e'),
  context: { ...clone(input), platform: 'ios', operation: 'ios-unsigned-archive' },
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null,
  agentIosArchive: clone(ORIGIN), ...patch });
const terminal = (patch = {}) => operation({ phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', ...patch });
const unmarked = (op) => { const result = clone(op); delete result.agentIosArchive; return result; };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function snapshot() {
  return { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(CONFIG), issues: [],
      data: { ios: { enabled: true, project: 'ios/Inert.xcodeproj', scheme: 'Inert', bundleId: 'org.example.inert', archiveConfiguration: 'Release', symbols: {policy: 'required'} },
        version: { source: VERSION.source, nameKey: 'NAME', buildKey: 'BUILD' } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(assurance), issues: [] };
}
function workspace() {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'DATA iOS project', path: '/inert/never-forwarded' } });
  value = workspaceReducer(value, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  return workspaceReducer(value, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot: snapshot(), observedAt: 1 });
}
async function nativeView(t, initial = status()) {
  let state = workspace(), current = clone(initial), listener; const calls = [], versionCalls = [];
  const selected = () => state.projects.p1;
  const version = new ReleaseVersionController(selected);
  version.setConnection({ mode: 'native', observeReleaseVersion: () => { const call = deferred(); versionCalls.push(call); return call.promise; } },
    { runtime: { state: 'available', mode: 'development', reason: null }, capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject();
  const api = { mode: 'native',
    subscribeIOSArchive: async (fn) => { listener = fn; return () => { listener = null; }; },
    iosArchiveStatus: async () => clone(current),
    prepareIOSArchive: (input) => { const call = { kind: 'prepare', input, ...deferred() }; calls.push(call); return call.promise; },
    startIOSArchive: (input) => { const call = { kind: 'start', input, ...deferred() }; calls.push(call); return call.promise; },
    cancelIOSArchive: (operationId, ownerGeneration) => { calls.push({ kind: 'cancel', operationId, ownerGeneration });
      current = status(current.statusRevision + 1, { ...current.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' });
      return Promise.resolve(clone(current)); },
  };
  const controller = new IOSArchiveController({ selectedProject: selected, releaseVersion: () => version.getSnapshot(), otherOperationReason: () => null, now: () => 100 });
  const unsubscribeVersion = version.subscribe(controller.syncReleaseVersion);
  controller.syncProject(); controller.setVisible(true); await controller.connect(api);
  controller.versionIntent(); const reading = version.read(); assert.equal(versionCalls.length, 1);
  versionCalls[0].resolve({ schemaVersion: 2, source: VERSION.source, version: { name: VERSION.name, build: VERSION.build },
    savedConfig: clone(CONFIG), savedVersion: { bytes: VERSION.bytes, sha256: VERSION.sha256 },
    observationScope: 'single-request-non-atomic', assurance: clone(assurance) }); await reading;
  t.after(() => { unsubscribeVersion(); controller.dispose(); version.dispose(); });
  return { controller, calls, get project() { return selected(); },
    emit(value) { assert.ok(parseIOSArchiveStatus(value)); current = clone(value); listener?.(clone(value)); },
    reply(call, value) { assert.ok(parseIOSArchiveStatus(value)); current = clone(value); call.resolve(clone(value)); },
    dispatch(action) { controller.beforeWorkspaceAction(action); version.beforeWorkspaceAction(action);
      state = workspaceReducer(state, action); version.syncProject(); controller.syncProject(); } };
}


test('only fixed iOS saved inputs enter its three permission routes; neither Android nor signing grants cross', async () => {
  const calls=[],api=createAgentIOSArchiveApi('native',async(command,raw)=>{assert.ok(raw instanceof Uint8Array&&raw.length<=4096);calls.push({command,value:JSON.parse(new TextDecoder().decode(raw))});return disabled();});
  await api.allow(approval());await api.status();await api.revoke();
  assert.deepEqual(calls.map(c=>c.command),['allow_agent_ios_archive','agent_ios_archive_access','revoke_agent_ios_archive']);
  assert.deepEqual(calls[0].value,{...approval(),consentVersion:AGENT_IOS_ARCHIVE_CONSENT});
  for(const field of ['toolchainSelection','root','command','window','operationId','executable','environment'])assert.equal(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',{...calls[0].value,[field]:'not-authority'}),null);
  assert.equal(encodeIOSArchiveAccessRequest('allow_agent_android_build',calls[0].value),null);
  assert.equal(encodeIOSArchiveAccessRequest('allow_agent_ios_archive',{...calls[0].value,consentVersion:'agent-saved-android-build-inspect-v1'}),null);
  assert.equal(createAgentIOSArchiveApi('preview',()=>assert.fail('no native fallback')),null);
  for(const fields of [{action:'create'},{action:'check-signing'},{recovery:{action:'inspect'}},{signing:{teamId:'ABCDE12345',distributionCertificateSha256:'a'.repeat(64),assignments:[]}},{artifactValidation:{mode:'structure-and-version',uploadCertificateSha256:null}}])assert.equal(copyIOSArchiveApproval({input:{...approval().input,...fields}}),null);
});
test('bounded iOS approval copying never calls property getters and retains the saved pair only', async () => {
  let reads=0,calls=0;const value=approval();Object.defineProperty(value.input,'savedVersion',{enumerable:true,get(){reads++;return VERSION;}});
  const api=createAgentIOSArchiveApi('native',async()=>{calls++;return disabled();});await assert.rejects(api.allow(value));assert.equal(reads,0);assert.equal(calls,0);
  const original=approval(),copied=copyIOSArchiveApproval(original);assert.ok(copied);original.input.savedVersion.name='changed';assert.equal(copied.input.savedVersion.name,VERSION.name);assert.ok(Object.isFrozen(copied.input.savedVersion));
  const huge=approval();huge.input.savedVersion.source='x'.repeat(4096);assert.equal(copyIOSArchiveApproval(huge),null);
});
test('iOS uses shared original UI revoke and pending-status connection retention, without a fresh Allow after reentrant Stop', async () => {
  const p=permission();let stopping,once=false;const unsubscribe=p.controller.subscribe(s=>{if(s.pending==='allow'&&!once){once=true;stopping=p.controller.revoke();}});
  p.controller.acknowledge(true);const allowing=p.controller.allow();assert.deepEqual(p.calls.map(c=>c.kind),['revoke']);p.calls[0].resolve(disabled());await stopping;await allowing;unsubscribe();
  const next=port(),reading=p.controller.status();p.controller.bind(next.api,approval());p.calls[1].resolve(enabled());await reading;
  p.controller.acknowledge(true);await p.controller.allow();assert.equal(next.calls.length,0);
  const stoppingAgain=p.controller.revoke();assert.equal(p.calls[2].kind,'revoke');p.calls[2].resolve(disabled());await stoppingAgain;
});
test('native iOS origin remains unsigned-only immutable DATA, never a GUI Prepare authority',()=>{
  const a=operation(),b=operation({phase:'running',intentUsable:false,stage:'archiving'});
  assert.ok(parseIOSArchiveStatus(status(1,a)));assert.ok(iosArchiveOperationProgress(a,b));assert.equal(iosArchiveOperationProgress(a,unmarked(b)),false);
  for(const change of [v=>{v.agentIosArchive.requestId=id('0');},v=>{v.agentIosArchive.window='main';},v=>{v.agentIosArchive=null;},v=>{v.agentAndroidBuild=v.agentIosArchive;delete v.agentIosArchive;},v=>{v.context.operation='ios-signed-export';},v=>{v.context.action='create';}]){const value=operation();change(value);assert.equal(parseIOSArchiveStatus(status(1,value)),null);}
  assert.equal(copyIOSArchiveRequest('prepare_ios_archive',{...approval().input,agentIosArchive:ORIGIN}),null);
});
test('same original saved-version controller supplies iOS approval and edits revoke the comparison',async(t)=>{
  const h=await nativeView(t);const a=h.controller.agentArchiveApproval();assert.ok(a,h.controller.prepareReason());assert.deepEqual(clone(a),{input:{...approval().input,draftRevision:h.project.revision,baselineGeneration:h.project.baselineGeneration}});
  h.dispatch({type:'edit',projectId:'p1',path:'ios.bundleId',value:'org.example.changed'});
  assert.equal(h.controller.agentArchiveApproval(),null);assert.equal(h.calls.length,0);
});
test('CLI Prepared adopts observe/STOP only after prior native terminal; GUI never fabricates Start consent', async (t) => {
  const old = unmarked(terminal({ operationId: id('1'), ownerGeneration: id('2') }));
  const h = await nativeView(t, status(2, old)); h.emit(status(3, operation()));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  assert.deepEqual({ ...h.controller.getSnapshot().status.operation.agentIosArchive }, ORIGIN);
  assert.equal(h.controller.getSnapshot().consent, null); assert.equal(h.controller.getSnapshot().historical, true);
  await h.controller.start(id('d'), id('e')); assert.equal(h.calls.length, 0);
  assert.equal(h.controller.cancel(), true); await flush();
  assert.deepEqual(h.calls, [{ kind: 'cancel', operationId: id('d'), ownerGeneration: id('e') }]);
  assert.equal(h.controller.getSnapshot().status.operation.phase, 'terminal');
});

test('active or unknown native originals and unmarked foreign IDs cannot be replaced by CLI DATA', async (t) => {
  for (const old of [operation({ operationId: id('1'), ownerGeneration: id('2'), phase: 'running', intentUsable: false }),
    operation({ operationId: id('1'), ownerGeneration: id('2'), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' })]) {
    assert.equal(canObserveAgentIOSArchive(status(2, old), status(3, operation()), false), false);
    const h = await nativeView(t, status(2, old)); h.emit(status(3, operation()));
    assert.equal(h.controller.getSnapshot().integrityFailed, true); assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  }
  const h = await nativeView(t, status(2, unmarked(terminal({ operationId: id('1'), ownerGeneration: id('2') }))));
  h.emit(status(3, unmarked(operation()))); assert.equal(h.controller.getSnapshot().integrityFailed, true);
});

test('pending GUI Prepare defers CLI display until the actual pre-admission refusal returns', async (t) => {
  const h = await nativeView(t, status(2, unmarked(terminal({ operationId: id('1'), ownerGeneration: id('2') }))));
  const preparing = h.controller.prepare(); assert.equal(h.calls[0].kind, 'prepare');
  h.emit(status(3, operation())); assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  assert.equal(h.controller.getSnapshot().integrityFailed, false);
  h.calls[0].reject({ code: 'ios_archive_busy' }); await preparing;
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('d'));
  assert.equal(h.controller.getSnapshot().consent, null); assert.equal(h.calls.length, 1);
});

test('actual GUI Start return is retained after terminal before a CLI request may take display', async (t) => {
  const h = await nativeView(t); const preparing = h.controller.prepare(), call = h.calls[0];
  const gui = unmarked(operation({ operationId: id('1'), ownerGeneration: id('2') }, call.input));
  h.reply(call, status(1, gui)); await preparing;
  h.controller.setAcknowledged(id('1'), id('2'), true); const starting = h.controller.start(id('1'), id('2')); assert.equal(h.calls[1].kind, 'start');
  h.emit(status(3, { ...gui, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled' }));
  h.emit(status(4, operation())); assert.equal(h.controller.getSnapshot().status.operation.operationId, id('1'));
  h.calls[1].resolve(status(2, { ...gui, phase: 'starting', intentUsable: false })); await starting;
  assert.equal(h.controller.getSnapshot().status.operation.operationId, id('d')); assert.equal(h.controller.getSnapshot().integrityFailed, false);
  await h.controller.start(id('d'), id('e')); assert.equal(h.calls.length, 2);
});
