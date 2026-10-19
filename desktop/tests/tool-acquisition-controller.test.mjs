// Controller custody tests with fake ports and inert comparison DATA only.
// No native qualification, source read, tool command, download or installation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ToolAcquisitionController } from '../src/toolAcquisitionController.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { TOOL_ACQUISITION_CONSENT } from '../src/toolAcquisitionProtocol.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), ACQUIRE = 'c'.repeat(32), ACQUIRE_OWNER = 'd'.repeat(32);
const SHA = 'e'.repeat(64), CONTENT = { bytes: 120, sha256: SHA };
const clone = (v) => structuredClone(v);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 60; i++) await Promise.resolve(); };
function workspace() {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'project-1', name: 'Inert project', path: '/never-opened' } });
  value = workspaceReducer(value, { type: 'snapshot-start', projectId: 'project-1', requestId: 1 });
  return workspaceReducer(value, { type: 'snapshot-done', projectId: 'project-1', requestId: 1, observedAt: 1,
    snapshot: { root: '/never-opened', config: { path: 'release/mobile-release.json', state: 'format-valid',
      data: { android: { enabled: true, module: ':app' } }, content: clone(CONTENT), issues: [] }, discovery: { hints: {} }, issues: [] } });
}
const status = (revision = 1, operation = null, availability = operation && operation.phase !== 'terminal' ? 'busy' : 'available') =>
  ({ schemaVersion: 1, statusRevision: revision, availability, operation });
const operation = (context, acquire = false) => ({ operationId: acquire ? ACQUIRE : OP, ownerGeneration: acquire ? ACQUIRE_OWNER : OWNER,
  context: clone(context), phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null });
const requirements = () => ({ kind: 'tool-requirements-observation', requirements: {
  schemaVersion: 1, basis: 'unverified-static-source-hints', sourcesSha256: SHA, complete: true, platform: 'android', projectCodeExecuted: false,
  xcode: { version: '26.3', build: '17C529' }, android: { jdk: { state: 'literal', value: '17' }, agp: { state: 'literal', value: '8.9.2' },
    sdkPlatform: { state: 'literal', value: 'android-35' }, sdkBuildTools: { state: 'unspecified', value: null },
    gradle: { state: 'literal', version: '8.14.5', distributionUrl: 'https://services.gradle.org/distributions/gradle-8.14.5-bin.zip', sha256: SHA } } } });
const staged = () => ({ schemaVersion: 1, kind: 'staged-tool-sources', operationId: ACQUIRE, contextSha256: SHA,
  referenceSha256: SHA, projectionSha256: SHA, cacheJob: `tool-${ACQUIRE}`, lookupScope: 'registered-selected-known', reusedArchives: ['jdk'],
  downloadedArchives: ['sdk-platform', 'sdk-build-tools', 'gradle'], groups: [
    { group: 'jdk', components: ['jdk'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'sdk', components: ['sdk-platform', 'sdk-build-tools'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'gradle', components: ['gradle'], allRequiredComponentsStaged: true, next: 'choose-native-source' }],
  assurance: { nativeFinality: false, registered: false, readyToBuild: false } });
const terminal = (op, outcome = 'complete') => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome,
  reason: outcome === 'complete' ? 'none' : outcome === 'refused' ? 'unsupported' : outcome,
  result: outcome === 'complete' ? op.context.action === 'inspect' ? requirements() : staged() : null });
const running = (op) => ({ ...clone(op), phase: 'running', intentUsable: false });
function harness(t, initial = status()) {
  let ws = workspace(), native = clone(initial), known = [{}, {}, {}], other = null;
  const calls = [], events = [], reads = [], readQueue = [];
  const api = { mode: 'native',
    subscribe: async (receive) => { const row = { receive, closed: false }; events.push(row); return () => { row.closed = true; }; },
    status: () => { reads.push(clone(native)); return readQueue.shift()?.promise ?? Promise.resolve(clone(native)); },
    prepare: (request) => { const call = { kind: 'prepare', request: clone(request), ...deferred() }; calls.push(call); return call.promise; },
    start: (request) => { const call = { kind: 'start', request: clone(request), ...deferred() }; calls.push(call); return call.promise; },
    cancel: (request) => { const call = { kind: 'cancel', request: clone(request), ...deferred() }; calls.push(call); return call.promise; },
  };
  const controller = new ToolAcquisitionController({ selectedProject: () => ws.selectedId ? ws.projects[ws.selectedId] : null,
    otherOperationReason: () => other, knownTools: () => known });
  controller.setVisible(true);
  const ready = controller.connect(api);
  t.after(() => controller.dispose());
  return { api, controller, ready, calls, events, reads, readQueue,
    get state() { return controller.getSnapshot(); }, get project() { return ws.projects[ws.selectedId]; },
    reply(call, value) { native = clone(value); call.resolve(clone(value)); },
    emit(value) { native = clone(value); for (const row of events) if (!row.closed) row.receive(clone(value)); },
    native(value) { native = clone(value); },
    replace(patch) { const p = ws.projects[ws.selectedId]; ws = { ...ws, projects: { ...ws.projects, [p.project.id]: { ...p, ...patch } } }; controller.syncProject(); },
    dispatch(action) { controller.beforeWorkspaceAction(action); ws = workspaceReducer(ws, action); controller.syncProject(); },
    other(value) { other = value; },
    known() { known = [{}, {}, {}]; controller.syncProject(); },
  };
}
async function inspected(h) {
  await h.ready;
  const flow = h.controller.inspect(), prepare = h.calls.at(-1);
  assert.equal(prepare.kind, 'prepare'); assert.equal(prepare.request.action, 'inspect');
  const op = operation(prepare.request);
  h.reply(prepare, status(2, op)); await flush();
  const start = h.calls.at(-1); assert.equal(start.kind, 'start');
  h.reply(start, status(3, terminal(op))); await flow;
  assert.equal(h.state.inspection?.kind, 'tool-requirements-observation');
  assert.equal(h.state.reviewReason, null); return op;
}
async function reviewed(h) {
  await inspected(h);
  const flow = h.controller.reviewDownload(), prepare = h.calls.at(-1);
  assert.equal(prepare.request.action, 'acquire');
  assert.deepEqual(prepare.request.review, { operationId: OP, ownerGeneration: OWNER, requirementsSha256: SHA });
  const op = operation(prepare.request, true); h.reply(prepare, status(4, op)); await flow;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function downloadStarted(h, op) {
  h.controller.setAcknowledged(ACQUIRE, ACQUIRE_OWNER, true);
  const flow = h.controller.download(ACQUIRE, ACQUIRE_OWNER); await flush();
  const start = h.calls.at(-1); assert.equal(start.kind, 'start');
  h.reply(start, status(5, running(op))); await flow; return start;
}

test('mount/status refresh perform no preparation; unqualified route keeps original reads available', async (t) => {
  const h = harness(t, status(1, null, 'runtime-unqualified')); await h.ready;
  await h.controller.checkStatus(); await h.controller.inspect(); await h.controller.reviewDownload();
  assert.equal(h.calls.length, 0); assert.match(h.state.checkReason, /not enabled/);
  assert.equal(h.state.canRead, true); assert.equal(h.controller.ownerReason(), null);
  assert.equal(h.state.inspection, null); assert.notEqual(h.state.presentation, 'current-staged');
});

test('explicit inspect alone chains prepare/start; acquisition always needs distinct unchecked one-use consent', async (t) => {
  const h = harness(t); const op = await reviewed(h);
  assert.deepEqual(h.calls.map((c) => c.kind), ['prepare', 'start', 'prepare']);
  await h.controller.download(ACQUIRE, ACQUIRE_OWNER); assert.equal(h.calls.length, 3);
  await h.controller.checkStatus(); assert.equal(h.state.consent.acknowledged, false);
  await downloadStarted(h, op);
  assert.equal(h.calls.length, 4); assert.equal(h.calls.at(-1).request.consentVersion, TOOL_ACQUISITION_CONSENT);
  assert.equal(h.state.consent, null);
  await h.controller.download(ACQUIRE, ACQUIRE_OWNER); await h.controller.reviewDownload();
  assert.equal(h.calls.length, 4);
  h.emit(status(6, terminal(op))); await flush();
  assert.equal(h.state.presentation, 'current-staged');
  assert.deepEqual({ ...h.state.status.operation.result.assurance }, { nativeFinality: false, registered: false, readyToBuild: false });
  assert.notEqual(h.state.reviewReason, null); // The old inspection was consumed, not rearmed.
});

test('same-byte replacement saved observation and known tool change retire original download consent', async (t) => {
  const h = harness(t); const op = await reviewed(h);
  h.controller.setAcknowledged(ACQUIRE, ACQUIRE_OWNER, true);
  const p = h.project;
  h.replace({ snapshot: clone(p.snapshot), observationGeneration: p.observationGeneration + 1 });
  assert.equal(h.state.consent, null); assert.equal(h.state.historical, true);
  assert.equal(h.calls.at(-1).kind, 'cancel');
  h.reply(h.calls.at(-1), status(5, terminal(op, 'cancelled'))); await flush();
  await h.controller.download(ACQUIRE, ACQUIRE_OWNER); assert.equal(h.calls.filter((c) => c.kind === 'start').length, 1);
  h.known(); assert.equal(h.state.inspection, null); assert.notEqual(h.state.reviewReason, null);
});

test('pending prepare survives project switch and cancel settlement; late reply cannot start', async (t) => {
  const h = harness(t); await h.ready;
  const flow = h.controller.inspect(), prepare = h.calls.at(-1), op = operation(prepare.request);
  h.dispatch({ type: 'select', project: { id: 'project-2', name: 'Another inert project', path: '/also-never-opened' } });
  h.emit(status(2, op)); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.reply(h.calls.at(-1), status(3, terminal(op, 'cancelled'))); await flush();
  assert.equal(h.state.requestPending, true); assert.equal(h.state.pending, 'inspect');
  await h.controller.inspect(); assert.equal(h.calls.filter((c) => c.kind === 'prepare').length, 1);
  prepare.resolve(status(2, op)); await flow;
  assert.equal(h.state.requestPending, false); assert.equal(h.state.pending, null);
  assert.equal(h.calls.filter((c) => c.kind === 'start').length, 0); assert.equal(h.state.historical, true);
});

test('event completion before start reply never clears original pending or stages files', async (t) => {
  const h = harness(t), op = await reviewed(h);
  h.controller.setAcknowledged(ACQUIRE, ACQUIRE_OWNER, true);
  const flow = h.controller.download(ACQUIRE, ACQUIRE_OWNER); await flush(); const start = h.calls.at(-1);
  h.emit(status(6, terminal(op))); await flush();
  assert.equal(h.state.requestPending, true); assert.equal(h.state.pending, 'download');
  assert.notEqual(h.state.presentation, 'current-staged');
  const postRead = deferred(); h.readQueue.push(postRead);
  start.resolve(status(5, running(op))); await flush();
  assert.equal(h.state.requestPending, false); assert.equal(h.state.reading, true);
  assert.notEqual(h.state.presentation, 'current-staged');
  postRead.resolve(status(6, terminal(op))); await flow;
  assert.equal(h.state.presentation, 'current-staged');
});

test('native terminal event triggers an original post-invoke read, not a completion shortcut', async (t) => {
  const h = harness(t), op = await reviewed(h); await downloadStarted(h, op);
  const read = deferred(); h.readQueue.push(read); const count = h.reads.length;
  h.emit(status(6, terminal(op))); await flush();
  assert.equal(h.reads.length, count + 1); assert.equal(h.state.reading, true);
  assert.notEqual(h.state.presentation, 'current-staged');
  read.resolve(status(6, terminal(op))); await flush(); assert.equal(h.state.presentation, 'current-staged');
});

test('retained old API and actual read remain after navigation/rebind; singleflight cannot be cleared by invalidation', async (t) => {
  const h = harness(t), op = await reviewed(h); await downloadStarted(h, op);
  const blocked = deferred(); h.readQueue.push(blocked); const read = h.controller.checkStatus(); await flush();
  h.controller.setVisible(false); assert.equal(h.state.reading, true);
  const otherCalls = []; const newApi = { ...h.api, status: async () => { otherCalls.push('status'); return status(); } };
  await h.controller.connect(newApi); assert.equal(otherCalls.length, 0); assert.equal(h.events[0].closed, false);
  const fresh = h.controller.checkStatus(true); await flush(); assert.equal(h.state.reading, true);
  blocked.resolve(status(5, running(op))); await read; await fresh;
  assert.equal(otherCalls.length, 0);
  const stop = h.controller.cancel(); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.reply(h.calls.at(-1), status(6, terminal(op, 'cancelled'))); await stop;
  assert.equal(h.state.historical, true); assert.notEqual(h.state.presentation, 'current-staged');
});

test('lost prepare reply keeps status/cancel on original connection and cannot mint consent from an event', async (t) => {
  const h = harness(t); await h.ready;
  const flow = h.controller.inspect(), prepare = h.calls.at(-1), op = operation(prepare.request);
  h.native(status(2, op)); prepare.reject({ message: 'RAW MUST NOT REACH UI' }); await flush();
  assert.equal(h.calls.at(-1).kind, 'cancel'); assert.equal(h.state.consent, null);
  assert.equal(h.calls.filter((c) => c.kind === 'start').length, 0);
  const stop = h.calls.at(-1); h.reply(stop, status(3, terminal(op, 'cancelled'))); await flow; await flush();
  assert.ok(!JSON.stringify(h.state).includes('RAW MUST NOT REACH UI'));
  assert.equal(h.state.requestPending, false); assert.equal(h.state.inspection, null);
});

test('same-revision conflicts and native unknown are sticky; malformed reports never qualify staging', async (t) => {
  const h = harness(t), op = await reviewed(h); await downloadStarted(h, op);
  h.emit(status(5, { ...running(op), reason: 'cancelled' }));
  assert.equal(h.state.issue, 'protocol');
  h.emit(status(6, terminal(op))); await flush();
  assert.equal(h.state.issue, 'protocol'); assert.notEqual(h.state.presentation, 'current-staged');
  await h.controller.reviewDownload(); assert.equal(h.calls.filter((c) => c.kind === 'prepare').length, 2);
  const unknown = { ...operation({ projectId: 'project-1', draftRevision: 0, baselineGeneration: 0,
    savedConfig: CONTENT, action: 'inspect', review: null }), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' };
  const second = harness(t, status(2, unknown, 'cleanup-unknown')); await second.ready;
  assert.equal(second.state.issue, 'unknown'); assert.equal(second.state.canRead, true);
  second.emit(status(3, terminal(unknown))); await flush();
  assert.equal(second.state.issue, 'unknown'); assert.notEqual(second.state.presentation, 'current-staged');
});

test('no fresh work from dirty, predates-save, incomplete observations or dynamic tool hints', async (t) => {
  for (const patch of [{ sourceChanged: true }, { snapshotPredatesSave: true }, { snapshotRequest: 9 }, { saveRecoveryRequired: true },
    { observationGeneration: 0 }, { savedConfigContent: { ...CONTENT, bytes: 121 } }, { draft: { different: true } }]) {
    const h = harness(t); await h.ready; h.replace(patch); await h.controller.inspect(); assert.equal(h.calls.length, 0);
  }
  const h = harness(t); await h.ready;
  const flow = h.controller.inspect(), prepare = h.calls.at(-1), op = operation(prepare.request);
  h.reply(prepare, status(2, op)); await flush(); const done = terminal(op);
  done.result.requirements.android.gradle = { state: 'unknown', version: null, distributionUrl: null, sha256: null };
  h.reply(h.calls.at(-1), status(3, done)); await flow;
  assert.match(h.state.reviewReason, /could not be read/); await h.controller.reviewDownload(); assert.equal(h.calls.length, 2);
});

test('busy peer blocks new preparation, not retained cancellation, and consent is consumed before status await', async (t) => {
  const h = harness(t), op = await reviewed(h);
  h.controller.setAcknowledged(ACQUIRE, ACQUIRE_OWNER, true);
  const read = deferred(); h.readQueue.push(read);
  const flow = h.controller.download(ACQUIRE, ACQUIRE_OWNER); await flush();
  assert.equal(h.state.consent, null);
  h.other('Another task is busy'); read.resolve(status(4, op)); await flow;
  assert.equal(h.calls.at(-1).kind, 'cancel'); assert.equal(h.calls.filter((c) => c.kind === 'start').length, 1);
  h.reply(h.calls.at(-1), status(5, terminal(op, 'cancelled'))); await flush();
  assert.equal(h.state.consent, null); assert.match(h.state.checkReason, /Another task/);
});

test('captured native methods cannot be replaced to receive an original token', async (t) => {
  const h = harness(t), op = await reviewed(h); let replacement = 0;
  h.api.start = async () => { replacement++; return status(); };
  await downloadStarted(h, op); assert.equal(replacement, 0);
  h.emit(status(6, terminal(op))); await flush(); assert.equal(h.state.presentation, 'current-staged');
});

test('concurrent fresh status callers serialize their actual reads after invalidation', async (t) => {
  const h = harness(t); await h.ready;
  const first = deferred(), second = deferred(), third = deferred(); h.readQueue.push(first, second, third);
  const before = h.reads.length;
  const a = h.controller.checkStatus(); await flush();
  const b = h.controller.checkStatus(true), c = h.controller.checkStatus(true);
  h.controller.snapshotIntent('project-1'); await flush(); assert.equal(h.reads.length, before + 1);
  first.resolve(status()); await a; await flush(); assert.equal(h.reads.length, before + 2);
  second.resolve(status()); await b; await flush(); assert.equal(h.reads.length, before + 3);
  third.resolve(status()); await c; assert.equal(h.state.reading, false);
});

test('synchronous retirement before prepare or Start never forwards the stale request', async (t) => {
  const h = harness(t); await h.ready; let retired = false;
  const off = h.controller.subscribe(() => {
    if (!retired && h.state.requestPending) { retired = true; h.controller.snapshotIntent('project-1'); }
  });
  await h.controller.inspect(); off(); assert.equal(h.calls.length, 0);
  const second = harness(t); await second.ready; let beforeStart = false;
  const unsubscribe = second.controller.subscribe(() => {
    if (!beforeStart && second.state.requestPending && second.calls.length === 1) {
      beforeStart = true; second.controller.toolInputsIntent();
    }
  });
  const flow = second.controller.inspect(), prepare = second.calls.at(-1), op = operation(prepare.request);
  second.reply(prepare, status(2, op)); await flush();
  assert.equal(second.calls.filter((call) => call.kind === 'start').length, 0);
  assert.equal(second.calls.at(-1).kind, 'cancel');
  second.reply(second.calls.at(-1), status(3, terminal(op, 'cancelled'))); await flow; await flush(); unsubscribe();
});

test('lost Start response and later unqualified status retain original cancellation; no acquisition retry', async (t) => {
  const h = harness(t), op = await reviewed(h);
  h.controller.setAcknowledged(ACQUIRE, ACQUIRE_OWNER, true);
  const flow = h.controller.download(ACQUIRE, ACQUIRE_OWNER); await flush(); const start = h.calls.at(-1);
  h.native(status(5, running(op), 'runtime-unqualified')); start.reject(new Error('not shown')); await flow;
  assert.equal(h.state.issue, 'unconfirmed'); assert.equal(h.state.canCancel, true); assert.equal(h.state.canRead, true);
  assert.notEqual(h.state.presentation, 'current-staged');
  await h.controller.download(ACQUIRE, ACQUIRE_OWNER); assert.equal(h.calls.length, 4);
  const cancel = h.controller.cancel(); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.reply(h.calls.at(-1), status(6, terminal(op, 'cancelled'), 'runtime-unqualified')); await cancel;
  assert.equal(h.state.issue, null); assert.match(h.state.checkReason, /not enabled/);
});
