// Inert DTO/controller/bridge promises and source integration guards only.
// No host tool, native owner, browser/GUI, timer, network or finality evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { EnvironmentDiagnosticsController, diagnosticsOwnerReason } from '../src/environmentDiagnosticsController.ts';
import { diagnosticsProjectionProgress, diagnosticsStatusProgress, ENVIRONMENT_DIAGNOSTICS_EVENT,
  environmentDiagnosticsError, environmentDiagnosticsRequestFits, parseEnvironmentDiagnosticsStatus } from '../src/environmentDiagnosticsProtocol.ts';

const RUN = 'a'.repeat(32), GENERATION = 'b'.repeat(32), OTHER = 'c'.repeat(32);
const CONTEXT = { projectId: 'project-1', draftRevision: 2, baselineGeneration: 3, platform: 'android', operation: 'build' };
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let index = 0; index < 14; index += 1) await Promise.resolve(); };
const request = () => ({ ...CONTEXT, draft: { current: true, android: { enabled: true }, ios: { enabled: true } } });
function core(context = CONTEXT, host = 'linux') {
  const ids = host === 'linux' ? context.platform === 'android' ? ['git', 'java', 'javac'] : ['git', 'xcode'] :
    context.platform === 'android' ? ['developer-selection', 'git', 'java', 'javac'] : ['developer-selection', 'git', 'xcode'];
  const mismatch = host === 'linux' && context.platform === 'ios';
  const checks = ids.map((id) => ({ id, state: mismatch ? 'not-run' : 'completed', reason: mismatch ? 'host-mismatch' : 'observed',
    version: mismatch || id === 'developer-selection' ? null : id === 'git' ? '2.45.1' : id === 'xcode' ? '26.3' : '21.0.5',
    build: !mismatch && id === 'xcode' ? '17C529' : null, returnCode: mismatch ? null : 0,
    baseline: id === 'xcode' ? { kind: 'exact-pin', version: '26.3', build: '17C529' } : id === 'java' || id === 'javac'
      ? { kind: 'workflow-reference', version: '21', build: null } : { kind: 'no-local-policy', version: null, build: null },
    assessment: mismatch || id === 'developer-selection' ? 'not-assessed' : id === 'xcode' ? 'match' : 'no-local-policy',
    help: 'Fixed core-owned example guidance; this DTO is not a tool observation.',
  }));
  const commandsAttempted = mismatch ? 0 : ids.length;
  return { schemaVersion: 1, policyVersion: 'environment-diagnostics-v1', context: clone(context), hostPlatform: host,
    outcome: mismatch ? 'unavailable' : 'complete', checks, commandsAttempted,
    lifetime: { complete: true, fatal: false, contained: true, commandDispatched: !mismatch, commands: commandsAttempted,
      inputClosed: true, handlersRestored: true, toolDescriptorsClosed: true, stopObserved: 'none' },
    assurance: { basis: 'local-tool-observation', toolsAttempted: !mismatch, projectCodeExecuted: false, projectFilesRead: false,
      repositoryObserved: false, sdkInspected: false, credentialsRead: false, storeContacted: false,
      dependencyCompleteness: 'unknown', releaseReadiness: 'unknown', toolCacheEffects: 'possible' } };
}
function owner(options = {}) {
  return { runId: RUN, ownerGeneration: GENERATION, context: clone(CONTEXT), phase: 'starting', outcome: null, finality: 'pending', reason: 'none', result: null, ...options };
}
function finished(options = {}) { return owner({ phase: 'settled', finality: 'settled', outcome: 'complete', result: core(), ...options }); }
function status(revision = 0, active = null, lastTerminal = null, reason = active ? 'busy' : 'available') {
  return { schemaVersion: 1, statusRevision: revision, capability: { available: reason === 'available', reason }, active, lastTerminal };
}
function harness({ initial = status(), listenError = null } = {}) {
  let project = { project: { id: CONTEXT.projectId, name: 'Inert fixture', path: '/never-forwarded' }, revision: 2, baselineGeneration: 3,
    draft: request().draft, baseline: { saved: true } };
  let registry = clone(initial), listener = null, otherReason = null, clock = 100;
  const calls = [], reads = [];
  const api = {
    mode: 'native',
    subscribeEnvironmentDiagnostics: async (callback) => { if (listenError) throw listenError; listener = callback; return () => { listener = null; }; },
    environmentDiagnosticsStatus: async () => { reads.push(clone(registry)); return clone(registry); },
    startEnvironmentDiagnostics: (input) => { const task = deferred(); calls.push({ kind: 'start', input: clone(input), ...task }); return task.promise; },
    cancelEnvironmentDiagnostics: (runId, ownerGeneration) => { const task = deferred(); calls.push({ kind: 'cancel', input: { runId, ownerGeneration }, ...task }); return task.promise; },
  };
  const controller = new EnvironmentDiagnosticsController({ selectedProject: () => project, otherOperationReason: () => otherReason, now: () => clock });
  controller.syncProject(); controller.setVisible(true);
  return { api, controller, calls, reads, ready: controller.connect(api),
    get state() { return controller.getSnapshot(); }, get project() { return project; },
    select(value) { project = value; controller.syncProject(); },
    other(value) { otherReason = value; }, tick() { clock += 100; },
    registry(value) { registry = clone(value); },
    emit(value) { registry = clone(value); listener?.(clone(value)); },
    reply(call, value) { registry = clone(value); call.resolve(clone(value)); },
  };
}
async function acknowledged(h) {
  await h.ready; assert.equal(h.controller.start(), true);
  h.reply(h.calls[0], status(1, owner())); await flush();
  assert.equal(h.state.attempt.acknowledged, true);
}

test('closed request admission rejects execution overrides, bad counters, tokens and non-DATA without getters', () => {
  assert.equal(environmentDiagnosticsRequestFits('start_environment_diagnostics', request()), true);
  let reads = 0;
  const getter = { ...request(), get draft() { reads += 1; return {}; } };
  const cycle = {}; cycle.self = cycle;
  const sparse = []; sparse[2] = 'value';
  for (const input of [getter, { ...request(), projectId: 'name\n' }, { ...request(), draftRevision: 0xffff_ffff },
    { ...request(), baselineGeneration: -1 }, { ...request(), baselineGeneration: 1.5 }, { ...request(), operation: 'artifact-validation' },
    { ...request(), platform: 'linux' }, { ...request(), draft: { padding: 'x'.repeat(512 * 1024) } },
    { ...request(), draft: { cycle } }, { ...request(), draft: { sparse } }, { ...request(), draft: { text: '\ud800' } },
    ...['runId', 'ownerGeneration', 'cwd', 'argv', 'env', 'native', 'root', 'profile', 'timeout', 'output'].map((key) => ({ ...request(), [key]: 'injected' }))]) {
    assert.equal(environmentDiagnosticsRequestFits('start_environment_diagnostics', input), false);
  }
  assert.equal(reads, 0);
  assert.equal(environmentDiagnosticsRequestFits('cancel_environment_diagnostics', { runId: RUN, ownerGeneration: GENERATION }), true);
  for (const input of [{ runId: RUN }, { runId: `${RUN}\n`, ownerGeneration: GENERATION }, { runId: RUN, ownerGeneration: GENERATION, retry: true }])
    assert.equal(environmentDiagnosticsRequestFits('cancel_environment_diagnostics', input), false);
  assert.equal(environmentDiagnosticsRequestFits('environment_diagnostics_status', {}), true);
  assert.equal(environmentDiagnosticsRequestFits('environment_diagnostics_status', { retry: true }), false);
});

test('fixed Linux/macOS rosters preserve complete negative observations and Java workflow-reference meaning', () => {
  for (const host of ['linux', 'macos']) for (const platform of ['android', 'ios']) {
    const context = { ...CONTEXT, platform }, result = core(context, host);
    const row = finished({ context, result, outcome: result.outcome });
    assert.deepEqual(parseEnvironmentDiagnosticsStatus(status(1, null, row)), status(1, null, row));
    if (host === 'linux' && platform === 'ios') assert.equal(result.commandsAttempted, 0);
    for (const check of result.checks.filter((item) => item.id === 'java' || item.id === 'javac')) assert.equal(check.assessment, 'no-local-policy');
  }
  const result = core({ ...CONTEXT, platform: 'ios' }, 'macos');
  result.checks[2].build = '17C530'; result.checks[2].assessment = 'mismatch';
  result.checks[1] = { ...result.checks[1], reason: 'nonzero-exit', returnCode: 1, version: null, assessment: 'not-assessed' };
  assert.ok(parseEnvironmentDiagnosticsStatus(status(1, null, finished({ context: result.context, result }))));
});

test('optional selection detail is closed DATA on the original mac negative row, never extra observation authority', () => {
  const result = core(CONTEXT, 'macos');
  result.checks = result.checks.map((row, index) => ({ ...row, state: index === 0 ? 'completed' : 'not-run',
    reason: index === 0 ? 'selection-unrecognized' : 'unselected-installation', version: null, build: null,
    returnCode: index === 0 ? 0 : null, assessment: 'not-assessed' }));
  result.commandsAttempted = 1; result.lifetime.commands = 1;
  const parse = (value) => parseEnvironmentDiagnosticsStatus(status(1, null, finished({ context: value.context, result: value, outcome: value.outcome })));
  assert.ok(parse(result));
  // Missing and explicit null are absent on any otherwise-valid row. A
  // present undefined is not DATA and must not be silently treated as absent.
  for (const value of [clone(result), core(), core({ ...CONTEXT, platform: 'ios' })]) {
    value.checks.forEach((row) => { row.selectionDiagnostic = null; });
    assert.ok(parse(value));
  }
  const detail = { stage: 'contents', reason: 'directory-group-write' };
  const detailed = clone(result); detailed.checks[0].selectionDiagnostic = detail;
  const admitted = parse(detailed);
  assert.deepEqual(admitted.lastTerminal.result.checks[0].selectionDiagnostic, detail);
  assert.notEqual(admitted.lastTerminal.result.checks[0].selectionDiagnostic, detail);
  for (const invalid of [undefined, false, [], { stage: 'selector-output', reason: 'directory-owner' },
    { stage: 'alias', reason: 'app-name' }, { stage: 'contents', reason: 'unknown' }, { stage: '/PRIVATE', reason: 'directory-kind' },
    { stage: 'contents', reason: 'directory-kind', path: 'PRIVATE' }, { stage: 'contents' }]) {
    const bad = clone(detailed); bad.checks[0].selectionDiagnostic = invalid; assert.equal(parse(bad), null);
  }
  for (const key of ['id', 'state', 'reason', 'version', 'build', 'returnCode', 'baseline', 'assessment', 'help']) {
    const bad = clone(detailed); delete bad.checks[0][key]; assert.equal(parse(bad), null, `required original row key ${key}`);
  }
  const extra = clone(detailed); extra.checks[0].extra = 'PRIVATE'; assert.equal(parse(extra), null);
  const positive = clone(detailed); positive.checks[0].reason = 'observed'; assert.equal(parse(positive), null);
  const nonzero = clone(detailed); nonzero.checks[0].reason = 'nonzero-exit'; nonzero.checks[0].returnCode = 1; assert.equal(parse(nonzero), null);
  for (const value of [clone(result), core()]) {
    value.checks.find((row) => row.id === 'git').selectionDiagnostic = detail; assert.equal(parse(value), null);
  }
  let reads = 0;
  const accessor = clone(detailed);
  Object.defineProperty(accessor.checks[0], 'selectionDiagnostic', { enumerable: true, get() { reads += 1; return detail; } });
  assert.equal(parse(accessor), null);
  const nestedAccessor = clone(detailed);
  Object.defineProperty(nestedAccessor.checks[0].selectionDiagnostic, 'reason', { enumerable: true, get() { reads += 1; return 'directory-kind'; } });
  assert.equal(parse(nestedAccessor), null); assert.equal(reads, 0);
});

test('strict row, assurance, lifetime and global scope joins reject invented observations or exit/finality facts', () => {
  const mutations = [
    (v) => { v.extra = 'private'; }, (v) => { v.runId += '\n'; }, (v) => { v.context.projectId += '\n'; },
    (v) => { v.result.context.draftRevision += 1; }, (v) => { v.result.checks.reverse(); },
    (v) => { v.result.checks[0].version = '2abc'; }, (v) => { v.result.checks[1].version = '21.0.0.0.0'; },
    (v) => { v.result.checks[0].version += '\n'; }, (v) => { v.result.checks[0].returnCode = null; },
    (v) => { v.result.checks[0].returnCode = 1; }, (v) => { v.result.checks[1].assessment = 'match'; },
    (v) => { v.result.checks[2].baseline.version = '22'; }, (v) => { v.result.checks[0].help = 'é'.repeat(513); },
    (v) => { v.result.checks[0].stdout = 'private'; }, (v) => { v.result.checks[0].help = 'unsafe\noutput'; },
    (v) => { v.result.checks[0].state = 'attempted'; v.result.checks[0].reason = 'command-incomplete'; },
    (v) => { v.result.commandsAttempted += 1; }, (v) => { v.result.assurance.toolsAttempted = false; },
    (v) => { v.result.assurance.writesPerformed = false; }, (v) => { v.result.assurance.releaseReadiness = 'ready'; },
    (v) => { v.result.lifetime.commands = 0; }, (v) => { v.result.lifetime.commandDispatched = null; },
    (v) => { v.result.lifetime.complete = false; }, (v) => { v.result.lifetime.fatal = true; },
    (v) => { delete v.result.checks[0].baseline.build; }, (v) => { v.result.outcome = 'partial'; },
    (v) => { v.result.checks[0] = { ...v.result.checks[0], state: 'not-run', reason: 'platform-disabled', version: null, returnCode: null, assessment: 'not-assessed' };
      v.result.commandsAttempted = 2; v.result.lifetime.commands = 2; },
  ];
  for (const mutate of mutations) { const row = finished(); mutate(row); assert.equal(parseEnvironmentDiagnosticsStatus(status(1, null, row)), null); }
  const mismatch = core({ ...CONTEXT, platform: 'ios' });
  mismatch.checks[0].reason = 'stopped';
  assert.equal(parseEnvironmentDiagnosticsStatus(status(1, null, finished({ context: mismatch.context, result: mismatch, outcome: 'unavailable' }))), null);
  const stopped = core(); stopped.outcome = 'cancelled'; stopped.lifetime.stopObserved = 'cancelled';
  stopped.checks[2] = { ...stopped.checks[2], state: 'attempted', reason: 'timed-out', version: null, returnCode: null, assessment: 'not-assessed' };
  assert.equal(parseEnvironmentDiagnosticsStatus(status(1, null, finished({ result: stopped, outcome: 'cancelled', reason: 'cancelled' }))), null);
  // Exercise the cross-field joins independently of the complete/unavailable
  // ledger and native settled-lifetime checks. These fatal partial/failed core
  // frames remain provisional under a pending native owner, never finality.
  const partial = core(); partial.outcome = 'partial'; partial.lifetime.complete = false; partial.lifetime.fatal = true;
  const pending = (result) => status(1, owner({ phase: 'stopping', outcome: result.outcome, reason: 'command-failed', result }));
  assert.ok(parseEnvironmentDiagnosticsStatus(pending(partial)));
  for (const mutate of [
    (v) => { v.lifetime.commands = 0; },
    (v) => { v.lifetime.commandDispatched = null; },
    (v) => { v.lifetime.commandDispatched = false; },
  ]) {
    const inconsistent = clone(partial); mutate(inconsistent);
    assert.equal(parseEnvironmentDiagnosticsStatus(pending(inconsistent)), null);
  }
  for (const outcome of ['partial', 'failed']) {
    const incomplete = clone(partial); incomplete.outcome = outcome;
    incomplete.checks = incomplete.checks.map((row, index) => outcome === 'failed' || index === 2
      ? { ...row, state: 'attempted', reason: 'command-incomplete', version: null, returnCode: null, assessment: 'not-assessed' } : row);
    assert.ok(parseEnvironmentDiagnosticsStatus(pending(incomplete)));
    for (const reason of ['cancelled', 'timed-out']) {
      const inconsistent = clone(incomplete); inconsistent.checks[2].reason = reason;
      assert.equal(inconsistent.lifetime.stopObserved, 'none');
      assert.equal(parseEnvironmentDiagnosticsStatus(pending(inconsistent)), null);
    }
  }
});

test('native phase/outcome/finality stay independent; core completion cannot free a pending or Unknown owner', () => {
  const pending = finished({ phase: 'stopping', finality: 'pending' });
  assert.ok(parseEnvironmentDiagnosticsStatus(status(2, pending)));
  assert.equal(parseEnvironmentDiagnosticsStatus(status(2, pending, null, 'available')), null);
  assert.equal(parseEnvironmentDiagnosticsStatus(status(2, finished())), null);
  assert.equal(parseEnvironmentDiagnosticsStatus(status(2, null, pending)), null);
  const unknown = finished({ phase: 'retained-unknown', finality: 'unknown', reason: 'timed-out', outcome: 'timed-out' });
  assert.ok(parseEnvironmentDiagnosticsStatus(status(3, unknown, null, 'cleanup-unknown')));
  assert.equal(parseEnvironmentDiagnosticsStatus(status(3, unknown)), null);
  assert.equal(parseEnvironmentDiagnosticsStatus(status(3, null, { ...unknown, outcome: 'complete' }, 'cleanup-unknown')), null);
  assert.equal(diagnosticsProjectionProgress(pending, unknown), true);
  assert.equal(diagnosticsProjectionProgress(unknown, finished()), false);
});

test('native revision replay, immutable results and sticky first reason reject rollback and conflicting same-revision data', () => {
  const starting = status(1, owner()), checking = status(2, owner({ phase: 'checking' }));
  const terminal = status(3, null, finished());
  assert.equal(diagnosticsStatusProgress(starting, clone(starting)), true);
  assert.equal(diagnosticsStatusProgress(starting, checking), true);
  assert.equal(diagnosticsStatusProgress(checking, starting), false);
  assert.equal(diagnosticsStatusProgress(checking, terminal), true);
  assert.equal(diagnosticsStatusProgress(starting, { ...checking, statusRevision: 1 }), false);
  assert.equal(diagnosticsStatusProgress(checking, status(3)), false);
  const changed = clone(terminal); changed.statusRevision += 1; changed.lastTerminal.result.checks[0].version = '2.46.0';
  assert.equal(diagnosticsStatusProgress(terminal, changed), false);
  const unknown = owner({ phase: 'retained-unknown', finality: 'unknown', outcome: 'failed', reason: 'protocol-error' });
  const late = { ...unknown, result: core(), outcome: 'partial' };
  assert.ok(parseEnvironmentDiagnosticsStatus(status(3, late, null, 'cleanup-unknown')));
  assert.equal(diagnosticsProjectionProgress(unknown, late), true);
  assert.equal(diagnosticsProjectionProgress(unknown, { ...late, reason: 'command-failed' }), false);
});

test('bridge exposes only fixed commands/event, clones input and separates native refusals from lost transport replies', async () => {
  const calls = [], task = deferred(); let callback;
  const api = createNativeApi('native', (command, args) => { calls.push({ command, args }); return task.promise; }, async (event, receive) => {
    assert.equal(event, ENVIRONMENT_DIAGNOSTICS_EVENT); callback = receive; return () => {};
  });
  const input = request(), original = clone(input), promise = api.startEnvironmentDiagnostics(input);
  input.draft.current = false; input.platform = 'ios';
  assert.deepEqual(calls, [{ command: 'start_environment_diagnostics', args: original }]);
  task.resolve(status(1, owner())); assert.ok(await promise);
  await api.cancelEnvironmentDiagnostics(RUN, GENERATION); await api.environmentDiagnosticsStatus();
  assert.deepEqual(calls.slice(1), [{ command: 'cancel_environment_diagnostics', args: { runId: RUN, ownerGeneration: GENERATION } }, { command: 'environment_diagnostics_status', args: {} }]);
  let observed; await api.subscribeEnvironmentDiagnostics((value) => { observed = value; });
  callback({ raw: 'PRIVATE' }); assert.equal(observed, null);
  const leaked = createNativeApi('native', async () => { throw { code: 'PRIVATE_CODE', message: 'PRIVATE_SECRET' }; });
  await assert.rejects(leaked.startEnvironmentDiagnostics(request()), (error) => error.code === 'environment_diagnostics_connection_lost' && !JSON.stringify(error).includes('PRIVATE'));
  const refused = createNativeApi('native', async () => { throw { code: 'environment_diagnostics_busy', message: 'PRIVATE_SECRET' }; });
  await assert.rejects(refused.startEnvironmentDiagnostics(request()), (error) => error.code === 'environment_diagnostics_busy' && !JSON.stringify(error).includes('PRIVATE'));
  const unavailable = createNativeApi('unavailable', async () => assert.fail('no fallback invoke'));
  await assert.rejects(unavailable.startEnvironmentDiagnostics(request()), (error) => error.code === 'environment_diagnostics_unavailable');
  let getterReads = 0;
  environmentDiagnosticsError({ get code() { getterReads += 1; return 'environment_diagnostics_busy'; } });
  assert.equal(getterReads, 0);
});

test('connection, selection and status reads never auto-start; qualification is separate from passive capabilities', async () => {
  const h = harness(); await h.ready;
  assert.equal(h.calls.length, 0); assert.equal(h.reads.length, 1); assert.equal(h.controller.startReason(), null);
  h.controller.setContext('ios', 'build'); h.controller.setContext('android', 'build'); h.controller.setVisible(false); h.controller.setVisible(true);
  h.controller.beginConnection(); await h.controller.connect(h.api);
  assert.equal(h.calls.length, 0); assert.equal(h.reads.length, 2);
  h.emit(status(1, null, null, 'runtime-unqualified')); assert.notEqual(h.controller.startReason(), null); assert.equal(h.controller.start(), false);
  h.controller.dispose();
});

test('Start snapshots current draft and all context generations synchronously; a second click does not queue', async () => {
  const h = harness(); await h.ready;
  assert.equal(h.controller.start(), true); assert.equal(h.controller.start(), false); assert.equal(h.calls.length, 1);
  assert.deepEqual(h.calls[0].input, request()); assert.notDeepEqual(h.calls[0].input.draft, h.project.baseline);
  assert.deepEqual(Object.keys(h.state.attempt.binding).sort(), ['projectId', 'draftRevision', 'baselineGeneration', 'platform', 'operation',
    'connectionGeneration', 'selectionGeneration', 'contextGeneration', 'nativeStatusRevision', 'previousRunId'].sort());
  h.emit(status(2, owner({ phase: 'checking' })));
  assert.equal(h.state.attempt.acknowledged, false);
  h.reply(h.calls[0], status(1, owner())); await flush();
  assert.equal(h.state.status.statusRevision, 2); assert.equal(h.state.attempt.acknowledged, true);
  h.controller.dispose();
});

test('a complete provisional core report retains busy ownership until the actual native settled projection', async () => {
  const h = harness(); await acknowledged(h);
  h.emit(status(2, finished({ phase: 'stopping', finality: 'pending' })));
  assert.equal(h.state.observation.projection.result.outcome, 'complete'); assert.equal(h.controller.start(), false);
  assert.notEqual(diagnosticsOwnerReason(h.state), null);
  h.tick(); h.emit(status(3, null, finished()));
  assert.equal(h.state.observation.receivedAt, 100); assert.equal(h.state.observation.projection.finality, 'settled');
  assert.equal(h.state.observation.stale, false); assert.equal(h.controller.startReason(), null);
  const earlierBinding = h.state.observation.binding;
  assert.equal(h.controller.start(), true);
  h.emit(status(4, owner({ runId: OTHER, ownerGeneration: 'd'.repeat(32) }), finished()));
  assert.equal(h.state.observation.binding, earlierBinding); assert.equal(h.state.observation.stale, true);
  assert.equal(h.state.observation.provenance, 'acknowledged-start');
  h.controller.dispose();
});

test('lost Start recovers same-context native tokens without acknowledgment, retry or automatic adoption/cancel', async () => {
  const h = harness(); await h.ready; h.controller.start();
  h.registry(status(1, owner())); h.calls[0].reject(new Error('PRIVATE_LOST_REPLY')); await flush();
  assert.equal(h.calls.length, 1); assert.equal(h.reads.length, 2); assert.equal(h.state.attempt.acknowledged, false);
  assert.equal(h.state.attempt.projection.runId, RUN);
  h.controller.setContext('ios', 'build'); h.controller.setVisible(false);
  assert.equal(h.calls.length, 1); assert.equal(h.controller.start(), false);
  assert.equal(h.controller.cancel({ runId: RUN, ownerGeneration: GENERATION }), true);
  assert.deepEqual(h.calls[1].input, { runId: RUN, ownerGeneration: GENERATION });
  assert.equal(h.state.attempt.adopted, true); assert.equal(h.controller.cancel({ runId: RUN, ownerGeneration: GENERATION }), false);
  h.controller.dispose(); assert.equal(h.calls.length, 2);
});

test('lost Start does not adopt a different context; exact pre-admission refusal clears intent only after Status', async () => {
  const h = harness(); await h.ready; h.controller.start();
  const foreign = owner({ runId: OTHER, context: { ...CONTEXT, projectId: 'project-2' } });
  h.registry(status(1, foreign)); h.calls[0].reject(new Error('lost')); await flush();
  assert.equal(h.state.attempt.projection, null); assert.equal(h.state.status.active.runId, OTHER); assert.equal(h.calls.length, 1);
  h.controller.setContext('ios', 'build'); assert.equal(h.calls.length, 1); h.controller.dispose();
  const refused = harness(); await refused.ready; refused.controller.start();
  refused.calls[0].reject({ code: 'environment_diagnostics_busy' }); await flush();
  assert.equal(refused.state.attempt, null); assert.equal(refused.state.error.code, 'environment_diagnostics_busy');
  assert.equal(refused.controller.startReason(), null); assert.equal(refused.calls.length, 1);
  refused.controller.dispose();
});

test('project/draft/baseline, context, navigation, picker and connection changes retire acknowledged intent once', async () => {
  const changes = [
    (h) => { const first = h.project; h.select({ ...first, project: { ...first.project, id: 'project-2' } }); h.select(first); },
    (h) => h.select({ ...h.project, revision: 3, draft: { changed: true } }),
    (h) => h.select({ ...h.project, baselineGeneration: 4 }),
    (h) => { h.controller.setContext('ios', 'build'); h.controller.setContext('android', 'build'); },
    (h) => { h.controller.setContext('android', 'artifact-validation'); h.controller.setContext('android', 'build'); },
    (h) => { h.controller.setVisible(false); h.controller.setVisible(true); },
    (h) => { h.controller.setSelectionPending(true); h.controller.setSelectionPending(false); },
    (h) => h.controller.beginConnection(),
  ];
  for (const change of changes) {
    const h = harness(); await acknowledged(h); change(h);
    assert.equal(h.calls.length, 2); assert.equal(h.calls[1].kind, 'cancel');
    assert.deepEqual(h.calls[1].input, { runId: RUN, ownerGeneration: GENERATION });
    h.reply(h.calls[1], status(2, null, finished())); await flush();
    assert.equal(h.state.observation.stale, true); assert.equal(h.state.attempt.invalidated, true);
    h.controller.dispose(); assert.equal(h.calls.length, 2);
  }
});

test('late Start acknowledgment after invalidation cancels only its exact original pair; synchronous pre-invoke retirement sends nothing', async () => {
  const h = harness(); await h.ready; h.controller.start(); h.select({ ...h.project, revision: 3 });
  assert.equal(h.calls.length, 1);
  h.reply(h.calls[0], status(1, owner())); await flush();
  assert.equal(h.calls.length, 2); assert.equal(h.calls[1].kind, 'cancel'); h.controller.dispose();
  const synchronous = harness(); await synchronous.ready;
  const unlisten = synchronous.controller.subscribe(() => { if (synchronous.state.attempt) synchronous.controller.setVisible(false); });
  assert.equal(synchronous.controller.start(), false); assert.equal(synchronous.calls.length, 0); assert.equal(synchronous.state.attempt, null);
  unlisten(); synchronous.controller.dispose();
});

test('Unknown is sticky across late joins, current reads and reconnect; contradictory or raw events cannot enable another operation', async () => {
  const h = harness(); await acknowledged(h);
  const unknown = owner({ phase: 'retained-unknown', finality: 'unknown', outcome: 'timed-out', reason: 'timed-out', result: core() });
  h.emit(status(2, unknown, null, 'cleanup-unknown'));
  const evidence = h.state.unknownEvidence;
  h.emit(status(3, null, unknown, 'cleanup-unknown'));
  assert.equal(h.state.status.active, null); assert.equal(h.state.nativeBlocked, true); assert.equal(h.state.unknownEvidence, evidence);
  await h.controller.checkStatus(); assert.notEqual(h.controller.startReason(), null);
  h.controller.beginConnection(); await h.controller.connect(h.api); assert.equal(h.state.nativeBlocked, true);
  h.emit(status(4, null, finished()));
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status.lastTerminal.finality, 'unknown'); assert.equal(h.controller.start(), false);
  h.controller.dispose();
  const bad = harness(); await bad.ready; bad.emit({ raw: 'PRIVATE_OUTPUT' });
  assert.equal(bad.state.integrityFailed, true); assert.equal(JSON.stringify(bad.state).includes('PRIVATE'), false);
  await bad.controller.checkStatus(); assert.equal(bad.state.integrityFailed, true); bad.controller.dispose();
});

test('browser, artifact-validation, missing listener and another original owner cannot start; disposal preserves ownership', async () => {
  const h = harness(); await h.ready;
  h.other('Another original owner'); assert.equal(h.controller.start(), false); h.other(null);
  h.controller.setContext('android', 'artifact-validation'); assert.equal(h.controller.start(), false); assert.match(h.controller.startReason(), /Artifact-validation/);
  h.controller.setContext('android', 'build'); await acknowledged(h);
  h.controller.dispose(); assert.equal(h.state.status.active.runId, RUN); assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1);
  const retained = h.state; h.calls[1].resolve(status(2, null, finished())); await flush(); assert.equal(h.state, retained);
  const offline = harness({ listenError: { code: 'unknown', message: 'PRIVATE' } }); await offline.ready;
  await offline.controller.checkStatus(); assert.equal(offline.state.initialized, true); assert.equal(offline.state.listening, false); assert.equal(offline.controller.start(), false);
  offline.controller.beginConnection(); await offline.controller.connect(previewApi); assert.equal(offline.controller.start(), false); assert.equal(offline.calls.length, 0);
  await assert.rejects(previewApi.environmentDiagnosticsStatus()); await assert.rejects(previewApi.startEnvironmentDiagnostics(request())); offline.controller.dispose();
});

test('source integration keeps explicit native controls, truthful budgets, core help, and both small contextual-help fixes', () => {
  // These are wiring/copy guards, not an executed component or GUI test.
  const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), 'utf8');
  const app = source('App.tsx'), page = source('pages/Environment.tsx'), panel = source('components/EnvironmentDiagnostics.tsx');
  assert.ok(app.includes('diagnosticsControllerRef.current?.syncProject()'));
  assert.ok(app.indexOf('diagnostics.beginConnection()') < app.indexOf('const connection = await desktopApi()'));
  assert.ok(app.includes("diagnostics.setVisible(next === 'environment')")); assert.ok(app.includes('diagnostics.setSelectionPending(true)'));
  assert.ok(app.includes("page !== 'environment' && <EnvironmentDiagnostics"));
  assert.ok(page.includes('diagnosticsController.setContext(platform, operation)')); assert.ok(page.includes('Load draft requirements'));
  assert.ok(panel.includes('Check build tools') && panel.includes('Cancel observed run') && panel.includes('Read native status'));
  for (const text of ['6-second work limit', '10-second total finality cutoff', '16 KiB aggregate stdout + stderr',
    'Complete means the finite check roster finished', 'Core result received; native settlement is still pending', '<p>{row.help}</p>',
    'Workflow reference · not a local compatibility rule', 'does not mean globally absent']) assert.ok(panel.includes(text));
  assert.equal(panel.includes('writesPerformed'), false);
  assert.ok(panel.includes("!compact && !active && attempt?.projection?.finality === 'settled' && attempt.projection.result === null"));
  assert.ok(panel.includes('The original check ended without a tool report. Native reason: {attempt.projection.reason}'));
  const github = source('pages/GitHub.tsx'), credentials = source('pages/Credentials.tsx');
  assert.ok(github.includes('credentialHelp?.find((entry) => entry.name === requirement.name)'));
  assert.ok(github.includes('HelpButton content={{ ...help, label: help.name }}'));
  assert.ok(github.includes('No substitute credential policy is supplied here'));
  assert.ok(app.includes('credentialHelp={catalog?.credentials ?? null} onHelp={setHelp}'));
  assert.ok(credentials.includes('!state.blocked && !state.observationFailed && nativeBusyReason === null'));
  assert.ok(credentials.includes('The session importer is currently unavailable. Read its status and reason above'));
  const session = source('components/CredentialSession.tsx');
  assert.ok(session.includes('const baseReason = nativeBusyReason ?? assetSessionReason(state)'));
  assert.ok(session.includes('const cancellationReason = assetCancellationReason(state)'));
  assert.ok(session.includes("disabled={state.mode !== 'native' || state.observing}"));
});
