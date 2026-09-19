// Inert DTO, reducer and controlled-promise checks only. No project files,
// native runtime, tools, network, DOM, clocks, polling or child processes.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { previewApi } from '../src/preview.ts';
import { ReleaseVersionController, parseReleaseVersionObservation, releaseVersionError, releaseVersionHelp,
  releaseVersionPhase, releaseVersionRequestFits, releaseVersionStartReason } from '../src/releaseVersion.ts';

const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function observation(source = 'release/saved-version.properties', name = '1.2.3-rc+4', build = 24) {
  return { schemaVersion: 1, source, version: { name, build }, observationScope: 'single-request-non-atomic', assurance: { ...assurance } };
}
const info = { runtime: { state: 'available', mode: 'development', reason: null },
  capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } };
function project(id = 'p1', dirty = false) {
  const selected = workspaceReducer(initialWorkspace, { type: 'select', project: { id, name: 'Inert project', path: '/inert/never-opened' } });
  const baseline = { version: { source: 'release/retained-baseline.properties', nameKey: 'OLD_NAME', buildKey: 'OLD_BUILD' }, ios: { enabled: true } };
  const draft = structuredClone(baseline);
  if (dirty) draft.version.source = 'release/unsaved-draft.properties';
  return { ...selected.projects[id], baseline, draft, revision: 4, baselineGeneration: 3, observationGeneration: 7 };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function controlled({ dirty = false } = {}) {
  let workspace = { selectedId: 'p1', projects: { p1: project('p1', dirty) } }, busy = false;
  const calls = [];
  const api = { mode: 'native', observeReleaseVersion: (...args) => {
    const work = deferred(); calls.push({ args, ...work }); return work.promise;
  } };
  const controller = new ReleaseVersionController(() => workspace.selectedId ? workspace.projects[workspace.selectedId] : null, () => busy);
  controller.setConnection(api, info); controller.syncProject();
  return {
    controller, api, calls,
    get state() { return controller.getSnapshot(); },
    get selected() { return workspace.projects[workspace.selectedId]; },
    get workspace() { return workspace; },
    busy(value) { busy = value; },
    replace(session) { workspace = { ...workspace, projects: { ...workspace.projects, [session.project.id]: session } }; controller.syncProject(); },
    dispatch(action) {
      // Same ordering as App: retire before the reducer can return unchanged.
      controller.beforeWorkspaceAction(action);
      const next = workspaceReducer(workspace, action);
      if (next === workspace) return;
      workspace = next; controller.syncProject();
    },
  };
}
function generations(session) { return [session.revision, session.baselineGeneration, session.observationGeneration]; }
function refreshFailure(h) {
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 90 });
  assert.equal(h.state.pending, null);
  assert.match(h.controller.startReason(), /static refresh/);
  h.dispatch({ type: 'snapshot-failed', projectId: 'p1', requestId: 90, error: { code: 'busy', message: 'Inert refusal', retryable: false } });
}
function refreshSuccess(h) {
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 91 });
  const snapshot = { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', data: structuredClone(h.selected.baseline), issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: { ...assurance }, issues: [] };
  h.dispatch({ type: 'snapshot-done', projectId: 'p1', requestId: 91, snapshot, observedAt: 1 });
}
// Minimal trusted reducer-event fixture, not a simulated native save or a
// finality claim. The existing config-edit suite owns full receipt admission.
function saveEvent(session, { result = 'unchanged', older = false } = {}) {
  const binding = { projectId: session.project.id, windowGeneration: 'a'.repeat(32), startStatusRevision: 1,
    previousTerminalId: null, draftRevision: session.revision - (older ? 1 : 0), baselineGeneration: session.baselineGeneration,
    expectedBase: structuredClone(session.baseline), draft: structuredClone(session.draft) };
  const sessionId = 'b'.repeat(32), planToken = 'c'.repeat(32), revision = 'd'.repeat(32);
  const projection = { projectId: session.project.id, ownerGeneration: binding.windowGeneration, sessionId,
    phase: 'final', nativeFinality: 'settled', nativeReason: 'none', lateSettled: false, applySubmitted: true,
    checkout: { revision, base: structuredClone(binding.expectedBase) },
    prepared: { revision, planToken, draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration,
      view: { files: [{ path: 'release/mobile-release.json', action: result === 'saved' ? 'replace' : 'preserve' }, { path: '.gitignore', action: 'preserve' }] } },
    coreOutcome: { effect: result === 'saved' ? 'committed' : 'unchanged', journal: result === 'saved' ? 'clean' : 'not_created', resources: 'settled', reason: 'none' } };
  return { type: 'config-save-final', projectId: session.project.id, receipt: { binding, projection, sessionId, planToken, statusRevision: 2, result } };
}
function recoveryEvent() {
  return { type: 'config-save-recovery', projectId: 'p1', attention: { projectId: 'p1', sessionId: 'e'.repeat(32), ownerGeneration: 'a'.repeat(32),
    phase: 'final', nativeFinality: 'settled', coreOutcome: { effect: 'rolled_back', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } } };
}

test('exact request admits only a bounded registered ID, never path/draft/key/platform overrides or getters', () => {
  assert.equal(releaseVersionRequestFits({ projectId: 'p_1-' }), true);
  assert.equal(releaseVersionRequestFits({ projectId: 'a'.repeat(64) }), true);
  assert.equal(releaseVersionRequestFits(Object.assign(Object.create(null), { projectId: 'p1' })), true);
  let reads = 0;
  const getter = { get projectId() { reads += 1; return 'p1'; } };
  const hidden = Object.defineProperty({}, 'projectId', { value: 'p1' });
  for (const value of [null, [], 'p1', {}, getter, hidden, new String('p1'), Object.create({ projectId: 'p1' }),
    { projectId: '' }, { projectId: '../p1' }, { projectId: 'é' }, { projectId: 'a'.repeat(65) }, { projectId: 'p1\n' }, { projectId: 'p1\r' }, { projectId: 1 },
    { projectId: 'p1', [Symbol('extra')]: false }, ...['root', 'source', 'path', 'draft', 'nameKey', 'buildKey', 'platform'].map((key) => ({ projectId: 'p1', [key]: 'PRIVATE' })),
    { projectId: 'x'.repeat(8193) }]) assert.equal(releaseVersionRequestFits(value), false);
  assert.equal(reads, 0);
});

test('DTO copies bounded saved source and core values without imposing renderer iOS version policy', () => {
  const raw = observation(), parsed = parseReleaseVersionObservation(raw);
  assert.deepEqual(parsed, raw);
  assert.notEqual(parsed, raw); assert.notEqual(parsed.version, raw.version); assert.notEqual(parsed.assurance, raw.assurance);
  raw.version.name = 'changed'; raw.assurance.toolsProbed = true;
  assert.equal(parsed.version.name, '1.2.3-rc+4'); assert.equal(parsed.assurance.toolsProbed, false);
  assert.ok(parseReleaseVersionObservation(observation('release/é-version.properties', 'a'.repeat(64), 2_100_000_000)));
  assert.ok(parseReleaseVersionObservation(observation('a/'.repeat(11) + 'v')));
  const maxBytes = 'é'.repeat(127) + '/' + 'é'.repeat(127) + '/aa';
  assert.equal(new TextEncoder().encode(maxBytes).byteLength, 512);
  assert.ok(parseReleaseVersionObservation(observation(maxBytes)));
  assert.equal(parseReleaseVersionObservation(observation(maxBytes + 'b')), null);
  assert.equal(parseReleaseVersionObservation(observation('é'.repeat(128))), null);
  assert.ok(new TextEncoder().encode(JSON.stringify(parsed)).byteLength <= 4096);
});

test('DTO admission rejects extra fields, coercions, false assurance, unsafe display paths and oversized data', () => {
  const mutations = [
    (v) => { v.extra = 'PRIVATE'; }, (v) => { v.schemaVersion = '1'; }, (v) => { v.observationScope = 'atomic'; },
    (v) => { delete v.source; }, (v) => { v.version.extra = 'PRIVATE'; }, (v) => { v.assurance.basis = 'schema-policy'; },
    (v) => { v.assurance.releaseReadiness = 'ready'; }, (v) => { v.assurance.extra = false; },
    ...['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].map((key) => (v) => { v.assurance[key] = true; }),
    ...[0, -1, 1.5, 2_100_000_001, Number.MAX_SAFE_INTEGER + 1, NaN, Infinity, '24', true, null].map((build) => (v) => { v.version.build = build; }),
    ...['', 'x'.repeat(65), '1_2', '1 2', '1\n2', '1\n', '1\r', 'é', '\ud800'].map((name) => (v) => { v.version.name = name; }),
    ...['', '/absolute', '../version', 'release/../version', 'release//version', './version', '.hidden/version', 'release/.env',
      'release/version.', 'release/version ', 'C:/version', 'release\\version', 'release/secret\u0000', 'release/bad\u007f',
      'release/bad?', 'release/PRIVATE/version', 'release/testflight/version', 'release/CON.txt', 'release/com1', 'release/LPT0.ini',
      'release/e\u0301.properties', 'release/\ud800', 'a/'.repeat(12) + 'v', 'x'.repeat(8193)].map((source) => (v) => { v.source = source; }),
  ];
  for (const mutate of mutations) { const value = observation(); mutate(value); assert.equal(parseReleaseVersionObservation(value), null); }
  let reads = 0;
  for (const field of ['source', 'version', 'assurance']) {
    const value = observation(); Object.defineProperty(value, field, { enumerable: true, get() { reads += 1; return 'PRIVATE'; } });
    assert.equal(parseReleaseVersionObservation(value), null);
  }
  const nested = observation(); Object.defineProperty(nested.version, 'name', { enumerable: true, get() { reads += 1; return 'PRIVATE'; } });
  assert.equal(parseReleaseVersionObservation(nested), null);
  const hidden = observation(); Object.defineProperty(hidden.assurance, 'basis', { enumerable: false, value: 'static-text' });
  assert.equal(parseReleaseVersionObservation(hidden), null);
  const cyclic = observation(); cyclic.version = cyclic;
  assert.equal(parseReleaseVersionObservation(cyclic), null);
  const exotic = observation(); Object.setPrototypeOf(exotic.version, { toJSON() { reads += 1; } });
  assert.equal(parseReleaseVersionObservation(exotic), null);
  assert.equal(reads, 0);
});

test('closed errors retain known owner/refusal codes but never raw messages, getters, secrets or retry authority', () => {
  const codes = ['invalid_params', 'unavailable', 'config_missing', 'config_invalid', 'source_missing', 'source_invalid',
    'unsafe', 'changed', 'unreadable', 'limit', 'encoding', 'sensitive', 'cleanup_unknown'].map((suffix) => 'release_version_' + suffix);
  codes.push('runtime_unavailable', 'unavailable', 'busy', 'environment_diagnostics_busy', 'quit_pending', 'shutting_down',
    'query_timeout', 'cleanup_unknown', 'unknown_project', 'protocol_error');
  for (const code of codes) {
    const error = releaseVersionError({ code, message: 'PRIVATE_REJECTION', retryable: true, source: 'PRIVATE_SOURCE' });
    assert.equal(error.code, code); assert.equal(error.retryable, false); assert.doesNotMatch(JSON.stringify(error), /PRIVATE/);
  }
  assert.equal(releaseVersionError({ code: 'invalid_request' }).code, 'release_version_invalid_params');
  for (const error of ['PRIVATE', null, new Error('PRIVATE'), { code: 'PRIVATE', message: 'PRIVATE' }]) {
    assert.equal(releaseVersionError(error).code, 'protocol_error');
    assert.doesNotMatch(JSON.stringify(releaseVersionError(error)), /PRIVATE/);
  }
  let reads = 0;
  assert.equal(releaseVersionError({ get code() { reads += 1; return 'busy'; }, get message() { reads += 1; return 'PRIVATE'; } }).code, 'protocol_error');
  assert.equal(releaseVersionError({ code: 'busy', get message() { reads += 1; return 'PRIVATE'; } }).code, 'busy');
  assert.equal(reads, 0);
});

test('bridge uses exactly release_version_observe with the ID-only request, copies its reply and refuses unavailable mode', async () => {
  const pending = deferred(), calls = [], raw = observation();
  const api = createNativeApi('native', (command, args) => { calls.push({ command, args }); return pending.promise; });
  const read = api.observeReleaseVersion('p1');
  assert.deepEqual(calls, [{ command: 'release_version_observe', args: { projectId: 'p1' } }]);
  pending.resolve(raw); const value = await read;
  raw.version.build = 99; assert.equal(value.version.build, 24);
  let called = false;
  const refusing = createNativeApi('native', async () => { called = true; return observation(); });
  for (const input of [{ projectId: 'p1', root: '/PRIVATE' }, '/PRIVATE', 'x'.repeat(65), null]) {
    await assert.rejects(refusing.observeReleaseVersion(input), (error) => error.code === 'release_version_invalid_params');
  }
  assert.equal(called, false);
  const unavailable = createNativeApi('unavailable', async () => assert.fail('No runtime fallback'));
  await assert.rejects(unavailable.observeReleaseVersion('p1'), (error) => error.code === 'runtime_unavailable');
  const invalid = createNativeApi('native', async () => ({ ...observation(), stdout: 'PRIVATE' }));
  await assert.rejects(invalid.observeReleaseVersion('p1'), (error) => error.code === 'protocol_error' && !JSON.stringify(error).includes('PRIVATE'));
  for (const code of ['release_version_source_invalid', 'cleanup_unknown', 'quit_pending', 'environment_diagnostics_busy', 'unavailable', 'PRIVATE']) {
    const rejecting = createNativeApi('native', async () => { throw { code, message: 'PRIVATE', retryable: true }; });
    await assert.rejects(rejecting.observeReleaseVersion('p1'), (error) => error.code === (code === 'PRIVATE' ? 'protocol_error' : code) && !JSON.stringify(error).includes('PRIVATE') && error.retryable === false);
  }
});

test('saved observation sends no draft or retained source, preserves dirty data and never becomes save/readiness evidence', async () => {
  const h = controlled({ dirty: true }), before = structuredClone(h.selected);
  assert.equal(releaseVersionPhase(h.state), 'not-read');
  assert.equal(h.state.project.dirtyDraft, true);
  assert.equal(releaseVersionStartReason(h.state), null);
  const read = h.controller.read(), binding = h.state.pending;
  assert.equal(releaseVersionPhase(h.state), 'reading');
  assert.deepEqual(h.calls[0].args, ['p1']);
  await h.controller.read(); assert.equal(h.calls.length, 1);
  const raw = observation(); h.calls[0].resolve(raw); await read;
  assert.equal(releaseVersionPhase(h.state), 'observed');
  assert.equal(h.state.result.source, 'release/saved-version.properties');
  assert.notEqual(h.state.result.source, h.selected.draft.version.source);
  assert.notEqual(h.state.result.source, h.selected.baseline.version.source);
  assert.deepEqual(h.selected, before); assert.equal(isDirty(h.selected), true); assert.equal(h.selected.lastSave, null);
  assert.equal(h.state.resultBinding, binding); assert.equal(h.state.result.assurance.releaseReadiness, 'unknown');
  assert.ok(Object.isFrozen(h.state) && Object.isFrozen(h.state.result.version) && Object.isFrozen(binding));
  raw.version.name = 'changed'; assert.equal(h.state.result.version.name, '1.2.3-rc+4');
  h.controller.dispose();
});

test('reads do not require a synthesized draft or snapshot and native capability reasons remain visible', async () => {
  const h = controlled(); h.replace({ ...h.selected, baseline: null, draft: null });
  assert.equal(h.selected.snapshot, null); assert.equal(h.controller.startReason(), null);
  const read = h.controller.read(); h.calls[0].reject({ code: 'release_version_config_missing', message: 'PRIVATE' }); await read;
  assert.equal(releaseVersionPhase(h.state), 'missing'); assert.equal(h.selected.draft, null);
  const unavailable = { ...info, runtime: { state: 'disabled', mode: 'unavailable', reason: 'Installed engine launch remains disabled.' } };
  h.controller.setConnection(h.api, unavailable);
  assert.equal(h.controller.startReason(), unavailable.runtime.reason);
  await h.controller.read(); assert.equal(h.calls.length, 1);
  h.controller.setConnection(h.api, { ...info, capabilities: { methods: [{ method: 'release.version.observe', available: false, reason: 'The named observer is unavailable on this platform.' }] } });
  assert.match(h.controller.startReason(), /unavailable on this platform/);
  await h.controller.read(); assert.equal(h.calls.length, 1);
  h.controller.dispose();
});

test('missing, invalid, changed and unavailable failures use fixed UI states without publishing partial values', async () => {
  const expected = { release_version_config_missing: 'missing', release_version_source_missing: 'missing',
    release_version_config_invalid: 'invalid', release_version_source_invalid: 'invalid', release_version_unsafe: 'invalid',
    release_version_encoding: 'invalid', release_version_sensitive: 'invalid', release_version_changed: 'stale',
    release_version_unavailable: 'unavailable', busy: 'unavailable', query_timeout: 'unavailable', protocol_error: 'unavailable' };
  for (const [code, phase] of Object.entries(expected)) {
    const h = controlled(), read = h.controller.read();
    h.calls[0].reject({ code, message: 'PRIVATE', version: { name: 'PRIVATE' } }); await read;
    assert.equal(releaseVersionPhase(h.state), phase); assert.equal(h.state.result, null);
    assert.deepEqual(h.state.error, releaseVersionError({ code }));
    assert.equal(h.controller.startReason(), null); // retry is an explicit action, not a timer
    h.controller.dispose();
  }
  const h = controlled(), read = h.controller.read();
  h.calls[0].resolve({ ...observation(), assurance: { ...assurance, writesPerformed: true } }); await read;
  assert.equal(h.state.error.code, 'protocol_error'); assert.equal(h.state.result, null); h.controller.dispose();
});

test('failed refresh, cancelled picker, save intents and unchanged/older events retire epochs without changing ordinary generations', async () => {
  const retirements = [
    ['failed refresh', refreshFailure],
    ['cancelled picker', (h) => { h.controller.setSelectionPending(true); assert.equal(h.state.pending, null); h.controller.setSelectionPending(false); }],
    ['save intent with no outcome', (h) => h.controller.saveIntent()],
    ['unchanged save', (h) => { h.dispatch(saveEvent(h.selected)); assert.equal(h.selected.lastSave.result, 'unchanged'); }],
    ['successful older save', (h) => { h.dispatch(saveEvent(h.selected, { result: 'saved', older: true })); assert.equal(h.selected.lastSave.result, 'saved'); assert.equal(h.selected.lastSave.resultingBaselineGeneration, null); }],
  ];
  for (const [label, retire] of retirements) for (const fails of [false, true]) {
    const h = controlled(), ordinary = generations(h.selected), old = h.controller.read(), epoch = h.state.readEpoch;
    retire(h);
    assert.deepEqual(generations(h.selected), ordinary, label); assert.ok(h.state.readEpoch > epoch, label);
    assert.equal(h.state.pending, null, label); assert.equal(h.calls.length, 1, 'No implicit reread');
    const newer = h.controller.read(), current = h.state.pending;
    assert.ok(current); assert.equal(h.calls.length, 2);
    if (fails) h.calls[0].reject({ code: 'cleanup_unknown', message: 'PRIVATE old failure' });
    else h.calls[0].resolve(observation('release/old.properties', '1.0.0', 1));
    await old;
    assert.equal(h.state.pending, current, label); assert.equal(h.state.result, null); assert.equal(h.state.error, null); assert.equal(h.state.reason, null);
    h.calls[1].resolve(observation('release/new.properties', '2.0.0', 2)); await newer;
    assert.equal(h.state.resultBinding, current); assert.equal(h.state.result.version.build, 2); h.controller.dispose();
  }
});

test('duplicate save and recovery events retire synchronously even when the reducer returns its original workspace', async () => {
  for (const fails of [false, true]) {
    const h = controlled(), event = saveEvent(h.selected);
    h.dispatch(event);
    const before = h.workspace, ordinary = generations(h.selected), old = h.controller.read(), epoch = h.state.readEpoch;
    h.dispatch(event);
    assert.equal(h.workspace, before); assert.deepEqual(generations(h.selected), ordinary);
    assert.ok(h.state.readEpoch > epoch); assert.equal(h.state.pending, null);
    const newer = h.controller.read(), current = h.state.pending;
    h.calls[0].resolve(observation()); await old; assert.equal(h.state.pending, current); assert.equal(h.state.result, null);
    h.calls[1].resolve(observation()); await newer;
    const original = h.state.result, waiting = h.controller.read(), recovery = recoveryEvent(), generation = generations(h.selected);
    h.dispatch(recovery);
    assert.deepEqual(generations(h.selected), generation); assert.equal(h.state.pending, null); assert.equal(h.state.stale, true);
    const recoveredWorkspace = h.workspace, retired = h.state.readEpoch;
    h.dispatch(recovery);
    assert.equal(h.workspace, recoveredWorkspace); assert.ok(h.state.readEpoch > retired);
    assert.match(h.controller.startReason(), /recovery attention/);
    if (fails) h.calls[2].reject({ code: 'release_version_source_invalid', message: 'PRIVATE' });
    else h.calls[2].resolve(observation('release/too-late.properties'));
    await waiting;
    assert.equal(h.state.result, original); assert.equal(h.state.error, null); assert.equal(h.state.stale, true);
    await h.controller.read(); assert.equal(h.calls.length, 3); h.controller.dispose();
  }
});

test('same-project edits, successful refresh and service replacement stale data; a late old result cannot become current', async () => {
  const changes = [
    (h) => h.dispatch({ type: 'edit', projectId: 'p1', path: 'version.source', value: 'release/new-draft.properties' }),
    (h) => h.replace({ ...h.selected, baselineGeneration: h.selected.baselineGeneration + 1 }),
    refreshSuccess,
    (h) => { h.controller.beginConnection(); h.controller.setConnection(h.api, info); },
    (h) => h.controller.setConnection({ ...h.api }, info),
    (h) => { h.controller.connectionUnavailable(); h.controller.setConnection(h.api, info); },
  ];
  for (const change of changes) {
    const h = controlled(), first = h.controller.read(); h.calls[0].resolve(observation()); await first;
    const original = h.state.result, old = h.controller.read();
    change(h); assert.equal(h.state.result, original); assert.equal(h.state.stale, true); assert.equal(h.state.pending, null);
    assert.equal(releaseVersionPhase(h.state), 'stale'); assert.equal(h.calls.length, 2);
    h.calls[1].resolve(observation('release/too-late.properties')); await old;
    assert.equal(h.state.result, original); assert.equal(h.state.stale, true);
    const next = h.controller.read(); h.calls[2].resolve(observation('release/current.properties')); await next;
    assert.equal(h.state.result.source, 'release/current.properties'); assert.equal(h.state.stale, false); h.controller.dispose();
  }
});

test('switch away and back clears foreign display and cannot resurrect even the same project/generations', async () => {
  for (const fails of [false, true]) {
    const h = controlled(), first = h.controller.read(); h.calls[0].resolve(observation()); await first;
    const original = h.selected, old = h.controller.read(), generation = h.state.selectionGeneration;
    h.dispatch({ type: 'select', project: project('p2').project });
    assert.equal(h.state.result, null); assert.equal(h.state.pending, null);
    h.dispatch({ type: 'switch', projectId: 'p1' });
    assert.equal(h.selected, original); assert.ok(h.state.selectionGeneration > generation);
    const newer = h.controller.read(), current = h.state.pending;
    if (fails) h.calls[1].reject({ code: 'cleanup_unknown', message: 'PRIVATE' }); else h.calls[1].resolve(observation());
    await old; assert.equal(h.state.pending, current); assert.equal(h.state.result, null); assert.equal(h.state.error, null);
    h.calls[2].resolve(observation('release/current.properties')); await newer; h.controller.dispose();
  }
});

test('synchronous subscribers can retire before invoke; save ownership, disposal and counter exhaustion never launch a replacement', async () => {
  const h = controlled();
  const unsubscribe = h.controller.subscribe(() => { if (h.state.pending) h.controller.saveIntent(); });
  await h.controller.read(); assert.equal(h.calls.length, 0); unsubscribe();
  h.busy(true); assert.match(h.controller.startReason(), /configuration save/);
  await h.controller.read(); assert.equal(h.calls.length, 0);
  h.busy(false); const read = h.controller.read(); h.controller.dispose(); h.calls[0].resolve(observation()); await read;
  assert.equal(h.state.result, null); await h.controller.read(); assert.equal(h.calls.length, 1);
  const reentrant = controlled(), old = reentrant.controller.read();
  const raw = new Proxy(observation(), { ownKeys(value) { reentrant.controller.saveIntent(); return Reflect.ownKeys(value); } });
  reentrant.calls[0].resolve(raw); await old;
  assert.equal(reentrant.state.pending, null); assert.equal(reentrant.state.result, null); reentrant.controller.dispose();
  const exhausted = controlled();
  // Deliberately inject a boundary fixture in the JS test; no public reset or
  // wrapped-epoch API is added to the controller.
  exhausted.controller.state = Object.freeze({ ...exhausted.state, readEpoch: Number.MAX_SAFE_INTEGER - 1 });
  await exhausted.controller.read(); assert.equal(exhausted.state.generationLost, true); assert.equal(exhausted.calls.length, 0);
  exhausted.controller.saveIntent(); assert.equal(exhausted.state.readEpoch, Number.MAX_SAFE_INTEGER);
  exhausted.controller.setConnection(exhausted.api, info); await exhausted.controller.read(); assert.equal(exhausted.calls.length, 0);
  exhausted.controller.dispose();
});

test('current cleanup uncertainty latches unavailable while stale errors cannot transfer native ownership/finality', async () => {
  for (const code of ['cleanup_unknown', 'release_version_cleanup_unknown', 'shutting_down']) {
    const h = controlled(), read = h.controller.read(); h.calls[0].reject({ code, message: 'PRIVATE' }); await read;
    assert.equal(releaseVersionPhase(h.state), 'unavailable'); assert.equal(h.controller.startReason(), h.state.error.message);
    await h.controller.read(); assert.equal(h.calls.length, 1); assert.equal(h.state.result, null); h.controller.dispose();
  }
});

test('browser preview refuses rather than manufacturing a saved-file result, even with a capability-shaped fixture', async () => {
  await assert.rejects(previewApi.observeReleaseVersion('preview-example'), (error) => error.code === 'release_version_unavailable' && /Browser preview/.test(error.message));
  const h = controlled(); h.controller.setConnection({ ...h.api, mode: 'preview' }, info);
  assert.match(h.controller.startReason(), /Browser preview/); assert.equal(releaseVersionPhase(h.state), 'unavailable');
  await h.controller.read(); assert.equal(h.calls.length, 0); assert.equal(h.state.result, null); h.controller.dispose();
});

test('source integration guards keep synchronous P2 hooks, returned-source labels, help and disabled release readiness', () => {
  // Source-text guard only, not an executed React/native-window test.
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../src/pages/Dashboard.tsx', import.meta.url), 'utf8');
  const module = readFileSync(new URL('../src/releaseVersion.ts', import.meta.url), 'utf8');
  const dispatch = app.slice(app.indexOf('const dispatch ='), app.indexOf('const [configEdit]'));
  const retire = dispatch.indexOf('beforeWorkspaceAction(action)');
  assert.ok(retire >= 0 && retire < dispatch.indexOf('workspaceReducer(previous, action)'));
  assert.ok(retire >= 0 && retire < dispatch.indexOf('if (next === previous) return'));
  assert.ok(dispatch.includes('releaseVersionControllerRef.current?.syncProject()'));
  const begin = app.indexOf('releaseVersion.beginConnection()');
  assert.ok(begin >= 0 && begin < app.indexOf('const connection = await desktopApi()'));
  assert.ok(app.includes('releaseVersion.setConnection(connection, appInfo)'));
  assert.ok(app.includes('releaseVersion.connectionUnavailable()') && app.includes('releaseVersion.dispose()'));
  const picker = app.slice(app.indexOf('const chooseProject ='), app.indexOf('const changeApplicationRepository'));
  const intent = picker.indexOf('releaseVersion.setSelectionPending(true)');
  assert.ok(intent >= 0 && intent < picker.indexOf('await api.chooseProject()'));
  assert.ok(picker.includes('finally') && picker.includes('releaseVersion.setSelectionPending(false)'));
  assert.ok(app.includes('releaseVersion.saveIntent(); configEdit.start(session.project.id)'));
  assert.ok(app.includes('releaseVersion.saveIntent(); return configEdit.apply(binding)'));
  assert.ok(app.includes("dispatch({ type: 'snapshot-start', projectId, requestId })") && module.includes("'snapshot-start', 'config-save-final', 'config-save-recovery'"));
  for (const label of ['Read saved version', 'Observed from saved version file', 'Unsaved draft not applied.', 'External changes are not continuously monitored.', 'Stale observation']) assert.ok(page.includes(label));
  assert.ok(page.includes('HelpButton content={releaseVersionHelp}'));
  assert.ok(page.includes('{result.source}') && !page.includes("getValue(config, 'version.source')"));
  assert.ok(page.includes("overflowWrap: 'anywhere', whiteSpace: 'normal'"));
  assert.ok(page.includes('Release readiness</span>') && page.includes('Not assessed</strong>') && page.includes('No release operations are enabled'));
  assert.ok(page.includes('<DisabledAction label="Create release candidate"'));
  assert.match(releaseVersionHelp.what, /release\/mobile-release\.json/);
  assert.match(releaseVersionHelp.failure, /non-atomic/); assert.match(releaseVersionHelp.failure, /not an artifact check/);
});
