// Passive source DATA and the existing workspace reducer only. No filesystem,
// native port, build, provider, DOM or source-edit operation is executed.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { canUseIosAppTarget, copyIosAppTarget, iosAppTargetHints, parseIosAppTargets } from '../src/iosAppTargetHints.ts';

const PROJECT = 'iosApp/Reader.xcodeproj';
const row = (project = PROJECT, targets = [{ name: 'Reader', line: 10 }, { name: 'Reader Beta', line: 21 }]) => ({
  project, source: `${project}/project.pbxproj`, targets,
});
const clone = value => structuredClone(value);
const reference = id => ({ id, name: `Synthetic ${id}`, path: `/inert/${id}` });
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function snapshot(id = 'a') {
  return {
    root: `/inert/${id}`, observedAt: '2026-10-20T00:00:00Z', observationScope: 'single-request-non-atomic',
    config: { state: 'format-valid', path: 'release/mobile-release.json', issues: [],
      content: { bytes: 256, sha256: 'a'.repeat(64) },
      data: { ios: { enabled: true, project: PROJECT, scheme: 'ReleaseArchive', bundleId: 'com.example.reader' } } },
    discovery: { state: 'unverified', partial: false, hints: { ios: { projects: [PROJECT], schemes: ['ReleaseArchive'], appTargets: [row()] } },
      scan: { entries: 7, sourceFiles: 2, sourceBytes: 3000, excludedEntries: 0 }, limits: {} },
    assurance: { ...assurance }, issues: [],
  };
}
function loaded(id = 'a', incoming = snapshot(id)) {
  let state = workspaceReducer(initialWorkspace, { type: 'select', project: reference(id) });
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: id, requestId: 1 });
  return workspaceReducer(state, { type: 'snapshot-done', projectId: id, requestId: 1, snapshot: incoming, observedAt: 1 });
}
function choice(session = loaded().projects.a) {
  const shown = iosAppTargetHints(session);
  const captured = { session, service: {}, binding: {}, epoch: 3, platform: 'ios', blocked: false };
  let current = { ...captured }, localTarget = 'Keep my manual target', retires = 0, sets = 0;
  return {
    shown, captured, get current() { return current; }, set current(value) { current = value; },
    get target() { return localTarget; }, get retires() { return retires; }, get sets() { return sets; },
    copy(target = 'Reader Beta', afterRetire = () => {}) {
      return copyIosAppTarget(shown, captured, target, () => current, () => {
        retires++; current = { ...current, epoch: current.epoch + 1 }; afterRetire(this);
      }, target => { sets++; localTarget = target; });
    },
  };
}

test('closed rows copy only source names and locations and freeze independent bounded data', () => {
  const original = [row(), row('second/Other.xcodeproj', [{ name: 'Other', line: 1 }])];
  const parsed = parseIosAppTargets(original);
  assert.deepEqual(parsed, original.map(row => ({ ...row, diagnostic: null }))); assert.ok(Object.isFrozen(parsed));
  assert.ok(Object.isFrozen(parsed[0])); assert.ok(Object.isFrozen(parsed[0].targets[0]));
  original[0].targets[0].name = 'Changed'; assert.equal(parsed[0].targets[0].name, 'Reader');
  assert.deepEqual(Object.keys(parsed[0]).sort(), ['diagnostic', 'project', 'source', 'targets']);
  assert.equal(Object.hasOwn(parsed[0], 'authorized'), false);
});

test('closed parser refuses getters, symbols, hidden fields, prototypes, sparse arrays and cycles without evaluation', () => {
  let getters = 0;
  const getter = [row()]; Object.defineProperty(getter[0], 'targets', { enumerable: true, get() { getters++; return []; } });
  assert.equal(parseIosAppTargets(getter), null); assert.equal(getters, 0);
  for (const mutate of [
    value => { value[0].unknown = true; },
    value => { value[0][Symbol('extra')] = true; },
    value => { Object.defineProperty(value[0], 'hidden', { value: true }); },
    value => { Object.setPrototypeOf(value[0], { extra: true }); },
    value => { value[0].targets = Array(2); },
    value => { value[0].targets.push(value); },
    value => { value[0].toJSON = () => { throw Error('not called'); }; },
  ]) { const value = [row()]; mutate(value); assert.equal(parseIosAppTargets(value), null); }
});

test('limits, unsafe paths, duplicate names and diagnostic/list contradictions refuse the entire optional field', () => {
  for (const mutate of [
    value => { value.push(clone(value[0])); },
    value => { value[0].targets.push({ name: 'Reader', line: 30 }); },
    value => { value[0].targets[0].line = true; },
    value => { value[0].targets[0].line = 524290; },
    value => { value[0].targets[0].name = '$(TARGET)'; },
    value => { value[0].targets[0].name = 'x'.repeat(256); },
    value => { value[0].source = 'Elsewhere.xcodeproj/project.pbxproj'; },
    value => { value[0].diagnostic = { code: 'unsupported-source', line: 1 }; },
    value => { value[0].diagnostic = null; },
    value => { value[0].targets = []; value[0].diagnostic = { code: 'raw-exception', line: 1 }; },
    value => { value[0].targets = Array.from({ length: 33 }, (_, i) => ({ name: `App${i}`, line: 1 })); },
  ]) { const value = [row()]; mutate(value); assert.equal(parseIosAppTargets(value), null); }
  for (const path of ['../Bad.xcodeproj', '/Bad.xcodeproj', 'private/App.xcodeproj', '.git/App.xcodeproj', 'a//App.xcodeproj'])
    assert.equal(parseIosAppTargets([row(path)]), null);
  assert.equal(parseIosAppTargets(Array.from({ length: 17 }, (_, i) => row(`App${i}.xcodeproj`))), null);
});

test('actual saved observation offers all literal app names without choosing a target or mutating a draft', () => {
  const state = loaded(), session = state.projects.a, before = clone(state);
  const hints = iosAppTargetHints(session);
  assert.equal(hints.state, 'available'); assert.equal(hints.project, PROJECT);
  assert.deepEqual(hints.targets.map(target => target.name), ['Reader', 'Reader Beta']);
  assert.equal(hints.targets.some(target => target.name === 'ReleaseArchive'), false);
  assert.match(hints.message, /not a build check/); assert.deepEqual(state, before);
  assert.equal(Object.hasOwn(hints, 'selectedTarget'), false);
  const edited = workspaceReducer(state, { type: 'edit', projectId: 'a', path: 'ios.project', value: 'DraftOnly.xcodeproj' });
  assert.equal(iosAppTargetHints(edited.projects.a).project, PROJECT, 'draft never supplies the saved project');
});

test('source rows must match the exact saved project; workspace and missing or malformed data stay manual', () => {
  for (const mutate of [
    value => { value.discovery.hints.ios.appTargets = [row('Other.xcodeproj')]; },
    value => { delete value.discovery.hints.ios.appTargets; },
    value => { value.discovery.hints.ios.appTargets[0].unexpected = true; },
    value => { value.discovery.hints.ios.appTargets[0].targets = []; },
    value => { value.config.data.ios.workspace = 'Reader.xcworkspace'; },
    value => { delete value.config.data.ios.project; },
    value => { value.config.data.ios.enabled = false; },
  ]) {
    const incoming = snapshot(); mutate(incoming);
    const hints = iosAppTargetHints(loaded('a', incoming).projects.a);
    assert.equal(hints.state, 'manual'); assert.deepEqual(hints.targets, []);
  }
});

test('unsupported source reports a useful fixed location without exposing raw source or pretending an absence', () => {
  for (const code of ['missing-source', 'source-limit', 'unsupported-source', 'ambiguous-target', 'generated-project']) {
    const incoming = snapshot(); incoming.discovery.hints.ios.appTargets = [{ ...row(), targets: [], diagnostic: { code, line: 12 } }];
    const hints = iosAppTargetHints(loaded('a', incoming).projects.a);
    assert.equal(hints.state, 'manual'); assert.equal(hints.source, `${PROJECT}/project.pbxproj`);
    assert.equal(hints.diagnosticLine, 12); assert.ok(hints.message.length > 30);
    assert.equal(hints.message.includes('Error:'), false); assert.deepEqual(hints.targets, []);
  }
});

test('pending, failed, partial, source-changed and recovery observations cannot supply clickable hints', () => {
  const original = loaded().projects.a;
  const variants = [null, { ...original, snapshot: null }, { ...original, snapshotRequest: 2 },
    { ...original, snapshotError: { code: 'unavailable', message: 'Inert', retryable: false } },
    { ...original, snapshotPredatesSave: true }, { ...original, sourceChanged: true },
    { ...original, saveRecoveryRequired: true }, { ...original, saveRecoveryNeedsReload: true },
    { ...original, savedConfigContent: { bytes: 256, sha256: 'b'.repeat(64) } }];
  for (const mutate of [
    value => { value.snapshot.root = '/inert/other'; },
    value => { value.snapshot.config.state = 'missing'; value.snapshot.config.data = null; },
    value => { value.snapshot.discovery.partial = true; },
    value => { value.snapshot.discovery.state = 'invented-resolved'; },
  ]) { const value = clone(original); mutate(value); variants.push(value); }
  for (const session of variants) {
    const hints = iosAppTargetHints(session);
    assert.equal(hints.state, 'refresh'); assert.deepEqual(hints.targets, []);
    assert.match(hints.message, /manual target is kept/);
    assert.equal(canUseIosAppTarget(iosAppTargetHints(original), original, session, 'Reader'), false);
  }
});

test('same-byte replacement observation and in-place drift retire an old choice instead of rebinding it', () => {
  const state = loaded(), original = state.projects.a, shown = iosAppTargetHints(original);
  let refresh = workspaceReducer(state, { type: 'snapshot-start', projectId: 'a', requestId: 2 });
  refresh = workspaceReducer(refresh, { type: 'snapshot-done', projectId: 'a', requestId: 2, snapshot: snapshot(), observedAt: 2 });
  assert.deepEqual(iosAppTargetHints(refresh.projects.a), shown);
  assert.equal(canUseIosAppTarget(shown, original, refresh.projects.a, 'Reader'), false);
  original.snapshot.discovery.hints.ios.appTargets[0].targets[0].name = 'ChangedAfterRender';
  assert.equal(canUseIosAppTarget(shown, original, original, 'Reader'), false);
});

test('explicit local choice retires the prior review exactly once and does not change saved settings', () => {
  const h = choice(), before = clone(h.captured.session);
  assert.equal(h.target, 'Keep my manual target'); assert.equal(h.sets, 0); assert.equal(h.retires, 0);
  assert.equal(h.copy(), true); assert.equal(h.target, 'Reader Beta'); assert.equal(h.retires, 1); assert.equal(h.sets, 1);
  assert.deepEqual(h.captured.session, before);
  assert.equal(h.copy(), false, 'same old rendered click cannot retire twice'); assert.equal(h.sets, 1);
});

test('missing native connection, wrong project, peer work and old epoch never retire or overwrite the manual field', () => {
  for (const change of [
    { service: null }, { binding: null }, { blocked: true }, { platform: 'android' },
    { session: loaded('b').projects.b }, { epoch: 4 }, { service: {} }, { binding: {} },
  ]) {
    const h = choice(); h.current = { ...h.current, ...change };
    assert.equal(h.copy(), false); assert.equal(h.retires, 0); assert.equal(h.sets, 0);
    assert.equal(h.target, 'Keep my manual target');
  }
  const h = choice(); assert.equal(h.copy('NotObserved'), false); assert.equal(h.retires, 0);
});

test('every synchronous retirement publication rechecks original session, API, binding, epoch and peer gate', () => {
  for (const mutate of [
    h => { h.current = { ...h.current, service: {} }; },
    h => { h.current = { ...h.current, binding: {} }; },
    h => { h.current = { ...h.current, session: loaded().projects.a }; },
    h => { h.current = { ...h.current, blocked: true }; },
    h => { h.current = { ...h.current, platform: 'android' }; },
    h => { h.current = { ...h.current, epoch: h.current.epoch + 2 }; }, // retired away/back ABA
    h => { h.current.session.snapshot.discovery.partial = true; },
    () => { throw Error('fixed refusal, not a logged exception'); },
  ]) {
    const h = choice(); assert.equal(h.copy('Reader', mutate), false);
    assert.equal(h.retires, 1); assert.equal(h.sets, 0); assert.equal(h.target, 'Keep my manual target');
  }
});

test('captured disabled context and exhausted epochs cannot invoke callbacks; retirement is never guessed', () => {
  const h = choice(); let calls = 0;
  for (const change of [{ blocked: true }, { service: null }, { binding: null }, { platform: 'android' },
    { epoch: -1 }, { epoch: NaN }, { epoch: Number.MAX_SAFE_INTEGER }]) {
    assert.equal(copyIosAppTarget(h.shown, { ...h.captured, ...change }, 'Reader', () => h.current,
      () => { calls++; }, () => { calls++; }), false);
  }
  assert.equal(calls, 0);
  assert.equal(copyIosAppTarget(h.shown, h.captured, 'Reader', () => h.current, () => { calls++; }, () => { calls++; }), false);
  assert.equal(calls, 1, 'an unchanged epoch after retire cannot copy a name');
});
