// Actual bundled field-help DATA plus pure layout/reducer/picker binding tests.
// No native APIs, DOM, files under an application project, or commands execute.
import assert from 'node:assert/strict';
import test from 'node:test';
import help from '../../src/mobile_release/api/data/field-help.json' with { type: 'json' };
import { blockingAncestor, getValue } from '../src/catalog.ts';
import { initialWorkspace, isDirty, workspaceReducer as reduce } from '../src/drafts.ts';
import { GUIDED_CONFIG_STAGES, guidedConfiguration, guidedConfigFieldMatches, guidedConfigGroup, guidedConfigSelectStage, guidedConfigVisibleStage } from '../src/guidedConfiguration.ts';
import { beginProjectPath, finishProjectPath, initialProjectPathState, projectPathOwnerReason } from '../src/projectPaths.ts';

const catalog = { fields: help };
const project = (id = 'a') => ({ id, name: `Inert ${id}`, path: `/inert/${id}` });
const original = {
  schemaVersion: 1,
  version: { source: 'release/version.properties', nameKey: 'VERSION_NAME', buildKey: 'BUILD_NUMBER' },
  source: { candidateBranch: 'main', productionBranch: 'main' },
  android: { enabled: true, applicationId: 'com.example.inert', identityStatus: 'unverified' },
  ios: { enabled: false },
  metadata: { root: 'release/store', androidLocales: ['en-US'], iosLocales: [] },
  services: { androidFirebase: 'disabled', iosFirebase: 'disabled' },
  projectChecks: { preflight: [], androidArtifact: [], iosArtifact: [] },
};
const assurance = { basis: 'schema-policy', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const invalidIssue = { code: 'config.invalid', status: 'INVALID', message: 'Inert format failure.', remediation: 'Review the draft.' };
const snapshot = (draft) => ({ root: '/inert/a', observedAt: '', observationScope: 'single-request-non-atomic',
  config: { path: 'release/mobile-release.json', state: 'format-valid', content: null, data: structuredClone(draft), issues: [] },
  discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
  assurance: { ...assurance, basis: 'static-text' }, issues: [] });
function observed(state, draft, requestId = 1) {
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId });
  return reduce(state, { type: 'snapshot-done', projectId: 'a', requestId, observedAt: requestId, snapshot: snapshot(draft) });
}
function loaded() { return observed(reduce(initialWorkspace, { type: 'select', project: project() }), original); }
function empty(draft = {}) {
  return reduce(reduce(initialWorkspace, { type: 'select', project: project() }), { type: 'new-draft', projectId: 'a', draft });
}
function result(draft, overrides = {}, { valid = false, partial = false, fields = help } = {}) {
  return { schemaVersion: 1, assurance,
    validation: { valid, state: valid ? 'format-valid' : 'invalid', issues: valid ? [] : [invalidIssue], requirements: [], assurance },
    comparison: { baseProvided: true, kind: 'compare', state: partial ? 'partial' : 'complete', semanticallyChanged: false,
      counts: { added: 0, changed: 0, removed: 0 }, changes: [], unreviewedCount: partial ? 1 : 0 },
    // Explicit inert core contexts, not an implementation of requiredness.
    fields: fields.map((field) => ({ path: field.path, state: 'optional', present: getValue(draft, field.path) !== undefined,
      reason: 'Inert core context; not native evidence.', ...overrides[field.path] })) };
}
function reviewed(state, preview = result(state.projects.a.draft), id = 2) {
  const session = state.projects.a;
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: { id, revision: session.revision, baselineGeneration: session.baselineGeneration } });
  return reduce(state, { type: 'review-done', projectId: 'a', requestId: id, result: preview });
}
const model = (state, fields = catalog, preview = false) => guidedConfiguration(fields, state.projects.a, state.selectedId, preview);
const paths = (layout) => layout.sections.flatMap((section) => section.fields.map((field) => field.path));
function unknown(layout, context = 'needs-review') {
  assert.equal(layout.context, context);
  assert.equal(layout.attentionCount, null, 'unknown is not zero missing settings');
  assert.equal(layout.format, null);
  assert.equal(layout.comparison, null);
  assert.equal(layout.contexts.size, 0);
  assert.ok(layout.sections.every((section) => section.attentionCount === null));
}

test('every actual catalogue field is present once, with its original help and stable path', () => {
  const state = loaded(), before = structuredClone({ state, catalog });
  const layout = model(state), all = paths(layout);
  assert.equal(help.length, 41);
  assert.deepEqual(layout.sections.map((section) => section.id), [...GUIDED_CONFIG_STAGES, 'advanced']);
  assert.equal(new Set(all).size, help.length);
  assert.deepEqual([...all].sort(), help.map((field) => field.path).sort());
  for (const field of help) assert.equal(layout.sections.find((section) => section.id === guidedConfigGroup(field.path)).fields.find((row) => row.path === field.path), field);
  for (const path of ['$schema', 'schemaVersion', 'projectChecks.preflight', 'ios.prepareCommand', 'ios.symbols.uploadCommand']) assert.equal(guidedConfigGroup(path), 'advanced');
  for (const path of ['metadata.root', 'metadata.androidLocales', 'metadata.iosLocales']) assert.equal(guidedConfigGroup(path), 'defaults');
  assert.deepEqual({ state, catalog }, before);
  unknown(layout);
});

test('future catalogue fields stay reachable in Advanced, never dropped or interpreted as policy', () => {
  const future = { ...help[0], path: 'future.setting', label: 'Future setting', requiredness: 'required' };
  const fields = { fields: [...help, future] }, state = loaded();
  let layout = model(state, fields);
  assert.equal(layout.sections.at(-1).fields.at(-1), future);
  unknown(layout);
  const withOldReview = reviewed(state);
  unknown(model(withOldReview, fields), 'needs-review'); // Old context does not cover a new catalogue.
  const current = reviewed(state, result(state.projects.a.draft, { 'future.setting': { state: 'required', present: false } }, { fields: fields.fields }));
  layout = model(current, fields);
  assert.equal(layout.attentionCount, 1);
  assert.equal(layout.attention[0].group, 'advanced');
  assert.equal(layout.attention[0].field, future);
  const duplicateCatalog = { fields: [...help, help[0]] };
  unknown(model(withOldReview, duplicateCatalog));
});

test('only a current core review supplies missing, conflict and unknown context', () => {
  const state = reviewed(empty(), result({}, {
    'android.applicationId': { state: 'required', present: false },
    'ios.workspace': { state: 'forbidden', present: true },
    'ios.identityStatus': { state: 'unknown', present: false },
    'ios.symbols.uploadCommand': { state: 'required', present: false },
  }));
  const layout = model(state);
  assert.equal(layout.context, 'current');
  assert.equal(layout.format, 'invalid');
  assert.deepEqual(layout.attention.map(({ field, kind, group }) => [field.path, kind, group]), [
    ['android.applicationId', 'missing', 'app'], ['ios.identityStatus', 'unknown', 'app'],
    ['ios.workspace', 'conflict', 'build'], ['ios.symbols.uploadCommand', 'missing', 'advanced'],
  ]);
  assert.equal(layout.attentionCount, 4);
  assert.equal(layout.sections.at(-1).attentionCount, 1, 'required Advanced fields are counted in the visible attention summary');
  assert.equal(state.projects.a.draft.ios, undefined, 'layout cannot insert or remove dependent values');
});

test('requiredness is never inferred from help prose or a later group label', () => {
  const state = loaded();
  const otherHelp = { fields: help.map((field) => ({ ...field, requiredness: 'optional', requiredWhen: 'Deliberately not executable policy.' })) };
  const current = reviewed(state, result(state.projects.a.draft, {
    'source.candidateBranch': { state: 'required', present: false },
    'services.androidFirebase': { state: 'required', present: false },
    'android.uploadCertificateSha256': { state: 'required', present: false },
    'ios.symbols.uploadCommand': { state: 'required', present: false },
  }));
  const layout = model(current, otherHelp);
  assert.equal(layout.attentionCount, 4);
  assert.equal(layout.sections.find((section) => section.id === 'defaults').attentionCount, 2);
  assert.equal(layout.sections.find((section) => section.id === 'delivery').attentionCount, 1);
  assert.equal(layout.sections.at(-1).attentionCount, 1);
});

test('stale-review-no-zero-attention: revision, baseline, selected project, pending and error all matter', () => {
  const state = reviewed(loaded()), session = state.projects.a;
  assert.equal(model(state).attentionCount, 0);
  for (const patch of [{ revision: session.revision + 1 }, { baselineGeneration: session.baselineGeneration + 1 },
    { reviewRequest: { id: 3, revision: session.revision, baselineGeneration: session.baselineGeneration } },
    { reviewError: { code: 'Unavailable', message: 'Fixed inert refusal.', retryable: false } }, { draft: null }]) {
    unknown(guidedConfiguration(catalog, { ...session, ...patch }, 'a'));
  }
  for (const selected of ['b', null]) unknown(guidedConfiguration(catalog, session, selected));
  unknown(model(state, catalog, true), 'example');
  const before = structuredClone(state);
  unknown(guidedConfiguration(catalog, session, 'b'));
  assert.deepEqual(state, before);
});

test('late original review cannot describe a newer draft or win a superseded request', () => {
  let state = loaded();
  const binding = { id: 2, revision: state.projects.a.revision, baselineGeneration: state.projects.a.baselineGeneration };
  state = reduce(state, { type: 'review-start', projectId: 'a', binding });
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.changed' });
  state = reduce(state, { type: 'review-done', projectId: 'a', requestId: 2, result: result(original) });
  unknown(model(state));
  const current = { id: 4, revision: state.projects.a.revision, baselineGeneration: state.projects.a.baselineGeneration };
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: current });
  const retained = state;
  state = reduce(state, { type: 'review-done', projectId: 'a', requestId: 3, result: result(original) });
  assert.equal(state, retained);
  unknown(model(state));
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.changed');
});

test('malformed or incomplete review data never becomes zero attention or field completion', () => {
  const state = reviewed(loaded()), originalReview = state.projects.a.review;
  const changes = [
    (r) => { r.binding = null; }, (r) => { delete r.binding.revision; }, (r) => { r.binding.id = -1; },
    (r) => { r.result = null; }, (r) => { r.result.schemaVersion = 2; }, (r) => { r.result.fields = []; },
    (r) => { r.result.fields.pop(); }, (r) => { r.result.fields[1] = r.result.fields[0]; },
    (r) => { r.result.fields[0].path = 'foreign.unknown'; }, (r) => { r.result.fields[0].state = 'ready'; },
    (r) => { r.result.fields[0].present = 'false'; }, (r) => { r.result.fields[0].reason = null; },
    (r) => { r.result.fields[0].reason = 'x'.repeat(4097); }, (r) => { r.result.fields[0].extra = true; },
    (r) => { r.result.assurance.writesPerformed = true; }, (r) => { r.result.assurance.releaseReadiness = 'ready'; },
    (r) => { delete r.result.validation; }, (r) => { r.result.validation.valid = 'true'; },
    (r) => { r.result.validation.issues = [null]; }, (r) => { r.result.validation.requirements = [{ state: 'ready' }]; },
    (r) => { r.result.comparison.state = 'partial'; }, (r) => { r.result.comparison.counts.changed = 1; },
    (r) => { r.result.comparison.changes = [{ path: 'android.enabled', operation: ['change'], before: { present: false }, after: { present: true, type: 'boolean' } }]; },
  ];
  for (const change of changes) {
    const review = structuredClone(originalReview); change(review);
    unknown(guidedConfiguration(catalog, { ...state.projects.a, review }, 'a'));
  }
});

test('presentation refuses response getters, inherited data and serialization hooks without running them', () => {
  const state = reviewed(loaded());
  let calls = 0;
  for (const makeUnsafe of [
    (review) => Object.defineProperty(review, 'binding', { enumerable: true, get() { calls++; return {}; } }),
    (review) => Object.defineProperty(review.result, 'fields', { enumerable: true, get() { calls++; return []; } }),
    (review) => { review.result.fields[0].toJSON = () => { calls++; return {}; }; },
    (review) => { review.result.fields[0] = Object.create(review.result.fields[0]); },
    (review) => { review.result.fields[0].reason = { toString() { calls++; return 'Not allowed'; } }; },
  ]) {
    const review = structuredClone(state.projects.a.review); makeUnsafe(review);
    unknown(guidedConfiguration(catalog, { ...state.projects.a, review }, 'a'));
  }
  assert.equal(calls, 0);
});

test('present-but-invalid values and partial comparisons remain issues, never setup or release readiness', () => {
  const state = empty({ version: { source: '' }, unsupported: { retain: 'inert text' } });
  const current = reviewed(state, result(state.projects.a.draft, { 'version.source': { state: 'required', present: true } }, { partial: true }));
  const layout = model(current);
  assert.equal(layout.context, 'current');
  assert.equal(layout.attentionCount, 0, 'presence count is not value validation');
  assert.equal(layout.format, 'invalid');
  assert.equal(layout.comparison, 'partial');
  for (const key of ['ready', 'completed', 'canSave', 'canBuild', 'canRelease', 'releaseReadiness', 'savedVersion']) assert.equal(Object.hasOwn(layout, key), false);
  assert.equal(current.projects.a.draft.version.source, '');
  assert.equal(current.projects.a.draft.unsupported.retain, 'inert text');
});

test('format-valid current field review still has no save, Store or build authority', () => {
  const state = loaded(), before = structuredClone(state);
  const layout = model(reviewed(state, result(state.projects.a.draft, {}, { valid: true })));
  assert.equal(layout.context, 'current');
  assert.equal(layout.format, 'format-valid');
  assert.equal(layout.attentionCount, 0);
  assert.deepEqual(state, before);
  assert.equal(state.projects.a.lastSave, null);
  assert.equal(state.projects.a.savedConfigContent, null, 'renderer fixture did not mint saved byte evidence');
  assert.ok(layout.sections.every((section) => !Object.hasOwn(section, 'complete')));
});

test('clean and dirty drafts retain their exact baseline through external observations and layout changes', () => {
  for (const dirty of [false, true]) {
    let state = loaded();
    if (dirty) state = reduce(state, { type: 'edit', projectId: 'a', path: 'version.nameKey', value: 'OTHER_VERSION_KEY' });
    state = reviewed(state);
    const retained = state.projects.a;
    state = observed(state, { ...original, android: { ...original.android, applicationId: 'com.example.elsewhere' } }, 7);
    for (const group of GUIDED_CONFIG_STAGES) {
      assert.equal(guidedConfigSelectStage('app', group, null), group);
      assert.equal(model(state).context, 'current', 'pure draft review still describes its retained JSON baseline, not disk');
    }
    assert.equal(state.projects.a.draft, retained.draft);
    assert.equal(state.projects.a.baseline, retained.baseline);
    assert.equal(state.projects.a.sourceChanged, true);
    assert.equal(isDirty(state.projects.a), dirty);
    assert.equal(state.projects.a.snapshot.config.data.android.applicationId, 'com.example.elsewhere');
  }
});

test('disabled platforms, invalid values and blocked parents stay present for the existing repair controls', () => {
  for (const draft of [
    { ios: { enabled: false, bundleId: 'com.example.retained', symbols: { uploadCommand: ['not-executed'] } } },
    { ios: { enabled: null, symbols: false }, android: { applicationId: [] }, unsupported: 'retained' },
    { ios: 'blocked parent', source: { candidateBranch: '' }, projectChecks: { preflight: [['not-executed']] } },
  ]) {
    const state = empty(draft), before = structuredClone(state), layout = model(state);
    assert.ok(paths(layout).includes('ios.bundleId'));
    assert.ok(paths(layout).includes('ios.symbols.uploadCommand'));
    assert.ok(paths(layout).includes('android.applicationId'));
    assert.ok(paths(layout).includes('projectChecks.preflight'));
    for (const group of GUIDED_CONFIG_STAGES) guidedConfigSelectStage('app', group, null);
    for (const section of layout.sections) for (const field of section.fields) guidedConfigFieldMatches(field, 'no matches', null);
    assert.deepEqual(state, before);
    if (draft.ios === 'blocked parent') assert.equal(blockingAncestor(state.projects.a.draft, 'ios.bundleId'), 'ios');
    if (draft.ios?.symbols === false) assert.equal(blockingAncestor(state.projects.a.draft, 'ios.symbols.uploadCommand'), 'ios.symbols');
  }
});

test('search includes labels, paths and help across every group without changing the mounted field list', () => {
  const layout = model(loaded()), retained = paths(layout);
  for (const field of help) {
    assert.equal(guidedConfigFieldMatches(field, `  ${field.path.toUpperCase()}  `, null), true);
    assert.equal(guidedConfigFieldMatches(field, field.label, null), true);
    assert.equal(guidedConfigFieldMatches(field, field.what, null), true);
    assert.equal(guidedConfigFieldMatches(field, 'not a matching setting', null), false);
  }
  assert.deepEqual(paths(layout), retained);
  assert.ok(layout.sections.at(-1).fields.some((field) => guidedConfigFieldMatches(field, 'Reserved symbol uploader', null)));
});

test('pending-picker-stage-switch-no-state-loss: original binding, visible field and eventual one-field edit survive', () => {
  let state = loaded();
  const generation = {}, picker = beginProjectPath(initialProjectPathState, state, 'version.source', generation);
  const binding = picker.pending, retained = state.projects.a, layout = model(state), mounted = paths(layout);
  assert.ok(binding);
  assert.equal(guidedConfigVisibleStage('app', binding.field), 'build');
  for (const requested of GUIDED_CONFIG_STAGES) assert.equal(guidedConfigSelectStage('build', requested, binding.field), 'build');
  const field = help.find((field) => field.path === binding.field);
  assert.equal(guidedConfigFieldMatches(field, 'a nonmatching search', binding.field), true);
  assert.deepEqual(paths(model(state)), mounted);
  assert.equal(picker.pending, binding);
  assert.equal(picker.eligible, binding);
  assert.notEqual(projectPathOwnerReason(picker), null);
  assert.equal(state.projects.a.draft, retained.draft);
  const finished = finishProjectPath(picker, binding, state, generation, { reply: { projectId: 'a', field: binding.field, relativePath: 'release/other.properties' } });
  assert.deepEqual(finished.edit, { field: 'version.source', value: 'release/other.properties' });
  state = reduce(state, { type: 'edit', projectId: 'a', path: finished.edit.field, value: finished.edit.value });
  assert.equal(state.projects.a.baseline, retained.baseline);
  assert.equal(state.projects.a.draft.version.source, 'release/other.properties');
  assert.equal(state.projects.a.draft.version.nameKey, retained.draft.version.nameKey);
  assert.equal(state.projects.a.draft.android, retained.draft.android);
  assert.equal(guidedConfigSelectStage('build', 'delivery', null), 'delivery');
});

test('layout never settles or clears the original cancelled or unknown picker outcome', () => {
  const state = loaded(), generation = {};
  for (const outcome of [{ reply: null }, { error: { code: 'project_path_cleanup_unknown' } }]) {
    const picker = beginProjectPath(initialProjectPathState, state, 'metadata.root', generation), binding = picker.pending;
    assert.equal(guidedConfigVisibleStage('delivery', binding.field), 'defaults');
    const finished = finishProjectPath(picker, binding, state, generation, outcome);
    assert.equal(finished.edit, null);
    for (const group of GUIDED_CONFIG_STAGES) guidedConfigSelectStage('defaults', group, null);
    model(state);
    if ('error' in outcome) {
      assert.equal(finished.state.unverified, binding);
      assert.notEqual(projectPathOwnerReason(finished.state), null);
    } else assert.equal(finished.state.unverified, null);
    assert.equal(state.projects.a.draft.metadata.root, original.metadata.root);
    assert.equal(isDirty(state.projects.a), false);
  }
});
