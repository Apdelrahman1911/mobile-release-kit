// Pure renderer helpers/reducer only. The result objects below are inert service
// DTO fixtures, not policy implementations or evidence of core/native execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { blockingAncestor, getValue, sameJson, setValue } from '../src/catalog.ts';
import { canUndoRemoval, initialWorkspace, isDirty, reviewFresh, suggestionFresh, validationFresh, workspaceReducer as reduce } from '../src/drafts.ts';
import { methodReason } from '../src/certainty.ts';
import { pathsOverlap, suggestionHints, valueSummary } from '../src/preparation.ts';

const assurance = {
  basis: 'schema-policy', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false,
  writesPerformed: false, releaseReadiness: 'unknown',
};
const validation = { valid: false, state: 'invalid', issues: [], requirements: [], assurance };
const preview = {
  schemaVersion: 1, validation, assurance,
  comparison: {
    baseProvided: true, kind: 'compare', state: 'complete', semanticallyChanged: true,
    counts: { added: 0, changed: 1, removed: 0 },
    changes: [{ path: 'android.enabled', operation: 'change', before: { present: true, type: 'boolean' }, after: { present: true, type: 'boolean' } }],
    unreviewedCount: 0,
  },
  fields: [{ path: 'android.applicationId', state: 'forbidden', present: true, reason: 'Inert core context fixture.' }],
};
const suggestion = {
  schemaVersion: 1, draft: { schemaVersion: 1, android: { enabled: false }, ios: { enabled: false } },
  platformSelectionRequired: true, provenance: [{ path: 'android.enabled', source: 'default', reason: 'No platform supplied.' }],
  validation, assurance,
};
const original = { android: { enabled: true, applicationId: 'com.example.inert' }, source: { candidateBranch: 'main' }, unsupported: { retained: 'inert text' } };
const project = (id) => ({ id, name: `Inert ${id}`, path: `/inert/${id}` });
const snapshot = (data) => ({
  root: '/inert/no-file-read', observedAt: '', observationScope: 'single-request-non-atomic',
  config: { content: null, path: 'release/mobile-release.json', state: data === null ? 'missing' : 'format-valid', data, issues: [] },
  discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
  assurance: { ...assurance, basis: 'static-text' }, issues: [],
});

function selected(id = 'a') {
  return reduce(initialWorkspace, { type: 'select', project: project(id) });
}

function observed(state, data, requestId = 1, id = 'a') {
  state = reduce(state, { type: 'snapshot-start', projectId: id, requestId });
  return reduce(state, { type: 'snapshot-done', projectId: id, requestId, snapshot: snapshot(structuredClone(data)), observedAt: requestId });
}

function loaded(data = original) {
  return observed(selected(), data);
}

function binding(state, id = 2, projectId = 'a') {
  const session = state.projects[projectId];
  return { id, revision: session.revision, baselineGeneration: session.baselineGeneration };
}

function review(state, result = preview, id = 2) {
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: binding(state, id) });
  return reduce(state, { type: 'review-done', projectId: 'a', requestId: id, result });
}

function suggestionBinding(state, id = 2, projectId = 'a') {
  return { ...binding(state, id, projectId), observationGeneration: state.projects[projectId].observationGeneration, observedHints: false, partial: false, omittedStrings: 0 };
}

test('semantic draft equality ignores object key order but retains arrays, types and presence', () => {
  assert.equal(sameJson({ b: [false, null, ''], a: { y: [], x: 1 } }, { a: { x: 1, y: [] }, b: [false, null, ''] }), true);
  assert.equal(sameJson([1, 2], [2, 1]), false);
  for (const [first, second] of [[false, 0], [null, undefined], ['', undefined], [[], undefined], [{}, []], [{ x: null }, {}], [{ x: false }, {}], [1, '1']]) {
    assert.equal(sameJson(first, second), false);
  }
  assert.equal(sameJson({}, Object.create({ inherited: true })), true);
  assert.equal(sameJson(JSON.parse('{"__proto__":{"example":true}}'), {}), false);
});

test('nested controls cannot coerce, erase or overwrite malformed ancestor data', () => {
  for (const value of [false, null, 4, 'inert', [], ['inert']]) {
    const draft = { ios: { symbols: value }, extra: 'preserve' };
    assert.equal(blockingAncestor(draft, 'ios.symbols.uploadCommand'), 'ios.symbols');
    assert.equal(setValue(draft, 'ios.symbols.uploadCommand', ['not-executed']), draft);
    assert.equal(setValue(draft, 'ios.symbols.uploadCommand', undefined), draft);
  }
  const empty = {};
  assert.equal(setValue(empty, 'ios.symbols.uploadCommand', undefined), empty);
  assert.deepEqual(setValue(empty, 'ios.symbols.uploadCommand', []), { ios: { symbols: { uploadCommand: [] } } });
});

test('static hint projection is closed and never invents a platform or chooses a candidate', () => {
  assert.deepEqual(suggestionHints(null), { hints: {}, omittedStrings: 0 });
  for (const hints of [{}, { android: {}, ios: {} }, { android: false, ios: [] }, { platforms: ['android'], androidApplicationId: 'ignored' }]) {
    assert.deepEqual(suggestionHints(hints), { hints: {}, omittedStrings: 0 });
  }
  const observedHints = {
    root: '/never-forward', git: { branch: 'never-forward' },
    android: { ambiguous: true, applicationId: 'never-select', candidates: [{ applicationId: 'never-select' }], namespace: 'never-select' },
    ios: { bundleId: 'com.example.ios', bundleIds: ['never-select'], project: '/never-forward' },
    versionSource: 'release/version.properties', versionNameKey: 'VERSION_NAME', versionBuildKey: 'BUILD_NUMBER', versionName: 'never-forward',
  };
  assert.deepEqual(suggestionHints(observedHints), {
    hints: { platforms: ['android', 'ios'], iosBundleId: 'com.example.ios', versionSource: 'release/version.properties', versionNameKey: 'VERSION_NAME', versionBuildKey: 'BUILD_NUMBER' },
    omittedStrings: 0,
  });
  assert.deepEqual(suggestionHints({ versionNameKey: 'VERSION_NAME' }).hints, { versionNameKey: 'VERSION_NAME' });
});

test('oversized or malformed hint strings are omitted whole, never truncated', () => {
  const projected = suggestionHints({
    android: { applicationId: 'a'.repeat(513) }, ios: { bundleId: 'inert\u0000value' },
    versionSource: 'é'.repeat(257), versionNameKey: '', versionBuildKey: ['NOT_A_STRING'],
  });
  assert.deepEqual(projected, { hints: { platforms: ['android', 'ios'] }, omittedStrings: 5 });
  assert.equal(suggestionHints({ versionSource: 'é'.repeat(256) }).hints.versionSource.length, 256);
  assert.deepEqual(suggestionHints({ versionSource: 'inert\u007fvalue', versionNameKey: '\ud800' }), { hints: {}, omittedStrings: 2 });
  // The transport projection follows ASCII controls/DEL, not a new C1 policy;
  // the core validator, rather than the projection, judges field validity.
  assert.equal(suggestionHints({ versionSource: 'inert\u0085value' }).hints.versionSource, 'inert\u0085value');
  const inherited = Object.assign(Object.create({ applicationId: 'must-not-copy' }), { module: ':inert' });
  assert.deepEqual(suggestionHints({ android: inherited }).hints, { platforms: ['android'] });
});

test('review summary text contains only declared presence, types and collection counts', () => {
  assert.equal(valueSummary({ present: false }), 'Not set');
  assert.equal(valueSummary({ present: true, type: 'null' }), 'null');
  assert.equal(valueSummary({ present: true, type: 'array', count: 0 }), 'Array · 0 items');
  assert.equal(valueSummary({ present: true, type: 'object', count: 2 }), 'Object · 2 keys');
  assert.equal(valueSummary({ present: true, type: 'string', count: 999, value: 'do-not-display' }), 'String · value omitted');
  assert.equal(valueSummary({ present: true, type: 'boolean', value: false }), 'Boolean · value omitted');
  assert.equal(pathsOverlap('ios.symbols', 'ios.symbols.uploadCommand'), true);
  assert.equal(pathsOverlap('ios.project', 'ios.projectOther'), false);
});

test('pure preparation capabilities work independently of unavailable Windows project reads', () => {
  const info = { runtime: { state: 'available', reason: null, mode: 'development' }, capabilities: { hostPlatform: 'windows', methods: [
    { method: 'config.preview', available: true, reason: 'Pure only' },
    { method: 'config.suggest', available: true, reason: 'Pure only' },
    { method: 'project.snapshot', available: false, reason: 'Not qualified' },
  ] } };
  assert.equal(methodReason(info, 'config.preview', 'native'), null);
  assert.equal(methodReason(info, 'config.suggest', 'native'), null);
  assert.notEqual(methodReason(info, 'project.snapshot', 'native'), null);
  assert.notEqual(methodReason(info, 'config.preview', 'preview'), null);
  assert.notEqual(methodReason(info, 'config.suggest', 'unavailable'), null);
  assert.notEqual(methodReason(info, 'config.save', 'native'), null);
});

test('an existing clean draft and its original baseline survive refreshed observations', () => {
  let state = review(loaded());
  const old = state.projects.a;
  state = observed(state, { ...original, source: { candidateBranch: 'new-observation' } }, 3);
  assert.equal(state.projects.a.draft, old.draft);
  assert.equal(state.projects.a.baseline, old.baseline);
  assert.equal(state.projects.a.baselineGeneration, old.baselineGeneration);
  assert.equal(state.projects.a.revision, old.revision);
  assert.equal(state.projects.a.sourceChanged, true);
  assert.equal(isDirty(state.projects.a), false);
  assert.equal(reviewFresh(state.projects.a), true); // still compares the retained JSON baseline
  assert.equal(state.projects.a.snapshot.config.data.source.candidateBranch, 'new-observation');
  state = reduce(state, { type: 'reset', projectId: 'a' });
  assert.equal(state.projects.a.draft.source.candidateBranch, 'new-observation');
  assert.equal(state.projects.a.baselineGeneration, old.baselineGeneration + 1);
  assert.equal(state.projects.a.review, null);
});

test('key reordering is a renderer no-op, not an unsaved edit or disk-byte assertion', () => {
  let state = loaded({ android: { enabled: true, applicationId: 'inert' } });
  const old = state;
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android', value: { applicationId: 'inert', enabled: true } });
  assert.equal(state, old);
  assert.equal(isDirty(state.projects.a), false);
});

test('review replies belong to their request, project, draft revision and baseline generation', () => {
  let state = loaded();
  const oldBinding = binding(state, 2);
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: oldBinding });
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'source.candidateBranch', value: 'new-draft' });
  state = reduce(state, { type: 'select', project: project('b') });
  state = reduce(state, { type: 'review-done', projectId: 'a', requestId: 2, result: preview });
  assert.equal(state.selectedId, 'b');
  assert.equal(state.projects.b.review, null);
  assert.equal(reviewFresh(state.projects.a), false);
  assert.equal(state.projects.a.draft.source.candidateBranch, 'new-draft');
  const before = state;
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: { ...binding(state, 3), baselineGeneration: oldBinding.baselineGeneration - 1 } });
  assert.equal(state, before);
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: binding(state, 4) });
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: binding(state, 5) });
  const afterNewerRequest = state;
  state = reduce(state, { type: 'review-done', projectId: 'a', requestId: 4, result: preview });
  assert.equal(state, afterNewerRequest);
  state = reduce(state, { type: 'review-done', projectId: 'a', requestId: 5, result: preview });
  assert.equal(reviewFresh(state.projects.a), true);
});

test('discarding a baseline prevents outstanding validation/review replies from repopulating it', () => {
  let state = loaded();
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: binding(state, 2) });
  state = reduce(state, { type: 'validate-start', projectId: 'a', requestId: 3, revision: state.projects.a.revision, baselineGeneration: state.projects.a.baselineGeneration });
  state = reduce(state, { type: 'reset', projectId: 'a' });
  const reset = state;
  state = reduce(state, { type: 'review-done', projectId: 'a', requestId: 2, result: preview });
  state = reduce(state, { type: 'validate-done', projectId: 'a', requestId: 3, result: validation });
  assert.equal(state, reset);
  assert.equal(reviewFresh(state.projects.a), false);
  assert.equal(validationFresh(state.projects.a), false);
});

test('a suggestion is separate until an explicit current-project adoption, with no create authority', () => {
  let state = selected();
  state = reduce(state, { type: 'suggest-start', projectId: 'a', binding: suggestionBinding(state) });
  state = reduce(state, { type: 'select', project: project('b') });
  state = reduce(state, { type: 'suggest-done', projectId: 'a', requestId: 2, result: suggestion });
  assert.equal(state.selectedId, 'b');
  assert.equal(state.projects.a.draft, null);
  assert.equal(state.projects.b.suggestion, null);
  assert.equal(suggestionFresh(state.projects.a), true);
  const before = state;
  assert.equal(reduce(state, { type: 'adopt-suggestion', projectId: 'b', requestId: 2 }), before);
  state = reduce(state, { type: 'adopt-suggestion', projectId: 'a', requestId: 2 });
  assert.equal(state.projects.a.baseline, null);
  assert.equal(state.projects.a.draftOrigin, 'suggestion');
  assert.equal(state.projects.a.draft.android.enabled, false);
  assert.equal(state.projects.a.draft.ios.enabled, false);
  assert.equal(isDirty(state.projects.a), true);
  assert.equal('saveToken' in state.projects.a, false);
  assert.equal(state.projects.a.snapshot, null);
});

test('changed observations or user-started drafts prevent late suggestion adoption', () => {
  let state = loaded(null);
  state = reduce(state, { type: 'suggest-start', projectId: 'a', binding: suggestionBinding(state) });
  state = observed(state, null, 3);
  state = reduce(state, { type: 'suggest-done', projectId: 'a', requestId: 2, result: suggestion });
  assert.equal(suggestionFresh(state.projects.a), false);
  const unchanged = state;
  assert.equal(reduce(state, { type: 'adopt-suggestion', projectId: 'a', requestId: 2 }), unchanged);
  state = reduce(state, { type: 'suggest-start', projectId: 'a', binding: suggestionBinding(state, 4) });
  state = reduce(state, { type: 'new-draft', projectId: 'a', draft: { schemaVersion: 1, retained: 'user choice' } });
  state = reduce(state, { type: 'suggest-done', projectId: 'a', requestId: 4, result: suggestion });
  state = reduce(state, { type: 'adopt-suggestion', projectId: 'a', requestId: 4 });
  assert.equal(state.projects.a.draft.retained, 'user choice');
  assert.equal(suggestionFresh(state.projects.a), false);
});

test('a pending refresh disables adoption even before a replacement observation arrives', () => {
  let state = loaded(null);
  state = reduce(state, { type: 'suggest-start', projectId: 'a', binding: suggestionBinding(state) });
  state = reduce(state, { type: 'suggest-done', projectId: 'a', requestId: 2, result: suggestion });
  assert.equal(suggestionFresh(state.projects.a), true);
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId: 3 });
  assert.equal(suggestionFresh(state.projects.a), false);
  assert.equal(reduce(state, { type: 'adopt-suggestion', projectId: 'a', requestId: 2 }), state);
});

test('controllers and core conflict results never automatically delete dependent or unsupported data', () => {
  let state = loaded();
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.enabled', value: false });
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.inert');
  state = review(state);
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.inert');
  assert.deepEqual(state.projects.a.draft.unsupported, original.unsupported);
  const before = state;
  assert.equal(reduce(state, { type: 'remove-forbidden', projectId: 'a', reviewId: 2, paths: ['unsupported'] }), before);
  state = reduce(state, { type: 'remove-forbidden', projectId: 'a', reviewId: 2, paths: ['android.applicationId'] });
  assert.equal(getValue(state.projects.a.draft, 'android.applicationId'), undefined);
  assert.equal(state.projects.a.removedFields[0].value, 'com.example.inert');
  assert.deepEqual(state.projects.a.draft.unsupported, original.unsupported);
  assert.equal(reviewFresh(state.projects.a), false);
});

test('explicit batch removals remain undoable independently and retain unrelated later edits', () => {
  let state = loaded({ ...original, ios: { enabled: false, project: 'inert.xcodeproj', workspace: 'inert.xcworkspace' } });
  const result = { ...preview, fields: [
    { path: 'ios.project', state: 'forbidden', present: true, reason: 'Inert fixture' },
    { path: 'ios.workspace', state: 'forbidden', present: true, reason: 'Inert fixture' },
  ] };
  state = review(state, result);
  state = reduce(state, { type: 'remove-forbidden', projectId: 'a', reviewId: 2, paths: ['ios.project', 'ios.workspace'] });
  assert.equal(state.projects.a.removedFields.length, 2);
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'source.candidateBranch', value: 'keep-this-edit' });
  const first = state.projects.a.removedFields[0];
  state = reduce(state, { type: 'undo-removal', projectId: 'a', removalId: first.id });
  assert.equal(state.projects.a.draft.ios.project, 'inert.xcodeproj');
  assert.equal(state.projects.a.draft.ios.workspace, undefined);
  assert.equal(state.projects.a.draft.source.candidateBranch, 'keep-this-edit');
  assert.equal(state.projects.a.removedFields.length, 1);
  assert.equal(canUndoRemoval(state.projects.a, state.projects.a.removedFields[0]), true);
});

test('stale context cannot drive dependent removal and failed queries leave drafts intact', () => {
  let state = review(loaded());
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.enabled', value: false });
  const before = state;
  assert.equal(reduce(state, { type: 'remove-forbidden', projectId: 'a', reviewId: 2, paths: ['android.applicationId'] }), before);
  state = reduce(state, { type: 'review-start', projectId: 'a', binding: binding(state, 3) });
  state = reduce(state, { type: 'review-failed', projectId: 'a', requestId: 3, error: { code: 'InertRefusal', message: 'No review prepared.', retryable: false } });
  assert.equal(state.projects.a.draft, before.projects.a.draft);
  assert.equal(state.projects.a.review.result, preview);
  assert.equal(state.projects.a.reviewError.code, 'InertRefusal');
});

test('unset distinguishes null, false, empty text, empty lists and empty objects, all with undo', () => {
  for (const value of [null, false, '', [], {}]) {
    let state = loaded({ android: { enabled: true }, field: value });
    state = reduce(state, { type: 'edit', projectId: 'a', path: 'field', value: undefined });
    assert.equal(Object.hasOwn(state.projects.a.draft, 'field'), false);
    assert.deepEqual(state.projects.a.removedFields[0].value, value);
    state = reduce(state, { type: 'undo-removal', projectId: 'a', removalId: state.projects.a.removedFields[0].id });
    assert.equal(Object.hasOwn(state.projects.a.draft, 'field'), true);
    assert.deepEqual(state.projects.a.draft.field, value);
    assert.equal(isDirty(state.projects.a), false);
  }
});

test('undo never overwrites a later same-field choice, even if that choice is later unset', () => {
  let state = loaded();
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: undefined });
  const oldRemoval = state.projects.a.removedFields[0];
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'new-choice' });
  assert.equal(canUndoRemoval(state.projects.a, state.projects.a.removedFields[0]), false);
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: undefined });
  const beforeUndo = state.projects.a.draft;
  state = reduce(state, { type: 'undo-removal', projectId: 'a', removalId: oldRemoval.id });
  assert.equal(state.projects.a.draft, beforeUndo);
  assert.equal(state.projects.a.removedFields.length, 2);
  assert.equal(state.projects.a.removedFields[0].value, oldRemoval.value);
  state = reduce(state, { type: 'forget-removal', projectId: 'a', removalId: oldRemoval.id });
  assert.equal(state.projects.a.removedFields.length, 1);
  assert.equal(state.projects.a.removedFields[0].value, 'new-choice');
});

test('undo cannot replace a malformed parent and project switches retain copies separately', () => {
  let state = loaded({ ios: { symbols: { policy: 'required', uploadCommand: ['inert', 'not executed'] } } });
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'ios.symbols.uploadCommand', value: undefined });
  const id = state.projects.a.removedFields[0].id;
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'ios.symbols', value: null });
  state = reduce(state, { type: 'select', project: project('b') });
  assert.equal(state.projects.b.removedFields.length, 0);
  state = reduce(state, { type: 'undo-removal', projectId: 'a', removalId: id });
  assert.equal(state.projects.a.draft.ios.symbols, null);
  assert.equal(state.projects.a.removedFields.length, 1);
  assert.equal(state.projects.a.editError.code, 'DraftUnchanged');
  state = reduce(state, { type: 'reset', projectId: 'a' });
  assert.equal(state.projects.a.removedFields.length, 0);
  assert.equal(state.selectedId, 'b');
});

test('undo capacity refuses additional removal instead of silently evicting earlier values', () => {
  let state = loaded(Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`field${index}`, index])));
  for (let index = 0; index < 64; index += 1) state = reduce(state, { type: 'edit', projectId: 'a', path: `field${index}`, value: undefined });
  const revision = state.projects.a.revision;
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'field64', value: undefined });
  assert.equal(state.projects.a.removedFields.length, 64);
  assert.equal(state.projects.a.draft.field64, 64);
  assert.equal(state.projects.a.revision, revision);
  assert.equal(state.projects.a.editError.code, 'DraftUnchanged');
  state = reduce(state, { type: 'forget-removal', projectId: 'a', removalId: state.projects.a.removedFields[0].id });
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'field64', value: undefined });
  assert.equal(state.projects.a.removedFields.length, 64);
  assert.equal(state.projects.a.draft.field64, undefined);
});
