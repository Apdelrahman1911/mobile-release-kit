// Inert UI state checks only. No DOM, filesystem fixtures, network, or child tools.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, isDirty, retainedEditAttention, validationFresh, workspaceReducer as reduce } from '../src/drafts.ts';
import { configurationStatus, draftStatus } from '../src/certainty.ts';

const project = (id) => ({ id, name: `Inert ${id}`, path: `/inert/${id}` });
const assurance = {
  basis: 'static-text', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false,
  writesPerformed: false, releaseReadiness: 'unknown',
};
const snapshot = (id, name = 'com.example.original') => ({
  root: `/inert/${id}`, observedAt: '2026-09-17T00:00:00Z', observationScope: 'single-request-non-atomic',
  config: { content: null, path: 'mobile-release.json', state: 'format-valid', data: { android: { enabled: true, applicationId: name } }, issues: [] },
  discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 1, sourceFiles: 1, sourceBytes: 50, excludedEntries: 0 }, limits: {} },
  assurance, issues: [],
});
const validation = { valid: true, state: 'format-valid', issues: [], requirements: [], assurance: { ...assurance, basis: 'schema-policy' } };

test('retained edit attention lists earlier projects and every edit domain without owner details', () => {
  const projects = { a: { project: project('a'), draft: { private: 'never project this' } }, b: { project: project('b') } };
  const config = [{ projectId: 'a', sessionId: 'private-session', coreOutcome: { journal: 'recovery_required' } }];
  const workflow = [{ projectId: 'b', prepared: { planToken: 'private-plan' } }];
  // The selector intentionally has no lastTerminal input: these earlier alerts
  // survive its replacement without adopting a different operation's result.
  const metadata = ['a'];
  const before = structuredClone({ projects, config, workflow, metadata });
  const rows = retainedEditAttention(projects, config, workflow, metadata);
  assert.deepEqual(rows, [
    { projectId: 'a', projectName: 'Inert a', domain: 'Project settings', page: 'settings' },
    { projectId: 'b', projectName: 'Inert b', domain: 'GitHub workflow files', page: 'github' },
    { projectId: 'a', projectName: 'Inert a', domain: 'Public Store text', page: 'metadata' },
  ]);
  assert.deepEqual({ projects, config, workflow, metadata }, before);
  assert.equal(JSON.stringify(rows).includes('private'), false);
  assert.equal(Object.hasOwn(rows[2], 'locale'), false);
  assert.equal(Object.hasOwn(rows[2], 'coreOutcome'), false);
});

test('retained edit attention keeps unloaded, inherited and mismatched projects without navigation names', () => {
  const projects = Object.create({ inherited: { project: project('inherited') } });
  projects.mismatch = { project: project('different') };
  const rows = retainedEditAttention(projects, [{ projectId: 'missing' }, { projectId: 'inherited' }], [{ projectId: 'mismatch' }], ['missing']);
  assert.equal(rows.length, 4);
  assert.ok(rows.every((row) => row.projectName === null));
  assert.deepEqual(rows.map((row) => row.projectId), ['missing', 'inherited', 'mismatch', 'missing']);
});

test('retained edit attention returns only observations, never a clean-state or recovery decision', () => {
  assert.deepEqual(retainedEditAttention({}, [], [], []), []);
  const rows = retainedEditAttention({}, [], [], ['unloaded']);
  assert.deepEqual(Object.keys(rows[0]).sort(), ['domain', 'page', 'projectId', 'projectName']);
  assert.equal(Object.hasOwn(rows[0], 'canRetry'), false);
  assert.equal(Object.hasOwn(rows[0], 'recovered'), false);
});

function loaded(id = 'a') {
  let state = reduce(initialWorkspace, { type: 'select', project: project(id) });
  state = reduce(state, { type: 'snapshot-start', projectId: id, requestId: 1 });
  return reduce(state, { type: 'snapshot-done', projectId: id, requestId: 1, snapshot: snapshot(id), observedAt: 1 });
}

test('project switch and late snapshot keep each project’s unsaved draft isolated', () => {
  let state = loaded();
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.edited' });
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId: 2 });
  state = reduce(state, { type: 'select', project: project('b') });
  state = reduce(state, { type: 'snapshot-start', projectId: 'b', requestId: 3 });
  state = reduce(state, { type: 'snapshot-done', projectId: 'b', requestId: 3, snapshot: snapshot('b', 'com.example.other'), observedAt: 3 });
  state = reduce(state, { type: 'snapshot-done', projectId: 'a', requestId: 2, snapshot: snapshot('a', 'com.example.changed-on-disk'), observedAt: 2 });
  assert.equal(state.selectedId, 'b');
  assert.equal(state.projects.b.draft.android.applicationId, 'com.example.other');
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.edited');
  assert.equal(state.projects.a.sourceChanged, true);
  assert.equal(isDirty(state.projects.a), true);
  state = reduce(state, { type: 'switch', projectId: 'a' });
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.edited');
});

test('a superseded snapshot cannot replace a newer observation or draft', () => {
  let state = loaded();
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId: 2 });
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId: 3 });
  const unchanged = reduce(state, { type: 'snapshot-done', projectId: 'a', requestId: 2, snapshot: snapshot('a', 'com.example.stale'), observedAt: 2 });
  assert.equal(unchanged, state);
  state = reduce(state, { type: 'snapshot-done', projectId: 'a', requestId: 3, snapshot: snapshot('a', 'com.example.newer'), observedAt: 3 });
  assert.equal(state.projects.a.snapshot.config.data.android.applicationId, 'com.example.newer');
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.original');
  assert.equal(state.projects.a.baseline.android.applicationId, 'com.example.original');
  assert.equal(state.projects.a.sourceChanged, true);
});

test('validation settling after an edit is visibly stale, never for the new draft', () => {
  let state = loaded();
  const revision = state.projects.a.revision;
  state = reduce(state, { type: 'validate-start', projectId: 'a', requestId: 2, revision, baselineGeneration: state.projects.a.baselineGeneration });
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'changed' });
  state = reduce(state, { type: 'validate-done', projectId: 'a', requestId: 2, result: validation });
  assert.equal(validationFresh(state.projects.a), false);
  assert.deepEqual(draftStatus(state.projects.a), { label: 'Validation is stale', tone: 'warning' });
  assert.equal(isDirty(state.projects.a), true);
});

test('a validation response stays with its project; old responses cannot win a race', () => {
  let state = loaded();
  const revision = state.projects.a.revision;
  state = reduce(state, { type: 'validate-start', projectId: 'a', requestId: 2, revision, baselineGeneration: state.projects.a.baselineGeneration });
  state = reduce(state, { type: 'validate-start', projectId: 'a', requestId: 3, revision, baselineGeneration: state.projects.a.baselineGeneration });
  state = reduce(state, { type: 'select', project: project('b') });
  state = reduce(state, { type: 'validate-done', projectId: 'a', requestId: 2, result: validation });
  assert.equal(state.projects.a.validation, null);
  state = reduce(state, { type: 'validate-done', projectId: 'a', requestId: 3, result: validation });
  assert.equal(state.selectedId, 'b');
  assert.equal(state.projects.b.validation, null);
  assert.equal(validationFresh(state.projects.a), true);
});

test('failed refresh preserves edits and labels the previous observation stale', () => {
  let state = loaded();
  state = reduce(state, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.edited' });
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId: 2 });
  state = reduce(state, { type: 'snapshot-failed', projectId: 'a', requestId: 2, error: { code: 'Busy', message: 'Read-only engine is busy.', retryable: false } });
  assert.equal(state.projects.a.draft.android.applicationId, 'com.example.edited');
  assert.equal(configurationStatus(state.projects.a, false).label, 'Stale observation');
});

test('missing configuration does not silently synthesize a draft; reset affects only one project', () => {
  let state = loaded('b');
  state = reduce(state, { type: 'select', project: project('a') });
  const missing = snapshot('a');
  missing.config = { path: 'mobile-release.json', state: 'missing', data: null, issues: [] };
  state = reduce(state, { type: 'snapshot-start', projectId: 'a', requestId: 2 });
  state = reduce(state, { type: 'snapshot-done', projectId: 'a', requestId: 2, snapshot: missing, observedAt: 2 });
  assert.equal(state.projects.a.draft, null);
  state = reduce(state, { type: 'new-draft', projectId: 'a', draft: { schemaVersion: 1 } });
  assert.equal(isDirty(state.projects.a), true);
  state = reduce(state, { type: 'reset', projectId: 'a' });
  assert.equal(state.projects.a.draft, null);
  assert.equal(state.projects.b.draft.android.applicationId, 'com.example.original');
});

test('format-valid is informational only; preview never claims a real observation', () => {
  let state = loaded();
  assert.deepEqual(configurationStatus(state.projects.a, false), { label: 'Format-valid only', tone: 'info' });
  assert.deepEqual(configurationStatus(state.projects.a, true), { label: 'Example only', tone: 'warning' });
  state = reduce(state, { type: 'validate-start', projectId: 'a', requestId: 2, revision: state.projects.a.revision, baselineGeneration: state.projects.a.baselineGeneration });
  state = reduce(state, { type: 'validate-done', projectId: 'a', requestId: 2, result: validation });
  assert.deepEqual(draftStatus(state.projects.a), { label: 'Format-valid · not saved', tone: 'info' });
  assert.equal(state.projects.a.validation.assurance.releaseReadiness, 'unknown');
});
