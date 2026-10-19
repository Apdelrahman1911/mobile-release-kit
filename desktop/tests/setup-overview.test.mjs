// Pure presentation fixtures only. No native runtime, files, DOM, tools,
// accounts, timers, credentials, network or build/release operation is used.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialConfigEdit } from '../src/configEdit.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { initialProjectInitialization } from '../src/projectInitialization.ts';
import { setupOverview, savedVersionForSetup, setupActivitySummary, setupDisclosureOpen } from '../src/setupOverview.ts';

const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function project(state = 'format-valid') {
  const selected = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'inert-app', name: 'Example app', path: '/inert/never-opened' } });
  const config = state === 'missing' ? null : { android: { enabled: true }, version: { source: 'release/version.properties' } };
  return { ...selected.projects['inert-app'], observedAt: 1, revision: 3, baselineGeneration: 2, observationGeneration: 5,
    draft: structuredClone(config), baseline: structuredClone(config), snapshot: {
      root: '/inert/never-opened', observedAt: '2026-10-19T00:00:00Z', observationScope: 'single-request-non-atomic',
      config: { state, data: structuredClone(config), path: 'release/mobile-release.json', content: null, issues: [] },
      discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
      assurance: { ...assurance }, issues: [],
    } };
}
function versionState(session, observed = false) {
  const project = session ? { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, dirtyDraft: JSON.stringify(session.draft) !== JSON.stringify(session.baseline),
    snapshotRequest: session.snapshotRequest, saveRecoveryRequired: session.saveRecoveryRequired } : null;
  return { mode: 'native', reason: null, project, readEpoch: 2, connectionGeneration: 3, selectionGeneration: 4,
    generationLost: false, selectionPending: false, pending: null, stale: false, error: null,
    resultBinding: observed ? { ...project, requestId: 8, readEpoch: 2, connectionGeneration: 3, selectionGeneration: 4 } : null,
    result: observed ? { schemaVersion: 2, source: 'release/version.properties', version: { name: '1.2.3', build: 17 },
      savedConfig: { bytes: 99, sha256: 'a'.repeat(64) }, savedVersion: { bytes: 33, sha256: 'b'.repeat(64) },
      observationScope: 'single-request-non-atomic', assurance: { ...assurance } } : null,
  };
}
function editorState() {
  return { mode: 'native', projectId: 'inert-app', visible: true, selectionPending: false, contextGeneration: 1, connectionGeneration: 1,
    entries: {}, help: null, error: null, edit: { ...structuredClone(initialConfigEdit), mode: 'native' } };
}
function input(session = project(), observedVersion = false) {
  return { session, preview: false, configSaveState: structuredClone(initialConfigEdit), releaseVersionState: versionState(session, observedVersion),
    initializationState: structuredClone(initialProjectInitialization), versionEditState: editorState(),
    chooseReason: null, refreshReason: null, releaseVersionReason: null };
}
function check(session, stage, state = 'checked') {
  return { projectId: session.project.id, observationGeneration: session.observationGeneration, baselineGeneration: session.baselineGeneration,
    draftRevision: session.revision, stage, state, summary: `${stage} fixture summary — not native evidence` };
}
function activity(state = 'running', projectId = 'inert-app') {
  return { projectId, task: 'Local build', state, action: { kind: 'navigate', page: 'releases' } };
}
function owner(phase = 'applying', extra = {}) {
  return { projectId: 'inert-app', phase, nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending',
    nativeReason: 'none', coreOutcome: null, ...extra };
}
function attempt(projection, extra = {}) {
  return { binding: { projectId: 'inert-app' }, projection, closeRequested: false, handled: false, ...extra };
}
const stage = (model, id) => model.stages.find((row) => row.id === id);

test('empty workspace has one next action: the existing native project picker', () => {
  const state = input(null);
  const model = setupOverview(state);
  assert.deepEqual(model.next, { label: 'Choose project folder', action: { kind: 'choose-project' }, disabledReason: null });
  assert.equal(model.currentStage, 'project');
  assert.deepEqual(model.known, []);
  assert.equal(model.version, null);
  assert.equal(setupOverview({ ...state, chooseReason: 'The original task is still stopping.' }).next.disabledReason, 'The original task is still stopping.');
});

test('preview never promotes example config, version or supplied checks to observed setup', () => {
  const state = input(project(), true);
  state.preview = true;
  state.checks = ['tools', 'signing'].map((name) => check(state.session, name));
  const model = setupOverview(state);
  assert.deepEqual(model.known, []);
  assert.equal(model.version, null);
  assert.equal(model.versionLabel, 'Example only');
  assert.equal(model.next.action.kind, 'choose-project');
});

test('complete missing config guides setup; partial, failed, old or superseded reads do not claim absence', () => {
  const state = input(project('missing'));
  assert.equal(stage(setupOverview(state), 'configuration').statusLabel, 'Not set up');
  assert.deepEqual(setupOverview(state).next.action, { kind: 'navigate', page: 'settings' });
  for (const change of [
    { snapshot: null }, { observedAt: null }, { snapshotPredatesSave: true }, { sourceChanged: true },
    { snapshotError: { code: 'unavailable', message: 'Inert read error', retryable: false } },
    { snapshot: { ...state.session.snapshot, discovery: { ...state.session.snapshot.discovery, partial: true } } },
  ]) {
    const model = setupOverview({ ...state, session: { ...state.session, ...change } });
    assert.notEqual(stage(model, 'configuration').statusLabel, 'Not set up');
    assert.deepEqual(model.next.action, { kind: 'refresh-project' });
  }
  const saving = { ...state, configSaveState: { ...state.configSaveState, attempt: attempt(owner('applying')) } };
  assert.equal(setupOverview(saving).currentActivity.state, 'running');
  const oldSave = { ...state, configSaveState: { ...state.configSaveState, status: { active: null, lastTerminal: owner('final') } } };
  assert.deepEqual(setupOverview(oldSave).next.action, { kind: 'refresh-project' });
});

test('saved version is bound to the selected project, revisions and the original read context', () => {
  const state = input(project(), true);
  assert.deepEqual(savedVersionForSetup(state.session, state.releaseVersionState, false), { name: '1.2.3', build: 17 });
  for (const patch of [
    { mode: 'preview' }, { mode: 'unavailable' }, { stale: true }, { generationLost: true }, { selectionPending: true },
    { reason: 'Service disconnected' }, { pending: state.releaseVersionState.resultBinding }, { resultBinding: null },
    ...['readEpoch', 'connectionGeneration', 'selectionGeneration'].map((key) => ({ [key]: 99 })),
    ...['project', 'resultBinding'].flatMap((name) => [
      { [name]: null },
      ...['projectId', 'draftRevision', 'baselineGeneration', 'observationGeneration', 'dirtyDraft', 'snapshotRequest', 'saveRecoveryRequired'].map((key) =>
        ({ [name]: { ...state.releaseVersionState[name], [key]: key === 'projectId' ? 'other-app' : key === 'dirtyDraft' || key === 'saveRecoveryRequired' ? true : 99 } })),
    ]),
  ]) assert.equal(savedVersionForSetup(state.session, { ...state.releaseVersionState, ...patch }, false), null, JSON.stringify(patch));
  for (const patch of [{ snapshotRequest: 9 }, { snapshotPredatesSave: true }, { sourceChanged: true }, { saveRecoveryRequired: true },
    { snapshotError: { code: 'unavailable', message: 'Inert error', retryable: false } }]) {
    assert.equal(savedVersionForSetup({ ...state.session, ...patch }, state.releaseVersionState, false), null);
  }
});

test('validated or newer drafts are not saved settings; the selector retains all input unchanged', () => {
  const state = input(project('missing'));
  state.session.draft = { version: { source: 'release/new-draft.properties' } };
  state.session.validation = { valid: true, state: 'format-valid', issues: [] };
  state.session.validatedRevision = state.session.revision;
  state.session.validatedBaselineGeneration = state.session.baselineGeneration;
  const before = structuredClone(state);
  const model = setupOverview(state);
  assert.equal(stage(model, 'configuration').statusLabel, 'Unsaved draft');
  assert.equal(model.version, null);
  assert.deepEqual(state, before);
  const saved = input(project());
  saved.session.draft.version.source = 'release/newer-unsaved.properties';
  saved.releaseVersionState = versionState(saved.session, true);
  const savedBefore = structuredClone(saved);
  const result = setupOverview(saved);
  assert.deepEqual(result.version, { name: '1.2.3', build: 17 });
  assert.equal(result.currentStage, 'configuration');
  assert.deepEqual(saved, savedBefore);
});

test('resume derives progress from current observations, never a visited or completed wizard flag', () => {
  const state = input(project(), true);
  state.checks = ['tools', 'signing'].map((name) => check(state.session, name));
  assert.equal(setupOverview(state).currentStage, 'build');
  const refreshed = { ...state, session: { ...state.session, observationGeneration: state.session.observationGeneration + 1 } };
  const model = setupOverview(refreshed);
  assert.equal(model.currentStage, 'version');
  assert.equal(model.version, null);
  assert.equal(stage(model, 'tools').state, 'not-checked');
  assert.equal(stage(model, 'signing').state, 'not-checked');
});

test('full-checked-guidance-still-no-auto-build: the final suggestion is navigation, not consent', () => {
  const state = input(project(), true);
  state.checks = ['tools', 'signing'].map((name) => check(state.session, name));
  const model = setupOverview(state);
  assert.equal(model.known.length, 5);
  assert.deepEqual(model.next, { label: 'Review a local build', action: { kind: 'navigate', page: 'releases' }, disabledReason: null });
  assert.equal(stage(model, 'build').state, 'not-checked');
  assert.match(stage(model, 'build').summary, /checks its own requirements/);
  for (const row of model.stages) assert.ok(['choose-project', 'refresh-project', 'read-version', 'open-version', 'open-initialization', 'navigate'].includes(row.next.action.kind));
  assert.ok(!/release.ready|approved|published|reserved/i.test(model.known.join(' ')));
});

test('ordinary-unknown-does-not-mask-cancel: unperformed tools and signing do not replace live progress', () => {
  const state = input(project(), true);
  state.activities = [activity('running'), activity('cancellation-requested')];
  const model = setupOverview(state);
  assert.equal(stage(model, 'tools').state, 'not-checked');
  assert.equal(stage(model, 'signing').state, 'not-checked');
  assert.equal(model.currentActivity.state, 'cancellation-requested');
  assert.equal(model.next.label, 'View current task');
  assert.match(setupActivitySummary(model.currentActivity), /not completion/);
});

test('original mutation unknown/recovery outrank live work; result-shaped data is not finality', () => {
  const state = input(project(), true);
  state.activities = [activity('running'), activity('recovery-required'), activity('unknown')];
  assert.equal(setupOverview(state).currentActivity.state, 'unknown');
  state.activities.pop();
  assert.equal(setupOverview(state).currentActivity.state, 'recovery-required');
  state.activities = [];
  state.initializationState.attempt = attempt(owner('applying', { coreOutcome: { effect: 'committed', journal: 'clean', reason: 'none' } }));
  const model = setupOverview(state);
  assert.equal(model.currentActivity.state, 'running');
  assert.equal(model.initializationNeedsAttention, true);
  assert.deepEqual(model.next.action, { kind: 'open-initialization' });
});

test('foreign-attention-not-current-readiness: keep other owned work separate from this project', () => {
  const state = input(project(), true);
  state.checks = [{ ...check(state.session, 'tools'), projectId: 'another-app' },
    { ...check(state.session, 'signing', 'needs-attention'), projectId: 'another-app' }];
  state.activities = [activity('recovery-required', 'another-app')];
  const model = setupOverview(state);
  assert.equal(model.currentActivity, null);
  assert.equal(model.currentStage, 'tools');
  assert.equal(stage(model, 'tools').state, 'not-checked');
  assert.equal(stage(model, 'signing').state, 'not-checked');
  assert.deepEqual(model.otherProjectActivities, state.activities);
  state.versionEditState.entries.other = { projectId: 'another-app', error: { code: 'bad', message: 'Other draft issue' }, stale: true };
  assert.equal(setupOverview(state).versionEditorNeedsAttention, false);
});

test('stale-recovery-remains-visible while stale or ambiguous ordinary success cannot mark setup checked', () => {
  const state = input(project(), true);
  state.checks = ['tools', 'signing'].map((name) => check(state.session, name));
  state.activities = [activity('recovery-required')];
  state.session.observationGeneration += 1;
  let model = setupOverview(state);
  assert.equal(model.currentActivity.state, 'recovery-required');
  assert.equal(stage(model, 'tools').state, 'not-checked');
  state.checks = [check(state.session, 'tools'), check(state.session, 'tools', 'needs-attention')];
  model = setupOverview(state);
  assert.equal(stage(model, 'tools').state, 'not-checked');
});

test('tool and signing observations cannot bypass missing, partial, invalid or unsaved project settings', () => {
  const base = input(project(), true);
  const checks = ['tools', 'signing'].map((name) => check(base.session, name));
  for (const session of [project('missing'), project('invalid'), { ...base.session, snapshot: null },
    { ...base.session, snapshot: { ...base.session.snapshot, discovery: { ...base.session.snapshot.discovery, partial: true } } },
    { ...base.session, draft: { ...base.session.draft, extra: 'unsaved' } }]) {
    const model = setupOverview({ ...base, session, checks });
    assert.equal(stage(model, 'tools').state, 'not-checked');
    assert.equal(stage(model, 'signing').state, 'not-checked');
  }
});

test('retained edit and recovery cancellation stay visible until actual settled projection', () => {
  const state = input(project(), true);
  state.versionEditState.edit.recovery = attempt(owner('finalizing'), { closeRequested: true });
  let model = setupOverview(state);
  assert.equal(model.currentActivity.state, 'cancellation-requested');
  assert.equal(model.versionEditorNeedsAttention, true);
  state.versionEditState.edit.recovery.projection = owner('final', { nativeReason: 'cancelled' });
  model = setupOverview(state);
  assert.equal(model.currentActivity, null);
  assert.equal(stage(model, 'build').state, 'not-checked');
});

test('active/error/recovery sections cannot be collapsed; ordinary idle panels can stay closed', () => {
  assert.equal(setupDisclosureOpen(false, false), false);
  assert.equal(setupDisclosureOpen(true, false), true);
  assert.equal(setupDisclosureOpen(false, true), true);
  assert.equal(setupDisclosureOpen(true, true), true);
  const state = input();
  assert.equal(setupOverview(state).initializationNeedsAttention, false);
  assert.equal(setupOverview(state).versionEditorNeedsAttention, false);
  state.initializationState.attempt = attempt(owner('reviewing'));
  state.versionEditState.error = { code: 'inert_error', message: 'Cannot read the saved values.' };
  const model = setupOverview(state);
  assert.equal(model.initializationNeedsAttention, true);
  assert.equal(model.versionEditorNeedsAttention, true);
  state.initializationState.attempt = attempt(owner('final', { nativeReason: 'io_error' }));
  assert.equal(setupOverview(state).initializationNeedsAttention, true);
});
