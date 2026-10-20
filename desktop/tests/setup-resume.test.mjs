// Pure presentation/reducer fixtures. Original controllers supply initial
// states only: no ports, timers, files, tools, credentials or native execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { initialConfigEdit } from '../src/configEdit.ts';
import { initialProjectInitialization } from '../src/projectInitialization.ts';
import { AndroidBuildController } from '../src/androidBuild.ts';
import { IOSArchiveController } from '../src/iosArchive.ts';
import { OfflinePreflightController } from '../src/offlinePreflight.ts';
import { EnvironmentDiagnosticsController } from '../src/environmentDiagnosticsController.ts';
import { ToolAcquisitionController } from '../src/toolAcquisitionController.ts';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { setupOverview } from '../src/setupOverview.ts';

const clone = (v) => structuredClone(v);
const configBytes = { bytes: 123, sha256: 'a'.repeat(64) };
const versionBytes = { bytes: 41, sha256: 'b'.repeat(64), source: 'release/version.properties', name: '1.2.3', build: 4 };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function analysis(platform = 'android') {
  const rows = [['project-layout', 'local', null, 'detected'], ['release-settings', 'local', null, 'configured'],
    ['version-source', 'local', 'version.source', 'configured'],
    ...(platform === 'android' ? [
      ['android-identity', 'local', 'android.applicationId', 'configured'], ['android-module', 'local', 'android.module', 'configured'],
      ['android-variant', 'local', 'android.variant', 'not-checked'], ['android-tools', 'local', null, 'not-checked'],
      ['android-signing', 'signing', 'android.uploadCertificateSha256', 'not-checked'], ['android-store', 'store', 'android.identityStatus', 'blocked'],
      ['android-testing', 'store', 'android.externalTrack', 'deferred'],
    ] : [
      ['ios-identity', 'local', 'ios.bundleId', 'configured'], ['ios-container', 'local', 'ios.project', 'configured'],
      ['ios-scheme', 'local', 'ios.scheme', 'configured'], ['ios-configuration', 'local', 'ios.archiveConfiguration', 'not-checked'],
      ['ios-tools', 'local', null, 'not-checked'], ['ios-signing', 'signing', 'ios.teamId', 'not-checked'],
      ['ios-store', 'store', 'ios.appStoreAppId', 'deferred'], ['ios-testing', 'store', 'ios.externalTestFlightGroup', 'deferred'],
    ]), ['store-metadata', 'store', 'metadata.root', 'deferred'], ['github-automation', 'automation', null, 'deferred']];
  return { schemaVersion: 1, scope: 'local-setup-guidance', configurationState: 'format-valid', discoveryPartial: false,
    platforms: [platform], requirements: rows.map(([id, stage, field, state]) => ({ id, stage, field, state, reference: null,
      summary: 'Inert static finding, not a passed operation.' })), limitations: Array(6).fill('No native qualification.'), assurance: clone(assurance) };
}
function session(platform = 'android') {
  const project = { id: 'app', name: 'Inert app', path: '/inert/never-opened' };
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: project.id, requestId: 1 });
  const data = { version: { source: versionBytes.source }, [platform]: platform === 'android'
    ? { enabled: true, applicationId: 'org.example.app', module: ':app', identityStatus: 'blocked' }
    : { enabled: true, bundleId: 'org.example.app', project: 'App.xcodeproj', scheme: 'App' } };
  const snapshot = { root: project.path, observedAt: '2026-10-20T00:00:00Z', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(configBytes), data, issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(assurance), issues: [], setupAnalysis: analysis(platform) };
  return workspaceReducer(workspace, { type: 'snapshot-done', projectId: project.id, requestId: 1, snapshot, observedAt: 1 }).projects.app;
}
const selection = { instance: '1'.repeat(32), ownerUid: 501, catalogGeneration: 1,
  recordSha256: '2'.repeat(64), inventorySha256: '3'.repeat(64), osProviderSha256: '4'.repeat(64) };
const selectedCatalog = () => ({ schemaVersion: 1, statusRevision: 1, catalogGeneration: 1, operationId: '5'.repeat(32),
  availability: 'available', phase: 'ready', reason: 'none', selected: clone(selection), entries: [{ instance: selection.instance,
    occupants: 1, status: 'verified-this-session', selection: clone(selection), recovery: null, versions: {
      jdkVendor: 'Inert', jdkVersion: '17.0.20.1', gradleVersion: '8.14.5', agpVersion: '8.9.2', sdkPlatform: 'android-35', sdkBuildToolsVersion: '35.0.0' } }] });
function input(platform = 'android') {
  const current = session(platform), context = { selectedProject: () => null, releaseVersion: () => null, otherOperationReason: () => null };
  const common = { projectId: current.project.id, draftRevision: current.revision, baselineGeneration: current.baselineGeneration,
    observationGeneration: current.observationGeneration, dirtyDraft: false, snapshotRequest: null, saveRecoveryRequired: false };
  const project = { ...common, savedConfig: clone(configBytes), savedVersion: clone(versionBytes), inputIssue: null,
    snapshotPending: false, versionPending: false, selection: null, versionObservation: null, uploadCertificateSha256: null, signingPolicy: null };
  const android = clone(new AndroidBuildController(context).getSnapshot()), ios = clone(new IOSArchiveController(context).getSnapshot());
  const chosen = platform === 'android' ? android : ios;
  Object.assign(chosen, { mode: 'native', initialized: true, listening: true, project, status: platform === 'android'
    ? { schemaVersion: 1, statusRevision: 1, availability: 'available', operation: null }
    : { schemaVersion: 2, statusRevision: 1, availability: 'available', modeCapabilities: { unsigned: true, signed: false, recovery: false }, operation: null } });
  if (platform === 'android') Object.assign(android, { catalogListening: true, catalogStatus: selectedCatalog() });
  return { session: current, preview: false, configSaveState: clone(initialConfigEdit), initializationState: clone(initialProjectInitialization),
    versionEditState: { mode: 'native', projectId: current.project.id, entries: {}, error: null, edit: clone(initialConfigEdit) },
    releaseVersionState: { mode: 'native', reason: null, project: clone(common), readEpoch: 1, connectionGeneration: 1, selectionGeneration: 1,
      generationLost: false, selectionPending: false, pending: null, stale: false, error: null,
      resultBinding: { ...common, readEpoch: 1, connectionGeneration: 1, selectionGeneration: 1, requestId: 1 },
      result: { schemaVersion: 2, source: versionBytes.source, version: { name: versionBytes.name, build: versionBytes.build },
        savedConfig: clone(configBytes), savedVersion: { bytes: versionBytes.bytes, sha256: versionBytes.sha256 },
        observationScope: 'single-request-non-atomic', assurance: clone(assurance) } },
    chooseReason: null, refreshReason: null, setupReadinessReason: null, releaseVersionReason: null,
    resume: { platform, android, ios,
      localChecks: clone(new OfflinePreflightController(context).getSnapshot()),
      diagnostics: clone(new EnvironmentDiagnosticsController(context).getSnapshot()),
      toolPreparation: clone(new ToolAcquisitionController({ ...context, knownTools: () => [null, null, null] }).getSnapshot()),
      credentials: clone(new AssetSessionController(() => null).getSnapshot()),
      androidSubmissionPending: false, iosSubmissionPending: false, localChecksSubmissionPending: false, otherOwnerReason: null } };
}
const stage = (model, id) => model.stages.find((row) => row.id === id);
function candidate(state) {
  const p = state.resume.android.project;
  state.resume.android.status.operation = { operationId: '6'.repeat(32), ownerGeneration: '7'.repeat(32),
    context: { projectId: p.projectId, draftRevision: p.draftRevision, baselineGeneration: p.baselineGeneration,
      savedConfig: clone(p.savedConfig), savedVersion: clone(p.savedVersion), operation: 'android-candidate-inputs', platform: 'android' },
    phase: 'terminal', outcome: 'complete', reason: 'none', intentUsable: false, result: { scope: 'local-android-candidate-inputs' } };
}

test('resume uses required local saved selections; Store fields and default build variants do not block it', () => {
  const state = input(), before = clone(state), ready = setupOverview(state);
  assert.equal(ready.currentStage, 'build'); assert.equal(stage(ready, 'signing').state, 'not-checked');
  assert.deepEqual(state, before, 'derivation does not change the saved config, draft, owners or Store policy');
  for (const kind of ['needs-input', 'detected', 'ambiguous', 'unsupported']) {
    const current = input(); current.session.snapshot.setupAnalysis.requirements.find((r) => r.id === 'android-module').state = kind;
    const model = setupOverview(current);
    assert.equal(model.currentStage, 'configuration'); assert.match(stage(model, 'configuration').title, /Android app module/);
    assert.deepEqual(model.next.action, { kind: 'navigate', page: 'settings' });
  }
  const ios = input('ios'); ios.session.snapshot.setupAnalysis.requirements.find((r) => r.id === 'ios-scheme').state = 'detected';
  assert.match(stage(setupOverview(ios), 'configuration').title, /shared scheme/);
  const signed = input(); signed.resume.android.buildMode = 'signed'; signed.resume.android.signing.issue = 'Missing assignment';
  assert.equal(stage(setupOverview(signed), 'build').state, 'needs-action');
  assert.equal(setupOverview(signed).next.action.page, 'settings');
  signed.resume.android.project.uploadCertificateSha256 = '8'.repeat(64);
  assert.equal(setupOverview(signed).next.action.page, 'credentials');
  signed.resume.android.signing.issue = null;
  assert.match(stage(setupOverview(signed), 'signing').statusLabel, /Assigned.*validation remains/);
  assert.equal(stage(setupOverview(signed), 'signing').state, 'not-checked');
});

test('manual setup and restart continue through the existing check/choose controls, never a download or ready flag', () => {
  const state = input(), model = setupOverview(state);
  assert.equal(model.currentStage, 'build'); assert.deepEqual(model.next.action, { kind: 'navigate', page: 'releases' });
  assert.equal(stage(model, 'tools').state, 'not-checked'); assert.match(stage(model, 'tools').statusLabel, /not build-ready/);
  const row = state.resume.android.catalogStatus.entries[0];
  state.resume.android.catalogStatus.selected = null; row.status = 'recovery-required'; row.selection = null;
  const resumed = setupOverview(state);
  assert.equal(resumed.currentStage, 'tools'); assert.match(resumed.next.label, /saved Android tools/);
  assert.deepEqual(resumed.next.action, { kind: 'open-build-tools', platform: 'android' });
  state.resume.android.catalogStatus = null;
  assert.match(stage(setupOverview(state), 'tools').summary, /Choose those existing folders/);
  const ios = setupOverview(input('ios'));
  assert.equal(ios.currentStage, 'build'); assert.equal(stage(ios, 'tools').state, 'not-checked');
  assert.deepEqual(stage(ios, 'tools').next.action, { kind: 'open-build-tools', platform: 'ios' });
});

test('actual save-intent, dirty drafts, partial/stale/retired observations keep drafts and refuse resume promotion', () => {
  const state = input(), original = state.session, workspace = { selectedId: 'app', projects: { app: original } };
  const retired = workspaceReducer(workspace, { type: 'config-save-intent', projectId: 'app' }).projects.app;
  assert.equal(retired.draft, original.draft); assert.equal(retired.baseline, original.baseline); assert.equal(retired.savedConfigContent, null);
  const refreshed = setupOverview({ ...state, session: retired });
  assert.equal(refreshed.currentStage, 'configuration'); assert.equal(refreshed.next.action.kind, 'refresh-project');
  for (const change of [
    { sourceChanged: true }, { saveRecoveryNeedsReload: true }, { snapshotPredatesSave: true },
    { savedConfigContent: { ...configBytes, sha256: '9'.repeat(64) } },
    { snapshot: { ...original.snapshot, setupAnalysis: undefined } },
    { snapshot: { ...original.snapshot, discovery: { ...original.snapshot.discovery, partial: true } } },
  ]) {
    const model = setupOverview({ ...state, session: { ...original, ...change } });
    assert.equal(model.currentStage, 'configuration'); assert.equal(model.next.action.kind, 'refresh-project');
    assert.ok(!model.known.some((v) => /tools selected|candidate result/.test(v)));
  }
  const dirty = workspaceReducer(workspace, { type: 'edit', projectId: 'app', path: 'android.module', value: ':unsaved' }).projects.app;
  const before = clone(dirty), model = setupOverview({ ...state, session: dirty });
  assert.equal(model.currentStage, 'configuration'); assert.equal(stage(model, 'configuration').statusLabel, 'Unsaved draft');
  assert.deepEqual(dirty, before); assert.equal(dirty.baseline, original.baseline);
  const oldVersion = { ...state.releaseVersionState, readEpoch: 99 };
  assert.equal(setupOverview({ ...state, releaseVersionState: oldVersion }).currentStage, 'version');
});

test('foreign or unknown original work outranks a local candidate without changing the selected project', () => {
  const state = input(); candidate(state);
  state.resume.ios = { ...state.resume.ios, mode: 'native', nativeBlocked: true, historical: true,
    status: { operation: { context: { projectId: 'other-app', operation: 'ios-unsigned-archive' }, phase: 'unknown', reason: 'cleanup-unknown' } } };
  const before = clone(state), model = setupOverview(state);
  assert.equal(model.currentActivity, null); assert.equal(model.attentionActivity.projectId, 'other-app');
  assert.equal(model.attentionActivity.state, 'unknown'); assert.equal(model.attentionIsCurrentProject, false);
  assert.deepEqual(model.next.action, { kind: 'navigate', page: 'releases' });
  assert.ok(!model.known.some((v) => /candidate result/.test(v))); assert.deepEqual(state, before);
  state.resume.ios.mode = 'unavailable'; state.resume.android.status.operation.phase = 'stopping';
  state.resume.android.status.operation.result = null; state.resume.android.cancelClaimed = { operationId: '6'.repeat(32), ownerGeneration: '7'.repeat(32) };
  assert.equal(setupOverview(state).attentionActivity.state, 'cancellation-requested');
  const retained = input(); retained.resume.otherOwnerReason = 'Original peer owner is still pending.';
  assert.equal(setupOverview(retained).attentionActivity.projectId, null);
  assert.deepEqual(setupOverview(retained).next.action, { kind: 'show-original-controls' });
  const unacknowledged = input(); candidate(unacknowledged);
  unacknowledged.resume.android.status.operation.context.projectId = 'previous-app';
  unacknowledged.resume.android.nativeBlocked = true; unacknowledged.resume.androidSubmissionPending = true;
  assert.equal(setupOverview(unacknowledged).attentionActivity.projectId, null, 'an older terminal cannot identify a new unacknowledged request');
});

test('only a current original joined build suggests its local result; stale, signing-only and returning results do not', () => {
  const state = input(); candidate(state);
  const model = setupOverview(state);
  assert.equal(model.currentStage, 'build'); assert.match(model.next.label, /candidate and local history/);
  assert.equal(stage(model, 'build').state, 'not-checked'); assert.equal(model.versionLabel, '1.2.3');
  assert.match(stage(model, 'build').summary, /Nothing was submitted/);
  for (const modify of [
    (s) => { s.resume.androidSubmissionPending = true; },
    (s) => { s.resume.android.historical = true; },
    (s) => { s.resume.android.status.operation.context.projectId = 'other-app'; },
    (s) => { s.resume.android.project.observationGeneration++; },
    (s) => { s.resume.android.status.operation.context.baselineGeneration++; },
    (s) => { s.resume.android.status.operation.outcome = 'failed'; },
    (s) => { s.resume.android.nativeBlocked = true; },
  ]) {
    const changed = clone(state); modify(changed);
    assert.ok(!setupOverview(changed).known.some((v) => /candidate result/.test(v)));
  }
  const signing = input('ios'), p = signing.resume.ios.project;
  signing.resume.ios.status.operation = { context: { ...p, operation: 'ios-signing-inputs-check' },
    phase: 'terminal', outcome: 'complete', reason: 'none', result: { scope: 'local-ios-signing-inputs-validation' } };
  assert.ok(!setupOverview(signing).known.some((v) => /build result/.test(v)));
});
