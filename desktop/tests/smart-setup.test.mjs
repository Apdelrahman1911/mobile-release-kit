// DATA/presentation only: no filesystem, process, account or native qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { parseSetupAnalysis, setupGuidanceView } from '../src/smartSetup.ts';

function analysis() {
  const spec = [
    ['project-layout', 'local', null, 'detected'], ['release-settings', 'local', null, 'configured'],
    ['version-source', 'local', 'version.source', 'configured'], ['android-identity', 'local', 'android.applicationId', 'configured'],
    ['android-module', 'local', 'android.module', 'detected'], ['android-variant', 'local', 'android.variant', 'not-checked'],
    ['android-tools', 'local', null, 'not-checked'], ['android-signing', 'signing', 'android.uploadCertificateSha256', 'not-checked'],
    ['android-store', 'store', 'android.identityStatus', 'deferred'], ['android-testing', 'store', 'android.externalTrack', 'deferred'],
    ['store-metadata', 'store', 'metadata.root', 'deferred'], ['github-automation', 'automation', null, 'deferred'],
  ];
  return { schemaVersion: 1, scope: 'local-setup-guidance', configurationState: 'format-valid', discoveryPartial: false, platforms: ['android'],
    requirements: spec.map(([id, stage, field, state]) => ({ id, stage, field, state, reference: null, summary: 'Inert static guidance, not a passed operation.' })),
    limitations: Array(6).fill('Inert limitation; no native operation.'), assurance: { basis: 'static-text', projectCodeExecuted: false,
      toolsProbed: false, credentialsRead: false, gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' } };
}
function session() {
  const workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'inert', name: 'Inert', path: '/inert/never-opened' } });
  const config = { android: { enabled: true } };
  const content = { bytes: 123, sha256: 'a'.repeat(64) };
  return { ...workspace.projects.inert, observedAt: 1, snapshotRequest: null, draft: structuredClone(config), baseline: structuredClone(config), savedConfigContent: structuredClone(content),
    snapshot: { root: '/inert/never-opened', observedAt: '2026-10-19T00:00:00Z', config: { state: 'format-valid', data: config, content },
      discovery: { partial: false }, setupAnalysis: analysis() } };
}

test('closed core guidance remains a detached finite copy, never readiness', () => {
  const source = analysis();
  const parsed = parseSetupAnalysis(source);
  assert.ok(parsed);
  assert.equal(parsed.assurance.releaseReadiness, 'unknown');
  source.requirements[0].state = 'blocked';
  assert.equal(parsed.requirements[0].state, 'detected');
  assert.equal(parsed.requirements.find((row) => row.id === 'android-tools').state, 'not-checked');
});

test('invalid/duplicate/foreign rows, authority claims and unsafe refs refuse', () => {
  const mutations = [
    (v) => { v.scope = 'release-ready'; }, (v) => { v.assurance.toolsProbed = true; },
    (v) => { v.requirements[0].state = 'READY'; }, (v) => { v.requirements.push(v.requirements[0]); },
    (v) => { v.platforms = ['ios']; }, (v) => { v.requirements[0].stage = 'store'; },
    (v) => { v.requirements[0].field = 'credential.password'; }, (v) => { v.configurationState = 'missing'; },
    (v) => { v.requirements.find((r) => r.id === 'android-tools').state = 'configured'; },
    (v) => { v.requirements[0].summary = 'x'.repeat(17000); }, (v) => { v.requirements[0].reference = '../../foreign'; },
    (v) => { v.requirements[0].reference = 'C:/foreign'; }, (v) => { v.requirements[0].reference = 'a//b'; },
    (v) => { v.requirements[0].reference = '/absolute'; }, (v) => { v.requirements[0].reference = 'x\\y'; },
    (v) => { v.requirements[0].extra = true; },
  ];
  for (const mutate of mutations) { const value = analysis(); mutate(value); assert.equal(parseSetupAnalysis(value), null); }
  let called = false;
  const value = analysis();
  Object.defineProperty(value, 'platforms', { enumerable: true, get() { called = true; throw Error(); } });
  assert.equal(parseSetupAnalysis(value), null);
  assert.equal(called, false);
});

test('only the original current saved observation is displayed; old/missing/preview are unavailable', () => {
  const current = session();
  assert.ok(setupGuidanceView(current, false, null).analysis);
  assert.equal(setupGuidanceView(current, true, null).analysis, null);
  for (const change of [{ snapshot: null }, { observedAt: null }, { snapshotRequest: 1 }, { snapshotPredatesSave: true },
    { sourceChanged: true }, { saveRecoveryRequired: true }, { saveRecoveryNeedsReload: true }, { snapshotError: { code: 'inert' } },
    { snapshot: { ...current.snapshot, root: '/other' } }, { snapshot: { ...current.snapshot, setupAnalysis: undefined } },
    { snapshot: { ...current.snapshot, config: { state: 'missing' } } },
    { snapshot: { ...current.snapshot, discovery: { partial: true } } }]) {
    assert.equal(setupGuidanceView({ ...current, ...change }, false, null).analysis, null);
  }
});

test('dirty draft stays intact and receives saved-only label; partial hints stay visibly partial', () => {
  const current = session();
  current.draft.android.module = 'new-unsaved-module';
  const before = structuredClone(current);
  const result = setupGuidanceView(current, false, null);
  assert.ok(result.analysis);
  assert.equal(result.savedOnly, true);
  assert.deepEqual(current, before);
  current.snapshot.discovery.partial = true;
  current.snapshot.setupAnalysis.discoveryPartial = true;
  current.snapshot.setupAnalysis.requirements[0].state = 'unverified';
  assert.equal(setupGuidanceView(current, false, null).analysis.discoveryPartial, true);
  assert.equal(setupGuidanceView(session(), false, null).savedOnly, false);
});


test('actual save-intent retires saved comparison and original mutation blocker covers missing settings', () => {
  const current = session();
  const state = { selectedId: 'inert', projects: { inert: current } };
  const pending = workspaceReducer(state, { type: 'config-save-intent', projectId: 'inert' });
  assert.equal(pending.projects.inert.savedConfigContent, null);
  assert.equal(setupGuidanceView(pending.projects.inert, false, null).analysis, null);
  const missing = session();
  missing.savedConfigContent = null; missing.snapshot.config = { state: 'missing', data: null, content: null };
  missing.snapshot.setupAnalysis.configurationState = 'missing';
  for (const row of missing.snapshot.setupAnalysis.requirements) if (row.state === 'configured') row.state = 'needs-input';
  assert.ok(setupGuidanceView(missing, false, null).analysis);
  assert.equal(setupGuidanceView(missing, false, 'Original initialization pending').analysis, null);
});
