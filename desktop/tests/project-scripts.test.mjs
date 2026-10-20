// Static DATA and the real local reducer only; no DOM, native calls or scripts.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { getValue } from '../src/catalog.ts';
import { parseExternalProjectSnapshot, sameExternalProjectSnapshot } from '../src/externalProjectObservation.ts';
import { PROJECT_SCRIPT_STAGES, applyProjectScriptEdit, parseProjectScriptDiscovery, prepareProjectScriptEdit, projectScriptsView } from '../src/projectScripts.ts';

const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function discovery() {
  return { schemaVersion: 1, scope: 'project-script-hints', coverage: 'conventional-paths-only', sourcePartial: false, truncated: false,
    platforms: ['android', 'ios'], candidates: [{ path: 'scripts/check.sh', purposeHint: 'check', status: 'direct-candidate', shell: 'sh' }],
    assurance: { ...assurance } };
}
function harness() {
  const snapshot = { root: '/inert/project', observedAt: '2026-10-20T00:00:00Z', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: { bytes: 300, sha256: 'a'.repeat(64) },
      data: { android: { enabled: true }, ios: { enabled: true }, projectChecks: { preflight: [['./existing', 'literal argument']], androidArtifact: [], iosArtifact: [] } }, issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 3, sourceFiles: 2, sourceBytes: 200, excludedEntries: 0 }, limits: {} },
    scriptDiscovery: discovery(), assurance: { ...assurance }, issues: [] };
  let state = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'inert', name: 'Inert', path: '/inert/project' } });
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: 'inert', requestId: 1 });
  state = workspaceReducer(state, { type: 'snapshot-done', projectId: 'inert', requestId: 1, snapshot, observedAt: 1 });
  const h = { state, service: {}, epoch: 1, preview: false, reason: null, commits: 0,
    catalog: { fields: PROJECT_SCRIPT_STAGES.map((path) => ({ path, input: path === 'ios.prepareCommand' ? 'argv' : 'commands' })) } };
  h.context = () => ({ session: h.state.projects[h.state.selectedId] ?? null, service: h.service, catalog: h.catalog, epoch: h.epoch, preview: h.preview, reason: h.reason });
  h.reduce = (action) => { const previous = h.state; h.state = workspaceReducer(h.state, action); return h.state !== previous; };
  h.commit = (action) => { h.commits++; return h.reduce(action); };
  h.edit = (path, value) => h.reduce({ type: 'edit', projectId: 'inert', path, value });
  return h;
}

test('closed script hints copy DATA and reject aliases, extra content and execution claims', () => {
  const input = discovery(), parsed = parseProjectScriptDiscovery(input);
  assert.ok(parsed);
  input.candidates[0].path = 'scripts/prepare.sh';
  assert.equal(parsed.candidates[0].path, 'scripts/check.sh');
  const changes = [
    (v) => { v.body = 'private source'; }, (v) => { v.assurance.projectCodeExecuted = true; },
    (v) => { v.candidates[0].path = '../scripts/check.sh'; }, (v) => { v.candidates[0].path = '/scripts/check.sh'; }, (v) => { v.candidates[0].path = '/check.sh'; },
    (v) => { v.candidates[0].path = 'scripts//check.sh'; }, (v) => { v.candidates[0].path = 'custom/check.sh'; },
    (v) => { v.candidates[0].purposeHint = 'prepare'; }, (v) => { v.candidates[0].shell = null; },
    (v) => { v.candidates[0].argv = ['sh', '-c', 'private']; }, (v) => { v.candidates.push({ ...v.candidates[0] }); },
    (v) => { v.truncated = true; }, (v) => { v.platforms = ['ios', 'android']; },
  ];
  for (const change of changes) { const value = discovery(); change(value); assert.equal(parseProjectScriptDiscovery(value), null); }
  let called = false;
  const getter = discovery(); Object.defineProperty(getter, 'candidates', { enumerable: true, get() { called = true; throw Error(); } });
  assert.equal(parseProjectScriptDiscovery(getter), null); assert.equal(called, false);
});

test('explicit Add preserves earlier commands and uses only the original draft reducer', () => {
  const h = harness(), before = h.context().session;
  const prepared = prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight');
  assert.ok(prepared.edit); assert.equal(h.commits, 0, 'preparing a local preview has no effects');
  assert.equal(applyProjectScriptEdit(prepared.edit, h.context, h.commit), true);
  const after = h.context().session;
  assert.deepEqual(after.draft.projectChecks.preflight, [['./existing', 'literal argument'], ['./scripts/check.sh']]);
  assert.equal(after.draft.projectChecks.preflight[0], before.draft.projectChecks.preflight[0]);
  assert.equal(after.baseline, before.baseline); assert.equal(after.snapshot, before.snapshot);
  assert.equal(after.revision, before.revision + 1); assert.equal(after.lastSave, null);
  assert.equal(applyProjectScriptEdit(prepared.edit, h.context, h.commit), false, 'old local append cannot replay');
  assert.equal(h.commits, 1);
  assert.match(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').reason, /already/);
});

test('iOS single command never replaces a value and malformed or full lists remain repairable', () => {
  const h = harness();
  assert.ok(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'ios.prepareCommand').edit);
  for (const value of [[], null, ['existing', 'with arguments']]) {
    h.edit('ios.prepareCommand', value);
    assert.equal(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'ios.prepareCommand').edit, null);
    assert.deepEqual(getValue(h.context().session.draft, 'ios.prepareCommand'), value);
  }
  for (const value of [null, 'bad parent', [], 4]) {
    h.edit('projectChecks', value);
    assert.equal(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').edit, null);
    assert.deepEqual(h.context().session.draft.projectChecks, value);
  }
  h.edit('projectChecks', { preflight: Array.from({ length: 32 }, () => ['./existing']) });
  assert.equal(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').edit, null);
  assert.equal(h.context().session.draft.projectChecks.preflight.length, 32);
});

test('partial, unknown execution hints, disabled platforms and stale saved contexts never enable Add', () => {
  for (const status of ['not-executable', 'unsupported-shebang', 'permissions-unavailable', 'unsupported-mode']) {
    const h = harness(), row = h.context().session.snapshot.scriptDiscovery.candidates[0]; row.status = status;
    if (status === 'unsupported-shebang') row.shell = null;
    assert.equal(prepareProjectScriptEdit(h.context(), row.path, 'projectChecks.preflight').edit, null);
  }
  for (const change of [
    (h) => { h.preview = true; }, (h) => { h.service = null; }, (h) => { h.reason = 'Original operation needs recovery'; },
    (h) => { h.context().session.snapshot.discovery.partial = true; h.context().session.snapshot.scriptDiscovery.sourcePartial = true; },
    (h) => { h.context().session.snapshot.scriptDiscovery.platforms = []; },
    (h) => { h.context().session.savedConfigContent = null; }, (h) => { h.context().session.saveRecoveryRequired = true; },
    (h) => { h.context().session.sourceChanged = true; }, (h) => { h.context().session.snapshotPredatesSave = true; },
    (h) => { h.context().session.snapshotRequest = 2; }, (h) => { h.context().session.snapshot.root = '/inert/other'; },
    (h) => { h.catalog = { fields: [] }; },
  ]) {
    const h = harness(); change(h); const draft = h.context().session.draft;
    assert.equal(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').edit, null);
    assert.equal(h.context().session.draft, draft); assert.equal(h.commits, 0);
  }
  const h = harness(); h.edit('ios.enabled', false);
  assert.equal(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'ios.prepareCommand').edit, null);
  assert.ok(prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').edit, 'enabled detected Android still supports explicit project checks');
});

test('API, epoch, catalog, draft or selected-project change invalidates a local append before commit', () => {
  for (const change of [
    (h) => { h.service = {}; }, (h) => { h.epoch += 2; }, (h) => { h.catalog = { ...h.catalog }; },
    (h) => { h.edit('android.applicationId', 'org.example.newdraft'); },
    (h) => { h.reduce({ type: 'select', project: { id: 'other', name: 'Other', path: '/inert/other' } }); },
    (h) => { h.reason = 'Pending original file picker'; },
  ]) {
    const h = harness(), prepared = prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').edit;
    change(h); const before = h.state;
    assert.equal(applyProjectScriptEdit(prepared, h.context, h.commit), false);
    assert.equal(h.commits, 0); assert.equal(h.state, before);
  }
});

test('actual reducer refuses reentrant newer draft or project after Add enters ordinary dispatch', () => {
  for (const change of ['draft', 'project']) {
    const h = harness(), prepared = prepareProjectScriptEdit(h.context(), 'scripts/check.sh', 'projectChecks.preflight').edit;
    let newer;
    const commit = (action) => {
      if (change === 'draft') h.edit('projectChecks.preflight', [['./newer-local-command']]);
      else h.reduce({ type: 'select', project: { id: 'other', name: 'Other', path: '/inert/other' } });
      newer = h.state;
      return h.reduce(action);
    };
    assert.equal(applyProjectScriptEdit(prepared, h.context, commit), false);
    assert.equal(h.state, newer, 'listener changes must not be replaced by the earlier append');
  }
  const h = harness();
  assert.equal(h.edit('projectChecks.preflight', [['./ordinary-manual-edit']]), true, 'unguarded existing manual editor is unchanged');
});

test('the real external snapshot parser validates the optional script DTO and compares mode changes', () => {
  const h = harness(), input = h.context().session.snapshot;
  const before = parseExternalProjectSnapshot(input); assert.ok(before);
  assert.equal(before.scriptDiscovery.assurance.projectCodeExecuted, false);
  const next = structuredClone(input); next.scriptDiscovery.candidates[0].status = 'not-executable';
  const after = parseExternalProjectSnapshot(next); assert.ok(after);
  assert.equal(sameExternalProjectSnapshot(before, after), false, 'changed executable hints invalidate the observed candidate');
  for (const change of [
    (v) => { v.scriptDiscovery.sourcePartial = true; }, (v) => { v.scriptDiscovery = null; },
    (v) => { v.scriptDiscovery.candidates[0].contents = 'must not be projected'; }, (v) => { v.newUnknownKey = {}; },
  ]) { const value = structuredClone(input); change(value); assert.equal(parseExternalProjectSnapshot(value), null); }
  delete next.scriptDiscovery;
  assert.ok(parseExternalProjectSnapshot(next), 'old optional-free observations remain supported');
  assert.equal(projectScriptsView({ ...h.context(), session: { ...h.context().session, snapshot: next } }).discovery, null, 'absence is unknown, not zero scripts');
});
