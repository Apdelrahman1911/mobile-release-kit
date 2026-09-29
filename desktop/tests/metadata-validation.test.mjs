// Inert DATA/parser/controller promises only; no native, filesystem, Store or
// installed assurance is acquired by these tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { METADATA_TEXT_IDS } from '../src/metadataText.ts';
import { parseSavedMetadataReport, savedMetadataError, savedMetadataRequestFits } from '../src/metadataValidation.ts';
import { SavedMetadataValidationController } from '../src/metadataValidationController.ts';

const clone = (value) => structuredClone(value);
const digest = { bytes: 312, sha256: 'a'.repeat(64) }; // declared fixture DATA, not a draft hash
const config = { schemaVersion: 1, metadata: { root: 'public/store', androidLocales: ['fr-FR', 'en-US'], iosLocales: ['en-US', 'fr-FR'] },
  android: { enabled: true }, ios: { enabled: true } };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const row = (kind, id, path, locale, required) => ({ kind, id, path, locale, required, state: 'checked', issues: [] });
function report(platform = 'android') {
  const files = [];
  for (const locale of ['en-US', 'fr-FR']) {
    for (const id of METADATA_TEXT_IDS[platform])
      files.push(row('public-text', id, 'public/store/' + platform + '/' + locale + '/' + id, locale, true));
    if (platform === 'android') files.push(row('android-note', 'release-notes', 'public/store/android/' + locale + '/changelogs/42.txt', locale, true));
  }
  if (platform === 'ios') for (const path of ['review/ios-beta-notes.txt', 'review/ios-notes.txt', 'testflight/what-to-test.txt'])
    files.push(row('ios-note', path.split('/').at(-1), 'public/store/' + path, null, true));
  return { schemaVersion: 1, platform, metadataRoot: 'public/store', locales: ['en-US', 'fr-FR'],
    androidBuild: platform === 'android' ? 42 : null, savedConfig: clone(digest),
    scope: 'configured-locales-canonical-images-fixed-notes', observationScope: 'single-request-non-atomic',
    valid: true, state: 'checked', files, imageSets: [], assurance: clone(assurance) };
}
function add(workspace, id = 'p') {
  workspace = workspaceReducer(workspace, { type: 'select', project: { id, name: 'Inert ' + id, path: '/never-forwarded' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: id, requestId: 1 });
  return workspaceReducer(workspace, { type: 'snapshot-done', projectId: id, requestId: 1, observedAt: 0,
    snapshot: { root: '/never-forwarded', observationScope: 'single-request-non-atomic', observedAt: '',
      config: { path: 'release/mobile-release.json', state: 'format-valid', data: clone(config), content: clone(digest), issues: [] },
      discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
      assurance: clone(assurance), issues: [] } });
}
function harness() {
  let workspace = add(initialWorkspace), other = null;
  const calls = [];
  const api = { mode: 'native', validateMetadata(input) { const pending = deferred(); calls.push({ input: clone(input), ...pending }); return pending.promise; } };
  const info = { runtime: { state: 'available' }, capabilities: { methods: [{ method: 'metadata.validate', available: true, reason: null }] } };
  const controller = new SavedMetadataValidationController({
    selectedProject: () => workspace.projects[workspace.selectedId] ?? null, otherOperationReason: () => other,
  });
  controller.setConnection(api, info); controller.setVisible(true);
  return { controller, api, info, calls, get state() { return controller.getSnapshot(); },
    get project() { return workspace.projects[workspace.selectedId]; },
    dispatch(action) { controller.beforeWorkspaceAction(action); workspace = workspaceReducer(workspace, action); controller.syncProject(); },
    add(id) { controller.selectionIntent(); workspace = add(workspace, id); controller.syncProject(); },
    block(value) { other = value; },
  };
}
test('closed request, full required roster, explicit nulls, safe issues and all-negative assurance', () => {
  assert.equal(savedMetadataRequestFits({ projectId: 'p', platform: 'android' }), true);
  for (const name of ['root', 'locale', 'path', 'metadataRoot', 'draft', 'policy', 'contents'])
    assert.equal(savedMetadataRequestFits({ projectId: 'p', platform: 'android', [name]: null }), false);
  assert.equal(savedMetadataRequestFits({ projectId: 'p\n', platform: 'android' }), false);
  for (const platform of ['android', 'ios']) {
    const good = report(platform); assert.ok(parseSavedMetadataReport(good));
    for (let index = 0; index < good.files.length; index += 1) {
      const bad = clone(good); bad.files.splice(index, 1); assert.equal(parseSavedMetadataReport(bad), null);
    }
    for (const key of ['path', 'locale']) {
      const bad = clone(good); delete bad.files[0][key]; assert.equal(parseSavedMetadataReport(bad), null);
    }
    for (const key of ['androidBuild', 'savedConfig', 'assurance']) {
      const bad = clone(good); delete bad[key]; assert.equal(parseSavedMetadataReport(bad), null);
    }
    const missing = clone(good); missing.files[0].state = 'missing'; missing.files[0].issues = ['metadata.missing'];
    assert.equal(parseSavedMetadataReport(missing), null);
    missing.valid = false; missing.state = 'issues'; assert.ok(parseSavedMetadataReport(missing));
    for (const key of ['credentialsRead', 'writesPerformed', 'storeContacted', 'projectCodeExecuted']) {
      const bad = clone(good); bad.assurance[key] = true; assert.equal(parseSavedMetadataReport(bad), null);
    }
    const duplicate = clone(good); duplicate.files.push(clone(good.files[0])); assert.equal(parseSavedMetadataReport(duplicate), null);
  }
});
test('no note text, derived summaries, private siblings or unknown issue messages enter the DTO', () => {
  const good = report('ios');
  for (const key of ['text', 'byteLength', 'sha256', 'summary', 'characterCount']) {
    const bad = clone(good); bad.files.at(-1)[key] = 'inert-sensitive-marker'; assert.equal(parseSavedMetadataReport(bad), null);
  }
  for (const path of ['public/store/review/contact.json', 'public/store/testflight/demo-password.txt', '../note.txt']) {
    const bad = clone(good); bad.files.at(-1).path = path; assert.equal(parseSavedMetadataReport(bad), null);
  }
  const bad = clone(good); bad.files[0].state = 'invalid'; bad.files[0].issues = ['inert-sensitive-marker'];
  bad.valid = false; bad.state = 'issues'; assert.equal(parseSavedMetadataReport(bad), null);
  const hostile = clone(good); let touched = false;
  Object.defineProperty(hostile, 'files', { enumerable: true, get() { touched = true; throw Error('never'); } });
  assert.equal(parseSavedMetadataReport(hostile), null); assert.equal(touched, false);
  const cycle = clone(good); cycle.files.push(cycle); assert.equal(parseSavedMetadataReport(cycle), null);
  const sparse = clone(good); delete sparse.files[1]; assert.equal(parseSavedMetadataReport(sparse), null);
  const oversized = clone(good); oversized.files[0].id = 'x'.repeat(256 * 1024); assert.equal(parseSavedMetadataReport(oversized), null);
});
test('optional images have canonical paths, exact nonempty group counts and duplicate correlation', () => {
  const value = report();
  value.files.push(row('image', 'icon', 'public/store/android/en-US/images/icon.png', 'en-US', false));
  assert.equal(parseSavedMetadataReport(value), null);
  value.imageSets.push({ locale: 'en-US', id: 'icon', count: 1, required: false, issues: [] });
  assert.ok(parseSavedMetadataReport(value));
  const bad = clone(value); bad.imageSets[0].count = 2; assert.equal(parseSavedMetadataReport(bad), null);
  bad.imageSets[0].count = 1; bad.files.at(-1).path = 'public/store/android/en-US/images/ICON.png';
  assert.equal(parseSavedMetadataReport(bad), null);
  value.files.push(row('image', 'icon', 'public/store/android/en-US/images/icon.jpg', 'en-US', false));
  value.imageSets[0].count = 2; value.imageSets[0].issues = ['image.count']; value.valid = false; value.state = 'issues';
  assert.ok(parseSavedMetadataReport(value));
  value.files.at(-1).state = 'invalid'; value.files.at(-1).issues = ['image.duplicate'];
  assert.equal(parseSavedMetadataReport(value), null);
  value.imageSets[0].issues.push('image.duplicate'); assert.ok(parseSavedMetadataReport(value));
});
test('image destination grammar and case aliases cannot invent a complete selected scope', () => {
  const folder = 'public/store/android/en-US/images/phoneScreenshots';
  const good = report();
  good.files.push(row('image', 'phoneScreenshots', folder + '/shot.png', 'en-US', false));
  good.imageSets.push({ locale: 'en-US', id: 'phoneScreenshots', count: 1, required: false, issues: [] });
  assert.ok(parseSavedMetadataReport(good));
  for (const name of ['-shot.png', 'shot..png', 'shot+.png', 'é.png', 'CON.png']) {
    const bad = clone(good); bad.files.at(-1).path = folder + '/' + name;
    assert.equal(parseSavedMetadataReport(bad), null);
  }
  const alias = clone(good);
  alias.files.push(row('image', 'phoneScreenshots', folder + '/SHOT.png', 'en-US', false));
  alias.imageSets[0].count = 2; assert.equal(parseSavedMetadataReport(alias), null);
  const textAlias = report();
  textAlias.files.push(row('public-text', 'TITLE.txt', 'public/store/android/en-US/TITLE.txt', 'en-US', false));
  assert.equal(parseSavedMetadataReport(textAlias), null);
});
test('native bridge has only one named command with project/platform; preview cannot simulate success', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, input) => { calls.push({ command, input }); return report(input.platform); });
  assert.ok(await api.validateMetadata({ projectId: 'p', platform: 'android' }));
  assert.deepEqual(calls, [{ command: 'metadata_validate', input: { projectId: 'p', platform: 'android' } }]);
  await assert.rejects(api.validateMetadata({ projectId: 'p', platform: 'android', root: '/private' }));
  assert.equal(calls.length, 1);
  await assert.rejects(previewApi.validateMetadata({ projectId: 'p', platform: 'android' }));
  const unavailable = createNativeApi('unavailable', async () => { throw Error('must not invoke'); });
  await assert.rejects(unavailable.validateMetadata({ projectId: 'p', platform: 'android' }));
  const wrong = createNativeApi('native', async () => report('ios'));
  await assert.rejects(wrong.validateMetadata({ projectId: 'p', platform: 'android' }));
});
test('explicit click only; saved bytes matched rather than reserialized drafts', async () => {
  const h = harness();
  assert.equal(h.calls.length, 0); h.controller.syncProject(); assert.equal(h.calls.length, 0);
  assert.equal(h.controller.startReason(), null);
  const pending = h.controller.validate(); assert.equal(h.calls.length, 1); assert.ok(h.controller.passiveBusyReason());
  assert.deepEqual(h.calls[0].input, { projectId: 'p', platform: 'android' });
  h.calls[0].resolve(report()); await pending;
  assert.equal(h.state.status, 'checked'); assert.equal(h.controller.passiveBusyReason(), null);
  assert.deepEqual(h.state.report.savedConfig, digest);
  assert.ok(Object.isFrozen(h.state.report.files));
  const mismatch = h.controller.validate(); const wrong = report(); wrong.savedConfig.sha256 = 'b'.repeat(64);
  h.calls.at(-1).resolve(wrong); await mismatch;
  assert.equal(h.state.status, 'incomplete'); assert.equal(h.state.report, null);
});
test('away-and-back, selection/config/refresh/save intent, platform and reconnect all retire late replies without settling ownership', async () => {
  const events = [
    (h) => { h.controller.setVisible(false); h.controller.setVisible(true); },
    (h) => { h.controller.selectionIntent(); h.controller.setSelectionPending(true); h.controller.setSelectionPending(false); },
    (h) => { h.dispatch({ type: 'switch', projectId: 'p' }); }, // unchanged reducer still retires
    (h) => { h.controller.snapshotIntent('p'); },
    (h) => { h.dispatch({ type: 'config-save-intent', projectId: 'p' }); },
    (h) => { h.controller.selectPlatform('ios'); h.controller.selectPlatform('android'); },
    (h) => { h.controller.beginConnection(); h.controller.setConnection(h.api, h.info); },
    (h) => { h.add('q'); h.dispatch({ type: 'switch', projectId: 'p' }); },
    (h) => { h.controller.invalidate(); }, // synchronous original-editor notification
  ];
  for (const event of events) {
    const h = harness(), pending = h.controller.validate();
    event(h);
    assert.equal(h.state.report, null); assert.equal(h.state.pending, true); assert.ok(h.controller.passiveBusyReason());
    await h.controller.validate(); assert.equal(h.calls.length, 1); // original barrier remains
    h.calls[0].resolve(report()); await pending;
    assert.equal(h.state.report, null); assert.equal(h.state.status, 'not-checked');
    assert.equal(h.state.pending, false); assert.equal(h.controller.passiveBusyReason(), null);
    assert.equal(h.calls.length, 1); // no implicit retry
  }
  // Pending publication is synchronous. A retired or newly ineligible
  // reservation must not become an API call, even on subscriber reentry.
  for (const event of [...events,
    (h) => { h.project.revision += 1; },
    (h) => { h.info.capabilities.methods[0].available = false; },
    (h) => h.block('Another original owner became active during publication.'),
  ]) {
    const h = harness(); let observed = false, reentry;
    const unsubscribe = h.controller.subscribe(() => {
      if (observed || !h.state.pending) return;
      observed = true;
      assert.ok(h.controller.passiveBusyReason());
      reentry = h.controller.validate();
      event(h);
    });
    await h.controller.validate(); await reentry; unsubscribe();
    assert.equal(observed, true); assert.equal(h.calls.length, 0);
    assert.equal(h.state.pending, false); assert.equal(h.controller.passiveBusyReason(), null);
    assert.equal(h.state.status, 'not-checked'); assert.equal(h.state.report, null);
  }
});
test('dirty, changed, missing exact baseline, external busy and unavailable gates never invoke', async () => {
  const cases = [
    (h) => h.dispatch({ type: 'edit', projectId: 'p', path: 'metadata.root', value: 'other/store' }),
    (h) => { h.project.savedConfigContent = null; h.controller.syncProject(); },
    (h) => { h.project.sourceChanged = true; h.controller.syncProject(); },
    (h) => h.block('An original operation still owns its resources.'),
    (h) => { const info = clone(h.info); info.capabilities.methods[0].available = false; h.controller.setConnection(h.api, info); },
  ];
  for (const setup of cases) {
    const h = harness(); setup(h); assert.ok(h.controller.startReason()); await h.controller.validate(); assert.equal(h.calls.length, 0);
  }
});
test('malformed and rejected outcomes are incomplete, fixed redacted and never stored as success', async () => {
  const h = harness(); const pending = h.controller.validate(); const bad = report(); bad.files.pop();
  h.calls[0].resolve(bad); await pending; assert.equal(h.state.status, 'incomplete'); assert.equal(h.state.report, null);
  const again = h.controller.validate(); h.calls.at(-1).reject({ code: 'metadata_validation_unreadable', message: 'inert-sensitive-marker' });
  await again; assert.equal(h.state.status, 'incomplete'); assert.equal(h.state.pending, false);
  assert.ok(!JSON.stringify(h.state).includes('inert-sensitive-marker'));
  const error = {}; let touched = false;
  Object.defineProperty(error, 'message', { get() { touched = true; throw Error('never'); } });
  assert.ok(!savedMetadataError(error).message.includes('never')); assert.equal(touched, false);
});
test('all 250 configured locales can return bounded missing-file issues without a smaller renderer node ceiling', () => {
  // Python asserts these are its encoded bytes; Rust traverses the same
  // frame's strict envelope decoder and closed metadata result validator.
  const envelope = JSON.parse(readFileSync(new URL('../../tests/desktop/fixtures/metadata-validation-250-locales-response.json', import.meta.url), 'utf8'));
  assert.deepEqual(Object.keys(envelope), ['protocol', 'id', 'ok', 'result']);
  assert.equal(envelope.protocol, 1); assert.equal(envelope.id, 'metadata-large'); assert.equal(envelope.ok, true);
  const value = envelope.result;
  assert.equal(value.locales.length, 250); assert.equal(value.files.length, 1253);
  assert.ok(value.files.every((entry) => entry.state === 'missing' && entry.issues[0] === 'metadata.missing'));
  assert.ok(new TextEncoder().encode(JSON.stringify(value)).byteLength <= 256 * 1024);
  assert.ok(parseSavedMetadataReport(value));
});
test('App retains controller and reciprocal pending/intent seams; card promises local checks only', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  for (const marker of ['new SavedMetadataValidationController', 'metadataValidationRef.current?.passiveBusyReason()',
    'metadataValidationRef.current?.beforeWorkspaceAction(action)', 'metadataValidationRef.current?.syncProject()',
    "metadataValidation.setVisible(next === 'metadata')", 'metadataValidation.snapshotIntent(projectId)', 'metadataValidation.selectionIntent()',
    'metadataText.subscribe(metadataValidation.invalidate)', 'metadataImages.subscribe(metadataValidation.invalidate)', 'versionEdit.subscribe(metadataValidation.invalidate)'])
    assert.ok(app.includes(marker), marker);
  for (const marker of ['excludeMetadataValidation = false',
    '(excludeMetadataValidation ? null : metadataValidationRef.current?.passiveBusyReason())',
    '(!excludeMetadataValidation && metadataValidation.passiveBusyReason())',
    'savedCommandBusy(false, false, false, false, true) ?? savedCommandPrerequisiteReason(false, false, undefined, true)'])
    assert.ok(app.includes(marker), marker);
  const card = readFileSync(new URL('../src/components/MetadataValidation.tsx', import.meta.url), 'utf8');
  for (const marker of ['Validate metadata', 'Completed local checks', 'not Store readiness', 'non-atomic', 'Pixels are not decoded', 'not inspected', 'Exhaustion'])
    assert.ok(card.includes(marker), marker);
  assert.ok(!card.includes('useEffect') && !card.includes('Store-ready'));
  const page = readFileSync(new URL('../src/pages/Metadata.tsx', import.meta.url), 'utf8');
  assert.ok(page.includes('not a review of your metadata files') && page.includes('Not inspected'));
});
