// Inert DATA, source syntax and DTO/reducer/controller promise tests. No DOM, native owner,
// project filesystem, worker, subprocess, network, Store, or finality evidence.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Script } from 'node:vm';
import guideResource from '../../src/mobile_release/api/data/metadata-text-help-v1.json' with { type: 'json' };
import { createNativeApi } from '../src/bridge.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { METADATA_TEXT_IDS, metadataCacheBytes, metadataCompareRetainedDraft, metadataConfiguredChoices, metadataConfigReason, metadataLineEndings,
  metadataNoOp, metadataProjectDirty, metadataTextDirty, metadataTextSavedFresh } from '../src/metadataText.ts';
import { MetadataTextEditController, currentMetadataApplyBinding, metadataOwnerReason, metadataPreparedMatches, metadataRetainsDraft } from '../src/metadataTextEditController.ts';
import { metadataProjectionProgress, metadataTextError, metadataTextRequestFits, normalMetadataTextResult,
  parseMetadataTextEditStatus, parseMetadataTextGuide, parseMetadataTextObservation, parseMetadataTextValidation } from '../src/metadataTextProtocol.ts';
import { previewApi } from '../src/preview.ts';

test('installed metadata observer scripts compile without evaluating a DOM or native operation', () => {
  const source = readFileSync(new URL('../src-tauri/src/installed_shell_observation.rs', import.meta.url), 'utf8');
  assert.ok(source.length <= 1 << 20);
  const selected = source.split('fn metadata_script(step: MetadataStep) -> Option<String> {')[1]?.split('\nfn workflow_script(')[0];
  assert.ok(selected?.endsWith('\n}\n'));
  assert.ok(selected.includes('"#,body,r#"'));
  assert.ok(selected.includes('"#].concat())'));
  assert.ok(!selected.includes('format!('));
  // These are Rust raw literals, not decoded/copied approximations of the
  // script. The final two are the unchanged common prefix and suffix.
  const literals = [...selected.matchAll(/r#"([\s\S]*?)"#/g)].map((match) => match[1]);
  const prefix = literals.at(-2), suffix = literals.at(-1), bodies = literals.slice(0, -2);
  assert.ok(prefix.startsWith('(() => { try {'));
  assert.equal(suffix, " } catch { return {state:'error'}; } })()");
  assert.equal(bodies.length, 20);
  for (const [index, body] of bodies.entries()) {
    new Script(prefix + body + suffix, { filename: `installed-metadata-step-${index}` });
  }
  const openText = bodies.filter((body) => body.includes("reason:'review-missing'"));
  assert.equal(openText.length, 1);
  // Prove this check refuses the actual former same-block lexical collision.
  assert.equal((openText[0].match(/\bdetails\b/g) ?? []).length, 3);
  const former = openText[0].replaceAll(/\bdetails\b/g, 'rows');
  assert.throws(() => new Script(prefix + former + suffix), SyntaxError);
});

const ID = { window: 'a'.repeat(32), session: 'b'.repeat(32), revision: 'c'.repeat(32), plan: 'd'.repeat(32), other: 'e'.repeat(32) };
const BASE = { schemaVersion: 1, metadata: { root: 'release/store', androidLocales: ['en-US', 'fr-FR'], iosLocales: ['en-US'] }, android: { enabled: true }, ios: { enabled: true } };
const assurance = (basis) => ({ basis, projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' });
const digest = (text) => ({ byteLength: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex') });
const deferred = () => { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const clone = (value) => structuredClone(value);
const flush = async () => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };
function snapshot(data = BASE) {
  return { root: '/inert-never-forwarded', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { content: null, path: 'release/mobile-release.json', state: 'format-valid', data: clone(data), issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: assurance('static-text'), issues: [] };
}
function addProject(workspace, projectId = 'a', data = BASE) {
  workspace = workspaceReducer(workspace, { type: 'select', project: { id: projectId, name: `Inert ${projectId}`, path: '/inert-never-forwarded' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId, requestId: 1 });
  return workspaceReducer(workspace, { type: 'snapshot-done', projectId, requestId: 1, snapshot: snapshot(data), observedAt: 0 });
}
function texts(platform = 'android') {
  return platform === 'android' ? ['Hello 😀\r\n', 'A short public summary.\r\n', 'Full public description.\n'] :
    ['A public iOS description.\n', 'notes,local', 'https://site.invalid/privacy', 'https://site.invalid/support', 'Improved local editing.\n'];
}
function observation(platform = 'android', locale = 'en-US', values = texts(platform), config = BASE) {
  const fields = METADATA_TEXT_IDS[platform].map((id, index) => values[index] === null ? { id, path: `${config.metadata.root}/${platform}/${locale}/${id}`, state: 'absent' } :
    { id, path: `${config.metadata.root}/${platform}/${locale}/${id}`, state: 'present', text: values[index], ...digest(values[index]) });
  return { schemaVersion: 1, platform, locale, metadataRoot: config.metadata.root, observationScope: 'single-request-non-atomic',
    baseline: { config: digest(JSON.stringify(config)), fields: fields.map((row) => row.state === 'absent' ? { id: row.id, state: row.state } :
      { id: row.id, state: row.state, byteLength: row.byteLength, sha256: row.sha256 }) }, fields, assurance: assurance('static-text') };
}
// Fixture counts are inert declared DTO values, not a release-policy oracle.
function validation(platform, fields, valid = true) {
  return { schemaVersion: 1, platform, valid, state: valid ? 'format-valid' : 'invalid', fields: fields.map((field, index) => ({ id: field.id,
    valid: valid || index !== 0, characterCount: [...field.text.replace(/\r\n?/g, '\n').replace(/\n+$/, '')].length,
    limit: field.id === 'title.txt' ? 30 : field.id === 'short_description.txt' ? 80 : field.id === 'keywords.txt' ? 100 : field.id.endsWith('_url.txt') ? 2048 : 4000,
    issues: !valid && index === 0 ? [{ code: 'metadata.placeholder', status: 'FAIL', message: 'Public Store text contains an unresolved placeholder.' }] : [],
  })), assurance: assurance('schema-policy') };
}
function status(revision = 0, active = null, lastTerminal = null, reason = 'available') {
  return { schemaVersion: 1, domain: 'metadata_text', windowGeneration: ID.window, statusRevision: revision,
    capability: { available: reason === 'available', reason }, active, lastTerminal };
}
function plan(h, binding = h.controller.getSnapshot().edit.attempt?.binding) {
  assert.ok(binding);
  const { platform, locale, metadataRoot } = binding.context;
  const files = binding.fields.map((field, index) => {
    const original = binding.originals[index];
    const before = original.text === null ? { state: 'absent' } : { state: 'present', text: original.text, ...digest(original.text) };
    return { id: field.id, path: original.path, before, after: { text: field.text, ...digest(field.text) },
      action: before.state === 'absent' ? 'create' : original.text === field.text ? 'preserve' : 'replace',
      lineEndingsChanged: metadataLineEndings(original.text ?? '') !== metadataLineEndings(field.text) };
  });
  return { schemaVersion: 1, platform, locale, metadataRoot, files, createDirectories: [], validation: validation(platform, binding.fields) };
}
function owner(h, phase = 'opening', options = {}) {
  const binding = h.state.edit.attempt.binding; const view = options.view ?? plan(h, binding);
  const hasPrepared = ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  return { domain: 'metadata_text', projectId: binding.projectId, sessionId: ID.session, ownerGeneration: ID.window,
    platform: binding.context.platform, locale: binding.context.locale, phase, reviewRemainingMs: 900000,
    checkout: phase === 'opening' ? null : { revision: ID.revision, metadataRoot: binding.context.metadataRoot, baseline: clone(binding.expectedBaseline) },
    prepared: hasPrepared ? { revision: ID.revision, planToken: ID.plan, draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration, view } : null,
    applySubmitted: ['applying', 'finalizing', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: metadataNoOp(view) ? 'unchanged' : 'committed', journal: metadataNoOp(view) ? 'not_created' : 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false,
    ...Object.fromEntries(Object.entries(options).filter(([key]) => key !== 'view')) };
}
function harness({ config = BASE, nativeStatus = status(), subscribeGate = null } = {}) {
  let workspace = addProject(initialWorkspace, 'a', config); let registry = clone(nativeStatus); let listener; let clock = 100;
  let otherReason = null; let operationReason = null; const calls = []; const reads = [];
  const selected = () => workspace.projects[workspace.selectedId] ?? null;
  const request = (kind, args) => { const pending = deferred(); calls.push({ kind, args: clone(args), ...pending }); return pending.promise; };
  const api = { mode: 'native',
    subscribeMetadataTextEdit: async (receive) => { calls.push({ kind: 'subscribe' }); listener = receive; if (subscribeGate) await subscribeGate.promise; return () => { listener = null; }; },
    metadataTextEditStatus: () => { calls.push({ kind: 'status' }); return reads.length ? reads.shift().promise : Promise.resolve(clone(registry)); },
    observeMetadataText: (input) => request('observe', input), validateMetadataText: (input) => request('validate', input),
    openMetadataTextEdit: (input) => request('open', input), prepareMetadataTextEdit: (input) => request('prepare', input),
    applyMetadataTextEdit: (sessionId, planToken) => request('apply', { sessionId, planToken }), closeMetadataTextEdit: (sessionId) => request('close', { sessionId }),
  };
  const controller = new MetadataTextEditController({ selectedProject: selected, otherEditReason: () => otherReason, otherOperationReason: () => operationReason, now: () => clock });
  const info = { runtime: { state: 'available', mode: 'development', reason: null }, capabilities: { methods: [
    { method: 'metadata.text.observe', available: true, reason: '' }, { method: 'metadata.text.validate', available: true, reason: '' },
  ] } };
  controller.beginConnection(); controller.setConnection(api, info); controller.setHelp(guideResource);
  const h = { controller, api, selected, calls, info,
    get state() { return controller.getSnapshot(); }, get workspace() { return workspace; }, get frame() { return registry; },
    count: (kind) => calls.filter((call) => call.kind === kind).length, last: (kind) => calls.filter((call) => call.kind === kind).at(-1),
    dispatch: (action) => { workspace = workspaceReducer(workspace, action); controller.syncProject(); },
    add: (id, data = BASE) => { workspace = addProject(workspace, id, data); controller.syncProject(); },
    blockOther: (value) => { otherReason = value; }, blockOperation: (value) => { operationReason = value; }, advance: (amount) => { clock += amount; },
    deferStatus: () => { const value = deferred(); reads.push(value); return value; },
    emit: (value) => { registry = clone(value); assert.ok(listener); listener(clone(value)); },
    publish: (projection, options = {}) => {
      const terminal = projection.phase === 'final' || projection.lateSettled;
      const value = status(options.revision ?? registry.statusRevision + 1, terminal ? null : projection,
        terminal ? projection : registry.lastTerminal, options.reason ?? registry.capability.reason);
      h.emit(value); return value;
    },
  };
  return h;
}
async function connected(options) { const h = harness(options); await h.controller.connect(h.api); return h; }
async function load(h, values) {
  const pending = h.controller.load(); const call = h.last('observe'); assert.ok(call);
  call.resolve(values ?? observation(call.args.platform, call.args.locale, texts(call.args.platform), h.selected().baseline));
  assert.equal(await pending, true); return h.controller.selectedEntry();
}
async function validate(h, valid = true) {
  const pending = h.controller.validate(); const call = h.last('validate'); assert.ok(call);
  call.resolve(validation(call.args.platform, call.args.fields, valid));
  assert.equal(await pending, true);
}
async function reviewing(h, { unchanged = false, observed } = {}) {
  const entry = await load(h, observed);
  if (!unchanged) h.controller.editField(entry.context.key, 'title.txt', 'A reviewed title\n');
  await validate(h); assert.equal(h.controller.startReason(), null); assert.equal(h.controller.start(), true);
  h.publish(owner(h, 'opening')); h.publish(owner(h, 'editing')); assert.equal(h.count('prepare'), 1);
  h.publish(owner(h, 'reviewing')); assert.ok(metadataPreparedMatches(h.state.edit.attempt));
  const binding = currentMetadataApplyBinding(h.state); assert.ok(binding); return binding;
}

test('guide and saved configuration choices are core-owned; raw originals keep Unicode/newlines/BOM', () => {
  assert.ok(parseMetadataTextGuide(guideResource)); assert.equal(guideResource.fields.length, 8);
  const h = harness(); assert.equal(metadataConfigReason(h.selected()), null); assert.equal(metadataConfiguredChoices(h.selected()).length, 3);
  const raw = '\ufeffA😀\r\nB\rC\n';
  const observed = observation('android', 'en-US', [raw, 'short', 'full']);
  assert.equal(parseMetadataTextObservation(observed)?.fields[0].text, raw);
  assert.equal(metadataLineEndings(raw), 'CRLF + CR + LF');
  const malformed = clone(guideResource); malformed.actions[0].requiredness = 'required'; assert.equal(parseMetadataTextGuide(malformed), null);
  malformed.actions[0].requiredness = 'optional'; malformed.fields[0].format = 'x'.repeat(2049); assert.equal(parseMetadataTextGuide(malformed), null);
});

test('wire admission is closed, bounded, canonical and refuses path overrides or accessor execution', () => {
  const fields = METADATA_TEXT_IDS.android.map((id, index) => ({ id, text: texts()[index] }));
  const request = { platform: 'android', fields }; assert.equal(metadataTextRequestFits('metadata_text_validate', request), true);
  for (const change of [(v) => { v.path = '/arbitrary'; }, (v) => { v.fields.reverse(); }, (v) => { v.fields[1].id = 'title.txt'; },
    (v) => { v.fields[0].text = '\ud800'; }, (v) => { v.fields[0].text = 'x'.repeat(32769); }, (v) => { delete v.fields[1]; }]) {
    const value = clone(request); change(value); assert.equal(metadataTextRequestFits('metadata_text_validate', value), false);
  }
  assert.equal(metadataTextRequestFits('metadata_text_observe', { projectId: 'a', platform: 'android', locale: 'en-US', metadataRoot: 'release/store' }), false);
  assert.equal(metadataTextRequestFits('metadata_text_edit_open', { projectId: 'a/b', platform: 'android', locale: 'en-US' }), false);
  let getters = 0; const accessor = { fields }; Object.defineProperty(accessor, 'platform', { enumerable: true, get() { getters += 1; return 'android'; } });
  assert.equal(metadataTextRequestFits('metadata_text_validate', accessor), false); assert.equal(getters, 0);
});

test('observation rejects unsafe/partial/withheld-as-absence and inconsistent digests/path summaries', () => {
  for (const change of [(v) => { v.fields[0].path = 'elsewhere/title.txt'; }, (v) => { v.fields[0].state = 'withheld'; },
    (v) => { v.fields[0].byteLength += 1; }, (v) => { v.fields[0].sha256 = 'f'.repeat(64); }, (v) => { v.fields[0].secret = 'no'; },
    (v) => { v.baseline.config.byteLength = 0; }, (v) => { v.fields.pop(); }, (v) => { v.assurance.credentialsRead = true; },
    (v) => { v.metadataRoot = '../other'; }, (v) => { v.metadataRoot = 'release/review'; }, (v) => { v.metadataRoot = 'release/COM0'; },
    (v) => { v.metadataRoot = 'release/e\u0301'; }, (v) => { v.metadataRoot = 'release/<unsafe>'; }]) {
    const value = observation(); change(value); assert.equal(parseMetadataTextObservation(value), null);
  }
  assert.ok(parseMetadataTextObservation(observation('ios')));
  const missing = observation('android', 'en-US', [null, 'short', 'full']); assert.ok(parseMetadataTextObservation(missing));
  missing.fields[0].text = ''; assert.equal(parseMetadataTextObservation(missing), null);
});

test('validation accepts core Unicode counts, fixed issue triples, and never echoes arbitrary messages', () => {
  const fields = METADATA_TEXT_IDS.android.map((id, index) => ({ id, text: texts()[index] }));
  const result = validation('android', fields); assert.equal(result.fields[0].characterCount, 7); assert.ok(parseMetadataTextValidation(result));
  const bad = validation('android', fields, false); assert.ok(parseMetadataTextValidation(bad));
  bad.fields[0].issues[0].message += ' raw input'; assert.equal(parseMetadataTextValidation(bad), null);
  const contradiction = clone(result); contradiction.fields[0].characterCount = 31; assert.equal(parseMetadataTextValidation(contradiction), null);
  const safe = metadataTextError({ code: 'metadata_text_sensitive', message: 'PRIVATE CANARY' }); assert.equal(safe.message.includes('CANARY'), false);
  assert.equal(metadataTextError({ code: 'unknown', message: 'PRIVATE CANARY' }).message.includes('CANARY'), false);
});

test('native bridge has seven fixed commands and browser preview never produces observation/validation/save', async () => {
  const fields = METADATA_TEXT_IDS.android.map((id, index) => ({ id, text: texts()[index] }));
  const calls = []; const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return command === 'metadata_text_observe' ? observation() :
    command === 'metadata_text_validate' ? validation('android', fields) : status(0, null, null, 'runtime_unqualified'); },
    async (event) => { calls.push({ event }); return () => {}; });
  await api.observeMetadataText({ projectId: 'a', platform: 'android', locale: 'en-US' });
  await api.validateMetadataText({ platform: 'android', fields });
  await api.openMetadataTextEdit({ projectId: 'a', platform: 'android', locale: 'en-US' });
  await api.prepareMetadataTextEdit({ sessionId: ID.session, revision: ID.revision, expectedBaseline: observation().baseline, fields, draftRevision: 1, baselineGeneration: 0 });
  await api.applyMetadataTextEdit(ID.session, ID.plan); await api.closeMetadataTextEdit(ID.session);
  await api.metadataTextEditStatus(); await api.subscribeMetadataTextEdit(() => {});
  assert.deepEqual(calls.map((call) => call.command ?? call.event), ['metadata_text_observe', 'metadata_text_validate', 'metadata_text_edit_open',
    'metadata_text_edit_prepare', 'metadata_text_edit_apply', 'metadata_text_edit_close', 'metadata_text_edit_status', 'metadata-text-edit-status']);
  await assert.rejects(api.observeMetadataText({ projectId: 'a', platform: 'android', locale: 'en-US', root: '/no' })); assert.equal(calls.length, 8);
  for (const action of [() => previewApi.observeMetadataText({ projectId: 'a', platform: 'android', locale: 'en-US' }),
    () => previewApi.validateMetadataText({ platform: 'android', fields: [] }), () => previewApi.openMetadataTextEdit({ projectId: 'a', platform: 'android', locale: 'en-US' }),
    () => previewApi.prepareMetadataTextEdit({}), () => previewApi.applyMetadataTextEdit(ID.session, ID.plan), () => previewApi.closeMetadataTextEdit(ID.session),
    () => previewApi.metadataTextEditStatus(), () => previewApi.subscribeMetadataTextEdit(() => {})]) await assert.rejects(action());
  const wrongLocale = createNativeApi('native', async () => observation('android', 'fr-FR'));
  await assert.rejects(wrongLocale.observeMetadataText({ projectId: 'a', platform: 'android', locale: 'en-US' }), { code: 'MetadataTextResponseInvalid' });
});

test('load preserves untouched raw bytes, draft refresh is observation-only, and explicit reconciliation is bound', async () => {
  const h = await connected(); const first = await load(h); const key = first.context.key;
  assert.equal(first.fields[0].text, 'Hello 😀\r\n'); assert.equal(metadataTextDirty(first), false);
  h.controller.editField(key, 'title.txt', 'Hello 😀\n'); assert.equal(h.controller.selectedEntry().baseline.originals[0].text, 'Hello 😀\r\n');
  assert.equal(metadataTextDirty(h.controller.selectedEntry()), true); assert.equal(metadataProjectDirty(h.state.entries, 'a'), true);
  await load(h, observation('android', 'en-US', ['External title\r\n', 'short', 'full']));
  assert.equal(h.controller.selectedEntry().fields[0].text, 'Hello 😀\n'); assert.equal(h.controller.selectedEntry().stale, true);
  const older = h.controller.discardBinding(key); h.controller.editField(key, 'title.txt', 'Newer local title');
  assert.equal(h.controller.discard(older, 'latest'), false);
  assert.equal(h.controller.discard(h.controller.discardBinding(key), 'latest'), true);
  assert.equal(h.controller.selectedEntry().fields[0].text, 'External title\r\n'); assert.equal(metadataTextDirty(h.controller.selectedEntry()), false);
  const kept = h.controller.selectedEntry(); const refused = h.controller.load();
  h.last('observe').reject({ code: 'metadata_text_sensitive', message: 'PRIVATE CANARY' }); assert.equal(await refused, false);
  const after = h.controller.selectedEntry(); assert.equal(after.fields, kept.fields); assert.equal(after.baseline, kept.baseline);
  assert.equal(after.observation, kept.observation); assert.equal(after.stale, true); assert.equal(after.loadError.message.includes('CANARY'), false);
});

test('late load/validation replies cannot overwrite newer text, project, locale or service contexts', async () => {
  const h = await connected(); const first = await load(h); const key = first.context.key;
  const pending = h.controller.load(); const oldLoad = h.last('observe'); h.controller.editField(key, 'title.txt', 'A newer draft');
  oldLoad.resolve(observation()); assert.equal(await pending, false); assert.equal(h.controller.selectedEntry().fields[0].text, 'A newer draft');
  const validating = h.controller.validate(); const oldValidate = h.last('validate'); h.add('b');
  oldValidate.resolve(validation('android', oldValidate.args.fields)); assert.equal(await validating, false); assert.equal(h.state.entries[key].validation, null);
  h.dispatch({ type: 'switch', projectId: 'a' }); h.controller.selectContext(key);
  const loading = h.controller.load(); const oldService = h.last('observe'); h.controller.beginConnection(); oldService.resolve(observation());
  assert.equal(await loading, false); assert.equal(h.state.entries[key].fields[0].text, 'A newer draft');
  assert.equal(h.controller.start(), false);
});

test('configuration edits/removal retain old contexts and never merge configuration/text drafts', async () => {
  const h = await connected(); const first = await load(h); const key = first.context.key;
  h.controller.editField(key, 'title.txt', 'Kept text'); h.dispatch({ type: 'edit', projectId: 'a', path: 'metadata.root', value: 'release/other' });
  assert.match(h.controller.loadReason(), /configuration draft/); assert.equal(isDirty(h.selected()), true);
  h.dispatch({ type: 'snapshot-start', projectId: 'a', requestId: 2 });
  const changed = clone(BASE); changed.metadata.androidLocales = ['fr-FR'];
  h.dispatch({ type: 'snapshot-done', projectId: 'a', requestId: 2, snapshot: snapshot(changed), observedAt: 2 }); h.dispatch({ type: 'reset', projectId: 'a' });
  assert.equal(h.state.entries[key].fields[0].text, 'Kept text'); assert.equal(h.state.selectedKey, key);
  assert.match(h.controller.loadReason(), /retained earlier/); assert.equal(h.state.choices.some((choice) => choice.key === key), false);
  assert.equal(h.controller.discard(h.controller.discardBinding(key), 'forget'), true); assert.equal(h.state.entries[key], undefined);
});

test('capacity refuses 33rd locale and aggregate overflow without evicting original text', async () => {
  const config = clone(BASE); config.ios.enabled = false;
  config.metadata.androidLocales = Array.from({ length: 33 }, (_, index) => `a${String.fromCharCode(97 + index % 26)}${index >= 26 ? 'a' : ''}`);
  const h = await connected({ config });
  for (const choice of h.state.choices.slice(0, 32)) { h.controller.selectContext(choice.key); await load(h, observation('android', choice.locale, texts(), config)); }
  const first = h.state.choices[0].key; const original = h.state.entries[first];
  h.controller.selectContext(h.state.choices[32].key); const calls = h.count('observe'); assert.equal(await h.controller.load(), false);
  assert.equal(h.count('observe'), calls); assert.equal(Object.keys(h.state.entries).length, 32); assert.equal(h.state.entries[first], original);
  assert.equal(h.state.cacheError.code, 'MetadataTextCacheFull');
  assert.equal(h.controller.discard(h.controller.discardBinding(first), 'forget'), true); await load(h, observation('android', h.state.choices[32].locale, texts(), config));
  const large = await connected({ config }); const full = Array(3).fill('A'.repeat(32768));
  for (const choice of large.state.choices.slice(0, 28)) { large.controller.selectContext(choice.key); await load(large, observation('android', choice.locale, full, config)); }
  const before = large.state.entries[large.state.choices[0].key]; const next = large.state.choices[28]; large.controller.selectContext(next.key);
  const pending = large.controller.load(); large.last('observe').resolve(observation('android', next.locale, full, config)); assert.equal(await pending, false);
  assert.ok(metadataCacheBytes(large.state.entries) <= 8388608); assert.equal(large.state.entries[large.state.choices[0].key], before);
  assert.equal(large.controller.selectedEntry().fields, null); assert.equal(large.controller.selectedEntry().loadError.code, 'MetadataTextCacheFull');
});

test('native subscribe precedes status; initial event buffering cannot acquire foreign-domain authority', async () => {
  const gate = deferred(); const h = harness({ subscribeGate: gate }); const connecting = h.controller.connect(h.api); await flush();
  assert.deepEqual(h.calls.map((call) => call.kind), ['subscribe']);
  h.emit(status(1, null, null, 'runtime_unqualified')); gate.resolve(); await connecting;
  assert.equal(h.state.edit.status.statusRevision, 1); assert.equal(h.controller.start(), false);
  const foreign = clone(h.frame); foreign.domain = 'github_workflows'; h.emit(foreign);
  assert.equal(h.state.edit.integrityFailed, true); assert.ok(metadataOwnerReason(h.state, 'a'));
});

test('native review binds expected baseline/raw payload and synchronous claims prevent duplicate clicks', async () => {
  const h = await connected(); const binding = await reviewing(h);
  assert.equal(h.controller.start(), false); assert.equal(h.count('open'), 1);
  assert.ok(metadataOwnerReason(h.state, 'a')); assert.equal(metadataRetainsDraft(h.state, 'a'), true);
  assert.deepEqual(Object.keys(h.last('prepare').args).sort(), ['sessionId', 'revision', 'expectedBaseline', 'fields', 'draftRevision', 'baselineGeneration'].sort());
  assert.equal(h.last('prepare').args.expectedBaseline.config.sha256, observation().baseline.config.sha256);
  assert.equal(h.state.edit.attempt.projection.prepared.view.files[0].before.text, 'Hello 😀\r\n');
  assert.equal(h.controller.apply(binding), true); assert.equal(h.controller.apply(binding), false); assert.equal(h.count('apply'), 1);
  h.publish(owner(h, 'applying')); h.publish(owner(h, 'final'));
  assert.equal(metadataTextSavedFresh(h.controller.selectedEntry()), true); assert.equal(metadataTextDirty(h.controller.selectedEntry()), false);
  assert.equal(h.controller.selectedEntry().baseline.originals[0].text, 'A reviewed title\n');
  assert.deepEqual(h.selected().baseline, BASE); assert.equal(isDirty(h.selected()), false);
  assert.equal(h.controller.selectedEntry().observation.fields[0].text, 'Hello 😀\r\n'); assert.equal(h.controller.selectedEntry().observationPredatesSave, true);
});

test('pre-Apply changes retire original review; late prepared replies and stale confirmations do not revive it', async () => {
  const h = await connected(); const binding = await reviewing(h); const old = clone(h.state.edit.attempt.projection);
  h.controller.editField(h.state.selectedKey, 'title.txt', 'A newer title');
  assert.equal(h.state.edit.attempt.invalidated, true); assert.equal(h.count('close'), 1);
  h.publish(old); assert.equal(h.controller.apply(binding), false); assert.equal(h.count('apply'), 0); assert.equal(h.count('open'), 1);
  const changed = await connected(); const confirm = await reviewing(changed);
  changed.controller.setSelectionPending(true); changed.controller.setSelectionPending(false);
  assert.equal(changed.controller.apply(confirm), false); assert.equal(changed.count('close'), 1);
});

test('Apply settlement preserves newer drafts and original outcome instead of marking a newer revision saved', async () => {
  const h = await connected(); const binding = await reviewing(h); const baseline = h.controller.selectedEntry().baseline;
  assert.equal(h.controller.apply(binding), true); h.publish(owner(h, 'applying'));
  h.controller.editField(h.state.selectedKey, 'title.txt', 'A post-submission draft');
  h.dispatch({ type: 'edit', projectId: 'a', path: 'metadata.root', value: 'release/new-context' });
  assert.equal(h.count('close'), 0); h.publish(owner(h, 'final'));
  const entry = h.controller.selectedEntry(); assert.equal(entry.fields[0].text, 'A post-submission draft'); assert.equal(entry.baseline, baseline);
  assert.equal(entry.lastSave.result, 'saved'); assert.equal(entry.lastSave.resultingBaselineGeneration, null); assert.equal(metadataTextSavedFresh(entry), false);
  assert.equal(entry.stale, true); assert.equal(isDirty(h.selected()), true); assert.equal(h.selected().draft.metadata.root, 'release/new-context');
});

test('unchanged bundle confirms only original no-op; create/mixed replace plans retain closed rosters', async () => {
  const h = await connected(); const binding = await reviewing(h, { unchanged: true });
  assert.equal(metadataNoOp(h.state.edit.attempt.projection.prepared.view), true); h.controller.apply(binding); h.publish(owner(h, 'final'));
  assert.equal(h.controller.selectedEntry().lastSave.result, 'unchanged'); assert.equal(h.state.edit.attempt.projection.coreOutcome.journal, 'not_created');
  const c = await connected(); await load(c, observation('android', 'en-US', [null, 'short', 'full']));
  c.controller.editField(c.state.selectedKey, 'title.txt', 'Created title'); await validate(c); assert.equal(c.controller.start(), true);
  c.publish(owner(c, 'opening')); c.publish(owner(c, 'editing')); c.publish(owner(c, 'reviewing'));
  assert.equal(c.state.edit.attempt.projection.prepared.view.files[0].action, 'create'); assert.ok(parseMetadataTextEditStatus(c.frame));
  const wrong = clone(c.frame); wrong.active.prepared.view.files[0].action = 'replace'; assert.equal(parseMetadataTextEditStatus(wrong), null);
});

test('lost Apply reply observes the original owner once and never retries Open/Prepare/Apply', async () => {
  const h = await connected(); const binding = await reviewing(h); h.controller.apply(binding);
  const before = h.count('status'); h.last('apply').reject({ code: 'untrusted', message: 'unbounded raw output' }); await flush();
  assert.equal(h.count('status'), before + 1); assert.equal(h.count('apply'), 1); assert.equal(h.count('open'), 1); assert.equal(h.count('prepare'), 1);
  assert.equal(h.controller.apply(binding), false); assert.equal(h.state.edit.attempt.applyClaimed, true);
});

test('ordinary finality alone advances baseline; recovery/unknown outcomes block other edit domains', async () => {
  const h = await connected(); const binding = await reviewing(h); h.controller.apply(binding);
  h.publish(owner(h, 'final', { coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } }));
  assert.equal(h.controller.selectedEntry().lastSave, null); assert.ok(metadataOwnerReason(h.state, 'a')); assert.equal(h.state.edit.recoveryProjects.includes('a'), true);
  const u = await connected(); const apply = await reviewing(u); u.controller.apply(apply);
  const unknown = owner(u, 'unknown', { coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' }, nativeReason: 'cleanup_unknown' });
  u.publish(unknown, { reason: 'cleanup_unknown' }); assert.equal(normalMetadataTextResult(unknown), null); assert.equal(u.state.edit.nativeBlocked, true);
  assert.equal(u.controller.discardReason(u.state.selectedKey) !== null, true); assert.ok(metadataOwnerReason(u.state, 'another-project'));
  const late = { ...unknown, lateSettled: true }; u.publish(late, { reason: 'cleanup_unknown' }); assert.equal(u.state.edit.nativeBlocked, true);
  assert.equal(metadataProjectionProgress(unknown, { ...unknown, coreOutcome: { ...unknown.coreOutcome, effect: 'unknown' } }), false);
});

test('expiry, contradictory plan payloads and cross-domain blocks never restore Apply authority', async () => {
  const h = await connected(); const binding = await reviewing(h); h.advance(900001);
  assert.equal(h.controller.remainingReviewMs(), 0); assert.equal(h.controller.apply(binding), false);
  h.publish(owner(h, 'reviewing')); assert.equal(h.controller.remainingReviewMs(), 0);
  const other = await connected(); const apply = await reviewing(other); other.blockOther('Unverified configuration owner'); assert.equal(other.controller.apply(apply), false);
  const forged = clone(other.frame); forged.active.prepared.view.files[0].after.text = 'Another reviewed title';
  forged.active.prepared.view.files[0].after = { text: 'Another reviewed title', ...digest('Another reviewed title') };
  forged.active.prepared.view.files[0].lineEndingsChanged = true;
  other.emit(forged); assert.equal(other.state.edit.integrityFailed, true); assert.equal(other.controller.apply(apply), false);
});

function adoptObservedConfiguration(h, data) {
  const projectId = h.selected().project.id; const requestId = h.selected().observationGeneration + 1;
  h.dispatch({ type: 'snapshot-start', projectId, requestId });
  h.dispatch({ type: 'snapshot-done', projectId, requestId, snapshot: snapshot(data), observedAt: requestId });
  h.dispatch({ type: 'reset', projectId });
}
async function retainedPair({ values = texts(), targetValues = values, edits = { 'title.txt': 'Recovered title 😀\n' }, nextConfig, validateSource = false, nativeStatus } = {}) {
  const h = await connected({ nativeStatus }); const first = await load(h, observation('android', 'en-US', values));
  const sourceKey = first.context.key;
  for (const [id, text] of Object.entries(edits)) assert.equal(h.controller.editField(sourceKey, id, text), true);
  if (validateSource) await validate(h);
  const source = h.state.entries[sourceKey];
  const config = nextConfig ?? { ...clone(BASE), metadata: { ...clone(BASE.metadata), androidLocales: ['en-US', 'fr-FR', 'de-DE'] } };
  adoptObservedConfiguration(h, config);
  const current = h.state.choices.find((choice) => choice.platform === 'android' && choice.locale === 'en-US');
  assert.ok(current); assert.equal(h.state.selectedKey, sourceKey); assert.equal(h.controller.selectContext(current.key), true);
  const target = await load(h, observation('android', 'en-US', targetValues, config));
  return { h, sourceKey, targetKey: target.context.key, source, target, config };
}

test('retained draft preview adopts only edited fields in one local revision and preserves both baselines', async () => {
  const targetValues = [texts()[0], 'Externally improved summary.\r\n', '\ufeffNew full description.\r\n'];
  const { h, sourceKey, targetKey, source } = await retainedPair({ targetValues, validateSource: true });
  await validate(h); const target = h.controller.selectedEntry();
  const entries = h.state.entries; const workspace = h.workspace; const edit = h.state.edit; const calls = h.calls.length;
  let updates = 0; const unsubscribe = h.controller.subscribe(() => { updates += 1; });
  const review = h.controller.reviewRetainedDraft(sourceKey);
  assert.ok(review); assert.equal(h.controller.retainedDraftReviewReason(review), null);
  assert.equal(h.state.entries, entries); assert.equal(updates, 0); assert.equal(h.calls.length, calls);
  assert.ok(Object.isFrozen(review) && Object.isFrozen(review.binding.source) && Object.isFrozen(review.changes[0]));
  assert.deepEqual(review.changes, [{ id: 'title.txt', path: 'release/store/android/en-US/title.txt', before: texts()[0], after: 'Recovered title 😀\n' }]);
  assert.equal(review.target.key, targetKey); assert.equal(review.source.key, sourceKey);
  assert.throws(() => { review.changes[0].after = 'Unreviewed'; }, TypeError);
  const altered = clone(review); altered.changes[0].after = 'Unreviewed';
  assert.equal(h.controller.adoptRetainedDraft(altered), false); assert.equal(h.state.entries, entries);
  assert.equal(h.controller.adoptRetainedDraft(review), true); assert.equal(updates, 1);
  const current = h.controller.selectedEntry();
  assert.equal(current.revision, target.revision + 1); assert.equal(current.baselineGeneration, target.baselineGeneration);
  assert.equal(current.observationGeneration, target.observationGeneration); assert.equal(current.baseline, target.baseline);
  assert.equal(current.observation, target.observation); assert.equal(current.fields[0].text, 'Recovered title 😀\n');
  assert.equal(current.fields[1], target.fields[1]); assert.equal(current.fields[2], target.fields[2]);
  assert.equal(current.validation, null); assert.equal(current.validationRequest, null); assert.equal(current.validationError, null);
  assert.equal(current.lastSave, target.lastSave); assert.equal(h.state.entries[sourceKey], source);
  assert.ok(source.validation); assert.equal(h.workspace, workspace); assert.equal(h.state.edit, edit); assert.equal(h.calls.length, calls);
  const after = h.state.entries; assert.equal(h.controller.adoptRetainedDraft(review), false); assert.equal(h.state.entries, after);
  assert.equal(updates, 1); unsubscribe();
});

test('retained draft conflicts refuse the whole adoption rather than partially reusing fields', async () => {
  for (const conflicting of [0, 1]) {
    const values = ['Original title', 'Original summary', 'Original full text'];
    const targetValues = [...values]; targetValues[conflicting] = 'External change';
    const { h, sourceKey } = await retainedPair({ values, targetValues, edits: { 'title.txt': 'Local title', 'short_description.txt': 'Local summary' } });
    const entries = h.state.entries; const calls = h.calls.length;
    assert.match(h.controller.retainedDraftReason(sourceKey), new RegExp(METADATA_TEXT_IDS.android[conflicting].replaceAll('.', '\\.')));
    assert.equal(h.controller.reviewRetainedDraft(sourceKey), null); assert.equal(h.state.entries, entries); assert.equal(h.calls.length, calls);
    const compared = metadataCompareRetainedDraft(h.state.entries[sourceKey], h.controller.selectedEntry());
    assert.equal(compared.changes, null); assert.match(compared.reason, /No fields were reused/);
  }
});

test('retained draft comparisons distinguish absent from empty and preserve raw Unicode BOM and line endings', async () => {
  const replacement = '\ufeffNew 😀\r\nB\rC\n';
  for (const [before, current, allowed] of [[null, null, true], [null, '', false], ['', null, false], ['', '', true]]) {
    const { h, sourceKey, source } = await retainedPair({ values: [before, 'short', 'full'], targetValues: [current, 'new short', 'new full'], edits: { 'title.txt': replacement } });
    const target = h.controller.selectedEntry(); const review = h.controller.reviewRetainedDraft(sourceKey);
    assert.equal(review !== null, allowed);
    if (allowed) {
      assert.equal(review.changes[0].before, current); assert.equal(review.changes[0].after, replacement);
      assert.equal(h.controller.adoptRetainedDraft(review), true);
      assert.equal(h.controller.selectedEntry().fields[0].text, replacement);
      assert.equal(h.controller.selectedEntry().baseline.originals[0].text, current);
      assert.equal(h.controller.selectedEntry().baseline, target.baseline);
      assert.equal(h.state.entries[sourceKey], source); assert.equal(h.count('open'), 0);
    } else assert.match(h.controller.retainedDraftReason(sourceKey), /original comparison/);
  }
  const original = '\ufeffOld 😀\r\nB\rC\n';
  const same = await retainedPair({ values: [original, 'short', 'full'], edits: { 'title.txt': replacement } });
  const review = same.h.controller.reviewRetainedDraft(same.sourceKey);
  assert.equal(review.changes[0].before, original); assert.equal(same.h.controller.adoptRetainedDraft(review), true);
  const normalized = await retainedPair({ values: [original, 'short', 'full'], targetValues: [original.replace(/\r\n?/g, '\n'), 'short', 'full'], edits: { 'title.txt': replacement } });
  assert.equal(normalized.h.controller.reviewRetainedDraft(normalized.sourceKey), null);
});

test('retained draft comparisons refuse different identities incomplete rosters paths and oversized fields', async () => {
  const { source, target } = await retainedPair();
  const variants = [
    (s) => { s.context.projectId = 'other'; }, (s) => { s.context.metadataRoot = 'release/other'; },
    (s) => { s.context.platform = 'ios'; }, (s) => { s.context.locale = 'fr-FR'; },
    (s, t) => { s.context.configBaselineGeneration = t.context.configBaselineGeneration; },
    (s, t) => { s.context.configBaselineGeneration = t.context.configBaselineGeneration + 1; },
    (s, t) => { s.context.key = t.context.key; }, (s) => { s.baseline = null; }, (s) => { s.fields = null; },
    (s) => { s.fields.pop(); }, (s) => { s.baseline.originals[0].id = 'short_description.txt'; },
    (s) => { s.baseline.originals[0].path = 'release/store/android/en-US/other.txt'; },
    (s) => { s.fields[0].text = 'A'.repeat(32769); }, (s) => { s.fields[0].text = '\ud800'; },
    (_s, t) => { t.fields[0].text = 'Existing local target'; },
  ];
  for (const change of variants) {
    const s = clone(source); const t = clone(target); change(s, t);
    const compared = metadataCompareRetainedDraft(s, t); assert.notEqual(compared.reason, null); assert.equal(compared.changes, null);
  }
  const clean = clone(source); clean.fields[0].text = clean.baseline.originals[0].text;
  assert.match(metadataCompareRetainedDraft(clean, target).reason, /no unsaved/);
});

test('retained draft controller never changes project root platform or locale to find a target', async () => {
  for (const change of [
    async ({ h }) => { const next = h.state.choices.find((choice) => choice.locale === 'fr-FR'); h.controller.selectContext(next.key); await load(h); },
    async ({ h }) => { const next = h.state.choices.find((choice) => choice.platform === 'ios'); h.controller.selectContext(next.key); await load(h); },
    async ({ h, config }) => { h.add('b', config); await load(h); },
    async ({ h, config }) => { const changed = clone(config); changed.metadata.root = 'release/other'; adoptObservedConfiguration(h, changed); h.controller.selectContext(h.state.choices[0].key); await load(h); },
  ]) {
    const pair = await retainedPair(); await change(pair); const { h, sourceKey, source } = pair;
    const key = h.state.selectedKey; const entries = h.state.entries; const calls = h.calls.length;
    assert.match(h.controller.retainedDraftReason(sourceKey), /same project, metadata root, platform and locale/);
    assert.equal(h.controller.reviewRetainedDraft(sourceKey), null); assert.equal(h.state.selectedKey, key);
    assert.equal(h.state.entries, entries); assert.equal(h.state.entries[sourceKey], source); assert.equal(h.calls.length, calls);
  }
});

test('retained draft target must be clean successfully observed and free of load or edit errors', async () => {
  const cases = [
    async ({ h, targetKey }) => { h.controller.editField(targetKey, 'title.txt', 'Existing unsaved title'); },
    async ({ h }) => { h.controller.selectContext(h.state.choices.find((choice) => choice.locale === 'fr-FR').key); },
    async ({ h, config }) => { await load(h, observation('android', 'en-US', ['External title', 'short', 'full'], config)); },
    async ({ h }) => { const pending = h.controller.load(); h.last('observe').reject({ code: 'metadata_text_sensitive' }); assert.equal(await pending, false); },
    async ({ h, targetKey }) => { assert.equal(h.controller.editField(targetKey, 'title.txt', 'A'.repeat(32769)), false); },
    async ({ h }) => { const pending = h.controller.validate(); h.last('validate').reject({ code: 'MetadataTextResponseInvalid' }); assert.equal(await pending, false); },
    async ({ h }) => { h.dispatch({ type: 'edit', projectId: 'a', path: 'metadata.root', value: 'release/unsaved' }); },
    async ({ h, config }) => { h.dispatch({ type: 'snapshot-start', projectId: 'a', requestId: 90 }); const changed = clone(config); changed.metadata.root = 'release/observed'; h.dispatch({ type: 'snapshot-done', projectId: 'a', requestId: 90, snapshot: snapshot(changed), observedAt: 90 }); },
  ];
  for (const change of cases) {
    const pair = await retainedPair(); const review = pair.h.controller.reviewRetainedDraft(pair.sourceKey); assert.ok(review);
    await change(pair); const { h, sourceKey } = pair; const entries = h.state.entries; const calls = h.calls.length;
    assert.notEqual(h.controller.retainedDraftReason(sourceKey), null); assert.equal(h.controller.reviewRetainedDraft(sourceKey), null);
    assert.equal(h.controller.adoptRetainedDraft(review), false); assert.equal(h.state.entries, entries); assert.equal(h.calls.length, calls);
  }
});

test('retained draft pending and retired passive requests block adoption without issuing replacement work', async () => {
  for (const kind of ['observe', 'validate', 'retired-source-validation']) {
    const { h, sourceKey, targetKey } = await retainedPair(); const review = h.controller.reviewRetainedDraft(sourceKey);
    if (kind === 'retired-source-validation') h.controller.selectContext(sourceKey);
    const pending = kind === 'observe' ? h.controller.load() : h.controller.validate();
    const call = h.last(kind === 'observe' ? 'observe' : 'validate');
    if (kind === 'retired-source-validation') h.controller.selectContext(targetKey);
    const entries = h.state.entries; const calls = h.calls.length;
    assert.match(h.controller.retainedDraftReason(sourceKey), /still pending/); assert.equal(h.controller.adoptRetainedDraft(review), false);
    assert.equal(h.state.entries, entries); assert.equal(h.calls.length, calls);
    call.resolve(kind === 'observe' ? observation('android', 'en-US', texts(), h.selected().baseline) : validation('android', call.args.fields));
    assert.equal(await pending, kind !== 'retired-source-validation');
    assert.equal(h.controller.adoptRetainedDraft(review), false); assert.ok(h.controller.reviewRetainedDraft(sourceKey));
  }
});

test('retained draft stale confirmations refuse revision selection configuration service and observation ABA changes', async () => {
  const changes = [
    async ({ h, sourceKey, source }) => { h.controller.editField(sourceKey, 'title.txt', 'Another draft'); h.controller.editField(sourceKey, 'title.txt', source.fields[0].text); },
    async ({ h, targetKey }) => { h.controller.editField(targetKey, 'title.txt', 'Temporary target'); assert.equal(h.controller.discard(h.controller.discardBinding(targetKey), 'reset'), true); },
    async ({ h, targetKey }) => { h.controller.selectContext(h.state.choices.find((choice) => choice.locale === 'fr-FR').key); h.controller.selectContext(targetKey); },
    async ({ h, targetKey }) => { h.add('b'); h.dispatch({ type: 'switch', projectId: 'a' }); h.controller.selectContext(targetKey); },
    async ({ h }) => { h.controller.setSelectionPending(true); h.controller.setSelectionPending(false); },
    async ({ h }) => { h.controller.beginConnection(); h.controller.setConnection(h.api, h.info); h.controller.setHelp(guideResource); },
    async ({ h, config }) => { h.dispatch({ type: 'edit', projectId: 'a', path: 'metadata.androidLocales', value: ['en-US'] }); h.dispatch({ type: 'edit', projectId: 'a', path: 'metadata.androidLocales', value: config.metadata.androidLocales }); },
    async ({ h, config }) => { h.dispatch({ type: 'snapshot-start', projectId: 'a', requestId: 90 }); h.dispatch({ type: 'snapshot-done', projectId: 'a', requestId: 90, snapshot: snapshot(config), observedAt: 90 }); },
    async ({ h }) => { await load(h); },
    async ({ h, targetKey }) => { assert.equal(h.controller.discard(h.controller.discardBinding(targetKey), 'forget'), true); await load(h); },
    async ({ h, sourceKey }) => { assert.equal(h.controller.discard(h.controller.discardBinding(sourceKey), 'forget'), true); },
    async ({ h }) => { h.emit(status(h.frame.statusRevision + 1)); },
  ];
  for (const change of changes) {
    const pair = await retainedPair(); const review = pair.h.controller.reviewRetainedDraft(pair.sourceKey); assert.ok(review);
    await change(pair); const { h } = pair; const entries = h.state.entries; const calls = h.calls.length;
    assert.notEqual(h.controller.retainedDraftReviewReason(review), null);
    assert.equal(h.controller.adoptRetainedDraft(review), false); assert.equal(h.state.entries, entries); assert.equal(h.calls.length, calls);
  }
  const disposed = await retainedPair(); const review = disposed.h.controller.reviewRetainedDraft(disposed.sourceKey);
  disposed.h.controller.dispose(); assert.equal(disposed.h.controller.adoptRetainedDraft(review), false);
});

test('retained draft original active Unknown recovery and other-domain owners remain blocking', async () => {
  for (const kind of ['active', 'unknown', 'recovery', 'other-edit', 'other-operation', 'integrity']) {
    const { h, sourceKey, targetKey } = await retainedPair(); const review = h.controller.reviewRetainedDraft(sourceKey);
    if (kind === 'other-edit') h.blockOther('Original configuration edit is unsettled');
    else if (kind === 'other-operation') h.blockOperation('Original native read is unsettled');
    else if (kind === 'integrity') { const invalid = clone(h.frame); invalid.domain = 'github_workflows'; h.emit(invalid); }
    else {
      h.controller.editField(targetKey, 'title.txt', 'Original owner edit');
      await validate(h); assert.equal(h.controller.start(), true);
      if (kind !== 'active') {
        h.publish(owner(h, 'editing')); h.publish(owner(h, 'reviewing'));
        assert.equal(h.controller.apply(currentMetadataApplyBinding(h.state)), true);
        h.publish(owner(h, kind === 'unknown' ? 'unknown' : 'final', {
          coreOutcome: { effect: 'committed', journal: kind === 'recovery' ? 'recovery_required' : 'clean', resources: 'settled', reason: kind === 'recovery' ? 'filesystem_error' : 'none' },
          nativeReason: kind === 'unknown' ? 'cleanup_unknown' : 'none',
        }), { reason: kind === 'unknown' ? 'cleanup_unknown' : 'available' });
      }
    }
    const entries = h.state.entries; const calls = h.calls.length;
    assert.notEqual(h.controller.retainedDraftReason(sourceKey), null); assert.equal(h.controller.reviewRetainedDraft(sourceKey), null);
    assert.equal(h.controller.adoptRetainedDraft(review), false); assert.equal(h.state.entries, entries); assert.equal(h.calls.length, calls);
    if (kind === 'unknown') assert.equal(h.state.edit.nativeBlocked, true);
    if (kind === 'recovery') assert.equal(h.state.edit.recoveryProjects.includes('a'), true);
  }
});

test('retained draft aggregate cache overflow preserves every bundle and exhausted counters are not reused', async () => {
  const config = clone(BASE); config.ios.enabled = false;
  const locales = Array.from({ length: 28 }, (_, index) => `a${String.fromCharCode(97 + index % 26)}${index >= 26 ? 'a' : ''}`);
  config.metadata.androidLocales = ['en-US', ...locales];
  const full = 'A'.repeat(32768);
  const pair = await retainedPair({ values: ['a', 'b', 'c'], edits: Object.fromEntries(METADATA_TEXT_IDS.android.map((id) => [id, full])), nextConfig: config });
  const { h, sourceKey, targetKey } = pair;
  for (const choice of h.state.choices.filter((row) => row.key !== targetKey)) { h.controller.selectContext(choice.key); await load(h, observation('android', choice.locale, Array(3).fill(full), config)); }
  h.controller.selectContext(targetKey); const review = h.controller.reviewRetainedDraft(sourceKey); assert.ok(review);
  const entries = h.state.entries; const calls = h.calls.length;
  assert.equal(Object.keys(entries).length, 30); assert.ok(metadataCacheBytes(entries) <= 8388608);
  assert.equal(h.controller.adoptRetainedDraft(review), false); assert.equal(h.state.cacheError.code, 'MetadataTextCacheFull');
  assert.equal(h.state.entries, entries); assert.equal(h.calls.length, calls); assert.equal(h.state.entries[targetKey].revision, pair.target.revision);
  // Inert counter-boundary fixtures only; reaching these values by billions of
  // UI actions is unnecessary. No native status or settlement is fabricated.
  for (const exhaust of [
    ({ h }) => { h.controller.state = { ...h.state, serviceGeneration: 0xffffffff }; },
    ({ h }) => { h.controller.nextRequest = 0xffffffff; },
    ({ h, sourceKey }) => { h.controller.state = { ...h.state, entries: { ...h.state.entries, [sourceKey]: { ...h.state.entries[sourceKey], revision: 0xffffffff } } }; },
    ({ h, targetKey }) => { h.controller.state = { ...h.state, entries: { ...h.state.entries, [targetKey]: { ...h.state.entries[targetKey], revision: 0xfffffffe } } }; },
  ]) {
    const current = await retainedPair(); const old = current.h.controller.reviewRetainedDraft(current.sourceKey); exhaust(current);
    const before = current.h.state.entries;
    assert.match(current.h.controller.retainedDraftReason(current.sourceKey), /counter is exhausted/);
    assert.equal(current.h.controller.adoptRetainedDraft(old), false); assert.equal(current.h.state.entries, before);
  }
});

test('retained draft still requires fresh validation and a separate native save bound to the new baseline', async () => {
  const { h, sourceKey, source, target } = await retainedPair();
  const review = h.controller.reviewRetainedDraft(sourceKey); assert.equal(h.controller.adoptRetainedDraft(review), true);
  assert.equal(h.count('validate'), 0); assert.equal(h.count('open'), 0); assert.equal(h.count('prepare'), 0); assert.equal(h.count('apply'), 0);
  assert.match(h.controller.startReason(), /Validate this exact text revision/); assert.equal(h.controller.start(), false);
  await validate(h); assert.equal(h.controller.start(), true);
  assert.deepEqual(h.last('open').args, { projectId: target.context.projectId, platform: target.context.platform, locale: target.context.locale });
  h.publish(owner(h, 'editing')); h.publish(owner(h, 'reviewing'));
  assert.deepEqual(h.last('prepare').args.expectedBaseline, target.baseline.assertion);
  assert.notEqual(h.last('prepare').args.expectedBaseline.config.sha256, source.baseline.assertion.config.sha256);
  assert.equal(h.last('prepare').args.draftRevision, target.revision + 1);
  assert.equal(h.last('prepare').args.fields[0].text, review.changes[0].after); assert.equal(h.count('apply'), 0);
  assert.equal(h.controller.apply(currentMetadataApplyBinding(h.state)), true); h.publish(owner(h, 'final'));
  assert.equal(metadataTextSavedFresh(h.controller.selectedEntry()), true); assert.equal(h.state.entries[sourceKey], source);
  assert.match(h.controller.retainedDraftReason(sourceKey), /successfully observed target/);
  const unavailable = await retainedPair({ nativeStatus: status(0, null, null, 'runtime_unqualified') });
  const local = unavailable.h.controller.reviewRetainedDraft(unavailable.sourceKey); assert.ok(local);
  assert.equal(unavailable.h.controller.adoptRetainedDraft(local), true); await validate(unavailable.h);
  assert.equal(unavailable.h.controller.start(), false); assert.equal(unavailable.h.count('open'), 0);
});
