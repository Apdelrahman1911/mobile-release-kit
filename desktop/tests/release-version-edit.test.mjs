// Inert DATA/controlled-promise regressions only. No DOM, project files,
// native processes, tools, Store, recovery or platform qualification evidence.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import guideResource from '../../src/mobile_release/api/data/release-version-help-v1.json' with { type: 'json' };
import { parseSavedTextRecoveryView, parseSavedTextRecoveryProjection, savedTextRecoveryEffect, savedTextRecoverySucceeded } from '../src/savedTextRecovery.ts';
import { createNativeApi } from '../src/bridge.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { previewApi } from '../src/preview.ts';
import { normalVersionEditResult, parseVersionEditGuide, parseVersionEditStatus, versionEditRequestFits,
  versionLineEndings, versionNoOp, versionProjectionProgress, versionValuesBounded } from '../src/releaseVersionEdit.ts';
import { ReleaseVersionEditController, currentVersionApplyBinding, versionDraftDirty, versionOwnerReason,
  versionPreparedMatches, versionProjectDirty, versionRetainsDraft } from '../src/releaseVersionEditController.ts';

const ID = { window: 'a'.repeat(32), session: 'b'.repeat(32), revision: 'c'.repeat(32), plan: 'd'.repeat(32) };
const SOURCE = 'public/version.properties';
const BASE = { schemaVersion: 1, version: { source: SOURCE, nameKey: 'VERSION_NAME', buildKey: 'BUILD_NUMBER' }, ios: { enabled: true } };
const ORIGINAL = "# Keep café\r\nVERSION_NAME='1.2.3'\nBUILD_NUMBER = \"7\"\r\nOTHER=keep";
const VALUES = { name: '2.3.4', build: '8' };
const clone = (value) => structuredClone(value);
const digest = (text) => ({ bytes: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex') });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 16; i += 1) await Promise.resolve(); };
function snapshot() {
  return { root: '/inert-not-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { content: null, path: 'release/mobile-release.json', state: 'format-valid', data: clone(BASE), issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
      gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' }, issues: [] };
}
function addProject(workspace, id = 'p') {
  workspace = workspaceReducer(workspace, { type: 'select', project: { id, name: 'Inert ' + id, path: '/inert-not-opened' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: id, requestId: 1 });
  return workspaceReducer(workspace, { type: 'snapshot-done', projectId: id, requestId: 1, snapshot: snapshot(), observedAt: 0 });
}
function checkout(raw = ORIGINAL, values = { name: '1.2.3', build: '7' }, options = {}) {
  return { revision: ID.revision, source: SOURCE, nameKey: 'VERSION_NAME', buildKey: 'BUILD_NUMBER', iosEnabled: true,
    values: raw === null ? null : clone(values), baseline: { savedConfig: digest(JSON.stringify(BASE)),
      savedVersion: raw === null ? { state: 'absent' } : { state: 'present', ...digest(raw) } }, ...options };
}
function view(opened, before = ORIGINAL, values = VALUES) {
  // Explicit inert fixture substitution, not a second version parser/serializer.
  const after = before === null ? opened.nameKey + '=' + values.name + '\n' + opened.buildKey + '=' + values.build + '\n' :
    before.replace("'" + opened.values.name + "'", "'" + values.name + "'").replace('"' + opened.values.build + '"', '"' + values.build + '"');
  const final = (text) => /[\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029]$/.test(text ?? '');
  return { schemaVersion: 1, source: opened.source, nameKey: opened.nameKey, buildKey: opened.buildKey, iosEnabled: opened.iosEnabled,
    intent: before === null ? 'create' : 'edit', values: clone(values),
    file: { path: opened.source, action: before === null ? 'create' : after === before ? 'preserve' : 'replace',
      before: before === null ? { state: 'absent' } : { state: 'present', text: before, ...digest(before) },
      after: { text: after, ...digest(after) }, requestedMode: 0o644, preserveMode: before !== null },
    createDirectories: before === null ? ['public'] : [],
    lineEndings: { before: versionLineEndings(before ?? ''), after: versionLineEndings(after), finalNewlineBefore: final(before),
      finalNewlineAfter: final(after), preserved: before !== null },
    validation: { valid: true, state: 'format-valid', issues: [] } };
}
function status(revision = 0, active = null, lastTerminal = null, reason = 'available') {
  return { schemaVersion: 1, domain: 'release_version', windowGeneration: ID.window, statusRevision: revision,
    capability: { available: reason === 'available', reason }, active, lastTerminal };
}
function projection(phase, opened = checkout(), preparedView = view(opened, opened.values === null ? null : ORIGINAL), options = {}) {
  const hasPrepared = ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  return { domain: 'release_version', projectId: 'p', sessionId: ID.session, ownerGeneration: ID.window,
    phase, reviewRemainingMs: 900000, checkout: phase === 'opening' ? null : clone(opened),
    prepared: hasPrepared ? { revision: opened.revision, planToken: ID.plan, draftRevision: 2, baselineGeneration: 0, view: preparedView } : null,
    applySubmitted: ['applying', 'finalizing', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: versionNoOp(preparedView) ? 'unchanged' : 'committed',
      journal: versionNoOp(preparedView) ? 'not_created' : 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false, ...options };
}
function harness({ raw = ORIGINAL, opened = checkout(raw), nativeStatus = status(), onSaveBoundary = () => {} } = {}) {
  let workspace = addProject(initialWorkspace), registry = clone(nativeStatus), listener, clock = 100, other = null, operation = null;
  let sessionId = ID.session; const calls = [], boundaries = [], reads = [];
  const selected = () => workspace.projects[workspace.selectedId] ?? null;
  const request = (kind, args) => { const pending = deferred(); calls.push({ kind, args: clone(args), ...pending }); return pending.promise; };
  const api = { mode: 'native',
    subscribeReleaseVersionEdit: async (receive) => { listener = receive; calls.push({ kind: 'subscribe' }); return () => { listener = null; }; },
    releaseVersionEditStatus: () => { calls.push({ kind: 'status' }); return reads.length ? reads.shift().promise : Promise.resolve(clone(registry)); },
    openReleaseVersionEdit: (input) => request('open', input), prepareReleaseVersionEdit: (input) => request('prepare', input),
    applyReleaseVersionEdit: (sessionId, planToken, intent) => request('apply', intent === undefined ? { sessionId, planToken } : { sessionId, planToken, intent }), closeReleaseVersionEdit: (sessionId) => request('close', { sessionId }),
  };
  const controller = new ReleaseVersionEditController({ selectedProject: selected, project: (id) => workspace.projects[id] ?? null,
    otherEditReason: () => other, otherOperationReason: () => operation, now: () => clock,
    onSaveBoundary: (id) => { boundaries.push(id); onSaveBoundary(id); } });
  controller.beginConnection(); controller.setHelp(guideResource); controller.syncProject();
  const h = { controller, api, selected, calls, boundaries,
    get state() { return controller.getSnapshot(); }, get workspace() { return workspace; }, get frame() { return registry; },
    count: (kind) => calls.filter((call) => call.kind === kind).length, last: (kind) => calls.filter((call) => call.kind === kind).at(-1),
    dispatch: (action) => {
      controller.beforeWorkspaceAction(action); const next = workspaceReducer(workspace, action);
      if (workspace === next) return; workspace = next; controller.syncProject();
    },
    add: (id) => { controller.selectionIntent(); workspace = addProject(workspace, id); controller.syncProject(); },
    other: (value) => { other = value; }, operation: (value) => { operation = value; }, advance: (amount) => { clock += amount; },
    deferStatus: () => { const value = deferred(); reads.push(value); return value; },
    original: (nextRaw, nextOpened, nextSession = 'e'.repeat(32)) => { raw = nextRaw; opened = clone(nextOpened); sessionId = nextSession; },
    emit: (value) => { registry = clone(value); assert.ok(listener); listener(clone(value)); },
    owner: (phase, options = {}) => {
      const input = h.state.edit.attempt?.submission, candidate = view(opened, raw, input?.values ?? VALUES);
      const owner = projection(phase, opened, candidate, { sessionId, projectId: h.state.edit.attempt?.binding.projectId ?? 'p', ...options });
      if (owner.prepared && input) { owner.prepared.draftRevision = input.draftRevision; owner.prepared.baselineGeneration = input.baselineGeneration; }
      return owner;
    },
    publish: (owner, options = {}) => {
      const terminal = owner.phase === 'final' || owner.lateSettled;
      const value = status(options.revision ?? registry.statusRevision + 1, terminal ? null : owner,
        terminal ? owner : registry.lastTerminal, options.reason ?? registry.capability.reason);
      h.emit(value); return value;
    },
    closeFinal: () => {
      const previous = h.state.edit.attempt.projection;
      h.publish({ ...clone(previous), phase: 'final', nativeFinality: 'settled', nativeReason: 'discarded',
        coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'none' } });
    },
  };
  return h;
}
async function connected(options) { const h = harness(options); await h.controller.connect(h.api); return h; }
async function openSaved(h) {
  assert.equal(h.controller.openReason(), null); assert.equal(h.controller.open(), true); assert.deepEqual(h.last('open').args, { projectId: 'p' });
  h.publish(h.owner('opening')); h.publish(h.owner('editing')); assert.ok(h.controller.selectedEntry()); return h.controller.selectedEntry();
}
async function reviewing(h, { unchanged = false } = {}) {
  await openSaved(h);
  if (!unchanged) { h.controller.editField('name', VALUES.name); h.controller.editField('build', VALUES.build); }
  assert.equal(h.controller.reviewReason(), null); assert.equal(h.controller.review(), true); assert.equal(h.count('prepare'), 1);
  h.publish(h.owner('reviewing')); assert.ok(versionPreparedMatches(h.state.edit.attempt));
  const binding = currentVersionApplyBinding(h.state); assert.ok(binding); return binding;
}

test('closed guide and two-string request bounds; policy-invalid strings are not trimmed or coerced', () => {
  assert.ok(parseVersionEditGuide(guideResource));
  const malformedGuide = clone(guideResource); malformedGuide.limits.maxNameBytes = 65; assert.equal(parseVersionEditGuide(malformedGuide), null);
  const input = { sessionId: ID.session, revision: ID.revision, expectedBaseline: checkout().baseline,
    intent: 'edit', values: VALUES, draftRevision: 0, baselineGeneration: 0 };
  assert.equal(versionEditRequestFits('release_version_edit_prepare', input), true);
  // These are bounded DATA, not renderer policy admission: core rejects invalid policy.
  assert.equal(versionValuesBounded({ name: ' 1.2 ', build: '0' }), true);
  assert.equal(versionValuesBounded({ name: 'x'.repeat(64) + '\n', build: '7' }), false);
  for (const mutate of [(v) => { v.root = '/inert'; }, (v) => { v.values.build = 8; }, (v) => { v.values.build = '7\n'; },
    (v) => { v.values.name = 'é'; }, (v) => { v.values.build = '1'.repeat(11); }, (v) => { v.values.extra = true; },
    (v) => { v.intent = 'create'; }, (v) => { v.draftRevision = 0xffffffff; }, (v) => { v.baselineGeneration = -1; },
    (v) => { v.sessionId += '\n'; }, (v) => { v.expectedBaseline.savedConfig.sha256 += '\n'; }]) {
    const value = clone(input); mutate(value); assert.equal(versionEditRequestFits('release_version_edit_prepare', value), false);
  }
  for (const projectId of ['../p', 'p\n', 'p\r', '', 'x'.repeat(65)]) assert.equal(versionEditRequestFits('release_version_edit_open', { projectId }), false);
  for (const extra of ['root', 'source', 'nameKey', 'buildKey', 'iosEnabled', 'draft']) assert.equal(versionEditRequestFits('release_version_edit_open', { projectId: 'p', [extra]: 'never' }), false);
  let getters = 0; const accessor = { get projectId() { getters += 1; return 'p'; } };
  assert.equal(versionEditRequestFits('release_version_edit_open', accessor), false); assert.equal(getters, 0);
  const cycle = {}; cycle.self = cycle; assert.equal(versionEditRequestFits('release_version_edit_status', cycle), false);
});

test('Open admits unambiguous policy-invalid originals and only explicit absence/null enables Create', () => {
  const invalid = checkout("VERSION_NAME='bad'\nBUILD_NUMBER=\"0\"\n", { name: 'bad', build: '0' });
  assert.ok(parseVersionEditStatus(status(1, projection('editing', invalid))));
  const long = checkout("VERSION_NAME='" + 'x'.repeat(200) + "'\nBUILD_NUMBER=\"0\"\n", { name: 'x'.repeat(200), build: '0' });
  assert.ok(parseVersionEditStatus(status(1, projection('editing', long))));
  const absent = status(1, projection('editing', checkout(null))); assert.ok(parseVersionEditStatus(absent));
  for (const mutate of [(v) => { delete v.active.checkout.values; }, (v) => { v.active.checkout.values = { name: '', build: '' }; },
    (v) => { v.active.checkout.baseline.savedVersion.text = ''; }, (v) => { v.active.checkout.baseline.savedVersion.state = 'unreadable'; }]) {
    const bad = clone(absent); mutate(bad); assert.equal(parseVersionEditStatus(bad), null);
  }
  const present = status(1, projection('editing'));
  for (const mutate of [(v) => { v.active.checkout.values = null; }, (v) => { v.active.checkout.values.build += '\n'; },
    (v) => { v.active.checkout.baseline.savedVersion.bytes = 0; }, (v) => { v.active.checkout.source = 'RELEASE/MOBILE-RELEASE.JSON'; },
    (v) => { v.active.checkout.nameKey += '\n'; }, (v) => { v.active.checkout.scopeResources = 'settled'; }]) {
    const bad = clone(present); mutate(bad); assert.equal(parseVersionEditStatus(bad), null);
  }
});

test('review includes full bytes, exact action/mode/ancestor suffix and complete separator facts', () => {
  const original = checkout(), review = status(2, projection('reviewing', original));
  assert.ok(parseVersionEditStatus(review)); assert.equal(review.active.prepared.view.file.before.text, ORIGINAL);
  assert.deepEqual(review.active.prepared.view.lineEndings.before, ['crlf', 'lf']);
  const absent = checkout(null, null, { source: 'public/nested/version.properties' });
  const create = view(absent, null); create.createDirectories = ['public/nested'];
  assert.ok(parseVersionEditStatus(status(2, projection('reviewing', absent, create))));
  assert.equal(create.file.after.text, 'VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n');
  const wrongSuffix = clone(create); wrongSuffix.createDirectories = ['public']; assert.equal(parseVersionEditStatus(status(2, projection('reviewing', absent, wrongSuffix))), null);
  for (const mutate of [(v) => { v.file.path = 'other/version.properties'; }, (v) => { v.file.after.bytes += 1; },
    (v) => { v.file.action = 'preserve'; }, (v) => { v.file.preserveMode = false; }, (v) => { v.createDirectories = ['public']; },
    (v) => { v.lineEndings.after = ['lf']; }, (v) => { v.lineEndings.finalNewlineAfter = true; }, (v) => { v.file.before.sha256 = '0'.repeat(64); },
    (v) => { v.file.requestedMode = 0o1000; }, (v) => { v.validation.issues = [{ code: 'unexpected' }]; }, (v) => { v.platform = 'ios'; }]) {
    const bad = clone(review); mutate(bad.active.prepared.view); assert.equal(parseVersionEditStatus(bad), null);
  }
  const separators = '\r\n\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029';
  assert.deepEqual(versionLineEndings(separators), ['crlf', 'lf', 'cr', 'vt', 'ff', 'fs', 'gs', 'rs', 'nel', 'ls', 'ps']);
});

test('settled success requires original action and separate finality; cross-domain and missing keys refuse', () => {
  const saved = projection('final'); assert.equal(normalVersionEditResult(saved), 'saved');
  assert.ok(parseVersionEditStatus(status(4, null, saved)));
  const noop = projection('final', checkout(), view(checkout(), ORIGINAL, { name: '1.2.3', build: '7' }));
  assert.equal(normalVersionEditResult(noop), 'unchanged'); assert.ok(parseVersionEditStatus(status(4, null, noop)));
  for (const mutate of [(v) => { v.domain = 'metadata_text'; }, (v) => { delete v.lastTerminal.prepared; },
    (v) => { v.lastTerminal.applySubmitted = false; }, (v) => { v.lastTerminal.coreOutcome.effect = 'unchanged'; },
    (v) => { v.lastTerminal.prepared.planToken = ID.revision; }, (v) => { v.lastTerminal.nativeFinality = 'pending'; },
    (v) => { v.lastTerminal.lateSettled = true; }, (v) => { v.windowGeneration += '\n'; }, (v) => { v.statusRevision = 1.5; }]) {
    const bad = status(4, null, clone(saved)); mutate(bad); assert.equal(parseVersionEditStatus(bad), null);
  }
  const unknown = { ...clone(saved), phase: 'unknown', nativeFinality: 'unknown', nativeReason: 'cleanup_unknown' };
  assert.equal(normalVersionEditResult(unknown), null);
  assert.equal(versionProjectionProgress(unknown, saved), false);
  assert.equal(versionProjectionProgress(saved, { ...saved, coreOutcome: { ...saved.coreOutcome, effect: 'unknown' } }), false);
});

test('native bridge only routes closed version commands; preview never pretends to open or save', async () => {
  const calls = [], events = []; const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return status(); },
    async (event) => { events.push(event); return () => {}; });
  await api.openReleaseVersionEdit({ projectId: 'p' }); assert.deepEqual(calls, [{ command: 'release_version_edit_open', args: { projectId: 'p' } }]);
  await api.subscribeReleaseVersionEdit(() => {}); assert.deepEqual(events, ['release-version-edit-status']);
  await assert.rejects(api.openReleaseVersionEdit({ projectId: 'p', source: SOURCE }), (error) => error.code === 'VersionEditInvalid');
  assert.equal(calls.length, 1);
  const malformed = createNativeApi('native', async () => ({ ...status(), domain: 'metadata_text' }));
  await assert.rejects(malformed.releaseVersionEditStatus(), (error) => error.code === 'VersionEditStatusInvalid');
  for (const name of ['openReleaseVersionEdit', 'prepareReleaseVersionEdit', 'applyReleaseVersionEdit', 'closeReleaseVersionEdit', 'releaseVersionEditStatus', 'subscribeReleaseVersionEdit'])
    await assert.rejects(previewApi[name]({ projectId: 'p' }), (error) => error.code === 'VersionEditUnavailable');
  const h = harness(); await h.controller.connect(previewApi); assert.notEqual(h.controller.openReason(), null); assert.equal(h.controller.open(), false);
});

test('explicit Open -> Review -> Apply saves only submitted strings and never the unsaved configuration', async () => {
  const h = await connected();
  h.dispatch({ type: 'edit', projectId: 'p', path: 'version.source', value: 'public/unsaved.properties' });
  assert.equal(isDirty(h.selected()), true);
  const binding = await reviewing(h), before = clone(h.selected().draft);
  assert.equal(h.controller.open(), false); assert.equal(h.count('open'), 1);
  const request = h.last('prepare').args;
  assert.deepEqual(Object.keys(request).sort(), ['sessionId', 'revision', 'expectedBaseline', 'intent', 'values', 'draftRevision', 'baselineGeneration'].sort());
  assert.deepEqual(request.values, VALUES); assert.equal(request.intent, 'edit'); assert.deepEqual(request.expectedBaseline, checkout().baseline);
  assert.equal(h.controller.apply({ ...binding, planToken: 'e'.repeat(32) }), false);
  assert.equal(h.controller.apply(binding), true); assert.equal(h.controller.apply(binding), false); assert.equal(h.count('apply'), 1);
  h.publish(h.owner('applying')); h.publish(h.owner('final'));
  const entry = h.controller.selectedEntry();
  assert.equal(versionDraftDirty(entry), false); assert.equal(entry.stale, false); assert.equal(normalVersionEditResult(entry.outcome), 'saved');
  assert.deepEqual(entry.original.values, VALUES); assert.equal(entry.original.baseline.savedVersion.sha256, entry.outcome.prepared.view.file.after.sha256);
  assert.deepEqual(h.selected().draft, before); assert.deepEqual(h.selected().baseline, BASE); assert.equal(isDirty(h.selected()), true);
  assert.deepEqual(h.boundaries, ['p', 'p', 'p']);
  const generation = entry.baselineGeneration; h.publish(clone(entry.outcome)); assert.equal(h.controller.selectedEntry().baselineGeneration, generation);
});

test('explicit Create requires absent Open; no-op still has one-use intent/outcome invalidation', async () => {
  const create = await connected({ raw: null }); const binding = await reviewing(create);
  assert.equal(create.last('prepare').args.intent, 'create'); assert.equal(create.state.edit.attempt.projection.prepared.view.file.action, 'create');
  create.controller.apply(binding); create.publish(create.owner('final'));
  assert.deepEqual(create.controller.selectedEntry().original.values, VALUES);
  const noop = await connected(); const apply = await reviewing(noop, { unchanged: true });
  assert.equal(versionNoOp(noop.state.edit.attempt.projection.prepared.view), true); noop.controller.apply(apply); noop.publish(noop.owner('final'));
  assert.equal(normalVersionEditResult(noop.controller.selectedEntry().outcome), 'unchanged'); assert.deepEqual(noop.boundaries, ['p', 'p', 'p']);
  assert.equal(noop.controller.selectedEntry().baselineGeneration, 1);
});

test('all pre-Apply selection/refresh/config/navigation/draft/reconnect intentions retire synchronously', async () => {
  const actions = [
    (h) => { h.dispatch({ type: 'switch', projectId: 'p' }); },
    (h) => { h.add('q'); h.dispatch({ type: 'switch', projectId: 'p' }); },
    (h) => { const previous = h.workspace; h.dispatch({ type: 'snapshot-failed', projectId: 'p', requestId: 999, error: { code: 'inert', message: '', retryable: false } }); assert.equal(h.workspace, previous); },
    (h) => { h.controller.snapshotIntent('p'); },
    (h) => { h.dispatch({ type: 'config-save-intent', projectId: 'p' }); },
    (h) => { h.controller.beforeWorkspaceAction({ type: 'config-save-final', projectId: 'p' }); },
    (h) => { h.controller.beforeWorkspaceAction({ type: 'config-save-recovery', projectId: 'p' }); },
    (h) => { h.controller.setVisible(false); h.controller.setVisible(true); },
    (h) => { h.controller.setSelectionPending(true); h.controller.setSelectionPending(false); },
    (h) => { h.controller.editField('name', '3.4.5'); },
    (h) => { h.dispatch({ type: 'edit', projectId: 'p', path: 'version.nameKey', value: 'UNSAVED_NAME' }); },
    (h) => { h.controller.beginConnection(); },
    (h) => { h.controller.shutdownIntent(); },
  ];
  for (const action of actions) {
    const h = await connected(), binding = await reviewing(h); const original = clone(h.state.edit.attempt.projection);
    action(h); assert.equal(h.state.edit.attempt.invalidated, true); assert.equal(h.count('close'), 1);
    h.publish(original); assert.equal(h.controller.apply(binding), false); assert.equal(h.count('apply'), 0); assert.equal(h.count('open'), 1);
  }
});

test('reopening binds the retained expected baseline; stale Open closes and only explicit reload can rebase', async () => {
  const h = await connected(); await openSaved(h); h.controller.editField('name', '2.3.4');
  const retained = h.controller.selectedEntry().original; h.controller.requestClose(); h.closeFinal();
  const differentRaw = ORIGINAL.replace("'1.2.3'", "'9.8.7'");
  h.original(differentRaw, checkout(differentRaw, { name: '9.8.7', build: '7' }, { revision: 'f'.repeat(32) }));
  assert.equal(h.controller.review(), true); h.publish(h.owner('editing'));
  assert.equal(h.count('prepare'), 0); assert.equal(h.count('close'), 2); assert.equal(h.controller.selectedEntry().stale, true);
  assert.equal(h.controller.selectedEntry().original, retained); assert.equal(h.controller.selectedEntry().values.name, '2.3.4');
  h.closeFinal(); assert.notEqual(h.controller.reviewReason(), null);
  const reset = h.controller.resetBinding(); assert.ok(reset);
  assert.equal(h.controller.reload({ ...reset, revision: reset.revision + 1 }), false);
  h.original(differentRaw, checkout(differentRaw, { name: '9.8.7', build: '7' }, { revision: '1'.repeat(32) }), '2'.repeat(32));
  assert.equal(h.controller.reload(reset), true); h.publish(h.owner('editing'));
  assert.equal(h.controller.selectedEntry().stale, false); assert.equal(h.controller.selectedEntry().values.name, '9.8.7');
  assert.equal(h.controller.selectedEntry().baselineGeneration, 1);
});

test('edits after confirmed Reload retire only its pending Open and retain the newer draft', async () => {
  for (const openingObserved of [false, true]) {
    const h = await connected(); await openSaved(h); h.controller.editField('name', '2.3.4');
    h.controller.requestClose(); h.closeFinal();
    const original = h.controller.selectedEntry().original, reset = h.controller.resetBinding();
    const differentRaw = ORIGINAL.replace("'1.2.3'", "'9.8.7'");
    h.original(differentRaw, checkout(differentRaw, { name: '9.8.7', build: '7' }, { revision: 'f'.repeat(32) }));
    assert.equal(h.controller.reload(reset), true); assert.equal(h.count('open'), 2);
    if (openingObserved) h.publish(h.owner('opening'));
    assert.equal(h.controller.editField('name', '3.4.5'), true);
    const newer = h.controller.selectedEntry();
    assert.equal(newer.revision, reset.revision + 1); assert.equal(newer.baselineGeneration, reset.baselineGeneration);
    assert.equal(newer.original, original); assert.deepEqual(newer.values, { name: '3.4.5', build: '7' });
    assert.equal(h.state.edit.attempt.invalidated, true); assert.equal(h.state.edit.attempt.closeRequested, true);
    assert.equal(h.state.edit.attempt.submission, null); assert.equal(h.count('close'), openingObserved ? 2 : 1);
    const late = status(h.frame.statusRevision + 1, h.owner('editing'), h.frame.lastTerminal);
    h.last('open').resolve(late); await flush(); h.emit(late); // Same original reply/event, not another Open.
    assert.equal(h.controller.selectedEntry(), newer); assert.equal(h.state.edit.attempt.openAdopted, false);
    assert.equal(h.count('close'), 2); assert.equal(h.last('close').args.sessionId, late.active.sessionId);
    assert.equal(h.controller.reload(reset), false); assert.equal(h.controller.open(), false); assert.equal(h.controller.review(), false);
    assert.equal(h.count('open'), 2); assert.equal(h.count('prepare'), 0); assert.equal(h.count('apply'), 0);
    assert.deepEqual(h.boundaries, []);
    h.closeFinal(); assert.equal(h.controller.selectedEntry(), newer); assert.equal(h.count('close'), 2);
  }
});

test('late Open after a navigation intent can only close; no Load or Prepare is adopted', async () => {
  const h = await connected(); assert.equal(h.controller.open(), true);
  h.controller.setVisible(false); h.publish(h.owner('editing'));
  assert.equal(h.controller.selectedEntry(), null); assert.equal(h.count('prepare'), 0); assert.equal(h.count('close'), 1);
  h.controller.setVisible(true); assert.equal(h.controller.open(), false);
});

test('post-submit newer draft/navigation retain exact outcome, never bless or overwrite a newer draft', async () => {
  const h = await connected(), binding = await reviewing(h); const baseline = h.controller.selectedEntry().original;
  assert.equal(h.controller.apply(binding), true); h.publish(h.owner('applying'));
  h.controller.editField('name', '3.4.5'); h.add('q'); h.controller.setVisible(false);
  assert.equal(h.count('close'), 0); h.publish(h.owner('final'));
  const retained = h.state.entries.p;
  assert.equal(retained.values.name, '3.4.5'); assert.equal(retained.original, baseline); assert.equal(retained.stale, true);
  assert.equal(retained.outcome.prepared.view.values.name, '2.3.4'); assert.equal(normalVersionEditResult(retained.outcome), 'saved');
  assert.equal(h.state.projectId, 'q'); assert.equal(versionProjectDirty(h.state, 'p'), true); assert.equal(versionProjectDirty(h.state, 'q'), false);
});

test('unknown or late cleanup retains original evidence and blocks retries and destructive discard', async () => {
  const h = await connected(), binding = await reviewing(h); const baseline = h.controller.selectedEntry().original;
  h.controller.apply(binding);
  const unknown = h.owner('unknown', { nativeReason: 'cleanup_unknown', coreOutcome: { effect: 'unknown', journal: 'unknown', resources: 'unknown', reason: 'custody_unknown' } });
  h.publish(unknown, { reason: 'cleanup_unknown' });
  assert.equal(h.state.edit.nativeBlocked, true); assert.ok(versionOwnerReason(h.state, 'q')); assert.equal(versionRetainsDraft(h.state, 'p'), true);
  assert.equal(h.controller.apply(binding), false); assert.equal(h.controller.open(), false); assert.equal(h.controller.discard(h.controller.resetBinding()), false);
  const late = { ...clone(unknown), lateSettled: true, coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'custody_unknown' } };
  h.publish(late, { reason: 'cleanup_unknown' });
  assert.equal(h.controller.selectedEntry().outcome.lateSettled, true); assert.equal(h.controller.selectedEntry().outcome.coreOutcome.effect, 'committed');
  assert.equal(h.controller.selectedEntry().original, baseline); assert.equal(normalVersionEditResult(h.controller.selectedEntry().outcome), null);
  assert.equal(h.state.edit.nativeBlocked, true); assert.equal(h.count('apply'), 1);
});

test('recovery-required uncertainty remains attributed to the original project and domain', async () => {
  const h = await connected(), binding = await reviewing(h); h.controller.apply(binding);
  h.publish(h.owner('unknown', { nativeReason: 'cleanup_unknown',
    coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'unknown', reason: 'custody_unknown' } }), { reason: 'cleanup_unknown' });
  assert.deepEqual(h.state.edit.recoveryProjects, ['p']); assert.ok(versionOwnerReason(h.state, 'p'));
  assert.equal(h.controller.selectedEntry().stale, true);
});

test('lost Apply reply observes the original once, never resubmits a mutation or extends review time', async () => {
  const h = await connected(), binding = await reviewing(h);
  h.controller.apply(binding); const reads = h.count('status');
  h.last('apply').reject({ code: 'inert_loss', message: 'must not be displayed' }); await flush();
  assert.equal(h.count('status'), reads + 1); assert.equal(h.count('apply'), 1); assert.equal(h.count('open'), 1); assert.equal(h.count('prepare'), 1);
  assert.equal(h.controller.apply(binding), false);
  const expired = await connected(), apply = await reviewing(expired); expired.advance(900001);
  assert.equal(expired.controller.canApply(apply), false); expired.publish(expired.owner('reviewing'));
  assert.equal(expired.controller.remainingReviewMs(), 0); assert.equal(expired.controller.apply(apply), false);
});

test('other original operations block Apply and contradictory prepared DATA fails closed', async () => {
  const h = await connected(), binding = await reviewing(h); h.operation('An original query is pending');
  assert.equal(h.controller.apply(binding), false); h.operation(null); h.other('A foreign edit owns custody');
  assert.equal(h.controller.apply(binding), false); h.other(null);
  const changed = clone(h.frame); changed.statusRevision += 1; changed.active.prepared.view.values.name = '9.9';
  h.emit(changed); assert.equal(h.state.edit.integrityFailed, true); assert.equal(h.controller.apply(binding), false);
  assert.equal(h.count('apply'), 0); assert.equal(h.count('close'), 1);
});

test('local fields reject non-ASCII line separators without changing the retained draft', async () => {
  const h = await connected(); await openSaved(h);
  const original = clone(h.controller.selectedEntry().values), revision = h.controller.selectedEntry().revision;
  for (const id of ['name', 'build']) for (const value of ['7\u2028', '7\u2029', 'é']) {
    assert.equal(h.controller.editField(id, value), false);
    assert.deepEqual(h.controller.selectedEntry().values, original);
    assert.equal(h.controller.selectedEntry().revision, revision);
  }
  assert.equal(h.count('prepare'), 0); assert.equal(h.count('apply'), 0);
});

test('App explicitly fans every version save boundary into passive/read/build/offline consent retirement', () => {
  // Source obligation only; this is not a DOM/native/process-finality proof.
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /onSaveBoundary:[\s\S]*?releaseVersion\.saveIntent\(\);[\s\S]*?releaseInputs\.saveIntent\(\);[\s\S]*?androidBuildControllerRef\.current\?\.versionIntent\(\);[\s\S]*?offlinePreflightControllerRef\.current\?\.versionIntent\(\)/);
  const action = app.indexOf('versionEditControllerRef.current?.beforeWorkspaceAction(action)');
  assert.ok(action >= 0); assert.ok(action < app.indexOf('workspaceReducer(', action));
  assert.match(app, /versionEdit\.snapshotIntent\(projectId\)/);
  assert.match(app, /versionEdit\.beginConnection\(\)/);
});

// Fresh-process recovery transport/controller DATA only. No journal is created
// or inspected by these fixtures; core/native restart evidence stays separate.
const RECOVERY = { session: 'f'.repeat(32), revision: '1'.repeat(32), plan: '2'.repeat(32), transaction: '3'.repeat(32) };
function recoveryView(action = 'rollback', absent = false) {
  const facts = (text) => { const value = digest(text); return { byteLength: value.bytes, sha256: value.sha256, mode: 0o640 }; };
  const before = absent ? null : facts(ORIGINAL), after = facts('VERSION_NAME=2.3.4\nBUILD_NUMBER=8\n');
  const effect = action === 'rollback' ? absent ? 'remove_new' : 'restore_original' : action === 'committed_cleanup' ? 'keep_committed' : 'preserve';
  return { schemaVersion: 1, kind: 'saved-text-recovery', domain: 'release_version', state: 'recoverable', reason: 'none',
    action, transactionId: RECOVERY.transaction, selection: { source: SOURCE, nameKey: 'VERSION_NAME', buildKey: 'BUILD_NUMBER', iosEnabled: true },
    files: [{ path: SOURCE, effect, before, after }], privateCleanup: { fileCount: 4, directoryCount: 1, scope: 'inspected-owned-journal-only' } };
}
function recoveryProjection(phase, view = recoveryView(), options = {}) {
  const prepared = view.state === 'recoverable' && ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  return { domain: 'release_version', projectId: 'p', sessionId: RECOVERY.session, ownerGeneration: ID.window,
     phase, reviewRemainingMs: 900000, checkout: null, prepared: null,
    recovery: { checkout: phase === 'opening' ? null : { revision: RECOVERY.revision, view: clone(view) },
      prepared: prepared ? { revision: RECOVERY.revision, planToken: RECOVERY.plan, view: clone(view) } : null },
    applySubmitted: prepared && ['applying', 'finalizing', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: view.action ? savedTextRecoveryEffect(view.action) : 'not_started', journal: 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false, ...options };
}
function inspectRecovery(h, view = recoveryView()) {
  const before = h.count('prepare');
  assert.equal(h.controller.inspectRecoveryReason(), null); assert.equal(h.controller.inspectRecovery(), true);
  assert.deepEqual(h.last('open').args, { projectId: 'p', intent: 'recover' });
  assert.equal(h.controller.inspectRecovery(), false);
  h.publish(recoveryProjection('opening', view)); h.publish(recoveryProjection('editing', view));
  assert.equal(h.count('prepare'), before + (view.state === 'recoverable' ? 1 : 0));
  if (view.state === 'recoverable') {
    assert.deepEqual(h.last('prepare').args, { sessionId: RECOVERY.session, revision: RECOVERY.revision, intent: 'recover' });
    h.publish(recoveryProjection('reviewing', view));
    const binding = h.controller.currentRecoveryApplyBinding(); assert.ok(binding); return binding;
  }
  return null;
}

test('release_version recovery uses exact intent variants in existing commands; normal shapes and preview refusal stay unchanged', async () => {
  const open = { projectId: 'p', intent: 'recover' }, prepare = { sessionId: RECOVERY.session, revision: RECOVERY.revision, intent: 'recover' },
    apply = { sessionId: RECOVERY.session, planToken: RECOVERY.plan, intent: 'recover' };
  for (const [command, value] of [['release_version_edit_open', open], ['release_version_edit_prepare', prepare], ['release_version_edit_apply', apply]]) {
    assert.equal(versionEditRequestFits(command, value), true);
    for (const key of ['root', 'source', 'platform', 'locale', 'fields', 'values', 'expectedBaseline', 'action', 'force'])
      assert.equal(versionEditRequestFits(command, { ...value, [key]: 'forbidden' }), false);
    assert.equal(versionEditRequestFits(command, { ...value, intent: 'recover-again' }), false);
  }
  const calls = [], api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return status(); });
  await api.openReleaseVersionEdit(open); await api.prepareReleaseVersionEdit(prepare); await api.applyReleaseVersionEdit(RECOVERY.session, RECOVERY.plan, 'recover');
  assert.deepEqual(calls, [{ command: 'release_version_edit_open', args: open }, { command: 'release_version_edit_prepare', args: prepare }, { command: 'release_version_edit_apply', args: apply }]);
  await api.applyReleaseVersionEdit(ID.session, ID.plan);
  assert.deepEqual(calls.at(-1).args, { sessionId: ID.session, planToken: ID.plan });
  await assert.rejects(api.applyReleaseVersionEdit(ID.session, ID.plan, 'wrong')); assert.equal(calls.length, 4);
  await assert.rejects(previewApi.openReleaseVersionEdit(open));
  await assert.rejects(previewApi.prepareReleaseVersionEdit(prepare));
  await assert.rejects(previewApi.applyReleaseVersionEdit(RECOVERY.session, RECOVERY.plan, 'recover'));
});

test('release_version recovery VIEW is closed, bounded and separate from normal checkout/Save', () => {
  for (const action of ['rollback', 'committed_cleanup', 'rolled_back_cleanup', 'preparing_cleanup']) {
    const view = recoveryView(action); assert.ok(parseSavedTextRecoveryView(view, 'release_version'));
    const owner = recoveryProjection('reviewing', view); assert.ok(parseSavedTextRecoveryProjection(owner, 'release_version'));
    assert.ok(parseVersionEditStatus(status(1, owner))); assert.equal(normalVersionEditResult(recoveryProjection('final', view)), null);
  }
  for (const mutate of [(v) => { v.domain = 'metadata_text'; }, (v) => { v.schemaVersion = 2; },
    (v) => { v.rawText = 'never-export'; }, (v) => { v.reason = 'exception text'; }, (v) => { v.action = 'continue_save'; },
    (v) => { v.transactionId += '\n'; }, (v) => { v.files[0].path = '/absolute/path'; }, (v) => { v.files[0].effect = 'save_draft'; },
    (v) => { v.files[0].before = null; v.files[0].after = null; }, (v) => { v.files[0].after.mode = 512; },
    (v) => { v.files[0].after.sha256 += '\n'; }, (v) => { v.files[0].after.byteLength = 65537; },
    (v) => { v.files.push(clone(v.files[0])); }, (v) => { v.privateCleanup.fileCount = 15; },
    (v) => { v.privateCleanup.directoryCount = 12; }, (v) => { v.privateCleanup.scope = 'whole-project'; }]) {
    const value = recoveryView(); mutate(value); assert.equal(parseSavedTextRecoveryView(value, 'release_version'), null);
  }
  for (const key of ['state', 'reason', 'action', 'transactionId']) {
    const invalid = recoveryView(); invalid[key] = [invalid[key]];
    assert.equal(parseSavedTextRecoveryView(invalid, 'release_version'), null);
  }
  for (const key of ['phase', 'nativeReason', 'nativeFinality']) {
    const invalid = recoveryProjection('reviewing'); invalid[key] = [invalid[key]];
    assert.equal(parseSavedTextRecoveryProjection(invalid, 'release_version'), null);
  }
  for (const key of ['effect', 'journal', 'resources', 'reason']) {
    const invalid = recoveryProjection('final'); invalid.coreOutcome[key] = [invalid.coreOutcome[key]];
    assert.equal(parseSavedTextRecoveryProjection(invalid, 'release_version'), null);
  }
  for (const mutate of [(v) => { delete v.recovery; }, (v) => { v.checkout = { revision: RECOVERY.revision }; },
    (v) => { v.prepared = { planToken: RECOVERY.plan }; }, (v) => { v.recovery.prepared.planToken = RECOVERY.revision; },
    (v) => { v.recovery.prepared.view.files[0].after.byteLength += 1; }, (v) => { v.recovery.checkout.view.domain = 'foreign'; }]) {
    const owner = recoveryProjection('reviewing'); mutate(owner); assert.equal(parseVersionEditStatus(status(1, owner)), null);
  }
  let invoked = 0; const value = recoveryView(); Object.defineProperty(value, 'files', { enumerable: true, get() { invoked += 1; return []; } });
  assert.equal(parseSavedTextRecoveryView(value, 'release_version'), null); assert.equal(invoked, 0);
  const a = recoveryProjection('reviewing'), b = clone(a); b.recovery.checkout.view.files[0].after.sha256 = '4'.repeat(64);
  b.recovery.prepared.view = clone(b.recovery.checkout.view); assert.ok(parseVersionEditStatus(status(2, b))); assert.equal(versionProjectionProgress(a, b), false);
});

test('version recovery needs no normal checkout and never invents a source or Create baseline', async () => {
  for (const absent of [false, true]) {
    const h = await connected(); h.controller.setHelp(null);
    const view = recoveryView('rollback', absent), binding = inspectRecovery(h, view);
    assert.equal(h.controller.selectedEntry(), null); assert.equal(h.state.edit.attempt, null); assert.equal(h.count('apply'), 0);
    assert.equal(binding.view.files[0].effect, absent ? 'remove_new' : 'restore_original');
    assert.equal(h.controller.applyRecovery({ ...binding, planToken: ID.plan }), false);
    assert.equal(h.controller.applyRecovery({ ...binding, domain: 'metadata_text' }), false);
    assert.equal(h.controller.applyRecovery({ ...binding, projectId: 'other' }), false);
    assert.equal(h.controller.applyRecovery(binding), true); assert.equal(h.controller.applyRecovery(binding), false);
    assert.deepEqual(h.last('apply').args, { sessionId: RECOVERY.session, planToken: RECOVERY.plan, intent: 'recover' });
    h.publish(recoveryProjection('final', view)); assert.equal(h.controller.selectedEntry(), null); h.controller.dispose();
  }
});

test('version recovery waits for original Close and preserves dirty/newer values and all four historical effects', async () => {
  for (const action of ['rollback', 'committed_cleanup', 'rolled_back_cleanup', 'preparing_cleanup']) {
    const h = await connected(); await openSaved(h); h.controller.editField('name', '9.9.9');
    assert.equal(h.controller.inspectRecovery(), false); assert.equal(h.count('open'), 1);
    h.controller.requestClose(); assert.equal(h.controller.inspectRecovery(), false); assert.equal(h.count('close'), 1);
    h.closeFinal(); const before = clone(h.controller.selectedEntry()), retained = h.state.edit.attempt, settings = clone(h.workspace);
    const view = recoveryView(action), binding = inspectRecovery(h, view); assert.equal(h.count('apply'), 0);
    assert.equal(h.controller.discard(h.controller.resetBinding()), false); assert.equal(h.controller.reload(h.controller.resetBinding()), false);
    assert.equal(h.controller.applyRecovery(binding), true); h.controller.editField('build', '99');
    h.publish(recoveryProjection('final', view));
    const after = h.controller.selectedEntry(); assert.equal(h.state.edit.recovery.succeeded, true);
    assert.equal(savedTextRecoverySucceeded(h.state.edit.recovery), true);
    assert.deepEqual(after.original, before.original); assert.equal(after.baselineGeneration, before.baselineGeneration);
    assert.deepEqual(after.values, { name: '9.9.9', build: '99' }); assert.equal(after.revision, before.revision + 1);
    assert.deepEqual(after.outcome, before.outcome); assert.equal(after.stale, true); assert.deepEqual({ ...h.state.edit.attempt, projectionRevision: retained.projectionRevision }, retained);
    assert.ok(h.state.edit.attempt.projectionRevision >= retained.projectionRevision); // Later status may re-observe the same normal outcome.
    assert.deepEqual(h.workspace, settings); assert.deepEqual(h.boundaries, ['p', 'p']); assert.equal(h.count('open'), 2);
    assert.equal(currentVersionApplyBinding(h.state), null); assert.notEqual(h.controller.reviewReason(), null);
    // Only explicit existing discard-confirmed Reload adopts fresh normal data.
    h.original(ORIGINAL, checkout(), '4'.repeat(32)); assert.equal(h.controller.reload(h.controller.resetBinding()), true);
    h.publish(h.owner('editing')); assert.deepEqual(h.controller.selectedEntry().values, { name: '1.2.3', build: '7' });
    assert.equal(h.controller.selectedEntry().stale, false); h.controller.dispose();
  }
});

test('release_version recovery stale context, navigation, service and expiry cannot revive frozen confirmation', async () => {
  for (const change of [(h) => { h.controller.setVisible(false); h.controller.setVisible(true); }, (h) => { h.controller.beginConnection(); }, (h) => { h.add('q'); h.dispatch({ type: 'switch', projectId: 'p' }); }, (h) => { h.controller.beforeWorkspaceAction({ type: 'snapshot-start', projectId: 'p', requestId: 99 }); }, (h) => { h.advance(900001); h.controller.recoveryTick(); }, (h) => { h.controller.selectionIntent(); }]) {
    const h = await connected(), binding = inspectRecovery(h);
    change(h); assert.equal(h.controller.canApplyRecovery(binding), false); assert.equal(h.controller.applyRecovery(binding), false);
    assert.equal(h.count('apply'), 0); assert.equal(h.count('close'), 1); assert.equal(h.state.edit.recovery.invalidated, true);
    h.publish(recoveryProjection('reviewing')); assert.equal(h.controller.canApplyRecovery(binding), false);
    assert.equal(h.count('prepare'), 1); h.controller.dispose();
  }
});

test('release_version recovery late Open can only close, and lost Apply reply observes once without resubmitting', async () => {
  const late = await connected(); assert.equal(late.controller.inspectRecovery(), true);
  late.controller.setVisible(false); late.publish(recoveryProjection('editing'));
  assert.equal(late.count('close'), 1); assert.equal(late.count('prepare'), 0); assert.equal(late.count('apply'), 0);
  late.controller.setVisible(true); assert.equal(late.controller.currentRecoveryApplyBinding(), null); late.controller.dispose();
  const h = await connected(), binding = inspectRecovery(h); assert.equal(h.controller.applyRecovery(binding), true);
  h.publish(recoveryProjection('applying')); const reads = h.count('status');
  h.last('apply').reject({ code: 'BridgeLost' }); await flush();
  assert.equal(h.count('status'), reads + 1); assert.equal(h.count('apply'), 1); assert.equal(h.count('open'), 1); assert.equal(h.count('prepare'), 1);
  assert.equal(h.controller.applyRecovery(binding), false);
  h.publish(recoveryProjection('final')); assert.equal(h.state.edit.recovery.succeeded, true); h.controller.dispose();
});

test('release_version recovery clears only its matched submitted success; conflicts, idle and inspected discard retain attention', async () => {
  for (const ending of ['idle', 'legacy_journal', 'incomplete_journal', 'invalid_journal', 'foreign_journal', 'dependency_changed', 'target_changed', 'discard', 'success']) {
    const h = await connected(); await reviewing(h); const n = currentVersionApplyBinding(h.state); h.controller.apply(n);
    h.publish(h.owner('final', { coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } }));
    assert.deepEqual(h.state.edit.recoveryProjects, ['p']);
    const view = recoveryView('committed_cleanup');
    if (!['discard', 'success'].includes(ending)) Object.assign(view, { state: ending === 'idle' ? 'idle' : 'conflict', reason: ending === 'idle' ? 'none' : ending,
      action: null, transactionId: null, selection: null, files: [], privateCleanup: { fileCount: 0, directoryCount: 0, scope: 'inspected-owned-journal-only' } });
    const prepares = h.count('prepare'), binding = inspectRecovery(h, view);
    if (ending === 'success') {
      assert.equal(h.controller.applyRecovery(binding), true);
      h.other('Another domain retains its own journal');
      h.publish(recoveryProjection('final', view)); assert.equal(h.state.edit.recovery.succeeded, true);
      assert.deepEqual(h.state.edit.recoveryProjects, []); assert.equal(h.controller.inspectRecoveryReason(), 'Another domain retains its own journal');
    } else {
      assert.equal(h.state.edit.recovery.succeeded, false); assert.equal(h.count('prepare'), prepares + (ending === 'discard' ? 1 : 0));
      h.controller.requestRecoveryClose(); const previous = h.state.edit.recovery.projection;
      h.publish({ ...clone(previous), phase: 'final', nativeFinality: 'settled', nativeReason: 'discarded',
        coreOutcome: { effect: ending === 'discard' ? 'committed' : 'not_started', journal: 'recovery_required', resources: 'settled', reason: 'none' } });
      assert.equal(h.state.edit.recovery.succeeded, false); assert.deepEqual(h.state.edit.recoveryProjects, ['p']);
      assert.equal(h.controller.currentRecoveryApplyBinding(), null);
    }
    h.controller.dispose();
  }
});

test('release_version recovery refusal/failure/unknown or altered original plans cannot clear native or journal blocks', async () => {
  const blocked = await connected(); blocked.other('Other original owner'); assert.equal(blocked.controller.inspectRecovery(), false);
  blocked.other(null); const binding = inspectRecovery(blocked); blocked.other('Other original owner');
  assert.equal(blocked.controller.applyRecovery(binding), false); assert.equal(blocked.count('apply'), 0); blocked.controller.dispose();
  for (const kind of ['failed', 'unknown', 'mismatched-plan', 'wrong-success-effect']) {
    const h = await connected(), consent = inspectRecovery(h);
    assert.equal(h.controller.applyRecovery(consent), true);
    if (kind === 'mismatched-plan') {
      const result = recoveryProjection('final'); result.recovery.prepared.planToken = '4'.repeat(32); h.publish(result);
      assert.equal(h.state.edit.integrityFailed, true); assert.equal(h.state.edit.recovery.succeeded, false);
    } else if (kind === 'wrong-success-effect') {
      const result = recoveryProjection('final'); result.coreOutcome.effect = 'committed'; h.publish(result);
      assert.equal(h.state.edit.integrityFailed, true); assert.equal(h.state.edit.recovery.succeeded, false);
    } else {
      const result = recoveryProjection(kind === 'unknown' ? 'unknown' : 'final', recoveryView(), {
        coreOutcome: { effect: 'rolled_back', journal: 'recovery_required', resources: kind === 'unknown' ? 'unknown' : 'settled', reason: 'filesystem_error' },
        nativeReason: kind === 'unknown' ? 'cleanup_unknown' : 'none' });
      h.publish(result, { reason: kind === 'unknown' ? 'cleanup_unknown' : 'available' });
      assert.equal(h.state.edit.recovery.succeeded, false);
      if (kind === 'unknown') {
        const refined = clone(result); refined.lateSettled = true; refined.coreOutcome.resources = 'settled'; h.publish(refined);
        assert.equal(h.state.edit.nativeBlocked, true); assert.equal(h.controller.inspectRecovery(), false);
        assert.equal(h.state.edit.recovery.succeeded, false);
      }
    }
    assert.equal(h.controller.applyRecovery(consent), false); assert.equal(h.count('apply'), 1); h.controller.dispose();
  }
});


test('release_version recovery completion covers only older exact-context known replies and never newer attention', async () => {
  const failedCore = { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' };
  const counts = (h) => ['open', 'prepare', 'apply', 'close'].map((kind) => h.count(kind));
  // Resolve the actual retained normal Apply promise AFTER recovery succeeds.
  // An isolated controller per case prevents a prior sticky flag masking a guard.
  for (const kind of ['older', 'equal', 'later', 'foreign-project', 'foreign-window', 'custody', 'late-finality',
    'unknown-companion', 'custody-companion', 'current-custody-companion', 'cleanup-capability',
    'navigation-aba', 'snapshot-intent', 'selection-aba', 'service-aba']) {
    const h = await connected(), normal = await reviewing(h);
    assert.equal(h.controller.apply(normal), true); const pending = h.last('apply');
    const failed = clone(h.publish(h.owner('final', { coreOutcome: clone(failedCore) })));
    assert.deepEqual(h.state.edit.recoveryProjects, ['p']);
    const view = recoveryView('committed_cleanup'), binding = inspectRecovery(h, view);
    assert.equal(h.controller.applyRecovery(binding), true);
    const done = clone(h.publish(recoveryProjection('final', view)));
    assert.equal(h.state.edit.recovery.succeeded, true); assert.deepEqual(h.state.edit.recoveryProjects, []);
    assert.equal(h.state.edit.recovery.projectionRevision, done.statusRevision);
    const draft = clone(h.controller.selectedEntry()), priorCounts = counts(h), reply = clone(failed);
    if (kind === 'equal') reply.statusRevision = done.statusRevision;
    if (kind === 'later') reply.statusRevision = done.statusRevision + 1;
    if (kind === 'foreign-project') { reply.lastTerminal.projectId = 'foreign'; reply.lastTerminal.sessionId = 'e'.repeat(32); }
    if (kind === 'foreign-window') { reply.windowGeneration = '9'.repeat(32); reply.lastTerminal.ownerGeneration = reply.windowGeneration; }
    if (kind === 'custody') { reply.lastTerminal.sessionId = 'e'.repeat(32); reply.lastTerminal.coreOutcome.reason = 'custody_unknown'; }
    if (kind === 'late-finality') {
      Object.assign(reply.lastTerminal, { sessionId: 'e'.repeat(32), phase: 'unknown', nativeFinality: 'unknown', nativeReason: 'cleanup_unknown', lateSettled: true });
      reply.capability = { available: false, reason: 'cleanup_unknown' };
    }
    if (kind === 'unknown-companion') {
      reply.active = h.owner('unknown', { sessionId: 'e'.repeat(32), nativeReason: 'cleanup_unknown', coreOutcome: {
        effect: 'unknown', journal: 'unknown', resources: 'unknown', reason: 'custody_unknown' } });
      reply.capability = { available: false, reason: 'cleanup_unknown' };
    }
    if (kind === 'custody-companion') {
      reply.active = h.owner('applying', { sessionId: 'e'.repeat(32), coreOutcome: {
        effect: 'not_started', journal: 'not_created', resources: 'unknown', reason: 'custody_unknown' } });
    }
    if (kind === 'current-custody-companion') h.emit(status(done.statusRevision + 1, h.owner('applying', { sessionId: 'e'.repeat(32), coreOutcome: {
        effect: 'not_started', journal: 'not_created', resources: 'unknown', reason: 'custody_unknown' } }), done.lastTerminal));
    if (kind === 'cleanup-capability') reply.capability = { available: false, reason: 'cleanup_unknown' };
    if (kind === 'navigation-aba') { h.controller.setVisible(false); h.controller.setVisible(true); }
    if (kind === 'snapshot-intent') h.controller.snapshotIntent('p');
    if (kind === 'selection-aba') { h.controller.setSelectionPending(true); h.controller.setSelectionPending(false); }
    if (kind === 'service-aba') { h.controller.beginConnection(); h.controller.setHelp(guideResource); await h.controller.connect(h.api); }
    pending.resolve(reply); await flush();
    assert.equal(h.state.edit.recovery.succeeded, true); // Historical result, not a reset of newer evidence.
    assert.deepEqual(h.controller.selectedEntry(), draft); assert.deepEqual(counts(h), priorCounts);
    if (kind === 'older') {
      assert.deepEqual(h.state.edit.recoveryProjects, []);
      assert.equal(h.state.edit.integrityFailed, false); assert.equal(h.state.edit.generationLost, false);
      assert.equal(h.state.edit.nativeBlocked, false); assert.equal(h.state.edit.unknownEvidence, null);
      assert.equal(versionOwnerReason(h.state, 'p'), null);
    } else {
      if (kind === 'equal') assert.equal(h.state.edit.integrityFailed, true);
      else if (kind === 'late-finality') {
        assert.equal(h.state.edit.nativeBlocked, true); assert.equal(h.state.edit.unknownEvidence.lateSettled, true);
      } else {
        assert.ok(h.state.edit.recoveryProjects.includes(kind === 'foreign-project' ? 'foreign' : 'p'), kind);
        if (kind === 'foreign-window') assert.equal(h.state.edit.generationLost, true);
        if (kind === 'unknown-companion') {
          assert.equal(h.state.edit.nativeBlocked, true); assert.equal(h.state.edit.unknownEvidence.sessionId, 'e'.repeat(32));
        }
        if (kind === 'cleanup-capability') assert.equal(h.state.edit.nativeBlocked, true);
      }
      // Re-observing handled success cannot re-clear any newly retained block.
      h.emit(done);
      if (kind === 'equal') assert.equal(h.state.edit.integrityFailed, true);
      else if (kind === 'late-finality') assert.equal(h.state.edit.nativeBlocked, true);
      else assert.ok(h.state.edit.recoveryProjects.includes(kind === 'foreign-project' ? 'foreign' : 'p'), kind);
      assert.deepEqual(counts(h), priorCounts);
    }
    h.controller.dispose();
  }
  for (const kind of ['newer-pending', 'newer-unrelated', 'success-with-active-pending', 'success-with-active-custody', 'context-after-submit',
    'snapshot-after-submit', 'workspace-after-submit', 'shutdown-after-submit']) {
    const h = await connected(), normal = await reviewing(h);
    assert.equal(h.controller.apply(normal), true);
    h.publish(h.owner('final', { coreOutcome: clone(failedCore) }));
    const view = recoveryView('committed_cleanup'), binding = inspectRecovery(h, view);
    assert.equal(h.controller.applyRecovery(binding), true); const pending = h.last('apply');
    h.publish(recoveryProjection('applying', view));
    const completed = status(h.frame.statusRevision + 1, null, recoveryProjection('final', view));
    if (kind === 'newer-pending') h.emit(status(completed.statusRevision + 1, null, h.owner('final', { sessionId: 'e'.repeat(32), coreOutcome: clone(failedCore) })));
    if (kind === 'newer-unrelated') h.emit(status(completed.statusRevision + 1));
    if (kind === 'success-with-active-pending') {
      // One publication can retain this success beside a newer active owner:
      // revision equality alone must not clear that owner's pending journal.
      completed.active = h.owner('applying', { sessionId: 'e'.repeat(32), coreOutcome: clone(failedCore) });
    }
    if (kind === 'success-with-active-custody') completed.active = h.owner('applying', { sessionId: 'e'.repeat(32), coreOutcome: {
        effect: 'not_started', journal: 'not_created', resources: 'unknown', reason: 'custody_unknown' } });
    if (kind === 'context-after-submit') { h.controller.setVisible(false); h.controller.setVisible(true); }
    if (kind === 'snapshot-after-submit') h.controller.snapshotIntent('p');
    if (kind === 'workspace-after-submit') h.controller.beforeWorkspaceAction({ type: 'snapshot-start', projectId: 'p', requestId: 99 });
    if (kind === 'shutdown-after-submit') h.controller.shutdownIntent();
    const priorCounts = counts(h); pending.resolve(completed); await flush();
    assert.equal(h.state.edit.integrityFailed, false); assert.equal(h.state.edit.nativeBlocked, false);
    assert.equal(h.state.edit.recovery.succeeded, true);
    assert.equal(h.state.edit.recovery.projectionRevision, completed.statusRevision);
    assert.deepEqual(h.state.edit.recoveryProjects, ['p'], kind);
    assert.deepEqual(counts(h), priorCounts);
    if (kind.startsWith('newer-')) assert.ok(h.state.edit.status.statusRevision > h.state.edit.recovery.projectionRevision);
    else assert.equal(h.state.edit.status.statusRevision, h.state.edit.recovery.projectionRevision);
    h.controller.dispose();
  }
});
