// Inert DTO, reducer, bridge and retained-controller tests. No DOM, dialog,
// project/image filesystem reads, worker, process, network or Store operation.
// Header/digest values below are declared fixture metadata, not image validation.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import catalogResource from '../../src/mobile_release/api/data/metadata-images-v1.json' with { type: 'json' };
import helpResource from '../../src/mobile_release/api/data/metadata-image-help-v1.json' with { type: 'json' };
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { createMetadataImagesApi } from '../src/metadataImagesBridge.ts';
import { imageConfigReason, imageConfiguredChoices, imageProjectBinding } from '../src/metadataImagesContext.ts';
import { MetadataImagesController, currentMetadataImagesApplyBinding, imageAttemptFinished, metadataImagesOwnerReason,
  metadataImagesAssetSessionReason, retainedMetadataImagesOperation } from '../src/metadataImagesController.ts';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { METADATA_IMAGES_EDIT_EVENT, METADATA_IMAGES_SELECTION_EVENT, imageCatalogLimits, imageCatalogTypes, imageFieldHelp,
  imagePreparedMatches, imageSelectionSettled, metadataImagesEditProgress, metadataImagesProjectionProgress,
  metadataImagesSelectionProgress, metadataImagesSelectionProjectionProgress, metadataImagesError, metadataImagesRequestFits,
  normalMetadataImagesResult, parseMetadataImagesCatalog, parseMetadataImagesEditStatus, parseMetadataImagesHelp,
  parseMetadataImagesSelectionStatus } from '../src/metadataImagesProtocol.ts';

const ID = { window: 'a'.repeat(32), session: 'b'.repeat(32), revision: 'c'.repeat(32), plan: 'd'.repeat(32),
  operation: 'e'.repeat(32), selection: 'f'.repeat(32), item1: '1'.repeat(32), item2: '2'.repeat(32), transaction: '3'.repeat(32), other: '4'.repeat(32) };
const BASE = { schemaVersion: 1, metadata: { root: 'release/store', androidLocales: ['en-US', 'fr-FR'], iosLocales: ['en-US'] },
  android: { enabled: true }, ios: { enabled: true } };
const clone = (value) => structuredClone(value);
const digest = (value) => ({ byteLength: Buffer.byteLength(value), sha256: createHash('sha256').update(value).digest('hex') });
const summary = (value) => ({ ...digest(value), format: 'png', width: 1080, height: 1920, headerChecked: true });
const baseline = () => ({ config: digest(JSON.stringify(BASE)), ignore: digest('inert ignore policy\n'), inventorySha256: '9'.repeat(64) });
const limits = { maxFiles: 10, maxFileBytes: 10485760, maxBatchBytes: 25165824, maxTransactionBytes: 67108864,
  maxDimension: 16384, maxPixels: 67108864, formats: ['png', 'jpeg'] };
const publicCatalog = () => ({ schemaVersion: catalogResource.schemaVersion, policy: catalogResource.policy,
  platforms: [{ id: 'android', label: 'Android' }, { id: 'ios', label: 'iOS' }],
  types: clone(catalogResource.types), limits: clone(limits), help: clone(helpResource.fields) });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 20; i += 1) await Promise.resolve(); };

function importView() {
  const folder = 'release/store/android/en-US/images/phoneScreenshots';
  const original = summary('inert old public image'), selected = summary('inert chosen different image'), second = summary('inert new absent image');
  return { kind: 'import', policy: 'metadata-images-v1', platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots',
    metadataRoot: 'release/store', folder,
    files: [
      { itemId: ID.item1, displayName: '01.png', path: folder + '/01.png', action: 'preserve', before: clone(original),
        selected, after: clone(original), canReplace: true, issues: [] },
      { itemId: ID.item2, displayName: '02.png', path: folder + '/02.png', action: 'create', before: null,
        selected: clone(second), after: second, canReplace: false, issues: [] },
    ],
    existing: [{ path: folder + '/01.png', summary: original }, { path: folder + '/03.png', summary: summary('inert relevant sibling') }],
    finalOrder: ['01.png', '02.png', '03.png'].map((name) => folder + '/' + name), valid: true, issues: [],
    assurance: { localCopyOnly: true, sourceFilesUnchanged: true, storeContacted: false, fullDecode: false, contentApproved: false, storeAccepted: false } };
}
const captureItems = (view = importView()) => view.files.map((row) => ({ itemId: row.itemId, displayName: row.displayName,
  byteLength: row.selected.byteLength, sha256: row.selected.sha256 }));
function recoveryView(action = 'rollback') {
  return { kind: 'recover', state: 'recoverable', action, transactionId: ID.transaction, platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots',
    files: action === 'preparing_cleanup' ? [] : [{ path: 'release/store/android/en-US/images/phoneScreenshots/01.png',
      effect: action === 'rollback' ? 'restore_original' : action === 'committed_cleanup' ? 'keep_committed' : 'preserve',
      original: digest('inert old public image'), new: digest('inert chosen different image') }],
    privateCleanup: { fileCount: 2, directoryCount: 1, scope: 'original-image-journal-only' }, valid: true, issues: [],
    assurance: { newRestorationAttempt: true, sourceFilesUnchanged: true, storeContacted: false, importRetried: false } };
}
function selection(phase = 'selected', extra = {}) {
  return { operationId: ID.operation, projectId: 'a', platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots', phase,
    reason: phase === 'cancelled' ? 'cancelled' : phase === 'failed' ? 'dialog_failed' : phase === 'unknown' ? 'cleanup_unknown' : 'none',
    settlement: phase === 'unknown' ? 'unknown' : ['selecting', 'capturing'].includes(phase) ? 'pending' : 'known',
    selectionToken: phase === 'selected' ? ID.selection : null, items: phase === 'selected' ? captureItems() : [], ...extra };
}
function selectionStatus(revision = 0, active = null, lastTerminal = null, reason = 'available') {
  return { schemaVersion: 1, domain: 'metadata_images_selection', windowGeneration: ID.window, statusRevision: revision,
    capability: { available: reason === 'available', reason }, active, lastTerminal };
}
function editStatus(revision = 0, active = null, lastTerminal = null, reason = 'available') {
  return { schemaVersion: 1, domain: 'metadata_images', windowGeneration: ID.window, statusRevision: revision,
    capability: { available: reason === 'available', reason }, active, lastTerminal };
}
function prepareRequest(view = importView()) {
  return { sessionId: ID.session, revision: ID.revision, draftRevision: 0, baselineGeneration: 1, expectedBaseline: baseline(),
    choices: view.kind === 'recover' ? [] : view.files.map((row) => ({ itemId: row.itemId, replaceExisting: false })) };
}
function planned(view, choices) {
  const result = clone(view); if (result.kind === 'recover') return result;
  result.files = result.files.map((row, index) => {
    const identical = row.before && row.before.byteLength === row.selected.byteLength && row.before.sha256 === row.selected.sha256;
    const action = row.before === null ? 'create' : identical || !choices[index]?.replaceExisting ? 'preserve' : 'replace';
    return { ...row, action, after: clone(action === 'preserve' ? row.before : row.selected) };
  });
  return result;
}
function projection(view = importView(), phase = 'reviewing', options = {}) {
  const { request = prepareRequest(view), preparedView = planned(view, request.choices), ...overrides } = options;
  const opened = { revision: ID.revision, baseline: baseline(), view: clone(view) };
  const hasPrepared = ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  const noOp = preparedView.kind === 'import' && preparedView.files.every((row) => row.action === 'preserve');
  const effects = { rollback: 'rolled_back', rolled_back_cleanup: 'rolled_back', committed_cleanup: 'committed', preparing_cleanup: 'not_started' };
  return { domain: 'metadata_images', projectId: 'a', sessionId: ID.session, ownerGeneration: ID.window, phase, reviewRemainingMs: 900000,
    applySubmitted: ['applying', 'finalizing', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: preparedView.kind === 'recover' ? effects[preparedView.action] : noOp ? 'unchanged' : 'committed',
      journal: noOp ? 'not_created' : 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false,
    details: phase === 'opening' ? null : { intent: view.kind, checkout: opened, prepared: hasPrepared ? {
      revision: ID.revision, planToken: ID.plan, draftRevision: request.draftRevision, baselineGeneration: request.baselineGeneration, view: clone(preparedView),
    } : null }, ...overrides };
}
function snapshot(data = BASE) {
  return { root: '/inert-never-forwarded', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { content: null, path: 'release/mobile-release.json', state: 'format-valid', data: clone(data), issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false, gitObserved: false,
      storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' }, issues: [] };
}
function addProject(workspace, id = 'a', data = BASE) {
  workspace = workspaceReducer(workspace, { type: 'select', project: { id, name: 'Inert ' + id, path: '/inert-never-forwarded' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: id, requestId: 1 });
  return workspaceReducer(workspace, { type: 'snapshot-done', projectId: id, requestId: 1, snapshot: snapshot(data), observedAt: 0 });
}
function harness({ config = BASE, view = importView(), reason = 'available', mode = 'native', catalogGate = null, subscribeGate = null } = {}) {
  let workspace = addProject(initialWorkspace, 'a', config), selectionFrame = selectionStatus(0, null, null, reason), editFrame = editStatus(0, null, null, reason);
  let selectionListener = null, editListener = null, clock = 100, otherReason = null;
  const calls = [], selectionReads = [], editReads = [];
  const selected = () => workspace.projects[workspace.selectedId] ?? null;
  const request = (kind, args) => { const pending = deferred(); calls.push({ kind, args: clone(args), ...pending }); return pending.promise; };
  const api = { mode,
    metadataImagesCatalog: () => { calls.push({ kind: 'catalog' }); return catalogGate ? catalogGate.promise : Promise.resolve(publicCatalog()); },
    subscribeMetadataImagesSelection: async (receive) => { calls.push({ kind: 'subscribe-selection' }); selectionListener = receive;
      if (subscribeGate) await subscribeGate.promise; return () => { calls.push({ kind: 'unlisten-selection' }); selectionListener = null; }; },
    subscribeMetadataImagesEdit: async (receive) => { calls.push({ kind: 'subscribe-edit' }); editListener = receive;
      return () => { calls.push({ kind: 'unlisten-edit' }); editListener = null; }; },
    metadataImagesSelectionStatus: () => { calls.push({ kind: 'selection-status' }); return selectionReads.length ? selectionReads.shift().promise : Promise.resolve(clone(selectionFrame)); },
    metadataImagesEditStatus: () => { calls.push({ kind: 'edit-status' }); return editReads.length ? editReads.shift().promise : Promise.resolve(clone(editFrame)); },
    chooseMetadataImages: (args) => request('choose', args),
    cancelMetadataImagesSelection: (operationId) => request('cancel', { operationId }),
    openMetadataImagesEdit: (args) => request('open', args),
    openMetadataImagesRecovery: (projectId) => request('recover', { projectId }),
    prepareMetadataImagesEdit: (args) => request('prepare', args),
    applyMetadataImagesEdit: (sessionId, planToken) => request('apply', { sessionId, planToken }),
    closeMetadataImagesEdit: (sessionId) => request('close', { sessionId }),
  };
  const controller = new MetadataImagesController({ selectedProject: selected, otherOperationReason: (step) => typeof otherReason === 'function' ? otherReason(step) : otherReason, now: () => clock });
  const h = { controller, api, calls, selected, view: clone(view),
    get state() { return controller.getSnapshot(); }, get workspace() { return workspace; },
    get selectionFrame() { return clone(selectionFrame); }, get editFrame() { return clone(editFrame); },
    count: (kind) => calls.filter((row) => row.kind === kind).length, last: (kind) => calls.filter((row) => row.kind === kind).at(-1),
    block: (reason) => { otherReason = reason; }, advance: (ms) => { clock += ms; },
    dispatch: (action) => { controller.beforeWorkspaceAction(action); workspace = workspaceReducer(workspace, action); controller.syncProject(); },
    add: (id, data = BASE) => { workspace = addProject(workspace, id, data); controller.syncProject(); },
    deferSelectionStatus: () => { const pending = deferred(); selectionReads.push(pending); return pending; },
    deferEditStatus: () => { const pending = deferred(); editReads.push(pending); return pending; },
    emitSelection: (value) => { selectionFrame = clone(value); assert.ok(selectionListener); selectionListener(clone(value)); },
    emitEdit: (value) => { editFrame = clone(value); assert.ok(editListener); editListener(clone(value)); },
    publishSelection: (row, options = {}) => {
      const terminal = imageSelectionSettled(row) || row.settlement === 'late-known';
      const value = selectionStatus(options.revision ?? selectionFrame.statusRevision + 1, terminal ? null : row,
        terminal ? row : selectionFrame.lastTerminal, options.reason ?? selectionFrame.capability.reason);
      h.emitSelection(value); return value;
    },
    publishEdit: (row, options = {}) => {
      const terminal = row.phase === 'final' || row.lateSettled;
      const value = editStatus(options.revision ?? editFrame.statusRevision + 1, terminal ? null : row,
        terminal ? row : editFrame.lastTerminal, options.reason ?? editFrame.capability.reason);
      h.emitEdit(value); return value;
    },
    owner: (phase = 'editing', options = {}) => projection(h.view, phase, { request: h.state.attempt?.prepareRequest ?? prepareRequest(h.view), ...options }),
    closed: (reason = 'cancelled', coreReason = 'cancelled') => ({ ...clone(h.state.attempt.projection), phase: 'final', reviewRemainingMs: 0,
      applySubmitted: false, coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: coreReason },
      nativeReason: reason, nativeFinality: 'settled', lateSettled: false }),
  };
  return h;
}
async function connected(options) {
  const h = harness(options); h.controller.beginConnection(); await h.controller.connect(h.api);
  h.controller.setVisible(true); h.controller.selectAssetType('phoneScreenshots'); return h;
}
function checkedOut(h) {
  assert.equal(h.controller.choose(), true);
  h.publishSelection(selection('selecting')); h.publishSelection(selection('capturing'));
  const captured = selection('selected', { items: captureItems(h.view) });
  h.publishSelection(captured); assert.equal(h.count('open'), 1);
  h.publishSelection({ ...captured, selectionToken: null });
  h.publishEdit(h.owner('opening')); h.publishEdit(h.owner('editing'));
  assert.ok(h.state.attempt.choices); return h.state.attempt;
}
function reviewing(h, replace = false) {
  checkedOut(h);
  if (replace) assert.equal(h.controller.setReplacement(ID.item1, true), true);
  assert.equal(h.controller.prepare(), true); h.publishEdit(h.owner('preparing')); h.publishEdit(h.owner('reviewing'));
  const binding = currentMetadataImagesApplyBinding(h.state); assert.ok(binding); return binding;
}
function recoveryReview(h) {
  assert.equal(h.controller.inspectRecovery(), true); h.publishEdit(h.owner('opening')); h.publishEdit(h.owner('editing'));
  assert.equal(h.controller.prepare(), true); h.publishEdit(h.owner('preparing')); h.publishEdit(h.owner('reviewing'));
  const binding = currentMetadataImagesApplyBinding(h.state); assert.ok(binding); return binding;
}

test('catalogue and seven-field help come from shared DATA, never a guessed image policy', () => {
  const catalog = publicCatalog(); assert.ok(parseMetadataImagesCatalog(catalog)); assert.ok(parseMetadataImagesHelp(helpResource));
  assert.deepEqual(catalog.help, helpResource.fields); assert.deepEqual(catalog.types, catalogResource.types);
  assert.deepEqual(catalog.help.map((row) => row.id), ['platform', 'locale', 'assetType', 'files', 'replaceExisting', 'copyConfirmation', 'recoveryConfirmation']);
  assert.deepEqual(imageCatalogLimits(catalog), { maxFiles: 10, maxFileBytes: 10485760, maxBatchBytes: 25165824 });
  assert.equal(imageFieldHelp(catalog, 'files').what, helpResource.fields.find((row) => row.id === 'files').what);
  for (const platform of ['android', 'ios']) {
    const choices = imageCatalogTypes(catalog, platform), source = catalogResource.types.filter((row) => row.platform === platform);
    assert.deepEqual(choices.map((row) => row.id), source.map((row) => row.id));
    for (const row of source) {
      const description = choices.find((choice) => choice.id === row.id).description;
      for (const [width, height] of row.dimensions) assert.ok(description.includes(width + ' × ' + height));
      if (!row.dimensions.length) assert.match(description, /do not prove Store acceptance/);
    }
  }
  for (const change of [(v) => { v.supplier = 'renderer override'; }, (v) => { v.limits.maxFiles = 11; },
    (v) => { v.help.reverse(); }, (v) => { v.types.push(clone(v.types[0])); }, (v) => { v.types[0].id = '../raw'; },
    (v) => { v.help[0].privatePath = '/not-public'; }, (v) => { v.help[0].what = ''; }]) {
    const malformed = clone(catalog); change(malformed); assert.equal(parseMetadataImagesCatalog(malformed), null);
  }
});

test('request admission is closed and small; paths, bytes, authority overrides and accessors are refused', () => {
  const requests = {
    metadata_images_catalog: {}, metadata_images_choose: { projectId: 'a', platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots' },
    metadata_images_selection_status: {}, metadata_images_selection_cancel: { operationId: ID.operation },
    metadata_images_edit_open: { projectId: 'a', selectionToken: ID.selection }, metadata_images_recovery_open: { projectId: 'a' },
    metadata_images_edit_prepare: prepareRequest(), metadata_images_edit_apply: { sessionId: ID.session, planToken: ID.plan },
    metadata_images_edit_close: { sessionId: ID.session }, metadata_images_edit_status: {},
  };
  for (const [command, request] of Object.entries(requests)) {
    assert.equal(metadataImagesRequestFits(command, request), true);
    for (const name of ['path', 'bytes', 'base64', 'force', 'transactionId', 'action'])
      assert.equal(metadataImagesRequestFits(command, { ...request, [name]: 'not allowed' }), false);
  }
  for (const change of [(v) => { v.sessionId += '\n'; }, (v) => { v.revision = 'C'.repeat(32); }, (v) => { v.draftRevision = 0xffffffff; },
    (v) => { v.baselineGeneration = -1; }, (v) => { v.expectedBaseline.inventorySha256 = 'f'.repeat(63); },
    (v) => { v.choices[0].replaceExisting = 1; }, (v) => { v.choices[1].itemId = v.choices[0].itemId; },
    (v) => { delete v.choices[0]; }, (v) => { v.expectedBaseline.config.extra = true; }]) {
    const request = prepareRequest(); change(request); assert.equal(metadataImagesRequestFits('metadata_images_edit_prepare', request), false);
  }
  let getters = 0; const accessor = { projectId: 'a', locale: 'en-US', assetType: 'phoneScreenshots' };
  Object.defineProperty(accessor, 'platform', { enumerable: true, get() { getters += 1; return 'android'; } });
  assert.equal(metadataImagesRequestFits('metadata_images_choose', accessor), false); assert.equal(getters, 0);
  const circular = {}; circular.loop = circular; assert.equal(metadataImagesRequestFits('metadata_images_catalog', circular), false);
  const hidden = {}; Object.defineProperty(hidden, 'path', { value: '/hidden' }); assert.equal(metadataImagesRequestFits('metadata_images_catalog', hidden), false);
  assert.equal(metadataImagesRequestFits('metadata_images_choose', { ...requests.metadata_images_choose, projectId: 'a/b' }), false);
  assert.equal(metadataImagesRequestFits('metadata_images_choose', { ...requests.metadata_images_choose, assetType: 'x'.repeat(16385) }), false);
});

test('selection DTO exposes only bounded safe metadata and never unsettled byte authority', () => {
  const good = selectionStatus(1, null, selection()); assert.ok(parseMetadataImagesSelectionStatus(good));
  for (const name of ['cafe\u0301.png', 'screen:home.png', '\u00e9'.repeat(125) + 'x.png']) {
    const labeled = clone(good); labeled.lastTerminal.items[0].displayName = name;
    const parsed = parseMetadataImagesSelectionStatus(labeled); assert.ok(parsed);
    assert.equal(parsed.lastTerminal.items[0].displayName, name);
  }
  for (const name of ['', '.', '..', 'a/image.png', 'a\\image.png', 'a\u0000.png', 'a\u001f.png', 'a\u007f.png',
    'a\u0080.png', 'a\u009f.png', 'a\u202a.png', 'a\u202e.png', 'a\u2066.png', 'a\u2069.png', 'a\ud800.png', '\u00e9'.repeat(126) + '.png']) {
    const malformed = clone(good); malformed.lastTerminal.items[0].displayName = name;
    assert.equal(parseMetadataImagesSelectionStatus(malformed), null);
  }
  for (const change of [(v) => { v.lastTerminal.path = '/source/private.png'; }, (v) => { v.lastTerminal.items[0].bytes = [1, 2]; },
    (v) => { v.lastTerminal.items[0].displayName = '../source.png'; }, (v) => { v.lastTerminal.items[0].byteLength = 10485761; },
    (v) => { v.lastTerminal.operationId = 'E'.repeat(32); }, (v) => { v.lastTerminal.settlement = 'late-known'; },
    (v) => { v.lastTerminal.reason = 'cancelled'; }, (v) => { v.lastTerminal.items = []; },
    (v) => { v.lastTerminal.items = Array.from({ length: 3 }, (_, i) => ({ itemId: String(i + 1).repeat(32), displayName: i + '.png', byteLength: 10485760, sha256: '0'.repeat(64) })); },
    (v) => { v.lastTerminal.items = Array.from({ length: 11 }, (_, i) => ({ itemId: i.toString(16).repeat(32), displayName: i + '.png', byteLength: 1, sha256: '0'.repeat(64) })); }]) {
    const malformed = clone(good); change(malformed); assert.equal(parseMetadataImagesSelectionStatus(malformed), null);
  }
  const pending = selectionStatus(1, selection('capturing', { selectionToken: ID.selection }));
  assert.equal(parseMetadataImagesSelectionStatus(pending), null);
  const cancelled = selection('cancelled', { items: captureItems() });
  assert.ok(parseMetadataImagesSelectionStatus(selectionStatus(2, null, cancelled)));
  assert.equal(imageSelectionSettled(cancelled), true);
});

test('browser/unavailable bridges cannot select, invoke, listen or fall back to browser files', async () => {
  let invokes = 0, listens = 0;
  for (const mode of ['preview', 'unavailable']) {
    const api = createMetadataImagesApi(mode, async () => { invokes += 1; }, async () => { listens += 1; return () => {}; });
    await assert.rejects(api.metadataImagesCatalog(), { code: 'metadata_images_unavailable' });
    await assert.rejects(api.chooseMetadataImages({ projectId: 'a', platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots' }), { code: 'metadata_images_unavailable' });
    await assert.rejects(api.subscribeMetadataImagesSelection(() => {}), { code: 'metadata_images_unavailable' });
    await assert.rejects(api.subscribeMetadataImagesEdit(() => {}), { code: 'metadata_images_unavailable' });
  }
  assert.equal(invokes, 0); assert.equal(listens, 0);
});

test('native bridge clones admitted requests before awaiting and sanitizes every failure', async () => {
  const pending = deferred(), calls = [], events = [];
  const api = createMetadataImagesApi('native', async (command, args) => { calls.push({ command, args }); return pending.promise; },
    async (event, receive) => { events.push(event); receive({ inert: true }); return () => {}; });
  const input = { projectId: 'a', platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots' };
  const operation = api.chooseMetadataImages(input); input.platform = 'ios';
  assert.equal(calls[0].args.platform, 'android'); assert.notEqual(calls[0].args, input);
  pending.resolve(selectionStatus(1, null, selection())); assert.ok(await operation);
  await api.subscribeMetadataImagesSelection(() => {}); await api.subscribeMetadataImagesEdit(() => {});
  assert.deepEqual(events, [METADATA_IMAGES_SELECTION_EVENT, METADATA_IMAGES_EDIT_EVENT]);
  await assert.rejects(api.openMetadataImagesEdit({ projectId: 'a', selectionToken: ID.selection, path: '/not-accepted' }), { code: 'metadata_images_request_invalid' });
  assert.equal(calls.length, 1);
  const refusing = createMetadataImagesApi('native', async () => { throw { code: 'not-public', message: 'private OS transcript' }; });
  await assert.rejects(refusing.metadataImagesEditStatus(), (error) => error.code === 'metadata_images_unavailable' && !error.message.includes('transcript') && error.retryable === false);
  let getters = 0; const error = { message: 'secret text' }; Object.defineProperty(error, 'code', { get() { getters += 1; return 'metadata_images_busy'; } });
  assert.equal(metadataImagesError(error).code, 'metadata_images_unavailable'); assert.equal(getters, 0);
  const malformed = createMetadataImagesApi('native', async () => ({ ...editStatus(), sourcePath: '/not-public' }));
  await assert.rejects(malformed.metadataImagesEditStatus(), { code: 'metadata_images_status_invalid' });
});

test('preservation displays before as after and keeps the newly selected source distinct', () => {
  const view = importView(), names = ['cafe\u0301.png', 'screen:home.png'];
  view.files.forEach((row, index) => { row.displayName = names[index]; });
  const owner = projection(view), parsed = parseMetadataImagesEditStatus(editStatus(1, owner)); assert.ok(parsed);
  assert.deepEqual(parsed.active.details.checkout.view.files.map((row) => row.displayName), names);
  assert.deepEqual(parsed.active.details.prepared.view.files.map((row) => row.displayName), names);
  assert.deepEqual(parsed.active.details.prepared.view.files.map((row) => row.path), view.files.map((row) => row.path));
  assert.notDeepEqual(view.files[0].selected, view.files[0].before); assert.deepEqual(view.files[0].after, view.files[0].before);
  for (const change of [(v) => { v.files[0].after = clone(v.files[0].selected); }, (v) => { v.files[1].action = 'preserve'; },
    (v) => { v.files[1].canReplace = true; }, (v) => { v.files[0].before = null; }, (v) => { v.files[0].selected = clone(v.files[0].before); },
    (v) => { v.files[0].issues = [{ code: 'image.invalid', severity: 'warning', message: 'Wrong severity' }]; }]) {
    const malformed = clone(view); change(malformed);
    assert.equal(parseMetadataImagesEditStatus(editStatus(1, projection(malformed, 'editing'))), null);
  }
  const request = prepareRequest(); request.choices[0].replaceExisting = true;
  const replaced = projection(view, 'reviewing', { request });
  assert.ok(parseMetadataImagesEditStatus(editStatus(2, replaced))); assert.equal(imagePreparedMatches(replaced, request), true);
  assert.equal(replaced.details.prepared.view.files[0].action, 'replace');
  assert.deepEqual(replaced.details.prepared.view.files[0].after, view.files[0].selected);
});

test('Prepare binds original baseline bytes, exact ordered item roster and permitted per-target choice', () => {
  const request = prepareRequest(), owner = projection(); assert.equal(imagePreparedMatches(owner, request), true);
  for (const change of [(v) => { v.expectedBaseline.inventorySha256 = '8'.repeat(64); }, (v) => { v.expectedBaseline.ignore.byteLength += 1; },
    (v) => { v.choices.reverse(); }, (v) => { v.choices.pop(); }, (v) => { v.choices[1].replaceExisting = true; }, (v) => { v.draftRevision += 1; }]) {
    const stale = clone(request); change(stale); assert.equal(imagePreparedMatches(owner, stale), false);
  }
  const identical = importView(); identical.files[0].selected = clone(identical.files[0].before); identical.files[0].canReplace = false;
  const kept = projection(identical); assert.ok(parseMetadataImagesEditStatus(editStatus(1, kept)));
  const replaceIdentical = prepareRequest(identical); replaceIdentical.choices[0].replaceExisting = true;
  assert.equal(imagePreparedMatches(kept, replaceIdentical), false);
  const changedCheckout = clone(owner); changedCheckout.details.prepared.view.files[0].path += '-different';
  assert.equal(parseMetadataImagesEditStatus(editStatus(1, changedCheckout)), null);
});

test('old malformed public image is displayable and replaceable, but malformed selected input cannot hide behind preserve', () => {
  const view = importView(), malformed = { ...summary('inert malformed old'), format: null, width: null, height: null, headerChecked: false };
  view.files[0].before = clone(malformed); view.files[0].after = clone(malformed); view.existing[0].summary = malformed;
  view.valid = false; view.files[0].issues = [{ code: 'image.header', severity: 'error', message: 'Existing header was not admitted.' }];
  assert.ok(parseMetadataImagesEditStatus(editStatus(1, projection(view, 'editing'))));
  const request = prepareRequest(view); request.choices[0].replaceExisting = true;
  const repaired = planned(view, request.choices); repaired.valid = true; repaired.files[0].issues = [];
  const owner = projection(view, 'reviewing', { request, preparedView: repaired });
  assert.ok(parseMetadataImagesEditStatus(editStatus(2, owner))); assert.equal(imagePreparedMatches(owner, request), true);
  const badSource = importView(); badSource.files[0].selected = malformed;
  assert.equal(parseMetadataImagesEditStatus(editStatus(1, projection(badSource, 'editing'))), null);
});

test('public relative paths, complete siblings and code-point lexical order are checked without renderer reordering', () => {
  for (const unsafe of ['../image.png', '/image.png', '.private/image.png', 'private/image.png', 'Credentials/image.png', 'build/image.png',
    'a//image.png', 'a/CON.png', 'a/file .', 'a\\image.png', 'a/image.png\n']) {
    const view = importView(); view.files[0].path = unsafe;
    assert.equal(parseMetadataImagesEditStatus(editStatus(1, projection(view, 'editing'))), null);
  }
  for (const name of ['cafe\u0301.png', 'screen:home.png']) {
    const view = importView(); view.files = [{ ...view.files[1], displayName: name }];
    view.existing = []; view.finalOrder = [view.files[0].path];
    assert.ok(parseMetadataImagesEditStatus(editStatus(1, projection(view, 'editing'))));
    const path = view.folder + '/' + name; view.files[0].path = path; view.finalOrder = [path];
    assert.equal(parseMetadataImagesEditStatus(editStatus(1, projection(view, 'editing'))), null);
  }
  const partial = importView(); partial.finalOrder.pop();
  assert.equal(parseMetadataImagesEditStatus(editStatus(1, projection(partial, 'editing'))), null);
  partial.valid = false; assert.ok(parseMetadataImagesEditStatus(editStatus(1, projection(partial, 'editing'))));
  const unicode = importView(); unicode.existing = [];
  unicode.files = unicode.files.map((row, index) => ({ ...row, displayName: index ? '😀.png' : '\ue000.png',
    path: unicode.folder + '/' + (index ? '😀.png' : '\ue000.png'), before: null, after: clone(row.selected), action: 'create', canReplace: false }));
  unicode.finalOrder = unicode.files.map((row) => row.path);
  assert.ok(parseMetadataImagesEditStatus(editStatus(1, projection(unicode, 'editing'))));
  unicode.finalOrder.reverse(); assert.equal(parseMetadataImagesEditStatus(editStatus(1, projection(unicode, 'editing'))), null);
});

test('selection consumption and cancellation are distinct monotone transitions with no reusable late token', () => {
  const captured = selection(), consumed = selection('selected', { selectionToken: null }), cancelled = selection('cancelled', { items: captureItems() });
  assert.equal(metadataImagesSelectionProjectionProgress(captured, consumed), true);
  assert.equal(metadataImagesSelectionProjectionProgress(consumed, captured), false);
  assert.equal(metadataImagesSelectionProjectionProgress(captured, cancelled), true);
  assert.equal(metadataImagesSelectionProjectionProgress(consumed, cancelled), false);
  assert.equal(metadataImagesSelectionProgress(selectionStatus(1, null, captured), selectionStatus(2, null, consumed)), true);
  assert.equal(metadataImagesSelectionProgress(selectionStatus(1, null, captured), selectionStatus(2)), false);
  const unknown = selection('unknown'), late = { ...unknown, settlement: 'late-known' };
  assert.equal(metadataImagesSelectionProjectionProgress(unknown, late), true);
  assert.equal(metadataImagesSelectionProjectionProgress(late, captured), false);
  assert.equal(imageSelectionSettled(late), false);
  assert.ok(parseMetadataImagesSelectionStatus(selectionStatus(2, null, late)));
  assert.equal(metadataImagesSelectionProgress(selectionStatus(1), { ...selectionStatus(2), windowGeneration: ID.other }), false);
});

test('edit status rejects immutable-view contradictions and can shorten but not resurrect finality', () => {
  const first = projection(), next = { ...clone(first), reviewRemainingMs: 1 };
  assert.equal(metadataImagesEditProgress(editStatus(4, first), editStatus(4, next)), true);
  const bad = clone(first); bad.details.checkout.baseline.inventorySha256 = '8'.repeat(64);
  assert.equal(metadataImagesEditProgress(editStatus(4, first), editStatus(4, bad)), false);
  assert.equal(metadataImagesProjectionProgress(first, bad), false);
  assert.equal(metadataImagesEditProgress(editStatus(4, first), editStatus(5)), false);
  assert.equal(metadataImagesEditProgress(editStatus(4, first), editStatus(3, first)), false);
  const final = projection(importView(), 'final'); assert.equal(normalMetadataImagesResult(final), 'copied');
  const unknown = { ...final, phase: 'unknown', nativeFinality: 'unknown', nativeReason: 'cleanup_unknown', lateSettled: true };
  assert.equal(normalMetadataImagesResult(unknown), null); assert.equal(metadataImagesProjectionProgress(unknown, final), false);
  assert.equal(parseMetadataImagesEditStatus(editStatus(5, { ...first, checkout: first.details.checkout })), null);
  assert.equal(parseMetadataImagesEditStatus(editStatus(5, { ...first, details: undefined })), null);
});

for (const [action, effect] of Object.entries({ rollback: 'rolled_back', rolled_back_cleanup: 'rolled_back', committed_cleanup: 'committed', preparing_cleanup: 'not_started' })) {
  test('recovery action ' + action + ' requires its own exact effect, journal and original finality', () => {
    const view = recoveryView(action), owner = projection(view, 'final');
    assert.ok(parseMetadataImagesEditStatus(editStatus(3, null, owner)));
    assert.equal(owner.coreOutcome.effect, effect); assert.equal(normalMetadataImagesResult(owner), 'recovered');
    const request = prepareRequest(view); assert.deepEqual(request.choices, []); assert.equal(imagePreparedMatches(owner, request), true);
    request.choices.push({ itemId: ID.item1, replaceExisting: false }); assert.equal(imagePreparedMatches(owner, request), false);
    for (const field of ['effect', 'journal', 'resources']) {
      const bad = clone(owner); bad.coreOutcome[field] = 'unknown'; assert.equal(normalMetadataImagesResult(bad), null);
    }
    const stopped = clone(owner); stopped.nativeReason = 'cancelled'; assert.equal(normalMetadataImagesResult(stopped), null);
    const changed = clone(owner); changed.details.prepared.view.action = action === 'rollback' ? 'committed_cleanup' : 'rollback';
    assert.equal(parseMetadataImagesEditStatus(editStatus(3, null, changed)), null);
  });
}

test('saved settings alone provide locale context; image import never saves a dirty configuration', async () => {
  const h = await connected(); assert.equal(imageConfigReason(h.selected()), null); assert.equal(isDirty(h.selected()), false);
  assert.deepEqual(imageConfiguredChoices(h.selected()).map((row) => row.platform + '/' + row.locale), ['android/en-US', 'android/fr-FR', 'ios/en-US']);
  assert.equal(imageProjectBinding(h.selected()).projectId, 'a');
  h.dispatch({ type: 'edit', projectId: 'a', path: 'metadata.root', value: 'release/different' });
  assert.ok(imageConfigReason(h.selected())); assert.equal(h.controller.choose(), false); assert.equal(h.count('choose'), 0);
  assert.equal(h.selected().baseline.metadata.root, 'release/store');
});

test('catalogue DATA cannot qualify an unsupported native owner or turn preview into a picker', async () => {
  const unavailable = await connected({ reason: 'unsupported_platform' });
  assert.ok(unavailable.state.catalog); assert.notEqual(unavailable.controller.startReason(), null);
  assert.equal(unavailable.controller.choose(), false); assert.equal(unavailable.controller.inspectRecovery(), false);
  assert.equal(unavailable.count('choose'), 0); assert.equal(metadataImagesOwnerReason(unavailable.state), null);
  const preview = await connected({ mode: 'preview' }); assert.equal(preview.state.catalog, null); assert.equal(preview.calls.length, 0);
  assert.equal(preview.controller.choose(), false); assert.equal(preview.controller.inspectRecovery(), false);
});

test('Choose and original cancellation claim once, including a late selected token after navigation', async () => {
  const h = await connected(); assert.equal(h.controller.choose(), true); assert.equal(h.controller.choose(), false);
  assert.equal(h.controller.inspectRecovery(), false); assert.ok(metadataImagesOwnerReason(h.state));
  h.controller.setVisible(false); h.controller.setVisible(true);
  h.publishSelection(selection()); assert.equal(h.count('open'), 0); assert.equal(h.count('cancel'), 1);
  h.controller.requestStop(); h.controller.requestStop(); assert.equal(h.count('cancel'), 1);
  assert.equal(h.controller.choose(), false);
  const cancelled = selection('cancelled', { items: captureItems() }); h.publishSelection(cancelled);
  assert.equal(imageAttemptFinished(h.state.attempt), true); assert.equal(metadataImagesOwnerReason(h.state), null);
  assert.equal(h.controller.choose(), true); assert.equal(h.count('choose'), 2);
});

test('settled native capture auto-opens once and exact baseline/ordered default-preserve choices reach one Prepare', async () => {
  const view = importView(), names = ['cafe\u0301.png', 'screen:home.png'];
  view.files.forEach((row, index) => { row.displayName = names[index]; });
  const h = await connected({ view }); checkedOut(h);
  assert.deepEqual(h.state.attempt.projection.details.checkout.view.files.map((row) => row.displayName), names);
  assert.deepEqual(h.last('open').args, { projectId: 'a', selectionToken: ID.selection });
  assert.deepEqual(h.state.attempt.choices, [{ itemId: ID.item1, replaceExisting: false }, { itemId: ID.item2, replaceExisting: false }]);
  assert.equal(h.controller.setReplacement(ID.item2, true), false); assert.equal(h.controller.setReplacement(ID.item1, true), true);
  assert.equal(h.controller.prepare(), true); assert.equal(h.controller.prepare(), false);
  const args = h.last('prepare').args;
  assert.deepEqual(args.expectedBaseline, h.state.attempt.projection.details.checkout.baseline);
  assert.deepEqual(args.choices, [{ itemId: ID.item1, replaceExisting: true }, { itemId: ID.item2, replaceExisting: false }]);
  assert.equal(args.draftRevision, 1); assert.equal(args.baselineGeneration, h.state.attempt.binding.serial);
  h.publishEdit(h.owner('reviewing')); assert.equal(h.controller.setReplacement(ID.item1, false), false);
  assert.deepEqual(h.state.attempt.projection.details.prepared.view.files.map((row) => row.displayName), names);
  assert.deepEqual(h.state.attempt.projection.details.prepared.view.files.map((row) => row.path), view.files.map((row) => row.path));
  h.publishSelection(selection('selected', { selectionToken: null, items: captureItems(h.view) }));
  assert.equal(h.state.integrityFailed, false);
  assert.equal(h.count('open'), 1); assert.equal(h.count('prepare'), 1); assert.equal(h.count('apply'), 0);
});

test('fresh explicit acknowledgement gates a single Apply, bound to the exact original plan', async () => {
  const h = await connected(); const binding = reviewing(h, true);
  assert.equal(h.controller.apply(binding), false); h.controller.acknowledge(true); assert.equal(h.controller.canApply(binding), true);
  assert.equal(h.controller.apply({ ...binding, planToken: ID.other }), false);
  assert.equal(h.controller.apply(binding), true); assert.equal(h.controller.apply(binding), false);
  assert.equal(h.count('apply'), 1); assert.deepEqual(h.last('apply').args, { sessionId: ID.session, planToken: ID.plan });
  assert.equal(h.state.acknowledged, null); assert.equal(currentMetadataImagesApplyBinding(h.state), null);
  h.publishEdit(h.owner('applying')); h.publishEdit(h.owner('final'));
  assert.equal(normalMetadataImagesResult(h.state.attempt.projection), 'copied');
  assert.equal(imageAttemptFinished(h.state.attempt), true); assert.equal(h.count('apply'), 1);
  assert.ok(Object.isFrozen(h.state.attempt.prepareRequest.expectedBaseline));
});

test('submitted original survives navigation/project switches without becoming authority for another project', async () => {
  const h = await connected(); const binding = reviewing(h); h.controller.acknowledge(true); assert.equal(h.controller.apply(binding), true);
  h.controller.setVisible(false); h.add('b'); h.controller.setVisible(true); h.controller.shutdownIntent();
  assert.equal(h.state.projectId, 'b'); assert.equal(h.state.attempt.binding.projectId, 'a'); assert.equal(h.state.attempt.invalidated, false);
  assert.equal(h.state.acknowledged, null); assert.equal(h.count('close'), 0); assert.equal(h.controller.choose(), false);
  h.publishEdit(h.owner('applying')); h.publishEdit(h.owner('final'));
  assert.equal(h.state.attempt.projection.projectId, 'a'); assert.equal(normalMetadataImagesResult(h.state.attempt.projection), 'copied');
  assert.equal(retainedMetadataImagesOperation(h.state).owner.projectId, 'a');
});

for (const [label, retire] of [
  ['navigation', (h) => { h.controller.setVisible(false); h.controller.setVisible(true); }],
  ['project pick intent', (h) => h.controller.selectionIntent()],
  ['snapshot intent', (h) => h.controller.snapshotIntent('a')],
  ['unchanged reducer intent', (h) => h.dispatch({ type: 'snapshot-done', projectId: 'a', requestId: 999, snapshot: snapshot(), observedAt: 0 })],
  ['saved locale selection', (h) => h.controller.selectLocale('fr-FR')],
  ['image type selection', (h) => h.controller.selectAssetType('icon')],
  ['project switch', (h) => h.add('b')],
  ['unload intent', (h) => h.controller.shutdownIntent()],
]) {
  test('pre-submit ' + label + ' retires consent and closes only the original review', async () => {
    const h = await connected(); const binding = reviewing(h); h.controller.acknowledge(true);
    const baselineBefore = clone(h.selected().baseline); retire(h);
    assert.equal(h.state.acknowledged, null); assert.equal(h.state.attempt.invalidated, true); assert.equal(h.count('close'), 1);
    assert.deepEqual(h.last('close').args, { sessionId: ID.session }); assert.equal(h.controller.apply(binding), false);
    h.controller.requestStop(); assert.equal(h.count('close'), 1); assert.equal(h.count('apply'), 0);
    assert.deepEqual(h.workspace.projects.a.baseline, baselineBefore);
  });
}

test('original review deadline only shortens; repeated status cannot renew consent or Apply', async () => {
  const h = await connected(); const binding = reviewing(h); h.controller.acknowledge(true);
  const original = h.controller.remainingReviewMs(); h.advance(1000);
  h.publishEdit(h.owner('reviewing'), { revision: h.editFrame.statusRevision });
  assert.equal(h.controller.remainingReviewMs(), original - 1000);
  h.publishEdit(h.owner('reviewing', { reviewRemainingMs: 500 })); assert.equal(h.controller.remainingReviewMs(), 500);
  h.advance(501); assert.equal(h.controller.remainingReviewMs(), 0); assert.equal(h.controller.canApply(binding), false);
  h.publishEdit(h.owner('reviewing')); assert.equal(h.controller.remainingReviewMs(), 0); assert.equal(h.controller.apply(binding), false);
});

test('reciprocal operation admission blocks Choose/Prepare/Apply but never retries a stopped owner', async () => {
  const h = await connected(); h.block('Another original operation is active.');
  assert.equal(h.controller.choose(), false); assert.equal(h.controller.inspectRecovery(), false); assert.equal(h.count('choose'), 0);
  h.block(null); checkedOut(h); h.block('Another original passive query is pending.');
  assert.equal(h.controller.prepare(), false); h.block(null); assert.equal(h.controller.prepare(), true);
  h.publishEdit(h.owner('reviewing')); const binding = currentMetadataImagesApplyBinding(h.state); assert.ok(binding);
  h.controller.acknowledge(true); h.block('Another original operation is active.'); assert.equal(h.controller.apply(binding), false);
  assert.ok(metadataImagesOwnerReason(h.state)); h.controller.requestStop(); h.controller.requestStop();
  assert.equal(h.count('close'), 1); assert.equal(h.count('apply'), 0);
});

test('a source/checkout mismatch closes original once without adopting false source metadata or looping', async () => {
  const h = await connected(); assert.equal(h.controller.choose(), true); h.publishSelection(selection());
  assert.equal(h.count('open'), 1); h.publishSelection(selection('selected', { selectionToken: null }));
  h.publishEdit(h.owner('opening'));
  const wrong = h.owner('editing'); wrong.details.checkout.view.files[0].selected.sha256 = '7'.repeat(64);
  h.publishEdit(wrong); assert.equal(h.state.integrityFailed, true); assert.equal(h.state.attempt.choices, null);
  assert.equal(h.count('close'), 1); assert.equal(h.count('prepare'), 0);
  await h.controller.checkStatus(); h.controller.requestStop(); assert.equal(h.count('close'), 1);
  assert.equal(h.controller.prepare(), false); assert.ok(metadataImagesOwnerReason(h.state));
});

test('lost command replies trigger one original observation and no mutation retry', async () => {
  for (const kind of ['choose', 'open', 'prepare', 'apply', 'cancel', 'close', 'recover']) {
    const h = await connected(kind === 'recover' ? { view: recoveryView() } : undefined);
    if (kind === 'choose') h.controller.choose();
    else if (kind === 'recover') h.controller.inspectRecovery();
    else if (kind === 'cancel') { h.controller.choose(); h.publishSelection(selection('selecting')); h.controller.requestStop(); }
    else if (kind === 'open' || kind === 'close') { checkedOut(h); if (kind === 'close') h.controller.requestStop(); }
    else { const binding = reviewing(h); if (kind === 'apply') { h.controller.acknowledge(true); assert.equal(h.controller.apply(binding), true); } }
    const selectionReads = h.count('selection-status'), editReads = h.count('edit-status'); assert.equal(h.count(kind), 1, kind);
    h.last(kind).reject({ code: 'unconfirmed-native-reply', message: 'private transcript never surfaced' }); await flush();
    assert.equal(h.count('selection-status'), selectionReads + 1, kind); assert.equal(h.count('edit-status'), editReads + 1, kind);
    assert.equal(h.count(kind), 1, kind); assert.equal(h.controller.choose(), false, kind);
    assert.ok(!h.state.error || !h.state.error.message.includes('transcript'));
    await h.controller.checkStatus(); assert.equal(h.count(kind), 1, kind);
  }
});

test('a lost Apply reply is not success; only a later consistent original settlement can clear the notice', async () => {
  const h = await connected(); const binding = reviewing(h); h.controller.acknowledge(true); h.controller.apply(binding);
  h.last('apply').reject(new Error('unconfirmed')); await flush();
  assert.equal(h.state.error.code, 'metadata_images_reply_lost'); assert.equal(h.state.attempt.projection.phase, 'reviewing');
  assert.equal(normalMetadataImagesResult(h.state.attempt.projection), null); assert.equal(h.controller.apply(binding), false);
  h.publishEdit(h.owner('applying')); h.publishEdit(h.owner('final'));
  assert.equal(h.state.error, null); assert.equal(normalMetadataImagesResult(h.state.attempt.projection), 'copied'); assert.equal(h.count('apply'), 1);
});

test('stale/equal contradictory status and document-generation changes remain fail-closed', async () => {
  const h = await connected(); checkedOut(h);
  const contradiction = h.editFrame; contradiction.active.details.checkout.baseline.inventorySha256 = '6'.repeat(64);
  h.emitEdit(contradiction); assert.equal(h.state.integrityFailed, true); assert.equal(h.count('close'), 1);
  assert.equal(h.controller.prepare(), false); assert.equal(currentMetadataImagesApplyBinding(h.state), null);
  const changed = await connected(); changed.emitSelection({ ...changed.selectionFrame, statusRevision: 1, windowGeneration: ID.other });
  assert.equal(changed.state.generationLost, true); assert.equal(changed.controller.choose(), false); assert.ok(metadataImagesOwnerReason(changed.state));
  const stale = await connected(); checkedOut(stale);
  const old = stale.editFrame; old.statusRevision -= 1; old.active.details.checkout.view.files[0].selected.sha256 = '5'.repeat(64);
  stale.emitEdit(old); assert.equal(stale.state.integrityFailed, true); assert.equal(stale.count('prepare'), 0);
});

test('unknown and late-known original selection can never authorize Open or a replacement Choose', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection('selecting'));
  h.publishSelection(selection('unknown')); assert.equal(h.state.nativeBlocked, true); assert.ok(h.state.unknownSelection);
  h.publishSelection(selection('unknown', { settlement: 'late-known' }));
  assert.equal(h.count('open'), 0); assert.equal(h.controller.choose(), false); assert.ok(metadataImagesOwnerReason(h.state));
  h.publishSelection(selection('selected')); assert.equal(h.state.integrityFailed, true); assert.equal(h.count('open'), 0);
});

test('unknown edit outcome may gain late evidence but never normal success or new authority', async () => {
  const h = await connected(); const binding = reviewing(h); h.controller.acknowledge(true); h.controller.apply(binding); h.publishEdit(h.owner('applying'));
  const unknown = h.owner('unknown', { nativeReason: 'cleanup_unknown', coreOutcome: { effect: 'unknown', journal: 'unknown', resources: 'unknown', reason: 'custody_unknown' } });
  h.publishEdit(unknown); assert.equal(h.state.nativeBlocked, true);
  const late = { ...clone(unknown), lateSettled: true, coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'custody_unknown' } };
  h.publishEdit(late); assert.equal(h.state.integrityFailed, false); assert.ok(h.state.unknownEdit);
  assert.equal(normalMetadataImagesResult(h.state.attempt.projection), null); assert.equal(h.controller.choose(), false);
  assert.equal(h.controller.inspectRecovery(), false); assert.equal(h.count('apply'), 1);
});

test('orphan selected custody arriving before original read is retained, cancelled once, never auto-opened', async () => {
  const h = harness(), read = h.deferSelectionStatus(); const connecting = h.controller.connect(h.api); await flush();
  h.emitSelection(selectionStatus(2, null, selection())); read.resolve(selectionStatus()); await connecting;
  h.controller.setVisible(true); h.controller.selectAssetType('phoneScreenshots');
  assert.equal(h.state.selectionStatus.statusRevision, 2); assert.equal(h.state.attempt, null);
  assert.equal(h.controller.choose(), false); assert.equal(h.count('open'), 0);
  h.controller.requestStop(); h.controller.requestStop(); assert.equal(h.count('cancel'), 1);
  h.publishSelection(selection('cancelled', { items: captureItems() }));
  assert.equal(h.controller.choose(), true);
});

test('a new attempt or held orphan selection cannot inherit an earlier edit success or its source provenance', async () => {
  const h = await connected(); const binding = reviewing(h); h.controller.acknowledge(true); h.controller.apply(binding);
  h.publishEdit(h.owner('applying')); h.publishEdit(h.owner('final'));
  assert.equal(normalMetadataImagesResult(retainedMetadataImagesOperation(h.state).owner), 'copied');
  assert.equal(h.controller.choose(), true);
  assert.deepEqual(retainedMetadataImagesOperation(h.state), { owner: null, selection: null });
  const orphan = { ...h.state, attempt: null, selectionStatus: selectionStatus(5, null, selection('selected', { operationId: ID.other })) };
  const retained = retainedMetadataImagesOperation(orphan); assert.equal(retained.owner, null); assert.equal(retained.selection.operationId, ID.other);
});

test('separate reviewed recovery uses empty choices and clears only its positively settled original journal block', async () => {
  const h = await connected({ view: recoveryView('rollback') });
  const previous = projection(importView(), 'final', { sessionId: ID.other,
    coreOutcome: { effect: 'rolled_back', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } });
  h.emitEdit(editStatus(1, null, previous)); assert.deepEqual(h.state.recoveryProjects, ['a']);
  assert.equal(h.controller.choose(), false); const binding = recoveryReview(h);
  assert.deepEqual(h.last('prepare').args.choices, []); assert.deepEqual(h.last('recover').args, { projectId: 'a' });
  h.controller.acknowledge(true); assert.equal(h.controller.apply(binding), true); h.publishEdit(h.owner('applying')); h.publishEdit(h.owner('final'));
  assert.equal(normalMetadataImagesResult(h.state.attempt.projection), 'recovered'); assert.deepEqual(h.state.recoveryProjects, []);
  assert.equal(h.count('choose'), 0); assert.equal(h.count('apply'), 1);
});

for (const state of ['idle', 'conflict']) {
  test('recovery ' + state + ' is inspectable but cannot Prepare, acknowledge or Apply', async () => {
    const view = recoveryView(); view.state = state; view.valid = false;
    if (state === 'idle') Object.assign(view, { action: null, transactionId: null, platform: null, locale: null, assetType: null,
      files: [], privateCleanup: { fileCount: 0, directoryCount: 0, scope: 'original-image-journal-only' } });
    else view.issues = [{ code: 'image.recovery_conflict', severity: 'error', message: 'An outside change was detected.' }];
    const h = await connected({ view }); assert.equal(h.controller.inspectRecovery(), true); h.publishEdit(h.owner('editing'));
    assert.notEqual(h.controller.prepareReason(), null); assert.equal(h.controller.prepare(), false);
    h.controller.acknowledge(true); assert.equal(h.state.acknowledged, null); assert.equal(currentMetadataImagesApplyBinding(h.state), null);
    assert.equal(h.count('prepare'), 0); assert.equal(h.count('apply'), 0); h.controller.requestStop(); assert.equal(h.count('close'), 1);
  });
}

test('disposal during original subscription settles only that observer and cannot start a second stream', async () => {
  const gate = deferred(), h = harness({ subscribeGate: gate }); const connecting = h.controller.connect(h.api);
  await flush(); h.controller.dispose(); gate.resolve(); await connecting;
  assert.equal(h.count('subscribe-selection'), 1); assert.equal(h.count('unlisten-selection'), 1);
  assert.equal(h.count('subscribe-edit'), 0); assert.equal(h.count('choose'), 0);
});

test('an all-preserve import is unchanged only with no journal and original settlement', () => {
  const view = importView(); view.files = [view.files[0]]; view.finalOrder = view.existing.map((row) => row.path);
  const owner = projection(view, 'final');
  assert.ok(parseMetadataImagesEditStatus(editStatus(3, null, owner))); assert.equal(normalMetadataImagesResult(owner), 'unchanged');
  const bad = clone(owner); bad.coreOutcome.journal = 'clean'; assert.equal(normalMetadataImagesResult(bad), null);
});

test('a still-held source token can be cancelled after its original edit already closed', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  h.publishEdit(h.owner('opening')); h.publishEdit(h.owner('editing')); h.controller.requestStop();
  h.publishEdit(h.closed()); assert.equal(imageAttemptFinished(h.state.attempt), true); assert.ok(metadataImagesOwnerReason(h.state));
  h.controller.requestStop(); h.controller.requestStop(); assert.equal(h.count('close'), 1); assert.equal(h.count('cancel'), 1);
  h.publishSelection(selection('cancelled', { items: captureItems() })); assert.equal(metadataImagesOwnerReason(h.state), null);
});

test('service replacement and exhausted correlation counters cannot create another owner', async () => {
  const h = await connected(); checkedOut(h); await h.controller.connect({ ...h.api });
  assert.equal(h.state.generationLost, true); assert.equal(h.count('subscribe-selection'), 1); assert.equal(h.count('subscribe-edit'), 1);
  assert.equal(h.controller.prepare(), false); assert.equal(h.controller.choose(), false);
  const exhausted = await connected(); exhausted.emitSelection({ ...exhausted.selectionFrame, statusRevision: 0xffffffff });
  assert.equal(exhausted.controller.choose(), false); assert.equal(exhausted.count('choose'), 0);
});

test('App owns one image controller app-wide, with reciprocal busy gates and synchronous intent retirement', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.equal((app.match(/new MetadataImagesController\(/g) ?? []).length, 1);
  assert.ok(app.includes('useSyncExternalStore(metadataImages.subscribe, metadataImages.getSnapshot, metadataImages.getSnapshot)'));
  const intent = app.indexOf('imageControllerRef.current?.beforeWorkspaceAction(action)');
  assert.ok(intent >= 0 && intent < app.indexOf('const next = workspaceReducer(previous, action)'));
  assert.ok(app.includes('imageControllerRef.current?.syncProject()'));
  assert.ok(app.includes('savedCommandBusy(false, false, false, true) ?? savedCommandPrerequisiteReason(false, true, step)'));
  assert.ok(app.includes('metadataImagesAssetSessionReason(assets, imageStep)'));
  const subscription = app.indexOf('assetSession.subscribe(metadataImages.syncAssetSession)');
  assert.ok(subscription >= 0 && subscription < app.indexOf('void bootstrap()'));
  assert.ok(app.includes('metadataImages.syncAssetSession();'));
  assert.ok(app.includes('excludeGitHubRelease = false, excludeImages = false'));
  assert.ok(app.includes('!excludeImages && imageControllerRef.current ? metadataImagesOwnerReason'));
  assert.ok(app.includes('excludeImages ? null : metadataImagesOwnerReason'));
  assert.ok(app.includes('!excludeImages && metadataImages.passiveBusyReason()'));
  assert.ok(app.includes('metadataImages.connect(metadataImagesApi(api.mode))'));
  assert.ok(app.includes('metadataImages.setVisible(next === \'metadata\')'));
  assert.ok(app.includes('imageControllerRef.current?.shutdownIntent()'));
  assert.ok(app.includes('metadataImages.selectionIntent()')); assert.ok(app.includes('metadataImages.snapshotIntent(projectId)'));
  assert.ok(app.includes('metadataImages.setSelectionPending(true)')); assert.ok(app.includes('metadataImages.setSelectionPending(false)'));
  assert.ok(app.includes("page !== 'metadata' && <MetadataImagesOperation"));
  assert.ok(app.includes('imageEditor={<MetadataImagesEditor'));
  const capability = app.slice(app.indexOf('const nativeImagesAvailable'), app.indexOf('const localEditingLabel'));
  assert.ok(capability.includes('catalog !== null')); assert.ok(capability.includes('selectionStatus?.capability.available === true'));
  assert.ok(capability.includes('editStatus?.capability.available === true')); assert.ok(capability.includes('!metadataImagesState.integrityFailed'));
});

test('all closed image commands reach the existing native handlers through the local main-window ACL', () => {
  const expected = [
    'metadata_images_catalog', 'metadata_images_choose', 'metadata_images_selection_status', 'metadata_images_selection_cancel',
    'metadata_images_edit_open', 'metadata_images_recovery_open', 'metadata_images_edit_prepare',
    'metadata_images_edit_apply', 'metadata_images_edit_close', 'metadata_images_edit_status',
  ].sort();
  const types = readFileSync(new URL('../src/metadataImages.ts', import.meta.url), 'utf8');
  const build = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const shell = readFileSync(new URL('../src-tauri/src/shell.rs', import.meta.url), 'utf8');
  const main = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const body = (source, pattern) => { const match = source.match(pattern); assert.ok(match); return match[1]; };
  const commands = (source) => [...source.matchAll(/\bmetadata_images_[a-z_]+\b/g)].map((match) => match[0]).sort();
  const sameClosedSet = (actual) => {
    assert.equal(new Set(actual).size, actual.length, 'duplicate image command or permission');
    assert.deepEqual(actual, expected);
  };
  sameClosedSet(commands(body(types, /export type MetadataImagesCommand\s*=([\s\S]*?);/)));
  sameClosedSet(commands(body(build, /const COMMANDS:\s*&\[&str\]\s*=\s*&\[([\s\S]*?)\];/)));
  sameClosedSet(commands(body(shell, /tauri::generate_handler!\[([\s\S]*?)\]/)));
  sameClosedSet([...shell.matchAll(/#\[tauri::command\]\s*async fn (metadata_images_[a-z_]+)\(/g)].map((match) => match[1]).sort());
  assert.match(build, /AppManifest::new\(\)\s*\.commands\(COMMANDS\)/);
  assert.equal(main.local, true);
  assert.deepEqual(main.windows, ['main']);
  assert.equal(Object.hasOwn(main, 'remote'), false);
  sameClosedSet(main.permissions.filter((entry) => typeof entry === 'string' && entry.startsWith('allow-metadata-images-'))
    .map((entry) => entry.slice('allow-'.length).replaceAll('-', '_')).sort());
});

test('guided Metadata UI displays real metadata, not fabricated thumbnails or browser/file-byte fallbacks', () => {
  const page = readFileSync(new URL('../src/pages/Metadata.tsx', import.meta.url), 'utf8');
  const ui = readFileSync(new URL('../src/components/MetadataImagesEditor.tsx', import.meta.url), 'utf8');
  const controller = readFileSync(new URL('../src/metadataImagesController.ts', import.meta.url), 'utf8');
  const bridge = readFileSync(new URL('../src/metadataImagesBridge.ts', import.meta.url), 'utf8');
  const api = readFileSync(new URL('../src/metadataImagesApi.ts', import.meta.url), 'utf8');
  assert.ok(page.includes('{imageEditor}')); assert.ok(!page.includes('Screenshot selection, registration and image validation are not implemented'));
  assert.ok(!page.includes('screenshot-card')); assert.ok(ui.includes('Header/dimensions checked')); assert.ok(ui.includes('version-controlled project metadata'));
  assert.ok(ui.includes('Source images are never moved')); assert.ok(ui.includes('not full image decoding'));
  assert.ok(ui.includes('original native')); assert.ok(ui.includes('Final lexical Store input order')); assert.ok(ui.includes('view.finalOrder.map'));
  assert.ok(ui.includes('file.selected')); assert.ok(ui.includes('file.after')); assert.ok(ui.includes('view.existing'));
  assert.ok(ui.includes('idle inspection is not a recovery pass')); assert.ok(ui.includes('recoveryAction[view.action]'));
  assert.ok(ui.includes('retainedMetadataImagesOperation(state)')); assert.ok(ui.includes('Image Apply submitted; awaiting original status'));
  assert.ok(ui.includes('!imageAttemptFinished(attempt) && (attempt.cancelClaimed || attempt.closeClaimed)'));
  assert.ok(api.includes("from '@tauri-apps/api/core'")); assert.ok(api.includes("from '@tauri-apps/api/event'"));
  for (const source of [ui, controller, bridge, api]) {
    assert.doesNotMatch(source, /type=["']file["']|FileReader|new File\b|new Blob\b|Uint8Array|\.arrayBuffer\(|localStorage|sessionStorage|fetch\(/);
    assert.doesNotMatch(source, /APP_IPHONE_[0-9]|APP_IPAD_PRO_/); // only the shared catalogue supplies device rows
  }
});


function genericImageStatus(revision = 0, operationPatch = null) {
  return { schemaVersion: 3, statusRevision: revision, mode: 'closed', persistence: null,
    capability: { available: true, reason: 'none' },
    modes: { session: { available: true, reason: 'none' }, encrypted: { available: false, reason: 'unqualified' } },
    context: null, records: [], assignments: [],
    operation: operationPatch === null ? null : { operationId: 73, operation: 'choose-images', phase: 'capturing',
      reason: 'none', source: 'pending', settlement: 'pending', storageOutcome: null,
      selectionToken: null, assessment: null, preview: null, ...operationPatch } };
}
async function linkedAssets(h) {
  let receive = null, frame = genericImageStatus(); const calls = [];
  const controller = new AssetSessionController(() => null);
  h.block((step) => metadataImagesAssetSessionReason(controller.getSnapshot(), step));
  const unsubscribe = controller.subscribe(h.controller.syncAssetSession);
  await controller.connect({ mode: 'native',
    subscribeAssets: async (listener) => { calls.push('listen'); receive = listener; return () => { receive = null; }; },
    assetStatus: async () => { calls.push('status'); return clone(frame); },
  });
  return { controller, calls, emit: (value) => { frame = clone(value); assert.ok(receive); receive(clone(value)); },
    dispose: () => { unsubscribe(); controller.dispose(); } };
}

for (const settledPhase of ['selected', 'idle']) {
  test('asset-only ' + settledPhase + '/known event releases exactly the same pending image Open without a poll', async () => {
    const h = await connected(), assets = await linkedAssets(h);
    try {
      assert.equal(h.controller.choose(), true);
      assets.emit(genericImageStatus(1, {}));
      h.publishSelection(selection());
      assert.equal(h.count('open'), 0, 'the generic original is still capturing');
      const reads = [h.count('selection-status'), h.count('edit-status'), assets.calls.length];
      assets.emit(genericImageStatus(2, { phase: settledPhase, source: 'captured', settlement: 'known' }));
      assert.equal(h.count('open'), 1, 'the generic event must recheck the already settled image selection');
      assert.deepEqual(h.last('open').args, { projectId: 'a', selectionToken: ID.selection });
      h.controller.syncAssetSession(); h.controller.syncAssetSession();
      assets.emit(genericImageStatus(3, { phase: settledPhase, source: 'captured', settlement: 'known' }));
      assert.equal(h.count('open'), 1);
      assert.deepEqual([h.count('selection-status'), h.count('edit-status'), assets.calls.length], reads);
      assert.equal(h.count('choose'), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
    } finally { assets.dispose(); }
  });
}

test('generic selected alone cannot authorize Open or Choose, and the reverse event order still opens only the held image token', async () => {
  const h = await connected(), assets = await linkedAssets(h);
  try {
    assert.equal(h.controller.choose(), true);
    assets.emit(genericImageStatus(1, { phase: 'selected', source: 'captured', settlement: 'known' }));
    assert.equal(h.count('open'), 0, 'numeric generic ID73 is not an image selection or token');
    assert.equal(h.controller.choose(), false);
    h.publishSelection(selection());
    assert.equal(h.count('open'), 1);
    assert.deepEqual(h.last('open').args, { projectId: 'a', selectionToken: ID.selection });
    assert.notEqual(h.state.attempt.selection.operationId, String(assets.controller.getSnapshot().status.operation.operationId));
  } finally { assets.dispose(); }
  const orphan = await connected(), orphanAssets = await linkedAssets(orphan);
  try {
    orphanAssets.emit(genericImageStatus(1, { phase: 'selected', source: 'captured', settlement: 'known' }));
    orphan.publishSelection(selection());
    orphan.controller.syncAssetSession();
    assert.equal(orphan.count('open'), 0); assert.equal(orphan.controller.choose(), false);
  } finally { orphanAssets.dispose(); }
});

test('own image Open never bypasses a competing generic owner, and unknown asset cleanup stays blocked after later idle', async () => {
  for (const competing of ['credential', 'unknown']) {
    const h = await connected(), assets = await linkedAssets(h);
    try {
      assert.equal(h.controller.choose(), true);
      assets.emit(genericImageStatus(1, {})); h.publishSelection(selection());
      assets.emit(genericImageStatus(2, competing === 'credential'
        ? { operation: 'choose-file', phase: 'selected', source: 'captured', settlement: 'known' }
        : { phase: 'unknown', reason: 'cleanup-unknown', source: 'unknown', settlement: 'unknown' }));
      h.controller.syncAssetSession(); assert.equal(h.count('open'), 0);
      assets.emit(genericImageStatus(3, { operation: competing === 'credential' ? 'choose-file' : 'choose-images',
        phase: 'idle', source: 'captured', settlement: 'known' }));
      assert.equal(h.count('open'), competing === 'credential' ? 1 : 0);
      assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
    } finally { assets.dispose(); }
  }
});

test('the generic self-selection exception is restricted to Open and never masks pending origin, context or observation state', async () => {
  const h = await connected(), assets = await linkedAssets(h);
  try {
    assets.emit(genericImageStatus(1, { phase: 'selected', source: 'captured', settlement: 'known' }));
    const state = assets.controller.getSnapshot();
    assert.notEqual(metadataImagesAssetSessionReason(state), null);
    assert.equal(metadataImagesAssetSessionReason(state, 'open-held-selection'), null);
    for (const patch of [{ blocked: true }, { observationFailed: true }, { originPending: true },
      { busy: 'choose-file' }, { updatingContext: true }, { status: null }, { mode: 'unavailable' }])
      assert.notEqual(metadataImagesAssetSessionReason({ ...state, ...patch }, 'open-held-selection'), null);
    for (const patch of [{ operation: 'choose-project-path' }, { phase: 'capturing' }, { settlement: 'pending' },
      { settlement: 'late-known' }, { source: 'pending' }, { reason: 'busy' }])
      assert.notEqual(metadataImagesAssetSessionReason({ ...state, status: genericImageStatus(2, {
        phase: 'selected', source: 'captured', settlement: 'known', ...patch }) }, 'open-held-selection'), null);
    assert.equal(h.count('open'), 0);
  } finally { assets.dispose(); }
});

test('an already consumed image token and an invalidated project never acquire Open permission from generic settlement', async () => {
  for (const changed of ['consumed', 'project']) {
    const h = await connected(), assets = await linkedAssets(h);
    try {
      assert.equal(h.controller.choose(), true);
      assets.emit(genericImageStatus(1, {}));
      h.publishSelection(selection('selected', { selectionToken: changed === 'consumed' ? null : ID.selection }));
      if (changed === 'project') h.add('b');
      assets.emit(genericImageStatus(2, { phase: 'selected', source: 'captured', settlement: 'known' }));
      assets.emit(genericImageStatus(3, { phase: 'idle', source: 'captured', settlement: 'known' }));
      assert.equal(h.count('open'), 0); assert.equal(h.count('choose'), 1);
    } finally { assets.dispose(); }
  }
});

test('the bridge preserves only closed method-specific no-admission markers without reflecting native error text', async () => {
  const routes = [
    ['metadata_images_selection_not_admitted', (api) => api.chooseMetadataImages({ projectId: 'a', platform: 'android', locale: 'en-US', assetType: 'phoneScreenshots' })],
    ['metadata_images_import_not_matched', (api) => api.openMetadataImagesEdit({ projectId: 'a', selectionToken: ID.selection })],
    ['metadata_images_import_not_admitted', (api) => api.openMetadataImagesEdit({ projectId: 'a', selectionToken: ID.selection })],
    ['metadata_images_recovery_not_admitted', (api) => api.openMetadataImagesRecovery('a')],
  ];
  for (const [code, call] of routes) {
    let invokes = 0;
    const api = createMetadataImagesApi('native', async () => { invokes += 1; throw { code, message: '/private-error-canary', cause: 'private-detail' }; });
    await assert.rejects(call(api), (error) => {
      assert.equal(error.code, code); assert.equal(error.retryable, false);
      assert.deepEqual(Object.keys(error).sort(), ['code', 'message', 'retryable']);
      assert.doesNotMatch(error.message, /private-error-canary|private-detail/); return true;
    });
    assert.equal(invokes, 1);
  }
});

for (const [kind, marker] of [['choose', 'metadata_images_selection_not_admitted'], ['recover', 'metadata_images_recovery_not_admitted']]) {
  test('proven pre-owner ' + kind + ' rejection retires only its no-ID attempt after one original status observation', async () => {
    const h = await connected();
    assert.equal(kind === 'choose' ? h.controller.choose() : h.controller.inspectRecovery(), true);
    assert.equal(h.state.attempt.selection, null); assert.equal(h.state.attempt.projection, null);
    const reads = [h.count('selection-status'), h.count('edit-status')], pending = h.deferSelectionStatus();
    h.last(kind).reject({ code: marker }); await flush();
    assert.equal(h.state.attempt, null); assert.equal(h.state.reading, true);
    assert.equal(h.controller.choose(), false, 'negative admission does not replace current status');
    pending.resolve(h.selectionFrame); await flush();
    assert.equal(h.state.error.code, marker); assert.equal(metadataImagesOwnerReason(h.state), null);
    assert.deepEqual([h.count('selection-status'), h.count('edit-status')], reads.map((n) => n + 1));
    assert.equal(h.count(kind), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
    assert.equal(h.controller.startReason(), null);
  });
}

test('a no-admission marker does not erase a different retained image selection or supply global idle', async () => {
  const h = await connected(); assert.equal(h.controller.choose(), true);
  h.publishSelection(selection('selected', { projectId: 'foreign', operationId: ID.other }));
  assert.equal(h.state.attempt.selection, null);
  h.last('choose').reject({ code: 'metadata_images_selection_not_admitted' }); await flush();
  assert.equal(h.state.attempt, null);
  assert.equal(h.state.selectionStatus.lastTerminal.projectId, 'foreign');
  assert.notEqual(metadataImagesOwnerReason(h.state), null); assert.equal(h.controller.choose(), false);
  assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
});

test('only the matching command-specific pre-owner marker can release a missing-ID attempt', async () => {
  for (const kind of ['choose', 'recover']) {
    for (const code of ['busy', 'metadata_images_busy', 'refused', 'metadata_images_unavailable',
      kind === 'choose' ? 'metadata_images_recovery_not_admitted' : 'metadata_images_selection_not_admitted',
      'metadata_images_import_not_matched', 'metadata_images_import_not_admitted']) {
      const h = await connected();
      assert.equal(kind === 'choose' ? h.controller.choose() : h.controller.inspectRecovery(), true);
      const serial = h.state.attempt.binding.serial;
      h.last(kind).reject({ code }); await flush();
      assert.equal(h.state.attempt.binding.serial, serial);
      assert.equal(imageAttemptFinished(h.state.attempt), false);
      assert.equal(h.state.error.code, 'metadata_images_reply_lost');
      assert.equal(h.controller.choose(), false); assert.equal(h.controller.inspectRecovery(), false);
      h.controller.requestStop();
      assert.equal(h.count(kind), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
    }
  }
});

test('unmatched Open retires only that Open and settles the retained selection through its one native cancel, never retry or edit Close', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  assert.equal(h.count('open'), 1); assert.equal(h.state.attempt.projection, null);
  h.last('open').reject({ code: 'metadata_images_import_not_matched' }); await flush();
  assert.equal(h.state.attempt.openClaimed, false); assert.equal(h.state.attempt.invalidated, true);
  assert.equal(h.state.attempt.selection.operationId, ID.operation);
  assert.equal(h.count('cancel'), 1); assert.deepEqual(h.last('cancel').args, { operationId: ID.operation });
  assert.equal(h.count('close'), 0); assert.equal(h.count('open'), 1);
  h.controller.requestStop(); h.controller.syncAssetSession();
  assert.equal(h.count('cancel'), 1); assert.equal(h.count('open'), 1);
  h.publishSelection(selection('cancelled', { items: captureItems() }));
  assert.equal(imageAttemptFinished(h.state.attempt), true); assert.equal(metadataImagesOwnerReason(h.state), null);
  assert.equal(h.state.error.code, 'metadata_images_import_not_matched');
});

test('unmatched Open may finish an already settled cancellation but cannot fabricate one', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  h.publishSelection(selection('cancelled', { items: captureItems() }));
  assert.equal(imageAttemptFinished(h.state.attempt), false, 'until its pending Open is proved unmatched');
  h.last('open').reject({ code: 'metadata_images_import_not_matched' }); await flush();
  assert.equal(imageAttemptFinished(h.state.attempt), true);
  assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0); assert.equal(h.count('open'), 1);
});

test('even a closed no-admission marker cannot clear an already observed original selection or edit owner', async () => {
  for (const [kind, marker] of [['choose', 'metadata_images_selection_not_admitted'],
    ['open', 'metadata_images_import_not_matched'], ['open', 'metadata_images_import_not_admitted'], ['recover', 'metadata_images_recovery_not_admitted']]) {
    const h = await connected({ view: kind === 'recover' ? recoveryView() : importView() });
    if (kind === 'recover') { h.controller.inspectRecovery(); h.publishEdit(h.owner('opening')); }
    else { h.controller.choose(); h.publishSelection(selection(kind === 'choose' ? 'selecting' : 'selected'));
      if (kind === 'open') h.publishEdit(h.owner('opening')); }
    const serial = h.state.attempt.binding.serial;
    h.last(kind).reject({ code: marker }); await flush();
    assert.equal(h.state.attempt.binding.serial, serial);
    assert.equal(imageAttemptFinished(h.state.attempt), false);
    assert.equal(h.count(kind), 1);
    assert.equal(h.count('cancel'), kind === 'choose' ? 1 : 0);
    assert.equal(h.count('close'), kind === 'choose' ? 0 : 1);
    assert.equal(h.controller.choose(), false);
  }
});

test('busy or lost Open after matching token consumption stays retained until its original edit status settles', async () => {
  for (const error of [{ code: 'metadata_images_busy' }, new Error('inert lost reply')]) {
    const h = await connected(); h.controller.choose(); h.publishSelection(selection());
    h.publishSelection(selection('selected', { selectionToken: null }));
    h.last('open').reject(error); await flush();
    assert.equal(h.state.attempt.openClaimed, true); assert.equal(h.state.attempt.projection, null);
    assert.equal(imageAttemptFinished(h.state.attempt), false);
    assert.equal(h.state.error.code, 'metadata_images_reply_lost');
    assert.equal(h.controller.choose(), false); h.controller.requestStop();
    assert.equal(h.count('open'), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
    h.publishEdit(h.owner('opening'));
    assert.equal(h.count('close'), 1, 'only the original admitted edit now supplies its Close identity');
    h.publishEdit(h.closed());
    assert.equal(imageAttemptFinished(h.state.attempt), true);
    assert.equal(h.count('open'), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 1);
  }
});

test('asset-only rechecks cannot skip the original status-read barrier after an unmatched Open', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  const pending = h.deferSelectionStatus();
  h.last('open').reject({ code: 'metadata_images_import_not_matched' }); await flush();
  assert.equal(h.state.reading, true); assert.equal(h.state.attempt.openClaimed, false);
  h.controller.syncAssetSession(); h.controller.syncAssetSession(); h.controller.requestStop();
  assert.equal(h.count('cancel'), 0); assert.equal(h.count('open'), 1); assert.equal(h.count('close'), 0);
  pending.resolve(h.selectionFrame); await flush();
  assert.equal(h.count('cancel'), 1); assert.deepEqual(h.last('cancel').args, { operationId: ID.operation });
  assert.equal(h.count('open'), 1); assert.equal(h.count('close'), 0);
});


test('selected source retirement preserves the complete original roster through pending and direct known refusal', () => {
  const captured = selection();
  for (const next of [selection('capturing', { reason: 'busy', items: captureItems() }),
    selection('failed', { reason: 'busy', items: captureItems() }), selection('cancelled', { items: captureItems() })]) {
    const after = next.phase === 'capturing' ? selectionStatus(2, next) : selectionStatus(2, null, next);
    assert.ok(parseMetadataImagesSelectionStatus(after));
    assert.equal(metadataImagesSelectionProjectionProgress(captured, next), true);
    assert.equal(metadataImagesSelectionProgress(selectionStatus(1, null, captured), after), true);
    for (const change of [(row) => { row.items = []; }, (row) => { row.items.reverse(); },
      (row) => { row.items[0].sha256 = '7'.repeat(64); }, (row) => { row.selectionToken = ID.selection; },
      (row) => { row.projectId = 'foreign'; }, (row) => { row.locale = 'fr-FR'; },
      (row) => { row.operationId = ID.other; }, (row) => { row.assetType = 'icon'; }]) {
      const wrong = clone(next); change(wrong);
      assert.equal(metadataImagesSelectionProjectionProgress(captured, wrong), false);
    }
  }
  assert.equal(metadataImagesSelectionProjectionProgress(captured, selection('cancelled', { reason: 'busy', items: captureItems() })), false);
  assert.equal(metadataImagesSelectionProjectionProgress(captured, selection('capturing', { items: captureItems() })), false);
  assert.equal(metadataImagesSelectionProjectionProgress(captured, selection('selecting', { reason: 'busy', items: captureItems() })), false);
});

test('global Unknown may overtake a consumed selection but never grants cancellation, token resurrection or normal settlement', () => {
  const captured = selection(), consumed = selection('selected', { selectionToken: null });
  const unknown = selection('unknown', { items: captureItems() }), late = { ...clone(unknown), settlement: 'late-known' };
  for (const first of [captured, consumed]) {
    assert.equal(metadataImagesSelectionProjectionProgress(first, unknown), true);
    assert.equal(metadataImagesSelectionProjectionProgress(first, late), true);
  }
  assert.equal(metadataImagesSelectionProjectionProgress(unknown, late), true);
  assert.equal(metadataImagesSelectionProjectionProgress(late, unknown), false);
  assert.equal(imageSelectionSettled(late), false);
  for (const next of [captured, selection('cancelled', { items: captureItems() }),
    selection('failed', { reason: 'busy', items: captureItems() }),
    selection('capturing', { reason: 'busy', items: captureItems() })]) {
    assert.equal(metadataImagesSelectionProjectionProgress(consumed, next), false);
    assert.equal(metadataImagesSelectionProjectionProgress(late, next), false);
  }
  assert.equal(metadataImagesSelectionProjectionProgress(consumed, { ...unknown, items: [] }), false);
  assert.equal(metadataImagesSelectionProjectionProgress(consumed, { ...unknown, reason: 'busy' }), false);
});

test('selection STOP-pending retains its first reason and items until known refusal or sticky global Unknown', () => {
  const pending = selection('capturing', { reason: 'busy', items: captureItems() });
  const failed = selection('failed', { reason: 'busy', items: captureItems() });
  const unknown = selection('unknown', { items: captureItems() });
  assert.equal(metadataImagesSelectionProjectionProgress(pending, failed), true);
  assert.equal(metadataImagesSelectionProjectionProgress(pending, unknown), true);
  assert.equal(metadataImagesSelectionProjectionProgress(failed, unknown), true);
  for (const next of [selection(), { ...pending, reason: 'none' }, { ...failed, reason: 'cancelled' },
    { ...failed, items: [] }, { ...pending, phase: 'selecting' }, { ...unknown, items: [] },
    { ...pending, items: [...captureItems(), { ...captureItems()[0], itemId: ID.other }] }]) {
    assert.equal(metadataImagesSelectionProjectionProgress(pending, next), false);
  }
});

test('matched pre-edit rejection releases only Open after the original selection actually reports failed-known', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  const serial = h.state.attempt.binding.serial;
  h.publishSelection(selection('failed', { reason: 'busy', items: captureItems() }));
  assert.equal(h.state.integrityFailed, false); assert.equal(imageAttemptFinished(h.state.attempt), false);
  h.last('open').reject({ code: 'metadata_images_import_not_admitted' }); await flush();
  assert.equal(h.state.attempt.binding.serial, serial); assert.equal(h.state.attempt.openClaimed, false);
  assert.equal(h.state.attempt.invalidated, true); assert.equal(h.state.attempt.projection, null);
  assert.equal(imageAttemptFinished(h.state.attempt), true); assert.equal(metadataImagesOwnerReason(h.state), null);
  assert.equal(h.state.acknowledged, null); assert.equal(currentMetadataImagesApplyBinding(h.state), null);
  h.controller.requestStop(); h.controller.syncAssetSession();
  assert.equal(h.count('open'), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
  assert.equal(h.controller.choose(), true, 'a later explicit selection is not a retry of the retired Open');
  assert.ok(h.state.attempt.binding.serial > serial); assert.equal(h.count('open'), 1);
});

test('matched pre-edit rejection cannot skip original status observation or declare pending selection cleanup complete', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  const read = h.deferSelectionStatus();
  h.last('open').reject({ code: 'metadata_images_import_not_admitted' }); await flush();
  assert.equal(h.state.attempt.openClaimed, false); assert.equal(h.state.attempt.invalidated, true);
  assert.equal(imageAttemptFinished(h.state.attempt), false); assert.equal(h.controller.choose(), false);
  h.controller.syncAssetSession(); h.controller.requestStop();
  const pending = selection('capturing', { reason: 'busy', items: captureItems() });
  h.emitSelection(selectionStatus(2, pending));
  assert.equal(h.state.integrityFailed, false); assert.equal(h.count('cancel'), 0, 'events do not release the read barrier');
  read.resolve(h.selectionFrame); await flush();
  assert.equal(h.count('cancel'), 1); assert.deepEqual(h.last('cancel').args, { operationId: ID.operation });
  assert.equal(h.count('close'), 0); assert.equal(h.count('open'), 1); assert.equal(imageAttemptFinished(h.state.attempt), false);
  h.publishSelection(selection('failed', { reason: 'busy', items: captureItems() }));
  h.last('cancel').resolve(h.selectionFrame); await flush();
  assert.equal(imageAttemptFinished(h.state.attempt), true); assert.equal(metadataImagesOwnerReason(h.state), null);
  assert.equal(h.count('cancel'), 1); assert.equal(h.count('close'), 0); assert.equal(h.count('open'), 1);
});

test('matched pre-edit rejection retains Unknown and late-known selection evidence without a replacement owner or Close', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  const unknown = selection('unknown', { items: captureItems() });
  h.emitSelection(selectionStatus(2, unknown, null, 'cleanup_unknown'));
  h.last('open').reject({ code: 'metadata_images_import_not_admitted' }); await flush();
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.attempt.openClaimed, false);
  assert.equal(h.state.nativeBlocked, true); assert.equal(h.state.unknownSelection.operationId, ID.operation);
  assert.equal(imageAttemptFinished(h.state.attempt), false);
  h.emitSelection(selectionStatus(3, null, { ...unknown, settlement: 'late-known' }, 'cleanup_unknown'));
  h.controller.requestStop(); h.controller.syncAssetSession();
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.attempt.selection.settlement, 'late-known');
  assert.equal(h.state.nativeBlocked, true); assert.equal(imageAttemptFinished(h.state.attempt), false);
  assert.equal(h.controller.choose(), false); assert.equal(h.controller.inspectRecovery(), false);
  assert.equal(h.count('open'), 1); assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0);
});

test('failed-known selection alone never proves that an ordinary or lost Open had no EditOwner claim', async () => {
  for (const error of [{ code: 'metadata_images_busy' }, new Error('inert lost admission reply')]) {
    const h = await connected(); h.controller.choose(); h.publishSelection(selection());
    h.publishSelection(selection('failed', { reason: 'busy', items: captureItems() }));
    h.last('open').reject(error); await flush();
    assert.equal(h.state.integrityFailed, false); assert.equal(h.state.attempt.openClaimed, true);
    assert.equal(imageAttemptFinished(h.state.attempt), false); assert.equal(h.controller.choose(), false);
    assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0); assert.equal(h.count('open'), 1);
    h.publishEdit(h.owner('opening')); assert.equal(h.count('close'), 1);
    h.publishEdit(h.closed()); assert.equal(imageAttemptFinished(h.state.attempt), true);
    assert.equal(h.count('close'), 1); assert.equal(h.count('open'), 1);
  }
});

test('matched pre-edit rejection cannot clear foreign active ownership or a different project recovery block', async () => {
  const h = await connected(); h.controller.choose(); h.publishSelection(selection());
  const foreign = h.owner('opening', { projectId: 'foreign', sessionId: ID.other });
  const recovery = h.owner('final', { projectId: 'needs-recovery', sessionId: '5'.repeat(32), applySubmitted: false, details: null,
    nativeReason: 'io_error', coreOutcome: { effect: 'not_started', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } });
  h.emitEdit(editStatus(1, foreign, recovery));
  h.publishSelection(selection('failed', { reason: 'busy', items: captureItems() }));
  h.last('open').reject({ code: 'metadata_images_import_not_admitted' }); await flush();
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.attempt.projection, null);
  assert.equal(h.state.attempt.openClaimed, false); assert.equal(imageAttemptFinished(h.state.attempt), true);
  assert.equal(h.state.editStatus.active.sessionId, ID.other); assert.deepEqual(h.state.recoveryProjects, ['needs-recovery']);
  assert.notEqual(metadataImagesOwnerReason(h.state), null); assert.equal(h.controller.choose(), false);
  assert.equal(h.count('cancel'), 0); assert.equal(h.count('close'), 0); assert.equal(h.count('open'), 1);
});

test('a late matched-no-edit marker from an earlier Open cannot retire a newer local selection serial', async () => {
  const h = await connected(); checkedOut(h); const earlierOpen = h.last('open');
  h.controller.requestStop(); h.publishEdit(h.closed());
  assert.equal(imageAttemptFinished(h.state.attempt), true); assert.equal(h.controller.choose(), true);
  const serial = h.state.attempt.binding.serial;
  h.publishSelection(selection('selecting', { operationId: ID.other }));
  earlierOpen.reject({ code: 'metadata_images_import_not_admitted' }); await flush();
  assert.equal(h.state.integrityFailed, false); assert.equal(h.state.attempt.binding.serial, serial);
  assert.equal(h.state.attempt.selection.operationId, ID.other); assert.equal(h.state.attempt.invalidated, false);
  assert.equal(h.state.attempt.cancelRequested, false); assert.equal(imageAttemptFinished(h.state.attempt), false);
  assert.equal(h.count('choose'), 2); assert.equal(h.count('open'), 1); assert.equal(h.count('cancel'), 0);
});


test('coalesced first negative selection snapshots catch up immutable metadata without restoring authority', async () => {
  const items = captureItems();
  const beforeSamples = [selection('selecting'), selection('capturing'), selection('capturing', { items: items.slice(0, 1) })];
  const afterSamples = [selection('capturing', { reason: 'busy', items }), selection('failed', { reason: 'busy', items }),
    selection('cancelled', { items }), selection('unknown', { items }), selection('unknown', { items, settlement: 'late-known' })];
  for (const first of beforeSamples) {
    const before = selectionStatus(1, first);
    assert.ok(parseMetadataImagesSelectionStatus(before));
    for (const next of afterSamples) {
      const terminal = imageSelectionSettled(next) || next.settlement === 'late-known';
      const after = selectionStatus(2, terminal ? null : next, terminal ? next : null, next.phase === 'unknown' ? 'cleanup_unknown' : 'available');
      assert.ok(parseMetadataImagesSelectionStatus(after));
      assert.equal(metadataImagesSelectionProjectionProgress(first, next), true);
      assert.equal(metadataImagesSelectionProgress(before, after), true);
      assert.equal(metadataImagesSelectionProjectionProgress(first, { ...next, selectionToken: ID.selection }), false);
      if (first.items.length) {
        assert.equal(metadataImagesSelectionProjectionProgress(first, { ...next, items: items.slice(1) }), false, 'observed prefix cannot disappear');
        assert.equal(metadataImagesSelectionProjectionProgress(first, { ...next, items: [{ ...items[0], sha256: '7'.repeat(64) }, items[1]] }), false);
        assert.equal(metadataImagesSelectionProjectionProgress(first, { ...next, items: [...items].reverse() }), false);
      }
      for (const changedItems of [[], items.slice(0, 1), [...items, { ...items[0], itemId: ID.other }]]) {
        assert.equal(metadataImagesSelectionProjectionProgress(next, { ...next, items: changedItems }), false, 'first STOP/Unknown freezes its complete roster');
      }
      assert.equal(metadataImagesSelectionProjectionProgress(next, selection()), false, 'negative catch-up never restores selected/token authority');
      const h = await connected(); assert.equal(h.controller.choose(), true);
      h.emitSelection(before); h.emitSelection(after);
      assert.equal(h.state.integrityFailed, false, 'skipping selected is legitimate coalesced native history');
      const observed = h.state.selectionStatus.active ?? h.state.selectionStatus.lastTerminal;
      assert.deepEqual(observed.items, items); assert.equal(observed.selectionToken, null);
      assert.equal(h.count('open'), 0); assert.equal(h.count('prepare'), 0); assert.equal(h.count('apply'), 0); assert.equal(h.count('close'), 0);
      if (next.phase === 'unknown') {
        assert.equal(h.state.nativeBlocked, true); assert.equal(imageAttemptFinished(h.state.attempt), false);
        assert.equal(h.controller.choose(), false); assert.equal(h.controller.inspectRecovery(), false);
      }
    }
  }
});
