// Fake ports + actual UI controllers. No native picker, source proof, download,
// tool execution, registration or qualification is supplied by these tests.
import test from 'node:test';
import assert from 'node:assert/strict';
import { PreparedToolSourceHandoff } from '../src/toolAcquisitionSourcePicker.ts';
import { ToolAcquisitionController } from '../src/toolAcquisitionController.ts';
import { AndroidBuildController, androidBuildOwnerReason } from '../src/androidBuild.ts';
import { encodeAndroidToolSourcesRequest } from '../src/androidToolSources.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';

const OP = 'a'.repeat(32), GEN = 'b'.repeat(32), INSPECT = 'c'.repeat(32), INSPECT_GEN = 'd'.repeat(32), SHA = 'e'.repeat(64);
const clone = (v) => structuredClone(v);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 30; n++) await Promise.resolve(); };
const sourceIdle = () => ({ schemaVersion: 1, statusRevision: 0, sourceGeneration: 0, projectId: null,
  availability: 'available', phase: 'idle', reason: 'not-inspected', operation: null, selections: [], inspection: 'not-run', protectedCopy: 'not-created' });
const source = (generation, role, phase = 'selected') => ({ ...sourceIdle(), statusRevision: generation * 3 + (phase === 'selected' ? 1 : 0),
  sourceGeneration: generation, projectId: 'p1', phase, reason: phase === 'selected' ? 'not-inspected' : 'none',
  availability: phase === 'selected' ? 'available' : 'busy', operation: { operationId: generation, sourceGeneration: generation, role },
  selections: phase === 'selected' ? [{ role, displayName: 'Prepared folder' }] : [] });
const context = () => ({ projectId: 'p1', draftRevision: 0, baselineGeneration: 1, savedConfig: { bytes: 120, sha256: SHA }, action: 'inspect', review: null });
const catalog = (revision = 0, phase = 'ready', availability = 'available') => ({ schemaVersion: 1, statusRevision: revision,
  catalogGeneration: 1, operationId: 'f'.repeat(32), availability, phase, reason: phase === 'ready' ? 'none' : 'catalog-changed', entries: [], selected: null });
const registration = (revision = 0, availability = 'runtime-unqualified') => ({ schemaVersion: 1, statusRevision: revision,
  registrationGeneration: 0, availability, prerequisite: 'approval-required', phase: 'idle', reason: 'approval-required', operation: null, review: null, report: null });
const report = () => ({ schemaVersion: 1, kind: 'staged-tool-sources', operationId: OP, contextSha256: SHA, referenceSha256: SHA,
  projectionSha256: SHA, cacheJob: `tool-${OP}`, lookupScope: 'registered-selected-known', reusedArchives: ['jdk'],
  downloadedArchives: ['sdk-platform', 'sdk-build-tools', 'gradle'], groups: [
    { group: 'jdk', components: ['jdk'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'sdk', components: ['sdk-platform', 'sdk-build-tools'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'gradle', components: ['gradle'], allRequiredComponentsStaged: true, next: 'choose-native-source' }],
  assurance: { nativeFinality: false, registered: false, readyToBuild: false } });
const completed = () => ({ operationId: OP, ownerGeneration: GEN, context: { ...context(), action: 'acquire',
  review: { operationId: INSPECT, ownerGeneration: INSPECT_GEN, requirementsSha256: SHA } }, phase: 'terminal', outcome: 'complete', reason: 'none', intentUsable: false, result: report() });
const folderContext = () => ({ connection: {}, context: context(), observation: 1, draft: {}, baseline: {}, snapshot: {}, catalog: catalog(), registration: registration(), sources: sourceIdle() });

test('nomination envelope extends only the old choose command; null/path/URL/extra fields refuse', () => {
  const ordinary = { schemaVersion: 1, sourceGeneration: 0, projectId: 'p1', role: 'jdk' };
  const acquired = { operationId: OP, ownerGeneration: GEN };
  for (const input of [ordinary, { ...ordinary, acquired }]) {
    const raw = encodeAndroidToolSourcesRequest('choose_android_tool_source', input);
    assert.ok(raw instanceof Uint8Array); assert.ok(raw.length <= 1024);
    assert.deepEqual(JSON.parse(new TextDecoder().decode(raw)), input);
  }
  for (const value of [null, undefined, {}, '/native/cache', { ...acquired, path: '/native/cache' },
    { ...acquired, operationId: 'https://vendor.invalid/file' }, { ...acquired, ownerGeneration: 'A'.repeat(32) }])
    assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source', { ...ordinary, acquired: value }), null);
  assert.equal(encodeAndroidToolSourcesRequest('android_tool_sources_status', { schemaVersion: 1, acquired }), null);
  let getter = 0;
  const bad = { ...ordinary }; Object.defineProperty(bad, 'acquired', { enumerable: true, get() { getter++; return acquired; } });
  assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source', bad), null); assert.equal(getter, 0);
});

test('only a current completed acquire offers folders; staging DATA never grants readiness', () => {
  const handoff = new PreparedToolSourceHandoff(), c = folderContext(), op = completed();
  for (const phase of ['settling', 'stale', 'recovery-required']) assert.equal(handoff.preview(c, op, phase), null);
  for (const change of [{ phase: 'running' }, { outcome: 'cancelled' }, { context: context() }, { result: { ...report(), operationId: INSPECT } }])
    assert.equal(handoff.preview(c, { ...op, ...change }, 'current-staged'), null);
  assert.deepEqual(handoff.preview(c, op, 'current-staged').roles, ['jdk', 'sdk', 'gradle']);
  assert.deepEqual(op.result.assurance, { nativeFinality: false, registered: false, readyToBuild: false });
});

test('incomplete SDK offers manual route, never a prepared SDK nomination', () => {
  const handoff = new PreparedToolSourceHandoff(), c = folderContext(), op = completed();
  op.result.downloadedArchives = ['sdk-platform', 'gradle'];
  op.result.groups[1] = { group: 'sdk', components: ['sdk-platform'], allRequiredComponentsStaged: false, next: 'complete-sdk-manually' };
  assert.deepEqual(handoff.preview(c, op, 'current-staged'), { roles: ['jdk', 'gradle'], incompleteSdk: true, continuing: false, waiting: false });
  assert.equal(handoff.begin(c, op, 'current-staged', 'sdk', () => c), null);
});

test('unqualified or absent original source-picker status cannot offer a prepared shortcut', () => {
  const handoff = new PreparedToolSourceHandoff(), op = completed();
  for (const value of [null, { ...sourceIdle(), availability: 'runtime-unqualified' }, { ...sourceIdle(), availability: 'cleanup-unknown' }]) {
    const c = { ...folderContext(), sources: value };
    assert.equal(handoff.preview(c, op, 'current-staged'), null);
    assert.equal(handoff.begin(c, op, 'current-staged', 'jdk', () => c), null);
  }
});

test('current IDs are one-use per explicit pick and only its own source generation advances', () => {
  const h = new PreparedToolSourceHandoff(); let c = folderContext(); const op = completed();
  const first = h.begin(c, op, 'current-staged', 'jdk', () => c);
  assert.deepEqual(first.claim('p1', 'jdk', 0), { operationId: OP, ownerGeneration: GEN });
  assert.equal(first.claim('p1', 'jdk', 0), null);
  c = { ...c, sources: source(1, 'jdk'), catalog: catalog(4, 'refused'), registration: registration(4) }; assert.ok(first.stillCurrent());
  // Even a positive source status cannot settle an unresolved original invoke.
  assert.equal(h.begin(c, op, 'stale', 'sdk', () => c), null);
  first.joined();
  const second = h.begin(c, op, 'stale', 'sdk', () => c); assert.ok(second);
  assert.equal(second.claim('p1', 'sdk', 0), null);
  assert.deepEqual(second.claim('p1', 'sdk', 1), { operationId: OP, ownerGeneration: GEN });
  c = { ...c, sources: source(3, 'sdk') }; assert.equal(second.stillCurrent(), false);
  assert.equal(h.preview(c, op, 'stale'), null);
});

for (const field of ['connection', 'draft', 'baseline', 'snapshot', 'catalog', 'registration', 'observation']) {
  test(`handoff retires on ${field} replacement, including equal-looking saved snapshots`, () => {
    const h = new PreparedToolSourceHandoff(); let c = folderContext(); const op = completed();
    const pick = h.begin(c, op, 'current-staged', 'jdk', () => c);
    c = { ...c, [field]: field === 'observation' ? 2 : clone(c[field]) };
    assert.equal(pick.claim('p1', 'jdk', 0), null); assert.equal(h.preview(c, op, 'stale'), null);
  });
}

test('context ABA, lost invoke and unknown source never refresh the handoff', () => {
  for (const cut of ['aba', 'lost', 'unknown']) {
    const h = new PreparedToolSourceHandoff(); let c = folderContext(); const old = c, op = completed();
    const pick = h.begin(c, op, 'current-staged', 'jdk', () => c);
    pick.claim('p1', 'jdk', 0);
    if (cut === 'aba') { h.retire(); c = old; }
    else if (cut === 'lost') pick.joined(); // No native acknowledgement, not a retry.
    else { c = { ...c, sources: { ...source(1, 'jdk'), phase: 'unknown', reason: 'cleanup-unknown', selections: [] } }; h.sync(c); }
    assert.equal(pick.stillCurrent(), false); assert.equal(h.preview(c, op, 'stale'), null);
  }
});

async function controllers(t, { initialSources = sourceIdle(), missing = ['jdk', 'sdk-platform', 'sdk-build-tools', 'gradle'], staged = report() } = {}) {
  let ws = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert', path: '/never-opened-tools' } });
  ws = workspaceReducer(ws, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  ws = workspaceReducer(ws, { type: 'snapshot-done', projectId: 'p1', requestId: 1, observedAt: 1, snapshot: {
    root: '/never-opened-tools', config: { path: 'release/mobile-release.json', state: 'format-valid', data: { android: { enabled: true, module: ':app' } },
      content: { bytes: 120, sha256: SHA }, issues: [] }, discovery: { hints: {} }, issues: [] } });
  let tools, native = { schemaVersion: 1, statusRevision: 0, availability: 'available', operation: null }, sources = clone(initialSources);
  let catalogStatus = catalog(), registrationStatus = registration();
  const calls = [], observers = [];
  const listen = (kind, callback) => { const entry = { kind, callback, closed: false }; observers.push(entry); return () => { entry.closed = true; }; };
  const project = () => ws.projects[ws.selectedId];
  const android = new AndroidBuildController({ selectedProject: project, releaseVersion: () => null, otherOperationReason: () => tools?.ownerReason() ?? null });
  const androidApi = { mode: 'native',
    subscribeAndroidBuild: async (receive) => listen('build', receive),
    androidBuildStatus: async () => ({ schemaVersion: 1, statusRevision: 0, availability: 'available', operation: null }),
    subscribeAndroidToolchainCatalog: async (receive) => listen('catalog', receive),
    androidToolchainCatalogStatus: async () => clone(catalogStatus),
    subscribeAndroidToolRegistration: async (receive) => listen('registration', receive),
    androidToolRegistrationStatus: async () => clone(registrationStatus),
    inspectAndroidToolSources: async () => { throw new Error('not this action'); },
    registerAndroidToolSources: async () => { throw new Error('not this action'); },
    cancelAndroidToolRegistration: async () => { throw new Error('not this action'); },
    subscribeAndroidToolSources: async (receive) => listen('sources', receive), androidToolSourcesStatus: async () => clone(sources),
    chooseAndroidToolSource: (input) => { const call = { kind: 'choose', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelAndroidToolSource: (input) => { const call = { kind: 'cancel', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    refreshAndroidToolchainCatalog: async () => { throw new Error('not this action'); }, prepareAndroidBuild: async () => { throw new Error('not this action'); } };
  android.syncProject(); await android.connect(androidApi);
  tools = new ToolAcquisitionController({ selectedProject: project, otherOperationReason: () => androidBuildOwnerReason(android.getSnapshot()),
    knownTools: () => { const s = android.getSnapshot(); return [s.catalogStatus, s.toolSources, s.toolRegistration]; } });
  const toolApi = { mode: 'native', subscribe: async (receive) => listen('tools', receive), status: async () => clone(native),
    prepare: async (input) => {
      native = { schemaVersion: 1, statusRevision: native.statusRevision + 1, availability: 'busy', operation: {
        operationId: input.action === 'inspect' ? INSPECT : OP, ownerGeneration: input.action === 'inspect' ? INSPECT_GEN : GEN,
        context: clone(input), phase: 'awaiting-consent', intentUsable: true, reason: 'none', outcome: null, result: null } }; return clone(native);
    }, start: async () => {
      const op = native.operation;
      const requirements = { kind: 'tool-requirements-observation', protectedTools: 'none-in-supported-catalogue', components: { missing,
        compatible: ['jdk', 'sdk-platform', 'sdk-build-tools', 'gradle'].filter((part) => !missing.includes(part)) }, requirements: { schemaVersion: 1, basis: 'unverified-static-source-hints', sourcesSha256: SHA,
        complete: true, platform: 'android', projectCodeExecuted: false, xcode: { version: '26.3', build: '17C529' }, android: {
          jdk: { state: 'literal', value: '17' }, agp: { state: 'literal', value: '8.9.2' }, sdkPlatform: { state: 'literal', value: 'android-35' },
          sdkBuildTools: { state: 'unspecified', value: null }, gradle: { state: 'literal', version: '8.14.5',
            distributionUrl: 'https://services.gradle.org/distributions/gradle-8.14.5-bin.zip', sha256: SHA } } } };
      native = { ...native, availability: 'available', statusRevision: native.statusRevision + 1, operation: { ...op, phase: 'terminal', intentUsable: false,
        outcome: 'complete', result: op.context.action === 'inspect' ? requirements : staged } }; return clone(native);
    }, cancel: async () => { throw new Error('completed acquire has no pending cancellation'); } };
  tools.setVisible(true); await tools.connect(toolApi);
  const off = android.subscribe(() => tools.syncProject());
  t.after(() => { off(); tools.dispose(); android.dispose(); });
  await tools.inspect(); await tools.reviewDownload(); tools.setAcknowledged(OP, GEN, true); await tools.download(OP, GEN);
  assert.equal(tools.getSnapshot().presentation, 'current-staged');
  const peer = (kind, value) => {
    if (kind === 'catalog') catalogStatus = clone(value); else registrationStatus = clone(value);
    observers.find((entry) => entry.kind === kind && !entry.closed)?.callback(clone(value));
  };
  return { tools, android, calls,
    peer,
    choose(role) { return tools.choosePreparedSource(role, (selected, pick) => android.chooseToolSource(selected, pick)); },
    emit(value) { sources = clone(value); observers.find((entry) => entry.kind === 'sources' && !entry.closed)?.callback(clone(value)); },
    reply(call, value, relays = true) {
      if (relays && call.kind === 'choose' && value.phase === 'selected') {
        peer('catalog', catalog(value.statusRevision, 'refused')); peer('registration', registration(value.statusRevision));
      }
      sources = clone(value); call.resolve(clone(value));
    },
    switch() { tools.selectionIntent(); android.selectionIntent(); ws = workspaceReducer(ws, { type: 'select', project: { id: 'p2', name: 'Other', path: '/never-opened-other' } });
      tools.syncProject(); android.syncProject(); },
  };
}

test('actual controllers retain folder handoff across JDK then SDK while old acquire intent stays stale', async (t) => {
  const h = await controllers(t);
  const first = h.choose('jdk'); assert.equal(h.calls.length, 1);
  assert.deepEqual(h.calls[0].input, { schemaVersion: 1, sourceGeneration: 0, projectId: 'p1', role: 'jdk', acquired: { operationId: OP, ownerGeneration: GEN } });
  assert.equal(h.tools.getSnapshot().presentation, 'stale');
  h.emit(source(1, 'jdk')); await h.choose('sdk'); assert.equal(h.calls.length, 1);
  h.reply(h.calls[0], source(1, 'jdk')); await first;
  assert.equal(h.tools.getSnapshot().preparedFolders.waiting, false);
  const second = h.choose('sdk'); assert.equal(h.calls.length, 2);
  assert.equal(h.calls[1].input.sourceGeneration, 1); assert.equal(h.calls[1].input.role, 'sdk');
  assert.deepEqual(h.calls[1].input.acquired, { operationId: OP, ownerGeneration: GEN });
  h.reply(h.calls[1], source(2, 'sdk')); await second;
  assert.equal(h.tools.getSnapshot().presentation, 'stale'); assert.equal(h.tools.getSnapshot().preparedFolders.continuing, true);
});

test('partial download keeps chosen JDK and SDK, offers only prepared Gradle and leaves SDK completion manual', async (t) => {
  const selections = [{ role: 'jdk', displayName: 'Existing JDK' }, { role: 'sdk', displayName: 'Existing SDK with platform 35' }];
  const staged = report(); staged.reusedArchives = []; staged.downloadedArchives = ['sdk-build-tools', 'gradle'];
  staged.groups = [
    { group: 'sdk', components: ['sdk-build-tools'], allRequiredComponentsStaged: false, next: 'complete-sdk-manually' },
    { group: 'gradle', components: ['gradle'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
  ];
  const h = await controllers(t, { initialSources: { ...source(2, 'sdk'), selections }, missing: ['sdk-build-tools', 'gradle'], staged });
  assert.deepEqual(h.tools.getSnapshot().preparedFolders, { roles: ['gradle'], incompleteSdk: true, continuing: false, waiting: false });
  assert.deepEqual(h.android.getSnapshot().toolSources.selections, selections);
  await h.choose('jdk'); await h.choose('sdk'); assert.equal(h.calls.length, 0);
  const picking = h.choose('gradle'); assert.equal(h.calls.length, 1);
  assert.deepEqual(h.calls[0].input, { schemaVersion: 1, sourceGeneration: 2, projectId: 'p1', role: 'gradle',
    acquired: { operationId: OP, ownerGeneration: GEN } });
  const after = [...selections, { role: 'gradle', displayName: 'Prepared Gradle folder' }];
  h.reply(h.calls[0], { ...source(3, 'gradle'), selections: after }); await picking;
  assert.deepEqual(h.android.getSnapshot().toolSources.selections, after);
  assert.equal(h.tools.getSnapshot().preparedFolders.incompleteSdk, true);
  assert.equal(h.tools.getSnapshot().presentation, 'stale');
  assert.equal(h.calls.length, 1); // No SDK replacement, inspection/register or build was auto-invoked.
});

test('same original catalogue retirement and prerequisite relays preserve only the nominated picker across relay order', async (t) => {
  for (const order of ['peers-first', 'source-first', 'after-reply']) {
    const h = await controllers(t), picking = h.choose('jdk');
    if (order === 'source-first') h.emit(source(1, 'jdk', 'picking'));
    if (order !== 'after-reply') {
      h.peer('catalog', catalog(3, 'refused', 'busy')); h.peer('registration', registration(3, 'busy'));
    }
    h.reply(h.calls[0], source(1, 'jdk'), false); await picking;
    assert.equal(h.tools.getSnapshot().preparedFolders.waiting, true);
    await h.choose('sdk'); assert.equal(h.calls.length, 1);
    // Actual status reads can advance the shared revision while restoring
    // their original capability. Wait for the same source's matching relay.
    h.peer('catalog', catalog(5, 'refused')); h.peer('registration', registration(6));
    assert.equal(h.tools.getSnapshot().preparedFolders.waiting, true);
    h.emit({ ...source(1, 'jdk'), statusRevision: 7 });
    assert.equal(h.tools.getSnapshot().preparedFolders.waiting, false);
    const next = h.choose('sdk'); assert.equal(h.calls.length, 2);
    h.reply(h.calls[1], { ...source(2, 'sdk'), statusRevision: 10 }); await next;
    assert.equal(h.tools.getSnapshot().preparedFolders.waiting, false);
    assert.equal(h.tools.getSnapshot().presentation, 'stale');
  }
});

test('catalogue replacement or registration prerequisite drift cannot borrow an outstanding prepared pick', async (t) => {
  for (const changed of ['catalog-generation', 'catalog-original', 'catalog-reason', 'registration-prerequisite']) {
    const h = await controllers(t), picking = h.choose('jdk');
    if (changed === 'registration-prerequisite') h.peer('registration', { ...registration(2), prerequisite: 'approval-denied', reason: 'approval-denied' });
    else h.peer('catalog', { ...catalog(2, 'refused'), ...(changed === 'catalog-generation' ? { catalogGeneration: 2 } :
      changed === 'catalog-original' ? { operationId: '0'.repeat(32) } : { reason: 'catalog-unavailable' }) });
    // A foreign catalogue identity is rejected by the ORIGINAL Android
    // controller before it replaces the known projection. Its sticky issue
    // still blocks all new picks; the handoff must not clear that original.
    const original = h.android.getSnapshot();
    assert.ok(h.tools.getSnapshot().preparedFolders === null || original.catalogIssue || original.registrationIssue);
    h.reply(h.calls[0], source(1, 'jdk'), false); await picking;
    await h.choose('sdk'); assert.equal(h.calls.length, 1);
  }
});

test('project retirement during source-pending notification prevents the original invoke with no fallback', async (t) => {
  const h = await controllers(t); let changed = false;
  const off = h.android.subscribe(() => { if (!changed && h.android.getSnapshot().sourcesPending) { changed = true; h.switch(); } });
  await h.choose('jdk'); off();
  assert.equal(changed, true); assert.equal(h.calls.length, 0);
  assert.equal(h.android.getSnapshot().sourcesPending, false); assert.equal(h.android.getSnapshot().sourcesUnconfirmed, false);
  assert.equal(h.tools.getSnapshot().preparedFolders, null);
});

test('project retirement during tools notification is checked before invoking the Android controller', async (t) => {
  const h = await controllers(t); let changed = false;
  const off = h.tools.subscribe(() => { const s = h.tools.getSnapshot(); if (!changed && s.presentation === 'stale' && s.preparedFolders?.waiting) { changed = true; h.switch(); } });
  await h.choose('jdk'); off(); assert.equal(changed, true); assert.equal(h.calls.length, 0);
});

test('lost invoke stays with the same Android status/cancel owner and cannot replay the prepared shortcut', async (t) => {
  const h = await controllers(t), picking = h.choose('jdk');
  h.calls[0].reject(new Error('inert lost reply')); await picking;
  assert.equal(h.android.getSnapshot().sourcesUnconfirmed, true); assert.equal(h.tools.getSnapshot().preparedFolders, null);
  await h.choose('jdk'); assert.equal(h.calls.length, 1);
  h.emit(source(1, 'jdk', 'picking')); assert.equal(h.android.canCancelToolSources(), true);
  h.android.cancelToolSources(); assert.equal(h.calls.length, 2); assert.equal(h.calls[1].kind, 'cancel');
  const stopped = { ...source(1, 'jdk'), statusRevision: 5, phase: 'cancelled', reason: 'cancelled', selections: [] };
  h.reply(h.calls[1], stopped); await flush();
  assert.equal(h.tools.getSnapshot().preparedFolders, null);
});

test('ordinary existing-folder selection is still plain and never automatically assigns or registers', async (t) => {
  const h = await controllers(t); h.tools.toolInputsIntent(); const flow = h.android.chooseToolSource('gradle');
  assert.equal(h.calls.length, 1); assert.equal(Object.hasOwn(h.calls[0].input, 'acquired'), false);
  assert.equal(h.tools.getSnapshot().preparedFolders, null);
  h.reply(h.calls[0], source(1, 'gradle')); await flow;
  assert.equal(h.android.getSnapshot().toolSources.inspection, 'not-run');
  assert.equal(h.android.getSnapshot().toolSources.protectedCopy, 'not-created');
});
