// Original controllers with inert native DATA/Promises. No DOM, credential,
// Play edit, counter write, process or native receipt is created by these tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAndroidCurrentVersions, ANDROID_VERSIONS_QUERY as QUERY, ANDROID_VERSIONS_CONSENT as CONSENT,
  ANDROID_VERSIONS_SCOPE as SCOPE, ANDROID_VERSIONS_COVERAGE as COVERAGE, androidVersionsLimitations as limitations } from '../src/androidStoreVersions.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, encodeLocalStoreRequest, storeConsent } from '../src/localStorePreflightProtocol.ts';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason, localStoreProjectObservation } from '../src/localStorePreflight.ts';
import { parseLocalStorePrepareRequest } from '../src/localStorePrepareProtocol.ts';
import { parseLocalStoreExecuteRequest } from '../src/localStoreExecuteProtocol.ts';
import { parseLocalStoreReconcileRequest } from '../src/localStoreReconcileProtocol.ts';
import { parseReservedVersion, versionReserveProjectIssue } from '../src/versionReserve.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';

const copy = value => structuredClone(value), A = 'a'.repeat(32), B = 'b'.repeat(32), C = 'c'.repeat(32);
const project = () => ({ projectId: 'synthetic-project', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) }, savedVersion: { bytes: 40, sha256: 'b'.repeat(64), source: 'release/version.properties', name: '1.2.3', build: 42 },
  inputIssue: null, dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false });
const assets = (platform = 'android') => {
  const kind = platform === 'ios' ? 'asc-p8' : 'google-service-account';
  return { mode: 'native', scope: { executionMode: 'local', platform, stage: 'candidate', purpose: 'store' },
    contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false,
    status: { mode: 'session', capability: { available: true }, modes: { session: { available: true } },
      context: { revision: 3, projectId: 'synthetic-project', executionMode: 'local', platform, stage: 'candidate', purpose: 'store' }, operation: null,
      assignments: [{ kind, recordId: C, recordRevision: 4, contextRevision: 3, availability: 'available' }],
      records: [{ kind, recordId: C, revision: 4, availability: 'assigned' }] } };
};
const input = () => ({ ...localStoreRequest(project(), assets()), platform: 'android', query: QUERY });
const status = (revision = 0, operation = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation });
const operation = request => ({ operationId: A, ownerGeneration: B, context: { ...copy(request), platform: request.platform ?? 'android', operation: 'local-store-preflight' },
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null });
const summary = () => ({ observation: 'observed', coverage: COVERAGE, revision: 'a'.repeat(64),
  counts: { tracks: 3, releases: 4, versionCodes: 6, bundles: 2, apks: 1 }, maxBuild: 11000, marketingVersion: null,
  temporaryEdit: 'deleted', historicalUniqueness: 'not-established' });
const complete = () => ({ ...operation(input()), phase: 'terminal', intentUsable: false, outcome: 'complete',
  result: { schemaVersion: 1, scope: SCOPE, findings: [], limitations: [...limitations], currentVersions: summary() } });
async function fixture(platform = 'android') {
  let selected = assets(platform), currentProject = project(), peer = null, now = 100, listener, latest = status(), deferred;
  const calls = { prepare: [], start: [], cancel: [] };
  const controller = new LocalStorePreflightController({ project: () => currentProject, assets: () => selected, otherOperationReason: () => peer, now: () => now });
  const api = { mode: 'native', subscribeLocalStorePreflight: async fn => { listener = fn; return () => {}; },
    localStorePreflightStatus: async () => copy(latest),
    prepareLocalStorePreflight: async request => { calls.prepare.push(copy(request)); if (deferred) await deferred; latest = status(latest.statusRevision + 1, operation(request)); return copy(latest); },
    startLocalStorePreflight: async request => { calls.start.push(copy(request)); latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'running', intentUsable: false }); return copy(latest); },
    cancelLocalStorePreflight: async (operationId, ownerGeneration) => { calls.cancel.push({ operationId, ownerGeneration }); latest = status(latest.statusRevision + 1,
      { ...latest.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null }); return copy(latest); } };
  await controller.connect(api); controller.syncProject();
  return { controller, api, calls, latest: () => copy(latest), now: value => now = value,
    peer: value => peer = value, changeProject: edit => edit(currentProject), changeAssets: edit => edit(selected),
    defer: () => { let release; deferred = new Promise(resolve => release = resolve); return release; },
    select: platform => { selected = assets(platform); controller.syncProject(); },
    emit: value => { latest = value; listener(copy(value)); } };
}

test('Play summary includes APKs and all track references but never invents marketing or history', () => {
  assert.deepEqual(copy(parseAndroidCurrentVersions(summary())), summary());
  const apk = summary(); apk.counts = { tracks: 0, releases: 0, versionCodes: 0, bundles: 0, apks: 1 };
  assert.ok(parseAndroidCurrentVersions(apk));
  const empty = summary(); for (const key of Object.keys(empty.counts)) empty.counts[key] = 0; empty.maxBuild = 0;
  assert.ok(parseAndroidCurrentVersions(empty)); assert.equal(empty.historicalUniqueness, 'not-established');
  for (const edit of [v => v.marketingVersion = '9.9.9', v => v.maxBuild = 0, v => v.maxBuild = 2_100_000_001,
    v => v.counts.apks = 401, v => v.counts.releases = 401, v => v.counts.versionCodes = 4001,
    v => v.coverage = 'application-all-builds', v => v.historicalUniqueness = 'established',
    v => v.revision += '\n', v => v.counts.bundles = true, v => v.temporaryEdit = 'not-started']) {
    const value = summary(); edit(value); assert.equal(parseAndroidCurrentVersions(value), null);
  }
});
test('failed or unconfirmed remote edit is null floor DATA, not a successful delete', () => {
  for (const observation of ['not-checked', 'not-permitted', 'inconclusive', 'too-many', 'unsupported-format', 'temporary-edit-unconfirmed']) {
    const value = { ...summary(), observation }; assert.equal(parseAndroidCurrentVersions(value), null);
    for (const key of ['revision', 'counts', 'maxBuild']) value[key] = null;
    value.temporaryEdit = observation === 'temporary-edit-unconfirmed' ? 'unconfirmed' : 'deleted';
    assert.ok(parseAndroidCurrentVersions(value));
    value.temporaryEdit = observation === 'temporary-edit-unconfirmed' ? 'deleted' : 'unconfirmed';
    assert.equal(parseAndroidCurrentVersions(value), null);
  }
  const missing = summary(); delete missing.temporaryEdit; assert.equal(parseAndroidCurrentVersions(missing), null);
});
test('Android public parser refuses accessors oversized values and extra raw provider fields', () => {
  let invoked = 0; const value = summary();
  Object.defineProperty(value, 'counts', { enumerable: true, get() { invoked++; return {}; } });
  assert.equal(parseAndroidCurrentVersions(value), null); assert.equal(invoked, 0);
  for (const extra of [{ bodyBase64: 'PRIVATE' }, { token: 'x'.repeat(10000) }, { editId: 'private-edit' }])
    assert.equal(parseAndroidCurrentVersions({ ...summary(), ...extra }), null);
  assert.equal(parseAndroidCurrentVersions(Array(100000)), null);
});
test('only explicit Android inventory query accepts the temporary-edit consent vocabulary', () => {
  assert.ok(parseLocalStoreRequest(input())); assert.equal(storeConsent('android', QUERY), CONSENT);
  assert.notEqual(storeConsent('android'), CONSENT); assert.notEqual(storeConsent('ios', 'ios-current-versions'), CONSENT);
  assert.ok(encodeLocalStoreRequest('start_local_store_preflight', { operationId: A, ownerGeneration: B, consentVersion: CONSENT }));
  for (const edit of [v => delete v.query, v => delete v.platform, v => v.platform = 'ios', v => v.query = 'ios-current-versions',
    v => v.query = 'all-history', v => v.editId = 'guess', v => v.token = 'private', v => v.url = 'https://example.invalid']) {
    const value = input(); edit(value); assert.equal(parseLocalStoreRequest(value), null);
  }
  assert.ok(parseLocalStoreRequest(localStoreRequest(project(), assets()))); // Old Android access shape unchanged.
  const prepared = { ...input(), candidateOperationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', candidateSha256: 'c'.repeat(64), confirmation: 'candidate:android:1.2.3:42' };
  assert.equal(parseLocalStorePrepareRequest(prepared), null);
  assert.equal(parseLocalStoreExecuteRequest({ ...prepared, intentSha256: 'd'.repeat(64) }), null);
  assert.equal(parseLocalStoreReconcileRequest({ ...prepared, intentSha256: 'd'.repeat(64) }), null);
});
test('current-inventory terminal cannot borrow iOS, ordinary access, cancellation or partial success', () => {
  assert.ok(parseLocalStoreStatus(status(1, complete())));
  for (const edit of [v => v.context.query = 'ios-current-versions', v => delete v.context.query, v => v.context.platform = 'ios',
    v => v.phase = 'running', v => v.reason = 'cancelled', v => v.result.scope = 'local-android-store-access-no-publishing',
    v => v.result.currentVersions = null, v => v.result.currentVersions.temporaryEdit = 'unconfirmed',
    v => v.result.findings.push({ check: 'store-access', status: 'PASS' }), v => v.result.findings.push({ check: 'credential-format', status: 'FAIL' }),
    v => v.result.limitations.pop()]) {
    const value = complete(); edit(value); assert.equal(parseLocalStoreStatus(status(1, value)), null);
  }
});
test('mount and status do not create a Play edit; explicit original consent starts once', async () => {
  const h = await fixture();
  try {
    assert.equal(h.calls.prepare.length, 0); assert.equal(h.calls.start.length, 0);
    await h.controller.prepare(QUERY); assert.deepEqual(h.calls.prepare, [copy(input())]);
    assert.equal(h.controller.getSnapshot().acknowledged, false); await h.controller.start();
    assert.equal(h.calls.start.length, 0); // An unchecked consent retires this original, never starts it.
  } finally { h.controller.dispose(); }
  const next = await fixture();
  try {
    await next.controller.prepare(QUERY); next.controller.acknowledge(true); await next.controller.start(); await next.controller.start();
    assert.deepEqual(next.calls.start, [{ operationId: A, ownerGeneration: B, consentVersion: CONSENT }]);
    next.select('ios'); await Promise.resolve();
    assert.deepEqual(next.calls.cancel, [{ operationId: A, ownerGeneration: B }]);
    assert.equal(next.controller.getSnapshot().historical, true);
  } finally { next.controller.dispose(); }
});
test('late original Prepare and expired consent never renew a temporary-edit action', async () => {
  const h = await fixture();
  try {
    const release = h.defer(), pending = h.controller.prepare(QUERY); h.select('ios'); release();
    await pending; await Promise.resolve(); assert.equal(h.calls.start.length, 0); assert.equal(h.calls.cancel.length, 1);
    assert.equal(h.controller.getSnapshot().consentUntil, null);
  } finally { h.controller.dispose(); }
  const next = await fixture();
  try {
    await next.controller.prepare(QUERY); next.controller.acknowledge(true); next.now(60101); await next.controller.start();
    assert.equal(next.calls.start.length, 0);
  } finally { next.controller.dispose(); }
});
test('unconfirmed remote cleanup is displayed without an automatic re-query or counter-only fallback', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(QUERY); h.controller.acknowledge(true); await h.controller.start();
    const value = complete(); value.result.currentVersions = { ...summary(), observation: 'temporary-edit-unconfirmed',
      revision: null, counts: null, maxBuild: null, temporaryEdit: 'unconfirmed' };
    h.emit(status(3, value)); await h.controller.checkStatus(); h.controller.syncProject();
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.start.length, 1);
    assert.equal(h.controller.getSnapshot().status.operation.result.currentVersions.maxBuild, null);
  } finally { h.controller.dispose(); }
});
test('lost native ACK and native cleanup-unknown preserve original ownership and block another query', async () => {
  const h = await fixture();
  try {
    h.api.prepareLocalStorePreflight = async request => { h.calls.prepare.push(request); throw Error('PRIVATE'); };
    await h.controller.prepare(QUERY); await h.controller.prepare();
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.start.length, 0);
    assert.ok(localStoreOwnerReason(h.controller.getSnapshot())); assert.equal(h.controller.getSnapshot().error.includes('PRIVATE'), false);
  } finally { h.controller.dispose(); }
  const next = await fixture();
  try {
    await next.controller.prepare(QUERY); const last = next.latest();
    next.emit(status(last.statusRevision + 1, { ...last.operation, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null }));
    await next.controller.prepare(QUERY); assert.equal(next.calls.prepare.length, 1);
    assert.equal(next.controller.getSnapshot().status.operation.result, null);
  } finally { next.controller.dispose(); }
});
test('iOS or another retained Store operation cannot acquire the Android inventory action', async () => {
  const h = await fixture('ios');
  try { await h.controller.prepare(QUERY); assert.equal(h.calls.prepare.length, 0); }
  finally { h.controller.dispose(); }
  const next = await fixture();
  try { await next.controller.prepare(); await next.controller.prepare(QUERY); assert.equal(next.calls.prepare.length, 1); }
  finally { next.controller.dispose(); }
});
test('Android Prepare post-notification currentness vetoes source, account, ABA and peer changes', async () => {
  for (const invalidate of [h => h.controller.selectionIntent(), h => { h.select('ios'); h.select('android'); },
    h => h.changeProject(p => p.savedVersion.sha256 = 'c'.repeat(64)), h => h.changeAssets(a => a.status.context.revision++),
    h => h.peer('A retained peer acquired work.'), h => h.controller.beginConnection(), h => h.controller.dispose()]) {
    const h = await fixture(); let fired = false;
    const off = h.controller.subscribe(() => { if (!fired && h.controller.getSnapshot().pending) { fired = true; invalidate(h); } });
    try { await h.controller.prepare(QUERY); assert.equal(fired, true); assert.equal(h.calls.prepare.length, 0); assert.equal(h.calls.start.length, 0); }
    finally { off(); h.controller.dispose(); }
  }
});
test('Android Start post-notification rechecks original consent clock, assignment, context and peers', async () => {
  for (const invalidate of [h => h.controller.selectionIntent(), h => { h.select('ios'); h.select('android'); },
    h => h.changeProject(p => p.savedConfig.sha256 = 'c'.repeat(64)), h => h.changeAssets(a => a.status.assignments[0].recordRevision++),
    h => h.peer('A retained peer acquired work.'), h => h.now(60101), h => h.controller.beginConnection(), h => h.controller.dispose()]) {
    const h = await fixture(); let fired = false;
    await h.controller.prepare(QUERY); h.controller.acknowledge(true);
    const off = h.controller.subscribe(() => { if (!fired && h.controller.getSnapshot().pending) { fired = true; invalidate(h); } });
    try { await h.controller.start(); await Promise.resolve(); assert.equal(fired, true); assert.equal(h.calls.start.length, 0); assert.equal(h.controller.getSnapshot().consentUntil, null); }
    finally { off(); h.controller.dispose(); }
  }
});
test('Android range in reserved DATA does not widen native iOS policy or create edit authority', () => {
  const value = { id: A, candidateId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', name: '1.2.3', build: 10000 };
  assert.ok(parseReservedVersion(value)); assert.ok(parseReservedVersion({ ...value, build: 2_100_000_000 }));
  for (const build of [0, -0, -1, true, 2_100_000_001]) assert.equal(parseReservedVersion({ ...value, build }), null);
  const saved = { ...project(), versionPlatforms: ['android'] };
  assert.equal(versionReserveProjectIssue(saved), null); // Negative UI guidance only; no port/counter call.
  assert.equal(versionReserveProjectIssue({ ...saved, versionPlatforms: ['android', 'ios'] }), null); // UI input only: native still requires one genuine paired receipt.
  assert.ok(versionReserveProjectIssue({ ...saved, versionPlatforms: null }));
  assert.ok(versionReserveProjectIssue({ ...saved, dirtyDraft: true }));
});
test('single-platform help derives only from current saved config and complete original version observation', async () => {
  const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
    gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
  const config = { bytes: 100, sha256: 'a'.repeat(64) }, source = 'release/version.properties';
  const snapshot = { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: copy(config), issues: [],
      data: { android: { enabled: true, applicationId: 'com.example.app' }, ios: { enabled: false }, version: { source } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: copy(assurance), issues: [] };
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'synthetic-project', name: 'Android fixture', path: '/inert/never-opened' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: 'synthetic-project', requestId: 1 });
  workspace = workspaceReducer(workspace, { type: 'snapshot-done', projectId: 'synthetic-project', requestId: 1, snapshot, observedAt: 1 });
  const selected = () => workspace.projects['synthetic-project'], version = new ReleaseVersionController(selected);
  const observation = { schemaVersion: 2, source, version: { name: '1.2.3', build: 42 }, savedConfig: copy(config),
    savedVersion: { bytes: 40, sha256: 'b'.repeat(64) }, observationScope: 'single-request-non-atomic', assurance: copy(assurance) };
  version.setConnection({ mode: 'native', observeReleaseVersion: async () => copy(observation) },
    { runtime: { state: 'available', mode: 'installed', reason: null }, capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject();
  try {
    assert.equal(localStoreProjectObservation(selected(), version.getSnapshot()).versionPlatforms, undefined);
    await version.read(); assert.deepEqual(localStoreProjectObservation(selected(), version.getSnapshot()).versionPlatforms, ['android']);
    workspace = workspaceReducer(workspace, { type: 'edit', projectId: 'synthetic-project', path: 'ios.enabled', value: true });
    version.syncProject(); assert.ok(versionReserveProjectIssue(localStoreProjectObservation(selected(), version.getSnapshot())));
    await version.read();
    const dirty = localStoreProjectObservation(selected(), version.getSnapshot());
    assert.equal(selected().draft.ios.enabled, true); assert.deepEqual(dirty.versionPlatforms, ['android']);
    assert.equal(dirty.dirtyDraft, true); assert.ok(versionReserveProjectIssue(dirty));
    assert.equal(localStoreRequest(dirty, assets()), null);
    const stale = copy(version.getSnapshot()); stale.resultBinding.observationGeneration++;
    assert.equal(localStoreProjectObservation(selected(), stale).versionPlatforms, undefined);
  } finally { version.dispose(); }
});
