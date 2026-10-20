// Actual controllers/reducer with inert ports only. No native work, Keychain,
// files, project scripts, Store requests, builds or browser automation.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { AndroidBuildController } from '../src/androidBuild.ts';
import { IOSArchiveController } from '../src/iosArchive.ts';
import { OfflinePreflightController } from '../src/offlinePreflight.ts';
import { EnvironmentDiagnosticsController } from '../src/environmentDiagnosticsController.ts';
import { ToolAcquisitionController } from '../src/toolAcquisitionController.ts';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { LocalReleaseHistoryController, localHistoryOwnerReason } from '../src/localReleaseHistory.ts';
import { LocalStorePreflightController, localStoreOwnerReason, localStoreProjectObservation } from '../src/localStorePreflight.ts';
import { parseLocalHistoryStatus } from '../src/localReleaseHistoryProtocol.ts';
import { parseLocalStoreStatus } from '../src/localStorePreflightProtocol.ts';
import { androidVersionsLimitations } from '../src/androidStoreVersions.ts';
import { iosVersionsLimitations } from '../src/iosStoreVersions.ts';
import { releaseRehearsal, selectRehearsalCandidate } from '../src/releaseRehearsal.ts';

const copy = (v) => structuredClone(v), A = 'a'.repeat(32), B = 'b'.repeat(32), C = 'c'.repeat(32);
const ID = '12345678-1234-4234-8234-123456789abc';
const configBytes = { bytes: 123, sha256: 'a'.repeat(64) }, versionBytes = { bytes: 41, sha256: 'b'.repeat(64) };
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const source = 'release/version.properties';
const turn = () => new Promise((resolve) => setImmediate(resolve));
const status = (revision = 0, operation = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation });
const historyResult = () => ({ schemaVersion: 1, scope: 'local-release-history', enrolled: true, headSequence: 3,
  history: [{ operationId: ID, phase: 'inputs-ready', recoveryRequired: true }],
  limitations: ['no-store-authority', 'no-build-or-publishing', 'keychain-intact-rollback-boundary'] });
const storeResult = (platform = 'android') => ({ schemaVersion: 1, scope: `local-${platform}-store-access-no-publishing`, findings: [],
  limitations: ['non-publishing', 'no-project-commands', 'no-build-or-signing', 'no-release-readiness', 'point-in-time-account-access', 'saved-inputs-not-atomic'] });
const candidateInputs = () => ({ operationId: ID, candidateSha256: 'a'.repeat(64), sourceCommit: 'b'.repeat(40), sourceTree: 'c'.repeat(40),
  applicationId: 'org.example.app', version: { name: '1.2.3', build: 4 }, files: [
    { fileName: 'app-release.aab', bytes: 100, sha256: 'd'.repeat(64) },
    { fileName: 'store-metadata.zip', bytes: 100, sha256: 'e'.repeat(64) },
    { fileName: 'validation-report.json', bytes: 100, sha256: 'f'.repeat(64) }],
  observation: 'current-bundle-only', priorCreateFinality: 'not-established' });
function setupAnalysis(platform) {
  const rows = [['project-layout', 'local', null, 'detected'], ['release-settings', 'local', null, 'configured'],
    ['version-source', 'local', 'version.source', 'configured'], ...(platform === 'android' ? [
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
  return { schemaVersion: 1, scope: 'local-setup-guidance', configurationState: 'format-valid', discoveryPartial: false, platforms: [platform],
    requirements: rows.map(([id, stage, field, state]) => ({ id, stage, field, state, reference: null, summary: 'Inert static finding.' })),
    limitations: Array(6).fill('No native qualification.'), assurance: copy(assurance) };
}
async function world(platform = 'android') {
  const project = { id: 'app', name: 'Inert app', path: '/inert/never-opened' };
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: 'app', requestId: 1 });
  const snapshot = { root: project.path, observedAt: '2026-10-20T00:00:00Z', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: copy(configBytes), issues: [], data: {
      version: { source }, [platform]: platform === 'android' ? { enabled: true, applicationId: 'org.example.app', module: ':app', identityStatus: 'blocked' }
        : { enabled: true, bundleId: 'org.example.app', project: 'App.xcodeproj', scheme: 'App' } } },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: copy(assurance), issues: [], setupAnalysis: setupAnalysis(platform) };
  workspace = workspaceReducer(workspace, { type: 'snapshot-done', projectId: 'app', requestId: 1, snapshot, observedAt: 1 });
  const w = { session: workspace.projects.app, nativeSession: {}, epoch: 0, peer: null, platform };
  const version = new ReleaseVersionController(() => w.session);
  version.setConnection({ mode: 'native', observeReleaseVersion: async () => ({ schemaVersion: 2, source,
    version: { name: '1.2.3', build: 4 }, savedConfig: copy(configBytes), savedVersion: copy(versionBytes),
    observationScope: 'single-request-non-atomic', assurance: copy(assurance) }) },
  { runtime: { state: 'available', mode: 'installed', reason: null }, capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject(); await version.read(); w.version = version;
  const options = { selectedProject: () => null, releaseVersion: () => null, otherOperationReason: () => null };
  const android = copy(new AndroidBuildController(options).getSnapshot()), ios = copy(new IOSArchiveController(options).getSnapshot());
  const selected = platform === 'android' ? android : ios;
  Object.assign(selected, { mode: 'native', initialized: true, listening: true,
    project: { ...localStoreProjectObservation(w.session, version.getSnapshot()), selection: null },
    status: platform === 'android' ? status() : { ...status(), schemaVersion: 2, modeCapabilities: { unsigned: true, signed: false, recovery: false } } });
  w.assets = copy(new AssetSessionController(() => null).getSnapshot());
  w.resume = { platform, android, ios, credentials: w.assets,
    localChecks: copy(new OfflinePreflightController(options).getSnapshot()), diagnostics: copy(new EnvironmentDiagnosticsController(options).getSnapshot()),
    toolPreparation: copy(new ToolAcquisitionController({ ...options, knownTools: () => [null, null, null] }).getSnapshot()),
    androidSubmissionPending: false, iosSubmissionPending: false, localChecksSubmissionPending: false, otherOwnerReason: null };
  return w;
}
function assignAssets(w, platform = w.platform) {
  const kind = platform === 'ios' ? 'asc-p8' : 'google-service-account';
  Object.assign(w.assets, { mode: 'native', scope: { executionMode: 'local', platform, stage: 'candidate', purpose: 'store' },
    contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false,
    status: { mode: 'session', capability: { available: true }, modes: { session: { available: true } },
      context: { revision: 3, projectId: 'app', executionMode: 'local', platform, stage: 'candidate', purpose: 'store' }, operation: null,
      assignments: [{ kind, recordId: C, recordRevision: 4, contextRevision: 3, availability: 'available' }],
      records: [{ kind, recordId: C, revision: 4, availability: 'assigned' }] } });
}
async function owner(kind, w) {
  if (kind === 'store') assignAssets(w);
  const names = kind === 'history' ? ['prepareLocalReleaseHistory', 'startLocalReleaseHistory', 'localReleaseHistoryStatus', 'cancelLocalReleaseHistory', 'subscribeLocalReleaseHistory']
    : ['prepareLocalStorePreflight', 'startLocalStorePreflight', 'localStorePreflightStatus', 'cancelLocalStorePreflight', 'subscribeLocalStorePreflight'];
  let latest = status(), listener, detached = 0, held = {};
  const calls = { prepare: 0, start: 0, status: 0, cancel: 0 }, returned = {};
  const controller = kind === 'history'
    ? new LocalReleaseHistoryController({ projectId: () => w.session?.project.id ?? null, otherOperationReason: () => w.peer, now: () => 100 })
    : new LocalStorePreflightController({ project: () => localStoreProjectObservation(w.session, w.version.getSnapshot()), assets: () => w.assets, otherOperationReason: () => w.peer, now: () => 100 });
  const call = (key, value) => { calls[key]++; returned[key] = copy(value); return held[key]?.promise ?? Promise.resolve(copy(value)); };
  const api = { mode: 'native',
    [names[4]]: async (fn) => { listener = fn; return () => { detached++; }; },
    [names[2]]: () => call('status', latest),
    [names[0]]: (request) => { latest = status(latest.statusRevision + 1, { operationId: calls.prepare === 0 ? A : (calls.prepare + 1).toString(16).padStart(32, '0'), ownerGeneration: B,
      context: kind === 'history' ? copy(request) : { ...copy(request), platform: request.platform ?? 'android', operation: 'local-store-preflight' },
      phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null }); return call('prepare', latest); },
    [names[1]]: (request) => { assert.equal(request.operationId, latest.operation.operationId); assert.equal(request.ownerGeneration, B);
      latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'running', intentUsable: false }); return call('start', latest); },
    [names[3]]: (a, b) => { assert.equal(a, latest.operation.operationId); assert.equal(b, B);
      latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null }); return call('cancel', latest); } };
  await controller.connect(api); controller.syncProject();
  const h = { controller, api, calls, names, w, ownerReason: kind === 'history' ? localHistoryOwnerReason : localStoreOwnerReason,
    latest: () => copy(latest), detached: () => detached,
    hold(key) { assert.equal(held[key], undefined); let resolve; const promise = new Promise((r) => { resolve = r; });
      held[key] = { promise, resolve }; return async (value = returned[key]) => { const original = held[key]; delete held[key]; original.resolve(copy(value)); await turn(); }; },
    emit(value) { latest = copy(value); listener(copy(value)); },
    complete(result = kind === 'history' ? historyResult() : storeResult(w.platform)) {
      const value = status(latest.statusRevision + 1, { ...latest.operation, phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result });
      assert.ok((kind === 'history' ? parseLocalHistoryStatus : parseLocalStoreStatus)(value)); h.emit(value); return value;
    },
    async dispose() { controller.dispose(); for (const [key, pending] of Object.entries(held)) { delete held[key]; pending.resolve(copy(latest)); } await turn(); }
  };
  return h;
}
async function guideWorld(platform = 'android') {
  const w = await world(platform), history = await owner('history', w), store = await owner('store', w);
  const current = () => ({ session: w.session, nativeSession: w.nativeSession, epoch: w.epoch, preview: false, readReason: null,
    resume: { ...w.resume, credentials: w.assets, otherOwnerReason: w.peer ?? localHistoryOwnerReason(history.controller.getSnapshot()) ?? localStoreOwnerReason(store.controller.getSnapshot()) },
    version: w.version.getSnapshot(), history: history.controller.getSnapshot(), historyController: history.controller,
    historyReason: history.controller.prepareReason(), store: store.controller.getSnapshot(), storeReason: store.controller.prepareReason() });
  return { w, history, store, current, async dispose() { await history.dispose(); await store.dispose(); w.version.dispose(); } };
}
const step = (view, id) => view.steps.find((s) => s.id === id);

test('all four actual History/Store callers survive a terminal event and notify only truthful first/last pending transitions', async () => {
  for (const kind of ['history', 'store']) for (const call of ['prepare', 'start', 'status', 'cancel']) {
    const w = await world(), h = await owner(kind, w), c = h.controller, flags = [];
    c.subscribe(() => { if (flags.at(-1) !== c.getSnapshot().callersPending) flags.push(c.getSnapshot().callersPending); });
    try {
      if (call !== 'prepare') await c.prepare();
      if (call === 'start') c.acknowledge(true);
      const join = h.hold(call), pending = call === 'status' ? c.checkStatus() : c[call]();
      h.complete();
      assert.equal(c.getSnapshot().pending, false, 'native terminal is distinct from the still-returning caller');
      assert.equal(c.getSnapshot().callersPending, true); assert.equal(c.hasPendingGuiSubmission(), true);
      assert.ok(h.ownerReason(c.getSnapshot())); const prepares = h.calls.prepare;
      await c.prepare(); assert.equal(h.calls.prepare, prepares);
      if (kind === 'history') { assert.equal(c.setInputPlatform('ios'), false); c.setAction('enroll'); assert.notEqual(c.getSnapshot().request.action, 'enroll'); }
      const beforeReturn = flags.slice(); await join(h.latest()); await pending;
      assert.equal(c.getSnapshot().callersPending, false); assert.equal(c.hasPendingGuiSubmission(), false);
      assert.equal(h.ownerReason(c.getSnapshot()), null); assert.deepEqual(flags, [...beforeReturn, false]);
    } finally { await h.dispose(); w.version.dispose(); }
  }
});

test('overlapping Start/Status/Cancel keep the original listener until all returns; reconnect and unknown cannot discard it', async () => {
  for (const kind of ['history', 'store']) {
    const w = await world(), h = await owner(kind, w), c = h.controller;
    try {
      await c.prepare(); c.acknowledge(true); const startJoin = h.hold('start'), start = c.start();
      const statusJoin = h.hold('status'), read = c.checkStatus(), cancelJoin = h.hold('cancel'); c.cancel();
      h.emit(h.latest()); c.dispose(); assert.equal(h.detached(), 0);
      await statusJoin(); await read; assert.equal(c.hasPendingGuiSubmission(), true); assert.equal(h.detached(), 0);
      await startJoin(); await start; assert.equal(c.hasPendingGuiSubmission(), true); assert.equal(h.detached(), 0);
      await cancelJoin(); assert.equal(c.hasPendingGuiSubmission(), false); assert.equal(h.detached(), 1);
    } finally { await h.dispose(); w.version.dispose(); }
    const w2 = await world(), h2 = await owner(kind, w2), original = h2.controller;
    try {
      const join = h2.hold('status'), read = original.checkStatus(); let newPortCalls = 0;
      await original.connect({ ...h2.api, [h2.names[4]]: async () => { newPortCalls++; return () => {}; } });
      assert.equal(newPortCalls, 0); assert.equal(h2.detached(), 0); assert.equal(original.getSnapshot().blocked, true);
      await join(); await read; original.dispose(); assert.equal(h2.detached(), 0, 'uncertainty retains the old original listener');
      const reads = h2.calls.status; await original.checkStatus(); assert.equal(h2.calls.status, reads + 1);
    } finally { await h2.dispose(); w2.version.dispose(); }
  }
});

test('synchronous listeners cannot send stale Prepare/Start; a thrown invocation joins its caller but retains native uncertainty', async () => {
  for (const kind of ['history', 'store']) for (const stage of ['prepare', 'start', 'throw']) {
    const w = await world(), h = await owner(kind, w), c = h.controller;
    try {
      if (stage === 'start') { await c.prepare(); c.acknowledge(true); }
      let once = true; c.subscribe(() => { if (stage !== 'throw' && once && c.getSnapshot().pending) { once = false; w.peer = 'Original peer changed during notification'; } });
      if (stage === 'throw') h.api[h.names[0]] = () => { throw new Error('inert private exception must not become UI text'); };
      await c[stage === 'throw' ? 'prepare' : stage](); await turn();
      assert.equal(c.hasPendingGuiSubmission(), false);
      if (stage === 'throw') { assert.ok(h.ownerReason(c.getSnapshot())); assert.equal(c.getSnapshot().blocked, true); assert.ok(!c.getSnapshot().error.includes('private exception')); }
      else { assert.equal(h.calls[stage], 0); assert.equal(h.calls.cancel, stage === 'start' ? 1 : 0); }
    } finally { await h.dispose(); w.version.dispose(); }
  }
});

test('restart Verify hands only the exact returned row and explicit platform to the existing form, never Prepare/Start or a new build', async () => {
  for (const platform of ['android', 'ios']) {
    const h = await guideWorld(platform), c = h.history.controller;
    try {
      assert.equal(c.getSnapshot().request.action, 'verify'); await c.prepare(); c.acknowledge(true);
      const join = h.history.hold('start'), originalStart = c.start(); h.history.complete();
      const early = releaseRehearsal(h.current()); assert.equal(early.attention, true); assert.notEqual(early.next.action.kind, 'select-candidate');
      assert.match(early.next.summary, /original call has not returned/);
      await join(h.history.latest()); await originalStart;
      assert.equal(c.setInputPlatform(platform), true);
      const ctx = h.current(), action = releaseRehearsal(ctx).next.action, calls = { ...h.history.calls }, reveals = [];
      assert.equal(action.kind, 'select-candidate'); assert.equal(action.platform, platform);
      assert.equal(action.row, ctx.history.status.operation.result.history[0]);
      assert.equal(selectRehearsalCandidate(action, h.current, (target) => reveals.push(target)), true);
      assert.deepEqual(reveals, ['history']); assert.deepEqual(h.history.calls, calls);
      assert.equal(c.getSnapshot().request.action, 'review-inputs'); assert.equal(c.getSnapshot().request.candidateOperationId, ID);
      assert.equal(c.getSnapshot().request.platform ?? 'android', platform); assert.equal(c.getSnapshot().acknowledged, false);
      assert.equal(c.getSnapshot().consentUntil, null); assert.equal(c.getSnapshot().historical, true);
      assert.equal(selectRehearsalCandidate(action, h.current, () => assert.fail('old click must not be replayed')), false);
    } finally { await h.dispose(); }
  }
});

test('candidate click refuses newer same-ID results, context/API ABA and synchronous draft replacement without losing the draft', async () => {
  for (const change of ['row', 'api', 'epoch', 'synchronous-draft', 'synchronous-row']) {
    const h = await guideWorld(), c = h.history.controller;
    try {
      await c.prepare(); c.acknowledge(true); await c.start(); h.history.complete();
      const action = releaseRehearsal(h.current()).next.action, before = h.w.session;
      assert.equal(action.kind, 'select-candidate'); let replacement = null, armed = true;
      const replace = () => {
        if (change.endsWith('row')) h.history.complete();
        else { replacement = workspaceReducer({ selectedId: 'app', projects: { app: before } },
          { type: 'edit', projectId: 'app', path: 'android.module', value: ':unsaved' }).projects.app; h.w.session = replacement; }
      };
      if (change === 'row') replace();
      else if (change === 'api') h.w.nativeSession = {};
      else if (change === 'epoch') h.w.epoch += 2; // away and back, not a reusable context.
      else c.subscribe(() => { if (armed) { armed = false; replace(); } });
      const calls = { ...h.history.calls };
      assert.equal(selectRehearsalCandidate(action, h.current, () => assert.fail('stale handoff must not reveal a completed selection')), false);
      assert.deepEqual(h.history.calls, calls);
      if (replacement) { assert.equal(h.w.session, replacement); assert.equal(replacement.baseline, before.baseline); assert.equal(replacement.draft.android.module, ':unsaved'); }
    } finally { await h.dispose(); }
  }
});

test('local build, candidate and optional Store guidance stay separate; foreign unknown/recovery or real returning calls win', async () => {
  const h = await guideWorld(), w = h.w;
  try {
    const p = w.resume.android.project;
    const complete = { operationId: A, ownerGeneration: B, context: { projectId: p.projectId, draftRevision: p.draftRevision,
      baselineGeneration: p.baselineGeneration, savedConfig: copy(p.savedConfig), savedVersion: copy(p.savedVersion), platform: 'android', operation: 'android-local-build' },
      phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result: { scope: 'local-android-build' } };
    w.assets.contextCurrent = false; h.store.controller.syncProject(); w.resume.android.status.operation = complete;
    let view = releaseRehearsal(h.current()); assert.equal(step(view, 'build').status, 'result-available');
    assert.match(view.next.summary, /ordinary local build.*not a retained release candidate/);
    assert.match(step(view, 'store').title, /optional/); assert.notEqual(step(view, 'store').reason, null);
    complete.context.operation = 'android-candidate-inputs'; complete.result.scope = 'local-android-candidate-inputs';
    view = releaseRehearsal(h.current()); assert.deepEqual(view.next.action, { kind: 'show', target: 'history' });
    w.resume.androidSubmissionPending = true; view = releaseRehearsal(h.current());
    assert.equal(view.attention, true); assert.notEqual(step(view, 'build').status, 'result-available'); w.resume.androidSubmissionPending = false;
    const join = h.history.hold('status'), read = h.history.controller.checkStatus();
    w.resume.ios = { ...w.resume.ios, mode: 'native', nativeBlocked: true, status: { operation: {
      context: { projectId: 'other-app', operation: 'ios-unsigned-archive' }, phase: 'unknown', reason: 'cleanup-unknown' } } };
    view = releaseRehearsal(h.current()); assert.match(view.next.summary, /earlier project/); assert.deepEqual(view.next.action, { kind: 'show', target: 'local-checks' });
    assert.equal(w.session.project.id, 'app'); await join(); await read;
    w.resume.ios.mode = 'unavailable';
    h.history.emit(status(h.history.latest().statusRevision + 1, { operationId: A, ownerGeneration: B, context: { projectId: 'app', executionMode: 'local', action: 'verify' },
      phase: 'terminal', intentUsable: false, outcome: 'refused', reason: 'recovery-required', result: null }));
    view = releaseRehearsal(h.current()); assert.equal(view.attention, true); assert.deepEqual(view.next.action, { kind: 'show', target: 'history' });
  } finally { await h.dispose(); }
});

test('candidate verification and ordinary Store findings use only current matching original results, never inventory or ready claims', async () => {
  for (const platform of ['android', 'ios']) {
    const h = await guideWorld(platform), c = h.store.controller;
    try {
      await c.prepare(); c.acknowledge(true); await c.start();
      const join = h.store.hold('status'), read = c.checkStatus(); h.store.complete();
      assert.equal(step(releaseRehearsal(h.current()), 'store').status, 'not-checked'); await join(); await read;
      let stepView = step(releaseRehearsal(h.current()), 'store'); assert.equal(stepView.status, 'result-available');
      assert.match(stepView.summary, /point-in-time.*not release readiness/); // zero findings are not PASS.
      await c.prepare(); c.acknowledge(true); await c.start();
      h.store.complete({ ...storeResult(platform), findings: [{ check: 'store-access', status: 'FAIL' }] });
      assert.equal(step(releaseRehearsal(h.current()), 'store').status, 'attention');
      wVersionDrift(h); assert.equal(step(releaseRehearsal(h.current()), 'store').status, 'not-checked');
    } finally { await h.dispose(); }
  }
  const h = await guideWorld('ios');
  try {
    const c = h.store.controller;
    const ios = { observation: 'observed', coverage: 'asc-ios-current-inventory/1', revision: 'a'.repeat(64), counts: { builds: 0, buildUploads: 0, appStoreVersions: 1 }, maxBuild: 0, marketingVersion: '2.0.0', historicalUniqueness: 'not-established' };
    const android = { observation: 'observed', coverage: 'play-android-current-inventory/1', revision: 'b'.repeat(64), counts: { tracks: 0, releases: 0, versionCodes: 0, bundles: 0, apks: 0 }, maxBuild: 0, marketingVersion: null, temporaryEdit: 'deleted', historicalUniqueness: 'not-established' };
    for (const query of ['bundle-id-registration', 'app-store-profile-reuse', 'ios-current-versions', 'android-current-versions', 'paired-current-versions']) {
      const pair = query === 'paired-current-versions', play = query === 'android-current-versions';
      if (pair) {
        assignAssets(h.w, 'android'); h.w.assets.scope = { executionMode: 'local', platform: 'both', stage: 'candidate', purpose: 'version-inventory' };
        h.w.assets.status.context = { ...h.w.assets.status.context, ...h.w.assets.scope };
        h.w.assets.status.assignments.push({ kind: 'asc-p8', recordId: 'd'.repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' });
        h.w.assets.status.records.push({ kind: 'asc-p8', recordId: 'd'.repeat(32), revision: 4, availability: 'assigned' });
        h.w.session.snapshot.config.data.android = { enabled: true };
      } else assignAssets(h.w, play ? 'android' : 'ios');
      c.syncProject(); await c.prepare(query); assert.equal(h.store.latest().operation.context.query, query); c.acknowledge(true); await c.start();
      const base = storeResult('ios'), bundle = query === 'bundle-id-registration', profile = query === 'app-store-profile-reuse';
      const result = bundle || profile ? { ...base, scope: bundle ? 'local-ios-bundle-id-registration-read' : 'local-ios-profile-reuse-metadata-read',
        limitations: [...base.limitations, 'no-team-verification', 'no-global-availability-claim', 'no-provisioning-changes',
          ...(profile ? ['metadata-only', 'no-private-key-match', 'no-profile-authentication', 'no-account-certificate-inventory'] : [])],
        ...(bundle ? { observation: 'not-returned' } : { profileReuse: { observation: 'not-returned', counts: { matchingProfiles: 0, activeProfiles: 0, currentMetadataCandidates: 0, relatedCertificates: 0 }, checkedAt: '2026-10-20T00:00:00.000000Z' } }) }
        : { ...base, scope: pair ? 'local-shared-current-version-inventory' : play ? 'local-android-current-version-inventory' : 'local-ios-current-version-inventory',
          limitations: [...(pair || play ? androidVersionsLimitations : iosVersionsLimitations)], currentVersions: pair ? { android, ios } : play ? android : ios };
      h.store.complete(result); assert.equal(c.getSnapshot().blocked, false);
      assert.equal(step(releaseRehearsal(h.current()), 'store').status, 'not-checked', query);
    }
  } finally { await h.dispose(); }
  const candidate = await guideWorld();
  try {
    const c = candidate.history.controller; await c.prepare(); c.acknowledge(true); await c.start(); candidate.history.complete();
    const action = releaseRehearsal(candidate.current()).next.action; assert.equal(selectRehearsalCandidate(action, candidate.current, () => {}), true);
    await c.prepare(); c.acknowledge(true); await c.start(); candidate.history.complete({ ...historyResult(), candidateInputs: candidateInputs() });
    const view = releaseRehearsal(candidate.current()); assert.equal(step(view, 'candidate').status, 'result-available');
    assert.deepEqual(view.next.action, { kind: 'show', target: 'store-access' });
    assert.equal(c.getSnapshot().status.operation.result.candidateInputs.priorCreateFinality, 'not-established');
  } finally { await candidate.dispose(); }
});
function wVersionDrift(h) { h.w.version.saveIntent(); }
