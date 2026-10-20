// Actual parsers/controllers with inert DATA/promises only. No keys, DOM,
// native receipt, Store request, external edit or allocation is created.
import assert from 'node:assert/strict';
import test from 'node:test';
import { PAIRED_VERSIONS_QUERY as QUERY, PAIRED_VERSIONS_CONSENT as CONSENT, PAIRED_VERSIONS_SCOPE as SCOPE,
  parsePairedCurrentVersions, pairedVersionsObserved } from '../src/pairedStoreVersions.ts';
import { assetRequestFits, parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, encodeLocalStoreRequest, storeConsent } from '../src/localStorePreflightProtocol.ts';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason } from '../src/localStorePreflight.ts';
import { androidVersionsLimitations } from '../src/androidStoreVersions.ts';
import { versionReserveProjectIssue } from '../src/versionReserve.ts';
import { parseLocalStorePrepareRequest } from '../src/localStorePrepareProtocol.ts';

const copy = value => structuredClone(value), A = 'a'.repeat(32), B = 'b'.repeat(32), C = 'c'.repeat(32), D = 'd'.repeat(32);
const scope = () => ({ platform: 'both', purpose: 'version-inventory', stage: 'candidate', executionMode: 'local' });
const project = () => ({ projectId: 'synthetic-project', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) }, savedVersion: { bytes: 40, sha256: 'b'.repeat(64), source: 'release/version.properties', name: '1.2.3', build: 42 },
  inputIssue: null, dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, versionPlatforms: ['android', 'ios'] });
const assets = () => ({ mode: 'native', scope: scope(), contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false,
  status: { schemaVersion: 3, statusRevision: 1, mode: 'session', persistence: null, capability: { available: true, reason: 'none' },
    modes: { session: { available: true, reason: 'none' }, encrypted: { available: true, reason: 'none' } },
    context: { revision: 3, projectId: 'synthetic-project', ...scope() }, operation: null,
    assignments: [['google-service-account', C], ['asc-p8', D]].map(([kind, recordId]) => ({ kind, recordId, recordRevision: 4, contextRevision: 3, availability: 'available' })),
    records: [['google-service-account', C], ['asc-p8', D]].map(([kind, recordId]) => ({ kind, recordId, revision: 4, availability: 'assigned', storage: 'session', payloadState: 'assessed', label: null })) } });
const summary = () => ({
  android: { observation: 'observed', coverage: 'play-android-current-inventory/1', revision: 'c'.repeat(64), counts: { tracks: 2, releases: 2, versionCodes: 3, bundles: 0, apks: 1 }, maxBuild: 40, marketingVersion: null, temporaryEdit: 'deleted', historicalUniqueness: 'not-established' },
  ios: { observation: 'observed', coverage: 'asc-ios-current-inventory/1', revision: 'd'.repeat(64), counts: { builds: 0, buildUploads: 0, appStoreVersions: 1 }, maxBuild: 0, marketingVersion: '2.0.0', historicalUniqueness: 'not-established' },
});
const input = () => localStoreRequest(project(), assets());
const operation = (request = input()) => ({ operationId: A, ownerGeneration: B, context: { ...request, operation: 'local-store-preflight' }, phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null });
const status = (revision = 0, op = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation: op });
const result = () => ({ schemaVersion: 1, scope: SCOPE, findings: [], limitations: [...androidVersionsLimitations], currentVersions: summary() });
function assessment(kind) {
  const p8 = kind === 'asc-p8';
  return { schemaVersion: 1, policyVersion: 'credential-policy-v1', kind,
    context: { platform: p8 ? 'ios' : 'android', purpose: 'store', stage: 'candidate', executionMode: 'local' },
    applicability: { state: 'required', reason: 'selected' }, state: 'format-valid', identity: 'not-assessed',
    fields: (p8 ? [['file', 'MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64'], ['keyId', 'MOBILE_RELEASE_ASC_KEY_ID'], ['issuerId', 'MOBILE_RELEASE_ASC_ISSUER_ID']] : [['file', 'GOOGLE_APPLICATION_CREDENTIALS']])
      .map(([id, requirement]) => ({ id, requirement, presence: 'supplied', state: 'configured', issues: [], checks: [] })),
    assurance: { basis: 'supplied-input-only', scalarValuesProcessed: p8, fileObservationsProcessed: true, selectedFilesRead: false, keyringAccessed: false,
      storageWritesPerformed: false, projectCodeExecuted: false, sourceCustody: 'not-established', nativeValidation: 'not-run', serviceValidation: 'not-run', releaseReadiness: 'unknown' } };
}
async function fixture() {
  const selected = assets(), saved = project(); let now = 100, peer = null, latest = status(), listener, waitPrepare;
  const calls = { prepare: [], start: [], cancel: [] };
  const controller = new LocalStorePreflightController({ project: () => saved, assets: () => selected, now: () => now, otherOperationReason: () => peer });
  const api = { mode: 'native', subscribeLocalStorePreflight: async fn => { listener = fn; return () => {}; }, localStorePreflightStatus: async () => copy(latest),
    prepareLocalStorePreflight: async request => { calls.prepare.push(copy(request)); if (waitPrepare) await waitPrepare; latest = status(latest.statusRevision + 1, operation(request)); return copy(latest); },
    startLocalStorePreflight: async request => { calls.start.push(copy(request)); latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'running', intentUsable: false }); return copy(latest); },
    cancelLocalStorePreflight: async (operationId, ownerGeneration) => { calls.cancel.push({ operationId, ownerGeneration }); latest = status(latest.statusRevision + 1,
      { ...latest.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null }); return copy(latest); } };
  await controller.connect(api); controller.syncProject();
  return { controller, api, calls, selected, saved, peer: value => peer = value, now: value => now = value,
    emit: value => { latest = value; listener(copy(value)); }, latest: () => latest,
    defer: () => { let release; waitPrepare = new Promise(resolve => release = resolve); return release; } };
}
test('native pair context is local candidate only; default Full and core scope are not widened', () => {
  const request = { projectId: 'synthetic-project', draft: { android: { enabled: true }, ios: { enabled: true } }, ...scope() };
  assert.equal(assetRequestFits('asset_context', request), true);
  for (const change of [v => v.platform = 'ios', v => v.purpose = 'store', v => v.stage = 'production', v => v.executionMode = 'github',
    v => delete v.executionMode, v => v.draft.ios.enabled = false, v => v.draft.android.enabled = 'true']) {
    const bad = copy(request); change(bad); assert.equal(assetRequestFits('asset_context', bad), false);
  }
});
test('native Both context displays the actual single-platform GSA or P8 assessment, never a relabelled core result', () => {
  for (const kind of ['google-service-account', 'asc-p8']) {
    const v = assets().status; v.operation = { operationId: 1, operation: 'prepare', phase: 'idle', reason: 'none', source: 'not-run', settlement: 'known', storageOutcome: null,
      selectionToken: null, assessment: assessment(kind), preview: null };
    const parsed = parseAssetStatus(v); assert.ok(parsed); assert.deepEqual(copy(parsed.operation.assessment.context), assessment(kind).context);
    for (const change of [r => r.context.platform = 'both', r => r.context.platform = kind === 'asc-p8' ? 'android' : 'ios',
      r => r.context.purpose = 'version-inventory', r => r.context.purpose = 'full', r => r.context.stage = 'production', r => r.context.executionMode = 'github']) {
      const bad = copy(v); change(bad.operation.assessment); assert.equal(parseAssetStatus(bad), null);
    }
  }
});
test('same saved shared source and both current assigned revisions are required before a paired request', () => {
  assert.ok(input()); assert.equal(input().recordId, C); assert.deepEqual(copy(input().iosRecord), { recordId: D, recordRevision: 4 });
  for (const index of [0, 1]) for (const change of [v => v.status.assignments[index].availability = 'unavailable', v => v.status.assignments[index].contextRevision++,
    v => v.status.records[index].revision++, v => v.status.records[index].availability = 'unassigned']) {
    const selected = assets(); change(selected); assert.equal(localStoreRequest(project(), selected), null);
  }
  for (const platforms of [null, ['android'], ['ios'], ['ios', 'android']]) assert.equal(localStoreRequest({ ...project(), versionPlatforms: platforms }, assets()), null);
  const stale = assets(); stale.scope.purpose = 'store'; assert.equal(localStoreRequest(project(), stale), null);
  assert.equal(localStoreRequest({ ...project(), dirtyDraft: true }, assets()), null);
});
test('one exact pair preserves marketing-only iOS and APK data but partial or oversized inventory never becomes observed', () => {
  assert.deepEqual(copy(parsePairedCurrentVersions(summary())), summary()); assert.equal(pairedVersionsObserved(summary()), true);
  for (const change of [v => delete v.ios, v => v.extra = {}, v => v.android.counts.apks = 401, v => v.android.temporaryEdit = 'unconfirmed',
    v => v.ios.coverage = 'all-history', v => v.ios.maxBuild = '1.0', v => v.android = v.ios]) {
    const bad = summary(); change(bad); assert.equal(parsePairedCurrentVersions(bad), null);
  }
  const partial = summary(); partial.ios.observation = 'not-permitted'; for (const k of ['revision', 'counts', 'maxBuild', 'marketingVersion']) partial.ios[k] = null;
  assert.ok(parsePairedCurrentVersions(partial)); assert.equal(pairedVersionsObserved(partial), false);
  let touched = false; const hostile = { ...summary() }; Object.defineProperty(hostile, 'ios', { enumerable: true, get() { touched = true; return summary().ios; } });
  assert.equal(parsePairedCurrentVersions(hostile), null); assert.equal(touched, false);
});
test('pair wire and temporary-edit consent cannot enter old Store access, delivery or a single-platform context', () => {
  const request = input(); assert.ok(parseLocalStoreRequest(request)); assert.ok(encodeLocalStoreRequest('prepare_local_store_preflight', request));
  assert.equal(storeConsent('both', QUERY), CONSENT); assert.ok(encodeLocalStoreRequest('start_local_store_preflight', { operationId: A, ownerGeneration: B, consentVersion: CONSENT }));
  for (const change of [v => v.platform = 'android', v => v.platform = 'ios', v => v.query = 'ios-current-versions', v => delete v.query,
    v => v.iosRecord = null, v => v.iosRecord.recordId = v.recordId, v => v.iosRecord.recordRevision = 0, v => v.iosRecord.privateKey = 'not-allowed']) {
    const bad = copy(request); change(bad); assert.equal(parseLocalStoreRequest(bad), null);
  }
  assert.equal(parseLocalStorePrepareRequest(request), null); // No build/upload/candidate authority.
});
test('complete paired result is context-bound; failed delete is displayable but never a usable pair', () => {
  const v = status(1, { ...operation(), phase: 'terminal', intentUsable: false, outcome: 'complete', result: result() });
  assert.ok(parseLocalStoreStatus(v));
  const failed = copy(v); const android = failed.operation.result.currentVersions.android;
  android.observation = 'temporary-edit-unconfirmed'; android.temporaryEdit = 'unconfirmed'; for (const key of ['revision', 'counts', 'maxBuild']) android[key] = null;
  failed.operation.result.findings = [{ check: 'store-access', status: 'FAIL' }]; assert.ok(parseLocalStoreStatus(failed)); assert.equal(pairedVersionsObserved(failed.operation.result.currentVersions), false);
  for (const change of [v => v.operation.context.platform = 'ios', v => v.operation.context.query = 'android-current-versions',
    v => v.operation.result.findings = [{ check: 'store-access', status: 'FAIL' }], v => v.operation.result.scope = 'local-ios-current-version-inventory']) {
    const bad = copy(v); change(bad); assert.equal(parseLocalStoreStatus(bad), null);
  }
});
test('actual controller is inert until explicit paired review and exact consent; no generic access fallback', async () => {
  const f = await fixture(); assert.deepEqual(f.calls, { prepare: [], start: [], cancel: [] });
  await f.controller.prepare(); await f.controller.prepare('ios-current-versions'); assert.equal(f.calls.prepare.length, 0);
  await f.controller.prepare(QUERY); assert.equal(f.calls.prepare.length, 1); assert.equal(f.calls.start.length, 0); assert.ok(localStoreOwnerReason(f.controller.getSnapshot()));
  f.controller.acknowledge(true); await f.controller.start(); assert.equal(f.calls.start.length, 1); assert.equal(f.calls.start[0].consentVersion, CONSENT);
  await f.controller.start(); assert.equal(f.calls.start.length, 1); await f.controller.cancel(); f.controller.dispose();
});
test('reentrant selection ABA, either assignment revocation or peer admission vetoes Prepare after notification', async () => {
  for (const change of [f => { f.controller.selectionIntent(); f.controller.syncProject(); }, f => f.selected.status.assignments[0].availability = 'unavailable',
    f => f.selected.status.assignments[1].availability = 'unavailable', f => f.peer('another operation')]) {
    const f = await fixture(); let used = false; const off = f.controller.subscribe(() => { if (!used && f.controller.getSnapshot().pending) { used = true; change(f); } });
    await f.controller.prepare(QUERY); assert.equal(f.calls.prepare.length, 0); off(); f.controller.dispose();
  }
});
test('same post-listener guard vetoes Start after either key/source/peer changes and keeps original cancellation', async () => {
  for (const change of [f => f.selected.status.assignments[0].recordRevision++, f => f.selected.status.assignments[1].recordRevision++,
    f => f.saved.savedVersion.sha256 = 'f'.repeat(64), f => f.peer('busy'), f => f.now(60100)]) {
    const f = await fixture(); await f.controller.prepare(QUERY); f.controller.acknowledge(true); let used = false;
    const off = f.controller.subscribe(() => { if (!used && f.controller.getSnapshot().pending) { used = true; change(f); } });
    await f.controller.start(); assert.equal(f.calls.start.length, 0); assert.equal(f.calls.prepare.length, 1); off(); await f.controller.cancel(); f.controller.dispose();
  }
});
test('late prepared pair stays owned across context change; missing Start reply is never replay permission', async () => {
  const f = await fixture(), release = f.defer(); const pending = f.controller.prepare(QUERY);
  f.controller.selectionIntent(); assert.ok(localStoreOwnerReason(f.controller.getSnapshot())); await f.controller.prepare(QUERY); assert.equal(f.calls.prepare.length, 1);
  release(); await pending; assert.equal(f.calls.start.length, 0); assert.ok(f.calls.cancel.length > 0); f.controller.dispose();
  const lost = await fixture(); await lost.controller.prepare(QUERY); lost.controller.acknowledge(true);
  lost.api.startLocalStorePreflight = async value => { lost.calls.start.push(copy(value)); throw new Error('private-error-canary'); };
  await lost.controller.start(); await lost.controller.start(); assert.equal(lost.calls.start.length, 1);
  assert.ok(lost.controller.getSnapshot().blocked); assert.ok(!JSON.stringify(lost.controller.getSnapshot()).includes('private-error-canary')); lost.controller.dispose();
});
test('shared saved source is supported UI input only; unknown or dirty source remains refused', () => {
  assert.equal(versionReserveProjectIssue(project()), null);
  assert.ok(versionReserveProjectIssue({ ...project(), versionPlatforms: null }));
  assert.ok(versionReserveProjectIssue({ ...project(), dirtyDraft: true }));
  assert.ok(versionReserveProjectIssue({ ...project(), versionPlatforms: ['ios', 'android'] }));
});
