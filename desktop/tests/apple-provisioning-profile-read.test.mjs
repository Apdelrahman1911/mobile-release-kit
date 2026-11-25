// Same original controller/raw bridge; synthetic native port and metadata only.
// No SDK, keychain, network, native processes, React/DOM or signing execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason } from '../src/localStorePreflight.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, encodeLocalStoreRequest, storeConsent,
  APPLE_STORE_CONSENT, APPLE_BUNDLE_QUERY, APPLE_BUNDLE_CONSENT, APPLE_BUNDLE_SCOPE,
  APPLE_PROFILE_QUERY, APPLE_PROFILE_CONSENT, APPLE_PROFILE_SCOPE } from '../src/localStorePreflightProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';

const A = 'a'.repeat(32), B = 'b'.repeat(32), C = 'c'.repeat(32);
const copy = value => structuredClone(value);
const limits = ['non-publishing', 'no-project-commands', 'no-build-or-signing', 'no-release-readiness',
  'point-in-time-account-access', 'saved-inputs-not-atomic', 'no-team-verification', 'no-global-availability-claim', 'no-provisioning-changes'];
const profileLimits = [...limits, 'metadata-only', 'no-private-key-match', 'no-profile-authentication', 'no-account-certificate-inventory'];
const project = () => ({ projectId: 'synthetic-project', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) }, savedVersion: { bytes: 40, sha256: 'b'.repeat(64), source: 'release/version.properties', name: '1.2.3', build: 42 },
  inputIssue: null, dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false });
function assets(platform = 'ios') {
  const kind = platform === 'ios' ? 'asc-p8' : 'google-service-account';
  return { mode: 'native', scope: { executionMode: 'local', platform, stage: 'candidate', purpose: 'store' },
    contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false,
    status: { mode: 'session', capability: { available: true }, modes: { session: { available: true } },
      context: { revision: 3, projectId: 'synthetic-project', executionMode: 'local', platform, stage: 'candidate', purpose: 'store' }, operation: null,
      assignments: [{ kind, recordId: C, recordRevision: 4, contextRevision: 3, availability: 'available' }],
      records: [{ kind, recordId: C, revision: 4, availability: 'assigned' }] } };
}
const request = query => ({ ...localStoreRequest(project(), assets()), query: query ?? APPLE_PROFILE_QUERY });
const status = (revision = 0, operation = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation });
const operation = request => ({ operationId: A, ownerGeneration: B, context: { ...copy(request), platform: request.platform ?? 'android', operation: 'local-store-preflight' },
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null });
const summary = () => ({ observation: 'found', counts: { matchingProfiles: 2, activeProfiles: 2, currentMetadataCandidates: 1, relatedCertificates: 1 }, checkedAt: '2026-10-19T12:30:00.123456Z' });
const complete = () => ({ ...operation(request()), phase: 'terminal', intentUsable: false, outcome: 'complete',
  result: { schemaVersion: 1, scope: APPLE_PROFILE_SCOPE, profileReuse: summary(), findings: [{ check: 'credential-format', status: 'PASS' }], limitations: profileLimits } });

async function fixture(platform = 'ios') {
  let selected = assets(platform), now = 100, listener, latest = status(), gate = null;
  const calls = { prepare: [], start: [], cancel: [] };
  const controller = new LocalStorePreflightController({ project, assets: () => selected, otherOperationReason: () => null, now: () => now });
  const api = { mode: 'native', subscribeLocalStorePreflight: async fn => { listener = fn; return () => {}; }, localStorePreflightStatus: async () => copy(latest),
    prepareLocalStorePreflight: async input => { calls.prepare.push(copy(input)); if (gate) await gate; latest = status(latest.statusRevision + 1, operation(input)); return copy(latest); },
    startLocalStorePreflight: async input => { calls.start.push(copy(input)); latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'running', intentUsable: false }); return copy(latest); },
    cancelLocalStorePreflight: async (operationId, ownerGeneration) => { calls.cancel.push({ operationId, ownerGeneration }); latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null }); return copy(latest); } };
  await controller.connect(api); controller.syncProject();
  return { controller, api, calls, latest: () => copy(latest), now: value => now = value,
    defer: () => { let release; gate = new Promise(resolve => release = resolve); return release; },
    select: platform => { selected = assets(platform); controller.syncProject(); },
    emit: value => { latest = value; listener(copy(value)); } };
}

test('profile query is explicit iOS-only and cannot borrow Bundle-ID/access consent or private inputs', () => {
  assert.ok(parseLocalStoreRequest(request()));
  assert.equal(storeConsent('ios', APPLE_PROFILE_QUERY), APPLE_PROFILE_CONSENT);
  assert.equal(storeConsent('ios', APPLE_BUNDLE_QUERY), APPLE_BUNDLE_CONSENT);
  assert.equal(storeConsent('ios'), APPLE_STORE_CONSENT);
  assert.notEqual(APPLE_PROFILE_CONSENT, APPLE_BUNDLE_CONSENT);
  for (const mutate of [v => delete v.platform, v => v.platform = 'android', v => v.query = 'download-profile',
    v => v.profileId = 'private', v => v.teamId = 'UNPROVEN00', v => v.privateKey = 'private', v => v.query = null]) {
    const value = request(); mutate(value); assert.equal(parseLocalStoreRequest(value), null);
  }
  const input = request(); let calls = 0;
  Object.defineProperty(input, 'query', { enumerable: true, get() { calls++; return APPLE_PROFILE_QUERY; } });
  assert.equal(parseLocalStoreRequest(input), null); assert.equal(calls, 0);
});

test('metadata counts and comparison date are bounded and never substitute for signing or other query results', () => {
  assert.ok(parseLocalStoreStatus(status(1, complete())));
  for (const mutate of [v => v.result.profileReuse.counts.matchingProfiles = 201,
    v => v.result.profileReuse.counts.activeProfiles = 3, v => v.result.profileReuse.counts.currentMetadataCandidates = 3,
    v => v.result.profileReuse.counts.relatedCertificates = 401, v => v.result.profileReuse.counts.relatedCertificates = 0,
    v => v.result.profileReuse.counts.currentMetadataCandidates = true, v => v.result.profileReuse.checkedAt = '2026-02-30T12:30:00.123456Z',
    v => v.result.profileReuse.checkedAt = '2026-10-19T12:30:00Z', v => v.result.profileReuse.checkedAt = '2026-10-19T24:00:00.000000Z',
    v => v.result.profileReuse.checkedAt = '1969-10-19T12:30:00.123456Z', v => v.result.profileReuse.privateKeyMatched = true,
    v => v.result.profileReuse.profileIds = ['private'], v => v.result.observation = 'found',
    v => v.result.findings[0].check = 'store-access', v => v.result.limitations = limits,
    v => v.result.scope = APPLE_BUNDLE_SCOPE, v => v.context.query = APPLE_BUNDLE_QUERY,
    v => delete v.context.query, v => v.result.profileReuse = null]) {
    const value = complete(); mutate(value); assert.equal(parseLocalStoreStatus(status(1, value)), null);
  }
});

test('inconclusive or denied has no counts/time; absence spelling requires exactly zero local counts', () => {
  for (const observation of ['inconclusive', 'not-permitted', 'not-checked']) {
    const value = complete(); value.result.profileReuse = { observation, counts: null, checkedAt: null };
    assert.ok(parseLocalStoreStatus(status(1, value)));
    for (const key of ['counts', 'checkedAt']) {
      const bad = copy(value); delete bad.result.profileReuse[key]; assert.equal(parseLocalStoreStatus(status(1, bad)), null);
    }
    const bad = complete(); bad.result.profileReuse.observation = observation;
    assert.equal(parseLocalStoreStatus(status(1, bad)), null);
  }
  const value = complete(); value.result.profileReuse.observation = 'not-returned';
  assert.equal(parseLocalStoreStatus(status(1, value)), null);
  value.result.profileReuse.counts = { matchingProfiles: 0, activeProfiles: 0, currentMetadataCandidates: 0, relatedCertificates: 0 };
  assert.ok(parseLocalStoreStatus(status(1, value)));
});

test('existing raw bridge carries only exact query/consent and rejects a download command', async () => {
  const calls = [];
  const api = createNativeApi('native', async (name, bytes) => { calls.push([name, JSON.parse(new TextDecoder().decode(bytes))]); return status(); }, async () => () => {});
  await api.prepareLocalStorePreflight(request());
  await api.startLocalStorePreflight({ operationId: A, ownerGeneration: B, consentVersion: APPLE_PROFILE_CONSENT });
  assert.deepEqual(calls.map(item => item[0]), ['prepare_local_store_preflight', 'start_local_store_preflight']);
  assert.deepEqual(calls[0][1], JSON.parse(JSON.stringify(request())));
  assert.equal(calls[1][1].consentVersion, APPLE_PROFILE_CONSENT);
  assert.equal(encodeLocalStoreRequest('start_local_store_preflight', { operationId: A, ownerGeneration: B, consentVersion: 'local-ios-profile-download-v1' }), null);
});

test('same controller retains one profile query, unchecked consent, original cancel and currentness', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(APPLE_PROFILE_QUERY);
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.controller.getSnapshot().acknowledged, false);
    assert.equal(h.latest().operation.context.query, APPLE_PROFILE_QUERY);
    h.controller.acknowledge(true); await h.controller.start(); await h.controller.start();
    assert.deepEqual(h.calls.start, [{ operationId: A, ownerGeneration: B, consentVersion: APPLE_PROFILE_CONSENT }]);
    h.select('android'); await Promise.resolve();
    assert.deepEqual(h.calls.cancel, [{ operationId: A, ownerGeneration: B }]);
    assert.equal(h.controller.getSnapshot().historical, true);
    assert.equal(h.controller.getSnapshot().consentUntil, null);
  } finally { h.controller.dispose(); }
});

test('profile read cannot replace a pending Bundle-ID read or run on Android', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(APPLE_BUNDLE_QUERY); await h.controller.prepare(APPLE_PROFILE_QUERY);
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.prepare[0].query, APPLE_BUNDLE_QUERY);
    h.controller.acknowledge(true); await h.controller.start(); assert.equal(h.calls.start[0].consentVersion, APPLE_BUNDLE_CONSENT);
  } finally { h.controller.dispose(); }
  const android = await fixture('android');
  try { await android.controller.prepare(APPLE_PROFILE_QUERY); assert.equal(android.calls.prepare.length, 0); }
  finally { android.controller.dispose(); }
});

test('late prepare after context change does not renew consent or attach metadata to a new selection', async () => {
  const h = await fixture();
  try {
    const release = h.defer(), pending = h.controller.prepare(APPLE_PROFILE_QUERY);
    h.select('android'); release(); await pending; await Promise.resolve();
    assert.equal(h.calls.start.length, 0); assert.equal(h.calls.cancel.length, 1);
    assert.equal(h.controller.getSnapshot().historical, true); assert.equal(h.controller.getSnapshot().consentUntil, null);
  } finally { h.controller.dispose(); }
});

test('expired consent and unknown cleanup cannot become a fresh check or metadata result', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(APPLE_PROFILE_QUERY); h.controller.acknowledge(true); h.now(60101); await h.controller.start();
    assert.equal(h.calls.start.length, 0);
    const old = h.latest(); h.emit(status(old.statusRevision + 1, { ...old.operation, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null }));
    await h.controller.checkStatus(); await h.controller.prepare(APPLE_PROFILE_QUERY);
    assert.equal(h.calls.prepare.length, 1); assert.ok(localStoreOwnerReason(h.controller.getSnapshot()));
    assert.equal(h.controller.getSnapshot().blocked, true); assert.equal(h.latest().operation.result, null);
  } finally { h.controller.dispose(); }
});

test('failed or mismatched replies stay unconfirmed without access fallback or provider text', async () => {
  const h = await fixture();
  try {
    h.api.prepareLocalStorePreflight = async input => { h.calls.prepare.push(input); throw new Error('PRIVATE_PROVIDER_TEXT'); };
    await h.controller.prepare(APPLE_PROFILE_QUERY); await h.controller.prepare();
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.start.length, 0);
    assert.equal(h.controller.getSnapshot().unconfirmed, true); assert.equal(h.controller.getSnapshot().blocked, true);
    assert.equal(h.controller.getSnapshot().error.includes('PRIVATE'), false);
  } finally { h.controller.dispose(); }
  const other = await fixture();
  try {
    await other.controller.prepare(APPLE_PROFILE_QUERY);
    const bad = other.latest(); bad.statusRevision++; bad.operation.context.query = APPLE_BUNDLE_QUERY;
    other.emit(bad); await Promise.resolve();
    assert.equal(other.controller.getSnapshot().blocked, true); assert.equal(other.calls.start.length, 0);
  } finally { other.controller.dispose(); }
});
