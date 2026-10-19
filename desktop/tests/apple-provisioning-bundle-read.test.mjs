// Closed protocol/controller DATA with a fake native port. No native SDK,
// account, credential, network, shell or browser UI execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason } from '../src/localStorePreflight.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, encodeLocalStoreRequest, storeConsent,
  APPLE_STORE_CONSENT, STORE_CONSENT, APPLE_BUNDLE_CONSENT, APPLE_BUNDLE_QUERY, APPLE_BUNDLE_SCOPE } from '../src/localStorePreflightProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';

const A = 'a'.repeat(32), B = 'b'.repeat(32), C = 'c'.repeat(32);
const copy = value => structuredClone(value);
const limits = ['non-publishing', 'no-project-commands', 'no-build-or-signing', 'no-release-readiness', 'point-in-time-account-access', 'saved-inputs-not-atomic'];
const bundleLimits = [...limits, 'no-team-verification', 'no-global-availability-claim', 'no-provisioning-changes'];
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
const request = () => ({ ...localStoreRequest(project(), assets()), query: APPLE_BUNDLE_QUERY });
const status = (revision = 0, operation = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation });
const op = request => ({ operationId: A, ownerGeneration: B, context: { ...copy(request), platform: request.platform ?? 'android', operation: 'local-store-preflight' },
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null });
const complete = (request, observation = 'not-returned') => ({ ...op(request), phase: 'terminal', intentUsable: false, outcome: 'complete',
  result: { schemaVersion: 1, scope: APPLE_BUNDLE_SCOPE, observation, findings: [{ check: 'credential-format', status: 'PASS' }], limitations: bundleLimits } });

async function fixture(platform = 'ios') {
  let selected = assets(platform), now = 100, listener, latest = status(), gate = null;
  const calls = { prepare: [], start: [], cancel: [] };
  const controller = new LocalStorePreflightController({ project, assets: () => selected, otherOperationReason: () => null, now: () => now });
  const api = { mode: 'native', subscribeLocalStorePreflight: async fn => { listener = fn; return () => {}; }, localStorePreflightStatus: async () => copy(latest),
    prepareLocalStorePreflight: async input => { calls.prepare.push(copy(input)); if (gate) await gate; latest = status(latest.statusRevision + 1, op(input)); return copy(latest); },
    startLocalStorePreflight: async input => { calls.start.push(copy(input)); latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'running', intentUsable: false }); return copy(latest); },
    cancelLocalStorePreflight: async (operationId, ownerGeneration) => { calls.cancel.push({ operationId, ownerGeneration }); latest = status(latest.statusRevision + 1, { ...latest.operation, phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null }); return copy(latest); } };
  await controller.connect(api); controller.syncProject();
  return { controller, api, calls, latest: () => copy(latest), now: value => now = value,
    defer: () => { let release; gate = new Promise(resolve => release = resolve); return release; },
    select: platform => { selected = assets(platform); controller.syncProject(); },
    emit: value => { latest = value; listener(copy(value)); } };
}

test('explicit iOS query and distinct consent do not widen legacy access or permit secret inputs', () => {
  const value = request(); assert.ok(parseLocalStoreRequest(value));
  assert.equal(storeConsent('ios', APPLE_BUNDLE_QUERY), APPLE_BUNDLE_CONSENT);
  assert.equal(storeConsent('ios'), APPLE_STORE_CONSENT); assert.equal(storeConsent('android'), STORE_CONSENT);
  for (const change of [v => delete v.platform, v => v.platform = 'android', v => v.query = null,
    v => v.query = 'create-bundle-id', v => v.teamId = 'FAKETEAM00', v => v.privateKey = 'PRIVATE', v => v.environment = {}]) {
    const bad = copy(value); change(bad); assert.equal(parseLocalStoreRequest(bad), null);
  }
  let getter = 0; const bad = copy(value); Object.defineProperty(bad, 'query', { enumerable: true, get() { getter++; return APPLE_BUNDLE_QUERY; } });
  assert.equal(parseLocalStoreRequest(bad), null); assert.equal(getter, 0);
  const ordinary = localStoreRequest(project(), assets()); assert.ok(parseLocalStoreRequest(ordinary)); assert.equal(Object.hasOwn(ordinary, 'query'), false);
});

test('one-page observation is a closed enum, not legacy access, team proof or global availability', () => {
  for (const observation of ['found', 'not-returned', 'not-permitted', 'inconclusive', 'not-checked']) {
    assert.ok(parseLocalStoreStatus(status(1, complete(request(), observation))));
  }
  for (const change of [v => delete v.result.observation, v => v.result.observation = null, v => v.result.observation = 'available',
    v => v.result.scope = 'local-ios-store-access-no-publishing', v => v.result.limitations = limits,
    v => v.result.teamVerified = true, v => v.result.providerBody = 'PRIVATE', v => v.result.findings[0].check = 'store-access',
    v => v.result.findings[0].message = 'PRIVATE', v => delete v.context.query,
    v => v.context.platform = 'android', v => v.context.query = null, v => v.phase = 'running', v => v.outcome = 'unknown']) {
    const bad = complete(request()); change(bad); assert.equal(parseLocalStoreStatus(status(1, bad)), null);
  }
  const legacy = complete(localStoreRequest(project(), assets())); delete legacy.result.observation;
  legacy.result.scope = 'local-ios-store-access-no-publishing'; legacy.result.limitations = limits;
  legacy.result.findings.push({ check: 'store-access', status: 'FAIL' }); assert.ok(parseLocalStoreStatus(status(1, legacy)));
});

test('same existing raw bridge carries only the closed query and distinct consent', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, bytes) => { calls.push([command, JSON.parse(new TextDecoder().decode(bytes))]); return status(); }, async () => () => {});
  await api.prepareLocalStorePreflight(request());
  await api.startLocalStorePreflight({ operationId: A, ownerGeneration: B, consentVersion: APPLE_BUNDLE_CONSENT });
  assert.deepEqual(calls.map(row => row[0]), ['prepare_local_store_preflight', 'start_local_store_preflight']);
  assert.deepEqual(calls[0][1], JSON.parse(JSON.stringify(request()))); assert.equal(calls[1][1].consentVersion, APPLE_BUNDLE_CONSENT);
  assert.equal(encodeLocalStoreRequest('start_local_store_preflight', { operationId: A, ownerGeneration: B, consentVersion: 'local-ios-provision-v1' }), null);
});

test('same original controller retains query, starts once with its own unchecked consent and cancels exact original', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(APPLE_BUNDLE_QUERY); assert.equal(h.calls.prepare.length, 1);
    assert.equal(h.controller.getSnapshot().acknowledged, false); assert.equal(h.calls.start.length, 0);
    assert.equal(h.latest().operation.context.query, APPLE_BUNDLE_QUERY);
    h.controller.acknowledge(true); await h.controller.start(); await h.controller.start();
    assert.deepEqual(h.calls.start, [{ operationId: A, ownerGeneration: B, consentVersion: APPLE_BUNDLE_CONSENT }]);
    h.select('android'); await Promise.resolve();
    assert.deepEqual(h.calls.cancel, [{ operationId: A, ownerGeneration: B }]);
    assert.equal(h.controller.getSnapshot().historical, true); assert.equal(h.controller.getSnapshot().consentUntil, null);
    assert.equal(h.calls.prepare.length, 1);
  } finally { h.controller.dispose(); }
});

test('query cannot replace a pending ordinary check or run in the Android context', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(); await h.controller.prepare(APPLE_BUNDLE_QUERY);
    assert.equal(h.calls.prepare.length, 1); assert.equal(Object.hasOwn(h.calls.prepare[0], 'query'), false);
    h.controller.acknowledge(true); await h.controller.start(); assert.equal(h.calls.start[0].consentVersion, APPLE_STORE_CONSENT);
  } finally { h.controller.dispose(); }
  const android = await fixture('android');
  try { await android.controller.prepare(APPLE_BUNDLE_QUERY); assert.equal(android.calls.prepare.length, 0); }
  finally { android.controller.dispose(); }
});

test('delayed query prepare on changed context never offers renewed consent', async () => {
  const h = await fixture();
  try {
    const release = h.defer(), pending = h.controller.prepare(APPLE_BUNDLE_QUERY);
    h.select('android'); release(); await pending; await Promise.resolve();
    assert.equal(h.calls.start.length, 0); assert.equal(h.calls.cancel.length, 1);
    assert.equal(h.controller.getSnapshot().consentUntil, null); assert.equal(h.controller.getSnapshot().historical, true);
  } finally { h.controller.dispose(); }
});

test('expired query intent cannot start; unknown cleanup retains original instead of retry or empty-result claim', async () => {
  const h = await fixture();
  try {
    await h.controller.prepare(APPLE_BUNDLE_QUERY); h.controller.acknowledge(true); h.now(60101); await h.controller.start();
    assert.equal(h.calls.start.length, 0);
    const before = h.latest(); h.emit(status(before.statusRevision + 1, { ...before.operation, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null }));
    await h.controller.checkStatus(); await h.controller.prepare(APPLE_BUNDLE_QUERY);
    assert.equal(h.calls.prepare.length, 1); assert.ok(localStoreOwnerReason(h.controller.getSnapshot()));
    assert.equal(h.controller.getSnapshot().blocked, true); assert.equal(h.latest().operation.result, null);
  } finally { h.controller.dispose(); }
});

test('failed prepare and contradictory query-shaped response never silently choose access or retry', async () => {
  const h = await fixture();
  try {
    h.api.prepareLocalStorePreflight = async input => { h.calls.prepare.push(input); throw new Error('PRIVATE_PROVIDER_OR_TRANSPORT'); };
    await h.controller.prepare(APPLE_BUNDLE_QUERY); await h.controller.prepare();
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.start.length, 0);
    assert.equal(h.controller.getSnapshot().unconfirmed, true); assert.equal(h.controller.getSnapshot().blocked, true);
    assert.equal(h.controller.getSnapshot().error.includes('PRIVATE'), false);
  } finally { h.controller.dispose(); }
  const other = await fixture();
  try {
    await other.controller.prepare(APPLE_BUNDLE_QUERY);
    const bad = other.latest(); bad.statusRevision++; delete bad.operation.context.query;
    other.emit(bad); await Promise.resolve();
    assert.equal(other.controller.getSnapshot().blocked, true); assert.equal(other.calls.start.length, 0);
  } finally { other.controller.dispose(); }
});
