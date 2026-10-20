// Original controller/protocol with inert native replies; no DOM, Store, keys,
// native process, allocation or release-readiness qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseIOSCurrentVersions, IOS_VERSIONS_QUERY as QUERY, IOS_VERSIONS_CONSENT as CONSENT,
  IOS_VERSIONS_SCOPE as SCOPE, IOS_VERSIONS_COVERAGE as COVERAGE, iosVersionsLimitations as limitations } from '../src/iosStoreVersions.ts';
import { parseLocalStoreRequest, parseLocalStoreStatus, encodeLocalStoreRequest, storeConsent } from '../src/localStorePreflightProtocol.ts';
import { LocalStorePreflightController, localStoreRequest, localStoreOwnerReason } from '../src/localStorePreflight.ts';

const copy = value => structuredClone(value), A = 'a'.repeat(32), B = 'b'.repeat(32), C = 'c'.repeat(32);
const project = () => ({ projectId: 'synthetic-project', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) }, savedVersion: { bytes: 40, sha256: 'b'.repeat(64), source: 'release/version.properties', name: '1.2.3', build: 42 },
  inputIssue: null, dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false });
const assets = (platform = 'ios') => {
  const kind = platform === 'ios' ? 'asc-p8' : 'google-service-account';
  return { mode: 'native', scope: { executionMode: 'local', platform, stage: 'candidate', purpose: 'store' },
    contextCurrent: true, busy: null, updatingContext: false, observationFailed: false, blocked: false, originPending: false,
    status: { mode: 'session', capability: { available: true }, modes: { session: { available: true } },
      context: { revision: 3, projectId: 'synthetic-project', executionMode: 'local', platform, stage: 'candidate', purpose: 'store' }, operation: null,
      assignments: [{ kind, recordId: C, recordRevision: 4, contextRevision: 3, availability: 'available' }],
      records: [{ kind, recordId: C, revision: 4, availability: 'assigned' }] } };
};
const input = () => ({ ...localStoreRequest(project(), assets()), query: QUERY });
const status = (revision = 0, operation = null) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation });
const operation = request => ({ operationId: A, ownerGeneration: B, context: { ...copy(request), platform: request.platform ?? 'android', operation: 'local-store-preflight' },
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null });
const summary = () => ({ observation: 'observed', coverage: COVERAGE, revision: 'a'.repeat(64), counts: { builds: 0, buildUploads: 0, appStoreVersions: 1 },
  maxBuild: 0, marketingVersion: '2.0.0', historicalUniqueness: 'not-established' });
const complete = () => ({ ...operation(input()), phase: 'terminal', intentUsable: false, outcome: 'complete',
  result: { schemaVersion: 1, scope: SCOPE, findings: [], limitations: [...limitations], currentVersions: summary() } });
async function fixture(platform = 'ios') {
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
    peer: value => peer = value,
    changeProject: edit => edit(currentProject),
    changeAssets: edit => edit(selected),
    defer: () => { let release; deferred = new Promise(resolve => release = resolve); return release; },
    select: platform => { selected = assets(platform); controller.syncProject(); },
    emit: value => { latest = value; listener(copy(value)); } };
}
test('marketing-only inventory is not historical uniqueness or a zero-history assertion', () => {
  assert.deepEqual(copy(parseIOSCurrentVersions(summary())), summary());
  const empty = summary(); empty.counts.appStoreVersions = 0; empty.marketingVersion = null;
  assert.deepEqual(copy(parseIOSCurrentVersions(empty)), empty);
  for (const edit of [v => v.maxBuild = 1, v => v.marketingVersion = null, v => v.counts.appStoreVersions = 401,
    v => v.coverage = 'application-all-builds', v => v.historicalUniqueness = 'established', v => v.marketingVersion = '2.00',
    v => v.marketingVersion = '2.0\n', v => v.revision += '\n', v => v.counts.builds = true]) {
    const value = summary(); edit(value); assert.equal(parseIOSCurrentVersions(value), null);
  }
});
test('denied incomplete and oversize are null data not a zero floor; getters never invoked', () => {
  for (const observation of ['not-checked', 'not-permitted', 'inconclusive', 'too-many', 'unsupported-format']) {
    const value = { ...summary(), observation }; assert.equal(parseIOSCurrentVersions(value), null);
    for (const key of ['revision', 'counts', 'maxBuild', 'marketingVersion']) value[key] = null;
    assert.ok(parseIOSCurrentVersions(value)); delete value.maxBuild; assert.equal(parseIOSCurrentVersions(value), null);
  }
  let invoked = 0; const value = summary();
  Object.defineProperty(value, 'counts', { enumerable: true, get() { invoked++; return {}; } });
  assert.equal(parseIOSCurrentVersions(value), null); assert.equal(invoked, 0);
  assert.equal(parseIOSCurrentVersions({ ...summary(), hidden: 'x'.repeat(10000) }), null);
});
test('existing raw vocabulary has one new exact iOS query and consent but no endpoint input', () => {
  assert.ok(parseLocalStoreRequest(input())); assert.equal(storeConsent('ios', QUERY), CONSENT);
  assert.ok(encodeLocalStoreRequest('start_local_store_preflight', { operationId: A, ownerGeneration: B, consentVersion: CONSENT }));
  for (const edit of [v => v.platform = 'android', v => v.query = null, v => v.query = 'all-history', v => v.appId = '123', v => v.url = 'https://example.invalid']) {
    const value = input(); edit(value); assert.equal(parseLocalStoreRequest(value), null);
  }
});
test('summary is accepted only with matching current-query terminal and never other read success', () => {
  assert.ok(parseLocalStoreStatus(status(1, complete())));
  for (const edit of [v => v.context.query = 'bundle-id-registration', v => delete v.context.query,
    v => v.phase = 'running', v => v.reason = 'cancelled', v => v.result.scope = 'local-ios-store-access-no-publishing',
    v => v.result.currentVersions = null, v => v.result.findings.push({ check: 'store-access', status: 'PASS' }),
    v => v.result.findings.push({ check: 'credential-format', status: 'FAIL' }),
    v => v.result.findings.push({ check: 'query-prerequisites', status: 'BLOCKED' }),
    v => v.result.observation = 'found', v => v.result.limitations.pop()]) {
    const value = complete(); edit(value); assert.equal(parseLocalStoreStatus(status(1, value)), null);
  }
});
test('manual mount and status do not grant; existing controller holds one explicit current-version read', async () => {
  const h = await fixture();
  try {
    assert.equal(h.calls.prepare.length, 0); assert.equal(h.calls.start.length, 0);
    await h.controller.prepare(QUERY); assert.equal(h.calls.prepare.length, 1);
    assert.equal(h.controller.getSnapshot().acknowledged, false);
    h.controller.acknowledge(true); await h.controller.start(); await h.controller.start();
    assert.deepEqual(h.calls.start, [{ operationId: A, ownerGeneration: B, consentVersion: CONSENT }]);
    h.select('android'); await Promise.resolve();
    assert.deepEqual(h.calls.cancel, [{ operationId: A, ownerGeneration: B }]);
    assert.equal(h.controller.getSnapshot().historical, true);
  } finally { h.controller.dispose(); }
});
test('late prepare or expired consent does not renew currentness or call a Store', async () => {
  const h = await fixture();
  try {
    const release = h.defer(), pending = h.controller.prepare(QUERY); h.select('android'); release();
    await pending; await Promise.resolve(); assert.equal(h.calls.start.length, 0); assert.equal(h.calls.cancel.length, 1);
    assert.equal(h.controller.getSnapshot().consentUntil, null);
  } finally { h.controller.dispose(); }
  const next = await fixture();
  try {
    await next.controller.prepare(QUERY); next.controller.acknowledge(true); next.now(60101); await next.controller.start();
    assert.equal(next.calls.start.length, 0);
  } finally { next.controller.dispose(); }
});
test('unknown and lost acknowledgments preserve original controls without access fallback', async () => {
  const h = await fixture();
  try {
    h.api.prepareLocalStorePreflight = async request => { h.calls.prepare.push(request); throw Error('PRIVATE'); };
    await h.controller.prepare(QUERY); await h.controller.prepare();
    assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.start.length, 0);
    assert.ok(localStoreOwnerReason(h.controller.getSnapshot())); assert.equal(h.controller.getSnapshot().error.includes('PRIVATE'), false);
  } finally { h.controller.dispose(); }
  const next = await fixture();
  try {
    await next.controller.prepare(QUERY);
    const last = next.latest(); next.emit(status(last.statusRevision + 1, { ...last.operation,
      phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null }));
    await next.controller.prepare(QUERY); assert.equal(next.calls.prepare.length, 1);
    assert.equal(next.controller.getSnapshot().status.operation.result, null);
  } finally { next.controller.dispose(); }
});
test('Android and a different pending Store query cannot acquire this iOS action', async () => {
  const h = await fixture('android');
  try { await h.controller.prepare(QUERY); assert.equal(h.calls.prepare.length, 0); }
  finally { h.controller.dispose(); }
  const next = await fixture();
  try {
    await next.controller.prepare('bundle-id-registration'); await next.controller.prepare(QUERY);
    assert.equal(next.calls.prepare.length, 1); assert.equal(next.calls.prepare[0].query, 'bundle-id-registration');
  } finally { next.controller.dispose(); }
});
test('current-inventory Prepare rechecks original source and peers after synchronous notification', async () => {
  for (const invalidate of [
    h => h.controller.selectionIntent(),
    h => { h.select('android'); h.select('ios'); }, // ABA cannot revive the epoch.
    h => h.changeProject(p => p.savedVersion.sha256 = 'c'.repeat(64)),
    h => h.changeAssets(a => a.status.context.revision++),
    h => h.peer('An original peer acquired work during notification.'),
    h => h.controller.beginConnection(),
    h => h.controller.dispose(),
  ]) {
    const h = await fixture(); let fired = false;
    const off = h.controller.subscribe(() => {
      if (!fired && h.controller.getSnapshot().pending) { fired = true; invalidate(h); }
    });
    try {
      await h.controller.prepare(QUERY);
      assert.equal(fired, true); assert.equal(h.calls.prepare.length, 0); assert.equal(h.calls.start.length, 0);
      assert.equal(h.controller.getSnapshot().pending, false);
    } finally { off(); h.controller.dispose(); }
  }
});
test('current-inventory Start never invokes a retired consent after notification or source ABA', async () => {
  for (const invalidate of [
    h => h.controller.selectionIntent(),
    h => { h.select('android'); h.select('ios'); },
    h => h.changeProject(p => p.savedConfig.sha256 = 'c'.repeat(64)),
    h => h.changeAssets(a => a.status.assignments[0].recordRevision++),
    h => h.peer('An original peer acquired work during notification.'),
    h => h.now(60101),
    h => h.controller.beginConnection(),
    h => h.controller.dispose(),
  ]) {
    const h = await fixture(); let fired = false;
    await h.controller.prepare(QUERY); h.controller.acknowledge(true);
    const off = h.controller.subscribe(() => {
      if (!fired && h.controller.getSnapshot().pending) { fired = true; invalidate(h); }
    });
    try {
      await h.controller.start(); await Promise.resolve();
      assert.equal(fired, true); assert.equal(h.calls.prepare.length, 1); assert.equal(h.calls.start.length, 0);
      assert.equal(h.controller.getSnapshot().consentUntil, null);
      assert.equal(h.controller.getSnapshot().pending, false);
    } finally { off(); h.controller.dispose(); }
  }
});
