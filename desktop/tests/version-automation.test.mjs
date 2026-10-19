// Inert policy/intent tests. No DOM, native operation, persistence, Store or HTTP.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { manualVersionPolicy, parseVersionPolicy, versionPolicyDraft, versionPolicyFromDraft,
  VersionReservationIntentController, versionAutomationUnavailable } from '../src/versionAutomation.ts';

const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const config = { schemaVersion: 1, version: { source: 'release/version.properties', nameKey: 'NAME', buildKey: 'BUILD' },
  android: { enabled: true }, ios: { enabled: false } };
const savedConfig = { bytes: 1024, sha256: 'a'.repeat(64) };
const savedVersion = { bytes: 35, sha256: 'b'.repeat(64) };
const automatic = (increment = 'build') => ({ schemaVersion: 1, mode: 'automatic',
  rules: [{ ref: 'refs/heads/main', increment }], buildCeiling: 2_100_000_000, storeMaxAgeSeconds: 900 });

async function harness({ dirty = false, begin = null } = {}) {
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert project', path: '/inert-not-opened' } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  workspace = workspaceReducer(workspace, { type: 'snapshot-done', projectId: 'p1', requestId: 1, observedAt: 1,
    snapshot: { root: '/inert-not-opened', observedAt: '', observationScope: 'single-request-non-atomic',
      config: { path: 'release/mobile-release.json', content: savedConfig, state: 'format-valid', data: structuredClone(config), issues: [] },
      discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
      assurance, issues: [] } });
  let session = workspace.projects.p1;
  if (dirty) session = { ...session, revision: session.revision + 1,
    draft: { ...session.draft, version: { ...session.draft.version, source: 'release/unsaved-draft.properties' } } };
  let reads = 0;
  const version = new ReleaseVersionController(() => session);
  version.setConnection({ mode: 'native', observeReleaseVersion: async () => {
    reads += 1;
    return { schemaVersion: 2, source: config.version.source, version: { name: '1.2.3', build: 7 },
      savedConfig, savedVersion, observationScope: 'single-request-non-atomic', assurance };
  } }, { runtime: { state: 'available', mode: 'development', reason: null },
    capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject(); await version.read();
  let context = { session, version: version.getSnapshot(), draft: versionPolicyDraft(automatic()), contextEpoch: 1,
    nativeGate: { projectId: 'p1', generation: 0, state: 'available' }, otherOwnerBusy: false };
  const submitted = [];
  const controller = new VersionReservationIntentController(() => context, (intent) => {
    submitted.push(intent); return begin ? begin(intent, controller) : true;
  });
  return { controller, submitted, get reads() { return reads; }, get context() { return context; },
    setContext(next) { context = next; }, patch(patch) { context = { ...context, ...patch }; } };
}

test('manual default is exact backend shape and never calculates or submits a version', async () => {
  assert.deepEqual(manualVersionPolicy(), { schemaVersion: 1, mode: 'manual', rules: [], buildCeiling: 2_100_000_000, storeMaxAgeSeconds: 900 });
  assert.deepEqual(versionPolicyFromDraft(versionPolicyDraft()), manualVersionPolicy());
  const h = await harness(); h.patch({ draft: versionPolicyDraft() });
  assert.equal(h.controller.prepare(), null);
  assert.match(h.controller.startReason(), /Manual/);
  assert.equal(h.submitted.length, 0); assert.equal(h.reads, 1);
  assert.deepEqual(h.context.version.result.version, { name: '1.2.3', build: 7 });
});

test('policy parser accepts exact refs and all four actions but rejects ambiguous or unbounded input', () => {
  for (const increment of ['build', 'patch', 'minor', 'major']) assert.deepEqual(parseVersionPolicy(automatic(increment)), automatic(increment));
  const tag = automatic('major'); tag.rules[0].ref = 'refs/tags/release/v2'; assert.deepEqual(parseVersionPolicy(tag), tag);
  for (const ref of ['main', 'refs/heads/*', 'refs/heads/main\n', 'refs/heads/a..b', 'refs/heads/.hidden',
    'refs/tags/a.lock', 'refs/heads/refs/heads/main', 'refs/heads/' + 'x'.repeat(201)]) {
    assert.equal(parseVersionPolicy({ ...automatic(), rules: [{ ref, increment: 'build' }] }), null);
  }
  for (const delta of [{ schemaVersion: true }, { buildCeiling: 2_100_000_001 }, { storeMaxAgeSeconds: 3601 },
    { rules: [] }, { rules: [...automatic().rules, ...automatic().rules] }, { extra: 'PRIVATE' }, { mode: 'manual' }]) {
    assert.equal(parseVersionPolicy({ ...automatic(), ...delta }), null);
  }
  assert.equal(versionPolicyFromDraft({ ...versionPolicyDraft(automatic()), buildCeiling: ' 8' }), null);
  assert.equal(versionPolicyFromDraft({ ...versionPolicyDraft(automatic()), storeMaxAgeSeconds: '0900' }), null);
  assert.equal(versionPolicyFromDraft({ ...versionPolicyDraft(), rules: 1 }), null);
  const retained = versionPolicyDraft(automatic('minor'));
  assert.deepEqual(versionPolicyFromDraft({ ...retained, mode: 'manual' }), manualVersionPolicy());
  assert.equal(retained.rules[0].increment, 'minor');
});

test('policy input getters, hidden fields, sparse arrays and toJSON are not executed', () => {
  let calls = 0;
  const getter = { ...automatic(), get rules() { calls += 1; return automatic().rules; } };
  const serializer = { ...automatic(), toJSON() { calls += 1; return automatic(); } };
  const hidden = Object.defineProperty(automatic(), 'private', { value: 'PRIVATE' });
  const sparse = automatic(); sparse.rules = new Array(1);
  for (const value of [getter, serializer, hidden, sparse, Object.assign(Object.create({ inherited: true }), automatic())]) {
    assert.equal(parseVersionPolicy(value), null);
  }
  assert.equal(calls, 0);
});

test('missing native gate or callback remains disabled even with a valid form and current saved observation', async () => {
  const h = await harness(); h.patch({ nativeGate: undefined });
  assert.equal(h.controller.startReason(), versionAutomationUnavailable); assert.equal(h.controller.prepare(), null);
  h.patch({ nativeGate: { projectId: 'p1', generation: 0, state: 'available' } });
  const absentCallback = new VersionReservationIntentController(() => h.context);
  assert.equal(absentCallback.startReason(), versionAutomationUnavailable); assert.equal(absentCallback.prepare(), null);
  for (const state of ['unqualified', 'disconnected', 'busy', 'recovery-required']) {
    h.patch({ nativeGate: { ...h.context.nativeGate, state } });
    assert.notEqual(h.controller.startReason(), null); assert.equal(h.controller.prepare(), null);
  }
  assert.equal(h.submitted.length, 0); assert.equal(h.reads, 1);
});

test('reserve intent binds saved bytes, not dirty settings, and does not edit or save any draft', async () => {
  const h = await harness({ dirty: true }), before = structuredClone(h.context.session);
  assert.equal(h.controller.startReason(), null);
  const intent = h.controller.prepare(); assert.ok(intent);
  assert.deepEqual(intent.savedConfig, savedConfig); assert.deepEqual(intent.savedVersion, savedVersion);
  assert.deepEqual(intent.version, { name: '1.2.3', build: 7 });
  assert.equal(intent.binding.dirtyDraft, true);
  assert.equal(Object.hasOwn(intent, 'source'), false); assert.equal(Object.hasOwn(intent, 'draft'), false);
  assert.equal(Object.isFrozen(intent.policy.rules[0]), true); assert.equal(Object.isFrozen(intent.binding), true);
  assert.equal(h.controller.submit(intent), true);
  assert.deepEqual(h.context.session, before); assert.equal(h.submitted.length, 1); assert.equal(h.reads, 1);
});

test('stale, foreign, preview, recovery, partial and mismatched saved input never enable a reservation', async () => {
  const h = await harness(), base = h.context;
  const changes = [
    { otherOwnerBusy: true }, { otherOwnerBusy: undefined },
    { nativeGate: { ...base.nativeGate, projectId: 'p2' } },
    ...[{ stale: true }, { mode: 'preview' }, { pending: base.version.resultBinding }, { resultBinding: null },
      { result: { ...base.version.result, savedConfig: { ...savedConfig, sha256: 'c'.repeat(64) } } }].map((delta) => ({ version: { ...base.version, ...delta } })),
    ...[{ snapshot: null }, { sourceChanged: true }, { saveRecoveryRequired: true }, { saveRecoveryNeedsReload: true },
      { snapshotPredatesSave: true }, { revision: base.session.revision + 1 }].map((delta) => ({ session: { ...base.session, ...delta } })),
  ];
  for (const delta of changes) {
    h.setContext({ ...base, ...delta }); assert.equal(h.controller.prepare(), null);
  }
  assert.equal(h.submitted.length, 0);
});

test('submission rechecks saved hashes, all context bindings, native generation and changed policy', async () => {
  const h = await harness(), base = h.context;
  const changes = [{ contextEpoch: base.contextEpoch + 1 }, { draft: versionPolicyDraft(automatic('major')) },
    { nativeGate: { ...base.nativeGate, generation: 1 } },
    { version: { ...base.version, readEpoch: base.version.readEpoch + 1 } },
    { version: { ...base.version, connectionGeneration: base.version.connectionGeneration + 1 } },
    { version: { ...base.version, selectionGeneration: base.version.selectionGeneration + 1 } },
    { version: { ...base.version, result: { ...base.version.result, savedVersion: { ...savedVersion, sha256: 'c'.repeat(64) } } } }];
  for (const delta of changes) {
    h.setContext(base); const intent = h.controller.prepare(); assert.ok(intent);
    h.setContext({ ...base, ...delta }); assert.equal(h.controller.submit(intent), false);
  }
  h.setContext(base); const original = h.controller.prepare(); assert.ok(original);
  h.controller.retire(); h.patch({ draft: versionPolicyDraft(automatic('patch')) });
  h.controller.retire(); h.setContext(base); // A -> B -> A is still retired.
  assert.equal(h.controller.submit(original), false);
  assert.equal(h.submitted.length, 0);
});

test('only original single-use intent can invoke the synchronous native owner hook', async () => {
  const h = await harness({ begin: (intent, controller) => {
    assert.equal(controller.submit(intent), false); assert.equal(controller.prepare(), null); return true;
  } });
  const intent = h.controller.prepare(); assert.ok(intent);
  assert.equal(h.controller.submit(structuredClone(intent)), false);
  assert.equal(h.controller.submit(intent), true); assert.equal(h.controller.submit(intent), false);
  assert.equal(h.submitted.length, 1);
});

test('uncertain callback is redacted, remains blocked and cannot be cleared by UI retirement', async () => {
  const h = await harness({ begin: () => { throw new Error('PRIVATE_NATIVE_REJECTION'); } });
  let renders = 0; const unsubscribe = h.controller.subscribe(() => { renders += 1; });
  const intent = h.controller.prepare(); assert.ok(intent);
  assert.equal(h.controller.submit(intent), false); h.controller.retire();
  assert.equal(h.controller.prepare(), null); assert.match(h.controller.startReason(), /original native operation/);
  assert.doesNotMatch(h.controller.startReason(), /PRIVATE/); assert.equal(h.submitted.length, 1);
  assert.equal(renders, 2); unsubscribe(); h.controller.retire(); assert.equal(renders, 2);
});
