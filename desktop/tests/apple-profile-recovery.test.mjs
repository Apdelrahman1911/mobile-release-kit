// Complete existing controller/protocol; inert API promises and historical
// comparison DATA only. No Apple, vault, native worker or real signing material.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { appleProvisioningContext, parseAppleProvisioningStatus } from '../src/appleProvisioningProtocol.ts';
import { APPLE_PROFILE_LIMITATIONS, appleProfileInputBase } from '../src/appleProfileSetup.ts';
import { appleProfileRecoveryCopy, parseAppleProfileRecoveryHistory } from '../src/appleProfileRecoverySelection.ts';

const copy = value => structuredClone(value);
const id = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'e'.repeat(32) });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const history = () => ({ schemaVersion: 1, scope: 'local-ios-profile-attempts', hiddenUnresolved: 0,
  attempts: [{ reference: id('a'), displayName: 'Earlier App 🧪', observedAt: '2026-10-19T12:34:56.123456+00:00',
    action: 'create-profile', provider: { kind: 'creation', status: 'unknown', reason: 'provider_outcome_unknown' },
    save: 'not-entered', nativeSettlement: 'pending', cancellationRequested: false, unresolved: true }] });
const project = () => ({ projectId: 'fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
  dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null });
function assets() {
  const scope = { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'provisioning' };
  return { mode: 'native', scope, contextCurrent: true, busy: null, updatingContext: false,
    observationFailed: false, blocked: false, originPending: false, entryGeneration: 1,
    status: { mode: 'encrypted', context: { revision: 3, projectId: 'fixture', ...scope },
      capability: { available: true, reason: 'none' },
      modes: { encrypted: { available: true, reason: 'none' }, session: { available: true, reason: 'none' } },
      persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, operation: null,
      assignments: ['asc-p8', 'apple-p12'].map((kind, i) => ({ kind, recordId: (i ? 'd' : 'c').repeat(32), recordRevision: 4,
        contextRevision: 3, availability: 'available' })),
      records: ['asc-p8', 'apple-p12'].map((kind, i) => ({ kind, recordId: (i ? 'd' : 'c').repeat(32), revision: 4,
        availability: 'assigned', storage: 'encrypted' })) } };
}
const result = mode => ({ schemaVersion: 1, scope: 'local-ios-profile-setup', mode, bundleId: 'example.fixture',
  decision: mode === 'profile-review' ? 'blocked' : 'comparison-only', reason: mode === 'profile-review' ? 'pending-setup' : 'inconclusive',
  profileResourceId: null, profileUuid: null, saved: false, credentialReady: false, cancellationRequested: false,
  limitations: [...APPLE_PROFILE_LIMITATIONS] });
const status = (revision = 1, operation = null) => ({ schemaVersion: 1, statusRevision: revision,
  availability: operation && operation.phase !== 'terminal' ? 'busy' : 'available', operation });
const operation = (request, digit = '1') => ({ ...id(digit), context: appleProvisioningContext(copy(request)),
  phase: 'awaiting-consent', intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const complete = (op, rows) => ({ ...copy(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none',
  result: result(op.context.mode), ...(rows === undefined ? {} : { profileRecovery: copy(rows) }) });

function harness(t, initial = status()) {
  let p = project(), a = assets(), native = initial, receiver = null, peer = null;
  const calls = [], readQueue = [];
  const call = (kind, request) => { const row = { kind, request: copy(request), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native', subscribe: async fn => { receiver = fn; return () => { receiver = null; }; },
    status: () => readQueue.shift()?.promise ?? Promise.resolve(copy(native)),
    prepare: value => call('prepare', value), start: value => call('start', value), cancel: value => call('cancel', value) };
  const controller = new AppleProvisioningController({ project: () => p, assets: () => a, otherOperationReason: () => peer, now: () => 100 });
  controller.setVisible(true); controller.setDisplayName('Current review name');
  const ready = controller.connect(api); t.after(() => controller.dispose());
  return { controller, api, ready, calls, readQueue,
    get state() { return controller.getSnapshot(); }, get native() { return copy(native); },
    reply(row, value) { native = copy(value); row.resolve(copy(value)); },
    emit(value) { native = copy(value); receiver?.(copy(value)); },
    project(patch) { p = { ...p, ...patch }; controller.syncProject(); },
    assets(value) { a = value; controller.syncProject(); },
    peer(value) { peer = value; controller.syncProject(); } };
}
async function startReview(h) {
  await h.ready; const prepare = h.controller.prepare('profile-review'), call = h.calls.at(-1);
  assert.equal(call.kind, 'prepare'); const op = operation(call.request);
  h.reply(call, status(2, op)); await prepare;
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration);
  return { op, work, call: h.calls.at(-1) };
}
async function reviewed(h, rows = history()) {
  const started = await startReview(h); h.reply(started.call, status(3, complete(started.op, rows))); await started.work;
  assert.ok(h.state.previousProfileAttempts); assert.equal(h.state.profileReviewReference, null);
  return started;
}

test('profile history codec preserves independent axes, joint bounds and privacy without getter execution', () => {
  const original = history(); assert.ok(parseAppleProfileRecoveryHistory(original));
  assert.match(appleProfileRecoveryCopy(original.attempts[0]).detail, /will not clear/);
  for (const change of [{ nativeSettlement: 'known', unresolved: false }, { save: 'saved' }, { action: 'reuse-download' },
    { retryAllowed: true }, { sourceKey: 'not-public' }, { destination: {} }, { savedReference: {} }, { profileContent: 'not-public' },
    { displayName: '' }, { displayName: 'a'.repeat(129) }, { observedAt: '2026-02-30T00:00:00+00:00' },
    { observedAt: '2026-10-19T12:34:56.000000+00:00' }, { reference: id('0') }]) {
    const bad = history(); Object.assign(bad.attempts[0], change); assert.equal(parseAppleProfileRecoveryHistory(bad), null);
  }
  for (const change of [{ hiddenUnresolved: -1 }, { hiddenUnresolved: 32 }, { accountRef: 'not-public' },
    { scope: 'local-ios-bundle-attempts' }, { schemaVersion: 2 }]) assert.equal(parseAppleProfileRecoveryHistory({ ...original, ...change }), null);
  const duplicate = history(); duplicate.attempts.push(copy(duplicate.attempts[0])); assert.equal(parseAppleProfileRecoveryHistory(duplicate), null);
  const full = history(); full.attempts = Array.from({ length: 32 }, (_, index) => ({ ...copy(original.attempts[0]),
    reference: { ...id('a'), operationId: (index + 1).toString(16).padStart(32, '0') }, displayName: '🧪'.repeat(128),
    provider: { kind: 'creation', status: 'cancellation_requested', reason: 'authorization_changed_after_send' } }));
  assert.equal(parseAppleProfileRecoveryHistory(full)?.attempts.length, 32);
  assert.ok(new TextEncoder().encode(JSON.stringify(full)).length < 32768);
  full.attempts.push(copy(original.attempts[0])); assert.equal(parseAppleProfileRecoveryHistory(full), null);
  let invoked = false; const getter = history();
  Object.defineProperty(getter.attempts[0], 'provider', { enumerable: true, get() { invoked = true; return original.attempts[0].provider; } });
  assert.equal(parseAppleProfileRecoveryHistory(getter), null); assert.equal(invoked, false);
  for (const save of ['not-entered', 'armed', 'written', 'read-back', 'unknown']) {
    const row = { ...original.attempts[0], action: 'reuse-download', provider: { kind: 'download-returned' },
      nativeSettlement: 'known', save, unresolved: ['armed', 'written', 'unknown'].includes(save) };
    assert.ok(parseAppleProfileRecoveryHistory({ ...original, attempts: [row] }));
  }
});

test('only an exact complete profile review can carry history; unresolved rows cannot grant a save choice', () => {
  const request = { ...appleProfileInputBase(project(), assets()), mode: 'profile-review', reference: null,
    newApplication: false, displayName: 'Current review name' };
  const op = complete(operation(request), history()); assert.ok(parseAppleProvisioningStatus(status(3, op)));
  for (const value of [null, undefined, { ...history(), attempts: [{ ...history().attempts[0], unresolved: false }] }]) {
    assert.equal(parseAppleProvisioningStatus(status(3, { ...op, profileRecovery: value })), null);
  }
  assert.equal(parseAppleProvisioningStatus(status(3, { ...op, phase: 'running', outcome: null })), null);
  for (const [decision, reason] of [['reuse-available', 'reuse-existing-profile'], ['create-available', 'profile-create-review']]) {
    assert.equal(parseAppleProvisioningStatus(status(3, { ...op, result: { ...op.result, decision, reason } })), null);
  }
  const reconcile = complete(operation({ ...request, mode: 'profile-reconcile', reference: id('a') }), history());
  assert.equal(parseAppleProvisioningStatus(status(4, reconcile)), null);
});

test('new controller requires a fresh joined review and explicit historical selection plus GET-only Start', async t => {
  const request = { ...appleProfileInputBase(project(), assets()), mode: 'profile-review', reference: null,
    newApplication: false, displayName: 'Current review name' };
  const h = harness(t, status(1, complete(operation(request, 'b'), history()))); await h.ready;
  assert.equal(h.state.previousProfileAttempts, null); assert.equal(h.calls.length, 0);
  const rows = history(); rows.attempts[0].provider = { kind: 'creation', status: 'succeeded', reason: 'provider_resource_confirmed' };
  rows.attempts[0].save = 'read-back'; // Historical save is NOT current savedProfile evidence.
  await reviewed(h, rows); assert.equal(h.state.profileAttemptReference, null); assert.equal(h.state.savedProfile, null);
  const work = h.controller.continuePreviousProfile(...Object.values(id('a'))), call = h.calls.at(-1);
  assert.equal(call.kind, 'prepare'); assert.equal(call.request.mode, 'profile-reconcile');
  assert.equal(call.request.newApplication, false); assert.deepEqual(call.request.reference, id('a'));
  assert.equal(call.request.displayName, 'Earlier App 🧪'); assert.equal(call.request.p12RecordId, 'd'.repeat(32));
  assert.equal(call.request.recordId, 'c'.repeat(32)); assert.equal(h.calls.length, 3);
  await h.controller.continuePreviousProfile(...Object.values(id('a'))); assert.equal(h.calls.length, 3);
  const op = operation(call.request, '2'); h.reply(call, status(4, op)); await work;
  assert.equal(h.state.consent.acknowledged, false);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.length, 3);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const check = h.controller.start(op.operationId, op.ownerGeneration), start = h.calls.at(-1);
  assert.equal(start.request.consentVersion, 'local-ios-profile-reconcile-v1');
  h.reply(start, status(5, complete(op))); await check;
  assert.equal(h.state.savedProfile, null); assert.equal(h.state.profileReviewReference, null);
  assert.equal(h.state.profileResult.decision, 'comparison-only');
  await h.controller.prepare('profile-create'); await h.controller.prepare('profile-reuse'); assert.equal(h.calls.length, 4);
});

test('original terminal event cannot expose previous profiles before the invoke and post-invoke read join', async t => {
  const h = harness(t), { op, work, call } = await startReview(h);
  h.emit(status(4, complete(op, history()))); assert.equal(h.state.previousProfileAttempts, null);
  await h.controller.continuePreviousProfile(...Object.values(id('a'))); assert.equal(h.calls.length, 2);
  const read = deferred(); h.readQueue.push(read);
  call.resolve(status(3, { ...op, phase: 'running', intentUsable: false })); await flush();
  assert.equal(h.state.previousProfileAttempts, null); assert.ok(h.state.retained);
  read.resolve(status(4, complete(op, history()))); await work;
  assert.equal(h.state.previousProfileAttempts.attempts.length, 1); assert.equal(h.state.retained, false);
});

test('synchronous draft edits at every selection publication veto Prepare without losing the newer draft', async t => {
  for (const publication of [1, 2, 3, 4]) {
    const h = harness(t); await reviewed(h); let count = 0;
    const off = h.controller.subscribe(() => { if (++count === publication) h.controller.setDisplayName('Newer user draft'); });
    await h.controller.continuePreviousProfile(...Object.values(id('a'))); off();
    assert.equal(h.calls.length, 2, `publication ${publication}`);
    assert.equal(h.state.displayName, 'Newer user draft'); assert.equal(h.state.consent, null);
    assert.equal(h.state.profileAttemptReference, null); assert.equal(h.state.profileReviewReference, null);
  }
});

test('P12, saved observation, account/API or peer changes cannot select stale or ABA history', async t => {
  for (const change of ['p12', 'entry', 'saved', 'dirty', 'api', 'peer']) {
    const h = harness(t); await reviewed(h);
    if (change === 'p12' || change === 'entry') {
      const a = assets(); if (change === 'p12') { a.status.assignments[1].recordRevision++; a.status.records[1].revision++; }
      else a.entryGeneration++;
      h.assets(a); h.assets(assets());
    } else if (change === 'saved') { h.project({ observationGeneration: 4 }); h.project({ observationGeneration: 3 }); }
    else if (change === 'dirty') h.project({ dirtyDraft: true });
    else if (change === 'api') await h.controller.connect({ ...h.api });
    else h.peer('A different original operation is retained.');
    await h.controller.continuePreviousProfile(...Object.values(id('a')));
    assert.equal(h.calls.length, 2, change); assert.equal(h.state.profileAttemptReference, null);
  }
});

test('withdrawn history cannot be replaced; lost original acknowledgement stays unknown and never retries', async t => {
  const h = harness(t), { op } = await reviewed(h), withdrawn = complete(op);
  h.emit(status(4, withdrawn)); assert.equal(h.state.issue, null); assert.equal(h.state.previousProfileAttempts, null);
  h.emit(status(5, complete(op, history()))); assert.equal(h.state.issue, 'protocol'); assert.equal(h.state.previousProfileAttempts, null);
  const lost = harness(t), started = await startReview(lost);
  started.call.reject(new Error('INERT-PRIVATE-ERROR-NOT-OUTPUT')); await flush();
  const cancel = lost.calls.at(-1); assert.equal(cancel.kind, 'cancel');
  lost.reply(cancel, status(4, { ...started.op, phase: 'terminal', outcome: 'cancelled', reason: 'cancelled', intentUsable: false }));
  await flush(); await started.work;
  assert.ok(lost.state.issue); assert.ok(lost.state.retained); assert.equal(lost.state.previousProfileAttempts, null);
  await lost.controller.prepare('profile-review'); await lost.controller.continuePreviousProfile(...Object.values(id('a')));
  assert.equal(lost.calls.length, 3); assert.equal(JSON.stringify(lost.state).includes('INERT-PRIVATE-ERROR'), false);
});
