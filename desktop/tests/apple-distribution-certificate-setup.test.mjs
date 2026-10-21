// Complete existing controller/RAW adapter with inert comparison DATA/Promises.
// No key, CSR, certificate bytes, filesystem, native owner or Apple account.
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppleProvisioningController } from '../src/appleProvisioningController.ts';
import { createAppleProvisioningApi } from '../src/appleProvisioningNative.ts';
import { appleProvisioningContext, appleProvisioningConsent, appleProvisioningProgress, parseAppleProvisioningRequest,
  parseAppleProvisioningStatus, encodeAppleProvisioningRequest } from '../src/appleProvisioningProtocol.ts';
import { appleCertificateKeyChoices, appleDistributionCertificateInputBase, retainedAppleDistributionCertificateInput,
  parseAppleDistributionCertificateResult, parseAppleCertificateRecoveryHistory, appleDistributionCertificateCopy,
  appleCertificateRecoveryCopy } from '../src/appleDistributionCertificateSetupProtocol.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';

const clone = value => structuredClone(value);
const id = digit => ({ operationId: digit.repeat(32), ownerGeneration: 'f'.repeat(32) });
const key = () => ({ recordId: 'd'.repeat(32), recordRevision: 1 });
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 40; i++) await Promise.resolve(); };
const project = () => ({ projectId: '_certificate_fixture', draftRevision: 1, baselineGeneration: 2, observationGeneration: 3,
  savedConfig: { bytes: 100, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'b'.repeat(64), name: '1.2.3', build: 4 },
  dirtyDraft: false, snapshotPending: false, versionPending: false, saveRecoveryRequired: false, inputIssue: null });
function assets() {
  const scope = { executionMode: 'local', platform: 'ios', stage: 'candidate', purpose: 'provisioning' };
  return { mode: 'native', scope, contextCurrent: true, busy: null, updatingContext: false, observationFailed: false,
    blocked: false, originPending: false, entryGeneration: 1,
    status: { schemaVersion: 3, statusRevision: 1, mode: 'encrypted',
      persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { available: true, reason: 'none' },
      modes: { encrypted: { available: true, reason: 'none' }, session: { available: true, reason: 'none' } }, operation: null,
      context: { revision: 3, projectId: '_certificate_fixture', ...scope },
      assignments: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), recordRevision: 4, contextRevision: 3, availability: 'available' }],
      records: [{ kind: 'asc-p8', recordId: 'c'.repeat(32), revision: 4, availability: 'assigned', storage: 'encrypted', label: null, payloadState: 'assessed' },
        { kind: 'apple-distribution-key', recordId: key().recordId, revision: 1, availability: 'unassigned', storage: 'encrypted', label: null, payloadState: 'not-checked' }] } };
}
const request = (mode = 'certificate-review', reference = mode === 'certificate-review' ? null : id('1')) => ({
  ...appleDistributionCertificateInputBase(project(), assets(), key()), mode, reference, newApplication: false, displayName: 'Fixture App',
});
const status = (revision = 1, operation = null, availability = operation && operation.phase !== 'terminal' ? 'busy' : 'available') =>
  ({ schemaVersion: 1, statusRevision: revision, availability, operation });
const operation = (input, digit = '1') => ({ ...id(digit), context: appleProvisioningContext(clone(input)), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const summary = (digit = '2', state = 'succeeded', reason = 'provider_resource_confirmed') => ({ ...id(digit),
  action: 'create_certificate', status: state, reason, retryAllowed: false, credentialReady: false, cancellationRequested: false });
function attempt(digit = '2', state = 'succeeded', reason = 'provider_resource_confirmed') {
  const { ownerGeneration: _notInSummary, ...value } = summary(digit, state, reason); return value;
}
const result = (mode = 'certificate-review', decision = 'request-review', reason = 'certificate-required', change = {}) => ({
  schemaVersion: 1, scope: 'local-ios-distribution-certificate', mode, decision, reason, certificateId: null, attempt: null, comparison: null,
  p12Saved: false, profileSaved: false, credentialReady: false, revocationChecked: false, ...change,
});
const complete = (op, value = result(op.context.mode)) => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'complete', reason: 'none', result: value });
const cancelled = op => ({ ...clone(op), phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason: 'cancelled', result: null });
const unknown = op => ({ ...clone(op), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', result: null });
const history = () => ({ schemaVersion: 1, scope: 'local-ios-certificate-attempts', hiddenUnresolved: 0,
  attempts: [{ reference: id('9'), displayName: 'Earlier Fixture Name', observedAt: '2026-10-20T08:00:00+00:00', status: 'unknown',
    reason: 'provider_outcome_unknown', nativeSettlement: 'known', cancellationRequested: false, certificateId: '_observed-1' }] });
function usingKey(value = assets()) {
  const a = clone(value); a.contextCurrent = false; a.busy = 'use-apple-distribution-key';
  a.status.operation = { operationId: 5, operation: 'use-apple-distribution-key', phase: 'admitting', reason: 'none', source: 'captured',
    settlement: 'pending', storageOutcome: null, selectionToken: null, assessment: null, preview: null };
  for (const row of a.status.assignments) row.availability = 'unavailable';
  return a;
}
function harness(t) {
  let p = project(), a = assets(), native = status(), now = 100, peer = null;
  const calls = [], reads = [], listeners = [];
  const call = (kind, value) => { const row = { kind, request: clone(value), ...deferred() }; calls.push(row); return row.promise; };
  const api = { mode: 'native', subscribe: async receive => { const row = { receive, closed: false }; listeners.push(row); return () => { row.closed = true; }; },
    status: () => reads.shift()?.promise ?? Promise.resolve(clone(native)),
    prepare: value => call('prepare', value), start: value => call('start', value), cancel: value => call('cancel', value) };
  const controller = new AppleProvisioningController({ project: () => p, assets: () => a, otherOperationReason: () => peer, now: () => now });
  controller.setVisible(true); controller.setDisplayName('Fixture App');
  const ready = controller.connect(api); t.after(() => controller.dispose());
  return { controller, api, ready, calls, reads, listeners,
    get state() { return controller.getSnapshot(); }, get assets() { return clone(a); }, get project() { return clone(p); },
    select() { controller.selectCertificateKey(key().recordId, key().recordRevision); },
    reply(row, value) { native = clone(value); row.resolve(clone(value)); },
    emit(value) { native = clone(value); for (const row of listeners) if (!row.closed) row.receive(clone(value)); },
    replaceAssets(value, notify = true) { a = value; if (notify) controller.syncProject(); },
    replaceProject(value, notify = true) { p = value; if (notify) controller.syncProject(); },
    peer(value) { peer = value; }, time(value) { now = value; } };
}
async function prepared(h, mode = 'certificate-review', digit = '1', revision = 2) {
  await h.ready; const count = h.calls.length, work = h.controller.prepare(mode), call = h.calls.at(-1);
  assert.equal(h.calls.length, count + 1); assert.equal(call.kind, 'prepare'); const op = operation(call.request, digit);
  h.reply(call, status(revision, op)); await work;
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false); return op;
}
async function started(h, op, value, revision) {
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration); h.reply(h.calls.at(-1), status(revision, value)); await work;
}
async function reviewed(h, value = result(), extra = {}) {
  await h.ready; h.select(); const op = await prepared(h);
  await started(h, op, { ...complete(op, value), ...extra }, 3); return op;
}

test('certificate modes use the same RAW4 with exact current key selection, no P12/private bytes or implicit authorization', async () => {
  const calls = [], events = [];
  const api = createAppleProvisioningApi('native', async (command, bytes) => { calls.push([command, JSON.parse(new TextDecoder().decode(bytes))]); return status(); },
    async event => { events.push(event); return () => {}; });
  assert.equal(createAppleProvisioningApi('preview', () => { throw Error('must not invoke'); }), null);
  for (const mode of ['certificate-review', 'certificate-create', 'certificate-reconcile']) {
    const r = request(mode); assert.ok(parseAppleProvisioningRequest(r)); assert.equal(appleProvisioningConsent(mode), `local-ios-${mode}-v1`);
    await api.prepare(r); await api.start({ ...id('1'), consentVersion: appleProvisioningConsent(mode) });
    for (const field of ['privateKey', 'csr', 'der', 'token', 'fullRef', 'nativeJoined', 'savedKey', 'p12RecordId', 'p12RecordRevision']) {
      assert.equal(parseAppleProvisioningRequest({ ...r, [field]: 'not-authority' }), null);
    }
    for (const change of [{ keyRecordId: '0'.repeat(32) }, { keyRecordId: r.recordId }, { keyRecordRevision: 0 },
      { keyRecordRevision: 0xffffffff }, { keyRecordRevision: undefined }, { newApplication: true }, { platform: 'android' }]) {
      assert.equal(parseAppleProvisioningRequest({ ...r, ...change }), null);
    }
  }
  assert.equal(parseAppleProvisioningRequest({ ...request(), reference: id('1') }), null);
  assert.equal(parseAppleProvisioningRequest({ ...request('certificate-create'), reference: null }), null);
  assert.equal(parseAppleProvisioningRequest({ ...request('certificate-reconcile'), reference: id('0') }), null);
  assert.equal(encodeAppleProvisioningRequest('start_apple_provisioning', { ...id('1'), consentVersion: 'local-ios-key-recover-v1' }), null);
  await api.status(); await api.cancel(id('1')); (await api.subscribe(() => {}))();
  assert.deepEqual([...new Set(calls.map(([command]) => command))].sort(),
    ['apple_provisioning_status', 'cancel_apple_provisioning', 'prepare_apple_provisioning', 'start_apple_provisioning'].sort());
  assert.deepEqual(events, ['apple-bundle-provisioning-state-changed']);
});

test('strict result pairs preserve provider/old-attempt facts without P12, native-join or trust promotion', () => {
  const parse = v => parseAppleDistributionCertificateResult(v, v.mode, id('2').operationId, id('9'));
  assert.ok(parse(result()));
  assert.ok(parse(result('certificate-review', 'reuse', 'existing-certificate', { certificateId: '_a-' })));
  for (const reason of ['account-pending', 'inventory-unavailable', 'key-history-unavailable', 'policy-unavailable', 'existing-certificate-needs-key', 'bundle-registration-required']) {
    assert.ok(parse(result('certificate-review', 'blocked', reason)));
  }
  const confirmed = result('certificate-create', 'request-confirmed', 'certificate-confirmed', { certificateId: 'a'.repeat(128), attempt: attempt() });
  assert.ok(parse(confirmed));
  for (const change of [{ certificateId: null }, { certificateId: 'a'.repeat(129) }, { certificateId: 'bad:id' }, { p12Saved: true },
    { profileSaved: true }, { credentialReady: true }, { revocationChecked: true }, { nativeJoined: true },
    { attempt: { ...attempt(), operationId: id('1').operationId } }, { attempt: { ...attempt(), cancellationRequested: true } },
    { attempt: { ...attempt(), reason: 'readback_required' } }]) assert.equal(parse({ ...confirmed, ...change }), null);
  const refused = result('certificate-create', 'request-unconfirmed', 'provider-rejected', { attempt: attempt('2', 'failed', 'provider_rejected_request') });
  assert.ok(parse(refused)); assert.equal(parse({ ...refused, certificateId: 'not-a-receipt' }), null);
  assert.equal(parse(result('certificate-create', 'request-unconfirmed', 'provider-outcome-unconfirmed', { attempt: attempt() })), null);
  assert.equal(parse(result('certificate-create')), null); assert.equal(parse({ ...confirmed, mode: 'certificate-review' }), null);
  for (const comparison of ['same-response', 'different-response', 'unattributed', 'not-returned', 'inconclusive']) {
    const v = result('certificate-reconcile', 'comparison-only', 'comparison-only', { comparison,
      certificateId: ['not-returned', 'inconclusive'].includes(comparison) ? null : '_receipt', attempt: attempt('9', 'unknown', 'provider_outcome_unknown') });
    assert.ok(parse(v)); assert.equal(parse({ ...v, attempt: attempt('2') }), null); assert.equal(parse({ ...v, attempt: null }), null);
  }
  let reads = 0; const getter = result(); Object.defineProperty(getter, 'decision', { enumerable: true, get() { reads++; return 'request-review'; } });
  assert.equal(parseAppleDistributionCertificateResult(getter, 'certificate-review', id('1').operationId, null), null); assert.equal(reads, 0);
  assert.match(appleDistributionCertificateCopy(confirmed, 'complete').detail, /No P12/);
  assert.match(appleDistributionCertificateCopy(refused, 'complete').detail, /Do not repeat/);
});

test('history is bounded joint-census DATA on a joined review; advanced status may withdraw but never replace it', () => {
  const recorded = history(); assert.ok(parseAppleCertificateRecoveryHistory(recorded));
  for (const changed of [{ ...recorded, hiddenUnresolved: 32 }, { ...recorded, attempts: [...recorded.attempts, clone(recorded.attempts[0])] },
    { ...recorded, extra: true }, { ...recorded, attempts: [{ ...recorded.attempts[0], nativeJoined: true }] }]) {
    assert.equal(parseAppleCertificateRecoveryHistory(changed), null);
  }
  const op = operation(request()), done = { ...complete(op, result('certificate-review', 'blocked', 'account-pending')), certificateRecovery: recorded };
  assert.ok(parseAppleProvisioningStatus(status(3, done)));
  for (const changed of [{ ...done, result: result() }, { ...done, phase: 'running', outcome: null },
    { ...done, outcome: 'failed', reason: 'command-incomplete' }, { ...done, savedKey: {} },
    { ...done, context: appleProvisioningContext(request('certificate-create')) }]) assert.equal(parseAppleProvisioningStatus(status(4, changed)), null);
  const withdrawn = clone(done); delete withdrawn.certificateRecovery;
  assert.equal(appleProvisioningProgress(done, withdrawn), true); assert.equal(appleProvisioningProgress(withdrawn, done), false);
  const modified = clone(done); modified.certificateRecovery.attempts[0].status = 'succeeded';
  assert.equal(appleProvisioningProgress(done, modified), false);
  assert.match(appleCertificateRecoveryCopy({ ...recorded.attempts[0], nativeSettlement: 'unknown' }), /will not clear/);
});

test('only a current explicit encrypted key selection combines with saved P8 input; retained use-key is correlation only', () => {
  assert.ok(parseAssetStatus(assets().status)); assert.deepEqual(appleCertificateKeyChoices(project(), assets()), [key()]);
  const base = appleDistributionCertificateInputBase(project(), assets(), key()); assert.ok(base);
  assert.equal(appleDistributionCertificateInputBase(project(), assets(), null), null);
  for (const change of ['missing', 'changed-key', 'duplicate', 'session', 'assigned-key', 'dirty', 'store', 'foreign', 'p8-revision', 'busy', 'locked']) {
    const p = project(), a = assets();
    if (change === 'missing') a.status.records.pop();
    if (change === 'changed-key') a.status.records[1].revision++;
    if (change === 'duplicate') a.status.records.push(clone(a.status.records[1]));
    if (change === 'session') a.status.records[1].storage = 'session';
    if (change === 'assigned-key') a.status.records[1].availability = 'assigned';
    if (change === 'dirty') p.dirtyDraft = true;
    if (change === 'store') { a.scope.purpose = 'store'; a.status.context.purpose = 'store'; }
    if (change === 'foreign') p.projectId = 'foreign';
    if (change === 'p8-revision') a.status.assignments[0].recordRevision++;
    if (change === 'busy') a.busy = 'prepare';
    if (change === 'locked') a.status.persistence.state = 'locked';
    assert.equal(appleDistributionCertificateInputBase(p, a, key()), null, change);
  }
  const using = usingKey(); assert.ok(parseAssetStatus(using.status));
  assert.equal(appleDistributionCertificateInputBase(project(), using, key()), null);
  assert.deepEqual(retainedAppleDistributionCertificateInput(project(), using, key(), base), base);
  for (const change of ['other-operation', 'unknown', 'different-key', 'p8', 'context']) {
    const bad = clone(using);
    if (change === 'other-operation') bad.status.operation.operation = 'prepare-apple-distribution-key';
    if (change === 'unknown') bad.status.operation.settlement = 'unknown';
    if (change === 'different-key') bad.status.records[1].revision++;
    if (change === 'p8') { bad.status.assignments[0].recordRevision++; bad.status.records[0].revision++; }
    if (change === 'context') bad.status.context.revision++;
    assert.equal(retainedAppleDistributionCertificateInput(project(), bad, key(), base), null, change);
  }
});

test('no auto-selection or issuance; only the same joined fresh review reaches separate one-use request consent', async t => {
  const h = harness(t); await h.ready; h.controller.syncProject(); h.controller.setVisible(false); h.controller.setVisible(true); await h.controller.checkStatus();
  assert.equal(h.calls.length, 0); assert.equal(h.state.certificateKeySelection, null);
  await h.controller.prepare('certificate-review'); assert.equal(h.calls.length, 0);
  h.select(); await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, 0);
  await reviewed(h); assert.deepEqual(h.state.certificateReviewReference, id('1'));
  const op = await prepared(h, 'certificate-create', '2', 4);
  assert.deepEqual(h.calls.at(-1).request.reference, id('1')); assert.equal(h.state.certificateReviewReference, null);
  await h.controller.start(op.operationId, op.ownerGeneration); assert.equal(h.calls.filter(row => row.kind === 'start').length, 1);
  const received = result('certificate-create', 'request-confirmed', 'certificate-confirmed', { certificateId: '_receipt', attempt: attempt() });
  await started(h, op, complete(op, received), 5);
  assert.equal(h.state.certificateResult.decision, 'request-confirmed'); assert.equal(h.state.certificateResult.p12Saved, false);
  const count = h.calls.length; await h.controller.start(op.operationId, op.ownerGeneration); await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, count);
});

test('reuse never authorizes issuance; original review age expires without refresh or input-change renewal', async t => {
  const h = harness(t); await reviewed(h, result('certificate-review', 'reuse', 'existing-certificate', { certificateId: '_existing' }));
  assert.equal(h.state.certificateReviewReference, null); const count = h.calls.length;
  await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, count);
  const next = await prepared(h, 'certificate-review', '3', 4); await started(h, next, complete(next), 5);
  assert.deepEqual(h.state.certificateReviewReference, id('3'));
  h.time(300101); await h.controller.checkStatus(); h.controller.syncProject();
  assert.equal(h.state.certificateReviewReference, null); await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, count + 2);
});

test('key/P8/source/name drift and API ABA retire consent without admitting another request', async t => {
  for (const change of ['key-revision', 'p8-revision', 'snapshot', 'entry', 'name', 'api']) {
    await t.test(change, async t => {
      const h = harness(t); await reviewed(h); const count = h.calls.length;
      if (change === 'key-revision') { const a = h.assets; a.status.records[1].revision++; h.replaceAssets(a); }
      if (change === 'p8-revision') { const a = h.assets; a.status.assignments[0].recordRevision++; a.status.records[0].revision++; h.replaceAssets(a); }
      if (change === 'snapshot') h.replaceProject({ ...h.project, observationGeneration: 9 });
      if (change === 'entry') h.replaceAssets({ ...h.assets, entryGeneration: 9 });
      if (change === 'name') h.controller.setDisplayName('Changed name');
      if (change === 'api') { h.controller.beginConnection(); await h.controller.connect(h.api); h.select(); }
      await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, count); assert.equal(h.state.certificateReviewReference, null);
    });
  }
});

test('synchronous subscribers cannot replace key selection or hand an old review to a new context', async t => {
  const h = harness(t); await h.ready;
  let fired = false; const off = h.controller.subscribe(() => {
    if (!fired) { fired = true; h.replaceProject({ ...h.project, observationGeneration: 7 }); }
  });
  h.select(); off(); assert.equal(h.state.certificateKeySelection, null);
  await reviewed(h); const count = h.calls.length;
  let changed = false; const off2 = h.controller.subscribe(() => {
    if (!changed) { changed = true; h.controller.setDisplayName('Reentrant name'); }
  });
  await h.controller.prepare('certificate-create'); off2();
  assert.equal(h.calls.length, count); assert.equal(h.state.certificateReviewReference, null);
});

test('terminal event before Start return cannot release the original or authorize a certificate request', async t => {
  const h = harness(t); await h.ready; h.select(); const op = await prepared(h);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), call = h.calls.at(-1);
  h.replaceAssets(usingKey(h.assets)); assert.equal(h.state.historical, false);
  h.emit(status(3, complete(op))); await h.controller.checkStatus();
  assert.equal(h.state.requestPending, true); assert.equal(h.state.certificateTerminalRead, false); assert.equal(h.state.certificateReviewReference, null);
  const count = h.calls.length; await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, count);
  // Real original return, then its own fresh status read: no event is a join.
  h.replaceAssets(assets()); h.reply(call, status(3, complete(op))); await work;
  assert.equal(h.state.requestPending, false); assert.equal(h.state.certificateTerminalRead, true); assert.deepEqual(h.state.certificateReviewReference, id('1'));
});

test('lost Create acknowledgement keeps original unknown and all new issuance disabled, even after late terminal DATA', async t => {
  const h = harness(t); await reviewed(h); const op = await prepared(h, 'certificate-create', '2', 4);
  h.controller.acknowledge(op.operationId, op.ownerGeneration, true);
  const work = h.controller.start(op.operationId, op.ownerGeneration), sent = h.calls.at(-1);
  h.emit(status(5, unknown(op))); sent.reject(Error('inert transport loss')); await flush();
  const stop = h.calls.findLast(row => row.kind === 'cancel'); if (stop) h.reply(stop, status(5, unknown(op)));
  await work; await flush();
  assert.equal(h.state.issue, 'cleanup-unknown'); assert.equal(h.state.retained, true); assert.equal(h.state.certificateReviewReference, null);
  const count = h.calls.length; await h.controller.prepare('certificate-create'); await h.controller.prepare('certificate-reconcile');
  assert.equal(h.calls.length, count); assert.equal(h.state.canRead, true);
  h.emit(status(6, complete(op, result('certificate-create', 'request-confirmed', 'certificate-confirmed', { certificateId: '_late', attempt: attempt() }))));
  assert.equal(h.state.retained, true); assert.equal(h.state.certificateResult, null);
});

test('known rejection or provider-unknown with native completion offers only a separate GET-only continuation, never reissue', async t => {
  for (const rejected of [true, false]) await t.test(rejected ? 'known rejection' : 'provider outcome unknown', async t => {
    const h = harness(t); await reviewed(h); const op = await prepared(h, 'certificate-create', '2', 4);
    const v = result('certificate-create', 'request-unconfirmed', rejected ? 'provider-rejected' : 'provider-outcome-unconfirmed', {
      certificateId: rejected ? null : '_receipt', attempt: attempt('2', rejected ? 'failed' : 'unknown', rejected ? 'provider_rejected_request' : 'provider_outcome_unknown'),
    });
    await started(h, op, complete(op, v), 5);
    assert.equal(h.state.issue, null); assert.equal(h.state.certificateResult.decision, 'request-unconfirmed');
    const count = h.calls.length; await h.controller.prepare('certificate-create'); assert.equal(h.calls.length, count);
    const check = await prepared(h, 'certificate-reconcile', '3', 6);
    assert.deepEqual(check.context.reference, id('2')); assert.equal(h.state.consent.acknowledged, false);
    assert.equal(h.calls.filter(row => row.kind === 'start').length, 2);
  });
});

test('fresh restart history selects exact earlier reference/name for read-only reconciliation, with no auto Start or restored review', async t => {
  const h = harness(t), recorded = history();
  await reviewed(h, result('certificate-review', 'blocked', 'account-pending'), { certificateRecovery: recorded });
  assert.deepEqual(clone(h.state.previousCertificateAttempts), recorded); assert.equal(h.state.certificateReviewReference, null);
  const starts = h.calls.filter(row => row.kind === 'start').length;
  const work = h.controller.continuePreviousCertificate(id('9').operationId, id('9').ownerGeneration), call = h.calls.at(-1);
  assert.equal(call.kind, 'prepare'); assert.equal(call.request.mode, 'certificate-reconcile'); assert.deepEqual(call.request.reference, id('9'));
  assert.equal(call.request.displayName, 'Earlier Fixture Name'); assert.equal(call.request.keyRecordId, key().recordId);
  const op = operation(call.request, '2'); h.reply(call, status(4, op)); await work;
  assert.equal(h.calls.filter(row => row.kind === 'start').length, starts); assert.equal(h.state.consent.acknowledged, false);
  assert.equal(h.state.certificateReviewReference, null);
  const v = result('certificate-reconcile', 'comparison-only', 'comparison-only', { certificateId: '_observed-1', comparison: 'same-response',
    attempt: attempt('9', 'unknown', 'provider_outcome_unknown') });
  await started(h, op, complete(op, v), 5);
  assert.equal(h.state.certificateResult.attempt.operationId, id('9').operationId); assert.equal(h.state.certificateResult.attempt.status, 'unknown');
});

test('restored encrypted record keeps its NEW selection while old request history offers only explicit read-only continuation', async t => {
  const h = harness(t), restoredId = 'e'.repeat(32), recorded = history();
  await h.ready;
  const current = h.assets; current.status.records[1].recordId = restoredId;
  h.replaceAssets(current); h.controller.selectCertificateKey(restoredId, 1);
  const review = await prepared(h);
  assert.equal(review.context.keyRecordId, restoredId);
  // Native supplied comparison DATA, not a mocked private key/binding. Its
  // original proof and cross-ref history filter are tested in their own seams.
  await started(h, review, { ...complete(review, result('certificate-review', 'blocked', 'account-pending')),
    certificateRecovery: recorded }, 3);
  const count = h.calls.length;
  const pending = h.controller.continuePreviousCertificate(id('9').operationId, id('9').ownerGeneration);
  const call = h.calls.at(-1);
  assert.equal(h.calls.length, count + 1); assert.equal(call.kind, 'prepare');
  assert.equal(call.request.mode, 'certificate-reconcile'); assert.equal(call.request.keyRecordId, restoredId);
  assert.deepEqual(call.request.reference, id('9'));
  const op = operation(call.request, '2'); h.reply(call, status(4, op)); await pending;
  assert.equal(h.state.consent.acknowledged, false); assert.equal(h.state.certificateReviewReference, null);
  const comparison = result('certificate-reconcile', 'comparison-only', 'comparison-only', {
    certificateId: '_observed-1', comparison: 'same-response', attempt: attempt('9', 'unknown', 'provider_outcome_unknown') });
  await started(h, op, complete(op, comparison), 5);
  assert.equal(h.state.certificateResult.attempt.status, 'unknown');
  assert.equal(h.state.certificateResult.attempt.retryAllowed, false);
  assert.equal(h.state.certificateResult.credentialReady, false);
  assert.ok(h.state.certificateCreateReason);
  assert.ok(h.calls.every(row => !['certificate-create', 'key-prepare', 'p12-save'].includes(row.request.mode)));
});

test('historical selection is refused after synchronous name/source drift or withdrawal, without overwriting the newer input', async t => {
  for (const change of ['reentrant-name', 'key-drift', 'withdrawal']) await t.test(change, async t => {
    const h = harness(t), recorded = history(); const op = await reviewed(h, result('certificate-review', 'blocked', 'account-pending'), { certificateRecovery: recorded });
    let off = () => {};
    if (change === 'reentrant-name') {
      let armed = false; off = h.controller.subscribe(() => {
        if (!armed && h.state.previousCertificateAttempts === null) { armed = true; h.controller.setDisplayName('Newer typed name'); }
      });
    }
    if (change === 'key-drift') { const a = h.assets; a.status.records[1].revision++; h.replaceAssets(a); }
    if (change === 'withdrawal') { h.emit(status(4, complete(op, result('certificate-review', 'blocked', 'account-pending')))); await flush(); }
    const count = h.calls.length; await h.controller.continuePreviousCertificate(id('9').operationId, id('9').ownerGeneration); off();
    assert.equal(h.calls.length, count); assert.equal(h.state.certificateReviewReference, null);
    if (change === 'reentrant-name') assert.equal(h.state.displayName, 'Newer typed name');
  });
});
