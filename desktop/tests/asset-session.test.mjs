// Inert contract/promise tests only. No native picker, secret file, browser,
// service, process fixture, storage, real credential or engine is accessed.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { AssetSessionController, assetCancellationReason, assetContextReason, assetImageOperationPending, assetIntentPending, assetSessionReason, assetStorageReason } from '../src/assetSessionController.ts';
import { ASSET_KINDS, SESSION_FIELDS, assetError, assetJsonFits, assetLabelFits, assetRequestFits, assetStorageWritable, isAssetFileKind, parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { sessionControlHelp, sessionKindHelp, sessionTargetLabel } from '../src/assetSessionHelp.ts';
import { preparationScopeChanged, preparationSessionReason } from '../src/releaseInputGuidance.ts';
import guide from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };

const A = 'a'.repeat(32);
const B = 'b'.repeat(32);
const C = 'c'.repeat(32);
const D = 'd'.repeat(32);
const context = { revision: 1, projectId: 'project-a', platform: 'android', stage: 'candidate', purpose: 'full' };
const fields = { provider: 'inert-provider-canary', serviceAccount: 'inert-account-canary' };
function status(revision = 0, patch = {}) {
  return { schemaVersion: 2, statusRevision: revision, persistence: null, mode: 'session', capability: { available: true, reason: 'none' },
    context: { ...context }, operation: null, records: [], assignments: [], ...patch };
}
function vaultStatus(revision = 0, patch = {}) {
  return status(revision, { mode: 'encrypted', persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, ...patch });
}
function vaultRecord(patch = {}) {
  return { recordId: C, revision: 1, kind: 'google-wif', availability: 'unassigned', storage: 'encrypted', label: null, payloadState: 'not-checked', ...patch };
}
function assessment() {
  return { schemaVersion: 1, policyVersion: 'credential-policy-v1', kind: 'google-wif',
    context: { platform: 'android', stage: 'candidate', purpose: 'full' }, applicability: { state: 'required', reason: 'selected' },
    state: 'configured', identity: 'not-applicable', fields: [
      { id: 'provider', requirement: 'MOBILE_RELEASE_GOOGLE_WIF_PROVIDER', presence: 'supplied', state: 'configured', issues: [], checks: [{ scope: 'identifier-format', outcome: 'passed' }] },
      { id: 'serviceAccount', requirement: 'MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT', presence: 'supplied', state: 'configured', issues: [], checks: [{ scope: 'identifier-format', outcome: 'passed' }] },
    ], assurance: { basis: 'supplied-input-only', scalarValuesProcessed: true, fileObservationsProcessed: false, selectedFilesRead: false,
      keyringAccessed: false, storageWritesPerformed: false, projectCodeExecuted: false, sourceCustody: 'not-established',
      nativeValidation: 'not-run', serviceValidation: 'not-run', releaseReadiness: 'unknown' } };
}
function operation(patch = {}) {
  return { operationId: 3, operation: 'prepare', phase: 'preview', reason: 'none', source: 'not-run', settlement: 'known', storageOutcome: null,
    selectionToken: null, assessment: assessment(), preview: { token: A, action: 'save', expiresInMs: 10000,
      subject: { type: 'record', kind: 'google-wif', change: 'new', recordId: null, recordRevision: null } }, ...patch };
}
function firebaseAssessment(kind = 'android-firebase') {
  const value = assessment();
  const ios = kind === 'ios-firebase';
  return { ...value, kind, context: { ...value.context, platform: ios ? 'ios' : 'android' }, state: 'format-valid', identity: 'match', fields: [
    { id: 'file', requirement: ios ? 'MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64' : 'MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64', presence: 'supplied', state: 'format-valid', issues: [],
      checks: [{ scope: ios ? 'plist-document' : 'json-document', outcome: 'asserted-pass' }, { scope: 'firebase-shape', outcome: 'asserted-pass' }, { scope: 'application-identity', outcome: 'asserted-pass' }] },
  ], assurance: { ...value.assurance, scalarValuesProcessed: false, fileObservationsProcessed: true } };
}
function appleAssessment(kind) {
  const value = assessment(), p12 = kind === 'apple-p12';
  if (kind === 'asc-p8') return { ...value, kind, context: { platform: 'ios', stage: 'candidate', purpose: 'full' }, fields: [
    { id: 'file', requirement: 'MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64', presence: 'supplied', state: 'configured', issues: [],
      checks: [{ scope: 'pkcs8-envelope', outcome: 'asserted-pass' }, { scope: 'ec-p256-identifiers', outcome: 'asserted-pass' }] },
    { id: 'keyId', requirement: 'MOBILE_RELEASE_ASC_KEY_ID', presence: 'supplied', state: 'configured', issues: [], checks: [{ scope: 'identifier-format', outcome: 'passed' }] },
    { id: 'issuerId', requirement: 'MOBILE_RELEASE_ASC_ISSUER_ID', presence: 'supplied', state: 'configured', issues: [], checks: [{ scope: 'identifier-format', outcome: 'passed' }] },
  ], assurance: { ...value.assurance, scalarValuesProcessed: true, fileObservationsProcessed: true } };
  return { ...value, kind, context: { platform: 'ios', stage: 'candidate', purpose: 'signing' }, state: 'configured', fields: [
    { id: 'file', requirement: p12 ? 'MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64' : 'MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64',
      presence: 'supplied', state: 'configured', issues: [], checks: [{ scope: p12 ? 'pfx-envelope' : 'cms-signed-data-envelope', outcome: 'asserted-pass' }] },
    ...(p12 ? [{ id: 'password', requirement: 'MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD', presence: 'supplied', state: 'configured', issues: [],
      checks: [{ scope: 'value-admission', outcome: 'passed' }] }] : []),
  ], assurance: { ...value.assurance, scalarValuesProcessed: p12, fileObservationsProcessed: true } };
}
function deferred() {
  let resolve; let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 10; i += 1) await Promise.resolve(); }
function harness(initial = status()) {
  let selected = { project: { id: 'project-a', name: 'Inert project', path: 'never-forwarded' }, draft: { schemaVersion: 1 }, revision: 1, baselineGeneration: 1 };
  let current = initial;
  let event;
  let time = 100;
  let unsubscribed = false;
  const calls = [];
  const pending = (command, args) => { const work = deferred(); calls.push({ command, args, ...work }); return work.promise; };
  const api = { mode: 'native', subscribeAssets: async (listener) => { calls.push({ command: 'listen' }); event = listener; return () => { unsubscribed = true; }; },
    assetStatus: async () => { calls.push({ command: 'status' }); return structuredClone(current); },
    setAssetContext: (input) => pending('context', input), openAssetSession: (mode = 'session') => pending('open', { mode }),
    prepareVaultInitialize: () => pending('initialize-review', {}), unlockVault: () => pending('unlock', {}),
    prepareCredential: (input) => pending('prepare', input), chooseAsset: (input) => pending('choose', input),
    prepareAssetDelete: (input) => pending('delete', input), commitAsset: (token) => pending('commit', token),
    bindAsset: (token) => pending('bind', token), discardAsset: (id) => pending('discard', id), lockAssetSession: () => pending('lock', {}),
  };
  const controller = new AssetSessionController(() => selected, () => time);
  return { api, controller, calls, selected: () => selected, latest: (command) => calls.filter((call) => call.command === command).at(-1),
    setProject: (value, sync = true) => { selected = value; if (sync) controller.syncProject(); },
    emit: (value) => { current = structuredClone(value); event(value); },
    time: (value) => { time = value; }, unsubscribed: () => unsubscribed };
}
async function ready(h, patch = {}) {
  await h.controller.connect(h.api);
  h.controller.submitContext(); await settle();
  h.latest('context').resolve(status(1, patch)); await settle();
  assert.equal(h.controller.getSnapshot().contextCurrent, true);
}
// Only the passive kind/scope projection consumed by the pure session guard.
// This does not fabricate an actionable hint: exact source/active/draft admission
// is exercised through the actual guidance controller in its own existing suite.
function preparationView(guideId = 'android-firebase', scope = { platform: 'android', stage: 'production', purpose: 'full' }) {
  return Object.freeze({ guideId, scope: Object.freeze({ ...scope }) });
}
const emptyPreparationLocal = { kindId: 'android-keystore', replacementId: null, confirmLock: false, writeOnlyFormMounted: false };
function assertPreparationPreservesOriginal(h) {
  const original = h.controller.getSnapshot(), count = h.calls.length;
  assert.notEqual(preparationSessionReason(preparationView(), original, emptyPreparationLocal), null);
  assert.equal(h.controller.getSnapshot(), original);
  assert.equal(h.controller.getSnapshot().intent, original.intent);
  assert.equal(h.controller.getSnapshot().previewDeadline, original.previewDeadline);
  assert.equal(h.controller.getSnapshot().entryGeneration, original.entryGeneration);
  assert.equal(h.calls.length, count);
}

test('status DTO detaches the provider and refuses raw material, extra authority and bad cross-links', () => {
  const input = status(2, { operation: operation() });
  const parsed = parseAssetStatus(input);
  assert.deepEqual(parsed, input);
  input.operation.assessment.fields[0].state = 'invalid';
  assert.equal(parsed.operation.assessment.fields[0].state, 'configured');
  for (const change of [
    (s) => { s.sourcePath = '/inert/no-read'; },
    (s) => { s.operation.assessment.fields[0].value = 'private-canary'; },
    (s) => { s.operation.assessment.assurance.nativeValidation = 'verified'; },
    (s) => { s.operation.assessment.context.stage = 'production'; },
    (s) => { s.operation.assessment = null; },
    (s) => { s.operation.preview.expiresInMs = 300001; },
    (s) => { delete s.operation.preview.subject; },
    (s) => { s.operation.preview.subject.recordId = A; },
    (s) => { s.operation.preview.subject.kind = 'project-read-token'; },
    (s) => { s.operation.settlement = 'unknown'; },
    (s) => { s.capability.reason = 'cleanup-unknown'; },
    (s) => { s.assignments = [{ kind: 'google-wif', recordId: A, recordRevision: 1, contextRevision: 1, availability: 'available' }]; },
  ]) { const s = status(2, { operation: operation() }); change(s); assert.equal(parseAssetStatus(s), null); }
  const lost = status(3, { capability: { available: false, reason: 'document-lost' }, context: null });
  assert.ok(parseAssetStatus(lost));
  lost.records = [{ recordId: C, revision: 0, kind: 'google-wif', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' }];
  assert.equal(parseAssetStatus(lost), null);
});

test('requests are exact, bounded unions; paths, bytes, observations and extra field roles cannot cross', () => {
  const request = { contextRevision: 1, source: { type: 'scalar', kind: 'google-wif', replacement: null }, fields: { ...fields } };
  assert.equal(assetRequestFits('credential_prepare', request), true);
  for (const change of [
    (r) => { r.path = '/inert'; }, (r) => { r.observation = { status: 'observed' }; },
    (r) => { r.fields.token = 'wrong-role'; }, (r) => { r.fields.provider = 'x'.repeat(4097); },
    (r) => { r.fields.provider = '\ud800'; }, (r) => { r.source.kind = 'asc-p8'; },
    (r) => { r.source.replacement = { recordId: 'unbound', expectedRevision: 1 }; },
  ]) { const changed = structuredClone(request); change(changed); assert.equal(assetRequestFits('credential_prepare', changed), false); }
  assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source: { type: 'record', recordId: A, expectedRevision: 0 }, fields: {} }), false);
  assert.equal(assetRequestFits('vault_lock', { discardSession: false }), false);
  assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind: 'android-keystore', replacement: null, filename: 'inert.jks' }), false);
  assert.equal(assetRequestFits('asset_context', { projectId: 'project-a', draft: {}, platform: 'android', stage: 'candidate', purpose: 'full' }), true);
  assert.equal(assetJsonFits({ value: '\u0000' }, 17), false); // Escaping is charged.
  const cycle = {}; cycle.self = cycle; assert.equal(assetJsonFits(cycle, 32768), false);
  assert.equal(assetJsonFits(new Array(1), 32768), false);
  let read = false;
  const accessor = []; Object.defineProperty(accessor, 0, { enumerable: true, get() { read = true; return null; } });
  assert.equal(assetJsonFits(accessor, 32768), false); assert.equal(read, false);
});

test('iOS Firebase and separately admitted Apple and ASC files extend only the exact closed session kinds', () => {
  assert.deepEqual(ASSET_KINDS, ['android-keystore', 'android-firebase', 'ios-firebase', 'apple-p12', 'apple-profile', 'asc-p8', 'google-wif', 'project-read-token']);
  assert.deepEqual(SESSION_FIELDS['ios-firebase'], []);
  for (const kind of ['android-keystore', 'android-firebase', 'ios-firebase', 'apple-p12', 'apple-profile', 'asc-p8']) {
    assert.equal(isAssetFileKind(kind), true);
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind, replacement: null }), true);
  }
  for (const kind of ['google-wif', 'project-read-token', 'IOS-Firebase', 'Apple-P12', 'ASC-P8']) {
    assert.equal(isAssetFileKind(kind), false);
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind, replacement: null }), false);
  }
  for (const extra of ['path', 'filename', 'bytes', 'observation', 'bundleId', 'encoding']) {
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind: 'ios-firebase', replacement: null, [extra]: 'PRIVATE_CANARY' }), false);
  }
  assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source: { type: 'scalar', kind: 'ios-firebase', replacement: null }, fields: {} }), false);
  const value = status(2, { context: { ...context, platform: 'ios' }, operation: operation({ source: 'captured', assessment: firebaseAssessment('ios-firebase'),
    preview: { token: A, action: 'save', expiresInMs: 10000, subject: { type: 'record', kind: 'ios-firebase', change: 'new', recordId: null, recordRevision: null } } }) });
  assert.deepEqual(parseAssetStatus(value), value);
  for (const mutate of [
    (s) => { s.operation.assessment.fields[0].requirement = 'MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64'; },
    (s) => { s.operation.assessment.fields.push({ ...s.operation.assessment.fields[0], id: 'keyPassword' }); },
    (s) => { s.operation.assessment.document = { bundleId: 'PRIVATE_CANARY' }; },
    (s) => { s.operation.assessment.fields[0].value = 'PRIVATE_CANARY'; },
    (s) => { s.operation.preview.subject.kind = 'apple-p12'; },
    (s) => { s.operation.assessment.assurance.serviceValidation = 'verified'; },
  ]) { const changed = structuredClone(value); mutate(changed); assert.equal(parseAssetStatus(changed), null); }
  assert.doesNotMatch(JSON.stringify(parseAssetStatus(value)), /PRIVATE_CANARY|bundleId/);
});

test('Apple selection password and assessment layouts stay exact, bounded and envelope-only', () => {
  assert.deepEqual(SESSION_FIELDS['apple-p12'], ['password']); assert.deepEqual(SESSION_FIELDS['apple-profile'], []);
  const request = { contextRevision: 1, source: { type: 'selection', selectionToken: A }, fields: { password: ' INERT_PASSWORD_CANARY\t' } };
  assert.equal(assetRequestFits('credential_prepare', request), true);
  for (const password of [null, '', 'é'.repeat(2048)]) assert.equal(assetRequestFits('credential_prepare', { ...request, fields: { password } }), true);
  for (const fields of [{ password: 1 }, { password: 'x'.repeat(4097) }, { password: 'é'.repeat(2049) }, { password: '\ud800' },
    { password: null, profile: null }, { privateKey: 'INERT_PASSWORD_CANARY' }])
    assert.equal(assetRequestFits('credential_prepare', { ...request, fields }), false);
  for (const kind of ['apple-p12', 'apple-profile']) {
    assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source: { type: 'scalar', kind, replacement: null }, fields: {} }), false);
    const value = status(2, { context: { ...context, platform: 'ios', purpose: 'signing' }, operation: operation({ source: 'captured', assessment: appleAssessment(kind),
      preview: { token: A, action: 'save', expiresInMs: 10000, subject: { type: 'record', kind, change: 'new', recordId: null, recordRevision: null } } }) });
    assert.deepEqual(parseAssetStatus(value), value);
    assert.equal(parseAssetStatus(value).operation.assessment.state, 'configured');
    for (const mutate of [
      (s) => { s.operation.assessment.fields[0].requirement = 'MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64'; },
      (s) => { s.operation.assessment.fields[0].value = 'INERT_PASSWORD_CANARY'; },
      (s) => { s.operation.assessment.fields.push({ ...s.operation.assessment.fields[0], id: 'keyPassword' }); },
      (s) => { s.operation.assessment.assurance.nativeValidation = 'verified'; },
      (s) => { s.operation.assessment.assurance.serviceValidation = 'verified'; },
      (s) => { s.operation.assessment.signerSha256 = 'e'.repeat(64); },
    ]) { const changed = structuredClone(value); mutate(changed); assert.equal(parseAssetStatus(changed), null); }
  }
});

test('ASC keeps exactly two nullable original companions and a fixed envelope-only assessment layout', () => {
  assert.deepEqual(SESSION_FIELDS['asc-p8'], ['keyId', 'issuerId']);
  const source = { type: 'selection', selectionToken: A };
  for (const [index, fields] of [
    { keyId: null, issuerId: null }, { keyId: '', issuerId: null },
    { keyId: ' INERT_ASC_KEY_CANARY\0é ', issuerId: 'MixedCase-Inert-UUID\t' },
    { keyId: 'é'.repeat(2048), issuerId: 'x'.repeat(4096) },
    // Transport admits bounded original bytes; the core reports value-nul.
    { keyId: '\0'.repeat(4096), issuerId: '\0'.repeat(4096) },
  ].entries()) assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source, fields }), true, `valid ASC wire fields case ${index}`);
  for (const [index, fields] of [
    { keyId: null }, { issuerId: null }, { keyId: null, issuerId: null, password: null },
    { keyId: 1, issuerId: null }, { keyId: null, issuerId: [] },
    { keyId: 'x'.repeat(4097), issuerId: null }, { keyId: null, issuerId: 'é'.repeat(2049) },
    { keyId: '\ud800', issuerId: null },
  ].entries()) assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source, fields }), false, `invalid ASC wire fields case ${index}`);
  const fields = { keyId: null, issuerId: null };
  assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source: { type: 'scalar', kind: 'asc-p8', replacement: null }, fields }), false);
  for (const extra of ['path', 'filename', 'bytes', 'privateKey', 'observation', 'algorithm', 'encoding']) {
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind: 'asc-p8', replacement: null, [extra]: 'INERT_ASC_KEY_CANARY' }), false);
    assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source: { ...source, [extra]: 'INERT_ASC_KEY_CANARY' }, fields }), false);
  }
  for (const stage of ['candidate', 'external-testing', 'production']) for (const purpose of ['full', 'store']) {
    const scope = { platform: 'ios', stage, purpose };
    const value = status(2, { context: { ...context, ...scope }, operation: operation({ source: 'captured',
      assessment: { ...appleAssessment('asc-p8'), context: scope },
      preview: { token: A, action: 'save', expiresInMs: 10000, subject: { type: 'record', kind: 'asc-p8', change: 'new', recordId: null, recordRevision: null } } }) });
    assert.deepEqual(parseAssetStatus(value), value); // DTO shape, not native profile qualification.
    for (const mutate of [
      (s) => { s.operation.assessment.fields.reverse(); },
      (s) => { s.operation.assessment.fields[1].requirement = 'MOBILE_RELEASE_ASC_ISSUER_ID'; },
      (s) => { s.operation.assessment.fields[1].value = 'INERT_ASC_KEY_CANARY'; },
      (s) => { s.operation.assessment.fields.push({ ...s.operation.assessment.fields[1], id: 'password' }); },
      (s) => { s.operation.assessment.privateKey = 'INERT_ASC_KEY_CANARY'; },
      (s) => { s.operation.assessment.assurance.nativeValidation = 'verified'; },
      (s) => { s.operation.assessment.assurance.serviceValidation = 'verified'; },
      (s) => { s.operation.preview.subject.kind = 'apple-p12'; },
    ]) { const changed = structuredClone(value); mutate(changed); assert.equal(parseAssetStatus(changed), null); }
    assert.doesNotMatch(JSON.stringify(parseAssetStatus(value)), /INERT_ASC_KEY_CANARY|privateKey/);
  }
});

test('bridge invokes only closed routes, copies admitted input, and removes raw error text', async () => {
  const work = deferred(); const calls = [];
  const api = createNativeApi('native', (command, args) => { calls.push({ command, args }); return work.promise; });
  const request = { contextRevision: 1, source: { type: 'scalar', kind: 'google-wif', replacement: null }, fields: { ...fields } };
  const response = api.prepareCredential(request);
  request.fields.provider = 'changed-after-handoff';
  assert.equal(calls[0].command, 'credential_prepare'); assert.deepEqual(calls[0].args.fields, fields);
  work.resolve(status(2, { operation: operation() })); await response;
  await assert.rejects(api.chooseAsset({ contextRevision: 1, kind: 'android-keystore', replacement: null, bytes: 'private-canary' }), (error) => error.code === 'asset_invalid_request');
  assert.equal(calls.length, 1);
  for (const code of ['asset_source_refused', 'assessment_context_stale', 'private-canary']) {
    const error = assetError({ code, message: 'private-canary native detail', retryable: true, path: '/inert/no-read' });
    assert.equal(JSON.stringify(error).includes('private-canary'), false); assert.equal(error.retryable, false);
  }
});

test('unqualified native and browser modes never collect input or fabricate a session status', async () => {
  const h = harness(status(0, { mode: 'closed', context: null, capability: { available: false, reason: 'unqualified' } }));
  try {
    await h.controller.connect(h.api);
    assert.deepEqual(h.calls.map((call) => call.command), ['listen', 'status']);
    assert.equal(h.controller.open(), false);
    assert.equal(h.controller.prepareScalar('google-wif', fields), false);
    assert.equal(h.controller.choose('android-keystore'), false);
    assert.equal(h.controller.choose('ios-firebase'), false);
    assert.equal(h.controller.choose('apple-p12'), false);
    assert.equal(h.controller.choose('apple-profile'), false);
    assert.equal(h.controller.choose('asc-p8'), false);
    assert.match(assetContextReason(h.controller.getSnapshot()), /qualification/u);
    await assert.rejects(previewApi.openAssetSession(), (error) => error.code === 'AssetSessionUnavailable');
    await assert.rejects(previewApi.prepareCredential({}), (error) => error.code === 'AssetSessionUnavailable');
  } finally { h.controller.dispose(); }
  assert.equal(h.unsubscribed(), true);
});

test('preparation refuses active or uncertain work and local replacement/private forms without treating completed intent as pending', async () => {
  const h = harness();
  try {
    await ready(h);
    const current = h.controller.getSnapshot(), count = h.calls.length, target = preparationView();
    assert.equal(preparationSessionReason(target, current, emptyPreparationLocal), null);
    const idle = operation({ phase: 'idle', settlement: 'known', assessment: null, preview: null });
    for (const [label, patch] of [
      ['native capability unavailable', { status: status(2, { capability: { available: false, reason: 'unqualified' } }) }],
      ['browser', { mode: 'preview' }],
      ['status observation', { observing: true }],
      ['unacknowledged original despite idle status', { originPending: true, status: status(2, { operation: idle }) }],
      ['unconfirmed intent', { observationFailed: true, intent: { type: 'record', kind: 'google-wif', change: 'new', record: null } }],
      ['project-path original', { status: status(2, { operation: operation({ operation: 'choose-project-path', phase: 'picking', settlement: 'pending', assessment: null, preview: null }) }) }],
      ['late-known original', { status: status(2, { operation: { ...idle, settlement: 'late-known' } }) }],
      ['selection', { status: status(2, { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) }) }],
      ['review', { status: status(2, { operation: operation() }), previewDeadline: 1000 }],
      ['cancellation', { cancelledOperationId: 3, status: status(2, { operation: operation({ phase: 'stopping', settlement: 'pending', assessment: null, preview: null }) }) }],
      ['record change', { status: status(2, { records: [{ recordId: D, revision: 7, kind: 'android-firebase', availability: 'mutation-pending', storage: 'session', label: null, payloadState: 'assessed' }] }) }],
    ]) assert.notEqual(preparationSessionReason(target, { ...current, ...patch }, emptyPreparationLocal), null, label);
    for (const patch of [{ replacementId: D }, { replacementId: 'no-longer-present' }, { confirmLock: true }, { writeOnlyFormMounted: true }]) {
      const local = Object.freeze({ ...emptyPreparationLocal, ...patch });
      assert.notEqual(preparationSessionReason(target, current, local), null);
      assert.deepEqual(local, { ...emptyPreparationLocal, ...patch });
    }
    assert.equal(preparationSessionReason(preparationView('asc-p8', { platform: 'ios', stage: 'candidate', purpose: 'full' }), current, emptyPreparationLocal), null);
    assert.match(preparationSessionReason(preparationView('unknown-credential'), current, emptyPreparationLocal), /reference guide only/);
    assert.equal(preparationSessionReason(target, current, emptyPreparationLocal, 'Other original work is pending.'), 'Other original work is pending.');
    const same = preparationView('google-wif', current.scope), form = { ...emptyPreparationLocal, kindId: 'google-wif', writeOnlyFormMounted: true };
    assert.equal(preparationScopeChanged(same, current.scope), false);
    assert.equal(preparationSessionReason(same, current, form), null); // focus only; no key/scope/form change
    assert.notEqual(preparationSessionReason(preparationView('project-read-token', current.scope), current, form), null);
    const completed = { ...current, originPending: false, intent: { type: 'record', kind: 'google-wif', change: 'assign', record: { recordId: C, expectedRevision: 1 } },
      cancelledOperationId: idle.operationId, selectionKind: 'android-firebase', status: status(2, { operation: idle }) };
    assert.equal(preparationSessionReason(same, completed, form), null); // residual completed intent/kind/cancel ID is not an original in flight
    assert.equal(h.controller.getSnapshot(), current); assert.equal(h.calls.length, count);
  } finally { h.controller.dispose(); }
});

test('an admitted changed preparation scope reuses one context submission; equal choices and closed sessions start nothing', async () => {
  const h = harness();
  try {
    await ready(h);
    const target = preparationView(), before = h.calls.length;
    assert.equal(preparationSessionReason(target, h.controller.getSnapshot(), emptyPreparationLocal), null);
    // This is the same guarded helper/setter seam as the reviewed UI handler,
    // not a React/native picker test. Its source wiring is checked separately.
    if (preparationScopeChanged(target, h.controller.getSnapshot().scope)) h.controller.setScope({ ...target.scope });
    await settle();
    assert.deepEqual(h.calls.slice(before).map((call) => call.command), ['context']);
    assert.deepEqual(h.latest('context').args, { projectId: 'project-a', draft: h.selected().draft, ...target.scope });
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    h.latest('context').resolve(status(2, { context: { ...context, ...target.scope, revision: 2 } })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
    const unchanged = h.controller.getSnapshot(), count = h.calls.length;
    assert.equal(preparationScopeChanged(target, unchanged.scope), false);
    if (preparationScopeChanged(target, unchanged.scope)) h.controller.setScope({ ...target.scope });
    assert.equal(h.controller.getSnapshot(), unchanged); assert.equal(h.calls.length, count);
  } finally { h.controller.dispose(); }
  const closed = harness(status(0, { mode: 'closed', context: null }));
  try {
    await closed.controller.connect(closed.api);
    const target = preparationView(), count = closed.calls.length;
    assert.equal(preparationSessionReason(target, closed.controller.getSnapshot(), emptyPreparationLocal), null);
    if (preparationScopeChanged(target, closed.controller.getSnapshot().scope)) closed.controller.setScope({ ...target.scope });
    await settle();
    assert.equal(closed.controller.getSnapshot().status.mode, 'closed'); assert.equal(closed.calls.length, count);
  } finally { closed.controller.dispose(); }
});

test('context edits invalidate immediately and coalesce while the original context reply is pending', async () => {
  const h = harness();
  try {
    await h.controller.connect(h.api);
    h.controller.submitContext(); await settle();
    const first = h.latest('context');
    h.setProject({ ...h.selected(), revision: 2, draft: { schemaVersion: 1, testRevision: 2 } });
    h.setProject({ ...h.selected(), revision: 3, draft: { schemaVersion: 1, testRevision: 3 } });
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    assert.equal(h.calls.filter((call) => call.command === 'context').length, 1);
    first.resolve(status(1)); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    const latest = h.latest('context'); assert.equal(latest.args.draft.testRevision, 3);
    latest.resolve(status(2, { context: { ...context, revision: 2 } })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
    assert.equal(h.calls.filter((call) => call.command === 'context').length, 2);
    let publishedStale = false;
    const stop = h.controller.subscribe(() => {
      const state = h.controller.getSnapshot();
      if (state.scope.stage === 'production' && state.contextCurrent) publishedStale = true;
    });
    h.controller.setScope({ platform: 'android', stage: 'production', purpose: 'full' });
    assert.equal(publishedStale, false); stop(); await settle();
    h.latest('context').resolve(status(3, { context: { ...context, revision: 3, stage: 'production' } })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
  } finally { h.controller.dispose(); }
});

test('late prior-context previews cannot authorize keep after a project/draft change', async () => {
  const h = harness();
  try {
    await ready(h);
    assert.equal(h.controller.prepareScalar('google-wif', { ...fields }), true);
    h.setProject({ ...h.selected(), revision: 2 });
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.calls.filter((call) => call.command === 'commit').length, 0);
    assert.equal(JSON.stringify(h.controller.getSnapshot()).includes('inert-provider-canary'), false);
  } finally { h.controller.dispose(); }
});

test('keep and assignment are separate one-use commands and do not renew the original review', async () => {
  const h = harness();
  try {
    await ready(h);
    assert.equal(h.controller.prepareScalar('google-wif', { ...fields }), true);
    assert.equal(Object.hasOwn(h.latest('prepare').args, 'label'), false, 'session requests retain their original exact shape');
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    assert.equal(h.controller.getSnapshot().previewDeadline, 10100);
    assert.equal(h.controller.confirmPreview(A, 'bind'), false);
    assert.equal(h.controller.confirmPreview(A, 'save'), true);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.controller.discard(), false); // Previous Prepare ID cannot cancel this new Commit.
    assert.match(assetCancellationReason(h.controller.getSnapshot()), /no cancellation has been sent/u);
    assert.equal(h.calls.filter((call) => call.command === 'discard').length, 0);
    h.time(5000);
    const kept = { recordId: C, revision: 1, kind: 'google-wif', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' };
    h.latest('commit').resolve(status(3, { records: [kept], operation: operation({ operationId: 4, operation: 'commit', preview: { token: B, action: 'bind', expiresInMs: 10000,
      subject: { type: 'record', kind: 'google-wif', change: 'assign', recordId: C, recordRevision: 1 } } }) })); await settle();
    assert.equal(h.controller.getSnapshot().previewDeadline, 10100);
    assert.deepEqual(h.controller.getSnapshot().status.assignments, []);
    assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
    assert.equal(h.controller.confirmPreview(B, 'bind'), true);
    assert.equal(h.controller.confirmPreview(B, 'bind'), false);
    h.latest('bind').resolve(status(4, { records: [{ ...kept, availability: 'assigned' }], operation: operation({ operationId: 5, operation: 'bind', phase: 'idle', preview: null, assessment: null }),
      assignments: [{ kind: 'google-wif', recordId: C, recordRevision: 1, contextRevision: 1, availability: 'available' }] })); await settle();
    assert.equal(h.controller.getSnapshot().status.assignments[0].availability, 'available');
    assert.equal(h.calls.filter((call) => call.command === 'commit').length, 1);
    assert.equal(h.calls.filter((call) => call.command === 'bind').length, 1);
  } finally { h.controller.dispose(); }
});

test('expiry is checked at the actual click; status refresh cannot extend it', async () => {
  const h = harness();
  try {
    await ready(h);
    h.controller.prepareScalar('google-wif', { ...fields });
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    h.time(5000); h.emit(status(2, { operation: operation() }));
    assert.equal(h.controller.getSnapshot().previewDeadline, 10100);
    const reordered = Object.fromEntries(Object.entries(status(2, { operation: operation() })).reverse());
    h.emit(reordered);
    assert.equal(h.controller.getSnapshot().blocked, false);
    h.time(10100);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.calls.filter((call) => call.command === 'commit').length, 0);
  } finally { h.controller.dispose(); }
});

test('equal-revision contradictions and unknown settlement are absorbing, including late-known output', async () => {
  const h = harness();
  try {
    await ready(h);
    h.emit(status(2, { capability: { available: false, reason: 'cleanup-unknown' },
      operation: operation({ phase: 'unknown', reason: 'cleanup-unknown', settlement: 'unknown', preview: null, assessment: null }) }));
    h.emit(status(3, { capability: { available: false, reason: 'cleanup-unknown' },
      operation: operation({ phase: 'unknown', reason: 'cleanup-unknown', settlement: 'late-known', preview: null, assessment: null }) }));
    h.emit(status(4));
    assert.equal(h.controller.getSnapshot().blocked, true);
    assert.equal(h.controller.prepareScalar('google-wif', fields), false);
    await h.controller.checkStatus(); assert.equal(h.controller.getSnapshot().blocked, true);
  } finally { h.controller.dispose(); }
  const other = harness();
  try {
    await ready(other);
    other.emit(status(1, { context: { ...context, stage: 'production' } }));
    assert.equal(other.controller.getSnapshot().blocked, true);
    assert.equal(other.controller.getSnapshot().error.code, 'AssetStatusInvalid');
  } finally { other.controller.dispose(); }
});

test('Cancel waits for original Choose acknowledgement; an older late event stays stale', async () => {
  const h = harness();
  try {
    await ready(h);
    assert.equal(h.controller.choose('android-keystore'), true);
    const pending = status(2, { operation: operation({ operation: 'choose-file', phase: 'capturing', source: 'pending', settlement: 'pending', assessment: null, preview: null }) });
    h.emit(pending);
    assert.equal(h.controller.discard(), false); // Event is not this command's origin receipt.
    h.latest('choose').resolve(pending); await settle();
    assert.equal(h.controller.discard(), true);
    assert.equal(h.controller.discard(), false);
    assert.equal(h.latest('discard').args, 3);
    h.latest('discard').resolve(status(4, { operation: operation({ operation: 'discard', phase: 'idle', reason: 'user-cancelled', source: 'refused', settlement: 'known', assessment: null, preview: null }) })); await settle();
    h.emit(status(3, { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', settlement: 'known', selectionToken: A, assessment: null, preview: null }) }));
    assert.equal(h.controller.getSnapshot().status.statusRevision, 4);
    assert.equal(h.controller.getSnapshot().status.operation.selectionToken, null);
    assert.equal(h.controller.prepareSelection({ storePassword: 'inert', keyAlias: 'inert', keyPassword: 'inert' }), false);
  } finally { h.controller.dispose(); }
});

test('a failed mutation is not retried by status, event, or view teardown', async () => {
  const h = harness();
  await ready(h);
  h.controller.prepareScalar('google-wif', fields);
  h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
  h.controller.confirmPreview(A, 'save');
  h.latest('commit').reject({ code: 'unknown', message: 'inert-provider-canary' }); await settle();
  assert.equal(JSON.stringify(h.controller.getSnapshot()).includes('inert-provider-canary'), false);
  h.emit(status(2, { operation: operation() })); await h.controller.checkStatus();
  assert.equal(h.controller.confirmPreview(A, 'save'), false);
  h.controller.dispose();
  assert.equal(h.calls.filter((call) => call.command === 'commit').length, 1);
  assert.equal(h.calls.filter((call) => call.command === 'lock' || call.command === 'discard').length, 0);
  assert.equal(h.unsubscribed(), true);
});

for (const code of ['unknown', 'asset_deadline']) test(`a status read started before a command failure cannot clear the newer uncertainty (${code})`, async () => {
  const h = harness();
  const terminal = (revision) => status(revision, code === 'asset_deadline' ? {
    operation: operation({ phase: 'idle', reason: 'deadline', settlement: 'known', assessment: null, preview: null }),
  } : {});
  try {
    await ready(h);
    h.controller.prepareScalar('google-wif', { ...fields });
    const oldRead = deferred(); h.api.assetStatus = () => oldRead.promise;
    const reading = h.controller.checkStatus(); await settle();
    h.latest('prepare').reject({ code, message: 'inert-private-detail' }); await settle();
    assert.equal(h.controller.getSnapshot().observationFailed, true);
    assert.equal(JSON.stringify(h.controller.getSnapshot()).includes('inert-private-detail'), false);
    // Native context can survive the known deadline. Neither its event nor the
    // already-started read can erase the original Prepare reply's uncertainty.
    h.emit(terminal(2));
    assert.deepEqual(h.controller.getSnapshot().status.context, context);
    assert.equal(h.controller.getSnapshot().observationFailed, true);
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    oldRead.resolve(terminal(2)); await reading;
    assert.equal(h.controller.getSnapshot().observationFailed, true);
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.getSnapshot().status.operation?.preview ?? null, null);
    if (code === 'asset_deadline') assert.equal(h.controller.getSnapshot().status.operation.reason, 'deadline');
    assert.equal(h.controller.prepareScalar('google-wif', fields), false);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    h.api.assetStatus = async () => terminal(3);
    await h.controller.checkStatus();
    assert.equal(h.controller.getSnapshot().observationFailed, false);
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
    assert.equal(h.controller.getSnapshot().error, null);
    assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.getSnapshot().status.operation?.preview ?? null, null);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.calls.filter((call) => call.command === 'prepare').length, 1);
    assert.equal(h.calls.filter((call) => call.command === 'commit' || call.command === 'bind').length, 0);
  } finally { h.controller.dispose(); }
});

test('requesting discard immediately retires a preview even before its native reply arrives', async () => {
  const h = harness();
  try {
    await ready(h);
    h.controller.prepareScalar('google-wif', { ...fields });
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    assert.equal(h.controller.discard(), true);
    h.emit(status(2, { operation: operation() })); await h.controller.checkStatus();
    assert.equal(h.controller.getSnapshot().previewDeadline, null);
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.controller.discard(), false);
    h.latest('discard').resolve(status(3, { operation: operation({ phase: 'idle', reason: 'user-cancelled', assessment: null, preview: null }) })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
    assert.equal(h.calls.filter((call) => call.command === 'commit').length, 0);
  } finally { h.controller.dispose(); }
});

test('original file replacement survives view subscriptions and Keep binds only its exact resulting revision', async () => {
  const records = [
    { recordId: C, revision: 0, kind: 'google-wif', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' },
    { recordId: D, revision: 7, kind: 'android-firebase', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' },
  ];
  const h = harness();
  try {
    await ready(h, { records });
    assert.equal(h.controller.choose('android-firebase', { recordId: D, expectedRevision: 7 }), true);
    // No native pending reply exists yet. Page-local defaults/subscriptions can
    // reset without hiding or retargeting the original replacement intent.
    assert.equal(h.controller.getSnapshot().status.operation, null);
    const stopBeforeReply = h.controller.subscribe(() => {}); stopBeforeReply();
    assert.equal(assetIntentPending(h.controller.getSnapshot()), true);
    assert.deepEqual(h.controller.getSnapshot().intent, { type: 'record', kind: 'android-firebase', change: 'replace', record: { recordId: D, expectedRevision: 7 } });
    assertPreparationPreservesOriginal(h);
    const pendingRecords = records.map((record) => record.recordId === D ? { ...record, availability: 'mutation-pending' } : record);
    h.latest('choose').resolve(status(2, { records: pendingRecords, operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) })); await settle();
    const unsubscribe = h.controller.subscribe(() => {}); unsubscribe();
    const intent = h.controller.getSnapshot().intent;
    assert.deepEqual(intent, { type: 'record', kind: 'android-firebase', change: 'replace', record: { recordId: D, expectedRevision: 7 } });
    assertPreparationPreservesOriginal(h);
    assert.equal(h.controller.prepareSelection({}), true);
    assert.equal(h.controller.discard(), false); // Selected predecessor is not the new Prepare operation.
    assert.equal(h.controller.getSnapshot().originPending, true);
    assert.equal(h.calls.filter((call) => call.command === 'discard').length, 0);
    assert.deepEqual(h.latest('prepare').args.source, { type: 'selection', selectionToken: A });
    const subject = { type: 'record', kind: 'android-firebase', change: 'replace', recordId: D, recordRevision: 7 };
    h.latest('prepare').resolve(status(3, { records: pendingRecords, operation: operation({ operationId: 4, source: 'captured', assessment: firebaseAssessment(),
      preview: { token: B, action: 'save', expiresInMs: 9000, subject } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.match(sessionTargetLabel(guide, subject, pendingRecords), /item 2 · revision 7/u);
    assertPreparationPreservesOriginal(h);
    assert.equal(h.controller.confirmPreview(B, 'save'), true);
    const resulting = records.map((record) => record.recordId === D ? { ...record, revision: 8 } : record);
    h.latest('commit').resolve(status(4, { records: resulting, operation: operation({ operationId: 5, operation: 'commit', source: 'captured', assessment: firebaseAssessment(),
      preview: { token: C, action: 'bind', expiresInMs: 8000, subject: { ...subject, change: 'assign', recordRevision: 8 } } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.match(sessionTargetLabel(guide, h.controller.getSnapshot().status.operation.preview.subject, resulting), /item 2 · revision 8/u);
    assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
    assert.equal(h.controller.getSnapshot().intent.record.expectedRevision, 7); // Original intent was not retargeted.
    assert.equal(JSON.stringify(h.controller.getSnapshot().intent).includes('fields'), false);
  } finally { h.controller.dispose(); }
});

for (const finalAction of ['assign explicitly', 'change context']) test(`iOS XML selection has empty companions and Keep cannot ${finalAction === 'change context' ? 'survive a stale context review' : 'assign automatically'}`, async () => {
  const iosContext = { ...context, platform: 'ios' };
  const ios = (revision, patch = {}) => status(revision, { context: iosContext, ...patch });
  const h = harness();
  try {
    h.controller.setScope({ platform: 'ios', stage: 'candidate', purpose: 'full' });
    await ready(h, { context: iosContext });
    assert.equal(h.controller.choose('ios-firebase'), true);
    assert.deepEqual(h.latest('choose').args, { contextRevision: 1, kind: 'ios-firebase', replacement: null });
    h.latest('choose').resolve(ios(2, { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) })); await settle();
    assert.equal(h.controller.prepareSelection({ storePassword: null, keyAlias: null, keyPassword: null }), false);
    assert.equal(h.calls.filter((call) => call.command === 'prepare').length, 0);
    assert.equal(h.controller.prepareSelection({}), true); // Invalid companions did not spend the selection.
    assert.deepEqual(h.latest('prepare').args, { contextRevision: 1, source: { type: 'selection', selectionToken: A }, fields: {} });
    const subject = { type: 'record', kind: 'ios-firebase', change: 'new', recordId: null, recordRevision: null };
    h.latest('prepare').resolve(ios(3, { operation: operation({ operationId: 4, source: 'captured', assessment: firebaseAssessment('ios-firebase'),
      preview: { token: B, action: 'save', expiresInMs: 9000, subject } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.equal(h.controller.confirmPreview(B, 'save'), true);
    const records = [{ recordId: D, revision: 1, kind: 'ios-firebase', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' }];
    h.latest('commit').resolve(ios(4, { records, operation: operation({ operationId: 5, operation: 'commit', source: 'captured', assessment: firebaseAssessment('ios-firebase'),
      preview: { token: C, action: 'bind', expiresInMs: 8000, subject: { type: 'record', kind: 'ios-firebase', change: 'assign', recordId: D, recordRevision: 1 } } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
    assert.deepEqual(h.controller.getSnapshot().status.assignments, []);
    if (finalAction === 'assign explicitly') {
      assert.equal(h.controller.confirmPreview(C, 'bind'), true);
      assert.equal(h.latest('bind').args, C);
      h.latest('bind').resolve(ios(5, { records: [{ ...records[0], availability: 'assigned' }],
        assignments: [{ kind: 'ios-firebase', recordId: D, recordRevision: 1, contextRevision: 1, availability: 'available' }],
        operation: operation({ operationId: 6, operation: 'bind', phase: 'idle', source: 'captured', assessment: null, preview: null }) })); await settle();
      assert.equal(h.controller.getSnapshot().contextCurrent, true);
      assert.equal(h.controller.getSnapshot().status.assignments[0].kind, 'ios-firebase');
    } else {
      h.setProject({ ...h.selected(), revision: 2, draft: { schemaVersion: 1, ios: { bundleId: 'org.changed' } } });
      assert.equal(h.controller.getSnapshot().contextCurrent, false);
      assert.equal(h.controller.getSnapshot().reviewReady, false);
      assert.equal(h.controller.confirmPreview(C, 'bind'), false);
      assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
    }
  } finally { h.controller.dispose(); }
});

for (const kind of ['apple-p12', 'apple-profile', 'asc-p8']) for (const finalAction of ['assign', 'context-change'])
test(`${kind} original selection keeps write-only companions separate and requires explicit current ${finalAction}`, async () => {
  const purpose = kind === 'asc-p8' ? 'full' : 'signing';
  const iosContext = { ...context, platform: 'ios', purpose };
  const ios = (revision, patch = {}) => status(revision, { context: iosContext, ...patch });
  const h = harness();
  try {
    h.controller.setScope({ platform: 'ios', stage: 'candidate', purpose }); await ready(h, { context: iosContext });
    assert.equal(h.controller.choose(kind), true);
    assert.deepEqual(h.latest('choose').args, { contextRevision: 1, kind, replacement: null });
    h.latest('choose').resolve(ios(2, { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) })); await settle();
    const fields = kind === 'apple-p12' ? { password: ' PRIVATE_P12_PASSWORD_CANARY\t' } :
      kind === 'asc-p8' ? { keyId: 'P8CANARY01', issuerId: '00112233-4455-6677-8899-AABBCCDDEEFF' } : {};
    const selected = h.controller.getSnapshot();
    for (const wrong of kind === 'apple-p12' ? [{}, { token: null }, { password: 'x'.repeat(4097) }] :
      kind === 'asc-p8' ? [{}, { keyId: null }, { keyId: null, issuerId: null, password: null }, { keyId: 'é'.repeat(2049), issuerId: null }] :
      [{ password: null }, { storePassword: null, keyAlias: null, keyPassword: null }]) {
      assert.equal(h.controller.prepareSelection(wrong), false);
      assert.equal(h.controller.getSnapshot().entryGeneration, selected.entryGeneration);
      assert.equal(h.controller.getSnapshot().previewDeadline, selected.previewDeadline);
      assert.deepEqual(h.controller.getSnapshot().intent, selected.intent);
      assert.equal(h.controller.getSnapshot().status.operation.selectionToken, A);
    }
    assert.equal(h.calls.filter((call) => call.command === 'prepare').length, 0);
    const before = h.controller.getSnapshot().entryGeneration;
    assert.equal(h.controller.prepareSelection(fields), true); assert.equal(h.controller.prepareSelection(fields), false);
    assert.ok(h.controller.getSnapshot().entryGeneration > before);
    assert.deepEqual(h.latest('prepare').args, { contextRevision: 1, source: { type: 'selection', selectionToken: A }, fields });
    assert.doesNotMatch(JSON.stringify(h.controller.getSnapshot()), /PRIVATE_P12_PASSWORD_CANARY|INERT_ASC_KEY_CANARY|P8CANARY01|00112233-4455-6677-8899-AABBCCDDEEFF/);
    const subject = { type: 'record', kind, change: 'new', recordId: null, recordRevision: null };
    h.latest('prepare').resolve(ios(3, { operation: operation({ operationId: 4, source: 'captured', assessment: appleAssessment(kind),
      preview: { token: B, action: 'save', expiresInMs: 9000, subject } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    const deadline = h.controller.getSnapshot().previewDeadline;
    assert.equal(h.controller.confirmPreview(B, 'bind'), false);
    assert.equal(h.controller.confirmPreview(B, 'save'), true); assert.equal(h.controller.confirmPreview(B, 'save'), false);
    const records = [{ recordId: D, revision: 1, kind, availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' }];
    h.latest('commit').resolve(ios(4, { records, operation: operation({ operationId: 5, operation: 'commit', source: 'captured', assessment: appleAssessment(kind),
      preview: { token: C, action: 'bind', expiresInMs: 8000, subject: { type: 'record', kind, change: 'assign', recordId: D, recordRevision: 1 } } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true); assert.deepEqual(h.controller.getSnapshot().status.assignments, []);
    assert.ok(h.controller.getSnapshot().previewDeadline <= deadline);
    assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
    if (finalAction === 'assign') {
      assert.equal(h.controller.confirmPreview(C, 'bind'), true);
      h.latest('bind').resolve(ios(5, { records: [{ ...records[0], availability: 'assigned' }],
        assignments: [{ kind, recordId: D, recordRevision: 1, contextRevision: 1, availability: 'available' }],
        operation: operation({ operationId: 6, operation: 'bind', phase: 'idle', source: 'captured', assessment: null, preview: null }) })); await settle();
      assert.equal(h.controller.getSnapshot().status.assignments[0].kind, kind);
      assert.doesNotMatch(JSON.stringify(h.controller.getSnapshot()), /PRIVATE_P12_PASSWORD_CANARY|INERT_ASC_KEY_CANARY|P8CANARY01|00112233-4455-6677-8899-AABBCCDDEEFF/);
    } else {
      h.setProject({ ...h.selected(), revision: 2, draft: { schemaVersion: 1, ios: { teamId: 'Z9Y8X7W6V5' } } });
      assert.equal(h.controller.getSnapshot().contextCurrent, false); assert.equal(h.controller.getSnapshot().reviewReady, false);
      assert.equal(h.controller.confirmPreview(C, 'bind'), false); assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
    }
  } finally { h.controller.dispose(); }
});

test('ASC replacement Cancel spends the selected original without restoring old assignments or private entry', async () => {
  const kind = 'asc-p8', iosContext = { ...context, platform: 'ios' };
  const ios = (revision, patch = {}) => status(revision, { context: iosContext, ...patch });
  const record = { recordId: D, revision: 7, kind, availability: 'assigned', storage: 'session', label: null, payloadState: 'assessed' };
  const assignment = { kind, recordId: D, recordRevision: 7, contextRevision: 1, availability: 'available' };
  const h = harness();
  try {
    h.controller.setScope({ platform: 'ios', stage: 'candidate', purpose: 'full' });
    await ready(h, { context: iosContext, records: [record], assignments: [assignment] });
    assert.equal(h.controller.choose(kind, { recordId: D, expectedRevision: 7 }), true);
    const revoked = { ...assignment, availability: 'unavailable' };
    const selected = ios(2, { records: [{ ...record, availability: 'mutation-pending' }], assignments: [revoked],
      operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) });
    h.latest('choose').resolve(selected); await settle();
    assert.deepEqual(h.controller.getSnapshot().intent, { type: 'record', kind, change: 'replace', record: { recordId: D, expectedRevision: 7 } });
    assertPreparationPreservesOriginal(h);
    const generation = h.controller.getSnapshot().entryGeneration;
    assert.equal(h.controller.discard(), true);
    assert.ok(h.controller.getSnapshot().entryGeneration > generation);
    assert.equal(h.latest('discard').args, 3);
    h.latest('discard').resolve(ios(3, { records: [{ ...record, availability: 'unassigned', payloadState: 'not-checked' }], assignments: [revoked],
      operation: operation({ operation: 'discard', phase: 'idle', reason: 'user-cancelled', source: 'refused', assessment: null, preview: null }) })); await settle();
    h.emit(selected); // A late original selection cannot revive the form/token.
    assert.equal(h.controller.getSnapshot().status.statusRevision, 3);
    assert.equal(h.controller.getSnapshot().status.operation.selectionToken, null);
    assert.equal(h.controller.prepareSelection({ keyId: null, issuerId: null }), false);
    assert.equal(h.controller.getSnapshot().status.records[0].revision, 7);
    assert.equal(h.controller.getSnapshot().status.assignments[0].availability, 'unavailable');
    assert.equal(h.calls.some((call) => ['prepare', 'commit', 'bind'].includes(call.command)), false);
  } finally { h.controller.dispose(); }
});

for (const refusal of ['expired', 'different-subject']) test(`ASC original review refuses ${refusal} confirmation without renewing authority`, async () => {
  const kind = 'asc-p8', iosContext = { ...context, platform: 'ios' };
  const ios = (revision, patch = {}) => status(revision, { context: iosContext, ...patch });
  const record = { recordId: D, revision: 1, kind, availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' };
  const h = harness();
  try {
    h.controller.setScope({ platform: 'ios', stage: 'candidate', purpose: 'full' }); await ready(h, { context: iosContext });
    assert.equal(h.controller.choose(kind), true);
    h.latest('choose').resolve(ios(2, { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) })); await settle();
    assert.equal(h.controller.prepareSelection({ keyId: 'P8CANARY01', issuerId: '00112233-4455-6677-8899-AABBCCDDEEFF' }), true);
    const reviewed = ios(3, { operation: operation({ operationId: 4, source: 'captured', assessment: appleAssessment(kind),
      preview: { token: B, action: 'save', expiresInMs: 9000, subject: { type: 'record', kind, change: 'new', recordId: null, recordRevision: null } } }) });
    h.latest('prepare').resolve(reviewed); await settle();
    const deadline = h.controller.getSnapshot().previewDeadline;
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    if (refusal === 'expired') {
      h.time(deadline); h.emit(reviewed);
      assert.equal(h.controller.getSnapshot().previewDeadline, deadline);
    } else {
      const changed = structuredClone(reviewed); changed.statusRevision = 4; changed.records = [record];
      changed.operation.preview.subject = { type: 'record', kind, change: 'replace', recordId: D, recordRevision: 1 };
      assert.ok(parseAssetStatus(changed)); h.emit(changed);
      assert.equal(h.controller.getSnapshot().reviewReady, false);
    }
    assert.equal(h.controller.confirmPreview(B, 'save'), false);
    assert.equal(h.calls.some((call) => call.command === 'commit'), false);
  } finally { h.controller.dispose(); }
});

test('removal identifies the exact record; another valid subject or unrelated newer operation cannot confirm', async () => {
  const records = [
    { recordId: B, revision: 0, kind: 'android-keystore', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' },
    { recordId: C, revision: 7, kind: 'google-wif', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' },
    { recordId: D, revision: 2, kind: 'google-wif', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' },
  ];
  const h = harness();
  try {
    await ready(h, { records });
    assert.equal(h.controller.prepareDelete({ recordId: C, expectedRevision: 7 }), true);
    const subject = { type: 'record', kind: 'google-wif', change: 'delete', recordId: C, recordRevision: 7 };
    const deletion = operation({ operation: 'prepare-delete', assessment: null, preview: { token: A, action: 'delete', expiresInMs: 10000, subject } });
    h.latest('delete').resolve(status(2, { records, operation: deletion })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.match(sessionTargetLabel(guide, subject, records), /item 2 · revision 7/u);
    h.emit(status(3, { records, operation: { ...deletion, preview: { ...deletion.preview, subject: { ...subject, recordId: D, recordRevision: 2 } } } }));
    assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.confirmPreview(A, 'delete'), false);
    h.emit(status(4, { records, operation: { ...deletion, preview: { ...deletion.preview, token: B } } }));
    assert.equal(h.controller.getSnapshot().reviewReady, false); // Same operation/subject cannot replace its original review token.
    assert.equal(h.controller.confirmPreview(B, 'delete'), false);
    assert.equal(h.calls.filter((call) => call.command === 'commit').length, 0);
  } finally { h.controller.dispose(); }
  const other = harness();
  try {
    await ready(other);
    other.controller.prepareScalar('google-wif', fields);
    other.latest('prepare').resolve(status(2, { operation: operation({ phase: 'assessing', settlement: 'pending', preview: null, assessment: null }) })); await settle();
    other.emit(status(3, { operation: operation({ operationId: 4 }) }));
    assert.equal(other.controller.getSnapshot().reviewReady, false);
    assert.equal(other.controller.confirmPreview(A, 'save'), false);
    assert.equal(other.calls.filter((call) => call.command === 'commit').length, 0);
  } finally { other.controller.dispose(); }
});

test('live session help explains actual collection and does not promise restored replacement authority', () => {
  const original = structuredClone(guide);
  const keystore = sessionKindHelp(guide.kinds.find((kind) => kind.id === 'android-keystore'));
  assert.equal(keystore.fields.find((field) => field.id === 'storePassword').requiredWhen, guide.kinds[0].fields.find((field) => field.id === 'storePassword').requiredWhen);
  assert.match(keystore.fields.find((field) => field.id === 'storePassword').failure, /accepts the write-only value/u);
  assert.doesNotMatch(keystore.fields.find((field) => field.id === 'storePassword').failure, /No password is entered/u);
  assert.deepEqual(keystore.fields.find((field) => field.id === 'file').suffixes, ['.jks', '.keystore']);
  assert.match(keystore.fields.find((field) => field.id === 'file').where, /admitted Linux or Apple-silicon Mac session.*private original outside registered project/);
  const android = sessionKindHelp(guide.kinds.find((kind) => kind.id === 'android-firebase'));
  assert.match(android.fields[0].where, /intended Android app.*google-services\.json.*admitted Linux or Apple-silicon Mac session/);
  assert.match(android.fields[0].failure, /application-ID mismatch.*No Firebase service is contacted/);
  assert.match(sessionControlHelp(guide, 'save').failure, /never restores assignment automatically/u);
  assert.doesNotMatch(sessionControlHelp(guide, 'save').failure, /preserves prior authority|No save is available/u);
  assert.match(sessionControlHelp(guide, 'project').format, /Submission is not validation/u);
  const ios = sessionKindHelp(guide.kinds.find((kind) => kind.id === 'ios-firebase'));
  assert.equal(ios.fields.length, 1); assert.equal(ios.fields[0].id, 'file');
  assert.equal(ios.fields[0].requiredWhen, guide.kinds.find((kind) => kind.id === 'ios-firebase').fields[0].requiredWhen);
  assert.match(ios.fields[0].where, /intended iOS app.*GoogleService-Info\.plist/u);
  assert.match(ios.fields[0].format, /UTF-8 XML 1\.0.*4 MiB.*Binary plist is not supported.*depth to 32.*duplicate keys/u);
  assert.match(ios.fields[0].failure, /bundle-ID match do not verify a Firebase account.*original is never changed/u);
  assert.match(sessionControlHelp(guide, 'choose').format, /iOS Firebase XML plist.*native availability is a separate gate/u);
  const p12 = sessionKindHelp(guide.kinds.find((kind) => kind.id === 'apple-p12'));
  assert.deepEqual(p12.fields.map((field) => field.id), ['file', 'password']);
  assert.match(p12.fields[0].format, /32 MiB.*4 MiB.*not password or trust checks/u);
  assert.match(p12.fields[1].where, /authorized owner/); assert.match(p12.fields[1].format, /4,096 UTF-8 bytes.*write-only/);
  const profile = sessionKindHelp(guide.kinds.find((kind) => kind.id === 'apple-profile'));
  assert.match(profile.fields[0].format, /4 MiB.*DER CMS SignedData.*No password/);
  assert.match(profile.fields[0].failure, /not proof of Apple authenticity/);
  const asc = sessionKindHelp(guide.kinds.find((kind) => kind.id === 'asc-p8'));
  assert.deepEqual(asc.fields.map((field) => field.id), ['file', 'keyId', 'issuerId']);
  assert.deepEqual(asc.fields[0].suffixes, ['.p8']);
  assert.match(asc.fields[0].format, /4 MiB.*unencrypted PRIVATE KEY PEM.*DER PKCS#8 version 0.*identifiers only/);
  assert.match(asc.fields[0].failure, /do not prove mathematical private-key validity.*ownership.*revocation.*permissions/);
  assert.match(asc.fields[1].format, /10 uppercase ASCII.*4,096 UTF-8 bytes.*Do not trim or normalize.*write-only/);
  assert.match(asc.fields[2].format, /UUID spelling: 8-4-4-4-12/);
  assert.match(asc.fields[2].format, /4,096 UTF-8 bytes.*Do not trim or normalize.*write-only/);
  assert.deepEqual(asc.fields.map((field) => field.requiredWhen), guide.kinds.find((kind) => kind.id === 'asc-p8').fields.map((field) => field.requiredWhen));
  assert.deepEqual(guide, original);
});

test('Android, Apple and ASC UI reuse the original write-only lifetime without file-path or browser-storage collection', () => {
  const component = readFileSync(new URL('../src/components/CredentialSession.tsx', import.meta.url), 'utf8');
  assert.match(component, /type="password".*autoComplete="new-password"/);
  assert.ok(component.includes("state.selectionKind === 'apple-p12' ? { password: fields.password ?? null }"));
  assert.ok(component.includes("state.selectionKind === 'asc-p8' ? { keyId: fields.keyId ?? null, issuerId: fields.issuerId ?? null }"));
  assert.ok(component.includes("if (onPrepare(fields, encrypted ? proposedLabel : null)) { setValues({}); setLabel(''); }"));
  assert.ok(component.includes('state.entryGeneration'));
  assert.match(component, /P12 envelope only: the password has not been tested/);
  assert.match(component, /CMS envelope only: this does not establish an Apple issuer/);
  assert.match(component, /P8 envelope and EC\/P-256 identifiers only: no mathematical private-key validity.*Store access has been verified/);
  assert.match(component, /state\.selectionKind === 'android-keystore' \?\s*\{ storePassword: fields\.storePassword \?\? null, keyAlias: fields\.keyAlias \?\? null, keyPassword: fields\.keyPassword \?\? null \}/u);
  assert.match(component, /Project dependency access<\/strong> rather than Android or iOS/);
  assert.match(component, /Admitted Linux or Apple-silicon Mac sessions can collect supported Android inputs and ASC P8/);
  assert.match(component, /Windows import and binary plist are unavailable/);
  assert.doesNotMatch(component, /Windows import, ASC P8 and binary plist are unavailable/);
  assert.doesNotMatch(component, /type="file"|\blocalStorage\b|\bsessionStorage\b|\bindexedDB\b/);
});

test('an overtaking event cannot replace the review carried by the original command reply', async () => {
  const h = harness();
  try {
    await ready(h);
    h.controller.prepareScalar('google-wif', fields);
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    assert.equal(h.controller.confirmPreview(A, 'save'), true);
    const kept = { recordId: C, revision: 1, kind: 'google-wif', availability: 'unassigned', storage: 'session', label: null, payloadState: 'assessed' };
    const original = status(3, { records: [kept], operation: operation({ operationId: 4, operation: 'commit',
      preview: { token: B, action: 'bind', expiresInMs: 9000, subject: { type: 'record', kind: 'google-wif', change: 'assign', recordId: C, recordRevision: 1 } } }) });
    const overtaking = structuredClone(original);
    overtaking.statusRevision = 4;
    overtaking.records[0].recordId = D;
    overtaking.operation.preview.token = A;
    overtaking.operation.preview.subject.recordId = D;
    h.emit(overtaking);
    assert.equal(h.controller.getSnapshot().reviewReady, false); // Origin still unacknowledged.
    h.latest('commit').resolve(original); await settle();
    assert.equal(h.controller.getSnapshot().originPending, false);
    assert.equal(h.controller.getSnapshot().status.statusRevision, 4);
    assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.confirmPreview(A, 'bind'), false);
    assert.equal(h.calls.filter((call) => call.command === 'bind').length, 0);
  } finally { h.controller.dispose(); }
});

test('v2 encrypted descriptors have their own finite bounds and cannot masquerade as session or payload authority', () => {
  const records = Array.from({ length: 128 }, (_, index) => vaultRecord({ recordId: (index + 1).toString(16).padStart(32, '0'), label: 'x'.repeat(128) }));
  const input = vaultStatus(1, { records });
  assert.equal(assetJsonFits(input, 32768), false, 'the encrypted cap must not accidentally retain the smaller session cap');
  assert.deepEqual(parseAssetStatus(input), input);
  for (const mutate of [
    (s) => { s.schemaVersion = 1; }, (s) => { s.persistence = null; },
    (s) => { s.records.push(vaultRecord({ recordId: 'f'.repeat(32) })); },
    (s) => { s.records[0].recordId = s.records[1].recordId; },
    (s) => { s.records[0].revision = 0; }, (s) => { s.records[0].storage = 'session'; },
    (s) => { s.records[0].label = 'x'.repeat(129); }, (s) => { s.records[0].label = 'hidden\nline'; },
    (s) => { s.records[0].payloadState = 'verified'; }, (s) => { s.records[0].payload = 'private-canary'; },
    (s) => { s.persistence.keyAccess = 'read-only'; },
    (s) => { s.persistence.state = 'initializing'; }, (s) => { s.persistence.keyAccess = 'locked'; },
  ]) { const changed = structuredClone(input); mutate(changed); assert.equal(parseAssetStatus(changed), null); }
  const memory = status(1, { records: records.slice(0, 32).map((record) => ({ ...record, storage: 'session', label: null })) });
  assert.ok(parseAssetStatus(memory), 'session not-checked is a truthful current-context state');
  memory.records.push({ ...memory.records[0], recordId: 'f'.repeat(32) });
  assert.equal(parseAssetStatus(memory), null, 'memory-only bound remains 32');
  assert.equal(assetLabelFits('🚀'.repeat(32)), true); assert.equal(assetLabelFits('🚀'.repeat(33)), false);
  for (const label of ['', '\u0000', '\u0085', '\ud800']) assert.equal(assetLabelFits(label), false);
  assert.equal(assetLabelFits(null), true);
  let readMode = false;
  const accessor = { ...input }; Object.defineProperty(accessor, 'mode', { enumerable: true, get() { readMode = true; return 'encrypted'; } });
  assert.equal(parseAssetStatus(accessor), null); assert.equal(readMode, false, 'choosing a response bound must not evaluate a provider getter');
});

test('locked and interrupted read-only projections cannot carry decrypted or assignment authority', () => {
  const locked = vaultStatus(2, { context: null, persistence: { state: 'locked', reason: 'vault-keyring-locked', keyAccess: 'locked' } });
  assert.ok(parseAssetStatus(locked)); assert.equal(assetStorageWritable(locked), false);
  for (const patch of [
    { records: [vaultRecord({ label: 'not-to-be-published' })] },
    { assignments: [{ kind: 'google-wif', recordId: C, recordRevision: 1, contextRevision: 1, availability: 'unavailable' }] },
    { context, operation: operation() },
    { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) },
  ]) assert.equal(parseAssetStatus({ ...locked, ...patch }), null);
  const interrupted = { ...locked, records: [vaultRecord({ label: 'Upload identity' })], persistence: { state: 'interrupted', reason: 'vault-interrupted', keyAccess: 'read-only' } };
  assert.ok(parseAssetStatus(interrupted)); assert.equal(assetStorageWritable(interrupted), false);
  for (const patch of [{ availability: 'assigned' }, { availability: 'mutation-pending' }, { payloadState: 'assessed' }])
    assert.equal(parseAssetStatus({ ...interrupted, records: [{ ...interrupted.records[0], ...patch }] }), null);
  const initialize = { ...locked, persistence: { state: 'uninitialized', reason: 'vault-uninitialized', keyAccess: 'locked' }, operation: operation({
    operation: 'prepare-initialize', assessment: null, preview: { token: A, action: 'initialize', expiresInMs: 10000, subject: { type: 'vault', change: 'initialize' } },
  }) };
  assert.ok(parseAssetStatus(initialize));
  for (const mutate of [
    (s) => { s.operation.preview.subject.kind = 'google-wif'; },
    (s) => { s.operation.preview.action = 'save'; }, (s) => { s.operation.operation = 'prepare'; },
    (s) => { s.persistence.state = 'locked'; }, (s) => { s.operation.assessment = assessment(); s.context = context; },
  ]) { const changed = structuredClone(initialize); mutate(changed); assert.equal(parseAssetStatus(changed), null); }
});

test('storage effect, durability and cleanup survive redacted closure but never become a successful session action', () => {
  const receipt = status(4, { mode: 'closed', context: null, operation: operation({ operation: 'initialize', phase: 'unknown', reason: 'user-cancelled', settlement: 'unknown', assessment: null, preview: null,
    storageOutcome: { effect: 'known-applied', durability: 'unknown', cleanup: 'unknown' } }) });
  assert.deepEqual(parseAssetStatus(receipt), receipt);
  for (const mutate of [
    (s) => { s.mode = 'session'; }, (s) => { s.context = context; }, (s) => { s.records = [vaultRecord()]; },
    (s) => { s.operation.operation = 'lock'; }, (s) => { s.operation.storageOutcome.effect = 'success'; },
    (s) => { s.operation.storageOutcome.effect = 'known-none'; s.operation.storageOutcome.durability = 'confirmed'; },
    (s) => { s.operation.storageOutcome.saved = true; },
  ]) { const changed = structuredClone(receipt); mutate(changed); assert.equal(parseAssetStatus(changed), null); }
  for (const name of ['open-vault', 'prepare-initialize', 'initialize', 'unlock'])
    assert.equal(parseAssetStatus(status(4, { operation: operation({ operation: name, phase: 'idle', assessment: null, preview: null }) })), null);
});

test('closed v2 statuses redact material even without a storage receipt and reject invented storage modes', () => {
  const closed = status(5, { mode: 'closed', context: null });
  assert.deepEqual(parseAssetStatus(closed), closed);
  const redacted = operation({ operation: 'lock', phase: 'idle', assessment: null, preview: null });
  assert.deepEqual(parseAssetStatus({ ...closed, operation: redacted }), { ...closed, operation: redacted });
  for (const storage of ['closed', 'session', 'encrypted']) {
    assert.equal(parseAssetStatus({ ...closed, records: [vaultRecord({ storage, label: null })] }), null, storage);
  }
  for (const patch of [
    { context },
    { assignments: [{ kind: 'google-wif', recordId: C, recordRevision: 1, contextRevision: 1, availability: 'unavailable' }] },
    { operation: { ...redacted, operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A } },
    { context, operation: { ...redacted, operation: 'prepare', assessment: assessment() } },
    { context, operation: operation() },
  ]) assert.equal(parseAssetStatus({ ...closed, ...patch }), null);
  for (const storage of ['closed', 'filesystem', null]) {
    assert.equal(parseAssetStatus(status(5, { records: [vaultRecord({ storage, label: null })] })), null);
    assert.equal(parseAssetStatus(vaultStatus(5, { records: [vaultRecord({ storage })] })), null);
  }
});

test('native v2 routes are exact, browser-unavailable, and never acquire fields for an existing stored record', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return vaultStatus(); });
  await api.openAssetSession(); await api.openAssetSession('encrypted'); await api.prepareVaultInitialize(); await api.unlockVault();
  assert.deepEqual(calls, [
    { command: 'vault_open', args: { mode: 'session' } }, { command: 'vault_open', args: { mode: 'encrypted' } },
    { command: 'vault_prepare_initialize', args: {} }, { command: 'vault_unlock', args: {} },
  ]);
  for (const [command, args] of [['vault_open', { mode: 'automatic' }], ['vault_prepare_initialize', { replaceExisting: true }], ['vault_unlock', { password: 'inert-canary' }]])
    assert.equal(assetRequestFits(command, args), false);
  const stored = { contextRevision: 1, source: { type: 'record', recordId: C, expectedRevision: 1 } };
  assert.equal(assetRequestFits('credential_prepare', stored), true);
  for (const patch of [{ fields: {} }, { label: null }, { label: 'not-an-update-route' }]) assert.equal(assetRequestFits('credential_prepare', { ...stored, ...patch }), false);
  for (const action of [() => previewApi.openAssetSession('encrypted'), () => previewApi.prepareVaultInitialize(), () => previewApi.unlockVault()])
    await assert.rejects(action(), (error) => error.code === 'AssetSessionUnavailable');
});

for (const kind of ['google-wif', 'asc-p8']) test(`${kind} encrypted Save ends unassigned; only explicit preparation of the actual saved revision can lead to Bind`, async () => {
  const scope = { platform: kind === 'asc-p8' ? 'ios' : 'android', stage: 'candidate', purpose: 'full' };
  const native = (revision, patch = {}) => vaultStatus(revision, { context: { ...context, ...scope }, ...patch });
  const checkedInput = kind === 'asc-p8' ? appleAssessment(kind) : assessment();
  const h = harness(native(0)); let revision = 1;
  try {
    h.controller.setScope(scope);
    await ready(h, { context: { ...context, ...scope }, mode: 'encrypted', persistence: vaultStatus().persistence });
    if (kind === 'asc-p8') {
      assert.equal(h.controller.choose(kind), true);
      h.latest('choose').resolve(native(++revision, { operation: operation({ operationId: 2, operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: D, assessment: null, preview: null }) })); await settle();
      const fields = { keyId: 'P8CANARY01', issuerId: '00112233-4455-6677-8899-AABBCCDDEEFF' };
      assert.equal(h.controller.prepareSelection(fields, 'Upload identity'), true);
      assert.deepEqual(h.latest('prepare').args, { contextRevision: 1, source: { type: 'selection', selectionToken: D }, fields, label: 'Upload identity' });
    } else {
      assert.equal(h.controller.prepareScalar(kind, fields, null, 'Upload identity'), true);
      assert.deepEqual(h.latest('prepare').args, { contextRevision: 1, source: { type: 'scalar', kind, replacement: null }, fields, label: 'Upload identity' });
    }
    assert.doesNotMatch(JSON.stringify(h.controller.getSnapshot()), /inert-provider-canary|P8CANARY01|Upload identity/, 'private entry is not retained in display state');
    h.latest('prepare').resolve(native(++revision, { operation: operation({ assessment: checkedInput,
      preview: { token: A, action: 'save', expiresInMs: 10000, subject: { type: 'record', kind, change: 'new', recordId: null, recordRevision: null } } }) })); await settle();
    assert.equal(h.controller.confirmPreview(A, 'save'), true);
    const record = vaultRecord({ kind, label: 'Upload identity' });
    h.latest('commit').resolve(native(++revision, { records: [record], operation: operation({ operationId: 4, operation: 'commit', phase: 'idle', assessment: null, preview: null,
      storageOutcome: { effect: 'known-applied', durability: 'confirmed', cleanup: 'known' } }) })); await settle();
    const saved = h.controller.getSnapshot();
    assert.equal(saved.reviewReady, false); assert.equal(saved.status.operation.preview, null);
    assert.equal(saved.status.records[0].payloadState, 'not-checked'); assert.deepEqual(saved.status.assignments, []);
    assert.equal(h.controller.confirmPreview(A, 'bind'), false); assert.equal(h.calls.some((call) => call.command === 'bind'), false);
    assert.equal(h.controller.prepareRecord({ recordId: C, expectedRevision: 2 }), false, 'no substitution of a newer revision');
    assert.equal(h.controller.prepareRecord({ recordId: C, expectedRevision: 1 }), true);
    assert.deepEqual(h.latest('prepare').args, { contextRevision: 1, source: { type: 'record', recordId: C, expectedRevision: 1 } });
    const checked = { ...record, payloadState: 'assessed' };
    h.latest('prepare').resolve(native(++revision, { records: [checked], operation: operation({ operationId: 5, assessment: checkedInput,
      preview: { token: B, action: 'bind', expiresInMs: 10000, subject: { type: 'record', kind, change: 'assign', recordId: C, recordRevision: 1 } } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.equal(h.controller.confirmPreview(B, 'bind'), true);
    assert.equal(h.latest('bind').args, B);
    h.latest('bind').resolve(native(++revision, { records: [{ ...checked, availability: 'assigned' }],
      assignments: [{ kind, recordId: C, recordRevision: 1, contextRevision: 1, availability: 'available' }],
      operation: operation({ operationId: 6, operation: 'bind', phase: 'idle', assessment: null, preview: null }) })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
    assert.equal(h.controller.getSnapshot().status.assignments.length, 1);
  } finally { h.controller.dispose(); }
});

test('encrypted save refuses an inherited source Bind review even when its record and native operation IDs are plausible', async () => {
  const h = harness(vaultStatus());
  try {
    await ready(h, { mode: 'encrypted', persistence: vaultStatus().persistence });
    h.controller.prepareScalar('google-wif', fields);
    assert.equal(h.latest('prepare').args.label, null, 'encrypted preparation supplies the explicit optional-label slot');
    h.latest('prepare').resolve(vaultStatus(2, { operation: operation() })); await settle();
    assert.equal(h.controller.confirmPreview(A, 'save'), true);
    h.latest('commit').resolve(vaultStatus(3, { records: [vaultRecord()], operation: operation({ operationId: 4, operation: 'commit',
      preview: { token: B, action: 'bind', expiresInMs: 10000, subject: { type: 'record', kind: 'google-wif', change: 'assign', recordId: C, recordRevision: 1 } } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.getSnapshot().observationFailed, true);
    assert.equal(h.controller.confirmPreview(B, 'bind'), false);
    assert.equal(h.calls.some((call) => call.command === 'bind'), false);
  } finally { h.controller.dispose(); }
});

test('initialization uses its original vault-only review without a project and cancellation targets the actual Initialize owner', async () => {
  const h = harness(status(0, { mode: 'closed', context: null }));
  const absent = { state: 'uninitialized', reason: 'vault-uninitialized', keyAccess: 'locked' };
  try {
    h.setProject(null); await h.controller.connect(h.api);
    assert.equal(h.controller.open('encrypted'), true);
    assert.deepEqual(h.latest('open').args, { mode: 'encrypted' });
    const opened = vaultStatus(1, { context: null, persistence: absent, operation: operation({ operationId: 1, operation: 'open-vault', phase: 'idle', assessment: null, preview: null }) });
    h.emit(opened); assert.equal(h.controller.getSnapshot().originPending, true);
    assert.equal(h.controller.prepareInitialize(), false);
    h.latest('open').resolve(opened); await settle();
    assert.equal(h.controller.prepareInitialize(), true);
    const reviewed = vaultStatus(2, { context: null, persistence: absent, operation: operation({ operationId: 2, operation: 'prepare-initialize', assessment: null,
      preview: { token: A, action: 'initialize', expiresInMs: 10000, subject: { type: 'vault', change: 'initialize' } } }) });
    h.emit(reviewed); assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.confirmPreview(A, 'initialize'), false);
    h.latest('initialize-review').resolve(reviewed); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.deepEqual(h.controller.getSnapshot().intent, { type: 'vault', change: 'initialize' });
    assert.equal(h.controller.confirmPreview(A, 'initialize'), true);
    assert.equal(h.controller.discard(), false, 'the preceding PrepareInitialize cannot identify a pending Initialize');
    const running = vaultStatus(3, { context: null, persistence: { state: 'initializing', reason: 'none', keyAccess: 'locked' },
      operation: operation({ operationId: 3, operation: 'initialize', phase: 'mutating', settlement: 'pending', assessment: null, preview: null,
        storageOutcome: { effect: 'not-started', durability: 'not-run', cleanup: 'pending' } }) });
    h.latest('commit').resolve(running); await settle();
    assert.equal(h.controller.discard(), true); assert.equal(h.latest('discard').args, 3);
    h.latest('discard').resolve(vaultStatus(4, { context: null, persistence: { state: 'interrupted', reason: 'vault-interrupted', keyAccess: 'locked' },
      operation: operation({ operationId: 3, operation: 'initialize', phase: 'idle', reason: 'user-cancelled', assessment: null, preview: null,
        storageOutcome: { effect: 'known-applied', durability: 'unknown', cleanup: 'known' } }) })); await settle();
    assert.equal(h.controller.getSnapshot().status.operation.reason, 'user-cancelled');
    assert.equal(h.controller.confirmPreview(A, 'initialize'), false);
    assert.equal(h.calls.some((call) => call.command === 'context' || call.command === 'prepare' || call.command === 'bind'), false);
  } finally { h.controller.dispose(); }
});

test('a later vault event cannot replace the originating initialization token or extend its review', async () => {
  const absent = { state: 'uninitialized', reason: 'vault-uninitialized', keyAccess: 'locked' };
  const h = harness(vaultStatus(0, { context: null, persistence: absent }));
  try {
    h.setProject(null); await h.controller.connect(h.api);
    assert.equal(h.controller.prepareInitialize(), true);
    const original = vaultStatus(1, { context: null, persistence: absent, operation: operation({ operation: 'prepare-initialize', assessment: null,
      preview: { token: A, action: 'initialize', expiresInMs: 5000, subject: { type: 'vault', change: 'initialize' } } }) });
    h.emit({ ...original, statusRevision: 2, operation: { ...original.operation, preview: { ...original.operation.preview, token: B } } });
    h.latest('initialize-review').resolve(original); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, false);
    assert.equal(h.controller.confirmPreview(B, 'initialize'), false);
    h.emit({ ...original, statusRevision: 3 });
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    h.time(5101);
    h.emit({ ...original, statusRevision: 4, operation: { ...original.operation, preview: { ...original.operation.preview, expiresInMs: 20000 } } });
    assert.equal(h.controller.confirmPreview(A, 'initialize'), false);
    assert.equal(h.calls.some((call) => call.command === 'commit'), false);
  } finally { h.controller.dispose(); }
});

test('locked, read-only and mutating storage cannot submit context, prepare, delete or assign or fall back to memory', async () => {
  for (const persistence of [
    { state: 'locked', reason: 'vault-keyring-locked', keyAccess: 'locked' },
    { state: 'interrupted', reason: 'vault-interrupted', keyAccess: 'read-only' },
    { state: 'mutating', reason: 'none', keyAccess: 'read-write' },
  ]) {
    const h = harness(vaultStatus(0, { context: null, persistence, records: persistence.keyAccess === 'locked' ? [] : [vaultRecord()] }));
    try {
      await h.controller.connect(h.api); const before = h.calls.length;
      h.controller.submitContext();
      assert.equal(h.controller.open(), false); assert.equal(h.controller.choose('android-keystore'), false);
      assert.equal(h.controller.prepareScalar('google-wif', fields), false); assert.equal(h.controller.prepareSelection({}), false);
      assert.equal(h.controller.prepareRecord({ recordId: C, expectedRevision: 1 }), false);
      assert.equal(h.controller.prepareDelete({ recordId: C, expectedRevision: 1 }), false);
      assert.equal(h.controller.confirmPreview(A, 'bind'), false);
      assert.notEqual(assetStorageReason(h.controller.getSnapshot()), null);
      await settle(); assert.equal(h.calls.length, before);
    } finally { h.controller.dispose(); }
  }
});

test('unlock is explicit and its delayed completion only submits the already requested context, never reads or assigns a record', async () => {
  const h = harness(vaultStatus(0, { context: null, persistence: { state: 'locked', reason: 'vault-keyring-locked', keyAccess: 'locked' } }));
  try {
    await h.controller.connect(h.api); await settle();
    assert.deepEqual(h.calls.map((call) => call.command), ['listen', 'status']);
    assert.equal(h.controller.unlock(), true); assert.deepEqual(h.latest('unlock').args, {});
    h.latest('unlock').resolve(vaultStatus(1, { context: null, persistence: { state: 'locked', reason: 'none', keyAccess: 'locked' },
      operation: operation({ operation: 'unlock', phase: 'admitting', settlement: 'pending', assessment: null, preview: null }) })); await settle();
    assert.equal(h.calls.some((call) => call.command === 'context'), false);
    h.emit(vaultStatus(2, { context: null, records: [vaultRecord()], operation: operation({ operation: 'unlock', phase: 'idle', assessment: null, preview: null }) })); await settle();
    assert.equal(h.calls.filter((call) => call.command === 'context').length, 1);
    h.latest('context').resolve(vaultStatus(3, { records: [vaultRecord()], operation: operation({ operation: 'unlock', phase: 'idle', assessment: null, preview: null }) })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
    assert.equal(h.controller.getSnapshot().status.records[0].payloadState, 'not-checked');
    assert.equal(h.calls.some((call) => ['prepare', 'bind', 'choose', 'open'].includes(call.command)), false);
  } finally { h.controller.dispose(); }
});

test('encrypted live help keeps user labels nonsecret and saving distinct from actual stored-revision assessment', () => {
  const before = structuredClone(guide);
  for (const id of ['mode', 'initialize', 'unlock', 'label', 'save', 'assign', 'replace', 'delete', 'lock']) {
    const help = sessionControlHelp(guide, id, 'encrypted');
    assert.ok(help);
    for (const field of ['label', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure']) assert.ok(help[field].length, `${id}/${field}`);
  }
  assert.equal(sessionControlHelp(guide, 'label', 'encrypted').requiredness, 'optional');
  assert.match(sessionControlHelp(guide, 'mode', 'encrypted').failure, /trusted operating system.*desktop account.*Secret Service.*not atomic process protection/);
  assert.match(sessionControlHelp(guide, 'label', 'encrypted').format, /128 UTF-8 bytes/);
  assert.match(sessionControlHelp(guide, 'save', 'encrypted').format, /Saved means not assigned.*stored payload has not yet been checked/);
  assert.match(sessionControlHelp(guide, 'assign', 'encrypted').format, /actual stored revision/);
  assert.match(sessionControlHelp(guide, 'lock', 'encrypted').what, /preserve encrypted records/);
  assert.equal(sessionTargetLabel(guide, { type: 'vault', change: 'initialize' }, []), 'New encrypted private-input vault');
  const subject = { type: 'record', kind: 'google-wif', change: 'assign', recordId: C, recordRevision: 1 };
  assert.match(sessionTargetLabel(guide, subject, [vaultRecord({ label: '<nonsecret text>' })], 'encrypted'), /<nonsecret text> · item 1 · revision 1/);
  assert.equal(sessionTargetLabel(guide, { ...subject, recordRevision: 2 }, [vaultRecord()], 'encrypted'), null);
  assert.deepEqual(guide, before, 'the static catalogue and requiredness are unchanged');
});


function imageOperation(patch = {}) {
  return operation({ operation: 'choose-images', phase: 'capturing', source: 'pending', settlement: 'pending',
    assessment: null, preview: null, selectionToken: null, ...patch });
}

test('generic choose-images status is passive closed DATA, never a credential kind or authority', () => {
  for (const mode of ['closed', 'session', 'encrypted']) {
    for (const phase of ['admitting', 'picking', 'capturing', 'selected', 'stopping', 'unknown', 'idle']) {
      const op = imageOperation({ phase, source: phase === 'selected' ? 'captured' : phase === 'unknown' ? 'unknown' : 'pending',
        settlement: phase === 'selected' || phase === 'idle' ? 'known' : phase === 'unknown' ? 'unknown' : 'pending' });
      const frame = status(1, { mode, context: null, operation: op,
        persistence: mode === 'encrypted' ? { state: 'locked', reason: 'vault-keyring-locked', keyAccess: 'locked' } : null });
      assert.deepEqual(parseAssetStatus(frame), frame);
      for (const change of [
        (v) => { v.operation.selectionToken = A; }, (v) => { v.operation.assessment = assessment(); },
        (v) => { v.operation.preview = operation().preview; }, (v) => { v.operation.items = []; },
        (v) => { v.operation.root = '/inert-not-a-source'; }, (v) => { v.operation.bytes = [1]; },
        (v) => { v.operation.operationId = A; },
        (v) => { v.operation.phase = 'assessing'; }, (v) => { v.operation.phase = 'preview'; },
        (v) => { v.operation.phase = 'mutating'; },
        (v) => { v.operation.storageOutcome = { effect: 'known-none', durability: 'not-run', cleanup: 'known' }; },
      ]) {
        const invalid = structuredClone(frame); change(invalid); assert.equal(parseAssetStatus(invalid), null);
      }
    }
  }
  assert.equal(ASSET_KINDS.includes('choose-images'), false);
  assert.equal(isAssetFileKind('choose-images'), false);
  assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind: 'choose-images', replacement: null }), false);
});

test('every active image phase blocks credential context, mutations, discard and lock without another cancellation route', async () => {
  for (const phase of ['admitting', 'picking', 'capturing', 'selected', 'stopping', 'unknown']) {
    const h = harness();
    try {
      await ready(h); const before = h.calls.length, scope = h.controller.getSnapshot().scope;
      h.emit(status(2, { operation: imageOperation({ phase, source: phase === 'selected' ? 'captured' : phase === 'unknown' ? 'unknown' : 'pending',
        settlement: phase === 'selected' ? 'known' : phase === 'unknown' ? 'unknown' : 'pending' }) }));
      const observed = h.controller.getSnapshot();
      assert.equal(assetImageOperationPending(observed.status), true);
      assert.notEqual(assetSessionReason(observed), null);
      assert.match(assetCancellationReason(observed), /original image operation in Metadata/);
      assert.equal(observed.contextCurrent, false);
      h.controller.setScope({ platform: 'ios', stage: 'production', purpose: 'store' });
      assert.deepEqual(h.controller.getSnapshot().scope, scope);
      h.controller.submitContext();
      assert.equal(h.controller.choose('android-keystore'), false);
      assert.equal(h.controller.prepareScalar('google-wif', fields), false);
      assert.equal(h.controller.prepareSelection({}), false);
      assert.equal(h.controller.prepareRecord({ recordId: C, expectedRevision: 1 }), false);
      assert.equal(h.controller.prepareDelete({ recordId: C, expectedRevision: 1 }), false);
      assert.equal(h.controller.confirmPreview(A, 'save'), false);
      assert.equal(h.controller.discard(), false); assert.equal(h.controller.lock(), false);
      h.setProject({ ...h.selected(), revision: 2 });
      await settle(); assert.equal(h.calls.length, before, phase);
      assert.equal(h.controller.getSnapshot().selectionKind, null);
      assert.equal(h.controller.getSnapshot().reviewReady, false);
    } finally { h.controller.dispose(); }
  }
});

test('an image slot suppresses an already queued credential context but does not auto-submit it on retirement', async () => {
  const h = harness();
  try {
    await ready(h); const before = h.calls.length;
    h.controller.setScope({ platform: 'android', stage: 'production', purpose: 'full' });
    h.emit(status(2, { operation: imageOperation() })); await settle();
    assert.equal(h.calls.length, before);
    assert.equal(h.controller.getSnapshot().updatingContext, false);
    h.emit(status(3, { operation: imageOperation({ phase: 'idle', source: 'captured', settlement: 'known' }) })); await settle();
    assert.equal(h.calls.length, before, 'retirement is passive, not permission to mutate credential context');
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    h.controller.submitContext(); await settle();
    assert.equal(h.calls.length, before + 1);
    assert.equal(h.latest('context').args.stage, 'production');
    h.latest('context').resolve(status(4, { context: { ...context, revision: 2, stage: 'production' },
      operation: imageOperation({ phase: 'idle', source: 'captured', settlement: 'known' }) })); await settle();
    assert.equal(h.controller.getSnapshot().contextCurrent, true);
  } finally { h.controller.dispose(); }
});

test('image retirement is monotone, unknown stays blocked and idle never supplies credential origin authority', async () => {
  const h = harness();
  try {
    await ready(h);
    const selected = status(2, { operation: imageOperation({ phase: 'selected', source: 'captured', settlement: 'known' }) });
    h.emit(selected); h.emit(status(1));
    assert.equal(h.controller.getSnapshot().status.operation.operation, 'choose-images');
    assert.equal(h.controller.getSnapshot().originPending, false);
    assert.equal(h.controller.getSnapshot().intent, null);
    assert.equal(h.controller.getSnapshot().previewDeadline, null);
    h.emit(status(3, { operation: imageOperation({ phase: 'unknown', source: 'unknown', settlement: 'unknown', reason: 'cleanup-unknown' }) }));
    h.emit(status(4, { operation: imageOperation({ phase: 'unknown', source: 'unknown', settlement: 'late-known', reason: 'cleanup-unknown' }) }));
    h.emit(status(5, { operation: imageOperation({ phase: 'idle', source: 'captured', settlement: 'known' }) }));
    assert.equal(h.controller.getSnapshot().blocked, true);
    assert.equal(h.controller.choose('android-keystore'), false);
    assert.equal(h.controller.discard(), false); assert.equal(h.controller.lock(), false);
    assert.equal(h.calls.some((row) => row.command === 'discard' || row.command === 'lock'), false);
  } finally { h.controller.dispose(); }
});

test('CredentialSession renders choose-images only as passive status without a second Stop or private form', () => {
  const component = readFileSync(new URL('../src/components/CredentialSession.tsx', import.meta.url), 'utf8');
  const start = component.indexOf('imageOperation ? <div'), end = component.indexOf(': projectPathOperation ?', start);
  assert.ok(start >= 0 && end > start);
  const passive = component.slice(start, end);
  assert.ok(passive.includes('Original image selection status'));
  assert.ok(passive.includes('passive busy and retirement display'));
  assert.ok(passive.includes('original image operation in Metadata'));
  assert.doesNotMatch(passive, /onClick=|controller\.(discard|lock|choose)|selectionToken|assessment|preview\.token/);
  assert.ok(component.includes('nativeAvailable && writable && guide && !projectPathActive && !imageActive'));
  assert.equal((component.match(/disabled=\{!!state\.busy \|\| projectPathActive \|\| imageActive \|\| installationActive\}/g) ?? []).length, 2);
  assert.ok(component.includes('nativeBusyReason !== null || imageActive'));
});

test('image retirement never auto-submits a deferred credential context even with a writable storage observation', async () => {
  const h = harness(vaultStatus(0, { context: null, persistence: { state: 'locked', reason: 'vault-keyring-locked', keyAccess: 'locked' } }));
  try {
    await h.controller.connect(h.api); const before = h.calls.length;
    h.emit(vaultStatus(1, { context: null, persistence: { state: 'locked', reason: 'vault-keyring-locked', keyAccess: 'locked' },
      operation: imageOperation() }));
    h.emit(vaultStatus(2, { context: null, operation: imageOperation({ phase: 'idle', source: 'captured', settlement: 'known' }) }));
    await settle(); assert.equal(h.calls.length, before);
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    h.controller.submitContext(); await settle(); assert.equal(h.calls.length, before + 1);
    h.latest('context').resolve(vaultStatus(3, { operation: imageOperation({ phase: 'idle', source: 'captured', settlement: 'known' }) }));
    await settle(); assert.equal(h.controller.getSnapshot().contextCurrent, true);
  } finally { h.controller.dispose(); }
});

test('installation status is foreign closed DATA, never credential selection, storage or preview authority', () => {
  const op = operation({ operation: 'inspect-installation', phase: 'capturing', source: 'not-run',
    settlement: 'pending', assessment: null, preview: null, selectionToken: null });
  const frame = status(2, { operation: op });
  assert.deepEqual(parseAssetStatus(frame), frame);
  for (const patch of [{ phase: 'selected' }, { phase: 'picking' }, { phase: 'preview' },
    { selectionToken: A }, { assessment: assessment() }, { preview: operation().preview },
    { storageOutcome: { effect: 'known-none', durability: 'not-run', cleanup: 'known' } }]) {
    assert.equal(parseAssetStatus({ ...frame, operation: { ...op, ...patch } }), null);
  }
  assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind: 'inspect-installation', replacement: null }), false);
});

test('installation originals block credential routes and queued contexts; known retirement is not an implicit context update', async () => {
  const h = harness();
  try {
    await ready(h); const before = h.calls.length, scope = h.controller.getSnapshot().scope;
    const op = operation({ operation: 'inspect-installation', phase: 'capturing', source: 'not-run',
      settlement: 'pending', assessment: null, preview: null, selectionToken: null });
    h.emit(status(2, { operation: op }));
    assert.match(assetSessionReason(h.controller.getSnapshot()), /installation check/);
    assert.match(assetCancellationReason(h.controller.getSnapshot()), /exact original check in Environment/);
    assert.equal(h.controller.getSnapshot().contextCurrent, false);
    h.controller.setScope({ platform: 'ios', stage: 'production', purpose: 'store' });
    assert.deepEqual(h.controller.getSnapshot().scope, scope);
    h.controller.submitContext();
    assert.equal(h.controller.choose('android-keystore'), false);
    assert.equal(h.controller.prepareScalar('google-wif', fields), false);
    assert.equal(h.controller.prepareSelection({}), false);
    assert.equal(h.controller.prepareRecord({ recordId: C, expectedRevision: 1 }), false);
    assert.equal(h.controller.prepareDelete({ recordId: C, expectedRevision: 1 }), false);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.controller.discard(), false); assert.equal(h.controller.lock(), false);
    h.setProject({ ...h.selected(), revision: 2 }); await settle();
    assert.equal(h.calls.length, before);
    h.emit(status(3, { operation: { ...op, phase: 'idle', settlement: 'known' } })); await settle();
    assert.equal(h.calls.length, before, 'settlement is passive, not new credential intent');
    h.controller.submitContext(); await settle();
    assert.equal(h.calls.length, before + 1);
    h.latest('context').resolve(status(4, { context: { ...context, revision: 2 },
      operation: { ...op, phase: 'idle', settlement: 'known' } })); await settle();
  } finally { h.controller.dispose(); }
});
