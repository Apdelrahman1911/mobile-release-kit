// Inert contract/promise tests only. No native picker, secret file, browser,
// service, process fixture, storage, real credential or engine is accessed.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController, assetCancellationReason, assetContextReason, assetIntentPending } from '../src/assetSessionController.ts';
import { ASSET_KINDS, SESSION_FIELDS, assetError, assetJsonFits, assetRequestFits, isAssetFileKind, parseAssetStatus } from '../src/assetSessionProtocol.ts';
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
  return { schemaVersion: 1, statusRevision: revision, mode: 'session', capability: { available: true, reason: 'none' },
    context: { ...context }, operation: null, records: [], assignments: [], ...patch };
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
  return { operationId: 3, operation: 'prepare', phase: 'preview', reason: 'none', source: 'not-run', settlement: 'known',
    selectionToken: null, assessment: assessment(), preview: { token: A, action: 'save', expiresInMs: 10000,
      subject: { kind: 'google-wif', change: 'new', recordId: null, recordRevision: null } }, ...patch };
}
function firebaseAssessment(kind = 'android-firebase') {
  const value = assessment();
  const ios = kind === 'ios-firebase';
  return { ...value, kind, context: { ...value.context, platform: ios ? 'ios' : 'android' }, state: 'format-valid', identity: 'match', fields: [
    { id: 'file', requirement: ios ? 'MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64' : 'MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64', presence: 'supplied', state: 'format-valid', issues: [],
      checks: [{ scope: ios ? 'plist-document' : 'json-document', outcome: 'asserted-pass' }, { scope: 'firebase-shape', outcome: 'asserted-pass' }, { scope: 'application-identity', outcome: 'asserted-pass' }] },
  ], assurance: { ...value.assurance, scalarValuesProcessed: false, fileObservationsProcessed: true } };
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
    setAssetContext: (input) => pending('context', input), openAssetSession: () => pending('open', {}),
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
  lost.records = [{ recordId: C, revision: 0, kind: 'google-wif', availability: 'unassigned' }];
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

test('iOS Firebase is exactly the fifth session kind with a closed file-only request and assessment layout', () => {
  assert.deepEqual(ASSET_KINDS, ['android-keystore', 'android-firebase', 'ios-firebase', 'google-wif', 'project-read-token']);
  assert.deepEqual(SESSION_FIELDS['ios-firebase'], []);
  for (const kind of ['android-keystore', 'android-firebase', 'ios-firebase']) {
    assert.equal(isAssetFileKind(kind), true);
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind, replacement: null }), true);
  }
  for (const kind of ['apple-p12', 'apple-profile', 'asc-p8', 'google-wif', 'project-read-token', 'IOS-Firebase']) {
    assert.equal(isAssetFileKind(kind), false);
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind, replacement: null }), false);
  }
  for (const extra of ['path', 'filename', 'bytes', 'observation', 'bundleId', 'encoding']) {
    assert.equal(assetRequestFits('asset_choose', { contextRevision: 1, kind: 'ios-firebase', replacement: null, [extra]: 'PRIVATE_CANARY' }), false);
  }
  assert.equal(assetRequestFits('credential_prepare', { contextRevision: 1, source: { type: 'scalar', kind: 'ios-firebase', replacement: null }, fields: {} }), false);
  const value = status(2, { context: { ...context, platform: 'ios' }, operation: operation({ source: 'captured', assessment: firebaseAssessment('ios-firebase'),
    preview: { token: A, action: 'save', expiresInMs: 10000, subject: { kind: 'ios-firebase', change: 'new', recordId: null, recordRevision: null } } }) });
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
      ['unconfirmed intent', { observationFailed: true, intent: { kind: 'google-wif', change: 'new', record: null } }],
      ['project-path original', { status: status(2, { operation: operation({ operation: 'choose-project-path', phase: 'picking', settlement: 'pending', assessment: null, preview: null }) }) }],
      ['late-known original', { status: status(2, { operation: { ...idle, settlement: 'late-known' } }) }],
      ['selection', { status: status(2, { operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) }) }],
      ['review', { status: status(2, { operation: operation() }), previewDeadline: 1000 }],
      ['cancellation', { cancelledOperationId: 3, status: status(2, { operation: operation({ phase: 'stopping', settlement: 'pending', assessment: null, preview: null }) }) }],
      ['record change', { status: status(2, { records: [{ recordId: D, revision: 7, kind: 'android-firebase', availability: 'mutation-pending' }] }) }],
    ]) assert.notEqual(preparationSessionReason(target, { ...current, ...patch }, emptyPreparationLocal), null, label);
    for (const patch of [{ replacementId: D }, { replacementId: 'no-longer-present' }, { confirmLock: true }, { writeOnlyFormMounted: true }]) {
      const local = Object.freeze({ ...emptyPreparationLocal, ...patch });
      assert.notEqual(preparationSessionReason(target, current, local), null);
      assert.deepEqual(local, { ...emptyPreparationLocal, ...patch });
    }
    assert.match(preparationSessionReason(preparationView('apple-p12'), current, emptyPreparationLocal), /reference guide only/);
    assert.equal(preparationSessionReason(target, current, emptyPreparationLocal, 'Other original work is pending.'), 'Other original work is pending.');
    const same = preparationView('google-wif', current.scope), form = { ...emptyPreparationLocal, kindId: 'google-wif', writeOnlyFormMounted: true };
    assert.equal(preparationScopeChanged(same, current.scope), false);
    assert.equal(preparationSessionReason(same, current, form), null); // focus only; no key/scope/form change
    assert.notEqual(preparationSessionReason(preparationView('project-read-token', current.scope), current, form), null);
    const completed = { ...current, originPending: false, intent: { kind: 'google-wif', change: 'assign', record: { recordId: C, expectedRevision: 1 } },
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
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    assert.equal(h.controller.getSnapshot().previewDeadline, 10100);
    assert.equal(h.controller.confirmPreview(A, 'bind'), false);
    assert.equal(h.controller.confirmPreview(A, 'save'), true);
    assert.equal(h.controller.confirmPreview(A, 'save'), false);
    assert.equal(h.controller.discard(), false); // Previous Prepare ID cannot cancel this new Commit.
    assert.match(assetCancellationReason(h.controller.getSnapshot()), /no cancellation has been sent/u);
    assert.equal(h.calls.filter((call) => call.command === 'discard').length, 0);
    h.time(5000);
    const kept = { recordId: C, revision: 1, kind: 'google-wif', availability: 'unassigned' };
    h.latest('commit').resolve(status(3, { records: [kept], operation: operation({ operationId: 4, operation: 'commit', preview: { token: B, action: 'bind', expiresInMs: 10000,
      subject: { kind: 'google-wif', change: 'assign', recordId: C, recordRevision: 1 } } }) })); await settle();
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
    { recordId: C, revision: 0, kind: 'google-wif', availability: 'unassigned' },
    { recordId: D, revision: 7, kind: 'android-firebase', availability: 'unassigned' },
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
    assert.deepEqual(h.controller.getSnapshot().intent, { kind: 'android-firebase', change: 'replace', record: { recordId: D, expectedRevision: 7 } });
    assertPreparationPreservesOriginal(h);
    const pendingRecords = records.map((record) => record.recordId === D ? { ...record, availability: 'mutation-pending' } : record);
    h.latest('choose').resolve(status(2, { records: pendingRecords, operation: operation({ operation: 'choose-file', phase: 'selected', source: 'captured', selectionToken: A, assessment: null, preview: null }) })); await settle();
    const unsubscribe = h.controller.subscribe(() => {}); unsubscribe();
    const intent = h.controller.getSnapshot().intent;
    assert.deepEqual(intent, { kind: 'android-firebase', change: 'replace', record: { recordId: D, expectedRevision: 7 } });
    assertPreparationPreservesOriginal(h);
    assert.equal(h.controller.prepareSelection({}), true);
    assert.equal(h.controller.discard(), false); // Selected predecessor is not the new Prepare operation.
    assert.equal(h.controller.getSnapshot().originPending, true);
    assert.equal(h.calls.filter((call) => call.command === 'discard').length, 0);
    assert.deepEqual(h.latest('prepare').args.source, { type: 'selection', selectionToken: A });
    const subject = { kind: 'android-firebase', change: 'replace', recordId: D, recordRevision: 7 };
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
    const subject = { kind: 'ios-firebase', change: 'new', recordId: null, recordRevision: null };
    h.latest('prepare').resolve(ios(3, { operation: operation({ operationId: 4, source: 'captured', assessment: firebaseAssessment('ios-firebase'),
      preview: { token: B, action: 'save', expiresInMs: 9000, subject } }) })); await settle();
    assert.equal(h.controller.getSnapshot().reviewReady, true);
    assert.equal(h.controller.confirmPreview(B, 'save'), true);
    const records = [{ recordId: D, revision: 1, kind: 'ios-firebase', availability: 'unassigned' }];
    h.latest('commit').resolve(ios(4, { records, operation: operation({ operationId: 5, operation: 'commit', source: 'captured', assessment: firebaseAssessment('ios-firebase'),
      preview: { token: C, action: 'bind', expiresInMs: 8000, subject: { kind: 'ios-firebase', change: 'assign', recordId: D, recordRevision: 1 } } }) })); await settle();
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

test('removal identifies the exact record; another valid subject or unrelated newer operation cannot confirm', async () => {
  const records = [
    { recordId: B, revision: 0, kind: 'android-keystore', availability: 'unassigned' },
    { recordId: C, revision: 7, kind: 'google-wif', availability: 'unassigned' },
    { recordId: D, revision: 2, kind: 'google-wif', availability: 'unassigned' },
  ];
  const h = harness();
  try {
    await ready(h, { records });
    assert.equal(h.controller.prepareDelete({ recordId: C, expectedRevision: 7 }), true);
    const subject = { kind: 'google-wif', change: 'delete', recordId: C, recordRevision: 7 };
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
  assert.deepEqual(guide, original);
});

test('an overtaking event cannot replace the review carried by the original command reply', async () => {
  const h = harness();
  try {
    await ready(h);
    h.controller.prepareScalar('google-wif', fields);
    h.latest('prepare').resolve(status(2, { operation: operation() })); await settle();
    assert.equal(h.controller.confirmPreview(A, 'save'), true);
    const kept = { recordId: C, revision: 1, kind: 'google-wif', availability: 'unassigned' };
    const original = status(3, { records: [kept], operation: operation({ operationId: 4, operation: 'commit',
      preview: { token: B, action: 'bind', expiresInMs: 9000, subject: { kind: 'google-wif', change: 'assign', recordId: C, recordRevision: 1 } } }) });
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
