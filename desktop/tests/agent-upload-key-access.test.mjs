// Original controllers, strict codecs and bounded inert promises only. No
// native process, key material, vault, service, account or IPC is constructed.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { AgentUploadKeyAccessController } from '../src/agentUploadKeyAccessController.ts';
import { AGENT_UPLOAD_KEY_DECLARATION, agentUploadKeyCommands, agentUploadKeySelection,
  createAgentUploadKeyAccessPort, parseAgentUploadKeyAccess, parseAgentUploadKeySelection } from '../src/agentUploadKeyAccess.ts';

const id = (c) => c.repeat(32);
const scope = { platform: 'android', stage: 'candidate', purpose: 'signing', executionMode: 'local' };
const context = { revision: 1, projectId: 'inert-project', ...scope };
const capability = { available: true, reason: 'none' };
function row(patch = {}) { return { recordId: id('c'), revision: 1, kind: 'android-keystore',
  storage: 'encrypted', availability: 'unassigned', label: null, payloadState: 'not-checked', ...patch }; }
function assets(revision = 1, patch = {}) { return { schemaVersion: 3, statusRevision: revision, mode: 'encrypted',
  persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { ...capability },
  modes: { session: { ...capability }, encrypted: { ...capability } }, context: { ...context }, records: [], assignments: [], operation: null, ...patch }; }
function keyStatus(revision = 1, patch = {}) { return { schemaVersion: 1, assets: assets(revision), capability: { ...capability },
  setup: 'required', plan: 'unavailable', operation: null, saved: null, ...patch }; }
function checkedAssessment() { return { schemaVersion: 1, policyVersion: 'credential-policy-v1', kind: 'android-keystore',
  context: { ...scope }, applicability: { state: 'required', reason: 'selected' }, state: 'configured', identity: 'not-applicable',
  fields: [['file', 'ANDROID_KEYSTORE_BASE64'], ['storePassword', 'ANDROID_KEYSTORE_PASSWORD'], ['keyAlias', 'ANDROID_KEY_ALIAS'], ['keyPassword', 'ANDROID_KEY_PASSWORD']]
    .map(([field, requirement]) => ({ id: field, requirement: `MOBILE_RELEASE_${requirement}`, presence: 'supplied', state: 'configured', issues: [],
      checks: [{ scope: field === 'file' ? 'jks-header' : 'value-admission', outcome: field === 'file' ? 'asserted-pass' : 'passed' }] })),
  assurance: { basis: 'supplied-input-only', scalarValuesProcessed: true, fileObservationsProcessed: true, selectedFilesRead: false,
    keyringAccessed: false, storageWritesPerformed: false, projectCodeExecuted: false, sourceCustody: 'not-established',
    nativeValidation: 'not-run', serviceValidation: 'not-run', releaseReadiness: 'unknown' } }; }
function preview(revision = 2, patch = {}) { return assets(revision, { records: [row({ payloadState: 'assessed' })],
  operation: { operationId: 7, operation: 'prepare', phase: 'preview', reason: 'none', source: 'captured', settlement: 'known',
    storageOutcome: null, selectionToken: null, assessment: checkedAssessment(), preview: { token: id('a'), action: 'bind', expiresInMs: 10_000,
      subject: { type: 'record', kind: 'android-keystore', change: 'assign', recordId: id('c'), recordRevision: 1 } } }, ...patch }); }
function empty() { return { schemaVersion: 1, serviceInstance: null, projectId: null, grantId: null, kind: null,
  requestId: null, enabled: false, remainingMs: 0, consumed: false }; }
function access(kind = 'bind-reviewed', patch = {}) { return { schemaVersion: 1, serviceInstance: id('b'), projectId: id('a'),
  grantId: id('d'), kind, requestId: null, enabled: true, remainingMs: 299_900, consumed: false, ...patch }; }
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function settle() { for (let i = 0; i < 16; ++i) await Promise.resolve(); }
function nativeHarness(t) {
  let project = { project: { id: context.projectId, name: 'Inert project' }, draft: { schemaVersion: 1 }, revision: 1, baselineGeneration: 1 };
  let current = assets(0), event, now = 100;
  const calls = [];
  const pending = (command, args) => { const work = deferred(); calls.push({ command, args, ...work }); return work.promise; };
  const api = { mode: 'native', assetStatus: async () => current, subscribeAssets: async (fn) => { event = fn; return () => {}; },
    setAssetContext: (args) => pending('context', args), prepareCredential: (args) => pending('assess', args),
    uploadKeyStatus: (args) => pending('key-status', args), prepareUploadKey: (args) => pending('setup', args),
    createUploadKey: (args) => pending('create', args), bindAsset: (args) => pending('bind', args),
    discardAsset: (args) => pending('discard', args), exportCredentialBackup: (args) => pending('backup', args) };
  const controller = new AssetSessionController(() => project, () => now);
  controller.setScope(scope);
  t.after(() => { controller.dispose(); for (const c of calls) c.reject({ code: 'inert_closed' }); });
  return { controller, api, calls, project: () => project, now: () => now,
    time: (value) => { now = value; }, changeProject: () => { project = { ...project, revision: project.revision + 1 }; },
    last: (command) => calls.filter((c) => c.command === command).at(-1),
    emit: (value) => { current = value; event(value); },
    reply: (command, value) => { current = value.assets ?? value; calls.filter((c) => c.command === command).at(-1).resolve(value); } };
}
async function ready(h, existing = false) {
  await h.controller.connect(h.api); h.controller.submitContext(); await settle();
  h.reply('context', assets(1, { records: existing ? [row()] : [] })); await settle();
  assert.equal(h.controller.getSnapshot().contextCurrent, true);
}
async function reviewed(t, kind = 'bind-reviewed') {
  const h = nativeHarness(t); await ready(h, kind === 'bind-reviewed');
  if (kind === 'generate-new') {
    const read = h.controller.checkUploadKeyStatus(); await settle(); h.reply('key-status', keyStatus()); await read;
    assert.equal(h.controller.prepareUploadKey(h.controller.getSnapshot()), true);
    h.reply('setup', keyStatus(2, { setup: 'ready', plan: 'confirm-application-history' })); await settle();
    assert.equal(h.controller.canConfirmUploadKey(h.controller.getSnapshot()), true);
  } else {
    assert.ok(parseAssetStatus(preview()), 'inert assessment is valid display DATA, not native validation');
    assert.equal(h.controller.prepareRecord({ recordId: id('c'), expectedRevision: 1 }), true);
    h.reply('assess', preview()); await settle(); assert.equal(h.controller.getSnapshot().reviewReady, true);
  }
  return h;
}
function permission(t, h) {
  const calls = [], session = {}, source = { blocked: null, port: null, project: null, assets: null };
  const pending = (command, input) => { const d = deferred(); calls.push({ command, input, ...d }); return d.promise; };
  const port = { status: () => pending('status'), allow: (v) => pending('allow', v), revoke: (v) => pending('revoke', v) };
  source.port = port;
  let nonce = 'd';
  const controller = new AgentUploadKeyAccessController({ current: () => ({ port: source.port, nativeSession: session,
    projectId: context.projectId, project: source.project ?? h.project(), assets: source.assets ?? h.controller.getSnapshot(),
    generateReady: h.controller.canConfirmUploadKey(h.controller.getSnapshot()), blockedReason: source.blocked }),
    now: h.now, nonce: () => id(nonce) });
  t.after(async () => { controller.dispose(); for (const c of calls) c.reject({ code: 'inert_closed' }); await controller.whenSettled(); });
  return { controller, calls, source, port, nonce: (c) => { nonce = c; }, last: () => calls.at(-1) };
}
function consent(p, kind = 'bind-reviewed') {
  assert.equal(p.controller.setKind(kind), true);
  if (kind === 'generate-new') assert.equal(p.controller.setNewApplication(true), true);
  assert.equal(p.controller.setAcknowledged(true), true); assert.equal(p.controller.allowReason(), null);
}
function noPrivateWork(h) { assert.equal(h.calls.some((c) => ['create', 'bind', 'backup'].includes(c.command)), false); }

test('strict nullable access and closed selections reject upgrades, getters and private inputs', () => {
  assert.deepEqual(parseAgentUploadKeyAccess(empty()), empty()); assert.deepEqual(parseAgentUploadKeyAccess(access()), access());
  for (const mutate of [v => delete v.grantId, v => { v.saved = true; }, v => { v.kind = 'backup'; },
    v => { v.requestId = id('f'); }, v => { v.remainingMs = 300001; }, v => { v.remainingMs = -0; },
    v => { v.enabled = false; }, v => { v.projectId = null; }, v => { v.serviceInstance = '0'.repeat(32); }]) {
    const v = access(); mutate(v); assert.equal(parseAgentUploadKeyAccess(v), null);
  }
  let read = false; const v = access(); Object.defineProperty(v, 'kind', { enumerable: true, get() { read = true; return 'bind-reviewed'; } });
  assert.equal(parseAgentUploadKeyAccess(v), null); assert.equal(read, false);
  for (const s of [{ kind: 'generate-new', declaration: AGENT_UPLOAD_KEY_DECLARATION }, { kind: 'bind-reviewed', previewOperationId: 7, previewToken: id('a') }]) {
    assert.ok(parseAgentUploadKeySelection(s));
    for (const key of ['password', 'path', 'file', 'replace', 'autoBind', 'backup']) assert.equal(parseAgentUploadKeySelection({ ...s, [key]: 'refused' }), null);
  }
  assert.equal(parseAgentUploadKeySelection({ kind: 'generate-new' }), null);
  assert.equal(parseAgentUploadKeySelection({ kind: 'bind-reviewed', previewOperationId: 0, previewToken: id('a') }), null);
});

test('actual fixed RAW adapter sends only three commands and kind-derived consent, not private input', async () => {
  const calls = [], port = createAgentUploadKeyAccessPort(async (command, body) => { calls.push({ command, bytes: body.byteLength, body: JSON.parse(new TextDecoder().decode(body)) }); return empty(); });
  await port.status();
  for (const selection of [{ kind: 'generate-new', declaration: AGENT_UPLOAD_KEY_DECLARATION }, { kind: 'bind-reviewed', previewOperationId: 7, previewToken: id('a') }])
    await port.allow({ projectId: context.projectId, consentId: id('d'), contextRevision: 1, expectedStatusRevision: 2, selection });
  await port.revoke(id('d'));
  assert.deepEqual(calls.map(c => c.command), ['agent_upload_key_access', 'allow_agent_upload_key', 'allow_agent_upload_key', 'revoke_agent_upload_key']);
  assert.equal(calls[1].body.consentVersion, 'agent-android-upload-key-generate-once-v1');
  assert.equal(calls[2].body.consentVersion, 'agent-android-upload-key-bind-once-v1');
  assert.ok(calls.every(c => c.bytes + 96 <= 1024));
  await assert.rejects(port.revoke('not-an-id'));
  await assert.rejects(port.allow({ projectId: context.projectId, consentId: id('d'), contextRevision: 1, expectedStatusRevision: 2,
    selection: { kind: 'generate-new', declaration: AGENT_UPLOAD_KEY_DECLARATION, password: 'never-forwarded' } }));
  assert.equal(calls.length, 4);
});

test('mount and permission status do not turn an ordinary stored record into a Bind review', async t => {
  const h = nativeHarness(t); await ready(h, true); const p = permission(t, h);
  assert.equal(p.calls.length, 0); assert.equal(p.controller.setAcknowledged(true), false);
  const read = p.controller.check(); p.last().resolve(access()); await read;
  assert.equal(p.controller.getSnapshot().access.enabled, true);
  assert.equal(p.controller.getSnapshot().acknowledged, false); assert.equal(await p.controller.allow(), false);
  // Do not use the observed Access as a new native review or completion.
  await p.controller.whenSettled(); noPrivateWork(h);
});

for (const kind of ['generate-new', 'bind-reviewed']) test(`${kind}: exact joined Desktop review gets a separately unchecked one-use permission, never key work`, async t => {
  const h = await reviewed(t, kind), p = permission(t, h);
  assert.equal(p.calls.length, 0); assert.notEqual(p.controller.allowReason(), null);
  consent(p, kind);
  const original = p.controller.allow(); assert.equal(p.calls.length, 1);
  assert.equal(await p.controller.allow(), false);
  assert.deepEqual(p.last().input, { projectId: context.projectId, consentId: id('d'), contextRevision: 1, expectedStatusRevision: 2,
    selection: kind === 'generate-new' ? { kind, declaration: AGENT_UPLOAD_KEY_DECLARATION } : { kind, previewOperationId: 7, previewToken: id('a') } });
  p.last().resolve(access(kind)); assert.equal(await original, true);
  assert.equal(p.controller.getSnapshot().acknowledged, false);
  const observe = p.controller.check(); p.last().resolve(access(kind, { enabled: false, remainingMs: 0, consumed: true, requestId: id('e') })); await observe;
  assert.equal(p.controller.getSnapshot().unknown, false); assert.equal(p.controller.getSnapshot().access.consumed, true);
  assert.deepEqual(agentUploadKeyCommands(p.controller.getSnapshot().access), [
    `mrk upload-key-status ${id('a')} ${id('b')} ${id('e')} --json`, `mrk upload-key-cancel ${id('a')} ${id('b')} ${id('e')} --json`]);
  assert.equal(p.controller.setAcknowledged(true), false, 'same review cannot regain consent from status'); noPrivateWork(h);
});

test('new generation needs the actual ordinary Setup and refuses every existing or uncertain key shape', async t => {
  const h = nativeHarness(t); await ready(h); const base = h.controller.getSnapshot();
  assert.equal(agentUploadKeySelection(base, 'generate-new', false, 100), null);
  const prepared = await reviewed(t, 'generate-new');
  const actual = prepared.controller.getSnapshot();
  assert.ok(agentUploadKeySelection(actual, 'generate-new', true, 100));
  for (const changed of [
    { ...actual, status: { ...actual.status, records: [row()] } },
    { ...actual, status: { ...actual.status, records: [row({ availability: 'mutation-pending' })] } },
    { ...actual, observationFailed: true }, { ...actual, originPending: true }, { ...actual, contextCurrent: false },
    { ...actual, status: { ...actual.status, context: { ...actual.status.context, executionMode: 'github' } } },
    { ...actual, status: { ...actual.status, persistence: { ...actual.status.persistence, keyAccess: 'read-only' } } },
  ]) assert.equal(agentUploadKeySelection(changed, 'generate-new', true, 100), null);
  noPrivateWork(h); noPrivateWork(prepared);
});

test('native preview event before its original Prepare return never enables delegation; expiry is original', async t => {
  const h = nativeHarness(t); await ready(h, true);
  assert.equal(h.controller.prepareRecord({ recordId: id('c'), expectedRevision: 1 }), true);
  h.emit(preview()); const p = permission(t, h);
  assert.equal(p.controller.setAcknowledged(true), false);
  h.reply('assess', preview()); await settle(); p.controller.syncContext();
  consent(p); const end = h.controller.getSnapshot().previewDeadline;
  h.time(end); assert.equal(await p.controller.allow(), false); assert.equal(p.calls.length, 0);
  assert.equal(h.controller.getSnapshot().previewDeadline, end); noPrivateWork(h);
});

test('reentrant peer/source/selection/ABA/reconnect/disposal/expiry after publication prevents native Allow', async t => {
  for (const change of ['peer', 'project', 'status', 'context-aba', 'api', 'dispose', 'expiry']) {
    const h = await reviewed(t), p = permission(t, h); consent(p); let fired = false;
    const unsub = p.controller.subscribe(() => {
      if (fired || p.controller.getSnapshot().pending !== 'allow') return; fired = true;
      if (change === 'peer') p.source.blocked = 'Another original action';
      if (change === 'project') h.changeProject();
      if (change === 'status') h.emit(preview(3));
      if (change === 'context-aba') {
        p.source.project = {}; p.controller.syncContext(); p.source.project = null; p.controller.syncContext();
      }
      if (change === 'api') p.source.port = { ...p.port };
      if (change === 'dispose') p.controller.dispose();
      if (change === 'expiry') h.time(h.controller.getSnapshot().previewDeadline);
    });
    assert.equal(await p.controller.allow(), false, change); unsub(); assert.equal(fired, true);
    assert.equal(p.calls.length, 0, change); noPrivateWork(h);
  }
});

test('lost Allow retains the original consent and Unknown; status and exact withdrawal never re-enable it', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p);
  const original = p.controller.allow(); p.last().reject({ code: 'lost_reply' }); await original;
  assert.equal(p.controller.getSnapshot().unknown, true); assert.equal(p.controller.revokeReason(), null);
  const oldPort = p.port; p.source.port = { status: () => { throw Error('replacement must not be called'); }, allow: oldPort.allow, revoke: oldPort.revoke };
  const check = p.controller.check(); assert.equal(p.last().command, 'status');
  p.last().resolve(access('bind-reviewed', { enabled: false, remainingMs: 0, consumed: true, requestId: id('e') })); await check;
  const withdraw = p.controller.revoke(); assert.equal(p.last().input, id('d'));
  p.last().resolve(access('bind-reviewed', { enabled: false, remainingMs: 0, consumed: true, requestId: id('e') })); await withdraw;
  assert.equal(p.controller.getSnapshot().unknown, true); assert.equal(p.controller.getSnapshot().access.enabled, false);
  assert.equal(await p.controller.allow(), false); assert.equal(p.calls.filter(c => c.command === 'allow').length, 1); noPrivateWork(h);
});

test('withdrawal may overtake a still retained Allow but late Allow cannot restore consent or replace its original', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p);
  const allow = p.controller.allow(), old = p.last();
  const revoke = p.controller.revoke(), current = p.last(); assert.equal(current.input, old.input.consentId);
  current.resolve(access('bind-reviewed', { enabled: false, remainingMs: 0 })); await revoke;
  let returned = false; const joined = p.controller.whenSettled().then(() => { returned = true; });
  await settle(); assert.equal(returned, false); assert.equal(p.controller.getSnapshot().pending, 'allow');
  old.resolve(access()); await allow; await joined;
  assert.equal(p.controller.getSnapshot().access.enabled, false); assert.equal(p.controller.getSnapshot().unknown, false);
  assert.equal(p.controller.setAcknowledged(true), false); noPrivateWork(h);
});

test('pre-Allow withdrawal keeps the exact original pending through late rejection or loss, and a lost withdrawal stays Unknown', async t => {
  for (const returned of ['conflict', 'lost-allow', 'lost-revoke']) {
    const h = await reviewed(t), p = permission(t, h); consent(p);
    const allow = p.controller.allow(), old = p.last();
    const revoke = p.controller.revoke(), withdrawal = p.last();
    assert.equal(withdrawal.input, old.input.consentId);
    // Empty/off is the real native contract after the exact nonce is retained
    // before the first Allow Doc cut. Native State tests prove that tombstone;
    // this inert port only exercises original controller replies and joins.
    if (returned === 'lost-revoke') withdrawal.reject({ code: 'lost_reply' });
    else withdrawal.resolve(empty());
    await revoke;
    let returnedAll = false;
    const joined = p.controller.whenSettled().then(() => { returnedAll = true; });
    await settle(); assert.equal(returnedAll, false);
    assert.equal(p.controller.getSnapshot().pending, 'allow');
    old.reject({ code: returned === 'lost-allow' ? 'lost_reply' : 'conflict' });
    await allow; await joined;
    assert.equal(p.controller.getSnapshot().unknown, returned === 'lost-revoke');
    assert.notEqual(p.controller.getSnapshot().access?.enabled, true);
    assert.equal(p.controller.setAcknowledged(true), false, 'an old review never regains consent');
    assert.equal(await p.controller.allow(), false);
    assert.deepEqual(p.calls.map(c => c.command), ['allow', 'revoke']); noPrivateWork(h);
  }
});

test('a consumed original permission blocks a genuinely fresh review until its exact returned withdrawal, not Check or countdown', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p);
  const consumed = access('bind-reviewed', { enabled: false, remainingMs: 0, consumed: true, requestId: id('e') });
  const first = p.controller.allow(); p.last().resolve(consumed); await first;

  // A foreign settled operation is display DATA only, not a reconstructed
  // original receipt. The fresh preview below comes from a NEW actual Prepare
  // invocation on the real Asset controller, with its own returned promise.
  const idle = assets(3, { records: [row({ payloadState: 'assessed' })], operation: {
    operationId: 8, operation: 'bind', phase: 'idle', reason: 'none', source: 'captured', settlement: 'known',
    storageOutcome: null, selectionToken: null, assessment: null, preview: null } });
  assert.ok(parseAssetStatus(idle)); h.emit(idle);
  assert.equal(h.controller.prepareRecord({ recordId: id('c'), expectedRevision: 1 }), true);
  const next = preview(4); next.operation.operationId = 9; next.operation.preview.token = id('f');
  h.reply('assess', next); await settle();
  assert.equal(h.controller.getSnapshot().reviewReady, true);
  p.controller.syncContext();
  assert.ok(agentUploadKeySelection(h.controller.getSnapshot(), 'bind-reviewed', false, h.now()));
  assert.match(p.controller.ownerReason(), /Withdraw that exact permission/);
  assert.equal(p.controller.setAcknowledged(true), false);
  assert.equal(await p.controller.allow(), false);
  const check = p.controller.check(); p.last().resolve(consumed); await check;
  assert.match(p.controller.ownerReason(), /Withdraw that exact permission/);
  assert.equal(p.controller.setAcknowledged(true), false, 'consumed/zero remaining time is not withdrawal');
  assert.equal(p.calls.filter(c => c.command === 'allow').length, 1);
  assert.match(agentUploadKeyCommands(p.controller.getSnapshot().access)[0], new RegExp(id('e')));

  const revoke = p.controller.revoke(); assert.equal(p.last().input, id('d'));
  p.last().resolve(consumed); await revoke;
  assert.equal(p.controller.getSnapshot().unknown, false);
  assert.equal(p.controller.ownerReason(), null);
  assert.match(agentUploadKeyCommands(p.controller.getSnapshot().access)[0], new RegExp(id('e')),
    'withdrawal does not claim that the old request completed or discard its address');
  p.nonce('9'); consent(p);
  const second = p.controller.allow();
  assert.equal(p.last().input.consentId, id('9'));
  assert.deepEqual(p.last().input.selection, { kind: 'bind-reviewed', previewOperationId: 9, previewToken: id('f') });
  p.last().resolve(access('bind-reviewed', { grantId: id('9') })); await second;
  assert.equal(p.controller.getSnapshot().unknown, false);
  assert.equal(p.controller.getSnapshot().access.grantId, id('9'));
  assert.equal(p.calls.filter(c => c.command === 'allow').length, 2); noPrivateWork(h);
});

test('synchronous withdrawal before Allow dispatch sends only the exact revoked nonce', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p); let revoke = null;
  const off = p.controller.subscribe(() => { if (!revoke && p.controller.getSnapshot().pending === 'allow' && !p.controller.getSnapshot().revoking) revoke = p.controller.revoke(); });
  const allow = p.controller.allow(); off(); assert.equal(p.calls.length, 1); assert.equal(p.last().command, 'revoke');
  p.last().resolve(empty()); await revoke; assert.equal(await allow, false);
  assert.equal(p.controller.getSnapshot().access.enabled, false); assert.equal(p.controller.getSnapshot().unknown, false); noPrivateWork(h);
});

test('original countdown only decreases; valid-shaped identity, consumed or revocation contradictions become Unknown', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p);
  const allow = p.controller.allow(); p.last().resolve(access('bind-reviewed', { remainingMs: 9000 })); await allow;
  h.time(5100); const check = p.controller.check(); p.last().resolve(access('bind-reviewed', { remainingMs: 9000 })); await check;
  assert.equal(p.controller.remainingSeconds(), 4); assert.equal(p.controller.getSnapshot().unknown, false);
  const mismatch = p.controller.check(); p.last().resolve(access('bind-reviewed', { projectId: id('f'), remainingMs: 1000 })); await mismatch;
  assert.equal(p.controller.getSnapshot().unknown, true);
  for (const wrong of ['request', 'reenable', 'revoke-live']) {
    const h2 = await reviewed(t), p2 = permission(t, h2); consent(p2);
    const a = p2.controller.allow(); p2.last().resolve(access('bind-reviewed', { enabled: false, remainingMs: 0, consumed: true, requestId: id('e') })); await a;
    const q = wrong === 'revoke-live' ? p2.controller.revoke() : p2.controller.check();
    p2.last().resolve(wrong === 'request' ? access('bind-reviewed', { enabled: false, remainingMs: 0, consumed: true, requestId: id('f') }) : access()); await q;
    assert.equal(p2.controller.getSnapshot().unknown, true, wrong); noPrivateWork(h2);
  }
});

test('a newer Asset/context while Allow returns preserves historical permission only and requires withdrawal', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p);
  const original = p.controller.allow(); h.emit(preview(3)); p.controller.syncContext();
  p.last().resolve(access()); await original;
  assert.equal(p.controller.getSnapshot().stale, true); assert.equal(p.controller.remainingSeconds(), null);
  assert.equal(p.controller.getSnapshot().acknowledged, false); assert.notEqual(p.controller.allowReason(), null);
  assert.equal(p.controller.revokeReason(), null); noPrivateWork(h);
});

test('disposed controller keeps both original promises joined and publishes no fabricated completion', async t => {
  const h = await reviewed(t), p = permission(t, h); consent(p);
  const a = p.controller.allow(), old = p.last(), r = p.controller.revoke(), rev = p.last();
  p.controller.dispose(); let joined = false; const done = p.controller.whenSettled().then(() => { joined = true; });
  old.reject({ code: 'unconfirmed' }); await a; await settle(); assert.equal(joined, false);
  rev.reject({ code: 'unconfirmed' }); await r; await done; assert.equal(joined, true);
  assert.equal(p.controller.getSnapshot().access, null); assert.equal(await p.controller.check(), false); noPrivateWork(h);
});
