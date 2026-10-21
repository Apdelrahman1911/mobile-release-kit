// Existing real Asset/permission controllers with inert promises and public
// comparison DATA only. No picker, vault, IPC, credential or key is acquired.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { AgentUploadKeyAccessController } from '../src/agentUploadKeyAccessController.ts';
import { agentUploadKeySelection, agentUploadKeyCommands, createAgentUploadKeyAccessPort,
  parseAgentUploadKeyAccess, parseAgentUploadKeySelection } from '../src/agentUploadKeyAccess.ts';
import { agentUploadKeyBackupOptions, agentUploadKeyBackupSelection, AGENT_UPLOAD_KEY_RESTORE_DECLARATION } from '../src/agentUploadKeyBackup.ts';

const id = c => c.repeat(32);
const scope = { platform: 'android', stage: 'candidate', purpose: 'signing', executionMode: 'local' };
const context = { revision: 1, projectId: 'inert-backup-project', ...scope };
const available = { available: true, reason: 'none' };
const row = (c = 'c', patch = {}) => ({ recordId: id(c), revision: 1, kind: 'android-keystore',
  storage: 'encrypted', availability: 'unassigned', label: null, payloadState: 'not-checked', ...patch });
const status = (revision = 1, patch = {}) => ({ schemaVersion: 3, statusRevision: revision, mode: 'encrypted',
  persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' }, capability: { ...available },
  modes: { session: { ...available }, encrypted: { ...available } }, backup: { ...available },
  context: { ...context }, records: [row(), row('d')], assignments: [], operation: null, ...patch });
const empty = () => ({ schemaVersion: 1, serviceInstance: null, projectId: null, grantId: null, kind: null,
  requestId: null, enabled: false, remainingMs: 0, consumed: false });
const access = (kind, patch = {}) => ({ schemaVersion: 1, serviceInstance: id('b'), projectId: id('a'), grantId: id('e'),
  kind, requestId: null, enabled: true, remainingMs: 299_000, consumed: false, ...patch });
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 12; ++i) await Promise.resolve(); }

async function fixture(t, initial = status()) {
  let current = status(0), event, now = 100, project = { project: { id: context.projectId, name: 'Inert project' },
    draft: { schemaVersion: 1 }, revision: 1, baselineGeneration: 1 };
  const assetCalls = [], permissionCalls = [];
  const call = (list, command, input) => { const d = deferred(); list.push({ command, input, ...d }); return d.promise; };
  const api = { mode: 'native', assetStatus: async () => current, subscribeAssets: async fn => { event = fn; return () => {}; },
    setAssetContext: input => call(assetCalls, 'context', input), prepareCredential: input => call(assetCalls, 'assess', input),
    bindAsset: input => call(assetCalls, 'bind', input), createUploadKey: input => call(assetCalls, 'generate', input),
    exportCredentialBackup: input => call(assetCalls, 'backup', input), importCredentialBackup: input => call(assetCalls, 'restore', input) };
  const assets = new AssetSessionController(() => project, () => now); assets.setScope(scope);
  await assets.connect(api); assets.submitContext(); await flush();
  assert.equal(assetCalls.at(-1)?.command, 'context');
  current = initial; assetCalls.at(-1).resolve(current); await flush();
  assert.equal(assets.getSnapshot().contextCurrent, true); assert.ok(parseAssetStatus(initial));
  const port = { status: () => call(permissionCalls, 'status'), allow: input => call(permissionCalls, 'allow', input),
    revoke: input => call(permissionCalls, 'revoke', input) };
  const nativeSession = {}; let currentPort = port, nonce = 'e';
  const controller = new AgentUploadKeyAccessController({ current: () => ({ port: currentPort, nativeSession,
    projectId: context.projectId, project, assets: assets.getSnapshot(), generateReady: false, blockedReason: null }),
    now: () => now, nonce: () => id(nonce) });
  t.after(async () => { controller.dispose(); assets.dispose();
    for (const c of [...assetCalls, ...permissionCalls]) c.reject({ code: 'inert_closed' });
    await controller.whenSettled(); });
  return { controller, assets, api, assetCalls, permissionCalls, port,
    last: () => permissionCalls.at(-1), time: n => { now = n; }, nonce: c => { nonce = c; },
    emit: value => { current = value; event(value); }, changeProject: () => { project = { ...project, revision: project.revision + 1 }; },
    disconnect: () => { currentPort = null; }, reconnect: () => { currentPort = port; } };
}
function choose(h, kind) {
  assert.equal(h.controller.setKind(kind), true);
  if (kind === 'backup-encrypted') assert.equal(h.controller.setBackupRecord({ recordId: id('c'), expectedRevision: 1 }), true);
  assert.equal(h.controller.setAcknowledged(true), true); assert.equal(h.controller.allowReason(), null);
}
function noNativeAction(h) { assert.ok(h.assetCalls.every(c => c.command === 'context' || c.command === 'assess')); }

test('strict new kind selections keep actual native file choices and private fields out of RAW', async () => {
  const selections = [{ kind: 'backup-encrypted', recordId: id('c'), expectedRevision: 1 },
    { kind: 'restore-encrypted', declaration: AGENT_UPLOAD_KEY_RESTORE_DECLARATION }];
  const calls = [], port = createAgentUploadKeyAccessPort(async (command, bytes) => {
    calls.push({ command, bytes: bytes.byteLength, body: JSON.parse(new TextDecoder().decode(bytes)) }); return empty();
  });
  for (const selection of selections) {
    assert.deepEqual(parseAgentUploadKeySelection(selection), selection);
    assert.ok(parseAgentUploadKeyAccess(access(selection.kind)));
    await port.allow({ projectId: context.projectId, consentId: id('e'), contextRevision: 1, expectedStatusRevision: 1, selection });
    for (const field of ['path', 'password', 'recoveryCode', 'backupPath', 'replace', 'autoBind', 'fields']) {
      assert.equal(parseAgentUploadKeySelection({ ...selection, [field]: 'never-send' }), null);
      await assert.rejects(port.allow({ projectId: context.projectId, consentId: id('e'), contextRevision: 1,
        expectedStatusRevision: 1, selection: { ...selection, [field]: 'never-send' } }));
    }
  }
  assert.deepEqual(calls.map(c => c.command), ['allow_agent_upload_key', 'allow_agent_upload_key']);
  assert.deepEqual(calls.map(c => c.body.consentVersion), ['agent-android-upload-key-backup-once-v1', 'agent-android-upload-key-restore-once-v1']);
  assert.ok(calls.every(c => c.bytes + 96 <= 1024));
  for (const s of [{ kind: 'restore-encrypted' }, { kind: 'restore-encrypted', declaration: 'replace-existing' },
    { kind: 'backup-encrypted', recordId: id('c'), expectedRevision: 0 },
    { kind: 'backup-encrypted', recordId: id('c'), expectedRevision: 0xffff_ffff }]) assert.equal(parseAgentUploadKeySelection(s), null);
  let read = false; const getter = { ...selections[0] }; Object.defineProperty(getter, 'recordId', { enumerable: true, get() { read = true; return id('c'); } });
  assert.equal(parseAgentUploadKeySelection(getter), null); assert.equal(read, false);
});

test('current backup capability is mandatory; no row/list data upgrades an unavailable route', async t => {
  const h = await fixture(t, status(1, { backup: { available: false, reason: 'unqualified' } }));
  for (const kind of ['backup-encrypted', 'restore-encrypted']) {
    assert.equal(h.controller.setKind(kind), true); assert.equal(h.controller.setAcknowledged(true), false);
    assert.match(h.controller.selectionReason(), /cannot enable or bypass/); assert.equal(await h.controller.allow(), false);
  }
  assert.deepEqual(h.controller.backupOptions(), []); assert.equal(h.permissionCalls.length, 0); noNativeAction(h);
});

test('backup needs one explicit exact encrypted Android row and rejects stale, duplicate and foreign rows', async t => {
  const h = await fixture(t);
  assert.equal(h.controller.setKind('backup-encrypted'), true); assert.equal(h.controller.setAcknowledged(true), false);
  assert.equal(h.controller.getSnapshot().backupRecord, null);
  assert.equal(h.controller.setBackupRecord({ recordId: id('c'), expectedRevision: 2 }), false);
  assert.equal(h.controller.setBackupRecord({ recordId: id('c'), expectedRevision: 1 }), true);
  assert.equal(h.controller.setAcknowledged(true), true);
  assert.equal(h.controller.setBackupRecord({ recordId: id('d'), expectedRevision: 1 }), true);
  assert.equal(h.controller.getSnapshot().acknowledged, false);
  const view = h.assets.getSnapshot();
  for (const records of [[row(), row()], [row('c', { kind: 'asc-p8' })], [row('c', { availability: 'mutation-pending' })],
    [row('c', { storage: 'session' })]]) {
    const changed = { ...view, status: { ...view.status, records } };
    assert.equal(agentUploadKeyBackupSelection(changed, 'backup-encrypted', { recordId: id('c'), expectedRevision: 1 }), null);
    assert.deepEqual(agentUploadKeyBackupOptions(changed), []);
  }
  assert.equal(h.permissionCalls.length, 0); noNativeAction(h);
});

for (const kind of ['backup-encrypted', 'restore-encrypted']) test(`${kind}: explicit one-use Allow dispatches only permission, never a picker or follow-up`, async t => {
  const h = await fixture(t); assert.equal(h.permissionCalls.length, 0); choose(h, kind);
  const call = h.controller.allow();
  assert.equal(h.last().command, 'allow'); assert.equal(h.last().input.selection.kind, kind);
  assert.equal(h.controller.getSnapshot().acknowledged, false);
  h.last().resolve(access(kind)); await call;
  assert.equal(await h.controller.allow(), false); assert.equal(h.permissionCalls.length, 1);
  assert.equal(h.controller.setKind('bind-reviewed'), false);
  assert.deepEqual(agentUploadKeyCommands(h.controller.getSnapshot().access), [`mrk upload-key-submit ${id('a')} ${id('b')} ${id('e')} --reviewed --json`]);
  noNativeAction(h);
});

test('restore receipt/list cannot manufacture Bind: only a separately joined real Asset preview may be delegated', async t => {
  const h = await fixture(t, status(1, { records: [row('d')], operation: {
    operationId: 9, operation: 'import-backup', phase: 'idle', reason: 'none', source: 'not-run', settlement: 'known',
    storageOutcome: { effect: 'known-applied', durability: 'confirmed', cleanup: 'known' }, selectionToken: null, assessment: null, preview: null,
  } }));
  assert.equal(h.controller.setKind('bind-reviewed'), true); assert.equal(h.controller.setAcknowledged(true), false);
  assert.equal(agentUploadKeySelection(h.assets.getSnapshot(), 'bind-reviewed', false, 100), null);
  assert.match(h.controller.selectionReason(), /Select and assess/); assert.equal(await h.controller.allow(), false);
  assert.equal(h.permissionCalls.length, 0); noNativeAction(h);
});

test('reentrant source change before Allow handoff refuses without choosing any native files', async t => {
  const h = await fixture(t); choose(h, 'backup-encrypted');
  let changed = false;
  const off = h.controller.subscribe(() => { if (!changed && h.controller.getSnapshot().pending === 'allow') {
    changed = true; h.changeProject(); h.controller.syncContext();
  } });
  assert.equal(await h.controller.allow(), false); off();
  assert.equal(changed, true); assert.equal(h.permissionCalls.length, 0); noNativeAction(h);
});

test('vault/status ABA invalidates original selection consent and never renews its age', async t => {
  const h = await fixture(t); choose(h, 'backup-encrypted');
  h.emit(status(2, { records: [row('d')] })); h.controller.syncContext();
  h.emit(status(3)); h.controller.syncContext();
  assert.equal(h.controller.getSnapshot().backupRecord, null); assert.equal(await h.controller.allow(), false);
  choose(h, 'backup-encrypted'); h.time(300_100);
  assert.notEqual(h.controller.allowReason(), null); assert.equal(await h.controller.allow(), false);
  assert.equal(h.permissionCalls.length, 0); noNativeAction(h);
});

test('lost Allow retains exact withdrawal address and Unknown across a returned revoke and Check', async t => {
  const h = await fixture(t); choose(h, 'restore-encrypted');
  const first = h.controller.allow(); h.last().reject({ code: 'inert_lost_reply' }); await first;
  assert.equal(h.controller.getSnapshot().unknown, true);
  const revoke = h.controller.revoke(); assert.equal(h.last().input, id('e')); h.last().resolve(empty()); await revoke;
  assert.equal(h.controller.getSnapshot().unknown, true); assert.equal(h.controller.setKind('generate-new'), false);
  assert.equal(await h.controller.allow(), false); noNativeAction(h);
});

test('exact Revoke overtaking Allow fences its late success and cannot enable a replacement action', async t => {
  const h = await fixture(t); choose(h, 'backup-encrypted');
  const allow = h.controller.allow(), original = h.last();
  const revoke = h.controller.revoke(); h.last().resolve(empty()); await revoke;
  original.resolve(access('backup-encrypted')); await allow;
  assert.equal(h.controller.getSnapshot().access.enabled, false);
  assert.equal(h.controller.getSnapshot().acknowledged, false); assert.equal(await h.controller.allow(), false);
  noNativeAction(h);
});

test('consumed restore requires exact returned withdrawal; no status countdown or stale new action can replace it', async t => {
  const h = await fixture(t); choose(h, 'restore-encrypted');
  const allow = h.controller.allow(); h.last().resolve(access('restore-encrypted', { enabled: false, remainingMs: 0, consumed: true, requestId: id('f') })); await allow;
  assert.equal(h.controller.setKind('backup-encrypted'), false); assert.equal(h.controller.setAcknowledged(true), false);
  const revoke = h.controller.revoke(); assert.equal(h.controller.setKind('backup-encrypted'), false);
  h.last().resolve(access('restore-encrypted', { enabled: false, remainingMs: 0, consumed: true, requestId: id('f') })); await revoke;
  assert.equal(h.controller.setKind('backup-encrypted'), true);
  assert.equal(h.controller.getSnapshot().acknowledged, false);
  assert.equal(h.controller.getSnapshot().access.consumed, true); // Withdrawal is not native completion.
  noNativeAction(h);
});

test('foreign-kind Allow reply and reconnect cannot launder a restore grant into export permission', async t => {
  const h = await fixture(t); choose(h, 'backup-encrypted');
  const allow = h.controller.allow(); h.last().resolve(access('restore-encrypted')); await allow;
  assert.equal(h.controller.getSnapshot().unknown, true);
  h.disconnect(); h.controller.syncContext(); h.reconnect(); h.controller.syncContext();
  assert.equal(h.controller.getSnapshot().unknown, true); assert.equal(await h.controller.allow(), false);
  noNativeAction(h);
});
