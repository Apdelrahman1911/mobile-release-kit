// Bounded DATA/promise tests of the actual frontend owners and fixed bridge.
// No picker, filesystem input, credential, native worker, key or account is used.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AssetSessionController } from '../src/assetSessionController.ts';
import { assetRequestFits, parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { credentialBackupExportRequest, credentialBackupImportRequest, credentialBackupMessage, credentialBackupReason, credentialBackupRequestFits } from '../src/credentialBackup.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const recordId = 'b'.repeat(32);
const ref = () => ({ recordId, expectedRevision: 1 });
const context = { revision: 1, projectId: 'inert-project', platform: 'android', stage: 'candidate', purpose: 'signing' };
const capability = { available: true, reason: 'none' };
const unavailable = { available: false, reason: 'unqualified' };
function record(patch = {}) {
  return { recordId, revision: 1, kind: 'android-keystore', availability: 'unassigned', storage: 'encrypted', label: null, payloadState: 'not-checked', ...patch };
}
function status(revision = 0, patch = {}) {
  return { schemaVersion: 3, statusRevision: revision, mode: 'encrypted',
    persistence: { state: 'unlocked', reason: 'none', keyAccess: 'read-write' },
    capability: { ...capability }, modes: { session: { ...capability }, encrypted: { ...capability } }, backup: { ...capability },
    context: { ...context }, operation: null, records: [record()], assignments: [], ...patch };
}
function operation(patch = {}) {
  return { operationId: 7, operation: 'prepare-backup-export', phase: 'picking', reason: 'none', source: 'pending', settlement: 'pending',
    storageOutcome: null, selectionToken: null, assessment: null, preview: null, ...patch };
}
function delivered(patch = {}) {
  return operation({ phase: 'idle', settlement: 'known', source: 'captured', backupDelivered: true, ...patch });
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function settle() { for (let i = 0; i < 12; i += 1) await Promise.resolve(); }
function harness(t, otherOperationReason = () => null) {
  let project = { project: { id: context.projectId, name: 'Inert project' }, draft: { schemaVersion: 1 }, revision: 1, baselineGeneration: 1 };
  let current = status();
  let event;
  const calls = [];
  const pending = (command, args) => {
    const work = deferred(); calls.push({ command, args, ...work }); return work.promise;
  };
  const api = { mode: 'native', subscribeAssets: async (listener) => { event = listener; return () => {}; },
    assetStatus: async () => structuredClone(current), setAssetContext: (args) => pending('context', args),
    exportCredentialBackup: (args) => pending('export', args), importCredentialBackup: (args) => pending('import', args),
    prepareCredential: (args) => pending('prepare', args), commitAsset: (args) => pending('commit', args),
    bindAsset: (args) => pending('bind', args), discardAsset: (args) => pending('discard', args),
  };
  const controller = new AssetSessionController(() => project, () => 100, otherOperationReason);
  controller.setScope({ platform: 'android', stage: 'candidate', purpose: 'signing' });
  t.after(() => controller.dispose());
  return { api, controller, calls, last: (command) => calls.filter((call) => call.command === command).at(-1),
    emit: (value) => { current = structuredClone(value); event(value); },
    reply: (command, value) => { current = structuredClone(value); calls.filter((call) => call.command === command).at(-1).resolve(value); },
    changeProject: () => { project = { ...project, revision: project.revision + 1 }; },
  };
}
async function ready(h) {
  await h.controller.connect(h.api);
  h.controller.submitContext(); await settle();
  h.reply('context', status(1)); await settle();
  assert.equal(h.controller.getSnapshot().contextCurrent, true);
}
function noPrivateMutation(h) {
  assert.equal(h.calls.filter((call) => ['prepare', 'commit', 'bind'].includes(call.command)).length, 0);
}

test('backup requests have exactly a positive context and original record revision, never paths or code', () => {
  const exportRequest = { contextRevision: 1, record: ref() };
  const importRequest = { contextRevision: 1 };
  assert.equal(credentialBackupRequestFits('vault_backup_export', exportRequest), true);
  assert.equal(assetRequestFits('vault_backup_import', importRequest), true);
  for (const extra of ['path', 'code', 'destination', 'replacement', 'fields', 'overwrite']) {
    assert.equal(assetRequestFits('vault_backup_export', { ...exportRequest, [extra]: 'inert-refused' }), false);
    assert.equal(assetRequestFits('vault_backup_import', { ...importRequest, [extra]: 'inert-refused' }), false);
    assert.equal(assetRequestFits('vault_backup_export', { ...exportRequest, record: { ...ref(), [extra]: 'inert-refused' } }), false);
  }
  for (const bad of [0, -1, 1.5, '1', 0x1_0000_0000, null]) {
    assert.equal(assetRequestFits('vault_backup_import', { contextRevision: bad }), false);
    assert.equal(assetRequestFits('vault_backup_export', { ...exportRequest, record: { recordId, expectedRevision: bad } }), false);
  }
  for (const bad of ['', '0'.repeat(32), 'B'.repeat(32), recordId + 'b']) {
    assert.equal(assetRequestFits('vault_backup_export', { ...exportRequest, record: { recordId: bad, expectedRevision: 1 } }), false);
  }
  let read = false;
  const accessor = { record: ref(), get contextRevision() { read = true; return 1; } };
  assert.equal(credentialBackupRequestFits('vault_backup_export', accessor), false);
  assert.equal(read, false);
});

test('old hosts remain wire-compatible and do not acquire backup capability from a writable vault', async (t) => {
  const old = status(); delete old.backup;
  assert.deepEqual(parseAssetStatus(old), old);
  const h = harness(t); await ready(h);
  h.emit({ ...old, statusRevision: 2 });
  assert.match(credentialBackupReason(h.controller.getSnapshot()), /unavailable/u);
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
  assert.equal(h.calls.length, 1); // The original context submission only.
  assert.ok(parseAssetStatus(status(3, { backup: { ...unavailable } })));
  assert.equal(parseAssetStatus(status(3, { backup: { available: true, reason: 'unqualified' } })), null);
  assert.equal(parseAssetStatus(status(3, { backup: undefined })), null);
});

test('only a current encrypted successful export may carry the optional native publication marker', () => {
  const good = status(3, { operation: delivered() });
  assert.deepEqual(parseAssetStatus(good), good);
  for (const change of [
    (s) => { s.operation.backupDelivered = false; },
    (s) => { s.operation.backupDelivered = 'true'; },
    (s) => { s.operation.operation = 'import-backup'; },
    (s) => { s.operation.phase = 'capturing'; },
    (s) => { s.operation.settlement = 'unknown'; },
    (s) => { s.operation.settlement = 'late-known'; },
    (s) => { s.operation.reason = 'user-cancelled'; },
    (s) => { s.operation.source = 'unknown'; },
    (s) => { s.operation.source = 'pending'; },
    (s) => { s.operation.operationId = 0; },
    (s) => { s.backup = { ...unavailable }; },
    (s) => { delete s.backup; },
    (s) => { s.context = null; },
    (s) => { s.context.revision = 0; },
    (s) => { s.mode = 'closed'; s.persistence = null; s.context = null; s.records = []; },
    (s) => { s.persistence = { state: 'interrupted', reason: 'vault-interrupted', keyAccess: 'read-only' }; },
    (s) => { s.operation.storageOutcome = { effect: 'known-applied', durability: 'confirmed', cleanup: 'known' }; },
    (s) => { s.operation.recoveryCode = 'inert-refused'; },
  ]) {
    const bad = structuredClone(good); change(bad); assert.equal(parseAssetStatus(bad), null);
  }
  const imported = status(4, { operation: operation({ operation: 'import-backup', phase: 'idle', settlement: 'known',
    storageOutcome: { effect: 'known-applied', durability: 'confirmed', cleanup: 'known' } }) });
  assert.ok(parseAssetStatus(imported));
  assert.equal(parseAssetStatus({ ...imported, mode: 'session', persistence: null, records: [] }), null);
});

test('the two real bridge adapters forward only the closed request; preview cannot invoke them', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return status(2); });
  const original = { contextRevision: 1, record: ref() };
  await api.exportCredentialBackup(original);
  await api.importCredentialBackup({ contextRevision: 1 });
  original.record.expectedRevision = 8;
  assert.deepEqual(calls, [
    { command: 'vault_backup_export', args: { contextRevision: 1, record: ref() } },
    { command: 'vault_backup_import', args: { contextRevision: 1 } },
  ]);
  await assert.rejects(api.importCredentialBackup({ contextRevision: 1, replacement: ref() }));
  await assert.rejects(api.exportCredentialBackup({ contextRevision: 1, record: ref(), code: 'inert-refused' }));
  await assert.rejects(previewApi.importCredentialBackup({ contextRevision: 1 }));
  await assert.rejects(previewApi.exportCredentialBackup({ contextRevision: 1, record: ref() }));
  assert.equal(calls.length, 2);
});

test('same-controller admission rejects double clicks and detaches the nonsecret reference', async (t) => {
  const h = harness(t); await ready(h);
  const expected = h.controller.getSnapshot(), original = ref();
  assert.equal(h.controller.exportBackup(original, expected), true);
  original.expectedRevision = 2;
  assert.equal(h.controller.exportBackup(ref(), expected), false);
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
  assert.deepEqual(h.last('export').args, { contextRevision: 1, record: ref() });
  assert.equal(h.calls.filter((call) => call.command === 'export').length, 1);
  h.reply('export', status(2, { operation: operation() })); await settle();
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
  noPrivateMutation(h);
});

test('a retained view and a changed record revision cannot start a backup', async (t) => {
  const h = harness(t); await ready(h);
  const old = h.controller.getSnapshot();
  h.emit(status(2, { records: [record({ revision: 2 })] }));
  assert.equal(h.controller.exportBackup(ref(), old), false);
  assert.equal(h.controller.importBackup(old), false);
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
  assert.equal(h.calls.length, 1);
});

test('an unsynchronized project edit is rechecked before either original command', async (t) => {
  const h = harness(t); await ready(h);
  const expected = h.controller.getSnapshot();
  h.changeProject(); // Even before the workspace delivers syncProject.
  assert.equal(h.controller.exportBackup(ref(), expected), false);
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
  await settle();
  assert.equal(h.calls.filter((call) => ['export', 'import'].includes(call.command)).length, 0);
  h.reply('context', status(2, { context: { ...context, revision: 2 } })); await settle();
});

test('unavailable, session, locked, read-only and mutation-pending views cannot invoke a private backup', async (t) => {
  for (const patch of [
    { backup: { ...unavailable } },
    { mode: 'session', persistence: null, records: [] },
    { persistence: { state: 'locked', reason: 'none', keyAccess: 'locked' }, context: null, records: [] },
    { persistence: { state: 'interrupted', reason: 'vault-interrupted', keyAccess: 'read-only' } },
  ]) {
    const h = harness(t); await ready(h); h.emit(status(2, patch));
    assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
    assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
    assert.equal(h.calls.length, 1);
  }
  const h = harness(t); await ready(h); h.emit(status(2, { records: [record({ availability: 'mutation-pending' })] }));
  assert.equal(credentialBackupExportRequest(h.controller.getSnapshot(), ref()), null);
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
});

test('the existing cross-feature busy owner still vetoes backup and restore', async (t) => {
  let busy = null;
  const h = harness(t, () => busy); await ready(h); busy = 'Another original operation owns the project.';
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
  assert.equal(h.calls.length, 1);
});

test('an overtaking delivered event cannot supply a missing original command acknowledgement', async (t) => {
  const h = harness(t); await ready(h);
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), true);
  h.emit(status(3, { operation: delivered() }));
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  assert.equal(h.controller.discard(), false);
  assert.notEqual(credentialBackupMessage(h.controller.getSnapshot(), false).title, 'Backup saved');
  h.reply('export', status(2, { operation: operation() })); await settle();
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), true);
  assert.equal(credentialBackupMessage(h.controller.getSnapshot(), true).title, 'Backup saved');
  noPrivateMutation(h);
});

test('Idle and known do not replace the explicit publication marker or the exact original ID', async (t) => {
  const h = harness(t); await ready(h);
  h.controller.exportBackup(ref(), h.controller.getSnapshot());
  h.reply('export', status(2, { operation: operation({ phase: 'idle', settlement: 'known' }) })); await settle();
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  h.emit(status(3, { operation: delivered({ operationId: 8 }) }));
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  assert.notEqual(credentialBackupMessage(h.controller.getSnapshot(), false).title, 'Backup saved');
});

test('a lost own reply stays uncertain even after a later completed-looking status', async (t) => {
  const h = harness(t); await ready(h);
  h.controller.exportBackup(ref(), h.controller.getSnapshot());
  h.last('export').reject({ code: 'AssetSessionUnavailable' }); await settle();
  h.emit(status(3, { operation: delivered() }));
  await h.controller.checkStatus();
  assert.equal(h.controller.getSnapshot().originPending, true);
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
  assert.equal(h.calls.filter((call) => call.command === 'export').length, 1);
});

test('unknown settlement is absorbing and cannot turn into backup success or a retry', async (t) => {
  const h = harness(t); await ready(h);
  h.controller.exportBackup(ref(), h.controller.getSnapshot());
  h.reply('export', status(2, { operation: operation({ phase: 'unknown', reason: 'cleanup-unknown', settlement: 'unknown' }) })); await settle();
  h.emit(status(3, { operation: delivered() }));
  assert.equal(h.controller.getSnapshot().blocked, true);
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  assert.equal(h.controller.exportBackup(ref(), h.controller.getSnapshot()), false);
  assert.match(credentialBackupMessage(h.controller.getSnapshot(), false).text, /do not retry/u);
});

test('completion presentation is retired by project drift, changed reference or a foreign controller', async (t) => {
  const h = harness(t); await ready(h);
  h.controller.exportBackup(ref(), h.controller.getSnapshot());
  h.reply('export', status(2, { operation: delivered() })); await settle();
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), true);
  const foreign = harness(t); await ready(foreign); foreign.emit(status(2, { operation: delivered() }));
  assert.equal(foreign.controller.backupExportCompleted(foreign.controller.getSnapshot()), false);
  h.emit(status(3, { operation: delivered(), records: [record({ revision: 2 })] }));
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  h.emit(status(4, { operation: delivered() })); h.changeProject();
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
});

test('restore remains New-only and unassigned; returned counts or storage effects never auto-prepare or Bind', async (t) => {
  const h = harness(t); await ready(h);
  assert.deepEqual(credentialBackupImportRequest(h.controller.getSnapshot()), { contextRevision: 1 });
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), true);
  assert.equal(h.controller.importBackup(h.controller.getSnapshot()), false);
  assert.deepEqual(h.last('import').args, { contextRevision: 1 });
  const added = record({ recordId: 'c'.repeat(32) });
  h.reply('import', status(2, { records: [record(), added], operation: operation({ operation: 'import-backup', phase: 'idle', settlement: 'known',
    storageOutcome: { effect: 'known-applied', durability: 'confirmed', cleanup: 'known' } }) })); await settle();
  noPrivateMutation(h);
  assert.equal(h.controller.getSnapshot().reviewReady, false);
  assert.equal(h.controller.backupExportCompleted(h.controller.getSnapshot()), false);
  assert.deepEqual(h.controller.getSnapshot().status.assignments, []);
  assert.match(credentialBackupMessage(h.controller.getSnapshot(), false).text, /new, unassigned copy/u);
});

test('only explicit cancellation targets the acknowledged original; renderer disposal starts nothing', async (t) => {
  const h = harness(t); await ready(h);
  h.controller.importBackup(h.controller.getSnapshot());
  assert.equal(h.controller.discard(), false);
  h.reply('import', status(2, { operation: operation({ operation: 'import-backup' }) })); await settle();
  assert.equal(h.controller.discard(), true);
  assert.equal(h.controller.discard(), false);
  assert.equal(h.last('discard').args, 7);
  h.reply('discard', status(3, { operation: operation({ operation: 'import-backup', phase: 'idle', settlement: 'known', reason: 'user-cancelled' }) })); await settle();
  const expected = h.controller.getSnapshot(), count = h.calls.length;
  h.controller.dispose();
  assert.equal(h.controller.importBackup(expected), false);
  assert.equal(h.controller.exportBackup(ref(), expected), false);
  assert.equal(h.calls.length, count);
  noPrivateMutation(h);
});
