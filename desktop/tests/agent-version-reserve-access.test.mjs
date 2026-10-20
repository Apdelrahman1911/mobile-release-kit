// Inert DATA and retained promises through the actual existing GUI controller.
// No native service, Store, allocation, credentials, CLI or version-file writes.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAgentVersionReserveAccess, createAgentVersionReserveAccessPort, agentVersionReserveCommands } from '../src/agentVersionReserveAccess.ts';
import { VersionReserveController } from '../src/versionReserveController.ts';

const REVIEW = 'a'.repeat(32), OP = 'b'.repeat(32), SERVICE = '1'.repeat(32), PROJECT = '2'.repeat(32), GRANT = '3'.repeat(32), REQUEST = '4'.repeat(32);
const options = { reference: 'refs/heads/main', increment: 'patch', newCandidate: false, acknowledgeLimitations: true };
const reservation = { id: OP, candidateId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', name: '1.2.4', build: 8 };
const access = (extra = {}) => ({ serviceInstance: SERVICE, projectId: PROJECT, grantId: GRANT, reviewId: REVIEW, reviewRevision: 1,
  enabled: true, remainingMs: 90_000, consumed: false, requestId: null, completedOperationId: null, ...extra });
const none = () => ({ serviceInstance: null, projectId: null, grantId: null, reviewId: null, reviewRevision: null,
  enabled: false, remainingMs: 0, consumed: false, requestId: null, completedOperationId: null });
const consumed = (completed = false, extra = {}) => access({ enabled: false, remainingMs: 0, consumed: true, requestId: REQUEST,
  completedOperationId: completed ? OP : null, ...extra });
const status = (phase, revision = 1, extra = {}) => ({ schemaVersion: 1, revision, projectId: 'project-1',
  operationId: phase === 'reviewed' || phase === 'reading' ? REVIEW : OP, phase,
  reason: phase === 'refused' ? 'reservation-refused' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'none',
  review: phase === 'reviewed' ? { id: REVIEW, reference: options.reference, increment: options.increment, newCandidate: false } : null,
  reservation: phase === 'reserved' ? reservation : null, ...extra });
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 12; n++) await Promise.resolve(); };
function harness() {
  const calls = [], edits = [];
  const method = (kind) => (...args) => { const d = deferred(); calls.push({ kind, args, ...d }); return d.promise; };
  const port = { status: method('version-status'), review: method('review'), reserve: method('reserve'), cancel: method('cancel') };
  const cliAccessPort = { status: method('access'), allow: method('allow'), revoke: method('revoke') };
  const editor = { reservedOpenReason: () => null, openReserved: (v) => { edits.push(v); return true; } };
  let context = { port, cliAccessPort, editor, nativeSession: {}, projectId: 'project-1', preview: false, blockedReason: null };
  const c = new VersionReserveController({ current: () => context });
  return { c, calls, edits, cliAccessPort, port, last: (kind) => calls.filter((v) => v.kind === kind).at(-1),
    set: (v) => { context = { ...context, ...v }; }, ready: () => { c.setEnabled(true); c.configure(options); } };
}
async function reviewed(h) { h.ready(); const p = h.c.review(); h.last('review').resolve(status('reviewed')); await p; }
async function allowed(h) { await reviewed(h); assert.equal(h.c.cliAccess.setAcknowledged(true), true);
  const p = h.c.cliAccess.allow(); h.last('allow').resolve(access()); await p; }
async function checked(h, a, native = null) {
  const p = h.c.checkCliAccess(); h.last('access').resolve(a); await flush();
  if (native) h.last('version-status').resolve(native);
  await p;
}

test('closed permission DTO rejects malformed authority, IDs, omissions and accessors without reading them', () => {
  for (const v of [none(), access(), access({ enabled: false, remainingMs: 0 }), consumed(), consumed(true)]) {
    const parsed = parseAgentVersionReserveAccess(v); assert.deepEqual(parsed, v); assert.ok(Object.isFrozen(parsed));
  }
  const missing = access(); delete missing.completedOperationId;
  for (const v of [missing, access({ source: {} }), access({ grantId: '0'.repeat(32) }), access({ projectId: 'project-1' }),
    access({ serviceInstance: SERVICE.toUpperCase().replace('1', 'A') }), access({ reviewRevision: 0 }), access({ reviewRevision: 0xffff_ffff }),
    access({ remainingMs: -0 }), access({ remainingMs: 0 }), access({ remainingMs: 120001 }), access({ remainingMs: 0.5 }), access({ enabled: false }),
    access({ consumed: true }), access({ completedOperationId: OP }), consumed(true, { requestId: null }),
    { ...none(), reviewId: REVIEW }, access({ reviewRevision: null })]) assert.equal(parseAgentVersionReserveAccess(v), null);
  let getters = 0; const getter = access(); Object.defineProperty(getter, 'grantId', { enumerable: true, get() { getters++; return GRANT; } });
  assert.equal(parseAgentVersionReserveAccess(getter), null); assert.equal(getters, 0);
  assert.equal(parseAgentVersionReserveAccess(Array(100000)), null);
});

test('only the three RAW bounded commands are emitted; CLI help contains exact original IDs, never execution', async () => {
  const calls = [], port = createAgentVersionReserveAccessPort(async (command, bytes) => {
    assert.ok(bytes instanceof Uint8Array); assert.ok(bytes.length + 96 <= 1024);
    calls.push([command, JSON.parse(new TextDecoder().decode(bytes))]); return none();
  });
  await port.status(); await port.allow('project-1', REVIEW, 12); await port.revoke();
  assert.deepEqual(calls, [['agent_version_reserve_access', {}], ['allow_agent_version_reserve', {
    projectId: 'project-1', reviewId: REVIEW, expectedReserveRevision: 12, consentVersion: 'agent-version-reserve-once-v1',
  }], ['revoke_agent_version_reserve', {}]]);
  for (const args of [['../project', REVIEW, 1], ['project-1', '0'.repeat(32), 1], ['project-1', REVIEW, 0xffff_ffff]]) await assert.rejects(port.allow(...args));
  assert.equal(calls.length, 3);
  assert.deepEqual(agentVersionReserveCommands(access()), [`mrk version-reserve-submit ${PROJECT} ${SERVICE} ${GRANT} ${REVIEW} --reviewed`]);
  assert.deepEqual(agentVersionReserveCommands(consumed()), [`mrk version-reserve-status ${PROJECT} ${SERVICE} ${REQUEST}`, `mrk version-reserve-cancel ${PROJECT} ${SERVICE} ${REQUEST}`]);
  assert.deepEqual(agentVersionReserveCommands(none()), []);
});

test('manual default and status-shaped review never allow CLI; explicit original GUI review and one consent are required', async () => {
  const h = harness(); h.c.syncContext(); assert.equal(await h.c.cliAccess.allow(), false); assert.equal(h.calls.length, 0);
  h.ready(); let p = h.c.check(); h.last('version-status').resolve(status('reviewed')); await p;
  assert.equal(h.c.cliAccess.setAcknowledged(true), false); assert.equal(await h.c.cliAccess.allow(), false);
  p = h.c.review(); h.last('review').resolve(status('reviewed', 2)); await p;
  assert.equal(await h.c.cliAccess.allow(), false); assert.equal(h.c.cliAccess.setAcknowledged(true), true);
  p = h.c.cliAccess.allow(); assert.deepEqual(h.last('allow').args, ['project-1', REVIEW, 2]);
  h.last('allow').resolve(access({ reviewRevision: 2 })); await p;
  assert.equal(h.c.cliAccess.getSnapshot().acknowledged, false); assert.ok(h.c.ownerReason());
  assert.equal(await h.c.reserve(), false); assert.equal(h.calls.filter((c) => c.kind === 'reserve').length, 0);
  const off = h.c.cliAccess.revoke(); h.last('revoke').resolve(access({ enabled: false, remainingMs: 0, reviewRevision: 2 })); await off;
  assert.notEqual(h.c.cliAccess.consentReason(), null); // No renewal of the same review.
  assert.equal(h.edits.length, 0);
});

test('Allow rechecks private review, context ABA and peer admission after synchronous listeners', async () => {
  for (const change of [h => h.c.beforeContextIntent(), h => { h.set({ projectId: 'project-2' }); h.c.syncContext(); h.set({ projectId: 'project-1' }); h.c.syncContext(); },
    h => h.set({ blockedReason: 'another original owner' })]) {
    const h = harness(); await reviewed(h); h.c.cliAccess.setAcknowledged(true); let once = false;
    h.c.subscribe(() => { if (!once && h.c.cliAccess.getSnapshot().pending === 'allow') { once = true; change(h); } });
    assert.equal(await h.c.cliAccess.allow(), false); assert.equal(h.calls.filter((c) => c.kind === 'allow').length, 0);
  }
});

test('immediate original Revoke overtakes pending Allow without dropping either promise or accepting its late grant', async () => {
  const h = harness(); await reviewed(h); h.c.cliAccess.setAcknowledged(true);
  const allow = h.c.cliAccess.allow(); const oldAllow = h.last('allow');
  h.set({ projectId: 'project-2', cliAccessPort: { status() { throw Error('new port'); }, allow() { throw Error('new port'); }, revoke() { throw Error('new port'); } }, nativeSession: {} });
  h.c.beforeContextIntent(); h.c.syncContext();
  const revoke = h.c.cliAccess.revoke(); assert.ok(h.last('revoke')); h.last('revoke').resolve(none()); await revoke;
  let joined = false; h.c.whenSettled().then(() => { joined = true; }); await flush(); assert.equal(joined, false);
  assert.ok(h.c.ownerReason()); oldAllow.resolve(access()); await allow; await flush(); assert.equal(joined, true);
  assert.deepEqual(h.c.cliAccess.getSnapshot().access, none()); assert.notEqual(h.c.cliAccess.allowReason(), null); assert.equal(h.edits.length, 0);
});

test('consumed is not completion; explicit permission Check and later fresh original status enable only separate edit', async () => {
  const h = harness(); await allowed(h);
  await checked(h, consumed(), status('reserved', 2)); assert.equal(h.c.edit(), false); assert.equal(h.c.cliAccess.checkedCompletion(), null);
  assert.equal(h.calls.filter((c) => c.kind === 'reserve').length, 0);
  const p = h.c.checkCliAccess(); h.last('access').resolve(consumed(true)); await flush();
  const native = h.last('version-status'); assert.ok(h.c.ownerReason()); assert.equal(h.c.edit(), false);
  native.resolve(status('reserved', 2)); await p;
  assert.equal(h.c.editReason(), null); assert.equal(h.edits.length, 0);
  assert.equal(h.c.edit(), true); assert.deepEqual(h.edits, [reservation]); assert.equal(h.c.edit(), false);
  assert.equal(h.calls.filter((c) => c.kind === 'reserve').length, 0);
});

test('older native status or unmatched marker cannot become the post-Check editor handoff', async () => {
  const h = harness(); await allowed(h);
  const old = h.c.check(); const oldCall = h.last('version-status');
  const a = h.c.cliAccess.check(); h.last('access').resolve(consumed(true)); await a;
  oldCall.resolve(status('reserved', 2)); await old; assert.equal(h.c.edit(), false);
  // A fresh read with a different actual reservation cannot borrow the marker.
  let p = h.c.check(); h.last('version-status').resolve(status('reserved', 3, { operationId: 'd'.repeat(32), reservation: { ...reservation, id: 'd'.repeat(32) } })); await p;
  assert.equal(h.c.edit(), false); assert.equal(h.edits.length, 0);
  const other = harness(); other.ready();
  await checked(other, consumed(true), status('reserved', 2)); assert.equal(other.c.edit(), false); // No original GUI Review/Allow binding.
});

test('terminal native status before Allow reply does not settle that original promise or open the editor', async () => {
  const h = harness(); await reviewed(h); h.c.cliAccess.setAcknowledged(true); const allow = h.c.cliAccess.allow();
  const read = h.c.check(); h.last('version-status').resolve(status('reserved', 2)); await read;
  let joined = false; h.c.whenSettled().then(() => { joined = true; }); await flush();
  assert.equal(joined, false); assert.ok(h.c.ownerReason()); assert.equal(h.c.edit(), false);
  h.last('allow').resolve(consumed(true)); await allow; await flush(); assert.equal(joined, true);
  assert.equal(h.c.edit(), false); // Even an Allow reply's joined marker is not the explicit follow-up Check.
  await checked(h, consumed(true), status('reserved', 2)); assert.equal(h.c.editReason(), null); assert.equal(h.edits.length, 0);
});

test('permission or native-response reentrancy and source/context drift cannot restore the old review', async () => {
  for (const atPermission of [true, false]) {
    const h = harness(); await allowed(h); const p = h.c.checkCliAccess(); let once = false;
    const retire = (value) => new Proxy(value, { ownKeys(target) { if (!once) { once = true; h.c.beforeContextIntent(); } return Reflect.ownKeys(target); } });
    h.last('access').resolve(atPermission ? retire(consumed(true)) : consumed(true)); await flush();
    if (!atPermission) h.last('version-status').resolve(retire(status('reserved', 2)));
    await p; assert.equal(h.c.edit(), false); assert.equal(h.edits.length, 0);
  }
  const h = harness(); await allowed(h); await checked(h, consumed(true), status('reserved', 2));
  assert.equal(h.c.configure({ ...options, increment: 'major' }), true); assert.equal(h.c.edit(), false);
});

test('lost Allow acknowledgement stays unknown, keeps drafts and original controls; later DATA cannot authorize edit', async () => {
  const h = harness(); await reviewed(h); h.c.cliAccess.setAcknowledged(true); const originalOptions = h.c.getSnapshot().options;
  const p = h.c.cliAccess.allow(); h.last('allow').reject(Error('private details must never be shown')); await p;
  assert.equal(h.c.cliAccess.getSnapshot().unknown, true); assert.equal(await h.c.cliAccess.allow(), false);
  const check = h.c.cliAccess.check(); h.last('access').resolve(consumed(true)); await check;
  assert.equal(h.c.cliAccess.getSnapshot().unknown, true); assert.equal(h.c.edit(), false); assert.equal(h.c.getSnapshot().options, originalOptions);
  const stop = h.c.cliAccess.revoke(); h.last('revoke').resolve(consumed()); await stop;
  assert.equal(h.c.cliAccess.getSnapshot().unknown, true); assert.equal(h.calls.filter((c) => c.kind === 'allow').length, 1);
  assert.ok(!JSON.stringify(h.c.cliAccess.getSnapshot()).includes('private details'));
});

test('only source-confirmed pre-grant Allow refusals remain retryable by a new explicit review, not a lost ACK', async () => {
  for (const code of ['version_reserve_refused', 'cli_access_busy', 'cli_access_changed']) {
    const h = harness(); await reviewed(h); h.c.cliAccess.setAcknowledged(true);
    const p = h.c.cliAccess.allow(); h.last('allow').reject({ code, message: 'not displayed' }); await p;
    assert.equal(h.c.cliAccess.getSnapshot().unknown, false); assert.equal(h.c.cliAccess.getSnapshot().access, null);
    assert.equal(h.c.cliAccess.getSnapshot().stale, true); assert.equal(h.c.ownerReason(), null);
    assert.equal(await h.c.cliAccess.allow(), false); assert.equal(h.edits.length, 0);
  }
  const h = harness(); const p = h.c.cliAccess.check(); h.last('access').reject({ code: 'cli_access_busy' }); await p;
  assert.equal(h.c.cliAccess.getSnapshot().unknown, true); // That Allow-only proof is not a read/Stop receipt.
});

test('known failed consumed request is not busy merely because permission was used; native Unknown still blocks', async () => {
  const h = harness(); await allowed(h); await checked(h, consumed(), status('refused', 2));
  assert.equal(h.c.cliAccess.ownerReason(), null); assert.equal(h.c.ownerReason(), null); assert.equal(h.c.edit(), false);
  const p = h.c.review(); h.last('review').resolve(status('reviewed', 3)); await p; // Native independently checks its original joins before admitting.
  const other = harness(); await allowed(other); await checked(other, consumed(true), status('cleanup-unknown', 2));
  assert.ok(other.c.ownerReason()); assert.equal(other.c.edit(), false); assert.equal(other.c.getSnapshot().unknown, true);
});

test('edit callback reentrancy cannot race original Revoke, and disposal never settles pending permission calls', async () => {
  const h = harness(); await allowed(h); await checked(h, consumed(true), status('reserved', 2)); let revoke;
  h.c.subscribe(() => { if (h.c.getSnapshot().editHandedOff && !revoke) { revoke = true; revoke = h.c.cliAccess.revoke(); } });
  assert.equal(h.c.edit(), false); assert.equal(h.edits.length, 0); h.last('revoke').resolve(consumed()); await revoke;
  const other = harness(); await reviewed(other); other.c.cliAccess.setAcknowledged(true); const p = other.c.cliAccess.allow();
  other.c.dispose(); let done = false; other.c.whenSettled().then(() => { done = true; }); await flush(); assert.equal(done, false);
  other.last('allow').resolve(consumed(true)); await p; await flush(); assert.equal(done, true); assert.equal(other.c.edit(), false);
});
