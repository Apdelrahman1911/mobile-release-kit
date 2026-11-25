// Inert DATA and manually settled promises; no native app, GitHub, Store,
// filesystem, timer, DOM or credential calls. No native-finality qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createVersionEnrollmentPort, parseVersionEnrollmentStatus, versionEnrollmentHelp } from '../src/versionEnrollment.ts';
import { VersionEnrollmentController } from '../src/versionEnrollmentController.ts';

const ID = 'a'.repeat(32), CONFIRM = 'b'.repeat(32);
function status(phase = 'idle', revision = 1, operationId = ID, projectId = 'project-1') {
  return { schemaVersion: 1, revision, projectId: phase === 'idle' ? null : projectId, operationId: phase === 'idle' ? null : operationId,
    phase, reason: phase === 'connected' ? 'connected' : phase === 'cleanup-unknown' ? 'cleanup-unknown' :
      phase === 'refused' ? 'review-changed' : phase === 'stopping' ? 'cancelled' : 'none',
    review: phase === 'reviewed' ? { id: operationId, repository: 'fixture/app', version: { name: '1.2.3', build: 7 }, reservations: 2 } : null };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function harness() {
  const h = { calls: [] };
  h.makePort = (label) => Object.fromEntries(['review', 'confirm', 'status', 'cancel'].map((kind) => [kind, (...args) => {
    const call = { ...deferred(), kind, args, label }; h.calls.push(call); return call.promise;
  }]));
  h.context = { port: h.makePort('original'), nativeSession: {}, projectId: 'project-1', preview: false, blockedReason: null };
  h.controller = new VersionEnrollmentController({ current: () => h.context });
  h.last = (kind) => h.calls.filter((c) => c.kind === kind).at(-1);
  h.change = (next = {}) => { h.controller.beforeContextIntent(); h.context = { ...h.context, ...next }; h.controller.syncContext(); };
  h.reviewed = async () => { const task = h.controller.review(); h.last('review').resolve(status('reviewed', 3)); await task; };
  Object.defineProperty(h, 'state', { get: () => h.controller.getSnapshot() });
  return h;
}

test('fixed native port sends only four bounded Raw requests and never calls on construction', async () => {
  const calls = [], invoke = (command, bytes) => { calls.push([command, bytes]); return Promise.resolve(status()); };
  const port = createVersionEnrollmentPort(invoke);
  assert.ok(Object.isFrozen(port)); assert.equal(calls.length, 0);
  await port.status(); await port.review('project-1'); await port.confirm('project-1', ID); await port.cancel(ID);
  assert.deepEqual(calls.map(([name, raw]) => [name, JSON.parse(new TextDecoder().decode(raw))]), [
    ['version_enrollment_status', {}], ['version_enrollment_review', { projectId: 'project-1' }],
    ['version_enrollment_confirm', { projectId: 'project-1', reviewId: ID }], ['version_enrollment_cancel', { operationId: ID }],
  ]);
  assert.ok(calls.every(([, raw]) => raw instanceof Uint8Array && raw.length <= 8192));
  for (const bad of ['', '../app', 'project-1\n']) await assert.rejects(port.review(bad));
  for (const bad of ['0'.repeat(32), ID + '\n', 'A'.repeat(32), 'review']) await assert.rejects(port.confirm('project-1', bad));
  assert.equal(calls.length, 4);
});

test('status parser copies exact redacted DATA and rejects phase/readiness contradictions', () => {
  const raw = status('reviewed', 3), parsed = parseVersionEnrollmentStatus(raw);
  assert.deepEqual(parsed, raw); assert.ok(Object.isFrozen(parsed.review.version));
  raw.review.version.build = 99; assert.equal(parsed.review.version.build, 7);
  for (const phase of ['idle', 'reading', 'connecting', 'reviewed', 'connected', 'refused', 'stopping', 'cleanup-unknown']) assert.ok(parseVersionEnrollmentStatus(status(phase)));
  for (const value of [{ ...status('connected'), reason: 'none' }, { ...status('reading'), review: status('reviewed').review },
    { ...status('reviewed'), review: null }, { ...status('cleanup-unknown'), reason: 'connected' }, { ...status(), floor: 123 },
    { ...status('refused'), reason: 'none' }, { ...status('reading'), operationId: null }, { ...status(), revision: 0 },
    { ...status(), revision: -0 }, { ...status(), revision: 0xffff_ffff }]) assert.equal(parseVersionEnrollmentStatus(value), null);
  assert.ok(parseVersionEnrollmentStatus({ ...status('cleanup-unknown'), revision: 0xffff_ffff }));
});

test('status bounds and descriptor parsing refuse getters, sparse arrays, private fields and expansion', () => {
  let reads = 0;
  const getter = { ...status('reviewed') }; Object.defineProperty(getter, 'review', { enumerable: true, get() { reads++; return null; } });
  const cases = [getter, { ...status(), token: 'inert-private' }, Object.assign(Object.create({ inherited: true }), status()),
    { ...status(), review: new Array(1_000_000) }, { ...status(), toJSON() { reads++; return status(); } }];
  for (const value of cases) assert.equal(parseVersionEnrollmentStatus(value), null);
  for (const repository of ['-owner/app', 'owner/app-', 'owner/app\n', 'owner/../app', 'a'.repeat(40) + '/app']) {
    const raw = status('reviewed'); raw.review.repository = repository; assert.equal(parseVersionEnrollmentStatus(raw), null);
  }
  for (const value of [ID + '\n', '0'.repeat(32), 'A'.repeat(32)]) assert.equal(parseVersionEnrollmentStatus({ ...status('reading'), operationId: value }), null);
  for (const name of ['1.2.3\n', 'x'.repeat(65)]) { const raw = status('reviewed'); raw.review.version.name = name; assert.equal(parseVersionEnrollmentStatus(raw), null); }
  assert.equal(reads, 0);
});

test('constructing, syncing and subscribing are inert; missing native gate and preview cannot review', async () => {
  const h = harness(); const draft = { dirty: true, version: '9.9.9' }; h.context.draft = draft;
  const off = h.controller.subscribe(() => {}); h.controller.syncContext(); off();
  assert.equal(h.calls.length, 0); assert.equal(h.controller.confirmReason(), 'Review this counter again before connecting it.');
  for (const next of [{ port: null }, { nativeSession: null }, { preview: true }, { blockedReason: 'Finish the other task.' }, { projectId: null }]) {
    const fixture = harness(); fixture.change(next); assert.equal(await fixture.controller.review(), false); assert.equal(fixture.calls.length, 0);
  }
  assert.equal(h.context.draft, draft);
});

test('explicit review and connect use separate one-use native requests, never auto-connect or change version', async () => {
  const h = harness(); await h.reviewed();
  assert.equal(h.calls.length, 1); assert.equal(h.controller.confirmReason(), null);
  const connect = h.controller.confirm();
  assert.deepEqual(h.last('confirm').args, ['project-1', ID]);
  assert.equal(await h.controller.confirm(), false); assert.equal(h.controller.ownerReason() !== null, true);
  h.last('confirm').resolve(status('connected', 6, CONFIRM)); await connect;
  assert.equal(h.state.status.phase, 'connected'); assert.equal(h.controller.ownerReason(), null);
  assert.notEqual(h.controller.confirmReason(), null); assert.equal(h.calls.length, 2);
  assert.match(versionEnrollmentHelp('connected'), /No version was reserved or changed/);
});

test('Check may observe a review but cannot mint a new Connect intent', async () => {
  const h = harness(), query = h.controller.check(); h.last('status').resolve(status('reviewed', 3)); await query;
  assert.equal(h.state.status.phase, 'reviewed'); assert.notEqual(h.controller.confirmReason(), null);
  assert.equal(await h.controller.confirm(), false); assert.equal(h.calls.length, 1);
});

test('Check and Stop remain original while a long request is pending; earlier replies cannot undo Stop', async () => {
  const h = harness(), read = h.controller.review();
  assert.match(h.controller.stopReason(), /Check status/);
  const check = h.controller.check(); h.last('status').resolve(status('reading', 2)); await check;
  assert.equal(h.controller.stopReason(), null);
  const stop = h.controller.stop(); assert.deepEqual(h.last('cancel').args, [ID]);
  assert.equal(await h.controller.review(), false);
  h.last('cancel').resolve(status('refused', 5)); await stop;
  assert.notEqual(h.controller.ownerReason(), null, 'the original long Promise has not returned');
  let joined = false; const all = h.controller.whenSettled().then(() => { joined = true; }); await Promise.resolve(); assert.equal(joined, false);
  h.last('review').resolve(status('reviewed', 4)); await read; await all;
  assert.equal(h.state.status.phase, 'refused'); assert.equal(h.state.status.revision, 5); assert.equal(h.controller.ownerReason(), null);
  assert.notEqual(h.controller.confirmReason(), null);
});

test('project/account ABA retires only UI review, keeps original pending and never publishes late freshness', async () => {
  const h = harness(), read = h.controller.review(); h.change({ projectId: 'project-2' }); h.change({ projectId: 'project-1' });
  assert.notEqual(h.controller.ownerReason(), null); assert.equal(await h.controller.review(), false);
  h.last('review').resolve(status('reviewed', 3)); await read;
  assert.equal(h.state.stale, true); assert.notEqual(h.controller.confirmReason(), null); assert.equal(h.controller.ownerReason(), null);
  await h.reviewed(); assert.equal(h.controller.confirmReason(), null);
  h.change(); assert.notEqual(h.controller.confirmReason(), null, 'same-string account/repository intent is still a new context');
});

test('erroneous host rebind cannot redirect original status or Stop while pending', async () => {
  const h = harness(), read = h.controller.review(); h.change({ port: h.makePort('replacement'), nativeSession: {}, projectId: 'project-2' });
  const check = h.controller.check(); assert.equal(h.last('status').label, 'original'); h.last('status').resolve(status('reading', 2)); await check;
  const stop = h.controller.stop(); assert.equal(h.last('cancel').label, 'original'); h.last('cancel').resolve(status('stopping', 3)); await stop;
  h.last('review').resolve(status('refused', 4)); await read;
  assert.equal(h.state.stale, true); assert.equal(h.controller.ownerReason(), null);
  const next = h.controller.check(); assert.equal(h.last('status').label, 'replacement'); h.last('status').resolve(status()); await next;
});

test('malformed or unreturned action latches unknown; later status cannot invent cleanup credit', async () => {
  for (const result of [null, { ...status('reviewed'), token: 'inert-private' }, status('connected', 3), status('reviewed', 3, ID, 'foreign')]) {
    const h = harness(), read = h.controller.review(); h.last('review').resolve(result); await read;
    assert.equal(h.state.unknown, true); assert.equal(await h.controller.review(), false);
    const check = h.controller.check(); h.last('status').resolve(status('refused', 8)); await check;
    assert.equal(h.state.unknown, true); assert.notEqual(h.controller.ownerReason(), null);
  }
  const h = harness(), read = h.controller.review(); h.last('review').reject(new Error('PRIVATE_SYNTHETIC_DETAIL')); await read;
  assert.equal(h.state.unknown, true); assert.equal(JSON.stringify(h.state).includes('PRIVATE_SYNTHETIC_DETAIL'), false);
});

test('only original native before-install errors allow a new explicit review, not generic refusals', async () => {
  for (const code of ['version_enrollment_not_started_busy', 'version_enrollment_not_started_not_connected']) {
    const h = harness(), read = h.controller.review(); h.last('review').reject({ code, message: 'PRIVATE_SYNTHETIC_DETAIL' }); await read;
    assert.equal(h.state.unknown, false); assert.equal(h.controller.ownerReason(), null); assert.equal(h.state.stale, true);
    assert.equal(JSON.stringify(h.state).includes('PRIVATE_SYNTHETIC_DETAIL'), false);
  }
  const h = harness(), read = h.controller.review(); h.last('review').reject({ code: 'version_enrollment_busy' }); await read;
  assert.equal(h.state.unknown, true);
});

test('reentrant listeners cannot hand off stale or duplicate Review/Stop', async () => {
  const h = harness(); let once = false, duplicate;
  h.controller.subscribe(() => { if (!once && h.state.pending) { once = true; duplicate = h.controller.review(); h.change(); } });
  assert.equal(await h.controller.review(), false); assert.equal(await duplicate, false); assert.equal(h.calls.length, 0);
  const second = harness(); await second.reviewed(); let again = false, duplicateStop;
  second.controller.subscribe(() => { if (!again && second.state.stopping) { again = true; duplicateStop = second.controller.stop(); } });
  const stop = second.controller.stop(); assert.equal(second.calls.filter((c) => c.kind === 'cancel').length, 1);
  second.last('cancel').resolve(status('refused', 4)); await stop; assert.equal(await duplicateStop, false);
});

test('descriptor-time context change vetoes a review even after successful structural parsing', async () => {
  const h = harness(), read = h.controller.review(); let once = false;
  const raw = new Proxy(status('reviewed', 3), { getOwnPropertyDescriptor(target, name) {
    if (!once) { once = true; h.change(); } return Reflect.getOwnPropertyDescriptor(target, name);
  } });
  h.last('review').resolve(raw); await read;
  assert.equal(h.state.unknown, false); assert.equal(h.state.stale, true); assert.notEqual(h.controller.confirmReason(), null);
});

test('native revision contradictions and unknown never become connected or release a pending promise', async () => {
  const h = harness(); await h.reviewed();
  const check = h.controller.check(); h.last('status').resolve(status('connected', 3)); await check;
  assert.equal(h.state.unknown, true);
  const other = harness(), read = other.controller.review(); const query = other.controller.check();
  other.last('status').resolve(status('cleanup-unknown', 2)); await query;
  other.last('review').resolve(status('refused', 3)); await read;
  assert.equal(other.state.unknown, true); assert.notEqual(other.controller.ownerReason(), null);
});

test('disposal preserves original completion and all help keeps manual/floor limitations explicit', async () => {
  const h = harness(), read = h.controller.review(); let finished = false;
  const join = h.controller.whenSettled().then(() => { finished = true; }); h.controller.dispose(); await Promise.resolve();
  assert.equal(finished, false); assert.equal(await h.controller.check(), false); assert.equal(h.calls.length, 1);
  h.last('review').resolve(status('reviewed', 3)); await read; await join;
  assert.equal(h.state.stale, true); assert.equal(finished, true);
  assert.match(versionEnrollmentHelp('state-too-large'), /All records were kept.*manual versions.*do not delete or reset state/s);
  assert.match(versionEnrollmentHelp('counter-missing'), /does not create a counter/);
  assert.match(versionEnrollmentHelp(null), /Manual versions remain unchanged/);
});
