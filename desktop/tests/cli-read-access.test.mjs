// Inert DATA and manually settled Promises only. No native host, IPC, files,
// timers, CLI connection, permission grant, network, DOM or source execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { CLI_READ_ACCESS_MAX_MS, CLI_READ_ACCESS_SCOPE, cliReadAccessSummary, cliReadAccessRevisionFits, parseCliReadAccessCheck, parseCliReadAccessStatus } from '../src/cliReadAccess.ts';
import { CliReadAccessController } from '../src/cliReadAccessController.ts';
import { createNativeApi } from '../src/bridge.ts';

const ID = 'a'.repeat(32), OTHER_ID = 'b'.repeat(32);
const on = (ids = [ID], remainingMs = CLI_READ_ACCESS_MAX_MS) => ({ enabled: true, remainingMs, projectIds: ids });
const off = () => ({ enabled: false, remainingMs: 0, projectIds: [] });
const checked = (status = off(), permissionRevision = '7') => ({ ...status, permissionRevision });
const project = (id = 'project-a') => ({ id, name: id === 'project-a' ? 'Example app' : 'Another app' });

test('native bridge exposes only the fixed read-access operations and retains independent revocation', async () => {
  const calls = [], pendingAllow = deferred();
  const api = createNativeApi('native', (command, args) => {
    calls.push({ command, args });
    return command === 'allow_application_read' ? pendingAllow.promise : Promise.resolve(command === 'application_read_status' ? checked() : off());
  });
  assert.deepEqual(calls, [], 'constructing or showing the port must not grant access');
  assert.ok(Object.isFrozen(api.applicationRead));
  const allow = api.applicationRead.allow('project-a', '7');
  assert.deepEqual(await api.applicationRead.revoke(), off());
  assert.deepEqual(await api.applicationRead.status(), checked());
  assert.deepEqual(calls, [
    { command: 'allow_application_read', args: { projectId: 'project-a', expectedPermissionRevision: '7' } },
    { command: 'revoke_application_read', args: {} },
    { command: 'application_read_status', args: {} },
  ]);
  pendingAllow.resolve(off());
  await allow;
  await assert.rejects(api.applicationRead.allow('../private', '7'), { code: 'cli_access_invalid_request' });
  for (const stamp of [undefined, null, 7, '', '07', '+7', '-1', '7\n', '18446744073709551616'])
    await assert.rejects(api.applicationRead.allow('project-a', stamp), { code: 'cli_access_invalid_request' });
  assert.equal(calls.length, 3, 'invalid input never reaches native admission');
});

test('unavailable bridge cannot expose an agent port or manufacture a successful native reply', () => {
  const api = createNativeApi('unavailable', () => { assert.fail('unavailable transport was invoked'); });
  assert.equal(api.applicationRead, undefined);
});
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function harness() {
  const h = { time: 1000, calls: [], active: 0, maxActive: 0 };
  h.port = (label) => {
    const call = (kind, input) => {
      const pending = deferred();
      h.calls.push({ ...pending, label, kind, input });
      h.active++; h.maxActive = Math.max(h.maxActive, h.active);
      return pending.promise.finally(() => { h.active--; });
    };
    return { status: () => call('status'), allow: (id, expectedPermissionRevision) => call('allow', { projectId: id, expectedPermissionRevision }), revoke: () => call('revoke') };
  };
  h.context = { port: h.port('original'), nativeSession: {}, selectedProject: project(), preview: false, busy: false };
  h.controller = new CliReadAccessController({ current: () => h.context, now: () => h.time });
  h.last = (kind) => h.calls.filter((call) => call.kind === kind).at(-1);
  h.change = (next) => {
    h.controller.invalidateContext(); h.context = { ...h.context, ...next }; h.controller.syncContext();
  };
  Object.defineProperty(h, 'state', { get: () => h.controller.getSnapshot() });
  return h;
}

// Real controller Check and its actual Promise finish, not an injected grant or
// private controller state. Its call remains in every test's retained roster.
async function prime(h, revision = '7') {
  const work = h.controller.check();
  h.last('status').resolve(checked(off(), revision));
  await work;
  assert.equal(h.state.pendingCount, 0);
}
async function checkedHarness() { const h = harness(); await prime(h); h.checkedObservation = h.state.observation; return h; }

test('MAIN Check revision is exact lossless decimal DATA and never extends the base status grammar', () => {
  for (const revision of ['0', '7', '9007199254740993', '18446744073709551615']) {
    const raw = checked(on(), revision), parsed = parseCliReadAccessCheck(raw);
    assert.equal(parsed.permissionRevision, revision); assert.ok(Object.isFrozen(parsed));
    assert.ok(Object.isFrozen(parsed.status)); assert.ok(Object.isFrozen(parsed.status.projectIds));
    raw.permissionRevision = '9'; raw.projectIds[0] = OTHER_ID;
    assert.equal(parsed.permissionRevision, revision); assert.deepEqual(parsed.status.projectIds, [ID]);
  }
  for (const revision of [0, null, undefined, '', '00', '+1', '-1', '1\n', ' 1', '18446744073709551616']) {
    assert.equal(cliReadAccessRevisionFits(revision), false);
    assert.equal(parseCliReadAccessCheck({ ...off(), permissionRevision: revision }), null);
  }
  assert.equal(parseCliReadAccessCheck(off()), null, 'old shared status cannot supply new MAIN intent');
  assert.equal(parseCliReadAccessStatus(checked()), null, 'shared/CLI/headless parser remains exact3');
  let reads = 0;
  const accessor = checked(); Object.defineProperty(accessor, 'permissionRevision', { enumerable: true, get() { reads++; return '7'; } });
  for (const raw of [accessor, { ...checked(), extra: true }, { ...checked(), [Symbol('extra')]: true },
    Object.assign(Object.create({}), checked())]) assert.equal(parseCliReadAccessCheck(raw), null);
  assert.equal(reads, 0);
});

test('Allow consumes only an actual explicit Check before handoff and never refreshes or rearms itself', async () => {
  const h = harness();
  assert.equal(await h.controller.allowSelected(), false); assert.equal(h.calls.length, 0);
  assert.match(h.controller.allowReason(), /Check access/);
  const checking = h.controller.check();
  assert.equal(await h.controller.allowSelected(), false, 'pending Check is not its returned observation');
  h.last('status').resolve(checked(off(), '9007199254740993')); await checking;
  const allowing = h.controller.allowSelected();
  assert.deepEqual(h.calls.map((v) => v.kind), ['status', 'allow'], 'Allow performs no hidden status refresh');
  assert.deepEqual(h.last('allow').input, { projectId: 'project-a', expectedPermissionRevision: '9007199254740993' });
  h.last('allow').resolve(on()); await allowing;
  assert.equal(await h.controller.allowSelected(), false, 'even successful Allow never lends a new consent stamp');
  assert.equal(h.calls.length, 2); assert.match(h.controller.allowReason(), /Check access/);
  const bad = h.controller.check(); h.last('status').resolve(off()); await bad;
  assert.equal(await h.controller.allowSelected(), false, 'unstamped response cannot rearm the old checked intent');
  assert.equal(h.calls.length, 3);
});

test('delayed original Allow keeps its old stamp across Revoke and only a fresh explicit Check can issue another', async () => {
  const h = await checkedHarness();
  const allowing = h.controller.allowSelected(), original = h.last('allow');
  const revoking = h.controller.revoke();
  h.last('revoke').resolve(off()); await revoking;
  assert.deepEqual(original.input, { projectId: 'project-a', expectedPermissionRevision: '7' });
  assert.deepEqual(h.calls.map((v) => v.kind), ['status', 'allow', 'revoke']);
  // The original native Host test covers the stale epoch's actual refusal.
  // This controller test proves there is no refresh/rebind while that request
  // is still pending at its native admission cut.
  original.reject({ code: 'cli_access_denied' }); await allowing;
  assert.equal(h.state.observation.status.enabled, false);
  assert.equal(await h.controller.allowSelected(), false);
  await prime(h, '8');
  const next = h.controller.allowSelected();
  assert.equal(h.last('allow').input.expectedPermissionRevision, '8');
  h.last('allow').resolve(off()); await next;
  assert.deepEqual(h.calls.map((v) => v.kind), ['status', 'allow', 'revoke', 'status', 'allow']);
});

test('a reentrant Check inspection cannot bind a stamp after original-host Revoke or project ABA', async () => {
  for (const change of ['revoke', 'aba']) {
    const h = harness(), checking = h.controller.check(); let once = false, revoking = null;
    const raw = new Proxy(checked(), { getPrototypeOf(target) {
      if (!once) {
        once = true;
        if (change === 'revoke') revoking = h.controller.revoke();
        else { h.change({ selectedProject: project('project-b') }); h.change({ selectedProject: project() }); }
      }
      return Reflect.getPrototypeOf(target);
    } });
    h.last('status').resolve(raw); await checking;
    if (revoking) { h.last('revoke').resolve(off()); await revoking; }
    assert.equal(await h.controller.allowSelected(), false);
    assert.equal(h.calls.filter((v) => v.kind === 'allow').length, 0);
    assert.match(h.controller.allowReason(), /Check access/);
  }
});

test('exact native status is bounded, copied and frozen without runtime-project membership inference', () => {
  const source = on(), parsed = parseCliReadAccessStatus(source);
  assert.deepEqual(parsed, source); assert.ok(Object.isFrozen(parsed)); assert.ok(Object.isFrozen(parsed.projectIds));
  source.projectIds[0] = OTHER_ID; source.remainingMs = 1;
  assert.deepEqual(parsed.projectIds, [ID]); assert.equal(parsed.remainingMs, CLI_READ_ACCESS_MAX_MS);
  assert.deepEqual(parseCliReadAccessStatus(off()), off());
  assert.deepEqual(parseCliReadAccessStatus(Object.assign(Object.create(null), on())), on());
  assert.ok(parseCliReadAccessStatus(on([ID], 0)), 'native live-grant/remaining-time race is not fabricated Off');
});

test('status parser refuses accessors, extra private fields, symbols and unusual prototypes without reading getters', () => {
  let reads = 0;
  const getter = { ...on() }; Object.defineProperty(getter, 'enabled', { enumerable: true, get() { reads++; return true; } });
  const nested = []; Object.defineProperty(nested, '0', { enumerable: true, get() { reads++; return ID; } });
  const cases = [getter, on(nested), { ...on(), token: 'SYNTHETIC_NOT_A_TOKEN' }, { ...on(), [Symbol('extra')]: true },
    Object.assign(Object.create({ inherited: true }), on()), { ...on(), toJSON() { reads++; return off(); } }, null, [], 'enabled', new Date(0)];
  for (const value of cases) assert.equal(parseCliReadAccessStatus(value), null);
  const hidden = { ...on() }; Object.defineProperty(hidden, 'remainingMs', { enumerable: false, value: 1 });
  assert.equal(parseCliReadAccessStatus(hidden), null); assert.equal(reads, 0);
});

test('status bounds reject invalid IDs, contradictory flags, oversized/sparse arrays and non-native numbers', () => {
  for (const ids of [[], [ID, ID], ['0'.repeat(32)], ['A'.repeat(32)], [`${ID}\n`], ['project-a'], [1], [null],
    Array(65).fill(ID), new Array(1_000_000)]) assert.equal(parseCliReadAccessStatus(on(ids)), null);
  const extra = [ID]; extra.extra = true;
  assert.equal(parseCliReadAccessStatus(on(extra)), null);
  const custom = [ID]; Object.setPrototypeOf(custom, null);
  assert.equal(parseCliReadAccessStatus(on(custom)), null);
  for (const remainingMs of [-1, 0.5, NaN, Infinity, CLI_READ_ACCESS_MAX_MS + 1, Number.MAX_SAFE_INTEGER, '1'])
    assert.equal(parseCliReadAccessStatus(on([ID], remainingMs)), null);
  assert.equal(parseCliReadAccessStatus({ ...off(), remainingMs: 1 }), null);
  assert.equal(parseCliReadAccessStatus({ ...off(), projectIds: [ID] }), null);
  assert.equal(parseCliReadAccessStatus({ ...on(), enabled: 1 }), null);
});

test('summary reports permitted project count, never IDs or selected-project membership or clock-derived Off', () => {
  const status = parseCliReadAccessStatus(on([ID, OTHER_ID]));
  const summary = cliReadAccessSummary(status);
  assert.match(summary.title, /^2 projects were allowed at last check$/);
  assert.match(summary.detail, /does not confirm.*currently selected project/);
  assert.equal(JSON.stringify(summary).includes(ID), false);
  assert.equal(JSON.stringify(summary).includes(OTHER_ID), false);
  for (const elapsed of [CLI_READ_ACCESS_MAX_MS, CLI_READ_ACCESS_MAX_MS + 1, NaN, -1])
    assert.equal(cliReadAccessSummary(status, elapsed).title, 'Access needs another check');
  assert.equal(cliReadAccessSummary(parseCliReadAccessStatus(on([ID], 0))).title, 'Access needs another check');
  assert.match(CLI_READ_ACCESS_SCOPE, /in-memory drafts, credentials or arbitrary files/);
  assert.match(CLI_READ_ACCESS_SCOPE, /cannot edit files, run commands, build, sign or publish/);
});

test('constructing, subscribing, syncing and elapsed display time never request, allow or renew access', () => {
  const h = harness(), original = h.state;
  let notified = 0; const unsubscribe = h.controller.subscribe(() => { notified++; });
  h.controller.syncContext(); h.time += 10_000_000; h.controller.summary(); unsubscribe();
  assert.equal(h.state, original); assert.equal(notified, 0); assert.equal(h.calls.length, 0);
});

test('preview/disconnected contexts cannot call any port, and malformed runtime project IDs cannot Allow', async () => {
  for (const context of [{ preview: true }, { nativeSession: null }, { port: null }]) {
    const h = harness(); h.change(context);
    assert.equal(await h.controller.check(), false); assert.equal(await h.controller.allowSelected(), false);
    assert.equal(await h.controller.revoke(), false); assert.equal(h.calls.length, 0);
  }
  for (const id of ['', '../somewhere', 'x'.repeat(65), `project-a\n`]) {
    const h = harness(); h.change({ selectedProject: project(id) });
    assert.equal(await h.controller.allowSelected(), false); assert.equal(h.calls.length, 0);
  }
});

test('Revoke and Check do not borrow Allow’s selection, busy or known-grant gate', async () => {
  const h = harness(); h.change({ selectedProject: null, busy: true });
  assert.equal(await h.controller.allowSelected(), false);
  const checking = h.controller.check(); h.last('status').resolve(checked(on())); await checking;
  assert.equal(h.controller.revokeReason(), null);
  const revoking = h.controller.revoke(); h.last('revoke').resolve(off()); await revoking;
  assert.equal(h.state.observation.status.enabled, false); assert.equal(h.calls.length, 2);
  h.change({ selectedProject: project(), busy: true });
  assert.equal(await h.controller.allowSelected(), false); assert.match(h.controller.allowReason(), /current task/);
});

test('Allow passes only the exact registered runtime selection, and a status count never proves its membership', async () => {
  const h = await checkedHarness(), allowing = h.controller.allowSelected();
  assert.deepEqual(h.calls.map(({ kind, input }) => ({ kind, input })), [{ kind: 'status', input: undefined }, { kind: 'allow', input: { projectId: 'project-a', expectedPermissionRevision: '7' } }]);
  h.last('allow').resolve(on([OTHER_ID])); await allowing;
  assert.match(h.controller.summary().title, /^1 project was/);
  assert.match(h.controller.summary().detail, /does not confirm/);
  assert.equal(h.state.observation.status.projectIds[0], OTHER_ID);
  await prime(h, '8');
  const unexpected = h.controller.allowSelected(); h.last('allow').resolve(on([ID, OTHER_ID])); await unexpected;
  assert.equal(h.state.stale, true); assert.equal(h.state.issue, 'response-invalid');
});

test('ordinary calls remain singleflight until the original promise actually settles', async () => {
  const h = harness(), checking = h.controller.check();
  assert.equal(await h.controller.check(), false); assert.equal(await h.controller.allowSelected(), false);
  let joined = false; const join = h.controller.whenSettled().then(() => { joined = true; });
  await Promise.resolve(); assert.equal(joined, false); assert.equal(h.state.pendingCount, 1);
  h.last('status').resolve(checked()); await checking; await join;
  assert.equal(joined, true); assert.equal(h.controller.pendingReason(), null); assert.equal(h.maxActive, 1);
});

test('explicit Revoke immediately overlaps Allow/status, fences either arrival order and retains both original promises', async () => {
  for (const kind of ['allow', 'status']) for (const first of ['ordinary', 'revoke']) {
    const h = await checkedHarness(), ordinary = kind === 'allow' ? h.controller.allowSelected() : h.controller.check();
    const revoking = h.controller.revoke();
    assert.deepEqual(h.calls.map((call) => call.kind), ['status', kind, 'revoke'], 'Revoke is sent now, not queued behind an acknowledgement');
    assert.equal(h.state.pendingCount, 2); assert.equal(h.state.pendingRetired, true); assert.equal(h.maxActive, 2);
    assert.equal(await h.controller.check(), false); assert.equal(await h.controller.allowSelected(), false);
    assert.equal(await h.controller.revoke(), false, 'only one revocation at a time');
    let joined = false; const join = h.controller.whenSettled().then(() => { joined = true; });
    if (first === 'revoke') {
      h.last('revoke').resolve(off()); await revoking;
      assert.equal(h.state.observation.status.enabled, false); assert.equal(h.state.pendingCount, 1);
      assert.notEqual(h.controller.pendingReason(), null); assert.equal(joined, false);
      h.last(kind).resolve(kind === 'status' ? checked(on()) : on()); await ordinary;
    } else {
      h.last(kind).resolve(kind === 'status' ? checked(on()) : on()); await ordinary;
      assert.equal(h.state.observation, h.checkedObservation); assert.equal(h.state.pendingCount, 1); assert.equal(joined, false);
      h.last('revoke').resolve(off()); await revoking;
    }
    await join; assert.equal(joined, true); assert.equal(h.state.pendingCount, 0);
    assert.equal(h.state.observation.status.enabled, false); assert.equal(h.state.stale, false); assert.equal(h.state.issue, null);
  }
});

test('a reply resolved just before Revoke but not yet delivered cannot overwrite its later generation', async () => {
  const h = await checkedHarness(), allowing = h.controller.allowSelected();
  h.last('allow').resolve(on()); // Delivery remains a queued promise continuation.
  const revoking = h.controller.revoke(); h.last('revoke').resolve(off());
  await Promise.all([allowing, revoking]);
  assert.equal(h.state.observation.status.enabled, false); assert.equal(h.state.pendingCount, 0);
});

test('a late old Allow failure cannot replace a confirmed original-host Revoke status or expose raw errors', async () => {
  const h = await checkedHarness(), allowing = h.controller.allowSelected(), revoking = h.controller.revoke();
  h.last('revoke').resolve(off()); await revoking;
  h.last('allow').reject(new Error('SYNTHETIC_PRIVATE_DIAGNOSTIC')); await allowing;
  assert.equal(h.state.observation.status.enabled, false); assert.equal(h.state.issue, null); assert.equal(h.state.stale, false);
  assert.equal(JSON.stringify(h.state).includes('SYNTHETIC_PRIVATE_DIAGNOSTIC'), false);
});

test('failed, malformed or still-enabled Revoke readback remains unknown, never fabricated Off or automatic retry', async () => {
  for (const result of [undefined, { enabled: false }, on(), new Error('SYNTHETIC_PRIVATE_DIAGNOSTIC')]) {
    const h = await checkedHarness(), allowing = h.controller.allowSelected(), revoking = h.controller.revoke();
    if (result instanceof Error) h.last('revoke').reject(result); else h.last('revoke').resolve(result);
    await revoking; h.last('allow').resolve(on()); await allowing;
    assert.equal(h.state.observation, h.checkedObservation); assert.equal(h.state.stale, true); assert.equal(h.state.issue, 'revoke-unconfirmed');
    assert.equal(h.controller.summary().title, 'Access not checked'); assert.equal(h.calls.length, 3);
    assert.equal(h.controller.revokeReason(), null, 'unknown status does not prevent an explicit native Revoke');
  }
});

test('selection changes and away-and-back ABA discard stale replies without releasing an original promise', async () => {
  for (const back of [false, true]) {
    const h = harness(), checking = h.controller.check();
    h.change({ selectedProject: project('project-b') }); if (back) h.change({ selectedProject: project() });
    assert.equal(h.state.pendingCount, 1); assert.equal(await h.controller.check(), false);
    h.last('status').resolve(checked(on())); await checking;
    assert.equal(h.state.observation, null); assert.equal(h.state.stale, true);
    assert.equal(h.state.selectedProject.id, back ? 'project-a' : 'project-b');
  }
});

test('a final context comparison rejects an unsynced changed project and a replaced native session', async () => {
  for (const change of [{ selectedProject: project('project-b') }, { nativeSession: {} }, { preview: true }]) {
    const h = await checkedHarness(), allowing = h.controller.allowSelected();
    h.context = { ...h.context, ...change }; h.last('allow').resolve(on()); await allowing;
    assert.equal(h.state.observation, h.checkedObservation); assert.equal(h.state.stale, true);
  }
});

test('context change or immediate Revoke during response inspection vetoes publication after parsing too', async () => {
  for (const change of ['project', 'revoke']) {
    const h = await checkedHarness(), allowing = h.controller.allowSelected(); let once = false, revoking = null;
    const reply = new Proxy(on(), { getPrototypeOf(target) {
      if (!once) { once = true; if (change === 'project') h.change({ selectedProject: project('project-b') }); else revoking = h.controller.revoke(); }
      return Reflect.getPrototypeOf(target);
    } });
    h.last('allow').resolve(reply); await allowing;
    assert.equal(h.state.observation, h.checkedObservation); assert.equal(h.state.stale, true);
    if (revoking) { h.last('revoke').resolve(off()); await revoking; assert.equal(h.state.observation.status.enabled, false); }
    assert.equal(h.state.pendingCount, 0);
  }
});

test('host replacement never retargets an old request, and pending ownership survives the new port', async () => {
  const h = await checkedHarness(), allowing = h.controller.allowSelected(), original = h.last('allow');
  h.change({ port: h.port('replacement'), nativeSession: {} });
  assert.equal(await h.controller.check(), false); assert.equal(h.state.pendingCount, 1);
  const revoking = h.controller.revoke();
  assert.equal(h.last('revoke').label, 'replacement'); assert.equal(original.label, 'original');
  h.last('revoke').resolve(off()); await revoking;
  original.resolve(on()); await allowing;
  assert.equal(h.state.observation.status.enabled, false); assert.equal(h.state.pendingCount, 0);
  // This tests UI scope only. Root still must join/revoke the ORIGINAL native
  // host independently; a new host's Off is not proof about the retired host.
});

test('a synchronous listener can Revoke before Allow handoff, preventing the Allow send entirely', async () => {
  const h = await checkedHarness(); let revoking = null, once = false;
  const stop = h.controller.subscribe(() => {
    if (!once && h.state.pending === 'allow') { once = true; revoking = h.controller.revoke(); }
  });
  assert.equal(await h.controller.allowSelected(), false);
  assert.deepEqual(h.calls.map((call) => call.kind), ['status', 'revoke']); assert.equal(h.state.pendingCount, 1);
  h.last('revoke').resolve(off()); await revoking; stop();
  assert.equal(h.state.observation.status.enabled, false); assert.equal(h.state.pendingCount, 0);
});

test('reentrant project or other-owner changes before Allow handoff veto its original send', async () => {
  for (const change of ['project', 'busy']) {
    const h = await checkedHarness(); let once = false;
    const stop = h.controller.subscribe(() => {
      if (!once && h.state.pending === 'allow') {
        once = true;
        if (change === 'project') h.change({ selectedProject: project('project-b') });
        else h.context = { ...h.context, busy: true };
      }
    });
    assert.equal(await h.controller.allowSelected(), false); stop();
    assert.equal(h.calls.length, 1); assert.equal(h.state.pendingCount, 0);
  }
});

test('a reentrant project/busy change cannot delay original-host Revoke, but its old selection reply stays stale', async () => {
  const h = harness(); let once = false;
  const stop = h.controller.subscribe(() => {
    if (!once && h.state.revoking) { once = true; h.change({ selectedProject: null, busy: true }); }
  });
  const revoking = h.controller.revoke();
  assert.equal(h.calls.length, 1); assert.equal(h.last('revoke').label, 'original');
  h.last('revoke').resolve(off()); await revoking; stop();
  assert.equal(h.state.observation, null); assert.equal(h.state.stale, true); assert.equal(h.state.selectedProject, null);
});

test('a reentrant preview/disconnection cannot send a Revoke to a replacement or nonexistent host', async () => {
  for (const change of [{ preview: true }, { nativeSession: null }, { port: null }]) {
    const h = harness(); let once = false;
    const stop = h.controller.subscribe(() => { if (!once && h.state.revoking) { once = true; h.change(change); } });
    assert.equal(await h.controller.revoke(), false); stop(); assert.equal(h.calls.length, 0); assert.equal(h.state.pendingCount, 0);
  }
});

test('unusable status/error invalidates an earlier successful observation without reading raw rejection fields', async () => {
  for (const invalid of [true, false]) {
    const h = harness(), first = h.controller.check(); h.last('status').resolve(checked(on())); await first;
    const saved = h.state.observation, checking = h.controller.check();
    let reads = 0; const rejection = {}; Object.defineProperty(rejection, 'message', { get() { reads++; return 'SYNTHETIC_PRIVATE_DIAGNOSTIC'; } });
    if (invalid) h.last('status').resolve({ ...checked(), extra: true }); else h.last('status').reject(rejection);
    await checking;
    assert.equal(h.state.observation, saved, 'earlier data is retained only as stale reference');
    assert.equal(h.state.stale, true); assert.equal(h.controller.summary().title, 'Access not checked'); assert.equal(reads, 0);
    assert.equal(h.calls.length, 2); assert.equal(JSON.stringify(h.state).includes('SYNTHETIC_PRIVATE_DIAGNOSTIC'), false);
  }
});

test('monotonic display expiry and backwards/invalid clock never synthesize native Off or renew permission', async () => {
  const h = harness(), checking = h.controller.check();
  h.time += 20_000; h.last('status').resolve(checked(on([ID], 60_000))); await checking;
  const original = h.state.observation;
  assert.match(h.controller.summary().detail, /Up to 1 minute/);
  for (const time of [61_000, 0, NaN]) {
    h.time = time; assert.equal(h.controller.summary().title, 'Access needs another check');
    assert.equal(h.state.observation, original); assert.equal(h.state.observation.status.enabled, true); assert.equal(h.calls.length, 1);
  }
});

test('listener exceptions and disposal never abandon either original promise or create another request', async () => {
  const h = await checkedHarness(); let notified = 0;
  h.controller.subscribe(() => { notified++; throw new Error('synthetic render failure'); });
  const allowing = h.controller.allowSelected(), revoking = h.controller.revoke();
  h.controller.dispose(); const atDispose = notified;
  let joined = false; const join = h.controller.whenSettled().then(() => { joined = true; });
  h.last('revoke').resolve(off()); await revoking;
  assert.equal(joined, false); assert.equal(h.state.pendingCount, 1);
  assert.equal(await h.controller.check(), false); assert.equal(await h.controller.revoke(), false);
  h.last('allow').resolve(on()); await allowing; await join;
  assert.equal(joined, true); assert.equal(h.state.pendingCount, 0); assert.equal(notified, atDispose);
  assert.equal(h.state.observation, h.checkedObservation); assert.equal(h.calls.length, 3);
});
