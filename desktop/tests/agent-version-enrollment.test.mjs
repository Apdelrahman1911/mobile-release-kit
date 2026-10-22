// Inert comparison DATA and manually returned original promises only. These
// exercise the REAL two controllers/RAW codecs, not native/Store/HTTP finality.
import assert from 'node:assert/strict';
import test from 'node:test';
import { VersionEnrollmentController } from '../src/versionEnrollmentController.ts';
import { AgentGithubActionAccessController } from '../src/agentGithubActionAccessController.ts';
import { createNativeApi } from '../src/bridge.ts';
import { parseVersionEnrollmentStatus } from '../src/versionEnrollment.ts';
import { createAgentVersionEnrollmentPort, isEnrollmentActionKind, parseEnrollmentActionSelection,
  parseEnrollmentActionReference, parseEnrollmentActionResult } from '../src/agentVersionEnrollment.ts';
import { parseGithubActionSelection, parseGithubActionStatus, parseAgentGithubActionAccess,
  githubActionCommands } from '../src/agentGithubActionAccess.ts';

const hex = (c, n = 32) => c.repeat(n), PROJECT = hex('1'), SERVICE = hex('2'), REVIEW = hex('a'), CONNECT = hex('b');
const REVIEW_KIND = 'counter-enrollment-review', CONNECT_KIND = 'counter-enrollment-connect';
const query = { projectId: PROJECT, serviceInstance: SERVICE, requestId: hex('7') };
const clone = structuredClone;
function native(phase = 'idle', revision = 1, operationId = REVIEW, reason = null) {
  return { schemaVersion: 1, revision, projectId: phase === 'idle' ? null : PROJECT, operationId: phase === 'idle' ? null : operationId,
    phase, reason: reason ?? (phase === 'connected' ? 'connected' : phase === 'refused' ? 'review-changed' : 'none'),
    review: phase === 'reviewed' ? { id: operationId, repository: 'fixture/app', version: { name: '1.2', build: 7 }, reservations: 2 } : null };
}
function selected(kind = REVIEW_KIND, revision = 1) {
  return { kind, sessionId: 'connection-a', expectedRevision: revision, expectedConnectionRevision: 8,
    ...(kind === CONNECT_KIND ? { reviewId: REVIEW } : {}) };
}
function reference(selection) {
  return { ...selection, ...(selection.kind === CONNECT_KIND ? { reviewSha256: hex('d', 64) } : { requestSha256: hex('c', 64) }) };
}
function result(kind, value) {
  return { type: 'enrollment', operation: kind === REVIEW_KIND ? 'review' : 'connect', phase: value.phase, reason: value.reason, review: clone(value.review) };
}
function row(selection = selected(), change = {}) {
  return { origin: query, grantId: hex('3'), review: reference(selection), revision: 1, state: 'queued', settlement: 'pending',
    operationId: null, reason: 'none', effect: selection.kind === REVIEW_KIND ? 'none' : 'not-sent', neverAdmitted: false, doNotReplay: true, ...change };
}
const empty = (revision = '0') => ({ permissionRevision: revision, serviceInstance: null, projectId: null, grantId: null, review: null,
  enabled: false, remainingMs: 0, consumed: false, pending: false, unknown: false, status: null });
function access(grant, status = null, permissionRevision = '1', overrides = {}) {
  return { permissionRevision, serviceInstance: SERVICE, projectId: PROJECT, grantId: grant.id, review: grant.review,
    enabled: status === null, remainingMs: status === null ? 90_000 : 0, consumed: status !== null,
    pending: status !== null && status.settlement !== 'settled', unknown: status?.state === 'unknown', status, ...overrides };
}
function deferred(kind, args) {
  const d = { kind, args: clone(args), ended: false };
  d.promise = new Promise((resolve, reject) => { d.resolve = v => { d.ended = true; resolve(clone(v)); }; d.reject = e => { d.ended = true; reject(e); }; });
  return d;
}
async function flush() { for (let i = 0; i < 24; ++i) await Promise.resolve(); }
const retained = [];
function fixture() {
  const h = { calls: [], peer: null, permissionRevision: 0n, grants: 0, scopeEpoch: {}, delegates: [] };
  const call = (kind, args) => { const d = deferred(kind, args); h.calls.push(d); return d.promise; };
  const port = Object.fromEntries(['status', 'review', 'confirm', 'cancel'].map(k => [k, (...args) => call('native-' + k, args)]));
  const agentPort = Object.fromEntries(['review', 'confirm'].map(k => [k, (...args) => call('agent-' + k, args)]));
  const permissionPort = Object.fromEntries(['access', 'allow', 'request', 'revoke'].map(k => [k, (...args) => call('permission-' + k, args)]));
  h.context = { port, agentPort, nativeSession: {}, projectId: PROJECT, preview: false, connection: { sessionId: 'connection-a', revision: 8 } };
  let enrollment, permission;
  const own = () => {
    const peer = permission?.peerSelection() ?? enrollment?.agentPeerSelection();
    return !!peer && isEnrollmentActionKind(peer.kind) && enrollment?.agentSelected(peer) === true;
  };
  // SAME exact reciprocal comparison cut as App; kind alone never excludes a
  // foreign owner. current() remains pure and cannot create a native review.
  enrollment = new VersionEnrollmentController({ current: () => ({ ...h.context,
    blockedReason: h.peer ?? (own() ? null : permission?.ownerReason() ?? null) }) });
  permission = new AgentGithubActionAccessController({ current: () => ({ port: permissionPort, nativeSession: h.context.nativeSession,
    projectId: h.context.projectId, epoch: h.scopeEpoch, preview: h.context.preview,
    blockedReason: h.peer ?? (own() ? null : enrollment.ownerReason()),
    reviews: [enrollment.agentSelection(REVIEW_KIND), enrollment.agentSelection(CONNECT_KIND)].filter(Boolean) }),
    syncOriginal: () => enrollment.syncContext(), delegate: s => { const d = enrollment.agentDelegate(s); if (d) h.delegates.push(d); return d; } });
  Object.assign(h, { enrollment, permission, last: kind => h.calls.filter(c => c.kind === kind).at(-1),
    pending: kind => h.calls.find(c => c.kind === kind && !c.ended), count: kind => h.calls.filter(c => c.kind === kind).length });
  h.sync = () => { enrollment.syncContext(); permission.syncContext(); };
  h.change = values => { enrollment.beforeContextIntent(); h.scopeEpoch = {}; Object.assign(h.context, values); h.sync(); };
  h.nativeCheck = async (value = native()) => { const p = enrollment.check(); h.last('native-status').resolve(value); await p; h.sync(); };
  h.permissionCheck = async () => { const p = permission.check(); h.last('permission-access').resolve(empty(String(h.permissionRevision))); await p; h.sync(); };
  h.allow = async (kind = REVIEW_KIND) => {
    assert.equal(permission.choose(kind), true); await h.permissionCheck(); assert.equal(permission.acknowledge(true), true);
    const p = permission.allow(), c = h.last('permission-allow'); assert.ok(c && !c.ended);
    h.selection = clone(c.args[0]); h.grants++;
    h.grant = { id: hex(String(h.grants + 2)), review: reference(h.selection) };
    h.origin = { ...query, requestId: hex(String(h.grants + 6)) };
    h.permissionRevision++; c.resolve(access(h.grant, null, String(h.permissionRevision))); await p;
    assert.equal(permission.getSnapshot().unknown, false); return h.grant;
  };
  h.row = (change = {}) => row(h.selection, { grantId: h.grant.id, review: h.grant.review, origin: h.origin, ...change });
  h.observe = async s => {
    assert.ok(parseGithubActionStatus(s), 'fixture must be valid closed service DATA');
    const p = permission.check(), a = h.pending('permission-access');
    if (a) { a.resolve(access(h.grant, s, String(h.permissionRevision))); await flush(); }
    const q = h.pending('permission-request'); assert.ok(q, 'same request read'); assert.deepEqual(q.args, [h.origin]);
    q.resolve(s); await p; h.status = s;
  };
  h.queued = async () => h.observe(h.row());
  h.final = (value = native('reviewed', 3), change = {}) => h.row({ revision: 5, state: 'complete', settlement: 'settled',
    operationId: value.operationId, effect: h.selection.kind === REVIEW_KIND ? 'none' : 'local-mapping-observed', result: result(h.selection.kind, value), ...change });
  h.returnNative = async value => {
    assert.ok(parseVersionEnrollmentStatus(value)); h.last(h.selection.kind === REVIEW_KIND ? 'agent-review' : 'agent-confirm').resolve(value);
    await enrollment.whenSettled(); await flush(); h.sync();
  };
  h.review = async () => { await h.nativeCheck(); await h.allow(); await h.queued(); await h.returnNative(native('reviewed', 3)); await h.observe(h.final()); };
  h.withdraw = async () => {
    const p = permission.revoke(); h.permissionRevision++;
    h.last('permission-revoke').resolve(access(h.grant, h.status, String(h.permissionRevision), { enabled: false, remainingMs: 0 })); await p;
    await h.permissionCheck();
  };
  retained.push(h); return h;
}
test.afterEach(async () => {
  for (const h of retained.splice(0)) {
    for (const c of h.calls) if (!c.ended) c.reject(new Error('inert original closed by fixture'));
    await flush(); await h.enrollment.whenSettled(); await h.permission.whenSettled();
    h.permission.dispose(); h.enrollment.dispose();
    assert.equal(h.calls.filter(c => !c.ended).length, 0);
  }
});

test('two extra native RAW methods keep exact original IDs; preview and invalid inputs never invoke', async () => {
  const calls = [], invoke = async (command, bytes) => { calls.push([command, JSON.parse(new TextDecoder().decode(bytes))]); assert.ok(bytes.length <= 1024); return native(); };
  const api = createNativeApi('native', invoke, async () => () => {});
  assert.ok(api.agentVersionEnrollment); assert.equal(calls.length, 0);
  await api.agentVersionEnrollment.review(query, PROJECT); await api.agentVersionEnrollment.confirm(query, PROJECT, REVIEW);
  assert.deepEqual(calls, [['agent_version_enrollment_review', { origin: query, input: { projectId: PROJECT } }],
    ['agent_version_enrollment_confirm', { origin: query, input: { projectId: PROJECT, reviewId: REVIEW } }]]);
  const port = createAgentVersionEnrollmentPort(invoke);
  for (const q of [{ ...query, token: 'INERT' }, { ...query, requestId: '0'.repeat(32) }, { ...query, requestId: query.requestId + '\n' }]) assert.throws(() => port.review(q, PROJECT));
  assert.throws(() => port.confirm(query, PROJECT, REVIEW + '\n')); assert.throws(() => port.review(query, '../project'));
  assert.equal(createNativeApi('preview', () => assert.fail('no preview invoke'), null).agentVersionEnrollment, null);
  assert.equal(calls.length, 2);
  await api.agentGithubAction.allow(selected(), '7'); await api.agentGithubAction.allow(selected(CONNECT_KIND, 3), '9');
  assert.deepEqual(calls.slice(2), [['allow_agent_github_action', { selection: selected(), consentVersion: 'agent-counter-enrollment-review-once-v1', expectedPermissionRevision: '7' }],
    ['allow_agent_github_action', { selection: selected(CONNECT_KIND, 3), consentVersion: 'agent-counter-enrollment-connect-once-v1', expectedPermissionRevision: '9' }]]);
});

test('closed enrollment codec correlates both native results without widening old effects or operation IDs', () => {
  for (const kind of [REVIEW_KIND, CONNECT_KIND]) {
    const selection = selected(kind), ref = reference(selection), value = kind === REVIEW_KIND ? native('reviewed', 3) : native('connected', 5, CONNECT);
    const r = row(selection, { revision: 5, state: 'complete', settlement: 'settled', operationId: value.operationId,
      effect: kind === REVIEW_KIND ? 'none' : 'local-mapping-observed', result: result(kind, value) });
    assert.deepEqual(parseGithubActionSelection(selection), Object.assign(Object.create(null), selection)); assert.deepEqual(parseEnrollmentActionReference(ref), Object.assign(Object.create(null), ref)); assert.ok(parseGithubActionStatus(r));
    assert.ok(parseAgentGithubActionAccess(access({ id: r.grantId, review: ref }, r)));
    for (const change of [s => s.operationId = 'version-enrollment-1', s => s.operationId += '\n', s => s.effect = 'accepted',
      s => s.result.phase = 'connected', s => s.result.privateState = {}, s => s.result.operation = 'execute',
      s => { s.state = 'running'; s.settlement = 'pending'; }, s => { s.review.expectedConnectionRevision = 0; }]) {
      const v = clone(r); change(v); if (JSON.stringify(v) !== JSON.stringify(r)) assert.equal(parseGithubActionStatus(v), null);
    }
  }
  const max = native('reviewed', 2); max.review.repository = 'a'.repeat(39) + '/' + 'b'.repeat(100); max.review.version.name = '1'.repeat(64); max.review.reservations = 64;
  assert.ok(parseEnrollmentActionResult(result(REVIEW_KIND, max), REVIEW_KIND, REVIEW));
  for (const mutate of [v => v.review.reservations = 65, v => v.review.id = CONNECT, v => v.review.version.build = -0,
    v => v.review.version.name += '1', v => v.review.repository += '\n', v => v.reason = 'connected']) {
    const v = result(REVIEW_KIND, max); mutate(v); assert.equal(parseEnrollmentActionResult(v, REVIEW_KIND, REVIEW), null);
  }
  for (const s of [{ ...selected(), expectedRevision: 0xffff_ffff }, { ...selected(), expectedConnectionRevision: -0 },
    { ...selected(), projectPath: '/INERT' }, { ...selected(CONNECT_KIND), reviewId: null }]) assert.equal(parseEnrollmentActionSelection(s), null);
  let gets = 0; const getter = selected(); Object.defineProperty(getter, 'kind', { enumerable: true, get() { gets++; return REVIEW_KIND; } });
  assert.equal(parseEnrollmentActionSelection(getter), null); assert.equal(gets, 0);
  const refused = row(selected(), { revision: 5, state: 'refused', settlement: 'settled', operationId: REVIEW,
    reason: 'native-refused', result: result(REVIEW_KIND, native('refused', 3)) });
  assert.ok(parseGithubActionStatus(refused));
  const old = { ...refused, review: { kind: 'repository-create', sessionId: 'connection-a', consentId: REVIEW, expectedRevision: 1, preparedSha256: hex('c', 64) }, operationId: 'repository-create-1', effect: 'not-sent' };
  assert.equal(parseGithubActionStatus(old), null);
});

test('Review Allow is inert; explicit same queued permission Check invokes the original MAIN Review once', async () => {
  const h = fixture(); assert.equal(h.enrollment.agentSelection(REVIEW_KIND), null); await h.nativeCheck(); await h.allow();
  assert.equal(h.count('agent-review'), 0); assert.equal(h.count('native-review'), 0); assert.equal(h.count('agent-confirm'), 0);
  assert.match(githubActionCommands(h.permission.getSnapshot().access, null)[0], /^mrk github-submit /);
  assert.equal(await h.enrollment.review(), false); assert.equal(await h.enrollment.confirm(), false);
  await h.queued(); assert.equal(h.count('agent-review'), 1); assert.deepEqual(h.last('agent-review').args, [h.origin, PROJECT]);
  await h.queued(); assert.equal(h.count('agent-review'), 1); assert.equal(h.count('agent-confirm'), 0);
  assert.ok(h.enrollment.ownerReason());
});

test('service Final before original Review caller cannot release or create the separate Connect intent', async () => {
  const h = fixture(); await h.nativeCheck(); await h.allow(); await h.queued(); await h.observe(h.final());
  assert.equal(h.delegates.at(-1).released(), false); assert.ok(h.enrollment.ownerReason()); assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null);
  let returned = false; const join = h.enrollment.whenSettled().then(() => { returned = true; }); await flush(); assert.equal(returned, false);
  await h.returnNative(native('reviewed', 3)); await join;
  assert.equal(h.delegates.at(-1).released(), true); assert.equal(h.enrollment.getSnapshot().unknown, false);
  assert.ok(h.permission.ownerReason(), 'unused old permission withdrawal remains required');
  assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null); assert.equal(h.count('agent-confirm'), 0);
});

test('native original reply alone waits for the same service history; exact request Check never adopts a later lease', async () => {
  const h = fixture(); await h.nativeCheck(); await h.allow(); await h.queued(); await h.returnNative(native('reviewed', 3));
  assert.equal(h.delegates.at(-1).released(), false); assert.ok(h.enrollment.ownerReason()); assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null);
  const accessCount = h.count('permission-access'); await h.observe(h.final());
  assert.equal(h.count('permission-access'), accessCount); assert.deepEqual(h.last('permission-request').args, [h.origin]);
  assert.equal(h.delegates.at(-1).released(), true);
});

test('actual Review then old Revoke/Check then NEW Connect permission preserves private review and invokes Confirm once', async () => {
  const h = fixture(); await h.review(); const old = h.delegates.at(-1), oldGrant = h.grant.id;
  assert.equal(h.permission.choose(CONNECT_KIND), false); assert.equal(h.count('native-cancel'), 0);
  await h.withdraw(); assert.equal(h.enrollment.getSnapshot().status.phase, 'reviewed'); assert.equal(h.enrollment.getSnapshot().stale, false);
  assert.ok(h.enrollment.agentSelection(CONNECT_KIND)); assert.equal(h.count('native-cancel'), 0);
  await h.allow(CONNECT_KIND); assert.notEqual(h.grant.id, oldGrant); assert.equal(h.selection.reviewId, REVIEW);
  old.unusedReturned(); old.notSubmitted(); old.allowReturned(); old.uncertain(); assert.equal(h.enrollment.getSnapshot().unknown, false);
  assert.equal(h.count('agent-confirm'), 0); await h.queued();
  assert.deepEqual(h.last('agent-confirm').args, [h.origin, PROJECT, REVIEW]); assert.equal(h.count('agent-confirm'), 1);
  await h.returnNative(native('connected', 5, CONNECT)); await h.observe(h.final(native('connected', 5, CONNECT)));
  assert.equal(h.delegates.at(-1).released(), true); assert.equal(h.enrollment.getSnapshot().status.phase, 'connected');
  assert.equal(h.permission.getSnapshot().status.effect, 'local-mapping-observed'); assert.equal(h.count('native-review'), 0); assert.equal(h.count('native-confirm'), 0);
});

test('status-only Reviewed and a copied valid Connect selection cannot recreate original reviewEpoch', async () => {
  const h = fixture(); await h.nativeCheck(native('reviewed', 3));
  assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null); assert.equal(h.enrollment.agentDelegate(selected(CONNECT_KIND, 3)), null);
  assert.equal(h.permission.choose(CONNECT_KIND), true); await h.permissionCheck();
  assert.equal(h.permission.acknowledge(true), false); assert.equal(await h.permission.allow(), false); assert.equal(h.count('permission-allow'), 0);
});

test('lost native caller or service history stays Unknown through later known status and never makes Connect available', async () => {
  for (const nativeLost of [true, false]) {
    const h = fixture(); await h.nativeCheck(); await h.allow(); await h.queued();
    if (nativeLost) { h.last('agent-review').reject(new Error('INERT no reply')); await h.enrollment.whenSettled(); await h.observe(h.final()); }
    else { await h.returnNative(native('reviewed', 3)); await h.observe(h.row({ revision: 5, state: 'unknown', settlement: 'unknown', operationId: REVIEW, reason: 'history-unavailable' })); }
    assert.ok(h.enrollment.ownerReason()); assert.equal(h.delegates.at(-1).released(), false);
    await h.nativeCheck(native('reviewed', 6)); assert.equal(h.enrollment.getSnapshot().unknown, true); assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null);
  }
});

test('lost old Revoke is absorbing and cannot authorize a new Connect lease', async () => {
  const h = fixture(); await h.review(); const p = h.permission.revoke(); h.last('permission-revoke').reject(new Error('INERT lost reply')); await p;
  assert.equal(h.permission.getSnapshot().unknown, true); assert.equal(h.permission.choose(CONNECT_KIND), false);
  assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null); assert.equal(h.count('permission-allow'), 1); assert.equal(h.count('agent-confirm'), 0);
});

test('lost Allow never starts a queued action or turns a returned status into replacement permission', async () => {
  const h = fixture(); await h.nativeCheck(); assert.equal(h.permission.choose(REVIEW_KIND), true); await h.permissionCheck();
  assert.equal(h.permission.acknowledge(true), true); const p = h.permission.allow(); h.last('permission-allow').reject(new Error('INERT lost Allow')); await p;
  assert.equal(h.permission.getSnapshot().unknown, true); assert.equal(h.enrollment.getSnapshot().unknown, true);
  assert.equal(h.delegates.at(-1).released(), false); assert.equal(await h.permission.allow(), false); assert.equal(h.count('agent-review'), 0);
});

test('native refusal compares actual action reply and exact result rather than assuming all final rows are success', async () => {
  const h = fixture(); await h.nativeCheck(); await h.allow(); await h.queued(); const value = native('refused', 3);
  await h.returnNative(value); await h.observe(h.final(value, { state: 'refused', reason: 'native-refused' }));
  assert.equal(h.delegates.at(-1).released(), true); assert.equal(h.enrollment.getSnapshot().unknown, false); assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null);
  await h.withdraw(); assert.ok(h.enrollment.agentSelection(REVIEW_KIND));
});

test('valid but mismatched result or first granted reference never replaces the retained original', async () => {
  for (const changedReference of [false, true]) {
    const h = fixture(); await h.nativeCheck(); await h.allow(); await h.queued(); await h.returnNative(native('reviewed', 3));
    const s = h.final(); if (changedReference) s.review.requestSha256 = hex('f', 64); else s.result.review.version.build++;
    assert.ok(parseGithubActionStatus(s));
    if (changedReference) { const p = h.permission.check(); h.last('permission-request').resolve(s); await p; }
    else await h.observe(s);
    assert.equal(h.delegates.at(-1).released(), false); assert.equal(h.enrollment.getSnapshot().unknown, true); assert.equal(h.enrollment.agentSelection(CONNECT_KIND), null);
  }
});

test('pre-admission final waits any submitted MAIN caller; Refused is not guessed native completion', async () => {
  const h = fixture(); await h.nativeCheck(); await h.allow(); await h.queued();
  const s = h.row({ revision: 3, state: 'refused', settlement: 'settled', reason: 'native-refused', neverAdmitted: true }); await h.observe(s);
  assert.equal(h.delegates.at(-1).released(), false);
  h.last('agent-review').reject({ code: 'version_enrollment_not_started_busy' }); await h.enrollment.whenSettled(); await flush();
  assert.equal(h.delegates.at(-1).released(), true); assert.equal(h.enrollment.getSnapshot().unknown, false); assert.equal(h.enrollment.getSnapshot().status.phase, 'idle');
});

test('pre-Submit Revoke does not invent an action; known unused Check may return that exact retained delegation', async () => {
  const h = fixture(); await h.nativeCheck(); await h.allow();
  const revoke = h.permission.revoke(); h.permissionRevision++;
  h.last('permission-revoke').resolve(access(h.grant, null, String(h.permissionRevision), { enabled: false, remainingMs: 0 })); await revoke;
  const check = h.permission.check(); h.last('permission-access').resolve(access(h.grant, null, String(h.permissionRevision), { enabled: false, remainingMs: 0 })); await check;
  assert.equal(h.delegates.at(-1).released(), true); assert.equal(h.count('agent-review'), 0); assert.equal(h.count('native-cancel'), 0);
});

test('reentrant source/connection/peer changes at queued begin veto the native call without replay or fake release', async () => {
  for (const mode of ['project-aba', 'connection-revision', 'peer']) {
    const h = fixture(); await h.nativeCheck(); await h.allow(); let changed = false;
    const off = h.enrollment.subscribe(() => {
      if (!changed && h.enrollment.getSnapshot().pending === 'review') {
        changed = true;
        if (mode === 'project-aba') { h.change({ projectId: hex('9') }); h.change({ projectId: PROJECT }); }
        else if (mode === 'connection-revision') h.context.connection = { ...h.context.connection, revision: 9 };
        else h.peer = 'Another original owner is now active';
      }
    });
    await h.queued(); await flush(); off(); assert.equal(h.count('agent-review'), 0); assert.equal(h.delegates.at(-1).released(), false);
    h.peer = null; h.context.connection = { sessionId: 'connection-a', revision: 8 }; h.sync(); await h.queued(); assert.equal(h.count('agent-review'), 0);
    await h.observe(h.row({ revision: 3, state: 'cancelled', settlement: 'settled', reason: 'permission-revoked', neverAdmitted: true }));
    assert.equal(h.delegates.at(-1).released(), true);
  }
});

test('missing native connection, old API and unrelated owner cannot supply an enrollment permission', async () => {
  const h = fixture(); await h.nativeCheck(); const s = h.enrollment.agentSelection(REVIEW_KIND); assert.ok(s);
  h.peer = 'A foreign original is still returning'; h.sync(); assert.equal(h.enrollment.agentDelegate(s), null); assert.equal(h.count('permission-allow'), 0);
  h.peer = null; h.context.agentPort = null; h.sync(); assert.equal(h.enrollment.agentSelection(REVIEW_KIND), null);
  h.context.connection = null; assert.equal(h.enrollment.agentSelected(s), false);
  assert.equal(h.count('agent-review'), 0);
});
