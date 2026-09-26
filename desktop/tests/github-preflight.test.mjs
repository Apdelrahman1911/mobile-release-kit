// Inert DATA and fake IPC promises only. No token, network, process, native
// journal/owner, installed runtime or service qualification is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { GitHubPreflightController, githubPreflightOwnerReason } from '../src/githubPreflightController.ts';
import { githubPreflightError, githubPreflightRequestFits, parseGitHubPreflightStatus } from '../src/githubPreflightProtocol.ts';

const TIME = '2026-09-26T18:00:00Z', EXPIRY = '2026-09-26T18:02:00Z', MARKER = 'd'.repeat(32);
const clone = (v) => structuredClone(v);
function connection() {
  return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'owner/app' },
    status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'owner/app', state: 'connected' },
      account: { state: 'observed', value: { id: '11' } }, repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } },
    retained: null, help: null, helpState: 'current', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null };
}
function prepared() {
  const t = { projectBinding: 'b'.repeat(64), repository: 'owner/app', accountId: '11', repositoryId: '22', branch: 'release/ui',
    toolingRepository: 'Apdelrahman1911/mobile-release-kit', toolingSha: 'c'.repeat(40), platform: 'android', marker: MARKER };
  const sourceSha = 'a'.repeat(40);
  return { target: t, sourceSha, workflowId: '33', workflowPath: '.github/workflows/mobile-preflight.yml', callerSha256: 'e'.repeat(64),
    observedAt: TIME, expectedRef: 'refs/heads/release/ui', displayTitle: `MRK Desktop preflight [${MARKER}]`,
    confirmation: `Run credential-free ${t.platform} preflight for ${t.repository} at ${sourceSha}? This may build project code, download dependencies, use GitHub-hosted minutes and upload diagnostic reports. The reviewed canonical workflow does not sign, upload to a Store or publish a release. GitHub dispatch uses this mutable branch, not an atomic commit lock. Authorized writers can replace its workflow after review; use a trusted protected branch.` };
}
function idle(revision = 1) {
  return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none',
    operation: null, prepared: null, consentExpiresAt: null, pending: [], run: null };
}
function operation(kind, phase, revision, reason = 'none', effect = kind === 'dispatch' ? 'not-sent' : 'none') {
  return { ...idle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
    operation: { id: kind + '-a', kind, phase, reason, effect } };
}
function review(revision = 3) { return { ...operation('prepare', 'settled', revision), prepared: prepared(), consentExpiresAt: EXPIRY }; }
function dispatchResult(revision = 5, effect = 'accepted', reason = 'none') {
  return { ...operation('dispatch', 'settled', revision, reason, effect), pending: [{ prepared: prepared(), runId: effect === 'accepted' ? '44' : null }] };
}
function observed(revision = 7) {
  return { ...operation('track', 'settled', revision), pending: [{ prepared: prepared(), runId: '44' }],
    run: { id: '44', attempt: 1, status: 'queued', conclusion: null, observedAt: TIME, jobs: [],
      url: 'https://github.com/owner/app/actions/runs/44', assurance: 'github-workflow-observation-not-release-evidence' } };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 12; i += 1) await Promise.resolve(); }
function harness() {
  const calls = []; let current = idle(), view = connection(), listener = null, detached = 0;
  const request = (kind, args) => { const d = deferred(); calls.push({ kind, args: clone(args), ...d }); return d.promise; };
  const api = { mode: 'native',
    githubPreflightStatus: async () => { calls.push({ kind: 'status' }); return clone(current); },
    subscribeGitHubPreflight: async (fn) => { listener = fn; calls.push({ kind: 'subscribe' }); return () => { listener = null; detached += 1; }; },
    prepareGitHubPreflight: (args) => request('prepare', args), dispatchGitHubPreflight: (args) => request('dispatch', args),
    trackGitHubPreflight: (args) => request('track', args), reconcileGitHubPreflight: (args) => request('reconcile', args),
    loadGitHubPreflightPending: (args) => request('pending', args), cancelGitHubPreflight: (args) => request('cancel', args),
  };
  const controller = new GitHubPreflightController(() => view);
  return { api, controller, calls,
    get state() { return controller.getSnapshot(); }, get detached() { return detached; },
    count: (kind) => calls.filter((v) => v.kind === kind).length, last: (kind) => calls.filter((v) => v.kind === kind).at(-1),
    emit: (s) => { current = clone(s); listener?.(clone(s)); }, retain: (s) => { current = clone(s); },
    respond: (kind, s) => { current = clone(s); calls.filter((v) => v.kind === kind).at(-1).resolve(clone(s)); },
    context: (next) => { view = next; controller.syncContext(); },
  };
}
async function attached() { const h = harness(); await h.controller.connect(h.api); return h; }
async function ready() {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  h.respond('prepare', review()); await flush(); return h;
}

test('closed status separates accepted identity from observed workflow, and success needs requested jobs', () => {
  for (const value of [idle(), review(), dispatchResult(), observed()]) assert.ok(parseGitHubPreflightStatus(value));
  const run = observed(); run.run.status = 'completed'; run.run.conclusion = 'success';
  assert.equal(parseGitHubPreflightStatus(run), null);
  run.run.jobs = [{ id: '55', kind: 'input-guard', status: 'completed', conclusion: 'success' },
    { id: '56', kind: 'android', status: 'completed', conclusion: 'skipped' }];
  assert.equal(parseGitHubPreflightStatus(run), null);
  run.run.jobs[1].conclusion = 'success'; assert.ok(parseGitHubPreflightStatus(run));
  for (const change of [(s) => { s.run.url += '/attempts/2'; }, (s) => { s.run.id = 44; },
    (s) => { s.run.jobs[1].id = '55'; }, (s) => { s.pending[0].prepared.displayTitle += ' other'; },
    (s) => { s.pending.push(clone(s.pending[0])); }, (s) => { s.run.assurance = 'release-approved'; }]) {
    const value = clone(run); change(value); assert.equal(parseGitHubPreflightStatus(value), null);
  }
  let got = 0; const getter = idle(); Object.defineProperty(getter, 'secret', { enumerable: true, get() { got += 1; return 'INERT'; } });
  assert.equal(parseGitHubPreflightStatus(getter), null); assert.equal(got, 0);
});

test('closed public inputs cannot select authority, secrets, ref endpoints or arbitrary run IDs', () => {
  const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, branch: 'release/ui', platform: 'android' };
  assert.equal(githubPreflightRequestFits('github_preflight_prepare', args), true);
  for (const name of ['token', 'toolingSha', 'home', 'runId', 'url', 'retry', 'force'])
    assert.equal(githubPreflightRequestFits('github_preflight_prepare', { ...args, [name]: 'INERT' }), false);
  for (const branch of ['refs/heads/main', '-main', 'x..y', 'x/.a', 'main.lock', 'x?y', 'x\ny'])
    assert.equal(githubPreflightRequestFits('github_preflight_prepare', { ...args, branch }), false);
  assert.equal(githubPreflightRequestFits('github_preflight_dispatch', { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirm: false }), false);
  assert.equal(githubPreflightError({ code: 'github_preflight_refused_busy' }).admission, 'not-admitted');
  assert.equal(githubPreflightError({ code: 'bridge_failed', admission: 'not-admitted' }).admission, 'unknown');
});

test('bridge routes only fixed action commands and rejects extra authority before invoke', async () => {
  const calls = [], events = [];
  const api = createNativeApi('native', async (name, args) => { calls.push({ name, args }); return idle(); }, async (name) => { events.push(name); return () => {}; });
  await api.githubPreflightStatus(); await api.loadGitHubPreflightPending({ sessionId: 'session-a', expectedRevision: 1 });
  await api.subscribeGitHubPreflight(() => {});
  assert.deepEqual(calls.map((c) => c.name), ['github_preflight_status', 'github_preflight_pending']);
  assert.deepEqual(events, ['github-preflight-status']);
  await assert.rejects(api.dispatchGitHubPreflight({ sessionId: 'session-a', expectedRevision: 1, consentId: MARKER, confirm: true, token: 'INERT' }),
    (e) => e.admission === 'not-admitted');
  assert.equal(calls.length, 2);
});

test('attachment only subscribes and reads local Status; choices and confirmation are explicit', async () => {
  const h = await attached(); assert.deepEqual(h.calls.map((v) => v.kind), ['subscribe', 'status']);
  assert.equal(h.state.branch, ''); assert.equal(h.state.platform, null); assert.equal(h.state.confirmed, false);
  h.controller.prepare(); h.controller.dispatch(); assert.equal(h.count('prepare') + h.count('dispatch'), 0);
  h.controller.setBranch('release/ui'); h.controller.setPlatform('android');
  let reentered = false;
  const stop = h.controller.subscribe(() => { if (h.state.pending && !reentered) { reentered = true; h.controller.prepare(); } });
  h.controller.prepare(); h.controller.prepare(); assert.equal(h.count('prepare'), 1); stop();
  assert.deepEqual(h.last('prepare').args, { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, branch: 'release/ui', platform: 'android' });
  h.respond('prepare', review()); await flush(); assert.ok(h.controller.currentPrepared()); assert.equal(h.state.confirmed, false);
  h.controller.dispatch(); assert.equal(h.count('dispatch'), 0);
  h.controller.setConfirmed(true); h.controller.dispatch(); h.controller.dispatch();
  assert.equal(h.count('dispatch'), 1); assert.equal(h.state.confirmed, false);
  assert.deepEqual(h.last('dispatch').args, { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirm: true });
  h.respond('dispatch', dispatchResult()); await flush(); assert.equal(h.state.pending, false); assert.equal(h.state.status.run, null);
});

test('selection change and away/back context cannot restore old consent', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.setBranch('main'); h.controller.setBranch('release/ui');
  assert.equal(h.controller.currentPrepared(), null); assert.equal(h.state.confirmed, false); h.controller.dispatch(); assert.equal(h.count('dispatch'), 0);
  const next = await ready(); next.controller.setConfirmed(true); next.context({ ...connection(), context: null }); next.context(connection());
  assert.equal(next.controller.currentPrepared(), null); assert.equal(next.state.branch, ''); assert.equal(next.state.platform, null);
});

test('generic dispatch failure and idle reads never authorize a retry; exact original settlement releases the latch', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.dispatch();
  h.last('dispatch').reject({ code: 'transport_lost' }); await flush();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true);
  h.retain(review()); await h.controller.checkStatus(); h.controller.setConfirmed(true); h.controller.dispatch();
  assert.equal(h.count('dispatch'), 1); assert.equal(h.state.uncertain, true);
  h.emit(dispatchResult(5, 'potentially-applied', 'network-unavailable'));
  assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false);
  assert.equal(h.state.status.pending[0].runId, null); assert.equal(h.controller.currentPrepared(), null);
  h.controller.observe(h.state.status.pending[0]); assert.equal(h.count('reconcile'), 1); assert.equal(h.count('dispatch'), 1);
});

test('event-before-reply and coherent older admission never replace newer terminal DATA', async () => {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  h.emit(review()); assert.equal(h.state.pending, false); assert.ok(h.controller.currentPrepared());
  h.last('prepare').resolve(operation('prepare', 'running', 2)); await flush();
  assert.equal(h.state.status.revision, 3); assert.ok(h.controller.currentPrepared()); assert.equal(h.state.uncertain, false);
});

test('native refusal releases only an unacknowledged, not-yet-observed admission', async () => {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  h.last('prepare').reject({ code: 'github_preflight_refused_busy' }); await flush(); assert.equal(h.state.pending, false);
  h.controller.prepare(); h.emit(operation('prepare', 'running', 2)); h.last('prepare').reject({ code: 'github_preflight_refused_busy' }); await flush();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); h.controller.prepare(); assert.equal(h.count('prepare'), 2);
});

test('wrong target prepare cannot authorize consent and conflicting terminal facts fail closed', async () => {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  const wrong = review(); wrong.prepared.target.accountId = '12'; h.respond('prepare', wrong); await flush();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentPrepared(), null);
  const valid = await ready(); const changed = review(4); changed.operation.reason = 'forbidden'; changed.prepared = null; changed.consentExpiresAt = null;
  valid.emit(changed); assert.equal(valid.state.uncertain, true); assert.equal(valid.state.error, 'response-invalid');
  assert.equal(valid.controller.currentPrepared(), null);
});

test('context retirement retains original terminal correlation, without adopting old review in new context', async () => {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  h.context({ ...connection(), context: null, status: null });
  const done = operation('prepare', 'settled', 3, 'cancelled'); done.available = false; done.reason = 'not-connected';
  h.emit(done); assert.equal(h.state.pending, false); assert.equal(h.controller.currentPrepared(), null);
  h.last('prepare').reject(new Error('late lost reply')); await flush(); assert.equal(h.state.pending, false);
});

test('replacing API retains the original pending observer until its exact settlement', async () => {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  const replacement = harness(); await h.controller.connect(replacement.api); assert.equal(h.detached, 0); assert.equal(replacement.count('subscribe'), 0);
  h.emit(review()); await flush(); assert.equal(h.detached, 1); assert.equal(replacement.count('subscribe'), 1);
  assert.equal(h.controller.currentPrepared(), null); assert.equal(h.state.pending, false);
});

test('local cancellation names only the original operation; cleanup unknown never becomes a late success', async () => {
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare();
  h.controller.cancel(); assert.equal(h.count('cancel'), 0);
  h.emit(operation('prepare', 'running', 2)); h.controller.cancel(); assert.deepEqual(h.last('cancel').args, { operationId: 'prepare-a' });
  h.respond('cancel', operation('prepare', 'running', 3, 'cancelled')); await flush(); assert.equal(h.state.pending, true);
  h.emit(operation('prepare', 'cleanup-unknown', 4, 'cleanup-unknown'));
  assert.equal(h.state.uncertain, true); assert.ok(githubPreflightOwnerReason(h.state));
  h.emit(review(5)); assert.equal(h.state.status.operation.phase, 'cleanup-unknown'); assert.equal(h.controller.currentPrepared(), null);
});

test('pending load and known run tracking are explicit and cannot substitute another marker', async () => {
  const h = await attached(); h.controller.loadPending(); assert.equal(h.count('pending'), 1); assert.equal(h.count('track'), 0);
  const loaded = { ...operation('pending', 'settled', 2), pending: dispatchResult().pending };
  h.respond('pending', loaded); await flush();
  const other = clone(loaded.pending[0]); other.prepared.target.marker = 'f'.repeat(32);
  h.controller.observe(other); assert.equal(h.count('track'), 0);
  h.controller.observe(h.state.status.pending[0]); h.controller.observe(h.state.status.pending[0]); assert.equal(h.count('track'), 1);
  assert.deepEqual(h.last('track').args, { sessionId: 'session-a', expectedRevision: 2, marker: MARKER });
  h.respond('track', observed(4)); await flush(); assert.equal(h.state.status.run.attempt, 1);
});
