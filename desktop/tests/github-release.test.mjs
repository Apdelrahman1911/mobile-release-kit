// Inert DATA and fake IPC promises only. No token, network, process, native
// journal/owner, installed runtime or service qualification is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { GitHubReleaseController, githubReleaseOwnerReason } from '../src/githubReleaseController.ts';
import { githubReleaseError, githubReleaseRequestFits, parseGitHubReleaseStatus, githubReleaseSelection } from '../src/githubReleaseProtocol.ts';

const TIME = '2026-09-26T18:00:00Z', EXPIRY = '2026-09-26T18:02:00Z', MARKER = 'd'.repeat(32);
const clone = (v) => structuredClone(v);
function connection() {
  return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'owner/app' },
    status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'owner/app', state: 'connected' },
      account: { state: 'observed', value: { id: '11' } }, repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } },
    retained: null, help: null, helpState: 'current', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null };
}
function selection(stage = 'candidate', recovery = false) {
  const original = stage !== 'candidate' || recovery;
  return { stage, candidateRunId: stage !== 'candidate' && !recovery ? '101' : null,
    externalRunId: stage === 'production-submit' && !recovery ? '102' : null, recoveryRunId: recovery ? '103' : null,
    originalSourceSha: original ? 'f'.repeat(40) : null, originalVersion: original ? { name: '1.2.3', build: 42 } : null };
}
function prepared(stage = 'candidate', recovery = false) {
  const t = { projectBinding: 'b'.repeat(64), repository: 'owner/app', accountId: '11', repositoryId: '22', branch: 'release/ui',
    toolingRepository: 'Apdelrahman1911/mobile-release-kit', toolingSha: 'c'.repeat(40), platform: 'android', marker: MARKER,
    selection: selection(stage, recovery) };
  const version = t.selection.originalVersion ?? { name: '2.0.0', build: 99 };
  return { target: t, sourceSha: 'a'.repeat(40), sourceTree: 'f'.repeat(40), workflowId: '33', workflowPath: `.github/workflows/mobile-${stage}.yml`, callerSha256: 'e'.repeat(64),
    observedAt: TIME, expectedRef: 'refs/heads/release/ui', displayTitle: `MRK Desktop ${stage} [${MARKER}]`,
    configSha256: '0'.repeat(64), versionSource: 'release/version.properties', versionSha256: '1'.repeat(64), currentVersion: { name: '2.0.0', build: 99 },
    destination: { applicationId: 'org.fixture.app', destination: 'internal', assurance: 'current-dispatch-config-not-authenticated-original-destination' },
    checklist: [], environment: stage === 'production-submit' ? 'mobile-production' : `mobile-${stage}`,
    confirmation: `${stage}:android:${version.name}:${version.build}`, originalAssurance: 'declared-original-references-not-authenticated-release-evidence' };
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
    githubReleaseStatus: async () => { calls.push({ kind: 'status' }); return clone(current); },
    subscribeGitHubRelease: async (fn) => { listener = fn; calls.push({ kind: 'subscribe' }); return () => { listener = null; detached += 1; }; },
    prepareGitHubRelease: (args) => request('prepare', args), dispatchGitHubRelease: (args) => request('dispatch', args),
    trackGitHubRelease: (args) => request('track', args), reconcileGitHubRelease: (args) => request('reconcile', args),
    loadGitHubReleasePending: (args) => request('pending', args), cancelGitHubRelease: (args) => request('cancel', args),
  };
  const controller = new GitHubReleaseController(() => view);
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
  const h = await attached(); h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.setStage('candidate'); h.controller.prepare();
  h.respond('prepare', review()); await flush(); return h;
}


test('closed original declarations cannot be confused with current-source or preflight consent', () => {
  for (const stage of ['candidate', 'external-testing', 'production-submit']) for (const recovery of [false, true]) {
    assert.equal(githubReleaseSelection(selection(stage, recovery)), true);
    assert.ok(parseGitHubReleaseStatus({ ...review(), prepared: prepared(stage, recovery) }));
  }
  const currentInstead = prepared('production-submit'); currentInstead.confirmation = 'production-submit:android:2.0.0:99';
  assert.equal(parseGitHubReleaseStatus({ ...review(), prepared: currentInstead }), null);
  for (const changes of [{ sourceTree: '' }, { originalAssurance: 'authenticated' }, { environment: 'invented' }, { workflowPath: '.github/workflows/mobile-preflight.yml' },
    { destination: { ...prepared().destination, assurance: 'verified-store-state' } }])
    assert.equal(parseGitHubReleaseStatus({ ...review(), prepared: { ...prepared(), ...changes } }), null);
  for (const changes of [{ candidateRunId: null }, { externalRunId: null }, { originalVersion: null }, { originalSourceSha: null }, { recoveryConfirmation: 'invented' }])
    assert.equal(githubReleaseSelection({ ...selection('production-submit'), ...changes }), false);
  const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, branch: 'release/ui', platform: 'android', selection: selection() };
  assert.equal(githubReleaseRequestFits('github_release_prepare', args), true);
  for (const name of ['token', 'home', 'url', 'runId', 'force', 'family'])
    assert.equal(githubReleaseRequestFits('github_release_prepare', { ...args, [name]: 'INERT' }), false);
  assert.equal(githubReleaseRequestFits('github_release_prepare', { ...args, platform: 'both' }), false);
  assert.equal(githubReleaseRequestFits('github_release_dispatch', { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirm: true }), false);
});

test('release review needs resolve/store jobs, not a second build after valid reuse', () => {
  const value = observed(); value.run.status = 'completed'; value.run.conclusion = 'success';
  value.run.jobs = ['input-guard', 'android-resolve', 'android-store'].map((kind, i) => ({ id: String(50 + i), kind, status: 'completed', conclusion: 'success' }));
  assert.ok(parseGitHubReleaseStatus(value));
  value.run.jobs.push({ id: '60', kind: 'android-build', status: 'completed', conclusion: 'skipped' });
  assert.ok(parseGitHubReleaseStatus(value));
  const missingStore = clone(value); missingStore.run.jobs[2].conclusion = 'skipped'; assert.equal(parseGitHubReleaseStatus(missingStore), null);
  for (const change of [(v) => { v.run.attempt = 2; }, (v) => { v.run.assurance = 'release-ready'; },
    (v) => { v.run.url += '/attempts/2'; }, (v) => { v.run.jobs.push(clone(v.run.jobs[0])); }]) {
    const changed = clone(value); change(changed); assert.equal(parseGitHubReleaseStatus(changed), null);
  }
  const promoted = clone(value); promoted.pending[0].prepared = prepared('external-testing');
  assert.equal(parseGitHubReleaseStatus(promoted), null);
  promoted.run.jobs = ['input-guard', 'android'].map((kind, i) => ({ id: String(50 + i), kind, status: 'completed', conclusion: 'success' }));
  assert.ok(parseGitHubReleaseStatus(promoted));
});

test('full64 retained records and maximum review/run remain serializable with escaped UTF8', () => {
  const bytes = (v) => new TextEncoder().encode(JSON.stringify(v)).byteLength;
  const p = prepared('candidate', true), maxId = '18446744073709551615';
  p.target.repository = 'a'.repeat(39) + '/' + 'b'.repeat(100);
  p.target.branch = 'b'.repeat(200); p.expectedRef = 'refs/heads/' + p.target.branch;
  p.target.accountId = maxId; p.target.repositoryId = maxId; p.workflowId = maxId;
  p.target.selection.recoveryRunId = maxId;
  p.target.selection.originalVersion = { name: '1.0+' + 'v'.repeat(60), build: 2_100_000_000 };
  p.currentVersion = { name: '1.0+' + 'v'.repeat(60), build: 2_100_000_000 };
  p.confirmation = `candidate:android:${p.currentVersion.name}:2100000000`;
  p.versionSource = 'a'.repeat(248) + '/' + 'é'.repeat(124) + '/' + 'v'.repeat(14);
  assert.equal(new TextEncoder().encode(p.versionSource).byteLength, 512);
  p.destination.applicationId = '"\\é'.repeat(40); p.destination.destination = '"\\é'.repeat(40);
  for (let i = 0; i < 16; i += 1) {
    p.checklist.push({ name: `MOBILE_RELEASE_FIXTURE_${i}`, kind: 'secret', reason: 'r'.repeat(192) });
    if (bytes(p) > 3900) { p.checklist.pop(); break; }
  }
  for (const [field, maximum] of [['destination', 256], ['applicationId', 255]]) {
    while (bytes(p) < 3900 && new TextEncoder().encode(p.destination[field]).byteLength < maximum) p.destination[field] += 'x';
  }
  while (bytes(p) < 3900) { assert.ok(p.checklist.at(-1).name.length < 'MOBILE_RELEASE_'.length + 96); p.checklist.at(-1).name += 'X'; }
  assert.equal(bytes(p), 3900);
  const full = { ...review(0xffff_fffe), sessionId: 's'.repeat(64), prepared: p };
  full.operation.id = 'o'.repeat(64);
  full.pending = Array.from({ length: 64 }, (_, i) => {
    const row = clone(p); row.target.marker = i.toString(16).padStart(32, '0'); row.displayTitle = `MRK Desktop candidate [${row.target.marker}]`;
    return { prepared: row, runId: (BigInt(maxId) - BigInt(i)).toString() };
  });
  assert.ok(bytes(full) <= 256 * 1024); assert.ok(parseGitHubReleaseStatus(full));
  const tracked = clone(full); tracked.prepared = null; tracked.consentExpiresAt = null; tracked.operation.kind = 'reconcile';
  const kinds = ['input-guard', 'android-resolve', 'android-online', 'android-build', 'android-store', 'ios-resolve', 'ios-online', 'ios-build', 'ios-store'];
  tracked.run = { id: maxId, attempt: 1, status: 'completed', conclusion: 'startup_failure', observedAt: '9999-12-31T23:59:59Z',
    jobs: kinds.map((kind, i) => ({ id: (BigInt(maxId) - BigInt(i)).toString(), kind, status: 'completed', conclusion: 'startup_failure' })),
    url: `https://github.com/${p.target.repository}/actions/runs/${maxId}`, assurance: 'github-workflow-observation-not-release-evidence' };
  assert.ok(bytes(tracked) <= 256 * 1024); assert.ok(parseGitHubReleaseStatus(tracked));
  const both = { ...full, run: tracked.run }; assert.ok(bytes(both) <= 256 * 1024);
  full.pending.push(clone(full.pending[0])); assert.equal(parseGitHubReleaseStatus(full), null);
  full.pending.pop(); full.prepared.checklist.at(-1).reason = 'r'.repeat(192) + 'x'; assert.equal(parseGitHubReleaseStatus(full), null);
});

test('attachment is local-only; explicit stage/platform and exact typed confirmation are necessary', async () => {
  const h = await attached(); assert.deepEqual(h.calls.map((v) => v.kind), ['subscribe', 'status']);
  h.controller.setBranch('release/ui'); h.controller.setPlatform('android'); h.controller.prepare(); assert.equal(h.count('prepare'), 0);
  h.controller.setStage('candidate'); h.controller.prepare(); h.controller.prepare(); assert.equal(h.count('prepare'), 1);
  assert.deepEqual(h.last('prepare').args.selection, selection());
  h.respond('prepare', review()); await flush(); assert.ok(h.controller.currentPrepared());
  h.controller.setConfirmed(true); h.controller.dispatch(); assert.equal(h.count('dispatch'), 0);
  h.controller.setConfirmation('wrong'); h.controller.dispatch(); assert.equal(h.count('dispatch'), 0);
  h.controller.setConfirmation(prepared().confirmation); h.controller.dispatch(); h.controller.dispatch();
  assert.equal(h.count('dispatch'), 1); assert.equal(h.state.confirmation, ''); assert.equal(h.state.confirmed, false);
  assert.deepEqual(h.last('dispatch').args, { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirm: true, confirmation: prepared().confirmation });
  h.respond('dispatch', dispatchResult()); await flush(); assert.equal(h.state.pending, false);
  assert.equal(h.state.status.run, null); h.controller.dispose();
});

test('original declarations and selection changes revoke consent even on an away-and-back edit', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.setConfirmation(prepared().confirmation);
  h.controller.setStage('external-testing'); h.controller.setStage('candidate');
  assert.equal(h.controller.currentPrepared(), null); h.controller.dispatch(); assert.equal(h.count('dispatch'), 0);
  h.controller.dispose();
  const second = await ready(); second.controller.setConfirmed(true); second.controller.setConfirmation(prepared().confirmation);
  second.context({ ...connection(), context: null }); second.context(connection());
  assert.equal(second.controller.currentPrepared(), null); second.controller.dispatch(); assert.equal(second.count('dispatch'), 0); second.controller.dispose();
  const promotion = await attached(); promotion.controller.setStage('production-submit'); promotion.controller.setPlatform('android'); promotion.controller.setBranch('release/ui');
  promotion.controller.setInput('candidateRunId', '101'); promotion.controller.setInput('externalRunId', '102');
  promotion.controller.setInput('originalVersionName', '1.2.3'); promotion.controller.setInput('originalVersionBuild', '42'); promotion.controller.setInput('originalSourceSha', 'f'.repeat(40));
  assert.deepEqual(promotion.controller.selection(), selection('production-submit'));
  promotion.controller.setRecovery(true); assert.equal(promotion.controller.selection(), null);
  promotion.controller.setInput('recoveryRunId', '103'); assert.equal(promotion.controller.selection().recoveryRunId, '103'); promotion.controller.dispose();
});

test('unknown dispatch retains its original observer, blocks re-send, and accepts only exact settlement', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.setConfirmation(prepared().confirmation); h.controller.dispatch();
  h.last('dispatch').reject({ code: 'untrusted', admission: 'not-admitted' }); await flush();
  assert.equal(h.state.uncertain, true); h.controller.prepare(); h.controller.dispatch(); assert.equal(h.count('dispatch'), 1);
  assert.match(githubReleaseOwnerReason(h.state), /original/i);
  await h.controller.connect(null); assert.equal(h.detached, 0);
  h.emit(dispatchResult()); await flush(); assert.equal(h.detached, 1); assert.equal(h.state.pending, false);
  assert.equal(h.state.status.pending[0].runId, '44'); h.controller.dispose();
});

test('event-before-reply and reentrant click still submit exactly once', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.setConfirmation(prepared().confirmation);
  let reentered = false;
  const stop = h.controller.subscribe(() => { if (h.state.pending && !reentered) { reentered = true; h.controller.dispatch(); } });
  h.controller.dispatch(); stop(); assert.equal(h.count('dispatch'), 1);
  h.emit(dispatchResult()); await flush(); assert.equal(h.state.pending, false);
  h.respond('dispatch', operation('dispatch', 'running', 4)); await flush();
  assert.equal(h.state.status.operation.phase, 'settled'); assert.equal(h.state.uncertain, false); h.controller.dispose();
});

test('bridge uses a distinct closed command family and never falls back in preview', async () => {
  const calls = [], events = [];
  const api = createNativeApi('native', async (name, args) => { calls.push({ name, args }); return idle(); }, async (name) => { events.push(name); return () => {}; });
  await api.githubReleaseStatus(); await api.loadGitHubReleasePending({ sessionId: 'session-a', expectedRevision: 1 });
  await api.subscribeGitHubRelease(() => {});
  assert.deepEqual(calls.map((c) => c.name), ['github_release_status', 'github_release_pending']);
  assert.deepEqual(events, ['github-release-status']);
  await assert.rejects(api.dispatchGitHubRelease({ sessionId: 'session-a', expectedRevision: 1, consentId: MARKER, confirm: true, confirmation: prepared().confirmation, token: 'INERT' }), (e) => e.admission === 'not-admitted');
  assert.equal(calls.length, 2);
  assert.equal(githubReleaseError({ code: 'github_preflight_refused_busy' }).admission, 'unknown');
  const unavailable = createNativeApi('unavailable', async () => { throw new Error('must not invoke'); });
  await assert.rejects(unavailable.githubReleaseStatus(), (e) => e.admission === 'not-admitted');
});
