// Inert DATA and fake IPC promises only. No token, network, process, native
// journal/owner, installed runtime or service qualification is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { GitHubReleaseController, githubReleaseOwnerReason } from '../src/githubReleaseController.ts';
import { GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES, githubReleaseError, githubReleaseRequestFits, parseGitHubReleaseStatus, githubReleaseRecoveryConfirmation, githubReleaseSelection } from '../src/githubReleaseProtocol.ts';

const TIME = '2026-09-26T18:00:00Z', EXPIRY = '2026-09-26T18:02:00Z', MARKER = 'd'.repeat(32);
const APPLE_INTENT = '1a'.repeat(32);
const APPLE_ADOPTION = `recover-ios-candidate:${APPLE_INTENT}:Build_7.-`;
const APPLE_UPLOAD = `retry-ios-candidate-upload:${APPLE_INTENT}:${'2b'.repeat(32)}`;
const APPLE_CREATES = `retry-ios-operation-creates:${APPLE_INTENT}:${'3c'.repeat(32)}`;
const APPLE_MAX_ADOPTION = `recover-ios-candidate:${APPLE_INTENT}:${'B'.repeat(255)}`;
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
function applePrepared(stage = 'candidate', grant = APPLE_ADOPTION) {
  const value = prepared(stage, true); value.target.platform = 'ios';
  value.target.selection.recoveryConfirmation = grant;
  value.confirmation = `${stage}:ios:1.2.3:42`; return value;
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

function selectApple(controller, stage = 'candidate', grant = APPLE_ADOPTION) {
  controller.setBranch('release/ui'); controller.setPlatform('ios'); controller.setStage(stage); controller.setRecovery(true);
  controller.setInput('recoveryRunId', '103'); controller.setInput('originalSourceSha', 'f'.repeat(40));
  controller.setInput('originalVersionName', '1.2.3'); controller.setInput('originalVersionBuild', '42');
  controller.setRecoveryConfirmation(grant);
}
async function readyApple(stage = 'candidate', grant = APPLE_ADOPTION) {
  const h = await attached(); selectApple(h.controller, stage, grant); h.controller.prepare();
  assert.equal(h.count('prepare'), 1);
  h.respond('prepare', { ...review(), prepared: applePrepared(stage, grant) }); await flush();
  assert.ok(h.controller.currentPrepared()); return h;
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

test('additional Apple confirmations are exact optional declarations at every wire join', () => {
  const admit = (p, expected) => {
    assert.equal(githubReleaseSelection(p.target.selection, p.target.platform), expected);
    const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12,
      branch: 'release/ui', platform: p.target.platform, selection: p.target.selection };
    assert.equal(githubReleaseRequestFits('github_release_prepare', args), expected);
    assert.equal(parseGitHubReleaseStatus({ ...review(), prepared: p }) !== null, expected);
  };
  assert.equal(GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES, 342);
  assert.deepEqual([APPLE_MAX_ADOPTION.length, APPLE_UPLOAD.length, APPLE_CREATES.length], [342, 156, 157]);
  for (const stage of ['candidate', 'external-testing', 'production-submit']) {
    for (const recovery of [false, true]) {
      const old = prepared(stage, recovery); const bytes = JSON.stringify(old);
      assert.equal(Object.hasOwn(old.target.selection, 'recoveryConfirmation'), false);
      assert.equal(JSON.stringify(parseGitHubReleaseStatus({ ...review(), prepared: old }).prepared), bytes);
      admit(old, true);
    }
    for (const grant of [APPLE_ADOPTION, APPLE_UPLOAD, APPLE_CREATES]) {
      const allowed = (stage === 'candidate') === (grant !== APPLE_CREATES), p = applePrepared(stage, grant);
      admit(p, allowed);
      assert.equal(githubReleaseRecoveryConfirmation(grant, stage), allowed);
      assert.equal(githubReleaseSelection(p.target.selection), false); // No platform-blind grant validation.
      if (!allowed) continue;
      assert.equal(parseGitHubReleaseStatus({ ...review(), prepared: p }).prepared.target.selection.recoveryConfirmation, grant);
      const otherProducer = clone(p); otherProducer.target.selection.recoveryRunId = '9001'; admit(otherProducer, true);
      const android = clone(p); android.target.platform = 'android'; android.confirmation = `${stage}:android:1.2.3:42`; admit(android, false);
      const noRecovery = prepared(stage); noRecovery.target.platform = 'ios';
      noRecovery.confirmation = `${stage}:ios:${stage === 'candidate' ? '2.0.0:99' : '1.2.3:42'}`;
      noRecovery.target.selection.recoveryConfirmation = grant; admit(noRecovery, false);
      for (const changes of [{ recoveryRunId: 'latest' }, { recoveryRunId: null }, { force: true }, { recovery_confirmation: grant }]) {
        const bad = clone(p); Object.assign(bad.target.selection, changes); admit(bad, false);
      }
    }
  }
  for (const grant of [`recover-ios-candidate:${APPLE_INTENT}:B`, APPLE_MAX_ADOPTION]) admit(applePrepared('candidate', grant), true);
  const malformed = [undefined, null, '', false, 1, [], {}, ' ' + APPLE_ADOPTION, APPLE_ADOPTION + ' ',
    APPLE_ADOPTION + '\n', APPLE_ADOPTION + '\r\n', APPLE_ADOPTION + '\t', APPLE_ADOPTION + '\0',
    APPLE_ADOPTION + '\u00a0', APPLE_ADOPTION + '\u2028', APPLE_ADOPTION + '\u200b',
    APPLE_ADOPTION.replace(APPLE_INTENT, APPLE_INTENT.toUpperCase()), APPLE_ADOPTION.replace('recover-ios', 'Recover-ios'),
    APPLE_ADOPTION.replace(':', ':\n'), `recover-ios-candidate:${APPLE_INTENT.slice(1)}:B`,
    `recover-ios-candidate:${APPLE_INTENT}0:B`, `recover-ios-candidate:${APPLE_INTENT}:`, APPLE_MAX_ADOPTION + 'B',
    APPLE_UPLOAD.slice(0, -1), APPLE_UPLOAD + '0', APPLE_UPLOAD.replaceAll('2b', '2B'),
    ...['B/7', 'B+7', 'B:7', 'B\\7', 'é'].map((detail) => `recover-ios-candidate:${APPLE_INTENT}:${detail}`)];
  for (const grant of malformed) {
    const bad = applePrepared(); bad.target.selection.recoveryConfirmation = grant;
    assert.equal(githubReleaseRecoveryConfirmation(grant, 'candidate'), false); admit(bad, false);
  }
  for (const grant of [APPLE_CREATES.slice(0, -1), APPLE_CREATES + '0', APPLE_CREATES + '\n', APPLE_CREATES.replaceAll('3c', '3c'.toUpperCase())])
    admit(applePrepared('external-testing', grant), false);
  const dispatch = { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirm: true, confirmation: applePrepared().confirmation };
  assert.equal(githubReleaseRequestFits('github_release_dispatch', dispatch), true);
  for (const extra of [{ recoveryConfirmation: APPLE_UPLOAD }, { selection: applePrepared().target.selection }])
    assert.equal(githubReleaseRequestFits('github_release_dispatch', { ...dispatch, ...extra }), false);
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
  for (const grant of [undefined, APPLE_MAX_ADOPTION]) {
    const bytes = (v) => new TextEncoder().encode(JSON.stringify(v)).byteLength;
    const p = grant === undefined ? prepared('candidate', true) : applePrepared('candidate', grant), maxId = '18446744073709551615';
    p.target.repository = 'a'.repeat(39) + '/' + 'b'.repeat(100);
    p.target.branch = 'b'.repeat(200); p.expectedRef = 'refs/heads/' + p.target.branch;
    p.target.accountId = maxId; p.target.repositoryId = maxId; p.workflowId = maxId;
    p.target.selection.recoveryRunId = maxId;
    p.target.selection.originalVersion = { name: grant === undefined ? '1.0+' + 'v'.repeat(60) : '1.2.3', build: 2_100_000_000 };
    p.currentVersion = clone(p.target.selection.originalVersion);
    p.confirmation = `candidate:${p.target.platform}:${p.currentVersion.name}:2100000000`;
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
    const retained = clone(full.pending);
    const mixed = clone(full); delete mixed.pending[1].prepared.target.selection.recoveryConfirmation;
    assert.ok(parseGitHubReleaseStatus(mixed));
    const unsupported = clone(full); unsupported.pending[1].prepared.target.selection.recoveryConfirmation = null;
    assert.equal(parseGitHubReleaseStatus(unsupported), null);
    const over = clone(full); assert.ok(over.prepared.checklist.length < 16);
    over.prepared.checklist.push({ name: 'MOBILE_RELEASE_OVERFLOW', kind: 'manual', reason: 'x' });
    assert.equal(parseGitHubReleaseStatus(over), null); assert.deepEqual(full.pending, retained);
    full.pending.push(clone(full.pending[0])); assert.equal(parseGitHubReleaseStatus(full), null);
    full.pending.pop(); full.prepared.checklist.at(-1).reason = 'r'.repeat(192) + 'x'; assert.equal(parseGitHubReleaseStatus(full), null);
  }
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

test('additional Apple draft rejects raw malformed or oversized edits without stale consent', async () => {
  for (const value of [APPLE_ADOPTION + '\n', APPLE_ADOPTION + '\r\n', ' ' + APPLE_ADOPTION,
    APPLE_ADOPTION.replace(APPLE_INTENT, APPLE_INTENT.toUpperCase()), APPLE_MAX_ADOPTION + 'B', 'é'.repeat(172), null]) {
    const h = await readyApple(); h.controller.setConfirmed(true); h.controller.setConfirmation(applePrepared().confirmation);
    h.controller.setRecoveryConfirmation(value);
    const rejected = typeof value !== 'string' || new TextEncoder().encode(value).byteLength > 342;
    assert.equal(h.state.recoveryConfirmationRejected, rejected);
    assert.equal(h.state.recoveryConfirmation, rejected ? '' : value); // No normalization or silent truncation.
    assert.equal(h.controller.currentPrepared(), null); assert.equal(h.controller.selection(), null);
    assert.equal(h.state.confirmed, false); assert.equal(h.state.confirmation, ''); assert.ok(h.controller.prepareReason());
    h.controller.prepare(); h.controller.dispatch(); assert.equal(h.count('prepare'), 1); assert.equal(h.count('dispatch'), 0);
    h.controller.setRecoveryConfirmation('');
    assert.equal(h.state.recoveryConfirmationRejected, false); assert.equal(h.controller.currentPrepared(), null);
    assert.equal(Object.hasOwn(h.controller.selection(), 'recoveryConfirmation'), false);
    assert.equal(h.controller.prepareReason(), null); h.controller.dispose();
  }
});

test('Apple confirmation and relevant context edits revoke the original prepared review', async () => {
  const changes = [
    (h) => h.controller.setBranch('release/other'), (h) => h.controller.setPlatform('android'),
    (h) => h.controller.setStage('external-testing'), (h) => h.controller.setRecovery(false),
    ...['candidateRunId', 'externalRunId', 'recoveryRunId', 'originalSourceSha', 'originalVersionName', 'originalVersionBuild']
      .map((name) => (h) => h.controller.setInput(name, name === 'originalSourceSha' ? 'e'.repeat(40) : name === 'originalVersionName' ? '1.2.4' : '104')),
    (h) => h.context({ ...connection(), context: { ...connection().context, documentId: 'doc-b' } }),
    (h) => h.context({ ...connection(), context: { ...connection().context, projectGeneration: 2 } }),
    (h) => { const view = connection(); view.context.projectId = 'project-b'; view.status.session.projectId = 'project-b'; h.context(view); },
    (h) => { const view = connection(); view.context.repository = 'owner/other'; view.status.repository.value.fullName = 'owner/other'; view.status.session.targetRepository = 'owner/other'; h.context(view); },
    (h) => { const view = connection(); view.status.account.value.id = '12'; h.context(view); },
    (h) => { const view = connection(); view.status.repository.value.id = '23'; h.context(view); },
    (h) => { const view = connection(); view.status.session.id = 'session-b'; h.context(view); },
    (h) => h.context({ ...connection(), context: null }),
    (h) => h.controller.connect({ ...h.api }),
  ];
  for (const change of changes) {
    const h = await readyApple(); h.controller.setConfirmed(true); h.controller.setConfirmation(applePrepared().confirmation);
    await change(h);
    assert.equal(h.state.recoveryConfirmation, ''); assert.equal(h.state.recoveryConfirmationRejected, false);
    assert.equal(h.state.confirmed, false); assert.equal(h.controller.currentPrepared(), null);
    h.controller.dispatch(); assert.equal(h.count('dispatch'), 0); h.controller.dispose();
  }
  const h = await readyApple(); h.controller.setConfirmed(true); h.controller.setConfirmation(applePrepared().confirmation);
  h.controller.setRecoveryConfirmation(APPLE_ADOPTION); assert.ok(h.controller.currentPrepared());
  h.controller.setRecoveryConfirmation(APPLE_UPLOAD); h.controller.setRecoveryConfirmation(APPLE_ADOPTION);
  assert.equal(h.controller.currentPrepared(), null); h.controller.dispatch(); assert.equal(h.count('dispatch'), 0); h.controller.dispose();
  const promotion = await readyApple('external-testing', APPLE_CREATES); promotion.controller.setConfirmed(true);
  promotion.controller.setStage('production-submit'); assert.equal(promotion.state.recoveryConfirmation, '');
  promotion.controller.setStage('external-testing'); promotion.controller.setRecoveryConfirmation(APPLE_CREATES);
  assert.equal(promotion.controller.currentPrepared(), null); promotion.controller.dispatch();
  assert.equal(promotion.count('dispatch'), 0); promotion.controller.dispose();
  const inFlight = await attached(); selectApple(inFlight.controller); inFlight.controller.prepare();
  inFlight.controller.setRecoveryConfirmation(APPLE_UPLOAD);
  inFlight.respond('prepare', { ...review(), prepared: applePrepared() }); await flush();
  assert.equal(inFlight.controller.currentPrepared(), null);
  assert.equal(inFlight.controller.selection().recoveryConfirmation, APPLE_UPLOAD);
  inFlight.controller.dispatch(); assert.equal(inFlight.count('dispatch'), 0); inFlight.controller.dispose();
});

test('captured Apple grant remains on the original record through uncertainty and observation only', async () => {
  const h = await readyApple(); const captured = clone(h.controller.currentPrepared());
  assert.equal(h.last('prepare').args.selection.recoveryConfirmation, APPLE_ADOPTION);
  assert.ok(Object.isFrozen(h.controller.currentPrepared().target.selection));
  h.controller.setConfirmed(true); h.controller.setConfirmation(captured.confirmation); h.controller.dispatch(); h.controller.dispatch();
  assert.deepEqual(h.last('dispatch').args, { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirm: true, confirmation: captured.confirmation });
  h.last('dispatch').reject({ code: 'unknown' }); await flush(); assert.equal(h.state.uncertain, true);
  h.controller.setRecoveryConfirmation(APPLE_UPLOAD); h.controller.prepare(); h.controller.dispatch();
  assert.equal(h.count('prepare'), 1); assert.equal(h.count('dispatch'), 1);
  const pending = [{ prepared: captured, runId: null }];
  h.emit({ ...operation('dispatch', 'settled', 5, 'network-unavailable', 'potentially-applied'), pending }); await flush();
  assert.equal(h.state.uncertain, false); assert.equal(h.state.status.pending[0].prepared.target.selection.recoveryConfirmation, APPLE_ADOPTION);
  assert.equal(h.controller.currentPrepared(), null); h.controller.dispatch(); assert.equal(h.count('dispatch'), 1);
  h.controller.observe(h.state.status.pending[0]);
  assert.deepEqual(h.last('reconcile').args, { sessionId: 'session-a', expectedRevision: 5, marker: MARKER });
  const reconciled = { ...operation('reconcile', 'settled', 7), pending: [{ prepared: captured, runId: '44' }], run: observed().run };
  h.respond('reconcile', reconciled); await flush(); h.controller.observe(h.state.status.pending[0]);
  assert.deepEqual(h.last('track').args, { sessionId: 'session-a', expectedRevision: 7, marker: MARKER });
  h.respond('track', { ...reconciled, ...operation('track', 'settled', 9), pending: reconciled.pending, run: reconciled.run }); await flush();
  h.controller.loadPending(); h.respond('pending', { ...operation('pending', 'settled', 11), pending: reconciled.pending }); await flush();
  assert.deepEqual(['prepare', 'dispatch', 'reconcile', 'track', 'pending'].map((kind) => h.count(kind)), [1, 1, 1, 1, 1]);
  assert.equal(h.state.status.pending[0].prepared.target.selection.recoveryConfirmation, APPLE_ADOPTION);
  const replaced = clone(h.state.status); replaced.revision += 1;
  replaced.pending[0].prepared.target.selection.recoveryConfirmation = APPLE_UPLOAD; // Valid syntax is not authority to replace a retained original.
  h.emit(replaced); assert.equal(h.state.error, 'response-invalid');
  assert.equal(h.state.status.pending[0].prepared.target.selection.recoveryConfirmation, APPLE_ADOPTION); h.controller.dispose();
});

test('expired or consumed Apple consent never authorizes a second dispatch', async () => {
  const h = await readyApple(); h.controller.setConfirmed(true); h.controller.setConfirmation(applePrepared().confirmation); h.controller.dispatch();
  h.last('dispatch').reject({ code: 'github_release_refused_consent_expired' }); await flush();
  assert.equal(h.state.error, 'consent-expired'); assert.equal(h.controller.currentPrepared(), null);
  h.controller.setConfirmed(true); h.controller.setConfirmation(applePrepared().confirmation); h.controller.dispatch();
  assert.equal(h.count('dispatch'), 1); h.controller.dispose();
  const expired = await readyApple(); expired.controller.setConfirmed(true);
  expired.emit({ ...review(4), available: false, reason: 'consent-expired', prepared: null, consentExpiresAt: null });
  assert.equal(expired.controller.currentPrepared(), null); assert.equal(expired.state.confirmed, false);
  expired.controller.dispatch(); assert.equal(expired.count('dispatch'), 0); expired.controller.dispose();
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
