// Inert DATA/fake IPC only. No credentials, native journal, services or workers.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import guide from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };
import { createNativeApi } from '../src/bridge.ts';
import { GitHubInputGroupController, githubInputGroupOwnerReason } from '../src/githubInputGroupController.ts';
import { githubInputGroupCompleted, githubInputGroupError, githubInputGroupRequestFits, parseGitHubInputGroupStatus } from '../src/githubInputGroupProtocol.ts';

const TIME = '2026-09-28T10:00:00Z', EXPIRY = '2026-09-28T10:02:00Z', MARKER = 'd'.repeat(32), RECORD = 'f'.repeat(32);
const clone = (value) => structuredClone(value);
const ASSIGNMENT = { kind: 'google-wif', recordId: RECORD, recordRevision: 0, contextRevision: 1 };
const SCOPE = { stage: 'candidate', platform: 'android', purpose: 'full' };
function connection() { return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'owner/app' },
  status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'owner/app', state: 'connected' },
    account: { state: 'observed', value: { id: '11' } }, repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } },
  helpState: 'current', busy: null, uncertain: false, blocked: false, retirementPending: false, error: null }; }
function project() { const draft = { project: { name: 'Fictional' } };
  return { project: { id: 'project-a' }, revision: 1, baselineGeneration: 1, observationGeneration: 1,
    snapshotRequest: null, snapshotError: null, snapshotPredatesSave: false, saveRecoveryRequired: false, sourceChanged: false,
    validationRequest: null, validationError: null, validatedRevision: 1, validatedBaselineGeneration: 1, draft,
    snapshot: { observedAt: TIME, config: { state: 'format-valid', data: clone(draft) } },
    validation: { valid: true, requirements: guide.kinds.find((kind) => kind.id === 'google-wif').fields.map((field) => ({ name: field.requirement,
      stage: 'candidate', platform: 'android', kind: 'variable', alternatives: [], environment: 'mobile-candidate', reason: 'Fictional requirement', state: 'unknown' })) } }; }
function assets() { return { mode: 'native', busy: null, blocked: false, observationFailed: false, updatingContext: false, contextCurrent: true,
  originPending: false, cancelledOperationId: null, scope: clone(SCOPE), status: { statusRevision: 1, mode: 'session', persistence: null,
    capability: { available: true, reason: 'none' }, context: { revision: 1, projectId: 'project-a', ...SCOPE }, operation: null,
    records: [{ recordId: RECORD, revision: 0, kind: 'google-wif', availability: 'assigned', label: 'NEVER_COPY_PRIVATE_LABEL', storage: 'session', payloadState: 'assessed' }],
    assignments: [{ ...ASSIGNMENT, availability: 'available' }] } }; }
function target() { return { projectBinding: 'b'.repeat(64), repository: 'owner/app', accountId: '11', repositoryId: '22', environment: 'mobile-candidate', environmentId: '33',
  branch: 'release/ui', sourceSha: 'a'.repeat(40), toolingSha: 'c'.repeat(40), callerPath: '.github/workflows/mobile-candidate.yml',
  callerSha256: 'e'.repeat(64), configSha256: 'f'.repeat(64), scope: clone(SCOPE), kind: 'google-wif', secretName: 'MOBILE_RELEASE_INPUT_GOOGLE_WIF_V1', protocol: 'mrk-github-input-group/1' }; }
function prepared() { return { consentId: MARKER, target: target(), assignment: clone(ASSIGNMENT), fields: ['provider', 'serviceAccount'],
  metadata: { state: 'missing-or-inaccessible', observedAt: TIME }, destination: { state: 'fits', plaintextLimitBytes: 48000 },
  effect: 'upsert-one-complete-group', observedAt: TIME, consentExpiresAt: EXPIRY }; }
// Existing cases start with a previous native observation as inert DTO data;
// these fixtures do not establish actual GitHub permissions or qualification.
function safeRunners() { return { result: 'safe', checkedAt: TIME, expiresAt: EXPIRY, groupCount: 0, runnerCount: 0, scope: 'repository', reason: 'none' }; }
function refusedRunners(reason = 'runner-collision') { return { result: 'refused', checkedAt: null, expiresAt: null, groupCount: null, runnerCount: null, scope: null, reason }; }
function idle(revision = 1, runner = safeRunners()) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, runner: clone(runner), prepared: null, records: [], observation: null }; }
function operation(kind, phase, revision, reason = 'none') { return { ...idle(revision), available: phase === 'settled',
  reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
  operation: { id: kind + '-ticket', kind, phase, reason } }; }
function review(revision = 3) { return { ...operation('prepare', 'settled', revision), prepared: prepared() }; }
function result(revision = 5, state = 'acknowledged-updated') {
  const write = state === 'acknowledged-updated' ? { state, statusCode: 204 } : { state };
  return { ...operation('apply', 'settled', revision), records: [{ originalOperationId: MARKER, target: target(), write,
    completion: { journal: 'confirmed', cleanup: 'confirmed', finality: 'settled' }, reason: state === 'attempted-outcome-unknown' ? 'network-unavailable' : 'none' }] };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 12; i++) await Promise.resolve(); }
function harness(runner = safeRunners()) {
  const calls = []; let current = idle(1, runner), conn = connection(), local = project(), material = assets(), listener = null, detached = 0;
  const request = (kind, args) => { const d = deferred(); calls.push({ kind, args: clone(args), ...d }); return d.promise; };
  const api = { mode: 'native', githubInputGroupStatus: async () => { calls.push({ kind: 'status' }); return clone(current); },
    subscribeGitHubInputGroup: async (fn) => { calls.push({ kind: 'subscribe' }); listener = fn; return () => { listener = null; detached++; }; },
    checkGitHubInputRunners: (args) => request('runner-check', args),
    prepareGitHubInputGroup: (args) => request('prepare', args), applyGitHubInputGroup: (args) => request('apply', args),
    reconcileGitHubInputGroup: (args) => request('reconcile', args), loadGitHubInputGroupPending: (args) => request('pending', args),
    cancelGitHubInputGroup: (args) => request('cancel', args) };
  const controller = new GitHubInputGroupController(() => conn, () => material, () => local);
  controller.setGuide(guide);
  return { controller, api, calls, get state() { return controller.getSnapshot(); }, get detached() { return detached; },
    get local() { return local; }, get assets() { return material; }, get connection() { return conn; },
    count: (kind) => calls.filter((row) => row.kind === kind).length, last: (kind) => calls.filter((row) => row.kind === kind).at(-1),
    emit: (value) => { current = clone(value); listener?.(clone(value)); }, retain: (value) => { current = clone(value); },
    respond: (kind, value) => { current = clone(value); calls.filter((row) => row.kind === kind).at(-1).resolve(clone(value)); },
    changeProject: (value) => { controller.beforeWorkspaceAction(); local = value; controller.syncContext(); },
    changeAssets: (value) => { material = value; controller.syncContext(); }, changeConnection: (value) => { conn = value; controller.syncContext(); } };
}
async function attached(runner) { const h = harness(runner); await h.controller.connect(h.api); return h; }
function choose(h) { h.controller.setBranch('release/ui'); h.controller.setAssignment(ASSIGNMENT); }
async function ready() { const h = await attached(); choose(h); h.controller.prepare(); h.respond('prepare', review()); await flush(); return h; }

test('closed group protocol preserves native u32 assignment revisions, whole fields and canonical response target', () => {
  for (const value of [idle(), review(), result(), result(5, 'attempted-outcome-unknown')]) assert.ok(parseGitHubInputGroupStatus(value));
  for (const mutate of [(s) => { s.prepared.fields.pop(); }, (s) => { s.prepared.target.secretName = 'OTHER'; },
    (s) => { s.prepared.target.environment = 'mobile-production'; }, (s) => { s.prepared.assignment.recordRevision = '0'; },
    (s) => { s.prepared.target.scope.stage = 'production'; }, (s) => { s.prepared.values = 'INERT'; },
    (s) => { s.prepared.metadata.state = 'absent'; }, (s) => { s.prepared.destination.plaintextLimitBytes = 65536; }]) {
    const s = review(); mutate(s); assert.equal(parseGitHubInputGroupStatus(s), null);
  }
  const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, expectedAssetStatusRevision: 1, branch: 'release/ui', assignment: clone(ASSIGNMENT) };
  assert.equal(githubInputGroupRequestFits('github_input_group_prepare', args), true);
  for (const name of ['token', 'values', 'ciphertext', 'secretName', 'environment', 'url', 'filename', 'path', 'stage'])
    assert.equal(githubInputGroupRequestFits('github_input_group_prepare', { ...args, [name]: 'INERT' }), false);
  assert.equal(githubInputGroupRequestFits('github_input_group_apply', { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirmUpsertWholeGroup: false }), false);
  let invoked = 0; const hostile = idle(); Object.defineProperty(hostile, 'private', { enumerable: true, get() { invoked++; return 'INERT'; } });
  assert.equal(parseGitHubInputGroupStatus(hostile), null); assert.equal(invoked, 0);
  assert.equal(githubInputGroupError({ code: 'unrelated', admission: 'not-admitted', message: 'INERT' }).admission, 'unknown');
});

test('bridge has only fixed P2 and runner-read commands and preview/unavailable never fabricates success', async () => {
  const calls = [], events = [];
  const api = createNativeApi('native', async (name, args) => { calls.push({ name, args }); return idle(); }, async (name) => { events.push(name); return () => {}; });
  await api.githubInputGroupStatus(); await api.subscribeGitHubInputGroup(() => {});
  await api.loadGitHubInputGroupPending({ sessionId: 'session-a', expectedRevision: 1 });
  const check = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, expectedAssetStatusRevision: 1, contextRevision: 1 };
  await api.checkGitHubInputRunners(check);
  assert.deepEqual(calls.map((row) => row.name), ['github_input_group_status', 'github_input_group_pending', 'github_input_runner_check']);
  assert.deepEqual(calls.at(-1).args, check);
  assert.deepEqual(events, ['github-input-group-status']);
  await assert.rejects(api.applyGitHubInputGroup({ sessionId: 'session-a', expectedRevision: 1, consentId: MARKER, confirmUpsertWholeGroup: true, token: 'INERT' }), (e) => e.admission === 'not-admitted');
  await assert.rejects(api.checkGitHubInputRunners({ ...check, branch: 'main' }), (e) => e.admission === 'not-admitted');
  assert.equal(calls.length, 3);
  const unavailable = createNativeApi('unavailable', async () => { throw new Error('must not invoke'); });
  await assert.rejects(unavailable.githubInputGroupStatus(), (e) => e.reason === 'runtime-unavailable');
  await assert.rejects(unavailable.checkGitHubInputRunners(check), (e) => e.reason === 'runtime-unavailable');
  const h = harness(); await h.controller.connect({ ...h.api, mode: 'preview' }); choose(h); h.controller.checkRunners(); h.controller.prepare(); h.controller.apply();
  assert.equal(h.calls.length, 0); h.controller.dispose();
});

test('one complete current native assignment is reviewed and exactly one explicit Apply is sent', async () => {
  const h = await attached(); assert.deepEqual(h.calls.map((row) => row.kind), ['subscribe', 'status']);
  assert.equal(h.state.assignment, null); assert.equal(h.state.branch, ''); choose(h);
  assert.equal(JSON.stringify(h.controller.choices()).includes('NEVER_COPY_PRIVATE_LABEL'), false);
  h.controller.prepare(); h.controller.prepare(); assert.equal(h.count('prepare'), 1);
  assert.deepEqual(h.last('prepare').args, { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12,
    expectedAssetStatusRevision: 1, branch: 'release/ui', assignment: ASSIGNMENT });
  h.respond('prepare', review()); await flush(); assert.ok(h.controller.currentPrepared());
  h.controller.apply(); assert.equal(h.count('apply'), 0); h.controller.setConfirmed(true);
  const stop = h.controller.subscribe(() => { if (h.state.pending) h.controller.apply(); });
  h.controller.apply(); h.controller.apply(); stop(); assert.equal(h.count('apply'), 1); assert.equal(h.state.confirmed, false);
  assert.deepEqual(h.last('apply').args, { sessionId: 'session-a', expectedRevision: 3, consentId: MARKER, confirmUpsertWholeGroup: true });
  h.respond('apply', result()); await flush(); assert.equal(h.state.pending, false); assert.equal(githubInputGroupOwnerReason(h.state), null);
  h.controller.dispose(); assert.equal(h.detached, 1);
});

test('pre-send reentrant invalidation suppresses Apply; sent origin survives context change and port retirement', async () => {
  const a = await ready(); a.controller.setConfirmed(true);
  const stop = a.controller.subscribe(() => { if (a.state.pending) a.controller.setAssignment(null); });
  a.controller.apply(); stop(); assert.equal(a.count('apply'), 0); assert.equal(a.state.pending, false); a.controller.dispose();
  const b = await ready(); b.controller.setConfirmed(true); b.controller.apply();
  const changed = clone(b.assets); changed.status.assignments[0].recordRevision = 1; b.changeAssets(changed);
  assert.equal(b.controller.currentPrepared(), null); assert.equal(b.state.pending, true);
  await b.controller.connect(null); assert.equal(b.detached, 0);
  b.respond('apply', result()); await flush(); assert.equal(b.detached, 1); assert.equal(b.state.pending, false); assert.equal(b.controller.currentPrepared(), null); b.controller.dispose();
  const c = await ready(); c.controller.setConfirmed(true);
  const off = c.controller.subscribe(() => { if (c.state.pending) c.controller.dispose(); });
  c.controller.apply(); off(); assert.equal(c.count('apply'), 0); assert.equal(c.detached, 1);
});

test('saved configuration, assignment, guide and native-context changes invalidate current reviews', async () => {
  for (const change of [(h) => { const p = clone(h.local); p.sourceChanged = true; h.changeProject(p); },
    (h) => { const a = clone(h.assets); a.status.context.revision++; h.changeAssets(a); },
    (h) => { const a = clone(h.assets); a.status.assignments[0].availability = 'unavailable'; h.changeAssets(a); },
    (h) => h.controller.setGuide(null), (h) => { const p = clone(h.local); p.validation.requirements.pop(); h.changeProject(p); }]) {
    const h = await ready(); h.controller.setConfirmed(true); change(h); h.controller.apply();
    assert.equal(h.controller.currentPrepared(), null); assert.equal(h.state.confirmed, false); assert.equal(h.count('apply'), 0); h.controller.dispose();
  }
});

test('lost invoke cannot be released by idle Status, and only the original ticket settles it', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.apply(); h.last('apply').reject({ message: 'INERT private diagnostics' }); await flush();
  assert.equal(h.state.uncertain, true); assert.ok(githubInputGroupOwnerReason(h.state));
  h.retain(review()); await h.controller.checkStatus(); assert.equal(h.state.pending, true); h.controller.apply(); assert.equal(h.count('apply'), 1);
  const original = result(); h.emit(original); await flush(); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false);
  const forged = clone(original); forged.records[0].target.repositoryId = '99'; forged.revision++;
  h.emit(forged); assert.equal(h.state.uncertain, true); assert.equal(h.state.status.records[0].target.repositoryId, '22'); h.controller.dispose();
});

test('acknowledgement survives failed finality and metadata reconciliation cannot upgrade an unknown write', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.apply();
  const incomplete = result(); incomplete.available = false; incomplete.reason = 'cleanup-unknown';
  incomplete.operation.phase = 'cleanup-unknown'; incomplete.operation.reason = 'cleanup-unknown';
  incomplete.records[0].completion = { journal: 'unknown', cleanup: 'unknown', finality: 'unknown' }; incomplete.records[0].reason = 'cleanup-unknown';
  assert.ok(parseGitHubInputGroupStatus(incomplete)); assert.equal(githubInputGroupCompleted(incomplete.records[0]), false);
  h.respond('apply', incomplete); await flush(); assert.equal(h.state.status.records[0].write.state, 'acknowledged-updated'); assert.ok(githubInputGroupOwnerReason(h.state));
  h.controller.dispose(); assert.equal(h.detached, 0); // The genuinely live original remains owned.
  const r = harness(); const unknown = result(2, 'attempted-outcome-unknown'); unknown.operation = null;
  unknown.records[0].completion = { journal: 'unknown', cleanup: 'unknown', finality: 'unknown' }; unknown.records[0].reason = 'cleanup-unknown';
  r.retain(unknown); await r.controller.connect(r.api); // Restored history, not work sent by this controller.
  const originalRecord = clone(unknown.records[0]);
  assert.ok(parseGitHubInputGroupStatus(unknown)); assert.equal(r.controller.startReason(), null);
  assert.equal(githubInputGroupOwnerReason(r.state), null); assert.deepEqual(r.state.status.records[0], originalRecord);
  r.controller.observe(r.state.status.records[0]); assert.deepEqual(r.last('reconcile').args, { sessionId: 'session-a', expectedRevision: 2, originalOperationId: MARKER });
  const read = { ...operation('reconcile', 'settled', 4), records: clone(unknown.records), observation: { originalOperationId: MARKER,
    metadata: { state: 'present', createdAt: TIME, updatedAt: TIME, observedAt: TIME }, assurance: 'metadata-only-not-secret-value-or-write-confirmation' } };
  r.respond('reconcile', read); await flush(); assert.deepEqual(r.state.status.records[0], originalRecord);
  assert.equal(githubInputGroupOwnerReason(r.state), null); assert.equal(githubInputGroupCompleted(r.state.status.records[0]), false);
  // Unknown history must not retain a replaced settled observer.
  const replacement = { ...r.api }; await r.controller.connect(replacement); assert.equal(r.detached, 1);
  assert.deepEqual(r.state.status.records[0], originalRecord);
  const forged = clone(read); forged.revision++; forged.records[0].write = { state: 'acknowledged-updated', statusCode: 204 }; forged.records[0].reason = 'none';
  r.emit(forged); assert.equal(r.state.uncertain, true); assert.equal(r.state.status.records[0].write.state, 'attempted-outcome-unknown'); r.controller.dispose();
});

test('replacement ports need their own acknowledged subscription and status before any new action', async () => {
  for (const outcome of ['delayed', 'rejected']) {
    const h = await attached(); choose(h);
    const historical = result(2, 'attempted-outcome-unknown'); historical.operation = null; h.emit(historical);
    const record = clone(historical.records[0]), subscribed = deferred(), status = deferred();
    let notify = null, statusReads = 0, stopped = 0;
    const replacement = { ...h.api,
      subscribeGitHubInputGroup: (listener) => { notify = listener; return subscribed.promise; },
      githubInputGroupStatus: () => { statusReads++; return status.promise; } };
    const connecting = h.controller.connect(replacement); await flush();
    assert.equal(h.detached, 1); assert.equal(h.state.status, null);
    const refuseAll = () => {
      h.controller.checkRunners(); h.controller.prepare(); h.controller.loadPending(); h.controller.observe(record); h.controller.apply();
      for (const kind of ['runner-check', 'prepare', 'pending', 'reconcile', 'apply']) assert.equal(h.count(kind), 0, `${outcome}: ${kind}`);
    };
    refuseAll(); assert.equal(statusReads, 0);
    if (outcome === 'delayed') {
      subscribed.resolve(() => { stopped++; }); await flush();
      assert.equal(statusReads, 1); refuseAll(); // ACK alone is not current status.
      status.resolve({ ...historical, revision: 17 }); await connecting;
    } else {
      notify({ ...historical, revision: 16 }); refuseAll(); // Status alone is not subscription ACK.
      subscribed.reject(new Error('INERT subscription unavailable')); await connecting;
      assert.equal(h.state.error, 'runtime-unavailable'); refuseAll(); assert.equal(statusReads, 0);
      const recovered = { ...h.api, subscribeGitHubInputGroup: async () => () => { stopped++; },
        githubInputGroupStatus: async () => ({ ...historical, revision: 17 }) };
      await h.controller.connect(recovered);
    }
    assert.equal(h.controller.startReason(), null); h.controller.loadPending();
    assert.deepEqual(h.last('pending').args, { sessionId: 'session-a', expectedRevision: 17 });
    h.respond('pending', { ...operation('pending', 'settled', 18), records: clone(historical.records) }); await flush();
    assert.equal(h.state.pending, false); h.controller.dispose(); assert.equal(stopped, 1);
  }
});

test('guided panel retains native file workflow, local-only history and whole-group warnings without raw entry', async () => {
  const source = await readFile(new URL('../src/components/GitHubInputGroup.tsx', import.meta.url), 'utf8');
  for (const text of ['Manage inputs / change release context', 'Review upload — read only', 'Apply this group once', 'missing or inaccessible',
    '48,000-byte', 'compare-and-swap', 'where:', 'format:', 'failure:', 'requiredness:', 'GitHub accepted the update; local completion needs attention',
    'Check current metadata — read only', 'This cannot prove the secret’s value', 'No release starts here',
    'Check runner safety — read only', 'including inherited groups', '100 runners per list', 'ubuntu-24.04', 'macos-26',
    'No branch or selected input group is needed', 'effective runner visibility', 'Native expiry · display only']) assert.ok(source.includes(text), text);
  assert.doesNotMatch(source, /type="(?:password|file)"|localStorage|sessionStorage|navigator\.clipboard|\.label\s*\}\s*·\s*record/u);
  const app = await readFile(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(app, /assetSession\.subscribe\(githubInputGroup\.syncContext\)/u);
  assert.match(app, /githubInputGroupControllerRef\.current\?\.beforeWorkspaceAction\(\)/u);
  assert.match(app, /!excludeGitHubInputGroup.*githubInputGroupOwnerReason/u);
  const preview = await readFile(new URL('../src/preview.ts', import.meta.url), 'utf8');
  assert.match(preview, /applyGitHubInputGroup: githubInputGroupUnavailable/u);
  assert.match(preview, /checkGitHubInputRunners: githubInputGroupUnavailable/u);
  const build = await readFile(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const acl = JSON.parse(await readFile(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const shell = await readFile(new URL('../src-tauri/src/shell.rs', import.meta.url), 'utf8');
  assert.equal(build.split('"github_input_runner_check"').length - 1, 1);
  assert.equal(acl.permissions.filter((p) => p === 'allow-github-input-runner-check').length, 1);
  const body = shell.match(/async fn github_input_runner_check\([^]*?\n\}/u)?.[0];
  assert.ok(body); assert.match(body, /fixture_command!\(state,Forbidden/u);
  assert.match(body, /webview\.label\(\)!=MAIN_WINDOW/u);
  assert.match(body, /github_input_group_command\("github_input_runner_check",request_body\(&request\)\?\)/u);
  assert.match(shell, /github_input_group_status, github_input_runner_check, github_input_group_prepare/u);
});

test('runner request and nullable observations reject authority injection, excessive inventory and premature success', () => {
  const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, expectedAssetStatusRevision: 1, contextRevision: 1 };
  assert.equal(githubInputGroupRequestFits('github_input_runner_check', args), true);
  for (const name of ['branch', 'assignment', 'token', 'repository', 'url', 'labels'])
    assert.equal(githubInputGroupRequestFits('github_input_runner_check', { ...args, [name]: 'INERT' }), false);
  for (const [name, value] of [['contextRevision', -1], ['contextRevision', 0], ['expectedAssetStatusRevision', 0], ['expectedAssetStatusRevision', 2 ** 32], ['expectedConnectionRevision', 0]])
    assert.equal(githubInputGroupRequestFits('github_input_runner_check', { ...args, [name]: value }), false);
  for (const runner of [null, safeRunners(), refusedRunners(), { ...safeRunners(), result: 'expired', reason: 'expired' },
    { ...safeRunners(), groupCount: 8, runnerCount: 900, scope: 'organization-wide' }]) assert.ok(parseGitHubInputGroupStatus(idle(1, runner)));
  const missing = idle(); delete missing.runner; assert.equal(parseGitHubInputGroupStatus(missing), null);
  for (const patch of [{ groupCount: 9 }, { groupCount: -1 }, { runnerCount: 1.5 }, { runnerCount: 101 },
    { groupCount: 1, runnerCount: 0 }, { groupCount: 1, runnerCount: 201, scope: 'organization-wide' },
    { expiresAt: TIME }, { checkedAt: '2026-02-30T10:00:00Z' }, { checkedAt: TIME.replace('Z', '+00:00') },
    { reason: 'runner-collision' }, { labels: ['ubuntu-24.04'] }, { result: 'expired' }, { result: 'refused', reason: 'runner-collision' }])
    assert.equal(parseGitHubInputGroupStatus(idle(1, { ...safeRunners(), ...patch })), null, JSON.stringify(patch));
  assert.equal(parseGitHubInputGroupStatus(idle(1, { ...refusedRunners(), reason: 'none' })), null);
  for (const phase of ['running', 'cleanup-unknown']) {
    const s = operation('runner-check', phase, 2, phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'none');
    assert.equal(parseGitHubInputGroupStatus(s), null);
    s.runner = null; assert.ok(parseGitHubInputGroupStatus(s));
  }
  assert.equal(parseGitHubInputGroupStatus(operation('runner-check', 'settled', 2, 'runner-collision')), null);
  assert.ok(parseGitHubInputGroupStatus(operation('pending', 'running', 2))); // Previous genuine runner facts may remain.
  for (const runner of [null, refusedRunners(), { ...safeRunners(), result: 'expired', reason: 'expired' }])
    assert.equal(parseGitHubInputGroupStatus({ ...review(), runner }), null);
  const beyond = review(); beyond.prepared.consentExpiresAt = '2026-09-28T10:02:01Z'; assert.equal(parseGitHubInputGroupStatus(beyond), null);
  // A post-I/O collision is an original result, not a pre-admission exception.
  assert.equal(githubInputGroupError({ code: 'github_input_group_refused_runner_collision' }).admission, 'unknown');
});

test('runner safety is one explicit read without branch or assignment, not a circular gate or automatic upload', async () => {
  const h = await attached(null);
  assert.equal(h.controller.startReason(), null); assert.equal(h.controller.runnerCheckReason(), null);
  assert.match(h.controller.prepareReason(), /Check runner safety/u);
  h.controller.loadPending(); h.respond('pending', { ...operation('pending', 'settled', 2), runner: null }); await flush();
  h.controller.checkRunners(); h.controller.checkRunners(); assert.equal(h.count('runner-check'), 1);
  assert.deepEqual(h.last('runner-check').args, { sessionId: 'session-a', expectedRevision: 2, expectedConnectionRevision: 12, expectedAssetStatusRevision: 1, contextRevision: 1 });
  h.emit({ ...operation('runner-check', 'running', 3), runner: null });
  h.respond('runner-check', operation('runner-check', 'settled', 4)); await flush();
  assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false); assert.equal(h.controller.runnerReason(), null);
  assert.equal(h.state.assignment, null); assert.equal(h.state.branch, '');
  assert.equal(h.count('prepare'), 0); assert.equal(h.count('apply'), 0); assert.equal(h.controller.currentPrepared(), null);
  assert.match(h.controller.prepareReason(), /Enter an application branch/u); h.controller.dispose();
});

test('runner check rechecks native revisions after subscribers and retains the exact lost original for cancellation', async () => {
  for (const change of [(h) => { const c = clone(h.connection); c.status.revision++; h.changeConnection(c); },
    (h) => h.emit(idle(2, null)),
    (h) => { const a = clone(h.assets); a.status.statusRevision++; h.changeAssets(a); },
    (h) => { const a = clone(h.assets); a.status.context.revision++; h.changeAssets(a); },
    (h) => { const p = clone(h.local); p.sourceChanged = true; h.changeProject(p); }]) {
    const h = await attached(null); let changed = false;
    const stop = h.controller.subscribe(() => { if (h.state.pending && !changed) { changed = true; change(h); } });
    h.controller.checkRunners(); stop(); assert.equal(h.count('runner-check'), 0); assert.equal(h.state.pending, false); h.controller.dispose();
  }
  const h = await attached(null); h.controller.checkRunners(); h.last('runner-check').reject(new Error('INERT lost response')); await flush();
  h.retain(idle(1, null)); await h.controller.checkStatus(); assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true);
  h.controller.checkRunners(); assert.equal(h.count('runner-check'), 1);
  const changed = clone(h.local); changed.sourceChanged = true; h.changeProject(changed); await h.controller.connect(null); assert.equal(h.detached, 0);
  h.emit({ ...operation('runner-check', 'running', 2), runner: null }); h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: 'runner-check-ticket' });
  h.respond('cancel', { ...operation('runner-check', 'settled', 3, 'cancelled'), runner: refusedRunners('cancelled') }); await flush();
  assert.equal(h.state.pending, false); assert.equal(h.detached, 1); assert.equal(h.count('apply'), 0); h.controller.dispose();
});

test('native runner expiry clears consent and cannot renew safe facts on the same original', async () => {
  const h = await ready(); h.controller.setConfirmed(true);
  const expired = { ...review(4), prepared: null, runner: { ...safeRunners(), result: 'expired', reason: 'expired' } };
  h.emit(expired); assert.equal(h.controller.currentPrepared(), null); assert.equal(h.state.confirmed, false);
  assert.match(h.controller.prepareReason(), /expired/u); assert.match(h.controller.applyReason(), /expired/u);
  h.controller.apply(); assert.equal(h.count('apply'), 0); assert.equal(h.controller.startReason(), null);
  h.emit(review(5)); assert.equal(h.state.error, 'response-invalid'); assert.equal(h.state.uncertain, true); h.controller.dispose();
});

test('a synchronous malformed status latches failure before runner, Prepare or Apply invocation', async () => {
  for (const kind of ['runner-check', 'prepare', 'apply']) {
    const h = kind === 'apply' ? await ready() : await attached(kind === 'runner-check' ? null : safeRunners());
    if (kind === 'prepare') choose(h);
    if (kind === 'apply') h.controller.setConfirmed(true);
    const accepted = h.state.status;
    let notified = false;
    const off = h.controller.subscribe(() => {
      if (h.state.pending && !notified) { notified = true; h.emit({ schemaVersion: 1 }); }
    });
    const start = () => kind === 'runner-check' ? h.controller.checkRunners() : h.controller[kind]();
    start(); off();
    assert.equal(notified, true); assert.equal(h.count(kind), 0, kind);
    assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, true);
    assert.equal(h.state.error, 'response-invalid'); assert.equal(h.state.status, accepted);
    start(); assert.equal(h.count(kind), 0); h.controller.dispose(); assert.equal(h.detached, 1);
  }
});

test('runner facts cannot disappear, resurrect or renew under an unrelated original', async () => {
  const renewed = { ...safeRunners(), checkedAt: '2026-09-28T10:00:01Z', expiresAt: '2026-09-28T10:02:01Z', runnerCount: 1 };
  const without = (runner) => ({ ...review(3), prepared: null, runner });
  const unrelated = { ...operation('pending', 'settled', 4), runner: renewed };
  const cases = [
    [review(3), { ...without(null), revision: 4 }],
    [without(null), review(4)],
    [without(refusedRunners()), review(4)],
    [review(3), unrelated],
    [without(refusedRunners()), { ...unrelated, runner: safeRunners() }],
  ];
  for (const [before, after] of cases) {
    assert.ok(parseGitHubInputGroupStatus(before)); assert.ok(parseGitHubInputGroupStatus(after));
    const h = harness(); h.retain(before); await h.controller.connect(h.api);
    const accepted = h.state.status; h.emit(after);
    assert.equal(h.state.uncertain, true); assert.equal(h.state.error, 'response-invalid');
    assert.equal(h.state.status, accepted); assert.equal(h.controller.currentPrepared(), null);
    h.controller.checkRunners(); assert.equal(h.count('runner-check'), 0); h.controller.dispose();
  }
  // A genuinely fresh original may clear the old facts and settle new ones.
  // Initial null -> same-original settlement also remains covered above.
  const h = await attached();
  h.emit({ ...operation('runner-check', 'running', 2), runner: null });
  assert.equal(h.state.uncertain, false); assert.equal(h.state.status.runner, null);
  h.emit({ ...operation('runner-check', 'settled', 3), runner: renewed });
  assert.equal(h.state.uncertain, false); assert.deepEqual(h.state.status.runner, renewed);
  h.emit({ ...operation('pending', 'settled', 4), runner: { ...renewed, result: 'expired', reason: 'expired' } });
  assert.equal(h.state.uncertain, false); assert.equal(h.state.status.runner.result, 'expired');
  h.controller.dispose();
});
