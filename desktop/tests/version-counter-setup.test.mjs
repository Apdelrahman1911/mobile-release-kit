// Real controllers/codec, inert original IPC only. No GitHub/Store/native state,
// durability or protection claim is supplied by these finite fake ports.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { GitHubPublicationController, githubPublicationOwnerReason } from '../src/githubPublicationController.ts';
import { parsePublicationStatus, publicationRequestFits } from '../src/githubPublicationProtocol.ts';
import { COUNTER_PURPOSE, COUNTER_PROTOCOL, COUNTER_CONFIRMATION, COUNTER_BRANCH, COUNTER_PATH, captureCounterSaved, counterPrepared, sameCounterSaved } from '../src/versionCounterSetup.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
const clone = structuredClone, marker = 'd'.repeat(32), consentId = 'e'.repeat(32), ledgerId = '12345678-1234-4234-8234-123456789abc';
const fingerprint = { bytes: 100, sha256: 'a'.repeat(64) }, source = 'release/version.properties';
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false, gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const hash = (s) => createHash('sha256').update(s).digest('hex');
function prepared() {
  const target = { purpose: COUNTER_PURPOSE, projectBinding: 'b'.repeat(64), repository: 'owner/app', accountId: '11', repositoryId: '22', base: 'main', marker,
    projectId: 'c'.repeat(32), ledgerId, initialVersion: { name: '1.2.3', build: 42 }, savedConfig: clone(fingerprint), savedVersion: { path: source, bytes: 40, sha256: 'b'.repeat(64) } };
  const genesis = { branch: COUNTER_BRANCH, initialVersion: { build: 42, name: '1.2.3' }, ledgerId, path: COUNTER_PATH, projectId: target.projectId, repositoryId: target.repositoryId };
  const ledger = JSON.stringify({ genesis, protocol: 'mrk-version-allocation/1', reservations: [], schemaVersion: 1 }) + '\n';
  return { protocol: COUNTER_PROTOCOL, target, baseCommit: '1'.repeat(40), baseTree: '2'.repeat(40), desiredTree: '3'.repeat(40), ledgerBlob: '4'.repeat(40),
    genesisSha256: hash('mrk:allocation-genesis:1\0' + JSON.stringify(genesis)), ledger, head: COUNTER_BRANCH, confirmation: COUNTER_CONFIRMATION };
}
function pending() { const r = prepared(); delete r.head; delete r.confirmation; r.ledger = { bytes: Buffer.byteLength(r.ledger), sha256: hash(r.ledger) };
  return { summary: r, claimed: ['tree', 'commit', 'branch'], confirmed: { tree: r.desiredTree, commit: '5'.repeat(40) } }; }
function connection() { return { mode: 'native', context: { documentId: 'doc-a', projectId: 'p1', projectGeneration: 1, repository: 'owner/app' }, status: { revision: 12, session: { id: 'session-a', projectId: 'p1', targetRepository: 'owner/app', state: 'connected' }, account: { state: 'observed', value: { id: '11' } }, repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } }, busy: null, uncertain: false, blocked: false, retirementPending: false }; }
function idle(revision = 1) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, consent: null, pending: [], pull: null }; }
function operation(kind, phase, revision, reason = 'none', effect = kind === 'publish' ? 'not-sent' : 'none') {
  return { ...idle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
    operation: { id: `${kind}-counter`, kind, phase, reason, effect, ...(kind === 'pending' ? {} : { purpose: COUNTER_PURPOSE }) } };
}
function review(revision = 3) { return { ...operation('prepare', 'settled', revision), consent: { id: consentId, expiresAt: '2026-10-21T15:02:00Z', prepared: prepared() } }; }
function observed(revision = 5, kind = 'publish') { return { ...operation(kind, 'settled', revision, 'none', 'counter-observed'), counter: { commit: '5'.repeat(40), ledgerId, genesisSha256: prepared().genesisSha256 } }; }
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let i = 0; i < 16; i++) await Promise.resolve(); }
async function savedFixture() {
  const snapshot = { root: '/inert/never-opened', observedAt: '', observationScope: 'single-request-non-atomic', config: { path: 'release/mobile-release.json', state: 'format-valid', content: clone(fingerprint), issues: [], data: { android: { enabled: true }, version: { source } } }, discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} }, assurance: clone(assurance), issues: [] };
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Counter fixture', path: snapshot.root } });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: 'p1', requestId: 1 });
  workspace = workspaceReducer(workspace, { type: 'snapshot-done', projectId: 'p1', requestId: 1, snapshot, observedAt: 1 });
  let session = workspace.projects.p1;
  const version = new ReleaseVersionController(() => session);
  const observation = { schemaVersion: 2, source, version: { name: '1.2.3', build: 42 }, savedConfig: clone(fingerprint), savedVersion: { bytes: 40, sha256: 'b'.repeat(64) }, observationScope: 'single-request-non-atomic', assurance: clone(assurance) };
  version.setConnection({ mode: 'native', observeReleaseVersion: async () => clone(observation) }, { runtime: { state: 'available', mode: 'installed', reason: null }, capabilities: { methods: [{ method: 'release.version.observe', available: true, reason: '' }] } });
  version.syncProject(); await version.read();
  return { version, get session() { return session; }, set session(s) { session = s; }, source: () => captureCounterSaved(session, version.getSnapshot()) };
}
async function fixture(t) {
  const saved = await savedFixture(); t.after(() => saved.version.dispose());
  let current = idle(), view = connection(), listener = null, detached = 0, readGate = null, peer = null;
  const calls = [], request = (kind, args) => { const d = deferred(); calls.push({ kind, args: clone(args), ...d }); return d.promise; };
  const api = { mode: 'native', githubPublicationStatus: () => { calls.push({ kind: 'status' }); return readGate ? readGate.promise : Promise.resolve(clone(current)); },
    subscribeGitHubPublication: async (f) => { listener = f; return () => { listener = null; detached++; }; },
    githubPublicationPrepare: (a) => request('prepare', a), githubPublicationPublish: (a) => request('publish', a), githubPublicationPending: (a) => request('pending', a),
    githubPublicationReconcile: (a) => request('reconcile', a), githubPublicationDiscard: (a) => request('discard', a), githubPublicationCancel: (a) => request('cancel', a) };
  const controller = new GitHubPublicationController(() => view, () => peer, saved.source);
  await controller.connect(api); controller.setPurpose(COUNTER_PURPOSE); controller.setBase('main');
  return { api, controller, calls, saved, get state() { return controller.getSnapshot(); }, get detached() { return detached; }, count: (k) => calls.filter((c) => c.kind === k).length, last: (k) => calls.filter((c) => c.kind === k).at(-1),
    emit(s) { current = clone(s); listener?.(clone(s)); }, retain(s) { current = clone(s); }, respond(k, s) { current = clone(s); this.last(k).resolve(clone(s)); },
    context(c) { view = c; controller.syncContext(); }, peer(p) { peer = p; }, deferRead() { readGate = deferred(); return readGate; }, finishRead() { readGate = null; } };
}
async function ready(t) { const h = await fixture(t); assert.equal(h.controller.prepareReason(), null); h.controller.prepare(); h.respond('prepare', review()); await flush(); assert.ok(h.controller.currentConsent()); return h; }

test('counter DTO is exact, numeric/canonical and cannot promote creation into protection, allocation or Store proof', () => {
  assert.ok(counterPrepared(prepared())); assert.ok(parsePublicationStatus(review())); assert.ok(parsePublicationStatus(observed()));
  assert.ok(parsePublicationStatus({ ...operation('pending', 'settled', 3), pending: [pending()] }));
  for (const change of [s => s.consent.prepared.target.projectId = null, s => delete s.consent.prepared.target.projectId,
    s => s.consent.prepared.target.initialVersion.name = '1.02.3', s => s.consent.prepared.target.base = COUNTER_BRANCH,
    s => s.consent.prepared.target.savedVersion.path = 'private/version', s => s.consent.prepared.ledger += '\n',
    s => s.consent.prepared.ledger = s.consent.prepared.ledger.replace('"reservations":[]', '"reservations":[{}]'),
    s => s.consent.prepared.confirmation += ' silently approve', s => delete s.operation.purpose]) { const s = review(); change(s); assert.equal(parsePublicationStatus(s), null); }
  for (const change of [s => s.counter.protected = true, s => s.counter = null, s => s.operation.phase = 'running', s => s.operation.reason = 'unresolved',
    s => delete s.operation.purpose, s => s.operation.purpose = 'setup-pr', s => s.operation.kind = 'prepare', s => s.pull = { number: '1', url: 'https://github.com/owner/app/pull/1', commit: '5'.repeat(40) }]) { const s = observed(); change(s); assert.equal(parsePublicationStatus(s), null); }
  const p = pending(); p.claimed.push('pull'); assert.equal(parsePublicationStatus({ ...operation('pending', 'settled', 3), pending: [p] }), null);
  let reads = 0; const v = prepared(); Object.defineProperty(v, 'target', { enumerable: true, get() { reads++; return {}; } }); assert.equal(counterPrepared(v), false); assert.equal(reads, 0);
});
test('same seven commands carry only optional purpose; arbitrary initial version, identity, state and paths never cross renderer IPC', async () => {
  const a = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, base: 'main', purpose: COUNTER_PURPOSE };
  assert.equal(publicationRequestFits('github_setup_publication_prepare', a), true);
  for (const field of ['projectId', 'ledgerId', 'initialVersion', 'prepared', 'source', 'home', 'token', 'protection']) assert.equal(publicationRequestFits('github_setup_publication_prepare', { ...a, [field]: 'INERT' }), false);
  for (const purpose of [null, 'setup-pr', 'reset-counter']) assert.equal(publicationRequestFits('github_setup_publication_prepare', { ...a, purpose }), false);
  assert.equal(publicationRequestFits('github_setup_publication_prepare', null), false);
  const calls = [], api = createNativeApi('native', async (cmd, args) => { calls.push([cmd, args]); return idle(); }, async () => () => {});
  await api.githubPublicationPrepare(a); assert.equal(calls[0][0], 'github_setup_publication_prepare'); assert.deepEqual(calls[0][1], a);
  await assert.rejects(api.githubPublicationPrepare({ ...a, initialVersion: 0 })); await assert.rejects(previewApi.githubPublicationPrepare(a)); assert.equal(calls.length, 1);
});
test('saved-input helper requires actual current complete read but no build tools or Store credentials', async (t) => {
  const h = await fixture(t), a = h.saved.source(); assert.ok(a);
  assert.equal(sameCounterSaved(a, h.saved.source()), true);
  for (const change of [s => s.sourceChanged = true, s => s.snapshotRequest = 2, s => s.saveRecoveryNeedsReload = true, s => s.snapshotPredatesSave = true]) {
    const s = clone(h.saved.session); change(s); assert.equal(captureCounterSaved(s, h.saved.version.getSnapshot()), null);
  }
  for (const change of [v => v.result.savedConfig.sha256 = 'f'.repeat(64), v => v.resultBinding.readEpoch++, v => v.result.version.name = 'custom-alpha', v => v.stale = true]) {
    const v = clone(h.saved.version.getSnapshot()); change(v); assert.equal(captureCounterSaved(h.saved.session, v), null);
  }
  await h.saved.version.read(); assert.equal(sameCounterSaved(a, h.saved.source()), false); // same bytes, different real read epoch/original
});
test('returned original review and separate unchecked consent permit exactly one Create; no automatic enroll or refresh', async (t) => {
  const h = await ready(t); assert.equal(h.state.confirmed, false); h.controller.publish(); assert.equal(h.count('publish'), 0);
  h.controller.setConfirmed(true); h.controller.publish(); h.controller.publish(); assert.equal(h.count('publish'), 1);
  assert.deepEqual(h.last('publish').args, { sessionId: 'session-a', expectedRevision: 3, consentId, confirm: true });
  h.respond('publish', observed()); await flush(); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false); assert.ok(h.state.status.counter);
  h.controller.publish(); assert.equal(h.count('publish'), 1); assert.deepEqual(h.calls.map(c => c.kind), ['status', 'prepare', 'publish']);
});
test('terminal event and earlier Status cannot retire the still-pending original Prepare call', async (t) => {
  const h = await fixture(t); h.controller.prepare(); h.emit(review()); await h.controller.checkStatus();
  assert.equal(h.state.pending, true); assert.equal(h.controller.currentConsent(), null); assert.equal(h.count('discard'), 0); assert.ok(githubPublicationOwnerReason(h.state));
  h.respond('prepare', operation('prepare', 'running', 2)); await flush(); assert.equal(h.state.pending, false); assert.ok(h.controller.currentConsent());
});
test('lost Create ACK requires a fresh post-return Status, not a prior read or later event; never a second Create', async (t) => {
  const h = await ready(t); h.controller.setConfirmed(true); h.controller.publish();
  const r = h.deferRead(), read = h.controller.checkStatus(); await flush();
  h.last('publish').reject(new Error('INERT lost ACK')); await flush(); h.emit(observed()); r.resolve(observed()); await read; h.finishRead();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); h.controller.publish(); assert.equal(h.count('publish'), 1);
  await h.controller.checkStatus(); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false); assert.equal(h.count('publish'), 1);
});
test('explicit family/source ABA retires old review and never auto-prepares new target', async (t) => {
  for (const action of ['purpose', 'source']) { const h = await ready(t); h.controller.setConfirmed(true);
    if (action === 'purpose') { h.controller.setPurpose('setup-pr'); h.controller.setPurpose(COUNTER_PURPOSE); }
    else { h.controller.versionIntent(); await h.saved.version.read(); h.controller.syncCounterSource(); }
    assert.equal(h.controller.currentConsent(), null); assert.equal(h.state.confirmed, false); assert.equal(h.count('discard'), 1); h.controller.publish(); assert.equal(h.count('publish'), 0);
    h.respond('discard', operation('prepare', 'settled', 4)); await flush(); assert.equal(h.count('prepare'), 1);
  }
});
test('reentrant source, account and peer changes prevent initial dispatch or same review reuse', async (t) => {
  for (const change of ['source', 'account', 'peer']) { const h = await fixture(t); let once = false;
    h.controller.subscribe(() => { if (once || !h.state.pending) return; once = true;
      if (change === 'source') h.controller.versionIntent();
      else if (change === 'account') { const c = connection(); c.status.account.value.id = '99'; h.context(c); }
      else h.peer('another original'); });
    h.controller.prepare(); assert.equal(h.count('prepare'), 0); assert.equal(h.state.pending, false);
  }
});
test('service handoff retains event-settled original until actual call and discard return, never adopts its consent', async (t) => {
  const h = await fixture(t); h.controller.prepare(); await h.controller.connect(null); h.emit(review()); await flush();
  assert.equal(h.detached, 0); assert.equal(h.count('discard'), 0); assert.equal(h.controller.currentConsent(), null);
  h.respond('prepare', review()); await flush(); assert.equal(h.count('discard'), 1); assert.equal(h.detached, 0);
  h.respond('discard', operation('prepare', 'settled', 4)); await flush(); assert.equal(h.detached, 1); assert.equal(h.count('publish'), 0);
});
test('foreign ledger positive or original cleanup-unknown stays blocked even after a later success offer', async (t) => {
  for (const wrong of [false, true]) { const h = await ready(t); h.controller.setConfirmed(true); h.controller.publish();
    const v = wrong ? observed() : operation('publish', 'cleanup-unknown', 5, 'cleanup-unknown', 'potentially-applied'); if (wrong) v.counter.ledgerId = 'abcdefab-1234-4234-8234-123456789abc';
    h.respond('publish', v); await flush(); assert.equal(h.state.uncertain, true); assert.equal(h.state.status.counter, undefined);
    h.emit(observed(6)); h.controller.publish(); h.controller.loadPending(); assert.equal(h.count('publish'), 1); assert.equal(h.count('pending'), 0);
  }
});
test('original counter pending row is reconciled read-only with its own target, never another send', async (t) => {
  const h = await fixture(t); h.controller.loadPending(); h.respond('pending', { ...operation('pending', 'settled', 3), pending: [pending()] }); await flush();
  h.controller.reconcile('0'.repeat(32)); assert.equal(h.count('reconcile'), 0); h.controller.reconcile(marker); assert.equal(h.count('reconcile'), 1);
  h.respond('reconcile', observed(5, 'reconcile')); await flush(); assert.equal(h.state.pending, false); assert.ok(h.state.status.counter); assert.equal(h.count('publish'), 0);
});
test('actual component has only explicit existing-owner actions and honest manual-protection boundary', () => {
  const ui = readFileSync(new URL('../src/components/VersionCounterSetup.tsx', import.meta.url), 'utf8');
  assert.match(ui, /not a verified Store floor/); assert.match(ui, /Protection and connection are still required/); assert.match(ui, /enforce administrators/);
  assert.match(ui, /CounterSetup|VersionCounterSetup/); assert.doesNotMatch(ui, /useEffect|fetch\(|\.enroll\(|\.connect\(|\.allocate\(|\.start\(/);
});
