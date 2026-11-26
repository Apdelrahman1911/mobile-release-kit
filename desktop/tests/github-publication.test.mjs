// Inert DATA and fake original IPC only. No token, network, Git, native owner or journal.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import mainCapability from '../src-tauri/capabilities/main.json' with { type: 'json' };
import { GitHubPublicationController, githubPublicationOwnerReason } from '../src/githubPublicationController.ts';
import { PUBLICATION_CONFIRMATION, PUBLICATION_PATHS, PUBLICATION_PROTOCOL, parsePublicationStatus, publicationError, publicationRequestFits } from '../src/githubPublicationProtocol.ts';
const clone = structuredClone, marker = 'd'.repeat(32), consentId = 'e'.repeat(32);
function connection() { return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'owner/app' }, status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'owner/app', state: 'connected' }, account: { state: 'observed', value: { id: '11' } }, repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } }, busy: null, uncertain: false, blocked: false, retirementPending: false }; }
function prepared() { return { protocol: PUBLICATION_PROTOCOL, target: { projectBinding: 'b'.repeat(64), repository: 'owner/app', accountId: '11', repositoryId: '22', base: 'release/setup', toolingRepository: 'Apdelrahman1911/mobile-release-kit', toolingSha: 'c'.repeat(40), marker }, baseCommit: 'a'.repeat(40), baseTree: 'b'.repeat(40), desiredTree: 'c'.repeat(40), files: PUBLICATION_PATHS.map((path, i) => ({ path, before: i ? null : '{"old":"inert"}\n', after: i ? 'inert caller\n' : '{"new":"inert"}\n' })), head: `mrk/setup-${marker}`, confirmation: PUBLICATION_CONFIRMATION }; }
function pending() { const p = prepared(); delete p.head; delete p.confirmation; p.files = p.files.map((f) => ({ path: f.path, before: f.before === null ? null : { bytes: 16, sha256: 'a'.repeat(64) }, after: { bytes: 16, sha256: 'b'.repeat(64) } })); return { summary: p, claimed: ['tree', 'commit', 'branch', 'pull'], confirmed: { tree: p.desiredTree, commit: 'f'.repeat(40), branch: 'f'.repeat(40) } }; }
function idle(revision = 1) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, consent: null, pending: [], pull: null }; }
function operation(kind, phase, revision, reason = 'none', effect = kind === 'publish' ? 'not-sent' : 'none') { return { ...idle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy', operation: { id: `${kind}-a`, kind, phase, reason, effect } }; }
function review(revision = 3) { return { ...operation('prepare', 'settled', revision), consent: { id: consentId, expiresAt: '2026-10-16T15:02:00Z', prepared: prepared() } }; }
function draftResult(revision = 5, kind = 'publish') { return { ...operation(kind, 'settled', revision, 'none', 'draft-pr-observed'), pull: { number: '99', url: 'https://github.com/owner/app/pull/99', commit: 'f'.repeat(40) } }; }
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let n = 0; n < 16; n++) await Promise.resolve(); }
function harness() { let current = idle(), view = connection(), listener = null, detached = 0; const calls = [];
  const request = (kind, args) => { const d = deferred(); calls.push({ kind, args: clone(args), ...d }); return d.promise; };
  const api = { mode: 'native', githubPublicationStatus: async () => { calls.push({ kind: 'status' }); return clone(current); }, subscribeGitHubPublication: async (fn) => { listener = fn; return () => { listener = null; detached++; }; },
    githubPublicationPrepare: (args) => request('prepare', args), githubPublicationPublish: (args) => request('publish', args), githubPublicationPending: (args) => request('pending', args), githubPublicationReconcile: (args) => request('reconcile', args), githubPublicationDiscard: (args) => request('discard', args), githubPublicationCancel: (args) => request('cancel', args) };
  const controller = new GitHubPublicationController(() => view);
  return { api, controller, calls, get state() { return controller.getSnapshot(); }, get detached() { return detached; }, count: (kind) => calls.filter((c) => c.kind === kind).length, last: (kind) => calls.filter((c) => c.kind === kind).at(-1), emit(s) { current = clone(s); listener?.(clone(s)); }, retain(s) { current = clone(s); }, respond(kind, s) { current = clone(s); this.last(kind).resolve(clone(s)); }, context(v) { view = v; controller.syncContext(); } };
}
async function attached() { const h = harness(); await h.controller.connect(h.api); h.controller.setBase('release/setup'); return h; }
async function ready() { const h = await attached(); h.controller.prepare(); h.respond('prepare', review()); await flush(); assert.ok(h.controller.currentConsent()); return h; }

test('closed finite review/pending parser preserves exact five files and rejects forged scope, phase prefixes and positive effects', () => {
  for (const s of [idle(), review(), draftResult(), operation('reconcile', 'settled', 5, 'unresolved', 'branch-observed'), { ...operation('pending', 'settled', 3), pending: [pending()] }]) assert.ok(parsePublicationStatus(s));
  for (const mutate of [(s) => s.consent.prepared.files.push(clone(s.consent.prepared.files[0])), (s) => s.consent.prepared.files[1].path = '.github/workflows/other.yml', (s) => s.consent.prepared.files[0].after = 'a'.repeat(65537), (s) => s.consent.prepared.target.root = '/not-authority', (s) => s.consent.prepared.confirmation += 'skip review', (s) => s.consent.prepared.head = 'main', (s) => s.consent.prepared.target.marker = 'x'.repeat(32), (s) => s.consent.prepared.files[0].before = '', (s) => s.consent.prepared.target = Object.values(s.consent.prepared.target)]) { const s = review(); mutate(s); assert.equal(parsePublicationStatus(s), null); }
  const p = { ...operation('pending', 'settled', 3), pending: [pending()] }; p.pending[0].claimed = ['commit']; assert.equal(parsePublicationStatus(p), null);
  const q = { ...operation('pending', 'settled', 3), pending: [pending(), pending()] }; assert.equal(parsePublicationStatus(q), null);
  for (const mutate of [(s) => s.pull.url = 'https://evil.invalid/pull/99', (s) => s.operation.phase = 'running', (s) => s.operation.reason = 'unresolved', (s) => s.pull = null]) { const s = draftResult(); mutate(s); assert.equal(parsePublicationStatus(s), null); }
  let reads = 0; const getter = idle(); Object.defineProperty(getter, 'consent', { enumerable: true, get() { reads++; return null; } }); assert.equal(parsePublicationStatus(getter), null); assert.equal(reads, 0);
});

test('closed commands reject renderer authority, false consent and raw error disclosure', async () => {
  const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, base: 'release/setup' };
  assert.equal(publicationRequestFits('github_setup_publication_prepare', args), true);
  for (const name of ['root', 'token', 'prepared', 'toolingSha', 'home', 'url', 'force', 'files']) assert.equal(publicationRequestFits('github_setup_publication_prepare', { ...args, [name]: 'INERT' }), false);
  for (const base of ['refs/heads/main', '-main', 'main.lock', 'a/../b', 'main\n']) assert.equal(publicationRequestFits('github_setup_publication_prepare', { ...args, base }), false);
  assert.equal(publicationRequestFits('github_setup_publication_publish', { sessionId: 'session-a', expectedRevision: 3, consentId, confirm: false }), false);
  assert.equal(publicationError({ code: 'github_setup_publication_refused_busy' }).admission, 'not-admitted');
  assert.equal(publicationError({ code: 'INERT_PRIVATE', admission: 'not-admitted', message: 'INERT_PRIVATE' }).admission, 'unknown');
  assert.equal(JSON.stringify(publicationError({ code: 'INERT_PRIVATE' })).includes('INERT_PRIVATE'), false);
  let invoked = 0; const api = createNativeApi('native', async () => { invoked++; return idle(); }, async () => () => {});
  await assert.rejects(api.githubPublicationPrepare({ ...args, token: 'INERT_PRIVATE' })); assert.equal(invoked, 0);
  await assert.rejects(previewApi.githubPublicationPending(args)); assert.equal(invoked, 0);
});

test('exact original review needs explicit one-use confirmation, publishes no renderer files or credentials', async () => {
  const h = await ready(); assert.equal(h.controller.getSnapshot().confirmed, false); h.controller.publish(); assert.equal(h.count('publish'), 0);
  h.controller.setConfirmed(true); h.controller.publish(); h.controller.publish(); assert.equal(h.count('publish'), 1);
  assert.deepEqual(h.last('publish').args, { sessionId: 'session-a', expectedRevision: 3, consentId, confirm: true });
  assert.equal(h.controller.currentConsent(), null); assert.ok(githubPublicationOwnerReason(h.state));
  h.respond('publish', draftResult()); await flush(); assert.equal(h.state.uncertain, false); assert.equal(h.state.pending, false); assert.equal(h.state.status.pull.number, '99');
  h.controller.setConfirmed(true); h.controller.publish(); assert.equal(h.count('publish'), 1);
});

test('failed unchanged workspace intent retires the review and exact native discard before new work', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.beforeWorkspaceAction(); assert.equal(h.controller.currentConsent(), null); assert.equal(h.state.confirmed, false); assert.equal(h.count('discard'), 1);
  h.controller.publish(); assert.equal(h.count('publish'), 0); assert.ok(githubPublicationOwnerReason(h.state));
  h.respond('discard', operation('prepare', 'settled', 4)); await flush(); assert.equal(githubPublicationOwnerReason(h.state), null);
});

test('unknown publish acknowledgement never retries, status observes original settlement then pending/reconcile are read-only commands', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.publish(); h.last('publish').reject({ code: 'INERT_FAILURE' }); await flush();
  assert.equal(h.state.uncertain, true); h.controller.publish(); assert.equal(h.count('publish'), 1);
  h.retain(operation('publish', 'settled', 5, 'unresolved', 'potentially-applied')); await h.controller.checkStatus(); assert.equal(h.state.uncertain, false); assert.equal(h.state.pending, false);
  h.controller.loadPending(); assert.equal(h.count('pending'), 1); h.respond('pending', { ...operation('pending', 'settled', 7), pending: [pending()] }); await flush();
  h.controller.reconcile('0'.repeat(32)); assert.equal(h.count('reconcile'), 0); h.controller.reconcile(marker); assert.equal(h.count('reconcile'), 1);
  assert.deepEqual(h.last('reconcile').args, { sessionId: 'session-a', expectedRevision: 7, marker });
  h.respond('reconcile', draftResult(9, 'reconcile')); await flush(); assert.equal(h.state.status.pull.number, '99'); assert.equal(h.count('publish'), 1);
});

test('context change before late prepare admission stops only original once and cannot inherit consent', async () => {
  const h = await attached(); h.controller.prepare(); const c = connection(); c.context.projectGeneration++; h.context(c);
  h.emit(operation('prepare', 'running', 2)); assert.equal(h.count('cancel'), 1); h.emit(operation('prepare', 'running', 2)); assert.equal(h.count('cancel'), 1);
  h.respond('prepare', review()); await flush(); assert.equal(h.controller.currentConsent(), null); assert.equal(h.count('discard'), 1);
  h.respond('cancel', operation('prepare', 'settled', 4)); h.respond('discard', operation('prepare', 'settled', 4)); await flush(); assert.equal(h.count('publish'), 0);
});

test('newer event before older reply preserves original progress; same revision conflict permanently refuses', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.publish(); h.emit(draftResult(5)); h.respond('publish', operation('publish', 'running', 4, 'none', 'potentially-applied')); await flush();
  assert.equal(h.state.status.revision, 5); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false);
  const conflict = draftResult(5); conflict.pull.number = '100'; conflict.pull.url = 'https://github.com/owner/app/pull/100'; h.emit(conflict); assert.equal(h.state.uncertain, true); assert.ok(githubPublicationOwnerReason(h.state));
});

test('cleanup unknown and wrong-repository positive reply never grant another send or misleading PR link', async () => {
  for (const wrongRepo of [false, true]) { const h = await ready(); h.controller.setConfirmed(true); h.controller.publish();
    const s = wrongRepo ? draftResult(5) : operation('publish', 'cleanup-unknown', 5, 'cleanup-unknown', 'potentially-applied'); if (wrongRepo) s.pull.url = 'https://github.com/other/app/pull/99';
    h.respond('publish', s); await flush(); assert.equal(h.state.uncertain, true); assert.equal(h.state.status.pull, null); h.controller.publish(); h.controller.loadPending(); assert.equal(h.count('publish'), 1); assert.equal(h.count('pending'), 0);
  }
});

test('service handoff retains original observer until settlement, never adopts a late review into new service', async () => {
  const h = await attached(); h.controller.prepare(); await h.controller.connect(null); assert.equal(h.detached, 0); h.emit(review()); await flush(); assert.equal(h.controller.currentConsent(), null); assert.equal(h.count('discard'), 0);
  assert.equal(h.state.pending, true); h.respond('prepare', review()); await flush(); assert.equal(h.count('discard'), 1);
  h.respond('discard', operation('prepare', 'settled', 4)); await flush(); assert.equal(h.detached, 1); assert.equal(h.count('publish'), 0);
});


test('actual main-local capability grants exactly the seven emitted publication commands without remote or event-write authority', async () => {
  const emitted = [];
  const api = createNativeApi('native', async (command, args) => { emitted.push([command, args]); return idle(); }, async () => () => {});
  await api.githubPublicationStatus();
  await api.githubPublicationPrepare({ sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, base: 'release/setup' });
  await api.githubPublicationPublish({ sessionId: 'session-a', expectedRevision: 1, consentId, confirm: true });
  await api.githubPublicationPending({ sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12 });
  await api.githubPublicationReconcile({ sessionId: 'session-a', expectedRevision: 1, marker });
  await api.githubPublicationDiscard({ sessionId: 'session-a', expectedRevision: 1, consentId });
  await api.githubPublicationCancel('original-1');
  const permitted = mainCapability.permissions.filter((p) => typeof p === 'string' && p.startsWith('allow-github-setup-publication-'));
  assert.equal(emitted.length, 7); assert.equal(new Set(emitted.map(([command]) => command)).size, 7);
  assert.deepEqual(new Set(permitted), new Set(emitted.map(([command]) => 'allow-' + command.replaceAll('_', '-'))));
  assert.equal(permitted.length, 7); assert.deepEqual(mainCapability.windows, ['main']); assert.equal(mainCapability.local, true);
  assert.equal(Object.hasOwn(mainCapability, 'remote'), false);
  assert.equal(mainCapability.permissions.some((p) => typeof p !== 'string' || p.includes('*') || /event:allow-emit|http:|shell:|opener:/.test(p)), false);
  // tauri-build generates the actual allow declarations from build.rs COMMANDS;
  // the subsequent desktop-shell build checks those declarations. This test
  // exercises actual bridge requests + ACL DATA, not native command execution.
});

// Shared only by the focused publication delegation tests; same original fake IPC.
export { connection, prepared, pending, idle, operation, review, draftResult, deferred, flush, harness, attached, ready, marker, consentId };
