// Inert DTO + fake IPC promises; no GitHub, native provider, process or Store.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { GitHubHistoryController, githubHistoryOwnerReason } from '../src/githubHistoryController.ts';
import { GITHUB_HISTORY_ASSURANCE, GITHUB_HISTORY_EVENT, GITHUB_HISTORY_REASONS,
  githubHistoryError, githubHistoryRequestFits, parseGitHubHistoryResult, parseGitHubHistoryStatus } from '../src/githubHistoryProtocol.ts';
import { candidateDownloadEffect, candidateDownloadExported, candidateDownloadNames, candidateDownloadProgress, GITHUB_CANDIDATE_DOWNLOAD_CONSENT } from '../src/githubCandidateDownload.ts';
const clone = (v) => structuredClone(v);
const selection = () => ({ runId: '123', attempt: 2, stage: 'candidate', platform: 'android' });
const saved = () => ({ bytes: 200, sha256: 'c'.repeat(64) });
function result(selected = selection()) {
  const authority = { workflow: 'External testing', callerPath: `.github/workflows/mobile-${selected.stage}.yml`,
    reusableRepository: 'Apdelrahman1911/mobile-release-kit', reusablePath: `.github/workflows/reusable-${selected.stage}.yml`,
    reusableCommit: 'a'.repeat(40), runId: selected.runId, attempt: selected.attempt, headSha: 'b'.repeat(40), ref: 'refs/heads/main', event: 'workflow_dispatch' };
  const stage = selected.stage === 'external-testing' ? 'external' : selected.stage === 'production-submit' ? 'production' : 'candidate';
  return { schemaVersion: 1, context: { schemaVersion: 1, projectBinding: 'd'.repeat(64), configSha256: saved().sha256,
    repository: 'owner/app', repositoryId: '22', accountId: '11', toolingRepository: 'Apdelrahman1911/mobile-release-kit', toolingSha: 'a'.repeat(40), selection: clone(selected) },
    observedAt: '2026-10-09T12:00:00.123456Z', verification: 'verified', reason: 'none', assurance: GITHUB_HISTORY_ASSURANCE,
    evidence: { artifactId: '44', artifactSha256: 'e'.repeat(64), artifactName: `mobile-release-${stage}-evidence-${selected.platform}`, producerJobId: '55',
      producedBy: clone(authority), authorizedBy: { ...authority, runId: '100', attempt: 1 },
      candidateSource: { commit: 'f'.repeat(40), tree: '1'.repeat(40) }, operationSource: { commit: '2'.repeat(40), tree: '3'.repeat(40) },
      version: { name: '1.2.3', build: 40 }, applicationId: 'app.example', outcome: 'reconciled',
      candidateManifestSha256: '4'.repeat(64), operationIntentSha256: '5'.repeat(64), receiptSha256: '6'.repeat(64), provenanceSha256: '7'.repeat(64) } };
}
function idle(revision = 1) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, result: null }; }
function status(phase, revision, options = {}) {
  const opReason = phase === 'stopping' ? 'cancelled' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : options.reason ?? 'none';
  return { ...idle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
    operation: { id: options.id ?? 'read-a', phase, reason: opReason, selection: clone(options.selection ?? selection()) },
    result: phase === 'settled' && opReason === 'none' ? clone(options.result ?? result(options.selection ?? selection())) : null };
}
function connection() {
  return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'owner/app' },
    status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'owner/app', state: 'connected' },
      account: { state: 'observed', value: { id: '11' } }, repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } },
    retirementPending: false, uncertain: false, blocked: false, busy: null };
}
function project() {
  return { project: { id: 'project-a' }, draft: { android: true }, baseline: { android: true }, revision: 1, baselineGeneration: 1,
    observationGeneration: 1, savedConfigContent: saved(), sourceChanged: false, snapshotPredatesSave: false, snapshotError: null,
    snapshotRequest: null, saveRecoveryRequired: false, saveRecoveryNeedsReload: false,
    validatedRevision: 1, validatedBaselineGeneration: 1, validation: { valid: true } };
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let n = 0; n < 12; n += 1) await Promise.resolve(); }
function harness(initial = idle()) {
  let current = clone(initial), cv = connection(), pv = project(), listener = null, detached = 0, peer = null;
  const calls = [];
  const request = (kind, args) => { const work = deferred(); calls.push({ kind, args: clone(args), ...work }); return work.promise; };
  const api = { mode: 'native', githubHistoryStatus: async () => { calls.push({ kind: 'status' }); return clone(current); },
    subscribeGitHubHistory: async (fn) => { calls.push({ kind: 'subscribe' }); listener = fn; return () => { listener = null; detached += 1; }; },
    startGitHubHistory: (args) => request('start', args), downloadGitHubCandidate: (args) => request('download', args), cancelGitHubHistory: (args) => request('cancel', args) };
  const controller = new GitHubHistoryController({ connection: () => cv, selectedProject: () => pv, otherOperationReason: () => peer });
  return { controller, api, calls, get state() { return controller.getSnapshot(); }, get detached() { return detached; },
    peer: (value) => { peer = value; },
    count: (kind) => calls.filter((v) => v.kind === kind).length, last: (kind) => calls.filter((v) => v.kind === kind).at(-1),
    emit: (v) => { current = clone(v); listener?.(clone(v)); }, raw: (v) => listener?.(v),
    respond: (kind, v) => { current = clone(v); calls.filter((c) => c.kind === kind).at(-1).resolve(clone(v)); },
    connection: (v) => { cv = v; controller.syncContext(); }, project: (v) => { pv = v; controller.syncContext(); } };
}
function select(h) { h.controller.setRunId('123'); h.controller.setAttempt('2'); h.controller.setStage('candidate'); h.controller.setPlatform('android'); }
async function ready(initial) { const h = harness(initial); await h.controller.connect(h.api); select(h); return h; }


function effect(patch = {}, selected = selection()) {
  const { relativePath, pendingPath } = candidateDownloadNames(selected);
  return { relativePath, pendingPath, publication: 'not-entered', durability: 'not-entered', closed: false, ...patch };
}
function downloaded(phase, revision, options = {}) {
  const out = status(phase, revision, options);
  out.operation.download = effect(options.effect, options.selection ?? selection());
  return out;
}
const published = () => ({ publication: 'published', durability: 'durable', closed: true });
const args = () => ({ sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12,
  selection: selection(), consentVersion: GITHUB_CANDIDATE_DOWNLOAD_CONSENT, confirmed: true });

test('candidate download is a distinct closed consent, never a path or old History read upgrade', () => {
  const a = args(); assert.ok(githubHistoryRequestFits('github_history_download_primary', a));
  const { consentVersion, confirmed, ...old } = a;
  assert.ok(githubHistoryRequestFits('github_history_start', old));
  assert.equal(githubHistoryRequestFits('github_history_start', a), false);
  assert.equal(githubHistoryRequestFits('github_history_download_primary', old), false);
  for (const patch of [{ consentVersion: 'read' }, { confirmed: false }, { confirmed: 1 }, { url: 'https://example.invalid' },
    { path: '/tmp/elsewhere' }, { overwrite: true }, { retry: true }, { artifactId: '44' }, { token: 'INERT' }])
    assert.equal(githubHistoryRequestFits('github_history_download_primary', { ...a, ...patch }), false);
  for (const stage of ['external-testing', 'production-submit']) {
    assert.equal(candidateDownloadNames({ ...selection(), stage }), null);
    assert.equal(githubHistoryRequestFits('github_history_download_primary', { ...a, selection: { ...selection(), stage } }), false);
  }
  assert.deepEqual(candidateDownloadNames({ ...selection(), platform: 'ios' }), {
    relativePath: 'release/downloads/candidate-123-attempt-2-ios', pendingPath: 'release/downloads/.candidate-123-attempt-2-ios.pending', primary: 'app.ipa',
  });
});

test('download diagnostics stay closed and cannot present unjoined publication as verified export', () => {
  assert.ok(candidateDownloadEffect(effect(), selection()));
  for (const patch of [{ relativePath: '/tmp/a' }, { pendingPath: 'release/downloads/other' }, { extra: 1 },
    { publication: 'entered', closed: true }, { publication: 'unknown', closed: true },
    { publication: 'not-entered', durability: 'durable' }, { publication: 'published', durability: 'unknown', closed: true }])
    assert.equal(candidateDownloadEffect(effect(patch), selection()), false);
  assert.ok(candidateDownloadProgress(effect(), effect({ publication: 'entered' })));
  assert.ok(candidateDownloadProgress(effect({ publication: 'entered' }), effect({ publication: 'published', durability: 'unknown' })));
  assert.equal(candidateDownloadProgress(effect({ publication: 'published', durability: 'unknown' }), effect(published())), false);
  assert.equal(candidateDownloadExported(effect({ publication: 'published', durability: 'durable' })), false);
  for (const patch of [{}, { publication: 'published', durability: 'durable' }, { publication: 'refused', closed: true }])
    assert.equal(parseGitHubHistoryStatus(downloaded('settled', 3, { effect: patch })), null);
  assert.ok(parseGitHubHistoryStatus(downloaded('settled', 3, { effect: published() })));
  const unavailable = result(); unavailable.verification = 'unavailable'; unavailable.reason = 'artifact-missing'; unavailable.evidence = null;
  assert.ok(parseGitHubHistoryStatus(downloaded('settled', 3, { result: unavailable, effect: { closed: true } })));
  assert.ok(parseGitHubHistoryStatus(status('settled', 3))); // unchanged old result shape
  const nullEffect = downloaded('running', 2); nullEffect.operation.download = null;
  assert.equal(parseGitHubHistoryStatus(nullEffect), null);
});

test('actual bridge requires original listener, copies closed download args and never falls back to old read', async () => {
  let calls = [];
  const absent = createNativeApi('native', async (command, data) => { calls.push([command, data]); return idle(); });
  await assert.rejects(absent.downloadGitHubCandidate(args()), (e) => e.admission === 'not-admitted' && e.reason === 'runtime-unavailable');
  assert.deepEqual(calls, []);
  const api = createNativeApi('native', async (command, data) => { calls.push([command, data]); return idle(); }, async () => () => {});
  const request = args(); await api.downloadGitHubCandidate(request);
  assert.equal(calls[0][0], 'github_history_download_primary'); assert.deepEqual(calls[0][1], request);
  assert.notEqual(calls[0][1], request); assert.notEqual(calls[0][1].selection, request.selection);
  await assert.rejects(api.downloadGitHubCandidate({ ...request, destination: 'INERT' }), (e) => e.admission === 'not-admitted');
  assert.equal(calls.length, 1);
});

test('download requires actual checkbox epoch and never revives consent across equal away/back data', async () => {
  const h = await ready(); assert.equal(h.count('download'), 0); assert.equal(h.controller.downloadReason(), null);
  const first = h.controller.downloadReview(); h.controller.downloadCandidate(false, first.scope);
  h.controller.downloadCandidate(true, {}); assert.equal(h.count('download'), 0);
  h.controller.setRunId('999'); h.controller.setRunId('123');
  h.controller.downloadCandidate(true, first.scope); assert.equal(h.count('download'), 0);
  const current = h.controller.downloadReview(); assert.notEqual(current.scope, first.scope);
  h.controller.downloadCandidate(true, current.scope); h.controller.downloadCandidate(true, current.scope);
  assert.equal(h.count('download'), 1); assert.equal(h.count('start'), 0); assert.deepEqual(h.last('download').args, args());
  h.respond('download', downloaded('settled', 3, { effect: published() })); await flush();
  assert.ok(h.controller.currentResult()); h.controller.dispose(); assert.equal(h.detached, 1);
});

test('reentrant listeners cannot change project, peer, epoch or API before raw download invocation', async () => {
  for (const mutate of [(h) => h.controller.beforeWorkspaceAction(), (h) => h.peer('another original'),
    (h) => { const p = project(); p.draft = { changed: true }; h.project(p); },
    (h) => { void h.controller.connect({ ...h.api }); }]) {
    const h = await ready(); let once = false; const scope = h.controller.downloadReview().scope;
    const stop = h.controller.subscribe(() => { if (!once && h.state.pending) { once = true; mutate(h); } });
    h.controller.downloadCandidate(true, scope); await flush(); stop(); assert.equal(h.count('download'), 0);
    assert.equal(h.state.pending, false); h.controller.dispose();
  }
});

test('download original rejects mode and context substitution, not merely matching run or result bytes', async () => {
  for (const substituted of [status('running', 2), downloaded('settled', 3, { effect: published(), result: {
    ...result(), context: { ...result().context, accountId: '99' },
  } })]) {
    const h = await ready(); h.controller.downloadCandidate(true, h.controller.downloadReview().scope);
    h.emit(substituted); assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentResult(), null);
    h.controller.downloadCandidate(true, h.controller.downloadReview().scope); assert.equal(h.count('download'), 1);
    h.last('download').reject({ code: 'unknown' }); await flush(); h.controller.dispose();
  }
  const old = await ready(); old.controller.start(); old.emit(downloaded('running', 2));
  assert.equal(old.state.uncertain, true); assert.equal(old.count('download'), 0); old.last('start').reject({}); await flush(); old.controller.dispose();
});

test('same original unknown retains later publication diagnostics without restoring result or permission', async () => {
  const h = await ready(); h.controller.downloadCandidate(true, h.controller.downloadReview().scope);
  h.emit(downloaded('running', 2)); h.emit(downloaded('cleanup-unknown', 3, { effect: { publication: 'entered' } }));
  h.emit(downloaded('cleanup-unknown', 4, { effect: { publication: 'published', durability: 'unknown' } }));
  assert.equal(h.state.status.operation.download.publication, 'published'); assert.equal(h.state.status.result, null);
  assert.equal(h.state.uncertain, true); assert.ok(githubHistoryOwnerReason(h.state));
  h.emit(downloaded('settled', 5, { effect: published() })); assert.equal(h.state.status.operation.phase, 'cleanup-unknown');
  assert.equal(h.controller.currentResult(), null); h.controller.downloadCandidate(true, h.controller.downloadReview().scope);
  assert.equal(h.count('download'), 1); h.last('download').reject({}); await flush(); h.controller.dispose();
});

test('context invalidation and dispose keep exact original Cancel and listener through returned acknowledgement', async () => {
  const h = await ready(); h.controller.downloadCandidate(true, h.controller.downloadReview().scope);
  h.emit(downloaded('running', 2)); h.controller.beforeWorkspaceAction(); h.controller.beforeWorkspaceAction();
  assert.equal(h.count('cancel'), 1); assert.deepEqual(h.last('cancel').args, { operationId: 'read-a' });
  h.controller.dispose(); assert.equal(h.detached, 0);
  const end = downloaded('settled', 4, { reason: 'cancelled', effect: { closed: true } });
  h.respond('download', end); await flush(); assert.equal(h.detached, 0);
  h.respond('cancel', end); await flush(); assert.equal(h.detached, 1); assert.equal(h.controller.currentResult(), null);
  assert.equal(h.count('download'), 1);
});

test('lost download call stays fenced, while a genuine pre-admission refusal is never fabricated as export', async () => {
  const h = await ready(); h.controller.downloadCandidate(true, h.controller.downloadReview().scope);
  h.last('download').reject({ message: 'INERT_PRIVATE' }); await flush();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentResult(), null);
  h.controller.downloadCandidate(true, h.controller.downloadReview().scope); assert.equal(h.count('download'), 1); h.controller.dispose();
  const refused = await ready(); refused.controller.downloadCandidate(true, refused.controller.downloadReview().scope);
  refused.last('download').reject({ code: 'github_history_refused_resources_unavailable' }); await flush();
  assert.equal(refused.state.pending, false); assert.equal(refused.state.uncertain, false);
  assert.equal(refused.state.status.operation, null); assert.equal(refused.controller.currentResult(), null); refused.controller.dispose();
});
