// Inert DTO + fake IPC promises; no GitHub, native provider, process or Store.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { GitHubHistoryController, githubHistoryOwnerReason } from '../src/githubHistoryController.ts';
import { GITHUB_HISTORY_ASSURANCE, GITHUB_HISTORY_EVENT, GITHUB_HISTORY_REASONS,
  githubHistoryError, githubHistoryRequestFits, parseGitHubHistoryResult, parseGitHubHistoryStatus } from '../src/githubHistoryProtocol.ts';
const clone = (v) => structuredClone(v);
const selection = () => ({ runId: '123', attempt: 2, stage: 'external-testing', platform: 'android' });
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
  let current = clone(initial), cv = connection(), pv = project(), listener = null, detached = 0;
  const calls = [];
  const request = (kind, args) => { const work = deferred(); calls.push({ kind, args: clone(args), ...work }); return work.promise; };
  const api = { mode: 'native', githubHistoryStatus: async () => { calls.push({ kind: 'status' }); return clone(current); },
    subscribeGitHubHistory: async (fn) => { calls.push({ kind: 'subscribe' }); listener = fn; return () => { listener = null; detached += 1; }; },
    startGitHubHistory: (args) => request('start', args), cancelGitHubHistory: (args) => request('cancel', args) };
  const controller = new GitHubHistoryController({ connection: () => cv, selectedProject: () => pv });
  return { controller, api, calls, get state() { return controller.getSnapshot(); }, get detached() { return detached; },
    count: (kind) => calls.filter((v) => v.kind === kind).length, last: (kind) => calls.filter((v) => v.kind === kind).at(-1),
    emit: (v) => { current = clone(v); listener?.(clone(v)); }, raw: (v) => listener?.(v),
    respond: (kind, v) => { current = clone(v); calls.filter((c) => c.kind === kind).at(-1).resolve(clone(v)); },
    connection: (v) => { cv = v; controller.syncContext(); }, project: (v) => { pv = v; controller.syncContext(); } };
}
function select(h) { h.controller.setRunId('123'); h.controller.setAttempt('2'); h.controller.setStage('external-testing'); h.controller.setPlatform('android'); }
async function ready(initial) { const h = harness(initial); await h.controller.connect(h.api); select(h); return h; }

test('History closed DATA binds exact selection and evidence without inferring Store authority', () => {
  assert.equal(GITHUB_HISTORY_EVENT, 'github-history-status');
  for (const stage of ['candidate', 'external-testing', 'production-submit']) for (const platform of ['android', 'ios']) {
    const r = result({ ...selection(), stage, platform }); assert.ok(parseGitHubHistoryResult(r));
    assert.ok(parseGitHubHistoryStatus(status('settled', 3, { result: r, selection: r.context.selection })));
  }
  const unavailable = new Set(['unqualified', 'publisher-unconfigured', 'unsupported-tooling', 'provider-unavailable', 'runtime-unavailable',
    'resources-unavailable', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'rate-limited', 'network-unavailable', 'tls-failed', 'artifact-missing', 'artifact-expired', 'producer-pending']);
  const refused = new Set(['invalid-input', 'target-changed', 'config-invalid', 'platform-disabled', 'provider-mismatch', 'response-invalid', 'response-limit', 'evidence-invalid', 'attestation-not-confirmed']);
  for (const reason of GITHUB_HISTORY_REASONS) for (const verification of ['verified', 'unavailable', 'refused']) {
    const r = { ...result(), reason, verification, evidence: verification === 'verified' ? result().evidence : null };
    assert.equal(!!parseGitHubHistoryResult(r), verification === 'verified' ? reason === 'none' : (verification === 'unavailable' ? unavailable : refused).has(reason));
  }
  const args = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, selection: selection() };
  assert.ok(githubHistoryRequestFits('github_history_start', args));
  assert.ok(githubHistoryRequestFits('github_history_status', {})); assert.ok(githubHistoryRequestFits('github_history_cancel', { operationId: 'read-a' }));
  for (const key of ['token', 'url', 'path', 'configSha256', 'toolingSha', 'expectedHash', 'retry', 'force', 'deadline'])
    assert.equal(githubHistoryRequestFits('github_history_start', { ...args, [key]: 'INERT' }), false);
  for (const revision of [0, 4294967295, 1.5, NaN, Infinity, true]) {
    assert.equal(githubHistoryRequestFits('github_history_start', { ...args, expectedRevision: revision }), false);
    assert.equal(parseGitHubHistoryStatus({ ...idle(), revision }), null);
  }
  assert.ok(parseGitHubHistoryStatus(idle(4294967294)));
  for (const runId of ['', '0', '01', '-1', '1e2', '18446744073709551616', 123])
    assert.equal(githubHistoryRequestFits('github_history_start', { ...args, selection: { ...selection(), runId } }), false);
  assert.ok(githubHistoryRequestFits('github_history_start', { ...args, selection: { ...selection(), runId: '18446744073709551615', attempt: 100 } }));
  for (const attempt of [0, 101, true, '2', 1.1]) assert.equal(githubHistoryRequestFits('github_history_start', { ...args, selection: { ...selection(), attempt } }), false);
  for (const observedAt of ['2026-02-30T12:00:00Z', '0000-01-01T00:00:00Z', '2026-10-09T12:00:00.1234567Z', '2026-10-09T12:00:00+00:00'])
    assert.equal(parseGitHubHistoryResult({ ...result(), observedAt }), null);
  for (const observedAt of ['2024-02-29T12:00:00Z', '2026-10-09T12:00:00.1Z', '2026-10-09T12:00:00.123456Z'])
    assert.ok(parseGitHubHistoryResult({ ...result(), observedAt }));
  for (const mutate of [(r) => { r.context.selection.attempt = 3; }, (r) => { r.context.toolingSha = 'b'.repeat(40); },
    (r) => { r.evidence.producedBy.runId = '999'; }, (r) => { r.evidence.authorizedBy.reusableCommit = 'b'.repeat(40); },
    (r) => { r.evidence.authorizedBy.event = 'push'; }, (r) => { r.evidence.authorizedBy.callerPath = '.github/workflows/other.yml'; },
    (r) => { r.evidence.artifactName += '-latest'; }, (r) => { r.evidence.version.build = 2100000001; },
    (r) => { r.evidence.version.name = '1'; }, (r) => { r.evidence.applicationId = 'a\u0085b'; },
    (r) => { r.evidence.applicationId = '\ud800'; }, (r) => { r.assurance = 'current-store-state'; },
    (r) => { r.context.token = 'INERT'; }, (r) => { r.evidence.producedBy.extra = 1; }]) {
    const r = result(); mutate(r); assert.equal(parseGitHubHistoryResult(r), null);
  }
  const unicode = result(); unicode.evidence.applicationId = '😀'.repeat(255); assert.ok(parseGitHubHistoryResult(unicode));
  unicode.evidence.applicationId += '😀'; assert.equal(parseGitHubHistoryResult(unicode), null);
  for (const path of [['context'], ['context', 'selection'], ['evidence'], ['evidence', 'producedBy'], ['evidence', 'authorizedBy'],
    ['evidence', 'candidateSource'], ['evidence', 'operationSource'], ['evidence', 'version']]) {
    const r = result(); let row = r; for (const key of path.slice(0, -1)) row = row[key]; row[path.at(-1)] = Object.values(row[path.at(-1)]);
    assert.equal(parseGitHubHistoryResult(r), null);
  }
  let reads = 0; const hostile = result(); Object.defineProperty(hostile.context, 'selection', { enumerable: true, get() { reads += 1; throw Error('INERT'); } });
  assert.equal(parseGitHubHistoryResult(hostile), null); assert.equal(reads, 0);
  const cyclic = idle(); cyclic.result = cyclic; assert.equal(parseGitHubHistoryStatus(cyclic), null);
  for (const bad of [{ ...idle(), result: result() }, { ...status('running', 2), result: result() },
    { ...status('settled', 3), operation: { ...status('settled', 3).operation, reason: 'cancelled' } },
    { ...status('cleanup-unknown', 3), available: true, reason: 'none' },
    { ...status('settled', 3), sessionId: null }, { ...idle(), available: false }]) assert.equal(parseGitHubHistoryStatus(bad), null);
  const revoked = { ...status('settled', 3), available: false, reason: 'cleanup-unknown' }; assert.ok(parseGitHubHistoryStatus(revoked));
  assert.equal(githubHistoryError({ code: 'github_history_refused_busy' }).admission, 'not-admitted');
  assert.equal(githubHistoryError({ code: 'github_history_refused_none' }).admission, 'unknown');
  assert.equal(githubHistoryError({ code: 'generic', admission: 'not-admitted', message: 'INERT' }).admission, 'unknown');
  assert.equal(githubHistoryError(Object.defineProperty({}, 'code', { get() { reads += 1; return 'github_history_refused_busy'; } })).admission, 'unknown');
  assert.equal(reads, 0);
});

test('History requires native clean saved context and explicit four-input read intent', async () => {
  const h = harness(); assert.equal(h.calls.length, 0); await h.controller.connect(h.api);
  assert.deepEqual(h.calls.map((c) => c.kind), ['subscribe', 'status']);
  h.controller.start(); h.controller.setRunId('123'); h.controller.start(); h.controller.setAttempt('2'); h.controller.start();
  h.controller.setStage('external-testing'); h.controller.start(); assert.equal(h.count('start'), 0);
  h.controller.setPlatform('android'); assert.equal(h.controller.startReason(), null);
  let nested = false; h.controller.subscribe(() => { if (!nested) { nested = true; h.controller.start(); } });
  h.controller.start(); assert.equal(h.count('start'), 1);
  assert.deepEqual(h.last('start').args, { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, selection: selection() });
  await flush(); assert.equal(h.count('status'), 1); assert.equal(h.count('start'), 1); assert.equal(h.controller.currentResult(), null);
  h.respond('start', status('settled', 3)); await flush(); assert.ok(h.controller.currentResult()); assert.equal(h.state.pending, false);
  for (const mutate of [(p) => { p.draft = { changed: true }; }, (p) => { p.sourceChanged = true; }, (p) => { p.snapshotPredatesSave = true; },
    (p) => { p.snapshotError = {}; }, (p) => { p.snapshotRequest = 3; }, (p) => { p.saveRecoveryRequired = true; },
    (p) => { p.saveRecoveryNeedsReload = true; }, (p) => { p.validation.valid = false; }, (p) => { p.savedConfigContent = null; },
    (p) => { p.project.id = 'other'; }, (p) => { p.revision = Infinity; }]) {
    const a = await ready(); const p = project(); mutate(p); a.project(p); a.controller.start(); assert.equal(a.count('start'), 0);
    assert.notEqual(a.controller.startReason(), null); a.controller.dispose();
  }
  for (const mode of ['preview', 'unavailable']) { const a = harness(); await a.controller.connect({ ...a.api, mode }); select(a); a.controller.start(); assert.equal(a.calls.length, 0); }
  for (const reason of ['unqualified', 'runtime-unavailable', 'provider-unavailable', 'resources-unavailable']) {
    const a = await ready({ ...idle(), available: false, reason }); a.controller.start(); assert.equal(a.count('start'), 0);
    assert.notEqual(a.controller.startReason(), null); a.controller.dispose();
  }
  const changed = await ready(); let once = false;
  changed.controller.subscribe(() => { if (!once) { once = true; changed.controller.beforeWorkspaceAction(); } });
  changed.controller.start(); assert.equal(changed.count('start'), 0); assert.equal(changed.state.pending, false);

  // Actual Desktop bridge + accepted controller, with inert IPC only. Status
  // observes local state; mounting or navigation never starts a remote read.
  const wireCalls = [], startReply = deferred(), cancelReply = deferred();
  let wireListener = null, wireClosed = 0;
  const actualApi = createNativeApi('native', (command, args) => {
    wireCalls.push({ command, args });
    if (command === 'github_history_status') return Promise.resolve(idle());
    if (command === 'github_history_start') return startReply.promise;
    if (command === 'github_history_cancel') return cancelReply.promise;
    throw Error('Unexpected inert command');
  }, async (event, listener) => {
    assert.equal(event, 'github-history-status'); wireListener = listener;
    return () => { wireClosed += 1; wireListener = null; };
  });
  let otherOriginal = 'Existing saved-edit original';
  const integrated = new GitHubHistoryController({ connection, selectedProject: project, otherOperationReason: () => otherOriginal });
  await integrated.connect(actualApi); select({ controller: integrated });
  assert.deepEqual(wireCalls, [{ command: 'github_history_status', args: {} }]);
  integrated.start(); assert.equal(wireCalls.length, 1); // Existing owner blocks admission, not Status.
  otherOriginal = null; assert.equal(integrated.startReason(), null); integrated.start();
  assert.deepEqual(wireCalls[1], { command: 'github_history_start', args: {
    sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, selection: selection(),
  } });
  wireListener(status('running', 2)); assert.ok(githubHistoryOwnerReason(integrated.getSnapshot()));
  integrated.beforeWorkspaceAction(); integrated.beforeWorkspaceAction(); integrated.cancel();
  assert.deepEqual(wireCalls[2], { command: 'github_history_cancel', args: { operationId: 'read-a' } });
  assert.equal(wireCalls.length, 3); assert.equal(wireClosed, 0); assert.equal(integrated.currentResult(), null);
  integrated.dispose(); assert.equal(wireClosed, 0);
  startReply.resolve(status('settled', 3, { reason: 'cancelled' })); await flush(); assert.equal(wireClosed, 0);
  cancelReply.resolve(status('settled', 3, { reason: 'cancelled' })); await flush(); assert.equal(wireClosed, 1);
  assert.equal(wireCalls.length, 3); assert.equal(integrated.currentResult(), null);

  let invokeCount = 0;
  const closedApi = createNativeApi('native', async () => { invokeCount += 1; return idle(); }, async () => () => {});
  const validArgs = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, selection: selection() };
  await assert.rejects(closedApi.startGitHubHistory({ ...validArgs, expectedHash: 'INERT' }),
    (error) => error.reason === 'invalid-input' && error.admission === 'not-admitted');
  await assert.rejects(closedApi.cancelGitHubHistory({ operationId: 'read-a', retry: true }),
    (error) => error.reason === 'invalid-input' && error.admission === 'not-admitted');
  const noListenerCalls = [];
  const noListenerApi = createNativeApi('native', async (command, args) => {
    noListenerCalls.push({ command, args }); return idle();
  });
  await assert.rejects(noListenerApi.startGitHubHistory(validArgs),
    (error) => error.reason === 'runtime-unavailable' && error.admission === 'not-admitted');
  await assert.rejects(noListenerApi.subscribeGitHubHistory(() => {}),
    (error) => error.reason === 'runtime-unavailable' && error.admission === 'not-admitted');
  assert.deepEqual(noListenerCalls, []);
  // A missing event adapter must not disable bounded status/returned Cancel
  // observation for an already retained original.
  assert.deepEqual(await noListenerApi.githubHistoryStatus(), idle());
  assert.deepEqual(await noListenerApi.cancelGitHubHistory({ operationId: 'read-a' }), idle());
  assert.deepEqual(noListenerCalls, [
    { command: 'github_history_status', args: {} },
    { command: 'github_history_cancel', args: { operationId: 'read-a' } },
  ]);
  assert.equal(invokeCount, 0);
  const unavailableApi = createNativeApi('unavailable', async () => { invokeCount += 1; return idle(); },
    async () => { invokeCount += 1; return () => {}; });
  for (const call of [() => unavailableApi.githubHistoryStatus(), () => unavailableApi.startGitHubHistory(validArgs),
    () => unavailableApi.cancelGitHubHistory({ operationId: 'read-a' }), () => unavailableApi.subscribeGitHubHistory(() => {})]) {
    await assert.rejects(call(), (error) => error.reason === 'runtime-unavailable' && error.admission === 'not-admitted');
  }
  assert.equal(invokeCount, 0);
  let passedArgs;
  const copied = createNativeApi('native', async (_command, args) => { passedArgs = args; return idle(); }, async () => () => {});
  await copied.startGitHubHistory(validArgs);
  assert.notEqual(passedArgs, validArgs); assert.notEqual(passedArgs.selection, validArgs.selection); assert.deepEqual(passedArgs, validArgs);
  const malformed = createNativeApi('native', async () => ({ ...idle(), unexpected: 'INERT_PRIVATE' }));
  await assert.rejects(malformed.githubHistoryStatus(), (error) => error.code === 'github_history_unknown'
    && error.admission === 'unknown' && !JSON.stringify(error).includes('INERT_PRIVATE'));
  for (const code of ['github_history_refused_provider_unavailable', 'generic']) {
    const rejecting = createNativeApi('native', () => { throw { code, admission: 'not-admitted', message: 'INERT_PRIVATE' }; }, async () => () => {});
    await assert.rejects(rejecting.startGitHubHistory(validArgs), (error) =>
      error.admission === (code === 'generic' ? 'unknown' : 'not-admitted') && !JSON.stringify(error).includes('INERT_PRIVATE'));
  }
  let delivered, listener, eventClosed = 0;
  const eventApi = createNativeApi('native', async () => idle(), async (event, callback) => {
    assert.equal(event, GITHUB_HISTORY_EVENT); listener = callback; return () => { eventClosed += 1; };
  });
  const stop = await eventApi.subscribeGitHubHistory((value) => { delivered = value; });
  const payload = idle(); listener(payload); assert.deepEqual(delivered, payload); assert.notEqual(delivered, payload);
  payload.revision = 7; assert.equal(delivered.revision, 1);
  listener({ ...idle(), extra: true }); assert.equal(delivered, null); stop(); assert.equal(eventClosed, 1);
});

test('History preserves original observation and cancellation across stale replies and context changes', async () => {
  const h = await ready(); h.controller.start(); h.emit(status('running', 2));
  const c = connection(); c.status.revision += 1; h.connection(c); assert.equal(h.count('cancel'), 0);
  h.emit(status('settled', 3)); assert.ok(h.controller.currentResult());
  h.respond('start', status('running', 2)); await flush(); assert.equal(h.state.status.revision, 3); assert.ok(h.controller.currentResult());
  const sameRevision = status('settled', 3); sameRevision.result.evidence.version.build += 1; h.emit(sameRevision);
  assert.equal(h.state.uncertain, true); assert.equal(h.controller.currentResult(), null); h.emit(status('settled', 4));
  assert.equal(h.state.uncertain, true); assert.notEqual(h.controller.startReason(), null);

  const late = await ready(); late.controller.start(); late.controller.setRunId('999'); late.controller.setRunId('123');
  assert.equal(late.count('cancel'), 0); late.emit(status('running', 2)); assert.equal(late.count('cancel'), 1);
  assert.deepEqual(late.last('cancel').args, { operationId: 'read-a' });
  late.controller.beforeWorkspaceAction(); late.controller.cancel(); assert.equal(late.count('cancel'), 1);
  late.respond('cancel', status('stopping', 3)); await flush(); assert.equal(late.state.pending, true); assert.ok(githubHistoryOwnerReason(late.state));
  late.respond('start', status('settled', 4)); await flush(); assert.equal(late.state.pending, false); assert.equal(late.controller.currentResult(), null);
  assert.equal(late.state.status.result.verification, 'verified'); // retained historical, never revived.

  const away = await ready(); away.controller.start(); const other = connection(); other.context.projectId = 'other'; away.connection(other); away.connection(connection());
  away.emit(status('running', 2)); assert.equal(away.count('cancel'), 1); away.respond('start', status('settled', 3)); await flush();
  assert.equal(away.controller.currentResult(), null); away.respond('cancel', status('settled', 3)); await flush();

  const apiSwap = await ready(); apiSwap.controller.start(); apiSwap.emit(status('running', 2));
  let newReads = 0; const next = { ...apiSwap.api, githubHistoryStatus: async () => { newReads += 1; return idle(); } };
  await apiSwap.controller.connect(next); assert.equal(apiSwap.detached, 0); assert.equal(newReads, 0); assert.equal(apiSwap.count('cancel'), 1);
  apiSwap.respond('start', status('settled', 3)); await flush(); assert.equal(apiSwap.detached, 0);
  apiSwap.respond('cancel', status('settled', 3)); await flush(); assert.equal(apiSwap.detached, 1); assert.equal(newReads, 1);
  assert.equal(apiSwap.controller.currentResult(), null);

  // A new port must supply its OWN accepted status; old available DATA stays display-only.
  const portRead = await ready(); const secondStatus = deferred(); let secondStarts = 0;
  const secondPort = { ...portRead.api, githubHistoryStatus: () => secondStatus.promise,
    startGitHubHistory: () => { secondStarts += 1; return Promise.resolve(status('settled', 3)); } };
  const connecting = portRead.controller.connect(secondPort); await flush();
  assert.equal(portRead.state.status.available, true); assert.notEqual(portRead.controller.startReason(), null);
  assert.doesNotThrow(() => portRead.controller.start()); assert.equal(secondStarts, 0);
  secondStatus.resolve(idle()); await connecting; assert.equal(portRead.controller.startReason(), null);
  portRead.controller.start(); await flush(); assert.equal(secondStarts, 1); assert.equal(portRead.count('start'), 0);

  // These genuine observed originals were NOT started by this controller.
  for (const action of ['context', 'port', 'dispose']) {
    const observed = harness(status('running', 2)); select(observed); await observed.controller.connect(observed.api);
    assert.equal(observed.state.pending, false); assert.equal(observed.count('start'), 0); assert.equal(observed.count('cancel'), 0);
    let replacementReads = 0;
    if (action === 'context') { const changed = connection(); changed.context.projectId = 'other'; observed.connection(changed); observed.connection(connection()); }
    else if (action === 'port') await observed.controller.connect({ ...observed.api,
      githubHistoryStatus: async () => { replacementReads += 1; return idle(); } });
    else observed.controller.dispose();
    assert.equal(observed.count('cancel'), 1); assert.deepEqual(observed.last('cancel').args, { operationId: 'read-a' });
    assert.equal(observed.detached, 0); assert.equal(replacementReads, 0); assert.equal(observed.controller.currentResult(), null);
    observed.emit(status('stopping', 3)); observed.controller.beforeWorkspaceAction(); observed.controller.cancel(); observed.controller.dispose();
    assert.equal(observed.count('cancel'), 1); assert.equal(observed.detached, 0);
    observed.respond('cancel', status('settled', 4, { reason: 'cancelled' })); await flush();
    assert.equal(observed.detached, 1); assert.equal(observed.count('start'), 0); assert.equal(observed.controller.currentResult(), null);
  }

  const disposed = await ready(); disposed.controller.start(); disposed.controller.dispose(); assert.equal(disposed.detached, 0);
  disposed.emit(status('running', 2)); assert.equal(disposed.count('cancel'), 1);
  disposed.respond('start', status('settled', 3)); await flush(); assert.equal(disposed.detached, 0);
  disposed.respond('cancel', status('settled', 3)); await flush(); assert.equal(disposed.detached, 1);

  const unknown = await ready(); unknown.controller.start(); unknown.last('start').reject({ code: 'generic' }); await flush();
  assert.equal(unknown.state.uncertain, true); assert.equal(unknown.state.pending, true); unknown.controller.start(); assert.equal(unknown.count('start'), 1);
  unknown.emit(status('settled', 3)); assert.equal(unknown.state.uncertain, false); assert.ok(unknown.controller.currentResult());
  const refused = await ready(); refused.controller.start(); refused.last('start').reject({ code: 'github_history_refused_busy' }); await flush();
  assert.equal(refused.state.pending, false); assert.equal(refused.state.uncertain, false);
  const admitted = await ready(); admitted.controller.start(); admitted.emit(status('running', 2));
  admitted.last('start').reject({ code: 'github_history_refused_busy' }); await flush(); assert.equal(admitted.state.pending, true); assert.equal(admitted.state.uncertain, true);
  admitted.emit(status('cleanup-unknown', 3)); admitted.emit(status('settled', 4)); assert.equal(admitted.state.uncertain, true); assert.equal(admitted.controller.currentResult(), null);

  const cancelFault = await ready(status('running', 2)); cancelFault.controller.cancel(); cancelFault.last('cancel').reject({ code: 'github_history_refused_busy' }); await flush();
  assert.equal(cancelFault.state.uncertain, true); cancelFault.controller.cancel(); assert.equal(cancelFault.count('cancel'), 1);
  cancelFault.emit(status('settled', 3, { reason: 'cancelled' })); assert.equal(cancelFault.state.uncertain, false);
  const mismatched = await ready(); mismatched.controller.start(); const foreign = status('settled', 3);
  foreign.result.context.configSha256 = '9'.repeat(64); mismatched.respond('start', foreign); await flush();
  assert.equal(mismatched.state.uncertain, true); assert.equal(mismatched.controller.currentResult(), null);
  mismatched.emit(status('settled', 4)); assert.equal(mismatched.state.uncertain, true);
  const restored = await ready(status('settled', 3)); assert.equal(restored.controller.currentResult(), null); assert.equal(restored.count('start'), 0);
  const savedChange = await ready(); savedChange.controller.start(); savedChange.respond('start', status('settled', 3)); await flush(); assert.ok(savedChange.controller.currentResult());
  const p = project(); p.savedConfigContent.sha256 = 'f'.repeat(64); savedChange.project(p); savedChange.project(project()); assert.equal(savedChange.controller.currentResult(), null);
  const revoked = await ready(); revoked.controller.start(); revoked.respond('start', status('settled', 3)); await flush();
  revoked.emit({ ...status('settled', 4), available: false, reason: 'not-connected' }); assert.equal(revoked.controller.currentResult(), null);
  assert.equal(revoked.state.status.result.verification, 'verified');
  revoked.emit(status('settled', 5)); assert.equal(revoked.controller.currentResult(), null); // no silent revival.
});

test('History component SOURCE exposes exact read controls, contextual help and retained evidence limits', () => {
  const packageData = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  const testEntries = packageData.scripts.test.split(/\s+/);
  assert.equal(testEntries.filter((entry) => entry === 'tests/github-history.test.mjs').length, 1);
  const source = readFileSync(new URL('../src/components/GitHubHistory.tsx', import.meta.url), 'utf8');
  for (const text of ['Exact GitHub run ID', 'Exact run attempt', 'Release stage to observe', 'Evidence platform',
    'Start authenticated history read', 'Cancel this local read', 'Read local Status',
    'NOT current Store state or permission to promote', 'Previous / retained observation', 'Original authorization (may be older)',
    'artifactSha256', 'candidateManifestSha256', 'operationIntentSha256', 'receiptSha256', 'provenanceSha256']) assert.ok(source.includes(text), text);
  for (const name of ['run', 'attempt', 'stage', 'platform', 'read', 'recovery']) assert.ok(source.includes(`HELP.${name}`));
  assert.equal((source.match(/requiredWhen:/g) ?? []).length, 6);
  assert.ok(source.includes('controller.currentResult()')); assert.ok(source.includes('disabled={reason !== null}'));
  assert.ok(source.includes('controller.canCancel()')); assert.ok(source.includes('compact && !state.pending && !state.uncertain'));
  assert.ok(source.includes('value=""')); assert.ok(source.includes('Status reads local native state, not GitHub'));
  for (const forbidden of ['dangerouslySetInnerHTML', 'window.open', 'fetch(', 'setInterval(', 'ENTRY_AVAILABLE', 'dispatchGitHub']) assert.equal(source.includes(forbidden), false);

  // The tested controller is mounted by the real Desktop factory/App route,
  // not merely an unused component. These source joins do not claim native IO.
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const bridge = readFileSync(new URL('../src/bridge.ts', import.meta.url), 'utf8');
  const api = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8');
  const types = readFileSync(new URL('../src/types.ts', import.meta.url), 'utf8');
  const preview = readFileSync(new URL('../src/preview.ts', import.meta.url), 'utf8');
  const connectionSource = readFileSync(new URL('../src/components/GitHubConnection.tsx', import.meta.url), 'utf8');
  assert.ok(types.includes('GitHubReleaseApi, GitHubHistoryApi, MetadataTextApi'));
  assert.ok(api.includes("return createNativeApi(mode === 'native' ? 'native' : 'unavailable', invoke,"));
  assert.ok(api.includes('listen<unknown>(event, ({ payload }) => onStatus(payload))'));
  const bridgeRead = bridge.slice(bridge.indexOf('  const githubHistoryCall ='), bridge.indexOf('  const githubPreflightCall ='));
  assert.ok(bridgeRead.includes("if (mode !== 'native' || (command === 'github_history_start' && !listen))"));
  assert.ok(bridgeRead.indexOf("command === 'github_history_start' && !listen") < bridgeRead.indexOf('await invoke<unknown>'));
  assert.ok(bridgeRead.indexOf('githubHistoryRequestFits(command, value)') < bridgeRead.indexOf('await invoke<unknown>'));
  assert.ok(bridgeRead.includes('parseGitHubHistoryStatus(await invoke<unknown>(command, structuredClone(value)))'));
  assert.ok(bridge.includes('listen(GITHUB_HISTORY_EVENT, (value) => onStatus(parseGitHubHistoryStatus(value)))'));
  for (const name of ['githubHistoryStatus', 'startGitHubHistory', 'cancelGitHubHistory', 'subscribeGitHubHistory']) {
    assert.equal((preview.match(new RegExp(`  ${name}: githubHistoryUnavailable,`, 'g')) ?? []).length, 1);
  }
  assert.ok(preview.includes("const githubHistoryUnavailable = (): Promise<never> => Promise.reject(githubHistoryError({ code: 'github_history_refused_runtime_unavailable' }))"));
  assert.equal((app.match(/new GitHubHistoryController\(/g) ?? []).length, 1);
  assert.ok(app.includes('connection: githubConnection.getSnapshot'));
  assert.ok(app.includes('useSyncExternalStore(githubHistory.subscribe, githubHistory.getSnapshot, githubHistory.getSnapshot)'));
  const dispatch = app.slice(app.indexOf('  const dispatch = useCallback'), app.indexOf('  const [configEdit]'));
  assert.ok(dispatch.indexOf('githubHistoryControllerRef.current?.beforeWorkspaceAction()') >= 0);
  assert.ok(dispatch.indexOf('githubHistoryControllerRef.current?.beforeWorkspaceAction()') < dispatch.indexOf('workspaceReducer(previous, action)'));
  assert.ok(dispatch.indexOf('githubHistoryControllerRef.current?.syncContext()') > dispatch.indexOf('workspaceRef.current = next'));
  assert.ok(app.indexOf('githubConnection.subscribe(githubHistory.syncContext)') < app.indexOf('    void bootstrap();'));
  assert.ok(app.includes('void githubHistory.connect(connection)')); assert.equal((app.match(/void githubHistory\.connect\(null\)/g) ?? []).length, 2);
  assert.ok(app.includes('useEffect(() => () => githubHistory.dispose(), [githubHistory])'));
  assert.ok(app.includes('const loadSnapshot = async (projectId: string, recoveryReload = false) => {\n    githubHistory.beforeWorkspaceAction();'));
  assert.ok(app.includes('const chooseProject = async () => {\n    githubHistory.beforeWorkspaceAction();'));
  const navigation = app.slice(app.indexOf('  const navigate ='), app.indexOf('  const refreshReason ='));
  assert.equal(navigation.includes('githubHistory.dispose'), false); assert.equal(navigation.includes('githubHistory.start'), false);
  assert.ok(app.includes('(excludeHistory ? null : historyBusy())'));
  assert.ok(app.includes('(forHistoryRead ? null : historyBusy())'));
  assert.ok(app.includes('excludeRemoteSetup = false, excludeHistory = false'));
  assert.ok(app.includes('excludeInitialization = false, forHistoryRead = false'));
  assert.equal((app.match(/savedCommandBusy\(false, false, false, false, false, false, true\)/g) ?? []).length, 1);
  assert.equal((app.match(/savedCommandPrerequisiteReason\(false, false, undefined, false, true\)/g) ?? []).length, 1);
  assert.ok(app.includes('connection.blocked || connection.uncertain || connection.busy || connection.retirementPending || !forHistoryRead && (connection.status ?? connection.retained)?.session'));
  assert.equal((app.match(/<GitHubHistory /g) ?? []).length, 2);
  assert.ok(app.includes("{page !== 'github' && <GitHubHistory state={githubHistoryState} controller={githubHistory} compact"));
  assert.ok(app.includes('<GitHubHistory state={githubHistoryState} controller={githubHistory} onHelp={setHelp} />'));
  assert.equal((app.match(/githubHistory\.start\(/g) ?? []).length, 0);
  for (const text of ['Authenticated release history panel below', 'Connect alone does not read History',
    'Contents and Actions read access', 'Missing native runtime or attestation provider stays unavailable']) assert.ok(connectionSource.includes(text), text);
  for (const text of [app, bridgeRead, preview]) assert.equal(/HISTORY_(?:ENTRY_)?AVAILABLE/.test(text), false);
});
