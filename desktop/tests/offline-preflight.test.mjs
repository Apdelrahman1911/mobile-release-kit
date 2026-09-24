// Authored inert DATA/controller/bridge/source guards. No subject process, native
// qualification, project execution, filesystem observation, network or GUI runs.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { OfflinePreflightController, offlinePreflightOwnerReason } from '../src/offlinePreflight.ts';
import { selectOfflinePreflightFindings } from '../src/offlinePreflightFindings.ts';
import { OFFLINE_CORE_STATUSES, OFFLINE_CHECK_IDS, OFFLINE_LIMITATIONS, OFFLINE_PREFLIGHT_CONSENT,
  OFFLINE_PREFLIGHT_COUNTER_MAX, OFFLINE_PREFLIGHT_DISCLOSURE, OFFLINE_PREFLIGHT_EVENT, copyOfflinePreflightRequest,
  encodeOfflinePreflightRequest, offlineOperationProgress, offlinePreflightError, parseOfflinePreflightResult,
  parseOfflinePreflightStatus, parseSavedConfigContent, savedConfigFromSnapshot } from '../src/offlinePreflightProtocol.ts';
import { EnvironmentController } from '../src/environment.ts';
import { ReleaseVersionController } from '../src/releaseVersion.ts';
import { ReleaseInputGuidanceController } from '../src/releaseInputGuidance.ts';
import { GitHubSetupController } from '../src/githubSetupController.ts';
import { MetadataTextEditController } from '../src/metadataTextEditController.ts';
import { CandidateEvidenceController } from '../src/candidateEvidence.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), OTHER = 'c'.repeat(32);
// Comparison DATA fixtures, not hashes claimed to come from a native file read.
const CONTENT = { bytes: 231, sha256: 'd'.repeat(64) };
const NEXT_CONTENT = { bytes: 241, sha256: 'e'.repeat(64) };
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 16; n++) await Promise.resolve(); };
const decode = (raw) => JSON.parse(new TextDecoder().decode(raw));
const source = (name) => readFileSync(new URL(`../src/${name}`, import.meta.url), 'utf8');
const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
function snapshot(content = CONTENT) {
  return { root: '/never-opened', observedAt: '', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', data: { android: { enabled: true }, projectChecks: { preflight: [] } }, content: clone(content), issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
    assurance: clone(assurance), issues: [] };
}
function workspace() {
  let state = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'project-1', name: 'Inert source project', path: '/never-forwarded' } });
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: 'project-1', requestId: 1 });
  return workspaceReducer(state, { type: 'snapshot-done', projectId: 'project-1', requestId: 1, snapshot: snapshot(), observedAt: 1 });
}
function request(project = workspace().projects['project-1']) {
  return { projectId: project.project.id, draftRevision: project.revision, baselineGeneration: project.baselineGeneration, savedConfig: clone(project.savedConfigContent) };
}
const context = (input = request()) => ({ ...clone(input), platform: 'android', operation: 'offline-preflight' });
function operation(options = {}) {
  return { operationId: OP, ownerGeneration: OWNER, context: context(), phase: 'awaiting-consent', intentUsable: true,
    outcome: null, reason: 'none', result: null, ...options };
}
function status(revision = 0, op = null, availability = 'available') { return { schemaVersion: 1, statusRevision: revision, availability, operation: op }; }
function report(total = 9, usedConfig = CONTENT) {
  const counts = Object.fromEntries(OFFLINE_CORE_STATUSES.map((key) => [key, 0]));
  for (let n = 0; n < total; n++) counts[OFFLINE_CORE_STATUSES[n % 9]]++;
  const findings = Array.from({ length: Math.min(total, 128) }, (_, ordinal) => ({ ordinal, check: 'configured-project-check',
    message: 'configured-project-check', status: OFFLINE_CORE_STATUSES[ordinal % 9], projectCheckIndex: ordinal < 32 ? ordinal : null }));
  return { schemaVersion: 1, scope: 'saved-offline-android-no-core-build', usedConfig: clone(usedConfig), findings,
    summary: { total, shown: findings.length, omitted: total - findings.length, counts }, limitations: [...OFFLINE_LIMITATIONS] };
}
function terminal(outcome = 'complete', options = {}) {
  return operation({ phase: 'terminal', intentUsable: false, outcome, reason: outcome === 'complete' ? 'none' : outcome === 'refused' ? 'intent-expired' : outcome,
    result: outcome === 'complete' ? report() : null, ...options });
}
function harness(t, { initial = status(), listenGate = null } = {}) {
  let state = workspace(), registry = clone(initial), clock = 10, other = null;
  const calls = [], subscriptions = [], reads = [];
  const api = {
    mode: 'native',
    subscribeOfflinePreflight: async (callback) => {
      const row = { callback, closed: false }; subscriptions.push(row);
      if (listenGate) await listenGate.promise;
      return () => { row.closed = true; };
    },
    offlinePreflightStatus: async () => { reads.push(clone(registry)); return clone(registry); },
    prepareOfflinePreflight: (input) => { const call = { kind: 'prepare', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    startOfflinePreflight: (input) => { const call = { kind: 'start', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelOfflinePreflight: (operationId, ownerGeneration) => { const call = { kind: 'cancel', input: { operationId, ownerGeneration }, ...deferred() }; calls.push(call); return call.promise; },
  };
  const controller = new OfflinePreflightController({ selectedProject: () => state.selectedId ? state.projects[state.selectedId] : null,
    otherOperationReason: () => typeof other === 'function' ? other() : other, now: () => clock });
  controller.syncProject(); controller.setVisible(true);
  t.after(() => controller.dispose());
  const ready = controller.connect(api);
  return { api, controller, calls, subscriptions, reads, ready,
    get state() { return controller.getSnapshot(); }, get workspace() { return state; }, get project() { return state.projects[state.selectedId]; },
    dispatch(action) { controller.beforeWorkspaceAction(action); const next = workspaceReducer(state, action); if (next !== state) { state = next; controller.syncProject(); } },
    replace(project) { state = { ...state, projects: { ...state.projects, [project.project.id]: project } }; controller.syncProject(); },
    other(value) { other = value; }, clock(value) { clock = value; },
    emit(value) { registry = clone(value); subscriptions.at(-1)?.callback(clone(value)); },
    reply(call, value) { registry = clone(value); call.resolve(clone(value)); },
    registry(value) { registry = clone(value); },
  };
}
async function reviewed(h, options = {}) {
  await h.ready;
  void h.controller.prepare();
  const call = h.calls.at(-1); assert.equal(call.kind, 'prepare');
  const op = operation({ context: context(call.input), ...options });
  h.reply(call, status((h.state.status?.statusRevision ?? 0) + 1, op)); await flush();
  assert.ok(h.state.consent); assert.equal(h.state.consent.acknowledged, false);
  return op;
}
function start(h, op) {
  h.controller.setAcknowledged(op.operationId, op.ownerGeneration, true);
  void h.controller.start(op.operationId, op.ownerGeneration);
  assert.equal(h.calls.at(-1).kind, 'start');
  return h.calls.at(-1);
}
function savedEvent(project, result = 'saved') {
  const binding = { projectId: project.project.id, windowGeneration: OWNER, startStatusRevision: 1, previousTerminalId: null,
    draftRevision: project.revision, baselineGeneration: project.baselineGeneration, expectedBase: clone(project.baseline), draft: clone(project.draft) };
  const sessionId = OP, planToken = OTHER, revision = 'f'.repeat(32);
  const projection = { projectId: project.project.id, ownerGeneration: OWNER, sessionId, phase: 'final', nativeFinality: 'settled', nativeReason: 'none',
    lateSettled: false, applySubmitted: true, checkout: { revision, base: clone(binding.expectedBase) },
    prepared: { revision, planToken, draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration,
      view: { files: [{ path: 'release/mobile-release.json', action: result === 'saved' ? 'replace' : 'preserve' }, { path: '.gitignore', action: 'preserve' }] } },
    coreOutcome: { effect: result === 'saved' ? 'committed' : 'unchanged', journal: result === 'saved' ? 'clean' : 'not_created', resources: 'settled', reason: 'none' } };
  return { type: 'config-save-final', projectId: project.project.id, receipt: { binding, projection, sessionId, planToken, statusRevision: 2, result } };
}

test('closed raw request encoding rejects hooks, prototype data and execution overrides without invoking them', () => {
  const good = request();
  assert.deepEqual(decode(encodeOfflinePreflightRequest('prepare_offline_preflight', good)), good);
  assert.deepEqual(clone(copyOfflinePreflightRequest('prepare_offline_preflight', good)), good);
  assert.equal(new TextDecoder().decode(encodeOfflinePreflightRequest('offline_preflight_status', {})), '{}');
  let reads = 0;
  const getter = { ...good, get savedConfig() { reads++; return CONTENT; } };
  const nested = { ...good, savedConfig: { get bytes() { reads++; return 231; }, sha256: CONTENT.sha256 } };
  const hidden = Object.defineProperty({ ...good }, 'projectId', { value: good.projectId, enumerable: false });
  const toJSON = { ...good, toJSON() { reads++; return good; } };
  const inherited = Object.assign(Object.create({ toJSON() { reads++; return good; } }), good);
  const cycle = { ...good }; cycle.savedConfig = cycle;
  const sparse = []; sparse[2] = good;
  const many = Object.fromEntries(Array.from({ length: 70 }, (_, n) => [String(n), null]));
  const bad = [getter, nested, hidden, toJSON, inherited, cycle, sparse, many, new Date(), new String('x'), { ...good, [Symbol('x')]: true },
    { ...good, projectId: '' }, { ...good, projectId: 'x\n' }, { ...good, projectId: '../x' }, { ...good, projectId: 'é' }, { ...good, projectId: 'x'.repeat(65) },
    ...[-1, -0, 1.5, NaN, Infinity, 0xffff_ffff, Number.MAX_SAFE_INTEGER + 1, 1n].map((draftRevision) => ({ ...good, draftRevision })),
    ...[0, -1, 524289, 1.25].map((bytes) => ({ ...good, savedConfig: { ...CONTENT, bytes } })),
    ...['D'.repeat(64), `${CONTENT.sha256}\n`, 'x'.repeat(8193), '\ud800'].map((sha256) => ({ ...good, savedConfig: { ...CONTENT, sha256 } })),
    ...['draft', 'root', 'path', 'argv', 'env', 'timeout', 'runtime', 'platform', 'operation', 'runBuilds', 'credentials', 'native'].map((key) => ({ ...good, [key]: 'PRIVATE' }))];
  for (const value of bad) assert.equal(encodeOfflinePreflightRequest('prepare_offline_preflight', value), null);
  assert.equal(reads, 0);
  assert.ok(encodeOfflinePreflightRequest('prepare_offline_preflight', Object.assign(Object.create(null), good)));
  assert.ok(encodeOfflinePreflightRequest('prepare_offline_preflight', { ...good, draftRevision: OFFLINE_PREFLIGHT_COUNTER_MAX, baselineGeneration: 0 }));
  assert.equal(encodeOfflinePreflightRequest('start_offline_preflight', { operationId: OP, ownerGeneration: OWNER, consentVersion: 'other' }), null);
  assert.equal(encodeOfflinePreflightRequest('cancel_offline_preflight', { operationId: `${OP}\n`, ownerGeneration: OWNER }), null);
  assert.equal(encodeOfflinePreflightRequest('offline_preflight_status', { refresh: true }), null);
});

test('the native bridge really sends Uint8Array bodies for all four commands and copies before await', async () => {
  const calls = []; let event, receive;
  const api = createNativeApi('native', async (command, raw) => {
    assert.ok(raw instanceof Uint8Array); assert.ok(raw.byteLength > 0 && raw.byteLength <= 8192);
    calls.push({ command, raw: raw.slice(), input: decode(raw) }); return status();
  }, async (name, callback) => { event = name; receive = callback; return () => {}; });
  const input = request(), before = clone(input);
  const prepare = api.prepareOfflinePreflight(input); input.savedConfig.sha256 = 'f'.repeat(64); await prepare;
  await api.startOfflinePreflight({ operationId: OP, ownerGeneration: OWNER, consentVersion: OFFLINE_PREFLIGHT_CONSENT });
  await api.offlinePreflightStatus(); await api.cancelOfflinePreflight(OP, OWNER);
  assert.deepEqual(calls.map((call) => call.command), ['prepare_offline_preflight', 'start_offline_preflight', 'offline_preflight_status', 'cancel_offline_preflight']);
  assert.deepEqual(calls[0].input, before); assert.equal(new TextDecoder().decode(calls[2].raw), '{}');
  let observed; await api.subscribeOfflinePreflight((value) => { observed = value; });
  assert.equal(event, OFFLINE_PREFLIGHT_EVENT); receive({ ...status(), extra: 'PRIVATE' }); assert.equal(observed, null);
  const count = calls.length;
  await assert.rejects(api.prepareOfflinePreflight({ ...request(), env: {} }), (error) => error.code === 'offline_preflight_invalid');
  assert.equal(calls.length, count);
});

test('closed result projection preserves nine statuses, first-128 ordering, all totals and only fixed local messages', () => {
  for (const total of [0, 9, 128, 129, 4096]) {
    const raw = report(total), parsed = parseOfflinePreflightResult(raw);
    assert.deepEqual(clone(parsed), raw); assert.notEqual(parsed, raw); assert.equal(parsed.summary.shown, Math.min(128, total));
  }
  for (const check of OFFLINE_CHECK_IDS) {
    const raw = report(1); raw.findings[0] = { ordinal: 0, check, message: check, status: 'PASS', projectCheckIndex: null };
    assert.ok(parseOfflinePreflightResult(raw));
  }
  const mutations = [
    (x) => { x.summary.total = 4097; }, (x) => { x.summary.shown = 8; }, (x) => { x.summary.omitted = 1; },
    (x) => { x.summary.counts.PASS++; }, (x) => { x.summary.counts.EXTRA = 0; }, (x) => { delete x.summary.counts.FAIL; },
    (x) => { x.summary.counts.PASS = 0; x.summary.counts.FAIL = 2; }, (x) => { x.findings[0].ordinal = 1; },
    (x) => { x.findings[0].message = '/PRIVATE/path --argv'; }, (x) => { x.findings[0].check = 'secret.dynamic.code'; },
    (x) => { x.findings[0].check = 'version-source'; x.findings[0].message = 'version-source'; },
    (x) => { x.findings[0].projectCheckIndex = 32; }, (x) => { x.findings[0].status = 'OK'; },
    (x) => { x.findings[0].details = 'PRIVATE'; }, (x) => { x.limitations.reverse(); },
    (x) => { x.limitations.push('no-network'); }, (x) => { x.assurance = assurance; }, (x) => { x.usedConfig.bytes = 0; },
  ];
  for (const mutate of mutations) { const value = report(); mutate(value); assert.equal(parseOfflinePreflightResult(value), null); }
  const extra = report(129); extra.findings.push({ ...extra.findings[0], ordinal: 128 }); assert.equal(parseOfflinePreflightResult(extra), null);
  const sparse = report(); delete sparse.findings[0]; assert.equal(parseOfflinePreflightResult(sparse), null);
  let reads = 0;
  const hooked = report(); Object.defineProperty(hooked.findings[0], 'message', { enumerable: true, get() { reads++; return 'version-source'; } });
  assert.equal(parseOfflinePreflightResult(hooked), null); assert.equal(reads, 0);
});

test('report filters preserve all nine statuses, emitted row identities and complete counts without mutation', () => {
  const result = parseOfflinePreflightResult(report(18));
  assert.ok(result);
  const before = JSON.stringify(result);
  Object.freeze(result); Object.freeze(result.findings); result.findings.forEach(Object.freeze);
  Object.freeze(result.summary); Object.freeze(result.summary.counts);
  const all = selectOfflinePreflightFindings(result, 'all');
  assert.equal(all.rows, result.findings);
  assert.deepEqual(all, { rows: result.findings, reported: 18, visible: 18, omitted: 0 });
  for (const [index, status] of OFFLINE_CORE_STATUSES.entries()) {
    const selected = selectOfflinePreflightFindings(result, status);
    assert.deepEqual(selected.rows.map((row) => row.ordinal), [index, index + 9]);
    assert.equal(selected.rows[0], result.findings[index]); assert.equal(selected.rows[1], result.findings[index + 9]);
    assert.equal(selected.reported, 2); assert.equal(selected.visible, 2); assert.equal(selected.omitted, 0);
  }
  assert.equal(JSON.stringify(result), before);
});

test('report filters distinguish genuinely zero findings from an omitted-only status', () => {
  const empty = parseOfflinePreflightResult(report(0));
  assert.ok(empty);
  for (const filter of ['all', 'FAIL']) assert.deepEqual(selectOfflinePreflightFindings(empty, filter), { rows: [], reported: 0, visible: 0, omitted: 0 });
  const raw = report(129);
  raw.findings.forEach((finding) => { finding.status = 'PASS'; });
  raw.summary.counts = Object.fromEntries(OFFLINE_CORE_STATUSES.map((status) => [status, status === 'PASS' ? 128 : status === 'FAIL' ? 1 : 0]));
  const result = parseOfflinePreflightResult(raw);
  assert.ok(result);
  const all = selectOfflinePreflightFindings(result, 'all'), pass = selectOfflinePreflightFindings(result, 'PASS');
  assert.equal(all.visible, 128); assert.equal(all.reported, 129); assert.equal(all.omitted, 1);
  assert.equal(pass.visible, 128); assert.equal(pass.reported, 128); assert.equal(pass.omitted, 0);
  assert.deepEqual(selectOfflinePreflightFindings(result, 'FAIL'), { rows: [], reported: 1, visible: 0, omitted: 1 });
  assert.deepEqual(selectOfflinePreflightFindings(result, 'MISSING'), { rows: [], reported: 0, visible: 0, omitted: 0 });
});

test('phase/outcome/content correlations distinguish complete-negative, refusal, incomplete and sticky Unknown', () => {
  const done = status(3, terminal()); assert.ok(parseOfflinePreflightStatus(done));
  assert.equal(parseOfflinePreflightStatus(done).operation.result.summary.counts.FAIL, 1);
  assert.ok(parseOfflinePreflightStatus(status(1, operation())));
  assert.ok(parseOfflinePreflightStatus(status(2, terminal('refused'))));
  const unknown = operation({ phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' });
  assert.ok(parseOfflinePreflightStatus(status(4, unknown, 'cleanup-unknown')));
  assert.equal(offlineOperationProgress(unknown, terminal()), false);
  for (const op of [operation({ outcome: 'complete' }), operation({ phase: 'running' }), operation({ result: report() }),
    terminal('refused', { result: report() }), terminal('refused', { reason: 'none' }), terminal('complete', { result: null }),
    terminal('complete', { result: report(9, NEXT_CONTENT) }), { ...unknown, result: report() }, { ...unknown, reason: 'none' },
    operation({ context: { ...context(), platform: 'ios' } }), operation({ ownerGeneration: OWNER.toUpperCase() }), operation({ operationId: `${OP}\n` })])
    assert.equal(parseOfflinePreflightStatus(status(3, op)), null);
  for (const revision of [-0, -1, 1.5, 0xffff_ffff, Infinity]) assert.equal(parseOfflinePreflightStatus(status(revision)), null);
  for (const availability of ['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified'])
    assert.ok(parseOfflinePreflightStatus(status(0, null, availability)));
  assert.equal(parseOfflinePreflightStatus({ ...status(), stdout: 'PRIVATE' }), null);
});

test('snapshot comparison is exact observed DATA; Save intent/results never hash or replace dirty drafts', () => {
  let state = workspace(), project = state.projects['project-1'];
  assert.deepEqual(project.savedConfigContent, CONTENT);
  state = workspaceReducer(state, { type: 'edit', projectId: project.project.id, path: 'android.enabled', value: false });
  const dirty = state.projects['project-1'].draft;
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: 'project-1', requestId: 2 }); assert.equal(state.projects['project-1'].savedConfigContent, null);
  state = workspaceReducer(state, { type: 'snapshot-done', projectId: 'project-1', requestId: 2, snapshot: snapshot(NEXT_CONTENT), observedAt: 2 });
  project = state.projects['project-1']; assert.deepEqual(project.savedConfigContent, NEXT_CONTENT); assert.equal(project.draft, dirty); assert.equal(isDirty(project), true);
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: 'project-1', requestId: 3 });
  state = workspaceReducer(state, { type: 'config-save-intent', projectId: 'project-1' });
  assert.equal(state.projects['project-1'].savedConfigContent, null); assert.equal(state.projects['project-1'].snapshotRequest, null);
  const late = workspaceReducer(state, { type: 'snapshot-done', projectId: 'project-1', requestId: 3, snapshot: snapshot(), observedAt: 3 }); assert.equal(late, state);
  for (const result of ['saved', 'unchanged']) {
    const base = workspace(), event = savedEvent(base.projects['project-1'], result), next = workspaceReducer(base, event);
    assert.equal(next.projects['project-1'].savedConfigContent, null); assert.equal(next.projects['project-1'].snapshotPredatesSave, true);
  }
  assert.equal(savedConfigFromSnapshot({ ...snapshot(), config: { ...snapshot().config, state: 'invalid' } }), null);
  const missing = snapshot(); delete missing.config.content; assert.equal(savedConfigFromSnapshot(missing), null);
  assert.equal(parseSavedConfigContent({ ...CONTENT, sha256: `${CONTENT.sha256}\n` }), null);
  let reads = 0; const bad = { get config() { reads++; return snapshot().config; } };
  assert.equal(savedConfigFromSnapshot(bad), null); assert.equal(reads, 0);
});

test('connect/page/status/acknowledgement never run; dirty draft uses only observed content and Start consumes once', async (t) => {
  const h = harness(t); await h.ready;
  h.dispatch({ type: 'edit', projectId: 'project-1', path: 'android.enabled', value: false });
  h.controller.setVisible(false); h.controller.setVisible(true); await h.controller.checkStatus();
  assert.equal(h.calls.length, 0);
  const draft = h.project.draft, op = await reviewed(h);
  assert.equal(h.state.project.dirtyDraft, true); assert.deepEqual(h.calls[0].input.savedConfig, CONTENT);
  assert.deepEqual(Object.keys(h.calls[0].input).sort(), ['baselineGeneration', 'draftRevision', 'projectId', 'savedConfig']);
  h.controller.setAcknowledged(OTHER, OWNER, true); assert.equal(h.state.consent.acknowledged, false);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.length, 1);
  h.controller.setAcknowledged(OP, OWNER, true); assert.equal(h.calls.length, 1);
  const pending = h.controller.start(OP, OWNER); assert.equal(h.state.consent, null); assert.equal(h.calls.length, 2);
  await h.controller.start(OP, OWNER); assert.equal(h.calls.length, 2);
  h.reply(h.calls[1], status(2, terminal('complete', { context: op.context }))); await pending;
  assert.equal(h.state.status.operation.outcome, 'complete'); assert.equal(h.state.status.operation.result.summary.counts.FAIL, 1);
  assert.equal(h.state.historical, false); assert.equal(h.project.draft, draft); assert.equal(isDirty(h.project), true);
});

test('every relevant workspace intent retires consent before even unchanged reducer outcomes and sends one original STOP', async (t) => {
  const events = [
    { type: 'switch', projectId: 'absent' }, { type: 'new-draft', projectId: 'project-1', draft: {} },
    { type: 'snapshot-done', projectId: 'project-1', requestId: 999, snapshot: snapshot(), observedAt: 2 },
    { type: 'snapshot-failed', projectId: 'project-1', requestId: 999, error: { code: 'busy', message: 'fixture', retryable: false } },
    { type: 'edit', projectId: 'project-1', path: 'android.enabled', value: true },
    { type: 'remove-forbidden', projectId: 'project-1', reviewId: 999, paths: [] },
    { type: 'undo-removal', projectId: 'project-1', removalId: 999 }, { type: 'forget-removal', projectId: 'project-1', removalId: 999 },
    { type: 'adopt-suggestion', projectId: 'project-1', requestId: 999 }, { type: 'reset', projectId: 'project-1' },
    { type: 'snapshot-start', projectId: 'project-1', requestId: 2 }, { type: 'config-save-intent', projectId: 'project-1' },
    savedEvent(workspace().projects['project-1']),
    { type: 'config-save-recovery', projectId: 'project-1', attention: { projectId: 'project-1', phase: 'final', nativeFinality: 'settled',
      coreOutcome: { journal: 'recovery_required', resources: 'settled' } } },
  ];
  for (const event of events) {
    const h = harness(t); const op = await reviewed(h);
    h.controller.setAcknowledged(OP, OWNER, true);
    h.controller.beforeWorkspaceAction(event); assert.equal(h.state.consent, null);
    h.dispatch(event); h.controller.cancel();
    assert.equal(h.calls.filter((call) => call.kind === 'cancel').length, 1, event.type);
    assert.deepEqual(h.calls.at(-1).input, { operationId: OP, ownerGeneration: OWNER });
    h.reply(h.calls.at(-1), status(2, terminal('cancelled', { context: op.context }))); await flush();
    h.emit(status(1, op)); assert.equal(h.state.consent, null); h.controller.dispose();
  }
});

test('late Prepare replies retire the ORIGINAL intent; events/status alone are never Run authority', async (t) => {
  const h = harness(t); await h.ready;
  void h.controller.prepare(); const call = h.calls[0], op = operation({ context: context(call.input) });
  h.emit(status(1, op)); assert.equal(h.state.consent, null);
  h.controller.setAcknowledged(OP, OWNER, true); await h.controller.start(OP, OWNER); assert.equal(h.calls.length, 1);
  h.dispatch({ type: 'edit', projectId: 'project-1', path: 'android.enabled', value: false }); assert.equal(h.calls.length, 1);
  h.reply(call, status(1, op)); await flush();
  assert.equal(h.state.consent, null); assert.equal(h.calls[1].kind, 'cancel');
  assert.equal(h.state.status.operation.operationId, OP); assert.equal(h.state.historical, true);
});

test('Cancel can retire unstarted/lost-reply intent without Start; next explicit review begins unchecked', async (t) => {
  const h = harness(t); await h.ready;
  void h.controller.prepare(); const op = operation({ context: context(h.calls[0].input) });
  h.emit(status(1, op)); assert.equal(h.controller.cancel(), true);
  h.reply(h.calls.at(-1), status(2, terminal('cancelled', { context: op.context }))); await flush();
  assert.equal(h.calls.some((call) => call.kind === 'start'), false); assert.equal(h.state.pending, null);
  const next = await reviewed(h, { operationId: OTHER }); assert.equal(next.operationId, OTHER);
  h.controller.setAcknowledged(OP, OWNER, true); assert.equal(h.state.consent.acknowledged, false);
  // The original Prepare reply can arrive after the new review; it is not adopted.
  h.calls[0].resolve(status(1, op)); await flush(); assert.equal(h.state.consent.operationId, OTHER);
});

test('started work survives Releases unmount, while context changes STOP once and retain historical report', async (t) => {
  const h = harness(t), op = await reviewed(h), call = start(h, op);
  h.reply(call, status(2, operation({ context: op.context, phase: 'running', intentUsable: false }))); await flush();
  h.controller.setVisible(false); assert.equal(h.calls.filter((x) => x.kind === 'cancel').length, 0); assert.ok(offlinePreflightOwnerReason(h.state));
  assert.equal(h.controller.canCancel(), true);
  h.dispatch({ type: 'config-save-intent', projectId: 'project-1' });
  h.controller.selectionIntent(); assert.equal(h.calls.filter((x) => x.kind === 'cancel').length, 1);
  h.emit(status(4, terminal('complete', { context: op.context }))); assert.equal(h.state.status.operation.outcome, 'complete');
  assert.equal(h.state.historical, true); assert.equal(h.state.consent, null);
});

test('original local expiry is not renewed by polling and stale consent never sends Start', async (t) => {
  const h = harness(t), op = await reviewed(h); const deadline = h.state.consent.deadline;
  h.clock(deadline - 1); await h.controller.checkStatus(); assert.equal(h.state.consent.deadline, deadline);
  h.clock(deadline); h.controller.setAcknowledged(OP, OWNER, true);
  assert.equal(h.state.consent, null); assert.equal(h.calls.at(-1).kind, 'cancel');
  h.emit(status(2, op)); await h.controller.start(OP, OWNER); assert.equal(h.calls.some((x) => x.kind === 'start'), false);
});

test('lost Start reply cannot rearm or retry; exact terminal status can settle only its original operation', async (t) => {
  const h = harness(t), op = await reviewed(h), call = start(h, op); let messages = 0;
  call.reject({ get message() { messages++; return 'PRIVATE'; } }); await flush();
  assert.equal(messages, 0); assert.equal(h.state.consent, null); assert.ok(offlinePreflightOwnerReason(h.state));
  await h.controller.start(OP, OWNER); assert.equal(h.calls.filter((x) => x.kind === 'start').length, 1);
  h.emit(status(3, terminal('cancelled', { context: op.context }))); await h.controller.checkStatus();
  assert.equal(h.state.originalUnconfirmed, false); assert.equal(h.state.consent, null);
  assert.equal(h.calls.filter((x) => x.kind === 'prepare').length, 1);
});

test('Prepare preallocation refusals release no assumed owner, but a contradictory admission fails closed', async (t) => {
  const h = harness(t); await h.ready;
  void h.controller.prepare(); h.calls[0].reject({ code: 'offline_preflight_busy' }); await flush();
  assert.equal(h.state.pending, null); assert.equal(h.state.originalUnconfirmed, false); assert.equal(h.state.integrityFailed, false);
  assert.equal(h.calls.length, 1);
  void h.controller.prepare(); const op = operation({ context: context(h.calls[1].input) });
  h.emit(status(1, op)); h.calls[1].reject({ code: 'offline_preflight_busy' }); await flush();
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.consent, null); assert.equal(h.controller.canCancel(), true);
});

test('unknown, foreign replacement, duplicate revision conflicts and counter exhaustion stay fail closed', async (t) => {
  for (const kind of ['unknown', 'foreign', 'revision-conflict', 'counter']) {
    const h = harness(t), op = await reviewed(h); start(h, op);
    h.emit(status(2, operation({ context: op.context, phase: 'running', intentUsable: false })));
    if (kind === 'unknown') h.emit(status(3, operation({ context: op.context, phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' }), 'cleanup-unknown'));
    if (kind === 'foreign') h.emit(status(3, terminal('complete', { operationId: OTHER, context: op.context })));
    if (kind === 'revision-conflict') h.emit(status(2, operation({ context: op.context, phase: 'stopping', intentUsable: false })));
    if (kind === 'counter') h.emit(status(OFFLINE_PREFLIGHT_COUNTER_MAX, operation({ context: op.context, phase: 'running', intentUsable: false })));
    assert.ok(h.state.nativeBlocked || h.state.generationLost); assert.equal(h.state.consent, null); assert.ok(offlinePreflightOwnerReason(h.state));
    if (kind === 'unknown') { h.emit(status(4, terminal('complete', { context: op.context }))); assert.equal(h.state.status.operation.phase, 'unknown'); assert.equal(h.state.status.operation.result, null); }
    h.controller.beginConnection(); let adopted = 0;
    await h.controller.connect({ ...h.api, subscribeOfflinePreflight: async () => { adopted++; return () => {}; } });
    assert.equal(adopted, 0); await h.controller.prepare(); assert.equal(h.calls.filter((x) => x.kind === 'prepare').length, 1);
    h.controller.dispose();
  }
});

test('late subscription setup is detached; replacing an active connection retains only the original observer', async (t) => {
  const gate = deferred(), h = harness(t, { listenGate: gate });
  h.controller.beginConnection();
  let newer = 0; const next = { ...h.api, subscribeOfflinePreflight: async () => { newer++; return () => {}; } };
  await h.controller.connect(next); gate.resolve(); await h.ready;
  assert.equal(h.subscriptions[0].closed, true); assert.equal(newer, 1);
  h.subscriptions[0].callback(null); assert.equal(h.state.integrityFailed, false);
  const active = harness(t), op = await reviewed(active); start(active, op);
  active.emit(status(2, operation({ context: op.context, phase: 'running', intentUsable: false })));
  active.controller.beginConnection(); const count = active.subscriptions.length;
  await active.controller.connect({ ...active.api }); assert.equal(active.subscriptions.length, count);
  assert.equal(active.subscriptions[0].closed, false); assert.equal(active.calls.filter((x) => x.kind === 'cancel').length, 1);
  active.emit(status(3, terminal('cancelled', { context: op.context }))); assert.equal(active.state.nativeBlocked, true);
});

test('unqualified/preview and competing owners cannot become frontend force-enable paths', async (t) => {
  const h = harness(t, { initial: status(0, null, 'runtime-unqualified') }); await h.ready;
  await h.controller.prepare(); assert.equal(h.calls.length, 0); assert.match(h.controller.prepareReason(), /disabled/);
  const blocked = harness(t); await blocked.ready; blocked.other('Original native owner is unverified.');
  await blocked.controller.prepare(); assert.equal(blocked.calls.length, 0);
  let invoked = 0; const unavailable = createNativeApi('unavailable', async () => { invoked++; return status(); });
  await assert.rejects(unavailable.prepareOfflinePreflight(request())); assert.equal(invoked, 0);
  for (const method of ['prepareOfflinePreflight', 'startOfflinePreflight', 'offlinePreflightStatus', 'cancelOfflinePreflight', 'subscribeOfflinePreflight'])
    await assert.rejects(previewApi[method](request()), (error) => error.code === 'offline_preflight_unavailable');
  let reads = 0;
  assert.equal(offlinePreflightError({ code: 'offline_preflight_owner', get message() { reads++; return 'PRIVATE'; } }).code, 'offline_preflight_owner');
  assert.equal(offlinePreflightError({ get code() { reads++; return 'offline_preflight_busy'; } }).code, 'offline_preflight_protocol'); assert.equal(reads, 0);
});

test('native unusable consent and a typed expired Start outcome never restore acknowledgement or retry', async (t) => {
  const expired = harness(t), op = await reviewed(expired);
  expired.controller.setAcknowledged(OP, OWNER, true);
  expired.emit(status(2, { ...op, intentUsable: false }));
  assert.equal(expired.state.consent, null); assert.equal(expired.controller.canCancel(), true);
  await expired.controller.start(OP, OWNER); assert.equal(expired.calls.some((call) => call.kind === 'start'), false);
  expired.controller.cancel(); assert.equal(expired.calls.filter((call) => call.kind === 'cancel').length, 1);

  const refused = harness(t), current = await reviewed(refused), call = start(refused, current);
  refused.reply(call, status(2, terminal('refused', { context: current.context }))); await flush();
  assert.equal(refused.state.pending, null); assert.equal(refused.state.originalUnconfirmed, false);
  assert.equal(refused.state.consent, null); assert.equal(refused.state.status.operation.reason, 'intent-expired');
  await refused.controller.start(OP, OWNER); assert.equal(refused.calls.filter((item) => item.kind === 'start').length, 1);
  assert.equal(refused.calls.filter((item) => item.kind === 'prepare').length, 1);
});

test('synchronous subscribers can retire Prepare and a consumed unsent Start before any handoff', async (t) => {
  const beforePrepare = harness(t); await beforePrepare.ready;
  let retiredPrepare = false;
  const offPrepare = beforePrepare.controller.subscribe(() => {
    if (!retiredPrepare && beforePrepare.state.pending === 'prepare') {
      retiredPrepare = true; beforePrepare.controller.selectionIntent();
    }
  });
  await beforePrepare.controller.prepare(); offPrepare();
  assert.equal(beforePrepare.calls.length, 0); assert.equal(beforePrepare.state.pending, null);
  assert.equal(beforePrepare.state.originalUnconfirmed, false);

  const beforeStart = harness(t); await reviewed(beforeStart);
  beforeStart.controller.setAcknowledged(OP, OWNER, true);
  let retiredStart = false;
  const offStart = beforeStart.controller.subscribe(() => {
    if (!retiredStart && beforeStart.state.pending === 'start') {
      retiredStart = true; beforeStart.controller.selectionIntent();
    }
  });
  await beforeStart.controller.start(OP, OWNER); offStart();
  assert.equal(beforeStart.calls.some((call) => call.kind === 'start'), false);
  assert.equal(beforeStart.calls.filter((call) => call.kind === 'cancel').length, 1);
  assert.equal(beforeStart.state.consent, null);
  beforeStart.reply(beforeStart.calls.at(-1), status(2, terminal('cancelled'))); await flush();
  assert.equal(beforeStart.state.originalUnconfirmed, false);
});

test('retiring passive display data does not release its original unresolved promise from preflight admission', async (t) => {
  const catalog = await previewApi.catalog();
  const info = { runtime: { state: 'available' }, capabilities: { methods: [
    'environment.requirements', 'release.version.observe', 'config.validate', 'github.setup.propose',
  ].map((method) => ({ method, available: true, reason: '' })) } };
  for (const kind of ['environment', 'version', 'inputs', 'github']) {
    const h = harness(t); await h.ready;
    const original = deferred(); let calls = 0;
    const api = { mode: 'native' };
    const selected = () => h.project, other = () => offlinePreflightOwnerReason(h.state);
    let controller, invoke;
    if (kind === 'environment') {
      controller = new EnvironmentController(selected, other);
      api.environmentRequirements = () => { calls++; return original.promise; }; invoke = () => controller.refresh();
    } else if (kind === 'version') {
      controller = new ReleaseVersionController(selected, () => false, other);
      api.observeReleaseVersion = () => { calls++; return original.promise; }; invoke = () => controller.read();
    } else if (kind === 'inputs') {
      controller = new ReleaseInputGuidanceController(selected, () => false, () => {}, other);
      api.validate = () => { calls++; return original.promise; }; invoke = () => controller.refresh();
    } else {
      controller = new GitHubSetupController(selected, undefined, other);
      api.proposeGitHubSetup = () => { calls++; return original.promise; }; invoke = () => controller.propose();
    }
    t.after(() => controller.dispose());
    controller.setConnection(api, info); controller.syncProject();
    if (kind === 'inputs') controller.setCatalog(catalog);
    if (kind === 'github') {
      assert.equal(controller.admitHelp(catalog.githubSetup), true);
      controller.setCoordinate('toolingRepository', 'inert/toolkit'); controller.setCoordinate('toolingSha', 'f'.repeat(40));
    }
    h.other(() => controller.passiveBusyReason());
    const pending = invoke(); assert.equal(calls, 1, kind); assert.ok(controller.passiveBusyReason(), kind);
    h.dispatch({ type: 'edit', projectId: 'project-1', path: 'android.enabled', value: false }); controller.syncProject();
    assert.ok(!controller.getSnapshot().pending, kind);
    await h.controller.prepare(); assert.equal(h.calls.length, 0, kind);
    original.reject({ code: 'inert-refusal' }); await pending;
    assert.equal(controller.passiveBusyReason(), null, kind); assert.equal(h.controller.prepareReason(), null, kind);
    controller.dispose();
  }
});

test('passive/evidence admission uses reciprocal callback, while source integration keeps original Cancel/status reachable', () => {
  const reason = () => 'Saved offline checks own the original slot.';
  assert.equal(new EnvironmentController(() => null, reason).startReason(), reason());
  assert.equal(new ReleaseVersionController(() => null, () => false, reason).startReason(), reason());
  assert.equal(new ReleaseInputGuidanceController(() => null, () => false, () => {}, reason).startReason(), reason());
  assert.equal(new GitHubSetupController(() => null, undefined, reason).startReason(), reason());
  assert.equal(new CandidateEvidenceController(reason).startReason(), reason());
  const metadata = new MetadataTextEditController({ selectedProject: () => null, otherEditReason: reason, otherOperationReason: reason });
  assert.equal(metadata.loadReason(), reason()); assert.equal(metadata.validateReason(), reason());
  const app = source('App.tsx'), bridge = source('bridge.ts'), ui = source('components/OfflinePreflight.tsx');
  const retire = app.indexOf('offlinePreflightControllerRef.current?.beforeWorkspaceAction(action)');
  assert.ok(retire >= 0 && retire < app.indexOf('workspaceReducer(previous, action)') && retire < app.indexOf('if (next === previous) return'));
  assert.match(app, /new OfflinePreflightController/); assert.match(app, /useSyncExternalStore\(offlinePreflight.subscribe/);
  assert.match(app, /savedCommandBusy = useCallback\(\(excludeVersion = false\) => preflightBusy\(\) \?\? androidBusy\(\)/);
  assert.match(app, /!excludeVersion && versionEditControllerRef\.current \? versionOwnerReason\(/);
  assert.match(app, /otherOperationReason: \(\) => androidBusy\(\) \?\? savedCommandPrerequisiteReason\(\)/);
  assert.match(app, /page !== 'releases'.*OfflinePreflight/); assert.match(app, /onApply=.*config-save-intent/);
  assert.match(app, /new GitHubConnectionController\(savedCommandBusy\)/); assert.match(app, /new CandidateEvidenceController\(savedCommandBusy\)/);
  assert.match(app, /otherOperationReason: savedCommandBusy/); assert.match(app, /savedCommandBusy\(\).*diagnosticsOwnerReason/);
  assert.match(app, /passivePending\.current > 0/); assert.match(app, /environment\.passiveBusyReason\(\)/);
  assert.match(app, /\(connection\.status \?\? connection\.retained\)\?\.session/);
  assert.match(bridge, /invoke<unknown>\(command, body\)/); assert.match(bridge, /encodeOfflinePreflightRequest\(command, value\)/);
  assert.doesNotMatch(ui, /controller\.dispose|\.message\s*\}|dangerouslySetInnerHTML/);
  assert.match(ui, /Run offline checks \(Android\)/); assert.match(ui, /Core builds are disabled/); assert.match(ui, /Run saved offline checks/);
  assert.match(ui, /checkbox/); assert.match(ui, /Check original status/); assert.match(ui, /Cancel original offline checks/);
  assert.match(ui, /useState<OfflinePreflightFindingFilter>\('all'\)/);
  assert.match(ui, /<label htmlFor=\{filterId\}>Filter findings by status<\/label>/);
  assert.match(ui, /<select id=\{filterId\} value=\{filter\} aria-describedby=\{`\$\{filterId\}-help`\}/);
  assert.match(ui, /Filter the checks shown below; this does not run checks again/);
  assert.match(ui, /key=\{`\$\{op\.ownerGeneration\}:\$\{op\.operationId\}`\}/);
  assert.match(ui, /selected\.rows\.map\(\(finding\) => <li key=\{finding\.ordinal\} value=\{finding\.ordinal \+ 1\}>/);
  assert.match(ui, /summary\.counts\[status\]/); assert.match(ui, /Omitted findings can include negative statuses/);
  assert.match(ui, /Historical \/ stale context/); assert.match(ui, /Complete is not PASS or release readiness/);
  assert.match(ui, /Matching findings were reported, but none are included/); assert.match(ui, /No findings were reported for this filter/);
  assert.match(OFFLINE_PREFLIGHT_DISCLOSURE, /Only run a project you trust/); assert.match(OFFLINE_PREFLIGHT_DISCLOSURE, /contact the network/);
  assert.match(OFFLINE_PREFLIGHT_DISCLOSURE, /not a network-isolation or sandbox guarantee/); assert.match(OFFLINE_PREFLIGHT_DISCLOSURE, /does not undo effects/);
  assert.doesNotMatch(app, /No builds or release operations/);
});

test('startup busy/null to unqualified or unsupported status does not manufacture a retained owner', async (t) => {
  for (const availability of ['runtime-unqualified', 'unsupported-platform']) {
    const h = harness(t, { initial: status(0, null, 'busy') }); await h.ready;
    assert.equal(h.state.status.operation, null); assert.equal(h.state.nativeBlocked, false);
    assert.equal(h.state.integrityFailed, false); assert.equal(offlinePreflightOwnerReason(h.state), null);
    assert.match(h.controller.prepareReason(), /native slot/);
    await h.controller.prepare(); assert.equal(h.calls.length, 0);
    // Capability changes are new native observations, never mutable fields at
    // the same revision and never evidence of an original execution owner.
    h.emit(status(1, null, availability)); await h.controller.checkStatus();
    assert.equal(h.state.status.availability, availability); assert.equal(h.state.status.statusRevision, 1);
    assert.equal(h.state.status.operation, null); assert.equal(h.state.nativeBlocked, false);
    assert.equal(h.state.integrityFailed, false); assert.equal(h.state.observationIssue, null);
    assert.equal(h.state.originalUnconfirmed, false); assert.equal(h.state.pending, null);
    assert.equal(offlinePreflightOwnerReason(h.state), null); assert.equal(h.controller.canCancel(), false);
    assert.match(h.controller.prepareReason(), availability === 'runtime-unqualified' ? /disabled/ : /unavailable/);
    assert.ok(h.controller.runReason()); await h.controller.prepare(); assert.equal(h.calls.length, 0);
  }
});

test('real document-lost/null remains sticky through later unavailable status and reconnect', async (t) => {
  const h = harness(t, { initial: status(0, null, 'busy') }); await h.ready;
  h.emit(status(1, null, 'document-lost'));
  assert.equal(h.state.status.operation, null); assert.equal(h.state.nativeBlocked, true);
  assert.equal(h.state.integrityFailed, false); assert.ok(offlinePreflightOwnerReason(h.state));
  h.emit(status(2, null, 'runtime-unqualified')); await h.controller.checkStatus();
  assert.equal(h.state.nativeBlocked, true); assert.ok(offlinePreflightOwnerReason(h.state));
  await h.controller.prepare(); assert.equal(h.calls.length, 0);
  const original = h.subscriptions[0]; let adopted = 0;
  h.controller.beginConnection();
  await h.controller.connect({ ...h.api, subscribeOfflinePreflight: async () => { adopted++; return () => {}; } });
  assert.equal(adopted, 0); assert.equal(h.subscriptions.length, 1); assert.equal(original.closed, false);
  assert.equal(h.state.nativeBlocked, true); assert.equal(h.controller.canCheckStatus(), true);
  assert.ok(offlinePreflightOwnerReason(h.state)); assert.equal(h.calls.length, 0);
});

test('availability-only same-revision disagreement is still a protocol failure', async (t) => {
  const h = harness(t, { initial: status(0, null, 'busy') }); await h.ready;
  h.emit(status(0, null, 'runtime-unqualified'));
  assert.equal(h.state.status.availability, 'busy');
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.nativeBlocked, true);
  assert.ok(offlinePreflightOwnerReason(h.state)); await h.controller.prepare(); assert.equal(h.calls.length, 0);
});
