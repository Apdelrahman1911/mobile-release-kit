// Pure DTO/promise/source integration checks; no renderer/native qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { LifecycleEvidenceController, documentPaths, evidenceStages, lifecycleEvidenceRequestFits,
  parseLifecycleEvidence, parseLifecycleEvidenceStatus, releaseEvidenceHelp, SAVED_EVIDENCE_WARNING } from '../src/lifecycleEvidence.ts';
import { parseCandidateEvidence, parseEvidenceStatus } from '../src/candidateEvidence.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
const fixtures = JSON.parse(readFileSync(new URL('./fixtures/lifecycle-evidence.json', import.meta.url), 'utf8'));
const clone = structuredClone;
const wire = (value) => JSON.parse(JSON.stringify(value));
const FIRST = { selectionId: 'evidence-local', displayName: 'Saved final folder', stage: 'candidate' };
const SECOND = { selectionId: 'evidence-new', displayName: 'External final folder', stage: 'external-testing' };
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let i = 0; i < 14; i++) await Promise.resolve(); };
function status(revision = '0', change = {}) { return { schemaVersion: 1, revision, availability: 'available', phase: 'idle', selection: null, operation: null, result: null, problem: null, ...clone(change) }; }
function selected(revision = '2', folder = FIRST, operationId = '1') { return status(revision, { phase: 'selected', selection: folder, operation: { operationId, kind: 'choose', selectionId: null, stage: folder.stage } }); }
function observing(revision = '3', folder = FIRST, operationId = '2') { return status(revision, { phase: 'observing', selection: folder, operation: { operationId, kind: 'observe', selectionId: folder.selectionId, stage: folder.stage } }); }
function observed(revision = '4', folder = FIRST, operationId = '2', result = fixtures.androidCandidate) { return { ...observing(revision, folder, operationId), phase: 'observed', result: clone(result) }; }
function harness(t, initial = status(), mode = 'native', otherReason = () => null) {
  let registry = clone(initial), sequence = 0; const calls = [], reads = [], timers = new Map();
  t.mock.method(globalThis, 'setTimeout', (callback, milliseconds) => { assert.equal(milliseconds, 300); const id = ++sequence; timers.set(id, callback); return id; });
  t.mock.method(globalThis, 'clearTimeout', (id) => timers.delete(id));
  const issue = (kind, args) => { const work = deferred(); calls.push({ kind, args, ...work }); return work.promise; };
  const api = { mode, releaseEvidenceStatus: () => { calls.push({ kind: 'status', args: {} }); return reads.length ? reads.shift().promise : Promise.resolve(clone(registry)); },
    chooseReleaseEvidenceFolder: (stage) => issue('choose', { stage }), observeReleaseEvidence: (selectionId) => issue('observe', { selectionId }),
    cancelReleaseEvidence: (operationId, selectionId) => issue('cancel', { operationId, selectionId }) };
  const controller = new LifecycleEvidenceController(otherReason);
  const last = (kind) => calls.filter((call) => call.kind === kind).at(-1);
  t.after(() => { controller.dispose(); assert.equal(timers.size, 0); });
  return { controller, api, calls, timers, ready: controller.connect(api), last,
    get state() { return controller.getSnapshot(); }, count: (kind) => calls.filter((call) => call.kind === kind).length,
    registry(value) { registry = clone(value); }, reply(kind, value) { registry = clone(value); last(kind).resolve(clone(value)); },
    deferRead() { const work = deferred(); reads.push(work); return work; },
    tick() { assert.equal(timers.size, 1); const [id, callback] = [...timers][0]; timers.delete(id); callback(); } };
}
test('13 shared core projections retain real stage layouts and exact false assurances', () => {
  assert.equal(Object.keys(fixtures).length, 13);
  for (const [name, value] of Object.entries(fixtures)) {
    const parsed = parseLifecycleEvidence(value); assert.ok(parsed, name); assert.deepEqual(wire(parsed), value);
    assert.equal(Object.isFrozen(parsed), true); assert.equal(Object.isFrozen(parsed.documents), true);
    assert.deepEqual(parsed.documents.map((doc) => doc.path), documentPaths[parsed.stage]);
    assert.equal(parsed.assurance.documentsOnly, true);
    for (const flag of ['artifactBytesVerified', 'workflowAuthenticated', 'storeStateObserved', 'comparedWithSourceProject', 'releaseReady', 'recoveryAuthorized']) assert.equal(parsed.assurance[flag], false);
    assert.equal(parseCandidateEvidence(value), null);
  }
  assert.deepEqual(evidenceStages.map((stage) => documentPaths[stage].length), [3, 5, 10]);
  assert.notDeepEqual(fixtures.iosRecordedRetry.history[0].recordedRuns, fixtures.iosRecordedRetry.summary.recordedRuns);
  assert.equal(parseLifecycleEvidence(fixtures.iosRecordedRetry).history[0].recordedRuns.executedBy.runId, '9007199254740993');
});
test('closed history does not normalize paths, order, missing nullable fields or predecessor hashes', () => {
  for (const change of [
    (v) => { v.documents[0].path = '../private'; }, (v) => { v.documents.reverse(); },
    (v) => { v.history.reverse(); }, (v) => { v.history[1].previousReceiptSha256 = 'f'.repeat(64); },
    (v) => { delete v.history[0].previousReceiptSha256; }, (v) => { v.history[0].intentSha256 = 'f'.repeat(64); },
    (v) => { v.history[0].receiptSha256 = 'f'.repeat(64); }, (v) => { v.history[0].recordedReadback = 'x'.repeat(65); },
    (v) => { v.history[0].recordedRuns.executedBy.runId = 9007199254740993; }, (v) => { v.history[0].recordedRuns.executedBy.attempt = '01'; },
    (v) => { v.history[0].recordedRuns.executedBy = ['1', '1']; }, (v) => { v.stage = 'candidate'; },
  ]) { const value = clone(fixtures.androidProduction); change(value); assert.equal(parseLifecycleEvidence(value), null); }
});
test('guidance has fixed code/message/stage/platform joins rather than untrusted exception text', () => {
  for (const change of [(v) => { v.guidance.message = 'PRIVATE_CANARY'; }, (v) => { v.guidance.code = 'release-ready'; },
    (v) => { v.guidance = clone(fixtures.iosPendingExternal.guidance); }, (v) => { v.guidance.extra = true; }]) {
    const value = clone(fixtures.androidProduction); change(value); assert.equal(parseLifecycleEvidence(value), null);
  }
  const wrongPlatform = clone(fixtures.androidExternal); wrongPlatform.guidance = clone(fixtures.iosPendingExternal.guidance); assert.equal(parseLifecycleEvidence(wrongPlatform), null);
  assert.match(fixtures.iosPendingExternal.guidance.message, /NEW external-testing dispatch/);
  assert.match(fixtures.androidObservedExternal.guidance.message, /not authorization/);
});
test('no partial summaries/history or authority upgrades; bound own-data-only input', () => {
  for (const name of ['missingExternal', 'invalidExternal', 'inconsistentProduction']) {
    let value = clone(fixtures[name]); value.history = clone(fixtures.androidCandidate.history); assert.equal(parseLifecycleEvidence(value), null);
    value = clone(fixtures[name]); value.summary = clone(fixtures.androidCandidate.summary); assert.equal(parseLifecycleEvidence(value), null);
  }
  for (const flag of ['artifactBytesVerified', 'workflowAuthenticated', 'storeStateObserved', 'comparedWithSourceProject', 'releaseReady', 'recoveryAuthorized']) {
    const value = clone(fixtures.androidCandidate); value.assurance[flag] = true; assert.equal(parseLifecycleEvidence(value), null);
  }
  let reads = 0; const value = clone(fixtures.androidCandidate); Object.defineProperty(value, 'guidance', { enumerable: true, get() { reads++; return fixtures.androidCandidate.guidance; } });
  assert.equal(parseLifecycleEvidence(value), null); assert.equal(reads, 0);
  assert.equal(parseLifecycleEvidence({ ...fixtures.androidCandidate, extra: Array(2049).fill(0) }), null);
  assert.equal(parseLifecycleEvidence({ ...fixtures.androidCandidate, extra: 'x'.repeat(65537) }), null);
});
test('stage-bearing native status is distinct from strict legacy status and internally joined', () => {
  assert.ok(parseLifecycleEvidenceStatus(observed())); assert.equal(parseEvidenceStatus(observed()), null);
  for (const change of [(v) => { delete v.operation.stage; }, (v) => { delete v.selection.stage; }, (v) => { v.operation.stage = 'production-submit'; },
    (v) => { v.selection.stage = 'external-testing'; }, (v) => { v.result = clone(fixtures.androidExternal); }, (v) => { v.phase = 'unknown'; v.problem = 'cleanup_unknown'; }]) {
    const value = observed(); change(value); assert.equal(parseLifecycleEvidenceStatus(value), null);
  }
  const legacy = selected(); delete legacy.operation.stage; delete legacy.selection.stage; assert.ok(parseEvidenceStatus(legacy)); assert.equal(parseLifecycleEvidenceStatus(legacy), null);
});
test('request closure permits only a stage at choose and opaque exact original IDs later', () => {
  assert.equal(lifecycleEvidenceRequestFits('release_evidence_choose', { stage: 'production-submit' }), true);
  assert.equal(lifecycleEvidenceRequestFits('release_evidence_choose', {}), false);
  assert.equal(lifecycleEvidenceRequestFits('release_evidence_status', {}), true);
  for (const value of [{ selectionId: FIRST.selectionId, stage: 'external-testing' }, { selectionId: '/private' }, { selectionId: FIRST.selectionId, root: '/private' }]) assert.equal(lifecycleEvidenceRequestFits('release_evidence_observe', value), false);
  assert.equal(lifecycleEvidenceRequestFits('release_evidence_cancel', { operationId: '2', selectionId: FIRST.selectionId }), true);
  assert.equal(lifecycleEvidenceRequestFits('release_evidence_cancel', { selectionId: FIRST.selectionId }), false);
  assert.equal(lifecycleEvidenceRequestFits('release_evidence_cancel', { operationId: '02', selectionId: FIRST.selectionId }), false);
  assert.equal(lifecycleEvidenceRequestFits('artifact_evidence_choose', { stage: 'candidate' }), false);
});
test('bridge uses new fixed routes and rejects wrong stage replies or private error contents', async () => {
  const calls = []; let response = selected();
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return response; });
  await api.chooseReleaseEvidenceFolder('candidate');
  response = status(); await api.releaseEvidenceStatus();
  response = observed(); await api.observeReleaseEvidence(FIRST.selectionId);
  response = { ...observing(), phase: 'stopping', problem: 'cancelled' }; await api.cancelReleaseEvidence('2', FIRST.selectionId);
  assert.deepEqual(calls, [{ command: 'release_evidence_choose', args: { stage: 'candidate' } }, { command: 'release_evidence_status', args: {} },
    { command: 'release_evidence_observe', args: { selectionId: FIRST.selectionId } }, { command: 'release_evidence_cancel', args: { operationId: '2', selectionId: FIRST.selectionId } }]);
  response = selected(); await assert.rejects(api.chooseReleaseEvidenceFolder('external-testing'), (e) => e.code === 'artifact_evidence_protocol');
  response = status(); await assert.rejects(api.cancelReleaseEvidence('2', FIRST.selectionId), (e) => e.code === 'artifact_evidence_protocol');
  await assert.rejects(api.observeReleaseEvidence('/private'), (e) => e.code === 'artifact_evidence_invalid');
  response = { ...status(), secret: 'PRIVATE_CANARY' }; await assert.rejects(api.releaseEvidenceStatus(), (e) => !JSON.stringify(e).includes('PRIVATE_CANARY'));
});
test('preview and unavailable APIs never fabricate folders or observations', async () => {
  for (const api of [previewApi, createNativeApi('unavailable', async () => { throw Error('must not invoke'); })]) {
    for (const run of [() => api.chooseReleaseEvidenceFolder('candidate'), () => api.releaseEvidenceStatus(), () => api.observeReleaseEvidence(FIRST.selectionId), () => api.cancelReleaseEvidence('2', FIRST.selectionId)]) {
      await assert.rejects(run(), (e) => e.code === 'artifact_evidence_unavailable');
    }
  }
});
test('stage change requires new native choice; observing the old selection cannot reclassify it', async (t) => {
  const h = harness(t, selected()); await h.ready;
  h.controller.setStage('external-testing'); assert.equal(h.state.stage, 'external-testing');
  assert.match(h.controller.observeReason(), /new folder/); await h.controller.observe(); assert.equal(h.count('observe'), 0);
  const choosing = h.controller.choose(); assert.deepEqual(h.last('choose').args, { stage: 'external-testing' });
  h.controller.setStage('production-submit'); assert.equal(h.state.stage, 'external-testing');
  h.reply('choose', selected('5', SECOND, '3')); await choosing;
  assert.equal(h.state.status.selection.stage, 'external-testing'); assert.equal(h.controller.observeReason(), null);
  const observing = h.controller.observe(); assert.deepEqual(h.last('observe').args, { selectionId: SECOND.selectionId });
  h.reply('observe', observed('7', SECOND, '4', fixtures.androidExternal)); await observing;
  assert.equal(h.state.status.result.stage, 'external-testing');
});
test('stage selection is recovered observationally on reconnect, never auto-inspected', async (t) => {
  const h = harness(t, selected('5', SECOND, '3')); await h.ready;
  assert.equal(h.state.stage, 'external-testing'); assert.equal(h.count('observe'), 0); assert.equal(h.count('choose'), 0);
  h.controller.beginConnection(); await h.controller.connect(h.api); assert.equal(h.state.stage, 'external-testing'); assert.equal(h.count('observe'), 0);
});
test('lost first choose reply is acknowledged by exact stage-bound terminal status', async (t) => {
  const h = harness(t); await h.ready; h.controller.setStage('external-testing');
  const held = h.controller.choose(); const original = h.last('choose');
  h.registry(selected('2', SECOND)); h.tick(); await flush();
  assert.equal(h.state.pending, null); assert.equal(h.state.status.phase, 'selected'); assert.equal(h.count('choose'), 1); assert.equal(h.count('observe'), 0);
  original.resolve(selected()); await held; assert.equal(h.state.status.selection.stage, 'external-testing');
});
test('lost first observation reply is recovered by status, not repeated document inspection', async (t) => {
  const h = harness(t, selected()); await h.ready; const held = h.controller.observe();
  h.registry(observed()); h.tick(); await flush(); assert.equal(h.state.pending, null); assert.equal(h.state.status.phase, 'observed');
  assert.equal(h.count('observe'), 1); h.last('observe').reject({ code: 'artifact_evidence_deadline', message: 'PRIVATE' }); await held;
  assert.equal(h.state.status.phase, 'observed'); assert.equal(h.state.error, null);
});
test('wrong-stage lost-reply status latches protocol failure instead of acknowledging a different choice', async (t) => {
  const h = harness(t); await h.ready; h.controller.setStage('external-testing'); const held = h.controller.choose();
  h.registry(selected()); h.tick(); await flush(); assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status, null);
  h.last('choose').resolve(selected()); await held; assert.equal(h.count('observe'), 0);
});
test('same selection or operation ID cannot change purpose or stage at a higher revision', async (t) => {
  const h = harness(t, selected()); await h.ready;
  h.registry(selected('3', { ...FIRST, stage: 'external-testing' })); await h.controller.check(); assert.equal(h.state.integrityFailed, true);
});
test('wrong-purpose legacy command reply is not accepted by the lifecycle controller', async (t) => {
  const h = harness(t); await h.ready; const held = h.controller.choose();
  const old = selected(); delete old.operation.stage; delete old.selection.stage; h.reply('choose', old); await held;
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status, null);
});
test('picker cancellation is terminal only for the original staged choice', async (t) => {
  const h = harness(t); await h.ready; const choosing = h.controller.choose();
  h.reply('choose', status('2', { phase: 'cancelled', operation: { operationId: '1', kind: 'choose', selectionId: null, stage: 'candidate' }, problem: 'cancelled' })); await choosing;
  assert.equal(h.state.pending, null); assert.equal(h.state.status.phase, 'cancelled'); assert.equal(h.count('observe'), 0); assert.equal(h.controller.startReason(), null);
});
test('exact cancellation joins original IDs/stage and stopping blocks stage/saved work', async (t) => {
  const h = harness(t, observing()); await h.ready; const cancel = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: '2', selectionId: FIRST.selectionId });
  h.reply('cancel', { ...observing('4'), phase: 'stopping', problem: 'cancelled' }); await cancel;
  assert.notEqual(h.controller.startReason(), null); h.controller.setStage('production-submit'); assert.equal(h.state.stage, 'candidate');
  await h.controller.choose(); await h.controller.observe(); assert.equal(h.count('choose'), 0); assert.equal(h.count('observe'), 0);
  h.registry({ ...observing('5'), phase: 'cancelled', problem: 'cancelled' }); await h.controller.check(); assert.equal(h.controller.startReason(), null);
});
test('wrong-stage cancellation reply cannot settle or relabel the original job', async (t) => {
  const h = harness(t, observing()); await h.ready; const cancel = h.controller.cancel();
  h.reply('cancel', { ...observing('4', { ...FIRST, stage: 'external-testing' }), phase: 'stopping', problem: 'cancelled' }); await cancel;
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status, null);
});
test('unknown remains sticky and generation retirement discards late invocation data', async (t) => {
  const h = harness(t, selected()); await h.ready; const held = h.controller.observe(); const old = h.last('observe');
  h.controller.beginConnection(); h.registry({ ...observing('4'), phase: 'unknown', problem: 'cleanup_unknown' }); await h.controller.connect(h.api);
  old.resolve(observed()); await held; assert.equal(h.state.status.phase, 'unknown'); assert.equal(h.count('observe'), 1);
  h.registry(observed('5')); await h.controller.check(); assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status.phase, 'unknown');
});
test('unavailable controller performs no folder/read/cancel work', async (t) => {
  const h = harness(t, observed(), 'preview'); await h.ready;
  await h.controller.choose(); await h.controller.observe(); await h.controller.cancel(); await h.controller.check();
  assert.equal(h.state.status, null); assert.deepEqual(h.calls, []); assert.equal(h.timers.size, 0);
});
test('SOURCE integration shares one controller and keeps Recovery alerts independent without an auto-read', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const source = readFileSync(new URL('../src/components/ReleaseEvidence.tsx', import.meta.url), 'utf8');
  const future = readFileSync(new URL('../src/pages/Future.tsx', import.meta.url), 'utf8');
  const artifacts = readFileSync(new URL('../src/pages/Artifacts.tsx', import.meta.url), 'utf8');
  assert.equal((app.match(/new LifecycleEvidenceController/g) ?? []).length, 1); assert.doesNotMatch(app, /new CandidateEvidenceController/);
  assert.match(app, /\['choosing', 'observing', 'stopping', 'unknown'\]\.includes\(evidence.status.phase\)/);
  assert.match(app, /<Releases[^\n]*evidence={<ReleaseEvidence state={evidenceState} controller={releaseEvidence}/);
  assert.match(app, /<Recovery[^\n]*evidenceGuidance={<ReleaseEvidenceGuidance state={evidenceState}/);
  assert.match(artifacts, /<ReleaseEvidence state={state} controller={controller}/);
  for (const text of ['Source project:', 'Evidence folder:', 'unchanged by evidence selection', 'Choose evidence folder', 'Inspect documents', 'Check operation status', 'Request stop',
    'Previous observation · stale', 'Document status and technical details', 'Stages recorded in this folder', 'Not supplied:', 'Project recovery remains unassessed']) assert.ok(source.includes(text), text);
  assert.match(source, /const current = !state.pending && !state.uncertain && !state.integrityFailed/);
  assert.match(source, /\['authorizedBy', 'executedBy', 'producedBy'\]/);
  assert.doesNotMatch(source, /useEffect|\bhref\s*=|\bfetch\s*\(|chooseProject|saveDraft|discardDraft/);
  for (const text of ['File-edit alerts from this session', 'Earlier alerts stay visible', 'Project recovery remains unassessed', 'This is not a clean-state check']) assert.ok(future.includes(text), text);
  assert.equal(SAVED_EVIDENCE_WARNING, 'Saved documents only, not live Store status or retry approval.');
  assert.match(releaseEvidenceHelp.where, /Download and extract.*protected release workflow.*final evidence folder, not your project or ZIP.*nested folders unchanged/);
});
test('SOURCE catalogs, shell permissions and purpose-gated reconciliation include only the new fixed family', () => {
  const source = (relative) => readFileSync(new URL(relative, import.meta.url), 'utf8');
  const quoted = (value) => [...value.matchAll(/"([^"\n]+)"/g)].map((match) => match[1]);
  const core = source('../../src/mobile_release/api/__init__.py');
  const observer = source('../src-tauri/src/installed_shell_observation.rs');
  const methods = quoted(core.split('METHODS = (', 2)[1].split(')\n_FUTURE_ACTIONS', 1)[0]);
  const installed = observer.match(/const METHODS: \[&str; (\d+)\] = \[([^\]]+)\];/);
  assert.ok(installed); assert.equal(Number(installed[1]), 13);
  assert.equal(methods.length, 14); assert.equal(new Set(methods).size, 14);
  assert.deepEqual(quoted(installed[2]), methods.filter((method) => method !== 'credentials.assess'));
  const runtime = source('../src-tauri/src/runtime.rs');
  const mac = runtime.split('fn macos_installed_passive_method', 2)[1].split('fn linux_installed_passive_method', 1)[0];
  const linux = runtime.split('fn linux_installed_passive_method', 2)[1].split('fn installed_passive_method', 1)[0];
  assert.doesNotMatch(mac, /release\.evidence\.observe/); assert.match(linux, /"release\.evidence\.observe"/);
  assert.match(observer, /"Inspect selected local release documents"/);
  assert.match(source('../src/pages/Environment.tsx'), /'release\.evidence\.observe': 'Inspect selected local release documents'/);
  const shell = source('../src-tauri/src/shell.rs'), build = source('../src-tauri/build.rs');
  const permissions = JSON.parse(source('../src-tauri/capabilities/main.json')).permissions;
  for (const suffix of ['choose', 'status', 'observe', 'cancel']) {
    const command = 'release_evidence_' + suffix;
    assert.equal((build.match(new RegExp('"' + command + '"', 'g')) ?? []).length, 1);
    assert.equal(permissions.filter((name) => name === 'allow-' + command.replaceAll('_', '-')).length, 1);
    const body = shell.split('async fn ' + command + '(', 2)[1].split('\n#[tauri::command', 1)[0];
    assert.match(body, /fixture_command!\(state, Forbidden/); assert.match(body, /edit_window\(&webview\)\?/);
    assert.doesNotMatch(body, /q\.evidence_/); // No conversion of the legacy installed witness into lifecycle evidence.
    assert.match(shell, new RegExp(command + '[,\\s]'));
  }
  const owner = source('../src-tauri/src/asset_session.rs');
  const reconcile = owner.split('fn reconcile_scope(', 2)[1].split('\n    fn publish(', 1)[0];
  assert.ok(reconcile.indexOf('evidence_route_gate(&state, family)') < reconcile.indexOf('self.expire(&mut state'));
  for (const [prefix, family] of [['artifact', 'false'], ['release', 'true']]) for (const suffix of ['status', 'choose', 'observe']) {
    const body = owner.split('pub(crate) fn ' + prefix + '_evidence_' + suffix + '(', 2)[1].split('\n    pub(crate) fn ', 1)[0];
    assert.ok(body.includes('self.reconcile_scope(Some(' + family + '))'));
    assert.ok(body.indexOf('evidence_route_gate(&state, ' + family + ')?') < body.indexOf('self.expire(&mut state'));
  }
});
