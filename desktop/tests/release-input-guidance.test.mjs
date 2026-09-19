// Inert DTOs, reducer events and controlled promises only. No DOM, native
// launch, credential IO, tool probing, remote calls, timers or child processes.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import guide from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { ReleaseInputGuidanceController, parseReleaseInputHelp, parseReleaseInputResult, releaseInputGroups, releaseInputRows } from '../src/releaseInputGuidance.ts';

const assurance = { basis: 'schema-policy', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const info = { runtime: { state: 'available' }, capabilities: { methods: [{ method: 'config.validate', available: true, reason: '' }] } };
function row(name = 'MOBILE_RELEASE_SYNTHETIC_INPUT', platform = 'project', stage = 'candidate', extra = {}) {
  return { name, platform, stage, environment: `mobile-${stage}`, kind: 'secret', alternatives: [], reason: 'Synthetic core-returned reason.', state: 'unknown', ...extra };
}
function valid(requirements = [row()]) { return { valid: true, state: 'format-valid', issues: [], requirements, assurance: { ...assurance } }; }
function invalid() { return { valid: false, state: 'invalid', issues: [{ code: 'config.invalid', status: 'INVALID',
  message: 'A reflective invalid draft contains PRIVATE_CANARY.', remediation: 'Correct PRIVATE_CANARY.' }], requirements: [], assurance: { ...assurance } }; }
function catalogRow(requirement) {
  return { name: requirement.name, kind: requirement.kind, platform: requirement.platform, stages: [requirement.stage], alternatives: requirement.alternatives,
    requiredness: 'conditional', requiredWhen: 'General reference condition, not presence.', what: 'Synthetic reference explanation.', why: 'Synthetic purpose.',
    where: 'Read the existing core instructions.', format: 'Synthetic format guidance.', failure: 'No input was checked here.' };
}
function project(id = 'p1') {
  const selected = workspaceReducer(initialWorkspace, { type: 'select', project: { id, name: 'Inert project', path: '/inert/not-read' } });
  // Deliberately arbitrary draft data: these tests admit synthetic core replies,
  // not a second renderer configuration/requiredness-policy implementation.
  const baseline = { android: { enabled: false }, services: { androidFirebase: 'optional' } };
  return { ...selected.projects[id], baseline, draft: { ...structuredClone(baseline), marker: 'DRAFT_ONLY_CANARY' }, revision: 4, baselineGeneration: 3, observationGeneration: 7 };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function harness() {
  let workspace = { selectedId: 'p1', projects: { p1: project(), p2: project('p2') } }, busy = false, helpRetirements = 0;
  const calls = [];
  const api = new Proxy({ mode: 'native', validate: (draft) => {
    const work = deferred(); calls.push({ draft, ...work }); return work.promise;
  } }, { get(target, key) { assert.ok(['mode', 'validate'].includes(key), `unexpected API access: ${String(key)}`); return Reflect.get(target, key); } });
  const controller = new ReleaseInputGuidanceController(() => workspace.projects[workspace.selectedId] ?? null, () => busy, () => { helpRetirements += 1; });
  controller.setConnection(api, info); controller.syncProject(); controller.setCatalog({ credentialGuide: guide, credentials: [] });
  return { controller, api, calls,
    get state() { return controller.getSnapshot(); }, get selected() { return workspace.projects[workspace.selectedId]; },
    get helpRetirements() { return helpRetirements; },
    busy(value) { busy = value; },
    replace(session) { workspace = { ...workspace, projects: { ...workspace.projects, [session.project.id]: session } }; controller.syncProject(); },
    dispatch(action) {
      controller.beforeWorkspaceAction(action); // Same pre-reducer ordering as App.
      workspace = workspaceReducer(workspace, action); controller.syncProject();
    },
  };
}
async function read(h, result = valid()) {
  const index = h.calls.length, request = h.controller.refresh();
  assert.equal(h.calls.length, index + 1); h.calls[index].resolve(result); await request;
}
function generations(h) { return [h.selected.revision, h.selected.baselineGeneration, h.selected.observationGeneration]; }
function failedSnapshot(h) {
  const before = generations(h);
  h.dispatch({ type: 'snapshot-start', projectId: 'p1', requestId: 30 });
  assert.equal(h.state.pending, false); assert.match(h.controller.startReason(), /snapshot/);
  h.dispatch({ type: 'snapshot-failed', projectId: 'p1', requestId: 30, error: { code: 'busy', message: 'PRIVATE_CANARY', retryable: false } });
  assert.deepEqual(generations(h), before); assert.equal(h.state.project.snapshotFailed, true);
}
// Trusted inert reducer-event fixture only. The saved-version/config-edit suites
// own receipt admission; this is not a simulated native save/finality result.
function saveEvent(session, older = false) {
  const binding = { projectId: session.project.id, windowGeneration: 'a'.repeat(32), startStatusRevision: 1, previousTerminalId: null,
    draftRevision: session.revision - (older ? 1 : 0), baselineGeneration: session.baselineGeneration,
    expectedBase: structuredClone(session.baseline), draft: structuredClone(session.draft) };
  const result = older ? 'saved' : 'unchanged', sessionId = 'b'.repeat(32), planToken = 'c'.repeat(32), revision = 'd'.repeat(32);
  const projection = { projectId: session.project.id, ownerGeneration: binding.windowGeneration, sessionId,
    phase: 'final', nativeFinality: 'settled', nativeReason: 'none', lateSettled: false, applySubmitted: true,
    checkout: { revision, base: structuredClone(binding.expectedBase) },
    prepared: { revision, planToken, draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration,
      view: { files: [{ path: 'release/mobile-release.json', action: older ? 'replace' : 'preserve' }, { path: '.gitignore', action: 'preserve' }] } },
    coreOutcome: { effect: older ? 'committed' : 'unchanged', journal: older ? 'clean' : 'not_created', resources: 'settled', reason: 'none' } };
  return { type: 'config-save-final', projectId: 'p1', receipt: { binding, projection, sessionId, planToken, statusRevision: 2, result } };
}
function recoveryEvent() {
  return { type: 'config-save-recovery', projectId: 'p1', attention: { projectId: 'p1', sessionId: 'e'.repeat(32), ownerGeneration: 'a'.repeat(32),
    phase: 'final', nativeFinality: 'settled', coreOutcome: { effect: 'rolled_back', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } } };
}

test('exact core rows retain all guide families, scalar/file companions, alternatives and project groups without local policy', () => {
  const supplied = guide.kinds.flatMap((kind) => kind.fields.map((field) => row(field.requirement, kind.platform, 'candidate', {
    kind: field.input === 'text' ? 'variable' : field.input, alternatives: field.alternatives,
  })));
  const review = row('MOBILE_RELEASE_APPLE_REVIEW_CONTACT_EMAIL', 'ios', 'production', { kind: 'variable' });
  const unknown = row('MOBILE_RELEASE_UNMATCHED_INPUT', 'project', 'candidate');
  const result = parseReleaseInputResult(valid([...supplied, review, unknown]));
  assert.ok(result);
  const help = parseReleaseInputHelp({ credentialGuide: guide, credentials: [catalogRow(review)] });
  const rows = releaseInputRows(result, 'candidate', help);
  assert.equal(rows.length, supplied.length + 1);
  for (const kind of guide.kinds) {
    const expected = kind.fields.length;
    assert.equal(rows.filter((entry) => entry.guideId === kind.id).length, expected, kind.id);
  }
  assert.equal(rows.at(-1).requirement.name, unknown.name); assert.equal(rows.at(-1).help, null);
  assert.deepEqual(rows[0].requirement, supplied[0]);
  const production = releaseInputRows(result, 'production', help);
  assert.equal(production.length, 1); assert.equal(production[0].guideId, null); assert.deepEqual(production[0].help.what, catalogRow(review).what);
  const grouped = releaseInputGroups({ pending: false, result, stage: 'candidate', help });
  assert.deepEqual(grouped.map((group) => group.platform), ['android', 'ios', 'project']);
  assert.equal(grouped.reduce((count, group) => count + group.rows.length, 0), rows.length);
  assert.deepEqual(releaseInputGroups({ pending: true, result, stage: 'candidate', help }), []);
  const alternativeKind = guide.kinds.find((kind) => kind.fields.some((field) => field.alternatives.length));
  const field = alternativeKind.fields.find((entry) => entry.alternatives.length);
  const alternative = row(field.alternatives[0], alternativeKind.platform, 'candidate', { alternatives: [field.requirement] });
  assert.equal(releaseInputRows(parseReleaseInputResult(valid([alternative])), 'candidate', help)[0].guideId, alternativeKind.id);
  assert.deepEqual(releaseInputRows(parseReleaseInputResult(valid([])), 'candidate', help), []);
});

test('bounded closed DTO/help admission detaches providers, rejects stronger claims, and drops reflective errors without executing getters', () => {
  const raw = valid(), parsed = parseReleaseInputResult(raw);
  raw.requirements[0].reason = 'changed after delivery'; assert.notEqual(parsed.requirements[0].reason, raw.requirements[0].reason);
  assert.throws(() => { parsed.requirements[0].name = 'MOBILE_RELEASE_MUTATED'; }, TypeError);
  for (const mutate of [
    (value) => { value.extra = true; }, (value) => { value.valid = false; }, (value) => { value.state = 'ready'; },
    (value) => { value.assurance.credentialsRead = true; }, (value) => { value.assurance.writesPerformed = true; },
    (value) => { value.assurance.releaseReadiness = 'ready'; }, (value) => { value.assurance.basis = 'static-text'; },
    (value) => { value.requirements.push(value.requirements[0]); },
    (value) => { value.requirements = Array.from({ length: 129 }, (_, i) => row(`MOBILE_RELEASE_INPUT_${i}`)); },
    (value) => { value.requirements[0].environment = 'mobile-production'; }, (value) => { value.requirements[0].platform = 'all'; },
    (value) => { value.requirements[0].kind = 'native'; }, (value) => { value.requirements[0].state = 'registered'; },
    (value) => { value.requirements[0].reason = 'x'.repeat(1025); }, (value) => { value.requirements[0].reason = '\u0000'; },
    (value) => { value.requirements[0].name = 'PRIVATE_CANARY'; }, (value) => { value.requirements[0].alternatives = [row().name, row().name, row().name]; },
    (value) => { value.requirements[0].value = 'PRIVATE_CANARY'; }, (value) => { value.requirements = Array(1); },
  ]) { const input = valid(); mutate(input); assert.equal(parseReleaseInputResult(input), null); }
  let getters = 0;
  const accessor = Object.defineProperty(valid(), 'requirements', { enumerable: true, get() { getters += 1; return []; } });
  assert.equal(parseReleaseInputResult(accessor), null); assert.equal(getters, 0);
  assert.equal(parseReleaseInputResult(Object.assign(Object.create({ inherited: true }), valid())), null);
  const cycle = valid(); cycle.loop = cycle; assert.equal(parseReleaseInputResult(cycle), null);
  assert.deepEqual(parseReleaseInputResult(invalid()), { state: 'invalid', requirements: [] });
  assert.doesNotMatch(JSON.stringify(parseReleaseInputResult(invalid())), /PRIVATE_CANARY/);
  const badIssue = invalid(); badIssue.issues[0].extra = 'PRIVATE_CANARY'; assert.equal(parseReleaseInputResult(badIssue), null);
  const helpSource = { credentialGuide: structuredClone(guide), credentials: [catalogRow(row())] }, admitted = parseReleaseInputHelp(helpSource);
  helpSource.credentialGuide.kinds[0].fields[0].where = 'changed'; helpSource.credentials[0].where = 'changed';
  assert.notEqual(admitted.guide.kinds[0].fields[0].where, 'changed'); assert.notEqual(admitted.credentials[0].where, 'changed');
  for (const change of [(entry) => { entry.where = 'x'.repeat(4097); }, (entry) => { entry.value = 'PRIVATE_CANARY'; },
    (entry) => { entry.stages = ['candidate', 'candidate']; }, (entry) => { entry.name = 'PRIVATE_CANARY'; }]) {
    const entry = catalogRow(row()); change(entry);
    assert.deepEqual(parseReleaseInputHelp({ credentialGuide: null, credentials: [entry] }).credentials, []);
  }
  const helpGetter = { get credentialGuide() { getters += 1; return guide; }, credentials: [] };
  assert.equal(parseReleaseInputHelp(helpGetter).guide, null); assert.equal(getters, 0);
  assert.equal(parseReleaseInputHelp({ credentialGuide: { ...guide, availability: 'stored' }, credentials: [] }).guide, null);
});

test('only explicit current-draft validation supplies rows; pending/failure/invalid/preview never reuse cached results or values', async () => {
  const h = harness();
  h.replace({ ...h.selected, validation: valid([row('MOBILE_RELEASE_OLD_CACHE')]), validatedRevision: 4, validatedBaselineGeneration: 3 });
  assert.equal(h.state.result, null); assert.equal(h.calls.length, 0);
  const pending = h.controller.refresh(); assert.equal(h.state.pending, true); assert.equal(h.state.result, null);
  assert.notEqual(h.calls[0].draft, h.selected.draft); assert.deepEqual(h.calls[0].draft, h.selected.draft);
  assert.equal(h.state.project.dirtyDraft, true); assert.doesNotMatch(JSON.stringify(h.state), /DRAFT_ONLY_CANARY/);
  h.controller.setStage('production'); assert.equal(h.calls.length, 1); assert.equal(h.state.result, null);
  const values = [row('MOBILE_RELEASE_ANDROID_RETURNED', 'android', 'production'), row('MOBILE_RELEASE_PROJECT_RETURNED', 'project', 'production')];
  h.calls[0].resolve(valid(values)); await pending;
  assert.deepEqual(releaseInputGroups(h.state).map((group) => group.platform), ['android', 'project']); // draft android.enabled=false never overrides core rows
  const beforeHelp = h.helpRetirements, refresh = h.controller.refresh();
  assert.equal(h.state.result, null); assert.equal(h.state.pending, true); assert.ok(h.helpRetirements > beforeHelp);
  h.controller.setStage('candidate'); assert.deepEqual(releaseInputGroups(h.state), []);
  h.calls[1].reject({ message: 'PRIVATE_CANARY' }); await refresh;
  assert.equal(h.state.result, null); assert.equal(h.state.pending, false); assert.doesNotMatch(JSON.stringify(h.state), /PRIVATE_CANARY|OLD_CACHE/);
  await read(h, invalid()); assert.equal(h.state.result.state, 'invalid'); assert.deepEqual(releaseInputGroups(h.state), []);
  assert.match(h.state.notice, /Project settings/); assert.doesNotMatch(JSON.stringify(h.state), /PRIVATE_CANARY/);
  await read(h, valid([])); assert.deepEqual(h.state.result.requirements, []);
  const count = h.calls.length;
  h.controller.setConnection({ mode: 'preview', validate: h.api.validate }, { ...info, capabilities: { ...info.capabilities, actions: [{ available: true }] } });
  await h.controller.refresh(); assert.equal(h.calls.length, count); assert.equal(h.state.result, null); assert.match(h.controller.startReason(), /Browser preview/);
  h.controller.dispose();
});

test('pre-reducer attempts and full context changes synchronously retire even unchanged generations and ignore original late replies', async () => {
  const changes = [
    ['failed snapshot', failedSnapshot],
    ['unmatched failed snapshot event', (h) => h.dispatch({ type: 'snapshot-failed', projectId: 'p1', requestId: 999, error: { code: 'busy' } })],
    ['failed validation', (h) => { h.dispatch({ type: 'validate-start', projectId: 'p1', requestId: 41, revision: 4, baselineGeneration: 3 }); h.dispatch({ type: 'validate-failed', projectId: 'p1', requestId: 41, error: { code: 'busy' } }); }],
    ['service edit', (h) => h.dispatch({ type: 'edit', projectId: 'p1', path: 'services.androidFirebase', value: 'required' })],
    ['new-draft no-op', (h) => h.dispatch({ type: 'new-draft', projectId: 'p1', draft: {} })],
    ['reset', (h) => h.dispatch({ type: 'reset', projectId: 'p1' })],
    ['remove no-op', (h) => h.dispatch({ type: 'remove-forbidden', projectId: 'p1', reviewId: 999, paths: [] })],
    ['undo no-op', (h) => h.dispatch({ type: 'undo-removal', projectId: 'p1', removalId: 999 })],
    ['forget no-op', (h) => h.dispatch({ type: 'forget-removal', projectId: 'p1', removalId: 999 })],
    ['adopt no-op', (h) => h.dispatch({ type: 'adopt-suggestion', projectId: 'p1', requestId: 999 })],
    ['draft identity without revision', (h) => h.replace({ ...h.selected, draft: structuredClone(h.selected.draft) })],
    ['baseline generation', (h) => h.replace({ ...h.selected, baselineGeneration: 4 })],
    ['away and back', (h) => { h.dispatch({ type: 'switch', projectId: 'p2' }); h.dispatch({ type: 'switch', projectId: 'p1' }); }],
    ['same project select', (h) => h.dispatch({ type: 'select', project: h.selected.project })],
    ['cancelled picker', (h) => { h.controller.setSelectionPending(true); assert.equal(h.state.pending, false); h.controller.setSelectionPending(false); }],
    ['same API reconnect', (h) => { h.controller.beginConnection(); assert.equal(h.state.pending, false); h.controller.setConnection(h.api, info); h.controller.setCatalog({ credentialGuide: guide, credentials: [] }); }],
    ['failed bootstrap', (h) => { h.controller.beginConnection(); h.controller.connectionUnavailable(); }],
    ['failed/replaced help', (h) => { h.controller.setCatalog(null); h.controller.setCatalog({ credentialGuide: guide, credentials: [] }); }],
    ['save intent', (h) => h.controller.saveIntent()],
    ['unchanged save', (h) => { const before = generations(h); h.dispatch(saveEvent(h.selected)); assert.equal(h.selected.lastSave.result, 'unchanged'); assert.deepEqual(generations(h), before); }],
    ['older save', (h) => { const before = generations(h); h.dispatch(saveEvent(h.selected, true)); assert.equal(h.selected.lastSave.resultingBaselineGeneration, null); assert.deepEqual(generations(h), before); }],
    ['recovery', (h) => { h.dispatch(recoveryEvent()); assert.equal(h.selected.saveRecoveryRequired, true); assert.match(h.controller.startReason(), /recovery/); }],
    ['dispose', (h) => h.controller.dispose()],
  ];
  for (const [label, change] of changes) {
    const h = harness(); await read(h);
    const original = h.controller.refresh(); assert.equal(h.state.pending, true, label);
    change(h); assert.equal(h.state.pending, false, label); assert.equal(h.state.result, null, label);
    h.controller.setStage('production'); h.controller.setStage('candidate'); assert.deepEqual(releaseInputGroups(h.state), [], label);
    h.calls[1].resolve(valid([row('MOBILE_RELEASE_RETIRED')])); await original;
    assert.equal(h.state.result, null, label); assert.equal(h.state.pending, false, label); h.controller.dispose();
  }
  const h = harness(); await read(h); failedSnapshot(h); await read(h);
  assert.equal(h.state.project.snapshotFailed, true); assert.ok(h.state.result); // explicitly re-requested draft, never a successful disk refresh
  h.dispatch(recoveryEvent()); const count = h.calls.length; await h.controller.refresh(); assert.equal(h.calls.length, count); assert.equal(h.state.result, null);
  h.controller.dispose();
});

test('old success/failure cannot clear a newer attempt; reentrant retirement, save busy and catalogue generation changes cannot publish', async () => {
  for (const outcome of ['resolve', 'reject']) {
    const h = harness(), old = h.controller.refresh();
    h.dispatch({ type: 'edit', projectId: 'p1', path: 'services.androidFirebase', value: 'required' });
    const newer = h.controller.refresh();
    h.calls[0][outcome](outcome === 'resolve' ? valid([row('MOBILE_RELEASE_OLD')]) : { message: 'PRIVATE_CANARY' }); await old;
    assert.equal(h.state.pending, true); assert.equal(h.state.result, null);
    h.calls[1].resolve(valid([row('MOBILE_RELEASE_NEW')])); await newer;
    assert.equal(h.state.pending, false); assert.equal(h.state.result.requirements[0].name, 'MOBILE_RELEASE_NEW'); h.controller.dispose();
  }
  const reentrant = harness(), off = reentrant.controller.subscribe(() => { if (reentrant.state.pending) reentrant.controller.saveIntent(); });
  await reentrant.controller.refresh(); assert.equal(reentrant.calls.length, 0); off(); reentrant.controller.dispose();
  const h = harness(), request = h.controller.refresh(); h.busy(true); h.calls[0].resolve(valid()); await request;
  assert.equal(h.state.pending, false); assert.equal(h.state.result, null); assert.match(h.controller.startReason(), /save/);
  const count = h.calls.length; await h.controller.refresh(); assert.equal(h.calls.length, count); h.busy(false);
  const late = h.controller.refresh();
  const proxy = new Proxy(valid(), { ownKeys(target) { h.controller.beginConnection(); return Reflect.ownKeys(target); } });
  h.calls[1].resolve(proxy); await late; assert.equal(h.state.result, null); assert.equal(h.state.loading, true);
  h.controller.setConnection(h.api, info);
  const hostileGuide = new Proxy(guide, { ownKeys(target) { h.controller.beginConnection(); return Reflect.ownKeys(target); } });
  h.controller.setCatalog({ credentialGuide: hostileGuide, credentials: [catalogRow(row())] });
  assert.equal(h.state.help.guide, null); assert.deepEqual(h.state.help.credentials, []); assert.equal(h.state.mode, 'unavailable');
  h.controller.dispose();
});

test('App and Credentials keep retirement before awaits/reducer, original save returns, safe reference navigation and honest UI labels', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../src/pages/Credentials.tsx', import.meta.url), 'utf8');
  const pane = readFileSync(new URL('../src/components/ReleaseInputGuidance.tsx', import.meta.url), 'utf8');
  const module = readFileSync(new URL('../src/releaseInputGuidance.ts', import.meta.url), 'utf8');
  const dispatch = app.slice(app.indexOf('const dispatch ='), app.indexOf('const [configEdit]'));
  const retire = dispatch.indexOf('releaseInputControllerRef.current?.beforeWorkspaceAction(action)');
  assert.ok(retire >= 0 && retire < dispatch.indexOf('workspaceReducer(previous, action)') && retire < dispatch.indexOf('if (next === previous) return'));
  assert.ok(dispatch.includes('releaseInputControllerRef.current?.syncProject()'));
  const bootstrap = app.slice(app.indexOf('const bootstrap ='), app.indexOf('useEffect(() => {\n    void bootstrap()'));
  assert.ok(bootstrap.indexOf('releaseInputs.beginConnection()') < bootstrap.indexOf('await desktopApi()'));
  for (const source of ['releaseInputs.setConnection(connection, appInfo)', 'releaseInputs.setCatalog(result)', 'releaseInputs.setCatalog(null)', 'releaseInputs.connectionUnavailable()']) assert.ok(bootstrap.includes(source));
  const picker = app.slice(app.indexOf('const chooseProject ='), app.indexOf('const changeApplicationRepository'));
  assert.ok(picker.indexOf('releaseInputs.setSelectionPending(true)') < picker.indexOf('await api.chooseProject()'));
  assert.ok(picker.includes('finally') && picker.includes('releaseInputs.setSelectionPending(false)'));
  assert.ok(app.includes('releaseInputs.saveIntent(); releaseVersion.saveIntent(); if (workspaceRef.current.selectedId === session.project.id) configEdit.start(session.project.id)'));
  assert.ok(app.includes('releaseInputs.saveIntent(); releaseVersion.saveIntent(); return configEdit.apply(binding)'));
  assert.ok(app.includes('releaseInputs.dispose()') && app.includes('() => setHelp(null)'));
  assert.ok(page.includes('<CredentialSession state={state} controller={controller}'));
  assert.ok(page.includes('<AssetGuide guide={inputState.help.guide} selected={selectedGuide} onSelect={setSelectedGuide}'));
  assert.ok(page.includes('setSelectedGuide(kind); guideRef.current?.focus()'));
  assert.ok(pane.includes('controller.getSnapshot() === state') && page.includes('inputController.getSnapshot() === inputState'));
  for (const label of ['Required by this draft; presence not checked.', 'How / where to find it', 'Expected format', 'If unavailable or incorrect',
    'No requirements returned for this stage', 'saved files were not re-observed', 'persistent vault storage', 'Project settings']) assert.ok(pane.includes(label), label);
  assert.doesNotMatch(pane, /type="(?:file|password|checkbox)"|dangerouslySetInnerHTML/);
  assert.doesNotMatch(module, /validationFresh|\.chooseProject\(|\.assess\(|\.assign\(|\.environment\(|\.snapshot\(/);
  assert.equal((module.match(/await binding\.api\.validate\(draft\)/g) ?? []).length, 1);
});
