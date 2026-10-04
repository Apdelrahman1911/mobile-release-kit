// Inert DTO/reducer/controller promises only. No native owner, DOM, filesystem
// fixture, real workflow generator, clock, subprocess, network or finality proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { configurationOwnerReason } from '../src/configEdit.ts';
import { ConfigEditController } from '../src/configEditController.ts';
import { parseConfigEditStatus } from '../src/configEditProtocol.ts';
import { initialWorkspace, isDirty, workspaceReducer } from '../src/drafts.ts';
import { GitHubSetupController } from '../src/githubSetupController.ts';
import { GITHUB_WORKFLOWS } from '../src/githubSetupProtocol.ts';
import {
  canApplyWorkflows, canRecoverWorkflows, confirmedWorkflowResult, currentWorkflowApplyBinding, currentWorkflowRecoveryBinding,
  workflowDisplayDiff, workflowEditNotice, workflowNoOp, workflowOwnerReason,
  workflowProjectionNotice, workflowRetainsDraft,
} from '../src/githubWorkflowEdit.ts';
import { GitHubWorkflowEditController } from '../src/githubWorkflowEditController.ts';
import { normalWorkflowRecovery, normalWorkflowResult, parseGitHubWorkflowEditStatus, workflowEditRequestFits, workflowProjectionProgress } from '../src/githubWorkflowEditProtocol.ts';
import { previewApi } from '../src/preview.ts';

const ID = { window: 'a'.repeat(32), otherWindow: 'b'.repeat(32), session: 'c'.repeat(32), otherSession: 'd'.repeat(32), revision: 'e'.repeat(32), plan: 'f'.repeat(32) };
const REPOSITORY = 'inert/toolkit'; const SHA = 'a'.repeat(40);
const DRAFT = { schemaVersion: 1, source: { candidateBranch: 'main', productionBranch: 'main' }, retained: 'inert unsaved text' };
function appInfo() { return { runtime: { state: 'available', mode: 'development', reason: null }, capabilities: { methods: [{ method: 'github.setup.propose', available: true, reason: null }], actions: [] } }; }
function workspace() {
  let value = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'a', name: 'Inert project', path: '/never-forward-this-path' } });
  return workspaceReducer(value, { type: 'new-draft', projectId: 'a', draft: structuredClone(DRAFT) });
}
function view(actions = ['create', 'create', 'create', 'create']) {
  return {
    schemaVersion: 1,
    files: GITHUB_WORKFLOWS.map(({ id, path }, index) => {
      // Not real YAML and not a claim of valid core rendering or actual hashing.
      const content = `inert display row ${index}\n`;
      const generated = { content, byteLength: Buffer.byteLength(content), sha256: String(index + 1).repeat(64) };
      if (actions[index] === 'update') {
        const old = `inert previous row ${index}\n`;
        const previous = { content: old, byteLength: Buffer.byteLength(old), sha256: String(index + 5).repeat(64) };
        return { id, path, action: 'update', observed: { state: 'present', byteLength: previous.byteLength, sha256: previous.sha256 }, generated, previous };
      }
      return { id, path, action: actions[index], observed: actions[index] === 'create' ? { state: 'absent' } : { state: 'present', byteLength: generated.byteLength, sha256: generated.sha256 }, generated };
    }),
    createDirectories: actions.every((action) => action === 'create') ? ['.github', '.github/workflows'] : [],
    templateSet: { coreVersion: '0.3.0', resourceVersion: 1, resourceSha256: '0'.repeat(64) },
    tooling: { repository: REPOSITORY, sha: SHA, schemaReference: `https://raw.githubusercontent.com/${REPOSITORY}/${SHA}/schemas/project.schema.json`, state: 'format-only' },
  };
}
function owner(phase = 'opening', { plan = view(), ...overrides } = {}) {
  const prepared = ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  return {
    domain: 'github_workflows', projectId: 'a', sessionId: ID.session, ownerGeneration: ID.window,
    phase, reviewRemainingMs: 900000,
    checkout: phase === 'opening' ? null : { revision: ID.revision, observed: plan.files.map((file) => ({ id: file.id, ...file.observed })) },
    prepared: prepared ? { revision: ID.revision, planToken: ID.plan, draftRevision: 1, baselineGeneration: 0, view: structuredClone(plan) } : null,
    conflict: null, applySubmitted: ['applying', 'finalizing', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: workflowNoOp(plan) ? 'unchanged' : 'committed', journal: workflowNoOp(plan) ? 'not_created' : 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false,
    ...overrides,
  };
}

function recoveryView(action = 'rollback', state = 'recoverable') {
  const files = GITHUB_WORKFLOWS.map(({ id, path }, index) => {
    const before = index === 1 ? null : { size: 12, mode: 0o644, sha256: String(index + 1).repeat(64) };
    const after = index === 2 ? null : { size: 16, mode: 0o644, sha256: String(index + 5).repeat(64) };
    return { id, path, before, after, action: action !== 'rollback' || after === null ? 'preserve' : before === null ? 'remove' : 'restore' };
  });
  return {
    schemaVersion: 1, kind: 'recovery', state, action: state === 'recoverable' ? action : null,
    transactionId: state === 'recoverable' ? '6'.repeat(32) : null, files: state === 'recoverable' ? files : [],
    privateCleanup: { fileCount: state === 'recoverable' ? 8 : 0, directoryCount: state === 'recoverable' ? 2 : 0, scope: 'inspected-workflow-journal-only' },
  };
}
function recoveryOwner(phase = 'opening', { action = 'rollback', state = 'recoverable', sessionId = ID.otherSession, ...overrides } = {}) {
  const plan = recoveryView(action, state);
  const prepared = state === 'recoverable' && ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  const submitted = state === 'recoverable' && ['applying', 'finalizing', 'final', 'unknown'].includes(phase);
  const effect = action === 'committed_cleanup' ? 'committed' : action === 'preparing_cleanup' ? 'not_started' : 'rolled_back';
  return {
    ...owner(phase, { sessionId }), checkout: null, prepared: null, conflict: null,
    recovery: { checkout: phase === 'opening' ? null : { revision: ID.revision, view: structuredClone(plan) },
      prepared: prepared ? { revision: ID.revision, planToken: ID.plan, view: structuredClone(plan) } : null },
    applySubmitted: submitted,
    coreOutcome: phase === 'final' ? { effect: submitted ? effect : 'not_started', journal: submitted ? 'clean' : 'not_created', resources: 'settled', reason: 'none' } : null,
    ...overrides,
  };
}
function reviewingRecovery(h, options = {}) {
  const before = h.count('recovery-prepare');
  assert.equal(h.controller.inspectRecovery(), true);
  h.publish(recoveryOwner('opening', options)); h.publish(recoveryOwner('editing', options));
  assert.equal(h.count('recovery-prepare'), before + 1);
  h.publish(recoveryOwner('reviewing', options));
  const binding = currentWorkflowRecoveryBinding(h.state); assert.ok(binding); return binding;
}

function status(revision = 0, active = null, lastTerminal = null, reason = 'available', windowGeneration = ID.window) {
  return { schemaVersion: 1, domain: 'github_workflows', windowGeneration, statusRevision: revision, capability: { available: reason === 'available', reason }, active, lastTerminal };
}
function configStatus(revision = 0, lastTerminal = null, reason = 'available') {
  return { schemaVersion: 1, windowGeneration: ID.window, statusRevision: revision, capability: { available: reason === 'available', reason }, active: null, lastTerminal };
}
function request() { return { sessionId: ID.session, revision: ID.revision, draft: structuredClone(DRAFT), toolingRepository: REPOSITORY, toolingSha: SHA, draftRevision: 1, baselineGeneration: 0 }; }
function deferred() { let resolve; let reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function flush() { for (let index = 0; index < 12; index += 1) await Promise.resolve(); }

function harness({ initial = status(), subscribeGate = null, mode = 'native' } = {}) {
  let current = workspace(); let registry = structuredClone(initial); let onEvent; let configEvent;
  let controller; let config; let unlistened = 0;
  const calls = []; const reads = [];
  const selected = () => current.projects[current.selectedId] ?? null;
  const setup = new GitHubSetupController(selected, () => controller?.syncContext());
  const mutation = (kind, args) => { const work = deferred(); calls.push({ kind, args: structuredClone(args), ...work }); return work.promise; };
  const api = {
    mode,
    subscribeGitHubWorkflowEdit: async (listener) => { calls.push({ kind: 'subscribe' }); onEvent = listener; if (subscribeGate) await subscribeGate.promise; return () => { unlistened += 1; onEvent = null; }; },
    githubWorkflowEditStatus: () => { calls.push({ kind: 'status' }); return reads.length ? reads.shift().promise : Promise.resolve(structuredClone(registry)); },
    openGitHubWorkflowEdit: (projectId) => mutation('open', { projectId }),
    prepareGitHubWorkflowEdit: (input) => mutation('prepare', input),
    applyGitHubWorkflowEdit: (sessionId, planToken) => mutation('apply', { sessionId, planToken }),
    closeGitHubWorkflowEdit: (sessionId) => mutation('close', { sessionId }),
    openGitHubWorkflowRecovery: (projectId) => mutation('recovery-open', { projectId }),
    prepareGitHubWorkflowRecovery: (sessionId, revision) => mutation('recovery-prepare', { sessionId, revision }),
    applyGitHubWorkflowRecovery: (sessionId, planToken) => mutation('recovery-apply', { sessionId, planToken }),
    subscribeConfigEdit: async (listener) => { configEvent = listener; return () => {}; },
    configEditStatus: async () => configStatus(),
    openConfigEdit: (projectId) => mutation('config-open', { projectId }),
    closeConfigEdit: (sessionId) => mutation('config-close', { sessionId }),
    prepareConfigEdit: (input) => mutation('config-prepare', input),
    applyConfigEdit: (sessionId, planToken) => mutation('config-apply', { sessionId, planToken }),
  };
  controller = new GitHubWorkflowEditController({ selectedProject: selected, setup: setup.getSnapshot, otherEditReason: (id) => config ? configurationOwnerReason(config.getSnapshot(), id) : null });
  config = new ConfigEditController({ project: (id) => current.projects[id] ?? null,
    otherEditReason: (id) => workflowOwnerReason(controller.getSnapshot(), id),
    onConfirmedSave: () => { assert.fail('workflow operations must never reach configuration save adoption'); },
  });
  setup.setConnection(api, appInfo()); setup.syncProject(); setup.setCoordinate('toolingRepository', REPOSITORY); setup.setCoordinate('toolingSha', SHA);
  const result = {
    controller, config, setup, api, calls,
    get state() { return controller.getSnapshot(); }, get workspace() { return current; }, get registry() { return registry; }, get unlistened() { return unlistened; },
    selected, count: (kind) => calls.filter((call) => call.kind === kind).length, last: (kind) => calls.filter((call) => call.kind === kind).at(-1),
    dispatch: (action) => { current = workspaceReducer(current, action); setup.syncProject(); controller.syncContext(); config.syncDraft(); },
    replaceSelected: (patch) => { current = { ...current, projects: { ...current.projects, [current.selectedId]: { ...selected(), ...patch } } }; setup.syncProject(); controller.syncContext(); },
    emit: (value, remember = true) => { if (remember) registry = structuredClone(value); assert.ok(onEvent); onEvent(value); },
    configEmit: (value) => { assert.ok(configEvent); configEvent(value); },
    deferRead: () => { const work = deferred(); reads.push(work); return work; },
    publish: (projection, options = {}) => {
      const terminal = projection.phase === 'final' || projection.lateSettled;
      const value = status(options.revision ?? registry.statusRevision + 1, terminal ? null : projection, terminal ? projection : registry.lastTerminal,
        options.reason ?? registry.capability.reason, options.windowGeneration ?? registry.windowGeneration);
      result.emit(value); return value;
    },
  };
  return result;
}
async function connected(options) { const value = harness(options); await value.controller.connect(value.api); return value; }
function reviewing(h, plan = view()) {
  assert.equal(h.controller.start(), true);
  h.publish(owner('opening', { plan })); h.publish(owner('editing', { plan }));
  assert.equal(h.count('prepare'), 1);
  h.publish(owner('reviewing', { plan }));
  const binding = currentWorkflowApplyBinding(h.state); assert.ok(binding); return binding;
}

test('workflow DTO admits only fixed create/preserve reviews, never another domain or caller-supplied file authority', () => {
  const valid = status(3, owner('reviewing', { plan: view(['create', 'preserve', 'create', 'preserve']) }));
  assert.ok(parseGitHubWorkflowEditStatus(valid));
  assert.equal(parseConfigEditStatus(valid), null);
  assert.equal(parseGitHubWorkflowEditStatus(configStatus()), null);
  for (const mutate of [
    (v) => { delete v.domain; }, (v) => { v.domain = 'configuration'; }, (v) => { v.active.domain = 'configuration'; },
    (v) => { v.active.prepared.view.files.pop(); }, (v) => { v.active.prepared.view.files.reverse(); },
    (v) => { v.active.prepared.view.files[0].path = '/private/anything.yml'; },
    (v) => { v.active.prepared.view.files[0].action = 'replace'; },
    (v) => { v.active.prepared.view.files[1].observed.sha256 = '0'.repeat(64); },
    (v) => { v.active.prepared.view.files[0].generated.content = 'x'.repeat(16385); },
    (v) => { v.active.checkout.observed[0].state = 'unknown'; },
    (v) => { v.active.prepared.view.createDirectories = ['.github']; },
    (v) => { v.active.prepared.view.tooling.sha = 'branch'; },
    (v) => { v.active.prepared.view.tooling.schemaReference = 'https://untrusted.example/schema'; },
  ]) { const bad = structuredClone(valid); mutate(bad); assert.equal(parseGitHubWorkflowEditStatus(bad), null); }
  const accessor = structuredClone(valid); let getters = 0;
  Object.defineProperty(accessor, 'active', { enumerable: true, get() { getters += 1; throw Error('must not be read'); } });
  assert.equal(parseGitHubWorkflowEditStatus(accessor), null); assert.equal(getters, 0);
  assert.equal(workflowEditRequestFits('github_workflow_edit_prepare', request()), true);
  for (const key of ['root', 'registeredIdentity', 'expectedBase', 'files', 'content', 'sha256', 'suppliedSnapshot', 'force', 'token']) {
    assert.equal(workflowEditRequestFits('github_workflow_edit_prepare', { ...request(), [key]: 'never forward' }), false, key);
  }
  assert.equal(workflowEditRequestFits('github_workflow_edit_prepare', { ...request(), draftRevision: 0xffffffff }), false);
});

test('a differing-file conflict is bounded terminal data with no plan, token, paths or YAML', () => {
  const plan = view(['preserve', 'preserve', 'preserve', 'preserve']);
  const projection = owner('final', { plan, prepared: null, applySubmitted: false,
    coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'none' },
    conflict: { schemaVersion: 1, reason: 'existing_workflow_differs', conflicts: [{ id: 'candidate', observed: plan.files[1].observed }] },
  });
  assert.ok(parseGitHubWorkflowEditStatus(status(3, null, projection)));
  assert.equal(normalWorkflowResult(projection), null);
  assert.match(workflowProjectionNotice(projection).title, /refused/);
  for (const mutate of [
    (p) => { p.conflict.planToken = ID.plan; }, (p) => { p.conflict.conflicts[0].content = 'PRIVATE YAML'; },
    (p) => { p.conflict.conflicts[0].path = '.github/workflows/mobile-candidate.yml'; },
    (p) => { p.conflict.conflicts[0].observed.byteLength += 1; }, (p) => { p.conflict.conflicts.push(p.conflict.conflicts[0]); },
    (p) => { p.conflict.conflicts = []; }, (p) => { p.conflict.conflicts[0].id = 'foreign'; },
    (p) => { p.applySubmitted = true; }, (p) => { p.prepared = owner('reviewing').prepared; },
  ]) { const bad = structuredClone(projection); mutate(bad); assert.equal(parseGitHubWorkflowEditStatus(status(3, null, bad)), null); }
  const failedObservation = owner('final', { checkout: null, prepared: null, applySubmitted: false,
    coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'filesystem_error' } });
  assert.ok(parseGitHubWorkflowEditStatus(status(3, null, failedObservation)));
  assert.equal(failedObservation.conflict, null);
});

test('success needs original revision, submitted Apply and clean native/core finality; full diffs are display-only', () => {
  const installed = owner('final'); const unchanged = owner('final', { plan: view(['preserve', 'preserve', 'preserve', 'preserve']) });
  assert.equal(normalWorkflowResult(installed), 'installed'); assert.equal(normalWorkflowResult(unchanged), 'unchanged');
  for (const patch of [
    { phase: 'finalizing', nativeFinality: 'pending' }, { nativeReason: 'cancelled' }, { phase: 'unknown', nativeFinality: 'unknown', lateSettled: true },
    { applySubmitted: false }, { checkout: { ...installed.checkout, revision: ID.otherSession } },
    { coreOutcome: { ...installed.coreOutcome, resources: 'unknown', reason: 'custody_unknown' } },
    { coreOutcome: { ...installed.coreOutcome, journal: 'recovery_required', reason: 'filesystem_error' } },
  ]) assert.equal(normalWorkflowResult({ ...installed, ...patch }), null);
  assert.equal(parseGitHubWorkflowEditStatus(status(3, null, { ...unchanged, coreOutcome: installed.coreOutcome })), null);
  assert.equal(workflowProjectionProgress(installed, { ...installed, nativeReason: 'cancelled' }), false);
  assert.equal(workflowDisplayDiff(installed.prepared.view.files[0]), `--- /dev/null\n+++ ${GITHUB_WORKFLOWS[0].path}\n@@ -0,0 +1,1 @@\n+inert display row 0\n`);
  assert.match(workflowDisplayDiff(unchanged.prepared.view.files[0]), /\n inert display row 0\n$/);
});

test('canonical update DTOs require complete old/new correspondence and render all lines', () => {
  const plan = view(['update', 'create', 'preserve', 'update']);
  const valid = status(3, owner('reviewing', { plan }));
  assert.ok(parseGitHubWorkflowEditStatus(valid));
  const old = plan.files[0];
  assert.equal(workflowDisplayDiff(old), `--- ${old.path}\n+++ ${old.path}\n@@ -1,1 +1,1 @@\n-inert previous row 0\n+inert display row 0\n`);
  assert.equal(workflowDisplayDiff({ ...old, previous: { ...old.previous, content: 'first\nlast' }, generated: { ...old.generated, content: 'new\n' } }),
    `--- ${old.path}\n+++ ${old.path}\n@@ -1,2 +1,1 @@\n-first\n-last\n\\ No newline at end of file\n+new\n`);
  for (const mutate of [
    (v) => { delete v.files[0].previous; }, (v) => { v.files[0].previous = null; },
    (v) => { v.files[0].previous.byteLength += 1; }, (v) => { v.files[0].previous.sha256 = 'f'.repeat(64); },
    (v) => { v.files[0].previous.private = 'unexpected'; }, (v) => { v.files[0].previous.content = 'x'.repeat(16385); },
    (v) => { v.files[0].previous = v.files[0].generated; }, (v) => { v.files[0].action = 'preserve'; },
    (v) => { v.files[1].previous = null; }, (v) => { v.files[2].previous = old.previous; },
  ]) {
    const bad = structuredClone(plan); mutate(bad);
    assert.equal(parseGitHubWorkflowEditStatus(status(3, owner('reviewing', { plan: bad }))), null);
  }
  for (const actions of [['update', 'update', 'update', 'update'], ['update', 'preserve', 'preserve', 'preserve']]) {
    const updated = owner('final', { plan: view(actions) });
    assert.ok(parseGitHubWorkflowEditStatus(status(3, null, updated)));
    assert.equal(normalWorkflowResult(updated), 'installed');
    assert.equal(parseGitHubWorkflowEditStatus(status(3, null, { ...updated,
      coreOutcome: { effect: 'unchanged', journal: 'not_created', resources: 'settled', reason: 'none' } })), null);
  }
});

test('update consent keeps one original plan and never resends or adopts changed before text', async () => {
  const h = await connected(); const plan = view(['update', 'preserve', 'preserve', 'update']);
  const binding = reviewing(h, plan);
  assert.equal(h.count('apply'), 0);
  assert.equal(h.controller.apply(binding), true);
  assert.equal(h.controller.apply(binding), false);
  h.publish(owner('applying', { plan })); h.publish(owner('final', { plan }));
  assert.equal(h.count('apply'), 1); assert.equal(confirmedWorkflowResult(h.state), 'installed');
  assert.equal(isDirty(h.selected()), true);
  const stale = await connected(); reviewing(stale, plan);
  const changed = owner('reviewing', { plan }); changed.prepared.view.files[0].previous.content = 'changed original';
  stale.publish(changed);
  assert.equal(stale.state.integrityFailed, true); assert.equal(stale.count('apply'), 0);
  h.controller.dispose(); stale.controller.dispose();
});

test('bridge uses only five exact workflow commands/event; denied or malformed calls never fall back to preview', async () => {
  const calls = []; let listener;
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return status(); }, async (event, callback) => { assert.equal(event, 'github-workflow-edit-status'); listener = callback; return () => {}; });
  await api.openGitHubWorkflowEdit('a'); await api.prepareGitHubWorkflowEdit(request()); await api.applyGitHubWorkflowEdit(ID.session, ID.plan); await api.closeGitHubWorkflowEdit(ID.session); await api.githubWorkflowEditStatus();
  assert.deepEqual(calls, [
    { command: 'github_workflow_edit_open', args: { projectId: 'a' } }, { command: 'github_workflow_edit_prepare', args: request() },
    { command: 'github_workflow_edit_apply', args: { sessionId: ID.session, planToken: ID.plan } },
    { command: 'github_workflow_edit_close', args: { sessionId: ID.session } }, { command: 'github_workflow_edit_status', args: {} },
  ]);
  let observed; await api.subscribeGitHubWorkflowEdit((value) => { observed = value; }); const event = status(); listener(event); assert.equal(observed, event);
  await assert.rejects(api.prepareGitHubWorkflowEdit({ ...request(), force: true }), { code: 'GitHubWorkflowRequestInvalid' }); assert.equal(calls.length, 5);
  await assert.rejects(createNativeApi('native', async () => configStatus()).githubWorkflowEditStatus(), { code: 'GitHubWorkflowStatusInvalid' });
  let forbidden = 0;
  const unavailable = createNativeApi('unavailable', async () => { forbidden += 1; }, async () => { forbidden += 1; return () => {}; });
  for (const target of [unavailable, previewApi]) {
    for (const operation of [() => target.openGitHubWorkflowEdit('a'), () => target.prepareGitHubWorkflowEdit(request()), () => target.applyGitHubWorkflowEdit(ID.session, ID.plan), () => target.closeGitHubWorkflowEdit(ID.session), () => target.githubWorkflowEditStatus(), () => target.subscribeGitHubWorkflowEdit(() => {})]) {
      await assert.rejects(operation, { code: target === previewApi ? 'PreviewOnly' : 'NativeBridgeRequired' });
    }
  }
  assert.equal(forbidden, 0);
});

test('subscribe-before-status and synchronous coalescing retain a buffered opposite-domain refusal', async () => {
  const gate = deferred(); const h = harness({ subscribeGate: gate });
  const connecting = h.controller.connect(h.api); const again = h.controller.checkStatus();
  await flush(); assert.equal(h.count('subscribe'), 1); assert.equal(h.count('status'), 0);
  h.emit(status(3, null, null, 'other_edit_active'), false);
  gate.resolve(); await Promise.all([connecting, again]);
  assert.equal(h.count('status'), 1); assert.equal(h.state.status.statusRevision, 3);
  assert.match(h.controller.startReason(), /configuration edit/); assert.equal(h.controller.start(), false);
  assert.ok(parseConfigEditStatus(configStatus(4, null, 'other_edit_active')));
  assert.equal(parseConfigEditStatus({ ...configStatus(4, null, 'other_edit_active'), capability: { available: true, reason: 'other_edit_active' } }), null);
  for (const options of [{ initial: status(0, null, null, 'runtime_unqualified') }, { mode: 'preview' }]) {
    const disabled = await connected(options); assert.equal(disabled.controller.start(), false); assert.equal(disabled.count('open'), 0);
  }
});

test('each pre-Apply selection/draft/baseline/pin/runtime change retires authority before late review replies', async () => {
  for (const change of [
    (h) => h.dispatch({ type: 'edit', projectId: 'a', path: 'retained', value: 'newer draft' }),
    (h) => h.replaceSelected({ baselineGeneration: 1 }),
    (h) => h.dispatch({ type: 'select', project: { id: 'b', name: 'Other', path: '/never-read' } }),
    (h) => { h.setup.setCoordinate('toolingSha', 'b'.repeat(40)); h.setup.setCoordinate('toolingSha', SHA); },
    (h) => h.setup.setCoordinate('toolingRepository', 'other/toolkit'),
    (h) => h.setup.beginConnection(),
    (h) => h.setup.setConnection(h.api, appInfo()),
  ]) {
    const h = await connected(); const binding = reviewing(h); change(h);
    assert.equal(h.state.attempt.invalidated, true); assert.equal(h.count('close'), 1);
    h.last('prepare').resolve(status(h.registry.statusRevision, owner('reviewing'))); await flush();
    assert.equal(h.controller.apply(binding), false); assert.equal(h.count('apply'), 0); assert.equal(h.count('prepare'), 1);
    assert.equal(h.controller.start(), false); h.controller.dispose(); assert.equal(h.count('close'), 1);
  }
  const delayed = await connected(); assert.equal(delayed.controller.start(), true);
  delayed.setup.setCoordinate('toolingSha', 'b'.repeat(40));
  assert.equal(delayed.state.attempt.closeRequested, true); assert.equal(delayed.count('close'), 0);
  delayed.last('open').resolve(status(1, owner('editing'))); await flush();
  assert.equal(delayed.count('close'), 1); assert.equal(delayed.count('prepare'), 0); assert.equal(delayed.count('apply'), 0);
  delayed.controller.dispose();
});

test('passive assertions cannot supply authority or invalidate a fresh native plan; duplicate claims and timers never renew it', async () => {
  const h = await connected(); const binding = reviewing(h);
  h.setup.setSnapshotEnabled(true); h.setup.setAssertion('candidate', { state: 'present', byteLength: '0', sha256: '0'.repeat(64) });
  assert.equal(h.state.attempt.invalidated, false);
  assert.deepEqual(Object.keys(h.last('prepare').args).sort(), Object.keys(request()).sort());
  const lower = owner('reviewing', { reviewRemainingMs: 200 }); h.emit(status(h.registry.statusRevision, lower));
  h.emit(status(h.registry.statusRevision, owner('reviewing', { reviewRemainingMs: 899999 })));
  assert.equal(h.state.attempt.projection.reviewRemainingMs, 200);
  let reentrant;
  const unsubscribe = h.controller.subscribe(() => { if (h.state.attempt.applyClaimed) reentrant = h.controller.apply(binding); });
  assert.equal(h.controller.apply(binding), true); assert.equal(reentrant, false); assert.equal(h.controller.apply(binding), false); assert.equal(h.count('apply'), 1);
  unsubscribe(); h.controller.dispose();
});

test('lost Apply replies observe the original once, preserve newer drafts and need actual native finality', async () => {
  const h = await connected(); const binding = reviewing(h); assert.equal(h.controller.apply(binding), true);
  h.dispatch({ type: 'edit', projectId: 'a', path: 'retained', value: 'newer must survive' });
  h.setup.setCoordinate('toolingSha', 'b'.repeat(40)); h.setup.beginConnection();
  const retained = structuredClone(h.workspace);
  h.publish(owner('applying')); h.last('apply').reject({ code: 'lost_reply', message: 'PRIVATE REJECTION' }); await flush();
  assert.equal(h.count('apply'), 1); assert.equal(h.count('open'), 1); assert.equal(h.count('prepare'), 1); assert.equal(h.count('close'), 0); assert.equal(h.count('status'), 2);
  h.publish(owner('finalizing', { coreOutcome: owner('final').coreOutcome }));
  assert.equal(confirmedWorkflowResult(h.state), null); assert.match(workflowEditNotice(h.state).title, /settlement/);
  h.publish(owner('final'));
  assert.equal(confirmedWorkflowResult(h.state), 'installed'); assert.equal(h.state.attempt.handled, true);
  assert.deepEqual(h.workspace, retained); assert.equal(isDirty(h.workspace.projects.a), true); assert.equal(h.workspace.projects.a.lastSave, null);
  h.last('open').reject({ message: 'late old failure' }); await flush(); assert.equal(confirmedWorkflowResult(h.state), 'installed');
  h.emit(status(h.registry.statusRevision + 1, null, null, 'other_edit_active'));
  assert.equal(confirmedWorkflowResult(h.state), 'installed', 'opposite-domain terminal replacement cannot erase the submitted result');
  assert.equal(h.controller.apply(binding), false); h.controller.dispose();
});

test('no-op and no-token conflict both await original settlement, never adopt a configuration baseline', async () => {
  const plan = view(['preserve', 'preserve', 'preserve', 'preserve']);
  const h = await connected(); const before = structuredClone(h.workspace); const binding = reviewing(h, plan);
  assert.equal(h.controller.apply(binding), true); h.publish(owner('final', { plan }));
  assert.equal(confirmedWorkflowResult(h.state), 'unchanged'); assert.deepEqual(h.workspace, before); assert.equal(h.workspace.projects.a.lastSave, null);
  const c = await connected(); assert.equal(c.controller.start(), true); c.publish(owner('editing', { plan }));
  const projection = owner('finalizing', { plan, prepared: null, applySubmitted: false,
    coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'none' },
    conflict: { schemaVersion: 1, reason: 'existing_workflow_differs', conflicts: [{ id: 'preflight', observed: plan.files[0].observed }] },
  });
  c.publish(projection); assert.equal(c.state.attempt.handled, false); assert.equal(currentWorkflowApplyBinding(c.state), null); assert.equal(c.count('apply'), 0);
  assert.equal(c.controller.start(), false);
  c.publish({ ...projection, phase: 'final', nativeFinality: 'settled' });
  assert.equal(c.state.attempt.handled, true); assert.match(workflowEditNotice(c.state).title, /refused/);
  assert.equal(confirmedWorkflowResult(c.state), null); assert.equal(workflowRetainsDraft(c.state, 'a'), false);
  h.controller.dispose(); c.controller.dispose();
});

test('one synchronous local admission covers configuration and workflow before native events', async () => {
  const h = await connected(); await h.config.connect(h.api);
  let workflowStart;
  const stop = h.config.subscribe(() => { if (h.config.getSnapshot().attempt) workflowStart = h.controller.start(); });
  assert.equal(h.config.start('a'), true); assert.equal(workflowStart, false); assert.equal(h.count('open'), 0); stop();
  h.configEmit(configStatus(1, {
    projectId: 'a', sessionId: ID.otherSession, ownerGeneration: ID.window, phase: 'final', reviewRemainingMs: 900000,
    checkout: null, prepared: null, applySubmitted: false, coreOutcome: null, nativeReason: 'spawn_failed', nativeFinality: 'settled', lateSettled: false,
  }));
  let configStart;
  const stopWorkflow = h.controller.subscribe(() => { if (h.state.attempt) configStart = h.config.start('a'); });
  assert.equal(h.controller.start(), true); assert.equal(configStart, false); assert.equal(h.count('config-open'), 1); stopWorkflow();
  h.controller.dispose(); h.config.dispose();
});

test('foreign/stale documents cannot acquire control; a submitted original can still be observed after document loss', async () => {
  const h = await connected(); assert.equal(h.controller.start(), true);
  h.publish(owner('reviewing', { projectId: 'foreign', sessionId: ID.otherSession }));
  assert.equal(h.state.attempt.sessionId, null); assert.equal(h.count('prepare'), 0); assert.equal(currentWorkflowApplyBinding(h.state), null);
  h.publish(owner('editing')); h.publish(owner('reviewing')); const binding = currentWorkflowApplyBinding(h.state); assert.ok(binding);
  assert.equal(h.controller.apply(binding), true); h.publish(owner('applying'));
  h.publish(owner('final'), { windowGeneration: ID.otherWindow });
  assert.equal(h.state.generationLost, true); assert.equal(confirmedWorkflowResult(h.state), 'installed'); assert.equal(h.controller.start(), false); assert.equal(h.controller.apply(binding), false);
  const old = await connected(); const previous = reviewing(old);
  old.emit(status(old.registry.statusRevision + 1, owner('reviewing'), null, 'available', ID.otherWindow));
  assert.equal(old.state.generationLost, true); assert.equal(old.controller.apply(previous), false); assert.equal(old.count('apply'), 0);
  h.controller.dispose(); old.controller.dispose();
});

test('unknown, late settlement, recovery attention and contradictory plans remain negative evidence', async () => {
  const h = await connected(); const binding = reviewing(h); h.controller.apply(binding);
  const pending = owner('unknown', { nativeReason: 'cleanup_unknown', coreOutcome: owner('final').coreOutcome });
  h.publish(pending, { reason: 'cleanup_unknown' });
  h.publish({ ...pending, lateSettled: true }, { reason: 'available' });
  assert.equal(h.state.nativeBlocked, true); assert.equal(confirmedWorkflowResult(h.state), null); assert.match(workflowEditNotice(h.state).title, /committed; completion unverified/);
  assert.equal(h.controller.apply(binding), false); assert.equal(h.controller.start(), false);
  const recovery = await connected(); const applied = reviewing(recovery); recovery.controller.apply(applied);
  recovery.publish(owner('final', { coreOutcome: { effect: 'rolled_back', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } }));
  recovery.emit(status(recovery.registry.statusRevision + 1));
  assert.equal(recovery.state.recoveryProjects.length, 1); assert.match(recovery.controller.startReason(), /recovery/); assert.match(workflowOwnerReason(recovery.state, 'a'), /recovery/);
  const invalid = await connected(); reviewing(invalid);
  const changed = owner('reviewing'); changed.prepared.planToken = ID.otherSession;
  invalid.publish(changed); assert.equal(invalid.state.integrityFailed, true); assert.equal(invalid.count('close'), 1); assert.equal(canApplyWorkflows(invalid.state, invalid.selected(), invalid.setup.getSnapshot()), false);
  h.controller.dispose(); recovery.controller.dispose(); invalid.controller.dispose();
});


test('recovery adapters retain the five original IPC names and send only closed explicit intent', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return status(); });
  await api.openGitHubWorkflowRecovery('a');
  await api.prepareGitHubWorkflowRecovery(ID.otherSession, ID.revision);
  await api.applyGitHubWorkflowRecovery(ID.otherSession, ID.plan);
  assert.deepEqual(calls, [
    { command: 'github_workflow_edit_open', args: { projectId: 'a', intent: 'recover' } },
    { command: 'github_workflow_edit_prepare', args: { sessionId: ID.otherSession, revision: ID.revision, intent: 'recover' } },
    { command: 'github_workflow_edit_apply', args: { sessionId: ID.otherSession, planToken: ID.plan, intent: 'recover' } },
  ]);
  for (const [command, params] of [
    ['github_workflow_edit_open', { projectId: 'a', intent: 'recover' }],
    ['github_workflow_edit_prepare', { sessionId: ID.otherSession, revision: ID.revision, intent: 'recover' }],
    ['github_workflow_edit_apply', { sessionId: ID.otherSession, planToken: ID.plan, intent: 'recover' }],
  ]) {
    assert.equal(workflowEditRequestFits(command, params), true);
    for (const key of ['draft', 'toolingRepository', 'toolingSha', 'files', 'path', 'content', 'force', 'transactionId']) {
      assert.equal(workflowEditRequestFits(command, { ...params, [key]: null }), false);
    }
    for (const intent of ['edit', 'rollback', 'Recover', null, false]) {
      assert.equal(workflowEditRequestFits(command, { ...params, intent }), false);
    }
  }
  let forbidden = 0;
  const unavailable = createNativeApi('unavailable', async () => { forbidden += 1; });
  for (const target of [previewApi, unavailable]) {
    for (const operation of [() => target.openGitHubWorkflowRecovery('a'),
      () => target.prepareGitHubWorkflowRecovery(ID.otherSession, ID.revision),
      () => target.applyGitHubWorkflowRecovery(ID.otherSession, ID.plan)]) {
      await assert.rejects(operation, { code: target === previewApi ? 'PreviewOnly' : 'NativeBridgeRequired' });
    }
  }
  assert.equal(forbidden, 0);
});

test('recovery DTOs keep historical terminal facts while summaries, roster and intent are closed', () => {
  const valid = status(3, recoveryOwner('reviewing', { action: 'committed_cleanup' }));
  assert.ok(parseGitHubWorkflowEditStatus(valid));
  for (const mutate of [
    (v) => { v.files.pop(); }, (v) => { v.files.reverse(); },
    (v) => { v.files[0].path = '/private/other'; }, (v) => { v.files[0].content = 'PRIVATE'; },
    (v) => { delete v.files[0].before; }, (v) => { v.files[0].before = null; v.files[0].after = null; },
    (v) => { v.files[0].action = 'restore'; }, (v) => { v.files[0].after.size = 16385; },
    (v) => { v.files[0].before.size = 1048577; }, (v) => { v.files[0].after.mode = 0o100644; },
    (v) => { v.files[0].after.mode = 0o600; }, (v) => { v.files[0].before.sha256 = 'z'.repeat(64); },
    (v) => { v.privateCleanup.fileCount = 17; }, (v) => { v.privateCleanup.directoryCount = 3; },
    (v) => { v.privateCleanup.scope = 'all-journals'; }, (v) => { v.transactionId = ID.plan + '0'; },
  ]) {
    const bad = structuredClone(valid); mutate(bad.active.recovery.prepared.view);
    bad.active.recovery.checkout.view = structuredClone(bad.active.recovery.prepared.view);
    assert.equal(parseGitHubWorkflowEditStatus(bad), null);
  }
  const mixed = structuredClone(valid); mixed.active.prepared = owner('reviewing').prepared;
  assert.equal(parseGitHubWorkflowEditStatus(mixed), null);
  for (const [action, effect] of [['committed_cleanup', 'committed'], ['rolled_back_cleanup', 'rolled_back'],
    ['preparing_cleanup', 'not_started'], ['rollback', 'not_started']]) {
    const stopped = recoveryOwner('final', { action, applySubmitted: false, nativeReason: 'discarded',
      coreOutcome: { effect, journal: 'recovery_required', resources: 'settled', reason: 'pending_state' } });
    assert.ok(parseGitHubWorkflowEditStatus(status(4, null, stopped)));
    assert.equal(normalWorkflowRecovery(stopped), false); assert.equal(normalWorkflowResult(stopped), null);
    const success = recoveryOwner('final', { action });
    assert.ok(parseGitHubWorkflowEditStatus(status(5, null, success)));
    assert.equal(normalWorkflowRecovery(success), true); assert.equal(normalWorkflowResult(success), null);
  }
  assert.equal(workflowProjectionProgress(valid.active, recoveryOwner('reviewing')), false);
  assert.equal(workflowProjectionProgress(valid.active, owner('reviewing', { sessionId: ID.otherSession })), false);
});

test('recovery needs no valid draft or pin and its explicit one-use consent can never become ordinary Apply', async () => {
  const h = await connected();
  h.replaceSelected({ draft: null });
  h.setup.setCoordinate('toolingRepository', ''); h.setup.setCoordinate('toolingSha', '');
  assert.notEqual(h.controller.startReason(), null); assert.equal(h.controller.recoveryStartReason(), null);
  const binding = reviewingRecovery(h);
  assert.deepEqual(h.last('recovery-prepare').args, { sessionId: ID.otherSession, revision: ID.revision });
  assert.equal(h.count('recovery-apply'), 0); assert.equal(currentWorkflowApplyBinding(h.state), null);
  h.replaceSelected({ draft: { deliberately: 'not valid configuration' } });
  h.setup.setCoordinate('toolingRepository', 'invalid//pin'); h.setup.setCoordinate('toolingSha', 'invalid');
  assert.equal(h.state.attempt.invalidated, false); assert.equal(h.count('close'), 0);
  assert.equal(canRecoverWorkflows(h.state, h.selected(), binding), true);
  assert.equal(canApplyWorkflows(h.state, h.selected(), h.setup.getSnapshot()), false);
  assert.equal(h.controller.apply({ sessionId: ID.otherSession, planToken: ID.plan, draftRevision: 1, baselineGeneration: 0 }), false);
  assert.equal(h.controller.recover({ ...binding, revision: ID.session }), false);
  const retained = structuredClone(h.workspace);
  let repeated;
  const stop = h.controller.subscribe(() => { if (h.state.attempt.applyClaimed) repeated = h.controller.recover(binding); });
  assert.equal(h.controller.recover(binding), true); assert.equal(repeated, false);
  stop();
  assert.equal(h.controller.recover(binding), false);
  h.publish(recoveryOwner('final'));
  assert.equal(normalWorkflowRecovery(h.state.attempt.projection), true);
  assert.equal(confirmedWorkflowResult(h.state), null);
  assert.equal(h.count('recovery-open'), 1); assert.equal(h.count('recovery-prepare'), 1); assert.equal(h.count('recovery-apply'), 1);
  assert.equal(h.count('open') + h.count('prepare') + h.count('apply'), 0);
  assert.deepEqual(h.workspace, retained); assert.equal(h.workspace.projects.a.lastSave, null);
  h.controller.dispose();
});

test('only fresh explicitly submitted recovery Final clears attention; Close and stale Apply evidence cannot', async () => {
  const historical = owner('final', { coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } });
  const old = status(6, null, historical);
  const h = await connected({ initial: old });
  assert.equal(h.state.recoveryProjects.length, 1); assert.equal(h.controller.start(), false);
  reviewingRecovery(h, { action: 'committed_cleanup' });
  h.controller.requestClose(); assert.equal(h.count('close'), 1);
  h.publish(recoveryOwner('final', { action: 'committed_cleanup', applySubmitted: false, nativeReason: 'discarded',
    coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'pending_state' } }));
  assert.equal(h.state.recoveryProjects.length, 1); assert.equal(h.state.attempt.handled, true);
  assert.equal(h.count('recovery-apply'), 0);
  const options = { action: 'committed_cleanup', sessionId: '9'.repeat(32) };
  const binding = reviewingRecovery(h, options);
  assert.equal(h.controller.recover(binding), true);
  const finished = recoveryOwner('final', options);
  h.publish({ ...finished, phase: 'finalizing', nativeFinality: 'pending' });
  assert.equal(h.state.recoveryProjects.length, 1); assert.equal(normalWorkflowRecovery(h.state.attempt.projection), false);
  h.publish(finished);
  assert.equal(h.state.recoveryProjects.length, 0); assert.equal(h.state.attempt.handled, true);
  assert.equal(h.controller.startReason(), null); assert.equal(workflowOwnerReason(h.state, 'a'), null);
  h.emit(old, false); // An older original terminal is observation, not a new pending journal.
  assert.equal(h.state.recoveryProjects.length, 0); assert.equal(h.state.integrityFailed, false);
  assert.equal(h.controller.recover(binding), false); assert.equal(h.count('recovery-apply'), 1);
  h.controller.dispose();
});

test('lost Recover reply observes once without resend, and Unknown or late settlement stays blocking', async () => {
  const h = await connected(); const binding = reviewingRecovery(h);
  assert.equal(h.controller.recover(binding), true); h.publish(recoveryOwner('applying'));
  h.last('recovery-apply').reject({ code: 'lost_reply', message: 'PRIVATE REJECTION' }); await flush();
  assert.equal(h.count('recovery-open'), 1); assert.equal(h.count('recovery-prepare'), 1); assert.equal(h.count('recovery-apply'), 1);
  assert.equal(h.count('status'), 2); assert.equal(h.count('close'), 0);
  const unknown = recoveryOwner('unknown', { nativeReason: 'cleanup_unknown', coreOutcome: recoveryOwner('final').coreOutcome });
  h.publish(unknown, { reason: 'cleanup_unknown' });
  h.publish({ ...unknown, lateSettled: true }, { reason: 'available' });
  assert.equal(h.state.nativeBlocked, true); assert.equal(normalWorkflowRecovery(h.state.attempt.projection), false);
  assert.equal(h.controller.inspectRecovery(), false); assert.equal(h.controller.recover(binding), false);
  assert.equal(h.controller.start(), false); assert.equal(h.count('recovery-apply'), 1);
  h.controller.dispose();
});

test('idle or conflict inspection closes the same owner without Prepare or Recover', async () => {
  for (const state of ['idle', 'conflict']) {
    const h = await connected(); const retained = structuredClone(h.workspace);
    assert.equal(h.controller.inspectRecovery(), true);
    h.publish(recoveryOwner('editing', { state }));
    assert.equal(h.count('close'), 1); assert.equal(h.count('recovery-prepare'), 0);
    assert.equal(h.count('recovery-apply'), 0); assert.equal(currentWorkflowRecoveryBinding(h.state), null);
    h.publish(recoveryOwner('final', { state, nativeReason: 'discarded',
      coreOutcome: { effect: 'not_started', journal: state === 'idle' ? 'not_created' : 'recovery_required',
        resources: 'settled', reason: state === 'idle' ? 'none' : 'pending_state' } }));
    assert.equal(h.state.attempt.handled, true); assert.equal(normalWorkflowRecovery(h.state.attempt.projection), false);
    assert.deepEqual(h.workspace, retained); assert.equal(h.count('close'), 1);
    h.controller.dispose();
  }
});

test('project or document changes retire a pre-Recover inspection and cannot reattach its token', async () => {
  const changed = await connected(); const binding = reviewingRecovery(changed);
  changed.dispatch({ type: 'select', project: { id: 'b', name: 'Other', path: '/never-read' } });
  assert.equal(changed.state.attempt.invalidated, true); assert.equal(changed.count('close'), 1);
  assert.equal(changed.controller.recover(binding), false); assert.equal(changed.count('recovery-apply'), 0);
  const document = await connected(); const old = reviewingRecovery(document);
  document.publish(recoveryOwner('reviewing'), { windowGeneration: ID.otherWindow });
  assert.equal(document.state.generationLost, true); assert.equal(document.controller.recover(old), false);
  assert.equal(document.controller.inspectRecovery(), false); assert.equal(document.count('recovery-apply'), 0);
  changed.controller.dispose(); document.controller.dispose();
});
