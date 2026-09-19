// Inert renderer DTO/state/promise checks only. These fixtures do not implement
// configuration or ignore policy and are NOT core/native/GUI finality evidence.
// No React, DOM, filesystem fixtures, network, subprocesses, clocks or polling.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import {
  canApplyEdit, configEditReducer, confirmedConfigSave, currentApplyBinding,
  draftMatches, editNotice, editRetainsDraft, editStartReason, initialConfigEdit,
  nativeReviewPath, nativeStartReason, noOpPlan, projectionNotice, saveHelp,
} from '../src/configEdit.ts';
import { ConfigEditController } from '../src/configEditController.ts';
import { editInputFits, isU32, normalEditResult, parseConfigEditStatus, projectionProgress, statusProgress, U32_MAX } from '../src/configEditProtocol.ts';
import { configurationStatus, draftStatus } from '../src/certainty.ts';
import { initialWorkspace, isDirty, savedRevisionFresh, workspaceReducer } from '../src/drafts.ts';
import { valueSummary } from '../src/preparation.ts';

const TOK = {
  window: 'a'.repeat(32), otherWindow: 'b'.repeat(32), session: 'c'.repeat(32),
  otherSession: 'd'.repeat(32), revision: 'e'.repeat(32), plan: 'f'.repeat(32), otherPlan: '1'.repeat(32),
};
const BASE = { schemaVersion: 1, android: { enabled: true, applicationId: 'com.example.inert' }, source: { candidateBranch: 'main' } };
const IGNORE = ['.mobile-release/', '.mobile-release-init-prepare/', '.mobile-release-init/', '.mobile-release-init-cleanup/',
  '.mobile-release-metadata-text-prepare/', '.mobile-release-metadata-text/', '.mobile-release-metadata-text-cleanup/'];
const assurance = {
  basis: 'schema-policy', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false,
  writesPerformed: false, releaseReadiness: 'unknown',
};
const validation = { valid: true, state: 'format-valid', issues: [], requirements: [], assurance };
const project = (id) => ({ id, name: `Inert ${id}`, path: `/inert/not-opened/${id}` });
const snapshot = (base) => ({
  root: '/inert/not-opened', observedAt: '', observationScope: 'single-request-non-atomic',
  config: { content: null, path: 'release/mobile-release.json', state: base === null ? 'missing' : 'format-valid', data: structuredClone(base), issues: [] },
  discovery: { state: 'unverified', partial: false, hints: {}, scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {} },
  assurance: { ...assurance, basis: 'static-text' }, issues: [],
});

function observed(workspace, base = BASE, id = 'a', requestId = 1) {
  workspace = workspaceReducer(workspace, { type: 'select', project: project(id) });
  workspace = workspaceReducer(workspace, { type: 'snapshot-start', projectId: id, requestId });
  return workspaceReducer(workspace, { type: 'snapshot-done', projectId: id, requestId, snapshot: snapshot(base), observedAt: requestId });
}

function loaded({ base = BASE, dirty = true } = {}) {
  let workspace = observed(initialWorkspace, base);
  if (base === null) workspace = workspaceReducer(workspace, { type: 'new-draft', projectId: 'a', draft: structuredClone(BASE) });
  if (dirty) workspace = workspaceReducer(workspace, { type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.submitted' });
  return workspace;
}

// Explicitly selected review fixtures, not a renderer payload/ignore builder.
function view(config = 'replace', ignore = 'preserve') {
  const changed = config !== 'preserve';
  const create = config === 'create';
  const operation = create ? 'add' : 'change';
  return {
    schemaVersion: 1,
    files: [
      { path: 'release/mobile-release.json', action: config, beforeBytes: create ? null : 240, afterBytes: config === 'preserve' ? 240 : 260 },
      { path: '.gitignore', action: ignore, beforeBytes: ignore === 'create' ? null : 130, afterBytes: ignore === 'preserve' ? 130 : 160 },
    ],
    createReleaseDirectory: create, rewritesConfigFormatting: config === 'replace',
    ignoreAdditions: ignore === 'preserve' ? [] : ignore === 'create' ? [...IGNORE] : [IGNORE[0]],
    preview: {
      schemaVersion: 1, validation: structuredClone(validation), assurance: structuredClone(assurance),
      comparison: {
        baseProvided: !create, kind: create ? 'proposed-create' : 'compare', state: 'complete', semanticallyChanged: changed,
        counts: { added: changed && create ? 1 : 0, changed: changed && !create ? 1 : 0, removed: 0 },
        changes: changed ? [{ path: 'android.applicationId', operation, before: create ? { present: false } : { present: true, type: 'string' }, after: { present: true, type: 'string' } }] : [],
        unreviewedCount: 0,
      },
      fields: [{ path: 'android.applicationId', state: 'required', present: true, reason: 'Inert core context fixture.' }],
    },
  };
}

function owner(phase = 'opening', options = {}) {
  const { base = BASE, draftRevision = 2, baselineGeneration = 1, plan = view(), ...overrides } = options;
  const hasPlan = ['reviewing', 'applying', 'finalizing', 'final', 'unknown'].includes(phase);
  return {
    projectId: 'a', sessionId: TOK.session, ownerGeneration: TOK.window, phase, reviewRemainingMs: 900_000,
    checkout: phase === 'opening' ? null : { revision: TOK.revision, base: structuredClone(base) },
    prepared: hasPlan ? { revision: TOK.revision, planToken: TOK.plan, draftRevision, baselineGeneration, view: structuredClone(plan) } : null,
    applySubmitted: ['applying', 'finalizing', 'final', 'unknown'].includes(phase),
    coreOutcome: phase === 'final' ? { effect: noOpPlan(plan) ? 'unchanged' : 'committed', journal: noOpPlan(plan) ? 'not_created' : 'clean', resources: 'settled', reason: 'none' } : null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false,
    ...overrides,
  };
}

function status(revision = 0, active = null, lastTerminal = null, reason = 'available', windowGeneration = TOK.window) {
  return { schemaVersion: 1, windowGeneration, statusRevision: revision, capability: { available: reason === 'available', reason }, active, lastTerminal };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((ok, fail) => { resolve = ok; reject = fail; });
  return { promise, resolve, reject };
}

// Fixed microtask drainage only; never a timeout, polling/retry loop or clock.
async function flush() { for (let index = 0; index < 12; index += 1) await Promise.resolve(); }

function setup({ workspace = loaded(), initial = status(), mode = 'native', subscribeGate = null } = {}) {
  let currentWorkspace = workspace;
  let registry = structuredClone(initial);
  let onEvent = null;
  let unlistened = 0;
  const calls = [];
  const reads = [];
  const receipts = [];
  const recoveries = [];
  const mutation = (kind, args) => {
    const pending = deferred();
    calls.push({ kind, args: structuredClone(args), ...pending });
    return pending.promise;
  };
  const api = {
    mode,
    subscribeConfigEdit: async (listener) => {
      calls.push({ kind: 'subscribe' });
      onEvent = listener;
      if (subscribeGate) await subscribeGate.promise;
      return () => { unlistened += 1; onEvent = null; };
    },
    configEditStatus: () => {
      calls.push({ kind: 'status', args: {} });
      return reads.length ? reads.shift().promise : Promise.resolve(structuredClone(registry));
    },
    openConfigEdit: (projectId) => mutation('open', { projectId }),
    prepareConfigEdit: (request) => mutation('prepare', request),
    applyConfigEdit: (sessionId, planToken) => mutation('apply', { sessionId, planToken }),
    closeConfigEdit: (sessionId) => mutation('close', { sessionId }),
  };
  const dispatch = (action) => { currentWorkspace = workspaceReducer(currentWorkspace, action); controller.syncDraft(); };
  const controller = new ConfigEditController({
    project: (id) => Object.hasOwn(currentWorkspace.projects, id) ? currentWorkspace.projects[id] : null,
    onConfirmedSave: (receipt) => { receipts.push(receipt); dispatch({ type: 'config-save-final', projectId: receipt.binding.projectId, receipt }); },
    onRecoveryRequired: (attention) => {
      recoveries.push(attention);
      dispatch({ type: 'config-save-recovery', projectId: attention.projectId, attention });
    },
  });
  const harness = {
    controller, api, calls, receipts, recoveries, dispatch,
    get workspace() { return currentWorkspace; },
    get state() { return controller.getSnapshot(); },
    get registry() { return registry; },
    get unlistened() { return unlistened; },
    count: (kind) => calls.filter((call) => call.kind === kind).length,
    last: (kind) => calls.filter((call) => call.kind === kind).at(-1),
    deferRead: () => { const pending = deferred(); reads.push(pending); return pending; },
    setRegistry: (value) => { registry = structuredClone(value); },
    emit: (value) => { registry = structuredClone(value); assert.ok(onEvent, 'inert event subscription exists'); onEvent(value); },
    owner: (phase, options = {}) => {
      const binding = controller.getSnapshot().attempt?.binding;
      return owner(phase, binding ? { base: binding.expectedBase, draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration, projectId: binding.projectId, ...options } : options);
    },
    publish: (projection, options = {}) => {
      const terminal = projection.phase === 'final' || projection.lateSettled;
      const value = status(options.revision ?? registry.statusRevision + 1, terminal ? null : projection,
        terminal ? projection : registry.lastTerminal, options.reason ?? registry.capability.reason, options.windowGeneration ?? registry.windowGeneration);
      harness.emit(value);
      return value;
    },
  };
  return harness;
}

async function connected(options) {
  const harness = setup(options);
  await harness.controller.connect(harness.api);
  return harness;
}

function reviewing(harness, plan = view()) {
  assert.equal(harness.controller.start('a'), true);
  harness.publish(harness.owner('opening'));
  harness.publish(harness.owner('editing'));
  assert.equal(harness.count('prepare'), 1);
  harness.publish(harness.owner('reviewing', { plan }));
  const binding = currentApplyBinding(harness.state);
  assert.ok(binding);
  return binding;
}

test('the bridge uses only the five fixed commands, exact arguments and exact event', async () => {
  const calls = [];
  const value = status();
  let listener;
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return value; }, async (event, callback) => {
    assert.equal(event, 'config-edit-state'); listener = callback; return () => {};
  });
  const request = { sessionId: TOK.session, revision: TOK.revision, expectedBase: BASE, draft: BASE, draftRevision: 1, baselineGeneration: 1 };
  await api.openConfigEdit('a');
  await api.prepareConfigEdit({ ...request, root: '/never-forward', force: true, deadline: 99, method: 'never-forward' });
  await api.applyConfigEdit(TOK.session, TOK.plan);
  await api.closeConfigEdit(TOK.session);
  await api.configEditStatus();
  assert.deepEqual(calls, [
    { command: 'open_config_edit', args: { projectId: 'a' } },
    { command: 'prepare_config_edit', args: request },
    { command: 'apply_config_edit', args: { sessionId: TOK.session, planToken: TOK.plan } },
    { command: 'close_config_edit', args: { sessionId: TOK.session } },
    { command: 'config_edit_status', args: {} },
  ]);
  let observed;
  await api.subscribeConfigEdit((item) => { observed = item; });
  listener(value);
  assert.equal(observed, value);
});

test('an unavailable bridge denies edit calls before invoke or event registration', async () => {
  let nativeCalls = 0;
  const api = createNativeApi('unavailable', async () => { nativeCalls += 1; }, async () => { nativeCalls += 1; return () => {}; });
  for (const operation of [
    () => api.openConfigEdit('a'), () => api.prepareConfigEdit({}), () => api.applyConfigEdit(TOK.session, TOK.plan),
    () => api.closeConfigEdit(TOK.session), () => api.configEditStatus(), () => api.subscribeConfigEdit(() => {}),
  ]) await assert.rejects(operation, { code: 'NativeBridgeRequired' });
  assert.equal(nativeCalls, 0);
  await assert.rejects(createNativeApi('native', async () => status()).subscribeConfigEdit(() => {}), { code: 'NativeBridgeRequired' });
});

test('preview, unavailable and unqualified capability states cannot acquire native edit authority', async () => {
  // The preview API itself is source-reviewed, not imported through its JSON
  // visual fixtures. This checks the shared controller's closed mode gate.
  for (const mode of ['preview', 'unavailable']) {
    const h = await connected({ mode });
    assert.equal(h.controller.start('a'), false);
    assert.equal(h.controller.apply({ sessionId: TOK.session, planToken: TOK.plan, draftRevision: 2, baselineGeneration: 1 }), false);
    await h.controller.checkStatus();
    assert.equal(h.calls.length, 0);
    assert.notEqual(editStartReason(h.state, h.workspace.projects.a), null);
  }
  for (const reason of ['runtime_unqualified', 'unsupported_platform', 'cleanup_unknown', 'shutdown']) {
    const h = await connected({ initial: status(0, null, null, reason) });
    assert.equal(h.controller.start('a'), false);
    assert.equal(h.count('open'), 0);
    assert.notEqual(editStartReason(h.state, h.workspace.projects.a), null);
  }
});

test('the DTO guard accepts retained legal phases, native no-op and ignore-only inventories', () => {
  for (const phase of ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'unknown']) {
    assert.ok(parseConfigEditStatus(status(1, owner(phase))), phase);
  }
  assert.ok(parseConfigEditStatus(status(1, null, owner('final'))));
  assert.ok(parseConfigEditStatus(status(1, null, owner('unknown', { lateSettled: true }))));
  for (const plan of [view('create', 'create'), view('preserve'), view('preserve', 'append'), view('replace', 'append')]) {
    const base = plan.files[0].action === 'create' ? null : BASE;
    assert.ok(parseConfigEditStatus(status(1, owner('reviewing', { plan, base }))));
    assert.ok(parseConfigEditStatus(status(2, null, owner('final', { plan, base }))));
  }
});

test('unknown keys, malformed tokens/counters and impossible lifecycle projections fail closed', () => {
  const mutations = [
    (s) => { s.extra = true; }, (s) => { delete s.schemaVersion; }, (s) => { s.schemaVersion = 2; },
    (s) => { s.windowGeneration = 'A'.repeat(32); }, (s) => { s.statusRevision = U32_MAX + 1; },
    (s) => { s.statusRevision = -1; }, (s) => { s.statusRevision = true; }, (s) => { s.statusRevision = 1.5; },
    (s) => { s.capability.reason = 'guessed_os_available'; }, (s) => { s.capability.available = false; },
    (s) => { s.active.sessionId = 'not-a-token'; }, (s) => { s.active.ownerGeneration = ''; },
    (s) => { s.active.projectId = 'inert\u0000bad'; }, (s) => { s.active.projectId = ''; },
    (s) => { s.active.reviewRemainingMs = Infinity; }, (s) => { s.active.phase = 'success'; },
    (s) => { s.active.nativeFinality = 'settled'; }, (s) => { s.active.lateSettled = true; },
    (s) => { s.active.nativeReason = 'arbitrary private message'; }, (s) => { s.active.stderr = 'never retain'; },
    (s) => { s.active.checkout.extra = true; }, (s) => { s.active.prepared.draftRevision = true; },
    (s) => { s.active.prepared.baselineGeneration = -1; }, (s) => { s.active.prepared.revision = TOK.otherPlan; },
    (s) => { s.active.applySubmitted = true; }, (s) => { s.active.checkout = null; },
    (s) => { s.active.coreOutcome = { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'stale_revision' }; },
    (s) => { s.lastTerminal = owner('editing'); }, (s) => { s.lastTerminal = owner('final'); },
    (s) => { s.active = owner('final'); },
  ];
  for (const mutate of mutations) {
    const value = status(1, owner('reviewing'));
    mutate(value);
    assert.equal(parseConfigEditStatus(value), null);
  }
  assert.equal(isU32(U32_MAX), true);
  assert.equal(parseConfigEditStatus(Object.create(status())), null);
});

test('native inventory validation is closed, bounded, ordered and rejects inconsistent summaries', () => {
  const mutations = [
    (v) => { v.files.reverse(); }, (v) => { v.files.push(v.files[0]); }, (v) => { v.files[0].path = '../other.json'; },
    (v) => { v.files[1].action = 'replace'; }, (v) => { v.files[0].beforeBytes = null; },
    (v) => { v.files[0].afterBytes = 512 * 1024 + 1; }, (v) => { v.files[1].afterBytes = 1024 * 1024 + 1; },
    (v) => { v.files[1].afterBytes = v.files[1].beforeBytes - 1; },
    (v) => { v.createReleaseDirectory = true; }, (v) => { v.rewritesConfigFormatting = false; },
    (v) => { v.ignoreAdditions = ['private-pattern']; }, (v) => { v.ignoreAdditions = [IGNORE[0], IGNORE[0]]; },
    (v) => { v.ignoreAdditions = [IGNORE[2], IGNORE[0]]; },
    (v) => { v.files[1].action = 'preserve'; v.files[1].afterBytes = v.files[1].beforeBytes; },
    (v) => { v.files[1].action = 'create'; v.files[1].beforeBytes = null; },
    (v) => { v.rawIgnore = 'not admitted'; }, (v) => { v.preview.comparison.semanticallyChanged = false; },
    (v) => { v.preview.comparison.baseProvided = false; }, (v) => { v.preview.comparison.state = 'partial'; },
    (v) => { v.preview.comparison.counts.changed = 2; }, (v) => { v.preview.comparison.unreviewedCount = 1; },
    (v) => { v.preview.comparison.changes[0].before.value = 'private'; },
    (v) => { v.preview.comparison.changes[0].after.count = 99; },
    (v) => { v.preview.validation.valid = false; }, (v) => { v.preview.validation.assurance.writesPerformed = true; },
    (v) => { v.preview.assurance.extra = false; }, (v) => { v.preview.fields[0].reason = 'x'.repeat(4097); },
    (v) => { v.preview.fields = Array.from({ length: 65 }, () => v.preview.fields[0]); },
    (v) => { v.preview.fields = Array.from({ length: 40 }, () => ({ path: 'android.enabled', state: 'optional', present: true, reason: 'x'.repeat(4096) })); },
  ];
  for (const mutate of mutations) {
    const plan = view('replace', 'append');
    mutate(plan);
    assert.equal(parseConfigEditStatus(status(1, owner('reviewing', { plan }))), null);
  }
});

test('configuration input bounds reject rather than truncate while allowing clean shared values', () => {
  assert.equal(editInputFits(BASE, BASE), true);
  assert.equal(editInputFits(null, { note: 'valid Unicode 😀' }), true);
  assert.equal(editInputFits({}, { text: 'é'.repeat(300_000) }), false);
  assert.equal(editInputFits({ text: 'x'.repeat(390 * 1024) }, { text: 'x'.repeat(390 * 1024) }), false);
  for (const draft of [{ list: Array(8001).fill(null) }, { note: '\ud800' }, { number: NaN }, { value: undefined }, []]) {
    assert.equal(editInputFits(null, draft), false);
  }
  let deep = {};
  for (let index = 0; index < 30; index += 1) deep = { child: deep };
  assert.equal(editInputFits(null, deep), false);
  const cycle = {};
  cycle.self = cycle;
  assert.equal(editInputFits(null, cycle), false);
  const incoming = status(1, owner('editing', { base: { text: 'x'.repeat(512 * 1024) } }));
  assert.equal(parseConfigEditStatus(incoming), null);
});

test('unknown core facts cannot be serialized as Final; only pre-child settled refusal can lack a receipt', () => {
  for (const facts of [
    { resources: 'unknown' }, { effect: 'unknown' }, { journal: 'unknown' },
  ]) {
    const projection = owner('final');
    projection.coreOutcome = { ...projection.coreOutcome, ...facts, reason: 'custody_unknown' };
    assert.equal(parseConfigEditStatus(status(1, null, projection)), null);
    assert.ok(parseConfigEditStatus(status(2, { ...projection, phase: 'unknown', nativeFinality: 'unknown' })));
  }
  assert.equal(parseConfigEditStatus(status(1, null, owner('final', { coreOutcome: null }))), null);
  assert.ok(parseConfigEditStatus(status(1, null, owner('final', {
    checkout: null, prepared: null, applySubmitted: false, coreOutcome: null, nativeReason: 'runtime_unavailable',
  }))));
  const invalidReason = owner('unknown', { coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'none' } });
  assert.equal(parseConfigEditStatus(status(1, invalidReason)), null);
});

test('normal success requires the complete finality/effect/journal/resource/reason tuple', () => {
  for (const plan of [view(), view('preserve')]) {
    for (const effect of ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) {
      for (const journal of ['not_created', 'clean', 'recovery_required', 'unknown']) {
        for (const resources of ['settled', 'unknown']) {
          for (const reason of ['none', 'filesystem_error']) {
            const projection = owner('final', { plan, coreOutcome: { effect, journal, resources, reason } });
            const expected = resources !== 'settled' || reason !== 'none' ? null :
              !noOpPlan(plan) && effect === 'committed' && journal === 'clean' ? 'saved' :
                noOpPlan(plan) && effect === 'unchanged' && journal === 'not_created' ? 'unchanged' : null;
            assert.equal(normalEditResult(projection), expected);
          }
        }
      }
    }
  }
  for (const overrides of [
    { phase: 'applying' }, { phase: 'finalizing' }, { phase: 'unknown' }, { nativeFinality: 'pending' },
    { nativeFinality: 'unknown' }, { nativeReason: 'cancelled' }, { lateSettled: true },
    { applySubmitted: false }, { coreOutcome: null }, { checkout: null }, { prepared: null },
  ]) assert.equal(normalEditResult(owner('final', overrides)), null);
});

test('subscribe precedes the initial status read; overtaking events cannot initialize authority alone', async () => {
  const gate = deferred();
  const h = setup({ subscribeGate: gate });
  const connecting = h.controller.connect(h.api);
  await flush();
  assert.deepEqual(h.calls.map((call) => call.kind), ['subscribe']);
  h.emit(status(2, owner('opening')));
  h.setRegistry(status(1)); // the initial read can be older than that event
  assert.equal(h.state.initialized, false);
  assert.equal(h.controller.start('a'), false);
  gate.resolve();
  await connecting;
  assert.deepEqual(h.calls.map((call) => call.kind), ['subscribe', 'status']);
  assert.equal(h.state.status.statusRevision, 2);
  assert.equal(h.state.attempt, null); // an existing native owner is not attached
  assert.equal(h.count('prepare'), 0);
});

test('concurrent and reentrant status checks coalesce without renewing or duplicating mutations', async () => {
  const h = await connected();
  const waiting = h.deferRead();
  let reentered = false;
  const unlisten = h.controller.subscribe(() => {
    if (h.state.readPending && !reentered) { reentered = true; void h.controller.checkStatus(); }
  });
  const first = h.controller.checkStatus();
  const second = h.controller.checkStatus();
  await flush();
  assert.equal(h.count('status'), 2); // one initial read plus one coalesced read
  assert.equal(h.count('subscribe'), 1);
  waiting.resolve(status());
  await Promise.all([first, second]);
  unlisten();
  assert.equal(h.state.readPending, false);
  assert.equal(h.count('open'), 0);
});

test('clean drafts can prepare a native no-op; no equality shortcut declares a save', async () => {
  const h = await connected({ workspace: loaded({ dirty: false }) });
  assert.equal(isDirty(h.workspace.projects.a), false);
  const binding = reviewing(h, view('preserve'));
  const request = h.last('prepare').args;
  assert.deepEqual(request.expectedBase, BASE);
  assert.deepEqual(request.draft, BASE);
  assert.equal(request.revision, TOK.revision);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.receipts.length, 0);
  assert.equal(noOpPlan(h.state.attempt.projection.prepared.view), true);
  assert.equal(h.controller.apply(binding), true);
  assert.equal(h.receipts.length, 0);
  const oldGeneration = h.workspace.projects.a.baselineGeneration;
  h.publish(h.owner('final', { plan: view('preserve') }));
  assert.equal(h.receipts.length, 1);
  assert.equal(h.workspace.projects.a.lastSave.result, 'unchanged');
  assert.equal(h.workspace.projects.a.baselineGeneration, oldGeneration);
  assert.equal(draftStatus(h.workspace.projects.a).label, 'No changes needed · not verified');
});

test('unchanged configuration plus ignore additions is a real native write plan', async () => {
  const h = await connected({ workspace: loaded({ dirty: false }) });
  const plan = view('preserve', 'append');
  const binding = reviewing(h, plan);
  assert.equal(noOpPlan(plan), false);
  assert.equal(h.controller.apply(binding), true);
  h.publish(h.owner('final', { plan }));
  assert.equal(h.receipts[0].result, 'saved');
  assert.equal(h.workspace.projects.a.baselineGeneration, 2);
  assert.deepEqual(h.workspace.projects.a.draft, BASE);
});

test('explicit create keeps expectedBase null; an existing checkout is never adopted as create authority', async () => {
  const h = await connected({ workspace: loaded({ base: null }) });
  const binding = reviewing(h, view('create', 'create'));
  assert.equal(h.last('prepare').args.expectedBase, null);
  assert.equal(h.controller.apply(binding), true);
  h.publish(h.owner('final', { plan: view('create', 'create') }));
  assert.equal(h.workspace.projects.a.lastSave.result, 'saved');
  assert.deepEqual(h.workspace.projects.a.baseline, h.workspace.projects.a.draft);

  for (const base of [null, BASE]) {
    const mismatch = await connected({ workspace: loaded({ base }) });
    const previous = mismatch.workspace.projects.a;
    assert.equal(mismatch.controller.start('a'), true);
    mismatch.publish(mismatch.owner('editing', { base: base === null ? BASE : null }));
    assert.equal(mismatch.count('prepare'), 0);
    assert.equal(mismatch.count('close'), 1);
    assert.equal(mismatch.state.attempt.invalidated, 'baseline_mismatch');
    assert.equal(mismatch.workspace.projects.a.draft, previous.draft);
    assert.equal(mismatch.workspace.projects.a.baseline, previous.baseline);
    assert.equal(mismatch.controller.start('a'), false);
  }
});

test('pending Opening cancellation remembers the original owner and closes it exactly once', async () => {
  const h = await connected();
  assert.equal(h.controller.start('a'), true);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.count('open'), 1);
  h.controller.requestClose();
  h.controller.requestClose();
  assert.equal(h.count('close'), 0);
  assert.match(editNotice(h.state).title, /waiting for the original session ID/);
  h.publish(h.owner('opening'));
  assert.equal(h.count('close'), 1);
  assert.deepEqual(h.last('close').args, { sessionId: TOK.session });
  h.publish(h.owner('editing'));
  h.controller.syncDraft();
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('close'), 1);
  assert.equal(editRetainsDraft(h.state, 'a'), true);
});

test('edits during opening, preparation or review invalidate only that session and never reprepare', async () => {
  for (const phase of ['opening', 'preparing', 'reviewing']) {
    const h = await connected();
    h.controller.start('a');
    h.publish(h.owner('opening'));
    if (phase !== 'opening') { h.publish(h.owner('editing')); h.publish(h.owner(phase)); }
    const prepares = h.count('prepare');
    h.dispatch({ type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.newer' });
    assert.equal(h.state.attempt.invalidated, 'draft_changed');
    assert.equal(h.count('close'), 1);
    h.publish(h.owner('reviewing'));
    h.controller.syncDraft();
    assert.equal(currentApplyBinding(h.state), null);
    assert.equal(h.count('apply'), 0);
    assert.equal(h.count('prepare'), prepares);
    assert.equal(h.count('close'), 1);
    assert.equal(h.workspace.projects.a.draft.android.applicationId, 'com.example.newer');
  }
});

test('Apply is latched synchronously; newer edits do not implicitly cancel an accepted submission', async () => {
  const h = await connected();
  const binding = reviewing(h);
  assert.equal(h.controller.apply(binding), true);
  assert.equal(h.controller.apply(binding), false);
  assert.equal(h.count('apply'), 1);
  assert.match(editNotice(h.state).title, /Apply requested/);
  assert.doesNotMatch(editNotice(h.state).detail, /Nothing has been applied/);
  h.dispatch({ type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.newer' });
  assert.equal(h.count('close'), 0);
  assert.equal(h.state.attempt.invalidated, null);
  assert.equal(h.receipts.length, 0);
  h.controller.requestClose();
  assert.equal(h.count('close'), 1);
  assert.match(editNotice(h.state).title, /Cancellation requested/);
  assert.match(editNotice(h.state).detail, /too late/);
});

test('wrong confirmation bindings cannot Apply and changed local baselines close before submission', async () => {
  const h = await connected();
  const binding = reviewing(h);
  for (const wrong of [
    { ...binding, sessionId: TOK.otherSession }, { ...binding, planToken: TOK.otherPlan },
    { ...binding, draftRevision: binding.draftRevision + 1 }, { ...binding, baselineGeneration: binding.baselineGeneration + 1 },
  ]) assert.equal(h.controller.apply(wrong), false);
  assert.equal(h.count('apply'), 0);
  assert.equal(draftMatches(h.state.attempt.binding, { ...h.workspace.projects.a, project: project('b') }), false);
  assert.equal(draftMatches(h.state.attempt.binding, { ...h.workspace.projects.a, baseline: {} }), false);
  // Reducer-level supersession stress, not UI permission to discard a live draft.
  h.dispatch({ type: 'reset', projectId: 'a' });
  assert.equal(h.controller.apply(binding), false);
  assert.equal(h.count('close'), 1);
});

test('native prepared replies must retain project/session/token and exact local counters', async () => {
  for (const mutate of [
    (p) => { p.prepared.draftRevision += 1; }, (p) => { p.prepared.baselineGeneration += 1; },
    (p) => { p.checkout.base = {}; }, (p) => { p.projectId = 'b'; },
  ]) {
    const h = await connected();
    h.controller.start('a');
    h.publish(h.owner('editing'));
    const prepared = h.owner('reviewing');
    mutate(prepared);
    h.publish(prepared);
    assert.equal(h.state.integrityFailed, true);
    assert.equal(currentApplyBinding(h.state), null);
    assert.equal(h.count('apply'), 0);
  }
  const h = await connected();
  reviewing(h);
  const changed = h.owner('reviewing');
  changed.prepared.planToken = TOK.otherPlan;
  h.publish(changed);
  assert.equal(h.state.integrityFailed, true);
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('apply'), 0);
});

test('a different session cannot satisfy the retained original attempt', async () => {
  const h = await connected();
  reviewing(h);
  h.publish(h.owner('final', { sessionId: TOK.otherSession }));
  assert.equal(h.state.attempt.sessionId, TOK.session);
  assert.equal(h.state.attempt.projection.phase, 'reviewing');
  assert.equal(currentApplyBinding(h.state), null);
  assert.equal(h.receipts.length, 0);
  assert.equal(h.controller.start('a'), false);
});

test('old owner generations stay read-only; a new native window generation revokes current authority', async () => {
  const old = await connected({ initial: status(4, owner('reviewing', { ownerGeneration: TOK.otherWindow })) });
  assert.equal(old.state.attempt, null);
  assert.equal(old.controller.start('a'), false);
  assert.equal(currentApplyBinding(old.state), null);
  assert.equal(old.count('prepare'), 0);

  const h = await connected();
  const binding = reviewing(h);
  h.publish(h.owner('reviewing'), { windowGeneration: TOK.otherWindow });
  assert.equal(h.state.generationLost, true);
  assert.equal(h.controller.apply(binding), false);
  h.publish(h.owner('final'), { windowGeneration: TOK.otherWindow });
  assert.equal(h.receipts.length, 0);
  assert.equal(editRetainsDraft(h.state, 'a'), true);
  assert.equal(h.controller.start('a'), false);
});

test('equal-revision timer snapshots clamp downward; contradictions and timer renewal do not grant Apply', async () => {
  const h = await connected();
  reviewing(h);
  const revision = h.state.status.statusRevision;
  h.publish(h.owner('reviewing', { reviewRemainingMs: 400 }), { revision });
  h.publish(h.owner('reviewing', { reviewRemainingMs: 800 }), { revision });
  assert.equal(h.state.integrityFailed, false);
  assert.equal(h.state.attempt.projection.reviewRemainingMs, 400);
  h.publish(h.owner('reviewing', { reviewRemainingMs: 0 }), { revision });
  assert.equal(currentApplyBinding(h.state), null);
  h.emit(status(revision + 1)); // a registry gap must not erase retained minima
  h.publish(h.owner('reviewing', { reviewRemainingMs: 500 }));
  assert.equal(h.state.attempt.projection.reviewRemainingMs, 0);
  assert.equal(currentApplyBinding(h.state), null);

  const first = status(9, owner('reviewing'));
  const contradiction = structuredClone(first);
  contradiction.active.prepared.planToken = TOK.otherPlan;
  assert.equal(statusProgress(first, contradiction), false);
  assert.equal(projectionProgress(first.active, { ...first.active, sessionId: TOK.otherSession }), false);
});

test('the retained original review is immutable even across an intervening registry omission', async () => {
  const h = await connected();
  reviewing(h);
  const old = h.state.attempt.projection;
  h.emit(status(h.registry.statusRevision + 1));
  const changed = h.owner('reviewing');
  changed.prepared.planToken = TOK.otherPlan;
  h.publish(changed);
  assert.equal(h.state.integrityFailed, true);
  assert.equal(h.state.attempt.projection, old);
  assert.equal(h.count('apply'), 0);
});

test('earlier core failure facts cannot be erased to manufacture a later normal success', () => {
  const failed = owner('finalizing', { coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } });
  assert.equal(projectionProgress(failed, owner('final')), false);
  assert.equal(projectionProgress(failed, { ...failed, coreOutcome: null }), false);
  const refused = { ...failed, coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'cancelled' } };
  assert.equal(projectionProgress(refused, owner('final')), false);
});

test('an out-of-order Unknown receipt still latches uncertainty without adopting stale authority', async () => {
  const h = await connected({ initial: status(8) });
  const previous = owner('unknown', { nativeReason: 'cleanup_unknown', coreOutcome: null, applySubmitted: false, prepared: null, checkout: null });
  h.emit(status(7, previous, null, 'cleanup_unknown'));
  assert.equal(h.state.status.statusRevision, 8);
  assert.equal(h.state.nativeBlocked, true);
  assert.equal(h.state.unknownEvidence.sessionId, TOK.session);
  assert.equal(h.state.attempt, null);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.receipts.length, 0);
});

test('native DTO and local submission copies cannot be changed after acceptance', async () => {
  const h = await connected();
  h.controller.start('a');
  h.publish(h.owner('editing'));
  const raw = status(h.registry.statusRevision + 1, h.owner('reviewing'));
  h.emit(raw);
  raw.active.prepared.planToken = TOK.otherPlan;
  raw.active.checkout.base.android.applicationId = 'changed after receipt';
  assert.equal(h.state.attempt.projection.prepared.planToken, TOK.plan);
  assert.equal(h.state.attempt.projection.checkout.base.android.applicationId, BASE.android.applicationId);
  assert.equal(Object.isFrozen(h.state.attempt.binding.draft.android), true);
  assert.equal(Object.isFrozen(h.state.attempt.projection.prepared.view), true);
});

test('out-of-order events outrank older admission replies and late invoke failure cannot undo Final', async () => {
  const h = await connected();
  h.controller.start('a');
  const opening = h.publish(h.owner('opening'));
  h.publish(h.owner('editing'));
  const preparing = h.publish(h.owner('preparing'));
  h.publish(h.owner('reviewing'));
  h.last('open').resolve(opening);
  h.last('prepare').resolve(preparing);
  await flush();
  assert.equal(h.state.attempt.projection.phase, 'reviewing');
  assert.equal(h.count('prepare'), 1);
  const binding = currentApplyBinding(h.state);
  assert.equal(h.controller.apply(binding), true);
  h.publish(h.owner('applying'));
  h.publish(h.owner('final'));
  const reads = h.count('status');
  h.last('apply').reject({ code: 'PrivateRejection', message: 'never show arbitrary text' });
  await flush();
  assert.equal(h.receipts.length, 1);
  assert.equal(h.state.observationIssue, null);
  assert.equal(h.count('status'), reads);
  assert.equal(h.workspace.projects.a.lastSave.result, 'saved');
});

test('a missing Open reply observes only the registry and closes the original registration when found', async () => {
  const h = await connected();
  h.controller.start('a');
  h.last('open').reject({ private: 'not a native outcome' });
  await flush();
  assert.equal(h.count('open'), 1);
  assert.equal(h.count('status'), 2);
  assert.equal(h.count('close'), 0);
  assert.equal(h.state.attempt.closeRequested, true);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.receipts.length, 0);
  h.setRegistry(status(1, h.owner('opening')));
  await h.controller.checkStatus();
  assert.equal(h.count('close'), 1);
  assert.equal(h.last('close').args.sessionId, TOK.session);
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('open'), 1);
});

test('a missing Prepare reply closes once and cannot cause a second preparation or replacement owner', async () => {
  const h = await connected();
  h.controller.start('a');
  h.publish(h.owner('editing'));
  h.publish(h.owner('preparing'));
  h.last('prepare').reject(new Error('inert private rejection'));
  await flush();
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('close'), 1);
  assert.equal(h.count('status'), 2);
  h.publish(h.owner('reviewing'));
  assert.equal(currentApplyBinding(h.state), null);
  h.controller.syncDraft();
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.workspace.projects.a.lastSave, null);
});

test('a missing Apply reply and failed observation never resend mutation or infer rollback', async () => {
  const h = await connected();
  const binding = reviewing(h);
  h.controller.apply(binding);
  h.publish(h.owner('applying'));
  const read = h.deferRead();
  h.last('apply').reject({ message: 'private arbitrary text' });
  await flush();
  read.reject({ private: 'status missing too' });
  await flush();
  assert.equal(h.state.observationIssue, 'bridge');
  assert.equal(h.state.nativeBlocked, false); // a missing reply is not a native Unknown receipt
  assert.equal(h.count('apply'), 1);
  assert.equal(h.count('close'), 0);
  assert.equal(h.controller.apply(binding), false);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.workspace.projects.a.lastSave, null);
  assert.doesNotMatch(JSON.stringify(editNotice(h.state)), /private arbitrary|status missing/);
  await h.controller.checkStatus();
  assert.equal(h.state.observationIssue, null);
  h.publish(h.owner('final'));
  assert.equal(h.receipts.length, 1);
  assert.equal(h.count('apply'), 1);
  assert.equal(h.count('open'), 1);
});

test('an unresolved mutation promise does not replace authoritative original-owner events', async () => {
  const h = await connected();
  const binding = reviewing(h); // neither Open nor Prepare promise is resolved
  h.controller.apply(binding);
  await h.controller.checkStatus();
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('apply'), 1);
  h.publish(h.owner('final'));
  assert.equal(h.receipts.length, 1);
  assert.equal(h.state.attempt.handled, true);
  assert.equal(h.count('open'), 1);
});

test('Finalizing or provisional commit evidence never advances the draft baseline', async () => {
  const h = await connected();
  const binding = reviewing(h);
  const before = h.workspace.projects.a;
  h.controller.apply(binding);
  for (const phase of ['applying', 'finalizing']) {
    h.publish(h.owner(phase, { coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' } }));
    assert.equal(h.receipts.length, 0);
    assert.equal(h.workspace.projects.a.baseline, before.baseline);
    assert.equal(confirmedConfigSave(h.state), null);
  }
  h.publish(h.owner('final'));
  assert.equal(h.receipts.length, 1);
  assert.notEqual(h.workspace.projects.a.baseline, before.baseline);
});

test('expiry/closed review retains all local values; a new owner needs a later explicit start', async () => {
  const h = await connected();
  reviewing(h);
  const before = h.workspace.projects.a;
  const facts = { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'cancelled' };
  h.publish(h.owner('finalizing', { applySubmitted: false, nativeReason: 'review_expired', coreOutcome: facts }));
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.receipts.length, 0);
  h.publish(h.owner('final', { applySubmitted: false, nativeReason: 'review_expired', coreOutcome: facts }));
  assert.equal(h.workspace.projects.a.draft, before.draft);
  assert.equal(h.workspace.projects.a.baseline, before.baseline);
  assert.equal(h.workspace.projects.a.removedFields, before.removedFields);
  assert.equal(h.count('open'), 1);
  assert.equal(editRetainsDraft(h.state, 'a'), false);
  assert.equal(h.controller.start('a'), true);
  assert.equal(h.count('open'), 2);
});

test('late cancellation with known commit is not normal Saved or a retryable rollback claim', async () => {
  const h = await connected();
  const binding = reviewing(h);
  h.controller.apply(binding);
  h.controller.requestClose();
  h.publish(h.owner('final', { nativeReason: 'cancelled' }));
  assert.equal(h.receipts.length, 0);
  assert.equal(isDirty(h.workspace.projects.a), true);
  assert.match(editNotice(h.state).title, /Changes committed/);
  assert.match(editNotice(h.state).detail, /Do not Apply again/);
});

test('native Unknown is sticky across late settlement, later availability and all project switches', async () => {
  const h = await connected();
  const binding = reviewing(h);
  h.controller.apply(binding);
  const unknown = h.owner('unknown', {
    nativeReason: 'io_error', coreOutcome: { effect: 'committed', journal: 'clean', resources: 'unknown', reason: 'custody_unknown' },
  });
  h.publish(unknown, { reason: 'cleanup_unknown' });
  assert.equal(h.state.nativeBlocked, true);
  assert.equal(h.receipts.length, 0);
  assert.match(editNotice(h.state).title, /Changes committed; completion is unverified/);
  h.publish({ ...unknown, lateSettled: true, coreOutcome: { ...unknown.coreOutcome, resources: 'settled' } }, { reason: 'available' });
  assert.equal(h.state.unknownEvidence.lateSettled, true);
  assert.equal(h.state.status.active, null);
  assert.equal(h.state.status.lastTerminal.phase, 'unknown');
  assert.equal(h.state.nativeBlocked, true);
  assert.equal(editRetainsDraft(h.state, 'a'), true);
  h.dispatch({ type: 'select', project: project('b') });
  h.dispatch({ type: 'new-draft', projectId: 'b', draft: structuredClone(BASE) });
  assert.equal(h.controller.start('b'), false);
  assert.equal(h.count('open'), 1);
  assert.equal(h.workspace.projects.a.lastSave, null);
  h.publish(h.owner('final'));
  assert.equal(h.state.integrityFailed, true); // Unknown cannot turn into ordinary success
  assert.equal(h.receipts.length, 0);
});

test('known settled recovery-required outcome blocks the affected project, not an available different one', async () => {
  const h = await connected();
  const binding = reviewing(h);
  h.controller.apply(binding);
  h.publish(h.owner('final', { coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' } }));
  assert.equal(h.state.nativeBlocked, false);
  assert.equal(h.workspace.projects.a.saveRecoveryRequired, true);
  assert.equal(h.receipts.length, 0);
  assert.equal(h.recoveries.length, 1);
  assert.equal(h.controller.start('a'), false);
  h.dispatch({ type: 'select', project: project('b') });
  h.dispatch({ type: 'new-draft', projectId: 'b', draft: structuredClone(BASE) });
  assert.equal(h.controller.start('b'), true);
  h.publish(h.owner('final', {
    sessionId: TOK.otherSession, checkout: null, prepared: null, applySubmitted: false,
    coreOutcome: null, nativeReason: 'runtime_unavailable',
  }));
  assert.equal(h.state.status.lastTerminal.projectId, 'b');
  assert.equal(nativeStartReason(h.state), null);
  h.dispatch({ type: 'reset', projectId: 'a' });
  h.dispatch({ type: 'snapshot-start', projectId: 'a', requestId: 50 });
  h.dispatch({ type: 'snapshot-done', projectId: 'a', requestId: 50, snapshot: snapshot(BASE), observedAt: 50 });
  assert.equal(h.workspace.projects.a.saveRecoveryRequired, true);
  assert.match(editStartReason(h.state, h.workspace.projects.a), /recovery attention/);
});

test('initial read-only recovery attention stays with its project after another terminal replaces it', async () => {
  const workspace = loaded();
  const before = workspace.projects.a;
  const recovery = owner('final', {
    ownerGeneration: TOK.otherWindow,
    coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' },
  });
  const h = await connected({ workspace, initial: status(10, null, recovery) });
  assert.equal(h.state.attempt, null);
  assert.equal(h.state.nativeBlocked, false);
  assert.equal(h.state.generationLost, false);
  assert.equal(h.workspace.projects.a.saveRecoveryRequired, true);
  assert.equal(h.workspace.projects.a.draft, before.draft);
  assert.equal(h.workspace.projects.a.baseline, before.baseline);
  assert.equal(h.workspace.projects.a.snapshot, before.snapshot);
  assert.equal(h.workspace.projects.a.removedFields, before.removedFields);
  assert.equal(h.workspace.projects.a.lastSave, null);
  assert.equal(h.receipts.length, 0);
  assert.equal(h.recoveries.length, 1);
  assert.equal(h.controller.start('a'), false);
  h.dispatch({ type: 'select', project: project('b') });
  h.dispatch({ type: 'new-draft', projectId: 'b', draft: structuredClone(BASE) });
  assert.equal(h.controller.start('b'), true);
  h.publish(h.owner('final', {
    sessionId: TOK.otherSession, checkout: null, prepared: null, applySubmitted: false,
    coreOutcome: null, nativeReason: 'runtime_unavailable',
  }));
  assert.equal(h.state.status.lastTerminal.projectId, 'b');
  assert.equal(h.controller.start('a'), false);
  h.controller.syncDraft();
  await h.controller.checkStatus();
  assert.equal(h.recoveries.length, 1); // no callback/reducer reentry loop
  assert.equal(h.receipts.length, 0);
  assert.deepEqual(Object.keys(h.state.recoveryProjects[0]).sort(), ['coreOutcome', 'nativeFinality', 'ownerGeneration', 'phase', 'projectId', 'sessionId']);
});

test('observed recovery is retained without raw drafts even before that project is loaded', async () => {
  const recovery = owner('final', {
    ownerGeneration: TOK.otherWindow,
    coreOutcome: { effect: 'rolled_back', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' },
  });
  const h = await connected({ workspace: observed(initialWorkspace, BASE, 'b'), initial: status(10, null, recovery) });
  assert.equal(Object.hasOwn(h.workspace.projects, 'a'), false);
  assert.equal(h.recoveries.length, 0);
  assert.equal(h.state.recoveryProjects.length, 1);
  assert.equal(h.controller.start('b'), true);
  h.publish(h.owner('final', {
    sessionId: TOK.otherSession, checkout: null, prepared: null, applySubmitted: false,
    coreOutcome: null, nativeReason: 'runtime_unavailable',
  }));
  h.dispatch({ type: 'select', project: project('a') });
  h.dispatch({ type: 'new-draft', projectId: 'a', draft: structuredClone(BASE) });
  assert.equal(h.workspace.projects.a.saveRecoveryRequired, true);
  assert.equal(h.workspace.projects.a.baseline, null);
  assert.equal(h.workspace.projects.a.baselineGeneration, 0);
  assert.equal(h.workspace.projects.a.lastSave, null);
  assert.equal(h.recoveries.length, 1);
  assert.equal(h.receipts.length, 0);
  assert.equal(h.controller.start('a'), false);
  assert.equal(h.state.recoveryProjects.length, 1);
  assert.equal(Object.hasOwn(h.state.recoveryProjects[0], 'checkout'), false);
  assert.equal(Object.hasOwn(h.state.recoveryProjects[0], 'prepared'), false);
});

test('negative recovery attention is bounded without evicting earlier project refusals', () => {
  let state = configEditReducer(initialConfigEdit, { type: 'connect', mode: 'native' });
  state = configEditReducer(state, { type: 'listening' });
  for (let index = 0; index < 65; index += 1) {
    const projection = owner('final', {
      projectId: `inert-${index}`, sessionId: index.toString(16).padStart(32, '0'),
      coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' },
    });
    state = configEditReducer(state, { type: 'observe', status: status(index + 1, null, projection), source: 'read' });
  }
  assert.equal(state.recoveryProjects.length, 64);
  assert.equal(state.recoveryProjects[0].projectId, 'inert-0');
  assert.equal(state.integrityFailed, true);
  assert.equal(state.observationIssue, 'protocol');
  assert.equal(state.nativeBlocked, false); // protocol refusal is not fabricated native Unknown
  assert.notEqual(nativeStartReason(state), null);
});

test('matching settled save advances only its baseline, keeps undo, and invalidates earlier responses', async () => {
  const h = await connected();
  h.dispatch({ type: 'edit', projectId: 'a', path: 'source.candidateBranch', value: undefined });
  const binding = reviewing(h);
  h.controller.apply(binding);
  const before = h.workspace.projects.a;
  h.dispatch({ type: 'validate-start', projectId: 'a', requestId: 11, revision: before.revision, baselineGeneration: before.baselineGeneration });
  h.dispatch({ type: 'review-start', projectId: 'a', binding: { id: 12, revision: before.revision, baselineGeneration: before.baselineGeneration } });
  h.dispatch({ type: 'snapshot-start', projectId: 'a', requestId: 13 });
  h.publish(h.owner('final'));
  const saved = h.workspace.projects.a;
  assert.equal(saved.draft, before.draft);
  assert.deepEqual(saved.baseline, before.draft);
  assert.equal(saved.revision, before.revision);
  assert.equal(saved.baselineGeneration, before.baselineGeneration + 1);
  assert.equal(saved.removedFields, before.removedFields);
  assert.equal(saved.removedFields.length, 1);
  assert.equal(saved.snapshot, before.snapshot);
  assert.equal(saved.snapshotPredatesSave, true);
  assert.equal(saved.snapshotRequest, null);
  assert.equal(saved.validationRequest, null);
  assert.equal(saved.reviewRequest, null);
  assert.equal(isDirty(saved), false);
  assert.equal(savedRevisionFresh(saved), true);
  assert.equal(configurationStatus(saved, false).label, 'Earlier static observation');
  assert.equal(draftStatus(saved).label, 'Saved revision · not verified');
  const state = h.workspace;
  h.dispatch({ type: 'validate-done', projectId: 'a', requestId: 11, result: validation });
  h.dispatch({ type: 'review-done', projectId: 'a', requestId: 12, result: view().preview });
  h.dispatch({ type: 'snapshot-done', projectId: 'a', requestId: 13, snapshot: snapshot(BASE), observedAt: 13 });
  assert.equal(h.workspace, state);
  h.publish(h.owner('final'));
  assert.equal(h.receipts.length, 1);
});

test('older successful Apply records its revision without replacing a newer draft or baseline', async () => {
  for (const supersedeBaseline of [false, true]) {
    const h = await connected();
    const binding = reviewing(h);
    h.controller.apply(binding);
    if (supersedeBaseline) {
      // Direct reducer stress only; the real discard UI rejects live owners.
      h.dispatch({ type: 'reset', projectId: 'a' });
    }
    h.dispatch({ type: 'edit', projectId: 'a', path: 'android.applicationId', value: 'com.example.newer' });
    h.dispatch({ type: 'edit', projectId: 'a', path: 'source.candidateBranch', value: undefined });
    const newer = h.workspace.projects.a;
    h.dispatch({ type: 'review-start', projectId: 'a', binding: { id: 90, revision: newer.revision, baselineGeneration: newer.baselineGeneration } });
    h.dispatch({ type: 'snapshot-start', projectId: 'a', requestId: 91 });
    h.publish(h.owner('final'));
    const after = h.workspace.projects.a;
    assert.equal(after.draft, newer.draft);
    assert.equal(after.baseline, newer.baseline);
    assert.equal(after.revision, newer.revision);
    assert.equal(after.baselineGeneration, newer.baselineGeneration);
    assert.equal(after.removedFields, newer.removedFields);
    assert.equal(after.reviewRequest.id, 90); // still a pure review of retained values
    assert.equal(after.snapshotRequest, null);
    assert.equal(after.snapshotPredatesSave, true);
    assert.equal(after.lastSave.resultingBaselineGeneration, null);
    assert.equal(after.lastSave.draftRevision, binding.draftRevision);
    assert.equal(savedRevisionFresh(after), false);
    assert.equal(isDirty(after), true);
    assert.equal(h.count('close'), 0);
  }
});

test('project switching and another project’s local edits cannot move the save binding', async () => {
  const h = await connected();
  const binding = reviewing(h);
  h.controller.apply(binding);
  h.dispatch({ type: 'select', project: project('b') });
  h.dispatch({ type: 'new-draft', projectId: 'b', draft: { schemaVersion: 1, note: 'inert other draft' } });
  const other = h.workspace.projects.b;
  assert.equal(h.controller.start('b'), false);
  h.publish(h.owner('final'));
  assert.equal(h.workspace.selectedId, 'b');
  assert.equal(h.workspace.projects.b, other);
  assert.equal(h.workspace.projects.a.lastSave.result, 'saved');
  assert.equal(h.count('close'), 0);
});

test('the draft reducer independently rejects wrong result bindings and old or duplicate receipts', async () => {
  const h = await connected();
  const binding = reviewing(h);
  const before = h.workspace;
  h.controller.apply(binding);
  h.publish(h.owner('final'));
  const receipt = h.receipts[0];
  const changes = [
    (r) => { r.binding.projectId = 'b'; }, (r) => { r.projection.projectId = 'b'; },
    (r) => { r.sessionId = TOK.otherSession; }, (r) => { r.planToken = TOK.otherPlan; },
    (r) => { r.binding.windowGeneration = TOK.otherWindow; },
    (r) => { r.binding.expectedBase = {}; }, (r) => { r.projection.prepared.revision = TOK.otherPlan; },
    (r) => { r.projection.prepared.draftRevision += 1; }, (r) => { r.projection.prepared.baselineGeneration += 1; },
    (r) => { r.projection.nativeReason = 'cancelled'; }, (r) => { r.projection.nativeFinality = 'unknown'; },
    (r) => { r.projection.applySubmitted = false; }, (r) => { r.projection.coreOutcome.reason = 'filesystem_error'; },
    (r) => { r.result = 'unchanged'; }, (r) => { r.statusRevision = -1; },
    (r) => { r.statusRevision = r.binding.startStatusRevision; },
  ];
  for (const change of changes) {
    const wrong = structuredClone(receipt);
    change(wrong);
    assert.equal(workspaceReducer(before, { type: 'config-save-final', projectId: 'a', receipt: wrong }), before);
  }
  const saved = h.workspace;
  assert.equal(workspaceReducer(saved, { type: 'config-save-final', projectId: 'a', receipt }), saved);
  const older = structuredClone(receipt);
  older.sessionId = TOK.otherSession;
  older.projection.sessionId = TOK.otherSession;
  older.statusRevision -= 1;
  assert.equal(workspaceReducer(saved, { type: 'config-save-final', projectId: 'a', receipt: older }), saved);
});

test('counter exhaustion and missing drafts deny admission without wrapping or coercion', async () => {
  const h = await connected();
  for (const property of ['revision', 'baselineGeneration']) {
    for (const count of [U32_MAX, U32_MAX + 1, -1, 1.5, true]) {
      assert.match(editStartReason(h.state, { ...h.workspace.projects.a, [property]: count }), /counter is exhausted/);
    }
  }
  assert.notEqual(editStartReason(h.state, { ...h.workspace.projects.a, draft: null }), null);
  assert.notEqual(editStartReason(h.state, { ...h.workspace.projects.a, draft: { text: 'x'.repeat(512 * 1024) } }), null);
  let state = configEditReducer(initialConfigEdit, { type: 'connect', mode: 'native' });
  state = configEditReducer(state, { type: 'listening' });
  state = configEditReducer(state, { type: 'observe', status: status(), source: 'read' });
  const invalid = { projectId: 'a', windowGeneration: TOK.window, startStatusRevision: 0, previousTerminalId: null, draftRevision: U32_MAX, baselineGeneration: 1, expectedBase: BASE, draft: BASE };
  assert.equal(configEditReducer(state, { type: 'begin', binding: invalid }), state);
  const exhausted = await connected({ initial: status(U32_MAX) });
  assert.equal(exhausted.controller.start('a'), false);
  assert.equal(exhausted.count('open'), 0);
});

test('safe notice/help/path summaries never expose arbitrary values, native exceptions or unknown field names', () => {
  const privateText = 'inert-private-value-must-not-display';
  const projection = owner('final', {
    nativeReason: 'io_error', coreOutcome: { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'filesystem_error' },
    error: privateText, stderr: privateText,
  });
  projection.checkout.base.private = privateText;
  assert.doesNotMatch(JSON.stringify(projectionNotice(projection)), new RegExp(privateText));
  const catalogue = { fields: [{ path: 'android.applicationId', label: 'Android application ID' }] };
  assert.deepEqual(nativeReviewPath(catalogue, 'android.applicationId'), { label: 'Android application ID', path: 'android.applicationId' });
  assert.deepEqual(nativeReviewPath(catalogue, 'android'), { label: 'Configuration section', path: 'android' });
  assert.equal(nativeReviewPath(catalogue, privateText).path, null);
  assert.doesNotMatch(JSON.stringify(nativeReviewPath(catalogue, privateText)), new RegExp(privateText));
  assert.equal(nativeReviewPath(null, 'android.applicationId').path, null);
  assert.equal(valueSummary({ present: true, type: 'string', value: privateText }), 'String · value omitted');
  assert.match(saveHelp.what, /release\/mobile-release\.json/);
  assert.match(saveHelp.what, /\.gitignore/);
  assert.match(saveHelp.format, /15-minute absolute/);
  assert.match(saveHelp.where, /destructive in-memory/);
  assert.match(saveHelp.failure, /never repeat Apply/);
});

test('disposal only requests best-effort close of the known owner; it never claims settlement', async () => {
  const h = await connected();
  reviewing(h);
  const before = h.workspace.projects.a;
  h.controller.dispose();
  h.controller.dispose();
  assert.equal(h.count('close'), 1);
  assert.equal(h.unlistened, 1);
  assert.equal(h.receipts.length, 0);
  assert.equal(h.workspace.projects.a, before);
  assert.equal(h.state.attempt.projection.phase, 'reviewing');
  assert.equal(h.controller.start('a'), false);
});
