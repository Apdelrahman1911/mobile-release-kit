// Inert DATA and manually settled Promises only. No native queries, project
// paths, actual timers, DOM, filesystem watchers, network or source execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { EXTERNAL_PROJECT_CHECK_INTERVAL_MS, EXTERNAL_PROJECT_FOCUS_THROTTLE_MS, externalVersionBaseline,
  parseExternalProjectSnapshot, sameExternalProjectSnapshot } from '../src/externalProjectObservation.ts';
import { ExternalProjectObservationController } from '../src/externalProjectObservationController.ts';

const assurance = { basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
  gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' };
const content = (letter = 'a', bytes = 91) => ({ bytes, sha256: letter.repeat(64) });
function snapshot() {
  return { root: '/inert/never-opened', observedAt: '2026-10-19T00:00:00+00:00', observationScope: 'single-request-non-atomic',
    config: { path: 'release/mobile-release.json', state: 'format-valid', content: content(),
      data: { version: { source: 'release/version.properties' }, android: { enabled: true } }, issues: [] },
    discovery: { state: 'unverified', partial: false, hints: {},
      scan: { entries: 2, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: { maxEntries: 10000, scanSeconds: 5 } },
    assurance: { ...assurance }, issues: [] };
}
function workspace(input = snapshot()) {
  let state = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'inert-app', name: 'Example app', path: '/inert/never-opened' } });
  state = workspaceReducer(state, { type: 'snapshot-start', projectId: 'inert-app', requestId: 1 });
  return workspaceReducer(state, { type: 'snapshot-done', projectId: 'inert-app', requestId: 1, snapshot: input, observedAt: 1 });
}
function version(session) {
  const project = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, dirtyDraft: false, snapshotRequest: null, saveRecoveryRequired: false };
  return { mode: 'native', reason: null, project, readEpoch: 2, connectionGeneration: 3, selectionGeneration: 4,
    generationLost: false, selectionPending: false, pending: null, stale: false, error: null,
    resultBinding: { ...project, requestId: 8, readEpoch: 2, connectionGeneration: 3, selectionGeneration: 4 },
    result: { schemaVersion: 2, source: 'release/version.properties', version: { name: '1.2.3', build: 17 },
      savedConfig: content(), savedVersion: content('b', 33), observationScope: 'single-request-non-atomic', assurance: { ...assurance } } };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
class Clock {
  time = 10_000;
  next = 1;
  tasks = new Map();
  now = () => this.time;
  setTimeout = (callback, delay) => {
    assert.equal(delay, EXTERNAL_PROJECT_CHECK_INTERVAL_MS, 'only a bounded idle timer is installed');
    const id = this.next++;
    this.tasks.set(id, { at: this.time + delay, callback });
    return id;
  };
  clearTimeout = (id) => { this.tasks.delete(id); };
  advance(ms) {
    this.time += ms;
    const due = [...this.tasks].filter(([, task]) => task.at <= this.time);
    for (const [id, task] of due) { this.tasks.delete(id); task.callback(); }
  }
}
function harness({ withVersion = false, input = snapshot(), apply = true } = {}) {
  const h = { clock: new Clock(), workspace: workspace(input), api: null, versionState: null, reason: null, reads: [],
    active: 0, maxActive: 0, outcomes: [], actions: [], snapshots: [], versions: [], beforeApply: null, request: 100, capturedGuard: null };
  h.session = () => h.workspace.projects[h.workspace.selectedId] ?? null;
  if (withVersion) h.versionState = version(h.session());
  const read = async (kind, projectId) => {
    h.reads.push({ kind, projectId }); h.active++; h.maxActive = Math.max(h.maxActive, h.active);
    try {
      const supplied = (kind === 'snapshot' ? h.snapshots : h.versions).shift();
      return supplied === undefined ? structuredClone(kind === 'snapshot' ? input : h.versionState.result) : await supplied;
    } finally { h.active--; }
  };
  h.makeApi = () => ({ mode: 'native', snapshot: (id) => read('snapshot', id), observeReleaseVersion: (id) => read('version', id) });
  h.api = h.makeApi();
  h.controller = new ExternalProjectObservationController({
    current: () => ({ api: h.api, session: h.session(), versionState: h.versionState }),
    otherOperationReason: () => h.reason,
    clock: h.clock,
    onObservation: (outcome, stillCurrent) => {
      h.capturedGuard = stillCurrent;
      h.beforeApply?.();
      if (!stillCurrent()) return false;
      assert.equal(h.active, 0, 'the original native Promise has settled before delivery');
      h.outcomes.push(outcome);
      if (!apply) return true;
      h.controller.beforeWorkspaceAction(); // existing snapshot-intent first
      if (h.versionState) h.versionState = { ...h.versionState, stale: true };
      const requestId = h.request++;
      const actions = [{ type: 'snapshot-start', projectId: outcome.projectId, requestId }, outcome.kind === 'observed'
        ? { type: 'snapshot-done', projectId: outcome.projectId, requestId, snapshot: outcome.snapshot, observedAt: outcome.observedAt }
        : { type: 'snapshot-failed', projectId: outcome.projectId, requestId, error: outcome.error }];
      for (const action of actions) { h.actions.push(action); h.workspace = workspaceReducer(h.workspace, action); }
      h.controller.syncContext();
      return true;
    },
  });
  h.open = async () => { h.controller.setVisible(true); await h.controller.whenSettled(); };
  h.focus = async () => { h.clock.advance(EXTERNAL_PROJECT_FOCUS_THROTTLE_MS); await h.controller.focus(); };
  return h;
}

test('unchanged-idle-check-does-not-retire-any-owner-or-replace-clean-draft', async () => {
  const h = harness({ withVersion: true }), saved = h.workspace, owner = h.versionState;
  const newer = snapshot(); newer.observedAt = '2026-10-19T12:23:00Z'; h.snapshots.push(newer);
  await h.open();
  assert.deepEqual(h.reads.map((row) => row.kind), ['snapshot', 'version']);
  assert.deepEqual(h.actions, []); assert.deepEqual(h.outcomes, []);
  assert.equal(h.workspace, saved); assert.equal(h.versionState, owner);
  assert.equal(h.controller.getSnapshot().notice, null);
  assert.equal(h.controller.passiveBusyReason(), null);
  assert.equal(h.maxActive, 1);
});

test('exact-config-byte-change-preserves-clean-and-dirty-drafts-and-baselines', async () => {
  for (const dirty of [false, true]) {
    const h = harness();
    if (dirty) h.workspace = workspaceReducer(h.workspace, { type: 'edit', projectId: 'inert-app', path: 'android.enabled', value: false });
    const draft = h.session().draft, baseline = h.session().baseline, revision = h.session().revision;
    const next = snapshot(); next.config.content = content('c', 92); next.config.data.android.enabled = false;
    h.snapshots.push(next); await h.open();
    assert.equal(h.outcomes[0].change, 'project-files');
    assert.equal(h.session().draft, draft); assert.equal(h.session().baseline, baseline); assert.equal(h.session().revision, revision);
    assert.equal(h.session().sourceChanged, true);
    assert.deepEqual(h.session().savedConfigContent, next.config.content);
    assert.equal(h.controller.getSnapshot().notice.message, 'Files changed elsewhere; your draft is kept.');
    assert.deepEqual(h.actions.map((row) => row.type), ['snapshot-start', 'snapshot-done']);
    assert.equal(h.capturedGuard(), false, 'delivery guard cannot be retained as future consent');
  }
  const h = harness(); const whitespace = snapshot(); whitespace.config.content = content('c', 92); h.snapshots.push(whitespace);
  await h.open(); assert.equal(h.outcomes[0].change, 'project-files', 'different saved bytes matter even with identical JSON');
});

test('only-top-level-observation-time-is-ignored-not-config-or-hint-timestamps', () => {
  const left = snapshot(), right = snapshot(); right.observedAt = '2026-10-19T12:23:00Z';
  assert.equal(sameExternalProjectSnapshot(parseExternalProjectSnapshot(left), parseExternalProjectSnapshot(right)), true);
  right.config.data.observedAt = 'a real setting';
  assert.equal(sameExternalProjectSnapshot(parseExternalProjectSnapshot(left), parseExternalProjectSnapshot(right)), false);
  delete right.config.data.observedAt; right.discovery.hints.timestamp = 'a real hint';
  assert.equal(sameExternalProjectSnapshot(parseExternalProjectSnapshot(left), parseExternalProjectSnapshot(right)), false);
});

test('saved-version-byte-change-invalidates-with-actual-snapshot-not-manufactured-version-state', async () => {
  const h = harness({ withVersion: true }), original = h.versionState.result;
  const next = structuredClone(original); next.savedVersion = content('c', 34); h.versions.push(next);
  await h.open();
  assert.equal(h.outcomes[0].change, 'saved-version');
  assert.equal(h.outcomes[0].version, undefined);
  assert.equal(h.versionState.result, original); assert.equal(h.versionState.stale, true);
  assert.equal(h.controller.getSnapshot().notice.next, 'read-saved-version');
  assert.equal(h.session().sourceChanged, false);
});

test('non-atomic-snapshot-version-mismatch-invalidates-freshness-without-success-or-draft-replacement', async () => {
  const h = harness({ withVersion: true }), draft = h.session().draft, baseline = h.session().baseline, previous = h.session().snapshot;
  const next = structuredClone(h.versionState.result); next.savedConfig = content('c'); h.versions.push(next);
  await h.open();
  assert.equal(h.outcomes[0].kind, 'unavailable'); assert.equal(h.outcomes[0].error.code, 'external_project_mismatch');
  assert.deepEqual(h.actions.map((row) => row.type), ['snapshot-start', 'snapshot-failed']);
  assert.equal(h.session().savedConfigContent, null); assert.equal(h.session().snapshot, previous);
  assert.equal(h.session().draft, draft); assert.equal(h.session().baseline, baseline); assert.equal(h.versionState.stale, true);
});

test('singleflight-is-held-through-both-original-sequential-promises-and-focus-storms', async () => {
  const h = harness({ withVersion: true }), first = deferred(), second = deferred();
  h.snapshots.push(first.promise); h.versions.push(second.promise); h.controller.setVisible(true);
  const pending = h.controller.whenSettled();
  for (let i = 0; i < 50; i++) assert.equal(h.controller.focus(), pending);
  assert.deepEqual(h.reads.map((row) => row.kind), ['snapshot']); assert.ok(h.controller.passiveBusyReason());
  first.resolve(snapshot());
  for (let i = 0; i < 8; i++) await Promise.resolve();
  assert.deepEqual(h.reads.map((row) => row.kind), ['snapshot', 'version']); assert.ok(h.controller.passiveBusyReason());
  h.clock.advance(90_000); assert.equal(h.controller.focus(), pending); assert.equal(h.reads.length, 2);
  second.resolve(h.versionState.result); await pending;
  assert.equal(h.maxActive, 1); assert.equal(h.controller.passiveBusyReason(), null);
  await h.controller.focus(); assert.equal(h.reads.length, 2, 'focus after settlement is throttled');
});

test('thirty-second-idle-cadence-and-focus-throttle-stop-when-hidden-or-disposed', async () => {
  const h = harness(); await h.controller.focus(); assert.equal(h.reads.length, 0);
  await h.open(); assert.equal(h.reads.length, 1); assert.equal(h.clock.tasks.size, 1);
  h.clock.advance(EXTERNAL_PROJECT_CHECK_INTERVAL_MS - 1); assert.equal(h.reads.length, 1);
  h.clock.advance(1); await h.controller.whenSettled(); assert.equal(h.reads.length, 2);
  await h.focus(); assert.equal(h.reads.length, 3);
  h.controller.setVisible(false); assert.equal(h.clock.tasks.size, 0);
  h.clock.advance(90_000); await h.controller.focus(); assert.equal(h.reads.length, 3);
  await h.controller.dispose(); h.controller.setVisible(true); assert.equal(h.clock.tasks.size, 0); assert.equal(h.reads.length, 3);
});

test('all-owned-prepared-active-cancelling-recovery-unknown-and-other-passive-gates-pause-auto-reads', async () => {
  for (const reason of ['prepared edit', 'prepared build', 'active native task', 'cancellation requested', 'recovery required',
    'cleanup unknown', 'original path picker', 'passive query still settling', 'diagnostics owner', 'GitHub session', 'capability unavailable']) {
    const h = harness(); h.reason = reason; await h.open(); h.clock.advance(90_000); await h.controller.whenSettled();
    assert.equal(h.reads.length, 0, reason); assert.equal(h.actions.length, 0); assert.equal(h.clock.tasks.size, 1);
    h.reason = null; await h.controller.focus(); assert.equal(h.reads.length, 1, `can resume only after ${reason} settles`);
  }
  for (const patch of [{ saveRecoveryRequired: true }, { saveRecoveryNeedsReload: true }, { recoveryReloadRequest: 5 },
    { snapshotRequest: 5 }, { validationRequest: {} }, { reviewRequest: {} }, { suggestionRequest: {} }]) {
    const h = harness(); h.workspace = { ...h.workspace, projects: { 'inert-app': { ...h.session(), ...patch } } }; await h.open();
    assert.equal(h.reads.length, 0, JSON.stringify(patch));
  }
  for (const mode of ['preview', 'unavailable']) {
    const h = harness(); h.api = { ...h.api, mode }; await h.open(); assert.equal(h.reads.length, 0, mode);
  }
});

test('retirement-and-api-project-ABA-never-release-original-promise-or-admit-another-read', async () => {
  const h = harness(), first = deferred(); h.snapshots.push(first.promise); h.controller.setVisible(true);
  const pending = h.controller.whenSettled(), originalApi = h.api, originalWorkspace = h.workspace;
  h.controller.beforeWorkspaceAction(); h.api = h.makeApi(); h.controller.syncContext();
  h.workspace = workspaceReducer(h.workspace, { type: 'select', project: { id: 'other-app', name: 'Other', path: '/inert/other' } }); h.controller.syncContext();
  assert.equal(h.controller.focus(), pending); assert.ok(h.controller.passiveBusyReason());
  h.controller.beforeWorkspaceAction(); h.api = originalApi; h.workspace = originalWorkspace; h.controller.syncContext();
  assert.equal(h.controller.focus(), pending); assert.equal(h.reads.length, 1);
  const changed = snapshot(); changed.config.content = content('c'); first.resolve(changed); await pending;
  assert.equal(h.outcomes.length, 0); assert.equal(h.actions.length, 0); assert.equal(h.controller.passiveBusyReason(), null);
  await h.focus(); assert.equal(h.reads.length, 2);
});

test('manual-mutation-arrival-must-block-before-admission-even-if-it-retires-passive-display', async () => {
  const h = harness(), read = deferred(); h.snapshots.push(read.promise); h.controller.setVisible(true);
  h.controller.beforeWorkspaceAction(); // Root's early intent, not cancellation
  const canStartMutation = h.controller.passiveBusyReason() === null;
  assert.equal(canStartMutation, false); assert.equal(h.controller.getSnapshot().checking, true);
  read.resolve(snapshot()); await h.controller.whenSettled();
  assert.equal(h.controller.passiveBusyReason(), null); assert.equal(h.outcomes.length, 0);
});

test('context-change-at-callback-and-owner-arrival-after-release-veto-all-effects', async () => {
  for (const mode of ['owner-on-release', 'context-at-callback']) {
    const h = harness(); const changed = snapshot(); changed.config.content = content('c'); h.snapshots.push(changed);
    if (mode === 'owner-on-release') {
      let hadBusy = false;
      h.controller.subscribe(() => {
        if (h.controller.getSnapshot().checking) hadBusy = true;
        else if (hadBusy) { assert.equal(h.controller.passiveBusyReason(), null); h.reason = 'new prepared owner'; }
      });
    } else h.beforeApply = () => { h.controller.beforeWorkspaceAction(); h.workspace = { ...h.workspace, projects: { 'inert-app': { ...h.session(), revision: h.session().revision + 1 } } }; };
    await h.open(); assert.equal(h.outcomes.length, 0, mode); assert.equal(h.actions.length, 0, mode);
    assert.equal(h.controller.getSnapshot().notice, null);
  }
});

test('version-context-change-without-reducer-change-retires-passive-reply', async () => {
  const h = harness({ withVersion: true }), read = deferred(); h.snapshots.push(read.promise); h.controller.setVisible(true);
  h.versionState = { ...h.versionState, readEpoch: h.versionState.readEpoch + 1, stale: true };
  const changed = snapshot(); changed.config.content = content('c'); read.resolve(changed); await h.controller.whenSettled();
  assert.equal(h.outcomes.length, 0); assert.deepEqual(h.reads.map((row) => row.kind), ['snapshot']);
});

test('partial-malformed-invalid-and-read-errors-invalidate-saved-freshness-with-fixed-copy', async () => {
  const partial = snapshot(); partial.discovery.partial = true;
  const invalid = snapshot(); invalid.config = { ...invalid.config, state: 'invalid', data: null, content: null };
  const malformed = snapshot(); malformed.assurance.projectCodeExecuted = true;
  const unavailable = snapshot(); unavailable.config.content = null;
  for (const reply of [partial, invalid, malformed, unavailable, { unexpected: 'do not display this payload' }, null]) {
    const h = harness(); const before = h.session(); h.snapshots.push(reply); await h.open();
    assert.equal(h.outcomes[0].kind, 'unavailable'); assert.equal(h.session().snapshot, before.snapshot);
    assert.equal(h.session().draft, before.draft); assert.equal(h.session().baseline, before.baseline); assert.equal(h.session().savedConfigContent, null);
    assert.deepEqual(h.actions.map((row) => row.type), ['snapshot-start', 'snapshot-failed']);
  }
  const h = harness(), read = deferred(); h.snapshots.push(read.promise); h.controller.setVisible(true);
  read.reject({ code: 'query_timeout', message: 'private payload must never enter notice or error' }); await h.controller.whenSettled();
  assert.equal(h.session().savedConfigContent, null); assert.equal(h.session().snapshotError.code, 'external_project_unavailable');
  assert.doesNotMatch(JSON.stringify(h.outcomes), /private payload/);
});

test('failed-same-context-check-can-be-rechecked-without-silently-replacing-the-draft', async () => {
  const h = harness(), original = h.session(); const partial = snapshot(); partial.discovery.partial = true; h.snapshots.push(partial);
  await h.open(); assert.equal(h.session().savedConfigContent, null);
  await h.focus(); assert.equal(h.outcomes[1].change, 'refresh'); assert.deepEqual(h.session().savedConfigContent, content());
  assert.equal(h.session().draft, original.draft); assert.equal(h.session().baseline, original.baseline);
  assert.equal(h.session().snapshotError, null); assert.equal(h.controller.getSnapshot().notice.kind, 'refreshed');
});

test('root-mismatch-is-not-another-projects-change-or-success', async () => {
  const h = harness(), changed = snapshot(); changed.root = '/inert/wrong-project'; h.snapshots.push(changed);
  await h.open(); assert.equal(h.outcomes[0].kind, 'unavailable'); assert.equal(h.outcomes[0].error.code, 'external_project_mismatch');
  assert.equal(h.session().snapshot.root, '/inert/never-opened');
});

test('cleanup-unknown-retains-original-foreign-context-and-lifetime-pause-not-current-readiness', async () => {
  const h = harness(), read = deferred(); h.snapshots.push(read.promise); h.controller.setVisible(true);
  h.controller.beforeWorkspaceAction(); h.workspace = workspaceReducer(h.workspace, { type: 'select', project: { id: 'other-app', name: 'Other', path: '/inert/other' } });
  h.controller.syncContext(); read.reject({ code: 'cleanup_unknown', message: 'never repeat this private payload' }); await h.controller.whenSettled();
  assert.equal(h.outcomes.length, 0); assert.equal(h.actions.length, 0); assert.equal(h.controller.getSnapshot().notice, null);
  assert.equal(h.controller.getSnapshot().recovery.projectId, 'inert-app'); assert.equal(h.controller.getSnapshot().projectId, 'other-app');
  assert.ok(h.controller.passiveBusyReason()); h.api = h.makeApi(); h.controller.syncContext();
  h.clock.advance(90_000); await h.controller.focus(); assert.equal(h.reads.length, 1); assert.equal(h.clock.tasks.size, 0);
  assert.doesNotMatch(JSON.stringify(h.controller.getSnapshot()), /private payload/);
});

test('current-cleanup-unknown-invalidates-before-pausing-and-disposal-keeps-original-pending', async () => {
  const h = harness(), read = deferred(); h.snapshots.push(read.promise); h.controller.setVisible(true);
  read.reject({ code: 'release_version_cleanup_unknown' }); await h.controller.whenSettled();
  assert.equal(h.outcomes[0].kind, 'unavailable'); assert.equal(h.session().savedConfigContent, null); assert.ok(h.controller.passiveBusyReason());
  const late = harness(), pending = deferred(); late.snapshots.push(pending.promise); late.controller.setVisible(true);
  const disposal = late.controller.dispose(); assert.ok(late.controller.passiveBusyReason());
  pending.resolve(snapshot()); await disposal;
  assert.equal(late.controller.passiveBusyReason(), null); assert.equal(late.actions.length, 0); assert.equal(late.clock.tasks.size, 0);
});

test('snapshot-copy-is-bounded-detached-and-never-evaluates-accessors-or-toJSON', async () => {
  let invoked = 0;
  const accessor = snapshot(); Object.defineProperty(accessor.config, 'data', { enumerable: true, get() { invoked++; return {}; } });
  assert.equal(parseExternalProjectSnapshot(accessor), null);
  const serialized = snapshot(); serialized.toJSON = () => { invoked++; return snapshot(); };
  assert.equal(parseExternalProjectSnapshot(serialized), null);
  const oversized = snapshot(); oversized.discovery.hints.oversized = 'x'.repeat(3 * 1024 * 1024);
  assert.equal(parseExternalProjectSnapshot(oversized), null); assert.equal(invoked, 0);
  const raw = snapshot(), copied = parseExternalProjectSnapshot(raw); raw.config.data.android.enabled = false;
  assert.equal(copied.config.data.android.enabled, true); assert.equal(Object.isFrozen(copied.config.data), true);
  const h = harness(), read = deferred(); h.snapshots.push(read.promise); h.controller.setVisible(true);
  const error = {}; Object.defineProperty(error, 'code', { get() { invoked++; return 'cleanup_unknown'; } });
  read.reject(error); await h.controller.whenSettled(); assert.equal(invoked, 0); assert.equal(h.controller.getSnapshot().recovery, null);
});

test('version-baseline-needs-current-original-bindings-not-values-only', () => {
  const session = workspace().projects['inert-app'], state = version(session);
  assert.deepEqual(externalVersionBaseline(session, state), state.result);
  for (const patch of [{ mode: 'preview' }, { stale: true }, { pending: state.resultBinding }, { error: {} }, { reason: 'unavailable' },
    { readEpoch: 99 }, { connectionGeneration: 99 }, { selectionGeneration: 99 }, { generationLost: true }, { selectionPending: true },
    { resultBinding: { ...state.resultBinding, projectId: 'other-app' } }, { resultBinding: { ...state.resultBinding, observationGeneration: 99 } }]) {
    assert.equal(externalVersionBaseline(session, { ...state, ...patch }), null, JSON.stringify(patch));
  }
});

test('reentrant-context-subscriber-cannot-start-two-original-reads', async () => {
  const h = harness(), read = deferred(); h.snapshots.push(read.promise);
  let triggered = false;
  h.controller.subscribe(() => { if (!triggered) { triggered = true; void h.controller.focus(); } });
  h.controller.setVisible(true); assert.equal(h.reads.length, 1); assert.equal(h.maxActive, 1);
  read.resolve(snapshot()); await h.controller.whenSettled(); assert.equal(h.outcomes.length, 0);
});
