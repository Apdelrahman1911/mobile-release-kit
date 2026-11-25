// Bounded, synthetic UI/controller tests. No native bridge, build, Store,
// credential, filesystem edit, installed route or React-render qualification.
// One -B Python call obtains real passive core views from our source fixtures;
// it neither runs project code nor creates native checkout/plan authority.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { IDENTITY_NEW_WARNING, identityDataEqual, identityPreviewMatches, identityTerminalResult, identityValueFits,
  parseIdentityAnalysis, parseIdentityContext, parseIdentityOwnerSnapshot, parseIdentityPreview, parseIdentityRecovery } from '../src/projectIdentity.ts';
import { ProjectIdentityController } from '../src/projectIdentityController.ts';

const root = fileURLToPath(new URL('../../', import.meta.url));
const FIXTURE = JSON.parse(execFileSync('python3', ['-B', '-c', `
import json
from types import SimpleNamespace
from mobile_release.project_identity import IdentitySelection, analyze_project_identity, prepare_project_identity
from mobile_release.project_identity_recovery import view as recovery_view
from tests.unit.test_project_identity import ANDROID, IOS, NEW, OLD, android, ios, config
from tests.unit.helpers import android_config
out = {}
for name, files, choice in (('android', android(), ANDROID), ('ios', ios(), IOS),
    ('existing', android(), IdentitySelection('android', ':app')),
    ('approved', {**android(), 'release/mobile-release.json':json.dumps(android_config(status='approved')).encode()}, ANDROID),
    ('mismatch', {**android(), 'release/mobile-release.json':config(applicationId='com.example.other')}, ANDROID),
    ('dynamic', android('plugins { id("com.android.application") }\\nandroid { defaultConfig { applicationId = providers.gradleProperty("appId").get() } }'), ANDROID)):
    found = analyze_project_identity(files, choice)
    item = {'analysis':found.view}
    if found.supported:
        item['unchanged'] = prepare_project_identity(found, OLD, expected_revision=found.revision, intent='preserve').view
        if name in ('android','ios'):
            item['preview'] = prepare_project_identity(found, NEW, expected_revision=found.revision, intent='new-application').view
    out[name] = item
out['idle'] = recovery_view(None, False)
out['conflict'] = recovery_view(None, 'target_changed')
header = json.dumps({'transactionId':'e'*32,'identity':{'desiredIdentity':NEW}}).encode()
plan = json.dumps({'files':[{'path':'app/build.gradle.kts','before':{'size':120},'after':{'size':124}},
    {'path':'release/mobile-release.json','before':{'size':400},'after':{'size':404}}]}).encode()
for action in ('rollback','preparing_cleanup','committed_cleanup','rolled_back_cleanup'):
    out[action] = recovery_view(SimpleNamespace(header=header, plan=plan, action=action,
        entries=[('header.json', SimpleNamespace(directory=False)), ('marker', SimpleNamespace(directory=False))]), False)
print(json.dumps(out, separators=(',',':')))
`], { cwd: root, encoding: 'utf8', timeout: 15_000, maxBuffer: 512 * 1024, env: { PATH: process.env.PATH, PYTHONPATH: 'src', PYTHONDONTWRITEBYTECODE: '1' } }));

const ID = { project: '1'.repeat(32), window: 'a'.repeat(32), session: 'b'.repeat(32), plan: 'd'.repeat(32), recovery: 'f'.repeat(32) };
const OLD = 'com.example.reader', NEW = 'com.example.another';
const clone = (v) => structuredClone(v);
const ctx = (selection = FIXTURE.android.analysis.selection) => ({ projectId: ID.project, selection: clone(selection), contextEpoch: 0, preview: false, blocked: false });
const status = (active = null, lastTerminal = null, revision = 0) => ({ schemaVersion: 1, domain: 'project_identity', windowGeneration: ID.window,
  statusRevision: revision, capability: { available: true, reason: 'available' }, active, lastTerminal });
function projection(kind = 'android', phase = 'editing', view = null, options = {}) {
  const recover = !Object.hasOwn(FIXTURE[kind], 'analysis');
  const captured = recover ? FIXTURE[kind] : FIXTURE[kind].analysis;
  const revision = recover ? ID.recovery : captured.revision;
  return { domain: 'project_identity', intent: recover ? 'recover' : 'edit', projectId: ID.project, sessionId: ID.session,
    ownerGeneration: ID.window, phase, reviewRemainingMs: 900_000,
    checkout: phase === 'opening' ? null : { revision, view: clone(captured) },
    prepared: view === null ? null : { revision, planToken: ID.plan, view: clone(view) }, diagnostic: null,
    applySubmitted: ['applying', 'finalizing', 'final', 'unknown'].includes(phase), coreOutcome: null,
    nativeReason: 'none', nativeFinality: phase === 'final' ? 'settled' : phase === 'unknown' ? 'unknown' : 'pending', lateSettled: false, ...clone(options) };
}
const allControllers = [];
test.afterEach(() => { for (const c of allControllers.splice(0)) c.dispose(); });
function harness({ kind = 'android', context = ctx(FIXTURE[kind]?.analysis?.selection), mode = 'native', initial = null } = {}) {
  let currentContext = context, frame = initial ?? { busy: false, status: status() };
  const listeners = new Set(), calls = [], behavior = {};
  const publish = () => { for (const listener of [...listeners]) listener(); };
  const port = { mode, getSnapshot: () => behavior.peek ? behavior.peek(clone(frame)) : clone(frame), subscribe: (listener) => { listeners.add(listener); return () => listeners.delete(listener); } };
  for (const action of ['analyze', 'prepare', 'apply', 'inspectRecovery', 'prepareRecovery', 'recover', 'discard', 'checkStatus']) {
    port[action] = (request) => {
      calls.push({ action, request: clone(request) });
      if (behavior[action]) return behavior[action](request);
      frame = { ...frame, busy: true }; publish(); return true;
    };
  }
  const c = new ProjectIdentityController(() => currentContext, port);
  allControllers.push(c); c.subscribe(() => {});
  return { c, port, calls, behavior,
    get state() { return c.getSnapshot(); }, get frame() { return clone(frame); }, get context() { return currentContext; },
    raw(value) { frame = value; publish(); },
    contextIntent(value) { c.retire(); currentContext = value; c.sync(); },
    drift(value) { currentContext = value; c.sync(); },
    publish(p, overrides = {}) {
      frame = { busy: false, status: status(p?.phase === 'final' || p?.lateSettled ? null : p,
        p?.phase === 'final' || p?.lateSettled ? p : frame.status.lastTerminal, frame.status.statusRevision + 1), ...overrides };
      assert.ok(parseIdentityOwnerSnapshot(frame), 'synthetic owner fixture conforms to display contract'); publish();
    },
    open() { assert.equal(c.analyze(), true); this.publish(projection(kind)); assert.ok(this.state.analysis); },
    review({ unchanged = false } = {}) {
      this.open();
      if (!unchanged) { assert.equal(c.setIntent('new-application'), true); assert.equal(c.setDesiredIdentity(NEW), true); assert.equal(c.acknowledgeNewApplication(true), true); }
      assert.equal(c.prepare(), true);
      this.publish(projection(kind, 'reviewing', FIXTURE[kind][unchanged ? 'unchanged' : 'preview']));
      assert.equal(this.state.reviewCurrent, true); assert.equal(this.state.actions.apply, false);
    },
    reviewRecovery(action = 'rollback') {
      assert.equal(c.inspectRecovery(), true); this.publish(projection(action)); assert.equal(c.prepareRecovery(), true);
      this.publish(projection(action, 'reviewing', FIXTURE[action])); assert.equal(this.state.reviewCurrent, true);
    },
    count(action) { return calls.filter((v) => v.action === action).length; },
  };
}

test('actual Python core analysis/preview/recovery views parse without invented tokens or source text', () => {
  for (const key of ['android', 'ios', 'existing', 'approved', 'mismatch', 'dynamic']) {
    assert.ok(parseIdentityAnalysis(FIXTURE[key].analysis), key);
    if (FIXTURE[key].unchanged) assert.ok(parseIdentityPreview(FIXTURE[key].unchanged));
    if (FIXTURE[key].preview) assert.ok(parseIdentityPreview(FIXTURE[key].preview));
  }
  for (const key of ['idle', 'conflict', 'rollback', 'preparing_cleanup', 'committed_cleanup', 'rolled_back_cleanup']) assert.ok(parseIdentityRecovery(FIXTURE[key]), key);
  assert.equal(Object.hasOwn(FIXTURE.rollback, 'revision'), false);
  assert.equal(Object.hasOwn(FIXTURE.android.preview, 'planToken'), false);
  assert.equal(JSON.stringify(FIXTURE).includes('DO-NOT-EXPORT-THIS-SCRIPT'), false);
});

test('closed bounded copies reject getters, symbols, hidden keys, sparse arrays, cycles and overlarge values', () => {
  let getters = 0;
  const hostile = clone(FIXTURE.android.analysis);
  Object.defineProperty(hostile, 'identity', { enumerable: true, get() { getters++; return OLD; } });
  assert.equal(parseIdentityAnalysis(hostile), null); assert.equal(getters, 0);
  for (const mutate of [
    (v) => v.extra = true, (v) => v[Symbol('x')] = true,
    (v) => Object.defineProperty(v, 'hidden', { value: true }),
    (v) => v.locations = Array(2), (v) => v.locations.push(v),
    (v) => v.toJSON = () => { throw Error('never'); },
    (v) => v.nextStep = 'x'.repeat(128 * 1024), (v) => v.locations = Array(4097).fill(v.locations[0]),
  ]) { const v = clone(FIXTURE.android.analysis); mutate(v); assert.equal(parseIdentityAnalysis(v), null); }
  const original = clone(FIXTURE.android.analysis), safe = parseIdentityAnalysis(original);
  assert.ok(Object.isFrozen(safe)); assert.ok(Object.isFrozen(safe.selection)); assert.ok(Object.isFrozen(safe.locations[0]));
  original.locations[0].path = 'elsewhere'; assert.notEqual(safe.locations[0].path, 'elsewhere');
});

test('source/config mismatch and unsupported syntax carry an exact useful source location and never preview', () => {
  for (const kind of ['mismatch', 'dynamic']) {
    const h = harness({ kind }); h.open();
    assert.equal(h.state.analysis.state, 'unsupported'); assert.equal(h.state.actions.prepare, false);
    assert.equal(h.c.prepare(), false); assert.equal(h.count('prepare'), 0);
    assert.ok(h.state.diagnostic.path.endsWith(kind === 'mismatch' ? 'mobile-release.json' : 'build.gradle.kts'));
    assert.ok(h.state.diagnostic.line >= 1); assert.match(h.state.message, kind === 'mismatch' ? /disagree/ : /computed|overridden/);
  }
});

test('view vocabulary rejects namespace edits, private paths, missing warnings and contradictory saved identity', () => {
  for (const mutate of [
    (v) => v.changes[0].role = 'namespace', (v) => v.changes[0].path = '.private-fixture/control',
    (v) => v.warnings = [], (v) => v.retainVersionReservations = false,
    (v) => v.buildVerificationRequired = false, (v) => v.intent = 'preserve',
    (v) => v.changes[1].afterId = 'com.example.wrong', (v) => v.changes.push(clone(v.changes[0])),
  ]) { const v = clone(FIXTURE.android.preview); mutate(v); assert.equal(parseIdentityPreview(v), null); }
  const mismatch = clone(FIXTURE.android.analysis); mismatch.configuredIdentity = 'com.example.other';
  assert.equal(parseIdentityAnalysis(mismatch), null);
  assert.ok(identityPreviewMatches(FIXTURE.ios.preview, FIXTURE.ios.analysis, NEW, 'new-application'));
  const missing = clone(FIXTURE.ios.preview); missing.changes.splice(0, 1);
  assert.equal(identityPreviewMatches(missing, FIXTURE.ios.analysis, NEW, 'new-application'), false);
});

test('missing native port, preview and unqualified owner never admit operations', () => {
  const none = new ProjectIdentityController(() => ctx()); allControllers.push(none);
  const noContext = new ProjectIdentityController(() => null); allControllers.push(noContext);
  assert.equal(noContext.getSnapshot().session, null);
  for (const action of ['analyze', 'prepare', 'apply', 'inspectRecovery', 'prepareRecovery', 'recover', 'discard', 'checkStatus']) assert.equal(none[action](), false);
  const examples = [harness({ mode: 'preview' }), harness({ context: { ...ctx(), preview: true } }),
    harness({ initial: { busy: false, status: { ...status(), capability: { available: false, reason: 'runtime_unqualified' } } } })];
  for (const h of examples) {
    assert.equal(h.c.analyze(), false); assert.equal(h.c.inspectRecovery(), false); assert.equal(h.c.apply(), false);
    assert.equal(h.calls.length, 0); assert.match(h.state.message, /native|operation|recovery/);
  }
});

test('mount, local drafts and consent have no native effects; existing identity is the default with no autofill', () => {
  const h = harness(); assert.equal(h.calls.length, 0); assert.equal(h.state.intent, 'preserve'); assert.equal(h.state.desiredIdentity, '');
  h.open(); const n = h.calls.length;
  assert.equal(h.c.setIntent('new-application'), true);
  assert.equal(h.state.desiredIdentity, ''); assert.equal(h.state.actions.prepare, false);
  assert.equal(h.c.setDesiredIdentity(NEW), true); assert.equal(h.state.actions.prepare, false);
  assert.equal(h.c.acknowledgeNewApplication(true), true); assert.equal(h.state.actions.prepare, true);
  assert.equal(h.calls.length, n); assert.equal(h.state.analysis.identity, OLD);
});

test('published/existing or approved identity cannot be overridden with a new-app toggle', () => {
  for (const kind of ['existing', 'approved']) {
    const h = harness({ kind }); h.open();
    assert.equal(h.state.canChooseNew, false); assert.equal(h.c.setIntent('new-application'), false);
    assert.equal(h.c.setDesiredIdentity(NEW), false); assert.equal(h.c.acknowledgeNewApplication(true), false);
    assert.equal(h.state.intent, 'preserve'); assert.equal(h.state.actions.prepare, true);
    assert.equal(h.c.prepare(), true); assert.equal(h.calls.at(-1).request.desiredIdentity, OLD);
    assert.equal(h.calls.at(-1).request.intent, 'preserve');
  }
});

test('ID format stays exact: no trimming, lowercasing, source-package inference or platform interchange', () => {
  assert.ok(identityValueFits('com.Example_app.Reader', 'android')); assert.ok(identityValueFits('com.Example-app.Reader', 'ios'));
  for (const [value, platform] of [[` ${NEW}`, 'android'], [`${NEW} `, 'ios'], ['com.example-app', 'android'], ['com.example_app', 'ios'],
    ['com.7reader', 'android'], ['com', 'ios'], ['a.' + 'b'.repeat(254), 'android'], ['com.example\nreader', 'ios']]) assert.equal(identityValueFits(value, platform), false);
  const h = harness(); h.open(); h.c.setIntent('new-application'); h.c.setDesiredIdentity(` ${NEW}`); h.c.acknowledgeNewApplication(true);
  assert.equal(h.state.desiredIdentity, ` ${NEW}`); assert.equal(h.state.actions.prepare, false); assert.equal(h.c.prepare(), false);
});

test('actual preview, separate exact consent and one original admission are required before apply', () => {
  const h = harness(); h.review();
  assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 0);
  assert.equal(h.c.acknowledgeReview(true), true); assert.equal(h.state.actions.apply, true);
  assert.equal(h.c.apply(), true); assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 1);
  assert.deepEqual(h.calls.at(-1).request, { sessionId: ID.session, revision: FIXTURE.android.analysis.revision, planToken: ID.plan });
  assert.equal(h.state.result, null); assert.equal(h.state.busy, true); assert.equal(h.state.reviewAcknowledged, false);
});

test('the original session, checkout revision, full locations and plan cannot be replaced under consent', () => {
  for (const mutate of [
    (p) => p.sessionId = 'c'.repeat(32), (p) => p.prepared.planToken = 'e'.repeat(32),
    (p) => { p.checkout.revision = 'c'.repeat(32); p.checkout.view.revision = p.checkout.revision; p.prepared.revision = p.checkout.revision; p.prepared.view.revision = p.checkout.revision; },
    (p) => { p.checkout.view.locations[0].line += 1; p.prepared.view.changes[0].line += 1; },
  ]) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true);
    const changed = projection('android', 'reviewing', FIXTURE.android.preview); mutate(changed); h.publish(changed);
    assert.equal(h.state.actions.apply, false); assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 0);
  }
});

test('context drift and explicit project/source/API ABA intents retire review and preserve the local draft', () => {
  for (const intent of ['epoch', 'project-aba', 'selection-aba', 'noop']) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true); const original = clone(h.context);
    if (intent === 'epoch') h.drift({ ...original, contextEpoch: 1 });
    else if (intent === 'project-aba') { h.contextIntent({ ...original, projectId: '2'.repeat(32) }); h.contextIntent(original); }
    else if (intent === 'selection-aba') { h.contextIntent({ ...original, selection: { ...original.selection, target: ':other' } }); h.contextIntent(original); }
    else h.contextIntent(original);
    assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 0); assert.equal(h.state.desiredIdentity, NEW);
    assert.equal(h.c.acknowledgeReview(true), false); assert.match(h.state.message, /no longer current/);
  }
});

test('draft/consent intents after review cannot revive the same prepared token, including no-op input', () => {
  for (const change of [(c) => c.setDesiredIdentity(NEW), (c) => c.setIntent('preserve'), (c) => c.acknowledgeNewApplication(true)]) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true); change(h.c);
    assert.equal(h.c.apply(), false); assert.equal(h.c.acknowledgeReview(true), false); assert.equal(h.count('apply'), 0);
  }
});

test('a preview from another UI, an expired review and native blocked/pending state do not authorize apply', () => {
  const unbound = harness({ initial: { busy: false, status: status(projection('android', 'reviewing', FIXTURE.android.preview)) } });
  assert.equal(unbound.c.acknowledgeReview(true), false); assert.equal(unbound.c.apply(), false);
  for (const why of ['expired', 'pending', 'blocked']) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true);
    if (why === 'expired') h.publish(projection('android', 'reviewing', FIXTURE.android.preview, { reviewRemainingMs: 0 }));
    if (why === 'pending') h.raw({ ...h.frame, busy: true });
    if (why === 'blocked') h.drift({ ...h.context, blocked: true });
    assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 0);
  }
});

test('remaining-time display changes do not discard consent, but an expired handoff does not send', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true); let remaining = 500;
  h.behavior.peek = (frame) => { frame.status.active.reviewRemainingMs = remaining--; return frame; };
  assert.equal(h.c.apply(), true); assert.equal(h.count('apply'), 1);
  const expired = harness(); expired.review(); expired.c.acknowledgeReview(true); let reads = 0;
  expired.behavior.peek = (frame) => { frame.status.active.reviewRemainingMs = ++reads >= 3 ? 0 : 100; return frame; };
  assert.equal(expired.c.apply(), false); assert.equal(expired.count('apply'), 0);
});

test('a replaced method cannot retarget the retained original native admission', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true); let replacement = 0;
  h.port.apply = () => { replacement++; return true; };
  assert.equal(h.c.apply(), true); assert.equal(h.count('apply'), 1); assert.equal(replacement, 0);
});

test('reentrant listeners cannot duplicate or retarget an apply at the actual handoff', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true);
  let once = false, nested = null;
  h.c.subscribe(() => { if (h.state.busy && !once) { once = true; nested = h.c.apply(); h.contextIntent({ ...h.context, contextEpoch: 1 }); } });
  assert.equal(h.c.apply(), false); assert.equal(nested, false); assert.equal(h.count('apply'), 0);
  assert.equal(h.state.reviewAcknowledged, false);
});

test('a context mutation during the pre-admission read cannot send the earlier captured project', () => {
  const h = harness(); let reads = 0;
  h.c.subscribe(() => { if (++reads === 2) h.contextIntent({ ...h.context, projectId: '2'.repeat(32) }); });
  assert.equal(h.c.analyze(), false); assert.equal(h.count('analyze'), 0);
});

test('nonboolean/Promise/throwing admissions latch unknown without raw exceptions or retries', () => {
  for (const behavior of [() => undefined, () => Promise.resolve(true), () => { throw Error('PRIVATE EXCEPTION MUST NOT APPEAR'); }]) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true); h.behavior.apply = behavior;
    assert.equal(h.c.apply(), false); assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 1);
    assert.equal(h.state.result, null); assert.match(h.state.message, /Could not confirm/);
    assert.equal(JSON.stringify(h.state).includes('PRIVATE EXCEPTION'), false); assert.equal(h.state.actions.checkStatus, true);
  }
});

test('true without original owner admission is not synthesized into an operation; false consumes old review', () => {
  const fake = harness(); fake.behavior.analyze = () => true;
  assert.equal(fake.c.analyze(), false); assert.equal(fake.c.analyze(), false); assert.equal(fake.count('analyze'), 1);
  const declined = harness(); declined.review(); declined.c.acknowledgeReview(true); declined.behavior.apply = () => false;
  assert.equal(declined.c.apply(), false); assert.equal(declined.c.acknowledgeReview(true), false); assert.equal(declined.c.apply(), false);
  assert.match(declined.state.message, /Nothing was submitted/); assert.equal(declined.state.actions.discard, true);
});

test('known committed but cleanup/finality unknown never says saved, never retries or promises rollback', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true); h.c.apply();
  const core = { effect: 'committed', journal: 'recovery_required', resources: 'settled', reason: 'stale_revision' };
  h.publish(projection('android', 'final', FIXTURE.android.preview, { coreOutcome: core }));
  assert.equal(h.state.result, null); assert.match(h.state.message, /committed/); assert.match(h.state.message, /Do not apply it again/);
  assert.equal(h.state.actions.analyze, false); assert.equal(h.state.actions.inspectRecovery, true); assert.equal(h.c.apply(), false);
  const p = projection('android', 'unknown', FIXTURE.android.preview, { coreOutcome: { ...core, resources: 'unknown', reason: 'custody_unknown' } });
  assert.equal(identityTerminalResult(p), null);
});

test('malformed or missing status after an admitted apply keeps unknown and no-repeat guidance visible', () => {
  for (const status of [{ busy: false, status: { kind: 'saved', effect: 'committed' } }, { busy: false, status: null }]) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true); assert.equal(h.c.apply(), true);
    h.raw(status);
    assert.equal(h.state.result, null); assert.equal(h.state.tone, 'danger');
    assert.match(h.state.message, /Could not confirm/); assert.match(h.state.message, /Do not apply the change again/);
    assert.doesNotMatch(h.state.message, /No files will be changed|Read the saved project/);
    assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 1); assert.equal(h.state.actions.checkStatus, true);
    h.raw({ busy: false, status: null });
    assert.match(h.state.message, /Could not confirm/); assert.equal(h.state.tone, 'danger');
  }
});

test('settled stale, rolled-back and native failures remain visible instead of analysis next steps', () => {
  for (const [coreOutcome, nativeReason, expected] of [
    [{ effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'stale_revision' }, 'none', /project changed.*No ID change was applied/],
    [{ effect: 'rolled_back', journal: 'clean', resources: 'settled', reason: 'filesystem_error' }, 'none', /problem after restoring the original files/],
    [{ effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'none' }, 'io_error', /could not finish.*No ID change was applied/],
  ]) {
    const h = harness(); h.review(); h.c.acknowledgeReview(true); h.c.apply();
    h.publish(projection('android', 'final', FIXTURE.android.preview, { coreOutcome, nativeReason }));
    assert.equal(h.state.result, null); assert.equal(h.state.tone, 'danger'); assert.match(h.state.message, expected);
    assert.match(h.state.message, /Read the project again|read the project again/);
    assert.notEqual(h.state.message, FIXTURE.android.analysis.nextStep);
    assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 1); assert.equal(h.state.actions.analyze, true);
    const failureMessage = h.state.message;
    h.behavior.checkStatus = () => false; assert.equal(h.c.checkStatus(), false);
    assert.equal(h.state.message, failureMessage); assert.equal(h.state.tone, 'danger');
    assert.doesNotMatch(h.state.message, /stale_revision|filesystem_error|io_error/);
  }
});

test('settled early open failures remain visible without claiming a submitted edit or successful read', () => {
  for (const nativeReason of ['spawn_failed', 'runtime_unavailable', 'io_error']) {
    const h = harness(); assert.equal(h.c.analyze(), true);
    h.publish(projection('android', 'final', null, { checkout: null, applySubmitted: false, nativeReason }));
    assert.equal(h.state.result, null); assert.equal(h.state.analysis, null); assert.equal(h.state.tone, 'danger');
    assert.match(h.state.message, /could not finish reading or preparing/); assert.match(h.state.message, /No ID change was submitted/);
    assert.match(h.state.message, /Check status/); assert.notEqual(h.state.message, 'Read the saved project to find its app ID.');
    assert.equal(h.count('apply'), 0); assert.equal(h.state.actions.apply, false); assert.equal(h.state.actions.checkStatus, true);
  }
});

test('settled failed operation with retained journal requires recovery, not a new edit or an old-plan retry', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true); h.c.apply();
  h.publish(projection('android', 'final', FIXTURE.android.preview, {
    coreOutcome: { effect: 'not_started', journal: 'recovery_required', resources: 'settled', reason: 'stale_revision' },
  }));
  assert.equal(h.state.result, null); assert.equal(h.state.tone, 'danger');
  assert.match(h.state.message, /Keep its recovery files/); assert.match(h.state.message, /review the interrupted change/);
  assert.doesNotMatch(h.state.message, /restoring|No ID change was applied|make a new preview/);
  assert.equal(h.state.actions.analyze, false); assert.equal(h.state.actions.inspectRecovery, true);
  assert.equal(h.c.apply(), false); assert.equal(h.count('apply'), 1);
});

test('only original settled finality and the exact submitted plan yield success, not core/result-shaped DATA', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true); h.c.apply();
  const core = { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' };
  for (const p of [projection('android', 'applying', FIXTURE.android.preview, { coreOutcome: core }),
    projection('android', 'finalizing', FIXTURE.android.preview, { coreOutcome: core }),
    projection('android', 'unknown', FIXTURE.android.preview, { coreOutcome: core, nativeReason: 'cleanup_unknown' }),
    projection('android', 'final', FIXTURE.android.preview, { coreOutcome: core, nativeReason: 'caller_lost' })]) assert.equal(identityTerminalResult(p), null);
  const done = projection('android', 'final', FIXTURE.android.preview, { coreOutcome: core }); h.publish(done);
  assert.equal(h.state.result, 'saved'); assert.match(h.state.message, /built app before release/);
  const unrelated = harness({ initial: { busy: false, status: status(null, done, 3) } }); assert.equal(unrelated.state.result, null);
});

test('actual EditOwner late settlement stays unknown, never normal success or a new editable scope', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true); h.c.apply();
  const p = projection('android', 'unknown', FIXTURE.android.preview, { nativeReason: 'cleanup_unknown', lateSettled: true,
    coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' } });
  h.publish(p);
  assert.equal(h.state.result, null); assert.match(h.state.message, /committed/);
  assert.equal(h.state.actions.analyze, false); assert.equal(h.state.actions.inspectRecovery, false); assert.equal(h.state.actions.checkStatus, true);
  assert.equal(identityTerminalResult(p), null);
});

test('ordinary preserve/no-op path uses the actual same-ID core preview and has no changed-app claim', () => {
  const h = harness({ kind: 'existing' }); h.review({ unchanged: true }); h.c.acknowledgeReview(true); h.c.apply();
  h.publish(projection('existing', 'final', FIXTURE.existing.unchanged, {
    coreOutcome: { effect: 'unchanged', journal: 'not_created', resources: 'settled', reason: 'none' },
  }));
  assert.equal(h.state.result, 'unchanged'); assert.match(h.state.message, /No files were changed/);
  assert.deepEqual(FIXTURE.existing.unchanged.warnings, []);
});

test('recovery has distinct native capture, preview and consent; no borrowed edit token or current-platform guess', () => {
  const h = harness({ context: { ...ctx(), selection: null } }); h.reviewRecovery();
  assert.equal(h.state.analysis, null); assert.equal(h.state.actions.apply, false); assert.equal(h.c.apply(), false);
  assert.equal(h.c.recover(), false); assert.equal(h.c.acknowledgeReview(true), true);
  assert.equal(h.c.recover(), true); assert.equal(h.c.recover(), false); assert.equal(h.count('recover'), 1);
  assert.deepEqual(h.calls.at(-1).request, { sessionId: ID.session, revision: ID.recovery, planToken: ID.plan });
  h.publish(projection('rollback', 'final', FIXTURE.rollback, { coreOutcome: { effect: 'rolled_back', journal: 'clean', resources: 'settled', reason: 'none' } }));
  assert.equal(h.state.result, 'recovered'); assert.equal(h.state.context.selection, null);
});

test('committed recovery is cleanup only and conflicting/idle recovery never creates a mutation plan', () => {
  const h = harness(); h.reviewRecovery('committed_cleanup'); h.c.acknowledgeReview(true); h.c.recover();
  h.publish(projection('committed_cleanup', 'final', FIXTURE.committed_cleanup, {
    coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' },
  }));
  assert.equal(h.state.result, 'recovered'); assert.match(h.state.message, /committed app ID was kept/);
  assert.ok(h.state.recovery.files.every((r) => r.action === 'preserve'));
  for (const kind of ['idle', 'conflict']) {
    const other = harness(); other.c.inspectRecovery(); other.publish(projection(kind));
    assert.equal(other.c.prepareRecovery(), false); assert.equal(other.c.recover(), false); assert.equal(other.count('recover'), 0);
  }
});

test('recovery view/revision substitution, context ABA and edit consent cannot authorize recovery', () => {
  const h = harness(); h.reviewRecovery(); h.c.acknowledgeReview(true);
  const changed = projection('rollback', 'reviewing', FIXTURE.rollback);
  changed.checkout.view.files[0].beforeBytes++; changed.prepared.view.files[0].beforeBytes++;
  h.publish(changed); assert.equal(h.c.recover(), false); assert.equal(h.c.acknowledgeReview(true), false);
  const other = harness(); other.reviewRecovery(); other.c.acknowledgeReview(true); other.contextIntent(clone(other.context));
  assert.equal(other.c.recover(), false); assert.equal(other.count('recover'), 0);
});

test('closed owner/context DATA rejects another domain, bad finality and malformed replies without claiming Off/saved', () => {
  for (const mutate of [
    (v) => v.status.domain = 'project_initialization', (v) => v.status.statusRevision = -0,
    (v) => v.status.capability.available = false, (v) => v.status.active.nativeFinality = 'settled',
    (v) => v.status.active.checkout.extra = 'path grant',
  ]) { const value = { busy: false, status: status(projection()) }; mutate(value); assert.equal(parseIdentityOwnerSnapshot(value), null); }
  for (const context of [{ ...ctx(), contextEpoch: -0 }, { ...ctx(), preview: 'false' }, { ...ctx(), extra: 1 }]) assert.equal(parseIdentityContext(context), null);
  const h = harness(); h.raw({ busy: false, status: { kind: 'saved', effect: 'committed' } });
  assert.equal(h.state.result, null); assert.equal(h.state.actions.analyze, false); assert.equal(h.c.apply(), false);
});

test('close review uses the original discard gate once, and unmount never settles pending native work', () => {
  const h = harness(); h.review(); h.c.acknowledgeReview(true);
  assert.equal(h.c.discard(), true); assert.equal(h.count('discard'), 1); assert.equal(h.c.discard(), false);
  h.c.dispose(); assert.equal(h.count('discard'), 1); assert.equal(h.frame.busy, true); assert.equal(h.c.apply(), false);
});

test('comparison preserves array order but ignores harmless JSON object property ordering', () => {
  assert.equal(identityDataEqual({ a: 1, b: [2, 3] }, { b: [2, 3], a: 1 }), true);
  assert.equal(identityDataEqual({ a: [1, 2] }, { a: [2, 1] }), false);
  assert.equal(FIXTURE.android.preview.warnings[0], IDENTITY_NEW_WARNING);
});
