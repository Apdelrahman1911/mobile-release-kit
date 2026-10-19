// Inert DTO, presentation and retained-controller tests only. No host tools,
// installers, native finality, process, network or credential material.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { ToolPreparationController } from '../src/toolPreparationController.ts';
import { encodeToolPreparationRequest, parseToolPreparationPlan, sameToolPreparationDecision } from '../src/toolPreparationProtocol.ts';
import { diagnosticToolGuidance, toolPreparationGuidance, xcodePreparationSteps } from '../src/toolPreparationGuidance.ts';

const clone = (value) => structuredClone(value);
const request = { schemaVersion: 1, projectId: 'project-a', expectedObservationRevision: 1 };
function copy() { return { schemaVersion: 1, catalogGeneration: 3, instance: 'a'.repeat(32), recordSha256: 'b'.repeat(64), inventorySha256: 'c'.repeat(64), osProviderSha256: 'd'.repeat(64) }; }
function plan(change = {}) {
  return { schemaVersion: 1, basis: 'tool-preparation-guidance',
    context: { projectId: 'project-a', sessionId: 'session-a', observationRevision: 1, savedConfigSha256: 'a'.repeat(64), requirementsSha256: 'b'.repeat(64), host: 'macos-arm64' },
    stamp: { catalogGeneration: 3, catalogRevision: 6, sourceGeneration: 2, sourceRevision: 4, registrationGeneration: 0, registrationRevision: 0, serviceGeneration: 0, serviceRevision: 0, diagnosticsRevision: 0 },
    platform: 'android', state: 'needs-preparation', action: 'choose-jdk', reason: 'selection-missing', reusable: [], unselectedSources: ['jdk', 'sdk', 'gradle'],
    policy: { host: 'macos-arm64', jdkVendor: 'temurin', jdk: '17.0.20.1', gradle: '8.14.5', agp: '8.9.2', sdkPlatform: 'android-35', sdkBuildTools: '35.0.0',
      distributionUrl: 'https://services.gradle.org/distributions/gradle-8.14.5-bin.zip', distributionSha256: 'e'.repeat(64) },
    xcode: { version: '26.3', build: '17C529' },
    assurance: { writesPerformed: false, projectCodeExecuted: false, downloadsPlanned: 0, executionAuthorized: false, releaseReadiness: 'not-assessed' }, ...change };
}
function harness(value = plan()) {
  let current = value, pending = null;
  const calls = [], reads = [];
  const actions = Object.fromEntries(['showProjectRequirements', 'refreshRegisteredTools', 'chooseRegisteredCopy', 'chooseSource', 'showSourceInspection', 'showToolService', 'showRecovery', 'showXcodeChecks', 'showXcodeInstructions', 'showBuild']
    .map((name) => [name, (...args) => { calls.push([name, ...args]); }]));
  const controller = new ToolPreparationController({ toolPreparationPlan: async (input) => { reads.push(clone(input)); return pending ? pending : clone(current); } }, actions);
  controller.select({ projectId: request.projectId, expectedObservationRevision: 1 });
  return { controller, calls, reads, set(value) { current = value; }, defer() { let resolve; pending = new Promise((yes) => { resolve = yes; }); return resolve; } };
}

test('the narrow planning request accepts no tool state, paths, pins, consent or getters', () => {
  assert.ok(encodeToolPreparationRequest(request));
  let getters = 0;
  for (const bad of [{ ...request, path: '/not-an-input' }, { ...request, consent: true }, { ...request, policies: [] },
    { ...request, projectId: 'project.with.dot' }, { ...request, expectedObservationRevision: 0 }, { ...request, expectedObservationRevision: 0xffffffff },
    { ...request, get projectId() { getters++; return 'project-a'; } }]) assert.equal(encodeToolPreparationRequest(bad), null);
  assert.equal(getters, 0);
});

test('closed planning projection rejects positive authority, incoherent reuse, other profiles and accessors', () => {
  assert.deepEqual(parseToolPreparationPlan(plan()), plan());
  let getters = 0;
  const accessor = plan(); Object.defineProperty(accessor.context, 'host', { enumerable: true, get() { getters++; return 'macos-arm64'; } });
  const roleGetter = plan(); Object.defineProperty(roleGetter.unselectedSources, '0', { enumerable: true, get() { getters++; return 'jdk'; } });
  const bads = [accessor, roleGetter, plan({ path: '/tool' }), plan({ state: 'can-reuse', action: 'use-selected-copy', reason: 'existing-selected' }),
    plan({ reusable: [copy(), copy()] }), plan({ unselectedSources: ['jdk', 'jdk'] }), plan({ platform: 'ios' }),
    plan({ state: 'recovery-required', action: 'review-protected-copy' })];
  for (const field of ['writesPerformed', 'projectCodeExecuted', 'executionAuthorized']) {
    const value = plan(); value.assurance[field] = true; bads.push(value);
  }
  const download = plan(); download.assurance.downloadsPlanned = 1; bads.push(download);
  const wrongHost = plan(); wrongHost.policy.host = 'macos-x86_64'; bads.push(wrongHost);
  const url = plan(); url.policy.distributionUrl += '?redirect=another'; bads.push(url);
  const wrongCopy = plan({ reusable: [copy()] }); wrongCopy.reusable[0].catalogGeneration++; bads.push(wrongCopy);
  for (const value of bads) assert.equal(parseToolPreparationPlan(value), null);
  assert.equal(getters, 0);
});

test('refresh is read-only; an explicit current continue delegates only the existing picker', async () => {
  const h = harness(); assert.equal(await h.controller.refresh(), true);
  assert.deepEqual(h.calls, []); assert.deepEqual(h.reads, [request]);
  assert.equal(await h.controller.continue(), true);
  assert.deepEqual(h.calls, [['chooseSource', 'jdk']]); assert.deepEqual(h.reads, [request, request]);
  assert.equal(h.controller.getSnapshot().stale, true);
  assert.equal(await h.controller.continue(), false); // forwarded is not an install result
});

test('registered reuse wins without installation and comparisons cannot be invented', async () => {
  const h = harness(plan({ action: 'choose-registered-copy', reason: 'existing-unselected', reusable: [copy()], unselectedSources: [] }));
  await h.controller.refresh();
  assert.equal(await h.controller.continue(), false);
  assert.equal(await h.controller.continue({ ...copy(), instance: 'f'.repeat(32) }), false);
  let getters = 0;
  assert.equal(await h.controller.continue({ ...copy(), get instance() { getters++; return 'a'.repeat(32); } }), false);
  assert.equal(getters, 0); assert.deepEqual(h.calls, []);
  assert.equal(await h.controller.continue(copy()), true);
  assert.deepEqual(h.calls, [['chooseRegisteredCopy', copy()]]);
  const reuse = harness(plan({ state: 'can-reuse', action: 'use-selected-copy', reason: 'existing-selected', reusable: [copy()], unselectedSources: [] }));
  await reuse.controller.refresh(); await reuse.controller.continue(); assert.deepEqual(reuse.calls, [['showBuild']]);
  assert.match(toolPreparationGuidance(reuse.controller.getSnapshot().plan).body, /No download or upgrade/);
});

test('all context, generations, pin and source-selection differences fence a displayed decision', async () => {
  const mutations = [
    ...['savedConfigSha256', 'requirementsSha256'].map((key) => (v) => { v.context[key] = 'f'.repeat(64); }),
    (v) => { v.context.sessionId = 'session-b'; }, (v) => { v.context.projectId = 'project-b'; },
    (v) => { v.context.observationRevision++; },
    (v) => { v.context.host = 'macos-x86_64'; v.policy.host = 'macos-x86_64'; },
    ...Object.keys(plan().stamp).map((key) => (v) => { v.stamp[key]++; }),
    (v) => { v.policy.distributionSha256 = 'f'.repeat(64); }, (v) => { v.policy.jdk = '21.0.1'; },
    (v) => { v.xcode.build = '17C530'; }, (v) => { v.unselectedSources = ['jdk']; },
  ];
  for (const mutate of mutations) {
    const h = harness(); await h.controller.refresh(); const next = plan(); mutate(next); h.set(next);
    assert.equal(sameToolPreparationDecision(plan(), next), false);
    assert.equal(await h.controller.continue(), false); assert.deepEqual(h.calls, []); assert.equal(h.controller.getSnapshot().stale, true);
  }
});

test('project switch and disposal discard late reads without manufacturing native cancellation or success', async () => {
  for (const dispose of [false, true]) {
    const h = harness(); const resolve = h.defer(); const read = h.controller.refresh();
    if (dispose) h.controller.dispose(); else h.controller.select({ projectId: 'project-b', expectedObservationRevision: 2 });
    resolve(plan()); assert.equal(await read, false); assert.deepEqual(h.calls, []); assert.equal(h.controller.getSnapshot().plan, null);
  }
});

test('invalidation and project switching retain the same in-flight read or forwarded action until settlement', async () => {
  for (const switchProject of [false, true]) {
    const h = harness(); const resolve = h.defer(); const original = h.controller.refresh();
    if (switchProject) h.controller.select({ projectId: 'project-b', expectedObservationRevision: 2 }); else h.controller.invalidate();
    assert.equal(h.controller.getSnapshot().pending, true);
    assert.equal(await h.controller.refresh(), false); assert.equal(h.reads.length, 1);
    resolve(plan()); assert.equal(await original, false); assert.equal(h.controller.getSnapshot().pending, false);
  }
  let finishAction, actionStarted;
  const started = new Promise((resolve) => { actionStarted = resolve; });
  const action = new Promise((resolve) => { finishAction = resolve; });
  let reads = 0, forwarded = 0;
  const controller = new ToolPreparationController({ toolPreparationPlan: async () => { reads++; return plan(); } }, {
    chooseSource: async () => { forwarded++; actionStarted(); await action; },
  });
  controller.select({ projectId: 'project-a', expectedObservationRevision: 1 }); await controller.refresh();
  const original = controller.continue(); await started;
  controller.invalidate(); controller.select({ projectId: 'project-b', expectedObservationRevision: 2 });
  assert.equal(controller.getSnapshot().pending, true); assert.equal(await controller.refresh(), false);
  assert.equal(await controller.continue(), false); assert.equal(reads, 2); assert.equal(forwarded, 1);
  finishAction(); assert.equal(await original, true); assert.equal(controller.getSnapshot().pending, false);
});

test('service, copy approval, recovery and Xcode guide actions navigate existing controls without installation', async () => {
  const actions = [
    ['check-tool-service', 'showToolService'], ['register-tool-service', 'showToolService'], ['open-tool-service-settings', 'showToolService'],
    ['inspect-sources', 'showSourceInspection'], ['review-protected-copy', 'showSourceInspection'], ['review-source-problem', 'showSourceInspection'],
    ['reconcile-setup', 'showRecovery'], ['install-xcode-manually', 'showXcodeInstructions'], ['inspect-xcode-copy', 'showXcodeChecks'],
  ];
  for (const [action, callback] of actions) {
    const value = plan({ action, unselectedSources: [] });
    if (action === 'reconcile-setup') { value.state = 'recovery-required'; value.reason = 'original-unsettled'; }
    if (action.includes('xcode')) { value.platform = 'ios'; value.policy = null; }
    const h = harness(value); assert.equal(await h.controller.refresh(), true); assert.deepEqual(h.calls, []);
    assert.equal(await h.controller.continue(), true); assert.deepEqual(h.calls, [[callback]]);
  }
  for (const value of [plan({ state: 'busy', action: 'wait-for-setup', reason: 'original-busy' }), plan({ state: 'unsupported', action: 'unsupported-host', reason: 'host-unavailable' })]) {
    const h = harness(value); await h.controller.refresh(); assert.equal(await h.controller.continue(), false); assert.deepEqual(h.calls, []);
  }
});

function diagnosticState(platform = 'ios') {
  const context = { projectId: 'project-a', draftRevision: 2, baselineGeneration: 3, platform, operation: 'build' };
  const result = { schemaVersion: 1, policyVersion: 'environment-diagnostics-v1', context: clone(context), hostPlatform: 'macos', outcome: 'complete',
    checks: [{ id: platform === 'ios' ? 'xcode' : 'java', state: 'completed', reason: 'observed', version: platform === 'ios' ? '26.3' : '21.0.1',
      build: platform === 'ios' ? '17C529' : null, returnCode: 0, baseline: platform === 'ios' ? { kind: 'exact-pin', version: '26.3', build: '17C529' }
        : { kind: 'workflow-reference', version: '21', build: null }, assessment: platform === 'ios' ? 'match' : 'no-local-policy', help: 'Inert presentation fixture' }],
    lifetime: { complete: true, fatal: false, contained: true, commandDispatched: true, commands: 1, inputClosed: true, handlersRestored: true, toolDescriptorsClosed: true, stopObserved: 'none' } };
  const projection = { runId: 'a'.repeat(32), ownerGeneration: 'b'.repeat(32), context: clone(context), phase: 'settled', finality: 'settled', outcome: 'complete', reason: 'none', result };
  return { mode: 'native', project: { projectId: 'project-a', draftRevision: 2, baselineGeneration: 3, hasDraft: true }, platform, operation: 'build',
    initialized: true, listening: true, selectionPending: false, observationIssue: null, nativeBlocked: false, integrityFailed: false, generationLost: false,
    unknownEvidence: null, attempt: null, status: { schemaVersion: 1, statusRevision: 4, capability: { available: true, reason: 'available' }, active: null, lastTerminal: clone(projection) },
    observation: { projection, statusRevision: 4, receivedAt: 123, provenance: 'native-status', binding: null, stale: false } };
}

test('real diagnostics presentation needs current original settled context, not capability or an earlier match', () => {
  assert.match(diagnosticToolGuidance(diagnosticState()).title, /version matches; more checks remain/);
  const mutations = [
    (s) => { s.mode = 'preview'; }, (s) => { s.observation = null; }, (s) => { s.observation.stale = true; },
    (s) => { s.project.draftRevision++; }, (s) => { s.project.baselineGeneration++; }, (s) => { s.project.projectId = 'project-b'; },
    (s) => { s.observation.projection.finality = 'pending'; }, (s) => { s.observation.projection.phase = 'stopping'; },
    (s) => { s.observation.projection.reason = 'context-changed'; }, (s) => { s.observation.projection.result.lifetime.toolDescriptorsClosed = false; },
    (s) => { s.nativeBlocked = true; }, (s) => { s.integrityFailed = true; }, (s) => { s.generationLost = true; },
    (s) => { s.status.lastTerminal.runId = 'c'.repeat(32); }, (s) => { s.status.statusRevision = 3; },
    (s) => { s.observationIssue = 'bridge'; }, (s) => { s.listening = false; }, (s) => { s.status.active = clone(s.observation.projection); s.status.active.finality = 'pending'; },
  ];
  for (const mutate of mutations) { const state = diagnosticState(); mutate(state); assert.doesNotMatch(diagnosticToolGuidance(state).title, /version matches/); }
});

test('manual guidance distinguishes exact Xcode build, companion and Java workflow examples', () => {
  const state = diagnosticState(); state.observation.projection.result.checks[0].build = '17C530';
  const guide = diagnosticToolGuidance(state); assert.match(guide.title, /Review/); assert.match(guide.body, /17C529/);
  assert.match(guide.steps.join(' '), /older companion restricted to macOS 26/);
  assert.match(guide.steps.join(' '), /working main app is not companion or iOS-build verification/);
  assert.match(guide.steps.join(' '), /do not delete/);
  assert.match(xcodePreparationSteps(null)[0], /current project requirements/);
  const android = diagnosticToolGuidance(diagnosticState('android'));
  assert.match(android.body, /workflow reference is not the protected-tool policy/); assert.doesNotMatch(android.title, /\bready\b|matches/);
  const picker = toolPreparationGuidance(plan()); assert.match(picker.body, /not evidence that it is missing/); assert.match(picker.steps[0], /17\.0\.20\.1/);
});

test('the existing Environment view is wired to the guide and original explicit native controls', () => {
  const source = readFileSync(new URL('../src/components/EnvironmentDiagnostics.tsx', import.meta.url), 'utf8');
  assert.match(source, /diagnosticToolGuidance\(state\)/); assert.match(source, /\{guidance\.body\}/);
  assert.match(source, /onClick=\{\(\) => controller\.start\(\)\}/); assert.match(source, /Check this computer/);
  assert.match(source, /controller\.cancel\(\{ runId: active\.runId, ownerGeneration: active\.ownerGeneration \}\)/);
  assert.match(source, /controller\.checkStatus\(\)/); assert.match(source, /if \(compact && !active && !unconfirmed && !unknown && !state\.observationIssue\) return null/);
  assert.doesNotMatch(source, /Open the Mac App Store/);
});
