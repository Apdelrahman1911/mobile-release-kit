// Passive DTO/controller contracts. No subprocesses, selected files, native
// runtime, GUI, tool discovery or network; controlled promises are in-memory.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { EnvironmentController, environmentError, environmentRequestFits, environmentStartReason, parseEnvironmentResult } from '../src/environment.ts';
import { previewApi } from '../src/preview.ts';

const roleSets = {
  'android/build': ['android-jdk', 'android-gradle-wrapper', 'android-sdk'],
  'android/artifact-validation': ['android-jdk', 'android-bundletool'],
  'ios/build': ['apple-macos', 'apple-xcode', 'apple-signing-tools'],
  'ios/artifact-validation': ['apple-macos', 'apple-codesign', 'apple-openssl', 'apple-security-framework'],
};
const guidance = { label: 'Inert prerequisite', requiredness: 'required', requiredWhen: 'This activity.',
  what: 'A described prerequisite, not a detected tool.', why: 'Used by the selected core activity.',
  where: 'Your approved build environment.', format: 'Expected policy, not an installed version.', failure: 'Later native verification is still required.' };
function request(platform = 'android', operation = 'build') { return { draft: { currentDraft: true }, platform, operation }; }
function fixture(input = request()) {
  const requirements = roleSets[`${input.platform}/${input.operation}`].map((id) => {
    const baseline = { kind: 'platform-defined', version: null, build: null, sha256: null, maxBytes: null };
    let kind = 'native-os';
    if (id === 'android-jdk') { kind = 'external-toolchain'; baseline.kind = 'workflow-reference'; baseline.version = '21'; }
    if (id === 'android-gradle-wrapper' || id === 'android-sdk') { kind = id === 'android-sdk' ? 'external-toolchain' : 'project-file'; baseline.kind = 'project-defined'; }
    if (id === 'android-bundletool') { kind = 'bundled-helper'; Object.assign(baseline, { kind: 'exact-pin', version: '1.18.3', sha256: 'a'.repeat(64), maxBytes: 32520401 }); }
    if (id === 'apple-xcode') { kind = 'external-toolchain'; Object.assign(baseline, { kind: 'exact-pin', version: '26.3', build: '17C529' }); }
    return { id, kind, presence: 'unknown', versionState: 'unknown', inspection: 'not-run', baseline, help: { ...guidance } };
  });
  return { schemaVersion: 1, policyVersion: 'environment-requirements-v1', hostPlatform: 'linux',
    context: { platform: input.platform, operation: input.operation }, platformEnabled: true, state: 'requirements-only',
    coverage: 'toolchain-prerequisites-only', nativeInspection: 'unavailable', dependencyCompleteness: 'unknown', requirements,
    help: { platform: { ...guidance }, operation: { ...guidance } }, limitations: ['Unknown tools are not a readiness result.'],
    assurance: { basis: 'schema-policy', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
      gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown' } };
}
function project(id = 'p1', revision = 1) {
  return { project: { id, name: 'Inert project', path: 'Never observed' }, revision, baselineGeneration: 2,
    baseline: { savedBaseline: true }, draft: { currentDraft: true }, observationGeneration: 7 };
}
const info = { runtime: { state: 'available', mode: 'development' }, capabilities: { methods: [{ method: 'environment.requirements', available: true }] } };
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function controlled() {
  let selected = project();
  const calls = [];
  const api = { mode: 'native', environmentRequirements: (input) => {
    const task = deferred(); calls.push({ input, ...task }); return task.promise;
  } };
  const controller = new EnvironmentController(() => selected);
  controller.setConnection(api, info); controller.syncProject();
  return { controller, api, calls, get selected() { return selected; }, select(next) { selected = next; controller.syncProject(); } };
}

test('four role contracts and disabled-platform joins preserve unknown facts and full help', () => {
  for (const key of Object.keys(roleSets)) {
    const input = request(...key.split('/')), value = fixture(input);
    const accepted = parseEnvironmentResult(value, input);
    assert.deepEqual(accepted, value);
    assert.notEqual(accepted, value);
    assert.equal(accepted.assurance.releaseReadiness, 'unknown');
    for (const row of accepted.requirements) assert.equal(row.presence, 'unknown');
    const disabled = { ...value, platformEnabled: false, state: 'platform-disabled', requirements: [] };
    assert.deepEqual(parseEnvironmentResult(disabled, input), disabled);
    assert.equal(parseEnvironmentResult({ ...disabled, requirements: value.requirements }, input), null);
    assert.equal(parseEnvironmentResult(value, request(input.platform === 'ios' ? 'android' : 'ios', input.operation)), null);
  }
});

test('strict result admission rejects shape, order, context, authority flags, help and baseline substitutions', () => {
  const mutations = [
    (value) => { value.extra = 'PRIVATE'; }, (value) => { value.context.operation = 'artifact-validation'; },
    (value) => { value.hostPlatform = 'detected-mac'; }, (value) => { value.nativeInspection = 'passed'; },
    (value) => { value.assurance.toolsProbed = true; }, (value) => { value.assurance.releaseReadiness = 'ready'; },
    (value) => { value.requirements.reverse(); }, (value) => { value.requirements[1] = value.requirements[0]; },
    (value) => { value.requirements[0].presence = 'present'; }, (value) => { value.requirements[0].kind = 'native-os'; },
    (value) => { delete value.requirements[0].baseline.build; }, (value) => { value.requirements[0].baseline.sha256 = 'a'.repeat(64); },
    (value) => { value.requirements[0].baseline.version = 'x'.repeat(129); },
    (value) => { value.requirements[0].help.where = ' '; }, (value) => { value.help.platform.extra = 'PRIVATE'; },
    (value) => { value.help.operation.requiredness = 'conditional'; value.help.operation.requiredWhen = ''; },
    (value) => { value.help.operation.what = 'é'.repeat(513); }, (value) => { value.limitations = []; },
    (value) => { value.limitations.push('line\nbreak'); }, (value) => { value.dependencyCompleteness = 'complete'; },
  ];
  for (const mutate of mutations) { const value = fixture(); mutate(value); assert.equal(parseEnvironmentResult(value, request()), null); }
  const bundle = fixture(request('android', 'artifact-validation'));
  for (const bytes of [0, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    bundle.requirements[1].baseline.maxBytes = bytes;
    assert.equal(parseEnvironmentResult(bundle, request('android', 'artifact-validation')), null);
  }
});

test('request admission is bounded and does not invoke getters or accept execution/path overrides', () => {
  assert.equal(environmentRequestFits(request()), true);
  const cyclic = {}; cyclic.self = cyclic;
  const sparse = []; sparse[2] = 'value';
  let reads = 0;
  const getter = { ...request(), get draft() { reads += 1; return {}; } };
  const deep = {}; let next = deep;
  for (let index = 0; index < 34; index += 1) { next.nested = {}; next = next.nested; }
  for (const value of [null, [], { ...request(), cwd: '/PRIVATE' }, { ...request(), executable: 'PRIVATE' },
    { ...request(), platform: 'linux' }, { ...request(), draft: { secret: 'x'.repeat(512 * 1024) } },
    { ...request(), draft: { cyclic } }, { ...request(), draft: { sparse } }, { ...request(), draft: deep }, getter,
    { ...request(), draft: { invalidUnicode: '\ud800' } }, { ...request(), draft: new Date() }]) assert.equal(environmentRequestFits(value), false);
  assert.equal(reads, 0);
});

test('bridge uses only the fixed passive command, clones inputs, binds the response and sanitizes errors', async () => {
  const pending = deferred(), calls = [];
  const api = createNativeApi('native', (command, input) => { calls.push({ command, input }); return pending.promise; });
  const input = request(), original = structuredClone(input), operation = api.environmentRequirements(input);
  input.platform = 'ios'; input.draft.currentDraft = false;
  assert.deepEqual(calls, [{ command: 'environment_requirements', input: original }]);
  pending.resolve(fixture(original));
  assert.deepEqual(await operation, fixture(original));
  const bad = createNativeApi('native', async () => fixture(request('ios')));
  await assert.rejects(bad.environmentRequirements(request()), (error) => error.code === 'protocol_error');
  const leaking = createNativeApi('native', async () => { throw { code: 'PRIVATE_CODE', message: 'PRIVATE_SECRET' }; });
  await assert.rejects(leaking.environmentRequirements(request()), (error) => error.code === 'environment_unavailable' && !JSON.stringify(error).includes('PRIVATE'));
  const unavailable = createNativeApi('unavailable', async () => { assert.fail('no native fallback'); });
  await assert.rejects(unavailable.environmentRequirements(request()), (error) => error.code === 'environment_unavailable');
});

test('controller supplies the current draft, not the saved baseline, and invalidation is synchronous', async () => {
  const task = controlled(), controller = task.controller;
  assert.equal(environmentStartReason(controller.getSnapshot()), null);
  const pending = controller.refresh();
  assert.deepEqual(task.calls[0].input.draft, task.selected.draft);
  assert.notDeepEqual(task.calls[0].input.draft, task.selected.baseline);
  task.calls[0].resolve(fixture(task.calls[0].input)); await pending;
  assert.equal(controller.getSnapshot().stale, false);
  const earlier = controller.getSnapshot().result;
  task.select({ ...task.selected, revision: 2, draft: { changedDraft: true } });
  assert.equal(controller.getSnapshot().stale, true);
  assert.equal(controller.getSnapshot().result, earlier);
  const refreshed = controller.refresh();
  task.calls[1].resolve(fixture(task.calls[1].input)); await refreshed;
  assert.equal(controller.getSnapshot().resultBinding.draftRevision, 2);
  assert.equal(controller.getSnapshot().stale, false);
  controller.dispose();
});

test('switch-away/back, draft/baseline/context/reload changes reject old success/error without clearing new pending', async () => {
  const invalidations = [
    (task) => { const first = task.selected; task.select(project('p2')); task.select(first); },
    (task) => task.select({ ...task.selected, revision: 2, draft: { newer: true } }),
    (task) => task.select({ ...task.selected, baselineGeneration: 3 }),
    (task) => { task.controller.setContext('ios', 'artifact-validation'); task.controller.setContext('android', 'build'); },
    (task) => { task.controller.beginConnection(); task.controller.setConnection(task.api, info); },
    (task) => { task.controller.connectionUnavailable(); task.controller.setConnection(task.api, info); },
  ];
  for (const invalidate of invalidations) for (const oldFailure of [false, true]) {
    const task = controlled(), old = task.controller.refresh();
    invalidate(task);
    const newer = task.controller.refresh(), binding = task.controller.getSnapshot().pending;
    assert.equal(task.calls.length, 2);
    if (oldFailure) task.calls[0].reject({ code: 'cleanup_unknown', message: 'PRIVATE' });
    else task.calls[0].resolve(fixture(task.calls[0].input));
    await old;
    assert.equal(task.controller.getSnapshot().pending, binding);
    assert.equal(task.controller.getSnapshot().result, null);
    assert.equal(task.controller.getSnapshot().error, null);
    assert.equal(task.controller.getSnapshot().reason, null);
    task.calls[1].resolve(fixture(task.calls[1].input)); await newer;
    assert.equal(task.controller.getSnapshot().resultBinding, binding);
    assert.equal(task.controller.getSnapshot().pending, null);
    task.controller.dispose();
  }
});

test('a synchronous subscriber can invalidate before invocation and disposed controllers ignore completions', async () => {
  const task = controlled();
  const unsubscribe = task.controller.subscribe(() => {
    if (task.controller.getSnapshot().pending) task.select(project('p2'));
  });
  await task.controller.refresh();
  assert.equal(task.calls.length, 0);
  unsubscribe();
  const pending = task.controller.refresh();
  task.controller.dispose();
  task.calls[0].resolve(fixture(task.calls[0].input)); await pending;
  assert.equal(task.controller.getSnapshot().result, null);
});

test('invalid drafts use fixed recovery text; a rejected context can be corrected without a fake result', async () => {
  const task = controlled(), pending = task.controller.refresh();
  task.calls[0].reject({ code: 'environment_draft_invalid', message: 'PRIVATE_INPUT' }); await pending;
  assert.deepEqual(task.controller.getSnapshot().error, environmentError({ code: 'environment_draft_invalid' }));
  assert.equal(task.controller.getSnapshot().result, null);
  task.select({ ...task.selected, revision: 2 });
  const retry = task.controller.refresh();
  task.calls[1].resolve(fixture(task.calls[1].input)); await retry;
  assert.equal(task.controller.getSnapshot().error, null);
  task.controller.dispose();
});

test('explicit browser fixtures stay identifiable across connection changes and never become observed host data', async () => {
  const task = controlled();
  task.controller.setConnection(previewApi, await previewApi.appInfo());
  await task.controller.refresh();
  const state = task.controller.getSnapshot();
  assert.equal(state.resultBinding.mode, 'preview');
  assert.equal(state.result.hostPlatform, 'other');
  assert.ok(state.result.limitations[0].includes('fixture'));
  assert.ok(state.result.requirements.every((row) => row.presence === 'unknown' && row.inspection === 'not-run'));
  task.controller.beginConnection(); task.controller.setConnection(task.api, info);
  assert.equal(task.controller.getSnapshot().stale, true);
  assert.equal(task.controller.getSnapshot().resultBinding.mode, 'preview');
  task.controller.dispose();
});

test('guided UI and synchronous workspace/bootstrap wiring preserve field help and fixture provenance', () => {
  // Source-only integration guard, not an executed React/GUI test.
  const page = readFileSync(new URL('../src/pages/Environment.tsx', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  for (const field of ['guide.platform', 'guide.operation', 'row.help']) assert.ok(page.includes(`HelpButton content={${field}}`));
  assert.ok(page.includes("const resultPreview = state.resultBinding?.mode === 'preview'"));
  assert.ok(page.includes('Host not observed in browser preview'));
  assert.ok(page.includes('Earlier requirements are stale'));
  assert.ok(page.includes('EnvironmentDiagnostics state={diagnosticsState}') && !page.includes('Run native doctor'));
  assert.ok(app.includes('workspaceRef.current = next;\n    environmentControllerRef.current?.syncProject();'));
  assert.ok(app.indexOf('environment.beginConnection()') < app.indexOf('const connection = await desktopApi()'));
});
