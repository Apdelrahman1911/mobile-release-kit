// Inert UI/bridge/controller DATA only. No picker, tool, filesystem source or
// native qualification is created by these tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { AndroidBuildController, androidBuildOwnerReason } from '../src/androidBuild.ts';
import { initialWorkspace, workspaceReducer } from '../src/drafts.ts';
import { ANDROID_TOOL_SOURCES_EVENT, androidToolSourceHelp, encodeAndroidToolSourcesRequest,
  parseAndroidToolSourcesStatus } from '../src/androidToolSources.ts';
const clone = (value) => structuredClone(value);
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
const flush = async () => { for (let n = 0; n < 16; n++) await Promise.resolve(); };
const idle = () => ({ schemaVersion: 1, statusRevision: 0, sourceGeneration: 0, projectId: null,
  availability: 'available', phase: 'idle', reason: 'not-inspected', operation: null, selections: [],
  inspection: 'not-run', protectedCopy: 'not-created' });
const picked = (patch = {}) => ({ ...idle(), statusRevision: 2, sourceGeneration: 1, projectId: 'p1',
  phase: 'selected', reason: 'not-inspected', operation: { operationId: 1, sourceGeneration: 1, role: 'jdk' },
  selections: [{ role: 'jdk', displayName: 'example-17.jdk' }], ...patch });
const pending = (patch = {}) => picked({ phase: 'picking', reason: 'none', selections: [], availability: 'busy', ...patch });
const refused = (patch = {}) => picked({ phase: 'refused', reason: 'source-refused', selections: [], ...patch });

test('tool source commands have one actual Raw handler, generated permission and local-main admission', () => {
  const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
  const build = read('../src-tauri/build.rs'), shell = read('../src-tauri/src/shell.rs');
  const capability = JSON.parse(read('../src-tauri/capabilities/main.json'));
  const manifest = build.match(/const COMMANDS:\s*&\[&str\]\s*=\s*&\[([\s\S]*?)\];/);
  const handlers = shell.match(/generate_handler!\[([\s\S]*?)\]/);
  assert.ok(manifest); assert.ok(handlers);
  const declared = [...manifest[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  const registered = handlers[1].split(',').map((name) => name.trim()).filter(Boolean);
  assert.deepEqual(capability.windows, ['main']); assert.equal(capability.local, true);
  assert.equal(capability.remote, undefined); assert.equal(capability.webviews, undefined);
  for (const command of ['android_tool_sources_status', 'choose_android_tool_source', 'cancel_android_tool_source']) {
    assert.equal(declared.filter((name) => name === command).length, 1, command);
    assert.equal(registered.filter((name) => name === command).length, 1, command);
    assert.equal(capability.permissions.filter((name) => name === 'allow-' + command.replaceAll('_', '-')).length, 1, command);
    const start = shell.indexOf('async fn ' + command + '('), end = shell.indexOf('\n#[tauri::command]', start + 1);
    assert.ok(start >= 0);
    const body = shell.slice(start, end === -1 ? undefined : end);
    assert.match(body, /edit_window\(&webview\)/); assert.match(body, /android_sources_request_body\(request\.body\(\)\)/);
  }
  const body = shell.slice(shell.indexOf('fn android_sources_request_body('), shell.indexOf('fn android_catalog_request_body('));
  assert.match(body, /InvokeBody::Raw\(bytes\) if bytes\.len\(\) <= crate::android_tool_sources::REQUEST_LIMIT/);
});

test('source wire requires bounded DATA, original identities and truthful not-inspected status', () => {
  assert.ok(parseAndroidToolSourcesStatus(idle())); assert.ok(parseAndroidToolSourcesStatus(picked()));
  for (const mutate of [
    (v) => { v.path = '/not-renderer-authority'; },
    (v) => { v.inspection = 'passed'; },
    (v) => { v.protectedCopy = 'created'; },
    (v) => { v.operation.sourceGeneration = 2; },
    (v) => { v.selections.push(clone(v.selections[0])); },
    (v) => { v.selections[0].displayName = 'parent/private-folder'; },
    (v) => { v.phase = 'unknown'; v.reason = 'cleanup-unknown'; },
  ]) { const value = picked(); mutate(value); assert.equal(parseAndroidToolSourcesStatus(value), null); }
  let calls = 0;
  const value = picked(); Object.defineProperty(value, 'selections', { enumerable: true, get() { calls++; return []; } });
  assert.equal(parseAndroidToolSourcesStatus(value), null);
  const array = picked(); Object.defineProperty(array.selections, '0', { enumerable: true, get() { calls++; return { role: 'jdk', displayName: 'jdk' }; } });
  assert.equal(parseAndroidToolSourcesStatus(array), null); assert.equal(calls, 0);
});

test('source bridge carries only project/generation/closed role; invalid input never reaches invoke', async () => {
  const input = { schemaVersion: 1, sourceGeneration: 0, projectId: 'p1', role: 'jdk' };
  for (const field of ['path', 'destination', 'uid', 'command', 'qualified'])
    assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source', { ...input, [field]: true }), null);
  assert.equal(encodeAndroidToolSourcesRequest('choose_android_tool_source', { ...input, role: 'shell' }), null);
  const calls = [], events = [];
  const api = createNativeApi('native', async (command, body) => { calls.push({ command, body }); return picked(); },
    async (event, callback) => { events.push(event); callback(picked()); return () => {}; });
  await api.chooseAndroidToolSource(input);
  assert.equal(calls[0].command, 'choose_android_tool_source'); assert.ok(calls[0].body instanceof Uint8Array);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0].body)), input);
  await assert.rejects(api.chooseAndroidToolSource({ ...input, path: '/ignored' }));
  assert.equal(calls.length, 1);
  const unlisten = await api.subscribeAndroidToolSources((value) => assert.ok(parseAndroidToolSourcesStatus(value)));
  unlisten(); assert.deepEqual(events, [ANDROID_TOOL_SOURCES_EVENT]);
  const preview = createNativeApi('preview', async () => { throw new Error('must not invoke'); });
  await assert.rejects(preview.chooseAndroidToolSource(input));
});

async function harness(t) {
  let workspace = workspaceReducer(initialWorkspace, { type: 'select', project: { id: 'p1', name: 'Inert project', path: '/inert/never-forwarded' } });
  let source = idle();
  const calls = [], subscriptions = [];
  const listen = (kind, callback) => { const item = { kind, callback, closed: false }; subscriptions.push(item); return () => { item.closed = true; }; };
  const api = {
    mode: 'native',
    subscribeAndroidBuild: async (callback) => listen('build', callback),
    androidBuildStatus: async () => ({ schemaVersion: 1, statusRevision: 0, availability: 'available', operation: null }),
    subscribeAndroidToolchainCatalog: async (callback) => listen('catalog', callback),
    androidToolchainCatalogStatus: async () => ({ schemaVersion: 1, statusRevision: 0, catalogGeneration: 0, operationId: null,
      availability: 'unsupported-platform', phase: 'idle', reason: 'not-inspected', entries: [], selected: null }),
    subscribeAndroidToolSources: async (callback) => listen('sources', callback),
    androidToolSourcesStatus: async () => clone(source),
    chooseAndroidToolSource: (input) => { const call = { kind: 'choose', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    cancelAndroidToolSource: (input) => { const call = { kind: 'cancel', input: clone(input), ...deferred() }; calls.push(call); return call.promise; },
    refreshAndroidToolchainCatalog: async () => { throw new Error('conflicting catalog request'); },
    prepareAndroidBuild: async () => { throw new Error('conflicting build request'); },
  };
  const controller = new AndroidBuildController({ selectedProject: () => workspace.projects[workspace.selectedId],
    releaseVersion: () => null, otherOperationReason: () => null });
  controller.syncProject(); await controller.connect(api);
  t.after(() => controller.dispose());
  return { controller, calls, subscriptions, get state() { return controller.getSnapshot(); },
    source(value) { source = clone(value); },
    emit(value) { source = clone(value); subscriptions.find((s) => s.kind === 'sources' && !s.closed)?.callback(clone(value)); },
    switchProject() {
      controller.selectionIntent();
      workspace = workspaceReducer(workspace, { type: 'select', project: { id: 'p2', name: 'Other inert project', path: '/inert/other' } });
      controller.syncProject();
    },
  };
}

test('lost chooser reply never permits duplicate work; original Status restores only that identity and Cancel', async (t) => {
  const h = await harness(t);
  assert.equal(h.controller.sourceActionReason(), null);
  const choose = h.controller.chooseToolSource('jdk');
  assert.equal(h.calls.length, 1); assert.deepEqual(h.calls[0].input, { schemaVersion: 1, sourceGeneration: 0, projectId: 'p1', role: 'jdk' });
  h.calls[0].reject(new Error('/private/raw-error-must-not-be-shown')); await choose;
  assert.equal(h.state.sourcesUnconfirmed, true);
  await h.controller.chooseToolSource('sdk'); assert.equal(h.calls.length, 1);
  await h.controller.checkToolSources(); // Old idle is not an acknowledgement.
  assert.equal(h.state.sourcesUnconfirmed, true); assert.ok(androidBuildOwnerReason(h.state));
  h.emit(pending());
  assert.equal(h.state.sourcesUnconfirmed, false); assert.equal(h.controller.canCancelToolSources(), true);
  assert.ok(h.controller.catalogActionReason()); assert.ok(h.controller.prepareReason());
  assert.equal(h.controller.cancelToolSources(), true); assert.equal(h.controller.cancelToolSources(), false);
  assert.deepEqual(h.calls[1].input, { schemaVersion: 1, sourceGeneration: 1, operationId: 1 });
  const done = refused({ statusRevision: 3 }); h.source(done); h.calls[1].resolve(clone(done)); await flush();
  await h.controller.checkToolSources();
  assert.equal(h.state.toolSources.phase, 'refused'); assert.equal(h.controller.sourceActionReason(), null);
  assert.equal(h.state.sourcesError, null);
});

test('project change and disposal retain pending original identity and request its stop when acknowledgement arrives', async (t) => {
  const h = await harness(t), choose = h.controller.chooseToolSource('jdk');
  h.switchProject(); h.controller.dispose();
  assert.ok(h.subscriptions.every((s) => !s.closed));
  h.emit(pending()); await flush();
  assert.equal(h.calls.length, 2); assert.equal(h.calls[1].kind, 'cancel');
  h.calls[0].reject(new Error('reply lost')); await choose;
  h.calls[1].resolve(refused({ statusRevision: 3, projectId: null, reason: 'context-changed' })); await flush();
  assert.ok(h.subscriptions.every((s) => s.closed));
});

test('foreign source/project, post-failure success and cleanup-unknown recovery are rejected by original controller', async (t) => {
  for (const mutate of [
    (v) => { v.projectId = 'p2'; },
    (v) => { v.operation.operationId = 2; },
    (v) => { v.operation.role = 'sdk'; },
  ]) {
    const h = await harness(t), choose = h.controller.chooseToolSource('jdk');
    h.calls[0].resolve(pending()); await choose;
    const foreign = pending({ statusRevision: 3 }); mutate(foreign); h.emit(foreign);
    assert.equal(h.state.integrityFailed, true); assert.ok(h.controller.sourceActionReason());
  }
  {
    const h = await harness(t), choose = h.controller.chooseToolSource('jdk');
    h.calls[0].resolve(refused()); await choose; h.emit(picked({ statusRevision: 3 }));
    assert.equal(h.state.integrityFailed, true);
  }
  {
    const h = await harness(t), choose = h.controller.chooseToolSource('jdk');
    const unknown = pending({ phase: 'unknown', reason: 'cleanup-unknown', projectId: null, availability: 'cleanup-unknown' });
    h.calls[0].resolve(unknown); await choose;
    assert.ok(androidBuildOwnerReason(h.state)); h.emit(refused({ statusRevision: 3 }));
    assert.equal(h.state.integrityFailed, true); assert.equal(h.state.toolSources.phase, 'unknown');
  }
});

test('each source role has practical in-app help and UI never presents selection as protected registration', () => {
  for (const role of ['jdk', 'sdk', 'gradle']) {
    const help = androidToolSourceHelp[role];
    assert.equal(help.requiredness, 'required');
    for (const field of ['what', 'why', 'where', 'format', 'failure']) assert.ok(help[field].length > 20, role + '.' + field);
  }
  const ui = readFileSync(new URL('../src/components/AndroidBuild.tsx', import.meta.url), 'utf8');
  assert.match(ui, /controller\.chooseToolSource\(role\)/);
  assert.match(ui, /HelpButton content=\{help\}/);
  assert.match(ui, /Supplier inspection and protected-copy creation are not available/);
  assert.match(ui, /sameProject \? sources\?\.selections\.find/);
});
