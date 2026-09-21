// Core-owned JSON resources and pure presentation helpers only; no engine or IPC.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import help from '../../src/mobile_release/api/data/field-help.json' with { type: 'json' };
import schema from '../../src/mobile_release/api/data/project.schema.json' with { type: 'json' };
import githubSetupResource from '../../src/mobile_release/api/data/github-setup-v1.json' with { type: 'json' };
import githubConnectionResource from '../../src/mobile_release/api/data/github-connection-v1.json' with { type: 'json' };
import credentialGuideResource from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };
import { emptyDraft, fieldsFor, getValue, localeRequirements, setValue } from '../src/catalog.ts';
import { apiError, bridgeMode, createNativeApi } from '../src/bridge.ts';
import { methodReason, projectSelectionReason } from '../src/certainty.ts';
import { PROJECT_PATH_FIELDS, isProjectPathField, parseProjectPathRequest, parseProjectPathSelection, projectPathAvailabilityReason, projectPathError, projectPathHelp } from '../src/projectPaths.ts';
import { previewApi } from '../src/preview.ts';
import { parseAssetStatus } from '../src/assetSessionProtocol.ts';
import { AssetSessionController, assetCancellationReason } from '../src/assetSessionController.ts';

test('browser preview requires the exact explicit flag; native errors cannot select it', async () => {
  for (const flag of [undefined, '', '0', 'true', true, 1]) assert.equal(bridgeMode(flag, false), 'unavailable');
  assert.equal(bridgeMode('1', false), 'preview');
  assert.equal(bridgeMode(undefined, true), 'native');
  let calls = 0;
  const native = createNativeApi('native', async () => { calls += 1; throw { code: 'RuntimeUnavailable', message: 'Trusted runtime missing.', retryable: false }; });
  await assert.rejects(native.appInfo(), (error) => error.code === 'RuntimeUnavailable');
  assert.equal(native.mode, 'native');
  assert.equal(calls, 1);
  const unavailable = createNativeApi('unavailable', async () => { throw new Error('MUST NOT INVOKE'); });
  await assert.rejects(unavailable.appInfo(), (error) => error.code === 'NativeBridgeRequired');
});

test('native bridge uses only closed command names and Rust-owned project identifiers', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, args) => {
    calls.push({ command, args });
    return command === 'catalog' ? { schemaVersion: 1, schema: {}, fields: [], credentials: [], metadata: null, githubSetup: githubSetupResource.help, assurance: {} } : null;
  });
  await api.appInfo();
  await api.chooseProject();
  await api.snapshot('bound-project-id');
  await api.catalog();
  const draft = { schemaVersion: 1 };
  await api.validate(draft);
  const hints = { platforms: ['ios'], iosBundleId: 'com.example.inert' };
  await api.suggestConfig(hints);
  await api.configPreview(null, draft);
  await api.configPreview(draft, draft);
  assert.deepEqual(calls, [
    { command: 'app_info', args: undefined }, { command: 'choose_project', args: undefined },
    { command: 'project_snapshot', args: { projectId: 'bound-project-id' } },
    { command: 'catalog', args: undefined }, { command: 'validate_config', args: { draft } },
    { command: 'suggest_config', args: { hints } },
    { command: 'preview_config', args: { base: null, draft } },
    { command: 'preview_config', args: { base: draft, draft } },
  ]);
  assert.equal('save' in api, false);
  assert.equal('apply' in api, false);
  assert.equal('initialize' in api, false);
  assert.equal('import' in api, false);
  assert.equal('shell' in api, false);
});

test('connection help is nullable additive catalogue data, never connection admission', async () => {
  const original = { schemaVersion: 1, schema: {}, fields: [], credentials: [], metadata: null,
    githubSetup: githubSetupResource.help, assurance: {} };
  const malformed = structuredClone(githubConnectionResource);
  malformed.inputs[1].requiredness = 'optional';
  const unknownField = { ...githubConnectionResource, connection: 'not observed' };
  for (const credentialGuide of [undefined, null, credentialGuideResource]) {
    for (const help of [undefined, null, {}, malformed, unknownField, githubConnectionResource]) {
      const reply = { ...original, ...(credentialGuide === undefined ? {} : { credentialGuide }),
        ...(help === undefined ? {} : { githubConnection: help }) };
      const calls = [];
      const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return reply; });
      const result = await api.catalog();
      assert.deepEqual(result.githubSetup, original.githubSetup);
      assert.deepEqual(result.schema, original.schema);
      assert.deepEqual(result.credentialGuide, credentialGuide ?? null);
      assert.deepEqual(calls, [{ command: 'catalog', args: undefined }]);
      assert.equal(typeof api.githubConnectionStatus, 'function');
      await assert.rejects(api.connectGitHubToken({ projectId: 'project-a', repository: 'Owner/App', token: 'INERT_TOKEN' }),
        (error) => error.code === 'github_connection_refused_unqualified');
      assert.deepEqual(calls, [{ command: 'catalog', args: undefined }], 'help never opens the compiled-disabled token route');
      assert.equal('connectGitHub' in api, false);
      if (help === githubConnectionResource) {
        assert.deepEqual(result.githubConnection, help);
        result.githubConnection.inputs[0].label = 'Changed local copy';
        assert.notEqual(help.inputs[0].label, 'Changed local copy');
      } else assert.equal(result.githubConnection, null);
    }
  }
  for (const guides of [{}, { credentialGuide: null }, { githubConnection: null },
    { credentialGuide: credentialGuideResource, githubConnection: githubConnectionResource }]) {
    for (const invalid of [{ unrecognized: true }, { schemaVersion: 2 }, { githubSetup: null }]) {
      const api = createNativeApi('native', async () => ({ ...original, ...guides, ...invalid }));
      await assert.rejects(api.catalog(), (error) => error.code === 'GitHubSetupHelpUnavailable');
    }
  }
});

test('unknown errors do not expose raw bridge values; no capability means no operation', () => {
  assert.equal(apiError('PRIVATE REJECTION DATA').message.includes('PRIVATE'), false);
  const info = { runtime: { state: 'available', reason: null, mode: 'bundled' }, capabilities: { methods: [] } };
  assert.notEqual(methodReason(info, 'config.validate', 'native'), null);
  info.capabilities.methods.push({ method: 'config.validate', available: true, reason: 'Pure only' });
  assert.equal(methodReason(info, 'config.validate', 'native'), null);
  assert.notEqual(methodReason(info, 'config.validate', 'preview'), null);
});

test('project selection is additive profile data, separate from core and browser preview availability', async () => {
  const original = { runtime: { state: 'available', reason: null, mode: 'bundled' },
    capabilities: { methods: [{ method: 'project.snapshot', available: false, reason: 'Core refusal' }] } };
  assert.notEqual(projectSelectionReason(null, 'native'), null);
  const admitted = { available: true, reason: null };
  const refused = { available: false, reason: 'Project picker profile unavailable.' };
  for (const selection of [undefined, null, false, true, 1, 'available', [], {}, { available: true },
    { reason: null }, { available: 'true', reason: null }, { available: 1, reason: null },
    { available: true, reason: '' }, { available: true, reason: 'Contradictory reason' },
    { available: true, reason: null, extra: true }, { available: false, reason: null },
    { available: false, reason: '' }, { available: false, reason: 'x'.repeat(513) }, refused, admitted]) {
    const reply = { ...original, ...(selection === undefined ? {} : { projectSelection: selection }) };
    const calls = [];
    const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return reply; });
    const info = await api.appInfo();
    assert.deepEqual(calls, [{ command: 'app_info', args: undefined }], 'availability does not invoke a picker');
    assert.equal(projectSelectionReason(info, 'native') === null, selection === admitted);
    if (selection === refused) assert.equal(projectSelectionReason(info, 'native'), refused.reason);
    assert.equal(methodReason(info, 'project.snapshot', 'native'), 'Core refusal', 'selection never enables a core-refused method');
    assert.notEqual(projectSelectionReason(info, 'preview'), null);
    assert.notEqual(projectSelectionReason(info, 'unavailable'), null);
  }
  const noEngine = { ...original, projectSelection: admitted,
    runtime: { state: 'unavailable', reason: 'Engine unavailable.', mode: 'bundled' }, capabilities: null };
  assert.equal(projectSelectionReason(noEngine, 'native'), null, 'profile DATA does not claim a successful core inspection');
  assert.equal(methodReason(noEngine, 'project.snapshot', 'native'), 'Engine unavailable.');
});

test('core fields have reachable help and metadata preserves its per-platform mapping', () => {
  const prefixes = ['version', 'source', 'android', 'ios', 'services', 'projectChecks', '$schema', 'schemaVersion', 'metadata'];
  const fields = fieldsFor({ fields: help }, prefixes);
  assert.equal(fields.length, help.length);
  assert.equal(new Set(fields.map((field) => field.path)).size, fields.length);
  for (const field of fields) {
    for (const key of ['label', 'what', 'why', 'where', 'format', 'requiredWhen', 'failure']) assert.ok(field[key]?.length > 0, `${field.path}: ${key}`);
    assert.ok(['text', 'boolean', 'number', 'enum', 'string-list', 'argv', 'commands'].includes(field.input));
  }
  assert.equal(fieldsFor({ fields: help }, ['version'], 'no-such-field').length, 0);
  assert.ok(fieldsFor({ fields: help }, ['android'], 'application').some((field) => field.path === 'android.applicationId'));
  assert.deepEqual(localeRequirements({ requiredLocaleText: { android: ['android-example.txt'], ios: ['ios-example.txt'] } }), [
    { platform: 'android', files: ['android-example.txt'] }, { platform: 'ios', files: ['ios-example.txt'] },
  ]);
  assert.deepEqual(localeRequirements(null), []);
});

test('an explicitly started empty draft never guesses identity, branches, or credentials', () => {
  const draft = emptyDraft(schema);
  assert.equal(draft.schemaVersion, 1);
  assert.equal(draft.android.enabled, false);
  assert.equal(draft.ios.enabled, false);
  assert.equal(draft.source.candidateBranch, '');
  assert.equal(draft.version.source, '');
  assert.equal(draft.android.applicationId, undefined);
  assert.deepEqual(draft.projectChecks.preflight, []);
  assert.equal(draft.$schema, undefined);
  assert.deepEqual(emptyDraft({ type: 'object', required: ['foreign'], properties: { foreign: { $ref: 'https://example.invalid/schema' } } }), {});
});

test('draft updates are immutable, preserve unrelated data, and reject prototype paths', () => {
  const original = { ios: { symbols: { policy: 'required', uploadCommand: ['example', 'argument with spaces'] }, enabled: true } };
  const updated = setValue(original, 'ios.symbols.uploadCommand', ['new']);
  assert.deepEqual(original.ios.symbols.uploadCommand, ['example', 'argument with spaces']);
  assert.deepEqual(getValue(updated, 'ios.symbols.uploadCommand'), ['new']);
  const unset = setValue(updated, 'ios.symbols.uploadCommand', undefined);
  assert.equal(getValue(unset, 'ios.symbols.policy'), 'required');
  assert.equal(getValue(unset, 'ios.enabled'), true);
  for (const path of ['__proto__.polluted', 'a.constructor.b', 'a.prototype.b', 'a..b']) assert.throws(() => setValue({}, path, true));
  assert.equal({}.polluted, undefined);
});

test('four desktop Browse controls append help without replacing bundled policy or requiredness', () => {
  const paths = ['version.source', 'ios.project', 'ios.workspace', 'metadata.root'];
  assert.deepEqual(PROJECT_PATH_FIELDS, paths);
  const original = structuredClone(help);
  assert.deepEqual(help.filter((field) => isProjectPathField(field.path)).map((field) => field.path), paths);
  for (const field of help) {
    const guided = projectPathHelp(field);
    if (!paths.includes(field.path)) { assert.equal(guided, field); continue; }
    assert.equal(field.input, 'text');
    for (const key of ['label', 'requiredness', 'requiredWhen', 'what', 'why']) assert.equal(guided[key], field[key]);
    for (const key of ['where', 'format', 'failure']) assert.ok(guided[key].startsWith(`${field[key]} `));
    assert.match(guided.where, /Browse existing….*inside the current project boundary.*Browsing is optional/);
    assert.match(guided.format, /project-relative slash-separated.*512 UTF-8 bytes and 12 components.*never clears another field/);
    assert.match(guided.failure, /Cancel.*outside-project.*unchanged.*does not read file contents, save the draft, or validate the resource/);
    if (field.path.startsWith('ios.')) {
      assert.match(guided.requiredWhen, /mutually exclusive/);
      assert.match(guided.failure, /Selecting both project and workspace is invalid/);
      assert.match(guided.where, /does not validate Xcode/);
    }
  }
  assert.deepEqual(help, original, 'desktop guidance never mutates the core catalogue');
  for (const field of [null, '', 'ios.scheme', 'android.gradleCommand', 'credential.file', '__proto__.path']) assert.equal(isProjectPathField(field), false);
  // SOURCE guards only; this does not execute React, a WebView or a native picker.
  const fieldSource = readFileSync(new URL('../src/components/Fields.tsx', import.meta.url), 'utf8');
  const editor = readFileSync(new URL('../src/components/DraftEditor.tsx', import.meta.url), 'utf8');
  assert.match(fieldSource, /const pathField = isProjectPathField\(field.path\)/);
  assert.match(fieldSource, /HelpButton content=\{projectPathHelp\(field\)\}/);
  assert.match(fieldSource, /projectPathDraftReason\(draft, pathField\) \?\? pathPicker.reason/);
  assert.match(fieldSource, /disabled=\{browseReason !== null\}/);
  assert.match(fieldSource, /pathPicker.onBrowse\(pathField\)/);
  assert.match(editor, /Current project boundary:.*session.project.path/);
  assert.match(editor, /pathPicker=\{pathPicker\} onChange=\{onEdit\}/);
});

test('project-path availability is fail-closed and independent of compatibility selection and preview', async () => {
  const admitted = { available: true, reason: null };
  const original = { runtime: { state: 'available', mode: 'bundled', reason: null }, capabilities: { methods: [] },
    projectSelection: { available: true, reason: null } };
  let getters = 0;
  const accessor = { get available() { getters += 1; return true; }, reason: null };
  for (const selection of [undefined, null, false, [], {}, { available: true }, { available: 'true', reason: null },
    { available: true, reason: '' }, { available: true, reason: null, extra: true }, { available: false, reason: '/INERT_PRIVATE/refusal' },
    Object.create(admitted), accessor, admitted]) {
    const reply = { ...original, ...(selection === undefined ? {} : { projectPathSelection: selection }) };
    const calls = [];
    const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return reply; });
    const info = await api.appInfo();
    assert.equal(projectSelectionReason(info, 'native'), null);
    const reason = projectPathAvailabilityReason(info, 'native');
    assert.equal(reason === null, selection === admitted);
    assert.ok(!reason?.includes('INERT_PRIVATE'));
    assert.notEqual(projectPathAvailabilityReason(info, 'preview'), null);
    assert.notEqual(projectPathAvailabilityReason(info, 'unavailable'), null);
    assert.deepEqual(calls, [{ command: 'app_info', args: undefined }]);
    assert.deepEqual(info.capabilities.methods, [], 'the additive gate does not add a passive method');
  }
  assert.equal(getters, 0);
  assert.notEqual(projectPathAvailabilityReason(null, 'native'), null);
  assert.notEqual(projectPathAvailabilityReason({ ...original, get projectPathSelection() { getters += 1; return admitted; } }, 'native'), null);
  assert.notEqual(projectPathAvailabilityReason(Object.defineProperty({ ...original }, 'projectPathSelection', { value: admitted }), 'native'), null);
  assert.equal(getters, 0);
  const unavailable = createNativeApi('unavailable', async () => { assert.fail('unavailable mode must not invoke'); });
  for (const api of [unavailable, previewApi]) {
    await assert.rejects(api.chooseProjectPath({ projectId: 'project-a', field: 'version.source' }), (error) => error.code === 'project_path_unavailable');
  }
  assert.notEqual(projectPathAvailabilityReason(await previewApi.appInfo(), 'preview'), null);
});

test('project-path IPC keeps exact bounded bindings and rejects malformed or private reply data whole', async () => {
  const examples = { 'version.source': 'release/VERSION', 'ios.project': 'ios/Reader.xcodeproj',
    'ios.workspace': 'ios/Reader.xcworkspace', 'metadata.root': 'release/store' };
  const calls = [];
  let reply = null;
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return reply; });
  for (const [field, relativePath] of Object.entries(examples)) {
    const request = { projectId: 'project-a', field };
    reply = { ...request, relativePath };
    const work = api.chooseProjectPath(request);
    request.projectId = 'changed-after-handoff';
    const result = await work;
    assert.deepEqual(result, { projectId: 'project-a', field, relativePath });
    assert.deepEqual(calls.at(-1), { command: 'choose_project_path', args: { projectId: 'project-a', field } });
    assert.ok(new TextEncoder().encode(JSON.stringify(result)).byteLength <= 1024);
    reply.relativePath = 'provider-mutated';
    assert.equal(result.relativePath, relativePath, 'the provider result is detached');
  }
  const request = { projectId: 'project-a', field: 'version.source' };
  const count = calls.length;
  let getters = 0;
  const invalidRequests = [null, [], {}, { projectId: 'project-a' }, { ...request, field: 'ios.scheme' }, { ...request, field: '__proto__.path' },
    ...['', 'a'.repeat(65), '../project', '/INERT_PRIVATE/project', 'é'].map((projectId) => ({ ...request, projectId })),
    ...['path', 'initialFolder', 'title', 'filters', 'draft'].map((key) => ({ ...request, [key]: 'MUST_NOT_FORWARD' })),
    { get projectId() { getters += 1; return 'project-a'; }, field: 'version.source' }, Object.create(request),
    { ...request, [Symbol('unknown')]: true }, { ...request, toJSON() { getters += 1; return request; } }];
  for (const input of invalidRequests) {
    assert.equal(parseProjectPathRequest(input), null);
    await assert.rejects(api.chooseProjectPath(input), (error) => error.code === 'project_path_invalid');
  }
  assert.equal(calls.length, count);
  assert.equal(getters, 0);
  const valid = { ...request, relativePath: 'release/VERSION' };
  const malformed = [undefined, false, [], {}, { ...valid, field: 'metadata.root' }, { ...valid, projectId: 'other-project' },
    { ...valid, absolutePath: '/INERT_PRIVATE/outside' }, { ...valid, selectionToken: 'a'.repeat(32) },
    { ...valid, get relativePath() { getters += 1; return 'release/VERSION'; } }, Object.create(valid),
    ...['', '/INERT_PRIVATE/outside', '../outside', './VERSION', 'a/../b', 'a//b', 'C:/VERSION', 'a\\b', 'a\u0000b', 'a\nb',
      'a\u007fb', '.hidden/file', 'private/file', 'node_modules/file', 'CON.txt', 'lpt9/file', 'last.', 'last ', '\ud800',
      'a'.repeat(256), 'é'.repeat(128), Array(13).fill('a').join('/'), `${'a'.repeat(255)}/${'b'.repeat(255)}/c`]
      .map((relativePath) => ({ ...valid, relativePath }))];
  for (const value of malformed) {
    assert.equal(parseProjectPathSelection(value, request), undefined);
    reply = value;
    await assert.rejects(api.chooseProjectPath(request), (error) => error.code === 'project_path_unknown' && !error.message.includes('INERT_PRIVATE'));
  }
  assert.equal(getters, 0);
  for (const relativePath of ['VERSION', 'release/any.extension', 'cafe\u0301/VERSION', Array(12).fill('a').join('/'),
    `${'a'.repeat(255)}/${'b'.repeat(254)}/c`, Array(3).fill('é'.repeat(85)).join('/')]) {
    assert.equal(parseProjectPathSelection({ ...valid, relativePath }, request)?.relativePath, relativePath, 'no normalization or invented extension policy');
  }
  for (const field of ['ios.project', 'ios.workspace']) {
    for (const relativePath of ['ios/Reader', 'ios/Reader.XCODEPROJ', 'ios/Reader.xcworkspace/child'])
      assert.equal(parseProjectPathSelection({ projectId: 'project-a', field, relativePath }, { projectId: 'project-a', field }), undefined);
  }
  reply = null;
  assert.equal(await api.chooseProjectPath(request), null, 'only native null is settled Cancel');
  const malicious = createNativeApi('native', async (_command, args) => {
    args.projectId = 'rebound-provider'; return { ...args, relativePath: 'release/VERSION' };
  });
  await assert.rejects(malicious.chooseProjectPath(request), (error) => error.code === 'project_path_unknown');
  for (const code of ['project_path_invalid', 'project_path_unavailable', 'project_path_busy', 'project_path_stale', 'project_path_unsafe',
    'project_path_changed', 'project_path_limit', 'project_path_deadline', 'project_path_cleanup_unknown', 'unknown-native-code']) {
    const error = { code, message: '/INERT_PRIVATE/native-error', retryable: true };
    const rejected = createNativeApi('native', async () => { throw error; });
    await assert.rejects(rejected.chooseProjectPath(request), (safe) => {
      assert.deepEqual(safe, projectPathError(error));
      assert.equal(safe.retryable, false); assert.equal(safe.message.includes('INERT_PRIVATE'), false); return true;
    });
  }
});

test('shared-slot project-path status cannot supply credential authority or use credential cancellation', async () => {
  const operation = { operationId: 3, operation: 'choose-project-path', phase: 'picking', reason: 'none', source: 'not-run', settlement: 'pending',
    selectionToken: null, assessment: null, preview: null };
  const status = { schemaVersion: 1, statusRevision: 1, mode: 'session', capability: { available: true, reason: 'none' }, context: null,
    operation, records: [], assignments: [] };
  assert.deepEqual(parseAssetStatus(status), status);
  const token = 'a'.repeat(32);
  const selected = { ...status, operation: { ...operation, phase: 'selected', source: 'captured', settlement: 'known', selectionToken: token } };
  assert.ok(parseAssetStatus({ ...selected, operation: { ...selected.operation, operation: 'choose-file' } }));
  assert.equal(parseAssetStatus(selected), null, 'a path cannot become an asset selection');
  const deletion = { ...status, records: [{ recordId: token, revision: 1, kind: 'google-wif', availability: 'unassigned' }],
    operation: { ...operation, phase: 'preview', settlement: 'known', preview: { token, action: 'delete', expiresInMs: 1000,
      subject: { kind: 'google-wif', change: 'delete', recordId: token, recordRevision: 1 } } } };
  assert.ok(parseAssetStatus({ ...deletion, operation: { ...deletion.operation, operation: 'prepare-delete' } }));
  assert.equal(parseAssetStatus(deletion), null, 'a path cannot acquire a credential preview');
  const scope = { platform: 'project', stage: 'candidate', purpose: 'full' };
  const assessed = { ...status, context: { revision: 1, projectId: 'project-a', ...scope }, operation: { ...operation, assessment: {
    schemaVersion: 1, policyVersion: 'credential-policy-v1', kind: 'project-read-token', context: scope,
    applicability: { state: 'required', reason: 'selected' }, state: 'missing', identity: 'not-assessed',
    fields: [{ id: 'token', requirement: 'MOBILE_RELEASE_PROJECT_READ_TOKEN', presence: 'missing', state: 'missing', issues: ['not-run'], checks: [] }],
    assurance: { basis: 'supplied-input-only', scalarValuesProcessed: false, fileObservationsProcessed: false, selectedFilesRead: false,
      keyringAccessed: false, storageWritesPerformed: false, projectCodeExecuted: false, sourceCustody: 'not-established',
      nativeValidation: 'not-run', serviceValidation: 'not-run', releaseReadiness: 'unknown' },
  } } };
  assert.ok(parseAssetStatus({ ...assessed, operation: { ...assessed.operation, operation: 'prepare' } }));
  assert.equal(parseAssetStatus(assessed), null, 'a path cannot acquire even a valid credential assessment');
  for (const change of [{ operation: 'choose-arbitrary-path' }, { relativePath: 'release/VERSION' }])
    assert.equal(parseAssetStatus({ ...status, operation: { ...operation, ...change } }), null);
  for (const [phase, settlement] of [['picking', 'pending'], ['unknown', 'unknown'], ['idle', 'late-known']]) {
    const current = { ...status, operation: { ...operation, phase, settlement } };
    let calls = 0;
    const controller = new AssetSessionController(() => null);
    await controller.connect({ mode: 'native', subscribeAssets: async () => () => {}, assetStatus: async () => current,
      discardAsset: async () => { calls += 1; return current; }, lockAssetSession: async () => { calls += 1; return current; } });
    assert.match(assetCancellationReason(controller.getSnapshot()), /original native picker/);
    assert.equal(controller.discard(), false); assert.equal(controller.lock(), false); assert.equal(calls, 0);
    controller.dispose();
  }
  assert.equal(assetCancellationReason({ status: { ...status, operation: { ...operation, phase: 'idle', settlement: 'known' } } }), null);
  const settled = { ...status, operation: { ...operation, phase: 'idle', settlement: 'known' } };
  let locks = 0;
  const controller = new AssetSessionController(() => null);
  await controller.connect({ mode: 'native', subscribeAssets: async () => () => {}, assetStatus: async () => settled,
    lockAssetSession: async () => { locks += 1; return { ...settled, statusRevision: 2, operation: { ...settled.operation, operation: 'lock' } }; } });
  assert.equal(controller.lock(), true, 'a known-idle path operation does not prohibit a later explicit session lock');
  assert.equal(locks, 1);
  await Promise.resolve(); controller.dispose();
  const pane = readFileSync(new URL('../src/components/CredentialSession.tsx', import.meta.url), 'utf8');
  assert.match(pane, /Original project-path picker status/);
  assert.match(pane, /guide && !projectPathActive/);
});
