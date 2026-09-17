// Core-owned JSON resources and pure presentation helpers only; no engine or IPC.
import assert from 'node:assert/strict';
import test from 'node:test';
import help from '../../src/mobile_release/api/data/field-help.json' with { type: 'json' };
import schema from '../../src/mobile_release/api/data/project.schema.json' with { type: 'json' };
import { emptyDraft, fieldsFor, getValue, localeRequirements, setValue } from '../src/catalog.ts';
import { apiError, bridgeMode, createNativeApi } from '../src/bridge.ts';
import { methodReason } from '../src/certainty.ts';

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
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return null; });
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

test('unknown errors do not expose raw bridge values; no capability means no operation', () => {
  assert.equal(apiError('PRIVATE REJECTION DATA').message.includes('PRIVATE'), false);
  const info = { runtime: { state: 'available', reason: null, mode: 'bundled' }, capabilities: { methods: [] } };
  assert.notEqual(methodReason(info, 'config.validate', 'native'), null);
  info.capabilities.methods.push({ method: 'config.validate', available: true, reason: 'Pure only' });
  assert.equal(methodReason(info, 'config.validate', 'native'), null);
  assert.notEqual(methodReason(info, 'config.validate', 'preview'), null);
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
