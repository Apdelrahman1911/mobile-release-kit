// Inert protocol/bridge DATA only; never native filesystem/tool qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { ANDROID_CATALOG_EVENT, encodeAndroidCatalogRequest, parseAndroidToolchainCatalogStatus } from '../src/androidToolchainCatalogProtocol.ts';
const clone = (value) => structuredClone(value);
const selected = { instance: 'a'.repeat(32), ownerUid: 501, catalogGeneration: 1, recordSha256: 'b'.repeat(64),
  inventorySha256: 'c'.repeat(64), osProviderSha256: 'd'.repeat(64) };
const ready = { schemaVersion: 1, statusRevision: 2, catalogGeneration: 1, operationId: 'e'.repeat(32),
  availability: 'available', phase: 'ready', reason: 'none', entries: [{ selection: selected,
    versions: { jdkVendor: 'Example', jdkVersion: '17.0.12', gradleVersion: '8.10', agpVersion: '8.7',
      sdkPlatform: 'android-35', sdkBuildToolsVersion: '35.0.0' } }], selected: { ...selected } };
test('ordinary catalog commands have generated permissions limited to the local main window', () => {
  const build = readFileSync(new URL('../src-tauri/build.rs', import.meta.url), 'utf8');
  const shell = readFileSync(new URL('../src-tauri/src/shell.rs', import.meta.url), 'utf8');
  const capability = JSON.parse(readFileSync(new URL('../src-tauri/capabilities/main.json', import.meta.url), 'utf8'));
  const manifest = build.match(/const COMMANDS:\s*&\[&str\]\s*=\s*&\[([\s\S]*?)\];/);
  const handlers = shell.match(/generate_handler!\[([\s\S]*?)\]/);
  assert.ok(manifest); assert.ok(handlers);
  const declared = [...manifest[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]);
  const registered = handlers[1].split(',').map((name) => name.trim()).filter(Boolean);
  assert.deepEqual(capability.windows, ['main']); assert.equal(capability.local, true);
  assert.equal(capability.remote, undefined); assert.equal(capability.webviews, undefined);
  for (const command of ['android_toolchain_catalog_status', 'refresh_android_toolchain_catalog',
    'select_android_toolchain', 'cancel_android_toolchain_catalog']) {
    assert.equal(declared.filter((name) => name === command).length, 1, command);
    assert.equal(registered.filter((name) => name === command).length, 1, command);
    assert.equal(capability.permissions.filter((name) => name === `allow-${command.replaceAll('_', '-')}`).length, 1, command);
  }
});
test('closed catalog parser requires a bounded current-generation member and does not invoke accessors', () => {
  assert.ok(parseAndroidToolchainCatalogStatus(ready));
  for (const mutate of [
    (v) => { v.selected.recordSha256 = '0'.repeat(64); },
    (v) => { v.entries[0].selection.catalogGeneration = 2; },
    (v) => { v.entries.push(clone(v.entries[0])); },
    (v) => { v.entries = Array.from({ length: 17 }, (_, i) => ({ ...clone(v.entries[0]), selection: { ...selected, instance: i.toString(16).padStart(32, '0') } })); },
    (v) => { v.root = '/not-a-capability'; },
    (v) => { v.phase = 'unknown'; v.reason = 'cleanup-unknown'; },
  ]) { const v = clone(ready); mutate(v); assert.equal(parseAndroidToolchainCatalogStatus(v), null); }
  let calls = 0; const v = clone(ready); Object.defineProperty(v, 'entries', { enumerable: true, get() { calls++; return []; } });
  assert.equal(parseAndroidToolchainCatalogStatus(v), null); assert.equal(calls, 0);
});
test('select IPC carries only generation and record comparisons; preview cannot issue it', async () => {
  const request = { schemaVersion: 1, catalogGeneration: 1, instance: selected.instance, recordSha256: selected.recordSha256 };
  for (const field of ['root', 'ownerUid', 'qualified', 'inventorySha256']) {
    assert.equal(encodeAndroidCatalogRequest('select_android_toolchain', { ...request, [field]: selected[field] ?? true }), null);
  }
  const calls = [], events = [];
  const api = createNativeApi('native', async (command, body) => { calls.push({ command, body }); return clone(ready); },
    async (event, callback) => { events.push(event); callback(clone(ready)); return () => {}; });
  await api.selectAndroidToolchain(request);
  assert.equal(calls[0].command, 'select_android_toolchain'); assert.ok(calls[0].body instanceof Uint8Array);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0].body)), request);
  const unlisten = await api.subscribeAndroidToolchainCatalog((v) => assert.ok(parseAndroidToolchainCatalogStatus(v)));
  unlisten(); assert.deepEqual(events, [ANDROID_CATALOG_EVENT]);
  await assert.rejects(previewApi.selectAndroidToolchain(request), (e) => e.code === 'android_catalog_unavailable');
});
