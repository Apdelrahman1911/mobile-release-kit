// Inert protocol/bridge DATA only; never native filesystem/tool qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { ANDROID_CATALOG_EVENT, encodeAndroidCatalogRequest, parseAndroidToolchainCatalogStatus } from '../src/androidToolchainCatalogProtocol.ts';
const clone = (value) => structuredClone(value);
const selected = { instance: 'a'.repeat(32), ownerUid: 501, catalogGeneration: 1, recordSha256: 'b'.repeat(64),
  inventorySha256: 'c'.repeat(64), osProviderSha256: 'd'.repeat(64) };
const ready = { schemaVersion: 1, statusRevision: 2, catalogGeneration: 1, operationId: 'e'.repeat(32),
  availability: 'available', phase: 'ready', reason: 'none', entries: [{ instance: selected.instance,
    occupants: 1, status: 'verified-this-session', recovery: null, selection: selected,
    versions: { jdkVendor: 'Example', jdkVersion: '17.0.12', gradleVersion: '8.10', agpVersion: '8.7',
      sdkPlatform: 'android-35', sdkBuildToolsVersion: '35.0.0' } }], selected: { ...selected } };
test('closed catalog parser requires a bounded current-generation member and does not invoke accessors', () => {
  assert.ok(parseAndroidToolchainCatalogStatus(ready));
  for (const mutate of [
    (v) => { v.selected.recordSha256 = '0'.repeat(64); },
    (v) => { v.entries[0].selection.catalogGeneration = 2; },
    (v) => { v.entries.push(clone(v.entries[0])); },
    (v) => { v.entries[0].instance = '0'.repeat(32); },
    (v) => { v.entries[0].occupants = 0; },
    (v) => { v.entries[0].status = 'interrupted'; },
    (v) => { v.root = '/not-a-capability'; },
    (v) => { v.phase = 'unknown'; v.reason = 'cleanup-unknown'; },
  ]) { const v = clone(ready); mutate(v); assert.equal(parseAndroidToolchainCatalogStatus(v), null); }
  const bounded = clone(ready);
  const interrupted = (i) => ({ instance: i.toString(16).padStart(32, '0'), occupants: 1,
    status: 'interrupted', versions: null, recovery: null, selection: null });
  bounded.entries.push(...Array.from({ length: 31 }, (_, i) => interrupted(i)));
  assert.ok(parseAndroidToolchainCatalogStatus(bounded));
  bounded.entries.push(interrupted(31));
  assert.equal(parseAndroidToolchainCatalogStatus(bounded), null);
  let calls = 0; const v = clone(ready); Object.defineProperty(v, 'entries', { enumerable: true, get() { calls++; return []; } });
  assert.equal(parseAndroidToolchainCatalogStatus(v), null); assert.equal(calls, 0);
});
test('select IPC carries only generation and record comparisons; preview cannot issue it', async () => {
  const request = { schemaVersion: 1, catalogGeneration: 1, instance: selected.instance,
    recordSha256: selected.recordSha256, inventorySha256: selected.inventorySha256, osProviderSha256: selected.osProviderSha256 };
  for (const field of ['root', 'ownerUid', 'qualified']) {
    assert.equal(encodeAndroidCatalogRequest('select_android_toolchain', { ...request, [field]: selected[field] ?? true }), null);
  }
  for (const field of ['recordSha256', 'inventorySha256', 'osProviderSha256']) {
    const missing = { ...request }; delete missing[field];
    assert.equal(encodeAndroidCatalogRequest('select_android_toolchain', missing), null);
    assert.equal(encodeAndroidCatalogRequest('select_android_toolchain', { ...request, [field]: 'not-a-digest' }), null);
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
