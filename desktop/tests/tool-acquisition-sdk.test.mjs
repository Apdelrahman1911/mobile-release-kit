// Closed assembled-source DATA. No native copy/registration/readiness receipt.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseStagedToolSources, stagedToolSourceGuidance } from '../src/toolAcquisitionGuidance.ts';
import { stagedMatchesComponents } from '../src/toolAcquisitionComponents.ts';

const report = (copied = 'sdk-platform') => ({ schemaVersion: 2, kind: 'staged-tool-sources', operationId: 'a'.repeat(32),
  contextSha256: 'b'.repeat(64), referenceSha256: 'c'.repeat(64), projectionSha256: 'd'.repeat(64),
  cacheJob: `tool-${'a'.repeat(32)}`, lookupScope: 'registered-selected-known', reusedArchives: [],
  downloadedArchives: [copied === 'sdk-platform' ? 'sdk-build-tools' : 'sdk-platform'], copiedSourceComponents: [copied],
  groups: [{ group: 'sdk', components: ['sdk-platform', 'sdk-build-tools'], allRequiredComponentsStaged: true, next: 'choose-native-source' }],
  assurance: { nativeFinality: false, registered: false, readyToBuild: false } });

test('each assembled SDK copies exactly the compatible half without changing the missing archive set', () => {
  for (const copied of ['sdk-platform', 'sdk-build-tools']) {
    const value = report(copied), parsed = parseStagedToolSources(value);
    assert.deepEqual(parsed, value);
    assert.equal(stagedMatchesComponents(parsed, { missing: value.downloadedArchives, compatible: ['jdk', copied, 'gradle'] }), true);
    assert.equal(stagedMatchesComponents(parsed, { missing: ['sdk-platform', 'sdk-build-tools'], compatible: ['jdk', 'gradle'] }), false);
    const current = stagedToolSourceGuidance(parsed, 'current-staged');
    assert.deepEqual(current.pickers, [{ role: 'sdk', label: 'Choose Android SDK' }]);
    assert.match(current.steps[0], /original SDK.*not changed/);
    assert.match(current.body, /not automatic installation or build readiness/);
    for (const state of ['settling', 'stale', 'recovery-required']) assert.deepEqual(stagedToolSourceGuidance(parsed, state).pickers, []);
  }
});

test('schema2 cannot copy JDK, both SDK halves, the missing half or carry a private source path', () => {
  for (const update of [{ copiedSourceComponents: [] }, { copiedSourceComponents: ['jdk'] },
    { copiedSourceComponents: ['sdk-platform', 'sdk-build-tools'] }, { copiedSourceComponents: ['sdk-build-tools'] },
    { downloadedArchives: ['sdk-platform', 'sdk-build-tools'] }, { downloadedArchives: [] },
    { root: '/private/never-accepted' }, { schemaVersion: 1 }]) assert.equal(parseStagedToolSources({ ...report(), ...update }), null);
  const getter = report(); let reads = 0;
  Object.defineProperty(getter, 'copiedSourceComponents', { enumerable: true, get() { reads++; return ['sdk-platform']; } });
  assert.equal(parseStagedToolSources(getter), null); assert.equal(reads, 0);
});

test('old one-piece reports remain incomplete and never gain a copied component by reinterpretation', () => {
  const old = report(); old.schemaVersion = 1; delete old.copiedSourceComponents;
  old.groups = [{ group: 'sdk', components: ['sdk-build-tools'], allRequiredComponentsStaged: false, next: 'complete-sdk-manually' }];
  assert.deepEqual(parseStagedToolSources(old), old);
  const guidance = stagedToolSourceGuidance(old, 'current-staged'); assert.match(guidance.steps[0], /staged SDK is incomplete/);
  assert.equal(stagedMatchesComponents(parseStagedToolSources(old), { missing: ['sdk-build-tools'], compatible: ['jdk', 'sdk-platform', 'gradle'] }), true);
  old.groups[0].allRequiredComponentsStaged = true; old.groups[0].next = 'choose-native-source';
  assert.equal(parseStagedToolSources(old), null);
});
