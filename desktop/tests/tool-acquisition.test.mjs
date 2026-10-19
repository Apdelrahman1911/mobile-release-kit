// Synthetic presentation only. Never native finality, download or installation.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseStagedToolSources, stagedToolSourceGuidance, toolAcquisitionFailureGuidance } from '../src/toolAcquisitionGuidance.ts';

const report = () => ({ schemaVersion: 1, kind: 'staged-tool-sources', operationId: 'synthetic-operation',
  contextSha256: 'a'.repeat(64), referenceSha256: 'b'.repeat(64), projectionSha256: 'c'.repeat(64),
  cacheJob: 'tool-synthetic-operation', lookupScope: 'registered-selected-known',
  reusedArchives: ['jdk'], downloadedArchives: ['sdk-platform', 'sdk-build-tools', 'gradle'],
  groups: [
    { group: 'jdk', components: ['jdk'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'sdk', components: ['sdk-platform', 'sdk-build-tools'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'gradle', components: ['gradle'], allRequiredComponentsStaged: true, next: 'choose-native-source' }],
  assurance: { nativeFinality: false, registered: false, readyToBuild: false } });

test('strict staged DATA does not establish native completion, registration or readiness', () => {
  assert.deepEqual(parseStagedToolSources(report()), report());
  for (const key of ['nativeFinality', 'registered', 'readyToBuild']) {
    const value = report(); value.assurance[key] = true;
    assert.equal(parseStagedToolSources(value), null);
  }
  const other = report(); other.cacheJob = '../existing';
  assert.equal(parseStagedToolSources(other), null);
  const overlap = report(); overlap.downloadedArchives.unshift('jdk');
  assert.equal(parseStagedToolSources(overlap), null);
  const extra = report(); extra.path = '/not-an-input';
  assert.equal(parseStagedToolSources(extra), null);
});

test('getters, unknown roles, duplicates and false complete SDK claims are rejected', () => {
  let reads = 0;
  const getter = report(); Object.defineProperty(getter.groups, '0', { enumerable: true, get() { reads++; return {}; } });
  assert.equal(parseStagedToolSources(getter), null);
  assert.equal(reads, 0);
  for (const field of ['groups', 'downloadedArchives']) {
    const value = report(); value[field].push(value[field][0]);
    assert.equal(parseStagedToolSources(value), null);
  }
  const partial = report(); partial.downloadedArchives = ['sdk-platform', 'gradle']; partial.groups[1].components = ['sdk-platform'];
  assert.equal(parseStagedToolSources(partial), null);
  partial.groups[1].allRequiredComponentsStaged = false; partial.groups[1].next = 'complete-sdk-manually';
  assert.ok(parseStagedToolSources(partial));
  const help = stagedToolSourceGuidance(partial, 'current-staged');
  assert.match(help.steps[0], /staged SDK is incomplete/);
  assert.equal(help.pickers[1].label, 'Choose complete Android SDK');
});

test('a result offer, stale context or unknown original cannot show continuation actions', () => {
  for (const state of ['settling', 'stale', 'recovery-required', undefined]) {
    const guidance = stagedToolSourceGuidance(report(), state);
    assert.deepEqual(guidance.pickers, []);
    assert.deepEqual(guidance.steps, []);
  }
  assert.deepEqual(stagedToolSourceGuidance({}, 'current-staged').pickers, []);
  const current = stagedToolSourceGuidance(report(), 'current-staged');
  assert.deepEqual(current.pickers.map((picker) => picker.role), ['jdk', 'sdk', 'gradle']);
  assert.match(current.body, /not automatic installation or build readiness/);
  assert.match(current.steps.join(' '), /not every folder/);
  assert.match(current.steps.join(' '), /explicitly approving/);
});

test('all-compatible no-effect report and precise failure guidance keep working tools', () => {
  const nothing = report(); nothing.reusedArchives = []; nothing.downloadedArchives = []; nothing.groups = []; nothing.cacheJob = '';
  assert.ok(parseStagedToolSources(nothing));
  assert.deepEqual(stagedToolSourceGuidance(nothing, 'current-staged').pickers, []);
  assert.match(stagedToolSourceGuidance(nothing, 'current-staged').body, /Nothing was downloaded/);
  assert.match(toolAcquisitionFailureGuidance('disk-space').body, /protected copy needs its own space/);
  assert.match(toolAcquisitionFailureGuidance('unknown').body, /absent folder/);
  assert.match(toolAcquisitionFailureGuidance('census-incomplete').body, /missing selection is not proof/);
  assert.match(toolAcquisitionFailureGuidance('network').body, /Do not disable TLS/);
});
