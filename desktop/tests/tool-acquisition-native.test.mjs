// Bounded DATA/fake-port tests. No native owner, filesystem, vendor download,
// tool execution, installation or qualification is exercised here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createToolAcquisitionApi } from '../src/toolAcquisitionNative.ts';
import { encodeToolAcquisitionRequest, parseToolAcquisitionContext, parseToolAcquisitionStatus,
  TOOL_ACQUISITION_CONSENT, TOOL_ACQUISITION_EVENT, toolAcquisitionProgress } from '../src/toolAcquisitionProtocol.ts';

const clone = (v) => structuredClone(v);
const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), SHA = 'c'.repeat(64);
const context = () => ({ projectId: 'inert-project', draftRevision: 1, baselineGeneration: 2,
  savedConfig: { bytes: 12, sha256: SHA }, action: 'inspect', review: null });
const operation = () => ({ operationId: OP, ownerGeneration: OWNER, context: context(), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', result: null });
const status = (op = null) => ({ schemaVersion: 1, statusRevision: 4, availability: op ? 'busy' : 'available', operation: op });
const requirements = () => ({ kind: 'tool-requirements-observation', protectedTools: 'none-in-supported-catalogue', requirements: {
  schemaVersion: 1, basis: 'unverified-static-source-hints', sourcesSha256: SHA, complete: true, platform: 'android', projectCodeExecuted: false,
  xcode: { version: '26.3', build: '17C529' }, android: { jdk: { state: 'literal', value: '17' }, agp: { state: 'literal', value: '8.9.2' },
    sdkPlatform: { state: 'literal', value: 'android-35' }, sdkBuildTools: { state: 'unspecified', value: null },
    gradle: { state: 'literal', version: '8.14.5', distributionUrl: 'https://services.gradle.org/distributions/gradle-8.14.5-bin.zip', sha256: SHA } } } });
function complete(action = 'inspect') {
  return { ...operation(), context: { ...context(), action, review: action === 'inspect' ? null :
    { operationId: 'd'.repeat(32), ownerGeneration: 'e'.repeat(32), requirementsSha256: SHA } },
  phase: 'terminal', intentUsable: false, outcome: 'complete', result: requirements() };
}
const staged = () => ({ schemaVersion: 1, kind: 'staged-tool-sources', operationId: OP, contextSha256: SHA,
  referenceSha256: SHA, projectionSha256: SHA, cacheJob: `tool-${OP}`, lookupScope: 'registered-selected-known', reusedArchives: ['jdk'],
  downloadedArchives: ['sdk-platform', 'sdk-build-tools', 'gradle'], groups: [
    { group: 'jdk', components: ['jdk'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'sdk', components: ['sdk-platform', 'sdk-build-tools'], allRequiredComponentsStaged: true, next: 'choose-native-source' },
    { group: 'gradle', components: ['gradle'], allRequiredComponentsStaged: true, next: 'choose-native-source' }],
  assurance: { nativeFinality: false, registered: false, readyToBuild: false } });

test('fixed port sends exactly four RAW commands and one event; no preview fallback', async () => {
  const calls = [], events = [];
  const invoke = async (name, raw) => { assert.ok(raw instanceof Uint8Array); assert.ok(raw.byteLength <= 8192); calls.push([name, JSON.parse(new TextDecoder().decode(raw))]); return status(); };
  const listen = async (name, callback) => { events.push([name, callback]); return () => {}; };
  assert.equal(createToolAcquisitionApi('preview', invoke, listen), null);
  assert.equal(createToolAcquisitionApi('native', invoke), null);
  const api = createToolAcquisitionApi('native', invoke, listen);
  await api.prepare(context()); await api.start({ operationId: OP, ownerGeneration: OWNER, consentVersion: TOOL_ACQUISITION_CONSENT });
  await api.status(); await api.cancel({ operationId: OP, ownerGeneration: OWNER }); await api.subscribe(() => {});
  assert.deepEqual(calls.map(([name]) => name), ['prepare_tool_acquisition', 'start_tool_acquisition', 'tool_acquisition_status', 'cancel_tool_acquisition']);
  assert.deepEqual(calls[2][1], {}); assert.equal(events[0][0], TOOL_ACQUISITION_EVENT);
  assert.ok(Object.isFrozen(api));
  assert.throws(() => api.prepare({ ...context(), url: 'https://example.invalid' }));
  assert.equal(calls.length, 4);
});

test('closed request grammar refuses extra authority, invalid review, getters and limits', () => {
  assert.ok(parseToolAcquisitionContext(context()));
  for (const field of ['url', 'path', 'native', 'pins', 'argv', 'sourceSnapshot', 'readyToBuild', 'consentVersion'])
    assert.equal(encodeToolAcquisitionRequest('prepare_tool_acquisition', { ...context(), [field]: 'not-an-authority' }), null);
  for (const change of [{ action: 'acquire' }, { review: {} }, { projectId: '../project' }, { draftRevision: -0 },
    { baselineGeneration: 0xffffffff }, { savedConfig: { bytes: 0, sha256: SHA } }, { padding: 'x'.repeat(8193) }])
    assert.equal(parseToolAcquisitionContext({ ...context(), ...change }), null);
  assert.equal(encodeToolAcquisitionRequest('start_tool_acquisition', { operationId: OP, ownerGeneration: OWNER, consentVersion: 'anything-else' }), null);
  assert.equal(encodeToolAcquisitionRequest('tool_acquisition_status', { resume: true }), null);
  assert.equal(encodeToolAcquisitionRequest('arbitrary_command', {}), null);
  const missing = context(); delete missing.review; assert.equal(parseToolAcquisitionContext(missing), null);
  let got = 0; const getter = context(); Object.defineProperty(getter, 'review', { enumerable: true, get() { got++; return null; } });
  assert.equal(parseToolAcquisitionContext(getter), null); assert.equal(got, 0);
});

test('public inspection parser matches omitted footprint, exact static hint grammar and nullable fields', () => {
  const valid = status(complete()); assert.ok(parseToolAcquisitionStatus(valid));
  const bad = [
    (v) => { v.operation.result.footprint = {}; },
    (v) => { v.operation.result.requirements.complete = false; },
    (v) => { v.operation.result.requirements.projectCodeExecuted = true; },
    (v) => { v.operation.result.requirements.android.agp = { state: 'unspecified', value: null }; },
    (v) => { v.operation.result.requirements.android.gradle.version = '8..14'; },
    (v) => { v.operation.result.requirements.android.gradle.distributionUrl = 'https://example.invalid/gradle.zip'; },
    (v) => { v.operation.result.requirements.android.gradle.sha256 = 'C'.repeat(64); },
    (v) => { v.operation.result.requirements.android.jdk.value = 'x'.repeat(129); },
    (v) => { delete v.operation.result.requirements.android.jdk.value; },
  ];
  for (const mutate of bad) { const v = clone(valid); mutate(v); assert.equal(parseToolAcquisitionStatus(v), null); }
  const unknown = clone(valid); unknown.operation.result.requirements.android.gradle = { state: 'unknown', version: null, distributionUrl: null, sha256: null };
  assert.ok(parseToolAcquisitionStatus(unknown)); // Unknown is DATA, not permission to guess a pin.
  const copy = parseToolAcquisitionStatus(valid); valid.operation.context.projectId = 'changed';
  assert.equal(copy.operation.context.projectId, 'inert-project');
});

test('phase/outcome/result contradictions, dangerous objects and bounded status fail closed', () => {
  for (const change of [{ phase: 'running', result: requirements() }, { phase: 'terminal', outcome: 'complete' },
    { outcome: 'complete' }, { intentUsable: 'true' }, { phase: 'unknown', outcome: 'unknown', reason: 'cleanup-unknown' },
    { reason: 'not-a-reason' }, { phase: 'all-done' }])
    assert.equal(parseToolAcquisitionStatus(status({ ...operation(), ...change })), null);
  const unknown = { ...operation(), phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown' };
  assert.ok(parseToolAcquisitionStatus(status(unknown)));
  assert.equal(toolAcquisitionProgress(unknown, complete()), false);
  assert.equal(toolAcquisitionProgress(complete(), { ...complete(), reason: 'cancelled' }), false);
  let got = 0; const bad = status(); Object.defineProperty(bad, 'operation', { enumerable: true, get() { got++; return null; } });
  assert.equal(parseToolAcquisitionStatus(bad), null); assert.equal(got, 0);
  assert.equal(parseToolAcquisitionStatus({ ...status(), padding: 'x'.repeat(65537) }), null);
  const cycle = status(); cycle.operation = cycle; assert.equal(parseToolAcquisitionStatus(cycle), null);
  assert.equal(parseToolAcquisitionStatus({ ...status(), toJSON() { got++; return {}; } }), null); assert.equal(got, 0);
});

test('public protected-tool comparison is closed and cannot be used as request authority', () => {
  for (const finding of [null, 'reuse-selected', 'none-in-supported-catalogue', 'manual-check-required']) {
    const op = complete(); op.result.protectedTools = finding;
    assert.equal(parseToolAcquisitionStatus(status(op)).operation.result.protectedTools, finding);
    assert.equal(encodeToolAcquisitionRequest('prepare_tool_acquisition', { ...context(), protectedTools: finding }), null);
  }
  for (const finding of [true, {}, ['jdk'], 'ready', 'installed', 'partial-reuse']) {
    const op = complete(); op.result.protectedTools = finding;
    assert.equal(parseToolAcquisitionStatus(status(op)), null);
  }
  const missing = complete(); delete missing.result.protectedTools;
  assert.equal(parseToolAcquisitionStatus(status(missing)), null);
  const extra = complete(); extra.result.readyToBuild = true;
  assert.equal(parseToolAcquisitionStatus(status(extra)), null);
});

test('native staged result requires all four sources, same operation and no installation assertions', () => {
  const op = { ...complete('acquire'), result: staged() }; assert.ok(parseToolAcquisitionStatus(status(op)));
  for (const field of ['nativeFinality', 'registered', 'readyToBuild']) {
    const v = clone(op); v.result.assurance[field] = true; assert.equal(parseToolAcquisitionStatus(status(v)), null);
  }
  for (const mutate of [
    (v) => { v.result.operationId = 'f'.repeat(32); },
    (v) => { v.result.downloadedArchives.pop(); v.result.groups.pop(); },
    (v) => { v.result.downloadedArchives.unshift('jdk'); },
    (v) => { v.result.groups[1].components.pop(); v.result.groups[1].allRequiredComponentsStaged = false; v.result.groups[1].next = 'complete-sdk-manually'; },
    (v) => { v.context.action = 'inspect'; v.context.review = null; },
  ]) { const v = clone(op); mutate(v); assert.equal(parseToolAcquisitionStatus(status(v)), null); }
  assert.equal(parseToolAcquisitionStatus(staged()), null);
});
