// Authored inert renderer DATA regressions; not executed during source staging.
// All hashes, identities, command observations and dispositions are invented
// fixtures. They establish no file custody, tool execution, cleanup, native
// finality, qualification or authority to Start. No bridge/controller is used.
import assert from 'node:assert/strict';
import test from 'node:test';
import { ANDROID_BUILD_ABIS, ANDROID_BUILD_CHECK_IDS, ANDROID_BUILD_CONSENT, ANDROID_BUILD_CONSENT_MS,
  ANDROID_BUILD_CORE_STATUSES, ANDROID_BUILD_COUNTER_MAX, ANDROID_BUILD_EVENT, ANDROID_BUILD_IPC_LIMIT,
  ANDROID_BUILD_LIMITATIONS, ANDROID_BUILD_MAX_AAB_BYTES, ANDROID_BUILD_MAX_FINDINGS, ANDROID_BUILD_SCOPE,
  ANDROID_BUILD_SIGNER_MESSAGE, ANDROID_BUILD_STAGES, ANDROID_BUILD_STATUS_LIMIT, ANDROID_BUILD_TOOLCHAIN_PROFILE,
  androidBuildAvailabilityText, androidBuildCounter, androidBuildError, androidBuildFindingText, androidBuildLimitationText,
  androidBuildOperationProgress, androidBuildReasonText, copyAndroidBuildRequest, encodeAndroidBuildRequest,
  parseAndroidBuildResult, parseAndroidBuildSavedConfig, parseAndroidBuildSavedVersion, parseAndroidBuildStatus,
  sameAndroidBuildData, sameAndroidBuildIdentity, sameAndroidBuildSavedPair } from '../src/androidBuildProtocol.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), OTHER = 'c'.repeat(32);
const CONFIG = { bytes: 512, sha256: 'd'.repeat(64) };
const VERSION = { source: 'release/version.properties', bytes: 41, sha256: 'e'.repeat(64), name: '1.2.3', build: 42 };
const ROWS = [['aab-structure', 'PASS'], ['aab-manifest', 'PASS'], ['signer', 'SKIP']];
const clone = (value) => structuredClone(value);
const decode = (value) => JSON.parse(new TextDecoder().decode(value));
const request = () => ({ projectId: 'inert-android', draftRevision: 2, baselineGeneration: 3, savedConfig: clone(CONFIG), savedVersion: clone(VERSION) });
const context = () => ({ ...request(), platform: 'android', operation: 'android-build-inspect' });
const selection = () => ({ module: ':app', variant: 'release', applicationId: 'org.example.app', task: ':app:bundleRelease' });
function inspection(rows = ROWS) {
  const counts = Object.fromEntries(ANDROID_BUILD_CORE_STATUSES.map((status) => [status, 0]));
  const findings = rows.map(([check, status], ordinal) => { counts[status]++; return { ordinal, check, status }; });
  return { findings, summary: { total: findings.length, shown: findings.length, omitted: 0, counts } };
}
function report(rows = ROWS, assurancePatch = {}) {
  return { schemaVersion: 1, scope: ANDROID_BUILD_SCOPE, usedConfig: clone(CONFIG), usedVersion: clone(VERSION),
    selection: selection(), toolchainProfile: ANDROID_BUILD_TOOLCHAIN_PROFILE, command: { outcome: 'exited', exitCode: 0 },
    ...inspection(rows), artifacts: [{ logicalName: 'android-aab', platform: 'android', kind: 'aab', fileName: 'app-release.aab',
      size: 1024, sha256: 'f'.repeat(64), architectures: ['arm64-v8a'], unknownAbi: false, freshness: 'not-established' }],
    assurances: { structure: 'passed', nativeManifest: 'passed', applicationVersion: 'native-checked', signer: 'not-inspected',
      toolkitSigning: 'not-requested', storeOperation: 'not-requested', sourceBinding: 'not-established', releaseReadiness: 'not-assessed', ...assurancePatch },
    limitations: [...ANDROID_BUILD_LIMITATIONS] };
}
const operation = (patch = {}) => ({ operationId: OP, ownerGeneration: OWNER, context: context(), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', stage: null, activity: null, disposition: null, result: null, ...patch });
const status = (op = null, revision = 0, availability = 'available') => ({ schemaVersion: 1, statusRevision: revision, availability, operation: op });
function completed(result = report()) {
  return operation({ phase: 'terminal', intentUsable: false, outcome: 'complete', stage: 'disposing-work',
    activity: { stage: 'disposing-work', selection: clone(result.selection), command: clone(result.command),
      findings: clone(result.findings), summary: clone(result.summary) },
    disposition: { work: 'removed', artifacts: 'retained-local-result' }, result: clone(result) });
}
function negative(reason = 'command-failed', exitCode = 7, patch = {}) {
  return operation({ phase: 'terminal', intentUsable: false, outcome: 'failed', reason, stage: 'disposing-work',
    activity: { stage: 'disposing-work', selection: selection(), command: { outcome: 'exited', exitCode }, ...inspection([]) },
    disposition: { work: 'removed', artifacts: 'not-created' }, ...patch });
}
function checkedOperation(op) {
  const value = parseAndroidBuildStatus(status(op)); assert.ok(value); return value.operation;
}

test('four raw request encoders copy only closed renderer DATA, not native inputs or execution overrides', () => {
  const input = request(), copy = copyAndroidBuildRequest('prepare_android_build', input);
  assert.deepEqual(clone(copy), input); assert.notEqual(copy, input); assert.notEqual(copy.savedVersion, input.savedVersion);
  const raw = encodeAndroidBuildRequest('prepare_android_build', input);
  assert.ok(raw instanceof Uint8Array); assert.ok(raw.byteLength <= ANDROID_BUILD_IPC_LIMIT); assert.deepEqual(decode(raw), input);
  input.savedVersion.build++; assert.equal(copy.savedVersion.build, VERSION.build); assert.equal(decode(raw).savedVersion.build, VERSION.build);
  const start = { operationId: OP, ownerGeneration: OWNER, consentVersion: ANDROID_BUILD_CONSENT };
  assert.deepEqual(decode(encodeAndroidBuildRequest('start_android_build', start)), start);
  assert.deepEqual(decode(encodeAndroidBuildRequest('cancel_android_build', { operationId: OP, ownerGeneration: OWNER })), { operationId: OP, ownerGeneration: OWNER });
  assert.equal(new TextDecoder().decode(encodeAndroidBuildRequest('android_build_status', {})), '{}');
  for (const key of ['root', 'path', 'native', 'toolchain', 'module', 'variant', 'argv', 'environment', 'timeout', 'credentials', 'draft', 'platform', 'operation']) {
    assert.equal(encodeAndroidBuildRequest('prepare_android_build', { ...request(), [key]: 'PRIVATE' }), null, key);
  }
  for (const key of ['source', 'savedConfig', 'savedVersion', 'retry', 'consent', 'deadline']) {
    assert.equal(encodeAndroidBuildRequest('start_android_build', { ...start, [key]: true }), null, key);
  }
  assert.equal(encodeAndroidBuildRequest('start_offline_preflight', start), null);
  assert.equal(encodeAndroidBuildRequest('start_android_build', { ...start, consentVersion: 'saved-offline-android-v1' }), null);
  assert.equal(encodeAndroidBuildRequest('android_build_status', { refresh: true }), null);
});

test('request counters, identities, integer ranges and hashes are closed and bounded', () => {
  for (const counter of [0, ANDROID_BUILD_COUNTER_MAX]) {
    assert.ok(androidBuildCounter(counter)); assert.ok(encodeAndroidBuildRequest('prepare_android_build', { ...request(), draftRevision: counter, baselineGeneration: counter }));
  }
  for (const counter of [-1, -0, true, 1.5, NaN, Infinity, 0xffff_ffff, Number.MAX_SAFE_INTEGER + 1, 1n]) {
    assert.equal(androidBuildCounter(counter), false);
    for (const key of ['draftRevision', 'baselineGeneration']) assert.equal(encodeAndroidBuildRequest('prepare_android_build', { ...request(), [key]: counter }), null);
    assert.equal(parseAndroidBuildStatus(status(null, counter)), null);
  }
  for (const projectId of ['', '../x', 'x\n', 'é', 'x'.repeat(65)]) assert.equal(encodeAndroidBuildRequest('prepare_android_build', { ...request(), projectId }), null);
  for (const token of ['', 'A'.repeat(32), OP + '\n', 'x'.repeat(32), OP.slice(1)]) {
    for (const key of ['operationId', 'ownerGeneration']) assert.equal(encodeAndroidBuildRequest('cancel_android_build', { operationId: OP, ownerGeneration: OWNER, [key]: token }), null);
  }
  for (const bytes of [1, 524288]) assert.ok(parseAndroidBuildSavedConfig({ ...CONFIG, bytes }));
  for (const bytes of [0, -0, -1, 524289, 1.25, true]) assert.equal(parseAndroidBuildSavedConfig({ ...CONFIG, bytes }), null);
  for (const sha256 of ['D'.repeat(64), CONFIG.sha256 + '\n', 'f'.repeat(63), 'x'.repeat(64)]) assert.equal(parseAndroidBuildSavedConfig({ ...CONFIG, sha256 }), null);
  assert.equal(parseAndroidBuildSavedConfig({ ...CONFIG, path: '/PRIVATE' }), null);
});

test('descriptor copying refuses getters, serialization hooks, inheritance, cycles and sparse data without running hooks', () => {
  let reads = 0;
  const getter = { ...request(), get savedVersion() { reads++; return VERSION; } };
  const nested = { ...request(), savedVersion: { ...VERSION, get name() { reads++; return VERSION.name; } } };
  const hidden = Object.defineProperty(request(), 'projectId', { value: 'inert-android', enumerable: false });
  const toJSON = { ...request(), toJSON() { reads++; return request(); } };
  const inherited = Object.assign(Object.create({ toJSON() { reads++; return request(); } }), request());
  const cycle = request(); cycle.savedConfig = cycle;
  const sparse = []; sparse[2] = request();
  const many = Object.fromEntries(Array.from({ length: 80 }, (_, n) => [String(n), null]));
  for (const value of [getter, nested, hidden, toJSON, inherited, cycle, sparse, many, new Date(), new String('x'),
    { ...request(), [Symbol('private')]: true }, { ...request(), projectId: 'x'.repeat(8193) }, { ...request(), projectId: '\ud800' }]) {
    assert.equal(copyAndroidBuildRequest('prepare_android_build', value), null);
  }
  const nullPrototype = Object.assign(Object.create(null), request());
  assert.ok(encodeAndroidBuildRequest('prepare_android_build', nullPrototype));
  const withGetter = report(); Object.defineProperty(withGetter.artifacts[0], 'sha256', { enumerable: true, get() { reads++; return 'f'.repeat(64); } });
  assert.equal(parseAndroidBuildResult(withGetter), null);
  assert.equal(parseAndroidBuildStatus({ ...status(), get operation() { reads++; return completed(); } }), null);
  const arrayHook = report(); arrayHook.findings.toJSON = () => { reads++; return []; };
  assert.equal(parseAndroidBuildResult(arrayHook), null);
  assert.equal(reads, 0);
});

test('saved version transport preserves exact source/name/build without duplicating core Unicode or release policy', () => {
  for (const bytes of [1, 65536]) for (const build of [1, 2_100_000_000]) assert.ok(parseAndroidBuildSavedVersion({ ...VERSION, bytes, build }));
  for (const [key, values] of [['bytes', [0, 65537, true]], ['build', [0, 2_100_000_001, 1.2, true]],
    ['name', ['', 'x'.repeat(65), '1.2.3\n', 'é']], ['sha256', ['E'.repeat(64), 'e'.repeat(63)]]]) {
    for (const value of values) assert.equal(parseAndroidBuildSavedVersion({ ...VERSION, [key]: value }), null, key);
  }
  const acceptedSources = ['release/version.properties', 'a/'.repeat(11) + 'v', 'é'.repeat(127) + 'a',
    'a'.repeat(255) + '/' + 'b'.repeat(254) + '/c'];
  for (const source of acceptedSources) assert.equal(parseAndroidBuildSavedVersion({ ...VERSION, source }).source, source);
  for (const source of ['', '/version', '../version', 'a//v', 'a/./v', 'a/../v', 'a/v/', 'a/v.', 'a/v ', 'a\\v', 'C:/v',
    '.mobile-release/v', 'release/PRIVATE/v', 'release/secrets/v', 'credentials/v', 'Review/v', 'TestFlight/v', 'Build/v',
    'DerivedData/v', 'Pods/v', 'node_modules/v', 'venv/v', 'dist/v', 'target/v', '__pycache__/v', 'con.txt', 'COM0/v', 'lpt9.txt',
    'v?x', 'v\u007f', 'v\n', '\ud800', 'a'.repeat(256), 'é'.repeat(128), 'a/'.repeat(12) + 'v',
    'a'.repeat(255) + '/' + 'b'.repeat(255) + '/c']) assert.equal(parseAndroidBuildSavedVersion({ ...VERSION, source }), null, source);
  // Deliberate native/renderer transport seam: preserve rather than normalize.
  // Full NFC/casefold source admission still belongs to core before any effect.
  for (const source of ['release/cafe\u0301.env', 'release/ſecrets/version.env']) {
    assert.equal(parseAndroidBuildSavedVersion({ ...VERSION, source }).source, source);
  }
  assert.equal(parseAndroidBuildSavedVersion({ ...VERSION, name: 'not-a-marketing-version' }).name, 'not-a-marketing-version');
  assert.equal(parseAndroidBuildSavedVersion({ ...VERSION, qualified: true }), null);
});

test('saved-pair comparison includes both hashes/byte counts plus source, effective name and build', () => {
  const a = request(), b = request(); assert.ok(sameAndroidBuildSavedPair(a, b));
  for (const [parent, key, value] of [['savedConfig', 'bytes', 513], ['savedConfig', 'sha256', 'a'.repeat(64)],
    ['savedVersion', 'bytes', 42], ['savedVersion', 'sha256', 'b'.repeat(64)], ['savedVersion', 'source', 'release/other.env'],
    ['savedVersion', 'name', '1.2.4'], ['savedVersion', 'build', 43]]) {
    const other = request(); other[parent][key] = value;
    assert.equal(sameAndroidBuildSavedPair(a, other), false, `${parent}.${key}`);
  }
  assert.ok(sameAndroidBuildSavedPair(null, null)); assert.equal(sameAndroidBuildSavedPair(a, null), false);
  b.savedVersion = Object.fromEntries(Object.entries(b.savedVersion).reverse()); assert.ok(sameAndroidBuildSavedPair(a, b));
  assert.ok(sameAndroidBuildIdentity({ operationId: OP, ownerGeneration: OWNER }, { ownerGeneration: OWNER, operationId: OP }));
  assert.equal(sameAndroidBuildIdentity(null, null), false); assert.equal(sameAndroidBuildIdentity(operation(), { operationId: OP, ownerGeneration: OTHER }), false);
});

test('result copies preserve all nine statuses and fixed redaction without inventing a release decision', () => {
  const rows = [['aab-structure', 'PASS'], ...ANDROID_BUILD_CORE_STATUSES.map((value) => ['other-core-finding', value])];
  const raw = report(rows, { nativeManifest: 'not-checked', applicationVersion: 'not-established' });
  const parsed = parseAndroidBuildResult(raw); assert.ok(parsed); assert.deepEqual(clone(parsed), raw); assert.notEqual(parsed, raw);
  assert.deepEqual(parsed.findings.slice(1).map((row) => row.status), [...ANDROID_BUILD_CORE_STATUSES]);
  raw.artifacts[0].sha256 = 'a'.repeat(64); raw.usedVersion.build++;
  assert.equal(parsed.artifacts[0].sha256, 'f'.repeat(64)); assert.equal(parsed.usedVersion.build, VERSION.build);
  assert.equal(parsed.assurances.signer, 'not-inspected'); assert.equal(parsed.assurances.toolkitSigning, 'not-requested');
  assert.equal(parsed.assurances.sourceBinding, 'not-established'); assert.equal(parsed.assurances.releaseReadiness, 'not-assessed');
  for (const check of ANDROID_BUILD_CHECK_IDS.filter((key) => !['signer', 'core-lifecycle'].includes(key))) {
    const single = report([['aab-structure', 'PASS'], [check, 'FAIL']], { structure: check === 'aab-structure' ? 'failed' : 'passed',
      nativeManifest: ['aab-manifest', 'application-id', 'build-number', 'version-name', 'release-flags'].includes(check) ? 'failed' : 'not-checked',
      applicationVersion: 'not-established' });
    assert.ok(parseAndroidBuildResult(single), check);
  }
});

test('exact finding counts/ordinals and 128-row bound cannot silently truncate negative findings', () => {
  const rows = [['aab-structure', 'PASS'], ...Array.from({ length: ANDROID_BUILD_MAX_FINDINGS - 1 }, () => ['other-core-finding', 'FAIL'])];
  const full = report(rows, { nativeManifest: 'not-checked', applicationVersion: 'not-established' });
  assert.equal(parseAndroidBuildResult(full).summary.shown, 128);
  assert.equal(parseAndroidBuildResult(report([...rows, ['application-id', 'FAIL']], { nativeManifest: 'failed', applicationVersion: 'not-established' })), null);
  const mutations = [
    (x) => { x.summary.total++; }, (x) => { x.summary.shown--; }, (x) => { x.summary.omitted = 1; },
    (x) => { x.summary.counts.PASS++; }, (x) => { delete x.summary.counts.FAIL; }, (x) => { x.summary.counts.EXTRA = 0; },
    (x) => { x.summary.counts.PASS = true; }, (x) => { x.findings[0].ordinal = 1; }, (x) => { x.findings[0].ordinal = true; },
    (x) => { x.findings[0].status = 'OK'; }, (x) => { x.findings[0].check = 'private.dynamic.check'; },
    (x) => { x.findings[0].message = 'PRIVATE compiler text'; }, (x) => { x.findings[0].details = { path: '/PRIVATE' }; },
    (x) => { x.findings[0].projectCheckIndex = 0; }, (x) => { delete x.findings[0]; },
    (x) => { x.findings[0].check = 'core-lifecycle'; }, (x) => { x.limitations.reverse(); },
    (x) => { x.limitations.push('fresh-build'); }, (x) => { x.limitations.pop(); }, (x) => { x.schemaVersion = true; },
  ];
  for (const mutate of mutations) { const value = report(); mutate(value); assert.equal(parseAndroidBuildResult(value), null); }
  const missingStructure = report([['aab-manifest', 'PASS']], { structure: 'not-checked', nativeManifest: 'not-checked', applicationVersion: 'not-established' });
  assert.equal(parseAndroidBuildResult(missingStructure), null);
});

test('assurances are derived from exact supported findings, not accepted as optimistic caller strings', () => {
  const cases = [
    [[['aab-structure', 'PASS'], ['aab-manifest', 'PASS']], 'passed', 'passed', 'native-checked'],
    [[['aab-structure', 'FAIL']], 'failed', 'not-checked', 'not-established'],
    [[['aab-structure', 'BLOCKED'], ['aab-manifest', 'PASS']], 'failed', 'not-checked', 'not-established'],
    [[['aab-structure', 'PASS'], ['aab-structure', 'PASS']], 'not-checked', 'not-checked', 'not-established'],
    [[['aab-structure', 'PASS'], ['aab-manifest', 'INVALID']], 'passed', 'failed', 'not-established'],
    [[['aab-structure', 'PASS'], ['aab-manifest', 'SKIP']], 'passed', 'not-checked', 'not-established'],
    [[['aab-structure', 'PASS'], ['aab-manifest', 'PASS'], ['application-id', 'PASS']], 'passed', 'not-checked', 'not-established'],
    [[['aab-structure', 'PASS'], ['aab-manifest', 'PASS'], ['other-core-finding', 'PASS']], 'passed', 'not-checked', 'not-established'],
  ];
  for (const [rows, structure, nativeManifest, applicationVersion] of cases) {
    const value = report(rows, { structure, nativeManifest, applicationVersion }); assert.ok(parseAndroidBuildResult(value));
    for (const key of ['structure', 'nativeManifest', 'applicationVersion']) {
      const forged = clone(value), current = forged.assurances[key];
      forged.assurances[key] = key === 'applicationVersion' ? (current === 'native-checked' ? 'not-established' : 'native-checked') :
        current === 'passed' ? 'not-checked' : 'passed'; // Valid enum, wrong derivation.
      assert.equal(parseAndroidBuildResult(forged), null, key);
    }
  }
  for (const [key, value] of [['signer', 'approved'], ['toolkitSigning', 'unsigned'], ['storeOperation', 'impossible'],
    ['sourceBinding', 'verified'], ['releaseReadiness', 'ready'], ['nativeFinality', true]]) {
    const forged = report(); forged.assurances[key] = value; assert.equal(parseAndroidBuildResult(forged), null, key);
  }
  for (const value of ANDROID_BUILD_CORE_STATUSES.filter((status) => status !== 'SKIP')) assert.equal(parseAndroidBuildResult(report([
    ['aab-structure', 'PASS'], ['aab-manifest', 'PASS'], ['signer', value]])), null, value);
});

test('one redacted AAB has bounded bytes, sorted unique ABIs and no current path/freshness/signer authority', () => {
  for (const size of [1, ANDROID_BUILD_MAX_AAB_BYTES]) {
    const value = report(); value.artifacts[0].size = size; value.artifacts[0].architectures = [...ANDROID_BUILD_ABIS];
    assert.ok(parseAndroidBuildResult(value));
  }
  const empty = report(); empty.artifacts[0].architectures = []; empty.artifacts[0].unknownAbi = true; assert.ok(parseAndroidBuildResult(empty));
  for (const [key, value] of [['size', 0], ['size', ANDROID_BUILD_MAX_AAB_BYTES + 1], ['size', true], ['sha256', 'F'.repeat(64)],
    ['fileName', '/PRIVATE/output.aab'], ['logicalName', 'android-mapping'], ['platform', 'ios'], ['kind', 'apk'], ['freshness', 'newly-built'],
    ['unknownAbi', 'false'], ['architectures', ['x86_64', 'arm64-v8a']], ['architectures', ['x86', 'x86']], ['architectures', ['PRIVATE_ARCHIVE_PATH']],
    ['path', '/PRIVATE/output.aab'], ['signer', 'PRIVATE_CERT'], ['observedAt', 'now']]) {
    const bad = report(); bad.artifacts[0][key] = value; assert.equal(parseAndroidBuildResult(bad), null, key);
  }
  const none = report(); none.artifacts = []; assert.equal(parseAndroidBuildResult(none), null);
  const extra = report(); extra.artifacts.push(clone(extra.artifacts[0])); assert.equal(parseAndroidBuildResult(extra), null);
});

test('selection strings are bounded labels only; no extra argv, toolchain or execution data survives', () => {
  const boundary = report(); boundary.selection = { module: ':' + 'a'.repeat(511), variant: 'r'.repeat(128),
    applicationId: 'a.' + 'b'.repeat(253), task: ':' + 't'.repeat(647) }; assert.ok(parseAndroidBuildResult(boundary));
  const rootModule = report(); rootModule.selection.module = ':'; assert.ok(parseAndroidBuildResult(rootModule));
  for (const [key, values] of [['module', ['', 'app', ':' + 'a'.repeat(512), ':app\n', ':app/path']],
    ['variant', ['', 'r'.repeat(129), 'release.debug', 'r\n']], ['applicationId', ['app', '1org.example', 'org.2app', 'org..app', 'org.example\n', 'a.' + 'b'.repeat(254)]],
    ['task', [':', 'bundleRelease', ':' + 't'.repeat(648), ':app:bundleRelease --offline']]]) {
    for (const value of values) { const bad = report(); bad.selection[key] = value; assert.equal(parseAndroidBuildResult(bad), null, key); }
  }
  for (const key of ['argv', 'root', 'toolchain', 'native', 'lifetime', 'nativeFinality', 'compilerOutput']) {
    const bad = report(); bad[key] = 'PRIVATE'; assert.equal(parseAndroidBuildResult(bad), null, key);
  }
  const extra = report(); extra.selection.argv = ['PRIVATE']; assert.equal(parseAndroidBuildResult(extra), null);
  const foreignProfile = report(); foreignProfile.toolchainProfile = 'android-local-macos-arm64-v1'; assert.equal(parseAndroidBuildResult(foreignProfile), null);
});

test('native Status exposes only stage while interim, withholds observations and never consumes core terminals as finality', () => {
  for (const availability of Object.keys(androidBuildAvailabilityText)) assert.ok(parseAndroidBuildStatus(status(null, ANDROID_BUILD_COUNTER_MAX, availability)));
  assert.equal(parseAndroidBuildStatus(status(null, 0, 'qualified-by-diagnostics')), null);
  for (const intentUsable of [true, false]) assert.ok(parseAndroidBuildStatus(status(operation({ intentUsable }))));
  for (const phase of ['starting', 'running', 'stopping']) {
    const stages = phase === 'starting' ? [null] : [null, ...ANDROID_BUILD_STAGES];
    for (const stage of stages) assert.ok(parseAndroidBuildStatus(status(operation({ phase, stage, intentUsable: false }))));
    for (const key of ['activity', 'disposition', 'result']) {
      const bad = operation({ phase, intentUsable: false }); bad[key] = completed()[key]; assert.equal(parseAndroidBuildStatus(status(bad)), null, `${phase}.${key}`);
    }
  }
  assert.equal(parseAndroidBuildStatus(status(operation({ phase: 'starting', intentUsable: false, stage: 'accepted' }))), null);
  assert.equal(parseAndroidBuildStatus(status(operation({ stage: 'accepted' }))), null);
  assert.equal(parseAndroidBuildStatus(status(operation({ phase: 'running', intentUsable: true }))), null);
  const coreLike = { schemaVersion: 1, context: context(), outcome: 'complete', reason: 'none', activity: completed().activity,
    disposition: completed().disposition, result: report(), lifetime: { complete: true } };
  assert.equal(parseAndroidBuildStatus(coreLike), null); // Even an optimistic core-shaped object is not native Status.
});

test('native completed status must match the complete saved pair and every projected activity observation', () => {
  const raw = status(completed(), 9), parsed = parseAndroidBuildStatus(raw); assert.ok(parsed); assert.deepEqual(clone(parsed), raw);
  assert.notEqual(parsed.operation.result, raw.operation.result); assert.notEqual(parsed.operation.activity.findings, raw.operation.activity.findings);
  for (const [parent, key, value] of [['usedConfig', 'bytes', 513], ['usedConfig', 'sha256', 'a'.repeat(64)], ['usedVersion', 'bytes', 42],
    ['usedVersion', 'sha256', 'b'.repeat(64)], ['usedVersion', 'source', 'release/other.env'], ['usedVersion', 'name', '1.2.4'], ['usedVersion', 'build', 43]]) {
    const bad = completed(); bad.result[parent][key] = value; assert.equal(parseAndroidBuildStatus(status(bad)), null, `${parent}.${key}`);
  }
  const mismatch = completed(); mismatch.activity.selection.task = ':other:bundleRelease'; assert.equal(parseAndroidBuildStatus(status(mismatch)), null);
  const rows = completed(); rows.activity.findings[0].check = 'aab-manifest'; assert.equal(parseAndroidBuildStatus(status(rows)), null);
  for (const key of ['stage', 'activity', 'disposition', 'result']) {
    const bad = completed(); bad[key] = null; assert.equal(parseAndroidBuildStatus(status(bad)), null, key);
  }
  for (const mutate of [(x) => { x.disposition.work = 'retained-work'; }, (x) => { x.disposition.artifacts = 'retained-incomplete'; },
    (x) => { x.stage = 'inspecting'; }, (x) => { x.reason = 'work-retained'; }, (x) => { x.intentUsable = true; }]) {
    const bad = completed(); mutate(bad); assert.equal(parseAndroidBuildStatus(status(bad)), null);
  }
});

test('complete-with-FAIL is a valid settled local observation, never native inspection or release approval', () => {
  const result = report([['aab-structure', 'FAIL']], { structure: 'failed', nativeManifest: 'not-checked', applicationVersion: 'not-established' });
  const parsed = parseAndroidBuildStatus(status(completed(result))); assert.ok(parsed);
  assert.equal(parsed.operation.outcome, 'complete'); assert.equal(parsed.operation.result.findings[0].status, 'FAIL');
  assert.equal(parsed.operation.result.assurances.nativeManifest, 'not-checked'); assert.equal(parsed.operation.result.assurances.releaseReadiness, 'not-assessed');
  assert.equal(parsed.operation.result.artifacts[0].freshness, 'not-established');
});

test('known command failure, incomplete command and no dispatch cannot be silently interchanged', () => {
  for (const code of [-0x8000_0000, -9, 7, 0x7fff_ffff]) assert.ok(parseAndroidBuildStatus(status(negative('command-failed', code))));
  for (const code of [0, -0, true, 1.5, NaN, 0x8000_0000, -0x8000_0001]) assert.equal(parseAndroidBuildStatus(status(negative('command-failed', code))), null);
  const unknown = negative('command-incomplete'); unknown.activity.command = { outcome: 'unknown', exitCode: null };
  assert.ok(parseAndroidBuildStatus(status(unknown))); // Unknown command outcome with known settlement is not unknown cleanup.
  for (const code of [0, 7, -9]) assert.equal(parseAndroidBuildStatus(status(negative('command-incomplete', code))), null);
  unknown.reason = 'command-failed'; assert.equal(parseAndroidBuildStatus(status(unknown)), null);
  unknown.reason = 'command-incomplete'; unknown.activity.command.exitCode = 7; assert.equal(parseAndroidBuildStatus(status(unknown)), null);
  const refusal = operation({ phase: 'terminal', intentUsable: false, outcome: 'refused', reason: 'module-required', stage: 'accepted',
    activity: { stage: 'accepted', selection: null, command: { outcome: 'not-dispatched', exitCode: null }, ...inspection([]) },
    disposition: { work: 'not-created', artifacts: 'not-created' } });
  assert.ok(parseAndroidBuildStatus(status(refusal)));
  refusal.activity.command.exitCode = 0; assert.equal(parseAndroidBuildStatus(status(refusal)), null);
  const dispatched = negative('module-required', 7, { outcome: 'refused' }); assert.equal(parseAndroidBuildStatus(status(dispatched)), null);
  const artifactAfterFailure = negative(); Object.assign(artifactAfterFailure.activity, inspection([['aab-structure', 'FAIL']]));
  assert.equal(parseAndroidBuildStatus(status(artifactAfterFailure)), null);
});

test('artifact reasons require actual post-zero command/capture-shaped DATA, never an admission refusal or substitute scan', () => {
  for (const reason of ['artifact-missing', 'artifact-ambiguous', 'artifact-unsafe', 'artifact-changed']) {
    for (const stage of ['capturing', 'inspecting', 'disposing-work']) {
      const value = negative(reason, 0); value.stage = stage; value.activity.stage = stage; assert.ok(parseAndroidBuildStatus(status(value)), reason);
    }
    const nonzero = negative(reason, 7); assert.equal(parseAndroidBuildStatus(status(nonzero)), null);
    const early = negative(reason, 0); early.stage = early.activity.stage = 'building'; assert.equal(parseAndroidBuildStatus(status(early)), null);
    const refused = negative(reason, 0, { outcome: 'refused' }); assert.equal(parseAndroidBuildStatus(status(refused)), null);
  }
});

test('known retained work requires Failed and cannot masquerade as clean cancellation, complete or unknown projection', () => {
  const retained = negative('work-retained', 0); retained.disposition = { work: 'retained-work', artifacts: 'retained-incomplete' };
  assert.ok(parseAndroidBuildStatus(status(retained)));
  const firstFailure = negative('command-failed', 7); firstFailure.disposition.work = 'retained-work'; assert.ok(parseAndroidBuildStatus(status(firstFailure)));
  const notRetained = negative('work-retained', 0); assert.equal(parseAndroidBuildStatus(status(notRetained)), null);
  for (const [outcome, reason] of [['complete', 'none'], ['cancelled', 'cancelled'], ['timed-out', 'timed-out'], ['unknown', 'cleanup-unknown']]) {
    const bad = clone(retained); Object.assign(bad, { outcome, reason, phase: outcome === 'unknown' ? 'unknown' : 'terminal' });
    assert.equal(parseAndroidBuildStatus(status(bad)), null, outcome);
  }
  for (const [work, artifacts] of [['unknown', 'not-created'], ['removed', 'unknown'], ['removed', 'retained-local-result']]) {
    const bad = negative(); bad.disposition = { work, artifacts }; assert.equal(parseAndroidBuildStatus(status(bad)), null);
  }
});

test('native negative terminals require paired support for command/artifact/work facts but can retain only a stage for protocol failures', () => {
  for (const reason of ['command-failed', 'command-incomplete', 'artifact-missing', 'artifact-ambiguous', 'artifact-unsafe', 'artifact-changed', 'work-retained']) {
    const bad = operation({ phase: 'terminal', intentUsable: false, outcome: 'failed', reason, stage: 'building' });
    assert.equal(parseAndroidBuildStatus(status(bad)), null, reason);
  }
  assert.ok(parseAndroidBuildStatus(status(operation({ phase: 'terminal', intentUsable: false, outcome: 'failed', reason: 'protocol-error', stage: 'building' }))));
  assert.ok(parseAndroidBuildStatus(status(operation({ phase: 'terminal', intentUsable: false, outcome: 'refused', reason: 'runtime-unavailable' }))));
  for (const key of ['activity', 'disposition']) {
    const bad = negative(); bad[key] = null; assert.equal(parseAndroidBuildStatus(status(bad)), null, key);
  }
  const wrongStage = negative(); wrongStage.stage = 'building'; assert.equal(parseAndroidBuildStatus(status(wrongStage)), null);
  const badResult = negative(); badResult.result = report(); assert.equal(parseAndroidBuildStatus(status(badResult)), null);
});

test('native-only Cancelled projection preserves all four retirement reasons, without weakening retained-work or timeout rules', () => {
  // M1: native first-reason semantics differ from the provisional Python core
  // terminal contract. A context/document/shutdown retirement is still Cancelled.
  for (const reason of ['cancelled', 'context-changed', 'document-lost', 'shutdown']) {
    const beforeStart = operation({ phase: 'terminal', intentUsable: false, outcome: 'cancelled', reason });
    assert.ok(parseAndroidBuildStatus(status(beforeStart)), reason);
    const observed = negative(reason, 7, { outcome: 'cancelled' }); assert.ok(parseAndroidBuildStatus(status(observed)), reason);
    observed.disposition.work = 'retained-work'; assert.equal(parseAndroidBuildStatus(status(observed)), null, reason);
    const complete = completed(); complete.reason = reason; assert.equal(parseAndroidBuildStatus(status(complete)), null, reason);
  }
  for (const reason of ['none', 'timed-out', 'protocol-error', 'command-failed', 'work-retained', 'cleanup-unknown']) {
    assert.equal(parseAndroidBuildStatus(status(negative(reason, 7, { outcome: 'cancelled' }))), null, reason);
  }
  assert.ok(parseAndroidBuildStatus(status(operation({ phase: 'terminal', intentUsable: false, outcome: 'timed-out', reason: 'timed-out' }))));
  for (const reason of ['cancelled', 'context-changed', 'document-lost', 'shutdown']) {
    assert.equal(parseAndroidBuildStatus(status(operation({ phase: 'terminal', intentUsable: false, outcome: 'timed-out', reason }))), null, reason);
  }
});

test('unknown native finality is sticky observation-only state, with no success result or paired terminal data', () => {
  const unknown = operation({ phase: 'unknown', intentUsable: false, outcome: 'unknown', reason: 'cleanup-unknown', stage: 'inspecting' });
  assert.ok(parseAndroidBuildStatus(status(unknown, 2, 'cleanup-unknown')));
  for (const key of ['activity', 'disposition', 'result']) {
    const bad = clone(unknown); bad[key] = completed()[key]; assert.equal(parseAndroidBuildStatus(status(bad)), null, key);
  }
  for (const patch of [{ intentUsable: true }, { reason: 'command-incomplete' }, { outcome: 'failed' }, { phase: 'terminal' }]) {
    assert.equal(parseAndroidBuildStatus(status({ ...unknown, ...patch })), null);
  }
  const a = checkedOperation(unknown), b = checkedOperation(completed()); assert.equal(androidBuildOperationProgress(a, b), false);
});

test('operation progression rejects stale saved pairs, identity replacement, backward stages and consent rearming', () => {
  const waiting = checkedOperation(operation());
  const starting = checkedOperation(operation({ phase: 'starting', intentUsable: false }));
  const running = checkedOperation(operation({ phase: 'running', intentUsable: false, stage: 'building' }));
  const stopping = checkedOperation(operation({ phase: 'stopping', intentUsable: false, stage: 'capturing', reason: 'cancelled' }));
  const terminal = checkedOperation(completed());
  for (const [a, b] of [[waiting, starting], [starting, running], [running, stopping], [running, terminal]]) assert.ok(androidBuildOperationProgress(a, b));
  for (const [a, b] of [[running, starting], [starting, waiting], [stopping, running], [terminal, running]]) assert.equal(androidBuildOperationProgress(a, b), false);
  const retired = checkedOperation(operation({ intentUsable: false })); assert.equal(androidBuildOperationProgress(retired, waiting), false);
  const backStage = checkedOperation(operation({ phase: 'stopping', intentUsable: false, stage: 'accepted', reason: 'cancelled' }));
  assert.equal(androidBuildOperationProgress(running, backStage), false);
  for (const mutate of [(x) => { x.ownerGeneration = OTHER; }, (x) => { x.operationId = OTHER; },
    (x) => { x.context.savedVersion.build++; }, (x) => { x.context.savedVersion.source = 'release/other.env'; },
    (x) => { x.context.savedConfig.sha256 = 'a'.repeat(64); }, (x) => { x.context.draftRevision++; }, (x) => { x.context.baselineGeneration++; }]) {
    const raw = operation({ phase: 'running', intentUsable: false, stage: 'building' }); mutate(raw);
    assert.equal(androidBuildOperationProgress(running, checkedOperation(raw)), false);
  }
  assert.ok(androidBuildOperationProgress(terminal, checkedOperation(completed())));
  const differentTerminal = completed(); differentTerminal.result.artifacts[0].sha256 = 'a'.repeat(64);
  assert.equal(androidBuildOperationProgress(terminal, checkedOperation(differentTerminal)), false);
  const reordered = Object.fromEntries(Object.entries(status(completed(), 8)).reverse());
  assert.ok(sameAndroidBuildData(parseAndroidBuildStatus(reordered), parseAndroidBuildStatus(status(completed(), 8))));
  assert.equal(sameAndroidBuildData(parseAndroidBuildStatus(status(completed(), 8)), parseAndroidBuildStatus(status(completed(), 8, 'shutdown'))), false);
});

test('required nullable status keys and aggregate copied-DATA limits fail closed without reflecting private text', () => {
  for (const key of ['stage', 'activity', 'disposition', 'result', 'outcome']) {
    const bad = operation(); delete bad[key]; assert.equal(parseAndroidBuildStatus(status(bad)), null, key);
  }
  for (const key of ['nativeFinality', 'lifetime', 'rootIdentity', 'toolchain', 'compilerOutput']) {
    const bad = completed(); bad[key] = 'PRIVATE'; assert.equal(parseAndroidBuildStatus(status(bad)), null, key);
  }
  for (const key of ['platform', 'operation']) {
    const bad = operation(); bad.context[key] = key === 'platform' ? 'ios' : 'offline-preflight'; assert.equal(parseAndroidBuildStatus(status(bad)), null, key);
  }
  const payload = status(completed()); payload.privateOutput = 'x'.repeat(ANDROID_BUILD_STATUS_LIMIT + 1); assert.equal(parseAndroidBuildStatus(payload), null);
  let deep = null; for (let n = 0; n < 20; n++) deep = { next: deep };
  assert.equal(parseAndroidBuildStatus({ ...status(), extra: deep }), null);
  const sparse = report(); delete sparse.artifacts[0]; assert.equal(parseAndroidBuildResult(sparse), null);
  assert.equal(parseAndroidBuildStatus({ ...status(), statusRevision: '1' }), null);
  assert.equal(parseAndroidBuildStatus({ ...status(), schemaVersion: true }), null);
});

test('fixed reasons/help distinguish failure from cleanup and errors never relay arbitrary native messages', () => {
  const reasons = ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error',
    'runtime-unavailable', 'intent-expired', 'stale-intent', ...['config', 'version'].flatMap((kind) =>
      ['missing', 'invalid', 'changed', 'sensitive', 'unsafe', 'too-large'].map((reason) => `saved-${kind}-${reason}`)),
    'platform-disabled', 'module-required', 'toolchain-unavailable', 'toolchain-mismatch', 'project-admission-refused',
    'command-failed', 'command-incomplete', 'artifact-missing', 'artifact-ambiguous', 'artifact-unsafe', 'artifact-changed',
    'input-limit', 'result-limit', 'work-retained', 'cleanup-unknown'];
  assert.deepEqual(Object.keys(androidBuildReasonText).sort(), reasons.sort());
  assert.deepEqual(Object.keys(androidBuildFindingText).sort(), [...ANDROID_BUILD_CHECK_IDS].sort());
  assert.deepEqual(Object.keys(androidBuildLimitationText).sort(), [...ANDROID_BUILD_LIMITATIONS].sort());
  assert.match(androidBuildReasonText['command-failed'], /Possible causes/); assert.match(androidBuildReasonText['command-incomplete'], /no exit code/);
  assert.match(androidBuildReasonText['cleanup-unknown'], /further execution stays blocked/); assert.match(androidBuildReasonText.none, /not release approval/);
  assert.equal(ANDROID_BUILD_SIGNER_MESSAGE, 'Toolkit signing was not requested; artifact signer was not inspected. Project code may have signed this file.');
  assert.equal(ANDROID_BUILD_EVENT, 'android-build-state-changed'); assert.equal(ANDROID_BUILD_CONSENT_MS, 300_000);
  let reads = 0;
  const privateError = { code: 'android_build_owner', get message() { reads++; return 'PRIVATE'; }, retryable: true };
  const safe = androidBuildError(privateError); assert.equal(safe.code, 'android_build_owner'); assert.equal(safe.retryable, false); assert.doesNotMatch(safe.message, /PRIVATE/);
  assert.equal(androidBuildError({ get code() { reads++; return 'android_build_owner'; } }).code, 'android_build_protocol');
  assert.equal(androidBuildError({ code: 'PRIVATE_COMPILER_DIAGNOSIS', message: 'PRIVATE' }).code, 'android_build_protocol');
  assert.equal(reads, 0);
});

test('availability text does not turn a closed gate into missing-SDK diagnosis or an installer', () => {
  assert.match(androidBuildAvailabilityText['runtime-unqualified'], /does not mean your JDK or SDK is missing/);
  assert.match(androidBuildAvailabilityText['toolchain-unqualified'], /not selected, not inspected or not yet qualified/);
  assert.match(androidBuildAvailabilityText['toolchain-unqualified'], /installs no tools and accepts no licenses/);
  assert.match(androidBuildAvailabilityText['unsupported-platform'], /no fallback runner/);
  assert.match(androidBuildAvailabilityText.available, /Saved-input review and explicit consent/);
});
