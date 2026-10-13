// SOURCE-only until separate command admission. Synthetic DTOs/promises and
// source-text integration checks, not document IO, native finality or GUI proof.
// The five JSON fixtures are EXACT expectedResultFixtures from core contract01:
// bfddf6299b3d5efbcedb4bf60a4f72f465b57933f1f85a2a0e41fbac53f83bd0.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { CandidateEvidenceController, EVIDENCE_ASSURANCE, compareDecimal,
  evidenceError, evidenceHelp, evidenceProblemText, evidenceRequestFits,
  parseCandidateEvidence, parseEvidenceStatus } from '../src/candidateEvidence.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const fixtureBytes = readFileSync(new URL('./fixtures/candidate-evidence.json', import.meta.url));
const fixtures = JSON.parse(fixtureBytes.toString('utf8'));
const clone = (value) => structuredClone(value);
const wire = (value) => JSON.parse(JSON.stringify(value));
const CANARY = 'inert-private-detail-not-for-display';
const FIRST = { selectionId: 'evidence-first', displayName: 'Saved candidate' };
const SECOND = { selectionId: 'evidence-second', displayName: 'Other candidate' };
const FALSE_FLAGS = ['artifactBytesVerified', 'workflowAuthenticated', 'storeStateObserved',
  'comparedWithSourceProject', 'releaseReady', 'recoveryAuthorized'];
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const flush = async () => { for (let i = 0; i < 14; i += 1) await Promise.resolve(); };
function frozenTree(value) {
  if (value !== null && typeof value === 'object') {
    assert.equal(Object.isFrozen(value), true);
    for (const child of Object.values(value)) frozenTree(child);
  }
}
function status(revision = '0', changes = {}) {
  return { schemaVersion: 1, revision, availability: 'available', phase: 'idle',
    selection: null, operation: null, result: null, problem: null, ...clone(changes) };
}
function selected(revision = '2', folder = FIRST, operationId = '1') {
  return status(revision, { phase: 'selected', selection: folder,
    operation: { operationId, kind: 'choose', selectionId: null } });
}
function observing(revision = '3', operationId = '2', folder = FIRST) {
  return status(revision, { phase: 'observing', selection: folder,
    operation: { operationId, kind: 'observe', selectionId: folder.selectionId } });
}
function observed(revision = '4', operationId = '2', folder = FIRST, result = fixtures.androidConsistent) {
  return { ...observing(revision, operationId, folder), phase: 'observed', result: clone(result) };
}
function cancelled(revision = '4', operationId = '2', folder = FIRST) {
  return { ...observing(revision, operationId, folder), phase: 'cancelled', problem: 'cancelled' };
}
function unknown(revision = '4', operationId = '2', folder = FIRST) {
  return { ...observing(revision, operationId, folder), phase: 'unknown', problem: 'cleanup_unknown' };
}
function harness(t, initial = status(), mode = 'native') {
  let registry = clone(initial), sequence = 0;
  const calls = [], reads = [], timers = new Map();
  // No real timer, sleep, event listener, host operation or native worker starts.
  t.mock.method(globalThis, 'setTimeout', (callback, milliseconds) => {
    assert.equal(milliseconds, 300);
    const id = ++sequence; timers.set(id, callback); return id;
  });
  t.mock.method(globalThis, 'clearTimeout', (id) => { timers.delete(id); });
  const issue = (kind, args) => {
    const work = deferred(); calls.push({ kind, args: clone(args), ...work }); return work.promise;
  };
  const api = {
    mode,
    evidenceStatus: () => {
      calls.push({ kind: 'status', args: {} });
      return reads.length ? reads.shift().promise : Promise.resolve(clone(registry));
    },
    chooseEvidenceFolder: () => issue('choose', {}),
    observeEvidence: (selectionId) => issue('observe', { selectionId }),
    cancelEvidence: (operationId, selectionId) => issue('cancel', { operationId, selectionId }),
  };
  const controller = new CandidateEvidenceController();
  const last = (kind) => calls.filter((row) => row.kind === kind).at(-1);
  t.after(() => { controller.dispose(); assert.equal(timers.size, 0); });
  return { controller, api, calls, timers, ready: controller.connect(api),
    get state() { return controller.getSnapshot(); }, last,
    count: (kind) => calls.filter((row) => row.kind === kind).length,
    registry(value) { registry = clone(value); },
    reply(kind, value) { registry = clone(value); last(kind).resolve(clone(value)); },
    deferRead() { const work = deferred(); reads.push(work); return work; },
    tick() {
      assert.equal(timers.size, 1);
      const [id, callback] = [...timers][0]; timers.delete(id); callback();
    },
  };
}

test('five pinned cross-language expected DTOs parse without upgrading any assurance', () => {
  assert.equal(fixtureBytes.length, 6652);
  assert.equal(createHash('sha256').update(fixtureBytes).digest('hex'),
    'a5689c1d0067cff8a2315f65fb8dc4d828ee041aab7f11d3c5eebf5ce0ec5923');
  assert.deepEqual(Object.keys(fixtures), ['androidConsistent', 'iosConsistent', 'missingAll',
    'invalidManifestMissingOthers', 'crossBindingMismatch']);
  for (const [name, fixture] of Object.entries(fixtures)) {
    const input = clone(fixture), parsed = parseCandidateEvidence(input);
    assert.ok(parsed, name); assert.deepEqual(wire(parsed), fixture); frozenTree(parsed);
    assert.equal(parsed.assurance.level, 'local-document-consistency');
    assert.equal(parsed.assurance.documentsOnly, true);
    for (const flag of FALSE_FLAGS) assert.equal(parsed.assurance[flag], false, flag);
    input.assurance.releaseReady = true;
    assert.equal(parsed.assurance.releaseReady, false, 'input cannot mutate accepted DATA');
  }
  const value = clone(fixtures.androidConsistent), parsed = parseCandidateEvidence(value);
  value.summary.artifacts[0].declaredBytes = '9'; value.documents[0].state = 'missing';
  assert.equal(parsed.summary.artifacts[0].declaredBytes, '12345678');
  assert.equal(parsed.documents[0].state, 'valid');
});

test('every assurance field is mandatory exact DATA, never truthy or a release/recovery grant', () => {
  for (const flag of FALSE_FLAGS) {
    for (const replacement of [true, 0, null, 'false']) {
      const value = clone(fixtures.androidConsistent); value.assurance[flag] = replacement;
      assert.equal(parseCandidateEvidence(value), null, flag);
    }
    const value = clone(fixtures.androidConsistent); delete value.assurance[flag];
    assert.equal(parseCandidateEvidence(value), null, flag);
  }
  for (const change of [
    (a) => { a.documentsOnly = false; }, (a) => { a.documentsOnly = 1; },
    (a) => { a.level = 'authenticated'; }, (a) => { a.provenanceVerified = false; },
  ]) {
    const value = clone(fixtures.androidConsistent); change(value.assurance);
    assert.equal(parseCandidateEvidence(value), null);
  }
});

test('closed keys and mandatory nested fields reject unknown or incomplete result shapes', () => {
  const targets = [(v) => v, (v) => v.documents[0], (v) => v.summary, (v) => v.summary.version,
    (v) => v.summary.source, (v) => v.summary.artifacts[0], (v) => v.summary.recordedRuns,
    (v) => v.summary.recordedRuns.authorizedBy, (v) => v.summary.documentPayloadSha256, (v) => v.assurance];
  for (const target of targets) {
    const extra = clone(fixtures.androidConsistent); target(extra).unexpected = CANARY;
    assert.equal(parseCandidateEvidence(extra), null);
    const missing = clone(fixtures.androidConsistent), row = target(missing);
    delete row[Object.keys(row)[0]]; assert.equal(parseCandidateEvidence(missing), null);
  }
  for (const schemaVersion of [true, '1', 0, 2]) {
    assert.equal(parseCandidateEvidence({ ...clone(fixtures.androidConsistent), schemaVersion }), null);
  }
});

test('document order and outcome precedence prevent partial/invalid data becoming a complete summary', () => {
  const cases = [
    [fixtures.androidConsistent, (v) => { v.documents.reverse(); }],
    [fixtures.androidConsistent, (v) => { v.documents[1].kind = 'manifest'; }],
    [fixtures.androidConsistent, (v) => { v.documents.pop(); }],
    [fixtures.androidConsistent, (v) => { v.documents[0].state = 'missing'; }],
    [fixtures.androidConsistent, (v) => { v.documents[0].state = 'invalid'; }],
    [fixtures.androidConsistent, (v) => { v.summary = null; }],
    [fixtures.missingAll, (v) => { v.outcome = 'invalid'; }],
    [fixtures.invalidManifestMissingOthers, (v) => { v.outcome = 'incomplete'; }],
    [fixtures.missingAll, (v) => { v.outcome = 'inconsistent'; }],
    [fixtures.crossBindingMismatch, (v) => { v.outcome = 'incomplete'; }],
    [fixtures.crossBindingMismatch, (v) => { v.summary = clone(fixtures.androidConsistent.summary); }],
  ];
  for (const [base, change] of cases) {
    const value = clone(base); change(value); assert.equal(parseCandidateEvidence(value), null);
  }
});

test('large declared sizes and all three run roles stay exact positive decimal strings', () => {
  const value = clone(fixtures.androidConsistent), big = '9'.repeat(64);
  value.summary.artifacts[0].declaredBytes = big;
  value.summary.recordedRuns = {
    authorizedBy: { runId: '9007199254740993', attempt: '7' },
    executedBy: { runId: '18446744073709551616', attempt: '12345678901234567890' },
    producedBy: { runId: big, attempt: '8'.repeat(64) },
  };
  const parsed = parseCandidateEvidence(value); assert.ok(parsed);
  assert.equal(parsed.summary.artifacts[0].declaredBytes, big);
  assert.deepEqual(wire(parsed.summary.recordedRuns), value.summary.recordedRuns);
  for (const bad of ['0', '01', '+1', '-1', '1.0', '1e2', ' 1', '1\n', '1\r', '1\u2028', '1\u2029', '١', '1'.repeat(65), 123, true]) {
    for (const target of ['size', 'run', 'attempt']) {
      const altered = clone(value);
      if (target === 'size') altered.summary.artifacts[0].declaredBytes = bad;
      else altered.summary.recordedRuns.producedBy[target === 'run' ? 'runId' : 'attempt'] = bad;
      assert.equal(parseCandidateEvidence(altered), null, target);
    }
  }
});

test('platform-specific roles are mandatory, ordered and unique without banning optional artifacts', () => {
  const android = clone(fixtures.androidConsistent), sample = android.summary.artifacts[0];
  android.summary.artifacts.splice(1, 0,
    { ...sample, logicalName: 'android-mapping' }, { ...sample, logicalName: 'android-native-symbols' });
  assert.ok(parseCandidateEvidence(android));
  const ios = clone(fixtures.iosConsistent);
  ios.summary.artifacts = ios.summary.artifacts.filter((row) => row.logicalName !== 'ios-dsyms');
  assert.ok(parseCandidateEvidence(ios));
  const cases = [
    [android, (v) => { v.summary.artifacts.shift(); }],
    [android, (v) => { v.summary.artifacts[1].logicalName = 'ios-ipa'; }],
    [android, (v) => { v.summary.artifacts[1].logicalName = 'android-aab'; }],
    [android, (v) => { v.summary.artifacts.reverse(); }],
    [android, (v) => { v.summary.artifacts = v.summary.artifacts.filter((r) => r.logicalName !== 'store-metadata'); }],
    [android, (v) => { v.summary.artifacts.pop(); }],
    [ios, (v) => { v.summary.artifacts = v.summary.artifacts.filter((r) => r.logicalName !== 'ios-archive'); }],
    [ios, (v) => { v.summary.artifacts[0].logicalName = 'android-aab'; }],
    [ios, (v) => { v.summary.artifacts[0].logicalName = 'other'; }],
  ];
  for (const [base, change] of cases) {
    const value = clone(base); change(value); assert.equal(parseCandidateEvidence(value), null);
  }
});

test('marketing versions, build integers, identifiers and digest alphabets retain core guards', () => {
  for (const marketing of ['1.2', '1.2.3', '1.2.3.4', '1.2.3-rc.1', '1.2.3+build.7']) {
    const value = clone(fixtures.androidConsistent); value.summary.version.marketing = marketing;
    assert.ok(parseCandidateEvidence(value), marketing);
  }
  for (const marketing of ['1', 'v1.2.3', '1.2.3.4.5', '1.2+', '1.2\n', '1.2\r', '1.2\u2028', '1.2\u2029', '1.' + '1'.repeat(63)]) {
    const value = clone(fixtures.androidConsistent); value.summary.version.marketing = marketing;
    assert.equal(parseCandidateEvidence(value), null);
  }
  const cases = [
    (v) => { v.summary.version.build = true; }, (v) => { v.summary.version.build = 1.5; },
    (v) => { v.summary.version.build = 0; }, (v) => { v.summary.version.build = 2100000001; },
    (v) => { v.summary.applicationId = 'ab'; }, (v) => { v.summary.applicationId = 'x'.repeat(256); },
    (v) => { v.summary.applicationId = 'a\u202eb'; }, (v) => { v.summary.applicationId = 'a\ud800b'; },
    (v) => { v.summary.applicationId = 'a\u0085b'; }, (v) => { v.summary.applicationId = '😀'.repeat(256); },
    (v) => { v.summary.source.commit = 'g'.repeat(40); },
    (v) => { v.summary.artifacts[0].sha256 = 'A'.repeat(64); },
    (v) => { v.summary.documentPayloadSha256.receipt = 'f'.repeat(63); },
  ];
  for (const change of cases) { const value = clone(fixtures.androidConsistent); change(value); assert.equal(parseCandidateEvidence(value), null); }
  const boundary = clone(fixtures.androidConsistent);
  boundary.summary.applicationId = '😀'.repeat(255); boundary.summary.version.build = 2100000000;
  boundary.summary.source.commit = 'A'.repeat(40); assert.ok(parseCandidateEvidence(boundary));
  for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
    for (const change of [
      (v) => { v.summary.source.commit += suffix; }, (v) => { v.summary.source.tree += suffix; },
      (v) => { v.summary.artifacts[0].sha256 += suffix; },
      (v) => { v.summary.documentPayloadSha256.manifest += suffix; },
    ]) {
      const value = clone(fixtures.androidConsistent); change(value); assert.equal(parseCandidateEvidence(value), null);
    }
  }
});

test('own accessors and serialization hooks are never read, called or leaked by either parser', () => {
  let reads = 0;
  for (const target of [(v) => v, (v) => v.summary, (v) => v.summary.artifacts[0]]) {
    const value = clone(fixtures.androidConsistent);
    Object.defineProperty(target(value), 'private', { enumerable: true, get() { reads += 1; return CANARY; } });
    assert.equal(parseCandidateEvidence(value), null);
    const envelope = observed(); envelope.result = value;
    assert.equal(parseEvidenceStatus(envelope), null);
  }
  const getter = clone(fixtures.androidConsistent);
  Object.defineProperty(getter, 'toJSON', { enumerable: true, get() { reads += 1; throw new Error(CANARY); } });
  assert.equal(parseCandidateEvidence(getter), null);
  const hook = clone(fixtures.androidConsistent); hook.toJSON = () => { reads += 1; return CANARY; };
  assert.equal(parseCandidateEvidence(hook), null);
  const array = clone(fixtures.androidConsistent);
  Object.defineProperty(array.documents, '0', { enumerable: true, get() { reads += 1; return CANARY; } });
  assert.equal(parseCandidateEvidence(array), null);
  const envelope = observed();
  Object.defineProperty(envelope.selection, 'displayName', { enumerable: true, get() { reads += 1; return CANARY; } });
  assert.equal(parseEvidenceStatus(envelope), null);
  assert.equal(reads, 0);
});

test('non-DATA, hidden/symbol fields, sparse arrays, cycles and bounded-copy overruns refuse', () => {
  const values = [new Date(0), new Uint8Array([1]), Object.create({ inherited: true }), null, [], Infinity, 1.5, 1n];
  const cycle = clone(fixtures.androidConsistent); cycle.loop = cycle; values.push(cycle);
  const hidden = clone(fixtures.androidConsistent); Object.defineProperty(hidden, 'private', { value: CANARY }); values.push(hidden);
  const symbol = clone(fixtures.androidConsistent); symbol[Symbol('private')] = CANARY; values.push(symbol);
  const sparse = clone(fixtures.androidConsistent); sparse.documents = new Array(3); values.push(sparse);
  const extra = clone(fixtures.androidConsistent); extra.documents.private = CANARY; values.push(extra);
  const deep = clone(fixtures.androidConsistent); let child = deep;
  for (let i = 0; i < 9; i += 1) child = child.extra = {}; values.push(deep);
  values.push({ ...clone(fixtures.androidConsistent), padding: 'x'.repeat(65537) });
  values.push({ ...clone(fixtures.androidConsistent), padding: '😀'.repeat(32760) });
  values.push(Object.fromEntries(Array.from({ length: 2049 }, (_, i) => [String(i), null])));
  const proxy = Proxy.revocable({}, {}); proxy.revoke(); values.push(proxy.proxy);
  for (const value of values) assert.equal(parseCandidateEvidence(value), null);
  const plain = Object.assign(Object.create(null), clone(fixtures.androidConsistent));
  assert.ok(parseCandidateEvidence(plain), 'own plain DATA with null prototype is supported');
});

test('only four bounded request forms cross the bridge; paths, roots and accessors do not', () => {
  for (const command of ['artifact_evidence_choose', 'artifact_evidence_status']) {
    assert.equal(evidenceRequestFits(command, {}), true);
    for (const key of ['root', 'path', 'projectId', 'draft', 'argv', 'force', 'timeout'])
      assert.equal(evidenceRequestFits(command, { [key]: CANARY }), false);
  }
  assert.equal(evidenceRequestFits('artifact_evidence_observe', { selectionId: FIRST.selectionId }), true);
  assert.equal(evidenceRequestFits('artifact_evidence_cancel', { operationId: '4294967294', selectionId: null }), true);
  assert.equal(evidenceRequestFits('artifact_evidence_cancel', { operationId: '2', selectionId: FIRST.selectionId }), true);
  for (const operationId of ['0', '01', '4294967295', '2\n', '2\r', '2\u2028', '2\u2029', 2, true])
    assert.equal(evidenceRequestFits('artifact_evidence_cancel', { operationId, selectionId: FIRST.selectionId }), false);
  for (const selectionId of ['', 'first', '/private/folder', 'evidence-a\n', 'evidence-a\r', 'evidence-a\u2028', 'evidence-a\u2029', 'evidence-' + 'x'.repeat(56), null])
    assert.equal(evidenceRequestFits('artifact_evidence_observe', { selectionId }), false);
  assert.equal(evidenceRequestFits('artifact_evidence_observe', { selectionId: FIRST.selectionId, operationId: '2' }), false);
  assert.equal(evidenceRequestFits('artifact_evidence_cancel', { operationId: '2' }), false);
  assert.equal(evidenceRequestFits('artifact_evidence_hash_payloads', {}), false);
  let reads = 0; const getter = {};
  Object.defineProperty(getter, 'selectionId', { enumerable: true, get() { reads += 1; return FIRST.selectionId; } });
  assert.equal(evidenceRequestFits('artifact_evidence_observe', getter), false); assert.equal(reads, 0);
});

test('status phase/selection/operation/result joins and cleanup-unknown semantics are closed', () => {
  for (const value of [status(), selected(), observing(), observed(), cancelled(), unknown(),
    status('1', { phase: 'choosing', operation: { operationId: '1', kind: 'choose', selectionId: null } }),
    { ...observing(), phase: 'stopping', problem: 'cancelled' },
    { ...observing(), phase: 'refused', problem: 'stale_selection' },
    status('0', { availability: 'unavailable', problem: 'unavailable' })]) assert.ok(parseEvidenceStatus(value));
  const cases = [
    [status(), (v) => { v.operation = observing().operation; }],
    [selected(), (v) => { v.operation = null; }],
    [selected(), (v) => { v.operation.kind = 'observe'; }],
    [observed(), (v) => { v.operation.selectionId = SECOND.selectionId; }],
    [observed(), (v) => { v.result = null; }],
    [observing(), (v) => { v.result = clone(fixtures.androidConsistent); }],
    [observed(), (v) => { v.result.assurance.recoveryAuthorized = true; }],
    [observed(), (v) => { v.problem = 'deadline'; }],
    [observed(), (v) => { v.availability = 'unavailable'; }],
    [unknown(), (v) => { v.problem = 'observation_failed'; }],
    [unknown(), (v) => { v.phase = 'refused'; }],
    [unknown(), (v) => { v.phase = 'cancelled'; }],
    [unknown(), (v) => { v.phase = 'stopping'; }],
    [cancelled(), (v) => { v.problem = 'stale_selection'; }],
    [cancelled(), (v) => { v.operation = null; }],
    [{ ...observing(), phase: 'stopping', problem: 'cancelled' }, (v) => { v.operation = null; }],
    [observed(), (v) => { v.operation.private = CANARY; }],
    [observed(), (v) => { v.selection.path = '/private/folder'; }],
    [observed(), (v) => { delete v.problem; }],
  ];
  for (const [base, change] of cases) { const value = clone(base); change(value); assert.equal(parseEvidenceStatus(value), null); }
  for (const displayName of ['/private/folder', 'private\\folder', 'name\n', 'a\u202eb', '\ud800', 'x'.repeat(129)]) {
    const value = selected(); value.selection.displayName = displayName; assert.equal(parseEvidenceStatus(value), null);
  }
  for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
    const value = observed(); value.selection.selectionId += suffix; value.operation.selectionId += suffix;
    assert.equal(parseEvidenceStatus(value), null, 'matching selection IDs still require true string end');
  }
});

test('status counters are lossless uint64 text and operation IDs have their own smaller bound', () => {
  const max = observed('18446744073709551615', '4294967294');
  const parsed = parseEvidenceStatus(max); assert.ok(parsed); assert.deepEqual(wire(parsed), max); frozenTree(parsed);
  for (const revision of ['18446744073709551616', '0001', '-1', '+1', '1\n', '1\r', '1\u2028', '1\u2029', true, 1, 1.5])
    assert.equal(parseEvidenceStatus({ ...max, revision }), null);
  for (const operationId of ['4294967295', '0', '01', '2\n', '2\r', '2\u2028', '2\u2029', 2]) {
    const value = clone(max); value.operation.operationId = operationId; assert.equal(parseEvidenceStatus(value), null);
  }
  assert.equal(compareDecimal('9007199254740993', '9007199254740992'), 1);
  assert.equal(compareDecimal('9999999999999999999', '10000000000000000000'), -1);
  assert.equal(compareDecimal('18446744073709551615', '18446744073709551615'), 0);
});

test('closed error mapping reads only a known own data code, never native detail or accessors', () => {
  let reads = 0;
  const getter = {};
  Object.defineProperty(getter, 'code', { get() { reads += 1; return 'artifact_evidence_deadline'; } });
  assert.equal(evidenceError(getter).code, 'artifact_evidence_protocol');
  const known = { code: 'artifact_evidence_deadline' };
  for (const key of ['message', 'path', 'stack', 'toString']) Object.defineProperty(known, key, { get() { reads += 1; throw new Error(CANARY); } });
  const mapped = evidenceError(known); assert.equal(mapped.code, 'artifact_evidence_deadline');
  assert.equal(mapped.retryable, false); assert.match(mapped.message, /does not extend/);
  for (const raw of [CANARY, new Error(CANARY), { code: CANARY, message: CANARY },
    { code: '__proto__' }, Object.create({ code: 'artifact_evidence_cancelled' })]) {
    const error = evidenceError(raw); assert.equal(error.code, 'artifact_evidence_protocol');
    assert.equal(JSON.stringify(error).includes(CANARY), false); assert.equal(error.retryable, false);
  }
  assert.equal(reads, 0); assert.match(evidenceProblemText('cleanup_unknown'), /new work is disabled/);
});

test('native bridge invokes only exact folder/status/registered-selection/original-cancel DTOs', async () => {
  const calls = []; let reply = selected();
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return reply; });
  const chosen = await api.chooseEvidenceFolder();
  reply.selection.displayName = 'Changed after return'; assert.equal(chosen.selection.displayName, FIRST.displayName);
  reply = selected(); await api.evidenceStatus();
  reply = observed(); await api.observeEvidence(FIRST.selectionId);
  reply = cancelled(); await api.cancelEvidence('2', FIRST.selectionId);
  assert.deepEqual(calls, [
    { command: 'artifact_evidence_choose', args: {} }, { command: 'artifact_evidence_status', args: {} },
    { command: 'artifact_evidence_observe', args: { selectionId: FIRST.selectionId } },
    { command: 'artifact_evidence_cancel', args: { operationId: '2', selectionId: FIRST.selectionId } },
  ]);
  await assert.rejects(api.observeEvidence('/private/folder'), (e) => e.code === 'artifact_evidence_invalid');
  await assert.rejects(api.cancelEvidence('4294967295', FIRST.selectionId), (e) => e.code === 'artifact_evidence_invalid');
  assert.equal(calls.length, 4);
});

test('bridge refuses malformed/accessor replies and redacts rejects without reading private properties', async () => {
  let reads = 0, invokes = 0;
  const value = observed();
  Object.defineProperty(value, 'private', { enumerable: true, get() { reads += 1; return CANARY; } });
  const api = createNativeApi('native', async () => { invokes += 1; return value; });
  await assert.rejects(api.evidenceStatus(), (e) => e.code === 'artifact_evidence_protocol' && !JSON.stringify(e).includes(CANARY));
  const request = {};
  Object.defineProperty(request, 'private', { enumerable: true, get() { reads += 1; return CANARY; } });
  await assert.rejects(api.observeEvidence(request), (e) => e.code === 'artifact_evidence_invalid');
  assert.equal(invokes, 1); assert.equal(reads, 0);
  const error = { code: 'artifact_evidence_unsafe_selection' };
  Object.defineProperty(error, 'message', { get() { reads += 1; return CANARY; } });
  const rejected = createNativeApi('native', async () => { throw error; });
  await assert.rejects(rejected.chooseEvidenceFolder(), (e) => e.code === error.code && !JSON.stringify(e).includes(CANARY));
  assert.equal(reads, 0);
});

test('unavailable bridge and explicit preview neither invoke nor fabricate evidence results', async () => {
  let invokes = 0;
  const unavailable = createNativeApi('unavailable', async () => { invokes += 1; return observed(); });
  for (const api of [unavailable, previewApi]) {
    for (const run of [() => api.chooseEvidenceFolder(), () => api.evidenceStatus(),
      () => api.observeEvidence(FIRST.selectionId), () => api.cancelEvidence('2', FIRST.selectionId)]) {
      await assert.rejects(run(), (e) => e.code === 'artifact_evidence_unavailable' && e.retryable === false);
    }
  }
  assert.equal(invokes, 0);
});

test('controller requires explicit folder choice then one registered-selection observation', async (t) => {
  const h = harness(t); await h.ready;
  assert.equal(h.controller.startReason(), null);
  await h.controller.observe(); assert.equal(h.count('observe'), 0);
  const choosing = h.controller.choose();
  assert.equal(h.state.pending, 'choose');
  await h.controller.choose(); await h.controller.observe();
  assert.equal(h.count('choose'), 1); assert.equal(h.count('observe'), 0);
  h.reply('choose', selected()); await choosing;
  assert.equal(h.state.status.selection.selectionId, FIRST.selectionId);
  assert.equal(h.state.status.result, null); assert.equal(h.state.pending, null);
  const reading = h.controller.observe();
  assert.deepEqual(h.last('observe').args, { selectionId: FIRST.selectionId });
  await h.controller.observe(); await h.controller.choose();
  assert.equal(h.count('observe'), 1); assert.equal(h.count('choose'), 1);
  h.reply('observe', observed()); await reading;
  assert.deepEqual(wire(h.state.status.result), fixtures.androidConsistent);
  assert.equal(h.state.pending, null); assert.equal(h.state.uncertain, false);
  assert.equal(h.controller.startReason(), null); assert.equal(h.state.stale, null);
  frozenTree(h.state);
});

test('pending read cannot cancel a prior terminal op; status binds the exact new op before STOP', async (t) => {
  const h = harness(t, selected()); await h.ready;
  const reading = h.controller.observe();
  await h.controller.cancel(); assert.equal(h.count('cancel'), 0);
  h.registry(observing()); h.tick(); await flush();
  assert.equal(h.state.pending, 'observe'); assert.notEqual(h.controller.startReason(), null);
  const stopping = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: '2', selectionId: FIRST.selectionId });
  await h.controller.cancel(); assert.equal(h.count('cancel'), 1);
  h.reply('cancel', { ...observing('4'), phase: 'stopping', problem: 'cancelled' }); await stopping;
  assert.equal(h.state.cancelling, false); assert.equal(h.state.status.phase, 'stopping');
  assert.equal(h.state.pending, 'observe'); assert.notEqual(h.controller.startReason(), null);
  h.last('observe').resolve(observing()); await reading;
  assert.equal(h.state.status.revision, '4'); assert.equal(h.state.status.phase, 'stopping');
  assert.equal(h.state.pending, null); assert.notEqual(h.controller.startReason(), null);
  h.registry(cancelled('5')); h.tick(); await flush();
  assert.equal(h.state.status.phase, 'cancelled'); assert.equal(h.controller.startReason(), null);
  assert.equal(h.count('observe'), 1); assert.equal(h.count('choose'), 0); assert.equal(h.timers.size, 0);
});

test('rejected initial choose is reconciled by status only, never by another picker invocation', async (t) => {
  const h = harness(t); await h.ready;
  const choosing = h.controller.choose(); h.registry(selected());
  h.last('choose').reject({ code: 'artifact_evidence_observation_failed', message: CANARY });
  await choosing; await flush();
  assert.equal(h.count('choose'), 1); assert.equal(h.count('observe'), 0); assert.equal(h.count('status'), 2);
  assert.equal(h.state.status.phase, 'selected'); assert.equal(h.state.pending, null);
  assert.equal(h.state.uncertain, false); assert.equal(h.state.error, null);
  assert.equal(h.controller.startReason(), null); assert.equal(h.timers.size, 0);
});

test('rejected initial read recovers the original result by status, without repeating the read', async (t) => {
  const h = harness(t, selected()); await h.ready;
  const reading = h.controller.observe(); h.registry(observed());
  h.last('observe').reject(new Error(CANARY)); await reading; await flush();
  assert.equal(h.count('observe'), 1); assert.equal(h.count('choose'), 0); assert.equal(h.count('status'), 2);
  assert.deepEqual(wire(h.state.status.result), fixtures.androidConsistent);
  assert.equal(h.state.pending, null); assert.equal(h.state.uncertain, false); assert.equal(h.state.error, null);
  assert.equal(h.controller.startReason(), null); assert.equal(h.timers.size, 0);
});

test('failed status suppresses current authority and starts until an explicit successful check', async (t) => {
  const h = harness(t, observed()); await h.ready;
  const delayed = h.deferRead(), checking = h.controller.check();
  assert.equal(h.state.checking, true);
  await h.controller.check(); assert.equal(h.count('status'), 2);
  delayed.reject({ code: 'artifact_evidence_observation_failed', message: CANARY }); await checking;
  assert.equal(h.state.uncertain, true); assert.equal(h.state.checking, false);
  assert.equal(h.state.error.code, 'artifact_evidence_observation_failed');
  assert.deepEqual(wire(h.state.stale), { selection: FIRST, result: fixtures.androidConsistent });
  assert.equal(JSON.stringify(h.state).includes(CANARY), false);
  await h.controller.choose(); await h.controller.observe();
  assert.equal(h.count('choose'), 0); assert.equal(h.count('observe'), 0); assert.equal(h.timers.size, 0);
  assert.notEqual(h.controller.startReason(), null);
  await h.controller.check();
  assert.equal(h.state.uncertain, false); assert.equal(h.state.error, null);
  assert.equal(h.state.stale, null); assert.equal(h.controller.startReason(), null);
  assert.equal(h.count('status'), 3);
});

test('terminal status frees a never-settled choose; its late rejection cannot poison the next read', async (t) => {
  const h = harness(t); await h.ready;
  const choosing = h.controller.choose(), held = h.last('choose');
  h.registry(status('1', { phase: 'choosing', operation: { operationId: '1', kind: 'choose', selectionId: null } }));
  h.tick(); await flush();
  assert.equal(h.state.pending, 'choose'); assert.notEqual(h.controller.startReason(), null);
  h.registry(selected()); h.tick(); await flush();
  assert.equal(h.state.pending, null); assert.equal(h.controller.startReason(), null); assert.equal(h.timers.size, 0);
  assert.equal(h.count('choose'), 1);
  const reading = h.controller.observe(), beforeLate = h.state;
  assert.equal(h.state.pending, 'observe');
  held.reject(new Error(CANARY)); await choosing;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.error, null); assert.equal(h.state.uncertain, false);
  h.reply('observe', observed()); await reading;
  assert.deepEqual(wire(h.state.status.result), fixtures.androidConsistent);
  assert.equal(h.count('choose'), 1); assert.equal(h.count('observe'), 1);
});

test('terminal status alone frees a lost choose; an old high-revision reply cannot replace a new choice', async (t) => {
  const h = harness(t); await h.ready;
  const first = h.controller.choose(), held = h.last('choose');
  h.registry(selected()); h.tick(); await flush();
  assert.equal(h.state.pending, null); assert.equal(h.controller.startReason(), null);
  const second = h.controller.choose(), beforeLate = h.state;
  held.resolve(selected('100', FIRST, '1')); await first;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.pending, 'choose');
  h.reply('choose', selected('4', SECOND, '2')); await second;
  assert.equal(h.state.status.selection.selectionId, SECOND.selectionId);
  assert.equal(h.state.status.revision, '4'); assert.equal(h.count('choose'), 2); assert.equal(h.count('observe'), 0);
});

test('terminal status frees a never-settled read; its late high-revision result cannot replace the next read', async (t) => {
  const h = harness(t, selected()); await h.ready;
  const first = h.controller.observe(), held = h.last('observe');
  h.registry(observing()); h.tick(); await flush();
  assert.equal(h.state.pending, 'observe'); assert.notEqual(h.controller.startReason(), null);
  h.registry(observed()); h.tick(); await flush();
  assert.equal(h.state.pending, null); assert.equal(h.controller.startReason(), null); assert.equal(h.timers.size, 0);
  assert.deepEqual(wire(h.state.status.result), fixtures.androidConsistent);
  const second = h.controller.observe(), beforeLate = h.state;
  held.resolve(observed('100', '2', FIRST, fixtures.iosConsistent)); await first;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.pending, 'observe');
  h.reply('observe', observed('6', '3')); await second;
  assert.equal(h.state.status.revision, '6'); assert.equal(h.state.status.operation.operationId, '3');
  assert.deepEqual(wire(h.state.status.result), fixtures.androidConsistent);
  assert.equal(h.count('observe'), 2); assert.equal(h.count('choose'), 0);
});

test('terminal status alone frees a lost read; its late rejection cannot mark a new choice uncertain', async (t) => {
  const h = harness(t, selected()); await h.ready;
  const reading = h.controller.observe(), held = h.last('observe');
  h.registry(observed()); h.tick(); await flush();
  assert.equal(h.state.pending, null); assert.equal(h.controller.startReason(), null);
  const choosing = h.controller.choose(), beforeLate = h.state;
  held.reject({ code: 'artifact_evidence_deadline', message: CANARY }); await reading;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.pending, 'choose');
  assert.equal(h.state.uncertain, false); assert.equal(h.state.error, null);
  h.reply('choose', selected('6', SECOND, '3')); await choosing;
  assert.equal(h.state.status.selection.selectionId, SECOND.selectionId);
  assert.deepEqual(wire(h.state.stale), { selection: FIRST, result: fixtures.androidConsistent });
  assert.equal(h.count('observe'), 1); assert.equal(h.count('choose'), 1);
});

test('older revisions lose even above Number precision; equal reordered data is valid but conflict latches', async (t) => {
  const current = observed('9007199254740993'), h = harness(t, current); await h.ready;
  h.registry(observed('9007199254740992', '1', SECOND, fixtures.iosConsistent)); await h.controller.check();
  assert.deepEqual(wire(h.state.status), current); assert.equal(h.state.integrityFailed, false);
  const equal = Object.fromEntries(Object.entries(clone(current)).reverse());
  equal.result.summary = Object.fromEntries(Object.entries(equal.result.summary).reverse());
  equal.operation = Object.fromEntries(Object.entries(equal.operation).reverse());
  h.registry(equal); await h.controller.check();
  assert.deepEqual(wire(h.state.status), current); assert.equal(h.state.integrityFailed, false);
  equal.selection.displayName = SECOND.displayName; h.registry(equal); await h.controller.check();
  assert.equal(h.state.status, null); assert.equal(h.state.integrityFailed, true); assert.equal(h.state.uncertain, true);
  assert.equal(h.state.error.code, 'artifact_evidence_protocol');
  assert.deepEqual(wire(h.state.stale), { selection: FIRST, result: fixtures.androidConsistent });
  const reads = h.count('status');
  await h.controller.check(); await h.controller.choose(); await h.controller.observe(); await h.controller.cancel();
  assert.equal(h.count('status'), reads); assert.equal(h.count('choose'), 0); assert.equal(h.count('observe'), 0);
  assert.equal(h.count('cancel'), 0); assert.notEqual(h.controller.startReason(), null); assert.equal(h.timers.size, 0);
});

test('once status binds the original read, another operation ID with the same selection is a protocol failure', async (t) => {
  const h = harness(t, selected()); await h.ready;
  void h.controller.observe();
  h.registry(observing()); h.tick(); await flush();
  assert.equal(h.state.status.operation.operationId, '2'); assert.equal(h.state.pending, 'observe');
  h.registry(observing('4', '3')); await h.controller.check();
  assert.equal(h.state.status, null); assert.equal(h.state.integrityFailed, true);
  assert.equal(h.state.error.code, 'artifact_evidence_protocol');
  await h.controller.choose(); await h.controller.observe(); await h.controller.cancel();
  assert.equal(h.count('choose'), 0); assert.equal(h.count('observe'), 1); assert.equal(h.count('cancel'), 0);
  assert.notEqual(h.controller.startReason(), null);
});

test('a prior same-selection operation cannot acknowledge a new read, even with a newer revision', async (t) => {
  const h = harness(t, observed()); await h.ready;
  const reading = h.controller.observe();
  h.tick(); await flush();
  assert.equal(h.state.pending, 'observe'); assert.notEqual(h.controller.startReason(), null);
  await h.controller.cancel(); assert.equal(h.count('cancel'), 0);
  h.last('observe').resolve(observed('5', '2')); await reading;
  assert.equal(h.state.status, null); assert.equal(h.state.integrityFailed, true);
  assert.equal(h.state.error.code, 'artifact_evidence_protocol'); assert.equal(h.state.pending, null);
  assert.deepEqual(wire(h.state.stale), { selection: FIRST, result: fixtures.androidConsistent });
  assert.equal(h.count('observe'), 1); assert.equal(h.timers.size, 0);
});

test('status can bind and cancel the exact original chooser with null selection before its invoke settles', async (t) => {
  const h = harness(t); await h.ready;
  const choosing = h.controller.choose(), held = h.last('choose');
  h.registry(status('1', { phase: 'choosing', operation: { operationId: '1', kind: 'choose', selectionId: null } }));
  h.tick(); await flush();
  const stopping = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: '1', selectionId: null });
  h.reply('cancel', status('2', { phase: 'cancelled', operation: { operationId: '1', kind: 'choose', selectionId: null }, problem: 'cancelled' }));
  await stopping;
  assert.equal(h.state.status.phase, 'cancelled'); assert.equal(h.state.status.selection, null);
  assert.equal(h.state.status.result, null); assert.equal(h.state.pending, null); assert.equal(h.state.cancelling, false);
  assert.equal(h.controller.startReason(), null);
  const beforeLate = h.state; held.reject(new Error(CANARY)); await choosing;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.count('choose'), 1); assert.equal(h.count('cancel'), 1);
});

test('cancel rejects a different newer operation even when its selection is unchanged', async (t) => {
  const h = harness(t, observing()); await h.ready;
  const stopping = h.controller.cancel();
  h.reply('cancel', cancelled('4', '3')); await stopping;
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status, null);
  assert.equal(h.state.error.code, 'artifact_evidence_protocol'); assert.equal(h.state.cancelling, false);
  assert.notEqual(h.controller.startReason(), null); assert.equal(h.count('cancel'), 1); assert.equal(h.timers.size, 0);
});

test('cancel rejects a stale earlier operation ID even with the same selection and a newer revision', async (t) => {
  const h = harness(t, observing('5', '3')); await h.ready;
  const stopping = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: '3', selectionId: FIRST.selectionId });
  h.reply('cancel', cancelled('6', '2')); await stopping;
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.status, null);
  assert.equal(h.state.error.code, 'artifact_evidence_protocol'); assert.equal(h.state.cancelling, false);
  assert.notEqual(h.controller.startReason(), null); assert.equal(h.count('cancel'), 1);
});

test('an exact but older cancel reply cannot replace newer active status or claim final cancellation', async (t) => {
  const h = harness(t, observing()); await h.ready;
  const stopping = h.controller.cancel();
  h.registry(observing('4')); await h.controller.check();
  assert.equal(h.state.cancelling, true);
  h.last('cancel').resolve(cancelled('3')); await stopping;
  assert.equal(h.state.status.revision, '4'); assert.equal(h.state.status.phase, 'observing');
  assert.equal(h.state.status.result, null); assert.equal(h.state.cancelling, false);
  assert.equal(h.state.uncertain, false); assert.equal(h.state.integrityFailed, false);
  assert.notEqual(h.controller.startReason(), null); assert.equal(h.count('cancel'), 1);
});

test('terminal status frees a lost cancel; its late rejection/finally cannot clear a newer cancel token', async (t) => {
  const h = harness(t, observing()); await h.ready;
  const first = h.controller.cancel(), held = h.last('cancel');
  assert.equal(h.state.cancelling, true);
  h.registry(cancelled()); h.tick(); await flush();
  assert.equal(h.state.cancelling, false); assert.equal(h.controller.startReason(), null); assert.equal(h.timers.size, 0);
  const reading = h.controller.observe(); h.reply('observe', observing('5', '3')); await reading;
  const second = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: '3', selectionId: FIRST.selectionId });
  const beforeLate = h.state; assert.equal(h.state.cancelling, true);
  held.reject({ code: 'artifact_evidence_deadline', message: CANARY }); await first;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.cancelling, true);
  assert.equal(h.state.uncertain, false); assert.equal(h.state.error, null);
  h.reply('cancel', cancelled('6', '3')); await second;
  assert.equal(h.state.cancelling, false); assert.equal(h.state.status.operation.operationId, '3');
  assert.equal(h.state.status.phase, 'cancelled'); assert.equal(h.controller.startReason(), null);
  assert.equal(h.count('cancel'), 2); assert.equal(h.count('observe'), 1); assert.equal(h.count('choose'), 0);
});

test('STOP status retires a lost cancel latch but not native ownership; its later result cannot replace new work', async (t) => {
  const h = harness(t, observing()); await h.ready;
  const stopping = h.controller.cancel(), held = h.last('cancel');
  h.registry({ ...observing('4'), phase: 'stopping', problem: 'cancelled' }); h.tick(); await flush();
  assert.equal(h.state.cancelling, false); assert.equal(h.state.status.phase, 'stopping');
  assert.notEqual(h.controller.startReason(), null);
  await h.controller.observe(); await h.controller.choose();
  assert.equal(h.count('observe'), 0); assert.equal(h.count('choose'), 0);
  h.registry(cancelled('5')); h.tick(); await flush();
  assert.equal(h.controller.startReason(), null);
  const reading = h.controller.observe(), beforeLate = h.state;
  held.resolve(observed('100', '2', FIRST, fixtures.iosConsistent)); await stopping;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.pending, 'observe');
  h.reply('observe', observed('7', '3')); await reading;
  assert.equal(h.state.status.operation.operationId, '3'); assert.equal(h.state.status.revision, '7');
  assert.deepEqual(wire(h.state.status.result), fixtures.androidConsistent);
  assert.equal(h.count('cancel'), 1); assert.equal(h.count('observe'), 1);
});

test('cleanup Unknown releases only local acknowledgment latches, never new work or late success', async (t) => {
  const h = harness(t, selected()); await h.ready;
  const reading = h.controller.observe(), held = h.last('observe');
  h.registry(unknown()); h.tick(); await flush();
  assert.equal(h.state.status.phase, 'unknown'); assert.equal(h.state.pending, null); assert.equal(h.timers.size, 0);
  assert.match(h.controller.startReason(), /cleanup/i);
  await h.controller.choose(); await h.controller.observe();
  assert.equal(h.count('choose'), 0); assert.equal(h.count('observe'), 1);
  const stopping = h.controller.cancel();
  assert.deepEqual(h.last('cancel').args, { operationId: '2', selectionId: FIRST.selectionId });
  h.reply('cancel', unknown('5')); await stopping;
  const beforeLate = h.state; held.resolve(observed('100')); await reading;
  assert.strictEqual(h.state, beforeLate); assert.equal(h.state.status.phase, 'unknown');
  assert.equal(h.state.cancelling, false); assert.notEqual(h.controller.startReason(), null);
  h.registry(observed('6')); await h.controller.check();
  assert.equal(h.state.status.phase, 'unknown'); assert.equal(h.state.status.result, null);
  assert.equal(h.state.integrityFailed, true); assert.equal(h.state.uncertain, true);
  assert.equal(h.state.error.code, 'artifact_evidence_protocol'); assert.equal(h.timers.size, 0);
});

test('detach/reconnect preserves historical evidence but ignores old-generation status and picker replies', async (t) => {
  const h = harness(t, observed()); await h.ready;
  const choosing = h.controller.choose(), held = h.last('choose');
  const delayed = h.deferRead(), checking = h.controller.check();
  h.controller.beginConnection();
  assert.equal(h.state.mode, 'unavailable'); assert.equal(h.state.status, null);
  assert.equal(h.state.pending, null); assert.equal(h.state.checking, false); assert.equal(h.timers.size, 0);
  assert.deepEqual(wire(h.state.stale), { selection: FIRST, result: fixtures.androidConsistent });
  h.registry(selected('8', SECOND, '5')); await h.controller.connect(h.api);
  const connected = h.state;
  assert.equal(connected.status.selection.selectionId, SECOND.selectionId);
  assert.deepEqual(wire(connected.stale), { selection: FIRST, result: fixtures.androidConsistent });
  delayed.resolve(observed('100', '98')); held.resolve(selected('101', FIRST, '99'));
  await Promise.all([checking, choosing]);
  assert.strictEqual(h.state, connected); assert.equal(h.count('choose'), 1); assert.equal(h.count('observe'), 0);
  const reading = h.controller.observe();
  assert.deepEqual(h.last('observe').args, { selectionId: SECOND.selectionId });
  h.reply('observe', observed('10', '6', SECOND, fixtures.iosConsistent)); await reading;
  assert.equal(h.state.status.selection.selectionId, SECOND.selectionId);
  assert.deepEqual(wire(h.state.status.result), fixtures.iosConsistent); assert.equal(h.state.stale, null);
  assert.equal(h.count('cancel'), 0); assert.equal(h.count('choose'), 1); assert.equal(h.count('observe'), 1);
});

test('reconnect revokes an old cancellation token so its reply cannot clear cancellation of another selection', async (t) => {
  const h = harness(t, observing()); await h.ready;
  const first = h.controller.cancel(), held = h.last('cancel');
  h.controller.beginConnection();
  assert.equal(h.state.cancelling, false); assert.equal(h.timers.size, 0);
  h.registry(observing('8', '5', SECOND)); await h.controller.connect(h.api);
  const second = h.controller.cancel(), connected = h.state;
  assert.deepEqual(h.last('cancel').args, { operationId: '5', selectionId: SECOND.selectionId });
  held.resolve(cancelled('100')); await first;
  assert.strictEqual(h.state, connected); assert.equal(h.state.cancelling, true);
  h.reply('cancel', cancelled('9', '5', SECOND)); await second;
  assert.equal(h.state.status.selection.selectionId, SECOND.selectionId);
  assert.equal(h.state.status.operation.operationId, '5'); assert.equal(h.state.cancelling, false);
  assert.equal(h.count('cancel'), 2);
});

test('dispose revokes pending read/status/cancel work, listeners and timers without replay or automatic stop', async (t) => {
  const h = harness(t, selected()); await h.ready;
  let updates = 0; const unsubscribe = h.controller.subscribe(() => { updates += 1; });
  const reading = h.controller.observe(), heldRead = h.last('observe');
  h.registry(observing()); h.tick(); await flush();
  const stopping = h.controller.cancel(), heldCancel = h.last('cancel');
  const delayed = h.deferRead(), checking = h.controller.check();
  h.controller.dispose();
  const disposed = h.state, count = updates, calls = h.calls.length;
  assert.equal(h.timers.size, 0);
  heldRead.resolve(observed('100')); heldCancel.reject(new Error(CANARY)); delayed.resolve(observed('101'));
  await Promise.all([reading, stopping, checking]); await flush();
  await h.controller.connect(h.api); await h.controller.choose(); await h.controller.observe();
  await h.controller.check(); await h.controller.cancel();
  assert.strictEqual(h.state, disposed); assert.equal(updates, count); assert.equal(h.calls.length, calls);
  assert.equal(h.count('cancel'), 1); assert.equal(h.count('observe'), 1); assert.equal(h.count('choose'), 0);
  assert.equal(h.timers.size, 0); unsubscribe();
});

test('preview controller cannot poll, choose, inspect or fabricate an otherwise well-shaped result', async (t) => {
  const h = harness(t, observed(), 'preview'); await h.ready;
  assert.equal(h.state.mode, 'preview'); assert.equal(h.state.status, null);
  assert.equal(h.state.error.code, 'artifact_evidence_unavailable'); assert.notEqual(h.controller.startReason(), null);
  await h.controller.check(); await h.controller.choose(); await h.controller.observe(); await h.controller.cancel();
  assert.deepEqual(h.calls, []); assert.equal(h.timers.size, 0);
});

test('native unavailable status never enables folder/read/cancel work or a fabricated observation', async (t) => {
  const h = harness(t, status('0', { availability: 'unavailable', problem: 'unavailable' })); await h.ready;
  assert.equal(h.state.status.availability, 'unavailable'); assert.equal(h.state.status.result, null);
  assert.notEqual(h.controller.startReason(), null);
  await h.controller.choose(); await h.controller.observe(); await h.controller.cancel();
  assert.equal(h.count('status'), 1); assert.equal(h.count('choose'), 0); assert.equal(h.count('observe'), 0);
  assert.equal(h.count('cancel'), 0); assert.equal(h.timers.size, 0);
});

test('evidence help is complete optional guidance about documents, not provenance or release/recovery authority', () => {
  assert.equal(EVIDENCE_ASSURANCE, 'Local document consistency; provenance and artifact bytes unverified.');
  assert.deepEqual(Object.keys(evidenceHelp), ['folder', 'summary', 'artifacts', 'runs', 'digests']);
  for (const help of Object.values(evidenceHelp)) {
    assert.deepEqual(Object.keys(help), ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure']);
    for (const value of Object.values(help)) assert.equal(typeof value === 'string' && value.trim().length > 0, true);
    assert.equal(help.requiredness, 'optional'); assert.match(help.requiredWhen, /not required for editing a project draft/);
  }
  assert.match(evidenceHelp.folder.format, /candidate-manifest\.json, candidate-receipt\.json and operation\/candidate-operation-intent\.json/);
  assert.match(evidenceHelp.folder.format, /at most 2 MiB each.*stay in place.*read only/);
  assert.match(evidenceHelp.folder.failure, /separate from your source project.*never saves or discards a draft/);
  assert.match(evidenceHelp.summary.failure, /self-consistent forged.*Do not.*authorize a release/);
  assert.match(evidenceHelp.artifacts.format, /never opens or hashes artifact payloads/);
  assert.match(evidenceHelp.artifacts.failure, /do not establish.*exists.*signed correctly.*matches those bytes/);
  assert.match(evidenceHelp.runs.what, /authorizing, executing and producing/);
  assert.match(evidenceHelp.runs.where, /authenticated GitHub.*not performed/);
  assert.match(evidenceHelp.runs.format, /Exact decimal text.*not clickable/);
  assert.match(evidenceHelp.runs.failure, /No GitHub or Store status is inferred/);
  assert.match(evidenceHelp.digests.format, /integrity field excluded, not the SHA-256 of the raw JSON file/);
  assert.match(evidenceHelp.digests.failure, /does not authenticate.*forged set can still be locally consistent/);
});

test('v1 facade stays strict while the App shares the lifecycle controller instead of a second polling owner', () => {
  const source = readFileSync(new URL('../src/candidateEvidence.ts', import.meta.url), 'utf8');
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  assert.match(source, /class CandidateEvidenceController extends EvidenceController<EvidenceStatus>/);
  assert.match(source, /super\(otherOperationReason, 'candidate', parseEvidenceStatus\)/);
  assert.doesNotMatch(app, /new CandidateEvidenceController/);
  assert.deepEqual([...app.matchAll(/new LifecycleEvidenceController\(([^)]*)\)/g)].map((m) => m[1]), ['savedCommandBusy']);
  assert.match(app, /releaseEvidence\.beginConnection\(\)/);
  assert.match(app, /releaseEvidence\.connect\(connection\)/);
  assert.match(app, /releaseEvidence\.dispose\(\)/);
});
