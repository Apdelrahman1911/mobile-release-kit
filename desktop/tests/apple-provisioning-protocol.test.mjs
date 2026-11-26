// Closed DATA/fake invoke tests only. No App Store, credential, filesystem,
// native bootstrap, journal mutation or native-finality qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { appleDisplayName, appleProvisioningConsent, appleProvisioningContext, APPLE_PROVISIONING_EVENT,
  APPLE_PROVISIONING_LIMITATIONS, encodeAppleProvisioningRequest, parseAppleProvisioningRequest,
  parseAppleProvisioningStatus, appleProvisioningProgress } from '../src/appleProvisioningProtocol.ts';
import { createAppleProvisioningApi } from '../src/appleProvisioningNative.ts';

const OP = 'a'.repeat(32), OWNER = 'b'.repeat(32), RECORD = 'c'.repeat(32);
const copy = value => structuredClone(value);
const reference = () => ({ operationId: OP, ownerGeneration: OWNER });
const request = (mode = 'review') => ({ projectId: 'fixture', draftRevision: 2, baselineGeneration: 3,
  savedConfig: { bytes: 120, sha256: 'd'.repeat(64) },
  savedVersion: { source: 'release/version.properties', bytes: 30, sha256: 'e'.repeat(64), name: '1.2.3', build: 4 },
  credentialContextRevision: 5, recordId: RECORD, recordRevision: 6, executionMode: 'local', platform: 'ios', mode,
  reference: mode === 'review' ? null : reference(), newApplication: mode === 'register', displayName: 'Explicit 🍎 name' });
const operation = (mode = 'review') => ({ ...reference(), context: appleProvisioningContext(request(mode)), phase: 'awaiting-consent',
  intentUsable: true, outcome: null, reason: 'none', result: null, recovery: null });
const result = (mode = 'review') => ({ schemaVersion: 1, scope: 'local-ios-bundle-provisioning', mode,
  observation: 'not-returned', decision: mode === 'reconcile' ? 'comparison-only' : 'review-required', attempt: null,
  comparison: mode === 'reconcile' ? 'not-returned' : null, limitations: [...APPLE_PROVISIONING_LIMITATIONS] });
const status = (op = null, revision = 1) => ({ schemaVersion: 1, statusRevision: revision, availability: 'available', operation: op });
const complete = (mode = 'review') => ({ ...operation(mode), phase: 'terminal', intentUsable: false, outcome: 'complete', result: result(mode) });

test('closed mode/context grammar refuses Access flags, paths, secrets and missing reference/null', () => {
  for (const mode of ['review', 'register', 'reconcile']) {
    assert.ok(parseAppleProvisioningRequest(request(mode)));
    assert.ok(encodeAppleProvisioningRequest('start_apple_provisioning', { ...reference(), consentVersion: appleProvisioningConsent(mode) }));
  }
  for (const patch of [{ platform: 'android' }, { executionMode: 'github' }, { query: 'bundle-id-registration' },
    { operation: 'apple-bundle-provisioning' }, { accountRef: 'f'.repeat(64) }, { issuerId: 'inert' }, { keyPath: '/not-opened' },
    { mode: 'create-profile' }, { newApplication: true }, { reference: reference() }, { recordRevision: 0 }, { draftRevision: 0xffffffff }]) {
    assert.equal(parseAppleProvisioningRequest({ ...request(), ...patch }), null);
  }
  const missing = request(); delete missing.reference; assert.equal(parseAppleProvisioningRequest(missing), null);
  assert.equal(parseAppleProvisioningRequest({ ...request('register'), newApplication: false }), null);
  assert.equal(encodeAppleProvisioningRequest('start_apple_provisioning', { ...reference(), consentVersion: 'local-ios-bundle-id-read-v1' }), null);
  assert.equal(encodeAppleProvisioningRequest('apple_provisioning_status', { operationId: OP }), null);
  assert.equal(encodeAppleProvisioningRequest('cancel_apple_provisioning', { ...reference(), retry: true }), null);
  assert.equal(encodeAppleProvisioningRequest('exec', request()), null);
});

test('project IDs match the native ASCII 1..64 grammar in both requests and status', () => {
  for (const projectId of ['_', '-', '_fixture', '-fixture', 'A0_-', 'x'.repeat(64)]) {
    assert.equal(parseAppleProvisioningRequest({ ...request(), projectId })?.projectId, projectId);
    const op = operation(); op.context.projectId = projectId;
    assert.equal(parseAppleProvisioningStatus(status(op))?.operation.context.projectId, projectId);
  }
  for (const projectId of ['', 'x:y', 'x.y', 'x'.repeat(65), 'x'.repeat(128), 'é', 'x\n', ' x']) {
    assert.equal(parseAppleProvisioningRequest({ ...request(), projectId }), null);
    const op = operation(); op.context.projectId = projectId;
    assert.equal(parseAppleProvisioningStatus(status(op)), null);
  }
});

test('name matches native Unicode scalar limits without normalization or implicit truncation', () => {
  assert.equal(appleDisplayName('🍎'.repeat(128)), true);
  for (const name of ['', 'x'.repeat(129), 'name\nnext', '\u007f', '\ud800']) assert.equal(appleDisplayName(name), false);
  const value = request(); value.displayName = ' e\u0301 '; const parsed = parseAppleProvisioningRequest(value);
  assert.equal(parsed.displayName, value.displayName);
});

test('bounded comparison copy refuses getters, cycles, oversized and non-plain request data', () => {
  let reads = 0; const getter = request(); Object.defineProperty(getter, 'displayName', { enumerable: true, get() { reads++; return 'not read'; } });
  assert.equal(parseAppleProvisioningRequest(getter), null); assert.equal(reads, 0);
  const cycle = request(); cycle.reference = cycle; assert.equal(parseAppleProvisioningRequest(cycle), null);
  assert.equal(parseAppleProvisioningRequest({ ...request(), displayName: 'x'.repeat(9000) }), null);
  assert.equal(parseAppleProvisioningRequest(Object.create(request())), null);
});

test('public result remains exact bundle-only DATA; raw provider/journal or readiness upgrades refuse', () => {
  for (const mode of ['review', 'register', 'reconcile']) assert.ok(parseAppleProvisioningStatus(status(complete(mode))));
  for (const patch of [{ phase: 'running' }, { reason: 'context-changed' }, { outcome: 'failed' }, { intentUsable: true }]) {
    assert.equal(parseAppleProvisioningStatus(status({ ...complete(), ...patch })), null);
  }
  for (const patch of [{ scope: 'local-ios-bundle-id-registration-read' }, { mode: 'register' }, { certificateReady: true },
    { limitations: [...APPLE_PROVISIONING_LIMITATIONS, 'ready-to-sign'] }, { comparison: 'same-response' },
    { observation: 'not-permitted', decision: 'review-required' }, { decision: 'registration-confirmed' }]) {
    const op = complete(); Object.assign(op.result, patch); assert.equal(parseAppleProvisioningStatus(status(op)), null);
  }
  const registration = complete('register'); registration.result = { ...result('register'), observation: 'found', decision: 'registration-confirmed',
    attempt: { operationId: OP, action: 'register_bundle_id', status: 'succeeded', reason: 'provider_resource_confirmed',
      retryAllowed: false, credentialReady: false, cancellationRequested: false } };
  assert.ok(parseAppleProvisioningStatus(status(registration)));
  for (const patch of [{ retryAllowed: true }, { credentialReady: true }, { operationId: RECORD }, { action: 'issue_certificate' }, { status: 'running' }]) {
    const op = copy(registration); Object.assign(op.result.attempt, patch); assert.equal(parseAppleProvisioningStatus(status(op)), null);
  }
});

test('unknown and terminal phase transitions cannot be downgraded or rebound', () => {
  const a = operation(), b = { ...copy(a), phase: 'running', intentUsable: false };
  assert.equal(appleProvisioningProgress(a, b), true); assert.equal(appleProvisioningProgress(b, a), false);
  const unknown = { ...b, phase: 'unknown', outcome: 'unknown', reason: 'cleanup-unknown' };
  assert.ok(parseAppleProvisioningStatus(status(unknown)));
  assert.equal(appleProvisioningProgress(unknown, complete()), false);
  assert.equal(appleProvisioningProgress(complete(), { ...complete(), reason: 'cancelled' }), false);
  const altered = copy(b); altered.context.displayName = 'different'; assert.equal(appleProvisioningProgress(b, altered), false);
});

test('actual native adapter has only four bounded RAW commands and one existing event; preview unavailable', async () => {
  const calls = []; let receiver; const invoke = async (name, bytes) => { calls.push([name, bytes]); return status(); };
  const listen = async (name, callback) => { assert.equal(name, APPLE_PROVISIONING_EVENT); receiver = callback; return () => { receiver = null; }; };
  assert.equal(createAppleProvisioningApi('preview', invoke, listen), null);
  assert.equal(createAppleProvisioningApi('native', invoke), null);
  const api = createAppleProvisioningApi('native', invoke, listen); const seen = [];
  const off = await api.subscribe(value => seen.push(value)); receiver(status());
  await api.prepare(request()); await api.start({ ...reference(), consentVersion: appleProvisioningConsent('review') });
  await api.status(); await api.cancel(reference());
  assert.deepEqual(calls.map(([name]) => name), ['prepare_apple_provisioning', 'start_apple_provisioning', 'apple_provisioning_status', 'cancel_apple_provisioning']);
  for (const [, bytes] of calls) { assert.ok(bytes instanceof Uint8Array); assert.ok(bytes.length <= 8192); }
  assert.deepEqual(JSON.parse(new TextDecoder().decode(calls[0][1])), request());
  assert.throws(() => api.prepare({ ...request(), key: 'not-a-real-key' })); assert.equal(calls.length, 4);
  off(); assert.equal(receiver, null); assert.equal(seen.length, 1);
});
