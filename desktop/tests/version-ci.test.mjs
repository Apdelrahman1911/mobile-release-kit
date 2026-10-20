// Public display/intent DATA only. No DOM, Clipboard, native or GitHub call.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createVersionReservePort, parseReservedVersion, parseVersionCiReference, parseVersionReserveStatus } from '../src/versionReserve.ts';

const candidate = '12345678-1234-4234-9234-123456789abc', id = 'a'.repeat(32);
const settings = JSON.stringify({ schemaVersion: 1, authority: { projectId: '1'.repeat(32), repository: 'fixture/ci',
  repositoryId: '27', ledgerId: '33333333-3333-4333-8333-333333333333', genesisSha256: 'b'.repeat(64), protectedBranch: true },
  checkpoint: { sequence: 1, headSha256: 'c'.repeat(64), commit: 'd'.repeat(40) } });
const ci = { authoritySettings: settings, commitTrailer: `MRK-Version-Reservation: ${candidate} ${'c'.repeat(64)}` };
const reservation = { id, candidateId: candidate, name: '1.2.3', build: 8, ci };
const status = { schemaVersion: 1, revision: 3, projectId: 'project-1', operationId: id, phase: 'reserved', reason: 'none', review: null, reservation };

test('completed reservation keeps exact bounded nonsecret copy DATA and legacy status cannot manufacture it', () => {
  const parsed = parseVersionReserveStatus(status);
  assert.deepEqual(parsed?.reservation, reservation);
  assert.ok(Object.isFrozen(parsed.reservation.ci));
  assert.equal(parsed.reservation.ci.authoritySettings, settings); // No rewrite of protected settings.
  const { ci: unused, ...legacy } = reservation;
  assert.deepEqual(parseReservedVersion(legacy), legacy);
  assert.equal(parseReservedVersion(legacy).ci, undefined);
});
test('copy DATA rejects another candidate, controls, overlong input and unknown fields before display', () => {
  for (const invalid of [ { ...ci, commitTrailer: ci.commitTrailer.replace(candidate, '22345678-1234-4234-9234-123456789abc') },
    { ...ci, commitTrailer: ci.commitTrailer + '\n' }, { ...ci, authoritySettings: '\n' + settings },
    { ...ci, authoritySettings: 'x'.repeat(769) }, { ...ci, token: 'inert-not-a-credential' }, null ]) {
    assert.equal(parseVersionCiReference(invalid, candidate), null);
    assert.equal(parseReservedVersion({ ...reservation, ci: invalid }), null);
  }
  assert.equal(parseVersionCiReference(ci, 'x'.repeat(10000)), null);
  let called = 0;
  const withGetter = { ...ci };
  Object.defineProperty(withGetter, 'authoritySettings', { enumerable: true, get() { called++; return settings; } });
  assert.equal(parseReservedVersion({ ...reservation, ci: withGetter }), null);
  assert.equal(called, 0);
});
test('pending unknown or refused status cannot publish prepared CI data as a completed reservation', () => {
  for (const [phase, reason] of [['reading', 'none'], ['reserving', 'none'], ['refused', 'reservation-refused'], ['cleanup-unknown', 'cleanup-unknown']]) {
    assert.equal(parseVersionReserveStatus({ ...status, phase, reason }), null);
  }
  assert.equal(parseVersionReserveStatus({ ...status, reservation: { ...reservation, nativeFinality: true } }), null);
});
test('reading/copying data has no side effect and CI settings cannot be supplied as reserve consent', async () => {
  const calls = [];
  const port = createVersionReservePort(async (...args) => { calls.push(args); return status; });
  assert.ok(parseReservedVersion(reservation));
  assert.equal(calls.length, 0);
  const options = { reference: 'refs/heads/main', increment: 'build', newCandidate: false, acknowledgeLimitations: true };
  await assert.rejects(port.review('project-1', { ...options, ci }));
  assert.equal(calls.length, 0);
  await port.status();
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'version_reserve_status');
  assert.equal(new TextDecoder().decode(calls[0][1]), '{}');
});
