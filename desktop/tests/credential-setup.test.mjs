// Bounded presentation/controller DATA only; no native credential operations.
import assert from 'node:assert/strict';
import test from 'node:test';
import { parseCredentialSetupStatus, credentialSetupGuidance, credentialSetupReview,
  formatCredentialSetupCli, credentialBackupHelp } from '../src/credentialSetup.ts';

function status(plan = 'assessment-needed') {
  return { schemaVersion: 1, projectId: '1'.repeat(32), observationRevision: 7,
    role: 'android-upload', plan };
}

test('strict safe projection has no material, recovery code, path or secret slot', () => {
  const original = status(); const parsed = parseCredentialSetupStatus(original);
  assert.deepEqual(parsed, original);
  original.plan = 'reuse-ready'; assert.equal(parsed.plan, 'assessment-needed');
  for (const key of ['key', 'privateKey', 'password', 'recoveryCode', 'path', 'record']) {
    assert.equal(parseCredentialSetupStatus({ ...status(), [key]: 'synthetic-canary' }), null);
  }
  for (const delta of [{ projectId: 'project-1' }, { projectId: '0'.repeat(32) },
    { observationRevision: 0 }, { observationRevision: 2 ** 32 }, { observationRevision: 1.5 },
    { role: 'asc-p8' }, { plan: 'generated' }, { schemaVersion: 2 }]) {
    assert.equal(parseCredentialSetupStatus({ ...status(), ...delta }), null);
  }
});

test('saved preferences are not ready until current native assessment and Bind', () => {
  for (const plan of ['assessment-needed', 'select-existing', 'existing-key-required', 'conflict',
    'confirm-application-history', 'offer-generation', 'recovery-required', 'unlock-storage', 'unavailable']) {
    assert.equal(credentialSetupGuidance(status(plan)).ready, false, plan);
  }
  assert.equal(credentialSetupGuidance(status('reuse-ready')).ready, true);
  assert.equal(credentialSetupGuidance(status('reuse-ready')).action, null);
});

test('generation is a separate explicit review, never resume or key creation', () => {
  const value = status('offer-generation');
  const request = credentialSetupReview(value, value.projectId, 7);
  assert.deepEqual(request, { projectId: value.projectId, expectedObservationRevision: 7,
    role: 'android-upload', action: 'review-generation' });
  assert.equal(credentialSetupReview(value, '2'.repeat(32), 7), null);
  assert.equal(credentialSetupReview(value, value.projectId, 8), null);
  assert.equal(credentialSetupReview(status('reuse-ready'), value.projectId, 7), null);
});

test('interrupted and existing-app cases never offer another key', () => {
  assert.equal(credentialSetupGuidance(status('recovery-required')).action, 'recover');
  assert.equal(credentialSetupGuidance(status('existing-key-required')).action, 'open-credentials');
  assert.match(credentialSetupGuidance(status('recovery-required')).detail, /Do not create another key/u);
  assert.match(credentialSetupGuidance(status('existing-key-required')).detail, /original key/u);
});

test('CLI and UI share concise beginner guidance without technical identifiers', () => {
  for (const plan of ['assessment-needed', 'existing-key-required', 'recovery-required', 'reuse-ready']) {
    const text = formatCredentialSetupCli(status(plan));
    assert.ok(text.includes(credentialSetupGuidance(status(plan)).title));
    assert.equal(text.includes(status().projectId), false);
    assert.equal(/revision|vaultId|recordId/u.test(text), false);
  }
  assert.match(credentialBackupHelp, /separately/u);
  assert.match(credentialBackupHelp, /not an account password/u);
  assert.match(credentialBackupHelp, /checked and assigned/u);
});
