// Closed local-key comparison DATA. None of these values is a private-key
// loan, native review, save permission, certificate consent or signing proof.
import { copyBoundedComparisonData, parseSavedConfigContent, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseAndroidBuildSavedVersion } from './androidBuildProtocol.ts';
import { assetStorageWritable } from './assetSessionProtocol.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { LocalStoreProject } from './localStorePreflight.ts';
import type { PrepareAppleProvisioning } from './appleProvisioningTypes.ts';
import type { OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

export const APPLE_DISTRIBUTION_KEY_MODES = Object.freeze(['key-review', 'key-prepare', 'key-recover'] as const);
export type AppleDistributionKeyMode = typeof APPLE_DISTRIBUTION_KEY_MODES[number];
export type AppleDistributionKeyDecision = 'prepare-review' | 'recover-existing-key' | 'reuse-existing-identity' | 'bundle-required' | 'blocked' | 'produced' | 'compared';
export type AppleDistributionKeyReason = 'local-key-required' | 'existing-key' | 'existing-certificate' | 'bundle-registration-required' | 'account-pending' | 'inventory-unavailable' | 'producer-returned' | 'stored-key-checked';
export interface AppleDistributionKeyResult {
  schemaVersion: 1; scope: 'local-ios-distribution-key'; mode: AppleDistributionKeyMode;
  decision: AppleDistributionKeyDecision; reason: AppleDistributionKeyReason;
  saved: false; certificateRequested: false; credentialReady: false;
}
export interface AppleDistributionKeySavedReference {
  vaultId: string; generationId: string; recordId: string; revisionId: string; revisionCounter: number;
}
export const isAppleDistributionKeyMode = (mode: unknown): mode is AppleDistributionKeyMode =>
  mode === 'key-review' || mode === 'key-prepare' || mode === 'key-recover';
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => !!value &&
  typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const id = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) && value !== '0'.repeat(32);
const revision = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0 && (value as number) < 0xffffffff;

export function parseAppleDistributionKeyResult(value: unknown, mode: unknown): AppleDistributionKeyResult | null {
  try {
    const v = copyBoundedComparisonData(value, 2048);
    if (!isAppleDistributionKeyMode(mode) || !keys(v, ['schemaVersion', 'scope', 'mode', 'decision', 'reason', 'saved', 'certificateRequested', 'credentialReady']) ||
        v.schemaVersion !== 1 || v.scope !== 'local-ios-distribution-key' || v.mode !== mode ||
        v.saved !== false || v.certificateRequested !== false || v.credentialReady !== false) return null;
    const valid = mode === 'key-recover' ? v.decision === 'compared' && v.reason === 'stored-key-checked' :
      mode === 'key-prepare' ? v.decision === 'produced' && v.reason === 'producer-returned' :
      v.decision === 'prepare-review' && v.reason === 'local-key-required' ||
      v.decision === 'recover-existing-key' && (v.reason === 'existing-key' || v.reason === 'existing-certificate') ||
      v.decision === 'reuse-existing-identity' && v.reason === 'existing-certificate' ||
      v.decision === 'bundle-required' && v.reason === 'bundle-registration-required' ||
      v.decision === 'blocked' && (v.reason === 'account-pending' || v.reason === 'inventory-unavailable');
    return valid ? v as unknown as AppleDistributionKeyResult : null;
  } catch { return null; }
}
export function parseAppleDistributionKeySavedReference(value: unknown): AppleDistributionKeySavedReference | null {
  try {
    const v = copyBoundedComparisonData(value, 1024);
    if (!keys(v, ['vaultId', 'generationId', 'recordId', 'revisionId', 'revisionCounter']) || v.revisionCounter !== 1) return null;
    const ids = [v.vaultId, v.generationId, v.recordId, v.revisionId];
    return ids.every(id) && new Set(ids).size === 4 ? v as unknown as AppleDistributionKeySavedReference : null;
  } catch { return null; }
}

export type AppleDistributionKeyInputBase = Omit<PrepareAppleProvisioning,
  'mode' | 'reference' | 'newApplication' | 'displayName' | 'p12RecordId' | 'p12RecordRevision' | 'keyRecordId' | 'keyRecordRevision'>;
function selectedBase(project: LocalStoreProject | null, assets: AssetDisplayState | null, retained: false | 'prepare-apple-distribution-key' | 'use-apple-distribution-key' | 'assemble-apple-p12'): AppleDistributionKeyInputBase | null {
  const s = assets?.status, c = s?.context;
  if (!project || project.inputIssue || project.dirtyDraft || project.snapshotPending || project.versionPending || project.saveRecoveryRequired ||
      !parseSavedConfigContent(project.savedConfig) || !parseAndroidBuildSavedVersion(project.savedVersion) ||
      !Number.isSafeInteger(project.draftRevision) || project.draftRevision < 0 || project.draftRevision >= 0xffffffff ||
      !Number.isSafeInteger(project.baselineGeneration) || project.baselineGeneration < 0 || project.baselineGeneration >= 0xffffffff ||
      !assets || assets.mode !== 'native' || assets.blocked || assets.observationFailed || assets.updatingContext || assets.originPending ||
      !s || s.mode !== 'encrypted' || !c || c.projectId !== project.projectId || !revision(c.revision) ||
      c.executionMode !== 'local' || c.platform !== 'ios' || c.stage !== 'candidate' || c.purpose !== 'provisioning' ||
      assets.scope.executionMode !== 'local' || assets.scope.platform !== 'ios' || assets.scope.stage !== 'candidate' || assets.scope.purpose !== 'provisioning') return null;
  if (retained) {
    // Correlate only the already-started original while its own vault slot
    // temporarily hides assignment availability. This never admits a command.
    if (s.operation?.operation !== retained || s.operation.phase === 'unknown' ||
        ['unknown', 'late-known'].includes(s.operation.settlement) ||
        !s.persistence || !['unlocked', 'mutating'].includes(s.persistence.state)) return null;
  } else if (assets.busy || !assets.contextCurrent || !assetStorageWritable(s) ||
      s.operation && (s.operation.phase !== 'idle' || s.operation.settlement !== 'known')) return null;
  const rows = s.assignments.filter(row => row.kind === 'asc-p8' && row.contextRevision === c.revision && (retained || row.availability === 'available'));
  if (rows.length !== 1) return null;
  const p8 = rows[0]!;
  if (!id(p8.recordId) || !revision(p8.recordRevision) || !s.records.some(record => record.kind === 'asc-p8' &&
      record.recordId === p8.recordId && record.revision === p8.recordRevision && record.storage === 'encrypted' &&
      (retained ? record.availability !== 'mutation-pending' : record.availability === 'assigned'))) return null;
  // Deliberately do not copy P12 fields, vault counts or record-list absence.
  // The native same-Store inventory and Apple read alone decide reuse/prepare.
  return { projectId: project.projectId, draftRevision: project.draftRevision, baselineGeneration: project.baselineGeneration,
    savedConfig: project.savedConfig!, savedVersion: project.savedVersion!, credentialContextRevision: c.revision,
    recordId: p8.recordId, recordRevision: p8.recordRevision, executionMode: 'local', platform: 'ios' };
}
export const appleDistributionKeyInputBase = (project: LocalStoreProject | null, assets: AssetDisplayState | null): AppleDistributionKeyInputBase | null => selectedBase(project, assets, false);
export function retainedAppleDistributionKeyInput(project: LocalStoreProject | null, assets: AssetDisplayState | null, original: unknown): AppleDistributionKeyInputBase | null {
  const current = selectedBase(project, assets, 'prepare-apple-distribution-key');
  return current && sameOfflineData(current, original) ? current : null;
}

// Only the already-started certificate attempt may use this correlation path.
// It is never passed to Prepare/Start admission.
export function retainedAppleDistributionCertificateKeyInput(project: LocalStoreProject | null, assets: AssetDisplayState | null, original: unknown): AppleDistributionKeyInputBase | null {
  const current = selectedBase(project, assets, 'use-apple-distribution-key');
  return current && sameOfflineData(current, original) ? current : null;
}

// Correlate the already-started P12 original by its ACTUAL operation name.
// No status relabeling, input adoption or new Prepare admission is allowed.
export function retainedAppleP12KeyInput(project: LocalStoreProject | null, assets: AssetDisplayState | null,
  original: unknown, operation: 'use-apple-distribution-key' | 'assemble-apple-p12'): AppleDistributionKeyInputBase | null {
  const current = selectedBase(project, assets, operation);
  return current && sameOfflineData(current, original) ? current : null;
}

export function appleDistributionKeyResultCopy(result: AppleDistributionKeyResult | null, saved: AppleDistributionKeySavedReference | null,
  outcome: OfflinePreflightOutcome | null): { title: string; detail: string } | null {
  if (saved) return outcome === 'complete' ? {
    title: 'Local signing key saved',
    detail: 'A new encrypted key was saved and read back. It is not an Apple certificate, P12 or signing assignment. Keep it and save an independent encrypted backup with its recovery code stored separately.',
  } : {
    title: 'Setup stopped; the key was saved',
    detail: 'The operation did not complete normally. Its generated key was preserved in encrypted storage, not deleted. Keep this key and the original result; do not generate a replacement. No certificate or signing assignment is confirmed.',
  };
  if (result?.mode === 'key-recover' && result.decision === 'compared') return {
    title: 'Saved key checked against its original record',
    detail: 'The same encrypted key and certificate request matched the original durable-save record. Earlier setup history is preserved. Review certificate setup separately; no certificate was requested, P12 saved, signing assignment made or backup repaired.',
  };
  if (result?.decision === 'prepare-review') return {
    title: 'Review creating a local signing key',
    detail: 'This completed check allows a separate local-key preparation review. Nothing has been generated. Confirm the separate create-and-save step below only if you need this key.',
  };
  if (result?.decision === 'recover-existing-key') return {
    title: 'Keep the existing key',
    detail: 'An existing key or certificate needs review. Open saved credentials and keep any earlier setup information; do not create a replacement. Recovery and certificate association are separate steps, not performed here.',
  };
  if (result?.decision === 'reuse-existing-identity') return {
    title: 'Use your existing signing identity',
    detail: 'Apple returned an existing distribution certificate. Choose its matching P12 and password in signing setup instead of creating another key. A certificate response alone does not prove you have its private key.',
  };
  if (result?.decision === 'bundle-required') return {
    title: 'Complete Bundle ID setup first', detail: 'Review or register the saved Bundle ID above before checking local-key setup again. No key was authorized by this result.',
  };
  if (result?.decision === 'produced') return {
    title: 'Key output returned; saved copy not confirmed',
    detail: 'Do not generate another key. Keep this original operation and its recovery information until the encrypted save is confirmed. Returned output is not a saved key, certificate or signing approval.',
  };
  if (result?.decision === 'blocked') return result.reason === 'account-pending' ? {
    title: 'Finish the earlier Apple setup', detail: 'An earlier operation for this account is unresolved. Keep it and use its status or recovery controls; do not create another key to bypass it.',
  } : {
    title: 'Existing signing setup could not be checked', detail: 'Check the selected account, Apple permissions and agreements. An unavailable or incomplete read is not proof that a key is missing.',
  };
  if (outcome && outcome !== 'complete' && outcome !== 'unknown') return {
    title: 'Setup stopped; no saved key is confirmed', detail: 'This result does not prove that no key was generated. Keep the original operation and any recovery information; do not repeat generation or replace an existing key.',
  };
  return null;
}
