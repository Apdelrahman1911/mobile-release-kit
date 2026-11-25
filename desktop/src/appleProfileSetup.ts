// Closed profile setup DATA on the existing Apple controller. These checks
// never create a native key loan, save permission, assignment or retry right.
import { copyBoundedComparisonData, parseSavedConfigContent, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseAndroidBuildSavedVersion } from './androidBuildProtocol.ts';
import { assetStorageWritable } from './assetSessionProtocol.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { LocalStoreProject } from './localStorePreflight.ts';
import type { AppleProvisioningMode, PrepareAppleProvisioning } from './appleProvisioningTypes.ts';

export type AppleProfileMode = 'profile-review' | 'profile-reuse' | 'profile-create' | 'profile-reconcile';
export type AppleProfileDecision = 'reuse-available' | 'create-available' | 'blocked' | 'download-returned' | 'creation-unconfirmed' | 'comparison-only';
export type AppleProfileReason = 'reuse-existing-profile' | 'profile-create-review' | 'identity-required' | 'bundle-required' |
  'profile-selection-required' | 'inventory-unavailable' | 'inventory-incomplete' | 'pending-setup' | 'capabilities-manual' |
  'selection-changed' | 'profile-returned' | 'provider-unconfirmed' | 'same-response' | 'unattributed' | 'not-returned' | 'inconclusive';
export interface AppleProfileSetupResult {
  schemaVersion: 1; scope: 'local-ios-profile-setup'; mode: AppleProfileMode;
  decision: AppleProfileDecision; reason: AppleProfileReason; bundleId: string;
  profileResourceId: string | null; profileUuid: string | null; saved: false;
  credentialReady: false; cancellationRequested: boolean; limitations: readonly string[];
}
export interface AppleProfileSavedReference {
  vaultId: string; generationId: string; recordId: string; revisionId: string; revisionCounter: number;
}
export const APPLE_PROFILE_MODES = Object.freeze(['profile-review', 'profile-reuse', 'profile-create', 'profile-reconcile'] as const);
export const APPLE_PROFILE_LIMITATIONS = Object.freeze(['existing-p12-only', 'no-key-or-certificate-creation',
  'no-build-or-store-release', 'profile-scoped-offline-validation', 'new-vault-record-not-assigned', 'no-post-retry', 'native-save-and-joins-required']);
export const isAppleProfileMode = (mode: unknown): mode is AppleProfileMode => typeof mode === 'string' && APPLE_PROFILE_MODES.includes(mode as AppleProfileMode);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' &&
  !Array.isArray(v) && Object.keys(v).length === names.length && names.every(name => Object.hasOwn(v, name));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
const revision = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0 && (v as number) < 0xffffffff;
const reasons: readonly string[] = ['reuse-existing-profile', 'profile-create-review', 'identity-required', 'bundle-required',
  'profile-selection-required', 'inventory-unavailable', 'inventory-incomplete', 'pending-setup', 'capabilities-manual',
  'selection-changed', 'profile-returned', 'provider-unconfirmed', 'same-response', 'unattributed', 'not-returned', 'inconclusive'];

export function parseAppleProfileSavedReference(value: unknown): AppleProfileSavedReference | null {
  try {
    const v = copyBoundedComparisonData(value, 1024);
    if (!keys(v, ['vaultId', 'generationId', 'recordId', 'revisionId', 'revisionCounter']) || !revision(v.revisionCounter)) return null;
    const ids = [v.vaultId, v.generationId, v.recordId, v.revisionId];
    return ids.every(id) && new Set(ids).size === 4 ? v as unknown as AppleProfileSavedReference : null;
  } catch { return null; }
}
export function parseAppleProfileSetupResult(value: unknown, mode: AppleProvisioningMode): AppleProfileSetupResult | null {
  try {
    const v = copyBoundedComparisonData(value, 8192);
    if (!isAppleProfileMode(mode) || !keys(v, ['schemaVersion', 'scope', 'mode', 'decision', 'reason', 'bundleId',
        'profileResourceId', 'profileUuid', 'saved', 'credentialReady', 'cancellationRequested', 'limitations']) ||
        v.schemaVersion !== 1 || v.scope !== 'local-ios-profile-setup' || v.mode !== mode ||
        typeof v.reason !== 'string' || !reasons.includes(v.reason) || typeof v.bundleId !== 'string' || v.bundleId.length > 255 ||
        !/^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$/.test(v.bundleId) ||
        v.saved !== false || v.credentialReady !== false || typeof v.cancellationRequested !== 'boolean' ||
        !sameOfflineData(v.limitations, APPLE_PROFILE_LIMITATIONS) ||
        (v.profileResourceId === null) !== (v.profileUuid === null) ||
        v.profileResourceId !== null && (typeof v.profileResourceId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(v.profileResourceId)) ||
        v.profileUuid !== null && (typeof v.profileUuid !== 'string' || !/^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/.test(v.profileUuid))) return null;
    const valid = v.decision === 'reuse-available' ? mode === 'profile-review' && v.reason === 'reuse-existing-profile' :
      v.decision === 'create-available' ? mode === 'profile-review' && v.reason === 'profile-create-review' :
      v.decision === 'download-returned' ? ['profile-reuse', 'profile-create'].includes(mode) && v.reason === 'profile-returned' && v.profileResourceId !== null && !v.cancellationRequested :
      v.decision === 'creation-unconfirmed' ? mode === 'profile-create' && v.reason === 'provider-unconfirmed' :
      v.decision === 'comparison-only' ? mode === 'profile-reconcile' && ['same-response', 'unattributed', 'not-returned', 'inconclusive'].includes(v.reason) :
      v.decision === 'blocked' && mode !== 'profile-reconcile';
    return valid ? v as unknown as AppleProfileSetupResult : null;
  } catch { return null; }
}

export type AppleProfileInputBase = Omit<PrepareAppleProvisioning, 'mode' | 'reference' | 'newApplication' | 'displayName'> &
  { p12RecordId: string; p12RecordRevision: number };
function selectedBase(project: LocalStoreProject | null, assets: AssetDisplayState | null, retained: boolean): AppleProfileInputBase | null {
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
    // ONLY correlation of an already-started original. Native mutation makes
    // ordinary assignment availability temporarily false. This branch never
    // admits another Prepare/Start or ignores a different credential revision.
    if (!s.operation || s.operation.operation !== 'apple-profile-setup' || s.operation.phase === 'unknown' ||
        ['unknown', 'late-known'].includes(s.operation.settlement) ||
        !s.persistence || !['unlocked', 'mutating'].includes(s.persistence.state)) return null;
  } else if (assets.busy || !assets.contextCurrent || !assetStorageWritable(s) ||
      s.operation && (s.operation.phase !== 'idle' || s.operation.settlement !== 'known')) return null;
  const selected = (kind: 'asc-p8' | 'apple-p12') => {
    const rows = s.assignments.filter(row => row.kind === kind && row.contextRevision === c.revision && (retained || row.availability === 'available'));
    if (rows.length !== 1) return null;
    const row = rows[0]!;
    return id(row.recordId) && revision(row.recordRevision) && s.records.some(record => record.kind === kind &&
      record.recordId === row.recordId && record.revision === row.recordRevision && record.storage === 'encrypted' &&
      (retained ? record.availability !== 'mutation-pending' : record.availability === 'assigned')) ? row : null;
  };
  const p8 = selected('asc-p8'), p12 = selected('apple-p12');
  if (!p8 || !p12 || p8.recordId === p12.recordId) return null;
  return { projectId: project.projectId, draftRevision: project.draftRevision, baselineGeneration: project.baselineGeneration,
    savedConfig: project.savedConfig!, savedVersion: project.savedVersion!, credentialContextRevision: c.revision,
    recordId: p8.recordId, recordRevision: p8.recordRevision, p12RecordId: p12.recordId, p12RecordRevision: p12.recordRevision,
    executionMode: 'local', platform: 'ios' };
}
export const appleProfileInputBase = (project: LocalStoreProject | null, assets: AssetDisplayState | null): AppleProfileInputBase | null => selectedBase(project, assets, false);
export function retainedAppleProfileInput(project: LocalStoreProject | null, assets: AssetDisplayState | null, original: unknown): AppleProfileInputBase | null {
  const current = selectedBase(project, assets, true);
  return current && sameOfflineData(current, original) ? current : null;
}

export function appleProfileResultCopy(result: AppleProfileSetupResult, saved: AppleProfileSavedReference | null): { title: string; detail: string } {
  if (saved && result.decision === 'download-returned') return { title: 'Profile saved', detail: 'A new encrypted profile was saved and read back. Open saved credentials to assess and assign it; it is not assigned automatically.' };
  if (result.decision === 'reuse-available') return { title: 'Reuse an existing profile', detail: 'The current review found a profile for this saved app and existing P12. Confirm a separate download and new encrypted save below.' };
  if (result.decision === 'create-available') return { title: 'A matching profile can be requested', detail: 'No reusable profile was found in this complete review. Confirm one profile request using the existing distribution certificate; no key or certificate will be created.' };
  if (result.decision === 'creation-unconfirmed') return { title: 'Check the earlier profile request', detail: 'Apple may have received it. Use read-only reconciliation; do not send another creation request.' };
  if (result.decision === 'comparison-only') return { title: 'Readback comparison only', detail: result.reason === 'same-response' ? 'Apple returned the recorded profile. This does not retry, save another copy, or clear an unresolved earlier operation.' : 'This read cannot confirm what the earlier request did. Missing or denied results do not mean it is safe to create another profile.' };
  if (result.decision === 'download-returned') return { title: 'Profile received; saved copy not confirmed', detail: 'No completed encrypted save is reported. Keep this operation and its recovery information; do not repeat creation.' };
  const detail: Partial<Record<AppleProfileReason, string>> = {
    'identity-required': 'Select the existing distribution P12 and password, and check the saved certificate fingerprint. No replacement key or certificate is created.',
    'bundle-required': 'Register or select the exact saved Bundle ID first, then review signing setup again.',
    'profile-selection-required': 'The returned profiles require manual selection. Keep valid existing profiles; nothing is revoked.',
    'inventory-unavailable': 'This key could not read the required Apple records. Check account roles, agreements or supported key type; denial is not absence.',
    'inventory-incomplete': 'The Apple response is incomplete or outside this check’s limits. Use the Apple Developer portal to review it.',
    'pending-setup': 'An earlier setup for this account is unresolved. Keep that attempt and use read-only reconciliation, not another creation request.',
    'capabilities-manual': 'This app’s capabilities need manual setup in the Apple Developer portal. This flow does not change capabilities.',
    'selection-changed': 'The saved app or selected signing files changed. Finish this operation, then make a fresh review.',
  };
  return { title: 'Signing setup needs attention', detail: detail[result.reason] ?? 'No safe profile action is available. Review the current app, account and signing files without replacing them.' };
}
