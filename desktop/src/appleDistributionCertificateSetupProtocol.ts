// Public comparison DATA only. A saved row, certificate ID or historical
// attempt never supplies a native key loan, issuance consent or signing proof.
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { appleDistributionKeyInputBase, retainedAppleDistributionCertificateKeyInput } from './appleDistributionKeySetupProtocol.ts';
import type { AppleDistributionKeyInputBase } from './appleDistributionKeySetupProtocol.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { LocalStoreProject } from './localStorePreflight.ts';
import type { AppleAttemptReason, AppleAttemptStatus, AppleBundleComparison, AppleProvisioningIdentity } from './appleProvisioningTypes.ts';
import type { OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

export const APPLE_DISTRIBUTION_CERTIFICATE_MODES = Object.freeze(['certificate-review', 'certificate-create', 'certificate-reconcile'] as const);
export type AppleDistributionCertificateMode = typeof APPLE_DISTRIBUTION_CERTIFICATE_MODES[number];
export const isAppleDistributionCertificateMode = (value: unknown): value is AppleDistributionCertificateMode =>
  value === 'certificate-review' || value === 'certificate-create' || value === 'certificate-reconcile';
export type AppleDistributionCertificateDecision = 'reuse' | 'request-review' | 'blocked' | 'request-unconfirmed' | 'request-confirmed' | 'comparison-only';
export type AppleDistributionCertificateReason = 'existing-certificate' | 'certificate-required' | 'account-pending' | 'inventory-unavailable' |
  'key-history-unavailable' | 'policy-unavailable' | 'existing-certificate-needs-key' | 'bundle-registration-required' |
  'provider-outcome-unconfirmed' | 'provider-rejected' | 'certificate-confirmed' | 'comparison-only';
export interface AppleCertificateAttemptSummary {
  operationId: string; action: 'create_certificate'; status: AppleAttemptStatus; reason: AppleAttemptReason;
  retryAllowed: false; credentialReady: false; cancellationRequested: boolean;
}
export interface AppleDistributionCertificateResult {
  schemaVersion: 1; scope: 'local-ios-distribution-certificate'; mode: AppleDistributionCertificateMode;
  decision: AppleDistributionCertificateDecision; reason: AppleDistributionCertificateReason;
  certificateId: string | null; attempt: AppleCertificateAttemptSummary | null; comparison: AppleBundleComparison | null;
  p12Saved: false; profileSaved: false; credentialReady: false; revocationChecked: false;
}
export interface AppleCertificateRecoveryAttempt {
  reference: AppleProvisioningIdentity; displayName: string; observedAt: string;
  status: AppleAttemptStatus; reason: AppleAttemptReason; nativeSettlement: 'pending' | 'known' | 'unknown';
  cancellationRequested: boolean; certificateId: string | null;
}
export interface AppleCertificateRecoveryHistory {
  schemaVersion: 1; scope: 'local-ios-certificate-attempts'; attempts: readonly AppleCertificateRecoveryAttempt[]; hiddenUnresolved: number;
}
export interface AppleCertificateKeySelection { recordId: string; recordRevision: number }
export type AppleDistributionCertificateInputBase = AppleDistributionKeyInputBase & { keyRecordId: string; keyRecordRevision: number };

const keys = (value: unknown, fields: readonly string[]): value is Record<string, unknown> => !!value && typeof value === 'object' &&
  !Array.isArray(value) && Object.keys(value).length === fields.length && fields.every(name => Object.hasOwn(value, name));
const oneOf = <T extends string>(value: unknown, choices: readonly T[]): value is T => typeof value === 'string' && choices.includes(value as T);
const id = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) && value !== '0'.repeat(32);
const revision = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) > 0 && (value as number) < 0xffffffff;
const certificateId = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const statuses = ['running', 'cancellation_requested', 'succeeded', 'failed', 'cancelled', 'recovery_required', 'unknown'] as const;
const reasons = ['readback_required', 'journal_settlement_required', 'authorization_changed', 'cancelled_before_send',
  'provider_outcome_unknown', 'original_transport_unsettled', 'authorization_changed_after_send', 'provider_rejected_request',
  'provider_result_requires_reconciliation', 'reconciliation_read_unavailable', 'reconciliation_context_changed',
  'resource_validation_required', 'provider_outcome_still_unknown', 'ambiguous_recovery_resources', 'resource_found_review_required',
  'response_readback_disagrees', 'provider_resource_confirmed', 'cancelled_after_settlement'] as const;
const blocked = ['account-pending', 'inventory-unavailable', 'key-history-unavailable', 'policy-unavailable',
  'existing-certificate-needs-key', 'bundle-registration-required'] as const;
const comparisons = ['same-response', 'different-response', 'unattributed', 'not-returned', 'inconclusive'] as const;
function attempt(value: unknown, originalId: unknown): value is AppleCertificateAttemptSummary {
  return keys(value, ['operationId', 'action', 'status', 'reason', 'retryAllowed', 'credentialReady', 'cancellationRequested']) &&
    id(value.operationId) && value.operationId === originalId && value.action === 'create_certificate' &&
    oneOf(value.status, statuses) && oneOf(value.reason, reasons) && value.retryAllowed === false &&
    value.credentialReady === false && typeof value.cancellationRequested === 'boolean';
}
export function parseAppleDistributionCertificateResult(value: unknown, mode: unknown, operationId: unknown,
  reference: AppleProvisioningIdentity | null): AppleDistributionCertificateResult | null {
  try {
    const v = copyBoundedComparisonData(value, 4096);
    if (!isAppleDistributionCertificateMode(mode) || !id(operationId) ||
        !keys(v, ['schemaVersion', 'scope', 'mode', 'decision', 'reason', 'certificateId', 'attempt', 'comparison',
          'p12Saved', 'profileSaved', 'credentialReady', 'revocationChecked']) || v.schemaVersion !== 1 ||
        v.scope !== 'local-ios-distribution-certificate' || v.mode !== mode || v.p12Saved !== false ||
        v.profileSaved !== false || v.credentialReady !== false || v.revocationChecked !== false ||
        v.certificateId !== null && !certificateId(v.certificateId)) return null;
    let valid = false;
    if (mode === 'certificate-reconcile') {
      valid = v.decision === 'comparison-only' && v.reason === 'comparison-only' && !!reference &&
        attempt(v.attempt, reference.operationId) && oneOf(v.comparison, comparisons) &&
        (['not-returned', 'inconclusive'].includes(v.comparison) ? v.certificateId === null : certificateId(v.certificateId));
    } else if (v.comparison === null) {
      valid = v.decision === 'reuse' && v.reason === 'existing-certificate' && certificateId(v.certificateId) && v.attempt === null ||
        v.decision === 'blocked' && oneOf(v.reason, blocked) && v.certificateId === null && v.attempt === null;
      if (mode === 'certificate-review') {
        valid ||= v.decision === 'request-review' && v.reason === 'certificate-required' && v.certificateId === null && v.attempt === null;
      } else if (attempt(v.attempt, operationId)) {
        valid ||= v.decision === 'request-confirmed' && v.reason === 'certificate-confirmed' && certificateId(v.certificateId) &&
          v.attempt.status === 'succeeded' && v.attempt.reason === 'provider_resource_confirmed' && !v.attempt.cancellationRequested ||
          v.decision === 'request-unconfirmed' && (v.reason === 'provider-rejected' ?
            v.certificateId === null && v.attempt.status === 'failed' && v.attempt.reason === 'provider_rejected_request' :
            v.reason === 'provider-outcome-unconfirmed' && v.attempt.status !== 'succeeded');
      }
    }
    return valid ? v as unknown as AppleDistributionCertificateResult : null;
  } catch { return null; }
}
function displayName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && [...value].length <= 128 && !/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value);
}
function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00$/.test(value) || value.endsWith('.000000+00:00')) return false;
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
}
export function parseAppleCertificateRecoveryHistory(value: unknown): AppleCertificateRecoveryHistory | null {
  try {
    const v = copyBoundedComparisonData(value, 32768);
    if (!keys(v, ['schemaVersion', 'scope', 'attempts', 'hiddenUnresolved']) || v.schemaVersion !== 1 ||
        v.scope !== 'local-ios-certificate-attempts' || !Array.isArray(v.attempts) || v.attempts.length > 32 ||
        !Number.isSafeInteger(v.hiddenUnresolved) || (v.hiddenUnresolved as number) < 0 ||
        (v.hiddenUnresolved as number) > 32 - v.attempts.length) return null;
    const seen = new Set<string>();
    for (const row of v.attempts) {
      if (!keys(row, ['reference', 'displayName', 'observedAt', 'status', 'reason', 'nativeSettlement', 'cancellationRequested', 'certificateId']) ||
          !keys(row.reference, ['operationId', 'ownerGeneration']) || !id(row.reference.operationId) || !id(row.reference.ownerGeneration) ||
          seen.has(row.reference.operationId) || !displayName(row.displayName) || !timestamp(row.observedAt) ||
          !oneOf(row.status, statuses) || !oneOf(row.reason, reasons) || !oneOf(row.nativeSettlement, ['pending', 'known', 'unknown']) ||
          typeof row.cancellationRequested !== 'boolean' || row.certificateId !== null && !certificateId(row.certificateId)) return null;
      seen.add(row.reference.operationId);
    }
    return v as unknown as AppleCertificateRecoveryHistory;
  } catch { return null; }
}
export const appleCertificateHistoryUnresolved = (history: AppleCertificateRecoveryHistory): boolean => history.hiddenUnresolved > 0 ||
  history.attempts.some(row => row.nativeSettlement !== 'known' || !['succeeded', 'failed', 'cancelled'].includes(row.status));

function recordSelections(assets: AssetDisplayState | null): readonly AppleCertificateKeySelection[] {
  const rows = copyBoundedComparisonData(assets?.status?.records, 65536);
  if (!Array.isArray(rows) || rows.length > 128) return [];
  const result: AppleCertificateKeySelection[] = [], seen = new Set<string>();
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row) || !id(row.recordId) || !revision(row.revision) || seen.has(row.recordId)) return [];
    seen.add(row.recordId);
    if (row.kind === 'apple-distribution-key' && row.storage === 'encrypted' && row.availability === 'unassigned' && row.payloadState === 'not-checked' && row.label === null) {
      result.push(Object.freeze({ recordId: row.recordId, recordRevision: row.revision }));
    }
  }
  return Object.freeze(result);
}
export function appleCertificateKeyChoices(project: LocalStoreProject | null, assets: AssetDisplayState | null): readonly AppleCertificateKeySelection[] {
  try { return appleDistributionKeyInputBase(project, assets) ? recordSelections(assets) : []; } catch { return []; }
}
export function appleDistributionCertificateInputBase(project: LocalStoreProject | null, assets: AssetDisplayState | null,
  selected: AppleCertificateKeySelection | null): AppleDistributionCertificateInputBase | null {
  try {
    const base = appleDistributionKeyInputBase(project, assets);
    if (!base || !selected || !recordSelections(assets).some(row => sameOfflineData(row, selected))) return null;
    return { ...base, keyRecordId: selected.recordId, keyRecordRevision: selected.recordRevision };
  } catch { return null; }
}
export function retainedAppleDistributionCertificateInput(project: LocalStoreProject | null, assets: AssetDisplayState | null,
  selected: AppleCertificateKeySelection | null, original: AppleDistributionKeyInputBase & { keyRecordId?: string; keyRecordRevision?: number }): AppleDistributionCertificateInputBase | null {
  try {
    if (!id(original.keyRecordId) || !revision(original.keyRecordRevision) || !selected || !id(selected.recordId) || !revision(selected.recordRevision) || selected.recordId !== original.keyRecordId ||
        selected.recordRevision !== original.keyRecordRevision || !recordSelections(assets).some(row => sameOfflineData(row, selected))) return null;
    const { keyRecordId, keyRecordRevision, ...p8 } = original;
    const base = retainedAppleDistributionCertificateKeyInput(project, assets, p8);
    const current = base && { ...base, keyRecordId, keyRecordRevision };
    return current && sameOfflineData(current, original) ? current : null;
  } catch { return null; }
}

export function appleDistributionCertificateCopy(result: AppleDistributionCertificateResult | null,
  outcome: OfflinePreflightOutcome | null): { title: string; detail: string } | null {
  if (result?.decision === 'reuse') return { title: 'Keep the existing certificate',
    detail: 'This check found an existing certificate for the selected key. Do not request another. P12 creation, profile setup and signing assignment remain separate.' };
  if (result?.decision === 'request-review') return { title: 'Review one certificate request',
    detail: 'The completed check permits a separate review for this saved key. Nothing has been requested yet. Only confirm the next step if you need this certificate.' };
  if (result?.decision === 'request-confirmed') return { title: 'Certificate request confirmed',
    detail: 'Apple’s response and the checked certificate matched this request. Keep the saved private key and an independent encrypted backup. No P12, profile or signing assignment was saved by this step.' };
  if (result?.decision === 'request-unconfirmed') return result.reason === 'provider-rejected' ? {
    title: 'Apple declined the certificate request', detail: 'Keep the saved key and this request. Check the selected key’s permissions, Apple agreements and certificate limits. Do not repeat the request or create a replacement key; a separate read-only check can inspect the earlier attempt.',
  } : { title: 'Certificate request needs checking',
    detail: 'Apple may already have received the request. Keep the saved key and earlier request. Use the original status or a read-only check when available; never submit it again because a response was lost.' };
  if (result?.decision === 'comparison-only') {
    const comparison = { 'same-response': 'The certificate returned matches the earlier recorded response.',
      'different-response': 'The returned certificate differs from the earlier response.', unattributed: 'A certificate was returned, but it cannot be attributed to this request.',
      'not-returned': 'This key did not return a matching certificate. That does not prove no request was sent.', inconclusive: 'The earlier certificate could not be compared conclusively.' };
    return { title: 'Earlier request checked without repeating it',
      detail: `${result.comparison ? comparison[result.comparison] : 'No comparison is available.'} This does not clear earlier uncertainty, authorize another request or save a P12.` };
  }
  if (result?.decision === 'blocked') {
    if (result.reason === 'existing-certificate-needs-key') return { title: 'Recover the existing signing key',
      detail: 'An existing certificate needs its matching private key. Use its P12/password or recover your encrypted key backup. Do not create another key or certificate to bypass this check.' };
    if (result.reason === 'bundle-registration-required') return { title: 'Review the saved Bundle ID first',
      detail: 'Use Bundle ID setup above. This result does not authorize changing an existing app or requesting a certificate.' };
    if (result.reason === 'account-pending' || result.reason === 'key-history-unavailable') return { title: 'Keep the earlier Apple setup',
      detail: 'Earlier setup or saved-key history needs attention. Keep the key and original records. Use available status or earlier-request checks; do not start another request to bypass missing history.' };
    return { title: 'Certificate setup could not be checked',
      detail: 'Check the selected account, permissions and Apple agreements. Incomplete records or unavailable certificate checks are not proof that a new certificate is needed. Some account or key layouts need manual Apple setup.' };
  }
  if (outcome && outcome !== 'complete') return { title: 'Certificate setup did not finish',
    detail: 'Keep the saved key and original request. A stopped or unconfirmed operation does not prove that Apple received nothing. Check the original status; do not repeat issuance or generate a replacement key.' };
  return null;
}
export function appleCertificateRecoveryCopy(row: AppleCertificateRecoveryAttempt): string {
  if (row.nativeSettlement !== 'known') return 'Earlier cleanup is still unconfirmed. Checking Apple will not clear it or permit another request.';
  if (row.status === 'succeeded') return 'A confirmed certificate request was recorded. Checking it will not issue another certificate or save a P12.';
  if (row.status === 'failed' && row.reason === 'provider_rejected_request') return 'Apple’s rejection was recorded. Keep the key; checking this record does not authorize resubmission.';
  return 'This earlier request needs review. Check it without repeating issuance or replacing the saved key.';
}
