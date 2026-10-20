// Historical comparison DATA only. No selected row restores a signing loan,
// provider approval, save destination, or the earlier operation's native joins.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import type { AppleAttemptReason, AppleAttemptStatus, AppleProvisioningIdentity } from './appleProvisioningTypes.ts';

export type AppleProfileRecordedProvider =
  | { kind: 'download-pending' | 'download-returned' | 'download-refused' | 'download-unknown' }
  | { kind: 'creation'; status: AppleAttemptStatus; reason: AppleAttemptReason };
export interface AppleProfileRecoveryAttempt {
  reference: AppleProvisioningIdentity;
  displayName: string;
  observedAt: string;
  action: 'reuse-download' | 'create-profile';
  provider: AppleProfileRecordedProvider;
  save: 'not-entered' | 'armed' | 'written' | 'read-back' | 'unknown';
  nativeSettlement: 'pending' | 'known' | 'unknown';
  cancellationRequested: boolean;
  unresolved: boolean;
}
export interface AppleProfileRecoveryHistory {
  schemaVersion: 1;
  scope: 'local-ios-profile-attempts';
  attempts: readonly AppleProfileRecoveryAttempt[];
  hiddenUnresolved: number;
}
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === names.length && names.every(name => Object.hasOwn(value, name));
const oneOf = <T extends string>(value: unknown, options: readonly T[]): value is T =>
  typeof value === 'string' && options.includes(value as T);
const token = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value) && value !== '0'.repeat(32);
const statuses = ['running', 'cancellation_requested', 'succeeded', 'failed', 'cancelled', 'recovery_required', 'unknown'] as const;
const reasons = ['readback_required', 'journal_settlement_required', 'authorization_changed', 'cancelled_before_send',
  'provider_outcome_unknown', 'original_transport_unsettled', 'authorization_changed_after_send', 'provider_rejected_request',
  'provider_result_requires_reconciliation', 'reconciliation_read_unavailable', 'reconciliation_context_changed',
  'resource_validation_required', 'provider_outcome_still_unknown', 'ambiguous_recovery_resources', 'resource_found_review_required',
  'response_readback_disagrees', 'provider_resource_confirmed', 'cancelled_after_settlement'] as const;
function timestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?\+00:00$/.test(value) || value.endsWith('.000000+00:00')) return false;
  const date = new Date(value);
  return Number.isFinite(date.valueOf()) && date.toISOString().slice(0, 19) === value.slice(0, 19);
}
function recordedProvider(value: unknown, action: unknown): value is AppleProfileRecordedProvider {
  if (action === 'reuse-download') return keys(value, ['kind']) &&
    oneOf(value.kind, ['download-pending', 'download-returned', 'download-refused', 'download-unknown']);
  return action === 'create-profile' && keys(value, ['kind', 'status', 'reason']) && value.kind === 'creation' &&
    oneOf(value.status, statuses) && oneOf(value.reason, reasons);
}
export function parseAppleProfileRecoveryHistory(value: unknown): AppleProfileRecoveryHistory | null {
  try {
    const v = copyBoundedComparisonData(value, 32768);
    if (!keys(v, ['schemaVersion', 'scope', 'attempts', 'hiddenUnresolved']) || v.schemaVersion !== 1 ||
        v.scope !== 'local-ios-profile-attempts' || !Array.isArray(v.attempts) || v.attempts.length > 32 ||
        !Number.isSafeInteger(v.hiddenUnresolved) || (v.hiddenUnresolved as number) < 0 ||
        (v.hiddenUnresolved as number) > 32 - v.attempts.length) return null;
    const seen = new Set<string>();
    for (const row of v.attempts) {
      if (!keys(row, ['reference', 'displayName', 'observedAt', 'action', 'provider', 'save', 'nativeSettlement', 'cancellationRequested', 'unresolved']) ||
          !keys(row.reference, ['operationId', 'ownerGeneration']) || !token(row.reference.operationId) || !token(row.reference.ownerGeneration) ||
          seen.has(row.reference.operationId) || typeof row.displayName !== 'string' || !row.displayName.length ||
          [...row.displayName].length > 128 || /[\u0000-\u001f\u007f\ud800-\udfff]/u.test(row.displayName) || !timestamp(row.observedAt) ||
          !recordedProvider(row.provider, row.action) || !oneOf(row.save, ['not-entered', 'armed', 'written', 'read-back', 'unknown']) ||
          !oneOf(row.nativeSettlement, ['pending', 'known', 'unknown']) || typeof row.cancellationRequested !== 'boolean') return null;
      const providerTerminal = row.provider.kind === 'creation' ? ['succeeded', 'failed', 'cancelled'].includes(row.provider.status) :
        ['download-returned', 'download-refused'].includes(row.provider.kind);
      const unresolved = row.nativeSettlement !== 'known' || !providerTerminal || ['armed', 'written', 'unknown'].includes(row.save);
      if (row.unresolved !== unresolved) return null;
      seen.add(row.reference.operationId);
    }
    return v as unknown as AppleProfileRecoveryHistory;
  } catch { return null; }
}

export function appleProfileRecoveryCopy(row: AppleProfileRecoveryAttempt): { provider: string; storage: string; detail: string } {
  const provider = row.provider.kind === 'creation' ? {
    running: 'Request may have been sent', cancellation_requested: 'Cancellation was requested',
    succeeded: 'Profile creation was recorded', failed: 'The request failed', cancelled: 'The request was cancelled',
    recovery_required: 'The request needs checking', unknown: 'The request outcome is unconfirmed',
  }[row.provider.status] : {
    'download-pending': 'Profile download was pending', 'download-returned': 'Profile download was recorded',
    'download-refused': 'Profile download was refused', 'download-unknown': 'Profile download is unconfirmed',
  }[row.provider.kind];
  const storage = {
    'not-entered': 'No encrypted save was entered', armed: 'Encrypted save was started; completion is not recorded',
    written: 'Encrypted copy was written; readback is not recorded',
    'read-back': 'An encrypted save and readback were recorded; reassess the saved credential before using it',
    unknown: 'The encrypted-save outcome is unconfirmed',
  }[row.save];
  return { provider, storage, detail: row.nativeSettlement !== 'known' ?
    'Earlier cleanup is still unconfirmed. Checking Apple will not clear it or permit another request.' : row.unresolved ?
    'This earlier attempt is unresolved. Check it without repeating the request or saving another copy.' :
    'This is a saved record, not a fresh Apple result or signing approval. A check will not repeat the request.' };
}
