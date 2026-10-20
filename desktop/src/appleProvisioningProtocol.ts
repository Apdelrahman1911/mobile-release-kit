// Exactly the original native Bundle-ID protocol. No Access query/consent,
// provider JSON, journal row, issuer override, secret or local path is accepted.
import { copyBoundedComparisonData, parseSavedConfigContent, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseAndroidBuildSavedVersion } from './androidBuildProtocol.ts';
import type { AppleProvisioningContext, AppleProvisioningIdentity, AppleProvisioningMode, AppleProvisioningConsent,
  AppleProvisioningOperation, AppleProvisioningStatus, PrepareAppleProvisioning } from './appleProvisioningTypes.ts';

export const APPLE_PROVISIONING_EVENT = 'apple-bundle-provisioning-state-changed';
export const APPLE_PROVISIONING_LIMITATIONS = Object.freeze(['bundle-id-only', 'no-release-or-signing-readiness',
  'no-certificate-or-profile-changes', 'no-team-verification', 'no-global-availability-claim', 'one-write-no-retry',
  'parent-journal-and-native-joins-required']);
export type AppleProvisioningCommand = 'prepare_apple_provisioning' | 'start_apple_provisioning' |
  'apple_provisioning_status' | 'cancel_apple_provisioning';
const encoder = new TextEncoder();
const modes = ['review', 'register', 'reconcile'] as const;
const phases = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'] as const;
const outcomes = ['complete', 'refused', 'cancelled', 'timed-out', 'failed', 'unknown'] as const;
const reasons = ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error',
  'runtime-unavailable', 'intent-expired', 'stale-intent', 'saved-source-changed', 'saved-source-invalid',
  'credentials-unavailable', 'query-prerequisites', 'command-incomplete', 'cleanup-unknown', 'journal-unavailable',
  'review-expired', 'registration-blocked'] as const;
const attemptReasons = ['readback_required', 'journal_settlement_required', 'authorization_changed', 'cancelled_before_send',
  'provider_outcome_unknown', 'original_transport_unsettled', 'authorization_changed_after_send', 'provider_rejected_request',
  'provider_result_requires_reconciliation', 'reconciliation_read_unavailable', 'reconciliation_context_changed',
  'resource_validation_required', 'provider_outcome_still_unknown', 'ambiguous_recovery_resources', 'resource_found_review_required',
  'response_readback_disagrees', 'provider_resource_confirmed', 'cancelled_after_settlement'] as const;
const fields = ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'credentialContextRevision',
  'recordId', 'recordRevision', 'executionMode', 'platform', 'mode', 'reference', 'newApplication', 'displayName'] as const;
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => !!value &&
  typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === names.length && names.every(n => Object.hasOwn(value, n));
const oneOf = <T extends string>(value: unknown, values: readonly T[]): value is T => typeof value === 'string' && values.includes(value as T);
const counter = (value: unknown, max = 0xffffffff): value is number => Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= max;
const token = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const identity = (value: unknown): value is AppleProvisioningIdentity => keys(value, ['operationId', 'ownerGeneration']) && token(value.operationId) && token(value.ownerGeneration);
export function appleDisplayName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && [...value].length <= 128 && !/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value);
}
export function appleProvisioningConsent(mode: AppleProvisioningMode): AppleProvisioningConsent {
  return mode === 'register' ? 'local-ios-bundle-register-v1' : mode === 'reconcile' ? 'local-ios-bundle-reconcile-v1' : 'local-ios-bundle-review-v1';
}
function request(value: unknown): value is PrepareAppleProvisioning {
  if (!keys(value, fields) || typeof value.projectId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(value.projectId) ||
      !counter(value.draftRevision, 0xfffffffe) || !counter(value.baselineGeneration, 0xfffffffe) || !parseSavedConfigContent(value.savedConfig) ||
      !parseAndroidBuildSavedVersion(value.savedVersion) || !counter(value.credentialContextRevision, 0xfffffffe) || value.credentialContextRevision < 1 ||
      !token(value.recordId) || !counter(value.recordRevision, 0xfffffffe) || value.recordRevision < 1 || value.executionMode !== 'local' ||
      value.platform !== 'ios' || !oneOf(value.mode, modes) || !appleDisplayName(value.displayName) || value.newApplication !== (value.mode === 'register')) return false;
  return value.mode === 'review' ? value.reference === null : identity(value.reference);
}
export function parseAppleProvisioningRequest(value: unknown): PrepareAppleProvisioning | null {
  try { const v = copyBoundedComparisonData(value, 8192); return request(v) ? v : null; } catch { return null; }
}
export function appleProvisioningContext(value: PrepareAppleProvisioning): AppleProvisioningContext {
  return { ...value, operation: 'apple-bundle-provisioning' };
}
export function encodeAppleProvisioningRequest(command: AppleProvisioningCommand, value: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(value, 8192);
    let valid = false;
    if (command === 'prepare_apple_provisioning') valid = request(v);
    else if (command === 'apple_provisioning_status') valid = keys(v, []);
    else if (command === 'cancel_apple_provisioning') valid = identity(v);
    else if (command === 'start_apple_provisioning') valid = keys(v, ['operationId', 'ownerGeneration', 'consentVersion']) &&
      token(v.operationId) && token(v.ownerGeneration) && modes.some(mode => v.consentVersion === appleProvisioningConsent(mode));
    if (!valid) return null;
    const bytes = encoder.encode(JSON.stringify(v)); return bytes.length <= 8192 ? bytes : null;
  } catch { return null; }
}
function result(value: unknown, op: Record<string, unknown>, context: AppleProvisioningContext): boolean {
  if (!keys(value, ['schemaVersion', 'scope', 'mode', 'observation', 'decision', 'attempt', 'comparison', 'limitations']) || value.schemaVersion !== 1 ||
      value.scope !== 'local-ios-bundle-provisioning' || value.mode !== context.mode ||
      !oneOf(value.observation, ['found', 'not-returned', 'not-permitted', 'inconclusive', 'not-checked']) ||
      !oneOf(value.decision, ['reuse', 'review-required', 'blocked', 'registration-unconfirmed', 'registration-confirmed', 'comparison-only']) ||
      !sameOfflineData(value.limitations, APPLE_PROVISIONING_LIMITATIONS)) return false;
  if (context.mode === 'reconcile') {
    return value.attempt === null && value.decision === 'comparison-only' &&
      (value.observation === 'found' ? oneOf(value.comparison, ['same-response', 'different-response', 'unattributed']) :
        value.observation === 'not-returned' ? value.comparison === 'not-returned' : value.comparison === 'inconclusive');
  }
  if (value.comparison !== null) return false;
  if (context.mode === 'review') return value.attempt === null &&
    (value.decision === 'reuse' && value.observation === 'found' || value.decision === 'review-required' && value.observation === 'not-returned' || value.decision === 'blocked');
  const a = value.attempt;
  if (a !== null && (!keys(a, ['operationId', 'action', 'status', 'reason', 'retryAllowed', 'credentialReady', 'cancellationRequested']) ||
      a.operationId !== op.operationId || a.action !== 'register_bundle_id' ||
      !oneOf(a.status, ['running', 'cancellation_requested', 'succeeded', 'failed', 'cancelled', 'recovery_required', 'unknown']) ||
      !oneOf(a.reason, attemptReasons) || a.retryAllowed !== false || a.credentialReady !== false || typeof a.cancellationRequested !== 'boolean')) return false;
  if (value.decision === 'registration-confirmed') return value.observation === 'found' && a !== null && a.status === 'succeeded';
  if (value.decision === 'registration-unconfirmed') return a !== null;
  return a === null && (value.decision === 'reuse' && value.observation === 'found' || value.decision === 'blocked' || value.decision === 'review-required');
}
export function parseAppleProvisioningStatus(value: unknown): AppleProvisioningStatus | null {
  try {
    const v = copyBoundedComparisonData(value, 16384);
    if (!keys(v, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || v.schemaVersion !== 1 || !counter(v.statusRevision) ||
        !oneOf(v.availability, ['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified'])) return null;
    const op = v.operation;
    if (op === null) return v as unknown as AppleProvisioningStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result']) ||
        !token(op.operationId) || !token(op.ownerGeneration) || !oneOf(op.phase, phases) || typeof op.intentUsable !== 'boolean' || !oneOf(op.reason, reasons) ||
        !keys(op.context, [...fields, 'operation']) || op.context.operation !== 'apple-bundle-provisioning') return null;
    const prepared = { ...op.context }; delete prepared.operation;
    if (!request(prepared)) return null;
    if (op.phase === 'terminal') {
      if (!oneOf(op.outcome, outcomes) || op.outcome === 'unknown' || op.intentUsable) return null;
      if (op.outcome === 'complete') {
        if (op.reason !== 'none' || !result(op.result, op, op.context as unknown as AppleProvisioningContext)) return null;
      } else if (op.result !== null || op.reason === 'none') return null;
    } else if (op.phase === 'unknown') {
      if (op.outcome !== 'unknown' || op.reason !== 'cleanup-unknown' || op.intentUsable || op.result !== null) return null;
    } else if (op.outcome !== null || op.result !== null || op.intentUsable && op.phase !== 'awaiting-consent') return null;
    return v as unknown as AppleProvisioningStatus;
  } catch { return null; }
}
export function sameAppleIdentity(a: AppleProvisioningIdentity | null | undefined, b: AppleProvisioningIdentity | null | undefined): boolean {
  return !!a && !!b && a.operationId === b.operationId && a.ownerGeneration === b.ownerGeneration;
}
export function appleProvisioningProgress(before: AppleProvisioningOperation, after: AppleProvisioningOperation): boolean {
  if (!sameAppleIdentity(before, after) || !sameOfflineData(before.context, after.context)) return false;
  if (before.phase === 'unknown' || before.phase === 'terminal') return sameOfflineData(before, after);
  return (before.intentUsable || !after.intentUsable) && phases.indexOf(after.phase) >= phases.indexOf(before.phase);
}
