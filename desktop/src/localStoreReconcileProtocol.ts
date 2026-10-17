import { localStoreSummaryIdentity } from './localReleaseHistoryProtocol.ts';
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStorePrepareRequest } from './localStorePrepareProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalStoreReconcileStatus, PrepareLocalStoreReconcile, LocalReconciliationReceipt } from './localStoreReconcileTypes.ts';

export const STORE_RECONCILE_EVENT = 'local-store-reconcile-state-changed';
export const STORE_RECONCILE_CONSENT = 'local-android-store-reconcile-v1' as const;
export type StoreReconcileCommand = 'prepare_local_store_reconcile' | 'start_local_store_reconcile' | 'local_store_reconcile_status' | 'cancel_local_store_reconcile';
const phases = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
const outcomes = ['complete', 'refused', 'cancelled', 'timed-out', 'failed', 'unknown'];
const reasons = ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error', 'runtime-unavailable', 'intent-expired', 'stale-intent', 'saved-source-changed', 'saved-source-invalid', 'credentials-unavailable', 'query-prerequisites', 'command-incomplete', 'cleanup-unknown', 'reconcile-unavailable'];
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < 4294967295;
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const member = (values: string[], v: unknown) => typeof v === 'string' && values.includes(v);
const contextKeys = ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'credentialContextRevision', 'recordId', 'recordRevision', 'executionMode', 'candidateOperationId', 'candidateSha256', 'confirmation', 'intentSha256'];
function request(v: unknown): v is PrepareLocalStoreReconcile {
  if (!keys(v, contextKeys) || !hex(v.intentSha256, 64)) return false;
  const base = { ...v }; delete base.intentSha256;
  return parseLocalStorePrepareRequest(base) !== null;
}
export function parseLocalStoreReconcileRequest(input: unknown): PrepareLocalStoreReconcile | null {
  try { const v = copyBoundedComparisonData(input, 16384); return request(v) ? v : null; } catch { return null; }
}
export function encodeLocalStoreReconcileRequest(command: StoreReconcileCommand, input: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    const valid = command === 'prepare_local_store_reconcile' ? request(v) : command === 'local_store_reconcile_status' ? keys(v, []) :
      keys(v, command === 'start_local_store_reconcile' ? ['operationId', 'ownerGeneration', 'consentVersion'] : ['operationId', 'ownerGeneration']) &&
      hex(v.operationId, 32) && hex(v.ownerGeneration, 32) && (command !== 'start_local_store_reconcile' || v.consentVersion === STORE_RECONCILE_CONSENT);
    if (!valid) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length <= 16384 ? bytes : null;
  } catch { return null; }
}
export function parseLocalStoreReconcileStatus(input: unknown): LocalStoreReconcileStatus | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    if (!keys(v, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || v.schemaVersion !== 1 || !counter(v.statusRevision) ||
      !member(['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified'], v.availability)) return null;
    const op = v.operation;
    if (op === null) return v as unknown as LocalStoreReconcileStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result']) || !hex(op.operationId, 32) || !hex(op.ownerGeneration, 32) || !member(phases, op.phase) || typeof op.intentUsable !== 'boolean' || !member(reasons, op.reason)) return null;
    const c = op.context;
    if (!keys(c, [...contextKeys, 'platform', 'operation']) || c.platform !== 'android' || c.operation !== 'local-store-reconcile') return null;
    const prepared = { ...c }; delete prepared.platform; delete prepared.operation;
    if (!request(prepared)) return null;
    if (op.phase === 'terminal') {
      if (!member(outcomes, op.outcome) || op.outcome === 'unknown' || op.intentUsable || op.reason === 'cleanup-unknown' ||
        op.outcome !== 'complete' && op.reason === 'none' ||
        op.outcome === 'cancelled' && !member(['cancelled', 'context-changed', 'document-lost', 'shutdown'], op.reason) ||
        op.outcome === 'timed-out' && op.reason !== 'timed-out') return null;
    }
    else if (op.phase === 'unknown') { if (op.outcome !== 'unknown' || op.reason !== 'cleanup-unknown' || op.intentUsable || op.result !== null) return null; }
    else if (op.outcome !== null || op.result !== null || op.intentUsable && op.phase !== 'awaiting-consent') return null;
    if (op.result !== null) {
      const r = op.result;
      if (op.phase !== 'terminal' || op.outcome !== 'complete' || op.reason !== 'none' || !keys(r, ['schemaVersion', 'scope', 'headSequence', 'reconciliationReceipt']) || r.schemaVersion !== 1 || r.scope !== 'local-android-store-reconcile' || !counter(r.headSequence) || r.headSequence < 6 || r.headSequence > 513) return null;
      const i = r.reconciliationReceipt;
      if (!reconciliationReceiptSummary(i, prepared.candidateOperationId) || i.candidateSha256 !== prepared.candidateSha256 || i.intentSha256 !== prepared.intentSha256 ||
        !sameOfflineData(i.version, { name: prepared.savedVersion.name, build: prepared.savedVersion.build })) return null;
    } else if (op.outcome === 'complete') return null;
    return v as unknown as LocalStoreReconcileStatus;
  } catch { return null; }
}
// Exact fresh target-only receipt DATA; never accept an Execute receipt here.
export function reconciliationReceiptSummary(i: unknown, operationId: unknown): i is LocalReconciliationReceipt {
  return keys(i, ['operationId', 'candidateSha256', 'intentSha256', 'receiptSha256', 'authorizationId', 'sourceCommit', 'sourceTree', 'applicationId', 'version', 'destination', 'observedAt', 'result', 'limitations', 'observation', 'priorExecutionFinality']) &&
    typeof i.authorizationId === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(i.authorizationId) && hex(i.receiptSha256, 64) && i.result === 'reconciled' &&
    i.observation === 'current-internal-target-only' && i.priorExecutionFinality === 'not-established' &&
    sameOfflineData(i.limitations, ['non-publishing', 'not-retry-permission', 'old-evidence-preserved', 'saved-inputs-not-atomic']) && localStoreSummaryIdentity(i, operationId);
}
export function localStoreReconcileError(_value?: unknown): ApiError {
  return { code: 'local_store_reconcile_unavailable', retryable: false, message: 'The current Play readback is unavailable or unverified. Preserve the earlier release, files and history. Refresh or cancel only this original check; do not upload again.' };
}
