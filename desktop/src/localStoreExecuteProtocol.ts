import { executionReceiptSummary, iosExecutionReceiptSummary } from './localReleaseHistoryProtocol.ts';
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStorePrepareRequest } from './localStorePrepareProtocol.ts';
import { parseAndroidMacToolchainSelection } from './androidToolchainCatalogProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalStoreExecuteStatus, PrepareLocalStoreExecute } from './localStoreExecuteTypes.ts';

export const STORE_EXECUTE_EVENT = 'local-store-execute-state-changed';
export const STORE_EXECUTE_CONSENT = 'local-android-store-execute-v1' as const;
export const IOS_STORE_EXECUTE_CONSENT = 'local-ios-store-execute-v1' as const;
export const storeExecuteConsent = (request: PrepareLocalStoreExecute) => request.platform === 'ios' ? IOS_STORE_EXECUTE_CONSENT : STORE_EXECUTE_CONSENT;
export type StoreExecuteCommand = 'prepare_local_store_execute' | 'start_local_store_execute' | 'local_store_execute_status' | 'cancel_local_store_execute';
const phases = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
const outcomes = ['complete', 'refused', 'cancelled', 'timed-out', 'failed', 'unknown'];
const reasons = ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error', 'runtime-unavailable', 'intent-expired', 'stale-intent', 'saved-source-changed', 'saved-source-invalid', 'credentials-unavailable', 'query-prerequisites', 'command-incomplete', 'cleanup-unknown', 'execute-unavailable'];
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < 4294967295;
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const member = (values: string[], v: unknown) => typeof v === 'string' && values.includes(v);
const contextKeys = ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'credentialContextRevision', 'recordId', 'recordRevision', 'executionMode', 'candidateOperationId', 'candidateSha256', 'confirmation', 'intentSha256'];
function request(v: unknown): v is PrepareLocalStoreExecute {
  const ios = object(v) && Object.hasOwn(v, 'platform');
  if (!keys(v, [...contextKeys, ios ? 'platform' : 'toolchainSelection']) || !hex(v.intentSha256, 64) ||
    (ios ? v.platform !== 'ios' : !parseAndroidMacToolchainSelection(v.toolchainSelection))) return false;
  const base = { ...v }; delete base.intentSha256; delete base.toolchainSelection;
  return parseLocalStorePrepareRequest(base) !== null;
}
export function parseLocalStoreExecuteRequest(input: unknown): PrepareLocalStoreExecute | null {
  try { const v = copyBoundedComparisonData(input, 16384); return request(v) ? v : null; } catch { return null; }
}
export function encodeLocalStoreExecuteRequest(command: StoreExecuteCommand, input: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    const valid = command === 'prepare_local_store_execute' ? request(v) : command === 'local_store_execute_status' ? keys(v, []) :
      keys(v, command === 'start_local_store_execute' ? ['operationId', 'ownerGeneration', 'consentVersion'] : ['operationId', 'ownerGeneration']) &&
      hex(v.operationId, 32) && hex(v.ownerGeneration, 32) && (command !== 'start_local_store_execute' || member([STORE_EXECUTE_CONSENT, IOS_STORE_EXECUTE_CONSENT], v.consentVersion));
    if (!valid) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length <= 16384 ? bytes : null;
  } catch { return null; }
}
export function parseLocalStoreExecuteStatus(input: unknown): LocalStoreExecuteStatus | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    if (!keys(v, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || v.schemaVersion !== 1 || !counter(v.statusRevision) ||
      !member(['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified'], v.availability)) return null;
    const op = v.operation;
    if (op === null) return v as unknown as LocalStoreExecuteStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result']) || !hex(op.operationId, 32) || !hex(op.ownerGeneration, 32) || !member(phases, op.phase) || typeof op.intentUsable !== 'boolean' || !member(reasons, op.reason)) return null;
    const c = op.context;
    if (!object(c) || !member(['android', 'ios'], c.platform) || c.operation !== 'local-store-execute') return null;
    const prepared = { ...c }; if (c.platform === 'android') delete prepared.platform; delete prepared.operation;
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
      if (op.phase !== 'terminal' || op.outcome !== 'complete' || op.reason !== 'none' || !keys(r, ['schemaVersion', 'scope', 'headSequence', 'executionReceipt']) || r.schemaVersion !== 1 || r.scope !== (c.platform === 'ios' ? 'local-ios-store-execute' : 'local-android-store-execute') || !counter(r.headSequence) || r.headSequence < 7 || r.headSequence > 513) return null;
      const i = r.executionReceipt;
      if (!object(i) || !(c.platform === 'ios' ? iosExecutionReceiptSummary(i, prepared.candidateOperationId) : executionReceiptSummary(i, prepared.candidateOperationId)) || i.candidateSha256 !== prepared.candidateSha256 || i.intentSha256 !== prepared.intentSha256 ||
        !sameOfflineData(i.version, { name: prepared.savedVersion.name, build: prepared.savedVersion.build })) return null;
    } else if (op.outcome === 'complete') return null;
    return v as unknown as LocalStoreExecuteStatus;
  } catch { return null; }
}
export function localStoreExecuteError(_value?: unknown): ApiError {
  return { code: 'local_store_execute_unavailable', retryable: false, message: 'The original Store execution is unavailable or unverified. Keep its history and files. Refresh status or cancel only the original operation; do not upload again.' };
}
