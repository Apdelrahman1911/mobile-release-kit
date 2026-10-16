import { preparedIntentSummary } from './localReleaseHistoryProtocol.ts';
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStoreRequest } from './localStorePreflightProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalStorePrepareStatus, PrepareLocalStoreIntent } from './localStorePrepareTypes.ts';

export const STORE_PREPARE_EVENT = 'local-store-prepare-state-changed';
export const STORE_PREPARE_CONSENT = 'local-android-store-prepare-v1' as const;
export type StorePrepareCommand = 'prepare_local_store_prepare' | 'start_local_store_prepare' | 'local_store_prepare_status' | 'cancel_local_store_prepare';
const phases = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
const outcomes = ['complete', 'refused', 'cancelled', 'timed-out', 'failed', 'unknown'];
const reasons = ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error', 'runtime-unavailable', 'intent-expired', 'stale-intent', 'saved-source-changed', 'saved-source-invalid', 'credentials-unavailable', 'query-prerequisites', 'command-incomplete', 'cleanup-unknown', 'prepare-unavailable'];
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < 4294967295;
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const member = (values: string[], v: unknown) => typeof v === 'string' && values.includes(v);
const contextKeys = ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'credentialContextRevision', 'recordId', 'recordRevision', 'executionMode', 'candidateOperationId', 'candidateSha256', 'confirmation'];
function request(v: unknown): v is PrepareLocalStoreIntent {
  if (!keys(v, contextKeys) || !uuid(v.candidateOperationId) || !hex(v.candidateSha256, 64)) return false;
  const base = { ...v }; delete base.candidateOperationId; delete base.candidateSha256; delete base.confirmation;
  const parsed = parseLocalStoreRequest(base);
  return !!parsed && v.confirmation === `candidate:android:${parsed.savedVersion.name}:${parsed.savedVersion.build}`;
}
export function parseLocalStorePrepareRequest(input: unknown): PrepareLocalStoreIntent | null {
  try { const v = copyBoundedComparisonData(input, 16384); return request(v) ? v : null; } catch { return null; }
}
export function encodeLocalStorePrepareRequest(command: StorePrepareCommand, input: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    const valid = command === 'prepare_local_store_prepare' ? request(v) : command === 'local_store_prepare_status' ? keys(v, []) :
      keys(v, command === 'start_local_store_prepare' ? ['operationId', 'ownerGeneration', 'consentVersion'] : ['operationId', 'ownerGeneration']) &&
      hex(v.operationId, 32) && hex(v.ownerGeneration, 32) && (command !== 'start_local_store_prepare' || v.consentVersion === STORE_PREPARE_CONSENT);
    if (!valid) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length <= 16384 ? bytes : null;
  } catch { return null; }
}
export function parseLocalStorePrepareStatus(input: unknown): LocalStorePrepareStatus | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    if (!keys(v, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || v.schemaVersion !== 1 || !counter(v.statusRevision) ||
      !member(['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified'], v.availability)) return null;
    const op = v.operation;
    if (op === null) return v as unknown as LocalStorePrepareStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result']) || !hex(op.operationId, 32) || !hex(op.ownerGeneration, 32) || !member(phases, op.phase) || typeof op.intentUsable !== 'boolean' || !member(reasons, op.reason)) return null;
    const c = op.context;
    if (!keys(c, [...contextKeys, 'platform', 'operation']) || c.platform !== 'android' || c.operation !== 'local-store-prepare') return null;
    const prepared = { ...c }; delete prepared.platform; delete prepared.operation;
    if (!request(prepared)) return null;
    if (op.phase === 'terminal') { if (!member(outcomes, op.outcome) || op.outcome === 'unknown' || op.intentUsable) return null; }
    else if (op.phase === 'unknown') { if (op.outcome !== 'unknown' || op.reason !== 'cleanup-unknown' || op.intentUsable || op.result !== null) return null; }
    else if (op.outcome !== null || op.result !== null || op.intentUsable && op.phase !== 'awaiting-consent') return null;
    if (op.result !== null) {
      const r = op.result;
      if (op.phase !== 'terminal' || op.outcome !== 'complete' || op.reason !== 'none' || !keys(r, ['schemaVersion', 'scope', 'headSequence', 'preparedIntent']) || r.schemaVersion !== 1 || r.scope !== 'local-android-store-prepare' || !counter(r.headSequence) || r.headSequence < 1 || r.headSequence > 513) return null;
      const i = r.preparedIntent;
      if (!preparedIntentSummary(i, prepared.candidateOperationId) || i.candidateSha256 !== prepared.candidateSha256 ||
        !sameOfflineData(i.version, { name: prepared.savedVersion.name, build: prepared.savedVersion.build })) return null;
    } else if (op.outcome === 'complete') return null;
    return v as unknown as LocalStorePrepareStatus;
  } catch { return null; }
}
export function localStorePrepareError(_value?: unknown): ApiError {
  return { code: 'local_store_prepare_unavailable', retryable: false, message: 'The original Play preparation is unavailable or unverified. Keep its history and files; refresh status or cancel the original operation, not a new release.' };
}
