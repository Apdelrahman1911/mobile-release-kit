import { recoveryReceiptFields } from './localReleaseHistoryProtocol.ts';
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStorePrepareRequest } from './localStorePrepareProtocol.ts';
import type { ApiError } from './types.ts';
import type { LocalStoreReconcileStatus, PrepareLocalStoreReconcile, LocalReconciliationReceipt, IOSReconciliationReceipt, LocalStoreReconcileContext } from './localStoreReconcileTypes.ts';

export const STORE_RECONCILE_EVENT = 'local-store-reconcile-state-changed';
export const STORE_RECONCILE_CONSENT = 'local-android-store-reconcile-v1' as const;
export const STORE_RECOVERY_CONSENT = 'local-android-recovery-settle-v1' as const;
export const IOS_STORE_RECONCILE_CONSENT = 'local-ios-store-reconcile-v1' as const;
export const reconcileConsent = (request: PrepareLocalStoreReconcile) => request.platform==='ios' ? IOS_STORE_RECONCILE_CONSENT : request.settlement ? STORE_RECOVERY_CONSENT : STORE_RECONCILE_CONSENT;
export function reconcileRequestContext(request: PrepareLocalStoreReconcile): LocalStoreReconcileContext {
  if(request.platform==='ios')return {...request,operation:'local-store-reconcile'};
  return { ...request, platform: 'android', operation: request.settlement ? 'local-store-recovery-settle' : 'local-store-reconcile' };
}
export type StoreReconcileCommand = 'prepare_local_store_reconcile' | 'start_local_store_reconcile' | 'local_store_reconcile_status' | 'cancel_local_store_reconcile';
const phases = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
const outcomes = ['complete', 'refused', 'cancelled', 'timed-out', 'failed', 'unknown'];
const reasons = ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error', 'runtime-unavailable', 'intent-expired', 'stale-intent', 'saved-source-changed', 'saved-source-invalid', 'credentials-unavailable', 'query-prerequisites', 'command-incomplete', 'cleanup-unknown', 'reconcile-unavailable', 'recovery-settle-unavailable'];
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < 4294967295;
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const member = (values: string[], v: unknown) => typeof v === 'string' && values.includes(v);
const contextKeys = ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'credentialContextRevision', 'recordId', 'recordRevision', 'executionMode', 'candidateOperationId', 'candidateSha256', 'confirmation', 'intentSha256'];
function request(v: unknown): v is PrepareLocalStoreReconcile {
  if (!(keys(v,[...contextKeys,'platform']) && v.platform==='ios' || keys(v, contextKeys) || keys(v, [...contextKeys, 'settlement']) && v.settlement === 'record-current-target') || !hex(v.intentSha256, 64)) return false;
  const base = { ...v }; delete base.intentSha256; delete base.settlement;
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
      hex(v.operationId, 32) && hex(v.ownerGeneration, 32) && (command !== 'start_local_store_reconcile' || (v.consentVersion === STORE_RECONCILE_CONSENT || v.consentVersion === STORE_RECOVERY_CONSENT || v.consentVersion === IOS_STORE_RECONCILE_CONSENT));
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
    if (!(keys(c, [...contextKeys, 'platform', 'operation']) && c.operation === 'local-store-reconcile' ||
      keys(c, [...contextKeys, 'platform', 'operation', 'settlement']) && c.operation === 'local-store-recovery-settle' && c.settlement === 'record-current-target') || !member(['android','ios'],c.platform) || c.platform==='ios'&&Object.hasOwn(c,'settlement')) return null;
    const prepared = { ...c }; if(c.platform==='android')delete prepared.platform; delete prepared.operation;
    if (!request(prepared)) return null;
    if (op.reason === 'recovery-settle-unavailable' && !prepared.settlement || op.reason === 'reconcile-unavailable' && prepared.settlement) return null;
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
      if (op.phase !== 'terminal' || op.outcome !== 'complete' || op.reason !== 'none' || !keys(r, ['schemaVersion', 'scope', 'headSequence', 'reconciliationReceipt']) || r.schemaVersion !== 1 || r.scope !== (c.platform==='ios'?'local-ios-store-reconcile':prepared.settlement ? 'local-android-recovery-settlement' : 'local-android-store-reconcile') || !counter(r.headSequence) || r.headSequence < (prepared.settlement ? 7 : 6) || r.headSequence > 513) return null;
      const i = r.reconciliationReceipt;
      if (!reconciliationReceiptSummary(i, prepared.candidateOperationId, c.platform==='ios'?'ios':'android') || i.candidateSha256 !== prepared.candidateSha256 || i.intentSha256 !== prepared.intentSha256 ||
        !sameOfflineData(i.version, { name: prepared.savedVersion.name, build: prepared.savedVersion.build })) return null;
    } else if (op.outcome === 'complete') return null;
    return v as unknown as LocalStoreReconcileStatus;
  } catch { return null; }
}
// Exact fresh target-only receipt DATA; never accept an Execute receipt here.
export function reconciliationReceiptSummary(i: unknown, operationId: unknown, platform:'android'|'ios'='android'): i is LocalReconciliationReceipt | IOSReconciliationReceipt {
  if(platform==='ios')return iosReconciliationReceipt(i,operationId);
  if (!object(i) || i.observation !== 'current-internal-target-only' || i.priorExecutionFinality !== 'not-established') return false;
  const { observation: _, priorExecutionFinality: __, ...summary } = i;
  return recoveryReceiptFields(summary, operationId);
}
function iosReconciliationReceipt(i:unknown,operationId:unknown):i is IOSReconciliationReceipt {
  const uuid=(v:unknown)=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v);
  if(!keys(i,['operationId','candidateSha256','intentSha256','receiptSha256','authorizationId','sourceCommit','sourceTree','bundleId','appStoreAppId','version','destination','observedAt','result','observation','priorExecutionFinality','limitations']) ||
    !uuid(i.operationId)||i.operationId!==operationId||!uuid(i.authorizationId)||!hex(i.candidateSha256,64)||!hex(i.intentSha256,64)||!hex(i.receiptSha256,64)||!hex(i.sourceCommit,40)||!hex(i.sourceTree,40)||
    typeof i.bundleId!=='string'||i.bundleId.length>255||!/^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$/.test(i.bundleId)||typeof i.appStoreAppId!=='string'||!/^[0-9]{1,20}$/.test(i.appStoreAppId)||
    !keys(i.version,['name','build'])||typeof i.version.name!=='string'||!/^[0-9A-Za-z.+-]{1,64}$/.test(i.version.name)||!counter(i.version.build)||i.version.build<1||i.version.build>2100000000||
    !sameOfflineData(i.destination,{channel:'testflight-internal'})||i.result!=='reconciled'||i.observation!=='current-internal-build-only'||i.priorExecutionFinality!=='not-established'||
    !sameOfflineData(i.limitations,['non-publishing','not-retry-permission','old-evidence-preserved','saved-inputs-not-atomic'])||
    typeof i.observedAt!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(i.observedAt)||!Number.isFinite(Date.parse(i.observedAt)))return false;
  return new Date(i.observedAt).toISOString()===i.observedAt.replace('Z','.000Z');
}
export function localStoreReconcileError(_value?: unknown): ApiError {
  return { code: 'local_store_reconcile_unavailable', retryable: false, message: 'The current Store readback is unavailable or unverified. Preserve the earlier release, files and history. Refresh or cancel only this original check; do not upload again.' };
}
