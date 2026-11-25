// Bounded UI comparison DATA only. Native/core authenticate the real originals.
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStoreRequest } from './localStorePreflightProtocol.ts';
import { stageAssignmentsValid } from './localStoreStageProtocol.ts';
import type { PrepareExternalReadiness } from './localStoreReconcileTypes.ts';
export const EXTERNAL_READINESS_CONSENT = 'local-ios-external-readiness-v1' as const;
export interface ExternalReadinessReceipt {
  operationId: string; candidateOperationId: string; candidateSha256: string; intentSha256: string;
  executionReceiptSha256: string; receiptSha256: string; authorizationId: string;
  sourceCommit: string; sourceTree: string; bundleId: string; appStoreAppId: string;
  version: { name: string; build: number }; destination: { channel: 'testflight-external' };
  observedAt: string; result: 'ready'; state: 'available-to-testers';
  limitations: ['non-publishing', 'not-retry-permission', 'old-evidence-preserved', 'saved-inputs-not-atomic'];
  observation: 'current-external-target-only'; priorExecutionFinality: 'not-established';
}
export type ExternalReadinessReview = Omit<ExternalReadinessReceipt, 'observation'> & { observation: 'current-external-readiness-files-only' };
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v,n));
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const requestKeys = ['projectId','draftRevision','baselineGeneration','savedConfig','savedVersion','credentialContextRevision','recordId','recordRevision','executionMode','platform',
  'candidateOperationId','candidateSha256','intentSha256','confirmation','action','stageOperationId','executionReceiptSha256','supplementalAssignments'];
export function parseExternalReadinessRequest(input: unknown): PrepareExternalReadiness | null {
  try {
    const v = copyBoundedComparisonData(input,16384);
    if (!keys(v,requestKeys) || v.platform !== 'ios' || v.action !== 'external-readiness' || !uuid(v.candidateOperationId) || !uuid(v.stageOperationId) || v.stageOperationId === v.candidateOperationId ||
        !hex(v.candidateSha256,64) || !hex(v.intentSha256,64) || !hex(v.executionReceiptSha256,64) || !stageAssignmentsValid(v.supplementalAssignments,v.recordId)) return null;
    const base = {...v};
    for (const key of ['candidateOperationId','candidateSha256','intentSha256','confirmation','action','stageOperationId','executionReceiptSha256','supplementalAssignments']) delete base[key];
    const parsed = parseLocalStoreRequest(base);
    return parsed && v.confirmation === `external-testing:ios:${parsed.savedVersion.name}:${parsed.savedVersion.build}` ? v as unknown as PrepareExternalReadiness : null;
  } catch { return null; }
}
// Live and offline observations are distinct; callers supply the original selected ID.
export function parseExternalReadinessSummary(input: unknown, operationId: unknown, offline: true): ExternalReadinessReview | null;
export function parseExternalReadinessSummary(input: unknown, operationId: unknown, offline?: false): ExternalReadinessReceipt | null;
export function parseExternalReadinessSummary(input: unknown, operationId: unknown, offline = false): ExternalReadinessReceipt | ExternalReadinessReview | null {
  try {
    const v = copyBoundedComparisonData(input,16384);
    if (!keys(v,['operationId','candidateOperationId','candidateSha256','intentSha256','executionReceiptSha256','receiptSha256','authorizationId','sourceCommit','sourceTree','bundleId','appStoreAppId','version','destination','observedAt','result','state','limitations','observation','priorExecutionFinality']) ||
        !uuid(v.operationId) || v.operationId !== operationId || !uuid(v.candidateOperationId) || v.candidateOperationId === v.operationId || !uuid(v.authorizationId) ||
        !['candidateSha256','intentSha256','executionReceiptSha256','receiptSha256'].every(key => hex(v[key],64)) || !hex(v.sourceCommit,40) || !hex(v.sourceTree,40) ||
        typeof v.bundleId !== 'string' || v.bundleId.length > 255 || !/^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$/.test(v.bundleId) ||
        typeof v.appStoreAppId !== 'string' || !/^[0-9]{1,20}$/.test(v.appStoreAppId) || !keys(v.version,['name','build']) ||
        typeof v.version.name !== 'string' || !/^[0-9A-Za-z.+-]{1,64}$/.test(v.version.name) || typeof v.version.build !== 'number' || !Number.isSafeInteger(v.version.build) || v.version.build < 1 || v.version.build > 2100000000 ||
        !sameOfflineData(v.destination,{channel:'testflight-external'}) || v.result !== 'ready' || v.state !== 'available-to-testers' ||
        v.observation !== (offline ? 'current-external-readiness-files-only' : 'current-external-target-only') || v.priorExecutionFinality !== 'not-established' ||
        !sameOfflineData(v.limitations,['non-publishing','not-retry-permission','old-evidence-preserved','saved-inputs-not-atomic']) ||
        typeof v.observedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v.observedAt) || !Number.isFinite(Date.parse(v.observedAt)) || new Date(v.observedAt).toISOString() !== v.observedAt.replace('Z','.000Z')) return null;
    return v as unknown as ExternalReadinessReceipt | ExternalReadinessReview;
  } catch { return null; }
}
