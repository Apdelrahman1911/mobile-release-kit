// Shared later-stage UI DATA, never source, predecessor or Store authority.
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { parseLocalStoreRequest } from './localStorePreflightProtocol.ts';
import type { PrepareLocalStorePreflight } from './localStorePreflightTypes.ts';

export type LocalStoreStage = 'external-testing' | 'production-submit';
export interface StageRecord { recordId: string; recordRevision: number }
export interface StageAssignments { reviewContact: StageRecord; commitment: StageRecord; reviewDemo: StageRecord | null }
type StageRequestBase = Omit<PrepareLocalStorePreflight, 'platform' | 'query' | 'iosRecord'> & {
  stage: LocalStoreStage; candidateOperationId: string; candidateSha256: string;
  predecessorOperationId: string; predecessorReceiptSha256: string; confirmation: string;
};
export type PrepareLocalStoreStage = StageRequestBase & (
  { platform: 'android'; supplementalAssignments?: never } |
  { platform: 'ios'; supplementalAssignments: StageAssignments }
);
export type ExecuteLocalStoreStage = PrepareLocalStoreStage & { stageOperationId: string; intentSha256: string };
interface StageSummaryBase {
  operationId: string; stage: LocalStoreStage; candidateOperationId: string; candidateSha256: string;
  predecessorOperationId: string; predecessorReceiptSha256: string; intentSha256: string;
  sourceCommit: string; sourceTree: string; version: { name: string; build: number }; observedAt: string;
}
type StageTarget =
  { applicationId: string; destination: { channel: string; releaseStatus: 'completed' | 'draft' } } |
  { bundleId: string; appStoreAppId: string; destination: { channel: 'testflight-external' } | { channel: 'app-store-review'; automaticRelease: false } };
export type StagePreparedIntent = StageSummaryBase & StageTarget & {
  storePreconditionSha256: string;
  limitations: ['non-publishing', 'prepare-not-execute', 'current-store-snapshot-may-change',
    'original-binary-reused', 'prior-native-finality-not-established', 'saved-inputs-not-atomic'];
};
export type StageExecutionReceipt = StageSummaryBase & StageTarget & {
  receiptSha256: string; authorizationId: string; result: 'accepted';
  state: 'available-to-testers' | 'draft' | 'submitted-for-review' | 'in-review' | 'approved' | 'pending-developer-release';
  limitations: ['original-binary-reused', 'not-public-release', 'prior-native-finality-not-established', 'saved-inputs-not-atomic'];
};
export const STAGE_PREPARE_LIMITS = ['non-publishing', 'prepare-not-execute', 'current-store-snapshot-may-change',
  'original-binary-reused', 'prior-native-finality-not-established', 'saved-inputs-not-atomic'] as const;
export const STAGE_EXECUTE_LIMITS = ['original-binary-reused', 'not-public-release', 'prior-native-finality-not-established', 'saved-inputs-not-atomic'] as const;
const object = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => object(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && new RegExp(`^[a-f0-9]{${n}}$`).test(v);
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v);
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0 && v < 4294967295;
export const isLocalStoreStage = (v: unknown): v is LocalStoreStage => v === 'external-testing' || v === 'production-submit';
export function nativeStageOperationId(value: unknown): string | null {
  if (!hex(value, 32)) return null;
  const id = `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
  return uuid(id) ? id : null;
}
const requestKeys = ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'credentialContextRevision',
  'recordId', 'recordRevision', 'executionMode', 'platform', 'stage', 'candidateOperationId', 'candidateSha256',
  'predecessorOperationId', 'predecessorReceiptSha256', 'confirmation'];
const record = (v: unknown): v is StageRecord => keys(v, ['recordId', 'recordRevision']) && hex(v.recordId, 32) && counter(v.recordRevision);
export function stageAssignmentsValid(a: unknown, recordId: unknown): a is StageAssignments {
  if (!keys(a, ['reviewContact', 'commitment', 'reviewDemo']) || !record(a.reviewContact) || !record(a.commitment) || a.reviewDemo !== null && !record(a.reviewDemo)) return false;
  const refs = [recordId, a.reviewContact.recordId, a.commitment.recordId, ...(a.reviewDemo === null ? [] : [a.reviewDemo.recordId])];
  return new Set(refs).size === refs.length;
}
function prepare(v: unknown): v is PrepareLocalStoreStage {
  const ios = object(v) && v.platform === 'ios';
  if (!keys(v, [...requestKeys, ...(ios ? ['supplementalAssignments'] : [])]) ||
    !['android', 'ios'].includes(v.platform as string) || !isLocalStoreStage(v.stage) ||
    !uuid(v.candidateOperationId) || !uuid(v.predecessorOperationId) || !hex(v.candidateSha256, 64) || !hex(v.predecessorReceiptSha256, 64) ||
    (v.stage === 'external-testing' ? v.predecessorOperationId !== v.candidateOperationId : v.predecessorOperationId === v.candidateOperationId)) return false;
  if (ios) {
    if (!stageAssignmentsValid(v.supplementalAssignments, v.recordId)) return false;
  }
  const base = { ...v };
  for (const key of ['stage', 'candidateOperationId', 'candidateSha256', 'predecessorOperationId', 'predecessorReceiptSha256', 'confirmation', 'supplementalAssignments']) delete base[key];
  if (!ios) delete base.platform;
  const parsed = parseLocalStoreRequest(base);
  return !!parsed && v.confirmation === `${v.stage}:${v.platform}:${parsed.savedVersion.name}:${parsed.savedVersion.build}`;
}
export function parseStagePrepareRequest(input: unknown): PrepareLocalStoreStage | null {
  try { const v = copyBoundedComparisonData(input, 16384); return prepare(v) ? v : null; } catch { return null; }
}
export function parseStageExecuteRequest(input: unknown): ExecuteLocalStoreStage | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    if (!object(v) || !uuid(v.stageOperationId) || !hex(v.intentSha256, 64) || v.stageOperationId === v.candidateOperationId || v.stageOperationId === v.predecessorOperationId) return null;
    const { stageOperationId: _, intentSha256: __, ...request } = v;
    return prepare(request) ? v as ExecuteLocalStoreStage : null;
  } catch { return null; }
}
const summaryKeys = ['operationId', 'stage', 'candidateOperationId', 'candidateSha256', 'predecessorOperationId', 'predecessorReceiptSha256',
  'intentSha256', 'sourceCommit', 'sourceTree', 'version', 'destination', 'observedAt', 'limitations'];
function summaryIdentity(v: Record<string, unknown>, operation: unknown, platform: 'android' | 'ios'): boolean {
  if (!uuid(v.operationId) || v.operationId !== operation || !isLocalStoreStage(v.stage) || !uuid(v.candidateOperationId) || !uuid(v.predecessorOperationId) ||
    v.operationId === v.candidateOperationId || v.operationId === v.predecessorOperationId ||
    (v.stage === 'external-testing' ? v.predecessorOperationId !== v.candidateOperationId : v.predecessorOperationId === v.candidateOperationId) ||
    !hex(v.candidateSha256, 64) || !hex(v.predecessorReceiptSha256, 64) || !hex(v.intentSha256, 64) || !hex(v.sourceCommit, 40) || !hex(v.sourceTree, 40) ||
    !keys(v.version, ['name', 'build']) || typeof v.version.name !== 'string' || !/^[0-9A-Za-z.+-]{1,64}$/.test(v.version.name) || !counter(v.version.build) || v.version.build > 2100000000 ||
    typeof v.observedAt !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v.observedAt) || !Number.isFinite(Date.parse(v.observedAt)) ||
    new Date(v.observedAt).toISOString() !== v.observedAt.replace('Z', '.000Z')) return false;
  if (platform === 'ios') return typeof v.bundleId === 'string' && v.bundleId.length <= 255 && /^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$/.test(v.bundleId) &&
    typeof v.appStoreAppId === 'string' && /^[0-9]{1,20}$/.test(v.appStoreAppId) && sameOfflineData(v.destination,
      v.stage === 'external-testing' ? { channel: 'testflight-external' } : { channel: 'app-store-review', automaticRelease: false });
  return typeof v.applicationId === 'string' && v.applicationId.length <= 255 && /^([A-Za-z][A-Za-z0-9_]*\.)+[A-Za-z][A-Za-z0-9_]*$/.test(v.applicationId) &&
    keys(v.destination, ['channel', 'releaseStatus']) && (v.stage === 'production-submit' ? sameOfflineData(v.destination, { channel: 'production', releaseStatus: 'draft' }) :
      typeof v.destination.channel === 'string' && v.destination.channel.trim().length > 0 && [...v.destination.channel].length <= 100 && !/[\0\r\n]/.test(v.destination.channel) && !['production', 'internal'].includes(v.destination.channel) && v.destination.releaseStatus === 'completed');
}
// Callers supply a comparison operation ID, not permission to inspect originals.
export function parseStagePreparedSummary(input: unknown, operation: unknown, platform: 'android' | 'ios'): StagePreparedIntent | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    return keys(v, [...summaryKeys, ...(platform === 'ios' ? ['bundleId', 'appStoreAppId'] : ['applicationId']), 'storePreconditionSha256']) &&
      hex(v.storePreconditionSha256, 64) && sameOfflineData(v.limitations, STAGE_PREPARE_LIMITS) && summaryIdentity(v, operation, platform) ? v as unknown as StagePreparedIntent : null;
  } catch { return null; }
}
export function parseStageExecutionSummary(input: unknown, operation: unknown, platform: 'android' | 'ios'): StageExecutionReceipt | null {
  try {
    const v = copyBoundedComparisonData(input, 16384);
    if (!keys(v, [...summaryKeys, ...(platform === 'ios' ? ['bundleId', 'appStoreAppId'] : ['applicationId']), 'receiptSha256', 'authorizationId', 'result', 'state']) ||
      !hex(v.receiptSha256, 64) || !uuid(v.authorizationId) || v.result !== 'accepted' || !sameOfflineData(v.limitations, STAGE_EXECUTE_LIMITS) || !summaryIdentity(v, operation, platform)) return null;
    const states = platform === 'android' ? [v.stage === 'external-testing' ? 'available-to-testers' : 'draft'] :
      v.stage === 'external-testing' ? ['available-to-testers', 'submitted-for-review', 'in-review', 'approved'] : ['submitted-for-review', 'in-review', 'approved', 'pending-developer-release'];
    return states.includes(v.state as string) ? v as unknown as StageExecutionReceipt : null;
  } catch { return null; }
}

export function localStoreStageLabel(stage: LocalStoreStage, platform: 'android' | 'ios'): string {
  return stage === 'external-testing' ? (platform === 'ios' ? 'TestFlight external testing' : 'Play external testing') :
    platform === 'ios' ? 'App Store review · manual release' : 'Play production draft';
}
