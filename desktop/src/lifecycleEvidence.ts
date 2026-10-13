import type { BridgeMode, HelpContent } from './types.ts';
import type { CandidateEvidence, EvidencePhase, EvidenceProblem, EvidenceView } from './candidateEvidence.ts';
import { EvidenceController, cleanEvidenceData, fields, one, text, counter, operationId, selectionId, sha, freeze,
  summaryShape, assuranceShape, runsShape } from './candidateEvidence.ts';

export const evidenceStages = ['candidate', 'external-testing', 'production-submit'] as const;
export type EvidenceStage = typeof evidenceStages[number];
export const stageLabels: Record<EvidenceStage, string> = { candidate: 'Candidate', 'external-testing': 'External testing', 'production-submit': 'Production submission' };
export const SAVED_EVIDENCE_WARNING = 'Saved documents only, not live Store status or retry approval.';
export const documentPaths: Record<EvidenceStage, readonly string[]> = {
  candidate: ['candidate-receipt.json', 'candidate-manifest.json', 'operation/candidate-operation-intent.json'],
  'external-testing': ['external-testing-receipt.json', 'operation/external-testing-operation-intent.json',
    'operation/candidate/candidate-receipt.json', 'operation/candidate/candidate-manifest.json', 'operation/candidate/operation/candidate-operation-intent.json'],
  'production-submit': ['production-submit-receipt.json', 'operation/production-submit-operation-intent.json',
    'operation/candidate/candidate-receipt.json', 'operation/candidate/candidate-manifest.json', 'operation/candidate/operation/candidate-operation-intent.json',
    'operation/external/external-testing-receipt.json', 'operation/external/operation/external-testing-operation-intent.json',
    'operation/external/operation/candidate/candidate-receipt.json', 'operation/external/operation/candidate/candidate-manifest.json',
    'operation/external/operation/candidate/operation/candidate-operation-intent.json'],
};
// Closed presentation messages, not a TypeScript release-policy evaluator.
// The existing core selects the reason after validating the complete chain.
const guidanceMessages = {
  'evidence-invalid': 'Some saved documents are invalid. Recovery is undetermined; no retry or release is approved.',
  'evidence-incomplete': 'Expected saved documents are missing. This does not prove that no Store operation occurred. Recovery is undetermined.',
  'evidence-inconsistent': 'The saved documents disagree. Keep the original evidence; this inspection cannot approve recovery or a retry.',
  'candidate-only': 'Only candidate evidence was supplied. Later stages and recovery remain undetermined; these saved documents do not approve another operation.',
  'ios-external-not-available': 'iOS production requires an external receipt whose readback.state is available-to-testers; start a NEW external-testing dispatch after Beta Review approval using the original candidate, without recovery_run_id. Rerunning the old dispatch preserves its immutable pending receipt.',
  'android-external-observation-only': 'Android production requires an external receipt produced by a confirmed promotion; an observation-only already-present receipt is not authorization',
  'recorded-external-gate': 'The saved external receipt satisfies the recorded external-to-production predicate only. Workflow authenticity, current configuration and live Store state are unverified; no release or retry is approved.',
  'production-recorded': 'A production receipt is recorded in this local chain. It is not a live Store observation or proof of publication, and does not approve replay or recovery.',
} as const;
export interface LifecycleEvidence {
  schemaVersion: 1; stage: EvidenceStage; outcome: CandidateEvidence['outcome'];
  documents: { path: string; state: 'missing' | 'invalid' | 'valid' }[];
  summary: CandidateEvidence['summary']; assurance: CandidateEvidence['assurance'];
  history: { stage: EvidenceStage; recordedOutcome: 'mutated' | 'reconciled' | 'already-present' | 'operator-authorized-reconciliation' | 'operator-authorized-retry' | 'operator-authorized-create-retry';
    recordedReadback: string; recordedRuns: NonNullable<CandidateEvidence['summary']>['recordedRuns'];
    receiptSha256: string; intentSha256: string; previousReceiptSha256: string | null }[];
  guidance: { code: keyof typeof guidanceMessages; message: string };
}
export interface LifecycleEvidenceSelection { selectionId: string; displayName: string; stage: EvidenceStage }
export interface LifecycleEvidenceOperation { operationId: string; kind: 'choose' | 'observe'; selectionId: string | null; stage: EvidenceStage }
export interface LifecycleEvidenceStatus {
  schemaVersion: 1; revision: string; availability: 'available' | 'unavailable'; phase: EvidencePhase;
  selection: LifecycleEvidenceSelection | null; operation: LifecycleEvidenceOperation | null; result: LifecycleEvidence | null; problem: EvidenceProblem | null;
}
export interface LifecycleEvidenceApi {
  chooseReleaseEvidenceFolder(stage: EvidenceStage): Promise<LifecycleEvidenceStatus>;
  releaseEvidenceStatus(): Promise<LifecycleEvidenceStatus>;
  observeReleaseEvidence(selectionId: string): Promise<LifecycleEvidenceStatus>;
  cancelReleaseEvidence(operationId: string, selectionId: string | null): Promise<LifecycleEvidenceStatus>;
}
export type LifecycleEvidenceCommand = 'release_evidence_choose' | 'release_evidence_status' | 'release_evidence_observe' | 'release_evidence_cancel';
export type LifecycleEvidenceView = EvidenceView<LifecycleEvidenceStatus>;
export function lifecycleEvidenceRequestFits(command: LifecycleEvidenceCommand, value: unknown): value is Record<string, unknown> {
  try {
    const input = cleanEvidenceData(value);
    if (command === 'release_evidence_choose') return fields(input, ['stage']) && one(input.stage, evidenceStages);
    if (command === 'release_evidence_status') return fields(input, []);
    if (command === 'release_evidence_observe') return fields(input, ['selectionId']) && selectionId(input.selectionId);
    return command === 'release_evidence_cancel' && fields(input, ['operationId', 'selectionId']) && operationId(input.operationId)
      && (input.selectionId === null || selectionId(input.selectionId));
  } catch { return false; }
}
function resultShape(input: unknown): input is LifecycleEvidence {
  if (!fields(input, ['schemaVersion', 'stage', 'outcome', 'documents', 'summary', 'history', 'guidance', 'assurance']) || input.schemaVersion !== 1
      || !one(input.stage, evidenceStages) || !one(input.outcome, ['consistent', 'incomplete', 'invalid', 'inconsistent'])
      || !Array.isArray(input.documents) || input.documents.length !== documentPaths[input.stage].length || !Array.isArray(input.history)
      || !assuranceShape(input.assurance) || !fields(input.guidance, ['code', 'message'])
      || !one(input.guidance.code, Object.keys(guidanceMessages) as (keyof typeof guidanceMessages)[])
      || input.guidance.message !== guidanceMessages[input.guidance.code]) return false;
  const paths = documentPaths[input.stage];
  if (!input.documents.every((row: unknown, i) => fields(row, ['path', 'state']) && row.path === paths[i] && one(row.state, ['missing', 'invalid', 'valid']))) return false;
  const invalid = input.documents.some((row) => row.state === 'invalid');
  const missing = input.documents.some((row) => row.state === 'missing');
  if (input.outcome !== 'consistent') return input.summary === null && input.history.length === 0 && input.guidance.code === `evidence-${input.outcome}`
    && (input.outcome === 'invalid' ? invalid : input.outcome === 'incomplete' ? !invalid && missing : !invalid && !missing);
  if (invalid || missing || !summaryShape(input.summary) || input.history.length !== evidenceStages.indexOf(input.stage) + 1) return false;
  let previous: string | null = null;
  if (!input.history.every((row: unknown, i) => {
    if (!fields(row, ['stage', 'recordedOutcome', 'recordedReadback', 'recordedRuns', 'receiptSha256', 'intentSha256', 'previousReceiptSha256'])
        || row.stage !== evidenceStages[i] || !one(row.recordedOutcome, ['mutated', 'reconciled', 'already-present', 'operator-authorized-reconciliation', 'operator-authorized-retry', 'operator-authorized-create-retry'])
        || !text(row.recordedReadback, 64, 256) || !runsShape(row.recordedRuns) || !sha(row.receiptSha256) || !sha(row.intentSha256) || row.previousReceiptSha256 !== previous) return false;
    previous = row.receiptSha256; return true;
  })) return false;
  const first = input.history[0] as LifecycleEvidence['history'][number];
  if (first.receiptSha256 !== input.summary.documentPayloadSha256.receipt || first.intentSha256 !== input.summary.documentPayloadSha256.intent) return false;
  if (input.stage === 'candidate') return input.guidance.code === 'candidate-only';
  if (input.stage === 'production-submit') return input.guidance.code === 'production-recorded';
  return input.guidance.code === 'recorded-external-gate'
    || input.guidance.code === 'ios-external-not-available' && input.summary.platform === 'ios'
    || input.guidance.code === 'android-external-observation-only' && input.summary.platform === 'android';
}
export function parseLifecycleEvidence(value: unknown): LifecycleEvidence | null {
  try { const input = cleanEvidenceData(value); return resultShape(input) ? freeze(input) : null; } catch { return null; }
}
export function parseLifecycleEvidenceStatus(value: unknown): LifecycleEvidenceStatus | null {
  try {
    const input = cleanEvidenceData(value);
    if (!fields(input, ['schemaVersion', 'revision', 'availability', 'phase', 'selection', 'operation', 'result', 'problem']) || input.schemaVersion !== 1 || !counter(input.revision)
        || !one(input.availability, ['available', 'unavailable']) || !one(input.phase, ['idle', 'choosing', 'selected', 'observing', 'observed', 'stopping', 'cancelled', 'refused', 'unknown'])
        || input.problem !== null && !one(input.problem, ['unavailable', 'busy', 'cancelled', 'stale_selection', 'unsafe_selection', 'observation_failed', 'limit', 'deadline', 'cleanup_unknown'])) return null;
    const selection = input.selection; const op = input.operation;
    if (selection !== null && (!fields(selection, ['selectionId', 'displayName', 'stage']) || !selectionId(selection.selectionId) || !text(selection.displayName, 128, 512)
        || /[/\\]/.test(selection.displayName) || !one(selection.stage, evidenceStages))) return null;
    if (op !== null && (!fields(op, ['operationId', 'kind', 'selectionId', 'stage']) || !operationId(op.operationId) || !one(op.kind, ['choose', 'observe'])
        || !one(op.stage, evidenceStages) || (op.kind === 'choose' ? op.selectionId !== null : !selectionId(op.selectionId))
        || selection !== null && (selection as unknown as LifecycleEvidenceSelection).stage !== op.stage)) return null;
    const s = selection as LifecycleEvidenceSelection | null; const o = op as LifecycleEvidenceOperation | null;
    if (input.availability === 'unavailable') {
      if (input.phase !== 'idle' || s !== null || o !== null || input.result !== null || input.problem !== 'unavailable') return null;
    } else {
      if (input.phase === 'idle' && (s !== null || o !== null || input.result !== null || input.problem !== null)) return null;
      if (['choosing', 'selected', 'observing', 'observed'].includes(input.phase) && (!o || input.problem !== null)) return null;
      if (input.phase === 'choosing' && (o?.kind !== 'choose' || s !== null)) return null;
      if (input.phase === 'selected' && (o?.kind !== 'choose' || !s)) return null;
      if (['observing', 'observed'].includes(input.phase) && (o?.kind !== 'observe' || !s || s.selectionId !== o.selectionId)) return null;
      if (['stopping', 'cancelled', 'refused', 'unknown'].includes(input.phase) && input.problem === null) return null;
      if ((input.phase === 'unknown') !== (input.problem === 'cleanup_unknown')) return null;
      if (input.phase === 'stopping' && !o || input.phase === 'cancelled' && (!o || input.problem !== 'cancelled')) return null;
      if (input.phase === 'observed' ? !resultShape(input.result) || input.result.stage !== s?.stage : input.result !== null) return null;
    }
    return freeze(input as unknown as LifecycleEvidenceStatus);
  } catch { return null; }
}
export class LifecycleEvidenceController extends EvidenceController<LifecycleEvidenceStatus> {
  constructor(otherOperationReason: () => string | null = () => null) { super(otherOperationReason, 'lifecycle', parseLifecycleEvidenceStatus); }
  connect(api: LifecycleEvidenceApi & { mode: BridgeMode }): Promise<void> {
    return this.connectEvidence({ mode: api.mode, evidenceStatus: () => api.releaseEvidenceStatus(),
      chooseEvidenceFolder: (stage) => api.chooseReleaseEvidenceFolder(stage!),
      observeEvidence: (id) => api.observeReleaseEvidence(id), cancelEvidence: (id, selection) => api.cancelReleaseEvidence(id, selection) });
  }
  setStage(stage: EvidenceStage): void { this.changeStage(stage); }
}
export const releaseEvidenceHelp: HelpContent = {
  label: 'Saved release evidence folder', requiredness: 'optional', requiredWhen: 'Only to inspect an existing local final-evidence folder; no source project is required.',
  what: 'Saved candidate, external-testing or production-submission documents from one protected workflow run, with their nested predecessor evidence.',
  why: 'Shows local document consistency, the stages recorded in this folder, and bounded core guidance. It is not authenticated or global history.',
  where: 'Download and extract the evidence artifact from your protected release workflow run. Choose its final evidence folder, not your project or ZIP. Keep nested folders unchanged.',
  format: 'Select the stage, then choose the final folder. Candidate has three selected JSON documents, external testing five, and production submission ten. At most 2 MiB per document and 6 MiB in total, including repeated copies.',
  failure: 'Missing, invalid or conflicting documents leave recovery undetermined. Payloads, ZIPs, workflow proof and live Store state are not inspected; no file is changed and no retry is approved.',
};
