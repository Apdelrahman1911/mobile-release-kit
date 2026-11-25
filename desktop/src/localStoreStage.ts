// Current UI eligibility only. Core/native owners authenticate history, source,
// material, metadata and predecessor originals again before any Store action.
import { localStoreRequest, type LocalStoreProject } from './localStorePreflight.ts';
import { localHistoryOwnerReason, type LocalHistoryState } from './localReleaseHistory.ts';
import { parseLocalHistoryStatus } from './localReleaseHistoryProtocol.ts';
import type { AssetDisplayState, AssetKind } from './assetSessionTypes.ts';
import { parseStagePrepareRequest, parseStageExecuteRequest, type StageAssignments, type StageRecord, type LocalStoreStage } from './localStoreStageProtocol.ts';

export function stageInputs(project: LocalStoreProject | null, assets: AssetDisplayState | null) {
  const base = localStoreRequest(project, assets), context = assets?.status?.context;
  if (!base || !context || !assets || assets.scope.stage !== context.stage || assets.scope.purpose !== context.purpose) return null;
  const stage: LocalStoreStage | null = context.stage === 'external-testing' ? 'external-testing' : context.stage === 'production' ? 'production-submit' : null;
  if (!stage) return null;
  if (base.platform !== 'ios') return { ...base, stage, platform: 'android' as const };
  if (typeof project?.iosDemoRequired !== 'boolean') return null;
  const assigned = (kind: AssetKind): StageRecord | null => {
    const rows = assets.status!.assignments.filter(row => row.kind === kind && row.availability === 'available' && row.contextRevision === context.revision);
    if (rows.length !== 1) return null;
    const row = rows[0]!;
    return assets.status!.records.some(record => record.kind === kind && record.recordId === row.recordId && record.revision === row.recordRevision && record.availability === 'assigned') ? { recordId: row.recordId, recordRevision: row.recordRevision } : null;
  };
  const reviewContact = assigned('apple-review-contact'), commitment = assigned('operation-commitment');
  const demoRows = assets.status!.assignments.filter(row => row.kind === 'apple-review-demo');
  const reviewDemo = project.iosDemoRequired ? assigned('apple-review-demo') : null;
  if (!reviewContact || !commitment || project.iosDemoRequired && !reviewDemo || !project.iosDemoRequired && demoRows.length !== 0) return null;
  const supplementalAssignments: StageAssignments = { reviewContact, commitment, reviewDemo };
  return { ...base, stage, platform: 'ios' as const, supplementalAssignments };
}
export function currentReview(history: LocalHistoryState | null, projectId: string) {
  if (!history || history.mode !== 'native' || history.historical || localHistoryOwnerReason(history)) return null;
  const op = parseLocalHistoryStatus(history.status)?.operation;
  return op?.phase === 'terminal' && op.outcome === 'complete' && op.context.projectId === projectId && op.result ? op : null;
}
export function localStoreStagePrepareRequest(project: LocalStoreProject | null, assets: AssetDisplayState | null, history: LocalHistoryState | null) {
  const base = stageInputs(project, assets);
  if (!base) return null;
  const op = currentReview(history, base.projectId), receipt = op?.result?.executionReceipt, last = op?.result?.history.at(-1);
  const readiness = op?.result?.readinessReceipt;
  if (base.platform === 'ios' && base.stage === 'production-submit' && op?.context.action === 'review-external-readiness' && readiness && last &&
      last.phase === 'external-ready' && last.operationId === readiness.operationId && op.context.stageOperationId === readiness.operationId &&
      readiness.version.name === base.savedVersion.name && readiness.version.build === base.savedVersion.build) {
    // Keep the original execution receipt as predecessor. The core selects and
    // authenticates the separate readiness receipt from its anchored journal.
    return parseStagePrepareRequest({...base, candidateOperationId: readiness.candidateOperationId, candidateSha256: readiness.candidateSha256,
      predecessorOperationId: readiness.operationId, predecessorReceiptSha256: readiness.executionReceiptSha256,
      confirmation: `production-submit:ios:${base.savedVersion.name}:${base.savedVersion.build}`});
  }
  if (!op || !receipt || !last || last.operationId !== receipt.operationId || last.phase !== 'settled-success' ||
      (base.platform === 'ios' ? !('bundleId' in receipt) : !('applicationId' in receipt)) ||
      receipt.version.name !== base.savedVersion.name || receipt.version.build !== base.savedVersion.build) return null;
  const later = 'stage' in receipt;
  if (base.stage === 'external-testing') {
    if (later || op.context.action !== 'review-execution' || op.context.candidateOperationId !== receipt.operationId || (op.context.platform ?? 'android') !== base.platform) return null;
  } else if (!later || receipt.stage !== 'external-testing' || op.context.action !== 'review-stage-execution' || op.context.stageOperationId !== receipt.operationId || op.context.platform !== base.platform || receipt.state !== 'available-to-testers') return null;
  return parseStagePrepareRequest({ ...base, candidateOperationId: later ? receipt.candidateOperationId : receipt.operationId,
    candidateSha256: receipt.candidateSha256, predecessorOperationId: receipt.operationId, predecessorReceiptSha256: receipt.receiptSha256,
    confirmation: `${base.stage}:${base.platform}:${base.savedVersion.name}:${base.savedVersion.build}` });
}
export function localStoreStageExecuteContext(project: LocalStoreProject | null, assets: AssetDisplayState | null, history: LocalHistoryState | null) {
  const base = stageInputs(project, assets);
  if (!base) return null;
  const op = currentReview(history, base.projectId), prepared = op?.result?.preparedIntent, last = op?.result?.history.at(-1);
  if (!op || op.context.action !== 'review-stage-prepared' || op.context.platform !== base.platform || !prepared || !('stage' in prepared) ||
      prepared.stage !== base.stage || op.context.stageOperationId !== prepared.operationId || !last || last.operationId !== prepared.operationId || last.phase !== 'prepared' ||
      (base.platform === 'ios' ? !('bundleId' in prepared) : !('applicationId' in prepared)) ||
      prepared.version.name !== base.savedVersion.name || prepared.version.build !== base.savedVersion.build) return null;
  const request = parseStageExecuteRequest({ ...base, stageOperationId: prepared.operationId, intentSha256: prepared.intentSha256,
    candidateOperationId: prepared.candidateOperationId, candidateSha256: prepared.candidateSha256,
    predecessorOperationId: prepared.predecessorOperationId, predecessorReceiptSha256: prepared.predecessorReceiptSha256,
    confirmation: `${base.stage}:${base.platform}:${base.savedVersion.name}:${base.savedVersion.build}` });
  return request ? { request, prepared, head: op.result!.headSequence } : null;
}
