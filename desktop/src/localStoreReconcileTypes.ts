import type { StageAssignments } from './localStoreStageProtocol.ts';
import type { ExternalReadinessReceipt } from './localExternalReadinessProtocol.ts';
import type { PrepareLocalCandidateIntent } from './localStorePrepareTypes.ts';
import type { LocalStoreIdentity, LocalStoreReason } from './localStorePreflightTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

// Renderer comparison DATA only. Native Document/material/tool originals own admission.
type ReconcileBase = Omit<PrepareLocalCandidateIntent,'platform'> & { intentSha256: string };
type CandidateReconcile = { action?: never; stageOperationId?: never; executionReceiptSha256?: never; supplementalAssignments?: never };
export type PrepareExternalReadiness = ReconcileBase & { platform: 'ios'; action: 'external-readiness'; stageOperationId: string;
  executionReceiptSha256: string; supplementalAssignments: StageAssignments; settlement?: never };
export type PrepareLocalStoreReconcile = (ReconcileBase & CandidateReconcile & (
  { platform?: never; settlement?: 'record-current-target' } | { platform: 'ios'; settlement?: never }
)) | PrepareExternalReadiness;
export type LocalStoreReconcileContext = (ReconcileBase & CandidateReconcile & (
  { platform: 'android'; operation: 'local-store-reconcile' | 'local-store-recovery-settle'; settlement?: 'record-current-target' } |
  { platform: 'ios'; operation: 'local-store-reconcile'; settlement?: never }
)) | (PrepareExternalReadiness & { operation: 'local-store-reconcile' });
export type LocalStoreReconcileIdentity = LocalStoreIdentity;
export interface LocalReconciliationReceipt {
  operationId: string; candidateSha256: string; intentSha256: string; receiptSha256: string; authorizationId: string;
  sourceCommit: string; sourceTree: string; applicationId: string; version: { name: string; build: number };
  destination: { channel: 'internal'; releaseStatus: 'completed' }; observedAt: string; result: 'reconciled';
  observation: 'current-internal-target-only'; priorExecutionFinality: 'not-established';
  limitations: ['non-publishing', 'not-retry-permission', 'old-evidence-preserved', 'saved-inputs-not-atomic'];
}
export interface IOSReconciliationReceipt extends Omit<LocalReconciliationReceipt,'applicationId'|'destination'|'observation'> {
  bundleId: string; appStoreAppId: string; destination: { channel: 'testflight-internal' }; observation: 'current-internal-build-only';
}
export type LocalStoreReconcileResult = { schemaVersion: 1; headSequence: number } & (
  { scope: 'local-android-store-reconcile' | 'local-android-recovery-settlement' | 'local-ios-store-reconcile';
    reconciliationReceipt: LocalReconciliationReceipt | IOSReconciliationReceipt; readinessReceipt?: never } |
  { scope: 'local-ios-external-readiness'; readinessReceipt: ExternalReadinessReceipt; reconciliationReceipt?: never }
);
export interface LocalStoreReconcileOperation extends LocalStoreReconcileIdentity {
  context: LocalStoreReconcileContext; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome | null; reason: LocalStoreReason | 'reconcile-unavailable' | 'recovery-settle-unavailable'; result: LocalStoreReconcileResult | null;
}
export interface LocalStoreReconcileStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability; operation: LocalStoreReconcileOperation | null;
}
export interface LocalStoreReconcileApi {
  prepareLocalStoreReconcile(request: PrepareLocalStoreReconcile): Promise<LocalStoreReconcileStatus>;
  startLocalStoreReconcile(request: LocalStoreReconcileIdentity & { consentVersion: 'local-ios-external-readiness-v1' | 'local-android-store-reconcile-v1' | 'local-android-recovery-settle-v1' | 'local-ios-store-reconcile-v1' }): Promise<LocalStoreReconcileStatus>;
  localStoreReconcileStatus(): Promise<LocalStoreReconcileStatus>;
  cancelLocalStoreReconcile(operationId: string, ownerGeneration: string): Promise<LocalStoreReconcileStatus>;
  subscribeLocalStoreReconcile(listener: (status: unknown) => void): Promise<() => void>;
}
