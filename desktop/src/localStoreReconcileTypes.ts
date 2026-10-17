import type { PrepareLocalStoreIntent } from './localStorePrepareTypes.ts';
import type { LocalStoreIdentity, LocalStoreReason } from './localStorePreflightTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

// Renderer comparison DATA only. Native Document/material/tool originals own admission.
export type PrepareLocalStoreReconcile = Omit<PrepareLocalStoreIntent,'platform'> & { intentSha256: string } & (
  { platform?: never; settlement?: 'record-current-target' } | { platform: 'ios'; settlement?: never }
);
export type LocalStoreReconcileContext = Omit<PrepareLocalStoreIntent,'platform'> & { intentSha256: string } & (
  { platform: 'android'; operation: 'local-store-reconcile' | 'local-store-recovery-settle'; settlement?: 'record-current-target' } |
  { platform: 'ios'; operation: 'local-store-reconcile'; settlement?: never }
);
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
export interface LocalStoreReconcileResult {
  schemaVersion: 1; scope: 'local-android-store-reconcile' | 'local-android-recovery-settlement' | 'local-ios-store-reconcile'; headSequence: number; reconciliationReceipt: LocalReconciliationReceipt | IOSReconciliationReceipt;
}
export interface LocalStoreReconcileOperation extends LocalStoreReconcileIdentity {
  context: LocalStoreReconcileContext; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome | null; reason: LocalStoreReason | 'reconcile-unavailable' | 'recovery-settle-unavailable'; result: LocalStoreReconcileResult | null;
}
export interface LocalStoreReconcileStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability; operation: LocalStoreReconcileOperation | null;
}
export interface LocalStoreReconcileApi {
  prepareLocalStoreReconcile(request: PrepareLocalStoreReconcile): Promise<LocalStoreReconcileStatus>;
  startLocalStoreReconcile(request: LocalStoreReconcileIdentity & { consentVersion: 'local-android-store-reconcile-v1' | 'local-android-recovery-settle-v1' | 'local-ios-store-reconcile-v1' }): Promise<LocalStoreReconcileStatus>;
  localStoreReconcileStatus(): Promise<LocalStoreReconcileStatus>;
  cancelLocalStoreReconcile(operationId: string, ownerGeneration: string): Promise<LocalStoreReconcileStatus>;
  subscribeLocalStoreReconcile(listener: (status: unknown) => void): Promise<() => void>;
}
