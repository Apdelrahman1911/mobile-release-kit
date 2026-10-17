import type { ExecuteLocalStoreStage, StageExecutionReceipt } from './localStoreStageProtocol.ts';
import type { PrepareLocalCandidateIntent } from './localStorePrepareTypes.ts';
import type { LocalStoreIdentity, LocalStoreReason } from './localStorePreflightTypes.ts';
import type { AndroidMacToolchainSelection } from './androidBuildTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

// Renderer comparison DATA only. Native Document/material/tool originals own admission.
type ExecuteBase = Omit<PrepareLocalCandidateIntent,'platform'> & { intentSha256: string };
export type PrepareLocalStoreExecute = ExecuteLocalStoreStage | ExecuteBase & (
  { platform?: never; toolchainSelection: AndroidMacToolchainSelection } |
  { platform: 'ios'; toolchainSelection?: never }
);
export type LocalStoreExecuteContext = (ExecuteLocalStoreStage & { operation: 'local-store-execute' }) | ExecuteBase & { operation: 'local-store-execute' } & (
  { platform: 'android'; toolchainSelection: AndroidMacToolchainSelection } |
  { platform: 'ios'; toolchainSelection?: never }
);
export type LocalStoreExecuteIdentity = LocalStoreIdentity;
export interface LocalExecutionReceipt {
  operationId: string; candidateSha256: string; intentSha256: string; receiptSha256: string; authorizationId: string;
  sourceCommit: string; sourceTree: string; applicationId: string; version: { name: string; build: number };
  destination: { channel: 'internal'; releaseStatus: 'completed' }; observedAt: string; result: 'accepted' | 'reconciled';
  limitations: ['internal-testing-only', 'not-public-release', 'prior-prepare-finality-not-established', 'saved-inputs-not-atomic'];
}
export interface IOSExecutionReceipt extends Omit<LocalExecutionReceipt,'applicationId'|'destination'> {
  bundleId: string; appStoreAppId: string; destination: { channel: 'testflight-internal' };
}
export interface LocalStoreExecuteResult {
  schemaVersion: 1; scope: 'local-android-store-execute' | 'local-ios-store-execute' | 'local-android-store-stage-execute' | 'local-ios-store-stage-execute'; headSequence: number;
  executionReceipt: LocalExecutionReceipt | IOSExecutionReceipt | StageExecutionReceipt;
}
export interface LocalStoreExecuteOperation extends LocalStoreExecuteIdentity {
  context: LocalStoreExecuteContext; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome | null; reason: LocalStoreReason | 'execute-unavailable'; result: LocalStoreExecuteResult | null;
}
export interface LocalStoreExecuteStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability; operation: LocalStoreExecuteOperation | null;
}
export interface LocalStoreExecuteApi {
  prepareLocalStoreExecute(request: PrepareLocalStoreExecute): Promise<LocalStoreExecuteStatus>;
  startLocalStoreExecute(request: LocalStoreExecuteIdentity & { consentVersion: 'local-android-store-execute-v1' | 'local-ios-store-execute-v1' | 'local-android-store-stage-execute-v1' | 'local-ios-store-stage-execute-v1' }): Promise<LocalStoreExecuteStatus>;
  localStoreExecuteStatus(): Promise<LocalStoreExecuteStatus>;
  cancelLocalStoreExecute(operationId: string, ownerGeneration: string): Promise<LocalStoreExecuteStatus>;
  subscribeLocalStoreExecute(listener: (status: unknown) => void): Promise<() => void>;
}
