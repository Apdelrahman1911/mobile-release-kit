import type { PrepareLocalStorePreflight, LocalStoreIdentity, LocalStoreReason } from './localStorePreflightTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

export interface PrepareLocalStoreIntent extends PrepareLocalStorePreflight {
  candidateOperationId: string;
  candidateSha256: string;
  confirmation: string;
}
export interface LocalStorePrepareContext extends Omit<PrepareLocalStoreIntent,'platform'> {
  platform: 'android' | 'ios'; operation: 'local-store-prepare';
}
export type LocalStorePrepareIdentity = LocalStoreIdentity;
export interface LocalPreparedIntent {
  operationId: string; candidateSha256: string; intentSha256: string; storePreconditionSha256: string;
  sourceCommit: string; sourceTree: string; applicationId: string;
  version: { name: string; build: number };
  destination: { channel: 'internal'; releaseStatus: 'completed' };
  observedAt: string;
  limitations: ['non-publishing', 'prepare-not-execute', 'temporary-edit-may-expire',
    'current-bundle-not-historical-finality', 'saved-inputs-not-atomic'];
}
export interface IOSPreparedIntent extends Omit<LocalPreparedIntent,'applicationId'|'destination'|'limitations'> {
  bundleId: string; appStoreAppId: string;
  destination: { channel: 'testflight-internal' };
  limitations: ['non-publishing', 'prepare-not-execute', 'current-asc-snapshot-may-change',
    'current-bundle-not-historical-finality', 'saved-inputs-not-atomic'];
}
export type AnyPreparedIntent = LocalPreparedIntent | IOSPreparedIntent;
export interface LocalStorePrepareResult {
  schemaVersion: 1; scope: 'local-android-store-prepare' | 'local-ios-store-prepare'; headSequence: number;
  preparedIntent: AnyPreparedIntent;
}
export interface LocalStorePrepareOperation extends LocalStorePrepareIdentity {
  context: LocalStorePrepareContext; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome | null; reason: LocalStoreReason | 'prepare-unavailable';
  result: LocalStorePrepareResult | null;
}
export interface LocalStorePrepareStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability;
  operation: LocalStorePrepareOperation | null;
}
export interface LocalStorePrepareApi {
  prepareLocalStorePrepare(request: PrepareLocalStoreIntent): Promise<LocalStorePrepareStatus>;
  startLocalStorePrepare(request: LocalStorePrepareIdentity & { consentVersion: 'local-android-store-prepare-v1' | 'local-ios-store-prepare-v1' }): Promise<LocalStorePrepareStatus>;
  localStorePrepareStatus(): Promise<LocalStorePrepareStatus>;
  cancelLocalStorePrepare(operationId: string, ownerGeneration: string): Promise<LocalStorePrepareStatus>;
  subscribeLocalStorePrepare(listener: (status: unknown) => void): Promise<() => void>;
}
