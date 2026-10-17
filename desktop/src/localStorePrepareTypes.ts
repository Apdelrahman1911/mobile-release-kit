import type { PrepareLocalStorePreflight, LocalStoreIdentity, LocalStoreReason } from './localStorePreflightTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

export interface PrepareLocalStoreIntent extends Omit<PrepareLocalStorePreflight,'platform'> {
  candidateOperationId: string;
  candidateSha256: string;
  confirmation: string;
}
export interface LocalStorePrepareContext extends PrepareLocalStoreIntent {
  platform: 'android'; operation: 'local-store-prepare';
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
export interface LocalStorePrepareResult {
  schemaVersion: 1; scope: 'local-android-store-prepare'; headSequence: number;
  preparedIntent: LocalPreparedIntent;
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
  startLocalStorePrepare(request: LocalStorePrepareIdentity & { consentVersion: 'local-android-store-prepare-v1' }): Promise<LocalStorePrepareStatus>;
  localStorePrepareStatus(): Promise<LocalStorePrepareStatus>;
  cancelLocalStorePrepare(operationId: string, ownerGeneration: string): Promise<LocalStorePrepareStatus>;
  subscribeLocalStorePrepare(listener: (status: unknown) => void): Promise<() => void>;
}
