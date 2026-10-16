import type { LocalPreparedIntent } from './localStorePrepareTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';
export type LocalHistoryAction = 'enroll' | 'verify' | 'review-inputs' | 'abandon-inputs' | 'review-prepared';
export type PrepareLocalHistory = { projectId: string; executionMode: 'local' } & (
  { action: 'enroll' | 'verify'; candidateOperationId?: never } |
  { action: 'review-inputs' | 'abandon-inputs' | 'review-prepared'; candidateOperationId: string }
);
export interface LocalCandidateInputs {
  operationId: string; candidateSha256: string; sourceCommit: string; sourceTree: string;
  applicationId: string; version: { name: string; build: number };
  files: { fileName: 'app-release.aab' | 'store-metadata.zip' | 'validation-report.json'; bytes: number; sha256: string }[];
  observation: 'current-bundle-only'; priorCreateFinality: 'not-established';
}
export interface LocalPreparedIntentReview extends LocalPreparedIntent {
  observation: 'current-prepared-files-only'; priorPrepareFinality: 'not-established';
}
export interface LocalHistoryIdentity { operationId: string; ownerGeneration: string }
export type LocalHistoryReason = 'none'|'cancelled'|'context-changed'|'document-lost'|'shutdown'|'timed-out'|'protocol-error'|'runtime-unavailable'|'intent-expired'|'stale-intent'|'saved-source-changed'|'saved-source-invalid'|'credentials-unavailable'|'query-prerequisites'|'command-incomplete'|'cleanup-unknown'|'journal-unavailable'|'enrollment-exists'|'recovery-required'|'project-busy';
export type LocalJournalPhase = 'inputs-pending'|'inputs-ready'|'prepare-pending'|'prepared'|'execute-pending'|'settled-success'|'settled-failure'|'reconciliation-required';
export interface LocalHistoryResult {
  schemaVersion: 1; scope: 'local-release-history'; enrolled: true; headSequence: number;
  history: { operationId: string; phase: LocalJournalPhase; recoveryRequired: boolean }[];
  limitations: ['no-store-authority', 'no-build-or-publishing', 'keychain-intact-rollback-boundary'];
  candidateInputs?: LocalCandidateInputs | null;
  preparedIntent?: LocalPreparedIntentReview;
}
export interface LocalHistoryOperation extends LocalHistoryIdentity {
  context: PrepareLocalHistory; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome|null; reason: LocalHistoryReason; result: LocalHistoryResult|null;
}
export interface LocalHistoryStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability; operation: LocalHistoryOperation|null;
}
export interface LocalHistoryApi {
  prepareLocalReleaseHistory(request: PrepareLocalHistory): Promise<LocalHistoryStatus>;
  startLocalReleaseHistory(request: LocalHistoryIdentity & {consentVersion:'local-release-history-v1'|'local-android-candidate-inputs-v1'}): Promise<LocalHistoryStatus>;
  localReleaseHistoryStatus(): Promise<LocalHistoryStatus>;
  cancelLocalReleaseHistory(operationId:string, ownerGeneration:string): Promise<LocalHistoryStatus>;
  subscribeLocalReleaseHistory(listener:(status:unknown)=>void): Promise<()=>void>;
}
