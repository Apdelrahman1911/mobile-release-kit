// Comparison/result DATA only. Native retains the original project, private
// checkpoint review, one-use intent, execution and finality.
export type ProjectRecoveryAction = 'inspect' | 'recover';
export type ProjectRecoveryInspectionStatus = 'idle' | 'busy' | 'conflict' | 'pending' | 'cleanup-only';
export type ProjectRecoveryQuiescence = 'none' | 'original' | 'operator';
export type ProjectRecoveryRole = 'android-services' | 'ios-services';
export interface ProjectRecoveryObservation {
  status: ProjectRecoveryInspectionStatus; session: string | null; roles: ProjectRecoveryRole[]; quiescence: ProjectRecoveryQuiescence;
}
export interface PrepareProjectRecovery {
  projectId: string; draftRevision: number; baselineGeneration: number; action: ProjectRecoveryAction;
}
export interface ProjectRecoveryContext extends PrepareProjectRecovery { review: ProjectRecoveryObservation | null }
export interface ProjectRecoveryIdentity { operationId: string; ownerGeneration: string }
export interface StartProjectRecovery extends ProjectRecoveryIdentity { consentVersion: 'reviewed-project-build-input-recovery-v1' }
export type ProjectRecoveryAvailability = 'available' | 'busy' | 'shutdown' | 'cleanup-unknown' | 'document-lost' | 'unsupported-platform' | 'runtime-unqualified';
export type ProjectRecoveryPhase = 'awaiting-consent' | 'starting' | 'running' | 'stopping' | 'terminal' | 'unknown';
export type ProjectRecoveryOutcome = 'complete' | 'refused' | 'cancelled' | 'timed-out' | 'failed' | 'unknown';
export type ProjectRecoveryReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' | 'protocol-error' |
  'runtime-unavailable' | 'intent-expired' | 'stale-intent' | 'project-changed' | 'review-stale' | 'manual-required' | 'project-busy' |
  'project-conflict' | 'recovery-incomplete' | 'input-limit' | 'result-limit' | 'cleanup-unknown';
export type ProjectRecoveryEffect = 'not-attempted' | 'inspection' | 'recovery-attempted';
export type ProjectRecoveryLimitation = 'build-inputs-only-not-store-or-account-recovery' | 'recorded-quiescence-not-new-worker-proof' |
  'foreign-changes-preserved' | 'cancellation-does-not-undo-completed-cleanup' | 'project-and-release-readiness-not-assessed';
export interface ProjectRecoveryResult {
  schemaVersion: 1; scope: 'project-build-inputs-only'; action: ProjectRecoveryAction;
  observation: ProjectRecoveryObservation | null; recoveredSession: string | null; limitations: ProjectRecoveryLimitation[];
}
export interface ProjectRecoveryOperation extends ProjectRecoveryIdentity {
  context: ProjectRecoveryContext; phase: ProjectRecoveryPhase; intentUsable: boolean; outcome: ProjectRecoveryOutcome | null;
  reason: ProjectRecoveryReason; result: ProjectRecoveryResult | null; effect: ProjectRecoveryEffect | null;
}
export interface ProjectRecoveryStatus {
  schemaVersion: 1; statusRevision: number; availability: ProjectRecoveryAvailability; operation: ProjectRecoveryOperation | null;
}
export interface ProjectRecoveryApi {
  prepareProjectRecovery(request: PrepareProjectRecovery): Promise<ProjectRecoveryStatus>;
  startProjectRecovery(request: StartProjectRecovery): Promise<ProjectRecoveryStatus>;
  projectRecoveryStatus(): Promise<ProjectRecoveryStatus>;
  cancelProjectRecovery(operationId: string, ownerGeneration: string): Promise<ProjectRecoveryStatus>;
  subscribeProjectRecovery(onStatus: (status: unknown) => void): Promise<() => void>;
}
