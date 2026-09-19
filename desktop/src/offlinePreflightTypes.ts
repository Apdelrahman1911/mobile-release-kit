// Closed comparison/result DATA only. Native owns admission, execution and finality.
export interface SavedConfigContent { bytes: number; sha256: string }
export interface PrepareOfflinePreflight {
  projectId: string; draftRevision: number; baselineGeneration: number; savedConfig: SavedConfigContent;
}
export interface OfflinePreflightIdentity { operationId: string; ownerGeneration: string }
export interface StartOfflinePreflight extends OfflinePreflightIdentity { consentVersion: 'saved-offline-android-v1' }
export interface OfflinePreflightContext extends PrepareOfflinePreflight { platform: 'android'; operation: 'offline-preflight' }
export type OfflinePreflightAvailability = 'available' | 'busy' | 'shutdown' | 'cleanup-unknown' | 'document-lost' | 'unsupported-platform' | 'runtime-unqualified';
export type OfflinePreflightPhase = 'awaiting-consent' | 'starting' | 'running' | 'stopping' | 'terminal' | 'unknown';
export type OfflinePreflightOutcome = 'complete' | 'refused' | 'cancelled' | 'timed-out' | 'failed' | 'unknown';
export type OfflinePreflightReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' | 'protocol-error' |
  'runtime-unavailable' | 'intent-expired' | 'stale-intent' | 'saved-config-missing' | 'saved-config-invalid' | 'saved-config-changed' |
  'saved-config-sensitive' | 'saved-config-unsafe' | 'saved-config-too-large' | 'platform-disabled' | 'project-admission-refused' |
  'input-limit' | 'result-limit' | 'command-incomplete' | 'cleanup-unknown';
export type OfflineCoreStatus = 'PASS' | 'FAIL' | 'MISSING' | 'BLOCKED' | 'INVALID' | 'SKIP' | 'MANUAL' | 'CONFIGURED' | 'NOT_APPLICABLE';
export type OfflineCheckId = 'version-source' | 'platform-selection' | 'android-module' | 'android-gradle-wrapper' | 'android-debug-identity' |
  'workspace-private-output' | 'android-artifact' | 'preflight-early-exit' | 'configuration-policy' | 'metadata-policy' |
  'configured-project-check' | 'core-lifecycle' | 'other-core-finding';
export type OfflineLimitation = 'saved-inputs-not-atomic' | 'project-code-effects-possible' | 'not-network-isolated' | 'core-builds-disabled' |
  'artifact-validation-not-requested' | 'toolkit-signing-credentials-store-not-requested' | 'release-readiness-not-assessed';
export interface OfflinePreflightFinding {
  ordinal: number; check: OfflineCheckId; status: OfflineCoreStatus; message: OfflineCheckId; projectCheckIndex: number | null;
}
export interface OfflinePreflightResult {
  schemaVersion: 1; scope: 'saved-offline-android-no-core-build'; usedConfig: SavedConfigContent;
  findings: OfflinePreflightFinding[];
  summary: { total: number; shown: number; omitted: number; counts: Record<OfflineCoreStatus, number> };
  limitations: OfflineLimitation[];
}
export interface OfflinePreflightOperation extends OfflinePreflightIdentity {
  context: OfflinePreflightContext; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome | null; reason: OfflinePreflightReason; result: OfflinePreflightResult | null;
}
export interface OfflinePreflightStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability; operation: OfflinePreflightOperation | null;
}
export interface OfflinePreflightApi {
  prepareOfflinePreflight(request: PrepareOfflinePreflight): Promise<OfflinePreflightStatus>;
  startOfflinePreflight(request: StartOfflinePreflight): Promise<OfflinePreflightStatus>;
  offlinePreflightStatus(): Promise<OfflinePreflightStatus>;
  cancelOfflinePreflight(operationId: string, ownerGeneration: string): Promise<OfflinePreflightStatus>;
  subscribeOfflinePreflight(onStatus: (status: unknown) => void): Promise<() => void>;
}
