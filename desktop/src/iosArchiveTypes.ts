// Closed comparison/projection DATA, not native tool, file, consent or finality
// custody. Signing, IPA export, Store operations and source provenance are not
// part of this unsigned archive operation.
export interface IOSArchiveSavedConfig { bytes: number; sha256: string }
export interface IOSArchiveSavedVersion extends IOSArchiveSavedConfig { source: string; name: string; build: number }
export interface IOSArchiveSavedPair { savedConfig: IOSArchiveSavedConfig; savedVersion: IOSArchiveSavedVersion }
export interface PrepareIOSArchive extends IOSArchiveSavedPair { projectId: string; draftRevision: number; baselineGeneration: number }
export interface IOSArchiveIdentity { operationId: string; ownerGeneration: string }
export interface StartIOSArchive extends IOSArchiveIdentity { consentVersion: 'saved-ios-unsigned-archive-v1' }
export interface IOSArchiveContext extends PrepareIOSArchive { platform: 'ios'; operation: 'ios-unsigned-archive' }
export type IOSArchiveAvailability = 'available' | 'busy' | 'shutdown' | 'cleanup-unknown' | 'document-lost' |
  'unsupported-platform' | 'runtime-unqualified' | 'toolchain-unqualified';
export type IOSArchivePhase = 'awaiting-consent' | 'starting' | 'running' | 'stopping' | 'terminal' | 'unknown';
export type IOSArchiveOutcome = 'complete' | 'refused' | 'failed' | 'cancelled' | 'timed-out' | 'unknown';
export type IOSArchiveReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' |
  'protocol-error' | 'runtime-unavailable' | 'intent-expired' | 'stale-intent' |
  `saved-${'config' | 'version'}-${'missing' | 'invalid' | 'changed' | 'sensitive' | 'unsafe' | 'too-large'}` |
  'platform-disabled' | 'container-required' | 'scheme-required' | 'container-missing' | 'toolchain-unavailable' |
  'toolchain-mismatch' | 'project-admission-refused' | 'command-failed' | 'command-incomplete' | 'artifact-missing' |
  'artifact-unsafe' | 'artifact-changed' | 'archive-validation-failed' | 'input-limit' | 'result-limit' | 'work-retained' | 'cleanup-unknown';
export type IOSArchiveStage = 'accepted' | 'inputs-bound' | 'checking-xcode' | 'preparing' | 'archiving' | 'inspecting' |
  'disposing-snapshot' | 'disposing-work';
export type IOSArchiveCoreStatus = 'PASS' | 'FAIL' | 'MISSING' | 'BLOCKED' | 'INVALID' | 'SKIP' | 'MANUAL' | 'CONFIGURED' | 'NOT_APPLICABLE';
export type IOSArchiveCheckId = 'archive-identity' | 'archive-dsym' | 'archive-structure' | 'other-core-finding';
export type IOSArchiveRole = 'xcode-version' | 'ios-sdk' | 'prepare' | 'archive';
export interface IOSArchiveSelection {
  containerKind: 'project' | 'workspace'; container: string; scheme: string; configuration: string; bundleId: string;
  symbolsPolicy: 'disabled' | 'retain' | 'required'; preparationConfigured: boolean;
}
export type IOSArchiveCommandObservation = { outcome: 'exited'; exitCode: number } |
  { outcome: 'not-dispatched' | 'unknown' | 'not-configured'; exitCode: null };
export interface IOSArchiveFinding { check: IOSArchiveCheckId; status: IOSArchiveCoreStatus }
export interface IOSArchiveActivity {
  stage: IOSArchiveStage; selection: IOSArchiveSelection | null; commands: Record<IOSArchiveRole, IOSArchiveCommandObservation>;
  findings: IOSArchiveFinding[];
}
export type IOSArchiveLimitation = 'saved-inputs-not-atomic' | 'project-build-code-is-trusted' | 'not-network-isolated' |
  'unsigned-archive-not-an-ipa' | 'signing-and-profile-not-validated' | 'ipa-correspondence-not-validated' |
  'source-provenance-not-authenticated' | 'store-operation-not-requested' | 'release-readiness-not-assessed' |
  'retained-location-not-current-file-authority' | 'core-terminal-requires-original-native-finality';
export interface IOSArchiveResult {
  schemaVersion: 1; scope: 'local-unsigned-ios-archive-observation'; usedConfig: IOSArchiveSavedConfig;
  usedVersion: IOSArchiveSavedVersion; archive: string; entries: number; bytes: number; limitations: IOSArchiveLimitation[];
}
export interface IOSArchiveDisposition {
  snapshot: 'not-created' | 'removed' | 'unknown'; work: 'not-created' | 'removed' | 'retained-work' | 'unknown';
  output: 'not-created' | 'retained-incomplete' | 'retained-local-result' | 'unknown'; relativeDirectory: string | null;
}
// This is original native Status, not the provisional Python core terminal.
export interface IOSArchiveOperation extends IOSArchiveIdentity {
  context: IOSArchiveContext; phase: IOSArchivePhase; intentUsable: boolean; outcome: IOSArchiveOutcome | null;
  reason: IOSArchiveReason; stage: IOSArchiveStage | null; activity: IOSArchiveActivity | null;
  disposition: IOSArchiveDisposition | null; result: IOSArchiveResult | null;
}
export interface IOSArchiveStatus {
  schemaVersion: 1; statusRevision: number; availability: IOSArchiveAvailability; operation: IOSArchiveOperation | null;
}
export interface IOSArchiveApi {
  prepareIOSArchive(request: PrepareIOSArchive): Promise<IOSArchiveStatus>;
  startIOSArchive(request: StartIOSArchive): Promise<IOSArchiveStatus>;
  iosArchiveStatus(): Promise<IOSArchiveStatus>;
  cancelIOSArchive(operationId: string, ownerGeneration: string): Promise<IOSArchiveStatus>;
  subscribeIOSArchive(onStatus: (status: unknown) => void): Promise<() => void>;
}
