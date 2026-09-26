// Closed comparison/projection DATA, not native tool, file, consent or finality
// custody. Signed export is a separate consented mode, never Store publication
// or authenticated source provenance.
export interface IOSArchiveSavedConfig { bytes: number; sha256: string }
export interface IOSArchiveSavedVersion extends IOSArchiveSavedConfig { source: string; name: string; build: number }
export interface IOSArchiveSavedPair { savedConfig: IOSArchiveSavedConfig; savedVersion: IOSArchiveSavedVersion }
export type IOSArchiveMode = 'unsigned' | 'signed' | 'recovery';
export type IOSSigningKind = 'apple-p12' | 'apple-profile' | 'ios-firebase' | 'project-read-token';
export interface IOSSigningAssignment { kind: IOSSigningKind; recordId: string; recordRevision: number; contextRevision: number }
export interface IOSSigningPolicy { teamId: string; distributionCertificateSha256: string; assignments: IOSSigningAssignment[] }
export interface PrepareIOSBuild extends IOSArchiveSavedPair {
  projectId: string; draftRevision: number; baselineGeneration: number; signing?: IOSSigningPolicy;
}
export type IOSRecoveryIntent = { action: 'inspect'; session?: never } | { action: 'account' | 'project'; session: string };
export interface PrepareIOSRecovery { projectId: string; recovery: IOSRecoveryIntent }
export type PrepareIOSArchive = PrepareIOSBuild | PrepareIOSRecovery;
export interface IOSArchiveIdentity { operationId: string; ownerGeneration: string }
export type StartIOSArchive = IOSArchiveIdentity & (
  { consentVersion: 'saved-ios-unsigned-archive-v1' | 'saved-ios-signed-export-v2'; confirmation?: never } |
  { consentVersion: 'local-ios-recovery-v1'; confirmation?: 'account-signing-is-idle-and-restore-owned-state' | 'project-build-inputs-are-idle-and-restore-owned-state' });
export interface IOSArchiveBuildContext extends PrepareIOSBuild { platform: 'ios'; operation: 'ios-unsigned-archive' | 'ios-signed-export' }
export interface IOSRecoveryContext extends PrepareIOSRecovery { platform: 'ios'; operation: 'ios-local-recovery' }
export type IOSArchiveContext = IOSArchiveBuildContext | IOSRecoveryContext;
export type IOSArchiveAvailability = 'available' | 'busy' | 'shutdown' | 'cleanup-unknown' | 'document-lost' |
  'unsupported-platform' | 'runtime-unqualified' | 'toolchain-unqualified';
export type IOSArchivePhase = 'awaiting-consent' | 'starting' | 'running' | 'stopping' | 'terminal' | 'unknown';
export type IOSArchiveOutcome = 'complete' | 'refused' | 'failed' | 'cancelled' | 'timed-out' | 'unknown';
export type IOSArchiveReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' |
  'protocol-error' | 'runtime-unavailable' | 'intent-expired' | 'stale-intent' |
  `saved-${'config' | 'version'}-${'missing' | 'invalid' | 'changed' | 'sensitive' | 'unsafe' | 'too-large'}` |
  'platform-disabled' | 'container-required' | 'scheme-required' | 'container-missing' | 'toolchain-unavailable' |
  'toolchain-mismatch' | 'project-admission-refused' | 'command-failed' | 'command-incomplete' | 'artifact-missing' |
  'artifact-unsafe' | 'artifact-changed' | 'archive-validation-failed' | 'input-limit' | 'result-limit' | 'work-retained' | 'cleanup-unknown' |
  'signing-policy-required' | 'signing-input-missing' | 'signing-input-invalid' | 'signing-validation-failed' |
  'account-admission-refused' | 'artifact-validation-failed' | 'symbols-upload-not-requested' | 'recovery-attention';
export type IOSRecoveryStage = 'accepted' | 'recovering-account' | 'recovering-project' | 'disposing-work';
export type IOSArchiveStage = 'accepted' | 'inputs-bound' | 'checking-xcode' | 'preparing' | 'archiving' | 'inspecting' |
  'disposing-snapshot' | 'disposing-work' | 'validating-signing' | 'materializing-signing' | 'exporting' | 'restoring-signing' | IOSRecoveryStage;
export type IOSArchiveCoreStatus = 'PASS' | 'FAIL' | 'MISSING' | 'BLOCKED' | 'INVALID' | 'SKIP' | 'MANUAL' | 'CONFIGURED' | 'NOT_APPLICABLE';
export type IOSArchiveCheckId = 'archive-identity' | 'archive-dsym' | 'archive-structure' | 'other-core-finding' |
  'signing-material' | 'profile-material' | 'firebase-material' | 'artifact-correspondence' | 'ipa-structure' |
  'ipa-profile' | 'ipa-entitlements' | 'ipa-signer' | 'ipa-validation' | 'symbols-upload';
export type IOSArchiveUnsignedRole = 'xcode-version' | 'ios-sdk' | 'prepare' | 'archive';
export type IOSArchiveRole = IOSArchiveUnsignedRole | 'export';
export interface IOSArchiveSelection {
  containerKind: 'project' | 'workspace'; container: string; scheme: string; configuration: string; bundleId: string;
  symbolsPolicy: 'disabled' | 'retain' | 'required'; preparationConfigured: boolean;
}
export type IOSArchiveCommandObservation = { outcome: 'exited'; exitCode: number } |
  { outcome: 'not-dispatched' | 'unknown' | 'not-configured'; exitCode: null };
export interface IOSArchiveFinding { check: IOSArchiveCheckId; status: IOSArchiveCoreStatus }
export interface IOSArchiveActivity {
  stage: IOSArchiveStage; selection: IOSArchiveSelection | null;
  commands: Record<IOSArchiveUnsignedRole, IOSArchiveCommandObservation> & { export?: IOSArchiveCommandObservation };
  findings: IOSArchiveFinding[];
}
export type IOSArchiveLimitation = 'saved-inputs-not-atomic' | 'project-build-code-is-trusted' | 'not-network-isolated' |
  'unsigned-archive-not-an-ipa' | 'signing-and-profile-not-validated' | 'ipa-correspondence-not-validated' |
  'source-provenance-not-authenticated' | 'store-operation-not-requested' | 'release-readiness-not-assessed' |
  'retained-location-not-current-file-authority' | 'core-terminal-requires-original-native-finality' | 'single-primary-profile';
interface IOSArchiveResultBase {
  schemaVersion: 1; usedConfig: IOSArchiveSavedConfig;
  usedVersion: IOSArchiveSavedVersion; archive: string; entries: number; bytes: number; limitations: IOSArchiveLimitation[];
}
export type IOSArchiveResult = (IOSArchiveResultBase & { scope: 'local-unsigned-ios-archive-observation' }) |
  (IOSArchiveResultBase & { scope: 'local-signed-ios-artifact-validation'; ipa: string; ipaBytes: number;
    pairing: { nativePaths: number; nativeIdentities: number; presentSymbolSlices: number } });
export interface IOSArchiveDisposition {
  snapshot: 'not-created' | 'removed' | 'unknown'; work: 'not-created' | 'removed' | 'retained-work' | 'unknown';
  output: 'not-created' | 'retained-incomplete' | 'retained-local-result' | 'unknown'; relativeDirectory: string | null;
}
export type IOSRecoveryRowState = 'idle' | 'pending' | 'busy' | 'conflict' | 'manual-required' | 'recovered' | 'recovered-with-conflict' | 'absent' | 'cleanup-only' | 'not-inspected';
export interface IOSRecoveryRow { status: IOSRecoveryRowState; session: string | null; next: 'none' | 'wait' | 'ordinary' | 'manual' | 'preserve' }
export interface IOSRecoveryReport { schemaVersion: 1; scope: 'local-ios-recovery'; account: IOSRecoveryRow | null; project: IOSRecoveryRow | null;
  limitations: ('local-recovery-only' | 'manual-recovery-not-supported' | 'user-confirmation-is-not-worker-finality' | 'no-store-operation')[] }
export interface IOSRecoveryActivity { stage: IOSRecoveryStage }
// This is original native Status, not the provisional Python core terminal.
interface IOSArchiveOperationBase extends IOSArchiveIdentity {
  phase: IOSArchivePhase; intentUsable: boolean; outcome: IOSArchiveOutcome | null; reason: IOSArchiveReason; stage: IOSArchiveStage | null;
}
export interface IOSArchiveBuildOperation extends IOSArchiveOperationBase {
  context: IOSArchiveBuildContext; activity: IOSArchiveActivity | null; disposition: IOSArchiveDisposition | null;
  result: IOSArchiveResult | null; report?: never;
}
export interface IOSRecoveryOperation extends IOSArchiveOperationBase {
  context: IOSRecoveryContext; activity: IOSRecoveryActivity | null; report: IOSRecoveryReport | null; disposition?: never; result?: never;
}
export type IOSArchiveOperation = IOSArchiveBuildOperation | IOSRecoveryOperation;
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
