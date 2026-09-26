// Closed renderer comparison/projection DATA only. These types confer no
// consent, file custody, tool selection, execution, cleanup or native finality.
export interface AndroidBuildSavedConfig { bytes: number; sha256: string }
export interface AndroidBuildSavedVersion extends AndroidBuildSavedConfig { source: string; name: string; build: number }
export interface AndroidBuildSavedPair { savedConfig: AndroidBuildSavedConfig; savedVersion: AndroidBuildSavedVersion }
export type AndroidBuildArtifactValidation = { mode: 'structure-and-version'; uploadCertificateSha256: null } |
  { mode: 'upload-signature'; uploadCertificateSha256: string };
export interface PrepareAndroidBuild extends AndroidBuildSavedPair {
  projectId: string; draftRevision: number; baselineGeneration: number; artifactValidation: AndroidBuildArtifactValidation;
}
export interface AndroidBuildIdentity { operationId: string; ownerGeneration: string }
export interface StartAndroidBuild extends AndroidBuildIdentity { consentVersion: 'saved-android-build-inspect-v2' }
export interface AndroidBuildContext extends PrepareAndroidBuild { platform: 'android'; operation: 'android-build-inspect' }
export type AndroidBuildAvailability = 'available' | 'busy' | 'shutdown' | 'cleanup-unknown' | 'document-lost' |
  'unsupported-platform' | 'runtime-unqualified' | 'toolchain-unqualified';
export type AndroidBuildPhase = 'awaiting-consent' | 'starting' | 'running' | 'stopping' | 'terminal' | 'unknown';
export type AndroidBuildOutcome = 'complete' | 'refused' | 'failed' | 'cancelled' | 'timed-out' | 'unknown';
export type AndroidBuildReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' |
  'protocol-error' | 'runtime-unavailable' | 'intent-expired' | 'stale-intent' |
  `saved-${'config' | 'version'}-${'missing' | 'invalid' | 'changed' | 'sensitive' | 'unsafe' | 'too-large'}` |
  'platform-disabled' | 'module-required' | 'toolchain-unavailable' | 'toolchain-mismatch' | 'project-admission-refused' |
  'command-failed' | 'command-incomplete' | 'artifact-missing' | 'artifact-ambiguous' | 'artifact-unsafe' | 'artifact-changed' |
  'input-limit' | 'result-limit' | 'work-retained' | 'cleanup-unknown';
export type AndroidBuildStage = 'accepted' | 'inputs-bound' | 'building' | 'capturing' | 'inspecting' | 'disposing-work';
export type AndroidBuildCoreStatus = 'PASS' | 'FAIL' | 'MISSING' | 'BLOCKED' | 'INVALID' | 'SKIP' | 'MANUAL' | 'CONFIGURED' | 'NOT_APPLICABLE';
export type AndroidBuildCheckId = 'aab-structure' | 'aab-manifest' | 'application-id' | 'build-number' | 'version-name' |
  'release-flags' | 'signature' | 'signer' | 'core-lifecycle' | 'other-core-finding';
export type AndroidBuildAbi = 'arm64-v8a' | 'armeabi' | 'armeabi-v7a' | 'mips' | 'mips64' | 'x86' | 'x86_64';
export type AndroidBuildLimitation = 'saved-inputs-not-atomic' | 'project-code-effects-possible' | 'not-network-isolated' |
  'post-run-bytes-may-be-incremental-reused-or-stale' | 'source-binding-not-established' | 'artifact-signer-not-inspected' | 'upload-signature-check-not-store-enrollment' |
  'toolkit-signing-not-requested' | 'store-operation-not-requested' | 'release-readiness-not-assessed' |
  'local-output-observation-not-current-file-authority' | 'core-terminal-requires-original-native-finality';
// Selection is a public label, never a renderer-supplied command or argv.
export interface AndroidBuildSelection { module: string; variant: string; applicationId: string; task: string }
export type AndroidBuildCommandObservation = { outcome: 'exited'; exitCode: number } |
  { outcome: 'not-dispatched' | 'unknown'; exitCode: null };
export interface AndroidBuildFinding { ordinal: number; check: AndroidBuildCheckId; status: AndroidBuildCoreStatus }
export interface AndroidBuildSummary { total: number; shown: number; omitted: number; counts: Record<AndroidBuildCoreStatus, number> }
export interface AndroidBuildInspection { findings: AndroidBuildFinding[]; summary: AndroidBuildSummary }
export interface AndroidBuildActivity extends AndroidBuildInspection {
  stage: AndroidBuildStage; selection: AndroidBuildSelection | null; command: AndroidBuildCommandObservation;
}
export interface AndroidBuildArtifact {
  logicalName: 'android-aab'; platform: 'android'; kind: 'aab'; fileName: 'app-release.aab'; size: number; sha256: string;
  architectures: AndroidBuildAbi[]; unknownAbi: boolean; freshness: 'not-established';
}
export interface AndroidBuildAssurances {
  structure: 'passed' | 'failed' | 'not-checked'; nativeManifest: 'passed' | 'failed' | 'not-checked';
  applicationVersion: 'native-checked' | 'not-established'; signature: 'passed' | 'failed' | 'not-checked' | 'not-inspected';
  signer: 'matches-saved-upload-certificate' | 'failed' | 'not-checked' | 'not-inspected'; toolkitSigning: 'not-requested';
  storeOperation: 'not-requested'; sourceBinding: 'not-established'; releaseReadiness: 'not-assessed';
}
export interface AndroidBuildResult extends AndroidBuildInspection {
  schemaVersion: 1; scope: 'local-post-build-artifact-observation'; usedConfig: AndroidBuildSavedConfig;
  usedVersion: AndroidBuildSavedVersion; artifactValidation: AndroidBuildArtifactValidation; selection: AndroidBuildSelection; toolchainProfile: 'android-local-linux-gnu-x86_64-v1';
  command: { outcome: 'exited'; exitCode: 0 }; artifacts: AndroidBuildArtifact[]; assurances: AndroidBuildAssurances;
  limitations: AndroidBuildLimitation[];
}
export interface AndroidBuildDisposition {
  work: 'not-created' | 'removed' | 'retained-work' | 'unknown';
  artifacts: 'not-created' | 'removed' | 'retained-local-result' | 'retained-incomplete' | 'unknown';
}
// This is the native Status projection, NOT a provisional Python core terminal.
// Interim/unknown projections withhold activity, disposition and result. Only
// native terminal finality can publish the paired observations; completion may
// still contain FAIL findings and never means release approval.
export interface AndroidBuildOperation extends AndroidBuildIdentity {
  context: AndroidBuildContext; phase: AndroidBuildPhase; intentUsable: boolean; outcome: AndroidBuildOutcome | null;
  reason: AndroidBuildReason; stage: AndroidBuildStage | null; activity: AndroidBuildActivity | null;
  disposition: AndroidBuildDisposition | null; result: AndroidBuildResult | null;
}
export interface AndroidBuildStatus {
  schemaVersion: 1; statusRevision: number; availability: AndroidBuildAvailability; operation: AndroidBuildOperation | null;
}
// Interface declarations only; no renderer bridge, native command registration,
// preview implementation, Start handler or capability is enabled by this file.
export interface AndroidBuildApi {
  prepareAndroidBuild(request: PrepareAndroidBuild): Promise<AndroidBuildStatus>;
  startAndroidBuild(request: StartAndroidBuild): Promise<AndroidBuildStatus>;
  androidBuildStatus(): Promise<AndroidBuildStatus>;
  cancelAndroidBuild(operationId: string, ownerGeneration: string): Promise<AndroidBuildStatus>;
  subscribeAndroidBuild(onStatus: (status: unknown) => void): Promise<() => void>;
}
