// Nonsecret UI DATA. Neither a source hash nor a prepared status is authority
// to run a workflow: native one-use consent and original finality remain owed.
import type { GitHubRunStatus, GitHubRunConclusion } from './githubPreflightTypes.ts';
export type GitHubReleasePlatform = 'android' | 'ios';
export type GitHubReleaseStage = 'candidate' | 'external-testing' | 'production-submit';
export interface GitHubReleaseVersion { name: string; build: number }
export interface GitHubReleaseSelection {
  stage: GitHubReleaseStage; candidateRunId: string | null; externalRunId: string | null; recoveryRunId: string | null;
  originalSourceSha: string | null; originalVersion: GitHubReleaseVersion | null;
  recoveryConfirmation?: string; // Omitted when absent, preserving original pending-record bytes.
}
export type GitHubReleaseKind = 'prepare' | 'dispatch' | 'track' | 'reconcile' | 'pending';
export type GitHubReleaseReason = 'none' | 'unqualified' | 'publisher-unconfigured' | 'not-connected' | 'busy' |
  'invalid-input' | 'target-changed' | 'expired' | 'rate-limited' | 'cancelled' | 'cleanup-unknown' | 'runtime-unavailable' |
  'consent-expired' | 'caller-mismatch' | 'workflow-unavailable' | 'source-changed' | 'unresolved-run' | 'ambiguous-run' |
  'run-changed' | 'jobs-incomplete' | 'unauthorized' | 'forbidden' | 'not-found-or-inaccessible' | 'network-unavailable' |
  'tls-failed' | 'response-invalid' | 'response-limit' | 'config-invalid' | 'version-invalid' | 'platform-disabled' | 'branch-mismatch' | 'source-tree-unavailable';
export type GitHubReleaseEffect = 'none' | 'not-sent' | 'potentially-applied' | 'accepted';
export interface GitHubReleaseTarget {
  projectBinding: string; repository: string; accountId: string; repositoryId: string; branch: string;
  toolingRepository: 'Apdelrahman1911/mobile-release-kit'; toolingSha: string; platform: GitHubReleasePlatform; marker: string; selection: GitHubReleaseSelection;
}
export interface GitHubReleasePrepared {
  target: GitHubReleaseTarget; sourceSha: string; sourceTree: string; workflowId: string; workflowPath: string;
  callerSha256: string; observedAt: string; expectedRef: string; displayTitle: string; confirmation: string;
  configSha256: string; versionSource: string; versionSha256: string; currentVersion: GitHubReleaseVersion;
  destination: { applicationId: string; destination: string; assurance: 'current-dispatch-config-not-authenticated-original-destination' };
  checklist: { name: string; kind: 'secret' | 'variable' | 'file' | 'manual'; reason: string }[];
  environment: 'mobile-candidate' | 'mobile-external-testing' | 'mobile-production';
  originalAssurance: 'declared-original-references-not-authenticated-release-evidence';
}
export interface GitHubReleaseRecord { prepared: GitHubReleasePrepared; runId: string | null }
export interface GitHubReleaseRun {
  id: string; attempt: 1; status: GitHubRunStatus; conclusion: GitHubRunConclusion | null; observedAt: string;
  jobs: { id: string; kind: 'input-guard' | 'android' | 'ios' | 'android-resolve' | 'android-online' | 'android-build' | 'android-store' | 'ios-resolve' | 'ios-online' | 'ios-build' | 'ios-store'; status: GitHubRunStatus; conclusion: GitHubRunConclusion | null }[];
  url: string; assurance: 'github-workflow-observation-not-release-evidence';
}
export interface GitHubReleaseStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: GitHubReleaseReason;
  operation: { id: string; kind: GitHubReleaseKind; phase: 'running' | 'settled' | 'cleanup-unknown';
    reason: GitHubReleaseReason; effect: GitHubReleaseEffect } | null;
  prepared: GitHubReleasePrepared | null; consentExpiresAt: string | null;
  pending: GitHubReleaseRecord[]; run: GitHubReleaseRun | null;
}
export interface GitHubReleaseControl { sessionId: string; expectedRevision: number }
export interface GitHubReleasePrepare extends GitHubReleaseControl { expectedConnectionRevision: number; branch: string; platform: GitHubReleasePlatform; selection: GitHubReleaseSelection }
export interface GitHubReleaseDispatch extends GitHubReleaseControl { consentId: string; confirm: true; confirmation: string }
export interface GitHubReleaseObserve extends GitHubReleaseControl { marker: string }
export interface GitHubReleaseApi {
  githubReleaseStatus(): Promise<GitHubReleaseStatus>;
  prepareGitHubRelease(args: GitHubReleasePrepare): Promise<GitHubReleaseStatus>;
  dispatchGitHubRelease(args: GitHubReleaseDispatch): Promise<GitHubReleaseStatus>;
  trackGitHubRelease(args: GitHubReleaseObserve): Promise<GitHubReleaseStatus>;
  reconcileGitHubRelease(args: GitHubReleaseObserve): Promise<GitHubReleaseStatus>;
  loadGitHubReleasePending(args: GitHubReleaseControl): Promise<GitHubReleaseStatus>;
  cancelGitHubRelease(args: { operationId: string }): Promise<GitHubReleaseStatus>;
  subscribeGitHubRelease(listener: (status: GitHubReleaseStatus | null) => void): Promise<() => void>;
}
export interface GitHubReleaseError { code: string; reason: GitHubReleaseReason; admission: 'not-admitted' | 'unknown'; message: string }
export interface GitHubReleaseView {
  mode: 'native' | 'preview' | 'unavailable'; status: GitHubReleaseStatus | null;
  branch: string; platform: GitHubReleasePlatform | null; stage: GitHubReleaseStage | null; recovery: boolean;
  candidateRunId: string; externalRunId: string; recoveryRunId: string; originalSourceSha: string;
  originalVersionName: string; originalVersionBuild: string; confirmation: string; confirmed: boolean;
  recoveryConfirmation: string; recoveryConfirmationRejected: boolean;
  pending: boolean; observing: boolean; cancelling: boolean; uncertain: boolean; error: GitHubReleaseReason | null;
}
