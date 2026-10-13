// Nonsecret UI DATA. Neither a source hash nor a prepared status is authority
// to run a workflow: native one-use consent and original finality remain owed.
export type GitHubPreflightPlatform = 'android' | 'ios' | 'both';
export type GitHubPreflightKind = 'prepare' | 'dispatch' | 'track' | 'reconcile' | 'pending';
export type GitHubPreflightReason = 'none' | 'unqualified' | 'publisher-unconfigured' | 'not-connected' | 'busy' |
  'invalid-input' | 'target-changed' | 'expired' | 'rate-limited' | 'cancelled' | 'cleanup-unknown' | 'runtime-unavailable' |
  'consent-expired' | 'caller-mismatch' | 'workflow-unavailable' | 'source-changed' | 'unresolved-run' | 'ambiguous-run' |
  'run-changed' | 'jobs-incomplete' | 'unauthorized' | 'forbidden' | 'not-found-or-inaccessible' | 'network-unavailable' |
  'tls-failed' | 'response-invalid' | 'response-limit';
export type GitHubPreflightEffect = 'none' | 'not-sent' | 'potentially-applied' | 'accepted';
export interface GitHubPreflightTarget {
  projectBinding: string; repository: string; accountId: string; repositoryId: string; branch: string;
  toolingRepository: 'Apdelrahman1911/mobile-release-kit'; toolingSha: string; platform: GitHubPreflightPlatform; marker: string;
}
export interface GitHubPreflightPrepared {
  target: GitHubPreflightTarget; sourceSha: string; workflowId: string; workflowPath: '.github/workflows/mobile-preflight.yml';
  callerSha256: string; observedAt: string; expectedRef: string; displayTitle: string; confirmation: string;
}
export interface GitHubPreflightRecord { prepared: GitHubPreflightPrepared; runId: string | null }
export type GitHubRunStatus = 'queued' | 'in_progress' | 'completed' | 'waiting' | 'pending' | 'requested';
export type GitHubRunConclusion = 'success' | 'failure' | 'neutral' | 'cancelled' | 'skipped' | 'timed_out' |
  'action_required' | 'stale' | 'startup_failure';
export interface GitHubPreflightRun {
  id: string; attempt: 1; status: GitHubRunStatus; conclusion: GitHubRunConclusion | null; observedAt: string;
  jobs: { id: string; kind: 'input-guard' | 'android' | 'ios'; status: GitHubRunStatus; conclusion: GitHubRunConclusion | null }[];
  url: string; assurance: 'github-workflow-observation-not-release-evidence';
}
export interface GitHubPreflightStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: GitHubPreflightReason;
  operation: { id: string; kind: GitHubPreflightKind; phase: 'running' | 'settled' | 'cleanup-unknown';
    reason: GitHubPreflightReason; effect: GitHubPreflightEffect } | null;
  prepared: GitHubPreflightPrepared | null; consentExpiresAt: string | null;
  pending: GitHubPreflightRecord[]; run: GitHubPreflightRun | null;
}
export interface GitHubPreflightControl { sessionId: string; expectedRevision: number }
export interface GitHubPreflightPrepare extends GitHubPreflightControl { expectedConnectionRevision: number; branch: string; platform: GitHubPreflightPlatform }
export interface GitHubPreflightDispatch extends GitHubPreflightControl { consentId: string; confirm: true }
export interface GitHubPreflightObserve extends GitHubPreflightControl { marker: string }
export interface GitHubPreflightApi {
  githubPreflightStatus(): Promise<GitHubPreflightStatus>;
  prepareGitHubPreflight(args: GitHubPreflightPrepare): Promise<GitHubPreflightStatus>;
  dispatchGitHubPreflight(args: GitHubPreflightDispatch): Promise<GitHubPreflightStatus>;
  trackGitHubPreflight(args: GitHubPreflightObserve): Promise<GitHubPreflightStatus>;
  reconcileGitHubPreflight(args: GitHubPreflightObserve): Promise<GitHubPreflightStatus>;
  loadGitHubPreflightPending(args: GitHubPreflightControl): Promise<GitHubPreflightStatus>;
  cancelGitHubPreflight(args: { operationId: string }): Promise<GitHubPreflightStatus>;
  subscribeGitHubPreflight(listener: (status: GitHubPreflightStatus | null) => void): Promise<() => void>;
}
export interface GitHubPreflightError { code: string; reason: GitHubPreflightReason; admission: 'not-admitted' | 'unknown'; message: string }
export interface GitHubPreflightView {
  mode: 'native' | 'preview' | 'unavailable'; status: GitHubPreflightStatus | null;
  branch: string; platform: GitHubPreflightPlatform | null; confirmed: boolean;
  pending: boolean; observing: boolean; cancelling: boolean; uncertain: boolean; error: GitHubPreflightReason | null;
}
