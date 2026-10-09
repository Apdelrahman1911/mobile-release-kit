// Closed renderer DATA only. Native owns the session, one-use consent and writes.
export type GitHubRemoteSetupRepositorySelection = { kind: 'actions_enabled'; enabled: boolean } |
  { kind: 'workflow_token_policy'; defaultWorkflowPermissions: 'read' | 'write'; canApprovePullRequestReviews: boolean };
export type GitHubRemoteSetupEnvironmentSelection = {
  kind: 'environment_protection'; mode: 'configure' | 'create'; stage: 'candidate' | 'external-testing' | 'production';
  waitTimerMinutes: number; preventSelfReview: boolean | null; reviewerLogin: string | null; branches: 'all' | 'protected' | null;
};
export type GitHubRemoteSetupSelection = GitHubRemoteSetupRepositorySelection | GitHubRemoteSetupEnvironmentSelection;
export interface GitHubRemoteSetupEnvironmentPolicy {
  waitTimerMinutes: number; protectedBranches: boolean;
  requiredReviewers: { preventSelfReview: boolean; reviewers: { type: 'User' | 'Team'; id: string }[] } | null;
}
export interface GitHubRemoteSetupEnvironmentFacts { name: string; id: string | null; policy: GitHubRemoteSetupEnvironmentPolicy | null }
export type GitHubRemoteSetupPolicy = { enabled: boolean; allowed_actions: 'all' | 'local_only' | 'selected'; sha_pinning_required: boolean } |
  { default_workflow_permissions: 'read' | 'write'; can_approve_pull_request_reviews: boolean };
export type GitHubRemoteSetupReason = 'none' | 'no-change' | 'policy-unsupported' | 'policy-changed' | 'organization-restricted' |
  'repository-archived' | 'unauthorized' | 'forbidden' | 'not-found-or-inaccessible' | 'target-changed' | 'rate-limited' |
  'network-unavailable' | 'tls-failed' | 'response-invalid' | 'response-limit' | 'expired' | 'cancelled' |
  'unqualified' | 'not-connected' | 'busy' | 'invalid-input' | 'cleanup-unknown' | 'runtime-unavailable' | 'consent-expired';
export interface GitHubRemoteSetupTarget<S extends GitHubRemoteSetupSelection = GitHubRemoteSetupSelection> {
  projectBinding: string; repository: string; accountId: string; repositoryId: string; selection: S;
}
export interface GitHubRemoteSetupRepositoryPrepared {
  target: GitHubRemoteSetupTarget<GitHubRemoteSetupRepositorySelection>;
  before: GitHubRemoteSetupPolicy; after: GitHubRemoteSetupPolicy; observedAt: string; confirmation: string;
}
export interface GitHubRemoteSetupEnvironmentPrepared {
  target: GitHubRemoteSetupTarget<GitHubRemoteSetupEnvironmentSelection>;
  before: GitHubRemoteSetupEnvironmentFacts; after: GitHubRemoteSetupEnvironmentPolicy;
  reviewer: { id: string; login: string; permission: 'read' | 'write' | 'admin' } | null;
  observedAt: string; confirmation: string;
}
export type GitHubRemoteSetupPrepared = GitHubRemoteSetupRepositoryPrepared | GitHubRemoteSetupEnvironmentPrepared;
export type GitHubRemoteSetupObservation = GitHubRemoteSetupPolicy | GitHubRemoteSetupEnvironmentFacts;
export interface GitHubRemoteSetupConsent { id: string; expiresAt: string; prepared: GitHubRemoteSetupPrepared }
export interface GitHubRemoteSetupStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: GitHubRemoteSetupReason;
  operation: { id: string; kind: 'prepare' | 'apply'; phase: 'running' | 'stopping' | 'settled' | 'cleanup-unknown';
    reason: GitHubRemoteSetupReason; effect: 'not-started' | 'unknown' | 'readback-confirmed';
    writeClaimed: boolean | null; writeAcknowledged: boolean | null } | null;
  consent: GitHubRemoteSetupConsent | null; observed: GitHubRemoteSetupObservation | null;
}
export interface GitHubRemoteSetupApi {
  githubRemoteSetupStatus(): Promise<GitHubRemoteSetupStatus>;
  githubRemoteSetupPrepare(args: { sessionId: string; expectedRevision: number; expectedConnectionRevision: number; selection: GitHubRemoteSetupSelection }): Promise<GitHubRemoteSetupStatus>;
  githubRemoteSetupApply(args: { sessionId: string; expectedRevision: number; consentId: string; confirm: true }): Promise<GitHubRemoteSetupStatus>;
  githubRemoteSetupDiscard(args: { sessionId: string; expectedRevision: number; consentId: string }): Promise<GitHubRemoteSetupStatus>;
  githubRemoteSetupCancel(operationId: string): Promise<GitHubRemoteSetupStatus>;
  subscribeGitHubRemoteSetup(onStatus: (status: GitHubRemoteSetupStatus | null) => void): Promise<() => void>;
}
export interface GitHubRemoteSetupView {
  mode: 'native' | 'preview' | 'unavailable'; status: GitHubRemoteSetupStatus | null; selection: GitHubRemoteSetupSelection | null;
  originalTarget: { repository: string; accountId: string; repositoryId: string; selection: GitHubRemoteSetupSelection } | null;
  confirmed: boolean; pending: boolean; observing: boolean; cancelling: boolean; discarding: boolean; uncertain: boolean;
  error: GitHubRemoteSetupReason | null;
}
export interface GitHubRemoteSetupError { code: string; reason: GitHubRemoteSetupReason; admission: 'not-admitted' | 'unknown'; message: string }
