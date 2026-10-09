// Closed renderer DATA only. Native owns the session, one-use consent and writes.
export type GitHubRemoteSetupSelection = { kind: 'actions_enabled'; enabled: boolean } |
  { kind: 'workflow_token_policy'; defaultWorkflowPermissions: 'read' | 'write'; canApprovePullRequestReviews: boolean };
export type GitHubRemoteSetupPolicy = { enabled: boolean; allowed_actions: 'all' | 'local_only' | 'selected'; sha_pinning_required: boolean } |
  { default_workflow_permissions: 'read' | 'write'; can_approve_pull_request_reviews: boolean };
export type GitHubRemoteSetupReason = 'none' | 'no-change' | 'policy-unsupported' | 'policy-changed' | 'organization-restricted' |
  'repository-archived' | 'unauthorized' | 'forbidden' | 'not-found-or-inaccessible' | 'target-changed' | 'rate-limited' |
  'network-unavailable' | 'tls-failed' | 'response-invalid' | 'response-limit' | 'expired' | 'cancelled' |
  'unqualified' | 'not-connected' | 'busy' | 'invalid-input' | 'cleanup-unknown' | 'runtime-unavailable' | 'consent-expired';
export interface GitHubRemoteSetupPrepared {
  target: { projectBinding: string; repository: string; accountId: string; repositoryId: string; selection: GitHubRemoteSetupSelection };
  before: GitHubRemoteSetupPolicy; after: GitHubRemoteSetupPolicy; observedAt: string; confirmation: string;
}
export interface GitHubRemoteSetupConsent { id: string; expiresAt: string; prepared: GitHubRemoteSetupPrepared }
export interface GitHubRemoteSetupStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: GitHubRemoteSetupReason;
  operation: { id: string; kind: 'prepare' | 'apply'; phase: 'running' | 'stopping' | 'settled' | 'cleanup-unknown';
    reason: GitHubRemoteSetupReason; effect: 'not-started' | 'unknown' | 'readback-confirmed';
    writeClaimed: boolean | null; writeAcknowledged: boolean | null } | null;
  consent: GitHubRemoteSetupConsent | null; observed: GitHubRemoteSetupPolicy | null;
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
