// Closed readonly projection DATA, not proof, Store state or a native permit.
export type GitHubHistoryStage = 'candidate' | 'external-testing' | 'production-submit';
export type GitHubHistoryPlatform = 'android' | 'ios';
export type GitHubHistoryReason = 'none' | 'unqualified' | 'not-connected' | 'busy' | 'invalid-input' | 'target-changed' |
  'config-invalid' | 'platform-disabled' | 'publisher-unconfigured' | 'unsupported-tooling' | 'provider-unavailable' |
  'provider-mismatch' | 'runtime-unavailable' | 'resources-unavailable' | 'unauthorized' | 'forbidden' |
  'not-found-or-inaccessible' | 'rate-limited' | 'network-unavailable' | 'tls-failed' | 'response-invalid' | 'response-limit' |
  'artifact-missing' | 'artifact-expired' | 'evidence-invalid' | 'attestation-not-confirmed' | 'producer-pending' |
  'cancelled' | 'expired' | 'cleanup-unknown';
export interface GitHubHistorySelection { runId: string; attempt: number; stage: GitHubHistoryStage; platform: GitHubHistoryPlatform }
export interface GitHubHistoryContext {
  schemaVersion: 1; projectBinding: string; configSha256: string; repository: string; repositoryId: string; accountId: string;
  toolingRepository: 'Apdelrahman1911/mobile-release-kit'; toolingSha: string; selection: GitHubHistorySelection;
}
export interface GitHubHistoryAuthority {
  workflow: string; callerPath: string; reusableRepository: 'Apdelrahman1911/mobile-release-kit'; reusablePath: string;
  reusableCommit: string; runId: string; attempt: number; headSha: string; ref: string; event: 'workflow_dispatch';
}
export interface GitHubHistoryEvidence {
  artifactId: string; artifactSha256: string; artifactName: string; producerJobId: string;
  producedBy: GitHubHistoryAuthority; authorizedBy: GitHubHistoryAuthority;
  candidateSource: { commit: string; tree: string }; operationSource: { commit: string; tree: string };
  version: { name: string; build: number }; applicationId: string;
  outcome: 'mutated' | 'reconciled' | 'already-present' | 'operator-authorized-reconciliation' |
    'operator-authorized-retry' | 'operator-authorized-create-retry';
  candidateManifestSha256: string; operationIntentSha256: string; receiptSha256: string; provenanceSha256: string;
}
export interface GitHubHistoryResult {
  schemaVersion: 1; context: GitHubHistoryContext; observedAt: string;
  verification: 'verified' | 'unavailable' | 'refused'; reason: GitHubHistoryReason; evidence: GitHubHistoryEvidence | null;
  assurance: 'authenticated-retained-workflow-evidence-not-current-store-state';
}
export interface GitHubHistoryOperation {
  id: string; phase: 'running' | 'stopping' | 'settled' | 'cleanup-unknown'; reason: GitHubHistoryReason; selection: GitHubHistorySelection;
}
export interface GitHubHistoryStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: GitHubHistoryReason;
  operation: GitHubHistoryOperation | null; result: GitHubHistoryResult | null;
}
export interface GitHubHistoryStart {
  sessionId: string; expectedRevision: number; expectedConnectionRevision: number; selection: GitHubHistorySelection;
}
export interface GitHubHistoryApi {
  githubHistoryStatus(): Promise<GitHubHistoryStatus>;
  startGitHubHistory(args: GitHubHistoryStart): Promise<GitHubHistoryStatus>;
  cancelGitHubHistory(args: { operationId: string }): Promise<GitHubHistoryStatus>;
  subscribeGitHubHistory(listener: (value: GitHubHistoryStatus | null) => void): Promise<() => void>;
}
export interface GitHubHistoryError { code: string; reason: GitHubHistoryReason; admission: 'not-admitted' | 'unknown'; message: string }
export interface GitHubHistoryView {
  mode: 'native' | 'preview' | 'unavailable'; status: GitHubHistoryStatus | null;
  runId: string; attempt: string; stage: GitHubHistoryStage | null; platform: GitHubHistoryPlatform | null;
  pending: boolean; observing: boolean; cancelling: boolean; uncertain: boolean; error: GitHubHistoryReason | null;
}
