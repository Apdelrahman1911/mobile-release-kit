// Public DATA for the same-owner P2 action. Native capability, actual assignment,
// one-use consent and original finality remain authoritative.
// No file/value/ciphertext/URL/token/secret-name request arguments.
import type { AssetKind, AssetScope, CredentialFieldId } from './assetSessionTypes.ts';
import type { GitHubConnectionReason } from './githubConnectionTypes.ts';

export type GitHubInputGroupReason = GitHubConnectionReason |
  'context-stale' | 'assignment-unavailable' | 'config-mismatch' |
  'caller-incompatible' | 'environment-unready' | 'runner-unverified' | 'runner-collision' |
  'input-invalid' | 'destination-limit' | 'sealing-unavailable' |
  'consent-expired' | 'source-changed' | 'metadata-changed' | 'journal-incomplete';
export type GitHubInputGroupKind = 'prepare' | 'apply' | 'reconcile' | 'pending';
// Runner inventory is a separate read, never another private P2 action.
export type GitHubInputGroupOperationKind = GitHubInputGroupKind | 'runner-check';
export type GitHubInputGroupEnvironment =
  'mobile-candidate' | 'mobile-external-testing' | 'mobile-production';

// References already owned by the existing native asset context/assignment.
// Context supplies stage/platform/purpose. Renderer cannot override them here.
export interface GitHubInputGroupAssignment {
  kind: AssetKind;
  recordId: string;
  recordRevision: number;
  contextRevision: number;
}
export interface GitHubInputGroupControl {
  sessionId: string;
  expectedRevision: number;
}
export interface GitHubInputRunnerCheck extends GitHubInputGroupControl {
  expectedConnectionRevision: number;
  expectedAssetStatusRevision: number;
  contextRevision: number;
}
export interface GitHubInputGroupPrepare extends GitHubInputGroupControl {
  expectedConnectionRevision: number;
  expectedAssetStatusRevision: number;
  branch: string;
  assignment: GitHubInputGroupAssignment;
}
export interface GitHubInputGroupApply extends GitHubInputGroupControl {
  consentId: string;
  confirmUpsertWholeGroup: true;
}
export interface GitHubInputGroupReconcile extends GitHubInputGroupControl {
  originalOperationId: string; // Exact32hex journal marker, not Supervisor ticket ID.
}

// Safe original journal target projection. No local path/label/record payload.
// Names/hashes here are native-observed public source/target facts, NOT inputs.
export interface GitHubInputGroupTarget {
  projectBinding: string;
  repository: string;
  repositoryId: string;
  accountId: string;
  environment: GitHubInputGroupEnvironment;
  environmentId: string;
  branch: string;
  sourceSha: string;
  toolingSha: string;
  callerPath: string;
  callerSha256: string;
  configSha256: string;
  scope: AssetScope;
  kind: AssetKind;
  secretName: string;
  protocol: 'mrk-github-input-group/1';
}
// Metadata is not a value readback or a compare-and-swap promise.
export type GitHubInputGroupMetadata =
  | { state: 'present'; createdAt: string; updatedAt: string; observedAt: string }
  | { state: 'missing-or-inaccessible'; observedAt: string };
export interface GitHubInputGroupPrepared {
  consentId: string;
  target: GitHubInputGroupTarget;
  assignment: GitHubInputGroupAssignment;
  fields: CredentialFieldId[]; // Labels/help from existing guide only; no values.
  metadata: GitHubInputGroupMetadata;
  destination: { state: 'fits'; plaintextLimitBytes: 48000 };
  effect: 'upsert-one-complete-group';
  observedAt: string;
  consentExpiresAt: string; // Display only. Native owns the original deadline.
}
export type GitHubInputGroupWrite =
  | { state: 'not-attempted' }
  | { state: 'attempted-outcome-unknown' }
  | { state: 'acknowledged-created'; statusCode: 201 }
  | { state: 'acknowledged-updated'; statusCode: 204 }
  | { state: 'explicitly-rejected'; reason: GitHubInputGroupReason };
export interface GitHubInputGroupCompletion {
  journal: 'not-run' | 'pending' | 'confirmed' | 'unknown';
  cleanup: 'pending' | 'confirmed' | 'unknown';
  finality: 'pending' | 'settled' | 'unknown';
}
// Exact 201/204 does not imply completion, credential validity or readiness.
export interface GitHubInputGroupRecord {
  originalOperationId: string; // Exact32hex journal marker, not Supervisor ticket ID.
  target: GitHubInputGroupTarget;
  write: GitHubInputGroupWrite;
  completion: GitHubInputGroupCompletion;
  reason: GitHubInputGroupReason;
}
export interface GitHubInputGroupObservation {
  originalOperationId: string; // Exact32hex journal marker, not Supervisor ticket ID.
  metadata: GitHubInputGroupMetadata;
  assurance: 'metadata-only-not-secret-value-or-write-confirmation';
}
interface GitHubInputRunnerFacts {
  checkedAt: string;
  expiresAt: string;
  groupCount: number;
  runnerCount: number;
  scope: 'repository' | 'organization-wide';
}
// Explanatory DATA only. Native custody/bindings and its clock grant authority.
export type GitHubInputRunnerSummary =
  | (GitHubInputRunnerFacts & { result: 'safe'; reason: 'none' })
  | (GitHubInputRunnerFacts & { result: 'expired'; reason: Exclude<GitHubInputGroupReason, 'none'> })
  | { result: 'refused'; checkedAt: null; expiresAt: null; groupCount: null; runnerCount: null;
      scope: null; reason: Exclude<GitHubInputGroupReason, 'none'> };
export interface GitHubInputGroupStatus {
  schemaVersion: 1;
  revision: number;
  sessionId: string | null;
  available: boolean;
  reason: GitHubInputGroupReason;
  operation: {
    id: string;
    kind: GitHubInputGroupOperationKind;
    phase: 'running' | 'settled' | 'cleanup-unknown';
    reason: GitHubInputGroupReason;
  } | null;
  runner: GitHubInputRunnerSummary | null;
  prepared: GitHubInputGroupPrepared | null;
  records: GitHubInputGroupRecord[]; // Existing journal's finite P2 capacity.
  observation: GitHubInputGroupObservation | null;
}
export interface GitHubInputGroupApi {
  githubInputGroupStatus(): Promise<GitHubInputGroupStatus>; // Local native DATA.
  checkGitHubInputRunners(args: GitHubInputRunnerCheck): Promise<GitHubInputGroupStatus>;
  prepareGitHubInputGroup(args: GitHubInputGroupPrepare): Promise<GitHubInputGroupStatus>;
  applyGitHubInputGroup(args: GitHubInputGroupApply): Promise<GitHubInputGroupStatus>;
  reconcileGitHubInputGroup(args: GitHubInputGroupReconcile): Promise<GitHubInputGroupStatus>;
  loadGitHubInputGroupPending(args: GitHubInputGroupControl): Promise<GitHubInputGroupStatus>;
  cancelGitHubInputGroup(args: { operationId: string }): Promise<GitHubInputGroupStatus>;
  subscribeGitHubInputGroup(listener: (status: GitHubInputGroupStatus | null) => void): Promise<() => void>;
}
export interface GitHubInputGroupError {
  code: string;
  reason: GitHubInputGroupReason;
  admission: 'not-admitted' | 'unknown';
  message: string; // Fixed local mapping only, never a remote message body.
}

// Controller view fields reuse existing action-controller conventions.
// 'confirmed' is merely local user intent, never a native permission/GO.
export interface GitHubInputGroupView {
  mode: 'native' | 'preview' | 'unavailable';
  status: GitHubInputGroupStatus | null;
  branch: string;
  assignment: GitHubInputGroupAssignment | null;
  confirmed: boolean;
  pending: boolean;
  observing: boolean;
  cancelling: boolean;
  uncertain: boolean;
  error: GitHubInputGroupReason | null;
}

export type GitHubInputGroupCommand = 'github_input_group_status' | 'github_input_runner_check' | 'github_input_group_prepare' | 'github_input_group_apply' |
  'github_input_group_reconcile' | 'github_input_group_pending' | 'github_input_group_cancel';
