// A separate native edit domain. Passive setup proposals and configuration save
// receipts are deliberately not assignable to these operation projections.
import type { CoreEditOutcome, EditAvailability, GitHubSetupProposed, GitHubWorkflowId, GitHubWorkflowPath, JsonObject, NativeEditReason } from './types.ts';

export type WorkflowObservation = { state: 'absent' } | { state: 'present'; byteLength: number; sha256: string };
export type WorkflowObservedFile = WorkflowObservation & { id: GitHubWorkflowId };
export interface WorkflowPreparedFile {
  id: GitHubWorkflowId;
  path: GitHubWorkflowPath;
  action: 'create' | 'preserve';
  observed: WorkflowObservation;
  generated: { content: string; byteLength: number; sha256: string };
}
export interface WorkflowPreparedView {
  schemaVersion: 1;
  files: WorkflowPreparedFile[];
  createDirectories: ('.github' | '.github/workflows')[];
  templateSet: GitHubSetupProposed['templateSet'];
  tooling: GitHubSetupProposed['tooling'];
}
export interface WorkflowConflict {
  schemaVersion: 1;
  reason: 'existing_workflow_differs';
  conflicts: { id: GitHubWorkflowId; observed: Extract<WorkflowObservation, { state: 'present' }> }[];
}
export interface GitHubWorkflowEditProjection {
  domain: 'github_workflows';
  projectId: string;
  sessionId: string;
  ownerGeneration: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number;
  checkout: { revision: string; observed: WorkflowObservedFile[] } | null;
  prepared: { revision: string; planToken: string; draftRevision: number; baselineGeneration: number; view: WorkflowPreparedView } | null;
  conflict: WorkflowConflict | null;
  applySubmitted: boolean;
  coreOutcome: CoreEditOutcome | null;
  nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown';
  lateSettled: boolean;
}
export interface GitHubWorkflowEditStatus {
  schemaVersion: 1;
  domain: 'github_workflows';
  windowGeneration: string;
  statusRevision: number;
  capability: { available: boolean; reason: EditAvailability };
  active: GitHubWorkflowEditProjection | null;
  lastTerminal: GitHubWorkflowEditProjection | null;
}
export interface PrepareGitHubWorkflowEditRequest {
  sessionId: string;
  revision: string;
  draft: JsonObject;
  toolingRepository: string;
  toolingSha: string;
  draftRevision: number;
  baselineGeneration: number;
}
export interface GitHubWorkflowEditApi {
  openGitHubWorkflowEdit(projectId: string): Promise<GitHubWorkflowEditStatus>;
  prepareGitHubWorkflowEdit(request: PrepareGitHubWorkflowEditRequest): Promise<GitHubWorkflowEditStatus>;
  applyGitHubWorkflowEdit(sessionId: string, planToken: string): Promise<GitHubWorkflowEditStatus>;
  closeGitHubWorkflowEdit(sessionId: string): Promise<GitHubWorkflowEditStatus>;
  githubWorkflowEditStatus(): Promise<GitHubWorkflowEditStatus>;
  subscribeGitHubWorkflowEdit(onStatus: (status: unknown) => void): Promise<() => void>;
}
