// A separate domain: no configuration/workflow token or passive proposal can
// authorize initialization. Native retains the actual registered root/owner.
import type { ConfigPreview, CoreEditOutcome, EditAvailability, FixedIgnoreLine, GitHubSetupProposed, GitHubWorkflowId, GitHubWorkflowPath, JsonObject, NativeEditReason } from './types.ts';
export type InitializationIntent = 'initialize' | 'recover';
export type InitializationKind = 'configuration' | 'gitignore' | 'workflow' | 'metadata';
export interface InitializationFile {
  index: number; kind: InitializationKind; path: string;
  action: 'create' | 'preserve' | 'append'; beforeBytes: number | null; afterBytes: number;
}
export interface InitializationView {
  schemaVersion: 1; kind: 'project-initialization'; files: InitializationFile[];
  directoryCount: number; createDirectories: string[]; configurationPreview: ConfigPreview;
  workflows: { id: GitHubWorkflowId; path: GitHubWorkflowPath; content: string; byteLength: number; sha256: string }[];
  ignoreAdditions: FixedIgnoreLine[]; templateSet: GitHubSetupProposed['templateSet']; tooling: GitHubSetupProposed['tooling'];
}
export interface InitializationConflict {
  schemaVersion: 1; reason: 'existing_targets_differ';
  files: { kind: 'configuration' | 'workflow'; path: string; beforeBytes: number }[];
}
export type InitializationRecoveryReason = 'none' | 'incomplete_journal' | 'foreign_journal' | 'legacy_journal' | 'invalid_journal' | 'unsupported_descriptor' | 'resource_changed' | 'target_changed' | 'control_changed' | 'namespace_changed';
export interface InitializationRecoveryFact { byteLength: number; sha256: string; mode: number }
export interface InitializationRecoveryView {
  schemaVersion: 1; kind: 'project-initialization-recovery'; state: 'idle' | 'recoverable' | 'conflict';
  reason: InitializationRecoveryReason; action: 'rollback' | 'preparing_cleanup' | 'committed_cleanup' | 'rolled_back_cleanup' | null;
  transactionId: string | null;
  context: { configuration: { byteLength: number; sha256: string }; templateSet: InitializationView['templateSet']; tooling: InitializationView['tooling'] } | null;
  files: { index: number; kind: InitializationKind; path: string; effect: 'preserve' | 'remove_new' | 'restore_original' | 'keep_committed'; before: InitializationRecoveryFact | null; after: InitializationRecoveryFact | null }[];
  privateCleanup: { fileCount: number; directoryCount: number; scope: 'inspected-owned-journal-only' };
}
export type InitializationCheckout =
  { intent: 'initialize'; revision: string; draftRevision: number; baselineGeneration: number; observed: { schemaVersion: 1; fileCount: number; directoryCount: number } } |
  { intent: 'recover'; revision: string; recovery: InitializationRecoveryView };
export type InitializationPrepared =
  { intent: 'initialize'; revision: string; planToken: string; draftRevision: number; baselineGeneration: number; view: InitializationView } |
  { intent: 'recover'; revision: string; planToken: string; recovery: InitializationRecoveryView };
export interface ProjectInitializationProjection {
  domain: 'project_initialization'; intent: InitializationIntent; projectId: string; sessionId: string; ownerGeneration: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number; checkout: InitializationCheckout | null; prepared: InitializationPrepared | null; conflict: InitializationConflict | null;
  applySubmitted: boolean; coreOutcome: CoreEditOutcome | null; nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown'; lateSettled: boolean;
}
export interface ProjectInitializationStatus {
  schemaVersion: 1; domain: 'project_initialization'; windowGeneration: string; statusRevision: number;
  capability: { available: boolean; reason: EditAvailability }; active: ProjectInitializationProjection | null; lastTerminal: ProjectInitializationProjection | null;
}
export type OpenProjectInitializationRequest =
  { projectId: string; intent: 'initialize'; draft: JsonObject; toolingRepository: string; toolingSha: string; draftRevision: number; baselineGeneration: number } |
  { projectId: string; intent: 'recover' };
export interface ProjectInitializationApi {
  openProjectInitialization(request: OpenProjectInitializationRequest): Promise<ProjectInitializationStatus>;
  prepareProjectInitialization(sessionId: string, revision: string, intent: InitializationIntent): Promise<ProjectInitializationStatus>;
  applyProjectInitialization(sessionId: string, planToken: string, intent: InitializationIntent): Promise<ProjectInitializationStatus>;
  discardProjectInitialization(sessionId: string): Promise<ProjectInitializationStatus>;
  projectInitializationStatus(): Promise<ProjectInitializationStatus>;
  subscribeProjectInitialization(onStatus: (status: unknown) => void): Promise<() => void>;
}
