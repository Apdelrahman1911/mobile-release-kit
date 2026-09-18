// Closed G1 wire/view contracts. The renderer owns neither native admission nor
// credentials after the single synchronous input handoff.
import type { GITHUB_WORKFLOWS } from './githubSetupProtocol.ts';

export type GitHubConnectionReason = 'none' | 'unqualified' | 'runtime-unavailable' | 'publisher-unconfigured' |
  'not-connected' | 'invalid-input' | 'busy' | 'unauthorized' | 'forbidden' | 'not-found-or-inaccessible' |
  'target-changed' | 'rate-limited' | 'network-unavailable' | 'tls-failed' | 'response-invalid' | 'response-limit' |
  'expired' | 'stale' | 'cancelled' | 'cleanup-unknown';
export interface GitHubFact<T> {
  state: 'not-observed' | 'observed' | 'stale' | 'unavailable';
  value: T | null;
  observedAt: string | null;
  reason: GitHubConnectionReason;
}
export interface GitHubAccount { id: string; login: string }
export type GitHubPermission = 'reported-allowed' | 'reported-denied' | 'unknown';
export interface GitHubRepository {
  id: string; fullName: string; defaultBranch: string; visibility: 'public' | 'private' | 'internal'; archived: boolean;
  permissions: { pull: GitHubPermission; push: GitHubPermission; admin: GitHubPermission };
}
export interface GitHubAutomation {
  coverage: 'complete' | 'limited';
  workflows: { id: typeof GITHUB_WORKFLOWS[number]['id']; remoteId: string | null;
    presence: 'listed' | 'not-listed' | 'unknown'; state: 'active' | 'disabled' | 'unknown' }[];
}
export interface GitHubConnectionStatus {
  schemaVersion: 1; revision: number;
  capability: { readOnlySessionAvailable: boolean; reason: GitHubConnectionReason;
    deviceLogin: 'publisher-unconfigured' | 'not-qualified'; storage: 'session-only' };
  session: { id: string; projectId: string; targetRepository: string;
    state: 'checking' | 'connected' | 'expired' | 'disconnecting' | 'failed' | 'cleanup-unknown'; expiresAt: string | null } | null;
  operation: { id: string; kind: 'connect' | 'refresh' | 'disconnect';
    phase: 'running' | 'settled' | 'cleanup-unknown'; reason: GitHubConnectionReason } | null;
  account: GitHubFact<GitHubAccount>;
  repository: GitHubFact<GitHubRepository>;
  automation: GitHubFact<GitHubAutomation>;
  facts: { remoteMutationAvailable: false; dispatchAvailable: false; repositoryActionsSettingsObservation: 'not-run';
    environmentObservation: 'not-run'; secretObservation: 'not-run'; variableObservation: 'not-run';
    protectionObservation: 'not-run'; runnerObservation: 'not-run'; templateCompatibility: 'unknown'; releaseReadiness: 'unknown' };
}
export interface GitHubConnectionHelpEntry {
  id: string; label: string; what: string; why: string; where: string; format: string; failure: string;
}
export interface GitHubConnectionHelp {
  schemaVersion: 1;
  inputs: (GitHubConnectionHelpEntry & { requiredness: 'required' | 'conditional' })[];
  guidance: GitHubConnectionHelpEntry[];
}
export interface GitHubConnectionContext {
  documentId: string; projectId: string; projectGeneration: number; repository: string;
}
export interface GitHubConnectionApi {
  githubConnectionStatus(): Promise<GitHubConnectionStatus>;
  connectGitHubToken(args: { projectId: string; repository: string; token: string }): Promise<GitHubConnectionStatus>;
  refreshGitHubConnection(args: { sessionId: string; expectedRevision: number }): Promise<GitHubConnectionStatus>;
  disconnectGitHubConnection(args: { sessionId: string }): Promise<GitHubConnectionStatus>;
  // null is a fixed invalid-event marker, never the rejected payload.
  subscribeGitHubConnection(listener: (status: GitHubConnectionStatus | null) => void): Promise<() => void>;
}
export interface GitHubConnectionError {
  code: string; message: string; retryable: false;
  reason: GitHubConnectionReason; admission: 'not-admitted' | 'unknown';
}
// Deliberately NO token/Connect method: retained observation and retirement must
// not retain the input or an invocation's private arguments.
export interface GitHubConnectionObservationPort {
  mode: 'native' | 'preview' | 'unavailable';
  subscribe: (listener: (value: unknown) => void) => Promise<() => void>;
  status: () => Promise<unknown>;
  refresh: (args: { sessionId: string; expectedRevision: number }) => Promise<unknown>;
  disconnect: (args: { sessionId: string }) => Promise<unknown>;
}
// Separate synchronous entry, bound to the exact observation port. It is never
// put in view state or retained with a pending operation's private arguments.
export interface GitHubConnectionTokenHandoff {
  port: GitHubConnectionObservationPort;
  submit: (args: { projectId: string; repository: string; token: string }) => Promise<unknown>;
}
export interface GitHubConnectionViewState {
  mode: 'native' | 'preview' | 'unavailable'; context: GitHubConnectionContext | null;
  status: GitHubConnectionStatus | null; retained: GitHubConnectionStatus | null;
  help: GitHubConnectionHelp | null; helpState: 'missing' | 'current' | 'previous';
  observing: boolean; busy: 'connect' | 'refresh' | 'disconnect' | null; uncertain: boolean;
  blocked: boolean; retirementPending: boolean; error: GitHubConnectionReason | null;
}
