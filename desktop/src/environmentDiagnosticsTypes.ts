import type { EnvironmentOperation, EnvironmentPlatform } from './environment.ts';
import type { JsonObject } from './types.ts';

// Dedicated native owner DATA; never a passive environment.requirements result.
export interface EnvironmentDiagnosticsContext {
  projectId: string; draftRevision: number; baselineGeneration: number;
  platform: EnvironmentPlatform; operation: 'build';
}
export interface StartEnvironmentDiagnostics extends EnvironmentDiagnosticsContext { draft: JsonObject }
export type EnvironmentCheckId = 'developer-selection' | 'git' | 'java' | 'javac' | 'xcode';
export type EnvironmentCheckReason = 'invalid-draft' | 'platform-disabled' | 'host-mismatch' | 'unsupported-host' |
  'missing-in-supported-lookup' | 'unsupported-installation' | 'unselected-installation' | 'full-xcode-not-selected' | 'stopped' |
  'command-incomplete' | 'binding-changed' | 'cancelled' | 'timed-out' | 'observed' | 'nonzero-exit' | 'version-unrecognized' | 'selection-unrecognized';
export type EnvironmentDiagnosticsOutcome = 'complete' | 'partial' | 'failed' | 'cancelled' | 'timed-out' | 'unavailable';
export interface EnvironmentCheck {
  id: EnvironmentCheckId; state: 'not-run' | 'attempted' | 'completed'; reason: EnvironmentCheckReason;
  version: string | null; build: string | null; returnCode: number | null;
  baseline: { kind: 'exact-pin' | 'workflow-reference' | 'no-local-policy'; version: string | null; build: string | null };
  assessment: 'match' | 'mismatch' | 'no-local-policy' | 'not-assessed'; help: string;
}
export interface EnvironmentDiagnosticsResult {
  schemaVersion: 1; policyVersion: 'environment-diagnostics-v1'; context: EnvironmentDiagnosticsContext;
  hostPlatform: 'linux' | 'macos'; outcome: EnvironmentDiagnosticsOutcome; checks: EnvironmentCheck[]; commandsAttempted: number;
  // Immutable core observations, NOT authority for native finality or new work.
  lifetime: { complete: boolean; fatal: boolean; contained: boolean; commandDispatched: boolean | null; commands: number;
    inputClosed: boolean; handlersRestored: boolean; toolDescriptorsClosed: boolean; stopObserved: 'none' | 'cancelled' | 'timed-out' };
  assurance: { basis: 'local-tool-observation'; toolsAttempted: boolean; projectCodeExecuted: false; projectFilesRead: false;
    repositoryObserved: false; sdkInspected: false; credentialsRead: false; storeContacted: false;
    dependencyCompleteness: 'unknown'; releaseReadiness: 'unknown'; toolCacheEffects: 'possible' };
}
export type EnvironmentDiagnosticsReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' |
  'protocol-error' | 'runtime-unavailable' | 'command-failed' | 'cleanup-unknown';
export interface EnvironmentDiagnosticsProjection {
  runId: string; ownerGeneration: string; context: EnvironmentDiagnosticsContext;
  phase: 'starting' | 'checking' | 'stopping' | 'settled' | 'retained-unknown';
  outcome: EnvironmentDiagnosticsOutcome | null; finality: 'pending' | 'settled' | 'unknown';
  reason: EnvironmentDiagnosticsReason; result: EnvironmentDiagnosticsResult | null;
}
export type EnvironmentDiagnosticsAvailability = 'available' | 'busy' | 'shutdown' | 'cleanup-unknown' | 'document-lost' |
  'unsupported-platform' | 'runtime-unqualified';
export interface EnvironmentDiagnosticsStatus {
  schemaVersion: 1; statusRevision: number;
  capability: { available: boolean; reason: EnvironmentDiagnosticsAvailability };
  active: EnvironmentDiagnosticsProjection | null; lastTerminal: EnvironmentDiagnosticsProjection | null;
}
export interface EnvironmentDiagnosticsApi {
  startEnvironmentDiagnostics(request: StartEnvironmentDiagnostics): Promise<EnvironmentDiagnosticsStatus>;
  cancelEnvironmentDiagnostics(runId: string, ownerGeneration: string): Promise<EnvironmentDiagnosticsStatus>;
  environmentDiagnosticsStatus(): Promise<EnvironmentDiagnosticsStatus>;
  subscribeEnvironmentDiagnostics(onStatus: (status: unknown) => void): Promise<() => void>;
}
export interface EnvironmentDiagnosticsSelection {
  projectId: string; draftRevision: number; baselineGeneration: number; hasDraft: boolean;
}
export interface EnvironmentDiagnosticsBinding extends EnvironmentDiagnosticsContext {
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number;
  nativeStatusRevision: number; previousRunId: string | null;
}
export interface EnvironmentDiagnosticsViewContext {
  platform: EnvironmentPlatform; operation: EnvironmentOperation;
}
