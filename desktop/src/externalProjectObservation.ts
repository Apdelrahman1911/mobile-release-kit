// Comparison DATA for an idle saved-file check. This is not a filesystem
// watcher, an atomic checkout, a draft replacement or build/release consent.
import { sameJson } from './catalog.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import { copyBoundedComparisonData, parseSavedConfigContent, sameSavedConfig } from './offlinePreflightProtocol.ts';
import { parseReleaseVersionObservation } from './releaseVersion.ts';
import type { ReleaseVersionObservation, ReleaseVersionState } from './releaseVersion.ts';
import { parseSetupAnalysis } from './smartSetup.ts';
import { parseProjectScriptDiscovery } from './projectScripts.ts';
import type { ApiError, JsonObject, ProjectSnapshot } from './types.ts';

export const EXTERNAL_PROJECT_CHECK_INTERVAL_MS = 30_000;
export const EXTERNAL_PROJECT_FOCUS_THROTTLE_MS = 5_000;

export interface ExternalProjectNotice {
  kind: 'changed' | 'refreshed' | 'unavailable' | 'recovery';
  message: string;
  next: 'review-settings' | 'read-saved-version' | 'refresh-project' | 'original-recovery';
}
export type ExternalProjectObservationOutcome =
  | { kind: 'observed'; projectId: string; observedAt: number; snapshot: ProjectSnapshot;
      change: 'project-files' | 'saved-version' | 'refresh'; notice: ExternalProjectNotice }
  | { kind: 'unavailable'; projectId: string; error: ApiError; notice: ExternalProjectNotice };

const encoder = new TextEncoder();
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const boundedText = (value: unknown, max: number): value is string => typeof value === 'string' && encoder.encode(value).byteLength <= max;
const count = (value: unknown, max: number): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;

function issues(value: unknown): boolean {
  return Array.isArray(value) && value.length <= 64 && value.every((item: unknown) =>
    keys(item, ['code', 'status', 'message', 'remediation']) && boundedText(item.code, 128) &&
    (item.status === 'INVALID' || item.status === 'SKIP') && boundedText(item.message, 2048) && boundedText(item.remediation, 2048));
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// Copy before inspecting or comparing: no getters, toJSON, supplied prototype,
// mutable reply alias, unbounded recursion or serialization of a draft.
// The allowance covers core's bounded configuration plus discovery hints.
export function parseExternalProjectSnapshot(value: unknown): ProjectSnapshot | null {
  try {
    const input = copyBoundedComparisonData(value, 3 * 1024 * 1024, 32_768);
    const hasSetupAnalysis = record(input) && Object.hasOwn(input, 'setupAnalysis');
    const hasScriptDiscovery = record(input) && Object.hasOwn(input, 'scriptDiscovery');
    if (!keys(input, ['root', 'observedAt', 'observationScope', 'config', 'discovery', 'assurance', 'issues',
      ...(hasSetupAnalysis ? ['setupAnalysis'] : []), ...(hasScriptDiscovery ? ['scriptDiscovery'] : [])]) ||
        !boundedText(input.root, 4096) || input.root.length === 0 || !boundedText(input.observedAt, 64) ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(input.observedAt) ||
        !Number.isFinite(Date.parse(input.observedAt)) || input.observationScope !== 'single-request-non-atomic' || !issues(input.issues)) return null;
    const config = input.config, discovery = input.discovery, assurance = input.assurance;
    if (!keys(config, ['path', 'state', 'content', 'data', 'issues']) || config.path !== 'release/mobile-release.json' ||
        typeof config.state !== 'string' || !['missing', 'invalid', 'format-valid', 'unavailable'].includes(config.state) || !issues(config.issues)) return null;
    if (config.state === 'format-valid') {
      if (!record(config.data) || config.content !== null && !parseSavedConfigContent(config.content)) return null;
    } else if (config.data !== null || config.content !== null) return null;
    if (!keys(discovery, ['state', 'partial', 'hints', 'scan', 'limits']) || discovery.state !== 'unverified' ||
        typeof discovery.partial !== 'boolean' || !record(discovery.hints) || !record(discovery.limits) ||
        Object.keys(discovery.limits).length > 32 || !Object.values(discovery.limits).every((value) => count(value, 16 * 1024 * 1024)) ||
        !keys(discovery.scan, ['entries', 'sourceFiles', 'sourceBytes', 'excludedEntries']) ||
        !Object.values(discovery.scan).every((value) => count(value, 16 * 1024 * 1024))) return null;
    if (!keys(assurance, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) ||
        assurance.basis !== 'static-text' || assurance.releaseReadiness !== 'unknown' ||
        !['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].every((key) => assurance[key] === false)) return null;
    if (hasSetupAnalysis) {
      const analysis = parseSetupAnalysis(input.setupAnalysis);
      if (!analysis || analysis.configurationState !== config.state || analysis.discoveryPartial !== discovery.partial) return null;
    }
    if (hasScriptDiscovery) {
      const scripts = parseProjectScriptDiscovery(input.scriptDiscovery);
      if (!scripts || scripts.sourcePartial !== discovery.partial) return null;
    }
    return freeze(input as unknown as ProjectSnapshot);
  } catch { return null; }
}

export function externalSnapshotComparable(snapshot: ProjectSnapshot): boolean {
  return !snapshot.discovery.partial && (snapshot.config.state === 'missing' ||
    snapshot.config.state === 'format-valid' && snapshot.config.content !== null);
}

// observedAt is known top-level observation metadata. A configuration/hint
// named observedAt (or timestamp, revision, etc.) is real DATA and stays here.
export function sameExternalProjectSnapshot(a: ProjectSnapshot, b: ProjectSnapshot): boolean {
  // Explicit JSON projection of the already parsed schema. Interface types
  // such as SavedConfigContent/Issue need not expose arbitrary index keys.
  const comparison = (snapshot: ProjectSnapshot): JsonObject => ({
    root: snapshot.root, observationScope: snapshot.observationScope,
    config: { ...snapshot.config, content: snapshot.config.content ? { ...snapshot.config.content } : null,
      issues: snapshot.config.issues.map((issue) => ({ ...issue })) },
    discovery: { ...snapshot.discovery, scan: { ...snapshot.discovery.scan }, limits: { ...snapshot.discovery.limits } },
    ...(snapshot.scriptDiscovery === undefined ? {} : { scriptDiscovery: snapshot.scriptDiscovery }),
    assurance: { ...snapshot.assurance }, issues: snapshot.issues.map((issue) => ({ ...issue })),
  });
  return sameJson(comparison(a), comparison(b));
}

// Only an already accepted, still-bound GUI version observation is a baseline.
// Reading this never advances its owner's read epoch or publishes a new result.
export function externalVersionBaseline(session: ProjectSession, state: ReleaseVersionState | null): ReleaseVersionObservation | null {
  if (!state || state.mode !== 'native' || state.reason !== null || state.pending || state.error || state.stale ||
      state.generationLost || state.selectionPending || !state.resultBinding || !state.project ||
      session.snapshot?.config.state !== 'format-valid' || session.snapshotRequest !== null || session.snapshotError || session.snapshotPredatesSave || session.sourceChanged ||
      session.saveRecoveryRequired || session.saveRecoveryNeedsReload) return null;
  const expected = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, dirtyDraft: isDirty(session), snapshotRequest: session.snapshotRequest,
    saveRecoveryRequired: session.saveRecoveryRequired };
  const matches = (binding: typeof state.project): boolean => binding !== null &&
    Object.entries(expected).every(([key, value]) => binding[key as keyof typeof expected] === value);
  if (!matches(state.project) || !matches(state.resultBinding) || state.resultBinding.readEpoch !== state.readEpoch ||
      state.resultBinding.connectionGeneration !== state.connectionGeneration || state.resultBinding.selectionGeneration !== state.selectionGeneration) return null;
  return parseReleaseVersionObservation(state.result);
}

export function sameExternalVersion(a: ReleaseVersionObservation, b: ReleaseVersionObservation): boolean {
  return a.source === b.source && a.version.name === b.version.name && a.version.build === b.version.build &&
    sameSavedConfig(a.savedConfig, b.savedConfig) && sameSavedConfig(a.savedVersion, b.savedVersion);
}

export type ExternalObservationFailure = 'unavailable' | 'incomplete' | 'mismatch' | 'cleanup-unknown';
export function externalObservationFailure(error: unknown): ExternalObservationFailure {
  // Native finality may outlive this renderer Promise. Never erase that with a
  // context switch, timer, apparent cancellation, reconnect or ordinary retry.
  try {
    const descriptor = error !== null && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const code: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (code === 'cleanup_unknown' || code === 'release_version_cleanup_unknown') return 'cleanup-unknown';
  } catch { /* Fixed public copy below; never exception text. */ }
  return 'unavailable';
}

export function externalUnavailable(projectId: string, failure: ExternalObservationFailure): ExternalProjectObservationOutcome {
  const recovery = failure === 'cleanup-unknown';
  const message = recovery ? 'The previous file check needs recovery. Your draft is kept; use the original recovery controls before trying again.' :
    failure === 'mismatch' ? 'Saved files changed during the check. Your draft is kept; refresh before using earlier checks.' :
    'Saved files could not be fully checked. Your draft is kept; refresh before using earlier checks.';
  return { kind: 'unavailable', projectId,
    error: { code: recovery ? 'cleanup_unknown' : `external_project_${failure}`, message, retryable: false },
    notice: { kind: recovery ? 'recovery' : 'unavailable', message, next: recovery ? 'original-recovery' : 'refresh-project' } };
}

export function externalObserved(projectId: string, snapshot: ProjectSnapshot, observedAt: number,
  change: 'project-files' | 'saved-version' | 'refresh'): ExternalProjectObservationOutcome {
  return { kind: 'observed', projectId, snapshot, observedAt, change,
    notice: { kind: change === 'refresh' ? 'refreshed' : 'changed',
      message: change === 'refresh' ? 'Saved files were rechecked. Your draft is kept.' : 'Files changed elsewhere; your draft is kept.',
      next: change === 'saved-version' ? 'read-saved-version' : 'review-settings' } };
}
