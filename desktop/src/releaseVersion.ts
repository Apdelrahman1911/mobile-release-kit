// One passive saved-input observation. No draft, path override, native owner,
// version policy, save authority or release-readiness decision lives here.
import { methodReason } from './certainty.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { ApiError, AppInfo, Assurance, BridgeMode, DesktopApi, HelpContent } from './types.ts';

export interface ReleaseVersionRequest { projectId: string }
export interface ReleaseVersionInputContent { bytes: number; sha256: string }
export interface ReleaseVersionObservation {
  schemaVersion: 2;
  source: string;
  version: { name: string; build: number };
  savedConfig: ReleaseVersionInputContent;
  savedVersion: ReleaseVersionInputContent;
  observationScope: 'single-request-non-atomic';
  assurance: Assurance & { basis: 'static-text' };
}
export interface ReleaseVersionApi {
  observeReleaseVersion(projectId: string): Promise<ReleaseVersionObservation>;
}

const encoder = new TextEncoder();
// Copy only exact, enumerable data descriptors. Never serialize the incoming
// object, invoke its getters/toJSON, or retain its mutable nested objects.
function fields(value: unknown, expected: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const names = Reflect.ownKeys(value);
  if (names.length !== expected.length) return null;
  const copy: Record<string, unknown> = {};
  for (const name of names) {
    if (typeof name !== 'string' || !expected.includes(name)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || descriptor.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return null;
    copy[name] = descriptor.value;
  }
  return copy;
}
export function releaseVersionRequestFits(value: unknown): value is ReleaseVersionRequest {
  try {
    const input = fields(value, ['projectId']);
    return input !== null && typeof input.projectId === 'string' && input.projectId.length > 0 && input.projectId.length <= 64 && !/[^A-Za-z0-9_-]/.test(input.projectId) &&
      encoder.encode(JSON.stringify(input)).byteLength <= 8192;
  } catch { return false; }
}
function displaySource(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 || /[\ud800-\udfff]/u.test(value) ||
      encoder.encode(value).byteLength > 512 || value.normalize('NFC') !== value) return false;
  const parts = value.split('/');
  // Display/transport safety only. Core independently owns the public-path
  // policy and original-object filesystem admission; this cannot select a read.
  return parts.length <= 12 && parts.every((part) => part.length > 0 && encoder.encode(part).byteLength <= 255 &&
    !part.startsWith('.') && !/[. ]$/.test(part) && !/[\u0000-\u001f\u007f\\:<>"|?*]/u.test(part) &&
    !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part) &&
    !['private', 'secrets', 'credentials', 'review', 'testflight', 'build', 'deriveddata', 'pods', 'node_modules', 'venv', 'dist', 'target', '__pycache__'].includes(part.toLowerCase()));
}
function contentComparison(value: unknown, maximum: number): ReleaseVersionInputContent | null {
  const input = fields(value, ['bytes', 'sha256']);
  if (!input || typeof input.bytes !== 'number' || !Number.isSafeInteger(input.bytes) || input.bytes < 1 || input.bytes > maximum ||
      typeof input.sha256 !== 'string' || input.sha256.length !== 64 || /[^0-9a-f]/.test(input.sha256)) return null;
  return { bytes: input.bytes, sha256: input.sha256 };
}
export function parseReleaseVersionObservation(value: unknown): ReleaseVersionObservation | null {
  try {
    const input = fields(value, ['schemaVersion', 'source', 'version', 'savedConfig', 'savedVersion', 'observationScope', 'assurance']);
    if (!input || input.schemaVersion !== 2 || !displaySource(input.source) || input.observationScope !== 'single-request-non-atomic') return null;
    const version = fields(input.version, ['name', 'build']);
    const savedConfig = contentComparison(input.savedConfig, 512 * 1024), savedVersion = contentComparison(input.savedVersion, 64 * 1024);
    const assurance = fields(input.assurance, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']);
    if (!savedConfig || !savedVersion || !version || typeof version.name !== 'string' || version.name.length === 0 || version.name.length > 64 || /[^0-9A-Za-z.+-]/.test(version.name) ||
        typeof version.build !== 'number' || !Number.isSafeInteger(version.build) || version.build < 1 || version.build > 2_100_000_000 ||
        !assurance || assurance.basis !== 'static-text' || assurance.releaseReadiness !== 'unknown' ||
        !['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].every((key) => assurance[key] === false)) return null;
    // No renderer iOS/marketing-version rule: the saved configuration and core
    // shared release policy decide which names are valid for this project.
    // Byte comparisons are copied DATA, not file custody or build consent.
    const result: ReleaseVersionObservation = {
      schemaVersion: 2, source: input.source, version: { name: version.name, build: version.build }, savedConfig, savedVersion,
      observationScope: 'single-request-non-atomic', assurance: {
        basis: 'static-text', projectCodeExecuted: false, toolsProbed: false, credentialsRead: false,
        gitObserved: false, storeContacted: false, writesPerformed: false, releaseReadiness: 'unknown',
      },
    };
    return encoder.encode(JSON.stringify(result)).byteLength <= 4096 ? result : null;
  } catch { return null; }
}

const errors: Record<string, string> = {
  release_version_invalid_params: 'Release-version input has an unsupported shape or size.',
  release_version_unavailable: 'Saved release-version observation is unavailable on this platform.',
  release_version_config_missing: 'Save the project configuration before reading the release version.',
  release_version_config_invalid: 'The saved configuration is invalid; correct it before reading the release version.',
  release_version_source_missing: "The saved configuration's version file was not found.",
  release_version_source_invalid: 'The version file does not satisfy the saved release-version policy.',
  release_version_unsafe: 'The saved configuration or version path cannot be read safely.',
  release_version_changed: 'The saved configuration or version source changed during observation. Read again explicitly.',
  release_version_unreadable: 'The saved configuration or version source could not be read.',
  release_version_limit: 'The release-version observation exceeded a supported input or observation limit.',
  release_version_encoding: 'The saved configuration or version source is not valid UTF-8.',
  release_version_sensitive: 'The saved configuration or version source may contain secret material; no values were returned.',
  release_version_cleanup_unknown: 'Original release-version observation cleanup could not be confirmed. Do not treat this as an observation.',
  runtime_unavailable: 'The admitted desktop runtime is unavailable. Installed engine launch remains disabled; no system-Python fallback is used.',
  unavailable: 'The passive observation service is unavailable. No saved version was observed.',
  busy: 'The passive query slots are busy. Wait for the original queries to settle before reading again.',
  environment_diagnostics_busy: 'Build-tool diagnostics must settle before reading the saved version.',
  quit_pending: 'Resolve the pending quit decision before reading the saved version.',
  shutting_down: 'The application is stopping its owned queries.',
  query_timeout: 'The read-only query exceeded its operation deadline.',
  cleanup_unknown: 'Original query cleanup is unconfirmed. Further queries are disabled; the owner is retained.',
  unknown_project: 'Select this project through the native folder picker before reading its saved version.',
  protocol_error: 'The service returned an invalid or incomplete saved-version response. No observation was accepted.',
};
export function releaseVersionError(error: unknown): ApiError {
  let code = 'protocol_error';
  try {
    const descriptor = error !== null && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (candidate === 'invalid_request') code = 'release_version_invalid_params';
    else if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
  } catch { /* Rejection messages, parser text and exception getters are not UI data. */ }
  return { code, message: errors[code]!, retryable: false };
}

export const releaseVersionHelp: HelpContent = {
  label: 'Read saved version', requiredness: 'optional', requiredWhen: 'Use this to inspect one saved release input before later release preparation.',
  what: 'Reads release/mobile-release.json and only the version file selected by that saved configuration, returning exact byte counts and SHA-256 comparisons for both.',
  why: 'See the version name and build number that shared core release policy resolves from saved files, not from an unsaved draft.',
  where: 'Choose the project root with the native folder picker. Save configuration separately; this action cannot select another path or save your draft.',
  format: 'The saved version.source points to a public UTF-8 KEY=VALUE file. Saved nameKey, buildKey and enabled platforms select the existing core version policy.',
  failure: 'Missing, invalid, unsafe, changed or unavailable inputs produce no current observation. Reads are non-atomic and external changes are not monitored. Byte comparisons are not file custody or build consent. This is not an artifact check, full preflight, native-tool check or release-readiness result.',
};

interface ProjectBinding {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  dirtyDraft: boolean; snapshotRequest: number | null; saveRecoveryRequired: boolean;
}
export interface ReleaseVersionBinding extends ProjectBinding {
  requestId: number; readEpoch: number; connectionGeneration: number; selectionGeneration: number;
}
export interface ReleaseVersionState {
  mode: BridgeMode; reason: string | null; project: ProjectBinding | null;
  readEpoch: number; connectionGeneration: number; selectionGeneration: number; generationLost: boolean; selectionPending: boolean;
  pending: ReleaseVersionBinding | null; result: ReleaseVersionObservation | null; resultBinding: ReleaseVersionBinding | null;
  stale: boolean; error: ApiError | null;
}
export type ReleaseVersionPhase = 'not-read' | 'reading' | 'observed' | 'stale' | 'missing' | 'invalid' | 'unavailable';
const previewReason = 'Browser preview cannot read saved project files or fabricate a version observation.';
const exhaustedReason = 'This observation context counter is exhausted. No earlier read can be reused.';
const saveReason = 'A configuration save is active or unverified. Finish or close that original session before reading the saved version.';
export function releaseVersionStartReason(state: ReleaseVersionState): string | null {
  if (state.generationLost) return exhaustedReason;
  if (state.mode === 'preview') return previewReason;
  if (!state.project) return 'Choose a project before reading its saved version.';
  if (state.reason) return state.reason;
  if (state.selectionPending) return 'Finish choosing a project before reading its saved version.';
  if (state.project.snapshotRequest !== null) return 'Wait for the admitted static refresh to settle, then read the saved version explicitly.';
  if (state.project.saveRecoveryRequired) return 'This project needs separate configuration recovery attention. A version read cannot resolve it.';
  return state.pending ? 'Reading the saved configuration and its version file…' : null;
}
export function releaseVersionPhase(state: ReleaseVersionState): ReleaseVersionPhase {
  if (state.pending) return 'reading';
  if (state.error) {
    if (['release_version_config_missing', 'release_version_source_missing'].includes(state.error.code)) return 'missing';
    if (['release_version_config_invalid', 'release_version_source_invalid', 'release_version_unsafe', 'release_version_encoding', 'release_version_sensitive'].includes(state.error.code)) return 'invalid';
    if (state.error.code === 'release_version_changed') return 'stale';
    return 'unavailable';
  }
  if (state.result) return state.stale ? 'stale' : 'observed';
  return state.generationLost || state.mode === 'preview' || (state.project !== null && state.reason !== null) ? 'unavailable' : 'not-read';
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function advance(value: number): number { return value < Number.MAX_SAFE_INTEGER ? value + 1 : value; }

export class ReleaseVersionController {
  private state: ReleaseVersionState = freeze<ReleaseVersionState>({ mode: 'unavailable', reason: errors.runtime_unavailable!, project: null,
    readEpoch: 0, connectionGeneration: 0, selectionGeneration: 0, generationLost: false, selectionPending: false,
    pending: null, result: null, resultBinding: null, stale: false, error: null });
  private readonly selectedProject: () => ProjectSession | null;
  private readonly configurationBusy: (projectId: string) => boolean;
  private readonly otherOperationReason: () => string | null;
  private api: DesktopApi | null = null;
  private passivePending = 0;
  private draft: ProjectSession['draft'] = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  constructor(selectedProject: () => ProjectSession | null, configurationBusy: (projectId: string) => boolean = () => false, otherOperationReason: () => string | null = () => null) {
    this.selectedProject = selectedProject; this.configurationBusy = configurationBusy; this.otherOperationReason = otherOperationReason;
  }
  getSnapshot = (): ReleaseVersionState => this.state;
  passiveBusyReason = (): string | null => this.passivePending > 0 ? 'An original saved-version query is still pending.' : null;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  startReason = (): string | null => this.otherOperationReason() ?? releaseVersionStartReason(this.state) ??
    (this.state.project && this.configurationBusy(this.state.project.projectId) ? saveReason : null);
  private update(patch: Partial<ReleaseVersionState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private retire(patch: Partial<ReleaseVersionState> = {}): void {
    const readEpoch = advance(this.state.readEpoch);
    this.update({ ...patch, readEpoch, generationLost: this.state.generationLost || readEpoch === Number.MAX_SAFE_INTEGER,
      pending: null, error: null, stale: (patch.result === undefined ? this.state.result : patch.result) !== null });
    // This is only UI retirement. The original passive supervisor still owns
    // and settles an already-submitted query; no native cancellation is claimed.
  }
  beginConnection(): void {
    this.api = null;
    this.retire({ mode: 'unavailable', reason: 'Core capabilities are loading. No saved version has been read by this connection.',
      connectionGeneration: advance(this.state.connectionGeneration) });
  }
  setConnection(api: DesktopApi, info: AppInfo): void {
    if (this.disposed) return;
    this.api = api;
    this.retire({ mode: api.mode, reason: api.mode === 'preview' ? previewReason : methodReason(info, 'release.version.observe', api.mode),
      connectionGeneration: advance(this.state.connectionGeneration) });
  }
  connectionUnavailable(): void {
    this.api = null;
    this.retire({ mode: 'unavailable', reason: errors.runtime_unavailable!, connectionGeneration: advance(this.state.connectionGeneration) });
  }
  setSelectionPending(pending: boolean): void {
    if (pending) this.retire({ selectionPending: true });
    else if (this.state.selectionPending) this.update({ selectionPending: false });
  }
  saveIntent(): void { this.retire(); }
  // App calls this BEFORE its reducer/early return, not from a React effect.
  // A failed refresh or unchanged/stale/idempotent save need not change any
  // ordinary project generation and must still retire the original read epoch.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (action.type === 'select' || action.type === 'switch') return;
    if (action.projectId !== this.state.project?.projectId) return;
    if (['snapshot-start', 'config-save-final', 'config-save-recovery', 'edit', 'new-draft', 'reset',
      'remove-forbidden', 'undo-removal', 'adopt-suggestion'].includes(action.type)) this.retire();
  }
  syncProject(): void {
    if (this.disposed) return;
    const session = this.selectedProject();
    const next: ProjectBinding | null = session ? { projectId: session.project.id, draftRevision: session.revision,
      baselineGeneration: session.baselineGeneration, observationGeneration: session.observationGeneration,
      dirtyDraft: isDirty(session), snapshotRequest: session.snapshotRequest, saveRecoveryRequired: session.saveRecoveryRequired } : null;
    const old = this.state.project, draft = session?.draft ?? null;
    if (old?.projectId === next?.projectId && old?.draftRevision === next?.draftRevision && old?.baselineGeneration === next?.baselineGeneration &&
        old?.observationGeneration === next?.observationGeneration && old?.dirtyDraft === next?.dirtyDraft && old?.snapshotRequest === next?.snapshotRequest &&
        old?.saveRecoveryRequired === next?.saveRecoveryRequired && this.draft === draft) return;
    const switched = old?.projectId !== next?.projectId;
    this.draft = draft;
    this.retire({ project: next, selectionGeneration: switched ? advance(this.state.selectionGeneration) : this.state.selectionGeneration,
      ...(switched ? { result: null, resultBinding: null } : {}) });
  }
  private current(binding: ReleaseVersionBinding): boolean {
    return !this.disposed && !this.state.generationLost && this.state.pending === binding && binding.readEpoch === this.state.readEpoch &&
      binding.connectionGeneration === this.state.connectionGeneration && binding.selectionGeneration === this.state.selectionGeneration &&
      binding.projectId === this.state.project?.projectId && binding.draftRevision === this.state.project?.draftRevision &&
      binding.baselineGeneration === this.state.project?.baselineGeneration && binding.observationGeneration === this.state.project?.observationGeneration;
  }
  async read(): Promise<void> {
    this.syncProject();
    if (this.disposed || !this.api || !this.state.project || this.startReason() !== null) return;
    const api = this.api, project = this.state.project;
    if (!releaseVersionRequestFits({ projectId: project.projectId })) { this.update({ error: releaseVersionError({ code: 'release_version_invalid_params' }) }); return; }
    const readEpoch = advance(this.state.readEpoch);
    if (readEpoch === Number.MAX_SAFE_INTEGER) { this.retire(); return; }
    const binding: ReleaseVersionBinding = freeze({ ...project, requestId: readEpoch, readEpoch,
      connectionGeneration: this.state.connectionGeneration, selectionGeneration: this.state.selectionGeneration });
    this.update({ readEpoch, pending: binding, error: null, stale: this.state.result !== null });
    this.syncProject();
    if (!this.current(binding)) return;
    if (this.configurationBusy(binding.projectId) || this.otherOperationReason()) { this.retire(); return; }
    this.passivePending += 1;
    try {
      // Only the registered ID crosses the bridge. Neither draft nor baseline
      // nor a snapshot version.source can select the observed saved files.
      const raw: unknown = await api.observeReleaseVersion(binding.projectId);
      this.syncProject();
      if (!this.current(binding)) return;
      if (this.configurationBusy(binding.projectId)) { this.retire(); return; }
      const result = parseReleaseVersionObservation(raw);
      this.syncProject();
      if (!this.current(binding)) return;
      if (!result) throw { code: 'protocol_error' };
      this.update({ pending: null, result: freeze(result), resultBinding: binding, stale: false, error: null });
    } catch (error) {
      this.syncProject();
      if (!this.current(binding)) return;
      if (this.configurationBusy(binding.projectId)) { this.retire(); return; }
      const safe = releaseVersionError(error);
      this.syncProject();
      if (!this.current(binding)) return;
      this.update({ pending: null, error: safe, stale: this.state.result !== null,
        reason: ['cleanup_unknown', 'release_version_cleanup_unknown', 'shutting_down'].includes(safe.code) ? safe.message : this.state.reason });
    } finally { this.passivePending -= 1; this.update({}); }
    // Finally releases only this original Promise's accounting, never a newer display binding.
  }
  dispose(): void { this.connectionUnavailable(); this.disposed = true; this.listeners.clear(); this.draft = null; }
}
