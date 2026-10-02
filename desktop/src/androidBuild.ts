// App-owned coordination only, following OfflinePreflightController's original
// observer/one-Start lifetime. A view, Promise or saved comparison is not native
// custody, qualification, cancellation settlement or a release approval.
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import { parseReleaseVersionObservation } from './releaseVersion.ts';
import type { ReleaseVersionState } from './releaseVersion.ts';
import { savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';
import type { ApiError, BridgeMode, HelpContent } from './types.ts';
import { androidToolSourcesActive, androidToolSourcesError, hasAndroidToolSources, parseAndroidToolSourcesStatus, sameAndroidToolSourceIdentity } from './androidToolSources.ts';
import type { AndroidToolSourceIdentity, AndroidToolSourceRole, AndroidToolSourcesStatus } from './androidToolSources.ts';
import type { AndroidMacToolchainSelection } from './androidBuildTypes.ts';
import type { AndroidCatalogIdentity, AndroidToolchainCatalogStatus } from './androidToolchainCatalogTypes.ts';
import { androidCatalogActive, androidCatalogError, parseAndroidToolchainCatalogStatus, sameAndroidCatalogIdentity, sameAndroidCatalogSelection } from './androidToolchainCatalogProtocol.ts';
import type { AndroidBuildApi, AndroidBuildArtifactValidation, AndroidBuildContext, AndroidBuildIdentity, AndroidBuildOperation, AndroidBuildSavedConfig,
  AndroidBuildSavedVersion, AndroidBuildSelection, AndroidBuildStatus, PrepareAndroidBuild } from './androidBuildTypes.ts';
import { ANDROID_BUILD_CONSENT, ANDROID_BUILD_CONSENT_MS, ANDROID_BUILD_COUNTER_MAX, androidBuildAvailabilityText,
  androidBuildCounter, androidBuildError, androidBuildOperationProgress, copyAndroidBuildRequest, parseAndroidBuildSavedConfig,
  parseAndroidBuildArtifactValidation, parseAndroidBuildSavedVersion, parseAndroidBuildStatus, sameAndroidBuildData, sameAndroidBuildIdentity, sameAndroidBuildSavedPair } from './androidBuildProtocol.ts';

export type AndroidBuildSavedSelection = Pick<AndroidBuildSelection, 'module' | 'variant' | 'applicationId'>;
interface VersionObservationBinding {
  observationGeneration: number; requestId: number; readEpoch: number; connectionGeneration: number; selectionGeneration: number;
}
export interface AndroidBuildProject {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  savedConfig: AndroidBuildSavedConfig | null; savedVersion: AndroidBuildSavedVersion | null;
  uploadCertificateSha256: string | null;
  selection: AndroidBuildSavedSelection | null; versionObservation: VersionObservationBinding | null; inputIssue: string | null;
  dirtyDraft: boolean; snapshotPending: boolean; versionPending: boolean; saveRecoveryRequired: boolean;
}
export interface AndroidBuildBinding {
  context: AndroidBuildContext; selection: AndroidBuildSavedSelection; toolchainSelection: AndroidMacToolchainSelection | null;
  observationGeneration: number; versionObservation: VersionObservationBinding;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
}
export interface AndroidBuildConsent extends AndroidBuildIdentity { binding: AndroidBuildBinding; acknowledged: boolean; deadline: number }
export interface AndroidBuildState {
  mode: BridgeMode; project: AndroidBuildProject | null; visible: boolean; selectionPending: boolean; verifyUploadSignature: boolean;
  catalogStatus: AndroidToolchainCatalogStatus | null; catalogListening: boolean; catalogReadPending: boolean;
  catalogPending: 'refresh' | 'select' | null; catalogUnconfirmed: boolean; catalogCancelClaimed: AndroidCatalogIdentity | null;
  catalogError: ApiError | null; catalogIssue: boolean;
  toolSources: AndroidToolSourcesStatus | null; sourcesListening: boolean; sourcesReadPending: boolean;
  sourcesPending: boolean; sourcesUnconfirmed: boolean; sourcesIssue: boolean; sourcesError: ApiError | null;
  sourcesCancelClaimed: AndroidToolSourceIdentity | null;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
  listening: boolean; initialized: boolean; readPending: boolean; status: AndroidBuildStatus | null;
  consent: AndroidBuildConsent | null; pending: 'prepare' | 'start' | null; originalUnconfirmed: boolean;
  historical: boolean; cancelClaimed: AndroidBuildIdentity | null; error: ApiError | null;
  observationIssue: 'bridge' | 'protocol' | null; nativeBlocked: boolean; integrityFailed: boolean; generationLost: boolean;
}
type Port = AndroidBuildApi & { mode: BridgeMode };
interface Observer { api: Port; active: boolean; generation: number; unlisten: (() => void) | null; reading: Promise<void> | null; status: AndroidBuildStatus | null;
  catalogUnlisten: (() => void) | null; catalogReading: Promise<void> | null; catalog: AndroidToolchainCatalogStatus | null;
  sourcesUnlisten: (() => void) | null; sourcesReading: Promise<void> | null; sources: AndroidToolSourcesStatus | null }
interface Attempt {
  observer: Observer; binding: AndroidBuildBinding; previous: AndroidBuildIdentity | null; after: number;
  identity: AndroidBuildIdentity | null; prepareSent: boolean; prepareReply: boolean; deadline: number;
  startSent: boolean; startAfter: number; retired: boolean; settled: boolean;
}
interface Context {
  selectedProject: () => ProjectSession | null; releaseVersion: () => ReleaseVersionState | null;
  otherOperationReason: () => string | null; now?: () => number;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
const id = (op: AndroidBuildIdentity): AndroidBuildIdentity => ({ operationId: op.operationId, ownerGeneration: op.ownerGeneration });
const active = (op: AndroidBuildOperation | null | undefined): boolean => !!op && op.phase !== 'terminal';
// The snapshot is not serialized or retained in state. Read only the bounded
// display fields through data descriptors, never getters or a dirty baseline.
function own(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const field = Object.getOwnPropertyDescriptor(value, key);
  return field?.enumerable && Object.hasOwn(field, 'value') ? field.value : undefined;
}
function savedSelection(data: unknown): AndroidBuildSavedSelection | null {
  const android = own(data, 'android'), module = own(android, 'module'), applicationId = own(android, 'applicationId');
  const configuredVariant = own(android, 'variant');
  const variant = configuredVariant === undefined && android !== null && typeof android === 'object' && !Object.hasOwn(android, 'variant') ? 'release' : configuredVariant;
  // Public labels only; the default is core's saved android.variant default.
  // No task or argv is derived, and core independently selects/admits inputs.
  if (own(android, 'enabled') !== true || typeof module !== 'string' || !module.startsWith(':') || module.length > 512 ||
      /[^0-9A-Za-z_.:-]/.test(module) || typeof variant !== 'string' || variant.length < 1 || variant.length > 128 || /[^0-9A-Za-z_-]/.test(variant) ||
      typeof applicationId !== 'string' || applicationId.length > 255 || /[^A-Za-z0-9_.]/.test(applicationId) ||
      !/^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(applicationId)) return null;
  return { module, variant, applicationId };
}
function projectObservation(session: ProjectSession, version: ReleaseVersionState | null): AndroidBuildProject {
  const project: AndroidBuildProject = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, savedConfig: null, savedVersion: null, uploadCertificateSha256: null, selection: null, versionObservation: null,
    dirtyDraft: isDirty(session), snapshotPending: session.snapshotRequest !== null, versionPending: version?.pending !== null && version?.pending !== undefined,
    saveRecoveryRequired: session.saveRecoveryRequired, inputIssue: 'Refresh a current, format-valid saved configuration, then read its saved version. Prior snapshots and editor baselines are not build inputs.' };
  try {
    if (project.snapshotPending || session.snapshotError !== null || session.snapshotPredatesSave || session.snapshot === null ||
        !Number.isFinite(session.observedAt) || session.observedAt === null || session.observedAt < 0 || session.observationGeneration < 1) return project;
    const observed = savedConfigFromSnapshot(session.snapshot), compared = parseAndroidBuildSavedConfig(session.savedConfigContent);
    if (!observed || !compared || !sameAndroidBuildData(observed, compared)) return project;
    project.savedConfig = compared;
    const data = own(own(session.snapshot, 'config'), 'data');
    const validation = parseAndroidBuildArtifactValidation({ mode: 'upload-signature',
      uploadCertificateSha256: own(own(data, 'android'), 'uploadCertificateSha256') });
    project.uploadCertificateSha256 = validation?.mode === 'upload-signature' ? validation.uploadCertificateSha256 : null;
    project.selection = savedSelection(data);
    if (!project.selection) { project.inputIssue = 'Enable and save the intended Android applicationId, explicit module and variant selection, then refresh the saved configuration.'; return project; }
    project.inputIssue = 'Read a complete saved-version observation for this current configuration. An older, pending, failed or partial version response cannot authorize a build.';
    if (!version || version.mode !== 'native' || version.reason !== null || version.generationLost || version.selectionPending || version.pending !== null ||
        version.stale || version.error !== null || !version.resultBinding || !version.project) return project;
    // Reparse the COMPLETE observe-v2 response, including its fixed assurance,
    // scope and both byte comparisons. Picking just name/build would lose proof
    // of which saved configuration selected the version source.
    const result = parseReleaseVersionObservation(version.result), binding = version.resultBinding;
    if (!result) return project;
    const expected = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
      observationGeneration: session.observationGeneration, dirtyDraft: project.dirtyDraft, snapshotRequest: null, saveRecoveryRequired: false };
    const fields = ['projectId', 'draftRevision', 'baselineGeneration', 'observationGeneration', 'dirtyDraft', 'snapshotRequest', 'saveRecoveryRequired'] as const;
    const current = version.project;
    if (!fields.every((key) => binding[key] === expected[key] && current[key] === expected[key]) ||
        binding.readEpoch !== version.readEpoch || binding.requestId !== version.readEpoch || binding.connectionGeneration !== version.connectionGeneration ||
        binding.selectionGeneration !== version.selectionGeneration || ![binding.observationGeneration, binding.requestId, binding.readEpoch,
          binding.connectionGeneration, binding.selectionGeneration].every(androidBuildCounter)) return project;
    if (!sameAndroidBuildData(result.savedConfig, compared) || own(own(data, 'version'), 'source') !== result.source) {
      project.inputIssue = 'The saved-version response does not match the current saved configuration/source. Refresh the saved configuration and explicitly read the saved version again.'; return project;
    }
    const savedVersion = parseAndroidBuildSavedVersion({ ...result.savedVersion, source: result.source, name: result.version.name, build: result.version.build });
    if (!savedVersion) return project;
    project.savedVersion = savedVersion;
    project.versionObservation = { observationGeneration: binding.observationGeneration, requestId: binding.requestId, readEpoch: binding.readEpoch,
      connectionGeneration: binding.connectionGeneration, selectionGeneration: binding.selectionGeneration };
    project.inputIssue = null;
  } catch { /* Snapshot hooks and parser exceptions never become UI text. */ }
  return project;
}
export function androidBuildOwnerReason(state: AndroidBuildState): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost) return 'Android-build ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.';
  if (state.sourcesUnconfirmed || state.sourcesPending || state.sourcesIssue || androidToolSourcesActive(state.toolSources)) return 'The original Android tool picker or folder check is active or unconfirmed. Keep tool-selection Status and Cancel before conflicting work.';
  if (state.catalogUnconfirmed || state.catalogPending || state.catalogIssue || androidCatalogActive(state.catalogStatus)) return 'The original Android tool catalog is still reading, stopping or unconfirmed. Keep catalog Status and Cancel before conflicting work.';
  if (state.originalUnconfirmed || state.pending || active(state.status?.operation)) return 'The Android build holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.';
  if (state.mode === 'native' && state.observationIssue) return 'The original Android-build status is unverified. Check retained Status before conflicting work.';
  return null;
}

export class AndroidBuildController {
  private state: AndroidBuildState = freeze<AndroidBuildState>({ mode: 'unavailable', project: null, visible: false, selectionPending: false, verifyUploadSignature: false,
    connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0, requestGeneration: 0, listening: false, initialized: false, readPending: false,
    status: null, consent: null, pending: null, originalUnconfirmed: false, historical: false, cancelClaimed: null, error: null,
    catalogStatus: null, catalogListening: false, catalogReadPending: false, catalogPending: null, catalogUnconfirmed: false,
    catalogCancelClaimed: null, catalogError: null, catalogIssue: false,
    toolSources: null, sourcesListening: false, sourcesReadPending: false, sourcesPending: false,
    sourcesUnconfirmed: false, sourcesIssue: false, sourcesError: null, sourcesCancelClaimed: null,
    observationIssue: null, nativeBlocked: false, integrityFailed: false, generationLost: false });
  private readonly context: Context;
  private observer: Observer | null = null;
  private attempt: Attempt | null = null;
  private cancelClaim: AndroidBuildIdentity | null = null;
  private catalogAttempt: { observer: Observer; before: number; after: number; identity: AndroidCatalogIdentity | null;
    selection: AndroidMacToolchainSelection | null; settled: boolean } | null = null;
  private catalogCancelClaim: AndroidCatalogIdentity | null = null;
  private sourcesAttempt: { observer: Observer; before: number; after: number; role: AndroidToolSourceRole; projectId: string; retired: boolean;
    identity: AndroidToolSourceIdentity | null; settled: boolean } | null = null;
  private sourcesCancelClaim: AndroidToolSourceIdentity | null = null;

  private draftReference: ProjectSession['draft'] = null;
  private snapshotReference: ProjectSession['snapshot'] = null;
  private versionReference: ReleaseVersionState['result'] = null;
  private versionBindingReference: ReleaseVersionState['resultBinding'] = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Set<() => void>();
  private disposed = false;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): AndroidBuildState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private now(): number { return (this.context.now ?? (() => performance.now()))(); }
  private update(patch: Partial<AndroidBuildState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private advance(field: 'connectionGeneration' | 'selectionGeneration' | 'contextGeneration' | 'requestGeneration'): Partial<AndroidBuildState> {
    const next = this.state[field] + 1;
    return { [field]: Math.min(next, ANDROID_BUILD_COUNTER_MAX), generationLost: this.state.generationLost || !androidBuildCounter(next) };
  }
  private clearTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private retire(patch: Partial<AndroidBuildState> = {}, stop = true): void {
    this.clearTimer();
    if (this.attempt) this.attempt.retired = true;
    this.update({ ...patch, consent: null, historical: !!this.state.status?.operation || this.state.historical });
    if (stop) this.stopOriginal();
  }
  private fail(error: unknown, protocol = false): void {
    this.retire({ error: androidBuildError(error), observationIssue: protocol ? 'protocol' : 'bridge',
      integrityFailed: this.state.integrityFailed || protocol, nativeBlocked: this.state.nativeBlocked || protocol });
  }
  // Call before the reducer/early return, including no-op or rejected actions.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (this.disposed) return;
    if (action.type === 'select' || action.type === 'switch') { this.selectionIntent(); return; }
    const relevant = ['snapshot-start', 'snapshot-done', 'snapshot-failed', 'new-draft', 'edit', 'remove-forbidden', 'undo-removal',
      'forget-removal', 'reset', 'adopt-suggestion', 'config-save-intent', 'config-save-final', 'config-save-recovery'];
    if (relevant.includes(action.type) && (action.projectId === this.state.project?.projectId || action.projectId === this.attempt?.binding.context.projectId))
      this.retire(this.advance('contextGeneration'));
  }
  selectionIntent(): void { if (!this.disposed) { this.retire(this.advance('selectionGeneration')); if (this.observer) this.stopSources(this.observer); } }
  snapshotIntent(projectId: string): void {
    if (!this.disposed && (projectId === this.state.project?.projectId || projectId === this.attempt?.binding.context.projectId))
      this.retire(this.advance('contextGeneration'));
  }
  versionIntent(): void { if (!this.disposed) this.retire(this.advance('contextGeneration')); }
  setVerifyUploadSignature(verifyUploadSignature: boolean): void {
    if (!this.disposed && typeof verifyUploadSignature === 'boolean' && verifyUploadSignature !== this.state.verifyUploadSignature)
      this.retire({ ...this.advance('contextGeneration'), verifyUploadSignature });
  }
  private artifactValidation(): AndroidBuildArtifactValidation | null {
    return this.state.verifyUploadSignature ? parseAndroidBuildArtifactValidation({ mode: 'upload-signature',
      uploadCertificateSha256: this.state.project?.uploadCertificateSha256 }) : { mode: 'structure-and-version', uploadCertificateSha256: null };
  }
  // Subscribe synchronously to ReleaseVersionController; a React effect after
  // rendering is too late to retire consent at read-pending/replacement time.
  syncReleaseVersion = (): void => { this.syncProject(); };
  setSelectionPending(selectionPending: boolean): void {
    if (!this.disposed && selectionPending !== this.state.selectionPending) this.retire({ ...this.advance('selectionGeneration'), selectionPending });
  }
  syncProject(): void {
    if (this.disposed) return;
    const session = this.context.selectedProject(), version = this.context.releaseVersion();
    const next = session ? projectObservation(session, version) : null, draft = session?.draft ?? null, snapshot = session?.snapshot ?? null;
    const result = version?.result ?? null, binding = version?.resultBinding ?? null;
    if (sameAndroidBuildData(next, this.state.project) && this.draftReference === draft && this.snapshotReference === snapshot &&
        this.versionReference === result && this.versionBindingReference === binding) return;
    if (next?.projectId !== this.state.project?.projectId && this.observer) this.stopSources(this.observer);
    this.draftReference = draft; this.snapshotReference = snapshot; this.versionReference = result; this.versionBindingReference = binding;
    const badCounter = next !== null && ![next.draftRevision, next.baselineGeneration, next.observationGeneration].every(androidBuildCounter);
    this.retire({ ...this.advance('contextGeneration'), project: next, generationLost: this.state.generationLost || badCounter ||
      this.state.contextGeneration === ANDROID_BUILD_COUNTER_MAX });
  }
  setVisible(visible: boolean): void {
    if (this.disposed || visible === this.state.visible) return;
    if (!visible && this.attempt && !this.attempt.startSent && !this.attempt.settled) this.retire({ ...this.advance('contextGeneration'), visible });
    else this.update({ visible }); // A started run stays app-owned across pages.
  }
  private needsOriginal(observer: Observer): boolean {
    return this.attempt?.observer === observer && this.attempt.prepareSent && !this.attempt.settled || active(observer.status?.operation)
      || this.catalogAttempt?.observer === observer && !this.catalogAttempt.settled || androidCatalogActive(observer.catalog)
      || this.observer === observer && this.state.catalogUnconfirmed
      || this.sourcesAttempt?.observer === observer && !this.sourcesAttempt.settled || androidToolSourcesActive(observer.sources);
  }
  private detach(observer: Observer): void {
    observer.active = false;
    try { observer.unlisten?.(); } catch { /* Listener release is not native settlement. */ }
    observer.unlisten = null;
    try { observer.catalogUnlisten?.(); } catch { /* Not native settlement. */ }
    observer.catalogUnlisten = null;
    try { observer.sourcesUnlisten?.(); } catch { /* Listener release is not native settlement. */ }
    observer.sourcesUnlisten = null;
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.retire(this.advance('connectionGeneration'));
    const observer = this.observer;
    if (observer) { this.stopCatalog(observer); this.stopSources(observer); }
    if (observer && (this.needsOriginal(observer) || this.state.nativeBlocked || this.state.integrityFailed)) {
      this.update({ nativeBlocked: true, historical: true }); return; // Never adopt a replacement document/API.
    }
    if (observer) this.detach(observer);
    this.observer = null;
    this.catalogAttempt = null; this.catalogCancelClaim = null; this.sourcesAttempt = null; this.sourcesCancelClaim = null;
    this.update({ mode: 'unavailable', listening: false, initialized: false, readPending: false,
      catalogStatus: null, catalogListening: false, catalogReadPending: false, catalogPending: null, catalogUnconfirmed: false, catalogIssue: false,
      toolSources: null, sourcesListening: false, sourcesReadPending: false, sourcesPending: false, sourcesUnconfirmed: false, sourcesIssue: false, sourcesError: null });
  }
  async connect(api: Port): Promise<void> {
    if (this.disposed || this.observer?.api === api) return;
    if (this.observer) this.beginConnection();
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost || this.observer) return;
    this.update({ mode: api.mode, observationIssue: null, error: null });
    if (api.mode !== 'native') return;
    const observer: Observer = { api, active: true, generation: this.state.connectionGeneration, unlisten: null, reading: null, status: null,
      catalogUnlisten: null, catalogReading: null, catalog: null, sourcesUnlisten: null, sourcesReading: null, sources: null };
    this.observer = observer;
    try {
      const unlisten = await api.subscribeAndroidBuild((value) => { if (observer.active) this.receive(observer, value); });
      if (!observer.active || this.observer !== observer || this.disposed && !this.needsOriginal(observer)) { unlisten(); return; }
      observer.unlisten = unlisten; this.update({ listening: true });
      const catalogUnlisten = await api.subscribeAndroidToolchainCatalog((value) => { if (observer.active) this.receiveCatalog(observer, value); });
      if (!observer.active || this.observer !== observer || this.disposed && !this.needsOriginal(observer)) { catalogUnlisten(); return; }
      observer.catalogUnlisten = catalogUnlisten; this.update({ catalogListening: true });
      await this.checkCatalogStatus();
      if (hasAndroidToolSources(api)) {
        const sourcesUnlisten = await api.subscribeAndroidToolSources!((value) => { if (observer.active) this.receiveSources(observer, value); });
        if (!observer.active || this.observer !== observer || this.disposed && !this.needsOriginal(observer)) { sourcesUnlisten(); return; }
        observer.sourcesUnlisten = sourcesUnlisten; this.update({ sourcesListening: true });
        await this.checkToolSources();
      }
      await this.checkStatus(); // Subscribe before reading or preparing.
    } catch (error) { if (observer.active) this.fail(error); }
  }
  private matches(attempt: Attempt): boolean {
    const p = this.state.project, b = attempt.binding;
    return !this.disposed && !attempt.retired && this.attempt === attempt && this.observer === attempt.observer && attempt.observer.active &&
      b.connectionGeneration === this.state.connectionGeneration && b.selectionGeneration === this.state.selectionGeneration &&
      b.contextGeneration === this.state.contextGeneration && b.requestGeneration === this.state.requestGeneration && p !== null && p.inputIssue === null &&
      b.observationGeneration === p.observationGeneration && sameAndroidBuildData(b.versionObservation, p.versionObservation) &&
      sameAndroidBuildData(b.selection, p.selection) && b.context.projectId === p.projectId && b.context.draftRevision === p.draftRevision &&
      b.context.baselineGeneration === p.baselineGeneration && p.savedConfig !== null && p.savedVersion !== null &&
      sameAndroidBuildData(b.context.artifactValidation, this.artifactValidation()) &&
      sameAndroidCatalogSelection(b.toolchainSelection, this.state.catalogStatus?.selected ?? null) &&
      sameAndroidBuildSavedPair(b.context, { savedConfig: p.savedConfig, savedVersion: p.savedVersion });
  }
  private originCandidate(attempt: Attempt, status: AndroidBuildStatus): boolean {
    const op = status.operation;
    return !!op && status.statusRevision > attempt.after && !sameAndroidBuildIdentity(op, attempt.previous) &&
      sameAndroidBuildData(op.context, attempt.binding.context) && (!attempt.identity || sameAndroidBuildIdentity(op, attempt.identity));
  }
  private reconcile(observer: Observer): void {
    const status = observer.status, attempt = this.attempt, op = status?.operation;
    if (!status || !op) return;
    const matched = attempt?.observer === observer && sameAndroidBuildIdentity(attempt.identity, op);
    if (attempt && matched && op.phase === 'terminal') attempt.settled = true;
    const finished = !!attempt && matched && attempt.settled;
    const startObserved = !!attempt && matched && attempt.startSent && status.statusRevision > attempt.startAfter && op.phase !== 'awaiting-consent';
    const blocked = this.state.nativeBlocked || ['shutdown', 'document-lost', 'cleanup-unknown'].includes(status.availability) || op.phase === 'unknown';
    const consent = this.state.consent;
    this.update({ status, initialized: true, nativeBlocked: blocked, pending: finished || startObserved ? null : this.state.pending,
      originalUnconfirmed: finished || startObserved ? false : this.state.originalUnconfirmed,
      historical: !attempt || !matched || attempt.retired || !this.matches(attempt),
      consent: attempt && consent && matched && this.matches(attempt) && !blocked && !attempt.startSent && op.phase === 'awaiting-consent' && op.intentUsable ? consent : null });
    if (!this.state.consent) this.clearTimer();
    if (attempt?.retired) this.stopOriginal();
    if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
  }
  private receive(observer: Observer, value: unknown): AndroidBuildStatus | null {
    if (!observer.active) return null;
    this.syncProject(); // Replies cannot rely on a last-rendered input pair.
    const status = parseAndroidBuildStatus(value);
    if (!status) { this.fail({ code: 'android_build_protocol' }, true); return null; }
    const previous = observer.status, a = previous?.operation, b = status.operation;
    if (previous && status.statusRevision < previous.statusRevision) {
      if (a && b && sameAndroidBuildIdentity(a, b) && !androidBuildOperationProgress(b, a)) this.fail({ code: 'android_build_protocol' }, true);
      return status;
    }
    if (previous && status.statusRevision === previous.statusRevision && !sameAndroidBuildData(previous, status)) {
      this.fail({ code: 'android_build_protocol' }, true); return null;
    }
    if (a && b && sameAndroidBuildIdentity(a, b) && !androidBuildOperationProgress(a, b)) { this.fail({ code: 'android_build_protocol' }, true); return null; }
    const attempt = this.attempt;
    if (attempt?.observer === observer && attempt.prepareSent) {
      if (attempt.identity ? !sameAndroidBuildIdentity(attempt.identity, b) :
          b && !sameAndroidBuildIdentity(b, attempt.previous) && !this.originCandidate(attempt, status)) { this.fail({ code: 'android_build_protocol' }, true); return null; }
      if (b && this.originCandidate(attempt, status) && !attempt.startSent &&
          (b.phase === 'starting' || b.phase === 'running' || b.outcome === 'complete')) { this.fail({ code: 'android_build_protocol' }, true); return null; }
      // While Prepare is pending, repeated previous-terminal Status is allowed
      // but belongs to the old review, not this attempt's changed selection.
      const belongsToAttempt = sameAndroidBuildIdentity(attempt.identity, b) || this.originCandidate(attempt, status);
      if (belongsToAttempt && b?.result && !sameAndroidCatalogSelection(
          b.result.schemaVersion === 2 ? b.result.toolchainSelection : null, attempt.binding.toolchainSelection)) {
        this.fail({ code: 'android_build_protocol' }, true); return null;
      }
      const selected = belongsToAttempt ? b?.activity?.selection : null;
      if (selected && !sameAndroidBuildData({ module: selected.module, variant: selected.variant, applicationId: selected.applicationId }, attempt.binding.selection)) {
        this.fail({ code: 'android_build_protocol' }, true); return null;
      }
    } else if (previous && !sameAndroidBuildIdentity(a ?? null, b) && (a !== null || b !== null)) {
      this.fail({ code: 'android_build_protocol' }, true); return null; // Unsolicited foreign IDs cannot authorize a run.
    }
    if (status.statusRevision === ANDROID_BUILD_COUNTER_MAX) this.retire({ generationLost: true });
    observer.status = status;
    if (observer === this.observer) {
      this.update({ status, initialized: true, nativeBlocked: this.state.nativeBlocked ||
        ['shutdown', 'document-lost', 'cleanup-unknown'].includes(status.availability), historical: this.state.historical || !attempt });
      this.reconcile(observer); this.expireConsent();
    }
    return status;
  }
  canCheckStatus(): boolean { return !this.disposed && !!this.observer?.active && !this.state.readPending; }
  async checkStatus(): Promise<void> {
    const observer = this.observer;
    if (this.disposed || !observer?.active) return;
    if (observer.reading) return observer.reading;
    const work = Promise.resolve().then(async () => {
      if (!observer.active) return;
      try {
        const status = this.receive(observer, await observer.api.androidBuildStatus());
        if (status && status.statusRevision >= (observer.status?.statusRevision ?? 0) && !this.state.integrityFailed)
          this.update({ observationIssue: null, error: null });
      } catch (error) { if (observer.active) this.fail(error); }
      this.expireConsent();
    });
    observer.reading = work; this.update({ readPending: true });
    try { await work; } finally {
      if (observer.reading === work) { observer.reading = null; if (this.observer === observer) this.update({ readPending: false }); }
    }
  }

  private sourcesFail(error: unknown, protocol = false): void {
    this.retire({ sourcesError: androidToolSourcesError(error), sourcesIssue: true,
      nativeBlocked: this.state.nativeBlocked || protocol, integrityFailed: this.state.integrityFailed || protocol });
  }
  private receiveSources(observer: Observer, value: unknown): AndroidToolSourcesStatus | null {
    if (!observer.active) return null;
    const status = parseAndroidToolSourcesStatus(value), previous = observer.sources, attempt = this.sourcesAttempt;
    if (!status) { this.sourcesFail(null, true); return null; }
    if (previous && status.statusRevision < previous.statusRevision) return status;
    if (previous && status.statusRevision === previous.statusRevision && !sameAndroidBuildData(previous, status)
        || previous && status.sourceGeneration < previous.sourceGeneration
        || previous?.phase === 'unknown' && status.phase !== 'unknown') { this.sourcesFail(null, true); return null; }
    const ours = attempt?.observer === observer;
    if (ours && status.sourceGeneration === attempt.before + 1 && status.projectId !== attempt.projectId &&
        !(status.projectId === null && status.selections.length === 0
          && ['context-changed', 'document-lost', 'shutdown', 'cleanup-unknown'].includes(status.reason))) {
      this.sourcesFail(null, true); return null;
    }
    if (previous && status.sourceGeneration !== previous.sourceGeneration &&
        (!ours || status.sourceGeneration !== attempt.before + 1 || status.statusRevision <= attempt.after
          || status.operation?.role !== attempt.role)) { this.sourcesFail(null, true); return null; }
    if (previous && previous.sourceGeneration === status.sourceGeneration && !sameAndroidToolSourceIdentity(previous.operation, status.operation)
        || ours && attempt.identity && !sameAndroidToolSourceIdentity(attempt.identity, status.operation)) { this.sourcesFail(null, true); return null; }
    if (previous && previous.sourceGeneration === status.sourceGeneration &&
        (!androidToolSourcesActive(previous) && androidToolSourcesActive(status)
          || ['refused', 'cancelled', 'stopping'].includes(previous.phase) && status.phase === 'selected'
          || previous.phase === 'checking' && status.phase === 'picking'
          || previous.phase === 'stopping' && ['picking', 'checking'].includes(status.phase))) {
      this.sourcesFail(null, true); return null;
    }
    if (ours && !attempt.identity && status.sourceGeneration === attempt.before + 1 && status.statusRevision > attempt.after
        && status.operation?.role === attempt.role) attempt.identity = status.operation;
    const acknowledged = !!ours && attempt.identity !== null && sameAndroidToolSourceIdentity(attempt.identity, status.operation)
      && status.statusRevision > attempt.after;
    if (acknowledged) attempt.settled = !androidToolSourcesActive(status);
    observer.sources = status;
    if (observer === this.observer) this.update({ toolSources: status,
      sourcesPending: acknowledged ? false : this.state.sourcesPending, sourcesUnconfirmed: acknowledged ? false : this.state.sourcesUnconfirmed,
      nativeBlocked: this.state.nativeBlocked || status.phase === 'unknown' || ['cleanup-unknown', 'document-lost', 'shutdown'].includes(status.availability) });
    if ((this.disposed || ours && attempt.retired) && androidToolSourcesActive(status)) this.stopSources(observer);
    if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
    return status;
  }
  canCheckToolSources(): boolean {
    return !this.disposed && !!this.observer?.active && hasAndroidToolSources(this.observer.api) && !this.state.sourcesReadPending;
  }
  async checkToolSources(): Promise<void> {
    const observer = this.observer;
    if (this.disposed || !observer?.active || !hasAndroidToolSources(observer.api)) return;
    if (observer.sourcesReading) return observer.sourcesReading;
    const work = Promise.resolve().then(async () => {
      if (!observer.active) return;
      try {
        const status = this.receiveSources(observer, await observer.api.androidToolSourcesStatus!());
        if (status && status.statusRevision >= (observer.sources?.statusRevision ?? 0) && !this.state.integrityFailed)
          this.update({ sourcesIssue: false, sourcesError: null });
      } catch (error) { if (observer.active) this.sourcesFail(error); }
    });
    observer.sourcesReading = work; this.update({ sourcesReadPending: true });
    try { await work; } finally {
      if (observer.sourcesReading === work) { observer.sourcesReading = null; if (this.observer === observer) this.update({ sourcesReadPending: false }); }
    }
  }
  sourceActionReason = (): string | null => {
    if (this.disposed || this.state.mode !== 'native' || !this.observer?.active || !hasAndroidToolSources(this.observer.api))
      return 'Open a supported native app to choose Android tool folders.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return androidBuildOwnerReason(this.state);
    if (this.observer.generation !== this.state.connectionGeneration || !this.state.sourcesListening || !this.state.toolSources || this.state.sourcesIssue)
      return 'Check the original tool-selection status before browsing.';
    if (this.state.sourcesPending || this.state.sourcesUnconfirmed || androidToolSourcesActive(this.state.toolSources))
      return 'Wait for the original picker and folder checks, or cancel that original selection.';
    if (this.state.catalogPending || this.state.catalogUnconfirmed || this.state.catalogIssue || androidCatalogActive(this.state.catalogStatus)
        || this.state.pending || this.state.originalUnconfirmed || active(this.state.status?.operation))
      return 'Finish or cancel the current tool-catalog or build operation first.';
    if (!this.state.project || this.state.selectionPending) return 'Choose a mobile project first.';
    if (this.state.toolSources.availability !== 'available') return androidBuildAvailabilityText[this.state.toolSources.availability];
    return this.context.otherOperationReason();
  };
  async chooseToolSource(role: AndroidToolSourceRole): Promise<void> {
    this.syncProject();
    if (!['jdk', 'sdk', 'gradle'].includes(role) || this.sourceActionReason() || !this.observer?.sources || !this.state.project) return;
    const observer = this.observer, previous = observer.sources!;
    if (previous.sourceGeneration >= ANDROID_BUILD_COUNTER_MAX - 1) { this.retire({ generationLost: true }); return; }
    const request = { schemaVersion: 1 as const, sourceGeneration: previous.sourceGeneration, projectId: this.state.project.projectId, role };
    this.retire(this.advance('contextGeneration'));
    const attempt = { observer, before: previous.sourceGeneration, after: previous.statusRevision, role, projectId: request.projectId, retired: false,
      identity: null as AndroidToolSourceIdentity | null, settled: false };
    this.sourcesAttempt = attempt; this.sourcesCancelClaim = null;
    this.update({ sourcesPending: true, sourcesUnconfirmed: true, sourcesError: null, sourcesCancelClaimed: null });
    try {
      const value = await observer.api.chooseAndroidToolSource!(request);
      if (!observer.active || this.sourcesAttempt !== attempt) return;
      const status = parseAndroidToolSourcesStatus(value);
      if (!status || status.sourceGeneration !== attempt.before + 1 || status.operation?.role !== role || status.statusRevision <= attempt.after) {
        this.sourcesFail(null, true); return;
      }
      this.receiveSources(observer, status);
    } catch (error) { if (observer.active && this.sourcesAttempt === attempt && !attempt.settled) this.sourcesFail(error); }
  }
  canCancelToolSources(): boolean {
    const observer = this.observer, status = observer?.sources;
    return !this.disposed && !!observer?.active && hasAndroidToolSources(observer.api) && !!status?.operation
      && androidToolSourcesActive(status) && !sameAndroidToolSourceIdentity(this.sourcesCancelClaim, status.operation);
  }
  cancelToolSources(): boolean { return !!this.observer && this.stopSources(this.observer); }
  private stopSources(observer: Observer): boolean {
    // Preserve context/connection/disposal STOP intent even when the chooser
    // reply was lost and its original identity has not arrived yet.
    if (this.sourcesAttempt?.observer === observer && !this.sourcesAttempt.settled) this.sourcesAttempt.retired = true;
    const status = observer.sources;
    if (!observer.active || !hasAndroidToolSources(observer.api) || !status?.operation || !androidToolSourcesActive(status)
        || sameAndroidToolSourceIdentity(this.sourcesCancelClaim, status.operation)) return false;
    const identity = status.operation;
    this.sourcesCancelClaim = identity; this.update({ sourcesCancelClaimed: identity });
    void (async () => {
      try {
        const value = await observer.api.cancelAndroidToolSource!({ schemaVersion: 1,
          sourceGeneration: identity.sourceGeneration, operationId: identity.operationId });
        if (!observer.active) return;
        const result = parseAndroidToolSourcesStatus(value);
        if (!result || !sameAndroidToolSourceIdentity(result.operation, identity)) { this.sourcesFail(null, true); return; }
        this.receiveSources(observer, result);
      } catch (error) { if (observer.active) this.sourcesFail(error); }
    })();
    return true;
  }

  private catalogFail(error: unknown, protocol = false): void {
    this.retire({ catalogError: androidCatalogError(error), catalogIssue: true,
      nativeBlocked: this.state.nativeBlocked || protocol, integrityFailed: this.state.integrityFailed || protocol });
  }
  private receiveCatalog(observer: Observer, value: unknown): AndroidToolchainCatalogStatus | null {
    if (!observer.active) return null;
    const status = parseAndroidToolchainCatalogStatus(value);
    if (!status) { this.catalogFail(null, true); return null; }
    const previous = observer.catalog, attempt = this.catalogAttempt;
    if (previous && status.statusRevision < previous.statusRevision) return status;
    if (previous && status.statusRevision === previous.statusRevision && !sameAndroidBuildData(previous, status)) {
      this.catalogFail(null, true); return null;
    }
    if (previous && status.catalogGeneration < previous.catalogGeneration) { this.catalogFail(null, true); return null; }
    const identity = status.operationId === null ? null : { catalogGeneration: status.catalogGeneration, operationId: status.operationId };
    const ours = attempt?.observer === observer;
    if (previous && status.catalogGeneration !== previous.catalogGeneration &&
        (!ours || attempt.selection !== null || status.catalogGeneration !== attempt.before + 1 || status.statusRevision <= attempt.after)) {
      this.catalogFail(null, true); return null;
    }
    if (previous && previous.catalogGeneration === status.catalogGeneration && previous.operationId !== status.operationId ||
        ours && attempt.identity && !sameAndroidCatalogIdentity(attempt.identity, identity)) {
      this.catalogFail(null, true); return null;
    }
    if (previous?.phase === 'unknown' && status.phase !== 'unknown' ||
        previous && previous.catalogGeneration === status.catalogGeneration && ['ready', 'refused', 'cancelled'].includes(previous.phase) &&
          androidCatalogActive(status)) { this.catalogFail(null, true); return null; }
    if (ours && !attempt.identity && identity && attempt.selection === null &&
        status.catalogGeneration === attempt.before + 1 && status.statusRevision > attempt.after) attempt.identity = identity;
    const acknowledged = !!ours && status.statusRevision > attempt.after &&
      (attempt.selection === null ? sameAndroidCatalogIdentity(attempt.identity, identity) && identity !== null :
        status.catalogGeneration === attempt.before && sameAndroidCatalogSelection(status.selected, attempt.selection));
    if (acknowledged) attempt.settled = !androidCatalogActive(status);
    if (previous && !sameAndroidCatalogSelection(previous.selected, status.selected)) this.retire(this.advance('contextGeneration'));
    observer.catalog = status;
    if (observer === this.observer) {
      this.update({ catalogStatus: status, catalogPending: acknowledged ? null : this.state.catalogPending,
        catalogUnconfirmed: acknowledged ? false : this.state.catalogUnconfirmed,
        nativeBlocked: this.state.nativeBlocked || status.phase === 'unknown' ||
          ['cleanup-unknown', 'document-lost', 'shutdown'].includes(status.availability) });
    }
    if (this.disposed && androidCatalogActive(status)) this.stopCatalog(observer);
    if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
    return status;
  }
  canCheckCatalogStatus(): boolean { return !this.disposed && !!this.observer?.active && !this.state.catalogReadPending; }
  async checkCatalogStatus(): Promise<void> {
    const observer = this.observer;
    if (this.disposed || !observer?.active) return;
    if (observer.catalogReading) return observer.catalogReading;
    const work = Promise.resolve().then(async () => {
      if (!observer.active) return;
      try {
        const status = this.receiveCatalog(observer, await observer.api.androidToolchainCatalogStatus());
        if (status && status.statusRevision >= (observer.catalog?.statusRevision ?? 0) && !this.state.integrityFailed)
          this.update({ catalogIssue: false, catalogError: null });
      } catch (error) { if (observer.active) this.catalogFail(error); }
    });
    observer.catalogReading = work; this.update({ catalogReadPending: true });
    try { await work; } finally {
      if (observer.catalogReading === work) { observer.catalogReading = null; if (this.observer === observer) this.update({ catalogReadPending: false }); }
    }
  }
  catalogActionReason = (): string | null => {
    if (this.disposed || this.state.mode !== 'native') return 'Open the native application to inspect protected Android tool copies.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return androidBuildOwnerReason(this.state);
    if (this.state.sourcesIssue || this.state.sourcesPending || this.state.sourcesUnconfirmed || androidToolSourcesActive(this.state.toolSources))
      return 'Settle or confirm the original Android tool picker before changing the protected copy.';
    const observer = this.observer, catalog = this.state.catalogStatus, op = this.state.status?.operation;
    if (!observer?.active || observer.generation !== this.state.connectionGeneration || !this.state.catalogListening || !catalog || this.state.catalogIssue)
      return 'Check the original tool catalog and its subscription before changing the selection.';
    if (this.state.catalogPending || this.state.catalogUnconfirmed || androidCatalogActive(catalog))
      return 'Wait for the original catalog read or cancel it; a lost reply is not cleanup.';
    if (this.state.pending || this.state.originalUnconfirmed || op && !['awaiting-consent', 'terminal'].includes(op.phase))
      return 'Settle the original build before changing tools.';
    if (catalog.availability !== 'available') return androidBuildAvailabilityText[catalog.availability];
    return this.context.otherOperationReason();
  };
  async refreshCatalog(): Promise<void> {
    if (this.catalogActionReason() || !this.observer?.catalog) return;
    const observer = this.observer, previous = observer.catalog!;
    if (previous.catalogGeneration >= ANDROID_BUILD_COUNTER_MAX - 1) { this.retire({ generationLost: true }); return; }
    this.retire(this.advance('contextGeneration'));
    const attempt = { observer, before: previous.catalogGeneration, after: previous.statusRevision,
      identity: null as AndroidCatalogIdentity | null, selection: null, settled: false };
    this.catalogAttempt = attempt; this.catalogCancelClaim = null;
    this.update({ catalogPending: 'refresh', catalogUnconfirmed: true, catalogCancelClaimed: null, catalogError: null });
    try {
      const value = await observer.api.refreshAndroidToolchainCatalog();
      if (!observer.active || this.catalogAttempt !== attempt) return;
      const status = parseAndroidToolchainCatalogStatus(value);
      if (!status || status.catalogGeneration !== attempt.before + 1 || !status.operationId || status.statusRevision <= attempt.after) {
        this.catalogFail(null, true); return;
      }
      this.receiveCatalog(observer, status);
    } catch (error) { if (observer.active && this.catalogAttempt === attempt && !attempt.settled) this.catalogFail(error); }
  }
  async selectToolchain(instance: string, recordSha256: string): Promise<void> {
    if (this.catalogActionReason() || !this.observer?.catalog) return;
    const observer = this.observer, previous = observer.catalog!;
    const selected = previous.entries.find((entry) => entry.selection.instance === instance && entry.selection.recordSha256 === recordSha256)?.selection;
    if (previous.phase !== 'ready' || !selected) return;
    this.retire(this.advance('contextGeneration'));
    const attempt = { observer, before: previous.catalogGeneration, after: previous.statusRevision,
      identity: previous.operationId ? { catalogGeneration: previous.catalogGeneration, operationId: previous.operationId } : null,
      selection: selected, settled: false };
    this.catalogAttempt = attempt;
    this.update({ catalogPending: 'select', catalogUnconfirmed: true, catalogError: null });
    try {
      const value = await observer.api.selectAndroidToolchain({ schemaVersion: 1, catalogGeneration: previous.catalogGeneration, instance, recordSha256 });
      if (!observer.active || this.catalogAttempt !== attempt) return;
      const status = parseAndroidToolchainCatalogStatus(value);
      if (!status || status.statusRevision <= attempt.after || status.catalogGeneration !== attempt.before ||
          !sameAndroidCatalogSelection(status.selected, selected)) { this.catalogFail(null, true); return; }
      this.receiveCatalog(observer, status);
    } catch (error) { if (observer.active && this.catalogAttempt === attempt && !attempt.settled) this.catalogFail(error); }
  }
  canCancelCatalog(): boolean {
    const status = this.observer?.catalog;
    return !this.disposed && !!this.observer?.active && !!status?.operationId && androidCatalogActive(status) &&
      !sameAndroidCatalogIdentity(this.catalogCancelClaim, { catalogGeneration: status.catalogGeneration, operationId: status.operationId });
  }
  cancelCatalog(): boolean { return this.canCancelCatalog() && !!this.observer && this.stopCatalog(this.observer); }
  private stopCatalog(observer: Observer): boolean {
    const status = observer.catalog;
    if (!observer.active || !status?.operationId || !androidCatalogActive(status)) return false;
    const identity = { catalogGeneration: status.catalogGeneration, operationId: status.operationId };
    if (sameAndroidCatalogIdentity(this.catalogCancelClaim, identity)) return false;
    this.catalogCancelClaim = identity; this.update({ catalogCancelClaimed: identity });
    void (async () => {
      try {
        const value = await observer.api.cancelAndroidToolchainCatalog({ schemaVersion: 1, ...identity });
        if (!observer.active) return;
        const status = parseAndroidToolchainCatalogStatus(value);
        if (!status || !sameAndroidCatalogIdentity(identity, status.operationId === null ? null :
            { catalogGeneration: status.catalogGeneration, operationId: status.operationId })) { this.catalogFail(null, true); return; }
        this.receiveCatalog(observer, status);
      } catch (error) { if (observer.active) this.catalogFail(error); }
    })();
    return true;
  }
  private commonReason(): string | null {
    if (this.disposed || this.state.mode !== 'native') return 'Open the native application. Browser preview cannot prepare or run an Android build.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return androidBuildOwnerReason(this.state);
    if (!this.observer?.active || this.observer.generation !== this.state.connectionGeneration || !this.state.listening || !this.state.initialized || !this.state.status || this.state.observationIssue)
      return 'A current original native Status and subscription are required. Passive diagnostics cannot qualify Android execution.';
    if (this.state.status.statusRevision >= ANDROID_BUILD_COUNTER_MAX) return 'The original status counter is exhausted. No counter or consent can be reused.';
    if (!['available', 'busy'].includes(this.state.status.availability)) return androidBuildAvailabilityText[this.state.status.availability];
    if (this.state.sourcesIssue || this.state.sourcesPending || this.state.sourcesUnconfirmed || androidToolSourcesActive(this.state.toolSources))
      return 'Settle or confirm the original Android tool picker before reviewing a build.';
    if (this.state.catalogIssue || this.state.catalogUnconfirmed || this.state.catalogPending || androidCatalogActive(this.state.catalogStatus))
      return 'Settle or confirm the original Android tool selection before reviewing this build.';
    if (!this.state.catalogListening || !this.state.catalogStatus) return 'Check the original Android tool catalog status first.';
    if (this.state.catalogStatus.availability !== 'unsupported-platform' && this.state.catalogStatus.selected === null)
      return 'Choose a registered protected Android tool copy before reviewing saved inputs.';
    if (!this.state.visible) return 'Open Releases to review this saved Android build and its project-code disclosure.';
    if (this.state.selectionPending) return 'Finish original project selection before reviewing this build.';
    const project = this.state.project;
    if (!project) return 'Choose a registered source project first; an evidence folder is not an execution target.';
    if (project.saveRecoveryRequired) return 'Finish original configuration-save recovery before reviewing a build.';
    if (project.snapshotPending) return 'Wait for the current saved-configuration refresh to settle.';
    if (project.versionPending) return 'Wait for the original saved-version read to settle; an earlier result cannot stand in.';
    return project.inputIssue ?? (this.artifactValidation() === null ?
      'Save android.uploadCertificateSha256, then refresh the saved configuration and version before reviewing upload-signature inspection.' : null) ?? this.context.otherOperationReason();
  }
  prepareReason = (): string | null => this.commonReason() ?? androidBuildOwnerReason(this.state) ??
    (this.state.status?.availability === 'busy' ? androidBuildAvailabilityText.busy : null);
  startReason = (): string | null => {
    const common = this.commonReason(); if (common) return common;
    const consent = this.state.consent, attempt = this.attempt, op = this.state.status?.operation;
    if (!consent || !attempt || !attempt.prepareReply || attempt.startSent || !this.matches(attempt) || !sameAndroidBuildIdentity(consent, op ?? null) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable) return 'Review a new saved-input build intent. Status or an earlier acknowledgement cannot authorize Start.';
    const now = this.now();
    if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) return 'This original five-minute review expired. Checking Status does not extend it.';
    return consent.acknowledged ? null : 'Acknowledge the exact saved inputs, project-code effects and inspection limits before Start.';
  };
  private expireConsent(): void {
    const consent = this.state.consent; if (!consent) return;
    const now = this.now(); if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) this.retire();
  }
  private armExpiry(): void {
    this.clearTimer(); const consent = this.state.consent; if (!consent) return;
    const remaining = consent.deadline - this.now();
    if (!Number.isFinite(remaining) || remaining <= 0) { this.retire(); return; }
    this.timer = setTimeout(() => { this.timer = null; this.expireConsent(); if (this.state.consent) this.armExpiry(); }, Math.min(remaining, ANDROID_BUILD_CONSENT_MS));
  }
  async prepare(): Promise<void> {
    this.syncProject();
    const project = this.state.project;
    if (this.prepareReason() || !this.observer || !project?.savedConfig || !project.savedVersion || !project.selection || !project.versionObservation) return;
    const request = copyAndroidBuildRequest('prepare_android_build', { projectId: project.projectId, draftRevision: project.draftRevision,
      baselineGeneration: project.baselineGeneration, savedConfig: project.savedConfig, savedVersion: project.savedVersion,
      artifactValidation: this.artifactValidation() }) as PrepareAndroidBuild | null;
    const now = this.now();
    if (!request || !Number.isFinite(now) || now < 0 || !Number.isFinite(now + ANDROID_BUILD_CONSENT_MS)) { this.fail({ code: 'android_build_invalid' }, true); return; }
    const counters = this.advance('requestGeneration'); if (counters.generationLost) { this.retire(counters); return; }
    const observer = this.observer;
    const binding: AndroidBuildBinding = freeze({ context: { ...request, platform: 'android', operation: 'android-build-inspect' }, selection: project.selection,
      toolchainSelection: this.state.catalogStatus?.selected ?? null,
      observationGeneration: project.observationGeneration, versionObservation: project.versionObservation, connectionGeneration: this.state.connectionGeneration,
      selectionGeneration: this.state.selectionGeneration, contextGeneration: this.state.contextGeneration, requestGeneration: counters.requestGeneration! });
    const attempt: Attempt = { observer, binding, previous: observer.status?.operation ? id(observer.status.operation) : null,
      after: observer.status?.statusRevision ?? 0, identity: null, prepareSent: false, prepareReply: false, deadline: now + ANDROID_BUILD_CONSENT_MS,
      startSent: false, startAfter: 0, retired: false, settled: false };
    this.attempt = attempt; this.cancelClaim = null;
    this.update({ ...counters, consent: null, pending: 'prepare', originalUnconfirmed: false, historical: true, cancelClaimed: null, error: null });
    this.syncProject(); // Synchronous subscribers can replace either observation.
    if (!this.matches(attempt) || this.commonReason()) { attempt.retired = true; attempt.settled = true; this.update({ pending: null }); return; }
    attempt.prepareSent = true; this.update({ originalUnconfirmed: true }); this.syncProject();
    if (!this.matches(attempt) || this.commonReason()) {
      attempt.prepareSent = false; attempt.retired = true; attempt.settled = true; this.update({ pending: null, originalUnconfirmed: false }); return;
    }
    try {
      const value = await observer.api.prepareAndroidBuild(request);
      if (!observer.active || this.attempt !== attempt) return;
      this.syncProject();
      const status = parseAndroidBuildStatus(value), op = status?.operation;
      if (!status || !op || !this.originCandidate(attempt, status) || ['starting', 'running'].includes(op.phase) || op.outcome === 'complete') {
        this.fail({ code: 'android_build_protocol' }, true); return;
      }
      attempt.identity = id(op); attempt.prepareReply = true;
      if (!this.receive(observer, status)) return;
      this.reconcile(observer); this.update({ pending: null, originalUnconfirmed: false });
      const current = observer.status?.operation;
      if (this.matches(attempt) && !this.commonReason() && current?.phase === 'awaiting-consent' && current.intentUsable &&
          sameAndroidBuildIdentity(current, attempt.identity) && this.now() < attempt.deadline) {
        this.update({ consent: { ...id(op), binding, acknowledged: false, deadline: attempt.deadline } }); this.armExpiry();
      } else { attempt.retired = true; this.stopOriginal(); }
    } catch (error) {
      if (observer.active && this.attempt === attempt) {
        const safe = androidBuildError(error);
        if (['android_build_invalid', 'android_build_unavailable', 'android_build_busy'].includes(safe.code) &&
            !attempt.identity && (!observer.status || !this.originCandidate(attempt, observer.status))) {
          attempt.retired = true; attempt.settled = true; this.update({ pending: null, originalUnconfirmed: false, consent: null, error: safe });
        } else this.fail(error, safe.code !== 'android_build_protocol');
      }
    }
  }
  setAcknowledged(operationId: string, ownerGeneration: string, acknowledged: boolean): void {
    this.syncProject(); this.expireConsent();
    const consent = this.state.consent, attempt = this.attempt;
    if (!consent || !attempt || !this.matches(attempt) || this.commonReason() || !sameAndroidBuildIdentity(consent, { operationId, ownerGeneration }) || typeof acknowledged !== 'boolean') return;
    this.update({ consent: { ...consent, acknowledged } });
  }
  async start(operationId: string, ownerGeneration: string): Promise<void> {
    this.syncProject(); this.expireConsent();
    const attempt = this.attempt, consent = this.state.consent;
    if (!attempt || !consent || !sameAndroidBuildIdentity(consent, { operationId, ownerGeneration }) || this.startReason()) return;
    attempt.startSent = true; attempt.startAfter = attempt.observer.status?.statusRevision ?? 0; this.clearTimer();
    this.update({ consent: null, pending: 'start', originalUnconfirmed: true, historical: false, error: null }); this.syncProject();
    if (!this.matches(attempt) || this.commonReason()) { this.retire(); return; }
    try {
      const value = await attempt.observer.api.startAndroidBuild({ operationId, ownerGeneration, consentVersion: ANDROID_BUILD_CONSENT });
      if (!attempt.observer.active || this.attempt !== attempt) return;
      const status = parseAndroidBuildStatus(value);
      if (!status?.operation || !sameAndroidBuildIdentity(status.operation, attempt.identity) || status.operation.phase === 'awaiting-consent') {
        this.fail({ code: 'android_build_protocol' }, true); return;
      }
      this.receive(attempt.observer, status);
    } catch (error) { if (attempt.observer.active && this.attempt === attempt && !attempt.settled) this.fail(error); }
  }
  canCancel(): boolean {
    const observer = this.observer, op = observer?.status?.operation;
    return !this.disposed && !!observer?.active && !!op && op.phase !== 'terminal' && !sameAndroidBuildIdentity(this.state.cancelClaimed, op);
  }
  cancel(): boolean {
    if (!this.canCancel() || !this.observer?.status?.operation) return false;
    const observer = this.observer, op = observer.status!.operation!; this.retire({}, false);
    const attempt = this.attempt;
    if (attempt?.observer === observer && !attempt.identity && this.originCandidate(attempt, observer.status!)) attempt.identity = id(op);
    return this.stop(observer, id(op)); // Cancel observed original ownership, never adopt its consent.
  }
  private stopOriginal(): void {
    const attempt = this.attempt;
    if (attempt?.identity && !attempt.settled && attempt.observer.active) this.stop(attempt.observer, attempt.identity);
  }
  private stop(observer: Observer, identity: AndroidBuildIdentity): boolean {
    if (!observer.active || sameAndroidBuildIdentity(this.cancelClaim, identity)) return false;
    this.cancelClaim = id(identity); this.update({ cancelClaimed: id(identity), consent: null });
    void (async () => {
      try {
        const value = await observer.api.cancelAndroidBuild(identity.operationId, identity.ownerGeneration);
        if (!observer.active) return;
        const status = parseAndroidBuildStatus(value);
        if (!status?.operation || !sameAndroidBuildIdentity(status.operation, identity)) { this.fail({ code: 'android_build_protocol' }, true); return; }
        this.receive(observer, status);
      } catch (error) { if (observer.active) this.fail(error); }
    })();
    return true;
  }
  dispose(): void {
    if (this.disposed) return;
    this.retire(); if (this.observer) { this.stopCatalog(this.observer); this.stopSources(this.observer); }
    this.disposed = true; this.listeners.clear();
    if (this.observer && !this.needsOriginal(this.observer)) this.detach(this.observer);
    // Sent work retains a retirement-only original observer until actual native
    // terminal settlement. Page navigation must call setVisible, not dispose.
  }
}

export const androidToolchainCatalogHelp: HelpContent = {
  label: 'Protected Android tools on this Mac', requiredness: 'conditional',
  requiredWhen: 'Select a compatible registered tool copy before reviewing a Mac Android build.',
  what: 'Lists protected copies of Java 17, Gradle, Android SDK tools and bundletool for your macOS account. Listing is not full qualification.',
  why: 'The build must use the exact tool copy you chose, not a changing PATH, another account’s files or whichever version looks newest.',
  where: 'Use Refresh tool list for protected copies, or Browse in Set up Android tools to choose source folders. Browsing does not inspect supplier contents or register a protected copy.',
  format: 'Choose one named copy after checking its version labels. The application retains its catalog generation and byte comparisons; you never enter a UID, hash, path or command.',
  failure: 'Changed, incompatible or unsafe copies are refused. Full runtime and tool admission runs again at Build. A failed or interrupted read keeps original Status and Cancel; no tools are silently installed or licenses accepted.',
};

export const androidBuildHelp: HelpContent = {
  label: 'Build saved Android app and inspect AAB', requiredness: 'optional', requiredWhen: 'Use only for an explicitly reviewed local Android build; it is separate from candidate evidence and Store release.',
  what: 'Uses a compatible user-installed JDK and Android SDK with the selected protected Gradle and pinned bundletool to build the saved app and inspect its required post-run AAB. It installs no tools and accepts no licenses.',
  why: 'Observe a known task outcome and bounded local AAB findings without mistaking completion for freshness, signing or release readiness.',
  where: 'Save android.enabled, android.applicationId, explicit android.module and optional android.variant in release/mobile-release.json. Use Environment Requirements for setup guidance; fix app or Gradle code in Android Studio or your editor.',
  format: 'The initial Linux GNU x86_64 profile still requires separate native qualification. Tools diagnostics observe only Git, Java and Javac: they do not inspect the SDK, establish Gradle readiness or authorize a build.',
  failure: 'Missing, unselected, unsupported, not inspected and unqualified are different states. A closed native gate does not mean your SDK is missing. Known nonzero exit is command failure; check private Build Output and wait for original cleanup before new consent.',
};
export const androidBuildInputHelp: HelpContent = {
  label: 'Saved Android build inputs', requiredness: 'required', requiredWhen: 'Before each new build review, and after any save, refresh, version read or selection change.',
  what: 'Pairs the current completed saved configuration snapshot with the complete release-version observe-v2 response, including both byte counts/hashes, source, name, build and observation generations.',
  why: 'An older editor baseline, matching name/build alone or a previous observation cannot identify the saved files that were reviewed.',
  where: 'Refresh the saved configuration, then explicitly read the version file selected by its saved version.source. No arbitrary path is accepted here.',
  format: 'Unsaved drafts are neither saved nor discarded. They are not execution inputs, even when they differ from the latest saved snapshot.',
  failure: 'Pending, stale, failed or mismatched observations retire consent. Refresh and read again after original ownership settles. External changes remain possible; these inputs are not an atomic checkout.',
};
export const androidBuildOutputHelp: HelpContent = {
  label: 'Local AAB observation limits', requiredness: 'conditional', requiredWhen: 'Whenever interpreting a completed build or retained output disposition.',
  what: 'Displays redacted local bytes, digest, ABI observations and exact core finding statuses only after native terminal completion.',
  why: 'An AAB may be incremental, reused or stale despite exit zero. A digest identifies observed bytes, not current source or current-file custody.',
  where: 'Use the original operation Status for disposition. Compiler details remain in private Build Output in Android Studio or your editor.',
  format: 'Signer is not inspected by default. Optional upload-signature inspection checks integrity and the saved upload certificate separately; toolkit signing/Store work are not requested and source binding/freshness/readiness remain unestablished.',
  failure: 'Complete may contain FAIL findings. No open-file link, upload, publication, substitute scan, automatic rerun or blanket cleanup is authorized by this result.',
};
export const androidBuildSignatureHelp: HelpContent = {
  label: 'Verify the saved upload certificate', requiredness: 'optional', requiredWhen: 'Choose before reviewing saved inputs when this project already produces a signed AAB.',
  what: 'Verifies signed content and compares the same captured AAB’s leaf signer with saved android.uploadCertificateSha256. This does not sign or upload the file.',
  why: 'A successful build may still produce an unsigned, tampered or wrong-signer AAB. Signature integrity and saved-certificate match are separate findings.',
  where: 'Find the SHA-256 under Upload key certificate in Play Console → App integrity, or inspect the public upload certificate. Do not use the separate App signing key certificate.',
  format: 'Save the upload-certificate SHA-256 as 64 hexadecimal characters without colons in release/mobile-release.json, then refresh configuration and read the saved version. No private key, password or keystore is needed here.',
  failure: 'Missing or changed saved values refuse the run. A rejected signature skips signer comparison; a match does not prove Play enrollment, fresh source outputs or release readiness.',
};
export const androidBuildCancelHelp: HelpContent = {
  label: 'Cancel original Android build', requiredness: 'optional', requiredWhen: 'To stop further original work, including from another page while a build is active.',
  what: 'Requests STOP for the original operation identity, then keeps its Status and cancellation observation available until native settlement.',
  why: 'Clicking Cancel, losing a reply, closing a view or reaching a deadline does not establish cleanup.',
  where: 'Use original Status and Cancel in the global operation notice. A replacement document cannot adopt or reset the original owner.',
  format: 'Cancellation is not rollback: project writes, network effects or signed files may already exist. Known retained work is a failed disposition, not a clean cancellation.',
  failure: 'Unknown cleanup is sticky and blocks conflicting work. Do not delete shared caches, stop global daemons or repeat Start to recover.',
};
