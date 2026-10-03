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
import { ANDROID_TOOL_REGISTRATION_CONSENT, androidToolRegistrationActive, androidToolRegistrationError,
  androidToolRegistrationPrerequisiteText, hasAndroidToolRegistration, parseAndroidToolRegistrationStatus,
  sameAndroidToolRegistrationIdentity } from './androidToolRegistration.ts';
import type { AndroidToolRegistrationIdentity, AndroidToolRegistrationKind, AndroidToolRegistrationStatus,
  InspectAndroidToolSources, RegisterAndroidToolSources } from './androidToolRegistration.ts';
import type { AndroidMacToolchainSelection } from './androidBuildTypes.ts';
import type { AndroidCatalogComparison, AndroidCatalogIdentity, AndroidToolchainCatalogStatus } from './androidToolchainCatalogTypes.ts';
import { androidCatalogActive, androidCatalogComparison, androidCatalogError, parseAndroidToolchainCatalogStatus, sameAndroidCatalogIdentity, sameAndroidCatalogSelection } from './androidToolchainCatalogProtocol.ts';
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
interface AndroidToolRegistrationBinding {
  context: PrepareAndroidBuild; sourceGeneration: number; connectionGeneration: number; selectionGeneration: number;
  contextGeneration: number; requestGeneration: number; observationGeneration: number; versionObservation: VersionObservationBinding;
}
export interface AndroidToolRegistrationConsent extends AndroidToolRegistrationIdentity {
  reviewId: string; binding: AndroidToolRegistrationBinding; acknowledged: boolean; deadline: number;
}
export interface AndroidBuildState {
  mode: BridgeMode; project: AndroidBuildProject | null; visible: boolean; selectionPending: boolean; verifyUploadSignature: boolean;
  catalogStatus: AndroidToolchainCatalogStatus | null; catalogListening: boolean; catalogReadPending: boolean;
  catalogPending: 'refresh' | 'recover' | 'select' | null; catalogUnconfirmed: boolean; catalogCancelClaimed: AndroidCatalogIdentity | null; catalogCancelPending: boolean;
  catalogError: ApiError | null; catalogIssue: boolean;
  toolSources: AndroidToolSourcesStatus | null; sourcesListening: boolean; sourcesReadPending: boolean;
  sourcesPending: boolean; sourcesUnconfirmed: boolean; sourcesIssue: boolean; sourcesError: ApiError | null;
  sourcesCancelClaimed: AndroidToolSourceIdentity | null;
  toolRegistration: AndroidToolRegistrationStatus | null; registrationListening: boolean; registrationReadPending: boolean;
  registrationPending: 'inspect' | 'register' | null; registrationUnconfirmed: boolean; registrationIssue: boolean;
  registrationError: ApiError | null; registrationCancelClaimed: AndroidToolRegistrationIdentity | null; registrationCancelPending: boolean;
  registrationConsent: AndroidToolRegistrationConsent | null;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
  listening: boolean; initialized: boolean; readPending: boolean; status: AndroidBuildStatus | null;
  consent: AndroidBuildConsent | null; pending: 'prepare' | 'start' | null; originalUnconfirmed: boolean;
  historical: boolean; cancelClaimed: AndroidBuildIdentity | null; error: ApiError | null;
  observationIssue: 'bridge' | 'protocol' | null; nativeBlocked: boolean; integrityFailed: boolean; generationLost: boolean;
}
type Port = AndroidBuildApi & { mode: BridgeMode };
interface Observer { api: Port; active: boolean; generation: number; unlisten: (() => void) | null; reading: Promise<void> | null; status: AndroidBuildStatus | null;
  catalogUnlisten: (() => void) | null; catalogReading: Promise<void> | null; catalog: AndroidToolchainCatalogStatus | null; catalogCancelPending: boolean; catalogCancelConfirmed: boolean; catalogUnconfirmed: boolean; catalogLost: boolean;
  sourcesUnlisten: (() => void) | null; sourcesReading: Promise<void> | null; sources: AndroidToolSourcesStatus | null;
  registrationUnlisten: (() => void) | null; registrationReading: Promise<void> | null; registration: AndroidToolRegistrationStatus | null;
  registrationLost: boolean; registrationStops: { identity: AndroidToolRegistrationIdentity; pending: boolean }[] }
interface Attempt {
  observer: Observer; binding: AndroidBuildBinding; previous: AndroidBuildIdentity | null; after: number;
  identity: AndroidBuildIdentity | null; prepareSent: boolean; prepareReply: boolean; deadline: number;
  startSent: boolean; startAfter: number; retired: boolean; settled: boolean;
}
interface CatalogAttempt {
  observer: Observer; before: number; after: number; identity: AndroidCatalogIdentity | null;
  selection: AndroidMacToolchainSelection | null; comparison: AndroidCatalogComparison | null;
  kind: 'refresh' | 'recover' | 'select'; settled: boolean; replySettled: boolean; replyConfirmed: boolean; notAdmitted: boolean;
}
interface RegistrationAttempt {
  observer: Observer; before: number; after: number; binding: AndroidToolRegistrationBinding; kind: AndroidToolRegistrationKind;
  identity: AndroidToolRegistrationIdentity | null; retired: boolean; settled: boolean; sent: boolean;
  replySettled: boolean; notAdmitted: boolean; requestedAt: number; reviewDeadline: number;
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
  if (state.registrationUnconfirmed || state.registrationPending || state.registrationCancelPending || state.registrationIssue || androidToolRegistrationActive(state.toolRegistration))
    return 'The original Android source inspection or protected registration is active or unconfirmed. Keep its Status and Cancel; do not repeat copy.';
  if (state.toolRegistration?.review) return 'An original source review is retained. Register that exact review or explicitly discard it before conflicting work.';
  if (state.sourcesUnconfirmed || state.sourcesPending || state.sourcesIssue || androidToolSourcesActive(state.toolSources)) return 'The original Android tool picker or folder check is active or unconfirmed. Keep tool-selection Status and Cancel before conflicting work.';
  if (state.catalogUnconfirmed || state.catalogPending || state.catalogCancelPending || state.catalogIssue || androidCatalogActive(state.catalogStatus)) return 'The original Android tool catalog is still reading, stopping or unconfirmed. Keep catalog Status and Cancel before conflicting work.';
  if (state.originalUnconfirmed || state.pending || active(state.status?.operation)) return 'The Android build holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.';
  if (state.mode === 'native' && state.observationIssue) return 'The original Android-build status is unverified. Check retained Status before conflicting work.';
  return null;
}

export class AndroidBuildController {
  private state: AndroidBuildState = freeze<AndroidBuildState>({ mode: 'unavailable', project: null, visible: false, selectionPending: false, verifyUploadSignature: false,
    connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0, requestGeneration: 0, listening: false, initialized: false, readPending: false,
    status: null, consent: null, pending: null, originalUnconfirmed: false, historical: false, cancelClaimed: null, error: null,
    catalogStatus: null, catalogListening: false, catalogReadPending: false, catalogPending: null, catalogUnconfirmed: false,
    catalogCancelClaimed: null, catalogCancelPending: false, catalogError: null, catalogIssue: false,
    toolSources: null, sourcesListening: false, sourcesReadPending: false, sourcesPending: false,
    sourcesUnconfirmed: false, sourcesIssue: false, sourcesError: null, sourcesCancelClaimed: null,
    toolRegistration: null, registrationListening: false, registrationReadPending: false, registrationPending: null,
    registrationUnconfirmed: false, registrationIssue: false, registrationError: null, registrationCancelClaimed: null, registrationCancelPending: false, registrationConsent: null,
    observationIssue: null, nativeBlocked: false, integrityFailed: false, generationLost: false });
  private readonly context: Context;
  private observer: Observer | null = null;
  private attempt: Attempt | null = null;
  private cancelClaim: AndroidBuildIdentity | null = null;
  private catalogAttempt: CatalogAttempt | null = null;
  private catalogCancelClaim: AndroidCatalogIdentity | null = null;
  private sourcesAttempt: { observer: Observer; before: number; after: number; role: AndroidToolSourceRole; projectId: string; retired: boolean;
    identity: AndroidToolSourceIdentity | null; settled: boolean } | null = null;
  private sourcesCancelClaim: AndroidToolSourceIdentity | null = null;
  private registrationAttempt: RegistrationAttempt | null = null;

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
    if (this.registrationAttempt) this.registrationAttempt.retired = true;
    this.update({ ...patch, consent: null, registrationConsent: null, historical: !!this.state.status?.operation || this.state.historical });
    if (stop) { this.stopOriginal(); if (this.observer) this.stopRegistration(this.observer); }
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
    if (relevant.includes(action.type) && (action.projectId === this.state.project?.projectId || action.projectId === this.attempt?.binding.context.projectId
        || action.projectId === this.registrationAttempt?.binding.context.projectId))
      this.retire(this.advance('contextGeneration'));
  }
  selectionIntent(): void { if (!this.disposed) { this.retire(this.advance('selectionGeneration')); if (this.observer) this.stopSources(this.observer); } }
  snapshotIntent(projectId: string): void {
    if (!this.disposed && (projectId === this.state.project?.projectId || projectId === this.attempt?.binding.context.projectId
        || projectId === this.registrationAttempt?.binding.context.projectId))
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
    if (!visible && (this.attempt && !this.attempt.startSent && !this.attempt.settled
        || this.registrationAttempt?.kind === 'inspection' && (this.registrationHeld() || !this.registrationAttempt.settled)
        || !!this.state.toolRegistration?.review))
      this.retire({ ...this.advance('contextGeneration'), visible });
    else this.update({ visible }); // Started build/copy originals stay app-owned across pages.
  }
  private needsOriginal(observer: Observer): boolean {
    return this.attempt?.observer === observer && this.attempt.prepareSent && !this.attempt.settled || active(observer.status?.operation)
      || this.catalogAttempt?.observer === observer && (!this.catalogAttempt.settled || !this.catalogAttempt.replySettled) || androidCatalogActive(observer.catalog)
      || observer.catalogCancelPending
      || observer.catalogUnconfirmed || observer.catalogLost
      || this.sourcesAttempt?.observer === observer && !this.sourcesAttempt.settled || androidToolSourcesActive(observer.sources)
      || this.registrationAttempt?.observer === observer && this.registrationAttempt.sent
        && (!this.registrationAttempt.replySettled || !this.registrationAttempt.settled)
      || this.registrationHeld(observer.registration) || observer.registrationLost || observer.registrationStops.some((claim) => claim.pending)
      || this.observer === observer && this.state.registrationUnconfirmed;
  }
  private detach(observer: Observer): void {
    observer.active = false;
    try { observer.unlisten?.(); } catch { /* Listener release is not native settlement. */ }
    observer.unlisten = null;
    try { observer.catalogUnlisten?.(); } catch { /* Not native settlement. */ }
    observer.catalogUnlisten = null;
    try { observer.sourcesUnlisten?.(); } catch { /* Listener release is not native settlement. */ }
    observer.sourcesUnlisten = null;
    try { observer.registrationUnlisten?.(); } catch { /* Not native settlement. */ }
    observer.registrationUnlisten = null;
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.retire(this.advance('connectionGeneration'));
    const observer = this.observer;
    if (observer) { this.stopCatalog(observer); this.stopSources(observer); this.stopRegistration(observer); }
    if (observer && (this.needsOriginal(observer) || this.state.nativeBlocked || this.state.integrityFailed)) {
      this.update({ nativeBlocked: true, historical: true }); return; // Never adopt a replacement document/API.
    }
    if (observer) this.detach(observer);
    this.observer = null;
    this.catalogAttempt = null; this.catalogCancelClaim = null; this.sourcesAttempt = null; this.sourcesCancelClaim = null;
    this.registrationAttempt = null;
    this.update({ mode: 'unavailable', listening: false, initialized: false, readPending: false,
      catalogStatus: null, catalogListening: false, catalogReadPending: false, catalogPending: null, catalogUnconfirmed: false, catalogCancelPending: false, catalogIssue: false,
      toolSources: null, sourcesListening: false, sourcesReadPending: false, sourcesPending: false, sourcesUnconfirmed: false, sourcesIssue: false, sourcesError: null,
      toolRegistration: null, registrationListening: false, registrationReadPending: false, registrationPending: null, registrationUnconfirmed: false,
      registrationIssue: false, registrationError: null, registrationCancelClaimed: null, registrationCancelPending: false, registrationConsent: null });
  }
  async connect(api: Port): Promise<void> {
    if (this.disposed || this.observer?.api === api) return;
    if (this.observer) this.beginConnection();
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost || this.observer) return;
    this.update({ mode: api.mode, observationIssue: null, error: null });
    if (api.mode !== 'native') return;
    const observer: Observer = { api, active: true, generation: this.state.connectionGeneration, unlisten: null, reading: null, status: null,
      catalogUnlisten: null, catalogReading: null, catalog: null, catalogCancelPending: false, catalogCancelConfirmed: false, catalogUnconfirmed: false, catalogLost: false, sourcesUnlisten: null, sourcesReading: null, sources: null,
      registrationUnlisten: null, registrationReading: null, registration: null, registrationLost: false, registrationStops: [] };
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
      if (hasAndroidToolRegistration(api)) {
        const registrationUnlisten = await api.subscribeAndroidToolRegistration!((value) => { if (observer.active) this.receiveRegistration(observer, value); });
        if (!observer.active || this.observer !== observer || this.disposed && !this.needsOriginal(observer)) { registrationUnlisten(); return; }
        observer.registrationUnlisten = registrationUnlisten; this.update({ registrationListening: true });
        await this.checkToolRegistration();
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
    const registration = this.registrationAttempt;
    if (registration?.observer === observer && !registration.retired && this.registrationHeld(observer.registration)
        && !this.registrationMatches(registration)) this.retire(this.advance('contextGeneration'));
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
    if (this.state.registrationPending || this.state.registrationUnconfirmed || this.state.registrationCancelPending || this.state.registrationIssue || this.registrationHeld())
      return 'Settle the original registration or explicitly discard its source review before choosing new folders.';
    if (this.state.catalogPending || this.state.catalogUnconfirmed || this.state.catalogCancelPending || this.state.catalogIssue || androidCatalogActive(this.state.catalogStatus)
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

  private registrationHeld(status = this.state.toolRegistration): boolean {
    return androidToolRegistrationActive(status) || !!status?.review;
  }
  private registrationBinding(context: PrepareAndroidBuild, sourceGeneration: number, requestGeneration: number): AndroidToolRegistrationBinding | null {
    const project = this.state.project;
    if (!project?.versionObservation) return null;
    return freeze({ context, sourceGeneration, connectionGeneration: this.state.connectionGeneration,
      selectionGeneration: this.state.selectionGeneration, contextGeneration: this.state.contextGeneration,
      requestGeneration, observationGeneration: project.observationGeneration, versionObservation: project.versionObservation });
  }
  private registrationMatches(attempt: RegistrationAttempt): boolean {
    const binding = attempt.binding, project = this.state.project, sources = this.state.toolSources;
    return !this.disposed && !attempt.retired && this.registrationAttempt === attempt
      && this.observer === attempt.observer && attempt.observer.active
      && binding.connectionGeneration === this.state.connectionGeneration && binding.selectionGeneration === this.state.selectionGeneration
      && binding.contextGeneration === this.state.contextGeneration && binding.requestGeneration === this.state.requestGeneration
      && !!project && project.inputIssue === null && project.savedConfig !== null && project.savedVersion !== null
      && !project.snapshotPending && !project.versionPending && !project.saveRecoveryRequired && !this.state.selectionPending
      && project.projectId === binding.context.projectId && project.draftRevision === binding.context.draftRevision
      && project.baselineGeneration === binding.context.baselineGeneration && project.observationGeneration === binding.observationGeneration
      && sameAndroidBuildData(project.versionObservation, binding.versionObservation)
      && sameAndroidBuildSavedPair(binding.context, { savedConfig: project.savedConfig, savedVersion: project.savedVersion })
      && sameAndroidBuildData(binding.context.artifactValidation, this.artifactValidation())
      && sources?.projectId === project.projectId && sources.sourceGeneration === binding.sourceGeneration
      && sources.selections.length === 3 && !androidToolSourcesActive(sources)
      && !this.state.sourcesIssue && !this.state.sourcesPending && !this.state.sourcesUnconfirmed;
  }
  private registrationCandidate(attempt: RegistrationAttempt, status: AndroidToolRegistrationStatus): boolean {
    const op = status.operation;
    return attempt.sent && !!op && status.registrationGeneration === attempt.before + 1 && status.statusRevision > attempt.after
      && op.kind === attempt.kind && op.sourceGeneration === attempt.binding.sourceGeneration
      && sameAndroidBuildData(op.context, attempt.binding.context)
      && (!attempt.identity || sameAndroidToolRegistrationIdentity(attempt.identity, op));
  }
  private registrationProgress(before: AndroidToolRegistrationStatus, after: AndroidToolRegistrationStatus): boolean {
    if (!sameAndroidBuildData(before.operation, after.operation)) return false;
    if (before.phase === 'unknown') return after.phase === 'unknown';
    if (['complete', 'refused', 'cancelled'].includes(before.phase)) {
      return after.phase === before.phase && after.reason === before.reason && sameAndroidBuildData(after.report, before.report)
        && after.review === null;
    }
    if (before.phase === 'review') {
      return after.phase === 'review' ? sameAndroidBuildData(before.review, after.review)
        : ['refused', 'cancelled', 'unknown'].includes(after.phase) && after.review === null;
    }
    if (before.phase === 'stopping') return ['stopping', 'refused', 'cancelled', 'unknown'].includes(after.phase);
    const working = before.operation?.kind === 'inspection' ? ['inspecting', 'settling', 'review']
      : ['copying', 'verifying', 'publishing', 'settling', 'complete'];
    return ['stopping', 'refused', 'cancelled', 'unknown'].includes(after.phase)
      || working.indexOf(after.phase) >= working.indexOf(before.phase);
  }
  private registrationFail(_error: unknown, protocol = false): void {
    // A Status/Cancel failure cannot deny the existence of an admitted original.
    this.retire({ registrationError: androidToolRegistrationError(null), registrationIssue: true,
      integrityFailed: this.state.integrityFailed || protocol, nativeBlocked: this.state.nativeBlocked || protocol });
  }
  private reconcileRegistrationConsent(observer: Observer): void {
    const status = observer.registration, attempt = this.registrationAttempt;
    if (!status?.review || !status.operation || status.phase !== 'review' || !attempt || attempt.observer !== observer
        || attempt.kind !== 'inspection' || !attempt.replySettled || !this.registrationCandidate(attempt, status)
        || !this.registrationMatches(attempt) || !this.state.visible || this.state.registrationIssue) {
      if (observer === this.observer && this.state.registrationConsent) this.update({ registrationConsent: null });
      return;
    }
    const now = this.now();
    // This renderer timeout starts BEFORE inspection admission, so it is only
    // conservative UI refusal. It cannot renew the native finalized-Review TTL.
    if (!Number.isFinite(now) || now < attempt.requestedAt || now >= attempt.reviewDeadline) {
      this.update({ registrationConsent: null }); this.stopRegistration(observer); return;
    }
    const existing = this.state.registrationConsent;
    if (existing && sameAndroidToolRegistrationIdentity(existing, status.operation) && existing.reviewId === status.review.reviewId) return;
    this.update({ registrationConsent: { operationId: status.operation.operationId,
      registrationGeneration: status.operation.registrationGeneration, reviewId: status.review.reviewId,
      binding: attempt.binding, acknowledged: false, deadline: attempt.reviewDeadline } });
    this.armRegistrationExpiry();
  }
  private rejectRegistrationObservation(observer: Observer, status: AndroidToolRegistrationStatus | null): void {
    observer.registrationLost = true;
    this.registrationFail(null, true);
    // A valid but contradictory identity may receive STOP once; it is never
    // adopted as Review, success, settlement or a replacement original.
    if (status?.operation && this.registrationHeld(status)) this.requestRegistrationStop(observer, status.operation);
  }
  private receiveRegistration(observer: Observer, value: unknown): AndroidToolRegistrationStatus | null {
    if (!observer.active) return null;
    const status = parseAndroidToolRegistrationStatus(value), before = observer.registration, attempt = this.registrationAttempt;
    if (!status) { this.rejectRegistrationObservation(observer, status); return null; }
    if (observer.registrationLost) {
      if (status.operation && this.registrationHeld(status)) this.requestRegistrationStop(observer, status.operation);
      return null; // Retained observer is now STOP-only, never a renewed Review/report.
    }
    if (before && status.statusRevision < before.statusRevision) return status;
    if (before && status.statusRevision === before.statusRevision && !sameAndroidBuildData(before, status)
        || before && status.registrationGeneration < before.registrationGeneration) { this.rejectRegistrationObservation(observer, status); return null; }
    const ours = attempt?.observer === observer, candidate = !!ours && this.registrationCandidate(attempt, status);
    if (before && status.registrationGeneration !== before.registrationGeneration && !candidate
        || before && status.registrationGeneration === before.registrationGeneration && before.operation !== null
          && !this.registrationProgress(before, status)
        || candidate && attempt.notAdmitted) { this.rejectRegistrationObservation(observer, status); return null; }
    if (ours && status.registrationGeneration === attempt.before + 1 && !candidate
        || ours && attempt.identity && !sameAndroidToolRegistrationIdentity(attempt.identity, status.operation)) {
      this.rejectRegistrationObservation(observer, status); return null;
    }
    if (candidate && !attempt.identity && status.operation) {
      attempt.identity = { operationId: status.operation.operationId, registrationGeneration: status.operation.registrationGeneration };
    }
    const acknowledged = !!candidate && !!attempt.identity && sameAndroidToolRegistrationIdentity(attempt.identity, status.operation);
    if (acknowledged) attempt.settled = !androidToolRegistrationActive(status);
    observer.registration = status;
    if (observer === this.observer) this.update({ toolRegistration: status,
      registrationPending: acknowledged && attempt.replySettled ? null : this.state.registrationPending,
      registrationUnconfirmed: acknowledged ? false : this.state.registrationUnconfirmed,
      nativeBlocked: this.state.nativeBlocked || status.phase === 'unknown'
        || ['cleanup-unknown', 'document-lost', 'shutdown'].includes(status.availability),
      generationLost: this.state.generationLost || status.statusRevision === ANDROID_BUILD_COUNTER_MAX });
    if (this.disposed || ours && attempt.retired) {
      if (this.registrationHeld(status)) this.stopRegistration(observer);
    } else this.reconcileRegistrationConsent(observer);
    if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
    return status;
  }
  canCheckToolRegistration(): boolean {
    return !this.disposed && !!this.observer?.active && hasAndroidToolRegistration(this.observer.api) && !this.state.registrationReadPending;
  }
  async checkToolRegistration(): Promise<void> {
    const observer = this.observer;
    if (this.disposed || !observer?.active || !hasAndroidToolRegistration(observer.api)) return;
    if (observer.registrationReading) return observer.registrationReading;
    const work = Promise.resolve().then(async () => {
      if (!observer.active) return;
      try {
        const status = this.receiveRegistration(observer, await observer.api.androidToolRegistrationStatus!());
        if (status && status.statusRevision >= (observer.registration?.statusRevision ?? 0) && !this.state.integrityFailed) {
          this.update({ registrationIssue: false, registrationError: null });
          this.reconcileRegistrationConsent(observer);
        }
      } catch (error) { if (observer.active) this.registrationFail(error); }
    });
    observer.registrationReading = work; this.update({ registrationReadPending: true });
    try { await work; } finally {
      if (observer.registrationReading === work) {
        observer.registrationReading = null;
        if (this.observer === observer) this.update({ registrationReadPending: false });
      }
    }
  }
  private registrationCommonReason(ignoreOwnPending = false): string | null {
    const observer = this.observer, status = this.state.toolRegistration, project = this.state.project, sources = this.state.toolSources;
    if (this.disposed || this.state.mode !== 'native' || !observer?.active || !hasAndroidToolRegistration(observer.api))
      return 'Protected registration is unavailable in this adapter. There is no browser, shell or unprivileged-copy fallback.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return androidBuildOwnerReason(this.state);
    if (observer.generation !== this.state.connectionGeneration || !this.state.registrationListening || !status || this.state.registrationIssue)
      return 'Check original registration Status and its subscription before inspecting or approving protected copy.';
    if (!this.state.listening || !this.state.initialized || !this.state.status || this.state.observationIssue
        || !this.state.catalogListening || !this.state.catalogStatus || !this.state.sourcesListening)
      return 'Observe the original build, catalog and selected-folder statuses before admitting source work.';
    if (this.state.registrationCancelPending || !ignoreOwnPending && (this.state.registrationPending || this.state.registrationUnconfirmed) || androidToolRegistrationActive(status))
      return 'Keep the original inspection or registration until its reply and native settlement are known. Do not repeat the action.';
    if (this.state.sourcesIssue || this.state.sourcesPending || this.state.sourcesUnconfirmed || androidToolSourcesActive(sources))
      return 'Settle the original folder picker and checks before inspecting those sources.';
    if (this.state.catalogIssue || this.state.catalogPending || this.state.catalogUnconfirmed || this.state.catalogCancelPending || androidCatalogActive(this.state.catalogStatus)
        || this.state.pending || this.state.originalUnconfirmed || active(this.state.status?.operation))
      return 'Finish or cancel the current catalog or prepared/active build before source inspection or registration.';
    if (status.prerequisite !== 'ready') return androidToolRegistrationPrerequisiteText[status.prerequisite];
    if (status.availability !== 'available') return androidBuildAvailabilityText[status.availability];
    if (!this.state.visible) return 'Open Releases to review the selected source contents and protected-copy consent.';
    if (!project || this.state.selectionPending) return 'Choose a registered source project first.';
    if (project.snapshotPending || project.versionPending || project.saveRecoveryRequired)
      return 'Finish the current saved-input read or save recovery before source inspection.';
    if (project.inputIssue) return project.inputIssue;
    if (!sources || sources.projectId !== project.projectId || sources.selections.length !== 3 || sources.sourceGeneration === 0)
      return 'Choose all three original JDK, SDK and Gradle folders for this project first.';
    if (this.artifactValidation() === null) return 'Refresh the saved configuration and version for the chosen inspection context.';
    return this.context.otherOperationReason();
  }
  inspectToolSourcesReason = (): string | null => this.registrationCommonReason() ??
    (this.state.toolRegistration?.review ? 'Register this exact review or discard it before inspecting new sources.' : null);
  registerToolSourcesReason = (): string | null => {
    const common = this.registrationCommonReason(); if (common) return common;
    const consent = this.state.registrationConsent, attempt = this.registrationAttempt, status = this.state.toolRegistration;
    if (!consent || !attempt || !this.registrationMatches(attempt) || !status?.operation || !status.review
        || !sameAndroidToolRegistrationIdentity(consent, status.operation) || consent.reviewId !== status.review.reviewId)
      return 'A current finalized inspection from this original action is required. Status alone cannot adopt an older source review.';
    const now = this.now();
    if (!Number.isFinite(now) || now < attempt.requestedAt || now >= consent.deadline) return 'This local review expired. It is never renewed by Status.';
    return consent.acknowledged ? null : 'Explicitly acknowledge the vendor licenses and approve this exact protected copy.';
  };
  private currentRegistrationContext(): PrepareAndroidBuild | null {
    const project = this.state.project;
    if (!project?.savedConfig || !project.savedVersion) return null;
    return copyAndroidBuildRequest('prepare_android_build', { projectId: project.projectId, draftRevision: project.draftRevision,
      baselineGeneration: project.baselineGeneration, savedConfig: project.savedConfig, savedVersion: project.savedVersion,
      artifactValidation: this.artifactValidation() }) as PrepareAndroidBuild | null;
  }
  private armRegistrationExpiry(): void {
    this.clearTimer();
    const consent = this.state.registrationConsent, attempt = this.registrationAttempt;
    if (!consent || !attempt) return;
    const now = this.now(), remaining = consent.deadline - now;
    if (!Number.isFinite(now) || now < attempt.requestedAt || !Number.isFinite(remaining) || remaining <= 0) {
      this.update({ registrationConsent: null }); if (this.observer) this.stopRegistration(this.observer); return;
    }
    this.timer = setTimeout(() => { this.timer = null; this.armRegistrationExpiry(); }, Math.min(remaining, ANDROID_BUILD_CONSENT_MS));
  }
  setRegistrationAcknowledged(operationId: string, registrationGeneration: number, reviewId: string, acknowledged: boolean): void {
    this.syncProject();
    const consent = this.state.registrationConsent, attempt = this.registrationAttempt;
    if (!consent || !attempt || typeof acknowledged !== 'boolean' || !this.registrationMatches(attempt)
        || this.registrationCommonReason() || !sameAndroidToolRegistrationIdentity(consent, { operationId, registrationGeneration })
        || consent.reviewId !== reviewId) return;
    const now = this.now();
    if (!Number.isFinite(now) || now < attempt.requestedAt || now >= consent.deadline) { this.armRegistrationExpiry(); return; }
    this.update({ registrationConsent: { ...consent, acknowledged } });
  }
  async inspectToolSources(): Promise<void> {
    this.syncProject();
    if (this.inspectToolSourcesReason() || !this.observer || !this.state.toolRegistration || !this.state.toolSources) return;
    const context = this.currentRegistrationContext(); if (!context) return;
    await this.admitRegistrationAction('inspection', context, this.state.toolSources.sourceGeneration, null);
  }
  async registerToolSources(operationId: string, registrationGeneration: number, reviewId: string): Promise<void> {
    this.syncProject();
    const consent = this.state.registrationConsent;
    if (!consent || !sameAndroidToolRegistrationIdentity(consent, { operationId, registrationGeneration })
        || consent.reviewId !== reviewId || this.registerToolSourcesReason()) return;
    await this.admitRegistrationAction('registration', consent.binding.context, consent.binding.sourceGeneration, reviewId);
  }
  private async admitRegistrationAction(kind: AndroidToolRegistrationKind, context: PrepareAndroidBuild, sourceGeneration: number, reviewId: string | null): Promise<void> {
    if (kind === 'registration' && reviewId === null) return;
    const observer = this.observer, previous = observer?.registration;
    if (!observer?.active || !previous || previous.registrationGeneration >= ANDROID_BUILD_COUNTER_MAX - 1) {
      if (previous) this.retire({ generationLost: true }); return;
    }
    const now = this.now(), counters = this.advance('requestGeneration');
    if (counters.generationLost || !Number.isFinite(now) || now < 0 || !Number.isFinite(now + ANDROID_BUILD_CONSENT_MS)) {
      this.retire({ generationLost: true }); return;
    }
    const binding = this.registrationBinding(context, sourceGeneration, counters.requestGeneration!);
    if (!binding) return;
    const attempt: RegistrationAttempt = { observer, before: previous.registrationGeneration, after: previous.statusRevision,
      binding, kind, identity: null, retired: false, settled: false, sent: false, replySettled: false, notAdmitted: false,
      requestedAt: now, reviewDeadline: now + ANDROID_BUILD_CONSENT_MS };
    // No call to retire(): Register consumes this exact review, not a parallel
    // cancellation of it. Native independently rejects any conflicting owner.
    this.clearTimer(); this.registrationAttempt = attempt;
    observer.registrationStops = []; // common gate already excluded pending Cancel and any protocol loss
    this.update({ ...counters, registrationConsent: null, registrationPending: kind === 'inspection' ? 'inspect' : 'register',
      registrationUnconfirmed: false, registrationError: null, registrationCancelClaimed: null });
    this.syncProject();
    if (!this.registrationMatches(attempt) || this.registrationCommonReason(true)) {
      attempt.retired = true; attempt.settled = true; attempt.replySettled = true;
      this.update({ registrationPending: null }); return;
    }
    const common: InspectAndroidToolSources = { schemaVersion: 1, registrationGeneration: attempt.before, sourceGeneration, context };
    const request: InspectAndroidToolSources | RegisterAndroidToolSources = kind === 'inspection' ? common
      : { ...common, reviewId: reviewId!, consentVersion: ANDROID_TOOL_REGISTRATION_CONSENT, licenseAcknowledged: true };
    this.update({ registrationUnconfirmed: true }); this.syncProject();
    if (!this.registrationMatches(attempt) || this.registrationCommonReason(true)) {
      // No invoke occurred. This local unsent request creates no native original.
      attempt.retired = true; attempt.settled = true; attempt.replySettled = true;
      this.update({ registrationPending: null, registrationUnconfirmed: false }); return;
    }
    attempt.sent = true; // No renderer callback/yield separates this flag and invoke.
    try {
      const value = kind === 'inspection' ? await observer.api.inspectAndroidToolSources!(request)
        : await observer.api.registerAndroidToolSources!(request as RegisterAndroidToolSources);
      attempt.replySettled = true;
      if (!observer.active || this.registrationAttempt !== attempt) return;
      const status = parseAndroidToolRegistrationStatus(value);
      if (!status || !this.registrationCandidate(attempt, status)) { this.rejectRegistrationObservation(observer, status); return; }
      this.receiveRegistration(observer, status);
    } catch (error) {
      attempt.replySettled = true;
      if (!observer.active || this.registrationAttempt !== attempt) return;
      const safe = androidToolRegistrationError(error);
      if (['android_registration_invalid', 'android_registration_unavailable'].includes(safe.code)
          && !attempt.identity && (!observer.registration || !this.registrationCandidate(attempt, observer.registration))) {
        // These two native codes are strictly pre-admission, never lost-GO codes.
        attempt.notAdmitted = true; attempt.retired = true; attempt.settled = true;
        this.update({ registrationPending: null, registrationUnconfirmed: false, registrationConsent: null, registrationError: safe });
      } else if (['android_registration_invalid', 'android_registration_unavailable'].includes(safe.code)) {
        this.rejectRegistrationObservation(observer, observer.registration);
      } else this.registrationFail(error); // An event-only Review never repairs a failed original invoke into consent.
    } finally {
      if (observer.active && this.registrationAttempt === attempt && attempt.identity && observer.registration
          && this.registrationCandidate(attempt, observer.registration)) {
        this.receiveRegistration(observer, observer.registration);
      }
      if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
    }
  }
  canCancelToolRegistration(): boolean {
    const observer = this.observer, status = observer?.registration;
    return !this.disposed && !!observer?.active && hasAndroidToolRegistration(observer.api) && !!status?.operation
      && this.registrationHeld(status) && !observer.registrationStops.some((claim) => sameAndroidToolRegistrationIdentity(claim.identity, status.operation));
  }
  cancelToolRegistration(): boolean { return !!this.observer && this.stopRegistration(this.observer); }
  private stopRegistration(observer: Observer): boolean {
    const attempt = this.registrationAttempt;
    if (attempt?.observer === observer) attempt.retired = true; // Also survives a lost identity/GO reply.
    if (observer === this.observer) { this.clearTimer(); this.update({ registrationConsent: null }); }
    const status = observer.registration;
    if (!status?.operation || !this.registrationHeld(status)) return false;
    return this.requestRegistrationStop(observer, status.operation);
  }
  private requestRegistrationStop(observer: Observer, observed: AndroidToolRegistrationIdentity): boolean {
    if (!observer.active || !hasAndroidToolRegistration(observer.api)
        || observer.registrationStops.some((claim) => sameAndroidToolRegistrationIdentity(claim.identity, observed))) return false;
    // One actual original and at most one contradictory stop-only identity.
    // Further identities stay quarantined, not an unbounded cancellation queue.
    if (observer.registrationStops.length >= 2) {
      observer.registrationLost = true;
      this.update({ registrationIssue: true, integrityFailed: true, nativeBlocked: true }); return false;
    }
    const identity = freeze({ operationId: observed.operationId, registrationGeneration: observed.registrationGeneration });
    const claim = { identity, pending: true };
    observer.registrationStops.push(claim);
    if (sameAndroidToolRegistrationIdentity(observer.registration?.operation ?? null, identity)) {
      this.update({ registrationCancelClaimed: identity });
    }
    this.update({ registrationCancelPending: true });
    void (async () => {
      try {
        const value = await observer.api.cancelAndroidToolRegistration!({ schemaVersion: 1, ...identity });
        if (!observer.active) return;
        const result = parseAndroidToolRegistrationStatus(value);
        if (!result || !sameAndroidToolRegistrationIdentity(result.operation, identity)) {
          this.rejectRegistrationObservation(observer, result); return;
        }
        this.receiveRegistration(observer, result);
      } catch (error) { if (observer.active) this.registrationFail(error); }
      finally {
        claim.pending = false;
        if (observer === this.observer) this.update({ registrationCancelPending: observer.registrationStops.some((item) => item.pending) });
        if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
      }
    })();
    return true;
  }

  private catalogFail(error: unknown, protocol = false, observer: Observer | null = this.observer): void {
    if (protocol && observer) observer.catalogLost = true;
    this.retire({ catalogError: androidCatalogError(error), catalogIssue: true,
      nativeBlocked: this.state.nativeBlocked || protocol, integrityFailed: this.state.integrityFailed || protocol });
  }
  private catalogCandidateMatches(attempt: CatalogAttempt, status: AndroidToolchainCatalogStatus): boolean {
    if (attempt.kind === 'select') return sameAndroidCatalogSelection(status.selected, attempt.selection);
    if (status.selected !== null) return false;
    if (status.phase !== 'ready') return true;
    const verified = status.entries.filter((row) => row.status === 'verified-this-session');
    if (attempt.kind === 'refresh') return verified.length === 0;
    const selected = verified[0]?.selection, expected = attempt.comparison;
    return verified.length === 1 && selected != null && expected !== null && selected.instance === expected.instance &&
      selected.recordSha256 === expected.recordSha256 && selected.inventorySha256 === expected.inventorySha256 &&
      selected.osProviderSha256 === expected.osProviderSha256;
  }
  private receiveCatalog(observer: Observer, value: unknown,
    receipt: 'event' | 'request' | 'status' | 'cancel' = 'event'): AndroidToolchainCatalogStatus | null {
    if (!observer.active) return null;
    const status = parseAndroidToolchainCatalogStatus(value);
    if (!status) { this.catalogFail(null, true); return null; }
    const previous = observer.catalog, attempt = this.catalogAttempt;
    const identity = status.operationId === null ? null : { catalogGeneration: status.catalogGeneration, operationId: status.operationId };
    const ours = attempt?.observer === observer;
    if (receipt === 'request') {
      if (!ours || !attempt || attempt.notAdmitted || status.statusRevision <= attempt.after || identity === null ||
          status.catalogGeneration !== attempt.before + (attempt.kind === 'select' ? 0 : 1) ||
          attempt.identity !== null && !sameAndroidCatalogIdentity(attempt.identity, identity) ||
          !this.catalogCandidateMatches(attempt, status)) { this.catalogFail(null, true, observer); return null; }
      if (!observer.catalogLost) attempt.replyConfirmed = true;
    }
    if (receipt === 'cancel' && !observer.catalogLost && sameAndroidCatalogIdentity(this.catalogCancelClaim, identity) && identity !== null)
      observer.catalogCancelConfirmed = true;
    if (previous && status.statusRevision < previous.statusRevision) return status;
    if (previous && status.statusRevision === previous.statusRevision && !sameAndroidBuildData(previous, status)) {
      this.catalogFail(null, true); return null;
    }
    if (previous && status.catalogGeneration < previous.catalogGeneration) { this.catalogFail(null, true); return null; }
    if (previous && status.catalogGeneration !== previous.catalogGeneration &&
        (!ours || attempt.kind === 'select' || attempt.notAdmitted || status.catalogGeneration !== attempt.before + 1 || status.statusRevision <= attempt.after)) {
      this.catalogFail(null, true); return null;
    }
    if (previous && previous.catalogGeneration === status.catalogGeneration && previous.operationId !== status.operationId ||
        ours && attempt.identity && !sameAndroidCatalogIdentity(attempt.identity, identity)) {
      this.catalogFail(null, true); return null;
    }
    if (previous?.phase === 'unknown' && status.phase !== 'unknown' ||
        previous && previous.catalogGeneration === status.catalogGeneration && ['ready', 'refused', 'cancelled'].includes(previous.phase) &&
          androidCatalogActive(status)) { this.catalogFail(null, true); return null; }
    if (ours && !attempt.identity && identity && attempt.kind !== 'select' && !attempt.notAdmitted &&
        status.catalogGeneration === attempt.before + 1 && status.statusRevision > attempt.after) attempt.identity = identity;
    const acknowledged = !!ours && status.statusRevision > attempt.after &&
      (attempt.kind !== 'select' ? sameAndroidCatalogIdentity(attempt.identity, identity) && identity !== null :
        status.catalogGeneration === attempt.before && sameAndroidCatalogSelection(status.selected, attempt.selection));
    if (ours && acknowledged && !this.catalogCandidateMatches(attempt, status)) {
      this.catalogFail(null, true, observer); return null;
    }
    // Events can identify native custody, never replace a returned request
    // receipt or release its still-pending invoke. After a rejected/unknown
    // reply, an exact original Status (or Cancel reply) may confirm it only
    // once that original invoke has actually settled. Protocol loss is sticky.
    if (!observer.catalogLost && ours && acknowledged && attempt.replySettled &&
        (receipt === 'status' || receipt === 'cancel')) attempt.replyConfirmed = true;
    if (!observer.catalogLost && receipt === 'status' && !observer.catalogCancelPending &&
        sameAndroidCatalogIdentity(this.catalogCancelClaim, identity) && identity !== null)
      observer.catalogCancelConfirmed = true;
    const returned = !!ours && attempt.replySettled && attempt.replyConfirmed;
    if (ours && acknowledged) attempt.settled = !observer.catalogLost && returned && !androidCatalogActive(status);
    const notAdmitted = !observer.catalogLost && !!ours && attempt.notAdmitted && attempt.replySettled &&
      status.catalogGeneration === attempt.before;
    if (notAdmitted) attempt.settled = true;
    const sameCancel = sameAndroidCatalogIdentity(this.catalogCancelClaim, identity) && identity !== null;
    const cancelReceipt = !sameCancel || !observer.catalogCancelPending && observer.catalogCancelConfirmed;
    const cancelSettled = sameCancel && cancelReceipt && !androidCatalogActive(status) && (!ours || returned || notAdmitted);
    const confirmed = !observer.catalogLost && cancelReceipt && (acknowledged && returned || notAdmitted || cancelSettled);
    if (confirmed) observer.catalogUnconfirmed = false;
    if (previous && !sameAndroidCatalogSelection(previous.selected, status.selected)) this.retire(this.advance('contextGeneration'));
    observer.catalog = status;
    if (observer === this.observer) {
      this.update({ catalogStatus: status, catalogPending: confirmed ? null : this.state.catalogPending,
        catalogUnconfirmed: observer.catalogUnconfirmed,
        nativeBlocked: this.state.nativeBlocked || status.phase === 'unknown' ||
          ['cleanup-unknown', 'document-lost', 'shutdown'].includes(status.availability) });
    }
    if (this.disposed && androidCatalogActive(status)) this.stopCatalog(observer);
    if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
    return status;
  }
  private catalogRequestFailed(attempt: CatalogAttempt, error: unknown): void {
    const observer = attempt.observer;
    if (!observer.active || this.catalogAttempt !== attempt) return;
    const normalized = androidCatalogError(error);
    if (normalized.code === 'android_catalog_invalid' || normalized.code === 'android_catalog_unavailable') {
      const stayed = attempt.kind === 'select' ?
        observer.catalog?.catalogGeneration === attempt.before && !sameAndroidCatalogSelection(observer.catalog.selected, attempt.selection) :
        attempt.identity === null && observer.catalog?.catalogGeneration === attempt.before;
      if (!stayed) { this.catalogFail(null, true); return; }
      // These codes are PRE-ADMISSION only; admitted release/status loss uses
      // unconfirmed. A contradictory native identity remains protocol loss.
      attempt.notAdmitted = true;
    } else { observer.catalogUnconfirmed = true; this.update({ catalogUnconfirmed: true }); }
    this.catalogFail(normalized);
  }
  private finishCatalogRequest(attempt: CatalogAttempt): void {
    attempt.replySettled = true;
    if (this.catalogAttempt === attempt && attempt.observer.active && attempt.observer.catalog) {
      this.receiveCatalog(attempt.observer, attempt.observer.catalog);
    }
    if (this.disposed && !this.needsOriginal(attempt.observer)) this.detach(attempt.observer);
  }
  canCheckCatalogStatus(): boolean { return !this.disposed && !!this.observer?.active && !this.state.catalogReadPending; }
  async checkCatalogStatus(): Promise<void> {
    const observer = this.observer;
    if (this.disposed || !observer?.active) return;
    if (observer.catalogReading) return observer.catalogReading;
    const work = Promise.resolve().then(async () => {
      if (!observer.active) return;
      try {
        const status = this.receiveCatalog(observer, await observer.api.androidToolchainCatalogStatus(), 'status');
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
    if (this.state.registrationPending || this.state.registrationUnconfirmed || this.state.registrationCancelPending || this.state.registrationIssue || this.registrationHeld())
      return 'Settle the original protected registration or explicitly discard its source review before catalog work.';
    const observer = this.observer, catalog = this.state.catalogStatus, op = this.state.status?.operation;
    if (!observer?.active || observer.generation !== this.state.connectionGeneration || !this.state.catalogListening || !catalog || this.state.catalogIssue)
      return 'Check the original tool catalog and its subscription before changing the selection.';
    if (this.state.catalogPending || this.state.catalogUnconfirmed || this.state.catalogCancelPending || androidCatalogActive(catalog))
      return 'Wait for the original catalog request or cancellation; a lost reply is not cleanup.';
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
    if (!observer.active || this.observer !== observer || observer.catalog !== previous || this.disposed) return;
    const attempt: CatalogAttempt = { observer, before: previous.catalogGeneration, after: previous.statusRevision,
      identity: null, selection: null, comparison: null, kind: 'refresh', settled: false, replySettled: false, replyConfirmed: false, notAdmitted: false };
    this.catalogAttempt = attempt; this.catalogCancelClaim = null; observer.catalogUnconfirmed = true;
    this.update({ catalogPending: 'refresh', catalogUnconfirmed: true, catalogCancelClaimed: null, catalogError: null });
    try {
      if (this.disposed || !observer.active || this.observer !== observer || this.state.nativeBlocked || this.state.integrityFailed) {
        attempt.notAdmitted = true; return;
      }
      const value = await observer.api.refreshAndroidToolchainCatalog();
      if (!observer.active || this.catalogAttempt !== attempt) return;
      const status = parseAndroidToolchainCatalogStatus(value);
      if (!status || status.catalogGeneration !== attempt.before + 1 || !status.operationId || status.statusRevision <= attempt.after) {
        this.catalogFail(null, true); return;
      }
      this.receiveCatalog(observer, status, 'request');
    } catch (error) { this.catalogRequestFailed(attempt, error); }
    finally { this.finishCatalogRequest(attempt); }
  }
  async recoverToolchain(instance: string, recordSha256: string): Promise<void> {
    if (this.catalogActionReason() || !this.observer?.catalog) return;
    const observer = this.observer, previous = observer.catalog!;
    const row = previous.entries.find((entry) => entry.instance === instance && entry.status === 'recovery-required' &&
      entry.recovery.recordSha256 === recordSha256);
    if (previous.phase !== 'ready' || row?.status !== 'recovery-required') return;
    if (typeof observer.api.recoverAndroidToolchain !== 'function') { this.catalogFail({ code: 'android_catalog_unavailable' }); return; }
    if (previous.catalogGeneration >= ANDROID_BUILD_COUNTER_MAX - 1) { this.retire({ generationLost: true }); return; }
    const comparison = freeze(androidCatalogComparison(row.recovery));
    this.retire(this.advance('contextGeneration'));
    if (!observer.active || this.observer !== observer || observer.catalog !== previous || this.disposed) return;
    const attempt: CatalogAttempt = { observer, before: previous.catalogGeneration, after: previous.statusRevision,
      identity: null, selection: null, comparison, kind: 'recover', settled: false, replySettled: false, replyConfirmed: false, notAdmitted: false };
    this.catalogAttempt = attempt; this.catalogCancelClaim = null; observer.catalogUnconfirmed = true;
    this.update({ catalogPending: 'recover', catalogUnconfirmed: true, catalogCancelClaimed: null, catalogError: null });
    try {
      if (this.disposed || !observer.active || this.observer !== observer || this.state.nativeBlocked || this.state.integrityFailed) {
        attempt.notAdmitted = true; return;
      }
      const value = await observer.api.recoverAndroidToolchain({ schemaVersion: 1, ...comparison });
      if (!observer.active || this.catalogAttempt !== attempt) return;
      const status = parseAndroidToolchainCatalogStatus(value);
      if (!status || status.catalogGeneration !== attempt.before + 1 || !status.operationId || status.statusRevision <= attempt.after) {
        this.catalogFail(null, true); return;
      }
      this.receiveCatalog(observer, status, 'request');
    } catch (error) { this.catalogRequestFailed(attempt, error); }
    finally { this.finishCatalogRequest(attempt); }
  }
  async selectToolchain(instance: string, recordSha256: string): Promise<void> {
    if (this.catalogActionReason() || !this.observer?.catalog) return;
    const observer = this.observer, previous = observer.catalog!;
    const row = previous.entries.find((entry) => entry.instance === instance && entry.status === 'verified-this-session' &&
      entry.selection.recordSha256 === recordSha256);
    if (previous.phase !== 'ready' || row?.status !== 'verified-this-session') return;
    const selected = row.selection;
    if (sameAndroidCatalogSelection(previous.selected, selected)) return;
    this.retire(this.advance('contextGeneration'));
    if (!observer.active || this.observer !== observer || observer.catalog !== previous || this.disposed) return;
    const attempt: CatalogAttempt = { observer, before: previous.catalogGeneration, after: previous.statusRevision,
      identity: previous.operationId ? { catalogGeneration: previous.catalogGeneration, operationId: previous.operationId } : null,
      selection: selected, comparison: null, kind: 'select', settled: false, replySettled: false, replyConfirmed: false, notAdmitted: false };
    this.catalogAttempt = attempt; this.catalogCancelClaim = null; observer.catalogUnconfirmed = true;
    this.update({ catalogPending: 'select', catalogUnconfirmed: true, catalogCancelClaimed: null, catalogError: null });
    try {
      if (this.disposed || !observer.active || this.observer !== observer || this.state.nativeBlocked || this.state.integrityFailed) {
        attempt.notAdmitted = true; return;
      }
      const value = await observer.api.selectAndroidToolchain({ schemaVersion: 1, ...androidCatalogComparison(selected) });
      if (!observer.active || this.catalogAttempt !== attempt) return;
      const status = parseAndroidToolchainCatalogStatus(value);
      if (!status || status.statusRevision <= attempt.after || status.catalogGeneration !== attempt.before ||
          !sameAndroidCatalogSelection(status.selected, selected)) { this.catalogFail(null, true); return; }
      this.receiveCatalog(observer, status, 'request');
    } catch (error) { this.catalogRequestFailed(attempt, error); }
    finally { this.finishCatalogRequest(attempt); }
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
    if (sameAndroidCatalogIdentity(this.catalogCancelClaim, identity) || observer.catalogCancelPending) return false;
    this.catalogCancelClaim = identity; observer.catalogCancelPending = true; observer.catalogCancelConfirmed = false;
    observer.catalogUnconfirmed = true;
    this.update({ catalogCancelClaimed: identity, catalogCancelPending: true, catalogUnconfirmed: true });
    void (async () => {
      try {
        const value = await observer.api.cancelAndroidToolchainCatalog({ schemaVersion: 1, ...identity });
        if (!observer.active) return;
        const status = parseAndroidToolchainCatalogStatus(value);
        if (!status || !sameAndroidCatalogIdentity(identity, status.operationId === null ? null :
            { catalogGeneration: status.catalogGeneration, operationId: status.operationId })) { this.catalogFail(null, true); return; }
        this.receiveCatalog(observer, status, 'cancel');
      } catch (error) {
        if (observer.active) { observer.catalogUnconfirmed = true; this.update({ catalogUnconfirmed: true }); this.catalogFail(error); }
      } finally {
        observer.catalogCancelPending = false;
        if (observer === this.observer) this.update({ catalogCancelPending: false });
        if (observer.active && observer.catalog) this.receiveCatalog(observer, observer.catalog);
        if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
      }
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
    if (this.state.registrationIssue || this.state.registrationUnconfirmed || this.state.registrationPending || this.state.registrationCancelPending || this.registrationHeld())
      return 'Settle the original source inspection or protected copy, then explicitly refresh and choose the catalog entry.';
    if (this.state.catalogIssue || this.state.catalogUnconfirmed || this.state.catalogPending || this.state.catalogCancelPending || androidCatalogActive(this.state.catalogStatus))
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
    this.retire(); if (this.observer) { this.stopCatalog(this.observer); this.stopSources(this.observer); this.stopRegistration(this.observer); }
    this.disposed = true; this.listeners.clear();
    if (this.observer && !this.needsOriginal(this.observer)) this.detach(this.observer);
    // Sent work retains a retirement-only original observer until actual native
    // terminal settlement. Page navigation must call setVisible, not dispose.
  }
}

export const androidToolchainCatalogHelp: HelpContent = {
  label: 'Protected Android tools on this Mac', requiredness: 'conditional',
  requiredWhen: 'Choose a fully verified protected tool copy before reviewing a Mac Android build.',
  what: 'Refresh lists at most32 original destination, lease and registration instances. Busy, Interrupted and Refused rows remain visible. Metadata-only rows cannot be selected.',
  why: 'The build must use the exact original tool copy you chose, not PATH, another account’s files or whichever version looks newest. Version labels are a supported tuple, not proof of project compatibility.',
  where: 'Use Refresh, then explicitly Recover a metadata row for full original comparison. After that original has settled, separately Choose its verified-this-session row.',
  format: 'Recover and Choose compare the same generation, instance and all three commitments retained by native ownership. You never enter a UID, path or command. Neither action approves a build.',
  failure: 'No automatic recovery, repair, deletion, selection, tool installation or license acceptance occurs. A pending invoke or Cancel remains app-owned even after a terminal event. Keep original Status and Cancel when its result is unconfirmed; Build performs fresh original admission.',
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
