// App-owned coordination only, following OfflinePreflightController's original
// observer/one-Start lifetime. A view, Promise or saved comparison is not native
// custody, qualification, cancellation settlement or a release approval.
import { assetStorageWritable } from './assetSessionProtocol.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import { parseReleaseVersionObservation } from './releaseVersion.ts';
import type { ReleaseVersionState } from './releaseVersion.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';
import type { ApiError, BridgeMode, HelpContent } from './types.ts';
import type { IOSArchiveApi, IOSArchiveContext, IOSArchiveIdentity, IOSArchiveOperation, IOSArchiveSavedConfig,
  IOSArchiveSavedVersion, IOSArchiveSelection, IOSArchiveStatus, IOSRecoveryIntent, IOSRecoveryOperation,
  IOSSigningAssignment, IOSSigningPolicy, PrepareIOSArchive, StartIOSArchive } from './iosArchiveTypes.ts';
import { IOS_ARCHIVE_CONSENT, IOS_SIGNED_ARCHIVE_CONSENT, IOS_RECOVERY_CONSENT, IOS_ACCOUNT_RECOVERY_CONFIRMATION,
  IOS_PROJECT_RECOVERY_CONFIRMATION, IOS_ARCHIVE_CONSENT_MS, IOS_ARCHIVE_COUNTER_MAX, iosArchiveAvailabilityText, iosArchiveModeAvailability, isIOSRecoveryOperation,
  iosArchiveCounter, iosArchiveError, iosArchiveOperationProgress, copyIOSArchiveRequest, parseIOSArchiveSavedConfig,
  parseIOSArchiveSavedVersion, parseIOSArchiveSelection, parseIOSArchiveStatus, parseIOSSigningPolicy,
  sameIOSArchiveData, sameIOSArchiveIdentity, sameIOSArchiveSavedPair } from './iosArchiveProtocol.ts';

export type IOSArchiveSavedSelection = IOSArchiveSelection;
interface VersionObservationBinding {
  observationGeneration: number; requestId: number; readEpoch: number; connectionGeneration: number; selectionGeneration: number;
}
export interface IOSArchiveProject {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  savedConfig: IOSArchiveSavedConfig | null; savedVersion: IOSArchiveSavedVersion | null;
  selection: IOSArchiveSavedSelection | null; versionObservation: VersionObservationBinding | null; inputIssue: string | null;
  signingPolicy: Pick<IOSSigningPolicy, 'teamId' | 'distributionCertificateSha256'> | null;
  dirtyDraft: boolean; snapshotPending: boolean; versionPending: boolean; saveRecoveryRequired: boolean;
}
export interface IOSArchiveBinding {
  context: IOSArchiveContext; selection: IOSArchiveSavedSelection | null; observationGeneration: number; versionObservation: VersionObservationBinding | null;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
}
export interface IOSArchiveConsent extends IOSArchiveIdentity { binding: IOSArchiveBinding; acknowledged: boolean; deadline: number }
export interface IOSSigningObservation { policy: IOSSigningPolicy | null; issue: string | null }
export interface IOSArchiveState {
  mode: BridgeMode; archiveMode: 'unsigned' | 'signed'; project: IOSArchiveProject | null; signing: IOSSigningObservation;
  visible: boolean; recoveryVisible: boolean; selectionPending: boolean;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
  listening: boolean; initialized: boolean; readPending: boolean; status: IOSArchiveStatus | null;
  consent: IOSArchiveConsent | null; pending: 'prepare' | 'start' | null; originalUnconfirmed: boolean;
  historical: boolean; cancelClaimed: IOSArchiveIdentity | null; error: ApiError | null;
  observationIssue: 'bridge' | 'protocol' | null; nativeBlocked: boolean; integrityFailed: boolean; generationLost: boolean;
}
type Port = IOSArchiveApi & { mode: BridgeMode };
interface Observer { api: Port; active: boolean; generation: number; unlisten: (() => void) | null; reading: Promise<void> | null; status: IOSArchiveStatus | null }
interface Attempt {
  observer: Observer; binding: IOSArchiveBinding; previous: IOSArchiveIdentity | null; after: number;
  identity: IOSArchiveIdentity | null; prepareSent: boolean; prepareReply: boolean; deadline: number;
  startSent: boolean; startAfter: number; retired: boolean; settled: boolean;
}
interface Context {
  selectedProject: () => ProjectSession | null; releaseVersion: () => ReleaseVersionState | null;
  assetSession?: () => AssetDisplayState | null;
  otherOperationReason: () => string | null; now?: () => number;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
const id = (op: IOSArchiveIdentity): IOSArchiveIdentity => ({ operationId: op.operationId, ownerGeneration: op.ownerGeneration });
const active = (op: IOSArchiveOperation | null | undefined): boolean => !!op && op.phase !== 'terminal';
// The snapshot is not serialized or retained in state. Read only the bounded
// display fields through data descriptors, never getters or a dirty baseline.
function own(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return undefined;
  const field = Object.getOwnPropertyDescriptor(value, key);
  return field?.enumerable && Object.hasOwn(field, 'value') ? field.value : undefined;
}
function savedSelection(data: unknown): IOSArchiveSavedSelection | null {
  const ios = own(data, 'ios'), workspace = own(ios, 'workspace'), project = own(ios, 'project');
  const containerKind = typeof workspace === 'string' && workspace.length > 0 ? 'workspace' : 'project';
  const container = containerKind === 'workspace' ? workspace : project;
  const scheme = own(ios, 'scheme'), bundleId = own(ios, 'bundleId'), configured = own(ios, 'archiveConfiguration');
  const symbols = own(ios, 'symbols'), policy = own(symbols, 'policy'), preparation = own(ios, 'prepareCommand');
  const configuration = configured === undefined ? 'Release' : configured;
  const symbolsPolicy = policy === undefined ? 'disabled' : policy;
  let preparationConfigured = false;
  if (preparation !== undefined && preparation !== null) {
    if (!Array.isArray(preparation) || Object.getPrototypeOf(preparation) !== Array.prototype) return null;
    const length = Object.getOwnPropertyDescriptor(preparation, 'length');
    if (!length || !Object.hasOwn(length, 'value') || typeof length.value !== 'number' || !Number.isSafeInteger(length.value) ||
        length.value < 0 || length.value > 256) return null;
    preparationConfigured = length.value > 0;
  }
  if (own(ios, 'enabled') !== true) return null;
  // Saved display labels only. The core independently selects/admits its exact
  // saved container, scheme and argv; the renderer sends none of these labels.
  return parseIOSArchiveSelection({ containerKind, container, scheme, configuration, bundleId, symbolsPolicy, preparationConfigured });
}
function savedSigningPolicy(data: unknown): IOSArchiveProject['signingPolicy'] {
  const ios = own(data, 'ios'), teamId = own(ios, 'teamId'), fingerprint = own(ios, 'distributionCertificateSha256');
  if (typeof teamId !== 'string' || teamId.length !== 10 || /[^A-Z0-9]/.test(teamId) || typeof fingerprint !== 'string' || fingerprint.length > 95) return null;
  // The saved core policy accepts colon-separated/uppercase public fingerprints;
  // its request comparison uses precisely this normalization, not a new signer.
  const distributionCertificateSha256 = fingerprint.replaceAll(':', '').toLowerCase();
  return distributionCertificateSha256.length === 64 && !/[^0-9a-f]/.test(distributionCertificateSha256) ? { teamId, distributionCertificateSha256 } : null;
}
function signingObservation(project: IOSArchiveProject | null, assets: AssetDisplayState | null): IOSSigningObservation {
  const unavailable = (issue: string): IOSSigningObservation => ({ policy: null, issue });
  if (!project?.signingPolicy) return unavailable('Save the Apple Team ID and reviewed Apple Distribution certificate SHA-256 fingerprint in Project settings, then refresh saved configuration.');
  if (project.dirtyDraft) return unavailable('Signed export requires the credential context to match the saved configuration. Save or explicitly revert the unsaved draft, then refresh, read the saved version and assign the current inputs again.');
  const status = assets?.status, context = status?.context, operation = status?.operation;
  if (!assets || assets.mode !== 'native' || !status || !assetStorageWritable(status) || !status.capability.available ||
      assets.blocked || assets.observationFailed || assets.originPending || assets.busy || assets.updatingContext || !assets.contextCurrent ||
      operation && (operation.phase !== 'idle' || operation.settlement !== 'known'))
    return unavailable('In Credentials, choose available memory-only storage or unlock your encrypted vault, then finish selection, assessment, save and separate assignment. An active, locked, read-only, stale or unverified source cannot supply signing input.');
  if (!context || context.projectId !== project.projectId || context.platform !== 'ios' || context.stage !== 'candidate' || context.purpose !== 'signing' ||
      assets.scope.platform !== 'ios' || assets.scope.stage !== 'candidate' || assets.scope.purpose !== 'signing')
    return unavailable('In Credentials, submit this saved project with iOS · Candidate / internal testing · Build / signing only, then assign its inputs. Other projects or release contexts cannot donate material.');
  const assignments: IOSSigningAssignment[] = [];
  for (const kind of ['apple-p12', 'apple-profile', 'ios-firebase', 'project-read-token'] as const) {
    const row = status.assignments.find((assignment) => assignment.kind === kind);
    if (!row) {
      if (kind === 'apple-p12' || kind === 'apple-profile') return unavailable(`Keep and assign ${kind === 'apple-p12' ? 'the Apple Distribution P12 and its password' : 'the Apple-issued App Store provisioning profile'} to this exact iOS signing context in Credentials.`);
      continue;
    }
    if (row.availability !== 'available' || row.contextRevision !== context.revision || !status.records.some((record) =>
      record.kind === kind && record.recordId === row.recordId && record.revision === row.recordRevision && record.availability === 'assigned'))
      return unavailable('A selected signing/build-input assignment is stale, unavailable or being replaced. Review and assign its current original record before preparing signed export.');
    assignments.push({ kind, recordId: row.recordId, recordRevision: row.recordRevision, contextRevision: row.contextRevision });
  }
  const policy = parseIOSSigningPolicy({ ...project.signingPolicy, assignments });
  return policy ? { policy, issue: null } : unavailable('The current assignment revisions cannot be bound to one exact signing context. Recheck the original credential-session status.');
}
function projectObservation(session: ProjectSession, version: ReleaseVersionState | null): IOSArchiveProject {
  const project: IOSArchiveProject = { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, savedConfig: null, savedVersion: null, selection: null, versionObservation: null, signingPolicy: null,
    dirtyDraft: isDirty(session), snapshotPending: session.snapshotRequest !== null, versionPending: version?.pending !== null && version?.pending !== undefined,
    saveRecoveryRequired: session.saveRecoveryRequired, inputIssue: 'Refresh a current, format-valid saved configuration, then read its saved version. Prior snapshots and editor baselines are not build inputs.' };
  try {
    if (project.snapshotPending || session.snapshotError !== null || session.snapshotPredatesSave || session.snapshot === null ||
        !Number.isFinite(session.observedAt) || session.observedAt === null || session.observedAt < 0 || session.observationGeneration < 1) return project;
    const observed = savedConfigFromSnapshot(session.snapshot), compared = parseIOSArchiveSavedConfig(session.savedConfigContent);
    if (!observed || !compared || !sameIOSArchiveData(observed, compared)) return project;
    project.savedConfig = compared;
    const data = own(own(session.snapshot, 'config'), 'data');
    project.signingPolicy = savedSigningPolicy(data);
    project.selection = savedSelection(data);
    if (!project.selection) { project.inputIssue = 'Enable and save the intended iOS bundle ID, explicit Xcode workspace or project and shared scheme, then refresh the saved configuration.'; return project; }
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
          binding.connectionGeneration, binding.selectionGeneration].every(iosArchiveCounter)) return project;
    if (!sameIOSArchiveData(result.savedConfig, compared) || own(own(data, 'version'), 'source') !== result.source) {
      project.inputIssue = 'The saved-version response does not match the current saved configuration/source. Refresh the saved configuration and explicitly read the saved version again.'; return project;
    }
    const savedVersion = parseIOSArchiveSavedVersion({ ...result.savedVersion, source: result.source, name: result.version.name, build: result.version.build });
    if (!savedVersion) return project;
    project.savedVersion = savedVersion;
    project.versionObservation = { observationGeneration: binding.observationGeneration, requestId: binding.requestId, readEpoch: binding.readEpoch,
      connectionGeneration: binding.connectionGeneration, selectionGeneration: binding.selectionGeneration };
    project.inputIssue = null;
  } catch { /* Snapshot hooks and parser exceptions never become UI text. */ }
  return project;
}
export function iosArchiveOwnerReason(state: IOSArchiveState): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost) return 'iOS-archive ownership or finality is unverified. Keep original Status and Cancel; conflicting work is disabled.';
  if (state.originalUnconfirmed || state.pending || active(state.status?.operation)) return 'The iOS archive holds its original consent or execution slot. Cancel or settle that original operation before conflicting work.';
  if (state.mode === 'native' && state.observationIssue) return 'The original iOS-archive status is unverified. Check retained Status before conflicting work.';
  return null;
}

export class IOSArchiveController {
  private state: IOSArchiveState = freeze<IOSArchiveState>({ mode: 'unavailable', archiveMode: 'unsigned', project: null,
    signing: { policy: null, issue: 'Review the saved signing policy and current credential assignments.' }, visible: false, recoveryVisible: false, selectionPending: false,
    connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0, requestGeneration: 0, listening: false, initialized: false, readPending: false,
    status: null, consent: null, pending: null, originalUnconfirmed: false, historical: false, cancelClaimed: null, error: null,
    observationIssue: null, nativeBlocked: false, integrityFailed: false, generationLost: false });
  private readonly context: Context;
  private observer: Observer | null = null;
  private attempt: Attempt | null = null;
  private cancelClaim: IOSArchiveIdentity | null = null;
  private draftReference: ProjectSession['draft'] = null;
  private snapshotReference: ProjectSession['snapshot'] = null;
  private versionReference: ReleaseVersionState['result'] = null;
  private versionBindingReference: ReleaseVersionState['resultBinding'] = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Set<() => void>();
  private disposed = false;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): IOSArchiveState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private now(): number { return (this.context.now ?? (() => performance.now()))(); }
  private update(patch: Partial<IOSArchiveState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private advance(field: 'connectionGeneration' | 'selectionGeneration' | 'contextGeneration' | 'requestGeneration'): Partial<IOSArchiveState> {
    const next = this.state[field] + 1;
    return { [field]: Math.min(next, IOS_ARCHIVE_COUNTER_MAX), generationLost: this.state.generationLost || !iosArchiveCounter(next) };
  }
  private clearTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private retire(patch: Partial<IOSArchiveState> = {}, stop = true): void {
    this.clearTimer();
    if (this.attempt) this.attempt.retired = true;
    this.update({ ...patch, consent: null, historical: !!this.state.status?.operation || this.state.historical });
    if (stop) this.stopOriginal();
  }
  private fail(error: unknown, protocol = false): void {
    this.retire({ error: iosArchiveError(error), observationIssue: protocol ? 'protocol' : 'bridge',
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
  selectionIntent(): void { if (!this.disposed) this.retire(this.advance('selectionGeneration')); }
  snapshotIntent(projectId: string): void {
    if (!this.disposed && (projectId === this.state.project?.projectId || projectId === this.attempt?.binding.context.projectId))
      this.retire(this.advance('contextGeneration'));
  }
  versionIntent(): void { if (!this.disposed) this.retire(this.advance('contextGeneration')); }
  // Subscribe synchronously to ReleaseVersionController; a React effect after
  // rendering is too late to retire consent at read-pending/replacement time.
  syncReleaseVersion = (): void => { this.syncProject(); };
  // Asset mutation/context notifications run synchronously, not after a render.
  // A status reread with unchanged assignment DATA does not retire consent.
  syncAssetSession = (): void => { this.syncProject(); };
  setSelectionPending(selectionPending: boolean): void {
    if (!this.disposed && selectionPending !== this.state.selectionPending) this.retire({ ...this.advance('selectionGeneration'), selectionPending });
  }
  syncProject(): void {
    if (this.disposed) return;
    const session = this.context.selectedProject(), version = this.context.releaseVersion();
    const next = session ? projectObservation(session, version) : null, draft = session?.draft ?? null, snapshot = session?.snapshot ?? null;
    const signing = signingObservation(next, this.context.assetSession?.() ?? null);
    const result = version?.result ?? null, binding = version?.resultBinding ?? null;
    const projectChanged = !sameIOSArchiveData(next, this.state.project) || this.draftReference !== draft || this.snapshotReference !== snapshot ||
      this.versionReference !== result || this.versionBindingReference !== binding;
    if (!projectChanged && sameIOSArchiveData(signing, this.state.signing)) return;
    const signingRelevant = this.attempt && !this.attempt.settled ? this.attempt.binding.context.operation === 'ios-signed-export' : this.state.archiveMode === 'signed';
    if (!projectChanged && !signingRelevant) {
      this.update({ signing }); return;
    }
    this.draftReference = draft; this.snapshotReference = snapshot; this.versionReference = result; this.versionBindingReference = binding;
    const badCounter = next !== null && ![next.draftRevision, next.baselineGeneration, next.observationGeneration].every(iosArchiveCounter);
    this.retire({ ...this.advance('contextGeneration'), project: next, signing, generationLost: this.state.generationLost || badCounter ||
      this.state.contextGeneration === IOS_ARCHIVE_COUNTER_MAX });
  }
  setVisible(visible: boolean): void {
    if (this.disposed || visible === this.state.visible) return;
    if (!visible && this.attempt && this.attempt.binding.context.operation !== 'ios-local-recovery' && !this.attempt.startSent && !this.attempt.settled) this.retire({ ...this.advance('contextGeneration'), visible });
    else this.update({ visible }); // A started run stays app-owned across pages.
  }
  setRecoveryVisible(recoveryVisible: boolean): void {
    if (this.disposed || recoveryVisible === this.state.recoveryVisible) return;
    if (!recoveryVisible && this.attempt?.binding.context.operation === 'ios-local-recovery' && !this.attempt.startSent && !this.attempt.settled)
      this.retire({ ...this.advance('contextGeneration'), recoveryVisible });
    else this.update({ recoveryVisible });
  }
  setArchiveMode(archiveMode: 'unsigned' | 'signed'): boolean {
    if (this.disposed || !['unsigned', 'signed'].includes(archiveMode) || this.attempt?.startSent && !this.attempt.settled) return false;
    if (archiveMode !== this.state.archiveMode) this.retire({ ...this.advance('contextGeneration'), archiveMode });
    return true;
  }
  private needsOriginal(observer: Observer): boolean {
    return this.attempt?.observer === observer && this.attempt.prepareSent && !this.attempt.settled || active(observer.status?.operation);
  }
  private detach(observer: Observer): void {
    observer.active = false;
    try { observer.unlisten?.(); } catch { /* Listener release is not native settlement. */ }
    observer.unlisten = null;
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.retire(this.advance('connectionGeneration'));
    const observer = this.observer;
    if (observer && (this.needsOriginal(observer) || this.state.nativeBlocked || this.state.integrityFailed)) {
      this.update({ nativeBlocked: true, historical: true }); return; // Never adopt a replacement document/API.
    }
    if (observer) this.detach(observer);
    this.observer = null;
    this.update({ mode: 'unavailable', listening: false, initialized: false, readPending: false });
  }
  async connect(api: Port): Promise<void> {
    if (this.disposed || this.observer?.api === api) return;
    if (this.observer) this.beginConnection();
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost || this.observer) return;
    this.update({ mode: api.mode, observationIssue: null, error: null });
    if (api.mode !== 'native') return;
    const observer: Observer = { api, active: true, generation: this.state.connectionGeneration, unlisten: null, reading: null, status: null };
    this.observer = observer;
    try {
      const unlisten = await api.subscribeIOSArchive((value) => { if (observer.active) this.receive(observer, value); });
      if (!observer.active || this.observer !== observer || this.disposed && !this.needsOriginal(observer)) { unlisten(); return; }
      observer.unlisten = unlisten; this.update({ listening: true });
      await this.checkStatus(); // Subscribe before reading or preparing.
    } catch (error) { if (observer.active) this.fail(error); }
  }
  private matches(attempt: Attempt): boolean {
    const p = this.state.project, b = attempt.binding;
    const common = !this.disposed && !attempt.retired && this.attempt === attempt && this.observer === attempt.observer && attempt.observer.active &&
      b.connectionGeneration === this.state.connectionGeneration && b.selectionGeneration === this.state.selectionGeneration &&
      b.contextGeneration === this.state.contextGeneration && b.requestGeneration === this.state.requestGeneration && p !== null && b.context.projectId === p.projectId;
    if (!common || !p) return false;
    if (b.context.operation === 'ios-local-recovery') return true;
    return p.inputIssue === null && this.state.archiveMode === (b.context.operation === 'ios-signed-export' ? 'signed' : 'unsigned') &&
      (b.context.operation !== 'ios-signed-export' || this.state.signing.issue === null && sameIOSArchiveData(b.context.signing, this.state.signing.policy)) &&
      b.observationGeneration === p.observationGeneration && sameIOSArchiveData(b.versionObservation, p.versionObservation) &&
      sameIOSArchiveData(b.selection, p.selection) && b.context.projectId === p.projectId && b.context.draftRevision === p.draftRevision &&
      b.context.baselineGeneration === p.baselineGeneration && p.savedConfig !== null && p.savedVersion !== null &&
      sameIOSArchiveSavedPair(b.context, { savedConfig: p.savedConfig, savedVersion: p.savedVersion });
  }
  private originCandidate(attempt: Attempt, status: IOSArchiveStatus): boolean {
    const op = status.operation;
    return !!op && status.statusRevision > attempt.after && !sameIOSArchiveIdentity(op, attempt.previous) &&
      sameIOSArchiveData(op.context, attempt.binding.context) && (!attempt.identity || sameIOSArchiveIdentity(op, attempt.identity));
  }
  private reconcile(observer: Observer): void {
    const status = observer.status, attempt = this.attempt, op = status?.operation;
    if (!status || !op) return;
    const matched = attempt?.observer === observer && sameIOSArchiveIdentity(attempt.identity, op);
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
  private receive(observer: Observer, value: unknown): IOSArchiveStatus | null {
    if (!observer.active) return null;
    this.syncProject(); // Replies cannot rely on a last-rendered input pair.
    const status = parseIOSArchiveStatus(value);
    if (!status) { this.fail({ code: 'ios_archive_protocol' }, true); return null; }
    const previous = observer.status, a = previous?.operation, b = status.operation;
    if (previous && status.statusRevision < previous.statusRevision) {
      if (a && b && sameIOSArchiveIdentity(a, b) && !iosArchiveOperationProgress(b, a)) this.fail({ code: 'ios_archive_protocol' }, true);
      return status;
    }
    if (previous && status.statusRevision === previous.statusRevision && !sameIOSArchiveData(previous, status)) {
      this.fail({ code: 'ios_archive_protocol' }, true); return null;
    }
    if (a && b && sameIOSArchiveIdentity(a, b) && !iosArchiveOperationProgress(a, b)) { this.fail({ code: 'ios_archive_protocol' }, true); return null; }
    const attempt = this.attempt;
    if (attempt?.observer === observer && attempt.prepareSent) {
      if (attempt.identity ? !sameIOSArchiveIdentity(attempt.identity, b) :
          b && !sameIOSArchiveIdentity(b, attempt.previous) && !this.originCandidate(attempt, status)) { this.fail({ code: 'ios_archive_protocol' }, true); return null; }
      if (b && this.originCandidate(attempt, status) && !attempt.startSent &&
          (b.phase === 'starting' || b.phase === 'running' || b.outcome === 'complete')) { this.fail({ code: 'ios_archive_protocol' }, true); return null; }
      // While Prepare is pending, repeated previous-terminal Status is allowed
      // but belongs to the old review, not this attempt's changed selection.
      const belongsToAttempt = sameIOSArchiveIdentity(attempt.identity, b) || this.originCandidate(attempt, status);
      const selected = belongsToAttempt && b && !isIOSRecoveryOperation(b) ? b.activity?.selection : null;
      if (selected && !sameIOSArchiveData(selected, attempt.binding.selection)) {
        this.fail({ code: 'ios_archive_protocol' }, true); return null;
      }
      // A newer, fully checked original identity is useful for STOP/finality
      // even if the Prepare reply was lost. Observation NEVER sets prepareReply
      // or creates consent. In particular an expired terminal can settle the
      // original slot instead of leaving peers blocked forever with no Cancel.
      if (!attempt.identity && b && this.originCandidate(attempt, status)) attempt.identity = id(b);
    } else if (previous && !sameIOSArchiveIdentity(a ?? null, b) && (a !== null || b !== null)) {
      this.fail({ code: 'ios_archive_protocol' }, true); return null; // Unsolicited foreign IDs cannot authorize a run.
    }
    if (status.statusRevision === IOS_ARCHIVE_COUNTER_MAX) this.retire({ generationLost: true });
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
        const status = this.receive(observer, await observer.api.iosArchiveStatus());
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
  private commonReason(operation: IOSArchiveContext['operation'] = this.state.archiveMode === 'signed' ? 'ios-signed-export' : 'ios-unsigned-archive'): string | null {
    if (this.disposed || this.state.mode !== 'native') return 'Open the native application. Browser preview cannot prepare or run an iOS archive, signed export or recovery.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return iosArchiveOwnerReason(this.state);
    if (!this.observer?.active || this.observer.generation !== this.state.connectionGeneration || !this.state.listening || !this.state.initialized || !this.state.status || this.state.observationIssue)
      return 'A current original native Status and subscription are required. Passive diagnostics cannot qualify iOS archive execution.';
    if (this.state.status.statusRevision >= IOS_ARCHIVE_COUNTER_MAX) return 'The original status counter is exhausted. No counter or consent can be reused.';
    const availability = iosArchiveModeAvailability(this.state.status, operation);
    if (!['available', 'busy'].includes(availability)) return iosArchiveAvailabilityText[availability];
    if (operation === 'ios-local-recovery' ? !this.state.recoveryVisible : !this.state.visible)
      return operation === 'ios-local-recovery' ? 'Open Recovery to review this local account/project action.' : 'Open Releases to review this saved iOS archive and its project-code disclosure.';
    if (this.state.selectionPending) return 'Finish original project selection before reviewing this build.';
    const project = this.state.project;
    if (!project) return 'Choose a registered source project first; an evidence folder is not an execution target.';
    if (operation === 'ios-local-recovery') return this.context.otherOperationReason();
    if (project.saveRecoveryRequired) return 'Finish original configuration-save recovery before reviewing a build.';
    if (project.snapshotPending) return 'Wait for the current saved-configuration refresh to settle.';
    if (project.versionPending) return 'Wait for the original saved-version read to settle; an earlier result cannot stand in.';
    return project.inputIssue ?? (operation === 'ios-signed-export' ? this.state.signing.issue : null) ?? this.context.otherOperationReason();
  }
  prepareReason = (): string | null => this.commonReason() ?? iosArchiveOwnerReason(this.state) ??
    (this.state.status?.availability === 'busy' ? iosArchiveAvailabilityText.busy : null);
  startReason = (): string | null => {
    const common = this.commonReason(this.attempt?.binding.context.operation); if (common) return common;
    const consent = this.state.consent, attempt = this.attempt, op = this.state.status?.operation;
    if (!consent || !attempt || !attempt.prepareReply || attempt.startSent || !this.matches(attempt) || !sameIOSArchiveIdentity(consent, op ?? null) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable) return 'Review a new saved-input archive intent. Status or an earlier acknowledgement cannot authorize Start.';
    const now = this.now();
    if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) return 'This original five-minute review expired. Checking Status does not extend it.';
    return consent.acknowledged ? null : consent.binding.context.operation === 'ios-local-recovery' ?
      'Acknowledge this exact local inspection or idle-state recovery action before Start.' :
      'Acknowledge the exact saved inputs, project-code effects and inspection limits before Start.';
  };
  recoveryReason = (action: IOSRecoveryIntent['action'] = 'inspect', inspected: IOSRecoveryOperation | null = null): string | null => {
    const reason = this.commonReason('ios-local-recovery') ?? iosArchiveOwnerReason(this.state) ??
      (this.state.status?.availability === 'busy' ? iosArchiveAvailabilityText.busy : null);
    if (reason) return reason;
    if (action === 'inspect') return null;
    if (action !== 'account' && action !== 'project') return 'Only the explicit ordinary account or project recovery actions are supported.';
    const current = this.state.status?.operation;
    if (!inspected || !current || !isIOSRecoveryOperation(current) || !sameIOSArchiveData(current, inspected) ||
        current.context.recovery.action !== 'inspect' || current.phase !== 'terminal' || !current.report || this.state.historical ||
        !this.attempt?.settled || !this.attempt.startSent || !sameIOSArchiveIdentity(this.attempt.identity, current) || !this.matches(this.attempt))
      return 'Inspect local state first in this same project and original iOS owner. A copied session label or earlier report cannot authorize recovery.';
    // Native retains an action observation only for a finalized inspection
    // without STOP or a non-grant failure. Retained report facts alone are not it.
    if (!(current.outcome === 'complete' && current.reason === 'none' ||
          (current.outcome === 'failed' || current.outcome === 'refused') && current.reason === 'recovery-attention'))
      return 'This finalized inspection did not grant ordinary recovery. Keep its retained report as observations, then inspect again in this same project before reviewing an action.';
    const row = current.report[action];
    return row?.next === 'ordinary' && row.session !== null ? null :
      'This exact inspected session does not permit ordinary recovery. Wait for busy work, preserve conflicts, or follow the manual-recovery limitation; do not reset state.';
  };
  private expireConsent(): void {
    const consent = this.state.consent; if (!consent) return;
    const now = this.now(); if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) this.retire();
  }
  private armExpiry(): void {
    this.clearTimer(); const consent = this.state.consent; if (!consent) return;
    const remaining = consent.deadline - this.now();
    if (!Number.isFinite(remaining) || remaining <= 0) { this.retire(); return; }
    this.timer = setTimeout(() => { this.timer = null; this.expireConsent(); if (this.state.consent) this.armExpiry(); }, Math.min(remaining, IOS_ARCHIVE_CONSENT_MS));
  }
  async prepare(): Promise<void> {
    this.syncProject();
    const project = this.state.project;
    if (this.prepareReason() || !this.observer || !project?.savedConfig || !project.savedVersion || !project.selection || !project.versionObservation) return;
    const request = copyIOSArchiveRequest('prepare_ios_archive', { projectId: project.projectId, draftRevision: project.draftRevision,
      baselineGeneration: project.baselineGeneration, savedConfig: project.savedConfig, savedVersion: project.savedVersion,
      ...(this.state.archiveMode === 'signed' ? { signing: this.state.signing.policy } : {}) }) as PrepareIOSArchive | null;
    if (!request) { this.fail({ code: 'ios_archive_invalid' }, true); return; }
    await this.prepareRequest(request);
  }
  async prepareRecovery(action: IOSRecoveryIntent['action'] = 'inspect', inspected: IOSRecoveryOperation | null = null): Promise<void> {
    this.syncProject();
    if (this.recoveryReason(action, inspected) || !this.state.project) return;
    const recovery: IOSRecoveryIntent = action === 'inspect' ? { action } : { action, session: inspected!.report![action]!.session! };
    const request = copyIOSArchiveRequest('prepare_ios_archive', { projectId: this.state.project.projectId, recovery }) as PrepareIOSArchive | null;
    if (!request) { this.fail({ code: 'ios_archive_invalid' }, true); return; }
    await this.prepareRequest(request);
  }
  private async prepareRequest(request: PrepareIOSArchive): Promise<void> {
    const project = this.state.project;
    if (!this.observer || !project) return;
    const context: IOSArchiveContext = 'recovery' in request ? { ...request, platform: 'ios', operation: 'ios-local-recovery' } :
      { ...request, platform: 'ios', operation: request.signing ? 'ios-signed-export' : 'ios-unsigned-archive' };
    const now = this.now();
    if (!Number.isFinite(now) || now < 0 || !Number.isFinite(now + IOS_ARCHIVE_CONSENT_MS)) { this.fail({ code: 'ios_archive_invalid' }, true); return; }
    const counters = this.advance('requestGeneration'); if (counters.generationLost) { this.retire(counters); return; }
    const observer = this.observer;
    const binding: IOSArchiveBinding = freeze({ context, selection: context.operation === 'ios-local-recovery' ? null : project.selection,
      observationGeneration: project.observationGeneration, versionObservation: context.operation === 'ios-local-recovery' ? null : project.versionObservation, connectionGeneration: this.state.connectionGeneration,
      selectionGeneration: this.state.selectionGeneration, contextGeneration: this.state.contextGeneration, requestGeneration: counters.requestGeneration! });
    const attempt: Attempt = { observer, binding, previous: observer.status?.operation ? id(observer.status.operation) : null,
      after: observer.status?.statusRevision ?? 0, identity: null, prepareSent: false, prepareReply: false, deadline: now + IOS_ARCHIVE_CONSENT_MS,
      startSent: false, startAfter: 0, retired: false, settled: false };
    this.attempt = attempt; this.cancelClaim = null;
    this.update({ ...counters, consent: null, pending: 'prepare', originalUnconfirmed: false, historical: true, cancelClaimed: null, error: null });
    this.syncProject(); // Synchronous subscribers can replace either observation.
    if (!this.matches(attempt) || this.commonReason(context.operation)) { attempt.retired = true; attempt.settled = true; this.update({ pending: null }); return; }
    attempt.prepareSent = true; this.update({ originalUnconfirmed: true }); this.syncProject();
    if (!this.matches(attempt) || this.commonReason(context.operation)) {
      attempt.prepareSent = false; attempt.retired = true; attempt.settled = true; this.update({ pending: null, originalUnconfirmed: false }); return;
    }
    try {
      const value = await observer.api.prepareIOSArchive(request);
      if (!observer.active || this.attempt !== attempt) return;
      this.syncProject();
      const status = parseIOSArchiveStatus(value), op = status?.operation;
      if (!status || !op || !this.originCandidate(attempt, status) || ['starting', 'running'].includes(op.phase) || op.outcome === 'complete') {
        this.fail({ code: 'ios_archive_protocol' }, true); return;
      }
      attempt.identity = id(op); attempt.prepareReply = true;
      if (!this.receive(observer, status)) return;
      this.reconcile(observer); this.update({ pending: null, originalUnconfirmed: false });
      const current = observer.status?.operation;
      if (this.matches(attempt) && !this.commonReason(context.operation) && current?.phase === 'awaiting-consent' && current.intentUsable &&
          sameIOSArchiveIdentity(current, attempt.identity) && this.now() < attempt.deadline) {
        this.update({ consent: { ...id(op), binding, acknowledged: false, deadline: attempt.deadline } }); this.armExpiry();
      } else { attempt.retired = true; this.stopOriginal(); }
    } catch (error) {
      if (observer.active && this.attempt === attempt) {
        const safe = iosArchiveError(error);
        if (['ios_archive_invalid', 'ios_archive_unavailable', 'ios_archive_busy', 'ios_archive_signing_inputs'].includes(safe.code) &&
            !attempt.identity && (!observer.status || !this.originCandidate(attempt, observer.status))) {
          attempt.retired = true; attempt.settled = true; this.update({ pending: null, originalUnconfirmed: false, consent: null, error: safe });
        } else this.fail(error, safe.code !== 'ios_archive_protocol');
      }
    }
  }
  setAcknowledged(operationId: string, ownerGeneration: string, acknowledged: boolean): void {
    this.syncProject(); this.expireConsent();
    const consent = this.state.consent, attempt = this.attempt;
    if (!consent || !attempt || !this.matches(attempt) || this.commonReason(attempt.binding.context.operation) || !sameIOSArchiveIdentity(consent, { operationId, ownerGeneration }) || typeof acknowledged !== 'boolean') return;
    this.update({ consent: { ...consent, acknowledged } });
  }
  async start(operationId: string, ownerGeneration: string): Promise<void> {
    this.syncProject(); this.expireConsent();
    const attempt = this.attempt, consent = this.state.consent;
    if (!attempt || !consent || !sameIOSArchiveIdentity(consent, { operationId, ownerGeneration }) || this.startReason()) return;
    attempt.startSent = true; attempt.startAfter = attempt.observer.status?.statusRevision ?? 0; this.clearTimer();
    this.update({ consent: null, pending: 'start', originalUnconfirmed: true, historical: false, error: null }); this.syncProject();
    if (!this.matches(attempt) || this.commonReason(attempt.binding.context.operation)) { this.retire(); return; }
    try {
      const context = attempt.binding.context;
      const request: StartIOSArchive = context.operation === 'ios-local-recovery' ? { operationId, ownerGeneration, consentVersion: IOS_RECOVERY_CONSENT,
        ...(context.recovery.action === 'inspect' ? {} : { confirmation: context.recovery.action === 'account' ? IOS_ACCOUNT_RECOVERY_CONFIRMATION : IOS_PROJECT_RECOVERY_CONFIRMATION }) } :
        { operationId, ownerGeneration, consentVersion: context.operation === 'ios-signed-export' ? IOS_SIGNED_ARCHIVE_CONSENT : IOS_ARCHIVE_CONSENT };
      const value = await attempt.observer.api.startIOSArchive(request);
      if (!attempt.observer.active || this.attempt !== attempt) return;
      const status = parseIOSArchiveStatus(value);
      if (!status?.operation || !sameIOSArchiveIdentity(status.operation, attempt.identity) || status.operation.phase === 'awaiting-consent') {
        this.fail({ code: 'ios_archive_protocol' }, true); return;
      }
      this.receive(attempt.observer, status);
    } catch (error) { if (attempt.observer.active && this.attempt === attempt && !attempt.settled) this.fail(error); }
  }
  canCancel(): boolean {
    const observer = this.observer, op = observer?.status?.operation;
    return !this.disposed && !!observer?.active && !!op && op.phase !== 'terminal' && !sameIOSArchiveIdentity(this.state.cancelClaimed, op);
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
  private stop(observer: Observer, identity: IOSArchiveIdentity): boolean {
    if (!observer.active || sameIOSArchiveIdentity(this.cancelClaim, identity)) return false;
    this.cancelClaim = id(identity); this.update({ cancelClaimed: id(identity), consent: null });
    void (async () => {
      try {
        const value = await observer.api.cancelIOSArchive(identity.operationId, identity.ownerGeneration);
        if (!observer.active) return;
        const status = parseIOSArchiveStatus(value);
        if (!status?.operation || !sameIOSArchiveIdentity(status.operation, identity)) { this.fail({ code: 'ios_archive_protocol' }, true); return; }
        this.receive(observer, status);
      } catch (error) { if (observer.active) this.fail(error); }
    })();
    return true;
  }
  dispose(): void {
    if (this.disposed) return;
    this.retire(); this.disposed = true; this.listeners.clear();
    if (this.observer && !this.needsOriginal(this.observer)) this.detach(this.observer);
    // Sent work retains a retirement-only original observer until actual native
    // terminal settlement. Page navigation must call setVisible, not dispose.
  }
}

export const iosArchiveHelp: HelpContent = {
  label: 'Local iOS archive or signed IPA export', requiredness: 'optional', requiredWhen: 'When preparing a local iOS artifact, without publishing or promoting a release.',
  what: 'Uses the original installed core and full Xcode with an explicit mode: an unsigned archive with structural checks, or a separately admitted signed IPA export with exact session inputs and paired validation.',
  why: 'Keep build completion, signing and local artifact validation separate from authenticated source provenance and Store release approval.',
  where: 'Install full Xcode in Applications and complete its normal first-launch setup. Choose your app’s Xcode project or workspace and shared scheme in the project configuration.',
  format: 'The initial profile is Apple-silicon macOS with the separately qualified installed runtime and protected full-Xcode/SDK layout. Command Line Tools alone are insufficient; Linux and Windows cannot perform this action.',
  failure: 'A disabled native gate is not a diagnosis that Xcode is missing. No runtime fallback, SDK download, license acceptance, provisioning download or Store mutation is attempted. Unsigned qualification cannot enable signing.',
};
export const iosArchiveInputHelp: HelpContent = {
  label: 'Saved iOS archive inputs', requiredness: 'required', requiredWhen: 'Before every new archive review and after any save, refresh, version observation or selection change.',
  what: 'Pairs the current saved configuration snapshot with the complete saved-version observation, including byte counts, digests, source, name and build.',
  why: 'A matching version label or an old editor baseline alone cannot identify which saved files you reviewed.',
  where: 'Refresh saved configuration, then click Read saved version. The app uses the version source already selected by that configuration.',
  format: 'Unsaved drafts are neither saved nor discarded and are not archive inputs. Signed export additionally requires the credential context to match the saved configuration, so a dirty draft blocks it. This review never accepts an arbitrary version-file path or Xcode command.',
  failure: 'Pending, stale, failed or changed observations retire consent. Refresh and read again after original cleanup settles. External changes remain possible; this is not an atomic source checkout.',
};
export const iosArchiveSelectionHelp: HelpContent = {
  label: 'Xcode container, scheme and build configuration', requiredness: 'required', requiredWhen: 'Before reviewing an iOS archive.',
  what: 'The container is your .xcworkspace or .xcodeproj; the shared scheme selects the app target and the configuration selects its build settings.',
  why: 'The toolkit must build the intended app rather than guessing between multiple projects, targets or schemes.',
  where: 'Use the Configuration screen’s iOS project/workspace picker when available. Find the scheme in Xcode under Product → Scheme → Manage Schemes and enable Shared. Build configurations are in the project’s Info settings.',
  format: 'Save ios.workspace or ios.project relative to the selected source project, ios.scheme, ios.bundleId and optionally ios.archiveConfiguration (default Release). A saved workspace takes precedence over a project.',
  failure: 'Missing or renamed containers and unshared/misspelled schemes can prevent archiving. This action does not rename files, guess another scheme or modify Xcode settings.',
};
export const iosArchiveOutputHelp: HelpContent = {
  label: 'Retained archive, optional IPA and symbols', requiredness: 'conditional', requiredWhen: 'When interpreting a completed local result or an incomplete retained output.',
  what: 'Retains archive.xcarchive and, only for signed export, the original exported IPA under this operation’s private project directory. Inspection snapshots and task work are disposed separately.',
  why: 'The original output remains available without mistaking its limited inspection for a signed or installable release.',
  where: 'The completed original Status displays its relative location. Set ios.symbols.policy in Configuration: disabled does not require dSYMs; retain or required applies the core’s existing archive symbols checks.',
  format: 'Unsigned results cover archive structure only. Signed results also contain exact IPA/archive/native-symbol correspondence counts and core signer/profile/entitlement findings. Neither result authenticates source provenance. A required symbols-upload policy remains BLOCKED: this operation never runs an uploader.',
  failure: 'Failed/cancelled archives may retain incomplete output. A displayed location is historical data, not current-file custody or permission to delete, adopt, upload or publish it.',
};
export const iosArchiveCancelHelp: HelpContent = {
  label: 'Cancel and original archive cleanup', requiredness: 'conditional', requiredWhen: 'When stopping a run or recovering a lost acknowledgement.',
  what: 'Requests STOP from the original owner and retains Status while its exact workers, files and cleanup settle.',
  why: 'A closed page, a rejected request or an elapsed timeout alone does not prove project code has stopped.',
  where: 'Use Cancel this iOS archive or Check archive status; those controls stay available outside Releases while the original owner remains active.',
  format: 'Cancel is one request, not rollback or permission to rerun. Project preparation/build phases can modify files, use your account and access the network. Only run a project you trust.',
  failure: 'Unknown cleanup remains blocked. Reconnecting, switching projects or checking Status cannot replace the original owner, extend the deadline or rearm consent.',
};
export const iosSigningHelp: HelpContent = {
  label: 'Prepare the Apple signing policy and session inputs', requiredness: 'conditional', requiredWhen: 'Before choosing Sign and export IPA for a trusted project on a separately admitted Apple-silicon Mac.',
  what: 'The saved public policy identifies the Apple team and reviewed distribution certificate; private P12/password/profile records are separately selected, kept and assigned in the session.',
  why: 'A P12 container or CMS envelope alone proves neither password correctness nor Apple authenticity, expiry, identity or permission to sign this app. Core validates those facts during the owned signed operation.',
  where: 'Find the 10-character Team ID in the authorized Apple Developer membership details. Obtain the public Apple Distribution certificate SHA-256 fingerprint from the signing-key owner and review it independently. That owner exports the existing certificate and private key as P12 with a password. Obtain the matching Apple-issued App Store profile from Certificates, Identifiers & Profiles.',
  format: 'Save ios.teamId and ios.distributionCertificateSha256 (64 hexadecimal digits, optionally colon-separated) in Project settings. Save the intended bundle ID and manual-signing Xcode selection. In Credentials use iOS / candidate / signing, select the private .p12/.pfx and .mobileprovision originals outside projects, enter the original password write-only, then assess → keep → assign. Reassign any required Firebase/project-read input in that same context. No ASC P8 or Store login is required.',
  failure: 'Ask the authorized owner to correct a wrong password, expired/revoked certificate, untrusted/expired profile or team/bundle/signer mismatch; never replace an identity or modify a profile just to pass assessment. One primary App Store profile is supported; extension/profile mismatches remain unsupported. Review incomplete retained outputs and normal recovery status after actual owner settlement. No automatic rerun, re-sign, upload or cleanup reset occurs.',
};
export const iosRecoveryHelp: HelpContent = {
  label: 'Ordinary exact-session iOS recovery', requiredness: 'conditional', requiredWhen: 'After original operations settle and retained account signing or project build-input state needs inspection.',
  what: 'The same iOS owner performs a bounded core inspection, then permits separately confirmed ordinary recovery only for the exact session it actually inspected. Account and project actions remain distinct.',
  why: 'A pasted session ID, timeout, copied success receipt or user statement cannot prove original worker finality or authorize a different recovery target.',
  where: 'Choose the original registered source project and open Recovery. Review and start Inspect local state. Read account state before project state, then review an offered ordinary action and explicitly confirm the relevant account or project is idle.',
  format: 'No configuration, version, Xcode build, private material or arbitrary path is supplied. Inspection and restoration use the existing core predicates and native owner. Busy, absent, conflict and manual-required are distinct observations. A complete inspection may correctly report pending state; it does not mean restoration occurred.',
  failure: 'A live Unknown stays owned and cannot be replaced by recovery. Preserve conflicts and wait for busy originals. Exceptional interactive manual recheck is not supported in Desktop: no fake terminal confirmation, lock release/reacquire, forced keychain/profile reset or shared-daemon stop is offered. Cancellation never rolls back completed restoration.',
};
