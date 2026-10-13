// App-retained two-string draft and observer. The SAME native EditOwner owns
// all leases, one-use plans, processes, journals, cancellation and finality.
import { savedTextRecoveryApplyBinding, savedTextRecoveryPreparedMatches, savedTextRecoverySettled, savedTextRecoverySucceeded } from './savedTextRecovery.ts';
import type { SavedTextRecoveryApplyBinding, SavedTextRecoveryAttempt, SavedTextRecoveryContext, SavedTextRecoveryProjection } from './savedTextRecovery.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { normalVersionEditResult, parseVersionEditGuide, parseVersionEditStatus, sameVersionData as same,
  versionEditError, versionEditRequestFits, versionProjectionProgress, versionStatusProgress, versionValuesBounded,
  viewMatchesVersionCheckout } from './releaseVersionEdit.ts';
import type { VersionBaseline, VersionCheckout, VersionEditGuide, NormalVersionEditProjection, VersionEditProjection, VersionEditStatus, VersionIntent, VersionValues } from './releaseVersionEdit.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { ApiError, BridgeMode, DesktopApi } from './types.ts';

export interface VersionDraft {
  projectId: string; projectName: string; revision: number; baselineGeneration: number;
  original: VersionCheckout; values: VersionValues; stale: boolean; error: ApiError | null;
  // Exact submitted outcome remains independent of later drafts/navigation.
  outcome: VersionEditProjection | null;
}
interface ContextBinding {
  projectId: string; configRevision: number; configBaselineGeneration: number; configObservationGeneration: number;
  contextGeneration: number; connectionGeneration: number; windowGeneration: string;
  startStatusRevision: number; previousTerminalId: string | null; reload: boolean;
  expectedOriginal: VersionCheckout | null;
}
interface Submission {
  expectedBaseline: VersionBaseline; intent: VersionIntent; values: VersionValues; draftRevision: number; baselineGeneration: number;
}
export interface VersionAttempt {
  binding: ContextBinding; submission: Submission | null; sessionId: string | null; projection: NormalVersionEditProjection | null; projectionRevision: number;
  openAdopted: boolean; prepareClaimed: boolean; applyClaimed: boolean; submittedPlanToken: string | null;
  closeRequested: boolean; closeClaimed: boolean; invalidated: boolean; handled: boolean; outcomeNotified: boolean; outcomeFingerprint: string | null;
}
interface OwnerState {
  mode: BridgeMode; listening: boolean; initialized: boolean; readPending: boolean; status: VersionEditStatus | null; buffered: VersionEditStatus | null;
  observationIssue: 'bridge' | 'protocol' | null; integrityFailed: boolean; generationLost: boolean; nativeBlocked: boolean;
  unknownEvidence: VersionEditProjection | null; recoveryProjects: readonly string[]; attempt: VersionAttempt | null;
  recovery: SavedTextRecoveryAttempt<'release_version'> | null;
}
export interface VersionEditState {
  mode: BridgeMode; projectId: string | null; visible: boolean; selectionPending: boolean; contextGeneration: number; connectionGeneration: number;
  entries: Readonly<Record<string, VersionDraft>>; help: VersionEditGuide | null; error: ApiError | null; edit: OwnerState;
}
export interface VersionApplyBinding { sessionId: string; planToken: string; draftRevision: number; baselineGeneration: number }
export interface VersionResetBinding { projectId: string; revision: number; baselineGeneration: number; contextGeneration: number }
interface Context {
  selectedProject: () => ProjectSession | null;
  project: (projectId: string) => ProjectSession | null;
  otherEditReason: (projectId: string) => string | null;
  // Includes original passive queries, pickers, diagnostics and saved commands.
  otherOperationReason: () => string | null;
  onSaveBoundary: (projectId: string) => void;
  now?: () => number;
}
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function settled(attempt: VersionAttempt | null): boolean { return !attempt || attempt.projection?.phase === 'final' && attempt.projection.nativeFinality === 'settled'; }
function usable(state: OwnerState): boolean {
  return state.mode === 'native' && state.listening && state.initialized && state.status?.capability.available === true &&
    !state.observationIssue && !state.integrityFailed && !state.generationLost && !state.nativeBlocked;
}
export function versionDraftDirty(entry: VersionDraft): boolean {
  return !same(entry.values, entry.original.values ?? { name: '', build: '' });
}
export function versionProjectDirty(state: VersionEditState, projectId?: string): boolean {
  return Object.values(state.entries).some((entry) => (projectId === undefined || entry.projectId === projectId) && versionDraftDirty(entry));
}
export function versionOwnerReason(state: VersionEditState, projectId: string): string | null {
  const owner = state.edit;
  if (owner.nativeBlocked || owner.integrityFailed || owner.generationLost || owner.observationIssue) return 'Saved-version edit ownership is unverified. Keep its original operation and do not retry.';
  if (owner.status?.active || !settled(owner.attempt) || owner.attempt && !owner.attempt.handled ||
      !savedTextRecoverySettled(owner.recovery) || owner.recovery && !owner.recovery.handled) return 'A saved-version edit is still owned. Close or finish that original session before another operation.';
  if (owner.recoveryProjects.includes(projectId)) return 'This project needs separately authorized saved-version recovery. No other edit can clear that journal.';
  return null;
}
export function versionRetainsDraft(state: VersionEditState, projectId: string): boolean {
  return state.edit.attempt?.binding.projectId === projectId && (!settled(state.edit.attempt) || state.edit.nativeBlocked || state.edit.integrityFailed || state.edit.observationIssue !== null) ||
    state.edit.recovery?.binding.projectId === projectId && (!savedTextRecoverySettled(state.edit.recovery) || state.edit.nativeBlocked || state.edit.integrityFailed || state.edit.observationIssue !== null) ||
    state.edit.status?.active?.projectId === projectId || state.edit.unknownEvidence?.projectId === projectId;
}
export function versionPreparedMatches(attempt: VersionAttempt): boolean {
  const owner = attempt.projection, prepared = owner?.prepared, submission = attempt.submission;
  return Boolean(owner?.checkout && prepared && submission && owner.domain === 'release_version' && owner.projectId === attempt.binding.projectId &&
    owner.ownerGeneration === attempt.binding.windowGeneration && owner.sessionId === attempt.sessionId &&
    prepared.revision === owner.checkout.revision && prepared.draftRevision === submission.draftRevision && prepared.baselineGeneration === submission.baselineGeneration &&
    same(owner.checkout.baseline, submission.expectedBaseline) && same(prepared.view.values, submission.values) && prepared.view.intent === submission.intent &&
    viewMatchesVersionCheckout(prepared.view, owner.checkout));
}
export function currentVersionApplyBinding(state: VersionEditState): VersionApplyBinding | null {
  const edit = state.edit, attempt = edit.attempt, owner = attempt?.projection;
  if (!usable(edit) || !attempt?.submission || !owner?.prepared || !attempt.prepareClaimed || attempt.applyClaimed || attempt.closeRequested ||
      attempt.invalidated || attempt.handled || owner.phase !== 'reviewing' || owner.nativeReason !== 'none' || owner.nativeFinality !== 'pending' ||
      owner.reviewRemainingMs === 0 || owner.applySubmitted || !versionPreparedMatches(attempt) || edit.status?.active?.sessionId !== owner.sessionId ||
      owner.ownerGeneration !== edit.status.windowGeneration) return null;
  return { sessionId: owner.sessionId, planToken: owner.prepared.planToken, draftRevision: attempt.submission.draftRevision, baselineGeneration: attempt.submission.baselineGeneration };
}
export class ReleaseVersionEditController {
  private state: VersionEditState = freeze<VersionEditState>({
    mode: 'unavailable', projectId: null, visible: true, selectionPending: false, contextGeneration: 0, connectionGeneration: 0, entries: {}, help: null, error: null,
    edit: { mode: 'unavailable', listening: false, initialized: false, readPending: false, status: null, buffered: null, observationIssue: null,
      integrityFailed: false, generationLost: false, nativeBlocked: false, unknownEvidence: null, recoveryProjects: [], attempt: null, recovery: null },
  });
  private api: DesktopApi | null = null;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private fingerprint = '';
  private processing = false;
  private processAgain = false;
  private disposed = false;
  private deadline: { sessionId: string; at: number } | null = null;
  // One private, context-bound completion; never an owner-generation ordering.
  private recoveryCompletion: { binding: SavedTextRecoveryContext; statusRevision: number } | null = null;
  private readonly context: Context;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): VersionEditState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(next: VersionEditState): void {
    if (this.disposed || next === this.state) return;
    this.state = freeze(next);
    if (this.recoveryCompletion && (!this.recoveryContextMatches(this.recoveryCompletion.binding) ||
        this.state.edit.status?.windowGeneration !== this.recoveryCompletion.binding.windowGeneration ||
        !usable(this.state.edit) || this.state.edit.unknownEvidence)) this.recoveryCompletion = null;
    for (const listener of this.listeners) listener();
  }
  private edit(next: OwnerState): void { this.publish({ ...this.state, edit: next }); }
  private attempt(patch: Partial<VersionAttempt>): void {
    if (this.state.edit.attempt) this.edit({ ...this.state.edit, attempt: { ...this.state.edit.attempt, ...patch } });
  }
  private put(entry: VersionDraft): void {
    this.publish({ ...this.state, entries: { ...this.state.entries, [entry.projectId]: entry } });
  }
  selectedEntry(): VersionDraft | null { return this.state.projectId ? this.state.entries[this.state.projectId] ?? null : null; }
  setHelp(value: unknown): void {
    this.publish({ ...this.state, help: parseVersionEditGuide(value) });
    if (!this.state.help) this.invalidate();
  }
  private now(): number { return this.context.now?.() ?? performance.now(); }
  remainingReviewMs(): number {
    const owner = this.state.edit.attempt?.projection;
    return owner && this.deadline?.sessionId === owner.sessionId ? Math.max(0, Math.min(owner.reviewRemainingMs, this.deadline.at - this.now())) : 0;
  }
  private invalidate(): void {
    this.recoveryCompletion = null;
    const attempt = this.state.edit.attempt;
    this.publish({ ...this.state, contextGeneration: Math.min(U32_MAX, this.state.contextGeneration + 1),
      edit: { ...this.state.edit, attempt: attempt && !attempt.applyClaimed && !attempt.handled && !settled(attempt) ?
        { ...attempt, invalidated: true, closeRequested: true } : attempt } });
    this.retireRecovery(true); this.process();
  }
  // These calls precede reducer/effect early returns, including failed refresh,
  // switch-away-back, malformed config actions and unchanged Save outcomes.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (action.type === 'select' || action.type === 'switch') { this.selectionIntent(); return; }
    if (action.projectId !== this.state.projectId && action.projectId !== this.state.edit.attempt?.binding.projectId) return;
    if (['snapshot-start', 'snapshot-done', 'snapshot-failed', 'new-draft', 'edit', 'remove-forbidden', 'undo-removal', 'forget-removal',
      'reset', 'adopt-suggestion', 'config-save-intent', 'config-save-final', 'config-save-recovery'].includes(action.type)) this.invalidate();
  }
  selectionIntent(): void { if (!this.disposed) this.invalidate(); }
  snapshotIntent(projectId: string): void { if (projectId === this.state.projectId || projectId === this.state.edit.attempt?.binding.projectId) this.invalidate(); }
  shutdownIntent(): void { this.invalidate(); }
  setSelectionPending(value: boolean): void {
    if (this.disposed || value === this.state.selectionPending) return;
    this.publish({ ...this.state, selectionPending: value }); this.invalidate();
  }
  setVisible(value: boolean): void {
    if (this.disposed || value === this.state.visible) return;
    this.publish({ ...this.state, visible: value }); this.invalidate();
  }
  syncProject = (): void => {
    const project = this.context.selectedProject();
    const fingerprint = JSON.stringify([project?.project.id, project?.revision, project?.baselineGeneration, project?.observationGeneration,
      project?.snapshotRequest, project?.sourceChanged, project?.saveRecoveryRequired]);
    if (fingerprint !== this.fingerprint) {
      this.fingerprint = fingerprint; this.invalidate();
      this.publish({ ...this.state, projectId: project?.project.id ?? null });
    }
    this.process();
  };
  private configReason(): string | null {
    const project = this.context.selectedProject();
    if (!project) return 'Choose a native project, then save its release/mobile-release.json in Settings.';
    if (!this.state.visible || this.state.selectionPending) return 'Return to the Dashboard and finish project selection before opening version editing.';
    if (project.saveRecoveryRequired) return 'Configuration recovery is required. Version editing cannot clear it.';
    if (project.snapshotRequest !== null || project.sourceChanged) return 'Finish the configuration observation and reconcile saved changes in Settings first.';
    if (!project.baseline || project.snapshot?.config.state !== 'format-valid' && project.lastSave?.resultingBaselineGeneration !== project.baselineGeneration)
      return 'Save a format-valid project configuration in Settings before opening the version editor.';
    if ([this.state.contextGeneration, this.state.connectionGeneration, project.revision, project.baselineGeneration, project.observationGeneration].some((n) => !isU32(n) || n >= U32_MAX))
      return 'An original binding counter is exhausted; no generation will be reused.';
    return null; // Unsaved settings are permitted but never applied or inherited.
  }
  private configuredOwnerReason(): string | null {
    const edit = this.state.edit;
    if (this.state.mode !== 'native' || edit.mode !== 'native') return 'Version Create/Edit needs the separately qualified native writer. Browser preview never loads or saves files.';
    if (edit.integrityFailed || edit.generationLost || edit.nativeBlocked || edit.observationIssue) return 'Original version edit authority or cleanup is unverified. Check the original status; do not retry.';
    if (!edit.listening || !edit.initialized || !edit.status) return 'Loading the separate version-writer capability and original status…';
    if (!edit.status.capability.available) return edit.status.capability.reason === 'other_edit_active' ?
      'Another edit domain owns the shared service. Finish or close that original edit first.' :
      'Version saving is unavailable in this build. It requires a supported, source-bound native writer; this status does not authorize recovery.';
    if (edit.status.statusRevision >= U32_MAX) return 'The original native status counter is exhausted.';
    if (!this.state.help) return 'Load the compatible saved-version help catalogue before editing.';
    return this.configReason() ?? this.context.otherEditReason(this.state.projectId ?? '') ?? this.context.otherOperationReason();
  }
  openReason(): string | null {
    return this.configuredOwnerReason() ?? versionOwnerReason(this.state, this.state.projectId ?? '') ??
      (!this.selectedEntry() && Object.keys(this.state.entries).length >= 16 ? 'Sixteen in-memory version drafts are already retained. No draft will be evicted automatically.' : null);
  }
  private sameContext(binding: ContextBinding, selected = true): boolean {
    const project = this.context.project(binding.projectId);
    return !this.disposed && !!project && project.revision === binding.configRevision && project.baselineGeneration === binding.configBaselineGeneration &&
      project.observationGeneration === binding.configObservationGeneration && this.state.connectionGeneration === binding.connectionGeneration &&
      (!selected || this.state.contextGeneration === binding.contextGeneration && this.state.projectId === binding.projectId && this.state.visible && !this.state.selectionPending);
  }
  private submission(entry: VersionDraft): Submission {
    return freeze({ expectedBaseline: structuredClone(entry.original.baseline), intent: entry.original.baseline.savedVersion.state === 'absent' ? 'create' : 'edit',
      values: structuredClone(entry.values), draftRevision: entry.revision, baselineGeneration: entry.baselineGeneration });
  }
  private matchesSubmission(attempt: VersionAttempt): boolean {
    const entry = this.state.entries[attempt.binding.projectId], input = attempt.submission;
    return !!entry && !!input && entry.revision === input.draftRevision && entry.baselineGeneration === input.baselineGeneration &&
      same(entry.values, input.values) && same(entry.original.baseline, input.expectedBaseline) && !entry.stale;
  }
  open(): boolean { return this.start(false, false); }
  private start(review: boolean, reload: boolean): boolean {
    if (this.disposed || !this.api || this.openReason()) return false;
    const project = this.context.selectedProject(), status = this.state.edit.status, entry = this.selectedEntry();
    if (!project || !status || review && (!entry || entry.stale || !versionValuesBounded(entry.values))) return false;
    const binding = freeze<ContextBinding>({ projectId: project.project.id, configRevision: project.revision, configBaselineGeneration: project.baselineGeneration,
      configObservationGeneration: project.observationGeneration, contextGeneration: this.state.contextGeneration, connectionGeneration: this.state.connectionGeneration,
      windowGeneration: status.windowGeneration, startStatusRevision: status.statusRevision, previousTerminalId: status.lastTerminal?.sessionId ?? null,
      reload, expectedOriginal: reload ? null : entry?.original ?? null });
    const submission = review && entry ? this.submission(entry) : null;
    this.publish({ ...this.state, error: null, edit: { ...this.state.edit, attempt: { binding, submission, sessionId: null, projection: null,
      projectionRevision: status.statusRevision, openAdopted: false, prepareClaimed: false, applyClaimed: false, submittedPlanToken: null,
      closeRequested: false, closeClaimed: false, invalidated: false, handled: false, outcomeNotified: false, outcomeFingerprint: null } } });
    if (review) this.context.onSaveBoundary(project.project.id);
    if (this.state.edit.attempt?.binding !== binding || this.state.edit.attempt.closeRequested) return false;
    void this.command('open', binding, () => this.api!.openReleaseVersionEdit({ projectId: binding.projectId }));
    return true;
  }
  editField(id: keyof VersionValues, value: string): boolean {
    const entry = this.selectedEntry();
    if (this.disposed || !entry || entry.revision >= U32_MAX - 1 || typeof value !== 'string' || !['name', 'build'].includes(id)) return false;
    if (value.length > (id === 'name' ? 64 : 10) || !/^[\x00-\x7f]*(?![\s\S])/.test(value)) {
      this.put({ ...entry, error: versionEditError({ code: 'VersionEditInvalid' }) }); return false;
    }
    if (entry.values[id] === value) return false;
    const attempt = this.state.edit.attempt;
    // Reload consent covers the confirmed draft, never edits made while its Open is pending.
    if (attempt && !attempt.applyClaimed && (attempt.submission || attempt.binding.reload && !attempt.openAdopted)) this.invalidate();
    this.put({ ...entry, revision: entry.revision + 1, values: { ...entry.values, [id]: value }, error: null });
    this.process(); return true;
  }
  reviewReason(): string | null {
    const reason = this.configuredOwnerReason(); if (reason) return reason;
    const entry = this.selectedEntry(), attempt = this.state.edit.attempt;
    if (!entry) return 'Open the saved version first. Only real observed absence permits Create.';
    if (entry.stale) return 'The baseline is stale. Close, then explicitly reload saved values and discard the earlier draft.';
    if (!versionValuesBounded(entry.values)) return 'Enter a marketing-version string (up to 64 ASCII characters) and a build string (up to 10 digits). Core validates their actual format.';
    if (attempt && !settled(attempt)) {
      if (!attempt.openAdopted || attempt.projection?.phase !== 'editing' || attempt.submission || attempt.closeRequested || attempt.invalidated || !this.sameContext(attempt.binding))
        return 'Finish or close the original version operation before another review.';
      return null;
    }
    return this.openReason();
  }
  review(): boolean {
    if (!this.api || this.reviewReason()) return false;
    const entry = this.selectedEntry(), attempt = this.state.edit.attempt;
    if (!entry) return false;
    if (!attempt || settled(attempt)) return this.start(true, false);
    this.attempt({ submission: this.submission(entry) });
    this.context.onSaveBoundary(entry.projectId); this.process(); return true;
  }
  canApply(binding?: VersionApplyBinding): boolean {
    const current = currentVersionApplyBinding(this.state), attempt = this.state.edit.attempt;
    return !!current && !!attempt && this.remainingReviewMs() > 0 && this.sameContext(attempt.binding) && this.matchesSubmission(attempt) &&
      !this.configReason() && !this.context.otherEditReason(attempt.binding.projectId) && !this.context.otherOperationReason() && (!binding || same(current, binding));
  }
  apply(binding: VersionApplyBinding): boolean {
    if (!this.api || !this.canApply(binding)) return false;
    const original = this.state.edit.attempt!.binding;
    this.attempt({ applyClaimed: true, submittedPlanToken: binding.planToken });
    this.context.onSaveBoundary(original.projectId);
    if (this.state.edit.attempt?.binding === original && !this.state.edit.attempt.closeRequested)
      void this.command('apply', original, () => this.api!.applyReleaseVersionEdit(binding.sessionId, binding.planToken));
    return true;
  }
  requestClose(): void {
    const attempt = this.state.edit.attempt;
    if (!attempt || settled(attempt) || attempt.handled || attempt.closeRequested) return;
    this.attempt({ closeRequested: true }); this.process();
  }
  resetBinding(): VersionResetBinding | null {
    const entry = this.selectedEntry();
    return entry ? { projectId: entry.projectId, revision: entry.revision, baselineGeneration: entry.baselineGeneration, contextGeneration: this.state.contextGeneration } : null;
  }
  discard(binding: VersionResetBinding): boolean {
    const entry = this.selectedEntry();
    if (!entry || !same(binding, this.resetBinding()) || versionRetainsDraft(this.state, entry.projectId) || entry.revision >= U32_MAX - 1) return false;
    this.put({ ...entry, revision: entry.revision + 1, values: structuredClone(entry.original.values ?? { name: '', build: '' }), error: null });
    this.invalidate(); return true;
  }
  reload(binding: VersionResetBinding): boolean {
    if (!same(binding, this.resetBinding())) return false;
    return this.start(false, true); // Only this explicit discard-confirmed branch rebases.
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.invalidate();
    const held = !settled(this.state.edit.attempt) || !savedTextRecoverySettled(this.state.edit.recovery) || !!this.state.edit.status?.active || this.state.edit.nativeBlocked || this.state.edit.integrityFailed;
    this.publish({ ...this.state, mode: 'unavailable', help: null, connectionGeneration: Math.min(U32_MAX, this.state.connectionGeneration + 1),
      edit: { ...this.state.edit, nativeBlocked: this.state.edit.nativeBlocked || held } });
    if (held) return; // Retain the ORIGINAL API/subscription for its own finality.
    try { this.unlisten?.(); } catch { /* No native settlement inferred. */ }
    this.unlisten = null; this.api = null; this.reading = null;
    this.edit({ ...this.state.edit, mode: 'unavailable', listening: false, initialized: false, readPending: false, status: null, buffered: null });
  }
  async connect(api: DesktopApi): Promise<void> {
    if (this.disposed || this.api === api) return;
    if (this.api) this.beginConnection();
    if (this.api || this.state.edit.nativeBlocked || this.state.edit.integrityFailed || this.state.edit.generationLost) return;
    this.api = api; this.publish({ ...this.state, mode: api.mode, edit: { ...this.state.edit, mode: api.mode } });
    this.syncProject(); if (api.mode === 'native') await this.checkStatus();
  }
  async checkStatus(): Promise<void> {
    if (this.disposed || !this.api || this.api.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api;
    const work = Promise.resolve().then(async () => {
      try {
        if (!this.unlisten) {
          const unlisten = await api.subscribeReleaseVersionEdit((value) => { if (this.api === api) this.receive(value, 'event'); });
          if (this.disposed || this.api !== api) { unlisten(); return; }
          this.unlisten = unlisten; this.edit({ ...this.state.edit, listening: true });
        }
        if (!this.disposed && this.api === api) {
          const status = await api.releaseVersionEditStatus();
          if (this.api === api) this.receive(status, 'read');
        }
      } catch (error) {
        if (!this.disposed && this.api === api) this.observationFailed(versionEditError(error).code === 'VersionEditStatusInvalid');
      }
    });
    this.reading = work; this.edit({ ...this.state.edit, readPending: true });
    try { await work; } finally { if (this.reading === work) this.reading = null; }
  }
  private observationFailed(protocol: boolean): void {
    this.edit({ ...this.state.edit, readPending: false, integrityFailed: this.state.edit.integrityFailed || protocol,
      observationIssue: protocol || this.state.edit.integrityFailed ? 'protocol' : 'bridge' });
    if (protocol) this.invalidate();
    this.process();
  }
  private recoveryAttentionCovered(status: VersionEditStatus, owner: VersionEditProjection): boolean {
    const completed = this.recoveryCompletion, core = owner.coreOutcome;
    return completed !== null && this.recoveryContextMatches(completed.binding) && usable(this.state.edit) && !this.state.edit.unknownEvidence &&
      owner.domain === 'release_version' && owner.projectId === completed.binding.projectId && owner.ownerGeneration === completed.binding.windowGeneration &&
      status.windowGeneration === completed.binding.windowGeneration && status.statusRevision < completed.statusRevision &&
      owner.phase === 'final' && owner.nativeFinality === 'settled' && !owner.lateSettled &&
      core?.journal === 'recovery_required' && core.resources === 'settled' && core.effect !== 'unknown' && core.reason !== 'custody_unknown' &&
      owner.nativeReason !== 'cleanup_unknown' && status.capability.reason !== 'cleanup_unknown' &&
      [status.active, status.lastTerminal, this.state.edit.status?.active, this.state.edit.status?.lastTerminal].every((row) => !row || row.phase !== 'unknown' && row.nativeFinality !== 'unknown' &&
        !row.lateSettled && row.nativeReason !== 'cleanup_unknown' && (!row.coreOutcome ||
          row.coreOutcome.resources === 'settled' && row.coreOutcome.effect !== 'unknown' && row.coreOutcome.journal !== 'unknown' && row.coreOutcome.reason !== 'custody_unknown'));
  }
  private receive(value: unknown, source: 'read' | 'event' | 'reply'): void {
    if (this.disposed) return;
    const parsed = parseVersionEditStatus(value);
    if (!parsed) { this.observationFailed(true); return; }
    let status = freeze(structuredClone(parsed)); let edit = this.state.edit;
    for (const owner of [status.active, status.lastTerminal]) {
      if (owner && (owner.phase === 'unknown' || owner.nativeFinality === 'unknown')) edit = { ...edit, nativeBlocked: true, unknownEvidence: edit.unknownEvidence ?? owner };
      if (owner?.coreOutcome?.journal === 'recovery_required' && !this.recoveryAttentionCovered(status, owner) && !edit.recoveryProjects.includes(owner.projectId)) {
        if (edit.recoveryProjects.length >= 64) { this.observationFailed(true); return; }
        edit = { ...edit, recoveryProjects: [...edit.recoveryProjects, owner.projectId] };
      }
    }
    if (status.capability.reason === 'cleanup_unknown') edit = { ...edit, nativeBlocked: true };
    edit = { ...edit, readPending: source === 'read' ? false : edit.readPending };
    if (!edit.initialized && source !== 'read') {
      this.edit({ ...edit, buffered: !edit.buffered || status.statusRevision >= edit.buffered.statusRevision ? status : edit.buffered }); return;
    }
    if (!edit.initialized && edit.buffered) {
      if (edit.buffered.windowGeneration !== status.windowGeneration) edit = { ...edit, generationLost: true };
      else {
        const first = edit.buffered.statusRevision <= status.statusRevision ? edit.buffered : status;
        const next = first === status ? edit.buffered : status;
        if (!versionStatusProgress(first, next)) { this.observationFailed(true); return; }
        if (edit.buffered.statusRevision > status.statusRevision) status = edit.buffered;
      }
    }
    edit = { ...edit, generationLost: edit.generationLost || Boolean(edit.status && edit.status.windowGeneration !== status.windowGeneration) };
    let attempt = edit.attempt;
    if (attempt) {
      const retained = attempt;
      const owner = [status.active, status.lastTerminal].find((row): row is NormalVersionEditProjection => !!row && !row.recovery && row.projectId === retained.binding.projectId && row.ownerGeneration === retained.binding.windowGeneration &&
        (retained.sessionId ? row.sessionId === retained.sessionId : status.statusRevision > retained.binding.startStatusRevision && row.sessionId !== retained.binding.previousTerminalId));
      if (owner) {
        const older = status.statusRevision < attempt.projectionRevision;
        if (attempt.projection && !(older ? versionProjectionProgress(owner, attempt.projection) : versionProjectionProgress(attempt.projection, owner))) { this.observationFailed(true); return; }
        if (!older) {
          const projection = attempt.projection ? { ...owner, reviewRemainingMs: Math.min(attempt.projection.reviewRemainingMs, owner.reviewRemainingMs) } : owner;
          attempt = { ...attempt, sessionId: owner.sessionId, projectionRevision: status.statusRevision, projection };
          const at = this.now() + projection.reviewRemainingMs;
          if (!attempt.handled && !['final', 'unknown'].includes(projection.phase))
            this.deadline = { sessionId: owner.sessionId, at: this.deadline?.sessionId === owner.sessionId ? Math.min(this.deadline.at, at) : at };
        }
      }
    }
    let recovery = edit.recovery;
    if (recovery) {
      const retained = recovery;
      const owner = [status.active, status.lastTerminal].find((row): row is SavedTextRecoveryProjection<'release_version'> => !!row?.recovery &&
        row.projectId === retained.binding.projectId && row.ownerGeneration === retained.binding.windowGeneration &&
        (retained.sessionId ? row.sessionId === retained.sessionId : status.statusRevision > retained.binding.startStatusRevision && row.sessionId !== retained.binding.previousTerminalId));
      if (owner) {
        const older = status.statusRevision < recovery.projectionRevision;
        if (recovery.projection && !(older ? versionProjectionProgress(owner, recovery.projection) : versionProjectionProgress(recovery.projection, owner))) { this.observationFailed(true); return; }
        if (!older) {
          const projection = recovery.projection ? { ...owner, reviewRemainingMs: Math.min(recovery.projection.reviewRemainingMs, owner.reviewRemainingMs) } : owner;
          recovery = { ...recovery, sessionId: owner.sessionId, projectionRevision: status.statusRevision, projection };
          if (!recovery.handled && !['final', 'unknown'].includes(projection.phase)) {
            const at = this.now() + projection.reviewRemainingMs;
            this.deadline = { sessionId: owner.sessionId, at: this.deadline?.sessionId === owner.sessionId ? Math.min(this.deadline.at, at) : at };
          }
        }
      }
    }
    if (edit.status && status.statusRevision < edit.status.statusRevision) {
      if (!versionStatusProgress(status, edit.status)) { this.observationFailed(true); return; }
      this.edit({ ...edit, attempt, recovery }); this.process(); return;
    }
    if (edit.status && !versionStatusProgress(edit.status, status)) { this.observationFailed(true); return; }
    this.edit({ ...edit, attempt, recovery, initialized: true, status, buffered: null, observationIssue: edit.integrityFailed ? 'protocol' : null });
    this.process();
  }

  private acceptOpened(attempt: VersionAttempt): void {
    const opened = attempt.projection?.checkout;
    if (!opened || attempt.openAdopted || attempt.invalidated || attempt.closeRequested || !this.sameContext(attempt.binding)) return;
    const expected = attempt.binding.expectedOriginal, entry = this.state.entries[attempt.binding.projectId];
    if (expected && !same({ ...expected, revision: '' }, { ...opened, revision: '' })) {
      if (entry) this.put({ ...entry, stale: true, error: versionEditError({ code: 'VersionEditContextChanged' }) });
      this.invalidate(); return;
    }
    let next = entry;
    if (!expected) {
      if (entry && (entry.revision >= U32_MAX - 1 || entry.baselineGeneration >= U32_MAX - 1)) { this.invalidate(); return; }
      next = { projectId: attempt.binding.projectId, projectName: this.context.project(attempt.binding.projectId)?.project.name ?? 'Selected project',
        revision: entry ? entry.revision + 1 : 0, baselineGeneration: entry ? entry.baselineGeneration + 1 : 0,
        original: structuredClone(opened), values: structuredClone(opened.values ?? { name: '', build: '' }), stale: false, error: null, outcome: entry?.outcome ?? null };
    }
    if (!next) { this.observationFailed(true); return; }
    this.publish({ ...this.state, entries: { ...this.state.entries, [next.projectId]: next },
      edit: { ...this.state.edit, attempt: { ...this.state.edit.attempt!, openAdopted: true } } });
  }
  private adoptOutcome(attempt: VersionAttempt): void {
    const owner = attempt.projection, input = attempt.submission, entry = this.state.entries[attempt.binding.projectId];
    if (!owner || !entry) return;
    if (!attempt.applyClaimed) {
      if (owner.coreOutcome?.reason && owner.coreOutcome.reason !== 'none')
        this.put({ ...entry, stale: entry.stale || owner.coreOutcome.reason === 'stale_revision',
          error: owner.coreOutcome.reason === 'stale_revision' ? versionEditError({ code: 'VersionEditContextChanged' }) :
            owner.coreOutcome.reason === 'invalid_params' ? versionEditError({ code: 'VersionEditInvalid' }) : versionEditError(null) });
      return;
    }
    const result = normalVersionEditResult(owner);
    const valid = !!result && !!input && !!owner.prepared && attempt.submittedPlanToken === owner.prepared.planToken &&
      versionPreparedMatches(attempt) && !this.state.edit.integrityFailed && !this.state.edit.observationIssue;
    const matches = valid && this.sameContext(attempt.binding, false) && this.matchesSubmission(attempt) && entry.baselineGeneration < U32_MAX - 1;
    const original = matches && input && owner.prepared ? { ...entry.original, values: structuredClone(input.values), baseline: {
      savedConfig: structuredClone(input.expectedBaseline.savedConfig),
      savedVersion: { state: 'present' as const, bytes: owner.prepared.view.file.after.bytes, sha256: owner.prepared.view.file.after.sha256 },
    } } : entry.original;
    this.put({ ...entry, original, baselineGeneration: matches ? entry.baselineGeneration + 1 : entry.baselineGeneration,
      stale: !matches, outcome: structuredClone(owner), error: result ? null : versionEditError(null) });
  }

  // Recovery shares this controller's ORIGINAL subscription, native commands
  // and one live EditOwner. It never acquires a normal checkout or draft.
  private recoveryPatch(patch: Partial<SavedTextRecoveryAttempt<'release_version'>>): void {
    const recovery = this.state.edit.recovery;
    if (recovery) this.edit({ ...this.state.edit, recovery: { ...recovery, ...patch } });
  }
  private recoveryContextMatches(binding: SavedTextRecoveryContext): boolean {
    const project = this.context.selectedProject();
    return !this.disposed && this.state.mode === 'native' && this.state.visible && !this.state.selectionPending && !!project &&
      project.project.id === binding.projectId && this.state.projectId === binding.projectId && project.snapshotRequest === null && !project.saveRecoveryRequired &&
      project.revision === binding.configRevision && project.baselineGeneration === binding.configBaselineGeneration &&
      project.observationGeneration === binding.configObservationGeneration && this.state.connectionGeneration === binding.serviceGeneration &&
      this.state.contextGeneration === binding.selectionGeneration && this.state.contextGeneration === binding.navigationGeneration;
  }
  inspectRecoveryReason(): string | null {
    const edit = this.state.edit, project = this.context.selectedProject();
    if (this.disposed || this.state.mode !== 'native' || edit.mode !== 'native') return 'Recovery inspection requires the qualified native saved-version service; browser preview cannot inspect files.';
    if (edit.integrityFailed || edit.generationLost || edit.nativeBlocked || edit.unknownEvidence || edit.observationIssue)
      return 'Original native ownership or cleanup is unverified. Keep the original operation; recovery cannot reset that block.';
    if (!edit.listening || !edit.initialized || !edit.status || edit.readPending) return 'Wait for the original native status before inspecting recovery.';
    if (!edit.status.capability.available) return 'The native saved-version recovery route is unavailable or another domain owns the service.';
    if (!project || !this.state.visible || this.state.selectionPending || project.snapshotRequest !== null) return 'Select a registered project and finish its current observation before inspecting this editor’s recovery.';
    if (project.saveRecoveryRequired) return 'Configuration recovery is required. This editor cannot clear another domain’s journal.';
    const other = this.context.otherEditReason(project.project.id) ?? this.context.otherOperationReason(); if (other) return other;
    if (edit.status.active || !settled(edit.attempt) || edit.attempt && !edit.attempt.handled || !savedTextRecoverySettled(edit.recovery) || edit.recovery && !edit.recovery.handled)
      return 'Close the original edit/recovery review and wait for its settlement first. No competing inspection or automatic retry is started.';
    if (![project.revision, project.baselineGeneration, project.observationGeneration, this.state.connectionGeneration, this.state.contextGeneration, this.state.contextGeneration, edit.status.statusRevision]
      .every((n) => isU32(n) && n < U32_MAX)) return 'An original recovery context counter is exhausted; no generation is reused.';
    // Deliberately no normal draft, field, locale, source or baseline required.
    // Only this domain's remembered journal attention is bypassed for Inspect.
    return null;
  }
  inspectRecovery(): boolean {
    if (!this.api || this.inspectRecoveryReason()) return false;
    const project = this.context.selectedProject(), status = this.state.edit.status;
    if (!project || !status) return false;
    const binding = freeze<SavedTextRecoveryContext>({ projectId: project.project.id, configRevision: project.revision,
      configBaselineGeneration: project.baselineGeneration, configObservationGeneration: project.observationGeneration,
      serviceGeneration: this.state.connectionGeneration, selectionGeneration: this.state.contextGeneration, navigationGeneration: this.state.contextGeneration,
      windowGeneration: status.windowGeneration, startStatusRevision: status.statusRevision, previousTerminalId: status.lastTerminal?.sessionId ?? null });
    this.edit({ ...this.state.edit, recovery: { binding, sessionId: null, projection: null, projectionRevision: status.statusRevision,
      prepareClaimed: false, applyClaimed: false, submitted: null, closeRequested: false, closeClaimed: false, invalidated: false, handled: false, succeeded: false } });
    if (this.state.edit.recovery?.binding !== binding) return false;
    // Publication can synchronously invalidate consent. Still retain the exact
    // original Open so it can be observed/closed; never start a replacement.
    void this.recoveryCommand('open', binding, () => this.api!.openReleaseVersionEdit({ projectId: binding.projectId, intent: 'recover' }));
    return true;
  }
  recoveryTick(): void { this.process(); }
  remainingRecoveryReviewMs(): number {
    const owner = this.state.edit.recovery?.projection;
    return owner && this.deadline?.sessionId === owner.sessionId ? Math.max(0, Math.min(owner.reviewRemainingMs, this.deadline.at - this.now())) : 0;
  }
  currentRecoveryApplyBinding(): SavedTextRecoveryApplyBinding<'release_version'> | null {
    const edit = this.state.edit, recovery = edit.recovery;
    if (!usable(edit) || edit.unknownEvidence || !recovery || !this.recoveryContextMatches(recovery.binding) || this.remainingRecoveryReviewMs() <= 0 ||
        edit.status?.active?.sessionId !== recovery.sessionId || edit.status.windowGeneration !== recovery.binding.windowGeneration ||
        this.context.otherEditReason(recovery.binding.projectId) || this.context.otherOperationReason()) return null;
    const binding = savedTextRecoveryApplyBinding(recovery);
    return binding ? freeze(binding) : null;
  }
  canApplyRecovery(binding: SavedTextRecoveryApplyBinding<'release_version'>): boolean {
    const current = this.currentRecoveryApplyBinding();
    return current !== null && same(current, binding);
  }
  private recoveryBoundary(projectId: string): void {
    // Retire dependent consents without adopting values, advancing a baseline,
    // deleting a draft, or relabeling an earlier normal Save outcome.
    const entry = this.state.entries[projectId];
    if (entry) this.put({ ...entry, stale: true });
    this.context.onSaveBoundary(projectId);
  }
  applyRecovery(binding: SavedTextRecoveryApplyBinding<'release_version'>): boolean {
    if (this.disposed || !this.api || !this.canApplyRecovery(binding)) return false;
    const original = this.state.edit.recovery!.binding;
    this.recoveryPatch({ applyClaimed: true, submitted: freeze(structuredClone(binding)) });
    this.recoveryBoundary(original.projectId);
    if (this.state.edit.recovery?.binding === original && !this.state.edit.recovery.closeRequested)
      void this.recoveryCommand('apply', original, () => this.api!.applyReleaseVersionEdit(binding.sessionId, binding.planToken, 'recover'));
    return true;
  }
  private retireRecovery(invalidated: boolean): void {
    const recovery = this.state.edit.recovery;
    if (!recovery || recovery.handled || savedTextRecoverySettled(recovery) || recovery.closeRequested || invalidated && recovery.applyClaimed) return;
    this.recoveryPatch({ closeRequested: true, invalidated: recovery.invalidated || invalidated });
  }
  requestRecoveryClose(): void { if (!this.disposed) { this.retireRecovery(false); this.process(); } }
  private processRecovery(): void {
    let recovery = this.state.edit.recovery; if (!recovery || recovery.handled) return;
    let owner = recovery.projection;
    if (!recovery.applyClaimed && !['final', 'unknown'].includes(owner?.phase ?? '') &&
        (!this.recoveryContextMatches(recovery.binding) || this.state.edit.generationLost || owner && this.remainingRecoveryReviewMs() <= 0)) this.retireRecovery(true);
    if (owner?.recovery.prepared && !savedTextRecoveryPreparedMatches(recovery) && !this.state.edit.integrityFailed) { this.observationFailed(true); return; }
    recovery = this.state.edit.recovery; if (!recovery) return; owner = recovery.projection;
    if (owner?.phase === 'final' && owner.nativeFinality === 'settled') {
      const edit = this.state.edit;
      const succeeded = savedTextRecoverySucceeded(recovery) && !edit.integrityFailed && !edit.generationLost && !edit.nativeBlocked && !edit.unknownEvidence && !edit.observationIssue;
      const observed = edit.status, context = recovery.binding;
      // The exact successful projection, not a later unrelated publication,
      // bounds which older attention is covered. Another pending row wins.
      const clearsAttention = succeeded && usable(edit) && this.recoveryContextMatches(context) &&
        observed?.windowGeneration === context.windowGeneration && observed.statusRevision === recovery.projectionRevision &&
        [observed.active, observed.lastTerminal].every((row) => !row || row.phase !== 'unknown' && row.nativeFinality !== 'unknown' &&
          !row.lateSettled && row.nativeReason !== 'cleanup_unknown' && (!row.coreOutcome ||
            row.coreOutcome.resources === 'settled' && row.coreOutcome.effect !== 'unknown' && row.coreOutcome.journal !== 'unknown' &&
            row.coreOutcome.reason !== 'custody_unknown' && !(row.domain === 'release_version' && row.projectId === context.projectId && row.coreOutcome.journal === 'recovery_required')));
      if (clearsAttention) this.recoveryCompletion = { binding: context, statusRevision: recovery.projectionRevision };
      this.edit({ ...edit, recovery: { ...recovery, handled: true, succeeded },
        recoveryProjects: clearsAttention ? edit.recoveryProjects.filter((id) => id !== context.projectId) : edit.recoveryProjects });
      if (recovery.applyClaimed) this.recoveryBoundary(recovery.binding.projectId);
      return;
    }
    if (!owner || !recovery.sessionId || this.state.edit.generationLost || owner.ownerGeneration !== this.state.edit.status?.windowGeneration || owner.phase === 'unknown') return;
    const sessionId = recovery.sessionId, binding = recovery.binding;
    if (recovery.closeRequested && !recovery.closeClaimed) {
      this.recoveryPatch({ closeClaimed: true });
      void this.recoveryCommand('close', binding, () => this.api!.closeReleaseVersionEdit(sessionId)); return;
    }
    const checkout = owner.recovery.checkout;
    if (owner.phase === 'editing' && checkout?.view.state === 'recoverable' && !recovery.prepareClaimed && !recovery.applyClaimed &&
        !recovery.closeRequested && !recovery.invalidated && usable(this.state.edit)) {
      this.recoveryPatch({ prepareClaimed: true });
      if (this.state.edit.recovery?.binding === binding && !this.state.edit.recovery.closeRequested)
        void this.recoveryCommand('prepare', binding, () => this.api!.prepareReleaseVersionEdit({ sessionId, revision: checkout.revision, intent: 'recover' }));
    }
  }
  private async recoveryCommand(kind: 'open' | 'prepare' | 'apply' | 'close', binding: SavedTextRecoveryContext, call: () => Promise<VersionEditStatus>): Promise<void> {
    try { this.receive(await call(), 'reply'); }
    catch (error) {
      const recovery = this.state.edit.recovery;
      if (this.disposed || recovery?.binding !== binding || savedTextRecoverySettled(recovery)) return;
      const protocol = versionEditError(error).code === 'VersionEditStatusInvalid';
      this.observationFailed(protocol);
      if (kind === 'open' || kind === 'prepare' || protocol) this.retireRecovery(true);
      this.process();
      await this.checkStatus(); // Observe the ORIGINAL once; never resubmit Apply.
    }
  }

  private process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.processAgain = true; return; }
    this.processing = true;
    try {
      do {
        this.processAgain = false;
        this.processRecovery();
        let attempt = this.state.edit.attempt; if (!attempt) continue;
        if (!attempt.applyClaimed && !attempt.handled && !attempt.invalidated && !settled(attempt) &&
            (this.state.edit.generationLost || !this.sameContext(attempt.binding) || this.configReason() || !this.state.help ||
              attempt.submission && !this.matchesSubmission(attempt))) this.invalidate();
        attempt = this.state.edit.attempt; if (!attempt) continue;
        if (attempt.projection?.phase === 'editing' && !attempt.openAdopted) this.acceptOpened(attempt);
        attempt = this.state.edit.attempt; if (!attempt) continue;
        const owner = attempt.projection;
        if (owner?.prepared && !versionPreparedMatches(attempt) && !this.state.edit.integrityFailed) { this.observationFailed(true); continue; }
        // Late original evidence can refine an unknown effect/cleanup state.
        // Keep it visible without treating a new observer or late join as success,
        // and do not reapply a settled baseline on unrelated status revisions.
        const outcomeFingerprint = owner && (owner.phase === 'final' || owner.phase === 'unknown') ?
          JSON.stringify([owner.phase, owner.coreOutcome, owner.nativeFinality, owner.nativeReason, owner.lateSettled]) : null;
        if (owner && outcomeFingerprint !== null && outcomeFingerprint !== attempt.outcomeFingerprint) {
          this.attempt({ outcomeNotified: true, outcomeFingerprint });
          if (attempt.submission || attempt.applyClaimed) this.context.onSaveBoundary(attempt.binding.projectId);
          this.adoptOutcome(attempt);
        }
        attempt = this.state.edit.attempt; if (!attempt) continue;
        if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled) this.attempt({ handled: true });
        attempt = this.state.edit.attempt;
        if (!attempt || attempt.handled || !attempt.sessionId || !attempt.projection || this.state.edit.generationLost ||
            attempt.projection.ownerGeneration !== this.state.edit.status?.windowGeneration || ['final', 'unknown'].includes(attempt.projection.phase)) continue;
        const sessionId = attempt.sessionId, binding = attempt.binding;
        if (attempt.closeRequested && !attempt.closeClaimed) {
          this.attempt({ closeClaimed: true });
          void this.command('close', binding, () => this.api!.closeReleaseVersionEdit(sessionId)); continue;
        }
        if (attempt.projection.phase === 'editing' && attempt.projection.checkout && attempt.openAdopted && attempt.submission &&
            !attempt.prepareClaimed && !attempt.applyClaimed && !attempt.invalidated && !attempt.closeRequested && usable(this.state.edit)) {
          const request = { sessionId, revision: attempt.projection.checkout.revision, ...attempt.submission };
          if (!versionEditRequestFits('release_version_edit_prepare', request)) { this.observationFailed(true); continue; }
          this.attempt({ prepareClaimed: true });
          if (this.state.edit.attempt?.binding === binding && !this.state.edit.attempt.closeRequested)
            void this.command('prepare', binding, () => this.api!.prepareReleaseVersionEdit(request));
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }
  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: ContextBinding, call: () => Promise<VersionEditStatus>): Promise<void> {
    try { this.receive(await call(), 'reply'); }
    catch (error) {
      const attempt = this.state.edit.attempt;
      if (this.disposed || attempt?.binding !== binding || settled(attempt)) return;
      const protocol = versionEditError(error).code === 'VersionEditStatusInvalid';
      this.observationFailed(protocol);
      if (kind === 'open' || kind === 'prepare' || protocol) this.invalidate();
      this.process();
      await this.checkStatus(); // One observation, never resend a mutation.
    }
  }
  dispose(): void {
    if (this.disposed) return;
    this.shutdownIntent();
    const attempt = this.state.edit.attempt;
    if (this.api?.mode === 'native' && attempt?.sessionId && attempt.projection && !attempt.closeClaimed && !this.state.edit.generationLost &&
        attempt.projection.ownerGeneration === this.state.edit.status?.windowGeneration && !['final', 'unknown'].includes(attempt.projection.phase)) {
      try { void this.api.closeReleaseVersionEdit(attempt.sessionId).catch(() => { /* Original native owner retains cleanup. */ }); }
      catch { /* No retry or success on renderer disposal. */ }
    }
    this.disposed = true;
    const recovery = this.state.edit.recovery;
    if (this.api?.mode === 'native' && recovery?.sessionId && recovery.projection && !recovery.closeClaimed && !this.state.edit.generationLost &&
        recovery.projection.ownerGeneration === this.state.edit.status?.windowGeneration && !['final', 'unknown'].includes(recovery.projection.phase)) {
      try { void this.api.closeReleaseVersionEdit(recovery.sessionId).catch(() => { /* Original owner retains finality; never retry. */ }); }
      catch { /* No successful settlement inferred from renderer disposal. */ }
    }
    try { this.unlisten?.(); } catch { /* Observer disposal is not native finality. */ }
    this.unlisten = null; this.listeners.clear();
  }
}
