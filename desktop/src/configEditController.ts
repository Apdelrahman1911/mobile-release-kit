// Closed renderer-side orchestration. Testable with inert DTO promises; the
// original native owner, never this object or a JS future, owns real resources.
import { sameJson } from './catalog.ts';
import {
  canApplyEdit, configEditReducer, confirmedConfigSave, draftMatches, editStartReason,
  initialConfigEdit, preparedMatches, nativeStartReason, configRecoveryPreparedMatches, configRecoverySucceeded,
} from './configEdit.ts';
import type { ConfigEditAction, ConfigEditState, ConfigRecoveryAttention, ConfirmedConfigSave, EditApplyBinding, EditDraftBinding, ConfigRecoveryBinding, ConfigRecoveryApplyBinding, ConfigRecoveryAttempt, ConfigRecoveryCompletion } from './configEdit.ts';
import { parseConfigEditStatus, isU32, U32_MAX } from './configEditProtocol.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { ConfigEditStatus, DesktopApi } from './types.ts';

interface EditContext {
  project: (projectId: string) => ProjectSession | null;
  selectedProject?: () => ProjectSession | null;
  recoveryUnavailable?: () => string | null;
  onRecovered?: (completion: ConfigRecoveryCompletion) => void;
  otherEditReason?: (projectId: string) => string | null;
  onConfirmedSave: (receipt: ConfirmedConfigSave) => void;
  onRecoveryRequired?: (attention: ConfigRecoveryAttention) => void;
}

function freezeJson<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freezeJson(child);
    Object.freeze(value);
  }
  return value;
}

export class ConfigEditController {
  private state: ConfigEditState = initialConfigEdit;
  private api: DesktopApi | null = null;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private processing = false;
  private processAgain = false;
  private disposed = false;
  private readonly context: EditContext;
  private recoveryContextGeneration = 0;
  private recoveryVisible = true;
  private recoveryCompletion: { binding: ConfigRecoveryBinding; statusRevision: number } | null = null;

  constructor(context: EditContext) { this.context = context; }

  getSnapshot = (): ConfigEditState => this.state;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private change(action: ConfigEditAction): void {
    const next = configEditReducer(this.state, action);
    if (next === this.state) return;
    this.state = next;
    if (this.recoveryCompletion && (!this.recoveryContextMatches(this.recoveryCompletion.binding) ||
        this.state.status?.windowGeneration !== this.recoveryCompletion.binding.windowGeneration ||
        this.state.integrityFailed || this.state.generationLost || this.state.nativeBlocked || this.state.observationIssue || this.state.unknownEvidence)) this.recoveryCompletion = null;
    for (const listener of this.listeners) listener();
  }

  async connect(api: DesktopApi): Promise<void> {
    if (this.disposed || this.api) return;
    this.api = api;
    this.change({ type: 'connect', mode: api.mode });
    if (api.mode === 'native') await this.checkStatus();
  }

  // Coalesce concurrent reads. No periodic polling, heartbeat, new process,
  // retry clock or reconnect authority is introduced by this observer.
  async checkStatus(): Promise<void> {
    if (this.disposed || !this.api || this.api.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api;
    // Claim before notifying subscribers, which may synchronously ask again.
    const work = Promise.resolve().then(() => this.readOnce(api));
    this.reading = work;
    this.change({ type: 'read-start' });
    try { await work; }
    finally { if (this.reading === work) this.reading = null; }
  }

  private async readOnce(api: DesktopApi): Promise<void> {
    if (this.disposed) return;
    try {
      if (!this.unlisten) {
        const unlisten = await api.subscribeConfigEdit((status) => this.receive(status, 'event'));
        if (this.disposed) { unlisten(); return; }
        this.unlisten = unlisten;
        this.change({ type: 'listening' });
      }
      if (this.disposed) return;
      // Always subscribe first and then read, including the first connection.
      const status = await api.configEditStatus();
      this.receive(status, 'read');
    } catch {
      if (!this.disposed) this.change({ type: 'observation-failed' });
    }
  }

  private receive(value: unknown, source: 'read' | 'event' | 'reply'): void {
    if (this.disposed) return;
    const parsed = parseConfigEditStatus(value);
    if (!parsed) {
      this.change({ type: 'observation-failed', protocol: true });
    } else {
      // A native response or an inert test double cannot mutate a retained
      // review after it has been accepted by this renderer.
      const status = freezeJson(structuredClone(parsed));
      const coveredAttention = [status.active, status.lastTerminal].filter((row) => row && this.attentionCovered(status, row)).map((row) => row!.sessionId);
      this.change({ type: 'observe', status, source, coveredAttention });
    }
    // A known pre-apply owner can still be closed, never replaced/reprepared,
    // including a contradictory progression of otherwise well-formed DTOs.
    if (this.state.integrityFailed) { this.change({ type: 'close-request', reason: 'invoke_failed' }); this.retireRecovery(true); }
    this.process();
  }

  start(projectId: string): boolean {
    if (this.disposed || !this.api || this.api.mode !== 'native') return false;
    if (this.context.otherEditReason?.(projectId)) return false;
    const session = this.context.project(projectId);
    if (editStartReason(this.state, session) !== null || !session?.draft || !this.state.status) return false;
    const binding: EditDraftBinding = freezeJson({
      projectId, windowGeneration: this.state.status.windowGeneration,
      startStatusRevision: this.state.status.statusRevision,
      previousTerminalId: this.state.status.lastTerminal?.sessionId ?? null,
      draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
      expectedBase: structuredClone(session.baseline), draft: structuredClone(session.draft),
    });
    const previous = this.state.attempt;
    this.change({ type: 'begin', binding });
    if (this.state.attempt === previous || this.state.attempt?.binding !== binding) return false;
    // The local registration latch is set synchronously, before invoking Rust.
    void this.command('open', binding, () => this.api!.openConfigEdit(projectId));
    return true;
  }

  apply(confirmation: EditApplyBinding): boolean {
    if (this.disposed || !this.api || !this.state.attempt) return false;
    const binding = this.state.attempt.binding;
    if (!canApplyEdit(this.state, this.context.project(binding.projectId), confirmation)) return false;
    const previous = this.state.attempt;
    this.change({ type: 'apply-claim', binding: confirmation });
    if (this.state.attempt === previous || !this.state.attempt?.applyClaimed) return false;
    // A reentrant close may win before submission; it is never converted into
    // an Apply. Once sent, only an explicit cancellation requests Close.
    if (this.state.attempt.binding === binding && !this.state.attempt.closeRequested) {
      void this.command('apply', binding, () => this.api!.applyConfigEdit(confirmation.sessionId, confirmation.planToken));
    }
    return true;
  }

  requestClose(): void {
    if (this.disposed) return;
    this.change({ type: 'close-request', reason: 'user' });
    this.process();
  }

  // Called synchronously with workspace dispatch, not in a later render effect.
  // Every local edit/removal/undo/reset invalidates pre-Apply authority at once.
  syncDraft(): void { if (!this.disposed) this.process(); }

  private process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.processAgain = true; return; }
    this.processing = true;
    try {
      do {
        this.processAgain = false;
        // Initial/read-only observations may have no local attempt or loaded
        // project yet. Propagate only negative attention, idempotently, when
        // the matching project appears; never fabricate a saved binding.
        for (const attention of this.state.recoveryProjects) {
          const project = this.context.project(attention.projectId);
          if (project && !project.saveRecoveryRequired) this.context.onRecoveryRequired?.(attention);
        }
        this.processRecovery();
        let attempt = this.state.attempt;
        if (!attempt) continue;
        const owner = attempt.projection;
        const terminal = owner?.phase === 'final' || owner?.phase === 'unknown';
        if (!attempt.applyClaimed && !attempt.closeRequested && !attempt.handled && !terminal) {
          if (!draftMatches(attempt.binding, this.context.project(attempt.binding.projectId))) {
            this.change({ type: 'close-request', reason: 'draft_changed' });
          } else if (owner?.checkout && !sameJson(owner.checkout.base, attempt.binding.expectedBase)) {
            this.change({ type: 'close-request', reason: 'baseline_mismatch' });
          }
        }
        if (owner?.prepared && !preparedMatches(attempt)) {
          this.change({ type: 'observation-failed', protocol: true });
          this.change({ type: 'close-request', reason: 'invoke_failed' });
        }
        const receipt = confirmedConfigSave(this.state);
        if (receipt) {
          // Mark handled before the workspace callback can reenter us. The
          // workspace independently checks the exact current draft/baseline.
          this.change({ type: 'handled', sessionId: receipt.sessionId });
          this.context.onConfirmedSave(receipt);
        } else if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled) {
          this.change({ type: 'handled', sessionId: owner.sessionId });
        }
        attempt = this.state.attempt;
        if (!attempt || attempt.handled || !attempt.sessionId || !attempt.projection ||
            attempt.projection.ownerGeneration !== this.state.status?.windowGeneration || this.state.generationLost ||
            attempt.projection.phase === 'final' || attempt.projection.phase === 'unknown') continue;
        if (attempt.closeRequested && !attempt.closeClaimed) {
          const sessionId = attempt.sessionId;
          const binding = attempt.binding;
          this.change({ type: 'close-claim', sessionId });
          if (this.state.attempt?.binding === binding && this.state.attempt.closeClaimed) void this.command('close', binding, () => this.api!.closeConfigEdit(sessionId));
          continue;
        }
        if (attempt.projection.phase === 'editing' && attempt.projection.checkout &&
            !attempt.prepareClaimed && !attempt.closeRequested && !attempt.applyClaimed && !attempt.invalidated) {
          const sessionId = attempt.sessionId;
          const revision = attempt.projection.checkout.revision;
          const binding = attempt.binding;
          this.change({ type: 'prepare-claim', sessionId });
          if (this.state.attempt?.binding === binding && this.state.attempt.prepareClaimed && !this.state.attempt.closeRequested) {
            void this.command('prepare', binding, () => this.api!.prepareConfigEdit({
              sessionId, revision, expectedBase: binding.expectedBase, draft: binding.draft,
              draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration,
            }));
          }
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }

  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: EditDraftBinding, call: () => Promise<ConfigEditStatus>): Promise<void> {
    try {
      const status = await call();
      this.receive(status, 'reply');
    } catch {
      if (this.disposed || this.state.attempt?.binding !== binding) return;
      // An old invoke rejection cannot undo an already observed original Final.
      if (this.state.attempt.projection?.phase === 'final' && this.state.attempt.projection.nativeFinality === 'settled') return;
      this.change({ type: 'observation-failed' });
      if (kind === 'open' || kind === 'prepare') this.change({ type: 'close-request', reason: 'invoke_failed' });
      this.process();
      // Observe the original registry once. Never resend an Apply, Prepare or
      // Open, even if the status read itself fails or finds no registration yet.
      await this.checkStatus();
    }
  }

  private recoveryPatch(patch: Partial<Omit<ConfigRecoveryAttempt, 'binding'>>): void {
    const recovery = this.state.recovery;
    if (recovery) this.change({ type: 'recovery-update', binding: recovery.binding, patch });
  }
  private recoveryContextMatches(binding: ConfigRecoveryBinding): boolean {
    const project = this.context.project(binding.projectId);
    return !this.disposed && this.recoveryVisible && this.state.mode === 'native' && !this.context.recoveryUnavailable?.() &&
      (!this.context.selectedProject || this.context.selectedProject()?.project.id === binding.projectId) &&
      !!project && project.snapshotRequest === null && project.revision === binding.draftRevision &&
      project.baselineGeneration === binding.baselineGeneration && project.observationGeneration === binding.observationGeneration &&
      this.recoveryContextGeneration === binding.contextGeneration && this.recoveryContextGeneration < U32_MAX;
  }
  private recoveryInvalidate(): void {
    this.recoveryCompletion = null;
    this.recoveryContextGeneration = Math.min(U32_MAX, this.recoveryContextGeneration + 1);
    this.retireRecovery(true); this.process();
  }
  setRecoveryVisible(value: boolean): void {
    if (this.disposed || value === this.recoveryVisible) return;
    this.recoveryVisible = value; this.recoveryInvalidate();
  }
  serviceIntent(): void { if (!this.disposed) this.recoveryInvalidate(); }
  selectionIntent(): void { if (!this.disposed) this.recoveryInvalidate(); }
  shutdownIntent(): void { if (!this.disposed) this.recoveryInvalidate(); }
  snapshotIntent(projectId: string): void {
    if (!this.disposed && (projectId === this.state.recovery?.binding.projectId || projectId === this.recoveryCompletion?.binding.projectId)) this.recoveryInvalidate();
  }
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (this.disposed) return;
    if (action.type === 'select' || action.type === 'switch' ||
        (action.projectId === this.state.recovery?.binding.projectId || action.projectId === this.recoveryCompletion?.binding.projectId) &&
        ['snapshot-start', 'snapshot-done', 'snapshot-failed', 'new-draft', 'edit', 'remove-forbidden', 'undo-removal', 'forget-removal', 'reset',
          'adopt-suggestion', 'config-save-intent', 'config-save-final', 'config-save-recovery'].includes(action.type)) this.recoveryInvalidate();
  }
  inspectRecoveryReason(projectId: string): string | null {
    const native = nativeStartReason(this.state);
    if (native) return native;
    if (this.disposed || !this.api || this.state.readPending || this.state.unknownEvidence) return 'Wait for the original native status; unknown custody cannot be recovered here.';
    const unavailable = this.context.recoveryUnavailable?.() ?? this.context.otherEditReason?.(projectId);
    if (unavailable) return unavailable;
    const project = this.context.project(projectId);
    if (!project || !this.recoveryVisible || project.snapshotRequest !== null ||
        this.context.selectedProject && this.context.selectedProject()?.project.id !== projectId) return 'Select the original registered project and finish its pending observation first.';
    if (![project.revision, project.baselineGeneration, project.observationGeneration, this.recoveryContextGeneration].every((n) => isU32(n) && n < U32_MAX)) return 'An original recovery context counter is exhausted; no generation is reused.';
    // No draft/config validity requirement: recovery cannot use draft bytes as
    // filesystem authority and bypasses only this domain's journal attention.
    return null;
  }
  inspectRecovery(projectId: string): boolean {
    if (this.inspectRecoveryReason(projectId)) return false;
    const project = this.context.project(projectId), status = this.state.status;
    if (!project || !status || !this.api) return false;
    const binding = freezeJson<ConfigRecoveryBinding>({ projectId, windowGeneration: status.windowGeneration,
      startStatusRevision: status.statusRevision, previousTerminalId: status.lastTerminal?.sessionId ?? null,
      draftRevision: project.revision, baselineGeneration: project.baselineGeneration, observationGeneration: project.observationGeneration,
      contextGeneration: this.recoveryContextGeneration });
    this.change({ type: 'recovery-begin', binding });
    if (this.state.recovery?.binding !== binding) return false;
    void this.recoveryCommand('open', binding, () => this.api!.openConfigRecovery(projectId));
    return true;
  }
  currentRecoveryApplyBinding(): ConfigRecoveryApplyBinding | null {
    const state = this.state, recovery = state.recovery, owner = recovery?.projection, prepared = owner?.recovery?.prepared;
    if (!recovery || !owner || !prepared || !prepared.view.action || !configRecoveryPreparedMatches(recovery) ||
        !this.recoveryContextMatches(recovery.binding) || this.context.otherEditReason?.(recovery.binding.projectId) ||
        state.integrityFailed || state.generationLost || state.nativeBlocked || state.unknownEvidence || state.observationIssue ||
        !state.initialized || !state.listening || !state.status?.capability.available || state.status.active?.sessionId !== owner.sessionId ||
        state.status.windowGeneration !== recovery.binding.windowGeneration || owner.phase !== 'reviewing' || owner.nativeFinality !== 'pending' ||
        owner.nativeReason !== 'none' || owner.reviewRemainingMs === 0 || owner.applySubmitted || !recovery.prepareClaimed ||
        recovery.applyClaimed || recovery.closeRequested || recovery.invalidated || recovery.handled) return null;
    return freezeJson({ sessionId: owner.sessionId, revision: prepared.revision, planToken: prepared.planToken,
      action: prepared.view.action, context: recovery.binding });
  }
  applyRecovery(confirmation: ConfigRecoveryApplyBinding): boolean {
    const binding = this.currentRecoveryApplyBinding();
    if (!binding || !sameJson(binding as unknown as import('./types.ts').JsonValue, confirmation as unknown as import('./types.ts').JsonValue) || !this.api) return false;
    this.recoveryPatch({ applyClaimed: true, submitted: freezeJson(structuredClone(confirmation)) });
    // change() notifies subscribers synchronously. A project/service intent
    // that wins before this original invocation must still retire the review.
    if (this.state.recovery?.binding !== binding.context || this.state.recovery.closeRequested ||
        !this.recoveryContextMatches(binding.context) || this.state.integrityFailed || this.state.generationLost ||
        this.state.nativeBlocked || this.state.observationIssue || this.state.unknownEvidence ||
        this.state.status?.active?.sessionId !== binding.sessionId || !this.state.status.capability.available) {
      this.retireRecovery(false); this.process(); return false;
    }
    void this.recoveryCommand('apply', binding.context, () => this.api!.applyConfigRecovery(binding.sessionId, binding.planToken));
    return true;
  }
  private retireRecovery(invalidated: boolean): void {
    const recovery = this.state.recovery;
    if (!recovery || recovery.handled || recovery.projection?.phase === 'final' || recovery.closeRequested || invalidated && recovery.applyClaimed) return;
    this.recoveryPatch({ closeRequested: true, invalidated: recovery.invalidated || invalidated });
  }
  requestRecoveryClose(): void { if (!this.disposed) { this.retireRecovery(false); this.process(); } }
  private safeRecoveryRows(status: ConfigEditStatus, projectId: string, rejectPending: boolean): boolean {
    return status.capability.reason !== 'cleanup_unknown' && [status.active, status.lastTerminal].every((row) => !row ||
      row.phase !== 'unknown' && row.nativeFinality !== 'unknown' && !row.lateSettled && row.nativeReason !== 'cleanup_unknown' &&
      (!row.coreOutcome || row.coreOutcome.resources === 'settled' && row.coreOutcome.effect !== 'unknown' && row.coreOutcome.journal !== 'unknown' &&
        row.coreOutcome.reason !== 'custody_unknown' && !(rejectPending && row.projectId === projectId && row.coreOutcome.journal === 'recovery_required')));
  }
  private attentionCovered(status: ConfigEditStatus, owner: import('./types.ts').ConfigEditProjection): boolean {
    const completed = this.recoveryCompletion, core = owner.coreOutcome;
    return !!completed && this.recoveryContextMatches(completed.binding) && !!this.state.status &&
      !this.state.integrityFailed && !this.state.generationLost && !this.state.nativeBlocked && !this.state.observationIssue && !this.state.unknownEvidence &&
      owner.projectId === completed.binding.projectId && owner.ownerGeneration === completed.binding.windowGeneration &&
      status.windowGeneration === completed.binding.windowGeneration && status.statusRevision < completed.statusRevision &&
      owner.phase === 'final' && owner.nativeFinality === 'settled' && core?.journal === 'recovery_required' && core.resources === 'settled' &&
      this.safeRecoveryRows(status, owner.projectId, false) && this.safeRecoveryRows(this.state.status, owner.projectId, true);
  }
  private processRecovery(): void {
    let recovery = this.state.recovery;
    if (!recovery || recovery.handled) return;
    let owner = recovery.projection;
    if (!recovery.applyClaimed && !['final', 'unknown'].includes(owner?.phase ?? '') &&
        (!this.recoveryContextMatches(recovery.binding) || this.state.generationLost)) this.retireRecovery(true);
    if (owner?.recovery?.prepared && !configRecoveryPreparedMatches(recovery)) {
      this.change({ type: 'observation-failed', protocol: true }); this.retireRecovery(true);
    }
    recovery = this.state.recovery;
    if (!recovery) return;
    owner = recovery.projection;
    if (owner?.phase === 'final' && owner.nativeFinality === 'settled') {
      const state = this.state, current = state.status;
      const succeeded = configRecoverySucceeded(recovery) && !state.integrityFailed && !state.generationLost && !state.nativeBlocked && !state.unknownEvidence && !state.observationIssue;
      const clears = succeeded && !!current && current.capability.available && this.recoveryContextMatches(recovery.binding) &&
        current.windowGeneration === recovery.binding.windowGeneration && current.statusRevision === recovery.projectionRevision && this.safeRecoveryRows(current, recovery.binding.projectId, true);
      if (clears) this.recoveryCompletion = { binding: recovery.binding, statusRevision: recovery.projectionRevision };
      this.recoveryPatch({ handled: true, succeeded });
      // Handling publication can synchronously deliver a new intent/status.
      // Recheck this exact completion, never borrow its successor's revision.
      const completed = recovery;
      const stillCurrent = () => {
        const currentStatus = this.state.status;
        return this.recoveryCompletion?.binding === completed.binding &&
          this.recoveryCompletion.statusRevision === completed.projectionRevision && this.recoveryContextMatches(completed.binding) &&
          currentStatus?.statusRevision === completed.projectionRevision && currentStatus.capability.available &&
          !this.state.integrityFailed && !this.state.generationLost && !this.state.nativeBlocked &&
          !this.state.unknownEvidence && !this.state.observationIssue && this.safeRecoveryRows(currentStatus, completed.binding.projectId, true);
      };
      if (clears && recovery.submitted && stillCurrent()) {
        this.change({ type: 'recovery-cleared', binding: recovery.binding, statusRevision: recovery.projectionRevision });
        if (stillCurrent()) this.context.onRecovered?.({ binding: recovery.binding, statusRevision: recovery.projectionRevision, projection: owner, submitted: recovery.submitted });
      }
      return;
    }
    if (!owner || !recovery.sessionId || this.state.generationLost || owner.ownerGeneration !== this.state.status?.windowGeneration || owner.phase === 'unknown') return;
    const binding = recovery.binding, sessionId = recovery.sessionId;
    if (recovery.closeRequested && !recovery.closeClaimed) {
      this.recoveryPatch({ closeClaimed: true });
      void this.recoveryCommand('close', binding, () => this.api!.closeConfigEdit(sessionId)); return;
    }
    const checkout = owner.recovery?.checkout;
    if (owner.phase === 'editing' && checkout?.view.state === 'recoverable' && !recovery.prepareClaimed && !recovery.applyClaimed &&
        !recovery.closeRequested && !recovery.invalidated && !this.state.observationIssue && !this.state.integrityFailed && !this.state.nativeBlocked) {
      this.recoveryPatch({ prepareClaimed: true });
      if (this.state.recovery?.binding === binding && !this.state.recovery.closeRequested)
        void this.recoveryCommand('prepare', binding, () => this.api!.prepareConfigRecovery(sessionId, checkout.revision));
    }
  }
  private async recoveryCommand(kind: 'open' | 'prepare' | 'apply' | 'close', binding: ConfigRecoveryBinding, call: () => Promise<ConfigEditStatus>): Promise<void> {
    try { this.receive(await call(), 'reply'); }
    catch {
      const recovery = this.state.recovery;
      if (this.disposed || recovery?.binding !== binding || recovery.projection?.phase === 'final' && recovery.projection.nativeFinality === 'settled') return;
      this.change({ type: 'observation-failed' });
      if (kind === 'open' || kind === 'prepare') this.retireRecovery(true);
      this.process(); await this.checkStatus(); // Observe this original once; no retry.
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.recoveryCompletion = null;
    const recovery = this.state.recovery;
    if (this.api?.mode === 'native' && recovery?.sessionId && recovery.projection && !recovery.closeClaimed &&
        recovery.projection.ownerGeneration === this.state.status?.windowGeneration && !['final', 'unknown'].includes(recovery.projection.phase)) {
      try { void this.api.closeConfigEdit(recovery.sessionId).catch(() => {}); } catch { /* No retry or finality claim. */ }
    }
    this.disposed = true;
    const attempt = this.state.attempt;
    // App-controller destruction (not page navigation or a status read ending)
    // requests stop for a known original owner. Native lifecycle cancellation
    // and quit settlement remain authoritative if this best-effort IPC is lost.
    if (this.api?.mode === 'native' && attempt?.sessionId && attempt.projection && !attempt.closeClaimed &&
        attempt.projection.ownerGeneration === this.state.status?.windowGeneration &&
        !['final', 'unknown'].includes(attempt.projection.phase)) {
      try { void this.api.closeConfigEdit(attempt.sessionId).catch(() => { /* No finality claim or resend. */ }); }
      catch { /* Native window loss still owns stopping; never claim completion. */ }
    }
    try { this.unlisten?.(); } catch { /* Observer cleanup is not native settlement. */ }
    this.unlisten = null;
    this.listeners.clear();
  }
}
