// Closed renderer-side orchestration. Testable with inert DTO promises; the
// original native owner, never this object or a JS future, owns real resources.
import { sameJson } from './catalog.ts';
import {
  canApplyEdit, configEditReducer, confirmedConfigSave, draftMatches, editStartReason,
  initialConfigEdit, preparedMatches,
} from './configEdit.ts';
import type { ConfigEditAction, ConfigEditState, ConfigRecoveryAttention, ConfirmedConfigSave, EditApplyBinding, EditDraftBinding } from './configEdit.ts';
import { parseConfigEditStatus } from './configEditProtocol.ts';
import type { ProjectSession } from './drafts.ts';
import type { ConfigEditStatus, DesktopApi } from './types.ts';

interface EditContext {
  project: (projectId: string) => ProjectSession | null;
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
      this.change({ type: 'observe', status: freezeJson(structuredClone(parsed)), source });
    }
    // A known pre-apply owner can still be closed, never replaced/reprepared,
    // including a contradictory progression of otherwise well-formed DTOs.
    if (this.state.integrityFailed) this.change({ type: 'close-request', reason: 'invoke_failed' });
    this.process();
  }

  start(projectId: string): boolean {
    if (this.disposed || !this.api || this.api.mode !== 'native') return false;
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

  dispose(): void {
    if (this.disposed) return;
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
