// Workflow-only orchestration using the existing edit observer pattern. The
// shared native EditOwner, not a JS promise/controller, owns all real resources.
import {
  canApplyWorkflows, githubWorkflowEditReducer, initialGitHubWorkflowEdit,
  workflowContextMatches, workflowPreparedMatches, workflowStartReason,
} from './githubWorkflowEdit.ts';
import type { GitHubWorkflowEditState, WorkflowApplyBinding, WorkflowDraftBinding, WorkflowEditAction } from './githubWorkflowEdit.ts';
import { parseGitHubWorkflowEditStatus, workflowEditError } from './githubWorkflowEditProtocol.ts';
import type { GitHubWorkflowEditStatus } from './githubWorkflowEditTypes.ts';
import type { ProjectSession } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { DesktopApi } from './types.ts';

interface WorkflowContext {
  selectedProject: () => ProjectSession | null;
  setup: () => GitHubSetupState;
  otherEditReason: (projectId: string) => string | null;
}
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export class GitHubWorkflowEditController {
  private state: GitHubWorkflowEditState = initialGitHubWorkflowEdit;
  private api: DesktopApi | null = null;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private processing = false;
  private processAgain = false;
  private disposed = false;
  private readonly context: WorkflowContext;

  constructor(context: WorkflowContext) { this.context = context; }
  getSnapshot = (): GitHubWorkflowEditState => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  private change(action: WorkflowEditAction): void {
    const next = githubWorkflowEditReducer(this.state, action);
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

  // One coalesced observation. Never a polling timer, retry clock, replacement
  // child or mutation retry. Even a failed first subscription precedes status.
  async checkStatus(): Promise<void> {
    if (this.disposed || !this.api || this.api.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api;
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
        const unlisten = await api.subscribeGitHubWorkflowEdit((status) => this.receive(status, 'event'));
        if (this.disposed) { unlisten(); return; }
        this.unlisten = unlisten;
        this.change({ type: 'listening' });
      }
      if (!this.disposed) this.receive(await api.githubWorkflowEditStatus(), 'read');
    } catch (error) {
      if (!this.disposed) {
        const protocol = workflowEditError(error).code === 'GitHubWorkflowStatusInvalid';
        this.change({ type: 'observation-failed', protocol });
        if (protocol) { this.change({ type: 'close-request', reason: 'invoke_failed' }); this.process(); }
      }
    }
  }
  private receive(value: unknown, source: 'read' | 'event' | 'reply'): void {
    if (this.disposed) return;
    const status = parseGitHubWorkflowEditStatus(value);
    if (!status) this.change({ type: 'observation-failed', protocol: true });
    else this.change({ type: 'observe', status: freeze(structuredClone(status)), source });
    if (this.state.integrityFailed) this.change({ type: 'close-request', reason: 'invoke_failed' });
    this.process();
  }
  startReason(): string | null {
    const project = this.context.selectedProject();
    return workflowStartReason(this.state, project, this.context.setup(), project ? this.context.otherEditReason(project.project.id) : null);
  }
  start(): boolean {
    if (this.disposed || !this.api || this.api.mode !== 'native' || this.startReason() !== null) return false;
    const project = this.context.selectedProject(); const setup = this.context.setup(); const status = this.state.status;
    if (!project?.draft || !status) return false;
    const binding: WorkflowDraftBinding = freeze({
      projectId: project.project.id, windowGeneration: status.windowGeneration,
      startStatusRevision: status.statusRevision, previousTerminalId: status.lastTerminal?.sessionId ?? null,
      draftRevision: project.revision, baselineGeneration: project.baselineGeneration,
      baseline: structuredClone(project.baseline), draft: structuredClone(project.draft),
      serviceGeneration: setup.serviceGeneration, selectionGeneration: setup.selectionGeneration, coordinateGeneration: setup.coordinateGeneration,
      toolingRepository: setup.inputs.toolingRepository, toolingSha: setup.inputs.toolingSha,
    });
    const previous = this.state.attempt;
    this.change({ type: 'begin', binding });
    if (this.state.attempt === previous || this.state.attempt?.binding !== binding) return false;
    // This synchronous latch also blocks the configuration controller before
    // either native domain has emitted its shared-owner status change.
    void this.command('open', binding, () => this.api!.openGitHubWorkflowEdit(binding.projectId));
    return true;
  }
  apply(confirmation: WorkflowApplyBinding): boolean {
    if (this.disposed || !this.api || !this.state.attempt ||
        !canApplyWorkflows(this.state, this.context.selectedProject(), this.context.setup(), confirmation)) return false;
    const binding = this.state.attempt.binding; const previous = this.state.attempt;
    this.change({ type: 'apply-claim', binding: confirmation });
    if (this.state.attempt === previous || !this.state.attempt?.applyClaimed) return false;
    // A reentrant explicit Close can win before enqueue. Once Apply is sent,
    // input changes preserve its outcome; only explicit cancellation stops it.
    if (this.state.attempt.binding === binding && !this.state.attempt.closeRequested) {
      void this.command('apply', binding, () => this.api!.applyGitHubWorkflowEdit(confirmation.sessionId, confirmation.planToken));
    }
    return true;
  }
  requestClose(): void {
    if (this.disposed) return;
    this.change({ type: 'close-request', reason: 'user' });
    this.process();
  }
  // App calls this synchronously for workspace dispatch and every setup setter
  // or connection generation change, not from a delayed React effect.
  syncContext = (): void => { if (!this.disposed) this.process(); };

  private process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.processAgain = true; return; }
    this.processing = true;
    try {
      do {
        this.processAgain = false;
        let attempt = this.state.attempt;
        if (!attempt) continue;
        const owner = attempt.projection;
        const terminal = owner?.phase === 'final' || owner?.phase === 'unknown';
        if (!attempt.applyClaimed && !attempt.closeRequested && !attempt.handled && !terminal &&
            (this.state.generationLost || !workflowContextMatches(attempt.binding, this.context.selectedProject(), this.context.setup()))) {
          this.change({ type: 'close-request', reason: 'context_changed' });
        }
        if (owner?.prepared && !workflowPreparedMatches(attempt)) {
          this.change({ type: 'observation-failed', protocol: true });
          this.change({ type: 'close-request', reason: 'invoke_failed' });
        }
        if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled) {
          // No configuration-save callback, draft reset or baseline adoption.
          // The retained original projection itself is the read-only result.
          this.change({ type: 'handled', sessionId: owner.sessionId });
        }
        attempt = this.state.attempt;
        if (!attempt || attempt.handled || !attempt.sessionId || !attempt.projection || this.state.generationLost ||
            attempt.projection.ownerGeneration !== this.state.status?.windowGeneration ||
            ['final', 'unknown'].includes(attempt.projection.phase)) continue;
        if (attempt.closeRequested && !attempt.closeClaimed) {
          const sessionId = attempt.sessionId; const binding = attempt.binding;
          this.change({ type: 'close-claim', sessionId });
          if (this.state.attempt?.binding === binding && this.state.attempt.closeClaimed) void this.command('close', binding, () => this.api!.closeGitHubWorkflowEdit(sessionId));
          continue;
        }
        if (attempt.projection.phase === 'editing' && attempt.projection.checkout && !attempt.prepareClaimed &&
            !attempt.closeRequested && !attempt.applyClaimed && !attempt.invalidated) {
          const sessionId = attempt.sessionId; const revision = attempt.projection.checkout.revision; const binding = attempt.binding;
          this.change({ type: 'prepare-claim', sessionId });
          if (this.state.attempt?.binding === binding && this.state.attempt.prepareClaimed && !this.state.attempt.closeRequested) {
            void this.command('prepare', binding, () => this.api!.prepareGitHubWorkflowEdit({
              sessionId, revision, draft: binding.draft, toolingRepository: binding.toolingRepository, toolingSha: binding.toolingSha,
              draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration,
            }));
          }
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }

  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: WorkflowDraftBinding, call: () => Promise<GitHubWorkflowEditStatus>): Promise<void> {
    try { this.receive(await call(), 'reply'); }
    catch (error) {
      if (this.disposed || this.state.attempt?.binding !== binding) return;
      if (this.state.attempt.projection?.phase === 'final' && this.state.attempt.projection.nativeFinality === 'settled') return;
      const protocol = workflowEditError(error).code === 'GitHubWorkflowStatusInvalid';
      this.change({ type: 'observation-failed', protocol });
      if (kind === 'open' || kind === 'prepare' || protocol) this.change({ type: 'close-request', reason: 'invoke_failed' });
      this.process();
      // Lost/duplicate results observe this owner once, never repeat any write
      // command or open a replacement when admission is unknown.
      await this.checkStatus();
    }
  }
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    const attempt = this.state.attempt;
    if (this.api?.mode === 'native' && attempt?.sessionId && attempt.projection && !attempt.closeClaimed && !this.state.generationLost &&
        attempt.projection.ownerGeneration === this.state.status?.windowGeneration && !['final', 'unknown'].includes(attempt.projection.phase)) {
      try { void this.api.closeGitHubWorkflowEdit(attempt.sessionId).catch(() => { /* Original native lifecycle still owns settlement. */ }); }
      catch { /* No completion claim or retry from renderer destruction. */ }
    }
    try { this.unlisten?.(); } catch { /* An observer close is not native finality. */ }
    this.unlisten = null;
    this.listeners.clear();
  }
}
