// Workflow-only orchestration using the existing edit observer pattern. The
// shared native EditOwner, not a JS promise/controller, owns all real resources.
import {
  canApplyWorkflows, canRecoverWorkflows, githubWorkflowEditReducer, initialGitHubWorkflowEdit,
  workflowContextMatches, workflowPreparedMatches, workflowRecoveryStartReason, workflowStartReason,
  workflowOwnerReason, workflowRetainsDraft,
} from './githubWorkflowEdit.ts';
import type { GitHubWorkflowEditState, WorkflowApplyBinding, WorkflowBinding, WorkflowDraftBinding, WorkflowEditAction, WorkflowRecoveryApplyBinding, WorkflowRecoveryBinding } from './githubWorkflowEdit.ts';
import { parseGitHubWorkflowEditStatus, workflowEditError } from './githubWorkflowEditProtocol.ts';
import type { GitHubWorkflowEditStatus } from './githubWorkflowEditTypes.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { DesktopApi } from './types.ts';
import { ServiceWorkflowEditController } from './serviceWorkflowEditController.ts';
import { sameWorkflowEditOrigin } from './serviceWorkflowEditProtocol.ts';
import type { WorkflowEditOrigin } from './serviceWorkflowEditProtocol.ts';

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

  readonly agent: ServiceWorkflowEditController;
  private agentBinding: WorkflowDraftBinding | null = null;
  private agentOrigin: WorkflowEditOrigin | null = null;
  private agentCommands = 0;

  constructor(context: WorkflowContext) {
    this.context = context;
    this.agent = new ServiceWorkflowEditController({
      native: () => this.state, project: context.selectedProject, setup: context.setup,
      startReason: () => this.originalStartReason(), linked: q => this.agentLinked(q), callsPending: () => this.agentCommands !== 0,
      checkNative: () => this.checkAgentNative(),
      open: (q,p,current) => this.agentOpen(q,p,current), prepare: (q,current) => this.agentPrepare(q,current),
      apply: (q,b,current,claimed) => this.agentApply(q,b,current,claimed), close: q => {
        if (this.agentLinked(q)) { this.change({type:'close-request',reason:'user'}); this.process(); }
      },
    });
    this.agent.subscribe(() => {
      if (this.disposed) return;
      this.state = {...this.state}; // Same App owner also retains pre-admission callers/draft.
      for (const listener of this.listeners) listener();
      this.process();
    });
  }
  private agentLinked(q: WorkflowEditOrigin): boolean {
    return !!this.agentOrigin && sameWorkflowEditOrigin(this.agentOrigin,q) && this.agentBinding !== null && this.state.attempt?.binding === this.agentBinding;
  }
  ownerReason(projectId: string): string | null { return this.agent.busyReason() ?? workflowOwnerReason(this.state,projectId); }
  retainsDraft(projectId: string): boolean { return this.agent.retainsDraft(projectId) || workflowRetainsDraft(this.state,projectId); }
  private async checkAgentNative(): Promise<boolean> {
    const api = this.api, prior = this.reading;
    if (prior) await prior;
    // A previously coalesced status is not this explicit Check's comparison.
    if (!api || this.api !== api || this.disposed || this.reading) return false;
    await this.checkStatus();
    return !this.disposed && this.api === api && this.state.initialized && this.state.listening &&
      !this.state.readPending && !this.state.observationIssue && !this.state.integrityFailed && !this.state.generationLost;
  }
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
    if (api.mode === 'native') { await this.checkStatus(); await this.agent.connect(api); }
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
  startReason(): string | null { return this.agent.busyReason() ?? this.originalStartReason(); }
  private originalStartReason(): string | null {
    const project = this.context.selectedProject();
    return workflowStartReason(this.state, project, this.context.setup(), project ? this.context.otherEditReason(project.project.id) : null);
  }
  recoveryStartReason(): string | null {
    if (this.agent.busyReason()) return this.agent.busyReason();
    const project = this.context.selectedProject();
    return workflowRecoveryStartReason(this.state, project, project ? this.context.otherEditReason(project.project.id) : null);
  }
  inspectRecovery(): boolean {
    if (this.disposed || !this.api || this.api.mode !== 'native' || this.recoveryStartReason() !== null) return false;
    const project = this.context.selectedProject(); const status = this.state.status;
    if (!project || !status) return false;
    const binding: WorkflowRecoveryBinding = freeze({ intent: 'recover', projectId: project.project.id,
      windowGeneration: status.windowGeneration, startStatusRevision: status.statusRevision,
      previousTerminalId: status.lastTerminal?.sessionId ?? null });
    const previous = this.state.attempt;
    this.change({ type: 'begin', binding });
    if (this.state.attempt === previous || this.state.attempt?.binding !== binding) return false;
    void this.command('open', binding, () => this.api!.openGitHubWorkflowRecovery(binding.projectId));
    return true;
  }
  recover(confirmation: WorkflowRecoveryApplyBinding): boolean {
    if (this.agent.isLinked()) return false;
    if (this.disposed || !this.api || !this.state.attempt ||
        !canRecoverWorkflows(this.state, this.context.selectedProject(), confirmation)) return false;
    const binding = this.state.attempt.binding; const previous = this.state.attempt;
    this.change({ type: 'recover-claim', binding: confirmation });
    if (this.state.attempt === previous || !this.state.attempt?.applyClaimed) return false;
    if (this.state.attempt.binding === binding && !this.state.attempt.closeRequested) {
      void this.command('apply', binding, () => this.api!.applyGitHubWorkflowRecovery(confirmation.sessionId, confirmation.planToken));
    }
    return true;
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
    if (this.agent.isLinked()) return false;
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
    this.agent.invalidate(true);
    this.change({ type: 'close-request', reason: 'user' });
    this.process();
  }
  // App calls this synchronously for workspace dispatch and every setup setter
  // or connection generation change, not from a delayed React effect.
  syncContext = (): void => { if (!this.disposed) this.process(); };

  // Invalidate only the new delegated review on explicit context intent,
  // including ABA/no-op actions. Ordinary workflow/recovery behavior is unchanged.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (['select','switch','new-draft','edit','remove-forbidden','undo-removal','reset','snapshot-start','suggest-start','adopt-suggestion','config-save-intent','config-save-final','initialization-intent','initialization-final'].includes(action.type)) this.selectionIntent();
  }
  selectionIntent(): void { if (!this.disposed) this.agent.invalidate(); }
  setVisible(visible: boolean): void { if (!visible) this.selectionIntent(); }

  private process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.processAgain = true; return; }
    this.processing = true;
    try {
      do {
        this.processAgain = false;
        this.agent.process();
        if (this.agent.completedWithoutOriginal() && this.agentBinding) this.change({type:'agent-unentered',binding:this.agentBinding});
        let attempt = this.state.attempt;
        if (!attempt) continue;
        const owner = attempt.projection;
        const terminal = owner?.phase === 'final' || owner?.phase === 'unknown';
        if (!attempt.applyClaimed && !attempt.closeRequested && !attempt.handled && !terminal &&
            (this.state.generationLost || !workflowContextMatches(attempt.binding, this.context.selectedProject(), this.context.setup()))) {
          this.change({ type: 'close-request', reason: 'context_changed' });
        }
        if ((owner?.prepared || owner?.recovery?.prepared) && !workflowPreparedMatches(attempt)) {
          this.change({ type: 'observation-failed', protocol: true });
          this.change({ type: 'close-request', reason: 'invoke_failed' });
        }
        if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled &&
            (attempt.binding !== this.agentBinding || this.agent.mayComplete())) {
          // No configuration-save callback, draft reset or baseline adoption.
          // The retained original projection itself is the read-only result.
          this.change({ type: 'handled', sessionId: owner.sessionId });
          if (attempt.binding === this.agentBinding) this.processAgain = true;
        }
        attempt = this.state.attempt;
        if (!attempt || attempt.handled || !attempt.sessionId || !attempt.projection || this.state.generationLost ||
            attempt.projection.ownerGeneration !== this.state.status?.windowGeneration ||
            ['final', 'unknown'].includes(attempt.projection.phase)) continue;
        if (attempt.closeRequested && !attempt.closeClaimed) {
          const sessionId = attempt.sessionId; const binding = attempt.binding;
          this.change({ type: 'close-claim', sessionId });
          if (this.state.attempt?.binding === binding && this.state.attempt.closeClaimed) void this.command('close', binding, () => this.api!.closeGitHubWorkflowEdit(sessionId)).catch(() => { /* The child retains this missing return. */ });
          continue;
        }
        if (attempt.binding !== this.agentBinding && attempt.projection.phase === 'editing' && !attempt.prepareClaimed &&
            !attempt.closeRequested && !attempt.applyClaimed && !attempt.invalidated) {
          const sessionId = attempt.sessionId; const binding = attempt.binding;
          if (binding.intent === 'recover') {
            const checkout = attempt.projection.recovery?.checkout;
            if (!checkout) continue;
            if (checkout.view.state !== 'recoverable') {
              this.change({ type: 'close-request', reason: 'user' });
              this.processAgain = true;
              continue; // Read-only idle/conflict inspection retires the same owner.
            }
            this.change({ type: 'prepare-claim', sessionId });
            if (this.state.attempt?.binding === binding && this.state.attempt.prepareClaimed && !this.state.attempt.closeRequested) {
              void this.command('prepare', binding, () => this.api!.prepareGitHubWorkflowRecovery(sessionId, checkout.revision));
            }
          } else {
            const checkout = attempt.projection.checkout;
            if (!checkout) continue;
            this.change({ type: 'prepare-claim', sessionId });
            if (this.state.attempt?.binding === binding && this.state.attempt.prepareClaimed && !this.state.attempt.closeRequested) {
              void this.command('prepare', binding, () => this.api!.prepareGitHubWorkflowEdit({
                sessionId, revision: checkout.revision, draft: binding.draft, toolingRepository: binding.toolingRepository, toolingSha: binding.toolingSha,
                draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration,
              }));
            }
          }
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }

  private async agentOpen(q: WorkflowEditOrigin, project: ProjectSession, current: () => boolean): Promise<boolean> {
    const api = this.api, service = api?.agentWorkflowEdit, setup = this.context.setup(), status = this.state.status;
    if (!api || !service || this.disposed || !current() || this.context.selectedProject() !== project ||
        this.originalStartReason() !== null || !project.draft || !status) return false;
    const binding: WorkflowDraftBinding = freeze({projectId:project.project.id,
      windowGeneration:status.windowGeneration,startStatusRevision:status.statusRevision,previousTerminalId:status.lastTerminal?.sessionId??null,
      draftRevision:project.revision,baselineGeneration:project.baselineGeneration,baseline:structuredClone(project.baseline),draft:structuredClone(project.draft),
      serviceGeneration:setup.serviceGeneration,selectionGeneration:setup.selectionGeneration,coordinateGeneration:setup.coordinateGeneration,
      toolingRepository:setup.inputs.toolingRepository,toolingSha:setup.inputs.toolingSha});
    // Bind before notifying: events cannot turn this into ordinary auto-Prepare.
    this.agentBinding = binding; this.agentOrigin = q;
    this.change({type:'begin',binding});
    if (this.api !== api || !current() || this.state.attempt?.binding !== binding || this.state.attempt.closeRequested) return false;
    return this.command('open',binding,() => service.open(q,{projectId:binding.projectId,
      toolingRepository:binding.toolingRepository,toolingSha:binding.toolingSha,draftRevision:binding.draftRevision,baselineGeneration:binding.baselineGeneration}));
  }
  private async agentPrepare(q: WorkflowEditOrigin, current: () => boolean): Promise<boolean> {
    const api = this.api, service = api?.agentWorkflowEdit, a = this.state.attempt, checkout = a?.projection?.checkout;
    if (!api || !service || !a || !a.sessionId || !checkout || a.binding.intent === 'recover' || a.projection?.recovery || !this.agentLinked(q) || !current()) return false;
    const binding = a.binding;
    this.change({type:'prepare-claim',sessionId:a.sessionId});
    if (this.api !== api || !current() || this.state.attempt === a || this.state.attempt?.binding !== binding ||
        !this.state.attempt.prepareClaimed || this.state.attempt.closeRequested) return false;
    return this.command('prepare',binding,() => service.prepare(q,{sessionId:a.sessionId!,revision:checkout.revision,draft:binding.draft,
      toolingRepository:binding.toolingRepository,toolingSha:binding.toolingSha,draftRevision:binding.draftRevision,baselineGeneration:binding.baselineGeneration}));
  }
  private async agentApply(q: WorkflowEditOrigin, confirmation: WorkflowApplyBinding, current: () => boolean, claimed: () => void): Promise<boolean> {
    const api = this.api, service = api?.agentWorkflowEdit, a = this.state.attempt;
    if (!api || !service || !a || !this.agentLinked(q) || !current() ||
        !canApplyWorkflows(this.state,this.context.selectedProject(),this.context.setup(),confirmation)) return false;
    this.change({type:'apply-claim',binding:confirmation});
    if (this.api !== api || !current() || this.state.attempt === a || this.state.attempt?.binding !== a.binding ||
        !this.state.attempt.applyClaimed || this.state.attempt.closeRequested) return false;
    claimed(); // Before any original invoke; later draft edits never rewrite its result.
    if (this.disposed || this.api !== api || !current() || !this.agentLinked(q) || this.state.attempt?.closeRequested ||
        this.state.generationLost || this.state.status?.windowGeneration !== a.binding.windowGeneration) return false;
    return this.command('apply',a.binding,() => service.apply(q,confirmation.sessionId,confirmation.planToken));
  }
  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: WorkflowBinding, call: () => Promise<GitHubWorkflowEditStatus>): Promise<boolean> {
    const delegated = binding === this.agentBinding;
    if (delegated) this.agentCommands++;
    try {
      this.receive(await call(), 'reply');
      if (delegated && this.state.integrityFailed) throw {code:'GitHubWorkflowStatusInvalid'};
      return true;
    } catch (error) {
      if (delegated) {
        this.agent.callerFailed();
        if (!this.disposed && this.state.attempt?.binding === binding) {
          this.change({type:'observation-failed',protocol:workflowEditError(error).code === 'GitHubWorkflowStatusInvalid'});
          this.change({type:'close-request',reason:'invoke_failed'}); this.process();
        }
        throw error; // Original missing return is not repaired by terminal DATA.
      }
      if (this.disposed || this.state.attempt?.binding !== binding) return false;
      if (this.state.attempt.projection?.phase === 'final' && this.state.attempt.projection.nativeFinality === 'settled') return false;
      const protocol = workflowEditError(error).code === 'GitHubWorkflowStatusInvalid';
      this.change({ type: 'observation-failed', protocol });
      if (kind === 'open' || kind === 'prepare' || protocol) this.change({ type: 'close-request', reason: 'invoke_failed' });
      this.process();
      // Ordinary observation behavior is unchanged; never repeat a write.
      await this.checkStatus();
      return false;
    } finally {
      if (delegated) { this.agentCommands--; this.agent.process(); this.process(); }
    }
  }
  dispose(): void {
    if (this.disposed) return;
    this.agent.dispose();
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
