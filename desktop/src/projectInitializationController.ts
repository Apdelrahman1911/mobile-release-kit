// Initialization-only orchestration using the existing edit observer pattern. The
// shared native EditOwner, not a JS promise/controller, owns all real resources.
import {
  canApplyInitializations, canRecoverInitializations, projectInitializationReducer, initialProjectInitialization,
  confirmedInitialization, initializationContextMatches, initializationPreparedMatches, initializationRecoveryStartReason, initializationStartReason,
  initializationOwnerReason, initializationRetainsDraft,
} from './projectInitialization.ts';
import type { ProjectInitializationState, InitializationApplyBinding, InitializationBinding, InitializationDraftBinding, InitializationEditAction, ConfirmedInitialization, InitializationRecoveryApplyBinding, InitializationRecoveryBinding } from './projectInitialization.ts';
import { parseProjectInitializationStatus, initializationError } from './projectInitializationProtocol.ts';
import type { ProjectInitializationStatus } from './projectInitializationTypes.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { DesktopApi } from './types.ts';
import { ServiceInitializationController } from './serviceInitializationController.ts';
import { sameInitializationOrigin } from './serviceInitializationProtocol.ts';
import type { InitializationOrigin } from './serviceInitializationProtocol.ts';

interface InitializationContext {
  selectedProject: () => ProjectSession | null;
  setup: () => GitHubSetupState;
  otherEditReason: (projectId: string) => string | null;
  onConfirmed: (completion: ConfirmedInitialization) => void;
  onApplyIntent: (projectId: string) => void;
}
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

export class ProjectInitializationController {
  private state: ProjectInitializationState = initialProjectInitialization;
  private api: DesktopApi | null = null;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private processing = false;
  private processAgain = false;
  private disposed = false;
  private readonly context: InitializationContext;
  readonly agent: ServiceInitializationController;
  private agentBinding: InitializationDraftBinding | null = null;
  private agentOrigin: InitializationOrigin | null = null;
  private agentCommands = 0;

  constructor(context: InitializationContext) {
    this.context = context;
    this.agent = new ServiceInitializationController({
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
      this.state = {...this.state}; // App peer/draft guards include pre-admission child custody.
      for (const listener of this.listeners) listener();
      this.process();
    });
  }
  private agentLinked(q: InitializationOrigin): boolean {
    return !!this.agentOrigin && sameInitializationOrigin(this.agentOrigin,q) && this.agentBinding !== null && this.state.attempt?.binding === this.agentBinding;
  }
  ownerReason(projectId: string): string | null { return this.agent.busyReason() ?? initializationOwnerReason(this.state,projectId); }
  retainsDraft(projectId: string): boolean { return this.agent.retainsDraft(projectId) || initializationRetainsDraft(this.state,projectId); }
  private async checkAgentNative(): Promise<boolean> {
    const api = this.api, prior = this.reading;
    if (prior) await prior;
    // A coalesced read cannot be this Check's fresh native comparison.
    if (!api || this.api !== api || this.disposed || this.reading) return false;
    await this.checkStatus();
    return !this.disposed && this.api === api && this.state.initialized && this.state.listening &&
      !this.state.readPending && !this.state.observationIssue && !this.state.integrityFailed && !this.state.generationLost;
  }
  getSnapshot = (): ProjectInitializationState => this.state;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  private change(action: InitializationEditAction): void {
    const next = projectInitializationReducer(this.state, action);
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
        const unlisten = await api.subscribeProjectInitialization((status) => this.receive(status, 'event'));
        if (this.disposed) { unlisten(); return; }
        this.unlisten = unlisten;
        this.change({ type: 'listening' });
      }
      if (!this.disposed) this.receive(await api.projectInitializationStatus(), 'read');
    } catch (error) {
      if (!this.disposed) {
        const protocol = initializationError(error).code === 'ProjectInitializationStatusInvalid';
        this.change({ type: 'observation-failed', protocol });
        if (protocol) { this.change({ type: 'close-request', reason: 'invoke_failed' }); this.process(); }
      }
    }
  }
  private receive(value: unknown, source: 'read' | 'event' | 'reply'): void {
    if (this.disposed) return;
    const status = parseProjectInitializationStatus(value);
    if (!status) this.change({ type: 'observation-failed', protocol: true });
    else this.change({ type: 'observe', status: freeze(structuredClone(status)), source });
    if (this.state.integrityFailed) this.change({ type: 'close-request', reason: 'invoke_failed' });
    this.process();
  }
  startReason(): string | null { return this.agent.busyReason() ?? this.originalStartReason(); }
  private originalStartReason(): string | null {
    const project = this.context.selectedProject();
    return initializationStartReason(this.state, project, this.context.setup(), project ? this.context.otherEditReason(project.project.id) : null);
  }
  recoveryStartReason(): string | null {
    if (this.agent.busyReason()) return this.agent.busyReason();
    const project = this.context.selectedProject();
    return initializationRecoveryStartReason(this.state, project, project ? this.context.otherEditReason(project.project.id) : null);
  }
  inspectRecovery(): boolean {
    if (this.disposed || !this.api || this.api.mode !== 'native' || this.recoveryStartReason() !== null) return false;
    const project = this.context.selectedProject(); const status = this.state.status;
    if (!project || !status) return false;
    const binding: InitializationRecoveryBinding = freeze({ intent: 'recover', projectId: project.project.id,
      windowGeneration: status.windowGeneration, startStatusRevision: status.statusRevision,
      previousTerminalId: status.lastTerminal?.sessionId ?? null });
    const previous = this.state.attempt;
    this.change({ type: 'begin', binding });
    if (this.state.attempt === previous || this.state.attempt?.binding !== binding) return false;
    void this.command('open', binding, () => this.api!.openProjectInitialization({projectId:binding.projectId,intent:'recover'}));
    return true;
  }
  recover(confirmation: InitializationRecoveryApplyBinding): boolean {
    if (this.agent.isLinked()) return false;
    if (this.disposed || !this.api || !this.state.attempt ||
        !canRecoverInitializations(this.state, this.context.selectedProject(), confirmation)) return false;
    const binding = this.state.attempt.binding; const previous = this.state.attempt;
    this.change({ type: 'recover-claim', binding: confirmation });
    if (this.state.attempt === previous || !this.state.attempt?.applyClaimed) return false;
    this.context.onApplyIntent(binding.projectId);
    if (this.state.attempt.binding === binding && !this.state.attempt.closeRequested) {
      void this.command('apply', binding, () => this.api!.applyProjectInitialization(confirmation.sessionId, confirmation.planToken,'recover'));
    }
    return true;
  }
  start(): boolean {
    if (this.disposed || !this.api || this.api.mode !== 'native' || this.startReason() !== null) return false;
    const project = this.context.selectedProject(); const setup = this.context.setup(); const status = this.state.status;
    if (!project?.draft || !status) return false;
    const binding: InitializationDraftBinding = freeze({
      intent: 'initialize', projectId: project.project.id, windowGeneration: status.windowGeneration,
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
    void this.command('open', binding, () => this.api!.openProjectInitialization({projectId:binding.projectId,intent:'initialize',draft:binding.draft,toolingRepository:binding.toolingRepository,toolingSha:binding.toolingSha,draftRevision:binding.draftRevision,baselineGeneration:binding.baselineGeneration}));
    return true;
  }
  apply(confirmation: InitializationApplyBinding): boolean {
    if (this.agent.isLinked()) return false;
    if (this.disposed || !this.api || !this.state.attempt ||
        !canApplyInitializations(this.state, this.context.selectedProject(), this.context.setup(), confirmation)) return false;
    const binding = this.state.attempt.binding; const previous = this.state.attempt;
    this.change({ type: 'apply-claim', binding: confirmation });
    if (this.state.attempt === previous || !this.state.attempt?.applyClaimed) return false;
    this.context.onApplyIntent(binding.projectId);
    // A reentrant explicit Close can win before enqueue. Once Apply is sent,
    // input changes preserve its outcome; only explicit cancellation stops it.
    if (this.state.attempt.binding === binding && !this.state.attempt.closeRequested) {
      void this.command('apply', binding, () => this.api!.applyProjectInitialization(confirmation.sessionId, confirmation.planToken,'initialize'));
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

  // Explicit intents retire consent even if a reducer later returns the same
  // value. Submitted Apply keeps its original outcome; never mutate the draft.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if(action.type==='initialization-final'||action.type==='initialization-intent')return;
    if(['select','switch','new-draft','edit','remove-forbidden','undo-removal','reset','snapshot-start','suggest-start','adopt-suggestion','config-save-intent','config-save-final'].includes(action.type))this.retireReview();
  }
  retireReview():void { if(!this.disposed){this.agent.invalidate();this.change({type:'close-request',reason:'context_changed'});this.process();} }
  selectionIntent():void{this.retireReview();}
  snapshotIntent():void{this.retireReview();}
  setVisible(visible:boolean):void{if(!visible)this.retireReview();}

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
            (this.state.generationLost || !initializationContextMatches(attempt.binding, this.context.selectedProject(), this.context.setup()))) {
          this.change({ type: 'close-request', reason: 'context_changed' });
        }
        if (owner?.prepared && !initializationPreparedMatches(attempt)) {
          this.change({ type: 'observation-failed', protocol: true });
          this.change({ type: 'close-request', reason: 'invoke_failed' });
        }
        if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled &&
            (attempt.binding !== this.agentBinding || this.agent.mayComplete())) {
          const completion=confirmedInitialization(this.state);
          this.change({ type: 'handled', sessionId: owner.sessionId });
          if (attempt.binding === this.agentBinding) this.processAgain = true; // Revisit an already-observed next queue only after handling this original.
          // Latch before a reentrant App dispatch. Only this original submitted
          // initialization records completion; no input draft becomes saved bytes.
          if(completion)this.context.onConfirmed(completion);
        }
        attempt = this.state.attempt;
        if (!attempt || attempt.handled || !attempt.sessionId || !attempt.projection || this.state.generationLost ||
            attempt.projection.ownerGeneration !== this.state.status?.windowGeneration ||
            ['final', 'unknown'].includes(attempt.projection.phase)) continue;
        if (attempt.closeRequested && !attempt.closeClaimed) {
          const sessionId = attempt.sessionId; const binding = attempt.binding;
          this.change({ type: 'close-claim', sessionId });
          if (this.state.attempt?.binding === binding && this.state.attempt.closeClaimed) void this.command('close', binding, () => this.api!.discardProjectInitialization(sessionId)).catch(() => { /* The child retains this missing return. */ });
          continue;
        }
        if (attempt.binding !== this.agentBinding && attempt.projection.phase === 'editing' && !attempt.prepareClaimed &&
            !attempt.closeRequested && !attempt.applyClaimed && !attempt.invalidated) {
          const sessionId = attempt.sessionId; const binding = attempt.binding;
          const checkout=attempt.projection.checkout;
          if(!checkout||checkout.intent!==binding.intent)continue;
          if(checkout.intent==='recover'&&checkout.recovery.state!=='recoverable'){
            this.change({type:'close-request',reason:'user'});this.processAgain=true;continue;
          }
          this.change({type:'prepare-claim',sessionId});
          if(this.state.attempt?.binding===binding&&this.state.attempt.prepareClaimed&&!this.state.attempt.closeRequested){
            void this.command('prepare',binding,()=>this.api!.prepareProjectInitialization(sessionId,checkout.revision,binding.intent));
          }
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }

  private async agentOpen(q: InitializationOrigin, project: ProjectSession, current: () => boolean): Promise<boolean> {
    const api = this.api, service = api?.agentInitialization, setup = this.context.setup(), status = this.state.status;
    if (!api || !service || this.disposed || !current() || this.context.selectedProject() !== project ||
        this.originalStartReason() !== null || !project.draft || !status) return false;
    const binding: InitializationDraftBinding = freeze({intent:'initialize',projectId:project.project.id,
      windowGeneration:status.windowGeneration,startStatusRevision:status.statusRevision,previousTerminalId:status.lastTerminal?.sessionId??null,
      draftRevision:project.revision,baselineGeneration:project.baselineGeneration,baseline:structuredClone(project.baseline),draft:structuredClone(project.draft),
      serviceGeneration:setup.serviceGeneration,selectionGeneration:setup.selectionGeneration,coordinateGeneration:setup.coordinateGeneration,
      toolingRepository:setup.inputs.toolingRepository,toolingSha:setup.inputs.toolingSha});
    // Private association precedes reducer publication; no event can turn this
    // original into an ordinary GUI auto-Prepare or a second writer.
    this.agentBinding = binding; this.agentOrigin = q;
    this.change({type:'begin',binding});
    if (this.api !== api || !current() || this.state.attempt?.binding !== binding || this.state.attempt.closeRequested) return false;
    return this.command('open',binding,() => service.open(q,{projectId:binding.projectId,intent:'initialize',draft:binding.draft,
      toolingRepository:binding.toolingRepository,toolingSha:binding.toolingSha,draftRevision:binding.draftRevision,baselineGeneration:binding.baselineGeneration}));
  }
  private async agentPrepare(q: InitializationOrigin, current: () => boolean): Promise<boolean> {
    const api = this.api, service = api?.agentInitialization, a = this.state.attempt, checkout = a?.projection?.checkout;
    if (!api || !service || !a || !a.sessionId || !checkout || checkout.intent !== 'initialize' || !this.agentLinked(q) || !current()) return false;
    const binding = a.binding;
    this.change({type:'prepare-claim',sessionId:a.sessionId});
    if (this.api !== api || !current() || this.state.attempt === a || this.state.attempt?.binding !== binding ||
        !this.state.attempt.prepareClaimed || this.state.attempt.closeRequested) return false;
    return this.command('prepare',binding,() => service.prepare(q,a.sessionId!,checkout.revision));
  }
  private async agentApply(q: InitializationOrigin, confirmation: InitializationApplyBinding, current: () => boolean, claimed: () => void): Promise<boolean> {
    const api = this.api, service = api?.agentInitialization, a = this.state.attempt;
    if (!api || !service || !a || !this.agentLinked(q) || !current() ||
        !canApplyInitializations(this.state,this.context.selectedProject(),this.context.setup(),confirmation)) return false;
    this.change({type:'apply-claim',binding:confirmation});
    if (this.api !== api || !current() || this.state.attempt === a || this.state.attempt?.binding !== a.binding ||
        !this.state.attempt.applyClaimed || this.state.attempt.closeRequested) return false;
    claimed(); // Before App's intentional initialization-intent invalidation.
    this.context.onApplyIntent(a.binding.projectId);
    if (this.disposed || this.api !== api || !this.agentLinked(q) || this.state.attempt?.closeRequested ||
        this.state.generationLost || this.state.status?.windowGeneration !== a.binding.windowGeneration) return false;
    return this.command('apply',a.binding,() => service.apply(q,confirmation.sessionId,confirmation.planToken));
  }
  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: InitializationBinding, call: () => Promise<ProjectInitializationStatus>): Promise<boolean> {
    const delegated = binding === this.agentBinding;
    if (delegated) this.agentCommands++;
    try {
      this.receive(await call(), 'reply');
      if (delegated && this.state.integrityFailed) throw {code:'ProjectInitializationStatusInvalid'};
      return true;
    } catch (error) {
      if (delegated) {
        this.agent.callerFailed();
        if (!this.disposed && this.state.attempt?.binding === binding) {
          this.change({type:'observation-failed',protocol:initializationError(error).code === 'ProjectInitializationStatusInvalid'});
          this.change({type:'close-request',reason:'invoke_failed'}); this.process();
        }
        throw error; // Exact child Promise stays unconfirmed, even after Final DATA.
      }
      if (this.disposed || this.state.attempt?.binding !== binding) return false;
      if (this.state.attempt.projection?.phase === 'final' && this.state.attempt.projection.nativeFinality === 'settled') return false;
      const protocol = initializationError(error).code === 'ProjectInitializationStatusInvalid';
      this.change({ type: 'observation-failed', protocol });
      if (kind === 'open' || kind === 'prepare' || protocol) this.change({ type: 'close-request', reason: 'invoke_failed' });
      this.process();
      // Ordinary existing behavior: observe once, never resend a mutation.
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
      try { void this.api.discardProjectInitialization(attempt.sessionId).catch(() => { /* Original native lifecycle still owns settlement. */ }); }
      catch { /* No completion claim or retry from renderer destruction. */ }
    }
    try { this.unlisten?.(); } catch { /* An observer close is not native finality. */ }
    this.unlisten = null;
    this.listeners.clear();
  }
}
