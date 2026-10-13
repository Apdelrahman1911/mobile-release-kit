// Initialization-only orchestration using the existing edit observer pattern. The
// shared native EditOwner, not a JS promise/controller, owns all real resources.
import {
  canApplyInitializations, canRecoverInitializations, projectInitializationReducer, initialProjectInitialization,
  confirmedInitialization, initializationContextMatches, initializationPreparedMatches, initializationRecoveryStartReason, initializationStartReason,
} from './projectInitialization.ts';
import type { ProjectInitializationState, InitializationApplyBinding, InitializationBinding, InitializationDraftBinding, InitializationEditAction, ConfirmedInitialization, InitializationRecoveryApplyBinding, InitializationRecoveryBinding } from './projectInitialization.ts';
import { parseProjectInitializationStatus, initializationError } from './projectInitializationProtocol.ts';
import type { ProjectInitializationStatus } from './projectInitializationTypes.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { DesktopApi } from './types.ts';

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

  constructor(context: InitializationContext) { this.context = context; }
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
  startReason(): string | null {
    const project = this.context.selectedProject();
    return initializationStartReason(this.state, project, this.context.setup(), project ? this.context.otherEditReason(project.project.id) : null);
  }
  recoveryStartReason(): string | null {
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
  retireReview():void { if(!this.disposed){this.change({type:'close-request',reason:'context_changed'});this.process();} }
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
        if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled) {
          const completion=confirmedInitialization(this.state);
          this.change({ type: 'handled', sessionId: owner.sessionId });
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
          if (this.state.attempt?.binding === binding && this.state.attempt.closeClaimed) void this.command('close', binding, () => this.api!.discardProjectInitialization(sessionId));
          continue;
        }
        if (attempt.projection.phase === 'editing' && !attempt.prepareClaimed &&
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

  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: InitializationBinding, call: () => Promise<ProjectInitializationStatus>): Promise<void> {
    try { this.receive(await call(), 'reply'); }
    catch (error) {
      if (this.disposed || this.state.attempt?.binding !== binding) return;
      if (this.state.attempt.projection?.phase === 'final' && this.state.attempt.projection.nativeFinality === 'settled') return;
      const protocol = initializationError(error).code === 'ProjectInitializationStatusInvalid';
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
      try { void this.api.discardProjectInitialization(attempt.sessionId).catch(() => { /* Original native lifecycle still owns settlement. */ }); }
      catch { /* No completion claim or retry from renderer destruction. */ }
    }
    try { this.unlisten?.(); } catch { /* An observer close is not native finality. */ }
    this.unlisten = null;
    this.listeners.clear();
  }
}
