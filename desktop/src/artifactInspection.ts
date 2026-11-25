// App-owned coordination, not a native owner or a cleanup receipt. A page,
// Promise, generation or listener cannot settle/reconstruct the original run.
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { ApiError, BridgeMode } from './types.ts';
import type { ArtifactInspectionApi, ArtifactInspectionContext, ArtifactInspectionIdentity, ArtifactInspectionOperation,
  ArtifactInspectionStatus, PrepareArtifactInspection, SavedConfigContent } from './artifactInspectionTypes.ts';
import { ARTIFACT_INSPECTION_CONSENT, ARTIFACT_INSPECTION_CONSENT_MS, ARTIFACT_INSPECTION_COUNTER_MAX, copyArtifactInspectionRequest,
  artifactAvailabilityText, artifactCounter, artifactOperationProgress, artifactInspectionError, parseArtifactInspectionStatus,
  sameArtifactData, sameArtifactIdentity } from './artifactInspectionProtocol.ts';
import { parseSavedConfigContent } from './offlinePreflightProtocol.ts';
import type { ArtifactFormat, ArtifactRole, PickArtifactInspection, ArtifactInspectionSelection } from './artifactInspectionTypes.ts';

export interface ArtifactInspectionProject {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  savedConfig: SavedConfigContent | null; dirtyDraft: boolean; invalidDraft:boolean; staleSaved:boolean; snapshotPending: boolean; saveRecoveryRequired: boolean;
}
export interface ArtifactInspectionBinding {
  context: ArtifactInspectionContext; observationGeneration: number;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
}
export interface ArtifactInspectionConsent extends ArtifactInspectionIdentity {
  binding: ArtifactInspectionBinding; acknowledged: boolean; deadline: number;
}
export interface ArtifactInspectionState {
  mode: BridgeMode; project: ArtifactInspectionProject | null; visible: boolean; selectionPending: boolean; format:ArtifactFormat; pickerPending:boolean; discardPending:boolean;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
  listening: boolean; initialized: boolean; readPending: boolean; status: ArtifactInspectionStatus | null;
  consent: ArtifactInspectionConsent | null; pending: 'prepare' | 'start' | null; originalUnconfirmed: boolean;
  historical: boolean; cancelClaimed: ArtifactInspectionIdentity | null; error: ApiError | null;
  observationIssue: 'bridge' | 'protocol' | null; nativeBlocked: boolean; integrityFailed: boolean; generationLost: boolean;
}
type Port = ArtifactInspectionApi & { mode: BridgeMode };
interface Observer { api: Port; active: boolean; generation: number; unlisten: (() => void) | null; reading: Promise<void> | null; status: ArtifactInspectionStatus | null }
interface Attempt {
  observer: Observer; binding: ArtifactInspectionBinding; previous: ArtifactInspectionIdentity | null; after: number;
  identity: ArtifactInspectionIdentity | null; prepareSent: boolean; prepareReply: boolean; deadline: number;
  startSent: boolean; startAfter: number; retired: boolean; settled: boolean;
}
interface SelectionBinding {nativeGeneration:number;projectId:string;connection:number;selection:number;context:number}
interface PickAttempt {observer:Observer;request:PickArtifactInspection;before:ArtifactInspectionStatus;binding:SelectionBinding;sent:boolean;settled:boolean}
interface Context { selectedProject: () => ProjectSession | null; otherOperationReason: () => string | null; now?: () => number }
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
const id = (op: ArtifactInspectionIdentity): ArtifactInspectionIdentity => ({ operationId: op.operationId, ownerGeneration: op.ownerGeneration });
const selectionActive=(selection:ArtifactInspectionSelection|undefined):boolean=>!!selection&&['picking','stopping','unknown'].includes(selection.phase);
const active = (op: ArtifactInspectionOperation | null | undefined): boolean => !!op && op.phase !== 'terminal';
export function artifactInspectionOwnerReason(state: ArtifactInspectionState): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost) return 'Artifact-inspection ownership or finality is unverified. Keep the original status; conflicting work is disabled.';
  if (state.originalUnconfirmed || state.pending || state.pickerPending || state.discardPending || selectionActive(state.status?.selection) || active(state.status?.operation)) return 'Artifact inspection hold the original intent or execution slot. Cancel or settle that original operation before conflicting work.';
  if (state.mode === 'native' && state.observationIssue) return 'The original artifact-inspection status is unverified. Check retained status before conflicting work.';
  return null;
}

export class ArtifactInspectionController {
  private state: ArtifactInspectionState = freeze<ArtifactInspectionState>({ mode: 'unavailable', project: null, visible: false, selectionPending: false, format:'aab',pickerPending:false,discardPending:false,
    connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0, requestGeneration: 0,
    listening: false, initialized: false, readPending: false, status: null, consent: null, pending: null, originalUnconfirmed: false,
    historical: false, cancelClaimed: null, error: null, observationIssue: null, nativeBlocked: false, integrityFailed: false, generationLost: false });
  private readonly context: Context;
  private observer: Observer | null = null;
  private attempt: Attempt | null = null;
  private pickClaim:PickAttempt|null=null;
  private discardClaim:object|null=null;
  private selectionBinding:SelectionBinding|null=null;
  private consumedSelection:number|null=null;
  private consumedIds:readonly string[]=[];
  private cancelClaim: ArtifactInspectionIdentity | null = null;
  private draftReference: ProjectSession['draft'] = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Set<() => void>();
  private disposed = false;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): ArtifactInspectionState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private now(): number { return (this.context.now ?? (() => performance.now()))(); }
  private update(patch: Partial<ArtifactInspectionState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private advance(field: 'connectionGeneration' | 'selectionGeneration' | 'contextGeneration' | 'requestGeneration'): Partial<ArtifactInspectionState> {
    const next = this.state[field] + 1;
    return { [field]: Math.min(next, ARTIFACT_INSPECTION_COUNTER_MAX), generationLost: this.state.generationLost || !artifactCounter(next) };
  }
  private clearTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private retire(patch: Partial<ArtifactInspectionState> = {}, stop = true): void {
    this.clearTimer();
    if (this.attempt) this.attempt.retired = true;
    // Burn before any subscriber, reducer, early return or asynchronous STOP.
    this.update({ ...patch, consent: null, historical: !!this.state.status?.operation || this.state.historical });
    if (stop) this.stopOriginal();
  }
  private fail(error: unknown, protocol = false): void {
    const safe=artifactInspectionError(error);
    const sticky=protocol||safe.code==='protocol_error'||safe.code==='cleanup_unknown';
    this.retire({ error: safe, observationIssue: sticky ? 'protocol' : 'bridge',
      integrityFailed: this.state.integrityFailed || sticky, nativeBlocked: this.state.nativeBlocked || sticky });
  }
  // Must be called before workspaceReducer, including actions it will reject or
  // regard as unchanged. Away-and-back and equal-byte edits never revive consent.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (this.disposed) return;
    if (action.type === 'select' || action.type === 'switch') { this.selectionIntent(); return; }
    const relevant = ['snapshot-start', 'snapshot-done', 'snapshot-failed', 'new-draft', 'edit', 'remove-forbidden', 'undo-removal',
      'forget-removal', 'reset', 'adopt-suggestion', 'config-save-intent', 'config-save-final', 'config-save-recovery',
      'initialization-intent','initialization-final','validate-start','validate-done','validate-failed'];
    if (relevant.includes(action.type) && (action.projectId === this.state.project?.projectId || action.projectId === this.attempt?.binding.context.projectId))
      this.retire(this.advance('contextGeneration'));
  }
  selectionIntent(): void { if (!this.disposed) this.retire(this.advance('selectionGeneration')); }
  snapshotIntent(projectId: string): void {
    if (!this.disposed && (projectId === this.state.project?.projectId || projectId === this.attempt?.binding.context.projectId))
      this.retire(this.advance('contextGeneration'));
  }
  // Version Save intents and every outcome retire prior saved-input consent,
  // including unchanged/refused saves that do not change config generations.
  versionIntent(): void { if (!this.disposed) this.retire(this.advance('contextGeneration')); }
  setSelectionPending(selectionPending: boolean): void {
    if (!this.disposed && selectionPending !== this.state.selectionPending) this.retire({ ...this.advance('selectionGeneration'), selectionPending });
  }
  syncProject(): void {
    if (this.disposed) return;
    const project = this.context.selectedProject();
    const next: ArtifactInspectionProject | null = project ? { projectId: project.project.id, draftRevision: project.revision,
      baselineGeneration: project.baselineGeneration, observationGeneration: project.observationGeneration,
      savedConfig: parseSavedConfigContent(project.savedConfigContent), dirtyDraft: isDirty(project),
      invalidDraft:project.draft===null||(project.validatedRevision===project.revision&&project.validatedBaselineGeneration===project.baselineGeneration&&project.validation?.valid===false),
      staleSaved:project.sourceChanged||project.snapshotPredatesSave||project.snapshotError!==null,
      snapshotPending: project.snapshotRequest !== null, saveRecoveryRequired: project.saveRecoveryRequired } : null;
    const draft = project?.draft ?? null;
    if (sameArtifactData(next, this.state.project) && this.draftReference === draft) return;
    this.draftReference = draft;
    const badCounter = next !== null && ![next.draftRevision, next.baselineGeneration, next.observationGeneration].every(artifactCounter);
    this.retire({ ...this.advance('contextGeneration'), project: next, generationLost: this.state.generationLost || badCounter ||
      this.state.contextGeneration === ARTIFACT_INSPECTION_COUNTER_MAX });
  }
  setVisible(visible: boolean): void {
    if (this.disposed || visible === this.state.visible) return;
    // Leaving a consent view retires its unchecked/checked intent. A STARTED
    // run is app-owned: ordinary page navigation keeps its status and Cancel.
    if (!visible && this.attempt && !this.attempt.startSent && !this.attempt.settled) this.retire({ ...this.advance('contextGeneration'), visible });
    else this.update({ visible });
  }
  private needsOriginal(observer: Observer): boolean {
    return this.pickClaim?.observer===observer&&this.pickClaim.sent&&!this.pickClaim.settled || !!this.discardClaim || selectionActive(observer.status?.selection) || this.attempt?.observer === observer && this.attempt.prepareSent && !this.attempt.settled || active(observer.status?.operation);
  }
  private detach(observer: Observer): void {
    observer.active = false;
    try { observer.unlisten?.(); } catch { /* Listener release is not original native settlement. */ }
    observer.unlisten = null;
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.retire(this.advance('connectionGeneration'));
    const observer = this.observer;
    if (observer && (this.needsOriginal(observer) || this.state.nativeBlocked || this.state.integrityFailed)) {
      // Keep ORIGINAL subscription, API and owner rooted. Do not attach the new
      // document or transfer its status into this operation, even after cleanup.
      this.update({ nativeBlocked: true, historical: true }); return;
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
      const unlisten = await api.subscribeArtifactInspection((value) => { if (observer.active) this.receive(observer, value); });
      if (!observer.active || this.observer !== observer || this.disposed && !this.needsOriginal(observer)) { unlisten(); return; }
      observer.unlisten = unlisten;
      this.update({ listening: true });
      await this.checkStatus();
    } catch (error) { if (observer.active) this.fail(error); }
  }
  private matches(attempt: Attempt): boolean {
    const p = this.state.project, b = attempt.binding;
    return !this.disposed && !attempt.retired && this.attempt === attempt && this.observer === attempt.observer && attempt.observer.active &&
      b.connectionGeneration === this.state.connectionGeneration && b.selectionGeneration === this.state.selectionGeneration &&
      b.contextGeneration === this.state.contextGeneration && b.requestGeneration === this.state.requestGeneration &&
      p !== null && b.observationGeneration === p.observationGeneration && b.context.projectId === p.projectId &&
      attempt.binding.context.format===this.state.format && this.selectionMatches(attempt.startSent) && b.context.draftRevision === p.draftRevision && b.context.baselineGeneration === p.baselineGeneration && sameArtifactData(b.context.savedConfig, p.savedConfig);
  }
  private originCandidate(attempt: Attempt, status: ArtifactInspectionStatus): boolean {
    const op = status.operation;
    return !!op && status.statusRevision > attempt.after && !sameArtifactIdentity(op, attempt.previous) &&
      sameArtifactData(op.context, attempt.binding.context) && (!attempt.identity || sameArtifactIdentity(op, attempt.identity));
  }
  private reconcile(observer: Observer): void {
    const status = observer.status, attempt = this.attempt, op = status?.operation;
    if (!status || !op) return;
    const matched = attempt?.observer === observer && sameArtifactIdentity(attempt.identity, op);
    if (attempt && matched && op.phase === 'terminal') attempt.settled = true;
    const finished = !!attempt && matched && attempt.settled;
    const startObserved = !!attempt && matched && attempt.startSent && status.statusRevision > attempt.startAfter && op.phase !== 'awaiting-consent';
    const blocked = this.state.nativeBlocked || (['shutdown', 'document-lost', 'cleanup-unknown'].includes(status.availability)||status.selection.phase==='unknown') || op.phase === 'unknown';
    const consent = this.state.consent;
    this.update({ status, initialized: true, nativeBlocked: blocked,
      pending: finished || startObserved ? null : this.state.pending,
      originalUnconfirmed: finished || startObserved ? false : this.state.originalUnconfirmed,
      historical: !attempt || !matched || attempt.retired || !this.matches(attempt),
      consent: attempt && consent && matched && this.matches(attempt) && !blocked && !attempt.startSent && op.phase === 'awaiting-consent' && op.intentUsable ? consent : null });
    if (!this.state.consent) this.clearTimer();
    if (attempt?.retired) this.stopOriginal();
    if (this.disposed && !this.needsOriginal(observer)) this.detach(observer);
  }
  private receive(observer: Observer, value: unknown): ArtifactInspectionStatus | null {
    if (!observer.active) return null;
    const status = parseArtifactInspectionStatus(value);
    if (!status) { this.fail({ code: 'artifact_inspection_protocol' }, true); return null; }
    const previous = observer.status, a = previous?.operation, b = status.operation;
    if (previous && status.statusRevision < previous.statusRevision) {
      if (a && b && sameArtifactIdentity(a, b) && !artifactOperationProgress(b, a)) this.fail({ code: 'artifact_inspection_protocol' }, true);
      return status;
    }
    if (previous && status.statusRevision === previous.statusRevision && !sameArtifactData(previous, status)) {
      this.fail({ code: 'artifact_inspection_protocol' }, true); return null;
    }
    if (a && b && sameArtifactIdentity(a, b) && !artifactOperationProgress(a, b)) {
      this.fail({ code: 'artifact_inspection_protocol' }, true); return null;
    }
    if(!this.receiveSelection(observer,status,previous))return null;
    const attempt = this.attempt;
    if (this.discardClaim && b===null && status.selection.phase==='idle') {
      if(attempt?.observer===observer){attempt.retired=true;attempt.settled=true;}
    } else if (attempt?.observer === observer && attempt.prepareSent) {
      if (attempt.identity ? !sameArtifactIdentity(attempt.identity, b) :
          b && !sameArtifactIdentity(b, attempt.previous) && !this.originCandidate(attempt, status)) {
        this.fail({ code: 'artifact_inspection_protocol' }, true); return null;
      }
      if (b && this.originCandidate(attempt, status) && !attempt.startSent &&
          (b.phase === 'starting' || b.phase === 'running' || b.outcome === 'complete')) {
        this.fail({ code: 'artifact_inspection_protocol' }, true); return null;
      }
    } else if (previous && !sameArtifactIdentity(a ?? null, b) && (a !== null || b !== null)) {
      // Unsolicited foreign IDs cannot replace a result or authorize a run.
      this.fail({ code: 'artifact_inspection_protocol' }, true); return null;
    }
    if (status.statusRevision === ARTIFACT_INSPECTION_COUNTER_MAX) this.retire({ generationLost: true });
    observer.status = status;
    if (observer === this.observer) {
      this.update({ status, initialized: true, nativeBlocked: this.state.nativeBlocked ||
        (['shutdown', 'document-lost', 'cleanup-unknown'].includes(status.availability)||status.selection.phase==='unknown'), historical: this.state.historical || !attempt });
      this.reconcile(observer);
      this.expireConsent();
      if(this.disposed&&!this.needsOriginal(observer))this.detach(observer);
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
        const status = this.receive(observer, await observer.api.artifactInspectionStatus());
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
  private selectionContext(nativeGeneration:number):SelectionBinding|null {
    const project=this.state.project;
    return project?{nativeGeneration,projectId:project.projectId,connection:this.state.connectionGeneration,
      selection:this.state.selectionGeneration,context:this.state.contextGeneration}:null;
  }
  private bindingCurrent(binding:SelectionBinding):boolean {
    return !this.disposed&&binding.projectId===this.state.project?.projectId&&binding.connection===this.state.connectionGeneration&&
      binding.selection===this.state.selectionGeneration&&binding.context===this.state.contextGeneration;
  }
  private selectedIds():PrepareArtifactInspection['selections'] {
    const items=this.state.status?.selection.items??[];
    return {artifact:items.find(item=>item.role==='artifact')?.selectionId??'',archive:items.find(item=>item.role==='archive')?.selectionId??null,
      dsyms:items.find(item=>item.role==='dsyms')?.selectionId??null};
  }
  private selectionMatches(allowConsumed=false):boolean {
    const selected=this.state.status?.selection,binding=this.selectionBinding;
    return !!selected&&!!binding&&this.bindingCurrent(binding)&&binding.nativeGeneration===selected.generation&&
      selected.phase==='ready'&&selected.projectId===this.state.project?.projectId&&selected.format===this.state.format&&
      selected.items.some(item=>item.role==='artifact')&&(allowConsumed||this.consumedSelection!==selected.generation);
  }
  setFormat(format:ArtifactFormat):void {
    if(!['aab','ipa'].includes(format)||format===this.state.format||artifactInspectionOwnerReason(this.state))return;
    this.retire({...this.advance('contextGeneration'),format});
  }
  pickReason(role:ArtifactRole='artifact'):string|null {
    return this.commonReason()??artifactInspectionOwnerReason(this.state)??
      (this.state.status?.availability==='busy'?artifactAvailabilityText.busy:null)??
      (!['artifact','archive','dsyms'].includes(role)?'Choose a supported fixed artifact role.':null)??
      (this.state.format==='aab'&&role!=='artifact'?'AAB inspection accepts only the AAB file.':null)??
      (role!=='artifact'&&(!this.selectionMatches()||role==='dsyms'&&!this.selectedIds().archive)?'Select the current IPA first, then its archive before debug symbols.':null);
  }
  private selectionData(selection:ArtifactInspectionSelection):unknown {
    return {generation:selection.generation,projectId:selection.projectId,format:selection.format,items:selection.items};
  }
  private receiveSelection(observer:Observer,status:ArtifactInspectionStatus,previous:ArtifactInspectionStatus|null):boolean {
    const selection=status.selection,claim=this.pickClaim;
    if(previous&&selection.generation<previous.selection.generation){this.fail({code:'artifact_inspection_protocol'},true);return false;}
    const changed=previous&&!sameArtifactData(this.selectionData(selection),this.selectionData(previous.selection));
    if(previous?.selection.phase==='unknown'&&selection.phase!=='unknown'){this.fail({code:'artifact_inspection_protocol'},true);return false;}
    if(changed&&!this.discardClaim&&!(claim?.observer===observer&&claim.sent&&!claim.settled)){
      this.fail({code:'artifact_inspection_protocol'},true);return false;
    }
    if(this.discardClaim&&selection.phase==='idle'&&status.operation===null){this.selectionBinding=null;return true;}
    if(!claim||claim.observer!==observer||!claim.sent||claim.settled)return true;
    if(status.statusRevision<=claim.before.statusRevision)return true;
    if(selectionActive(selection)){
      if(selection.phase!=='unknown'&&selection.operation?.role!==claim.request.role){this.fail({code:'artifact_inspection_protocol'},true);return false;}
      return true;
    }
    const sameBefore=sameArtifactData(this.selectionData(selection),this.selectionData(claim.before.selection));
    if(selection.reason==='cancelled'||['source-refused','source-changed','unsupported-format','input-limit'].includes(selection.reason)){
      // A returned promise alone never restores the previous selection. This is
      // a newer, known-settled native panel/probe observation of its exact data.
      if(!sameBefore){this.fail({code:'artifact_inspection_protocol'},true);return false;}
    }else if(selection.phase==='ready'&&selection.reason==='none'&&selection.generation>claim.before.selection.generation&&
      selection.projectId===claim.request.projectId&&selection.format===claim.request.format&&selection.items.some(item=>item.role===claim.request.role)){
      const next=this.selectionContext(selection.generation);
      if(selection.items.some(item=>this.consumedIds.includes(item.selectionId))){this.fail({code:'artifact_inspection_protocol'},true);return false;}
      this.selectionBinding=next&&this.bindingCurrent(claim.binding)?next:null;
      this.retire({historical:!!status.operation},false);
    }else {this.fail({code:'artifact_inspection_protocol'},true);return false;}
    claim.settled=true;this.update({pickerPending:false});
    return true;
  }
  async pick(role:ArtifactRole):Promise<void> {
    this.syncProject();
    if(this.pickReason(role)||!this.observer?.status||!this.state.project)return;
    const observer=this.observer,before=observer.status!,request={projectId:this.state.project.projectId,format:this.state.format,role};
    const binding=this.selectionContext(before.selection.generation);if(!binding)return;
    const claim:PickAttempt={observer,request,before,binding,sent:false,settled:false};
    this.pickClaim=claim;this.update({pickerPending:true,error:null});
    if(!this.bindingCurrent(binding)||this.commonReason()){claim.settled=true;this.update({pickerPending:false});return;}
    claim.sent=true;
    try{
      const value=await observer.api.pickArtifactInspection(request);
      if(!observer.active||this.pickClaim!==claim)return;
      if(!this.receive(observer,value))return;
      // A picking/stopping status intentionally leaves the claim retained.
    }catch(error){
      if(observer.active&&this.pickClaim===claim){
        const safe=artifactInspectionError(error);
        if(['artifact_inspection_invalid','artifact_inspection_unavailable','artifact_inspection_busy'].includes(safe.code)&&observer.status===before){
          claim.settled=true;this.update({pickerPending:false,error:safe});
        }else this.fail(error);
      }
    }
  }
  discardReason():string|null {
    if(this.disposed||this.state.mode!=='native'||!this.observer?.active||!this.state.initialized||this.state.observationIssue||
      this.state.nativeBlocked||this.state.integrityFailed||this.state.generationLost)return 'A known original native status is required; unknown ownership cannot be discarded.';
    if(this.discardClaim||this.state.pickerPending||selectionActive(this.state.status?.selection)||this.state.pending||this.state.originalUnconfirmed)return 'Wait for the original action to settle. Use native Cancel for an active picker.';
    const op=this.state.status?.operation;
    if(op&&op.phase!=='terminal'&&op.phase!=='awaiting-consent')return 'Cancel and settle the original inspection before discarding its selection.';
    return this.context.otherOperationReason();
  }
  async discard():Promise<void> {
    if(this.discardReason()||!this.observer?.status)return;
    const observer=this.observer,status=observer.status!,op=status.operation,claim={};
    this.discardClaim=claim;this.retire({discardPending:true},false);
    try{
      const value=await observer.api.discardArtifactInspection({selectionGeneration:status.selection.generation,
        operationId:op?.operationId??null,ownerGeneration:op?.ownerGeneration??null});
      if(!observer.active||this.discardClaim!==claim)return;
      const result=this.receive(observer,value);
      if(!result||result.statusRevision<=status.statusRevision||result.selection.phase!=='idle'||result.operation!==null){this.fail({code:'artifact_inspection_protocol'},true);return;}
      // Only this newer, known native discard retires the original routing.
      // A late Cancel/Prepare completion must not resurrect the discarded run.
      if(this.attempt?.observer===observer)this.attempt=null;
      this.cancelClaim=null;this.discardClaim=null;this.selectionBinding=null;
      // Keep consumedSelection/consumedIds: discard cannot rearm old inputs.
      this.update({discardPending:false,pending:null,originalUnconfirmed:false,consent:null,cancelClaimed:null,historical:true});
    }catch(error){if(observer.active&&this.discardClaim===claim)this.fail(error);}
  }
  private commonReason(): string | null {
    if (this.disposed || this.state.mode !== 'native') return 'Open the native application. Browser preview cannot prepare or run selected artifact inspection.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return artifactInspectionOwnerReason(this.state);
    if (!this.observer?.active || this.observer.generation !== this.state.connectionGeneration || !this.state.listening || !this.state.initialized || !this.state.status || this.state.observationIssue)
      return 'A current original native status and subscription are required. Check status; do not infer permission from passive capabilities.';
    if (this.state.status.statusRevision >= ARTIFACT_INSPECTION_COUNTER_MAX) return 'The original status counter is exhausted. No counter or intent can be reused.';
    if (!['available', 'busy'].includes(this.state.status.availability)) return artifactAvailabilityText[this.state.status.availability];
    if (!this.state.visible) return 'Open Artifacts to review the selected byte inspection and its limits.';
    if (this.state.selectionPending) return 'Finish the original project selection before reviewing artifact inspection.';
    const project = this.state.project;
    if (!project) return 'Choose a registered source project first; an evidence folder is not an execution target.';
    if (project.saveRecoveryRequired) return 'This project needs its original configuration-save recovery procedure. Artifact inspection cannot reset that attention.';
    if (project.snapshotPending) return 'Wait for the explicit saved snapshot request to settle.';
    if(project.invalidDraft||project.staleSaved)return 'Refresh saved inputs and resolve the invalid or stale draft explicitly before artifact inspection. No automatic save or reset is performed.';
    if (project.dirtyDraft) return 'Save or reset your draft deliberately and refresh its saved observation first. Artifact inspection uses only clean saved inputs and never saves or discards edits.';
    if (!project.savedConfig) return 'Explicitly refresh a format-valid saved configuration observation. Saving or editing a draft does not supply its exact-byte fingerprint.';
    return this.context.otherOperationReason();
  }
  prepareReason = (): string | null => this.commonReason() ?? artifactInspectionOwnerReason(this.state) ??
    (this.state.status?.availability === 'busy' ? artifactAvailabilityText.busy : null) ??
    (!this.selectionMatches()?'Choose the required artifact inputs for this current clean project; old or consumed selections cannot authorize a review.':null);
  runReason = (): string | null => {
    const common = this.commonReason(); if (common) return common;
    const consent = this.state.consent, attempt = this.attempt, op = this.state.status?.operation;
    if (!consent || !attempt || !attempt.prepareReply || attempt.startSent || !this.matches(attempt) || !sameArtifactIdentity(consent, op ?? null) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable) return 'Review a new artifact-inspection intent. A status observation or old acknowledgement cannot authorize Run.';
    const now = this.now();
    if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) return 'This original review has expired. Polling cannot extend it.';
    return consent.acknowledged ? null : 'Acknowledge the inspection scope and limitations for this exact review before Run.';
  };
  private expireConsent(): void {
    const consent = this.state.consent;
    if (!consent) return;
    const now = this.now();
    if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) this.retire();
  }
  private armExpiry(): void {
    this.clearTimer();
    const consent = this.state.consent; if (!consent) return;
    const remaining = consent.deadline - this.now();
    if (!Number.isFinite(remaining) || remaining <= 0) { this.retire(); return; }
    this.timer = setTimeout(() => { this.timer = null; this.expireConsent(); if (this.state.consent) this.armExpiry(); }, Math.min(remaining, ARTIFACT_INSPECTION_CONSENT_MS));
  }
  async prepare(): Promise<void> {
    this.syncProject();
    if (this.prepareReason() || !this.observer || !this.state.project?.savedConfig) return;
    const project = this.state.project;
    const request = copyArtifactInspectionRequest('artifact_inspection_prepare', { projectId: project.projectId, draftRevision: project.draftRevision,
      baselineGeneration: project.baselineGeneration, savedConfig: project.savedConfig,format:this.state.format,
      selections:this.selectedIds() }) as PrepareArtifactInspection | null;
    const now = this.now();
    if (!request || !Number.isFinite(now) || now < 0 || !Number.isFinite(now + ARTIFACT_INSPECTION_CONSENT_MS)) { this.fail({ code: 'artifact_inspection_invalid' }, true); return; }
    const counters = this.advance('requestGeneration');
    if (counters.generationLost) { this.retire(counters); return; }
    const observer = this.observer;
    const binding: ArtifactInspectionBinding = freeze({ context: request,
      observationGeneration: project.observationGeneration, connectionGeneration: this.state.connectionGeneration,
      selectionGeneration: this.state.selectionGeneration, contextGeneration: this.state.contextGeneration, requestGeneration: counters.requestGeneration! });
    const attempt: Attempt = { observer, binding, previous: observer.status?.operation ? id(observer.status.operation) : null,
      after: observer.status?.statusRevision ?? 0, identity: null, prepareSent: false, prepareReply: false, deadline: now + ARTIFACT_INSPECTION_CONSENT_MS,
      startSent: false, startAfter: 0, retired: false, settled: false };
    this.attempt = attempt; this.cancelClaim = null;
    this.update({ ...counters, consent: null, pending: 'prepare', originalUnconfirmed: false, historical: true, cancelClaimed: null, error: null });
    // Synchronous subscribers can edit/select/close. Recheck before the one handoff.
    if (!this.matches(attempt) || this.commonReason()) {
      attempt.retired = true; attempt.settled = true;
      this.update({ pending: null }); return;
    }
    attempt.prepareSent = true;
    this.update({ originalUnconfirmed: true });
    if (!this.matches(attempt) || this.commonReason()) {
      attempt.prepareSent = false; attempt.retired = true; attempt.settled = true;
      this.update({ pending: null, originalUnconfirmed: false }); return;
    }
    try {
      const value = await observer.api.prepareArtifactInspection(request);
      if (!observer.active || this.attempt !== attempt) return;
      const status = parseArtifactInspectionStatus(value), op = status?.operation;
      if (!status || !op || !this.originCandidate(attempt, status) || ['starting', 'running'].includes(op.phase) || op.outcome === 'complete') {
        this.fail({ code: 'artifact_inspection_protocol' }, true); return;
      }
      attempt.identity = id(op); attempt.prepareReply = true;
      if (!this.receive(observer, status)) return;
      this.reconcile(observer);
      this.update({ pending: null, originalUnconfirmed: false });
      const current = observer.status?.operation;
      if (this.matches(attempt) && !this.commonReason() && current?.phase === 'awaiting-consent' && current.intentUsable &&
          sameArtifactIdentity(current, attempt.identity) && this.now() < attempt.deadline) {
        this.update({ consent: { ...id(op), binding, acknowledged: false, deadline: attempt.deadline } });
        this.armExpiry();
      } else {
        attempt.retired = true;
        this.stopOriginal();
      }
    } catch (error) {
      if (observer.active && this.attempt === attempt) {
        const safe = artifactInspectionError(error);
        // Native reserves these codes for PREPARE rejection before allocation.
        // They never release/rearm a Start, or contradict an observed admission.
        if (['artifact_inspection_invalid', 'artifact_inspection_unavailable', 'artifact_inspection_busy'].includes(safe.code) &&
            !attempt.identity && (!observer.status || !this.originCandidate(attempt, observer.status))) {
          attempt.retired = true; attempt.settled = true;
          this.update({ pending: null, originalUnconfirmed: false, consent: null, error: safe });
        } else this.fail(error, safe.code !== 'artifact_inspection_protocol');
      }
    }
  }
  setAcknowledged(operationId: string, ownerGeneration: string, acknowledged: boolean): void {
    this.syncProject(); this.expireConsent();
    const consent = this.state.consent, attempt = this.attempt;
    if (!consent || !attempt || !this.matches(attempt) || this.commonReason() ||
        !sameArtifactIdentity(consent, { operationId, ownerGeneration }) || typeof acknowledged !== 'boolean') return;
    this.update({ consent: { ...consent, acknowledged } });
    // Acknowledgement is never an invocation, a persisted preference or a Start.
  }
  async start(operationId: string, ownerGeneration: string): Promise<void> {
    this.syncProject(); this.expireConsent();
    const attempt = this.attempt, consent = this.state.consent;
    if (!attempt || !consent || !sameArtifactIdentity(consent, { operationId, ownerGeneration }) || this.runReason()) return;
    // Consume locally BEFORE yielding or notifying subscribers. Neither a lost
    // reply nor a same-context status can create another consent or Start.
    this.consumedSelection=this.state.status?.selection.generation??null;
    this.consumedIds=(this.state.status?.selection.items??[]).map(item=>item.selectionId);
    attempt.startSent = true; attempt.startAfter = attempt.observer.status?.statusRevision ?? 0;
    this.clearTimer();
    this.update({ consent: null, pending: 'start', originalUnconfirmed: true, historical: false, error: null });
    if (!this.matches(attempt) || this.commonReason()) { this.retire(); return; }
    try {
      const value = await attempt.observer.api.startArtifactInspection({ operationId, ownerGeneration, consentVersion: ARTIFACT_INSPECTION_CONSENT });
      if (!attempt.observer.active || this.attempt !== attempt) return;
      const status = parseArtifactInspectionStatus(value);
      if (!status?.operation || !sameArtifactIdentity(status.operation, attempt.identity) || status.operation.phase === 'awaiting-consent') {
        this.fail({ code: 'artifact_inspection_protocol' }, true); return;
      }
      this.receive(attempt.observer, status);
    } catch (error) { if (attempt.observer.active && this.attempt === attempt && !attempt.settled) this.fail(error); }
  }
  canCancel(): boolean {
    const observer = this.observer, op = observer?.status?.operation;
    return !this.disposed && !!observer?.active && !!op && op.phase !== 'terminal' && !sameArtifactIdentity(this.state.cancelClaimed, op);
  }
  cancel(): boolean {
    if (!this.canCancel() || !this.observer?.status?.operation) return false;
    const observer = this.observer, op = observer.status!.operation!;
    this.retire({}, false);
    // Explicit cancellation can name a displayed original status. This is not
    // adoption of its consent: only a matching Prepare reply can enable Run.
    const attempt = this.attempt;
    if (attempt?.observer === observer && !attempt.identity && this.originCandidate(attempt, observer.status!)) attempt.identity = id(op);
    return this.stop(observer, id(op));
  }
  private stopOriginal(): void {
    const attempt = this.attempt;
    if (!attempt?.identity || attempt.settled || !attempt.observer.active) return;
    this.stop(attempt.observer, attempt.identity);
  }
  private stop(observer: Observer, identity: ArtifactInspectionIdentity): boolean {
    if (!observer.active || sameArtifactIdentity(this.cancelClaim, identity)) return false;
    // Single local STOP claim. Lost cancellation replies are reconciled by the
    // original observer, never by automatic retries or replacement documents.
    const claim = id(identity);
    this.cancelClaim = claim;
    this.update({ cancelClaimed: id(identity), consent: null });
    // A later Prepare replaces this completion's routing token. Native terminal
    // settlement may permit new work, but an old Cancel reply cannot retire it.
    const current = () => observer.active && this.observer === observer && this.cancelClaim === claim;
    void (async () => {
      try {
        const value = await observer.api.cancelArtifactInspection(identity.operationId, identity.ownerGeneration);
        if (!current()) return;
        const status = parseArtifactInspectionStatus(value);
        if (!status?.operation || !sameArtifactIdentity(status.operation, identity)) { this.fail({ code: 'artifact_inspection_protocol' }, true); return; }
        this.receive(observer, status);
      } catch (error) { if (current()) this.fail(error); }
    })();
    return true;
  }
  dispose(): void {
    if (this.disposed) return;
    this.retire(); this.disposed = true; this.listeners.clear();
    if (this.observer && !this.needsOriginal(this.observer)) this.detach(this.observer);
    // A sent intent/run keeps its original retirement-only observer. Native
    // document-loss/shutdown paths, not JS disposal, settle actual resources.
  }
}
