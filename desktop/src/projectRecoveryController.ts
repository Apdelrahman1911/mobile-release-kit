// App-owned coordination, not a native owner or a cleanup receipt. A page,
// Promise, generation or listener cannot settle/reconstruct the original run.
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { ApiError, BridgeMode } from './types.ts';
import type { ProjectRecoveryApi, ProjectRecoveryContext, ProjectRecoveryIdentity, ProjectRecoveryOperation,
  ProjectRecoveryStatus, PrepareProjectRecovery, ProjectRecoveryAction, ProjectRecoveryObservation } from './projectRecoveryTypes.ts';
import { PROJECT_RECOVERY_CONSENT, PROJECT_RECOVERY_CONSENT_MS, PROJECT_RECOVERY_COUNTER_MAX, copyProjectRecoveryRequest,
  recoveryAvailabilityText, recoveryCounter, recoveryOperationProgress, projectRecoveryError, parseProjectRecoveryStatus,
  recoveryEligible, sameRecoveryData, sameRecoveryIdentity } from './projectRecoveryProtocol.ts';

export interface ProjectRecoveryProject {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  dirtyDraft: boolean; snapshotPending: boolean;
}
export interface ProjectRecoveryBinding {
  context: ProjectRecoveryContext; observationGeneration: number;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
}
export interface ProjectRecoveryConsent extends ProjectRecoveryIdentity {
  binding: ProjectRecoveryBinding; acknowledged: boolean; deadline: number;
}
export interface ProjectRecoveryState {
  mode: BridgeMode; project: ProjectRecoveryProject | null; visible: boolean; selectionPending: boolean;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; requestGeneration: number;
  listening: boolean; initialized: boolean; readPending: boolean; status: ProjectRecoveryStatus | null;
  consent: ProjectRecoveryConsent | null; pending: 'prepare' | 'start' | null; originalUnconfirmed: boolean;
  historical: boolean; cancelClaimed: ProjectRecoveryIdentity | null; error: ApiError | null;
  observationIssue: 'bridge' | 'protocol' | null; nativeBlocked: boolean; integrityFailed: boolean; generationLost: boolean;
}
type Port = ProjectRecoveryApi & { mode: BridgeMode };
interface Observer { api: Port; active: boolean; generation: number; unlisten: (() => void) | null; reading: Promise<void> | null; status: ProjectRecoveryStatus | null }
interface Attempt {
  observer: Observer; binding: ProjectRecoveryBinding; previous: ProjectRecoveryIdentity | null; after: number;
  identity: ProjectRecoveryIdentity | null; prepareSent: boolean; prepareReply: boolean; deadline: number;
  startSent: boolean; startAfter: number; retired: boolean; settled: boolean;
}
interface Context { selectedProject: () => ProjectSession | null; otherOperationReason: () => string | null; now?: () => number }
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
const id = (op: ProjectRecoveryIdentity): ProjectRecoveryIdentity => ({ operationId: op.operationId, ownerGeneration: op.ownerGeneration });
const active = (op: ProjectRecoveryOperation | null | undefined): boolean => !!op && op.phase !== 'terminal';
export function projectRecoveryOwnerReason(state: ProjectRecoveryState): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost) return 'Project-recovery ownership or finality is unverified. Keep the original status; conflicting work is disabled.';
  if (state.originalUnconfirmed || state.pending || active(state.status?.operation)) return 'Project build-input recovery holds the original intent or execution slot. Cancel or settle that original operation before conflicting work.';
  if (state.mode === 'native' && state.observationIssue) return 'The original project-recovery status is unverified. Check retained status before conflicting work.';
  return null;
}

export class ProjectRecoveryController {
  private state: ProjectRecoveryState = freeze<ProjectRecoveryState>({ mode: 'unavailable', project: null, visible: false, selectionPending: false,
    connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0, requestGeneration: 0,
    listening: false, initialized: false, readPending: false, status: null, consent: null, pending: null, originalUnconfirmed: false,
    historical: false, cancelClaimed: null, error: null, observationIssue: null, nativeBlocked: false, integrityFailed: false, generationLost: false });
  private readonly context: Context;
  private observer: Observer | null = null;
  private attempt: Attempt | null = null;
  private cancelClaim: ProjectRecoveryIdentity | null = null;
  private draftReference: ProjectSession['draft'] = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private listeners = new Set<() => void>();
  private disposed = false;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): ProjectRecoveryState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private now(): number { return (this.context.now ?? (() => performance.now()))(); }
  private update(patch: Partial<ProjectRecoveryState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private advance(field: 'connectionGeneration' | 'selectionGeneration' | 'contextGeneration' | 'requestGeneration'): Partial<ProjectRecoveryState> {
    const next = this.state[field] + 1;
    return { [field]: Math.min(next, PROJECT_RECOVERY_COUNTER_MAX), generationLost: this.state.generationLost || !recoveryCounter(next) };
  }
  private clearTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private retire(patch: Partial<ProjectRecoveryState> = {}, stop = true): void {
    this.clearTimer();
    if (this.attempt) this.attempt.retired = true;
    // Burn before any subscriber, reducer, early return or asynchronous STOP.
    this.update({ ...patch, consent: null, historical: !!this.state.status?.operation || this.state.historical });
    if (stop) this.stopOriginal();
  }
  private fail(error: unknown, protocol = false): void {
    this.retire({ error: projectRecoveryError(error), observationIssue: protocol ? 'protocol' : 'bridge',
      integrityFailed: this.state.integrityFailed || protocol, nativeBlocked: this.state.nativeBlocked || protocol });
  }
  // Must be called before workspaceReducer, including actions it will reject or
  // regard as unchanged. Away-and-back and equal-byte edits never revive consent.
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
  // Version Save intents and every outcome retire prior project-recovery consent,
  // including unchanged/refused saves that do not change config generations.
  versionIntent(): void { if (!this.disposed) this.retire(this.advance('contextGeneration')); }
  setSelectionPending(selectionPending: boolean): void {
    if (!this.disposed && selectionPending !== this.state.selectionPending) this.retire({ ...this.advance('selectionGeneration'), selectionPending });
  }
  syncProject(): void {
    if (this.disposed) return;
    const project = this.context.selectedProject();
    const next: ProjectRecoveryProject | null = project ? { projectId: project.project.id, draftRevision: project.revision,
      baselineGeneration: project.baselineGeneration, observationGeneration: project.observationGeneration,
      dirtyDraft: isDirty(project), snapshotPending: project.snapshotRequest !== null } : null;
    const draft = project?.draft ?? null;
    if (sameRecoveryData(next, this.state.project) && this.draftReference === draft) return;
    this.draftReference = draft;
    const badCounter = next !== null && ![next.draftRevision, next.baselineGeneration, next.observationGeneration].every(recoveryCounter);
    this.retire({ ...this.advance('contextGeneration'), project: next, generationLost: this.state.generationLost || badCounter ||
      this.state.contextGeneration === PROJECT_RECOVERY_COUNTER_MAX });
  }
  setVisible(visible: boolean): void {
    if (this.disposed || visible === this.state.visible) return;
    // Leaving a consent view retires its unchecked/checked intent. A STARTED
    // run is app-owned: ordinary page navigation keeps its status and Cancel.
    if (!visible && this.attempt && !this.attempt.startSent && !this.attempt.settled) this.retire({ ...this.advance('contextGeneration'), visible });
    else this.update({ visible });
  }
  private needsOriginal(observer: Observer): boolean {
    return this.attempt?.observer === observer && this.attempt.prepareSent && !this.attempt.settled || active(observer.status?.operation);
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
      const unlisten = await api.subscribeProjectRecovery((value) => { if (observer.active) this.receive(observer, value); });
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
      b.context.draftRevision === p.draftRevision && b.context.baselineGeneration === p.baselineGeneration;
  }
  private originCandidate(attempt: Attempt, status: ProjectRecoveryStatus): boolean {
    const op = status.operation;
    return !!op && status.statusRevision > attempt.after && !sameRecoveryIdentity(op, attempt.previous) &&
      sameRecoveryData(op.context, attempt.binding.context) && (!attempt.identity || sameRecoveryIdentity(op, attempt.identity));
  }
  private reconcile(observer: Observer): void {
    const status = observer.status, attempt = this.attempt, op = status?.operation;
    if (!status || !op) return;
    const matched = attempt?.observer === observer && sameRecoveryIdentity(attempt.identity, op);
    if (attempt && matched && op.phase === 'terminal') attempt.settled = true;
    const finished = !!attempt && matched && attempt.settled;
    const startObserved = !!attempt && matched && attempt.startSent && status.statusRevision > attempt.startAfter && op.phase !== 'awaiting-consent';
    const blocked = this.state.nativeBlocked || ['shutdown', 'document-lost', 'cleanup-unknown'].includes(status.availability) || op.phase === 'unknown';
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
  private receive(observer: Observer, value: unknown): ProjectRecoveryStatus | null {
    if (!observer.active) return null;
    const status = parseProjectRecoveryStatus(value);
    if (!status) { this.fail({ code: 'project_recovery_protocol' }, true); return null; }
    const previous = observer.status, a = previous?.operation, b = status.operation;
    if (previous && status.statusRevision < previous.statusRevision) {
      if (a && b && sameRecoveryIdentity(a, b) && !recoveryOperationProgress(b, a)) this.fail({ code: 'project_recovery_protocol' }, true);
      return status;
    }
    if (previous && status.statusRevision === previous.statusRevision && !sameRecoveryData(previous, status)) {
      this.fail({ code: 'project_recovery_protocol' }, true); return null;
    }
    if (a && b && sameRecoveryIdentity(a, b) && !recoveryOperationProgress(a, b)) {
      this.fail({ code: 'project_recovery_protocol' }, true); return null;
    }
    const attempt = this.attempt;
    if (attempt?.observer === observer && attempt.prepareSent) {
      if (attempt.identity ? !sameRecoveryIdentity(attempt.identity, b) :
          b && !sameRecoveryIdentity(b, attempt.previous) && !this.originCandidate(attempt, status)) {
        this.fail({ code: 'project_recovery_protocol' }, true); return null;
      }
      if (b && this.originCandidate(attempt, status) && !attempt.startSent &&
          (b.phase === 'starting' || b.phase === 'running' || b.outcome === 'complete')) {
        this.fail({ code: 'project_recovery_protocol' }, true); return null;
      }
    } else if (previous && !sameRecoveryIdentity(a ?? null, b) && (a !== null || b !== null)) {
      // Unsolicited foreign IDs cannot replace a result or authorize a run.
      this.fail({ code: 'project_recovery_protocol' }, true); return null;
    }
    if (status.statusRevision === PROJECT_RECOVERY_COUNTER_MAX) this.retire({ generationLost: true });
    observer.status = status;
    if (observer === this.observer) {
      this.update({ status, initialized: true, nativeBlocked: this.state.nativeBlocked ||
        ['shutdown', 'document-lost', 'cleanup-unknown'].includes(status.availability), historical: this.state.historical || !attempt });
      this.reconcile(observer);
      this.expireConsent();
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
        const status = this.receive(observer, await observer.api.projectRecoveryStatus());
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
  private commonReason(): string | null {
    if (this.disposed || this.state.mode !== 'native') return 'Open the native application. Browser preview cannot prepare or run project recovery.';
    if (this.state.nativeBlocked || this.state.integrityFailed || this.state.generationLost) return projectRecoveryOwnerReason(this.state);
    if (!this.observer?.active || this.observer.generation !== this.state.connectionGeneration || !this.state.listening || !this.state.initialized || !this.state.status || this.state.observationIssue)
      return 'A current original native status and subscription are required. Check status; do not infer permission from passive capabilities.';
    if (this.state.status.statusRevision >= PROJECT_RECOVERY_COUNTER_MAX) return 'The original status counter is exhausted. No counter or intent can be reused.';
    if (!['available', 'busy'].includes(this.state.status.availability)) return recoveryAvailabilityText[this.state.status.availability];
    if (!this.state.visible) return 'Open Recovery to review this action and the state it can change.';
    if (this.state.selectionPending) return 'Finish the original project selection before reviewing project recovery.';
    const project = this.state.project;
    if (!project) return 'Choose a registered source project first; an evidence folder is not an execution target.';
    if (project.snapshotPending) return 'Wait for the explicit saved snapshot request to settle.';
    return this.context.otherOperationReason();
  }
  private inspected(): ProjectRecoveryObservation | null {
    const attempt = this.attempt, op = this.state.status?.operation;
    if (!attempt || !attempt.settled || !this.matches(attempt) || this.state.historical || !op ||
        !sameRecoveryIdentity(attempt.identity, op) || op.phase !== 'terminal' || op.outcome !== 'complete' ||
        op.context.action !== 'inspect' || op.result?.action !== 'inspect') return null;
    const now = this.now();
    return Number.isFinite(now) && now >= 0 && now < attempt.deadline ? op.result.observation : null;
  }
  prepareReason = (action: ProjectRecoveryAction): string | null => {
    const blocked = this.commonReason() ?? projectRecoveryOwnerReason(this.state) ??
      (this.state.status?.availability === 'busy' ? recoveryAvailabilityText.busy : null);
    if (blocked || action === 'inspect') return blocked;
    const inspected = this.inspected();
    if (!inspected) return 'Inspect this project first. Only that fresh, settled original inspection can be reviewed for recovery.';
    if (inspected.quiescence === 'none' && inspected.status === 'pending')
      return 'Original-worker finality is missing. This UI cannot supply a manual idle assertion or force cleanup.';
    return recoveryEligible(inspected) ? null : 'The inspection has no eligible pending build-input session to recover.';
  };
  runReason = (): string | null => {
    const common = this.commonReason(); if (common) return common;
    const consent = this.state.consent, attempt = this.attempt, op = this.state.status?.operation;
    if (!consent || !attempt || !attempt.prepareReply || attempt.startSent || !this.matches(attempt) || !sameRecoveryIdentity(consent, op ?? null) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable) return 'Review a new recovery intent. A status observation or old acknowledgement cannot authorize Recover.';
    const now = this.now();
    if (!Number.isFinite(now) || now < 0 || now >= consent.deadline) return 'This original review has expired. Polling cannot extend it.';
    return consent.acknowledged ? null : 'Confirm the exact build-input recovery attempt and its preservation limits before Recover.';
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
    this.timer = setTimeout(() => { this.timer = null; this.expireConsent(); if (this.state.consent) this.armExpiry(); }, Math.min(remaining, PROJECT_RECOVERY_CONSENT_MS));
  }
  async prepare(action: ProjectRecoveryAction): Promise<void> {
    this.syncProject();
    if (this.prepareReason(action) || !this.observer || !this.state.project || !['inspect', 'recover'].includes(action)) return;
    const project = this.state.project;
    // Display comparison only. Native fills its own review from the exact
    // original inspection; the renderer sends no session or private stamp.
    const review = action === 'recover' ? this.inspected() : null;
    const inspectionDeadline = action === 'recover' ? this.attempt?.deadline ?? 0 : Number.POSITIVE_INFINITY;
    if (action === 'recover' && review === null) return;
    const request = copyProjectRecoveryRequest('prepare_project_recovery', { projectId: project.projectId, draftRevision: project.draftRevision,
      baselineGeneration: project.baselineGeneration, action }) as PrepareProjectRecovery | null;
    const now = this.now();
    if (!request || !Number.isFinite(now) || now < 0 || !Number.isFinite(now + PROJECT_RECOVERY_CONSENT_MS)) { this.fail({ code: 'project_recovery_invalid' }, true); return; }
    const counters = this.advance('requestGeneration');
    if (counters.generationLost) { this.retire(counters); return; }
    const observer = this.observer;
    const binding: ProjectRecoveryBinding = freeze({ context: { ...request, review },
      observationGeneration: project.observationGeneration, connectionGeneration: this.state.connectionGeneration,
      selectionGeneration: this.state.selectionGeneration, contextGeneration: this.state.contextGeneration, requestGeneration: counters.requestGeneration! });
    const attempt: Attempt = { observer, binding, previous: observer.status?.operation ? id(observer.status.operation) : null,
      after: observer.status?.statusRevision ?? 0, identity: null, prepareSent: false, prepareReply: false, deadline: Math.min(now + PROJECT_RECOVERY_CONSENT_MS, inspectionDeadline),
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
      const value = await observer.api.prepareProjectRecovery(request);
      if (!observer.active || this.attempt !== attempt) return;
      const status = parseProjectRecoveryStatus(value), op = status?.operation;
      if (!status || !op || !this.originCandidate(attempt, status) || ['starting', 'running'].includes(op.phase) || op.outcome === 'complete') {
        this.fail({ code: 'project_recovery_protocol' }, true); return;
      }
      attempt.identity = id(op); attempt.prepareReply = true;
      if (!this.receive(observer, status)) return;
      this.reconcile(observer);
      this.update({ pending: null, originalUnconfirmed: false });
      const current = observer.status?.operation;
      if (this.matches(attempt) && !this.commonReason() && current?.phase === 'awaiting-consent' && current.intentUsable &&
          sameRecoveryIdentity(current, attempt.identity) && this.now() < attempt.deadline) {
        this.update({ consent: { ...id(op), binding, acknowledged: action === 'inspect', deadline: attempt.deadline } });
        this.armExpiry();
        // The explicit Inspect click authorizes only this non-mutating read.
        // Recovery always returns to its visible, unchecked confirmation.
        if (action === 'inspect') await this.start(op.operationId, op.ownerGeneration);
      } else {
        attempt.retired = true;
        this.stopOriginal();
      }
    } catch (error) {
      if (observer.active && this.attempt === attempt) {
        const safe = projectRecoveryError(error);
        // Native reserves these codes on PREPARE for rejection before allocation.
        // They never release/rearm a Start, or contradict an observed admission.
        if (['project_recovery_invalid', 'project_recovery_unavailable', 'project_recovery_busy', 'project_recovery_owner'].includes(safe.code) &&
            !attempt.identity && (!observer.status || !this.originCandidate(attempt, observer.status))) {
          attempt.retired = true; attempt.settled = true;
          this.update({ pending: null, originalUnconfirmed: false, consent: null, error: safe });
        } else this.fail(error, safe.code !== 'project_recovery_protocol');
      }
    }
  }
  setAcknowledged(operationId: string, ownerGeneration: string, acknowledged: boolean): void {
    this.syncProject(); this.expireConsent();
    const consent = this.state.consent, attempt = this.attempt;
    if (!consent || !attempt || !this.matches(attempt) || this.commonReason() ||
        !sameRecoveryIdentity(consent, { operationId, ownerGeneration }) || typeof acknowledged !== 'boolean') return;
    this.update({ consent: { ...consent, acknowledged } });
    // Acknowledgement is never an invocation, a persisted preference or a Start.
  }
  async start(operationId: string, ownerGeneration: string): Promise<void> {
    this.syncProject(); this.expireConsent();
    const attempt = this.attempt, consent = this.state.consent;
    if (!attempt || !consent || !sameRecoveryIdentity(consent, { operationId, ownerGeneration }) || this.runReason()) return;
    // Consume locally BEFORE yielding or notifying subscribers. Neither a lost
    // reply nor a same-context status can create another consent or Start.
    attempt.startSent = true; attempt.startAfter = attempt.observer.status?.statusRevision ?? 0;
    this.clearTimer();
    this.update({ consent: null, pending: 'start', originalUnconfirmed: true, historical: false, error: null });
    if (!this.matches(attempt) || this.commonReason()) { this.retire(); return; }
    try {
      const value = await attempt.observer.api.startProjectRecovery({ operationId, ownerGeneration, consentVersion: PROJECT_RECOVERY_CONSENT });
      if (!attempt.observer.active || this.attempt !== attempt) return;
      const status = parseProjectRecoveryStatus(value);
      if (!status?.operation || !sameRecoveryIdentity(status.operation, attempt.identity) || status.operation.phase === 'awaiting-consent') {
        this.fail({ code: 'project_recovery_protocol' }, true); return;
      }
      this.receive(attempt.observer, status);
    } catch (error) { if (attempt.observer.active && this.attempt === attempt && !attempt.settled) this.fail(error); }
  }
  canCancel(): boolean {
    const observer = this.observer, op = observer?.status?.operation;
    return !this.disposed && !!observer?.active && !!op && op.phase !== 'terminal' && !sameRecoveryIdentity(this.state.cancelClaimed, op);
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
  private stop(observer: Observer, identity: ProjectRecoveryIdentity): boolean {
    if (!observer.active || sameRecoveryIdentity(this.cancelClaim, identity)) return false;
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
        const value = await observer.api.cancelProjectRecovery(identity.operationId, identity.ownerGeneration);
        if (!current()) return;
        const status = parseProjectRecoveryStatus(value);
        if (!status?.operation || !sameRecoveryIdentity(status.operation, identity)) { this.fail({ code: 'project_recovery_protocol' }, true); return; }
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
