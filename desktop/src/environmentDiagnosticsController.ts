// App-retained observation/intent only. Native owns the slot, clocks, STOP and
// original resources even when this controller, a promise or a view disappears.
import type { ProjectSession } from './drafts.ts';
import type { EnvironmentOperation, EnvironmentPlatform } from './environment.ts';
import type { ApiError, BridgeMode, DesktopApi, JsonObject } from './types.ts';
import type { EnvironmentDiagnosticsAvailability, EnvironmentDiagnosticsBinding, EnvironmentDiagnosticsProjection,
  EnvironmentDiagnosticsSelection, EnvironmentDiagnosticsStatus, StartEnvironmentDiagnostics } from './environmentDiagnosticsTypes.ts';
import { diagnosticsCounter, diagnosticsProjectionProgress, diagnosticsStatusProgress, ENVIRONMENT_DIAGNOSTICS_COUNTER_MAX,
  environmentDiagnosticsError, parseEnvironmentDiagnosticsStatus, sameDiagnosticsContext, startEnvironmentDiagnosticsFits } from './environmentDiagnosticsProtocol.ts';

export interface EnvironmentDiagnosticsAttempt {
  binding: EnvironmentDiagnosticsBinding; projection: EnvironmentDiagnosticsProjection | null; projectionRevision: number;
  acknowledged: boolean; adopted: boolean; startPending: boolean; invalidated: boolean; stopRequested: boolean;
  refusal: ApiError | null;
}
export interface EnvironmentDiagnosticsObservation {
  projection: EnvironmentDiagnosticsProjection; binding: EnvironmentDiagnosticsBinding | null;
  statusRevision: number; receivedAt: number; provenance: 'acknowledged-start' | 'native-status'; stale: boolean;
}
export interface EnvironmentDiagnosticsState {
  mode: BridgeMode; project: EnvironmentDiagnosticsSelection | null; platform: EnvironmentPlatform; operation: EnvironmentOperation;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number; visible: boolean; selectionPending: boolean;
  listening: boolean; initialized: boolean; readPending: boolean; status: EnvironmentDiagnosticsStatus | null;
  observationIssue: 'bridge' | 'protocol' | null; integrityFailed: boolean; generationLost: boolean; nativeBlocked: boolean;
  attempt: EnvironmentDiagnosticsAttempt | null; observation: EnvironmentDiagnosticsObservation | null;
  unknownEvidence: EnvironmentDiagnosticsProjection | null; cancelClaimed: { runId: string; ownerGeneration: string } | null; error: ApiError | null;
}
interface Context { selectedProject: () => ProjectSession | null; otherOperationReason: () => string | null; now?: () => number }
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function sameRun(first: { runId: string; ownerGeneration: string } | null, next: { runId: string; ownerGeneration: string } | null): boolean {
  return first !== null && next !== null && first.runId === next.runId && first.ownerGeneration === next.ownerGeneration;
}
function attemptSettled(attempt: EnvironmentDiagnosticsAttempt | null): boolean { return !attempt || attempt.projection?.finality === 'settled'; }
export const diagnosticsAvailabilityText: Record<EnvironmentDiagnosticsAvailability, string> = {
  available: 'The separate native diagnostics capability is available. Checking tools still requires your explicit request.',
  busy: 'An original native operation owns the application-wide slot. Finish or cancel that operation and read status before starting a check.',
  shutdown: 'The application is stopping its original operations. No new tool check can start.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the application open; conflicting operations and normal exit remain blocked.',
  'document-lost': 'The original native document is no longer available. A renderer reconnect cannot replace its ownership.',
  'unsupported-platform': 'Build-tool diagnostics are unavailable for this host profile. Windows and other unsupported hosts have no fallback.',
  'runtime-unqualified': 'Build-tool diagnostics are not enabled for this host, runtime and native document. Passive requirements remain available separately.',
};
export function diagnosticsOwnerReason(state: EnvironmentDiagnosticsState): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost) return 'Native diagnostics ownership or finality is unverified. Keep the original operation; conflicting work is disabled.';
  if (state.status?.active || !attemptSettled(state.attempt)) return 'A build-tool diagnostics run is active or its Start reply is unconfirmed. Read or cancel the original run before conflicting native work.';
  if (state.mode === 'native' && state.observationIssue) return 'Native diagnostics status is not current. Read original status before conflicting native work.';
  return null;
}

export class EnvironmentDiagnosticsController {
  private state: EnvironmentDiagnosticsState = freeze<EnvironmentDiagnosticsState>({ mode: 'unavailable', project: null, platform: 'android', operation: 'build',
    connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0, visible: false, selectionPending: false,
    listening: false, initialized: false, readPending: false, status: null, observationIssue: null, integrityFailed: false, generationLost: false,
    nativeBlocked: false, attempt: null, observation: null, unknownEvidence: null, cancelClaimed: null, error: null });
  private readonly context: Context;
  private api: DesktopApi | null = null;
  private attemptApi: DesktopApi | null = null;
  private draft: JsonObject | null = null;
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private listeners = new Set<() => void>();
  private disposed = false;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): EnvironmentDiagnosticsState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<EnvironmentDiagnosticsState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private advance(field: 'connectionGeneration' | 'selectionGeneration' | 'contextGeneration'): Partial<EnvironmentDiagnosticsState> {
    const next = this.state[field] + 1;
    return { [field]: Math.min(next, ENVIRONMENT_DIAGNOSTICS_COUNTER_MAX), generationLost: this.state.generationLost || !diagnosticsCounter(next) };
  }
  private invalidate(patch: Partial<EnvironmentDiagnosticsState>): void {
    const attempt = this.state.attempt;
    this.update({ ...patch, observation: this.state.observation ? { ...this.state.observation, stale: true } : null,
      attempt: attempt ? { ...attempt, invalidated: true, stopRequested: !attemptSettled(attempt) || attempt.stopRequested } : null });
    this.stopOriginal();
  }
  syncProject(): void {
    if (this.disposed) return;
    const session = this.context.selectedProject();
    const next = session ? { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration, hasDraft: session.draft !== null } : null;
    const old = this.state.project, draft = session?.draft ?? null;
    if (old?.projectId === next?.projectId && old?.draftRevision === next?.draftRevision && old?.baselineGeneration === next?.baselineGeneration &&
        old?.hasDraft === next?.hasDraft && this.draft === draft) return;
    this.draft = draft;
    this.invalidate({ ...this.advance('selectionGeneration'), project: next });
  }
  setContext(platform: EnvironmentPlatform, operation: EnvironmentOperation): void {
    if (this.disposed || !(platform === 'android' || platform === 'ios') || !(operation === 'build' || operation === 'artifact-validation') ||
        platform === this.state.platform && operation === this.state.operation) return;
    this.invalidate({ ...this.advance('contextGeneration'), platform, operation });
  }
  setVisible(visible: boolean): void {
    if (!this.disposed && visible !== this.state.visible) this.invalidate({ ...this.advance('contextGeneration'), visible });
  }
  setSelectionPending(selectionPending: boolean): void {
    if (!this.disposed && selectionPending !== this.state.selectionPending) this.invalidate({ ...this.advance('selectionGeneration'), selectionPending });
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.invalidate({ ...this.advance('connectionGeneration'), mode: 'unavailable', listening: false, initialized: false, readPending: false });
    try { this.unlisten?.(); } catch { /* Observer release is not native settlement. */ }
    this.unlisten = null; this.reading = null; this.api = null;
  }
  async connect(api: DesktopApi): Promise<void> {
    if (this.disposed) return;
    if (this.api) this.beginConnection();
    this.api = api;
    const generation = this.state.connectionGeneration;
    this.update({ mode: api.mode });
    if (api.mode !== 'native') return;
    try {
      const unlisten = await api.subscribeEnvironmentDiagnostics((value) => {
        if (!this.disposed && this.api === api && this.state.connectionGeneration === generation) this.receive(value, 'event');
      });
      if (this.disposed || this.api !== api || this.state.connectionGeneration !== generation) { unlisten(); return; }
      this.unlisten = unlisten; this.update({ listening: true });
      await this.checkStatus();
    } catch (error) {
      if (!this.disposed && this.api === api && this.state.connectionGeneration === generation) this.failed(error);
    }
  }
  async checkStatus(): Promise<void> {
    if (this.disposed || this.api?.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api, generation = this.state.connectionGeneration;
    const work = Promise.resolve().then(async () => {
      try {
        const status = await api.environmentDiagnosticsStatus();
        if (!this.disposed && this.api === api && this.state.connectionGeneration === generation) this.receive(status, 'read');
      } catch (error) {
        if (!this.disposed && this.api === api && this.state.connectionGeneration === generation) this.failed(error);
      }
    });
    this.reading = work; this.update({ readPending: true });
    try { await work; } finally {
      if (this.reading === work) { this.reading = null; this.update({ readPending: false }); }
    }
  }
  private failed(error: unknown): void {
    const safe = environmentDiagnosticsError(error);
    const protocol = safe.code === 'environment_diagnostics_status_invalid';
    this.update({ error: safe, observationIssue: protocol || this.state.integrityFailed ? 'protocol' : 'bridge',
      integrityFailed: this.state.integrityFailed || protocol, nativeBlocked: this.state.nativeBlocked || safe.code === 'cleanup_unknown',
      observation: this.state.observation ? { ...this.state.observation, stale: true } : null });
    if (protocol) {
      const attempt = this.state.attempt;
      if (attempt) this.update({ attempt: { ...attempt, invalidated: true, stopRequested: true } });
      this.stopOriginal();
    }
  }
  private matches(binding: EnvironmentDiagnosticsBinding): boolean {
    const project = this.state.project;
    if (!project) return false;
    return !this.disposed && this.state.visible && !this.state.selectionPending && this.state.mode === 'native' &&
      binding.connectionGeneration === this.state.connectionGeneration && binding.selectionGeneration === this.state.selectionGeneration &&
      binding.contextGeneration === this.state.contextGeneration && binding.projectId === project.projectId && binding.draftRevision === project.draftRevision &&
      binding.baselineGeneration === project.baselineGeneration && project.hasDraft && binding.platform === this.state.platform && binding.operation === this.state.operation;
  }
  private candidate(status: EnvironmentDiagnosticsStatus, attempt: EnvironmentDiagnosticsAttempt): EnvironmentDiagnosticsProjection | null {
    if (attempt.refusal) return null;
    const rows = [status.active, status.lastTerminal];
    return rows.find((row) => row && sameDiagnosticsContext(row.context, attempt.binding) && (attempt.projection
      ? sameRun(row, attempt.projection) : status.statusRevision > attempt.binding.nativeStatusRevision && row.runId !== attempt.binding.previousRunId)) ?? null;
  }
  private receive(value: unknown, source: 'read' | 'event' | 'reply', acknowledgedBinding?: EnvironmentDiagnosticsBinding): void {
    if (this.disposed) return;
    const parsed = parseEnvironmentDiagnosticsStatus(value);
    if (!parsed) { this.failed({ code: 'environment_diagnostics_status_invalid' }); return; }
    const incoming = freeze(parsed), previous = this.state.status;
    const unknown = [incoming.active, incoming.lastTerminal].find((row) => row?.finality === 'unknown') ?? null;
    if (unknown || incoming.capability.reason === 'cleanup-unknown') this.update({ nativeBlocked: true, unknownEvidence: this.state.unknownEvidence ?? unknown });
    if (previous && !(incoming.statusRevision < previous.statusRevision ? diagnosticsStatusProgress(incoming, previous) : diagnosticsStatusProgress(previous, incoming))) {
      this.failed({ code: 'environment_diagnostics_status_invalid' }); return;
    }
    let attempt = this.state.attempt;
    const refused = source === 'read' ? attempt?.refusal ?? null : null;
    if (refused) { attempt = null; this.attemptApi = null; }
    if (attempt) {
      const row = this.candidate(incoming, attempt);
      if (acknowledgedBinding === attempt.binding && !row) { this.failed({ code: 'environment_diagnostics_status_invalid' }); return; }
      if (row) {
        const older = incoming.statusRevision < attempt.projectionRevision;
        if (attempt.projection && !(older ? diagnosticsProjectionProgress(row, attempt.projection) : diagnosticsProjectionProgress(attempt.projection, row))) {
          this.failed({ code: 'environment_diagnostics_status_invalid' }); return;
        }
        attempt = { ...attempt, projection: older ? attempt.projection : row, projectionRevision: older ? attempt.projectionRevision : incoming.statusRevision,
          acknowledged: attempt.acknowledged || acknowledgedBinding === attempt.binding,
          startPending: acknowledgedBinding === attempt.binding ? false : attempt.startPending };
      }
    }
    const status = previous && incoming.statusRevision < previous.statusRevision ? previous : incoming;
    this.update({ status, attempt, initialized: this.state.initialized || source === 'read',
      observationIssue: this.state.integrityFailed ? 'protocol' : source === 'read' ? null : this.state.observationIssue,
      error: refused ?? (source === 'read' && !this.state.integrityFailed ? null : this.state.error) });
    this.retainObservation();
    this.stopOriginal();
  }
  private retainObservation(): void {
    const status = this.state.status;
    if (!status) return;
    const row = status.active?.result ? status.active : status.lastTerminal?.result ? status.lastTerminal : null;
    if (!row) return;
    const attempt = this.state.attempt;
    const earlier = this.state.observation;
    const currentAttempt = attempt && sameRun(attempt.projection, row) ? attempt : null;
    const sameEarlier = sameRun(earlier?.projection ?? null, row);
    const binding = currentAttempt?.binding ?? (sameEarlier ? earlier!.binding : null);
    this.update({ observation: { projection: row, binding, statusRevision: status.statusRevision,
      receivedAt: sameEarlier ? earlier!.receivedAt : this.context.now?.() ?? Date.now(),
      provenance: currentAttempt ? currentAttempt.acknowledged ? 'acknowledged-start' : 'native-status' : sameEarlier ? earlier!.provenance : 'native-status',
      stale: !currentAttempt || !binding || !this.matches(binding) || currentAttempt.invalidated || this.state.observationIssue !== null || this.state.integrityFailed || this.state.nativeBlocked } });
  }
  startReason(): string | null {
    const state = this.state;
    if (state.mode !== 'native') return 'Native diagnostics are unavailable in browser preview or without the desktop bridge. Example requirements are not tool observations.';
    if (state.operation !== 'build') return 'Artifact-validation diagnostics are not implemented. Its expected requirements remain available separately.';
    const owned = diagnosticsOwnerReason(state); if (owned) return owned;
    if (!state.listening || !state.initialized || !state.status) return 'Read the separate native diagnostics capability and original-owner status before checking tools.';
    if (state.readPending) return 'The original native status is being read.';
    if (!state.status.capability.available) return diagnosticsAvailabilityText[state.status.capability.reason];
    if (state.status.statusRevision >= ENVIRONMENT_DIAGNOSTICS_COUNTER_MAX) return 'The native status counter cannot advance. No sequence or run will be reused.';
    const other = this.context.otherOperationReason(); if (other) return other;
    if (!state.visible || state.selectionPending) return 'Return to Environment and finish choosing a project before checking tools.';
    if (!state.project?.hasDraft || !this.draft) return 'Select a project and prepare a current configuration draft first.';
    return null;
  }
  start(): boolean {
    this.syncProject();
    if (this.disposed || !this.api || !this.draft || !this.state.project || !this.state.status || this.startReason() !== null) return false;
    const project = this.state.project, api = this.api, status = this.state.status;
    const request: StartEnvironmentDiagnostics = { projectId: project.projectId, draftRevision: project.draftRevision,
      baselineGeneration: project.baselineGeneration, platform: this.state.platform, operation: 'build', draft: this.draft };
    if (!startEnvironmentDiagnosticsFits(request)) { this.update({ error: environmentDiagnosticsError({ code: 'environment_diagnostics_invalid' }) }); return false; }
    const input = structuredClone(request);
    const binding: EnvironmentDiagnosticsBinding = freeze({ projectId: request.projectId, draftRevision: request.draftRevision,
      baselineGeneration: request.baselineGeneration, platform: request.platform, operation: 'build', connectionGeneration: this.state.connectionGeneration,
      selectionGeneration: this.state.selectionGeneration, contextGeneration: this.state.contextGeneration, nativeStatusRevision: status.statusRevision,
      previousRunId: status.lastTerminal?.runId ?? null });
    this.attemptApi = api;
    this.update({ attempt: { binding, projection: null, projectionRevision: status.statusRevision, acknowledged: false, adopted: false,
      startPending: true, invalidated: false, stopRequested: false, refusal: null }, error: null,
      observation: this.state.observation ? { ...this.state.observation, stale: true } : null });
    // A synchronous workspace/subscriber change can still retire intent before
    // invoke. Do not send an obsolete draft or leave an invented native owner.
    if (this.state.attempt?.binding !== binding || !this.matches(binding)) {
      if (this.state.attempt?.binding === binding) this.update({ attempt: null });
      return false;
    }
    void this.startCommand(api, input, binding);
    return true;
  }
  private async startCommand(api: DesktopApi, request: StartEnvironmentDiagnostics, binding: EnvironmentDiagnosticsBinding): Promise<void> {
    try {
      const status = await api.startEnvironmentDiagnostics(request);
      if (!this.disposed && this.state.attempt?.binding === binding) this.receive(status, 'reply', binding);
    } catch (error) {
      if (this.disposed || this.state.attempt?.binding !== binding) return;
      const safe = environmentDiagnosticsError(error);
      // Only these exact structured native rejections occur before admission.
      // Generic/transport/protocol/cleanup failures cannot make that claim.
      const refused = ['environment_diagnostics_invalid', 'environment_diagnostics_unavailable', 'environment_diagnostics_busy',
        'environment_diagnostics_owner', 'unknown_project', 'query_timeout'].includes(safe.code);
      this.update({ attempt: { ...this.state.attempt, startPending: false, refusal: refused ? safe : null } });
      this.failed(error);
      // One DATA read, never another Start. If no original run can be correlated,
      // retain unconfirmed intent instead of treating a missing reply as refusal.
      await this.checkStatus();
    }
  }
  private stopOriginal(): void {
    const attempt = this.state.attempt, row = attempt?.projection;
    if (!attempt?.stopRequested || !row || !(attempt.acknowledged || attempt.adopted) || row.finality !== 'pending' || !this.attemptApi) return;
    this.claimCancel(this.attemptApi, row);
  }
  cancel(row: { runId: string; ownerGeneration: string }): boolean {
    if (this.disposed || this.api?.mode !== 'native') return false;
    const active = this.state.status?.active;
    const projection = active && sameRun(active, row) ? active : this.state.attempt?.projection;
    if (!projection || !sameRun(projection, row) || projection.finality !== 'pending') return false;
    const attempt = this.state.attempt;
    if (attempt && sameRun(attempt.projection, row)) this.update({ attempt: { ...attempt, adopted: true, stopRequested: true } });
    // Explicit Cancel adopts only this displayed native token pair. Merely
    // seeing a same-context run after a lost Start never auto-cancels it.
    return this.claimCancel(this.api, projection);
  }
  private claimCancel(api: DesktopApi, row: EnvironmentDiagnosticsProjection): boolean {
    if (sameRun(this.state.cancelClaimed, row)) return false;
    this.update({ cancelClaimed: { runId: row.runId, ownerGeneration: row.ownerGeneration } });
    void this.cancelCommand(api, row.runId, row.ownerGeneration);
    return true;
  }
  private async cancelCommand(api: DesktopApi, runId: string, ownerGeneration: string): Promise<void> {
    try { this.receive(await api.cancelEnvironmentDiagnostics(runId, ownerGeneration), 'reply'); }
    catch (error) { if (!this.disposed) { this.failed(error); await this.checkStatus(); } }
  }
  dispose(): void {
    if (this.disposed) return;
    const attempt = this.state.attempt;
    if (attempt) this.update({ attempt: { ...attempt, invalidated: true, stopRequested: true } });
    this.stopOriginal();
    this.disposed = true;
    try { this.unlisten?.(); } catch { /* Native document/quit owner remains authoritative. */ }
    this.unlisten = null; this.listeners.clear(); this.draft = null;
    // Do not erase status, attempt, token pair or Unknown as if cleanup finished.
  }
}
