// App-owned observation only. Native owns the saved originals, read consent,
// provider, absolute deadlines and finality. No polling, replacement owner or writes.
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import { parseSavedConfigContent } from './offlinePreflightProtocol.ts';
import { GITHUB_HISTORY_REASON_HELP, GITHUB_HISTORY_STAGES, GITHUB_HISTORY_PLATFORMS,
  githubHistorySelection, githubHistoryRequestFits, githubHistoryError, parseGitHubHistoryStatus } from './githubHistoryProtocol.ts';
import type { GitHubHistoryApi, GitHubHistoryPlatform, GitHubHistoryReason, GitHubHistoryResult,
  GitHubHistorySelection, GitHubHistoryStage, GitHubHistoryStatus, GitHubHistoryView } from './githubHistoryTypes.ts';

type Port = GitHubHistoryApi & { mode: 'native' | 'preview' | 'unavailable' };
interface Context {
  documentId: string; projectId: string; projectGeneration: number; repository: string;
  sessionId: string; accountId: string; repositoryId: string;
  draftRevision: number; baselineGeneration: number; observationGeneration: number; savedConfig: { bytes: number; sha256: string };
}
interface Observer { api: Port; active: boolean; unlisten: (() => void) | null; ready: Promise<void> | null;
  reading: Promise<void> | null; accepted: GitHubHistoryStatus | null; invalidated: boolean }
interface Pending { observer: Observer; context: Context; epoch: object; selection: GitHubHistorySelection;
  revision: number; previousId: string | null; operationId: string | null; sent: boolean; cancelAfterAdmission: boolean; cancelRequested: boolean }
interface Observation { observer: Observer; context: Context; epoch: object; id: string; result: GitHubHistoryResult }
interface Callbacks { connection: () => GitHubConnectionViewState; selectedProject: () => ProjectSession | null; otherOperationReason?: () => string | null }
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); } return value;
}
function counter(value: number): boolean { return Number.isSafeInteger(value) && value >= 0 && value < 4294967295; }
function context(connection: GitHubConnectionViewState, project: ProjectSession | null): Context | null {
  const c = connection.context, s = connection.status, session = s?.session;
  if (!c || !s || !session || !project || project.project.id !== c.projectId || connection.mode !== 'native'
      || connection.retirementPending || connection.uncertain || connection.blocked || connection.busy
      || session.state !== 'connected' || session.projectId !== c.projectId || session.targetRepository !== c.repository
      || s.account.state !== 'observed' || !s.account.value || s.repository.state !== 'observed' || !s.repository.value
      || s.repository.value.fullName.toLowerCase() !== c.repository.toLowerCase()
      || project.draft === null || isDirty(project) || project.sourceChanged || project.snapshotPredatesSave || project.snapshotError !== null
      || project.snapshotRequest !== null || project.saveRecoveryRequired || project.saveRecoveryNeedsReload
      || project.validatedRevision === project.revision && project.validatedBaselineGeneration === project.baselineGeneration && project.validation?.valid === false
      || ![c.projectGeneration, project.revision, project.baselineGeneration, project.observationGeneration].every(counter)) return null;
  const savedConfig = parseSavedConfigContent(project.savedConfigContent); if (!savedConfig) return null;
  return { ...c, repository: s.repository.value.fullName, sessionId: session.id, accountId: s.account.value.id,
    repositoryId: s.repository.value.id, draftRevision: project.revision, baselineGeneration: project.baselineGeneration,
    observationGeneration: project.observationGeneration, savedConfig };
}
function inContext(result: GitHubHistoryResult, c: Context, selection: GitHubHistorySelection): boolean {
  const t = result.context;
  return t.repository === c.repository && t.accountId === c.accountId && t.repositoryId === c.repositoryId
    && t.configSha256 === c.savedConfig.sha256 && same(t.selection, selection);
}
function progress(old: GitHubHistoryStatus, next: GitHubHistoryStatus): boolean {
  if (old.revision === next.revision) return same(old, next);
  if (old.revision > next.revision || old.reason === 'cleanup-unknown' || old.operation?.phase === 'cleanup-unknown') return false;
  const a = old.operation, b = next.operation;
  if (a && b?.id === a.id) {
    if (old.sessionId !== next.sessionId || !same(a.selection, b.selection)
        || a.phase === 'stopping' && b.phase === 'running'
        || a.phase === 'settled' && (!same(a, b) || !same(old.result, next.result))) return false;
  } else if (a && a.phase !== 'settled') return false;
  return true;
}
export class GitHubHistoryController {
  private state: GitHubHistoryView = freeze({ mode: 'unavailable', status: null, runId: '', attempt: '', stage: null, platform: null,
    pending: false, observing: false, cancelling: false, uncertain: false, error: null });
  private listeners = new Set<() => void>();
  private readonly callbacks: Callbacks;
  private api: Port | null = null;
  private observer: Observer | null = null;
  private current: Context | null = null;
  private epoch: object = {};
  private pending: Pending | null = null;
  private observation: Observation | null = null;
  private blocked = false;
  private disposed = false;
  private cancelClaim: { observer: Observer; id: string } | null = null;
  private cancelledOriginal: { observer: Observer; id: string } | null = null;
  constructor(callbacks: Callbacks) { this.callbacks = callbacks; }
  getSnapshot = (): GitHubHistoryView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<GitHubHistoryView>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); this.listeners.forEach((fn) => fn());
  }
  private liveContext(): Context | null { return context(this.callbacks.connection(), this.callbacks.selectedProject()); }
  private invalidate(patch: Partial<GitHubHistoryView> = {}): void {
    this.epoch = {}; this.observation = null;
    if (this.observer) this.observer.invalidated = true;
    if (this.pending && !this.pending.sent) { this.pending = null; patch.pending = false; }
    else if (this.pending) this.pending.cancelAfterAdmission = true;
    this.update(patch); this.stopInvalidatedOriginal();
  }
  // Invoke BEFORE workspace reducer, including refused/unchanged edit and switch intents.
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate({ error: 'target-changed' }); }
  syncContext = (): void => {
    if (this.disposed) return;
    const next = this.liveContext();
    if (!same(next, this.current)) { this.current = next; this.invalidate({ error: this.pending ? 'target-changed' : null }); }
  };
  setRunId(value: string): void {
    if (!this.disposed && typeof value === 'string' && value.length <= 20 && value !== this.state.runId) this.invalidate({ runId: value, error: null });
  }
  setAttempt(value: string): void {
    if (!this.disposed && typeof value === 'string' && value.length <= 3 && value !== this.state.attempt) this.invalidate({ attempt: value, error: null });
  }
  setStage(value: GitHubHistoryStage | null): void {
    if (!this.disposed && (value === null || GITHUB_HISTORY_STAGES.includes(value)) && value !== this.state.stage) this.invalidate({ stage: value, error: null });
  }
  setPlatform(value: GitHubHistoryPlatform | null): void {
    if (!this.disposed && (value === null || GITHUB_HISTORY_PLATFORMS.includes(value)) && value !== this.state.platform) this.invalidate({ platform: value, error: null });
  }
  private selection(): GitHubHistorySelection | null {
    if (!/^[1-9][0-9]{0,2}$(?![\s\S])/.test(this.state.attempt)) return null;
    const value = { runId: this.state.runId, attempt: Number(this.state.attempt), stage: this.state.stage, platform: this.state.platform };
    return githubHistorySelection(value) ? value : null;
  }
  private needsOriginal(o: Observer): boolean {
    return this.blocked || this.pending?.observer === o && this.pending.sent || this.cancelClaim?.observer === o
      || !!o.accepted?.operation && o.accepted.operation.phase !== 'settled';
  }
  private detach(o: Observer): void { o.active = false; const stop = o.unlisten; o.unlisten = null; try { stop?.(); } catch { /* Listener closure is not native finality. */ } }
  private maintain(): Observer | null {
    if (this.observer && (this.disposed || this.observer.api !== this.api)) {
      if (this.needsOriginal(this.observer)) return this.observer;
      this.detach(this.observer); this.observer = null;
    }
    if (!this.observer && !this.disposed && this.api?.mode === 'native') {
      const o: Observer = { api: this.api, active: true, unlisten: null, ready: null, reading: null, accepted: null, invalidated: false };
      this.observer = o; o.ready = this.monitor(o);
    }
    return this.observer;
  }
  async connect(api: Port | null): Promise<void> {
    if (this.disposed || api === this.api) return;
    this.api = api; this.syncContext(); this.invalidate({ mode: api?.mode ?? 'unavailable' }); await this.maintain()?.ready;
  }
  private async monitor(o: Observer): Promise<void> {
    try {
      const unlisten = await o.api.subscribeGitHubHistory((value) => { this.receive(o, value); });
      if (!o.active) { try { unlisten(); } catch { /* No original settlement. */ } return; }
      o.unlisten = unlisten; await this.read(o);
    } catch { if (o.active) this.fail('runtime-unavailable'); }
  }
  private fail(reason: GitHubHistoryReason): void {
    this.blocked = true; this.observation = null; this.update({ error: reason, uncertain: true });
  }
  private origin(p: Pending, s: GitHubHistoryStatus): boolean {
    const op = s.operation;
    return p.sent && s.revision > p.revision && s.sessionId === p.context.sessionId && op !== null
      && op.id !== p.previousId && (p.operationId === null || op.id === p.operationId) && same(op.selection, p.selection)
      && (s.result === null || inContext(s.result, p.context, p.selection));
  }
  private correlate(o: Observer, s: GitHubHistoryStatus): void {
    const p = this.pending;
    if (!p || p.observer !== o || !this.origin(p, s)) return;
    p.operationId = s.operation!.id;
    const actual = o.accepted;
    if (!actual || !this.origin(p, actual)) return;
    if (actual.operation?.phase === 'cleanup-unknown') { this.fail('cleanup-unknown'); return; }
    if (actual.operation?.phase !== 'settled') { this.stopInvalidatedOriginal(); return; }
    this.pending = null;
    if (!this.blocked && actual.available && p.epoch === this.epoch && same(p.context, this.liveContext()) && o.api === this.api && actual.result)
      this.observation = { observer: o, context: p.context, epoch: p.epoch, id: actual.operation.id, result: actual.result };
    this.update({ pending: false, uncertain: this.blocked, error: this.blocked ? this.state.error :
      actual.operation.reason === 'none' ? null : actual.operation.reason });
  }
  private receive(o: Observer, value: unknown): GitHubHistoryStatus | null {
    if (!o.active) return null;
    const s = parseGitHubHistoryStatus(value);
    if (!s) { this.fail('response-invalid'); return null; }
    const p = this.pending, op = s.operation;
    if (p?.observer === o && p.sent && s.revision > p.revision && s.sessionId === p.context.sessionId
        && op && op.id !== p.previousId && (p.operationId === null || op.id === p.operationId)
        && same(op.selection, p.selection) && s.result && !inContext(s.result, p.context, p.selection)) {
      this.fail('response-invalid'); return null;
    }
    const old = o.accepted;
    if (old && s.revision < old.revision) { if (progress(s, old)) this.correlate(o, s); return s; }
    if (old && !progress(old, s)) { this.fail('response-invalid'); return null; }
    o.accepted = s;
    if (!s.available) this.observation = null;
    if (s.operation?.phase === 'cleanup-unknown' || s.reason === 'cleanup-unknown') this.fail('cleanup-unknown');
    this.update({ status: s }); this.correlate(o, s); this.stopInvalidatedOriginal();
    if (!this.blocked && !this.pending && this.cancelledOriginal?.observer === o
        && s.operation?.id === this.cancelledOriginal.id && s.operation.phase === 'settled') this.update({ uncertain: false });
    this.maintain(); return s;
  }
  private async read(o: Observer): Promise<void> {
    if (!o.active || o.reading) return o.reading ?? undefined;
    const work = Promise.resolve().then(async () => {
      if (!o.active) return;
      try { this.receive(o, await o.api.githubHistoryStatus()); }
      catch { if (o.active) this.update({ error: 'response-invalid' }); }
    });
    o.reading = work; this.update({ observing: true });
    try { await work; } finally { if (o.reading === work) { o.reading = null; this.update({ observing: false }); } }
  }
  checkStatus(): Promise<void> { const o = this.maintain(); return o && !this.disposed ? this.read(o) : Promise.resolve(); }
  currentResult(): GitHubHistoryResult | null {
    const observed = this.observation, s = this.state.status;
    return observed && !this.blocked && !this.state.uncertain && s?.available && observed.epoch === this.epoch
      && observed.observer === this.observer && observed.observer.api === this.api && same(observed.context, this.liveContext())
      && same(this.selection(), observed.result.context.selection) && s.operation?.id === observed.id
      && same(s.result, observed.result) ? observed.result : null;
  }
  contextSummary(): { repository: string; accountId: string; configSha256: string } | null {
    const c = this.liveContext(); return c ? { repository: c.repository, accountId: c.accountId, configSha256: c.savedConfig.sha256 } : null;
  }
  startReason(): string | null {
    if (this.disposed || this.state.mode !== 'native' || !this.api || !this.observer?.active || this.observer.api !== this.api) return 'A real native History capability is required. Preview does not read authenticated evidence.';
    if (this.blocked || this.state.uncertain) return 'The original acknowledgement or cleanup is unconfirmed. Read local Status; do not repeat the read.';
    const s = this.observer.accepted; // Retained prior-port DATA cannot admit a new original.
    if (this.pending || this.cancelClaim || s?.operation && s.operation.phase !== 'settled') return 'Wait for the original local read to settle. Cancel is a request, not a cleanup receipt.';
    const c = this.liveContext();
    if (!c) return 'Select the connected registered project with clean, current saved settings. Save or discard edits explicitly, resolve recovery and refresh changed saved data first.';
    if (!s || s.sessionId !== c.sessionId) return 'Read local History Status for this original GitHub connection first.';
    if (!s.available) return GITHUB_HISTORY_REASON_HELP[s.reason];
    return this.callbacks.otherOperationReason?.() ?? (!this.selection() ? 'Choose an exact run ID, attempt 1–100, release stage and platform. No latest run is selected.' : null);
  }
  start(): void {
    this.syncContext();
    if (this.startReason()) return;
    const o = this.observer!, c = this.liveContext()!, s = o.accepted!, selection = this.selection()!;
    const args = { sessionId: c.sessionId, expectedRevision: s.revision,
      expectedConnectionRevision: this.callbacks.connection().status!.revision, selection };
    if (!githubHistoryRequestFits('github_history_start', args)) { this.update({ error: 'invalid-input' }); return; }
    const p: Pending = { observer: o, context: c, epoch: this.epoch, selection, revision: s.revision,
      previousId: s.operation?.id ?? null, operationId: null, sent: false, cancelAfterAdmission: false, cancelRequested: false };
    this.pending = p; this.observation = null; this.update({ pending: true, error: null });
    // The latch precedes synchronous subscriber reentry, then every selection/context is checked again.
    if (this.pending !== p || p.epoch !== this.epoch || o.api !== this.api || o.accepted !== s || !same(c, this.liveContext())
        || this.callbacks.connection().status?.revision !== args.expectedConnectionRevision || !same(selection, this.selection())) {
      if (this.pending === p) { this.pending = null; this.update({ pending: false, error: 'target-changed' }); } return;
    }
    o.invalidated = false; // Fresh explicit read after actual current-port admission.
    p.sent = true;
    const failed = (error: unknown): void => {
      if (this.pending !== p) return; // Exact original settlement won the race.
      const e = githubHistoryError(error);
      if (e.reason === 'cleanup-unknown') { this.fail('cleanup-unknown'); return; }
      if (e.admission === 'not-admitted' && p.operationId === null && !this.blocked) {
        this.pending = null; this.update({ pending: false, error: e.reason }); this.maintain();
      } else this.update({ uncertain: true, error: e.reason });
    };
    try { void o.api.startGitHubHistory(args).then((reply) => {
      const accepted = this.receive(o, reply);
      if (this.pending === p && (!accepted || p.operationId === null)) this.update({ uncertain: true, error: 'response-invalid' });
    }, failed); } catch (error) { failed(error); }
  }
  private stopInvalidatedOriginal(): void {
    const p = this.pending, o = this.observer, op = o?.accepted?.operation;
    // Restored running originals have no local Pending. Invalidation still
    // stops that exact observed original once, without adopting its result.
    if (o?.invalidated && op && (op.phase === 'running' || op.phase === 'stopping')) this.stop(o, op.id);
    else if (p?.cancelAfterAdmission && !p.cancelRequested && p.operationId
        && p.observer.accepted?.operation?.id === p.operationId && p.observer.accepted.operation.phase !== 'settled') this.stop(p.observer, p.operationId);
  }
  private stop(o: Observer, id: string): void {
    if (this.cancelClaim || this.cancelledOriginal?.observer === o && this.cancelledOriginal.id === id) return;
    const claim = { observer: o, id }; this.cancelClaim = claim; this.cancelledOriginal = claim;
    if (this.pending?.observer === o && this.pending.operationId === id) this.pending.cancelRequested = true;
    this.update({ cancelling: true });
    const failed = (): void => {
      if (this.cancelClaim === claim && !(o.accepted?.operation?.id === id && o.accepted.operation.phase === 'settled'))
        this.update({ uncertain: true, error: 'response-invalid' });
    };
    const finished = (): void => { if (this.cancelClaim === claim) { this.cancelClaim = null; this.update({ cancelling: false }); this.maintain(); } };
    try { void o.api.cancelGitHubHistory({ operationId: id }).then((reply) => { this.receive(o, reply); }, failed).finally(finished); }
    catch { failed(); finished(); }
  }
  canCancel(): boolean {
    const o = this.observer, op = o?.accepted?.operation;
    return !this.disposed && !this.cancelClaim && !!o && !!op && (op.phase === 'running' || op.phase === 'stopping')
      && !(this.cancelledOriginal?.observer === o && this.cancelledOriginal.id === op.id);
  }
  cancel(): void { if (this.canCancel()) this.stop(this.observer!, this.observer!.accepted!.operation!.id); }
  dispose(): void {
    if (this.disposed) return;
    this.invalidate(); this.disposed = true; this.listeners.clear(); this.api = null; this.maintain();
  }
}
export function githubHistoryOwnerReason(state: GitHubHistoryView): string | null {
  return state.pending || state.uncertain || state.cancelling || state.status?.operation && state.status.operation.phase !== 'settled'
    ? 'The original authenticated History read is running or unverified. Keep its local Status and settle it before conflicting work.' : null;
}
