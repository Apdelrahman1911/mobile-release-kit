// Renderer coordination only. Native owns consent, credential custody, clocks,
// durable intent, the one POST, and original-worker finality. No automatic
// network polling/retry, replacement owner, or browser fallback lives here.
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { connectionNumericId, sameConnectionData } from './githubConnectionProtocol.ts';
import { GITHUB_RELEASE_REASON_HELP, GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES, githubReleaseBranch, githubReleaseError,
  parseGitHubReleaseStatus, githubReleaseRecoveryConfirmation, githubReleaseSelection } from './githubReleaseProtocol.ts';
import type { GitHubReleaseApi, GitHubReleaseKind, GitHubReleasePlatform, GitHubReleasePrepared,
  GitHubReleaseReason, GitHubReleaseRecord, GitHubReleaseStatus, GitHubReleaseView, GitHubReleaseSelection, GitHubReleaseStage } from './githubReleaseTypes.ts';

type Port = GitHubReleaseApi & { mode: 'native' | 'preview' | 'unavailable' };
interface Context { documentId: string; projectId: string; projectGeneration: number; repository: string;
  sessionId: string; accountId: string; repositoryId: string }
interface Observer { api: Port; active: boolean; unlisten: (() => void) | null; ready: Promise<void> | null;
  reading: Promise<void> | null; accepted: GitHubReleaseStatus | null }
interface Pending { observer: Observer; context: Context; epoch: object; kind: GitHubReleaseKind;
  revision: number; previousId: string | null; operationId: string | null; sent: boolean;
  branch: string; platform: GitHubReleasePlatform | null; selection: GitHubReleaseSelection | null; marker: string | null }
interface Review { observer: Observer; context: Context; epoch: object; prepared: GitHubReleasePrepared }

function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}
function context(view: GitHubConnectionViewState): Context | null {
  const c = view.context, s = view.status, session = s?.session;
  if (!c || !session || view.mode !== 'native' || view.retirementPending || view.uncertain || view.blocked || view.busy
      || session.state !== 'connected' || session.projectId !== c.projectId
      || session.targetRepository !== c.repository || s.account.state !== 'observed' || !s.account.value
      || s.repository.state !== 'observed' || !s.repository.value || s.repository.value.fullName.toLowerCase() !== c.repository.toLowerCase()) return null;
  return { ...c, repository: s.repository.value.fullName, sessionId: session.id,
    accountId: s.account.value.id, repositoryId: s.repository.value.id };
}
function inContext(prepared: GitHubReleasePrepared, c: Context): boolean {
  const t = prepared.target;
  return t.repository === c.repository && t.accountId === c.accountId && t.repositoryId === c.repositoryId;
}
function progress(old: GitHubReleaseStatus, next: GitHubReleaseStatus): boolean {
  if (old.revision === next.revision) return sameConnectionData(old, next);
  if (old.revision > next.revision) return false;
  const a = old.operation, b = next.operation;
  if (a?.phase === 'cleanup-unknown' || old.reason === 'cleanup-unknown') return false;
  if (a && b?.id === a.id) {
    if (a.kind !== b.kind || a.phase === 'settled' && !sameConnectionData(a, b)
        || a.reason === 'cancelled' && b.phase === 'running' && b.reason !== 'cancelled'
        || a.effect === 'potentially-applied' && b.phase === 'running' && b.effect !== 'potentially-applied') return false;
  } else if (a?.phase === 'running') return false;
  if (old.sessionId === next.sessionId) {
    for (const record of old.pending) {
      const row = next.pending.find((v) => v.prepared.target.marker === record.prepared.target.marker);
      if (!row || !sameConnectionData(record.prepared, row.prepared) || record.runId !== null && row.runId !== record.runId) return false;
    }
    if (old.prepared && next.prepared && a?.id === b?.id && !sameConnectionData(old.prepared, next.prepared)) return false;
    if (old.run && next.run && a?.id === b?.id && !sameConnectionData(old.run, next.run)) return false;
  }
  return true;
}

export class GitHubReleaseController {
  private state: GitHubReleaseView = freeze({ mode: 'unavailable', status: null, branch: '', platform: null, stage: null, recovery: false, candidateRunId: '', externalRunId: '', recoveryRunId: '', originalSourceSha: '', originalVersionName: '', originalVersionBuild: '', confirmation: '',
    recoveryConfirmation: '', recoveryConfirmationRejected: false, confirmed: false, pending: false, observing: false, cancelling: false, uncertain: false, error: null });
  private listeners = new Set<() => void>();
  private api: Port | null = null;
  private observer: Observer | null = null;
  private pending: Pending | null = null;
  private review: Review | null = null;
  private current: Context | null = null;
  private epoch: object = {};
  private blocked = false;
  private cancellationId: string | null = null;
  private disposed = false;
  private connection: () => GitHubConnectionViewState;
  private otherOperationReason: () => string | null;
  constructor(connection: () => GitHubConnectionViewState, otherOperationReason: () => string | null = () => null) {
    this.connection = connection; this.otherOperationReason = otherOperationReason;
  }
  getSnapshot = (): GitHubReleaseView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<GitHubReleaseView>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); this.listeners.forEach((fn) => fn());
  }
  private invalidate(patch: Partial<GitHubReleaseView> = {}): void {
    this.epoch = {}; this.review = null;
    if (this.pending && !this.pending.sent) { this.pending = null; patch.pending = false; }
    this.update({ confirmed: false, confirmation: '', ...patch });
  }
  syncContext = (): void => {
    if (this.disposed) return;
    const next = context(this.connection());
    if (!sameConnectionData(this.current, next)) {
      this.current = next;
      this.invalidate({ branch: '', platform: null, stage: null, recovery: false, candidateRunId: '', externalRunId: '', recoveryRunId: '', originalSourceSha: '', originalVersionName: '', originalVersionBuild: '', recoveryConfirmation: '', recoveryConfirmationRejected: false, error: this.pending ? 'target-changed' : null });
    }
  };
  setBranch(value: string): void {
    if (this.disposed || typeof value !== 'string' || value.length > 200 || value === this.state.branch) return;
    this.invalidate({ branch: value, recoveryConfirmation: '', recoveryConfirmationRejected: false, error: null });
  }
  setPlatform(value: GitHubReleasePlatform | null): void {
    if (this.disposed || value !== null && !['android', 'ios'].includes(value) || value === this.state.platform) return;
    this.invalidate({ platform: value, recoveryConfirmation: '', recoveryConfirmationRejected: false, error: null });
  }
  setStage(value: GitHubReleaseStage | null): void {
    if (this.disposed || value !== null && !['candidate', 'external-testing', 'production-submit'].includes(value) || value === this.state.stage) return;
    this.invalidate({ stage: value, recoveryConfirmation: '', recoveryConfirmationRejected: false, error: null });
  }
  setRecovery(value: boolean): void { if (this.state.recovery !== value) this.invalidate({ recovery: value === true, recoveryConfirmation: '', recoveryConfirmationRejected: false, error: null }); }
  setInput(name: 'candidateRunId' | 'externalRunId' | 'recoveryRunId' | 'originalSourceSha' | 'originalVersionName' | 'originalVersionBuild', value: string): void {
    if (this.disposed || typeof value !== 'string' || value.length > 64 || value === this.state[name]) return;
    this.invalidate({ [name]: value, recoveryConfirmation: '', recoveryConfirmationRejected: false, error: null });
  }
  setRecoveryConfirmation(value: string): void {
    if (this.disposed) return;
    if (typeof value !== 'string' || value.length > GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES
        || new TextEncoder().encode(value).byteLength > GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES) {
      // Drop an over-bound draft, never truncate it or silently prepare without it.
      this.invalidate({ recoveryConfirmation: '', recoveryConfirmationRejected: true, error: 'invalid-input' }); return;
    }
    if (value === this.state.recoveryConfirmation && !this.state.recoveryConfirmationRejected) return;
    this.invalidate({ recoveryConfirmation: value, recoveryConfirmationRejected: false,
      error: value === '' || githubReleaseRecoveryConfirmation(value, this.state.stage) ? null : 'invalid-input' });
  }
  setConfirmation(value: string): void {
    if (typeof value !== 'string' || value.length > 160) return;
    this.update({ confirmation: value });
  }
  selection(): GitHubReleaseSelection | null {
    const s = this.state;
    if (s.stage === null || s.recoveryConfirmationRejected) return null;
    const original = s.stage !== 'candidate' || s.recovery;
    const selected = { stage: s.stage,
      candidateRunId: s.stage === 'candidate' ? null : s.candidateRunId || null,
      externalRunId: s.stage === 'production-submit' ? s.externalRunId || null : null,
      recoveryRunId: s.recovery ? s.recoveryRunId || null : null,
      originalSourceSha: original ? s.originalSourceSha : null,
      originalVersion: original ? { name: s.originalVersionName, build: /^[1-9][0-9]{0,9}$/.test(s.originalVersionBuild) ? Number(s.originalVersionBuild) : 0 } : null,
      ...(s.recoveryConfirmation === '' ? {} : { recoveryConfirmation: s.recoveryConfirmation }) };
    return (!s.recovery || selected.recoveryRunId !== null) && githubReleaseSelection(selected, s.platform) ? selected : null;
  }
  setConfirmed(value: boolean): void { this.update({ confirmed: value === true && this.currentPrepared() !== null }); }
  private needsOriginal(observer: Observer): boolean {
    return this.pending?.observer === observer && this.pending.sent || !!observer.accepted?.operation && observer.accepted.operation.phase !== 'settled';
  }
  private detach(observer: Observer): void {
    observer.active = false; const stop = observer.unlisten; observer.unlisten = null;
    try { stop?.(); } catch { /* Event-listener closure is not native finality. */ }
  }
  private maintain(): Observer | null {
    if (this.observer && (this.disposed || this.observer.api !== this.api)) {
      if (this.needsOriginal(this.observer)) return this.observer;
      this.detach(this.observer); this.observer = null;
    }
    if (!this.observer && !this.disposed && this.api?.mode === 'native') {
      const o: Observer = { api: this.api, active: true, unlisten: null, ready: null, reading: null, accepted: null };
      this.observer = o; o.ready = this.monitor(o);
    }
    return this.observer;
  }
  async connect(api: Port | null): Promise<void> {
    if (this.disposed || this.api === api) return;
    this.api = api; this.syncContext(); this.invalidate({ mode: api?.mode ?? 'unavailable', recoveryConfirmation: '', recoveryConfirmationRejected: false });
    await this.maintain()?.ready;
  }
  private async monitor(o: Observer): Promise<void> {
    try {
      const unlisten = await o.api.subscribeGitHubRelease((value) => { this.receive(o, value); });
      if (!o.active) { try { unlisten(); } catch { /* Retired callback only. */ } return; }
      o.unlisten = unlisten; await this.read(o); // Local native DATA, never GitHub I/O.
    } catch { if (o.active) this.update({ error: 'runtime-unavailable' }); }
  }
  private fail(reason: GitHubReleaseReason): void {
    this.blocked = true; this.review = null;
    this.update({ error: reason, uncertain: true, confirmed: false });
  }
  private origin(p: Pending, s: GitHubReleaseStatus): boolean {
    const op = s.operation;
    if (!p.sent || s.revision <= p.revision || s.sessionId !== p.context.sessionId || !op || op.kind !== p.kind
        || op.id === p.previousId || p.operationId !== null && op.id !== p.operationId) return false;
    if (p.kind === 'prepare' && s.prepared && (!inContext(s.prepared, p.context)
        || s.prepared.target.branch !== p.branch || s.prepared.target.platform !== p.platform || !sameConnectionData(s.prepared.target.selection, p.selection))) return false;
    if (p.marker && (s.run || op.effect === 'accepted') && !s.pending.some((r) => r.prepared.target.marker === p.marker
        && inContext(r.prepared, p.context) && (op.effect !== 'accepted' || r.runId !== null) && (s.run === null || r.runId === s.run.id))) return false;
    return true;
  }
  private correlate(o: Observer, s: GitHubReleaseStatus): void {
    const p = this.pending;
    if (!p || p.observer !== o || !this.origin(p, s)) return;
    p.operationId = s.operation!.id;
    const accepted = o.accepted;
    if (!accepted || !this.origin(p, accepted)) return;
    if (accepted.operation?.phase === 'cleanup-unknown') { this.fail('cleanup-unknown'); return; }
    if (accepted.operation?.phase !== 'settled') return;
    this.pending = null;
    if (!this.blocked && p.epoch === this.epoch && sameConnectionData(p.context, context(this.connection()))
        && o.api === this.api && p.kind === 'prepare' && accepted.prepared) {
      this.review = { observer: o, context: p.context, epoch: p.epoch, prepared: accepted.prepared };
    }
    this.update({ pending: false, uncertain: this.blocked, error: this.blocked ? this.state.error :
      accepted.operation.reason === 'none' ? null : accepted.operation.reason });
  }
  private receive(o: Observer, value: unknown): GitHubReleaseStatus | null {
    if (!o.active) return null;
    const s = parseGitHubReleaseStatus(value);
    if (!s) { this.fail('response-invalid'); return null; }
    const old = o.accepted;
    if (old && s.revision < old.revision) { if (progress(s, old)) this.correlate(o, s); return s; }
    if (old && !progress(old, s)) { this.fail('response-invalid'); return null; }
    o.accepted = s;
    if (s.operation?.phase === 'cleanup-unknown' || s.reason === 'cleanup-unknown') this.fail('cleanup-unknown');
    if (this.review && (!s.prepared || s.sessionId !== this.review.context.sessionId
        || !sameConnectionData(s.prepared, this.review.prepared))) { this.review = null; this.update({ confirmed: false }); }
    this.update({ status: s });
    this.correlate(o, s);
    if (this.cancellationId === s.operation?.id && s.operation?.phase === 'settled') {
      this.cancellationId = null; this.update({ uncertain: this.blocked || this.pending !== null });
    }
    this.maintain(); return s;
  }
  private async read(o: Observer): Promise<void> {
    if (!o.active || o.reading) return o.reading ?? undefined;
    const work = Promise.resolve().then(async () => {
      if (!o.active) return;
      try { this.receive(o, await o.api.githubReleaseStatus()); }
      catch { if (o.active) this.update({ error: 'response-invalid' }); }
    });
    o.reading = work; this.update({ observing: true });
    try { await work; } finally { if (o.reading === work) { o.reading = null; this.update({ observing: false }); } }
  }
  checkStatus(): Promise<void> { const o = this.maintain(); return o && !this.disposed ? this.read(o) : Promise.resolve(); }
  currentPrepared(): GitHubReleasePrepared | null {
    const r = this.review, s = this.state.status, c = context(this.connection());
    return r && !this.blocked && r.epoch === this.epoch && r.observer === this.observer && r.observer.api === this.api
      && c && sameConnectionData(c, r.context) && s?.sessionId === c.sessionId && s.prepared
      && sameConnectionData(s.prepared, r.prepared) && this.state.branch === r.prepared.target.branch
      && this.state.platform === r.prepared.target.platform && sameConnectionData(this.selection(), r.prepared.target.selection) ? r.prepared : null;
  }
  startReason(): string | null {
    if (this.disposed || this.state.mode !== 'native' || !this.api || this.observer?.api !== this.api) return 'A native connection is required; preview never dispatches workflows.';
    if (this.blocked || this.state.uncertain) return 'Original acknowledgement or cleanup is unconfirmed. Read local Status; do not repeat the request.';
    if (this.pending || this.state.cancelling || this.state.status?.operation && this.state.status.operation.phase !== 'settled') return 'Wait for the original action to settle. Stopping locally does not cancel a GitHub run.';
    const c = context(this.connection()), s = this.state.status;
    if (!c || !s || s.sessionId !== c.sessionId) return 'Connect the selected project’s explicit repository and read local Status first.';
    if (!s.available) return GITHUB_RELEASE_REASON_HELP[s.reason];
    return this.otherOperationReason();
  }
  prepareReason(): string | null {
    return this.startReason() ?? (!githubReleaseBranch(this.state.branch) ? 'Enter an explicit branch name, such as main or release/next; no tags or refs/ prefix.' :
      this.state.platform === null ? 'Choose Android or iOS. Each review requests only one platform.' :
      this.state.recoveryConfirmationRejected ? 'The additional Apple recovery confirmation was rejected, not shortened or treated as absent. Clear it explicitly or paste the complete supported text (at most 342 ASCII bytes).' :
      this.state.recoveryConfirmation !== '' && (this.state.platform !== 'ios' || !this.state.recovery || !connectionNumericId(this.state.recoveryRunId)
        || !githubReleaseRecoveryConfirmation(this.state.recoveryConfirmation, this.state.stage)) ? 'Use the exact additional Apple confirmation for this iOS recovery step and producer. Whitespace, newlines and unsupported forms are refused; the core authenticates its original intent and effects.' :
      this.selection() === null ? 'Choose a release step and supply its original version, source commit and evidence-producing run IDs where required.' : null);
  }
  dispatchReason(): string | null {
    return this.startReason() ?? (!this.currentPrepared() ? 'Prepare and review this exact selection first.' :
      !this.state.confirmed ? 'Read the effects and explicitly confirm this one release workflow request.' :
      this.state.confirmation !== this.currentPrepared()!.confirmation ? 'Type the exact displayed release confirmation, including the original version and build number.' : null);
  }
  recordReason(record: GitHubReleaseRecord): string | null {
    const reason = this.startReason(); if (reason) return reason;
    const c = context(this.connection()), saved = this.state.status?.pending.find((r) => r.prepared.target.marker === record.prepared.target.marker);
    return c && saved && sameConnectionData(saved, record) && inContext(record.prepared, c) ? null : 'Reconnect the original project, account and repository before observing this intent.';
  }
  private begin(kind: GitHubReleaseKind, marker: string | null, invoke: (api: Port, c: Context, revision: number) => Promise<GitHubReleaseStatus>): void {
    if (this.disposed || this.startReason()) return;
    const o = this.observer!, c = context(this.connection())!, s = this.state.status!;
    const p: Pending = { observer: o, context: c, epoch: this.epoch, kind, revision: s.revision,
      previousId: s.operation?.id ?? null, operationId: null, sent: false, branch: this.state.branch, platform: this.state.platform, selection: this.selection(), marker };
    this.pending = p; this.review = null; this.update({ pending: true, confirmed: false, confirmation: '', error: null });
    // Latch before any subscriber, then recheck after synchronous notifications.
    if (this.pending !== p || p.epoch !== this.epoch || o.api !== this.api || !sameConnectionData(c, context(this.connection()))) {
      if (this.pending === p) { this.pending = null; this.update({ pending: false, error: 'target-changed' }); } return;
    }
    p.sent = true;
    const failed = (error: unknown) => {
      if (this.pending !== p) return; // Exact native settlement already won.
      const e = githubReleaseError(error);
      if (e.admission === 'not-admitted' && p.operationId === null && !this.blocked) {
        this.pending = null; this.update({ pending: false, error: e.reason }); this.maintain();
      } else this.update({ uncertain: true, error: e.reason });
    };
    try { void invoke(o.api, c, s.revision).then((reply) => {
      const accepted = this.receive(o, reply);
      if (this.pending === p && (!accepted || p.operationId === null)) this.update({ uncertain: true, error: 'response-invalid' });
    }, failed); } catch (error) { failed(error); }
  }
  prepare(): void {
    if (this.prepareReason()) return;
    const branch = this.state.branch, platform = this.state.platform!, selection = this.selection()!, connectionRevision = this.connection().status!.revision;
    this.begin('prepare', null, (api, c, revision) => api.prepareGitHubRelease({ sessionId: c.sessionId,
      expectedRevision: revision, expectedConnectionRevision: connectionRevision, branch, platform, selection }));
  }
  dispatch(): void {
    if (this.dispatchReason()) return;
    const marker = this.currentPrepared()!.target.marker, confirmation = this.state.confirmation;
    this.begin('dispatch', marker, (api, c, revision) => api.dispatchGitHubRelease({ sessionId: c.sessionId,
      expectedRevision: revision, consentId: marker, confirm: true, confirmation }));
  }
  loadPending(): void {
    this.begin('pending', null, (api, c, revision) => api.loadGitHubReleasePending({ sessionId: c.sessionId, expectedRevision: revision }));
  }
  observe(record: GitHubReleaseRecord): void {
    if (this.recordReason(record)) return;
    const marker = record.prepared.target.marker, kind = record.runId === null ? 'reconcile' : 'track';
    this.begin(kind, marker, (api, c, revision) => (kind === 'track' ? api.trackGitHubRelease : api.reconcileGitHubRelease)
      ({ sessionId: c.sessionId, expectedRevision: revision, marker }));
  }
  canCancel(): boolean {
    return !this.disposed && !this.state.cancelling && !!this.observer?.accepted?.operation
      && this.observer.accepted.operation.phase === 'running';
  }
  cancel(): void {
    if (!this.canCancel()) return;
    const o = this.observer!, id = o.accepted!.operation!.id;
    this.cancellationId = id; this.update({ cancelling: true, confirmed: false }); this.review = null;
    try { void o.api.cancelGitHubRelease({ operationId: id }).then((v) => { this.receive(o, v); }, () => {
      if (this.cancellationId === id) this.update({ uncertain: true, error: 'response-invalid' });
    }).finally(() => this.update({ cancelling: false })); }
    catch { this.update({ cancelling: false, uncertain: true, error: 'response-invalid' }); }
  }
  dispose(): void { this.disposed = true; this.listeners.clear(); this.review = null; this.api = null; this.maintain(); }
}

export function githubReleaseOwnerReason(state: GitHubReleaseView): string | null {
  return state.pending || state.uncertain || state.cancelling || state.status?.operation && state.status.operation.phase !== 'settled'
    ? 'The original protected release workflow action is running or unverified. Read its local Status before starting another operation.' : null;
}
