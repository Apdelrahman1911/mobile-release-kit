// Renderer coordination only. Native owns consent, credential custody, clocks,
// durable intent, the one PUT, and original-worker finality. No automatic
// network polling/retry, replacement owner, or browser fallback lives here.
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { sameConnectionData } from './githubConnectionProtocol.ts';
import { githubPreflightBranch } from './githubPreflightProtocol.ts';
import { parseCredentialGuide } from './credentialGuide.ts';
import { assetContextReason } from './assetSessionController.ts';
import { savedGitHubInputs } from './githubEnvironmentInputs.ts';
import type { AssetDisplayState, AssetScope } from './assetSessionTypes.ts';
import type { ProjectSession } from './drafts.ts';
import type { CredentialGuide, CredentialKind } from './types.ts';
import { GITHUB_INPUT_GROUP_REASON_HELP, githubInputGroupAssignment, githubInputGroupError, parseGitHubInputGroupStatus } from './githubInputGroupProtocol.ts';
import type { GitHubInputGroupApi, GitHubInputGroupOperationKind, GitHubInputGroupAssignment, GitHubInputGroupPrepared,
  GitHubInputGroupReason, GitHubInputGroupRecord, GitHubInputGroupStatus, GitHubInputGroupTarget, GitHubInputGroupView } from './githubInputGroupTypes.ts';

type Port = GitHubInputGroupApi & { mode: 'native' | 'preview' | 'unavailable' };
interface Context { documentId: string; projectId: string; projectGeneration: number; repository: string;
  sessionId: string; accountId: string; repositoryId: string }
interface Observer { api: Port; active: boolean; unlisten: (() => void) | null; ready: Promise<void> | null;
  reading: Promise<void> | null; accepted: GitHubInputGroupStatus | null }
interface Pending { observer: Observer; context: Context; epoch: object; kind: GitHubInputGroupOperationKind;
  revision: number; previousId: string | null; operationId: string | null; sent: boolean;
  branch: string; assignment: GitHubInputGroupAssignment | null; material: InputContext | null;
  marker: string | null; target: GitHubInputGroupTarget | null }
interface InputContext { projectId: string; revision: number; baselineGeneration: number; observationGeneration: number;
  contextRevision: number; scope: AssetScope }
export interface GitHubInputGroupChoice { assignment: GitHubInputGroupAssignment; kind: CredentialKind }
interface Review { observer: Observer; context: Context; epoch: object; material: InputContext; prepared: GitHubInputGroupPrepared }

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
function inContext(t: GitHubInputGroupTarget, c: Context): boolean {
  return t.repository === c.repository && t.accountId === c.accountId && t.repositoryId === c.repositoryId;
}
function progress(old: GitHubInputGroupStatus, next: GitHubInputGroupStatus): boolean {
  if (old.revision === next.revision) return sameConnectionData(old, next);
  if (old.revision > next.revision) return false;
  const a = old.operation, b = next.operation;
  if (a && b?.id === a.id) {
    if (a.kind !== b.kind || a.phase === 'settled' && !sameConnectionData(a, b) ||
      a.phase === 'cleanup-unknown' && b.phase !== 'cleanup-unknown' ||
      a.reason !== 'none' && b.reason !== a.reason && b.reason !== 'cleanup-unknown') return false;
  } else if (a && a.phase !== 'settled') return false;
  if (old.reason === 'cleanup-unknown' && next.reason !== 'cleanup-unknown') return false;
  if (old.sessionId === next.sessionId) {
    for (const before of old.records) {
      const after = next.records.find((row) => row.originalOperationId === before.originalOperationId);
      if (!after || !sameConnectionData(before.target, after.target)) return false;
      if (!sameConnectionData(before.write, after.write)) {
        // Metadata-only reconciliation cannot establish a past private write.
        if (b?.kind !== 'apply' || a?.id !== b.id ||
          !['not-attempted', 'attempted-outcome-unknown'].includes(before.write.state) ||
          after.write.state === 'not-attempted' || before.completion.finality === 'settled') return false;
      }
      if (before.completion.finality === 'settled' && !sameConnectionData(before, after) ||
        before.completion.finality === 'unknown' && after.completion.finality !== 'unknown' ||
        before.completion.journal === 'unknown' && after.completion.journal !== 'unknown' ||
        before.completion.cleanup === 'unknown' && after.completion.cleanup !== 'unknown' ||
        before.reason !== 'none' && after.reason !== before.reason && after.reason !== 'cleanup-unknown') return false;
    }
    if (old.prepared && next.prepared && a?.id === b?.id && !sameConnectionData(old.prepared, next.prepared)) return false;
    const before = old.runner, after = next.runner;
    const freshCheck = b?.kind === 'runner-check' && b.id !== a?.id;
    if (!freshCheck && !sameConnectionData(before, after)) {
      // Only a fresh original check clears/replaces facts. Its running null
      // summary may settle once; unrelated actions cannot renew an observation.
      const completedOriginal = before === null && a?.kind === 'runner-check' && a.phase === 'running' &&
        b?.id === a.id && b.phase === 'settled';
      const expiredOriginal = before?.result === 'safe' && after?.result === 'expired' &&
        before.checkedAt === after.checkedAt && before.expiresAt === after.expiresAt &&
        before.groupCount === after.groupCount && before.runnerCount === after.runnerCount && before.scope === after.scope;
      if (!completedOriginal && !expiredOriginal) return false;
    }
  }
  return true;
}

export class GitHubInputGroupController {
  private state: GitHubInputGroupView = freeze({ mode: 'unavailable', status: null, branch: '', assignment: null,
    confirmed: false, pending: false, observing: false, cancelling: false, uncertain: false, error: null });
  private listeners = new Set<() => void>();
  private api: Port | null = null;
  private observer: Observer | null = null;
  private pending: Pending | null = null;
  private review: Review | null = null;
  private current: Context | null = null;
  private material: InputContext | null = null;
  private guide: CredentialGuide | null = null;
  private epoch: object = {};
  private blocked = false;
  private cancellationId: string | null = null;
  private disposed = false;
  private connection: () => GitHubConnectionViewState;
  private otherOperationReason: () => string | null;
  private assets: () => AssetDisplayState;
  private project: () => ProjectSession | null;
  constructor(connection: () => GitHubConnectionViewState, assets: () => AssetDisplayState,
    project: () => ProjectSession | null, otherOperationReason: () => string | null = () => null) {
    this.connection = connection; this.assets = assets; this.project = project; this.otherOperationReason = otherOperationReason;
  }
  private inputContext(): InputContext | null {
    const p = this.project(), a = this.assets(), c = a.status?.context;
    if (!p || !savedGitHubInputs(p) || assetContextReason(a) || !c || c.projectId !== p.project.id ||
      a.status?.operation && (a.status.operation.phase !== 'idle' || a.status.operation.settlement !== 'known')) return null;
    return { projectId: p.project.id, revision: p.revision, baselineGeneration: p.baselineGeneration,
      observationGeneration: p.observationGeneration, contextRevision: c.revision,
      scope: { platform: c.platform, stage: c.stage, purpose: c.purpose } };
  }
  choices(): GitHubInputGroupChoice[] {
    const material = this.inputContext(), a = this.assets().status, saved = savedGitHubInputs(this.project());
    if (!material || !a || !saved || !this.guide) return [];
    const rows = saved.inputs.filter((row) => row.stage === material.scope.stage &&
      (row.platform === material.scope.platform || row.platform === 'project'));
    return a.assignments.flatMap((assignment) => {
      if (assignment.availability !== 'available' || assignment.contextRevision !== material.contextRevision) return [];
      const record = a.records.find((row) => row.recordId === assignment.recordId && row.revision === assignment.recordRevision &&
        row.kind === assignment.kind && row.availability === 'assigned');
      const kind = this.guide!.kinds.find((row) => row.id === assignment.kind);
      if (!record || !kind || !kind.fields.every((field) => rows.some((row) => row.name === field.requirement))) return [];
      return [{ assignment: { kind: assignment.kind, recordId: assignment.recordId, recordRevision: assignment.recordRevision,
        contextRevision: assignment.contextRevision }, kind }];
    });
  }
  selectedKind(): CredentialKind | null { return this.choices().find((row) => sameConnectionData(row.assignment, this.state.assignment))?.kind ?? null; }
  currentScope(): AssetScope | null { return this.inputContext()?.scope ?? null; }
  setGuide(value: unknown): void {
    const next = parseCredentialGuide(value);
    if (sameConnectionData(this.guide, next)) return;
    this.guide = next ? freeze(next) : null;
    this.invalidate({ assignment: null });
  }
  // Invoked synchronously before relevant workspace intents, including failed
  // reload/save attempts that need not advance a displayed revision.
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate(); }

  getSnapshot = (): GitHubInputGroupView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<GitHubInputGroupView>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); this.listeners.forEach((fn) => fn());
  }
  private invalidate(patch: Partial<GitHubInputGroupView> = {}): void {
    this.epoch = {}; this.review = null;
    if (this.pending && !this.pending.sent) { this.pending = null; patch.pending = false; }
    this.update({ confirmed: false, ...patch });
  }
  syncContext = (): void => {
    if (this.disposed) return;
    const next = context(this.connection());
    const material = this.inputContext();
    if (!sameConnectionData(this.current, next)) {
      this.current = next; this.material = material;
      this.invalidate({ branch: '', assignment: null, error: this.pending ? 'target-changed' : null });
    } else if (!sameConnectionData(this.material, material) || this.state.assignment && !this.selectedKind()) {
      this.material = material;
      this.invalidate({ assignment: null, error: this.pending ? 'context-stale' : null });
    }
  };
  setBranch(value: string): void {
    if (this.disposed || typeof value !== 'string' || value.length > 200 || value === this.state.branch) return;
    this.invalidate({ branch: value, error: null });
  }
  setAssignment(value: GitHubInputGroupAssignment | null): void {
    if (this.disposed || value !== null && (!githubInputGroupAssignment(value) ||
      !this.choices().some((row) => sameConnectionData(row.assignment, value))) || sameConnectionData(value, this.state.assignment)) return;
    this.invalidate({ assignment: value ? { ...value } : null, error: null });
  }
  setConfirmed(value: boolean): void { this.update({ confirmed: value === true && this.currentPrepared() !== null }); }
  private needsOriginal(observer: Observer): boolean {
    // Only this process's original sent work/current native operation owns it.
    return this.pending?.observer === observer && this.pending.sent ||
      !!observer.accepted?.operation && observer.accepted.operation.phase !== 'settled';
  }
  private detach(observer: Observer): void {
    observer.active = false; const stop = observer.unlisten; observer.unlisten = null;
    try { stop?.(); } catch { /* Event-listener closure is not native finality. */ }
  }
  private maintain(): Observer | null {
    if (this.observer && (this.disposed || this.observer.api !== this.api)) {
      if (this.needsOriginal(this.observer)) return this.observer;
      this.detach(this.observer); this.observer = null;
      this.update({ status: null }); // A replacement must earn its own readiness.
    }
    if (!this.observer && !this.disposed && this.api?.mode === 'native') {
      const o: Observer = { api: this.api, active: true, unlisten: null, ready: null, reading: null, accepted: null };
      this.observer = o; o.ready = this.monitor(o);
    }
    return this.observer;
  }
  async connect(api: Port | null): Promise<void> {
    if (this.disposed || this.api === api) return;
    this.api = api; this.syncContext(); this.invalidate({ mode: api?.mode ?? 'unavailable' });
    await this.maintain()?.ready;
  }
  private async monitor(o: Observer): Promise<void> {
    try {
      const unlisten = await o.api.subscribeGitHubInputGroup((value) => { this.receive(o, value); });
      if (!o.active) { try { unlisten(); } catch { /* Retired callback only. */ } return; }
      o.unlisten = unlisten; await this.read(o); // Local native DATA, never GitHub I/O.
    } catch { if (o.active) this.update({ error: 'runtime-unavailable' }); }
  }
  private fail(reason: GitHubInputGroupReason): void {
    this.blocked = true; this.review = null;
    this.update({ error: reason, uncertain: true, confirmed: false });
  }
  private origin(p: Pending, s: GitHubInputGroupStatus): boolean {
    const op = s.operation;
    if (!p.sent || s.revision <= p.revision || s.sessionId !== p.context.sessionId || !op || op.kind !== p.kind ||
      op.id === p.previousId || p.operationId !== null && op.id !== p.operationId) return false;
    if (p.kind === 'prepare' && s.prepared && (!inContext(s.prepared.target, p.context) ||
      s.prepared.target.branch !== p.branch || !sameConnectionData(s.prepared.assignment, p.assignment) ||
      !sameConnectionData(s.prepared.target.scope, p.material?.scope))) return false;
    if (p.marker) {
      const row = s.records.find((r) => r.originalOperationId === p.marker);
      if (row && (p.target === null || !sameConnectionData(row.target, p.target))) return false;
      if (op.phase === 'settled' && op.reason === 'none' && !row) return false;
      if (s.observation && s.observation.originalOperationId !== p.marker) return false;
    }
    return true;
  }
  private correlate(o: Observer, s: GitHubInputGroupStatus): void {
    const p = this.pending;
    if (!p || p.observer !== o || !this.origin(p, s)) return;
    p.operationId = s.operation!.id;
    const accepted = o.accepted;
    if (!accepted || !this.origin(p, accepted)) return;
    if (accepted.operation?.phase === 'cleanup-unknown') { this.fail('cleanup-unknown'); return; }
    if (accepted.operation?.phase !== 'settled') return;
    this.pending = null;
    if (!this.blocked && p.epoch === this.epoch && sameConnectionData(p.context, context(this.connection()))
        && o.api === this.api && p.kind === 'prepare' && accepted.prepared && p.material
        && sameConnectionData(p.material, this.inputContext()) && sameConnectionData(p.assignment, this.state.assignment)) {
      this.review = { observer: o, context: p.context, epoch: p.epoch, material: p.material, prepared: accepted.prepared };
    }
    this.update({ pending: false, uncertain: this.blocked, error: this.blocked ? this.state.error :
      accepted.operation.reason === 'none' ? null : accepted.operation.reason });
  }
  private receive(o: Observer, value: unknown): GitHubInputGroupStatus | null {
    if (!o.active) return null;
    const s = parseGitHubInputGroupStatus(value);
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
      try { this.receive(o, await o.api.githubInputGroupStatus()); }
      catch { if (o.active) this.update({ error: 'response-invalid' }); }
    });
    o.reading = work; this.update({ observing: true });
    try { await work; } finally { if (o.reading === work) { o.reading = null; this.update({ observing: false }); } }
  }
  checkStatus(): Promise<void> { const o = this.maintain(); return o && !this.disposed ? this.read(o) : Promise.resolve(); }
  currentPrepared(): GitHubInputGroupPrepared | null {
    const r = this.review, s = this.state.status, c = context(this.connection());
    return r && !this.blocked && r.epoch === this.epoch && r.observer === this.observer && r.observer.api === this.api
      && c && sameConnectionData(c, r.context) && s?.sessionId === c.sessionId && s.runner?.result === 'safe' && s.prepared
      && sameConnectionData(s.prepared, r.prepared) && this.state.branch === r.prepared.target.branch
      && sameConnectionData(this.state.assignment, r.prepared.assignment) && this.selectedKind() !== null
      && sameConnectionData(r.material, this.inputContext()) ? r.prepared : null;
  }
  startReason(): string | null {
    const observer = this.observer;
    if (this.disposed || this.state.mode !== 'native' || !this.api || !observer || observer.api !== this.api) return 'A native connection is required; preview never uploads private input groups.';
    if (!observer.active || observer.unlisten === null || observer.accepted === null || observer.accepted !== this.state.status)
      return 'Wait for this native connection’s status subscription and current local Status before starting an action.';
    if (this.blocked || this.state.uncertain) return 'Original acknowledgement or cleanup is unconfirmed. Read local Status; do not repeat the request.';
    if (this.pending || this.state.cancelling || this.state.status?.operation && this.state.status.operation.phase !== 'settled') return 'Wait for the original action to settle. Stopping locally cannot undo a GitHub update.';
    const c = context(this.connection()), s = this.state.status;
    if (!c || !s || s.sessionId !== c.sessionId) return 'Connect the selected project’s explicit repository and read local Status first.';
    if (!s.available) return GITHUB_INPUT_GROUP_REASON_HELP[s.reason];
    return this.otherOperationReason();
  }
  runnerCheckReason(): string | null {
    return this.startReason() ?? (!this.inputContext()
      ? 'Save and check the project configuration, then submit its release context in Credentials. A selected input group or branch is not needed for this read.' : null);
  }
  runnerReason(): string | null {
    const runner = this.state.status?.runner;
    if (!runner) return 'Check runner safety before reviewing or applying a private input group.';
    if (runner.result === 'expired' && runner.reason === 'expired') return 'The short-lived runner check expired. Check runner safety again; reading local Status does not renew it.';
    return runner.result === 'safe' ? null : `${GITHUB_INPUT_GROUP_REASON_HELP[runner.reason]} Fix the cause, then choose Check runner safety again.`;
  }
  prepareReason(): string | null {
    return this.startReason() ?? this.runnerReason() ?? (!githubPreflightBranch(this.state.branch) ? 'Enter an application branch, such as main or release/next; no URL, tag or refs/ prefix.' :
      !this.inputContext() ? 'Save and check the project configuration, then use Credentials to submit the current release context.' :
      !this.state.assignment || !this.selectedKind() ? 'Choose one currently assigned complete input group. Manage missing inputs in Credentials.' : null);
  }
  applyReason(): string | null {
    return this.startReason() ?? this.runnerReason() ?? (!this.currentPrepared() ? 'Prepare and review this exact whole-group update first.' :
      !this.state.confirmed ? 'Confirm that this complete group may replace its existing GitHub value.' : null);
  }
  recordReason(record: GitHubInputGroupRecord): string | null {
    const blocked = this.startReason(); if (blocked) return blocked;
    const c = context(this.connection()), saved = this.state.status?.records.find((row) => row.originalOperationId === record.originalOperationId);
    return c && saved && sameConnectionData(saved, record) && inContext(record.target, c)
      ? null : 'Reconnect the original project, account and repository and read current local Status before checking metadata.';
  }
  private begin(kind: GitHubInputGroupOperationKind, marker: string | null, target: GitHubInputGroupTarget | null,
    invoke: (api: Port, c: Context, revision: number) => Promise<GitHubInputGroupStatus>, current: () => boolean = () => true): void {
    if (this.disposed || this.startReason()) return;
    const o = this.observer!, c = context(this.connection())!, s = this.state.status!;
    const p: Pending = { observer: o, context: c, epoch: this.epoch, kind, revision: s.revision,
      previousId: s.operation?.id ?? null, operationId: null, sent: false, branch: this.state.branch,
      assignment: this.state.assignment, material: this.inputContext(), marker, target };
    this.pending = p; this.review = null; this.update({ pending: true, confirmed: false, error: null });
    // Latch before any subscriber, then recheck after synchronous notifications.
    if (this.disposed || this.blocked || this.state.uncertain || this.state.cancelling || this.cancellationId !== null ||
      this.pending !== p || p.epoch !== this.epoch || o.api !== this.api ||
      this.state.status?.revision !== s.revision || o.accepted !== this.state.status || !sameConnectionData(c, context(this.connection())) ||
      this.otherOperationReason() !== null || !current() ||
      (kind === 'runner-check' || kind === 'prepare' || kind === 'apply') && (!p.material || !sameConnectionData(p.material, this.inputContext())) ||
      (kind === 'prepare' || kind === 'apply') &&
      (!sameConnectionData(p.assignment, this.state.assignment) || !this.selectedKind() || this.runnerReason() !== null)) {
      if (this.pending === p) { this.pending = null; this.update({ pending: false,
        error: this.blocked || this.state.uncertain ? this.state.error : 'target-changed' }); } return;
    }
    p.sent = true;
    const failed = (error: unknown) => {
      if (this.pending !== p) return; // Exact native settlement already won.
      const e = githubInputGroupError(error);
      if (e.admission === 'not-admitted' && p.operationId === null && !this.blocked) {
        this.pending = null; this.update({ pending: false, error: e.reason }); this.maintain();
      } else this.update({ uncertain: true, error: e.reason });
    };
    try { void invoke(o.api, c, s.revision).then((reply) => {
      const accepted = this.receive(o, reply);
      if (this.pending === p && (!accepted || p.operationId === null)) this.update({ uncertain: true, error: 'response-invalid' });
    }, failed); } catch (error) { failed(error); }
  }
  checkRunners(): void {
    if (this.runnerCheckReason()) return;
    const expectedConnectionRevision = this.connection().status!.revision;
    const expectedAssetStatusRevision = this.assets().status!.statusRevision, contextRevision = this.inputContext()!.contextRevision;
    this.begin('runner-check', null, null, (api, c, expectedRevision) => api.checkGitHubInputRunners({ sessionId: c.sessionId,
      expectedRevision, expectedConnectionRevision, expectedAssetStatusRevision, contextRevision }),
      () => this.connection().status?.revision === expectedConnectionRevision &&
        this.assets().status?.statusRevision === expectedAssetStatusRevision && this.inputContext()?.contextRevision === contextRevision);
  }
  prepare(): void {
    if (this.prepareReason()) return;
    const branch = this.state.branch, assignment = { ...this.state.assignment! }, expectedConnectionRevision = this.connection().status!.revision;
    const expectedAssetStatusRevision = this.assets().status!.statusRevision;
    this.begin('prepare', null, null, (api, c, expectedRevision) => api.prepareGitHubInputGroup({ sessionId: c.sessionId,
      expectedRevision, expectedConnectionRevision, expectedAssetStatusRevision, branch, assignment }),
      () => this.connection().status?.revision === expectedConnectionRevision && this.assets().status?.statusRevision === expectedAssetStatusRevision);
  }
  apply(): void {
    if (this.applyReason()) return;
    const reviewed = this.currentPrepared()!;
    const connectionRevision = this.connection().status!.revision, assetStatusRevision = this.assets().status!.statusRevision;
    this.begin('apply', reviewed.consentId, reviewed.target, (api, c, expectedRevision) => api.applyGitHubInputGroup({ sessionId: c.sessionId,
      expectedRevision, consentId: reviewed.consentId, confirmUpsertWholeGroup: true }),
      () => this.connection().status?.revision === connectionRevision && this.assets().status?.statusRevision === assetStatusRevision);
  }
  loadPending(): void {
    this.begin('pending', null, null, (api, c, expectedRevision) => api.loadGitHubInputGroupPending({ sessionId: c.sessionId, expectedRevision }));
  }
  observe(record: GitHubInputGroupRecord): void {
    if (this.recordReason(record)) return;
    this.begin('reconcile', record.originalOperationId, record.target, (api, c, expectedRevision) => api.reconcileGitHubInputGroup({
      sessionId: c.sessionId, expectedRevision, originalOperationId: record.originalOperationId }));
  }
  canCancel(): boolean {
    return !this.disposed && !this.state.cancelling && !!this.observer?.accepted?.operation
      && this.observer.accepted.operation.phase === 'running';
  }
  cancel(): void {
    if (!this.canCancel()) return;
    const o = this.observer!, id = o.accepted!.operation!.id;
    this.cancellationId = id; this.update({ cancelling: true, confirmed: false }); this.review = null;
    try { void o.api.cancelGitHubInputGroup({ operationId: id }).then((v) => { this.receive(o, v); }, () => {
      if (this.cancellationId === id) this.update({ uncertain: true, error: 'response-invalid' });
    }).finally(() => this.update({ cancelling: false })); }
    catch { this.update({ cancelling: false, uncertain: true, error: 'response-invalid' }); }
  }
  dispose(): void { this.disposed = true; this.listeners.clear(); this.review = null; this.api = null; this.maintain(); }
}

export function githubInputGroupOwnerReason(state: GitHubInputGroupView): string | null {
  return state.pending || state.uncertain || state.cancelling || state.status?.operation && state.status.operation.phase !== 'settled'
    ? 'The original GitHub input-group action is running or unverified. Read its local Status before starting another operation.' : null;
}
