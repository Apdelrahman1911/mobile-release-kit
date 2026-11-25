import { enrollmentActive, enrollmentProjectId, parseVersionEnrollmentStatus } from './versionEnrollment.ts';
import type { VersionEnrollmentPort, VersionEnrollmentReason, VersionEnrollmentStatus } from './versionEnrollment.ts';
import { isEnrollmentActionKind, parseEnrollmentActionSelection, parseEnrollmentActionReference, sameEnrollmentActionSelection, sameEnrollmentActionReference, parseEnrollmentActionResult, enrollmentResultMatchesNative } from './agentVersionEnrollment.ts';
import type { AgentVersionEnrollmentPort, EnrollmentActionKind, EnrollmentActionSelection, EnrollmentDelegateRecord } from './agentVersionEnrollment.ts';
import { parseGithubActionStatus } from './agentGithubActionAccess.ts';
import type { GithubActionSelection, GithubActionDelegate, GithubActionStatus } from './agentGithubActionAccess.ts';

export interface VersionEnrollmentContext {
  port: VersionEnrollmentPort | null;
  nativeSession: object | null; // Root's original API identity; never serialized.
  projectId: string | null;
  preview: boolean;
  blockedReason: string | null; // OTHER owners/prerequisites only, excluding this lane.
  agentPort?: AgentVersionEnrollmentPort | null;
  connection?: { readonly sessionId: string; readonly revision: number } | null;
}
export interface VersionEnrollmentView {
  readonly status: VersionEnrollmentStatus | null;
  readonly stale: boolean;
  readonly pending: 'review' | 'confirm' | null;
  readonly checking: boolean;
  readonly stopping: boolean;
  readonly unknown: boolean;
  readonly issue: VersionEnrollmentReason | null;
}
type Kind = 'review' | 'confirm' | 'status' | 'cancel';
interface Scope {
  kind: Kind; context: VersionEnrollmentContext; epoch: object; operationId: string | null;
  sent: boolean; original: Promise<unknown> | null; completion: Promise<void>; finish(): void;
  agent: EnrollmentDelegateRecord | null;
}
const absent = (): VersionEnrollmentContext => ({ port: null, nativeSession: null, projectId: null, preview: false,
  blockedReason: 'Open the native app to connect a shared counter.' });
const unavailable = (c: VersionEnrollmentContext) => c.preview ? 'Shared counters are unavailable in the browser preview.' :
  !c.port || !c.nativeSession ? 'Open the native app’s current connection first.' : null;
const uncertain = 'The original counter operation is unconfirmed. Keep it open; check its status rather than starting another.';
const busy = 'The original counter operation is still finishing. Check its status or request Stop.';

// ONLY these native action errors originate BEFORE lane installation. Arbitrary
// rejected promises, renderer exceptions and result-shaped errors are unknown.
function notStarted(error: unknown): VersionEnrollmentReason | null {
  try {
    if (!error || typeof error !== 'object') return null;
    const d = Object.getOwnPropertyDescriptor(error, 'code');
    if (!d || !Object.hasOwn(d, 'value') || typeof d.value !== 'string') return null;
    const prefix = 'version_enrollment_not_started_';
    const names = ['busy', 'not_connected', 'runtime_unavailable', 'target_changed', 'review_changed', 'rate_limited'];
    return d.value.startsWith(prefix) && names.includes(d.value.slice(prefix.length)) ?
      d.value.slice(prefix.length).replaceAll('_', '-') as VersionEnrollmentReason : null;
  } catch { return null; }
}

// Original promises remain retained across navigation/context changes. There
// is no timer, automatic review/retry, native cancellation fiction or UI lease.
export class VersionEnrollmentController {
  private readonly options: { current(): VersionEnrollmentContext };
  private context: VersionEnrollmentContext = absent();
  private heldContext: VersionEnrollmentContext | null = null;
  private epoch: object = {};
  private reviewEpoch: { epoch: object; id: string } | null = null;
  private normal: Scope | null = null;
  private query: Scope | null = null;
  private stopping: Scope | null = null;
  private delegated: EnrollmentDelegateRecord | null = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  private state: VersionEnrollmentView = Object.freeze({ status: null, stale: true, pending: null,
    checking: false, stopping: false, unknown: false, issue: null });

  constructor(options: { current(): VersionEnrollmentContext }) { this.options = options; this.syncContext(); }
  getSnapshot = (): VersionEnrollmentView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  whenSettled = (): Promise<void> => Promise.all([this.normal?.completion, this.query?.completion, this.stopping?.completion, this.delegated?.original]).then(() => undefined);
  private originalOwnerReason = (): string | null => this.state.unknown || this.state.status?.phase === 'cleanup-unknown' ? uncertain :
    this.normal || this.query || this.stopping || enrollmentActive(this.state.status) ? busy : null;
  ownerReason = (): string | null => this.originalOwnerReason() ?? (this.delegated ?
    'The original counter CLI delegation is retained. Check or revoke that exact permission; no new enrollment is implied.' : null);
  private readContext(): VersionEnrollmentContext {
    try {
      const c = this.options.current();
      if (typeof c.preview !== 'boolean' || c.nativeSession !== null && typeof c.nativeSession !== 'object' ||
          c.blockedReason !== null && typeof c.blockedReason !== 'string') return absent();
      const p = c.port;
      const a = c.agentPort, connection = c.connection;
      return { port: p && ['status', 'review', 'confirm', 'cancel'].every((k) => typeof p[k as keyof VersionEnrollmentPort] === 'function') ? p : null,
        nativeSession: c.nativeSession, projectId: enrollmentProjectId(c.projectId) ? c.projectId : null,
        preview: c.preview, blockedReason: c.blockedReason,
        agentPort: a && typeof a.review === 'function' && typeof a.confirm === 'function' ? a : null,
        connection: connection && typeof connection.sessionId === 'string' && connection.sessionId.length >= 1 && connection.sessionId.length <= 64 &&
          !/[^A-Za-z0-9_-]/.test(connection.sessionId) && Number.isSafeInteger(connection.revision) && connection.revision > 0 && connection.revision < 0xffff_ffff ?
          { sessionId: connection.sessionId, revision: connection.revision } : null };
    } catch { return absent(); }
  }
  private sameSession(a: VersionEnrollmentContext, b: VersionEnrollmentContext): boolean {
    return a.port === b.port && a.nativeSession === b.nativeSession && a.preview === b.preview;
  }
  private sameContext(a: VersionEnrollmentContext, b: VersionEnrollmentContext): boolean {
    return this.sameSession(a, b) && a.projectId === b.projectId;
  }
  private current(scope: Scope): boolean {
    const c = this.readContext();
    return !this.disposed && scope.epoch === this.epoch && this.sameContext(scope.context, c) &&
      (!scope.agent || c.agentPort === scope.agent.port);
  }
  private patch(change: Partial<VersionEnrollmentView> = {}): void {
    this.state = Object.freeze({ ...this.state, ...change, pending: this.normal?.kind === 'confirm' ? 'confirm' : this.normal ? 'review' : null,
      checking: this.query !== null, stopping: this.stopping !== null });
    if (!this.disposed) for (const listener of [...this.listeners]) { try { listener(); } catch { /* No owner release from UI delivery. */ } }
  }
  // Root calls BEFORE workspace/account/repository/API intents, including ABA,
  // then syncs context. It must not replace/dispose an owned original pair.
  beforeContextIntent = (): void => { this.epoch = {}; this.reviewEpoch = null; this.patch({ stale: true }); };
  syncContext(): void {
    if (this.disposed) return;
    const c = this.readContext(), changed = !this.sameContext(c, this.context);
    const display = c.blockedReason !== this.context.blockedReason;
    this.context = c;
    if (changed) { this.epoch = {}; this.reviewEpoch = null; }
    if (changed || display) this.patch(changed ? { stale: true } : {});
  }
  private reviewActionReason(agent: EnrollmentDelegateRecord | null): string | null {
    const c = this.readContext();
    return this.disposed ? 'This controller has been retired.' :
      (agent && this.delegated === agent ? this.originalOwnerReason() : this.ownerReason()) ?? unavailable(c) ??
      (!c.projectId ? 'Select a saved native project first.' : c.blockedReason);
  }
  reviewReason(): string | null { return this.reviewActionReason(null); }
  private confirmActionReason(agent: EnrollmentDelegateRecord | null): string | null {
    const status = this.state.status;
    return this.reviewActionReason(agent) ?? (this.state.stale || status?.phase !== 'reviewed' || status.projectId !== this.readContext().projectId ||
      this.reviewEpoch?.epoch !== this.epoch || this.reviewEpoch.id !== status.review?.id ? 'Review this counter again before connecting it.' : null);
  }
  confirmReason(): string | null { return this.confirmActionReason(null); }
  private controlContext(): VersionEnrollmentContext {
    // Status/STOP always address the retained original host during owned work,
    // even if an erroneous outer rebind or project switch already occurred.
    return this.ownerReason() && this.heldContext ? this.heldContext : this.readContext();
  }
  checkReason(): string | null {
    return this.disposed ? 'This controller has been retired.' : this.query ? 'Checking the original operation…' : unavailable(this.controlContext());
  }
  stopReason(): string | null {
    return this.disposed ? 'This controller has been retired.' : this.stopping ? 'Stop is already requested…' :
      unavailable(this.controlContext()) ?? (!this.state.status?.operationId || this.normal &&
        this.normal.operationId !== this.state.status.operationId ? 'Check status to find the original operation before requesting Stop.' :
        !enrollmentActive(this.state.status) && this.state.status?.phase !== 'reviewed' && !this.normal ? 'No pending counter operation was reported.' : null);
  }
  private begin(kind: Kind, c: VersionEnrollmentContext, agent: EnrollmentDelegateRecord | null = null): Scope {
    let reset = false;
    if (this.heldContext && !this.sameSession(this.heldContext, c)) {
      // Admission/controls cannot get here with a still-owned foreign host.
      reset = true; this.reviewEpoch = null;
    }
    this.heldContext = c;
    let finish!: () => void;
    const completion = new Promise<void>((resolve) => { finish = resolve; });
    const scope: Scope = { kind, context: c, epoch: this.epoch, operationId: kind === 'cancel' ? this.state.status?.operationId ?? null : null,
      sent: false, original: null, completion, finish, agent };
    if (kind === 'status') this.query = scope;
    else if (kind === 'cancel') this.stopping = scope;
    else { this.normal = scope; this.reviewEpoch = null; }
    this.patch({ issue: null, ...(reset ? { status: null, stale: true } : {}),
      ...(kind === 'review' || kind === 'confirm' || kind === 'cancel' ? { stale: true } : {}) });
    return scope;
  }
  private end(scope: Scope): void {
    if (this.normal === scope) this.normal = null;
    if (this.query === scope) this.query = null;
    if (this.stopping === scope) this.stopping = null;
    this.patch(); scope.finish();
    if (this.delegated) this.settleDelegation(this.delegated);
  }
  private unknown(): void { this.reviewEpoch = null; this.patch({ unknown: true, stale: true, issue: 'cleanup-unknown' }); }
  private accept(scope: Scope, raw: unknown): void {
    const status = parseVersionEnrollmentStatus(raw);
    if (!status || !this.heldContext || !this.sameSession(this.heldContext, scope.context)) { this.unknown(); return; }
    if (scope.kind === 'review' || scope.kind === 'confirm') {
      if (status.projectId !== scope.context.projectId || status.operationId === null ||
          scope.operationId !== null && scope.operationId !== status.operationId ||
          ![scope.kind === 'confirm' ? 'connected' : 'reviewed', 'refused', 'cleanup-unknown'].includes(status.phase)) { this.unknown(); return; }
      // This is the returned ORIGINAL action, not a status observation. Keep
      // its native fact independently from any coalesced display projection.
      if (scope.agent) scope.agent.native = status;
    } else if (scope.kind === 'cancel' && status.operationId !== scope.operationId) { this.unknown(); return; }
    const previous = this.state.status;
    if (previous && status.revision < previous.revision) return; // Ordinary cross-request response order, never a rollback.
    if (previous && status.revision === previous.revision && JSON.stringify(status) !== JSON.stringify(previous)) { this.unknown(); return; }
    // A status query may discover this operation's native ID while its long
    // request is still pending. It cannot create a review/consent from DATA.
    if (scope.kind === 'status' && this.normal?.sent && status.projectId === this.normal.context.projectId && enrollmentActive(status)) {
      if (this.normal.operationId !== null && this.normal.operationId !== status.operationId) { this.unknown(); return; }
      this.normal.operationId = status.operationId;
    }
    if (status.phase === 'cleanup-unknown') { this.patch({ status }); this.unknown(); return; }
    // Parse can run Proxy descriptor traps; recheck the original context AFTER
    // parsing too. A retired success is retained only as stale original DATA.
    const current = this.current(scope) && (status.projectId === null || status.projectId === scope.context.projectId);
    if (scope.kind === 'review' && status.phase === 'reviewed' && current && !this.state.unknown) {
      this.reviewEpoch = { epoch: scope.epoch, id: status.review!.id };
    } else if (status.phase !== 'reviewed') this.reviewEpoch = null;
    this.patch({ status, stale: !current || this.state.unknown, issue: null });
  }
  private fail(scope: Scope, error: unknown): void {
    const reason = scope.kind === 'review' || scope.kind === 'confirm' ? notStarted(error) : null;
    if (reason) this.patch({ stale: true, issue: reason });
    else this.unknown();
  }
  private async action(kind: 'review' | 'confirm', agent: EnrollmentDelegateRecord | null = null): Promise<boolean> {
    this.syncContext();
    if ((kind === 'review' ? this.reviewActionReason(agent) : this.confirmActionReason(agent)) !== null ||
        agent && !this.delegationCurrent(agent)) return false;
    const reviewId = kind === 'confirm' ? this.state.status!.review!.id : null;
    const scope = this.begin(kind, this.readContext(), agent);
    try {
      // Listener reentrancy cannot hand off a stale/blocked/revoked intent.
      const live = this.readContext();
      if (!this.current(scope) || live.blockedReason !== null || this.stopping || !scope.context.projectId ||
          agent && (this.delegated !== agent || agent.unknown || !agent.query || agent.epoch !== this.epoch ||
            live.agentPort !== agent.port || live.connection?.sessionId !== agent.selection.sessionId ||
            live.connection.revision !== agent.selection.expectedConnectionRevision)) return false;
      scope.sent = true;
      if (agent) agent.sent = true;
      scope.original = agent ? (kind === 'review' ? agent.port.review(agent.query!, scope.context.projectId) : agent.port.confirm(agent.query!, scope.context.projectId, reviewId!)) :
        kind === 'review' ? scope.context.port!.review(scope.context.projectId) : scope.context.port!.confirm(scope.context.projectId, reviewId!);
      if (agent && !(scope.original instanceof Promise)) throw new Error('Missing original enrollment caller');
      this.accept(scope, await scope.original);
    } catch (e) { this.fail(scope, e); }
    finally { this.end(scope); }
    return scope.sent; // Dispatch only, never native admission or success.
  }
  review = (): Promise<boolean> => this.action('review');
  confirm = (): Promise<boolean> => this.action('confirm');

  private selectionData(c: VersionEnrollmentContext, kind: EnrollmentActionKind): EnrollmentActionSelection | null {
    const s = this.state.status, connection = c.connection;
    if (!c.agentPort || !connection || !c.projectId || this.state.stale || this.state.unknown || !s ||
        s.revision >= 0xffff_ffff || s.projectId !== null && s.projectId !== c.projectId || enrollmentActive(s)) return null;
    if (kind === 'counter-enrollment-connect' && (s.phase !== 'reviewed' || !s.review ||
        this.reviewEpoch?.epoch !== this.epoch || this.reviewEpoch.id !== s.review.id)) return null;
    return parseEnrollmentActionSelection({ kind, sessionId: connection.sessionId, expectedRevision: s.revision,
      expectedConnectionRevision: connection.revision, ...(kind === 'counter-enrollment-connect' ? { reviewId: s.review!.id } : {}) });
  }
  agentSelection(kind: EnrollmentActionKind): EnrollmentActionSelection | null {
    if (!isEnrollmentActionKind(kind) || this.reviewReason()) return null;
    return this.selectionData(this.readContext(), kind);
  }
  // These two pure comparison helpers are for App's reciprocal busy gates.
  // They never call current()/publish recursively and confer no RAW authority.
  agentPeerSelection(): EnrollmentActionSelection | null { return this.delegated && !this.delegated.unknown ? this.delegated.selection : null; }
  agentSelected(selection: GithubActionSelection): boolean {
    if (!isEnrollmentActionKind(selection.kind) || this.disposed || this.state.unknown) return false;
    const selected = this.delegated ? this.delegated.epoch === this.epoch && !this.delegated.unknown ? this.delegated.selection : null :
      this.selectionData(this.context, selection.kind);
    return !!selected && sameEnrollmentActionSelection(selected, selection as EnrollmentActionSelection);
  }
  private delegationCurrent(d: EnrollmentDelegateRecord): boolean {
    const c = this.readContext();
    return this.delegated === d && !d.unknown && !d.released && !this.disposed && d.epoch === this.epoch &&
      this.sameContext(d.context, c) && c.agentPort === d.port && c.connection?.sessionId === d.selection.sessionId &&
      c.connection.revision === d.selection.expectedConnectionRevision && !c.blockedReason && this.state.status === d.status &&
      !this.state.stale && !this.state.unknown && (d.selection.kind !== 'counter-enrollment-connect' || this.reviewEpoch === d.reviewEpoch);
  }
  agentDelegate(raw: GithubActionSelection): GithubActionDelegate | null {
    const selection = parseEnrollmentActionSelection(raw);
    if (!selection || !this.agentSelected(selection) || this.reviewReason()) return null;
    const c = this.readContext(), status = this.state.status, current = this.selectionData(c, selection.kind);
    if (!c.agentPort || !status || !current || !sameEnrollmentActionSelection(selection, current)) return null;
    const d: EnrollmentDelegateRecord = { context: c, epoch: this.epoch, selection, status, reviewEpoch: this.reviewEpoch, port: c.agentPort,
      allowReturned: false, started: false, sent: false, returned: false, original: null, reference: null, query: null, grantId: null,
      native: null, terminal: null, unused: false, noAllow: false, unknown: false, released: false };
    this.delegated = d; this.heldContext = c; this.patch();
    const uncertainDelegate = () => { d.unknown = true; if (this.delegated === d) this.unknown(); };
    return Object.freeze({ current: () => this.delegationCurrent(d), released: () => d.released && !d.unknown,
      allowReturned: () => { if (this.delegated === d && !d.unknown) { d.allowReturned = true; this.patch(); } },
      observe: (rawStatus: GithubActionStatus) => {
        if (this.delegated !== d || d.unknown) return;
        const s = parseGithubActionStatus(rawStatus), reference = s ? parseEnrollmentActionReference(s.review) : null;
        if (!s || !reference || !sameEnrollmentActionSelection(reference, d.selection) || s.settlement === 'unknown' ||
            d.reference && !sameEnrollmentActionReference(reference, d.reference) || d.grantId && d.grantId !== s.grantId ||
            d.query && (d.query.projectId !== s.origin.projectId || d.query.serviceInstance !== s.origin.serviceInstance || d.query.requestId !== s.origin.requestId)) { uncertainDelegate(); return; }
        d.reference ??= reference; d.grantId ??= s.grantId; d.query ??= s.origin;
        if (s.settlement === 'settled') { d.terminal = s; this.settleDelegation(d); return; }
        if (s.state !== 'queued' || d.started || !d.allowReturned || !this.delegationCurrent(d) || this.originalOwnerReason()) return;
        d.started = true; // Before begin publishes; repeated Check never replays.
        const original = this.action(d.selection.kind === 'counter-enrollment-review' ? 'review' : 'confirm', d); d.original = original;
        void original.then(() => { d.returned = true; this.settleDelegation(d); }, () => { d.returned = true; uncertainDelegate(); });
      },
      unusedReturned: () => { if (this.delegated === d && !d.unknown) { d.unused = true; this.settleDelegation(d); } },
      notSubmitted: () => { if (this.delegated === d && !d.unknown) { d.noAllow = true; d.unused = true; this.settleDelegation(d); } },
      uncertain: uncertainDelegate,
    });
  }
  private settleDelegation(d: EnrollmentDelegateRecord): void {
    if (this.delegated !== d || d.unknown || this.state.unknown || d.started && !d.returned ||
        this.normal?.agent === d || this.stopping || this.query || !d.allowReturned && !d.noAllow) return;
    const s = d.terminal;
    if (s) {
      if (s.neverAdmitted) { if (d.native !== null || s.operationId !== null) { d.unknown = true; this.unknown(); return; } }
      else {
        const native = d.native, result = parseEnrollmentActionResult(s.result, d.selection.kind, s.operationId);
        if (!d.started || !d.sent || !native || native.operationId !== s.operationId || native.projectId !== d.context.projectId ||
            !result || !enrollmentResultMatchesNative(result, native)) { d.unknown = true; this.unknown(); return; }
      }
    } else if (!d.unused || d.started) return;
    // Only presentation is released. The shared permission controller still
    // requires Revoke+Check; App's shared-owner gate blocks new actions until
    // that actual withdrawal. Never Stop or erase a genuine returned Review.
    d.released = true; this.delegated = null; this.patch();
  }
  private async control(kind: 'status' | 'cancel'): Promise<boolean> {
    this.syncContext();
    if ((kind === 'status' ? this.checkReason() : this.stopReason()) !== null) return false;
    // Install the STOP scope before publishing to listeners; none can reenter
    // a second STOP between retirement and the original request handoff.
    if (kind === 'cancel') { this.epoch = {}; this.reviewEpoch = null; }
    const scope = this.begin(kind, this.controlContext());
    try {
      if (this.disposed || unavailable(scope.context) !== null || kind === 'cancel' && !scope.operationId) return false;
      scope.sent = true;
      scope.original = kind === 'status' ? scope.context.port!.status() : scope.context.port!.cancel(scope.operationId!);
      this.accept(scope, await scope.original);
    } catch (e) { this.fail(scope, e); }
    finally { this.end(scope); }
    return scope.sent;
  }
  check = (): Promise<boolean> => this.control('status');
  stop = (): Promise<boolean> => this.control('cancel');
  dispose(): void { this.disposed = true; this.beforeContextIntent(); this.listeners.clear(); }
}
