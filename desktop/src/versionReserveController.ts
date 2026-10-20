import { parseReserveOptions, parseVersionReserveStatus, reserveActive, reserveProject } from './versionReserve.ts';
import type { ReservedVersion, VersionReserveOptions, VersionReservePort, VersionReserveStatus } from './versionReserve.ts';
import { AgentVersionReserveAccessController } from './agentVersionReserveAccessController.ts';
import type { AgentVersionReserveCompletion, AgentVersionReserveReview } from './agentVersionReserveAccessController.ts';
import type { AgentVersionReserveAccessPort } from './agentVersionReserveAccess.ts';

export interface VersionReserveContext {
  port: VersionReservePort | null; nativeSession: object | null; projectId: string | null; preview: boolean;
  blockedReason: string | null; // OTHER owners only. Native still admits every action.
  cliAccessPort?: AgentVersionReserveAccessPort | null;
  editor: { reservedOpenReason(): string | null; openReserved(value: ReservedVersion): boolean } | null;
}
export interface VersionReserveView {
  readonly enabled: boolean; readonly options: VersionReserveOptions; readonly status: VersionReserveStatus | null;
  readonly stale: boolean; readonly pending: 'review' | 'reserve' | null; readonly checking: boolean; readonly stopping: boolean;
  readonly unknown: boolean; readonly issue: string | null; readonly editHandedOff: boolean;
}
type Kind = 'review' | 'reserve' | 'status' | 'cancel';
interface Work {
  kind: Kind; context: VersionReserveContext; epoch: object; options: VersionReserveOptions; operationId: string | null;
  sent: boolean; original: Promise<unknown> | null; completion: Promise<void>; finish(): void;
  cliCompletion: AgentVersionReserveCompletion | null;
}
const absent = (): VersionReserveContext => ({ port: null, nativeSession: null, projectId: null, preview: false, editor: null,
  blockedReason: 'Open the native app first.' });
const unavailable = (c: VersionReserveContext) => c.preview ? 'Automatic reservations are unavailable in browser preview.' :
  !c.port || !c.nativeSession ? 'This native connection has no reservation service.' : null;
const unknownReason = 'The original reservation is unconfirmed. Keep it and check its status; do not retry.';
const busyReason = 'The original reservation operation is still finishing. Check its status or request Stop.';

// One finite native interaction and separate original status/STOP promises.
// No timer, automatic read/bump/retry, token, path or replacement native owner.
export class VersionReserveController {
  readonly cliAccess: AgentVersionReserveAccessController;
  private readonly currentContext: () => VersionReserveContext;
  private context: VersionReserveContext = absent();
  private originalContext: VersionReserveContext | null = null;
  private epoch: object = {};
  private reviewed: { epoch: object; id: string; options: VersionReserveOptions; cli: AgentVersionReserveReview } | null = null;
  private reserved: { epoch: object; id: string; cliCompletion?: AgentVersionReserveCompletion } | null = null;
  private work: Work | null = null;
  private query: Work | null = null;
  private stopping: Work | null = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  private state: VersionReserveView = Object.freeze({ enabled: false,
    options: Object.freeze({ reference: '', increment: 'build', newCandidate: false, acknowledgeLimitations: false }),
    status: null, stale: true, pending: null, checking: false, stopping: false, unknown: false, issue: null, editHandedOff: false });
  constructor(options: { current(): VersionReserveContext }) {
    this.currentContext = options.current;
    this.cliAccess = new AgentVersionReserveAccessController({ current: () => {
      const c = this.readContext(), s = this.state.status, r = this.reviewed;
      const review = !this.state.stale && !this.state.unknown && r?.epoch === this.epoch && r.options === this.state.options &&
        s?.phase === 'reviewed' && s.projectId === c.projectId && s.review?.id === r.id && s.revision === r.cli.revision &&
        s.review.reference === r.options.reference && s.review.increment === r.options.increment && s.review.newCandidate === r.options.newCandidate ? r.cli : null;
      return { port: c.cliAccessPort ?? null, nativeSession: c.nativeSession, projectId: c.projectId, preview: c.preview,
        epoch: this.epoch, options: this.state.options, enabled: this.state.enabled, review,
        blockedReason: this.nativeOwnerReason() ?? unavailable(c) ?? c.blockedReason };
    } });
    this.cliAccess.subscribe(() => this.patch());
    this.syncContext();
  }
  getSnapshot = (): VersionReserveView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  whenSettled = (): Promise<void> => Promise.all([this.work?.completion, this.query?.completion, this.stopping?.completion, this.cliAccess.whenSettled()]).then(() => undefined);
  ownerReason = (): string | null => this.nativeOwnerReason() ?? this.cliAccess.ownerReason();
  private nativeOwnerReason = (): string | null => this.state.unknown || this.state.status?.phase === 'cleanup-unknown' ? unknownReason :
    this.work || this.query || this.stopping || reserveActive(this.state.status) ? busyReason : null;
  private readContext(): VersionReserveContext {
    try {
      const c = this.currentContext(), p = c.port;
      if (typeof c.preview !== 'boolean' || c.nativeSession !== null && typeof c.nativeSession !== 'object' ||
          c.blockedReason !== null && typeof c.blockedReason !== 'string') return absent();
      return { port: p && ['status', 'review', 'reserve', 'cancel'].every((k) => typeof p[k as keyof VersionReservePort] === 'function') ? p : null,
        cliAccessPort: c.cliAccessPort ?? null, nativeSession: c.nativeSession, projectId: reserveProject(c.projectId) ? c.projectId : null, preview: c.preview,
        blockedReason: c.blockedReason, editor: c.editor && typeof c.editor.openReserved === 'function' && typeof c.editor.reservedOpenReason === 'function' ? c.editor : null };
    } catch { return absent(); }
  }
  private sameHost(a: VersionReserveContext, b: VersionReserveContext): boolean {
    return a.port === b.port && a.nativeSession === b.nativeSession && a.preview === b.preview && a.editor === b.editor && a.cliAccessPort === b.cliAccessPort;
  }
  private sameContext(a: VersionReserveContext, b: VersionReserveContext): boolean { return this.sameHost(a, b) && a.projectId === b.projectId; }
  private current(work: Work): boolean { return !this.disposed && work.epoch === this.epoch && this.sameContext(work.context, this.readContext()); }
  private patch(patch: Partial<VersionReserveView> = {}): void {
    this.state = Object.freeze({ ...this.state, ...patch, pending: this.work?.kind === 'reserve' ? 'reserve' : this.work ? 'review' : null,
      checking: this.query !== null, stopping: this.stopping !== null });
    this.cliAccess?.syncContext();
    if (!this.disposed) for (const callback of [...this.listeners]) { try { callback(); } catch { /* Delivery cannot free an original. */ } }
  }
  beforeContextIntent = (): void => { this.epoch = {}; this.reviewed = null; this.reserved = null; this.patch({ stale: true }); };
  syncContext(): void {
    if (this.disposed) return;
    const c = this.readContext(), changed = !this.sameContext(c, this.context), display = c.blockedReason !== this.context.blockedReason;
    this.context = c;
    if (changed) { this.epoch = {}; this.reviewed = null; this.reserved = null; }
    if (changed || display) this.patch(changed ? { stale: true } : {});
  }
  setEnabled(enabled: boolean): boolean {
    if (this.disposed || this.ownerReason() || typeof enabled !== 'boolean' || enabled === this.state.enabled) return false;
    this.beforeContextIntent(); this.patch({ enabled, issue: null }); return true;
  }
  configure(options: VersionReserveOptions): boolean {
    if (this.disposed || this.ownerReason()) return false;
    // Form DATA can be incomplete, but is bounded. Real input is checked again
    // at Review; no invalid field is defaulted into a native policy.
    if (typeof options.reference !== 'string' || options.reference.length > 211 ||
        !['build', 'patch', 'minor', 'major'].includes(options.increment) || typeof options.newCandidate !== 'boolean' ||
        typeof options.acknowledgeLimitations !== 'boolean') return false;
    const next = Object.freeze({ reference: options.reference, increment: options.increment, newCandidate: options.newCandidate,
      acknowledgeLimitations: options.acknowledgeLimitations });
    if (JSON.stringify(next) === JSON.stringify(this.state.options)) return false;
    this.beforeContextIntent(); this.patch({ options: next, issue: null }); return true;
  }
  reviewReason(): string | null {
    const c = this.readContext();
    return this.disposed ? 'This controller is retired.' : this.ownerReason() ?? unavailable(c) ??
      (!this.state.enabled ? 'Manual versions are selected.' : !c.projectId ? 'Choose a saved native Android or iOS project.' : c.blockedReason) ??
      (!parseReserveOptions(this.state.options) ? 'Enter the exact checked-out branch (for example refs/heads/main) and acknowledge the Store limits.' : null);
  }
  reserveReason(): string | null {
    const s = this.state.status;
    return this.reviewReason() ?? (this.state.stale || s?.phase !== 'reviewed' || s.projectId !== this.readContext().projectId ||
      this.reviewed?.epoch !== this.epoch || this.reviewed.id !== s.review?.id || this.reviewed.options !== this.state.options ?
      'Review these exact choices first. A status read cannot replace that review.' : null);
  }
  editReason(): string | null {
    const c = this.readContext(), s = this.state.status;
    return this.disposed ? 'This controller is retired.' : this.ownerReason() ?? unavailable(c) ?? c.blockedReason ??
      (!this.state.enabled || this.state.stale || s?.phase !== 'reserved' || s.projectId !== c.projectId || !s.reservation ||
        this.reserved?.epoch !== this.epoch || this.reserved.id !== s.reservation.id ||
        this.reserved.cliCompletion && this.reserved.cliCompletion !== this.cliAccess.checkedCompletion() || this.state.editHandedOff ?
        'No current unconsumed reservation is ready for this editor.' : !c.editor ? 'The original version editor is unavailable.' : c.editor.reservedOpenReason());
  }
  edit(): boolean {
    this.syncContext(); if (this.editReason()) return false;
    const c = this.readContext(), epoch = this.epoch, reservation = this.state.status!.reservation!;
    this.patch({ editHandedOff: true }); // consume local intent BEFORE callbacks
    if (this.disposed || this.epoch !== epoch || !this.sameContext(c, this.readContext()) || this.readContext().blockedReason || this.ownerReason() || !c.editor ||
        this.reserved?.cliCompletion && this.reserved.cliCompletion !== this.cliAccess.checkedCompletion()) return false;
    try { return c.editor.openReserved(reservation); } // SAME original editor owns Open/review/Apply/finality.
    catch { this.patch({ issue: 'The original version editor handoff is unconfirmed. Check its own status; the candidate is retained.' }); return false; }
  }
  private controls(): VersionReserveContext { return this.ownerReason() && this.originalContext ? this.originalContext : this.readContext(); }
  checkReason(): string | null { return this.disposed ? 'This controller is retired.' : this.query ? 'Checking original status…' : unavailable(this.controls()); }
  stopReason(): string | null {
    return this.disposed ? 'This controller is retired.' : this.stopping ? 'Stop is already requested.' : unavailable(this.controls()) ??
      (!this.state.status?.operationId || this.work && this.work.operationId !== this.state.status.operationId ? 'Check status to identify the original operation first.' :
        !reserveActive(this.state.status) && !this.work ? 'No pending reservation operation was reported.' : null);
  }
  private begin(kind: Kind, context: VersionReserveContext): Work {
    const reset = this.originalContext !== null && !this.sameHost(context, this.originalContext);
    this.originalContext = context;
    let finish!: () => void;
    const completion = new Promise<void>((resolve) => { finish = resolve; });
    const work: Work = { kind, context, epoch: this.epoch, options: this.state.options, operationId: kind === 'cancel' ? this.state.status?.operationId ?? null : null,
      sent: false, original: null, completion, finish, cliCompletion: kind === 'status' ? this.cliAccess.checkedCompletion() : null };
    if (kind === 'status') this.query = work;
    else if (kind === 'cancel') this.stopping = work;
    else { this.work = work; this.reviewed = null; this.reserved = null; }
    this.patch({ issue: null, ...(reset ? { status: null, stale: true } : {}),
      ...(kind === 'review' || kind === 'reserve' ? { stale: true, editHandedOff: false } : {}) });
    return work;
  }
  private end(work: Work): void {
    if (this.work === work) this.work = null;
    if (this.query === work) this.query = null;
    if (this.stopping === work) this.stopping = null;
    this.patch(); work.finish();
  }
  private unknown(): void { this.reviewed = null; this.reserved = null; this.patch({ unknown: true, stale: true, issue: unknownReason }); }
  private accept(work: Work, raw: unknown): void {
    const s = parseVersionReserveStatus(raw);
    if (!s || !this.originalContext || !this.sameHost(work.context, this.originalContext)) { this.unknown(); return; }
    if (work.kind === 'review' || work.kind === 'reserve') {
      if (s.projectId !== work.context.projectId || s.operationId === null || work.operationId !== null && work.operationId !== s.operationId ||
          ![work.kind === 'review' ? 'reviewed' : 'reserved', 'refused', 'cleanup-unknown'].includes(s.phase)) { this.unknown(); return; }
    } else if (work.kind === 'cancel' && s.operationId !== work.operationId) { this.unknown(); return; }
    const before = this.state.status;
    if (before && s.revision < before.revision) return;
    if (before && s.revision === before.revision && JSON.stringify(before) !== JSON.stringify(s)) { this.unknown(); return; }
    if (work.kind === 'status' && this.work?.sent && s.projectId === this.work.context.projectId && reserveActive(s)) {
      if (this.work.operationId !== null && this.work.operationId !== s.operationId) { this.unknown(); return; }
      this.work.operationId = s.operationId;
    }
    if (s.phase === 'cleanup-unknown') { this.patch({ status: s }); this.unknown(); return; }
    // Descriptor parsing can invoke Proxy traps: rematch original epoch/API
    // afterwards. Stale replies remain original DATA, never a new intent.
    const current = this.current(work) && (s.projectId === null || s.projectId === work.context.projectId) && !this.state.unknown;
    if (work.kind === 'review' && s.phase === 'reviewed' && current) this.reviewed = { epoch: work.epoch, id: s.review!.id, options: work.options,
      cli: Object.freeze({ id: s.review!.id, revision: s.revision, options: work.options }) };
    else if (s.phase !== 'reviewed') this.reviewed = null;
    if (work.kind === 'reserve' && s.phase === 'reserved' && current) this.reserved = { epoch: work.epoch, id: s.reservation!.id };
    else if (work.kind === 'status' && s.phase === 'reserved' && current && this.readContext().blockedReason === null &&
        work.cliCompletion && work.cliCompletion === this.cliAccess.checkedCompletion() && work.cliCompletion.options === work.options &&
        work.cliCompletion.projectId === s.projectId && work.cliCompletion.operationId === s.operationId && s.reservation!.id === s.operationId) {
      // Only after explicit permission Check and a subsequent original status
      // reply. This correlation is NOT native edit authority: the same existing
      // edit_reserved_version path rechecks and consumes the retained Lane.
      this.reserved = { epoch: work.epoch, id: s.reservation!.id, cliCompletion: work.cliCompletion };
    } else if (s.phase !== 'reserved') this.reserved = null;
    this.patch({ status: s, stale: !current, issue: null });
  }
  private fail(work: Work, error: unknown): void {
    let known = false;
    try { const d = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
      known = !!d && Object.hasOwn(d, 'value') && d.value === 'version_reserve_not_started'; } catch { /* Unknown, not retryable. */ }
    if (known && (work.kind === 'review' || work.kind === 'reserve')) this.patch({ stale: true, issue: 'Native admission refused. No new reservation operation started; check the prerequisites before another review.' });
    else this.unknown();
  }
  private async action(kind: 'review' | 'reserve'): Promise<boolean> {
    this.syncContext(); if ((kind === 'review' ? this.reviewReason() : this.reserveReason()) !== null) return false;
    const review = kind === 'reserve' ? this.state.status!.review!.id : null;
    const work = this.begin(kind, this.readContext());
    try {
      if (!this.current(work) || this.stopping || this.cliAccess.ownerReason() || this.readContext().blockedReason !== null || !work.context.projectId || work.options !== this.state.options || !this.state.enabled) return false;
      work.sent = true;
      work.original = kind === 'review' ? work.context.port!.review(work.context.projectId, work.options) : work.context.port!.reserve(work.context.projectId, review!);
      this.accept(work, await work.original);
    } catch (e) { this.fail(work, e); } finally { this.end(work); }
    return work.sent;
  }
  review = (): Promise<boolean> => this.action('review');
  reserve = (): Promise<boolean> => this.action('reserve');
  private async control(kind: 'status' | 'cancel'): Promise<boolean> {
    this.syncContext(); if ((kind === 'status' ? this.checkReason() : this.stopReason()) !== null) return false;
    const c = this.controls();
    if (kind === 'cancel') this.beforeContextIntent();
    const work = this.begin(kind, c);
    try {
      if (this.disposed || unavailable(c) || kind === 'cancel' && !work.operationId) return false;
      work.sent = true; work.original = kind === 'status' ? c.port!.status() : c.port!.cancel(work.operationId!);
      this.accept(work, await work.original);
    } catch (e) { this.fail(work, e); } finally { this.end(work); }
    return work.sent;
  }
  check = (): Promise<boolean> => this.control('status');
  checkCliAccess = async (): Promise<boolean> => {
    const sent = await this.cliAccess.check();
    // This is the explicit Check button, not a mount/background effect. A lost,
    // stale or unjoined request does not start another Reserve or open an edit.
    const access = this.cliAccess.getSnapshot();
    return sent && !access.stale && !access.unknown && access.access?.consumed ? this.check() : sent;
  };
  stop = (): Promise<boolean> => this.control('cancel');
  dispose(): void { this.disposed = true; this.beforeContextIntent(); this.cliAccess.dispose(); this.listeners.clear(); }
}
