import { parseAgentVersionReserveAccess, reserveReviewRevision } from './agentVersionReserveAccess.ts';
import type { AgentVersionReserveAccess, AgentVersionReserveAccessPort } from './agentVersionReserveAccess.ts';
import { parseReserveOptions, reserveId, reserveProject } from './versionReserve.ts';
import type { VersionReserveOptions } from './versionReserve.ts';

export interface AgentVersionReserveReview {
  readonly id: string; readonly revision: number; readonly options: VersionReserveOptions;
}
export interface AgentVersionReserveContext {
  port: AgentVersionReserveAccessPort | null; nativeSession: object | null; projectId: string | null; preview: boolean;
  epoch: object; options: VersionReserveOptions; enabled: boolean;
  // Supplied only by the existing controller's genuinely completed GUI Review.
  review: AgentVersionReserveReview | null;
  blockedReason: string | null; // Other owners, including the original Reserve caller; excludes this child.
}
export interface AgentVersionReserveCompletion {
  readonly operationId: string; readonly projectId: string; readonly review: AgentVersionReserveReview;
  readonly options: VersionReserveOptions;
}
export interface AgentVersionReserveAccessView {
  readonly access: AgentVersionReserveAccess | null; readonly review: AgentVersionReserveReview | null;
  readonly acknowledged: boolean; readonly stale: boolean; readonly unknown: boolean; readonly issue: string | null;
  readonly pending: 'status' | 'allow' | null; readonly revoking: boolean;
}
interface Work {
  kind: 'status' | 'allow' | 'revoke'; context: AgentVersionReserveContext; generation: object;
  sent: boolean; original: Promise<unknown> | null; startedAt: number | null;
  completion: Promise<void>; finish(): void;
}
interface Binding { context: AgentVersionReserveContext; review: AgentVersionReserveReview; access: AgentVersionReserveAccess }
const missingOptions = Object.freeze({ reference: '', increment: 'build' as const, newCandidate: false, acknowledgeLimitations: false });
const missingEpoch = {};
const absent = (): AgentVersionReserveContext => ({ port: null, nativeSession: null, projectId: null, preview: false,
  epoch: missingEpoch, options: missingOptions, enabled: false, review: null, blockedReason: 'Open the native app first.' });
const nativeReason = (c: AgentVersionReserveContext) => c.preview ? 'CLI reservations are unavailable in browser preview.' :
  !c.port || !c.nativeSession ? 'This native connection has no CLI reservation permission service.' : null;
const uncertain = 'CLI permission is unconfirmed. Keep the original request, check its status or turn off permission and request Stop. Do not repeat the reservation.';
const sameGrant = (a: AgentVersionReserveAccess, b: AgentVersionReserveAccess) => a.grantId === b.grantId && a.serviceInstance === b.serviceInstance &&
  a.projectId === b.projectId && a.reviewId === b.reviewId && a.reviewRevision === b.reviewRevision;

// A permission child of VersionReserveController, NOT a second Reserve owner.
// It sends only Access/Allow/Revoke. The native Entry, Lane and continuation
// retain execution/finality; no Access field settles a JavaScript caller.
export class AgentVersionReserveAccessController {
  private readonly source: { current(): AgentVersionReserveContext; now?(): number };
  private context = absent();
  private originalContext: AgentVersionReserveContext | null = null;
  private generation: object = {};
  private normal: Work | null = null;
  private revocation: Work | null = null;
  private consent: { context: AgentVersionReserveContext; review: AgentVersionReserveReview } | null = null;
  private attemptedReview: AgentVersionReserveReview | null = null;
  private binding: Binding | null = null;
  private completed: AgentVersionReserveCompletion | null = null;
  private observedAt: number | null = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  private state: AgentVersionReserveAccessView = Object.freeze({ access: null, review: null, acknowledged: false, stale: true,
    unknown: false, issue: null, pending: null, revoking: false });
  constructor(source: { current(): AgentVersionReserveContext; now?(): number }) { this.source = source; this.syncContext(); }
  getSnapshot = (): AgentVersionReserveAccessView => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  whenSettled = (): Promise<void> => Promise.all([this.normal?.completion, this.revocation?.completion]).then(() => undefined);
  ownerReason = (): string | null => this.state.unknown ? uncertain : this.normal || this.revocation ?
    'The original CLI permission request is still finishing. Turn off permission to request Stop.' : this.state.access?.enabled ?
      'CLI permission was allowed at the last check. Check it or turn it off before starting a different task.' : null;

  private readContext(): AgentVersionReserveContext {
    try {
      const c = this.source.current(), p = c.port, r = c.review;
      if (typeof c.preview !== 'boolean' || typeof c.enabled !== 'boolean' || !c.epoch || typeof c.epoch !== 'object' ||
          !c.options || typeof c.options !== 'object' || c.nativeSession !== null && typeof c.nativeSession !== 'object' ||
          c.blockedReason !== null && typeof c.blockedReason !== 'string') return absent();
      return { ...c, projectId: reserveProject(c.projectId) ? c.projectId : null,
        port: p && ['status', 'allow', 'revoke'].every((k) => typeof p[k as keyof AgentVersionReserveAccessPort] === 'function') ? p : null,
        review: r && reserveId(r.id) && reserveReviewRevision(r.revision) && r.options === c.options && parseReserveOptions(r.options) ? r : null };
    } catch { return absent(); }
  }
  private sameHost(a: AgentVersionReserveContext, b: AgentVersionReserveContext): boolean {
    return a.port === b.port && a.nativeSession === b.nativeSession && a.preview === b.preview;
  }
  private sameContext(a: AgentVersionReserveContext, b: AgentVersionReserveContext): boolean {
    return this.sameHost(a, b) && a.projectId === b.projectId && a.epoch === b.epoch && a.options === b.options && a.enabled === b.enabled;
  }
  private isCurrent(c: AgentVersionReserveContext): boolean { return !this.disposed && this.sameContext(c, this.readContext()) && nativeReason(c) === null; }
  private patch(change: Partial<AgentVersionReserveAccessView> = {}): void {
    this.state = Object.freeze({ ...this.state, ...change, pending: this.normal?.kind === 'allow' ? 'allow' : this.normal ? 'status' : null,
      revoking: this.revocation !== null });
    if (!this.disposed) for (const fn of [...this.listeners]) { try { fn(); } catch { /* An observer cannot free the original request. */ } }
  }
  syncContext(): void {
    if (this.disposed) return;
    const c = this.readContext(), changed = !this.sameContext(c, this.context), reviewChanged = c.review !== this.context.review;
    const displayChanged = reviewChanged || c.blockedReason !== this.context.blockedReason;
    this.context = c;
    const newReview = !!c.review && this.binding !== null && c.review !== this.binding.review;
    if (changed || newReview) { this.binding = null; this.completed = null; }
    if (changed || reviewChanged) this.consent = null;
    if (changed || displayChanged) this.patch({ review: c.review, acknowledged: this.consent !== null, ...(changed || newReview ? { stale: true } : {}),
      ...(reviewChanged && c.review && c.review !== this.attemptedReview && !this.state.unknown ? { issue: null } : {}) });
  }
  private controls(): AgentVersionReserveContext { return this.ownerReason() && this.originalContext ? this.originalContext : this.readContext(); }
  statusReason(): string | null { return this.disposed ? 'This permission controller is retired.' : nativeReason(this.controls()) ??
    (this.normal || this.revocation ? 'Wait for the original permission reply. Turning off permission stays available.' : null); }
  consentReason(): string | null {
    const c = this.readContext();
    return this.disposed ? 'This permission controller is retired.' : this.ownerReason() ?? nativeReason(c) ?? c.blockedReason ??
      (!c.enabled || !c.projectId || !c.review ? 'Review the exact version choices in this app first.' :
        c.review === this.attemptedReview ? 'Review again before allowing another one-use request. Permission is never renewed automatically.' : null);
  }
  allowReason(): string | null {
    const c = this.readContext(), consent = this.consent;
    return this.consentReason() ?? (!consent || consent.review !== c.review || !this.sameContext(consent.context, c) ?
      'Confirm permission for this one reviewed reservation.' : null);
  }
  setAcknowledged(value: boolean): boolean {
    this.syncContext();
    if (typeof value !== 'boolean' || this.disposed || this.normal || this.revocation || value && this.consentReason()) return false;
    const c = this.readContext(); this.consent = value && c.review ? { context: c, review: c.review } : null;
    this.patch({ acknowledged: this.consent !== null }); return true;
  }
  revokeReason(): string | null { return this.disposed ? 'This permission controller is retired.' : nativeReason(this.controls()) ??
    (this.revocation ? 'Turning off permission and requesting Stop…' : null); }
  private now(): number | null {
    try { const n = this.source.now ? this.source.now() : performance.now(); return Number.isFinite(n) && n >= 0 ? n : null; } catch { return null; }
  }
  remainingSeconds(): number | null {
    const now = this.now(), start = this.observedAt, access = this.state.access;
    return this.state.stale || !access?.enabled || start === null || now === null || now < start ? null : Math.max(0, Math.ceil((access.remainingMs - (now - start)) / 1000));
  }
  checkedCompletion(): AgentVersionReserveCompletion | null {
    // Comparison only. The existing parent still checks its peer gate before
    // accepting a later status reply or entering the original version editor.
    return !this.normal && !this.revocation && !this.state.unknown && !this.state.stale && this.completed && this.binding &&
      this.isCurrent(this.binding.context) ? this.completed : null;
  }
  private begin(kind: Work['kind'], context: AgentVersionReserveContext): Work {
    if (kind === 'revoke') this.generation = {}; // Fence old Allow/status before callbacks or native handoff.
    this.completed = null;
    if (kind !== 'status') this.consent = null;
    let finish!: () => void; const completion = new Promise<void>((resolve) => { finish = resolve; });
    const w: Work = { kind, context, generation: this.generation, sent: false, original: null, startedAt: this.now(), completion, finish };
    this.originalContext = context;
    if (kind === 'revoke') this.revocation = w; else this.normal = w;
    this.patch({ stale: true, acknowledged: this.consent !== null }); return w;
  }
  private end(w: Work): void {
    if (this.normal === w) this.normal = null;
    if (this.revocation === w) this.revocation = null;
    this.patch(); w.finish();
  }
  private delivery(w: Work): boolean { return !this.disposed && w.generation === this.generation && this.originalContext !== null && this.sameHost(w.context, this.originalContext); }
  private unknown(): void { this.completed = null; this.consent = null; this.patch({ unknown: true, stale: true, acknowledged: false, issue: uncertain }); }
  private failed(w: Work, error: unknown): void {
    if (!this.delivery(w)) return;
    let refused = false;
    try {
      const d = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
      // For this exact Allow route these fixed codes precede native lease
      // insertion. They do not revoke or prove the absence of an older grant.
      refused = w.kind === 'allow' && !!d && Object.hasOwn(d, 'value') &&
        ['version_reserve_refused', 'cli_access_busy', 'cli_access_changed'].includes(d.value);
    } catch { /* Lost or unusable errors are not proof of no admission. */ }
    if (!this.delivery(w)) return;
    if (refused) this.patch({ stale: true, issue: 'No new CLI permission was granted by this attempt. The review changed, expired or another task is busy. Check any earlier permission, then review again explicitly.' });
    else this.unknown();
  }
  private accept(w: Work, raw: unknown): void {
    if (!this.delivery(w)) return;
    const s = parseAgentVersionReserveAccess(raw);
    if (!this.delivery(w)) return; // Descriptor/Proxy inspection may reenter the same controller.
    const review = w.context.review;
    if (!s || w.kind === 'revoke' && s.enabled || w.kind === 'allow' && (!s.grantId || !review || s.reviewId !== review.id || s.reviewRevision !== review.revision)) {
      this.unknown(); return;
    }
    const old = this.state.access;
    if (old?.grantId && old.grantId === s.grantId && (!sameGrant(old, s) || old.consumed && (!s.consumed || old.requestId !== s.requestId) ||
        old.completedOperationId !== null && s.completedOperationId !== null && old.completedOperationId !== s.completedOperationId)) { this.unknown(); return; }
    const current = this.isCurrent(w.context);
    if (w.kind === 'allow' && current && !this.state.unknown && w.context.review) this.binding = { context: w.context, review: w.context.review, access: s };
    if (this.binding && !sameGrant(this.binding.access, s)) this.binding = null;
    this.completed = w.kind === 'status' && !this.state.unknown && current && s.completedOperationId && this.binding &&
      sameGrant(this.binding.access, s) && this.isCurrent(this.binding.context) && w.context.projectId ?
      Object.freeze({ operationId: s.completedOperationId, projectId: w.context.projectId, review: this.binding.review, options: this.binding.context.options }) : null;
    this.observedAt = w.startedAt;
    this.patch({ access: s, stale: !current || this.state.unknown, ...(this.state.unknown ? {} : { issue: null }) });
  }
  private async ordinary(kind: 'status' | 'allow'): Promise<boolean> {
    this.syncContext(); if ((kind === 'allow' ? this.allowReason() : this.statusReason()) !== null) return false;
    const context = kind === 'allow' ? this.readContext() : this.controls(), consent = this.consent;
    const w = this.begin(kind, context);
    try {
      const c = this.readContext();
      if (!this.delivery(w) || this.revocation || kind === 'allow' && (!this.isCurrent(context) || c.blockedReason || !context.projectId ||
          !context.review || c.review !== context.review || !consent || consent.review !== context.review || !this.sameContext(consent.context, c))) return false;
      w.sent = true;
      if (kind === 'allow') this.attemptedReview = context.review;
      w.original = kind === 'status' ? context.port!.status() : context.port!.allow(context.projectId!, context.review!.id, context.review!.revision);
      if (!w.original || typeof w.original.then !== 'function') { this.unknown(); return true; }
      this.accept(w, await w.original);
    } catch (error) { this.failed(w, error); }
    finally { this.end(w); }
    return w.sent; // Actual invocation attempted, never permission or Reserve success.
  }
  check = (): Promise<boolean> => this.ordinary('status');
  allow = (): Promise<boolean> => this.ordinary('allow');
  async revoke(): Promise<boolean> {
    this.syncContext(); if (this.revokeReason() !== null) return false;
    const w = this.begin('revoke', this.controls());
    try {
      if (!this.delivery(w) || nativeReason(w.context)) return false;
      w.sent = true; w.original = w.context.port!.revoke();
      if (!w.original || typeof w.original.then !== 'function') { this.unknown(); return true; }
      this.accept(w, await w.original);
    } catch (error) { this.failed(w, error); }
    finally { this.end(w); }
    return w.sent;
  }
  dispose(): void { this.disposed = true; this.generation = {}; this.binding = null; this.completed = null; this.consent = null; this.listeners.clear(); }
}
