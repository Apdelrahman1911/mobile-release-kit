// A permission/continuation facet of MetadataImagesController. It owns no
// editor, picker, image bytes, journal, source writer or native-finality timer.
import { METADATA_IMAGES_AGENT_CONSENT, parseImagesAgentAccess, parseImagesAgentRevoked,
  sameImagesAgentOrigin, sameImagesAgentReview, sameImagesAgentSummary } from './serviceMetadataImagesProtocol.ts';
import type { ImagesAgentAccess, ImagesAgentOrigin, ImagesAgentRequest, ImagesAgentReview,
  ImagesAgentSummary, MetadataImagesAgentApi } from './serviceMetadataImagesProtocol.ts';
import type { MetadataImagesEditProjection } from './metadataImages.ts';

export interface ImagesAgentCandidate {
  projectId: string; api: MetadataImagesAgentApi; summary: ImagesAgentSummary; remainingMs: number;
  same(): boolean; ready(): boolean; native(): MetadataImagesEditProjection | null;
  apply(origin: ImagesAgentOrigin): Promise<boolean>;
}
interface Permission {
  candidate: ImagesAgentCandidate; nonce: string; end: number; expired: boolean;
  entered: boolean; returned: boolean; accepted: boolean; revoked: boolean; revokeAck: boolean; gui: boolean;
  review: ImagesAgentReview | null; access: ImagesAgentAccess | null;
}
interface Run { permission: Permission; origin: ImagesAgentOrigin; entered: boolean; returned: boolean }
export interface ImagesAgentState { access: ImagesAgentAccess | null; pending: boolean; retained: boolean; unknown: boolean; issue: string | null }
const equal = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);
const knownNative = (p: MetadataImagesEditProjection | null): p is MetadataImagesEditProjection =>
  !!p && p.phase === 'final' && p.nativeFinality === 'settled' && !p.lateSettled;
function advances(a: ImagesAgentRequest, b: ImagesAgentRequest): boolean {
  if (!sameImagesAgentOrigin(a.origin,b.origin) || a.grantId !== b.grantId || !sameImagesAgentReview(a.review,b.review) ||
    b.revision < a.revision || a.cancelRequested && !b.cancelRequested) return false;
  if (a.revision === b.revision || a.phase === 'final' || a.phase === 'unknown') return equal(a,b);
  if (b.phase === 'final' || b.phase === 'unknown' || b.phase === 'stopping') return true;
  return ['queued','admitting','applying'].indexOf(b.phase) >= ['queued','admitting','applying'].indexOf(a.phase) && a.phase !== 'stopping';
}
export class ServiceMetadataImagesController {
  private state: ImagesAgentState = Object.freeze({access:null,pending:false,retained:false,unknown:false,issue:null});
  private listeners = new Set<() => void>();
  private api: MetadataImagesAgentApi | null = null;
  private off: (() => void) | null = null;
  private subscribing: Promise<void> | null = null;
  private permission: Permission | null = null;
  private run: Run | null = null;
  private allowWork: Promise<void> | null = null;
  private revokeWork: Promise<void> | null = null;
  private statusWork: Promise<void> | null = null;
  private applyWork: Promise<void> | null = null;
  private disposed = false;
  private readonly candidate: () => ImagesAgentCandidate | null;
  private readonly now: () => number;
  constructor(candidate: () => ImagesAgentCandidate | null, now: () => number = () => performance.now()) { this.candidate = candidate; this.now = now; }
  getSnapshot = (): ImagesAgentState => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  hasPendingCalls(): boolean { return !!(this.allowWork || this.revokeWork || this.statusWork || this.applyWork || this.subscribing); }
  private resolved(): boolean {
    const p = this.permission;
    if (!p) return !this.state.unknown;
    if (this.state.unknown || !p.returned || this.hasPendingCalls()) return false;
    const native = p.candidate.native();
    if (this.run) {
      const q = p.access?.request;
      return this.run.returned && !!q && sameImagesAgentOrigin(q.origin,this.run.origin) && q.phase === 'final' && knownNative(native) &&
        native.applySubmitted === q.result!.applySubmitted && (native.coreOutcome ?
          native.coreOutcome.resources === 'settled' && native.coreOutcome.effect === q.result!.effect && native.coreOutcome.journal === q.result!.journal :
          !q.result!.applySubmitted && q.result!.effect === 'not_started' && q.result!.journal === 'not_created') &&
        (!q.result!.completed || native.nativeReason === 'none' && native.coreOutcome?.reason === 'none');
    }
    if (!p.entered) return p.revokeAck || !p.revoked;
    return knownNative(native) && (p.gui || p.revokeAck) && !p.access?.request;
  }
  retains(): boolean { return this.hasPendingCalls() || !!this.permission && !this.resolved() || this.state.unknown; }
  private publish(issue = this.state.issue): void {
    this.state = Object.freeze({...this.state,access:this.permission?.access ?? this.state.access,
      pending:this.hasPendingCalls(),retained:this.retains(),issue});
    for (const fn of this.listeners) fn();
    if (this.disposed && !this.hasPendingCalls()) { try { this.off?.(); } catch { /* Not a native receipt. */ } this.off = null; this.listeners.clear(); }
  }
  private uncertain(message: string, sticky = false): void {
    if (sticky) this.state = {...this.state,unknown:true};
    this.publish(message); this.revoke();
  }
  available(): boolean { return !!this.api && !!this.off && !this.disposed; }
  hasAllowance(): boolean { return !!this.permission && !this.permission.revoked && !this.resolved(); }
  approvalKey(): string | null { const c = this.candidate(); return c ? JSON.stringify([c.projectId,c.summary]) : null; }
  canAllow(): boolean { const c = this.candidate(); return !this.disposed && !this.permission && !this.state.unknown && !this.hasPendingCalls() &&
    !!this.off && !!c && c.api === this.api && c.ready() && c.remainingMs > 0; }
  guiAllowed(): boolean { return !this.state.unknown && !this.run && !this.allowWork && !this.revokeWork && !this.applyWork; }
  guiClaim(): boolean {
    if (!this.guiAllowed()) return false;
    const p = this.permission; if (p) { p.gui = true; this.publish(); }
    // This is intent only. Native atomically competes with CLI Submit on the
    // exact same unused row. Neither this bit nor a GUI error proves who won.
    return true;
  }
  async connect(api: MetadataImagesAgentApi | undefined): Promise<void> {
    if (this.disposed || this.api === (api ?? null)) return this.subscribing ?? Promise.resolve();
    if (this.retains()) { this.revoke(); return; }
    try { this.off?.(); } catch { /* No native settlement. */ } this.off = null; this.api = api ?? null;
    if (!api) return;
    const work = Promise.resolve().then(async () => {
      try { const off = await api.subscribe(v => { if (this.api === api) this.observe(v); });
        if (this.disposed || this.api !== api) off(); else this.off = off;
      } catch { this.publish('CLI permission observation is unavailable. Use the original image controls.'); }
    });
    this.subscribing = work; this.publish();
    try { await work; } finally { if (this.subscribing === work) this.subscribing = null; this.publish(); }
  }
  allow(): Promise<void> {
    const c = this.candidate(); if (!c || !this.canAllow() || c.api !== this.api) return Promise.resolve();
    const p: Permission = {candidate:c,nonce:crypto.randomUUID().replaceAll('-',''),end:this.now()+c.remainingMs,expired:false,
      entered:false,returned:false,accepted:false,revoked:false,revokeAck:false,gui:false,review:null,access:null};
    this.permission = p;
    const work = Promise.resolve().then(async () => {
      if (this.permission !== p || p.revoked || this.disposed || this.api !== c.api || !c.ready()) return;
      const startedAt = this.now();
      p.entered = true; // Immediately before the sole Allow call, with no event/await in between.
      try {
        const a = parseImagesAgentAccess(await c.api.allow({projectId:c.projectId,original:c.summary.original,
          statusRevision:c.summary.nativeStatusRevision,nonce:p.nonce,consent:METADATA_IMAGES_AGENT_CONSENT}));
        if (!a || !this.matches(p,a)) throw new Error('comparison');
        p.accepted = true; this.observeAt(a,startedAt);
      } catch { this.uncertain('Permission was not confirmed. Revoke this allowance and check the same review; do not allow again.'); }
    });
    this.allowWork = work; this.publish(null);
    return work.finally(() => { p.returned = true; if (this.allowWork === work) this.allowWork = null; this.publish(); this.maybeDispatch(); });
  }
  revoke(): Promise<void> {
    const p = this.permission;
    if (!p || p.revoked || this.resolved()) return this.revokeWork ?? Promise.resolve();
    p.revoked = true;
    const work = Promise.resolve().then(async () => {
      try {
        const startedAt = this.now();
        const r = parseImagesAgentRevoked(await p.candidate.api.revoke(p.nonce));
        if (!r || r.nonce !== p.nonce) throw new Error('comparison');
        if (r.access.nonce === p.nonce) {
          if (!this.matches(p,r.access)) throw new Error('foreign revocation');
          p.revokeAck = true; this.observeAt(r.access,startedAt);
        } else if (r.access.nonce === null && !p.access) p.revokeAck = true;
        else throw new Error('foreign revocation');
      } catch { this.publish('Revocation is unconfirmed. Keep the original request and its Observe / Stop controls.'); }
    });
    this.revokeWork = work; this.publish();
    return work.finally(() => { if (this.revokeWork === work) this.revokeWork = null; this.publish(); });
  }
  check(): Promise<void> {
    if (this.statusWork) return this.statusWork;
    const api = this.permission?.candidate.api ?? this.api; if (!api || this.disposed) return Promise.resolve();
    const p = this.permission, q = this.run?.origin;
    const work = Promise.resolve().then(async () => {
      try {
        const startedAt = this.now();
        const a = parseImagesAgentAccess(await api.status(q));
        if (!a || this.permission !== p || this.api !== api || q && (!a.request || !sameImagesAgentOrigin(a.request.origin,q)) ||
          p && !this.matches(p,a)) throw new Error('comparison');
        this.observeAt(a,startedAt);
      } catch { this.publish('The original allowance or request is unconfirmed. Do not resend the image copy.'); }
    });
    this.statusWork = work; this.publish();
    return work.finally(() => { if (this.statusWork === work) this.statusWork = null; this.publish(); this.maybeDispatch(); });
  }
  private matches(p: Permission, a: ImagesAgentAccess): boolean {
    return a.nonce === p.nonce && !!a.review && sameImagesAgentSummary(a.review,p.candidate.summary) &&
      (!p.review || sameImagesAgentReview(a.review,p.review)) && (!p.access || a.serviceInstance === p.access.serviceInstance &&
        a.projectId === p.access.projectId && a.grantId === p.access.grantId);
  }
  observe(raw: unknown): void { this.observeAt(raw,this.now()); }
  private observeAt(raw: unknown, startedAt: number): void {
    const a = parseImagesAgentAccess(raw), p = this.permission;
    if (!a) { if (p) this.uncertain('Image permission data is invalid. Keep and stop the original operation.',true); return; }
    if (!p) { this.state = {...this.state,access:a}; this.publish(); return; } // Cold DATA never dispatches.
    if (!p.entered || a.nonce !== p.nonce) return;
    if (!this.matches(p,a)) { this.uncertain('The original allowance no longer matches this image preview.',true); return; }
    p.review ??= a.review;
    // A returned countdown is clipped to the SAME invocation's start, never
    // delayed receipt time. Events retain only the already observed minimum.
    if (!a.request) p.end = Math.min(p.end,startedAt+a.remainingMs);
    if (!a.live && !a.request) p.expired = true;
    const previous = p.access;
    if (previous?.request && !a.request) { this.publish(); return; } // Older Allow reply, never a regrant.
    if (previous?.request && a.request) {
      const [first,next] = previous.request.revision <= a.request.revision ? [previous.request,a.request] : [a.request,previous.request];
      if (!advances(first,next)) { this.uncertain('Request progress is inconsistent. Keep the original image operation.',true); return; }
      if (previous.request.revision > a.request.revision) { this.publish(); return; }
    }
    const remainingMs = Math.floor(Math.max(0,Math.min(a.remainingMs,p.end-this.now())));
    p.access = Object.freeze({...a,live:a.live && !p.expired && remainingMs > 0,remainingMs:a.live && !p.expired ? Math.floor(remainingMs) : 0});
    if (a.request) {
      if (this.run && !sameImagesAgentOrigin(this.run.origin,a.request.origin)) { this.uncertain('A different request cannot replace this original.',true); return; }
      this.run ??= {permission:p,origin:a.request.origin,entered:false,returned:false};
      if (a.request.phase === 'unknown') this.state = {...this.state,unknown:true};
    }
    this.publish(); this.maybeDispatch();
  }
  private maybeDispatch(): void {
    const p = this.permission, run = this.run, q = p?.access?.request;
    if (!p || !run || !q || run.entered || run.returned || this.applyWork || this.allowWork || this.statusWork || !p.returned) return;
    if (!p.accepted || p.revoked || p.gui || p.expired || this.disposed || this.state.unknown || this.now() >= p.end ||
      q.phase !== 'queued' || q.cancelRequested || !p.candidate.ready() || this.api !== p.candidate.api) {
      run.returned = true; void this.revoke(); this.publish(); return;
    }
    const work = Promise.resolve().then(async () => {
      const latest = p.access?.request;
      if (this.permission !== p || this.run !== run || run.permission !== p || this.applyWork !== work ||
        run.entered || run.returned || !p.accepted || !p.returned || this.allowWork || this.statusWork ||
        p.revoked || p.gui || p.expired || this.disposed || this.state.unknown || this.now() >= p.end ||
        !latest || !sameImagesAgentOrigin(latest.origin,run.origin) || latest.phase !== 'queued' || latest.cancelRequested ||
        this.api !== p.candidate.api || !p.candidate.ready()) {
        void this.revoke(); return;
      }
      run.entered = true;
      try { if (!await p.candidate.apply(run.origin)) this.uncertain('The Apply response is unconfirmed. Observe or stop this request only.'); }
      catch { this.uncertain('The Apply response is unconfirmed. Observe or stop this request only.'); }
    });
    this.applyWork = work; this.publish();
    void work.finally(() => { run.returned = true; if (this.applyWork === work) this.applyWork = null; this.publish(); });
  }
  sourceChanged(): void {
    const p = this.permission;
    if (p && !p.gui && !this.resolved() && !p.candidate.same()) void this.revoke();
    this.publish();
  }
  newOriginal(): boolean {
    if (this.retains()) return false;
    this.permission = null; this.run = null; this.state = {...this.state,access:null,unknown:false}; this.publish(null); return true;
  }
  dispose(): void { if (this.disposed) return; void this.revoke(); this.disposed = true; this.publish(); }
}
