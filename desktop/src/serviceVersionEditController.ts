// Retains the real Apply promise as well as the original editor's finality.
// This is a small UI permission/dispatch facet, never a second edit controller.
import { parseVersionEditAccess, sameVersionEditReview, VERSION_EDIT_CONSENT } from './serviceVersionEditProtocol.ts';
import type { VersionEditAccess, VersionEditAgentApi, VersionEditOrigin, VersionEditReview } from './serviceVersionEditProtocol.ts';
export interface VersionEditCandidate {
  projectId: string; api: VersionEditAgentApi; review: VersionEditReview;
  current(): boolean; live(): boolean; apply(origin: VersionEditOrigin): Promise<void>;
}
interface Permission { candidate: VersionEditCandidate; nonce: string; end: number; revoked: boolean }
interface Run { permission: Permission; origin: VersionEditOrigin; returned: boolean; final: boolean }
export class ServiceVersionEditController {
  private state: {access: VersionEditAccess | null; busy: boolean; issue: string | null} = {access:null,busy:false,issue:null};
  private listeners = new Set<() => void>();
  private api: VersionEditAgentApi | null = null;
  private permission: Permission | null = null;
  private run: Run | null = null;
  private allowWork: Promise<void> | null = null;
  private preparationWork: Promise<void> | null = null;
  private statusWork: Promise<void> | null = null;
  private unlisten: (() => void) | null = null;
  private disposed = false;
  private readonly candidate: () => VersionEditCandidate | null;
  private finalOriginal: {session: string; generation: string} | null = null;
  private readonly preparation?: { observe(raw:unknown):void; origin():VersionEditOrigin|undefined; released(origin:VersionEditOrigin):boolean };
  constructor(candidate: () => VersionEditCandidate | null, preparation?: { observe(raw:unknown):void; origin():VersionEditOrigin|undefined; released(origin:VersionEditOrigin):boolean }) { this.candidate = candidate; this.preparation=preparation; }
  getSnapshot = () => this.state;
  subscribe = (fn: () => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private publish(issue = this.state.issue): void { this.state = {...this.state,busy:this.retains(),issue}; for (const fn of this.listeners) fn(); }
  retains(): boolean { return !!this.allowWork || !!this.run && !(this.run.returned && this.run.final); }
  delegated(): boolean { return this.run !== null; }
  approvalKey(): string | null { const c = this.candidate(); return c ? JSON.stringify([c.projectId,c.review]) : null; }
  canAllow(): boolean { return !this.disposed && !this.retains() && !this.permission && !!this.candidate(); }
  async connect(api: VersionEditAgentApi | null | undefined): Promise<void> {
    if (!api || this.disposed || this.api === api) return;
    if (this.api) { this.revoke(); if (this.retains()) return; try { this.unlisten?.(); } catch { /* No finality. */ } }
    this.api = api;
    try { const off = await api.subscribe(v => { if (this.api === api) this.observe(v); }); if (this.disposed || this.api !== api) off(); else this.unlisten = off; }
    catch { this.publish('Permission observation is unavailable. Keep the original review.'); }
    await this.checkPreparation();
  }
  allow(): Promise<void> {
    const c = this.candidate();
    if (!this.canAllow() || !c || c.api !== this.api) return Promise.resolve();
    const nonce = crypto.randomUUID().replaceAll('-','');
    const permission: Permission = {candidate:c,nonce,end:performance.now()+900000,revoked:false}; this.permission = permission;
    // Retain identity and promise BEFORE any subscriber can revoke/navigate.
    const work = Promise.resolve().then(async () => {
      if (this.permission !== permission || permission.revoked || !c.current() || this.api !== c.api || this.disposed) return;
      try {
        const raw = await c.api.allow({projectId:c.projectId,original:c.review.original,statusRevision:c.review.nativeStatusRevision,nonce,consent:VERSION_EDIT_CONSENT});
        if (this.permission !== permission) return;
        const access = parseVersionEditAccess(raw);
        if (!access || access.nonce !== nonce || !access.review || !sameVersionEditReview(access.review,c.review)) throw new Error('comparison');
        permission.end = Math.min(permission.end,performance.now()+access.remainingMs);
        this.state = {...this.state,access};
        if (permission.revoked || !c.current() || this.api !== c.api || this.disposed) { this.revoke(); return; }
        this.observe(access);
      } catch { this.publish('The allowance is unconfirmed. Revoke this original permission; do not create another.'); }
    });
    this.allowWork = work; this.publish(null);
    void work.finally(() => { if (this.allowWork === work) this.allowWork = null; this.publish(); });
    return work;
  }
  revoke(): void {
    const p = this.permission; if (!p || p.revoked) return;
    p.revoked = true; this.publish();
    // Exact retained API+nonce works even before the first Allow response.
    try { void p.candidate.api.revoke(p.nonce).then(v => { if (this.permission === p) this.observe(v); }).catch(() => this.publish('Revocation is unconfirmed. The original native permission/READ clock still applies.')); }
    catch { this.publish('Revocation is unconfirmed; keep the original operation.'); }
  }
  sourceChanged(): void { const p = this.permission; if (p && !(this.run ? p.candidate.live() : p.candidate.current())) this.revoke(); }
  async checkPreparation(): Promise<void> {
    if (this.preparationWork || !this.api?.preparation || !this.preparation || this.disposed) return this.preparationWork ?? Promise.resolve();
    const api=this.api, port=api.preparation!, preparation=this.preparation, origin=preparation.origin();
    const work=Promise.resolve().then(async()=>{try {
      const value=await port.status(origin);if(this.api!==api||this.disposed)return;
      preparation.observe(value);
      // A coalesced next event is only a hint. Reconcile the exact old original
      // before ONE fresh latest read, retaining both reads in this same promise.
      if(origin && value!==null && this.api===api && !this.disposed && preparation.released(origin)) {
        const latest=await port.status();
        if(this.api===api&&!this.disposed&&preparation.released(origin))preparation.observe(latest);
      }
    }
      catch { this.publish('Version preparation is unconfirmed. Keep or cancel its original request; do not resend.'); }});
    this.preparationWork=work;try{await work;}finally{if(this.preparationWork===work)this.preparationWork=null;}
  }
  async check(): Promise<void> {
    await this.checkPreparation();
    if (this.statusWork || !this.api || this.disposed) return this.statusWork ?? Promise.resolve();
    const api = this.permission?.candidate.api ?? this.api, origin = this.run?.origin;
    const work = Promise.resolve().then(async () => { try { this.observe(await api.status(origin)); } catch { this.publish('Request status is unconfirmed; never resend Apply.'); } });
    this.statusWork = work; try { await work; } finally { if (this.statusWork === work) this.statusWork = null; }
  }
  observe(raw: unknown): void {
    if (raw && typeof raw==='object' && !Array.isArray(raw) && Object.keys(raw).length===2 && Object.hasOwn(raw,'kind') && Object.hasOwn(raw,'request') &&
        (raw as {kind:unknown}).kind==='preparation') { this.preparation?.observe((raw as {request:unknown}).request);return; }
    const a = parseVersionEditAccess(raw), p = this.permission;
    if (!a) { this.revoke(); this.publish('Invalid version delegation observation. Keep the original request.'); return; }
    if (!p || a.nonce !== p.nonce || !a.review || !sameVersionEditReview(a.review,p.candidate.review)) return;
    if (this.state.access?.request && a.request && this.state.access.request.origin.requestId === a.request.origin.requestId && a.request.revision < this.state.access.request.revision) return;
    this.state = {...this.state,access:a};
    const q = a.request;
    if (q && q.grantId === a.grantId && q.origin.projectId === a.projectId && q.origin.serviceInstance === a.serviceInstance && sameVersionEditReview(q.review,p.candidate.review) && !this.run) {
      const run: Run = {permission:p,origin:q.origin,returned:false,final:this.finalOriginal?.session === p.candidate.review.original.sessionId && this.finalOriginal.generation === p.candidate.review.original.ownerGeneration}; this.run = run; this.publish();
      // Always hold a claimed request even if a post-publication UI cut refuses
      // dispatch; exact revoke sends the original STOP and native retirement.
      if (q.phase !== 'queued' || q.cancelRequested || p.revoked || performance.now() >= p.end || !p.candidate.current() || this.disposed) {
        run.returned = true; this.revoke(); this.publish(); return;
      }
      const work = Promise.resolve().then(async () => {
        if (p.revoked || !p.candidate.current() || this.disposed) { this.revoke(); return; }
        try { await p.candidate.apply(q.origin); } catch { this.revoke(); this.publish('Apply response is unconfirmed. Observe or stop the same request only.'); }
      });
      void work.finally(() => { run.returned = true; this.publish(); });
    }
    this.publish();
  }
  nativeFinal(session: string, generation: string, settled: boolean): void {
    const p = this.permission;
    if (!p || p.candidate.review.original.sessionId !== session || p.candidate.review.original.ownerGeneration !== generation || !settled) return;
    // Retain this exact native final even if the request event is coalesced or
    // arrives later; it cannot be supplied by an unrelated current Status.
    this.finalOriginal = {session,generation};
    if (this.run) this.run.final = true;
    this.publish();
  }
  newOriginal(): void {
    if (this.retains()) return;
    this.revoke(); this.permission = null; this.run = null; this.finalOriginal = null; this.state = {...this.state,access:null}; this.publish(null);
  }
  dispose(): void { this.revoke(); this.disposed = true; try { this.unlisten?.(); } catch { /* No join inferred. */ } this.listeners.clear(); }
}
