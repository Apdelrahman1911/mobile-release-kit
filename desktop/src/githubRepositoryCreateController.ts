import { parseGithubActionStatus, sameGithubActionSelection } from './agentGithubActionAccess.ts';
import type { GithubActionSelection, GithubActionStatus, GithubActionDelegate } from './agentGithubActionAccess.ts';
// One presentation coordinator for the original native connection operation.
// No HTTP, token, timer, automatic creation, Git mutation or new execution owner.
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { parseRepositoryCreateStatus, repositoryCreateCoordinate, repositoryCreateError, REPOSITORY_CREATE_HELP } from './githubRepositoryCreateProtocol.ts';
import type { RepositoryCreateConsent, RepositoryCreateKind, RepositoryCreatePort, RepositoryCreateReason,
  RepositoryCreateStatus, RepositoryCreateTarget, RepositoryOwnerKind, RepositoryVisibility } from './githubRepositoryCreateProtocol.ts';

interface Context { documentId: string; projectId: string; projectGeneration: number; repository: string; sessionId: string; accountId: string; accountLogin: string }
interface Original { port: RepositoryCreatePort; live: boolean; unlisten: (() => void) | null; status: RepositoryCreateStatus | null; fresh: boolean }
interface Work { agentCheck?:{delegate:Delegated;status:RepositoryCreateStatus|null}; owner: Original; kind: 'subscribe' | 'status' | 'start' | 'cancel' | 'discard'; ended: boolean }
interface Attempt { owner: Original; work: Work; context: Context; epoch: object; kind: RepositoryCreateKind; ownerKind: RepositoryOwnerKind;
  visibility: RepositoryVisibility; revision: number; previousId: string | null; operationId: string | null; marker: string | null;
  sent: boolean; replyOk: boolean; stopWanted: boolean; stopSent: boolean; consent: RepositoryCreateConsent | null }
interface Review { owner: Original; context: Context; epoch: object; consent: RepositoryCreateConsent }
interface Delegated {prepareId:string;review:Review;selection:GithubActionSelection;allowReturned:boolean;noAllow:boolean;unused:boolean;terminal:GithubActionStatus|null;unknown:boolean;released:boolean}
export interface RepositoryCreateView {
  native: boolean; status: RepositoryCreateStatus | null; ownerKind: RepositoryOwnerKind; visibility: RepositoryVisibility;
  confirmed: boolean; pending: boolean; observing: boolean; cancelling: boolean; discarding: boolean; uncertain: boolean;
  error: RepositoryCreateReason | null; originalRepository: string | null;
}
function immutable<T>(v: T): T {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.values(v).forEach(immutable); Object.freeze(v); } return v;
}
function context(view: GitHubConnectionViewState): Context | null {
  const c = view.context, s = view.status, account = s?.account.value, session = s?.session;
  if (!c || !s || !account || !session || view.mode !== 'native' || view.blocked || view.uncertain || view.retirementPending || view.busy ||
    session.state !== 'connected' || session.projectId !== c.projectId || session.targetRepository !== c.repository ||
    s.account.state !== 'observed' || !repositoryCreateCoordinate(c.repository)) return null;
  return { ...c, sessionId: session.id, accountId: account.id, accountLogin: account.login };
}
function inContext(t: RepositoryCreateTarget, c: Context): boolean {
  return t.repository.toLowerCase() === c.repository.toLowerCase() && t.accountId === c.accountId && t.accountLogin.toLowerCase() === c.accountLogin.toLowerCase();
}
function advances(a: RepositoryCreateStatus, b: RepositoryCreateStatus): boolean {
  if (a.revision === b.revision) return same(a, b);
  if (a.revision > b.revision || a.reason === 'cleanup-unknown' || a.operation?.phase === 'cleanup-unknown') return false;
  const x = a.operation, y = b.operation;
  if (x && y?.id === x.id) {
    if (x.kind !== y.kind || x.projectId !== y.projectId || !same(x.target, y.target) ||
      x.phase === 'settled' && (!same(x, y) || !same(a.observed, b.observed) || !same(a.pending, b.pending)) ||
      x.phase === 'stopping' && y.phase === 'running' || x.effect === 'potentially-applied' && y.phase !== 'settled' && y.effect !== 'potentially-applied') return false;
  } else if (x && x.phase !== 'settled') return false;
  if (a.consent && b.consent?.id === a.consent.id && !same(a.consent, b.consent)) return false;
  return true;
}
export class GitHubRepositoryCreateController {
  private state: RepositoryCreateView = immutable({ native: false, status: null, ownerKind: 'user', visibility: 'private', confirmed: false,
    pending: false, observing: false, cancelling: false, discarding: false, uncertain: false, error: null, originalRepository: null });
  private listeners = new Set<() => void>();
  private desired: RepositoryCreatePort | null = null;
  private original: Original | null = null;
  private work = new Set<Work>();
  private attempt: Attempt | null = null;
  private review: Review | null = null;
  private delegated:Delegated|null=null;
  private current: Context | null = null;
  private epoch: object = {};
  private unknown = false;
  private cancelledId: string | null = null;
  private disposed = false;
  private connection: () => GitHubConnectionViewState;
  private peer: () => string | null;
  constructor(connection: () => GitHubConnectionViewState, peer: () => string | null = () => null) { this.connection = connection; this.peer = peer; }
  getSnapshot = (): RepositoryCreateView => this.state;
  subscribe = (f: () => void): (() => void) => { this.listeners.add(f); return () => { this.listeners.delete(f); }; };
  private update(patch: Partial<RepositoryCreateView> = {}): void {
    this.state = immutable({ ...this.state, ...patch, pending: this.attempt !== null,
      observing: [...this.work].some((w) => w.kind === 'status' || w.kind === 'subscribe'), cancelling: [...this.work].some((w) => w.kind === 'cancel'),
      discarding: [...this.work].some((w) => w.kind === 'discard') });
    for(const f of [...this.listeners]){try{f();}catch{/* Rendering cannot disown an original invocation. */}}
  }
  private fail(reason: RepositoryCreateReason): void { this.unknown = true; this.review = null; this.update({ uncertain: true, confirmed: false, error: reason }); }
  private invalidate(): void {
    this.epoch = {}; this.review = null;
    if (this.attempt) this.attempt.stopWanted = true;
    this.update({ confirmed: false }); this.stopInvalidated();
  }
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate(); }
  syncContext = (): void => {
    if (this.disposed) return;
    const c = context(this.connection());
    if (!same(c, this.current)) { this.current = c; this.invalidate(); }
  };
  setOwnerKind(kind: RepositoryOwnerKind): void {
    if (!this.disposed && ['user', 'organization'].includes(kind) && kind !== this.state.ownerKind) { this.invalidate(); this.update({ ownerKind: kind }); }
  }
  setVisibility(value: RepositoryVisibility): void {
    if (!this.disposed && ['private', 'public'].includes(value) && value !== this.state.visibility) { this.invalidate(); this.update({ visibility: value }); }
  }
  setConfirmed(value: boolean): void { if (!this.disposed) this.update({ confirmed: value === true && this.currentConsent() !== null }); }
  private owns(o: Original): boolean {
    return this.delegated?.review.owner === o || this.unknown || this.attempt?.owner === o || [...this.work].some((w) => w.owner === o) || !!o.status?.consent ||
      !!o.status?.operation && o.status.operation.phase !== 'settled';
  }
  private maintain(): void {
    const old = this.original;
    if (old && (this.desired !== old.port || this.disposed)) {
      if (this.owns(old)) return;
      const unlisten = old.unlisten; old.unlisten = null; old.live = false;
      try { unlisten?.(); } catch { this.fail('cleanup-unknown'); return; }
      this.original = null;
    }
    if (this.original || this.disposed || !this.desired) return;
    const o: Original = { port: this.desired, live: true, unlisten: null, status: null, fresh: false };
    this.original = o;
    const w = this.latch(o, 'subscribe');
    try {
      const promise = o.port.subscribe((v) => { this.receive(o, v); });
      if (!(promise instanceof Promise)) throw new Error('No original subscription promise');
      void promise.then((stop) => {
        if (typeof stop !== 'function') { this.fail('response-invalid'); return; }
        o.unlisten = stop;
      }, () => this.fail('runtime-unavailable')).finally(() => {
        this.finish(w);
        if (this.original === o && o.live && o.port === this.desired && !this.disposed && !this.unknown) this.checkStatus();
      });
    } catch { this.fail('response-invalid'); this.finish(w); }
  }
  connect(port: RepositoryCreatePort | null): void {
    if (this.disposed || this.desired === port) return;
    this.desired = port; this.syncContext(); this.invalidate(); this.update({ native: port !== null }); this.maintain();
  }
  private latch(owner: Original, kind: Work['kind']): Work { const w: Work = { owner, kind, ended: false }; this.work.add(w); this.update(); return w; }
  private finish(w: Work): void { w.ended = true; this.work.delete(w); this.settle(); this.settleDelegated(w); this.update(); this.maintain();
    if(w.kind==='discard'&&this.delegated?.noAllow&&!this.unknown)this.checkStatus(); }
  private origin(a: Attempt, s: RepositoryCreateStatus): boolean {
    const o = s.operation;
    return a.sent && s.revision > a.revision && s.sessionId === a.context.sessionId && !!o && o.id !== a.previousId &&
      (!a.operationId || o.id === a.operationId) && o.projectId === a.context.projectId && o.kind === a.kind && inContext(o.target, a.context) &&
      (a.kind !== 'prepare' && a.kind !== 'create' || o.target.ownerKind === a.ownerKind && o.target.visibility === a.visibility) &&
      (a.marker === null || a.marker === o.target.marker) && (a.consent === null || same(o.target, a.consent.prepared.target));
  }
  private receive(o: Original, raw: unknown): RepositoryCreateStatus | null {
    if (o !== this.original || !o.live) return null;
    const next = parseRepositoryCreateStatus(raw);
    // Descriptor traps may synchronously retire the viewport. Only the SAME
    // original remains eligible to accept status; no callback installs a port.
    if (o !== this.original || !o.live) return null;
    if (!next) { this.fail('response-invalid'); return null; }
    if (this.unknown) {
      // A later exact original identity can make STOP reachable, never clear
      // uncertainty or replace the retained terminal/result with late success.
      const a = this.attempt;
      if (a?.owner === o && this.origin(a, next) && a.operationId === null) a.operationId = next.operation!.id;
      this.update(); this.stopInvalidated(); return null;
    }
    const s = immutable(next), old = o.status;
    if (old && s.revision < old.revision) {
      if (!advances(s, old)) { this.fail('response-invalid'); return null; }
    } else {
      if (old && !advances(old, s)) { this.fail('response-invalid'); return null; }
      o.status = s; o.fresh = true;
      if (s.reason === 'cleanup-unknown' || s.operation?.phase === 'cleanup-unknown') {
        const a = this.attempt; if (a?.owner === o && this.origin(a, s)) a.operationId = s.operation!.id;
        this.update({ status: s }); this.fail('cleanup-unknown'); this.stopInvalidated(); return s;
      }
      if (this.review && !same(s.consent, this.review.consent)) { this.review = null; this.update({ confirmed: false }); }
      this.update({ status: s, error: this.attempt ? this.state.error : s.operation?.reason && s.operation.reason !== 'none' ? s.operation.reason : null });
    }
    const a = this.attempt;
    if (a?.owner === o && this.origin(a, s)) a.operationId = s.operation!.id;
    this.settle(); this.stopInvalidated(); return s;
  }
  private settle(): void {
    const a = this.attempt, s = a?.owner.status;
    if (!a || !s || !a.work.ended || !this.origin(a, s) || s.operation?.phase !== 'settled' || this.unknown) return;
    this.attempt = null;
    if (a.kind === 'prepare' && a.replyOk && s.consent && a.epoch === this.epoch && a.owner.port === this.desired && !this.disposed &&
      same(a.context, context(this.connection())) && a.ownerKind === this.state.ownerKind && a.visibility === this.state.visibility) {
      this.review = { owner: a.owner, epoch: a.epoch, context: a.context, consent: s.consent };
    }
    this.update({ uncertain: false, error: s.operation.reason === 'none' ? null : s.operation.reason });
  }
  checkStatus(): void {
    const o = this.original;
    if (!o?.live || this.disposed && !this.owns(o) || [...this.work].some((w) => w.owner === o && ['status', 'subscribe'].includes(w.kind))) return;
    const w = this.latch(o, 'status');
    const delegated=this.delegated;
    if(delegated&&(delegated.allowReturned||delegated.noAllow)&&(delegated.unused||delegated.terminal?.settlement==='settled'))w.agentCheck={delegate:delegated,status:null};
    const failed = () => { o.fresh = false; if (this.attempt || o.status?.operation && o.status.operation.phase !== 'settled') this.update({ uncertain: true, error: 'response-invalid' });
      else this.update({ error: 'response-invalid' }); };
    try { const promise = o.port.status(); if (!(promise instanceof Promise)) throw new Error('No original status promise');
      void promise.then((v) => { const accepted=this.receive(o, v);if(w.agentCheck)w.agentCheck.status=accepted; }, failed).finally(() => this.finish(w));
    } catch { failed(); this.finish(w); }
  }
  currentConsent(): RepositoryCreateConsent | null {
    const r = this.review, o = this.original, c = context(this.connection());
    return r && !this.unknown && !this.disposed && r.owner === o && o.port === this.desired && o.fresh && r.epoch === this.epoch &&
      same(c, r.context) && same(o.status?.consent, r.consent) && r.consent.prepared.target.ownerKind === this.state.ownerKind &&
      r.consent.prepared.target.visibility === this.state.visibility ? r.consent : null;
  }
  ownerReason(): string | null {
    if(this.delegated)return 'The original GitHub review is delegated to a local CLI. Check or revoke that permission; original Check/Stop/Close remain available.';
    if (this.unknown) return REPOSITORY_CREATE_HELP['cleanup-unknown'];
    if (this.attempt || this.work.size || this.original?.status?.operation && this.original.status.operation.phase !== 'settled')
      return 'The original GitHub repository task is still active. Check status or Stop it before starting another task.';
    if (this.original?.status?.consent) return 'Create or close the original GitHub repository review before starting another task.';
    return null;
  }
  private startReason(): string | null {
    if(this.delegated)return 'This exact review was delegated. Ordinary Create/Retry cannot consume it, including after a lost Allow reply.';
    const o = this.original, c = context(this.connection()), s = o?.status;
    if (this.disposed || !o?.live || o.port !== this.desired || !o.unlisten) return REPOSITORY_CREATE_HELP['runtime-unavailable'];
    if (this.unknown) return REPOSITORY_CREATE_HELP['cleanup-unknown'];
    if (this.attempt || this.work.size || s?.operation && s.operation.phase !== 'settled') return 'Wait for the original request to finish; status and Stop stay available.';
    if (!c || this.connection().observing) return REPOSITORY_CREATE_HELP['not-connected'];
    if (!s || !o.fresh || s.sessionId !== c.sessionId) return 'Check the current repository task status first.';
    if (s.consent && !this.currentConsent()) return 'Close the previous review before preparing a new one. Your choices are kept.';
    if (!s.available) return REPOSITORY_CREATE_HELP[s.reason];
    return this.peer();
  }
  prepareReason(): string | null {
    const blocked = this.startReason(); if (blocked) return blocked;
    if (this.currentConsent()) return 'Create or close the current review first.';
    const s = this.original!.status!, c = context(this.connection())!;
    if (s.pending.some((p) => inContext(p.prepared.target, c)) || s.operation?.kind === 'create' && s.operation.effect !== 'not-sent' && inContext(s.operation.target, c))
      return 'Check the previous attempt below. A new Create must not repeat an earlier request.';
    return this.state.ownerKind === 'user' && c.repository.split('/')[0]?.toLowerCase() !== c.accountLogin.toLowerCase()
      ? 'For a personal repository, OWNER must be the verified account above. Otherwise choose Organization.' : null;
  }
  createReason(): string | null { return this.startReason() ?? (!this.currentConsent() ? 'Review this exact repository first.' : !this.state.confirmed ? 'Confirm the repository owner, name and visibility below.' : null); }
  pendingReason(): string | null { return this.startReason() ?? (this.currentConsent() ? 'Close this review before checking previous attempts.' : null); }
  reconcileReason(marker: string): string | null {
    return this.pendingReason() ?? (this.original?.status?.pending.filter((p) => p.prepared.target.marker === marker &&
      !!context(this.connection()) && inContext(p.prepared.target, context(this.connection())!)).length === 1 ? null : 'Load this repository’s saved attempt first.');
  }
  private begin(kind: RepositoryCreateKind, marker: string | null,
    invoke: (port: RepositoryCreatePort, attempt: Attempt, connectionRevision: number) => Promise<unknown>): void {
    if (kind === 'prepare' ? this.prepareReason() : kind === 'create' ? this.createReason() :
      kind === 'pending' ? this.pendingReason() : this.reconcileReason(marker!)) return;
    const source = this.connection(), o = this.original, c = context(source), s = o?.status, epoch = this.epoch, consent = this.currentConsent();
    if (!o || !c || !s || !source.status || kind === 'create' && (!consent || !this.state.confirmed)) return;
    const connectionRevision = source.status.revision;
    // Latch without notifying until the Attempt also exists. A listener cannot
    // observe a half-owned request and sneak in a second native admission.
    const w: Work = { owner: o, kind: 'start', ended: false }; this.work.add(w);
    const a: Attempt = { owner: o, work: w, context: c, epoch, kind, ownerKind: this.state.ownerKind, visibility: this.state.visibility,
      revision: s.revision, previousId: s.operation?.id ?? null, operationId: null, marker, sent: false, replyOk: false, stopWanted: false, stopSent: false,
      consent: kind === 'create' ? consent : null };
    this.attempt = a; this.review = null; this.update({ confirmed: false, error: null, originalRepository: c.repository });
    const peer = this.peer();
    if (this.attempt !== a || this.epoch !== epoch || o !== this.original || o.port !== this.desired || this.disposed ||
      this.unknown || o.status !== s || !o.fresh || peer ||
      !same(c, context(this.connection())) || connectionRevision !== this.connection().status?.revision) {
      this.attempt = null; this.update({ error: 'target-changed' }); this.finish(w); return;
    }
    a.sent = true;
    const failed = (error: unknown, sync: boolean) => {
      const parsed = repositoryCreateError(error);
      if (!sync && parsed.notAdmitted && this.attempt === a && a.operationId === null && !this.unknown) {
        this.attempt = null; o.fresh = false; this.update({ error: parsed.reason });
      } else this.update({ uncertain: true, error: parsed.reason });
    };
    try {
      const promise = invoke(o.port, a, connectionRevision);
      if (!(promise instanceof Promise)) throw new Error('No original request promise');
      void promise.then((v) => { const accepted = this.receive(o, v); a.replyOk = accepted !== null && this.origin(a, accepted);
        if (!a.replyOk) this.update({ uncertain: true, error: 'response-invalid' }); }, (e) => failed(e, false)).finally(() => this.finish(w));
    } catch (e) { failed(e, true); this.finish(w); }
  }
  prepare(): void {
    this.begin('prepare', null, (port, a, expectedConnectionRevision) => port.prepare({ sessionId: a.context.sessionId,
      expectedRevision: a.revision, expectedConnectionRevision, ownerKind: a.ownerKind, visibility: a.visibility }));
  }
  create(): void {
    if (this.createReason()) return;
    const review = this.currentConsent()!;
    this.begin('create', review.prepared.target.marker, (port, a) => port.create({ sessionId: a.context.sessionId,
      expectedRevision: a.revision, consentId: a.consent!.id, confirm: true }));
  }
  loadPending(): void {
    this.begin('pending', null, (port, a, expectedConnectionRevision) => port.pending({ sessionId: a.context.sessionId,
      expectedRevision: a.revision, expectedConnectionRevision }));
  }
  reconcile(marker: string): void {
    this.begin('reconcile', marker, (port, a) => port.reconcile({ sessionId: a.context.sessionId, expectedRevision: a.revision, marker: a.marker! }));
  }
  canCancel(): boolean {
    const o = this.original, op = o?.status?.operation;
    const originalId = this.attempt?.operationId ?? op?.id;
    return !!o?.live && !!originalId && (this.unknown && !!this.attempt?.operationId || !!op && op.phase !== 'settled') &&
      originalId !== this.cancelledId && ![...this.work].some((w) => w.kind === 'cancel') && !this.attempt?.stopSent;
  }
  private stopInvalidated(): void { if (this.attempt?.stopWanted && this.attempt.operationId && this.canCancel()) this.cancel(); }
  cancel(): void {
    const a = this.attempt;
    if (a && !a.operationId) { a.stopWanted = true; this.update(); return; }
    if (!this.canCancel()) return;
    const o = this.original!, id = a?.operationId ?? o.status!.operation!.id;
    this.cancelledId = id;
    if (a) a.stopSent = true;
    const w = this.latch(o, 'cancel');
    try { const promise = o.port.cancel({ operationId: id }); if (!(promise instanceof Promise)) throw new Error('No original Stop promise');
      void promise.then((v) => { this.receive(o, v); }, () => this.update({ uncertain: true, error: 'response-invalid' })).finally(() => this.finish(w));
    } catch { this.update({ uncertain: true, error: 'response-invalid' }); this.finish(w); }
  }
  canDiscard(): boolean { return !!this.original?.live && !!this.original.status?.consent && !this.attempt &&
    ![...this.work].some((w) => ['start', 'discard'].includes(w.kind)) && this.original.status.operation?.phase === 'settled' && !this.unknown; }
  discardReview(): void {
    if (!this.canDiscard()) return;
    const o = this.original!, s = o.status!, consent = s.consent!;
    this.review = null; this.epoch = {}; this.state = immutable({ ...this.state, confirmed: false });
    const w = this.latch(o, 'discard');
    try { const promise = o.port.discard({ sessionId: s.sessionId!, expectedRevision: s.revision, consentId: consent.id });
      if (!(promise instanceof Promise)) throw new Error('No original Close promise');
      void promise.then((v) => { this.receive(o, v); if (o.status?.consent?.id === consent.id) this.fail('response-invalid'); }, () => this.fail('response-invalid')).finally(() => this.finish(w));
    } catch { this.fail('response-invalid'); this.finish(w); }
  }
  // Eligibility comes only from the SAME private review, minted after the
  // original Prepare promise returned; a public status/selection cannot mint it.
  agentSelection():GithubActionSelection|null {
    const r=this.review,s=this.original?.status;
    return !this.delegated&&!this.attempt&&!this.work.size&&!this.state.uncertain&&r&&s&&this.currentConsent()===r.consent&&s.sessionId?
      Object.freeze({kind:'repository-create',sessionId:s.sessionId,consentId:r.consent.id,expectedRevision:s.revision}):null;
  }
  agentSelected(selection:GithubActionSelection):boolean {
    const d=this.delegated;
    if(d)return sameGithubActionSelection(d.selection,selection)&&this.delegatedCurrent(d);
    return sameGithubActionSelection(this.agentSelection(),selection);
  }
  private delegatedCurrent(d:Delegated):boolean {
    return this.delegated===d&&!d.unknown&&!this.unknown&&!this.disposed&&!this.attempt&&!this.work.size&&
      this.review===d.review&&this.currentConsent()===d.review.consent&&d.review.owner===this.original&&d.review.owner.live&&
      this.original.status?.revision===d.selection.expectedRevision;
  }
  delegatePrepared(selection:GithubActionSelection):GithubActionDelegate|null {
    if(!sameGithubActionSelection(this.agentSelection(),selection)||!this.review)return null;
    const d:Delegated={prepareId:this.original!.status!.operation!.id,review:this.review,selection:Object.freeze({...selection}),allowReturned:false,noAllow:false,unused:false,terminal:null,unknown:false,released:false};
    this.delegated=d;this.update({confirmed:false}); // latch BEFORE listeners; never rearm this Review.
    const uncertain=()=>{d.unknown=true;this.fail('cleanup-unknown');};
    return Object.freeze({
      current:()=>this.delegatedCurrent(d),released:()=>d.released,
      allowReturned:()=>{if(this.delegated===d&&!d.unknown){d.allowReturned=true;this.update();}},
      observe:(raw:GithubActionStatus)=>{
        const value=parseGithubActionStatus(raw);
        if(this.delegated!==d||d.unknown)return;
        if(!value||!sameGithubActionSelection(value.review,d.selection)||value.settlement==='unknown'){uncertain();return;}
        if(value.settlement==='settled'){d.terminal=value;this.checkStatus();}
      },
      unusedReturned:()=>{if(this.delegated===d&&!d.unknown){d.unused=true;this.checkStatus();}},
      notSubmitted:()=>{if(this.delegated!==d||d.unknown)return;d.noAllow=true;d.unused=true;
        if(this.canDiscard())this.discardReview();else this.checkStatus();},
      uncertain,
    });
  }
  private settleDelegated(w:Work):void {
    const d=this.delegated,s=w.agentCheck?.status;
    if(!d||w.agentCheck?.delegate!==d||!w.ended||!s||d.unknown||this.unknown||!(d.allowReturned||d.noAllow)||
      this.original!==d.review.owner||!d.review.owner.live||this.work.size||!same(s,d.review.owner.status)||s.sessionId!==d.selection.sessionId||
      s.consent!==null||s.operation?.phase!=='settled'||s.operation.projectId!==d.review.context.projectId)return;
    const final=d.terminal,op=s.operation;
    const originalTarget=d.review.consent.prepared.target;
    if(!same(op.target,originalTarget))return;
    if(final?.settlement==='settled'&&!final.neverAdmitted){if(op.kind!=='create'||op.id!==final.operationId)return;}
    else if(d.unused||final?.neverAdmitted){if(op.kind!=='prepare'||op.id!==d.prepareId||s.revision<d.selection.expectedRevision)return;}
    else return;
    d.released=true;this.delegated=null;this.review=null;this.epoch={};
  }
  dispose(): void { this.disposed = true; this.desired = null; this.invalidate(); this.maintain(); }
}
