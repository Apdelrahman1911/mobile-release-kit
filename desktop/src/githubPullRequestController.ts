import { parseGithubActionStatus, sameGithubActionSelection } from './agentGithubActionAccess.ts';
import type { GithubActionSelection, GithubActionStatus, GithubActionDelegate } from './agentGithubActionAccess.ts';
// One presentation coordinator for the original native connection operation.
// No HTTP, token, timer, automatic creation, Git mutation or new execution owner.
import { browserRequestReturned, browserFailure, BROWSER_HELP } from './githubPullRequestManagement.ts';
import type { GitHubBrowserState, GitHubBrowserPage } from './githubPullRequestManagement.ts';
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { parsePullRequestStatus, parsePullRequestDraft, pullRequestError, PULL_REQUEST_HELP } from './githubPullRequestProtocol.ts';
import type { PullRequestConsent, PullRequestKind, PullRequestPort, PullRequestReason,
  PullRequestStatus, PullRequestTarget, PullRequestDraft } from './githubPullRequestProtocol.ts';

interface Context { documentId: string; projectId: string; projectGeneration: number; repository: string; sessionId: string; accountId: string; repositoryId: string }
interface Original { port: PullRequestPort; live: boolean; unlisten: (() => void) | null; status: PullRequestStatus | null; fresh: boolean; closeCheck: object | null }
interface Work { agentCheck?:{delegate:Delegated;status:PullRequestStatus|null}; owner: Original; kind: 'subscribe' | 'status' | 'start' | 'cancel' | 'discard' | 'browser'; ended: boolean; promise: Promise<unknown> | null }
interface Attempt { owner: Original; work: Work; context: Context; epoch: object; kind: PullRequestKind; draft: PullRequestDraft; target: PullRequestTarget | null; revision: number; previousId: string | null; operationId: string | null; marker: string | null;
  sent: boolean; replyOk: boolean; stopWanted: boolean; stopSent: boolean; consent: PullRequestConsent | null }
interface Review { owner: Original; context: Context; epoch: object; consent: PullRequestConsent; draft: PullRequestDraft }
interface Delegated {prepareId:string;review:Review;selection:GithubActionSelection;allowReturned:boolean;noAllow:boolean;unused:boolean;terminal:GithubActionStatus|null;unknown:boolean;released:boolean}
export interface PullRequestCompletion { readonly context:Context; readonly status:PullRequestStatus }
interface Completion {owner:Original;epoch:object;value:PullRequestCompletion}
export interface PullRequestView {
  browserState:GitHubBrowserState;browserPending:boolean;
  native: boolean; status: PullRequestStatus | null; draft: PullRequestDraft;
  confirmed: boolean; pending: boolean; observing: boolean; cancelling: boolean; discarding: boolean; uncertain: boolean;
  error: PullRequestReason | null; originalRepository: string | null;
}
function immutable<T>(v: T): T {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.values(v).forEach(immutable); Object.freeze(v); } return v;
}
function context(view: GitHubConnectionViewState): Context | null {
  const c = view.context, s = view.status, account = s?.account.value, repository=s?.repository.value, session = s?.session;
  if (!c || !s || !account || !repository || !session || view.mode !== 'native' || view.blocked || view.uncertain || view.retirementPending || view.busy ||
    session.state !== 'connected' || session.projectId !== c.projectId || session.targetRepository !== c.repository ||
    s.account.state !== 'observed' || s.repository.state !== 'observed' || repository.fullName.toLowerCase()!==c.repository.toLowerCase()) return null;
  return { ...c, sessionId: session.id, accountId: account.id, repositoryId: repository.id };
}
function inContext(t: PullRequestTarget, c: Context): boolean {
  return t.scope.repository.toLowerCase()===c.repository.toLowerCase() && t.scope.accountId===c.accountId && t.scope.repositoryId===c.repositoryId;
}
function sameBranches(t:PullRequestTarget,d:PullRequestDraft):boolean { return t.intent?.base===d.base && t.intent.head===d.head; }
function advances(a: PullRequestStatus, b: PullRequestStatus): boolean {
  if (a.revision === b.revision) return same(a, b);
  if (a.revision > b.revision || a.reason === 'cleanup-unknown' || a.operation?.phase === 'cleanup-unknown') return false;
  const x = a.operation, y = b.operation;
  if (x && y?.id === x.id) {
    if (x.kind !== y.kind || x.projectId !== y.projectId || !same(x.target, y.target) ||
      x.phase === 'settled' && (!same(x, y) || !same(a.observed, b.observed) || !same(a.acknowledged,b.acknowledged) || !same(a.pending, b.pending)) ||
      x.phase === 'stopping' && y.phase === 'running' || x.effect === 'potentially-applied' && y.phase !== 'settled' && y.effect !== 'potentially-applied') return false;
  } else if (x && x.phase !== 'settled') return false;
  if (a.consent && b.consent?.id === a.consent.id && !same(a.consent, b.consent)) return false;
  return true;
}
export class GitHubPullRequestController {
  private state: PullRequestView = immutable({ browserState:'idle',browserPending:false,native: false, status: null, draft: {base:'',head:'',title:'',body:''}, confirmed: false,
    pending: false, observing: false, cancelling: false, discarding: false, uncertain: false, error: null, originalRepository: null });
  private listeners = new Set<() => void>();
  private desired: PullRequestPort | null = null;
  private original: Original | null = null;
  private work = new Set<Work>();
  private attempt: Attempt | null = null;
  private review: Review | null = null;
  private delegated:Delegated|null=null;
  private completion:Completion|null=null;
  private browserToken:object|null=null;
  private current: Context | null = null;
  private epoch: object = {};
  private approval: object = {};
  private unknown = false;
  private cancelledId: string | null = null;
  private disposed = false;
  private connection: () => GitHubConnectionViewState;
  private peer: () => string | null;
  constructor(connection: () => GitHubConnectionViewState, peer: () => string | null = () => null) { this.connection = connection; this.peer = peer; }
  getSnapshot = (): PullRequestView => this.state;
  subscribe = (f: () => void): (() => void) => { this.listeners.add(f); return () => { this.listeners.delete(f); }; };
  private update(patch: Partial<PullRequestView> = {}): void {
    this.state = immutable({ ...this.state, ...patch, pending: this.attempt !== null, browserPending:[...this.work].some(w=>w.kind==='browser'),
      observing: [...this.work].some((w) => w.kind === 'status' || w.kind === 'subscribe'), cancelling: [...this.work].some((w) => w.kind === 'cancel'),
      discarding: [...this.work].some((w) => w.kind === 'discard') });
    for (const f of [...this.listeners]) { try { f(); } catch { /* Rendering cannot disown an original invocation. */ } }
  }
  private fail(reason: PullRequestReason): void { if (this.unknown) { this.update(); return; } this.unknown = true; this.completion=null; this.review = null; this.update({ uncertain: true, confirmed: false, error: reason }); }
  private invalidate(): void {
    this.epoch = {}; this.review = null; this.completion=null; this.browserToken=null; this.state=immutable({...this.state,browserState:'idle'});
    if (this.attempt) this.attempt.stopWanted = true;
    this.update({ confirmed: false }); this.stopInvalidated();
  }
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate(); }
  syncContext = (): void => {
    if (this.disposed) return;
    const c = context(this.connection());
    if (!same(c, this.current)) { this.current = c; this.invalidate(); }
  };
  setDraft(field:keyof PullRequestDraft,value:string):void {
    if(this.disposed || !['base','head','title','body'].includes(field) || typeof value!=='string' || value.length>8192 || this.state.draft[field]===value)return;
    // Keep even invalid user text for repair, but never a prior review/approval.
    this.state=immutable({...this.state,draft:{...this.state.draft,[field]:value}});
    this.invalidate();
  }
  setConfirmed(value:boolean):void { if(!this.disposed){this.approval={};this.update({confirmed:value===true&&this.currentConsent()!==null});} }
  private owns(o: Original): boolean {
    return this.delegated?.review.owner === o || this.unknown || o.closeCheck !== null || this.attempt?.owner === o || [...this.work].some((w) => w.owner === o) || !!o.status?.consent ||
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
    const o: Original = { port: this.desired, live: true, unlisten: null, status: null, fresh: false, closeCheck: null };
    this.original = o;
    const w = this.latch(o, 'subscribe');
    try {
      const promise = o.port.subscribe((v) => { this.receive(o, v); });
      if (!(promise instanceof Promise)) throw new Error('No original subscription promise'); w.promise=promise;
      void promise.then((stop) => {
        if (typeof stop !== 'function') { this.fail('response-invalid'); return; }
        o.unlisten = stop;
      }, () => this.fail('runtime-unavailable')).finally(() => {
        this.finish(w);
        if (this.original === o && o.live && o.port === this.desired && !this.disposed && !this.unknown) this.checkStatus();
      });
    } catch { this.fail('response-invalid'); this.finish(w); }
  }
  connect(port: PullRequestPort | null): void {
    if (this.disposed || this.desired === port) return;
    this.desired = port; this.syncContext(); this.invalidate(); this.update({ native: port !== null }); this.maintain();
  }
  private latch(owner: Original, kind: Work['kind']): Work { const w: Work = { owner, kind, ended: false, promise: null }; this.work.add(w); this.update(); return w; }
  private finish(w: Work): void { w.ended = true; w.promise=null; this.work.delete(w); this.settle(); this.settleDelegated(w); this.update(); this.maintain();
    if(w.kind==='discard'&&this.delegated?.noAllow&&!this.unknown)this.checkStatus(); }
  private origin(a: Attempt, s: PullRequestStatus): boolean {
    const o = s.operation;
    return a.sent && s.revision > a.revision && s.sessionId === a.context.sessionId && !!o && o.id !== a.previousId &&
      (!a.operationId || o.id === a.operationId) && o.projectId === a.context.projectId && o.kind === a.kind && inContext(o.target, a.context) &&
      (a.kind !== 'prepare' && a.kind !== 'create' || sameBranches(o.target,a.draft)) && (a.target===null || same(o.target,a.target)) &&
      (a.marker === null || a.marker === o.target.intent?.marker) && (a.consent === null || same(o.target, a.consent.prepared.target));
  }
  private receive(o: Original, raw: unknown): PullRequestStatus | null {
    if (o !== this.original || !o.live) return null;
    const next = parsePullRequestStatus(raw);
    // Descriptor traps may synchronously retire the viewport. Only the SAME
    // original remains eligible to accept status; no callback installs a port.
    if (o !== this.original || !o.live) return null;
    if (!next) { this.fail('response-invalid'); return null; }
    if (this.unknown) {
      // A later exact original identity can make STOP reachable, never clear
      // uncertainty or replace the retained terminal/result with late success.
      const a = this.attempt;
      if (a?.owner === o && this.origin(a, next) && a.operationId === null) {a.operationId = next.operation!.id; a.target=next.operation!.target;}
      this.update(); this.stopInvalidated(); return null;
    }
    const s = immutable(next), old = o.status;
    if (old && s.revision < old.revision) {
      if (!advances(s, old)) { this.fail('response-invalid'); return null; }
    } else {
      if (old && !advances(old, s)) { this.fail('response-invalid'); return null; }
      o.status = s; o.fresh = o.closeCheck === null;
      if (s.reason === 'cleanup-unknown' || s.operation?.phase === 'cleanup-unknown') {
        const a = this.attempt; if (a?.owner === o && this.origin(a, s)) {a.operationId = s.operation!.id; a.target=s.operation!.target;}
        this.update({ status: s }); this.fail('cleanup-unknown'); this.stopInvalidated(); return s;
      }
      if (this.review && !same(s.consent, this.review.consent)) { this.review = null; this.update({ confirmed: false }); }
      this.update({ status: s, error: this.attempt || o.closeCheck ? this.state.error : s.operation?.reason && s.operation.reason !== 'none' ? s.operation.reason : null });
    }
    const a = this.attempt;
    if (a?.owner === o && this.origin(a, s)) {a.operationId = s.operation!.id; a.target=s.operation!.target;}
    this.settle(); this.stopInvalidated(); return s;
  }
  private settle(): void {
    const a = this.attempt, s = a?.owner.status;
    if (!a || !s || !a.work.ended || !this.origin(a, s) || s.operation?.phase !== 'settled' || this.unknown) return;
    this.attempt = null;
    if (a.kind === 'prepare' && a.replyOk && s.consent && a.epoch === this.epoch && a.owner.port === this.desired && !this.disposed &&
      same(a.context, context(this.connection())) && a.draft === this.state.draft && sameBranches(s.consent.prepared.target,a.draft)) {
      this.review = { owner: a.owner, epoch: a.epoch, context: a.context, consent: s.consent, draft:a.draft };
    }
    if(a.replyOk&&(a.kind==='create'||a.kind==='reconcile')&&(s.acknowledged||s.observed)&&a.epoch===this.epoch&&a.owner.port===this.desired&&!this.disposed&&same(a.context,context(this.connection())))
      this.completion={owner:a.owner,epoch:a.epoch,value:immutable({context:a.context,status:s})};
    this.update({ uncertain: false, error: s.operation.reason === 'none' ? null : s.operation.reason });
  }
  canCheck():boolean { const o=this.original;return !!o?.live&&(!this.disposed||this.owns(o))&&![...this.work].some(w=>w.owner===o&&(w.kind==='status'||w.kind==='subscribe')); }
  checkStatus(): void {
    const o = this.original;
    if (!o?.live || this.disposed && !this.owns(o) || [...this.work].some((w) => w.owner === o && ['status', 'subscribe'].includes(w.kind))) return;
    const closeCheck = o.closeCheck;
    const w = this.latch(o, 'status');
    const delegated=this.delegated;
    if(delegated&&(delegated.allowReturned||delegated.noAllow)&&(delegated.unused||delegated.terminal?.settlement==='settled'))w.agentCheck={delegate:delegated,status:null};
    const failed = () => { o.fresh = false; if (this.attempt || o.status?.operation && o.status.operation.phase !== 'settled') this.update({ uncertain: true, error: 'response-invalid' });
      else this.update({ error: 'response-invalid' }); };
    try { const promise = o.port.status(); if (!(promise instanceof Promise)) throw new Error('No original status promise'); w.promise=promise;
      void promise.then((v) => {
        const accepted = this.receive(o, v);
        if(w.agentCheck)w.agentCheck.status=accepted;
        // Only a Check started after this exact known refusal can restore
        // freshness. Old polls/events cannot reopen Close or replace its owner.
        if (accepted && !this.unknown && o === this.original && o.live && closeCheck !== null &&
          o.closeCheck === closeCheck && o.status && accepted.revision === o.status.revision) {
          o.closeCheck = null; o.fresh = true;
          this.update({ error: o.status.operation?.reason && o.status.operation.reason !== 'none' ? o.status.operation.reason : null });
        }
      }, failed).finally(() => this.finish(w));
    } catch { failed(); this.finish(w); }
  }
  currentConsent(): PullRequestConsent | null {
    const r = this.review, o = this.original, c = context(this.connection());
    return r && !this.unknown && !this.disposed && r.owner === o && o.port === this.desired && o.fresh && r.epoch === this.epoch &&
      same(c, r.context) && same(o.status?.consent, r.consent) && r.draft===this.state.draft && sameBranches(r.consent.prepared.target,r.draft) ? r.consent : null;
  }
  currentCompletion():PullRequestCompletion|null {
    const r=this.completion,o=this.original,s=o?.status;
    return r&&!this.unknown&&!this.disposed&&r.owner===o&&o.live&&o.port===this.desired&&o.fresh&&r.epoch===this.epoch&&
      same(r.value.context,context(this.connection()))&&same(r.value.status.operation,s?.operation)&&same(r.value.status.acknowledged,s?.acknowledged)&&
      same(r.value.status.observed,s?.observed)?r.value:null;
  }
  completionBrowserReason(expected:PullRequestCompletion):string|null {
    return this.currentCompletion()!==expected?BROWSER_HELP.stale:this.browserReason();
  }
  comparisonBrowserReason(expected:PullRequestConsent):string|null {
    return this.currentConsent()!==expected?BROWSER_HELP.stale:this.browserReason();
  }
  private browserReason():string|null {
    if(!this.original?.port.openBrowser)return BROWSER_HELP.unavailable;
    if(['unconfirmed','unavailable','stale'].includes(this.state.browserState))return BROWSER_HELP[this.state.browserState];
    return this.startReason();
  }
  openCompletedPullRequest(expected:PullRequestCompletion,page:GitHubBrowserPage):void {
    if(!['conversation','files'].includes(page)||this.completionBrowserReason(expected)||!expected.status.operation)return;
    this.openBrowser({kind:'created-pull-request',operationId:expected.status.operation.id,page},()=>this.currentCompletion()===expected);
  }
  openComparison(expected:PullRequestConsent):void {
    if(this.comparisonBrowserReason(expected))return;
    this.openBrowser({kind:'comparison',consentId:expected.id},()=>this.currentConsent()===expected);
  }
  private openBrowser(target:{kind:'created-pull-request';operationId:string;page:GitHubBrowserPage}|{kind:'comparison';consentId:string},sourceCurrent:()=>boolean):void {
    const o=this.original!,s=o.status!,c=context(this.connection()),epoch=this.epoch,revision=this.connection().status?.revision;
    if(!c||revision===undefined||!o.port.openBrowser)return;
    const token={};this.browserToken=token;
    const w:Work={owner:o,kind:'browser',ended:false,promise:null};this.work.add(w);this.update({browserState:'requesting'});
    const peer=this.peer();
    const current=()=>this.browserToken===token&&this.epoch===epoch&&sourceCurrent()&&o===this.original&&o.port===this.desired&&
      o.status===s&&same(c,context(this.connection()))&&revision===this.connection().status?.revision;
    if(!current()||peer||this.work.size!==1){if(this.browserToken===token)this.update({browserState:'stale'});this.finish(w);return;}
    const returned=(raw:unknown)=>{const ok=browserRequestReturned(raw);if(this.browserToken===token)this.update({browserState:current()?(ok?'request-sent':'unconfirmed'):'stale'});};
    const failed=(raw:unknown)=>{const state=browserFailure(raw);if(this.browserToken===token)this.update({browserState:current()?state:'stale'});};
    try {
      const promise=o.port.openBrowser({...target,sessionId:c.sessionId,expectedRevision:s.revision,expectedConnectionRevision:revision});
      if(!(promise instanceof Promise))throw new Error('Original browser request not retained');w.promise=promise;
      void promise.then(returned,failed).finally(()=>this.finish(w));
    }catch(e){failed(e);this.finish(w);}
  }
  ownerReason(): string | null {
    if(this.delegated)return 'The original GitHub review is delegated to a local CLI. Check or revoke that permission; original Check/Stop/Close remain available.';
    if (this.unknown) return PULL_REQUEST_HELP['cleanup-unknown'];
    if([...this.work].some(w=>w.kind==='browser'))return 'The original browser request is still returning. Other tasks wait for that same call.';
    if (this.attempt || this.work.size || this.original?.status?.operation && this.original.status.operation.phase !== 'settled')
      return 'The original draft pull request task is still active. Check status or Stop it before starting another task.';
    if (this.original?.closeCheck) return 'Check task status to refresh the original review. Your draft is kept; Close has not been repeated.';
    if (this.original?.status?.consent) return 'Create or close the original draft pull request review before starting another task.';
    return null;
  }
  private startReason(): string | null {
    if(this.delegated)return 'This exact review was delegated. Ordinary Create/Retry cannot consume it, including after a lost Allow reply.';
    const o = this.original, c = context(this.connection()), s = o?.status;
    if (this.disposed || !o?.live || o.port !== this.desired || !o.unlisten) return PULL_REQUEST_HELP['runtime-unavailable'];
    if (this.unknown) return PULL_REQUEST_HELP['cleanup-unknown'];
    if (this.attempt || this.work.size || s?.operation && s.operation.phase !== 'settled') return 'Wait for the original request to finish; status and Stop stay available.';
    if (!c || this.connection().observing) return PULL_REQUEST_HELP['not-connected'];
    if (!s || !o.fresh || s.sessionId !== c.sessionId) return 'Check the current draft pull request task status first.';
    if (s.consent && !this.currentConsent()) return 'Close the previous review before preparing a new one. Your choices are kept.';
    if (!s.available) return PULL_REQUEST_HELP[s.reason];
    return this.peer();
  }
  prepareReason(): string | null {
    const blocked=this.startReason();if(blocked)return blocked;
    if(this.currentConsent())return 'Create or close the current review first.';
    if(!parsePullRequestDraft(this.state.draft))return PULL_REQUEST_HELP['invalid-input'];
    const s=this.original!.status!,c=context(this.connection())!;
    if(s.pending.some(p=>!p.closed&&inContext(p.prepared.target,c)&&sameBranches(p.prepared.target,this.state.draft)) ||
      s.operation?.kind==='create'&&s.operation.effect!=='not-sent'&&inContext(s.operation.target,c)&&sameBranches(s.operation.target,this.state.draft))
      return 'Check the previous attempt for these branches below. A new review cannot authorize a duplicate Create.';
    return null;
  }
  createReason():string|null { return this.startReason() ?? (!this.currentConsent()?'Review these exact branches and text first.':!this.state.confirmed?'Confirm the draft pull request and CI-trigger warning below.':null); }
  pendingReason(): string | null { return this.startReason() ?? (this.currentConsent() ? 'Close this review before checking previous attempts.' : null); }
  reconcileReason(marker: string): string | null {
    return this.pendingReason() ?? (this.original?.status?.pending.filter((p) => p.prepared.target.intent?.marker === marker &&
      !!context(this.connection()) && inContext(p.prepared.target, context(this.connection())!)).length === 1 ? null : 'Load this repository’s saved attempt first.');
  }
  private begin(kind: PullRequestKind, marker: string | null,
    invoke: (port: PullRequestPort, attempt: Attempt, connectionRevision: number) => Promise<unknown>): void {
    if (kind === 'prepare' ? this.prepareReason() : kind === 'create' ? this.createReason() :
      kind === 'pending' ? this.pendingReason() : this.reconcileReason(marker!)) return;
    const source = this.connection(), o = this.original, c = context(source), s = o?.status, epoch = this.epoch, consent = this.currentConsent(), approval=this.approval;
    if (!o || !c || !s || !source.status || kind === 'create' && (!consent || !this.state.confirmed)) return;
    const connectionRevision = source.status.revision;
    // Latch without notifying until the Attempt also exists. A listener cannot
    // observe a half-owned request and sneak in a second native admission.
    const w: Work = { owner: o, kind: 'start', ended: false, promise:null }; this.work.add(w);
    const a: Attempt = { owner: o, work: w, context: c, epoch, kind, draft:this.state.draft, target:kind==='create'?consent?.prepared.target??null:kind==='reconcile'?s.pending.find(p=>p.prepared.target.intent?.marker===marker)?.prepared.target??null:null,
      revision: s.revision, previousId: s.operation?.id ?? null, operationId: null, marker, sent: false, replyOk: false, stopWanted: false, stopSent: false,
      consent: kind === 'create' ? consent : null };
    this.attempt = a; this.review = null; this.completion=null; this.browserToken=null; this.update({ confirmed: false, error: null, browserState:'idle', originalRepository: c.repository });
    const peer = this.peer();
    if (this.attempt !== a || a.stopWanted || kind==='create'&&approval!==this.approval || a.draft!==this.state.draft || this.epoch !== epoch || o !== this.original || o.port !== this.desired || this.disposed ||
      this.unknown || o.status !== s || !o.fresh || peer ||
      !same(c, context(this.connection())) || connectionRevision !== this.connection().status?.revision) {
      this.attempt = null; this.update({ error: a.stopWanted?'cancelled':'target-changed' }); this.finish(w); return;
    }
    a.sent = true;
    const failed = (error: unknown, sync: boolean) => {
      const parsed = pullRequestError(error);
      if (!sync && parsed.notAdmitted && this.attempt === a && a.operationId === null && !this.unknown) {
        this.attempt = null; o.fresh = false; this.update({ error: parsed.reason });
      } else this.fail(parsed.reason);
    };
    try {
      const promise = invoke(o.port, a, connectionRevision);
      if (!(promise instanceof Promise)) throw new Error('No original request promise'); w.promise=promise;
      void promise.then((v) => { const accepted = this.receive(o, v); a.replyOk = accepted !== null && this.origin(a, accepted);
        if (!a.replyOk) this.fail('response-invalid'); }, (e) => failed(e, false)).finally(() => this.finish(w));
    } catch (e) { failed(e, true); this.finish(w); }
  }
  prepare(): void {
    this.begin('prepare', null, (port, a, expectedConnectionRevision) => port.prepare({ sessionId: a.context.sessionId,
      expectedRevision: a.revision, expectedConnectionRevision, draft:a.draft }));
  }
  create(): void {
    if (this.createReason()) return;
    const review = this.currentConsent()!;
    this.begin('create', review.prepared.target.intent!.marker, (port, a) => port.create({ sessionId: a.context.sessionId,
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
    if(this.attempt&&!this.attempt.operationId)return !this.attempt.stopWanted&&!this.attempt.stopSent;
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
    try { const promise = o.port.cancel({ operationId: id }); if (!(promise instanceof Promise)) throw new Error('No original Stop promise'); w.promise=promise;
      void promise.then((v) => { this.receive(o, v); }, () => this.fail('response-invalid')).finally(() => this.finish(w));
    } catch { this.fail('response-invalid'); this.finish(w); }
  }
  canDiscard(): boolean { return !!this.original?.live && this.original.fresh && !!this.original.status?.consent && !this.attempt &&
    ![...this.work].some((w) => ['start', 'discard'].includes(w.kind)) && this.original.status.operation?.phase === 'settled' && !this.unknown; }
  discardReview(): void {
    if (!this.canDiscard()) return;
    const o = this.original!, s = o.status!, consent = s.consent!;
    this.review = null; this.epoch = {}; this.state = immutable({ ...this.state, confirmed: false });
    const w = this.latch(o, 'discard');
    const failed = (error: unknown, sync: boolean) => {
      const parsed = pullRequestError(error);
      if (!sync && parsed.notAdmitted && !this.unknown) {
        // Native expiry may already have retired this unused consent. Keep the
        // original and require a fresh Check; this is not a lost Close receipt.
        o.closeCheck = {}; o.fresh = false; this.update({ error: parsed.reason });
      } else this.fail(parsed.reason);
    };
    try { const promise = o.port.discard({ sessionId: s.sessionId!, expectedRevision: s.revision, consentId: consent.id });
      if (!(promise instanceof Promise)) throw new Error('No original Close promise'); w.promise=promise;
      void promise.then((v) => { this.receive(o, v); if (o.status?.consent?.id === consent.id) this.fail('response-invalid'); }, (e) => failed(e, false)).finally(() => this.finish(w));
    } catch (e) { failed(e, true); this.finish(w); }
  }
  // Eligibility comes only from the SAME private review, minted after the
  // original Prepare promise returned; a public status/selection cannot mint it.
  agentSelection():GithubActionSelection|null {
    const r=this.review,s=this.original?.status;
    return !this.delegated&&!this.attempt&&!this.work.size&&!this.state.uncertain&&r&&s&&this.currentConsent()===r.consent&&s.sessionId?
      Object.freeze({kind:'draft-pr-create',sessionId:s.sessionId,consentId:r.consent.id,expectedRevision:s.revision}):null;
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
