import { isGithubOperationKind, parseGithubOperationSelection, githubOperationPreparedHash, githubOperationRecord, githubOperationRecordHash } from './githubOperationDelegation.ts';
import type { GithubOperationKind, GithubOperationSelection } from './githubOperationDelegation.ts';
import type { ActionsRetryPending } from './githubActionsRetryProtocol.ts';
import { parseGithubActionStatus, sameGithubActionSelection } from './agentGithubActionAccess.ts';
import type { GithubActionSelection, GithubActionStatus, GithubActionDelegate } from './agentGithubActionAccess.ts';
// One presentation coordinator for the original native connection operation.
// No HTTP, token, timer, automatic creation, Git mutation or new execution owner.
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import type { ActivityObservation } from './githubActivityProtocol.ts';
import { parseActionsRetryStatus, actionsRetryError, ACTIONS_RETRY_HELP } from './githubActionsRetryProtocol.ts';
import type { ActionsRetryConsent, ActionsRetryKind, ActionsRetryPort, ActionsRetryReason,
  ActionsRetryStatus, ActionsRetryTarget } from './githubActionsRetryProtocol.ts';

interface Context { documentId: string; projectId: string; projectGeneration: number; repository: string; sessionId: string; accountId: string; repositoryId: string }
interface Original { port: ActionsRetryPort; live: boolean; unlisten: (() => void) | null; status: ActionsRetryStatus | null; fresh: boolean; closeCheck: object | null }
interface Work { operationCheck?:OperationCheck; agentCheck?:{delegate:Delegated;status:ActionsRetryStatus|null}; owner: Original; kind: 'subscribe' | 'status' | 'start' | 'cancel' | 'discard'; ended: boolean; promise: Promise<unknown> | null }
interface Attempt { owner: Original; work: Work; context: Context; epoch: object; kind: ActionsRetryKind; picked: ActionsRetryActivitySource | null; target: ActionsRetryTarget | null; revision: number; previousId: string | null; operationId: string | null; marker: string | null;
  sent: boolean; replyOk: boolean; stopWanted: boolean; stopSent: boolean; consent: ActionsRetryConsent | null }
interface Review { owner: Original; context: Context; epoch: object; consent: ActionsRetryConsent; picked: ActionsRetryActivitySource }
interface Delegated {prepareId:string;review:Review;selection:GithubActionSelection;allowReturned:boolean;noAllow:boolean;unused:boolean;terminal:GithubActionStatus|null;unknown:boolean;released:boolean}
interface OperationDelegated {owner:Original;context:Context;epoch:object;selection:GithubOperationSelection;previousId:string|null;record:ActionsRetryPending|null;picked:ActionsRetryActivitySource|null;
 allowed:boolean;unused:boolean;noAllow:boolean;terminal:GithubActionStatus|null;unknown:boolean;released:boolean}
interface OperationCheck {delegate:OperationDelegated;allowed:boolean;unused:boolean;noAllow:boolean;terminal:GithubActionStatus|null;status:ActionsRetryStatus|null}
interface OperationRecords {owner:Original;context:Context;epoch:object;status:ActionsRetryStatus}
export interface ActionsRetryView {
  agentReconcileMarker:string|null;
  native: boolean; status: ActionsRetryStatus | null;
  confirmed: boolean; pending: boolean; observing: boolean; cancelling: boolean; discarding: boolean; uncertain: boolean;
  error: ActionsRetryReason | null; originalRepository: string | null;
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
function inContext(t: ActionsRetryTarget, c: Context): boolean {
  return t.scope.repository.toLowerCase()===c.repository.toLowerCase() && t.scope.accountId===c.accountId && t.scope.repositoryId===c.repositoryId;
}
export interface ActionsRetryActivitySource { revision:number; observation:ActivityObservation }
function samePicked(a:ActionsRetryActivitySource|null,b:ActionsRetryActivitySource|null):boolean {
  return a===b || !!a&&!!b&&a.revision===b.revision&&a.observation===b.observation;
}
function sameSelection(t:ActionsRetryTarget,p:ActionsRetryActivitySource|null):boolean {
  const r=p?.observation.data;
  return r?.kind==='workflow-run' && t.selection?.runId===r.run.id && t.selection.attempt===r.run.attempt && t.selection.headSha===r.run.headSha;
}

function advances(a: ActionsRetryStatus, b: ActionsRetryStatus): boolean {
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
export class GitHubActionsRetryController {
  private state: ActionsRetryView = immutable({ agentReconcileMarker:null,native: false, status: null, confirmed: false,
    pending: false, observing: false, cancelling: false, discarding: false, uncertain: false, error: null, originalRepository: null });
  private listeners = new Set<() => void>();
  private desired: ActionsRetryPort | null = null;
  private original: Original | null = null;
  private work = new Set<Work>();
  private attempt: Attempt | null = null;
  private review: Review | null = null;
  private delegated:Delegated|null=null;
  private operationDelegate:OperationDelegated|null=null; private operationRecords:OperationRecords|null=null; private operationRecord:ActionsRetryPending|null=null;
  private current: Context | null = null;
  private epoch: object = {};
  private approval: object = {};
  private unknown = false;
  private cancelledId: string | null = null;
  private disposed = false;
  private connection: () => GitHubConnectionViewState;
  private peer: () => string | null;
  private activity: () => ActionsRetryActivitySource | null;
  constructor(connection: () => GitHubConnectionViewState, activity: () => ActionsRetryActivitySource | null, peer: () => string | null = () => null) { this.connection = connection; this.activity = activity; this.peer = peer; }
  getSnapshot = (): ActionsRetryView => this.state;
  subscribe = (f: () => void): (() => void) => { this.listeners.add(f); return () => { this.listeners.delete(f); }; };
  private update(patch: Partial<ActionsRetryView> = {}): void {
    this.state = immutable({ ...this.state, ...patch, agentReconcileMarker:this.operationRecord?.prepared.target.selection?.marker??null, pending: this.attempt !== null,
      observing: [...this.work].some((w) => w.kind === 'status' || w.kind === 'subscribe'), cancelling: [...this.work].some((w) => w.kind === 'cancel'),
      discarding: [...this.work].some((w) => w.kind === 'discard') });
    for (const f of [...this.listeners]) { try { f(); } catch { /* Rendering cannot disown an original invocation. */ } }
  }
  private fail(reason: ActionsRetryReason): void { if (this.unknown) { this.update(); return; } this.unknown = true; this.review = null; this.update({ uncertain: true, confirmed: false, error: reason }); }
  private invalidate(): void {
    this.epoch = {}; this.review = null; this.operationRecords=null; this.operationRecord=null;
    if (this.attempt) this.attempt.stopWanted = true;
    this.update({ confirmed: false }); this.stopInvalidated();
  }
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate(); }
  syncContext = (): void => {
    if (this.disposed) return;
    const c = context(this.connection());
    if (!same(c, this.current)) { this.current = c; this.invalidate(); }
  };
  setConfirmed(value:boolean):void { if(!this.disposed){this.approval={};this.update({confirmed:value===true&&this.currentConsent()!==null});} }
  private owns(o: Original): boolean {
    return this.operationDelegate?.owner === o || this.delegated?.review.owner === o || this.unknown || o.closeCheck !== null || this.attempt?.owner === o || [...this.work].some((w) => w.owner === o) || !!o.status?.consent ||
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
  connect(port: ActionsRetryPort | null): void {
    if (this.disposed || this.desired === port) return;
    this.desired = port; this.syncContext(); this.invalidate(); this.update({ native: port !== null }); this.maintain();
  }
  private latch(owner: Original, kind: Work['kind']): Work { const w: Work = { owner, kind, ended: false, promise: null }; this.work.add(w); this.update(); return w; }
  private finish(w: Work): void { w.ended = true; w.promise=null; this.work.delete(w); this.settle(); this.settleDelegated(w); this.settleOperation(w); this.update(); this.maintain();
    if(w.kind==='discard'&&this.delegated?.noAllow&&!this.unknown)this.checkStatus(); }
  private origin(a: Attempt, s: ActionsRetryStatus): boolean {
    const o = s.operation;
    return a.sent && s.revision > a.revision && s.sessionId === a.context.sessionId && !!o && o.id !== a.previousId &&
      (!a.operationId || o.id === a.operationId) && o.projectId === a.context.projectId && o.kind === a.kind && inContext(o.target, a.context) &&
      (a.kind !== 'prepare' && a.kind !== 'retry' || sameSelection(o.target,a.picked)) && (a.target===null || same(o.target,a.target)) &&
      (a.marker === null || a.marker === o.target.selection?.marker) && (a.consent === null || same(o.target, a.consent.prepared.target));
  }
  private receive(o: Original, raw: unknown): ActionsRetryStatus | null {
    if (o !== this.original || !o.live) return null;
    const next = parseActionsRetryStatus(raw);
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
    if(a.kind==='pending'&&a.replyOk&&s.operation.reason==='none'&&a.epoch===this.epoch&&a.owner.port===this.desired&&!this.disposed&&same(a.context,context(this.connection())))
      this.operationRecords={owner:a.owner,context:a.context,epoch:a.epoch,status:s};
    if (a.kind === 'prepare' && a.replyOk && s.consent && a.epoch === this.epoch && a.owner.port === this.desired && !this.disposed &&
      same(a.context, context(this.connection())) && a.picked !== null && sameSelection(s.consent.prepared.target,a.picked)) {
      this.review = { owner: a.owner, epoch: a.epoch, context: a.context, consent: s.consent, picked:a.picked };
    }
    this.update({ uncertain: false, error: s.operation.reason === 'none' ? null : s.operation.reason });
  }
  canCheck():boolean { const o=this.original;return !!o?.live&&(!this.disposed||this.owns(o))&&![...this.work].some(w=>w.owner===o&&(w.kind==='status'||w.kind==='subscribe')); }
  checkStatus(): void {
    const o = this.original;
    if (!o?.live || this.disposed && !this.owns(o) || [...this.work].some((w) => w.owner === o && ['status', 'subscribe'].includes(w.kind))) return;
    const closeCheck = o.closeCheck;
    // Capture the exact service-final/permission facts BEFORE listener publication.
    // A later compact event cannot convert a previously started Status into a join.
    const w:Work={owner:o,kind:'status',ended:false,promise:null};
    const delegated=this.delegated,operation=this.operationDelegate;
    if(delegated&&(delegated.allowReturned||delegated.noAllow)&&(delegated.unused||delegated.terminal?.settlement==='settled'))w.agentCheck={delegate:delegated,status:null};
    if(operation)w.operationCheck={delegate:operation,allowed:operation.allowed,unused:operation.unused,noAllow:operation.noAllow,terminal:operation.terminal,status:null};
    this.work.add(w);this.update();
    const failed = () => { o.fresh = false; if (this.attempt || o.status?.operation && o.status.operation.phase !== 'settled') this.update({ uncertain: true, error: 'response-invalid' });
      else this.update({ error: 'response-invalid' }); };
    try { const promise = o.port.status(); if (!(promise instanceof Promise)) throw new Error('No original status promise'); w.promise=promise;
      void promise.then((v) => {
        const accepted = this.receive(o, v);
        if(w.agentCheck)w.agentCheck.status=accepted;
        if(w.operationCheck)w.operationCheck.status=accepted;
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
  currentConsent(): ActionsRetryConsent | null {
    const r = this.review, o = this.original, c = context(this.connection());
    return r && !this.unknown && !this.disposed && r.owner === o && o.port === this.desired && o.fresh && r.epoch === this.epoch &&
      same(c, r.context) && same(o.status?.consent, r.consent) && r.picked!==null && sameSelection(r.consent.prepared.target,r.picked) ? r.consent : null;
  }
  ownerReason(): string | null {
    if(this.operationDelegate)return 'This original preparation/read is delegated. Check or revoke its permission; no Create/Retry is automatic.';
    if(this.delegated)return 'The original GitHub review is delegated to a local CLI. Check or revoke that permission; original Check/Stop/Close remain available.';
    if (this.unknown) return ACTIONS_RETRY_HELP['cleanup-unknown'];
    if (this.attempt || this.work.size || this.original?.status?.operation && this.original.status.operation.phase !== 'settled')
      return 'The original Actions retry task is still active. Check status or Stop it before starting another task.';
    if (this.original?.closeCheck) return 'Check task status to refresh the original review. Close has not been repeated.';
    if (this.original?.status?.consent) return 'Retry or close the original run review before starting another task.';
    return null;
  }
  private startReason(): string | null {
    if(this.operationDelegate)return 'Withdraw the original preparation/read permission before another action.';
    if(this.delegated)return 'This exact review was delegated. Ordinary Create/Retry cannot consume it, including after a lost Allow reply.';
    const o = this.original, c = context(this.connection()), s = o?.status;
    if (this.disposed || !o?.live || o.port !== this.desired || !o.unlisten) return ACTIONS_RETRY_HELP['runtime-unavailable'];
    if (this.unknown) return ACTIONS_RETRY_HELP['cleanup-unknown'];
    if (this.attempt || this.work.size || s?.operation && s.operation.phase !== 'settled') return 'Wait for the original request to finish; status and Stop stay available.';
    if (!c || this.connection().observing) return ACTIONS_RETRY_HELP['not-connected'];
    if (!s || !o.fresh || s.sessionId !== c.sessionId) return 'Check the current Actions retry task status first.';
    if (s.consent && !this.currentConsent()) return 'Close the previous review before preparing a new one. The original run is still identified.';
    if (!s.available) return ACTIONS_RETRY_HELP[s.reason];
    return this.peer();
  }
  private selectedRun(): ActionsRetryActivitySource | null {
    const picked=this.activity(),c=context(this.connection()),r=picked?.observation,run=r?.data;
    if(!picked||!r||!c||run?.kind!=='workflow-run'||!Number.isInteger(picked.revision)||picked.revision<1||picked.revision>0xffff_fffe||
      r.selection.kind!=='workflow-run'||r.selection.runId!==run.run.id||r.selection.attempt!==run.run.attempt||
      r.target.repository.toLowerCase()!==c.repository.toLowerCase()||r.target.accountId!==c.accountId||r.target.repositoryId!==c.repositoryId||
      run.run.status!=='completed'||!['failure','timed_out'].includes(run.run.conclusion??''))return null;
    return picked;
  }
  prepareReason(): string | null {
    const blocked=this.startReason();if(blocked)return blocked;
    if(this.currentConsent())return 'Retry or close the current review first.';
    const picked=this.selectedRun(),run=picked?.observation.data;
    if(!picked||run?.kind!=='workflow-run')return 'Read a completed failed or timed-out workflow attempt in Activity first.';
    const s=this.original!.status!,c=context(this.connection())!,selected=run.run;
    // An acknowledged older attempt does NOT ban a genuinely newer explicit
    // review. Unknown claims remain protected, including a lost POST reply.
    if(s.pending.some(p=>inContext(p.prepared.target,c)&&p.prepared.run.id===selected.id&&(!p.acknowledged||p.prepared.run.attempt>=selected.attempt)))
      return ACTIONS_RETRY_HELP['previous-attempt'];
    const old=s.operation;
    if(old&&['retry','reconcile'].includes(old.kind)&&old.effect!=='not-sent'&&inContext(old.target,c)&&old.target.selection?.runId===selected.id&&
      (!s.acknowledged||old.target.selection.attempt>=selected.attempt))return ACTIONS_RETRY_HELP['previous-attempt'];
    return null;
  }
  retryReason():string|null { return this.startReason() ?? (!this.currentConsent()?'Review this exact failed run first.':!this.state.confirmed?'Confirm the exact run and workflow-effects warning below.':null); }
  pendingReason(): string | null { return this.startReason() ?? (this.currentConsent() ? 'Close this review before checking previous attempts.' : null); }
  reconcileReason(marker: string): string | null {
    return this.pendingReason() ?? (this.original?.status?.pending.filter((p) => p.prepared.target.selection?.marker === marker &&
      !!context(this.connection()) && inContext(p.prepared.target, context(this.connection())!)).length === 1 ? null : 'Load this repository’s saved attempt first.');
  }
  private begin(kind: ActionsRetryKind, marker: string | null,
    invoke: (port: ActionsRetryPort, attempt: Attempt, connectionRevision: number) => Promise<unknown>): void {
    if (kind === 'prepare' ? this.prepareReason() : kind === 'retry' ? this.retryReason() :
      kind === 'pending' ? this.pendingReason() : this.reconcileReason(marker!)) return;
    const source = this.connection(), o = this.original, c = context(source), s = o?.status, epoch = this.epoch, consent = this.currentConsent(), approval=this.approval;
    if (!o || !c || !s || !source.status || kind === 'retry' && (!consent || !this.state.confirmed)) return;
    const connectionRevision = source.status.revision;
    const picked=kind==='prepare'?this.selectedRun():kind==='retry'?this.review?.picked??null:null;
    if(kind==='prepare'&&!picked)return;
    // Latch without notifying until the Attempt also exists. A listener cannot
    // observe a half-owned request and sneak in a second native admission.
    const w: Work = { owner: o, kind: 'start', ended: false, promise:null }; this.work.add(w);
    const a: Attempt = { owner: o, work: w, context: c, epoch, kind, picked, target:kind==='retry'?consent?.prepared.target??null:kind==='reconcile'?s.pending.find(p=>p.prepared.target.selection?.marker===marker)?.prepared.target??null:null,
      revision: s.revision, previousId: s.operation?.id ?? null, operationId: null, marker, sent: false, replyOk: false, stopWanted: false, stopSent: false,
      consent: kind === 'retry' ? consent : null };
    this.attempt = a; this.review = null; this.operationRecords=null; this.operationRecord=null; this.update({ confirmed: false, error: null, originalRepository: c.repository });
    const peer = this.peer();
    if (this.attempt !== a || a.stopWanted || kind==='retry'&&approval!==this.approval || kind==='prepare'&&!samePicked(a.picked,this.selectedRun()) || this.epoch !== epoch || o !== this.original || o.port !== this.desired || this.disposed ||
      this.unknown || o.status !== s || !o.fresh || peer ||
      !same(c, context(this.connection())) || connectionRevision !== this.connection().status?.revision) {
      this.attempt = null; this.update({ error: a.stopWanted?'cancelled':'target-changed' }); this.finish(w); return;
    }
    a.sent = true;
    const failed = (error: unknown, sync: boolean) => {
      const parsed = actionsRetryError(error);
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
      expectedRevision: a.revision, expectedConnectionRevision, activityRevision:a.picked!.revision,
      runId:a.picked!.observation.data.kind==='workflow-run'?a.picked!.observation.data.run.id:'',
      attempt:a.picked!.observation.data.kind==='workflow-run'?a.picked!.observation.data.run.attempt:0 }));
  }
  retry(): void {
    if (this.retryReason()) return;
    const review = this.currentConsent()!;
    this.begin('retry', review.prepared.target.selection!.marker, (port, a) => port.start({ sessionId: a.context.sessionId,
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
  canDiscard(): boolean { return !this.operationDelegate && !!this.original?.live && this.original.fresh && !!this.original.status?.consent && !this.attempt &&
    ![...this.work].some((w) => ['start', 'discard'].includes(w.kind)) && this.original.status.operation?.phase === 'settled' && !this.unknown; }
  discardReview(): void {
    if (!this.canDiscard()) return;
    const o = this.original!, s = o.status!, consent = s.consent!;
    this.review = null; this.epoch = {}; this.state = immutable({ ...this.state, confirmed: false });
    const w = this.latch(o, 'discard');
    const failed = (error: unknown, sync: boolean) => {
      const parsed = actionsRetryError(error);
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
  agentSelection(kind?:GithubOperationKind):GithubActionSelection|null {
    if(kind)return this.operationSelection(kind);
    const r=this.review,s=this.original?.status;
    return !this.operationDelegate&&!this.delegated&&!this.attempt&&!this.work.size&&!this.state.uncertain&&r&&s&&this.currentConsent()===r.consent&&s.sessionId?
      Object.freeze({kind:'failed-jobs-retry',sessionId:s.sessionId,consentId:r.consent.id,expectedRevision:s.revision}):null;
  }
  agentSelected(selection:GithubActionSelection):boolean {
    if(isGithubOperationKind(selection.kind))return this.operationDelegate?sameGithubActionSelection(this.operationDelegate.selection,selection)&&this.operationCurrent(this.operationDelegate):sameGithubActionSelection(this.operationSelection(selection.kind),selection);
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
    if(isGithubOperationKind(selection.kind))return this.delegateOperation(selection);
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
    if(final?.settlement==='settled'&&!final.neverAdmitted){if(op.kind!=='retry'||op.id!==final.operationId)return;}
    else if(d.unused||final?.neverAdmitted){if(op.kind!=='prepare'||op.id!==d.prepareId||s.revision<d.selection.expectedRevision)return;}
    else return;
    d.released=true;this.delegated=null;this.review=null;this.epoch={};
  }

  // These nine inputs use the SAME original native controller. The relay owns
  // their native invocation; neither a status event nor a synthetic Prepare
  // promise can mint the private continuation below.
  private recordForAgent(marker:string):ActionsRetryPending|null {
    if(this.operationDelegate||this.delegated||this.attempt||this.work.size||this.unknown||this.disposed)return null;
    const rr=this.operationRecords,o=this.original,c=context(this.connection()),s=o?.status;
    if(!rr||!o||!c||!s||rr.owner!==o||rr.epoch!==this.epoch||!same(rr.context,c)||rr.status.operation?.id!==s.operation?.id||!same(rr.status.pending,s.pending))return null;
    const row=rr.status.pending.find(r=>r.prepared.target.selection?.marker===marker);
    return row&&inContext(row.prepared.target,c)?row:null;
  }
  canSelectRecordForAgent(marker:string):boolean {return this.recordForAgent(marker)!==null;}
  selectRecordForAgent(marker:string):boolean {
    const row=this.recordForAgent(marker);if(!row)return false;
    this.operationRecord=row;this.update();return true;
  }
  private operationSelection(kind:GithubOperationKind):GithubOperationSelection|null {
    if(!['failed-jobs-prepare','failed-jobs-pending','failed-jobs-reconcile'].includes(kind)||this.operationDelegate||this.delegated||this.attempt||this.work.size||this.unknown||this.disposed)return null;
    const c=context(this.connection()),o=this.original,s=o?.status,connectionRevision=this.connection().status?.revision;
    if(!c||!o?.live||o.port!==this.desired||!s||!o.fresh||s.sessionId!==c.sessionId||connectionRevision===undefined)return null;
    if(kind==='failed-jobs-prepare'?this.prepareReason():this.pendingReason())return null;
    const base={kind,sessionId:c.sessionId,expectedRevision:s.revision};
    if(kind==='failed-jobs-prepare'){const picked=this.selectedRun(),data=picked?.observation.data;if(!picked||data?.kind!=='workflow-run')return null;return parseGithubOperationSelection({...base,expectedConnectionRevision:connectionRevision,activityRevision:picked.revision,runId:data.run.id,attempt:data.run.attempt});}
    if(kind==='failed-jobs-pending')return parseGithubOperationSelection({...base,expectedConnectionRevision:connectionRevision});
    const rr=this.operationRecords,row=this.operationRecord;
    if(!rr||!row||rr.owner!==o||rr.epoch!==this.epoch||!same(rr.context,c)||rr.status.operation?.id!==s.operation?.id||!same(rr.status.pending,s.pending)||!rr.status.pending.includes(row)||!inContext(row.prepared.target,c))return null;
    return parseGithubOperationSelection({...base,marker:githubOperationRecord(row).marker});
  }
  private operationCurrent(d:OperationDelegated):boolean {
    if(this.operationDelegate!==d||d.unknown||this.unknown||this.disposed||this.delegated||this.attempt||this.work.size||this.state.uncertain||
      d.owner!==this.original||!d.owner.live||d.owner.port!==this.desired||!d.owner.fresh||d.epoch!==this.epoch||!same(d.context,context(this.connection()))||
      d.owner.status?.revision!==d.selection.expectedRevision||d.owner.status.consent||'expectedConnectionRevision'in d.selection&&this.connection().status?.revision!==d.selection.expectedConnectionRevision)return false;
    if(!(d.selection.kind!=='failed-jobs-prepare'||samePicked(d.picked,this.selectedRun())))return false;
    return !('marker'in d.selection)||this.operationRecord===d.record;
  }
  private delegateOperation(raw:GithubActionSelection):GithubActionDelegate|null {
    if(!isGithubOperationKind(raw.kind))return null;
    const selected=this.operationSelection(raw.kind);if(!selected||!sameGithubActionSelection(selected,raw))return null;
    const o=this.original!,d:OperationDelegated={owner:o,context:context(this.connection())!,epoch:this.epoch,selection:selected,previousId:o.status?.operation?.id??null,record:this.operationRecord,picked:this.selectedRun(),
      allowed:false,unused:false,noAllow:false,terminal:null,unknown:false,released:false};
    this.operationDelegate=d;this.update({confirmed:false});
    const uncertain=()=>{d.unknown=true;this.fail('cleanup-unknown');};
    return Object.freeze({current:()=>this.operationCurrent(d),released:()=>d.released,
      allowReturned:()=>{if(this.operationDelegate===d&&!d.unknown){d.allowed=true;this.update();}},
      observe:(raw:GithubActionStatus)=>{if(this.operationDelegate!==d||d.unknown)return;const f=parseGithubActionStatus(raw);
        if(!f||!sameGithubActionSelection(f.review,d.selection)||f.settlement==='unknown'){uncertain();return;}
        if(f.settlement==='settled'){d.terminal=f;this.checkStatus();}
      },
      unusedReturned:()=>{if(this.operationDelegate===d&&!d.unknown){d.unused=true;this.checkStatus();}},
      notSubmitted:()=>{if(this.operationDelegate===d&&!d.unknown){d.noAllow=true;d.unused=true;this.checkStatus();}},uncertain});
  }
  private settleOperation(w:Work):void {
    const check=w.operationCheck,d=check?.delegate,s=check?.status,f=check?.terminal;
    if(!check||!d||this.operationDelegate!==d||!w.ended||!s||d.unknown||this.unknown||!(check.allowed||check.noAllow)||this.attempt||this.work.size||
      d.owner!==this.original||!d.owner.live||!same(s,d.owner.status)||s.sessionId!==d.selection.sessionId||s.reason==='cleanup-unknown'||s.operation&&s.operation.phase!=='settled')return;
    let adopt=false;
    try {
      if(f?.settlement==='settled'&&!f.neverAdmitted){
        const op=s.operation,kind=d.selection.kind.slice('failed-jobs-'.length);
        if(!op||op.id!==f.operationId||op.id===d.previousId||op.kind!==kind||op.projectId!==d.context.projectId||op.effect!==f.effect||!inContext(op.target,d.context))return;
        if('marker'in d.selection&&(!d.record||!('recordSha256'in f.review)||f.review.recordSha256!==githubOperationRecordHash(d.record)||!same(op.target,d.record.prepared.target)))return;
        const result=f.result;
        if(f.state==='complete'){
          if(op.reason!=='none'||!result||result.type!=='operation')return;
          if(d.selection.kind==='failed-jobs-prepare'){
            if(result.phase!=='prepared')return;
            // A known expired/withdrawn Prepared cannot mint a new review, but
            // the exact completed producer and original Status may still retire.
            if(s.consent){const p=s.consent.prepared;if(result.consentId!==s.consent.id||result.preparedSha256!==githubOperationPreparedHash(p)||!d.picked||!sameSelection(p.target,d.picked))return;adopt=true;}
          }else if(d.selection.kind==='failed-jobs-pending'){
            if(s.consent||result.phase!=='pending'||!same(result.rows,s.pending.map(githubOperationRecord)))return;
          }else if(s.consent||result.phase!=='reconciled'||!('marker'in d.selection)||result.marker!==d.selection.marker||result.effect!==op.effect||!same(result.observed,s.observed?{target:'failed-jobs',runId:s.observed.id,attempt:s.observed.attempt}:null))return;
        }else if(result){
          if(result.type!=='operation'||result.phase!=='reconciled'||!('marker'in d.selection)||result.marker!==d.selection.marker||result.effect!==op.effect||!same(result.observed,s.observed?{target:'failed-jobs',runId:s.observed.id,attempt:s.observed.attempt}:null))return;
        }
      }else if(check.unused||f?.neverAdmitted){if((s.operation?.id??null)!==d.previousId||s.revision<d.selection.expectedRevision||s.consent)return;}
      else return;
    }catch{d.unknown=true;this.fail('response-invalid');return;}
    d.released=true;this.operationDelegate=null;this.review=null;this.operationRecord=null;
    const current=d.epoch===this.epoch&&d.owner.port===this.desired&&!this.disposed&&same(d.context,context(this.connection()))&&(d.selection.kind!=='failed-jobs-prepare'||samePicked(d.picked,this.selectedRun()));
    if(current&&adopt&&s.consent)this.review={owner:d.owner,context:d.context,epoch:d.epoch,consent:s.consent,picked:d.picked!};
    if(current&&f?.state==='complete'&&d.selection.kind==='failed-jobs-pending')this.operationRecords={owner:d.owner,context:d.context,epoch:d.epoch,status:s};
    this.update({confirmed:false});
  }
  dispose(): void { this.disposed = true; this.desired = null; this.invalidate(); this.maintain(); }
}
