// One App-retained facet of GitHubWorkflowEditController. This retains only
// comparison DATA and original promises; it never owns a second file writer.
import { sameJson } from './catalog.ts';
import { currentWorkflowApplyBinding, workflowContextMatches, workflowPreparedMatches } from './githubWorkflowEdit.ts';
import type { WorkflowApplyBinding, GitHubWorkflowEditState } from './githubWorkflowEdit.ts';
import type { ProjectSession } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { DesktopApi, JsonValue } from './types.ts';
import type { GitHubWorkflowEditProjection } from './githubWorkflowEditTypes.ts';
import { WORKFLOW_EDIT_CONSENT, freezeWorkflowEditData, parseWorkflowEditAgentStatus, sameWorkflowEditOrigin } from './serviceWorkflowEditProtocol.ts';
import type { WorkflowEditAgentApi, WorkflowEditAgentRequest, WorkflowEditAgentStatus, WorkflowEditOrigin } from './serviceWorkflowEditProtocol.ts';

interface Context {
  native(): GitHubWorkflowEditState;
  project(): ProjectSession | null;
  setup(): GitHubSetupState;
  startReason(): string | null;
  linked(origin: WorkflowEditOrigin): boolean;
  callsPending(): boolean;
  checkNative(): Promise<boolean>;
  open(origin: WorkflowEditOrigin, project: ProjectSession, current: () => boolean): Promise<boolean>;
  prepare(origin: WorkflowEditOrigin, current: () => boolean): Promise<boolean>;
  apply(origin: WorkflowEditOrigin, binding: WorkflowApplyBinding, current: () => boolean, claimed: () => void): Promise<boolean>;
  close(origin: WorkflowEditOrigin): void;
}
interface Hold {
  api: WorkflowEditAgentApi; request: WorkflowEditAgentRequest; project: ProjectSession;
  window: string; setup: readonly [number, number, number, string, string]; end: number;
  openStarted: boolean; openReturned: boolean; prepareStarted: boolean; prepareReturned: boolean;
  applyStarted: boolean; applyReturned: boolean; submitted: boolean;
  allowSpent: boolean; allowReturned: boolean; revoked: boolean; completed: boolean;
}
interface Checked {
  hold: Hold; request: WorkflowEditAgentRequest;
  prepared: NonNullable<GitHubWorkflowEditProjection['prepared']>;
}
interface Work { promise: Promise<void>; start: number }
export interface WorkflowEditServiceState {
  status: WorkflowEditAgentStatus | null;
  pending: 'check' | 'open' | 'prepare' | 'allow' | 'apply' | null;
  revokePending: boolean; checked: boolean; acknowledged: boolean; unknown: boolean; message: string | null;
}
const equal = (a: unknown, b: unknown) => sameJson(a as JsonValue, b as JsonValue);
const key = (q: WorkflowEditOrigin) => `${q.serviceInstance}/${q.projectId}/${q.requestId}`;
const withoutClock = (r: WorkflowEditAgentRequest) => ({...r, remainingMs: 0, permissionAvailable: false});

export class ServiceWorkflowEditController {
  private api: WorkflowEditAgentApi | null = null;
  private desktop: DesktopApi | null = null;
  private unlisten: (() => void) | null = null;
  private hold: Hold | null = null;
  private control: Work | null = null;
  private step: Work | null = null;
  private stopping: Work | null = null;
  private checked: Checked | null = null;
  private acknowledged: Checked | null = null;
  private approved: Checked | null = null;
  private observedEnd: {origin: string; end: number} | null = null;
  private seen = new Set<string>(); // Same native Book32, never evict/replay.
  private listeners = new Set<() => void>();
  private processing = false;
  private again = false;
  private disposed = false;
  private state: WorkflowEditServiceState = {status: null, pending: null, revokePending: false, checked: false, acknowledged: false, unknown: false, message: null};
  private readonly context: Context;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): WorkflowEditServiceState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<WorkflowEditServiceState>): void {
    if (this.disposed) return;
    this.state = Object.freeze({...this.state, ...patch});
    for (const fn of this.listeners) fn();
  }
  private clearCheck(): void { this.checked = null; this.acknowledged = null; }
  private fail(message: string): void {
    this.clearCheck();
    if (!this.state.unknown) this.update({unknown: true, checked: false, acknowledged: false, message});
  }
  busyReason(): string | null {
    return this.state.unknown || this.hold && !this.hold.completed || this.step || this.stopping || this.control && this.hold
      ? 'The original CLI workflow-edit request or its actual callers are still retained. Check or stop that same request.' : null;
  }
  retainsDraft(projectId: string): boolean { return this.hold?.project.project.id === projectId && this.busyReason() !== null; }
  isLinked(): boolean { return !!this.hold && this.context.linked(this.hold.request.origin); }
  mayComplete(): boolean {
    return this.isLinked() && this.hold?.completed === true && !this.state.unknown &&
      !this.control && !this.step && !this.stopping && !this.context.callsPending();
  }
  completedWithoutOriginal(): boolean { return this.mayComplete() && this.hold?.request.original === null; }
  callerFailed(): void { this.fail('An original native invoke did not return. Status or terminal events cannot replace that caller.'); }

  async connect(desktop: DesktopApi): Promise<void> {
    if (this.disposed || this.desktop || desktop.mode !== 'native' || !desktop.agentWorkflowEdit) return;
    this.desktop = desktop; this.api = desktop.agentWorkflowEdit;
    await this.check();
  }
  private current(h: Hold): boolean {
    const s = this.context.setup(), n = this.context.native();
    return !this.disposed && this.hold === h && this.api === h.api && this.desktop?.agentWorkflowEdit === h.api && !h.revoked && !h.completed && !this.state.unknown &&
      !h.request.cancelRequested && performance.now() < h.end && this.context.project() === h.project && n.status?.windowGeneration === h.window && !n.generationLost &&
      equal(h.setup, [s.serviceGeneration,s.selectionGeneration,s.coordinateGeneration,s.inputs.toolingRepository,s.inputs.toolingSha]) &&
      (!this.context.linked(h.request.origin) || !!n.attempt && workflowContextMatches(n.attempt.binding,h.project,s));
  }
  private retain(h: Hold, r: WorkflowEditAgentRequest, at: number): boolean {
    const p = h.request;
    if (!sameWorkflowEditOrigin(p.origin,r.origin)) return false;
    if (r.revision < p.revision) return true;
    if (r.runtimeProjectId !== p.runtimeProjectId || p.original && !equal(p.original,r.original) || p.review && !equal(p.review,r.review) ||
        p.permissionConsumed && !r.permissionConsumed || p.cancelRequested && !r.cancelRequested ||
        ['final','unknown'].includes(p.phase) && (p.phase !== r.phase || !equal(p.result,r.result)) ||
        r.revision === p.revision && !equal(withoutClock(p),withoutClock(r))) {
      this.fail('The original workflow status contradicted its retained source, review or finality.'); return false;
    }
    h.end = Math.min(h.end, at + r.remainingMs);
    h.request = freezeWorkflowEditData({...r, remainingMs: Math.min(p.remainingMs,r.remainingMs), permissionAvailable:r.permissionAvailable && (r.revision!==p.revision || p.permissionAvailable)});
    if (r.phase === 'unknown') this.fail('The original workflow or its cleanup is unknown. Never repeat Apply.');
    if (this.checked && this.checked.request.revision !== r.revision) { this.clearCheck(); }
    return true;
  }
  private receive(value: unknown, at = performance.now(), expected?: WorkflowEditOrigin): boolean {
    if (this.disposed) return false;
    const s = parseWorkflowEditAgentStatus(value), prior = this.state.status;
    if (!s || prior && s.serviceInstance !== prior.serviceInstance || expected && (!s.request || !sameWorkflowEditOrigin(s.request.origin,expected))) {
      this.fail('The original workflow service or request could not be confirmed.'); return false;
    }
    const h = this.hold, r = s.request;
    if (h && !h.completed) {
      // A coalesced newer origin is a hint only. A later Check reads this exact
      // original first, then latest only after all original returns resolve it.
      if (!r || !sameWorkflowEditOrigin(r.origin,h.request.origin)) return true;
      if (!this.retain(h,r,at)) return false;
      this.update({status: freezeWorkflowEditData({...s,request:h.request}), checked: !!this.checked, acknowledged: !!this.acknowledged});
    } else {
      if (r && prior?.request && sameWorkflowEditOrigin(r.origin,prior.request.origin) && r.revision < prior.request.revision) return true;
      if (r) {
        const id = key(r.origin), end = at + r.remainingMs;
        this.observedEnd = {origin:id,end:this.observedEnd?.origin === id ? Math.min(this.observedEnd.end,end) : end};
      }
      this.update({status:s});
    }
    this.process(); return true;
  }
  async check(): Promise<void> {
    const api = this.api;
    if (!api || this.disposed || this.stopping) return;
    if (this.control) return this.control.promise;
    const work: Work = {promise:Promise.resolve(),start:performance.now()}; this.control = work;
    this.clearCheck();
    work.promise = Promise.resolve().then(async () => {
      try {
        if (!this.unlisten) {
          const unlisten = await api.subscribe(v => this.receive(v));
          if (this.disposed || api !== this.api) { unlisten(); return; } this.unlisten = unlisten;
        }
        if (this.disposed || this.control !== work || api !== this.api) return;
        const old = this.hold && !this.hold.completed ? this.hold : null;
        if (!this.receive(await api.status(old?.request.origin),work.start,old?.request.origin)) return;
        if (this.disposed || this.control !== work || api !== this.api) return;
        const nativeRead = await this.context.checkNative();
        if (this.disposed || this.control !== work || api !== this.api) return;
        this.complete(true);
        if (old?.completed && !this.state.unknown) {
          // No latest discovery from null/error/Unknown/pending original DATA.
          const start = performance.now();
          if (!this.receive(await api.status(),start)) return;
          if (this.disposed || this.control !== work || api !== this.api) return;
        }
        const h = this.hold;
        if (nativeRead && h && this.reviewCurrent(h) && !h.allowSpent && !this.step && !this.context.callsPending()) {
          const prepared = this.context.native().attempt?.projection?.prepared;
          if (prepared) this.checked = {hold:h,request:h.request,prepared};
        }
      } catch {
        if (!this.hold && !this.state.status?.request) this.update({message:'Enable this project’s CLI READ access, then Check requests. Ordinary workflow remains available.'});
        else this.fail('The original Check return is unavailable. Keep its request; do not repeat Open or Apply.');
      } finally {
        if (this.control === work) { this.control = null; this.update({pending:null,checked:!!this.checked,acknowledged:false}); this.process(); }
      }
    });
    this.update({pending:'check',checked:false,acknowledged:false});
    await work.promise;
  }
  private nativeMatches(h: Hold): boolean {
    const n = this.context.native(), a = n.attempt, p = a?.projection, o = h.request.original;
    return this.context.linked(h.request.origin) && !!a && !!p && !!o && !p.recovery && p.projectId === h.request.runtimeProjectId &&
      p.sessionId === o.sessionId && p.ownerGeneration === o.ownerGeneration && p.checkout?.revision === o.revision;
  }
  private summaryMatches(h: Hold): boolean {
    const a = this.context.native().attempt, p = a?.projection?.prepared, r = h.request.review;
    if (!a || !p || !r || !this.nativeMatches(h) || !workflowPreparedMatches(a)) return false;
    const v=p.view;
    const summaries=v.files.map(f=>({id:f.id,action:f.action,observed:f.observed.state==='absent'?null:{byteLength:f.observed.byteLength,sha256:f.observed.sha256},generated:{byteLength:f.generated.byteLength,sha256:f.generated.sha256}}));
    return p.planToken===r.planToken && p.draftRevision===r.draftRevision && p.baselineGeneration===r.baselineGeneration &&
      equal(summaries,r.files) && v.createDirectories.length===r.createdDirectories && v.templateSet.coreVersion===r.coreVersion &&
      v.templateSet.resourceVersion===r.resourceVersion && v.templateSet.resourceSha256===r.resourceSha256 && v.tooling.repository===r.toolingRepository && v.tooling.sha===r.toolingSha;
  }
  private reviewCurrent(h: Hold): boolean {
    const n = this.context.native(), r = h.request, p = n.attempt?.projection;
    return this.current(h) && h.openReturned && h.prepareReturned && r.phase === 'reviewing' && !r.cancelRequested && !r.permissionConsumed &&
      r.remainingMs > 0 && !!r.review && n.status?.statusRevision === r.review.nativeStatusRevision &&
      !!p && p.phase === 'reviewing' && p.nativeFinality === 'pending' && p.nativeReason === 'none' && p.reviewRemainingMs > 0 &&
      !!currentWorkflowApplyBinding(n) && this.summaryMatches(h);
  }
  allowReason(): string | null {
    const h = this.hold, c = this.checked;
    if (!h || !c || c.hold !== h || this.control || this.step || this.stopping || this.context.callsPending() || h.allowSpent ||
        !this.reviewCurrent(h) || h.request.revision !== c.request.revision || !equal(this.context.native().attempt?.projection?.prepared,c.prepared)) {
      return 'After the original preparation returns, Check this exact request and review the complete four-file before/after view before acknowledging Apply.';
    }
    return null;
  }
  acknowledge(value: boolean): void {
    this.acknowledged = value && this.allowReason() === null ? this.checked : null;
    this.update({acknowledged:!!this.acknowledged});
  }
  async allow(): Promise<void> {
    const c = this.acknowledged;
    if (!c || this.allowReason() !== null) return;
    const h = c.hold, r = c.request;
    if (!r.original || !r.review) return;
    h.allowSpent = true; this.approved = c; this.clearCheck();
    const work: Work = {promise:Promise.resolve(),start:performance.now()}; this.control = work;
    work.promise = Promise.resolve().then(async () => {
      try {
        // No status read or consent refresh here, including after listeners.
        if (!this.current(h) || this.control !== work || this.stopping || h.request.revision !== r.revision || !this.reviewCurrent(h)) { void this.revoke(); return; }
        const value = await h.api.allow({origin:r.origin,original:r.original!,planToken:r.review!.planToken,
          expectedNativeStatusRevision:r.review!.nativeStatusRevision,expectedRequestRevision:r.revision,consentVersion:WORKFLOW_EDIT_CONSENT});
        if (!this.receive(value,work.start,r.origin) || !this.current(h)) return;
        h.allowReturned = h.request.permissionAvailable || h.request.permissionConsumed;
        if (!h.allowReturned) void this.revoke();
      } catch { this.fail('The original Allow return is unconfirmed. Withdraw this request; do not Allow again.'); }
      finally { if (this.control === work) { this.control = null; this.update({pending:null}); this.process(); } }
    });
    this.update({pending:'allow',checked:false,acknowledged:false}); await work.promise;
  }
  async revoke(): Promise<void> {
    const h = this.hold, r = h && !h.completed ? h.request : this.state.status?.request, api = h?.api ?? this.api;
    if (!api || !r || this.disposed) return;
    if (this.stopping) return this.stopping.promise;
    if (h?.completed) return;
    if (h) h.revoked = true;
    this.clearCheck();
    const work: Work = {promise:Promise.resolve(),start:performance.now()}; this.stopping = work;
    work.promise = Promise.resolve().then(async () => {
      try { this.receive(await api.revoke(r.origin),work.start,r.origin); }
      catch { this.fail('The original STOP acknowledgement is missing. Keep the same request and cleanup evidence.'); }
      finally { if (this.stopping === work) { this.stopping = null; this.update({revokePending:false}); this.process(); } }
    });
    this.update({revokePending:true,checked:false,acknowledged:false,message:'STOP requested; waiting for the same original calls, native retirement and history.'});
    if (h && this.context.linked(r.origin)) this.context.close(r.origin);
    await work.promise;
  }
  invalidate(explicit = false): void {
    const h = this.hold;
    if (!h || h.completed || h.revoked || h.submitted && !explicit) return;
    void this.revoke();
  }
  private complete(insideCheck = false): void {
    const h = this.hold;
    if (!h || h.completed || this.state.unknown || this.step || this.stopping || this.context.callsPending() || this.control && !insideCheck || h.request.phase !== 'final') return;
    const r = h.request, result = r.result, n = this.context.native(), p = n.attempt?.projection;
    if (!result) return;
    if (!r.original) {
      const own = this.context.linked(h.request.origin) ? n.attempt : null;
      if (own?.sessionId || own?.projection || result.applySubmitted || result.effect !== 'not_started' || result.journal !== 'not_created') { this.fail('A pre-admission result cannot replace an actual native original.'); return; }
    } else {
      if (!this.nativeMatches(h) || !p || p.phase !== 'final' || p.nativeFinality !== 'settled') return;
      if (!p.coreOutcome || p.coreOutcome.resources !== 'settled' || p.coreOutcome.effect !== result.effect || p.coreOutcome.journal !== result.journal ||
          p.applySubmitted !== result.applySubmitted || (p.nativeReason !== 'none') !== result.cancelled || r.review && !this.summaryMatches(h)) {
        this.fail('The native and service return facts disagree. No workflow success is inferred.'); return;
      }
    }
    h.completed = true; this.clearCheck();
    this.update({checked:false,acknowledged:false,message:'The original request and callers settled. Your draft is retained; saved-file refresh and recovery remain separate.'});
  }
  process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.again = true; return; }
    this.processing = true;
    try { do {
      this.again = false;
      const held = this.hold;
      if (held && !held.completed && this.context.linked(held.request.origin)) {
        const n = this.context.native(), p = n.attempt?.projection;
        if (p?.phase === 'unknown' || p?.nativeFinality === 'unknown' || n.integrityFailed || n.nativeBlocked) this.fail('The actual native workflow original is unverified.');
        if (!held.submitted && !held.revoked && !['final','unknown'].includes(held.request.phase) && !this.current(held)) void this.revoke();
      }
      this.complete();
      if (this.control || this.step || this.stopping || this.state.unknown) continue;
      let h = this.hold; const r = this.state.status?.request;
      if (!h || h.completed) {
        if (!r || r.phase !== 'queued-open' || this.seen.has(key(r.origin)) || this.seen.size >= 32) continue;
        const project = this.context.project(), n = this.context.native(), s = this.context.setup();
        if (!project || project.project.id !== r.runtimeProjectId || !n.status || this.context.startReason() !== null || r.cancelRequested || r.remainingMs === 0) continue;
        this.seen.add(key(r.origin)); this.clearCheck(); this.approved = null;
        h = {api:this.api,request:r,project,window:n.status.windowGeneration,
          setup:[s.serviceGeneration,s.selectionGeneration,s.coordinateGeneration,s.inputs.toolingRepository,s.inputs.toolingSha],
          end:this.observedEnd?.origin === key(r.origin) ? this.observedEnd.end : performance.now(),
          openStarted:false,openReturned:false,prepareStarted:false,prepareReturned:false,applyStarted:false,applyReturned:false,submitted:false,
          allowSpent:false,allowReturned:false,revoked:false,completed:false}; this.hold = h;
      }
      // Once this original Apply is claimed, preserve its actual result despite
      // later draft changes, like the ordinary four-caller editor;
      // no later continuation needs a renewed pre-Apply draft comparison.
      if (h.revoked || h.completed || h.applyStarted) continue;
      if (!this.current(h)) { void this.revoke(); continue; }
      if (!h.openStarted && h.request.phase === 'queued-open') { this.run(h,'open'); continue; }
      if (h.openReturned && !h.prepareStarted && h.request.phase === 'opened' && this.nativeMatches(h) && this.context.native().attempt?.projection?.phase === 'editing') { this.run(h,'prepare'); continue; }
      if (h.request.phase === 'queued-apply' && !h.applyStarted && h.allowReturned && this.approved?.hold === h && this.summaryMatches(h)) this.run(h,'apply');
    } while (this.again); } finally { this.processing = false; }
  }
  private run(h: Hold, kind: 'open'|'prepare'|'apply'): void {
    if (kind === 'open') h.openStarted = true;
    else if (kind === 'prepare') h.prepareStarted = true;
    else h.applyStarted = true;
    const work: Work = {promise:Promise.resolve(),start:performance.now()}; this.step = work;
    work.promise = Promise.resolve().then(async () => {
      try {
        const current = () => this.step === work && this.current(h) && !this.stopping;
        if (!current()) { void this.revoke(); return; }
        let ok: boolean;
        if (kind === 'open') ok = await this.context.open(h.request.origin,h.project,current);
        else if (kind === 'prepare') ok = await this.context.prepare(h.request.origin,current);
        else {
          const b = currentWorkflowApplyBinding(this.context.native());
          if (!b || !this.approved || !equal(this.context.native().attempt?.projection?.prepared,this.approved.prepared)) { void this.revoke(); return; }
          ok = await this.context.apply(h.request.origin,b,current,() => { h.submitted = true; });
        }
        if (!ok) { void this.revoke(); return; }
        if (kind === 'open') h.openReturned = true;
        else if (kind === 'prepare') h.prepareReturned = true;
        else h.applyReturned = true;
      } catch { this.fail(`The original ${kind} invoke did not return a confirmed reply. No replacement or retry is allowed.`); void this.revoke(); }
      finally { if (this.step === work) { this.step = null; this.update({pending:null}); this.process(); } }
    });
    this.update({pending:kind});
  }
  dispose(): void {
    if (this.disposed) return;
    this.invalidate(true); this.disposed = true;
    try { this.unlisten?.(); } catch { /* Observer closure is not native retirement. */ }
    this.unlisten = null; this.listeners.clear();
  }
}
