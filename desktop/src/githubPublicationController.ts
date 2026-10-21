import { COUNTER_BRANCH, COUNTER_PURPOSE, counterPrepared, counterSummary, counterSourceMatches, publicationPurpose, sameCounterSaved, type CounterSavedWitness, type PublicationPurpose, type CounterSummary } from './versionCounterSetup.ts';
// Coordinates the original native publication only: no token, HTTP, polling,
// write retry, local Git mutation or renderer-created consent.
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { PUBLICATION_HELP, publicationError, parsePublicationStatus } from './githubPublicationProtocol.ts';
import { githubPreflightBranch as branch } from './githubPreflightProtocol.ts';
import type { PublicationApi, PublicationConsent, PublicationReason, PublicationKind, PublicationStatus, PublicationView } from './githubPublicationTypes.ts';
type Port = PublicationApi & { mode: 'native' | 'preview' | 'unavailable' };
type Context = { documentId: string; projectId: string; projectGeneration: number; repository: string; sessionId: string; accountId: string; repositoryId: string };
type Observer = { api: Port; active: boolean; unlisten: (() => void) | null; ready: Promise<void> | null; reading: Promise<void> | null; accepted: PublicationStatus | null };
type Pending = { observer: Observer; context: Context; epoch: object; base: string; marker: string | null; kind: PublicationKind;
  revision: number; previousId: string | null; operationId: string | null; sent: boolean; cancelAfterAdmission: boolean; cancelRequested: boolean; returned: boolean; requiresRead: boolean; purpose: PublicationPurpose; saved: CounterSavedWitness | null; counterRecord: CounterSummary | null; reviewed: PublicationConsent | null };
type Review = { observer: Observer; context: Context; epoch: object; saved: CounterSavedWitness | null; consent: PublicationConsent };
type Discard = { observer: Observer; session: string; consent: string; revision: number };
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); } return value;
}
function context(view: GitHubConnectionViewState): Context | null {
  const c = view.context, s = view.status, session = s?.session;
  if (!c || !session || view.mode !== 'native' || view.retirementPending || view.uncertain || view.blocked || view.busy ||
      session.state !== 'connected' || session.projectId !== c.projectId || session.targetRepository !== c.repository ||
      s.account.state !== 'observed' || !s.account.value || s.repository.state !== 'observed' || !s.repository.value ||
      s.repository.value.fullName.toLowerCase() !== c.repository.toLowerCase()) return null;
  return { ...c, repository: s.repository.value.fullName, sessionId: session.id, accountId: s.account.value.id, repositoryId: s.repository.value.id };
}
function inContext(consent: PublicationConsent, c: Context, base: string): boolean {
  const t = consent.prepared.target;
  return t.repository === c.repository && t.accountId === c.accountId && t.repositoryId === c.repositoryId && t.base === base;
}
function seenPullMatches(repository: string, s: PublicationStatus): boolean {
  return s.pull !== null && s.pull.url === `https://github.com/${repository}/pull/${s.pull.number}`;
}
function progress(old: PublicationStatus, next: PublicationStatus): boolean {
  if (old.revision === next.revision) return same(old, next);
  if (old.revision > next.revision || old.reason === 'cleanup-unknown' || old.operation?.phase === 'cleanup-unknown') return false;
  const a = old.operation, b = next.operation;
  if (a && b?.id === a.id) {
    if (a.kind !== b.kind || a.purpose !== b.purpose || a.phase === 'settled' && !same(a, b) || a.phase === 'stopping' && b.phase === 'running' ||
        a.effect === 'potentially-applied' && b.phase !== 'settled' && b.effect !== 'potentially-applied') return false;
  } else if (a && a.phase !== 'settled') return false;
  if (old.consent && next.consent && old.sessionId === next.sessionId && old.consent.id === next.consent.id && !same(old.consent, next.consent)) return false;
  return true;
}
export class GitHubPublicationController {
  private state: PublicationView = freeze({ mode: 'unavailable', status: null, base: '', purpose: 'setup-pr', originalTarget: null, confirmed: false,
    pending: false, observing: false, cancelling: false, discarding: false, uncertain: false, error: null });
  private listeners = new Set<() => void>();
  private api: Port | null = null;
  private observer: Observer | null = null;
  private current: Context | null = null;
  private epoch: object = {};
  private pending: Pending | null = null;
  private review: Review | null = null;
  private discard: Discard | null = null;
  private retired: { observer: Observer; session: string; consent: string } | null = null;
  private discardUnknown = false;
  private blocked = false;
  private disposed = false;
  private cancelId: string | null = null;
  private cancelObserver: Observer | null = null;
  private connection: () => GitHubConnectionViewState;
  private counterSource: () => CounterSavedWitness | null;
  private otherOperationReason: () => string | null;
  constructor(connection: () => GitHubConnectionViewState, otherOperationReason: () => string | null = () => null,
    counterSource: () => CounterSavedWitness | null = () => null) { this.connection = connection; this.otherOperationReason = otherOperationReason; this.counterSource = counterSource; }
  getSnapshot = (): PublicationView => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private update(patch: Partial<PublicationView>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); this.listeners.forEach((fn) => fn());
  }
  private invalidate(patch: Partial<PublicationView> = {}): void {
    this.epoch = {}; this.review = null;
    if (this.pending && !this.pending.sent) { this.pending = null; patch.pending = false; }
    else if (this.pending) this.pending.cancelAfterAdmission = true;
    this.update({ confirmed: false, ...patch }); this.stopInvalidatedOriginal(); this.retireConsent();
  }
  private stopInvalidatedOriginal(): void {
    const p = this.pending, op = p?.observer.accepted?.operation;
    // The private start/returned-status correlation, not an arbitrary visible ID,
    // must identify THIS controller's original. One automatic stop per original.
    if (!p || !p.cancelAfterAdmission || p.cancelRequested || !p.operationId || p.observer !== this.observer ||
        !op || op.id !== p.operationId || op.phase === 'settled' || this.cancelObserver) return;
    this.cancel();
  }
  // Called before reducer changes, including failed/unchanged edit attempts.
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate({ error: 'target-changed' }); }
  // Input-read intent is a separate counter-source epoch, never a new owner or
  // an automatic read/retry. Ordinary five-file reviews are unaffected.
  versionIntent(): void { if (!this.disposed && (this.state.purpose === COUNTER_PURPOSE || this.pending?.purpose === COUNTER_PURPOSE || this.review?.saved)) this.invalidate({ error: 'source-changed' }); }
  syncCounterSource = (): void => {
    const saved = this.pending?.saved ?? this.review?.saved;
    if (!this.disposed && saved && !sameCounterSaved(saved, this.counterSource())) this.versionIntent();
  };
  setPurpose(purpose: PublicationPurpose): void {
    if (!this.disposed && (purpose === 'setup-pr' || purpose === COUNTER_PURPOSE) && purpose !== this.state.purpose) this.invalidate({ purpose, error: null });
  }
  syncContext = (): void => {
    if (this.disposed) return;
    const c = context(this.connection());
    if (!same(c, this.current)) { this.current = c; this.invalidate({ base: '', error: this.pending ? 'target-changed' : null }); }
  };
  setBase(value: string): void {
    if (this.disposed || typeof value !== 'string' || value.length > 200 || value === this.state.base) return;
    this.invalidate({ base: value, error: null });
  }
  setConfirmed(value: boolean): void { this.update({ confirmed: value === true && this.currentConsent() !== null }); }
  private needsOriginal(o: Observer): boolean {
    return this.pending?.observer === o && this.pending.sent || this.cancelObserver === o || this.discard?.observer === o || this.retired?.observer === o ||
      !!o.accepted?.operation && o.accepted.operation.phase !== 'settled';
  }
  private detach(o: Observer): void {
    o.active = false; const stop = o.unlisten; o.unlisten = null; try { stop?.(); } catch { /* Listener closure is not native finality. */ }
  }
  private maintain(): Observer | null {
    if (this.observer && (this.disposed || this.observer.api !== this.api)) {
      if (this.needsOriginal(this.observer)) return this.observer;
      this.detach(this.observer); this.observer = null;
    }
    if (!this.observer && !this.disposed && this.api?.mode === 'native') {
      const o: Observer = { api: this.api, active: true, unlisten: null, ready: null, reading: null, accepted: null };
      this.observer = o; o.ready = this.monitor(o);
    }
    return this.observer;
  }
  async connect(api: Port | null): Promise<void> {
    if (this.disposed || api === this.api) return;
    this.api = api; this.syncContext(); this.invalidate({ mode: api?.mode ?? 'unavailable' }); await this.maintain()?.ready;
  }
  private async monitor(o: Observer): Promise<void> {
    try {
      const stop = await o.api.subscribeGitHubPublication((v) => { this.receive(o, v); });
      if (!o.active) { try { stop(); } catch { /* No native receipt. */ } return; }
      o.unlisten = stop; await this.read(o);
    } catch { if (o.active) this.fail('runtime-unavailable'); }
  }
  private fail(reason: PublicationReason): void { this.blocked = true; this.review = null; this.update({ uncertain: true, confirmed: false, error: reason }); }
  private origin(p: Pending, s: PublicationStatus): boolean {
    const op = s.operation;
    if (!p.sent || s.revision <= p.revision || s.sessionId !== p.context.sessionId || !op || op.kind !== p.kind || (op.purpose ?? 'setup-pr') !== p.purpose ||
        op.id === p.previousId || p.operationId !== null && op.id !== p.operationId) return false;
    if (s.consent && (p.kind !== 'prepare' || !inContext(s.consent, p.context, p.base) || publicationPurpose(s.consent.prepared) !== p.purpose || p.purpose === COUNTER_PURPOSE && (!p.saved || !counterPrepared(s.consent.prepared) || !counterSourceMatches(s.consent.prepared, p.saved)))) return false;
    if (p.kind === 'publish' && op.effect === 'draft-pr-observed' && (!p.reviewed || !seenPullMatches(p.reviewed.prepared.target.repository, s))) return false;
    if (p.kind === 'reconcile' && op.effect === 'draft-pr-observed' && !seenPullMatches(p.context.repository, s)) return false;
    if (op.effect === 'counter-observed') {
      const counter = p.reviewed && counterPrepared(p.reviewed.prepared) ? p.reviewed.prepared : p.counterRecord;
      if (!counter || !s.counter || s.counter.ledgerId !== counter.target.ledgerId || s.counter.genesisSha256 !== counter.genesisSha256) return false;
    }
    return true;
  }
  private correlate(o: Observer, seen: PublicationStatus, readAfterReturn: Pending | null = null): void {
    const p = this.pending;
    if (!p || p.observer !== o || !this.origin(p, seen)) return;
    p.operationId = seen.operation!.id;
    const s = o.accepted;
    if (!s || !this.origin(p, s)) return;
    if (s.operation!.phase === 'cleanup-unknown') { this.fail('cleanup-unknown'); this.stopInvalidatedOriginal(); return; }
    if (s.operation!.phase !== 'settled') { this.stopInvalidatedOriginal(); return; }
    // Counter actions keep this SAME invocation until its actual Promise has
    // returned. A lost acknowledgement additionally needs an explicit Status
    // call begun after that return; an earlier read/event cannot release it.
    if (p.purpose === COUNTER_PURPOSE && (!p.returned || p.requiresRead && readAfterReturn !== p)) return;
    this.pending = null;
    if (!this.blocked && p.kind === 'prepare' && s.consent && p.epoch === this.epoch && o.api === this.api &&
        same(p.context, context(this.connection())) && p.base === this.state.base && p.purpose === this.state.purpose &&
        (p.purpose !== COUNTER_PURPOSE || p.saved !== null && sameCounterSaved(p.saved, this.counterSource()))) {
      this.review = { observer: o, context: p.context, epoch: p.epoch, saved: p.saved, consent: s.consent };
    }
    this.update({ pending: false, uncertain: this.blocked, error: this.blocked ? this.state.error : s.operation!.reason === 'none' ? null : s.operation!.reason });
  }
  private receive(o: Observer, value: unknown, readAfterReturn: Pending | null = null): PublicationStatus | null {
    if (!o.active) return null;
    const parsed = parsePublicationStatus(value);
    if (!parsed) { this.fail('response-invalid'); return null; }
    const s = freeze(structuredClone(parsed)), old = o.accepted;
    const originalRepository = this.pending?.context.repository ?? this.state.originalTarget?.repository ?? context(this.connection())?.repository;
    if (s.pull && (!originalRepository || !seenPullMatches(originalRepository, s))) { this.fail('response-invalid'); return null; }
    if (s.counter && this.pending?.observer === o && s.revision > this.pending.revision && s.operation?.id !== this.pending.previousId && !this.origin(this.pending, s)) { this.fail('response-invalid'); return null; }
    if (old && s.revision < old.revision) { if (progress(s, old)) this.correlate(o, s, readAfterReturn); return s; }
    if (old && !progress(old, s)) { this.fail('response-invalid'); return null; }
    o.accepted = s;
    if (s.reason === 'cleanup-unknown' || s.operation?.phase === 'cleanup-unknown') this.fail('cleanup-unknown');
    if (this.review && (s.sessionId !== this.review.context.sessionId || !same(s.consent, this.review.consent))) {
      this.review = null; this.update({ confirmed: false });
    }
    if (this.retired?.observer === o && (this.retired.session !== s.sessionId || this.retired.consent !== s.consent?.id)) {
      this.retired = null;
      if (this.discardUnknown) { this.discardUnknown = false; this.update({ uncertain: this.blocked || this.pending !== null || this.cancelId !== null }); }
    }
    this.update({ status: s }); this.correlate(o, s, readAfterReturn);
    if (this.cancelId === s.operation?.id && s.operation.phase === 'settled') { this.cancelId = null; this.update({ uncertain: this.blocked || this.pending !== null }); }
    this.retireConsent(); this.maintain(); return s;
  }
  private async read(o: Observer): Promise<void> {
    if (!o.active || o.reading) return o.reading ?? undefined;
    const work = Promise.resolve().then(async () => {
      if (!o.active) return;
      try {
        const returnedOriginal = this.pending?.observer === o && this.pending.returned ? this.pending : null;
        this.receive(o, await o.api.githubPublicationStatus(), returnedOriginal);
      } catch { if (o.active) this.update({ error: 'response-invalid' }); }
    });
    o.reading = work; this.update({ observing: true });
    try { await work; } finally { if (o.reading === work) { o.reading = null; this.update({ observing: false }); } }
  }
  checkStatus(): Promise<void> { const o = this.maintain(); return !this.disposed && o ? this.read(o) : Promise.resolve(); }
  currentConsent(): PublicationConsent | null {
    const r = this.review, c = context(this.connection()), s = this.state.status;
    return r && !this.blocked && !this.retired && !this.discard && r.epoch === this.epoch && r.observer === this.observer && r.observer.api === this.api &&
      c && same(c, r.context) && s?.sessionId === c.sessionId && same(s.consent, r.consent) && this.state.base === r.consent.prepared.target.base && publicationPurpose(r.consent.prepared) === this.state.purpose &&
      (this.state.purpose !== COUNTER_PURPOSE || r.saved !== null && sameCounterSaved(r.saved, this.counterSource())) ? r.consent : null;
  }
  // Discard is local native grant retirement, never a remote write or retry.
  private retireConsent(): void {
    const o = this.observer, s = o?.accepted;
    if (!o || !s?.consent || !s.sessionId || s.operation?.phase !== 'settled' || this.review || this.pending || this.discard || this.retired) return;
    this.retired = { observer: o, session: s.sessionId, consent: s.consent.id }; this.sendDiscard(o, s);
  }
  private sendDiscard(o: Observer, s: PublicationStatus): void {
    if (!s.consent || !s.sessionId || this.discard) return;
    const d: Discard = { observer: o, session: s.sessionId, consent: s.consent.id, revision: s.revision };
    this.discard = d; this.update({ discarding: true, confirmed: false });
    const done = () => { if (this.discard === d) { this.discard = null; this.update({ discarding: false }); this.maintain(); } };
    const failed = () => { if (this.discard === d && this.retired) { this.discardUnknown = true; this.update({ uncertain: true, error: 'response-invalid' }); } };
    try { void o.api.githubPublicationDiscard({ sessionId: d.session, expectedRevision: d.revision, consentId: d.consent }).then((v) => {
      this.receive(o, v); if (this.retired) failed();
    }, failed).finally(done); } catch { failed(); done(); }
  }
  discardReview(): void {
    if (this.disposed) return;
    this.invalidate();
    const o = this.observer, s = o?.accepted;
    if (!this.discard && o && s?.consent && s.operation?.phase === 'settled' && this.retired) this.sendDiscard(o, s);
  }
  startReason(): string | null {
    if (this.disposed || this.state.mode !== 'native' || !this.api || this.observer?.api !== this.api) return 'A current native GitHub session is required. Browser preview never changes repository files.';
    if (this.blocked || this.state.uncertain) return 'Original acknowledgement or cleanup is unconfirmed. Read local Status; do not repeat Publish.';
    if (this.pending || this.discard || this.retired || this.state.cancelling || this.state.status?.operation && this.state.status.operation.phase !== 'settled') return 'Wait for the original action or consent retirement. Status and Stop original remain available.';
    const c = context(this.connection()), s = this.state.status;
    if (!c || !s || !this.observer?.accepted || s.sessionId !== c.sessionId) return 'Connect the selected project’s repository and read local Status first.';
    if (s.consent && !this.currentConsent()) return 'The previous native consent must be retired before another operation.';
    if (!s.available) return PUBLICATION_HELP[s.reason];
    return this.otherOperationReason();
  }
  prepareReason(): string | null { return this.startReason() ?? (this.state.purpose === COUNTER_PURPOSE && (!this.counterSource() || this.state.base === COUNTER_BRANCH) ? 'Read current saved inputs and choose an existing source branch, not the counter branch. Saved numeric versions are DATA, never a Store floor.' : !branch(this.state.base) ? 'Choose the exact existing GitHub base branch.' : this.currentConsent() ? 'Publish or discard this exact review before preparing another.' : null); }
  publishReason(): string | null { return this.startReason() ?? (!this.currentConsent() ? this.state.purpose === COUNTER_PURPOSE ? 'Prepare and review the exact first counter before Create.' : 'Prepare and review these exact five files first.' : !this.state.confirmed ? 'Explicitly confirm this one exact before/after change.' : null); }
  pendingReason(): string | null { return this.startReason() ?? (this.currentConsent() ? 'Discard the current review before loading original intents.' : null); }
  reconcileReason(marker: string): string | null { return this.pendingReason() ?? (this.state.status?.pending.filter((v) => v.summary.target.marker === marker && v.summary.target.repository === this.current?.repository && v.summary.target.accountId === this.current?.accountId && v.summary.target.repositoryId === this.current?.repositoryId).length === 1 ? null : 'Load the original intent for this repository first.'); }
  private begin(kind: PublicationKind, marker: string | null, invoke: (api: Port, c: Context, revision: number) => Promise<PublicationStatus>): void {
    if (this.startReason()) return;
    const o = this.observer!, c = context(this.connection())!, s = this.state.status!, base = this.state.base;
    const selectedRecord = kind === 'reconcile' ? s.pending.find((v) => v.summary.target.marker === marker)?.summary : null;
    const purpose = kind === 'pending' ? 'setup-pr' : selectedRecord ? publicationPurpose(selectedRecord) : this.state.purpose;
    const saved = purpose === COUNTER_PURPOSE && (kind === 'prepare' || kind === 'publish') ? this.counterSource() : null;
    if (purpose === COUNTER_PURPOSE && (kind === 'prepare' || kind === 'publish') && !saved) return;
    const p: Pending = { observer: o, context: c, epoch: this.epoch, base, marker, kind, revision: s.revision,
      previousId: s.operation?.id ?? null, operationId: null, sent: false, cancelAfterAdmission: false, cancelRequested: false, returned: false, requiresRead: false, purpose, saved, counterRecord: counterSummary(selectedRecord) ? selectedRecord : null, reviewed: this.currentConsent() };
    this.pending = p; this.review = null; this.update({ pending: true, confirmed: false, error: null,
      originalTarget: { repository: c.repository, accountId: c.accountId, repositoryId: c.repositoryId, base } });
    const nextContext = context(this.connection()), peer = this.otherOperationReason(), nextSaved = p.saved ? this.counterSource() : null;
    if (this.disposed || this.pending !== p || p.epoch !== this.epoch || o.api !== this.api || !same(c, nextContext) || peer || p.saved !== null && !sameCounterSaved(p.saved, nextSaved)) {
      if (this.pending === p) { this.pending = null; this.update({ pending: false, error: 'target-changed' }); this.retireConsent(); } return;
    }
    p.sent = true;
    const failed = (error: unknown) => {
      p.returned = true;
      if (this.pending !== p) return;
      const e = publicationError(error);
      if (e.admission === 'not-admitted' && p.operationId === null && !this.blocked && (p.purpose !== COUNTER_PURPOSE || e.reason !== 'cleanup-unknown')) {
        this.pending = null; this.update({ pending: false, error: e.reason }); this.retireConsent(); this.maintain();
      } else { p.requiresRead = true; this.update({ uncertain: true, error: e.reason }); }
    };
    try { void invoke(o.api, c, s.revision).then((v) => {
      p.returned = true;
      const accepted = this.receive(o, v);
      if (this.pending === p && (!accepted || p.operationId === null)) this.update({ uncertain: true, error: 'response-invalid' });
    }, failed); } catch (e) { failed(e); }
  }
  prepare(): void {
    if (this.prepareReason()) return;
    const base = this.state.base, purpose = this.state.purpose, connectionRevision = this.connection().status!.revision;
    this.begin('prepare', null, (api, c, revision) => api.githubPublicationPrepare({ sessionId: c.sessionId, expectedRevision: revision, expectedConnectionRevision: connectionRevision, base, ...(purpose === COUNTER_PURPOSE ? { purpose } : {}) }));
  }
  publish(): void {
    if (this.publishReason()) return;
    const consent = this.currentConsent()!;
    this.begin('publish', consent.prepared.target.marker, (api, c, revision) => api.githubPublicationPublish({ sessionId: c.sessionId, expectedRevision: revision, consentId: consent.id, confirm: true }));
  }
  loadPending(): void {
    if (this.pendingReason()) return;
    const connectionRevision = this.connection().status!.revision;
    this.begin('pending', null, (api, c, revision) => api.githubPublicationPending({ sessionId: c.sessionId, expectedRevision: revision, expectedConnectionRevision: connectionRevision }));
  }
  reconcile(marker: string): void {
    if (this.reconcileReason(marker)) return;
    this.begin('reconcile', marker, (api, c, revision) => api.githubPublicationReconcile({ sessionId: c.sessionId, expectedRevision: revision, marker }));
  }
  canCancel(): boolean { return !this.disposed && !this.cancelObserver && !this.state.cancelling && !!this.observer?.accepted?.operation && this.observer.accepted.operation.phase !== 'settled'; }
  cancel(): void {
    if (!this.canCancel()) return;
    const o = this.observer!, id = o.accepted!.operation!.id;
    this.cancelId = id; this.cancelObserver = o;
    if (this.pending?.observer === o && this.pending.operationId === id) this.pending.cancelRequested = true;
    this.epoch = {}; this.review = null; this.update({ cancelling: true, confirmed: false });
    const failed = () => { if (this.cancelId === id) this.update({ uncertain: true, error: 'response-invalid' }); };
    const done = () => { if (this.cancelObserver === o) { this.cancelObserver = null; this.update({ cancelling: false }); this.maintain(); } };
    try { void o.api.githubPublicationCancel(id).then((v) => { this.receive(o, v); }, failed).finally(done); }
    catch { failed(); done(); }
  }
  dispose(): void { this.disposed = true; this.invalidate(); this.listeners.clear(); this.api = null; this.maintain(); }
}
export function githubPublicationOwnerReason(state: PublicationView): string | null {
  return state.pending || state.uncertain || state.cancelling || state.discarding || state.status?.consent || state.status?.operation && state.status.operation.phase !== 'settled'
    ? 'The original setup-publication action is running or unverified. Read local Status before starting another operation.' : null;
}
