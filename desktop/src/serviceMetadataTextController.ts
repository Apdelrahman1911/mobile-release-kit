// App-retained child of the existing MetadataText controller. This owns only
// bounded correlation DATA and the actual original bridge promises, not files,
// jobs, source witnesses, cleanup receipts or a second writer.
import { sameJson } from './catalog.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import type { DesktopApi, JsonValue } from './types.ts';
import type { MetadataConfiguredContext, MetadataTextBaseline, MetadataTextDraft, MetadataTextEditStatus, NormalMetadataTextEditProjection } from './metadataText.ts';
import { metadataProjectionProgress, normalMetadataTextResult, parseMetadataTextEditStatus, parseMetadataTextObservation } from './metadataTextProtocol.ts';
import { deepFreeze } from './serviceConfigurationProtocol.ts';
import { METADATA_TEXT_CONSENT, metadataServicePreviewMatches, metadataTextSaved, parseMetadataServiceStatus } from './serviceMetadataTextProtocol.ts';
import type { MetadataOrigin, MetadataServiceApi, MetadataServiceRequest, MetadataServiceStatus, MetadataStep } from './serviceMetadataTextProtocol.ts';
export interface MetadataServiceWitness {
  session: ProjectSession; context: MetadataConfiguredContext; serviceGeneration: number; selectionGeneration: number;
  // Object identity and counters are local display fences, never source loans.
  draft: MetadataTextDraft | null; draftRevision: number; baselineGeneration: number; observationGeneration: number;
}
interface Context {
  capture(request: MetadataServiceRequest): MetadataServiceWitness | null;
  current(request: MetadataServiceRequest, witness: MetadataServiceWitness): boolean;
  native(): MetadataTextEditStatus | null;
  nativeUsable(): boolean;
  observe(value: unknown): void;
  checkNative(): Promise<void>;
  busy(value: boolean): void;
  boundary(request: MetadataServiceRequest, witness: MetadataServiceWitness): MetadataServiceWitness | null;
}
interface Work { api: MetadataServiceApi; request: MetadataServiceRequest | null; epoch: number; promise: Promise<void> }
interface Flow {
  api: MetadataServiceApi; epoch: number; witness: MetadataServiceWitness; request: MetadataServiceRequest;
  baseline: {metadataRoot: string; baseline: MetadataTextBaseline} | null;
  native: NormalMetadataTextEditProjection | null; final: MetadataServiceRequest | null;
  allowed: boolean; revoked: boolean; applyEntered: boolean; completed: boolean;
}
export interface MetadataServiceState {
  status: MetadataServiceStatus | null; pending: 'check' | 'allow' | MetadataStep | null;
  revokePending: boolean; acknowledged: boolean; unknown: boolean; message: string | null;
}
const key = (q: MetadataOrigin) => `${q.serviceInstance}/${q.projectId}/${q.requestId}`;
const equal = (a: unknown, b: unknown) => sameJson(a as JsonValue | undefined, b as JsonValue | undefined);
const terminal = (r: MetadataServiceRequest) => r.phase === 'final' || r.phase === 'refused';
const withoutClock = (r: MetadataServiceRequest) => ({...r, remainingMs: 0, permissionLive: false});
export class MetadataServiceController {
  private api: MetadataServiceApi | null = null;
  private desktop: DesktopApi | null = null;
  private disposed = false;
  private epoch = 0;
  private unlisten: (() => void) | null = null;
  private work: Work | null = null;
  private revokeWork: Work | null = null;
  private flow: Flow | null = null;
  private claims = new Set<string>(); // 32 combined native rows x four calls.
  private listeners = new Set<() => void>();
  private processing = false;
  private again = false;
  private state: MetadataServiceState = {status: null, pending: null, revokePending: false, acknowledged: false, unknown: false, message: null};
  private readonly context: Context;
  constructor(context: Context) {this.context = context;}
  getSnapshot = (): MetadataServiceState => this.state;
  subscribe = (listener: () => void): (() => void) => {this.listeners.add(listener); return () => {this.listeners.delete(listener);};};
  private update(patch: Partial<MetadataServiceState>): void {
    if (this.disposed) return;
    this.state = Object.freeze({...this.state, ...patch});
    const r = this.state.status?.request;
    this.context.busy(!!this.work || !!this.revokeWork || this.state.unknown || !!this.flow && !this.flow.completed || !!r && !terminal(r));
    for (const listener of this.listeners) listener();
  }
  private fail(message: string): void {this.update({unknown: true, acknowledged: false, message});}
  async connect(desktop: DesktopApi): Promise<void> {
    if (this.disposed || this.desktop || desktop.mode !== 'native' || !desktop.agentMetadataText) return;
    this.desktop = desktop; this.api = desktop.agentMetadataText; await this.check();
  }
  async check(): Promise<void> {
    const api = this.api; if (!api || this.disposed || this.work || this.revokeWork) return;
    const work: Work = {api, request: null, epoch: this.epoch, promise: Promise.resolve()}; this.work = work;
    work.promise = Promise.resolve().then(async () => {
      try {
        if (!this.unlisten) {
          const unlisten = await api.subscribe(v => this.receive(v));
          if (this.disposed || this.api !== api) {unlisten(); return;} this.unlisten = unlisten;
        }
        if (this.disposed || this.api !== api) return;
        this.receive(await api.status());
        const flow = this.flow;
        if (flow && !flow.completed && this.work === work && this.api === api && !this.disposed) {
          // Original final may have coalesced directly to a later queued row.
          // Query its exact ID without replacing latest or inventing retirement.
          const exact = parseMetadataServiceStatus(await api.status(flow.request.origin));
          if (this.work !== work || this.flow !== flow || this.disposed) return;
          if (!exact?.request || key(exact.request.origin) !== key(flow.request.origin) || exact.serviceInstance !== flow.request.origin.serviceInstance) {this.fail('The original text request could not be found; do not repeat it.'); return;}
          this.retain(flow, exact.request);
        }
        if (!this.disposed && this.work === work) await this.context.checkNative();
      } catch {
        if (!this.flow && this.claims.size === 0 && !this.state.status?.request) this.update({message: 'Enable the selected project’s CLI READ access, then check requests.'});
        else this.fail('The original text request is unconfirmed. Check or stop the same ID; never reload or repeat Apply automatically.');
      } finally {if (this.work === work) {this.work = null; this.update({pending: null}); this.process();}}
    });
    this.update({pending: 'check'}); await work.promise;
  }
  receive(value: unknown): void {
    if (this.disposed) return;
    let next = parseMetadataServiceStatus(value); const prior = this.state.status;
    if (!next || prior && next.serviceInstance !== prior.serviceInstance) {this.fail('The metadata service identity or closed status is unverified.'); return;}
    // Even an older event may contain the exact original final, not a newer row.
    if (next.request && this.flow && key(next.request.origin) === key(this.flow.request.origin) && !this.retain(this.flow, next.request)) return;
    if (prior && next.revision < prior.revision) return;
    if (prior && next.revision === prior.revision && !equal({...prior, request: prior.request && withoutClock(prior.request)}, {...next, request: next.request && withoutClock(next.request)})) {
      this.fail('Contradictory metadata request status. Keep the original.'); return;
    }
    const a = prior?.request, b = next.request;
    if (a && b && key(a.origin) === key(b.origin)) {
      if (b.revision < a.revision) return;
      if (!this.progress(a, b)) {this.fail('The original metadata request changed identity, preview or terminal result.'); return;}
      if (b.revision === a.revision && b.remainingMs > a.remainingMs) next = deepFreeze({...next, request: {...b, remainingMs: a.remainingMs, permissionLive: a.remainingMs > 0}});
    }
    this.update({status: next, acknowledged: a && b && key(a.origin) === key(b.origin) ? this.state.acknowledged : false});
    if (b?.phase === 'unknown') this.fail('Original cleanup or the Apply outcome is unknown. Do not repeat the operation.');
    this.process();
  }
  private progress(a: MetadataServiceRequest, b: MetadataServiceRequest): boolean {
    if (key(a.origin) !== key(b.origin) || a.runtimeProjectId !== b.runtimeProjectId || a.platform !== b.platform || a.locale !== b.locale ||
        a.original && !equal(a.original, b.original) || a.proposalSha256 && a.proposalSha256 !== b.proposalSha256 || a.review && !equal(a.review, b.review) ||
        a.applyConsumed && !b.applyConsumed || a.cancelRequested && !b.cancelRequested || terminal(a) && (a.phase !== b.phase || !equal(a.result, b.result))) return false;
    if (b.revision === a.revision && !equal(withoutClock(a), withoutClock(b))) return false;
    return true;
  }
  private retain(flow: Flow, r: MetadataServiceRequest): boolean {
    if (r.revision < flow.request.revision) return true;
    if (!this.progress(flow.request, r)) {this.fail('The retained original metadata correlation changed.'); return false;}
    flow.request = r.revision === flow.request.revision && r.remainingMs > flow.request.remainingMs
      ? deepFreeze({...r, remainingMs: flow.request.remainingMs, permissionLive: flow.request.remainingMs > 0}) : r;
    if (r.phase === 'unknown') {this.fail('The original metadata request is unknown; STOP remains separate from success.'); return false;}
    if (terminal(r)) flow.final = r;
    return true;
  }
  private current(flow: Flow, witness = flow.witness): boolean {
    return !this.disposed && this.api === flow.api && this.epoch === flow.epoch && !flow.revoked && !flow.completed &&
      this.context.current(flow.request, witness) && !isDirty(witness.session);
  }
  private captureNative(flow: Flow): void {
    const status = this.context.native(), o = flow.request.original;
    if (!status || !o) return;
    const actual = [status.active, status.lastTerminal].find((p): p is NormalMetadataTextEditProjection => !!p && !p.recovery && p.sessionId === o.sessionId && p.ownerGeneration === o.ownerGeneration && p.projectId === flow.request.runtimeProjectId && p.platform === flow.request.platform && p.locale === flow.request.locale);
    if (!actual) return;
    if (flow.native && !metadataProjectionProgress(flow.native, actual)) {this.fail('The actual native metadata owner contradicted its original result.'); return;}
    flow.native = actual;
    if (actual.phase === 'unknown' || actual.nativeFinality === 'unknown') this.fail('The actual native metadata cleanup is unknown.');
  }
  nativeChanged(): void {if (this.flow) this.captureNative(this.flow); this.process();}
  private complete(): void {
    const f = this.flow; if (!f || f.completed || this.work || this.revokeWork || this.state.unknown) return;
    this.captureNative(f);
    const r = f.final; if (!r) return;
    if (r.phase === 'refused' && !r.original && !f.native) {f.completed = true; this.update({message: 'The original request ended before an editor was opened. No save was made.'}); return;}
    const owner = f.native;
    if (!owner || owner.phase !== 'final' || owner.nativeFinality !== 'settled' || !r.result) return;
    const core = owner.coreOutcome;
    if (!core || core.resources !== 'settled' || core.effect !== r.result.effect || core.journal !== r.result.journal || r.result.cancelled !== (owner.nativeReason !== 'none') || r.result.applySubmitted !== owner.applySubmitted ||
        r.review && !metadataServicePreviewMatches(r, owner)) {this.fail('Service/native return facts disagree; no Save result is inferred.'); return;}
    f.completed = true; // Before publication/reentrant callbacks.
    const saved = f.applyEntered && metadataTextSaved(r.result) && !!normalMetadataTextResult(owner);
    this.update({message: saved ? 'The original local text save settled. Existing drafts are kept and stale; explicitly load/reconcile before another edit. Nothing was uploaded to a Store.' : 'The original ended without a confirmed ordinary Save. Keep the draft and inspect its effect/recovery status.'});
  }
  acknowledge(value: boolean): void {this.update({acknowledged: value === true && this.allowReason() === null});}
  allowReason(): string | null {
    const f = this.flow, r = this.state.status?.request;
    if (!this.api || this.disposed) return 'Open the current Desktop and enable project READ access.';
    if (this.work || this.revokeWork || this.state.unknown) return 'Wait for the original calls or stop this request; no new permission is inferred.';
    if (!f || !r || key(r.origin) !== key(f.request.origin) || !this.current(f) || f.allowed) return 'Use this same selected project/locale and current native request. Drafts and earlier consent are not reused.';
    if (r.phase !== 'reviewing' || !r.original || !r.review || r.applyConsumed || r.cancelRequested || r.permissionLive) return 'The CLI must Load and Prepare its complete text bundle first.';
    if (!this.reviewCurrent(f, r)) return 'Wait for the same complete native before/after preview. Source drift never reloads or rebases the request.';
    return null;
  }
  private reviewCurrent(f: Flow, r: MetadataServiceRequest): boolean {
    const owner = f.native, status = this.context.native();
    return r.phase === 'reviewing' && !r.applyConsumed && !r.cancelRequested && !!r.original && !!r.review &&
      this.context.nativeUsable() && !!owner && owner.phase === 'reviewing' && owner.nativeFinality === 'pending' && owner.nativeReason === 'none' && !owner.applySubmitted && owner.reviewRemainingMs > 0 &&
      status?.active?.sessionId === owner.sessionId && status.statusRevision === r.review.nativeStatusRevision && metadataServicePreviewMatches(r, owner) && !!f.baseline &&
      owner.checkout?.metadataRoot === f.baseline.metadataRoot && equal(owner.checkout.baseline, f.baseline.baseline);
  }
  async allow(): Promise<void> {
    if (!this.state.acknowledged || this.allowReason() !== null) return;
    const f = this.flow!, request = f.request, api = f.api;
    f.allowed = true; // Consumed locally before any reentrant publication/send.
    const work: Work = {api, request, epoch: this.epoch, promise: Promise.resolve()}; this.work = work;
    work.promise = Promise.resolve().then(async () => {
      try {
        if (this.work !== work || !this.current(f) || this.revokeWork || this.state.unknown) {await this.revoke(); return;}
        const live = this.state.status?.request;
        if (!live || key(live.origin) !== key(request.origin) || !this.reviewCurrent(f, live) || !request.original || !request.review ||
            !equal(live.original, request.original) || !equal(live.review, request.review)) {await this.revoke(); return;}
        this.receive(await api.allow({origin: request.origin, original: request.original, planToken: request.review.planToken, expectedNativeStatusRevision: request.review.nativeStatusRevision, consentVersion: METADATA_TEXT_CONSENT}));
      } catch {this.fail('Apply permission acknowledgement is missing. Withdraw only this original; do not Allow again.');}
      finally {if (this.work === work) {this.work = null; this.update({pending: null}); this.process();}}
    });
    this.update({pending: 'allow', acknowledged: false}); await work.promise;
  }
  async revoke(): Promise<void> {
    const f = this.flow && !this.flow.completed ? this.flow : null;
    const request = f?.request ?? this.work?.request ?? this.state.status?.request;
    const api = f?.api ?? this.work?.api ?? this.api;
    if (!api || !request || this.revokeWork) return;
    this.epoch = Math.min(Number.MAX_SAFE_INTEGER, this.epoch + 1); if (f) f.revoked = true;
    const work: Work = {api, request, epoch: this.epoch, promise: Promise.resolve()}; this.revokeWork = work;
    work.promise = Promise.resolve().then(async () => {
      try {
        const raw = await api.revoke(request.origin), exact = parseMetadataServiceStatus(raw);
        if (!exact?.request || key(exact.request.origin) !== key(request.origin)) {this.fail('Original STOP address or return is unconfirmed.'); return;}
        if (f) this.retain(f, exact.request);
        if (!this.state.status?.request || key(this.state.status.request.origin) === key(request.origin)) this.receive(raw);
      } catch {this.fail('Original STOP acknowledgement is missing. Keep this request and check it.');}
      finally {if (this.revokeWork === work) {this.revokeWork = null; this.update({revokePending: false}); this.process();}}
    });
    this.update({revokePending: true, acknowledged: false, message: 'STOP requested; still waiting for the original caller and native cleanup.'}); await work.promise;
  }
  invalidate(): void {
    this.epoch = Math.min(Number.MAX_SAFE_INTEGER, this.epoch + 1); this.update({acknowledged: false});
    if (this.flow && !this.flow.completed && !this.flow.revoked) void this.revoke();
  }
  process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) {this.again = true; return;} this.processing = true;
    try {do {
      this.again = false; this.complete();
      if (this.work || this.revokeWork || this.state.unknown) continue;
      const r = this.state.status?.request;
      const step: MetadataStep | null = r?.phase === 'queued-read' ? 'read' : r?.phase === 'queued-prepare' ? 'open' : r?.phase === 'opened' ? 'prepare' : r?.phase === 'queued-apply' ? 'apply' : null;
      if (!r || !step) continue;
      let flow = this.flow;
      if (!flow || flow.completed) {
        if (step !== 'read') continue; // Reconnect/status cannot reconstruct a prior Load origin.
        const witness = this.context.capture(r); if (!witness || this.epoch === Number.MAX_SAFE_INTEGER) continue;
        flow = {api: this.api, epoch: this.epoch, witness, request: r, baseline: null, native: null, final: null, allowed: false, revoked: false, applyEntered: false, completed: false}; this.flow = flow;
      }
      const f = flow;
      if (key(f.request.origin) !== key(r.origin)) continue;
      const claim = `${key(r.origin)}/${step}`;
      if (this.claims.has(claim) || this.claims.size >= 128) continue;
      if (!this.current(f)) {void this.revoke(); continue;}
      this.captureNative(f);
      if (step !== 'read' && !f.baseline) continue;
      if (step === 'open' && this.context.native()?.active) continue;
      if (step === 'prepare') {
        if (f.native?.phase !== 'editing') continue;
        if (f.native.checkout?.metadataRoot !== f.baseline?.metadataRoot || !equal(f.native.checkout?.baseline, f.baseline?.baseline)) {
          this.update({message: 'The fresh native checkout differs from the original public Load. Stop this request; it will not reload or merge.'});
          void this.revoke(); continue;
        }
      }
      if (step === 'apply' && (!f.allowed || !f.native || f.native.phase !== 'reviewing' || !metadataServicePreviewMatches(r, f.native))) {void this.revoke(); continue;}
      this.claims.add(claim);
      const api = f.api, work: Work = {api, request: r, epoch: this.epoch, promise: Promise.resolve()}; this.work = work;
      work.promise = Promise.resolve().then(async () => {
        try {
          if (this.work !== work || this.flow !== f || this.api !== api || !this.current(f) || this.revokeWork || this.state.unknown || this.state.status?.request !== r) {await this.revoke(); return;}
          if (step === 'read') {
            const raw = await api.load(r.origin), loaded = parseMetadataTextObservation(raw);
            if (!loaded || loaded.platform !== r.platform || loaded.locale !== r.locale || loaded.metadataRoot !== f.witness.context.metadataRoot) throw new Error('Unconfirmed original Load');
            f.baseline = deepFreeze({metadataRoot: loaded.metadataRoot, baseline: loaded.baseline});
          } else {
            if (step === 'apply') {
              const native = this.context.native(), owner = native?.active;
              // The real parent boundary publishes twice and calls App. Only
              // its exact stale-marking delta may change the display witness;
              // every original and permission must still match after return.
              const witness = this.context.boundary(r, f.witness);
              if (!witness || this.work !== work || this.flow !== f || this.api !== api || !this.current(f, witness) ||
                  this.revokeWork || this.state.unknown || this.state.status?.request !== r || native !== this.context.native() ||
                  !this.context.nativeUsable() || !owner || owner.recovery || owner.phase !== 'reviewing' || owner.nativeReason !== 'none' ||
                  owner.nativeFinality !== 'pending' || owner.applySubmitted || owner.reviewRemainingMs <= 0 || !metadataServicePreviewMatches(r, owner)) {
                await this.revoke(); return;
              }
              f.witness = witness;
              f.applyEntered = true; // Immediately before the same original send.
            }
            const raw = await api.continue(r.origin, step);
            if (!parseMetadataTextEditStatus(raw)) throw new Error('Unconfirmed original editor reply');
            this.context.observe(raw);
          }
        } catch {this.fail('The original metadata call did not return a verified reply. Keep its ID, Check/STOP; it will not be replayed.');}
        finally {if (this.work === work) {this.work = null; this.update({pending: null}); this.process();}}
      });
      this.update({pending: step, acknowledged: false});
    } while (this.again);} finally {this.processing = false;}
  }
  dispose(): void {
    if (this.disposed) return; void this.revoke(); this.disposed = true;
    try {this.unlisten?.();} catch { /* No successful native settlement inferred. */ }
    this.unlisten = null; this.listeners.clear(); // Original pending Work is retained.
  }
}
