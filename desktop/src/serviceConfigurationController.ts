// Child of ConfigEditController. The real main Webview alone continues the
// existing native Config commands. These finite promises are NOT native jobs.
import { sameJson } from './catalog.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import { nativeStartReason } from './configEdit.ts';
import type { ConfigEditState } from './configEdit.ts';
import { normalEditResult, parseConfigEditStatus } from './configEditProtocol.ts';
import type { ConfigEditProjection, DesktopApi, JsonObject } from './types.ts';
import { CONFIGURATION_CONSENT, changedConfiguration, configurationSaved, deepFreeze, parseConfigurationStatus, settingsFromConfig } from './serviceConfigurationProtocol.ts';
import type { ConfigurationApi, ConfigurationRequest, ConfigurationStatus, ConfigurationStep } from './serviceConfigurationProtocol.ts';
export interface DelegatedConfigurationSave {
  expectedSession: ProjectSession; before: JsonObject; after: JsonObject; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  request: ConfigurationRequest; projection: ConfigEditProjection; statusRevision: number;
}
export interface ConfigurationControllerState {
  status: ConfigurationStatus | null; pending: 'check' | 'allow' | ConfigurationStep | null; revokePending: boolean;
  acknowledged: boolean; unknown: boolean; message: string | null;
}
interface Context {
  project(id: string): ProjectSession | null; selected(): ProjectSession | null; otherReason(id: string): string | null;
  native(): ConfigEditState; observe(value: unknown): void; checkNative(): Promise<void>;
  busy(value: boolean): void; saved(value: DelegatedConfigurationSave): void;
}
interface Approval {
  api: ConfigurationApi; epoch: number; session: ProjectSession; request: ConfigurationRequest; before: JsonObject; after: JsonObject;
  revoked: boolean; applyEntered: boolean; delivered: boolean; retired: ConfigurationRequest | null;
}
interface Work { api: ConfigurationApi; request: ConfigurationRequest | null; epoch: number; promise: Promise<void> }
const key = (r: ConfigurationRequest) => `${r.origin.serviceInstance}/${r.origin.projectId}/${r.origin.requestId}`;
const terminal = (r: ConfigurationRequest) => ['final', 'refused'].includes(r.phase);
const changed = (a: unknown, b: unknown) => JSON.stringify(a) !== JSON.stringify(b);
export class ConfigurationServiceController {
  private api: ConfigurationApi | null = null;
  private desktop: DesktopApi | null = null;
  private unlisten: (() => void) | null = null;
  private disposed = false;
  private epoch = 0;
  private work: Work | null = null;
  private revokeWork: Work | null = null;
  private approval: Approval | null = null;
  private claims = new Set<string>(); // <=32 native entries x three one-shot continuations.
  private listeners = new Set<() => void>();
  private processing = false;
  private again = false;
  private state: ConfigurationControllerState = {status: null, pending: null, revokePending: false, acknowledged: false, unknown: false, message: null};
  private readonly context: Context;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): ConfigurationControllerState => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => {this.listeners.delete(fn);}; };
  private update(patch: Partial<ConfigurationControllerState>): void {
    this.state = Object.freeze({...this.state, ...patch});
    const request = this.state.status?.request;
    this.context.busy(!!this.work || !!this.revokeWork || this.state.unknown || !!request && !terminal(request));
    for (const listener of this.listeners) listener();
  }
  async connect(desktop: DesktopApi): Promise<void> {
    if (this.disposed || this.desktop || desktop.mode !== 'native' || !desktop.agentConfiguration) return;
    this.desktop = desktop; this.api = desktop.agentConfiguration;
    await this.check();
  }
  async check(): Promise<void> {
    const api = this.api; if (!api || this.disposed || this.work || this.revokeWork) return;
    const work: Work = {api, request: null, epoch: this.epoch, promise: Promise.resolve()};
    this.work = work;
    // Install the actual original before publication; terminal DATA cannot
    // retire this promise while the bridge is still returning.
    work.promise = Promise.resolve().then(async () => {
      try {
        if (!this.unlisten) {
          const unlisten = await api.subscribe(v => this.receive(v));
          if (this.disposed || this.api !== api) {unlisten(); return;}
          this.unlisten = unlisten;
        }
        if (this.disposed || this.api !== api) return;
        this.receive(await api.status());
        if (this.disposed || this.api !== api || this.work !== work) return;
        const approval = this.approval;
        if (approval && !approval.delivered && !approval.retired && approval.api === api) {
          // A coalesced relay may skip the old service Final. Query only this
          // retained origin in the SAME Check; its reply never replaces latest.
          const raw = await api.status(approval.request.origin);
          if (this.disposed || this.api !== api || this.work !== work || this.approval !== approval || approval.delivered) return;
          const exact = parseConfigurationStatus(raw);
          if (!exact?.request || !this.retainApprovalRetirement(approval, exact.request)) {
            if (!exact?.request) this.fail('The exact original configuration request could not be observed. Do not repeat Apply.');
            return;
          }
        }
        if (this.disposed || this.api !== api || this.work !== work) return;
        await this.context.checkNative();
      } catch {
        if (!this.state.status?.request && !this.approval && this.claims.size === 0) {
          // An unconfigured/closed READ service is normal at startup. This
          // read-only probe has admitted no Config original and cannot disable
          // ordinary Desktop edits or pretend to have observed an empty inbox.
          this.update({message: 'CLI request status is unavailable. Enable project READ access and check again.'});
        } else this.fail('The original request could not be observed. Check or stop it; no save is inferred.');
      }
      finally { if (this.work === work) {this.work = null; this.update({pending: null}); this.process();} }
    });
    this.update({pending: 'check'}); await work.promise;
  }
  receive(value: unknown): void {
    if (this.disposed) return;
    let next = parseConfigurationStatus(value);
    const prior = this.state.status;
    if (!next || prior && next.serviceInstance !== prior.serviceInstance) {this.fail('Configuration service identity or status changed. Keep the original request.'); return;}
    if (prior && next.revision < prior.revision) return;
    if (prior && next.revision === prior.revision && changed({...next, request: next.request && {...next.request, remainingMs: 0, permissionLive: false}}, {...prior, request: prior.request && {...prior.request, remainingMs: 0, permissionLive: false}})) {
      this.fail('Contradictory configuration status; do not repeat the change.'); return;
    }
    if (next.request?.phase === 'unknown') {this.update({status: next}); this.fail('Original native cleanup or outcome is unverified. Do not repeat Apply.'); return;}
    const a = prior?.request, b = next.request;
    if (a && b && key(a) === key(b)) {
      if (b.revision < a.revision) return;
      if (a.original && changed(a.original, b.original) || a.change && changed(a.change, b.change) || a.review && changed(a.review, b.review) ||
        a.applyConsumed && !b.applyConsumed || a.cancelRequested && !b.cancelRequested || terminal(a) && (a.phase !== b.phase || changed(a.result, b.result))) {
        this.fail('The retained original comparison changed. Check or stop it, without retry.'); return;
      }
      // First Allow advances the native row revision. Only that SAME revision
      // shares a countdown; pre-Allow zero must not expire a newly issued grant.
      // Delayed status/Allow replies cannot increase or revive an observed end.
      if (b.revision === a.revision && b.remainingMs > a.remainingMs) {
        next = deepFreeze({...next, request: {...b, remainingMs: a.remainingMs, permissionLive: a.remainingMs > 0}});
      }
    }
    const approval = this.approval;
    if (b?.phase === 'final' && approval && !approval.delivered && key(b) === key(approval.request)) {
      if (!this.retainApprovalRetirement(approval, b)) return;
    }
    const replacement = !!a && !!b && key(a) !== key(b);
    this.update({status: next, acknowledged: replacement ? false : this.state.acknowledged}); this.process();
  }
  private retainApprovalRetirement(approval: Approval, request: ConfigurationRequest): boolean {
    if (key(request) !== key(approval.request) || request.phase === 'unknown' || request.runtimeProjectId !== approval.request.runtimeProjectId ||
      changed(request.original, approval.request.original) || changed(request.change, approval.request.change) || changed(request.review, approval.request.review) ||
      approval.retired && changed({...approval.retired, revision: request.revision}, request)) {
      this.fail('The original configuration retirement is unverified or changed. Do not repeat Apply.'); return false;
    }
    // Valid pending DATA does not imply failure or retirement. One bounded
    // Final survives later rows and returning invokes; it is not a native join.
    if (request.phase === 'final') approval.retired = request;
    return true;
  }
  private fail(message: string): void { if (!this.disposed) this.update({unknown: true, acknowledged: false, message}); }
  acknowledge(value: boolean): void { this.update({acknowledged: value === true}); }
  private currentApproval(a: Approval): boolean {
    const session = this.context.project(a.request.runtimeProjectId);
    return !this.disposed && this.api === a.api && a.epoch === this.epoch && !a.revoked && session === a.session && this.context.selected() === session &&
      session.snapshotRequest === null && !isDirty(session) && session.baseline === a.before && !!session.draft && sameJson(session.draft, a.before) &&
      !session.saveRecoveryRequired && !session.saveRecoveryNeedsReload && !session.sourceChanged && !this.context.otherReason(a.request.runtimeProjectId);
  }
  private nativeOriginal(r: ConfigurationRequest): ConfigEditProjection | null {
    const state = this.context.native(), status = state.status;
    if (!status || state.integrityFailed || state.generationLost || state.nativeBlocked || state.observationIssue || !r.original || status.windowGeneration !== r.original.ownerGeneration) return null;
    return [status.active, status.lastTerminal].find(v => v?.sessionId === r.original!.sessionId && v.ownerGeneration === r.original!.ownerGeneration && v.projectId === r.runtimeProjectId) ?? null;
  }
  allowReason(): string | null {
    const r = this.state.status?.request, session = r && this.context.project(r.runtimeProjectId), owner = r && this.nativeOriginal(r);
    if (!this.api || this.disposed) return 'Open the current native Desktop and enable project READ access.';
    if (this.work || this.revokeWork || this.state.unknown || this.approval && !this.approval.delivered) return 'Wait for or stop the retained original permission.';
    if (!r || r.phase !== 'reviewing' || !r.original || !r.review || !r.change || r.applyConsumed || r.cancelRequested || r.permissionLive) return 'The CLI must first read and prepare one exact settings change.';
    if (!session || this.context.selected() !== session || !session.baseline || !session.draft || isDirty(session) || session.snapshotRequest !== null || session.saveRecoveryRequired || session.saveRecoveryNeedsReload || session.sourceChanged ||
      ![session.revision, session.baselineGeneration, session.observationGeneration].every(n => Number.isInteger(n) && n >= 0 && n < 0xffffffff)) return 'Select the original project with a clean, current form. Unsaved edits are never replaced.';
    if (!owner || owner.phase !== 'reviewing' || owner.nativeFinality !== 'pending' || owner.applySubmitted || !owner.checkout || !owner.prepared || owner.prepared.revision !== r.original.revision ||
      owner.prepared.planToken !== r.review.planToken || this.context.native().status!.statusRevision !== r.review.nativeStatusRevision || !sameJson(owner.checkout.base, session.baseline) ||
      changed(settingsFromConfig(session.baseline), r.review.before) || changed(settingsFromConfig(changedConfiguration(session.baseline, r.change) ?? {}), r.review.after)) return 'The original saved checkout and exact native preview must still match this clean form.';
    return this.context.otherReason(r.runtimeProjectId);
  }
  async allow(): Promise<void> {
    if (!this.state.acknowledged || this.allowReason() !== null) return;
    const api = this.api!, request = this.state.status!.request!, session = this.context.project(request.runtimeProjectId)!;
    const after = changedConfiguration(session.baseline!, request.change!); if (!after) return;
    const approval: Approval = {api, epoch: this.epoch, session, request, before: session.baseline!, after: deepFreeze(after), revoked: false, applyEntered: false, delivered: false, retired: null};
    this.approval = approval;
    const work: Work = {api, request, epoch: this.epoch, promise: Promise.resolve()}; this.work = work;
    work.promise = Promise.resolve().then(async () => {
      try {
        if (!this.currentApproval(approval) || this.revokeWork || this.state.unknown || this.state.status?.request !== request) return;
        this.receive(await api.allow({origin: request.origin, original: request.original!, planToken: request.review!.planToken, expectedNativeStatusRevision: request.review!.nativeStatusRevision, consentVersion: CONFIGURATION_CONSENT}));
        if (!this.currentApproval(approval) && !approval.applyEntered && !approval.revoked) void this.revoke();
      } catch { this.fail('Apply permission acknowledgement is missing. Stop the original permission; do not allow again.'); }
      finally { if (this.work === work) {this.work = null; this.update({pending: null}); this.process();} }
    });
    this.update({pending: 'allow', acknowledged: false, message: null}); await work.promise;
  }
  async revoke(): Promise<void> {
    const approval = this.approval && !this.approval.delivered ? this.approval : null;
    const api = this.work?.api ?? approval?.api ?? this.api;
    const request = this.work?.request ?? approval?.request ?? this.state.status?.request;
    if (!api || !request || this.revokeWork) return;
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    if (this.approval) this.approval.revoked = true;
    const work: Work = {api, request, epoch: this.epoch, promise: Promise.resolve()}; this.revokeWork = work;
    work.promise = Promise.resolve().then(async () => {
      try { this.receive(await api.revoke(request.origin)); }
      catch { this.fail('Original STOP acknowledgement is missing. Keep its request ID and check status.'); }
      finally { if (this.revokeWork === work) {this.revokeWork = null; this.update({revokePending: false}); this.process();} }
    });
    this.update({revokePending: true, acknowledged: false, message: 'STOP requested for this original only; wait for native settlement.'}); await work.promise;
  }
  beforeWorkspaceAction(action: WorkspaceAction): void {
    const r = this.approval?.request ?? this.state.status?.request;
    if (!r || action.type === 'delegated-config-save-final') return;
    if (action.type === 'switch' || action.type === 'select' || 'projectId' in action && action.projectId === r.runtimeProjectId &&
      ['snapshot-start', 'snapshot-done', 'snapshot-failed', 'edit', 'new-draft', 'remove-forbidden', 'undo-removal', 'forget-removal', 'reset', 'adopt-suggestion', 'config-save-intent', 'config-save-final'].includes(action.type)) this.invalidate();
  }
  invalidate(): void {
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    this.update({acknowledged: false});
    if (this.approval && !this.approval.applyEntered && !this.approval.delivered && !this.approval.revoked) void this.revoke();
  }
  private complete(): void {
    const a = this.approval; if (!a || a.delivered || this.work || this.revokeWork || this.state.unknown) return;
    const retired = a.retired;
    if (!retired?.result || retired.phase !== 'final') return;
    const owner = this.nativeOriginal(a.request), status = this.context.native().status;
    if (!owner || !status || owner.phase !== 'final' || owner.nativeFinality !== 'settled') return;
    const core = owner.coreOutcome;
    if (!core || core.resources !== 'settled' || retired.result.effect !== core.effect || retired.result.journal !== core.journal ||
      retired.result.cancelled !== (owner.nativeReason !== 'none') || retired.result.applySubmitted !== owner.applySubmitted ||
      owner.prepared?.planToken !== a.request.review!.planToken || owner.checkout?.revision !== a.request.original!.revision || !sameJson(owner.checkout.base, a.before)) {
      this.fail('The native and service retirement of the original configuration do not match. Keep its request ID.'); return;
    }
    if (!a.applyEntered && !owner.applySubmitted) {
      // Known pre-Apply retirement releases only this UI approval. Neither a
      // cancelled flag nor final DATA alone retires either pending promise.
      a.delivered = true; this.approval = null;
      this.update({message: 'The original permission ended without Apply. A new request needs its own native preview and approval.'}); return;
    }
    a.delivered = true; // Mark before the workspace callback/reentrant notification.
    const result = normalEditResult(owner);
    if (!a.applyEntered || !result || !configurationSaved(retired.result) || changed(retired.settings, a.request.review!.after)) {
      this.update({message: 'The original ended without a verified ordinary save. Keep the draft and inspect its retained outcome.'}); return;
    }
    this.context.saved({expectedSession: a.session, before: a.before, after: a.after, draftRevision: a.session.revision, baselineGeneration: a.session.baselineGeneration,
      observationGeneration: a.session.observationGeneration, request: a.request, projection: owner, statusRevision: status.statusRevision});
    this.update({message: 'The original save settled. Any newer or dirty form state is preserved; check saved files before another edit.'});
  }
  process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) {this.again = true; return;}
    this.processing = true;
    try { do {this.again = false; this.complete(); if (this.work || this.revokeWork || this.state.unknown) continue;
      const request = this.state.status?.request;
      const step: ConfigurationStep | null = request?.phase === 'queued-read' ? 'read' : request?.phase === 'queued-prepare' ? 'prepare' : request?.phase === 'queued-apply' ? 'apply' : null;
      if (!request || !step) continue;
      if (this.approval && !this.approval.delivered && key(this.approval.request) !== key(request)) continue;
      const claim = `${key(request)}/${step}`;
      if (this.claims.has(claim) || this.claims.size >= 96 || this.epoch === Number.MAX_SAFE_INTEGER) continue;
      const session = this.context.project(request.runtimeProjectId), api = this.api, epoch = this.epoch;
      if (!session || this.context.selected() !== session || session.snapshotRequest !== null || this.context.otherReason(request.runtimeProjectId)) continue;
      const native = this.context.native();
      if (step === 'read' && nativeStartReason({...native, delegationPending: false}) !== null) continue;
      if (step !== 'read') { const owner = this.nativeOriginal(request); if (!owner || owner.phase !== (step === 'prepare' ? 'editing' : 'reviewing')) continue; }
      if (step === 'apply' && (!this.approval || key(this.approval.request) !== key(request) || !this.currentApproval(this.approval))) {void this.revoke(); continue;}
      this.claims.add(claim);
      const work: Work = {api, request, epoch, promise: Promise.resolve()}; this.work = work;
      work.promise = Promise.resolve().then(async () => {
        try {
          if (this.disposed || this.api !== api || epoch !== this.epoch || this.revokeWork || this.state.unknown || this.context.project(request.runtimeProjectId) !== session ||
            this.context.selected() !== session || this.context.otherReason(request.runtimeProjectId) || this.state.status?.request !== request) return;
          if (step === 'apply') {if (!this.approval || !this.currentApproval(this.approval)) return; this.approval.applyEntered = true;}
          const raw = await api.continue(request.origin, step);
          if (!parseConfigEditStatus(raw)) throw new Error('Invalid native configuration status');
          this.context.observe(raw);
        } catch { this.fail('An original native call has not been confirmed. Check or stop its request; it will not be replayed.'); }
        finally {if (this.work === work) {this.work = null; this.update({pending: null}); this.process();}}
      });
      this.update({pending: step, acknowledged: false});
    } while (this.again); } finally {this.processing = false;}
  }
  dispose(): void {
    if (this.disposed) return;
    // Keep every actual pending promise; renderer loss has independent native
    // READ/watchdog/Window STOP. Best-effort original Revoke is not finality.
    void this.revoke(); this.disposed = true;
    try {this.unlisten?.();} catch { /* No settlement claim. */ }
    this.unlisten = null; this.listeners.clear();
  }
}
