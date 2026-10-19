// Local draft/consent only. The injected original native controller owns every
// command Promise, lease, timer, source revision, publication and settlement.
// No polling, file access, Store lookup, auto-apply, or synthetic native session.
import { identityDataEqual, identityPreviewMatches, identityTerminalResult, identityValueFits,
  parseIdentityContext, parseIdentityOwnerSnapshot } from './projectIdentity.ts';
import type { IdentityAnalysis, IdentityCheckout, IdentityDiagnostic, IdentityIntent, IdentityNativePort, IdentityOwnerSnapshot,
  IdentityPrepared, IdentityPreview, IdentityProjection, IdentityRecovery, IdentityUiContext } from './projectIdentity.ts';

interface Frame { context: IdentityUiContext | null; owner: IdentityOwnerSnapshot | null }
interface ReviewRequest {
  context: IdentityUiContext; windowGeneration: string; sessionId: string; ownerGeneration: string;
  checkout: IdentityCheckout; desiredIdentity: string | null; intent: IdentityIntent | null; epoch: number;
}
interface ReviewBinding extends ReviewRequest { prepared: IdentityPrepared }
export interface IdentityActions {
  analyze: boolean; prepare: boolean; apply: boolean; inspectRecovery: boolean; prepareRecovery: boolean;
  recover: boolean; discard: boolean; checkStatus: boolean;
}
export interface ProjectIdentityUiState {
  context: IdentityUiContext | null; session: IdentityProjection | null; busy: boolean;
  analysis: IdentityAnalysis | null; preview: IdentityPreview | null; recovery: IdentityRecovery | null;
  diagnostic: IdentityDiagnostic | null; desiredIdentity: string; intent: IdentityIntent;
  newApplicationAcknowledged: boolean; reviewAcknowledged: boolean; canChooseNew: boolean; canEditDraft: boolean;
  reviewCurrent: boolean; result: 'saved' | 'unchanged' | 'recovered' | null;
  message: string; tone: 'neutral' | 'info' | 'warning' | 'danger' | 'success'; actions: IdentityActions;
}
type Action = keyof IdentityActions;
const UNKNOWN = 'Could not confirm the app ID operation. Check its status before doing anything else. Do not apply the change again.';
const methods = ['getSnapshot', 'subscribe', 'analyze', 'prepare', 'apply', 'inspectRecovery', 'prepareRecovery', 'recover', 'discard', 'checkStatus'] as const;
const nativePort = (port: IdentityNativePort | null | undefined): IdentityNativePort | null => {
  try {
    if (port?.mode !== 'native' || !methods.every((key) => typeof port[key] === 'function')) return null;
    const { getSnapshot, subscribe, analyze, prepare, apply, inspectRecovery, prepareRecovery, recover, discard, checkStatus } = port;
    // Retain the original callbacks, never dynamically route a pending review
    // through replacement methods. A different native host needs a new UI
    // controller after Root retires the old scope and retains its original work.
    const original: IdentityNativePort = { mode: 'native', getSnapshot: () => getSnapshot.call(port), subscribe: (listener) => subscribe.call(port, listener),
      analyze: (r) => analyze.call(port, r), prepare: (r) => prepare.call(port, r), apply: (r) => apply.call(port, r),
      inspectRecovery: (r) => inspectRecovery.call(port, r), prepareRecovery: (r) => prepareRecovery.call(port, r),
      recover: (r) => recover.call(port, r), discard: (r) => discard.call(port, r), checkStatus: () => checkStatus.call(port) };
    return Object.freeze(original);
  }
  catch { return null; }
};
const sameSession = (p: IdentityProjection, request: ReviewRequest): boolean => p.sessionId === request.sessionId &&
  p.projectId === request.context.projectId && p.ownerGeneration === request.ownerGeneration && identityDataEqual(p.checkout, request.checkout);
function sameAdmissionFrame(a: Frame, b: Frame): boolean {
  const stable = (frame: Frame) => ({ context: frame.context, owner: frame.owner === null ? null : { ...frame.owner,
    status: !frame.owner.status ? null : { ...frame.owner.status,
      active: frame.owner.status.active ? { ...frame.owner.status.active, reviewRemainingMs: 0 } : null,
      lastTerminal: frame.owner.status.lastTerminal ? { ...frame.owner.status.lastTerminal, reviewRemainingMs: 0 } : null } } });
  // Time remaining is a display estimate, not a new consent. Check it is still
  // positive at handoff; the original native admission owns the real deadline.
  return identityDataEqual(stable(a), stable(b));
}

export class ProjectIdentityController {
  readonly #context: () => unknown;
  readonly #port: IdentityNativePort | null;
  #state!: ProjectIdentityUiState;
  #frame: Frame = { context: null, owner: null };
  #listeners = new Set<() => void>();
  #unsubscribe: (() => void) | null = null;
  #notifying = false;
  #disposed = false;
  #admitting = false;
  #uncertain = false;
  #epoch = 0;
  #desired = '';
  #intent: IdentityIntent = 'preserve';
  #newAcknowledged = false;
  #request: ReviewRequest | null = null;
  #consent: ReviewBinding | null = null;
  #submitted: ReviewBinding | null = null;
  #retired = new Set<string>();
  #message: string | null = null;

  constructor(context: () => unknown, port?: IdentityNativePort | null) {
    this.#context = context;
    this.#port = nativePort(port);
    this.sync();
  }
  getSnapshot = (): ProjectIdentityUiState => this.#state;
  subscribe = (listener: () => void): (() => void) => {
    if (this.#disposed) return () => {};
    this.#listeners.add(listener);
    if (!this.#unsubscribe && this.#port) {
      // A local original-controller subscription, never bridge registration or
      // a native command. Component mounting cannot analyze or edit a project.
      try {
        const off = this.#port.subscribe(this.sync);
        if (typeof off !== 'function') this.#uncertain = true;
        else this.#unsubscribe = off;
      } catch { this.#uncertain = true; }
      this.sync();
    }
    return () => {
      this.#listeners.delete(listener);
      if (this.#listeners.size === 0) this.#stopListening();
    };
  };
  #stopListening(): void {
    const off = this.#unsubscribe;
    this.#unsubscribe = null;
    try { off?.(); } catch { this.#uncertain = true; }
  }
  dispose(): void {
    this.#disposed = true; this.#consent = null; this.#request = null;
    this.#listeners.clear(); this.#stopListening(); this.sync();
    // Disposing display state NEVER cancels or settles the original operation.
  }
  #notify(): void {
    if (this.#notifying) return;
    this.#notifying = true;
    try { for (const listener of [...this.#listeners]) { try { listener(); } catch { this.#uncertain = true; } } }
    finally { this.#notifying = false; }
  }
  #bump(): void {
    if (this.#epoch === Number.MAX_SAFE_INTEGER) this.#uncertain = true;
    else this.#epoch += 1;
  }
  #retireSession(id: string | undefined): void {
    if (!id) return;
    // Bounded display memory; exhaustion disables reuse rather than forgetting
    // an old review. Native independently enforces one-shot authority.
    if (this.#retired.size >= 128 && !this.#retired.has(id)) this.#uncertain = true;
    else this.#retired.add(id);
  }
  #invalidate(reviewOnly: boolean): void {
    this.#bump(); this.#consent = null;
    if (!reviewOnly || this.#request || this.#frame.owner?.status?.active?.prepared) {
      this.#retireSession(this.#frame.owner?.status?.active?.sessionId);
      this.#request = null;
    }
  }
  // Root calls BEFORE context/save/API/selection intents, including ABA/no-op.
  // Root separately retires original native reviews and invalidates assignments
  // and candidates (never version reservations). This method does not do so.
  retire(): void {
    this.#invalidate(false); this.#newAcknowledged = false; this.sync();
  }
  #read(): Frame {
    let context: IdentityUiContext | null = null, owner: IdentityOwnerSnapshot | null = null;
    try { context = parseIdentityContext(this.#context()); } catch { /* No raw errors in UI. */ }
    if (this.#port) {
      try { owner = parseIdentityOwnerSnapshot(this.#port.getSnapshot()); } catch { /* Preserve unknown. */ }
      if (!owner || !owner.status && this.#submitted) this.#uncertain = true;
    }
    const old = this.#frame;
    if (!identityDataEqual(old.context, context) || old.owner?.status?.windowGeneration !== owner?.status?.windowGeneration) {
      if (old.context !== null || old.owner !== null) this.#invalidate(false);
      this.#intent = 'preserve'; this.#newAcknowledged = false;
    }
    // Draft text is local. Observations never overwrite it, even after drift.
    return { context, owner };
  }
  sync = (): void => {
    this.#frame = this.#read();
    let bound = this.#binding(this.#frame);
    if (this.#consent && (!bound || !identityDataEqual(this.#consent, bound))) {
      this.#retireSession(this.#consent.sessionId); this.#consent = null; this.#request = null; bound = null;
    }
    this.#state = Object.freeze(this.#present(this.#frame, bound));
    this.#notify();
  };
  #active(frame: Frame): IdentityProjection | null {
    const p = frame.owner?.status?.active;
    return p && p.projectId === frame.context?.projectId ? p : null;
  }
  #selected(p: IdentityProjection | null, frame: Frame): boolean {
    return p !== null && p.projectId === frame.context?.projectId && (p.intent === 'recover' ||
      p.checkout?.view.kind === 'project-identity' && identityDataEqual(p.checkout.view.selection, frame.context?.selection));
  }
  #binding(frame: Frame): ReviewBinding | null {
    const p = this.#active(frame), request = this.#request;
    if (!p || !request || !p.prepared || !p.checkout || this.#retired.has(p.sessionId) || p.phase !== 'reviewing' ||
      p.reviewRemainingMs <= 0 || p.applySubmitted || p.diagnostic || !sameSession(p, request) || request.epoch !== this.#epoch ||
      request.windowGeneration !== frame.owner?.status?.windowGeneration || !identityDataEqual(request.context, frame.context)) return null;
    if (p.intent === 'edit') {
      if (p.checkout.view.kind !== 'project-identity' || p.prepared.view.kind !== 'project-identity-preview' || request.intent !== this.#intent ||
        request.desiredIdentity !== (this.#intent === 'preserve' ? p.checkout.view.identity : this.#desired) ||
        request.desiredIdentity === null || !identityPreviewMatches(p.prepared.view, p.checkout.view, request.desiredIdentity, this.#intent) ||
        this.#intent === 'new-application' && !this.#newAcknowledged) return null;
    } else if (p.prepared.view.kind !== 'project-identity-recovery' || request.intent !== null ||
      !identityDataEqual(p.prepared.view, p.checkout.view)) return null;
    return { ...request, prepared: p.prepared };
  }
  #present(frame: Frame, bound: ReviewBinding | null): ProjectIdentityUiState {
    const { context, owner } = frame, status = owner?.status;
    const active = this.#active(frame);
    const terminal = status?.lastTerminal;
    const session = active ?? (terminal?.projectId === context?.projectId ? terminal : null);
    const selected = this.#selected(session, frame);
    const analysis = selected && session?.checkout?.view.kind === 'project-identity' ? session.checkout.view : null;
    const preview = selected && session?.prepared?.view.kind === 'project-identity-preview' ? session.prepared.view : null;
    const recovery = selected && session?.checkout?.view.kind === 'project-identity-recovery' ? session.checkout.view : null;
    const busy = this.#admitting || owner?.busy === true;
    const ready = Boolean(this.#port && !this.#disposed && context && !context.preview && !context.blocked && !busy &&
      !this.#uncertain && status?.capability.available);
    const settled = !terminal || terminal.nativeFinality === 'settled' && terminal.coreOutcome?.resources !== 'unknown' && terminal.coreOutcome?.journal !== 'unknown';
    const idle = ready && !status?.active && settled;
    const editing = ready && active?.phase === 'editing' && !active.applySubmitted && !active.diagnostic && selected && !this.#retired.has(active.sessionId);
    const canChooseNew = Boolean(editing && analysis?.state === 'supported' && analysis.selection.continuity === 'unknown' && analysis.identityStatus === 'unverified');
    const canEditDraft = Boolean(editing && analysis?.state === 'supported');
    const changedInput = canChooseNew && this.#newAcknowledged && analysis && this.#desired !== analysis.identity && identityValueFits(this.#desired, analysis.selection.platform);
    const reviewAcknowledged = bound !== null && identityDataEqual(bound, this.#consent);
    const actions: IdentityActions = {
      analyze: Boolean(idle && context?.projectId && context.selection && !['recovery_required', 'unknown'].includes(terminal?.coreOutcome?.journal ?? 'not_created')),
      prepare: Boolean(canEditDraft && !this.#request && (this.#intent === 'preserve' || changedInput)),
      apply: Boolean(ready && bound && active?.intent === 'edit' && reviewAcknowledged),
      inspectRecovery: Boolean(idle && context?.projectId),
      prepareRecovery: Boolean(editing && active?.intent === 'recover' && recovery?.state === 'recoverable' && !this.#request),
      recover: Boolean(ready && bound && active?.intent === 'recover' && reviewAcknowledged),
      discard: Boolean(this.#port && !this.#disposed && context && !context.preview && !busy && !this.#uncertain && active &&
        !active.applySubmitted && ['editing', 'reviewing'].includes(active.phase)),
      checkStatus: Boolean(this.#port && !this.#disposed && context && !context.preview && !busy),
    };
    const submitted = this.#submitted;
    const result = !this.#uncertain && session && submitted && submitted.windowGeneration === status?.windowGeneration && sameSession(session, submitted) &&
      identityDataEqual(session.prepared, submitted.prepared) ? identityTerminalResult(session) : null;
    const diagnostic = selected ? session?.diagnostic ?? analysis?.diagnostics[0] ?? null : null;
    const unresolved = session?.nativeFinality === 'unknown' || session?.coreOutcome?.resources === 'unknown' || session?.coreOutcome?.journal === 'unknown';
    const failed = session?.phase === 'final' && session.nativeFinality === 'settled' &&
      (session.nativeReason !== 'none' && session.nativeReason !== 'discarded' ||
        session.coreOutcome !== null && session.coreOutcome.reason !== 'none' ||
        session.applySubmitted && identityTerminalResult(session) === null);
    const committedNeedsAttention = session?.coreOutcome?.effect === 'committed' && !result;
    const needsRecovery = session?.coreOutcome?.journal === 'recovery_required';
    let message = 'Read the saved project to find its app ID.', tone: ProjectIdentityUiState['tone'] = 'neutral';
    // A missing/malformed later status is not evidence that an admitted change
    // never happened. Retained uncertainty must outlive generic disabled help.
    if (this.#uncertain) { message = UNKNOWN; tone = 'danger'; }
    else if (committedNeedsAttention) {
      message = 'The ID change committed, but cleanup or final confirmation still needs attention. Do not apply it again. Check status, then review recovery if offered.'; tone = 'warning';
    } else if (unresolved) {
      message = UNKNOWN; tone = 'warning';
    } else if (!this.#port || !status || context?.preview || this.#disposed) message = 'App ID editing needs the native Desktop app and its supported identity editor. No files will be changed here.';
    else if (!context?.projectId) message = 'Choose a saved project first.';
    else if (busy || session && ['opening', 'preparing', 'applying', 'finalizing'].includes(session.phase)) {
      message = 'Working on the app ID. Wait for the original operation to finish.'; tone = 'info';
    } else if (result) {
      message = result === 'saved' ? 'The reviewed ID change finished. Read the project again, then check credentials and the built app before release.' :
        result === 'unchanged' ? 'The app ID was kept. No files were changed.' :
          session?.prepared?.view.kind === 'project-identity-recovery' && session.prepared.view.action === 'committed_cleanup'
            ? 'Cleanup finished. The committed app ID was kept. Read the project again before continuing.'
            : 'Recovery finished. Read the project again before continuing.';
      tone = 'success';
    } else if (failed) {
      const core = session!.coreOutcome;
      tone = 'danger';
      if (needsRecovery) message = 'The app ID operation did not finish. Keep its recovery files and review the interrupted change before trying another ID change.';
      else if (core?.effect === 'rolled_back' && core.journal === 'clean') message = 'The app ID operation reported a problem after restoring the original files. Read the project again and make a new preview before trying again.';
      else if (core && ['not_started', 'unchanged'].includes(core.effect) && ['not_created', 'clean'].includes(core.journal)) {
        message = core.reason === 'stale_revision'
          ? 'The project changed before the ID change could finish. No ID change was applied. Read the project again and make a new preview.'
          : 'The app ID operation could not finish. No ID change was applied. Check status, then read the project again before making a new preview.';
      } else if (!session!.applySubmitted) message = 'The native app ID editor could not finish reading or preparing this project. No ID change was submitted. Check status, then read the project again.';
      else message = 'The app ID operation did not finish successfully. Check status before continuing; do not apply the old review again.';
    } else if (diagnostic) { message = diagnostic.help; tone = 'warning'; }
    else if (needsRecovery) { message = 'An interrupted ID change needs attention. Review recovery before making another change.'; tone = 'warning'; }
    else if (recovery) { message = recovery.help; tone = recovery.state === 'idle' ? 'neutral' : 'warning'; }
    else if (active && this.#retired.has(active.sessionId) || active?.prepared && !bound) {
      message = 'This review is no longer current. Close it, then read the app ID again.'; tone = 'warning';
    } else if (bound) { message = preview?.state === 'unchanged' ? 'Review the unchanged ID, then confirm to keep it.' : 'Check the old and new IDs, then approve this exact change.'; tone = 'info'; }
    else if (context.blocked || !status.capability.available) { message = 'Finish the current project operation or recovery before editing its app ID.'; tone = 'warning'; }
    else if (!context.selection) message = 'Choose the Android app module or native iOS app target in project settings first.';
    else if (analysis) {
      message = this.#intent === 'new-application'
        ? 'Enter a different ID and confirm that this is a separate app. Store availability has not been checked.'
        : analysis.nextStep;
    }
    if (this.#message && !this.#uncertain && !busy && !unresolved && !failed && !committedNeedsAttention && !needsRecovery) { message = this.#message; tone = 'warning'; }
    return { context, session, busy, analysis, preview, recovery, diagnostic, desiredIdentity: this.#desired, intent: this.#intent,
      newApplicationAcknowledged: this.#newAcknowledged, reviewAcknowledged, canChooseNew, canEditDraft, reviewCurrent: bound !== null,
      result, message, tone, actions: Object.freeze(actions) };
  }
  setIntent(intent: IdentityIntent): boolean {
    this.sync();
    const allowed = this.#state.canEditDraft && (intent === 'preserve' || intent === 'new-application' && this.#state.canChooseNew);
    this.#invalidate(true);
    if (allowed) { this.#intent = intent; this.#newAcknowledged = false; this.#message = null; }
    this.sync(); return allowed;
  }
  setDesiredIdentity(value: string): boolean {
    this.sync();
    const allowed = this.#state.canEditDraft && this.#intent === 'new-application' && typeof value === 'string' && value.length <= 255;
    this.#invalidate(true);
    if (allowed) { this.#desired = value; this.#message = null; }
    this.sync(); return allowed;
  }
  acknowledgeNewApplication(value: boolean): boolean {
    this.sync();
    const allowed = this.#state.canChooseNew && this.#intent === 'new-application' && typeof value === 'boolean';
    this.#invalidate(true);
    if (allowed) { this.#newAcknowledged = value; this.#message = null; }
    this.sync(); return allowed;
  }
  acknowledgeReview(value: boolean): boolean {
    this.sync();
    const bound = this.#binding(this.#frame);
    if (typeof value !== 'boolean' || value && (!bound || this.#state.busy || this.#uncertain)) return false;
    this.#consent = value ? bound : null; this.sync(); return true;
  }
  #invoke(action: Action, call: (port: IdentityNativePort) => boolean, before?: () => void): boolean {
    const expected = this.#frame, expectedEpoch = this.#epoch;
    this.sync();
    if (!this.#port || !this.#state.actions[action] || expectedEpoch !== this.#epoch || !sameAdmissionFrame(expected, this.#frame)) return false;
    const original = this.#frame;
    this.#admitting = true; this.#message = null;
    before?.(); const epoch = this.#epoch;
    this.sync(); // Reentrant listeners see a latched admission.
    const checked = this.#read();
    const expired = (action === 'apply' || action === 'recover') && !(checked.owner?.status?.active && checked.owner.status.active.reviewRemainingMs > 0);
    if (this.#disposed || this.#epoch !== epoch || !sameAdmissionFrame(original, checked) || expired || this.#uncertain && action !== 'checkStatus') {
      this.#admitting = false; this.sync(); return false;
    }
    let result: unknown;
    try { result = call(this.#port); } catch { this.#uncertain = true; }
    if (typeof result !== 'boolean') this.#uncertain = true;
    else if (!result) this.#message = 'Nothing was submitted. Close any old review and read the app ID again.';
    this.#admitting = false;
    this.sync();
    if (result === true && action !== 'checkStatus' && !this.#frame.owner?.busy && identityDataEqual(original.owner, this.#frame.owner)) {
      // No original admission was observable. Never turn a fire-and-forget
      // bridge wrapper into a usable owner by manufacturing local progress.
      this.#uncertain = true; this.sync();
    }
    return result === true && !this.#uncertain;
  }
  analyze(): boolean {
    this.sync();
    const context = this.#frame.context;
    if (!context?.projectId || !context.selection) return false;
    return this.#invoke('analyze', (port) => port.analyze({ projectId: context.projectId!, selection: context.selection! }));
  }
  inspectRecovery(): boolean {
    this.sync(); const id = this.#frame.context?.projectId;
    return id ? this.#invoke('inspectRecovery', (port) => port.inspectRecovery({ projectId: id })) : false;
  }
  #prepare(recover: boolean): boolean {
    this.sync();
    const frame = this.#frame, p = this.#active(frame), context = frame.context;
    if (!p?.checkout || !context || !frame.owner?.status) return false;
    const desired = !recover && p.checkout.view.kind === 'project-identity' ? this.#intent === 'preserve' ? p.checkout.view.identity : this.#desired : null;
    const request: ReviewRequest = { context, windowGeneration: frame.owner.status.windowGeneration, sessionId: p.sessionId,
      ownerGeneration: p.ownerGeneration, checkout: p.checkout, desiredIdentity: desired, intent: recover ? null : this.#intent, epoch: this.#epoch };
    return this.#invoke(recover ? 'prepareRecovery' : 'prepare', (port) => recover
      ? port.prepareRecovery({ sessionId: p.sessionId, revision: p.checkout!.revision })
      : port.prepare({ sessionId: p.sessionId, revision: p.checkout!.revision, desiredIdentity: desired!, intent: this.#intent }),
    () => { this.#request = request; this.#consent = null; });
  }
  prepare(): boolean { return this.#prepare(false); }
  prepareRecovery(): boolean { return this.#prepare(true); }
  #apply(recover: boolean): boolean {
    this.sync(); const bound = this.#binding(this.#frame);
    if (!bound) return false;
    const request = Object.freeze({ sessionId: bound.sessionId, revision: bound.checkout.revision, planToken: bound.prepared.planToken });
    const admitted = this.#invoke(recover ? 'recover' : 'apply', (port) => recover ? port.recover(request) : port.apply(request), () => {
      this.#submitted = bound; this.#consent = null; this.#retireSession(bound.sessionId);
    });
    if (!admitted && !this.#uncertain) { this.#submitted = null; this.sync(); }
    return admitted;
  }
  apply(): boolean { return this.#apply(false); }
  recover(): boolean { return this.#apply(true); }
  discard(): boolean {
    this.sync(); const p = this.#active(this.#frame);
    return p ? this.#invoke('discard', (port) => port.discard({ sessionId: p.sessionId }), () => this.#invalidate(false)) : false;
  }
  checkStatus(): boolean { this.sync(); return this.#invoke('checkStatus', (port) => port.checkStatus()); }
}
