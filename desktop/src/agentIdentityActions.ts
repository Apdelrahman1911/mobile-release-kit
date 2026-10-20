// One exact, already-read proposal. These controls retain permission requests;
// the existing ProjectIdentityNativeController/EditOwner retains the operation.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { identityDataEqual, identityValueFits, parseIdentityAnalysis } from './projectIdentity.ts';
import type { IdentityAnalysis, IdentityCheckout, IdentityLocation } from './projectIdentity.ts';
import { encodeProjectIdentityRequest } from './projectIdentityNative.ts';
import type { AgentIdentityProposal, ProjectIdentityNativeController } from './projectIdentityNative.ts';
import type { ProjectIdentityController } from './projectIdentityController.ts';

export const AGENT_IDENTITY_ACTION_CONSENT = 'agent-exact-opened-identity-edit-v1';
export type AgentIdentityActionCommand = 'allow_agent_identity_action' | 'agent_identity_action_status' | 'revoke_agent_identity_action';
export interface IdentityActionAllow { intentId: string; sessionId: string; revision: string; acknowledgeNewApplication: boolean; consentVersion: typeof AGENT_IDENTITY_ACTION_CONSENT }
export interface AgentIdentityActionApi {
  readonly mode: 'native';
  allow(input: IdentityActionAllow): Promise<unknown>;
  status(intentId: string): Promise<unknown>;
  revoke(intentId: string): Promise<unknown>;
}
type Change = AgentIdentityProposal['request']['change'];
type Origin = Pick<AgentIdentityProposal['request'], 'serviceInstance' | 'projectId' | 'intentId'>;
type Original = { operationId: string; ownerGeneration: string; revision: string };
type Step = 'not-requested' | 'queued' | 'admitting' | 'submitted' | 'refused' | 'unconfirmed';
type Effect = 'not_started' | 'unchanged' | 'committed' | 'rolled_back' | 'unknown';
type Journal = 'not_created' | 'clean' | 'recovery_required' | 'unknown';
export interface IdentityActionReview {
  planToken: string; beforeIdentity: string; afterIdentity: string; changes: IdentityLocation[]; unchanged: boolean;
  newApplicationWarning: boolean; buildVerificationRequired: true; retainVersionReservations: true;
}
export interface IdentityActionObservation {
  statusRevision: number; state: 'prepared' | 'running' | 'succeeded' | 'failed' | 'cancellation-requested' | 'cancelled' | 'recovery-required' | 'unknown';
  settlement: 'pending' | 'settled' | 'unknown'; applySubmitted: boolean;
  review: IdentityActionReview | null; effect: Effect | null; journal: Journal | null;
}
export interface IdentityActionStatus {
  origin: Origin; change: Change; original: Original; prepare: Step; start: Step; permissionLive: boolean; remainingMs: number;
  cancelRequested: boolean; unconfirmed: boolean; observation: IdentityActionObservation | null; doNotReplay: true; historyMustBeQueried: true;
}
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const token = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v) && v !== '0'.repeat(32);
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const one = (v: unknown, values: readonly string[]) => typeof v === 'string' && values.includes(v);
const steps = ['not-requested', 'queued', 'admitting', 'submitted', 'refused', 'unconfirmed'];
function change(v: unknown): v is Change {
  return keys(v, ['selection', 'desiredIdentity', 'identityIntent']) && keys(v.selection, ['platform', 'target', 'project']) &&
    (v.selection.platform === 'android' || v.selection.platform === 'ios') && identityValueFits(v.desiredIdentity, v.selection.platform) &&
    one(v.identityIntent, ['preserve', 'new-application']) && !!encodeProjectIdentityRequest('project_identity_open', { intent: 'edit', projectId: 'project-1', selection: v.selection });
}
function review(v: unknown, c: Change, revision: string): v is IdentityActionReview {
  if (!keys(v, ['planToken', 'beforeIdentity', 'afterIdentity', 'changes', 'unchanged', 'newApplicationWarning', 'buildVerificationRequired', 'retainVersionReservations']) ||
    !token(v.planToken) || v.planToken === revision || !identityValueFits(v.beforeIdentity, c.selection.platform) || v.afterIdentity !== c.desiredIdentity ||
    typeof v.unchanged !== 'boolean' || v.unchanged !== (v.beforeIdentity === v.afterIdentity) || v.newApplicationWarning !== !v.unchanged ||
    v.buildVerificationRequired !== true || v.retainVersionReservations !== true || !Array.isArray(v.changes) || v.changes.length > 65) return false;
  if (v.unchanged) return v.changes.length === 0;
  if (c.identityIntent !== 'new-application') return false;
  // Reuse the strict source-location grammar. This is parser DATA, not a
  // synthetic source observation, permission or native checkout.
  return parseIdentityAnalysis({ schemaVersion: 1, kind: 'project-identity', revision,
    selection: { ...c.selection, continuity: 'unknown' }, state: 'supported', identity: v.beforeIdentity, configuredIdentity: v.beforeIdentity,
    identityStatus: 'unverified', configurations: ['display'], locations: v.changes, diagnostics: [], nextStep: 'Display only.',
    scope: 'recognized-literal-source-only', buildVerificationRequired: true }) !== null;
}
function observation(v: unknown, c: Change, revision: string): v is IdentityActionObservation {
  if (!keys(v, ['statusRevision', 'state', 'settlement', 'applySubmitted', 'review', 'effect', 'journal']) ||
    !integer(v.statusRevision, 0xffff_ffff) || v.statusRevision === 0 || typeof v.applySubmitted !== 'boolean' ||
    v.review !== null && !review(v.review, c, revision) || (v.effect === null) !== (v.journal === null) ||
    v.effect !== null && !one(v.effect, ['not_started', 'unchanged', 'committed', 'rolled_back', 'unknown']) ||
    v.journal !== null && !one(v.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) ||
    v.applySubmitted && v.review === null && v.state !== 'unknown') return false;
  if (v.state === 'unknown') return v.settlement === 'unknown';
  if (v.effect === 'unknown' || v.journal === 'unknown') return false;
  if (v.state === 'running' || v.state === 'cancellation-requested') return v.settlement === 'pending';
  if (v.state === 'prepared') return v.settlement === 'pending' && v.review !== null && !v.applySubmitted;
  if (v.settlement !== 'settled') return false;
  if (v.state === 'recovery-required') return v.journal === 'recovery_required';
  if (v.journal === 'recovery_required') return false;
  if (v.state === 'succeeded') return v.applySubmitted && (v.effect === 'committed' && v.journal === 'clean' ||
    v.effect === 'unchanged' && (v.journal === 'clean' || v.journal === 'not_created'));
  return v.state === 'failed' || v.state === 'cancelled';
}
function freeze<T>(v: T): T {
  if (v && typeof v === 'object') { for (const value of Object.values(v)) freeze(value); Object.freeze(v); } return v;
}
export function parseIdentityActionStatus(input: unknown): IdentityActionStatus | null {
  try {
    const v = copyBoundedComparisonData(input, 64 * 1024, 4096);
    if (!keys(v, ['origin', 'change', 'original', 'prepare', 'start', 'permissionLive', 'remainingMs', 'cancelRequested', 'unconfirmed', 'observation', 'doNotReplay', 'historyMustBeQueried']) ||
      !keys(v.origin, ['serviceInstance', 'projectId', 'intentId']) || !Object.values(v.origin).every(token) || !change(v.change) ||
      !keys(v.original, ['operationId', 'ownerGeneration', 'revision']) || !Object.values(v.original).every(token) ||
      !one(v.prepare, steps) || !one(v.start, steps) || typeof v.permissionLive !== 'boolean' || typeof v.cancelRequested !== 'boolean' ||
      typeof v.unconfirmed !== 'boolean' || !integer(v.remainingMs, 900_000) || !v.permissionLive && v.remainingMs !== 0 ||
      v.permissionLive && (v.cancelRequested || v.unconfirmed || v.start === 'submitted') ||
      v.permissionLive && (v.prepare === 'refused' || v.start === 'refused' || v.prepare === 'unconfirmed' || v.start === 'unconfirmed') ||
      (v.prepare === 'unconfirmed' || v.start === 'unconfirmed') && !v.unconfirmed ||
      v.doNotReplay !== true || v.historyMustBeQueried !== true ||
      v.observation !== null && (!observation(v.observation, v.change, v.original.revision as string) ||
        v.observation.applySubmitted && !one(v.start, ['submitted', 'unconfirmed']) ||
        v.observation.review !== null && !one(v.prepare, ['submitted', 'unconfirmed']))) return null;
    return freeze(v) as unknown as IdentityActionStatus;
  } catch { return null; }
}
export function encodeIdentityActionRequest(command: AgentIdentityActionCommand, input: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(input, 4096, 64);
    const valid = command === 'allow_agent_identity_action'
      ? keys(v, ['intentId', 'sessionId', 'revision', 'acknowledgeNewApplication', 'consentVersion']) && token(v.intentId) && token(v.sessionId) && token(v.revision) &&
        typeof v.acknowledgeNewApplication === 'boolean' && v.consentVersion === AGENT_IDENTITY_ACTION_CONSENT
      : (command === 'agent_identity_action_status' || command === 'revoke_agent_identity_action') && keys(v, ['intentId']) && token(v.intentId);
    return valid ? new TextEncoder().encode(JSON.stringify(v)) : null;
  } catch { return null; }
}
export function createAgentIdentityActionApi(mode: string, invoke: (c: AgentIdentityActionCommand, raw: Uint8Array) => Promise<unknown>): AgentIdentityActionApi | null {
  if (mode !== 'native') return null;
  const call = (command: AgentIdentityActionCommand, value: unknown) => {
    const raw = encodeIdentityActionRequest(command, value); if (!raw) throw new Error('Invalid app ID permission request.'); return invoke(command, raw);
  };
  return Object.freeze({ mode: 'native' as const, allow: (v: IdentityActionAllow) => call('allow_agent_identity_action', v),
    status: (intentId: string) => call('agent_identity_action_status', { intentId }), revoke: (intentId: string) => call('revoke_agent_identity_action', { intentId }) });
}

interface Source { api: AgentIdentityActionApi | null; connection: object | null; proposal: AgentIdentityProposal | null;
  native: ProjectIdentityNativeController; editor: ProjectIdentityController; epoch: number; projectId: string | null; blocked: boolean }
interface Binding { connection: object; proposal: AgentIdentityProposal; epoch: number; window: string; original: Original;
  checkout: IdentityCheckout & { view: IdentityAnalysis }; acknowledged: boolean }
interface Work { promise: Promise<unknown> | null; epoch: number; kind: 'allow' | 'status' | 'revoke' }
export interface AgentIdentityActionView {
  analysis: IdentityAnalysis | null; change: Change | null; reviewed: boolean; claimed: boolean; status: IdentityActionStatus | null;
  pending: number; canAllow: boolean; canCheck: boolean; canRevoke: boolean; message: string; attention: boolean;
}
const UNKNOWN = 'The original permission or edit could not be confirmed. Keep its IDs, check status or request Stop. Do not repeat the change.';

/** No native effects on construction/subscription. Root retains this alongside
 * the SAME original editor, and calls beforeContextIntent before every intent. */
export class AgentIdentityActionController {
  readonly #current: () => Source;
  readonly #api: AgentIdentityActionApi | null;
  readonly #calls: AgentIdentityActionApi | null;
  readonly #native: ProjectIdentityNativeController;
  readonly #editor: ProjectIdentityController;
  readonly #proposal: AgentIdentityProposal | null;
  #ack: Binding | null = null;
  #bound: Binding | null = null;
  #claimed = false;
  #retired = false;
  #uncertain = false;
  #epoch = 0;
  #normal: Work | null = null;
  #revoke: Work | null = null;
  #status: IdentityActionStatus | null = null;
  #message: string | null = null;
  #listeners = new Set<() => void>();
  #notifying = false;
  #state!: AgentIdentityActionView;
  constructor(current: () => Source) {
    this.#current = current; const c = current(); this.#api = c.api; this.#native = c.native; this.#editor = c.editor; this.#proposal = c.proposal;
    const api = this.#api;
    const allow = api?.allow, status = api?.status, revoke = api?.revoke;
    this.#calls = api?.mode === 'native' && typeof allow === 'function' && typeof status === 'function' && typeof revoke === 'function'
      ? Object.freeze({ mode: 'native' as const, allow: (input: IdentityActionAllow) => allow.call(api, input),
        status: (intentId: string) => status.call(api, intentId), revoke: (intentId: string) => revoke.call(api, intentId) }) : null;
    this.sync();
  }
  getSnapshot = (): AgentIdentityActionView => this.#state;
  subscribe = (fn: () => void): (() => void) => { this.#listeners.add(fn); return () => { this.#listeners.delete(fn); }; };
  #source(): Source | null { try { const c = this.#current(); return c.api === this.#api && c.api?.mode === 'native' && c.native === this.#native &&
    this.#calls && c.editor === this.#editor && c.proposal === this.#proposal && c.connection && c.projectId === c.proposal?.runtimeId && !c.blocked && integer(c.epoch, Number.MAX_SAFE_INTEGER - 1) ? c : null; } catch { return null; } }
  #capture(): Binding | null {
    const c = this.#source(), n = this.#native.getState(), ui = this.#editor.getSnapshot(), p = n.original, view = p?.checkout?.view;
    if (!c?.proposal || n.issue || n.pendingCount || !n.initialized || !n.listening || !n.status?.capability.available || !p || p.intent !== 'edit' ||
      p.projectId !== c.projectId || p.diagnostic || p.nativeReason !== 'none' || p.phase !== 'editing' || p.prepared || p.applySubmitted || p.reviewRemainingMs <= 0 ||
      !p.checkout || view?.kind !== 'project-identity' || view.state !== 'supported' || ui.session?.sessionId !== p.sessionId || !ui.canEditDraft ||
      !identityDataEqual(c.proposal.request.change.selection, { platform: view.selection.platform, target: view.selection.target, project: view.selection.project })) return null;
    const desired = c.proposal.request.change, changing = desired.desiredIdentity !== view.identity;
    if (ui.intent !== desired.identityIntent || (ui.intent === 'preserve' ? view.identity : ui.desiredIdentity) !== desired.desiredIdentity ||
      desired.identityIntent === 'new-application' && !ui.newApplicationAcknowledged ||
      changing && (desired.identityIntent !== 'new-application' || !ui.newApplicationAcknowledged || view.selection.continuity !== 'unknown' || view.identityStatus !== 'unverified')) return null;
    return { connection: c.connection!, proposal: c.proposal, epoch: c.epoch, window: n.status.windowGeneration,
      original: { operationId: p.sessionId, ownerGeneration: p.ownerGeneration, revision: p.checkout.revision },
      checkout: p.checkout as Binding['checkout'], acknowledged: ui.newApplicationAcknowledged };
  }
  #same(a: Binding | null, b: Binding | null): boolean { return !!a && !!b && a.connection === b.connection && a.proposal === b.proposal && a.epoch === b.epoch &&
    a.window === b.window && a.acknowledged === b.acknowledged && identityDataEqual(a.original, b.original) && identityDataEqual(a.checkout, b.checkout); }
  #currentBinding(b: Binding): boolean {
    const c = this.#source(), n = this.#native.getState(), p = n.original, ui = this.#editor.getSnapshot();
    return !!c && c.connection === b.connection && c.proposal === b.proposal && c.epoch === b.epoch && n.status?.windowGeneration === b.window &&
      p?.sessionId === b.original.operationId && p.ownerGeneration === b.original.ownerGeneration && identityDataEqual(p.checkout, b.checkout) &&
      ui.intent === b.proposal.request.change.identityIntent && ui.newApplicationAcknowledged === b.acknowledged &&
      (ui.intent === 'preserve' ? b.checkout.view.identity : ui.desiredIdentity) === b.proposal.request.change.desiredIdentity;
  }
  sync = (): void => {
    const f = this.#capture(); if (this.#ack && !this.#same(this.#ack, f)) this.#ack = null;
    const pending = Number(this.#normal !== null) + Number(this.#revoke !== null), status = this.#status, observation = status?.observation;
    let message = this.#message ?? 'Read the requested source, then allow only this exact change. The agent can preview and start it once; you do not need to Apply again here.';
    let attention = this.#uncertain || status?.unconfirmed === true || observation?.settlement === 'unknown';
    if (attention) message = UNKNOWN;
    else if (pending) message = this.#revoke ? 'Requesting Stop. The original operation must still finish.' : 'Checking the original permission. No completion is assumed.';
    else if (observation?.settlement === 'settled') {
      message = observation.state === 'succeeded' ? (observation.effect === 'unchanged' ? 'The original operation kept the app ID unchanged.' : 'The original ID edit finished. Recheck credentials and the built app before release.') :
        observation.state === 'recovery-required' ? 'The ID edit needs recovery in the original Desktop editor. Do not start it again.' : 'The original ID operation stopped or failed. Read its final status before any new proposal.';
      attention = observation.state !== 'succeeded';
    } else if (this.#retired || status?.cancelRequested) message = 'This permission is retired. Check the original status; a Stop request is not completed cleanup.';
    else if (status?.permissionLive) message = 'Only this source and requested ID are allowed. The agent may preview and start once before the original review expires.';
    else if (this.#claimed) message = 'The one-use request is retained. Check status; do not create a replacement or repeat Apply.';
    this.#state = Object.freeze({ analysis: f?.checkout.view ?? this.#bound?.checkout.view ?? null, change: this.#proposal?.request.change ?? null,
      reviewed: this.#ack !== null, claimed: this.#claimed, status, pending, canAllow: !!f && !this.#claimed && !this.#retired && !this.#uncertain && pending === 0 && this.#ack !== null,
      canCheck: !!this.#calls && !!this.#proposal && pending === 0, canRevoke: !!this.#calls && !!this.#proposal && this.#revoke === null,
      message, attention });
    if (this.#notifying) return; this.#notifying = true;
    try { for (const fn of [...this.#listeners]) { try { fn(); } catch { /* A view cannot dispose original work. */ } } } finally { this.#notifying = false; }
  };
  acknowledge(value: boolean): boolean {
    if (this.#claimed || this.#retired || this.#normal || this.#revoke || this.#uncertain) return false;
    this.#ack = value ? this.#capture() : null; this.sync(); return !value || this.#ack !== null;
  }
  allow(): boolean {
    const f = this.#capture(); if (!f || !this.#same(this.#ack, f) || this.#claimed || this.#retired || this.#uncertain || this.#normal || this.#revoke || !this.#api) return false;
    this.#claimed = true; this.#bound = f; this.#ack = null;
    const work: Work = { promise: null, epoch: this.#epoch, kind: 'allow' }; this.#normal = work; this.sync();
    if (this.#retired || work.epoch !== this.#epoch || !this.#currentBinding(f) ||
      !this.#native.expectAgentIdentityAction({ sessionId: f.original.operationId, revision: f.original.revision,
        desiredIdentity: f.proposal.request.change.desiredIdentity, intent: f.proposal.request.change.identityIntent }) ||
      this.#retired || work.epoch !== this.#epoch || !this.#currentBinding(f)) { this.#finish(work); return false; }
    return this.#send(work, () => this.#calls!.allow({ intentId: f.proposal.request.intentId, sessionId: f.original.operationId,
      revision: f.original.revision, acknowledgeNewApplication: f.acknowledged, consentVersion: AGENT_IDENTITY_ACTION_CONSENT }));
  }
  check(): boolean {
    if (!this.#calls || !this.#proposal || this.#normal || this.#revoke) return false;
    const work: Work = { promise: null, epoch: this.#epoch, kind: 'status' }; this.#normal = work; this.sync();
    if (work.epoch !== this.#epoch || this.#revoke) { this.#finish(work); return false; }
    return this.#send(work, () => this.#calls!.status(this.#proposal!.request.intentId));
  }
  revoke(): boolean {
    if (!this.#calls || !this.#proposal || this.#revoke) return false;
    this.#retired = true; this.#ack = null; this.#epoch = Math.min(Number.MAX_SAFE_INTEGER, this.#epoch + 1);
    const work: Work = { promise: null, epoch: this.#epoch, kind: 'revoke' }; this.#revoke = work; this.sync();
    return this.#send(work, () => this.#calls!.revoke(this.#proposal!.request.intentId));
  }
  #send(work: Work, call: () => Promise<unknown>): boolean {
    try {
      const promise = call(); if (!promise || typeof promise.then !== 'function') throw new Error('Unconfirmed');
      work.promise = promise;
      void Promise.resolve(promise).then(value => this.#receive(work, value), () => { if (work.epoch === this.#epoch) this.#uncertain = true; })
        .finally(() => this.#finish(work)); return true;
    } catch { this.#uncertain = true; this.#finish(work); return false; }
  }
  #receive(work: Work, raw: unknown): void {
    if (work.epoch !== this.#epoch) return;
    if (raw === null && !this.#claimed) { this.#message = 'No one-use edit permission was observed. Proposal permission alone cannot edit files.'; return; }
    if (work.kind === 'allow' && this.#bound && !this.#currentBinding(this.#bound)) { this.beforeContextIntent(); return; }
    const s = parseIdentityActionStatus(raw), p = this.#proposal?.request;
    if (!s || !p || !identityDataEqual(s.origin, { serviceInstance: p.serviceInstance, projectId: p.projectId, intentId: p.intentId }) || !identityDataEqual(s.change, p.change) ||
      this.#bound && (!identityDataEqual(s.original, this.#bound.original) || s.observation?.review &&
        (s.observation.review.beforeIdentity !== this.#bound.checkout.view.identity ||
         !s.observation.review.unchanged && !identityDataEqual(s.observation.review.changes, this.#bound.checkout.view.locations)))) { this.#uncertain = true; return; }
    const old = this.#status, before = old?.observation, after = s.observation;
    const advances = (a: Step, b: Step) => a === b || (a === 'not-requested' || a === 'queued' || a === 'admitting') &&
      steps.indexOf(b) > steps.indexOf(a) || a === 'submitted' && b === 'unconfirmed';
    if (old && (!advances(old.prepare, s.prepare) || !advances(old.start, s.start) || !old.permissionLive && s.permissionLive ||
      old.permissionLive && s.permissionLive && s.remainingMs > old.remainingMs || !identityDataEqual(old.original, s.original) || old.unconfirmed && !s.unconfirmed || old.cancelRequested && !s.cancelRequested ||
      before && (!after || after.statusRevision < before.statusRevision || after.statusRevision === before.statusRevision && !identityDataEqual(before, after) || before.settlement === 'unknown' && after.settlement !== 'unknown' ||
        before.settlement === 'settled' && !identityDataEqual(before, after) || before.review && !identityDataEqual(before.review, after.review) || before.applySubmitted && !after.applySubmitted))) {
      this.#uncertain = true; return;
    }
    this.#status = s;
    if (s.unconfirmed || s.observation?.settlement === 'unknown') this.#uncertain = true;
  }
  #finish(work: Work): void { if (this.#normal === work) this.#normal = null; if (this.#revoke === work) this.#revoke = null; this.sync(); }
  beforeContextIntent(): void {
    const wasRetired = this.#retired;
    this.#retired = true; this.#ack = null; this.#epoch = Math.min(Number.MAX_SAFE_INTEGER, this.#epoch + 1);
    // Original Apply publication itself invalidates local inputs. Preserve its
    // ordinary semantics: that notification must not cancel the admitted edit.
    if (!wasRetired && this.#claimed && !this.#native.agentIdentityApplySubmitted()) this.revoke(); else this.sync();
  }
  pendingReason(): string | null { return this.#normal || this.#revoke ? 'The original app ID permission request is still finishing.' : this.#uncertain ? UNKNOWN : null; }
}
