// Operation-specific renderer transport/custody for the ORIGINAL native
// ProjectIdentity EditOwner. A returned true means one original request was
// handed off and retained, never native admission, completed work or a save.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { identityDataEqual, identityPreviewMatches, identityValueFits, parseIdentityContext,
  parseIdentityOwnerSnapshot } from './projectIdentity.ts';
import type { IdentityApplyRequest, IdentityIntent, IdentityNativePort, IdentityOwnerSnapshot,
  IdentityOwnerStatus, IdentityProjection, IdentitySelection, IdentitySessionRequest, IdentityUiContext } from './projectIdentity.ts';

export const PROJECT_IDENTITY_EVENT = 'project-identity-state-changed';
export type ProjectIdentityCommand = 'project_identity_open' | 'project_identity_prepare' |
  'project_identity_apply' | 'project_identity_close' | 'project_identity_status';
type Target = Omit<IdentitySelection, 'continuity'>;
export type IdentityOpenRequest = { intent: 'edit'; projectId: string; selection: Target } | { intent: 'recover'; projectId: string };
export type IdentityPrepareRequest = IdentitySessionRequest &
  ({ intent: 'edit'; desiredIdentity: string; identityIntent: IdentityIntent } | { intent: 'recover' });
export type IdentitySendRequest = IdentityApplyRequest & { intent: 'edit' | 'recover' };
type Invoke = (command: ProjectIdentityCommand, body: Uint8Array) => Promise<unknown>;
type Listen = (event: typeof PROJECT_IDENTITY_EVENT, listener: (value: unknown) => void) => Promise<() => void>;
export interface ProjectIdentityApi {
  readonly mode: 'native';
  open(request: IdentityOpenRequest): Promise<unknown>;
  prepare(request: IdentityPrepareRequest): Promise<unknown>;
  apply(request: IdentitySendRequest): Promise<unknown>;
  close(request: { sessionId: string }): Promise<unknown>;
  status(): Promise<unknown>;
  subscribe(listener: (value: unknown) => void): Promise<() => void>;
}
const failure = () => ({ code: 'ProjectIdentityUnconfirmed', message: 'The original app ID request could not be confirmed. Check its status; do not repeat the change.', retryable: false as const });
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => record(v) &&
  Object.keys(v).length === names.length && names.every((name) => Object.hasOwn(v, name));
const token = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
function uiArguments(input: unknown, names: string[]): Record<string, unknown> | null {
  try { const safe = copyBoundedComparisonData(input, 4096, 128); return keys(safe, names) ? safe : null; }
  catch { return null; }
}

/** Exact RAW JSON boundary. This validates syntax, not roots or continuity. */
export function encodeProjectIdentityRequest(command: ProjectIdentityCommand, input: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(input, 16 * 1024, 128);
    let valid = false;
    if (command === 'project_identity_status') valid = keys(v, []);
    else if (command === 'project_identity_close') valid = keys(v, ['sessionId']) && token(v.sessionId);
    else if (command === 'project_identity_open' && record(v)) {
      const id = typeof v.projectId === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v.projectId);
      if (v.intent === 'recover') valid = id && keys(v, ['intent', 'projectId']);
      else if (v.intent === 'edit' && keys(v, ['intent', 'projectId', 'selection']) && keys(v.selection, ['platform', 'target', 'project'])) {
        // UNKNOWN here is only an input grammar check. It is NOT sent. Native
        // supplies its own continuity and independently vetoes existing apps.
        valid = id && parseIdentityContext({ projectId: v.projectId, selection: { ...v.selection, continuity: 'unknown' },
          contextEpoch: 0, preview: false, blocked: false }) !== null;
      }
    } else if (command === 'project_identity_prepare' && record(v)) {
      const binding = token(v.sessionId) && token(v.revision);
      valid = binding && (v.intent === 'recover' ? keys(v, ['intent', 'sessionId', 'revision']) :
        v.intent === 'edit' && keys(v, ['intent', 'sessionId', 'revision', 'desiredIdentity', 'identityIntent']) &&
        (v.identityIntent === 'preserve' || v.identityIntent === 'new-application') &&
        (identityValueFits(v.desiredIdentity, 'android') || identityValueFits(v.desiredIdentity, 'ios')));
    } else if (command === 'project_identity_apply') valid = keys(v, ['intent', 'sessionId', 'revision', 'planToken']) &&
      (v.intent === 'edit' || v.intent === 'recover') && token(v.sessionId) && token(v.revision) && token(v.planToken) && v.revision !== v.planToken;
    return valid ? new TextEncoder().encode(JSON.stringify(v)) : null;
  } catch { return null; }
}

/** Root injects only its real native invoke/listen; no preview or HTTP fallback. */
export function createProjectIdentityApi(mode: string, invoke: Invoke, listen?: Listen): ProjectIdentityApi | null {
  if (mode !== 'native' || !listen) return null;
  const call = (command: ProjectIdentityCommand, request: unknown): Promise<unknown> => {
    const body = encodeProjectIdentityRequest(command, request);
    if (!body) throw { code: 'ProjectIdentityRequestInvalid', message: 'The app ID request is invalid. Nothing was sent.', retryable: false };
    return invoke(command, body);
  };
  return Object.freeze({ mode: 'native' as const,
    open: (r: IdentityOpenRequest) => call('project_identity_open', r),
    prepare: (r: IdentityPrepareRequest) => call('project_identity_prepare', r),
    apply: (r: IdentitySendRequest) => call('project_identity_apply', r),
    close: (r: { sessionId: string }) => call('project_identity_close', r),
    status: () => call('project_identity_status', {}),
    subscribe: (listener: (value: unknown) => void) => listen(PROJECT_IDENTITY_EVENT, listener) });
}


// Identity proposals are DATA in the running Desktop, not CLI write permits.
export type AgentIdentityCommand = 'agent_identity_status' | 'allow_agent_identity' | 'revoke_agent_identity' |
  'decline_agent_identity' | 'review_agent_identity' | 'prepare_agent_identity' | 'apply_agent_identity';
export interface AgentIdentityProposal {
  runtimeId: string;
  request: { serviceInstance: string; intentId: string; projectId: string; expectedObservationRevision: number;
    change: { selection: Target; desiredIdentity: string; identityIntent: IdentityIntent } };
}
export interface AgentIntentObservation {
  serviceInstance: string; projectId: string; intentId: string;
  state: 'queued' | 'desktop-review' | 'original-sid-available' | 'declined' | 'expired' | 'refused-before-claim' | 'admission-unconfirmed';
  operationId: string | null; originalLinkRetained: boolean; historyMustBeQueried: boolean;
}
export interface AgentIdentityGuiStatus {
  lease: { enabled: boolean; remainingMs: number; projectId: string | null };
  pending: AgentIdentityProposal | null; requests: readonly AgentIntentObservation[];
}
export interface AgentIdentityCheck extends AgentIdentityGuiStatus { readonly permissionRevision: string }
export interface AgentIdentityApi {
  readonly mode: 'native';
  status(): Promise<unknown>; allow(projectId: string, expectedPermissionRevision: string): Promise<unknown>; revoke(): Promise<unknown>;
  decline(intentId: string): Promise<unknown>; review(intentId: string): Promise<unknown>;
  prepare(args: { intentId: string; sessionId: string; revision: string; acknowledgeNewApplication: boolean }): Promise<unknown>;
  apply(args: { intentId: string; sessionId: string; revision: string; planToken: string; reviewed: boolean }): Promise<unknown>;
}
const agentToken = (v: unknown): v is string => token(v) && v !== '0'.repeat(32);
const runtimeProject = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v);
export const agentIdentityPermissionRevisionFits = (v: unknown): v is string => typeof v === 'string' &&
  /^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(v) && (v.length < 20 || v <= '18446744073709551615');
function agentProposal(value: unknown): AgentIdentityProposal | null {
  if (!keys(value, ['runtimeId', 'request']) || !runtimeProject(value.runtimeId) ||
      !keys(value.request, ['serviceInstance', 'intentId', 'projectId', 'expectedObservationRevision', 'change'])) return null;
  const r = value.request;
  if (!agentToken(r.serviceInstance) || !agentToken(r.intentId) || !agentToken(r.projectId) ||
      !Number.isSafeInteger(r.expectedObservationRevision) || (r.expectedObservationRevision as number) <= 0 ||
      !keys(r.change, ['selection', 'desiredIdentity', 'identityIntent']) ||
      !keys(r.change.selection, ['platform', 'target', 'project']) ||
      !encodeProjectIdentityRequest('project_identity_open', { intent: 'edit', projectId: value.runtimeId, selection: r.change.selection }) ||
      !['android', 'ios'].includes(r.change.selection.platform as string) ||
      !identityValueFits(r.change.desiredIdentity, r.change.selection.platform as 'android' | 'ios') ||
      !['preserve', 'new-application'].includes(r.change.identityIntent as string)) return null;
  Object.freeze(r.change.selection); Object.freeze(r.change); Object.freeze(r);
  return Object.freeze(value) as unknown as AgentIdentityProposal;
}
function agentObservation(value: unknown): value is AgentIntentObservation {
  if (!keys(value, ['serviceInstance', 'projectId', 'intentId', 'state', 'operationId', 'originalLinkRetained', 'historyMustBeQueried']) ||
      !agentToken(value.serviceInstance) || !agentToken(value.projectId) || !agentToken(value.intentId) ||
      !['queued', 'desktop-review', 'original-sid-available', 'declined', 'expired', 'refused-before-claim', 'admission-unconfirmed'].includes(value.state as string) ||
      value.operationId !== null && !agentToken(value.operationId) || typeof value.originalLinkRetained !== 'boolean' ||
      typeof value.historyMustBeQueried !== 'boolean') return false;
  const linked = value.operationId !== null;
  return value.historyMustBeQueried === linked && (!value.originalLinkRetained || linked) &&
    (value.state !== 'original-sid-available' || linked) &&
    (!linked || value.state === 'original-sid-available' || value.state === 'admission-unconfirmed');
}
export function parseAgentIdentityGuiStatus(input: unknown): AgentIdentityGuiStatus | null {
  try {
    const v = copyBoundedComparisonData(input, 64 * 1024, 4096);
    return agentGuiStatusData(v);
  } catch { return null; }
}
// Called only after the original bounded descriptor-safe copy, including the
// MAIN wrapper below. Do not duplicate the retained proposal/status graph.
function agentGuiStatusData(v: unknown): AgentIdentityGuiStatus | null {
    if (!keys(v, ['lease', 'pending', 'requests']) || !keys(v.lease, ['enabled', 'remainingMs', 'projectId']) ||
        typeof v.lease.enabled !== 'boolean' || typeof v.lease.remainingMs !== 'number' || !Number.isSafeInteger(v.lease.remainingMs) ||
        v.lease.remainingMs < 0 || v.lease.remainingMs > 900_000 ||
        (v.lease.projectId !== null && !agentToken(v.lease.projectId)) ||
        (v.lease.enabled ? !agentToken(v.lease.projectId) : v.lease.projectId !== null || v.lease.remainingMs !== 0) ||
        !Array.isArray(v.requests) || v.requests.length > 32 || !v.requests.every(agentObservation)) return null;
    if (new Set(v.requests.map((row) => row.intentId)).size !== v.requests.length) return null;
    const pending = v.pending === null ? null : agentProposal(v.pending);
    if (v.pending !== null && (!pending || !v.requests.some((row) => row.intentId === pending.request.intentId &&
        row.projectId === pending.request.projectId && row.serviceInstance === pending.request.serviceInstance && row.state === 'queued'))) return null;
    v.requests.forEach(Object.freeze); Object.freeze(v.requests);
    const lease = Object.freeze({ enabled: v.lease.enabled, remainingMs: v.lease.remainingMs, projectId: v.lease.projectId });
    return Object.freeze({ lease, pending, requests: v.requests });
}
export function parseAgentIdentityCheck(input: unknown): AgentIdentityCheck | null {
  try {
    const v = copyBoundedComparisonData(input, 64 * 1024, 4096);
    if (!keys(v, ['lease', 'pending', 'requests', 'permissionRevision']) || !agentIdentityPermissionRevisionFits(v.permissionRevision)) return null;
    const status = agentGuiStatusData({ lease: v.lease, pending: v.pending, requests: v.requests });
    return status ? Object.freeze({ ...status, permissionRevision: v.permissionRevision }) : null;
  } catch { return null; }
}
export function encodeAgentIdentityRequest(command: AgentIdentityCommand, input: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(input, 4096, 128);
    let valid = false;
    if (command === 'agent_identity_status' || command === 'revoke_agent_identity') valid = keys(v, []);
    if (command === 'allow_agent_identity') valid = keys(v, ['projectId', 'expectedPermissionRevision']) &&
      runtimeProject(v.projectId) && agentIdentityPermissionRevisionFits(v.expectedPermissionRevision);
    if (command === 'decline_agent_identity' || command === 'review_agent_identity') valid = keys(v, ['intentId']) && agentToken(v.intentId);
    if (command === 'prepare_agent_identity') valid = keys(v, ['intentId', 'sessionId', 'revision', 'acknowledgeNewApplication']) &&
      agentToken(v.intentId) && agentToken(v.sessionId) && agentToken(v.revision) && typeof v.acknowledgeNewApplication === 'boolean';
    if (command === 'apply_agent_identity') valid = keys(v, ['intentId', 'sessionId', 'revision', 'planToken', 'reviewed']) &&
      agentToken(v.intentId) && agentToken(v.sessionId) && agentToken(v.revision) && agentToken(v.planToken) &&
      v.revision !== v.planToken && typeof v.reviewed === 'boolean';
    if (!valid) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length <= 4096 ? bytes : null;
  } catch { return null; }
}
export function createAgentIdentityApi(mode: string,
    invoke: (command: AgentIdentityCommand, body: Uint8Array) => Promise<unknown>): AgentIdentityApi | null {
  if (mode !== 'native') return null;
  const call = (command: AgentIdentityCommand, input: unknown) => {
    const body = encodeAgentIdentityRequest(command, input);
    if (!body) throw failure();
    return invoke(command, body);
  };
  return Object.freeze({ mode: 'native' as const, status: () => call('agent_identity_status', {}),
    allow: (projectId: string, expectedPermissionRevision: string) => call('allow_agent_identity', { projectId, expectedPermissionRevision }), revoke: () => call('revoke_agent_identity', {}),
    decline: (intentId: string) => call('decline_agent_identity', { intentId }), review: (intentId: string) => call('review_agent_identity', { intentId }),
    prepare: (args: Parameters<AgentIdentityApi['prepare']>[0]) => call('prepare_agent_identity', args),
    apply: (args: Parameters<AgentIdentityApi['apply']>[0]) => call('apply_agent_identity', args) });
}
/** One immutable proposal, explicit GUI controls and the ORIGINAL native
 * controller/preview. This adapter cannot mint a SID or a history receipt. */
export function bindAgentIdentityApi(base: ProjectIdentityApi, agent: AgentIdentityApi, value: AgentIdentityProposal): ProjectIdentityApi | null {
  let proposal: AgentIdentityProposal | null;
  try { proposal = agentProposal(copyBoundedComparisonData(value, 4096, 128)); } catch { return null; }
  if (!proposal || base.mode !== 'native' || agent.mode !== 'native') return null;
  const { open, prepare, apply, close, status, subscribe } = base;
  const review = agent.review, prepareIntent = agent.prepare, applyIntent = agent.apply;
  const retained = proposal, id = retained.request.intentId, change = retained.request.change;
  let sent = false;
  return Object.freeze({ mode: 'native' as const,
    open: (request: IdentityOpenRequest) => {
      if (!encodeProjectIdentityRequest('project_identity_open', request)) throw failure();
      // Explicit ordinary GUI recovery remains its separate original action.
      // It never reuses the proposal link or replaces its remembered SID.
      if (request.intent === 'recover') return open.call(base, request);
      if (sent || request.projectId !== retained.runtimeId || !identityDataEqual(request.selection, change.selection)) throw failure();
      sent = true; return review.call(agent, id);
    },
    prepare: (request: IdentityPrepareRequest) => {
      if (!encodeProjectIdentityRequest('project_identity_prepare', request)) throw failure();
      if (request.intent === 'recover') return prepare.call(base, request);
      if (!sent || request.desiredIdentity !== change.desiredIdentity || request.identityIntent !== change.identityIntent) throw failure();
      return prepareIntent.call(agent, { intentId: id, sessionId: request.sessionId, revision: request.revision,
        acknowledgeNewApplication: request.identityIntent === 'new-application' });
    },
    apply: (request: IdentitySendRequest) => {
      if (!encodeProjectIdentityRequest('project_identity_apply', request)) throw failure();
      if (request.intent === 'recover') return apply.call(base, request);
      if (!sent) throw failure();
      return applyIntent.call(agent, { intentId: id, sessionId: request.sessionId, revision: request.revision, planToken: request.planToken, reviewed: true });
    },
    close: (request: { sessionId: string }) => close.call(base, request),
    status: () => status.call(base), subscribe: (listener: (value: unknown) => void) => subscribe.call(base, listener) });
}

type Issue = 'unconfirmed' | 'protocol' | 'generation-changed' | 'cleanup-unknown';
export interface ProjectIdentityNativeState {
  status: IdentityOwnerStatus | null; original: IdentityProjection | null; projectId: string | null;
  pendingCount: number; reading: boolean; initialized: boolean; listening: boolean;
  issue: Issue | null; closeRequested: boolean; closeSent: boolean;
}
interface Source {
  current(): unknown; // The existing IdentityUiContext, never an authority token.
  otherOperationReason?(projectId: string): string | null;
  onMutationSubmitted?(projectId: string, intent: 'edit' | 'recover'): void;
  onOutcome?(original: IdentityProjection): void; // Invalidate observations, never adopt a draft.
}
interface Attempt {
  context: IdentityUiContext; stamp: number; window: string; after: number; previous: string | null;
  request: IdentityOpenRequest; sessionId: string | null; projection: IdentityProjection | null;
  preparation: IdentityPrepareRequest | null;
  delegated: IdentityPrepareRequest | null; mutationPublished: boolean;
  retired: boolean; sent: boolean; prepareClaimed: boolean; applyClaimed: boolean; applySent: boolean;
  closeRequested: boolean; closeSent: boolean; outcomePublished: boolean;
}
interface Work { kind: 'open' | 'prepare' | 'apply' | 'close' | 'status'; promise: Promise<unknown> | null }
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const terminal = (p: IdentityProjection | null) => p?.phase === 'final' || p?.phase === 'unknown';
const facts = (p: IdentityProjection) => ({ ...p, reviewRemainingMs: 0 });
function progresses(a: IdentityProjection, b: IdentityProjection): boolean {
  if (a.domain !== b.domain || a.intent !== b.intent || a.projectId !== b.projectId || a.sessionId !== b.sessionId ||
    a.ownerGeneration !== b.ownerGeneration || a.checkout && !identityDataEqual(a.checkout, b.checkout) ||
    a.prepared && !identityDataEqual(a.prepared, b.prepared) || a.diagnostic && !identityDataEqual(a.diagnostic, b.diagnostic) ||
    a.applySubmitted && !b.applySubmitted || a.lateSettled && !b.lateSettled ||
    a.nativeReason !== 'none' && a.nativeReason !== b.nativeReason || phases.indexOf(b.phase) < phases.indexOf(a.phase)) return false;
  if (a.phase === 'final') return identityDataEqual(facts(a), facts(b));
  if (a.phase === 'unknown' && b.phase !== 'unknown') return false;
  if (a.coreOutcome) {
    if (!b.coreOutcome) return false;
    // A complete core receipt is immutable, independently of native finality.
    for (const key of ['effect', 'journal', 'resources', 'reason'] as const) {
      if (a.coreOutcome[key] !== 'unknown' && a.coreOutcome[key] !== b.coreOutcome[key]) return false;
    }
  }
  return true;
}
const parseStatus = (v: unknown): IdentityOwnerStatus | null => parseIdentityOwnerSnapshot({ busy: false, status: v })?.status ?? null;

export class ProjectIdentityNativeController implements IdentityNativePort {
  readonly mode = 'native' as const;
  readonly #api: ProjectIdentityApi;
  readonly #source: Source;
  #status: IdentityOwnerStatus | null = null;
  #buffer: IdentityOwnerStatus | null = null;
  #initialized = false;
  #off: (() => void) | null = null;
  #read: Work | null = null;
  #works = new Set<Work>();
  #attempt: Attempt | null = null;
  #seen = new Map<string, IdentityProjection>();
  #issue: Issue | null = null;
  #stamp = 0;
  #disposed = false;
  #notifying = false;
  #listeners = new Set<() => void>();
  #snapshot: IdentityOwnerSnapshot = Object.freeze({ busy: false, status: null });
  #state!: ProjectIdentityNativeState;

  constructor(api: ProjectIdentityApi, source: Source) {
    // Capture one original connection. Later method/property replacement is
    // never a route for a pending token; Root retains this controller on rebind.
    const { open, prepare, apply, close, status, subscribe } = api;
    if (api.mode !== 'native' || ![open, prepare, apply, close, status, subscribe].every((f) => typeof f === 'function')) throw failure();
    this.#api = Object.freeze({ mode: 'native' as const,
      open: (r: IdentityOpenRequest) => open.call(api, r), prepare: (r: IdentityPrepareRequest) => prepare.call(api, r),
      apply: (r: IdentitySendRequest) => apply.call(api, r), close: (r: { sessionId: string }) => close.call(api, r),
      status: () => status.call(api), subscribe: (listener: (v: unknown) => void) => subscribe.call(api, listener) });
    this.#source = source; this.#publish();
  }
  getSnapshot = (): IdentityOwnerSnapshot => this.#snapshot;
  getState = (): ProjectIdentityNativeState => this.#state;
  subscribe = (listener: () => void): (() => void) => { this.#listeners.add(listener); return () => { this.#listeners.delete(listener); }; };
  #current(): IdentityUiContext | null { try { return parseIdentityContext(this.#source.current()); } catch { return null; } }
  #other(projectId: string): boolean { try { return !!this.#source.otherOperationReason?.(projectId); } catch { return true; } }
  #original(): IdentityProjection | null { return this.#attempt ? this.#attempt.projection : this.#status?.active ?? this.#status?.lastTerminal ?? null; }
  #publish(): void {
    const visible = this.#issue === null ? this.#status : null;
    this.#snapshot = Object.freeze({ busy: this.#works.size !== 0, status: this.#initialized ? visible : null });
    this.#state = Object.freeze({ status: this.#status, original: this.#original(), projectId: this.#attempt?.context.projectId ?? this.#original()?.projectId ?? null,
      pendingCount: this.#works.size,
      reading: this.#read !== null, initialized: this.#initialized, listening: this.#off !== null, issue: this.#issue,
      closeRequested: this.#attempt?.closeRequested ?? false, closeSent: this.#attempt?.closeSent ?? false });
    if (this.#notifying) return;
    this.#notifying = true;
    try { for (const listener of [...this.#listeners]) { try { listener(); } catch { /* A view cannot release original work. */ } } }
    finally { this.#notifying = false; }
  }
  #fail(issue: Issue): void {
    if (this.#issue === null || this.#issue === 'unconfirmed') this.#issue = issue;
    this.#publish();
  }
  /** Root includes this in other-action, reconnect and passive-read admission. */
  ownerReason(projectId?: string): string | null {
    if (this.#issue) return 'The original app ID status needs attention. Check that original request; do not repeat the change or reconnect to dismiss it.';
    if (this.#works.size) return 'An app ID request is still finishing. Its original status and cancellation controls remain available.';
    if (this.#status?.active || this.#attempt?.sent && !terminal(this.#attempt.projection)) return 'Finish or close the original app ID review before starting another task.';
    const p = this.#original();
    return p?.coreOutcome?.journal === 'recovery_required' && (!projectId || p.projectId === projectId)
      ? 'This project has an interrupted app ID change. Preserve its files and review the separate recovery.' : null;
  }
  /** Explicit setup only. Component subscriptions never start native work. */
  connect(): boolean { return !this.#initialized && this.checkStatus(); }
  checkStatus(): boolean {
    if (this.#disposed || this.#read) return false;
    const work: Work = { kind: 'status', promise: null };
    this.#read = work; this.#works.add(work); this.#publish();
    if (this.#disposed) { this.#finish(work); return false; }
    try {
      const subscribing = this.#off === null;
      const original = subscribing ? this.#api.subscribe((value) => this.#receive(value, 'event')) : this.#api.status();
      if (!original || typeof original.then !== 'function') throw failure();
      work.promise = original;
      void this.#readOriginal(work, original, subscribing);
      return true;
    } catch { this.#fail('unconfirmed'); this.#finish(work); return false; }
  }
  async #readOriginal(work: Work, original: Promise<unknown>, subscribing: boolean): Promise<void> {
    try {
      let value = await original;
      if (subscribing) {
        if (typeof value !== 'function') { this.#fail('protocol'); return; }
        this.#off = value as () => void;
        if (this.#disposed && !this.#attempt?.sent) return;
        // Subscribe before the first read; events alone cannot initialize.
        const read = this.#api.status(); work.promise = read;
        value = await read;
      }
      this.#receive(value, 'read');
    } catch { this.#fail('unconfirmed'); }
    finally { this.#finish(work); }
  }
  #finish(work: Work): void {
    this.#works.delete(work);
    if (this.#read === work) this.#read = null;
    this.#publish(); this.#closeOriginal(); this.#detachIfFinished();
  }
  #receive(value: unknown, source: 'event' | 'read' | 'reply'): void {
    const s = parseStatus(value);
    if (!s) { this.#fail('protocol'); return; }
    if (this.#status && s.windowGeneration !== this.#status.windowGeneration) { this.#fail('generation-changed'); return; }
    if (!this.#initialized && source !== 'read') {
      const old = this.#buffer;
      if (old && old.windowGeneration !== s.windowGeneration) { this.#fail('generation-changed'); return; }
      if (old && old.statusRevision === s.statusRevision && !identityDataEqual(
        { ...old, active: old.active && facts(old.active), lastTerminal: old.lastTerminal && facts(old.lastTerminal) },
        { ...s, active: s.active && facts(s.active), lastTerminal: s.lastTerminal && facts(s.lastTerminal) })) { this.#fail('protocol'); return; }
      if (old && s.statusRevision > old.statusRevision) for (const before of [old.active, old.lastTerminal]) {
        const after = before && [s.active, s.lastTerminal].find((p) => p?.sessionId === before.sessionId);
        if (before && after && !progresses(before, after)) { this.#fail('protocol'); return; }
      }
      if (!old || s.statusRevision >= old.statusRevision) {
        const clamp = (p: IdentityProjection | null) => {
          const before = p && old && [old.active, old.lastTerminal].find((v) => v?.sessionId === p.sessionId);
          return p && before ? Object.freeze({ ...p, reviewRemainingMs: Math.min(p.reviewRemainingMs, before.reviewRemainingMs) }) : p;
        };
        this.#buffer = Object.freeze({ ...s, active: clamp(s.active), lastTerminal: clamp(s.lastTerminal) });
      }
      if (s.capability.reason === 'cleanup_unknown' || [s.active, s.lastTerminal].some((p) => p?.nativeFinality === 'unknown')) this.#fail('cleanup-unknown');
      return;
    }
    const prior = this.#status;
    // Even delayed negative evidence cannot become a fresh positive result.
    if (s.capability.reason === 'cleanup_unknown' || [s.active, s.lastTerminal].some((p) => p?.nativeFinality === 'unknown')) this.#fail('cleanup-unknown');
    if (prior && s.statusRevision < prior.statusRevision) return;
    if (prior && s.statusRevision === prior.statusRevision && !identityDataEqual(
      { ...prior, active: prior.active && facts(prior.active), lastTerminal: prior.lastTerminal && facts(prior.lastTerminal) },
      { ...s, active: s.active && facts(s.active), lastTerminal: s.lastTerminal && facts(s.lastTerminal) })) { this.#fail('protocol'); return; }
    for (const p of [s.active, s.lastTerminal]) if (p) {
      const old = this.#seen.get(p.sessionId);
      if (old && !progresses(old, p) || !old && this.#seen.size >= 128) { this.#fail('protocol'); return; }
    }
    const clamp = (p: IdentityProjection | null): IdentityProjection | null => {
      if (!p) return null;
      const old = this.#seen.get(p.sessionId);
      const kept = old ? Object.freeze({ ...p, reviewRemainingMs: Math.min(old.reviewRemainingMs, p.reviewRemainingMs) }) : p;
      this.#seen.set(kept.sessionId, kept); return kept;
    };
    this.#status = Object.freeze({ ...s, active: clamp(s.active), lastTerminal: clamp(s.lastTerminal) });
    if (source === 'read') this.#initialized = true;
    if (this.#issue === 'unconfirmed') this.#issue = null;
    const a = this.#attempt;
    if (a?.sent && a.window === s.windowGeneration && s.statusRevision > a.after) {
      const p = [this.#status.active, this.#status.lastTerminal].find((p) => p && p.projectId === a.context.projectId &&
        p.intent === a.request.intent && (a.sessionId ? p.sessionId === a.sessionId : p.sessionId !== a.previous));
      if (p) {
        if (a.request.intent === 'edit' && p.checkout?.view.kind === 'project-identity' && !identityDataEqual(a.request.selection,
          { platform: p.checkout.view.selection.platform, target: p.checkout.view.selection.target, project: p.checkout.view.selection.project })) {
          this.#fail('protocol'); return;
        }
        const expectedPreparation = a.preparation ?? a.delegated;
        if (p.prepared && (!expectedPreparation || expectedPreparation.intent === 'edit' && (p.checkout?.view.kind !== 'project-identity' ||
          p.prepared.view.kind !== 'project-identity-preview' || !identityPreviewMatches(p.prepared.view, p.checkout.view,
            expectedPreparation.desiredIdentity, expectedPreparation.identityIntent)))) { this.#fail('protocol'); return; }
        a.sessionId = p.sessionId; a.projection = p;
        if (p.applySubmitted && a.delegated && !a.mutationPublished) {
          // Actual original observation, not a permission ACK, invalidates the
          // same saved inputs. Mark submitted BEFORE the reentrant callback.
          a.applySent = true; a.mutationPublished = true;
          try { this.#source.onMutationSubmitted?.(a.context.projectId!, a.request.intent); } catch { this.#fail('unconfirmed'); }
        }
        if (terminal(p) && !a.outcomePublished && (p.phase === 'unknown' || this.#issue === null)) {
          a.outcomePublished = true;
          try { this.#source.onOutcome?.(p); } catch { this.#fail('unconfirmed'); }
        }
      }
    }
    if (a && !a.retired && !identityDataEqual(a.context, this.#current())) this.beforeContextIntent();
    this.#publish(); this.#closeOriginal();
    const buffered = this.#buffer; this.#buffer = null;
    if (buffered) this.#receive(buffered, 'event');
  }
  #ready(): IdentityUiContext | null {
    const c = this.#current();
    return !this.#disposed && this.#initialized && this.#off && !this.#issue && !this.#works.size &&
      this.#status?.capability.available && this.#status.statusRevision < 0xffff_ffff && c?.projectId &&
      c.contextEpoch < Number.MAX_SAFE_INTEGER && !c.preview && !c.blocked && !this.#other(c.projectId) ? c : null;
  }
  #bound(): Attempt | null {
    const a = this.#attempt, c = this.#ready();
    return a && c && !a.retired && a.sent && a.stamp === this.#stamp && identityDataEqual(a.context, c) &&
      a.window === this.#status?.windowGeneration && a.sessionId === this.#status?.active?.sessionId ? a : null;
  }
  #send(kind: Exclude<Work['kind'], 'status'>, a: Attempt, call: () => Promise<unknown>, guard: () => boolean): boolean {
    const work: Work = { kind, promise: null };
    this.#works.add(work); this.#publish();
    if (!guard()) { this.#finish(work); return false; }
    // This is a local handoff latch, not a manufactured native phase/session.
    if (kind === 'open') a.sent = true;
    if (kind === 'apply') a.applySent = true;
    if (kind === 'close') a.closeSent = true;
    let original: Promise<unknown>;
    try {
      original = call();
      if (!original || typeof original.then !== 'function') throw failure();
      work.promise = original;
    } catch { this.#fail('unconfirmed'); this.#finish(work); throw failure(); }
    void Promise.resolve(original).then((value) => this.#receive(value, 'reply'), () => {
      // A late transport error cannot erase an original settled receipt.
      if (!(a.projection?.phase === 'final' && a.projection.nativeFinality === 'settled')) this.#fail('unconfirmed');
    }).finally(() => this.#finish(work));
    if (kind === 'apply' && !a.mutationPublished) { a.mutationPublished = true; try { this.#source.onMutationSubmitted?.(a.context.projectId!, a.request.intent); } catch { this.#fail('unconfirmed'); } }
    this.#publish();
    return true;
  }
  #guard(a: Attempt, status: IdentityOwnerStatus | null, stamp: number): boolean {
    // Read caller-owned context/gates FIRST: they may synchronously retire this
    // very intent. The final local stamp checks must follow those callbacks.
    const current = this.#current(), blocked = this.#other(a.context.projectId!);
    return !this.#disposed && !this.#issue && this.#works.size === 1 && this.#attempt === a && !a.retired &&
      this.#stamp === stamp && this.#status === status && identityDataEqual(a.context, current) && !blocked;
  }
  #open(request: IdentityOpenRequest): boolean {
    if (!encodeProjectIdentityRequest('project_identity_open', request)) return false;
    const c = this.#ready(), status = this.#status;
    if (!c || !status || c.projectId !== request.projectId || status.active ||
      this.#attempt?.sent && !terminal(this.#attempt.projection) || request.intent === 'edit' &&
      (!c.selection || !identityDataEqual(request.selection, { platform: c.selection.platform, target: c.selection.target, project: c.selection.project }) ||
        this.#original()?.projectId === c.projectId && this.#original()?.coreOutcome?.journal === 'recovery_required')) return false;
    const a: Attempt = { context: c, stamp: this.#stamp, window: status.windowGeneration, after: status.statusRevision,
      previous: status.lastTerminal?.sessionId ?? null, request, sessionId: null, projection: null, retired: false, sent: false,
      preparation: null, delegated: null, mutationPublished: false, prepareClaimed: false, applyClaimed: false, applySent: false, closeRequested: false, closeSent: false, outcomePublished: false };
    this.#attempt = a;
    const sent = this.#send('open', a, () => this.#api.open(request), () => this.#guard(a, status, a.stamp));
    if (!sent && this.#attempt === a && !a.sent) { this.#attempt = null; this.#publish(); }
    return sent;
  }
  analyze(request: { projectId: string; selection: IdentitySelection }): boolean {
    const args = uiArguments(request, ['projectId', 'selection']);
    if (!args) return false;
    const c = parseIdentityContext({ ...args, contextEpoch: 0, preview: false, blocked: false });
    if (!c?.projectId || !c.selection) return false;
    const { platform, target, project } = c.selection;
    return this.#open({ intent: 'edit', projectId: c.projectId, selection: { platform, target, project } });
  }
  inspectRecovery(request: { projectId: string }): boolean {
    const args = uiArguments(request, ['projectId']);
    return args ? this.#open({ intent: 'recover', projectId: args.projectId as string }) : false;
  }
  #prepare(request: IdentityPrepareRequest): boolean {
    if (!encodeProjectIdentityRequest('project_identity_prepare', request)) return false;
    const a = this.#bound(), p = a?.projection, status = this.#status;
    if (!a || !p?.checkout || p.phase !== 'editing' || p.nativeReason !== 'none' || p.diagnostic || a.prepareClaimed || a.delegated || request.intent !== p.intent ||
      request.sessionId !== p.sessionId || request.revision !== p.checkout.revision) return false;
    if (request.intent === 'edit' && (p.checkout.view.kind !== 'project-identity' || p.checkout.view.state !== 'supported' ||
      !identityValueFits(request.desiredIdentity, p.checkout.view.selection.platform) || request.desiredIdentity !== p.checkout.view.identity &&
      (request.identityIntent !== 'new-application' || p.checkout.view.selection.continuity !== 'unknown' || p.checkout.view.identityStatus !== 'unverified'))) return false;
    if (request.intent === 'recover' && (p.checkout.view.kind !== 'project-identity-recovery' || p.checkout.view.state !== 'recoverable')) return false;
    a.prepareClaimed = true; a.preparation = Object.freeze(request);
    return this.#send('prepare', a, () => this.#api.prepare(request), () => this.#guard(a, status, a.stamp));
  }
  prepare(request: IdentitySessionRequest & { desiredIdentity: string; intent: IdentityIntent }): boolean {
    const args = uiArguments(request, ['sessionId', 'revision', 'desiredIdentity', 'intent']);
    return args ? this.#prepare({ intent: 'edit', sessionId: args.sessionId as string, revision: args.revision as string,
      desiredIdentity: args.desiredIdentity as string, identityIntent: args.intent as IdentityIntent }) : false;
  }
  prepareRecovery(request: IdentitySessionRequest): boolean {
    const args = uiArguments(request, ['sessionId', 'revision']);
    return args ? this.#prepare({ sessionId: args.sessionId as string, revision: args.revision as string, intent: 'recover' }) : false;
  }
  #apply(request: IdentitySendRequest): boolean {
    if (!encodeProjectIdentityRequest('project_identity_apply', request)) return false;
    const a = this.#bound(), p = a?.projection, status = this.#status;
    if (!a || a.delegated || !a.prepareClaimed || !a.preparation || !p?.prepared || p.phase !== 'reviewing' || p.nativeReason !== 'none' ||
      p.reviewRemainingMs === 0 || a.applyClaimed || p.applySubmitted ||
      request.intent !== p.intent || request.sessionId !== p.sessionId || request.revision !== p.prepared.revision || request.planToken !== p.prepared.planToken) return false;
    a.applyClaimed = true;
    return this.#send('apply', a, () => this.#api.apply(request), () => this.#guard(a, status, a.stamp) && !a.closeRequested);
  }
  #sendApply(request: IdentityApplyRequest, intent: 'edit' | 'recover'): boolean {
    const args = uiArguments(request, ['sessionId', 'revision', 'planToken']);
    return args ? this.#apply({ sessionId: args.sessionId as string, revision: args.revision as string, planToken: args.planToken as string, intent }) : false;
  }
  apply(request: IdentityApplyRequest): boolean { return this.#sendApply(request, 'edit'); }
  recover(request: IdentityApplyRequest): boolean { return this.#sendApply(request, 'recover'); }
  /** Passive expectation for one explicitly delegated, already-opened proposal.
   * This sends nothing and is NOT native permission or a Prepare claim. The
   * separate original native Allow still has to bind the exact source/change. */
  expectAgentIdentityAction(request: IdentitySessionRequest & { desiredIdentity: string; intent: IdentityIntent }): boolean {
    const args = uiArguments(request, ['sessionId', 'revision', 'desiredIdentity', 'intent']);
    const a = this.#bound(), p = a?.projection;
    if (!args || !a || a.delegated || a.preparation || a.prepareClaimed || a.applyClaimed || p?.intent !== 'edit' ||
      p.phase !== 'editing' || p.nativeReason !== 'none' || p.diagnostic || !p.checkout || p.checkout.view.kind !== 'project-identity' ||
      p.checkout.view.state !== 'supported' || p.checkout.revision !== args.revision || p.sessionId !== args.sessionId ||
      !identityValueFits(args.desiredIdentity, p.checkout.view.selection.platform) || !['preserve', 'new-application'].includes(args.intent as string) ||
      args.desiredIdentity !== p.checkout.view.identity && (args.intent !== 'new-application' || p.checkout.view.selection.continuity !== 'unknown' ||
        p.checkout.view.identityStatus !== 'unverified')) return false;
    a.delegated = Object.freeze({ intent: 'edit', sessionId: p.sessionId, revision: p.checkout.revision,
      desiredIdentity: args.desiredIdentity, identityIntent: args.intent as IdentityIntent });
    this.#publish(); return true;
  }
  /** Read the SAME original attempt, including during its synchronous mutation
   * callback before the next view publication. Permission DATA cannot set it. */
  agentIdentityApplySubmitted(): boolean {
    const a = this.#attempt;
    return !!a?.delegated && a.applySent && a.projection?.applySubmitted === true;
  }
  /** BEFORE every context/API/selection intent, even no-op or ABA intents. */
  beforeContextIntent(): void {
    if (this.#stamp === Number.MAX_SAFE_INTEGER) this.#fail('protocol'); else this.#stamp += 1;
    const a = this.#attempt;
    if (a) { a.retired = true; if (!a.applySent) a.closeRequested = true; }
    this.#publish(); this.#closeOriginal();
  }
  // Display only: a foreign status summary never enables original cancellation.
  canRequestClose(): boolean {
    const a = this.#attempt;
    return !!a?.sent && !terminal(a.projection) && !a.closeRequested;
  }
  /** Explicit original cancellation, independent of selected project/busy. */
  requestClose(): boolean {
    const a = this.#attempt;
    if (!a?.sent || terminal(a.projection) || a.closeRequested) return false;
    a.retired = true; a.closeRequested = true; this.#publish(); this.#closeOriginal(); return true;
  }
  discard(request: { sessionId: string }): boolean {
    const args = uiArguments(request, ['sessionId']);
    if (!args || args.sessionId !== this.#attempt?.sessionId || !this.requestClose()) return false;
    const sent = [...this.#works].some((w) => w.kind === 'close' && w.promise !== null);
    if (!sent && this.#issue) throw failure();
    return sent;
  }
  #closeOriginal(): void {
    const a = this.#attempt, p = a?.projection;
    if (!a?.closeRequested || a.closeSent || !a.sessionId || !p || terminal(p) || a.window !== this.#status?.windowGeneration ||
      this.#issue === 'generation-changed' || this.#issue === 'cleanup-unknown' || [...this.#works].some((w) => w.kind === 'close')) return;
    try { this.#send('close', a, () => this.#api.close({ sessionId: a.sessionId! }), () => this.#attempt === a &&
      !a.closeSent && !terminal(a.projection) && a.window === this.#status?.windowGeneration); }
    catch { /* The original lost request remains retained; never retry Close. */ }
  }
  dispose(): void {
    this.#disposed = true; this.beforeContextIntent(); this.#listeners.clear(); this.#detachIfFinished();
  }
  #detachIfFinished(): void {
    if (!this.#disposed || this.#works.size || this.#status?.active || this.#attempt?.sent && !terminal(this.#attempt.projection) || this.#issue) return;
    const off = this.#off; this.#off = null;
    try { off?.(); } catch { this.#fail('unconfirmed'); }
  }
}
