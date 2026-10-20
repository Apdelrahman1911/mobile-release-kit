// App-held UI coordination only. Neither promises, events nor comparison
// counters can settle the original native Session or its account-wide journal.
import { localStoreRequest } from './localStorePreflight.ts';
import type { LocalStoreProject } from './localStorePreflight.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { appleDisplayName, appleProvisioningConsent, appleProvisioningContext, appleProvisioningProgress,
  parseAppleProvisioningRequest, parseAppleProvisioningStatus, sameAppleIdentity } from './appleProvisioningProtocol.ts';
import type { AppleProvisioningApi } from './appleProvisioningNative.ts';
import type { AppleProvisioningIdentity, AppleProvisioningMode, AppleProvisioningOperation, AppleProvisioningResult,
  AppleProvisioningStatus, PrepareAppleProvisioning } from './appleProvisioningTypes.ts';

interface Source {
  project(): LocalStoreProject | null;
  assets(): AssetDisplayState | null;
  otherOperationReason(): string | null; // Root excludes THIS controller.
  now?(): number;
}
type Base = Omit<PrepareAppleProvisioning, 'mode' | 'reference' | 'newApplication' | 'displayName'>;
interface Witness { base: Base; observation: number; entry: number }
interface Attempt {
  request: PrepareAppleProvisioning; witness: Witness; epoch: number; after: number;
  previous: AppleProvisioningIdentity | null; identity: AppleProvisioningIdentity | null;
  preparedAt: number; startedAt: number | null; retired: boolean; prepareAccepted: boolean;
  prepareJoined: boolean; startClaimed: boolean; startJoined: boolean; terminalRead: boolean;
}
interface Reference { identity: AppleProvisioningIdentity; witness: Witness; displayName: string; expires: number | null }
interface ActionSlot { kind: 'prepare' | 'start'; joined: boolean; original: Promise<unknown> | null; promise: Promise<void> | null }
interface ReadSlot { mutation: number; afterInvoke: boolean; original: Promise<unknown> | null; promise: Promise<void> | null }
interface CancelSlot { identity: AppleProvisioningIdentity; joined: boolean; original: Promise<unknown> | null; promise: Promise<void> | null }
type Issue = 'unconfirmed' | 'protocol' | 'cleanup-unknown';
export interface AppleProvisioningState {
  native: boolean; visible: boolean; listening: boolean; initialized: boolean; reading: boolean;
  pending: 'prepare' | 'start' | null; requestPending: boolean; cancelPending: boolean;
  status: AppleProvisioningStatus | null; projectId: string | null; ios: boolean;
  displayName: string; newApplication: boolean; issue: Issue | null; historical: boolean;
  consent: (AppleProvisioningIdentity & { mode: AppleProvisioningMode; acknowledged: boolean }) | null;
  result: AppleProvisioningResult | null; reviewReference: AppleProvisioningIdentity | null;
  registrationReference: AppleProvisioningIdentity | null;
  reviewReason: string | null; registerReason: string | null; reconcileReason: string | null; startReason: string | null;
  canRead: boolean; canCancel: boolean; retained: boolean; cancelRequested: boolean;
}
const identity = (value: AppleProvisioningIdentity): AppleProvisioningIdentity => ({ operationId: value.operationId, ownerGeneration: value.ownerGeneration });
const active = (op: AppleProvisioningOperation | null | undefined) => !!op && op.phase !== 'terminal';
const sameWitness = (a: Witness | null, b: Witness | null): boolean => a === null || b === null ? a === b :
  a.observation === b.observation && a.entry === b.entry && sameOfflineData(a.base, b.base);
const attention = 'The original Bundle-ID operation is unconfirmed. Keep its status and cancellation; do not repeat registration or reconnect to dismiss it.';
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

export class AppleProvisioningController {
  private readonly source: Source;
  private original: AppleProvisioningApi | null = null;
  private off: (() => void) | null = null;
  private subscribing: Promise<void> | null = null;
  private read: ReadSlot | null = null;
  private action: ActionSlot | null = null;
  private cancellation: CancelSlot | null = null;
  private cancelClaim: AppleProvisioningIdentity | null = null;
  private attempt: Attempt | null = null;
  private review: Reference | null = null;
  private registration: Reference | null = null;
  private witness: Witness | null = null;
  private status: AppleProvisioningStatus | null = null;
  private issue: Issue | null = null;
  private epoch = 0;
  private mutation = 0;
  private visible = false;
  private initialized = false;
  private connectionRetired = false;
  private selectionPending = false;
  private disposed = false;
  private displayName = '';
  private declaredNew = false;
  private acknowledged = false;
  private consentUntil: number | null = null;
  private consentTimer: ReturnType<typeof setTimeout> | null = null;
  private cancelRequested = false;
  private readonly listeners = new Set<() => void>();
  private state: AppleProvisioningState;

  constructor(source: Source) { this.source = source; this.state = this.projected(); }
  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private now(): number { return (this.source.now ?? (() => performance.now()))(); }
  private capture(): Witness | null {
    try {
      if (this.selectionPending) return null;
      const project = this.source.project(), assets = this.source.assets();
      const base = localStoreRequest(project, assets);
      if (!project || !assets || !base || base.platform !== 'ios' || Object.hasOwn(base, 'query') ||
          !Number.isSafeInteger(project.observationGeneration) || project.observationGeneration < 0 ||
          !Number.isSafeInteger(assets.entryGeneration) || assets.entryGeneration < 0) return null;
      return freeze({ base: { ...base, platform: 'ios' as const }, observation: project.observationGeneration, entry: assets.entryGeneration });
    } catch { return null; }
  }
  private current(attempt: Attempt): boolean {
    return !attempt.retired && attempt.epoch === this.epoch && sameWitness(attempt.witness, this.witness) &&
      attempt.request.displayName === this.displayName && !this.connectionRetired && !this.disposed;
  }
  private settled(): boolean {
    return !this.action && !this.cancellation && !this.read && !this.subscribing && !active(this.status?.operation) &&
      (!this.attempt || this.attempt.terminalRead) && !this.issue;
  }
  ownerReason = (): string | null => this.issue || this.action || this.cancellation || this.subscribing || this.read ||
    active(this.status?.operation) || this.attempt && !this.attempt.terminalRead ?
    'A Bundle-ID intent, request or original cleanup is retained. Finish or cancel it before other work.' : null;
  private baseReason(): string | null {
    if (!this.original || this.connectionRetired) return 'Use the installed Mac app. Browser preview cannot prepare or register Bundle IDs.';
    if (this.issue) return attention;
    if (this.ownerReason() || this.read) return this.ownerReason() ?? 'Wait for the current original status response.';
    if (!this.initialized || !this.off || this.status?.availability !== 'available') return 'The original native Bundle-ID capability is unavailable or busy. Refresh its status; no fallback account is used.';
    if (!this.witness) return 'Select This Mac → iOS → Store (or Full), save the configuration, read its saved version and assign the original App Store Connect P8 with its Key ID and Issuer ID.';
    if (!appleDisplayName(this.displayName)) return 'Enter an explicit Bundle ID display name (1–128 characters, no control characters).';
    return this.source.otherOperationReason();
  }
  private referenceCurrent(value: Reference | null): value is Reference {
    return !!value && sameWitness(value.witness, this.witness) && value.displayName === this.displayName &&
      (value.expires === null || this.now() < value.expires);
  }
  private reason(mode: AppleProvisioningMode): string | null {
    const base = this.baseReason(); if (base) return base;
    if (mode === 'register') {
      if (!this.referenceCurrent(this.review)) return 'First finish a current reuse-first review. A key-only not-returned result is not global availability or permission.';
      if (!this.declaredNew) return 'Explicitly declare this is a new application, not a change to an existing store identity.';
    }
    if (mode === 'reconcile' && !this.referenceCurrent(this.registration)) return 'Readback requires the exact retained prior registration in this same saved/key context. It never retries the write.';
    return null;
  }
  private startReason(): string | null {
    const a = this.attempt, op = this.status?.operation;
    if (!a || !a.prepareAccepted || !a.prepareJoined || !a.identity || !this.current(a) || !sameAppleIdentity(a.identity, op) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable || this.action || this.cancellation || this.read || this.issue ||
        a.startClaimed || this.consentUntil === null || this.now() >= this.consentUntil) return 'This original intent is unavailable, expired or still pending. Do not replay Start.';
    if (a.request.mode === 'register' && !this.declaredNew) return 'The explicit new-application declaration is required.';
    return this.source.otherOperationReason() ?? (this.acknowledged ? null : 'Confirm the separate permission for this exact original intent.');
  }
  private projected(): AppleProvisioningState {
    const a = this.attempt, op = this.status?.operation;
    const current = !!a && this.current(a) && sameAppleIdentity(a.identity, op);
    const readResult = !!a?.terminalRead && !this.action && !this.cancellation && !this.issue && sameAppleIdentity(a.identity, op) ? op?.result ?? null : null;
    const cancelId = a?.identity ?? (active(op) ? op : null);
    return Object.freeze({ native: !!this.original && !this.connectionRetired, visible: this.visible, initialized: this.initialized,
      listening: !!this.off, reading: !!this.read, pending: this.action?.kind ?? null, requestPending: !!this.action && !this.action.joined,
      cancelPending: !!this.cancellation, status: this.status, projectId: this.witness?.base.projectId ?? null,
      ios: this.source.assets()?.scope.platform === 'ios', displayName: this.displayName, newApplication: this.declaredNew,
      issue: this.issue, historical: !!op && !current,
      consent: a?.identity && this.consentUntil !== null && current && !a.startClaimed ?
        Object.freeze({ ...identity(a.identity), mode: a.request.mode, acknowledged: this.acknowledged }) : null,
      result: readResult, reviewReference: this.referenceCurrent(this.review) ? this.review.identity : null,
      registrationReference: this.registration?.identity ?? null,
      reviewReason: this.reason('review'), registerReason: this.reason('register'), reconcileReason: this.reason('reconcile'),
      startReason: this.startReason(), canRead: !!this.original && !this.read && (!this.connectionRetired || !this.settled()),
      canCancel: !!this.original && !!cancelId && !this.cancellation && !sameAppleIdentity(this.cancelClaim, cancelId) && active(op),
      retained: this.ownerReason() !== null, cancelRequested: this.cancelRequested });
  }
  private publish(): void { this.state = this.projected(); if (!this.disposed) for (const listener of this.listeners) listener(); }
  private clearConsent(): void {
    this.acknowledged = false; this.consentUntil = null;
    if (this.consentTimer !== null) clearTimeout(this.consentTimer); this.consentTimer = null;
  }
  private fail(issue: Issue = 'unconfirmed'): void {
    this.issue ??= issue; this.clearConsent(); this.review = null;
    if (this.attempt) this.attempt.retired = true;
    this.cancelRequested = true; this.publish(); void this.cancelOriginal();
  }
  syncProject = (): void => {
    const next = this.capture();
    if (!sameWitness(next, this.witness)) { this.invalidate(); this.witness = next; }
    // Peer-owner changes can disable/enable the view without changing saved
    // comparison inputs. Reproject only; this does not renew a native intent.
    this.publish();
  };
  invalidate = (): void => {
    this.epoch++; this.clearConsent(); this.review = null; this.declaredNew = false;
    if (this.attempt) this.attempt.retired = true;
    if (this.action || active(this.status?.operation)) { this.cancelRequested = true; void this.cancelOriginal(); }
    this.publish();
  };
  beforeWorkspaceAction = (): void => this.invalidate();
  selectionIntent = (): void => this.invalidate();
  snapshotIntent = (): void => this.invalidate();
  versionIntent = (): void => this.invalidate();
  setSelectionPending = (value: boolean): void => { if (value !== this.selectionPending) { this.selectionPending = value; this.syncProject(); } };
  setVisible = (value: boolean): void => { if (!value && this.consentUntil !== null) this.invalidate(); this.visible = value; this.publish(); };
  setDisplayName = (value: string): void => {
    if (value === this.displayName || value.length > 512) return;
    this.invalidate(); this.displayName = value; this.publish();
  };
  setNewApplication = (value: boolean): void => {
    if (value === this.declaredNew) return;
    if (this.attempt?.request.mode === 'register' && !this.attempt.terminalRead) this.invalidate();
    this.declaredNew = value; this.publish();
  };
  acknowledge = (operationId: string, ownerGeneration: string, value: boolean): void => {
    if (sameAppleIdentity(this.attempt?.identity, { operationId, ownerGeneration }) && this.consentUntil !== null &&
        this.now() < this.consentUntil && this.attempt && this.current(this.attempt) && !this.attempt.startClaimed) {
      this.acknowledged = value; this.publish();
    }
  };
  beginConnection = (): void => {
    this.connectionRetired = true; this.invalidate();
    if (!this.settled()) this.fail();
  };
  async connect(api: AppleProvisioningApi | null): Promise<void> {
    if (this.disposed || this.original === api && !this.connectionRetired) return;
    if (this.original) {
      if (!this.settled()) { this.beginConnection(); return; }
      try { this.off?.(); } catch { this.fail(); return; }
    }
    this.original = api; this.off = null; this.connectionRetired = false; this.initialized = false;
    this.status = null; this.attempt = null; this.review = null; this.registration = null; this.clearConsent(); this.witness = this.capture(); this.publish();
    if (!api) return;
    const pending = (async () => {
      try {
        const off = await api.subscribe(value => {
          if (this.original !== api) return;
          this.receive(value, 'event');
          if (this.status?.operation?.phase === 'terminal' && !this.action && !this.cancellation) void this.checkStatus();
        });
        if (this.original !== api) { off(); return; }
        this.off = off;
      } catch { this.fail(); }
    })();
    this.subscribing = pending; this.publish();
    await pending; if (this.subscribing === pending) this.subscribing = null;
    await this.checkStatus(); this.cleanupListener(); this.publish();
  }
  private receive(value: unknown, source: 'event' | 'invoke' | 'read', read?: ReadSlot): AppleProvisioningStatus | null {
    const next = parseAppleProvisioningStatus(value), before = this.status;
    if (!next) { this.fail('protocol'); return null; }
    if (before && next.statusRevision < before.statusRevision) return next;
    if (before && next.statusRevision === before.statusRevision && !sameOfflineData(before, next)) { this.fail('protocol'); return null; }
    const op = next.operation, a = this.attempt;
    if (before?.operation && sameAppleIdentity(before.operation, op) && !appleProvisioningProgress(before.operation, op!)) { this.fail('protocol'); return null; }
    if (before?.operation && active(before.operation) && !sameAppleIdentity(before.operation, op)) { this.fail('protocol'); return null; }
    if (a && !a.identity && op && next.statusRevision > a.after && !sameAppleIdentity(a.previous, op) &&
        sameOfflineData(op.context, appleProvisioningContext(a.request))) a.identity = freeze(identity(op));
    if (a?.identity && sameAppleIdentity(a.identity, op) && !sameOfflineData(op!.context, appleProvisioningContext(a.request))) { this.fail('protocol'); return null; }
    if (a?.identity && !a.terminalRead && !sameAppleIdentity(a.identity, op)) { this.fail('protocol'); return null; }
    this.status = freeze(next);
    if (next.availability === 'cleanup-unknown' || op?.phase === 'unknown') this.fail('cleanup-unknown');
    if (a && source === 'read' && read?.afterInvoke && read.mutation === this.mutation && a.prepareJoined &&
        (!a.startClaimed || a.startJoined) && sameAppleIdentity(a.identity, op) && op?.phase === 'terminal' && !this.issue) {
      a.terminalRead = true; this.clearConsent();
      if (this.current(a) && a.startClaimed && a.startedAt !== null && a.request.mode === 'review' && op.outcome === 'complete' &&
          op.result?.decision === 'review-required' && op.result.observation === 'not-returned' && this.now() < a.startedAt + 300000) {
        this.review = freeze({ identity: identity(op), witness: a.witness, displayName: a.request.displayName, expires: a.startedAt + 300000 });
      }
    }
    if (this.cancelRequested || a?.retired) void this.cancelOriginal();
    this.publish(); return next;
  }
  checkStatus = (): Promise<void> => {
    if (this.read) return this.read.promise ?? Promise.resolve();
    const api = this.original; if (!api || this.connectionRetired && this.settled()) return Promise.resolve();
    const slot: ReadSlot = { mutation: this.mutation, afterInvoke: (!this.action || this.action.joined) && (!this.cancellation || this.cancellation.joined), original: null, promise: null };
    this.read = slot;
    slot.promise = (async () => {
      try { slot.original = api.status(); this.receive(await slot.original, 'read', slot); this.initialized = true; }
      catch { this.fail(); }
      finally { if (this.read === slot) this.read = null; this.cleanupListener(); this.publish(); }
    })(); this.publish(); return slot.promise;
  };
  private async postInvokeRead(): Promise<void> {
    const previous = this.read?.promise; if (previous) await previous;
    await this.checkStatus();
  }
  prepare = (mode: AppleProvisioningMode): Promise<void> => {
    this.syncProject(); if (this.disposed || !this.visible || this.reason(mode) || !this.original || !this.witness || !this.status) return Promise.resolve();
    const reference = mode === 'review' ? null : mode === 'register' ? this.review?.identity : this.registration?.identity;
    const request = parseAppleProvisioningRequest({ ...this.witness.base, mode, reference, newApplication: mode === 'register', displayName: this.displayName });
    if (!request) return Promise.resolve();
    const api = this.original, a: Attempt = { request: freeze(request), witness: this.witness, epoch: this.epoch, after: this.status.statusRevision,
      previous: this.status.operation ? identity(this.status.operation) : null, identity: null, preparedAt: this.now(), startedAt: null,
      retired: false, prepareAccepted: false, prepareJoined: false, startClaimed: false, startJoined: false, terminalRead: false };
    this.attempt = a; if (mode === 'register') this.review = null; // Consumed once, including failed/lost Prepare.
    this.cancelClaim = null; this.cancelRequested = false; this.clearConsent(); this.mutation++;
    const slot: ActionSlot = { kind: 'prepare', joined: false, original: null, promise: null }; this.action = slot;
    slot.promise = (async () => {
      try {
        slot.original = api.prepare(request); const reply = this.receive(await slot.original, 'invoke');
        const op = reply?.operation;
        if (!op || !sameAppleIdentity(a.identity, op) || !sameOfflineData(op.context, appleProvisioningContext(a.request))) this.fail('protocol');
        else a.prepareAccepted = op.phase === 'awaiting-consent' && op.intentUsable;
      } catch { this.fail(); }
      finally {
        a.prepareJoined = true; slot.joined = true; this.publish(); await this.postInvokeRead();
        if (this.action === slot) this.action = null;
        const op = this.status?.operation;
        if (!this.issue && this.current(a) && a.prepareAccepted && sameAppleIdentity(a.identity, op) && op?.phase === 'awaiting-consent' && op.intentUsable) {
          this.consentUntil = a.preparedAt + 60000; this.acknowledged = false;
          if (this.now() >= this.consentUntil) this.invalidate();
          else this.consentTimer = setTimeout(() => { if (this.attempt === a && !a.startClaimed) this.invalidate(); }, this.consentUntil - this.now());
        }
        this.cleanupListener(); this.publish();
      }
    })(); this.publish(); return slot.promise;
  };
  start = (operationId: string, ownerGeneration: string): Promise<void> => {
    this.syncProject(); const a = this.attempt, api = this.original;
    if (!a || !api || a.startClaimed || !sameAppleIdentity(a.identity, { operationId, ownerGeneration }) || this.startReason()) return Promise.resolve();
    a.startClaimed = true; a.startedAt = this.now(); this.clearConsent(); this.mutation++;
    if (a.request.mode === 'register') this.registration = freeze({ identity: identity(a.identity!), witness: a.witness, displayName: a.request.displayName, expires: null });
    const slot: ActionSlot = { kind: 'start', joined: false, original: null, promise: null }; this.action = slot;
    slot.promise = (async () => {
      try { slot.original = api.start({ ...a.identity!, consentVersion: appleProvisioningConsent(a.request.mode) }); this.receive(await slot.original, 'invoke'); }
      catch { this.fail(); }
      finally {
        a.startJoined = true; slot.joined = true; this.publish(); await this.postInvokeRead();
        if (this.action === slot) this.action = null; this.cleanupListener(); this.publish();
      }
    })(); this.publish(); return slot.promise;
  };
  cancel = (): Promise<void> => { this.invalidate(); this.cancelRequested = true; this.publish(); return this.cancelOriginal(); };
  private cancelOriginal(): Promise<void> {
    if (this.cancellation?.promise) return this.cancellation.promise;
    const api = this.original, op = this.status?.operation, id = this.attempt?.identity ?? (active(op) ? op : null);
    if (!api || !id || !this.cancelRequested || sameAppleIdentity(this.cancelClaim, id) || sameAppleIdentity(id, op) && op?.phase === 'terminal') return Promise.resolve();
    this.cancelClaim = freeze(identity(id)); this.mutation++;
    const slot: CancelSlot = { identity: this.cancelClaim, joined: false, original: null, promise: null }; this.cancellation = slot;
    slot.promise = (async () => {
      try { slot.original = api.cancel(slot.identity); this.receive(await slot.original, 'invoke'); }
      catch { this.fail(); }
      finally { slot.joined = true; this.publish(); await this.postInvokeRead(); if (this.cancellation === slot) this.cancellation = null; this.cleanupListener(); this.publish(); }
    })(); this.publish(); return slot.promise;
  }
  private cleanupListener(): void {
    if (!this.disposed || !this.settled() || !this.off) return;
    const off = this.off; this.off = null; try { off(); } catch { this.issue ??= 'unconfirmed'; }
  }
  dispose = (): void => {
    if (this.disposed) return;
    this.disposed = true; this.invalidate(); this.listeners.clear(); this.cleanupListener();
  };
}
