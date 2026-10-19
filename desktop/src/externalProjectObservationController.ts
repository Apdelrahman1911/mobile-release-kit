import { sameSavedConfig } from './offlinePreflightProtocol.ts';
import { parseReleaseVersionObservation, releaseVersionRequestFits } from './releaseVersion.ts';
import type { ReleaseVersionState } from './releaseVersion.ts';
import type { ProjectSession } from './drafts.ts';
import type { DesktopApi } from './types.ts';
import { EXTERNAL_PROJECT_CHECK_INTERVAL_MS, EXTERNAL_PROJECT_FOCUS_THROTTLE_MS,
  externalObservationFailure, externalObserved, externalSnapshotComparable, externalUnavailable, externalVersionBaseline,
  parseExternalProjectSnapshot, sameExternalProjectSnapshot, sameExternalVersion } from './externalProjectObservation.ts';
import type { ExternalProjectNotice, ExternalProjectObservationOutcome } from './externalProjectObservation.ts';

export type ExternalProjectObservationApi = Pick<DesktopApi, 'mode' | 'snapshot' | 'observeReleaseVersion'>;
export interface ExternalProjectObservationContext {
  api: ExternalProjectObservationApi | null;
  session: ProjectSession | null;
  versionState: ReleaseVersionState | null;
}
export interface ExternalProjectObservationClock {
  now(): number;
  setTimeout(callback: () => void, delay: number): unknown;
  clearTimeout(handle: unknown): void;
}
export interface ExternalProjectObservationOptions {
  current(): ExternalProjectObservationContext;
  // ALL original owner and passive-query gates, plus snapshot capability.
  // Exclude only THIS controller to avoid recursive admission/deadlock.
  otherOperationReason(): string | null;
  // Synchronous existing snapshot-intent/start/done-or-failed batch. Check
  // stillCurrent immediately before its first effect. No await, reset/discard,
  // mutation retry or fabricated ReleaseVersionState. Return true if applied.
  onObservation(outcome: ExternalProjectObservationOutcome, stillCurrent: () => boolean): boolean;
  clock?: ExternalProjectObservationClock;
}
export interface ExternalProjectObservationState {
  projectId: string | null;
  checking: boolean;
  notice: ExternalProjectNotice | null;
  // A late foreign-project cleanup-unknown must remain visible, but must not
  // become the selected project's positive/negative readiness observation.
  recovery: { projectId: string; notice: ExternalProjectNotice } | null;
}
interface Scope {
  epoch: object;
  api: ExternalProjectObservationApi;
  session: ProjectSession;
  versionState: ReleaseVersionState | null;
  projectId: string;
  revision: number;
  baselineGeneration: number;
  observationGeneration: number;
  nativePending: boolean;
  completion: Promise<void>;
}

const defaultClock: ExternalProjectObservationClock = {
  now: () => Date.now(),
  setTimeout: (callback, delay) => globalThis.setTimeout(callback, delay),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof globalThis.setTimeout>),
};
const pendingReason = 'An original saved-file check is still pending. Wait for it to settle before starting another task.';
const recoveryReason = 'The previous saved-file check needs original service recovery. Do not start another check or task.';

export class ExternalProjectObservationController {
  private readonly options: ExternalProjectObservationOptions;
  private readonly clock: ExternalProjectObservationClock;
  private state: ExternalProjectObservationState = Object.freeze({ projectId: null, checking: false, notice: null, recovery: null });
  private listeners = new Set<() => void>();
  private epoch: object = {};
  private api: ExternalProjectObservationApi | null = null;
  private flight: Scope | null = null;
  private timer: unknown = null;
  private visible = false;
  private disposed = false;
  private lastSettledAt: number | null = null;

  constructor(options: ExternalProjectObservationOptions) {
    this.options = options;
    this.clock = options.clock ?? defaultClock;
  }
  getSnapshot = (): ExternalProjectObservationState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  // This ORIGINAL Promise ownership is deliberately independent of epoch,
  // visible project, UI retirement and disposal. Existing action/read owners
  // must synchronously consult it BEFORE native admission, not in an effect.
  passiveBusyReason = (): string | null => this.flight?.nativePending ? pendingReason : this.state.recovery ? recoveryReason : null;
  whenSettled = (): Promise<void> => this.flight?.completion ?? Promise.resolve();

  private update(patch: Partial<ExternalProjectObservationState>): void {
    this.state = Object.freeze({ ...this.state, ...patch });
    if (!this.disposed) for (const listener of this.listeners) listener();
  }
  private clearTimer(): void {
    if (this.timer !== null) this.clock.clearTimeout(this.timer);
    this.timer = null;
  }
  private schedule(): void {
    if (this.disposed || !this.visible || this.flight || this.state.recovery || this.timer !== null) return;
    this.timer = this.clock.setTimeout(() => {
      this.timer = null;
      void this.requestCheck();
    }, EXTERNAL_PROJECT_CHECK_INTERVAL_MS);
  }
  // Root calls before workspace actions, explicit read/save/selection intent,
  // navigation/context changes and service retirement, even on an early return.
  // An opaque epoch also detects away-and-back ABA without counter exhaustion.
  beforeWorkspaceAction = (): void => { this.epoch = {}; };

  syncContext(): void {
    if (this.disposed) return;
    const context = this.options.current(), projectId = context.session?.project.id ?? null;
    if (this.api !== context.api || this.state.projectId !== projectId) {
      this.beforeWorkspaceAction();
      this.api = context.api;
      this.update({ projectId, notice: null });
    }
    this.schedule();
  }
  setVisible(visible: boolean): void {
    if (this.disposed || this.visible === visible) return;
    this.visible = visible;
    if (!visible) { this.beforeWorkspaceAction(); this.clearTimer(); }
    else { this.syncContext(); void this.requestCheck(); }
  }
  focus = (): Promise<void> => this.requestCheck();
  dismissNotice(): void { if (!this.disposed && this.state.notice) this.update({ notice: null }); }

  private otherReason(): string | null {
    // A failed host guard is not permission to run or publish a passive check.
    try { return this.options.otherOperationReason(); }
    catch { return 'Saved-file checking is unavailable until the current task can be checked.'; }
  }
  private current(scope: Scope): boolean {
    if (this.disposed || !this.visible || scope.epoch !== this.epoch) return false;
    const context = this.options.current(), session = context.session;
    return context.api === scope.api && scope.api.mode === 'native' && session === scope.session &&
      context.versionState === scope.versionState && session.project.id === scope.projectId &&
      session.revision === scope.revision && session.baselineGeneration === scope.baselineGeneration &&
      session.observationGeneration === scope.observationGeneration;
  }
  private blocked(context: ExternalProjectObservationContext): boolean {
    const session = context.session;
    return !context.api || context.api.mode !== 'native' || !session || !releaseVersionRequestFits({ projectId: session.project.id }) ||
      session.snapshotRequest !== null || session.validationRequest !== null || session.reviewRequest !== null || session.suggestionRequest !== null ||
      session.saveRecoveryRequired || session.saveRecoveryNeedsReload || session.recoveryReloadRequest !== null ||
      Boolean(context.versionState?.pending) || this.otherReason() !== null;
  }
  // Reentrant host callbacks may acquire a scope despite an earlier null read.
  // Read it again without TypeScript retaining the pre-callback narrowing.
  private currentFlight(): Scope | null { return this.flight; }

  // Focus calls are coalesced into the original flight, then throttled. Hidden
  // windows do no automatic reads. A paused poll waits another 30s or a focus;
  // it does not spin, repeatedly retire owners or queue a competing action.
  requestCheck(): Promise<void> {
    if (this.flight) return this.flight.completion;
    if (this.disposed || !this.visible || this.state.recovery) return Promise.resolve();
    this.syncContext();
    const afterSync = this.currentFlight();
    if (afterSync) return afterSync.completion;
    if (this.disposed || !this.visible || this.state.recovery) return Promise.resolve();
    const context = this.options.current(), now = this.clock.now();
    if (this.blocked(context) || this.lastSettledAt !== null && now >= this.lastSettledAt && now - this.lastSettledAt < EXTERNAL_PROJECT_FOCUS_THROTTLE_MS) {
      this.schedule();
      return Promise.resolve();
    }
    const afterGuard = this.currentFlight();
    if (afterGuard) return afterGuard.completion;
    // blocked() established native API + selected session. Recheck again
    // after publishing busy: subscribers can synchronously retire this scope.
    const api = context.api!, session = context.session!;
    let resolve!: () => void, reject!: (error: unknown) => void;
    const completion = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
    const scope: Scope = { epoch: this.epoch, api, session, versionState: context.versionState, projectId: session.project.id,
      revision: session.revision, baselineGeneration: session.baselineGeneration, observationGeneration: session.observationGeneration,
      nativePending: true, completion };
    this.flight = scope;
    this.clearTimer();
    const finish = () => {
      if (this.flight === scope) this.flight = null;
      this.schedule();
    };
    // Never await a new service/selection intent in place of this original job.
    void this.observe(scope).then(() => { finish(); resolve(); }, () => {
      finish();
      // Host callback/programming errors are not native success or raw output.
      reject(new Error('The saved-file observation callback failed. No automatic action may use this result.'));
    });
    return completion;
  }

  private async observe(scope: Scope): Promise<void> {
    let outcome: ExternalProjectObservationOutcome | null = null;
    try {
      this.update({ checking: true });
      if (!this.current(scope) || this.otherReason() !== null) return;
      const raw = await scope.api.snapshot(scope.projectId);
      if (!this.current(scope) || this.otherReason() !== null) return;
      const snapshot = parseExternalProjectSnapshot(raw);
      if (!snapshot || !externalSnapshotComparable(snapshot)) outcome = externalUnavailable(scope.projectId, 'incomplete');
      else {
        const previous = parseExternalProjectSnapshot(scope.session.snapshot);
        if (previous && previous.root !== snapshot.root) outcome = externalUnavailable(scope.projectId, 'mismatch');
        else if (!previous || scope.session.snapshotError || scope.session.snapshotPredatesSave || scope.session.observedAt === null ||
            snapshot.config.state === 'format-valid' && scope.session.savedConfigContent === null) {
          outcome = externalObserved(scope.projectId, snapshot, this.clock.now(), 'refresh');
        } else if (!sameExternalProjectSnapshot(previous, snapshot)) {
          outcome = externalObserved(scope.projectId, snapshot, this.clock.now(), 'project-files');
        } else {
          const version = externalVersionBaseline(scope.session, scope.versionState);
          if (version) {
            // Sequential reads, never Promise.all. Config and version remain
            // non-atomic even when their comparison hashes happen to agree.
            const rawVersion = await scope.api.observeReleaseVersion(scope.projectId);
            if (!this.current(scope) || this.otherReason() !== null) return;
            const observed = parseReleaseVersionObservation(rawVersion);
            if (!observed) outcome = externalUnavailable(scope.projectId, 'incomplete');
            else if (!sameSavedConfig(snapshot.config.content, observed.savedConfig)) outcome = externalUnavailable(scope.projectId, 'mismatch');
            else if (!sameExternalVersion(version, observed)) outcome = externalObserved(scope.projectId, snapshot, this.clock.now(), 'saved-version');
          }
        }
      }
    } catch (error) {
      const failure = externalObservationFailure(error);
      outcome = externalUnavailable(scope.projectId, failure);
      if (failure === 'cleanup-unknown') {
        // Preserve even a foreign/retired original owner. This is a lifetime
        // pause, not new native recovery authority or a retry-install button.
        this.clearTimer();
        this.update({ recovery: Object.freeze({ projectId: scope.projectId, notice: Object.freeze(outcome.notice) }) });
      }
    } finally {
      scope.nativePending = false;
      this.lastSettledAt = this.clock.now();
      // A subscriber may admit a user action right here. The callback below
      // MUST recheck after release; an earlier check is not saved consent.
      this.update({ checking: false });
    }
    if (!outcome) return; // Unchanged means NO workspace action/read retirement.
    let deliveryOpen = true;
    const stillCurrent = () => deliveryOpen && this.current(scope) && this.otherReason() === null;
    try {
      if (!stillCurrent()) return;
      const accepted = this.options.onObservation(outcome, stillCurrent);
      // The synchronous accepted batch legitimately changes the epoch/session.
      // Keep its notice only for the same selected project + API, not a foreign
      // task. Never use this check to accept data or mark anything ready.
      const after = this.options.current();
      if (accepted && !this.disposed && after.api === scope.api && after.session?.project.id === scope.projectId) {
        this.update({ notice: Object.freeze(outcome.notice) });
      }
    } finally { deliveryOpen = false; }
  }

  dispose(): Promise<void> {
    this.disposed = true;
    this.beforeWorkspaceAction();
    this.clearTimer();
    this.listeners.clear();
    // No abort/kill/retry fiction. Native settlement (including an unknown
    // cleanup result) remains the original supervisor's responsibility.
    return this.whenSettled();
  }
}
