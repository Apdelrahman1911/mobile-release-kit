// Renderer coordination only. One original observer and bounded nonsecret
// intent survive lost replies/view invalidation. Native owns all admission,
// credentials, clocks and finality; neither a Promise nor JS cleanup is receipt.
import type { GitHubConnectionContext, GitHubConnectionObservationPort, GitHubConnectionReason,
  GitHubConnectionStatus, GitHubConnectionTokenHandoff, GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { connectionOpaqueId, connectionProgress, connectionRepository, connectionRetryable, connectionRevision,
  githubConnectionError, githubConnectionRequestFits, parseGitHubConnectionHelp, parseGitHubConnectionStatus,
  sameConnectionData } from './githubConnectionProtocol.ts';

function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze); Object.freeze(value);
  }
  return value;
}
function contextCopy(value: GitHubConnectionContext | null): GitHubConnectionContext | null {
  if (value === null || typeof value !== 'object') return null;
  const fields = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(fields).length !== 4 || !['documentId', 'projectId', 'projectGeneration', 'repository'].every((key) =>
    fields[key]?.enumerable && Object.hasOwn(fields[key]!, 'value'))) return null;
  const documentId: unknown = fields.documentId!.value; const projectId: unknown = fields.projectId!.value;
  const projectGeneration: unknown = fields.projectGeneration!.value; const repository: unknown = fields.repository!.value;
  return connectionOpaqueId(documentId) && connectionOpaqueId(projectId) && connectionRevision(projectGeneration) && connectionRepository(repository) ?
    { documentId, projectId, projectGeneration, repository } : null;
}
interface Observation {
  port: GitHubConnectionObservationPort; active: boolean; listening: boolean; subscriptionFailed: boolean; unlisten: (() => void) | null;
  ready: Promise<void> | null; reading: Promise<void> | null; serial: object;
  accepted: GitHubConnectionStatus | null;
  identity: { sessionId: string; accountId: string | null; repositoryId: string | null } | null;
  retiredSessionId: string | null;
}
interface Pending {
  kind: 'connect' | 'refresh'; observer: Observation; epoch: object; context: GitHubConnectionContext;
  baseRevision: number; oldOperationId: string | null; sessionId: string | null;
  operationId: string | null; admittedRevision: number | null;
  sent: boolean; retiring: boolean; uncertain: boolean; done: boolean;
}
interface Retirement { observer: Observation; sessionId: string; revision: number }

export class GitHubConnectionController {
  private state: GitHubConnectionViewState = freeze({ mode: 'unavailable', context: null, status: null, retained: null,
    help: null, helpState: 'missing', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null });
  private port: GitHubConnectionObservationPort | null = null;
  private observer: Observation | null = null;
  private listeners = new Set<() => void>();
  private epoch: object = {};
  private disposed = false;
  private pending: Pending | null = null;
  private retirement: Retirement | null = null;
  private otherOperationReason: () => string | null;
  constructor(otherOperationReason: () => string | null = () => null) { this.otherOperationReason = otherOperationReason; }

  getSnapshot = (): GitHubConnectionViewState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<GitHubConnectionViewState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); this.listeners.forEach((listener) => listener());
  }
  private fail(reason: GitHubConnectionReason, block = false): void {
    if (block && this.pending) this.pending.uncertain = true;
    this.update({ error: reason, blocked: this.state.blocked || block, uncertain: this.state.uncertain || block && this.pending !== null });
  }
  private needsOriginal(observer: Observation): boolean {
    return this.retirement?.observer === observer || !!this.pending && this.pending.observer === observer && this.pending.sent && !this.pending.done;
  }
  private detach(observer: Observation): void {
    observer.active = false; observer.listening = false;
    const unlisten = observer.unlisten; observer.unlisten = null;
    try { unlisten?.(); } catch { /* A listener close is not native settlement. */ }
  }
  private maintainObserver(): Observation | null {
    if (this.observer && (this.disposed || this.observer.port !== this.port)) {
      if (this.needsOriginal(this.observer)) return this.observer;
      this.detach(this.observer); this.observer = null;
    }
    if (!this.observer && !this.disposed && this.port?.mode === 'native') {
      const observer: Observation = { port: this.port, active: true, listening: false, subscriptionFailed: false, unlisten: null, ready: null, reading: null,
        serial: {}, accepted: null, identity: null, retiredSessionId: null };
      this.observer = observer; observer.ready = this.monitor(observer);
    }
    return this.observer;
  }
  private invalidateView(patch: Partial<GitHubConnectionViewState>): void {
    this.epoch = {};
    const pending = this.pending;
    if (pending) {
      pending.retiring = true;
      // No token handoff has occurred yet; synchronous subscriber invalidation
      // can retire this unsent intent without inventing a native operation.
      if (!pending.sent) { pending.done = true; this.pending = null; }
    }
    const observer = this.observer;
    if (observer && !this.needsOriginal(observer) && !observer.accepted?.session) {
      // Before the first accepted Status, coordinates alone cannot bind an
      // observation to this view. Retire the unneeded callback/read before
      // notifying subscribers; away-and-back cannot make its result current.
      // A sent Connect's original retirement-only observer is NOT replaced.
      this.observer = null; this.detach(observer);
      patch = { ...patch, observing: false };
    }
    const mustRetire = !!this.retirement || !!this.pending || !!this.observer?.accepted?.session;
    this.update({ ...patch, status: null, retained: this.state.status ?? this.state.retained,
      retirementPending: mustRetire, busy: mustRetire ? 'disconnect' : null,
      uncertain: this.pending?.uncertain ?? (!!this.retirement && this.state.uncertain), error: null });
    this.retireOriginal(); this.maintainObserver();
  }
  setHelp(value: unknown): void {
    if (this.disposed) return;
    const help = parseGitHubConnectionHelp(value);
    const patch: Partial<GitHubConnectionViewState> = help ? { help, helpState: 'current' } : { helpState: this.state.help ? 'previous' : 'missing' };
    if (this.state.helpState === 'current' && (!help || !sameConnectionData(help, this.state.help))) this.invalidateView(patch);
    else this.update(patch);
  }
  setContext(value: GitHubConnectionContext | null): void {
    if (this.disposed) return;
    let context: GitHubConnectionContext | null;
    try { context = contextCopy(value); } catch { context = null; }
    if (!sameConnectionData(context, this.state.context)) this.invalidateView({ context });
  }
  async attach(port: GitHubConnectionObservationPort | null): Promise<void> {
    if (this.disposed || this.port === port) return;
    this.port = port;
    this.invalidateView({ mode: port?.mode ?? 'unavailable', observing: false });
    // When an old Connect is still unacknowledged this is its ORIGINAL observer,
    // not a replacement subscription that could guess which session to cancel.
    await this.maintainObserver()?.ready;
  }
  private async monitor(observer: Observation): Promise<void> {
    try {
      const unlisten = await observer.port.subscribe((value) => { if (observer.active) this.receive(observer, value); });
      if (!observer.active) { try { unlisten(); } catch { /* Retired subscription only. */ } return; }
      observer.unlisten = unlisten; observer.listening = true;
      await this.readStatus(observer); // Subscribe before first Status; no read/auth retry.
    } catch {
      observer.subscriptionFailed = true;
      if (observer.active) this.fail('runtime-unavailable');
      // Explicit Status remains usable even after subscription failure. It is
      // not proof of refusal and does not release an unacknowledged intent.
    }
  }
  private matches(status: GitHubConnectionStatus): boolean {
    const context = this.state.context; const session = status.session;
    return session === null || !!context && context.projectId === session.projectId && context.repository === session.targetRepository;
  }
  private originMatches(pending: Pending, status: GitHubConnectionStatus): boolean {
    const session = status.session; const operation = status.operation;
    return status.revision > pending.baseRevision && !!session && !!operation &&
      session.projectId === pending.context.projectId && session.targetRepository === pending.context.repository &&
      operation.kind === pending.kind && operation.id !== pending.oldOperationId &&
      (pending.sessionId === null || pending.sessionId === session.id) &&
      (pending.operationId === null || pending.operationId === operation.id);
  }
  private correlate(observer: Observation, status: GitHubConnectionStatus): void {
    const pending = this.pending;
    if (!pending || pending.observer !== observer || !pending.sent || !this.originMatches(pending, status)) return;
    pending.sessionId = status.session!.id; pending.operationId = status.operation!.id;
    pending.admittedRevision ??= status.revision;
    if (pending.retiring) this.retireOriginal();
    else this.settlePending(observer.accepted);
  }
  private receive(observer: Observation, value: unknown, readSerial?: object): GitHubConnectionStatus | null {
    if (!observer.active) return null;
    const status = parseGitHubConnectionStatus(value);
    if (!status) {
      if (readSerial === undefined || readSerial === observer.serial) this.fail('response-invalid', true);
      return null;
    }
    const old = observer.accepted;
    if (old && status.revision < old.revision) {
      // The admitted reply may be behind its own settled event. A coherent
      // earlier frame can bind the origin, but can never replace newer DATA.
      if (connectionProgress(status, old)) this.correlate(observer, status);
      return status;
    }
    if (status.session?.id === observer.retiredSessionId && ['checking', 'connected'].includes(status.session.state)) return status;
    if (old && !connectionProgress(old, status)) { this.fail('response-invalid', true); return null; }
    if (this.retirement?.observer === observer && status.session && status.session.id !== this.retirement.sessionId) {
      this.fail('target-changed', true); return null;
    }
    const pending = this.pending;
    if (old?.session === null && status.session && (!pending || pending.observer !== observer || !pending.sent || !this.originMatches(pending, status))) {
      this.fail('target-changed', true); return null;
    }
    const pinned = observer.identity;
    if (status.session && pinned?.sessionId === status.session.id &&
        (pinned.accountId && status.account.value && pinned.accountId !== status.account.value.id ||
         pinned.repositoryId && status.repository.value && pinned.repositoryId !== status.repository.value.id)) {
      this.fail('target-changed', true); return null;
    }
    observer.identity = status.session === null ? null : {
      sessionId: status.session.id,
      accountId: (pinned?.sessionId === status.session.id ? pinned.accountId : null) ?? status.account.value?.id ?? null,
      repositoryId: (pinned?.sessionId === status.session.id ? pinned.repositoryId : null) ?? status.repository.value?.id ?? null,
    };
    observer.accepted = status; observer.serial = {};
    this.correlate(observer, status);
    if (this.retirement?.observer === observer && status.session === null && status.revision > this.retirement.revision) {
      this.finishRetirement();
      if (this.observer !== observer || !observer.active) return status;
    }
    const blocked = this.state.blocked || status.session?.state === 'cleanup-unknown';
    const blockingReason = status.session?.state === 'cleanup-unknown' ? 'cleanup-unknown' : this.state.error;
    const retiring = this.pending?.retiring || this.retirement?.observer === observer;
    if (observer.port === this.port && this.matches(status) && !retiring) {
      this.update({ status, blocked, error: blocked ? blockingReason ?? 'cleanup-unknown' : this.state.uncertain ? this.state.error : null });
    } else {
      this.update({ retained: status, status: null, blocked,
        error: blocked ? blockingReason ?? 'cleanup-unknown' : retiring ? this.state.error : 'target-changed' });
    }
    this.settlePending(observer.accepted);
    return status;
  }
  private settlePending(status: GitHubConnectionStatus | null): void {
    const pending = this.pending;
    if (!pending || pending.retiring || pending.done || !pending.sent || !status || !this.originMatches(pending, status) ||
        pending.operationId === null || status.operation?.phase !== 'settled' || this.disposed ||
        pending.epoch !== this.epoch || pending.observer.port !== this.port || !sameConnectionData(pending.context, this.state.context)) return;
    pending.done = true; this.pending = null;
    this.update({ busy: null, uncertain: false, error: this.state.blocked ? this.state.error : null });
    this.maintainObserver();
  }
  private async readStatus(observer: Observation): Promise<void> {
    if (!observer.active || !observer.listening && !observer.subscriptionFailed || this.disposed && !this.needsOriginal(observer)) return;
    if (observer.reading) return observer.reading;
    const serial = observer.serial;
    const work = Promise.resolve().then(async () => {
      if (!observer.active || this.disposed && !this.needsOriginal(observer)) return;
      try { this.receive(observer, await observer.port.status(), serial); }
      catch { if (observer.active && serial === observer.serial) this.fail('response-invalid'); }
    });
    observer.reading = work; this.update({ observing: true });
    try { await work; } finally {
      if (observer.reading === work) {
        observer.reading = null;
        if (this.observer === observer) this.update({ observing: false });
      }
    }
  }
  checkStatus(): Promise<void> {
    const observer = this.maintainObserver();
    return observer ? this.readStatus(observer) : Promise.resolve();
  }
  canCheckStatus(): boolean { return !this.disposed && !!this.observer?.active && (this.observer.listening || this.observer.subscriptionFailed); }
  private contextReady(): boolean {
    const observer = this.observer; const status = this.state.status;
    return !this.disposed && !this.otherOperationReason() && this.port?.mode === 'native' && !!observer && observer.port === this.port && observer.listening &&
      !!this.state.context && !!status && observer.accepted?.revision === status.revision && this.matches(status) && status.capability.readOnlySessionAvailable &&
      this.state.helpState === 'current' && !this.state.blocked && !this.state.error && !this.state.uncertain &&
      !this.retirement && !this.state.retirementPending;
  }
  // Logical eligibility only. The component AND bridge independently enforce
  // the compiled entry gate; native qualification is never a renderer Boolean.
  canConnect(): boolean { return !this.pending && !this.state.busy && this.contextReady() && this.state.status?.session === null; }
  connectToken(token: string, handoff: GitHubConnectionTokenHandoff): boolean {
    if (!this.canConnect() || handoff.port !== this.port || !this.observer || !this.state.context || !this.state.status) return false;
    const context = this.state.context;
    if (!githubConnectionRequestFits('github_connection_connect_token', { projectId: context.projectId, repository: context.repository, token })) {
      this.fail('invalid-input'); return false;
    }
    const pending = this.newPending('connect', this.observer, context, this.state.status);
    this.pending = pending; this.update({ busy: 'connect', uncertain: false, error: null });
    if (!this.unsentCurrent(pending) || !this.contextReady() || this.state.status?.session !== null || handoff.port !== this.port) {
      this.discardUnsent(pending); return false;
    }
    pending.sent = true;
    try {
      // No async function/callback here retains token or args. Only this one
      // synchronous handoff receives them. observeReply captures safe metadata.
      this.observeReply(pending, handoff.submit({ projectId: context.projectId, repository: context.repository, token }));
    } catch (error) { this.originRejected(pending, error); }
    return true;
  }
  private newPending(kind: Pending['kind'], observer: Observation, context: GitHubConnectionContext, status: GitHubConnectionStatus): Pending {
    return { kind, observer, epoch: this.epoch, context, baseRevision: status.revision, oldOperationId: status.operation?.id ?? null,
      sessionId: kind === 'refresh' ? status.session!.id : null, operationId: null, admittedRevision: null,
      sent: false, retiring: false, uncertain: false, done: false };
  }
  private unsentCurrent(pending: Pending): boolean {
    return !this.disposed && this.pending === pending && !pending.retiring && !pending.done && pending.epoch === this.epoch &&
      pending.observer.port === this.port && sameConnectionData(pending.context, this.state.context) && this.state.status?.revision === pending.baseRevision;
  }
  private discardUnsent(pending: Pending): void {
    if (pending.sent || pending.done) return;
    pending.done = true;
    if (this.pending === pending) { this.pending = null; this.update({ busy: this.retirement ? 'disconnect' : null }); }
    this.maintainObserver();
  }
  private refreshReady(): boolean {
    const status = this.state.status;
    return this.contextReady() && !!status && (status.session?.state === 'connected' || connectionRetryable(status));
  }
  canRefresh(): boolean { return !this.pending && !this.state.busy && this.refreshReady(); }
  refresh(): boolean {
    if (!this.canRefresh() || !this.observer || !this.state.status?.session || !this.state.context) return false;
    const pending = this.newPending('refresh', this.observer, this.state.context, this.state.status);
    this.pending = pending; this.update({ busy: 'refresh', uncertain: false, error: null });
    if (!this.unsentCurrent(pending) || !this.refreshReady() || this.state.status?.session?.id !== pending.sessionId) {
      this.discardUnsent(pending); return false;
    }
    pending.sent = true;
    try { this.observeReply(pending, pending.observer.port.refresh({ sessionId: pending.sessionId!, expectedRevision: pending.baseRevision })); }
    catch (error) { this.originRejected(pending, error); }
    return true;
  }
  private observeReply(pending: Pending, work: Promise<unknown>): void {
    // This method's lexical environment contains no token/private request.
    void work.then((value) => {
      if (pending.done || this.pending !== pending || !pending.observer.active) return;
      const reply = this.receive(pending.observer, value);
      if (!pending.done && (!reply || !this.originMatches(pending, reply))) this.originRejected(pending, null);
    }, (error) => this.originRejected(pending, error));
  }
  private originRejected(pending: Pending, value: unknown): void {
    if (pending.done || this.pending !== pending) return;
    const error = githubConnectionError(value);
    if (error.admission === 'not-admitted' && pending.operationId === null) {
      pending.done = true; this.pending = null;
      this.update({ busy: this.retirement ? 'disconnect' : null, retirementPending: !!this.retirement,
        uncertain: !!this.retirement && this.state.uncertain,
        error: pending.retiring || pending.observer.port !== this.port ? this.state.error : error.reason });
      this.maintainObserver(); return;
    }
    pending.uncertain = true;
    this.update({ uncertain: true }); this.fail('response-invalid', error.admission === 'not-admitted');
    // A refused code contradicting an already identified admission cannot undo
    // the latter. Keep the original session available for exact retirement.
  }
  canDisconnect(): boolean {
    const observer = this.observer;
    if (this.disposed || !observer?.active || observer.port.mode !== 'native' || this.retirement) return false;
    if (this.pending?.kind === 'connect' && this.pending.sessionId === null) return false;
    return !!observer.accepted?.session;
  }
  disconnect(): boolean {
    if (!this.canDisconnect()) return false;
    if (this.pending) this.pending.retiring = true;
    this.retireOriginal(); return true;
  }
  private retireOriginal(): void {
    if (this.retirement) return;
    const pending = this.pending; const observer = this.observer;
    if (!observer?.active) return;
    if (pending?.retiring && pending.kind === 'connect' && pending.sessionId === null) return;
    const sessionId = pending?.retiring ? pending.sessionId : observer.accepted?.session?.id;
    const accepted = observer.accepted;
    const revision = accepted?.session && accepted.session.id === sessionId ? accepted.revision : pending?.admittedRevision ?? pending?.baseRevision;
    if (!sessionId || revision === undefined || observer.retiredSessionId === sessionId) return;
    observer.retiredSessionId = sessionId;
    const retirement: Retirement = { observer, sessionId, revision }; this.retirement = retirement;
    this.update({ busy: 'disconnect', retirementPending: true, error: 'cancelled' });
    const failed = () => {
      if (this.retirement === retirement) { this.update({ uncertain: true }); this.fail('response-invalid'); }
    };
    try { void observer.port.disconnect({ sessionId }).then((value) => { if (this.retirement === retirement) this.receive(observer, value); }, failed); }
    catch { failed(); }
    if (observer.accepted?.session === null && observer.accepted.revision > retirement.revision) this.finishRetirement();
  }
  private finishRetirement(): void {
    const retirement = this.retirement;
    if (!retirement) return;
    if (this.pending?.observer === retirement.observer) { this.pending.done = true; this.pending = null; }
    this.retirement = null;
    this.update({ busy: null, retirementPending: false, uncertain: false, error: this.state.blocked ? this.state.error : null });
    this.maintainObserver();
  }
  dispose(): void {
    if (this.disposed) return;
    this.invalidateView({});
    this.disposed = true; this.listeners.clear(); this.maintainObserver();
    // Retain at most the original reply/listener for exact late retirement.
    // Document destruction independently retires native state, not JS success.
  }
}
