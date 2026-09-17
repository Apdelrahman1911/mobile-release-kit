// Inert-port UI coordination only. No live bridge, Connect/token method, timers,
// credential storage or optimistic native settlement. Native owns all admission.
import type { GitHubConnectionContext, GitHubConnectionObservationPort, GitHubConnectionReason,
  GitHubConnectionStatus, GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { connectionOpaqueId, connectionProgress, connectionRepository, connectionRevision,
  parseGitHubConnectionHelp, parseGitHubConnectionStatus, sameConnectionData } from './githubConnectionProtocol.ts';

function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze); Object.freeze(value);
  }
  return value;
}
function contextCopy(value: GitHubConnectionContext | null): GitHubConnectionContext | null {
  if (value === null) return null;
  if (Object.keys(value).length !== 4 || !connectionOpaqueId(value.documentId) || !connectionOpaqueId(value.projectId) ||
      !connectionRevision(value.projectGeneration) || !connectionRepository(value.repository)) return null;
  return { documentId: value.documentId, projectId: value.projectId, projectGeneration: value.projectGeneration, repository: value.repository };
}
interface Pending {
  write: number; sessionId: string; baseRevision: number; oldOperationId: string | null;
  operationId: string | null; uncertain: boolean;
}

export class GitHubConnectionController {
  private state: GitHubConnectionViewState = freeze({ mode: 'unavailable', context: null, status: null, retained: null,
    help: null, helpState: 'missing', observing: false, busy: null, uncertain: false, blocked: false, retirementPending: false, error: null });
  private port: GitHubConnectionObservationPort | null = null;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private epoch = 0;
  private write = 0;
  private serial = 0;
  private disposed = false;
  private reading: { epoch: number; work: Promise<void> } | null = null;
  private accepted: GitHubConnectionStatus | null = null;
  private identity: { sessionId: string; accountId: string | null; repositoryId: string | null } | null = null;
  private pending: Pending | null = null;
  private retirement: { port: GitHubConnectionObservationPort; sessionId: string; revision: number } | null = null;
  private retiredSessionId: string | null = null;

  getSnapshot = (): GitHubConnectionViewState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<GitHubConnectionViewState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); this.listeners.forEach((listener) => listener());
  }
  private current(epoch: number, port: GitHubConnectionObservationPort): boolean { return !this.disposed && epoch === this.epoch && port === this.port; }
  private invalidate(): void {
    this.epoch += 1; this.write += 1; this.pending = null; this.reading = null;
    const unlisten = this.unlisten; this.unlisten = null;
    // Detaching a renderer listener is not native cancellation or settlement.
    try { unlisten?.(); } catch { /* No raw callback diagnostic is rendered. */ }
  }
  private fail(reason: GitHubConnectionReason, block = false): void {
    this.serial += 1;
    this.update({ error: reason, blocked: this.state.blocked || block });
  }
  setHelp(value: unknown): void {
    if (this.disposed) return;
    const help = parseGitHubConnectionHelp(value);
    this.update(help ? { help, helpState: 'current' } : { helpState: this.state.help ? 'previous' : 'missing' });
  }
  setContext(value: GitHubConnectionContext | null): void {
    if (this.disposed) return;
    let context: GitHubConnectionContext | null;
    try { context = contextCopy(value); } catch { context = null; }
    if (sameConnectionData(context, this.state.context)) return;
    const old = this.state.status; const port = this.port;
    this.invalidate(); // Away-and-back changes invalidate before any async work.
    this.update({ context, status: null, retained: old ?? this.state.retained, observing: false,
      busy: this.retirement ? 'disconnect' : null, uncertain: false, error: null });
    if (old?.session && port?.mode === 'native') this.beginDisconnect(old, port, false);
    if (port?.mode === 'native') void this.monitor(port, this.epoch);
  }
  async attach(port: GitHubConnectionObservationPort | null): Promise<void> {
    if (this.disposed || this.port === port) return;
    const old = this.state.status; const previous = this.port;
    this.invalidate();
    if (old?.session && previous?.mode === 'native') this.beginDisconnect(old, previous, false);
    this.port = port; this.accepted = null;
    this.update({ mode: port?.mode ?? 'unavailable', status: null, retained: old ?? this.state.retained, observing: false,
      busy: this.retirement ? 'disconnect' : null, uncertain: false, error: null,
      blocked: this.state.blocked || this.retirement !== null && this.retirement.port !== port });
    if (port?.mode === 'native') await this.monitor(port, this.epoch);
  }
  private async monitor(port: GitHubConnectionObservationPort, epoch: number): Promise<void> {
    try {
      const unlisten = await port.subscribe((value) => { if (this.current(epoch, port)) this.receive(value); });
      if (!this.current(epoch, port)) { try { unlisten(); } catch { /* Old teardown, not current state. */ } return; }
      this.unlisten = unlisten;
      await this.checkStatus(); // Subscribe before the first read; no auth retry.
    } catch {
      if (this.current(epoch, port)) this.fail('runtime-unavailable');
    }
  }
  private matches(status: GitHubConnectionStatus): boolean {
    const context = this.state.context; const session = status.session;
    return session === null || !!context && context.projectId === session.projectId && context.repository === session.targetRepository;
  }
  private receive(value: unknown, readSerial?: number): GitHubConnectionStatus | null {
    const status = parseGitHubConnectionStatus(value);
    if (!status) {
      // A malformed reply to an older retained read is an old error too. A
      // current event/reply still fails closed; valid revision conflicts do not
      // get this exemption merely because their request began earlier.
      if (readSerial === undefined || readSerial === this.serial) this.fail('response-invalid', true);
      return null;
    }
    const old = this.accepted;
    if (old && status.revision < old.revision) return status;
    if (old && !connectionProgress(old, status)) { this.fail('response-invalid', true); return null; }
    // Never resurrect the original session after a local retirement request,
    // even if its late refresh success has a greater status revision.
    if (status.session?.id === this.retiredSessionId && ['checking', 'connected'].includes(status.session.state)) return status;
    if (this.retirement && this.retirement.port === this.port && status.session && status.session.id !== this.retirement.sessionId) {
      this.fail('target-changed', true); return null;
    }
    const pinned = this.identity;
    if (status.session && pinned?.sessionId === status.session.id &&
        (pinned.accountId && status.account.value && pinned.accountId !== status.account.value.id ||
         pinned.repositoryId && status.repository.value && pinned.repositoryId !== status.repository.value.id)) {
      this.fail('target-changed', true); return null;
    }
    // Remember original immutable identities across temporarily unavailable
    // facts; comparing only the immediately previous DTO loses that binding.
    this.identity = status.session === null ? null : {
      sessionId: status.session.id,
      accountId: (pinned?.sessionId === status.session.id ? pinned.accountId : null) ?? status.account.value?.id ?? null,
      repositoryId: (pinned?.sessionId === status.session.id ? pinned.repositoryId : null) ?? status.repository.value?.id ?? null,
    };
    this.accepted = status; this.serial += 1;
    if (this.retirement?.port === this.port && status.session === null && status.revision > this.retirement.revision) {
      this.retirement = null; this.pending = null;
      this.update({ retirementPending: false, busy: null, uncertain: false });
    }
    const blocked = this.state.blocked || status.session?.state === 'cleanup-unknown';
    if (this.matches(status)) this.update({ status, blocked, error: blocked ? this.state.error ?? 'cleanup-unknown' : null });
    else this.update({ retained: status, status: null, blocked, error: 'target-changed' });
    this.settlePending();
    return status;
  }
  private settlePending(): void {
    const pending = this.pending; const operation = this.accepted?.operation;
    if (pending && !pending.uncertain && pending.operationId && this.accepted?.session?.id === pending.sessionId &&
        operation?.id === pending.operationId && operation.phase === 'settled') {
      this.pending = null; this.update({ busy: null, uncertain: false });
    }
  }
  async checkStatus(): Promise<void> {
    const port = this.port; const epoch = this.epoch;
    if (this.disposed || port?.mode !== 'native' || !this.unlisten) return;
    if (this.reading?.epoch === epoch) return this.reading.work;
    const serial = this.serial;
    const work = Promise.resolve().then(async () => {
      // A queued read can be retired before its microtask gets a turn. Checking
      // only the eventual reply would still invoke an abandoned native port.
      if (!this.current(epoch, port) || !this.unlisten) return;
      try {
        const value = await port.status();
        if (this.current(epoch, port)) this.receive(value, serial);
      } catch {
        // A newer original event outranks an older read's failure too.
        if (this.current(epoch, port) && serial === this.serial) this.fail('response-invalid');
      }
    });
    this.reading = { epoch, work }; this.update({ observing: true });
    try { await work; } finally {
      if (this.current(epoch, port) && this.reading?.work === work) { this.reading = null; this.update({ observing: false }); }
    }
  }
  private refreshContextReady(): boolean {
    const status = this.state.status;
    return !this.disposed && this.port?.mode === 'native' && !!this.unlisten && !!status && this.matches(status) &&
      status.capability.readOnlySessionAvailable && status.session?.state === 'connected' && this.state.helpState === 'current' &&
      !this.state.blocked && !this.state.error && !this.state.uncertain && !this.retirement;
  }
  canRefresh(): boolean { return !this.state.busy && this.refreshContextReady(); }
  refresh(): boolean {
    const port = this.port; const status = this.state.status;
    if (!this.canRefresh() || !port || !status?.session) return false;
    const epoch = this.epoch; const write = ++this.write;
    const pending: Pending = { write, sessionId: status.session.id, baseRevision: status.revision,
      oldOperationId: status.operation?.id ?? null, operationId: null, uncertain: false };
    this.pending = pending; this.update({ busy: 'refresh', uncertain: false, error: null });
    const failed = () => {
      if (this.current(epoch, port) && this.write === write && this.pending === pending) {
        pending.uncertain = true; this.update({ uncertain: true }); this.fail('response-invalid');
      }
    };
    try {
      // update() synchronously notifies listeners. They may retire the context,
      // request Disconnect, invalidate help or publish a newer native status.
      // Re-admit the exact unsent request, not merely its eventual callback.
      if (!this.current(epoch, port) || this.write !== write || this.pending !== pending) return false;
      if (!this.refreshContextReady() || this.state.status?.revision !== pending.baseRevision ||
          this.state.status?.session?.id !== pending.sessionId) {
        this.pending = null; this.update({ busy: null }); return false;
      }
      void port.refresh({ sessionId: pending.sessionId, expectedRevision: pending.baseRevision }).then((value) => {
        if (!this.current(epoch, port) || this.write !== write || this.pending !== pending) return;
        const reply = parseGitHubConnectionStatus(value);
        if (!reply || reply.revision <= pending.baseRevision || reply.session?.id !== pending.sessionId ||
            reply.operation?.kind !== 'refresh' || reply.operation.id === pending.oldOperationId) { failed(); return; }
        pending.operationId = reply.operation.id;
        this.receive(reply); this.settlePending();
      }, failed);
    } catch { failed(); }
    return true;
  }
  canDisconnect(): boolean {
    const session = this.state.status?.session;
    // Busy, capability/help failure and a pending Status do not block retirement.
    return !this.disposed && this.port?.mode === 'native' && !!session && this.matches(this.state.status!) &&
      session.state !== 'cleanup-unknown' && session.state !== 'disconnecting' && !this.retirement;
  }
  disconnect(): boolean {
    if (!this.canDisconnect() || !this.port || !this.state.status) return false;
    this.beginDisconnect(this.state.status, this.port, true); return true;
  }
  private beginDisconnect(status: GitHubConnectionStatus, port: GitHubConnectionObservationPort, report: boolean): void {
    const session = status.session;
    if (!session || this.retirement || session.id === this.retiredSessionId) return;
    const epoch = this.epoch; const write = ++this.write;
    this.pending = null; this.retiredSessionId = session.id;
    this.retirement = { port, sessionId: session.id, revision: status.revision };
    this.update({ busy: 'disconnect', retirementPending: true, uncertain: false, error: 'cancelled' });
    const failed = () => {
      if (report && this.current(epoch, port) && this.write === write && this.retirement) {
        this.update({ uncertain: true }); this.fail('response-invalid');
      }
    };
    try {
      void port.disconnect({ sessionId: session.id }).then((value) => {
        if (report && this.current(epoch, port) && this.write === write) this.receive(value);
      }, failed);
    } catch { failed(); }
  }
  dispose(): void {
    if (this.disposed) return;
    const status = this.state.status; const port = this.port;
    this.invalidate();
    if (status?.session && port?.mode === 'native') this.beginDisconnect(status, port, false);
    this.disposed = true; this.listeners.clear();
    // The original native owner still owes settlement. No erasure claim here.
  }
}
