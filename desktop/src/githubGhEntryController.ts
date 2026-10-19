// Original selected-gh picker/capture custody only. The existing connection
// controller exclusively owns account facts, HTTP correlation and Connected.
import type { GitHubConnectionController } from './githubConnectionController.ts';
import type { GitHubConnectionContext, GitHubConnectionObservationPort, GitHubConnectionReason } from './githubConnectionTypes.ts';
import { connectionKeys, connectionOpaqueId, connectionRepository, connectionRevision, sameConnectionData } from './githubConnectionProtocol.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { ghActive, ghAdmissionRevision, ghLoginFits, ghResultMatches, ghUnconfirmed, githubGhFailure,
  parseGitHubGhResult, parseGitHubGhStatus } from './githubGhEntryProtocol.ts';
import type { GitHubGhApi, GitHubGhRequest, GitHubGhStatus } from './githubGhEntryProtocol.ts';

export interface GitHubGhSource {
  current(): { api: GitHubGhApi | null; port: GitHubConnectionObservationPort | null;
    context: GitHubConnectionContext | null; blocked: string | null };
}
export interface GitHubGhClock { schedule(callback: () => void, delay: number): unknown; cancel(handle: unknown): void }
export interface GitHubGhView {
  mode: 'native' | 'unavailable'; context: GitHubConnectionContext | null; login: string;
  status: GitHubGhStatus | null; original: GitHubGhStatus | null; originalProjectId: string | null;
  pendingCount: number; reading: boolean; cancelRequested: boolean;
  issue: 'unconfirmed' | 'cleanup-unknown' | null; failure: GitHubConnectionReason | null;
}
interface Binding { identity: GitHubGhApi; api: GitHubGhApi; port: GitHubConnectionObservationPort }
interface Attempt {
  binding: Binding; context: GitHubConnectionContext; epoch: object; request: GitHubGhRequest;
  previousId: string | null; operationId: string | null; auth: GitHubGhStatus | null;
  http: { sessionId: string; operationId: string } | null; sent: boolean; retired: boolean;
  cancelRequested: boolean; cancelSent: boolean; ended: boolean; refused: boolean;
}
interface Work { kind: 'connect' | 'status' | 'cancel'; promise: Promise<unknown> | null }
const clock: GitHubGhClock = { schedule: (fn, delay) => globalThis.setTimeout(fn, delay),
  cancel: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>) };
function contextCopy(value: unknown): GitHubConnectionContext | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 24);
    return connectionKeys(v, ['documentId', 'projectId', 'projectGeneration', 'repository']) &&
      connectionOpaqueId(v.documentId) && connectionOpaqueId(v.projectId) && connectionRevision(v.projectGeneration) && connectionRepository(v.repository)
      ? v as unknown as GitHubConnectionContext : null;
  } catch { return null; }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

export class GitHubGhEntryController {
  #connection: GitHubConnectionController; #source: GitHubGhSource; #clock: GitHubGhClock;
  #binding: Binding | null = null; #context: GitHubConnectionContext | null = null; #epoch: object = {};
  #attempt: Attempt | null = null; #status: GitHubGhStatus | null = null; #fresh = false;
  #issue: GitHubGhView['issue'] = null; #failure: GitHubConnectionReason | null = null;
  #drafts = new Map<string, string>(); #works = new Set<Work>(); #reading: Work | null = null;
  #fence = 0; #starting = false; #disposed = false; #notifying = false;
  #timer: unknown = null; #polls = 0; #off: (() => void) | null; #observedCancel: string | null = null;
  #listeners = new Set<() => void>();
  #state: GitHubGhView = freeze({ mode: 'unavailable', context: null, login: '', status: null, original: null,
    originalProjectId: null, pendingCount: 0, reading: false, cancelRequested: false, issue: null, failure: null });
  constructor(connection: GitHubConnectionController, source: GitHubGhSource, timer: GitHubGhClock = clock) {
    this.#connection = connection; this.#source = source; this.#clock = timer;
    this.#off = connection.subscribe(() => this.syncContext());
  }
  getSnapshot = (): GitHubGhView => this.#state;
  subscribe = (listener: () => void): (() => void) => { this.#listeners.add(listener); return () => { this.#listeners.delete(listener); }; };
  #current() {
    try { const source = this.#source.current(); return { api: source.api, port: source.port,
      context: contextCopy(source.context), blocked: typeof source.blocked === 'string' ? source.blocked : null }; }
    catch { return { api: null, port: null, context: null, blocked: 'The current project connection is unavailable.' }; }
  }
  #publish(): void {
    const original = this.#attempt?.sent ? this.#attempt.auth : this.#status;
    this.#state = freeze({ mode: this.#binding ? 'native' : 'unavailable', context: this.#context,
      login: this.#context ? this.#drafts.get(this.#context.projectId) ?? '' : '', status: this.#fresh ? this.#status : null,
      original, originalProjectId: this.#attempt?.request.projectId ?? original?.projectId ?? null,
      pendingCount: this.#works.size, reading: this.#reading !== null, cancelRequested: this.#attempt?.cancelRequested || this.#observedCancel !== null,
      issue: this.#issue, failure: this.#failure });
    if (this.#notifying) return;
    this.#notifying = true;
    try { for (const listener of [...this.#listeners]) { try { listener(); } catch { /* Views cannot release originals. */ } } }
    finally { this.#notifying = false; }
  }
  #fail(issue: GitHubGhView['issue'] = 'unconfirmed'): void {
    if (this.#issue !== 'cleanup-unknown') this.#issue = issue;
    this.#fresh = false; this.#publish();
  }
  /** Root also includes this in other-action/reconnect/passive-read gates. */
  ownerReason(): string | null {
    if (this.#issue) return 'The original GitHub CLI request is unconfirmed. Keep the app open; check or stop that request instead of connecting again.';
    const known = this.#attempt?.sent ? this.#attempt.auth : this.#status;
    if (this.#works.size || this.#attempt?.sent && !this.#attempt.ended || ghActive(known))
      return 'The original GitHub CLI request is still finishing. Its status and Stop controls remain available.';
    if (known?.phase === 'cleanup-unknown') return 'GitHub CLI cleanup is unconfirmed. Keep the app open and do not repeat the connection.';
    return null;
  }
  /** Explicit API handoff only; never drop an old original to reconnect. */
  attach(api: GitHubGhApi | null, port: GitHubConnectionObservationPort | null): boolean {
    if (this.#disposed) return false;
    if (this.#binding?.identity === api && this.#binding?.port === port) return true;
    if (this.ownerReason()) return false;
    this.beforeContextIntent();
    if (this.ownerReason()) return false; // A synchronous listener may have started a read.
    if (api?.mode === 'native' && port?.mode === 'native') {
      const { status, connect, cancel } = api;
      if (![status, connect, cancel].every((f) => typeof f === 'function')) return false;
      this.#binding = { identity: api, port, api: Object.freeze({ mode: 'native' as const,
        status: () => status.call(api), connect: (r: GitHubGhRequest) => connect.call(api, r), cancel: (r: { operationId: string }) => cancel.call(api, r) }) };
    } else this.#binding = null;
    this.#attempt = null; this.#status = null; this.#fresh = false; this.#failure = null; this.#observedCancel = null;
    this.syncContext(); return true;
  }
  syncContext(): void {
    if (this.#disposed) return;
    const current = this.#current(), changed = !sameConnectionData(this.#context, current.context) ||
      !!this.#binding && (this.#binding.identity !== current.api || this.#binding.port !== current.port);
    this.#context = current.context;
    if (changed) this.beforeContextIntent();
    this.#publish();
  }
  /** BEFORE even no-op project/repository/service intents, not ordinary renders. */
  beforeContextIntent(): void {
    this.#epoch = {}; this.#fence++; this.#fresh = false;
    const a = this.#attempt;
    if (a && !a.ended) { a.retired = true; if (a.sent) a.cancelRequested = true; }
    this.#publish(); this.#sendCancel();
  }
  setLogin(value: string): boolean {
    if (this.#disposed || typeof value !== 'string' || value.length > 39 || this.#starting || this.ownerReason()) return false;
    const c = this.#current().context;
    if (!c) return false;
    // Local nonsecret draft only; typing neither discovers nor selects an account.
    this.#epoch = {}; this.#fence++; this.#context = c; this.#drafts.set(c.projectId, value); this.#failure = null;
    // An idle profile/revision observation is not login verification or consent.
    // Keep that comparison; native still rechecks it on the explicit Connect.
    this.#publish(); return true;
  }
  startReason(): string | null {
    const c = this.#current(), b = this.#binding, status = this.#status;
    if (this.#disposed || !b || b.identity !== c.api || b.port !== c.port) return 'GitHub CLI connection needs the connected native Desktop app.';
    if (!c.context) return 'Select your project and enter its GitHub repository first.';
    if (this.#starting || this.ownerReason()) return this.ownerReason() ?? 'A connection is being submitted.';
    if (c.blocked) return c.blocked;
    if (!ghLoginFits(this.#drafts.get(c.context.projectId))) return 'Enter the username already signed in with GitHub CLI.';
    if (!this.#fresh || !status) return 'Check GitHub CLI availability for this project before connecting.';
    if (!status.available) return 'GitHub CLI connection is not available in this native build. The separate token option is unchanged.';
    if (!ghAdmissionRevision(status.documentRevision) || !ghAdmissionRevision(status.connectionRevision)) return 'The original native comparison is exhausted. Do not start a new connection.';
    if (status.connectionRevision !== this.#connection.getSnapshot().status?.revision) return 'Check the connection status, then GitHub CLI availability again.';
    return this.#connection.canConnect() ? null : 'Check the connection status below, or finish the original connection before connecting again.';
  }
  #same(a: Attempt): boolean {
    const c = this.#current();
    return !this.#disposed && this.#attempt === a && !a.retired && this.#epoch === a.epoch &&
      this.#binding === a.binding && a.binding.identity === c.api && a.binding.port === c.port &&
      sameConnectionData(a.context, c.context) && c.blocked === null;
  }
  connect(): boolean {
    if (this.startReason()) return false;
    const b = this.#binding, current = this.#current(), context = current.context, status = this.#status;
    if (!b || !context || !status || !this.#fresh || b.identity !== current.api || b.port !== current.port || current.blocked || this.ownerReason()) return false;
    const login = this.#drafts.get(context.projectId);
    if (!ghLoginFits(login)) return false;
    const request = { projectId: context.projectId, repository: context.repository, selectedLogin: login,
      expectedDocumentRevision: status.documentRevision, expectedConnectionRevision: status.connectionRevision };
    const a: Attempt = { binding: b, context, epoch: this.#epoch, request, previousId: status.operationId,
      operationId: null, auth: null, http: null, sent: false, retired: false, cancelRequested: false, cancelSent: false, ended: false, refused: false };
    this.#attempt = a; this.#starting = true; this.#polls = 0; this.#failure = null; this.#observedCancel = null;
    try { return this.#connection.connectSelectedGh(request, { port: b.port, submit: (r) => this.#submit(a, r) }); }
    finally { this.#starting = false; if (!a.sent && this.#attempt === a) this.#attempt = null; this.#publish(); }
  }
  #submit(a: Attempt, request: GitHubGhRequest): Promise<unknown> {
    if (!this.#same(a) || !sameConnectionData(a.request, request)) throw { code: 'github_connection_refused_target_changed' };
    const work: Work = { kind: 'connect', promise: null }; this.#works.add(work); this.#publish();
    if (!this.#same(a)) { this.#finish(work); throw { code: 'github_connection_refused_target_changed' }; }
    a.sent = true; this.#fresh = false; this.#fence++;
    let original: Promise<unknown>;
    try {
      original = a.binding.api.connect(request); work.promise = original;
      if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
    } catch (error) { const safe = this.#rejected(a, error); this.#finish(work); throw safe; }
    this.#schedule();
    return original.then((value) => {
      const result = parseGitHubGhResult(value);
      if (!result || !ghResultMatches(result, a.request) || a.operationId !== null && a.operationId !== result.operationId ||
          this.#attempt !== a || this.#issue === 'cleanup-unknown') { this.#fail(); throw ghUnconfirmed(); }
      a.operationId = result.operationId; this.#fence++;
      if (result.outcome === 'http-handoff') {
        const ids = { sessionId: result.connection.session!.id, operationId: result.connection.operation!.id };
        if (a.http && !sameConnectionData(a.http, ids)) { this.#fail(); throw ghUnconfirmed(); }
        a.http = ids;
      } else {
        if (result.outcome === 'no-http' && a.http) { this.#fail(); throw ghUnconfirmed(); }
        a.auth = result.auth; a.http = result.auth.http;
        if (result.outcome === 'unknown') { a.ended = false; this.#fail('cleanup-unknown'); }
        else { a.ended = true; this.#failure = result.auth.reason; if (this.#issue === 'unconfirmed') this.#issue = null; }
      }
      this.#publish(); this.#sendCancel(); return result;
    }, (error) => { throw this.#rejected(a, error); }).finally(() => this.#finish(work));
  }
  #rejected(a: Attempt, error: unknown): object {
    const failure = githubGhFailure(error);
    if (failure.notAdmitted && a.operationId === null && a.http === null && this.#issue !== 'cleanup-unknown') {
      a.refused = true; a.ended = true; this.#failure = failure.reason; this.#fresh = false; this.#issue = null; this.#publish();
      return { code: failure.code };
    }
    this.#fail(); return ghUnconfirmed();
  }
  #matches(status: GitHubGhStatus, a: Attempt): boolean {
    return status.operationId !== null && status.operationId !== a.previousId &&
      (a.operationId === null || status.operationId === a.operationId) && status.projectId === a.request.projectId &&
      status.repository === a.request.repository && status.selectedLogin === a.request.selectedLogin;
  }
  #receive(status: GitHubGhStatus, binding: Binding, context: GitHubConnectionContext | null, epoch: object, fence: number): void {
    // Native cleanup Unknown is absorbing for this original binding. A later
    // ordinary Status/Cancel reply can settle its own Promise, but cannot
    // replace the retained identity/evidence, mark it ended or remove Stop.
    if (this.#issue === 'cleanup-unknown') return;
    const a = this.#attempt;
    if (a?.sent && !a.refused && a.binding === binding) {
      const matches = this.#matches(status, a);
      // Known original Unknown is never hidden by a newer local cancellation.
      if (matches && status.phase === 'cleanup-unknown') { a.operationId = status.operationId; a.auth = status; a.ended = false; this.#fail('cleanup-unknown'); return; }
      if (fence !== this.#fence) return;
      if (!matches) {
        if (a.operationId === null && (status.phase === 'idle' || status.operationId === a.previousId)) return; // May overtake Connect admission.
        this.#fail(); return;
      }
      if (a.http && !sameConnectionData(a.http, status.http)) { this.#fail(); return; }
      a.operationId = status.operationId; a.auth = status; a.http = status.http;
      if (status.phase === 'failed' || status.phase === 'settled') {
        a.ended = true; this.#failure = status.reason === 'none' ? null : status.reason;
        // This releases only auth-custody uncertainty after actual native HTTP
        // handoff + joins. It cannot settle the connection controller's latch.
        if (status.http && this.#issue === 'unconfirmed') this.#issue = null;
      }
      this.#sendCancel();
    } else if (fence !== this.#fence) return;
    const c = this.#current();
    if (this.#binding === binding && this.#fence === fence) {
      // Explicit Status may finish an OLD port's observed original even after
      // the current service/context changed. It never readies the new view.
      this.#status = status;
      if (!a?.sent && this.#issue === 'unconfirmed' && status.phase !== 'cleanup-unknown') this.#issue = null;
      this.#fresh = this.#issue === null && binding.identity === c.api && binding.port === c.port &&
        this.#epoch === epoch && sameConnectionData(context, c.context);
    }
    if (status.phase === 'cleanup-unknown') this.#fail('cleanup-unknown'); else this.#publish();
  }
  canCheckStatus(): boolean { return !this.#disposed && !!this.#binding && this.#reading === null; }
  checkStatus(): boolean {
    const binding = this.#attempt?.sent && !this.#attempt.refused ? this.#attempt.binding : this.#binding;
    if (this.#disposed || !binding || this.#reading) return false;
    const context = this.#current().context, epoch = this.#epoch, fence = this.#fence, work: Work = { kind: 'status', promise: null };
    this.#reading = work; this.#works.add(work); this.#publish();
    if (this.#disposed) { this.#finish(work); return false; }
    try {
      const original = binding.api.status(); work.promise = original;
      if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
      void original.then((value) => {
        const status = parseGitHubGhStatus(value);
        if (!status) { if (fence === this.#fence) this.#fail(); return; }
        this.#receive(status, binding, context, epoch, fence);
      }, () => { if (fence === this.#fence) this.#fail(); }).finally(() => this.#finish(work));
      return true;
    } catch { this.#fail(); this.#finish(work); return false; }
  }
  canCancel(): boolean {
    if (this.#disposed) return false;
    if (this.#attempt?.sent) return !this.#attempt.ended && !this.#attempt.cancelRequested;
    return this.#observedCancel === null && !!this.#binding && !!this.#status?.operationId &&
      (ghActive(this.#status) || this.#status.phase === 'cleanup-unknown');
  }
  requestCancel(): boolean {
    if (!this.canCancel()) return false;
    const a = this.#attempt;
    if (!a?.sent) {
      // An explicit stop can target the original native operation returned by
      // this exact port after a renderer reload. This is not a Connect intent.
      const status = this.#status!, binding = this.#binding!;
      this.#observedCancel = status.operationId; this.#epoch = {}; this.#fresh = false;
      const epoch = this.#epoch, fence = ++this.#fence, context = this.#current().context;
      const work: Work = { kind: 'cancel', promise: null }; this.#works.add(work); this.#publish();
      try {
        const original = binding.api.cancel({ operationId: status.operationId! }); work.promise = original;
        if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
        void original.then((value) => {
          const next = parseGitHubGhStatus(value);
          if (!next || !['operationId', 'projectId', 'repository', 'selectedLogin'].every((key) =>
            next[key as keyof GitHubGhStatus] === status[key as keyof GitHubGhStatus])) { this.#fail(); return; }
          this.#receive(next, binding, context, epoch, fence);
        }, () => this.#fail()).finally(() => this.#finish(work));
      } catch { this.#fail(); this.#finish(work); }
      return true;
    }
    a.retired = true; a.cancelRequested = true; this.#epoch = {}; this.#fence++;
    this.#fresh = false; this.#publish(); this.#sendCancel(); this.#schedule(); return true;
  }
  #sendCancel(): void {
    const a = this.#attempt;
    if (!a?.sent || a.ended || !a.cancelRequested || a.cancelSent || !a.operationId) return;
    a.cancelSent = true; const epoch = this.#epoch, fence = ++this.#fence, context = this.#current().context;
    const work: Work = { kind: 'cancel', promise: null }; this.#works.add(work); this.#publish();
    try {
      const original = a.binding.api.cancel({ operationId: a.operationId }); work.promise = original;
      if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
      void original.then((value) => {
        const status = parseGitHubGhStatus(value);
        if (!status || !this.#matches(status, a)) { this.#fail(); return; }
        this.#receive(status, a.binding, context, epoch, fence);
      }, () => this.#fail()).finally(() => this.#finish(work));
    } catch { this.#fail(); this.#finish(work); }
  }
  #finish(work: Work): void {
    this.#works.delete(work); if (this.#reading === work) this.#reading = null;
    this.#publish(); this.#sendCancel(); this.#schedule();
    if (this.#disposed && !this.ownerReason()) { this.#off?.(); this.#off = null; }
  }
  #schedule(): void {
    // Bounded serial status reads, never retries of Connect/Cancel or a clock-
    // based finality claim. After 70 observations only explicit Status remains.
    if (this.#disposed || this.#timer !== null || this.#reading || this.#issue || !this.#attempt?.sent || this.#attempt.ended || this.#polls >= 70) return;
    this.#timer = this.#clock.schedule(() => {
      this.#timer = null;
      if (this.#disposed || this.#issue || !this.#attempt?.sent || this.#attempt.ended) return;
      this.#polls++; this.checkStatus();
    }, 1000);
  }
  dispose(): void {
    if (this.#disposed) return;
    this.beforeContextIntent(); this.#disposed = true;
    if (this.#timer !== null) { this.#clock.cancel(this.#timer); this.#timer = null; }
    this.#listeners.clear();
    if (!this.ownerReason()) { this.#off?.(); this.#off = null; }
    // The original connect/status/cancel closures still own their Promises.
    // Native cleanup Unknown is not disposal or permission to reconnect.
  }
}
