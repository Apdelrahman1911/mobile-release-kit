// Original selected-gh picker/capture custody only. The existing connection
// controller exclusively owns account facts, HTTP correlation and Connected.
import type { GitHubConnectionController } from './githubConnectionController.ts';
import type { GitHubConnectionContext, GitHubConnectionObservationPort, GitHubConnectionReason } from './githubConnectionTypes.ts';
import { connectionKeys, connectionOpaqueId, connectionRepository, connectionRevision, sameConnectionData } from './githubConnectionProtocol.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { ghActive, ghAdmissionRevision, ghLoginFits, ghResultMatches, ghUnconfirmed, githubGhFailure,
  parseGitHubGhResult, parseGitHubGhStatus } from './githubGhEntryProtocol.ts';
import type { GitHubGhApi, GitHubGhRequest, GitHubGhStatus } from './githubGhEntryProtocol.ts';
import { ghAccountsActive, parseGitHubGhAccountsStatus } from './githubGhAccountsProtocol.ts';
import type { GitHubGhAccountsRequest, GitHubGhAccountsStatus } from './githubGhAccountsProtocol.ts';

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
  accountsOriginal: GitHubGhAccountsStatus | null;
  accounts: GitHubGhAccountsStatus['accounts']; accountsFresh: boolean;
  selectedAccount: string | null; manual: boolean;
}
interface Binding { identity: GitHubGhApi; api: GitHubGhApi; port: GitHubConnectionObservationPort }
interface Attempt {
  binding: Binding; context: GitHubConnectionContext; epoch: object; request: GitHubGhRequest;
  previousId: string | null; operationId: string | null; auth: GitHubGhStatus | null;
  http: { sessionId: string; operationId: string } | null; sent: boolean; retired: boolean;
  cancelRequested: boolean; cancelSent: boolean; ended: boolean; refused: boolean;
}
interface AccountsAttempt {
  binding: Binding; context: GitHubConnectionContext; epoch: object; request: GitHubGhAccountsRequest | null;
  previousId: string | null; operationId: string | null; auth: GitHubGhAccountsStatus | null;
  sent: boolean; retired: boolean; cancelRequested: boolean; cancelSent: boolean; ended: boolean; refused: boolean;
}
interface Work { kind: 'connect' | 'accounts' | 'status' | 'cancel'; promise: Promise<unknown> | null }
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
  #accountsAttempt: AccountsAttempt | null = null; #accountsStatus: GitHubGhAccountsStatus | null = null;
  #latest: 'connection' | 'accounts' = 'connection'; #list: GitHubGhAccountsStatus['accounts'] = null;
  #listFresh = false; #selectedAccount: string | null = null; #manual = new Set<string>();
  #issue: GitHubGhView['issue'] = null; #failure: GitHubConnectionReason | null = null;
  #drafts = new Map<string, string>(); #works = new Set<Work>(); #reading: Work | null = null;
  #fence = 0; #starting = false; #disposed = false; #notifying = false;
  #timer: unknown = null; #polls = 0; #off: (() => void) | null; #observedCancel: string | null = null;
  #listeners = new Set<() => void>();
  #state: GitHubGhView = freeze({ mode: 'unavailable', context: null, login: '', status: null, original: null,
    originalProjectId: null, pendingCount: 0, reading: false, cancelRequested: false, issue: null, failure: null,
    accountsOriginal: null, accounts: null, accountsFresh: false, selectedAccount: null, manual: false });
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
    const original = this.#attempt?.sent ? this.#attempt.auth : this.#latest === 'connection' ? this.#status : null;
    const accountsOriginal = this.#accountsAttempt?.sent ? this.#accountsAttempt.auth : this.#latest === 'accounts' ? this.#accountsStatus : null;
    this.#state = freeze({ mode: this.#binding ? 'native' : 'unavailable', context: this.#context,
      login: this.#context ? this.#drafts.get(this.#context.projectId) ?? '' : '', status: this.#fresh && this.#latest === 'connection' ? this.#status : null,
      original, originalProjectId: this.#attempt?.request.projectId ?? this.#accountsAttempt?.context.projectId ?? original?.projectId ?? accountsOriginal?.projectId ?? null,
      pendingCount: this.#works.size, reading: this.#reading !== null, cancelRequested: !!this.#attempt?.cancelRequested || !!this.#accountsAttempt?.cancelRequested || this.#observedCancel !== null,
      issue: this.#issue, failure: this.#failure, accountsOriginal, accounts: this.#list, accountsFresh: this.#listFresh,
      selectedAccount: this.#selectedAccount, manual: !!this.#context && this.#manual.has(this.#context.projectId) });
    if (this.#notifying) return;
    this.#notifying = true;
    try { for (const listener of [...this.#listeners]) { try { listener(); } catch { /* Views cannot release originals. */ } } }
    finally { this.#notifying = false; }
  }
  #fail(issue: GitHubGhView['issue'] = 'unconfirmed'): void {
    if (this.#issue !== 'cleanup-unknown') this.#issue = issue;
    this.#fresh = false; this.#listFresh = false; this.#publish();
  }
  /** Root also includes this in other-action/reconnect/passive-read gates. */
  ownerReason(): string | null {
    if (this.#issue) return 'The original GitHub CLI request is unconfirmed. Keep the app open; check or stop that request instead of connecting again.';
    const known = this.#attempt?.sent ? this.#attempt.auth : this.#status;
    const accounts = this.#accountsAttempt?.sent ? this.#accountsAttempt.auth : this.#accountsStatus;
    if (this.#works.size || this.#attempt?.sent && !this.#attempt.ended || this.#accountsAttempt && !this.#accountsAttempt.ended ||
        this.#latest === 'connection' && ghActive(known) || this.#latest === 'accounts' && ghAccountsActive(accounts))
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
      const { status, connect, cancel, accounts } = api;
      if (![status, connect, cancel, accounts].every((f) => typeof f === 'function')) return false;
      this.#binding = { identity: api, port, api: Object.freeze({ mode: 'native' as const,
        status: () => status.call(api), connect: (r: GitHubGhRequest) => connect.call(api, r), cancel: (r: { operationId: string }) => cancel.call(api, r),
        accounts: (r: GitHubGhAccountsRequest) => accounts.call(api, r) }) };
    } else this.#binding = null;
    this.#attempt = null; this.#status = null; this.#fresh = false; this.#failure = null; this.#observedCancel = null;
    this.#accountsAttempt = null; this.#accountsStatus = null; this.#latest = 'connection'; this.#listFresh = false; this.#selectedAccount = null;
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
    this.#epoch = {}; this.#fence++; this.#fresh = false; this.#listFresh = false; this.#selectedAccount = null;
    const a = this.#attempt;
    if (a && !a.ended) { a.retired = true; if (a.sent) a.cancelRequested = true; }
    const read = this.#accountsAttempt;
    if (read && !read.ended) { read.retired = true; if (read.sent) read.cancelRequested = true; else read.ended = true; }
    this.#publish(); this.#sendCancel();
  }
  setLogin(value: string): boolean {
    if (this.#disposed || typeof value !== 'string' || value.length > 39 || this.#starting || this.ownerReason()) return false;
    const c = this.#current().context;
    if (!c) return false;
    // Local nonsecret draft only; typing neither discovers nor selects an account.
    this.#epoch = {}; this.#fence++; this.#context = c; this.#drafts.set(c.projectId, value); this.#failure = null;
    this.#manual.add(c.projectId); this.#selectedAccount = null; this.#listFresh = false;
    // An idle profile/revision observation is not login verification or consent.
    // Keep that comparison; native still rechecks it on the explicit Connect.
    this.#publish(); return true;
  }
  #comparison(): GitHubGhStatus | GitHubGhAccountsStatus | null {
    return this.#fresh ? this.#latest === 'accounts' ? this.#accountsStatus : this.#status : null;
  }
  useManual(): boolean {
    const current = this.#current().context;
    return !!current && this.setLogin(this.#drafts.get(current.projectId) ?? '');
  }
  chooseAccount(login: string): boolean {
    const current = this.#current(), b = this.#binding;
    if (this.#disposed || !b || b.identity !== current.api || b.port !== current.port || !current.context ||
        !sameConnectionData(current.context, this.#context) || current.blocked || this.ownerReason() || this.#starting ||
        !this.#listFresh || !this.#list?.current || !this.#list.logins.includes(login)) return false;
    this.#fence++; this.#selectedAccount = login; this.#manual.delete(current.context.projectId); this.#failure = null;
    this.#publish(); return true;
  }
  findAccountsReason(): string | null {
    const c = this.#current(), b = this.#binding;
    if (this.#disposed || !b || b.identity !== c.api || b.port !== c.port) return 'Finding local accounts needs the connected native Desktop app.';
    if (!c.context) return 'Select your project and enter its GitHub repository first.';
    if (this.#starting || this.ownerReason()) return this.ownerReason() ?? 'A connection is being submitted.';
    if (c.blocked) return c.blocked;
    return this.#connection.canConnect() ? null : 'Check the connection status below, or finish the original connection first.';
  }
  /** Explicit read intent only: the initial comparison read and the local
   * account read remain serial and never start a connection automatically. */
  findAccounts(): boolean {
    if (this.findAccountsReason()) return false;
    const c = this.#current(), b = this.#binding;
    if (!b || !c.context || c.blocked || b.identity !== c.api || b.port !== c.port || this.ownerReason()) return false;
    this.#attempt = null; this.#selectedAccount = null; this.#listFresh = false; this.#failure = null; this.#observedCancel = null;
    this.#manual.delete(c.context.projectId); this.#polls = 0;
    const a: AccountsAttempt = { binding: b, context: c.context, epoch: this.#epoch, request: null,
      previousId: null, operationId: null, auth: null, sent: false, retired: false, cancelRequested: false,
      cancelSent: false, ended: false, refused: false };
    this.#accountsAttempt = a; this.#publish();
    if (!this.#sameAccounts(a)) { a.ended = true; this.#publish(); return false; }
    // A new explicit discovery always obtains current native comparisons.
    if (!this.checkStatus()) { a.ended = true; this.#publish(); return false; }
    return true;
  }
  #sameAccounts(a: AccountsAttempt): boolean {
    const c = this.#current();
    return !this.#disposed && this.#accountsAttempt === a && !a.retired && this.#epoch === a.epoch && this.#binding === a.binding &&
      a.binding.identity === c.api && a.binding.port === c.port && sameConnectionData(a.context, c.context) && c.blocked === null;
  }
  #continueAccounts(): void {
    const a = this.#accountsAttempt;
    if (!a || a.sent || a.ended || this.#works.size) return;
    const status = this.#comparison();
    if (!this.#sameAccounts(a) || this.#issue || !status || ghActive(this.#latest === 'connection' ? this.#status : null) ||
        ghAccountsActive(this.#latest === 'accounts' ? this.#accountsStatus : null)) { a.ended = true; this.#publish(); return; }
    if (!status.available || !ghAdmissionRevision(status.documentRevision) || !ghAdmissionRevision(status.connectionRevision) ||
        status.connectionRevision !== this.#connection.getSnapshot().status?.revision) {
      a.ended = true; this.#failure = !status.available ? 'runtime-unavailable' : 'target-changed'; this.#publish(); return;
    }
    a.request = { projectId: a.context.projectId, repository: a.context.repository,
      expectedDocumentRevision: status.documentRevision, expectedConnectionRevision: status.connectionRevision };
    a.previousId = status.operationId;
    const work: Work = { kind: 'accounts', promise: null }; this.#works.add(work); this.#publish();
    if (!this.#sameAccounts(a) || this.#issue) { a.ended = true; this.#finish(work); return; }
    a.sent = true; this.#fresh = false; this.#fence++;
    try {
      const original = a.binding.api.accounts(a.request); work.promise = original;
      if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
      void original.then((value) => {
        const status = parseGitHubGhAccountsStatus(value);
        if (!status || !this.#accountsMatch(status, a) || this.#accountsAttempt !== a ||
            !['settled', 'failed', 'cleanup-unknown'].includes(status.phase) || status.phase === 'settled' && !status.accounts) {
          this.#fail(); return;
        }
        // This exact original terminal overtakes polls started before its
        // return. Their Promises stay owned, but older Reading/idle DATA must
        // not contradict this joined result. Matching Unknown still wins.
        this.#receiveAccounts(status, a.binding, a.context, a.epoch, ++this.#fence, true);
      }, (error) => this.#accountsRejected(a, error)).finally(() => this.#finish(work));
      this.#schedule();
    } catch (error) { this.#accountsRejected(a, error); this.#finish(work); }
  }
  #accountsRejected(a: AccountsAttempt, error: unknown): void {
    const failure = githubGhFailure(error);
    if (failure.notAdmitted && a.operationId === null && this.#issue !== 'cleanup-unknown') {
      a.refused = true; a.ended = true; this.#failure = failure.reason; this.#fresh = false; this.#listFresh = false; this.#issue = null; this.#publish();
    } else this.#fail();
  }
  startReason(): string | null {
    const c = this.#current(), b = this.#binding, status = this.#comparison();
    if (this.#disposed || !b || b.identity !== c.api || b.port !== c.port) return 'GitHub CLI connection needs the connected native Desktop app.';
    if (!c.context) return 'Select your project and enter its GitHub repository first.';
    if (this.#starting || this.ownerReason()) return this.ownerReason() ?? 'A connection is being submitted.';
    if (c.blocked) return c.blocked;
    if (this.#manual.has(c.context.projectId)) {
      if (!ghLoginFits(this.#drafts.get(c.context.projectId))) return 'Enter the username already signed in with GitHub CLI.';
    } else if (!this.#listFresh || !this.#list?.current || !this.#selectedAccount || !this.#list.logins.includes(this.#selectedAccount))
      return 'Find local GitHub accounts, then choose the one to connect.';
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
    const b = this.#binding, current = this.#current(), context = current.context, status = this.#comparison();
    if (!b || !context || !status || !this.#fresh || b.identity !== current.api || b.port !== current.port || current.blocked || this.ownerReason()) return false;
    const manual = this.#manual.has(context.projectId), login = manual ? this.#drafts.get(context.projectId) : this.#selectedAccount;
    if (!ghLoginFits(login)) return false;
    const request = { projectId: context.projectId, repository: context.repository, selectedLogin: login,
      expectedDocumentRevision: status.documentRevision, expectedConnectionRevision: status.connectionRevision,
      ...(!manual && this.#listFresh && this.#list ? { accountsObservationId: this.#list.observationId } : {}) };
    if (!manual && !request.accountsObservationId) return false;
    const a: Attempt = { binding: b, context, epoch: this.#epoch, request, previousId: status.operationId,
      operationId: null, auth: null, http: null, sent: false, retired: false, cancelRequested: false, cancelSent: false, ended: false, refused: false };
    this.#attempt = a; this.#accountsAttempt = null; this.#starting = true; this.#polls = 0; this.#failure = null; this.#observedCancel = null;
    try { return this.#connection.connectSelectedGh(request, { port: b.port, submit: (r) => this.#submit(a, r) }); }
    finally { this.#starting = false; if (!a.sent && this.#attempt === a) this.#attempt = null; this.#publish(); }
  }
  #submit(a: Attempt, request: GitHubGhRequest): Promise<unknown> {
    if (!this.#same(a) || !sameConnectionData(a.request, request)) throw { code: 'github_connection_refused_target_changed' };
    const work: Work = { kind: 'connect', promise: null }; this.#works.add(work); this.#publish();
    if (!this.#same(a)) { this.#finish(work); throw { code: 'github_connection_refused_target_changed' }; }
    a.sent = true; this.#fresh = false; this.#listFresh = false; this.#latest = 'connection'; this.#fence++;
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
    const read = this.#accountsAttempt;
    if (read?.sent && !read.refused && read.binding === binding) {
      if (fence !== this.#fence) return;
      if (read.operationId === null && (status.phase === 'idle' || status.operationId === read.previousId)) return;
      this.#fail(); return; // A connection-shaped observation cannot finish a name read.
    }
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
      this.#latest = 'connection'; this.#listFresh = false;
      if (!a?.sent && this.#issue === 'unconfirmed' && status.phase !== 'cleanup-unknown') this.#issue = null;
      this.#fresh = this.#issue === null && binding.identity === c.api && binding.port === c.port &&
        this.#epoch === epoch && sameConnectionData(context, c.context);
    }
    if (status.phase === 'cleanup-unknown') this.#fail('cleanup-unknown'); else this.#publish();
  }
  #accountsMatch(status: GitHubGhAccountsStatus, a: AccountsAttempt): boolean {
    return status.operationId !== a.previousId && (a.operationId === null || status.operationId === a.operationId) &&
      status.projectId === a.context.projectId && status.repository === a.context.repository;
  }
  #receiveAccounts(status: GitHubGhAccountsStatus, binding: Binding, context: GitHubConnectionContext | null, epoch: object, fence: number, returned = false): void {
    if (this.#issue === 'cleanup-unknown') return;
    const connect = this.#attempt;
    if (connect?.sent && !connect.refused && connect.binding === binding) {
      if (connect.operationId === null && status.operationId === connect.previousId) return; // Prior list may overtake Connect.
      this.#fail(); return;
    }
    const a = this.#accountsAttempt;
    if (a?.sent && !a.refused && a.binding === binding) {
      const matches = this.#accountsMatch(status, a);
      if (matches && status.phase === 'cleanup-unknown') {
        a.operationId = status.operationId; a.auth = status; a.ended = false; this.#fail('cleanup-unknown'); return;
      }
      if (fence !== this.#fence) return;
      if (!matches) { if (!returned && a.operationId === null && status.operationId === a.previousId) return; this.#fail(); return; }
      // A positively joined list/failure is immutable. Status may change its
      // currentness/revision metadata, never the original complete name set.
      if (a.auth && ['settled', 'failed'].includes(a.auth.phase) &&
          (a.auth.phase !== status.phase || a.auth.reason !== status.reason ||
            !sameConnectionData(a.auth.accounts && { id: a.auth.accounts.observationId, names: a.auth.accounts.logins },
              status.accounts && { id: status.accounts.observationId, names: status.accounts.logins }))) { this.#fail(); return; }
      a.operationId = status.operationId; a.auth = status;
      if (status.phase === 'settled' || status.phase === 'failed') {
        a.ended = true; this.#failure = status.reason === 'none' ? null : status.reason;
        if (returned && this.#issue === 'unconfirmed') this.#issue = null;
      }
      this.#sendCancel();
    } else if (fence !== this.#fence) return;
    const c = this.#current();
    if (this.#binding === binding && this.#fence === fence) {
      this.#accountsStatus = status; this.#latest = 'accounts';
      if (!a?.sent && this.#issue === 'unconfirmed' && status.phase !== 'cleanup-unknown') this.#issue = null;
      this.#fresh = this.#issue === null && binding.identity === c.api && binding.port === c.port && this.#epoch === epoch && sameConnectionData(context, c.context);
      this.#listFresh = this.#fresh && !!a?.sent && this.#sameAccounts(a) && status.phase === 'settled' && status.accounts?.current === true &&
        status.projectId === c.context?.projectId && status.repository === c.context?.repository;
      if (status.accounts) this.#list = status.accounts;
      if (!this.#listFresh) this.#selectedAccount = null;
    }
    if (status.phase === 'cleanup-unknown') this.#fail('cleanup-unknown'); else this.#publish();
  }
  #receivePublic(value: unknown, binding: Binding, context: GitHubConnectionContext | null, epoch: object, fence: number): boolean {
    const status = parseGitHubGhStatus(value);
    if (status) { this.#receive(status, binding, context, epoch, fence); return true; }
    const accounts = parseGitHubGhAccountsStatus(value);
    if (accounts) { this.#receiveAccounts(accounts, binding, context, epoch, fence); return true; }
    return false;
  }
  canCheckStatus(): boolean { return !this.#disposed && !!this.#binding && this.#reading === null; }
  checkStatus(): boolean {
    const binding = this.#attempt?.sent && !this.#attempt.refused ? this.#attempt.binding :
      this.#accountsAttempt?.sent && !this.#accountsAttempt.refused ? this.#accountsAttempt.binding : this.#binding;
    if (this.#disposed || !binding || this.#reading) return false;
    const context = this.#current().context, epoch = this.#epoch, fence = this.#fence, work: Work = { kind: 'status', promise: null };
    this.#reading = work; this.#works.add(work); this.#publish();
    if (this.#disposed) { this.#finish(work); return false; }
    try {
      const original = binding.api.status(); work.promise = original;
      if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
      void original.then((value) => {
        if (!this.#receivePublic(value, binding, context, epoch, fence) && fence === this.#fence) this.#fail();
      }, () => { if (fence === this.#fence) this.#fail(); }).finally(() => this.#finish(work));
      return true;
    } catch { this.#fail(); this.#finish(work); return false; }
  }
  canCancel(): boolean {
    if (this.#disposed) return false;
    if (this.#attempt?.sent) return !this.#attempt.ended && !this.#attempt.cancelRequested;
    const a = this.#accountsAttempt;
    if (a && !a.ended) return !a.cancelRequested;
    const accounts = this.#latest === 'accounts' ? this.#accountsStatus : null, status = this.#latest === 'connection' ? this.#status : null;
    return this.#observedCancel === null && !!this.#binding && (!!status?.operationId &&
      (ghActive(status) || status.phase === 'cleanup-unknown') || !!accounts && (ghAccountsActive(accounts) || accounts.phase === 'cleanup-unknown'));
  }
  requestCancel(): boolean {
    if (!this.canCancel()) return false;
    const read = this.#accountsAttempt;
    if (read && !read.ended) {
      read.retired = true; read.cancelRequested = true; if (!read.sent) read.ended = true;
      this.#epoch = {}; this.#fence++; this.#fresh = false; this.#listFresh = false;
      this.#publish(); this.#sendCancel(); this.#schedule(); return true;
    }
    const a = this.#attempt;
    if (!a?.sent) {
      // An explicit stop can target the original native operation returned by
      // this exact port after a renderer reload. This is not a Connect intent.
      const status = this.#latest === 'accounts' ? this.#accountsStatus! : this.#status!, binding = this.#binding!;
      this.#observedCancel = status.operationId; this.#epoch = {}; this.#fresh = false; this.#listFresh = false;
      const epoch = this.#epoch, fence = ++this.#fence, context = this.#current().context;
      const work: Work = { kind: 'cancel', promise: null }; this.#works.add(work); this.#publish();
      try {
        const original = binding.api.cancel({ operationId: status.operationId! }); work.promise = original;
        if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
        void original.then((value) => {
          const next = 'kind' in status ? parseGitHubGhAccountsStatus(value) : parseGitHubGhStatus(value);
          if (!next || next.operationId !== status.operationId || next.projectId !== status.projectId || next.repository !== status.repository ||
            ('selectedLogin' in status && (!('selectedLogin' in next) || next.selectedLogin !== status.selectedLogin))) { this.#fail(); return; }
          if ('kind' in next) this.#receiveAccounts(next, binding, context, epoch, fence);
          else this.#receive(next, binding, context, epoch, fence);
        }, () => this.#fail()).finally(() => this.#finish(work));
      } catch { this.#fail(); this.#finish(work); }
      return true;
    }
    a.retired = true; a.cancelRequested = true; this.#epoch = {}; this.#fence++;
    this.#fresh = false; this.#listFresh = false; this.#publish(); this.#sendCancel(); this.#schedule(); return true;
  }
  #sendCancel(): void {
    const read = this.#accountsAttempt;
    if (read?.sent && !read.ended && read.cancelRequested && !read.cancelSent && read.operationId) {
      read.cancelSent = true; const epoch = this.#epoch, fence = ++this.#fence, context = this.#current().context;
      const work: Work = { kind: 'cancel', promise: null }; this.#works.add(work); this.#publish();
      try {
        const original = read.binding.api.cancel({ operationId: read.operationId }); work.promise = original;
        if (!original || typeof original.then !== 'function') throw ghUnconfirmed();
        void original.then((value) => {
          const status = parseGitHubGhAccountsStatus(value);
          if (!status || !this.#accountsMatch(status, read)) { this.#fail(); return; }
          this.#receiveAccounts(status, read.binding, context, epoch, fence);
        }, () => this.#fail()).finally(() => this.#finish(work));
      } catch { this.#fail(); this.#finish(work); }
      return;
    }
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
    this.#publish(); this.#sendCancel(); this.#continueAccounts(); this.#schedule();
    if (this.#disposed && !this.ownerReason()) { this.#off?.(); this.#off = null; }
  }
  #schedule(): void {
    // Bounded serial status reads, never retries of Connect/Cancel or a clock-
    // based finality claim. After 70 observations only explicit Status remains.
    const pending = () => !!this.#attempt?.sent && !this.#attempt.ended || !!this.#accountsAttempt?.sent && !this.#accountsAttempt.ended;
    if (this.#disposed || this.#timer !== null || this.#reading || this.#issue || !pending() || this.#polls >= 70) return;
    this.#timer = this.#clock.schedule(() => {
      this.#timer = null;
      if (this.#disposed || this.#issue || !pending()) return;
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
