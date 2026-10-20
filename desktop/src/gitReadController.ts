// Renderer coordination for three original native read-only commands. The
// native Supervisor remains the only process/resource owner and finality source.
import { gitReadPathOrder, gitReadRequest, parseGitReadStatus, parseGitReadStartResult, sameGitReadAction, sameGitReadContext, sameGitReadOperation } from './gitReadProtocol.ts';
import type { GitReadAction, GitReadApi, GitReadHistory, GitReadObservation, GitReadOperation, GitReadStatus, GitReadStartResult } from './gitReadProtocol.ts';
import type { GitIssue, GitReason } from './gitRepositoryProtocol.ts';
import type { GitBranches } from './gitBranchesProtocol.ts';
import type { GitRepositoryPort } from './gitRepositoryController.ts';

export interface GitReadBinding { readonly api: GitReadApi | null; readonly session: object | null;
  readonly projectId: string | null; readonly epoch: number; readonly blocked: string | null }
export interface GitReadView { readonly status: GitReadStatus | null; readonly busy: boolean; readonly checking: boolean;
  readonly original: GitReadOperation | null; readonly issue: GitIssue | null; readonly uncertain: boolean;
  readonly observation: GitReadObservation | null; readonly observationProject: string | null;
  readonly history: GitReadHistory | null; readonly historyProject: string | null; readonly historyCurrent: boolean;
  readonly branches: GitBranches | null; readonly branchesProject: string | null; readonly branchesCurrent: boolean; readonly stale: boolean }
interface Attempt { readonly binding: GitReadBinding; readonly api: GitReadApi; readonly action: GitReadAction;
  readonly baseline: string | null; readonly documentRevision: number; readonly observedOnly: boolean;
  resolve: ((value: unknown) => void) | null; reject: ((error: unknown) => void) | null;
  refusal: Extract<GitReadStartResult, { admission: 'refused' }> | null;
  operation: GitReadOperation | null; entered: boolean; startReturned: boolean; hardUnknown: boolean; uncertain: boolean; cancelSent: boolean }
interface Work { readonly kind: 'start' | 'status' | 'cancel'; readonly attempt: Attempt | null; readonly binding: GitReadBinding;
  original: Promise<unknown> | null }
class Declined { readonly reason: GitIssue; constructor(reason: GitIssue) { this.reason = reason; } }
const same = (a: GitReadBinding, b: GitReadBinding) => a.api === b.api && a.session === b.session && a.projectId === b.projectId && a.epoch === b.epoch;
const rank = { starting: 0, running: 1, stopping: 2, settled: 3, 'cleanup-unknown': 4 } as const;
const failure = (reason: GitReason, finality: 'settled' | 'unknown') => Object.freeze({ reason, nativeFinality: finality });

export class GitReadController {
  private readonly source: { current(): GitReadBinding };
  private readonly listeners = new Set<() => void>();
  private readonly works = new Set<Work>();
  private attempt: Attempt | null = null;
  private baseline: GitReadBinding | null = null;
  private state: GitReadView = Object.freeze({ status: null, busy: false, checking: false, original: null, issue: null, uncertain: false,
    observation: null, observationProject: null, history: null, historyProject: null, historyCurrent: false,
    branches: null, branchesProject: null, branchesCurrent: false, stale: true });
  constructor(source: { current(): GitReadBinding }) { this.source = source; }
  getSnapshot = (): GitReadView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private current(): GitReadBinding {
    try { return Object.freeze({ ...this.source.current() }); } catch { return { api: null, session: null, projectId: null, epoch: -1, blocked: 'unavailable' }; }
  }
  private publish(change: Partial<GitReadView> = {}): void {
    this.state = Object.freeze({ ...this.state, ...change, busy: this.works.size > 0,
      checking: [...this.works].some((w) => w.kind === 'status') });
    for (const listener of [...this.listeners]) { try { listener(); } catch { /* Rendering never disowns an original Promise. */ } }
  }
  ownerReason(): string | null {
    return this.attempt?.hardUnknown ? 'Local Git cleanup is unconfirmed. Keep the original task and files.' :
      this.attempt ? 'Finish checking or stopping the original local Git read first.' : this.works.size ? 'Wait for the original Git status request.' : null;
  }
  syncContext(): void {
    const context = this.current();
    if (!this.baseline || !same(this.baseline, context)) {
      this.baseline = context;
      this.publish({ status: this.attempt ? this.state.status : null, stale: true, historyCurrent: false, branchesCurrent: false });
    }
  }
  beforeContextIntent(): void { this.baseline = null; this.publish({ stale: true, historyCurrent: false, branchesCurrent: false, status: this.attempt ? this.state.status : null }); }
  readReason(projectId: string): GitIssue | null {
    const current = this.current();
    if (!current.api || !current.session) return 'unavailable';
    if (current.projectId !== projectId) return 'inactive';
    if (this.ownerReason() || current.blocked) return 'busy';
    if (!this.baseline || !same(this.baseline, current) || !this.state.status?.available ||
        this.state.status.documentRevision === 0 || this.state.status.documentRevision === 0xffffffff) return 'unavailable';
    return null;
  }
  port(projectId: string): GitRepositoryPort {
    // Permanently project-bound; no writes, no retargeting of existing drafts.
    const original = this.current();
    return Object.freeze({ projectId, readReason: () => this.portReason(projectId, original),
      declined: (error: unknown) => error instanceof Declined ? error.reason : null,
      observe: () => this.start(projectId, { kind: 'observe', expectedRevision: null, paths: [], staged: false }, original),
      diff: (input: { paths: readonly string[]; expectedRevision: string; staged: boolean }) => this.start(projectId,
        { kind: 'diff', expectedRevision: input.expectedRevision, paths: [...input.paths].sort(gitReadPathOrder), staged: input.staged }, original) });
  }
  private portReason(projectId: string, original: GitReadBinding): GitIssue | null {
    const current = this.current();
    return original.api !== current.api || original.session !== current.session ? 'inactive' : this.readReason(projectId);
  }
  async readHistory(projectId: string, expectedRevision: string): Promise<boolean> {
    try { await this.start(projectId, { kind: 'history', expectedRevision, paths: [], staged: false }); return true; }
    catch { return false; } // Original fixed issue remains visible, never raw text.
  }
  async readBranches(projectId: string, expectedRevision: string): Promise<boolean> {
    try { await this.start(projectId, { kind: 'branches', expectedRevision, paths: [], staged: false }); return true; }
    catch { return false; } // Original fixed issue remains visible; never a retry.
  }
  private start(projectId: string, action: GitReadAction, original?: GitReadBinding): Promise<unknown> {
    const reason = this.readReason(projectId); if (reason) return Promise.reject(new Declined(reason));
    const binding = this.current(), status = this.state.status!;
    if (original && (original.api !== binding.api || original.session !== binding.session)) return Promise.reject(new Declined('inactive'));
    const raw = gitReadRequest('start', { projectId, expectedDocumentRevision: status.documentRevision, action });
    if (!raw || !binding.api) return Promise.reject(new Declined('invalid-input'));
    return new Promise((resolve, reject) => {
      const attempt: Attempt = { binding, api: binding.api!, action: Object.freeze({ ...action, paths: Object.freeze([...action.paths]) }),
        baseline: status.operation?.operationId ?? null, documentRevision: status.documentRevision, observedOnly: false,
        refusal: null, operation: null, entered: false, startReturned: false, hardUnknown: false, uncertain: false, cancelSent: false, resolve, reject };
      this.attempt = attempt;
      // Latch reciprocal UI admission before any rendering callback/invoke.
      this.publish({ original: null, issue: null, uncertain: false, ...(action.kind === 'observe' ? { stale: true, branchesCurrent: false } : action.kind === 'branches' ? { branchesCurrent: false } : {}) });
      const now = this.current();
      if (!same(binding, now) || now.blocked) {
        this.attempt = null; reject(new Declined('inactive')); this.publish(); return;
      }
      void this.send('start', binding.api!, raw, attempt, binding);
    });
  }
  checkReason(): string | null {
    if ([...this.works].some((w) => w.kind === 'status')) return 'Wait for the original status check to finish.';
    if (this.attempt) return null; // Always the original port, including foreign-project work.
    const current = this.current();
    return !current.api || !current.session ? 'Connect the native app service to check local Git access.' : current.blocked;
  }
  canCheck(): boolean { return this.checkReason() === null; }
  async checkStatus(): Promise<boolean> {
    if (!this.canCheck()) return false;
    const attempt = this.attempt, binding = attempt?.binding ?? this.current(), api = attempt?.api ?? binding.api;
    if (!api || !attempt && (!binding.session || binding.blocked)) return false;
    await this.send('status', api, gitReadRequest('status', {})!, attempt, binding); return true;
  }
  canCancel(): boolean { return !!this.attempt?.operation && !this.attempt.cancelSent &&
    (this.attempt.operation.phase !== 'settled' || this.attempt.hardUnknown); }
  async cancel(): Promise<boolean> {
    const attempt = this.attempt;
    if (!attempt || !this.canCancel()) return false;
    attempt.cancelSent = true; // Independent of pending status/start, one exact STOP only.
    this.publish();
    await this.send('cancel', attempt.api, gitReadRequest('cancel', { operationId: attempt.operation!.operationId })!, attempt, attempt.binding);
    return true;
  }
  private markUncertain(attempt: Attempt, hard: boolean): void {
    if (this.attempt !== attempt) return;
    attempt.uncertain = true; attempt.hardUnknown ||= hard;
    this.publish({ issue: hard ? 'unknown' : 'acknowledgement-missing', uncertain: true, stale: true });
  }
  private async send(kind: Work['kind'], api: GitReadApi, raw: Uint8Array, attempt: Attempt | null, binding: GitReadBinding): Promise<void> {
    const work: Work = { kind, attempt, binding, original: null }; this.works.add(work); this.publish();
    try {
      if (kind === 'start') {
        // Listener reentrancy cannot nominate another context before dispatch.
        const now = this.current();
        if (!attempt || this.attempt !== attempt || !same(binding, now) || now.blocked) {
          if (attempt && this.attempt === attempt) { this.attempt = null; attempt.reject?.(new Declined('inactive')); }
          return;
        }
        attempt.entered = true;
      }
      work.original = api[kind](raw);
      const value = await work.original;
      if (kind === 'start') {
        const reply = parseGitReadStartResult(value);
        if (!attempt || this.attempt !== attempt) return;
        if (!reply || reply.request.projectId !== attempt.binding.projectId ||
            reply.request.expectedDocumentRevision !== attempt.documentRevision || !sameGitReadAction(reply.request.action, attempt.action)) {
          this.markUncertain(attempt, false); return;
        }
        if (reply.admission === 'refused') {
          if (attempt.hardUnknown) return;
          // A new operation already seen is incompatible with no admission.
          // Do not overwrite its evidence, hide Stop or infer nested finality.
          if (attempt.operation) { this.markUncertain(attempt, true); return; }
          attempt.refusal = reply;
          this.publish({ issue: reply.reason, stale: true }); return;
        }
        this.receive(reply.status, attempt, binding, kind); return;
      }
      const parsed = parseGitReadStatus(value);
      // Parsing descriptors can reenter Root. Idle replies need the final
      // binding comparison too; original replies always belong to their owner.
      if (!attempt && !same(binding, this.current())) return;
      if (!parsed) {
        if (attempt) this.markUncertain(attempt, false);
        else this.publish({ status: null, issue: 'response-invalid', stale: true });
        return;
      }
      this.receive(parsed, attempt, binding, kind);
    } catch {
      if (attempt) this.markUncertain(attempt, false);
      else if (same(binding, this.current())) this.publish({ status: null, issue: 'unavailable', stale: true });
    } finally {
      if (kind === 'start' && attempt) attempt.startReturned = true;
      this.works.delete(work); this.publish(); this.finish();
    }
  }
  private receive(status: GitReadStatus, captured: Attempt | null, binding: GitReadBinding, kind: Work['kind']): void {
    let attempt = captured;
    const operation = status.operation;
    if (attempt && this.attempt !== attempt) return;
    if (!attempt) {
      if (this.attempt || !same(binding, this.current())) return;
      this.baseline = binding;
      if (operation && operation.phase !== 'settled') {
        attempt = { binding, api: binding.api!, action: operation.action, baseline: null,
          documentRevision: status.documentRevision, observedOnly: true, refusal: null, operation, entered: true, startReturned: true,
          hardUnknown: operation.phase === 'cleanup-unknown', uncertain: operation.phase === 'cleanup-unknown', cancelSent: false, resolve: null, reject: null };
        this.attempt = attempt;
      } else { this.publish({ status, original: operation, issue: null, uncertain: false }); return; }
    }
    // Once original cleanup is UNKNOWN, later ordinary replies cannot replace
    // evidence, hide an unsent Stop, retire this owner or authorize another read.
    if (attempt.hardUnknown) {
      this.publish({ status: this.state.status ?? status, original: attempt.operation, issue: 'unknown', uncertain: true }); return;
    }
    if (!operation || !attempt.operation && operation.operationId === attempt.baseline) {
      if (kind !== 'status') this.markUncertain(attempt, false);
      return;
    }
    if (attempt.refusal) { this.markUncertain(attempt, true); return; }
    const context = operation.context;
    if (attempt.operation ? operation.operationId !== attempt.operation.operationId ||
        !sameGitReadContext(context, attempt.operation.context) || !sameGitReadAction(operation.action, attempt.action) :
        context.projectId !== attempt.binding.projectId || context.revision !== `document-${attempt.documentRevision}` || !sameGitReadAction(operation.action, attempt.action)) {
      this.markUncertain(attempt, true); return;
    }
    if (attempt.operation?.phase === 'settled') {
      if (operation.phase === 'cleanup-unknown' || operation.phase === 'settled' && !sameGitReadOperation(operation, attempt.operation)) {
        this.markUncertain(attempt, true);
      } else if (operation.phase === 'settled' && kind !== 'start') {
        // A fresh exact original status can resolve a lost transport reply,
        // never actual unknown or contradictory terminal evidence.
        attempt.uncertain = false;
        this.publish({ status, issue: operation.reason, uncertain: false });
      }
      return; // Historical start/status cannot rewind original terminal evidence.
    }
    if (attempt.operation && rank[operation.phase] < rank[attempt.operation.phase]) return;
    attempt.operation = operation;
    attempt.uncertain = false; attempt.hardUnknown = operation.phase === 'cleanup-unknown';
    this.publish({ status, original: operation, issue: attempt.hardUnknown ? 'unknown' : operation.reason,
      uncertain: attempt.hardUnknown });
  }
  private finish(): void {
    const attempt = this.attempt;
    if (!attempt || !attempt.startReturned || this.works.size) return;
    const operation = attempt.operation;
    if (attempt.hardUnknown) {
      attempt.reject?.(failure('unknown', 'unknown')); attempt.resolve = null; attempt.reject = null; return;
    }
    if (attempt.refusal && !attempt.uncertain) {
      const reply = attempt.refusal;
      // This only discharges the exact never-admitted request, after every
      // original Promise joined. No Git failure/settlement receipt is invented.
      const previous = reply.status.operation;
      // Install any disclosed older original BEFORE publishing/reentrant Root
      // admission; there is no temporary owner-free reconnect window.
      this.attempt = previous && previous.phase !== 'settled' ? {
        binding: attempt.binding, api: attempt.api, action: previous.action, baseline: null,
        documentRevision: reply.status.documentRevision, observedOnly: true, refusal: null, operation: previous, entered: true,
        startReturned: true, hardUnknown: previous.phase === 'cleanup-unknown', uncertain: previous.phase === 'cleanup-unknown',
        cancelSent: false, resolve: null, reject: null,
      } : null;
      this.baseline = null;
      attempt.reject?.(new Declined(reply.reason));
      this.publish({ status: this.attempt ? reply.status : null, original: previous,
        issue: previous?.phase === 'cleanup-unknown' ? 'unknown' : reply.reason,
        uncertain: previous?.phase === 'cleanup-unknown', stale: true, historyCurrent: false, branchesCurrent: false });
      return; // A fresh explicit status check is required; no resubmission.
    }
    if (!operation || operation.phase !== 'settled' || attempt.uncertain) return;
    const current = same(attempt.binding, this.current());
    if (!attempt.observedOnly && operation.outcome === 'ok' && current) {
      if (attempt.action.kind === 'observe') this.publish({ observation: operation.result as GitReadObservation, observationProject: operation.context.projectId, stale: false });
      if (attempt.action.kind === 'branches') this.publish({ branches: operation.result as GitBranches, branchesProject: operation.context.projectId, branchesCurrent: true });
      if (attempt.action.kind === 'history') this.publish({ history: operation.result as GitReadHistory, historyProject: operation.context.projectId, historyCurrent: true });
      if (same(attempt.binding, this.current())) {
        attempt.resolve?.(attempt.action.kind === 'observe' ? (operation.result as GitReadObservation).observation : operation.result);
      } else { attempt.reject?.(failure('stale-observation', 'settled')); }
    } else if (!attempt.observedOnly) {
      attempt.reject?.(failure(current ? operation.reason ?? 'command-failed' : 'stale-observation', 'settled'));
    }
    const stillCurrent = same(attempt.binding, this.current());
    this.attempt = null;
    this.baseline = stillCurrent ? attempt.binding : null;
    this.publish({ status: stillCurrent ? this.state.status : null, issue: stillCurrent ? operation.reason : 'stale-observation',
      ...(!stillCurrent ? { stale: true, historyCurrent: false, branchesCurrent: false } : {}) });
  }
}
