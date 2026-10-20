// UI coordination for the five original GitLocal calls, not a process owner.
// Root retains this controller across navigation and supplies only native ports.
import { gitLocalIntentMatchesReview, gitLocalPreparedResult, gitLocalRequest, parseGitLocalStartResult, parseGitLocalStatus, sameGitLocalAction, sameGitLocalData, samePaths } from './gitLocalProtocol.ts';
import { gitReadPathOrder, sameGitReadContext } from './gitReadProtocol.ts';
import { gitStagedPaths } from './gitRepositoryProtocol.ts';
import type { GitLocalAction, GitLocalApi, GitLocalCommand, GitLocalFileInput, GitLocalIssue, GitLocalMutationResult, GitLocalOperation, GitLocalPrepared, GitLocalStartRequest, GitLocalStartResult, GitLocalStatus } from './gitLocalProtocol.ts';
import type { GitAction, GitCommitDraft, GitIssue, GitObservation } from './gitRepositoryProtocol.ts';
import type { GitRepositoryController } from './gitRepositoryController.ts';
import type { GitReadController } from './gitReadController.ts';
import { gitBranchName } from './gitBranchesProtocol.ts';
import type { GitBranchAction, GitBranches } from './gitBranchesProtocol.ts';
import type { GitSwitchAction } from './gitSwitchProtocol.ts';
import { sameRenameParent } from './gitRenameProtocol.ts';
import type { GitRenameAction } from './gitRenameProtocol.ts';

export interface GitLocalBinding { readonly api: GitLocalApi | null; readonly session: object | null; readonly projectId: string | null;
  readonly epoch: number; readonly repository: GitRepositoryController | null; readonly blocked: string | null;
  readonly reader?: GitReadController | null }
interface Capture { readonly binding: GitLocalBinding; readonly repository: GitRepositoryController; readonly observation: GitObservation;
  readonly selected: readonly string[]; readonly draft: GitCommitDraft; readonly action: GitLocalAction; readonly paths: readonly string[];
  readonly branches: GitBranches | null; readonly branchDraft: { readonly name: string }; readonly switchDraft: { readonly name: string }; readonly renameDraft: { readonly name: string } }
interface HeldReview { readonly api: GitLocalApi; readonly binding: GitLocalBinding; readonly prepared: GitLocalPrepared; readonly capture: Capture | null;
  stale: boolean; consumed: boolean; discardSent: boolean; discardConfirmed: boolean; uncertain: boolean }
interface Attempt { readonly binding: GitLocalBinding; readonly api: GitLocalApi; readonly request: GitLocalStartRequest;
  readonly action: GitLocalAction; readonly capture: Capture | null; readonly applied: HeldReview | null; readonly baseline: string | null;
  operation: GitLocalOperation | null; entered: boolean; returned: boolean; uncertain: boolean; hardUnknown: boolean; recovery: boolean; cancelSent: boolean;
  retired: boolean;
  refusal: Extract<GitLocalStartResult, { admission: 'refused' }> | null }
interface Work { readonly kind: GitLocalCommand; readonly binding: GitLocalBinding; readonly attempt: Attempt | null; readonly review: HeldReview | null;
  original: Promise<unknown> | null }
export interface GitLocalReviewView { readonly prepared: GitLocalPrepared; readonly draft: GitCommitDraft | null; readonly stale: boolean; readonly approved: boolean }
export interface GitLocalView { readonly status: GitLocalStatus | null; readonly original: GitLocalOperation | null; readonly review: GitLocalReviewView | null;
  readonly submitted: GitLocalPrepared | null; readonly projectId: string | null; readonly pending: number; readonly checking: boolean; readonly issue: GitLocalIssue | null;
  readonly uncertain: boolean; readonly recovery: boolean }
const same = (a: GitLocalBinding, b: GitLocalBinding) => a.api === b.api && a.session === b.session && a.projectId === b.projectId &&
  a.epoch === b.epoch && a.repository === b.repository && a.reader === b.reader;
const rank = { starting: 0, running: 1, stopping: 2, settled: 3, 'cleanup-unknown': 4 } as const;
const appliedResult = (o: GitLocalOperation | null): GitLocalMutationResult | null => o?.phase === 'apply' && o.result ? o.result as GitLocalMutationResult : null;

export class GitLocalController {
  private readonly source: { current(): GitLocalBinding; onMutationSubmitted(projectId: string): void };
  private readonly listeners = new Set<() => void>();
  private readonly works = new Set<Work>();
  private attempt: Attempt | null = null;
  private held: HeldReview | null = null;
  private approved: HeldReview | null = null;
  private context: GitLocalBinding | null = null;
  private observed: GitLocalBinding | null = null;
  private originalBinding: GitLocalBinding | null = null;
  private state: GitLocalView = Object.freeze({ status: null, original: null, review: null, submitted: null,
    projectId: null, pending: 0, checking: false, issue: null, uncertain: false, recovery: false });
  constructor(source: { current(): GitLocalBinding; onMutationSubmitted(projectId: string): void }) { this.source = source; }
  getSnapshot = (): GitLocalView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private current(): GitLocalBinding {
    try { return Object.freeze({ ...this.source.current() }); }
    catch { return { api: null, session: null, projectId: null, epoch: -1, repository: null, blocked: 'Native Git is unavailable.' }; }
  }
  private publish(change: Partial<GitLocalView> = {}): void {
    const h = this.held, next = { ...this.state, ...change };
    this.state = Object.freeze({ ...next, pending: this.works.size,
      projectId: this.attempt?.request.projectId ?? h?.prepared.context.projectId ?? next.original?.context.projectId ?? null,
      checking: [...this.works].some((w) => w.kind === 'status'),
      review: h ? Object.freeze({ prepared: h.prepared, draft: h.capture?.action.kind === 'commit' ? h.capture.draft : null,
        stale: h.stale || !h.capture || !this.captureCurrent(h.capture, false), approved: this.approved === h }) : null });
    for (const listener of [...this.listeners]) { try { listener(); } catch { /* Rendering never releases an original call. */ } }
  }
  private report(issue: GitLocalIssue): false { this.publish({ issue }); return false; }
  ownerReason(): string | null {
    if (this.attempt?.hardUnknown || this.state.uncertain) return 'The original Git result or cleanup is unconfirmed. Keep the app and project files.';
    if (this.attempt?.recovery || this.state.recovery) return 'The original Git change needs recovery. Do not repeat it or remove its locks.';
    if (this.attempt) return 'Finish checking or stopping the original Git action first.';
    if (this.held) return 'Apply or close the original Git review before starting another task.';
    return this.works.size ? 'Wait for the original Git request to finish.' : null;
  }
  syncContext(): void {
    const now = this.current();
    if (!this.context || !same(this.context, now)) {
      this.context = now; this.observed = null; this.approved = null;
      if (this.attempt) this.attempt.retired = true;
      if (this.held) this.held.stale = true;
      this.publish({ status: this.attempt || this.held ? this.state.status : null });
    }
  }
  beforeContextIntent(): void {
    this.context = null; this.observed = null; this.approved = null;
    if (this.attempt) this.attempt.retired = true;
    if (this.held) this.held.stale = true;
    this.publish({ status: this.attempt || this.held ? this.state.status : null });
  }
  private captureCurrent(c: Capture, peers = true): boolean {
    const now = this.current(), r = c.repository.getSnapshot();
    return same(c.binding, now) && (!peers || !now.blocked) && r.projectId === now.projectId && r.active && !r.stale && !r.blocked &&
      r.busy === null && !r.checkingStatus && r.observation === c.observation &&
      (c.action.kind === 'branch-rename' ? r.renameDraft === c.renameDraft && this.branchList(now) === c.branches :
        c.action.kind === 'branch-switch' ? r.switchDraft === c.switchDraft && this.branchList(now) === c.branches :
        c.action.kind === 'branch-create' ? r.branchDraft === c.branchDraft && this.branchList(now) === c.branches : r.selected === c.selected && r.draft === c.draft);
  }
  private branchList(binding: GitLocalBinding): GitBranches | null {
    const read = binding.reader?.getSnapshot(), r = binding.repository?.getSnapshot();
    return read && r?.observation && !read.stale && read.branchesCurrent && read.branchesProject === binding.projectId &&
      read.branches?.revision === r.observation.revision && read.branches.head === r.observation.head && read.branches.branch === r.observation.branch ? read.branches : null;
  }
  private currentReason(): GitIssue | null {
    const now = this.current();
    if (!now.api || !now.session) return 'unavailable';
    if (!now.projectId || !now.repository || now.repository.getSnapshot().projectId !== now.projectId) return 'inactive';
    if (now.blocked) return 'busy';
    if (!this.observed || !same(this.observed, now) || !this.state.status?.available ||
        this.state.status.documentRevision === 0 || this.state.status.documentRevision === 0xffffffff) return 'unavailable';
    const r = now.repository.getSnapshot();
    return !r.active ? 'inactive' : r.busy || r.checkingStatus ? 'busy' : r.blocked ?? (!r.observation ? 'no-observation' :
      r.stale ? 'stale-observation' : r.observation.restrictions[0] ?? (r.observation.changes.some((row) => row.conflict) ? 'conflicts' : null));
  }
  prepareReason(action: GitAction): GitIssue | null {
    if (!['stage', 'unstage', 'commit'].includes(action)) return 'invalid-input';
    if (this.ownerReason()) return this.state.recovery ? 'recovery-required' : this.state.uncertain ? 'unknown' : 'busy';
    const reason = this.currentReason(); if (reason) return reason;
    const r = this.current().repository!.getSnapshot();
    if (action !== 'commit') return !r.selected.length ? 'no-selection' :
      r.selected.some((p) => !r.observation!.changes.some((row) => row.path === p)) ? 'selection-changed' : null;
    const staged = gitStagedPaths(r.observation!);
    if (!staged.length) return 'nothing-staged';
    if (staged.length > 64) return 'limit';
    return gitLocalRequest('prepare', { projectId: r.projectId, expectedDocumentRevision: this.state.status!.documentRevision,
      action: this.input('commit') }) ? null : 'draft-incomplete';
  }
  private input(kind: GitAction): GitLocalFileInput {
    const r = this.current().repository!.getSnapshot();
    return Object.freeze({ kind, expectedRevision: r.observation!.revision, paths: Object.freeze(kind === 'commit' ? [] : [...r.selected].sort(gitReadPathOrder)),
      message: kind === 'commit' ? r.draft.message : null,
      identity: kind === 'commit' ? Object.freeze({ name: r.draft.authorName, email: r.draft.authorEmail }) : null });
  }
  async prepare(kind: GitAction): Promise<boolean> {
    const reason = this.prepareReason(kind); if (reason) return this.report(reason);
    const binding = this.current(), repository = binding.repository!, r = repository.getSnapshot(), input = this.input(kind);
    const action: GitLocalAction = Object.freeze({ kind, expectedRevision: input.expectedRevision, paths: input.paths });
    const request: GitLocalStartRequest = Object.freeze({ phase: 'prepare', projectId: binding.projectId!,
      expectedDocumentRevision: this.state.status!.documentRevision, action, reviewId: null });
    const raw = gitLocalRequest('prepare', { projectId: request.projectId, expectedDocumentRevision: request.expectedDocumentRevision, action: input });
    if (!raw) return this.report('invalid-input');
    const capture: Capture = Object.freeze({ binding, repository, observation: r.observation!, selected: r.selected, draft: r.draft, action,
      paths: Object.freeze([...(kind === 'commit' ? gitStagedPaths(r.observation!) : r.selected)].sort(gitReadPathOrder)), branches: null, branchDraft: r.branchDraft, switchDraft: r.switchDraft, renameDraft: r.renameDraft });
    const attempt = this.newAttempt(binding, request, action, capture, null);
    this.attempt = attempt; this.approved = null; this.publish({ original: null, submitted: null, issue: null });
    await this.send('prepare', raw, binding, attempt, null); return attempt.entered;
  }
  prepareBranchReason(): GitLocalIssue | null {
    if (this.ownerReason()) return this.state.recovery ? 'recovery-required' : this.state.uncertain ? 'unknown' : 'busy';
    const reason = this.currentReason(); if (reason) return reason;
    const binding = this.current(), r = binding.repository!.getSnapshot(), branches = this.branchList(binding);
    if (!branches) return 'branch-list-required';
    if (!branches.head) return 'unborn-head';
    if (!gitBranchName(r.branchDraft.name)) return 'branch-name-required';
    return branches.branches.some((b) => b.ref === `refs/heads/${r.branchDraft.name}`) ? 'branch-exists' : null;
  }
  async prepareBranch(): Promise<boolean> {
    const reason = this.prepareBranchReason(); if (reason) return this.report(reason);
    const binding = this.current(), repository = binding.repository!, r = repository.getSnapshot(), branches = this.branchList(binding);
    if (!branches || !r.observation) return this.report('branch-list-required');
    const action: GitBranchAction = Object.freeze({ kind: 'branch-create', expectedRevision: r.observation.revision,
      expectedReferenceRevision: branches.referenceRevision, name: r.branchDraft.name });
    const request: GitLocalStartRequest = Object.freeze({ phase: 'prepare', projectId: binding.projectId!,
      expectedDocumentRevision: this.state.status!.documentRevision, action, reviewId: null });
    const raw = gitLocalRequest('prepare', { projectId: request.projectId, expectedDocumentRevision: request.expectedDocumentRevision, action });
    if (!raw) return this.report('invalid-input');
    const capture: Capture = Object.freeze({ binding, repository, observation: r.observation, selected: r.selected, draft: r.draft,
      branchDraft: r.branchDraft, switchDraft: r.switchDraft, renameDraft: r.renameDraft, action, branches, paths: Object.freeze([]) });
    const attempt = this.newAttempt(binding, request, action, capture, null);
    this.attempt = attempt; this.approved = null; this.publish({ original: null, submitted: null, issue: null });
    await this.send('prepare', raw, binding, attempt, null); return attempt.entered;
  }
  prepareSwitchReason(): GitLocalIssue | null {
    if (this.ownerReason()) return this.state.recovery ? 'recovery-required' : this.state.uncertain ? 'unknown' : 'busy';
    const reason = this.currentReason(); if (reason) return reason;
    const binding = this.current(), r = binding.repository!.getSnapshot(), branches = this.branchList(binding);
    if (!branches) return 'branch-list-required';
    if (!branches.head || !branches.branch) return 'switch-target';
    if (r.observation!.changes.length) return 'switch-dirty';
    if (!gitBranchName(r.switchDraft.name)) return 'switch-name-required';
    const target = `refs/heads/${r.switchDraft.name}`;
    return target === branches.branch || !branches.branches.some((b) => b.ref === target) ? 'switch-target' : null;
  }
  async prepareSwitch(): Promise<boolean> {
    const reason = this.prepareSwitchReason(); if (reason) return this.report(reason);
    const binding = this.current(), repository = binding.repository!, r = repository.getSnapshot(), branches = this.branchList(binding);
    if (!branches || !r.observation) return this.report('branch-list-required');
    const action: GitSwitchAction = Object.freeze({ kind: 'branch-switch', expectedRevision: r.observation.revision,
      expectedReferenceRevision: branches.referenceRevision, name: r.switchDraft.name });
    const request: GitLocalStartRequest = Object.freeze({ phase: 'prepare', projectId: binding.projectId!,
      expectedDocumentRevision: this.state.status!.documentRevision, action, reviewId: null });
    const raw = gitLocalRequest('prepare', { projectId: request.projectId, expectedDocumentRevision: request.expectedDocumentRevision, action });
    if (!raw) return this.report('invalid-input');
    const capture: Capture = Object.freeze({ binding, repository, observation: r.observation, selected: r.selected, draft: r.draft,
      branchDraft: r.branchDraft, switchDraft: r.switchDraft, renameDraft: r.renameDraft, action, branches, paths: Object.freeze([]) });
    const attempt = this.newAttempt(binding, request, action, capture, null);
    this.attempt = attempt; this.approved = null; this.publish({ original: null, submitted: null, issue: null });
    await this.send('prepare', raw, binding, attempt, null); return attempt.entered;
  }
  prepareRenameReason(): GitLocalIssue | null {
    if (this.ownerReason()) return this.state.recovery ? 'recovery-required' : this.state.uncertain ? 'unknown' : 'busy';
    const reason = this.currentReason(); if (reason) return reason;
    const binding = this.current(), r = binding.repository!.getSnapshot(), branches = this.branchList(binding);
    if (!branches) return 'branch-list-required';
    if (!branches.head || !branches.branch || !branches.branches.some((b) => b.ref === branches.branch && b.oid === branches.head)) return 'rename-layout';
    if (!gitBranchName(r.renameDraft.name)) return 'rename-name-required';
    const target = `refs/heads/${r.renameDraft.name}`;
    if (!sameRenameParent(branches.branch, target)) return 'rename-target';
    const lower = target.toLowerCase();
    return branches.branches.some((b) => b.ref.toLowerCase() === lower || b.ref.toLowerCase().startsWith(`${lower}/`) ||
      lower.startsWith(`${b.ref.toLowerCase()}/`)) ? 'rename-target' : null;
  }
  async prepareRename(): Promise<boolean> {
    const reason = this.prepareRenameReason(); if (reason) return this.report(reason);
    const binding = this.current(), repository = binding.repository!, r = repository.getSnapshot(), branches = this.branchList(binding);
    if (!branches || !r.observation) return this.report('branch-list-required');
    const action: GitRenameAction = Object.freeze({ kind: 'branch-rename', expectedRevision: r.observation.revision,
      expectedReferenceRevision: branches.referenceRevision, name: r.renameDraft.name });
    const request: GitLocalStartRequest = Object.freeze({ phase: 'prepare', projectId: binding.projectId!,
      expectedDocumentRevision: this.state.status!.documentRevision, action, reviewId: null });
    const raw = gitLocalRequest('prepare', { projectId: request.projectId, expectedDocumentRevision: request.expectedDocumentRevision, action });
    if (!raw) return this.report('invalid-input');
    const capture: Capture = Object.freeze({ binding, repository, observation: r.observation, selected: r.selected, draft: r.draft,
      branchDraft: r.branchDraft, switchDraft: r.switchDraft, renameDraft: r.renameDraft, action, branches, paths: Object.freeze([]) });
    const attempt = this.newAttempt(binding, request, action, capture, null);
    this.attempt = attempt; this.approved = null; this.publish({ original: null, submitted: null, issue: null });
    await this.send('prepare', raw, binding, attempt, null); return attempt.entered;
  }
  private preparedMatchesCapture(prepared: GitLocalPrepared, capture: Capture): boolean {
    const r = prepared.review;
    if (r.head !== capture.observation.head || r.branch !== capture.observation.branch) return false;
    if (capture.action.kind === 'branch-rename') return r.action === 'branch-rename' && r.name === capture.action.name &&
      r.expectedReferenceRevision === capture.branches?.referenceRevision;
    if (capture.action.kind === 'branch-switch') return r.action === 'branch-switch' && r.name === capture.action.name && !!capture.branches &&
      r.expectedReferenceRevision === capture.branches.referenceRevision &&
      capture.branches.branches.some((b) => b.ref === r.targetRef && b.oid === r.targetOid);
    return capture.action.kind === 'branch-create' ? r.action === 'branch-create' && r.name === capture.action.name &&
      r.expectedReferenceRevision === capture.branches?.referenceRevision : r.action !== 'branch-create' && r.action !== 'branch-switch' && r.action !== 'branch-rename' && samePaths(r.paths, capture.paths);
  }
  reviewReason(): GitIssue | null {
    const h = this.held;
    if (!h) return 'review-first';
    if (this.state.uncertain || this.attempt?.hardUnknown) return 'unknown';
    if (this.state.recovery) return 'recovery-required';
    if (h.consumed) return 'already-used';
    if (this.attempt || this.works.size || h.discardSent) return 'busy';
    if (h.stale || !h.capture || !this.captureCurrent(h.capture) || !this.observed || !same(h.binding, this.observed) ||
        this.state.status?.review?.reviewId !== h.prepared.reviewId || !sameGitLocalData(this.state.status.review, h.prepared) ||
        h.prepared.context.revision !== `document-${this.state.status.documentRevision}`) return 'review-changed';
    return this.currentReason();
  }
  approve(checked: boolean): boolean {
    if (typeof checked !== 'boolean') return false;
    if (checked && this.reviewReason()) return false;
    this.approved = checked ? this.held : null; this.publish(); return true;
  }
  async apply(): Promise<boolean> {
    const reason = this.reviewReason(); if (reason) return this.report(reason);
    const h = this.held!; if (this.approved !== h) return this.report('review-first');
    const request: GitLocalStartRequest = Object.freeze({ phase: 'apply', projectId: h.binding.projectId!,
      expectedDocumentRevision: this.state.status!.documentRevision, action: null, reviewId: h.prepared.reviewId });
    const raw = gitLocalRequest('apply', { projectId: request.projectId, expectedDocumentRevision: request.expectedDocumentRevision, reviewId: request.reviewId });
    if (!raw) return this.report('invalid-input');
    const attempt = this.newAttempt(h.binding, request, h.prepared.action, h.capture, h);
    h.consumed = true; this.held = null; this.approved = null; this.attempt = attempt;
    this.publish({ original: null, submitted: h.prepared, issue: null });
    await this.send('apply', raw, h.binding, attempt, null); return attempt.entered;
  }
  private newAttempt(binding: GitLocalBinding, request: GitLocalStartRequest, action: GitLocalAction, capture: Capture | null, applied: HeldReview | null): Attempt {
    return { binding, api: binding.api!, request, action, capture, applied, baseline: this.state.status?.operation?.operationId ?? null,
      operation: null, entered: false, returned: false, uncertain: false, hardUnknown: false, recovery: false, cancelSent: false, retired: false, refusal: null };
  }
  checkReason(): string | null {
    if ([...this.works].some((w) => w.kind === 'status')) return 'Wait for the original status check.';
    if (this.attempt || this.held) return null;
    const now = this.current();
    return !now.api || !now.session ? 'Connect the native app service to check local Git actions.' : now.blocked;
  }
  canCheck(): boolean { return this.checkReason() === null; }
  async checkStatus(): Promise<boolean> {
    if (!this.canCheck()) return false;
    const a = this.attempt, h = this.held, binding = a?.binding ?? h?.binding ?? this.current();
    await this.send('status', gitLocalRequest('status', {})!, binding, a, h); return true;
  }
  canCancel(): boolean { return !!this.attempt?.operation && !this.attempt.cancelSent &&
    (this.attempt.operation.stage !== 'settled' || this.attempt.hardUnknown); }
  async cancel(): Promise<boolean> {
    const a = this.attempt; if (!a || !this.canCancel()) return false;
    a.cancelSent = true; this.publish();
    await this.send('cancel', gitLocalRequest('cancel', { operationId: a.operation!.operationId })!, a.binding, a, null); return true;
  }
  canDiscard(): boolean { return !!this.held && !this.attempt && !this.works.size && !this.held.discardSent && !this.state.recovery; }
  async discard(): Promise<boolean> {
    const h = this.held; if (!h || !this.canDiscard()) return false;
    h.discardSent = true; this.approved = null; this.publish();
    await this.send('discard', gitLocalRequest('discard', { reviewId: h.prepared.reviewId })!, h.binding, null, h); return true;
  }
  private uncertain(a: Attempt | null, h: HeldReview | null, hard = false): void {
    if (a?.hardUnknown || a?.recovery) { this.publish(); return; }
    if (a && this.attempt === a) { a.uncertain = true; a.hardUnknown ||= hard; }
    if (h && this.held === h) { h.uncertain = true; h.stale = true; }
    this.approved = null;
    this.publish({ issue: hard ? 'unknown' : 'acknowledgement-missing', uncertain: true });
  }
  private entryCurrent(a: Attempt): boolean { return this.attempt === a && !a.retired && !!a.capture && this.captureCurrent(a.capture) &&
    (a.request.phase !== 'apply' || !!a.applied && !a.applied.stale); }
  private async send(kind: GitLocalCommand, raw: Uint8Array, binding: GitLocalBinding, a: Attempt | null, h: HeldReview | null): Promise<void> {
    const work: Work = { kind, binding, attempt: a, review: h, original: null }; this.works.add(work); this.publish();
    try {
      if (kind === 'prepare' || kind === 'apply') {
        if (!a || !this.entryCurrent(a)) {
          if (a && this.attempt === a) {
            this.attempt = null;
            if (a.applied) { a.applied.consumed = false; a.applied.stale = true; this.held = a.applied; }
            this.publish({ issue: 'review-changed' });
          }
          return;
        }
        a.entered = true; // One-way claim before the actual original call.
      } else if (!a && !h && (!same(binding, this.current()) || this.current().blocked || this.attempt || this.held)) return;
      const api = a?.api ?? h?.api ?? binding.api;
      if (!api) return;
      try {
        const original = api[kind](raw);
        if (original instanceof Promise) work.original = original;
      } finally {
        // Even a synchronous throw/non-Promise after call entry is NOT proof of
        // no native admission. Invalidate eligibility, never the user's draft.
        if (kind === 'apply' && a?.entered) {
          try { this.source.onMutationSubmitted(a.request.projectId); }
          catch { this.uncertain(a, null, true); }
        }
      }
      if (!work.original) { this.uncertain(a, h); return; }
      const rawResult = await work.original;
      if (kind === 'prepare' || kind === 'apply') {
        const result = parseGitLocalStartResult(rawResult);
        if (!a || this.attempt !== a) return;
        if (!result || !sameGitLocalData(result.request, a.request)) { this.uncertain(a, null); return; }
        if (result.admission === 'refused') {
          if (a.hardUnknown) return;
          if (a.operation) { this.uncertain(a, null, true); return; }
          if (result.reason === 'stale-observation') a.capture?.repository.invalidate();
          a.refusal = result; this.publish({ issue: result.reason }); return;
        }
        this.receive(result.status, a, null, binding, kind); return;
      }
      const status = parseGitLocalStatus(rawResult);
      // Descriptor traps can reenter even when getter values are refused.
      if (!a && !h && !same(binding, this.current())) return;
      if (!status) {
        if (a || h) this.uncertain(a, h);
        else this.publish({ status: null, issue: 'response-invalid' });
        return;
      }
      this.receive(status, a, h, binding, kind);
    } catch {
      if (a || h) this.uncertain(a, h);
      else if (same(binding, this.current())) this.publish({ status: null, issue: 'unavailable' });
    } finally {
      if ((kind === 'prepare' || kind === 'apply') && a) a.returned = true;
      this.works.delete(work); this.publish(); this.finish();
    }
  }
  private receive(status: GitLocalStatus, a: Attempt | null, h: HeldReview | null, binding: GitLocalBinding, kind: GitLocalCommand): void {
    if (a) { if (this.attempt === a) this.receiveAttempt(status, a, kind); return; }
    if (this.attempt) return;
    if (h) {
      if (this.held !== h) return;
      // A discard/status read can confirm absence of THIS unused review, never
      // infer that a pending mutation settled or manufacture a new review.
      const op = status.operation;
      if (op && (op.stage !== 'settled' || appliedResult(op)?.state === 'recovery-required')) {
        this.observeOriginal(status, binding); return;
      }
      if (status.review && !sameGitLocalData(status.review, h.prepared)) { this.uncertain(null, h); return; }
      if (this.state.original && op?.operationId === this.state.original.operationId &&
          this.state.original.stage === 'settled' && !sameGitLocalData(op, this.state.original)) { this.uncertain(null, h); return; }
      if (!status.review) h.discardConfirmed = true;
      // Late pre-discard status cannot resurrect an already closed review.
      if (!h.discardConfirmed || !status.review) {
        h.uncertain = false;
        this.publish({ status, uncertain: false, issue: null });
        if (same(binding, this.current())) this.observed = binding;
      }
      return;
    }
    if (!same(binding, this.current())) return;
    this.observed = binding; this.context = binding;
    this.observeOriginal(status, binding);
  }
  private observeOriginal(status: GitLocalStatus, binding: GitLocalBinding): void {
    const op = status.operation, recovery = appliedResult(op)?.state === 'recovery-required';
    const previous = this.state.original;
    if (previous?.stage === 'settled' && op?.operationId === previous.operationId &&
        this.originalBinding?.api === binding.api && this.originalBinding.session === binding.session && !sameGitLocalData(previous, op)) {
      const request: GitLocalStartRequest = Object.freeze({ phase: previous.phase, projectId: previous.context.projectId,
        expectedDocumentRevision: Number(previous.context.revision.slice(9)), action: previous.phase === 'prepare' ? previous.action : null, reviewId: null });
      const a = this.newAttempt(binding, request, previous.action, null, null);
      a.operation = previous; a.entered = true; a.returned = true; this.attempt = a;
      this.uncertain(a, null, true); return;
    }
    this.originalBinding = binding;
    if (op && (op.stage !== 'settled' || recovery)) {
      const request: GitLocalStartRequest = Object.freeze({ phase: op.phase, projectId: op.context.projectId,
        expectedDocumentRevision: Number(op.context.revision.slice(9)), action: op.phase === 'prepare' ? op.action : null, reviewId: null });
      const a = this.newAttempt(binding, request, op.action, null, null);
      a.operation = op; a.entered = true; a.returned = true; a.hardUnknown = op.stage === 'cleanup-unknown'; a.uncertain = a.hardUnknown; a.recovery = recovery;
      this.attempt = a; this.approved = null; this.held = null;
      this.publish({ status, original: op, issue: a.hardUnknown ? 'unknown' : recovery ? 'recovery-required' : op.reason,
        uncertain: a.hardUnknown, recovery }); return;
    }
    // An observed-only review is closable on this port, never applicable with
    // a guessed/empty draft. Historical prepare.result is not a capability.
    this.held = status.review ? { api: binding.api!, binding, prepared: status.review, capture: null, stale: true,
      consumed: false, discardSent: false, discardConfirmed: false, uncertain: false } : null;
    this.approved = null;
    this.publish({ status, original: op, uncertain: false, recovery: false, issue: op?.reason ?? appliedResult(op)?.reason ?? null });
  }
  private receiveAttempt(status: GitLocalStatus, a: Attempt, kind: GitLocalCommand): void {
    if (a.hardUnknown || a.recovery) { this.publish(); return; } // Pin original evidence, including an unsent Stop.
    const op = status.operation;
    if (!op || !a.operation && op.operationId === a.baseline) {
      if (a.operation || kind !== 'status') this.uncertain(a, null, !!a.operation);
      return;
    }
    if (a.refusal || op.phase !== a.request.phase || !sameGitLocalAction(op.action, a.action) ||
        (a.operation ? op.operationId !== a.operation.operationId || !sameGitReadContext(op.context, a.operation.context) :
          op.context.projectId !== a.request.projectId || op.context.revision !== `document-${a.request.expectedDocumentRevision}`)) {
      this.uncertain(a, null, true); return;
    }
    if (a.operation?.stage === 'settled') {
      if (op.stage === 'cleanup-unknown' || op.stage === 'settled' && !sameGitLocalData(op, a.operation)) { this.uncertain(a, null, true); return; }
      if (op.stage !== 'settled') return;
      // The admitted Start reply may be a historical snapshot. Once an
      // original status supplied terminal evidence, it cannot retract that
      // status's retained review (or resurrect one that was cleared).
      if (kind === 'prepare' || kind === 'apply') return;
    } else if (a.operation && rank[op.stage] < rank[a.operation.stage]) return;
    const prepared = status.review;
    if (prepared && (a.request.phase !== 'prepare' || op.stage !== 'settled' || op.outcome !== 'ok' ||
        !sameGitReadContext(prepared.context, op.context) || !sameGitLocalAction(prepared.action, a.action) ||
        !sameGitLocalData(gitLocalPreparedResult(prepared), op.result) ||
        a.capture && !this.preparedMatchesCapture(prepared, a.capture))) { this.uncertain(a, null, true); return; }
    const result = appliedResult(op), originalReview = a.applied?.prepared.review;
    if (result?.intent && originalReview && !gitLocalIntentMatchesReview(result.intent, originalReview)) { this.uncertain(a, null, true); return; }
    a.operation = op; a.hardUnknown = op.stage === 'cleanup-unknown'; a.recovery = result?.state === 'recovery-required';
    this.originalBinding = a.binding;
    if (op.reason === 'stale-observation' || result?.reason === 'stale-observation') a.capture?.repository.invalidate();
    a.uncertain = a.hardUnknown;
    if (prepared) {
      if (this.held && !sameGitLocalData(this.held.prepared, prepared)) { this.uncertain(a, null, true); return; }
      this.held ??= { api: a.api, binding: a.binding, prepared, capture: a.capture, stale: a.retired || !a.capture || !this.captureCurrent(a.capture, false),
        consumed: false, discardSent: false, discardConfirmed: false, uncertain: false };
    } else if (a.request.phase === 'prepare') { this.held = null; this.approved = null; }
    if (same(a.binding, this.current())) { this.observed = a.binding; this.context = a.binding; }
    this.publish({ status, original: op, issue: a.hardUnknown ? 'unknown' : a.recovery ? 'recovery-required' : op.reason ?? result?.reason ?? null,
      uncertain: a.uncertain, recovery: a.recovery });
  }
  private finish(): void {
    if (this.works.size) return;
    const a = this.attempt;
    if (a && a.returned && !a.hardUnknown && !a.recovery) {
      if (a.refusal) {
        const { status, reason } = a.refusal;
        this.attempt = null;
        this.observeOriginal(status, a.binding);
        if (this.held && a.applied && this.held.prepared.reviewId === a.applied.prepared.reviewId) {
          // The native unused review remains close-only after a refused Apply.
          this.held.consumed = true;
        }
        if (same(a.binding, this.current())) { this.observed = a.binding; this.context = a.binding; }
        this.publish({ issue: reason });
      } else if (!a.uncertain && a.operation?.stage === 'settled') { this.attempt = null; this.publish(); }
    }
    if (!this.attempt && this.held?.discardConfirmed && !this.held.uncertain) { this.held = null; this.approved = null; this.publish({ uncertain: false }); }
  }
}
