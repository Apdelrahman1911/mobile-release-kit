// One controller per original registered project/session. Root retains it across
// panel unmounts; switching projects never retargets a pending port or operation.
// This is UI coordination, not a native project lease or an authorization issuer.
import { gitDiscardAcknowledged, gitDraftFieldFits, gitSamePaths, gitStagedPaths, parseGitApplyReceipt,
  parseGitDiff, parseGitFailure, parseGitObservation, parseGitPlan } from './gitRepositoryProtocol.ts';
import { gitBranchDraftFits } from './gitBranchesProtocol.ts';
import type { GitAction, GitApplyReceipt, GitCommitDraft, GitDiff, GitIssue, GitMutationResult, GitObservation, GitPlan } from './gitRepositoryProtocol.ts';

interface PathRequest { readonly paths: readonly string[]; readonly expectedRevision: string }
interface PlanRequest { readonly planId: string }
export interface GitMutationPort {
  prepareStage(input: PathRequest): Promise<unknown>;
  prepareUnstage(input: PathRequest): Promise<unknown>;
  prepareCommit(input: GitCommitDraft & { readonly expectedRevision: string }): Promise<unknown>;
  applyStage(input: PlanRequest): Promise<unknown>;
  applyUnstage(input: PlanRequest): Promise<unknown>;
  applyCommit(input: PlanRequest): Promise<unknown>;
  discardPlan(input: PlanRequest): Promise<unknown>;
  // Optional Root-owned lookup of the ORIGINAL invocation registered for this
  // exact plan, not a fresh Git read, new owner, or renderer-claimed settlement.
  readOriginalStatus?(input: PlanRequest): Promise<unknown>;
}
export interface GitRepositoryPort {
  // Display consistency only; native independently binds the actual registered
  // root and client/session. This object must never be retargeted/reused.
  readonly projectId: string;
  // Optional original read-only bridge admission/locally declined handoff.
  // Absent for the existing mutation port: its behavior is unchanged.
  readReason?(): GitIssue | null;
  declined?(error: unknown): GitIssue | null;
  // Only the original native owner may offer a read result/settled failure after
  // its own process/pipe/close/join accounting. Generic exceptions are unknown.
  observe(): Promise<unknown>;
  diff(input: PathRequest & { readonly staged: boolean }): Promise<unknown>;
  readonly mutations?: GitMutationPort;
}
export interface GitReview {
  readonly plan: GitPlan; readonly draft: GitCommitDraft | null;
  readonly preview: GitDiff | null; readonly stale: boolean;
}
export interface GitAttempt {
  readonly review: GitReview;
  readonly phase: 'sending' | 'awaiting-status' | 'settled' | 'recovery-required' | 'unknown';
  readonly receipt: GitApplyReceipt | null;
}
export interface GitRepositoryView {
  readonly projectId: string; readonly active: boolean; readonly observation: GitObservation | null;
  readonly stale: boolean; readonly selected: readonly string[]; readonly draft: GitCommitDraft; readonly branchDraft: { readonly name: string };
  readonly switchDraft: { readonly name: string };
  readonly diff: GitDiff | null; readonly review: GitReview | null; readonly attempt: GitAttempt | null;
  readonly busy: 'observe' | 'diff' | 'review' | 'discard' | 'apply' | null; readonly checkingStatus: boolean;
  readonly issue: GitIssue | null; readonly blocked: 'unknown' | 'response-invalid' | 'recovery-required' | null;
}
interface Flight { readonly epoch: number; readonly selection: number; readonly draft: number }
const freeze = <T extends object>(value: T): Readonly<T> => Object.freeze(value);
// Only already-decoded, bounded, immutable public DATA enters this projection.
// A core result is terminal evidence even while native cleanup is still pending.
// Object key ordering on the wire is not part of that evidence.
const coreEvidence = (result: GitMutationResult): string => {
  const o = result.observation, i = result.intent;
  return JSON.stringify([result.operationId, result.action, result.state, result.settlement, result.reason,
    o && [o.revision, o.head, o.branch, o.unborn, o.detached,
      o.changes.map((c) => [c.path, c.index, c.worktree, c.kind, c.conflict]), o.remotes, o.restrictions],
    i && [i.action, i.expectedRevision, i.expectedRef, i.expectedHead, i.expectedIndex, i.candidateIndex, i.candidateCommit]]);
};

export class GitRepositoryController {
  private readonly port: GitRepositoryPort | null;
  private state: GitRepositoryView;
  private readonly listeners = new Set<() => void>();
  private epoch = 0;
  private selectionRevision = 0;
  private draftRevision = 0;
  private flight: Flight | null = null;
  private applySent = false;

  constructor(projectId: string, port: GitRepositoryPort | null) {
    this.port = port?.projectId === projectId ? port : null;
    this.state = freeze({ projectId, active: true, observation: null, stale: true, selected: freeze([]),
      draft: freeze({ message: '', authorName: '', authorEmail: '' }), branchDraft: freeze({ name: '' }), switchDraft: freeze({ name: '' }), diff: null, review: null, attempt: null,
      busy: null, checkingStatus: false, issue: port && !this.port ? 'authorization' : null, blocked: null });
  }
  getSnapshot = (): GitRepositoryView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  hasWriter(): boolean { return this.port?.mutations !== undefined; }
  private patch(change: Partial<GitRepositoryView>): void {
    this.state = freeze({ ...this.state, ...change });
    for (const listener of [...this.listeners]) { try { listener(); } catch { /* Rendering cannot abandon the original call. */ } }
  }
  private report(issue: GitIssue): false { this.patch({ issue }); return false; }
  private staleReview(): GitReview | null { return this.state.review ? freeze({ ...this.state.review, stale: true }) : null; }
  invalidate(): void {
    this.epoch += 1;
    this.patch({ stale: true, diff: null, review: this.staleReview() });
  }
  setActive(active: boolean): void {
    if (active === this.state.active) return;
    this.epoch += 1;
    this.patch({ active, stale: true, diff: null, review: this.staleReview() });
  }
  editDraft(field: keyof GitCommitDraft, value: string): boolean {
    if (!['message', 'authorName', 'authorEmail'].includes(field) || !gitDraftFieldFits(field, value)) return this.report('limit');
    if (this.state.draft[field] === value) return true;
    this.draftRevision += 1;
    this.patch({ draft: freeze({ ...this.state.draft, [field]: value }),
      review: this.state.review?.plan.action === 'commit' ? this.staleReview() : this.state.review });
    return true;
  }
  editBranchName(value: string): boolean {
    if (!gitBranchDraftFits(value)) return this.report('limit');
    if (this.state.branchDraft.name !== value) this.patch({ branchDraft: freeze({ name: value }) });
    return true; // Original project-local draft; changed-and-restored is a new capture.
  }
  selectSwitchBranch(value: string): boolean {
    if (!gitBranchDraftFits(value)) return this.report('limit');
    if (this.state.switchDraft.name !== value) this.patch({ switchDraft: freeze({ name: value }) });
    return true; // Selection only, never a checkout or an implicit new review.
  }
  select(path: string, selected: boolean): boolean {
    if (!this.state.observation?.changes.some((row) => row.path === path)) return this.report('selection-changed');
    const values = this.state.selected;
    if (values.includes(path) === selected) return true;
    if (selected && values.length >= 64) return this.report('limit');
    this.replaceSelection(selected ? [...values, path] : values.filter((item) => item !== path)); return true;
  }
  clearSelection(): void { if (this.state.selected.length) this.replaceSelection([]); }
  private replaceSelection(selected: readonly string[]): void {
    this.selectionRevision += 1;
    this.patch({ selected: freeze([...selected]), diff: null,
      review: this.state.review?.plan.action === 'commit' ? this.state.review : this.staleReview() });
  }
  readReason(): GitIssue | null {
    if (!this.state.active) return 'inactive';
    if (!this.port) return 'unavailable';
    if (this.state.busy !== null || this.state.checkingStatus) return 'busy';
    return this.state.blocked ?? this.port.readReason?.() ?? null;
  }
  private currentReason(): GitIssue | null {
    return this.readReason() ?? (!this.state.observation ? 'no-observation' : this.state.stale ? 'stale-observation' : null);
  }
  selectionReason(): GitIssue | null {
    return this.currentReason() ?? (!this.state.selected.length ? 'no-selection' :
      this.state.selected.some((path) => !this.state.observation?.changes.some((row) => row.path === path)) ? 'selection-changed' : null);
  }
  prepareReason(action: GitAction): GitIssue | null {
    const reason = this.currentReason();
    if (reason) return reason;
    if (!this.port?.mutations) return 'unavailable';
    if (this.state.attempt && this.state.attempt.phase !== 'settled') return 'already-used';
    if (this.state.review) return 'review-changed';
    if (action !== 'commit') return this.selectionReason();
    if (!gitStagedPaths(this.state.observation!).length) return 'nothing-staged';
    return Object.values(this.state.draft).every((value) => value.trim().length > 0) ? null : 'draft-incomplete';
  }
  applyReason(planId: string): GitIssue | null {
    const reason = this.currentReason();
    if (reason) return reason;
    if (!this.port?.mutations) return 'unavailable';
    if (this.state.attempt && this.state.attempt.phase !== 'settled') return 'already-used';
    const review = this.state.review;
    if (!review || review.plan.planId !== planId) return 'review-first';
    return review.stale || !review.preview || review.plan.expectedRevision !== this.state.observation!.revision ? 'review-changed' : null;
  }
  private begin(busy: GitRepositoryView['busy']): Flight {
    const flight = freeze({ epoch: this.epoch, selection: this.selectionRevision, draft: this.draftRevision });
    this.flight = flight; this.patch({ busy, issue: null }); return flight;
  }
  private current(flight: Flight): boolean { return this.flight === flight && this.state.active && this.epoch === flight.epoch; }
  private finish(flight: Flight): void { if (this.flight === flight) { this.flight = null; this.patch({ busy: null }); } }
  private fail(error: unknown): void {
    const declined = this.port?.declined?.(error);
    if (declined) { this.patch({ issue: declined }); return; }
    const failure = parseGitFailure(error);
    if (!failure || failure.nativeFinality === 'unknown' || failure.reason === 'unknown') {
      this.patch({ blocked: 'unknown', issue: failure?.reason ?? 'acknowledgement-missing', stale: true, review: this.staleReview() }); return;
    }
    if (failure.reason === 'stale-observation') this.invalidate();
    this.patch({ issue: failure.reason, blocked: failure.reason === 'recovery-required' || failure.reason === 'response-invalid' ? failure.reason : this.state.blocked });
  }
  private invalid(): void { this.patch({ blocked: 'response-invalid', issue: 'response-invalid', stale: true, review: this.staleReview() }); }

  async refresh(): Promise<boolean> {
    const reason = this.readReason(); if (reason) return this.report(reason);
    const flight = this.begin('observe');
    this.patch({ stale: true });
    try {
      if (!this.current(flight)) return false;
      const observation = parseGitObservation(await this.port!.observe());
      if (!observation) { this.invalid(); return true; }
      if (this.current(flight)) {
        const changed = this.state.observation?.revision !== observation.revision;
        this.patch({ observation, stale: false, diff: changed ? null : this.state.diff,
          review: changed ? this.staleReview() : this.state.review });
      }
    } catch (error) { this.fail(error); } finally { this.finish(flight); }
    return true;
  }
  async preview(staged: boolean): Promise<boolean> {
    const reason = this.selectionReason(); if (reason) return this.report(reason);
    if (typeof staged !== 'boolean') return this.report('invalid-input');
    const request = freeze({ paths: this.state.selected, expectedRevision: this.state.observation!.revision, staged });
    const flight = this.begin('diff');
    this.patch({ diff: null });
    try {
      if (!this.current(flight)) return false;
      const diff = parseGitDiff(await this.port!.diff(request));
      if (!diff || diff.revision !== request.expectedRevision || diff.staged !== staged || !gitSamePaths(diff.paths, request.paths)) this.invalid();
      else if (this.current(flight) && flight.selection === this.selectionRevision) this.patch({ diff });
    } catch (error) { this.fail(error); } finally { this.finish(flight); }
    return true;
  }
  async prepare(action: GitAction): Promise<boolean> {
    if (!['stage', 'unstage', 'commit'].includes(action)) return this.report('invalid-input');
    const reason = this.prepareReason(action); if (reason) return this.report(reason);
    const original = this.state.observation!, writes = this.port!.mutations!;
    const selected = freeze([...(action === 'commit' ? gitStagedPaths(original) : this.state.selected)]);
    const request = freeze({ paths: selected, expectedRevision: original.revision });
    const draft = action === 'commit' ? this.state.draft : null;
    const flight = this.begin('review');
    const stillCurrent = () => this.current(flight) && (action === 'commit' ? flight.draft === this.draftRevision : flight.selection === this.selectionRevision);
    try {
      if (!stillCurrent()) return false;
      const raw = action === 'stage' ? await writes.prepareStage(request) : action === 'unstage' ? await writes.prepareUnstage(request) :
        await writes.prepareCommit(freeze({ ...draft!, expectedRevision: original.revision }));
      const plan = parseGitPlan(raw);
      if (!plan || plan.action !== action || plan.expectedRevision !== original.revision || plan.head !== original.head ||
          plan.branch !== original.branch || !gitSamePaths(plan.paths, selected)) { this.invalid(); return true; }
      // A late successful prepare is still an original retained plan. Never
      // silently discard it or use it with a newer selection/draft/session.
      this.patch({ review: freeze({ plan, draft, preview: null, stale: !stillCurrent() }) });
      if (!stillCurrent()) return true;
      const staged = action !== 'stage';
      const preview = parseGitDiff(await this.port!.diff(freeze({ ...request, staged })));
      if (!preview || preview.revision !== original.revision || preview.staged !== staged || !gitSamePaths(preview.paths, plan.paths)) this.invalid();
      else this.patch({ review: freeze({ plan, draft, preview, stale: !stillCurrent() }) });
    } catch (error) { this.fail(error); this.patch({ review: this.staleReview() }); } finally { this.finish(flight); }
    return true;
  }
  async discardReview(planId: string): Promise<boolean> {
    const reason = this.readReason(); if (reason) return this.report(reason);
    const review = this.state.review;
    if (!review || planId !== review.plan.planId || !this.port?.mutations) return this.report('review-first');
    const flight = this.begin('discard');
    try {
      if (!this.current(flight)) return false;
      const ack = await this.port.mutations.discardPlan(freeze({ planId }));
      if (!gitDiscardAcknowledged(ack)) this.invalid();
      else this.patch({ review: null }); // Retire only this unused plan; keep every draft/attempt.
    } catch (error) { this.fail(error); this.patch({ review: this.staleReview() }); } finally { this.finish(flight); }
    return true;
  }
  async applyReviewed(planId: string): Promise<boolean> {
    const reason = this.applyReason(planId); if (reason) return this.report(reason);
    const review = this.state.review!, writes = this.port!.mutations!;
    const flight = this.begin('apply');
    if (!this.current(flight) || this.state.review !== review || review.stale) { this.finish(flight); return false; }
    const previous = this.state.attempt;
    this.applySent = false;
    this.patch({ review: null, attempt: freeze({ review, phase: 'sending', receipt: null }), stale: true, diff: null });
    try {
      // Listeners may synchronously change the selected project. No call has
      // been made yet, so retain the unused review instead of inventing a send.
      if (!this.current(flight) || (review.plan.action === 'commit' ? flight.draft !== this.draftRevision : flight.selection !== this.selectionRevision)) {
        this.patch({ review: freeze({ ...review, stale: true }), attempt: previous }); return false;
      }
      this.applySent = true; // One-way local claim BEFORE the original port call.
      const request = freeze({ planId });
      const raw = review.plan.action === 'stage' ? await writes.applyStage(request) : review.plan.action === 'unstage' ?
        await writes.applyUnstage(request) : await writes.applyCommit(request);
      this.acceptReceipt(raw, this.current(flight));
    } catch (error) {
      const failure = parseGitFailure(error);
      if (failure?.nativeFinality === 'unknown' || failure?.reason === 'unknown' || failure?.reason === 'recovery-required') {
        const phase = failure.nativeFinality === 'unknown' || failure.reason === 'unknown' ? 'unknown' : 'recovery-required';
        this.patch({ attempt: freeze({ ...this.state.attempt!, phase }), blocked: phase, issue: phase });
      } else {
        // Even a settled generic rejection lacks this operation's effect.
        // Only its exact native status may establish a settled failed result.
        this.patch({ attempt: freeze({ ...this.state.attempt!, phase: 'awaiting-status' }), issue: 'acknowledgement-missing' });
      }
    } finally { this.finish(flight); }
    return true;
  }
  private acceptReceipt(raw: unknown, adoptObservation: boolean): void {
    const attempt = this.state.attempt!, plan = attempt.review.plan;
    const receipt = parseGitApplyReceipt(raw), result = receipt?.result;
    const intent = result?.intent, previous = attempt.receipt?.result;
    if (!receipt || receipt.planId !== plan.planId || result && result.action !== plan.action ||
        previous && (!result || coreEvidence(previous) !== coreEvidence(result)) ||
        intent && (intent.expectedRevision !== plan.expectedRevision || intent.expectedRef !== plan.branch || intent.expectedHead !== plan.head) ||
        previous?.intent && (!intent || (Object.keys(previous.intent) as (keyof typeof intent)[]).some((key) => previous.intent![key] !== intent[key]))) {
      this.invalid(); this.patch({ attempt: freeze({ ...attempt, phase: attempt.phase === 'recovery-required' ? 'recovery-required' : 'unknown' }) }); return;
    }
    // Actual unknown/recovery is absorbing in this UI. Later source observations
    // or a success-shaped result cannot release original native custody.
    const phase: GitAttempt['phase'] = attempt.phase === 'unknown' || attempt.phase === 'recovery-required' ? attempt.phase :
      receipt.nativeFinality === 'unknown' || result?.settlement === 'unknown' ? 'unknown' : result?.state === 'recovery-required' ? 'recovery-required' :
      receipt.nativeFinality === 'settled' ? 'settled' : 'awaiting-status';
    const blocked = phase === 'unknown' || phase === 'recovery-required' ? phase : this.state.blocked;
    const observation = adoptObservation && phase === 'settled' && result?.state === 'succeeded' ? result.observation : null;
    this.patch({ attempt: freeze({ ...attempt, receipt, phase }), blocked, issue: blocked ?? result?.reason ?? null,
      ...(observation ? { observation, stale: false } : { stale: true }) });
  }
  canCheckOriginalStatus(): boolean {
    return this.applySent && this.state.attempt !== null && this.state.attempt.phase !== 'settled' && !this.state.checkingStatus &&
      this.state.busy === null && this.port?.mutations?.readOriginalStatus !== undefined;
  }
  async checkOriginalStatus(): Promise<boolean> {
    if (!this.canCheckOriginalStatus()) return false;
    const planId = this.state.attempt!.review.plan.planId;
    this.patch({ checkingStatus: true });
    try { this.acceptReceipt(await this.port!.mutations!.readOriginalStatus!(freeze({ planId })), false); }
    catch (error) {
      const failure = parseGitFailure(error);
      if (failure?.nativeFinality === 'unknown' || failure?.reason === 'unknown')
        this.patch({ attempt: freeze({ ...this.state.attempt!, phase: 'unknown' }), blocked: 'unknown', issue: 'unknown' });
      else this.patch({ issue: 'acknowledgement-missing' });
    }
    finally { this.patch({ checkingStatus: false }); }
    return true;
  }
}
