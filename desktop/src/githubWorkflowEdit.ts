// App-wide workflow review state. Drafts, passive previews and these renderer
// generations are never filesystem revisions or native write authority.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { githubSetupRequestFits } from './githubSetupProtocol.ts';
import { normalWorkflowResult, workflowProjectionProgress, workflowStatusProgress } from './githubWorkflowEditProtocol.ts';
import type { Tone } from './certainty.ts';
import type { ProjectSession } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { BridgeMode, CoreEditReason, EditAvailability, HelpContent, JsonObject, NativeEditReason } from './types.ts';
import type { GitHubWorkflowEditProjection, GitHubWorkflowEditStatus, WorkflowPreparedFile, WorkflowPreparedView } from './githubWorkflowEditTypes.ts';

export interface WorkflowDraftBinding {
  projectId: string;
  windowGeneration: string;
  startStatusRevision: number;
  previousTerminalId: string | null;
  draftRevision: number;
  baselineGeneration: number;
  baseline: JsonObject | null;
  draft: JsonObject;
  serviceGeneration: number;
  selectionGeneration: number;
  coordinateGeneration: number;
  toolingRepository: string;
  toolingSha: string;
}
export interface WorkflowApplyBinding {
  sessionId: string;
  planToken: string;
  draftRevision: number;
  baselineGeneration: number;
}
export interface WorkflowAttempt {
  binding: WorkflowDraftBinding;
  sessionId: string | null;
  projection: GitHubWorkflowEditProjection | null;
  projectionRevision: number;
  prepareClaimed: boolean;
  applyClaimed: boolean;
  submittedPlanToken: string | null;
  closeRequested: boolean;
  closeClaimed: boolean;
  invalidated: boolean;
  handled: boolean;
}
export type WorkflowRecoveryAttention = Pick<GitHubWorkflowEditProjection, 'projectId' | 'sessionId' | 'ownerGeneration' | 'coreOutcome'>;
export interface GitHubWorkflowEditState {
  mode: BridgeMode;
  listening: boolean;
  initialized: boolean;
  readPending: boolean;
  status: GitHubWorkflowEditStatus | null;
  buffered: GitHubWorkflowEditStatus | null;
  observationIssue: 'bridge' | 'protocol' | null;
  integrityFailed: boolean;
  generationLost: boolean;
  nativeBlocked: boolean;
  unknownEvidence: GitHubWorkflowEditProjection | null;
  recoveryProjects: readonly WorkflowRecoveryAttention[];
  attempt: WorkflowAttempt | null;
}
export const initialGitHubWorkflowEdit: GitHubWorkflowEditState = {
  mode: 'unavailable', listening: false, initialized: false, readPending: false,
  status: null, buffered: null, observationIssue: null, integrityFailed: false,
  generationLost: false, nativeBlocked: false, unknownEvidence: null, recoveryProjects: [], attempt: null,
};
export type WorkflowEditAction =
  | { type: 'connect'; mode: BridgeMode }
  | { type: 'listening' }
  | { type: 'read-start' }
  | { type: 'observe'; status: GitHubWorkflowEditStatus; source: 'read' | 'event' | 'reply' }
  | { type: 'observation-failed'; protocol?: boolean }
  | { type: 'begin'; binding: WorkflowDraftBinding }
  | { type: 'prepare-claim'; sessionId: string }
  | { type: 'apply-claim'; binding: WorkflowApplyBinding }
  | { type: 'close-request'; reason: 'user' | 'context_changed' | 'invoke_failed' }
  | { type: 'close-claim'; sessionId: string }
  | { type: 'handled'; sessionId: string };

function unknown(owner: GitHubWorkflowEditProjection | null): boolean { return owner?.phase === 'unknown' || owner?.nativeFinality === 'unknown'; }
export function workflowAttemptSettled(attempt: WorkflowAttempt | null): boolean {
  return attempt === null || attempt.projection?.phase === 'final' && attempt.projection.nativeFinality === 'settled';
}
function usable(state: GitHubWorkflowEditState): boolean {
  return state.mode === 'native' && state.listening && state.initialized && state.status?.capability.available === true &&
    !state.observationIssue && !state.integrityFailed && !state.generationLost && !state.nativeBlocked;
}
function minimumTimers(previous: GitHubWorkflowEditStatus | null, status: GitHubWorkflowEditStatus): GitHubWorkflowEditStatus {
  const clamp = (owner: GitHubWorkflowEditProjection | null) => {
    if (!owner) return null;
    const old = [previous?.active, previous?.lastTerminal].find((item) => item?.sessionId === owner.sessionId);
    return old ? { ...owner, reviewRemainingMs: Math.min(old.reviewRemainingMs, owner.reviewRemainingMs) } : owner;
  };
  return { ...status, active: clamp(status.active), lastTerminal: clamp(status.lastTerminal) };
}
function retainAttention(state: GitHubWorkflowEditState, status: GitHubWorkflowEditStatus): GitHubWorkflowEditState {
  for (const owner of [status.active, status.lastTerminal]) {
    if (owner && unknown(owner)) {
      const old = state.unknownEvidence;
      const evidence = old && (old.sessionId !== owner.sessionId || !workflowProjectionProgress(old, owner)) ? old : owner;
      state = { ...state, nativeBlocked: true, unknownEvidence: evidence };
    }
    if (owner?.phase !== 'final' || owner.nativeFinality !== 'settled' || owner.coreOutcome?.journal !== 'recovery_required' ||
        owner.coreOutcome.resources !== 'settled' || state.recoveryProjects.some((item) => item.projectId === owner.projectId)) continue;
    if (state.recoveryProjects.length >= 64) return { ...state, integrityFailed: true, observationIssue: 'protocol' };
    const { projectId, sessionId, ownerGeneration, coreOutcome } = owner;
    state = { ...state, recoveryProjects: [...state.recoveryProjects, { projectId, sessionId, ownerGeneration, coreOutcome }] };
  }
  return status.capability.reason === 'cleanup_unknown' ? { ...state, nativeBlocked: true } : state;
}

function observe(state: GitHubWorkflowEditState, status: GitHubWorkflowEditStatus, source: 'read' | 'event' | 'reply'): GitHubWorkflowEditState {
  state = retainAttention(state, status);
  const readPending = source === 'read' ? false : state.readPending;
  if (!state.initialized && source !== 'read') return {
    ...state, readPending, buffered: !state.buffered || status.statusRevision >= state.buffered.statusRevision ? status : state.buffered,
  };
  if (!state.initialized && state.buffered?.windowGeneration === status.windowGeneration) {
    const first = state.buffered.statusRevision <= status.statusRevision ? state.buffered : status;
    const next = first === status ? state.buffered : status;
    if (!workflowStatusProgress(first, next)) return { ...state, readPending, integrityFailed: true, observationIssue: 'protocol' };
    if (state.buffered.statusRevision > status.statusRevision) status = state.buffered;
    status = minimumTimers(first, status);
  }
  // A replaced document can observe an original submitted result, never regain
  // its token. Latch revocation while retaining monotone original projections.
  const generationLost = state.generationLost || Boolean(state.status && state.status.windowGeneration !== status.windowGeneration);
  let attempt = state.attempt;
  if (attempt) {
    const retained = attempt;
    const owner = [status.active, status.lastTerminal].find((item) => item && item.domain === 'github_workflows' &&
      item.projectId === retained.binding.projectId && item.ownerGeneration === retained.binding.windowGeneration &&
      (retained.sessionId ? item.sessionId === retained.sessionId : status.statusRevision > retained.binding.startStatusRevision && item.sessionId !== retained.binding.previousTerminalId));
    if (owner) {
      const older = status.statusRevision < attempt.projectionRevision;
      if (attempt.projection && !(older ? workflowProjectionProgress(owner, attempt.projection) : workflowProjectionProgress(attempt.projection, owner))) {
        return { ...state, readPending, generationLost, integrityFailed: true, observationIssue: 'protocol' };
      }
      if (!older) attempt = { ...attempt, sessionId: owner.sessionId, projectionRevision: status.statusRevision,
        projection: attempt.projection ? { ...owner, reviewRemainingMs: Math.min(attempt.projection.reviewRemainingMs, owner.reviewRemainingMs) } : owner };
    }
  }
  if (state.status && status.statusRevision < state.status.statusRevision) {
    const contradictory = !workflowStatusProgress(status, state.status);
    return { ...state, readPending, generationLost, attempt,
      integrityFailed: state.integrityFailed || contradictory, observationIssue: contradictory ? 'protocol' : state.observationIssue };
  }
  if (state.status && !workflowStatusProgress(state.status, status)) return { ...state, readPending, generationLost, integrityFailed: true, observationIssue: 'protocol' };
  status = minimumTimers(state.status, status);
  return { ...state, initialized: true, readPending, status, buffered: null, attempt, generationLost, observationIssue: state.integrityFailed ? 'protocol' : null };
}

export function githubWorkflowEditReducer(state: GitHubWorkflowEditState, action: WorkflowEditAction): GitHubWorkflowEditState {
  switch (action.type) {
    case 'connect': return { ...state, mode: action.mode };
    case 'listening': return { ...state, listening: true };
    case 'read-start': return { ...state, readPending: true };
    case 'observe': return observe(state, action.status, action.source);
    case 'observation-failed': {
      const observationIssue = action.protocol || state.integrityFailed ? 'protocol' : 'bridge';
      const integrityFailed = state.integrityFailed || Boolean(action.protocol);
      return !state.readPending && state.observationIssue === observationIssue && state.integrityFailed === integrityFailed ? state :
        { ...state, readPending: false, observationIssue, integrityFailed };
    }
    case 'begin': {
      if (workflowNativeStartReason(state) || !state.status || action.binding.windowGeneration !== state.status.windowGeneration ||
          action.binding.startStatusRevision !== state.status.statusRevision ||
          ![action.binding.draftRevision, action.binding.baselineGeneration, action.binding.serviceGeneration, action.binding.selectionGeneration, action.binding.coordinateGeneration].every((counter) => isU32(counter) && counter < U32_MAX)) return state;
      return { ...state, attempt: { binding: action.binding, sessionId: null, projection: null, projectionRevision: state.status.statusRevision,
        prepareClaimed: false, applyClaimed: false, submittedPlanToken: null, closeRequested: false, closeClaimed: false, invalidated: false, handled: false } };
    }
    case 'prepare-claim': {
      const attempt = state.attempt;
      if (!attempt || attempt.sessionId !== action.sessionId || attempt.prepareClaimed || attempt.applyClaimed || attempt.closeRequested || attempt.invalidated ||
          attempt.projection?.phase !== 'editing' || !attempt.projection.checkout || !usable(state)) return state;
      return { ...state, attempt: { ...attempt, prepareClaimed: true } };
    }
    case 'apply-claim': {
      const binding = currentWorkflowApplyBinding(state);
      if (!binding || !sameWorkflowApplyBinding(binding, action.binding) || !state.attempt) return state;
      return { ...state, attempt: { ...state.attempt, applyClaimed: true, submittedPlanToken: action.binding.planToken } };
    }
    case 'close-request': {
      const attempt = state.attempt;
      if (!attempt || attempt.handled || workflowAttemptSettled(attempt) || attempt.closeRequested || attempt.applyClaimed && action.reason !== 'user') return state;
      return { ...state, attempt: { ...attempt, closeRequested: true, invalidated: attempt.invalidated || action.reason === 'context_changed' } };
    }
    case 'close-claim': {
      const attempt = state.attempt;
      if (!attempt || attempt.sessionId !== action.sessionId || !attempt.closeRequested || attempt.closeClaimed ||
          workflowAttemptSettled(attempt) || unknown(attempt.projection) || state.generationLost) return state;
      return { ...state, attempt: { ...attempt, closeClaimed: true } };
    }
    case 'handled': return state.attempt?.sessionId === action.sessionId ? { ...state, attempt: { ...state.attempt, handled: true } } : state;
  }
}

const availabilityCopy: Record<EditAvailability, string> = {
  available: 'Native local workflow review is available. No file change happens without a new plan and explicit confirmation.',
  unsupported_platform: 'Local workflow writes are unavailable on this platform. This slice requires the separately qualified Linux native backend; Windows writes are not supported.',
  runtime_unqualified: 'This build has no qualified local-workflow writer. Its distinct production gate remains disabled; configuration saving or a passive preview cannot enable it.',
  cleanup_unknown: 'Native ownership or cleanup is unverified. No new edit or repeated Apply is allowed; retain the original operation and recovery evidence.',
  shutdown: 'The native application is stopping. No local workflow edit can be opened.',
  other_edit_active: 'A configuration edit owns the shared native edit service. Finish or close that original session before reviewing workflow files.',
};
export function workflowNativeStartReason(state: GitHubWorkflowEditState): string | null {
  if (state.mode === 'preview') return 'Browser preview cannot observe workflow files, issue an Apply token or simulate successful installation.';
  if (state.mode !== 'native') return 'Local workflow review requires the native desktop bridge.';
  if (state.integrityFailed) return 'Native workflow status failed its closed contract. Observe the original owner; no new edit is allowed.';
  if (state.generationLost) return 'This native document generation changed. Original review authority cannot be reattached.';
  if (state.nativeBlocked) return availabilityCopy.cleanup_unknown;
  if (state.observationIssue) return 'Native workflow confirmation is unavailable. Check the original status; do not open a replacement session.';
  if (!state.listening || !state.initialized || !state.status) return 'Loading the separate local-workflow capability and original-owner status…';
  if (!state.status.capability.available) return availabilityCopy[state.status.capability.reason];
  if (state.status.statusRevision === U32_MAX) return 'The native status counter is exhausted. A new edit cannot reuse or wrap that sequence.';
  if (state.status.active || !workflowAttemptSettled(state.attempt) || state.attempt && !state.attempt.handled) return 'The original workflow edit is still active or awaiting settlement. Finish or close that owner before starting a new review.';
  return null;
}
export function workflowStartReason(state: GitHubWorkflowEditState, session: ProjectSession | null, setup: GitHubSetupState, otherEditReason: string | null = null): string | null {
  const native = workflowNativeStartReason(state);
  if (native) return native;
  if (otherEditReason) return otherEditReason;
  if (setup.mode !== 'native') return 'The current service/runtime context is unavailable. Reload it before opening a native workflow review.';
  if (session?.saveRecoveryRequired || session && state.recoveryProjects.some((item) => item.projectId === session.project.id)) return 'This project needs separate transaction recovery. This screen cannot reset a journal, resume persisted recovery or bypass the block.';
  if (!session?.draft) return 'Choose a project and prepare an in-memory configuration draft. Saving it to disk is not required for local workflow review.';
  if (setup.project?.projectId !== session.project.id || setup.project.draftRevision !== session.revision || setup.project.baselineGeneration !== session.baselineGeneration || !setup.project.hasDraft) return 'The selected draft context is changing. Wait for its synchronous binding before opening a native review.';
  if (![session.revision, session.baselineGeneration, setup.serviceGeneration, setup.selectionGeneration, setup.coordinateGeneration].every((counter) => isU32(counter) && counter < U32_MAX)) return 'An in-memory binding counter is exhausted. No review or generation will be reused.';
  if (!setup.inputs.toolingRepository || !setup.inputs.toolingSha) return 'Enter the toolkit repository and full toolkit commit above. The native core validates both; there is no default pin.';
  if (!githubSetupRequestFits({ draft: session.draft, toolingRepository: setup.inputs.toolingRepository, toolingSha: setup.inputs.toolingSha, suppliedSnapshot: null })) return 'The draft or toolkit inputs exceed the bounded JSON/text contract. No values were truncated or submitted.';
  return null;
}
export function workflowContextMatches(binding: WorkflowDraftBinding, session: ProjectSession | null, setup: GitHubSetupState): boolean {
  return setup.mode === 'native' && session !== null && session.project.id === binding.projectId && session.draft !== null &&
    session.revision === binding.draftRevision && session.baselineGeneration === binding.baselineGeneration &&
    sameJson(session.draft, binding.draft) && sameJson(session.baseline, binding.baseline) &&
    setup.serviceGeneration === binding.serviceGeneration && setup.selectionGeneration === binding.selectionGeneration && setup.coordinateGeneration === binding.coordinateGeneration &&
    setup.inputs.toolingRepository === binding.toolingRepository && setup.inputs.toolingSha === binding.toolingSha;
}
export function workflowPreparedMatches(attempt: WorkflowAttempt): boolean {
  const owner = attempt.projection; const plan = owner?.prepared;
  return Boolean(owner?.checkout && plan && owner.domain === 'github_workflows' && owner.projectId === attempt.binding.projectId &&
    owner.ownerGeneration === attempt.binding.windowGeneration && owner.sessionId === attempt.sessionId && plan.revision === owner.checkout.revision &&
    plan.draftRevision === attempt.binding.draftRevision && plan.baselineGeneration === attempt.binding.baselineGeneration &&
    plan.view.tooling.repository === attempt.binding.toolingRepository && plan.view.tooling.sha === attempt.binding.toolingSha.toLowerCase());
}
export function currentWorkflowApplyBinding(state: GitHubWorkflowEditState): WorkflowApplyBinding | null {
  const attempt = state.attempt; const owner = attempt?.projection;
  if (!usable(state) || !attempt || !owner?.prepared || !attempt.prepareClaimed || attempt.applyClaimed || attempt.closeRequested || attempt.invalidated || attempt.handled ||
      owner.phase !== 'reviewing' || owner.nativeReason !== 'none' || owner.nativeFinality !== 'pending' || owner.reviewRemainingMs === 0 || owner.applySubmitted || owner.conflict ||
      !workflowPreparedMatches(attempt) || state.status?.active?.sessionId !== owner.sessionId || owner.ownerGeneration !== state.status.windowGeneration) return null;
  return { sessionId: owner.sessionId, planToken: owner.prepared.planToken, draftRevision: attempt.binding.draftRevision, baselineGeneration: attempt.binding.baselineGeneration };
}
export function sameWorkflowApplyBinding(first: WorkflowApplyBinding, next: WorkflowApplyBinding): boolean {
  return first.sessionId === next.sessionId && first.planToken === next.planToken && first.draftRevision === next.draftRevision && first.baselineGeneration === next.baselineGeneration;
}
export function canApplyWorkflows(state: GitHubWorkflowEditState, session: ProjectSession | null, setup: GitHubSetupState, confirmation?: WorkflowApplyBinding): boolean {
  const current = currentWorkflowApplyBinding(state);
  return current !== null && state.attempt !== null && workflowContextMatches(state.attempt.binding, session, setup) && (!confirmation || sameWorkflowApplyBinding(current, confirmation));
}
export function confirmedWorkflowResult(state: GitHubWorkflowEditState): 'installed' | 'unchanged' | null {
  const attempt = state.attempt;
  if (!attempt?.projection || !attempt.applyClaimed || state.integrityFailed || state.observationIssue || !workflowPreparedMatches(attempt) ||
      attempt.submittedPlanToken === null || attempt.submittedPlanToken !== attempt.projection.prepared?.planToken) return null;
  // Observation of this submitted outcome remains meaningful after selection,
  // draft, runtime or document changes. It never marks any configuration saved.
  return normalWorkflowResult(attempt.projection);
}
export function workflowOwnerReason(state: GitHubWorkflowEditState, projectId: string): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost || state.observationIssue) return 'Workflow edit ownership is unverified. Observe the original native status; do not open a competing configuration edit.';
  if (state.status?.active || !workflowAttemptSettled(state.attempt) || state.attempt && !state.attempt.handled) return 'A local workflow edit is still owned or awaiting settlement. Finish or close that original session before preparing a configuration save.';
  if (state.recoveryProjects.some((item) => item.projectId === projectId)) return 'This project needs separate workflow transaction recovery. A configuration edit cannot clear its journal or bypass the block.';
  return null;
}
export function workflowRetainsDraft(state: GitHubWorkflowEditState, projectId: string): boolean {
  return state.attempt?.binding.projectId === projectId && (!workflowAttemptSettled(state.attempt) || state.integrityFailed || state.nativeBlocked || state.observationIssue !== null) ||
    state.status?.active?.projectId === projectId || state.unknownEvidence?.projectId === projectId;
}
export function workflowNoOp(view: WorkflowPreparedView): boolean { return view.files.every((file) => file.action === 'preserve'); }

// Full display-only diff: prefix the already prepared text, never regenerate
// payloads, parse YAML, compute file digests or manufacture before-file content.
export function workflowDisplayDiff(file: WorkflowPreparedFile): string {
  const content = file.generated.content;
  const newline = content.endsWith('\n');
  const lines = (newline ? content.slice(0, -1) : content).split('\n');
  const create = file.action === 'create';
  return `--- ${create ? '/dev/null' : file.path}\n+++ ${file.path}\n@@ ${create ? '-0,0' : `-1,${lines.length}`} +1,${lines.length} @@\n` +
    lines.map((line) => `${create ? '+' : ' '}${line}`).join('\n') + '\n' + (newline ? '' : '\\ No newline at end of file\n');
}

export const workflowApplyHelp: HelpContent = {
  label: 'Review and apply local workflow callers', requiredness: 'optional',
  requiredWhen: 'Only to install these four local caller files, with the distinct qualified native workflow capability. No browser preview, configuration-save qualification or remote GitHub permission can enable it.',
  what: 'Freshly observe four fixed workflow destinations, generate once from the current draft and toolkit pin, review their complete text, then explicitly confirm the whole native plan.',
  why: 'Create only absent files or preserve exact existing bytes. One differing, unsafe or changed file refuses the entire bundle instead of overwriting user edits or treating a reported digest as authority.',
  where: 'Select the native-registered project, enter the toolkit repository/full commit above, then choose Review local workflow files. Passive comparison assertions are ignored by native review.',
  format: 'Exactly mobile-preflight.yml, mobile-candidate.yml, mobile-external-testing.yml and mobile-production-submit.yml under .github/workflows. Only absent .github/workflows ancestors may also be created. New files request 0644 subject to inherited umask; new directories use 0755. Preserved files/directories are not rewritten or chmodded. The native absolute review lifetime is at most 15 minutes and cannot be renewed.',
  failure: 'Conflicts have no Apply token. Changing selection, draft/baseline, pin, service/runtime or document retires a pre-Apply review. After submission, check only that original owner; cancellation may be too late. Recovery-required or unknown status retains evidence and blocks further edits. No force, overwrite, journal reset or automatic retry is offered. This never saves configuration, provisions secrets, commits, contacts GitHub, dispatches a workflow or establishes release readiness.',
};
export interface WorkflowNotice { title: string; detail: string; tone: Tone; code?: string }
const coreCopy: Record<CoreEditReason, string> = {
  none: '', invalid_params: 'The request did not fit the fixed bounded contract; nothing was truncated or coerced.',
  invalid_config: 'The draft failed core format/policy validation. Review Project settings; no rejected values or invented plan are shown.',
  ignore_conflict: 'A foreign configuration reason cannot authorize a workflow edit.',
  stale_revision: 'An original root, ancestor, file or absence binding changed. Reconcile outside this attempt, then explicitly review afresh only after settlement.',
  pending_state: 'Pre-existing transaction state requires separate attention. This operation does not reset or delete its journal.',
  busy: 'Another owner is using the project. Observe settlement; there is no automatic retry.',
  cancelled: 'Cancellation was observed; the transaction facts, not the request, determine what happened.',
  filesystem_error: 'A filesystem operation did not finish normally. Retain evidence and follow the effect/journal/resource facts; do not repeat Apply.',
  custody_unknown: 'Original resource custody or cleanup is unverified. Further edits remain disabled.',
  unsupported_platform: 'This platform has no qualified workflow transaction backend.',
};
const nativeCopy: Record<NativeEditReason, string> = {
  none: '', discarded: 'The native review ended. The in-memory configuration draft was kept.',
  cancelled: 'Cancellation was requested; this is not evidence of rollback.',
  active_timeout: 'The native operation deadline elapsed. Original cleanup and finality must still be observed.',
  review_expired: 'The nonrenewable native review lifetime expired. A new review requires original settlement first.',
  caller_lost: 'The request observer was lost. Its original native owner still owns settlement.',
  window_lost: 'The original native document was lost. Its authority cannot be reattached.',
  shutdown: 'The native application is stopping; original owners must settle.',
  runtime_unavailable: 'A qualified workflow runtime could not be admitted. No ambient runtime or mock is substituted.',
  spawn_failed: 'The native child could not start normally. Original acquisition and cleanup still govern finality.',
  protocol_error: 'Native communication failed its contract. A missing receipt does not prove that nothing changed.',
  io_error: 'Native communication failed. Observe the original operation; do not resend Apply.',
  output_limit: 'The bounded native output limit was exceeded. Nothing was truncated into a successful result.',
  cleanup_unknown: 'Native settlement is unverified. Further edits remain disabled.',
};
export function workflowProjectionNotice(owner: GitHubWorkflowEditProjection): WorkflowNotice {
  const core = owner.coreOutcome;
  const code = core && core.reason !== 'none' ? core.reason : owner.nativeReason !== 'none' ? owner.nativeReason : undefined;
  const reason = core && core.reason !== 'none' ? coreCopy[core.reason] : nativeCopy[owner.nativeReason];
  if (unknown(owner)) return { title: core?.effect === 'committed' ? 'Workflow changes committed; completion unverified' : 'Workflow outcome or cleanup is unverified', tone: 'danger', code,
    detail: `${core?.effect === 'committed' ? 'Original commit evidence is retained, but installation did not finish normally.' : owner.applySubmitted ? 'This operation may have committed.' : 'No Apply is recorded, but native cleanup is unverified.'} Do not repeat Apply, clear the journal or retry recovery. ${owner.lateSettled ? 'Late settlement does not clear the earlier uncertainty. ' : ''}${reason}` };
  const result = normalWorkflowResult(owner);
  if (result) return { title: result === 'installed' ? 'Reviewed local workflow bundle installed' : 'Four callers verified unchanged', tone: 'info',
    detail: result === 'installed' ? 'The original native owner confirmed commit, clean journal cleanup and full settlement. Exact-preserved files were not rewritten. Configuration was not saved; GitHub was not contacted and release readiness is unknown.' : 'The native owner rechecked all four exact originals, confirmed no journal was created and fully settled. Original bytes and file identity were preserved. Configuration was not saved; remote state remains unknown.' };
  if (owner.phase === 'final') {
    if (core?.journal === 'recovery_required') return { title: core.effect === 'committed' ? 'Workflows committed; recovery attention required' : 'Workflow transaction needs recovery attention', tone: 'danger', code,
      detail: `Retain the journal and original operation evidence. Only the original in-session recovery attempt was available; persisted recovery is not implemented here. Do not reset or delete controls, repeat Apply or assume rollback. ${reason}` };
    if (core?.effect === 'committed') return { title: 'Workflows committed; installation did not finish normally', tone: 'danger', code, detail: `Do not Apply again. The original commit is retained, but interruption or cleanup needs attention. ${reason}` };
    if (core?.effect === 'rolled_back' && core.journal === 'clean' && core.resources === 'settled') return { title: 'Not installed; original transaction changes rolled back', tone: 'warning', code, detail: `The native owner confirmed clean rollback of this operation’s own effects, not unrelated state. Your configuration draft is unchanged. ${reason}` };
    if (owner.conflict) return { title: 'Local workflow bundle refused', tone: 'warning', code: owner.conflict.reason,
      detail: 'At least one existing caller differs. No Apply token was issued and this operation performed no installation. Existing YAML is not exposed or overwritten. Resolve differences separately, then explicitly request a fresh review after settlement.' };
    return { title: 'Workflow review ended; configuration draft kept', tone: 'warning', code, detail: `${core?.effect === 'not_started' ? 'This operation did not start installation. ' : 'No successful installation is confirmed. '}${reason}` };
  }
  if (owner.conflict) return { title: 'Existing callers differ; settling the refused review…', tone: 'warning', code: owner.conflict.reason, detail: 'There is no Apply token or partial-bundle option. Wait for original native settlement; no success or completed cleanup is claimed yet.' };
  if (owner.phase === 'reviewing') return { title: 'Review the fresh native workflow plan', tone: 'info', detail: 'No Apply has been submitted for this plan. Inspect all four paths and complete generated text; confirm the whole bundle or close this review and keep the draft.' };
  if (owner.phase === 'applying') return { title: 'Applying the submitted workflow review…', tone: 'info', detail: 'Admission is not installation success. The original transaction and native owner must settle. Newer selections, drafts and toolkit inputs will be kept.' };
  if (owner.phase === 'finalizing') return { title: 'Waiting for original workflow settlement…', tone: 'warning', code, detail: `${owner.applySubmitted ? 'Apply was submitted. Cancellation may be too late to prevent commit; no rollback is assumed.' : 'No Apply is recorded. Closing this review does not delete the draft.'} ${reason}` };
  return { title: owner.phase === 'opening' ? 'Capturing original workflow files…' : 'Preparing the native workflow review…', tone: 'info', detail: 'The original registered project and four fixed files are being observed and checked. Capture and preparation do not stage, create directories or write files.' };
}
export function workflowEditNotice(state: GitHubWorkflowEditState): WorkflowNotice | null {
  const attempt = state.attempt;
  const owner = attempt?.projection ?? state.unknownEvidence ?? state.status?.active ?? state.status?.lastTerminal;
  if (state.integrityFailed) return { title: 'Native workflow status violated its contract', tone: 'danger', detail: `${owner?.coreOutcome?.effect === 'committed' ? 'Original commit evidence is retained. ' : ''}No malformed or contradictory reply proves successful installation or rollback. Keep the draft and original evidence; do not repeat Apply.` };
  if (state.observationIssue && owner?.phase !== 'final') return { title: 'Native workflow confirmation is unavailable', tone: 'warning', detail: 'The original operation and in-memory draft are retained. Check status; a missing reply is not permission to resend Apply, Prepare or Open.' };
  if (state.generationLost && !attempt?.applyClaimed) return { title: 'Native document authority changed', tone: 'warning', detail: 'This renderer cannot reattach the earlier workflow edit. Only read-only observation of its original settlement remains possible.' };
  if (attempt?.invalidated && !workflowAttemptSettled(attempt)) return { title: 'Earlier workflow review invalidated', tone: 'warning', detail: 'The selection, draft/baseline, toolkit pin, service/runtime or document changed before Apply. The original review is being retired. No late reply can restore it; your draft is kept.' };
  if (attempt?.closeRequested && !workflowAttemptSettled(attempt)) return { title: attempt.applyClaimed ? 'Cancellation requested; workflow outcome still pending' : 'Closing native workflow review; draft kept', tone: 'warning', detail: attempt.applyClaimed ? 'Cancellation may be too late. Observe the original effect and settlement; do not assume rollback or repeat Apply.' : 'The original owner is being stopped, not replaced. No completed cleanup is claimed until native settlement.' };
  if (attempt?.applyClaimed && owner?.phase === 'reviewing') return { title: 'Apply requested once; awaiting native confirmation', tone: 'info', detail: 'The submitted token has been consumed locally. A delayed or missing reply never authorizes another Apply.' };
  if (owner) return workflowProjectionNotice(owner);
  if (state.nativeBlocked) return { title: 'Native cleanup needs attention', tone: 'danger', detail: availabilityCopy.cleanup_unknown };
  return attempt ? { title: 'Waiting for original workflow admission…', tone: 'info', detail: 'No successful registration or file change is assumed. A requested close will follow the original session ID when observed; no replacement owner is opened.' } : null;
}
