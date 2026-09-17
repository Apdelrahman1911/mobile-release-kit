// Pure application-wide edit state. Native status is observation/authority;
// drafts and this controller never manufacture a filesystem revision or save.
import { sameJson } from './catalog.ts';
import { editInputFits, isU32, normalEditResult, projectionProgress, statusProgress, U32_MAX } from './configEditProtocol.ts';
import type { ProjectSession } from './drafts.ts';
import type { Tone } from './certainty.ts';
import type { BridgeMode, Catalog, ConfigEditProjection, ConfigEditStatus, CoreEditReason, EditAvailability, HelpContent, JsonObject, NativeEditReason, PreparedConfigView } from './types.ts';

export interface EditDraftBinding {
  projectId: string;
  windowGeneration: string;
  startStatusRevision: number;
  previousTerminalId: string | null;
  draftRevision: number;
  baselineGeneration: number;
  expectedBase: JsonObject | null;
  draft: JsonObject;
}

export interface EditApplyBinding {
  sessionId: string;
  planToken: string;
  draftRevision: number;
  baselineGeneration: number;
}

export interface EditAttempt {
  binding: EditDraftBinding;
  sessionId: string | null;
  projection: ConfigEditProjection | null;
  projectionRevision: number;
  prepareClaimed: boolean;
  applyClaimed: boolean;
  submittedPlanToken: string | null;
  closeRequested: boolean;
  closeClaimed: boolean;
  invalidated: 'draft_changed' | 'baseline_mismatch' | null;
  handled: boolean;
}

// Negative project attention only. Retain no checkout, draft or prepared view
// history, and never turn an observed foreign/old owner's result into a save.
export type ConfigRecoveryAttention = Pick<ConfigEditProjection,
  'projectId' | 'sessionId' | 'ownerGeneration' | 'phase' | 'nativeFinality' | 'coreOutcome'>;

export interface ConfigEditState {
  mode: BridgeMode;
  listening: boolean;
  initialized: boolean;
  readPending: boolean;
  status: ConfigEditStatus | null;
  buffered: ConfigEditStatus | null;
  observationIssue: 'bridge' | 'protocol' | null;
  integrityFailed: boolean;
  generationLost: boolean;
  nativeBlocked: boolean;
  unknownEvidence: ConfigEditProjection | null;
  recoveryProjects: readonly ConfigRecoveryAttention[];
  attempt: EditAttempt | null;
}

export const initialConfigEdit: ConfigEditState = {
  mode: 'unavailable', listening: false, initialized: false, readPending: false,
  status: null, buffered: null, observationIssue: null, integrityFailed: false,
  generationLost: false, nativeBlocked: false, unknownEvidence: null, recoveryProjects: [], attempt: null,
};

export type ConfigEditAction =
  | { type: 'connect'; mode: BridgeMode }
  | { type: 'listening' }
  | { type: 'read-start' }
  | { type: 'observe'; status: ConfigEditStatus; source: 'read' | 'event' | 'reply' }
  | { type: 'observation-failed'; protocol?: boolean }
  | { type: 'begin'; binding: EditDraftBinding }
  | { type: 'prepare-claim'; sessionId: string }
  | { type: 'apply-claim'; binding: EditApplyBinding }
  | { type: 'close-request'; reason: 'user' | 'draft_changed' | 'baseline_mismatch' | 'invoke_failed' }
  | { type: 'close-claim'; sessionId: string }
  | { type: 'handled'; sessionId: string };

function isUnknown(projection: ConfigEditProjection | null): boolean {
  return projection?.phase === 'unknown' || projection?.nativeFinality === 'unknown';
}

function completedAttempt(attempt: EditAttempt | null): boolean {
  return attempt === null || (attempt.projection?.phase === 'final' && attempt.projection.nativeFinality === 'settled');
}

function minimumTimers(previous: ConfigEditStatus | null, incoming: ConfigEditStatus): ConfigEditStatus {
  if (!previous) return incoming;
  const clamp = (item: ConfigEditProjection | null): ConfigEditProjection | null => {
    if (!item) return null;
    const old = [previous.active, previous.lastTerminal].find((entry) => entry?.sessionId === item.sessionId);
    return old ? { ...item, reviewRemainingMs: Math.min(old.reviewRemainingMs, item.reviewRemainingMs) } : item;
  };
  return { ...incoming, active: clamp(incoming.active), lastTerminal: clamp(incoming.lastTerminal) };
}

function retainRecoveryAttention(state: ConfigEditState, status: ConfigEditStatus): ConfigEditState {
  for (const projection of [status.active, status.lastTerminal]) {
    if (projection?.phase !== 'final' || projection.nativeFinality !== 'settled' ||
        projection.coreOutcome?.journal !== 'recovery_required' || projection.coreOutcome.resources !== 'settled' ||
        state.recoveryProjects.some((item) => item.projectId === projection.projectId)) continue;
    // Matches the native picker/blocked-project registry's 64-project bound.
    // Do not evict earlier negative evidence to make a project startable again.
    if (state.recoveryProjects.length >= 64) return { ...state, integrityFailed: true, observationIssue: 'protocol' };
    const { projectId, sessionId, ownerGeneration, phase, nativeFinality, coreOutcome } = projection;
    state = { ...state, recoveryProjects: [...state.recoveryProjects, { projectId, sessionId, ownerGeneration, phase, nativeFinality, coreOutcome }] };
  }
  return state;
}

function observe(state: ConfigEditState, status: ConfigEditStatus, source: 'read' | 'event' | 'reply'): ConfigEditState {
  // Also remember initial/read-only/older observations before lastTerminal is
  // replaced. This is a bounded refusal latch, never current edit authority.
  state = retainRecoveryAttention(state, status);
  const readPending = source === 'read' ? false : state.readPending;
  // Events cannot choose this renderer's native generation before its initial
  // registry read. Keep at most one bounded projection while that read is pending.
  if (!state.initialized && source !== 'read') {
    const unknown = [status.active, status.lastTerminal].find((item) => isUnknown(item)) ?? null;
    const retained = { ...state, readPending,
      nativeBlocked: state.nativeBlocked || unknown !== null || status.capability.reason === 'cleanup_unknown',
      unknownEvidence: state.unknownEvidence ?? unknown,
    };
    return !state.buffered || status.statusRevision >= state.buffered.statusRevision
      ? { ...retained, buffered: status }
      : retained;
  }
  if (!state.initialized && state.buffered?.windowGeneration === status.windowGeneration) {
    const first = state.buffered.statusRevision <= status.statusRevision ? state.buffered : status;
    const next = first === status ? state.buffered : status;
    if (!statusProgress(first, next)) return { ...state, readPending, integrityFailed: true, observationIssue: 'protocol' };
    if (state.buffered.statusRevision > status.statusRevision) status = state.buffered;
    status = minimumTimers(first, status);
  }
  if (state.status && status.windowGeneration !== state.status.windowGeneration) {
    // Actual native document/window replacement revokes the old authority.
    // Never automatically adopt its new generation inside an old controller.
    return { ...state, readPending, generationLost: true };
  }
  if (state.status && status.statusRevision < state.status.statusRevision) {
    // A stale delivery grants no authority, but an earlier native Unknown is
    // still permanent evidence: dropping it must not clear a global latch.
    const unknown = [status.active, status.lastTerminal].find((item) => isUnknown(item)) ?? null;
    const contradictory = !statusProgress(status, state.status);
    return { ...state, readPending,
      nativeBlocked: state.nativeBlocked || unknown !== null || status.capability.reason === 'cleanup_unknown',
      unknownEvidence: state.unknownEvidence ?? unknown,
      integrityFailed: state.integrityFailed || contradictory,
      observationIssue: contradictory ? 'protocol' : state.observationIssue,
    };
  }
  if (state.status && !statusProgress(state.status, status)) {
    return { ...state, readPending, integrityFailed: true, observationIssue: 'protocol' };
  }
  status = minimumTimers(state.status, status);
  let attempt = state.attempt;
  if (attempt) {
    const retained = attempt;
    const owner = [status.active, status.lastTerminal].find((item) => item !== null &&
      item.ownerGeneration === retained.binding.windowGeneration && item.projectId === retained.binding.projectId &&
      (retained.sessionId !== null ? item.sessionId === retained.sessionId :
        status.statusRevision > retained.binding.startStatusRevision && item.sessionId !== retained.binding.previousTerminalId));
    if (owner) {
      if (attempt.projection && !projectionProgress(attempt.projection, owner)) {
        return { ...state, readPending, integrityFailed: true, observationIssue: 'protocol' };
      }
      const projection = attempt.projection ? { ...owner, reviewRemainingMs: Math.min(attempt.projection.reviewRemainingMs, owner.reviewRemainingMs) } : owner;
      attempt = { ...attempt, sessionId: owner.sessionId, projection, projectionRevision: status.statusRevision };
    }
  }
  const unknown = [status.active, status.lastTerminal].find((item) => isUnknown(item)) ?? null;
  return {
    ...state, initialized: true, readPending, status, buffered: null, attempt,
    observationIssue: state.integrityFailed ? 'protocol' : null,
    nativeBlocked: state.nativeBlocked || unknown !== null || status.capability.reason === 'cleanup_unknown',
    unknownEvidence: state.unknownEvidence && unknown?.sessionId !== state.unknownEvidence.sessionId ? state.unknownEvidence : unknown ?? state.unknownEvidence,
  };
}

export function configEditReducer(state: ConfigEditState, action: ConfigEditAction): ConfigEditState {
  switch (action.type) {
    case 'connect': return { ...state, mode: action.mode };
    case 'listening': return { ...state, listening: true };
    case 'read-start': return { ...state, readPending: true };
    case 'observe': return observe(state, action.status, action.source);
    case 'observation-failed': return {
      ...state, readPending: false, observationIssue: action.protocol || state.integrityFailed ? 'protocol' : 'bridge',
      integrityFailed: state.integrityFailed || Boolean(action.protocol),
    };
    case 'begin': {
      if (nativeStartReason(state) !== null || !state.status || action.binding.windowGeneration !== state.status.windowGeneration ||
          action.binding.startStatusRevision !== state.status.statusRevision ||
          !isU32(action.binding.draftRevision) || action.binding.draftRevision === U32_MAX ||
          !isU32(action.binding.baselineGeneration) || action.binding.baselineGeneration === U32_MAX) return state;
      return { ...state, attempt: {
        binding: action.binding, sessionId: null, projection: null, projectionRevision: state.status.statusRevision,
        prepareClaimed: false, applyClaimed: false, submittedPlanToken: null, closeRequested: false, closeClaimed: false, invalidated: null, handled: false,
      } };
    }
    case 'prepare-claim': {
      const attempt = state.attempt;
      if (!attempt || attempt.sessionId !== action.sessionId || attempt.prepareClaimed || attempt.applyClaimed ||
          attempt.closeRequested || attempt.invalidated || attempt.projection?.phase !== 'editing' ||
          !attempt.projection.checkout || !observationUsable(state)) return state;
      return { ...state, attempt: { ...attempt, prepareClaimed: true } };
    }
    case 'apply-claim': {
      const binding = currentApplyBinding(state);
      if (!binding || !sameApplyBinding(binding, action.binding) || !state.attempt) return state;
      return { ...state, attempt: { ...state.attempt, applyClaimed: true, submittedPlanToken: action.binding.planToken } };
    }
    case 'close-request': {
      const attempt = state.attempt;
      if (!attempt || attempt.handled || completedAttempt(attempt) || attempt.closeRequested ||
          (attempt.applyClaimed && action.reason !== 'user')) return state;
      return { ...state, attempt: { ...attempt, closeRequested: true,
        invalidated: action.reason === 'draft_changed' || action.reason === 'baseline_mismatch' ? action.reason : attempt.invalidated,
      } };
    }
    case 'close-claim': {
      const attempt = state.attempt;
      if (!attempt || attempt.sessionId !== action.sessionId || !attempt.closeRequested || attempt.closeClaimed ||
          completedAttempt(attempt) || isUnknown(attempt.projection) || state.generationLost) return state;
      return { ...state, attempt: { ...attempt, closeClaimed: true } };
    }
    case 'handled':
      return state.attempt?.sessionId === action.sessionId ? { ...state, attempt: { ...state.attempt, handled: true } } : state;
  }
}

function observationUsable(state: ConfigEditState): boolean {
  return state.mode === 'native' && state.listening && state.initialized && state.status?.capability.available === true &&
    !state.observationIssue && !state.integrityFailed && !state.generationLost && !state.nativeBlocked;
}

const availabilityCopy: Record<EditAvailability, string> = {
  available: 'Configuration-only saving is available through the native owner.',
  unsupported_platform: 'Configuration saving is not qualified on this platform. In-memory drafting and available pure checks still work.',
  runtime_unqualified: 'This build has no qualified native edit runtime. Drafting does not enable production saving.',
  cleanup_unknown: 'Native cleanup or an earlier outcome is unverified. Saving remains disabled; do not repeat Apply.',
  shutdown: 'The native application is stopping. No new save session can be opened.',
  other_edit_active: 'A local workflow edit owns the shared native edit service. Finish or close that original session before preparing a configuration save.',
};

export function nativeStartReason(state: ConfigEditState): string | null {
  if (state.mode === 'preview') return 'Browser preview cannot open a native save session or simulate saving.';
  if (state.mode !== 'native') return 'Saving requires the native desktop bridge.';
  if (state.integrityFailed) return 'Native save status did not match the reviewed contract. Saving is disabled; your draft is retained.';
  if (state.generationLost) return 'This native window generation changed. Earlier save authority cannot be reattached.';
  if (state.nativeBlocked) return availabilityCopy.cleanup_unknown;
  if (state.observationIssue) return 'Native confirmation is unavailable. Check the original session status; do not start a replacement save.';
  if (!state.listening || !state.initialized || !state.status) return 'Loading the native edit capability and owned-session status…';
  if (!state.status.capability.available) return availabilityCopy[state.status.capability.reason];
  if (state.status.statusRevision === U32_MAX) return 'The native status counter is exhausted. A new save session cannot reuse or wrap that sequence.';
  if (state.status.active) return 'A native save session is still active. Close or finish that original session before preparing another.';
  if (!completedAttempt(state.attempt)) return 'The original save session has not been confirmed settled. Check status; no replacement owner will be opened.';
  if (state.attempt && !state.attempt.handled) return 'Recording the original native result before another save session can be opened.';
  return null;
}

export function editStartReason(state: ConfigEditState, session: ProjectSession | null): string | null {
  const native = nativeStartReason(state);
  if (native) return native;
  if (session?.saveRecoveryRequired || (session && state.recoveryProjects.some((item) => item.projectId === session.project.id))) {
    return 'This project needs separate transaction/recovery attention. No new save review or GUI recovery is offered here. Other projects remain independently gated.';
  }
  if (!session?.draft) return 'Load or explicitly start a draft before preparing a save review.';
  if (!isU32(session.revision) || session.revision === U32_MAX || !isU32(session.baselineGeneration) || session.baselineGeneration === U32_MAX) return 'This in-memory revision counter is exhausted. No counter or save session will be reused.';
  if (!editInputFits(session.baseline, session.draft)) return 'The draft and retained baseline exceed the bounded JSON edit contract or contain unsupported JSON. Your values were not truncated.';
  // Deliberately no isDirty guard: only native preparation can establish a
  // whole-operation no-op, and a clean config can still need ignore additions.
  return null;
}

// Synchronous renderer exclusion before an opposite-domain Open reply/event.
// This is a refusal only; the shared native registry is still the real owner.
export function configurationOwnerReason(state: ConfigEditState, projectId: string): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost || state.observationIssue) {
    return 'Configuration edit ownership is unverified. Observe the original native status; do not open a competing workflow edit.';
  }
  if (state.status?.active || !completedAttempt(state.attempt) || (state.attempt && !state.attempt.handled)) {
    return 'A configuration edit is still owned or awaiting settlement. Finish or close that original session before reviewing workflow files.';
  }
  if (state.recoveryProjects.some((item) => item.projectId === projectId)) {
    return 'This project needs separate configuration transaction recovery. A workflow edit cannot clear its journal or bypass that block.';
  }
  return null;
}

export function draftMatches(binding: EditDraftBinding, session: ProjectSession | null): boolean {
  return session !== null && session.project.id === binding.projectId && session.draft !== null &&
    session.revision === binding.draftRevision && session.baselineGeneration === binding.baselineGeneration &&
    sameJson(session.baseline, binding.expectedBase) && sameJson(session.draft, binding.draft);
}

export function preparedMatches(attempt: EditAttempt): boolean {
  const owner = attempt.projection;
  const prepared = owner?.prepared;
  return Boolean(owner && prepared && owner.checkout && attempt.sessionId === owner.sessionId &&
    owner.ownerGeneration === attempt.binding.windowGeneration && owner.projectId === attempt.binding.projectId &&
    prepared.revision === owner.checkout.revision && prepared.draftRevision === attempt.binding.draftRevision &&
    prepared.baselineGeneration === attempt.binding.baselineGeneration && sameJson(owner.checkout.base, attempt.binding.expectedBase));
}

export function currentApplyBinding(state: ConfigEditState): EditApplyBinding | null {
  const attempt = state.attempt;
  const owner = attempt?.projection;
  if (!observationUsable(state) || !attempt || !owner || !owner.prepared || !attempt.prepareClaimed ||
      attempt.applyClaimed || attempt.closeRequested || attempt.invalidated || attempt.handled ||
      owner.phase !== 'reviewing' || owner.nativeReason !== 'none' || owner.nativeFinality !== 'pending' ||
      owner.reviewRemainingMs === 0 || owner.applySubmitted || !preparedMatches(attempt) ||
      state.status?.active?.sessionId !== owner.sessionId || owner.ownerGeneration !== state.status.windowGeneration) return null;
  return { sessionId: owner.sessionId, planToken: owner.prepared.planToken,
    draftRevision: attempt.binding.draftRevision, baselineGeneration: attempt.binding.baselineGeneration };
}

export function sameApplyBinding(first: EditApplyBinding, next: EditApplyBinding): boolean {
  return first.sessionId === next.sessionId && first.planToken === next.planToken &&
    first.draftRevision === next.draftRevision && first.baselineGeneration === next.baselineGeneration;
}

export function canApplyEdit(state: ConfigEditState, session: ProjectSession | null, confirmation?: EditApplyBinding): boolean {
  const current = currentApplyBinding(state);
  return current !== null && state.attempt !== null && draftMatches(state.attempt.binding, session) &&
    (!confirmation || sameApplyBinding(current, confirmation));
}

export function noOpPlan(view: PreparedConfigView): boolean {
  return view.files.every((file) => file.action === 'preserve');
}

export function nativeReviewPath(catalog: Catalog | null, path: string): { label: string; path: string | null } {
  if (path === '') return { label: 'Configuration document', path: null };
  const field = catalog?.fields.find((item) => item.path === path);
  if (field) return { label: field.label, path };
  if (catalog?.fields.some((item) => item.path.startsWith(`${path}.`))) return { label: 'Configuration section', path };
  return { label: 'Configuration structure · name omitted', path: null };
}

export const saveHelp: HelpContent = {
  label: 'Native configuration create / save', requiredness: 'optional',
  requiredWhen: 'Only when the native edit capability is explicitly available. Windows, browser preview and an unqualified production runtime remain unavailable.',
  what: 'Open one owned checkout, prepare one review, then explicitly apply or close it. Only release/mobile-release.json and required append-only root .gitignore additions are admitted.',
  why: 'Bind the intended draft to the original configuration, ignore rules and file identities instead of silently overwriting a newer file or treating a missing reply as success.',
  where: 'Use Prepare save review in this editor. Pure draft review is separate and never grants a save token. Closing the save review keeps the draft; Discard draft changes is a different, destructive in-memory action.',
  format: 'A real configuration change rewrites the whole JSON document using core formatting. An unchanged configuration keeps its original bytes and inode, but ignore additions may still require a write. A missing release directory may be created. The native 15-minute absolute review lifetime starts at registration and is never renewed by clicks or status reads.',
  failure: 'Stale, invalid, busy or pending state ends that attempt; keep the draft and reconcile explicitly after settlement. Cancellation can be too late. Saved requires original native finality, clean committed cleanup and no failure reason. Unknown completion disables saving; never repeat Apply. No force, GUI recovery, workflows, metadata files, assets, builds, credentials, Git or Store operation is included.',
};

export interface ConfirmedConfigSave {
  binding: EditDraftBinding;
  sessionId: string;
  planToken: string;
  statusRevision: number;
  projection: ConfigEditProjection;
  result: 'saved' | 'unchanged';
}

export function confirmedConfigSave(state: ConfigEditState): ConfirmedConfigSave | null {
  const attempt = state.attempt;
  if (!attempt?.sessionId || !attempt.projection || !attempt.applyClaimed || attempt.handled ||
      state.integrityFailed || state.generationLost || state.nativeBlocked || state.observationIssue || !preparedMatches(attempt) ||
      attempt.submittedPlanToken === null || attempt.projection.prepared?.planToken !== attempt.submittedPlanToken) return null;
  const result = normalEditResult(attempt.projection);
  return result ? { binding: attempt.binding, sessionId: attempt.sessionId, planToken: attempt.submittedPlanToken,
    statusRevision: attempt.projectionRevision, projection: attempt.projection, result } : null;
}

export function editRetainsDraft(state: ConfigEditState, projectId: string): boolean {
  if (state.attempt?.binding.projectId === projectId &&
      (!completedAttempt(state.attempt) || state.nativeBlocked || state.integrityFailed || state.observationIssue !== null)) return true;
  return state.status?.active?.projectId === projectId || state.unknownEvidence?.projectId === projectId;
}

const coreCopy: Record<CoreEditReason, string> = {
  none: '',
  invalid_params: 'The request did not fit the closed edit contract. Nothing was truncated or coerced.',
  invalid_config: 'Configuration format or policy needs correction. An invalid existing file is not permission to replace it; use the pure draft checks for guidance.',
  ignore_conflict: 'The required ignore rules cannot be added safely. Existing negations or ambiguous coverage need explicit attention outside this save flow; no rules are automatically rewritten.',
  stale_revision: 'Configuration, ignore rules or their file/ancestor identities changed. Even formatting-only changes can conflict. Keep your draft and explicitly reconcile a fresh observation after settlement.',
  pending_state: 'An existing transaction needs attention. This app will not recover it, clear its journal or save over it.',
  busy: 'Another owner is using the project. Wait for it to finish, then explicitly start a fresh review; there is no automatic retry.',
  cancelled: 'Cancellation was observed. The transaction facts below, not the cancellation request, determine what happened.',
  filesystem_error: 'A filesystem operation could not finish normally. Keep the draft and follow the reported effect and cleanup facts; do not guess or repeat Apply.',
  custody_unknown: 'Original resource ownership or cleanup could not be verified. Saving remains disabled.',
  unsupported_platform: 'This platform does not have a qualified configuration transaction backend.',
};
const nativeCopy: Record<NativeEditReason, string> = {
  none: '', discarded: 'The native save session ended; the in-memory draft was kept.',
  cancelled: 'Cancellation was requested; it is not proof that the operation was undone.',
  active_timeout: 'The native active-operation time limit was reached. Cleanup/finality must still be observed; the deadline is not restarted.',
  review_expired: 'The native review lifetime expired. Keep the draft and explicitly start fresh only after this owner settles.',
  caller_lost: 'The original request observer was lost. The native owner, not the reply channel, still owns settlement.',
  window_lost: 'The originating native window generation was lost. Its authority cannot be reattached.',
  shutdown: 'Native shutdown was confirmed. Original owners must settle before a graceful exit can be claimed.',
  runtime_unavailable: 'A qualified native edit runtime could not be admitted. No ambient Python or mock engine is substituted.',
  spawn_failed: 'The native edit engine could not be started normally. Its original acquisition/cleanup status still governs finality.',
  protocol_error: 'The native engine protocol failed. Missing or malformed output never proves rollback.',
  io_error: 'Native communication failed. Check only the original owner; do not resend Apply.',
  output_limit: 'The bounded native communication limit was exceeded. Output was not truncated into a successful result.',
  cleanup_unknown: 'Native resource settlement could not be verified. Saving remains disabled.',
};

export interface EditNotice { title: string; detail: string; tone: Tone; code?: string }

export function projectionNotice(owner: ConfigEditProjection): EditNotice {
  const core = owner.coreOutcome;
  const reason = core && core.reason !== 'none' ? coreCopy[core.reason] : nativeCopy[owner.nativeReason];
  const code = core && core.reason !== 'none' ? core.reason : owner.nativeReason !== 'none' ? owner.nativeReason : undefined;
  if (isUnknown(owner)) return {
    title: core?.effect === 'committed' ? 'Changes committed; completion is unverified' : 'Native save outcome or cleanup is unverified', tone: 'danger', code,
    detail: `${core?.effect === 'committed' ? 'Commit evidence is retained, but this is not a completed successful save.' : owner.applySubmitted ? 'The operation may have committed.' : 'No Apply was authorized by this session, but its cleanup is unverified.'} Saving is disabled. Do not repeat Apply or launch recovery from this app.${owner.lateSettled ? ' Late resource settlement does not clear the earlier uncertainty.' : ''}`,
  };
  const result = normalEditResult(owner);
  if (result === 'saved') return { title: 'Submitted configuration saved', detail: 'The native owner confirmed commit, clean cleanup and full settlement. This is not release readiness or verification of tools, files, credentials, Git or Store state.', tone: 'info' };
  if (result === 'unchanged') return { title: 'No changes needed', detail: 'The native owner rechecked the whole operation and confirmed unchanged files with no transaction journal and full settlement. Original bytes and file identity were preserved.', tone: 'info' };
  if (owner.phase === 'final') {
    if (core?.effect === 'committed') return { title: 'Changes committed; the save did not finish normally', detail: `Do not Apply again. Cleanup, recovery or interruption needs attention; this is not an ordinary retryable save error. ${reason}`, tone: 'danger', code };
    if (core?.effect === 'rolled_back' && core.journal === 'clean' && core.resources === 'settled') return { title: 'Not saved; originals restored by this operation', detail: `Your draft and comparison baseline were kept. ${reason}`, tone: 'warning', code };
    return { title: 'Save session ended; draft retained', detail: `${core?.effect === 'not_started' ? 'This operation did not start applying the configuration. ' : 'No successful save is confirmed. '}${reason} Pre-existing pending state was not silently cleared.`, tone: 'warning', code };
  }
  if (owner.phase === 'reviewing') return { title: 'Review the native save plan', detail: 'Nothing has been applied. Confirm the two destinations before Apply, or close this session and keep the draft.', tone: 'info' };
  if (owner.phase === 'applying') return { title: 'Applying the submitted review…', detail: 'Admission is not a successful save. The native owner must confirm the transaction and settle all original resources. Newer in-memory edits will be kept.', tone: 'info' };
  if (owner.phase === 'finalizing') return { title: 'Waiting for original native settlement…', detail: `${owner.applySubmitted ? 'Apply was submitted. Cancellation may be too late to prevent a commit; no save or rollback is confirmed yet.' : 'No Apply was submitted by this session. Closing it does not erase the draft.'} ${reason}`, tone: 'warning', code };
  return { title: owner.phase === 'opening' ? 'Opening a native save session…' : owner.phase === 'preparing' ? 'Preparing the native save review…' : 'Checking the retained baseline…',
    detail: 'This phase captures or checks the original configuration and ignore state without staging or writing files. Your existing draft and baseline are retained.', tone: 'info' };
}

export function editNotice(state: ConfigEditState): EditNotice | null {
  if (state.integrityFailed) return { title: 'Native status did not match the reviewed contract', detail: 'Saving is disabled. Keep your draft, check the original native status and do not repeat Apply. No malformed reply is treated as success or rollback.', tone: 'danger' };
  if (state.generationLost) return { title: 'Native window authority changed', detail: 'The earlier session cannot be reattached to this renderer. Keep the draft where available; only original native settlement can resolve its status.', tone: 'danger' };
  if (state.nativeBlocked) return state.unknownEvidence ? projectionNotice(state.unknownEvidence) : { title: 'Native cleanup needs attention', detail: availabilityCopy.cleanup_unknown, tone: 'danger' };
  if (state.observationIssue) return { title: 'Native confirmation is unavailable', detail: 'Your draft is retained. Check the original registry status; a missing reply is not a save, discard or rollback. No Apply or new save session is retried automatically.', tone: 'warning' };
  const attempt = state.attempt;
  if (attempt?.invalidated && !completedAttempt(attempt)) return {
    title: attempt.invalidated === 'baseline_mismatch' ? 'The owned checkout differs from your retained baseline' : 'Draft changed; the earlier save review is invalid',
    detail: 'The original save session is being closed. Your draft, baseline and undo copies were kept. Nothing is rebased or reprepared automatically; wait for settlement before explicitly starting fresh.', tone: 'warning',
  };
  if (attempt?.closeRequested && !attempt.projection) return { title: 'Close requested; waiting for the original session ID', detail: 'The registered native owner will be closed when its status is observed. Your draft is retained; a replacement owner will not be opened.', tone: 'warning' };
  if (attempt?.closeRequested && !completedAttempt(attempt)) return {
    title: attempt.applyClaimed || attempt.projection?.applySubmitted ? 'Cancellation requested; awaiting native settlement' : 'Closing the save session; draft retained',
    detail: attempt.applyClaimed || attempt.projection?.applySubmitted ? 'It may be too late to prevent this save. Do not assume rollback or repeat Apply; only the original native outcome can confirm what happened.' : 'Close retires this session’s authority, not your draft or undo copies. No completed discard is claimed until native settlement.', tone: 'warning',
  };
  if (attempt?.applyClaimed && attempt.projection?.phase === 'reviewing') return { title: 'Apply requested; awaiting native confirmation', detail: 'The displayed plan was submitted once. A delayed admission reply does not prove that no writes occurred, and is never permission to resend Apply.', tone: 'info' };
  const owner = attempt?.projection ?? state.status?.active ?? state.status?.lastTerminal;
  if (owner) return projectionNotice(owner);
  if (attempt) return { title: 'Waiting for native save admission…', detail: 'The original registration has not been observed yet. No files or successful save are assumed. You can request Close without losing the draft.', tone: 'info' };
  return null;
}
