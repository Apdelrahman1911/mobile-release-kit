// App-wide initialization review state. Drafts, passive previews and these renderer
// generations are never filesystem revisions or native write authority.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { githubSetupRequestFits } from './githubSetupProtocol.ts';
import { normalInitializationRecovery, normalInitializationResult, initializationProjectionProgress, initializationStatusProgress } from './projectInitializationProtocol.ts';
import type { ProjectSession } from './drafts.ts';
import type { GitHubSetupState } from './githubSetupController.ts';
import type { BridgeMode, EditAvailability, JsonObject } from './types.ts';
import type { ProjectInitializationProjection, ProjectInitializationStatus, InitializationView, InitializationRecoveryView } from './projectInitializationTypes.ts';

// Display only: these persisted facts describe the inspected journal, not the
// current draft or permission to initialize again. The core supplies the tuple.
export function initializationRecoveryContextRows(view: InitializationRecoveryView): {label:string;value:string}[] {
  if (view.state !== 'recoverable' || view.context === null) return [];
  const {configuration,templateSet,tooling}=view.context;
  return [
    {label:'Stored configuration bytes',value:String(configuration.byteLength)},
    {label:'Stored configuration SHA-256',value:configuration.sha256},
    {label:'Template core version',value:templateSet.coreVersion},
    {label:'Template resource version',value:String(templateSet.resourceVersion)},
    {label:'Template resource SHA-256',value:templateSet.resourceSha256},
    {label:'Toolkit repository',value:tooling.repository},
    {label:'Toolkit full commit',value:tooling.sha},
    {label:'Pinned configuration schema',value:tooling.schemaReference},
    {label:'Toolkit verification',value:tooling.state},
  ];
}

export interface InitializationDraftBinding {
  intent: 'initialize';
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
export interface InitializationRecoveryBinding {
  intent: 'recover'; projectId: string; windowGeneration: string;
  startStatusRevision: number; previousTerminalId: string | null;
}
export type InitializationBinding = InitializationDraftBinding | InitializationRecoveryBinding;
export interface InitializationRecoveryApplyBinding { sessionId: string; planToken: string; revision: string }
export interface InitializationApplyBinding {
  sessionId: string;
  planToken: string;
  draftRevision: number;
  baselineGeneration: number;
}
export interface InitializationAttempt {
  binding: InitializationBinding;
  sessionId: string | null;
  projection: ProjectInitializationProjection | null;
  projectionRevision: number;
  prepareClaimed: boolean;
  applyClaimed: boolean;
  submittedPlanToken: string | null;
  closeRequested: boolean;
  closeClaimed: boolean;
  invalidated: boolean;
  handled: boolean;
}
export type InitializationRecoveryAttention = Pick<ProjectInitializationProjection, 'projectId' | 'sessionId' | 'ownerGeneration' | 'coreOutcome'>;
export interface ProjectInitializationState {
  mode: BridgeMode;
  listening: boolean;
  initialized: boolean;
  readPending: boolean;
  status: ProjectInitializationStatus | null;
  buffered: ProjectInitializationStatus | null;
  observationIssue: 'bridge' | 'protocol' | null;
  integrityFailed: boolean;
  generationLost: boolean;
  nativeBlocked: boolean;
  unknownEvidence: ProjectInitializationProjection | null;
  recoveryProjects: readonly InitializationRecoveryAttention[];
  attempt: InitializationAttempt | null;
}
export const initialProjectInitialization: ProjectInitializationState = {
  mode: 'unavailable', listening: false, initialized: false, readPending: false,
  status: null, buffered: null, observationIssue: null, integrityFailed: false,
  generationLost: false, nativeBlocked: false, unknownEvidence: null, recoveryProjects: [], attempt: null,
};
export type InitializationEditAction =
  | { type: 'connect'; mode: BridgeMode }
  | { type: 'listening' }
  | { type: 'read-start' }
  | { type: 'observe'; status: ProjectInitializationStatus; source: 'read' | 'event' | 'reply' }
  | { type: 'observation-failed'; protocol?: boolean }
  | { type: 'begin'; binding: InitializationBinding }
  | { type: 'prepare-claim'; sessionId: string }
  | { type: 'apply-claim'; binding: InitializationApplyBinding }
  | { type: 'recover-claim'; binding: InitializationRecoveryApplyBinding }
  | { type: 'close-request'; reason: 'user' | 'context_changed' | 'invoke_failed' }
  | { type: 'close-claim'; sessionId: string }
  | { type: 'handled'; sessionId: string };

function unknown(owner: ProjectInitializationProjection | null): boolean { return owner?.phase === 'unknown' || owner?.nativeFinality === 'unknown'; }
export function initializationAttemptSettled(attempt: InitializationAttempt | null): boolean {
  return attempt === null || attempt.projection?.phase === 'final' && attempt.projection.nativeFinality === 'settled';
}
function usable(state: ProjectInitializationState): boolean {
  return state.mode === 'native' && state.listening && state.initialized && state.status?.capability.available === true &&
    !state.observationIssue && !state.integrityFailed && !state.generationLost && !state.nativeBlocked;
}
function minimumTimers(previous: ProjectInitializationStatus | null, status: ProjectInitializationStatus): ProjectInitializationStatus {
  const clamp = (owner: ProjectInitializationProjection | null) => {
    if (!owner) return null;
    const old = [previous?.active, previous?.lastTerminal].find((item) => item?.sessionId === owner.sessionId);
    return old ? { ...owner, reviewRemainingMs: Math.min(old.reviewRemainingMs, owner.reviewRemainingMs) } : owner;
  };
  return { ...status, active: clamp(status.active), lastTerminal: clamp(status.lastTerminal) };
}
function retainAttention(state: ProjectInitializationState, status: ProjectInitializationStatus): ProjectInitializationState {
  for (const owner of [status.active, status.lastTerminal]) {
    if (owner && unknown(owner)) {
      const old = state.unknownEvidence;
      const evidence = old && (old.sessionId !== owner.sessionId || !initializationProjectionProgress(old, owner)) ? old : owner;
      state = { ...state, nativeBlocked: true, unknownEvidence: evidence };
    }
    // Stale earlier pending projections cannot resurrect attention after an
    // exact fresh recovery cleared it. Unknown evidence above stays absorbing.
    if (state.status && status.windowGeneration === state.status.windowGeneration && status.statusRevision < state.status.statusRevision) continue;
    if (owner?.phase !== 'final' || owner.nativeFinality !== 'settled' || owner.coreOutcome?.journal !== 'recovery_required' ||
        owner.coreOutcome.resources !== 'settled' || state.recoveryProjects.some((item) => item.projectId === owner.projectId)) continue;
    if (state.recoveryProjects.length >= 64) return { ...state, integrityFailed: true, observationIssue: 'protocol' };
    const { projectId, sessionId, ownerGeneration, coreOutcome } = owner;
    state = { ...state, recoveryProjects: [...state.recoveryProjects, { projectId, sessionId, ownerGeneration, coreOutcome }] };
  }
  return status.capability.reason === 'cleanup_unknown' ? { ...state, nativeBlocked: true } : state;
}

function observe(state: ProjectInitializationState, status: ProjectInitializationStatus, source: 'read' | 'event' | 'reply'): ProjectInitializationState {
  state = retainAttention(state, status);
  const readPending = source === 'read' ? false : state.readPending;
  if (!state.initialized && source !== 'read') return {
    ...state, readPending, buffered: !state.buffered || status.statusRevision >= state.buffered.statusRevision ? status : state.buffered,
  };
  if (!state.initialized && state.buffered?.windowGeneration === status.windowGeneration) {
    const first = state.buffered.statusRevision <= status.statusRevision ? state.buffered : status;
    const next = first === status ? state.buffered : status;
    if (!initializationStatusProgress(first, next)) return { ...state, readPending, integrityFailed: true, observationIssue: 'protocol' };
    if (state.buffered.statusRevision > status.statusRevision) status = state.buffered;
    status = minimumTimers(first, status);
  }
  // A replaced document can observe an original submitted result, never regain
  // its token. Latch revocation while retaining monotone original projections.
  const generationLost = state.generationLost || Boolean(state.status && state.status.windowGeneration !== status.windowGeneration);
  let attempt = state.attempt;
  if (attempt) {
    const retained = attempt;
    const owner = [status.active, status.lastTerminal].find((item) => item && item.domain === 'project_initialization' &&
      item.projectId === retained.binding.projectId && item.ownerGeneration === retained.binding.windowGeneration &&
      (retained.sessionId ? item.sessionId === retained.sessionId : status.statusRevision > retained.binding.startStatusRevision && item.sessionId !== retained.binding.previousTerminalId));
    if (owner) {
      if (owner.intent !== attempt.binding.intent) {
        return { ...state, readPending, generationLost, integrityFailed: true, observationIssue: 'protocol' };
      }
      const older = status.statusRevision < attempt.projectionRevision;
      if (attempt.projection && !(older ? initializationProjectionProgress(owner, attempt.projection) : initializationProjectionProgress(attempt.projection, owner))) {
        return { ...state, readPending, generationLost, integrityFailed: true, observationIssue: 'protocol' };
      }
      if (!older) attempt = { ...attempt, sessionId: owner.sessionId, projectionRevision: status.statusRevision,
        projection: attempt.projection ? { ...owner, reviewRemainingMs: Math.min(attempt.projection.reviewRemainingMs, owner.reviewRemainingMs) } : owner };
    }
  }
  if (state.status && status.statusRevision < state.status.statusRevision) {
    const contradictory = !initializationStatusProgress(status, state.status);
    return { ...state, readPending, generationLost, attempt,
      integrityFailed: state.integrityFailed || contradictory, observationIssue: contradictory ? 'protocol' : state.observationIssue };
  }
  if (state.status && !initializationStatusProgress(state.status, status)) return { ...state, readPending, generationLost, integrityFailed: true, observationIssue: 'protocol' };
  status = minimumTimers(state.status, status);
  // Only this fresh explicitly submitted recovery and an accepted monotone
  // original Final/Settled can clear its project's earlier attention.
  if (!state.integrityFailed && !state.nativeBlocked && !generationLost && attempt?.binding.intent === 'recover' &&
      attempt.applyClaimed && attempt.submittedPlanToken !== null && attempt.projection &&
      status.lastTerminal?.sessionId === attempt.sessionId && normalInitializationRecovery(attempt.projection) &&
      attempt.submittedPlanToken === attempt.projection.prepared?.planToken) {
    const recoveredProject = attempt.binding.projectId; const recoveredSession = attempt.sessionId;
    state = { ...state, recoveryProjects: state.recoveryProjects.filter((item) =>
      item.projectId !== recoveredProject || item.sessionId === recoveredSession) };
  }
  return { ...state, initialized: true, readPending, status, buffered: null, attempt, generationLost, observationIssue: state.integrityFailed ? 'protocol' : null };
}

export function projectInitializationReducer(state: ProjectInitializationState, action: InitializationEditAction): ProjectInitializationState {
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
      if (initializationNativeStartReason(state) || !state.status || action.binding.windowGeneration !== state.status.windowGeneration ||
          action.binding.startStatusRevision !== state.status.statusRevision ||
          action.binding.intent !== 'recover' && ![action.binding.draftRevision, action.binding.baselineGeneration, action.binding.serviceGeneration, action.binding.selectionGeneration, action.binding.coordinateGeneration].every((counter) => isU32(counter) && counter < U32_MAX)) return state;
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
      const binding = currentInitializationApplyBinding(state);
      if (!binding || !sameInitializationApplyBinding(binding, action.binding) || !state.attempt) return state;
      return { ...state, attempt: { ...state.attempt, applyClaimed: true, submittedPlanToken: action.binding.planToken } };
    }
    case 'recover-claim': {
      const binding = currentInitializationRecoveryBinding(state);
      if (!binding || !sameInitializationRecoveryBinding(binding, action.binding) || !state.attempt) return state;
      return { ...state, attempt: { ...state.attempt, applyClaimed: true, submittedPlanToken: action.binding.planToken } };
    }
    case 'close-request': {
      const attempt = state.attempt;
      if (!attempt || attempt.handled || initializationAttemptSettled(attempt) || attempt.closeRequested || attempt.applyClaimed && action.reason !== 'user') return state;
      return { ...state, attempt: { ...attempt, closeRequested: true, invalidated: attempt.invalidated || action.reason === 'context_changed' } };
    }
    case 'close-claim': {
      const attempt = state.attempt;
      if (!attempt || attempt.sessionId !== action.sessionId || !attempt.closeRequested || attempt.closeClaimed ||
          initializationAttemptSettled(attempt) || unknown(attempt.projection) || state.generationLost) return state;
      return { ...state, attempt: { ...attempt, closeClaimed: true } };
    }
    case 'handled': return state.attempt?.sessionId === action.sessionId ? { ...state, attempt: { ...state.attempt, handled: true } } : state;
  }
}

const availabilityCopy: Record<EditAvailability, string> = {
  available: 'Native local initialization review is available. No file change happens without a new full plan and explicit confirmation.',
  unsupported_platform: 'Local initialization writes are unavailable on this platform. This slice requires the separately qualified native initialization backend.',
  runtime_unqualified: 'This build has no qualified local-initialization writer. Its distinct production gate remains disabled; configuration saving or a passive preview cannot enable it.',
  cleanup_unknown: 'Native ownership or cleanup is unverified. No new edit or repeated Apply is allowed; retain the original operation and recovery evidence.',
  shutdown: 'The native application is stopping. No local initialization edit can be opened.',
  other_edit_active: 'Another operation owns the shared native edit service. Finish or close that original session before reviewing initialization files.',
};
export function initializationNativeStartReason(state: ProjectInitializationState): string | null {
  if (state.mode === 'preview') return 'Browser preview cannot observe initialization files, issue an Apply token or simulate successful installation.';
  if (state.mode !== 'native') return 'Local initialization review requires the native desktop bridge.';
  if (state.integrityFailed) return 'Native initialization status failed its closed contract. Observe the original owner; no new edit is allowed.';
  if (state.generationLost) return 'This native document generation changed. Original review authority cannot be reattached.';
  if (state.nativeBlocked) return availabilityCopy.cleanup_unknown;
  if (state.observationIssue) return 'Native initialization confirmation is unavailable. Check the original status; do not open a replacement session.';
  if (!state.listening || !state.initialized || !state.status) return 'Loading the separate local-initialization capability and original-owner status…';
  if (!state.status.capability.available) return availabilityCopy[state.status.capability.reason];
  if (state.status.statusRevision === U32_MAX) return 'The native status counter is exhausted. A new edit cannot reuse or wrap that sequence.';
  if (state.status.active || !initializationAttemptSettled(state.attempt) || state.attempt && !state.attempt.handled) return 'The original initialization edit is still active or awaiting settlement. Finish or close that owner before starting a new review.';
  return null;
}
export function initializationStartReason(state: ProjectInitializationState, session: ProjectSession | null, setup: GitHubSetupState, otherEditReason: string | null = null): string | null {
  const native = initializationNativeStartReason(state);
  if (native) return native;
  if (otherEditReason) return otherEditReason;
  if (setup.mode !== 'native') return 'The current service/runtime context is unavailable. Reload it before opening a native initialization review.';
  if (session?.saveRecoveryRequired || session && state.recoveryProjects.some((item) => item.projectId === session.project.id)) return 'This project needs transaction recovery. Use the separate Inspect initialization recovery action for a qualified initialization journal; ordinary Apply cannot bypass the block.';
  if (!session?.draft) return 'Choose a project and prepare an in-memory configuration draft. Saving it to disk first is not required.';
  if (setup.project?.projectId !== session.project.id || setup.project.draftRevision !== session.revision || setup.project.baselineGeneration !== session.baselineGeneration || !setup.project.hasDraft) return 'The selected draft context is changing. Wait for its synchronous binding before opening a native review.';
  if (![session.revision, session.baselineGeneration, setup.serviceGeneration, setup.selectionGeneration, setup.coordinateGeneration].every((counter) => isU32(counter) && counter < U32_MAX)) return 'An in-memory binding counter is exhausted. No review or generation will be reused.';
  if (!setup.inputs.toolingRepository || !setup.inputs.toolingSha) return 'Enter the toolkit repository and full toolkit commit above. The native core validates both; there is no default pin.';
  if (!githubSetupRequestFits({ draft: session.draft, toolingRepository: setup.inputs.toolingRepository, toolingSha: setup.inputs.toolingSha, suppliedSnapshot: null })) return 'The draft or toolkit inputs exceed the bounded JSON/text contract. No values were truncated or submitted.';
  return null;
}
export function initializationRecoveryStartReason(state: ProjectInitializationState, session: ProjectSession | null, otherEditReason: string | null = null): string | null {
  const native = initializationNativeStartReason(state);
  if (native) return native;
  if (otherEditReason) return otherEditReason;
  if (!session) return 'Choose the registered project whose interrupted initialization journal should be inspected.';
  if (session.saveRecoveryRequired) return 'This project has separate configuration recovery attention. Initialization recovery cannot clear another domain’s journal.';
  return null; // No draft validation, toolkit pin, templates or remote service are needed.
}
export function initializationContextMatches(binding: InitializationBinding, session: ProjectSession | null, setup: GitHubSetupState): boolean {
  if (binding.intent === 'recover') return session !== null && session.project.id === binding.projectId;
  return setup.mode === 'native' && session !== null && session.project.id === binding.projectId && session.draft !== null &&
    session.revision === binding.draftRevision && session.baselineGeneration === binding.baselineGeneration &&
    sameJson(session.draft, binding.draft) && sameJson(session.baseline, binding.baseline) &&
    setup.serviceGeneration === binding.serviceGeneration && setup.selectionGeneration === binding.selectionGeneration && setup.coordinateGeneration === binding.coordinateGeneration &&
    setup.inputs.toolingRepository === binding.toolingRepository && setup.inputs.toolingSha === binding.toolingSha;
}
export function initializationPreparedMatches(attempt: InitializationAttempt): boolean {
  const owner=attempt.projection,binding=attempt.binding;
  if(!owner||owner.domain!=='project_initialization'||owner.intent!==binding.intent||owner.projectId!==binding.projectId||owner.ownerGeneration!==binding.windowGeneration||owner.sessionId!==attempt.sessionId||!owner.prepared||!owner.checkout||owner.prepared.revision!==owner.checkout.revision)return false;
  if(binding.intent==='recover')return owner.prepared.intent==='recover'&&owner.checkout.intent==='recover'&&owner.prepared.recovery.state==='recoverable'&&sameJson(owner.prepared.recovery as unknown as JsonObject,owner.checkout.recovery as unknown as JsonObject);
  return owner.prepared.intent==='initialize'&&owner.checkout.intent==='initialize'&&owner.prepared.draftRevision===binding.draftRevision&&owner.prepared.baselineGeneration===binding.baselineGeneration&&owner.checkout.draftRevision===binding.draftRevision&&owner.checkout.baselineGeneration===binding.baselineGeneration&&owner.prepared.view.tooling.repository===binding.toolingRepository&&owner.prepared.view.tooling.sha===binding.toolingSha.toLowerCase();
}
export function currentInitializationApplyBinding(state: ProjectInitializationState): InitializationApplyBinding | null {
  const attempt = state.attempt; const owner = attempt?.projection;
  if (!usable(state) || !attempt || attempt.binding.intent === 'recover' || !owner?.prepared || !attempt.prepareClaimed || attempt.applyClaimed || attempt.closeRequested || attempt.invalidated || attempt.handled ||
      owner.phase !== 'reviewing' || owner.nativeReason !== 'none' || owner.nativeFinality !== 'pending' || owner.reviewRemainingMs === 0 || owner.applySubmitted || owner.conflict ||
      !initializationPreparedMatches(attempt) || state.status?.active?.sessionId !== owner.sessionId || owner.ownerGeneration !== state.status.windowGeneration) return null;
  return { sessionId: owner.sessionId, planToken: owner.prepared.planToken, draftRevision: attempt.binding.draftRevision, baselineGeneration: attempt.binding.baselineGeneration };
}
export function sameInitializationApplyBinding(first: InitializationApplyBinding, next: InitializationApplyBinding): boolean {
  return first.sessionId === next.sessionId && first.planToken === next.planToken && first.draftRevision === next.draftRevision && first.baselineGeneration === next.baselineGeneration;
}
export function canApplyInitializations(state: ProjectInitializationState, session: ProjectSession | null, setup: GitHubSetupState, confirmation?: InitializationApplyBinding): boolean {
  const current = currentInitializationApplyBinding(state);
  return current !== null && state.attempt !== null && initializationContextMatches(state.attempt.binding, session, setup) && (!confirmation || sameInitializationApplyBinding(current, confirmation));
}

export function currentInitializationRecoveryBinding(state: ProjectInitializationState): InitializationRecoveryApplyBinding | null {
  const attempt = state.attempt; const owner = attempt?.projection; const prepared = owner?.prepared?.intent === 'recover' ? owner.prepared : null;
  if (!usable(state) || !attempt || attempt.binding.intent !== 'recover' || !owner || !prepared || !attempt.prepareClaimed ||
      attempt.applyClaimed || attempt.closeRequested || attempt.invalidated || attempt.handled ||
      owner.phase !== 'reviewing' || owner.nativeReason !== 'none' || owner.nativeFinality !== 'pending' ||
      owner.reviewRemainingMs === 0 || owner.applySubmitted || !initializationPreparedMatches(attempt) ||
      state.status?.active?.sessionId !== owner.sessionId || owner.ownerGeneration !== state.status.windowGeneration) return null;
  return { sessionId: owner.sessionId, planToken: prepared.planToken, revision: prepared.revision };
}
export function sameInitializationRecoveryBinding(first: InitializationRecoveryApplyBinding, next: InitializationRecoveryApplyBinding): boolean {
  return first.sessionId === next.sessionId && first.planToken === next.planToken && first.revision === next.revision;
}
export function canRecoverInitializations(state: ProjectInitializationState, session: ProjectSession | null, confirmation?: InitializationRecoveryApplyBinding): boolean {
  const current = currentInitializationRecoveryBinding(state);
  return current !== null && session !== null && session.project.id === state.attempt?.binding.projectId &&
    (!confirmation || sameInitializationRecoveryBinding(current, confirmation));
}

export function confirmedInitializationResult(state: ProjectInitializationState): 'initialized' | 'unchanged' | null {
  const attempt = state.attempt;
  if (!attempt?.projection || !attempt.applyClaimed || state.integrityFailed || state.observationIssue || !initializationPreparedMatches(attempt) ||
      attempt.submittedPlanToken === null || attempt.submittedPlanToken !== attempt.projection.prepared?.planToken) return null;
  // Observation of this submitted outcome remains meaningful after selection,
  // draft, runtime or document changes. It never marks any configuration saved.
  return normalInitializationResult(attempt.projection);
}
export function initializationOwnerReason(state: ProjectInitializationState, projectId: string): string | null {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost || state.observationIssue) return 'Initialization edit ownership is unverified. Observe the original native status; do not open a competing operation.';
  if (state.status?.active || !initializationAttemptSettled(state.attempt) || state.attempt && !state.attempt.handled) return 'A local initialization edit is still owned or awaiting settlement. Finish or close that original session before preparing a configuration save.';
  if (state.recoveryProjects.some((item) => item.projectId === projectId)) return 'This project needs separate initialization transaction recovery. A configuration edit cannot clear its journal or bypass the block.';
  return null;
}
export function initializationRetainsDraft(state: ProjectInitializationState, projectId: string): boolean {
  return state.attempt?.binding.projectId === projectId && (!initializationAttemptSettled(state.attempt) || state.integrityFailed || state.nativeBlocked || state.observationIssue !== null) ||
    state.status?.active?.projectId === projectId || state.unknownEvidence?.projectId === projectId;
}
export function initializationNoOp(view: InitializationView): boolean { return view.files.every((file) => file.action === 'preserve'); }


export interface ConfirmedInitialization { binding: InitializationDraftBinding; projection: ProjectInitializationProjection; submittedPlanToken: string; statusRevision: number }
export function confirmedInitialization(state: ProjectInitializationState): ConfirmedInitialization | null {
  const a=state.attempt;
  return a?.binding.intent==='initialize' && a.projection && a.submittedPlanToken!==null && confirmedInitializationResult(state)!==null ? {binding:a.binding,projection:a.projection,submittedPlanToken:a.submittedPlanToken,statusRevision:a.projectionRevision}:null;
}
export function validInitializationCompletion(value: ConfirmedInitialization): boolean {
  const b=value.binding,p=value.projection;
  return b.intent==='initialize'&&isU32(value.statusRevision)&&value.statusRevision>b.startStatusRevision&&value.submittedPlanToken===p.prepared?.planToken&&p.projectId===b.projectId&&p.ownerGeneration===b.windowGeneration&&p.prepared?.intent==='initialize'&&p.prepared.draftRevision===b.draftRevision&&p.prepared.baselineGeneration===b.baselineGeneration&&p.prepared.view.tooling.repository===b.toolingRepository&&p.prepared.view.tooling.sha===b.toolingSha.toLowerCase()&&normalInitializationResult(p)!==null;
}
