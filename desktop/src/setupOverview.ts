// Presentation only. These selectors never grant consent, complete a task,
// persist wizard progress, replace a draft, or call an operation owner.
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import type { ConfigEditState } from './configEdit.ts';
import { configurationSetupNeeded } from './setupGuidance.ts';
import { releaseVersionPhase } from './releaseVersion.ts';
import type { ReleaseVersionState } from './releaseVersion.ts';
import type { ProjectInitializationState } from './projectInitialization.ts';
import type { VersionEditState } from './releaseVersionEditController.ts';
import type { Page } from './types.ts';

export type SetupStageId = 'project' | 'configuration' | 'version' | 'tools' | 'signing' | 'build';
export type SetupAction =
  | { kind: 'choose-project' | 'refresh-project' | 'read-version' | 'open-version' | 'open-initialization' }
  | { kind: 'navigate'; page: Page };
export interface SetupNextAction {
  label: string;
  action: SetupAction;
  disabledReason: string | null;
}
export interface SetupStage {
  id: SetupStageId;
  title: string;
  summary: string;
  state: 'observed' | 'needs-action' | 'not-checked' | 'working' | 'unavailable';
  statusLabel: string;
  next: SetupNextAction;
}

// Internal UI projections from the existing domain controllers, NOT bridge
// DTOs. Root must supply only their current, qualified observations. A tool
// catalogue, stored credential descriptor, format check, or result-shaped
// native reply cannot become "checked" here. No private material belongs here.
export interface SetupCheckObservation {
  projectId: string;
  observationGeneration: number;
  baselineGeneration: number;
  draftRevision: number;
  stage: 'tools' | 'signing';
  state: 'checked' | 'needs-attention' | 'unavailable';
  summary: string;
}
export interface SetupActivity {
  projectId: string;
  task: string;
  // "unknown" is ORIGINAL OPERATION finality, never an unperformed check.
  state: 'prepared' | 'running' | 'cancellation-requested' | 'failed' | 'recovery-required' | 'unknown';
  action: SetupAction;
}
export interface SetupOverviewInput {
  session: ProjectSession | null;
  preview: boolean;
  configSaveState: ConfigEditState;
  releaseVersionState: ReleaseVersionState;
  initializationState: ProjectInitializationState;
  versionEditState: VersionEditState;
  chooseReason: string | null;
  refreshReason: string | null;
  releaseVersionReason: string | null;
  checks?: readonly SetupCheckObservation[];
  activities?: readonly SetupActivity[];
}
export interface SetupOverview {
  stages: readonly SetupStage[];
  currentStage: SetupStageId;
  next: SetupNextAction;
  currentActivity: SetupActivity | null;
  otherProjectActivities: readonly SetupActivity[];
  known: readonly string[];
  remaining: readonly string[];
  version: { name: string; build: number } | null;
  versionLabel: string;
  initializationNeedsAttention: boolean;
  versionEditorNeedsAttention: boolean;
}

const navigate = (page: Page): SetupAction => ({ kind: 'navigate', page });
const next = (label: string, action: SetupAction, disabledReason: string | null = null): SetupNextAction => ({ label, action, disabledReason });
const activityRank: Record<SetupActivity['state'], number> = {
  unknown: 0, 'recovery-required': 1, 'cancellation-requested': 2, running: 3, prepared: 4, failed: 5,
};

// A shared *display* subset, not a generic native command or lifecycle owner.
interface EditDisplayOwner {
  projectId: string;
  phase: string;
  nativeFinality: string;
  nativeReason: string;
  coreOutcome: { journal: string; reason: string } | null;
}
interface EditDisplayAttempt {
  binding: { projectId: string };
  projection: EditDisplayOwner | null;
  closeRequested: boolean;
  handled: boolean;
}
interface EditDisplayState {
  status: { active: EditDisplayOwner | null; lastTerminal: EditDisplayOwner | null } | null;
  buffered: { active: EditDisplayOwner | null; lastTerminal: EditDisplayOwner | null } | null;
  unknownEvidence: EditDisplayOwner | null;
  observationIssue: string | null;
  nativeBlocked: boolean;
  integrityFailed: boolean;
  generationLost: boolean;
  attempt: EditDisplayAttempt | null;
  recovery?: EditDisplayAttempt | null;
}
function unsettled(attempt: EditDisplayAttempt | null | undefined): boolean {
  return Boolean(attempt && (attempt.projection?.phase !== 'final' || attempt.projection.nativeFinality !== 'settled'));
}
function editActivities(state: EditDisplayState, task: string, action: SetupAction, recoveryProjects: readonly string[]): SetupActivity[] {
  const activities: SetupActivity[] = recoveryProjects.map((projectId) => ({ projectId, task, action, state: 'recovery-required' }));
  const attempts = [state.attempt, state.recovery].filter((attempt) => unsettled(attempt));
  const owners = [state.unknownEvidence, state.status?.active, state.buffered?.active, ...attempts.map((attempt) => attempt?.projection)];
  for (const owner of owners) {
    if (!owner) continue;
    const attempt = attempts.find((item) => item?.projection === owner);
    const unknown = state.nativeBlocked || state.integrityFailed || state.generationLost || state.observationIssue !== null ||
      owner.phase === 'unknown' || owner.nativeFinality === 'unknown';
    const status: SetupActivity['state'] = unknown ? 'unknown' : owner.coreOutcome?.journal === 'recovery_required' ? 'recovery-required' :
      attempt?.closeRequested ? 'cancellation-requested' : ['editing', 'reviewing'].includes(owner.phase) ? 'prepared' : 'running';
    activities.push({ projectId: owner.projectId, task, action, state: status });
  }
  for (const attempt of attempts) {
    if (attempt && !attempt.projection) activities.push({ projectId: attempt.binding.projectId, task, action,
      state: state.nativeBlocked || state.integrityFailed || state.generationLost || state.observationIssue ? 'unknown' :
        attempt.closeRequested ? 'cancellation-requested' : 'running' });
  }
  return activities;
}
function editNeedsAttention(state: EditDisplayState, recoveryProjects: readonly unknown[]): boolean {
  if (state.nativeBlocked || state.integrityFailed || state.generationLost || state.observationIssue || state.unknownEvidence ||
    state.status?.active || state.buffered?.active || unsettled(state.attempt) || unsettled(state.recovery) || recoveryProjects.length) return true;
  // A failed terminal result stays findable without promoting it to success.
  return [state.attempt?.projection, state.recovery?.projection, state.status?.lastTerminal, state.buffered?.lastTerminal].some((owner) => owner && (
    owner.nativeFinality === 'unknown' || owner.phase === 'unknown' || owner.coreOutcome?.journal === 'recovery_required' ||
    !['none', 'discarded', 'cancelled'].includes(owner.nativeReason) ||
    owner.coreOutcome !== null && !['none', 'cancelled'].includes(owner.coreOutcome.reason)));
}

export function savedVersionForSetup(session: ProjectSession | null, state: ReleaseVersionState, preview: boolean): { name: string; build: number } | null {
  const binding = state.resultBinding;
  if (preview || !session || state.mode !== 'native' || state.generationLost || state.selectionPending || state.reason ||
    releaseVersionPhase(state) !== 'observed' || !state.result || !binding || !state.project ||
    session.snapshotRequest !== null || session.snapshotError || session.snapshotPredatesSave || session.sourceChanged || session.saveRecoveryRequired ||
    binding.readEpoch !== state.readEpoch || binding.connectionGeneration !== state.connectionGeneration || binding.selectionGeneration !== state.selectionGeneration ||
    [state.project, binding].some((context) => context.projectId !== session.project.id || context.draftRevision !== session.revision ||
      context.baselineGeneration !== session.baselineGeneration || context.observationGeneration !== session.observationGeneration ||
      context.dirtyDraft !== isDirty(session) || context.snapshotRequest !== null || context.saveRecoveryRequired)) return null;
  // Copy only the accepted public values; no native ID, paths or byte hashes.
  return { name: state.result.version.name, build: state.result.version.build };
}

function configurationStage(input: SetupOverviewInput): SetupStage {
  const { session, preview } = input;
  const stage: SetupStage = { id: 'configuration', title: 'Save release settings', state: 'not-checked', statusLabel: 'Not read',
    summary: 'Tell the app how your project is built. Changes stay in a draft until you review and save them.',
    next: next('Review release settings', navigate('settings')) };
  if (!session) return stage;
  if (preview) return { ...stage, statusLabel: 'Example only', summary: 'Example settings are not a read of your project files.' };
  if (session.snapshotRequest !== null) return { ...stage, state: 'working', statusLabel: 'Reading…',
    summary: 'Reading saved project settings. Your draft is kept.', next: next('Reading project settings…', { kind: 'refresh-project' }, 'Wait for this read to finish.') };
  if (!session.snapshot || session.observedAt === null || session.snapshotError || session.snapshotPredatesSave || session.sourceChanged ||
    session.snapshot.discovery.partial || session.snapshot.config.state === 'unavailable') return { ...stage,
    summary: 'Saved settings need a fresh, complete read. Reading again keeps your unsaved draft.',
    next: next('Read project settings', { kind: 'refresh-project' }, input.refreshReason) };
  if (isDirty(session)) return { ...stage, state: 'needs-action', statusLabel: 'Unsaved draft',
    summary: 'You have unsaved release settings. Review them before continuing; nothing is saved automatically.' };
  if (session.snapshot.config.state === 'format-valid') return { ...stage, state: 'observed', statusLabel: 'Saved settings read',
    summary: 'Saved settings passed format checks. Tools, signing and build checks are separate.' };
  if (session.snapshot.config.state === 'invalid') return { ...stage, state: 'needs-action', statusLabel: 'Needs correction',
    summary: 'The saved release settings need correction. Open the settings to see the issue; existing files are kept.' };
  if (configurationSetupNeeded(session, preview, input.configSaveState)) return { ...stage, state: 'needs-action', statusLabel: 'Not set up',
    summary: 'No release settings file was found in the complete read. Start with a draft, then review the proposed save.',
    next: next('Set up release settings', navigate('settings')) };
  return { ...stage, summary: 'Earlier file changes need another read before setup can continue.',
    next: next('Read project settings', { kind: 'refresh-project' }, input.refreshReason) };
}

function versionStage(input: SetupOverviewInput, version: SetupOverview['version']): SetupStage {
  const { releaseVersionState: state, session } = input;
  const stage: SetupStage = { id: 'version', title: 'Choose the release version', state: 'not-checked', statusLabel: 'Not read',
    summary: 'Read the saved version and build number. You choose any changes; there is no automatic version increase.',
    next: next('Read saved version', { kind: 'read-version' }, input.releaseVersionReason) };
  if (version) return { ...stage, state: 'observed', statusLabel: 'Saved version read',
    summary: `${version.name} · Build ${version.build}. These are saved values, not a Store release or a build approval.`,
    next: next('Review version values', { kind: 'open-version' }) };
  if (input.preview) return { ...stage, state: 'unavailable', statusLabel: 'Example only' };
  if (state.project?.projectId !== session?.project.id) return stage;
  if (state.pending) return { ...stage, state: 'working', statusLabel: 'Reading…', next: next('Reading saved version…', { kind: 'read-version' }, 'Wait for this read to finish.') };
  if (['missing', 'invalid'].includes(releaseVersionPhase(state))) return { ...stage, state: 'needs-action', statusLabel: 'Needs attention',
    summary: 'The saved version could not be read. Review the version settings before trying again.',
    next: state.error?.code.startsWith('release_version_config_') ? next('Review release settings', navigate('settings')) : next('Review version values', { kind: 'open-version' }) };
  if (state.stale || state.result) return { ...stage, statusLabel: 'Read again', summary: 'An earlier version read is no longer current for these settings. Read it again; unsaved edits stay separate.' };
  return stage;
}

function checkStage(input: SetupOverviewInput, id: 'tools' | 'signing'): SetupStage {
  const { session } = input;
  const stage: SetupStage = id === 'tools'
    ? { id, title: 'Check this computer', state: 'not-checked', statusLabel: 'Not checked',
      summary: 'Check the tools this project needs. Use compatible tools already installed before preparing anything new.',
      next: next('Check this computer', navigate('environment')) }
    : { id, title: 'Set up signing when needed', state: 'not-checked', statusLabel: 'Not checked',
      summary: 'Your chosen build or Store action explains which signing inputs it needs. Reuse your app’s existing key; a different key can prevent updates. Selecting a file is not a signing check.',
      next: next('Set up app signing', navigate('credentials')) };
  if (!session || input.preview || !session.snapshot || session.observedAt === null || session.snapshot.config.state !== 'format-valid' ||
    session.snapshotRequest !== null || session.snapshotError || session.snapshotPredatesSave || session.sourceChanged ||
    session.saveRecoveryRequired || session.snapshot.discovery.partial || isDirty(session)) return stage;
  const matches = input.checks?.filter((check) => check.stage === id && check.projectId === session.project.id &&
    check.observationGeneration === session.observationGeneration && check.baselineGeneration === session.baselineGeneration && check.draftRevision === session.revision) ?? [];
  // No last-result-wins rule: conflicting/duplicated adapter observations are
  // not one current check. Foreign and stale ordinary negatives are ignored.
  if (matches.length !== 1) return stage;
  const check = matches[0]!;
  return { ...stage, summary: check.summary, state: check.state === 'checked' ? 'observed' : check.state === 'unavailable' ? 'unavailable' : 'needs-action',
    statusLabel: check.state === 'checked' ? 'Checked for setup' : check.state === 'unavailable' ? 'Unavailable here' : 'Needs attention' };
}

export function setupActivitySummary(activity: SetupActivity): string {
  switch (activity.state) {
    case 'unknown': return `${activity.task}: the result or cleanup is not confirmed. Keep the original files and check this task before trying again.`;
    case 'recovery-required': return `${activity.task} needs recovery. Keep the original files; do not restart or repeat the change.`;
    case 'cancellation-requested': return `${activity.task} is stopping. A cancellation request is not completion; wait for its final result.`;
    case 'running': return `${activity.task} is in progress. Open it to see progress and the available cancel controls.`;
    case 'prepared': return `${activity.task} is waiting for your review. Nothing is approved by continuing this guide.`;
    case 'failed': return `${activity.task} did not complete successfully. Review its error and recovery guidance before trying again.`;
  }
}

export function setupOverview(input: SetupOverviewInput): SetupOverview {
  const { session, configSaveState: saves, initializationState: initialization, versionEditState: editor } = input;
  const version = savedVersionForSetup(session, input.releaseVersionState, input.preview);
  const activities = [
    ...editActivities(saves, 'Saving release settings', navigate('settings'), saves.recoveryProjects.map((item) => item.projectId)),
    ...editActivities(initialization, 'Release-file setup', { kind: 'open-initialization' }, initialization.recoveryProjects.map((item) => item.projectId)),
    ...editActivities(editor.edit, 'Editing the version', { kind: 'open-version' }, editor.edit.recoveryProjects),
    ...(input.activities ?? []),
  ];
  if (session?.saveRecoveryRequired) activities.push({ projectId: session.project.id, task: 'Release settings', state: 'recovery-required', action: navigate('settings') });
  const currentActivity = activities.filter((activity) => activity.projectId === session?.project.id).sort((a, b) => activityRank[a.state] - activityRank[b.state])[0] ?? null;
  const stages: SetupStage[] = [
    { id: 'project', title: 'Choose your app', state: session && !input.preview ? 'observed' : 'needs-action',
      statusLabel: input.preview && session ? 'Example only' : session ? 'Folder selected' : 'Choose a folder',
      summary: session ? 'The selected folder is your workspace. Choosing it does not change its files.' : 'Choose the folder containing your Android, iOS or Kotlin app.',
      next: next(input.preview ? 'Load example project' : session ? 'Choose another project' : 'Choose project folder', { kind: 'choose-project' }, input.chooseReason) },
    configurationStage(input), versionStage(input, version), checkStage(input, 'tools'),
    { id: 'build', title: 'Review a local build', state: 'not-checked', statusLabel: 'Separate checks',
      summary: 'Review Android or iOS build options before setting up Store accounts. Each build checks its own requirements and asks before running project code or using a signing key.',
      next: next('Review a local build', navigate('releases')) },
    checkStage(input, 'signing'),
  ];
  const current = stages.find((stage) => stage.state !== 'observed')!;
  const action = currentActivity ? next(currentActivity.state === 'prepared' ? 'Continue reviewing this task' :
    currentActivity.state === 'running' || currentActivity.state === 'cancellation-requested' ? 'View current task' : 'Review unfinished work', currentActivity.action) : current.next;
  return {
    stages, currentStage: current.id, next: action, currentActivity,
    otherProjectActivities: activities.filter((activity) => activity.projectId !== session?.project.id),
    known: stages.filter((stage) => stage.state === 'observed').map((stage) => stage.statusLabel === 'Checked for setup' ? `${stage.title}: checked for setup` : stage.statusLabel),
    remaining: stages.filter((stage) => stage.state !== 'observed').map((stage) => `${stage.title} — ${stage.statusLabel.toLowerCase()}`),
    version, versionLabel: version ? version.name : input.preview ? 'Example only' : input.releaseVersionState.pending && input.releaseVersionState.project?.projectId === session?.project.id ? 'Reading…' : 'Not read for these settings',
    initializationNeedsAttention: editNeedsAttention(initialization, initialization.recoveryProjects),
    versionEditorNeedsAttention: editNeedsAttention(editor.edit, editor.edit.recoveryProjects) || editor.projectId === session?.project.id && editor.error !== null ||
      Object.values(editor.entries).some((entry) => entry.projectId === session?.project.id && (entry.error !== null || entry.stale)),
  };
}

// Native <details> keeps children mounted; attention may open it, never hide
// it. This helper has no access to controller state or operation callbacks.
export function setupDisclosureOpen(requested: boolean, needsAttention: boolean): boolean {
  return requested || needsAttention;
}
