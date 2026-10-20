// Read-only presentation of existing owners. No persisted wizard progress,
// native calls, credential material, or permission to reuse a result lives here.
import type { AndroidBuildState } from './androidBuild.ts';
import type { IOSArchiveState } from './iosArchive.ts';
import type { ToolAcquisitionState } from './toolAcquisitionController.ts';
import type { EnvironmentDiagnosticsState } from './environmentDiagnosticsController.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { OfflinePreflightState } from './offlinePreflight.ts';
import type { ProjectSession } from './drafts.ts';
import type { SetupActivity, SetupNextAction, SetupStage } from './setupOverview.ts';
import { sameSavedConfig } from './offlinePreflightProtocol.ts';
import { sameAndroidCatalogSelection } from './androidToolchainCatalogProtocol.ts';
import { setupGuidanceView, setupRequirementLabels } from './smartSetup.ts';

export interface SetupResumeSource {
  platform: 'android' | 'ios'; // Existing Tools view choice, not another setting.
  android: AndroidBuildState;
  ios: IOSArchiveState;
  toolPreparation: ToolAcquisitionState;
  diagnostics: EnvironmentDiagnosticsState;
  credentials: AssetDisplayState;
  localChecks: OfflinePreflightState;
  androidSubmissionPending: boolean; // Original controller's actual caller count.
  iosSubmissionPending: boolean;
  localChecksSubmissionPending: boolean;
  otherOwnerReason: string | null; // Existing application owner guard, not a new census.
}
type Step = Pick<SetupStage, 'title' | 'summary' | 'state' | 'statusLabel' | 'next'>;
export interface SetupResume {
  configuration: Step | null;
  tools: Step | null;
  build: Step | null;
  signing: Step | null;
  reviewBuild: boolean;
  completedBuild: 'local' | 'candidate' | null; // Same current-result branch; presentation only.
  activities: SetupActivity[];
  facts: string[];
}
const go = (label: string, page: 'settings' | 'environment' | 'releases' | 'credentials' | 'recovery'): SetupNextAction =>
  ({ label, action: { kind: 'navigate', page }, disabledReason: null });
const tools = (label: string, platform: 'android' | 'ios'): SetupNextAction =>
  ({ label, action: { kind: 'open-build-tools', platform }, disabledReason: null });
const step = (title: string, summary: string, next: SetupNextAction, statusLabel = 'Needs a review'): Step =>
  ({ title, summary, next, state: 'not-checked', statusLabel });

// These three original owners share this *display* subset, not a lifecycle or
// command implementation. Unknown ownership is retained even for stale inputs.
function buildActivity(state: AndroidBuildState | IOSArchiveState | OfflinePreflightState, pending: boolean,
  task: string, page: 'releases' | 'recovery'): SetupActivity | null {
  if (state.mode !== 'native') return null;
  const op = state.status?.operation;
  const held = pending || !!state.pending || state.originalUnconfirmed || state.readPending;
  const unknown = state.nativeBlocked || state.integrityFailed || state.generationLost || op?.phase === 'unknown';
  const recovery = op?.reason === 'recovery-required' || op?.reason === 'recovery-attention' ||
    op?.reason === 'build-inputs-unrestored' || op?.reason === 'work-retained';
  const active = !!op && op.phase !== 'terminal';
  if (!unknown && !recovery && !held && !active && !state.observationIssue) return null;
  // Before an acknowledgement, the currently selected project (or the previous
  // terminal) cannot identify the original in-flight request after a switch.
  const projectId = op && (active || recovery) ? op.context.projectId : null;
  return { projectId, task, action: { kind: 'navigate', page }, state: unknown ? 'unknown' : recovery ? 'recovery-required' :
    state.cancelClaimed && (active || held) || op?.phase === 'stopping' ? 'cancellation-requested' :
      state.consent && op?.phase === 'awaiting-consent' && !pending ? 'prepared' : held || active ? 'running' : 'retained' };
}
function originalActivities(source: SetupResumeSource): SetupActivity[] {
  const result: SetupActivity[] = [];
  const add = (value: SetupActivity | null) => { if (value) result.push(value); };
  add(buildActivity(source.android, source.androidSubmissionPending, 'Android build', 'releases'));
  const iosOp = source.ios.status?.operation;
  add(buildActivity(source.ios, source.iosSubmissionPending,
    iosOp?.context.operation === 'ios-local-recovery' ? 'iOS build recovery' : 'iOS build or signing check',
    iosOp?.context.operation === 'ios-local-recovery' ? 'recovery' : 'releases'));
  add(buildActivity(source.localChecks, source.localChecksSubmissionPending, 'Local project checks', 'releases'));
  const android = source.android;
  if (android.mode === 'native') {
    const rows = [
      { status: android.toolRegistration, pending: android.registrationPending !== null || android.registrationReadPending || android.registrationCancelPending,
        unconfirmed: android.registrationUnconfirmed || android.registrationIssue, cancel: !!android.registrationCancelClaimed,
        prepared: !!android.toolRegistration?.review, task: 'Android tool inspection and approval' },
      { status: android.toolService, pending: android.servicePending !== null || android.serviceReadPending || android.serviceCancelPending,
        unconfirmed: android.serviceUnconfirmed || android.serviceIssue, cancel: !!android.serviceCancelClaimed,
        prepared: !!android.serviceConsent, task: 'Android tool setup approval' },
    ];
    for (const row of rows) {
      const phase = row.status?.phase;
      const active = phase !== undefined && !['idle', 'complete', 'refused', 'cancelled'].includes(phase);
      if (row.pending || row.unconfirmed || row.prepared || active) add({
        projectId: active || row.prepared ? row.status?.operation?.context.projectId ?? null : null,
        task: row.task, action: { kind: 'open-build-tools', platform: 'android' },
        state: phase === 'unknown' || row.unconfirmed ? 'unknown' : row.cancel || phase === 'stopping' ? 'cancellation-requested' :
          row.prepared && !row.pending ? 'prepared' : 'running',
      });
    }
    const sources = android.toolSources;
    if (android.sourcesPending || android.sourcesReadPending || android.sourcesUnconfirmed || android.sourcesIssue ||
        sources && ['picking', 'checking', 'stopping', 'unknown'].includes(sources.phase)) add({
      projectId: sources && ['picking', 'checking', 'stopping', 'unknown'].includes(sources.phase) ? sources.projectId : null,
      task: 'Choose Android tool folders', action: { kind: 'open-build-tools', platform: 'android' },
      state: sources?.phase === 'unknown' || android.sourcesUnconfirmed || android.sourcesIssue ? 'unknown' :
        android.sourcesCancelClaimed || sources?.phase === 'stopping' ? 'cancellation-requested' : 'running',
    });
    const catalog = android.catalogStatus;
    if (android.catalogPending || android.catalogReadPending || android.catalogCancelPending || android.catalogUnconfirmed || android.catalogIssue ||
        catalog && ['reading', 'stopping', 'unknown'].includes(catalog.phase)) add({
      projectId: null, task: 'Check protected Android tools', action: { kind: 'open-build-tools', platform: 'android' },
      state: catalog?.phase === 'unknown' || android.catalogUnconfirmed || android.catalogIssue ? 'unknown' :
        android.catalogCancelClaimed || catalog?.phase === 'stopping' ? 'cancellation-requested' : 'running',
    });
  }
  const prep = source.toolPreparation, op = prep.status?.operation;
  if (prep.native && (prep.issue || prep.pending || prep.requestPending || prep.reading || prep.cancelPending ||
      op && op.phase !== 'terminal')) add({
    projectId: op && op.phase !== 'terminal' ? op.context.projectId : null, task: 'Prepare Android tools', action: { kind: 'open-build-tools', platform: 'android' },
    state: prep.issue || op?.phase === 'unknown' ? 'unknown' : prep.cancelRequested || prep.cancelSent || op?.phase === 'stopping' ? 'cancellation-requested' :
      prep.consent && !prep.requestPending ? 'prepared' : 'running',
  });
  const diagnostics = source.diagnostics, run = diagnostics.unknownEvidence ?? diagnostics.status?.active ?? diagnostics.attempt?.projection;
  if (diagnostics.mode === 'native' && (diagnostics.nativeBlocked || diagnostics.integrityFailed || diagnostics.generationLost ||
      diagnostics.readPending || diagnostics.attempt?.startPending || diagnostics.status?.active || run && run.finality !== 'settled')) add({
    projectId: run?.context.projectId ?? null, task: 'Check this computer', action: { kind: 'navigate', page: 'environment' },
    state: diagnostics.nativeBlocked || diagnostics.integrityFailed || diagnostics.generationLost || run?.finality === 'unknown' ? 'unknown' :
      diagnostics.cancelClaimed || diagnostics.attempt?.stopRequested ? 'cancellation-requested' : 'running',
  });
  const assets = source.credentials, operation = assets.status?.operation;
  if (assets.mode === 'native' && (assets.blocked || assets.busy || assets.updatingContext || assets.originPending || assets.observing ||
      operation && (operation.phase !== 'idle' || operation.settlement !== 'known'))) {
    const page = operation?.operation === 'choose-project-path' ? 'settings' : operation?.operation === 'choose-images' ? 'metadata' :
      operation?.operation === 'inspect-installation' ? 'environment' : 'credentials';
    add({ projectId: assets.originPending || assets.updatingContext ? null : assets.status?.context?.projectId ?? null,
      task: page === 'credentials' ? 'Signing keys and private inputs' : 'Original file or installation task', action: { kind: 'navigate', page },
      state: assets.blocked || operation?.settlement === 'unknown' || operation?.settlement === 'late-known' ? 'unknown' :
        assets.cancelledOperationId !== null ? 'cancellation-requested' : operation?.preview && !assets.busy ? 'prepared' : 'running' });
  }
  return result;
}

type Project = AndroidBuildState['project'] | IOSArchiveState['project'];
function currentProject(project: Project, session: ProjectSession): boolean {
  return project !== null && project.projectId === session.project.id && project.draftRevision === session.revision &&
    project.baselineGeneration === session.baselineGeneration && project.observationGeneration === session.observationGeneration &&
    !project.dirtyDraft && !project.snapshotPending && !project.versionPending && !project.saveRecoveryRequired &&
    project.savedConfig !== null && sameSavedConfig(project.savedConfig, session.savedConfigContent) && project.inputIssue === null;
}
function buildStatusCurrent(state: AndroidBuildState | IOSArchiveState, session: ProjectSession, pending: boolean): boolean {
  return currentProject(state.project, session) && state.mode === 'native' && state.initialized && state.listening &&
    !state.selectionPending && !state.readPending && !state.pending && !pending && !state.originalUnconfirmed &&
    !state.nativeBlocked && !state.integrityFailed && !state.generationLost && !state.observationIssue && !state.error;
}

export function setupResume(session: ProjectSession | null, preview: boolean, readReason: string | null,
  source: SetupResumeSource): SetupResume {
  const result: SetupResume = { configuration: null, tools: null, build: null, signing: null, reviewBuild: false, completedBuild: null,
    activities: originalActivities(source), facts: [] };
  // The existing app guard covers the other original owners. Do not invent a
  // project, phase or recovery action when their compact controls are the only
  // available projection. It still prevents a superficially successful next step.
  if (source.otherOwnerReason !== null && result.activities.length === 0) result.activities.push({ projectId: null,
    task: 'An existing app task needs attention', state: 'retained', action: { kind: 'show-original-controls' } });
  const view = setupGuidanceView(session, preview, readReason), analysis = view.analysis;
  if (!session || preview) return result;
  if (!analysis || session.snapshot?.discovery.partial) {
    result.configuration = step('Read the saved project again',
      'The saved setup information is old, incomplete or unavailable. Read it again after the original task finishes; your draft stays intact.',
      { label: 'Read project settings', action: { kind: 'refresh-project' }, disabledReason: readReason }, 'Read again');
    return result;
  }
  if (view.savedOnly || analysis.configurationState !== 'format-valid') return result;
  const platform = analysis.platforms.includes(source.platform) ? source.platform : analysis.platforms[0];
  if (!platform) {
    result.configuration = step('Choose the app platform', 'Enable the Android or iOS app you want to build in Project settings.', go('Choose app settings', 'settings'));
    return result;
  }
  // Required local selections come from the existing core rows, not help prose.
  // Detected hints still need an explicit saved choice. Build defaults for
  // variant/configuration and later Store fields are deliberately not blockers.
  const required = new Set(['version-source', `${platform}-identity`, platform === 'android' ? 'android-module' : 'ios-container',
    ...(platform === 'ios' ? ['ios-scheme'] : [])]);
  const missing = analysis.requirements.find((row) => row.stage === 'local' && required.has(row.id) && row.state !== 'configured');
  if (missing) {
    const label = setupRequirementLabels[missing.id];
    result.configuration = { ...step(`Choose ${label}`, `${missing.summary} Open Project settings; use the field’s ? help and native picker. Nothing is changed by this guide.`,
      go(`Review ${label}`, 'settings'), missing.state === 'unsupported' ? 'Manual setup needed' : 'Needs a saved choice'), state: 'needs-action' };
    return result;
  }
  const state = platform === 'android' ? source.android : source.ios;
  const submissionPending = platform === 'android' ? source.androidSubmissionPending : source.iosSubmissionPending;
  const ready = buildStatusCurrent(state, session, submissionPending);
  result.tools = step(platform === 'android' ? 'Continue Android tool setup' : 'Check Xcode for this app', platform === 'android' ?
    'Already installed the JDK, Android SDK or Gradle? Choose those existing folders in Tools, then inspect and review them. A missing selection is not proof you need another download.' :
    'After installing or preparing Xcode, reopen Tools and check it again. A restart, installer message or matching version is not an archive check.',
  tools(platform === 'android' ? 'Review existing Android tools' : 'Review Xcode setup', platform), 'Not checked for a build');
  if (!ready || result.activities.length > 0) return result;
  const op = state.status?.operation;
  // Historical, cancelled, provisional and still-returning outcomes remain in
  // the original result view only. Never turn their data into a new approval.
  if (!state.historical && !state.cancelClaimed && op?.phase === 'terminal' && op.outcome === 'complete' && op.reason === 'none' && op.result &&
      op.context.operation !== 'ios-signing-inputs-check' && 'savedConfig' in op.context &&
      op.context.projectId === session.project.id && op.context.draftRevision === session.revision &&
      op.context.baselineGeneration === session.baselineGeneration && sameSavedConfig(op.context.savedConfig, session.savedConfigContent)) {
    const candidate = op.result.scope === 'local-android-candidate-inputs' || op.result.scope === 'local-ios-candidate-inputs';
    result.completedBuild = candidate ? 'candidate' : 'local';
    result.build = step(candidate ? 'Review your local candidate' : 'Review the local build result', candidate ?
      'This original build kept local candidate inputs. Review the result and Local release history before a later release. Nothing was submitted to a Store.' :
      'This original local build returned a result. Review its checks and limitations; the files have not been re-inspected and no Store release was approved.',
    go(candidate ? 'View candidate and local history' : 'View local build result', 'releases'), 'Result available — local only');
    result.facts.push(candidate ? 'Local candidate result available — not submitted' : 'A local build result is available');
    result.reviewBuild = true;
    return result;
  }
  if (platform === 'android') {
    const android = source.android, catalog = android.catalogStatus;
    const selected = catalog?.selected;
    const selectedHere = android.catalogListening && !android.catalogReadPending && !android.catalogPending && !android.catalogUnconfirmed &&
      !android.catalogCancelPending && !android.catalogIssue && !android.sourcesPending && !android.sourcesUnconfirmed && !android.sourcesIssue &&
      !android.registrationPending && !android.registrationUnconfirmed && !android.registrationIssue && !android.toolRegistration?.review &&
      !android.servicePending && !android.serviceUnconfirmed && !android.serviceIssue && catalog?.phase === 'ready' && catalog.reason === 'none' &&
      catalog.availability === 'available' && selected && catalog.entries.filter((row) => row.status === 'verified-this-session' &&
        sameAndroidCatalogSelection(row.selection, selected)).length === 1;
    if (selectedHere) {
      result.tools = step('Android tool copy selected', 'Your current protected tool copy is selected. Review a local build next; that build still checks this project, its tools and any signing inputs.',
        tools('Review selected Android tools', 'android'), 'Selected — not build-ready');
      result.facts.push('Protected Android tools selected — build checks remain'); result.reviewBuild = true;
    } else if (catalog?.availability === 'available' && catalog.phase === 'ready' &&
        catalog.entries.some((row) => row.status === 'recovery-required' || row.status === 'verified-this-session')) {
      result.tools = step('Check and choose the saved tool copy', 'A previously prepared tool copy is listed. Use its existing check/recovery and Choose controls before preparing another. The list alone is not verification.',
        tools('Review saved Android tools', 'android'), 'Needs a current selection');
    } else if (catalog?.availability === 'unsupported-platform' && state.status?.availability === 'available') {
      result.reviewBuild = true; // Existing non-Mac local route; no Mac-copy claim.
      result.tools = step('Review the available local build', 'This host uses the existing local build checks, not the Mac protected-copy setup. Review that operation’s requirements before running project code.',
        go('Review local build requirements', 'releases'), 'Build checks remain');
    }
  } else if (source.ios.status?.availability === 'available' && source.ios.status.modeCapabilities.unsigned) {
    result.reviewBuild = true;
    result.tools = step('Review the iOS archive requirements', 'The native archive option is available. Its own review and run check Xcode, the SDK and the saved project. A tool-version observation is not an archive result.',
      tools('Review Xcode setup', 'ios'), 'Archive checks remain');
  }
  const signingNeeded = platform === 'android' ? source.android.buildMode === 'signed' : source.ios.archiveMode !== 'unsigned';
  if (signingNeeded) {
    const issue = platform === 'android' ? source.android.signing.issue : source.ios.signing.issue;
    const policyMissing = platform === 'android' ? !source.android.project?.uploadCertificateSha256 : !source.ios.project?.signingPolicy;
    result.signing = step('Signing for your chosen build', issue ?
      'This selected build mode uses signing inputs. Reuse your app’s existing key; check and assign it in Credentials. Missing Store access is a different, later requirement.' :
      'Signing inputs are assigned for this saved build context. The build still validates the key and certificate; assignment alone is not a successful signing check.',
    go(issue && policyMissing ? 'Review signing settings' : 'Review existing signing inputs', issue && policyMissing ? 'settings' : 'credentials'),
    issue ? 'Needed for this signed mode' : 'Assigned — validation remains');
    if (issue && result.reviewBuild) result.build = { ...result.signing, title: 'Prepare signing for this build', state: 'needs-action' };
  }
  return result;
}
