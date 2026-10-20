import { LocalStoreReconcileController, localStoreReconcileOwnerReason } from './localStoreReconcile.ts';
import { LocalStoreReconcile } from './components/LocalStoreReconcile.tsx';
import { LocalStoreExecuteController, localStoreExecuteOwnerReason } from './localStoreExecute.ts';
import { LocalStoreExecute } from './components/LocalStoreExecute.tsx';
import { LocalStorePrepareController, localStorePrepareOwnerReason } from './localStorePrepare.ts';
import { LocalStorePrepare } from './components/LocalStorePrepare.tsx';
import { LocalReleaseHistoryController, localHistoryOwnerReason } from './localReleaseHistory.ts';
import { LocalReleaseHistory } from './components/LocalReleaseHistory.tsx';
import { LocalStorePreflightController, localStoreOwnerReason, localStoreProjectObservation } from './localStorePreflight.ts';
import { LocalStorePreflight } from './components/LocalStorePreflight.tsx';
import { AppleProvisioningController } from './appleProvisioningController.ts';
import { AppleBundleRegistration } from './components/AppleBundleRegistration.tsx';
import { GitHubPublicationController, githubPublicationOwnerReason } from './githubPublicationController.ts';
import { GitHubPublication } from './components/GitHubPublication.tsx';
import { ArtifactInspectionController, artifactInspectionOwnerReason } from './artifactInspection.ts';
import { artifactInspectionError } from './artifactInspectionProtocol.ts';
import { ArtifactInspection } from './components/ArtifactInspection.tsx';
import { ProjectInitializationController } from './projectInitializationController.ts';
import { initializationOwnerReason, initializationRetainsDraft } from './projectInitialization.ts';
import { ProjectInitialization } from './components/ProjectInitialization.tsx';
import { useCallback, useEffect, useId, useRef, useState, useSyncExternalStore } from 'react';
import { desktopApi } from './api.ts';
import { metadataImagesApi } from './metadataImagesApi.ts';
import { apiError } from './bridge.ts';
import { emptyDraft, getValue, isObject, textValue } from './catalog.ts';
import { copyBoundedComparisonData, savedConfigFromSnapshot, sameSavedConfig } from './offlinePreflightProtocol.ts';
import { methodReason, projectSelectionReason } from './certainty.ts';
import { initialWorkspace, isDirty, retainedEditAttention, workspaceReducer } from './drafts.ts';
import type { ProjectSession, RetainedEditAttention, WorkspaceAction } from './drafts.ts';
import { configurationOwnerReason, editRetainsDraft, editStartReason } from './configEdit.ts';
import { ConfigEditController } from './configEditController.ts';
import { GitHubSetupController } from './githubSetupController.ts';
import { EnvironmentController } from './environment.ts';
import { ReleaseVersionController } from './releaseVersion.ts';
import { ExternalProjectObservationController } from './externalProjectObservationController.ts';
import { CliReadAccessController } from './cliReadAccessController.ts';
import { CliReadAccessPanel } from './components/CliReadAccessPanel.tsx';
import { AgentLocalCheckPermission } from './agentLocalChecks.ts';
import { AgentAndroidBuildPermission } from './agentAndroidBuild.ts';
import { AgentAndroidBuildAccess } from './components/AgentAndroidBuildAccess.tsx';
import { AgentLocalCheckAccess } from './components/AgentLocalCheckAccess.tsx';
import { VersionEnrollmentController } from './versionEnrollmentController.ts';
import { VersionEnrollmentPanel } from './components/VersionEnrollmentPanel.tsx';
import { ProjectIdentityNativeController, bindAgentIdentityApi, parseAgentIdentityGuiStatus } from './projectIdentityNative.ts';
import type { ProjectIdentityNativeState, AgentIdentityProposal, AgentIdentityGuiStatus } from './projectIdentityNative.ts';
import { ProjectIdentityController } from './projectIdentityController.ts';
import type { ProjectIdentityUiState } from './projectIdentityController.ts';
import { parseIdentityContext } from './projectIdentity.ts';
import type { IdentitySelection, IdentityUiContext } from './projectIdentity.ts';
import { ProjectIdentityEditor } from './components/ProjectIdentityEditor.tsx';
import { IosAppTargetField } from './components/IosAppTargetField.tsx';
import { copyIosAppTarget, iosAppTargetHints } from './iosAppTargetHints.ts';
import type { IosTargetChoiceContext } from './iosAppTargetHints.ts';
import { ProgressiveDisclosure } from './components/ProgressiveDisclosure.tsx';
import { ReleaseVersionEditController, versionOwnerReason, versionProjectDirty, versionRetainsDraft } from './releaseVersionEditController.ts';
import { versionEditError } from './releaseVersionEdit.ts';
import { ReleaseInputGuidanceController } from './releaseInputGuidance.ts';
import { LifecycleEvidenceController } from './lifecycleEvidence.ts';
import { ReleaseEvidence, ReleaseEvidenceGuidance } from './components/ReleaseEvidence.tsx';
import { EnvironmentDiagnosticsController, diagnosticsOwnerReason } from './environmentDiagnosticsController.ts';
import { OfflinePreflightController, offlinePreflightOwnerReason } from './offlinePreflight.ts';
import { ToolAcquisitionController } from './toolAcquisitionController.ts';
import { PrepareBuildEnvironment } from './components/PrepareBuildEnvironment.tsx';
import type { PrepareBuildEnvironmentProps } from './components/PrepareBuildEnvironment.tsx';
import { offlinePreflightError } from './offlinePreflightProtocol.ts';
import { AndroidBuildController, androidBuildOwnerReason } from './androidBuild.ts';
import { androidBuildError } from './androidBuildProtocol.ts';
import { ProjectRecoveryController, projectRecoveryOwnerReason } from './projectRecoveryController.ts';
import { projectRecoveryError } from './projectRecoveryProtocol.ts';
import { ProjectRecovery } from './components/ProjectRecovery.tsx';
import { IOSArchiveController, iosArchiveOwnerReason } from './iosArchive.ts';
import { iosArchiveError } from './iosArchiveProtocol.ts';
import { GitHubRemoteSetupController, githubRemoteSetupOwnerReason } from './GitHubRemoteSetupController.ts';
import { GitHubRemoteSetup } from './components/GitHubRemoteSetup.tsx';
import { GitReadController } from './gitReadController.ts';
import { GitLocalController } from './gitLocalController.ts';
import { GitLocalChanges, GitLocalControls } from './components/GitLocalChanges.tsx';
import { GitRepositoryController } from './gitRepositoryController.ts';
import { LocalGitRead, LocalGitReadControls } from './components/LocalGitRead.tsx';
import { GitHubConnectionController } from './githubConnectionController.ts';
import { GitHubGhEntryController } from './githubGhEntryController.ts';
import type { GitHubGhApi } from './githubGhEntryProtocol.ts';
import { GitHubPreflightController, githubPreflightOwnerReason } from './githubPreflightController.ts';
import { GitHubReleaseController, githubReleaseOwnerReason } from './githubReleaseController.ts';
import { GitHubHistoryController, githubHistoryOwnerReason } from './githubHistoryController.ts';
import { connectionRepository } from './githubConnectionProtocol.ts';
import type { GitHubConnectionObservationPort, GitHubConnectionTokenHandoff } from './githubConnectionTypes.ts';
import { workflowOwnerReason, workflowRetainsDraft } from './githubWorkflowEdit.ts';
import { GitHubWorkflowEditController } from './githubWorkflowEditController.ts';
import { AssetSessionController } from './assetSessionController.ts';
import { metadataProjectDirty } from './metadataText.ts';
import { MetadataTextEditController, metadataOwnerReason, metadataRetainsDraft } from './metadataTextEditController.ts';
import { MetadataImagesController, metadataImagesAssetSessionReason, metadataImagesOwnerReason } from './metadataImagesController.ts';
import { metadataImagesError } from './metadataImagesProtocol.ts';
import { githubSetupError } from './githubSetupProtocol.ts';
import { suggestionHints } from './preparation.ts';
import { beginProjectPath, finishProjectPath, initialProjectPathState, projectPathAvailabilityReason, projectPathOwnerReason, retireProjectPath } from './projectPaths.ts';
import type { ProjectPathState } from './projectPaths.ts';
import type { ApiError, AppInfo, Catalog, DesktopApi, HelpContent, JsonValue, Page, ProjectPathField } from './types.ts';
import { Badge, ConfirmDialog, ErrorNotice, HelpDialog, PageHeading } from './components/Common.tsx';
import { DraftEditor } from './components/DraftEditor.tsx';
import { ConfigSave } from './components/ConfigSave.tsx';
import { GitHubWorkflowApply } from './components/GitHubWorkflowApply.tsx';
import { GitHubConnection } from './components/GitHubConnection.tsx';
import { GitHubGhEntry } from './components/GitHubGhEntry.tsx';
import { GitHubPreflight } from './components/GitHubPreflight.tsx';
import { GitHubRelease } from './components/GitHubRelease.tsx';
import { GitHubHistory } from './components/GitHubHistory.tsx';
import { MetadataTextEditor, MetadataTextSave } from './components/MetadataTextEditor.tsx';
import { MetadataImagesEditor, MetadataImagesOperation } from './components/MetadataImagesEditor.tsx';
import { ReleaseVersionEditor, ReleaseVersionSave } from './components/ReleaseVersionEditor.tsx';
import { EnvironmentDiagnostics } from './components/EnvironmentDiagnostics.tsx';
import { OfflinePreflight } from './components/OfflinePreflight.tsx';
import { AndroidBuild, AndroidBuildResultView } from './components/AndroidBuild.tsx';
import { IOSArchive, IOSArchiveResultView, IOSRecovery } from './components/IOSArchive.tsx';
import { Icon } from './components/Icon.tsx';
import { WorkspaceNavigation, workspacePages } from './components/WorkspaceNavigation.tsx';
import { Dashboard } from './pages/Dashboard.tsx';
import { Environment } from './pages/Environment.tsx';
import { Credentials } from './pages/Credentials.tsx';
import { Metadata } from './pages/Metadata.tsx';
import { Recovery, Releases } from './pages/Future.tsx';
import { Artifacts } from './pages/Artifacts.tsx';
import { GitHub } from './pages/GitHub.tsx';

interface IdentityInput { platform: 'android' | 'ios'; target: string }
interface IdentityBinding { service: object; native: ProjectIdentityNativeController; ui: ProjectIdentityController; rebindFailed: boolean; proposal: AgentIdentityProposal | null; proposalSeeded: boolean }
const emptyIdentitySubscribe = () => () => {};
const emptyIdentitySnapshot = () => null;

// Only the actual saved configuration supplies source coordinates. This is
// input selection, not a native checkout, Store fact or eligibility decision.
function savedIdentityInput(session: ProjectSession | null, input?: IdentityInput): {
  platform: 'android' | 'ios'; target: string; project: string | null; selection: IdentitySelection | null; reason: string | null;
} {
  let platform = input?.platform ?? 'android';
  const target = input?.target ?? '';
  const unavailable = (reason: string, project: string | null = null) => ({ platform, target, project, selection: null, reason });
  try {
    const snapshot = session?.snapshot, content = savedConfigFromSnapshot(snapshot);
    if (!session || !snapshot || snapshot.root !== session.project.path || !content ||
        !sameSavedConfig(content, session.savedConfigContent) || session.snapshotRequest !== null || session.snapshotError ||
        session.snapshotPredatesSave || session.saveRecoveryRequired || session.saveRecoveryNeedsReload)
      return unavailable('Check the saved project files first. Your unsaved settings are kept separate.');
    const saved = copyBoundedComparisonData(snapshot.config.data, 512 * 1024, 32768);
    if (!isObject(saved)) return unavailable('The saved project settings could not be read. Keep your draft and check the saved files.');
    if (!input && getValue(saved, 'ios.enabled') === true && getValue(saved, 'android.enabled') !== true) platform = 'ios';
    if (getValue(saved, `${platform}.enabled`) !== true)
      return unavailable(`Save the ${platform === 'ios' ? 'iOS' : 'Android'} project settings before reading its app ID.`);
    const module = getValue(saved, 'android.module'), project = getValue(saved, 'ios.project');
    if (platform === 'ios' && getValue(saved, 'ios.workspace') !== undefined)
      return unavailable('This editor supports a saved .xcodeproj without a workspace. For this workspace layout, update the bundle ID in Xcode; do not remove the workspace just to use this editor.');
    const selected = platform === 'android' ? { platform, target: module, project: null, continuity: 'unknown' } :
      { platform, target, project, continuity: 'unknown' };
    const parsed = parseIdentityContext({ projectId: session.project.id, selection: selected, contextEpoch: 0, preview: false, blocked: false });
    if (!parsed?.selection) return unavailable(platform === 'android'
      ? 'Choose and save the real Android app module in project settings. This editor will not assume a module.'
      : 'Use the saved .xcodeproj and enter its exact app target below. A scheme name is not an app target.', typeof project === 'string' ? project : null);
    return { platform, target, project: parsed.selection.project, selection: parsed.selection, reason: null };
  } catch { return unavailable('The saved project settings are not usable for this editor. Keep your draft and check the saved files.'); }
}

export function App() {
  const [api, setApi] = useState<DesktopApi | null>(null);
  const [info, setInfo] = useState<AppInfo | null>(null);
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [loading, setLoading] = useState(true);
  const [bootError, setBootError] = useState<ApiError | null>(null);
  const [catalogError, setCatalogError] = useState<ApiError | null>(null);
  const [choosing, setChoosing] = useState(false);
  const [chooseError, setChooseError] = useState<ApiError | null>(null);
  const [page, setPage] = useState<Page>('dashboard');
  const [cliAccessReveal, setCliAccessReveal] = useState(0);
  const [identityReveal, setIdentityReveal] = useState(0);
  const [releaseCheckFocus, setReleaseCheckFocus] = useState<'offline' | 'android-signing' | null>(null);
  const [help, setHelp] = useState<HelpContent | null>(null);
  const [discardProject, setDiscardProject] = useState<string | null>(null);
  const [workspace, setWorkspace] = useState(initialWorkspace);
  // Explicit application coordinates, never the toolkit inputs or a guessed Git
  // remote. This nonsecret field is in-memory and cleared on project switches.
  const [applicationRepository, setApplicationRepository] = useState('');
  const applicationRepositoryRef = useRef('');
  const connectionDocumentId = useId().replace(/[^A-Za-z0-9_-]/g, '-');
  const connectionProjectGeneration = useRef(1);
  const connectionGenerationLost = useRef(false);
  const connectionPicking = useRef(false);
  const connectionPortRef = useRef<GitHubConnectionObservationPort | null>(null);
  const connectionHandoffRef = useRef<GitHubConnectionTokenHandoff | null>(null);
  const workspaceRef = useRef(workspace);
  const editControllerRef = useRef<ConfigEditController | null>(null);
  const githubControllerRef = useRef<GitHubSetupController | null>(null);
  const environmentControllerRef = useRef<EnvironmentController | null>(null);
  const releaseVersionControllerRef = useRef<ReleaseVersionController | null>(null);
  const versionEditControllerRef = useRef<ReleaseVersionEditController | null>(null);
  const releaseInputControllerRef = useRef<ReleaseInputGuidanceController | null>(null);
  const diagnosticsControllerRef = useRef<EnvironmentDiagnosticsController | null>(null);
  const artifactInspectionControllerRef = useRef<ArtifactInspectionController | null>(null);
  const localHistoryControllerRef = useRef<LocalReleaseHistoryController | null>(null);
  const localStoreControllerRef = useRef<LocalStorePreflightController | null>(null);
  const localStorePrepareControllerRef = useRef<LocalStorePrepareController | null>(null);
  const localStoreExecuteControllerRef = useRef<LocalStoreExecuteController | null>(null);
  const localStoreReconcileControllerRef = useRef<LocalStoreReconcileController | null>(null);
  const appleProvisioningControllerRef = useRef<AppleProvisioningController | null>(null);
  const offlinePreflightControllerRef = useRef<OfflinePreflightController | null>(null);
  const toolAcquisitionControllerRef = useRef<ToolAcquisitionController | null>(null);
  const androidBuildControllerRef = useRef<AndroidBuildController | null>(null);
  const projectRecoveryControllerRef = useRef<ProjectRecoveryController | null>(null);
  const iosArchiveControllerRef = useRef<IOSArchiveController | null>(null);
  const bootstrapPending = useRef(true);
  // Original passive promises outlive retired display request bindings.
  const passivePending = useRef(0);
  const [, setPassivePending] = useState(0);
  const externalObserverRef = useRef<ExternalProjectObservationController | null>(null);
  const cliReadAccessControllerRef = useRef<CliReadAccessController | null>(null);
  const versionEnrollmentRef = useRef<VersionEnrollmentController | null>(null);
  const versionEnrollmentAdmission = useRef<() => string | null>(() => 'Wait for the native service.');
  const versionEnrollmentBusy = useCallback(() => versionEnrollmentRef.current?.ownerReason() ?? null, []);
  // One read coordinator owns the original promises across all pages. Local
  // commit drafts belong to immutable native-service/project ports, not rows.
  const gitLocalRef = useRef<GitLocalController | null>(null);
  const gitLocalAdmission = useRef<() => string | null>(() => 'Wait for the native service.');
  const gitReadRef = useRef<GitReadController | null>(null);
  const gitReadAdmission = useRef<() => string | null>(() => 'Wait for the native service.');
  const gitReadEpoch = useRef(0);
  const gitReadGenerationLost = useRef(false);
  const gitRepositories = useRef<{ service: object; projectId: string; controller: GitRepositoryController }[]>([]);
  const [gitRepository, setGitRepository] = useState<GitRepositoryController | null>(null);
  const syncGitReadRef = useRef<() => void>(() => {});
  // All peers/reconnection include BOTH Git owners. Their own admission below
  // excludes only themselves, never the other original or a retained review.
  const gitBusy = useCallback(() => gitLocalRef.current?.ownerReason() ?? gitReadRef.current?.ownerReason() ?? null, []);
  const retireGitRead = useCallback(() => {
    if (gitReadEpoch.current === Number.MAX_SAFE_INTEGER) gitReadGenerationLost.current = true;
    else gitReadEpoch.current += 1;
    gitLocalRef.current?.beforeContextIntent();
    gitReadRef.current?.beforeContextIntent();
    for (const entry of gitRepositories.current) entry.controller.invalidate();
  }, []);
  const identityRef = useRef<IdentityBinding | null>(null);
  const [identityBinding, setIdentityBinding] = useState<IdentityBinding | null>(null);
  const identityEpoch = useRef(0);
  const [agentObserved, setAgentObserved] = useState<{ service: object; value: AgentIdentityGuiStatus } | null>(null);
  const [agentMessage, setAgentMessage] = useState<{ service: object; text: string } | null>(null);
  const [agentRequestPending, setAgentRequestPending] = useState(false);
  const agentRequestWork = useRef<{ normal: { promise: Promise<unknown> | null; superseded: boolean } | null; revoke: { promise: Promise<unknown> | null; superseded: boolean } | null; epoch: number }>({ normal: null, revoke: null, epoch: 0 });
  const identityInputs = useRef(new Map<string, IdentityInput>());
  const identityTexts = useRef(new Map<string, string>());
  const [, updateIdentityInputs] = useState(0);
  const identityAdmission = useRef<() => string | null>(() => 'Wait for the native service.');
  const identityInvalidation = useRef<(projectId: string) => void>(() => {});
  const identityBusy = useCallback(() => identityRef.current?.rebindFailed
    ? 'The original app ID connection could not be closed reliably. Other tasks remain paused; keep the app open and preserve its project files.'
    : identityRef.current?.native.ownerReason() ?? null, []);
  const retireIdentity = useCallback(() => {
    versionEnrollmentRef.current?.beforeContextIntent();
    retireGitRead();
    identityEpoch.current = Math.min(Number.MAX_SAFE_INTEGER, identityEpoch.current + 1);
    identityRef.current?.native.beforeContextIntent();
    identityRef.current?.ui.retire();
  }, [retireGitRead]);
  const externalBusy = useCallback(() => externalObserverRef.current?.passiveBusyReason() ?? null, []);
  const connectionControllerRef = useRef<GitHubConnectionController | null>(null);
  const githubGhEntryRef = useRef<GitHubGhEntryController | null>(null);
  const githubGhApiRef = useRef<GitHubGhApi | null>(null);
  const githubGhAdmission = useRef<() => string | null>(() => 'Wait for the native service.');
  const githubGhBusy = useCallback(() => githubGhEntryRef.current?.ownerReason() ?? null, []);
  const githubPublicationControllerRef = useRef<GitHubPublicationController | null>(null);
  const githubRemoteSetupControllerRef = useRef<GitHubRemoteSetupController | null>(null);
  const githubPreflightControllerRef = useRef<GitHubPreflightController | null>(null);
  const githubReleaseControllerRef = useRef<GitHubReleaseController | null>(null);
  const githubHistoryControllerRef = useRef<GitHubHistoryController | null>(null);
  const connectionHelpGeneration = useRef<object>({});
  const initializationControllerRef = useRef<ProjectInitializationController | null>(null);
  const workflowControllerRef = useRef<GitHubWorkflowEditController | null>(null);
  const assetControllerRef = useRef<AssetSessionController | null>(null);
  const metadataControllerRef = useRef<MetadataTextEditController | null>(null);
  const imageControllerRef = useRef<MetadataImagesController | null>(null);
  const [pathPicker, setPathPicker] = useState(initialProjectPathState);
  const pathPickerRef = useRef(pathPicker);
  // Object identity is a service generation, including reconnect-away-and-back.
  const pathService = useRef<{ api: DesktopApi | null; info: AppInfo | null }>({ api: null, info: null });
  // Retain the original native port through a failed/rejected reconnect so
  // turning OFF an existing grant remains possible. Only a successful binding
  // replaces it; Allow also requires the current ordinary service binding.
  const cliService = useRef<{ api: DesktopApi | null; info: AppInfo | null }>({ api: null, info: null });
  // Never adopt an earlier Desktop instance's proposal/status after reconnect.
  const agentRequests = agentObserved?.service === pathService.current ? agentObserved.value : null;
  const agentRequestMessage = agentMessage?.service === pathService.current || agentMessage?.service === cliService.current ? agentMessage?.text ?? null : null;
  const publishPathPicker = useCallback((next: ProjectPathState) => { pathPickerRef.current = next; setPathPicker(next); }, []);
  const retirePathPicker = useCallback(() => {
    const next = retireProjectPath(pathPickerRef.current);
    if (next !== pathPickerRef.current) publishPathPicker(next);
  }, [publishPathPicker]);
  const artifactBusy = useCallback(() => artifactInspectionControllerRef.current ? artifactInspectionOwnerReason(artifactInspectionControllerRef.current.getSnapshot()) : null, []);
  const localHistoryBusy = useCallback(() => localHistoryControllerRef.current ? localHistoryOwnerReason(localHistoryControllerRef.current.getSnapshot()) : null, []);
  const storePrepareBusy = useCallback(() => localStorePrepareControllerRef.current ? localStorePrepareOwnerReason(localStorePrepareControllerRef.current.getSnapshot()) : null, []);
  const storeExecuteBusy = useCallback(() => localStoreExecuteControllerRef.current ? localStoreExecuteOwnerReason(localStoreExecuteControllerRef.current.getSnapshot()) : null, []);
  const storeReconcileBusy = useCallback(() => localStoreReconcileControllerRef.current ? localStoreReconcileOwnerReason(localStoreReconcileControllerRef.current.getSnapshot()) : null, []);
  const storeWithoutAppleBusy = useCallback(() => storeReconcileBusy() ?? storeExecuteBusy() ?? storePrepareBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null), [storeReconcileBusy, storeExecuteBusy, storePrepareBusy]);
  const appleProvisioningBusy = useCallback(() => appleProvisioningControllerRef.current?.ownerReason() ?? null, []);
  const storeBusy = useCallback(() => appleProvisioningBusy() ?? storeWithoutAppleBusy(), [appleProvisioningBusy, storeWithoutAppleBusy]);
  const toolPreparationBusy = useCallback(() => toolAcquisitionControllerRef.current?.ownerReason() ?? null, []);
  const preflightBusy = useCallback(() => offlinePreflightControllerRef.current ? offlinePreflightOwnerReason(offlinePreflightControllerRef.current.getSnapshot()) : null, []);
  const androidBusy = useCallback(() => androidBuildControllerRef.current ? androidBuildOwnerReason(androidBuildControllerRef.current.getSnapshot()) : null, []);
  const iosBusy = useCallback(() => iosArchiveControllerRef.current ? iosArchiveOwnerReason(iosArchiveControllerRef.current.getSnapshot()) : null, []);
  const recoveryBusy = useCallback(() => projectRecoveryControllerRef.current ? projectRecoveryOwnerReason(projectRecoveryControllerRef.current.getSnapshot()) : null, []);
  const historyBusy = useCallback(() => githubHistoryControllerRef.current ? githubHistoryOwnerReason(githubHistoryControllerRef.current.getSnapshot()) : null, []);
  // Existing reciprocal admission callbacks also retain the original path
  // picker, even after its display eligibility was retired by a local edit.
  const savedOwnersWithoutToolsBusy = useCallback((excludeVersion = false, excludeGitHubPreflight = false, excludeGitHubRelease = false, excludeImages = false, excludeInitialization = false, excludeRemoteSetup = false, excludeHistory = false, excludePublication = false) => localHistoryBusy() ?? storeBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? iosBusy() ?? recoveryBusy() ??
    (excludeHistory ? null : historyBusy()) ??
    (!excludePublication && githubPublicationControllerRef.current ? githubPublicationOwnerReason(githubPublicationControllerRef.current.getSnapshot()) : null) ??
    (!excludeRemoteSetup && githubRemoteSetupControllerRef.current ? githubRemoteSetupOwnerReason(githubRemoteSetupControllerRef.current.getSnapshot()) : null) ??
    (!excludeGitHubPreflight && githubPreflightControllerRef.current ? githubPreflightOwnerReason(githubPreflightControllerRef.current.getSnapshot()) : null) ??
    (!excludeGitHubRelease && githubReleaseControllerRef.current ? githubReleaseOwnerReason(githubReleaseControllerRef.current.getSnapshot()) : null) ?? projectPathOwnerReason(pathPickerRef.current) ??
    (!excludeInitialization && initializationControllerRef.current ? initializationOwnerReason(initializationControllerRef.current.getSnapshot(),workspaceRef.current.selectedId??'') : null) ??
    (!excludeVersion && versionEditControllerRef.current ? versionOwnerReason(versionEditControllerRef.current.getSnapshot(), workspaceRef.current.selectedId ?? '') : null) ??
    (!excludeImages && imageControllerRef.current ? metadataImagesOwnerReason(imageControllerRef.current.getSnapshot(), workspaceRef.current.selectedId ?? '') : null), [localHistoryBusy, storeBusy, artifactBusy, preflightBusy, androidBusy, recoveryBusy, iosBusy, historyBusy]);
  // Tools excludes only itself. Existing peers, passive observation and every
  // ordinary mutation admission include the original tool operation below.
  const savedOwnersBusy = useCallback((...args: Parameters<typeof savedOwnersWithoutToolsBusy>) =>
    toolPreparationBusy() ?? savedOwnersWithoutToolsBusy(...args), [toolPreparationBusy, savedOwnersWithoutToolsBusy]);
  // Every existing new-action/read admission includes the actual passive
  // original. Only the observer itself uses the underlying owner-only helper.
  const savedCommandBusy = useCallback((...args: Parameters<typeof savedOwnersBusy>) =>
    versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy(...args) ?? externalBusy() ?? cliReadAccessControllerRef.current?.pendingReason() ?? null, [versionEnrollmentBusy, gitBusy, githubGhBusy, identityBusy, savedOwnersBusy, externalBusy]);
  const syncConnectionContext = useCallback(() => {
    const selected = workspaceRef.current.selectedId;
    const project = selected && Object.hasOwn(workspaceRef.current.projects, selected) ? workspaceRef.current.projects[selected] : null;
    // Renderer IDs/generations correlate the view only. The native command gets
    // neither documentId nor projectGeneration and rechecks its actual owner.
    connectionControllerRef.current?.setContext(project && !connectionPicking.current && connectionPortRef.current?.mode === 'native' &&
      !connectionGenerationLost.current && connectionRepository(applicationRepositoryRef.current) ? {
        documentId: connectionDocumentId, projectId: project.project.id,
        projectGeneration: connectionProjectGeneration.current, repository: applicationRepositoryRef.current,
      } : null);
    githubGhEntryRef.current?.syncContext();
    versionEnrollmentRef.current?.syncContext();
  }, [connectionDocumentId]);
  const advanceConnectionContext = () => {
    if (connectionProjectGeneration.current === 0xffff_ffff) connectionGenerationLost.current = true;
    else connectionProjectGeneration.current += 1;
  };
  // Keep the reducer's latest state synchronously visible to save admission.
  // A React render/effect delay must not let an older review authorize Apply.
  const dispatch = useCallback((action: WorkspaceAction) => {
    githubGhEntryRef.current?.beforeContextIntent();
    retireIdentity();
    externalObserverRef.current?.beforeWorkspaceAction();
    cliReadAccessControllerRef.current?.invalidateContext();
    // Intent/event retirement must precede even an unchanged reducer result:
    // failed refresh and unchanged/older saves need not advance generations.
    retirePathPicker();
    githubPublicationControllerRef.current?.beforeWorkspaceAction();
    githubRemoteSetupControllerRef.current?.beforeWorkspaceAction();
    githubHistoryControllerRef.current?.beforeWorkspaceAction();
    artifactInspectionControllerRef.current?.beforeWorkspaceAction(action);
    toolAcquisitionControllerRef.current?.beforeWorkspaceAction(action);
    offlinePreflightControllerRef.current?.beforeWorkspaceAction(action); localStoreControllerRef.current?.beforeWorkspaceAction(); localStorePrepareControllerRef.current?.beforeWorkspaceAction(); localStoreExecuteControllerRef.current?.beforeWorkspaceAction(); localStoreReconcileControllerRef.current?.beforeWorkspaceAction(); localHistoryControllerRef.current?.beforeWorkspaceAction(); appleProvisioningControllerRef.current?.beforeWorkspaceAction();
    androidBuildControllerRef.current?.beforeWorkspaceAction(action);
    projectRecoveryControllerRef.current?.beforeWorkspaceAction(action);
    iosArchiveControllerRef.current?.beforeWorkspaceAction(action);
    releaseVersionControllerRef.current?.beforeWorkspaceAction(action);
    versionEditControllerRef.current?.beforeWorkspaceAction(action);
    metadataControllerRef.current?.beforeWorkspaceAction(action);
    releaseInputControllerRef.current?.beforeWorkspaceAction(action);
    imageControllerRef.current?.beforeWorkspaceAction(action);
    editControllerRef.current?.beforeWorkspaceAction(action);
    initializationControllerRef.current?.beforeWorkspaceAction(action);
    const previous = workspaceRef.current;
    const next = workspaceReducer(previous, action);
    if (next === previous) return;
    if (next.selectedId !== previous.selectedId) {
      // Retire before publishing the project change; even away-and-back cannot
      // adopt an older catalogue reply. No native document/session is invented.
      connectionHelpGeneration.current = {};
      connectionControllerRef.current?.setHelp(null);
      connectionControllerRef.current?.setContext(null);
      if (connectionProjectGeneration.current === 0xffff_ffff) connectionGenerationLost.current = true;
      else connectionProjectGeneration.current += 1;
      applicationRepositoryRef.current = ''; setApplicationRepository('');
    }
    workspaceRef.current = next;
    syncGitReadRef.current();
    identityRef.current?.ui.sync();
    cliReadAccessControllerRef.current?.syncContext();
    versionEnrollmentRef.current?.syncContext();
    externalObserverRef.current?.syncContext();
    environmentControllerRef.current?.syncProject();
    releaseVersionControllerRef.current?.syncProject();
    versionEditControllerRef.current?.syncProject();
    releaseInputControllerRef.current?.syncProject();
    diagnosticsControllerRef.current?.syncProject();
    artifactInspectionControllerRef.current?.syncProject();
    offlinePreflightControllerRef.current?.syncProject(); localStoreControllerRef.current?.syncProject(); localStorePrepareControllerRef.current?.syncProject(); localStoreExecuteControllerRef.current?.syncProject(); localStoreReconcileControllerRef.current?.syncProject(); localHistoryControllerRef.current?.syncProject(); appleProvisioningControllerRef.current?.syncProject();
    androidBuildControllerRef.current?.syncProject();
    toolAcquisitionControllerRef.current?.syncProject();
    projectRecoveryControllerRef.current?.syncProject();
    iosArchiveControllerRef.current?.syncProject();
    metadataControllerRef.current?.syncProject();
    imageControllerRef.current?.syncProject();
    assetControllerRef.current?.syncProject();
    setWorkspace(next);
    githubControllerRef.current?.syncProject();
    workflowControllerRef.current?.syncContext();
    initializationControllerRef.current?.syncContext();
    editControllerRef.current?.syncDraft();
    syncConnectionContext();
    githubHistoryControllerRef.current?.syncContext();
  }, [syncConnectionContext, retirePathPicker, retireIdentity]);
  const [configEdit] = useState(() => new ConfigEditController({
    project: (projectId) => Object.hasOwn(workspaceRef.current.projects, projectId) ? workspaceRef.current.projects[projectId] ?? null : null,
    otherEditReason: (projectId) => savedCommandBusy() ?? (diagnosticsControllerRef.current ? diagnosticsOwnerReason(diagnosticsControllerRef.current.getSnapshot()) : null) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null),
    selectedProject: () => { const w = workspaceRef.current; return w.selectedId ? w.projects[w.selectedId] ?? null : null; },
    recoveryUnavailable: () => versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ?? externalBusy() ?? (passivePending.current > 0 || connectionPicking.current ? 'Finish the original observation or project selection first.' :
      !pathService.current.api || !pathService.current.info ? 'Wait for the current service capabilities.' : null),
    onRecovered: (completion) => dispatch({ type: 'config-recovery-final', projectId: completion.binding.projectId, completion }),
    onConfirmedSave: (receipt) => dispatch({ type: 'config-save-final', projectId: receipt.binding.projectId, receipt }),
    onRecoveryRequired: (attention) => dispatch({ type: 'config-save-recovery', projectId: attention.projectId, attention }),
  }));
  editControllerRef.current = configEdit;
  const saveState = useSyncExternalStore(configEdit.subscribe, configEdit.getSnapshot, configEdit.getSnapshot);
  const [githubSetup] = useState(() => new GitHubSetupController(() => {
    const current = workspaceRef.current;
    return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
  }, () => { workflowControllerRef.current?.syncContext(); initializationControllerRef.current?.syncContext(); }, savedCommandBusy));
  githubControllerRef.current = githubSetup;
  const githubState = useSyncExternalStore(githubSetup.subscribe, githubSetup.getSnapshot, githubSetup.getSnapshot);
  const [environment] = useState(() => new EnvironmentController(() => {
    const current = workspaceRef.current;
    return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
  }, savedCommandBusy));
  environmentControllerRef.current = environment;
  const environmentState = useSyncExternalStore(environment.subscribe, environment.getSnapshot, environment.getSnapshot);
  const [releaseVersion] = useState(() => new ReleaseVersionController(() => {
    const current = workspaceRef.current;
    return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
  }, (projectId) => configurationOwnerReason(configEdit.getSnapshot(), projectId) !== null, savedCommandBusy));
  releaseVersionControllerRef.current = releaseVersion;
  const releaseVersionState = useSyncExternalStore(releaseVersion.subscribe, releaseVersion.getSnapshot, releaseVersion.getSnapshot);
  const [releaseInputs] = useState(() => new ReleaseInputGuidanceController(() => {
    const current = workspaceRef.current;
    return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
  }, (projectId) => configurationOwnerReason(configEdit.getSnapshot(), projectId) !== null, () => setHelp(null), savedCommandBusy));
  releaseInputControllerRef.current = releaseInputs;
  const releaseInputState = useSyncExternalStore(releaseInputs.subscribe, releaseInputs.getSnapshot, releaseInputs.getSnapshot);
  const [diagnostics] = useState(() => new EnvironmentDiagnosticsController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherOperationReason: () => {
      const saved = savedCommandBusy(); if (saved) return saved;
      const projectId = workspaceRef.current.selectedId ?? '';
      const edits = configurationOwnerReason(configEdit.getSnapshot(), projectId) ??
        (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
        (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null);
      if (edits) return edits;
      const assets = assetControllerRef.current?.getSnapshot();
      return assets && (assets.blocked || assets.observationFailed || assets.busy || assets.updatingContext ||
        assets.status?.operation && (assets.status.operation.phase !== 'idle' || assets.status.operation.settlement !== 'known'))
        ? 'A credential-session operation is active or unverified. Finish or cancel it before checking build tools.' : null;
    },
  }));
  diagnosticsControllerRef.current = diagnostics;
  const diagnosticsState = useSyncExternalStore(diagnostics.subscribe, diagnostics.getSnapshot, diagnostics.getSnapshot);
  // Safe observation is separate from the compiled-disabled token entry path.
  const [githubConnection] = useState(() => new GitHubConnectionController(savedCommandBusy));
  connectionControllerRef.current = githubConnection;
  const connectionState = useSyncExternalStore(githubConnection.subscribe, githubConnection.getSnapshot, githubConnection.getSnapshot);
  const [githubGhEntry] = useState(() => new GitHubGhEntryController(githubConnection, {
    current: () => ({ api: githubGhApiRef.current, port: connectionPortRef.current,
      context: connectionControllerRef.current?.getSnapshot().context ?? null, blocked: githubGhAdmission.current() }),
  }));
  githubGhEntryRef.current = githubGhEntry;
  const githubGhState = useSyncExternalStore(githubGhEntry.subscribe, githubGhEntry.getSnapshot, githubGhEntry.getSnapshot);
  const originalConnection = connectionState.status ?? connectionState.retained;
  const [versionEnrollment] = useState(() => new VersionEnrollmentController({ current: () => {
    const service = pathService.current;
    return { port: service.api?.mode === 'native' ? service.api.versionEnrollment ?? null : null,
      nativeSession: service.api?.mode === 'native' ? service : null,
      projectId: connectionPicking.current ? null : workspaceRef.current.selectedId,
      preview: service.api?.mode === 'preview', blockedReason: versionEnrollmentAdmission.current() };
  } }));
  versionEnrollmentRef.current = versionEnrollment;
  const versionEnrollmentState = useSyncExternalStore(versionEnrollment.subscribe, versionEnrollment.getSnapshot, versionEnrollment.getSnapshot);
  useEffect(() => { versionEnrollment.syncContext(); });
  const [githubPublication] = useState(() => new GitHubPublicationController(githubConnection.getSnapshot, () => {
    const projectId = workspaceRef.current.selectedId ?? '';
    const session = projectId ? workspaceRef.current.projects[projectId] : null;
    return savedCommandBusy(false, false, false, false, false, false, false, true) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null) ??
      (!session ? 'Select the original project first.' : null);
  }));
  githubPublicationControllerRef.current = githubPublication;
  const githubPublicationState = useSyncExternalStore(githubPublication.subscribe, githubPublication.getSnapshot, githubPublication.getSnapshot);
  const [githubRemoteSetup] = useState(() => new GitHubRemoteSetupController(githubConnection.getSnapshot, () => {
    const projectId = workspaceRef.current.selectedId ?? '';
    return savedCommandBusy(false, false, false, false, false, true) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null);
  }, () => assetControllerRef.current?.getSnapshot() ?? null));
  githubRemoteSetupControllerRef.current = githubRemoteSetup;
  const githubRemoteSetupState = useSyncExternalStore(githubRemoteSetup.subscribe, githubRemoteSetup.getSnapshot, githubRemoteSetup.getSnapshot);
  const [githubPreflight] = useState(() => new GitHubPreflightController(githubConnection.getSnapshot, () => {
    const projectId = workspaceRef.current.selectedId ?? '';
    return savedCommandBusy(false, true) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null);
  }));
  githubPreflightControllerRef.current = githubPreflight;
  const githubPreflightState = useSyncExternalStore(githubPreflight.subscribe, githubPreflight.getSnapshot, githubPreflight.getSnapshot);
  const [githubRelease] = useState(() => new GitHubReleaseController(githubConnection.getSnapshot, () => {
    const projectId = workspaceRef.current.selectedId ?? '';
    return savedCommandBusy(false, false, true) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null);
  }));
  githubReleaseControllerRef.current = githubRelease;
  const githubReleaseState = useSyncExternalStore(githubRelease.subscribe, githubRelease.getSnapshot, githubRelease.getSnapshot);
  const [githubHistory] = useState(() => new GitHubHistoryController({
    connection: githubConnection.getSnapshot,
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    // Exclude only this owner and the idle connected session it requires.
    // The unchanged controller and native owner both admit that actual context.
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? savedCommandBusy(false, false, false, false, false, false, true) ??
      savedCommandPrerequisiteReason(false, false, undefined, false, true),
  }));
  githubHistoryControllerRef.current = githubHistory;
  const githubHistoryState = useSyncExternalStore(githubHistory.subscribe, githubHistory.getSnapshot, githubHistory.getSnapshot);
  const [workflowEdit] = useState(() => new GitHubWorkflowEditController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    setup: githubSetup.getSnapshot,
    otherEditReason: (projectId) => savedCommandBusy() ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null),
  }));
  workflowControllerRef.current = workflowEdit;
  const workflowState = useSyncExternalStore(workflowEdit.subscribe, workflowEdit.getSnapshot, workflowEdit.getSnapshot);
  const [initialization] = useState(() => new ProjectInitializationController({
    selectedProject:()=>{const w=workspaceRef.current;return w.selectedId?w.projects[w.selectedId]??null:null;},
    setup:githubSetup.getSnapshot,
    otherEditReason:()=>savedCommandBusy(false,false,false,false,true)??savedCommandPrerequisiteReason(false,false,undefined,true),
    onApplyIntent:projectId=>{
      dispatch({type:'initialization-intent',projectId});
      retirePathPicker(); releaseVersionControllerRef.current?.saveIntent(); releaseInputControllerRef.current?.saveIntent();
      toolAcquisitionControllerRef.current?.versionIntent();
      androidBuildControllerRef.current?.versionIntent();offlinePreflightControllerRef.current?.versionIntent(); localStoreControllerRef.current?.versionIntent(); localStorePrepareControllerRef.current?.versionIntent(); localStoreExecuteControllerRef.current?.versionIntent(); localStoreReconcileControllerRef.current?.versionIntent(); localHistoryControllerRef.current?.versionIntent(); appleProvisioningControllerRef.current?.versionIntent(); artifactInspectionControllerRef.current?.versionIntent();projectRecoveryControllerRef.current?.versionIntent();iosArchiveControllerRef.current?.versionIntent();
    },
    onConfirmed:completion=>dispatch({type:'initialization-final',projectId:completion.binding.projectId,completion}),
  }));
  initializationControllerRef.current=initialization;
  const initializationState=useSyncExternalStore(initialization.subscribe,initialization.getSnapshot,initialization.getSnapshot);
  const [metadataText] = useState(() => new MetadataTextEditController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherEditReason: (projectId) => savedCommandBusy() ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ?? workflowOwnerReason(workflowEdit.getSnapshot(), projectId),
    otherOperationReason: savedCommandBusy,
    onRecoveryBoundary: () => {
      // Recovery changes persisted saved-file facts, never the retained draft.
      // Invalidate existing passive/build consent; no replacement Read is made.
      releaseVersion.saveIntent(); releaseInputs.saveIntent();
      toolAcquisitionControllerRef.current?.versionIntent();
      androidBuildControllerRef.current?.versionIntent(); offlinePreflightControllerRef.current?.versionIntent(); localStoreControllerRef.current?.versionIntent(); localStorePrepareControllerRef.current?.versionIntent(); localStoreExecuteControllerRef.current?.versionIntent(); localStoreReconcileControllerRef.current?.versionIntent(); localHistoryControllerRef.current?.versionIntent(); appleProvisioningControllerRef.current?.versionIntent(); artifactInspectionControllerRef.current?.versionIntent(); projectRecoveryControllerRef.current?.versionIntent(); iosArchiveControllerRef.current?.versionIntent();
    },
  }));
  metadataControllerRef.current = metadataText;
  const metadataState = useSyncExternalStore(metadataText.subscribe, metadataText.getSnapshot, metadataText.getSnapshot);
  const [metadataImages] = useState(() => new MetadataImagesController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    // Exclude only this retained image owner. All other domains include it, and
    // native registration independently enforces the same reciprocal admission.
    otherOperationReason: (step) => savedCommandBusy(false, false, false, true) ?? savedCommandPrerequisiteReason(false, true, step),
  }));
  imageControllerRef.current = metadataImages;
  const metadataImagesState = useSyncExternalStore(metadataImages.subscribe, metadataImages.getSnapshot, metadataImages.getSnapshot);
  const [versionEdit] = useState(() => new ReleaseVersionEditController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    project: (projectId) => Object.hasOwn(workspaceRef.current.projects, projectId) ? workspaceRef.current.projects[projectId] ?? null : null,
    // Excluding this controller avoids turning its own retained checkout into a
    // conflicting operation. All other consumers include the version owner.
    otherEditReason: (projectId) => savedCommandBusy(true) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ??
      configurationOwnerReason(configEdit.getSnapshot(), projectId) ?? workflowOwnerReason(workflowEdit.getSnapshot(), projectId) ??
      metadataOwnerReason(metadataText.getSnapshot(), projectId),
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? savedCommandPrerequisiteReason(true),
    onSaveBoundary: () => {
      retireGitRead();
      // Retire before the submitted intent/outcome can notify subscribers, even
      // for unchanged, failed or out-of-context saves. Never fabricate a Read.
      releaseVersion.saveIntent(); releaseInputs.saveIntent();
      toolAcquisitionControllerRef.current?.versionIntent();
      androidBuildControllerRef.current?.versionIntent(); offlinePreflightControllerRef.current?.versionIntent(); localStoreControllerRef.current?.versionIntent(); localStorePrepareControllerRef.current?.versionIntent(); localStoreExecuteControllerRef.current?.versionIntent(); localStoreReconcileControllerRef.current?.versionIntent(); localHistoryControllerRef.current?.versionIntent(); appleProvisioningControllerRef.current?.versionIntent(); artifactInspectionControllerRef.current?.versionIntent(); projectRecoveryControllerRef.current?.versionIntent(); iosArchiveControllerRef.current?.versionIntent();
    },
  }));
  versionEditControllerRef.current = versionEdit;
  const versionEditState = useSyncExternalStore(versionEdit.subscribe, versionEdit.getSnapshot, versionEdit.getSnapshot);
  const [assetSession] = useState(() => new AssetSessionController(() => {
    const current = workspaceRef.current;
    return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
  }, undefined, savedCommandBusy));
  assetControllerRef.current = assetSession;
  const assetState = useSyncExternalStore(assetSession.subscribe, assetSession.getSnapshot, assetSession.getSnapshot);
  // Evidence selection has deliberately no source-project or draft callback.
  const [releaseEvidence] = useState(() => new LifecycleEvidenceController(savedCommandBusy));
  const evidenceState = useSyncExternalStore(releaseEvidence.subscribe, releaseEvidence.getSnapshot, releaseEvidence.getSnapshot);
  const savedOwnersPrerequisiteReason = (excludeVersion = false, excludeImages = false, imageStep?: 'open-held-selection', excludeInitialization = false, forHistoryRead = false, forGhEntry = false): string | null => {
    const pathOwner = projectPathOwnerReason(pathPickerRef.current); if (pathOwner) return pathOwner;
    if (bootstrapPending.current || connectionPicking.current) return 'Finish the original service or project-selection request before browsing or reviewing saved checks.';
    const projectId = workspaceRef.current.selectedId ?? '';
    const owned = (forHistoryRead ? null : historyBusy()) ?? (excludeInitialization?null:initializationOwnerReason(initialization.getSnapshot(),projectId)) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ?? workflowOwnerReason(workflowEdit.getSnapshot(), projectId) ??
      metadataOwnerReason(metadataText.getSnapshot(), projectId) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ??
      (excludeVersion ? null : versionOwnerReason(versionEdit.getSnapshot(), projectId)) ??
      (excludeImages ? null : metadataImagesOwnerReason(metadataImages.getSnapshot(), projectId));
    if (owned) return owned;
    const assets = assetSession.getSnapshot();
    const assetReason = metadataImagesAssetSessionReason(assets, imageStep);
    if (assetReason) return assetReason;
    const evidence = releaseEvidence.getSnapshot();
    if (evidence.integrityFailed || evidence.uncertain || evidence.pending || evidence.cancelling ||
        evidence.status && ['choosing', 'observing', 'stopping', 'unknown'].includes(evidence.status.phase))
      return 'An original evidence operation is active or unverified. Evidence selection is not source-project authority.';
    const publicationReason = githubPublicationOwnerReason(githubPublication.getSnapshot());
    if (publicationReason) return publicationReason;
    const remoteSetupReason = githubRemoteSetupOwnerReason(githubRemoteSetup.getSnapshot());
    if (remoteSetupReason) return remoteSetupReason;
    const connection = githubConnection.getSnapshot();
    // History is read-only work inside this original connected session, not a
    // saved-code grant. Busy/unknown/retirement checks are never exempted.
    if (!forGhEntry && (connection.blocked || connection.uncertain || connection.busy || connection.retirementPending || !forHistoryRead && (connection.status ?? connection.retained)?.session))
      return 'Finish or disconnect the original GitHub session before starting saved project code.';
    if (passivePending.current > 0 || Object.values(workspaceRef.current.projects).some((project) => project.snapshotRequest !== null || project.validationRequest || project.reviewRequest || project.suggestionRequest) ||
        environment.getSnapshot().pending || environment.passiveBusyReason() || releaseVersion.getSnapshot().pending || releaseVersion.passiveBusyReason() ||
        releaseInputs.getSnapshot().pending || releaseInputs.passiveBusyReason() || githubSetup.getSnapshot().pending || githubSetup.passiveBusyReason() || metadataText.passiveBusyReason() ||
        !excludeImages && metadataImages.passiveBusyReason())
      return 'An original passive project query is still pending. Wait for it to settle before reviewing saved checks.';
    return null;
  };
  // This one action borrows the current authenticated connection, not a
  // saved-code grant. Exclude only enrollment itself from reciprocal busy checks.
  versionEnrollmentAdmission.current = () => {
    const blocked = gitBusy() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy() ??
      savedOwnersPrerequisiteReason(false, false, undefined, false, true) ?? externalBusy() ??
      cliReadAccessControllerRef.current?.pendingReason();
    if (blocked) return blocked;
    if (githubPreflight.getSnapshot().status?.prepared || githubRelease.getSnapshot().status?.prepared)
      return 'Finish the prepared GitHub review before connecting a shared counter.';
    const connection = githubConnection.getSnapshot(), selected = workspaceRef.current.selectedId;
    const current = connection.status;
    return current?.session?.state === 'connected' && current.session.projectId === selected &&
      connection.context?.projectId === selected && current.account.state === 'observed' &&
      current.repository.state === 'observed' ? null : 'Connect the intended GitHub account and repository first.';
  };
  // Identity excludes ONLY itself; all original passive/private/build owners
  // and retained GitHub reviews still block a new source edit.
  identityAdmission.current = () => versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? savedOwnersBusy() ?? savedOwnersPrerequisiteReason() ?? externalBusy() ??
    cliReadAccessControllerRef.current?.pendingReason() ??
    (githubPreflight.getSnapshot().status?.prepared || githubRelease.getSnapshot().status?.prepared
      ? 'Finish the prepared GitHub review before editing the app ID.' : null);
  // This coupled entry excludes only its own picker work and the existing
  // Connect latch. That controller independently checks its original idle
  // session before latching, then retains the exact handoff before native IPC.
  githubGhAdmission.current = () => versionEnrollmentBusy() ?? gitBusy() ?? identityBusy() ?? savedOwnersBusy() ??
    savedOwnersPrerequisiteReason(false, false, undefined, false, false, true) ?? externalBusy() ??
    cliReadAccessControllerRef.current?.pendingReason() ??
    (githubPreflight.getSnapshot().status?.prepared || githubRelease.getSnapshot().status?.prepared
      ? 'Finish the prepared GitHub review before connecting another account.' : null);
  const savedCommandPrerequisiteReason = (...args: Parameters<typeof savedOwnersPrerequisiteReason>): string | null =>
    versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? toolPreparationBusy() ?? identityBusy() ?? savedOwnersPrerequisiteReason(...args) ?? externalBusy() ?? cliReadAccessControllerRef.current?.pendingReason() ?? null;
  const [artifactInspection] = useState(() => new ArtifactInspectionController({
    selectedProject: () => {
      const current=workspaceRef.current;
      return current.selectedId&&Object.hasOwn(current.projects,current.selectedId)?current.projects[current.selectedId]??null:null;
    },
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  artifactInspectionControllerRef.current=artifactInspection;
  const artifactInspectionState=useSyncExternalStore(artifactInspection.subscribe,artifactInspection.getSnapshot,artifactInspection.getSnapshot);
  const [offlinePreflight] = useState(() => new OfflinePreflightController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? artifactBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  offlinePreflightControllerRef.current = offlinePreflight;
  const offlinePreflightState = useSyncExternalStore(offlinePreflight.subscribe, offlinePreflight.getSnapshot, offlinePreflight.getSnapshot);
  const [androidBuild] = useState(() => new AndroidBuildController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    releaseVersion: releaseVersion.getSnapshot,
    assetSession: assetSession.getSnapshot,
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? artifactBusy() ?? preflightBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  androidBuildControllerRef.current = androidBuild;
  const androidBuildState = useSyncExternalStore(androidBuild.subscribe, androidBuild.getSnapshot, androidBuild.getSnapshot);
  const [toolAcquisition] = useState(() => new ToolAcquisitionController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherOperationReason: () => versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersWithoutToolsBusy() ?? savedOwnersPrerequisiteReason() ??
      externalBusy() ?? cliReadAccessControllerRef.current?.pendingReason() ?? null,
    knownTools: () => {
      const state = androidBuildControllerRef.current?.getSnapshot();
      return [state?.catalogStatus ?? null, state?.toolSources ?? null, state?.toolRegistration ?? null];
    },
  }));
  toolAcquisitionControllerRef.current = toolAcquisition;
  const toolAcquisitionState = useSyncExternalStore(toolAcquisition.subscribe, toolAcquisition.getSnapshot, toolAcquisition.getSnapshot);
  const [projectRecovery] = useState(() => new ProjectRecoveryController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  projectRecoveryControllerRef.current = projectRecovery;
  const projectRecoveryState = useSyncExternalStore(projectRecovery.subscribe, projectRecovery.getSnapshot, projectRecovery.getSnapshot);
  const [iosArchive] = useState(() => new IOSArchiveController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    releaseVersion: releaseVersion.getSnapshot,
    assetSession: assetSession.getSnapshot,
    otherOperationReason: () => localHistoryBusy() ?? storeBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? savedCommandPrerequisiteReason(),
  }));
  iosArchiveControllerRef.current = iosArchive;
  const iosArchiveState = useSyncExternalStore(iosArchive.subscribe, iosArchive.getSnapshot, iosArchive.getSnapshot);
  // Same saved observation and selected P8 projection as Store reads. These
  // comparison inputs never create the native key/account/journal authority.
  const appleOtherOperationReason = () => storeWithoutAppleBusy() ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ??
    androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason();
  const [appleProvisioning] = useState(() => new AppleProvisioningController({
    project: () => { const current = workspaceRef.current; return current.selectedId && Object.hasOwn(current.projects, current.selectedId)
      ? localStoreProjectObservation(current.projects[current.selectedId]!, releaseVersion.getSnapshot()) : null; },
    assets: assetSession.getSnapshot,
    // Do not call storeBusy()/savedCommandBusy(): those include this owner.
    otherOperationReason: appleOtherOperationReason,
  }));
  appleProvisioningControllerRef.current = appleProvisioning;
  const appleProvisioningState = useSyncExternalStore(appleProvisioning.subscribe, appleProvisioning.getSnapshot, appleProvisioning.getSnapshot);
  const [localStore] = useState(() => new LocalStorePreflightController({
    project: () => {const current=workspaceRef.current;return current.selectedId&&Object.hasOwn(current.projects,current.selectedId)?localStoreProjectObservation(current.projects[current.selectedId]!,releaseVersion.getSnapshot()):null;}, assets: assetSession.getSnapshot,
    otherOperationReason: () => appleProvisioningBusy() ?? storeReconcileBusy() ?? storeExecuteBusy() ?? storePrepareBusy() ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  localStoreControllerRef.current=localStore;
  const localStoreState=useSyncExternalStore(localStore.subscribe,localStore.getSnapshot,localStore.getSnapshot);
  const [localHistory] = useState(() => new LocalReleaseHistoryController({
    projectId: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId]?.project.id ?? null : null;
    },
    otherOperationReason: () => storeBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  localHistoryControllerRef.current = localHistory;
  const localHistoryState = useSyncExternalStore(localHistory.subscribe, localHistory.getSnapshot, localHistory.getSnapshot);
  const [localStorePrepare] = useState(() => new LocalStorePrepareController({
    project: () => {const current=workspaceRef.current;return current.selectedId&&Object.hasOwn(current.projects,current.selectedId)?localStoreProjectObservation(current.projects[current.selectedId]!,releaseVersion.getSnapshot()):null;}, assets: assetSession.getSnapshot,
    history: localHistory.getSnapshot,
    // Exclude this controller's own intent from reciprocal admission.
    otherOperationReason: () => appleProvisioningBusy() ?? storeReconcileBusy() ?? storeExecuteBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null) ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  localStorePrepareControllerRef.current=localStorePrepare;
  const localStorePrepareState=useSyncExternalStore(localStorePrepare.subscribe,localStorePrepare.getSnapshot,localStorePrepare.getSnapshot);
  const [localStoreExecute] = useState(() => new LocalStoreExecuteController({
    project: () => {
      if(assetSession.getSnapshot().scope.platform!=='ios'&&assetSession.getSnapshot().scope.stage==='candidate')return androidBuild.getSnapshot().project;
      const current=workspaceRef.current;
      return current.selectedId&&Object.hasOwn(current.projects,current.selectedId)?localStoreProjectObservation(current.projects[current.selectedId]!,releaseVersion.getSnapshot()):null;
    }, assets: assetSession.getSnapshot,
    history: localHistory.getSnapshot, tools: androidBuild.getSnapshot,
    // Same reciprocal admission, excluding only this original's own slot.
    otherOperationReason: () => appleProvisioningBusy() ?? storeReconcileBusy() ?? storePrepareBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null) ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  localStoreExecuteControllerRef.current=localStoreExecute;
  const localStoreExecuteState=useSyncExternalStore(localStoreExecute.subscribe,localStoreExecute.getSnapshot,localStoreExecute.getSnapshot);
  const [localStoreReconcile] = useState(() => new LocalStoreReconcileController({
    project: () => {
      if(assetSession.getSnapshot().scope.platform!=='ios')return androidBuild.getSnapshot().project;
      const current=workspaceRef.current;
      return current.selectedId&&Object.hasOwn(current.projects,current.selectedId)?localStoreProjectObservation(current.projects[current.selectedId]!,releaseVersion.getSnapshot()):null;
    }, assets: assetSession.getSnapshot,
    history: localHistory.getSnapshot,
    // Same reciprocal admission, excluding only this original's own slot.
    otherOperationReason: () => appleProvisioningBusy() ?? storeExecuteBusy() ?? storePrepareBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null) ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  localStoreReconcileControllerRef.current=localStoreReconcile;
  const localStoreReconcileState=useSyncExternalStore(localStoreReconcile.subscribe,localStoreReconcile.getSnapshot,localStoreReconcile.getSnapshot);
  const appleOtherReason = appleOtherOperationReason();
  const identityState = useSyncExternalStore<ProjectIdentityNativeState | null>(identityBinding?.native.subscribe ?? emptyIdentitySubscribe,
    identityBinding?.native.getState ?? emptyIdentitySnapshot, identityBinding?.native.getState ?? emptyIdentitySnapshot);
  const identityUi = useSyncExternalStore<ProjectIdentityUiState | null>(identityBinding?.ui.subscribe ?? emptyIdentitySubscribe,
    identityBinding?.ui.getSnapshot ?? emptyIdentitySnapshot, identityBinding?.ui.getSnapshot ?? emptyIdentitySnapshot);
  const identityOtherReason = identityAdmission.current();
  useEffect(() => { identityRef.current?.ui.sync(); }, [identityBinding, identityOtherReason]);
  const identityContext = useCallback((service: object): IdentityUiContext => {
    const w = workspaceRef.current, selected = w.selectedId ? w.projects[w.selectedId] ?? null : null;
    const proposal = identityRef.current?.service === service ? identityRef.current.proposal : null;
    const selection = proposal ? (selected?.project.id === proposal.runtimeId ? { ...proposal.request.change.selection, continuity: 'unknown' as const } : null) :
      savedIdentityInput(selected, selected ? identityInputs.current.get(selected.project.id) : undefined).selection;
    return { projectId: selected?.project.id ?? null, selection,
      contextEpoch: identityEpoch.current, preview: pathService.current.api?.mode === 'preview',
      blocked: service !== pathService.current || identityRef.current?.rebindFailed === true || bootstrapPending.current || connectionPicking.current || identityAdmission.current() !== null };
  }, []);
  const connectIdentity = useCallback((service: { api: DesktopApi | null; info: AppInfo | null }, requested?: AgentIdentityProposal | null) => {
    const base = service.api?.mode === 'native' ? service.api.projectIdentity : null;
    const old = identityRef.current;
    const proposal = requested === undefined ? (old?.service === service ? old.proposal : null) : requested;
    if (!base || old?.service === service && old.proposal === proposal) return;
    const port = proposal ? service.api?.agentIdentity && bindAgentIdentityApi(base, service.api.agentIdentity, proposal) : base;
    if (!port) return;
    // Never dispose/rebind an original Promise, active review or unknown cleanup.
    if (old?.rebindFailed || old?.native.ownerReason()) return;
    retireIdentity();
    if (old?.native.ownerReason()) return; // A synchronous listener may have started an original status read.
    const retainFailedDisposal = () => {
      if (!old) return;
      // Disposal may clear subscriptions before unlisten throws. Keep the same
      // original pair and explicitly refresh the view; never reconnect it.
      const retained = { ...old, rebindFailed: true };
      identityRef.current = retained; setIdentityBinding(retained);
    };
    try { old?.ui.dispose(); old?.native.dispose(); }
    catch { retainFailedDisposal(); return; }
    if (old?.native.ownerReason()) { retainFailedDisposal(); return; }
    const native = new ProjectIdentityNativeController(port, { current: () => identityContext(service),
      otherOperationReason: () => identityAdmission.current(),
      // Called only AFTER the real Apply invocation is retained. These effects
      // may retire local consent, but never cancel a submitted original Apply.
      onMutationSubmitted: (projectId) => identityInvalidation.current(projectId),
      onOutcome: (original) => { if (original.applySubmitted) identityInvalidation.current(original.projectId); } });
    const pair: IdentityBinding = { service, native, ui: new ProjectIdentityController(() => identityContext(service), native), rebindFailed: false, proposal, proposalSeeded: false };
    identityRef.current = pair; setIdentityBinding(pair); native.connect();
  }, [identityContext, retireIdentity]);
  useEffect(() => {
    const binding = identityRef.current;
    if (!binding?.proposal || binding !== identityBinding || binding.ui.getSnapshot() !== identityUi || binding.proposalSeeded || !identityUi?.canEditDraft || identityUi.session?.intent !== 'edit') return;
    // Only draft DATA is copied, once after the original native analysis.
    // Neither new-app acknowledgement nor preview/Apply consent is restored.
    binding.proposalSeeded = true;
    const change = binding.proposal.request.change;
    if (binding.ui.setIntent(change.identityIntent) && change.identityIntent === 'new-application') binding.ui.setDesiredIdentity(change.desiredIdentity);
  }, [identityBinding, identityUi]);
  const agentRequestAction = useCallback(async (action: 'status' | 'allow' | 'revoke' | 'decline', intentId?: string) => {
    // The existing retained native service keeps Revoke usable during a failed
    // reconnect. New Allow/status never borrows that old service binding.
    const service = action === 'revoke' ? cliService.current : pathService.current;
    const port = service.api?.mode === 'native' ? service.api.agentIdentity : null;
    const book = agentRequestWork.current, slot = action === 'revoke' ? 'revoke' : 'normal';
    const project = workspaceRef.current.selectedId;
    if (!port || book[slot] || action !== 'revoke' && book.revoke || action === 'allow' && (!project || versionEnrollmentBusy() || gitBusy() || identityBusy())) return;
    if (book.epoch === Number.MAX_SAFE_INTEGER && action !== 'revoke') { setAgentMessage({ service, text: 'Request controls need attention. Keep the original Desktop task; do not replay.' }); return; }
    const epoch = book.epoch = Math.min(Number.MAX_SAFE_INTEGER, book.epoch + 1);
    // Bound normal+revoke slots; revoke remains available during first Allow.
    // Original promise completion is not a project operation/finality receipt.
    const work = { promise: null as Promise<unknown> | null, superseded: false };
    // Stop stays usable even if the display epoch saturates. Its original
    // native revoke still runs; no late normal result may overwrite it.
    if (action === 'revoke' && book.normal) book.normal.superseded = true;
    book[slot] = work; // Latch BEFORE a native invocation or reentrant listener.
    setAgentRequestPending(true); setAgentMessage(null);
    try {
      work.promise = action === 'allow' ? port.allow(project!) : action === 'revoke' ? port.revoke() : action === 'decline' ? port.decline(intentId!) : port.status();
      const value = await work.promise;
      if (work.superseded || (action === 'revoke' ? cliService.current : pathService.current) !== service || book.epoch !== epoch) return;
      const parsed = parseAgentIdentityGuiStatus(value);
      if (!parsed) throw new Error('unconfirmed');
      setAgentObserved({ service, value: parsed });
      setAgentMessage(action === 'allow' ? { service, text: 'Identity proposals are allowed for 15 minutes. Each still needs your separate native review and exact-preview approval.' } : null);
    } catch {
      if (!work.superseded && (action === 'revoke' ? cliService.current : pathService.current) === service && book.epoch === epoch) setAgentMessage({ service, text: 'The request permission/status could not be confirmed. Check again or revoke; do not replay an edit.' });
    } finally {
      if (book[slot] === work) book[slot] = null;
      setAgentRequestPending(book.normal !== null || book.revoke !== null);
    }
  }, [versionEnrollmentBusy, gitBusy, identityBusy]);
  identityInvalidation.current = (projectId) => {
    snapshotIntentBatch(projectId);
    dispatch({ type: 'project-identity-intent', projectId });
    releaseVersion.saveIntent(); releaseInputs.saveIntent();
    assetSession.savedProjectChanged(projectId);
  };
  gitReadAdmission.current = () => versionEnrollmentBusy() ?? gitLocalRef.current?.ownerReason() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy() ?? savedOwnersPrerequisiteReason() ?? externalBusy() ??
    cliReadAccessControllerRef.current?.pendingReason() ??
    (githubPreflight.getSnapshot().status?.prepared || githubRelease.getSnapshot().status?.prepared
      ? 'Finish the prepared GitHub review before reading local project files.' : null);
  const [gitRead] = useState(() => new GitReadController({ current: () => ({
    api: pathService.current.api?.gitRead ?? null,
    session: pathService.current.api?.mode === 'native' && !gitReadGenerationLost.current ? pathService.current : null,
    projectId: workspaceRef.current.selectedId, epoch: gitReadEpoch.current, blocked: gitReadAdmission.current(),
  }) }));
  gitReadRef.current = gitRead;
  const gitReadState = useSyncExternalStore(gitRead.subscribe, gitRead.getSnapshot, gitRead.getSnapshot);
  const syncGitRead = useCallback(() => {
    gitRead.syncContext();
    const service = pathService.current, projectId = workspaceRef.current.selectedId;
    const usable = service.api?.mode === 'native' && !!service.api.gitRead && !!projectId &&
      Object.hasOwn(workspaceRef.current.projects, projectId) && !gitReadGenerationLost.current;
    let entry = usable ? gitRepositories.current.find((value) => value.service === service && value.projectId === projectId) : undefined;
    // Bounded in-memory local drafts; never evict an earlier draft or retarget
    // its port on service replacement. Native registration has its own bounds.
    if (!entry && usable && projectId && gitRepositories.current.length < 64) {
      entry = { service, projectId, controller: new GitRepositoryController(projectId, gitRead.port(projectId)) };
      gitRepositories.current.push(entry);
    }
    for (const value of gitRepositories.current) value.controller.setActive(value === entry);
    setGitRepository(entry?.controller ?? null);
    gitLocalRef.current?.syncContext();
  }, [gitRead]);
  syncGitReadRef.current = syncGitRead;
  useEffect(() => { syncGitRead(); });
  useEffect(() => {
    const timer = window.setInterval(() => {
      const original = gitRead.getSnapshot();
      if (gitRead.ownerReason() && !original.uncertain && original.original?.phase !== 'settled' && gitRead.canCheck()) void gitRead.checkStatus();
    }, 1000);
    return () => window.clearInterval(timer); // Stops observation only, not the original native read.
  }, [gitRead]);
  gitLocalAdmission.current = () => versionEnrollmentBusy() ?? gitReadRef.current?.ownerReason() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy() ??
    savedOwnersPrerequisiteReason() ?? externalBusy() ?? cliReadAccessControllerRef.current?.pendingReason() ??
    (githubPreflight.getSnapshot().status?.prepared || githubRelease.getSnapshot().status?.prepared
      ? 'Finish the prepared GitHub review before reviewing local Git changes.' : null);
  const [gitLocal] = useState(() => new GitLocalController({
    current: () => {
      const service = pathService.current, projectId = workspaceRef.current.selectedId;
      const entry = gitRepositories.current.find((value) => value.service === service && value.projectId === projectId);
      return { api: service.api?.gitLocal ?? null,
        session: service.api?.mode === 'native' && !gitReadGenerationLost.current ? service : null,
        projectId, epoch: gitReadEpoch.current, repository: entry?.controller ?? null, blocked: gitLocalAdmission.current() };
    },
    onMutationSubmitted: (projectId) => {
      // After actual Apply entry, including a lost/throwing acknowledgement.
      // These invalidate eligibility only; no draft/old baseline is replaced.
      snapshotIntentBatch(projectId);
      dispatch({ type: 'git-local-intent', projectId });
      releaseVersion.saveIntent(); releaseInputs.saveIntent();
      assetSession.savedProjectChanged(projectId);
    },
  }));
  gitLocalRef.current = gitLocal;
  const gitLocalState = useSyncExternalStore(gitLocal.subscribe, gitLocal.getSnapshot, gitLocal.getSnapshot);
  const gitLocalProjectName = gitLocalState.projectId ? workspace.projects[gitLocalState.projectId]?.project.name : undefined;
  const requests = useRef(0);
  const bootGeneration = useRef(0);
  const [cliReadAccess] = useState(() => new CliReadAccessController({
    current: () => {
      const service = cliService.current, current = workspaceRef.current;
      const project = current.selectedId ? current.projects[current.selectedId]?.project : null;
      return {
        port: service.api?.mode === 'native' ? service.api.applicationRead ?? null : null,
        nativeSession: service.api?.mode === 'native' ? service : null,
        selectedProject: project && !connectionPicking.current ? { id: project.id, name: project.name } : null,
        preview: service.api?.mode === 'preview',
        // Only OTHER original owners. In particular, Revoke stays available
        // during Allow and during unrelated work. A connected GitHub session
        // alone is not execution and does not prevent this limited read grant.
        busy: service !== pathService.current || !!(versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy() ?? savedOwnersPrerequisiteReason(false, false, undefined, false, true) ?? externalBusy()),
      };
    },
  }));
  cliReadAccessControllerRef.current = cliReadAccess;
  const cliReadState = useSyncExternalStore(cliReadAccess.subscribe, cliReadAccess.getSnapshot, cliReadAccess.getSnapshot);
  const cliReadNeedsAttention = cliReadState.pendingCount > 0 || cliReadState.issue !== null;
  // Keep the retained controller when its Advanced panel is hidden. This
  // refreshes display/admission only; it never starts an IPC request or grant.
  useEffect(() => { cliReadAccess.syncContext(); });
  const [agentLocalChecks] = useState(() => new AgentLocalCheckPermission(() => {
    const service = cliService.current, current = workspaceRef.current;
    const project = current.selectedId ? current.projects[current.selectedId] : null;
    const usable = project && !connectionPicking.current && !isDirty(project) && project.snapshotRequest === null &&
      !project.snapshotPredatesSave && !project.saveRecoveryRequired && project.savedConfigContent !== null;
    return { api: service.api?.mode === 'native' ? service.api.agentLocalChecks ?? null : null,
      project: usable ? { projectId: project.project.id, draftRevision: project.revision, baselineGeneration: project.baselineGeneration } : null,
      blocked: service !== pathService.current || !!(versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy() ??
        savedOwnersPrerequisiteReason(false, false, undefined, false, true) ?? externalBusy() ?? cliReadAccessControllerRef.current?.pendingReason()),
    };
  }));
  // App-owned pending calls survive the Advanced panel being hidden. Current
  // context is also sampled again synchronously inside the Allow event.
  useEffect(() => { agentLocalChecks.syncContext(); });
  const [agentAndroidBuild] = useState(() => new AgentAndroidBuildPermission(() => {
    const service = cliService.current;
    return { api: service.api?.mode === 'native' ? service.api.agentAndroidBuild ?? null : null,
      project: androidBuildControllerRef.current?.agentBuildApproval() ?? null,
      blocked: service !== pathService.current || connectionPicking.current || !!(versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ??
        externalBusy() ?? cliReadAccessControllerRef.current?.pendingReason()),
    };
  }));
  useEffect(() => { agentAndroidBuild.syncContext(); });
  const [externalObserver] = useState(() => new ExternalProjectObservationController({
    current: () => {
      const current = workspaceRef.current;
      return { api: pathService.current.api, session: current.selectedId ? current.projects[current.selectedId] ?? null : null,
        versionState: releaseVersionControllerRef.current?.getSnapshot() ?? null };
    },
    otherOperationReason: () => versionEnrollmentBusy() ?? gitBusy() ?? githubGhBusy() ?? identityBusy() ?? savedOwnersBusy() ?? savedOwnersPrerequisiteReason() ?? cliReadAccessControllerRef.current?.pendingReason() ??
      (githubPreflight.getSnapshot().status?.prepared || githubRelease.getSnapshot().status?.prepared
        ? 'Review or retire the prepared GitHub task before refreshing saved files.' : null) ??
      methodReason(pathService.current.info, 'project.snapshot', pathService.current.api?.mode ?? 'unavailable'),
    onObservation: (outcome, stillCurrent) => {
      // The original read is already settled. Check once before this entirely
      // synchronous batch; its own intent/reducer changes legitimately retire
      // the old scope. Unchanged polls never reach this callback.
      if (!stillCurrent()) return false;
      snapshotIntentBatch(outcome.projectId);
      const requestId = ++requests.current;
      dispatch({ type: 'snapshot-start', projectId: outcome.projectId, requestId });
      if (outcome.kind === 'observed') dispatch({ type: 'snapshot-done', projectId: outcome.projectId, requestId,
        snapshot: outcome.snapshot, observedAt: outcome.observedAt });
      else dispatch({ type: 'snapshot-failed', projectId: outcome.projectId, requestId, error: outcome.error });
      return true;
    },
  }));
  externalObserverRef.current = externalObserver;
  const externalObservation = useSyncExternalStore(externalObserver.subscribe, externalObserver.getSnapshot, externalObserver.getSnapshot);
  const main = useRef<HTMLElement>(null);
  const offlineCheckSection = useRef<HTMLDivElement>(null);
  const androidSigningSection = useRef<HTMLDivElement>(null);
  const androidToolSetupSection = useRef<HTMLElement>(null);
  useEffect(() => {
    if (page !== 'releases' || releaseCheckFocus === null) return;
    const section = releaseCheckFocus === 'offline' ? offlineCheckSection.current : androidSigningSection.current;
    section?.focus({ preventScroll: true });
    section?.scrollIntoView({ block: 'start' });
    setReleaseCheckFocus(null);
  }, [page, releaseCheckFocus]);
  const mode = api?.mode ?? 'unavailable';
  const preview = mode === 'preview';
  const session = workspace.selectedId ? workspace.projects[workspace.selectedId] ?? null : null;
  const currentNavigation = workspacePages[page];
  const nativeSaveAvailable = mode === 'native' && saveState.status?.capability.available === true &&
    !saveState.observationIssue && !saveState.integrityFailed && !saveState.generationLost && !saveState.nativeBlocked;
  const nativeWorkflowAvailable = mode === 'native' && workflowState.status?.capability.available === true &&
    !workflowState.observationIssue && !workflowState.integrityFailed && !workflowState.generationLost && !workflowState.nativeBlocked;
  const nativeMetadataAvailable = mode === 'native' && metadataState.edit.status?.capability.available === true &&
    !metadataState.edit.observationIssue && !metadataState.edit.integrityFailed && !metadataState.edit.generationLost && !metadataState.edit.nativeBlocked;
  const nativeVersionAvailable = mode === 'native' && versionEditState.edit.status?.capability.available === true &&
    !versionEditState.edit.observationIssue && !versionEditState.edit.integrityFailed && !versionEditState.edit.generationLost && !versionEditState.edit.nativeBlocked;
  const nativeImagesAvailable = mode === 'native' && metadataImagesState.catalog !== null &&
    metadataImagesState.selectionInitialized && metadataImagesState.editInitialized && metadataImagesState.selectionListening && metadataImagesState.editListening &&
    metadataImagesState.selectionStatus?.capability.available === true && metadataImagesState.editStatus?.capability.available === true &&
    !metadataImagesState.reading && !metadataImagesState.integrityFailed && !metadataImagesState.generationLost && !metadataImagesState.nativeBlocked &&
    !metadataImagesState.selectionIssue && !metadataImagesState.editIssue;
  const localEditingLabel = nativeWorkflowAvailable || nativeMetadataAvailable || nativeVersionAvailable || nativeImagesAvailable ? 'Local file editing' : nativeSaveAvailable ? 'Configuration-only editing' : 'Read-only drafting';

  const bootstrap = useCallback(async () => {
    const originalCounter = versionEnrollmentBusy();
    if (originalCounter) { setBootError({ code: 'version_enrollment_busy', message: originalCounter, retryable: false }); return; }
    const originalGit = gitBusy();
    if (originalGit) { setBootError({ code: 'git_read_busy', message: originalGit, retryable: false }); return; }
    const originalGh = githubGhBusy();
    if (originalGh) { setBootError({ code: 'github_cli_busy', message: originalGh, retryable: false }); return; }
    githubGhEntry.beforeContextIntent();
    const originalIdentity = identityBusy();
    if (originalIdentity) {
      setBootError({ code: 'identity_busy', message: originalIdentity, retryable: false }); return;
    }
    const originalApple = appleProvisioningBusy();
    if (originalApple) { setBootError({ code: 'apple_provisioning_busy', message: originalApple, retryable: false }); return; }
    const originalTools = toolPreparationBusy();
    if (originalTools) { setBootError({ code: 'tool_acquisition_busy', message: originalTools, retryable: false }); return; }
    // Reconnecting is not permission to close an original review to get it out
    // of the way. Only a genuinely settled owner reaches this retirement.
    retireIdentity();
    if (cliReadAccessControllerRef.current?.pendingReason()) {
      setBootError({ code: 'cli_access_busy', message: 'Finish the current CLI access request before reconnecting. You can still turn off access.', retryable: false });
      return;
    }
    cliReadAccessControllerRef.current?.invalidateContext();
    externalObserverRef.current?.beforeWorkspaceAction();
    versionEdit.beginConnection();
    metadataImages.beginConnection();
    retirePathPicker();
    pathService.current = { api: null, info: null }; syncGitReadRef.current();
    cliReadAccessControllerRef.current?.syncContext();
    // Reconnection cannot discard a pending or unverified original picker.
    if (projectPathOwnerReason(pathPickerRef.current)) return;
    artifactInspection.beginConnection();
    offlinePreflight.beginConnection(); localStore.beginConnection(); localStorePrepare.beginConnection(); localStoreExecute.beginConnection(); localStoreReconcile.beginConnection(); localHistory.beginConnection(); appleProvisioning.beginConnection();
    androidBuild.beginConnection();
    toolAcquisition.beginConnection();
    projectRecovery.beginConnection(); iosArchive.beginConnection();
    if (savedCommandBusy()) { setBootError(versionOwnerReason(versionEdit.getSnapshot(), workspaceRef.current.selectedId ?? '') ?
      versionEditError({ code: 'VersionEditBusy' }) : artifactBusy() ? artifactInspectionError({code:'artifact_inspection_busy'}) : metadataImagesOwnerReason(metadataImages.getSnapshot()) ? metadataImagesError({ code: 'metadata_images_busy' }) : recoveryBusy() ? projectRecoveryError({ code: 'project_recovery_busy' }) : androidBusy() ? androidBuildError({ code: 'android_build_busy' }) : iosBusy() ? iosArchiveError({ code: 'ios_archive_busy' }) : offlinePreflightError({ code: 'offline_preflight_busy' })); return; }
    bootstrapPending.current = true;
    const generation = ++bootGeneration.current;
    const helpGeneration = {};
    connectionHelpGeneration.current = helpGeneration;
    githubConnection.setHelp(null);
    githubConnection.setContext(null);
    connectionHandoffRef.current = null; connectionPortRef.current = null; githubGhApiRef.current = null;
    githubGhEntry.attach(null, null); // Refuses replacement if an original read intervened.
    void githubConnection.attach(null);
    void githubRemoteSetup.connect(null); void githubPublication.connect(null);
    void githubPreflight.connect(null);
    void githubRelease.connect(null);
    void githubHistory.connect(null);
    githubSetup.beginConnection();
    environment.beginConnection();
    releaseVersion.beginConnection();
    releaseInputs.beginConnection();
    diagnostics.beginConnection();
    releaseEvidence.beginConnection();
    metadataText.beginConnection();
    configEdit.serviceIntent();
    setLoading(true);
    setBootError(null);
    setCatalogError(null);
    passivePending.current += 1; setPassivePending(passivePending.current);
    try {
      const connection = await desktopApi();
      if (generation !== bootGeneration.current) return;
      setApi(connection);
      // This fixed native Status has its own qualification gate. Passive
      // appInfo/catalogue success never enables tool execution.
      void artifactInspection.connect(connection);
      void offlinePreflight.connect(connection); void localStore.connect(connection); void localStorePrepare.connect(connection); void localStoreExecute.connect(connection); void localStoreReconcile.connect(connection); void localHistory.connect(connection).then(localHistory.syncProject);
      void androidBuild.connect(connection);
      void toolAcquisition.connect(connection.toolAcquisition ?? null);
      void appleProvisioning.connect(connection.appleProvisioning ?? null);
      void projectRecovery.connect(connection);
      void iosArchive.connect(connection);
      void diagnostics.connect(connection);
      void releaseEvidence.connect(connection);
      const port: GitHubConnectionObservationPort = {
        mode: connection.mode, subscribe: connection.subscribeGitHubConnection, status: connection.githubConnectionStatus,
        refresh: connection.refreshGitHubConnection, disconnect: connection.disconnectGitHubConnection,
      };
      connectionPortRef.current = port;
      connectionHandoffRef.current = connection.mode === 'native' ? { port, submit: connection.connectGitHubToken } : null;
      githubGhApiRef.current = connection.mode === 'native' ? connection.githubGhEntry ?? null : null;
      // No account discovery or Connect on attach. Availability/status remains
      // an explicit read; failed rebind retains old original controls.
      githubGhEntry.attach(githubGhApiRef.current, port);
      // Fixed read-only Status may expose an unavailable native gate. Working
      // passive appInfo is neither credential admission nor TLS qualification.
      void githubConnection.attach(port);
      void githubRemoteSetup.connect(connection); void githubPublication.connect(connection);
      void githubPreflight.connect(connection);
      void githubRelease.connect(connection);
      void githubHistory.connect(connection);
      const appInfo = await connection.appInfo();
      if (generation !== bootGeneration.current) return;
      pathService.current = { api: connection, info: appInfo }; syncGitReadRef.current();
      cliService.current = pathService.current;
      connectIdentity(pathService.current);
      cliReadAccessControllerRef.current?.syncContext();
      setInfo(appInfo);
      githubSetup.setConnection(connection, appInfo);
      environment.setConnection(connection, appInfo);
      releaseVersion.setConnection(connection, appInfo);
      releaseInputs.setConnection(connection, appInfo);
      metadataText.setConnection(connection, appInfo);
      if (connection.mode === 'preview' || methodReason(appInfo, 'catalog', connection.mode) === null) {
        try {
          const result = await connection.catalog();
          if (generation === bootGeneration.current) {
            if (!githubSetup.admitHelp(result.githubSetup)) throw githubSetupError({ code: 'GitHubSetupHelpUnavailable' });
            releaseInputs.setCatalog(result);
            setCatalog(result);
            metadataText.setHelp(result.metadataText);
            versionEdit.setHelp(result.releaseVersionEdit);
            if (helpGeneration === connectionHelpGeneration.current) {
              githubConnection.setHelp(result.githubConnection); syncConnectionContext();
            }
          }
        } catch (error) {
          if (generation === bootGeneration.current) { releaseInputs.setCatalog(null); setCatalog(null); githubSetup.helpUnavailable(); metadataText.setHelp(null); versionEdit.setHelp(null); setCatalogError(apiError(error)); }
        }
      } else {
        releaseInputs.setCatalog(null);
        setCatalog(null);
        githubSetup.helpUnavailable();
        metadataText.setHelp(null); versionEdit.setHelp(null);
      }
    } catch (error) {
      if (generation === bootGeneration.current) {
        retireIdentity();
        appleProvisioning.beginConnection();
        pathService.current = { api: null, info: null }; syncGitReadRef.current();
        identityRef.current?.ui.sync();
        cliReadAccessControllerRef.current?.invalidateContext();
        cliReadAccessControllerRef.current?.syncContext();
        githubGhEntry.beforeContextIntent();
        connectionHandoffRef.current = null; connectionPortRef.current = null; githubGhApiRef.current = null;
        githubGhEntry.attach(null, null);
        githubConnection.setHelp(null); githubConnection.setContext(null); void githubConnection.attach(null); void githubRemoteSetup.connect(null); void githubPublication.connect(null); void githubPreflight.connect(null); void githubRelease.connect(null); void githubHistory.connect(null);
        setInfo(null); setCatalog(null); versionEdit.setHelp(null); githubSetup.connectionUnavailable(); environment.connectionUnavailable(); releaseVersion.connectionUnavailable(); releaseInputs.connectionUnavailable(); setBootError(apiError(error));
      }
    } finally {
      passivePending.current -= 1; setPassivePending(passivePending.current);
      if (generation === bootGeneration.current) { bootstrapPending.current = false; setLoading(false); externalObserverRef.current?.syncContext(); identityRef.current?.ui.sync(); githubGhEntry.syncContext(); }
    }
  }, [versionEnrollmentBusy, gitBusy, githubSetup, githubConnection, githubGhEntry, githubGhBusy, githubRemoteSetup, githubPublication, githubPreflight, githubRelease, githubHistory, environment, releaseVersion, releaseInputs, diagnostics, releaseEvidence, artifactInspection, artifactBusy, offlinePreflight, localStore, localStorePrepare, localStoreExecute, localStoreReconcile, localHistory, appleProvisioning, appleProvisioningBusy, androidBuild, toolAcquisition, toolPreparationBusy, projectRecovery, iosArchive, androidBusy, recoveryBusy, iosBusy, savedCommandBusy, metadataText, metadataImages, versionEdit, syncConnectionContext, retirePathPicker, identityBusy, retireIdentity, connectIdentity]);

  // Before bootstrap: retire consent on the actual saved/key projection, and
  // keep the view responsive to peer-owner changes without renewing an intent.
  useEffect(() => {
    const a = assetSession.subscribe(appleProvisioning.syncProject), b = releaseVersion.subscribe(appleProvisioning.syncProject);
    appleProvisioning.syncProject(); return () => { a(); b(); };
  }, [assetSession, releaseVersion, appleProvisioning]);
  useEffect(() => appleProvisioning.syncProject(), [appleProvisioning, appleOtherReason]);
  useEffect(() => appleProvisioning.setVisible(page === 'dashboard'), [appleProvisioning, page]);

  // Only comparison invalidation. Changed catalogue/source/registration DATA
  // retires reviews; these projections cannot authorize acquisition.
  useEffect(() => {
    const changed = () => toolAcquisition.syncProject();
    const off = androidBuild.subscribe(changed); changed(); return off;
  }, [androidBuild, toolAcquisition]);
  // Subscribe before bootstrap. A version read/replacement retires consent
  // synchronously, before React publishes another frame of the review.
  useEffect(() => releaseVersion.subscribe(() => androidBuild.syncReleaseVersion()), [releaseVersion, androidBuild]);
  useEffect(() => {
    // Original connection intent/pins, not every status timestamp. This retires
    // a UI review on account/repository/session ABA before another handoff.
    const key = () => {
      const c = githubConnection.getSnapshot(), s = c.status;
      return JSON.stringify([c.context, c.busy, c.blocked, c.uncertain, c.retirementPending,
        s?.session?.id, s?.session?.state, s?.account.state, s?.account.value?.id,
        s?.repository.state, s?.repository.value?.id]);
    };
    let original = key();
    return githubConnection.subscribe(() => {
      const next = key();
      if (next !== original) { original = next; versionEnrollment.beforeContextIntent(); }
      versionEnrollment.syncContext();
    });
  }, [githubConnection, versionEnrollment]);
  useEffect(() => githubConnection.subscribe(githubPublication.syncContext), [githubConnection, githubPublication]);
  useEffect(() => githubConnection.subscribe(githubRemoteSetup.syncContext), [githubConnection, githubRemoteSetup]);
  useEffect(() => githubConnection.subscribe(githubPreflight.syncContext), [githubConnection, githubPreflight]);
  useEffect(() => githubConnection.subscribe(githubHistory.syncContext), [githubConnection, githubHistory]);
  useEffect(() => releaseVersion.subscribe(() => iosArchive.syncReleaseVersion()), [releaseVersion, iosArchive]);
  // Exact assignment/context changes retire signed consent before a new render;
  // idle retained records remain available to the existing native borrower.
  useEffect(() => {
    const unsubscribe = assetSession.subscribe(githubRemoteSetup.syncAssetSession);
    githubRemoteSetup.syncAssetSession();
    return unsubscribe;
  }, [assetSession, githubRemoteSetup]);
  useEffect(() => assetSession.subscribe(() => iosArchive.syncAssetSession()), [assetSession, iosArchive]);
  useEffect(() => assetSession.subscribe(() => androidBuild.syncAssetSession()), [assetSession, androidBuild]);
  useEffect(() => {
    let scope = JSON.stringify(assetSession.getSnapshot().scope);
    return assetSession.subscribe(() => {
      const next = JSON.stringify(assetSession.getSnapshot().scope);
      if (scope !== next) { scope = next; retireIdentity(); }
    });
  }, [assetSession, retireIdentity]);
  // Subscribe before bootstrap; a generic asset-only event must recheck the
  // same held selection even when no further image status event will arrive.
  useEffect(() => {
    const unsubscribe = assetSession.subscribe(metadataImages.syncAssetSession);
    metadataImages.syncAssetSession();
    return unsubscribe;
  }, [assetSession, metadataImages]);
  useEffect(() => githubConnection.subscribe(githubRelease.syncContext), [githubConnection, githubRelease]);

  useEffect(() => {
    void bootstrap();
    return () => { githubGhEntry.beforeContextIntent(); githubGhApiRef.current = null; retireIdentity(); externalObserverRef.current?.beforeWorkspaceAction(); bootGeneration.current += 1; pathService.current = { api: null, info: null }; syncGitReadRef.current(); retirePathPicker(); connectionHelpGeneration.current = {}; githubConnection.setHelp(null); releaseInputs.connectionUnavailable(); };
  }, [bootstrap]);

  useEffect(() => { if (api) void configEdit.connect(api); }, [api, configEdit]);
  useEffect(() => () => configEdit.dispose(), [configEdit]);
  useEffect(() => () => cliReadAccess.dispose(), [cliReadAccess]);
  useEffect(() => () => versionEnrollment.dispose(), [versionEnrollment]);
  useEffect(() => () => { identityRef.current?.ui.dispose(); identityRef.current?.native.dispose(); }, []);
  useEffect(() => () => githubSetup.dispose(), [githubSetup]);
  useEffect(() => () => environment.dispose(), [environment]);
  useEffect(() => () => releaseVersion.dispose(), [releaseVersion]);
  useEffect(() => () => releaseInputs.dispose(), [releaseInputs]);
  useEffect(() => () => diagnostics.dispose(), [diagnostics]);
  useEffect(() => () => artifactInspection.dispose(), [artifactInspection]);
  useEffect(() => () => offlinePreflight.dispose(), [offlinePreflight]);
  useEffect(() => () => toolAcquisition.dispose(), [toolAcquisition]);
  useEffect(() => () => localStore.dispose(), [localStore]);
  useEffect(() => () => appleProvisioning.dispose(), [appleProvisioning]);
  useEffect(() => () => localStorePrepare.dispose(), [localStorePrepare]);
  useEffect(() => () => localStoreExecute.dispose(), [localStoreExecute]);
  useEffect(() => {
    const a=assetSession.subscribe(localStoreExecute.syncProject),b=androidBuild.subscribe(localStoreExecute.syncProject),c=localHistory.subscribe(localStoreExecute.syncProject),d=releaseVersion.subscribe(localStoreExecute.syncProject);
    localStoreExecute.syncProject();return()=>{a();b();c();d();};
  },[assetSession,androidBuild,localHistory,releaseVersion,localStoreExecute]);
  useEffect(() => () => localStoreReconcile.dispose(), [localStoreReconcile]);
  useEffect(() => {
    const a=assetSession.subscribe(localStoreReconcile.syncProject),b=androidBuild.subscribe(localStoreReconcile.syncProject),c=localHistory.subscribe(localStoreReconcile.syncProject),d=releaseVersion.subscribe(localStoreReconcile.syncProject);
    localStoreReconcile.syncProject();return()=>{a();b();c();d();};
  },[assetSession,androidBuild,localHistory,releaseVersion,localStoreReconcile]);
  useEffect(() => {
    const a=assetSession.subscribe(localStorePrepare.syncProject),b=releaseVersion.subscribe(localStorePrepare.syncProject),c=localHistory.subscribe(localStorePrepare.syncProject);
    localStorePrepare.syncProject();return()=>{a();b();c();};
  },[assetSession,releaseVersion,localHistory,localStorePrepare]);
  useEffect(() => () => localHistory.dispose(), [localHistory]);
  useEffect(() => {const a=assetSession.subscribe(localStore.syncProject), b=releaseVersion.subscribe(localStore.syncProject);localStore.syncProject(); localStorePrepare.syncProject();return()=>{a();b();};},[assetSession,releaseVersion,localStore]);
  useEffect(() => () => androidBuild.dispose(), [androidBuild]);
  useEffect(() => () => projectRecovery.dispose(), [projectRecovery]);
  useEffect(() => () => iosArchive.dispose(), [iosArchive]);
  useEffect(() => () => releaseEvidence.dispose(), [releaseEvidence]);
  useEffect(() => () => githubGhEntry.dispose(), [githubGhEntry]);
  useEffect(() => () => githubConnection.dispose(), [githubConnection]);
  useEffect(() => () => githubPublication.dispose(), [githubPublication]);
  useEffect(() => () => githubRemoteSetup.dispose(), [githubRemoteSetup]);
  useEffect(() => () => githubPreflight.dispose(), [githubPreflight]);
  useEffect(() => () => githubRelease.dispose(), [githubRelease]);
  useEffect(() => () => githubHistory.dispose(), [githubHistory]);
  useEffect(() => { if(api)void initialization.connect(api); },[api,initialization]);
  useEffect(() => ()=>initialization.dispose(),[initialization]);
  useEffect(() => { if (api) void workflowEdit.connect(api); }, [api, workflowEdit]);
  useEffect(() => () => workflowEdit.dispose(), [workflowEdit]);
  useEffect(() => { if (api) void metadataText.connect(api); }, [api, metadataText]);
  useEffect(() => () => metadataText.dispose(), [metadataText]);
  useEffect(() => { if (api) void metadataImages.connect(metadataImagesApi(api.mode)); }, [api, metadataImages]);
  useEffect(() => () => metadataImages.dispose(), [metadataImages]);
  useEffect(() => { if (api) void versionEdit.connect(api); }, [api, versionEdit]);
  useEffect(() => () => versionEdit.dispose(), [versionEdit]);
  useEffect(() => { if (api) void assetSession.connect(api); }, [api, assetSession]);
  useEffect(() => () => assetSession.dispose(), [assetSession]);

  useEffect(() => {
    const visibility = () => externalObserver.setVisible(!document.hidden);
    const focus = () => { void externalObserver.focus(); };
    document.addEventListener('visibilitychange', visibility);
    window.addEventListener('focus', focus);
    visibility();
    return () => {
      document.removeEventListener('visibilitychange', visibility);
      window.removeEventListener('focus', focus);
      void externalObserver.dispose();
    };
  }, [externalObserver]);

  useEffect(() => {
    document.title = `${currentNavigation.label} · Mobile Release Kit${preview ? ' · Browser preview' : ''}`;
  }, [currentNavigation, preview]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      retireIdentity();
      externalObserverRef.current?.beforeWorkspaceAction();
      cliReadAccessControllerRef.current?.invalidateContext();
      githubGhEntryRef.current?.beforeContextIntent();
      void toolAcquisitionControllerRef.current?.cancel();
      void appleProvisioningControllerRef.current?.cancel();
      initializationControllerRef.current?.requestClose();
      editControllerRef.current?.shutdownIntent();
      versionEditControllerRef.current?.shutdownIntent();
      metadataControllerRef.current?.shutdownIntent();
      imageControllerRef.current?.shutdownIntent();
      githubHistoryControllerRef.current?.beforeWorkspaceAction();
      if (Object.values(workspaceRef.current.projects).some(isDirty) ||
          versionEditControllerRef.current && versionProjectDirty(versionEditControllerRef.current.getSnapshot()) || metadataControllerRef.current && metadataProjectDirty(metadataControllerRef.current.getSnapshot().entries) ||
          diagnosticsControllerRef.current && diagnosticsOwnerReason(diagnosticsControllerRef.current.getSnapshot()) || savedCommandBusy()) {
        event.preventDefault();
        event.returnValue = '';
      }
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, []);

  const navigate = (next: Page) => { if (next !== page) gitLocal.beforeContextIntent(); externalObserver.beforeWorkspaceAction(); initialization.setVisible(next==='dashboard'); configEdit.setRecoveryVisible(next === 'settings' || next === 'metadata'); metadataText.setVisible(next === 'metadata'); metadataImages.setVisible(next === 'metadata'); versionEdit.setVisible(next === 'dashboard'); retirePathPicker(); artifactInspection.setVisible(next === 'artifacts'); offlinePreflight.setVisible(next === 'releases'); localStore.setVisible(next === 'releases'); localStorePrepare.setVisible(next === 'releases'); localStoreExecute.setVisible(next === 'releases'); localStoreReconcile.setVisible(next === 'releases'); localHistory.setVisible(next === 'releases'); appleProvisioning.setVisible(next === 'dashboard'); androidBuild.setVisible(next === 'releases'); androidBuild.setToolSetupVisible(next === 'environment' && environment.getSnapshot().platform === 'android' && environment.getSnapshot().operation === 'build'); projectRecovery.setVisible(next === 'recovery'); iosArchive.setVisible(next === 'releases'); iosArchive.setRecoveryVisible(next === 'recovery'); diagnostics.setVisible(next === 'environment'); toolAcquisition.setVisible(next === 'environment' && environment.getSnapshot().platform === 'android' && environment.getSnapshot().operation === 'build'); if (next !== 'settings') { setCliAccessReveal(0); setIdentityReveal(0); } setReleaseCheckFocus(null); setPage(next); main.current?.focus({ preventScroll: true }); };
  const reviewCredentialChecks = (kind: 'offline' | 'android-signing') => {
    if (savedCommandBusy() || diagnosticsOwnerReason(diagnostics.getSnapshot())) return;
    // Navigation selects a review only. The existing controller still owns
    // availability, original private inputs, consent, Start and cancellation.
    if (kind === 'android-signing') androidBuild.setBuildMode('signed');
    navigate('releases');
    setReleaseCheckFocus(kind);
  };
  const refreshReason = savedCommandBusy() ?? methodReason(info, 'project.snapshot', mode);
  const validateReason = savedCommandBusy() ?? methodReason(info, 'config.validate', mode);
  const reviewReason = savedCommandBusy() ?? methodReason(info, 'config.preview', mode);
  const suggestReason = savedCommandBusy() ?? methodReason(info, 'config.suggest', mode);
  // Example loading remains an explicit preview action, never a fallback for
  // missing native project-selection DATA or a failed native picker.
  const chooseReason = loading ? 'Application capabilities are being loaded.' : choosing ? 'Finish the original project selection first.'
    : savedCommandBusy() ?? (preview ? null : projectSelectionReason(info, mode))
      ?? (initializationState.status?.capability.reason === 'shutdown' || saveState.status?.capability.reason === 'shutdown' || workflowState.status?.capability.reason === 'shutdown'
        || metadataImagesState.selectionStatus?.capability.reason === 'shutdown' || metadataImagesState.editStatus?.capability.reason === 'shutdown'
        || metadataState.edit.status?.capability.reason === 'shutdown' || versionEditState.edit.status?.capability.reason === 'shutdown' || diagnosticsState.status?.capability.reason === 'shutdown'
        ? 'The application is shutting down.' : null);
  const chooseDisabled = chooseReason !== null;

  function snapshotIntentBatch(projectId: string) {
    retireIdentity();
    externalObserverRef.current?.beforeWorkspaceAction();
    githubHistory.beforeWorkspaceAction();
    initialization.snapshotIntent();
    configEdit.snapshotIntent(projectId);
    metadataImages.snapshotIntent(projectId);
    versionEdit.snapshotIntent(projectId);
    metadataText.snapshotIntent(projectId);
    retirePathPicker();
    artifactInspection.snapshotIntent(projectId);
    toolAcquisition.snapshotIntent(projectId);
    offlinePreflight.snapshotIntent(projectId); localStore.snapshotIntent(); localStorePrepare.snapshotIntent(); localStoreExecute.snapshotIntent(); localStoreReconcile.snapshotIntent(); localHistory.snapshotIntent(); appleProvisioning.snapshotIntent();
    androidBuild.snapshotIntent(projectId);
    projectRecovery.snapshotIntent(projectId);
    iosArchive.snapshotIntent(projectId);
  }
  const loadSnapshot = async (projectId: string, recoveryReload = false) => {
    snapshotIntentBatch(projectId);
    if (!api || savedCommandBusy() || (refreshReason !== null && !preview)) return;
    const requestId = ++requests.current;
    passivePending.current += 1; setPassivePending(passivePending.current);
    try {
      dispatch({ type: 'snapshot-start', projectId, requestId, recoveryReload });
      const snapshot = await api.snapshot(projectId);
      dispatch({ type: 'snapshot-done', projectId, requestId, snapshot, observedAt: Date.now() });
      externalObserver.dismissNotice();
    } catch (error) {
      dispatch({ type: 'snapshot-failed', projectId, requestId, error: apiError(error) });
    } finally { passivePending.current -= 1; setPassivePending(passivePending.current); }
  };

  const chooseProject = async () => {
    externalObserver.beforeWorkspaceAction();
    githubHistory.beforeWorkspaceAction();
    initialization.selectionIntent();
    configEdit.selectionIntent();
    metadataImages.selectionIntent();
    versionEdit.selectionIntent();
    retirePathPicker();
    artifactInspection.selectionIntent();
    toolAcquisition.selectionIntent();
    offlinePreflight.selectionIntent(); localStore.selectionIntent(); localStorePrepare.selectionIntent(); localStoreExecute.selectionIntent(); localStoreReconcile.selectionIntent(); localHistory.selectionIntent(); appleProvisioning.selectionIntent();
    androidBuild.selectionIntent();
    projectRecovery.selectionIntent();
    iosArchive.selectionIntent();
    if (!api || savedCommandBusy() || chooseDisabled || connectionPicking.current) return;
    // Admission of the native picker retires the original GitHub context even
    // if selection later cancels/fails. Do not wait for a successful folder.
    connectionPicking.current = true; advanceConnectionContext(); githubConnection.setContext(null);
    metadataImages.setSelectionPending(true);
    releaseVersion.setSelectionPending(true);
    releaseInputs.setSelectionPending(true);
    diagnostics.setSelectionPending(true);
    artifactInspection.setSelectionPending(true);
    toolAcquisition.setSelectionPending(true);
    offlinePreflight.setSelectionPending(true); localStore.setSelectionPending(true); localStorePrepare.setSelectionPending(true); localStoreExecute.setSelectionPending(true); localStoreReconcile.setSelectionPending(true); localHistory.setSelectionPending(true); appleProvisioning.setSelectionPending(true);
    androidBuild.setSelectionPending(true);
    projectRecovery.setSelectionPending(true);
    iosArchive.setSelectionPending(true);
    metadataText.setSelectionPending(true);
    versionEdit.setSelectionPending(true);
    retireIdentity();
    setChoosing(true);
    setChooseError(null);
    try {
      const project = await api.chooseProject();
      if (!project) return;
      const alreadyLoaded = workspaceRef.current.projects[project.id]?.snapshot;
      dispatch({ type: 'select', project });
      if (!alreadyLoaded) await loadSnapshot(project.id);
    } catch (error) { setChooseError(apiError(error)); }
    finally { connectionPicking.current = false; identityRef.current?.ui.sync(); setChoosing(false); syncConnectionContext(); releaseVersion.setSelectionPending(false); releaseInputs.setSelectionPending(false); metadataText.setSelectionPending(false); metadataImages.setSelectionPending(false); versionEdit.setSelectionPending(false); diagnostics.setSelectionPending(false); artifactInspection.setSelectionPending(false); toolAcquisition.setSelectionPending(false); offlinePreflight.setSelectionPending(false); localStore.setSelectionPending(false); localStorePrepare.setSelectionPending(false); localStoreExecute.setSelectionPending(false); localStoreReconcile.setSelectionPending(false); localHistory.setSelectionPending(false); appleProvisioning.setSelectionPending(false); androidBuild.setSelectionPending(false); projectRecovery.setSelectionPending(false); iosArchive.setSelectionPending(false); }
  };

  const changeApplicationRepository = (value: string) => {
    if (versionEnrollmentBusy()) return;
    githubGhEntry.beforeContextIntent();
    retireIdentity();
    if (value === applicationRepositoryRef.current) return;
    externalObserver.beforeWorkspaceAction();
    advanceConnectionContext(); applicationRepositoryRef.current = value;
    // Invalidate synchronously, before React can publish this input edit.
    syncConnectionContext(); setApplicationRepository(value);
  };

  const validate = async () => {
    externalObserver.beforeWorkspaceAction();
    if (!api || savedCommandBusy() || !session?.draft || validateReason !== null || session.validationRequest || session.reviewRequest) return;
    const projectId = session.project.id;
    const requestId = ++requests.current;
    const revision = session.revision;
    const baselineGeneration = session.baselineGeneration;
    const draft = structuredClone(session.draft);
    passivePending.current += 1; setPassivePending(passivePending.current);
    try {
      dispatch({ type: 'validate-start', projectId, requestId, revision, baselineGeneration });
      const result = await api.validate(draft);
      dispatch({ type: 'validate-done', projectId, requestId, result });
    } catch (error) { dispatch({ type: 'validate-failed', projectId, requestId, error: apiError(error) }); }
    finally { passivePending.current -= 1; setPassivePending(passivePending.current); }
  };

  const review = async () => {
    externalObserver.beforeWorkspaceAction();
    if (!api || savedCommandBusy() || !session?.draft || reviewReason !== null || session.reviewRequest || session.validationRequest) return;
    const projectId = session.project.id;
    const binding = { id: ++requests.current, revision: session.revision, baselineGeneration: session.baselineGeneration };
    const base = structuredClone(session.baseline);
    const draft = structuredClone(session.draft);
    passivePending.current += 1; setPassivePending(passivePending.current);
    try {
      dispatch({ type: 'review-start', projectId, binding });
      const result = await api.configPreview(base, draft);
      dispatch({ type: 'review-done', projectId, requestId: binding.id, result });
    } catch (error) { dispatch({ type: 'review-failed', projectId, requestId: binding.id, error: apiError(error) }); }
    finally { passivePending.current -= 1; setPassivePending(passivePending.current); }
  };

  const suggest = async () => {
    externalObserver.beforeWorkspaceAction();
    if (!api || savedCommandBusy() || !session || session.draft !== null || suggestReason !== null || session.suggestionRequest || session.snapshotRequest) return;
    const projectId = session.project.id;
    const projection = suggestionHints(session.snapshot?.discovery.hints ?? null);
    const binding = {
      id: ++requests.current, revision: session.revision, baselineGeneration: session.baselineGeneration,
      observationGeneration: session.observationGeneration, observedHints: session.snapshot !== null,
      partial: session.snapshot?.discovery.partial ?? false, omittedStrings: projection.omittedStrings,
    };
    passivePending.current += 1; setPassivePending(passivePending.current);
    try {
      dispatch({ type: 'suggest-start', projectId, binding });
      const result = await api.suggestConfig(projection.hints);
      dispatch({ type: 'suggest-done', projectId, requestId: binding.id, result });
    } catch (error) { dispatch({ type: 'suggest-failed', projectId, requestId: binding.id, error: apiError(error) }); }
    finally { passivePending.current -= 1; setPassivePending(passivePending.current); }
  };

  const edit = (path: string, value: JsonValue | undefined) => {
    if (session) dispatch({ type: 'edit', projectId: session.project.id, path, value });
  };

  const projectPathStartReason = (): string | null => {
    const owner = projectPathOwnerReason(pathPickerRef.current); if (owner) return owner;
    if (bootstrapPending.current) return 'Application capabilities are being loaded. Text entry remains available.';
    const service = pathService.current;
    return projectPathAvailabilityReason(service.info, service.api?.mode ?? 'unavailable')
      ?? savedCommandBusy() ?? savedCommandPrerequisiteReason();
  };
  const chooseProjectPath = async (field: ProjectPathField) => {
    const service = pathService.current;
    // A queued click from an older editor cannot select into a different view.
    if (!session || workspaceRef.current.selectedId !== session.project.id || workspaceRef.current.projects[session.project.id] !== session) return;
    if (!service.api || projectPathStartReason() !== null || !catalog?.fields.some((entry) => entry.path === field && entry.input === 'text')) return;
    const next = beginProjectPath(pathPickerRef.current, workspaceRef.current, field, service);
    if (next === pathPickerRef.current || !next.pending) return;
    const binding = next.pending;
    publishPathPicker(next);
    const finish = (outcome: { reply: unknown } | { error: unknown }) => {
      const completion = finishProjectPath(pathPickerRef.current, binding, workspaceRef.current, pathService.current, outcome);
      // Consume once before ordinary onEdit dispatch, never auto-save, replace a
      // baseline, switch projects or unset the other Xcode field.
      publishPathPicker(completion.state);
      if (completion.edit) edit(completion.edit.field, completion.edit.value);
    };
    try { finish({ reply: await service.api.chooseProjectPath({ projectId: binding.projectId, field: binding.field }) }); }
    catch (error) { finish({ error }); }
  };

  const draftRetained = (projectId: string) => !!(identityBusy() && identityRef.current?.native.getState().projectId === projectId) || initializationRetainsDraft(initialization.getSnapshot(),projectId) || editRetainsDraft(configEdit.getSnapshot(), projectId) || workflowRetainsDraft(workflowEdit.getSnapshot(), projectId) || metadataRetainsDraft(metadataText.getSnapshot(), projectId) || versionRetainsDraft(versionEdit.getSnapshot(), projectId);

  const editor = (metadataOnly = false) => <DraftEditor
    key={`${session?.project.id ?? 'none'}-${metadataOnly ? 'metadata' : 'settings'}`}
    catalog={catalog} session={session} metadataOnly={metadataOnly} preview={preview}
    chooseReason={chooseReason}
    pathPicker={{ reason: projectPathStartReason(), pendingField: pathPicker.eligible?.field ?? null, onBrowse: (field) => void chooseProjectPath(field) }}
    validateReason={loading ? 'Engine capabilities are being loaded.' : validateReason}
    reviewReason={loading ? 'Engine capabilities are being loaded.' : reviewReason}
    suggestReason={loading ? 'Engine capabilities are being loaded.' : suggestReason}
    saveReason={loading ? 'Application capabilities are being loaded.' : savedCommandBusy() ?? diagnosticsOwnerReason(diagnosticsState) ?? (session ? workflowOwnerReason(workflowState, session.project.id) ?? metadataOwnerReason(metadataState, session.project.id) : null) ?? editStartReason(saveState, session)}
    discardReason={versionEnrollmentBusy() ?? (session && draftRetained(session.project.id) ? 'Keep this draft until the original native file-edit session has settled. Closing a review is separate from discarding draft data.' : null)}
    onChoose={() => void chooseProject()} onEdit={edit} onValidate={() => void validate()}
    onReview={() => void review()} onSuggest={() => void suggest()}
    onPrepareSave={() => { if (session) { dispatch({ type: 'config-save-intent', projectId: session.project.id }); releaseInputs.saveIntent(); releaseVersion.saveIntent(); if (workspaceRef.current.selectedId === session.project.id) configEdit.start(session.project.id); } }}
    onAdoptSuggestion={(requestId) => { if (session) dispatch({ type: 'adopt-suggestion', projectId: session.project.id, requestId }); }}
    onRemoveForbidden={(reviewId, paths) => { if (session) dispatch({ type: 'remove-forbidden', projectId: session.project.id, reviewId, paths }); }}
    onUndoRemoval={(removalId) => { if (session) dispatch({ type: 'undo-removal', projectId: session.project.id, removalId }); }}
    onForgetRemoval={(removalId) => { if (session) dispatch({ type: 'forget-removal', projectId: session.project.id, removalId }); }}
    onNewDraft={() => { if (session && catalog) dispatch({ type: 'new-draft', projectId: session.project.id, draft: emptyDraft(catalog.schema) }); }}
    onDiscard={() => { if (session && !draftRetained(session.project.id)) setDiscardProject(session.project.id); }} onHelp={setHelp}
  />;

  const workflowPanel = (detailed: boolean) => <GitHubWorkflowApply state={workflowState} controller={workflowEdit} setup={githubState} projects={workspace.projects} selectedId={workspace.selectedId} detailed={detailed}
    onShowProject={(projectId) => { dispatch({ type: 'switch', projectId }); navigate('github'); }} onHelp={setHelp} />;
  const showMetadataProject = (projectId: string, key?: string) => {
    dispatch({ type: 'switch', projectId });
    if (key) metadataText.selectContext(key);
    navigate('metadata');
  };
  const showVersionProject = (projectId: string) => {
    if (connectionPicking.current || !Object.hasOwn(workspaceRef.current.projects, projectId) ||
        workspaceRef.current.projects[projectId]?.project.id !== projectId) return;
    if (workspaceRef.current.selectedId !== projectId) dispatch({ type: 'switch', projectId });
    navigate('dashboard');
  };
  const showRetainedEditProject = (attention: RetainedEditAttention) => {
    const projects = workspaceRef.current.projects;
    if (connectionPicking.current || !Object.hasOwn(projects, attention.projectId) ||
        projects[attention.projectId]?.project.id !== attention.projectId) return;
    // Preserve ordinary context retirement and drafts. This does not recover an
    // edit, reload its original outcome, or infer a public-text locale.
    if (workspaceRef.current.selectedId !== attention.projectId) dispatch({ type: 'switch', projectId: attention.projectId });
    navigate(attention.page);
  };

  const identityInput = savedIdentityInput(session, session ? identityInputs.current.get(session.project.id) : undefined);
  const retainedIdentityText = session ? identityTexts.current.get(session.project.id) ?? '' : '';
  const identityAttention = identityBusy() !== null || !!identityUi?.session && (identityUi.tone === 'danger' || identityUi.tone === 'warning');
  const changeIdentityInput = (next: IdentityInput) => {
    if (!session || workspaceRef.current.selectedId !== session.project.id || next.target.length > 255) return;
    retireIdentity(); identityInputs.current.set(session.project.id, next);
    identityRef.current?.ui.sync(); updateIdentityInputs((value) => value + 1);
  };
  const identityTargetHints = iosAppTargetHints(session);
  const currentIdentityTargetChoice = (): IosTargetChoiceContext => {
    const w = workspaceRef.current, selected = w.selectedId ? w.projects[w.selectedId] ?? null : null;
    const binding = identityRef.current, service = pathService.current;
    return { session: selected, service, binding, epoch: identityEpoch.current,
      platform: savedIdentityInput(selected, selected ? identityInputs.current.get(selected.project.id) : undefined).platform,
      blocked: service.api?.mode !== 'native' || !binding || binding.service !== service || !!binding.proposal ||
        connectionPicking.current || bootstrapPending.current || identityBusy() !== null || identityAdmission.current() !== null };
  };
  // Pin the rendered saved observation, not whichever project a late click sees.
  const shownIdentityTargetChoice = { ...currentIdentityTargetChoice(), session, platform: identityInput.platform };
  const chooseIdentityTarget = (name: string) => copyIosAppTarget(identityTargetHints, shownIdentityTargetChoice, name,
    currentIdentityTargetChoice, retireIdentity, (target) => {
      if (!session) return;
      identityInputs.current.set(session.project.id, { platform: 'ios', target });
      identityRef.current?.ui.sync(); updateIdentityInputs(value => value + 1);
    });
  const keepIdentityText = (text: string) => {
    const current = identityRef.current?.ui.getSnapshot().context;
    if (current?.projectId && text.length <= 255 && Object.hasOwn(workspaceRef.current.projects, current.projectId))
      identityTexts.current.set(current.projectId, text);
  };
  const showIdentity = () => {
    const original = identityRef.current?.native.getState().projectId;
    if (original && Object.hasOwn(workspaceRef.current.projects, original) && workspaceRef.current.selectedId !== original)
      dispatch({ type: 'switch', projectId: original });
    setIdentityReveal((value) => value + 1); navigate('settings');
  };

  const toolPreparationView: PrepareBuildEnvironmentProps = {
    state: toolAcquisitionState, controller: toolAcquisition,
    toolsBusy: loading || choosing || savedCommandBusy() !== null || diagnosticsOwnerReason(diagnosticsState) !== null,
    chooseSource: (role) => { toolAcquisition.toolInputsIntent(); return androidBuild.chooseToolSource(role); },
    choosePreparedSource: (role) => toolAcquisition.choosePreparedSource(role,(selected,original) => androidBuild.chooseToolSource(selected,original)),
    refreshCatalog: () => { toolAcquisition.toolInputsIntent(); return androidBuild.refreshCatalog(); },
    openRegistration: () => { const section = androidToolSetupSection.current; section?.focus({ preventScroll: true }); section?.scrollIntoView({ block: 'start' }); },
  };

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to workspace</a>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><Icon name="box" size={25} /></span><div>Mobile Release Kit<span>THE KIT FOR A CAREFUL LAUNCH</span></div></div>
      <div className="project-switcher"><label htmlFor="project-switch">CURRENT PROJECT</label><div className="project-switcher-control"><span className="project-switch-icon"><Icon name="folder" size={18} /></span><select id="project-switch" aria-label="Switch project; unsaved configuration, text and version drafts are retained" value={workspace.selectedId ?? ''} onChange={(event) => dispatch({ type: 'switch', projectId: event.target.value })}><option value="" disabled>{choosing ? 'Opening project…' : 'Choose a project'}</option>{Object.values(workspace.projects).map((entry) => <option key={entry.project.id} value={entry.project.id}>{entry.project.name}{isDirty(entry) ? ' • unsaved config' : ''}{metadataProjectDirty(metadataState.entries, entry.project.id) ? ' • unsaved text' : ''}{versionProjectDirty(versionEditState, entry.project.id) ? ' • unsaved version' : ''}</option>)}</select><button type="button" className="icon-button" disabled={chooseDisabled} aria-label={preview ? 'Load example project' : 'Open another project folder'} onClick={() => void chooseProject()}><Icon name="plus" size={16} /></button></div></div>
      <WorkspaceNavigation page={page} onNavigate={navigate} />
      <div className="sidebar-footer"><div className="foundation-label"><span className="local-dot" />{localEditingLabel}</div><p>Thoughtful preparation.<br />No accidental releases.</p><div className="sidebar-version"><span>{`DESKTOP ${info?.appVersion ?? 'Not loaded'}`}</span><Icon name="shield" size={14} /></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumbs"><Icon name="folder" size={16} /><span>{session?.project.name ?? 'Workspace'}</span><Icon name="chevron" size={13} /><strong>{currentNavigation?.label}</strong></div><div className="topbar-status"><span className="no-write-note"><Icon name="lock" size={13} />No automatic publishing</span><Badge tone={preview || appleProvisioningState.issue !== null || toolAcquisitionState.issue !== null || artifactInspectionState.nativeBlocked || initializationState.nativeBlocked || metadataImagesState.nativeBlocked || metadataImagesState.integrityFailed || metadataImagesState.generationLost || metadataImagesState.selectionIssue || metadataImagesState.editIssue || saveState.nativeBlocked || workflowState.nativeBlocked || metadataState.edit.nativeBlocked || versionEditState.edit.nativeBlocked || diagnosticsState.nativeBlocked || localHistoryState.blocked || localStoreState.blocked || localStorePrepareState.blocked || localStoreExecuteState.blocked || localStoreReconcileState.blocked || offlinePreflightState.nativeBlocked || androidBuildState.nativeBlocked || projectRecoveryState.nativeBlocked || iosArchiveState.nativeBlocked ? 'warning' : 'neutral'}>{preview ? 'Browser preview' : initializationState.status?.active ? 'Project setup · see status below' : recoveryBusy() ? 'Recovery · see status below' : androidBusy() ? 'Android build · see status below' : iosBusy() ? 'iOS build · see status below' : artifactBusy() ? 'Build files · see status below' : localHistoryBusy() ? 'Release history · see status below' : storeBusy() ? 'Store operation · see status below' : preflightBusy() ? 'Local checks · see status below' : toolPreparationBusy() ? 'Tool preparation · see status below' : diagnosticsState.status?.active ? 'Build tools · see status below' : saveState.status?.active ? 'Project settings task · see status below' : workflowState.status?.active ? 'GitHub files task · see status below' : metadataImagesOwnerReason(metadataImagesState) ? 'Store images · see status below' : metadataState.edit.status?.active ? 'Store listing task · see status below' : versionEditState.edit.status?.active ? 'Version task · see status below' : localEditingLabel}</Badge></div></header>
      {preview && <div className="preview-banner" role="status"><Icon name="environment" size={19} /><div><strong>BROWSER PREVIEW — EXAMPLE DATA ONLY</strong><span>No native bridge, project files, core validation, credentials, or release operations. Never use this view as evidence.</span></div></div>}
      <main id="main-content" tabIndex={-1} ref={main}>
        {loading && <div className="notice notice-info" role="status"><Icon name="refresh" className="spin" size={19} /><span>Connecting to the app and loading project settings…</span></div>}
        {bootError && <><ErrorNotice error={bootError} title="The native service is unavailable" /><div className="bridge-retry"><button className="button small secondary" disabled={loading || savedCommandBusy() !== null} onClick={() => void bootstrap()}><Icon name="refresh" size={15} />Retry connection</button><span>No browser fallback or mock engine has been enabled.</span></div></>}
        {identityBinding && identityState && identityBusy() && <div className={`notice ${identityBinding.rebindFailed || identityState.issue ? 'notice-warning' : 'notice-info'}`} role={identityBinding.rebindFailed || identityState.issue ? 'alert' : 'status'}>
          <Icon name="info" /><div><strong>App ID task · {identityState.projectId ? workspace.projects[identityState.projectId]?.project.name ?? 'a previously selected project' : 'original project'}</strong>
            <p>{identityBusy()}</p>
            {identityBinding.rebindFailed && <p>The previous connection’s controls are no longer available. No replacement connection was opened for this task, and your local drafts are kept.</p>}
            {identityState.issue && <p>Keep the app open and preserve its project files. Your drafts are kept; reconnecting or repeating the change cannot clear an unconfirmed result.</p>}
            <div className="button-row">
              <button type="button" className="button small secondary" disabled={identityBinding.rebindFailed || identityState.reading} onClick={() => identityBinding.native.checkStatus()}>Check original status</button>
              <button type="button" className="button small secondary" disabled={identityBinding.rebindFailed || !identityBinding.native.canRequestClose() || identityState.issue === 'generation-changed' || identityState.issue === 'cleanup-unknown'}
                onClick={() => identityBinding.native.requestClose()}>{identityState.closeRequested ? 'Close requested — wait for status' : 'Request close'}</button>
              <button type="button" className="button small secondary" onClick={showIdentity}>Show app ID review</button>
            </div>
          </div></div>}
        {page !== 'github' && <LocalGitReadControls controller={gitRead} compact
          originalProjectName={gitReadState.original ? workspace.projects[gitReadState.original.context.projectId]?.project.name : undefined}
          onShow={() => navigate('github')} />}
        {(page !== 'github' || !gitRepository) && <GitLocalControls controller={gitLocal} compact={page !== 'github'}
          originalProjectName={gitLocalProjectName} onShow={() => navigate('github')} />}
        {catalogError && <ErrorNotice error={catalogError} title="The field catalogue could not be loaded" />}
        {chooseError && <ErrorNotice error={chooseError} title="The project could not be selected" />}
        {page !== 'settings' && cliReadNeedsAttention && <div className={`notice ${cliReadState.issue ? 'notice-warning' : 'notice-info'}`} role={cliReadState.issue ? 'alert' : 'status'}>
          <Icon name="info" /><div><strong>{cliReadState.issue ? 'CLI access needs attention' : 'CLI access request is finishing'}</strong>
            <p>{cliReadState.issue === 'revoke-unconfirmed' ? 'Turning off access was not confirmed. Review access before continuing.' : cliReadState.issue ? 'The last access request could not be confirmed. Your saved files have not been changed by this read-only feature.' : 'Other tasks will be available when this request finishes. You can still turn off access.'}</p>
            <button type="button" className="button small secondary" onClick={() => { setCliAccessReveal((value) => value + 1); navigate('settings'); }}>Show CLI access</button>
          </div></div>}
        {externalObservation.recovery && <div className="notice notice-warning" role="alert"><Icon name="info" />
          <div><strong>A saved-file check needs attention</strong>
            <p>The earlier check for {workspace.projects[externalObservation.recovery.projectId]?.project.name ?? 'a previously selected project'} could not confirm cleanup.
              Your drafts are preserved. New checks and tasks are paused. Keep the app open and preserve the project files; do not repeat the check or reconnect to dismiss this warning.</p>
          </div></div>}
        {!externalObservation.recovery && externalObservation.projectId === session?.project.id && externalObservation.notice &&
          <div className={`notice ${externalObservation.notice.kind === 'unavailable' ? 'notice-warning' : 'notice-info'}`} role="status">
            <Icon name="info" /><span>{externalObservation.notice.message}</span>
            <div className="button-row">
              {externalObservation.notice.next === 'review-settings' && <button type="button" className="button small secondary" onClick={() => navigate('settings')}>Review project settings</button>}
              {externalObservation.notice.next === 'read-saved-version' && <button type="button" className="button small secondary" disabled={releaseVersion.startReason() !== null}
                onClick={() => { navigate('dashboard'); externalObserver.beforeWorkspaceAction(); toolAcquisition.versionIntent(); appleProvisioning.versionIntent(); void releaseVersion.read(); }}>Read updated version</button>}
              {externalObservation.notice.next === 'refresh-project' && <button type="button" className="button small secondary" disabled={loading || refreshReason !== null}
                onClick={() => { if (session) void loadSnapshot(session.project.id); }}>Check saved files again</button>}
              <button type="button" className="button small secondary" onClick={() => externalObserver.dismissNotice()}>Dismiss</button>
            </div>
          </div>}
        {agentRequests?.pending && <div className="notice notice-info" role="status"><div>
          <strong>CLI app ID proposal awaiting your review</strong><p><code>{agentRequests.pending.request.change.desiredIdentity}</code> · registered project {agentRequests.pending.runtimeId}</p>
          <p>No edit has been approved. Your settings and local app ID draft are kept.</p>
          <div className="button-row"><button type="button" className="button small secondary"
            disabled={identityBusy() !== null || session?.project.id !== agentRequests.pending.runtimeId || identityAdmission.current() !== null}
            onClick={() => { const proposal = agentRequests.pending; if (!proposal || session?.project.id !== proposal.runtimeId) return;
              connectIdentity(pathService.current, proposal); if (identityRef.current?.proposal === proposal) { navigate('settings'); setIdentityReveal((n) => n + 1); } }}>Open request review</button>
            <button type="button" className="button small secondary" disabled={agentRequestPending}
              onClick={() => void agentRequestAction('decline', agentRequests.pending!.request.intentId)}>Decline proposal</button></div>
        </div></div>}
        {(pathPicker.pending || pathPicker.unverified || pathPicker.message) && <div className={`notice ${pathPicker.unverified ? 'notice-warning' : 'notice-info'}`} role={pathPicker.unverified ? 'alert' : 'status'}>
          <Icon name="info" /><span>{projectPathOwnerReason(pathPicker) ?? pathPicker.message}{pathPicker.pending ? ' If the original picker is still open, its Cancel button leaves the draft unchanged.' : ''}</span></div>}
        {info?.runtime.state !== 'available' && info && !preview && <div className="notice notice-warning"><Icon name="info" /><div><strong>{info.runtime.state === 'disabled' ? 'The engine is disabled' : 'Bundled engine unavailable'}</strong><p>{info.runtime.reason ?? 'A trusted packaged runtime has not been supplied. The app will not select an ambient Python or a mock engine.'} Folder selection does not establish a project observation.</p></div></div>}
        {page !== 'artifacts' && <ArtifactInspection state={artifactInspectionState} controller={artifactInspection} compact
          projectName={session?.project.name??null} onHelp={setHelp} onShow={()=>navigate('artifacts')}/>}
        {page !== 'dashboard' && <AppleBundleRegistration controller={appleProvisioning} state={appleProvisioningState} compact
          onCredentials={() => navigate('credentials')} onProjectIdentity={() => { navigate('settings'); setIdentityReveal(n => n + 1); }}
          onShow={() => navigate('dashboard')} />}
        {page !== 'releases' && <>
          <LocalReleaseHistory state={localHistoryState} controller={localHistory} compact onShow={()=>navigate('releases')}/>
          <LocalStorePreflight state={localStoreState} controller={localStore} compact onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
          <LocalStorePrepare state={localStorePrepareState} controller={localStorePrepare} compact onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
          <LocalStoreExecute state={localStoreExecuteState} controller={localStoreExecute} compact onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
          <LocalStoreReconcile state={localStoreReconcileState} controller={localStoreReconcile} compact onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
        </>}
        {page !== 'releases' && <OfflinePreflight state={offlinePreflightState} controller={offlinePreflight} compact
          projectName={session?.project.name ?? null} operationProjectName={offlinePreflightState.status?.operation ? workspace.projects[offlinePreflightState.status.operation.context.projectId]?.project.name ?? null : null}
          onShow={() => navigate('releases')} />}
        {page !== 'releases' && <AndroidBuild state={androidBuildState} controller={androidBuild} compact
          projectName={session?.project.name ?? null} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null}
          onShow={() => navigate('releases')} onHelp={setHelp} />}
        {page !== 'recovery' && <ProjectRecovery state={projectRecoveryState} controller={projectRecovery} compact
          projectName={session?.project.name ?? null} operationProjectName={projectRecoveryState.status?.operation ? workspace.projects[projectRecoveryState.status.operation.context.projectId]?.project.name ?? null : null}
          onShow={() => navigate('recovery')} onHelp={setHelp} />}
        {page !== 'releases' && <IOSArchive state={iosArchiveState} controller={iosArchive} compact
          projectName={session?.project.name ?? null} operationProjectName={iosArchiveState.status?.operation ? workspace.projects[iosArchiveState.status.operation.context.projectId]?.project.name ?? null : null}
          onShow={() => navigate(iosArchiveState.status?.operation?.context.operation === 'ios-local-recovery' ? 'recovery' : 'releases')} onHelp={setHelp} />}
        {page !== 'environment' && <EnvironmentDiagnostics state={diagnosticsState} controller={diagnostics} compact onShow={() => navigate('environment')} />}
        {(page !== 'environment' || environmentState.platform !== 'android' || environmentState.operation !== 'build') &&
          <PrepareBuildEnvironment {...toolPreparationView} compact />}
        {page !== 'github' && <GitHubGhEntry controller={githubGhEntry} compact
          originalProjectName={githubGhState.originalProjectId ? workspace.projects[githubGhState.originalProjectId]?.project.name : undefined}
          onShow={() => navigate('github')} />}
        {page !== 'github' && (connectionState.busy || connectionState.uncertain || connectionState.blocked || connectionState.retirementPending) &&
          <div className={`notice ${connectionState.uncertain || connectionState.blocked ? 'notice-warning' : 'notice-info'}`} role="status">
            <Icon name="github" /><div><strong>Original GitHub connection · {originalConnection?.session?.projectId ? workspace.projects[originalConnection.session.projectId]?.project.name ?? 'a previously selected project' : 'selected app'}</strong>
              <p>{connectionState.uncertain || connectionState.blocked ? 'The original result needs attention. Do not connect again or switch accounts to bypass it.' : 'The original connection task is still finishing.'}</p>
              <div className="button-row">
                <button type="button" className="button small secondary" disabled={!githubConnection.canCheckStatus() || connectionState.observing} onClick={() => void githubConnection.checkStatus()}>Check original connection status</button>
                <button type="button" className="button small secondary" disabled={!githubConnection.canDisconnect()} onClick={() => githubConnection.disconnect()}>Disconnect original connection</button>
                <button type="button" className="button small secondary" onClick={() => navigate('github')}>Show GitHub connection</button>
              </div>
            </div></div>}
        {page !== 'github' && <VersionEnrollmentPanel controller={versionEnrollment} compact />}
        {page !== 'github' && <GitHubPublication state={githubPublicationState} controller={githubPublication} compact onShow={() => navigate('github')} />}
        {page !== 'github' && <GitHubRemoteSetup state={githubRemoteSetupState} controller={githubRemoteSetup} compact onShow={() => navigate('github')} onHelp={setHelp} />}
        {page !== 'github' && <GitHubPreflight state={githubPreflightState} controller={githubPreflight} compact onShow={() => navigate('github')} onHelp={setHelp} />}
        {page !== 'github' && <GitHubHistory state={githubHistoryState} controller={githubHistory} compact onShow={() => navigate('github')} onHelp={setHelp} />}
        {page !== 'releases' && <GitHubRelease state={githubReleaseState} controller={githubRelease} compact onShow={() => navigate('releases')} onHelp={setHelp} />}
        <ConfigSave state={saveState} projects={workspace.projects} catalog={catalog} selectedId={workspace.selectedId} detailed={page === 'settings' || page === 'metadata'} onReviewVersion={showVersionProject}
          onInspectRecovery={(projectId) => configEdit.inspectRecovery(projectId)} onRecoveryApply={(binding) => configEdit.applyRecovery(binding)}
          recoveryReason={workspace.selectedId ? configEdit.inspectRecoveryReason(workspace.selectedId) : 'Select an original registered project first.'}
          recoveryApplyBinding={configEdit.currentRecoveryApplyBinding()} onRecoveryClose={() => configEdit.requestRecoveryClose()}
          onRecoveryReload={(projectId) => { if (!configEdit.getSnapshot().status?.active && !configEdit.getSnapshot().nativeBlocked) void loadSnapshot(projectId, true); }}
          onCheck={() => void configEdit.checkStatus()} onClose={() => configEdit.requestClose()} onApply={(binding) => { const projectId = configEdit.getSnapshot().attempt?.binding.projectId; if (projectId) dispatch({ type: 'config-save-intent', projectId }); releaseInputs.saveIntent(); releaseVersion.saveIntent(); return configEdit.apply(binding); }}
          onShowProject={(projectId) => { dispatch({ type: 'switch', projectId }); navigate('settings'); }} onHelp={setHelp} />
        {page !== 'dashboard' && (initializationState.attempt || initializationState.nativeBlocked) && <ProjectInitialization controller={initialization} state={initializationState} setup={githubSetup} setupState={githubState} compact/>}
        {page !== 'github' && workflowPanel(false)}
        {page !== 'metadata' && <MetadataTextSave state={metadataState} controller={metadataText} detailed={false} onShowProject={showMetadataProject} onHelp={setHelp} />}
        {page !== 'metadata' && <MetadataImagesOperation state={metadataImagesState} controller={metadataImages} detailed={false} onShowProject={showMetadataProject} onHelp={setHelp} />}
        {page !== 'dashboard' && <ReleaseVersionSave state={versionEditState} controller={versionEdit} onShowProject={showVersionProject} />}
        {page === 'dashboard' && <Dashboard session={session} info={info} preview={preview} configSaveState={saveState} chooseDisabled={chooseDisabled} chooseReason={chooseReason} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
          setupReadinessReason={(loading ? 'Capabilities are loading.' : refreshReason) ?? configurationOwnerReason(saveState, session?.project.id ?? '') ??
            workflowOwnerReason(workflowState, session?.project.id ?? '') ?? metadataOwnerReason(metadataState, session?.project.id ?? '') ??
            (passivePending.current > 0 ? 'An original project read is still pending.' : null)}
          appleProvisioningPanel={<AppleBundleRegistration controller={appleProvisioning} state={appleProvisioningState}
            savedBundleId={textValue(getValue(session?.snapshot?.config.data ?? null, 'ios.bundleId'))}
            configuredTeamId={textValue(getValue(session?.snapshot?.config.data ?? null, 'ios.teamId'))}
            onCredentials={() => navigate('credentials')} onProjectIdentity={() => { navigate('settings'); setIdentityReveal(n => n + 1); }} />}
          appleProvisioningNeedsAttention={appleProvisioningState.retained || appleProvisioningState.issue !== null || appleProvisioningState.consent !== null || appleProvisioningState.result?.decision === 'registration-unconfirmed' || appleProvisioningState.status?.operation?.phase === 'terminal' && appleProvisioningState.status.operation.outcome !== 'complete'}
          initializationState={initializationState} versionEditState={versionEditState}
          initializationPanel={<ProjectInitialization controller={initialization} state={initializationState} setup={githubSetup} setupState={githubState}/>}
          versionEditor={<ReleaseVersionEditor state={versionEditState} controller={versionEdit} session={session} onSettings={() => navigate('settings')} onHelp={setHelp} onShowProject={showVersionProject} />}
          releaseVersionState={releaseVersionState} releaseVersionReason={releaseVersion.startReason()} onReadVersion={() => { externalObserver.beforeWorkspaceAction(); artifactInspection.versionIntent(); androidBuild.versionIntent(); iosArchive.versionIntent(); toolAcquisition.versionIntent(); appleProvisioning.versionIntent(); void releaseVersion.read(); }}
          onChoose={() => void chooseProject()} onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} onNavigate={navigate} onHelp={setHelp} />}
        {page === 'settings' && <><PageHeading eyebrow="PROJECT SETTINGS" title="Set up your project" description="Change your app settings one group at a time. Review the proposed file changes before saving." />{editor()}
          <ProgressiveDisclosure title="App ID · keep this app or set up a separate new app" needsAttention={identityAttention} reveal={identityReveal}>
            <p>Keep the current ID when updating an existing app. This editor reads saved files; it never saves or replaces your unsaved settings draft.</p>
            {identityBinding && identityBinding.service === pathService.current && mode === 'native' ? <>
              <fieldset disabled={!session || identityBusy() !== null || !!identityBinding.proposal}><legend>Choose the app to inspect</legend>
                <label className="field"><span className="field-label">Platform</span><select value={identityInput.platform}
                  onChange={(event) => changeIdentityInput({ platform: event.target.value === 'ios' ? 'ios' : 'android', target: identityInput.target })}>
                  <option value="android">Android</option><option value="ios">iOS</option></select></label>
                {identityInput.platform === 'ios' && <IosAppTargetField value={identityInput.target} hints={identityTargetHints} choiceDisabled={shownIdentityTargetChoice.blocked}
                  onChange={target => changeIdentityInput({ platform: 'ios', target })} onChoose={chooseIdentityTarget} />}
                {identityInput.project && <p className="subtle-note">Saved Xcode project: <code>{identityInput.project}</code></p>}
              </fieldset>
              {identityInput.reason && <p className="review-caution">{identityInput.reason}</p>}
              {identityOtherReason && <p className="subtle-note">{identityOtherReason}</p>}
              <div className="button-row"><button type="button" className="button small secondary" disabled={!session || loading || refreshReason !== null || identityBusy() !== null}
                onClick={() => { if (session) void loadSnapshot(session.project.id); }}>Check saved project files</button></div>
              {!identityBinding.proposal && retainedIdentityText && retainedIdentityText !== identityUi?.desiredIdentity && <div className="notice notice-info">
                <div><strong>Your local app ID draft is kept</strong><p><code>{retainedIdentityText}</code></p>
                  <p>Read the app ID again before reusing this text. No earlier preview or approval carries over.</p>
                  <button type="button" className="button small secondary" disabled={!identityUi?.canChooseNew}
                    onClick={() => { if (identityBinding.ui.setIntent('new-application')) identityBinding.ui.setDesiredIdentity(retainedIdentityText); }}>Reuse local draft text</button>
                </div></div>}
              {identityBinding.proposal && <div className="button-row"><button type="button" className="button small secondary" disabled={identityBusy() !== null}
                onClick={() => connectIdentity(pathService.current, null)}>Return to my local app ID draft</button></div>}
              <ProjectIdentityEditor controller={identityBinding.ui} onDraftChange={identityBinding.proposal ? undefined : keepIdentityText}
                requestedChange={identityBinding.proposal?.request.change} />
            </> : <p>App ID editing needs the connected native Desktop app. No app ID files are changed here; your local drafts are kept.</p>}
          </ProgressiveDisclosure>
          <ProgressiveDisclosure title="Advanced · CLI / AI access" needsAttention={cliReadNeedsAttention || !!agentRequestMessage || !!agentRequests?.pending} reveal={cliAccessReveal}>
            <CliReadAccessPanel controller={cliReadAccess} />
            <AgentLocalCheckAccess controller={agentLocalChecks} blocked={loading || choosing || !session || savedCommandBusy() !== null} />
            {cliService.current.api?.mode === 'native' && cliService.current.api.agentIdentity && <section className="card"><h3>Let an agent propose an app ID</h3>
              <p>Separate from read access. Enable this only for the selected project, for up to 15 minutes. The CLI cannot Apply: you must read the saved source, acknowledge a new app when applicable, preview, and approve the exact native change here.</p>
              <p>Current observation: {agentRequests ? agentRequests.lease.enabled ? 'request permission was observed enabled' : 'request permission was observed disabled' : 'not checked'}. Status is not an approval or completed edit.</p>
              {agentRequestMessage && <p role="status" className="review-caution">{agentRequestMessage}</p>}
              <div className="button-row"><button type="button" className="button secondary" disabled={!session || !pathService.current.api?.agentIdentity || agentRequestPending || identityBusy() !== null}
                onClick={() => void agentRequestAction('allow')}>Allow identity proposals · 15 minutes</button>
                <button type="button" className="button secondary" disabled={agentRequestWork.current.revoke !== null}
                  onClick={() => void agentRequestAction('revoke')}>Revoke proposals and request original stop</button>
                <button type="button" className="button secondary" disabled={agentRequestPending || !pathService.current.api?.agentIdentity}
                  onClick={() => void agentRequestAction('status')}>Check requests</button></div>
              {agentRequests?.requests.map((row) => <p key={row.intentId}><code>{row.intentId}</code> · {row.state}
                {row.operationId && <> · original session <code>{row.operationId}</code>; query its separate operation history (which may be unavailable)</>}</p>)}
            </section>}
          </ProgressiveDisclosure></>}
        {page === 'environment' && <Environment info={info} api={api} preview={preview} session={session} state={environmentState} controller={environment}
          diagnosticsState={diagnosticsState} diagnosticsController={diagnostics} toolPreparation={toolPreparationView} toolSetup={{ state: androidBuildState, controller: androidBuild, onHelp: setHelp, sectionRef: androidToolSetupSection }} onRetry={() => void bootstrap()} onSettings={() => navigate('settings')} onHelp={setHelp} loading={loading} />}
        {page === 'credentials' && <Credentials catalog={catalog} state={assetState} controller={assetSession} project={session} inputState={releaseInputState} inputController={releaseInputs} onSettings={() => navigate('settings')} onHelp={setHelp}
          onOfflineChecks={() => reviewCredentialChecks('offline')} onAndroidSigning={() => reviewCredentialChecks('android-signing')}
          nativeBusyReason={savedCommandBusy() ?? diagnosticsOwnerReason(diagnosticsState)} />}
        {page === 'metadata' && <Metadata catalog={catalog} textEditor={<MetadataTextEditor state={metadataState} controller={metadataText} session={session} onShowProject={showMetadataProject} onHelp={setHelp} />}
          imageEditor={<MetadataImagesEditor state={metadataImagesState} controller={metadataImages} session={session} onShowProject={showMetadataProject} onHelp={setHelp} />}>{editor(true)}</Metadata>}
        {page === 'github' && <GitHub info={info} session={session} state={githubState} controller={githubSetup} loading={loading} onReload={() => void bootstrap()} onNavigate={navigate} credentialHelp={catalog?.credentials ?? null} onHelp={setHelp} nativeReview={workflowPanel(true)}
          connectionView={<><LocalGitRead controller={gitRead} repository={gitRepository} projectName={session?.project.name ?? 'No project selected'}
            localActions={gitRepository ? <GitLocalChanges controller={gitLocal} repository={gitRepository} originalProjectName={gitLocalProjectName} /> : undefined}
            originalProjectName={gitReadState.original ? workspace.projects[gitReadState.original.context.projectId]?.project.name : undefined} />
            {!gitRepository && gitRepositories.current.length >= 64 && <p className="review-caution">The local draft limit has been reached. Earlier drafts are kept; use your Git client for additional projects or service sessions.</p>}
            <GitHubConnection state={connectionState} controller={githubConnection} onHelp={setHelp} nativeBusyReason={savedCommandBusy()}
            repositoryInput={applicationRepository} onRepository={changeApplicationRepository} projectSelected={session !== null && !choosing}
            handoff={connectionHandoffRef.current}
            ghEntry={<GitHubGhEntry controller={githubGhEntry}
              originalProjectName={githubGhState.originalProjectId ? workspace.projects[githubGhState.originalProjectId]?.project.name : undefined} />} />
            {connectionState.helpState !== 'current' && <div className="button-row"><button type="button" className="button small secondary" disabled={loading} onClick={() => void bootstrap()}>Reload service and connection guidance</button></div>}
            <ProgressiveDisclosure title="Advanced · shared version counter" needsAttention={versionEnrollmentBusy() !== null || versionEnrollmentState.issue !== null}>
              <VersionEnrollmentPanel controller={versionEnrollment} />
            </ProgressiveDisclosure>
            <GitHubPublication state={githubPublicationState} controller={githubPublication} />
            <GitHubRemoteSetup state={githubRemoteSetupState} controller={githubRemoteSetup} assets={assetState} projectId={workspace.selectedId ?? null} onCredentials={() => navigate('credentials')} onHelp={setHelp} />
            <GitHubPreflight state={githubPreflightState} controller={githubPreflight} onHelp={setHelp} />
            <GitHubHistory state={githubHistoryState} controller={githubHistory} onHelp={setHelp} /></>} />}
        {page === 'releases' && <Releases onOpenGitHub={() => navigate('github')}
          storeNeedsAttention={!!(localHistoryBusy() ?? storeBusy()) || [localHistoryState, localStoreState, localStorePrepareState, localStoreExecuteState, localStoreReconcileState].some((state) => state.error !== null || state.status?.operation?.phase === 'terminal' && state.status.operation.outcome !== 'complete')}
          workflowNeedsAttention={githubReleaseOwnerReason(githubReleaseState) !== null || githubReleaseState.error !== null || githubRelease.currentPrepared() !== null}
          storeOperations={<>
            <LocalReleaseHistory state={localHistoryState} controller={localHistory} onShow={()=>navigate('releases')}/>
            <LocalStorePreflight state={localStoreState} controller={localStore} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
            <LocalStorePrepare state={localStorePrepareState} controller={localStorePrepare} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
            <LocalStoreExecute state={localStoreExecuteState} controller={localStoreExecute} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
            <LocalStoreReconcile state={localStoreReconcileState} controller={localStoreReconcile} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
          </>}
          protectedWorkflows={<GitHubRelease state={githubReleaseState} controller={githubRelease} onHelp={setHelp} onGitHub={() => navigate('github')} />} evidence={<ReleaseEvidence state={evidenceState} controller={releaseEvidence} projectName={session?.project.name ?? null} onHelp={setHelp} />} offlineChecks={<div ref={offlineCheckSection} tabIndex={-1} aria-label="Saved offline checks review"><OfflinePreflight state={offlinePreflightState} controller={offlinePreflight}
          projectName={session?.project.name ?? null} operationProjectName={offlinePreflightState.status?.operation ? workspace.projects[offlinePreflightState.status.operation.context.projectId]?.project.name ?? null : null}
          onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason} /></div>}
          androidBuild={<div ref={androidSigningSection} tabIndex={-1} aria-label="Android build and signing review"><AndroidBuild state={androidBuildState} controller={androidBuild}
            projectName={session?.project.name ?? null} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null}
            onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
            onReadVersion={() => { externalObserver.beforeWorkspaceAction(); toolAcquisition.versionIntent(); appleProvisioning.versionIntent(); void releaseVersion.read(); }} versionReason={releaseVersion.startReason()} onHelp={setHelp}
            onCredentials={() => navigate('credentials')} onSettings={() => navigate('settings')} onRecovery={() => navigate('recovery')} />
            <AgentAndroidBuildAccess controller={agentAndroidBuild} /></div>}
          iosArchive={<IOSArchive state={iosArchiveState} controller={iosArchive}
            projectName={session?.project.name ?? null} operationProjectName={iosArchiveState.status?.operation ? workspace.projects[iosArchiveState.status.operation.context.projectId]?.project.name ?? null : null}
            onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
            onReadVersion={() => { externalObserver.beforeWorkspaceAction(); toolAcquisition.versionIntent(); appleProvisioning.versionIntent(); void releaseVersion.read(); }} versionReason={releaseVersion.startReason()} onHelp={setHelp}
            onCredentials={() => navigate('credentials')} onSettings={() => navigate('settings')} onRecovery={() => navigate('recovery')} />} />}
        {page === 'artifacts' && <><Artifacts state={evidenceState} controller={releaseEvidence} inspectionState={artifactInspectionState} inspectionController={artifactInspection} projectName={session?.project.name ?? null} onHelp={setHelp} />
          <AndroidBuildResultView state={androidBuildState} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null} />
          <IOSArchiveResultView state={iosArchiveState} operationProjectName={iosArchiveState.status?.operation ? workspace.projects[iosArchiveState.status.operation.context.projectId]?.project.name ?? null : null} /></>}
        {page === 'recovery' && <><Recovery onOpenReleases={() => navigate('releases')} evidenceGuidance={<ReleaseEvidenceGuidance state={evidenceState} onOpenEvidence={() => navigate('releases')} />}
          projectRecovery={<ProjectRecovery state={projectRecoveryState} controller={projectRecovery}
          projectName={session?.project.name ?? null} operationProjectName={projectRecoveryState.status?.operation ? workspace.projects[projectRecoveryState.status.operation.context.projectId]?.project.name ?? null : null}
          onHelp={setHelp} />}
          attention={retainedEditAttention(workspace.projects, saveState.recoveryProjects, workflowState.recoveryProjects, metadataState.edit.recoveryProjects, versionEditState.edit.recoveryProjects, initializationState.recoveryProjects)}
          choosingProject={choosing} onOpenProject={showRetainedEditProject} onHelp={setHelp} />
          <IOSRecovery state={iosArchiveState} controller={iosArchive} projectName={session?.project.name ?? null}
            operationProjectName={iosArchiveState.status?.operation ? workspace.projects[iosArchiveState.status.operation.context.projectId]?.project.name ?? null : null} onHelp={setHelp} /></>}
        <footer className="workspace-footer"><span><Icon name="shield" size={14} />Configuration is not verification.</span><span>{preview ? 'Illustration only · no engine connected' : 'Configuration desktop slice · not a completed release product'}</span></footer>
      </main>
    </div>
    <HelpDialog content={help} onClose={() => setHelp(null)} />
    {discardProject && <ConfirmDialog onCancel={() => setDiscardProject(null)}
      blockedReason={versionEnrollmentBusy() ?? (draftRetained(discardProject) ? 'An original native file-edit session is still active or unverified. Keep this draft; closing a review is not draft deletion.' : null)}
      observationPredatesSave={workspace.projects[discardProject]?.snapshotPredatesSave ?? false}
      onConfirm={() => { if (!versionEnrollmentBusy() && !draftRetained(discardProject)) dispatch({ type: 'reset', projectId: discardProject }); setDiscardProject(null); }} />}
  </div>;
}
