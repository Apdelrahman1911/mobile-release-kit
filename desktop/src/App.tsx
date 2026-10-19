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
import { emptyDraft } from './catalog.ts';
import { methodReason, projectSelectionReason } from './certainty.ts';
import { initialWorkspace, isDirty, retainedEditAttention, workspaceReducer } from './drafts.ts';
import type { RetainedEditAttention, WorkspaceAction } from './drafts.ts';
import { configurationOwnerReason, editRetainsDraft, editStartReason } from './configEdit.ts';
import { ConfigEditController } from './configEditController.ts';
import { GitHubSetupController } from './githubSetupController.ts';
import { EnvironmentController } from './environment.ts';
import { ReleaseVersionController } from './releaseVersion.ts';
import { ExternalProjectObservationController } from './externalProjectObservationController.ts';
import { ReleaseVersionEditController, versionOwnerReason, versionProjectDirty, versionRetainsDraft } from './releaseVersionEditController.ts';
import { versionEditError } from './releaseVersionEdit.ts';
import { ReleaseInputGuidanceController } from './releaseInputGuidance.ts';
import { LifecycleEvidenceController } from './lifecycleEvidence.ts';
import { ReleaseEvidence, ReleaseEvidenceGuidance } from './components/ReleaseEvidence.tsx';
import { EnvironmentDiagnosticsController, diagnosticsOwnerReason } from './environmentDiagnosticsController.ts';
import { OfflinePreflightController, offlinePreflightOwnerReason } from './offlinePreflight.ts';
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
import { GitHubConnectionController } from './githubConnectionController.ts';
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
  const offlinePreflightControllerRef = useRef<OfflinePreflightController | null>(null);
  const androidBuildControllerRef = useRef<AndroidBuildController | null>(null);
  const projectRecoveryControllerRef = useRef<ProjectRecoveryController | null>(null);
  const iosArchiveControllerRef = useRef<IOSArchiveController | null>(null);
  const bootstrapPending = useRef(true);
  // Original passive promises outlive retired display request bindings.
  const passivePending = useRef(0);
  const [, setPassivePending] = useState(0);
  const externalObserverRef = useRef<ExternalProjectObservationController | null>(null);
  const externalBusy = useCallback(() => externalObserverRef.current?.passiveBusyReason() ?? null, []);
  const connectionControllerRef = useRef<GitHubConnectionController | null>(null);
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
  const storeBusy = useCallback(() => storeReconcileBusy() ?? storeExecuteBusy() ?? storePrepareBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null), [storeReconcileBusy, storeExecuteBusy, storePrepareBusy]);
  const preflightBusy = useCallback(() => offlinePreflightControllerRef.current ? offlinePreflightOwnerReason(offlinePreflightControllerRef.current.getSnapshot()) : null, []);
  const androidBusy = useCallback(() => androidBuildControllerRef.current ? androidBuildOwnerReason(androidBuildControllerRef.current.getSnapshot()) : null, []);
  const iosBusy = useCallback(() => iosArchiveControllerRef.current ? iosArchiveOwnerReason(iosArchiveControllerRef.current.getSnapshot()) : null, []);
  const recoveryBusy = useCallback(() => projectRecoveryControllerRef.current ? projectRecoveryOwnerReason(projectRecoveryControllerRef.current.getSnapshot()) : null, []);
  const historyBusy = useCallback(() => githubHistoryControllerRef.current ? githubHistoryOwnerReason(githubHistoryControllerRef.current.getSnapshot()) : null, []);
  // Existing reciprocal admission callbacks also retain the original path
  // picker, even after its display eligibility was retired by a local edit.
  const savedOwnersBusy = useCallback((excludeVersion = false, excludeGitHubPreflight = false, excludeGitHubRelease = false, excludeImages = false, excludeInitialization = false, excludeRemoteSetup = false, excludeHistory = false, excludePublication = false) => localHistoryBusy() ?? storeBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? iosBusy() ?? recoveryBusy() ??
    (excludeHistory ? null : historyBusy()) ??
    (!excludePublication && githubPublicationControllerRef.current ? githubPublicationOwnerReason(githubPublicationControllerRef.current.getSnapshot()) : null) ??
    (!excludeRemoteSetup && githubRemoteSetupControllerRef.current ? githubRemoteSetupOwnerReason(githubRemoteSetupControllerRef.current.getSnapshot()) : null) ??
    (!excludeGitHubPreflight && githubPreflightControllerRef.current ? githubPreflightOwnerReason(githubPreflightControllerRef.current.getSnapshot()) : null) ??
    (!excludeGitHubRelease && githubReleaseControllerRef.current ? githubReleaseOwnerReason(githubReleaseControllerRef.current.getSnapshot()) : null) ?? projectPathOwnerReason(pathPickerRef.current) ??
    (!excludeInitialization && initializationControllerRef.current ? initializationOwnerReason(initializationControllerRef.current.getSnapshot(),workspaceRef.current.selectedId??'') : null) ??
    (!excludeVersion && versionEditControllerRef.current ? versionOwnerReason(versionEditControllerRef.current.getSnapshot(), workspaceRef.current.selectedId ?? '') : null) ??
    (!excludeImages && imageControllerRef.current ? metadataImagesOwnerReason(imageControllerRef.current.getSnapshot(), workspaceRef.current.selectedId ?? '') : null), [localHistoryBusy, storeBusy, artifactBusy, preflightBusy, androidBusy, recoveryBusy, iosBusy, historyBusy]);
  // Every existing new-action/read admission includes the actual passive
  // original. Only the observer itself uses the underlying owner-only helper.
  const savedCommandBusy = useCallback((...args: Parameters<typeof savedOwnersBusy>) =>
    savedOwnersBusy(...args) ?? externalBusy(), [savedOwnersBusy, externalBusy]);
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
  }, [connectionDocumentId]);
  const advanceConnectionContext = () => {
    if (connectionProjectGeneration.current === 0xffff_ffff) connectionGenerationLost.current = true;
    else connectionProjectGeneration.current += 1;
  };
  // Keep the reducer's latest state synchronously visible to save admission.
  // A React render/effect delay must not let an older review authorize Apply.
  const dispatch = useCallback((action: WorkspaceAction) => {
    externalObserverRef.current?.beforeWorkspaceAction();
    // Intent/event retirement must precede even an unchanged reducer result:
    // failed refresh and unchanged/older saves need not advance generations.
    retirePathPicker();
    githubPublicationControllerRef.current?.beforeWorkspaceAction();
    githubRemoteSetupControllerRef.current?.beforeWorkspaceAction();
    githubHistoryControllerRef.current?.beforeWorkspaceAction();
    artifactInspectionControllerRef.current?.beforeWorkspaceAction(action);
    offlinePreflightControllerRef.current?.beforeWorkspaceAction(action); localStoreControllerRef.current?.beforeWorkspaceAction(); localStorePrepareControllerRef.current?.beforeWorkspaceAction(); localStoreExecuteControllerRef.current?.beforeWorkspaceAction(); localStoreReconcileControllerRef.current?.beforeWorkspaceAction(); localHistoryControllerRef.current?.beforeWorkspaceAction();
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
    externalObserverRef.current?.syncContext();
    environmentControllerRef.current?.syncProject();
    releaseVersionControllerRef.current?.syncProject();
    versionEditControllerRef.current?.syncProject();
    releaseInputControllerRef.current?.syncProject();
    diagnosticsControllerRef.current?.syncProject();
    artifactInspectionControllerRef.current?.syncProject();
    offlinePreflightControllerRef.current?.syncProject(); localStoreControllerRef.current?.syncProject(); localStorePrepareControllerRef.current?.syncProject(); localStoreExecuteControllerRef.current?.syncProject(); localStoreReconcileControllerRef.current?.syncProject(); localHistoryControllerRef.current?.syncProject();
    androidBuildControllerRef.current?.syncProject();
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
  }, [syncConnectionContext, retirePathPicker]);
  const [configEdit] = useState(() => new ConfigEditController({
    project: (projectId) => Object.hasOwn(workspaceRef.current.projects, projectId) ? workspaceRef.current.projects[projectId] ?? null : null,
    otherEditReason: (projectId) => savedCommandBusy() ?? (diagnosticsControllerRef.current ? diagnosticsOwnerReason(diagnosticsControllerRef.current.getSnapshot()) : null) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null),
    selectedProject: () => { const w = workspaceRef.current; return w.selectedId ? w.projects[w.selectedId] ?? null : null; },
    recoveryUnavailable: () => externalBusy() ?? (passivePending.current > 0 || connectionPicking.current ? 'Finish the original observation or project selection first.' :
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
      androidBuildControllerRef.current?.versionIntent();offlinePreflightControllerRef.current?.versionIntent(); localStoreControllerRef.current?.versionIntent(); localStorePrepareControllerRef.current?.versionIntent(); localStoreExecuteControllerRef.current?.versionIntent(); localStoreReconcileControllerRef.current?.versionIntent(); localHistoryControllerRef.current?.versionIntent(); artifactInspectionControllerRef.current?.versionIntent();projectRecoveryControllerRef.current?.versionIntent();iosArchiveControllerRef.current?.versionIntent();
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
      androidBuildControllerRef.current?.versionIntent(); offlinePreflightControllerRef.current?.versionIntent(); localStoreControllerRef.current?.versionIntent(); localStorePrepareControllerRef.current?.versionIntent(); localStoreExecuteControllerRef.current?.versionIntent(); localStoreReconcileControllerRef.current?.versionIntent(); localHistoryControllerRef.current?.versionIntent(); artifactInspectionControllerRef.current?.versionIntent(); projectRecoveryControllerRef.current?.versionIntent(); iosArchiveControllerRef.current?.versionIntent();
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
      // Retire before the submitted intent/outcome can notify subscribers, even
      // for unchanged, failed or out-of-context saves. Never fabricate a Read.
      releaseVersion.saveIntent(); releaseInputs.saveIntent();
      androidBuildControllerRef.current?.versionIntent(); offlinePreflightControllerRef.current?.versionIntent(); localStoreControllerRef.current?.versionIntent(); localStorePrepareControllerRef.current?.versionIntent(); localStoreExecuteControllerRef.current?.versionIntent(); localStoreReconcileControllerRef.current?.versionIntent(); localHistoryControllerRef.current?.versionIntent(); artifactInspectionControllerRef.current?.versionIntent(); projectRecoveryControllerRef.current?.versionIntent(); iosArchiveControllerRef.current?.versionIntent();
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
  const savedOwnersPrerequisiteReason = (excludeVersion = false, excludeImages = false, imageStep?: 'open-held-selection', excludeInitialization = false, forHistoryRead = false): string | null => {
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
    if (connection.blocked || connection.uncertain || connection.busy || connection.retirementPending || !forHistoryRead && (connection.status ?? connection.retained)?.session)
      return 'Finish or disconnect the original GitHub session before starting saved project code.';
    if (passivePending.current > 0 || Object.values(workspaceRef.current.projects).some((project) => project.snapshotRequest !== null || project.validationRequest || project.reviewRequest || project.suggestionRequest) ||
        environment.getSnapshot().pending || environment.passiveBusyReason() || releaseVersion.getSnapshot().pending || releaseVersion.passiveBusyReason() ||
        releaseInputs.getSnapshot().pending || releaseInputs.passiveBusyReason() || githubSetup.getSnapshot().pending || githubSetup.passiveBusyReason() || metadataText.passiveBusyReason() ||
        !excludeImages && metadataImages.passiveBusyReason())
      return 'An original passive project query is still pending. Wait for it to settle before reviewing saved checks.';
    return null;
  };
  const savedCommandPrerequisiteReason = (...args: Parameters<typeof savedOwnersPrerequisiteReason>): string | null =>
    savedOwnersPrerequisiteReason(...args) ?? externalBusy();
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
  const [localStore] = useState(() => new LocalStorePreflightController({
    project: () => {const current=workspaceRef.current;return current.selectedId&&Object.hasOwn(current.projects,current.selectedId)?localStoreProjectObservation(current.projects[current.selectedId]!,releaseVersion.getSnapshot()):null;}, assets: assetSession.getSnapshot,
    otherOperationReason: () => storeReconcileBusy() ?? storeExecuteBusy() ?? storePrepareBusy() ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
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
    otherOperationReason: () => storeReconcileBusy() ?? storeExecuteBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null) ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
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
    otherOperationReason: () => storeReconcileBusy() ?? storePrepareBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null) ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
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
    otherOperationReason: () => storeExecuteBusy() ?? storePrepareBusy() ?? (localStoreControllerRef.current ? localStoreOwnerReason(localStoreControllerRef.current.getSnapshot()) : null) ?? localHistoryBusy() ?? artifactBusy() ?? preflightBusy() ?? androidBusy() ?? recoveryBusy() ?? iosBusy() ?? savedCommandPrerequisiteReason(),
  }));
  localStoreReconcileControllerRef.current=localStoreReconcile;
  const localStoreReconcileState=useSyncExternalStore(localStoreReconcile.subscribe,localStoreReconcile.getSnapshot,localStoreReconcile.getSnapshot);
  const requests = useRef(0);
  const bootGeneration = useRef(0);
  const [externalObserver] = useState(() => new ExternalProjectObservationController({
    current: () => {
      const current = workspaceRef.current;
      return { api: pathService.current.api, session: current.selectedId ? current.projects[current.selectedId] ?? null : null,
        versionState: releaseVersionControllerRef.current?.getSnapshot() ?? null };
    },
    otherOperationReason: () => savedOwnersBusy() ?? savedOwnersPrerequisiteReason() ??
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
    externalObserverRef.current?.beforeWorkspaceAction();
    versionEdit.beginConnection();
    metadataImages.beginConnection();
    retirePathPicker();
    pathService.current = { api: null, info: null };
    // Reconnection cannot discard a pending or unverified original picker.
    if (projectPathOwnerReason(pathPickerRef.current)) return;
    artifactInspection.beginConnection();
    offlinePreflight.beginConnection(); localStore.beginConnection(); localStorePrepare.beginConnection(); localStoreExecute.beginConnection(); localStoreReconcile.beginConnection(); localHistory.beginConnection();
    androidBuild.beginConnection();
    projectRecovery.beginConnection(); iosArchive.beginConnection();
    if (savedCommandBusy()) { setBootError(versionOwnerReason(versionEdit.getSnapshot(), workspaceRef.current.selectedId ?? '') ?
      versionEditError({ code: 'VersionEditBusy' }) : artifactBusy() ? artifactInspectionError({code:'artifact_inspection_busy'}) : metadataImagesOwnerReason(metadataImages.getSnapshot()) ? metadataImagesError({ code: 'metadata_images_busy' }) : recoveryBusy() ? projectRecoveryError({ code: 'project_recovery_busy' }) : androidBusy() ? androidBuildError({ code: 'android_build_busy' }) : iosBusy() ? iosArchiveError({ code: 'ios_archive_busy' }) : offlinePreflightError({ code: 'offline_preflight_busy' })); return; }
    bootstrapPending.current = true;
    const generation = ++bootGeneration.current;
    const helpGeneration = {};
    connectionHelpGeneration.current = helpGeneration;
    githubConnection.setHelp(null);
    githubConnection.setContext(null);
    connectionHandoffRef.current = null; connectionPortRef.current = null;
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
      // Fixed read-only Status may expose an unavailable native gate. Working
      // passive appInfo is neither credential admission nor TLS qualification.
      void githubConnection.attach(port);
      void githubRemoteSetup.connect(connection); void githubPublication.connect(connection);
      void githubPreflight.connect(connection);
      void githubRelease.connect(connection);
      void githubHistory.connect(connection);
      const appInfo = await connection.appInfo();
      if (generation !== bootGeneration.current) return;
      pathService.current = { api: connection, info: appInfo };
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
        pathService.current = { api: null, info: null };
        connectionHandoffRef.current = null; connectionPortRef.current = null;
        githubConnection.setHelp(null); githubConnection.setContext(null); void githubConnection.attach(null); void githubRemoteSetup.connect(null); void githubPublication.connect(null); void githubPreflight.connect(null); void githubRelease.connect(null); void githubHistory.connect(null);
        setInfo(null); setCatalog(null); versionEdit.setHelp(null); githubSetup.connectionUnavailable(); environment.connectionUnavailable(); releaseVersion.connectionUnavailable(); releaseInputs.connectionUnavailable(); setBootError(apiError(error));
      }
    } finally {
      passivePending.current -= 1; setPassivePending(passivePending.current);
      if (generation === bootGeneration.current) { bootstrapPending.current = false; setLoading(false); externalObserverRef.current?.syncContext(); }
    }
  }, [githubSetup, githubConnection, githubRemoteSetup, githubPublication, githubPreflight, githubRelease, githubHistory, environment, releaseVersion, releaseInputs, diagnostics, releaseEvidence, artifactInspection, artifactBusy, offlinePreflight, localStore, localStorePrepare, localStoreExecute, localStoreReconcile, localHistory, androidBuild, projectRecovery, iosArchive, androidBusy, recoveryBusy, iosBusy, savedCommandBusy, metadataText, metadataImages, versionEdit, syncConnectionContext, retirePathPicker]);

  // Subscribe before bootstrap. A version read/replacement retires consent
  // synchronously, before React publishes another frame of the review.
  useEffect(() => releaseVersion.subscribe(() => androidBuild.syncReleaseVersion()), [releaseVersion, androidBuild]);
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
    return () => { externalObserverRef.current?.beforeWorkspaceAction(); bootGeneration.current += 1; pathService.current = { api: null, info: null }; retirePathPicker(); connectionHelpGeneration.current = {}; githubConnection.setHelp(null); releaseInputs.connectionUnavailable(); };
  }, [bootstrap]);

  useEffect(() => { if (api) void configEdit.connect(api); }, [api, configEdit]);
  useEffect(() => () => configEdit.dispose(), [configEdit]);
  useEffect(() => () => githubSetup.dispose(), [githubSetup]);
  useEffect(() => () => environment.dispose(), [environment]);
  useEffect(() => () => releaseVersion.dispose(), [releaseVersion]);
  useEffect(() => () => releaseInputs.dispose(), [releaseInputs]);
  useEffect(() => () => diagnostics.dispose(), [diagnostics]);
  useEffect(() => () => artifactInspection.dispose(), [artifactInspection]);
  useEffect(() => () => offlinePreflight.dispose(), [offlinePreflight]);
  useEffect(() => () => localStore.dispose(), [localStore]);
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
      externalObserverRef.current?.beforeWorkspaceAction();
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

  const navigate = (next: Page) => { externalObserver.beforeWorkspaceAction(); initialization.setVisible(next==='dashboard'); configEdit.setRecoveryVisible(next === 'settings' || next === 'metadata'); metadataText.setVisible(next === 'metadata'); metadataImages.setVisible(next === 'metadata'); versionEdit.setVisible(next === 'dashboard'); retirePathPicker(); artifactInspection.setVisible(next === 'artifacts'); offlinePreflight.setVisible(next === 'releases'); localStore.setVisible(next === 'releases'); localStorePrepare.setVisible(next === 'releases'); localStoreExecute.setVisible(next === 'releases'); localStoreReconcile.setVisible(next === 'releases'); localHistory.setVisible(next === 'releases'); androidBuild.setVisible(next === 'releases'); projectRecovery.setVisible(next === 'recovery'); iosArchive.setVisible(next === 'releases'); iosArchive.setRecoveryVisible(next === 'recovery'); diagnostics.setVisible(next === 'environment'); setReleaseCheckFocus(null); setPage(next); main.current?.focus({ preventScroll: true }); };
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
    externalObserverRef.current?.beforeWorkspaceAction();
    githubHistory.beforeWorkspaceAction();
    initialization.snapshotIntent();
    configEdit.snapshotIntent(projectId);
    metadataImages.snapshotIntent(projectId);
    versionEdit.snapshotIntent(projectId);
    metadataText.snapshotIntent(projectId);
    retirePathPicker();
    artifactInspection.snapshotIntent(projectId);
    offlinePreflight.snapshotIntent(projectId); localStore.snapshotIntent(); localStorePrepare.snapshotIntent(); localStoreExecute.snapshotIntent(); localStoreReconcile.snapshotIntent(); localHistory.snapshotIntent();
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
    offlinePreflight.selectionIntent(); localStore.selectionIntent(); localStorePrepare.selectionIntent(); localStoreExecute.selectionIntent(); localStoreReconcile.selectionIntent(); localHistory.selectionIntent();
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
    offlinePreflight.setSelectionPending(true); localStore.setSelectionPending(true); localStorePrepare.setSelectionPending(true); localStoreExecute.setSelectionPending(true); localStoreReconcile.setSelectionPending(true); localHistory.setSelectionPending(true);
    androidBuild.setSelectionPending(true);
    projectRecovery.setSelectionPending(true);
    iosArchive.setSelectionPending(true);
    metadataText.setSelectionPending(true);
    versionEdit.setSelectionPending(true);
    setChoosing(true);
    setChooseError(null);
    try {
      const project = await api.chooseProject();
      if (!project) return;
      const alreadyLoaded = workspaceRef.current.projects[project.id]?.snapshot;
      dispatch({ type: 'select', project });
      if (!alreadyLoaded) await loadSnapshot(project.id);
    } catch (error) { setChooseError(apiError(error)); }
    finally { connectionPicking.current = false; setChoosing(false); syncConnectionContext(); releaseVersion.setSelectionPending(false); releaseInputs.setSelectionPending(false); metadataText.setSelectionPending(false); metadataImages.setSelectionPending(false); versionEdit.setSelectionPending(false); diagnostics.setSelectionPending(false); artifactInspection.setSelectionPending(false); offlinePreflight.setSelectionPending(false); localStore.setSelectionPending(false); localStorePrepare.setSelectionPending(false); localStoreExecute.setSelectionPending(false); localStoreReconcile.setSelectionPending(false); localHistory.setSelectionPending(false); androidBuild.setSelectionPending(false); projectRecovery.setSelectionPending(false); iosArchive.setSelectionPending(false); }
  };

  const changeApplicationRepository = (value: string) => {
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

  const draftRetained = (projectId: string) => initializationRetainsDraft(initialization.getSnapshot(),projectId) || editRetainsDraft(configEdit.getSnapshot(), projectId) || workflowRetainsDraft(workflowEdit.getSnapshot(), projectId) || metadataRetainsDraft(metadataText.getSnapshot(), projectId) || versionRetainsDraft(versionEdit.getSnapshot(), projectId);

  const editor = (metadataOnly = false) => <DraftEditor
    key={`${session?.project.id ?? 'none'}-${metadataOnly ? 'metadata' : 'settings'}`}
    catalog={catalog} session={session} metadataOnly={metadataOnly} preview={preview}
    chooseReason={chooseReason}
    pathPicker={{ reason: projectPathStartReason(), pendingField: pathPicker.eligible?.field ?? null, onBrowse: (field) => void chooseProjectPath(field) }}
    validateReason={loading ? 'Engine capabilities are being loaded.' : validateReason}
    reviewReason={loading ? 'Engine capabilities are being loaded.' : reviewReason}
    suggestReason={loading ? 'Engine capabilities are being loaded.' : suggestReason}
    saveReason={loading ? 'Application capabilities are being loaded.' : savedCommandBusy() ?? diagnosticsOwnerReason(diagnosticsState) ?? (session ? workflowOwnerReason(workflowState, session.project.id) ?? metadataOwnerReason(metadataState, session.project.id) : null) ?? editStartReason(saveState, session)}
    discardReason={session && draftRetained(session.project.id) ? 'Keep this draft until the original native file-edit session has settled. Closing a review is separate from discarding draft data.' : null}
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

  return <div className="app-shell">
    <a className="skip-link" href="#main-content">Skip to workspace</a>
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark"><Icon name="box" size={25} /></span><div>Mobile Release Kit<span>THE KIT FOR A CAREFUL LAUNCH</span></div></div>
      <div className="project-switcher"><label htmlFor="project-switch">CURRENT PROJECT</label><div className="project-switcher-control"><span className="project-switch-icon"><Icon name="folder" size={18} /></span><select id="project-switch" aria-label="Switch project; unsaved configuration, text and version drafts are retained" value={workspace.selectedId ?? ''} onChange={(event) => dispatch({ type: 'switch', projectId: event.target.value })}><option value="" disabled>{choosing ? 'Opening project…' : 'Choose a project'}</option>{Object.values(workspace.projects).map((entry) => <option key={entry.project.id} value={entry.project.id}>{entry.project.name}{isDirty(entry) ? ' • unsaved config' : ''}{metadataProjectDirty(metadataState.entries, entry.project.id) ? ' • unsaved text' : ''}{versionProjectDirty(versionEditState, entry.project.id) ? ' • unsaved version' : ''}</option>)}</select><button type="button" className="icon-button" disabled={chooseDisabled} aria-label={preview ? 'Load example project' : 'Open another project folder'} onClick={() => void chooseProject()}><Icon name="plus" size={16} /></button></div></div>
      <WorkspaceNavigation page={page} onNavigate={navigate} />
      <div className="sidebar-footer"><div className="foundation-label"><span className="local-dot" />{localEditingLabel}</div><p>Thoughtful preparation.<br />No accidental releases.</p><div className="sidebar-version"><span>{`DESKTOP ${info?.appVersion ?? 'Not loaded'}`}</span><Icon name="shield" size={14} /></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumbs"><Icon name="folder" size={16} /><span>{session?.project.name ?? 'Workspace'}</span><Icon name="chevron" size={13} /><strong>{currentNavigation?.label}</strong></div><div className="topbar-status"><span className="no-write-note"><Icon name="lock" size={13} />No automatic publishing</span><Badge tone={preview || artifactInspectionState.nativeBlocked || initializationState.nativeBlocked || metadataImagesState.nativeBlocked || metadataImagesState.integrityFailed || metadataImagesState.generationLost || metadataImagesState.selectionIssue || metadataImagesState.editIssue || saveState.nativeBlocked || workflowState.nativeBlocked || metadataState.edit.nativeBlocked || versionEditState.edit.nativeBlocked || diagnosticsState.nativeBlocked || localHistoryState.blocked || localStoreState.blocked || localStorePrepareState.blocked || localStoreExecuteState.blocked || localStoreReconcileState.blocked || offlinePreflightState.nativeBlocked || androidBuildState.nativeBlocked || projectRecoveryState.nativeBlocked || iosArchiveState.nativeBlocked ? 'warning' : 'neutral'}>{preview ? 'Browser preview' : initializationState.status?.active ? 'Project setup · see status below' : recoveryBusy() ? 'Recovery · see status below' : androidBusy() ? 'Android build · see status below' : iosBusy() ? 'iOS build · see status below' : artifactBusy() ? 'Build files · see status below' : localHistoryBusy() ? 'Release history · see status below' : storeBusy() ? 'Store operation · see status below' : preflightBusy() ? 'Local checks · see status below' : diagnosticsState.status?.active ? 'Build tools · see status below' : saveState.status?.active ? 'Project settings task · see status below' : workflowState.status?.active ? 'GitHub files task · see status below' : metadataImagesOwnerReason(metadataImagesState) ? 'Store images · see status below' : metadataState.edit.status?.active ? 'Store listing task · see status below' : versionEditState.edit.status?.active ? 'Version task · see status below' : localEditingLabel}</Badge></div></header>
      {preview && <div className="preview-banner" role="status"><Icon name="environment" size={19} /><div><strong>BROWSER PREVIEW — EXAMPLE DATA ONLY</strong><span>No native bridge, project files, core validation, credentials, or release operations. Never use this view as evidence.</span></div></div>}
      <main id="main-content" tabIndex={-1} ref={main}>
        {loading && <div className="notice notice-info" role="status"><Icon name="refresh" className="spin" size={19} /><span>Connecting to the app and loading project settings…</span></div>}
        {bootError && <><ErrorNotice error={bootError} title="The native service is unavailable" /><div className="bridge-retry"><button className="button small secondary" disabled={loading || savedCommandBusy() !== null} onClick={() => void bootstrap()}><Icon name="refresh" size={15} />Retry connection</button><span>No browser fallback or mock engine has been enabled.</span></div></>}
        {catalogError && <ErrorNotice error={catalogError} title="The field catalogue could not be loaded" />}
        {chooseError && <ErrorNotice error={chooseError} title="The project could not be selected" />}
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
                onClick={() => { navigate('dashboard'); externalObserver.beforeWorkspaceAction(); void releaseVersion.read(); }}>Read updated version</button>}
              {externalObservation.notice.next === 'refresh-project' && <button type="button" className="button small secondary" disabled={loading || refreshReason !== null}
                onClick={() => { if (session) void loadSnapshot(session.project.id); }}>Check saved files again</button>}
              <button type="button" className="button small secondary" onClick={() => externalObserver.dismissNotice()}>Dismiss</button>
            </div>
          </div>}
        {(pathPicker.pending || pathPicker.unverified || pathPicker.message) && <div className={`notice ${pathPicker.unverified ? 'notice-warning' : 'notice-info'}`} role={pathPicker.unverified ? 'alert' : 'status'}>
          <Icon name="info" /><span>{projectPathOwnerReason(pathPicker) ?? pathPicker.message}{pathPicker.pending ? ' If the original picker is still open, its Cancel button leaves the draft unchanged.' : ''}</span></div>}
        {info?.runtime.state !== 'available' && info && !preview && <div className="notice notice-warning"><Icon name="info" /><div><strong>{info.runtime.state === 'disabled' ? 'The engine is disabled' : 'Bundled engine unavailable'}</strong><p>{info.runtime.reason ?? 'A trusted packaged runtime has not been supplied. The app will not select an ambient Python or a mock engine.'} Folder selection does not establish a project observation.</p></div></div>}
        {page !== 'artifacts' && <ArtifactInspection state={artifactInspectionState} controller={artifactInspection} compact
          projectName={session?.project.name??null} onHelp={setHelp} onShow={()=>navigate('artifacts')}/>}
        <LocalReleaseHistory state={localHistoryState} controller={localHistory} compact={page!=='releases'} onShow={()=>navigate('releases')}/>
        <LocalStorePreflight state={localStoreState} controller={localStore} compact={page!=='releases'} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
        <LocalStorePrepare state={localStorePrepareState} controller={localStorePrepare} compact={page!=='releases'} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
        <LocalStoreExecute state={localStoreExecuteState} controller={localStoreExecute} compact={page!=='releases'} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
        <LocalStoreReconcile state={localStoreReconcileState} controller={localStoreReconcile} compact={page!=='releases'} onCredentials={()=>navigate('credentials')} onShow={()=>navigate('releases')}/>
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
          initializationState={initializationState} versionEditState={versionEditState}
          initializationPanel={<ProjectInitialization controller={initialization} state={initializationState} setup={githubSetup} setupState={githubState}/>}
          versionEditor={<ReleaseVersionEditor state={versionEditState} controller={versionEdit} session={session} onSettings={() => navigate('settings')} onHelp={setHelp} onShowProject={showVersionProject} />}
          releaseVersionState={releaseVersionState} releaseVersionReason={releaseVersion.startReason()} onReadVersion={() => { externalObserver.beforeWorkspaceAction(); artifactInspection.versionIntent(); androidBuild.versionIntent(); iosArchive.versionIntent(); void releaseVersion.read(); }}
          onChoose={() => void chooseProject()} onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} onNavigate={navigate} onHelp={setHelp} />}
        {page === 'settings' && <><PageHeading eyebrow="PROJECT SETTINGS" title="A little clarity before the next release." description="Edit a practical, schema-driven draft. The bundled core provides every field, requirement, and validation rule." />{editor()}</>}
        {page === 'environment' && <Environment info={info} api={api} preview={preview} session={session} state={environmentState} controller={environment}
          diagnosticsState={diagnosticsState} diagnosticsController={diagnostics} onRetry={() => void bootstrap()} onSettings={() => navigate('settings')} onHelp={setHelp} loading={loading} />}
        {page === 'credentials' && <Credentials catalog={catalog} state={assetState} controller={assetSession} project={session} inputState={releaseInputState} inputController={releaseInputs} onSettings={() => navigate('settings')} onHelp={setHelp}
          onOfflineChecks={() => reviewCredentialChecks('offline')} onAndroidSigning={() => reviewCredentialChecks('android-signing')}
          nativeBusyReason={savedCommandBusy() ?? diagnosticsOwnerReason(diagnosticsState)} />}
        {page === 'metadata' && <Metadata catalog={catalog} textEditor={<MetadataTextEditor state={metadataState} controller={metadataText} session={session} onShowProject={showMetadataProject} onHelp={setHelp} />}
          imageEditor={<MetadataImagesEditor state={metadataImagesState} controller={metadataImages} session={session} onShowProject={showMetadataProject} onHelp={setHelp} />}>{editor(true)}</Metadata>}
        {page === 'github' && <GitHub info={info} session={session} state={githubState} controller={githubSetup} loading={loading} onReload={() => void bootstrap()} onNavigate={navigate} credentialHelp={catalog?.credentials ?? null} onHelp={setHelp} nativeReview={workflowPanel(true)}
          connectionView={<><GitHubConnection state={connectionState} controller={githubConnection} onHelp={setHelp} nativeBusyReason={savedCommandBusy()}
            repositoryInput={applicationRepository} onRepository={changeApplicationRepository} projectSelected={session !== null && !choosing}
            handoff={connectionHandoffRef.current} />
            {connectionState.helpState !== 'current' && <div className="button-row"><button type="button" className="button small secondary" disabled={loading} onClick={() => void bootstrap()}>Reload service and connection guidance</button></div>}
            <GitHubPublication state={githubPublicationState} controller={githubPublication} />
            <GitHubRemoteSetup state={githubRemoteSetupState} controller={githubRemoteSetup} assets={assetState} projectId={workspace.selectedId ?? null} onCredentials={() => navigate('credentials')} onHelp={setHelp} />
            <GitHubPreflight state={githubPreflightState} controller={githubPreflight} onHelp={setHelp} />
            <GitHubHistory state={githubHistoryState} controller={githubHistory} onHelp={setHelp} /></>} />}
        {page === 'releases' && <Releases onOpenGitHub={() => navigate('github')} protectedWorkflows={<GitHubRelease state={githubReleaseState} controller={githubRelease} onHelp={setHelp} onGitHub={() => navigate('github')} />} evidence={<ReleaseEvidence state={evidenceState} controller={releaseEvidence} projectName={session?.project.name ?? null} onHelp={setHelp} />} offlineChecks={<div ref={offlineCheckSection} tabIndex={-1} aria-label="Saved offline checks review"><OfflinePreflight state={offlinePreflightState} controller={offlinePreflight}
          projectName={session?.project.name ?? null} operationProjectName={offlinePreflightState.status?.operation ? workspace.projects[offlinePreflightState.status.operation.context.projectId]?.project.name ?? null : null}
          onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason} /></div>}
          androidBuild={<div ref={androidSigningSection} tabIndex={-1} aria-label="Android build and signing review"><AndroidBuild state={androidBuildState} controller={androidBuild}
            projectName={session?.project.name ?? null} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null}
            onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
            onReadVersion={() => { externalObserver.beforeWorkspaceAction(); void releaseVersion.read(); }} versionReason={releaseVersion.startReason()} onHelp={setHelp}
            onCredentials={() => navigate('credentials')} onSettings={() => navigate('settings')} onRecovery={() => navigate('recovery')} /></div>}
          iosArchive={<IOSArchive state={iosArchiveState} controller={iosArchive}
            projectName={session?.project.name ?? null} operationProjectName={iosArchiveState.status?.operation ? workspace.projects[iosArchiveState.status.operation.context.projectId]?.project.name ?? null : null}
            onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
            onReadVersion={() => { externalObserver.beforeWorkspaceAction(); void releaseVersion.read(); }} versionReason={releaseVersion.startReason()} onHelp={setHelp}
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
      blockedReason={draftRetained(discardProject) ? 'An original native file-edit session is still active or unverified. Keep this draft; closing a review is not draft deletion.' : null}
      observationPredatesSave={workspace.projects[discardProject]?.snapshotPredatesSave ?? false}
      onConfirm={() => { if (!draftRetained(discardProject)) dispatch({ type: 'reset', projectId: discardProject }); setDiscardProject(null); }} />}
  </div>;
}
