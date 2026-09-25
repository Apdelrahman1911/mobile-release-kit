import { useCallback, useEffect, useId, useRef, useState, useSyncExternalStore } from 'react';
import { desktopApi } from './api.ts';
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
import { ReleaseVersionEditController, versionOwnerReason, versionProjectDirty, versionRetainsDraft } from './releaseVersionEditController.ts';
import { versionEditError } from './releaseVersionEdit.ts';
import { ReleaseInputGuidanceController } from './releaseInputGuidance.ts';
import { CandidateEvidenceController } from './candidateEvidence.ts';
import { EnvironmentDiagnosticsController, diagnosticsOwnerReason } from './environmentDiagnosticsController.ts';
import { OfflinePreflightController, offlinePreflightOwnerReason } from './offlinePreflight.ts';
import { offlinePreflightError } from './offlinePreflightProtocol.ts';
import { AndroidBuildController, androidBuildOwnerReason } from './androidBuild.ts';
import { androidBuildError } from './androidBuildProtocol.ts';
import { GitHubConnectionController } from './githubConnectionController.ts';
import { connectionRepository } from './githubConnectionProtocol.ts';
import type { GitHubConnectionObservationPort, GitHubConnectionTokenHandoff } from './githubConnectionTypes.ts';
import { workflowOwnerReason, workflowRetainsDraft } from './githubWorkflowEdit.ts';
import { GitHubWorkflowEditController } from './githubWorkflowEditController.ts';
import { AssetSessionController } from './assetSessionController.ts';
import { metadataProjectDirty } from './metadataText.ts';
import { MetadataTextEditController, metadataOwnerReason, metadataRetainsDraft } from './metadataTextEditController.ts';
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
import { MetadataTextEditor, MetadataTextSave } from './components/MetadataTextEditor.tsx';
import { ReleaseVersionEditor, ReleaseVersionSave } from './components/ReleaseVersionEditor.tsx';
import { EnvironmentDiagnostics } from './components/EnvironmentDiagnostics.tsx';
import { OfflinePreflight } from './components/OfflinePreflight.tsx';
import { AndroidBuild, AndroidBuildResultView } from './components/AndroidBuild.tsx';
import { Icon } from './components/Icon.tsx';
import type { IconName } from './components/Icon.tsx';
import { Dashboard } from './pages/Dashboard.tsx';
import { Environment } from './pages/Environment.tsx';
import { Credentials } from './pages/Credentials.tsx';
import { Metadata } from './pages/Metadata.tsx';
import { Recovery, Releases } from './pages/Future.tsx';
import { Artifacts } from './pages/Artifacts.tsx';
import { GitHub } from './pages/GitHub.tsx';

const navigation: { id: Page; label: string; icon: IconName; group: 'workspace' | 'release' }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: 'dashboard', group: 'workspace' },
  { id: 'settings', label: 'Project settings', icon: 'settings', group: 'workspace' },
  { id: 'environment', label: 'Environment', icon: 'environment', group: 'workspace' },
  { id: 'credentials', label: 'Credentials', icon: 'key', group: 'workspace' },
  { id: 'metadata', label: 'Metadata', icon: 'metadata', group: 'workspace' },
  { id: 'github', label: 'GitHub', icon: 'github', group: 'release' },
  { id: 'releases', label: 'Releases', icon: 'rocket', group: 'release' },
  { id: 'artifacts', label: 'Artifacts', icon: 'box', group: 'release' },
  { id: 'recovery', label: 'Recovery', icon: 'recovery', group: 'release' },
];

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
  const offlinePreflightControllerRef = useRef<OfflinePreflightController | null>(null);
  const androidBuildControllerRef = useRef<AndroidBuildController | null>(null);
  const bootstrapPending = useRef(true);
  // Original passive promises outlive retired display request bindings.
  const passivePending = useRef(0);
  const [, setPassivePending] = useState(0);
  const connectionControllerRef = useRef<GitHubConnectionController | null>(null);
  const connectionHelpGeneration = useRef<object>({});
  const workflowControllerRef = useRef<GitHubWorkflowEditController | null>(null);
  const assetControllerRef = useRef<AssetSessionController | null>(null);
  const metadataControllerRef = useRef<MetadataTextEditController | null>(null);
  const [pathPicker, setPathPicker] = useState(initialProjectPathState);
  const pathPickerRef = useRef(pathPicker);
  // Object identity is a service generation, including reconnect-away-and-back.
  const pathService = useRef<{ api: DesktopApi | null; info: AppInfo | null }>({ api: null, info: null });
  const publishPathPicker = useCallback((next: ProjectPathState) => { pathPickerRef.current = next; setPathPicker(next); }, []);
  const retirePathPicker = useCallback(() => {
    const next = retireProjectPath(pathPickerRef.current);
    if (next !== pathPickerRef.current) publishPathPicker(next);
  }, [publishPathPicker]);
  const preflightBusy = useCallback(() => offlinePreflightControllerRef.current ? offlinePreflightOwnerReason(offlinePreflightControllerRef.current.getSnapshot()) : null, []);
  const androidBusy = useCallback(() => androidBuildControllerRef.current ? androidBuildOwnerReason(androidBuildControllerRef.current.getSnapshot()) : null, []);
  // Existing reciprocal admission callbacks also retain the original path
  // picker, even after its display eligibility was retired by a local edit.
  const savedCommandBusy = useCallback((excludeVersion = false) => preflightBusy() ?? androidBusy() ?? projectPathOwnerReason(pathPickerRef.current) ??
    (!excludeVersion && versionEditControllerRef.current ? versionOwnerReason(versionEditControllerRef.current.getSnapshot(), workspaceRef.current.selectedId ?? '') : null), [preflightBusy, androidBusy]);
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
    // Intent/event retirement must precede even an unchanged reducer result:
    // failed refresh and unchanged/older saves need not advance generations.
    retirePathPicker();
    offlinePreflightControllerRef.current?.beforeWorkspaceAction(action);
    androidBuildControllerRef.current?.beforeWorkspaceAction(action);
    releaseVersionControllerRef.current?.beforeWorkspaceAction(action);
    versionEditControllerRef.current?.beforeWorkspaceAction(action);
    releaseInputControllerRef.current?.beforeWorkspaceAction(action);
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
    environmentControllerRef.current?.syncProject();
    releaseVersionControllerRef.current?.syncProject();
    versionEditControllerRef.current?.syncProject();
    releaseInputControllerRef.current?.syncProject();
    diagnosticsControllerRef.current?.syncProject();
    offlinePreflightControllerRef.current?.syncProject();
    androidBuildControllerRef.current?.syncProject();
    metadataControllerRef.current?.syncProject();
    assetControllerRef.current?.syncProject();
    setWorkspace(next);
    githubControllerRef.current?.syncProject();
    workflowControllerRef.current?.syncContext();
    editControllerRef.current?.syncDraft();
    syncConnectionContext();
  }, [syncConnectionContext, retirePathPicker]);
  const [configEdit] = useState(() => new ConfigEditController({
    project: (projectId) => Object.hasOwn(workspaceRef.current.projects, projectId) ? workspaceRef.current.projects[projectId] ?? null : null,
    otherEditReason: (projectId) => savedCommandBusy() ?? (diagnosticsControllerRef.current ? diagnosticsOwnerReason(diagnosticsControllerRef.current.getSnapshot()) : null) ??
      (workflowControllerRef.current ? workflowOwnerReason(workflowControllerRef.current.getSnapshot(), projectId) : null) ??
      (metadataControllerRef.current ? metadataOwnerReason(metadataControllerRef.current.getSnapshot(), projectId) : null),
    onConfirmedSave: (receipt) => dispatch({ type: 'config-save-final', projectId: receipt.binding.projectId, receipt }),
    onRecoveryRequired: (attention) => dispatch({ type: 'config-save-recovery', projectId: attention.projectId, attention }),
  }));
  editControllerRef.current = configEdit;
  const saveState = useSyncExternalStore(configEdit.subscribe, configEdit.getSnapshot, configEdit.getSnapshot);
  const [githubSetup] = useState(() => new GitHubSetupController(() => {
    const current = workspaceRef.current;
    return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
  }, () => workflowControllerRef.current?.syncContext(), savedCommandBusy));
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
  const [metadataText] = useState(() => new MetadataTextEditController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherEditReason: (projectId) => savedCommandBusy() ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ?? configurationOwnerReason(configEdit.getSnapshot(), projectId) ?? workflowOwnerReason(workflowEdit.getSnapshot(), projectId),
    otherOperationReason: savedCommandBusy,
  }));
  metadataControllerRef.current = metadataText;
  const metadataState = useSyncExternalStore(metadataText.subscribe, metadataText.getSnapshot, metadataText.getSnapshot);
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
    otherOperationReason: () => savedCommandPrerequisiteReason(true),
    onSaveBoundary: () => {
      // Retire before the submitted intent/outcome can notify subscribers, even
      // for unchanged, failed or out-of-context saves. Never fabricate a Read.
      releaseVersion.saveIntent(); releaseInputs.saveIntent();
      androidBuildControllerRef.current?.versionIntent(); offlinePreflightControllerRef.current?.versionIntent();
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
  const [candidateEvidence] = useState(() => new CandidateEvidenceController(savedCommandBusy));
  const evidenceState = useSyncExternalStore(candidateEvidence.subscribe, candidateEvidence.getSnapshot, candidateEvidence.getSnapshot);
  const savedCommandPrerequisiteReason = (excludeVersion = false): string | null => {
    const pathOwner = projectPathOwnerReason(pathPickerRef.current); if (pathOwner) return pathOwner;
    if (bootstrapPending.current || connectionPicking.current) return 'Finish the original service or project-selection request before browsing or reviewing saved checks.';
    const projectId = workspaceRef.current.selectedId ?? '';
    const owned = configurationOwnerReason(configEdit.getSnapshot(), projectId) ?? workflowOwnerReason(workflowEdit.getSnapshot(), projectId) ??
      metadataOwnerReason(metadataText.getSnapshot(), projectId) ?? diagnosticsOwnerReason(diagnostics.getSnapshot()) ??
      (excludeVersion ? null : versionOwnerReason(versionEdit.getSnapshot(), projectId));
    if (owned) return owned;
    const assets = assetSession.getSnapshot();
    if (assets.blocked || assets.observationFailed || assets.originPending || assets.busy || assets.updatingContext ||
        assets.status?.operation && (assets.status.operation.phase !== 'idle' || assets.status.operation.settlement !== 'known'))
      return 'An original credential-session operation is active or unverified. Settle or cancel it first.';
    const evidence = candidateEvidence.getSnapshot();
    if (evidence.integrityFailed || evidence.uncertain || evidence.pending || evidence.cancelling ||
        evidence.status && ['choosing', 'observing', 'unknown'].includes(evidence.status.phase))
      return 'An original evidence operation is active or unverified. Evidence selection is not source-project authority.';
    const connection = githubConnection.getSnapshot();
    if (connection.blocked || connection.uncertain || connection.busy || connection.retirementPending || (connection.status ?? connection.retained)?.session)
      return 'Finish or disconnect the original GitHub session before starting saved project code.';
    if (passivePending.current > 0 || Object.values(workspaceRef.current.projects).some((project) => project.snapshotRequest !== null || project.validationRequest || project.reviewRequest || project.suggestionRequest) ||
        environment.getSnapshot().pending || environment.passiveBusyReason() || releaseVersion.getSnapshot().pending || releaseVersion.passiveBusyReason() ||
        releaseInputs.getSnapshot().pending || releaseInputs.passiveBusyReason() || githubSetup.getSnapshot().pending || githubSetup.passiveBusyReason() || metadataText.passiveBusyReason())
      return 'An original passive project query is still pending. Wait for it to settle before reviewing saved checks.';
    return null;
  };
  const [offlinePreflight] = useState(() => new OfflinePreflightController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    otherOperationReason: () => androidBusy() ?? savedCommandPrerequisiteReason(),
  }));
  offlinePreflightControllerRef.current = offlinePreflight;
  const offlinePreflightState = useSyncExternalStore(offlinePreflight.subscribe, offlinePreflight.getSnapshot, offlinePreflight.getSnapshot);
  const [androidBuild] = useState(() => new AndroidBuildController({
    selectedProject: () => {
      const current = workspaceRef.current;
      return current.selectedId && Object.hasOwn(current.projects, current.selectedId) ? current.projects[current.selectedId] ?? null : null;
    },
    releaseVersion: releaseVersion.getSnapshot,
    otherOperationReason: () => preflightBusy() ?? savedCommandPrerequisiteReason(),
  }));
  androidBuildControllerRef.current = androidBuild;
  const androidBuildState = useSyncExternalStore(androidBuild.subscribe, androidBuild.getSnapshot, androidBuild.getSnapshot);
  const requests = useRef(0);
  const bootGeneration = useRef(0);
  const main = useRef<HTMLElement>(null);
  const mode = api?.mode ?? 'unavailable';
  const preview = mode === 'preview';
  const session = workspace.selectedId ? workspace.projects[workspace.selectedId] ?? null : null;
  const currentNavigation = navigation.find((item) => item.id === page) ?? navigation[0];
  const nativeSaveAvailable = mode === 'native' && saveState.status?.capability.available === true &&
    !saveState.observationIssue && !saveState.integrityFailed && !saveState.generationLost && !saveState.nativeBlocked;
  const nativeWorkflowAvailable = mode === 'native' && workflowState.status?.capability.available === true &&
    !workflowState.observationIssue && !workflowState.integrityFailed && !workflowState.generationLost && !workflowState.nativeBlocked;
  const nativeMetadataAvailable = mode === 'native' && metadataState.edit.status?.capability.available === true &&
    !metadataState.edit.observationIssue && !metadataState.edit.integrityFailed && !metadataState.edit.generationLost && !metadataState.edit.nativeBlocked;
  const nativeVersionAvailable = mode === 'native' && versionEditState.edit.status?.capability.available === true &&
    !versionEditState.edit.observationIssue && !versionEditState.edit.integrityFailed && !versionEditState.edit.generationLost && !versionEditState.edit.nativeBlocked;
  const localEditingLabel = nativeWorkflowAvailable || nativeMetadataAvailable || nativeVersionAvailable ? 'Local file editing' : nativeSaveAvailable ? 'Configuration-only editing' : 'Read-only drafting';

  const bootstrap = useCallback(async () => {
    versionEdit.beginConnection();
    retirePathPicker();
    pathService.current = { api: null, info: null };
    // Reconnection cannot discard a pending or unverified original picker.
    if (projectPathOwnerReason(pathPickerRef.current)) return;
    offlinePreflight.beginConnection();
    androidBuild.beginConnection();
    if (savedCommandBusy()) { setBootError(versionOwnerReason(versionEdit.getSnapshot(), workspaceRef.current.selectedId ?? '') ?
      versionEditError({ code: 'VersionEditBusy' }) : androidBusy() ? androidBuildError({ code: 'android_build_busy' }) : offlinePreflightError({ code: 'offline_preflight_busy' })); return; }
    bootstrapPending.current = true;
    const generation = ++bootGeneration.current;
    const helpGeneration = {};
    connectionHelpGeneration.current = helpGeneration;
    githubConnection.setHelp(null);
    githubConnection.setContext(null);
    connectionHandoffRef.current = null; connectionPortRef.current = null;
    void githubConnection.attach(null);
    githubSetup.beginConnection();
    environment.beginConnection();
    releaseVersion.beginConnection();
    releaseInputs.beginConnection();
    diagnostics.beginConnection();
    candidateEvidence.beginConnection();
    metadataText.beginConnection();
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
      void offlinePreflight.connect(connection);
      void androidBuild.connect(connection);
      void diagnostics.connect(connection);
      void candidateEvidence.connect(connection);
      const port: GitHubConnectionObservationPort = {
        mode: connection.mode, subscribe: connection.subscribeGitHubConnection, status: connection.githubConnectionStatus,
        refresh: connection.refreshGitHubConnection, disconnect: connection.disconnectGitHubConnection,
      };
      connectionPortRef.current = port;
      connectionHandoffRef.current = connection.mode === 'native' ? { port, submit: connection.connectGitHubToken } : null;
      // Fixed read-only Status may expose an unavailable native gate. Working
      // passive appInfo is neither credential admission nor TLS qualification.
      void githubConnection.attach(port);
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
        githubConnection.setHelp(null); githubConnection.setContext(null); void githubConnection.attach(null);
        setInfo(null); setCatalog(null); versionEdit.setHelp(null); githubSetup.connectionUnavailable(); environment.connectionUnavailable(); releaseVersion.connectionUnavailable(); releaseInputs.connectionUnavailable(); setBootError(apiError(error));
      }
    } finally {
      passivePending.current -= 1; setPassivePending(passivePending.current);
      if (generation === bootGeneration.current) { bootstrapPending.current = false; setLoading(false); }
    }
  }, [githubSetup, githubConnection, environment, releaseVersion, releaseInputs, diagnostics, candidateEvidence, offlinePreflight, androidBuild, androidBusy, savedCommandBusy, metadataText, versionEdit, syncConnectionContext, retirePathPicker]);

  // Subscribe before bootstrap. A version read/replacement retires consent
  // synchronously, before React publishes another frame of the review.
  useEffect(() => releaseVersion.subscribe(() => androidBuild.syncReleaseVersion()), [releaseVersion, androidBuild]);

  useEffect(() => {
    void bootstrap();
    return () => { bootGeneration.current += 1; pathService.current = { api: null, info: null }; retirePathPicker(); connectionHelpGeneration.current = {}; githubConnection.setHelp(null); releaseInputs.connectionUnavailable(); };
  }, [bootstrap]);

  useEffect(() => { if (api) void configEdit.connect(api); }, [api, configEdit]);
  useEffect(() => () => configEdit.dispose(), [configEdit]);
  useEffect(() => () => githubSetup.dispose(), [githubSetup]);
  useEffect(() => () => environment.dispose(), [environment]);
  useEffect(() => () => releaseVersion.dispose(), [releaseVersion]);
  useEffect(() => () => releaseInputs.dispose(), [releaseInputs]);
  useEffect(() => () => diagnostics.dispose(), [diagnostics]);
  useEffect(() => () => offlinePreflight.dispose(), [offlinePreflight]);
  useEffect(() => () => androidBuild.dispose(), [androidBuild]);
  useEffect(() => () => candidateEvidence.dispose(), [candidateEvidence]);
  useEffect(() => () => githubConnection.dispose(), [githubConnection]);
  useEffect(() => { if (api) void workflowEdit.connect(api); }, [api, workflowEdit]);
  useEffect(() => () => workflowEdit.dispose(), [workflowEdit]);
  useEffect(() => { if (api) void metadataText.connect(api); }, [api, metadataText]);
  useEffect(() => () => metadataText.dispose(), [metadataText]);
  useEffect(() => { if (api) void versionEdit.connect(api); }, [api, versionEdit]);
  useEffect(() => () => versionEdit.dispose(), [versionEdit]);
  useEffect(() => { if (api) void assetSession.connect(api); }, [api, assetSession]);
  useEffect(() => () => assetSession.dispose(), [assetSession]);

  useEffect(() => {
    document.title = `${currentNavigation?.label ?? 'Dashboard'} · Mobile Release Kit${preview ? ' · Browser preview' : ''}`;
  }, [currentNavigation, preview]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => {
      versionEditControllerRef.current?.shutdownIntent();
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

  const navigate = (next: Page) => { versionEdit.setVisible(next === 'dashboard'); retirePathPicker(); offlinePreflight.setVisible(next === 'releases'); androidBuild.setVisible(next === 'releases'); diagnostics.setVisible(next === 'environment'); setPage(next); main.current?.focus({ preventScroll: true }); };
  const refreshReason = savedCommandBusy() ?? methodReason(info, 'project.snapshot', mode);
  const validateReason = savedCommandBusy() ?? methodReason(info, 'config.validate', mode);
  const reviewReason = savedCommandBusy() ?? methodReason(info, 'config.preview', mode);
  const suggestReason = savedCommandBusy() ?? methodReason(info, 'config.suggest', mode);
  // Example loading remains an explicit preview action, never a fallback for
  // missing native project-selection DATA or a failed native picker.
  const chooseReason = loading ? 'Application capabilities are being loaded.' : choosing ? 'Finish the original project selection first.'
    : savedCommandBusy() ?? (preview ? null : projectSelectionReason(info, mode))
      ?? (saveState.status?.capability.reason === 'shutdown' || workflowState.status?.capability.reason === 'shutdown'
        || metadataState.edit.status?.capability.reason === 'shutdown' || versionEditState.edit.status?.capability.reason === 'shutdown' || diagnosticsState.status?.capability.reason === 'shutdown'
        ? 'The application is shutting down.' : null);
  const chooseDisabled = chooseReason !== null;

  const loadSnapshot = async (projectId: string) => {
    versionEdit.snapshotIntent(projectId);
    retirePathPicker();
    offlinePreflight.snapshotIntent(projectId);
    androidBuild.snapshotIntent(projectId);
    if (!api || savedCommandBusy() || (refreshReason !== null && !preview)) return;
    const requestId = ++requests.current;
    passivePending.current += 1; setPassivePending(passivePending.current);
    try {
      dispatch({ type: 'snapshot-start', projectId, requestId });
      const snapshot = await api.snapshot(projectId);
      dispatch({ type: 'snapshot-done', projectId, requestId, snapshot, observedAt: Date.now() });
    } catch (error) {
      dispatch({ type: 'snapshot-failed', projectId, requestId, error: apiError(error) });
    } finally { passivePending.current -= 1; setPassivePending(passivePending.current); }
  };

  const chooseProject = async () => {
    versionEdit.selectionIntent();
    retirePathPicker();
    offlinePreflight.selectionIntent();
    androidBuild.selectionIntent();
    if (!api || savedCommandBusy() || chooseDisabled || connectionPicking.current) return;
    // Admission of the native picker retires the original GitHub context even
    // if selection later cancels/fails. Do not wait for a successful folder.
    connectionPicking.current = true; advanceConnectionContext(); githubConnection.setContext(null);
    releaseVersion.setSelectionPending(true);
    releaseInputs.setSelectionPending(true);
    diagnostics.setSelectionPending(true);
    offlinePreflight.setSelectionPending(true);
    androidBuild.setSelectionPending(true);
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
    finally { connectionPicking.current = false; setChoosing(false); syncConnectionContext(); releaseVersion.setSelectionPending(false); releaseInputs.setSelectionPending(false); metadataText.setSelectionPending(false); versionEdit.setSelectionPending(false); diagnostics.setSelectionPending(false); offlinePreflight.setSelectionPending(false); androidBuild.setSelectionPending(false); }
  };

  const changeApplicationRepository = (value: string) => {
    if (value === applicationRepositoryRef.current) return;
    advanceConnectionContext(); applicationRepositoryRef.current = value;
    // Invalidate synchronously, before React can publish this input edit.
    syncConnectionContext(); setApplicationRepository(value);
  };

  const validate = async () => {
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

  const draftRetained = (projectId: string) => editRetainsDraft(configEdit.getSnapshot(), projectId) || workflowRetainsDraft(workflowEdit.getSnapshot(), projectId) || metadataRetainsDraft(metadataText.getSnapshot(), projectId) || versionRetainsDraft(versionEdit.getSnapshot(), projectId);

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
      <nav aria-label="Workspace navigation">{(['workspace', 'release'] as const).map((group) => <div className="nav-group" key={group}><span className="nav-group-label">{group === 'workspace' ? 'WORKSPACE' : 'DELIVERY'}</span>{navigation.filter((entry) => entry.group === group).map((entry) => <button type="button" key={entry.id} className={`nav-item${entry.id === page ? ' active' : ''}`} aria-label={entry.label} aria-current={entry.id === page ? 'page' : undefined} onClick={() => navigate(entry.id)}><Icon name={entry.icon} size={19} /><span>{entry.label}</span></button>)}</div>)}</nav>
      <div className="sidebar-footer"><div className="foundation-label"><span className="local-dot" />{localEditingLabel}</div><p>Thoughtful preparation.<br />No accidental releases.</p><div className="sidebar-version"><span>DESKTOP {info?.appVersion ?? 'Not loaded'}</span><Icon name="shield" size={14} /></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><div className="breadcrumbs"><Icon name="folder" size={16} /><span>{session?.project.name ?? 'Workspace'}</span><Icon name="chevron" size={13} /><strong>{currentNavigation?.label}</strong></div><div className="topbar-status"><span className="no-write-note"><Icon name="lock" size={13} />Core-managed builds are disabled</span><Badge tone={preview || saveState.nativeBlocked || workflowState.nativeBlocked || metadataState.edit.nativeBlocked || versionEditState.edit.nativeBlocked || diagnosticsState.nativeBlocked || offlinePreflightState.nativeBlocked || androidBuildState.nativeBlocked ? 'warning' : 'neutral'}>{preview ? 'Browser preview' : androidBusy() ? 'Android build owner retained' : preflightBusy() ? 'Saved offline-check owner retained' : diagnosticsState.status?.active ? 'Build-tool diagnostics active' : saveState.status?.active ? 'Native save session active' : workflowState.status?.active ? 'Local workflow session active' : metadataState.edit.status?.active ? 'Public-text session active' : versionEditState.edit.status?.active ? 'Saved-version session active' : localEditingLabel}</Badge></div></header>
      {preview && <div className="preview-banner" role="status"><Icon name="environment" size={19} /><div><strong>BROWSER PREVIEW — EXAMPLE DATA ONLY</strong><span>No native bridge, project files, core validation, credentials, or release operations. Never use this view as evidence.</span></div></div>}
      <main id="main-content" tabIndex={-1} ref={main}>
        {loading && <div className="notice notice-info" role="status"><Icon name="refresh" className="spin" size={19} /><span>Loading desktop capabilities and the core field catalogue…</span></div>}
        {bootError && <><ErrorNotice error={bootError} title="The native service is unavailable" /><div className="bridge-retry"><button className="button small secondary" disabled={loading || savedCommandBusy() !== null} onClick={() => void bootstrap()}><Icon name="refresh" size={15} />Retry connection</button><span>No browser fallback or mock engine has been enabled.</span></div></>}
        {catalogError && <ErrorNotice error={catalogError} title="The field catalogue could not be loaded" />}
        {chooseError && <ErrorNotice error={chooseError} title="The project could not be selected" />}
        {(pathPicker.pending || pathPicker.unverified || pathPicker.message) && <div className={`notice ${pathPicker.unverified ? 'notice-warning' : 'notice-info'}`} role={pathPicker.unverified ? 'alert' : 'status'}>
          <Icon name="info" /><span>{projectPathOwnerReason(pathPicker) ?? pathPicker.message}{pathPicker.pending ? ' If the original picker is still open, its Cancel button leaves the draft unchanged.' : ''}</span></div>}
        {info?.runtime.state !== 'available' && info && !preview && <div className="notice notice-warning"><Icon name="info" /><div><strong>{info.runtime.state === 'disabled' ? 'The engine is disabled' : 'Bundled engine unavailable'}</strong><p>{info.runtime.reason ?? 'A trusted packaged runtime has not been supplied. The app will not select an ambient Python or a mock engine.'} Folder selection does not establish a project observation.</p></div></div>}
        {page !== 'releases' && <OfflinePreflight state={offlinePreflightState} controller={offlinePreflight} compact
          projectName={session?.project.name ?? null} operationProjectName={offlinePreflightState.status?.operation ? workspace.projects[offlinePreflightState.status.operation.context.projectId]?.project.name ?? null : null}
          onShow={() => navigate('releases')} />}
        {page !== 'releases' && <AndroidBuild state={androidBuildState} controller={androidBuild} compact
          projectName={session?.project.name ?? null} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null}
          onShow={() => navigate('releases')} onHelp={setHelp} />}
        {page !== 'environment' && <EnvironmentDiagnostics state={diagnosticsState} controller={diagnostics} compact onShow={() => navigate('environment')} />}
        <ConfigSave state={saveState} projects={workspace.projects} catalog={catalog} selectedId={workspace.selectedId} detailed={page === 'settings' || page === 'metadata'} onReviewVersion={showVersionProject}
          onCheck={() => void configEdit.checkStatus()} onClose={() => configEdit.requestClose()} onApply={(binding) => { const projectId = configEdit.getSnapshot().attempt?.binding.projectId; if (projectId) dispatch({ type: 'config-save-intent', projectId }); releaseInputs.saveIntent(); releaseVersion.saveIntent(); return configEdit.apply(binding); }}
          onShowProject={(projectId) => { dispatch({ type: 'switch', projectId }); navigate('settings'); }} onHelp={setHelp} />
        {page !== 'github' && workflowPanel(false)}
        {page !== 'metadata' && <MetadataTextSave state={metadataState} controller={metadataText} detailed={false} onShowProject={showMetadataProject} onHelp={setHelp} />}
        {page !== 'dashboard' && <ReleaseVersionSave state={versionEditState} controller={versionEdit} onShowProject={showVersionProject} />}
        {page === 'dashboard' && <Dashboard session={session} info={info} preview={preview} configSaveState={saveState} chooseDisabled={chooseDisabled} chooseReason={chooseReason} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
          versionEditor={<ReleaseVersionEditor state={versionEditState} controller={versionEdit} session={session} onSettings={() => navigate('settings')} onHelp={setHelp} onShowProject={showVersionProject} />}
          releaseVersionState={releaseVersionState} releaseVersionReason={releaseVersion.startReason()} onReadVersion={() => { androidBuild.versionIntent(); void releaseVersion.read(); }}
          onChoose={() => void chooseProject()} onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} onNavigate={navigate} onHelp={setHelp} />}
        {page === 'settings' && <><PageHeading eyebrow="PROJECT SETTINGS" title="A little clarity before the next release." description="Edit a practical, schema-driven draft. The bundled core provides every field, requirement, and validation rule." />{editor()}</>}
        {page === 'environment' && <Environment info={info} preview={preview} session={session} state={environmentState} controller={environment}
          diagnosticsState={diagnosticsState} diagnosticsController={diagnostics} onRetry={() => void bootstrap()} onSettings={() => navigate('settings')} onHelp={setHelp} loading={loading} />}
        {page === 'credentials' && <Credentials catalog={catalog} state={assetState} controller={assetSession} project={session} inputState={releaseInputState} inputController={releaseInputs} onSettings={() => navigate('settings')} onHelp={setHelp} nativeBusyReason={savedCommandBusy() ?? diagnosticsOwnerReason(diagnosticsState)} />}
        {page === 'metadata' && <Metadata catalog={catalog} textEditor={<MetadataTextEditor state={metadataState} controller={metadataText} session={session} onShowProject={showMetadataProject} onHelp={setHelp} />}>{editor(true)}</Metadata>}
        {page === 'github' && <GitHub info={info} session={session} state={githubState} controller={githubSetup} loading={loading} onReload={() => void bootstrap()} onNavigate={navigate} credentialHelp={catalog?.credentials ?? null} onHelp={setHelp} nativeReview={workflowPanel(true)}
          connectionView={<><GitHubConnection state={connectionState} controller={githubConnection} onHelp={setHelp} nativeBusyReason={savedCommandBusy()}
            repositoryInput={applicationRepository} onRepository={changeApplicationRepository} projectSelected={session !== null && !choosing}
            handoff={connectionHandoffRef.current} />
            {connectionState.helpState !== 'current' && <div className="button-row"><button type="button" className="button small secondary" disabled={loading} onClick={() => void bootstrap()}>Reload service and connection guidance</button></div>}</>} />}
        {page === 'releases' && <Releases info={info} offlineChecks={<OfflinePreflight state={offlinePreflightState} controller={offlinePreflight}
          projectName={session?.project.name ?? null} operationProjectName={offlinePreflightState.status?.operation ? workspace.projects[offlinePreflightState.status.operation.context.projectId]?.project.name ?? null : null}
          onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason} />}
          androidBuild={<AndroidBuild state={androidBuildState} controller={androidBuild}
            projectName={session?.project.name ?? null} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null}
            onRefresh={() => { if (session) void loadSnapshot(session.project.id); }} refreshReason={loading ? 'Capabilities are loading.' : refreshReason}
            onReadVersion={() => void releaseVersion.read()} versionReason={releaseVersion.startReason()} onHelp={setHelp} />} />}
        {page === 'artifacts' && <><Artifacts state={evidenceState} controller={candidateEvidence} projectName={session?.project.name ?? null} onHelp={setHelp} />
          <AndroidBuildResultView state={androidBuildState} operationProjectName={androidBuildState.status?.operation ? workspace.projects[androidBuildState.status.operation.context.projectId]?.project.name ?? null : null} /></>}
        {page === 'recovery' && <Recovery info={info}
          attention={retainedEditAttention(workspace.projects, saveState.recoveryProjects, workflowState.recoveryProjects, metadataState.edit.recoveryProjects, versionEditState.edit.recoveryProjects)}
          choosingProject={choosing} onOpenProject={showRetainedEditProject} onHelp={setHelp} />}
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
