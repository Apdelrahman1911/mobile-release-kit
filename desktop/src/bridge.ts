import type { ApiError, AppInfo, BridgeMode, Catalog, ConfigEditStatus, ConfigPreview, ConfigSuggestion, DesktopApi, JsonObject, ProjectReference, ProjectSnapshot, SuggestionHints, ValidationResult } from './types.ts';
import { environmentError, environmentRequestFits, parseEnvironmentResult } from './environment.ts';
import { parseReleaseVersionObservation, releaseVersionError, releaseVersionRequestFits } from './releaseVersion.ts';
import { evidenceError, evidenceRequestFits, parseEvidenceStatus } from './candidateEvidence.ts';
import type { EvidenceCommand, EvidenceStatus } from './candidateEvidence.ts';
import { ENVIRONMENT_DIAGNOSTICS_EVENT, environmentDiagnosticsError, environmentDiagnosticsRequestFits, parseEnvironmentDiagnosticsStatus } from './environmentDiagnosticsProtocol.ts';
import type { EnvironmentDiagnosticsCommand } from './environmentDiagnosticsProtocol.ts';
import type { EnvironmentDiagnosticsStatus } from './environmentDiagnosticsTypes.ts';
import { githubSetupError, githubSetupRequestFits, githubSetupResultMatches, parseCatalogGitHubSetup, parseGitHubSetupResult } from './githubSetupProtocol.ts';
import { parseCatalogCredentialGuide } from './credentialGuide.ts';
import { assetError, assetRequestFits, parseAssetStatus } from './assetSessionProtocol.ts';
import type { AssetCommand } from './assetSessionProtocol.ts';
import type { AssetStatus } from './assetSessionTypes.ts';
import { parseGitHubWorkflowEditStatus, workflowEditError, workflowEditRequestFits } from './githubWorkflowEditProtocol.ts';
import type { GitHubWorkflowEditCommand } from './githubWorkflowEditProtocol.ts';
import type { GitHubWorkflowEditStatus } from './githubWorkflowEditTypes.ts';
import { GITHUB_CONNECTION_ENTRY_AVAILABLE, GITHUB_CONNECTION_EVENT, githubConnectionError, githubConnectionRequestFits,
  parseGitHubConnectionHelp, parseGitHubConnectionStatus } from './githubConnectionProtocol.ts';
import type { GitHubConnectionStatus } from './githubConnectionTypes.ts';
import { metadataTextError, metadataTextRequestFits, parseMetadataTextEditStatus, parseMetadataTextGuide, parseMetadataTextObservation, parseMetadataTextValidation } from './metadataTextProtocol.ts';
import type { MetadataTextCommand } from './metadataTextProtocol.ts';
import { OFFLINE_PREFLIGHT_EVENT, encodeOfflinePreflightRequest, offlinePreflightError, parseOfflinePreflightStatus } from './offlinePreflightProtocol.ts';
import type { OfflinePreflightCommand } from './offlinePreflightProtocol.ts';
import type { OfflinePreflightStatus } from './offlinePreflightTypes.ts';

export type NativeInvoke = <T>(command: string, args?: Record<string, unknown> | Uint8Array) => Promise<T>;
export type NativeEditListen = (event: 'config-edit-state' | 'asset-session-state' | 'github-workflow-edit-status' | 'github-connection-status' | 'metadata-text-edit-status' | 'environment-diagnostics-state-changed' | 'offline-preflight-state-changed', onStatus: (status: unknown) => void) => Promise<() => void>;

function connectionReply(value: unknown): GitHubConnectionStatus {
  const status = parseGitHubConnectionStatus(value);
  if (!status) throw githubConnectionError(null);
  return status;
}
function connectionRejection(error: unknown): never { throw githubConnectionError(error); }

export function bridgeMode(previewFlag: unknown, isNative: boolean): BridgeMode {
  if (previewFlag === '1') return 'preview';
  return isNative ? 'native' : 'unavailable';
}

export function apiError(error: unknown): ApiError {
  if (typeof error === 'object' && error !== null && 'code' in error && 'message' in error &&
      typeof error.code === 'string' && typeof error.message === 'string') {
    return { code: error.code.slice(0, 80), message: error.message.slice(0, 1024), retryable: false };
  }
  // Do not expose arbitrary rejection data, tool output, or project values.
  return { code: 'BridgeUnavailable', message: 'The desktop service did not return a usable response. No operation was confirmed.', retryable: false };
}

export function createNativeApi(mode: Exclude<BridgeMode, 'preview'>, invoke: NativeInvoke, listen?: NativeEditListen): DesktopApi {
  const offlineCall = async (command: OfflinePreflightCommand, value: unknown): Promise<OfflinePreflightStatus> => {
    try {
      if (mode !== 'native') throw { code: 'offline_preflight_unavailable' };
      const body = encodeOfflinePreflightRequest(command, value);
      if (!body) throw { code: 'offline_preflight_invalid' };
      // Uint8Array is Tauri Raw IPC. Never wrap JSON text in an object/string.
      const status = parseOfflinePreflightStatus(await invoke<unknown>(command, body));
      if (!status) throw { code: 'offline_preflight_protocol' };
      return status;
    } catch (error) { throw offlinePreflightError(error); }
  };
  const evidenceCall = async (command: EvidenceCommand, args: Record<string, unknown>): Promise<EvidenceStatus> => {
    try {
      if (mode !== 'native') throw { code: 'artifact_evidence_unavailable' };
      if (!evidenceRequestFits(command, args)) throw { code: 'artifact_evidence_invalid' };
      const result = parseEvidenceStatus(await invoke<unknown>(command, structuredClone(args)));
      if (!result) throw { code: 'artifact_evidence_protocol' };
      return result;
    } catch (error) { throw evidenceError(error); }
  };
  const diagnosticsCall = async (command: EnvironmentDiagnosticsCommand, args: unknown): Promise<EnvironmentDiagnosticsStatus> => {
    try {
      if (mode !== 'native') throw { code: 'environment_diagnostics_unavailable' };
      if (!environmentDiagnosticsRequestFits(command, args)) throw { code: 'environment_diagnostics_invalid' };
      const status = parseEnvironmentDiagnosticsStatus(await invoke<unknown>(command, structuredClone(args) as Record<string, unknown>));
      if (!status) throw { code: 'environment_diagnostics_status_invalid' };
      return status;
    } catch (error) { throw environmentDiagnosticsError(error); }
  };
  const call = async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
    if (mode !== 'native') {
      throw { code: 'NativeBridgeRequired', message: 'Open the installed desktop application. Browser preview requires an explicit developer build flag.', retryable: false } satisfies ApiError;
    }
    try { return await invoke<T>(command, args); }
    catch (error) { throw apiError(error); }
  };
  const assetCall = async (command: AssetCommand, args: Record<string, unknown>): Promise<AssetStatus> => {
    try {
      if (!assetRequestFits(command, args)) throw { code: 'asset_invalid_request' };
      // These bounded copies belong only to this invocation. Neither input nor
      // raw rejection data is kept in UI state, diagnostics or browser storage.
      const result = parseAssetStatus(await call<unknown>(command, structuredClone(args)));
      if (!result) throw { code: 'AssetStatusInvalid' };
      return result;
    } catch (error) { throw assetError(error); }
  };
  const workflowCall = async (command: GitHubWorkflowEditCommand, args: unknown): Promise<GitHubWorkflowEditStatus> => {
    try {
      if (!workflowEditRequestFits(command, args)) throw { code: 'GitHubWorkflowRequestInvalid' };
      const value = await call<unknown>(command, structuredClone(args) as Record<string, unknown>);
      const status = parseGitHubWorkflowEditStatus(value);
      if (!status) throw { code: 'GitHubWorkflowStatusInvalid' };
      return structuredClone(status);
    } catch (error) { throw workflowEditError(error); }
  };
  const metadataCall = async <T>(command: MetadataTextCommand, args: unknown, parse: (value: unknown) => T | null): Promise<T> => {
    try {
      if (!metadataTextRequestFits(command, args)) throw { code: 'MetadataTextRequestInvalid' };
      const request = structuredClone(args) as Record<string, unknown>;
      const result = parse(await call<unknown>(command, request));
      if (!result) throw { code: command.startsWith('metadata_text_edit_') ? 'MetadataTextStatusInvalid' : 'MetadataTextResponseInvalid' };
      if (command === 'metadata_text_observe' || command === 'metadata_text_validate') {
        const passive = result as { platform?: unknown; locale?: unknown };
        if (passive.platform !== request.platform || command === 'metadata_text_observe' && passive.locale !== request.locale) throw { code: 'MetadataTextResponseInvalid' };
      }
      return structuredClone(result);
    } catch (error) { throw metadataTextError(error); }
  };
  const connectionCall = (command: 'github_connection_status' | 'github_connection_connect_token' | 'github_connection_refresh' | 'github_connection_disconnect', args: Record<string, unknown>): Promise<GitHubConnectionStatus> => {
    // Deliberately not async and not the generic call/apiError route. Start one
    // invoke synchronously; its callbacks do not close over the token arguments.
    // The false compiled gate is independent of renderer/native capability DATA.
    if (mode !== 'native') return Promise.reject(githubConnectionError({ code: 'github_connection_refused_runtime_unavailable' }));
    if ((command === 'github_connection_connect_token' || command === 'github_connection_refresh') && !GITHUB_CONNECTION_ENTRY_AVAILABLE)
      return Promise.reject(githubConnectionError({ code: 'github_connection_refused_unqualified' }));
    if (!githubConnectionRequestFits(command, args)) return Promise.reject(githubConnectionError({ code: 'github_connection_refused_invalid_input' }));
    try { return invoke<unknown>(command, args).then(connectionReply, connectionRejection); }
    catch (error) { return Promise.reject(githubConnectionError(error)); }
  };
  return {
    mode,
    appInfo: () => call<AppInfo>('app_info'),
    chooseProject: () => call<ProjectReference | null>('choose_project'),
    chooseEvidenceFolder: () => evidenceCall('artifact_evidence_choose', {}),
    evidenceStatus: () => evidenceCall('artifact_evidence_status', {}),
    observeEvidence: (selectionId) => evidenceCall('artifact_evidence_observe', { selectionId }),
    cancelEvidence: (operationId, selectionId) => evidenceCall('artifact_evidence_cancel', { operationId, selectionId }),
    snapshot: (projectId) => call<ProjectSnapshot>('project_snapshot', { projectId }),
    observeReleaseVersion: async (projectId) => {
      try {
        if (mode !== 'native') throw { code: 'runtime_unavailable' };
        const input = { projectId };
        if (!releaseVersionRequestFits(input)) throw { code: 'release_version_invalid_params' };
        // One fixed registered-ID route, not the generic reflective apiError
        // adapter. No supplied path, draft, key or platform crosses this seam.
        const request = structuredClone(input);
        const result = parseReleaseVersionObservation(await invoke<unknown>('release_version_observe', request));
        if (!result) throw { code: 'protocol_error' };
        return result;
      } catch (error) { throw releaseVersionError(error); }
    },
    catalog: async () => {
      const result = await call<Catalog>('catalog');
      const githubSetup = parseCatalogGitHubSetup(result);
      if (!githubSetup) throw githubSetupError({ code: 'GitHubSetupHelpUnavailable' });
      return { ...result, githubSetup: structuredClone(githubSetup), credentialGuide: parseCatalogCredentialGuide(result),
        githubConnection: parseGitHubConnectionHelp(result.githubConnection), metadataText: parseMetadataTextGuide(result.metadataText) };
    },
    validate: (draft: JsonObject) => call<ValidationResult>('validate_config', { draft }),
    suggestConfig: (hints: SuggestionHints) => call<ConfigSuggestion>('suggest_config', { hints }),
    configPreview: (base: JsonObject | null, draft: JsonObject) => call<ConfigPreview>('preview_config', { base, draft }),
    environmentRequirements: async (input) => {
      try {
        if (mode !== 'native') throw { code: 'environment_unavailable' };
        if (!environmentRequestFits(input)) throw { code: 'environment_request_invalid' };
        const request = structuredClone(input);
        const value = await invoke<unknown>('environment_requirements', structuredClone({ draft: request.draft, platform: request.platform, operation: request.operation }));
        const result = parseEnvironmentResult(value, request);
        if (!result) throw { code: 'protocol_error' };
        return result;
      } catch (error) { throw environmentError(error); }
    },
    prepareOfflinePreflight: (request) => offlineCall('prepare_offline_preflight', request),
    startOfflinePreflight: (request) => offlineCall('start_offline_preflight', request),
    offlinePreflightStatus: () => offlineCall('offline_preflight_status', {}),
    cancelOfflinePreflight: (operationId, ownerGeneration) => offlineCall('cancel_offline_preflight', { operationId, ownerGeneration }),
    subscribeOfflinePreflight: async (onStatus) => {
      try {
        if (mode !== 'native' || !listen) throw { code: 'offline_preflight_unavailable' };
        return await listen(OFFLINE_PREFLIGHT_EVENT, (value) => onStatus(parseOfflinePreflightStatus(value)));
      } catch (error) { throw offlinePreflightError(error); }
    },
    startEnvironmentDiagnostics: (request) => diagnosticsCall('start_environment_diagnostics', request),
    cancelEnvironmentDiagnostics: (runId, ownerGeneration) => diagnosticsCall('cancel_environment_diagnostics', { runId, ownerGeneration }),
    environmentDiagnosticsStatus: () => diagnosticsCall('environment_diagnostics_status', {}),
    subscribeEnvironmentDiagnostics: async (onStatus) => {
      try {
        if (mode !== 'native' || !listen) throw { code: 'environment_diagnostics_unavailable' };
        return await listen(ENVIRONMENT_DIAGNOSTICS_EVENT, (value) => onStatus(parseEnvironmentDiagnosticsStatus(value)));
      } catch (error) { throw environmentDiagnosticsError(error); }
    },
    proposeGitHubSetup: async (input) => {
      try {
        if (!githubSetupRequestFits(input)) throw { code: 'invalid_request' };
        // Closed arguments, no project path/identity, values, tokens or flags.
        // Copy before await so a retained test double/caller cannot rebind it.
        const request = structuredClone(input);
        const value = await call<unknown>('propose_github_setup', {
          draft: structuredClone(request.draft), toolingRepository: request.toolingRepository,
          toolingSha: request.toolingSha, suppliedSnapshot: structuredClone(request.suppliedSnapshot),
        });
        const result = parseGitHubSetupResult(value);
        if (!result || !githubSetupResultMatches(result, request)) throw { code: 'GitHubSetupResponseInvalid' };
        return structuredClone(result);
      } catch (error) { throw githubSetupError(error); }
    },
    openConfigEdit: (projectId) => call<ConfigEditStatus>('open_config_edit', { projectId }),
    prepareConfigEdit: ({ sessionId, revision, expectedBase, draft, draftRevision, baselineGeneration }) =>
      call<ConfigEditStatus>('prepare_config_edit', { sessionId, revision, expectedBase, draft, draftRevision, baselineGeneration }),
    applyConfigEdit: (sessionId, planToken) => call<ConfigEditStatus>('apply_config_edit', { sessionId, planToken }),
    closeConfigEdit: (sessionId) => call<ConfigEditStatus>('close_config_edit', { sessionId }),
    configEditStatus: () => call<ConfigEditStatus>('config_edit_status', {}),
    subscribeConfigEdit: async (onStatus) => {
      if (mode !== 'native' || !listen) throw { code: 'NativeBridgeRequired', message: 'Native edit status events are unavailable. Saving is disabled.', retryable: false } satisfies ApiError;
      try { return await listen('config-edit-state', onStatus); }
      catch (error) { throw apiError(error); }
    },
    openGitHubWorkflowEdit: (projectId) => workflowCall('github_workflow_edit_open', { projectId }),
    prepareGitHubWorkflowEdit: (request) => workflowCall('github_workflow_edit_prepare', request),
    applyGitHubWorkflowEdit: (sessionId, planToken) => workflowCall('github_workflow_edit_apply', { sessionId, planToken }),
    closeGitHubWorkflowEdit: (sessionId) => workflowCall('github_workflow_edit_close', { sessionId }),
    githubWorkflowEditStatus: () => workflowCall('github_workflow_edit_status', {}),
    subscribeGitHubWorkflowEdit: async (onStatus) => {
      try {
        if (mode !== 'native' || !listen) throw { code: 'NativeBridgeRequired' };
        return await listen('github-workflow-edit-status', onStatus);
      } catch (error) { throw workflowEditError(error); }
    },
    observeMetadataText: (request) => metadataCall('metadata_text_observe', request, parseMetadataTextObservation),
    validateMetadataText: (request) => metadataCall('metadata_text_validate', request, parseMetadataTextValidation),
    openMetadataTextEdit: (request) => metadataCall('metadata_text_edit_open', request, parseMetadataTextEditStatus),
    prepareMetadataTextEdit: (request) => metadataCall('metadata_text_edit_prepare', request, parseMetadataTextEditStatus),
    applyMetadataTextEdit: (sessionId, planToken) => metadataCall('metadata_text_edit_apply', { sessionId, planToken }, parseMetadataTextEditStatus),
    closeMetadataTextEdit: (sessionId) => metadataCall('metadata_text_edit_close', { sessionId }, parseMetadataTextEditStatus),
    metadataTextEditStatus: () => metadataCall('metadata_text_edit_status', {}, parseMetadataTextEditStatus),
    subscribeMetadataTextEdit: async (onStatus) => {
      try {
        if (mode !== 'native' || !listen) throw { code: 'MetadataTextUnavailable' };
        return await listen('metadata-text-edit-status', onStatus);
      } catch (error) { throw metadataTextError(error); }
    },
    githubConnectionStatus: () => connectionCall('github_connection_status', {}),
    connectGitHubToken: (args) => connectionCall('github_connection_connect_token', args),
    refreshGitHubConnection: (args) => connectionCall('github_connection_refresh', args),
    disconnectGitHubConnection: (args) => connectionCall('github_connection_disconnect', args),
    subscribeGitHubConnection: (onStatus) => {
      if (mode !== 'native' || !listen) return Promise.reject(githubConnectionError({ code: 'github_connection_refused_runtime_unavailable' }));
      try { return listen(GITHUB_CONNECTION_EVENT, (value) => onStatus(parseGitHubConnectionStatus(value))).catch(connectionRejection); }
      catch (error) { return Promise.reject(githubConnectionError(error)); }
    },
    assetStatus: () => assetCall('vault_status', {}),
    openAssetSession: () => assetCall('vault_open', { mode: 'session' }),
    setAssetContext: (request) => assetCall('asset_context', { ...request }),
    chooseAsset: (request) => assetCall('asset_choose', { ...request }),
    prepareCredential: (request) => assetCall('credential_prepare', { ...request }),
    prepareAssetDelete: (record) => assetCall('vault_prepare_delete', { ...record }),
    commitAsset: (previewToken) => assetCall('vault_commit', { previewToken }),
    bindAsset: (previewToken) => assetCall('vault_bind', { previewToken }),
    discardAsset: (operationId) => assetCall('vault_discard', { operationId }),
    lockAssetSession: () => assetCall('vault_lock', { discardSession: true }),
    subscribeAssets: async (onStatus) => {
      try {
        if (mode !== 'native' || !listen) throw { code: 'AssetSessionUnavailable' };
        return await listen('asset-session-state', onStatus);
      } catch (error) { throw assetError(error); }
    },
  };
}
