import type { ApiError, AppInfo, BridgeMode, Catalog, ConfigEditStatus, ConfigPreview, ConfigSuggestion, DesktopApi, JsonObject, ProjectReference, ProjectSnapshot, SuggestionHints, ValidationResult } from './types.ts';
import { githubSetupError, githubSetupRequestFits, githubSetupResultMatches, parseCatalogGitHubSetup, parseGitHubSetupResult } from './githubSetupProtocol.ts';
import { parseCatalogCredentialGuide } from './credentialGuide.ts';
import { assetError, assetRequestFits, parseAssetStatus } from './assetSessionProtocol.ts';
import type { AssetCommand } from './assetSessionProtocol.ts';
import type { AssetStatus } from './assetSessionTypes.ts';

export type NativeInvoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
export type NativeEditListen = (event: 'config-edit-state' | 'asset-session-state', onStatus: (status: unknown) => void) => Promise<() => void>;

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
  return {
    mode,
    appInfo: () => call<AppInfo>('app_info'),
    chooseProject: () => call<ProjectReference | null>('choose_project'),
    snapshot: (projectId) => call<ProjectSnapshot>('project_snapshot', { projectId }),
    catalog: async () => {
      const result = await call<Catalog>('catalog');
      const githubSetup = parseCatalogGitHubSetup(result);
      if (!githubSetup) throw githubSetupError({ code: 'GitHubSetupHelpUnavailable' });
      return { ...result, githubSetup: structuredClone(githubSetup), credentialGuide: parseCatalogCredentialGuide(result) };
    },
    validate: (draft: JsonObject) => call<ValidationResult>('validate_config', { draft }),
    suggestConfig: (hints: SuggestionHints) => call<ConfigSuggestion>('suggest_config', { hints }),
    configPreview: (base: JsonObject | null, draft: JsonObject) => call<ConfigPreview>('preview_config', { base, draft }),
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
