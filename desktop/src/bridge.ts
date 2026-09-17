import type { ApiError, AppInfo, BridgeMode, Catalog, ConfigPreview, ConfigSuggestion, DesktopApi, JsonObject, ProjectReference, ProjectSnapshot, SuggestionHints, ValidationResult } from './types.ts';

export type NativeInvoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;

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

export function createNativeApi(mode: Exclude<BridgeMode, 'preview'>, invoke: NativeInvoke): DesktopApi {
  const call = async <T>(command: string, args?: Record<string, unknown>): Promise<T> => {
    if (mode !== 'native') {
      throw { code: 'NativeBridgeRequired', message: 'Open the installed desktop application. Browser preview requires an explicit developer build flag.', retryable: false } satisfies ApiError;
    }
    try { return await invoke<T>(command, args); }
    catch (error) { throw apiError(error); }
  };
  return {
    mode,
    appInfo: () => call<AppInfo>('app_info'),
    chooseProject: () => call<ProjectReference | null>('choose_project'),
    snapshot: (projectId) => call<ProjectSnapshot>('project_snapshot', { projectId }),
    catalog: () => call<Catalog>('catalog'),
    validate: (draft: JsonObject) => call<ValidationResult>('validate_config', { draft }),
    suggestConfig: (hints: SuggestionHints) => call<ConfigSuggestion>('suggest_config', { hints }),
    configPreview: (base: JsonObject | null, draft: JsonObject) => call<ConfigPreview>('preview_config', { base, draft }),
  };
}
