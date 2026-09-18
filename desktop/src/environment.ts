// Passive DATA admission and current-draft display orchestration only. Nothing
// here searches for, selects, installs, executes or grants authority to a tool.
import type { ProjectSession } from './drafts.ts';
import type { ApiError, AppInfo, Assurance, BridgeMode, DesktopApi, HelpContent, JsonObject } from './types.ts';

export type EnvironmentPlatform = 'android' | 'ios';
export type EnvironmentOperation = 'build' | 'artifact-validation';
export interface EnvironmentRequest { draft: JsonObject; platform: EnvironmentPlatform; operation: EnvironmentOperation }
export type EnvironmentRole = 'android-jdk' | 'android-gradle-wrapper' | 'android-sdk' | 'android-bundletool' |
  'apple-macos' | 'apple-xcode' | 'apple-signing-tools' | 'apple-codesign' | 'apple-openssl' | 'apple-security-framework';
export interface EnvironmentBaseline {
  kind: 'exact-pin' | 'workflow-reference' | 'project-defined' | 'platform-defined' | 'none';
  version: string | null; build: string | null; sha256: string | null; maxBytes: number | null;
}
export interface EnvironmentRequirement {
  id: EnvironmentRole; kind: 'external-toolchain' | 'project-file' | 'bundled-helper' | 'native-os';
  presence: 'unknown'; versionState: 'unknown'; inspection: 'not-run'; baseline: EnvironmentBaseline; help: HelpContent;
}
export interface EnvironmentResult {
  schemaVersion: 1; policyVersion: 'environment-requirements-v1'; hostPlatform: 'linux' | 'macos' | 'windows' | 'other';
  context: { platform: EnvironmentPlatform; operation: EnvironmentOperation }; platformEnabled: boolean;
  state: 'requirements-only' | 'platform-disabled'; coverage: 'toolchain-prerequisites-only';
  nativeInspection: 'unavailable'; dependencyCompleteness: 'unknown'; requirements: EnvironmentRequirement[];
  help: { platform: HelpContent; operation: HelpContent }; limitations: string[]; assurance: Assurance;
}

// Closed wire role joins, not a second version/configuration policy. Pin values
// come only from core DATA; this table cannot authorize a native operation.
const roles: Record<EnvironmentPlatform, Record<EnvironmentOperation, readonly EnvironmentRole[]>> = {
  android: { build: ['android-jdk', 'android-gradle-wrapper', 'android-sdk'], 'artifact-validation': ['android-jdk', 'android-bundletool'] },
  ios: { build: ['apple-macos', 'apple-xcode', 'apple-signing-tools'], 'artifact-validation': ['apple-macos', 'apple-codesign', 'apple-openssl', 'apple-security-framework'] },
};
const kinds: Record<EnvironmentRole, EnvironmentRequirement['kind']> = {
  'android-jdk': 'external-toolchain', 'android-gradle-wrapper': 'project-file', 'android-sdk': 'external-toolchain',
  'android-bundletool': 'bundled-helper', 'apple-macos': 'native-os', 'apple-xcode': 'external-toolchain',
  'apple-signing-tools': 'native-os', 'apple-codesign': 'native-os', 'apple-openssl': 'native-os', 'apple-security-framework': 'native-os',
};
const encoder = new TextEncoder();
function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function keys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const names = Reflect.ownKeys(value);
  return names.length === expected.length && names.every((name) => typeof name === 'string' && expected.includes(name) &&
    Object.getOwnPropertyDescriptor(value, name)?.enumerable === true && Object.hasOwn(Object.getOwnPropertyDescriptor(value, name) ?? {}, 'value'));
}
function text(value: unknown, limit: number, empty = false, plain = true): value is string {
  return typeof value === 'string' && (empty || value.trim().length > 0) && value.length <= limit &&
    !/[\ud800-\udfff]/u.test(value) && (!plain || !/[\u0000-\u001f\u007f]/u.test(value)) && encoder.encode(value).byteLength <= limit;
}
// Inspect data descriptors before serialization: no getters, exotic objects,
// sparse arrays or cycles. Count keys and values under the core JSON bounds.
function finiteJson(value: unknown, limit: number): boolean {
  const pending: [unknown, number][] = [[value, 0]];
  let nodes = 0, floor = 0;
  try {
    while (pending.length) {
      const [item, depth] = pending.pop()!;
      if (++nodes > 20_000 || depth > 32) return false;
      if (item === null || typeof item === 'boolean') floor += 1;
      else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; floor += 1; }
      else if (typeof item === 'string') { if (!text(item, limit, true, false)) return false; floor += encoder.encode(item).byteLength + 2; }
      else {
        if (depth >= 32 || typeof item !== 'object' || item === null) return false;
        const names = Reflect.ownKeys(item);
        if (Array.isArray(item)) {
          if (Object.getPrototypeOf(item) !== Array.prototype || names.length !== item.length + 1 || item.length > 20_000 - nodes) return false;
          floor += 2 + item.length;
          for (let index = 0; index < item.length; index += 1) {
            const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
            if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return false;
            pending.push([descriptor.value, depth + 1]);
          }
        } else {
          if (!record(item) || names.length > 20_000 - nodes) return false;
          floor += 2 + 2 * names.length;
          for (const name of names) {
            const descriptor = Object.getOwnPropertyDescriptor(item, name);
            if (typeof name !== 'string' || descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return false;
            pending.push([name, depth + 1], [descriptor.value, depth + 1]);
          }
        }
      }
      if (floor > limit) return false;
    }
    return encoder.encode(JSON.stringify(value)).byteLength <= limit;
  } catch { return false; }
}
export function environmentRequestFits(value: unknown): value is EnvironmentRequest {
  try {
    return finiteJson(value, 1024 * 1024 - 1) && keys(value, ['draft', 'platform', 'operation']) &&
      record(value.draft) && finiteJson(value.draft, 512 * 1024) &&
      (value.platform === 'android' || value.platform === 'ios') && (value.operation === 'build' || value.operation === 'artifact-validation');
  } catch { return false; }
}
function help(value: unknown): value is HelpContent {
  return keys(value, ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure']) &&
    (value.requiredness === 'required' || value.requiredness === 'optional' || value.requiredness === 'conditional') &&
    ['label', 'what', 'why', 'where', 'format', 'failure'].every((field) => text(value[field], 1024)) &&
    text(value.requiredWhen, 1024, value.requiredness !== 'conditional');
}
function baseline(value: unknown, role: EnvironmentRole): boolean {
  if (!keys(value, ['kind', 'version', 'build', 'sha256', 'maxBytes'])) return false;
  const noFile = value.sha256 === null && value.maxBytes === null;
  if (role === 'android-jdk') return value.kind === 'workflow-reference' && text(value.version, 128) && value.build === null && noFile;
  if (role === 'android-bundletool') return value.kind === 'exact-pin' && text(value.version, 128) && value.build === null &&
    typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256) &&
    typeof value.maxBytes === 'number' && Number.isSafeInteger(value.maxBytes) && value.maxBytes > 0;
  if (role === 'apple-xcode') return value.kind === 'exact-pin' && text(value.version, 128) && text(value.build, 128) && noFile;
  return value.kind === (role === 'android-gradle-wrapper' || role === 'android-sdk' ? 'project-defined' : 'platform-defined') &&
    value.version === null && value.build === null && noFile;
}
function assurance(value: unknown): value is Assurance {
  return keys(value, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) &&
    value.basis === 'schema-policy' && value.releaseReadiness === 'unknown' &&
    ['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].every((field) => value[field] === false);
}
export function parseEnvironmentResult(value: unknown, request: Pick<EnvironmentRequest, 'platform' | 'operation'>): EnvironmentResult | null {
  try {
    if (!finiteJson(value, 65536) || !keys(value, ['schemaVersion', 'policyVersion', 'hostPlatform', 'context', 'platformEnabled', 'state',
      'coverage', 'nativeInspection', 'dependencyCompleteness', 'requirements', 'help', 'limitations', 'assurance']) ||
      value.schemaVersion !== 1 || value.policyVersion !== 'environment-requirements-v1' ||
      !['linux', 'macos', 'windows', 'other'].includes(value.hostPlatform as string) ||
      !keys(value.context, ['platform', 'operation']) || value.context.platform !== request.platform || value.context.operation !== request.operation ||
      !(request.platform === 'android' || request.platform === 'ios') || !(request.operation === 'build' || request.operation === 'artifact-validation') ||
      typeof value.platformEnabled !== 'boolean' || value.state !== (value.platformEnabled ? 'requirements-only' : 'platform-disabled') ||
      value.coverage !== 'toolchain-prerequisites-only' || value.nativeInspection !== 'unavailable' || value.dependencyCompleteness !== 'unknown' ||
      !keys(value.help, ['platform', 'operation']) || !help(value.help.platform) || !help(value.help.operation) ||
      !Array.isArray(value.limitations) || value.limitations.length < 1 || value.limitations.length > 8 || !value.limitations.every((item) => text(item, 1024)) ||
      !assurance(value.assurance)) return null;
    const expected = value.platformEnabled ? roles[request.platform][request.operation] : [];
    if (!Array.isArray(value.requirements) || value.requirements.length !== expected.length || !value.requirements.every((row, index) => {
      const role = expected[index];
      return role !== undefined && keys(row, ['id', 'kind', 'presence', 'versionState', 'inspection', 'baseline', 'help']) &&
        row.id === role && row.kind === kinds[role] && row.presence === 'unknown' && row.versionState === 'unknown' &&
        row.inspection === 'not-run' && baseline(row.baseline, role) && help(row.help);
    })) return null;
    return structuredClone(value) as unknown as EnvironmentResult;
  } catch { return null; }
}

const errors: Record<string, string> = {
  environment_request_invalid: 'The environment request is invalid.',
  environment_draft_invalid: 'Review the project configuration before loading environment requirements.',
  environment_unavailable: 'Environment requirements could not be loaded. Check the core connection and try again.',
  protocol_error: 'The core returned an invalid or incomplete response.',
  query_timeout: 'The read-only query exceeded its operation deadline.',
  cleanup_unknown: 'Original query cleanup is unconfirmed. Further queries are disabled; the owner is retained.',
  shutting_down: 'The application is stopping its owned queries.',
};
export function environmentError(error: unknown): ApiError {
  let code = 'environment_unavailable';
  try {
    const descriptor = typeof error === 'object' && error !== null ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
    else if (candidate === 'invalid_request') code = 'environment_request_invalid';
  } catch { /* Never retain exception text, arbitrary getters or request DATA. */ }
  return { code, message: errors[code]!, retryable: false };
}

interface ProjectBinding { projectId: string; draftRevision: number; baselineGeneration: number; hasDraft: boolean }
export interface EnvironmentBinding extends ProjectBinding {
  requestId: number; connectionGeneration: number; selectionGeneration: number; contextGeneration: number;
  platform: EnvironmentPlatform; operation: EnvironmentOperation; mode: BridgeMode;
}
export interface EnvironmentState {
  mode: BridgeMode; reason: string | null; project: ProjectBinding | null;
  platform: EnvironmentPlatform; operation: EnvironmentOperation;
  connectionGeneration: number; selectionGeneration: number; contextGeneration: number;
  pending: EnvironmentBinding | null; result: EnvironmentResult | null; resultBinding: EnvironmentBinding | null;
  stale: boolean; error: ApiError | null;
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export function environmentStartReason(state: EnvironmentState): string | null {
  if (!state.project) return 'Choose a project to see its toolchain requirements.';
  if (!state.project.hasDraft) return 'Prepare a configuration draft in Project settings first.';
  if (state.reason) return state.reason;
  return state.pending ? 'Loading requirements for this exact draft and activity.' : null;
}
export class EnvironmentController {
  private state: EnvironmentState = freeze<EnvironmentState>({ mode: 'unavailable', reason: errors.environment_unavailable!, project: null,
    platform: 'android', operation: 'build', connectionGeneration: 0, selectionGeneration: 0, contextGeneration: 0,
    pending: null, result: null, resultBinding: null, stale: false, error: null });
  private readonly selectedProject: () => ProjectSession | null;
  private api: DesktopApi | null = null;
  private draft: JsonObject | null = null;
  private requestId = 0;
  private disposed = false;
  private listeners = new Set<() => void>();
  constructor(selectedProject: () => ProjectSession | null) { this.selectedProject = selectedProject; }
  getSnapshot = (): EnvironmentState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<EnvironmentState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private invalidate(patch: Partial<EnvironmentState>): void {
    this.update({ ...patch, pending: null, error: null, stale: this.state.result !== null });
  }
  beginConnection(): void {
    this.api = null;
    this.invalidate({ mode: 'unavailable', reason: 'Core capabilities are loading. This requirements request does not start native tool checks.', connectionGeneration: this.state.connectionGeneration + 1 });
  }
  setConnection(api: DesktopApi, info: AppInfo): void {
    if (this.disposed) return;
    this.api = api;
    const available = api.mode === 'preview' || (api.mode === 'native' && info.runtime.state === 'available' &&
      info.capabilities?.methods.some((item) => item.method === 'environment.requirements' && item.available) === true);
    this.invalidate({ mode: api.mode, reason: available ? null : errors.environment_unavailable!, connectionGeneration: this.state.connectionGeneration + 1 });
  }
  connectionUnavailable(): void {
    this.api = null;
    this.invalidate({ mode: 'unavailable', reason: errors.environment_unavailable!, connectionGeneration: this.state.connectionGeneration + 1 });
  }
  // Synchronous App workspace publication calls this before React can render.
  // The monotonic selection generation rejects switch-away-and-back results.
  syncProject(): void {
    if (this.disposed) return;
    const session = this.selectedProject();
    const next = session ? { projectId: session.project.id, draftRevision: session.revision,
      baselineGeneration: session.baselineGeneration, hasDraft: session.draft !== null } : null;
    const old = this.state.project, draft = session?.draft ?? null;
    if (old?.projectId === next?.projectId && old?.draftRevision === next?.draftRevision && old?.baselineGeneration === next?.baselineGeneration &&
      old?.hasDraft === next?.hasDraft && this.draft === draft) return;
    this.draft = draft;
    this.invalidate({ project: next, selectionGeneration: this.state.selectionGeneration + 1 });
  }
  setContext(platform: EnvironmentPlatform, operation: EnvironmentOperation): void {
    if (this.disposed || !(platform === 'android' || platform === 'ios') || !(operation === 'build' || operation === 'artifact-validation') ||
      (platform === this.state.platform && operation === this.state.operation)) return;
    this.invalidate({ platform, operation, contextGeneration: this.state.contextGeneration + 1 });
  }
  private current(binding: EnvironmentBinding): boolean {
    return !this.disposed && this.state.pending === binding && binding.connectionGeneration === this.state.connectionGeneration &&
      binding.selectionGeneration === this.state.selectionGeneration && binding.contextGeneration === this.state.contextGeneration &&
      binding.platform === this.state.platform && binding.operation === this.state.operation && binding.projectId === this.state.project?.projectId &&
      binding.draftRevision === this.state.project?.draftRevision && binding.baselineGeneration === this.state.project?.baselineGeneration;
  }
  async refresh(): Promise<void> {
    this.syncProject();
    if (this.disposed || !this.api || !this.draft || !this.state.project || environmentStartReason(this.state) !== null) return;
    const input = { draft: this.draft, platform: this.state.platform, operation: this.state.operation };
    if (!environmentRequestFits(input)) { this.update({ error: environmentError({ code: 'environment_request_invalid' }) }); return; }
    const request = freeze(structuredClone(input)), api = this.api;
    const binding: EnvironmentBinding = freeze({ ...this.state.project, requestId: ++this.requestId,
      connectionGeneration: this.state.connectionGeneration, selectionGeneration: this.state.selectionGeneration,
      contextGeneration: this.state.contextGeneration, platform: request.platform, operation: request.operation, mode: this.state.mode });
    this.update({ pending: binding, error: null, stale: this.state.result !== null });
    if (!this.current(binding)) return;
    try {
      const raw: unknown = await api.environmentRequirements(request);
      this.syncProject();
      if (!this.current(binding)) return;
      const result = parseEnvironmentResult(raw, request);
      if (!result) throw { code: 'protocol_error' };
      this.update({ pending: null, result: freeze(result), resultBinding: binding, stale: false, error: null });
    } catch (error) {
      this.syncProject();
      if (!this.current(binding)) return;
      const safe = environmentError(error);
      this.update({ pending: null, error: safe, stale: this.state.result !== null,
        reason: ['cleanup_unknown', 'shutting_down'].includes(safe.code) ? safe.message : this.state.reason });
    }
    // No unconditional finally can clear a newer request's pending binding.
  }
  dispose(): void { this.connectionUnavailable(); this.disposed = true; this.listeners.clear(); this.draft = null; }
}
