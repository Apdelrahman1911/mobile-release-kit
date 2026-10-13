// The original Android controller owns source selection. These are comparison
// records only: no renderer path, filesystem handle, UID or tool qualification.
import type { ApiError, HelpContent } from './types.ts';
import type { AndroidBuildAvailability } from './androidBuildTypes.ts';
export type AndroidToolSourceRole = 'jdk' | 'sdk' | 'gradle';
export interface AndroidToolSourceIdentity { operationId: number; sourceGeneration: number; role: AndroidToolSourceRole }
export interface AndroidToolSourcesStatus {
  schemaVersion: 1; statusRevision: number; sourceGeneration: number; projectId: string | null;
  availability: AndroidBuildAvailability; phase: 'idle' | 'picking' | 'checking' | 'selected' | 'refused' | 'cancelled' | 'stopping' | 'unknown';
  reason: 'none' | 'not-inspected' | 'cancelled' | 'source-refused' | 'source-changed' | 'timed-out' | 'context-changed' | 'document-lost' | 'shutdown' | 'cleanup-unknown';
  operation: AndroidToolSourceIdentity | null; selections: { role: AndroidToolSourceRole; displayName: string }[];
  inspection: 'not-run'; protectedCopy: 'not-created';
}
export interface AndroidToolSourcesApi {
  // Older/unqualified adapters can omit the entire surface. The controller
  // never enables a picker when any member is unavailable.
  androidToolSourcesStatus?(): Promise<AndroidToolSourcesStatus>;
  chooseAndroidToolSource?(request: { schemaVersion: 1; sourceGeneration: number; projectId: string; role: AndroidToolSourceRole }): Promise<AndroidToolSourcesStatus>;
  cancelAndroidToolSource?(request: { schemaVersion: 1; sourceGeneration: number; operationId: number }): Promise<AndroidToolSourcesStatus>;
  subscribeAndroidToolSources?(onStatus: (status: unknown) => void): Promise<() => void>;
}
export type AndroidToolSourcesCommand = 'android_tool_sources_status' | 'choose_android_tool_source' | 'cancel_android_tool_source';
export const ANDROID_TOOL_SOURCES_EVENT = 'android-tool-sources-state-changed';
const roles = ['jdk', 'sdk', 'gradle'] as const;
const availability = ['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified', 'toolchain-unqualified'];
const phases = ['idle', 'picking', 'checking', 'selected', 'refused', 'cancelled', 'stopping', 'unknown'];
const reasons = ['none', 'not-inspected', 'cancelled', 'source-refused', 'source-changed', 'timed-out', 'context-changed', 'document-lost', 'shutdown', 'cleanup-unknown'];
function record(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || !actual.every((key) => typeof key === 'string' && keys.includes(key))) return null;
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) return null;
  }
  return value as Record<string, unknown>;
}
const count = (v: unknown, positive = false): v is number =>
  typeof v === 'number' && Number.isSafeInteger(v) && v >= (positive ? 1 : 0) && v < 0xffff_ffff;
const role = (v: unknown): v is AndroidToolSourceRole => typeof v === 'string' && (roles as readonly string[]).includes(v);
const project = (v: unknown): v is string => typeof v === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(v);
export function sameAndroidToolSourceIdentity(a: AndroidToolSourceIdentity | null, b: AndroidToolSourceIdentity | null): boolean {
  return a === null || b === null ? a === b : a.operationId === b.operationId && a.sourceGeneration === b.sourceGeneration && a.role === b.role;
}
export function androidToolSourcesActive(status: AndroidToolSourcesStatus | null): boolean {
  return !!status && ['picking', 'checking', 'stopping', 'unknown'].includes(status.phase);
}
export function hasAndroidToolSources(api: AndroidToolSourcesApi): boolean {
  return typeof api.androidToolSourcesStatus === 'function' && typeof api.chooseAndroidToolSource === 'function'
    && typeof api.cancelAndroidToolSource === 'function' && typeof api.subscribeAndroidToolSources === 'function';
}
export function parseAndroidToolSourcesStatus(value: unknown): AndroidToolSourcesStatus | null {
  try {
    const data = record(value, ['schemaVersion', 'statusRevision', 'sourceGeneration', 'projectId', 'availability', 'phase', 'reason',
      'operation', 'selections', 'inspection', 'protectedCopy']);
    if (!data || data.schemaVersion !== 1 || !count(data.statusRevision) || !count(data.sourceGeneration)
        || data.projectId !== null && !project(data.projectId) || !availability.includes(data.availability as string)
        || !phases.includes(data.phase as string) || !reasons.includes(data.reason as string)
        || data.inspection !== 'not-run' || data.protectedCopy !== 'not-created') return null;
    let operation: AndroidToolSourceIdentity | null = null;
    if (data.operation !== null) {
      const op = record(data.operation, ['operationId', 'sourceGeneration', 'role']);
      if (!op || !count(op.operationId, true) || !count(op.sourceGeneration, true) || op.sourceGeneration !== data.sourceGeneration || !role(op.role)) return null;
      operation = { operationId: op.operationId, sourceGeneration: op.sourceGeneration, role: op.role };
    }
    if (data.sourceGeneration === 0 ? operation !== null || data.phase !== 'idle' : operation === null) return null;
    if (!Array.isArray(data.selections) || Object.getPrototypeOf(data.selections) !== Array.prototype || data.selections.length > 3) return null;
    // The array itself must also contain DATA, not holes or getters.
    if (Reflect.ownKeys(data.selections).length !== data.selections.length + 1) return null;
    const selections: AndroidToolSourcesStatus['selections'] = [];
    for (let i = 0; i < data.selections.length; i++) {
      const slot = Object.getOwnPropertyDescriptor(data.selections, String(i));
      if (!slot || !Object.hasOwn(slot, 'value')) return null;
      const selected = record(slot.value, ['role', 'displayName']);
      if (!selected || !role(selected.role) || selections.some((s) => s.role === selected.role)
          || typeof selected.displayName !== 'string' || selected.displayName.length === 0 || new TextEncoder().encode(selected.displayName).length > 128
          || /[\/\\\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(selected.displayName)) return null;
      selections.push({ role: selected.role, displayName: selected.displayName });
    }
    if (selections.length && !project(data.projectId)) return null;
    if (data.phase === 'unknown' && (data.reason !== 'cleanup-unknown' || selections.length !== 0)
        || data.phase === 'selected' && (data.reason !== 'not-inspected' || !operation || !selections.some((s) => s.role === operation.role))
        || data.phase === 'cancelled' && data.reason !== 'cancelled'
        || ['picking', 'checking'].includes(data.phase as string) && data.reason !== 'none') return null;
    return { schemaVersion: 1, statusRevision: data.statusRevision, sourceGeneration: data.sourceGeneration, projectId: data.projectId as string | null,
      availability: data.availability as AndroidBuildAvailability, phase: data.phase as AndroidToolSourcesStatus['phase'],
      reason: data.reason as AndroidToolSourcesStatus['reason'], operation, selections, inspection: 'not-run', protectedCopy: 'not-created' };
  } catch { return null; }
}
export function encodeAndroidToolSourcesRequest(command: AndroidToolSourcesCommand, value: unknown): Uint8Array | null {
  try {
    const keys = command === 'android_tool_sources_status' ? ['schemaVersion'] : command === 'choose_android_tool_source'
      ? ['schemaVersion', 'sourceGeneration', 'projectId', 'role'] : command === 'cancel_android_tool_source'
      ? ['schemaVersion', 'sourceGeneration', 'operationId'] : null;
    if (!keys) return null;
    const data = record(value, keys);
    if (!data || data.schemaVersion !== 1 || command !== 'android_tool_sources_status' && !count(data.sourceGeneration, command === 'cancel_android_tool_source')
        || command === 'choose_android_tool_source' && (!project(data.projectId) || !role(data.role))
        || command === 'cancel_android_tool_source' && !count(data.operationId, true)) return null;
    const raw = new TextEncoder().encode(JSON.stringify(data));
    return raw.length <= 1024 ? raw : null;
  } catch { return null; }
}
export function androidToolSourcesError(_error: unknown): ApiError {
  return { code: 'android_sources_unconfirmed', message: 'The original tool-selection reply is unconfirmed. Check Status; do not repeat the picker or assume it has closed.', retryable: false };
}
export const androidToolSourceHelp: Record<AndroidToolSourceRole, HelpContent> = {
  jdk: { label: 'Java development kit (JDK)', requiredness: 'required', requiredWhen: 'Before registering tools for an Android build.',
    what: 'Java 17 runs Gradle and provides the Java compiler and signing tools.',
    why: 'The app needs one exact JDK installation; the system PATH or another Java version is not a tool selection.',
    where: 'Choose the .jdk bundle in Library → Java → JavaVirtualMachines, or its Contents → Home folder. Android Studio also includes Java; compatibility still needs inspection.',
    format: 'Choose an installed JDK folder using Browse. The original files are not changed, copied or executed by this selection.',
    failure: 'A folder selection is not a compatibility or supplier check. Unsupported or changed contents will be refused during registration.' },
  sdk: { label: 'Android SDK', requiredness: 'required', requiredWhen: 'Before registering tools for an Android build.',
    what: 'The SDK contains the Android platform and build tools needed by the selected project.',
    why: 'Its platform and build-tools versions must match the reviewed build setup.',
    where: 'Find Android SDK Location in Android Studio → Settings → Languages & Frameworks → Android SDK; commonly Library/Android/sdk in your home folder.',
    format: 'Choose the SDK root. Registration will select only the required platform and build-tools versions, not emulator images or unrelated versions.',
    failure: 'Missing or incompatible versions require installing the matching package in Android Studio. The app never accepts vendor licenses for you.' },
  gradle: { label: 'Gradle distribution', requiredness: 'required', requiredWhen: 'Before registering tools for an Android build.',
    what: 'Gradle is the build engine used by the Android project.',
    why: 'A protected, reviewed distribution prevents a changing launcher or unrelated PATH entry from replacing the intended tool.',
    where: 'Select an extracted Gradle distribution from the official Gradle release. Its version must match the project’s reviewed wrapper configuration.',
    format: 'Choose the folder containing bin/gradle and lib. Do not choose a ZIP archive or a project folder.',
    failure: 'Wrong versions or modified supplier files are refused during inspection. Browsing alone does not install or qualify Gradle.' },
};
