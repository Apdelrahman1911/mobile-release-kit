// The four request bodies use original UTF-8 Raw IPC, never InvokeBody::Json.
// Replies/events are already deserialized DATA: this renderer cannot recover
// duplicate keys from their original bytes. Native owns that boundary.
import type { ApiError } from './types.ts';
import type { OfflineCheckId, OfflineCoreStatus, OfflineLimitation, OfflinePreflightAvailability, OfflinePreflightContext,
  OfflinePreflightIdentity, OfflinePreflightOperation, OfflinePreflightReason, OfflinePreflightResult, OfflinePreflightStatus,
  PrepareOfflinePreflight, SavedConfigContent, StartOfflinePreflight } from './offlinePreflightTypes.ts';

export const OFFLINE_PREFLIGHT_EVENT = 'offline-preflight-state-changed';
export const OFFLINE_PREFLIGHT_CONSENT = 'saved-offline-android-v1';
export const OFFLINE_PREFLIGHT_COUNTER_MAX = 0xffff_fffe;
export const OFFLINE_PREFLIGHT_CONSENT_MS = 300_000;
export const OFFLINE_CORE_STATUSES: readonly OfflineCoreStatus[] = ['PASS', 'FAIL', 'MISSING', 'BLOCKED', 'INVALID', 'SKIP', 'MANUAL', 'CONFIGURED', 'NOT_APPLICABLE'];
export const OFFLINE_CHECK_IDS: readonly OfflineCheckId[] = ['version-source', 'platform-selection', 'android-module', 'android-gradle-wrapper',
  'android-debug-identity', 'workspace-private-output', 'android-artifact', 'preflight-early-exit', 'configuration-policy', 'metadata-policy',
  'configured-project-check', 'core-lifecycle', 'other-core-finding'];
export const OFFLINE_LIMITATIONS: readonly OfflineLimitation[] = ['saved-inputs-not-atomic', 'project-code-effects-possible', 'not-network-isolated',
  'core-builds-disabled', 'artifact-validation-not-requested', 'toolkit-signing-credentials-store-not-requested', 'release-readiness-not-assessed'];
export type OfflinePreflightCommand = 'prepare_offline_preflight' | 'start_offline_preflight' | 'cancel_offline_preflight' | 'offline_preflight_status';
const encoder = new TextEncoder();
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const oneOf = <T extends string>(value: unknown, options: readonly T[]): value is T => typeof value === 'string' && options.includes(value as T);
export const offlineCounter = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) &&
  !Object.is(value, -0) && value >= 0 && value <= OFFLINE_PREFLIGHT_COUNTER_MAX;
const integer = (value: unknown, max: number): value is number => offlineCounter(value) && value <= max;
const projectId = (value: unknown): value is string => typeof value === 'string' && value.length >= 1 && value.length <= 64 && !/[^A-Za-z0-9_-]/.test(value);
const token = (value: unknown): value is string => typeof value === 'string' && value.length === 32 && /^[0-9a-f]{32}$/.test(value);

// Inspect descriptors before reading values, cloning or serialization. Every
// returned object is our copy, not the supplied object and not its prototype.
// Bounds apply during collection as well as to the final encoded closed DATA.
function copyData(input: unknown, maxBytes: number, maxNodes = 4096): unknown {
  let nodes = 0, bytes = 0;
  const ancestors = new Set<object>();
  const charge = (amount: number) => { bytes += amount; if (bytes > maxBytes) throw new Error(); };
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > maxNodes || depth > 12) throw new Error();
    if (value === null || typeof value === 'boolean') { charge(5); return value; }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error();
      charge(String(value).length); return value;
    }
    if (typeof value === 'string') {
      if (value.length > maxBytes || /[\ud800-\udfff]/u.test(value)) throw new Error();
      charge(encoder.encode(value).byteLength + 2); return value;
    }
    if (typeof value !== 'object' || ancestors.has(value)) throw new Error();
    ancestors.add(value);
    try {
      const prototype: unknown = Object.getPrototypeOf(value);
      if (Array.isArray(value)) {
        const length = Object.getOwnPropertyDescriptor(value, 'length');
        if (prototype !== Array.prototype || !length || !Object.hasOwn(length, 'value') ||
            !integer(length.value, 4096) || length.value > maxNodes - nodes) throw new Error();
        const names = Reflect.ownKeys(value);
        if (names.length !== length.value + 1) throw new Error();
        charge(2 + length.value);
        const output: unknown[] = [];
        for (let i = 0; i < length.value; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
          if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new Error();
          output.push(copy(descriptor.value, depth + 1));
        }
        return output;
      }
      if (prototype !== Object.prototype && prototype !== null) throw new Error();
      const names = Reflect.ownKeys(value);
      if (names.length > maxNodes - nodes) throw new Error();
      charge(2 + 2 * names.length);
      const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      for (const name of names) {
        if (typeof name !== 'string' || name === 'toJSON') throw new Error();
        const descriptor = Object.getOwnPropertyDescriptor(value, name);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new Error();
        copy(name, depth + 1); // Keys consume the same byte/node allowance.
        output[name] = copy(descriptor.value, depth + 1);
      }
      return output;
    } finally { ancestors.delete(value); }
  };
  const value = copy(input, 0);
  if (encoder.encode(JSON.stringify(value)).byteLength > maxBytes) throw new Error();
  return value;
}
function content(value: unknown): value is SavedConfigContent {
  return keys(value, ['bytes', 'sha256']) && integer(value.bytes, 524288) && value.bytes > 0 &&
    typeof value.sha256 === 'string' && value.sha256.length === 64 && /^[0-9a-f]{64}$/.test(value.sha256);
}
export function parseSavedConfigContent(value: unknown): SavedConfigContent | null {
  try { const safe = copyData(value, 256, 16); return content(safe) ? { bytes: safe.bytes, sha256: safe.sha256 } : null; }
  catch { return null; }
}
// This only extracts comparison DATA from the original saved observation. It
// never serializes draft JSON, reads a project path or claims an atomic checkout.
export function savedConfigFromSnapshot(value: unknown): SavedConfigContent | null {
  try {
    if (!record(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
    const config = Object.getOwnPropertyDescriptor(value, 'config');
    if (!config?.enumerable || !Object.hasOwn(config, 'value') || !record(config.value) ||
        ![Object.prototype, null].includes(Object.getPrototypeOf(config.value))) return null;
    const state = Object.getOwnPropertyDescriptor(config.value, 'state');
    const data = Object.getOwnPropertyDescriptor(config.value, 'data');
    const saved = Object.getOwnPropertyDescriptor(config.value, 'content');
    if (!state?.enumerable || !Object.hasOwn(state, 'value') || state.value !== 'format-valid' ||
        !data?.enumerable || !Object.hasOwn(data, 'value') || !record(data.value) ||
        !saved?.enumerable || !Object.hasOwn(saved, 'value')) return null;
    return parseSavedConfigContent(saved.value);
  } catch { return null; }
}
export function sameSavedConfig(a: SavedConfigContent | null, b: SavedConfigContent | null): boolean {
  return a === null || b === null ? a === b : a.bytes === b.bytes && a.sha256 === b.sha256;
}
function prepare(value: unknown): value is PrepareOfflinePreflight {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig']) && projectId(value.projectId) &&
    offlineCounter(value.draftRevision) && offlineCounter(value.baselineGeneration) && content(value.savedConfig);
}
function identity(value: unknown): value is OfflinePreflightIdentity {
  return record(value) && token(value.operationId) && token(value.ownerGeneration);
}
function context(value: unknown): value is OfflinePreflightContext {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'platform', 'operation']) &&
    projectId(value.projectId) && offlineCounter(value.draftRevision) && offlineCounter(value.baselineGeneration) &&
    content(value.savedConfig) && value.platform === 'android' && value.operation === 'offline-preflight';
}
export function copyOfflinePreflightRequest(command: OfflinePreflightCommand, value: unknown): PrepareOfflinePreflight | StartOfflinePreflight | OfflinePreflightIdentity | Record<string, never> | null {
  try {
    const safe = copyData(value, 8192, 64);
    if (command === 'prepare_offline_preflight' && prepare(safe)) return safe;
    if (command === 'start_offline_preflight' && keys(safe, ['operationId', 'ownerGeneration', 'consentVersion']) &&
        identity(safe) && safe.consentVersion === OFFLINE_PREFLIGHT_CONSENT) return safe as unknown as StartOfflinePreflight;
    if (command === 'cancel_offline_preflight' && keys(safe, ['operationId', 'ownerGeneration']) && identity(safe)) return safe;
    if (command === 'offline_preflight_status' && keys(safe, [])) return safe as Record<string, never>;
  } catch { /* Invalid descriptors/data are not executable serialization hooks. */ }
  return null;
}
export function encodeOfflinePreflightRequest(command: OfflinePreflightCommand, value: unknown): Uint8Array | null {
  const copy = copyOfflinePreflightRequest(command, value);
  if (copy === null) return null;
  const bytes = encoder.encode(JSON.stringify(copy));
  return bytes.byteLength >= 1 && bytes.byteLength <= 8192 ? bytes : null;
}
function result(value: unknown): value is OfflinePreflightResult {
  if (!keys(value, ['schemaVersion', 'scope', 'usedConfig', 'findings', 'summary', 'limitations']) || value.schemaVersion !== 1 ||
      value.scope !== 'saved-offline-android-no-core-build' || !content(value.usedConfig)) return false;
  const summary = value.summary, findings = value.findings, limitations = value.limitations;
  if (!keys(summary, ['total', 'shown', 'omitted', 'counts']) || !integer(summary.total, 4096) ||
      !integer(summary.shown, 128) || !integer(summary.omitted, 4096) || summary.shown !== Math.min(summary.total, 128) ||
      summary.omitted !== summary.total - summary.shown || !Array.isArray(findings) || findings.length !== summary.shown ||
      !Array.isArray(limitations) || limitations.length !== OFFLINE_LIMITATIONS.length ||
      !OFFLINE_LIMITATIONS.every((key, index) => limitations[index] === key)) return false;
  const counts = summary.counts;
  if (!keys(counts, OFFLINE_CORE_STATUSES) || !OFFLINE_CORE_STATUSES.every((key) => integer(counts[key], 4096)) ||
      OFFLINE_CORE_STATUSES.reduce((sum, key) => sum + (counts[key] as number), 0) !== summary.total) return false;
  const shown: Record<string, number> = Object.create(null) as Record<string, number>;
  for (let index = 0; index < findings.length; index++) {
    const row: unknown = findings[index];
    if (!keys(row, ['ordinal', 'check', 'status', 'message', 'projectCheckIndex']) || row.ordinal !== index ||
        !oneOf(row.check, OFFLINE_CHECK_IDS) || row.message !== row.check || !oneOf(row.status, OFFLINE_CORE_STATUSES) ||
        !(row.projectCheckIndex === null || row.check === 'configured-project-check' && integer(row.projectCheckIndex, 31))) return false;
    shown[row.status] = (shown[row.status] ?? 0) + 1;
  }
  return OFFLINE_CORE_STATUSES.every((key) => (shown[key] ?? 0) <= (counts[key] as number));
}
export function parseOfflinePreflightResult(value: unknown): OfflinePreflightResult | null {
  try { const safe = copyData(value, 65536); return result(safe) ? safe : null; } catch { return null; }
}
export const offlineAvailabilityText: Record<OfflinePreflightAvailability, string> = {
  available: 'The separate native offline-preflight capability is available. Review and explicit Run are still required.',
  busy: 'An original operation owns the native slot. Finish or cancel that operation and check its status before new work.',
  shutdown: 'The application is stopping its original operations. No new offline check can start.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the original owner; conflicting work and normal exit remain blocked.',
  'document-lost': 'The original native document is no longer available. Reconnecting cannot replace or reset its owner.',
  'unsupported-platform': 'Saved offline checks are unavailable on this host profile. There is no fallback runner.',
  'runtime-unqualified': 'Saved offline checks are disabled for this host, runtime and native document. Passive capability success does not qualify execution.',
};
export const offlineReasonText: Record<OfflinePreflightReason, string> = {
  none: 'No lifecycle failure has been reported. Individual findings retain their own core status.',
  cancelled: 'Cancellation was requested for this original operation. Effects already performed are not undone.',
  'context-changed': 'The reviewed context changed. Its consent is retired and any active original work is being stopped.',
  'document-lost': 'The original document was lost. A replacement view cannot adopt or reset its owner.',
  shutdown: 'Shutdown stopped further owned work; original cleanup must still settle.',
  'timed-out': 'The original operation deadline was reached. No new allowance or retry is implied.',
  'protocol-error': 'The operation did not return a valid, complete protocol result. No report was accepted.',
  'runtime-unavailable': 'The separately qualified bundled runtime is unavailable. No ambient runtime or fallback was selected.',
  'intent-expired': 'The original five-minute review expired. Status refresh does not renew it; a new run needs a new explicit review.',
  'stale-intent': 'This intent is stale or already consumed. It cannot authorize another Start.',
  'saved-config-missing': 'The saved configuration was missing. Save separately and explicitly refresh its observation.',
  'saved-config-invalid': 'The saved configuration was invalid. This is not a passed preflight.',
  'saved-config-changed': 'The saved configuration no longer matched the reviewed bytes. Refresh and review explicitly.',
  'saved-config-sensitive': 'The saved configuration may contain sensitive material. No configuration values were returned.',
  'saved-config-unsafe': 'The saved configuration could not be admitted safely. No path or exception details are exposed.',
  'saved-config-too-large': 'The saved configuration exceeded the admitted size limit.',
  'platform-disabled': 'Android is not enabled by the saved configuration. The draft is not an execution input.',
  'project-admission-refused': 'Project admission was refused. Use the original operation, status or recovery procedure; this screen cannot distinguish or reset that ownership.',
  'input-limit': 'The operation reached its fixed input/work allowance. Incomplete work is not reported as complete.',
  'result-limit': 'The operation could not represent its report within the fixed limits. No partial successful report was invented.',
  'command-incomplete': 'A configured command did not establish complete original ownership and settlement. This is not an ordinary negative finding.',
  'cleanup-unknown': 'Original cleanup is unknown. Later observations cannot reauthorize this slot or relabel it complete.',
};
export const offlineFindingText: Record<OfflineCheckId, string> = {
  'version-source': 'Saved release-version source policy.', 'platform-selection': 'Saved target-platform selection.',
  'android-module': 'Android module configuration.', 'android-gradle-wrapper': 'Android Gradle wrapper policy.',
  'android-debug-identity': 'Android debug/release identity policy.', 'workspace-private-output': 'Private workspace output policy.',
  'android-artifact': 'Android artifact policy; artifact validation was not requested.', 'preflight-early-exit': 'Core early-exit or remaining-check policy.',
  'configuration-policy': 'Saved configuration policy.', 'metadata-policy': 'Project metadata policy.',
  'configured-project-check': 'Configured project check.', 'core-lifecycle': 'Core lifecycle finding.',
  'other-core-finding': 'Other core finding; its exact core status is preserved.',
};
export const offlineLimitationText: Record<OfflineLimitation, string> = {
  'saved-inputs-not-atomic': 'Saved inputs were not an atomic checkout. Script bodies, version sources and metadata may change externally; no filesystem watcher is promised.',
  'project-code-effects-possible': 'Configured project code can modify files, run programs, build things and read your account’s files.',
  'not-network-isolated': 'Offline selects the core checking mode. It is not network isolation or a sandbox.',
  'core-builds-disabled': 'Core-managed builds were disabled; configured checks can still perform their own builds.',
  'artifact-validation-not-requested': 'Artifact validation was not requested by the toolkit.',
  'toolkit-signing-credentials-store-not-requested': 'The toolkit did not request signing, credential loading or Store access. Arbitrary project code is not constrained by that selection.',
  'release-readiness-not-assessed': 'Release readiness was not assessed. A returned report is not a release candidate or publication authority.',
};
export const OFFLINE_PREFLIGHT_DISCLOSURE = 'This runs the selected project’s saved offline preflight, including its configured project checks. Only run a project you trust. Unsaved editor changes are not used. Core-managed builds are disabled; the toolkit does not request signing, artifact validation, credential loading or Store access. Configured checks are project code: they can modify files, run other programs, build things, read your account’s files or contact the network. “Offline” selects the core checking mode; it is not a network-isolation or sandbox guarantee. Cancel stops further owned work and waits for original cleanup; it does not undo effects already performed.';
export function parseOfflinePreflightStatus(value: unknown): OfflinePreflightStatus | null {
  try {
    const safe = copyData(value, 65536);
    if (!keys(safe, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || safe.schemaVersion !== 1 ||
        !offlineCounter(safe.statusRevision) || !oneOf(safe.availability, Object.keys(offlineAvailabilityText))) return null;
    const op = safe.operation;
    if (op === null) return safe as unknown as OfflinePreflightStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result']) ||
        !identity(op) || !context(op.context) || !oneOf(op.phase, ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown']) ||
        typeof op.intentUsable !== 'boolean' || !oneOf(op.reason, Object.keys(offlineReasonText))) return null;
    if (op.phase === 'awaiting-consent') {
      if (op.outcome !== null || op.result !== null || op.reason !== 'none') return null;
    } else if (op.phase === 'unknown') {
      if (op.intentUsable || op.outcome !== 'unknown' || op.result !== null || op.reason !== 'cleanup-unknown') return null;
    } else if (op.phase === 'terminal') {
      if (op.intentUsable || !oneOf(op.outcome, ['complete', 'refused', 'cancelled', 'timed-out', 'failed']) ||
          (op.reason === 'none') !== (op.outcome === 'complete')) return null;
      if (op.outcome === 'complete' ? !result(op.result) || !sameSavedConfig(op.result.usedConfig, op.context.savedConfig) : op.result !== null) return null;
    } else if (op.intentUsable || op.outcome !== null || op.result !== null) return null;
    return safe as unknown as OfflinePreflightStatus;
  } catch { return null; }
}
// Call only on validated, copied DATA; key order has no protocol meaning.
export function sameOfflineData(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>;
  const names = Object.keys(left);
  return names.length === Object.keys(right).length && names.every((name) => Object.hasOwn(right, name) && sameOfflineData(left[name], right[name]));
}
export function sameOfflineIdentity(a: OfflinePreflightIdentity | null, b: OfflinePreflightIdentity | null): boolean {
  return !!a && !!b && a.operationId === b.operationId && a.ownerGeneration === b.ownerGeneration;
}
export function offlineOperationProgress(a: OfflinePreflightOperation, b: OfflinePreflightOperation): boolean {
  if (!sameOfflineIdentity(a, b) || !sameOfflineData(a.context, b.context)) return false;
  if (a.phase === 'unknown') return b.phase === 'unknown';
  if (a.phase === 'terminal') return sameOfflineData(a, b);
  if (!a.intentUsable && b.intentUsable) return false;
  const order = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
  return order.indexOf(b.phase) >= order.indexOf(a.phase);
}
const errors: Record<string, string> = {
  offline_preflight_invalid: 'The offline-check request was not a valid closed DATA request. Nothing was authorized by this response.',
  offline_preflight_unavailable: 'The separate native offline-check capability is unavailable. No browser or ambient-runtime fallback is used.',
  offline_preflight_busy: 'Another original operation owns the native slot. Keep its status and cancellation accessible.',
  offline_preflight_owner: 'The intent identity is foreign, stale or consumed. No Start can be replayed or rearmed.',
  offline_preflight_protocol: 'A usable original offline-check response was not received. Check retained status; do not repeat Start.',
};
export function offlinePreflightError(value: unknown): ApiError {
  let code = 'offline_preflight_protocol';
  try {
    const descriptor = value !== null && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'code') : undefined;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
  } catch { /* No getter, parser error, exception message or raw output is UI text. */ }
  return { code, message: errors[code]!, retryable: false };
}
