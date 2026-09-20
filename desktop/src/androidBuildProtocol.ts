// Renderer-consumed closed DATA only. The four requests are original UTF-8 Raw
// IPC, never InvokeBody::Json. Native owns duplicate-aware raw decoding, core
// frame ordering/byte accounting, tool custody and original final joins. These
// copies cannot recover duplicate keys from already-deserialized replies, turn
// a core terminal into native Status, or authorize Start from an observation.
import type { ApiError } from './types.ts';
import type { AndroidBuildAbi, AndroidBuildActivity, AndroidBuildArtifact, AndroidBuildAssurances, AndroidBuildAvailability,
  AndroidBuildCheckId, AndroidBuildCommandObservation, AndroidBuildContext, AndroidBuildCoreStatus, AndroidBuildDisposition,
  AndroidBuildFinding, AndroidBuildIdentity, AndroidBuildInspection, AndroidBuildLimitation, AndroidBuildOperation,
  AndroidBuildOutcome, AndroidBuildPhase, AndroidBuildReason, AndroidBuildResult, AndroidBuildSavedConfig,
  AndroidBuildSavedPair, AndroidBuildSavedVersion, AndroidBuildSelection, AndroidBuildStage, AndroidBuildStatus,
  PrepareAndroidBuild, StartAndroidBuild } from './androidBuildTypes.ts';

export const ANDROID_BUILD_EVENT = 'android-build-state-changed';
export const ANDROID_BUILD_CONSENT = 'saved-android-build-inspect-v1';
export const ANDROID_BUILD_SCOPE = 'local-post-build-artifact-observation';
export const ANDROID_BUILD_TOOLCHAIN_PROFILE = 'android-local-linux-gnu-x86_64-v1';
export const ANDROID_BUILD_COUNTER_MAX = 0xffff_fffe;
export const ANDROID_BUILD_IPC_LIMIT = 8192;
export const ANDROID_BUILD_STATUS_LIMIT = 65536;
export const ANDROID_BUILD_CONSENT_MS = 300_000;
export const ANDROID_BUILD_MAX_FINDINGS = 128;
export const ANDROID_BUILD_MAX_AAB_BYTES = 1024 * 1024 * 1024;
export const ANDROID_BUILD_CORE_STATUSES: readonly AndroidBuildCoreStatus[] = Object.freeze([
  'PASS', 'FAIL', 'MISSING', 'BLOCKED', 'INVALID', 'SKIP', 'MANUAL', 'CONFIGURED', 'NOT_APPLICABLE',
]);
export const ANDROID_BUILD_CHECK_IDS: readonly AndroidBuildCheckId[] = Object.freeze([
  'aab-structure', 'aab-manifest', 'application-id', 'build-number', 'version-name', 'release-flags', 'signer', 'core-lifecycle', 'other-core-finding',
]);
export const ANDROID_BUILD_STAGES: readonly AndroidBuildStage[] = Object.freeze([
  'accepted', 'inputs-bound', 'building', 'capturing', 'inspecting', 'disposing-work',
]);
export const ANDROID_BUILD_ABIS: readonly AndroidBuildAbi[] = Object.freeze(['arm64-v8a', 'armeabi', 'armeabi-v7a', 'mips', 'mips64', 'x86', 'x86_64']);
export const ANDROID_BUILD_LIMITATIONS: readonly AndroidBuildLimitation[] = Object.freeze([
  'saved-inputs-not-atomic', 'project-code-effects-possible', 'not-network-isolated',
  'post-run-bytes-may-be-incremental-reused-or-stale', 'source-binding-not-established', 'artifact-signer-not-inspected',
  'toolkit-signing-not-requested', 'store-operation-not-requested', 'release-readiness-not-assessed',
  'local-output-observation-not-current-file-authority', 'core-terminal-requires-original-native-finality',
]);
export const ANDROID_BUILD_SIGNER_MESSAGE = 'Toolkit signing was not requested; artifact signer was not inspected. Project code may have signed this file.';
const phases: readonly AndroidBuildPhase[] = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
const outcomes: readonly AndroidBuildOutcome[] = ['complete', 'refused', 'failed', 'cancelled', 'timed-out', 'unknown'];
const failures: readonly AndroidBuildCoreStatus[] = ['FAIL', 'MISSING', 'BLOCKED', 'INVALID'];
const manifestChecks: readonly AndroidBuildCheckId[] = ['aab-manifest', 'application-id', 'build-number', 'version-name', 'release-flags'];
const artifactReasons: readonly AndroidBuildReason[] = ['artifact-missing', 'artifact-ambiguous', 'artifact-unsafe', 'artifact-changed'];
export type AndroidBuildCommand = 'prepare_android_build' | 'start_android_build' | 'cancel_android_build' | 'android_build_status';
const encoder = new TextEncoder();
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const oneOf = <T extends string>(value: unknown, options: readonly T[]): value is T => typeof value === 'string' && options.includes(value as T);
const integer = (value: unknown, maximum: number, minimum = 0): value is number => typeof value === 'number' &&
  Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum && value <= maximum;
export const androidBuildCounter = (value: unknown): value is number => integer(value, ANDROID_BUILD_COUNTER_MAX);
const projectId = (value: unknown): value is string => typeof value === 'string' && value.length >= 1 && value.length <= 64 && !/[^A-Za-z0-9_-]/.test(value);
const token = (value: unknown): value is string => typeof value === 'string' && value.length === 32 && !/[^0-9a-f]/.test(value);
const sha = (value: unknown): value is string => typeof value === 'string' && value.length === 64 && !/[^0-9a-f]/.test(value);

// Inspect descriptors before reading, cloning or serializing values. Bounds
// apply during collection and to the final encoded closed copy, not just after
// allocation. Getters/toJSON, sparse arrays and inherited data are not input.
function copyData(input: unknown, maxBytes: number, maxNodes = 8192): unknown {
  let nodes = 0, bytes = 0;
  const ancestors = new Set<object>();
  const charge = (amount: number) => { bytes += amount; if (bytes > maxBytes) throw new Error(); };
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > maxNodes || depth > 16) throw new Error();
    if (value === null || typeof value === 'boolean') { charge(5); return value; }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error();
      charge(String(value).length); return value;
    }
    if (typeof value === 'string') {
      if (value.length > 4096 || /[\ud800-\udfff]/u.test(value)) throw new Error();
      const length = encoder.encode(value).byteLength;
      if (length > 4096) throw new Error();
      charge(length + 2); return value;
    }
    if (typeof value !== 'object' || ancestors.has(value)) throw new Error();
    ancestors.add(value);
    try {
      const prototype: unknown = Object.getPrototypeOf(value);
      if (Array.isArray(value)) {
        const length = Object.getOwnPropertyDescriptor(value, 'length');
        if (prototype !== Array.prototype || !length || !Object.hasOwn(length, 'value') ||
            !integer(length.value, maxNodes) || length.value > maxNodes - nodes) throw new Error();
        if (Reflect.ownKeys(value).length !== length.value + 1) throw new Error();
        charge(2 + length.value);
        const output: unknown[] = [];
        for (let index = 0; index < length.value; index++) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
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
        copy(name, depth + 1);
        output[name] = copy(descriptor.value, depth + 1);
      }
      return output;
    } finally { ancestors.delete(value); }
  };
  const value = copy(input, 0);
  if (encoder.encode(JSON.stringify(value)).byteLength > maxBytes) throw new Error();
  return value;
}
function content(value: unknown, maximum = 524288): value is AndroidBuildSavedConfig {
  return keys(value, ['bytes', 'sha256']) && integer(value.bytes, maximum, 1) && sha(value.sha256);
}
function relativeDisplayPath(value: unknown): value is string {
  // Match the native release-version bounded TRANSPORT/DISPLAY seam. Do not
  // normalize or casefold binding text, invent a Unicode policy, select a read,
  // or claim full Python _source_path admission. Core independently owns NFC,
  // full-casefold private-tree policy, saved selection and original file custody.
  if (typeof value !== 'string' || value.length === 0 || value.length > 512 ||
      /[\ud800-\udfff]/u.test(value) || encoder.encode(value).byteLength > 512) return false;
  const parts = value.split('/');
  return parts.length <= 12 && parts.every((part) => {
    if (part.length === 0 || encoder.encode(part).byteLength > 255 || part.startsWith('.') || /[. ]$/.test(part) ||
        /[\u0000-\u001f\u007f\\:<>"|?*]/u.test(part)) return false;
    const lower = part.toLowerCase();
    return !['private', 'secrets', 'credentials', 'review', 'testflight', 'build', 'deriveddata', 'pods', 'node_modules',
      'venv', 'dist', 'target', '__pycache__'].includes(lower) && !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/.test(lower);
  });
}
function savedVersion(value: unknown): value is AndroidBuildSavedVersion {
  return keys(value, ['source', 'bytes', 'sha256', 'name', 'build']) && relativeDisplayPath(value.source) &&
    content({ bytes: value.bytes, sha256: value.sha256 }, 65536) && typeof value.name === 'string' &&
    value.name.length >= 1 && value.name.length <= 64 && !/[^0-9A-Za-z.+-]/.test(value.name) && integer(value.build, 2_100_000_000, 1);
}
export function parseAndroidBuildSavedConfig(value: unknown): AndroidBuildSavedConfig | null {
  try { const safe = copyData(value, 256, 16); return content(safe) ? safe : null; } catch { return null; }
}
export function parseAndroidBuildSavedVersion(value: unknown): AndroidBuildSavedVersion | null {
  try { const safe = copyData(value, ANDROID_BUILD_IPC_LIMIT, 32); return savedVersion(safe) ? safe : null; } catch { return null; }
}
function prepare(value: unknown): value is PrepareAndroidBuild {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion']) && projectId(value.projectId) &&
    androidBuildCounter(value.draftRevision) && androidBuildCounter(value.baselineGeneration) && content(value.savedConfig) && savedVersion(value.savedVersion);
}
function identity(value: unknown): value is AndroidBuildIdentity {
  return record(value) && token(value.operationId) && token(value.ownerGeneration);
}
function context(value: unknown): value is AndroidBuildContext {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'platform', 'operation']) &&
    value.platform === 'android' && value.operation === 'android-build-inspect' && prepare({ projectId: value.projectId,
      draftRevision: value.draftRevision, baselineGeneration: value.baselineGeneration, savedConfig: value.savedConfig, savedVersion: value.savedVersion });
}
export function copyAndroidBuildRequest(command: AndroidBuildCommand, value: unknown): PrepareAndroidBuild | StartAndroidBuild | AndroidBuildIdentity | Record<string, never> | null {
  try {
    const safe = copyData(value, ANDROID_BUILD_IPC_LIMIT, 64);
    if (command === 'prepare_android_build' && prepare(safe)) return safe;
    if (command === 'start_android_build' && keys(safe, ['operationId', 'ownerGeneration', 'consentVersion']) &&
        identity(safe) && safe.consentVersion === ANDROID_BUILD_CONSENT) return safe as unknown as StartAndroidBuild;
    if (command === 'cancel_android_build' && keys(safe, ['operationId', 'ownerGeneration']) && identity(safe)) return safe;
    if (command === 'android_build_status' && keys(safe, [])) return safe as Record<string, never>;
  } catch { /* No rejected data or exception text is reflected. */ }
  return null;
}
export function encodeAndroidBuildRequest(command: AndroidBuildCommand, value: unknown): Uint8Array | null {
  const safe = copyAndroidBuildRequest(command, value);
  if (safe === null) return null;
  const bytes = encoder.encode(JSON.stringify(safe));
  return bytes.byteLength >= 1 && bytes.byteLength <= ANDROID_BUILD_IPC_LIMIT ? bytes : null;
}
function selection(value: unknown): value is AndroidBuildSelection {
  return keys(value, ['module', 'variant', 'applicationId', 'task']) && typeof value.module === 'string' &&
    value.module.startsWith(':') && value.module.length <= 512 && !/[^0-9A-Za-z_.:-]/.test(value.module) &&
    typeof value.variant === 'string' && value.variant.length >= 1 && value.variant.length <= 128 && !/[^0-9A-Za-z_-]/.test(value.variant) &&
    typeof value.applicationId === 'string' && value.applicationId.length <= 255 && !/[^A-Za-z0-9_.]/.test(value.applicationId) &&
    /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/.test(value.applicationId) &&
    typeof value.task === 'string' && value.task.startsWith(':') && value.task.length >= 2 && value.task.length <= 648 && !/[^0-9A-Za-z_.:-]/.test(value.task);
}
function commandObservation(value: unknown): value is AndroidBuildCommandObservation {
  return keys(value, ['outcome', 'exitCode']) && oneOf(value.outcome, ['not-dispatched', 'exited', 'unknown']) &&
    (value.outcome === 'exited' ? integer(value.exitCode, 0x7fff_ffff, -0x8000_0000) : value.exitCode === null);
}
const exitedZero = (value: AndroidBuildCommandObservation): boolean => value.outcome === 'exited' && value.exitCode === 0;
function inspection(value: unknown): value is AndroidBuildInspection {
  if (!keys(value, ['findings', 'summary']) || !Array.isArray(value.findings) || value.findings.length > ANDROID_BUILD_MAX_FINDINGS ||
      !keys(value.summary, ['total', 'shown', 'omitted', 'counts'])) return false;
  const findings = value.findings, summary = value.summary, counts = summary.counts;
  if (!integer(summary.total, ANDROID_BUILD_MAX_FINDINGS) || summary.total !== findings.length ||
      summary.shown !== summary.total || summary.omitted !== 0 || !keys(counts, ANDROID_BUILD_CORE_STATUSES) ||
      !ANDROID_BUILD_CORE_STATUSES.every((key) => integer(counts[key], ANDROID_BUILD_MAX_FINDINGS))) return false;
  const observed: Record<string, number> = Object.create(null) as Record<string, number>;
  for (let ordinal = 0; ordinal < findings.length; ordinal++) {
    const row: unknown = findings[ordinal];
    if (!keys(row, ['ordinal', 'check', 'status']) || row.ordinal !== ordinal || !oneOf(row.check, ANDROID_BUILD_CHECK_IDS) ||
        !oneOf(row.status, ANDROID_BUILD_CORE_STATUSES) || row.check === 'signer' && row.status !== 'SKIP') return false;
    observed[row.status] = (observed[row.status] ?? 0) + 1;
  }
  return ANDROID_BUILD_CORE_STATUSES.every((key) => (observed[key] ?? 0) === counts[key]);
}
function activity(value: unknown): value is AndroidBuildActivity {
  if (!keys(value, ['stage', 'selection', 'command', 'findings', 'summary']) || !oneOf(value.stage, ANDROID_BUILD_STAGES) ||
      !(value.selection === null || selection(value.selection)) || !commandObservation(value.command)) return false;
  const selected = value.selection, command = value.command;
  if (['inputs-bound', 'building', 'capturing', 'inspecting'].includes(value.stage) && selected === null) return false;
  if (['capturing', 'inspecting'].includes(value.stage) && !exitedZero(command)) return false;
  if (command.outcome !== 'not-dispatched' && (selected === null || !['building', 'capturing', 'inspecting', 'disposing-work'].includes(value.stage))) return false;
  const observed = { findings: value.findings, summary: value.summary };
  return inspection(observed) && (!observed.findings.some((row) => !['core-lifecycle', 'other-core-finding'].includes(row.check)) ||
    exitedZero(command) && ['inspecting', 'disposing-work'].includes(value.stage));
}
function artifact(value: unknown): value is AndroidBuildArtifact {
  if (!keys(value, ['logicalName', 'platform', 'kind', 'fileName', 'size', 'sha256', 'architectures', 'unknownAbi', 'freshness']) ||
      value.logicalName !== 'android-aab' || value.platform !== 'android' || value.kind !== 'aab' || value.fileName !== 'app-release.aab' ||
      !integer(value.size, ANDROID_BUILD_MAX_AAB_BYTES, 1) || !sha(value.sha256) || typeof value.unknownAbi !== 'boolean' ||
      value.freshness !== 'not-established' || !Array.isArray(value.architectures)) return false;
  const architectures = value.architectures;
  const ordered = ANDROID_BUILD_ABIS.filter((abi) => architectures.includes(abi));
  return ordered.length === architectures.length && ordered.every((abi, index) => architectures[index] === abi);
}
function derivedAssurances(rows: AndroidBuildFinding[]): AndroidBuildAssurances {
  const structures = rows.filter((row) => row.check === 'aab-structure').map((row) => row.status);
  const structure = structures.length === 1 && structures[0] === 'PASS' ? 'passed' : structures.some((status) => failures.includes(status)) ? 'failed' : 'not-checked';
  const manifest = rows.filter((row) => manifestChecks.includes(row.check));
  const unsupported = rows.some((row) => row.check === 'other-core-finding' || row.check === 'core-lifecycle');
  const nativeManifest = structure === 'passed' && !unsupported && manifest.length === 1 && manifest[0]?.check === 'aab-manifest' &&
    manifest[0].status === 'PASS' ? 'passed' : manifest.some((row) => failures.includes(row.status)) ? 'failed' : 'not-checked';
  return { structure, nativeManifest, applicationVersion: nativeManifest === 'passed' ? 'native-checked' : 'not-established',
    signer: 'not-inspected', toolkitSigning: 'not-requested', storeOperation: 'not-requested', sourceBinding: 'not-established', releaseReadiness: 'not-assessed' };
}
function result(value: unknown): value is AndroidBuildResult {
  if (!keys(value, ['schemaVersion', 'scope', 'usedConfig', 'usedVersion', 'selection', 'toolchainProfile', 'command', 'findings', 'summary',
      'artifacts', 'assurances', 'limitations']) || value.schemaVersion !== 1 || value.scope !== ANDROID_BUILD_SCOPE ||
      !content(value.usedConfig) || !savedVersion(value.usedVersion) || !selection(value.selection) || value.toolchainProfile !== ANDROID_BUILD_TOOLCHAIN_PROFILE ||
      !commandObservation(value.command) || !exitedZero(value.command) || !Array.isArray(value.artifacts) || value.artifacts.length !== 1 ||
      !artifact(value.artifacts[0]) || !Array.isArray(value.limitations) || value.limitations.length !== ANDROID_BUILD_LIMITATIONS.length) return false;
  const limitations = value.limitations, observed = { findings: value.findings, summary: value.summary };
  if (!ANDROID_BUILD_LIMITATIONS.every((key, index) => limitations[index] === key) || !inspection(observed) ||
      !observed.findings.some((row) => row.check === 'aab-structure') || observed.findings.some((row) => row.check === 'core-lifecycle')) return false;
  const expected = derivedAssurances(observed.findings);
  return keys(value.assurances, Object.keys(expected)) && sameAndroidBuildData(value.assurances, expected);
}
export function parseAndroidBuildResult(value: unknown): AndroidBuildResult | null {
  try { const safe = copyData(value, ANDROID_BUILD_STATUS_LIMIT); return result(safe) ? safe : null; } catch { return null; }
}
function disposition(value: unknown): value is AndroidBuildDisposition {
  return keys(value, ['work', 'artifacts']) && oneOf(value.work, ['not-created', 'removed', 'retained-work', 'unknown']) &&
    oneOf(value.artifacts, ['not-created', 'removed', 'retained-local-result', 'retained-incomplete', 'unknown']);
}
function operation(value: unknown): value is AndroidBuildOperation {
  if (!keys(value, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'stage', 'activity', 'disposition', 'result']) ||
      !identity(value) || !context(value.context) || !oneOf(value.phase, phases) || typeof value.intentUsable !== 'boolean' ||
      !(value.outcome === null || oneOf(value.outcome, outcomes)) || !oneOf(value.reason, Object.keys(androidBuildReasonText)) ||
      !(value.stage === null || oneOf(value.stage, ANDROID_BUILD_STAGES)) || !(value.activity === null || activity(value.activity)) ||
      !(value.disposition === null || disposition(value.disposition)) || !(value.result === null || result(value.result))) return false;
  const op = value as unknown as AndroidBuildOperation;
  if ((op.activity === null) !== (op.disposition === null) || op.activity !== null && op.stage !== op.activity.stage) return false;
  if (op.phase === 'awaiting-consent') return op.outcome === null && op.reason === 'none' && op.stage === null &&
    op.activity === null && op.disposition === null && op.result === null;
  if (op.intentUsable) return false;
  if (op.phase === 'unknown') return op.outcome === 'unknown' && op.reason === 'cleanup-unknown' &&
    op.activity === null && op.disposition === null && op.result === null;
  if (op.phase !== 'terminal') return op.outcome === null && op.result === null && op.activity === null && op.disposition === null &&
    (op.phase !== 'starting' || op.stage === null);
  if (op.outcome === null || op.outcome === 'unknown' || (op.reason === 'none') !== (op.outcome === 'complete')) return false;
  if (op.outcome === 'complete') {
    return op.stage === 'disposing-work' && op.activity !== null && op.disposition?.work === 'removed' &&
      op.disposition.artifacts === 'retained-local-result' && op.result !== null &&
      sameAndroidBuildSavedPair(op.context, { savedConfig: op.result.usedConfig, savedVersion: op.result.usedVersion }) &&
      sameAndroidBuildData(op.activity.selection, op.result.selection) && sameAndroidBuildData(op.activity.command, op.result.command) &&
      sameAndroidBuildData(op.activity.findings, op.result.findings) && sameAndroidBuildData(op.activity.summary, op.result.summary);
  }
  // Native retirement preserves its first context/document/shutdown reason.
  // This is not the stricter provisional Python core-terminal stop predicate.
  if (op.result !== null || op.reason === 'cleanup-unknown' ||
      op.outcome === 'cancelled' && !['cancelled', 'context-changed', 'document-lost', 'shutdown'].includes(op.reason) ||
      op.outcome === 'timed-out' && op.reason !== 'timed-out') return false;
  if (op.activity === null || op.disposition === null) return !artifactReasons.includes(op.reason) &&
    !['command-failed', 'command-incomplete', 'work-retained'].includes(op.reason);
  if (op.disposition.work === 'unknown' || ['unknown', 'retained-local-result'].includes(op.disposition.artifacts) ||
      op.disposition.work === 'retained-work' && op.outcome !== 'failed') return false;
  const observed = op.activity;
  if (op.outcome === 'refused' && observed.command.outcome !== 'not-dispatched') return false;
  if (op.reason === 'command-failed' && (op.outcome !== 'failed' || observed.command.outcome !== 'exited' || observed.command.exitCode === 0)) return false;
  if (op.reason === 'command-incomplete' && (op.outcome !== 'failed' || observed.command.outcome === 'exited')) return false;
  if (artifactReasons.includes(op.reason) && (op.outcome !== 'failed' || observed.selection === null || !exitedZero(observed.command) ||
      !['capturing', 'inspecting', 'disposing-work'].includes(observed.stage))) return false;
  return op.reason !== 'work-retained' || op.outcome === 'failed' && op.disposition.work === 'retained-work';
}
export function parseAndroidBuildStatus(value: unknown): AndroidBuildStatus | null {
  try {
    const safe = copyData(value, ANDROID_BUILD_STATUS_LIMIT);
    if (!keys(safe, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || safe.schemaVersion !== 1 ||
        !androidBuildCounter(safe.statusRevision) || !oneOf(safe.availability, Object.keys(androidBuildAvailabilityText)) ||
        !(safe.operation === null || operation(safe.operation))) return null;
    return safe as unknown as AndroidBuildStatus;
  } catch { return null; }
}
// Only validated, copied DATA belongs in these comparison helpers. Key order is
// immaterial; matching a saved pair is not atomic input capture or fresh consent.
export function sameAndroidBuildData(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>, names = Object.keys(left);
  return names.length === Object.keys(right).length && names.every((name) => Object.hasOwn(right, name) && sameAndroidBuildData(left[name], right[name]));
}
export function sameAndroidBuildSavedPair(a: AndroidBuildSavedPair | null, b: AndroidBuildSavedPair | null): boolean {
  return a === null || b === null ? a === b : sameAndroidBuildData(a.savedConfig, b.savedConfig) && sameAndroidBuildData(a.savedVersion, b.savedVersion);
}
export function sameAndroidBuildIdentity(a: AndroidBuildIdentity | null, b: AndroidBuildIdentity | null): boolean {
  return !!a && !!b && a.operationId === b.operationId && a.ownerGeneration === b.ownerGeneration;
}
export function androidBuildOperationProgress(a: AndroidBuildOperation, b: AndroidBuildOperation): boolean {
  if (!sameAndroidBuildIdentity(a, b) || !sameAndroidBuildData(a.context, b.context)) return false;
  if (a.phase === 'terminal') return sameAndroidBuildData(a, b);
  if (a.phase === 'unknown' && b.phase !== 'unknown' || !a.intentUsable && b.intentUsable) return false;
  const stageIndex = (stage: AndroidBuildStage | null) => stage === null ? -1 : ANDROID_BUILD_STAGES.indexOf(stage);
  return phases.indexOf(b.phase) >= phases.indexOf(a.phase) && stageIndex(b.stage) >= stageIndex(a.stage);
}

export const androidBuildAvailabilityText: Record<AndroidBuildAvailability, string> = {
  available: 'The separate native Android build capability is available. Saved-input review and explicit consent are still required.',
  busy: 'An original operation owns the native slot. Keep its Status and Cancel accessible until original settlement.',
  shutdown: 'The application is stopping its original operations. No new Android build can start.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the original owner; conflicting work and normal exit remain blocked.',
  'document-lost': 'The original native document is no longer available. A replacement view cannot adopt or reset its owner.',
  'unsupported-platform': 'This Android build action is unsupported on this host profile. There is no fallback runner.',
  'runtime-unqualified': 'Android builds are disabled for this runtime and native document. Passive capability success does not qualify execution.',
  'toolchain-unqualified': 'The separately qualified Android toolchain and original custody are unavailable. This action installs no tools and accepts no licenses.',
};
const savedConfigGuidance = 'Correct the saved configuration and refresh its saved input comparison after original cleanup settles; unsaved drafts are not used.';
const savedVersionGuidance = 'Correct the version file selected by the saved configuration, then refresh both saved comparisons after original cleanup settles.';
// Exact fixed Python reason_guidance text, never a compiler/exception message.
export const androidBuildReasonText: Record<AndroidBuildReason, string> = {
  none: 'Review the separate inspection findings. Task completion and retained local bytes are not release approval.',
  cancelled: 'Cancellation is not rollback. Check original status and output disposition; start no new run until original cleanup is confirmed.',
  'context-changed': 'The reviewed selection changed. Wait for the original run to settle, refresh saved inputs and provide new consent.',
  'document-lost': 'The original document is no longer attached. Check original status; do not repeat Start or adopt its files from a new session.',
  shutdown: 'Wait for original shutdown and cleanup. Closing a view does not prove the command or its helpers have stopped.',
  'timed-out': 'The original deadline was reached. Check original cleanup and retained output status; a timeout does not identify a private compiler error.',
  'protocol-error': 'The original build communication did not match its fixed contract. Check original status and wait for cleanup; do not repeat Start.',
  'runtime-unavailable': 'The required Desktop runtime is unavailable. Use a separately qualified runtime; no system-runtime fallback is used.',
  'intent-expired': 'The saved-input review expired. After original settlement, refresh the saved comparisons and provide new consent.',
  'stale-intent': 'This consent no longer identifies the current original owner. Check original status rather than repeating Start.',
  'saved-config-missing': savedConfigGuidance, 'saved-config-invalid': savedConfigGuidance, 'saved-config-changed': savedConfigGuidance,
  'saved-config-sensitive': savedConfigGuidance, 'saved-config-unsafe': savedConfigGuidance, 'saved-config-too-large': savedConfigGuidance,
  'saved-version-missing': savedVersionGuidance, 'saved-version-invalid': savedVersionGuidance, 'saved-version-changed': savedVersionGuidance,
  'saved-version-sensitive': savedVersionGuidance, 'saved-version-unsafe': savedVersionGuidance, 'saved-version-too-large': savedVersionGuidance,
  'platform-disabled': 'Enable and save the intended Android configuration before refreshing the saved build selection.',
  'module-required': 'Configure android.module as the intended Android application module, save it, then refresh the saved selection.',
  'toolchain-unavailable': 'Configure the separately qualified JDK, Android SDK, Gradle and pinned bundletool profile. This action installs no tools and accepts no SDK licenses.',
  'toolchain-mismatch': "Make the project's wrapper and SDK/JDK selection agree with the qualified fixed profile. No alternate wrapper or ambient installation is selected.",
  'project-admission-refused': "Resolve the original project's pending toolkit work or private-directory admission issue before reviewing a new run; do not delete shared caches.",
  'command-failed': "Gradle returned a known nonzero code. Possible causes include project or dependency configuration; inspect private Build Output in Android Studio or the project's normal editor. App-code fixes may require that editor. Refresh and provide new consent only after original cleanup is confirmed.",
  'command-incomplete': 'No usable Gradle command outcome was obtained. Check original cleanup status; no exit code or hidden compiler diagnosis is inferred.',
  'artifact-missing': "The required AAB was not found in the configured module and variant output. Check that project's bundle task before a newly consented run.",
  'artifact-ambiguous': "More than one required AAB candidate was observed. Resolve the configured project's ambiguous output without adopting a substitute file.",
  'artifact-unsafe': "The selected output could not be admitted safely. Correct the project's output layout; no alternate path or arbitrary file picker is used.",
  'artifact-changed': 'The original captured output or input changed during observation. Review project changes and refresh only after original cleanup settles.',
  'input-limit': 'The saved input or task-owned processing limit was reached. Reduce the applicable input or use a separately supported profile; no limit is raised automatically.',
  'result-limit': 'The bounded result could not be represented safely. Check original status and cleanup; raw tool output is not a substitute report.',
  'work-retained': 'Original task work is known to remain. Review its disposition; this result offers no automatic rerun, blanket deletion or global daemon stop.',
  'cleanup-unknown': 'Original cleanup is unconfirmed and the owner remains retained. Use original Status or Cancel; further execution stays blocked. Do not adopt or delete files from a new session.',
};
export const androidBuildFindingText: Record<AndroidBuildCheckId, string> = {
  'aab-structure': 'AAB structure inspection.', 'aab-manifest': 'Native AAB manifest inspection.', 'application-id': 'Application ID inspection.',
  'build-number': 'Build number inspection.', 'version-name': 'Version name inspection.', 'release-flags': 'Release flags inspection.',
  signer: ANDROID_BUILD_SIGNER_MESSAGE, 'core-lifecycle': 'Core lifecycle finding.', 'other-core-finding': 'Other core finding; its exact status is preserved.',
};
export const androidBuildLimitationText: Record<AndroidBuildLimitation, string> = {
  'saved-inputs-not-atomic': 'Saved input comparisons do not describe an atomic checkout; external changes are not continuously watched.',
  'project-code-effects-possible': 'Project code can modify files, run programs, read account files and sign outputs.',
  'not-network-isolated': 'The build is not network isolation or a sandbox guarantee.',
  'post-run-bytes-may-be-incremental-reused-or-stale': 'Post-run artifact bytes may be incremental, reused or stale; a zero exit does not prove freshness.',
  'source-binding-not-established': 'Binding of these output bytes to current source has not been established.',
  'artifact-signer-not-inspected': ANDROID_BUILD_SIGNER_MESSAGE,
  'toolkit-signing-not-requested': 'Toolkit signing was not requested. That does not establish that project code left the file unsigned.',
  'store-operation-not-requested': 'No Store operation was requested by the toolkit.',
  'release-readiness-not-assessed': 'Release readiness was not assessed. A completed task is not release approval.',
  'local-output-observation-not-current-file-authority': 'The redacted local output observation is not current-file authority or permission to open, adopt, delete or publish a file.',
  'core-terminal-requires-original-native-finality': 'A core terminal is provisional until the original native owners and final joins settle.',
};
const errors: Record<string, string> = {
  android_build_invalid: 'The Android-build request was not valid closed DATA. Nothing was authorized by this response.',
  android_build_unavailable: 'The separate native Android-build capability is unavailable. No browser or ambient-runtime fallback is used.',
  android_build_busy: 'Another original operation owns the native slot. Keep its Status and Cancel accessible.',
  android_build_owner: 'The intent identity is foreign, stale or consumed. No Start can be replayed or rearmed.',
  android_build_protocol: 'A usable original Android-build response was not received. Check retained Status; do not repeat Start.',
};
export function androidBuildError(value: unknown): ApiError {
  let code = 'android_build_protocol';
  try {
    const descriptor = value !== null && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'code') : undefined;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
  } catch { /* No getter, private compiler output or exception message is UI text. */ }
  return { code, message: errors[code]!, retryable: false };
}
