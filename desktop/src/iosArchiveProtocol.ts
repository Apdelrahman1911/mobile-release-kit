// Strict renderer DATA for the original unsigned iOS archive owner. Raw native
// decoding and original final joins remain native responsibilities. No status,
// path label or signature-like field can authorize execution or publication.
import type { ApiError } from './types.ts';
import type { IOSArchiveActivity, IOSArchiveAvailability, IOSArchiveCheckId, IOSArchiveCommandObservation,
  IOSArchiveContext, IOSArchiveCoreStatus, IOSArchiveDisposition, IOSArchiveIdentity, IOSArchiveLimitation,
  IOSArchiveOperation, IOSArchiveOutcome, IOSArchivePhase, IOSArchiveReason, IOSArchiveResult,
  IOSArchiveSavedConfig, IOSArchiveSavedPair, IOSArchiveSavedVersion, IOSArchiveSelection, IOSArchiveStage,
  IOSArchiveStatus, PrepareIOSArchive, StartIOSArchive } from './iosArchiveTypes.ts';

export const IOS_ARCHIVE_EVENT = 'ios-archive-state-changed';
export const IOS_ARCHIVE_CONSENT = 'saved-ios-unsigned-archive-v1';
export const IOS_ARCHIVE_SCOPE = 'local-unsigned-ios-archive-observation';
export const IOS_ARCHIVE_COUNTER_MAX = 0xffff_fffe;
export const IOS_ARCHIVE_IPC_LIMIT = 8192;
export const IOS_ARCHIVE_STATUS_LIMIT = 65536;
export const IOS_ARCHIVE_CONSENT_MS = 300_000;
export const IOS_ARCHIVE_CORE_STATUSES: readonly IOSArchiveCoreStatus[] = Object.freeze([
  'PASS', 'FAIL', 'MISSING', 'BLOCKED', 'INVALID', 'SKIP', 'MANUAL', 'CONFIGURED', 'NOT_APPLICABLE',
]);
export const IOS_ARCHIVE_CHECK_IDS: readonly IOSArchiveCheckId[] = Object.freeze([
  'archive-identity', 'archive-dsym', 'archive-structure', 'other-core-finding',
]);
export const IOS_ARCHIVE_STAGES: readonly IOSArchiveStage[] = Object.freeze([
  'accepted', 'inputs-bound', 'checking-xcode', 'preparing', 'archiving', 'inspecting', 'disposing-snapshot', 'disposing-work',
]);
export const IOS_ARCHIVE_ROLES = Object.freeze(['xcode-version', 'ios-sdk', 'prepare', 'archive'] as const);
export const IOS_ARCHIVE_LIMITATIONS: readonly IOSArchiveLimitation[] = Object.freeze([
  'saved-inputs-not-atomic', 'project-build-code-is-trusted', 'not-network-isolated', 'unsigned-archive-not-an-ipa',
  'signing-and-profile-not-validated', 'ipa-correspondence-not-validated', 'source-provenance-not-authenticated',
  'store-operation-not-requested', 'release-readiness-not-assessed', 'retained-location-not-current-file-authority',
  'core-terminal-requires-original-native-finality',
]);
const phases: readonly IOSArchivePhase[] = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
const outcomes: readonly IOSArchiveOutcome[] = ['complete', 'refused', 'failed', 'cancelled', 'timed-out', 'unknown'];
export type IOSArchiveCommand = 'prepare_ios_archive' | 'start_ios_archive' | 'cancel_ios_archive' | 'ios_archive_status';
const encoder = new TextEncoder();
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const oneOf = <T extends string>(value: unknown, options: readonly T[]): value is T => typeof value === 'string' && options.includes(value as T);
const integer = (value: unknown, maximum: number, minimum = 0): value is number => typeof value === 'number' &&
  Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum && value <= maximum;
export const iosArchiveCounter = (value: unknown): value is number => integer(value, IOS_ARCHIVE_COUNTER_MAX);
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
function content(value: unknown, maximum = 524288): value is IOSArchiveSavedConfig {
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
function savedVersion(value: unknown): value is IOSArchiveSavedVersion {
  return keys(value, ['source', 'bytes', 'sha256', 'name', 'build']) && relativeDisplayPath(value.source) &&
    content({ bytes: value.bytes, sha256: value.sha256 }, 65536) && typeof value.name === 'string' &&
    value.name.length >= 1 && value.name.length <= 64 && !/[^0-9A-Za-z.+-]/.test(value.name) && integer(value.build, 2_100_000_000, 1);
}
export function parseIOSArchiveSavedConfig(value: unknown): IOSArchiveSavedConfig | null {
  try { const safe = copyData(value, 256, 16); return content(safe) ? safe : null; } catch { return null; }
}
export function parseIOSArchiveSavedVersion(value: unknown): IOSArchiveSavedVersion | null {
  try { const safe = copyData(value, IOS_ARCHIVE_IPC_LIMIT, 32); return savedVersion(safe) ? safe : null; } catch { return null; }
}

function prepare(value: unknown): value is PrepareIOSArchive {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion']) && projectId(value.projectId) &&
    iosArchiveCounter(value.draftRevision) && iosArchiveCounter(value.baselineGeneration) && content(value.savedConfig) && savedVersion(value.savedVersion);
}
function identity(value: unknown): value is IOSArchiveIdentity {
  return record(value) && token(value.operationId) && token(value.ownerGeneration);
}
function context(value: unknown): value is IOSArchiveContext {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'platform', 'operation']) &&
    value.platform === 'ios' && value.operation === 'ios-unsigned-archive' && prepare({ projectId: value.projectId,
      draftRevision: value.draftRevision, baselineGeneration: value.baselineGeneration, savedConfig: value.savedConfig, savedVersion: value.savedVersion });
}
export function copyIOSArchiveRequest(command: IOSArchiveCommand, value: unknown): PrepareIOSArchive | StartIOSArchive | IOSArchiveIdentity | Record<string, never> | null {
  try {
    const safe = copyData(value, IOS_ARCHIVE_IPC_LIMIT, 64);
    if (command === 'prepare_ios_archive' && prepare(safe)) return safe;
    if (command === 'start_ios_archive' && keys(safe, ['operationId', 'ownerGeneration', 'consentVersion']) &&
        identity(safe) && safe.consentVersion === IOS_ARCHIVE_CONSENT) return safe as unknown as StartIOSArchive;
    if (command === 'cancel_ios_archive' && keys(safe, ['operationId', 'ownerGeneration']) && identity(safe)) return safe;
    if (command === 'ios_archive_status' && keys(safe, [])) return safe as Record<string, never>;
  } catch { /* Rejected data and exceptions never become UI text. */ }
  return null;
}
export function encodeIOSArchiveRequest(command: IOSArchiveCommand, value: unknown): Uint8Array | null {
  const safe = copyIOSArchiveRequest(command, value);
  if (safe === null) return null;
  const bytes = encoder.encode(JSON.stringify(safe));
  return bytes.byteLength >= 1 && bytes.byteLength <= IOS_ARCHIVE_IPC_LIMIT ? bytes : null;
}
function selection(value: unknown): value is IOSArchiveSelection {
  return keys(value, ['containerKind', 'container', 'scheme', 'configuration', 'bundleId', 'symbolsPolicy', 'preparationConfigured']) &&
    oneOf(value.containerKind, ['project', 'workspace']) && oneOf(value.symbolsPolicy, ['disabled', 'retain', 'required']) &&
    typeof value.preparationConfigured === 'boolean' && ['container', 'scheme', 'configuration', 'bundleId'].every((key) => {
      const text = value[key]; return typeof text === 'string' && encoder.encode(text).byteLength >= 1 &&
        encoder.encode(text).byteLength <= 512 && !/[\u0000-\u001f\u007f]/u.test(text);
    });
}
export function parseIOSArchiveSelection(value: unknown): IOSArchiveSelection | null {
  try { const safe = copyData(value, IOS_ARCHIVE_IPC_LIMIT, 32); return selection(safe) ? safe : null; } catch { return null; }
}
function commandObservation(value: unknown): value is IOSArchiveCommandObservation {
  return keys(value, ['outcome', 'exitCode']) && oneOf(value.outcome, ['not-dispatched', 'exited', 'unknown', 'not-configured']) &&
    (value.outcome === 'exited' ? integer(value.exitCode, 0x7fff_ffff, -0x8000_0000) : value.exitCode === null);
}
const exitedZero = (value: IOSArchiveCommandObservation): boolean => value.outcome === 'exited' && value.exitCode === 0;
function activity(value: unknown): value is IOSArchiveActivity {
  if (!keys(value, ['stage', 'selection', 'commands', 'findings']) || !oneOf(value.stage, IOS_ARCHIVE_STAGES) ||
      !(value.selection === null || selection(value.selection)) || value.stage !== 'accepted' && value.selection === null ||
      !keys(value.commands, IOS_ARCHIVE_ROLES) ||
      !Array.isArray(value.findings) || value.findings.length > 16) return false;
  const commands = value.commands;
  if (!IOS_ARCHIVE_ROLES.every((role) => commandObservation(commands[role]))) return false;
  const observed = value as unknown as IOSArchiveActivity;
  return ['xcode-version', 'ios-sdk', 'archive'].every((role) => observed.commands[role as keyof typeof observed.commands].outcome !== 'not-configured') &&
    observed.findings.every((row) => keys(row, ['check', 'status']) && oneOf(row.check, IOS_ARCHIVE_CHECK_IDS) && oneOf(row.status, IOS_ARCHIVE_CORE_STATUSES)) &&
    (observed.findings.length === 0 && IOS_ARCHIVE_STAGES.indexOf(observed.stage) < IOS_ARCHIVE_STAGES.indexOf('inspecting') || exitedZero(observed.commands.archive));
}
function completedActivity(value: IOSArchiveActivity): boolean {
  const selected = value.selection, commands = value.commands, findings = value.findings;
  return selected !== null && value.stage === 'disposing-work' && exitedZero(commands['xcode-version']) && exitedZero(commands['ios-sdk']) &&
    exitedZero(commands.archive) && (selected.preparationConfigured ? exitedZero(commands.prepare) : commands.prepare.outcome === 'not-configured') &&
    findings.length === 2 && findings[0]?.check === 'archive-identity' && findings[0].status === 'PASS' && findings[1]?.check === 'archive-dsym' &&
    (findings[1].status === 'PASS' || selected.symbolsPolicy === 'disabled' && findings[1].status === 'NOT_APPLICABLE');
}
function result(value: unknown, ctx: IOSArchiveContext, operationId: string): value is IOSArchiveResult {
  if (!keys(value, ['schemaVersion', 'scope', 'usedConfig', 'usedVersion', 'archive', 'entries', 'bytes', 'limitations']) ||
      value.schemaVersion !== 1 || value.scope !== IOS_ARCHIVE_SCOPE || !content(value.usedConfig) || !savedVersion(value.usedVersion) ||
      !sameIOSArchiveSavedPair(ctx, { savedConfig: value.usedConfig, savedVersion: value.usedVersion }) ||
      value.archive !== `.mobile-release/desktop-ios-archive/${operationId}/archive.xcarchive` ||
      !integer(value.entries, 100_000, 1) || !integer(value.bytes, 8 * 1024 ** 3, 1) || !Array.isArray(value.limitations)) return false;
  const limits = value.limitations;
  return limits.length === IOS_ARCHIVE_LIMITATIONS.length && IOS_ARCHIVE_LIMITATIONS.every((key, index) => limits[index] === key);
}
function disposition(value: unknown, operationId: string): value is IOSArchiveDisposition {
  return keys(value, ['snapshot', 'work', 'output', 'relativeDirectory']) && oneOf(value.snapshot, ['not-created', 'removed', 'unknown']) &&
    oneOf(value.work, ['not-created', 'removed', 'retained-work', 'unknown']) &&
    oneOf(value.output, ['not-created', 'retained-local-result', 'retained-incomplete', 'unknown']) &&
    (value.output === 'not-created' ? value.relativeDirectory === null : value.relativeDirectory === `.mobile-release/desktop-ios-archive/${operationId}`);
}
function operation(value: unknown): value is IOSArchiveOperation {
  if (!keys(value, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'stage', 'activity', 'disposition', 'result']) ||
      !identity(value) || !context(value.context) || !oneOf(value.phase, phases) || typeof value.intentUsable !== 'boolean' ||
      !(value.outcome === null || oneOf(value.outcome, outcomes)) || !oneOf(value.reason, Object.keys(iosArchiveReasonText)) ||
      !(value.stage === null || oneOf(value.stage, IOS_ARCHIVE_STAGES)) || !(value.activity === null || activity(value.activity)) ||
      !(value.disposition === null || disposition(value.disposition, value.operationId)) ||
      !(value.result === null || result(value.result, value.context, value.operationId))) return false;
  const op = value as unknown as IOSArchiveOperation;
  if ((op.activity === null) !== (op.disposition === null) || op.activity !== null && op.stage !== op.activity.stage) return false;
  const empty = op.activity === null && op.disposition === null && op.result === null;
  if (op.phase === 'awaiting-consent') return op.outcome === null && op.reason === 'none' && op.stage === null && empty;
  if (op.intentUsable) return false;
  if (op.phase === 'unknown') return op.outcome === 'unknown' && op.reason === 'cleanup-unknown' && empty;
  if (op.phase !== 'terminal') return op.outcome === null && empty && (op.phase !== 'starting' || op.stage === null);
  if (op.outcome === null || op.outcome === 'unknown' || op.reason === 'cleanup-unknown' || (op.reason === 'none') !== (op.outcome === 'complete')) return false;
  if (op.outcome === 'complete') return op.stage === 'disposing-work' && op.activity !== null && completedActivity(op.activity) &&
    op.disposition?.snapshot === 'removed' && op.disposition.work === 'removed' && op.disposition.output === 'retained-local-result' && op.result !== null;
  // Native retirement preserves first context/document/shutdown reason; a
  // provisional Python terminal alone cannot publish these observations.
  if (op.result !== null || op.outcome === 'cancelled' && !['cancelled', 'context-changed', 'document-lost', 'shutdown'].includes(op.reason) ||
      op.outcome === 'timed-out' && op.reason !== 'timed-out') return false;
  return op.disposition === null || op.disposition.snapshot !== 'unknown' && op.disposition.work !== 'unknown' &&
    !['unknown', 'retained-local-result'].includes(op.disposition.output);
}
export function parseIOSArchiveStatus(value: unknown): IOSArchiveStatus | null {
  try {
    const safe = copyData(value, IOS_ARCHIVE_STATUS_LIMIT);
    if (!keys(safe, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || safe.schemaVersion !== 1 ||
        !iosArchiveCounter(safe.statusRevision) || !oneOf(safe.availability, Object.keys(iosArchiveAvailabilityText)) ||
        !(safe.operation === null || operation(safe.operation))) return null;
    return safe as unknown as IOSArchiveStatus;
  } catch { return null; }
}
// Compare only validated DATA. Matching labels never grants file authority.
export function sameIOSArchiveData(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>, names = Object.keys(left);
  return names.length === Object.keys(right).length && names.every((name) => Object.hasOwn(right, name) && sameIOSArchiveData(left[name], right[name]));
}
export function sameIOSArchiveSavedPair(a: IOSArchiveSavedPair | null, b: IOSArchiveSavedPair | null): boolean {
  return a === null || b === null ? a === b : sameIOSArchiveData(a.savedConfig, b.savedConfig) && sameIOSArchiveData(a.savedVersion, b.savedVersion);
}
export function sameIOSArchiveIdentity(a: IOSArchiveIdentity | null, b: IOSArchiveIdentity | null): boolean {
  return !!a && !!b && a.operationId === b.operationId && a.ownerGeneration === b.ownerGeneration;
}
export function iosArchiveOperationProgress(a: IOSArchiveOperation, b: IOSArchiveOperation): boolean {
  if (!sameIOSArchiveIdentity(a, b) || !sameIOSArchiveData(a.context, b.context)) return false;
  if (a.phase === 'terminal') return sameIOSArchiveData(a, b);
  if (a.phase === 'unknown' && b.phase !== 'unknown' || !a.intentUsable && b.intentUsable) return false;
  const stageIndex = (stage: IOSArchiveStage | null) => stage === null ? -1 : IOS_ARCHIVE_STAGES.indexOf(stage);
  return phases.indexOf(b.phase) >= phases.indexOf(a.phase) && stageIndex(b.stage) >= stageIndex(a.stage);
}

export const iosArchiveAvailabilityText: Record<IOSArchiveAvailability, string> = {
  available: 'The separate native iOS archive capability is available. Review saved inputs and explicitly approve one archive first.',
  busy: 'An original operation owns the native slot. Keep its Status and Cancel until original cleanup settles.',
  shutdown: 'The application is stopping its original operations. No new archive can start.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep this owner; conflicting work and normal exit remain blocked.',
  'document-lost': 'The original native document is no longer available. A replacement view cannot adopt or reset its owner.',
  'unsupported-platform': 'This archive action requires the separately supported Apple-silicon macOS profile. Linux and Windows cannot archive an iOS app.',
  'runtime-unqualified': 'Unsigned iOS archives remain disabled by the native qualification gate. This does not mean Xcode is missing; passive checks do not qualify execution.',
  'toolchain-unqualified': 'The protected full-Xcode selection has not been qualified. This action does not install Xcode, download an SDK or accept a license.',
};
const configGuidance = 'Correct and save the configuration, then refresh its saved comparison after original cleanup settles. Unsaved drafts are not used.';
const versionGuidance = 'Correct the version file selected by the saved configuration, then refresh both saved comparisons after original cleanup settles.';
export const iosArchiveReasonText: Record<IOSArchiveReason, string> = {
  none: 'The unsigned archive passed this limited structural inspection. Signing, IPA export, Store readiness and authenticated source provenance were not checked.',
  cancelled: 'Cancellation is not rollback. Check retained output and original cleanup before reviewing another run.',
  'context-changed': 'The reviewed selection changed. Wait for original cleanup, refresh saved inputs and provide new consent.',
  'document-lost': 'The original document is no longer attached. Retain original Status; a new window cannot adopt its operation.',
  shutdown: 'Wait for original shutdown and cleanup. Closing a view does not prove that Xcode or project helpers stopped.',
  'timed-out': 'The original deadline was reached. Check cleanup and output disposition; a timeout does not identify a private compiler error.',
  'protocol-error': 'Original archive communication did not match its fixed contract. Keep Status; do not repeat Start.',
  'runtime-unavailable': 'The required installed Desktop runtime is unavailable. No system Python or development fallback is used.',
  'intent-expired': 'This saved-input review expired. After original cleanup settles, refresh the comparisons and review again.',
  'stale-intent': 'This consent no longer identifies the current unused owner. Check original Status rather than repeating Start.',
  'saved-config-missing': configGuidance, 'saved-config-invalid': configGuidance, 'saved-config-changed': configGuidance,
  'saved-config-sensitive': configGuidance, 'saved-config-unsafe': configGuidance, 'saved-config-too-large': configGuidance,
  'saved-version-missing': versionGuidance, 'saved-version-invalid': versionGuidance, 'saved-version-changed': versionGuidance,
  'saved-version-sensitive': versionGuidance, 'saved-version-unsafe': versionGuidance, 'saved-version-too-large': versionGuidance,
  'platform-disabled': 'Enable and save the intended iOS configuration before refreshing saved inputs.',
  'container-required': 'Save the intended iOS Xcode workspace or project. The archive action does not guess from discovery.',
  'scheme-required': 'Save the shared Xcode scheme for the app. In Xcode, use Product → Scheme → Manage Schemes to check its name and Shared setting.',
  'container-missing': 'The saved Xcode workspace or project is missing. Select the correct project configuration; no substitute path is adopted.',
  'toolchain-unavailable': 'Install full Xcode in Applications and finish its normal first-launch setup. Command Line Tools alone are insufficient. No tool is downloaded or license accepted here.',
  'toolchain-mismatch': 'The protected Xcode/SDK layout does not match the supported profile. Review Environment Requirements; an ambient xcode-select value cannot override this selection.',
  'project-admission-refused': 'Resolve pending toolkit work or unsafe private-directory state in the original project before a new review. Do not delete unrelated work or shared caches.',
  'command-failed': 'A known Xcode or preparation command returned a nonzero code. Review the role below and private build details in Xcode; compiler output is not copied into this report.',
  'command-incomplete': 'No usable original command outcome was obtained. Check retained cleanup; no exit code or private compiler diagnosis is inferred.',
  'artifact-missing': 'The expected task-owned archive was not created. Review the app scheme and build settings in Xcode before a newly consented run.',
  'artifact-unsafe': 'The archive layout could not be safely inspected. Correct the project output; no alternate artifact is silently substituted.',
  'artifact-changed': 'Original captured inputs or output changed during inspection. Review changes after original cleanup settles.',
  'archive-validation-failed': 'The archive did not pass the required identity/version or symbols checks. Review the exact finding below; do not use this as a signed release.',
  'input-limit': 'A bounded saved input or archive-processing limit was reached. Reduce the relevant input; no limit is silently raised.',
  'result-limit': 'The bounded result could not be represented safely. Keep original Status; raw tool output is not a substitute report.',
  'work-retained': 'Original task work is known to remain. This observation does not authorize blanket deletion or an automatic rerun.',
  'cleanup-unknown': 'Original cleanup is unconfirmed and ownership is retained. Use original Status or Cancel; new execution remains blocked.',
};
export const iosArchiveFindingText: Record<IOSArchiveCheckId, string> = {
  'archive-identity': 'Archive bundle identity and saved version/build.', 'archive-dsym': 'Archive symbols under the saved symbols policy.',
  'archive-structure': 'Archive structural inspection.', 'other-core-finding': 'Other core finding; its exact status is preserved.',
};
export const iosArchiveLimitationText: Record<IOSArchiveLimitation, string> = {
  'saved-inputs-not-atomic': 'Saved comparisons are not an atomic checkout; external changes remain possible.',
  'project-build-code-is-trusted': 'Xcode build phases and preparation code execute with your account access. Only build a project you trust.',
  'not-network-isolated': 'This operation is not network isolation or a project-code sandbox.',
  'unsigned-archive-not-an-ipa': 'This is an unsigned archive, not an exported or installable IPA.',
  'signing-and-profile-not-validated': 'Signing certificates, provisioning profiles and signature authenticity were not validated.',
  'ipa-correspondence-not-validated': 'No exported IPA was paired with this archive.',
  'source-provenance-not-authenticated': 'The archive is not authenticated source or build provenance.',
  'store-operation-not-requested': 'No toolkit Store upload, testing release or public release was requested.',
  'release-readiness-not-assessed': 'This limited completion is not overall release approval.',
  'retained-location-not-current-file-authority': 'The retained location describes this run only; it is not permission to open, adopt, delete or publish current files.',
  'core-terminal-requires-original-native-finality': 'Core output is provisional until the original native workers and final joins settle.',
};
const errors: Record<string, string> = {
  ios_archive_invalid: 'The iOS archive request was not valid closed DATA. Nothing was authorized by this response.',
  ios_archive_unavailable: 'The separate native iOS archive capability is unavailable. No browser or ambient-runtime fallback is used.',
  ios_archive_busy: 'Another original operation owns the native slot. Keep its Status and Cancel accessible.',
  ios_archive_owner: 'This intent is foreign, stale or consumed. No Start can be replayed or rearmed.',
  ios_archive_protocol: 'A usable original iOS archive response was not received. Check retained Status; do not repeat Start.',
};
export function iosArchiveError(value: unknown): ApiError {
  let code = 'ios_archive_protocol';
  try {
    const descriptor = value !== null && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'code') : undefined;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
  } catch { /* No getter, private compiler output or exception message is UI text. */ }
  return { code, message: errors[code]!, retryable: false };
}
