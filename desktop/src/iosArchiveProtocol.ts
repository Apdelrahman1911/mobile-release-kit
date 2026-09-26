// Strict renderer DATA for the original unsigned/signed iOS archive owner. Raw native
// decoding and original final joins remain native responsibilities. No status,
// path label or signature-like field can authorize execution or publication.
import type { ApiError } from './types.ts';
import type { IOSArchiveActivity, IOSArchiveAvailability, IOSArchiveCheckId, IOSArchiveCommandObservation,
  IOSArchiveBuildContext, IOSArchiveBuildOperation, IOSArchiveContext, IOSArchiveCoreStatus, IOSArchiveDisposition, IOSArchiveIdentity, IOSArchiveLimitation,
  IOSArchiveOperation, IOSArchiveOutcome, IOSArchivePhase, IOSArchiveReason, IOSArchiveResult,
  IOSArchiveSavedConfig, IOSArchiveSavedPair, IOSArchiveSavedVersion, IOSArchiveSelection, IOSArchiveStage,
  IOSArchiveStatus, IOSRecoveryContext, IOSRecoveryIntent, IOSRecoveryOperation, IOSRecoveryReport, IOSRecoveryRow, IOSRecoveryStage,
  IOSSigningPolicy, PrepareIOSArchive, StartIOSArchive } from './iosArchiveTypes.ts';

export const IOS_ARCHIVE_EVENT = 'ios-archive-state-changed';
export const IOS_ARCHIVE_CONSENT = 'saved-ios-unsigned-archive-v1';
export const IOS_SIGNED_ARCHIVE_CONSENT = 'saved-ios-signed-export-v2';
export const IOS_RECOVERY_CONSENT = 'local-ios-recovery-v1';
export const IOS_ACCOUNT_RECOVERY_CONFIRMATION = 'account-signing-is-idle-and-restore-owned-state';
export const IOS_PROJECT_RECOVERY_CONFIRMATION = 'project-build-inputs-are-idle-and-restore-owned-state';
export const IOS_ARCHIVE_SCOPE = 'local-unsigned-ios-archive-observation';
export const IOS_SIGNED_ARCHIVE_SCOPE = 'local-signed-ios-artifact-validation';
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
export const IOS_SIGNED_ARCHIVE_CHECK_IDS: readonly IOSArchiveCheckId[] = Object.freeze([
  ...IOS_ARCHIVE_CHECK_IDS, 'signing-material', 'profile-material', 'firebase-material', 'artifact-correspondence',
  'ipa-structure', 'ipa-profile', 'ipa-entitlements', 'ipa-signer', 'ipa-validation', 'symbols-upload',
]);
export const IOS_ARCHIVE_STAGES: readonly IOSArchiveStage[] = Object.freeze([
  'accepted', 'inputs-bound', 'checking-xcode', 'preparing', 'archiving', 'inspecting', 'disposing-snapshot', 'disposing-work',
]);
export const IOS_ARCHIVE_ROLES = Object.freeze(['xcode-version', 'ios-sdk', 'prepare', 'archive'] as const);
export const IOS_SIGNED_ARCHIVE_ROLES = Object.freeze([...IOS_ARCHIVE_ROLES, 'export'] as const);
export const IOS_SIGNED_ARCHIVE_STAGES: readonly IOSArchiveStage[] = Object.freeze([
  'accepted', 'inputs-bound', 'checking-xcode', 'validating-signing', 'materializing-signing', 'preparing', 'archiving',
  'exporting', 'restoring-signing', 'inspecting', 'disposing-snapshot', 'disposing-work',
]);
export const IOS_RECOVERY_STAGES: readonly IOSRecoveryStage[] = Object.freeze(['accepted', 'recovering-account', 'recovering-project', 'disposing-work']);
export const IOS_RECOVERY_LIMITATIONS: readonly IOSRecoveryReport['limitations'][number][] = Object.freeze([
  'local-recovery-only', 'manual-recovery-not-supported', 'user-confirmation-is-not-worker-finality', 'no-store-operation',
]);
export const isIOSRecoveryOperation = (op: IOSArchiveOperation): op is IOSRecoveryOperation => op.context.operation === 'ios-local-recovery';
export const iosArchiveRoles = (ctx: IOSArchiveBuildContext) => ctx.operation === 'ios-signed-export' ? IOS_SIGNED_ARCHIVE_ROLES : IOS_ARCHIVE_ROLES;
export const iosArchiveStages = (ctx: IOSArchiveContext): readonly IOSArchiveStage[] =>
  ctx.operation === 'ios-local-recovery' ? IOS_RECOVERY_STAGES : ctx.operation === 'ios-signed-export' ? IOS_SIGNED_ARCHIVE_STAGES : IOS_ARCHIVE_STAGES;
export const IOS_ARCHIVE_LIMITATIONS: readonly IOSArchiveLimitation[] = Object.freeze([
  'saved-inputs-not-atomic', 'project-build-code-is-trusted', 'not-network-isolated', 'unsigned-archive-not-an-ipa',
  'signing-and-profile-not-validated', 'ipa-correspondence-not-validated', 'source-provenance-not-authenticated',
  'store-operation-not-requested', 'release-readiness-not-assessed', 'retained-location-not-current-file-authority',
  'core-terminal-requires-original-native-finality',
]);
export const IOS_SIGNED_ARCHIVE_LIMITATIONS: readonly IOSArchiveLimitation[] = Object.freeze([
  'saved-inputs-not-atomic', 'project-build-code-is-trusted', 'not-network-isolated', 'single-primary-profile',
  'source-provenance-not-authenticated', 'store-operation-not-requested', 'release-readiness-not-assessed',
  'retained-location-not-current-file-authority', 'core-terminal-requires-original-native-finality',
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

function signingPolicy(value: unknown): value is IOSSigningPolicy {
  if (!keys(value, ['teamId', 'distributionCertificateSha256', 'assignments']) || typeof value.teamId !== 'string' ||
      value.teamId.length !== 10 || /[^A-Z0-9]/.test(value.teamId) || !sha(value.distributionCertificateSha256) ||
      !Array.isArray(value.assignments) || value.assignments.length < 2 || value.assignments.length > 4) return false;
  const rows = value.assignments as unknown[];
  if (!rows.every((row) => keys(row, ['kind', 'recordId', 'recordRevision', 'contextRevision']) &&
      oneOf(row.kind, ['apple-p12', 'apple-profile', 'ios-firebase', 'project-read-token']) && token(row.recordId) &&
      integer(row.recordRevision, IOS_ARCHIVE_COUNTER_MAX, 1) && integer(row.contextRevision, IOS_ARCHIVE_COUNTER_MAX, 1))) return false;
  const assignments = rows as IOSSigningPolicy['assignments'], kinds = assignments.map((row) => row.kind).join(',');
  return ['apple-p12,apple-profile', 'apple-p12,apple-profile,ios-firebase', 'apple-p12,apple-profile,project-read-token',
    'apple-p12,apple-profile,ios-firebase,project-read-token'].includes(kinds) &&
    new Set(assignments.map((row) => row.recordId)).size === assignments.length &&
    assignments.every((row) => row.contextRevision === assignments[0]!.contextRevision);
}
export function parseIOSSigningPolicy(value: unknown): IOSSigningPolicy | null {
  try { const safe = copyData(value, IOS_ARCHIVE_IPC_LIMIT, 64); return signingPolicy(safe) ? safe : null; } catch { return null; }
}
function recoveryIntent(value: unknown): value is IOSRecoveryIntent {
  return keys(value, ['action']) && value.action === 'inspect' || keys(value, ['action', 'session']) &&
    oneOf(value.action, ['account', 'project']) && token(value.session);
}
export function parseIOSRecoveryIntent(value: unknown): IOSRecoveryIntent | null {
  try { const safe = copyData(value, 256, 8); return recoveryIntent(safe) ? safe : null; } catch { return null; }
}
function prepare(value: unknown): value is PrepareIOSArchive {
  if (record(value) && Object.hasOwn(value, 'recovery')) return keys(value, ['projectId', 'recovery']) &&
    projectId(value.projectId) && recoveryIntent(value.recovery);
  const signed = record(value) && Object.hasOwn(value, 'signing');
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', ...(signed ? ['signing'] : [])]) && projectId(value.projectId) &&
    iosArchiveCounter(value.draftRevision) && iosArchiveCounter(value.baselineGeneration) && content(value.savedConfig) && savedVersion(value.savedVersion) &&
    (!signed || signingPolicy(value.signing));
}
function identity(value: unknown): value is IOSArchiveIdentity {
  return record(value) && token(value.operationId) && token(value.ownerGeneration);
}
function context(value: unknown): value is IOSArchiveContext {
  if (record(value) && Object.hasOwn(value, 'recovery')) return keys(value, ['projectId', 'recovery', 'platform', 'operation']) &&
    projectId(value.projectId) && recoveryIntent(value.recovery) && value.platform === 'ios' && value.operation === 'ios-local-recovery';
  const signed = record(value) && Object.hasOwn(value, 'signing');
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'savedVersion', 'platform', 'operation', ...(signed ? ['signing'] : [])]) &&
    value.platform === 'ios' && value.operation === (signed ? 'ios-signed-export' : 'ios-unsigned-archive') && prepare({ projectId: value.projectId,
      draftRevision: value.draftRevision, baselineGeneration: value.baselineGeneration, savedConfig: value.savedConfig, savedVersion: value.savedVersion,
      ...(signed ? { signing: value.signing } : {}) });
}
export function copyIOSArchiveRequest(command: IOSArchiveCommand, value: unknown): PrepareIOSArchive | StartIOSArchive | IOSArchiveIdentity | Record<string, never> | null {
  try {
    // Four signed assignment bindings need 69 key/value nodes. Keep collection
    // bounded before the exact mode-specific shape check; unsigned stays closed.
    const safe = copyData(value, IOS_ARCHIVE_IPC_LIMIT, 96);
    if (command === 'prepare_ios_archive' && prepare(safe)) return safe;
    if (command === 'start_ios_archive' && record(safe)) {
      const confirmation = Object.hasOwn(safe, 'confirmation');
      if (keys(safe, ['operationId', 'ownerGeneration', 'consentVersion', ...(confirmation ? ['confirmation'] : [])]) && identity(safe) &&
          oneOf(safe.consentVersion, [IOS_ARCHIVE_CONSENT, IOS_SIGNED_ARCHIVE_CONSENT, IOS_RECOVERY_CONSENT]) &&
          (!confirmation || safe.consentVersion === IOS_RECOVERY_CONSENT && oneOf(safe.confirmation, [IOS_ACCOUNT_RECOVERY_CONFIRMATION, IOS_PROJECT_RECOVERY_CONFIRMATION])))
        return safe as unknown as StartIOSArchive;
    }
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
const exitedZero = (value: IOSArchiveCommandObservation | undefined): boolean => value?.outcome === 'exited' && value.exitCode === 0;
function activity(value: unknown, ctx: IOSArchiveBuildContext): value is IOSArchiveActivity {
  const signed = ctx.operation === 'ios-signed-export', stages = iosArchiveStages(ctx), roles = iosArchiveRoles(ctx);
  if (!keys(value, ['stage', 'selection', 'commands', 'findings']) || !oneOf(value.stage, stages) ||
      !(value.selection === null || selection(value.selection)) || value.stage !== 'accepted' && value.selection === null ||
      !keys(value.commands, roles) ||
      !Array.isArray(value.findings) || value.findings.length > 16) return false;
  const commands = value.commands;
  if (!roles.every((role) => commandObservation(commands[role]))) return false;
  const observed = value as unknown as IOSArchiveActivity;
  return roles.filter((role) => role !== 'prepare').every((role) => observed.commands[role]?.outcome !== 'not-configured') &&
    observed.findings.every((row) => keys(row, ['check', 'status']) && oneOf(row.check, signed ? IOS_SIGNED_ARCHIVE_CHECK_IDS : IOS_ARCHIVE_CHECK_IDS) && oneOf(row.status, IOS_ARCHIVE_CORE_STATUSES)) &&
    ((signed || observed.findings.length === 0) && stages.indexOf(observed.stage) < stages.indexOf('inspecting') ||
      exitedZero(observed.commands.archive) && (!signed || exitedZero(observed.commands.export)));
}
function completedActivity(value: IOSArchiveActivity, ctx: IOSArchiveBuildContext): boolean {
  const selected = value.selection, commands = value.commands, findings = value.findings;
  if (selected === null || value.stage !== 'disposing-work' || !exitedZero(commands['xcode-version']) || !exitedZero(commands['ios-sdk']) ||
      !exitedZero(commands.archive) || !(selected.preparationConfigured ? exitedZero(commands.prepare) : commands.prepare.outcome === 'not-configured')) return false;
  if (ctx.operation === 'ios-signed-export') {
    const expected = ['signing-material', 'profile-material', 'artifact-correspondence', 'ipa-structure', 'ipa-profile', 'ipa-entitlements', 'ipa-signer'];
    if (ctx.signing?.assignments.some((row) => row.kind === 'ios-firebase')) expected.push('firebase-material');
    return selected.symbolsPolicy !== 'required' && exitedZero(commands.export) && findings.length === expected.length &&
      expected.every((check) => findings.some((row) => row.check === check && row.status === 'PASS'));
  }
  return findings.length === 2 && findings[0]?.check === 'archive-identity' && findings[0].status === 'PASS' && findings[1]?.check === 'archive-dsym' &&
    (findings[1].status === 'PASS' || selected.symbolsPolicy === 'disabled' && findings[1].status === 'NOT_APPLICABLE');
}
function result(value: unknown, ctx: IOSArchiveBuildContext, operationId: string): value is IOSArchiveResult {
  const signed = ctx.operation === 'ios-signed-export';
  if (!keys(value, ['schemaVersion', 'scope', 'usedConfig', 'usedVersion', 'archive', 'entries', 'bytes', 'limitations', ...(signed ? ['ipa', 'ipaBytes', 'pairing'] : [])]) ||
      value.schemaVersion !== 1 || value.scope !== (signed ? IOS_SIGNED_ARCHIVE_SCOPE : IOS_ARCHIVE_SCOPE) || !content(value.usedConfig) || !savedVersion(value.usedVersion) ||
      !sameIOSArchiveSavedPair(ctx, { savedConfig: value.usedConfig, savedVersion: value.usedVersion }) ||
      value.archive !== `.mobile-release/desktop-ios-archive/${operationId}/archive.xcarchive` ||
      !integer(value.entries, 100_000, 1) || !integer(value.bytes, 8 * 1024 ** 3, 1) || !Array.isArray(value.limitations)) return false;
  const limits = value.limitations, expected = signed ? IOS_SIGNED_ARCHIVE_LIMITATIONS : IOS_ARCHIVE_LIMITATIONS;
  if (limits.length !== expected.length || !expected.every((key, index) => limits[index] === key)) return false;
  if (!signed) return true;
  const prefix = `.mobile-release/desktop-ios-archive/${operationId}/export/`;
  if (typeof value.ipa !== 'string' || !value.ipa.startsWith(prefix) || !value.ipa.endsWith('.ipa') ||
      !integer(value.ipaBytes, 4 * 1024 ** 3, 1)) return false;
  const name = value.ipa.slice(prefix.length), pair = value.pairing;
  return encoder.encode(name).byteLength >= 1 && encoder.encode(name).byteLength <= 255 && !/[\u0000-\u001f\u007f/\\:]/u.test(name) &&
    keys(pair, ['nativePaths', 'nativeIdentities', 'presentSymbolSlices']) && integer(pair.nativePaths, 100_000, 1) &&
    integer(pair.nativeIdentities, 100_000, 1) && integer(pair.presentSymbolSlices, 100_000);
}
function disposition(value: unknown, operationId: string): value is IOSArchiveDisposition {
  return keys(value, ['snapshot', 'work', 'output', 'relativeDirectory']) && oneOf(value.snapshot, ['not-created', 'removed', 'unknown']) &&
    oneOf(value.work, ['not-created', 'removed', 'retained-work', 'unknown']) &&
    oneOf(value.output, ['not-created', 'retained-local-result', 'retained-incomplete', 'unknown']) &&
    (value.output === 'not-created' ? value.relativeDirectory === null : value.relativeDirectory === `.mobile-release/desktop-ios-archive/${operationId}`);
}
function recoveryRow(value: unknown, account: boolean): value is IOSRecoveryRow {
  if (!keys(value, ['status', 'session', 'next']) || !oneOf(value.status, ['idle', 'pending', 'busy', 'conflict', 'manual-required', 'recovered', 'absent',
    ...(account ? ['recovered-with-conflict'] : ['cleanup-only', 'not-inspected'])]) || !(value.session === null || token(value.session))) return false;
  const state = value.status;
  if (['pending', 'cleanup-only', 'manual-required', 'recovered', 'recovered-with-conflict', 'absent'].includes(state) && value.session === null ||
      ['idle', 'not-inspected'].includes(state) && value.session !== null) return false;
  const expected = ['idle', 'recovered', 'absent'].includes(state) ? ['none'] : state === 'busy' ? ['wait'] : state === 'manual-required' ? ['manual'] :
    state === 'pending' ? ['ordinary', 'manual'] : state === 'cleanup-only' ? ['ordinary'] : ['preserve'];
  return oneOf(value.next, expected);
}
function recoveryReport(value: unknown, ctx: IOSRecoveryContext): value is IOSRecoveryReport {
  if (!keys(value, ['schemaVersion', 'scope', 'account', 'project', 'limitations']) || value.schemaVersion !== 1 || value.scope !== 'local-ios-recovery' ||
      !Array.isArray(value.limitations) || value.limitations.length !== IOS_RECOVERY_LIMITATIONS.length) return false;
  const limitations = value.limitations;
  if (!IOS_RECOVERY_LIMITATIONS.every((limitation, index) => limitations[index] === limitation)) return false;
  for (const name of ['account', 'project'] as const) {
    const needed = ctx.recovery.action === 'inspect' || ctx.recovery.action === name, row = value[name];
    if (needed !== (row !== null)) return false;
    if (needed) {
      if (!recoveryRow(row, name === 'account')) return false;
      if (ctx.recovery.action === 'inspect' ? ['recovered', 'recovered-with-conflict', 'absent'].includes(row.status) :
        row.session !== ctx.recovery.session || !['recovered', 'recovered-with-conflict', 'absent', 'busy', 'conflict', 'manual-required'].includes(row.status)) return false;
    }
  }
  return true;
}
function recoveryOperation(value: Record<string, unknown>, ctx: IOSRecoveryContext): value is Record<string, unknown> & IOSRecoveryOperation {
  if (!keys(value, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'stage', 'activity', 'report']) ||
      !(value.activity === null || keys(value.activity, ['stage']) && oneOf(value.activity.stage, IOS_RECOVERY_STAGES)) ||
      !(value.report === null || recoveryReport(value.report, ctx))) return false;
  const op = value as unknown as IOSRecoveryOperation;
  if (op.activity !== null && op.stage !== op.activity.stage || op.report !== null && op.activity === null) return false;
  const empty = op.activity === null && op.report === null;
  if (op.phase === 'awaiting-consent') return op.outcome === null && op.reason === 'none' && op.stage === null && empty;
  if (op.intentUsable) return false;
  if (op.phase === 'unknown') return op.outcome === 'unknown' && op.reason === 'cleanup-unknown' && empty;
  if (op.phase !== 'terminal') return op.outcome === null && empty && (op.phase !== 'starting' || op.stage === null);
  if (op.outcome === null || op.outcome === 'unknown' || op.reason === 'cleanup-unknown' || (op.reason === 'none') !== (op.outcome === 'complete')) return false;
  if (op.outcome === 'complete') return op.stage === 'disposing-work' && op.activity !== null && op.report !== null;
  return !(op.outcome === 'cancelled' && !['cancelled', 'context-changed', 'document-lost', 'shutdown'].includes(op.reason) ||
    op.outcome === 'timed-out' && op.reason !== 'timed-out');
}
function operation(value: unknown): value is IOSArchiveOperation {
  if (!record(value) || !identity(value) || !context(value.context) || !oneOf(value.phase, phases) || typeof value.intentUsable !== 'boolean' ||
      !(value.outcome === null || oneOf(value.outcome, outcomes)) || !oneOf(value.reason, Object.keys(iosArchiveReasonText)) ||
      !(value.stage === null || oneOf(value.stage, iosArchiveStages(value.context)))) return false;
  if (value.context.operation === 'ios-local-recovery') return recoveryOperation(value, value.context);
  if (!keys(value, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'stage', 'activity', 'disposition', 'result']) ||
      !(value.activity === null || activity(value.activity, value.context)) ||
      !(value.disposition === null || disposition(value.disposition, value.operationId)) ||
      !(value.result === null || result(value.result, value.context, value.operationId))) return false;
  const op = value as unknown as IOSArchiveBuildOperation;
  if ((op.activity === null) !== (op.disposition === null) || op.activity !== null && op.stage !== op.activity.stage) return false;
  const empty = op.activity === null && op.disposition === null && op.result === null;
  if (op.phase === 'awaiting-consent') return op.outcome === null && op.reason === 'none' && op.stage === null && empty;
  if (op.intentUsable) return false;
  if (op.phase === 'unknown') return op.outcome === 'unknown' && op.reason === 'cleanup-unknown' && empty;
  if (op.phase !== 'terminal') return op.outcome === null && empty && (op.phase !== 'starting' || op.stage === null);
  if (op.outcome === null || op.outcome === 'unknown' || op.reason === 'cleanup-unknown' || (op.reason === 'none') !== (op.outcome === 'complete')) return false;
  if (op.outcome === 'complete') return op.stage === 'disposing-work' && op.activity !== null && completedActivity(op.activity, op.context) &&
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
  const stageIndex = (stage: IOSArchiveStage | null) => stage === null ? -1 : iosArchiveStages(a.context).indexOf(stage);
  return phases.indexOf(b.phase) >= phases.indexOf(a.phase) && stageIndex(b.stage) >= stageIndex(a.stage);
}

export const iosArchiveAvailabilityText: Record<IOSArchiveAvailability, string> = {
  available: 'The native iOS owner is available. Each selected mode still needs its own admission, saved inputs and explicit one-use consent.',
  busy: 'An original operation owns the native slot. Keep its Status and Cancel until original cleanup settles.',
  shutdown: 'The application is stopping its original operations. No new archive can start.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep this owner; conflicting work and normal exit remain blocked.',
  'document-lost': 'The original native document is no longer available. A replacement view cannot adopt or reset its owner.',
  'unsupported-platform': 'This archive action requires the separately supported Apple-silicon macOS profile. Linux and Windows cannot archive an iOS app.',
  'runtime-unqualified': 'This iOS mode remains disabled by its native qualification gate. This does not mean Xcode is missing; unsigned, format-only or passive checks do not qualify signed execution.',
  'toolchain-unqualified': 'The protected full-Xcode selection has not been qualified. This action does not install Xcode, download an SDK or accept a license.',
};
const configGuidance = 'Correct and save the configuration, then refresh its saved comparison after original cleanup settles. Unsaved drafts are not used.';
const versionGuidance = 'Correct the version file selected by the saved configuration, then refresh both saved comparisons after original cleanup settles.';
export const iosArchiveReasonText: Record<IOSArchiveReason, string> = {
  none: 'The operation completed within its stated local scope. Review the unsigned or signed result and its limits below; completion does not authorize publication.',
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
  'signing-policy-required': 'Save the Apple Team ID and the reviewed Apple Distribution certificate SHA-256 fingerprint before reviewing signed export.',
  'signing-input-missing': 'Assign the P12/password and App Store provisioning profile in this project’s credential session. Keep any required Firebase or project-read input assigned too.',
  'signing-input-invalid': 'The original signing assignment or captured input did not satisfy the saved request. Review the current session; record labels and format checks are not signing authority.',
  'signing-validation-failed': 'Core signing validation did not pass. Check the P12 password, matching distribution identity, Apple-issued profile and validity dates using the original local details. Container format alone proves none of these.',
  'account-admission-refused': 'The original account signing state could not be admitted. Inspect its recovery status after all original operations settle; do not reset keychains or remove unrelated profiles.',
  'artifact-validation-failed': 'The exported IPA and retained archive did not pass the required identity, signer, profile, entitlements or native/symbol correspondence checks. Retained output is incomplete, not release-ready.',
  'symbols-upload-not-requested': 'The saved symbols policy requires an upload. This local operation never runs an uploader and cannot satisfy that release obligation; inspect the BLOCKED finding.',
  'recovery-attention': 'Recovery found busy, conflicting or manual-recheck state. Read the exact account/project status. Do not remove state, retry signing or treat confirmation as original worker finality.',
};
export const iosArchiveFindingText: Record<IOSArchiveCheckId, string> = {
  'archive-identity': 'Archive bundle identity and saved version/build.', 'archive-dsym': 'Archive symbols under the saved symbols policy.',
  'archive-structure': 'Archive structural inspection.', 'other-core-finding': 'Other core finding; its exact status is preserved.',
  'signing-material': 'Original P12/password and saved distribution-certificate policy validated by core.',
  'profile-material': 'Original provisioning profile and saved app/team policy validated by core.',
  'firebase-material': 'Assigned iOS Firebase material matches the saved application.',
  'artifact-correspondence': 'Exported IPA, retained archive and present native/symbol slices correspond.',
  'ipa-structure': 'Exported IPA structure and application identity.',
  'ipa-profile': 'Exported application provisioning-profile policy.',
  'ipa-entitlements': 'Exported application entitlement policy.',
  'ipa-signer': 'Exported application signer policy.',
  'ipa-validation': 'Additional IPA validation finding; its exact status is preserved.',
  'symbols-upload': 'Required symbols-upload obligation; no uploader is run by this local operation.',
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
  'single-primary-profile': 'This signed export supports one primary App Store provisioning profile. Extension/profile mismatches are not guessed or rewritten.',
};
const errors: Record<string, string> = {
  ios_archive_invalid: 'The iOS archive request was not valid closed DATA. Nothing was authorized by this response.',
  ios_archive_unavailable: 'The separate native iOS archive capability is unavailable. No browser or ambient-runtime fallback is used.',
  ios_archive_busy: 'Another original operation owns the native slot. Keep its Status and Cancel accessible.',
  ios_archive_owner: 'This intent is foreign, stale or consumed. No Start can be replayed or rearmed.',
  ios_archive_protocol: 'A usable original iOS archive response was not received. Check retained Status; do not repeat Start.',
  ios_archive_signing_inputs: 'Current original P12/password/profile assignments could not be borrowed for these saved inputs. Recheck the iOS candidate signing context after original work settles; displayed record IDs are not material authority.',
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
