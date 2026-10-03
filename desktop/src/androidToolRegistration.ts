// Closed app DATA, never source-path, helper-transaction or native authority.
// This is not a decoder for the helper's PRE-G terminal. The original Saved
// owner alone can publish a usable Review or a final registration report.
import type { ApiError } from './types.ts';
import type { AndroidBuildAvailability, PrepareAndroidBuild } from './androidBuildTypes.ts';
import type { AndroidToolSourceRole } from './androidToolSources.ts';
import { androidBuildCounter, copyAndroidBuildRequest, sameAndroidBuildData } from './androidBuildProtocol.ts';

export const ANDROID_TOOL_REGISTRATION_EVENT = 'android-tool-registration-state-changed';
export const ANDROID_TOOL_REGISTRATION_CONSENT = 'android-tool-protected-copy-v1';
export const ANDROID_TOOL_REGISTRATION_REQUEST_LIMIT = 8192;
export const ANDROID_TOOL_REGISTRATION_STATUS_LIMIT = 65536;
export type AndroidToolRegistrationPrerequisite = 'ready' | 'supplier-unavailable' | 'signing-unavailable' |
  'approval-required' | 'approval-denied' | 'service-unavailable' | 'fresh-service-unavailable';
export type AndroidToolRegistrationKind = 'inspection' | 'registration';
export type AndroidToolRegistrationPhase = 'idle' | 'inspecting' | 'review' | 'copying' | 'verifying' | 'publishing' |
  'settling' | 'stopping' | 'complete' | 'refused' | 'cancelled' | 'unknown';
export type AndroidToolRegistrationReason = 'none' | 'not-inspected' | 'cancelled' | 'context-changed' | 'source-changed' |
  'source-refused' | 'version-mismatch' | 'layout-refused' | 'supplier-unavailable' | 'signing-unavailable' |
  'approval-required' | 'approval-denied' | 'service-unavailable' | 'fresh-service-unavailable' | 'review-expired' |
  'stale-review' | 'timed-out' | 'document-lost' | 'shutdown' | 'busy' | 'input-limit' | 'result-limit' |
  'protocol-error' | 'registration-refused' | 'cleanup-unknown';
export interface AndroidToolRegistrationIdentity { operationId: string; registrationGeneration: number }
export interface AndroidToolRegistrationOperation extends AndroidToolRegistrationIdentity {
  sourceGeneration: number; kind: AndroidToolRegistrationKind; context: PrepareAndroidBuild;
}
// These are the three picked-role subtotals, not the private whole-copy census.
// Fixed app-owned bundletool/AAPT2 originals also consume the native limits.
export interface AndroidToolRegistrationSource {
  role: AndroidToolSourceRole; version: string | null; logicalBytes: number;
  files: number; entries: number; aliases: number; complete: boolean; compatibility: 'compatible' | 'refused' | 'unavailable';
}
export interface AndroidToolRegistrationReview {
  reviewId: string; sourceGeneration: number; context: PrepareAndroidBuild;
  consentVersion: typeof ANDROID_TOOL_REGISTRATION_CONSENT; licenseAcknowledgmentRequired: true;
  sources: AndroidToolRegistrationSource[];
}
// Preserve the entire unsigned64 accounting range as canonical decimal DATA;
// never round these observations through a JavaScript Number.
export interface AndroidToolRegistrationAccounting {
  writtenBytes: string; observedLogicalBytes: string; observedAllocatedBytes: string;
  complete: boolean; contentFiles: number; contentAliases: number;
}
export type AndroidToolRegistrationProblem = 'binding' | 'bounds' | 'supplier-unavailable' | 'inventory' | 'ownership' |
  'collision' | 'native' | 'stopped' | 'unknown' | 'transfer' | 'persist' | 'admission' | 'unavailable';
export interface AndroidToolRegistrationProblems {
  recorded: number; shown: number; omitted: number; first: AndroidToolRegistrationProblem | null;
  items: AndroidToolRegistrationProblem[];
}
export interface AndroidToolRegistrationReport {
  sources: AndroidToolRegistrationSource[]; protectedCopy: 'not-created' | 'published' | 'retained-partial';
  accounting: AndroidToolRegistrationAccounting | null; problems: AndroidToolRegistrationProblems;
}
export interface AndroidToolRegistrationStatus {
  schemaVersion: 1; statusRevision: number; registrationGeneration: number;
  availability: AndroidBuildAvailability; prerequisite: AndroidToolRegistrationPrerequisite;
  phase: AndroidToolRegistrationPhase; reason: AndroidToolRegistrationReason;
  operation: AndroidToolRegistrationOperation | null; review: AndroidToolRegistrationReview | null;
  report: AndroidToolRegistrationReport | null;
}
export interface InspectAndroidToolSources {
  schemaVersion: 1; registrationGeneration: number; sourceGeneration: number; context: PrepareAndroidBuild;
}
export interface RegisterAndroidToolSources extends InspectAndroidToolSources {
  reviewId: string; consentVersion: typeof ANDROID_TOOL_REGISTRATION_CONSENT; licenseAcknowledged: true;
}
export interface CancelAndroidToolRegistration extends AndroidToolRegistrationIdentity { schemaVersion: 1 }
export interface AndroidToolRegistrationApi {
  // The entire surface is optional for older/unsupported adapters. Partial
  // adapters never enable registration; absence is not an alternate protocol.
  androidToolRegistrationStatus?(): Promise<AndroidToolRegistrationStatus>;
  inspectAndroidToolSources?(request: InspectAndroidToolSources): Promise<AndroidToolRegistrationStatus>;
  registerAndroidToolSources?(request: RegisterAndroidToolSources): Promise<AndroidToolRegistrationStatus>;
  cancelAndroidToolRegistration?(request: CancelAndroidToolRegistration): Promise<AndroidToolRegistrationStatus>;
  subscribeAndroidToolRegistration?(onStatus: (status: unknown) => void): Promise<() => void>;
}
export type AndroidToolRegistrationCommand = 'android_tool_registration_status' | 'inspect_android_tool_sources' |
  'register_android_tool_sources' | 'cancel_android_tool_registration';
type Request = { schemaVersion: 1 } | InspectAndroidToolSources | RegisterAndroidToolSources | CancelAndroidToolRegistration;
const encoder = new TextEncoder();
const roles = ['jdk', 'sdk', 'gradle'] as const;
const availability = ['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified', 'toolchain-unqualified'] as const;
const prerequisites = ['ready', 'supplier-unavailable', 'signing-unavailable', 'approval-required', 'approval-denied', 'service-unavailable', 'fresh-service-unavailable'] as const;
const phases = ['idle', 'inspecting', 'review', 'copying', 'verifying', 'publishing', 'settling', 'stopping', 'complete', 'refused', 'cancelled', 'unknown'] as const;
const reasons = ['none', 'not-inspected', 'cancelled', 'context-changed', 'source-changed', 'source-refused', 'version-mismatch', 'layout-refused',
  'supplier-unavailable', 'signing-unavailable', 'approval-required', 'approval-denied', 'service-unavailable', 'fresh-service-unavailable',
  'review-expired', 'stale-review', 'timed-out', 'document-lost', 'shutdown', 'busy', 'input-limit', 'result-limit', 'protocol-error',
  'registration-refused', 'cleanup-unknown'] as const;
const problems = ['binding', 'bounds', 'supplier-unavailable', 'inventory', 'ownership', 'collision', 'native', 'stopped', 'unknown',
  'transfer', 'persist', 'admission', 'unavailable'] as const;
const oneOf = <T extends string>(value: unknown, values: readonly T[]): value is T =>
  typeof value === 'string' && values.includes(value as T);
const integer = (value: unknown, maximum: number, minimum = 0): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && !Object.is(value, -0) && value >= minimum && value <= maximum;
const counter = (value: unknown, positive = false): value is number => androidBuildCounter(value) && (!positive || value > 0);
const token = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const decimal = (value: unknown): value is string => typeof value === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(value)
  && (value.length < 20 || value <= '18446744073709551615');

// Copy descriptor DATA, not a live object subsequently read through getters.
// Exact names reject symbols, inherited authority, toJSON and extra fields.
function record(value: unknown, names: readonly string[]): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const actual = Reflect.ownKeys(value);
  if (actual.length !== names.length || !actual.every((key) => typeof key === 'string' && names.includes(key))) return null;
  const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const name of names) {
    const field = Object.getOwnPropertyDescriptor(value, name);
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) return null;
    output[name] = field.value;
  }
  return output;
}
function array(value: unknown, maximum: number): unknown[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return null;
  const length = Object.getOwnPropertyDescriptor(value, 'length');
  if (!length || !Object.hasOwn(length, 'value') || !integer(length.value, maximum)
      || Reflect.ownKeys(value).length !== length.value + 1) return null;
  const output: unknown[] = [];
  for (let i = 0; i < length.value; i++) {
    const slot = Object.getOwnPropertyDescriptor(value, String(i));
    if (!slot?.enumerable || !Object.hasOwn(slot, 'value')) return null;
    output.push(slot.value);
  }
  return output;
}
function context(value: unknown): PrepareAndroidBuild | null {
  // Reuse the existing bounded saved-config/version/signature contract exactly.
  const safe = copyAndroidBuildRequest('prepare_android_build', value);
  return safe === null ? null : safe as PrepareAndroidBuild;
}
function sourceData(value: unknown, review: boolean): AndroidToolRegistrationSource[] | null {
  const rows = array(value, 3);
  if (!rows || review && rows.length !== 3) return null;
  const output: AndroidToolRegistrationSource[] = [];
  let previous = -1, bytes = 0, files = 0, entries = 0, aliases = 0;
  for (const row of rows) {
    const source = record(row, ['role', 'version', 'logicalBytes', 'files', 'entries', 'aliases', 'complete', 'compatibility']);
    if (!source || !oneOf(source.role, roles) || !(source.version === null || typeof source.version === 'string'
        && /^[0-9A-Za-z.+_-]{1,64}$/.test(source.version)) || !integer(source.logicalBytes, 1_073_741_824)
        || !integer(source.files, 16384) || !integer(source.entries, 32768) || !integer(source.aliases, 128)
        || source.files + source.aliases > source.entries || typeof source.complete !== 'boolean'
        || !oneOf(source.compatibility, ['compatible', 'refused', 'unavailable'] as const)) return null;
    const index = roles.indexOf(source.role);
    if (index <= previous || review && (!source.complete || source.compatibility !== 'compatible' || source.version === null || source.files === 0)) return null;
    previous = index;
    bytes += source.logicalBytes; files += source.files; entries += source.entries; aliases += source.aliases;
    if (bytes > 1_073_741_824 || files > 16384 || entries > 32768 || aliases > 128) return null;
    output.push({ role: source.role, version: source.version, logicalBytes: source.logicalBytes, files: source.files,
      entries: source.entries, aliases: source.aliases, complete: source.complete, compatibility: source.compatibility });
  }
  return output;
}
function accounting(value: unknown): AndroidToolRegistrationAccounting | null {
  const data = record(value, ['writtenBytes', 'observedLogicalBytes', 'observedAllocatedBytes', 'complete', 'contentFiles', 'contentAliases']);
  if (!data || !decimal(data.writtenBytes) || !decimal(data.observedLogicalBytes) || !decimal(data.observedAllocatedBytes)
      || typeof data.complete !== 'boolean' || !integer(data.contentFiles, 16384) || !integer(data.contentAliases, 16384)) return null;
  return { writtenBytes: data.writtenBytes, observedLogicalBytes: data.observedLogicalBytes, observedAllocatedBytes: data.observedAllocatedBytes,
    complete: data.complete, contentFiles: data.contentFiles, contentAliases: data.contentAliases };
}
function problemData(value: unknown): AndroidToolRegistrationProblems | null {
  const data = record(value, ['recorded', 'shown', 'omitted', 'first', 'items']);
  if (!data || !integer(data.recorded, 64) || !integer(data.shown, 20) || data.shown !== Math.min(data.recorded, 20)
      || !integer(data.omitted, 64) || data.omitted !== data.recorded - data.shown) return null;
  const items = array(data.items, 20);
  if (!items || items.length !== data.shown || !items.every((item) => oneOf(item, problems))
      || data.first !== (items[0] ?? null)) return null;
  return { recorded: data.recorded, shown: data.shown, omitted: data.omitted,
    first: data.first as AndroidToolRegistrationProblem | null, items: items as AndroidToolRegistrationProblem[] };
}
function reportData(value: unknown, kind: AndroidToolRegistrationKind): AndroidToolRegistrationReport | null {
  const data = record(value, ['sources', 'protectedCopy', 'accounting', 'problems']);
  if (!data || !oneOf(data.protectedCopy, ['not-created', 'published', 'retained-partial'] as const)) return null;
  const sources = sourceData(data.sources, false), errors = problemData(data.problems), counts = data.accounting === null ? null : accounting(data.accounting);
  if (!sources || !errors || data.accounting !== null && counts === null
      || kind === 'inspection' && (data.protectedCopy !== 'not-created' || data.accounting !== null)) return null;
  return { sources, protectedCopy: data.protectedCopy, accounting: counts, problems: errors };
}
function operationData(value: unknown, generation: number): AndroidToolRegistrationOperation | null {
  const data = record(value, ['operationId', 'registrationGeneration', 'sourceGeneration', 'kind', 'context']);
  if (!data || !token(data.operationId) || !counter(data.registrationGeneration, true) || data.registrationGeneration !== generation
      || !counter(data.sourceGeneration, true) || !oneOf(data.kind, ['inspection', 'registration'] as const)) return null;
  const saved = context(data.context);
  return saved ? { operationId: data.operationId, registrationGeneration: data.registrationGeneration,
    sourceGeneration: data.sourceGeneration, kind: data.kind, context: saved } : null;
}
function reviewData(value: unknown, original: AndroidToolRegistrationOperation): AndroidToolRegistrationReview | null {
  const data = record(value, ['reviewId', 'sourceGeneration', 'context', 'consentVersion', 'licenseAcknowledgmentRequired', 'sources']);
  if (!data || !token(data.reviewId) || data.sourceGeneration !== original.sourceGeneration
      || data.consentVersion !== ANDROID_TOOL_REGISTRATION_CONSENT || data.licenseAcknowledgmentRequired !== true) return null;
  const saved = context(data.context), sources = sourceData(data.sources, true);
  if (!saved || !sources || !sameAndroidBuildData(saved, original.context)) return null;
  return { reviewId: data.reviewId, sourceGeneration: original.sourceGeneration, context: saved,
    consentVersion: ANDROID_TOOL_REGISTRATION_CONSENT, licenseAcknowledgmentRequired: true, sources };
}
export function parseAndroidToolRegistrationStatus(value: unknown): AndroidToolRegistrationStatus | null {
  try {
    const data = record(value, ['schemaVersion', 'statusRevision', 'registrationGeneration', 'availability', 'prerequisite',
      'phase', 'reason', 'operation', 'review', 'report']);
    if (!data || data.schemaVersion !== 1 || !counter(data.statusRevision) || !counter(data.registrationGeneration)
        || !oneOf(data.availability, availability) || !oneOf(data.prerequisite, prerequisites)
        || !oneOf(data.phase, phases) || !oneOf(data.reason, reasons)
        || data.availability === 'available' && data.prerequisite !== 'ready') return null;
    const original = data.operation === null ? null : operationData(data.operation, data.registrationGeneration);
    let review: AndroidToolRegistrationReview | null = null, report: AndroidToolRegistrationReport | null = null;
    if (data.operation === null) {
      if (data.registrationGeneration !== 0 || data.phase !== 'idle' || data.review !== null || data.report !== null
          || !['not-inspected', 'supplier-unavailable', 'signing-unavailable', 'approval-required', 'approval-denied',
            'service-unavailable', 'fresh-service-unavailable'].includes(data.reason)) return null;
    } else {
      if (!original || data.registrationGeneration === 0 || data.phase === 'idle'
          || original.kind === 'inspection' && ['copying', 'verifying', 'publishing', 'complete'].includes(data.phase)
          || original.kind === 'registration' && ['inspecting', 'review'].includes(data.phase)) return null;
      if (data.phase === 'unknown' && (data.availability !== 'cleanup-unknown' || data.reason !== 'cleanup-unknown')
          || ['inspecting', 'review', 'copying', 'verifying', 'publishing', 'settling', 'complete'].includes(data.phase) && data.reason !== 'none'
          || data.phase === 'cancelled' && data.reason !== 'cancelled'
          || ['stopping', 'refused'].includes(data.phase) && ['none', 'not-inspected'].includes(data.reason)) return null;
      if (data.phase === 'review') {
        if (data.availability !== 'available' || data.prerequisite !== 'ready') return null;
        review = reviewData(data.review, original);
        if (!review) return null;
      } else if (data.review !== null) return null;
      if (data.report !== null) {
        if (!['complete', 'refused', 'cancelled'].includes(data.phase)) return null;
        report = reportData(data.report, original.kind);
        if (!report) return null;
      }
      if (data.phase === 'complete' && (!report || report.protectedCopy !== 'published' || !sourceData(report.sources, true)
          || report.accounting?.complete !== true || report.problems.recorded !== 0)) return null;
    }
    const safe: AndroidToolRegistrationStatus = { schemaVersion: 1, statusRevision: data.statusRevision,
      registrationGeneration: data.registrationGeneration, availability: data.availability, prerequisite: data.prerequisite,
      phase: data.phase, reason: data.reason, operation: original, review, report };
    return encoder.encode(JSON.stringify(safe)).byteLength <= ANDROID_TOOL_REGISTRATION_STATUS_LIMIT ? safe : null;
  } catch { return null; }
}
export function copyAndroidToolRegistrationRequest(command: AndroidToolRegistrationCommand, value: unknown): Request | null {
  try {
    const names = command === 'android_tool_registration_status' ? ['schemaVersion'] : command === 'inspect_android_tool_sources'
      ? ['schemaVersion', 'registrationGeneration', 'sourceGeneration', 'context'] : command === 'register_android_tool_sources'
      ? ['schemaVersion', 'registrationGeneration', 'sourceGeneration', 'reviewId', 'context', 'consentVersion', 'licenseAcknowledged']
      : command === 'cancel_android_tool_registration' ? ['schemaVersion', 'operationId', 'registrationGeneration'] : null;
    if (!names) return null;
    const data = record(value, names);
    if (!data || data.schemaVersion !== 1) return null;
    let safe: Request;
    if (command === 'android_tool_registration_status') { safe = { schemaVersion: 1 }; }
    else if (command === 'cancel_android_tool_registration') {
      if (!token(data.operationId) || !counter(data.registrationGeneration, true)) return null;
      safe = { schemaVersion: 1, operationId: data.operationId, registrationGeneration: data.registrationGeneration };
    } else {
      if (!counter(data.registrationGeneration, command === 'register_android_tool_sources') || !counter(data.sourceGeneration, true)) return null;
      const saved = context(data.context);
      if (!saved) return null;
      const common: InspectAndroidToolSources = { schemaVersion: 1, registrationGeneration: data.registrationGeneration,
        sourceGeneration: data.sourceGeneration, context: saved };
      if (command === 'register_android_tool_sources') {
        if (!token(data.reviewId) || data.consentVersion !== ANDROID_TOOL_REGISTRATION_CONSENT || data.licenseAcknowledged !== true) return null;
        safe = { ...common, reviewId: data.reviewId, consentVersion: ANDROID_TOOL_REGISTRATION_CONSENT, licenseAcknowledged: true };
      } else { safe = common; }
    }
    return encoder.encode(JSON.stringify(safe)).byteLength <= ANDROID_TOOL_REGISTRATION_REQUEST_LIMIT ? safe : null;
  } catch { return null; }
}
export function encodeAndroidToolRegistrationRequest(command: AndroidToolRegistrationCommand, value: unknown): Uint8Array | null {
  const safe = copyAndroidToolRegistrationRequest(command, value);
  return safe === null ? null : encoder.encode(JSON.stringify(safe));
}
// Comparison helpers accept only validated/copy-owned DATA, never native facts.
export function sameAndroidToolRegistrationIdentity(a: AndroidToolRegistrationIdentity | null, b: AndroidToolRegistrationIdentity | null): boolean {
  return a === null || b === null ? a === b : a.operationId === b.operationId && a.registrationGeneration === b.registrationGeneration;
}
export function androidToolRegistrationActive(status: AndroidToolRegistrationStatus | null): boolean {
  return !!status && ['inspecting', 'copying', 'verifying', 'publishing', 'settling', 'stopping', 'unknown'].includes(status.phase);
}
export function hasAndroidToolRegistration(api: AndroidToolRegistrationApi): boolean {
  return typeof api.androidToolRegistrationStatus === 'function' && typeof api.inspectAndroidToolSources === 'function'
    && typeof api.registerAndroidToolSources === 'function' && typeof api.cancelAndroidToolRegistration === 'function'
    && typeof api.subscribeAndroidToolRegistration === 'function';
}
// Native invalid/unavailable errors are reserved for rejection BEFORE original
// admission. Every lost GO/invoke/status reply after admission is unconfirmed;
// it cannot use these codes to erase the original. Owner wiring must preserve
// this distinction, and an already observed original always wins reconciliation.
const registrationErrors: Record<string, string> = {
  android_registration_invalid: 'The closed source-review request was rejected before admission. Nothing was authorized.',
  android_registration_unavailable: 'Source inspection or protected registration was not admitted. Check its prerequisites and original Status.',
  android_registration_unconfirmed: 'The original source inspection or registration reply is unconfirmed. Check its retained Status and Cancel; do not repeat inspection or protected copy.',
};
export function androidToolRegistrationError(error: unknown): ApiError {
  let code = 'android_registration_unconfirmed';
  try {
    const descriptor = error !== null && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
    const value: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
    if (typeof value === 'string' && Object.hasOwn(registrationErrors, value)) code = value;
  } catch { /* No getter, exception message or helper transcript reaches UI. */ }
  return { code, message: registrationErrors[code]!, retryable: false };
}
export const androidToolRegistrationPrerequisiteText: Record<AndroidToolRegistrationPrerequisite, string> = {
  ready: 'Protected-copy prerequisites are currently available. Source inspection and separate explicit license acknowledgment are still required.',
  'supplier-unavailable': 'Registration is unavailable because the complete official supplier correspondence or original app-provided support tools are not available. Local hashes, version text or cache files cannot replace them.',
  'signing-unavailable': 'The required signed service is unavailable. This view does not install a service or run administrator commands.',
  'approval-required': 'The system setup approval is still required before a registration can start. No protected copy is waiting in the background for approval.',
  'approval-denied': 'System setup approval was denied. Registration is unavailable; changing selected folders does not bypass approval.',
  'service-unavailable': 'The genuinely installed protected-copy service is unavailable. There is no shell, browser or unprivileged-copy fallback.',
  'fresh-service-unavailable': 'No fresh approved service context is available for this original operation. Reconnecting or restarting a retired context is not qualification.',
};
export const androidToolRegistrationReasonText: Record<AndroidToolRegistrationReason, string> = {
  none: 'A completed protected copy is not a tool selection or build approval. Use an explicit catalog Refresh and Choose after original settlement.',
  'not-inspected': 'Choose the installed JDK, SDK and Gradle folders, then inspect those exact sources.',
  cancelled: 'Cancel is not rollback. Keep the original Status and any retained-output observation until settlement is confirmed.',
  'context-changed': 'The saved project or input comparison changed. The previous review is no longer usable; inspect again only after original settlement.',
  'source-changed': 'A selected original source changed. No updated contents inherit the old review or consent.',
  'source-refused': 'The selected source could not be safely inspected. Use an ordinary official vendor installation; do not rename or modify files to bypass a refusal.',
  'version-mismatch': 'The selected JDK, SDK platform/build-tools or Gradle version does not match the reviewed project requirements.',
  'layout-refused': 'The selected vendor layout is unsupported or unsafe. Choose the JDK bundle or Contents/Home, SDK root, and extracted Gradle distribution.',
  'supplier-unavailable': androidToolRegistrationPrerequisiteText['supplier-unavailable'],
  'signing-unavailable': androidToolRegistrationPrerequisiteText['signing-unavailable'],
  'approval-required': androidToolRegistrationPrerequisiteText['approval-required'],
  'approval-denied': androidToolRegistrationPrerequisiteText['approval-denied'],
  'service-unavailable': androidToolRegistrationPrerequisiteText['service-unavailable'],
  'fresh-service-unavailable': androidToolRegistrationPrerequisiteText['fresh-service-unavailable'],
  'review-expired': 'The finalized inspection review expired. Source readers are not held open to extend consent; inspect again after original settlement.',
  'stale-review': 'This action does not identify the current finalized source review. Check the original Status rather than repeating registration.',
  'timed-out': 'The original operation deadline was reached. A later status reply cannot renew its cleanup time.',
  'document-lost': 'The original document was lost. A replacement view cannot adopt, reset or replace its operation.',
  shutdown: 'The application is stopping the original operation. A closed view is not proof of native cleanup.',
  busy: 'Another original operation owns the required slot. Keep its Status and Cancel available.',
  'input-limit': 'The selected source exceeds the fixed read/copy limits. No limit or traversal scope is enlarged automatically.',
  'result-limit': 'The bounded result could not be represented safely. Check original Status; private file contents and raw helper output are not a substitute.',
  'protocol-error': 'The original communication failed its closed contract. Keep the original owner and check Status; do not repeat copy.',
  'registration-refused': 'Protected registration was refused. Any observed retained files are not an eligible catalog entry or permission to delete or adopt them.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Retain the same owner; conflicting work and normal exit remain blocked.',
};
