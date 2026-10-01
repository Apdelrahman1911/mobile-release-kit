// Closed transport checks only. Core provider policy and original native authority
// are not reproduced here. Private DTOs must never enter parseRoutineStatus.
import { isU32 } from './configEditProtocol.ts';
import { REQUIRED_NOTE_KINDS, requiredNoteByteLimit, requiredNoteCharacterLimit, sameRequiredNoteContext } from './requiredNotes.ts';
import type { RequiredNoteAssertion, RequiredNoteBaseline, RequiredNoteContext, RequiredNoteKind, RequiredNoteOriginal,
  RequiredNoteSelection, RequiredNoteValidation, RequiredNotesGuide, RequiredNotesImported, RequiredNotesLoaded,
  RequiredNotesPrepared, RequiredNotesPrepareInput, RequiredNotesRoutineStatus } from './requiredNotes.ts';
import type { ApiError } from './types.ts';

const encoder = new TextEncoder();
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost',
  'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state',
  'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
export const REQUIRED_NOTE_ISSUES = {
  'notes.missing': 'This selected note file has not been saved yet.',
  'notes.utf8': 'Use a UTF-8 text file. The selected contents were not decoded or changed.',
  'notes.editor-byte-limit': 'This note exceeds its disclosed local text-editor byte limit. It was not truncated.',
  'notes.android-content': 'Google Play notes need non-whitespace text without NUL characters.',
  'notes.android-length': 'Google Play notes allow 500 Unicode characters, including all whitespace and line endings.',
  'notes.android-policy': 'Google Play notes failed the shared core release-note policy.',
  'notes.apple-empty': 'Apple receives an empty value after its whitespace trimming. Add useful instructions.',
  'notes.testflight-length': 'TestFlight what-to-test allows at most 4000 characters after Apple-bound whitespace trimming.',
  'metadata.empty-text': 'Add non-whitespace instructions instead of an empty note.',
  'metadata.nul': 'Text notes must not contain NUL characters.',
  'metadata.placeholder': 'Replace unresolved placeholders with reviewed release or testing instructions.',
  'metadata.secret-pattern': 'Remove possible credentials from this note. Use the separate credential fields; rotate any exposed credential.',
  'metadata.length': 'The note exceeds the existing core preflight character limit.',
} as const;

function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  return Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null;
}
function keys(value: unknown, names: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const actual = Reflect.ownKeys(value);
  return actual.length === names.length && actual.every((name) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return typeof name === 'string' && names.includes(name) && descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
function list(value: unknown, max: number): value is unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max || Reflect.ownKeys(value).length !== value.length + 1) return false;
  for (let i = 0; i < value.length; i += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}
function text(value: unknown, max: number, empty = true): value is string {
  return typeof value === 'string' && value.length <= max && (empty || value.length > 0) &&
    !/[\ud800-\udfff]/u.test(value) && encoder.encode(value).byteLength <= max;
}
function atom(value: unknown, max: number): value is string { return text(value, max, false) && !/[\u0000-\u001f\u007f]/u.test(value); }
function token(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value); }
function project(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value); }
function one(value: unknown, choices: readonly string[]): boolean { return typeof value === 'string' && choices.includes(value); }
function count(value: unknown, max = 262148): boolean { return value === null || isU32(value) && value <= max; }
function kind(value: unknown): value is RequiredNoteKind { return one(value, REQUIRED_NOTE_KINDS); }
function context(value: unknown): value is RequiredNoteContext {
  if (!(keys(value, ['kind']) || keys(value, ['kind', 'locale'])) || !kind(value.kind)) return false;
  return value.kind === 'android-build' || value.kind === 'android-default' ?
    keys(value, ['kind', 'locale']) && typeof value.locale === 'string' && /^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-[A-Z]{2}|-[0-9]{3})?$/.test(value.locale) && value.locale.length <= 12 :
    keys(value, ['kind']);
}
function path(value: unknown): value is string {
  return atom(value, 512) && value.split('/').length <= 12 && value.split('/').every((part) =>
    !!part && part !== '.' && part !== '..' && !part.startsWith('.') && !/[\\:<>"|?*]/u.test(part) && !/[ .]$/.test(part));
}
function digest(value: unknown, max: number): boolean {
  return keys(value, ['byteLength', 'sha256']) && isU32(value.byteLength) && value.byteLength <= max &&
    typeof value.sha256 === 'string' && /^[0-9a-f]{64}$/.test(value.sha256);
}
function assertion(value: unknown, max: number): value is RequiredNoteAssertion {
  return keys(value, ['state']) && value.state === 'absent' || keys(value, ['state', 'byteLength', 'sha256']) && value.state === 'present' &&
    digest({ byteLength: value.byteLength, sha256: value.sha256 }, max);
}
function baseline(value: unknown, selected: RequiredNoteContext): value is RequiredNoteBaseline {
  if (!keys(value, ['config', 'version', 'note', 'counterpart']) || !digest(value.config, 524288) ||
      !assertion(value.note, requiredNoteByteLimit(selected.kind))) return false;
  return 'locale' in selected ? digest(value.version, 65536) && assertion(value.counterpart, 2000) : value.version === null && value.counterpart === null;
}
function original(value: unknown, expected: RequiredNoteAssertion, selected: RequiredNoteKind): value is RequiredNoteOriginal {
  if (expected.state === 'absent') return keys(value, ['state']) && value.state === 'absent';
  return keys(value, ['state', 'text']) && value.state === 'present' && text(value.text, requiredNoteByteLimit(selected)) &&
    encoder.encode(value.text).byteLength === expected.byteLength;
}
function selection(value: unknown): value is RequiredNoteSelection {
  if (!keys(value, ['context', 'metadataRoot', 'destination', 'savedBuild', 'effective']) || !context(value.context) ||
      !path(value.metadataRoot) || !path(value.destination)) return false;
  const selected = value.context;
  if ('locale' in selected) {
    if (!Number.isInteger(value.savedBuild) || (value.savedBuild as number) < 1 || (value.savedBuild as number) > 2100000000 ||
        !keys(value.effective, ['source', 'valid']) || !one(value.effective.source, ['exact', 'default', 'missing']) ||
        typeof value.effective.valid !== 'boolean' || value.effective.source === 'missing' && value.effective.valid) return false;
    const name = selected.kind === 'android-build' ? String(value.savedBuild) : 'default';
    return value.destination === `${value.metadataRoot}/android/${selected.locale}/changelogs/${name}.txt`;
  }
  const fixed = { 'ios-beta-review': 'review/ios-beta-notes.txt', 'ios-app-review': 'review/ios-notes.txt', 'testflight-what-to-test': 'testflight/what-to-test.txt' };
  return value.savedBuild === null && value.effective === null && value.destination === `${value.metadataRoot}/${fixed[selected.kind]}`;
}
function validation(value: unknown): value is RequiredNoteValidation {
  if (!keys(value, ['schemaVersion', 'kind', 'valid', 'state', 'rawByteCount', 'characterCount', 'characterLimit', 'outboundCharacterCount', 'editorByteLimit', 'issues']) ||
      value.schemaVersion !== 1 || !kind(value.kind) || typeof value.valid !== 'boolean' ||
      value.characterLimit !== requiredNoteCharacterLimit(value.kind) || value.editorByteLimit !== requiredNoteByteLimit(value.kind) ||
      !count(value.rawByteCount) || !count(value.characterCount, 65537) || !count(value.outboundCharacterCount, 65537) || !list(value.issues, 13)) return false;
  const codes = new Set<string>();
  for (const row of value.issues) {
    if (!keys(row, ['code', 'message']) || typeof row.code !== 'string' || !Object.hasOwn(REQUIRED_NOTE_ISSUES, row.code) ||
        codes.has(row.code) || row.message !== REQUIRED_NOTE_ISSUES[row.code as keyof typeof REQUIRED_NOTE_ISSUES]) return false;
    codes.add(row.code);
  }
  if (value.valid && (!isU32(value.rawByteCount) || value.rawByteCount > requiredNoteByteLimit(value.kind) || !isU32(value.characterCount) ||
    (value.kind.startsWith('android-') ? value.outboundCharacterCount !== null : !isU32(value.outboundCharacterCount)))) return false;
  return value.valid === (codes.size === 0) && value.state === (value.valid ? 'format-valid' : 'invalid');
}
function clone<T>(value: unknown): T { return JSON.parse(JSON.stringify(value)) as T; }

export function parseRequiredNoteValidation(value: unknown): RequiredNoteValidation | null {
  try { return validation(value) ? clone<RequiredNoteValidation>(value) : null; } catch { return null; }
}
export function parseRequiredNotesLoaded(value: unknown): RequiredNotesLoaded | null {
  try {
    if (!keys(value, ['schemaVersion', 'type', 'projectId', 'windowGeneration', 'selection', 'baseline', 'original', 'validation']) || value.schemaVersion !== 1 ||
        value.type !== 'required-notes-loaded' || !project(value.projectId) || !token(value.windowGeneration) || !selection(value.selection) ||
        !baseline(value.baseline, value.selection.context) || !original(value.original, value.baseline.note, value.selection.context.kind) ||
        !validation(value.validation) || value.validation.kind !== value.selection.context.kind ||
        value.validation.issues.some((issue) => issue.code === 'metadata.secret-pattern' || issue.code === 'notes.utf8')) return null;
    if (value.original.state === 'absent') {
      if (value.validation.rawByteCount !== null || !value.validation.issues.some((issue) => issue.code === 'notes.missing')) return null;
    } else if (value.baseline.note.state !== 'present' || value.validation.rawByteCount !== value.baseline.note.byteLength) return null;
    return clone<RequiredNotesLoaded>(value);
  } catch { return null; }
}
export function parseRequiredNotesPrepared(value: unknown): RequiredNotesPrepared | null {
  try {
    if (!keys(value, ['schemaVersion', 'type', 'projectId', 'windowGeneration', 'ownerGeneration', 'sessionId', 'revision', 'planToken', 'draftRevision',
      'selection', 'baseline', 'before', 'after', 'action', 'createDirectories', 'validation']) || value.schemaVersion !== 1 || value.type !== 'required-notes-prepared' ||
      !project(value.projectId) || !token(value.windowGeneration) || !token(value.ownerGeneration) || !token(value.sessionId) || !token(value.revision) || !token(value.planToken) ||
      !isU32(value.draftRevision) || !selection(value.selection) || !baseline(value.baseline, value.selection.context) ||
      !original(value.before, value.baseline.note, value.selection.context.kind) || !text(value.after, requiredNoteByteLimit(value.selection.context.kind)) ||
      !validation(value.validation) || !value.validation.valid || value.validation.kind !== value.selection.context.kind ||
      value.validation.rawByteCount !== encoder.encode(value.after).byteLength || !list(value.createDirectories, 11)) return null;
    const expected = value.before.state === 'absent' ? 'create' : value.before.text === value.after ? 'preserve' : 'replace';
    if (value.action !== expected) return null;
    const directorySet = new Set<string>();
    for (const directory of value.createDirectories) {
      if (!path(directory) || !value.selection.destination.startsWith(directory + '/') || directorySet.has(directory)) return null;
      directorySet.add(directory);
    }
    return clone<RequiredNotesPrepared>(value);
  } catch { return null; }
}
export function parseRequiredNotesRoutineStatus(value: unknown): RequiredNotesRoutineStatus | null {
  try {
    if (!keys(value, ['schemaVersion', 'domain', 'projectId', 'windowGeneration', 'ownerGeneration', 'sessionId', 'planToken', 'revision', 'context',
      'draftRevision', 'statusRevision', 'phase', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled']) ||
      value.schemaVersion !== 1 || value.domain !== 'required_notes' || !project(value.projectId) || !token(value.windowGeneration) || !token(value.ownerGeneration) || !token(value.sessionId) ||
      !(value.planToken === null || token(value.planToken)) || !(value.revision === null || token(value.revision)) || !context(value.context) ||
      !isU32(value.draftRevision) || !isU32(value.statusRevision) || !one(value.phase, phases) || typeof value.applySubmitted !== 'boolean' ||
      !one(value.nativeReason, nativeReasons) || !one(value.nativeFinality, ['pending', 'settled', 'unknown']) || typeof value.lateSettled !== 'boolean') return null;
    const core = value.coreOutcome;
    if (core !== null && (!keys(core, ['effect', 'journal', 'resources', 'reason']) || !one(core.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !one(core.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) || !one(core.resources, ['settled', 'unknown']) || !one(core.reason, coreReasons))) return null;
    if ((value.applySubmitted || value.phase === 'reviewing' || value.phase === 'applying') && (value.planToken === null || value.revision === null) ||
      value.phase === 'final' && value.nativeFinality !== 'settled') return null;
    return clone<RequiredNotesRoutineStatus>(value);
  } catch { return null; }
}
export function requiredNotesStatusProgress(a: RequiredNotesRoutineStatus, b: RequiredNotesRoutineStatus): boolean {
  if (a.projectId !== b.projectId || a.windowGeneration !== b.windowGeneration || a.ownerGeneration !== b.ownerGeneration || a.sessionId !== b.sessionId ||
    !sameRequiredNoteContext(a.context, b.context) || a.draftRevision !== b.draftRevision || a.planToken !== null && a.planToken !== b.planToken ||
    a.revision !== null && a.revision !== b.revision || a.applySubmitted && !b.applySubmitted || a.lateSettled && !b.lateSettled ||
    a.nativeFinality === 'settled' && b.nativeFinality !== 'settled' || a.nativeFinality === 'unknown' && b.nativeFinality === 'pending') return false;
  if (b.statusRevision <= a.statusRevision || a.phase === 'final') return JSON.stringify(a) === JSON.stringify(b);
  if (a.phase === 'unknown' && b.phase !== 'unknown' || phases.indexOf(b.phase) < phases.indexOf(a.phase) || a.nativeReason !== 'none' && a.nativeReason !== b.nativeReason) return false;
  const before = a.coreOutcome, after = b.coreOutcome;
  return !before || after !== null && (before.effect === 'unknown' || before.effect === after.effect) &&
    (before.journal === 'unknown' || before.journal === after.journal) && (before.reason === 'none' || before.reason === after.reason) &&
    (before.resources !== 'settled' || after.resources === 'settled');
}
export function parseRequiredNotesImported(value: unknown): RequiredNotesImported | null {
  try {
    if (keys(value, ['schemaVersion', 'type', 'state']) && value.schemaVersion === 1 && value.type === 'required-notes-import' && value.state === 'cancelled') return clone<RequiredNotesImported>(value);
    if (!keys(value, ['schemaVersion', 'type', 'state', 'kind', 'text', 'validation']) || value.schemaVersion !== 1 || value.type !== 'required-notes-import' || value.state !== 'selected' ||
      !kind(value.kind) || !text(value.text, requiredNoteByteLimit(value.kind)) || !validation(value.validation) || value.validation.kind !== value.kind || !value.validation.valid ||
      value.validation.rawByteCount !== encoder.encode(value.text).byteLength) return null;
    return clone<RequiredNotesImported>(value);
  } catch { return null; }
}
export function parseRequiredNotesGuide(value: unknown): RequiredNotesGuide | null {
  try {
    if (!keys(value, ['schemaVersion', 'fields', 'actions']) || value.schemaVersion !== 1 || !list(value.fields, 5) || value.fields.length !== 5 || !list(value.actions, 6) || value.actions.length !== 6) return null;
    const help = ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure'];
    const actions = ['load', 'validate', 'review', 'save', 'import', 'discard'];
    for (const [index, row] of value.fields.entries()) {
      if (!keys(row, [...help, 'id', 'audience']) || row.id !== REQUIRED_NOTE_KINDS[index] || row.requiredness !== 'conditional' ||
        row.audience !== (index < 2 ? 'public-play' : index < 4 ? 'apple-review' : 'testflight-testers') || help.filter((key) => key !== 'requiredness').some((key) => !atom(row[key], 2048))) return null;
    }
    for (const [index, row] of value.actions.entries()) {
      if (!keys(row, [...help, 'id']) || row.id !== actions[index] || row.requiredness !== 'optional' || help.filter((key) => key !== 'requiredness').some((key) => !atom(row[key], 2048))) return null;
    }
    return clone<RequiredNotesGuide>(value);
  } catch { return null; }
}


// Fixed Phase-B native adapter. These are correlation/transport DATA only;
// registry project resolution, original admission and writing stay native/core.
export const REQUIRED_NOTES_EVENT = 'mrk-required-notes-status' as const;
export const REQUIRED_NOTES_IMPORT_EVENT = 'mrk-required-notes-import-status' as const;
export type RequiredNotesCapabilityReason = 'none' | 'unsupported_platform' | 'runtime_unavailable' | 'unqualified' | 'document_unavailable';
export interface RequiredNotesCapability { available: boolean; reason: RequiredNotesCapabilityReason }
export interface RequiredNotesCapabilities {
  schemaVersion: 1;
  windowGeneration: string;
  read: RequiredNotesCapability;
  edit: RequiredNotesCapability;
  import: RequiredNotesCapability;
}
export interface RequiredNotesCorrelation { requestId: number; windowGeneration: string }
export interface RequiredNotesObserveInput { projectId: string; windowGeneration: string; context: RequiredNoteContext }
export interface RequiredNotesImportInput extends RequiredNotesObserveInput { requestId: number }
export interface RequiredNotesNativePrepareInput extends RequiredNotesPrepareInput { requestId: number; windowGeneration: string }
export interface RequiredNotesApplyInput extends RequiredNotesCorrelation { sessionId: string; planToken: string }
export interface RequiredNotesCloseInput extends RequiredNotesCorrelation { sessionId: string }
export interface RequiredNotesRoutineEnvelope { requestId: number; status: RequiredNotesRoutineStatus }
export interface RequiredNotesStatusReply { requestId: number; status: RequiredNotesRoutineStatus | null }
export interface RequiredNotesPreparedReply { requestId: number; prepared: RequiredNotesPrepared }
export interface RequiredNotesImportStatus {
  schemaVersion: 1;
  requestId: number;
  windowGeneration: string;
  projectId: string;
  context: RequiredNoteContext;
  phase: 'pending' | 'settled' | 'unknown';
  outcome: null | 'selected' | 'cancelled' | 'refused';
  reason: 'none' | 'cancelled' | 'invalid_file' | 'changed_file' | 'invalid_text' | 'unavailable' | 'io_error' | 'context_changed' | 'cleanup_unknown';
}
export interface RequiredNotesImportEnvelope { requestId: number; status: RequiredNotesImportStatus }
export interface RequiredNotesImportStatusReply { requestId: number; status: RequiredNotesImportStatus | null }
export interface RequiredNotesImportReply {
  requestId: number;
  result: RequiredNotesImported | null;
  status: RequiredNotesImportStatus;
}
// Optional methods keep old/preview services unavailable rather than creating a
// mock picker or write implementation. Native createNativeApi supplies all nine.
export interface RequiredNotesApi {
  requiredNotesCapabilities?(): Promise<RequiredNotesCapabilities>;
  observeRequiredNotes?(input: RequiredNotesObserveInput): Promise<RequiredNotesLoaded>;
  validateRequiredNotes?(input: { context: RequiredNoteContext; text: string }): Promise<RequiredNoteValidation>;
  importRequiredNotes?(input: RequiredNotesImportInput): Promise<RequiredNotesImportReply>;
  prepareRequiredNotes?(input: RequiredNotesNativePrepareInput): Promise<RequiredNotesPreparedReply>;
  applyRequiredNotes?(input: RequiredNotesApplyInput): Promise<RequiredNotesRoutineEnvelope>;
  closeRequiredNotes?(input: RequiredNotesCloseInput): Promise<RequiredNotesRoutineEnvelope>;
  requiredNotesStatus?(input: RequiredNotesCorrelation): Promise<RequiredNotesStatusReply>;
  requiredNotesImportStatus?(input: RequiredNotesCorrelation): Promise<RequiredNotesImportStatusReply>;
  subscribeRequiredNotes?(onStatus: (value: unknown) => void): Promise<() => void>;
  subscribeRequiredNotesImport?(onStatus: (value: unknown) => void): Promise<() => void>;
}
export type RequiredNotesCommand = 'required_notes_capabilities' | 'required_notes_observe' | 'required_notes_validate' | 'required_notes_import' |
  'required_notes_edit_prepare' | 'required_notes_edit_apply' | 'required_notes_edit_close' | 'required_notes_edit_status' | 'required_notes_import_status';

export function parseRequiredNoteContext(value: unknown): RequiredNoteContext | null {
  try { return context(value) ? clone<RequiredNoteContext>(value) : null; } catch { return null; }
}
export function parseRequiredNotesCapabilities(value: unknown): RequiredNotesCapabilities | null {
  try {
    if (!keys(value, ['schemaVersion', 'windowGeneration', 'read', 'edit', 'import']) || value.schemaVersion !== 1 || !token(value.windowGeneration)) return null;
    for (const name of ['read', 'edit', 'import']) {
      const item = value[name];
      if (!keys(item, ['available', 'reason']) || typeof item.available !== 'boolean' ||
          !one(item.reason, ['none', 'unsupported_platform', 'runtime_unavailable', 'unqualified', 'document_unavailable']) ||
          item.available !== (item.reason === 'none')) return null;
    }
    return clone<RequiredNotesCapabilities>(value);
  } catch { return null; }
}
export function parseRequiredNotesPreparedReply(value: unknown): RequiredNotesPreparedReply | null {
  try {
    if (!keys(value, ['requestId', 'prepared']) || !isU32(value.requestId)) return null;
    const prepared = parseRequiredNotesPrepared(value.prepared);
    return prepared ? { requestId: value.requestId as number, prepared } : null;
  } catch { return null; }
}
export function parseRequiredNotesStatusReply(value: unknown): RequiredNotesStatusReply | null {
  try {
    if (!keys(value, ['requestId', 'status']) || !isU32(value.requestId)) return null;
    const status = value.status === null ? null : parseRequiredNotesRoutineStatus(value.status);
    return value.status !== null && status === null ? null : { requestId: value.requestId as number, status };
  } catch { return null; }
}
export function parseRequiredNotesRoutineEnvelope(value: unknown): RequiredNotesRoutineEnvelope | null {
  const reply = parseRequiredNotesStatusReply(value);
  return reply?.status ? { requestId: reply.requestId, status: reply.status } : null;
}
export function parseRequiredNotesImportStatus(value: unknown): RequiredNotesImportStatus | null {
  try {
    if (!keys(value, ['schemaVersion', 'requestId', 'windowGeneration', 'projectId', 'context', 'phase', 'outcome', 'reason']) ||
        value.schemaVersion !== 1 || !isU32(value.requestId) || !token(value.windowGeneration) || !project(value.projectId) || !context(value.context)) return null;
    const pending = value.phase === 'pending' && value.outcome === null && value.reason === 'none';
    const unknown = value.phase === 'unknown' && value.outcome === null && value.reason === 'cleanup_unknown';
    const settled = value.phase === 'settled' && (value.outcome === 'selected' && value.reason === 'none' ||
      value.outcome === 'cancelled' && value.reason === 'cancelled' ||
      value.outcome === 'refused' && one(value.reason, ['invalid_file', 'changed_file', 'invalid_text', 'unavailable', 'io_error', 'context_changed']));
    return pending || unknown || settled ? clone<RequiredNotesImportStatus>(value) : null;
  } catch { return null; }
}
export function parseRequiredNotesImportStatusReply(value: unknown): RequiredNotesImportStatusReply | null {
  try {
    if (!keys(value, ['requestId', 'status']) || !isU32(value.requestId)) return null;
    const status = value.status === null ? null : parseRequiredNotesImportStatus(value.status);
    if (value.status !== null && (!status || status.requestId !== value.requestId)) return null;
    return { requestId: value.requestId as number, status };
  } catch { return null; }
}
export function parseRequiredNotesImportEnvelope(value: unknown): RequiredNotesImportEnvelope | null {
  const reply = parseRequiredNotesImportStatusReply(value);
  return reply?.status ? { requestId: reply.requestId, status: reply.status } : null;
}
export function parseRequiredNotesImportReply(value: unknown): RequiredNotesImportReply | null {
  try {
    if (!keys(value, ['requestId', 'result', 'status']) || !isU32(value.requestId)) return null;
    const status = parseRequiredNotesImportStatus(value.status);
    if (!status || status.requestId !== value.requestId || status.phase === 'pending') return null;
    const result = value.result === null ? null : parseRequiredNotesImported(value.result);
    if (status.phase === 'unknown' || status.outcome === 'refused') {
      return value.result === null ? { requestId: value.requestId as number, result: null, status } : null;
    }
    if (!result || result.state !== status.outcome || result.state === 'selected' && result.kind !== status.context.kind) return null;
    return { requestId: value.requestId as number, result, status };
  } catch { return null; }
}
export function requiredNotesImportProgress(a: RequiredNotesImportStatus, b: RequiredNotesImportStatus): boolean {
  return a.requestId === b.requestId && a.windowGeneration === b.windowGeneration && a.projectId === b.projectId &&
    sameRequiredNoteContext(a.context, b.context) && (a.phase === 'pending' || JSON.stringify(a) === JSON.stringify(b));
}
export function requiredNotesRequestFits(command: RequiredNotesCommand, value: unknown): boolean {
  try {
    if (command === 'required_notes_capabilities') return keys(value, []);
    if (command === 'required_notes_validate') {
      // Transport ceiling, not a duplicated provider limit: invalid drafts must
      // still reach the one core validator without silent truncation.
      return keys(value, ['context', 'text']) && context(value.context) && text(value.text, 262148) && [...value.text].length <= 65537;
    }
    if (command === 'required_notes_observe') return keys(value, ['projectId', 'windowGeneration', 'context']) &&
      project(value.projectId) && token(value.windowGeneration) && context(value.context);
    if (command === 'required_notes_import') return keys(value, ['requestId', 'projectId', 'windowGeneration', 'context']) &&
      isU32(value.requestId) && project(value.projectId) && token(value.windowGeneration) && context(value.context);
    if (command === 'required_notes_edit_prepare') return keys(value, ['requestId', 'projectId', 'windowGeneration', 'context', 'draftRevision', 'expectedBaseline', 'text']) &&
      isU32(value.requestId) && project(value.projectId) && token(value.windowGeneration) && context(value.context) &&
      isU32(value.draftRevision) && baseline(value.expectedBaseline, value.context) && text(value.text, requiredNoteByteLimit(value.context.kind));
    if (command === 'required_notes_edit_apply') return keys(value, ['requestId', 'windowGeneration', 'sessionId', 'planToken']) &&
      isU32(value.requestId) && token(value.windowGeneration) && token(value.sessionId) && token(value.planToken);
    if (command === 'required_notes_edit_close') return keys(value, ['requestId', 'windowGeneration', 'sessionId']) &&
      isU32(value.requestId) && token(value.windowGeneration) && token(value.sessionId);
    return (command === 'required_notes_edit_status' || command === 'required_notes_import_status') &&
      keys(value, ['requestId', 'windowGeneration']) && isU32(value.requestId) && token(value.windowGeneration);
  } catch { return false; }
}
const requiredNotesMessages = {
  required_notes_unavailable: 'Required-note native operations are unavailable. No replacement picker or file writer was used.',
  required_notes_runtime_unavailable: 'The required-note runtime is unavailable. Restore the supported application runtime.',
  required_notes_unsupported_platform: 'This required-note operation is not supported on the current platform.',
  required_notes_unqualified: 'This required-note native boundary has not been qualified on this application profile.',
  required_notes_document_unavailable: 'The original native window is unavailable. No replacement window or session was assumed.',
  required_notes_invalid_params: 'The closed required-note request was refused. No private request details are shown.',
  required_notes_config_invalid: 'Read and save valid project settings before selecting required notes.',
  required_notes_not_configured: 'The note platform or Android locale is not enabled in the saved project settings.',
  required_notes_version_invalid: 'The saved version source could not be accepted. Review it before selecting build-specific notes.',
  required_notes_unsafe: 'The original note path or dependency could not be admitted safely.',
  required_notes_invalid_file: 'The selected file is not a supported regular UTF-8 text file. The previous draft was kept.',
  required_notes_changed_file: 'The original selected file changed during capture. The previous draft was kept.',
  required_notes_invalid_text: 'The selected text was refused by the shared core policy. The previous draft was kept.',
  required_notes_context_changed: 'The original project, window or saved note context changed. Reload before editing.',
  required_notes_cleanup_unknown: 'Original cleanup is unverified. Keep the gate closed and check the original operation.',
  required_notes_io_error: 'The original required-note operation encountered an I/O failure. No private details are shown.',
  required_notes_busy: 'Another original operation retains the shared gate. Wait for its verified finality.',
  required_notes_pending_state: 'The original transaction requires recovery. Do not retry the write.',
  required_notes_stale_revision: 'The saved note or a dependency changed after Load. Reload before another review.',
  required_notes_protocol: 'The original required-note response could not be accepted. No operation was confirmed.',
} as const;
export function requiredNotesError(value: unknown): ApiError {
  let code: unknown;
  try { code = typeof value === 'string' ? value : record(value) ? Object.getOwnPropertyDescriptor(value, 'code')?.value : null; } catch { code = null; }
  const safe = typeof code === 'string' && Object.hasOwn(requiredNotesMessages, code) ? code as keyof typeof requiredNotesMessages : 'required_notes_protocol';
  return { code: safe, message: requiredNotesMessages[safe], retryable: false };
}
export function requiredNotesCapabilityMessage(value: RequiredNotesCapability | null): string | null {
  if (value?.available) return null;
  const messages = {
    none: 'The required-note native capability is unavailable.',
    unsupported_platform: 'This required-note operation is not supported on the current platform.',
    runtime_unavailable: 'The supported required-note runtime is unavailable.',
    unqualified: 'This required-note native boundary is not qualified on the current application profile.',
    document_unavailable: 'The original native window is unavailable.',
  };
  return value ? messages[value.reason] : 'Required-note native capabilities have not been established.';
}

export function encodeRequiredNotesRequest(command: RequiredNotesCommand, value: unknown): Uint8Array | null {
  if (!requiredNotesRequestFits(command, value)) return null;
  try {
    const body = encoder.encode(JSON.stringify(value));
    return body.byteLength <= 524288 ? body : null;
  } catch { return null; }
}
