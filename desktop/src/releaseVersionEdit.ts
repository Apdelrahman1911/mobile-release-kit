// Saved-version VALUE DATA, separate from passive observation and config drafts.
// Core alone decides policy and patches the original bytes.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import type { ApiError, CoreEditOutcome, EditAvailability, HelpContent, JsonValue, NativeEditReason } from './types.ts';

export interface VersionValues { name: string; build: string }
export interface VersionDigest { bytes: number; sha256: string }
export type VersionBaselineFile = { state: 'absent' } | ({ state: 'present' } & VersionDigest);
export interface VersionBaseline { savedConfig: VersionDigest; savedVersion: VersionBaselineFile }
export type VersionIntent = 'edit' | 'create';
export interface VersionCheckout {
  revision: string; source: string; nameKey: string; buildKey: string; iosEnabled: boolean;
  values: VersionValues | null; baseline: VersionBaseline;
}
export interface VersionPreparedView {
  schemaVersion: 1; source: string; nameKey: string; buildKey: string; iosEnabled: boolean; intent: VersionIntent; values: VersionValues;
  file: { path: string; action: 'create' | 'replace' | 'preserve'; before: { state: 'absent' } | ({ state: 'present'; text: string } & VersionDigest);
    after: { text: string } & VersionDigest; requestedMode: number; preserveMode: boolean };
  createDirectories: string[];
  lineEndings: { before: string[]; after: string[]; finalNewlineBefore: boolean; finalNewlineAfter: boolean; preserved: boolean };
  validation: { valid: true; state: 'format-valid'; issues: [] };
}
export interface VersionEditProjection {
  domain: 'release_version'; projectId: string; sessionId: string; ownerGeneration: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number; checkout: VersionCheckout | null;
  prepared: { revision: string; planToken: string; draftRevision: number; baselineGeneration: number; view: VersionPreparedView } | null;
  applySubmitted: boolean; coreOutcome: CoreEditOutcome | null; nativeReason: NativeEditReason; nativeFinality: 'pending' | 'settled' | 'unknown'; lateSettled: boolean;
}
export interface VersionEditStatus {
  schemaVersion: 1; domain: 'release_version'; windowGeneration: string; statusRevision: number;
  capability: { available: boolean; reason: EditAvailability }; active: VersionEditProjection | null; lastTerminal: VersionEditProjection | null;
}
export interface PrepareVersionEditRequest {
  sessionId: string; revision: string; expectedBaseline: VersionBaseline; intent: VersionIntent; values: VersionValues; draftRevision: number; baselineGeneration: number;
}
export interface ReleaseVersionEditApi {
  openReleaseVersionEdit(input: { projectId: string }): Promise<VersionEditStatus>;
  prepareReleaseVersionEdit(input: PrepareVersionEditRequest): Promise<VersionEditStatus>;
  applyReleaseVersionEdit(sessionId: string, planToken: string): Promise<VersionEditStatus>;
  closeReleaseVersionEdit(sessionId: string): Promise<VersionEditStatus>;
  releaseVersionEditStatus(): Promise<VersionEditStatus>;
  subscribeReleaseVersionEdit(onStatus: (status: unknown) => void): Promise<() => void>;
}
export type VersionActionId = 'open' | 'review' | 'save' | 'reload' | 'discard';
export interface VersionEditGuide {
  schemaVersion: 1;
  fields: (HelpContent & { id: 'name' | 'build'; requiredness: 'required' })[];
  actions: (HelpContent & { id: VersionActionId; requiredness: 'optional' })[];
  limits: { maxNameBytes: 64; maxBuildBytes: 10; maxSourceBytes: 65536 };
}
export const VERSION_EDIT_EVENT = 'release-version-edit-status';
export const VERSION_SOURCE_LIMIT = 64 * 1024;
const encoder = new TextEncoder();
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const availability = ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active'];
function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function keys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const names = Reflect.ownKeys(value);
  return names.length === expected.length && names.every((name) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return typeof name === 'string' && expected.includes(name) && descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
function oneOf(value: unknown, choices: readonly string[]): boolean { return typeof value === 'string' && choices.includes(value); }
function token(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{32}(?![\s\S])/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{64}(?![\s\S])/.test(value); }
function length(value: unknown, max: number): value is number { return isU32(value) && value <= max; }
function text(value: unknown, max: number, empty = false): value is string {
  return typeof value === 'string' && (empty || value.length > 0) && value.length <= max &&
    !/[\ud800-\udfff]/u.test(value) && encoder.encode(value).byteLength <= max;
}
function projectId(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(value); }

// Bounded JSON DATA before any stringify/copy or parser descent. Accessors,
// sparse arrays, cycles, exotic objects and hidden keys are never interpreted.
function boundedJson(value: unknown, maxBytes: number, maxNodes = 20000, maxDepth = 32): boolean {
  const ancestors = new Set<object>();
  let nodes = 0; let floor = 0;
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > maxNodes || depth > maxDepth) return false;
    if (item === null || typeof item === 'boolean') floor += 1;
    else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; floor += 1; }
    else if (typeof item === 'string') {
      if (!text(item, maxBytes, true)) return false;
      floor += encoder.encode(item).byteLength + 2;
    } else {
      if (typeof item !== 'object' || depth >= maxDepth || ancestors.has(item)) return false;
      ancestors.add(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || item.length > maxNodes - nodes || Reflect.ownKeys(item).length !== item.length + 1) return false;
        floor += 2 + Math.max(0, item.length - 1);
        if (floor > maxBytes) return false;
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(descriptor.value, depth + 1)) return false;
        }
      } else {
        if (!record(item)) return false;
        const names = Reflect.ownKeys(item);
        if (names.length > maxNodes - nodes) return false;
        floor += 2 + Math.max(0, 2 * names.length - 1);
        if (floor > maxBytes) return false;
        for (const name of names) {
          if (typeof name !== 'string') return false;
          const descriptor = Object.getOwnPropertyDescriptor(item, name);
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(name, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
        }
      }
      ancestors.delete(item);
    }
    return floor <= maxBytes;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= maxBytes; }
  catch { return false; }
}
function equal(first: unknown, next: unknown): boolean { return sameJson(first as JsonValue, next as JsonValue); }
function relativePath(value: unknown, maxDepth = 12): value is string {
  if (!text(value, 512) || value.normalize('NFC') !== value || /[\\:<>"|?*\u0000-\u001f\u007f]/u.test(value)) return false;
  const parts = value.split('/');
  const reserved = ['private', 'secrets', 'credentials', 'review', 'testflight', 'build', 'deriveddata', 'pods', 'node_modules', 'venv', 'dist', 'target', '__pycache__'];
  return parts.length <= maxDepth && parts.every((part) => part.length > 0 && encoder.encode(part).byteLength <= 255 && !part.startsWith('.') && !/[. ]$/.test(part) && !reserved.includes(part.toLowerCase()) &&
    !/^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(part));
}

export function sameVersionData(first: unknown, next: unknown): boolean { return equal(first, next); }
function proposed(value: unknown): value is VersionValues {
  return keys(value, ['name', 'build']) && typeof value.name === 'string' && /^[\x00-\x7f]{1,64}(?![\s\S])/.test(value.name) &&
    typeof value.build === 'string' && /^[0-9]{1,10}(?![\s\S])/.test(value.build);
}
export function versionValuesBounded(value: unknown): value is VersionValues { return proposed(value); }
function originalValues(value: unknown): value is VersionValues {
  return keys(value, ['name', 'build']) && [value.name, value.build].every((s) => typeof s === 'string' && s.length <= VERSION_SOURCE_LIMIT && /^[0-9A-Za-z_.+-]+(?![\s\S])/.test(s));
}
function comparison(value: unknown, limit: number): boolean {
  return keys(value, ['bytes', 'sha256']) && length(value.bytes, limit) && value.bytes > 0 && digest(value.sha256);
}
function baselineFile(value: unknown): value is VersionBaselineFile {
  return keys(value, ['state']) && value.state === 'absent' ||
    keys(value, ['state', 'bytes', 'sha256']) && value.state === 'present' && length(value.bytes, VERSION_SOURCE_LIMIT) && value.bytes > 0 && digest(value.sha256);
}
function baseline(value: unknown): value is VersionBaseline {
  return keys(value, ['savedConfig', 'savedVersion']) && comparison(value.savedConfig, 512 * 1024) && baselineFile(value.savedVersion);
}
function selection(value: Record<string, unknown>): boolean {
  return relativePath(value.source) && value.source.toLowerCase() !== 'release/mobile-release.json' && typeof value.nameKey === 'string' && /^[A-Z][A-Z0-9_]{0,63}(?![\s\S])/.test(value.nameKey) &&
    typeof value.buildKey === 'string' && /^[A-Z][A-Z0-9_]{0,63}(?![\s\S])/.test(value.buildKey) && value.nameKey !== value.buildKey && typeof value.iosEnabled === 'boolean';
}
function checkout(value: unknown): value is VersionCheckout {
  if (!keys(value, ['revision', 'source', 'nameKey', 'buildKey', 'iosEnabled', 'values', 'baseline']) || !token(value.revision) || !selection(value) || !baseline(value.baseline)) return false;
  return value.baseline.savedVersion.state === 'absent' ? value.values === null : originalValues(value.values) &&
    value.values.name.length + value.values.build.length < value.baseline.savedVersion.bytes;
}
const lineBreaks = [['\r\n', 'crlf'], ['\n', 'lf'], ['\r', 'cr'], ['\v', 'vt'], ['\f', 'ff'], ['\x1c', 'fs'], ['\x1d', 'gs'],
  ['\x1e', 'rs'], ['\x85', 'nel'], ['\u2028', 'ls'], ['\u2029', 'ps']] as const;
export function versionLineEndings(text: string): string[] {
  const styles: string[] = [];
  for (const [separator, label] of lineBreaks) if (text.includes(separator)) { styles.push(label); text = text.split(separator).join(''); }
  return styles;
}
function finalNewline(text: string): boolean { return lineBreaks.some(([separator]) => text.endsWith(separator)); }
function preparedView(value: unknown): value is VersionPreparedView {
  if (!boundedJson(value, 1024 * 1024) || !keys(value, ['schemaVersion', 'source', 'nameKey', 'buildKey', 'iosEnabled', 'intent', 'values', 'file', 'createDirectories', 'lineEndings', 'validation']) ||
      value.schemaVersion !== 1 || !selection(value) || !proposed(value.values) || !oneOf(value.intent, ['edit', 'create']) ||
      !keys(value.validation, ['valid', 'state', 'issues']) || value.validation.valid !== true || value.validation.state !== 'format-valid' ||
      !Array.isArray(value.validation.issues) || value.validation.issues.length !== 0 || !Array.isArray(value.createDirectories) || value.createDirectories.length > 11) return false;
  const file = value.file, endings = value.lineEndings;
  if (!keys(file, ['path', 'action', 'before', 'after', 'requestedMode', 'preserveMode']) || file.path !== value.source ||
      !oneOf(file.action, ['create', 'replace', 'preserve']) || !length(file.requestedMode, 0o777) || typeof file.preserveMode !== 'boolean' ||
      !keys(file.after, ['text', 'bytes', 'sha256']) || !text(file.after.text, VERSION_SOURCE_LIMIT) || file.after.bytes !== encoder.encode(file.after.text).byteLength || !digest(file.after.sha256) ||
      !keys(endings, ['before', 'after', 'finalNewlineBefore', 'finalNewlineAfter', 'preserved']) || typeof endings.preserved !== 'boolean') return false;
  let before = '';
  if (keys(file.before, ['state']) && file.before.state === 'absent') {
    if (value.intent !== 'create' || file.action !== 'create' || file.preserveMode || file.requestedMode !== 0o644 || endings.preserved ||
        file.after.text !== String(value.nameKey) + '=' + value.values.name + '\n' + String(value.buildKey) + '=' + value.values.build + '\n') return false;
  } else {
    if (!keys(file.before, ['state', 'text', 'bytes', 'sha256']) || file.before.state !== 'present' || !text(file.before.text, VERSION_SOURCE_LIMIT) ||
        file.before.bytes !== encoder.encode(file.before.text).byteLength || !digest(file.before.sha256) || value.intent !== 'edit' || !file.preserveMode ||
        !endings.preserved || value.createDirectories.length !== 0) return false;
    before = file.before.text;
    const unchanged = before === file.after.text;
    if (file.action !== (unchanged ? 'preserve' : 'replace') || unchanged !== (file.before.bytes === file.after.bytes && file.before.sha256 === file.after.sha256)) return false;
    if (!equal(endings.before, endings.after) || endings.finalNewlineBefore !== endings.finalNewlineAfter) return false;
  }
  if (!equal(endings.before, versionLineEndings(before)) || !equal(endings.after, versionLineEndings(file.after.text)) ||
      endings.finalNewlineBefore !== finalNewline(before) || endings.finalNewlineAfter !== finalNewline(file.after.text)) return false;
  const parts = String(value.source).split('/'); const ancestors = parts.slice(0, -1).map((_, index) => parts.slice(0, index + 1).join('/'));
  return value.createDirectories.length <= ancestors.length && equal(value.createDirectories, ancestors.slice(ancestors.length - value.createDirectories.length));
}
export function versionNoOp(view: VersionPreparedView): boolean { return view.file.action === 'preserve'; }
export function viewMatchesVersionCheckout(view: VersionPreparedView, opened: VersionCheckout): boolean {
  const before = view.file.before;
  return view.source === opened.source && view.nameKey === opened.nameKey && view.buildKey === opened.buildKey && view.iosEnabled === opened.iosEnabled &&
    view.intent === (opened.baseline.savedVersion.state === 'absent' ? 'create' : 'edit') &&
    equal(before.state === 'absent' ? { state: 'absent' } : { state: 'present', bytes: before.bytes, sha256: before.sha256 }, opened.baseline.savedVersion);
}
export type VersionEditCommand = 'release_version_edit_open' | 'release_version_edit_prepare' | 'release_version_edit_apply' | 'release_version_edit_close' | 'release_version_edit_status';
export function versionEditRequestFits(command: VersionEditCommand, value: unknown): boolean {
  if (!boundedJson(value, 16 * 1024, 256, 16)) return false;
  switch (command) {
    case 'release_version_edit_open': return keys(value, ['projectId']) && projectId(value.projectId);
    case 'release_version_edit_prepare': return keys(value, ['sessionId', 'revision', 'expectedBaseline', 'intent', 'values', 'draftRevision', 'baselineGeneration']) &&
      token(value.sessionId) && token(value.revision) && baseline(value.expectedBaseline) && value.intent === (value.expectedBaseline.savedVersion.state === 'absent' ? 'create' : 'edit') &&
      proposed(value.values) && isU32(value.draftRevision) && value.draftRevision < U32_MAX && isU32(value.baselineGeneration) && value.baselineGeneration < U32_MAX;
    case 'release_version_edit_apply': return keys(value, ['sessionId', 'planToken']) && token(value.sessionId) && token(value.planToken);
    case 'release_version_edit_close': return keys(value, ['sessionId']) && token(value.sessionId);
    case 'release_version_edit_status': return keys(value, []);
  }
}
export function parseVersionEditGuide(value: unknown): VersionEditGuide | null {
  if (!boundedJson(value, 32 * 1024, 512, 8) || !keys(value, ['schemaVersion', 'fields', 'actions', 'limits']) || value.schemaVersion !== 1 ||
      !keys(value.limits, ['maxNameBytes', 'maxBuildBytes', 'maxSourceBytes']) || value.limits.maxNameBytes !== 64 || value.limits.maxBuildBytes !== 10 || value.limits.maxSourceBytes !== 65536) return null;
  const rows = (input: unknown, ids: readonly string[], required: string): boolean => Array.isArray(input) && input.length === ids.length &&
    input.every((row, index) => keys(row, ['id', 'label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure']) &&
      row.id === ids[index] && row.requiredness === required && ['label', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure'].every((field) => text(row[field], 4096, true)));
  return rows(value.fields, ['name', 'build'], 'required') && rows(value.actions, ['open', 'review', 'save', 'reload', 'discard'], 'optional') ? value as unknown as VersionEditGuide : null;
}
export function versionEditError(error: unknown): ApiError {
  const code = record(error) && typeof error.code === 'string' ? error.code : '';
  if (code === 'VersionEditStatusInvalid') return { code, message: 'The original saved-version status is invalid. Keep the draft and operation evidence; do not retry the save.', retryable: false };
  if (code === 'VersionEditContextChanged') return { code, message: 'The saved configuration or version baseline changed. Close, then explicitly reload saved values and discard the old draft before another review.', retryable: false };
  if (code === 'VersionEditInvalid') return { code, message: 'Use two bounded strings: a marketing version and a canonical positive build number. Nothing was trimmed, coerced or saved.', retryable: false };
  return { code: 'VersionEditUnavailable', message: 'Saved-version editing is unavailable or its original status was not confirmed. No save or cleanup is assumed; check the original status.', retryable: false };
}
function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) || !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) || !oneOf(value.resources, ['settled', 'unknown']) || !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created' || oneOf(value.effect, ['committed', 'rolled_back']) && value.journal === 'not_created') return false;
  return value.reason !== 'none' || value.resources === 'settled' && value.effect !== 'unknown' && !oneOf(value.journal, ['unknown', 'recovery_required']);
}
function projection(value: unknown): value is VersionEditProjection {
  if (!keys(value, ['domain', 'projectId', 'sessionId', 'ownerGeneration', 'phase', 'reviewRemainingMs', 'checkout', 'prepared', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled']) ||
      value.domain !== 'release_version' || !projectId(value.projectId) || !token(value.sessionId) || !token(value.ownerGeneration) ||
      !oneOf(value.phase, phases) || !length(value.reviewRemainingMs, 900000) || typeof value.applySubmitted !== 'boolean' || typeof value.lateSettled !== 'boolean' ||
      !oneOf(value.nativeReason, nativeReasons) || !oneOf(value.nativeFinality, ['pending', 'settled', 'unknown']) || !(value.coreOutcome === null || outcome(value.coreOutcome))) return false;
  const opened = value.checkout, prepared = value.prepared;
  if (opened !== null && !checkout(opened)) return false;
  if (prepared !== null && (!keys(prepared, ['revision', 'planToken', 'draftRevision', 'baselineGeneration', 'view']) ||
      !token(prepared.revision) || !token(prepared.planToken) || prepared.revision === prepared.planToken ||
      !isU32(prepared.draftRevision) || prepared.draftRevision >= U32_MAX || !isU32(prepared.baselineGeneration) || prepared.baselineGeneration >= U32_MAX ||
      !preparedView(prepared.view) || !checkout(opened) || prepared.revision !== opened.revision || !viewMatchesVersionCheckout(prepared.view, opened))) return false;
  const result = value as unknown as VersionEditProjection;
  if (result.phase === 'final') {
    if (result.nativeFinality !== 'settled' || result.lateSettled) return false;
    if (!result.coreOutcome) { if (result.checkout || result.prepared || result.applySubmitted || result.nativeReason === 'none') return false; }
    else if (result.coreOutcome.resources === 'unknown' || result.coreOutcome.effect === 'unknown' || result.coreOutcome.journal === 'unknown') return false;
  } else if (result.phase === 'unknown') { if (result.nativeFinality !== 'unknown') return false; }
  else if (result.nativeFinality !== 'pending' || result.lateSettled) return false;
  if (result.phase === 'opening' && (result.checkout || result.prepared || result.applySubmitted)) return false;
  if (['editing', 'preparing', 'reviewing', 'applying'].includes(result.phase) && !result.checkout) return false;
  if (['editing', 'preparing'].includes(result.phase) && (result.prepared || result.applySubmitted)) return false;
  if (['reviewing', 'applying'].includes(result.phase) && !result.prepared) return false;
  if (result.phase === 'reviewing' && result.applySubmitted || result.phase === 'applying' && !result.applySubmitted || result.applySubmitted && !result.prepared) return false;
  if (['opening', 'editing', 'preparing', 'reviewing'].includes(result.phase) && result.coreOutcome !== null) return false;
  if (result.coreOutcome && ['committed', 'rolled_back', 'unchanged'].includes(result.coreOutcome.effect)) {
    if (!result.checkout || !result.prepared || !result.applySubmitted) return false;
    if (result.coreOutcome.effect === 'unchanged' ? !versionNoOp(result.prepared.view) : versionNoOp(result.prepared.view)) return false;
  }
  return true;
}
export function parseVersionEditStatus(value: unknown): VersionEditStatus | null {
  try {
    if (!boundedJson(value, 2 * 1024 * 1024) || !keys(value, ['schemaVersion', 'domain', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
        value.schemaVersion !== 1 || value.domain !== 'release_version' || !token(value.windowGeneration) || !isU32(value.statusRevision) ||
        !keys(value.capability, ['available', 'reason']) || typeof value.capability.available !== 'boolean' || !oneOf(value.capability.reason, availability) ||
        value.capability.available !== (value.capability.reason === 'available') || !(value.active === null || projection(value.active)) || !(value.lastTerminal === null || projection(value.lastTerminal))) return null;
    const result = value as unknown as VersionEditStatus;
    if (result.active?.phase === 'final' || result.active?.lateSettled || result.active && result.capability.reason === 'other_edit_active' ||
        result.lastTerminal && !['final', 'unknown'].includes(result.lastTerminal.phase) || result.active && result.active.sessionId === result.lastTerminal?.sessionId) return null;
    return result;
  } catch { return null; }
}
export function normalVersionEditResult(owner: VersionEditProjection): 'saved' | 'unchanged' | null {
  const core = owner.coreOutcome;
  if (owner.domain !== 'release_version' || owner.phase !== 'final' || owner.nativeFinality !== 'settled' || owner.nativeReason !== 'none' || owner.lateSettled ||
      !core || core.resources !== 'settled' || core.reason !== 'none' || !owner.applySubmitted || !owner.checkout || !owner.prepared || owner.prepared.revision !== owner.checkout.revision) return null;
  if (core.effect === 'committed' && core.journal === 'clean' && !versionNoOp(owner.prepared.view)) return 'saved';
  if (core.effect === 'unchanged' && core.journal === 'not_created' && versionNoOp(owner.prepared.view)) return 'unchanged';
  return null;
}
function sameFacts(first: VersionEditProjection, next: VersionEditProjection): boolean {
  return equal({ ...first, reviewRemainingMs: 0 }, { ...next, reviewRemainingMs: 0 });
}
export function versionProjectionProgress(first: VersionEditProjection, next: VersionEditProjection): boolean {
  if (first.domain !== next.domain || first.sessionId !== next.sessionId || first.projectId !== next.projectId || first.ownerGeneration !== next.ownerGeneration ||
      first.checkout !== null && !equal(first.checkout, next.checkout) ||
      first.prepared !== null && !equal(first.prepared, next.prepared) || first.applySubmitted && !next.applySubmitted || first.lateSettled && !next.lateSettled) return false;
  if (first.phase === 'final') return sameFacts(first, next);
  if (first.phase === 'unknown' && next.phase !== 'unknown' || phases.indexOf(next.phase) < phases.indexOf(first.phase) || first.nativeReason !== 'none' && first.nativeReason !== next.nativeReason) return false;
  if (first.coreOutcome && (!next.coreOutcome || first.coreOutcome.effect !== 'unknown' && first.coreOutcome.effect !== next.coreOutcome.effect ||
      first.coreOutcome.reason !== 'none' && first.coreOutcome.reason !== next.coreOutcome.reason ||
      first.coreOutcome.journal !== 'unknown' && first.coreOutcome.journal !== next.coreOutcome.journal ||
      first.coreOutcome.resources === 'settled' && next.coreOutcome.resources !== 'settled')) return false;
  return true;
}
export function versionStatusProgress(first: VersionEditStatus, next: VersionEditStatus): boolean {
  if (first.windowGeneration !== next.windowGeneration || next.statusRevision < first.statusRevision) return true;
  if (next.statusRevision === first.statusRevision) return equal(first.capability, next.capability) && (['active', 'lastTerminal'] as const).every((key) => {
    const before = first[key]; const after = next[key];
    return before === null || after === null ? before === after : sameFacts(before, after);
  });
  return [first.active, first.lastTerminal].every((before) => {
    if (!before) return true;
    const after = [next.active, next.lastTerminal].find((row) => row?.sessionId === before.sessionId);
    return !after || versionProjectionProgress(before, after);
  });
}

