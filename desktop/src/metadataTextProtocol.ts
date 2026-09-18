// Closed transport and display consistency checks only. No renderer paths,
// content digests or character counts can acquire original filesystem authority.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { METADATA_TEXT_IDS, METADATA_TEXT_FIELD_BYTES, metadataLineEndings, metadataNoOp } from './metadataText.ts';
import type { MetadataPlatform, MetadataTextBaseline, MetadataTextObservation, MetadataTextValidation, MetadataTextGuide,
  MetadataTextEditProjection, MetadataTextEditStatus, PreparedMetadataTextView, MetadataTextField } from './metadataText.ts';
import type { ApiError, CoreEditOutcome, JsonValue } from './types.ts';

const encoder = new TextEncoder();
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const availability = ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active'];
const issueRows = [
  ['metadata.empty-text', 'INVALID', 'Public Store text must contain non-whitespace content.'],
  ['metadata.nul', 'INVALID', 'Public Store text must not contain NUL.'],
  ['metadata.placeholder', 'FAIL', 'Public Store text contains an unresolved placeholder.'],
  ['metadata.secret-pattern', 'FAIL', 'Public Store text may contain secret material. Remove it and rotate exposed credentials.'],
  ['metadata.url', 'INVALID', 'Use an absolute credential-free HTTPS URL without a query or fragment.'],
  ['metadata.length', 'FAIL', 'Public Store text exceeds the shared core character limit.'],
] as const;

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
function platform(value: unknown): value is MetadataPlatform { return value === 'android' || value === 'ios'; }
function token(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function length(value: unknown, max: number): value is number { return isU32(value) && value <= max; }
function text(value: unknown, max: number, empty = false): value is string {
  return typeof value === 'string' && (empty || value.length > 0) && value.length <= max &&
    !/[\ud800-\udfff]/u.test(value) && encoder.encode(value).byteLength <= max;
}
function locale(value: unknown): value is string { return typeof value === 'string' && /^[\x20-\x7e]{2,12}$/.test(value); }
function projectId(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value); }

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
function contentDigest(value: unknown, max: number, minimum = 0): boolean {
  return keys(value, ['byteLength', 'sha256']) && length(value.byteLength, max) && value.byteLength >= minimum && digest(value.sha256);
}
function baseline(value: unknown, selected: MetadataPlatform): value is MetadataTextBaseline {
  return keys(value, ['config', 'fields']) && contentDigest(value.config, 524288, 1) && Array.isArray(value.fields) &&
    value.fields.length === METADATA_TEXT_IDS[selected].length && value.fields.every((row, index) => {
      if (!record(row) || row.id !== METADATA_TEXT_IDS[selected][index]) return false;
      return keys(row, ['id', 'state']) && row.state === 'absent' || keys(row, ['id', 'state', 'byteLength', 'sha256']) &&
        row.state === 'present' && length(row.byteLength, METADATA_TEXT_FIELD_BYTES) && digest(row.sha256);
    });
}
function textFields(value: unknown, selected: MetadataPlatform): value is MetadataTextField[] {
  return Array.isArray(value) && value.length === METADATA_TEXT_IDS[selected].length && value.every((row, index) =>
    keys(row, ['id', 'text']) && row.id === METADATA_TEXT_IDS[selected][index] && text(row.text, METADATA_TEXT_FIELD_BYTES, true));
}
function assurance(value: unknown, basis: 'static-text' | 'schema-policy'): boolean {
  return keys(value, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) &&
    value.basis === basis && value.projectCodeExecuted === false && value.toolsProbed === false && value.credentialsRead === false &&
    value.gitObserved === false && value.storeContacted === false && value.writesPerformed === false && value.releaseReadiness === 'unknown';
}

export type MetadataTextCommand = 'metadata_text_observe' | 'metadata_text_validate' | 'metadata_text_edit_open' |
  'metadata_text_edit_prepare' | 'metadata_text_edit_apply' | 'metadata_text_edit_close' | 'metadata_text_edit_status';
export function metadataTextRequestFits(command: MetadataTextCommand, value: unknown): boolean {
  try {
    if (!boundedJson(value, 1024 * 1024)) return false;
    switch (command) {
      case 'metadata_text_observe': case 'metadata_text_edit_open':
        return keys(value, ['projectId', 'platform', 'locale']) && projectId(value.projectId) && platform(value.platform) && locale(value.locale);
      case 'metadata_text_validate':
        return keys(value, ['platform', 'fields']) && platform(value.platform) && textFields(value.fields, value.platform);
      case 'metadata_text_edit_status': return keys(value, []);
      case 'metadata_text_edit_close': return keys(value, ['sessionId']) && token(value.sessionId);
      case 'metadata_text_edit_apply': return keys(value, ['sessionId', 'planToken']) && token(value.sessionId) && token(value.planToken);
      case 'metadata_text_edit_prepare': {
        if (!keys(value, ['sessionId', 'revision', 'expectedBaseline', 'fields', 'draftRevision', 'baselineGeneration']) ||
            !token(value.sessionId) || !token(value.revision) || !isU32(value.draftRevision) || value.draftRevision === U32_MAX ||
            !isU32(value.baselineGeneration) || value.baselineGeneration === U32_MAX) return false;
        return (['android', 'ios'] as const).some((selected) => textFields(value.fields, selected) && baseline(value.expectedBaseline, selected));
      }
    }
  } catch { return false; }
}

export function parseMetadataTextObservation(value: unknown): MetadataTextObservation | null {
  try {
    if (!boundedJson(value, 2 * 1024 * 1024) || !keys(value, ['schemaVersion', 'platform', 'locale', 'metadataRoot', 'observationScope', 'baseline', 'fields', 'assurance']) ||
        value.schemaVersion !== 1 || !platform(value.platform) || !locale(value.locale) || !relativePath(value.metadataRoot, 9) ||
        value.observationScope !== 'single-request-non-atomic' || !baseline(value.baseline, value.platform) || !assurance(value.assurance, 'static-text') ||
        !Array.isArray(value.fields) || value.fields.length !== METADATA_TEXT_IDS[value.platform].length) return null;
    const selected = value.platform; const original = value.baseline;
    if (!value.fields.every((row, index) => {
      if (!record(row) || row.id !== METADATA_TEXT_IDS[selected][index] || !relativePath(row.path) ||
          row.path !== `${value.metadataRoot}/${selected}/${value.locale}/${row.id}`) return false;
      const expected = original.fields[index];
      return keys(row, ['id', 'path', 'state']) && row.state === 'absent' && expected?.state === 'absent' ||
        keys(row, ['id', 'path', 'state', 'text', 'byteLength', 'sha256']) && row.state === 'present' && text(row.text, METADATA_TEXT_FIELD_BYTES, true) &&
        row.byteLength === encoder.encode(row.text).byteLength && digest(row.sha256) && expected?.state === 'present' &&
        expected.byteLength === row.byteLength && expected.sha256 === row.sha256;
    })) return null;
    return value as unknown as MetadataTextObservation;
  } catch { return null; }
}

export function parseMetadataTextValidation(value: unknown): MetadataTextValidation | null {
  try {
    if (!boundedJson(value, 65536, 2048, 12) || !keys(value, ['schemaVersion', 'platform', 'valid', 'state', 'fields', 'assurance']) || value.schemaVersion !== 1 ||
        !platform(value.platform) || typeof value.valid !== 'boolean' || value.state !== (value.valid ? 'format-valid' : 'invalid') ||
        !assurance(value.assurance, 'schema-policy') || !Array.isArray(value.fields) || value.fields.length !== METADATA_TEXT_IDS[value.platform].length) return null;
    const selected = value.platform;
    if (!value.fields.every((row, index) => {
      if (!keys(row, ['id', 'valid', 'characterCount', 'limit', 'issues']) || row.id !== METADATA_TEXT_IDS[selected][index] || typeof row.valid !== 'boolean' ||
          !length(row.characterCount, METADATA_TEXT_FIELD_BYTES) || !length(row.limit, METADATA_TEXT_FIELD_BYTES) || row.limit === 0 ||
          !Array.isArray(row.issues) || row.issues.length > issueRows.length || row.valid !== (row.issues.length === 0) || row.valid && row.characterCount > row.limit) return false;
      let previous = -1;
      return row.issues.every((issue) => {
        if (!keys(issue, ['code', 'status', 'message'])) return false;
        const found = issueRows.findIndex(([code, status, message]) => issue.code === code && issue.status === status && issue.message === message);
        if (found <= previous) return false;
        previous = found; return true;
      });
    }) || value.valid !== value.fields.every((row) => (row as { valid: boolean }).valid)) return null;
    return value as unknown as MetadataTextValidation;
  } catch { return null; }
}

export function parseMetadataTextGuide(value: unknown): MetadataTextGuide | null {
  try {
    if (!boundedJson(value, 262144, 2048, 12) || !keys(value, ['schemaVersion', 'fields', 'actions', 'limits']) || value.schemaVersion !== 1 ||
        !keys(value.limits, ['maxTextBytes', 'maxCachedLocales', 'maxCachedTextBytes']) || value.limits.maxTextBytes !== 32768 ||
        value.limits.maxCachedLocales !== 32 || value.limits.maxCachedTextBytes !== 8388608 || !Array.isArray(value.fields) || value.fields.length !== 8 ||
        !Array.isArray(value.actions) || value.actions.length !== 5) return null;
    const helpKeys = ['label', 'requiredness', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure'];
    const strings = ['label', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure'];
    const fields = (['android', 'ios'] as const).flatMap((selected) => METADATA_TEXT_IDS[selected].map((id) => ({ id, platform: selected })));
    if (!value.fields.every((row, index) => keys(row, ['id', 'platform', ...helpKeys]) && row.id === fields[index]?.id && row.platform === fields[index]?.platform &&
        row.requiredness === 'required' && strings.every((key) => text(row[key], 2048))) ||
        !value.actions.every((row, index) => keys(row, ['id', ...helpKeys]) && row.id === ['load', 'validate', 'review', 'save', 'discard'][index] &&
          row.requiredness === 'optional' && strings.every((key) => text(row[key], 2048)))) return null;
    return value as unknown as MetadataTextGuide;
  } catch { return null; }
}

function preparedView(value: unknown): value is PreparedMetadataTextView {
  if (!boundedJson(value, 768 * 1024, 10000, 16) || !keys(value, ['schemaVersion', 'platform', 'locale', 'metadataRoot', 'files', 'createDirectories', 'validation']) ||
      value.schemaVersion !== 1 || !platform(value.platform) || !locale(value.locale) || !relativePath(value.metadataRoot, 9) || !Array.isArray(value.files) ||
      value.files.length !== METADATA_TEXT_IDS[value.platform].length || !Array.isArray(value.createDirectories) || value.createDirectories.length > 11) return false;
  const selected = value.platform;
  const validation = parseMetadataTextValidation(value.validation);
  if (!validation?.valid || validation.platform !== selected) return false;
  if (!value.files.every((row, index) => {
    if (!keys(row, ['id', 'path', 'action', 'before', 'after', 'lineEndingsChanged']) || row.id !== METADATA_TEXT_IDS[selected][index] ||
        !relativePath(row.path) || row.path !== `${value.metadataRoot}/${selected}/${value.locale}/${row.id}` || !oneOf(row.action, ['create', 'replace', 'preserve']) ||
        typeof row.lineEndingsChanged !== 'boolean' || !keys(row.after, ['text', 'byteLength', 'sha256']) || !text(row.after.text, METADATA_TEXT_FIELD_BYTES, true) ||
        row.after.byteLength !== encoder.encode(row.after.text).byteLength || !digest(row.after.sha256)) return false;
    if (keys(row.before, ['state']) && row.before.state === 'absent') return row.action === 'create' &&
      row.lineEndingsChanged === (metadataLineEndings(row.after.text) !== 'No line endings');
    if (!keys(row.before, ['state', 'text', 'byteLength', 'sha256']) || row.before.state !== 'present' || !text(row.before.text, METADATA_TEXT_FIELD_BYTES, true) ||
        row.before.byteLength !== encoder.encode(row.before.text).byteLength || !digest(row.before.sha256) ||
        row.lineEndingsChanged !== (metadataLineEndings(row.before.text) !== metadataLineEndings(row.after.text))) return false;
    const same = row.before.text === row.after.text;
    if (same !== (row.before.byteLength === row.after.byteLength && row.before.sha256 === row.after.sha256)) return false;
    return row.action === (same ? 'preserve' : 'replace');
  })) return false;
  const result = value as unknown as PreparedMetadataTextView;
  let previous: string | null = null;
  return result.createDirectories.every((path) => {
    if (!relativePath(path, 11) || previous !== null && (path.split('/').length < previous.split('/').length ||
        path.split('/').length === previous.split('/').length && path <= previous)) return false;
    previous = path;
    return result.files.some((file) => file.action !== 'preserve' && file.path.startsWith(`${path}/`)) &&
      !result.files.some((file) => file.action === 'preserve' && file.path.startsWith(`${path}/`));
  });
}
function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) || !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) || !oneOf(value.resources, ['settled', 'unknown']) || !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created' || oneOf(value.effect, ['committed', 'rolled_back']) && value.journal === 'not_created') return false;
  return value.reason !== 'none' || value.resources === 'settled' && value.effect !== 'unknown' && !oneOf(value.journal, ['unknown', 'recovery_required']);
}
function projection(value: unknown): value is MetadataTextEditProjection {
  if (!keys(value, ['domain', 'projectId', 'sessionId', 'ownerGeneration', 'platform', 'locale', 'phase', 'reviewRemainingMs', 'checkout', 'prepared', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled']) ||
      value.domain !== 'metadata_text' || !projectId(value.projectId) || !token(value.sessionId) || !token(value.ownerGeneration) || !platform(value.platform) || !locale(value.locale) ||
      !oneOf(value.phase, phases) || !length(value.reviewRemainingMs, 900000) || typeof value.applySubmitted !== 'boolean' || typeof value.lateSettled !== 'boolean' ||
      !oneOf(value.nativeReason, nativeReasons) || !oneOf(value.nativeFinality, ['pending', 'settled', 'unknown']) || !(value.coreOutcome === null || outcome(value.coreOutcome))) return false;
  const checkout = value.checkout;
  if (checkout !== null && (!keys(checkout, ['revision', 'metadataRoot', 'baseline']) || !token(checkout.revision) || !relativePath(checkout.metadataRoot, 9) || !baseline(checkout.baseline, value.platform))) return false;
  const prepared = value.prepared;
  if (prepared !== null && (!keys(prepared, ['revision', 'planToken', 'draftRevision', 'baselineGeneration', 'view']) || !token(prepared.revision) || !token(prepared.planToken) ||
      !isU32(prepared.draftRevision) || !isU32(prepared.baselineGeneration) || !preparedView(prepared.view) || !record(checkout) || prepared.revision !== checkout.revision)) return false;
  const result = value as unknown as MetadataTextEditProjection;
  if (result.prepared && (result.prepared.view.platform !== result.platform || result.prepared.view.locale !== result.locale || result.prepared.view.metadataRoot !== result.checkout?.metadataRoot ||
      !result.prepared.view.files.every((file, index) => equal(file.before.state === 'absent' ? { id: file.id, state: 'absent' } :
        { id: file.id, state: 'present', byteLength: file.before.byteLength, sha256: file.before.sha256 }, result.checkout?.baseline.fields[index])))) return false;
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
    if (result.coreOutcome.effect === 'unchanged' ? !metadataNoOp(result.prepared.view) : metadataNoOp(result.prepared.view)) return false;
  }
  return true;
}
export function parseMetadataTextEditStatus(value: unknown): MetadataTextEditStatus | null {
  try {
    if (!boundedJson(value, 2 * 1024 * 1024) || !keys(value, ['schemaVersion', 'domain', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
        value.schemaVersion !== 1 || value.domain !== 'metadata_text' || !token(value.windowGeneration) || !isU32(value.statusRevision) ||
        !keys(value.capability, ['available', 'reason']) || typeof value.capability.available !== 'boolean' || !oneOf(value.capability.reason, availability) ||
        value.capability.available !== (value.capability.reason === 'available') || !(value.active === null || projection(value.active)) || !(value.lastTerminal === null || projection(value.lastTerminal))) return null;
    const result = value as unknown as MetadataTextEditStatus;
    if (result.active?.phase === 'final' || result.active?.lateSettled || result.active && result.capability.reason === 'other_edit_active' ||
        result.lastTerminal && !['final', 'unknown'].includes(result.lastTerminal.phase) || result.active && result.active.sessionId === result.lastTerminal?.sessionId) return null;
    return result;
  } catch { return null; }
}
export function normalMetadataTextResult(owner: MetadataTextEditProjection): 'saved' | 'unchanged' | null {
  const core = owner.coreOutcome;
  if (owner.domain !== 'metadata_text' || owner.phase !== 'final' || owner.nativeFinality !== 'settled' || owner.nativeReason !== 'none' || owner.lateSettled ||
      !core || core.resources !== 'settled' || core.reason !== 'none' || !owner.applySubmitted || !owner.checkout || !owner.prepared || owner.prepared.revision !== owner.checkout.revision) return null;
  if (core.effect === 'committed' && core.journal === 'clean' && !metadataNoOp(owner.prepared.view)) return 'saved';
  if (core.effect === 'unchanged' && core.journal === 'not_created' && metadataNoOp(owner.prepared.view)) return 'unchanged';
  return null;
}
function sameFacts(first: MetadataTextEditProjection, next: MetadataTextEditProjection): boolean {
  return equal({ ...first, reviewRemainingMs: 0 }, { ...next, reviewRemainingMs: 0 });
}
export function metadataProjectionProgress(first: MetadataTextEditProjection, next: MetadataTextEditProjection): boolean {
  if (first.domain !== next.domain || first.sessionId !== next.sessionId || first.projectId !== next.projectId || first.ownerGeneration !== next.ownerGeneration ||
      first.platform !== next.platform || first.locale !== next.locale || first.checkout !== null && !equal(first.checkout, next.checkout) ||
      first.prepared !== null && !equal(first.prepared, next.prepared) || first.applySubmitted && !next.applySubmitted || first.lateSettled && !next.lateSettled) return false;
  if (first.phase === 'final') return sameFacts(first, next);
  if (first.phase === 'unknown' && next.phase !== 'unknown' || phases.indexOf(next.phase) < phases.indexOf(first.phase) || first.nativeReason !== 'none' && first.nativeReason !== next.nativeReason) return false;
  if (first.coreOutcome && (!next.coreOutcome || first.coreOutcome.effect !== 'unknown' && first.coreOutcome.effect !== next.coreOutcome.effect ||
      first.coreOutcome.reason !== 'none' && first.coreOutcome.reason !== next.coreOutcome.reason ||
      first.coreOutcome.journal !== 'unknown' && first.coreOutcome.journal !== next.coreOutcome.journal ||
      first.coreOutcome.resources === 'settled' && next.coreOutcome.resources !== 'settled')) return false;
  return true;
}
export function metadataStatusProgress(first: MetadataTextEditStatus, next: MetadataTextEditStatus): boolean {
  if (first.windowGeneration !== next.windowGeneration || next.statusRevision < first.statusRevision) return true;
  if (next.statusRevision === first.statusRevision) return equal(first.capability, next.capability) && (['active', 'lastTerminal'] as const).every((key) => {
    const before = first[key]; const after = next[key];
    return before === null || after === null ? before === after : sameFacts(before, after);
  });
  return [first.active, first.lastTerminal].every((before) => {
    if (!before) return true;
    const after = [next.active, next.lastTerminal].find((row) => row?.sessionId === before.sessionId);
    return !after || metadataProjectionProgress(before, after);
  });
}

const errors: Record<string, string> = {
  metadata_text_invalid_params: 'Metadata text input has an unsupported shape or size.',
  metadata_text_unavailable: 'Selected public text observation is unavailable on this platform.',
  metadata_text_config_missing: 'Save the project configuration before loading locale text.',
  metadata_text_config_invalid: 'The saved configuration is invalid; correct it before loading locale text.',
  metadata_text_not_configured: 'Select an enabled platform and a locale declared in the saved configuration.',
  metadata_text_unsafe: 'A selected public text path cannot be read safely.',
  metadata_text_changed: 'The selected configuration or public text changed during observation.',
  metadata_text_unreadable: 'The selected configuration or public text could not be read.',
  metadata_text_limit: 'The selected public text exceeds the bounded editor observation limit.',
  metadata_text_encoding: 'A selected public text file is not valid UTF-8.',
  metadata_text_sensitive: 'A selected public text file may contain secret material; no contents were returned.',
  metadata_text_cleanup_unknown: 'Original observation resource cleanup could not be confirmed.',
  MetadataTextResponseInvalid: 'The metadata response did not satisfy its closed contract. Your draft was kept; no observation or validation was accepted.',
  MetadataTextStatusInvalid: 'Native metadata status did not satisfy its closed contract. Keep the draft and original evidence; no save was confirmed.',
  MetadataTextHelpUnavailable: 'The packaged public-text guide is unavailable. No replacement metadata policy was invented.',
  MetadataTextRequestInvalid: 'The metadata request exceeds its closed shape or size. Nothing was truncated or submitted.',
  MetadataTextCacheFull: 'The in-memory public-text cache is full. Explicitly discard a retained locale draft before admitting more text; nothing was evicted.',
  MetadataTextDraftLimit: 'This draft exceeds 32 KiB of valid UTF-8 per field. The previous draft was kept; no text was truncated.',
  MetadataTextContextChanged: 'The project, saved configuration, locale, text or service context changed. The earlier result was retired and your draft was kept.',
  MetadataTextUnavailable: 'Public-text operations need the compatible native service. Browser preview cannot read, validate or save locale files.',
};
export function metadataTextError(error: unknown): ApiError {
  let code = 'MetadataTextUnavailable';
  try {
    if (record(error)) {
      const value: unknown = Object.getOwnPropertyDescriptor(error, 'code')?.value;
      if (typeof value === 'string' && Object.hasOwn(errors, value)) code = value;
    }
  } catch { /* Never echo arbitrary bridge rejection values. */ }
  return { code, message: errors[code]!, retryable: false };
}
