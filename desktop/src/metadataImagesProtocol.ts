// Closed transport/display consistency only. Shared core policy and the
// original native owner decide image admission, safe paths and write authority.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import type { ApiError, CoreEditOutcome, JsonValue } from './types.ts';
import type { MetadataPlatform } from './metadataText.ts';
import type { ImageSummary, MetadataImagesBaseline, MetadataImagesCatalog, MetadataImagesCommand, MetadataImagesEditProjection,
  MetadataImagesEditStatus, MetadataImagesSelection, MetadataImagesSelectionStatus, MetadataImagesImportView, MetadataImagesRecoveryView,
  MetadataImagesView, MetadataImagesCheckout, MetadataImagesPrepared, MetadataImagesHelp, MetadataImageHelpId,
  MetadataImageTypeChoice, MetadataImagesLimits, PrepareMetadataImagesRequest } from './metadataImages.ts';

export const METADATA_IMAGES_EDIT_EVENT = 'mrk://metadata-images-edit';
export const METADATA_IMAGES_SELECTION_EVENT = 'mrk://metadata-images-selection';
const encoder = new TextEncoder();
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const availability = ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active'];
const selectionReasons = ['none', 'cancelled', 'dialog_failed', 'unsupported_platform', 'runtime_unqualified', 'invalid_selection', 'source_changed',
  'source_unavailable', 'selection_limit', 'busy', 'caller_lost', 'window_lost', 'shutdown', 'active_timeout', 'cleanup_unknown'];
const helpIds: MetadataImageHelpId[] = ['platform', 'locale', 'assetType', 'files', 'replaceExisting', 'copyConfirmation', 'recoveryConfirmation'];
const MAX_FILE_BYTES = 10485760;
const MAX_BATCH_BYTES = 25165824;
// Transport/display bounds, not a replacement Store policy or native frame cap.
const MAX_ROWS = 512;
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
function platform(value: unknown): value is MetadataPlatform { return value === 'android' || value === 'ios'; }
function locale(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{1,11}(?![\s\S])/.test(value); }
function assetType(value: unknown): value is string { return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,95}(?![\s\S])/.test(value); }
function displayName(value: unknown): value is string {
  // Native source labels are display DATA; core separately derives portable destinations.
  return text(value, 255) && !/[\\/\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value) &&
    value !== '.' && value !== '..';
}
function relativePath(value: unknown): value is string {
  if (!text(value, 1024) || value.normalize('NFC') !== value || /[\\:<>"|?*\u0000-\u001f\u007f]/u.test(value)) return false;
  const parts = value.split('/');
  const reserved = ['private', 'secrets', 'credentials', 'review', 'testflight', 'build', 'deriveddata', 'pods', 'node_modules', 'venv', 'dist', 'target', '__pycache__'];
  return parts.length <= 20 && parts.every((part) => part.length > 0 && encoder.encode(part).byteLength <= 255 && !part.startsWith('.') && !reserved.includes(part.toLowerCase()) &&
    !/[. ]$/.test(part) && !/^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(part));
}
function contentDigest(value: unknown, maximum = U32_MAX): boolean {
  return keys(value, ['byteLength', 'sha256']) && length(value.byteLength, maximum) && digest(value.sha256);
}
function baseline(value: unknown): value is MetadataImagesBaseline {
  return keys(value, ['config', 'ignore', 'inventorySha256']) && contentDigest(value.config) && contentDigest(value.ignore) && digest(value.inventorySha256);
}
function imageSummary(value: unknown): value is ImageSummary {
  if (!keys(value, ['byteLength', 'sha256', 'format', 'width', 'height', 'headerChecked']) ||
      !length(value.byteLength, MAX_FILE_BYTES) || !digest(value.sha256) ||
      !(value.format === null || oneOf(value.format, ['png', 'jpeg'])) || typeof value.headerChecked !== 'boolean' ||
      !(value.width === null || isU32(value.width) && value.width > 0) || !(value.height === null || isU32(value.height) && value.height > 0)) return false;
  return !value.headerChecked || value.format !== null && value.width !== null && value.height !== null;
}
function sameContent(first: ImageSummary, next: ImageSummary): boolean {
  return first.byteLength === next.byteLength && first.sha256 === next.sha256;
}
function issues(value: unknown): boolean {
  return Array.isArray(value) && value.length <= MAX_ROWS && value.every((row) =>
    keys(row, ['code', 'severity', 'message']) && typeof row.code === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}(?![\s\S])/.test(row.code) && row.severity === 'error' && text(row.message, 2048));
}
function importAssurance(value: unknown): boolean {
  return keys(value, ['localCopyOnly', 'sourceFilesUnchanged', 'storeContacted', 'fullDecode', 'contentApproved', 'storeAccepted']) &&
    value.localCopyOnly === true && value.sourceFilesUnchanged === true && value.storeContacted === false &&
    value.fullDecode === false && value.contentApproved === false && value.storeAccepted === false;
}
// Python/core lexical order is Unicode code-point order, not locale sorting or
// JavaScript's UTF-16 ordering for non-BMP filenames. Do not reorder user input.
function lexical(first: string, next: string): number {
  const a = Array.from(first), b = Array.from(next);
  for (let i = 0; i < Math.min(a.length, b.length); i += 1) {
    const difference = a[i]!.codePointAt(0)! - b[i]!.codePointAt(0)!;
    if (difference) return difference;
  }
  return a.length - b.length;
}
function unique(values: readonly string[]): boolean { return new Set(values).size === values.length; }
export function parseMetadataImagesHelp(value: unknown): MetadataImagesHelp | null {
  try {
    if (!boundedJson(value, 65536, 2048, 8) || !keys(value, ['schemaVersion', 'fields']) || value.schemaVersion !== 1 ||
        !Array.isArray(value.fields) || value.fields.length !== helpIds.length) return null;
    const strings = ['label', 'requiredWhen', 'what', 'why', 'where', 'format', 'failure'];
    if (!value.fields.every((row, index) => keys(row, ['id', 'requiredness', ...strings]) && row.id === helpIds[index] &&
      oneOf(row.requiredness, ['required', 'optional']) && strings.every((key) => text(row[key], 2048)))) return null;
    return value as unknown as MetadataImagesHelp;
  } catch { return null; }
}
export function parseMetadataImagesCatalog(value: unknown): MetadataImagesCatalog | null {
  try {
    if (!boundedJson(value, 262144, 10000, 12) || !keys(value, ['schemaVersion', 'policy', 'platforms', 'types', 'limits', 'help']) ||
        value.schemaVersion !== 1 || value.policy !== 'metadata-images-v1' || !Array.isArray(value.platforms) ||
        value.platforms.length < 1 || value.platforms.length > 2 || !value.platforms.every((row) =>
          keys(row, ['id', 'label']) && platform(row.id) && text(row.label, 128)) ||
        !unique(value.platforms.map((row) => (row as { id: string }).id)) || !Array.isArray(value.types) || value.types.length < 1 || value.types.length > 128 ||
        !keys(value.limits, ['maxFiles', 'maxFileBytes', 'maxBatchBytes', 'maxTransactionBytes', 'maxDimension', 'maxPixels', 'formats']) ||
        value.limits.maxFiles !== 10 || value.limits.maxFileBytes !== MAX_FILE_BYTES || value.limits.maxBatchBytes !== MAX_BATCH_BYTES ||
        value.limits.maxTransactionBytes !== 67108864 || value.limits.maxDimension !== 16384 || value.limits.maxPixels !== 67108864 ||
        !equal(value.limits.formats, ['png', 'jpeg']) || !parseMetadataImagesHelp({ schemaVersion: 1, fields: value.help })) return null;
    const platforms = value.platforms.map((row) => (row as { id: string }).id);
    if (!value.types.every((row) => keys(row, ['platform', 'id', 'label', 'singleton', 'maxCount', 'dimensions']) &&
      platform(row.platform) && platforms.includes(row.platform) && assetType(row.id) && text(row.label, 256) && typeof row.singleton === 'boolean' &&
      length(row.maxCount, MAX_ROWS) && row.maxCount > 0 && (!row.singleton || row.maxCount === 1) &&
      Array.isArray(row.dimensions) && row.dimensions.length <= 256 && (row.platform !== 'android' || row.dimensions.length === 0) &&
      row.dimensions.every((pair) => Array.isArray(pair) && pair.length === 2 && pair.every((dimension) => isU32(dimension) && dimension > 0)))) return null;
    if (!unique(value.types.map((row) => { const type = row as { platform: string; id: string }; return type.platform + '/' + type.id; }))) return null;
    return value as unknown as MetadataImagesCatalog;
  } catch { return null; }
}
export function imageCatalogTypes(catalog: MetadataImagesCatalog, selected: MetadataPlatform): MetadataImageTypeChoice[] {
  return catalog.types.filter((row) => row.platform === selected).map((row) => ({ id: row.id, label: row.label,
    description: (row.singleton ? 'One image in this slot.' : 'Up to ' + row.maxCount + ' images in this slot.') + ' ' +
      (row.dimensions.length ? 'Catalogue dimensions (width × height): ' + row.dimensions.map(([width, height]) => width + ' × ' + height).join(', ') + '.' :
        'No exact Store dimension table is supplied for this slot; bounded header checks do not prove Store acceptance.') }));
}
export function imageCatalogLimits(catalog: MetadataImagesCatalog): MetadataImagesLimits {
  return { maxFiles: catalog.limits.maxFiles, maxFileBytes: catalog.limits.maxFileBytes, maxBatchBytes: catalog.limits.maxBatchBytes };
}
export function imageFieldHelp(catalog: MetadataImagesCatalog | null, id: MetadataImageHelpId): MetadataImagesHelp['fields'][number] | null {
  return catalog?.help.find((row) => row.id === id) ?? null;
}
export function metadataImagesRequestFits(command: MetadataImagesCommand, value: unknown): boolean {
  try {
    if (!boundedJson(value, 16384, 1024, 12)) return false;
    switch (command) {
      case 'metadata_images_catalog': case 'metadata_images_selection_status': case 'metadata_images_edit_status': return keys(value, []);
      case 'metadata_images_choose':
        return keys(value, ['projectId', 'platform', 'locale', 'assetType']) && projectId(value.projectId) && platform(value.platform) && locale(value.locale) && assetType(value.assetType);
      case 'metadata_images_selection_cancel': return keys(value, ['operationId']) && token(value.operationId);
      case 'metadata_images_edit_open': return keys(value, ['projectId', 'selectionToken']) && projectId(value.projectId) && token(value.selectionToken);
      case 'metadata_images_recovery_open': return keys(value, ['projectId']) && projectId(value.projectId);
      case 'metadata_images_edit_close': return keys(value, ['sessionId']) && token(value.sessionId);
      case 'metadata_images_edit_apply': return keys(value, ['sessionId', 'planToken']) && token(value.sessionId) && token(value.planToken);
      case 'metadata_images_edit_prepare':
        return keys(value, ['sessionId', 'revision', 'draftRevision', 'baselineGeneration', 'expectedBaseline', 'choices']) &&
          token(value.sessionId) && token(value.revision) && isU32(value.draftRevision) && value.draftRevision < U32_MAX &&
          isU32(value.baselineGeneration) && value.baselineGeneration < U32_MAX && baseline(value.expectedBaseline) &&
          Array.isArray(value.choices) && value.choices.length <= 10 && value.choices.every((row) =>
            keys(row, ['itemId', 'replaceExisting']) && token(row.itemId) && typeof row.replaceExisting === 'boolean') &&
          unique(value.choices.map((row) => (row as { itemId: string }).itemId));
    }
  } catch { return false; }
}
function importView(value: unknown): value is MetadataImagesImportView {
  if (!keys(value, ['kind', 'policy', 'platform', 'locale', 'assetType', 'metadataRoot', 'folder', 'files', 'existing', 'finalOrder', 'valid', 'issues', 'assurance']) ||
      value.kind !== 'import' || value.policy !== 'metadata-images-v1' || !platform(value.platform) || !locale(value.locale) || !assetType(value.assetType) ||
      !relativePath(value.metadataRoot) || !relativePath(value.folder) || !value.folder.startsWith(value.metadataRoot + '/') ||
      !Array.isArray(value.files) || value.files.length < 1 || value.files.length > 10 ||
      !Array.isArray(value.existing) || value.existing.length > MAX_ROWS || !Array.isArray(value.finalOrder) || value.finalOrder.length > MAX_ROWS ||
      typeof value.valid !== 'boolean' || !issues(value.issues) || !importAssurance(value.assurance)) return false;
  const folder = value.folder;
  const target = (path: unknown): path is string => relativePath(path) && path.startsWith(folder + '/') && !path.slice(folder.length + 1).includes('/');
  if (!value.files.every((row) => keys(row, ['itemId', 'displayName', 'path', 'action', 'before', 'selected', 'after', 'canReplace', 'issues']) &&
    token(row.itemId) && displayName(row.displayName) && target(row.path) && oneOf(row.action, ['create', 'replace', 'preserve']) &&
    (row.before === null || imageSummary(row.before)) && imageSummary(row.selected) && imageSummary(row.after) &&
    typeof row.canReplace === 'boolean' && issues(row.issues)) ||
    !value.existing.every((row) => keys(row, ['path', 'summary']) && target(row.path) && imageSummary(row.summary)) ||
    !value.finalOrder.every(target)) return false;
  const result = value as unknown as MetadataImagesImportView;
  if (!unique(result.files.map((row) => row.itemId)) || !unique(result.existing.map((row) => row.path)) ||
      !unique(result.finalOrder) || result.files.reduce((sum, row) => sum + row.selected.byteLength, 0) > MAX_BATCH_BYTES) return false;
  if (!result.files.every((row) => {
    const original = result.existing.find((item) => item.path === row.path);
    if (row.before === null ? Boolean(original) : !original || !equal(original.summary, row.before)) return false;
    if (row.canReplace && (row.before === null || sameContent(row.before, row.selected))) return false;
    if (row.action === 'create') return row.before === null && !row.canReplace && equal(row.after, row.selected);
    if (row.action === 'replace') return row.before !== null && row.canReplace && !sameContent(row.before, row.selected) && equal(row.after, row.selected);
    return row.before !== null && equal(row.after, row.before);
  })) return false;
  const paths = [...new Set([...result.existing.map((row) => row.path), ...result.files.map((row) => row.path)])].sort(lexical);
  if (!equal(result.finalOrder, [...result.finalOrder].sort(lexical)) ||
      (result.valid ? !equal(result.finalOrder, paths) : result.finalOrder.some((path) => !paths.includes(path)))) return false;
  return !result.valid || result.issues.length === 0 && unique(result.files.map((row) => row.path)) &&
    result.files.every((row) => row.issues.length === 0 && row.after.headerChecked && row.selected.headerChecked);
}
function recoveryView(value: unknown): value is MetadataImagesRecoveryView {
  if (!keys(value, ['kind', 'state', 'action', 'transactionId', 'platform', 'locale', 'assetType', 'files', 'privateCleanup', 'valid', 'issues', 'assurance']) ||
      value.kind !== 'recover' || !oneOf(value.state, ['idle', 'recoverable', 'conflict']) ||
      !(value.action === null || oneOf(value.action, ['rollback', 'committed_cleanup', 'rolled_back_cleanup', 'preparing_cleanup'])) ||
      !(value.transactionId === null || token(value.transactionId)) || !(value.platform === null || platform(value.platform)) ||
      !(value.locale === null || locale(value.locale)) || !(value.assetType === null || assetType(value.assetType)) ||
      !Array.isArray(value.files) || value.files.length > MAX_ROWS || typeof value.valid !== 'boolean' || !issues(value.issues) ||
      !keys(value.privateCleanup, ['fileCount', 'directoryCount', 'scope']) || !length(value.privateCleanup.fileCount, 4096) ||
      !length(value.privateCleanup.directoryCount, 4096) || value.privateCleanup.scope !== 'original-image-journal-only' ||
      !keys(value.assurance, ['newRestorationAttempt', 'sourceFilesUnchanged', 'storeContacted', 'importRetried']) ||
      value.assurance.newRestorationAttempt !== true || value.assurance.sourceFilesUnchanged !== true ||
      value.assurance.storeContacted !== false || value.assurance.importRetried !== false ||
      !value.files.every((row) => keys(row, ['path', 'effect', 'original', 'new']) && relativePath(row.path) &&
        oneOf(row.effect, ['restore_original', 'keep_committed', 'preserve']) &&
        (row.original === null || contentDigest(row.original, MAX_FILE_BYTES)) && (row.new === null || contentDigest(row.new, MAX_FILE_BYTES)))) return false;
  const result = value as unknown as MetadataImagesRecoveryView;
  if (!unique(result.files.map((row) => row.path))) return false;
  if (result.state === 'idle') return !result.valid && result.action === null && result.transactionId === null && result.platform === null &&
    result.locale === null && result.assetType === null && result.files.length === 0 && result.issues.length === 0 &&
    result.privateCleanup.fileCount === 0 && result.privateCleanup.directoryCount === 0;
  if (result.state === 'conflict') return result.valid === false;
  return !result.valid || result.action !== null && result.issues.length === 0;
}
function view(value: unknown): value is MetadataImagesView { return importView(value) || recoveryView(value); }
function checkout(value: unknown): value is MetadataImagesCheckout {
  return keys(value, ['revision', 'baseline', 'view']) && token(value.revision) && baseline(value.baseline) && view(value.view);
}
function preparedMatchesCheckout(opened: MetadataImagesCheckout, prepared: MetadataImagesPrepared): boolean {
  if (prepared.revision !== opened.revision || prepared.view.kind !== opened.view.kind || !prepared.view.valid) return false;
  if (prepared.view.kind === 'recover') return opened.view.kind === 'recover' && prepared.view.state === 'recoverable' && equal(prepared.view, opened.view);
  if (opened.view.kind !== 'import') return false;
  const before = opened.view; const after = prepared.view;
  return before.platform === after.platform && before.locale === after.locale && before.assetType === after.assetType &&
    before.metadataRoot === after.metadataRoot && before.folder === after.folder && equal(before.existing, after.existing) &&
    after.files.length === before.files.length && after.files.every((row, index) => {
      const original = before.files[index]!;
      return row.itemId === original.itemId && row.displayName === original.displayName && row.path === original.path &&
        row.canReplace === original.canReplace && equal(row.before, original.before) && equal(row.selected, original.selected);
    });
}
export function imagePreparedMatches(owner: MetadataImagesEditProjection, request: PrepareMetadataImagesRequest): boolean {
  const opened = owner.details?.checkout, prepared = owner.details?.prepared;
  if (!opened || !prepared || owner.sessionId !== request.sessionId || opened.revision !== request.revision ||
      prepared.draftRevision !== request.draftRevision || prepared.baselineGeneration !== request.baselineGeneration ||
      !equal(opened.baseline, request.expectedBaseline) || !preparedMatchesCheckout(opened, prepared)) return false;
  if (prepared.view.kind === 'recover') return request.choices.length === 0;
  if (request.choices.length !== prepared.view.files.length) return false;
  return prepared.view.files.every((row, index) => {
    const choice = request.choices[index]!;
    if (choice.itemId !== row.itemId || choice.replaceExisting && !row.canReplace) return false;
    const action = row.before === null ? 'create' : sameContent(row.before, row.selected) || !choice.replaceExisting ? 'preserve' : 'replace';
    return action === row.action;
  });
}
function capability(value: unknown): boolean {
  return keys(value, ['available', 'reason']) && typeof value.available === 'boolean' && oneOf(value.reason, availability) &&
    value.available === (value.reason === 'available');
}
export function imageSelectionSettled(row: MetadataImagesSelection): boolean {
  return row.settlement === 'known' && ['selected', 'cancelled', 'failed'].includes(row.phase);
}
function selection(value: unknown): value is MetadataImagesSelection {
  if (!keys(value, ['operationId', 'projectId', 'platform', 'locale', 'assetType', 'phase', 'reason', 'settlement', 'selectionToken', 'items']) ||
      !token(value.operationId) || !projectId(value.projectId) || !platform(value.platform) || !locale(value.locale) || !assetType(value.assetType) ||
      !oneOf(value.phase, ['selecting', 'capturing', 'selected', 'cancelled', 'failed', 'unknown']) || !oneOf(value.reason, selectionReasons) ||
      !oneOf(value.settlement, ['pending', 'known', 'unknown', 'late-known']) || !(value.selectionToken === null || token(value.selectionToken)) ||
      !Array.isArray(value.items) || value.items.length > 10 || !value.items.every((row) =>
        keys(row, ['itemId', 'displayName', 'byteLength', 'sha256']) && token(row.itemId) && displayName(row.displayName) &&
        length(row.byteLength, MAX_FILE_BYTES) && digest(row.sha256))) return false;
  const result = value as unknown as MetadataImagesSelection;
  if (!unique(result.items.map((row) => row.itemId)) || result.items.reduce((sum, row) => sum + row.byteLength, 0) > MAX_BATCH_BYTES) return false;
  if (result.phase === 'selected') return result.reason === 'none' && result.settlement === 'known' && result.items.length > 0;
  if (result.selectionToken !== null) return false;
  if (result.phase === 'selecting' || result.phase === 'capturing') return result.settlement === 'pending';
  if (result.phase === 'unknown') return result.settlement === 'unknown' || result.settlement === 'late-known';
  return result.reason !== 'none' && (result.settlement === 'known' || result.settlement === 'late-known');
}
export function parseMetadataImagesSelectionStatus(value: unknown): MetadataImagesSelectionStatus | null {
  try {
    if (!boundedJson(value, 65536, 4096, 12) || !keys(value, ['schemaVersion', 'domain', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
        value.schemaVersion !== 1 || value.domain !== 'metadata_images_selection' || !token(value.windowGeneration) || !isU32(value.statusRevision) ||
        !capability(value.capability) || !(value.active === null || selection(value.active)) || !(value.lastTerminal === null || selection(value.lastTerminal))) return null;
    const result = value as unknown as MetadataImagesSelectionStatus;
    if (result.active && (imageSelectionSettled(result.active) || result.active.settlement === 'late-known') ||
        result.lastTerminal && ['selecting', 'capturing'].includes(result.lastTerminal.phase) ||
        result.active && result.active.operationId === result.lastTerminal?.operationId) return null;
    return result;
  } catch { return null; }
}
function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) || !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) || !oneOf(value.resources, ['settled', 'unknown']) || !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created' || oneOf(value.effect, ['committed', 'rolled_back']) && value.journal === 'not_created') return false;
  return value.reason !== 'none' || value.resources === 'settled' && value.effect !== 'unknown' && !oneOf(value.journal, ['unknown', 'recovery_required']);
}
function projection(value: unknown): value is MetadataImagesEditProjection {
  if (!keys(value, ['domain', 'projectId', 'sessionId', 'ownerGeneration', 'phase', 'reviewRemainingMs', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled', 'details']) ||
      value.domain !== 'metadata_images' || !projectId(value.projectId) || !token(value.sessionId) || !token(value.ownerGeneration) ||
      !oneOf(value.phase, phases) || !length(value.reviewRemainingMs, 900000) || typeof value.applySubmitted !== 'boolean' ||
      typeof value.lateSettled !== 'boolean' || !oneOf(value.nativeReason, nativeReasons) || !oneOf(value.nativeFinality, ['pending', 'settled', 'unknown']) ||
      !(value.coreOutcome === null || outcome(value.coreOutcome))) return false;
  const details = value.details;
  if (details !== null) {
    if (!keys(details, ['intent', 'checkout', 'prepared']) || !oneOf(details.intent, ['import', 'recover']) ||
        !(details.checkout === null || checkout(details.checkout))) return false;
    const opened = details.checkout; const prepared = details.prepared;
    if (prepared !== null && (!keys(prepared, ['revision', 'planToken', 'draftRevision', 'baselineGeneration', 'view']) ||
        !token(prepared.revision) || !token(prepared.planToken) || !isU32(prepared.draftRevision) || prepared.draftRevision >= U32_MAX ||
        !isU32(prepared.baselineGeneration) || prepared.baselineGeneration >= U32_MAX || !view(prepared.view) ||
        !checkout(opened) || !preparedMatchesCheckout(opened, prepared as unknown as MetadataImagesPrepared))) return false;
    if (opened && checkout(opened) && opened.view.kind !== details.intent) return false;
  }
  const result = value as unknown as MetadataImagesEditProjection;
  const opened = result.details?.checkout, prepared = result.details?.prepared;
  if (result.phase === 'final') {
    if (result.nativeFinality !== 'settled' || result.lateSettled) return false;
    if (!result.coreOutcome) { if (opened || prepared || result.applySubmitted || result.nativeReason === 'none') return false; }
    else if (result.coreOutcome.resources === 'unknown' || result.coreOutcome.effect === 'unknown' || result.coreOutcome.journal === 'unknown') return false;
  } else if (result.phase === 'unknown') { if (result.nativeFinality !== 'unknown') return false; }
  else if (result.nativeFinality !== 'pending' || result.lateSettled) return false;
  if (result.phase === 'opening' && (opened || prepared || result.applySubmitted)) return false;
  if (['editing', 'preparing', 'reviewing', 'applying'].includes(result.phase) && !opened) return false;
  if (['editing', 'preparing'].includes(result.phase) && (prepared || result.applySubmitted)) return false;
  if (['reviewing', 'applying'].includes(result.phase) && !prepared) return false;
  if (result.phase === 'reviewing' && result.applySubmitted || result.phase === 'applying' && !result.applySubmitted || result.applySubmitted && !prepared) return false;
  if (['opening', 'editing', 'preparing', 'reviewing'].includes(result.phase) && result.coreOutcome !== null) return false;
  if (result.coreOutcome && ['committed', 'rolled_back', 'unchanged'].includes(result.coreOutcome.effect) && (!opened || !prepared || !result.applySubmitted)) return false;
  if (result.coreOutcome?.effect === 'unchanged' && (prepared?.view.kind !== 'import' || !prepared.view.files.every((row) => row.action === 'preserve'))) return false;
  return true;
}
export function parseMetadataImagesEditStatus(value: unknown): MetadataImagesEditStatus | null {
  try {
    if (!boundedJson(value, 1048576, 20000, 24) || !keys(value, ['schemaVersion', 'domain', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
        value.schemaVersion !== 1 || value.domain !== 'metadata_images' || !token(value.windowGeneration) || !isU32(value.statusRevision) ||
        !capability(value.capability) || !(value.active === null || projection(value.active)) || !(value.lastTerminal === null || projection(value.lastTerminal))) return null;
    const result = value as unknown as MetadataImagesEditStatus;
    if (result.active?.phase === 'final' || result.active?.lateSettled || result.active && result.active.ownerGeneration !== result.windowGeneration ||
        result.lastTerminal && (result.lastTerminal.ownerGeneration !== result.windowGeneration || !['final', 'unknown'].includes(result.lastTerminal.phase)) ||
        result.active && result.active.sessionId === result.lastTerminal?.sessionId) return null;
    return result;
  } catch { return null; }
}
export function metadataImagesSelectionProjectionProgress(first: MetadataImagesSelection, next: MetadataImagesSelection): boolean {
  if (first.operationId !== next.operationId || first.projectId !== next.projectId || first.platform !== next.platform ||
      first.locale !== next.locale || first.assetType !== next.assetType) return false;
  if (first.phase === 'unknown' || first.settlement === 'unknown' || first.settlement === 'late-known')
    return next.phase === first.phase && next.reason === first.reason && equal(first.items, next.items) && next.selectionToken === null &&
      (next.settlement === first.settlement || first.settlement === 'unknown' && next.settlement === 'late-known');
  // Snapshots can skip selected before the first STOP/Unknown. Only an
  // uninterrupted unselected sample may catch up immutable safe metadata.
  const uninterrupted = ['selecting', 'capturing'].includes(first.phase) && first.reason === 'none' &&
    first.settlement === 'pending' && first.selectionToken === null;
  const itemsProgress = uninterrupted ? first.items.every((item, index) => equal(item, next.items[index])) : equal(first.items, next.items);
  // Original/global uncertainty can overtake even an already consumed selection.
  // It never erases/replaces captured items or restores a selectable token.
  if (next.phase === 'unknown') return next.reason === 'cleanup_unknown' && next.selectionToken === null &&
    itemsProgress && (next.settlement === 'unknown' || next.settlement === 'late-known');
  if (first.phase === 'selected') {
    if (!equal(first.items, next.items)) return false;
    if (next.phase === 'selected') return next.reason === first.reason && next.settlement === first.settlement &&
      (first.selectionToken === next.selectionToken || first.selectionToken !== null && next.selectionToken === null);
    // STOP after a held selection can publish pending cleanup or skip directly
    // to known refusal/cancellation. Consumed success has no such cancel route.
    if (first.selectionToken === null || next.selectionToken !== null || next.reason === 'none') return false;
    return next.phase === 'capturing' && next.settlement === 'pending' ||
      (next.phase === 'cancelled' && next.reason === 'cancelled' || next.phase === 'failed') && next.settlement === 'known';
  }
  if (['cancelled', 'failed'].includes(first.phase)) return equal(first, next);
  if (first.phase === 'capturing' && next.phase === 'selecting') return false;
  if (first.reason !== 'none' || next.reason !== 'none') {
    // A previously latched STOP cannot change its reason, grow/drop the original safe
    // item roster, return to selected, or regain positive authority.
    return (first.reason === 'none' || first.reason === next.reason) && itemsProgress && next.selectionToken === null &&
      (['selecting', 'capturing'].includes(next.phase) && next.settlement === 'pending' ||
        (next.phase === 'cancelled' && next.reason === 'cancelled' || next.phase === 'failed') && next.settlement === 'known');
  }
  return first.items.every((item, index) => equal(item, next.items[index]));
}
export function metadataImagesSelectionProgress(first: MetadataImagesSelectionStatus, next: MetadataImagesSelectionStatus): boolean {
  if (first.windowGeneration !== next.windowGeneration || next.statusRevision < first.statusRevision) return false;
  if (next.statusRevision === first.statusRevision) return equal(first, next);
  for (const previous of [first.active, first.lastTerminal]) {
    if (!previous) continue;
    const after = [next.active, next.lastTerminal].find((row) => row?.operationId === previous.operationId);
    if (after ? !metadataImagesSelectionProjectionProgress(previous, after) :
        previous === first.active || previous.phase === 'selected' && previous.selectionToken !== null) return false;
  }
  return true;
}
function sameProjection(first: MetadataImagesEditProjection, next: MetadataImagesEditProjection): boolean {
  return equal({ ...first, reviewRemainingMs: 0 }, { ...next, reviewRemainingMs: 0 });
}
export function metadataImagesProjectionProgress(first: MetadataImagesEditProjection, next: MetadataImagesEditProjection): boolean {
  if (first.domain !== next.domain || first.sessionId !== next.sessionId || first.projectId !== next.projectId || first.ownerGeneration !== next.ownerGeneration ||
      first.details && (!next.details || first.details.intent !== next.details.intent) ||
      first.details?.checkout && !equal(first.details.checkout, next.details?.checkout) ||
      first.details?.prepared && !equal(first.details.prepared, next.details?.prepared) || first.applySubmitted && !next.applySubmitted || first.lateSettled && !next.lateSettled) return false;
  if (first.phase === 'final') return sameProjection(first, next);
  if (first.phase === 'unknown' && next.phase !== 'unknown' || phases.indexOf(next.phase) < phases.indexOf(first.phase) ||
      first.nativeReason !== 'none' && first.nativeReason !== next.nativeReason) return false;
  if (first.coreOutcome && (!next.coreOutcome || first.coreOutcome.effect !== 'unknown' && first.coreOutcome.effect !== next.coreOutcome.effect ||
      first.coreOutcome.reason !== 'none' && first.coreOutcome.reason !== next.coreOutcome.reason ||
      first.coreOutcome.journal !== 'unknown' && first.coreOutcome.journal !== next.coreOutcome.journal ||
      first.coreOutcome.resources === 'settled' && next.coreOutcome.resources !== 'settled')) return false;
  return true;
}
export function metadataImagesEditProgress(first: MetadataImagesEditStatus, next: MetadataImagesEditStatus): boolean {
  if (first.windowGeneration !== next.windowGeneration || next.statusRevision < first.statusRevision) return false;
  if (next.statusRevision === first.statusRevision) return equal(first.capability, next.capability) && (['active', 'lastTerminal'] as const).every((key) => {
    const before = first[key], after = next[key];
    return before === null || after === null ? before === after : sameProjection(before, after);
  });
  for (const previous of [first.active, first.lastTerminal]) {
    if (!previous) continue;
    const after = [next.active, next.lastTerminal].find((row) => row?.sessionId === previous.sessionId);
    if (after ? !metadataImagesProjectionProgress(previous, after) : previous === first.active) return false;
  }
  return true;
}
export function normalMetadataImagesResult(owner: MetadataImagesEditProjection): 'copied' | 'unchanged' | 'recovered' | null {
  const core = owner.coreOutcome, opened = owner.details?.checkout, prepared = owner.details?.prepared;
  if (owner.domain !== 'metadata_images' || owner.phase !== 'final' || owner.nativeFinality !== 'settled' || owner.nativeReason !== 'none' || owner.lateSettled ||
      !owner.applySubmitted || !core || core.resources !== 'settled' || core.reason !== 'none' || !opened || !prepared ||
      !preparedMatchesCheckout(opened, prepared)) return null;
  if (prepared.view.kind === 'recover') {
    const effects = { rollback: 'rolled_back', rolled_back_cleanup: 'rolled_back', committed_cleanup: 'committed', preparing_cleanup: 'not_started' } as const;
    return prepared.view.state === 'recoverable' && prepared.view.valid && prepared.view.action &&
      core.journal === 'clean' && core.effect === effects[prepared.view.action] ? 'recovered' : null;
  }
  const noOp = prepared.view.files.every((row) => row.action === 'preserve');
  if (noOp && core.effect === 'unchanged' && core.journal === 'not_created') return 'unchanged';
  return !noOp && core.effect === 'committed' && core.journal === 'clean' ? 'copied' : null;
}
const errorCopy: Record<string, string> = {
  metadata_images_selection_not_admitted: 'This Choose request was rejected before a new image selection owner was installed. Observe existing operations before another explicit action.',
  metadata_images_recovery_not_admitted: 'This recovery request was rejected before a new image edit owner was installed. No recovery was started by this request; preserve existing journals and observe their original operations.',
  metadata_images_import_not_matched: 'This Open request did not match an original project and image selection. It consumed no matching token and started no edit. The original selection remains subject to its own status and Stop.',
  metadata_images_import_not_admitted: 'This Open matched the original selection and permanently retired its token before any image edit owner was claimed. Observe the original selection until its own cleanup settles; do not retry this Open.',
  metadata_images_busy: 'The original image selection, review or cleanup still owns the native service. Observe or stop that original operation; do not reconnect around it.',
  metadata_images_unavailable: 'Localized image import needs a compatible, separately qualified native picker and file owner. Browser preview cannot select, inspect, copy or recover image files.',
  metadata_images_request_invalid: 'The image request has an unsupported shape or exceeds its small transport bound. Nothing was truncated or submitted.',
  metadata_images_catalog_invalid: 'The shared image catalogue or field guide did not satisfy its contract. No replacement Store policy was invented.',
  metadata_images_status_invalid: 'The original image status was contradictory or outside its closed contract. Keep the original files and evidence; no copy or cleanup is confirmed.',
  metadata_images_reply_lost: 'A native reply was not confirmed. Observe the original selection or edit status; do not repeat the operation.',
  metadata_images_context_changed: 'The saved project, locale, image type or service context changed. Earlier selection and confirmation cannot authorize a new copy.',
};
export function metadataImagesError(error: unknown): ApiError {
  let code = 'metadata_images_unavailable';
  try {
    if (record(error)) {
      const candidate: unknown = Object.getOwnPropertyDescriptor(error, 'code')?.value;
      if (typeof candidate === 'string' && Object.hasOwn(errorCopy, candidate)) code = candidate;
    }
  } catch { /* Never reflect OS errors, raw rejection data, filenames or bytes. */ }
  return { code, message: errorCopy[code]!, retryable: false };
}
