// One closed, read-only report. Consistency checks are not Store policy.
import imagePolicy from '../../src/mobile_release/api/data/metadata-images-v1.json' with { type: 'json' };
import { METADATA_TEXT_IDS } from './metadataText.ts';
import type { MetadataPlatform } from './metadataText.ts';
import { metadataBoundedJson, metadataKeys, metadataRelativePath, metadataAssurance } from './metadataTextProtocol.ts';
import { parseSavedConfigContent } from './offlinePreflightProtocol.ts';
import type { SavedConfigContent } from './offlinePreflightTypes.ts';
import type { ApiError, Assurance } from './types.ts';

export interface SavedMetadataRequest { projectId: string; platform: MetadataPlatform }
export interface SavedMetadataFile {
  kind: 'public-text' | 'android-note' | 'ios-note' | 'image';
  id: string; path: string | null; locale: string | null; required: boolean;
  state: 'checked' | 'missing' | 'invalid'; issues: string[];
}
export interface SavedMetadataImageSet { locale: string; id: string; count: number; required: false; issues: string[] }
export interface SavedMetadataReport {
  schemaVersion: 1; platform: MetadataPlatform; metadataRoot: string; locales: string[];
  androidBuild: number | null; savedConfig: SavedConfigContent;
  scope: 'configured-locales-canonical-images-fixed-notes'; observationScope: 'single-request-non-atomic';
  valid: boolean; state: 'checked' | 'issues'; files: SavedMetadataFile[];
  imageSets: SavedMetadataImageSet[]; assurance: Assurance & { basis: 'static-text' };
}
export interface SavedMetadataApi { validateMetadata(request: SavedMetadataRequest): Promise<SavedMetadataReport> }
export const SAVED_METADATA_RESULT_BYTES = 256 * 1024;
const MAX_ROWS = 2048;
const IOS_NOTES = ['review/ios-beta-notes.txt', 'review/ios-notes.txt', 'testflight/what-to-test.txt'];
const TEXT_CODES = ['metadata.empty-text', 'metadata.nul', 'metadata.placeholder', 'metadata.secret-pattern',
  'metadata.url', 'metadata.length', 'metadata.utf8', 'metadata.json'];
const IMAGE_CODES = ['image.empty', 'image.limit', 'image.format', 'image.header', 'image.extension',
  'image.dimensions', 'image.device', 'image.duplicate'];
const platform = (value: unknown): value is MetadataPlatform => value === 'android' || value === 'ios';
const integer = (value: unknown, max: number): value is number => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max;
const codes = (value: unknown, allowed: readonly string[]): value is string[] =>
  Array.isArray(value) && value.length <= allowed.length && value.every((code) => typeof code === 'string' && allowed.includes(code)) && new Set(value).size === value.length;
const basename = (value: unknown): value is string => typeof value === 'string' && !value.includes('/') && metadataRelativePath(value);
const suffix = (value: string, allowed: readonly string[]) => allowed.includes(value.slice(value.lastIndexOf('.') + 1).toLowerCase());
// Closed destination spelling mirrors core safe_name; it grants no write authority.
const imageBasename = (name: string) => basename(name) && name.length <= 255 &&
  /^[A-Za-z0-9][A-Za-z0-9._ -]{0,250}\.(?:png|jpg|jpeg)(?![\s\S])/i.test(name) && !name.includes('..');
const groupKey = (locale: string, id: string) => JSON.stringify([locale, id]);

export function savedMetadataRequestFits(value: unknown): value is SavedMetadataRequest {
  try {
    return metadataBoundedJson(value, 512, 8, 3) && metadataKeys(value, ['projectId', 'platform']) &&
      typeof value.projectId === 'string' && /^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(value.projectId) && platform(value.platform);
  } catch { return false; }
}
export function parseSavedMetadataReport(value: unknown): SavedMetadataReport | null {
  try {
    if (!metadataBoundedJson(value, SAVED_METADATA_RESULT_BYTES, 32768, 12) ||
      !metadataKeys(value, ['schemaVersion', 'platform', 'metadataRoot', 'locales', 'androidBuild', 'savedConfig', 'scope',
        'observationScope', 'valid', 'state', 'files', 'imageSets', 'assurance']) ||
      value.schemaVersion !== 1 || !platform(value.platform) || !metadataRelativePath(value.metadataRoot, 9) ||
      !Array.isArray(value.locales) || !value.locales.length || value.locales.length > MAX_ROWS ||
      !value.locales.every((locale) => typeof locale === 'string' && /^[\x20-\x7e]{2,12}(?![\s\S])/.test(locale) &&
        !locale.includes('/') && !locale.includes('\\')) ||
      !value.locales.every((locale, index, all) => !index || all[index - 1] < locale) ||
      (value.androidBuild !== null && (!integer(value.androidBuild, 0xffff_ffff) || value.androidBuild === 0)) ||
      value.platform === 'ios' && value.androidBuild !== null || !parseSavedConfigContent(value.savedConfig) ||
      value.scope !== 'configured-locales-canonical-images-fixed-notes' || value.observationScope !== 'single-request-non-atomic' ||
      typeof value.valid !== 'boolean' || value.state !== (value.valid ? 'checked' : 'issues') ||
      !metadataAssurance(value.assurance, 'static-text') || !Array.isArray(value.files) || value.files.length > MAX_ROWS ||
      !Array.isArray(value.imageSets) || value.imageSets.length > MAX_ROWS) return null;
    const selected = value.platform, root = value.metadataRoot, locales = value.locales as string[];
    const requiredIds: readonly string[] = METADATA_TEXT_IDS[selected];
    if (!locales.every((locale) => requiredIds.every((id) => metadataRelativePath(root + '/' + selected + '/' + locale + '/' + id)))) return null;
    const paths = new Set<string>(), fields = new Set<string>(), androidNotes = new Set<string>(), iosNotes = new Set<string>();
    const images = new Map<string, { count: number; duplicate: boolean; max: number }>();
    for (const row of value.files) {
      if (!metadataKeys(row, ['kind', 'id', 'path', 'locale', 'required', 'state', 'issues']) ||
        !['public-text', 'android-note', 'ios-note', 'image'].includes(row.kind as string) ||
        typeof row.id !== 'string' || !row.id || row.id.length > 255 || typeof row.required !== 'boolean' ||
        !['checked', 'missing', 'invalid'].includes(row.state as string) || !Array.isArray(row.issues) ||
        (row.state === 'checked') !== (row.issues.length === 0) ||
        row.locale !== null && (typeof row.locale !== 'string' || !locales.includes(row.locale)) ||
        row.path !== null && (typeof row.path !== 'string' || row.path.length > 512 ||
          new TextEncoder().encode(row.path).byteLength > 512 || row.path.split('/').length > 12 || paths.has(row.path.toLowerCase()))) return null;
      if (row.path !== null) paths.add((row.path as string).toLowerCase());
      if (row.state === 'missing') {
        if (!row.required || row.issues.length !== 1 || row.issues[0] !== 'metadata.missing') return null;
      } else if (!codes(row.issues, row.kind === 'image' ? IMAGE_CODES : row.kind === 'android-note' ?
        ['metadata.utf8', 'metadata.android-note', 'metadata.android-version'] : TEXT_CODES)) return null;
      if (row.kind === 'public-text') {
        if (typeof row.locale !== 'string' || !basename(row.id) || !suffix(row.id, ['txt', 'md', 'json']) ||
          row.required !== requiredIds.includes(row.id) || fields.has(groupKey(row.locale, row.id)) ||
          row.path !== root + '/' + selected + '/' + row.locale + '/' + row.id || !metadataRelativePath(row.path) ||
          row.issues.includes('metadata.json') && !suffix(row.id, ['json'])) return null;
        fields.add(groupKey(row.locale, row.id));
      } else if (row.kind === 'android-note') {
        if (selected !== 'android' || typeof row.locale !== 'string' || row.id !== 'release-notes' ||
          !row.required || androidNotes.has(row.locale)) return null;
        androidNotes.add(row.locale);
        if (value.androidBuild === null) {
          if (row.path !== null || row.state !== 'invalid' || row.issues.length !== 1 || row.issues[0] !== 'metadata.android-version') return null;
        } else {
          const folder = root + '/android/' + row.locale + '/changelogs';
          if (![folder + '/' + value.androidBuild + '.txt', folder + '/default.txt'].includes(row.path as string) ||
            row.issues.includes('metadata.android-version')) return null;
        }
      } else if (row.kind === 'ios-note') {
        if (selected !== 'ios' || row.locale !== null || !row.required || iosNotes.has(row.id) ||
          !IOS_NOTES.some((name) => name.split('/').at(-1) === row.id && row.path === root + '/' + name) || row.issues.includes('metadata.json')) return null;
        iosNotes.add(row.id);
      } else {
        if (typeof row.locale !== 'string' || !metadataRelativePath(row.path) || row.required || row.state === 'missing') return null;
        const kind = imagePolicy.types.find((kind) => kind.platform === selected && kind.id === row.id);
        if (!kind) return null;
        const index = row.path.lastIndexOf('/'), name = row.path.slice(index + 1);
        const folder = selected === 'ios' ? root + '/ios/screenshots/' + row.locale + '/' + row.id :
          root + '/android/' + row.locale + '/images' + (kind.singleton ? '' : '/' + row.id);
        if (row.path.slice(0, index) !== folder || !imageBasename(name) ||
          kind.singleton && !['png', 'jpg', 'jpeg'].some((ext) => name === row.id + '.' + ext)) return null;
        const key = groupKey(row.locale, row.id), group = images.get(key) ?? { count: 0, duplicate: false, max: kind.maxCount };
        group.count += 1; group.duplicate ||= row.issues.includes('image.duplicate'); images.set(key, group);
      }
    }
    if (!locales.every((locale) => requiredIds.every((id) => fields.has(groupKey(locale, id)))) ||
      selected === 'android' && androidNotes.size !== locales.length || selected === 'ios' && iosNotes.size !== IOS_NOTES.length ||
      value.imageSets.length !== images.size) return null;
    const seen = new Set<string>();
    for (const row of value.imageSets) {
      if (!metadataKeys(row, ['locale', 'id', 'count', 'required', 'issues']) || typeof row.locale !== 'string' || typeof row.id !== 'string' ||
        row.required !== false || !integer(row.count, MAX_ROWS) || row.count === 0 || !codes(row.issues, ['image.count', 'image.duplicate'])) return null;
      const key = groupKey(row.locale, row.id), group = images.get(key);
      if (!group || seen.has(key) || group.count !== row.count ||
        row.issues.includes('image.count') !== (row.count > group.max) || row.issues.includes('image.duplicate') !== group.duplicate) return null;
      seen.add(key);
    }
    const valid = value.files.every((row: Record<string, unknown>) => row.state === 'checked') &&
      value.imageSets.every((row: Record<string, unknown>) => (row.issues as string[]).length === 0);
    return valid === value.valid ? value as unknown as SavedMetadataReport : null;
  } catch { return null; }
}

// Machine-derived fixed core copy. No exception messages, file values or unknown
// error codes are read, logged or echoed.
const ERROR_MESSAGES: Readonly<Record<string, string>> = {
  "metadata_validation_invalid_params": "Saved metadata validation requires a selected project and one platform.",
  "metadata_validation_unavailable": "Saved metadata validation is unavailable on this platform.",
  "metadata_validation_config_missing": "Save release/mobile-release.json before validating metadata.",
  "metadata_validation_config_invalid": "Correct and save the project configuration before validating metadata.",
  "metadata_validation_not_configured": "Enable the selected platform and save at least one configured locale.",
  "metadata_validation_unsafe": "A requested metadata path or portable alias cannot be inspected safely.",
  "metadata_validation_changed": "The selected configuration or metadata changed during this check. Run a new check.",
  "metadata_validation_unreadable": "The selected metadata could not be read safely. No complete report was returned.",
  "metadata_validation_limit": "The local check exceeded its bounded file, byte, entry, result or time limit. No complete report was returned.",
  "metadata_validation_encoding": "The saved configuration is not valid UTF-8.",
  "metadata_validation_sensitive": "The saved configuration may contain secret material. No values were returned.",
  "metadata_validation_catalog_unavailable": "The bundled image policy is unavailable. No complete report was returned.",
  "metadata_validation_cleanup_unknown": "Original metadata observation cleanup could not be confirmed.",
  "metadata_validation_busy": "The original saved metadata request is still pending. Wait for its passive owner to settle before another operation."
};
export function savedMetadataError(value: unknown): ApiError {
  let code = 'metadata_validation_incomplete';
  try {
    const candidate = typeof value === 'object' && value !== null ? Object.getOwnPropertyDescriptor(value, 'code')?.value : null;
    if (typeof candidate === 'string') {
      if (Object.hasOwn(ERROR_MESSAGES, candidate)) code = candidate;
      else if (['runtime_unavailable', 'BridgeUnavailable'].includes(candidate)) code = 'metadata_validation_unavailable';
      else if (['query_timeout', 'output_limit'].includes(candidate)) code = 'metadata_validation_limit';
      else if (candidate === 'cleanup_unknown') code = 'metadata_validation_cleanup_unknown';
    }
  } catch { /* hostile/non-DATA errors stay generic */ }
  return { code, message: ERROR_MESSAGES[code] ?? 'No complete saved metadata report was returned. Settle the original operation, then run a new check.', retryable: false };
}

const REMEDIATION: Readonly<Record<string, string>> = {
  'metadata.missing': 'Add this required saved file, then run a new check.',
  'metadata.empty-text': 'Replace empty or whitespace-only text with the required content.',
  'metadata.nul': 'Remove NUL characters from this saved text.',
  'metadata.placeholder': 'Replace unresolved placeholders.',
  'metadata.secret-pattern': 'Remove possible secret material and rotate any exposed credentials. No content is shown.',
  'metadata.url': 'Use an absolute credential-free HTTPS URL without a query or fragment. Reachability is not checked.',
  'metadata.length': 'Shorten the content to the shared core character limit.',
  'metadata.utf8': 'Save this text as valid UTF-8.',
  'metadata.json': 'Correct the JSON, including duplicate object keys.',
  'metadata.android-version': 'Correct and save the configured version source, then check the current-build changelog again.',
  'metadata.android-note': 'Correct the saved release note using the core Android note rules; an invalid exact-build file does not fall back to default.',
  'image.empty': 'Replace the empty image with a supported PNG or JPEG.',
  'image.limit': 'Use an image within the existing core byte limit.',
  'image.format': 'Use supported PNG or JPEG bytes, not just a renamed file.',
  'image.header': 'Replace the image with a file that passes the core header checks.',
  'image.extension': 'Match the PNG/JPEG filename extension to its bytes.',
  'image.dimensions': 'Use dimensions within the bundled core bounds.',
  'image.device': 'Use a header size allowed for this declared display type.',
  'image.duplicate': 'Remove duplicate bytes within this locale/type group.',
  'image.count': 'Reduce this canonical image group to the bundled type count limit.',
};
export function savedMetadataRemediation(code: string): string { return REMEDIATION[code] ?? 'Review this saved file and run a new check.'; }
