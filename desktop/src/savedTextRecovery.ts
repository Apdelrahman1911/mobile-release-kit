// Closed two-domain recovery DATA. This module owns no filesystem, native
// process, journal, deadline or authority; the existing EditOwner owns those.
import { sameJson } from './catalog.ts';
import type { CoreEditOutcome, JsonValue, NativeEditReason } from './types.ts';

export type SavedTextRecoveryDomain = 'metadata_text' | 'release_version';
export type SavedTextRecoveryAction = 'rollback' | 'committed_cleanup' | 'rolled_back_cleanup' | 'preparing_cleanup';
export type SavedTextRecoveryReason = 'none' | 'legacy_journal' | 'incomplete_journal' | 'invalid_journal' | 'foreign_journal' | 'dependency_changed' | 'target_changed';
export interface SavedTextRecoveryDigest { byteLength: number; sha256: string; mode: number }
export interface SavedTextRecoveryFile {
  path: string; effect: 'preserve' | 'remove_new' | 'restore_original' | 'keep_committed';
  before: SavedTextRecoveryDigest | null; after: SavedTextRecoveryDigest | null;
}
export interface SavedTextRecoverySelections {
  metadata_text: { platform: 'android' | 'ios'; locale: string; metadataRoot: string };
  release_version: { source: string; nameKey: string; buildKey: string; iosEnabled: boolean };
}
export interface SavedTextRecoveryView<D extends SavedTextRecoveryDomain = SavedTextRecoveryDomain> {
  schemaVersion: 1; kind: 'saved-text-recovery'; domain: D;
  state: 'idle' | 'conflict' | 'recoverable'; reason: SavedTextRecoveryReason;
  action: SavedTextRecoveryAction | null; transactionId: string | null;
  selection: SavedTextRecoverySelections[D] | null; files: SavedTextRecoveryFile[];
  privateCleanup: { fileCount: number; directoryCount: number; scope: 'inspected-owned-journal-only' };
}
export interface SavedTextRecoveryDetails<D extends SavedTextRecoveryDomain = SavedTextRecoveryDomain> {
  checkout: { revision: string; view: SavedTextRecoveryView<D> } | null;
  prepared: { revision: string; planToken: string; view: SavedTextRecoveryView<D> } | null;
}
export type SavedTextRecoveryProjection<D extends SavedTextRecoveryDomain = SavedTextRecoveryDomain> = {
  domain: D; projectId: string; sessionId: string; ownerGeneration: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number; checkout: null; prepared: null; recovery: SavedTextRecoveryDetails<D>;
  applySubmitted: boolean; coreOutcome: CoreEditOutcome | null; nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown'; lateSettled: boolean;
} & (D extends 'metadata_text' ? { platform: null; locale: null } : unknown);
export interface SavedTextRecoveryOpenRequest { projectId: string; intent: 'recover' }
export interface SavedTextRecoveryPrepareRequest { sessionId: string; revision: string; intent: 'recover' }
export interface SavedTextRecoveryContext {
  projectId: string; configRevision: number; configBaselineGeneration: number; configObservationGeneration: number;
  serviceGeneration: number; selectionGeneration: number; navigationGeneration: number;
  windowGeneration: string; startStatusRevision: number; previousTerminalId: string | null;
}
export interface SavedTextRecoveryApplyBinding<D extends SavedTextRecoveryDomain = SavedTextRecoveryDomain> {
  domain: D; projectId: string; sessionId: string; ownerGeneration: string;
  revision: string; planToken: string; action: SavedTextRecoveryAction; transactionId: string;
  view: SavedTextRecoveryView<D>; context: SavedTextRecoveryContext;
}
export interface SavedTextRecoveryAttempt<D extends SavedTextRecoveryDomain = SavedTextRecoveryDomain> {
  binding: SavedTextRecoveryContext; sessionId: string | null; projection: SavedTextRecoveryProjection<D> | null;
  projectionRevision: number; prepareClaimed: boolean; applyClaimed: boolean;
  submitted: SavedTextRecoveryApplyBinding<D> | null;
  closeRequested: boolean; closeClaimed: boolean; invalidated: boolean; handled: boolean; succeeded: boolean;
}

const encoder = new TextEncoder();
const actions = ['rollback', 'committed_cleanup', 'rolled_back_cleanup', 'preparing_cleanup'] as const;
const reasons = ['none', 'legacy_journal', 'incomplete_journal', 'invalid_journal', 'foreign_journal', 'dependency_changed', 'target_changed'];
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const ids = { android: ['title.txt', 'short_description.txt', 'full_description.txt'],
  ios: ['description.txt', 'keywords.txt', 'privacy_url.txt', 'support_url.txt', 'release_notes.txt'] } as const;
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function keys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const names = Reflect.ownKeys(value);
  return names.length === expected.length && names.every((name) => {
    const item = Object.getOwnPropertyDescriptor(value, name);
    return typeof name === 'string' && expected.includes(name) && item?.enumerable === true && Object.hasOwn(item, 'value');
  });
}
function integer(value: unknown, max: number): value is number { return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max; }
function oneOf<T extends string>(value: unknown, choices: readonly T[]): value is T { return typeof value === 'string' && choices.includes(value as T); }
function token(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{32}(?![\s\S])/.test(value); }
function text(value: unknown, max: number): value is string {
  return typeof value === 'string' && value.length <= max && !/[\ud800-\udfff]/u.test(value) && encoder.encode(value).byteLength <= max;
}
function path(value: unknown, depth = 12): value is string {
  if (!text(value, 512) || !value || value.normalize('NFC') !== value || /[\\:<>"|?*\u0000-\u001f\u007f]/u.test(value)) return false;
  const parts = value.split('/');
  const reserved = ['private', 'secrets', 'credentials', 'review', 'testflight', 'build', 'deriveddata', 'pods', 'node_modules', 'venv', 'dist', 'target', '__pycache__'];
  return parts.length <= depth && parts.every((part) => part.length > 0 && encoder.encode(part).byteLength <= 255 && !part.startsWith('.') &&
    !/[. ]$/.test(part) && !reserved.includes(part.toLowerCase()) && !/^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i.test(part));
}
// Check only plain bounded DATA before copying/stringifying. Never invoke a
// getter, toJSON, prototype method or a caller-supplied parser.
function bounded(value: unknown, limit: number): boolean {
  let nodes = 0, bytes = 0;
  const ancestors = new Set<object>();
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > 1024 || depth > 12) return false;
    if (item === null || typeof item === 'boolean') bytes += 1;
    else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; bytes += 1; }
    else if (typeof item === 'string') { if (!text(item, limit)) return false; bytes += encoder.encode(item).byteLength + 2; }
    else {
      if (typeof item !== 'object' || ancestors.has(item)) return false;
      ancestors.add(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || item.length > 1024 || Reflect.ownKeys(item).length !== item.length + 1) return false;
        bytes += 2 + Math.max(0, item.length - 1);
        for (let index = 0; index < item.length; index += 1) {
          const row = Object.getOwnPropertyDescriptor(item, String(index));
          if (row?.enumerable !== true || !Object.hasOwn(row, 'value') || !visit(row.value, depth + 1)) return false;
        }
      } else {
        if (!record(item)) return false;
        const names = Reflect.ownKeys(item); if (names.length > 1024) return false;
        bytes += 2 + Math.max(0, 2 * names.length - 1);
        for (const name of names) {
          const row = Object.getOwnPropertyDescriptor(item, name);
          if (typeof name !== 'string' || row?.enumerable !== true || !Object.hasOwn(row, 'value') || !visit(name, depth + 1) || !visit(row.value, depth + 1)) return false;
        }
      }
      ancestors.delete(item);
    }
    return bytes <= limit;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= limit; } catch { return false; }
}
function same(first: unknown, next: unknown): boolean { return sameJson(first as JsonValue, next as JsonValue); }
function digest(value: unknown, max: number): value is SavedTextRecoveryDigest {
  return keys(value, ['byteLength', 'sha256', 'mode']) && integer(value.byteLength, max) && integer(value.mode, 511) &&
    typeof value.sha256 === 'string' && /^[0-9a-f]{64}(?![\s\S])/.test(value.sha256);
}
export function parseSavedTextRecoveryView<D extends SavedTextRecoveryDomain>(value: unknown, domain: D): SavedTextRecoveryView<D> | null {
  try {
    if ((domain !== 'metadata_text' && domain !== 'release_version') || !bounded(value, 16384) || !keys(value, ['schemaVersion', 'kind', 'domain', 'state', 'reason', 'action', 'transactionId', 'selection', 'files', 'privateCleanup']) ||
        value.schemaVersion !== 1 || value.kind !== 'saved-text-recovery' || value.domain !== domain ||
        !oneOf(value.state, ['idle', 'conflict', 'recoverable']) || !oneOf(value.reason, reasons) || !Array.isArray(value.files) ||
        !keys(value.privateCleanup, ['fileCount', 'directoryCount', 'scope']) || !integer(value.privateCleanup.fileCount, 14) ||
        !integer(value.privateCleanup.directoryCount, 11) || value.privateCleanup.scope !== 'inspected-owned-journal-only') return null;
    if (value.state !== 'recoverable') return value.action === null && value.transactionId === null && value.selection === null && value.files.length === 0 &&
      value.privateCleanup.fileCount === 0 && value.privateCleanup.directoryCount === 0 && (value.state === 'idle' ? value.reason === 'none' : value.reason !== 'none')
      ? value as unknown as SavedTextRecoveryView<D> : null;
    if (value.reason !== 'none' || !oneOf(value.action, actions) || !token(value.transactionId)) return null;
    const selection = value.selection;
    let roster: string[], limit: number;
    if (domain === 'metadata_text') {
      if (!keys(selection, ['platform', 'locale', 'metadataRoot']) || (selection.platform !== 'android' && selection.platform !== 'ios') ||
          typeof selection.locale !== 'string' || !/^[\x20-\x7e]{2,12}(?![\s\S])/.test(selection.locale) || !path(selection.metadataRoot, 9)) return null;
      roster = ids[selection.platform].map((id) => `${selection.metadataRoot}/${selection.platform}/${selection.locale}/${id}`); limit = 32768;
    } else {
      if (!keys(selection, ['source', 'nameKey', 'buildKey', 'iosEnabled']) || !path(selection.source) || selection.source.toLowerCase() === 'release/mobile-release.json' ||
          typeof selection.nameKey !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}(?![\s\S])/.test(selection.nameKey) ||
          typeof selection.buildKey !== 'string' || !/^[A-Z][A-Z0-9_]{0,63}(?![\s\S])/.test(selection.buildKey) ||
          selection.nameKey === selection.buildKey || typeof selection.iosEnabled !== 'boolean') return null;
      roster = [selection.source]; limit = 65536;
    }
    if (value.files.length !== roster.length || !value.files.every((file, index) => {
      if (!keys(file, ['path', 'effect', 'before', 'after']) || file.path !== roster[index] || !path(file.path) ||
          !(file.before === null || digest(file.before, limit)) || !(file.after === null || digest(file.after, limit)) || file.before === null && file.after === null) return false;
      const effect = value.action === 'rollback' ? file.after === null ? 'preserve' : file.before === null ? 'remove_new' : 'restore_original' :
        value.action === 'committed_cleanup' && file.after !== null ? 'keep_committed' : 'preserve';
      return file.effect === effect;
    })) return null;
    return value as unknown as SavedTextRecoveryView<D>;
  } catch { return null; }
}
function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) || !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) || !oneOf(value.resources, ['settled', 'unknown']) ||
      !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created' || oneOf(value.effect, ['committed', 'rolled_back']) && value.journal === 'not_created') return false;
  // An inspected journal is not a synthetic first failure. Discard may retain
  // known effect/recovery_required with reason none, but it is never success.
  return value.reason !== 'none' || value.resources === 'settled' && value.effect !== 'unknown' && value.journal !== 'unknown';
}
export function savedTextRecoveryEffect(action: SavedTextRecoveryAction): 'rolled_back' | 'committed' | 'not_started' {
  return action === 'committed_cleanup' ? 'committed' : action === 'preparing_cleanup' ? 'not_started' : 'rolled_back';
}
export function parseSavedTextRecoveryProjection<D extends SavedTextRecoveryDomain>(value: unknown, domain: D): SavedTextRecoveryProjection<D> | null {
  try {
    const expected = ['domain', 'projectId', 'sessionId', 'ownerGeneration', 'phase', 'reviewRemainingMs', 'checkout', 'prepared', 'recovery', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled'];
    if (domain === 'metadata_text') expected.push('platform', 'locale');
    if ((domain !== 'metadata_text' && domain !== 'release_version') || !bounded(value, 65536) || !keys(value, expected) || value.domain !== domain || typeof value.projectId !== 'string' ||
        !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(value.projectId) || !token(value.sessionId) || !token(value.ownerGeneration) ||
        !oneOf(value.phase, phases) || !integer(value.reviewRemainingMs, 900000) || value.checkout !== null || value.prepared !== null ||
        domain === 'metadata_text' && (value.platform !== null || value.locale !== null) ||
        typeof value.applySubmitted !== 'boolean' || typeof value.lateSettled !== 'boolean' || !oneOf(value.nativeReason, nativeReasons) ||
        !oneOf(value.nativeFinality, ['pending', 'settled', 'unknown']) || !(value.coreOutcome === null || outcome(value.coreOutcome)) ||
        !keys(value.recovery, ['checkout', 'prepared'])) return null;
    const checkout = value.recovery.checkout, prepared = value.recovery.prepared;
    if (checkout !== null && (!keys(checkout, ['revision', 'view']) || !token(checkout.revision) || !parseSavedTextRecoveryView(checkout.view, domain))) return null;
    if (prepared !== null && (!keys(prepared, ['revision', 'planToken', 'view']) || !token(prepared.revision) || !token(prepared.planToken) ||
        prepared.planToken === prepared.revision || !parseSavedTextRecoveryView(prepared.view, domain) || !record(checkout) ||
        prepared.revision !== checkout.revision || !same(prepared.view, checkout.view) || !record(prepared.view) || prepared.view.state !== 'recoverable')) return null;
    const result = value as unknown as SavedTextRecoveryProjection<D>;
    if (result.phase === 'final') {
      if (result.nativeFinality !== 'settled' || result.lateSettled) return null;
      if (!result.coreOutcome) { if (checkout || prepared || result.applySubmitted || result.nativeReason === 'none') return null; }
      else if (result.coreOutcome.resources === 'unknown' || result.coreOutcome.effect === 'unknown' || result.coreOutcome.journal === 'unknown') return null;
    } else if (result.phase === 'unknown') { if (result.nativeFinality !== 'unknown') return null; }
    else if (result.nativeFinality !== 'pending' || result.lateSettled) return null;
    if (result.phase === 'opening' && (checkout || prepared || result.applySubmitted) ||
        ['editing', 'preparing', 'reviewing', 'applying'].includes(result.phase) && !checkout ||
        ['editing', 'preparing'].includes(result.phase) && (prepared || result.applySubmitted) ||
        ['reviewing', 'applying'].includes(result.phase) && !prepared ||
        result.phase === 'reviewing' && result.applySubmitted || result.phase === 'applying' && !result.applySubmitted || result.applySubmitted && !prepared ||
        ['opening', 'editing', 'preparing', 'reviewing'].includes(result.phase) && result.coreOutcome !== null) return null;
    if (result.phase === 'final' && result.nativeReason === 'none' && result.coreOutcome?.reason === 'none') {
      const action = result.recovery.prepared?.view.action;
      if (!result.applySubmitted || !action || result.coreOutcome.effect !== savedTextRecoveryEffect(action) || result.coreOutcome.journal !== 'clean') return null;
    }
    return result;
  } catch { return null; }
}
export function savedTextRecoveryDetailsProgress(first: SavedTextRecoveryDetails | undefined, next: SavedTextRecoveryDetails | undefined): boolean {
  if (!first || !next) return first === next;
  return (!first.checkout || same(first.checkout, next.checkout)) && (!first.prepared || same(first.prepared, next.prepared));
}
export function savedTextRecoverySettled(attempt: SavedTextRecoveryAttempt | null): boolean {
  return !attempt || attempt.projection?.phase === 'final' && attempt.projection.nativeFinality === 'settled';
}
export function savedTextRecoveryPreparedMatches<D extends SavedTextRecoveryDomain>(attempt: SavedTextRecoveryAttempt<D>): boolean {
  const owner = attempt.projection, checkout = owner?.recovery.checkout, prepared = owner?.recovery.prepared;
  return !!owner && !!checkout && !!prepared && owner.projectId === attempt.binding.projectId && owner.sessionId === attempt.sessionId &&
    owner.ownerGeneration === attempt.binding.windowGeneration && prepared.revision === checkout.revision && same(prepared.view, checkout.view) &&
    prepared.view.domain === owner.domain && prepared.view.state === 'recoverable';
}
function binding<D extends SavedTextRecoveryDomain>(attempt: SavedTextRecoveryAttempt<D>): SavedTextRecoveryApplyBinding<D> | null {
  const owner = attempt.projection, prepared = owner?.recovery.prepared;
  if (!owner || !prepared?.view.action || !prepared.view.transactionId || !savedTextRecoveryPreparedMatches(attempt)) return null;
  return { domain: owner.domain, projectId: owner.projectId, sessionId: owner.sessionId, ownerGeneration: owner.ownerGeneration,
    revision: prepared.revision, planToken: prepared.planToken, action: prepared.view.action, transactionId: prepared.view.transactionId,
    view: prepared.view, context: attempt.binding };
}
export function savedTextRecoveryApplyBinding<D extends SavedTextRecoveryDomain>(attempt: SavedTextRecoveryAttempt<D> | null): SavedTextRecoveryApplyBinding<D> | null {
  const owner = attempt?.projection;
  return attempt && owner && attempt.prepareClaimed && !attempt.applyClaimed && !attempt.closeRequested && !attempt.invalidated && !attempt.handled &&
    owner.phase === 'reviewing' && owner.nativeReason === 'none' && owner.nativeFinality === 'pending' && owner.reviewRemainingMs > 0 && !owner.applySubmitted
    ? binding(attempt) : null;
}
export function savedTextRecoverySucceeded<D extends SavedTextRecoveryDomain>(attempt: SavedTextRecoveryAttempt<D>): boolean {
  const owner = attempt.projection, core = owner?.coreOutcome;
  return !!owner && !!core && attempt.applyClaimed && !!attempt.submitted && same(attempt.submitted, binding(attempt)) &&
    owner.phase === 'final' && owner.applySubmitted && owner.nativeFinality === 'settled' && owner.nativeReason === 'none' && !owner.lateSettled &&
    core.reason === 'none' && core.resources === 'settled' && core.journal === 'clean' && core.effect === savedTextRecoveryEffect(attempt.submitted.action);
}
export const savedTextRecoveryActionLabel: Record<SavedTextRecoveryAction, string> = {
  rollback: 'Roll back the interrupted save', committed_cleanup: 'Keep the earlier commit; clean its private journal',
  rolled_back_cleanup: 'Keep the earlier rollback; clean its private journal', preparing_cleanup: 'Clean private preparation only',
};
export function savedTextRecoveryGuidance(view: SavedTextRecoveryView): string {
  if (view.state === 'idle') return 'No selected-domain journal was found by this inspection. This is not a whole-project clean-state check and does not clear an earlier alert.';
  if (view.state === 'recoverable') return 'The original journal and current dependencies identify exactly this action. Review every file and private cleanup count, then confirm separately. Your current draft is not being saved.';
  if (view.reason === 'legacy_journal') return 'This older journal lacks the original recovery context. The supported route cannot infer it or safely upgrade the journal.';
  if (view.reason === 'dependency_changed' || view.reason === 'target_changed') return 'The saved configuration, ignore proof or required target facts no longer match the journal. No replacement state is adopted.';
  return 'The journal is incomplete, contradictory, foreign or unsafe to inspect. There is not enough original evidence to authorize recovery.';
}
export const savedTextRecoveryPreservationGuidance = 'Leave public files and private journal names and contents in place. Keep original operation details and unsaved drafts separately. Do not delete, rename or reset journals, force another edit, use generic init --recover, or repeatedly retry. Obtain manual reconciliation assistance when this supported route reports a conflict.';
