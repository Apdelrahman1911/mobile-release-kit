// Renderer checks of the frozen native DTO, not configuration/ignore policy.
// No file read, payload preparation, native capability or finality is invented.
import { sameJson } from './catalog.ts';
import type { ConfigEditProjection, ConfigEditStatus, CoreEditOutcome, JsonObject, JsonValue, PreparedConfigView } from './types.ts';

export const U32_MAX = 0xffff_ffff;
const CONFIG_BYTES = 512 * 1024;
const IGNORE_BYTES = 1024 * 1024;
const encoder = new TextEncoder();
const IGNORE_LINES = ['.mobile-release/', '.mobile-release-init-prepare/', '.mobile-release-init/', '.mobile-release-init-cleanup/',
  '.mobile-release-metadata-text-prepare/', '.mobile-release-metadata-text/', '.mobile-release-metadata-text-cleanup/'] as const;
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'] as const;
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'] as const;
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'] as const;

function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function keys(value: unknown, required: readonly string[], optional: readonly string[] = []): value is Record<string, unknown> {
  return record(value) && required.every((key) => Object.hasOwn(value, key)) &&
    Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}

function oneOf(value: unknown, values: readonly string[]): boolean {
  return typeof value === 'string' && values.includes(value);
}

export function isU32(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= U32_MAX;
}

function text(value: unknown, maxBytes = 4096): value is string {
  return typeof value === 'string' && value.length <= maxBytes &&
    !/[\u0000-\u001f\u007f\ud800-\udfff]/u.test(value) && encoder.encode(value).byteLength <= maxBytes;
}

function token(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
}

function list(value: unknown, check: (item: unknown) => boolean, max = 64): value is unknown[] {
  return Array.isArray(value) && value.length <= max && value.every(check);
}

// Match the transport's finite data contract before retaining/copying data.
// This checks JSON shape/size only; the core remains the validator of values.
function boundedJson(value: unknown, bytes: number, nodes: number, depth: number): boolean {
  let count = 0;
  const seen = new Set<object>();
  const visit = (item: unknown, level: number): boolean => {
    if (++count > nodes || level > depth) return false;
    if (item === null || typeof item === 'boolean') return true;
    if (typeof item === 'number') return Number.isFinite(item);
    if (typeof item === 'string') return item.length <= bytes && !/[\ud800-\udfff]/u.test(item);
    if (typeof item !== 'object' || seen.has(item)) return false;
    seen.add(item);
    if (Array.isArray(item)) {
      const valid = item.length <= nodes && item.every((child) => visit(child, level + 1));
      seen.delete(item);
      return valid;
    }
    if (!record(item)) return false;
    const entries = Object.keys(item);
    if (entries.length > nodes) return false;
    const valid = entries.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      return descriptor !== undefined && Object.hasOwn(descriptor, 'value') &&
        visit(key, level + 1) && visit(descriptor.value, level + 1);
    });
    seen.delete(item);
    return valid;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= bytes; }
  catch { return false; }
}

export function editInputFits(expectedBase: JsonObject | null, draft: JsonObject): boolean {
  try {
    return (expectedBase === null || record(expectedBase)) && record(draft) &&
      boundedJson(expectedBase, CONFIG_BYTES, 8000, 28) && boundedJson(draft, CONFIG_BYTES, 8000, 28) &&
      // Count each document independently: the same in-memory object may be both
      // a clean draft and baseline. It is serialized twice, never shared on wire.
      encoder.encode(JSON.stringify({ expectedBase, draft })).byteLength <= 768 * 1024;
  } catch { return false; }
}

function assurance(value: unknown): boolean {
  return keys(value, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) &&
    value.basis === 'schema-policy' && value.projectCodeExecuted === false && value.toolsProbed === false &&
    value.credentialsRead === false && value.gitObserved === false && value.storeContacted === false &&
    value.writesPerformed === false && value.releaseReadiness === 'unknown';
}

function requirement(value: unknown): boolean {
  return keys(value, ['name', 'kind', 'stage', 'platform', 'environment', 'alternatives', 'reason', 'state']) &&
    ['name', 'kind', 'stage', 'platform', 'environment', 'reason'].every((key) => text(value[key])) &&
    list(value.alternatives, (item) => text(item)) && value.state === 'unknown';
}

function summary(value: unknown): boolean {
  if (!keys(value, ['present'], ['type', 'count']) || typeof value.present !== 'boolean') return false;
  if (!value.present) return Object.keys(value).length === 1;
  if (!oneOf(value.type, ['null', 'boolean', 'number', 'string', 'array', 'object'])) return false;
  return value.type === 'array' || value.type === 'object'
    ? isU32(value.count)
    : !Object.hasOwn(value, 'count');
}

function preview(value: unknown): boolean {
  if (!keys(value, ['schemaVersion', 'validation', 'comparison', 'fields', 'assurance']) || value.schemaVersion !== 1 || !assurance(value.assurance)) return false;
  const validation = value.validation;
  if (!keys(validation, ['valid', 'state', 'issues', 'requirements', 'assurance']) || validation.valid !== true || validation.state !== 'format-valid' ||
      !Array.isArray(validation.issues) || validation.issues.length !== 0 || !list(validation.requirements, requirement) || !assurance(validation.assurance)) return false;
  const comparison = value.comparison;
  if (!keys(comparison, ['baseProvided', 'kind', 'state', 'semanticallyChanged', 'counts', 'changes', 'unreviewedCount']) ||
      typeof comparison.baseProvided !== 'boolean' || comparison.kind !== (comparison.baseProvided ? 'compare' : 'proposed-create') ||
      comparison.state !== 'complete' || comparison.unreviewedCount !== 0 || typeof comparison.semanticallyChanged !== 'boolean') return false;
  if (!keys(comparison.counts, ['added', 'changed', 'removed']) || !Object.values(comparison.counts).every(isU32)) return false;
  if (!list(comparison.changes, (item) => keys(item, ['path', 'operation', 'before', 'after']) && text(item.path, 256) &&
      oneOf(item.operation, ['add', 'change', 'remove']) && summary(item.before) && summary(item.after))) return false;
  for (const [operation, key] of [['add', 'added'], ['change', 'changed'], ['remove', 'removed']] as const) {
    if (comparison.counts[key] !== comparison.changes.filter((item) => record(item) && item.operation === operation).length) return false;
  }
  return list(value.fields, (item) => keys(item, ['path', 'state', 'present', 'reason']) && text(item.path, 256) &&
    oneOf(item.state, ['required', 'optional', 'forbidden', 'unknown']) && typeof item.present === 'boolean' && text(item.reason));
}

function file(value: unknown, path: string, actions: readonly string[], limit: number): value is Record<string, unknown> {
  if (!keys(value, ['path', 'action', 'beforeBytes', 'afterBytes']) || value.path !== path || !oneOf(value.action, actions)) return false;
  const before = value.beforeBytes;
  const after = value.afterBytes;
  if (!isU32(after) || after > limit) return false;
  if (before === null) return value.action === 'create' && after > 0;
  if (!isU32(before) || before > limit || value.action === 'create') return false;
  if (value.action === 'preserve') return before === after;
  return value.action !== 'append' || after > before;
}

function preparedView(value: unknown): value is PreparedConfigView {
  if (!keys(value, ['schemaVersion', 'files', 'createReleaseDirectory', 'rewritesConfigFormatting', 'ignoreAdditions', 'preview']) || value.schemaVersion !== 1 ||
      typeof value.createReleaseDirectory !== 'boolean' || typeof value.rewritesConfigFormatting !== 'boolean' ||
      !Array.isArray(value.files) || value.files.length !== 2 ||
      !file(value.files[0], 'release/mobile-release.json', ['create', 'replace', 'preserve'], CONFIG_BYTES) ||
      !file(value.files[1], '.gitignore', ['create', 'append', 'preserve'], IGNORE_BYTES) ||
      !list(value.ignoreAdditions, (item) => oneOf(item, IGNORE_LINES), IGNORE_LINES.length) || !preview(value.preview)) return false;
  const config = value.files[0];
  const ignore = value.files[1];
  if (value.rewritesConfigFormatting !== (config.action === 'replace') || (value.createReleaseDirectory && config.action !== 'create')) return false;
  const additions = value.ignoreAdditions;
  const ordered = IGNORE_LINES.filter((line) => additions.includes(line));
  if (additions.length !== ordered.length || !additions.every((line, index) => line === ordered[index])) return false;
  if (ignore.action === 'preserve' ? additions.length !== 0 : additions.length === 0) return false;
  if (ignore.action === 'create' && additions.length !== IGNORE_LINES.length) return false;
  const comparison = (value.preview as unknown as { comparison: { baseProvided: boolean; semanticallyChanged: boolean } }).comparison;
  if (comparison.baseProvided !== (config.action !== 'create') || comparison.semanticallyChanged !== (config.action !== 'preserve')) return false;
  return boundedJson(value, 128 * 1024, 20_000, 32);
}

function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) ||
      !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) ||
      !oneOf(value.resources, ['settled', 'unknown']) || !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created') return false;
  if ((value.effect === 'committed' || value.effect === 'rolled_back') && value.journal === 'not_created') return false;
  if (value.reason === 'none' && (value.resources !== 'settled' || value.effect === 'unknown' ||
      value.journal === 'unknown' || value.journal === 'recovery_required')) return false;
  return true;
}

function projection(value: unknown): value is ConfigEditProjection {
  if (!keys(value, ['projectId', 'sessionId', 'ownerGeneration', 'phase', 'reviewRemainingMs', 'checkout', 'prepared', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled']) ||
      !text(value.projectId, 128) || value.projectId.length === 0 || !token(value.sessionId) || !token(value.ownerGeneration) ||
      !oneOf(value.phase, phases) || !isU32(value.reviewRemainingMs) || typeof value.applySubmitted !== 'boolean' || typeof value.lateSettled !== 'boolean' ||
      !oneOf(value.nativeReason, nativeReasons) || !oneOf(value.nativeFinality, ['pending', 'settled', 'unknown']) ||
      !(value.coreOutcome === null || outcome(value.coreOutcome))) return false;
  if (value.checkout !== null && (!keys(value.checkout, ['revision', 'base']) || !token(value.checkout.revision) ||
      !(value.checkout.base === null || (record(value.checkout.base) && boundedJson(value.checkout.base, CONFIG_BYTES, 8000, 28))))) return false;
  if (value.prepared !== null && (!keys(value.prepared, ['revision', 'planToken', 'draftRevision', 'baselineGeneration', 'view']) ||
      !token(value.prepared.revision) || !token(value.prepared.planToken) || !isU32(value.prepared.draftRevision) || !isU32(value.prepared.baselineGeneration) ||
      !preparedView(value.prepared.view) || !record(value.checkout) || value.prepared.revision !== value.checkout.revision)) return false;
  if (value.phase === 'final') {
    if (value.nativeFinality !== 'settled' || value.lateSettled) return false;
  } else if (value.phase === 'unknown') {
    if (value.nativeFinality !== 'unknown') return false;
  } else if (value.nativeFinality !== 'pending' || value.lateSettled) return false;
  if (value.phase === 'opening' && (value.checkout !== null || value.prepared !== null || value.applySubmitted)) return false;
  if (['editing', 'preparing', 'reviewing', 'applying'].includes(value.phase as string) && value.checkout === null) return false;
  if (['editing', 'preparing'].includes(value.phase as string) && (value.prepared !== null || value.applySubmitted)) return false;
  if (['reviewing', 'applying'].includes(value.phase as string) && value.prepared === null) return false;
  if (value.phase === 'reviewing' && value.applySubmitted) return false;
  if (value.phase === 'applying' && !value.applySubmitted) return false;
  if (value.applySubmitted && value.prepared === null) return false;
  if (['opening', 'editing', 'preparing', 'reviewing'].includes(value.phase as string) && value.coreOutcome !== null) return false;
  const result = value as unknown as ConfigEditProjection;
  if (result.prepared && result.checkout && result.prepared.view.preview.comparison.baseProvided !== (result.checkout.base !== null)) return false;
  if (result.phase === 'final') {
    if (result.coreOutcome === null) {
      // Only a known-settled refusal before a child was acquired can lack a
      // core receipt. A spawned engine's missing terminal is native Unknown.
      if (result.checkout !== null || result.prepared !== null || result.applySubmitted || result.nativeReason === 'none') return false;
    } else if (result.coreOutcome.resources === 'unknown' || result.coreOutcome.effect === 'unknown' || result.coreOutcome.journal === 'unknown') return false;
  }
  if (result.coreOutcome && ['committed', 'rolled_back', 'unchanged'].includes(result.coreOutcome.effect)) {
    if (!result.checkout || !result.prepared || !result.applySubmitted) return false;
    const noWrites = result.prepared.view.files.every((item) => item.action === 'preserve');
    if (result.coreOutcome.effect === 'unchanged' ? !noWrites : noWrites) return false;
  }
  return true;
}

export function parseConfigEditStatus(value: unknown): ConfigEditStatus | null {
  try {
    if (!boundedJson(value, 2 * 1024 * 1024, 40_000, 36) ||
        !keys(value, ['schemaVersion', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) || value.schemaVersion !== 1 ||
        !token(value.windowGeneration) || !isU32(value.statusRevision) ||
        !keys(value.capability, ['available', 'reason']) || typeof value.capability.available !== 'boolean' ||
        !oneOf(value.capability.reason, ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active']) ||
        value.capability.available !== (value.capability.reason === 'available') ||
        !(value.active === null || projection(value.active)) || !(value.lastTerminal === null || projection(value.lastTerminal))) return null;
    const result = value as unknown as ConfigEditStatus;
    if (result.active?.phase === 'final' || result.active?.lateSettled) return null;
    if (result.lastTerminal && !['final', 'unknown'].includes(result.lastTerminal.phase)) return null;
    if (result.active && result.lastTerminal?.sessionId === result.active.sessionId) return null;
    return result;
  } catch { return null; }
}

// The renderer consumes the original owner's positive finality receipt. It
// does not try to reproduce child wait/EOF/durability/close qualification.
export function normalEditResult(value: ConfigEditProjection): 'saved' | 'unchanged' | null {
  const core = value.coreOutcome;
  if (value.phase !== 'final' || value.nativeFinality !== 'settled' || value.nativeReason !== 'none' ||
      value.lateSettled || !core || core.resources !== 'settled' || core.reason !== 'none' || !value.applySubmitted ||
      !value.checkout || !value.prepared || value.prepared.revision !== value.checkout.revision) return null;
  const noWrites = value.prepared.view.files.every((item) => item.action === 'preserve');
  if (core.effect === 'committed' && core.journal === 'clean' && !noWrites) return 'saved';
  if (core.effect === 'unchanged' && core.journal === 'not_created' && noWrites) return 'unchanged';
  return null;
}

function equal(first: unknown, second: unknown): boolean {
  return sameJson(first as JsonValue, second as JsonValue);
}

function sameProjectionFacts(first: ConfigEditProjection, second: ConfigEditProjection): boolean {
  return equal({ ...first, reviewRemainingMs: 0 }, { ...second, reviewRemainingMs: 0 });
}

export function projectionProgress(first: ConfigEditProjection, next: ConfigEditProjection): boolean {
  if (first.sessionId !== next.sessionId || first.projectId !== next.projectId || first.ownerGeneration !== next.ownerGeneration ||
      (first.checkout !== null && !equal(first.checkout, next.checkout)) ||
      (first.prepared !== null && !equal(first.prepared, next.prepared)) ||
      (first.applySubmitted && !next.applySubmitted) || (first.lateSettled && !next.lateSettled)) return false;
  if (first.phase === 'final') return sameProjectionFacts(first, next);
  if (first.phase === 'unknown' && next.phase !== 'unknown') return false;
  if (phases.indexOf(next.phase) < phases.indexOf(first.phase)) return false;
  if (first.nativeReason !== 'none' && first.nativeReason !== next.nativeReason) return false;
  if (first.coreOutcome) {
    if (!next.coreOutcome || (first.coreOutcome.effect !== 'unknown' && first.coreOutcome.effect !== next.coreOutcome.effect) ||
        (first.coreOutcome.reason !== 'none' && first.coreOutcome.reason !== next.coreOutcome.reason)) return false;
  }
  return true;
}

// false means a contradictory status, not an ordinary old/duplicate delivery.
export function statusProgress(first: ConfigEditStatus, next: ConfigEditStatus): boolean {
  if (first.windowGeneration !== next.windowGeneration || next.statusRevision < first.statusRevision) return true;
  if (next.statusRevision === first.statusRevision) {
    if (!equal(first.capability, next.capability)) return false;
    for (const key of ['active', 'lastTerminal'] as const) {
      const before = first[key];
      const after = next[key];
      if (before === null || after === null) { if (before !== after) return false; }
      // A delayed same-revision event may contain an older timer snapshot.
      // The reducer keeps the minimum; arrival order never grants more time.
      else if (!sameProjectionFacts(before, after)) return false;
    }
    return true;
  }
  for (const before of [first.active, first.lastTerminal]) {
    if (!before) continue;
    const after = [next.active, next.lastTerminal].find((item) => item?.sessionId === before.sessionId);
    if (after && !projectionProgress(before, after)) return false;
  }
  return true;
}
