// Closed transport admission only. This module never reads, hashes or renders
// a workflow template. Exact-byte equality and filesystem finality belong to
// the original native/core owner, not these display consistency checks.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { GITHUB_WORKFLOWS, githubSetupRequestFits } from './githubSetupProtocol.ts';
import type { ApiError, CoreEditOutcome, JsonValue } from './types.ts';
import type { GitHubWorkflowEditProjection, GitHubWorkflowEditStatus, WorkflowConflict, WorkflowObservation, WorkflowPreparedView } from './githubWorkflowEditTypes.ts';

const encoder = new TextEncoder();
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'] as const;
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown', 'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'stale_revision', 'pending_state', 'busy', 'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const availability = ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active'];
const repository = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/;

function record(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function keys(value: unknown, expected: readonly string[]): value is Record<string, unknown> {
  if (!record(value)) return false;
  const names = Reflect.ownKeys(value);
  return names.length === expected.length && names.every((name) => {
    if (typeof name !== 'string' || !expected.includes(name)) return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
  });
}
function text(value: unknown, max: number, plain = true): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max &&
    !/[\ud800-\udfff]/u.test(value) && (!plain || !/[\u0000-\u001f\u007f]/u.test(value)) && encoder.encode(value).byteLength <= max;
}
function oneOf(value: unknown, choices: readonly string[]): boolean { return typeof value === 'string' && choices.includes(value); }
function token(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{32}$/.test(value); }
function digest(value: unknown): value is string { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function length(value: unknown, max: number): value is number { return isU32(value) && value <= max; }

// Reject accessors/exotic objects, sparse arrays, cycles and hidden keys before
// copying data or allocating a serialized aggregate. Count keys as JSON nodes.
function boundedJson(value: unknown, bytes: number, maxNodes: number, maxDepth: number): boolean {
  let nodes = 0;
  let floor = 0;
  const ancestors = new Set<object>();
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > maxNodes || depth > maxDepth) return false;
    if (item === null || typeof item === 'boolean') floor += 1;
    else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; floor += 1; }
    else if (typeof item === 'string') {
      if (item.length > bytes || /[\ud800-\udfff]/u.test(item)) return false;
      floor += encoder.encode(item).byteLength + 2;
    } else {
      if (typeof item !== 'object' || depth >= maxDepth || ancestors.has(item)) return false;
      ancestors.add(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || item.length > maxNodes - nodes || Reflect.ownKeys(item).length !== item.length + 1) return false;
        floor += 2 + Math.max(0, item.length - 1);
        if (floor > bytes) return false;
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(descriptor.value, depth + 1)) return false;
        }
      } else {
        if (!record(item)) return false;
        const names = Reflect.ownKeys(item);
        if (names.length > maxNodes - nodes) return false;
        floor += 2 + Math.max(0, names.length * 2 - 1);
        if (floor > bytes) return false;
        for (const name of names) {
          if (typeof name !== 'string') return false;
          const descriptor = Object.getOwnPropertyDescriptor(item, name);
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value') || !visit(name, depth + 1) || !visit(descriptor.value, depth + 1)) return false;
        }
      }
      ancestors.delete(item);
    }
    return floor <= bytes;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= bytes; }
  catch { return false; }
}

export type GitHubWorkflowEditCommand = 'github_workflow_edit_open' | 'github_workflow_edit_prepare' | 'github_workflow_edit_apply' | 'github_workflow_edit_close' | 'github_workflow_edit_status';

export function workflowEditRequestFits(command: GitHubWorkflowEditCommand, value: unknown): boolean {
  try {
    if (!boundedJson(value, 768 * 1024, 9000, 32)) return false;
    switch (command) {
      case 'github_workflow_edit_open': return keys(value, ['projectId']) && text(value.projectId, 128);
      case 'github_workflow_edit_close': return keys(value, ['sessionId']) && token(value.sessionId);
      case 'github_workflow_edit_apply': return keys(value, ['sessionId', 'planToken']) && token(value.sessionId) && token(value.planToken);
      case 'github_workflow_edit_status': return keys(value, []);
      case 'github_workflow_edit_prepare': return keys(value, ['sessionId', 'revision', 'draft', 'toolingRepository', 'toolingSha', 'draftRevision', 'baselineGeneration']) &&
        token(value.sessionId) && token(value.revision) && isU32(value.draftRevision) && value.draftRevision < U32_MAX &&
        isU32(value.baselineGeneration) && value.baselineGeneration < U32_MAX &&
        githubSetupRequestFits({ draft: value.draft, toolingRepository: value.toolingRepository, toolingSha: value.toolingSha, suppliedSnapshot: null });
    }
  } catch { return false; }
}

function observation(value: unknown): value is WorkflowObservation {
  return keys(value, ['state']) && value.state === 'absent' ||
    keys(value, ['state', 'byteLength', 'sha256']) && value.state === 'present' && length(value.byteLength, 1048576) && digest(value.sha256);
}

function preparedView(value: unknown): value is WorkflowPreparedView {
  if (!boundedJson(value, 262144, 8000, 16) || !keys(value, ['schemaVersion', 'files', 'createDirectories', 'templateSet', 'tooling']) || value.schemaVersion !== 1 ||
      !Array.isArray(value.files) || value.files.length !== 4 || !Array.isArray(value.createDirectories)) return false;
  const template = value.templateSet;
  const tooling = value.tooling;
  if (!keys(template, ['coreVersion', 'resourceVersion', 'resourceSha256']) || !text(template.coreVersion, 32) ||
      !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(template.coreVersion) || template.resourceVersion !== 1 || !digest(template.resourceSha256) ||
      !keys(tooling, ['repository', 'sha', 'schemaReference', 'state']) || !text(tooling.repository, 140) || !repository.test(tooling.repository) ||
      !text(tooling.sha, 40) || !/^[0-9a-f]{40}$/.test(tooling.sha) || tooling.state !== 'format-only' ||
      tooling.schemaReference !== `https://raw.githubusercontent.com/${tooling.repository}/${tooling.sha}/schemas/project.schema.json`) return false;
  const directories = value.createDirectories;
  if (!(directories.length === 0 || directories.length === 1 && directories[0] === '.github/workflows' ||
      directories.length === 2 && directories[0] === '.github' && directories[1] === '.github/workflows')) return false;
  let bytes = 0;
  return value.files.every((file, index) => {
    if (!keys(file, ['id', 'path', 'action', 'observed', 'generated']) || file.id !== GITHUB_WORKFLOWS[index]?.id || file.path !== GITHUB_WORKFLOWS[index]?.path ||
        !oneOf(file.action, ['create', 'preserve']) || !observation(file.observed) ||
        !keys(file.generated, ['content', 'byteLength', 'sha256']) || !text(file.generated.content, 16384, false) ||
        !length(file.generated.byteLength, 16384) || file.generated.byteLength !== encoder.encode(file.generated.content).byteLength || !digest(file.generated.sha256)) return false;
    if (file.action === 'create' ? file.observed.state !== 'absent' : file.observed.state !== 'present' ||
        file.observed.byteLength !== file.generated.byteLength || file.observed.sha256 !== file.generated.sha256) return false;
    if (directories.length > 0 && file.action !== 'create') return false;
    bytes += file.generated.byteLength;
    return bytes <= 65536;
  });
}

function conflict(value: unknown): value is WorkflowConflict {
  if (!boundedJson(value, 4096, 256, 8) || !keys(value, ['schemaVersion', 'reason', 'conflicts']) || value.schemaVersion !== 1 ||
      value.reason !== 'existing_workflow_differs' || !Array.isArray(value.conflicts) || value.conflicts.length < 1 || value.conflicts.length > 4) return false;
  let previous = -1;
  return value.conflicts.every((row) => {
    if (!keys(row, ['id', 'observed']) || !observation(row.observed) || row.observed.state !== 'present') return false;
    const index = GITHUB_WORKFLOWS.findIndex((entry) => entry.id === row.id);
    if (index <= previous) return false;
    previous = index;
    return true;
  });
}

function outcome(value: unknown): value is CoreEditOutcome {
  if (!keys(value, ['effect', 'journal', 'resources', 'reason']) ||
      !oneOf(value.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) ||
      !oneOf(value.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) ||
      !oneOf(value.resources, ['settled', 'unknown']) || !oneOf(value.reason, coreReasons)) return false;
  if (value.effect === 'unchanged' && value.journal !== 'not_created') return false;
  if (oneOf(value.effect, ['committed', 'rolled_back']) && value.journal === 'not_created') return false;
  return value.reason !== 'none' || value.resources === 'settled' &&
    value.effect !== 'unknown' && value.journal !== 'unknown' && value.journal !== 'recovery_required';
}

function projection(value: unknown): value is GitHubWorkflowEditProjection {
  if (!keys(value, ['domain', 'projectId', 'sessionId', 'ownerGeneration', 'phase', 'reviewRemainingMs', 'checkout', 'prepared', 'conflict', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled']) ||
      value.domain !== 'github_workflows' || !text(value.projectId, 128) || !token(value.sessionId) || !token(value.ownerGeneration) ||
      !oneOf(value.phase, phases) || !length(value.reviewRemainingMs, 900000) || typeof value.applySubmitted !== 'boolean' || typeof value.lateSettled !== 'boolean' ||
      !oneOf(value.nativeReason, nativeReasons) || !oneOf(value.nativeFinality, ['pending', 'settled', 'unknown']) ||
      !(value.coreOutcome === null || outcome(value.coreOutcome)) || !(value.conflict === null || conflict(value.conflict))) return false;
  const checkout = value.checkout;
  if (checkout !== null && (!keys(checkout, ['revision', 'observed']) || !token(checkout.revision) || !Array.isArray(checkout.observed) ||
      checkout.observed.length !== 4 || !checkout.observed.every((row, index) => {
        if (!record(row) || row.id !== GITHUB_WORKFLOWS[index]?.id) return false;
        return keys(row, ['id', 'state']) && row.state === 'absent' || keys(row, ['id', 'state', 'byteLength', 'sha256']) &&
          row.state === 'present' && length(row.byteLength, 1048576) && digest(row.sha256);
      }))) return false;
  if (value.prepared !== null && (!keys(value.prepared, ['revision', 'planToken', 'draftRevision', 'baselineGeneration', 'view']) ||
      !token(value.prepared.revision) || !token(value.prepared.planToken) || !isU32(value.prepared.draftRevision) || !isU32(value.prepared.baselineGeneration) ||
      !preparedView(value.prepared.view) || !record(checkout) || value.prepared.revision !== checkout.revision)) return false;
  const result = value as unknown as GitHubWorkflowEditProjection;
  if (result.prepared && !result.prepared.view.files.every((file, index) => equal({ id: file.id, ...file.observed }, result.checkout?.observed[index]))) return false;
  if (result.conflict && (result.prepared !== null || result.applySubmitted || !['finalizing', 'final', 'unknown'].includes(result.phase) || !result.checkout ||
      !result.conflict.conflicts.every((row) => equal({ id: row.id, ...row.observed }, result.checkout?.observed.find((entry) => entry.id === row.id))) ||
      result.coreOutcome && (result.coreOutcome.effect !== 'not_started' || result.coreOutcome.journal !== 'not_created'))) return false;
  if (result.phase === 'final') {
    if (result.nativeFinality !== 'settled' || result.lateSettled) return false;
    if (result.coreOutcome === null) {
      if (result.checkout || result.prepared || result.conflict || result.applySubmitted || result.nativeReason === 'none') return false;
    } else if (result.coreOutcome.resources === 'unknown' || result.coreOutcome.effect === 'unknown' || result.coreOutcome.journal === 'unknown') return false;
  } else if (result.phase === 'unknown') {
    if (result.nativeFinality !== 'unknown') return false;
  } else if (result.nativeFinality !== 'pending' || result.lateSettled) return false;
  if (result.phase === 'opening' && (result.checkout || result.prepared || result.conflict || result.applySubmitted)) return false;
  if (['editing', 'preparing', 'reviewing', 'applying'].includes(result.phase) && !result.checkout) return false;
  if (['editing', 'preparing'].includes(result.phase) && (result.prepared || result.conflict || result.applySubmitted)) return false;
  if (['reviewing', 'applying'].includes(result.phase) && !result.prepared) return false;
  if (result.phase === 'reviewing' && result.applySubmitted || result.phase === 'applying' && !result.applySubmitted || result.applySubmitted && !result.prepared) return false;
  if (['opening', 'editing', 'preparing', 'reviewing'].includes(result.phase) && result.coreOutcome !== null) return false;
  if (result.coreOutcome && ['committed', 'rolled_back', 'unchanged'].includes(result.coreOutcome.effect)) {
    if (!result.checkout || !result.prepared || !result.applySubmitted || result.conflict) return false;
    const noWrites = result.prepared.view.files.every((file) => file.action === 'preserve');
    if (result.coreOutcome.effect === 'unchanged' ? !noWrites : noWrites) return false;
  }
  return true;
}

export function parseGitHubWorkflowEditStatus(value: unknown): GitHubWorkflowEditStatus | null {
  try {
    if (!boundedJson(value, 1024 * 1024, 20000, 24) || !keys(value, ['schemaVersion', 'domain', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
        value.schemaVersion !== 1 || value.domain !== 'github_workflows' || !token(value.windowGeneration) || !isU32(value.statusRevision) ||
        !keys(value.capability, ['available', 'reason']) || typeof value.capability.available !== 'boolean' || !oneOf(value.capability.reason, availability) ||
        value.capability.available !== (value.capability.reason === 'available') ||
        !(value.active === null || projection(value.active)) || !(value.lastTerminal === null || projection(value.lastTerminal))) return null;
    const result = value as unknown as GitHubWorkflowEditStatus;
    if (result.active?.phase === 'final' || result.active?.lateSettled || result.active && result.capability.reason === 'other_edit_active' ||
        result.lastTerminal && !['final', 'unknown'].includes(result.lastTerminal.phase) || result.active && result.active.sessionId === result.lastTerminal?.sessionId) return null;
    return result;
  } catch { return null; }
}

export function normalWorkflowResult(owner: GitHubWorkflowEditProjection): 'installed' | 'unchanged' | null {
  const core = owner.coreOutcome;
  if (owner.domain !== 'github_workflows' || owner.phase !== 'final' || owner.nativeFinality !== 'settled' || owner.nativeReason !== 'none' || owner.lateSettled ||
      !core || core.resources !== 'settled' || core.reason !== 'none' || !owner.applySubmitted || owner.conflict ||
      !owner.checkout || !owner.prepared || owner.prepared.revision !== owner.checkout.revision) return null;
  const noWrites = owner.prepared.view.files.every((file) => file.action === 'preserve');
  if (core.effect === 'committed' && core.journal === 'clean' && !noWrites) return 'installed';
  if (core.effect === 'unchanged' && core.journal === 'not_created' && noWrites) return 'unchanged';
  return null;
}

function equal(first: unknown, next: unknown): boolean { return sameJson(first as JsonValue, next as JsonValue); }
function sameFacts(first: GitHubWorkflowEditProjection, next: GitHubWorkflowEditProjection): boolean {
  return equal({ ...first, reviewRemainingMs: 0 }, { ...next, reviewRemainingMs: 0 });
}
export function workflowProjectionProgress(first: GitHubWorkflowEditProjection, next: GitHubWorkflowEditProjection): boolean {
  if (first.domain !== next.domain || first.sessionId !== next.sessionId || first.projectId !== next.projectId || first.ownerGeneration !== next.ownerGeneration ||
      first.checkout !== null && !equal(first.checkout, next.checkout) || first.prepared !== null && !equal(first.prepared, next.prepared) ||
      first.conflict !== null && !equal(first.conflict, next.conflict) || first.applySubmitted && !next.applySubmitted || first.lateSettled && !next.lateSettled) return false;
  if (first.phase === 'final') return sameFacts(first, next);
  if (first.phase === 'unknown' && next.phase !== 'unknown' || phases.indexOf(next.phase) < phases.indexOf(first.phase) ||
      first.nativeReason !== 'none' && first.nativeReason !== next.nativeReason) return false;
  if (first.coreOutcome && (!next.coreOutcome || first.coreOutcome.effect !== 'unknown' && first.coreOutcome.effect !== next.coreOutcome.effect ||
      first.coreOutcome.reason !== 'none' && first.coreOutcome.reason !== next.coreOutcome.reason)) return false;
  return true;
}
export function workflowStatusProgress(first: GitHubWorkflowEditStatus, next: GitHubWorkflowEditStatus): boolean {
  if (first.windowGeneration !== next.windowGeneration || next.statusRevision < first.statusRevision) return true;
  if (next.statusRevision === first.statusRevision) {
    if (!equal(first.capability, next.capability)) return false;
    return (['active', 'lastTerminal'] as const).every((key) => {
      const before = first[key]; const after = next[key];
      return before === null || after === null ? before === after : sameFacts(before, after);
    });
  }
  return [first.active, first.lastTerminal].every((before) => {
    if (!before) return true;
    const after = [next.active, next.lastTerminal].find((item) => item?.sessionId === before.sessionId);
    return !after || workflowProjectionProgress(before, after);
  });
}

export function workflowEditError(error: unknown): ApiError {
  let code: unknown;
  try { code = record(error) ? Object.getOwnPropertyDescriptor(error, 'code')?.value : undefined; }
  catch { /* Never inspect arbitrary rejection text or execute an accessor. */ }
  if (code === 'GitHubWorkflowStatusInvalid') return { code, message: 'Native workflow status did not match the closed contract. Observe the original owner; no successful installation or rollback is confirmed.', retryable: false };
  if (code === 'GitHubWorkflowRequestInvalid') return { code, message: 'The local workflow request did not fit the fixed bounded contract. No request was sent or truncated.', retryable: false };
  if (code === 'NativeBridgeRequired' || code === 'PreviewOnly') return { code, message: 'Local workflow review requires the qualified native owner. Browser preview never simulates an installation.', retryable: false };
  return { code: 'GitHubWorkflowEditUnavailable', message: 'The original native workflow operation could not be confirmed. Check its status; never resend an ambiguous Apply or open a replacement owner.', retryable: false };
}
