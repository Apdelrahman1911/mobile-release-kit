// Closed DTO admission only. Core owns lookup, version policy, help and command
// observations; the native owner alone supplies availability and finality.
import { environmentRequestFits } from './environment.ts';
import type { ApiError } from './types.ts';
import type { EnvironmentCheck, EnvironmentCheckId, EnvironmentDiagnosticsContext, EnvironmentDiagnosticsProjection,
  EnvironmentDiagnosticsResult, EnvironmentDiagnosticsStatus, StartEnvironmentDiagnostics } from './environmentDiagnosticsTypes.ts';

export const ENVIRONMENT_DIAGNOSTICS_EVENT = 'environment-diagnostics-state-changed';
export const ENVIRONMENT_DIAGNOSTICS_COUNTER_MAX = 0xffff_fffe;
export type EnvironmentDiagnosticsCommand = 'start_environment_diagnostics' | 'cancel_environment_diagnostics' | 'environment_diagnostics_status';
const encoder = new TextEncoder();
const outcomes = ['complete', 'partial', 'failed', 'cancelled', 'timed-out', 'unavailable'];
const notRun = ['invalid-draft', 'platform-disabled', 'host-mismatch', 'unsupported-host', 'missing-in-supported-lookup',
  'unsupported-installation', 'unselected-installation', 'full-xcode-not-selected', 'stopped'];
const attempted = ['command-incomplete', 'binding-changed', 'cancelled', 'timed-out'];
const completed = ['observed', 'nonzero-exit', 'version-unrecognized', 'selection-unrecognized'];
const rosters: Record<'linux' | 'macos', Record<'android' | 'ios', readonly EnvironmentCheckId[]>> = {
  linux: { android: ['git', 'java', 'javac'], ios: ['git', 'xcode'] },
  macos: { android: ['developer-selection', 'git', 'java', 'javac'], ios: ['developer-selection', 'git', 'xcode'] },
};
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
export function diagnosticsCounter(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= ENVIRONMENT_DIAGNOSTICS_COUNTER_MAX;
}
const token = (value: unknown): value is string => typeof value === 'string' && value.length === 32 && /^[0-9a-f]{32}$/.test(value);
const version = (value: unknown): value is string => typeof value === 'string' && !/[\r\n]/.test(value) && /^[0-9][0-9A-Za-z._+\-]{0,63}$/.test(value);
const build = (value: unknown): value is string => typeof value === 'string' && !/[\r\n]/.test(value) && /^[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?$/.test(value);
const roleVersion: Record<Exclude<EnvironmentCheckId, 'developer-selection'>, RegExp> = {
  git: /^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?(?:[.\-][0-9A-Za-z][0-9A-Za-z.+\-]{0,40})?$/,
  java: /^[0-9]{1,3}(?:[._][0-9]{1,6}){0,3}(?:[+\-][0-9A-Za-z][0-9A-Za-z.+_\-]{0,32})?$/,
  javac: /^[0-9]{1,3}(?:[._][0-9]{1,6}){0,3}(?:[+\-][0-9A-Za-z][0-9A-Za-z.+_\-]{0,32})?$/,
  xcode: /^[0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?$/,
};
const oneOf = (value: unknown, choices: readonly string[]): value is string => typeof value === 'string' && choices.includes(value);
function boundedData(value: unknown, limit: number): boolean {
  const pending: [unknown, number][] = [[value, 0]];
  let nodes = 0, floor = 0;
  while (pending.length) {
    const [item, depth] = pending.pop()!;
    if (++nodes > 20_000 || depth > 32) return false;
    if (item === null || typeof item === 'boolean') floor += 1;
    else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; floor += 1; }
    else if (typeof item === 'string') {
      if (item.length > limit || /[\ud800-\udfff]/u.test(item)) return false;
      floor += encoder.encode(item).byteLength + 2;
    } else {
      if (depth >= 32 || typeof item !== 'object' || item === null) return false;
      const names = Reflect.ownKeys(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || names.length !== item.length + 1 || item.length > 20_000 - nodes) return false;
        floor += 2 + item.length;
        for (let index = 0; index < item.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(item, String(index));
          if (descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return false;
          pending.push([descriptor.value, depth + 1]);
        }
      } else {
        if (!record(item) || names.length > 20_000 - nodes) return false;
        floor += 2 + 2 * names.length;
        for (const name of names) {
          const descriptor = Object.getOwnPropertyDescriptor(item, name);
          if (typeof name !== 'string' || descriptor?.enumerable !== true || !Object.hasOwn(descriptor, 'value')) return false;
          pending.push([name, depth + 1], [descriptor.value, depth + 1]);
        }
      }
    }
    if (floor > limit) return false;
  }
  return encoder.encode(JSON.stringify(value)).byteLength <= limit;
}
function context(value: unknown): value is EnvironmentDiagnosticsContext {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'platform', 'operation']) &&
    typeof value.projectId === 'string' && value.projectId.length > 0 && value.projectId.length <= 64 && !/[^A-Za-z0-9_-]/.test(value.projectId) &&
    diagnosticsCounter(value.draftRevision) && diagnosticsCounter(value.baselineGeneration) &&
    (value.platform === 'android' || value.platform === 'ios') && value.operation === 'build';
}
export function sameDiagnosticsContext(first: EnvironmentDiagnosticsContext, next: EnvironmentDiagnosticsContext): boolean {
  return first.projectId === next.projectId && first.draftRevision === next.draftRevision && first.baselineGeneration === next.baselineGeneration &&
    first.platform === next.platform && first.operation === next.operation;
}
// Inputs are data-descriptor checked before getters/serialization could run.
export function environmentDiagnosticsRequestFits(command: EnvironmentDiagnosticsCommand, value: unknown): boolean {
  try {
    if (command === 'environment_diagnostics_status') return keys(value, []);
    if (command === 'cancel_environment_diagnostics') return keys(value, ['runId', 'ownerGeneration']) && token(value.runId) && token(value.ownerGeneration);
    if (!keys(value, ['projectId', 'draft', 'draftRevision', 'baselineGeneration', 'platform', 'operation'])) return false;
    const { draft, ...binding } = value;
    return context(binding) && environmentRequestFits({ draft, platform: value.platform, operation: value.operation }) && boundedData(value, 1024 * 1024 - 1);
  } catch { return false; }
}
export function startEnvironmentDiagnosticsFits(value: unknown): value is StartEnvironmentDiagnostics {
  return environmentDiagnosticsRequestFits('start_environment_diagnostics', value);
}
const selectionDirectoryReasons = ['namespace-missing', 'namespace-inaccessible', 'directory-kind', 'directory-owner',
  'directory-world-write', 'directory-group-write'];
const selectionDiagnosticReasons: Record<string, readonly string[]> = {
  ...Object.fromEntries(['root', 'applications', 'contents', 'developer', 'library', 'library-developer', 'command-line-tools']
    .map((stage) => [stage, selectionDirectoryReasons])),
  application: [...selectionDirectoryReasons, 'alias-disallowed'],
  'selector-output': ['stderr-present', 'byte-shape', 'line-shape', 'utf8-invalid', 'path-shape', 'app-name'],
  'selection-path': ['path-depth', 'project-overlap'],
  alias: ['namespace-missing', 'namespace-inaccessible', 'alias-kind', 'alias-owner', 'target-bytes',
    'target-encoding', 'target-shape', 'identity-changed'],
};
function selectionDiagnostic(value: unknown): boolean {
  return keys(value, ['stage', 'reason']) && typeof value.stage === 'string' && Object.hasOwn(selectionDiagnosticReasons, value.stage) &&
    oneOf(value.reason, selectionDiagnosticReasons[value.stage]!) && encoder.encode(JSON.stringify(value)).byteLength < 160;
}
function check(value: unknown, id: EnvironmentCheckId): value is EnvironmentCheck {
  if ((!keys(value, ['id', 'state', 'reason', 'version', 'build', 'returnCode', 'baseline', 'assessment', 'help']) &&
      !keys(value, ['id', 'state', 'reason', 'version', 'build', 'returnCode', 'baseline', 'assessment', 'help', 'selectionDiagnostic'])) || value.id !== id ||
      !oneOf(value.state, ['not-run', 'attempted', 'completed']) || !oneOf(value.reason, value.state === 'not-run' ? notRun : value.state === 'attempted' ? attempted : completed) ||
      !oneOf(value.assessment, ['match', 'mismatch', 'no-local-policy', 'not-assessed']) ||
      typeof value.help !== 'string' || value.help.trim().length === 0 || encoder.encode(value.help).byteLength > 1024 || /[\u0000-\u001f\u007f]/u.test(value.help) ||
      !keys(value.baseline, ['kind', 'version', 'build']) || value.version !== null && !version(value.version) || value.build !== null && !build(value.build)) return false;
  if (Object.hasOwn(value, 'selectionDiagnostic') && value.selectionDiagnostic !== null &&
      (!selectionDiagnostic(value.selectionDiagnostic) || id !== 'developer-selection' || value.state !== 'completed' ||
        value.reason !== 'selection-unrecognized' || value.returnCode !== 0)) return false;
  const baseline = value.baseline;
  // Validate policy *shape* and joins, never maintain a second pin catalogue.
  if (id === 'java' || id === 'javac') {
    if (baseline.kind !== 'workflow-reference' || !version(baseline.version) || baseline.build !== null) return false;
  } else if (id === 'xcode') {
    if (baseline.kind !== 'exact-pin' || !version(baseline.version) || !build(baseline.build)) return false;
  } else if (baseline.kind !== 'no-local-policy' || baseline.version !== null || baseline.build !== null) return false;
  const empty = value.version === null && value.build === null && value.assessment === 'not-assessed';
  if (value.state !== 'completed') return empty && value.returnCode === null && (value.reason !== 'full-xcode-not-selected' || id === 'xcode');
  if (typeof value.returnCode !== 'number' || !Number.isInteger(value.returnCode) || value.returnCode < -0x8000_0000 || value.returnCode > 0x7fff_ffff ||
      (value.reason === 'nonzero-exit') !== (value.returnCode !== 0)) return false;
  if (value.reason !== 'observed') return empty && (value.reason === 'selection-unrecognized') === (id === 'developer-selection' && value.reason !== 'nonzero-exit');
  if (id === 'developer-selection') return empty;
  if (typeof value.version !== 'string' || !roleVersion[id].test(value.version)) return false;
  if (id === 'xcode') return value.version !== null && value.build !== null &&
    value.assessment === (value.version === baseline.version && value.build === baseline.build ? 'match' : 'mismatch');
  return value.version !== null && value.build === null && value.assessment === 'no-local-policy';
}
function result(value: unknown, expected: EnvironmentDiagnosticsContext): value is EnvironmentDiagnosticsResult {
  if (!keys(value, ['schemaVersion', 'policyVersion', 'context', 'hostPlatform', 'outcome', 'checks', 'commandsAttempted', 'lifetime', 'assurance']) ||
      value.schemaVersion !== 1 || value.policyVersion !== 'environment-diagnostics-v1' || !context(value.context) || !sameDiagnosticsContext(value.context, expected) ||
      !(value.hostPlatform === 'linux' || value.hostPlatform === 'macos') || !oneOf(value.outcome, outcomes) || !Array.isArray(value.checks)) return false;
  const roles = rosters[value.hostPlatform][expected.platform];
  if (value.checks.length !== roles.length || !value.checks.every((row, index) => roles[index] !== undefined && check(row, roles[index]!))) return false;
  const checks = value.checks as EnvironmentCheck[];
  const attempts = value.commandsAttempted;
  if (!diagnosticsCounter(attempts) || attempts > 4 || attempts !== checks.filter((row) => row.state !== 'not-run').length) return false;
  if (value.hostPlatform === 'linux' && expected.platform === 'ios' && (attempts !== 0 || checks.some((row) => row.state !== 'not-run'))) return false;
  for (const row of checks) {
    if (['invalid-draft', 'platform-disabled', 'host-mismatch', 'unsupported-host'].includes(row.reason) &&
        (attempts !== 0 || checks.some((other) => other.reason !== row.reason))) return false;
    if (row.reason === 'host-mismatch' && !(value.hostPlatform === 'linux' && expected.platform === 'ios')) return false;
  }
  const java = checks.find((row) => row.id === 'java'), javac = checks.find((row) => row.id === 'javac');
  if (java && javac && !sameDiagnosticsData(java.baseline, javac.baseline)) return false;
  const assurance = value.assurance;
  if (!keys(assurance, ['basis', 'toolsAttempted', 'projectCodeExecuted', 'projectFilesRead', 'repositoryObserved', 'sdkInspected', 'credentialsRead',
      'storeContacted', 'dependencyCompleteness', 'releaseReadiness', 'toolCacheEffects']) || assurance.basis !== 'local-tool-observation' ||
      assurance.toolsAttempted !== (attempts > 0) || assurance.dependencyCompleteness !== 'unknown' || assurance.releaseReadiness !== 'unknown' || assurance.toolCacheEffects !== 'possible' ||
      !['projectCodeExecuted', 'projectFilesRead', 'repositoryObserved', 'sdkInspected', 'credentialsRead', 'storeContacted'].every((key) => assurance[key] === false)) return false;
  const lifetime = value.lifetime;
  if (!keys(lifetime, ['complete', 'fatal', 'contained', 'commandDispatched', 'commands', 'inputClosed', 'handlersRestored', 'toolDescriptorsClosed', 'stopObserved']) ||
      !['complete', 'fatal', 'contained', 'inputClosed', 'handlersRestored', 'toolDescriptorsClosed'].every((key) => typeof lifetime[key] === 'boolean') ||
      !(lifetime.commandDispatched === null || typeof lifetime.commandDispatched === 'boolean') || !diagnosticsCounter(lifetime.commands) || lifetime.commands > attempts ||
      !oneOf(lifetime.stopObserved, ['none', 'cancelled', 'timed-out'])) return false;
  if (!(lifetime.fatal || lifetime.complete && lifetime.contained && lifetime.commandDispatched !== null)) return false;
  const completedCount = checks.filter((row) => row.state === 'completed').length;
  if (completedCount > lifetime.commands || completedCount > 0 && lifetime.commandDispatched !== true ||
      checks.some((row) => row.state === 'attempted' && (row.reason === 'cancelled' || row.reason === 'timed-out') && row.reason !== lifetime.stopObserved)) return false;
  const coreSettled = lifetime.complete && !lifetime.fatal && lifetime.contained && lifetime.commandDispatched !== null &&
    lifetime.inputClosed && lifetime.handlersRestored && lifetime.toolDescriptorsClosed;
  if (value.outcome === 'complete' || value.outcome === 'unavailable') return Boolean(coreSettled && lifetime.stopObserved === 'none' &&
    checks.every((row) => row.state !== 'attempted' && row.reason !== 'stopped') && (value.outcome === 'unavailable') === (attempts === 0) &&
    lifetime.commands === attempts && lifetime.commandDispatched === (attempts > 0));
  if (value.outcome === 'partial' || value.outcome === 'failed') return (value.outcome === 'partial') === checks.some((row) => row.state === 'completed') && lifetime.stopObserved === 'none';
  return lifetime.stopObserved === value.outcome;
}
function projection(value: unknown, terminal: boolean): value is EnvironmentDiagnosticsProjection {
  if (!keys(value, ['runId', 'ownerGeneration', 'context', 'phase', 'outcome', 'finality', 'reason', 'result']) || !token(value.runId) || !token(value.ownerGeneration) ||
      !context(value.context) || !oneOf(value.phase, ['starting', 'checking', 'stopping', 'settled', 'retained-unknown']) ||
      !oneOf(value.finality, ['pending', 'settled', 'unknown']) || value.outcome !== null && !oneOf(value.outcome, outcomes) ||
      !oneOf(value.reason, ['none', 'cancelled', 'context-changed', 'document-lost', 'shutdown', 'timed-out', 'protocol-error', 'runtime-unavailable', 'command-failed', 'cleanup-unknown']) ||
      value.result !== null && !result(value.result, value.context)) return false;
  const row = value as unknown as EnvironmentDiagnosticsProjection;
  if (row.finality !== (row.phase === 'settled' ? 'settled' : row.phase === 'retained-unknown' ? 'unknown' : 'pending') ||
      terminal && row.finality === 'pending' || !terminal && row.phase === 'settled' || row.finality !== 'pending' && row.outcome === null) return false;
  const lifetime = row.result?.lifetime;
  if (row.finality === 'settled' && lifetime && !(lifetime.complete && !lifetime.fatal && lifetime.contained && lifetime.commandDispatched !== null &&
      lifetime.inputClosed && lifetime.handlersRestored && lifetime.toolDescriptorsClosed)) return false;
  if (row.phase === 'starting' || row.phase === 'checking') return row.reason === 'none' && row.outcome === null && row.result === null;
  if (row.reason === 'none') return row.finality !== 'unknown' && row.result !== null && row.outcome === row.result.outcome &&
    (row.outcome === 'complete' || row.outcome === 'unavailable');
  const expected = ['cancelled', 'context-changed', 'document-lost', 'shutdown'].includes(row.reason) ? 'cancelled' : row.reason === 'timed-out' ? 'timed-out' :
    row.reason === 'runtime-unavailable' && row.result === null ? 'unavailable' : row.result?.checks.some((check) => check.state === 'completed') ? 'partial' : 'failed';
  return row.outcome === expected;
}
export function parseEnvironmentDiagnosticsStatus(value: unknown): EnvironmentDiagnosticsStatus | null {
  try {
    if (!boundedData(value, 65536) || !keys(value, ['schemaVersion', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
        value.schemaVersion !== 1 || !diagnosticsCounter(value.statusRevision) || !keys(value.capability, ['available', 'reason']) ||
        !oneOf(value.capability.reason, ['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified']) ||
        value.capability.available !== (value.capability.reason === 'available') ||
        value.active !== null && !projection(value.active, false) || value.lastTerminal !== null && !projection(value.lastTerminal, true)) return null;
    const status = value as unknown as EnvironmentDiagnosticsStatus;
    if (status.active && (status.capability.available || status.active.runId === status.lastTerminal?.runId) ||
        [status.active, status.lastTerminal].some((row) => row?.finality === 'unknown') && status.capability.reason !== 'cleanup-unknown') return null;
    return structuredClone(status);
  } catch { return null; }
}
// Only call on admitted immutable DTOs; object key order is not wire authority.
export function sameDiagnosticsData(first: unknown, next: unknown): boolean {
  if (first === next) return true;
  if (typeof first !== 'object' || first === null || typeof next !== 'object' || next === null || Array.isArray(first) !== Array.isArray(next)) return false;
  const a = Object.keys(first), b = Object.keys(next);
  return a.length === b.length && a.every((key) => Object.hasOwn(next, key) &&
    sameDiagnosticsData((first as Record<string, unknown>)[key], (next as Record<string, unknown>)[key]));
}
export function diagnosticsProjectionProgress(first: EnvironmentDiagnosticsProjection, next: EnvironmentDiagnosticsProjection): boolean {
  if (first.runId !== next.runId || first.ownerGeneration !== next.ownerGeneration || !sameDiagnosticsContext(first.context, next.context) ||
      first.result !== null && !sameDiagnosticsData(first.result, next.result) || first.reason !== 'none' && first.reason !== next.reason) return false;
  if (first.finality === 'settled') return sameDiagnosticsData(first, next);
  if (first.finality === 'unknown' && next.finality !== 'unknown') return false;
  const rank = { starting: 0, checking: 1, stopping: 2, settled: 3, 'retained-unknown': 3 };
  return rank[next.phase] >= rank[first.phase];
}
export function diagnosticsStatusProgress(first: EnvironmentDiagnosticsStatus, next: EnvironmentDiagnosticsStatus): boolean {
  if (next.statusRevision < first.statusRevision) return false;
  if (next.statusRevision === first.statusRevision) return sameDiagnosticsData(first, next);
  if (first.capability.reason === 'cleanup-unknown' && next.capability.reason !== 'cleanup-unknown') return false;
  if (first.active) {
    const retained = next.active?.runId === first.active.runId ? next.active : next.lastTerminal?.runId === first.active.runId ? next.lastTerminal : null;
    if (!retained || !diagnosticsProjectionProgress(first.active, retained)) return false;
  }
  if (first.lastTerminal) {
    if (next.active?.runId === first.lastTerminal.runId) return false;
    if (next.lastTerminal?.runId === first.lastTerminal.runId) {
      if (!diagnosticsProjectionProgress(first.lastTerminal, next.lastTerminal)) return false;
    } else if (!next.lastTerminal || first.lastTerminal.finality === 'unknown') return false;
  }
  return true;
}
const errors: Record<string, string> = {
  environment_diagnostics_invalid: 'This build-tool request is invalid. Review the current configuration draft and selected activity.',
  environment_diagnostics_unavailable: 'The separate native build-tool diagnostics service is unavailable. No check was confirmed.',
  environment_diagnostics_connection_lost: 'The diagnostics bridge reply was lost or unusable. Read native status; the original run may still be owned.',
  environment_diagnostics_busy: 'Another original native operation owns the service. Read its status before requesting another check.',
  environment_diagnostics_owner: 'The request does not identify the original native diagnostics run. Read native status; do not substitute another run.',
  environment_diagnostics_status_invalid: 'Native diagnostics returned invalid or contradictory status. Ownership is unverified; new checks are disabled.',
  protocol_error: 'Native diagnostics did not return a usable protocol response. Read original status; no result is assumed.',
  query_timeout: 'The original native admission deadline elapsed. Read its status; do not infer a completed tool observation.',
  unknown_project: 'This project is not registered in the original native document. Select it again before requesting a check.',
  cleanup_unknown: 'Original native cleanup is unconfirmed. Keep the application open; conflicting operations remain disabled.',
  shutting_down: 'The application is stopping original native operations. No new check is permitted.',
};
export function environmentDiagnosticsError(error: unknown): ApiError {
  // A transport failure must never be relabelled as the native pre-admission
  // unavailable refusal: that would incorrectly erase uncertain Start intent.
  let code = 'environment_diagnostics_connection_lost';
  try {
    const descriptor = typeof error === 'object' && error !== null ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
  } catch { /* No arbitrary rejection text, getters, tool output or input values. */ }
  return { code, message: errors[code]!, retryable: false };
}
