// Closed raw IPC and renderer projection. No private review stamp, root path,
// control file or command can be supplied by the renderer.
import type { ApiError } from './types.ts';
import type { PrepareProjectRecovery, ProjectRecoveryAvailability, ProjectRecoveryContext, ProjectRecoveryIdentity,
  ProjectRecoveryLimitation, ProjectRecoveryObservation, ProjectRecoveryOperation, ProjectRecoveryReason,
  ProjectRecoveryResult, ProjectRecoveryStatus, StartProjectRecovery } from './projectRecoveryTypes.ts';

export const PROJECT_RECOVERY_EVENT = 'project-recovery-state-changed';
export const PROJECT_RECOVERY_CONSENT = 'reviewed-project-build-input-recovery-v1';
export const PROJECT_RECOVERY_COUNTER_MAX = 0xffff_fffe;
export const PROJECT_RECOVERY_CONSENT_MS = 300_000;
export const PROJECT_RECOVERY_LIMITATIONS: readonly ProjectRecoveryLimitation[] = ['build-inputs-only-not-store-or-account-recovery',
  'recorded-quiescence-not-new-worker-proof', 'foreign-changes-preserved', 'cancellation-does-not-undo-completed-cleanup',
  'project-and-release-readiness-not-assessed'];
export type ProjectRecoveryCommand = 'prepare_project_recovery' | 'start_project_recovery' | 'cancel_project_recovery' | 'project_recovery_status';
const encoder = new TextEncoder();
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const oneOf = <T extends string>(value: unknown, options: readonly T[]): value is T => typeof value === 'string' && options.includes(value as T);
export const recoveryCounter = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) &&
  !Object.is(value, -0) && value >= 0 && value <= PROJECT_RECOVERY_COUNTER_MAX;
const integer = (value: unknown, max: number): value is number => recoveryCounter(value) && value <= max;
const projectId = (value: unknown): value is string => typeof value === 'string' && value.length >= 1 && value.length <= 64 && !/[^A-Za-z0-9_-]/.test(value);
const token = (value: unknown): value is string => typeof value === 'string' && value.length === 32 && /^[0-9a-f]{32}$/.test(value);

// Inspect descriptors before reading values, cloning or serialization. Every
// returned object is our copy, not the supplied object and not its prototype.
// Bounds apply during collection as well as to the final encoded closed DATA.
function copyData(input: unknown, maxBytes: number, maxNodes = 4096): unknown {
  let nodes = 0, bytes = 0;
  const ancestors = new Set<object>();
  const charge = (amount: number) => { bytes += amount; if (bytes > maxBytes) throw new Error(); };
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > maxNodes || depth > 12) throw new Error();
    if (value === null || typeof value === 'boolean') { charge(5); return value; }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) throw new Error();
      charge(String(value).length); return value;
    }
    if (typeof value === 'string') {
      if (value.length > maxBytes || /[\ud800-\udfff]/u.test(value)) throw new Error();
      charge(encoder.encode(value).byteLength + 2); return value;
    }
    if (typeof value !== 'object' || ancestors.has(value)) throw new Error();
    ancestors.add(value);
    try {
      const prototype: unknown = Object.getPrototypeOf(value);
      if (Array.isArray(value)) {
        const length = Object.getOwnPropertyDescriptor(value, 'length');
        if (prototype !== Array.prototype || !length || !Object.hasOwn(length, 'value') ||
            !integer(length.value, 4096) || length.value > maxNodes - nodes) throw new Error();
        const names = Reflect.ownKeys(value);
        if (names.length !== length.value + 1) throw new Error();
        charge(2 + length.value);
        const output: unknown[] = [];
        for (let i = 0; i < length.value; i++) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
          if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new Error();
          output.push(copy(descriptor.value, depth + 1));
        }
        return output;
      }
      if (prototype !== Object.prototype && prototype !== null) throw new Error();
      const names = Reflect.ownKeys(value);
      if (names.length > maxNodes - nodes) throw new Error();
      charge(2 + 2 * names.length);
      const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      for (const name of names) {
        if (typeof name !== 'string' || name === 'toJSON') throw new Error();
        const descriptor = Object.getOwnPropertyDescriptor(value, name);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw new Error();
        copy(name, depth + 1); // Keys consume the same byte/node allowance.
        output[name] = copy(descriptor.value, depth + 1);
      }
      return output;
    } finally { ancestors.delete(value); }
  };
  const value = copy(input, 0);
  if (encoder.encode(JSON.stringify(value)).byteLength > maxBytes) throw new Error();
  return value;
}
function observation(value: unknown): value is ProjectRecoveryObservation {
  if (!keys(value, ['status', 'session', 'roles', 'quiescence']) ||
      !oneOf(value.status, ['idle', 'busy', 'conflict', 'pending', 'cleanup-only']) ||
      !oneOf(value.quiescence, ['none', 'original', 'operator']) || !Array.isArray(value.roles) || value.roles.length > 2) return false;
  const roles = value.roles;
  if (!roles.every((role: unknown) => oneOf(role, ['android-services', 'ios-services'])) ||
      roles.some((role, index) => {
        const previous = roles[index - 1];
        return index > 0 && (previous === undefined || previous >= role);
      })) return false;
  if (['idle', 'busy', 'conflict'].includes(value.status)) return value.session === null && value.roles.length === 0 && value.quiescence === 'none';
  return token(value.session) && (value.status !== 'cleanup-only' || value.roles.length === 0 && value.quiescence !== 'none');
}
export function recoveryEligible(value: ProjectRecoveryObservation): boolean {
  return ['pending', 'cleanup-only'].includes(value.status) && ['original', 'operator'].includes(value.quiescence);
}
function prepare(value: unknown): value is PrepareProjectRecovery {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'action']) && projectId(value.projectId) &&
    recoveryCounter(value.draftRevision) && recoveryCounter(value.baselineGeneration) && oneOf(value.action, ['inspect', 'recover']);
}
function identity(value: unknown): value is ProjectRecoveryIdentity {
  return record(value) && token(value.operationId) && token(value.ownerGeneration);
}
function context(value: unknown): value is ProjectRecoveryContext {
  return keys(value, ['projectId', 'draftRevision', 'baselineGeneration', 'action', 'review']) && projectId(value.projectId) &&
    recoveryCounter(value.draftRevision) && recoveryCounter(value.baselineGeneration) &&
    (value.action === 'inspect' ? value.review === null : value.action === 'recover' && observation(value.review) && recoveryEligible(value.review));
}
export function copyProjectRecoveryRequest(command: ProjectRecoveryCommand, value: unknown): PrepareProjectRecovery | StartProjectRecovery | ProjectRecoveryIdentity | Record<string, never> | null {
  try {
    const safe = copyData(value, 8192, 64);
    if (command === 'prepare_project_recovery' && prepare(safe)) return safe;
    if (command === 'start_project_recovery' && keys(safe, ['operationId', 'ownerGeneration', 'consentVersion']) &&
        identity(safe) && safe.consentVersion === PROJECT_RECOVERY_CONSENT) return safe as unknown as StartProjectRecovery;
    if (command === 'cancel_project_recovery' && keys(safe, ['operationId', 'ownerGeneration']) && identity(safe)) return safe;
    if (command === 'project_recovery_status' && keys(safe, [])) return safe as Record<string, never>;
  } catch { /* No input accessors or serialization hooks are executed. */ }
  return null;
}
export function encodeProjectRecoveryRequest(command: ProjectRecoveryCommand, value: unknown): Uint8Array | null {
  const copy = copyProjectRecoveryRequest(command, value);
  return copy === null ? null : encoder.encode(JSON.stringify(copy));
}
function result(value: unknown, selected: ProjectRecoveryContext): value is ProjectRecoveryResult {
  if (!keys(value, ['schemaVersion', 'scope', 'action', 'observation', 'recoveredSession', 'limitations']) ||
      value.schemaVersion !== 1 || value.scope !== 'project-build-inputs-only' || value.action !== selected.action ||
      !Array.isArray(value.limitations) || value.limitations.length !== PROJECT_RECOVERY_LIMITATIONS.length) return false;
  const limitations = value.limitations;
  if (!PROJECT_RECOVERY_LIMITATIONS.every((item, index) => limitations[index] === item)) return false;
  return value.action === 'inspect' ? observation(value.observation) && value.recoveredSession === null :
    value.observation === null && selected.review !== null && value.recoveredSession === selected.review.session;
}
export const recoveryAvailabilityText: Record<ProjectRecoveryAvailability, string> = {
  available: 'This installed build supports local build-input recovery. Inspect first, then explicitly review a recovery attempt.',
  busy: 'Another original operation still owns the project slot. Finish or cancel it and wait for confirmed cleanup.',
  shutdown: 'The application is stopping. No new recovery operation can start.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the original status and files; conflicting work and normal exit remain blocked.',
  'document-lost': 'The original native document is unavailable. Reconnecting cannot replace its operation or reset cleanup.',
  'unsupported-platform': 'Project build-input recovery is not supported by this host profile. Windows is not supported by this core path.',
  'runtime-unqualified': 'Project recovery is disabled in this build until its exact bundled runtime and native lifecycle have been independently verified.',
};
export const recoveryReasonText: Record<ProjectRecoveryReason, string> = {
  none: 'No lifecycle failure was reported. This operation concerns project build inputs only, not release readiness.',
  cancelled: 'Cancellation stopped further work when possible. Cleanup already performed is not undone.',
  'context-changed': 'The selected project or review context changed. Its old consent cannot be used again.',
  'document-lost': 'The original app document was lost. Preserve the original status rather than starting a replacement operation.',
  shutdown: 'Shutdown stopped further work; original cleanup must still settle.',
  'timed-out': 'The original deadline was reached. Checking status does not extend it or authorize a retry.',
  'protocol-error': 'A complete, valid original result was not received. Do not infer that files were recovered.',
  'runtime-unavailable': 'The separately verified bundled runtime is unavailable. The app will not select an ambient Python installation.',
  'intent-expired': 'The inspection/review expired. Inspect again; status refresh never renews recovery permission.',
  'stale-intent': 'The original review is stale or belongs to an earlier project registration. Inspect again after the original settles.',
  'project-changed': 'The actual selected project directory changed. Its private recovery data was not opened using the old registration.',
  'review-stale': 'The recorded session or checkpoint changed since inspection. No attempt based on the old review is allowed.',
  'manual-required': 'The record lacks original-worker finality. This UI cannot assert that workers are idle or force cleanup. Preserve the files and investigate the original operation.',
  'project-busy': 'Another owner holds the project lock. This app will not take over or stop that owner.',
  'project-conflict': 'The original core refused conflicting or changed recovery state. Unrelated changes must be preserved; do not delete recovery files to force a retry.',
  'recovery-incomplete': 'The recovery action did not produce a confirmed result. Preserve its original state and inspect only after known settlement.',
  'input-limit': 'The bounded request limit was exceeded. Nothing in the rejected request authorizes recovery.',
  'result-limit': 'The bounded output limit was exceeded. No complete report was accepted.',
  'cleanup-unknown': 'Original resource cleanup is unconfirmed. Keep the original owner and files; reconnecting is not recovery.',
};
export function parseProjectRecoveryStatus(value: unknown): ProjectRecoveryStatus | null {
  try {
    const safe = copyData(value, 32768, 1024);
    if (!keys(safe, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || safe.schemaVersion !== 1 ||
        !recoveryCounter(safe.statusRevision) || !oneOf(safe.availability, Object.keys(recoveryAvailabilityText))) return null;
    const op = safe.operation;
    if (op === null) return safe as unknown as ProjectRecoveryStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result', 'effect']) ||
        !identity(op) || !context(op.context) || !oneOf(op.phase, ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown']) ||
        typeof op.intentUsable !== 'boolean' || !oneOf(op.reason, Object.keys(recoveryReasonText)) ||
        !(op.effect === null || oneOf(op.effect, ['not-attempted', 'inspection', 'recovery-attempted'])) ||
        op.effect === 'inspection' && op.context.action !== 'inspect' || op.effect === 'recovery-attempted' && op.context.action !== 'recover') return null;
    if (op.phase === 'awaiting-consent') {
      if (op.outcome !== null || op.result !== null || op.effect !== null || op.reason !== 'none') return null;
    } else if (op.phase === 'unknown') {
      if (op.intentUsable || op.outcome !== 'unknown' || op.result !== null || op.effect !== null || op.reason !== 'cleanup-unknown') return null;
    } else if (op.phase === 'terminal') {
      if (op.intentUsable || !oneOf(op.outcome, ['complete', 'refused', 'cancelled', 'timed-out', 'failed']) ||
          (op.reason === 'none') !== (op.outcome === 'complete')) return null;
      if (op.outcome === 'complete') {
        if (!result(op.result, op.context) || op.effect !== (op.context.action === 'inspect' ? 'inspection' : 'recovery-attempted')) return null;
      } else if (op.result !== null) return null;
    } else if (op.intentUsable || op.outcome !== null || op.result !== null || op.effect !== null) return null;
    return safe as unknown as ProjectRecoveryStatus;
  } catch { return null; }
}
// These comparisons accept only validated copied DATA, never arbitrary objects.
export function sameRecoveryData(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>, right = b as Record<string, unknown>, names = Object.keys(left);
  return names.length === Object.keys(right).length && names.every((name) => Object.hasOwn(right, name) && sameRecoveryData(left[name], right[name]));
}
export function sameRecoveryIdentity(a: ProjectRecoveryIdentity | null, b: ProjectRecoveryIdentity | null): boolean {
  return !!a && !!b && a.operationId === b.operationId && a.ownerGeneration === b.ownerGeneration;
}
export function recoveryOperationProgress(a: ProjectRecoveryOperation, b: ProjectRecoveryOperation): boolean {
  if (!sameRecoveryIdentity(a, b) || !sameRecoveryData(a.context, b.context)) return false;
  if (a.phase === 'unknown') return b.phase === 'unknown';
  if (a.phase === 'terminal') return sameRecoveryData(a, b);
  if (!a.intentUsable && b.intentUsable) return false;
  const order = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'];
  return order.indexOf(b.phase) >= order.indexOf(a.phase);
}
const errors: Record<string, string> = {
  project_recovery_invalid: 'The recovery request is invalid. No recovery was authorized by this response.',
  project_recovery_unavailable: 'The separate native recovery capability is unavailable. There is no browser or ambient-runtime fallback.',
  project_recovery_busy: 'Another original operation owns the native slot. Keep its status and cancellation accessible.',
  project_recovery_owner: 'The inspection or one-use review is absent, expired, foreign or consumed. Inspect again; never repeat Start.',
  project_recovery_protocol: 'A usable original response was not received. Check retained status; do not repeat recovery.',
};
export function projectRecoveryError(value: unknown): ApiError {
  let code = 'project_recovery_protocol';
  try {
    const descriptor = value !== null && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'code') : undefined;
    const candidate: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof candidate === 'string' && Object.hasOwn(errors, candidate)) code = candidate;
  } catch { /* Private error strings, getters, paths and tool output are not UI text. */ }
  return { code, message: errors[code]!, retryable: false };
}
