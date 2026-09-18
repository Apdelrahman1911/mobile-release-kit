// Closed public DATA admission. No invoke, fetch, browser fallback or credential
// collection. Native must separately enforce document/operation/expiry authority.
import { GITHUB_WORKFLOWS } from './githubSetupProtocol.ts';
import type { GitHubConnectionError, GitHubConnectionHelp, GitHubConnectionReason, GitHubConnectionStatus } from './githubConnectionTypes.ts';

export const GITHUB_CONNECTION_ENTRY_AVAILABLE = false;
export const GITHUB_CONNECTION_EVENT = 'github-connection-status';
export const GITHUB_CONNECTION_REASONS = ['none', 'unqualified', 'runtime-unavailable', 'publisher-unconfigured',
  'not-connected', 'invalid-input', 'busy', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'target-changed',
  'rate-limited', 'network-unavailable', 'tls-failed', 'response-invalid', 'response-limit', 'expired', 'stale', 'cancelled', 'cleanup-unknown'] as const;
export const GITHUB_CONNECTION_REASON_HELP: Readonly<Record<GitHubConnectionReason, string>> = Object.freeze({
  none: 'The reported observation is available, not release or mutation authority.',
  unqualified: 'GitHub connection is not qualified. No credential entry is available.',
  'runtime-unavailable': 'The required native runtime is unavailable. There is no browser fallback.',
  'publisher-unconfigured': 'Preferred App/device login needs a registered publisher configuration.',
  'not-connected': 'No account has been observed for this original session.',
  'invalid-input': 'The input does not satisfy the bounded connection contract.',
  busy: 'An original observation is pending. Status and exact-session Disconnect remain available.',
  unauthorized: 'Authentication was refused. Retire the original request before explicitly authenticating again.',
  forbidden: 'Access was forbidden; token, organization or SSO policy may apply. Do not escalate automatically.',
  'not-found-or-inaccessible': 'The repository was not found or is inaccessible; absence is not established.',
  'target-changed': 'The original account, repository or context identity changed. Do not adopt the replacement.',
  'rate-limited': 'GitHub limited this read. There is no automatic retry or native cooldown bypass.',
  'network-unavailable': 'The bounded read failed. Raw service diagnostics are not displayed.',
  'tls-failed': 'TLS verification failed. Do not disable verification or supply alternate trust.',
  'response-invalid': 'The original result did not satisfy the closed response contract.',
  'response-limit': 'The bounded response limit was reached. No broader discovery is authorized.',
  expired: 'The native session expired. Retained observations are stale; Status does not renew it.',
  stale: 'This is a previous observation, not current access or setup verification.',
  cancelled: 'Local retirement was requested; actual original settlement must still be observed.',
  'cleanup-unknown': 'Original cleanup is unknown. Further requests stay blocked even after late success.',
});

// These nine codes alone mean that THIS command installed no native ticket.
// Do not trust a caller-supplied admission marker, message or generic error code.
const REFUSALS: Readonly<Record<string, GitHubConnectionReason>> = Object.freeze({
  github_connection_refused_unqualified: 'unqualified',
  github_connection_refused_runtime_unavailable: 'runtime-unavailable',
  github_connection_refused_invalid_input: 'invalid-input',
  github_connection_refused_busy: 'busy',
  github_connection_refused_target_changed: 'target-changed',
  github_connection_refused_rate_limited: 'rate-limited',
  github_connection_refused_expired: 'expired',
  github_connection_refused_cancelled: 'cancelled',
  github_connection_refused_cleanup_unknown: 'cleanup-unknown',
});
export function githubConnectionError(value: unknown): GitHubConnectionError {
  try {
    if (value !== null && typeof value === 'object') {
      const field = Object.getOwnPropertyDescriptor(value, 'code');
      const code: unknown = field && Object.hasOwn(field, 'value') ? field.value : null;
      if (typeof code === 'string' && Object.hasOwn(REFUSALS, code)) {
        const reason = REFUSALS[code]!;
        return { code, message: GITHUB_CONNECTION_REASON_HELP[reason], retryable: false, reason, admission: 'not-admitted' };
      }
    }
  } catch { /* No getter, exception text or raw rejection becomes guidance. */ }
  return { code: 'GitHubConnectionResponseUnavailable', message: 'No usable acknowledgement was received. Read retained Status or retire the identified original session; do not replay the request.',
    retryable: false, reason: 'response-invalid', admission: 'unknown' };
}

const encoder = new TextEncoder();
const RECORD = Object.prototype;
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === RECORD || Object.getPrototypeOf(value) === null);
}
function keys(value: unknown, names: readonly string[]): value is Record<string, unknown> {
  return record(value) && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}
function oneOf(value: unknown, values: readonly string[]): value is string { return typeof value === 'string' && values.includes(value); }
function text(value: unknown, bytes: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= bytes && !!value.trim() &&
    !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value) && encoder.encode(value).byteLength <= bytes;
}
function bounded(value: unknown, bytes: number, nodesLimit: number, depthLimit: number): boolean {
  let nodes = 0; let floor = 0;
  const ancestors = new Set<object>();
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > nodesLimit || depth > depthLimit) return false;
    if (item === null || typeof item === 'boolean') floor += 1;
    else if (typeof item === 'number') { if (!Number.isFinite(item)) return false; floor += 1; }
    else if (typeof item === 'string') {
      if (item.length > bytes || /\p{Cs}/u.test(item)) return false;
      floor += encoder.encode(item).byteLength + 2;
    } else {
      if (typeof item !== 'object' || depth >= depthLimit || ancestors.has(item)) return false;
      ancestors.add(item);
      if (Array.isArray(item)) {
        if (Object.getPrototypeOf(item) !== Array.prototype || item.length > nodesLimit - nodes || Reflect.ownKeys(item).length !== item.length + 1) return false;
        floor += 2 + Math.max(0, item.length - 1);
        if (floor > bytes) return false;
        for (let i = 0; i < item.length; i += 1) {
          const field = Object.getOwnPropertyDescriptor(item, String(i));
          if (!field?.enumerable || !Object.hasOwn(field, 'value') || !visit(field.value, depth + 1)) return false;
        }
      } else {
        if (!record(item)) return false;
        const names = Reflect.ownKeys(item);
        if (names.length > nodesLimit - nodes) return false;
        floor += 2 + Math.max(0, names.length * 2 - 1);
        if (floor > bytes) return false;
        for (const name of names) {
          if (typeof name !== 'string') return false;
          const field = Object.getOwnPropertyDescriptor(item, name);
          if (!field?.enumerable || !Object.hasOwn(field, 'value') || !visit(name, depth + 1) || !visit(field.value, depth + 1)) return false;
        }
      }
      ancestors.delete(item);
    }
    return floor <= bytes;
  };
  try { return visit(value, 0) && encoder.encode(JSON.stringify(value)).byteLength <= bytes; } catch { return false; }
}
export function connectionOpaqueId(value: unknown): value is string { return typeof value === 'string' && value.length > 0 && value.length <= 64 && !/[^A-Za-z0-9_-]/.test(value); }
export function connectionRevision(value: unknown): value is number { return typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= 0xffff_ffff; }
export function connectionRepository(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 140 && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$(?![\s\S])/.test(value);
}
function numericId(value: unknown): value is string {
  return typeof value === 'string' && /^[1-9][0-9]{0,19}$(?![\s\S])/.test(value) && (value.length < 20 || value <= '18446744073709551615');
}
function utc(value: unknown): value is string {
  if (typeof value !== 'string' || value.length !== 20 || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value) || value.startsWith('0000')) return false;
  const parsed = new Date(value); // Parse display DATA, never read the current clock.
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value.slice(0, -1) + '.000Z';
}
function reason(value: unknown): value is GitHubConnectionReason { return oneOf(value, GITHUB_CONNECTION_REASONS); }
function account(value: unknown): boolean { return keys(value, ['id', 'login']) && numericId(value.id) && text(value.login, 96); }
function repository(value: unknown): boolean {
  return keys(value, ['id', 'fullName', 'defaultBranch', 'visibility', 'archived', 'permissions']) && numericId(value.id) &&
    connectionRepository(value.fullName) && text(value.defaultBranch, 1024) && oneOf(value.visibility, ['public', 'private', 'internal']) &&
    typeof value.archived === 'boolean' && keys(value.permissions, ['pull', 'push', 'admin']) &&
    Object.values(value.permissions).every((p) => oneOf(p, ['reported-allowed', 'reported-denied', 'unknown']));
}
function automation(value: unknown): boolean {
  if (!keys(value, ['coverage', 'workflows']) || !oneOf(value.coverage, ['complete', 'limited']) || !Array.isArray(value.workflows) || value.workflows.length !== 4) return false;
  const seen = new Set<string>();
  return value.workflows.every((row, index) => {
    if (!keys(row, ['id', 'remoteId', 'presence', 'state']) || row.id !== GITHUB_WORKFLOWS[index]?.id ||
        !oneOf(row.presence, ['listed', 'not-listed', 'unknown']) || !oneOf(row.state, ['active', 'disabled', 'unknown']) ||
        row.presence === (value.coverage === 'complete' ? 'unknown' : 'not-listed')) return false;
    if (row.presence === 'listed') {
      if (!numericId(row.remoteId) || seen.has(row.remoteId)) return false;
      seen.add(row.remoteId); return true;
    }
    return row.remoteId === null && row.state === 'unknown';
  });
}
function fact(value: unknown, admit: (value: unknown) => boolean): boolean {
  if (!keys(value, ['state', 'value', 'observedAt', 'reason']) || !reason(value.reason)) return false;
  if (value.state === 'not-observed' || value.state === 'unavailable') return value.value === null && value.observedAt === null &&
    value.reason !== 'none' && (value.state !== 'not-observed' || value.reason === 'not-connected');
  return oneOf(value.state, ['observed', 'stale']) && (value.reason === 'none') === (value.state === 'observed') && utc(value.observedAt) && admit(value.value);
}

export function parseGitHubConnectionStatus(value: unknown): GitHubConnectionStatus | null {
  try {
    if (!bounded(value, 65536, 2000, 12) || !keys(value, ['schemaVersion', 'revision', 'capability', 'session', 'operation', 'account', 'repository', 'automation', 'facts']) ||
        value.schemaVersion !== 1 || !connectionRevision(value.revision) ||
        !keys(value.capability, ['readOnlySessionAvailable', 'reason', 'deviceLogin', 'storage']) ||
        typeof value.capability.readOnlySessionAvailable !== 'boolean' || !reason(value.capability.reason) ||
        value.capability.readOnlySessionAvailable !== (value.capability.reason === 'none') ||
        !oneOf(value.capability.deviceLogin, ['publisher-unconfigured', 'not-qualified']) || value.capability.storage !== 'session-only' ||
        !fact(value.account, account) || !fact(value.repository, repository) || !fact(value.automation, automation)) return null;
    const session = value.session; const operation = value.operation;
    if (session !== null && (!keys(session, ['id', 'projectId', 'targetRepository', 'state', 'expiresAt']) ||
        !connectionOpaqueId(session.id) || !connectionOpaqueId(session.projectId) || !connectionRepository(session.targetRepository) ||
        !oneOf(session.state, ['checking', 'connected', 'expired', 'disconnecting', 'failed', 'cleanup-unknown']) ||
        !(session.expiresAt === null || utc(session.expiresAt)))) return null;
    if (operation !== null && (!keys(operation, ['id', 'kind', 'phase', 'reason']) || !connectionOpaqueId(operation.id) ||
        !oneOf(operation.kind, ['connect', 'refresh', 'disconnect']) || !oneOf(operation.phase, ['running', 'settled', 'cleanup-unknown']) || !reason(operation.reason) ||
        (operation.phase === 'cleanup-unknown') !== (operation.reason === 'cleanup-unknown') ||
        operation.phase === 'running' && operation.reason !== 'none')) return null;
    if (!keys(value.facts, ['remoteMutationAvailable', 'dispatchAvailable', 'repositoryActionsSettingsObservation', 'environmentObservation', 'secretObservation',
      'variableObservation', 'protectionObservation', 'runnerObservation', 'templateCompatibility', 'releaseReadiness']) ||
        value.facts.remoteMutationAvailable !== false || value.facts.dispatchAvailable !== false ||
        value.facts.templateCompatibility !== 'unknown' || value.facts.releaseReadiness !== 'unknown' ||
        !['repositoryActionsSettingsObservation', 'environmentObservation', 'secretObservation', 'variableObservation', 'protectionObservation', 'runnerObservation'].every((k) => value.facts && (value.facts as Record<string, unknown>)[k] === 'not-run')) return null;
    const result = value as unknown as GitHubConnectionStatus;
    const facts = [result.account, result.repository, result.automation];
    if ((result.capability.reason === 'cleanup-unknown') !== (result.session?.state === 'cleanup-unknown')) return null;
    if (facts.some((f) => f.reason === 'cleanup-unknown') && result.session?.state !== 'cleanup-unknown') return null;
    if (result.repository.value && !result.account.value || result.automation.value && !result.repository.value) return null;
    if (result.repository.state === 'observed' && result.account.state !== 'observed' ||
        result.automation.state === 'observed' && result.repository.state !== 'observed') return null;
    if (result.session === null) {
      if (result.operation !== null || facts.some((f) => f.state !== 'not-observed')) return null;
    } else {
      const s = result.session; const op = result.operation;
      if (result.repository.value && result.repository.value.fullName.toLowerCase() !== s.targetRepository.toLowerCase()) return null;
      if (s.state === 'checking' && (!op || op.kind === 'disconnect' || op.phase !== 'running' || facts.some((f) => f.state === 'observed'))) return null;
      if (s.state === 'connected' && (s.expiresAt === null || result.account.state !== 'observed' || op && (op.phase !== 'settled' || op.kind === 'disconnect'))) return null;
      if (s.state === 'disconnecting' && (!op || op.kind !== 'disconnect' || op.phase !== 'running')) return null;
      if (s.state === 'cleanup-unknown' && (!op || op.phase !== 'cleanup-unknown' || result.capability.readOnlySessionAvailable || result.capability.reason !== 'cleanup-unknown')) return null;
      if (s.state !== 'cleanup-unknown' && op?.phase === 'cleanup-unknown') return null;
      if (['expired', 'failed'].includes(s.state) && op && op.phase !== 'settled') return null;
      if (s.state === 'expired' && s.expiresAt === null) return null;
      if (['expired', 'failed', 'disconnecting', 'cleanup-unknown'].includes(s.state) && facts.some((f) => f.state === 'observed')) return null;
    }
    return JSON.parse(JSON.stringify(result)) as GitHubConnectionStatus;
  } catch { return null; }
}

export function sameConnectionData(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
  const names = Object.keys(a);
  return names.length === Object.keys(b).length && names.every((key) => Object.hasOwn(b, key) &&
    sameConnectionData((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]));
}
export function connectionProgress(old: GitHubConnectionStatus, next: GitHubConnectionStatus): boolean {
  if (next.revision <= old.revision) return next.revision === old.revision && sameConnectionData(old, next);
  const first = old.session; const second = next.session;
  if (first?.state === 'cleanup-unknown' && (!second || second.id !== first.id || second.state !== 'cleanup-unknown')) return false;
  if (first && second) {
    if (first.id !== second.id || first.projectId !== second.projectId || first.targetRepository !== second.targetRepository) return false;
    if (first.expiresAt !== null && (second.expiresAt === null || second.expiresAt > first.expiresAt)) return false;
    if (first.state === 'expired' && !['expired', 'disconnecting', 'cleanup-unknown'].includes(second.state)) return false;
    const op = old.operation; const after = next.operation;
    if (first.state === 'disconnecting' && !['disconnecting', 'cleanup-unknown'].includes(second.state)) {
      // Automatic retirement stays Running until the original owner settles.
      // Its same Disconnect may then expose expiry/context retirement, never
      // new facts, usable credentials, a replacement operation or read revival.
      if (op?.kind !== 'disconnect' || op.phase !== 'running' || after?.id !== op.id || after.kind !== 'disconnect' || after.phase !== 'settled' ||
          !(second.state === 'expired' && after.reason === 'expired' || second.state === 'failed' && ['cancelled', 'target-changed'].includes(after.reason)) ||
          next.capability.readOnlySessionAvailable ||
          [next.account, next.repository, next.automation].some((f) => f.state === 'observed') ||
          !sameConnectionData(old.account, next.account) || !sameConnectionData(old.repository, next.repository) || !sameConnectionData(old.automation, next.automation)) return false;
    }
    if (first.state === 'failed' && ['checking', 'connected'].includes(second.state) &&
        (!connectionRetryable(old) || next.operation?.kind !== 'refresh' || next.operation.id === old.operation?.id)) return false;
    if (old.account.value && next.account.value && old.account.value.id !== next.account.value.id ||
        old.repository.value && next.repository.value && old.repository.value.id !== next.repository.value.id) return false;
    if (op && !after) return false;
    if (op && after) {
      if (op.id === after.id && (op.kind !== after.kind || op.phase === 'settled' && (after.phase !== 'settled' || after.reason !== op.reason) ||
          op.phase === 'cleanup-unknown' && after.phase !== 'cleanup-unknown')) return false;
      if (op.id !== after.id && (after.kind === 'connect' || op.phase !== 'settled' && after.kind !== 'disconnect' ||
          after.kind === 'refresh' && first.state === 'failed' && !connectionRetryable(old))) return false;
    }
  }
  return true;
}

export function connectionRetryable(status: GitHubConnectionStatus): boolean {
  return status.capability.readOnlySessionAvailable && status.session?.state === 'failed' && status.session.expiresAt !== null &&
    status.operation?.phase === 'settled' && status.operation.kind !== 'disconnect' &&
    ['network-unavailable', 'tls-failed', 'response-limit', 'rate-limited', 'forbidden', 'not-found-or-inaccessible'].includes(status.operation.reason);
  // response-invalid retires credential use under the accepted control policy.
  // An expired/unknown operation, or the same settled ID, can never run again.
}

// This validator returns only a Boolean, never an echo, retained private object
// or Debug diagnostic. It is not native admission or credential ownership.
export function githubConnectionRequestFits(command: unknown, args: unknown): boolean {
  try {
    if (!oneOf(command, ['github_connection_status', 'github_connection_connect_token', 'github_connection_refresh', 'github_connection_disconnect']) ||
        !bounded({ command, args }, 8192, 128, 6)) return false;
    if (command === 'github_connection_status') return keys(args, []);
    if (command === 'github_connection_disconnect') return keys(args, ['sessionId']) && connectionOpaqueId(args.sessionId);
    if (command === 'github_connection_refresh') return keys(args, ['sessionId', 'expectedRevision']) && connectionOpaqueId(args.sessionId) && connectionRevision(args.expectedRevision);
    return keys(args, ['projectId', 'repository', 'token']) && connectionOpaqueId(args.projectId) && connectionRepository(args.repository) &&
      typeof args.token === 'string' && args.token.length > 0 && args.token.length <= 4096 && !/[^\x21-\x7e]/.test(args.token);
  } catch { return false; }
}

export function parseGitHubConnectionHelp(value: unknown): GitHubConnectionHelp | null {
  try {
    if (!bounded(value, 32768, 2000, 12) || !keys(value, ['schemaVersion', 'inputs', 'guidance']) || value.schemaVersion !== 1) return null;
    for (const [field, ids] of [
      ['inputs', ['repository', 'token']],
      ['guidance', ['authentication', 'permissions', 'session-memory', 'repository-identity', 'automation-observation', 'remote-changes', 'revocation']],
    ] as const) {
      const entries = value[field];
      if (!Array.isArray(entries) || entries.length !== ids.length || !entries.every((entry, index) =>
        keys(entry, ['id', 'label', 'what', 'why', 'where', 'format', 'failure', ...(field === 'inputs' ? ['requiredness'] : [])]) &&
        entry.id === ids[index] && text(entry.label, 96) && ['what', 'why', 'where', 'format', 'failure'].every((k) => text(entry[k], 1024)) &&
        (field !== 'inputs' || entry.requiredness === (entry.id === 'repository' ? 'required' : 'conditional')))) return null;
    }
    return JSON.parse(JSON.stringify(value)) as GitHubConnectionHelp;
  } catch { return null; }
}
