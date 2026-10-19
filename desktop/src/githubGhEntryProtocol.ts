// Selected-gh DATA only. No account discovery, path, token, process, provider
// nomination or native authority is accepted or returned by this adapter.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionOpaqueId, connectionRepository, connectionRevision,
  GITHUB_CONNECTION_REASONS, parseGitHubConnectionStatus } from './githubConnectionProtocol.ts';
import type { GitHubConnectionObservationPort, GitHubConnectionReason, GitHubConnectionStatus } from './githubConnectionTypes.ts';

export type GitHubGhCommand = 'github_auth_status' | 'github_auth_connect' | 'github_auth_cancel';
export type GitHubGhPhase = 'idle' | 'picking' | 'running' | 'checking-identity' | 'stopping' | 'settled' | 'failed' | 'cleanup-unknown';
export interface GitHubGhRequest {
  projectId: string; repository: string; selectedLogin: string;
  expectedDocumentRevision: number; expectedConnectionRevision: number;
}
export interface GitHubGhStatus {
  schemaVersion: 1; documentRevision: number; connectionRevision: number; available: boolean;
  operationId: string | null; projectId: string | null; repository: string | null; selectedLogin: string | null;
  phase: GitHubGhPhase; reason: GitHubConnectionReason;
  http: { sessionId: string; operationId: string } | null;
}
export type GitHubGhResult = { schemaVersion: 1; operationId: string } & (
  { outcome: 'http-handoff'; connection: GitHubConnectionStatus } |
  { outcome: 'no-http' | 'unknown'; auth: GitHubGhStatus });
export interface GitHubGhApi {
  readonly mode: 'native';
  status(): Promise<unknown>;
  connect(request: GitHubGhRequest): Promise<unknown>;
  cancel(request: { operationId: string }): Promise<unknown>;
}
// A nonsecret entry attached to the SAME existing connection observer. It
// cannot bypass the existing controller's context/help/native-capability gate.
export interface GitHubGhHandoff {
  port: GitHubConnectionObservationPort;
  submit(request: GitHubGhRequest): Promise<unknown>;
}
const phases = ['idle', 'picking', 'running', 'checking-identity', 'stopping', 'settled', 'failed', 'cleanup-unknown'];
export const ghLoginFits = (value: unknown): value is string => typeof value === 'string' && value.length <= 39 &&
  /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$(?![\s\S])/.test(value);
export const ghAdmissionRevision = (value: unknown): value is number => connectionRevision(value) && value < 0xffff_ffff;
const reasonFits = (value: unknown): value is GitHubConnectionReason => typeof value === 'string' &&
  (GITHUB_CONNECTION_REASONS as readonly string[]).includes(value);
export const ghActive = (status: GitHubGhStatus | null): boolean => !!status &&
  ['picking', 'running', 'checking-identity', 'stopping'].includes(status.phase);

export function parseGitHubGhRequest(value: unknown): GitHubGhRequest | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 32);
    return keys(v, ['projectId', 'repository', 'selectedLogin', 'expectedDocumentRevision', 'expectedConnectionRevision']) &&
      connectionOpaqueId(v.projectId) && connectionRepository(v.repository) && ghLoginFits(v.selectedLogin) &&
      ghAdmissionRevision(v.expectedDocumentRevision) && ghAdmissionRevision(v.expectedConnectionRevision)
      ? v as unknown as GitHubGhRequest : null;
  } catch { return null; }
}
export function encodeGitHubGhRequest(command: GitHubGhCommand, value: unknown): Uint8Array | null {
  try {
    const v = command === 'github_auth_connect' ? parseGitHubGhRequest(value) : copyBoundedComparisonData(value, 1024, 8);
    if (!(command === 'github_auth_status' ? keys(v, []) : command === 'github_auth_cancel'
      ? keys(v, ['operationId']) && connectionOpaqueId(v.operationId) : command === 'github_auth_connect' && v !== null)) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v));
    return bytes.byteLength + command.length + 32 <= 1024 ? bytes : null;
  } catch { return null; }
}

export function parseGitHubGhStatus(value: unknown): GitHubGhStatus | null {
  try {
    const v = copyBoundedComparisonData(value, 8192, 64);
    if (!keys(v, ['schemaVersion', 'documentRevision', 'connectionRevision', 'available', 'operationId', 'projectId',
      'repository', 'selectedLogin', 'phase', 'reason', 'http']) || v.schemaVersion !== 1 ||
      !connectionRevision(v.documentRevision) || !connectionRevision(v.connectionRevision) || typeof v.available !== 'boolean' ||
      typeof v.phase !== 'string' || !phases.includes(v.phase) || !reasonFits(v.reason)) return null;
    if (v.phase === 'idle') {
      if ([v.operationId, v.projectId, v.repository, v.selectedLogin, v.http].some((f) => f !== null) ||
          v.reason !== (v.available ? 'none' : 'runtime-unavailable')) return null;
    } else {
      if (!connectionOpaqueId(v.operationId) || !connectionOpaqueId(v.projectId) || !connectionRepository(v.repository) || !ghLoginFits(v.selectedLogin)) return null;
      if (v.http !== null && (!keys(v.http, ['sessionId', 'operationId']) || !connectionOpaqueId(v.http.sessionId) || !connectionOpaqueId(v.http.operationId))) return null;
      if (v.phase === 'cleanup-unknown' ? v.reason !== 'cleanup-unknown' :
          ['picking', 'running', 'checking-identity', 'settled'].includes(v.phase) ? v.reason !== 'none' : v.reason === 'none') return null;
    }
    return v as unknown as GitHubGhStatus;
  } catch { return null; }
}

export function parseGitHubGhResult(value: unknown): GitHubGhResult | null {
  try {
    const v = copyBoundedComparisonData(value, 73728, 4096);
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    const row = v as Record<string, unknown>;
    if (row.schemaVersion !== 1 || !connectionOpaqueId(row.operationId)) return null;
    if (row.outcome === 'http-handoff' && keys(row, ['schemaVersion', 'operationId', 'outcome', 'connection'])) {
      const connection = parseGitHubConnectionStatus(row.connection);
      // The native result slot holds the historical admission, not a later
      // current Connected snapshot. Newer existing connection events win.
      if (!connection?.session || connection.session.state !== 'checking' || connection.operation?.kind !== 'connect' ||
          connection.operation.phase !== 'running' || connection.operation.reason !== 'none') return null;
      return { schemaVersion: 1, operationId: row.operationId, outcome: 'http-handoff', connection };
    }
    if (!['no-http', 'unknown'].includes(row.outcome as string) || !keys(row, ['schemaVersion', 'operationId', 'outcome', 'auth'])) return null;
    const auth = parseGitHubGhStatus(row.auth);
    if (!auth || auth.operationId !== row.operationId || (row.outcome === 'no-http'
      ? auth.phase !== 'failed' || auth.http !== null || auth.reason === 'cleanup-unknown'
      : auth.phase !== 'cleanup-unknown')) return null;
    return { schemaVersion: 1, operationId: row.operationId, outcome: row.outcome as 'no-http' | 'unknown', auth };
  } catch { return null; }
}

export function ghResultMatches(result: GitHubGhResult, request: GitHubGhRequest): boolean {
  return result.outcome === 'http-handoff' ? result.connection.session?.projectId === request.projectId &&
    result.connection.session.targetRepository === request.repository && result.connection.revision > request.expectedConnectionRevision :
    result.auth.projectId === request.projectId && result.auth.repository === request.repository && result.auth.selectedLogin === request.selectedLogin;
}

// These codes are returned before the NEW entry installs its original. After
// registration native returns a typed result or cleanup_unknown, never a
// generic refusal. No caller admission flag/message or arbitrary error counts.
const refusals: Readonly<Record<string, GitHubConnectionReason>> = Object.freeze({
  github_connection_refused_unqualified: 'unqualified', github_connection_refused_runtime_unavailable: 'runtime-unavailable',
  github_connection_refused_invalid_input: 'invalid-input', github_connection_refused_busy: 'busy',
  github_connection_refused_target_changed: 'target-changed', github_connection_refused_rate_limited: 'rate-limited',
  github_connection_refused_expired: 'expired', github_connection_refused_cancelled: 'cancelled', invalid_request: 'invalid-input',
});
export function githubGhFailure(value: unknown): { reason: GitHubConnectionReason; notAdmitted: boolean; code: string | null } {
  try {
    if (value && typeof value === 'object') {
      const field = Object.getOwnPropertyDescriptor(value, 'code'), code: unknown = field && Object.hasOwn(field, 'value') ? field.value : null;
      if (typeof code === 'string' && Object.hasOwn(refusals, code)) return { reason: refusals[code]!, notAdmitted: true, code };
    }
  } catch { /* No private error detail or accessor becomes guidance. */ }
  return { reason: 'response-invalid', notAdmitted: false, code: null };
}
export const ghUnconfirmed = () => ({ code: 'GitHubGhUnconfirmed', message: 'The original GitHub CLI request could not be confirmed. Check its status; do not repeat it.', retryable: false as const });

/** Only these three NEW commands are RAW. Existing PAT transport is untouched. */
export function createGitHubGhApi(mode: string, invoke: (command: GitHubGhCommand, body: Uint8Array) => Promise<unknown>): GitHubGhApi | null {
  if (mode !== 'native') return null;
  const call = (command: GitHubGhCommand, request: unknown) => {
    const bytes = encodeGitHubGhRequest(command, request);
    if (!bytes) throw { code: 'github_connection_refused_invalid_input', message: 'The GitHub CLI request is invalid. Nothing was sent.', retryable: false };
    return invoke(command, bytes);
  };
  return Object.freeze({ mode: 'native' as const, status: () => call('github_auth_status', {}),
    connect: (r: GitHubGhRequest) => call('github_auth_connect', r), cancel: (r: { operationId: string }) => call('github_auth_cancel', r) });
}
