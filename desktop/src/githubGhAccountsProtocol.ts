// A finite list of local configuration names, not credentials/authentication.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionOpaqueId, connectionRepository, connectionRevision, GITHUB_CONNECTION_REASONS } from './githubConnectionProtocol.ts';
import type { GitHubConnectionReason } from './githubConnectionTypes.ts';

export interface GitHubGhAccountsRequest { projectId: string; repository: string; expectedDocumentRevision: number; expectedConnectionRevision: number }
export interface GitHubGhAccountsStatus {
  schemaVersion: 1; kind: 'accounts'; documentRevision: number; connectionRevision: number; available: boolean;
  operationId: string; projectId: string; repository: string;
  phase: 'reading' | 'stopping' | 'settled' | 'failed' | 'cleanup-unknown'; reason: GitHubConnectionReason;
  accounts: { observationId: string; logins: readonly string[]; current: boolean } | null;
}
const revision = (v: unknown): v is number => connectionRevision(v) && v < 0xffff_ffff;
export const ghListedLogin = (v: unknown): v is string => typeof v === 'string' && v.length <= 39 &&
  /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$(?![\s\S])/.test(v) && !v.includes('--');
export function parseGitHubGhAccountsRequest(value: unknown): GitHubGhAccountsRequest | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 24);
    return keys(v, ['projectId', 'repository', 'expectedDocumentRevision', 'expectedConnectionRevision']) &&
      connectionOpaqueId(v.projectId) && connectionRepository(v.repository) && revision(v.expectedDocumentRevision) && revision(v.expectedConnectionRevision)
      ? v as unknown as GitHubGhAccountsRequest : null;
  } catch { return null; }
}
export function parseGitHubGhAccountsStatus(value: unknown): GitHubGhAccountsStatus | null {
  try {
    const v = copyBoundedComparisonData(value, 8192, 128);
    if (!keys(v, ['schemaVersion', 'kind', 'documentRevision', 'connectionRevision', 'available', 'operationId', 'projectId', 'repository', 'phase', 'reason', 'accounts']) ||
      v.schemaVersion !== 1 || v.kind !== 'accounts' || !connectionRevision(v.documentRevision) || !connectionRevision(v.connectionRevision) ||
      typeof v.available !== 'boolean' || !connectionOpaqueId(v.operationId) || !connectionOpaqueId(v.projectId) || !connectionRepository(v.repository) ||
      !['reading', 'stopping', 'settled', 'failed', 'cleanup-unknown'].includes(v.phase as string) ||
      !(GITHUB_CONNECTION_REASONS as readonly unknown[]).includes(v.reason)) return null;
    if (v.phase === 'cleanup-unknown' ? v.reason !== 'cleanup-unknown' : v.phase === 'reading' || v.phase === 'settled' ? v.reason !== 'none' : v.reason === 'none') return null;
    if (v.phase === 'settled' && v.accounts === null) return null;
    if (v.accounts !== null) {
      if (v.phase !== 'settled' || !keys(v.accounts, ['observationId', 'logins', 'current']) || !connectionOpaqueId(v.accounts.observationId) ||
        typeof v.accounts.current !== 'boolean' || !Array.isArray(v.accounts.logins) || v.accounts.logins.length > 16 || !v.accounts.logins.every(ghListedLogin)) return null;
      const logins = v.accounts.logins as string[];
      if (logins.some((name, i) => i > 0 && logins[i - 1]!.toLowerCase() >= name.toLowerCase())) return null;
    }
    return v as unknown as GitHubGhAccountsStatus;
  } catch { return null; }
}
export const ghAccountsActive = (status: GitHubGhAccountsStatus | null): boolean => !!status && (status.phase === 'reading' || status.phase === 'stopping');
