// Fixed Desktop Commit approval. The private draft is never sent to the CLI.
import { Permission, type PermissionApi, type PermissionContext } from './service_git_permission.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { gitReadPathOrder } from './gitReadProtocol.ts';
export const GIT_COMMIT_CONSENT = 'agent-local-git-commit-once-v1';
export interface GitCommitApproval {
  readonly projectId: string; readonly expectedDocumentRevision: number; readonly readOperationId: string;
  readonly message: string; readonly authorName: string; readonly authorEmail: string;
}
export interface GitCommitSelection {
  readonly summary: { readonly action: 'commit'; readonly repositoryRevision: string; readonly pathCount: number; readonly selectionSha256: string };
  readonly paths: readonly string[];
}
export interface GitCommitAccess {
  readonly enabled: boolean; readonly remainingMs: number; readonly consumed: boolean;
  readonly projectId: string | null; readonly grantId: string | null; readonly selection: GitCommitSelection | null;
}
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const bytes = (v: string) => new TextEncoder().encode(v).length;
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-zA-Z0-9_-]{1,96}$/.test(v);
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && /^[0-9a-f]+$/.test(v) && (n !== 32 || !/^0+$/.test(v));
const text = (v: unknown, limit: number, multiline: boolean): v is string => typeof v === 'string' && bytes(v) <= limit
  && !/[\p{Cs}]/u.test(v) && !(multiline ? /[\x00-\x08\x0b-\x1f\x7f]/ : /[\x00-\x1f\x7f]/).test(v);
export function copyGitCommitApproval(value: unknown): GitCommitApproval | null {
  try {
    const v = copyBoundedComparisonData(value, 96 * 1024 - 96, 24);
    if (!keys(v, ['projectId', 'expectedDocumentRevision', 'readOperationId', 'message', 'authorName', 'authorEmail'])
      || !id(v.projectId) || v.projectId.length > 64 || !id(v.readOperationId)
      || typeof v.expectedDocumentRevision !== 'number' || !Number.isSafeInteger(v.expectedDocumentRevision)
      || v.expectedDocumentRevision < 1 || v.expectedDocumentRevision >= 0xffffffff
      || !text(v.message, 4096, true) || !v.message.trim() || !text(v.authorName, 128, false) || !v.authorName || /[<>]/.test(v.authorName)
      || !text(v.authorEmail, 254, false) || /[\s<>]/u.test(v.authorEmail) || v.authorEmail.split('@').length !== 2 || !v.authorEmail.split('@').every(Boolean)) return null;
    return Object.freeze({ projectId: v.projectId, expectedDocumentRevision: v.expectedDocumentRevision, readOperationId: v.readOperationId,
      message: v.message, authorName: v.authorName, authorEmail: v.authorEmail });
  } catch { return null; }
}
export function parseGitCommitAccess(value: unknown): GitCommitAccess | null {
  try {
    const v = copyBoundedComparisonData(value, 128 * 1024, 220);
    if (!keys(v, ['enabled', 'remainingMs', 'consumed', 'projectId', 'grantId', 'selection'])
      || typeof v.enabled !== 'boolean' || typeof v.consumed !== 'boolean' || typeof v.remainingMs !== 'number'
      || !Number.isSafeInteger(v.remainingMs) || v.remainingMs < 0 || v.remainingMs > 900000
      || v.enabled && (v.consumed || !v.remainingMs) || !v.enabled && v.remainingMs !== 0) return null;
    if (v.projectId === null || v.grantId === null || v.selection === null) return v.projectId === null && v.grantId === null && v.selection === null && !v.enabled && !v.consumed
      ? Object.freeze({ enabled: false, remainingMs: 0, consumed: false, projectId: null, grantId: null, selection: null }) : null;
    if (!hex(v.projectId, 32) || !hex(v.grantId, 32) || !keys(v.selection, ['summary', 'paths'])
      || !keys(v.selection.summary, ['action', 'repositoryRevision', 'pathCount', 'selectionSha256']) || !Array.isArray(v.selection.paths)) return null;
    const s = v.selection.summary, paths: unknown[] = v.selection.paths;
    const validPaths = (p: unknown, i: number): p is string => typeof p === 'string' && !!p && text(p, 1024, false) && !p.includes('\\')
      && p.split('/').length <= 32 && p.split('/').every(part => !!part && bytes(part) <= 255 && !['.', '..', '.git'].includes(part))
      && (i === 0 || typeof paths[i - 1] === 'string' && gitReadPathOrder(paths[i - 1] as string, p) < 0);
    if (s.action !== 'commit' || !hex(s.repositoryRevision, 64) || !hex(s.selectionSha256, 64)
      || !paths.length || paths.length > 64 || s.pathCount !== paths.length || !paths.every(validPaths)) return null;
    return Object.freeze({ enabled: v.enabled, remainingMs: v.remainingMs, consumed: v.consumed, projectId: v.projectId, grantId: v.grantId,
      selection: Object.freeze({ summary: Object.freeze({ action: 'commit', repositoryRevision: s.repositoryRevision, pathCount: paths.length, selectionSha256: s.selectionSha256 }), paths: Object.freeze([...paths]) }) });
  } catch { return null; }
}
export type GitCommitApi = PermissionApi<GitCommitApproval, GitCommitAccess>;
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
export function createGitCommitApi(mode: string, invoke: Invoke): GitCommitApi | null {
  if (mode !== 'native') return null;
  const failure = () => ({ code: 'agent_git_commit_unconfirmed', message: 'Commit permission was not confirmed. Inspect or stop it in the original Desktop; do not repeat the commit.', retryable: false });
  const call = async (command: 'agent_git_commit_access' | 'allow_agent_git_commit' | 'revoke_agent_git_commit', input: unknown): Promise<GitCommitAccess> => {
    try {
      const raw = new TextEncoder().encode(JSON.stringify(input)); if (raw.length + 96 > 96 * 1024) throw failure();
      const result = parseGitCommitAccess(await invoke<unknown>(command, raw)); if (!result) throw failure(); return result;
    } catch { throw failure(); }
  };
  return Object.freeze({ status: () => call('agent_git_commit_access', {}), revoke: () => call('revoke_agent_git_commit', {}),
    allow: (input: GitCommitApproval) => { const safe = copyGitCommitApproval(input); return safe ? call('allow_agent_git_commit', { ...safe, consentVersion: GIT_COMMIT_CONSENT }) : Promise.reject(failure()); } });
}
export class GitCommitPermission extends Permission<GitCommitApproval, GitCommitAccess> {
  constructor(current: () => PermissionContext<GitCommitApproval, GitCommitAccess>) { super(copyGitCommitApproval, current); }
}
