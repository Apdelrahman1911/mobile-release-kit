// One closed Remote permission on the existing finite Permission controller.
// All values are comparison DATA; no token, native review or send is made here.
import { Permission, gitPermissionRevision, type PermissionApi, type PermissionContext } from './service_git_permission.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { isGitFetchAction, type GitFetchAction } from './gitFetchProtocol.ts';
import { isGitPushAction, type GitPushAction } from './gitPushProtocol.ts';
import { isGitPushNewBranchAction, gitPushNewBranchActionFor, type GitPushNewBranchAction } from './gitPushNewBranchProtocol.ts';
import { gitFetchAccount, gitFetchDraftReady, gitFetchLocalSource } from './gitFetchSelection.ts';
import { gitPushAccount, gitPushActionFor } from './gitPushSelection.ts';
import { sameGitLocalData, gitLocalIssueHelp } from './gitLocalProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import type { GitRepositoryController } from './gitRepositoryController.ts';
import type { GitReadController } from './gitReadController.ts';
import type { GitLocalController } from './gitLocalController.ts';
export type GitRemoteAction = GitFetchAction | GitPushAction | GitPushNewBranchAction;
export type GitRemoteKind = GitRemoteAction['kind'];
export const GIT_REMOTE_CONSENT = Object.freeze({ fetch: 'agent-git-fetch-once-v1', push: 'agent-git-push-once-v1', 'push-new-branch': 'agent-git-push-new-branch-once-v1' });
export interface GitRemoteApproval { readonly projectId: string; readonly expectedDocumentRevision: number; readonly readOperationId: string; readonly action: GitRemoteAction }
export interface GitRemoteAccount { readonly accountId: string; readonly login: string; readonly repositoryId: string; readonly repository: string }
export interface GitRemoteAccess {
  readonly permissionRevision: string;
  readonly enabled: boolean; readonly remainingMs: number; readonly consumed: boolean; readonly projectId: string | null; readonly grantId: string | null;
  readonly selection: { readonly action: GitRemoteAction; readonly account: GitRemoteAccount; readonly selectionSha256: string } | null;
}
export type GitRemotePermissionApi = PermissionApi<GitRemoteApproval, GitRemoteAccess>;
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const id = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max && /^[A-Za-z0-9_-]+$(?![\s\S])/.test(v);
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && /^[0-9a-f]+$(?![\s\S])/.test(v) && (n !== 32 || !/^0+$/.test(v));
const numeric = (v: unknown): v is string => typeof v === 'string' && /^[1-9][0-9]{0,19}$(?![\s\S])/.test(v) && BigInt(v) <= 18446744073709551615n;
const login = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$(?![\s\S])/.test(v);
function action(v: unknown): GitRemoteAction | null {
  // Each actual native action validator remains separate. A zero old OID or
  // absent upstream never changes an ordinary Push into create-only consent.
  if (isGitFetchAction(v) && id(v.connectionSessionId, 64)) return Object.freeze({ kind: v.kind, expectedRevision: v.expectedRevision,
    expectedReferenceRevision: v.expectedReferenceRevision, remote: v.remote, reference: v.reference,
    connectionSessionId: v.connectionSessionId, expectedConnectionRevision: v.expectedConnectionRevision });
  if (isGitPushAction(v) && id(v.connectionSessionId, 64)) return Object.freeze({ kind: v.kind, expectedRevision: v.expectedRevision,
    expectedReferenceRevision: v.expectedReferenceRevision, remote: v.remote, localRef: v.localRef, remoteRef: v.remoteRef,
    oldOid: v.oldOid, newOid: v.newOid, connectionSessionId: v.connectionSessionId, expectedConnectionRevision: v.expectedConnectionRevision });
  if (isGitPushNewBranchAction(v) && id(v.connectionSessionId, 64)) return Object.freeze({ kind: v.kind, expectedRevision: v.expectedRevision,
    expectedReferenceRevision: v.expectedReferenceRevision, remote: v.remote, localRef: v.localRef, remoteRef: v.remoteRef,
    oldOid: v.oldOid, newOid: v.newOid, connectionSessionId: v.connectionSessionId, expectedConnectionRevision: v.expectedConnectionRevision });
  return null;
}
function account(v: unknown): GitRemoteAccount | null {
  if (!keys(v, ['accountId', 'login', 'repositoryId', 'repository']) || !numeric(v.accountId) || !numeric(v.repositoryId) || !login(v.login)
    || typeof v.repository !== 'string') return null;
  const parts = v.repository.split('/'), owner = parts[0], repo = parts[1];
  return parts.length === 2 && login(owner) && typeof repo === 'string' && repo.length <= 100 && /^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$(?![\s\S])/.test(repo)
    ? Object.freeze({ accountId: v.accountId, login: v.login, repositoryId: v.repositoryId, repository: v.repository }) : null;
}
export function copyGitRemoteApproval(value: unknown): GitRemoteApproval | null {
  try {
    const v = copyBoundedComparisonData(value, 8192 - 192, 80);
    if (!keys(v, ['projectId', 'expectedDocumentRevision', 'readOperationId', 'action']) || !id(v.projectId, 64) || !id(v.readOperationId, 96)
      || typeof v.expectedDocumentRevision !== 'number' || !Number.isSafeInteger(v.expectedDocumentRevision) || v.expectedDocumentRevision < 1 || v.expectedDocumentRevision >= 0xffffffff) return null;
    const a = action(v.action); return a ? Object.freeze({ projectId: v.projectId, expectedDocumentRevision: v.expectedDocumentRevision, readOperationId: v.readOperationId, action: a }) : null;
  } catch { return null; }
}
export function parseGitRemoteAccess(value: unknown): GitRemoteAccess | null {
  try {
    const v = copyBoundedComparisonData(value, 8192, 100);
    if (!keys(v, ['enabled', 'remainingMs', 'consumed', 'projectId', 'grantId', 'selection', 'permissionRevision']) || !gitPermissionRevision(v.permissionRevision) || typeof v.enabled !== 'boolean' || typeof v.consumed !== 'boolean'
      || typeof v.remainingMs !== 'number' || !Number.isSafeInteger(v.remainingMs) || Object.is(v.remainingMs, -0) || v.remainingMs < 0 || v.remainingMs > 900000
      || v.enabled && (v.consumed || v.remainingMs === 0) || !v.enabled && v.remainingMs !== 0) return null;
    if (v.projectId === null || v.grantId === null || v.selection === null) return v.projectId === null && v.grantId === null && v.selection === null && !v.enabled && !v.consumed
      ? Object.freeze({ permissionRevision: v.permissionRevision, enabled: false, remainingMs: 0, consumed: false, projectId: null, grantId: null, selection: null }) : null;
    if (!hex(v.projectId, 32) || !hex(v.grantId, 32) || !keys(v.selection, ['action', 'account', 'selectionSha256']) || !hex(v.selection.selectionSha256, 64)) return null;
    const a = action(v.selection.action), who = account(v.selection.account); if (!a || !who) return null;
    return Object.freeze({ permissionRevision: v.permissionRevision, enabled: v.enabled, remainingMs: v.remainingMs, consumed: v.consumed, projectId: v.projectId, grantId: v.grantId,
      selection: Object.freeze({ action: a, account: who, selectionSha256: v.selection.selectionSha256 }) });
  } catch { return null; }
}
export function sameGitRemoteAction(a: GitRemoteAction, b: GitRemoteAction): boolean {
  // Only canonical bounded copies produced above enter this comparison.
  const left = action(a), right = action(b); return left !== null && right !== null && JSON.stringify(left) === JSON.stringify(right);
}
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
export function createGitRemotePermissionApi(mode: string, invoke: Invoke): GitRemotePermissionApi | null {
  if (mode !== 'native') return null;
  const failure = () => ({ code: 'agent_git_remote_unconfirmed', message: 'Permission was not confirmed. Check or stop its original Desktop request; never repeat an unconfirmed remote send.', retryable: false });
  const call = async (command: 'agent_git_remote_access' | 'allow_agent_git_remote' | 'revoke_agent_git_remote', body: unknown): Promise<GitRemoteAccess> => {
    try {
      const raw = new TextEncoder().encode(JSON.stringify(body)); if (raw.length + 96 > (command === 'allow_agent_git_remote' ? 8192 : 1024)) throw failure();
      const result = parseGitRemoteAccess(await invoke<unknown>(command, raw)); if (!result) throw failure(); return result;
    } catch { throw failure(); }
  };
  return Object.freeze({ status: () => call('agent_git_remote_access', {}), revoke: () => call('revoke_agent_git_remote', {}), allow: async (input: GitRemoteApproval, expectedPermissionRevision: string) => {
    const safe = copyGitRemoteApproval(input); if (!safe || !gitPermissionRevision(expectedPermissionRevision)) throw failure();
    const result = await call('allow_agent_git_remote', { ...safe, expectedPermissionRevision, consentVersion: GIT_REMOTE_CONSENT[safe.action.kind] });
    if (!result.selection || !sameGitRemoteAction(safe.action, result.selection.action)) throw failure(); return result;
  } });
}
export interface GitRemotePermissionContext extends PermissionContext<GitRemoteApproval, GitRemoteAccess> {
  readonly witness: readonly unknown[]; readonly reason: string | null; readonly account: GitRemoteAccount | null;
}
export interface GitRemotePermissionSource {
  readonly api: GitRemotePermissionApi | null; readonly session: object | null; readonly projectId: string | null; readonly epoch: number;
  readonly repository: GitRepositoryController | null; readonly reader: GitReadController | null; readonly local: GitLocalController | null;
  readonly connection: GitHubConnectionViewState | null; readonly blocked: string | null;
}
export function gitRemotePermissionContext(kind: GitRemoteKind, source: GitRemotePermissionSource): GitRemotePermissionContext {
  const { api, session, projectId, repository, reader, local, connection } = source;
  const r = repository?.getSnapshot() ?? null, read = reader?.getSnapshot() ?? null, writes = local?.getSnapshot() ?? null;
  const witness = Object.freeze([kind, api, session, projectId, source.epoch, repository, reader, local, r, read, writes, connection, connection?.context, connection?.status, source.blocked]);
  let who: GitRemoteAccount | null = null;
  const finish = (reason: string | null, a: GitRemoteAction | null = null): GitRemotePermissionContext => {
    const project = !reason && a && read?.status && read.original ? copyGitRemoteApproval({ projectId, expectedDocumentRevision: read.status.documentRevision, readOperationId: read.original.operationId, action: a }) : null;
    const why = reason ?? (project ? null : 'Review this exact remote selection first.'); return { api, project, blocked: why !== null, reason: why, witness, account: who };
  };
  if (!api || !session || !projectId || !r || !reader || !local) return finish('Select the original native project and its GitHub connection.');
  const owner = local.ownerReason() ?? reader.ownerReason() ?? source.blocked;
  if (owner) return finish(owner);
  if (!Number.isSafeInteger(source.epoch) || source.epoch < 0) return finish('The original service context is unavailable.');
  const current = gitFetchLocalSource(read, r, projectId), original = read?.original;
  if (!current || !read?.status?.available || !original || original.action.kind !== 'observe' || original.phase !== 'settled' || original.outcome !== 'ok' || original.reason !== null
    || original.context.projectId !== projectId || original.context.revision !== `document-${read.status.documentRevision}` || read.status.operation?.operationId !== original.operationId
    || !sameGitLocalData(original.result, current) || !sameGitLocalData(current.observation, r.observation)) return finish('Refresh this project’s changes first. Pending, historical or local-branch-list results cannot grant a remote action.');
  if (current.observation.restrictions.length) return finish(gitLocalIssueHelp(current.observation.restrictions[0]!));
  const a = kind === 'fetch' ? gitFetchAccount(connection, projectId) : gitPushAccount(connection, projectId);
  if (!a) return finish(kind === 'fetch' ? 'Connect the intended GitHub account and repository first.' : 'Connect the intended account/repository with reported Push access.');
  who = Object.freeze({ accountId: a.accountId, login: a.login, repositoryId: a.repositoryId, repository: a.repository });
  const issue = kind === 'push-new-branch' ? local.preparePushNewBranchReason() : kind === 'push' ? local.preparePushReason() : local.prepareFetchReason(); if (issue) return finish(gitLocalIssueHelp(issue));
  if (kind === 'push-new-branch') return finish(null, gitPushNewBranchActionFor(current, a));
  if (kind === 'push') return finish(null, gitPushActionFor(current, a));
  if (!gitFetchDraftReady(r.fetchDraft, current.observation.remotes)) return finish('Choose one observed remote and branch in Fetch above.');
  return finish(null, { kind: 'fetch', expectedRevision: current.observation.revision, expectedReferenceRevision: current.referenceRevision,
    remote: r.fetchDraft.remote, reference: `refs/heads/${r.fetchDraft.branch}`, connectionSessionId: a.sessionId, expectedConnectionRevision: a.revision });
}
/** The same finite Permission owns every actual Allow/Status/Revoke promise. */
export class GitRemotePermission extends Permission<GitRemoteApproval, GitRemoteAccess> {
  private readonly choice: { kind: GitRemoteKind };
  private readonly source: (kind: GitRemoteKind) => GitRemotePermissionContext;
  private witnessed: readonly unknown[] | null = null;
  constructor(current: (kind: GitRemoteKind) => GitRemotePermissionContext) {
    const choice: { kind: GitRemoteKind } = { kind: 'fetch' }; super(copyGitRemoteApproval, () => current(choice.kind)); this.choice = choice; this.source = current;
  }
  getKind(): GitRemoteKind { return this.choice.kind; }
  getContext(): GitRemotePermissionContext { return this.source(this.choice.kind); }
  override syncContext(): void {
    const current = this.getContext();
    if (!this.witnessed || current.witness.length !== this.witnessed.length || current.witness.some((v, i) => v !== this.witnessed![i])) {
      this.witnessed = current.witness; super.bind(current.api, null); // Withdraw stale consent, never erase an issued grant.
    }
    super.syncContext(); // Re-sample after synchronous listeners/ABA/revoke.
  }
  chooseKind(kind: string): void { if ((kind !== 'fetch' && kind !== 'push' && kind !== 'push-new-branch') || kind === this.choice.kind) return; this.choice.kind = kind; this.acknowledge(false); this.syncContext(); }
}
