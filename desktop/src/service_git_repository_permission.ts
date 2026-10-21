// Closed permission DATA for the existing GitLocal owner. This does not
// inspect a repository, mint a review, start Git or establish native finality.
import { isGitUpstreamAction, sameUpstreamAction, type GitUpstreamAction } from './gitUpstreamProtocol.ts';
import { Permission, type PermissionApi, type PermissionContext } from './service_git_permission.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { isGitInitAction, type GitInitAction } from './gitInitProtocol.ts';
import { isGitBranchAction, type GitBranchAction } from './gitBranchesProtocol.ts';
import { isGitSwitchAction, type GitSwitchAction } from './gitSwitchProtocol.ts';
import { isGitRenameAction, type GitRenameAction } from './gitRenameProtocol.ts';
import { isGitFastForwardAction, type GitFastForwardAction } from './gitFastForwardProtocol.ts';

export const GIT_REPOSITORY_CONSENT = 'agent-local-git-repository-once-v1';
export type GitRepositoryPermissionAction = GitUpstreamAction | GitInitAction | GitBranchAction | GitSwitchAction | GitRenameAction | GitFastForwardAction;
export type GitRepositoryPermissionKind = GitRepositoryPermissionAction['kind'];
export interface GitRepositoryApproval {
  readonly projectId: string; readonly expectedDocumentRevision: number; readonly readOperationId: string | null;
  readonly action: GitRepositoryPermissionAction;
}
export interface GitRepositoryAccess {
  readonly enabled: boolean; readonly remainingMs: number; readonly consumed: boolean;
  readonly projectId: string | null; readonly grantId: string | null;
  readonly selection: { readonly action: GitRepositoryPermissionAction; readonly selectionSha256: string } | null;
}
export type GitRepositoryPermissionApi = PermissionApi<GitRepositoryApproval, GitRepositoryAccess>;
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const id = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max && /^[A-Za-z0-9_-]+$(?![\s\S])/.test(v);
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && /^[0-9a-f]+$(?![\s\S])/.test(v)
  && (n !== 32 || !/^0+$/.test(v));

// Only call after the bounded descriptor-copy below: no getters are run.
function action(value: unknown): GitRepositoryPermissionAction | null {
  if (isGitUpstreamAction(value)) return Object.freeze({ ...value, identity: value.identity && Object.freeze({ ...value.identity }) });
  if (isGitInitAction(value)) return Object.freeze({ kind: 'initialize' });
  if (isGitBranchAction(value) || isGitSwitchAction(value) || isGitRenameAction(value)) return Object.freeze({
    kind: value.kind, expectedRevision: value.expectedRevision, expectedReferenceRevision: value.expectedReferenceRevision, name: value.name,
  });
  if (isGitFastForwardAction(value)) return Object.freeze({ kind: 'fast-forward', expectedRevision: value.expectedRevision,
    expectedReferenceRevision: value.expectedReferenceRevision, targetRef: value.targetRef, targetOid: value.targetOid });
  return null;
}
export function copyGitRepositoryApproval(value: unknown): GitRepositoryApproval | null {
  try {
    const v = copyBoundedComparisonData(value, 8192 - 192, 64);
    if (!keys(v, ['projectId', 'expectedDocumentRevision', 'readOperationId', 'action']) || !id(v.projectId, 64)
      || typeof v.expectedDocumentRevision !== 'number' || !Number.isSafeInteger(v.expectedDocumentRevision)
      || v.expectedDocumentRevision < 1 || v.expectedDocumentRevision >= 0xffffffff) return null;
    const a = action(v.action);
    if (!a || (a.kind === 'initialize' ? v.readOperationId !== null : !id(v.readOperationId, 96))) return null;
    return Object.freeze({ projectId: v.projectId, expectedDocumentRevision: v.expectedDocumentRevision,
      readOperationId: v.readOperationId as string | null, action: a });
  } catch { return null; }
}
export function parseGitRepositoryAccess(value: unknown): GitRepositoryAccess | null {
  try {
    const v = copyBoundedComparisonData(value, 8192, 80);
    if (!keys(v, ['enabled', 'remainingMs', 'consumed', 'projectId', 'grantId', 'selection']) || typeof v.enabled !== 'boolean'
      || typeof v.consumed !== 'boolean' || typeof v.remainingMs !== 'number' || !Number.isSafeInteger(v.remainingMs)
      || v.remainingMs < 0 || v.remainingMs > 900000 || v.enabled && (v.consumed || v.remainingMs === 0)
      || !v.enabled && v.remainingMs !== 0) return null;
    if (v.projectId === null || v.grantId === null || v.selection === null) return v.projectId === null && v.grantId === null && v.selection === null && !v.enabled && !v.consumed
      ? Object.freeze({ enabled: false, remainingMs: 0, consumed: false, projectId: null, grantId: null, selection: null }) : null;
    if (!hex(v.projectId, 32) || !hex(v.grantId, 32) || !keys(v.selection, ['action', 'selectionSha256']) || !hex(v.selection.selectionSha256, 64)) return null;
    const a = action(v.selection.action); if (!a) return null;
    return Object.freeze({ enabled: v.enabled, remainingMs: v.remainingMs, consumed: v.consumed, projectId: v.projectId, grantId: v.grantId,
      selection: Object.freeze({ action: a, selectionSha256: v.selection.selectionSha256 }) });
  } catch { return null; }
}
export function sameGitRepositoryPermissionAction(a: GitRepositoryPermissionAction, b: GitRepositoryPermissionAction): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'initialize') return true;
  if (b.kind === 'initialize' || a.expectedRevision !== b.expectedRevision || a.expectedReferenceRevision !== b.expectedReferenceRevision) return false;
  if (a.kind === 'set-upstream' || b.kind === 'set-upstream') return a.kind === 'set-upstream' && b.kind === 'set-upstream' && sameUpstreamAction(a, b);
  return a.kind === 'fast-forward' ? b.kind === 'fast-forward' && a.targetRef === b.targetRef && a.targetOid === b.targetOid :
    b.kind !== 'fast-forward' && a.name === b.name;
}
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
export function createGitRepositoryPermissionApi(mode: string, invoke: Invoke): GitRepositoryPermissionApi | null {
  if (mode !== 'native') return null;
  const failure = () => ({ code: 'agent_git_repository_unconfirmed', message: 'Permission was not confirmed. Check or stop it in the original Desktop; do not repeat the Git change.', retryable: false });
  const call = async (command: 'agent_git_repository_access' | 'allow_agent_git_repository' | 'revoke_agent_git_repository', body: unknown): Promise<GitRepositoryAccess> => {
    try {
      const raw = new TextEncoder().encode(JSON.stringify(body));
      if (raw.length + 96 > (command === 'allow_agent_git_repository' ? 8192 : 1024)) throw failure();
      const parsed = parseGitRepositoryAccess(await invoke<unknown>(command, raw)); if (!parsed) throw failure(); return parsed;
    } catch { throw failure(); }
  };
  return Object.freeze({ status: () => call('agent_git_repository_access', {}), revoke: () => call('revoke_agent_git_repository', {}),
    allow: async (input: GitRepositoryApproval) => {
      const safe = copyGitRepositoryApproval(input); if (!safe) throw failure();
      const result = await call('allow_agent_git_repository', { ...safe, consentVersion: GIT_REPOSITORY_CONSENT });
      if (!result.selection || !sameGitRepositoryPermissionAction(safe.action, result.selection.action)) throw failure();
      return result; // The native digest stays paired with its action; it is not renderer authority.
    } });
}

export interface GitRepositoryPermissionContext extends PermissionContext<GitRepositoryApproval, GitRepositoryAccess> {
  /** Actual retained controller/source object identities, never serialized. */
  readonly witness: readonly unknown[];
  readonly reason: string | null;
}
const KINDS: readonly GitRepositoryPermissionKind[] = ['initialize', 'branch-create', 'branch-switch', 'branch-rename', 'fast-forward', 'set-upstream'];
/** One small choice/projection child of the EXISTING permission request owner.
 * All Allow/Status/Revoke promises and lost-ACK rules stay in Permission. */
export class GitRepositoryPermission extends Permission<GitRepositoryApproval, GitRepositoryAccess> {
  private readonly choice: { kind: GitRepositoryPermissionKind };
  private readonly source: (kind: GitRepositoryPermissionKind) => GitRepositoryPermissionContext;
  private witnessed: readonly unknown[] | null = null;
  constructor(current: (kind: GitRepositoryPermissionKind) => GitRepositoryPermissionContext) {
    const choice: { kind: GitRepositoryPermissionKind } = { kind: 'initialize' };
    super(copyGitRepositoryApproval, () => current(choice.kind)); this.choice = choice; this.source = current;
  }
  getKind(): GitRepositoryPermissionKind { return this.choice.kind; }
  getContext(): GitRepositoryPermissionContext { return this.source(this.choice.kind); }
  override syncContext(): void {
    const current = this.getContext();
    if (!this.witnessed || current.witness.length !== this.witnessed.length || current.witness.some((v, i) => v !== this.witnessed![i])) {
      this.witnessed = current.witness;
      // Equal action bytes are not an exemption for a new source/draft/API/ABA.
      // This only withdraws UI consent, never revokes or forgets an issued grant.
      super.bind(current.api, null);
    }
    // Re-sample after the synchronous withdrawal notification. A listener may
    // have changed projects, selected a different action or requested Revoke.
    super.syncContext();
  }
  chooseKind(kind: string): void {
    if (!KINDS.includes(kind as GitRepositoryPermissionKind) || kind === this.choice.kind) return;
    this.choice.kind = kind as GitRepositoryPermissionKind; this.acknowledge(false); this.syncContext();
  }
}
