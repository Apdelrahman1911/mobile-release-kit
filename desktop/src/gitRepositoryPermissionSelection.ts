// Current-view selection only. The native shared grant and its subsequent
// original Prepare still check the repository; this is not a Git inspection.
import type { GitRepositoryController } from './gitRepositoryController.ts';
import type { GitReadController } from './gitReadController.ts';
import type { GitLocalController } from './gitLocalController.ts';
import { gitLocalIssueHelp, sameGitLocalData } from './gitLocalProtocol.ts';
import { gitBranchName } from './gitBranchesProtocol.ts';
import { sameRenameParent } from './gitRenameProtocol.ts';
import { copyGitRepositoryApproval } from './service_git_repository_permission.ts';
import type { GitRepositoryPermissionAction, GitRepositoryPermissionApi, GitRepositoryPermissionContext, GitRepositoryPermissionKind } from './service_git_repository_permission.ts';

export interface GitRepositoryPermissionSource {
  readonly api: GitRepositoryPermissionApi | null; readonly session: object | null; readonly projectId: string | null; readonly epoch: number;
  readonly repository: GitRepositoryController | null; readonly reader: GitReadController | null; readonly local: GitLocalController | null;
  readonly blocked: string | null;
}
export const GIT_REPOSITORY_PERMISSION_LABELS: Readonly<Record<GitRepositoryPermissionKind, string>> = Object.freeze({
  initialize: 'Start local Git tracking', 'branch-create': 'Create a local branch', 'branch-switch': 'Switch local branch',
  'branch-rename': 'Rename the current local branch', 'fast-forward': 'Update to the cached upstream commit',
});
export function gitRepositoryPermissionEffect(a: GitRepositoryPermissionAction): string {
  switch (a.kind) {
    case 'initialize': return 'Create an empty local repository on main, only if the native review confirms this is safe. Project files stay in place; no files are staged or committed.';
    case 'branch-create': return `Create “${a.name}” at the reviewed current commit. Do not switch branches or change working files.`;
    case 'branch-switch': return `Switch this clean checkout to local branch “${a.name}”. The existing bounded review must show the tracked-file content changes first.`;
    case 'branch-rename': return `Rename the current local branch to “${a.name}”. Keep its commit, staged work and working files; do not rename a GitHub branch.`;
    case 'fast-forward': return `Advance this clean branch to the already-cached ${a.targetRef} commit ${a.targetOid.slice(0, 12)}. No fetch, merge, rebase or force update.`;
  }
}
export function gitRepositoryPermissionContext(kind: GitRepositoryPermissionKind, source: GitRepositoryPermissionSource): GitRepositoryPermissionContext {
  const { api, session, projectId, repository, reader, local } = source;
  const r = repository?.getSnapshot() ?? null, read = reader?.getSnapshot() ?? null, writes = local?.getSnapshot() ?? null;
  const witness = [kind, api, session, projectId, source.epoch, repository, reader, local, r, read, writes, source.blocked];
  const finish = (reason: string | null, a: GitRepositoryPermissionAction | null = null, revision: number | null = null, readId: string | null = null): GitRepositoryPermissionContext => {
    const project = reason === null && a && revision !== null ? copyGitRepositoryApproval({ projectId, expectedDocumentRevision: revision, readOperationId: readId, action: a }) : null;
    const actualReason = reason ?? (project ? null : 'The selected action is incomplete. Review its fields above first.');
    return { api, project, blocked: actualReason !== null, reason: actualReason, witness: Object.freeze([...witness, actualReason]) };
  };
  if (!api || !session) return finish('Connect the native Desktop service to manage this permission. No permission is granted in preview mode.');
  if (!projectId || !r || r.projectId !== projectId || !r.active) return finish('Select the original project before allowing a local Git action.');
  const owner = local?.ownerReason() ?? reader?.ownerReason() ?? source.blocked;
  if (owner) return finish(owner);
  if (!Number.isSafeInteger(source.epoch) || source.epoch < 0 || !local || !reader) return finish('Current local Git access is unavailable. Check it above first.');
  if (r.busy || r.checkingStatus || writes?.pending || read?.busy || read?.checking) return finish('Wait for the original Git request to finish, or use its Stop control.');
  if (r.blocked) return finish(gitLocalIssueHelp(r.blocked));
  if (kind === 'initialize') {
    // No Observe is required or fabricated for a folder without a repository.
    // The same native GitLocal status/context check is still required.
    const issue = local.prepareInitializeReason();
    return issue ? finish(gitLocalIssueHelp(issue)) : finish(null, { kind: 'initialize' }, writes?.status?.documentRevision ?? null);
  }
  if (!r.observation || r.stale) return finish('Refresh changes above for this project before allowing a branch action.');
  const o = r.observation, operation = read?.original;
  if (reader.readReason(projectId) !== null || !read || read.stale || read.uncertain || !read.status?.available || !operation ||
    operation.phase !== 'settled' || operation.outcome !== 'ok' || operation.reason !== null || operation.context.projectId !== projectId ||
    operation.context.revision !== `document-${read.status.documentRevision}` || read.status.operation?.operationId !== operation.operationId) {
    return finish('Use a current completed changes or local-branches read. A previous result or a pending request cannot authorize this permission.');
  }
  if (o.restrictions.length) return finish(gitLocalIssueHelp(o.restrictions[0]!));
  if (o.changes.some(c => c.conflict)) return finish(gitLocalIssueHelp('conflicts'));
  if (!o.head || o.unborn) return finish('Make the first local commit before using a branch action.');

  let references: string;
  if (operation.action.kind === 'observe') {
    const observed = read.observation;
    if (!observed || read.observationProject !== projectId || observed.basis !== 'local-refs-no-fetch' ||
      !sameGitLocalData(operation.result, observed) || !sameGitLocalData(observed.observation, o)) {
      return finish('Refresh changes again; the original read no longer matches this project’s displayed changes.');
    }
    references = observed.referenceRevision;
  } else if (operation.action.kind === 'branches' && kind !== 'fast-forward') {
    const b = read.branches;
    if (!b || !read.branchesCurrent || read.branchesProject !== projectId || b.revision !== o.revision || b.head !== o.head || b.branch !== o.branch ||
      operation.action.expectedRevision !== o.revision || !sameGitLocalData(operation.result, b)) {
      return finish('Read local branches again; the last list no longer matches the current changes.');
    }
    references = b.referenceRevision;
  } else return finish(kind === 'fast-forward' ? 'Refresh changes to read the cached upstream again. A branch list is not an upstream check.' :
    'Refresh changes or read local branches above first. History and diff results cannot authorize a branch action.');

  const base = { expectedRevision: o.revision, expectedReferenceRevision: references };
  if (kind === 'fast-forward') {
    const t = read.observation!.tracking;
    if (!o.branch || o.detached || o.changes.length || t.state !== 'complete' || t.ahead !== 0 || t.behind === null || t.behind < 1 || t.behind > 10000 || !t.localRef || !t.head || t.head === o.head) {
      return finish('This update needs a clean branch that is strictly behind its already-cached upstream. It does not fetch or resolve diverged or incomplete history.');
    }
    return finish(null, { kind, ...base, targetRef: t.localRef, targetOid: t.head }, read.status.documentRevision, operation.operationId);
  }
  const name = kind === 'branch-create' ? r.branchDraft.name : kind === 'branch-switch' ? r.switchDraft.name : r.renameDraft.name;
  if (!gitBranchName(name)) return finish(kind === 'branch-switch' ? 'Choose the target in “Switch to an existing local branch” above.' :
    kind === 'branch-rename' ? 'Enter the new name in “Rename the current local branch” above.' : 'Enter the name in “Create a new local branch” above.');
  const target = `refs/heads/${name}`;
  if (target === o.branch) return finish('Choose a different local branch name; this action must not target the current name.');
  if (kind === 'branch-switch' && (!o.branch || o.detached || o.changes.length)) return finish('A supported branch switch needs a clean, attached checkout. Keep your changes and use your Git client for other layouts.');
  if (kind === 'branch-rename' && !sameRenameParent(o.branch, target)) return finish('Use a different name in the current branch’s local folder, not a case-only rename.');
  if (operation.action.kind === 'branches') {
    const branches = read.branches!.branches;
    if (kind === 'branch-switch' && !branches.some(b => b.ref === target)) return finish('The selected target is not in this current local-branch list. Choose an existing branch above.');
    if (kind !== 'branch-switch' && branches.some(b => b.ref === target)) return finish('That branch already exists. Choose an unused local name above.');
  }
  return finish(null, { kind, ...base, name }, read.status.documentRevision, operation.operationId);
}
