// The existing connected account and local read supply comparison DATA, never
// a token, a fresh remote tip, a native review or a send permission.
import { parseGitHubConnectionStatus } from './githubConnectionProtocol.ts';
import type { GitHubConnectionStatus, GitHubConnectionViewState } from './githubConnectionTypes.ts';
import type { GitReadObservation } from './gitReadProtocol.ts';
import type { GitReadView } from './gitReadController.ts';
import type { GitRepositoryView } from './gitRepositoryController.ts';
import { gitPushTracking, isGitPushAction } from './gitPushProtocol.ts';
import type { GitPushAction, GitPushReview } from './gitPushProtocol.ts';

export type GitConnectedAdmission = 'git-read' | 'git-status' | 'git-fetch' | 'git-push';
// Only the Connection portion of App's existing saved-owner gate. Callers
// still check history, all other original peers, and native admission. This
// grants no credential access or mutation: Fetch/Push separately capture their
// exact selected account and native action; ordinary saved/local writes have
// no scope and continue to require disconnection.
export function gitConnectionBlocksSavedWork(view: GitHubConnectionViewState, projectId: string,
  scope?: GitConnectedAdmission | 'history-read'): boolean {
  if (view.blocked || view.uncertain || view.busy || view.retirementPending) return true;
  if (scope === 'history-read') return false; // Existing history semantics only.
  if (!(view.status ?? view.retained)?.session) return false;
  if (!scope || view.mode !== 'native' || view.observing || view.error || !view.status ||
      !view.context || view.context.projectId !== projectId) return true;
  const status = parseGitHubConnectionStatus(view.status), session = status?.session;
  return !status || !session || session.state !== 'connected' || session.projectId !== projectId ||
    session.targetRepository !== view.context.repository || status.revision === 0 || status.revision === 0xffffffff ||
    status.operation !== null && status.operation.phase !== 'settled' ||
    status.account.state !== 'observed' || status.account.value === null ||
    status.repository.state !== 'observed' || status.repository.value === null ||
    status.repository.value.fullName.toLowerCase() !== view.context.repository.toLowerCase();
}

export interface GitPushAccount {
  readonly view: GitHubConnectionViewState; readonly status: GitHubConnectionStatus;
  readonly context: NonNullable<GitHubConnectionViewState['context']>;
  readonly sessionId: string; readonly revision: number; readonly accountId: string; readonly login: string;
  readonly repositoryId: string; readonly repository: string; readonly visibility: 'public' | 'private' | 'internal';
}
export function gitPushAccount(view: GitHubConnectionViewState | null | undefined, projectId: string): GitPushAccount | null {
  if (!view || view.mode !== 'native' || view.blocked || view.uncertain || view.retirementPending || view.busy || view.observing || view.error) return null;
  const c = view.context, s = view.status, parsed = s ? parseGitHubConnectionStatus(s) : null;
  if (!c || c.projectId !== projectId || !s || !parsed) return null;
  const session = parsed.session, a = parsed.account.value, r = parsed.repository.value;
  if (!session || session.state !== 'connected' || session.projectId !== projectId || session.targetRepository !== c.repository ||
      parsed.revision === 0 || parsed.revision === 0xffffffff || parsed.account.state !== 'observed' || !a || parsed.repository.state !== 'observed' || !r ||
      r.fullName.toLowerCase() !== c.repository.toLowerCase() || r.archived || r.permissions.pull !== 'reported-allowed' || r.permissions.push !== 'reported-allowed') return null;
  return Object.freeze({ view, context: c, status: s, sessionId: session.id, revision: parsed.revision, accountId: a.id, login: a.login,
    repositoryId: r.id, repository: r.fullName, visibility: r.visibility });
}
export function sameGitPushAccount(a: GitPushAccount, view: GitHubConnectionViewState | null | undefined, projectId: string): boolean {
  if (!view || view !== a.view || view.context !== a.context || view.status !== a.status) return false;
  const b = gitPushAccount(view, projectId);
  return !!b && a.sessionId === b.sessionId && a.revision === b.revision && a.accountId === b.accountId && a.login === b.login &&
    a.repositoryId === b.repositoryId && a.repository === b.repository;
}
export function pushReviewMatchesAccount(review: GitPushReview, a: GitPushAccount): boolean {
  return review.accountId === a.accountId && review.login === a.login && review.repositoryId === a.repositoryId && review.repository === a.repository;
}
export function gitPushLocalSource(read: GitReadView | null | undefined, files: GitRepositoryView, projectId: string): GitReadObservation | null {
  const o = read?.observation, f = files.observation;
  return read && !read.stale && !read.busy && !read.uncertain && !read.checking && read.observationProject === projectId &&
    files.projectId === projectId && files.active && !files.stale && !files.blocked && !files.busy && !files.checkingStatus &&
    o?.basis === 'local-refs-no-fetch' && f && o.observation.revision === f.revision && o.observation.head === f.head && o.observation.branch === f.branch ? o : null;
}
export function gitPushActionFor(local: GitReadObservation, account: GitPushAccount): GitPushAction | null {
  const o = local.observation, t = local.tracking;
  if (o.unborn || o.detached || !o.head || !o.branch || t.state !== 'complete' || t.behind !== 0 ||
      t.ahead === null || t.ahead < 1 || t.ahead > 64 || !t.remote || !t.mergeRef || !t.head ||
      t.localRef !== gitPushTracking(t.remote, t.mergeRef) || !o.remotes.includes(t.remote)) return null;
  const action = { kind: 'push' as const, expectedRevision: o.revision, expectedReferenceRevision: local.referenceRevision, remote: t.remote,
    localRef: o.branch, remoteRef: t.mergeRef, oldOid: t.head, newOid: o.head, connectionSessionId: account.sessionId, expectedConnectionRevision: account.revision };
  return isGitPushAction(action) ? Object.freeze(action) : null;
}
