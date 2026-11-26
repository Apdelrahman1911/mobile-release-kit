// Pure local draft and comparison helpers. These values cannot lend a token,
// authorize a provider request, make a remote current or settle native work.
import { parseGitHubConnectionStatus } from './githubConnectionProtocol.ts';
import type { GitHubConnectionStatus, GitHubConnectionViewState } from './githubConnectionTypes.ts';
import type { GitReadObservation } from './gitReadProtocol.ts';
import type { GitReadView } from './gitReadController.ts';
import type { GitRepositoryView } from './gitRepositoryController.ts';
import { gitFetchReference, gitFetchRemote } from './gitFetchProtocol.ts';
import type { GitFetchReview } from './gitFetchProtocol.ts';

export interface GitFetchDraft { readonly remote: string; readonly branch: string }
export const emptyGitFetchDraft = (): GitFetchDraft => Object.freeze({ remote: '', branch: '' });
export function gitFetchDraftFits(field: keyof GitFetchDraft, v: unknown): v is string {
  const max = field === 'remote' ? 64 : field === 'branch' ? 244 : 0;
  return max > 0 && typeof v === 'string' && v.length <= max && new TextEncoder().encode(v).length <= max && !/[\x00-\x1f\x7f\p{Cs}]/u.test(v);
}
export function gitFetchDraftReady(d: GitFetchDraft, remotes: readonly string[]): boolean {
  return gitFetchRemote(d.remote) && remotes.includes(d.remote) && gitFetchReference(`refs/heads/${d.branch}`);
}
export interface GitFetchAccount {
  readonly view: GitHubConnectionViewState; readonly status: GitHubConnectionStatus;
  readonly context: NonNullable<GitHubConnectionViewState['context']>;
  readonly sessionId: string; readonly revision: number; readonly accountId: string; readonly login: string;
  readonly repositoryId: string; readonly repository: string; readonly visibility: 'public' | 'private' | 'internal';
}
export function gitFetchAccount(view: GitHubConnectionViewState | null | undefined, projectId: string): GitFetchAccount | null {
  if (!view || view.mode !== 'native' || view.blocked || view.uncertain || view.retirementPending || view.busy || view.observing || view.error) return null;
  const c = view.context, s = view.status, parsed = s ? parseGitHubConnectionStatus(s) : null;
  if (!c || c.projectId !== projectId || !s || !parsed) return null;
  const session = parsed.session, a = parsed.account.value, r = parsed.repository.value;
  if (!session || session.state !== 'connected' || session.projectId !== projectId || session.targetRepository !== c.repository ||
      parsed.revision === 0 || parsed.revision === 0xffffffff || parsed.account.state !== 'observed' || !a || parsed.repository.state !== 'observed' || !r ||
      r.fullName.toLowerCase() !== c.repository.toLowerCase()) return null;
  return Object.freeze({ view, context: c, status: s, sessionId: session.id, revision: parsed.revision, accountId: a.id, login: a.login,
    repositoryId: r.id, repository: r.fullName, visibility: r.visibility });
}
export function sameGitFetchAccount(a: GitFetchAccount, view: GitHubConnectionViewState | null | undefined, projectId: string): boolean {
  if (!view || view !== a.view || view.context !== a.context || view.status !== a.status) return false;
  const b = gitFetchAccount(view, projectId);
  return !!b && a.sessionId === b.sessionId && a.revision === b.revision && a.accountId === b.accountId && a.login === b.login &&
    a.repositoryId === b.repositoryId && a.repository === b.repository;
}
export function fetchReviewMatchesAccount(review: GitFetchReview, account: GitFetchAccount): boolean {
  return review.accountId === account.accountId && review.login === account.login && review.repositoryId === account.repositoryId && review.repository === account.repository;
}
export function gitFetchLocalSource(read: GitReadView | null | undefined, files: GitRepositoryView, projectId: string): GitReadObservation | null {
  const o = read?.observation, f = files.observation;
  return read && !read.stale && !read.busy && !read.uncertain && !read.checking && read.observationProject === projectId &&
    files.projectId === projectId && files.active && !files.stale && !files.blocked && !files.busy && !files.checkingStatus &&
    o?.basis === 'local-refs-no-fetch' && f && o.observation.revision === f.revision && o.observation.head === f.head &&
    o.observation.branch === f.branch ? o : null;
}
