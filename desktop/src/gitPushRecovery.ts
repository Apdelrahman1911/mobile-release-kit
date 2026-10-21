import type { GitPushNewBranchReview } from './gitPushNewBranchProtocol.ts';
// Later GET-only comparison through the EXISTING Activity owner. This object
// owns no invocation, clock, grant, native proof or journal settlement.
import type { GitLocalController, GitLocalBinding } from './gitLocalController.ts';
import type { GitLocalOperation } from './gitLocalProtocol.ts';
import type { GitPushReview } from './gitPushProtocol.ts';
import type { GitPushAccount } from './gitPushSelection.ts';
import type { GitHubActivityController } from './githubActivityController.ts';

export interface GitPushReadbackSource {
  readonly operation: GitLocalOperation;
  readonly review: GitPushReview | GitPushNewBranchReview;
  readonly account: GitPushAccount;
  readonly binding: GitLocalBinding;
}
export interface GitPushReadback {
  readonly source: GitPushReadbackSource;
  current(): boolean;
  result(): { readonly comparison: 'matches-intended' | 'still-old' | 'other'; readonly tip: string; readonly observedAt: string } | null;
}
export function startGitPushReadback(local: GitLocalController, activity: GitHubActivityController): GitPushReadback | null {
  const source = local.pushReadbackSource();
  if (!source) return null;
  const branch = source.review.upstreamRef.slice('refs/heads/'.length);
  const current = () => local.pushReadbackSource() === source;
  const original = activity.readPushRecovery(branch, current);
  if (!original) return null;
  return Object.freeze({ source, current, result: () => {
    if (!current()) return null;
    const value = original.result();
    if (!value || value.selection.kind !== 'overview' || value.selection.branch !== branch || value.data.kind !== 'overview' ||
        value.target.repository !== source.review.repository || value.target.accountId !== source.review.accountId ||
        value.target.repositoryId !== source.review.repositoryId || !value.data.branchHead || !current()) return null;
    const tip = value.data.branchHead;
    return Object.freeze({ comparison: tip === source.review.head ? 'matches-intended' as const :
      tip === source.review.expectedRemoteOid ? 'still-old' as const : 'other' as const, tip, observedAt: value.observedAt });
  } });
}
