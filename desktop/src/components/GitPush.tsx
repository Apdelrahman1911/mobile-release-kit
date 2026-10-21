import type { GitPushNewBranchMutation } from '../gitPushNewBranchProtocol.ts';
import { useState, useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import type { GitHubConnectionViewState } from '../githubConnectionTypes.ts';
import type { GitHubActivityController } from '../githubActivityController.ts';
import { startGitPushReadback } from '../gitPushRecovery.ts';
import type { GitPushReadback } from '../gitPushRecovery.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import { GIT_PUSH_EFFECT_LABELS } from '../gitPushProtocol.ts';
import type { GitPushMutationResult } from '../gitPushProtocol.ts';
import { gitPushAccount } from '../gitPushSelection.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

// Rendering does not prepare, send, stop or release anything. The existing
// GitLocal controller retains all original promises across panel navigation.
export function GitPush({ controller, repository, connection, activity, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController; connection: GitHubConnectionViewState;
  activity: GitHubActivityController; originalProjectName?: string;
}) {
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const activityState = useSyncExternalStore(activity.subscribe, activity.getSnapshot, activity.getSnapshot);
  const [readback, setReadback] = useState<GitPushReadback | null>(null);
  const account = gitPushAccount(connection, files.projectId), review = writes.review;
  const prepared = review?.prepared.review.action === 'push' ? review.prepared.review : null;
  const originalPush = writes.original?.action.kind === 'push' || writes.submitted?.action.kind === 'push';
  const prepareReason = controller.preparePushReason(), reason = controller.reviewReason();
  const recovery = controller.pushReadbackSource(), comparison = readback?.result() ?? null;
  const readReason = recovery ? activity.readReason({ kind: 'overview', branch: recovery.review.upstreamRef.slice('refs/heads/'.length) }) :
    'Check the original Push status first. This comparison is available only after that task and its cleanup finish, in the same project and account. An unclear outcome stays blocked.';
  return <ProgressiveDisclosure title="Send commits to GitHub (Push)" needsAttention={!!prepared || !!originalPush &&
    (!!controller.ownerReason() || !!writes.issue || writes.recovery || writes.uncertain)}>
    <p>Upload changes you have already saved as Git commits to this branch’s linked GitHub branch. Uncommitted files and staged changes are not included.</p>
    <p>{account ? <>Connected account: <strong><bdi>{account.login}</bdi></strong> · <bdi>{account.repository}</bdi> ({account.visibility}).</> :
      'Connect the intended GitHub account and repository with push access first.'}</p>
    <button type="button" className="button secondary" disabled={prepareReason !== null} onClick={() => void controller.preparePush()}>Review commits to send…</button>
    <p className="save-note">Review checks GitHub using this account but does not upload commits. You approve the upload separately. The destination must already be linked; first-time branch setup and force-push are not supported here.</p>
    {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    {review && prepared && <section className="version-review" aria-label="Review ordinary GitHub push">
      <h3>Send {prepared.commits.length} {prepared.commits.length === 1 ? 'commit' : 'commits'} to GitHub</h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>Account: <strong><bdi>{prepared.login}</bdi></strong> · Repository: <bdi>{prepared.repository}</bdi>.</p>
      <p>Local branch <strong><bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi></strong> → GitHub branch <strong><bdi>{prepared.upstreamRef.slice('refs/heads/'.length)}</bdi></strong>.</p>
      <p><strong>People with access to this repository can read the uploaded commits.</strong> This includes commits made outside MRK. Check for private information before approving: messages, author emails and file contents are not shown or scanned for secrets here.</p>
      <p>The account, branch and latest GitHub commit must still match this review. If they changed, Push is refused instead of overwriting them. Your local files and branches stay unchanged.</p>
      {reason && <p className="review-caution" role="status">{gitLocalIssueHelp(reason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reason === null} disabled={reason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed these commits and this destination. Push them once using this account.</label>
      <button type="button" className="button primary" disabled={reason !== null || !review.approved} onClick={() => void controller.apply()}>Push these commits</button>
      <p className="save-note">Use the original Check, Stop and Close review controls above. Stop cannot undo an upload. If the result is unclear, check status—do not push again.</p>
      <details><summary>Reviewed commits and account details</summary>
        <ol>{prepared.commits.map((oid) => <li key={oid}><code>{oid}</code></li>)}</ol>
        <p>Account ID: <code>{prepared.accountId}</code>. Repository ID: <code>{prepared.repositoryId}</code>.</p>
        <p>GitHub commit when reviewed: <code>{prepared.expectedRemoteOid}</code>. Your reviewed commit: <code>{prepared.head}</code>.</p>
        <p>Remote name: <bdi>{prepared.remote}</bdi>.</p>
        <p>Review: <code>{review.prepared.reviewId}</code>.</p>
      </details>
    </section>}
    {originalPush && writes.recovery && <section className="version-review" aria-label="Read the remote branch after Push">
      <h3>Check GitHub without sending again</h3>
      <p>Read the destination branch again to compare its latest commit. This does not upload anything or resolve the earlier Push warning.</p>
      <button type="button" className="button secondary" disabled={readReason !== null}
        onClick={() => setReadback(startGitPushReadback(controller, activity))}>Check GitHub branch (read-only)</button>
      {readReason && <p className="save-note">{readReason}</p>}
      {readback && <>
        {activityState.pending ? <p role="status">Checking GitHub. The original Push result will not be changed by this check.</p> :
          comparison ? <p role="status">{comparison.comparison === 'matches-intended' ? 'GitHub reported the intended commit.' :
            comparison.comparison === 'still-old' ? 'GitHub still reported the previous commit.' : 'GitHub reported a different commit.'}
            {' '}This later check cannot prove which request changed GitHub. Do not use it as permission to push again.</p> :
          <p role="status">This check could not provide a current comparison. That does not mean the upload failed or never happened.</p>}
        {comparison && <details><summary>Later check details</summary><p>Commit: <code>{comparison.tip}</code>. Checked: {comparison.observedAt}.</p></details>}
        {activity.ownerReason() && <div className="inline-actions">
          <button type="button" className="button secondary" disabled={!activity.canCheck()} onClick={() => activity.checkStatus()}>Check read status</button>
          <button type="button" className="button secondary" disabled={!activity.canCancel()} onClick={() => activity.cancel()}>Stop read</button>
        </div>}
      </>}
    </section>}
    <details><summary>Supported Git setups</summary>
      <p>This action sends 1–64 existing commits to one already-linked GitHub branch. Unsupported history, hooks, signing, LFS, submodules or connection settings need your Git client. MRK does not bypass repository rules.</p>
      <p>Downloading updates (Fetch), updating your local branch, linking a destination and the first push of a new branch are separate actions. A recorded result describes that attempt, not GitHub’s future state.</p>
    </details>
  </ProgressiveDisclosure>;
}
export function GitPushRecovery({ result }: { result: GitPushMutationResult | GitPushNewBranchMutation }) {
  if (result.state !== 'recovery-required') return null;
  return <div className="review-caution" role="status">
    <p>Last reported Push step: {GIT_PUSH_EFFECT_LABELS[result.effectPhase]}. GitHub may already have changed. Do not send again.</p>
    <p>Keep this task and its files. A separate check can compare the GitHub branch, but a matching commit does not prove this Push succeeded or that cleanup finished.</p>
    {result.retainedPaths.length > 0 && <details open><summary>Retained private work — preserve it</summary>
      <p>Keep these recorded work items. Their names are not instructions to delete anything or run a command.</p><ul>{result.retainedPaths.map((p) => <li key={p}><code>{p}</code></li>)}</ul>
    </details>}
  </div>;
}
