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
    'The original Push must have finished returning with known cleanup, in this same project and account. Unknown work remains blocked.';
  return <ProgressiveDisclosure title="Push committed changes to GitHub" needsAttention={!!prepared || !!originalPush &&
    (!!controller.ownerReason() || !!writes.issue || writes.recovery || writes.uncertain)}>
    <p>Send this branch’s existing commits to its configured GitHub branch. Working files and staged changes are not committed or sent automatically.</p>
    <p>{account ? <>Connected account: <strong><bdi>{account.login}</bdi></strong> · <bdi>{account.repository}</bdi> ({account.visibility}).</> :
      'Connect the intended GitHub account and repository with push access first.'}</p>
    <button type="button" className="button secondary" disabled={prepareReason !== null} onClick={() => void controller.preparePush()}>Review push…</button>
    <p className="save-note">Review contacts GitHub privately but does not upload commits. Push is a separate approval. Only an existing configured upstream is supported here; no new remote, new branch, force-push or reset is offered.</p>
    {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    {review && prepared && <section className="version-review" aria-label="Review ordinary GitHub push">
      <h3>Push {prepared.commits.length} committed {prepared.commits.length === 1 ? 'change' : 'changes'}</h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>Account: <strong><bdi>{prepared.login}</bdi></strong> · Repository: <bdi>{prepared.repository}</bdi>.</p>
      <p>Local branch <strong><bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi></strong> → GitHub branch <strong><bdi>{prepared.upstreamRef.slice('refs/heads/'.length)}</bdi></strong>.</p>
      <p>GitHub tip when checked: <code>{prepared.expectedRemoteOid.slice(0, 12)}</code> → your reviewed commit: <code>{prepared.head.slice(0, 12)}</code>.</p>
      <p><strong>This publishes committed content, including commits made in another Git client.</strong> Check those commits before approving. Commit messages, author emails and file bodies are not displayed here; this is not a secret scan.</p>
      <p>Push must still match this exact account, branch and old remote tip. Later changes are refused, not overwritten or force-pushed. Your local branch, index, worktree and cached upstream stay unchanged.</p>
      {reason && <p className="review-caution" role="status">{gitLocalIssueHelp(reason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reason === null} disabled={reason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed these commits and this destination. Push them once using this account.</label>
      <button type="button" className="button primary" disabled={reason !== null || !review.approved} onClick={() => void controller.apply()}>Push these commits</button>
      <p className="save-note">Use the original Check, Stop and Close review controls above. Stop cannot undo a remote update; a lost reply is not permission to repeat Push.</p>
      <details><summary>Reviewed commits and account details</summary>
        <ol>{prepared.commits.map((oid) => <li key={oid}><code>{oid}</code></li>)}</ol>
        <p>Account ID: <code>{prepared.accountId}</code>. Repository ID: <code>{prepared.repositoryId}</code>.</p>
        <p>Previous remote commit: <code>{prepared.expectedRemoteOid}</code>. Remote name: <bdi>{prepared.remote}</bdi>.</p>
        <p>Review: <code>{review.prepared.reviewId}</code>.</p>
      </details>
    </section>}
    {originalPush && writes.recovery && <section className="version-review" aria-label="Read the remote branch after Push">
      <h3>Check the remote branch without pushing again</h3>
      <p>This starts a fresh, read-only GitHub Activity check of the exact destination branch. It does not repeat Push, change the saved journal, or clear the original recovery warning.</p>
      <button type="button" className="button secondary" disabled={readReason !== null}
        onClick={() => setReadback(startGitPushReadback(controller, activity))}>Check remote branch (read-only)</button>
      {readReason && <p className="save-note">{readReason}</p>}
      {readback && <>
        {activityState.pending ? <p role="status">The separate read is running or finishing. The original Push remains unchanged.</p> :
          comparison ? <p role="status">{comparison.comparison === 'matches-intended' ? 'The remote branch now matches the intended commit.' :
            comparison.comparison === 'still-old' ? 'The remote branch still reports the old commit.' : 'The remote branch now reports a different commit.'}
            {' '}This later read does not prove which request changed GitHub and is not permission to retry.</p> :
          <p role="status">No current comparison is available from this read. Missing, denied, changed or unconfirmed responses are not proof that Push did not happen.</p>}
        {comparison && <details><summary>Later read details</summary><p>Tip: <code>{comparison.tip}</code>. Checked: {comparison.observedAt}.</p></details>}
        {activity.ownerReason() && <div className="inline-actions">
          <button type="button" className="button secondary" disabled={!activity.canCheck()} onClick={() => activity.checkStatus()}>Check read status</button>
          <button type="button" className="button secondary" disabled={!activity.canCancel()} onClick={() => activity.cancel()}>Stop read</button>
        </div>}
      </>}
    </section>}
    <details><summary>Supported push and recovery limits</summary>
      <p>This bounded route sends 1–64 existing outgoing commits to one configured upstream. Unsupported history, hooks, signing, LFS, submodules or transport settings need your Git client. MRK does not bypass repository policy.</p>
      <p>Fetch, local fast-forward, creating an upstream and the first push of a new branch are separate actions. A recorded result is historical, not a promise about GitHub’s current state.</p>
    </details>
  </ProgressiveDisclosure>;
}
export function GitPushRecovery({ result }: { result: GitPushMutationResult }) {
  if (result.state !== 'recovery-required') return null;
  return <div className="review-caution" role="status">
    <p>Last reported Push step: {GIT_PUSH_EFFECT_LABELS[result.effectPhase]}. The remote may have changed; this is not permission to resend.</p>
    <p>Keep the original task and files. Only a separate read of the exact remote branch can compare its tip; a match does not prove this request performed the update or that native cleanup finished.</p>
    {result.retainedPaths.length > 0 && <details open><summary>Retained private work — preserve it</summary>
      <p>These are recorded private work names, not cleanup paths or commands.</p><ul>{result.retainedPaths.map((p) => <li key={p}><code>{p}</code></li>)}</ul>
    </details>}
  </div>;
}
