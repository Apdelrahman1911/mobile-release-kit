import { useState, useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import type { GitHubConnectionViewState } from '../githubConnectionTypes.ts';
import type { GitHubActivityController } from '../githubActivityController.ts';
import { startGitPushReadback } from '../gitPushRecovery.ts';
import type { GitPushReadback } from '../gitPushRecovery.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import type { GitLocalIssue } from '../gitLocalProtocol.ts';
import { gitPushAccount } from '../gitPushSelection.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

function help(reason: GitLocalIssue): string {
  if (reason === 'push-upstream') return 'Choose a local branch with commits and no linked upstream. An existing or incomplete upstream must be handled separately; this action never rewrites it.';
  if (reason === 'push-history') return 'First publication reviews the entire reachable history, up to 64 commits. Shallow or unsupported history is refused rather than uploaded partially.';
  if (reason === 'push-read-required') return 'Refresh changes first to read the current local branch. A historical result does not select a branch to publish.';
  return gitLocalIssueHelp(reason);
}

// View only. Review, upload, Stop and the later read all stay in the existing
// original controllers; opening this section does not start any of them.
export function GitPushNewBranch({ controller, repository, connection, activity, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController; connection: GitHubConnectionViewState;
  activity: GitHubActivityController; originalProjectName?: string;
}) {
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const activityState = useSyncExternalStore(activity.subscribe, activity.getSnapshot, activity.getSnapshot);
  const [readback, setReadback] = useState<GitPushReadback | null>(null);
  const account = gitPushAccount(connection, files.projectId), review = writes.review;
  const prepared = review?.prepared.review.action === 'push-new-branch' ? review.prepared.review : null;
  const original = writes.original?.action.kind === 'push-new-branch' || writes.submitted?.action.kind === 'push-new-branch';
  const prepareReason = controller.preparePushNewBranchReason(), reason = controller.reviewReason();
  const source = controller.pushReadbackSource(), comparison = readback?.result() ?? null;
  const readReason = source?.review.action === 'push-new-branch' ?
    activity.readReason({ kind: 'overview', branch: source.review.upstreamRef.slice('refs/heads/'.length) }) :
    'Wait for the original task and cleanup. An unconfirmed result stays blocked; a later read cannot clear it.';
  return <ProgressiveDisclosure title="Publish a new GitHub branch" needsAttention={!!prepared || !!original &&
    (!!controller.ownerReason() || !!writes.issue || writes.recovery || writes.uncertain)}>
    <p>Create a GitHub branch with the same name as your current local branch. This can be the first branch in an empty repository. An existing GitHub branch is never replaced.</p>
    <p>{account ? <>Connected account: <strong><bdi>{account.login}</bdi></strong> · <bdi>{account.repository}</bdi> ({account.visibility}).</> :
      'Connect the intended GitHub account and repository with push access first.'}</p>
    <button type="button" className="button secondary" disabled={prepareReason !== null}
      onClick={() => void controller.preparePushNewBranch()}>Review first publication…</button>
    <p className="save-note">Review reads GitHub but uploads nothing. Your local branch must have no linked upstream. Uncommitted and staged changes are not included.</p>
    {prepareReason && !prepared && <p className="save-note">{help(prepareReason)}</p>}
    {review && prepared && <section className="version-review" aria-label="Review first GitHub publication">
      <h3>Publish {prepared.commits.length} {prepared.commits.length === 1 ? 'commit' : 'commits'} as a new branch</h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>Account: <strong><bdi>{prepared.login}</bdi></strong> · Repository: <bdi>{prepared.repository}</bdi>.</p>
      <p>New GitHub branch: <strong><bdi>{prepared.upstreamRef.slice('refs/heads/'.length)}</bdi></strong>.</p>
      <p><strong>People with access to this repository can read all uploaded history.</strong> This includes earlier commits and files, even if you later removed them. Messages, author emails and file contents are not shown or scanned for secrets here.</p>
      <p>The upload asks the server to create this branch only if it is still absent. A hidden or concurrently created branch must be refused, not overwritten. Your local files, index and upstream settings are not changed.</p>
      {reason && <p className="review-caution" role="status">{help(reason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reason === null} disabled={reason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed the full commit list and destination. Publish this new branch once using this account.</label>
      <button type="button" className="button primary" disabled={reason !== null || !review.approved}
        onClick={() => void controller.apply()}>Publish new branch</button>
      <p className="save-note">Use the original Check, Stop and Close review controls above. Stop cannot undo an upload. Do not repeat an uncertain publication.</p>
      <details><summary>All reviewed commits and account details</summary>
        <ol>{prepared.commits.map(oid => <li key={oid}><code>{oid}</code></li>)}</ol>
        <p>Account ID: <code>{prepared.accountId}</code>. Repository ID: <code>{prepared.repositoryId}</code>.</p>
        <p>Local tip: <code>{prepared.head}</code>. Review: <code>{review.prepared.reviewId}</code>.</p>
        <p>No configured remote alias or cached tracking tip is used as proof that the new branch is absent.</p>
      </details>
    </section>}
    {original && writes.recovery && <section className="version-review" aria-label="Read after first publication">
      <h3>Check GitHub without sending again</h3>
      <p>This separate read can compare the branch’s current tip. It cannot prove this publication succeeded, clear its warning or authorize a retry.</p>
      <button type="button" className="button secondary" disabled={readReason !== null}
        onClick={() => setReadback(startGitPushReadback(controller, activity))}>Check GitHub branch (read-only)</button>
      {readReason && <p className="save-note">{readReason}</p>}
      {readback && <>
        <p role="status">{activityState.pending ? 'Reading GitHub; the original result stays unchanged.' : comparison ?
          comparison.comparison === 'matches-intended' ? 'GitHub now reports the intended commit. This does not prove which request created it.' :
            'GitHub now reports a different commit. No overwrite or retry is authorized.' :
          'No current comparison is available. A missing or inaccessible branch does not prove the upload never happened.'}</p>
        {activity.ownerReason() && <div className="inline-actions">
          <button type="button" className="button secondary" disabled={!activity.canCheck()} onClick={() => activity.checkStatus()}>Check read status</button>
          <button type="button" className="button secondary" disabled={!activity.canCancel()} onClick={() => activity.cancel()}>Stop read</button>
        </div>}
      </>}
    </section>}
    <details><summary>Supported setups and next steps</summary>
      <p>This action reviews 1–64 reachable commits and creates one branch. It does not bypass hooks, signing, LFS, submodules or repository policy. Unsupported setups need your Git client.</p>
      <p>Linking an upstream for later Fetch and ordinary Push is a separate, explicitly approved local change. A publication result never applies that change automatically.</p>
    </details>
  </ProgressiveDisclosure>;
}
