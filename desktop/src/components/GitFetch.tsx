import { useId, useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import type { GitHubConnectionViewState } from '../githubConnectionTypes.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import { GIT_FETCH_EFFECT_LABELS, gitFetchRemote } from '../gitFetchProtocol.ts';
import type { GitFetchMutationResult } from '../gitFetchProtocol.ts';
import { gitFetchAccount } from '../gitFetchSelection.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

// Rendering only. The existing GitLocal owner retains all five calls, original
// review/Stop controls and drafts while this panel is hidden or unmounted.
export function GitFetch({ controller, repository, connection, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController;
  connection: GitHubConnectionViewState; originalProjectName?: string;
}) {
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const remoteId = useId(), branchId = useId(), account = gitFetchAccount(connection, files.projectId);
  const remotes = files.observation?.remotes.filter(gitFetchRemote) ?? [];
  const review = writes.review, prepared = review?.prepared.review.action === 'fetch' ? review.prepared.review : null;
  const originalFetch = writes.original?.action.kind === 'fetch' || writes.submitted?.action.kind === 'fetch';
  const prepareReason = controller.prepareFetchReason(), reason = controller.reviewReason();
  const upToDate = prepared !== null && prepared.expectedTarget === prepared.candidateRefOid;
  return <ProgressiveDisclosure title="Get a branch from GitHub (Fetch)" needsAttention={!!prepared || !!originalFetch &&
    (!!controller.ownerReason() || !!writes.issue || writes.recovery || writes.uncertain)}>
    <p>Download one reviewed GitHub branch into this project’s remote-tracking copy. Your current branch, working files and staged files stay unchanged. This does not merge, pull, push or publish.</p>
    <p>{account ? <>Current connection: <strong><bdi>{account.login}</bdi></strong> · <bdi>{account.repository}</bdi> ({account.visibility}).</> :
      'Connect the intended GitHub account and repository above before reviewing a fetch.'}</p>
    <form onSubmit={(event) => { event.preventDefault(); void controller.prepareFetch(); }}>
      <label htmlFor={remoteId}>Remote name in this project</label>
      <select id={remoteId} value={files.fetchDraft.remote} onChange={(event) => repository.editFetchDraft('remote', event.target.value)}>
        <option value="">Choose a remote</option>
        {files.fetchDraft.remote && !remotes.includes(files.fetchDraft.remote) &&
          <option value={files.fetchDraft.remote}>{files.fetchDraft.remote} — previous selection</option>}
        {remotes.map((name) => <option key={name} value={name}>{name}</option>)}
      </select>
      <label htmlFor={branchId}>Branch on GitHub</label>
      <input id={branchId} value={files.fetchDraft.branch} maxLength={244} autoComplete="off" spellCheck={false}
        placeholder="For example, main" onChange={(event) => repository.editFetchDraft('branch', event.target.value)} />
      <p className="save-note">Choose an existing remote such as origin after refreshing changes. Find the branch name in GitHub’s branch selector. Typing a name does not check that it exists.</p>
      <button type="submit" className="button secondary" disabled={prepareReason !== null}>Review fetch…</button>
      <p className="save-note">Review contacts GitHub using the connected account privately, including for private repositories. It checks the selected branch but does not update your project’s tracking copy yet. No token input or automatic account switch is used here.</p>
      {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    </form>
    {review && prepared && <section className="version-review" aria-label="Review one GitHub branch fetch">
      <h3>{upToDate ? 'This tracking copy matched when checked' : 'Review the branch to download'}</h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>Account: <strong><bdi>{prepared.login}</bdi></strong> · Repository: <bdi>{prepared.repository}</bdi>.</p>
      <p>GitHub branch <strong><bdi>{prepared.reference.slice('refs/heads/'.length)}</bdi></strong> → local tracking copy <strong><bdi>{prepared.targetRef.slice('refs/remotes/'.length)}</bdi></strong>.</p>
      <p>Previous tracking commit: <code>{prepared.expectedTarget?.slice(0, 12) ?? 'not present'}</code> → observed GitHub commit: <code>{prepared.candidateRefOid.slice(0, 12)}</code>.</p>
      <p>{upToDate ? 'No Fetch can be applied from this review. Close it using the original controls; later remote changes have not been checked.' :
        'Only this remote-tracking reference and its downloaded Git objects are updated. Other branches and working files are kept. The remote can change after this observation; Fetch rechecks its original selection rather than silently choosing a newer commit.'}</p>
      {reason && <p className="review-caution" role="status">{gitLocalIssueHelp(reason)}</p>}
      {!upToDate && <><label className="save-confirm-check"><input type="checkbox" checked={review.approved && reason === null} disabled={reason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> Use this account to fetch only the reviewed branch and update its local tracking copy.</label>
        <button type="button" className="button primary" disabled={reason !== null || !review.approved} onClick={() => void controller.apply()}>Fetch this branch</button></>}
      <p className="save-note">Use the original Check, Stop and Close review controls on this page. A lost reply is not permission to repeat Fetch. Your remote and branch draft is kept.</p>
      <details><summary>Reviewed account and commits</summary>
        <p>Account ID: <code>{prepared.accountId}</code>. Repository ID: <code>{prepared.repositoryId}</code>.</p>
        <p>Old tracking commit: <code>{prepared.expectedTarget ?? 'not present'}</code>. Observed commit: <code>{prepared.candidateRefOid}</code>.</p>
        <p>Unchanged checkout: <code>{prepared.head ?? 'no commit yet'}</code>. Review: <code>{review.prepared.reviewId}</code>.</p>
      </details>
    </section>}
    <details><summary>Supported layout and what stays separate</summary>
      <p>The remote must use the ordinary HTTPS URL for the selected GitHub repository. MRK will not rewrite remote settings, bypass required hooks or filters, fetch every branch, prune, fetch tags or force-push. Unsupported layouts need your Git client.</p>
      <p>A successful fetch records this one operation, not the latest future state of GitHub. Refresh local changes explicitly afterward. Updating your current branch is a separate reviewed action.</p>
    </details>
  </ProgressiveDisclosure>;
}

export function GitFetchRecovery({ result }: { result: GitFetchMutationResult }) {
  if (result.state !== 'recovery-required') return null;
  return <div className="review-caution" role="status">
    <p>Last reported Fetch step: {GIT_FETCH_EFFECT_LABELS[result.effectPhase]}. This is not proof of complete cleanup or permission to repeat the operation.</p>
    <p>Keep the original task, project and Git metadata. Check the original status before using your Git client for recovery; this screen cannot roll back or delete retained objects.</p>
    {result.retainedPaths.length > 0 && <details open><summary>Reported retained entries — preserve these</summary>
      <p>These names are relative to the original Git metadata directory, not a complete cleanup inventory or commands.</p>
      <ul>{result.retainedPaths.map((p) => <li key={p}><code><bdi>{p}</bdi></code></li>)}</ul>
    </details>}
  </div>;
}
