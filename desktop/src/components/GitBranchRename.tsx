import { useId, useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import { GIT_RENAME_EFFECT_LABELS } from '../gitRenameProtocol.ts';
import type { GitRenameMutationResult } from '../gitRenameProtocol.ts';

// Rendering only. All five operations remain on the retained GitLocal owner.
export function GitBranchRename({ controller, repository, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController; originalProjectName?: string;
}) {
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const input = useId(), review = writes.review;
  const prepared = review?.prepared.review.action === 'branch-rename' ? review.prepared.review : null;
  const prepareReason = controller.prepareRenameReason(), reviewReason = controller.reviewReason();
  return <section aria-label="Rename current local branch">
    <h4>Rename the current local branch</h4>
    <p>Keep the same commit, staged files and working files. This changes only the local branch name and its existing Git metadata—not a branch on GitHub.</p>
    <form onSubmit={(event) => { event.preventDefault(); void controller.prepareRename(); }}>
      <label htmlFor={input}>New local branch name</label>
      <input id={input} value={files.renameDraft.name} maxLength={255} autoComplete="off" spellCheck={false}
        onChange={(event) => repository.editRenameName(event.target.value)} />
      <button type="submit" className="button secondary" disabled={prepareReason !== null}>Review branch rename</button>
      {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    </form>
    <p className="save-note">Use an unused name in the same branch folder. No force, reset, checkout, remote change or automatic recovery is included.</p>
    {review && prepared && <section className="version-review" aria-label="Review local branch rename">
      <h3>Rename <bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi> to <bdi>{prepared.name}</bdi></h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>The commit and index stay unchanged, including staged work. Your working files are kept.</p>
      <p>{prepared.configMoved ? 'Existing branch settings move to the new local name. Upstream values and unrelated settings stay unchanged.' :
        'There is no existing branch settings section to move. The configuration file stays unchanged.'}</p>
      <p>{prepared.logging ? 'Existing branch and HEAD logs are preserved with the original Git rename entry.' : 'Logging stays disabled by the reviewed repository policy.'}</p>
      {reviewReason && <p className="review-caution" role="status">{gitLocalIssueHelp(reviewReason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reviewReason === null} disabled={reviewReason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed the old and new names. Rename only this local branch.</label>
      <button type="button" className="button primary" disabled={reviewReason !== null || !review.approved} onClick={() => void controller.apply()}>Rename this local branch</button>
      <p className="save-note">The original Check, Stop and Close review controls remain above. An interrupted rename can need manual recovery; never repeat it or delete lock files to dismiss a warning.</p>
      <details><summary>Reviewed commit and operation</summary><p>Unchanged commit: <code>{prepared.head}</code>.</p><p>Review: <code>{review.prepared.reviewId}</code>.</p></details>
    </section>}
  </section>;
}

export function GitRenameRecovery({ result }: { result: GitRenameMutationResult }) {
  if (result.state !== 'recovery-required') return null;
  return <div className="review-caution" role="status">
    <p>Last reported rename step: {GIT_RENAME_EFFECT_LABELS[result.effectPhase]}. This does not authorize another attempt or prove the whole rename completed.</p>
    <p>Preserve the project, Git metadata and retained candidates. Check the original action before manual recovery in your Git client; the app does not roll back or delete them.</p>
    {result.retainedPaths.length > 0 && <details open><summary>Reported retained candidates — keep these</summary>
      <p>These relative paths are guidance, not a complete cleanup inventory or commands.</p>
      <ul>{result.retainedPaths.map((p) => <li key={p}><code><bdi>{p}</bdi></code></li>)}</ul></details>}
  </div>;
}
