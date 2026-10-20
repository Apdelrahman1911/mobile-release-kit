import { useSyncExternalStore } from 'react';
import type { GitReadController } from '../gitReadController.ts';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import { GIT_FAST_FORWARD_EFFECT_LABELS } from '../gitFastForwardProtocol.ts';
import type { GitFastForwardMutationResult } from '../gitFastForwardProtocol.ts';

// Existing controllers retain every request. Rendering or expanding this panel
// neither fetches nor prepares/applies an update.
export function GitFastForward({ reader, controller, repository, originalProjectName }: {
  reader: GitReadController; controller: GitLocalController; repository: GitRepositoryController; originalProjectName?: string;
}) {
  const reads = useSyncExternalStore(reader.subscribe, reader.getSnapshot, reader.getSnapshot);
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const review = writes.review, prepared = review?.prepared.review.action === 'fast-forward' ? review.prepared.review : null;
  const cached = reads.observationProject === files.projectId ? reads.observation : null;
  const prepareReason = controller.prepareFastForwardReason(), reviewReason = controller.reviewReason();
  return <section aria-label="Local fast-forward">
    <h4>Update this branch to its last-fetched tip</h4>
    <p>This local fast-forward uses the upstream commit already on this computer. It does not fetch or check for newer remote changes, merge, rebase or push.</p>
    {cached?.tracking.localRef && <p>Previously read tracking ref: <code><bdi>{cached.tracking.localRef}</bdi></code>.</p>}
    <p className="save-note">Start with a clean working folder. This bounded update changes only existing regular-file contents, not file names or modes. Other layouts need your Git client.</p>
    <button type="button" className="button secondary" disabled={prepareReason !== null} onClick={() => void controller.prepareFastForward()}>Review local fast-forward</button>
    {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    {review && prepared && <section className="version-review" aria-label="Review cached upstream update">
      <h3>Fast-forward <bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi></h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>. The current branch stays the same.</p>
      <p>Target: <code><bdi>{prepared.targetRef}</bdi></code>, from the last fetched history. This is not a fresh remote check.</p>
      {prepared.files.length ? <><p>Only these {prepared.files.length} files change contents:</p>
        <ul>{prepared.files.map((f) => <li key={f.path}><code><bdi>{f.path}</bdi></code> · {f.targetSize} bytes after update</li>)}</ul></> :
        <p>The committed file contents are identical. The branch still advances to a different commit; this is not a no-op.</p>}
      <p>Review the committed file changes in your Git client if needed. File bodies and credentials are not displayed here. Untracked and ignored files are preserved.</p>
      {reviewReason && <p className="review-caution" role="status">{gitLocalIssueHelp(reviewReason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reviewReason === null} disabled={reviewReason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed this cached target and the listed changes. Fast-forward this clean branch only.</label>
      <button type="button" className="button primary" disabled={reviewReason !== null || !review.approved} onClick={() => void controller.apply()}>Fast-forward to this cached commit</button>
      <p className="save-note">Use the original Check, Stop and Close review controls above. An uncertain update must not be repeated or rolled back automatically.</p>
      <details><summary>Reviewed commit details</summary><p>From <code>{prepared.head}</code> to <code>{prepared.targetOid}</code>.</p>
        <p>{prepared.trackedCount} tracked files compared; existing branch and HEAD log policies remain unchanged.</p>
        <p>Review: <code>{review.prepared.reviewId}</code>.</p></details>
    </section>}
  </section>;
}
export function GitFastForwardRecovery({ result }: { result: GitFastForwardMutationResult }) {
  if (result.state !== 'recovery-required') return null;
  return <div className="review-caution" role="status">
    <p>Last reported update step: {GIT_FAST_FORWARD_EFFECT_LABELS[result.effectPhase]}. This is not proof of native closure or permission to repeat the change.</p>
    <p>Keep the working files and Git metadata. Check the original task before manual recovery; the app will not reset, restore or delete anything automatically.</p>
    {result.retainedPaths.length > 0 && <details open><summary>Retained candidate files — keep these</summary>
      <p>These paths are relative to the original project, not cleanup commands.</p>
      <ul>{result.retainedPaths.map((p) => <li key={p}><code><bdi>{p}</bdi></code></li>)}</ul></details>}
  </div>;
}
