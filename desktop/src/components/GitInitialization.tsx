import { useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';

// No effects on mount. This uses the existing five-call controller and original
// Check/Stop/Close controls; it is not a second setup/process owner.
export function GitInitialization({ controller, repository, projectName, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController; projectName: string; originalProjectName?: string;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const review = state.review, prepared = review?.prepared.review.action === 'initialize' ? review.prepared.review : null;
  const original = state.original?.action.kind === 'initialize' && state.original.context.projectId === files.projectId;
  if (files.observation && !prepared && !original) return null;
  const prepareReason = controller.prepareInitializeReason(), reviewReason = controller.reviewReason();
  return <section className="github-workflow" aria-label="Set up local Git">
    <h3>Start tracking this project with Git</h3>
    <p>Create an empty local repository in <strong>{projectName}</strong>. Your files stay as they are—nothing is staged, committed, uploaded or published.</p>
    <p className="save-note">First check local Git actions below, then review setup. A missing file view does not prove this folder has no Git metadata; the native review checks it.</p>
    <button type="button" className="button secondary" disabled={prepareReason !== null} onClick={() => void controller.prepareInitialize()}>Review Git setup</button>
    {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    {review && prepared && <section className="version-review" aria-label="Review local Git initialization">
      <h4>Create an empty local repository</h4>
      <p>Original project: <strong>{originalProjectName ?? 'a previously selected project'}</strong>. Its folder passed the native absence check. Git will start on <code>{prepared.initialBranch}</code> with no commits, index or remote.</p>
      <p>Only new Git metadata is added. Existing source files, unsaved changes and project settings are kept. Existing or newly appearing Git metadata is never replaced.</p>
      {reviewReason && <p className="review-caution" role="status">{gitLocalIssueHelp(reviewReason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reviewReason === null} disabled={reviewReason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed this folder. Create only its empty local Git repository.</label>
      <button type="button" className="button primary" disabled={reviewReason !== null || !review.approved} onClick={() => void controller.apply()}>Create local repository</button>
      <p className="save-note">Check, Stop and Close review below stay attached to the original task. If interrupted or unconfirmed, keep all metadata and do not repeat setup or remove its private folders.</p>
      <details><summary>Review details</summary><p>Review: <code>{review.prepared.reviewId}</code>. Metadata format: {prepared.objectFormat}.</p></details>
    </section>}
  </section>;
}
