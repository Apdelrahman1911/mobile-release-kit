import { useId, useSyncExternalStore } from 'react';
import type { GitReadController } from '../gitReadController.ts';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import { GIT_SWITCH_EFFECT_LABELS } from '../gitSwitchProtocol.ts';
import type { GitSwitchMutationResult } from '../gitSwitchProtocol.ts';

// Subscribers only: mounting, selecting a branch or opening details cannot
// launch work, create another owner, close a review or synthesize a receipt.
export function GitBranchSwitch({ reader, controller, repository, originalProjectName }: {
  reader: GitReadController; controller: GitLocalController; repository: GitRepositoryController; originalProjectName?: string;
}) {
  const reads = useSyncExternalStore(reader.subscribe, reader.getSnapshot, reader.getSnapshot);
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const select = useId(), review = writes.review;
  const prepared = review?.prepared.review.action === 'branch-switch' ? review.prepared.review : null;
  const branches = reads.branchesProject === files.projectId ? reads.branches : null;
  const choices = branches?.branches.filter((b) => b.ref !== branches.branch) ?? [];
  const selected = files.switchDraft.name, present = choices.some((b) => b.ref === `refs/heads/${selected}`);
  const prepareReason = controller.prepareSwitchReason(), reviewReason = controller.reviewReason();
  return <section aria-label="Switch local branch">
    <h4>Switch to an existing local branch</h4>
    <p>Start with a clean working folder. This bounded switch changes file contents only: both branches must have the same regular-file names and modes.</p>
    <form onSubmit={(event) => { event.preventDefault(); void controller.prepareSwitch(); }}>
      <label htmlFor={select}>Local branch</label>
      <select id={select} value={selected} onChange={(event) => repository.selectSwitchBranch(event.target.value)}>
        <option value="">Choose a branch…</option>
        {selected && !present && <option value={selected}>{selected} · not in the current target list</option>}
        {choices.map((b) => <option key={b.ref} value={b.ref.slice('refs/heads/'.length)}>{b.ref.slice('refs/heads/'.length)}</option>)}
      </select>
      <button type="submit" className="button secondary" disabled={prepareReason !== null}>Review branch switch</button>
      {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    </form>
    <p className="save-note">No force, stash, reset, push or rename. Untracked and ignored files are not discarded. Required hooks, LFS and unsupported conversions are refused rather than run or silently skipped.</p>
    {review && prepared && <section className="version-review" aria-label="Review local branch switch">
      <h3>Switch to <bdi>{prepared.name}</bdi></h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>From <strong><bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi></strong> to <strong><bdi>{prepared.name}</bdi></strong>.</p>
      {prepared.files.length ? <><p>Only these {prepared.files.length} existing files change contents. No file is added, removed or renamed.</p>
        <ul>{prepared.files.map((f) => <li key={f.path}><code><bdi>{f.path}</bdi></code> · {f.targetSize} bytes after checkout</li>)}</ul></> :
        <p>The branches have the same file contents. This still changes the current branch and updates Git metadata; it is not a no-op.</p>}
      <p>File contents are not shown here. Compare the listed committed files in your Git client if needed; no credential content should be pasted into this view.</p>
      {reviewReason && <p className="review-caution" role="status">{gitLocalIssueHelp(reviewReason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reviewReason === null} disabled={reviewReason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed the target branch and listed content changes. Switch this clean checkout only.</label>
      <button type="button" className="button primary" disabled={reviewReason !== null || !review.approved} onClick={() => void controller.apply()}>Switch to this local branch</button>
      <p className="save-note">The original Check, Stop and Close review controls remain above. If an effect is uncertain, preserve files and candidates; do not retry or remove locks.</p>
      <details><summary>Reviewed commit details</summary><p>From <code>{prepared.head}</code> to <code>{prepared.targetOid}</code>.</p>
        <p>{prepared.trackedCount} tracked files checked. {prepared.log.enabled ? 'The existing Git HEAD-log policy is retained.' : 'HEAD logging is disabled by the reviewed repository policy.'}</p>
        <p>Review: <code>{review.prepared.reviewId}</code>.</p></details>
    </section>}
  </section>;
}

export function GitSwitchRecovery({ result }: { result: GitSwitchMutationResult }) {
  if (result.state !== 'recovery-required') return null;
  return <div className="review-caution" role="status">
    <p>Last reported switch step: {GIT_SWITCH_EFFECT_LABELS[result.effectPhase]}. This is not permission to repeat or repair the change.</p>
    <p>Preserve the working files and Git metadata. Check the original action before using your Git client for manual recovery; the app will not roll back or delete anything automatically.</p>
    {result.retainedPaths.length > 0 && <details open><summary>Retained candidate files — keep these</summary>
      <p>Paths are relative to the original project. They are not cleanup commands or downloadable files.</p>
      <ul>{result.retainedPaths.map((p) => <li key={p}><code><bdi>{p}</bdi></code></li>)}</ul></details>}
  </div>;
}
