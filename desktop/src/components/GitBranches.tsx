import { GitFastForward } from './GitFastForward.tsx';
import { useId, useSyncExternalStore } from 'react';
import type { GitReadController } from '../gitReadController.ts';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { GitBranchSwitch } from './GitBranchSwitch.tsx';
import { GitBranchRename } from './GitBranchRename.tsx';

// Pure rendering subscriber. The same retained GitRead/GitLocal controllers
// own every original Promise; mounting or editing a draft sends no command.
export function GitBranches({ reader, controller, repository, originalProjectName }: {
  reader: GitReadController; controller: GitLocalController; repository: GitRepositoryController; originalProjectName?: string;
}) {
  const reads = useSyncExternalStore(reader.subscribe, reader.getSnapshot, reader.getSnapshot);
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const name = useId(), review = writes.review;
  const prepared = review?.prepared.review.action === 'branch-create' ? review.prepared.review : null;
  const branches = reads.branchesProject === files.projectId ? reads.branches : null;
  const fresh = !!branches && reads.branchesCurrent && !reads.stale && !files.stale && branches.revision === files.observation?.revision;
  const readReason = reader.readReason(files.projectId), prepareReason = controller.prepareBranchReason(), reviewReason = controller.reviewReason();
  return <ProgressiveDisclosure title="Local branches" needsAttention={!!prepared || review?.prepared.review.action === 'branch-switch' || review?.prepared.review.action === 'fast-forward'}>
    <p>Read branches on this computer, then review a clean switch or create a new starting point. Nothing is pushed to GitHub.</p>
    <button type="button" className="button secondary" disabled={readReason !== null || !files.observation || files.stale}
      onClick={() => { if (files.observation) void reader.readBranches(files.projectId, files.observation.revision); }}>Read local branches</button>
    {readReason && <p className="save-note">{gitLocalIssueHelp(readReason)}</p>}
    {!files.observation && <p className="save-note">Refresh changes above before reading branches.</p>}
    {branches && <>
      {!fresh && <p className="review-caution" role="status">This is a previously read list, not a current branch review. Read local branches again after other tasks finish.</p>}
      <p>{branches.branch ? <>Current branch: <strong><bdi>{branches.branch.slice('refs/heads/'.length)}</bdi></strong>.</> : 'The checkout is detached; creating a branch will not attach or switch it.'}</p>
      {branches.branches.length ? <ul>{branches.branches.map((b) => <li key={b.ref}><bdi>{b.ref.slice('refs/heads/'.length)}</bdi>
        {b.ref === branches.branch ? ' · current' : ''} <code>{b.oid.slice(0, 12)}</code></li>)}</ul> : <p>No local branch commits were observed.</p>}
      <p className="save-note">Local references only; no fetch or online account check.</p>
    </>}
    <GitFastForward reader={reader} controller={controller} repository={repository} originalProjectName={originalProjectName} />
    <GitBranchRename controller={controller} repository={repository} originalProjectName={originalProjectName} />
    <GitBranchSwitch reader={reader} controller={controller} repository={repository} originalProjectName={originalProjectName} />
    <h4>Create a new local branch without switching</h4>
    <form onSubmit={(event) => { event.preventDefault(); void controller.prepareBranch(); }}>
      <label htmlFor={name}>New local branch name</label>
      <input id={name} maxLength={255} autoComplete="off" spellCheck={false} value={files.branchDraft.name}
        placeholder="release-1.2" onChange={(event) => repository.editBranchName(event.target.value)} />
      <p className="save-note">Choose an unused name. Use a top-level name unless the matching namespace already exists. The draft stays when you refresh, navigate or switch projects.</p>
      <button type="submit" className="button secondary" disabled={prepareReason !== null}>Review new local branch</button>
      {prepareReason && !prepared && <p className="save-note">{gitLocalIssueHelp(prepareReason)}</p>}
    </form>
    {review && prepared && <section className="version-review" aria-label="Review new local branch">
      <h3>Create <bdi>{prepared.name}</bdi> locally</h3>
      <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
      <p>Starts at commit <code>{prepared.head}</code>.</p>
      <p>{prepared.branch ? <>The current branch stays <strong><bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi></strong>.</> : 'The checkout stays detached.'}
        {' '}No files are staged, committed, checked out or changed by this branch action.</p>
      {reviewReason && <p className="review-caution" role="status">{gitLocalIssueHelp(reviewReason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reviewReason === null} disabled={reviewReason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed this name and starting commit; keep my current branch and files unchanged.</label>
      <button type="button" className="button primary" disabled={reviewReason !== null || !review.approved} onClick={() => void controller.apply()}>Create this local branch</button>
      <p className="save-note">The original Check, Stop and Close review controls above remain available. A successful ref read alone cannot settle an unconfirmed operation.</p>
    </section>}
  </ProgressiveDisclosure>;
}
