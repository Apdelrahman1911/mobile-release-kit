import { GitPushRecovery } from './GitPush.tsx';
import { GitFastForwardRecovery } from './GitFastForward.tsx';
import { useId, useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitStagedPaths } from '../gitRepositoryProtocol.ts';
import type { GitDiff } from '../gitRepositoryProtocol.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import type { GitLocalMutationResult } from '../gitLocalProtocol.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { GitSwitchRecovery } from './GitBranchSwitch.tsx';
import { GitRenameRecovery } from './GitBranchRename.tsx';
import { GitFetchRecovery } from './GitFetch.tsx';

function Difference({ diff }: { diff: GitDiff }) {
  return <div className="version-raw"><h4>Reviewed differences</h4>
    {diff.text !== null ? diff.text ? <pre tabIndex={0} aria-label="Reviewed Git differences"><code>{diff.text}</code></pre> : <p>No text differences were returned.</p> :
      <p className="review-caution" role="status">{diff.withheld === 'sensitive-content' ? 'Potential credential content was withheld. Review it privately; do not paste it here.' :
        diff.withheld === 'untracked' ? 'New file contents are not shown here. Review each listed file in your editor before continuing.' :
          'These contents cannot be shown as text. Review the listed files in the appropriate editor before continuing.'}</p>}
  </div>;
}

// Rendering only. Neither mounting nor hiding these controls invokes a native
// action, discards a review, retries a write or disposes its original owner.
export function GitLocalControls({ controller, compact = false, originalProjectName, onShow }: {
  controller: GitLocalController; compact?: boolean; originalProjectName?: string; onShow?: () => void;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const active = controller.ownerReason() !== null, op = state.original;
  if (compact && !active && !state.issue) return null;
  const result = op?.phase === 'apply' && op.result ? op.result as GitLocalMutationResult : null;
  const title = state.uncertain ? 'Git action needs attention' : state.recovery ? 'Git recovery is needed' : state.pending ? 'Waiting for the original Git request' :
    state.review ? 'Review before changing Git' : active ? 'Git action is still running' : result?.state === 'succeeded' ?
      result.action === 'fetch' ? 'Reviewed branch fetched' : result.action === 'push' ? 'Reviewed commits pushed to GitHub' : result.action === 'initialize' ? 'Local repository created' : result.action === 'fast-forward' ? 'Local branch fast-forwarded to the cached tip' : result.action === 'branch-rename' ? 'Local branch renamed' : result.action === 'branch-switch' ? 'Local branch switched' : result.action === 'branch-create' ? 'Local branch created' : result.action === 'commit' ? 'Local commit created' : result.action === 'stage' ? 'Selected files staged' : 'Selected files unstaged' :
        op?.stage === 'settled' ? op.outcome !== 'ok' || result?.state === 'failed' ? 'Git action did not complete' : 'Git check finished' : 'Local Git actions';
  return <section className={compact ? 'notice notice-info' : 'github-workflow'} aria-label="Local Git action status">
    <div><h3>{title}</h3>
      {state.projectId && <p>Original project: <strong>{originalProjectName ?? 'a previously selected project'}</strong>.</p>}
      {state.uncertain && <p className="review-caution" role="alert">The original result or cleanup is unconfirmed. Keep the app and project files. Do not repeat the action, reconnect to dismiss it, or remove Git lock files.</p>}
      {state.recovery && <p className="review-caution" role="alert">Preserve the original task and project files. This screen cannot prove recovery or safely repeat the change.</p>}
      {result?.action === 'push' && <GitPushRecovery result={result} />}
      {result?.action === 'fast-forward' && <GitFastForwardRecovery result={result} />}
      {result?.action === 'fetch' && <GitFetchRecovery result={result} />}
      {result?.action === 'branch-rename' && <GitRenameRecovery result={result} />}
      {result?.action === 'branch-switch' && <GitSwitchRecovery result={result} />}
      {state.issue && !state.uncertain && !state.recovery && <p className="review-caution" role="status">{gitLocalIssueHelp(state.issue)}</p>}
      {result?.action === 'initialize' && result.state === 'succeeded' && !active && <p>No files were staged or committed. Git is local only; no remote was configured.</p>}
      {result?.state === 'succeeded' && result.action !== 'push' && !active && <p>Your drafts are kept. Refresh changes explicitly to read the files again; nothing was pushed to GitHub.</p>}
      {result?.action === 'push' && result.state === 'succeeded' && !active && <p>This records the original reviewed push, not the current state of GitHub. Working files, staging and local refs were kept; refresh and fetch separately when needed.</p>}
      {!active && (!state.status || !state.status.available) && <p className="save-note">{state.status ?
        'Local Git changes are not enabled in this installed session. You can still keep a draft and use your Git client; a read-only view does not enable writes.' :
        'Check local Git actions first. This checks native availability; it does not stage files or create a commit.'}</p>}
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!controller.canCheck()} onClick={() => void controller.checkStatus()}>
          {state.checking ? 'Checking…' : active ? 'Check original action' : 'Check local Git actions'}</button>
        {active && <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => void controller.cancel()}>Stop original action</button>}
        {state.review && <button type="button" className="button secondary" disabled={!controller.canDiscard()} onClick={() => void controller.discard()}>Close review, keep draft</button>}
        {compact && onShow && <button type="button" className="text-button" onClick={onShow}>Show local changes</button>}
      </div>
      {!active && controller.checkReason() && <p className="save-note">{controller.checkReason()}</p>}
      {op && <details><summary>Original action details</summary><p>{op.phase === 'prepare' ? 'Read-only review' : 'Submitted change'} · {op.action.kind} · {op.stage}.</p>
        <p>Original operation: <code>{op.operationId}</code>. Native outcome: {op.outcome ?? 'not settled'}.</p>
        {result && <p>Git result: {result.state}. This is not a fresh file or remote observation.</p>}</details>}
    </div>
  </section>;
}

export function GitLocalChanges({ controller, repository, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController; originalProjectName?: string;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const message = useId(), author = useId(), email = useId();
  const stageReason = controller.prepareReason('stage'), unstageReason = controller.prepareReason('unstage'), commitReason = controller.prepareReason('commit');
  const staged = files.observation ? gitStagedPaths(files.observation) : [];
  const review = state.review, reason = controller.reviewReason();
  const prepared = review && 'diff' in review.prepared ? review.prepared : null;
  const nextStage = files.selected.length > 0 && !review;
  return <div>
    <h3>Save changes in Git</h3>
    <p>Choose files above, review what will be staged, then make a local commit. Your working files are kept. Nothing is pushed or published.</p>
    <div className="button-row">
      <button type="button" className={`button ${nextStage ? 'primary' : 'secondary'}`} disabled={stageReason !== null}
        onClick={() => void controller.prepare('stage')}>Review files to stage</button>
      <button type="button" className="button secondary" disabled={unstageReason !== null}
        onClick={() => void controller.prepare('unstage')}>Review files to unstage</button>
    </div>
    {stageReason && !review && <p className="save-note">{gitLocalIssueHelp(stageReason)}</p>}
    <p className="save-note">Staging selects whole files for the next commit. Unstaging removes them from that selection, not from your working folder.</p>
    <ProgressiveDisclosure title={`Create a local commit${staged.length ? ` · ${staged.length} staged` : ''}`} needsAttention={staged.length > 0 || review?.prepared.action.kind === 'commit'}>
      <form onSubmit={(event) => { event.preventDefault(); void controller.prepare('commit'); }}>
        <label htmlFor={message}>Commit message</label><textarea id={message} rows={3} maxLength={4096} value={files.draft.message}
          placeholder="Describe what changed" onChange={(event) => repository.editDraft('message', event.target.value)} />
        <div className="form-grid">
          <div><label htmlFor={author}>Author name</label><input id={author} value={files.draft.authorName} maxLength={128} autoComplete="off"
            onChange={(event) => repository.editDraft('authorName', event.target.value)} /></div>
          <div><label htmlFor={email}>Author email</label><input id={email} type="email" value={files.draft.authorEmail} maxLength={254} autoComplete="off"
            onChange={(event) => repository.editDraft('authorEmail', event.target.value)} /></div>
        </div>
        <p className="save-note">Use your preferred public name and a verified or private no-reply email from GitHub Settings → Emails. These details are for this commit only; your Git account settings are not changed. The draft stays when you refresh, switch projects or close a review.</p>
        <p><strong>A commit includes every staged change, including files staged in another Git client—not just the checked files above.</strong></p>
        <button type="submit" className={`button ${!nextStage && !review ? 'primary' : 'secondary'}`} disabled={commitReason !== null}>Review complete commit</button>
        {commitReason && !review && <p className="save-note">{gitLocalIssueHelp(commitReason)}</p>}
      </form>
    </ProgressiveDisclosure>
    <GitLocalControls controller={controller} originalProjectName={originalProjectName} />
    {review && prepared && <section className="version-review" aria-label="Review local Git change">
      <h3>{prepared.action.kind === 'commit' ? 'Review the complete staged commit' : prepared.action.kind === 'stage' ? 'Review files to stage' : 'Review files to unstage'}</h3>
      <p>{prepared.action.kind === 'commit' ? 'Every file below is included in this local commit.' : 'Only the whole files below will be staged or unstaged. Other entries and working files are kept.'}</p>
      {prepared.action.kind === 'commit' && <p>Commit to <strong><bdi>{prepared.review.branch?.slice('refs/heads/'.length)}</bdi></strong> on this computer.</p>}
      <ul>{prepared.review.paths.map((path) => <li key={path}><code><bdi>{path}</bdi></code></li>)}</ul>
      {review.draft && <><p>Author: <bdi>{review.draft.authorName}</bdi> · <bdi>{review.draft.authorEmail}</bdi>.</p><div className="version-raw"><h4>Reviewed commit message</h4><pre>{review.draft.message}</pre></div></>}
      <Difference diff={prepared.diff} />
      {reason && <p className="review-caution" role="status">{gitLocalIssueHelp(reason)}</p>}
      <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reason === null} disabled={reason !== null}
        onChange={(event) => controller.approve(event.target.checked)} /> I reviewed all listed files, including any contents not shown here.</label>
      <p className="save-note">Local Git only. No push, branch change, hook, build or release is included. Required repository policies are not bypassed.</p>
      <button type="button" className="button primary" disabled={reason !== null || !review.approved} onClick={() => void controller.apply()}>
        {prepared.action.kind === 'commit' ? 'Create this local commit' : prepared.action.kind === 'stage' ? 'Stage these files' : 'Unstage these files'}</button>
      <details><summary>Review details</summary><p>Review: <code>{prepared.reviewId}</code>. Revision: <code>{prepared.review.expectedRevision}</code>.</p></details>
    </section>}
  </div>;
}
