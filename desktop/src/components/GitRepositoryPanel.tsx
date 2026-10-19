import { useId, useState, useSyncExternalStore } from 'react';
import { GIT_ISSUE_HELP, gitStagedPaths } from '../gitRepositoryProtocol.ts';
import type { GitDiff } from '../gitRepositoryProtocol.ts';
import type { GitRepositoryController, GitReview } from '../gitRepositoryController.ts';
import { Badge, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const statusLabel: Readonly<Record<string, string>> = Object.freeze({ ' ': '—', M: 'Modified', T: 'Type changed', A: 'Added',
  D: 'Deleted', R: 'Renamed', C: 'Copied', U: 'Conflict', '?': 'Not tracked', '!': 'Ignored' });
function DiffPreview({ diff }: { diff: GitDiff }) {
  return <div className="version-raw">
    <h4>{diff.staged ? 'Staged changes' : 'Working-file changes'}</h4>
    {diff.text !== null ? diff.text ? <pre tabIndex={0} aria-label="Selected Git changes"><code>{diff.text}</code></pre> :
      <p>No differences in this comparison.</p> : <p className="review-caution" role="status">
        {diff.withheld === 'sensitive-content' ? 'Potential credential content was withheld. Review it privately; do not paste it into MRK.' :
          diff.withheld === 'untracked' ? 'New, untracked file contents are not displayed here. Review those files in your editor before staging.' :
            'Non-text content cannot be displayed here. Review the listed files with the appropriate editor.'}
      </p>}
  </div>;
}
function Review({ review, controller }: { review: GitReview; controller: GitRepositoryController }) {
  const [checked, setChecked] = useState(false);
  const { plan, draft } = review;
  const reason = controller.applyReason(plan.planId);
  const label = plan.action === 'commit' ? 'Create this local commit' : plan.action === 'stage' ? 'Stage these files' : 'Unstage these files';
  return <section className="version-review" aria-label="Review this Git change">
    <h3>{plan.action === 'commit' ? 'Review the complete staged commit' : plan.action === 'stage' ? 'Review files to stage' : 'Review files to unstage'}</h3>
    <p>{plan.action === 'commit' ? <strong>Every staged change below is included, even files staged outside MRK. This is not limited to the checked selection.</strong> :
      plan.action === 'stage' ? 'Stage only these whole files for the next commit. Other staged entries and working files are kept.' :
        'Remove only these files from the next commit. Your working files and other staged entries are kept.'}</p>
    <ul>{plan.paths.map((path) => <li key={path}><code><bdi>{path}</bdi></code></li>)}</ul>
    {draft && <><p>Commit on <strong><bdi>{plan.branch?.slice('refs/heads/'.length)}</bdi></strong> with author <bdi>{draft.authorName}</bdi> · <bdi>{draft.authorEmail}</bdi>.</p>
      <div className="version-raw"><h4>Reviewed commit message</h4><pre>{draft.message}</pre></div></>}
    {review.preview ? <DiffPreview diff={review.preview} /> : <p>Waiting for the original bounded preview. Nothing can be applied yet.</p>}
    {review.stale && <p className="review-caution" role="status">This review changed or became stale. Close it and prepare a new one. Your current commit draft is kept.</p>}
    <label className="save-confirm-check"><input type="checkbox" checked={checked} disabled={reason !== null}
      onChange={(event) => setChecked(event.target.checked)} /> I reviewed all listed files, including any contents not shown here.</label>
    <p className="save-note">Local Git only. No push, remote changes, hooks, build or release is included. This review cannot bypass required repository policies.</p>
    <div className="button-row">
      <button type="button" className="button primary" disabled={reason !== null || !checked}
        onClick={() => void controller.applyReviewed(plan.planId)}>{label}</button>
      <button type="button" className="button secondary" disabled={controller.readReason() !== null}
        onClick={() => void controller.discardReview(plan.planId)}>Close review, keep draft</button>
    </div>
    {reason && <p className="save-note">{GIT_ISSUE_HELP[reason]}</p>}
  </section>;
}

// Root supplies and retains the original bound controller. Unmounting this view
// unsubscribes rendering only: it never cancels, discards, retries or adopts work.
export function GitRepositoryPanel({ controller, projectName, onRecovery }: {
  controller: GitRepositoryController; projectName: string; onRecovery?: () => void;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const messageId = useId(), authorNameId = useId(), authorEmailId = useId();
  const observation = state.observation;
  const staged = observation ? gitStagedPaths(observation) : [];
  const attempt = state.attempt, result = attempt?.receipt?.result;
  const stageReason = controller.prepareReason('stage'), unstageReason = controller.prepareReason('unstage');
  const commitReason = controller.prepareReason('commit'), selectReason = controller.selectionReason();
  const next = !observation || state.stale ? 'refresh' : state.selected.some((path) => observation.changes.some((row) => row.path === path && row.worktree !== ' ')) ?
    'stage' : staged.length ? 'commit' : 'select';
  return <section className="card" aria-label="Local Git changes">
    <SectionHeading title="Source changes" description="Review your local files, stage only what you choose, then create a commit.">
      <Icon name="branch" size={24} />
    </SectionHeading>
    <p>Project: <strong>{projectName}</strong>. {observation && <>{observation.detached ? 'Not on a branch' :
      <>Branch: <bdi>{observation.branch?.slice('refs/heads/'.length)}</bdi></>}{observation.unborn && ' · No commits yet'}.</>}</p>
    {!controller.hasWriter() && <p className="save-note">Git writes are unavailable in this session. A read-only view does not enable them.</p>}
    {state.issue && <p className="review-caution" role="status">{GIT_ISSUE_HELP[state.issue]}</p>}
    {state.blocked && state.issue !== state.blocked && <p className="review-caution" role="alert">{GIT_ISSUE_HELP[state.blocked]}</p>}
    {state.blocked && !attempt && onRecovery && <button type="button" className="text-button" onClick={onRecovery}>View retained recovery</button>}
    {attempt && <div className="notice notice-info" role="status"><div>
      <strong>{attempt.phase === 'settled' ? result?.state === 'succeeded' ? attempt.review.plan.action === 'commit' ? 'Local commit created' :
        attempt.review.plan.action === 'stage' ? 'Selected files staged' : 'Selected files unstaged' : 'Git action settled without success' :
        attempt.phase === 'sending' ? 'Waiting for the original Git action' : attempt.phase === 'awaiting-status' ? 'Original action needs a status check' :
          attempt.phase === 'recovery-required' ? 'Git recovery is needed' : 'Original outcome or cleanup is unknown'}</strong>
      <p>{attempt.phase === 'settled' ? 'This receipt describes the submitted review, not later edits. Your commit draft is kept.' :
        'The submitted review is retained. Do not send it again; refreshing files cannot settle this operation.'}</p>
      {attempt.phase !== 'settled' && <div className="button-row">
        <button type="button" className="button secondary" disabled={!controller.canCheckOriginalStatus()}
          onClick={() => void controller.checkOriginalStatus()}>Check original action</button>
        {onRecovery && <button type="button" className="text-button" onClick={onRecovery}>View retained recovery</button>}
      </div>}
      <details><summary>Submitted action details</summary>
        <p>Action: {attempt.review.plan.action}. Core outcome: {result?.state ?? 'not received'}.
          {' '}Core settlement: {result?.settlement ?? 'not received'}. Native settlement: {attempt.receipt?.nativeFinality ?? 'not received'}.</p>
        <ul>{attempt.review.plan.paths.map((path) => <li key={path}><code><bdi>{path}</bdi></code></li>)}</ul>
        {result && <p>Original operation: <code>{result.operationId}</code>.</p>}
      </details>
    </div></div>}
    <div className="button-row"><button type="button" className={`button ${next === 'refresh' && !state.review ? 'primary' : 'secondary'}`}
      disabled={controller.readReason() !== null} onClick={() => void controller.refresh()}><Icon name="refresh" size={16} />Refresh changes</button>
      {observation && <Badge tone={state.stale ? 'warning' : 'neutral'}>{state.stale ? 'Refresh needed' : `${observation.changes.length} changed · ${staged.length} staged`}</Badge>}
    </div>
    {!observation && <p className="save-note">Refresh to read the selected project’s working files and staged changes. No remote repository is contacted.</p>}
    {observation && <>
      {state.stale && <p className="save-note">The previous file list is retained. Refresh before reviewing a new change; this never replaces your commit draft.</p>}
      {observation.restrictions.map((reason) => <p key={reason} className="review-caution">{GIT_ISSUE_HELP[reason]}</p>)}
      {observation.changes.length ? <div className="review-table-wrap"><table className="review-table">
        <caption>Choose individual files. Staged files are included in the next commit.</caption>
        <thead><tr><th scope="col">Select</th><th scope="col">File</th><th scope="col">Staged</th><th scope="col">Working file</th></tr></thead>
        <tbody>{observation.changes.map((row) => <tr key={row.path}>
          <td><input type="checkbox" aria-label={`Select ${row.path}`} checked={state.selected.includes(row.path)}
            disabled={state.stale || !state.active || state.busy !== null} onChange={(event) => controller.select(row.path, event.target.checked)} /></td>
          <th scope="row"><code><bdi>{row.path}</bdi></code>{row.conflict && <Badge tone="warning">Conflict</Badge>}</th>
          <td>{statusLabel[row.index]}</td><td>{statusLabel[row.worktree]}</td>
        </tr>)}</tbody>
      </table></div> : <p>No changed files were observed.</p>}
      <div className="button-row">
        <button type="button" className={`button ${next === 'stage' && !state.review ? 'primary' : 'secondary'}`} disabled={stageReason !== null}
          onClick={() => void controller.prepare('stage')}>Review staging</button>
        <button type="button" className="button secondary" disabled={unstageReason !== null}
          onClick={() => void controller.prepare('unstage')}>Review unstaging</button>
        <button type="button" className="text-button" disabled={!state.selected.length} onClick={() => controller.clearSelection()}>Clear selection</button>
      </div>
      {state.selected.length > 0 && <p className="save-note">{state.selected.length} selected. {selectReason && GIT_ISSUE_HELP[selectReason]}</p>}
      <details className="github-workflow"><summary>Inspect selected differences</summary>
        <div className="button-row">
          <button type="button" className="button secondary" disabled={selectReason !== null} onClick={() => void controller.preview(false)}>Working changes</button>
          <button type="button" className="button secondary" disabled={selectReason !== null} onClick={() => void controller.preview(true)}>Staged changes</button>
        </div>
        {state.diff && <DiffPreview diff={state.diff} />}
        <p className="save-note">Only bounded text is displayed. Known sensitive content is withheld; this is not a guarantee that a file contains no secrets.</p>
      </details>
    </>}
    <form onSubmit={(event) => { event.preventDefault(); void controller.prepare('commit'); }}>
      <h3>Create a local commit</h3>
      <label htmlFor={messageId}>Commit message</label>
      <textarea id={messageId} rows={3} maxLength={4096} value={state.draft.message} placeholder="Describe what changed"
        onChange={(event) => controller.editDraft('message', event.target.value)} />
      <div><h4>Commit author · required</h4>
        <div className="form-grid">
          <div><label htmlFor={authorNameId}>Author name</label><input id={authorNameId} value={state.draft.authorName} maxLength={128}
            autoComplete="off" onChange={(event) => controller.editDraft('authorName', event.target.value)} /></div>
          <div><label htmlFor={authorEmailId}>Author email</label><input id={authorEmailId} type="email" value={state.draft.authorEmail} maxLength={254}
            autoComplete="off" onChange={(event) => controller.editDraft('authorEmail', event.target.value)} /></div>
        </div>
        <p className="save-note">Used for this commit only. MRK does not change your Git account settings.</p>
      </div>
      <p className="save-note">Commit messages and author details stay in this project’s local draft. Refreshing files or switching views does not replace them.</p>
      <button type="submit" className={`button ${next === 'commit' && !state.review ? 'primary' : 'secondary'}`} disabled={commitReason !== null}>Review commit</button>
      {commitReason && !state.review && <p className="save-note">{GIT_ISSUE_HELP[commitReason]}</p>}
    </form>
    {state.review && <Review key={state.review.plan.planId} review={state.review} controller={controller} />}
    {observation && <details><summary>Repository details</summary><p>Observed commit: <code>{observation.head ?? 'none yet'}</code>.</p>
      <p>Observation revision: <code>{observation.revision}</code>.</p>
      <p>Remote names: {observation.remotes.length ? observation.remotes.map((name) => <code key={name}><bdi>{name}</bdi>{' '}</code>) : 'none observed'}.</p>
      <p className="save-note">Remote URLs, tokens and raw Git errors are not displayed. Git is the source of truth; a saved observation is not permission to overwrite later edits.</p>
    </details>}
  </section>;
}
