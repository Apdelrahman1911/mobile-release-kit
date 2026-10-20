import { useId } from 'react';
import { SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { ACTIVITY_HELP, activityLink } from '../githubActivityProtocol.ts';
import type { ActivitySection, ActivityJob, ActivityRun } from '../githubActivityProtocol.ts';
import type { GitHubActivityController, GitHubActivityView } from '../githubActivityController.ts';

function Coverage({ value, empty }: { value: ActivitySection<unknown>; empty: string }) {
  if (value.state === 'unavailable') return <p className="review-caution">{ACTIVITY_HELP[value.reason]}</p>;
  return <p className="save-note">{value.rows.length ? `Showing ${value.rows.length}${value.total === null ? '' : ` of ${value.total} reported`}.` : empty}
    {value.coverage === 'windowed' ? ' This is one bounded page, not the full history. Open GitHub for more.' : ' A snapshot, not a live or release-eligibility check.'}</p>;
}
function ResultText({ row }: { row: ActivityJob }) {
  return <span>{row.status.replaceAll('_', ' ')}{row.conclusion ? ` · ${row.conclusion.replaceAll('_', ' ')}` : ' · no conclusion reported'}</span>;
}
export function GitHubActivity({ controller, state, branchSuggestion = null, compact = false, onShow }: {
  controller: GitHubActivityController; state: GitHubActivityView; branchSuggestion?: string | null; compact?: boolean; onShow?: () => void;
}) {
  const id = useId(), status = state.status, op = status?.operation, busy = controller.ownerReason();
  const attention = state.uncertain || state.error !== null || op?.phase === 'cleanup-unknown';
  if (compact && !busy && !attention) return null;
  const result = controller.currentResult(), data = result?.data, repository = result?.target.repository ?? '';
  const reason = controller.readReason();
  const runLink = (r: ActivityRun) => `${activityLink(repository, 'run', r.id)!}/attempts/${r.attempt}`;
  const originalRepository = state.originalRepository ?? op?.target.repository;
  return <section className="card" aria-label="GitHub pull requests and workflow results">
    <SectionHeading title="Pull requests & Actions" description="Read what is happening on GitHub. Nothing is approved, created, rerun or published here.">
      <Icon name="github" size={24} />
    </SectionHeading>
    {originalRepository && (busy || attention) && <p>Original repository: <strong>{originalRepository}</strong></p>}
    {(state.pending || op && op.phase !== 'settled') && <p role="status">{op?.phase === 'cleanup-unknown' ? 'Cleanup needs attention.' : op?.phase === 'stopping' ? 'Stopping the original read…' : 'Reading the original GitHub selection…'}</p>}
    {state.uncertain && <p className="review-caution" role="alert">The original read is unconfirmed. Keep the app open and preserve its files. Checking status does not repeat the remote read or clear unknown cleanup.</p>}
    {state.error && <p className="review-caution" role="status">{ACTIVITY_HELP[state.error]}</p>}
    {op && op.reason !== 'none' && op.reason !== state.error && <p className="review-caution">{ACTIVITY_HELP[op.reason]}</p>}
    <div className="button-row">
      <button type="button" className="button small secondary" disabled={!controller.canCheck()} onClick={() => controller.checkStatus()}>Check task status</button>
      {(state.pending || op && op.phase !== 'settled') && <button type="button" className="button small secondary" disabled={!controller.canCancel() || state.cancelling} onClick={() => controller.cancel()}>Stop original read</button>}
      {compact && onShow && <button type="button" className="button small" onClick={onShow}>Show GitHub activity</button>}
    </div>
    {!compact && <>
      <label htmlFor={`${id}-branch`}>Branch (optional)</label>
      <input id={`${id}-branch`} value={state.branchDraft} maxLength={200} disabled={!!busy} placeholder="All branches" onChange={e => controller.setBranch(e.target.value)} />
      <p className="save-note">Leave blank for recent activity across the repository. Enter a branch name such as main, not a URL. A branch filter shows this repository’s own branch, not a fork with the same name.</p>
      {branchSuggestion && <button type="button" className="button small secondary" disabled={!!busy} onClick={() => controller.setBranch(branchSuggestion)}>Use last-read local branch: {branchSuggestion}</button>}
      {branchSuggestion && <p className="save-note">This suggestion is from your last local Git read, not a new GitHub check.</p>}
      {reason && <p className="save-note" role="status">{reason}</p>}
      <button type="button" className="button" disabled={!!reason} onClick={() => controller.read()}>Read recent activity</button>
      {status?.result && !result && !state.pending && <p className="save-note">The previous read is no longer current for this selection. Read again explicitly; old results cannot choose a new task.</p>}
      {result && <p className="save-note">{repository} · Last read {result.observedAt}. These sequential observations are not an atomic snapshot or permission to release.</p>}
      {result && data?.kind === 'overview' && <>
        <h4>Open pull requests</h4><Coverage value={data.pullRequests} empty="No open pull requests were returned on this page." />
        {data.pullRequests.rows.map(p => <div className="review-item" key={p.id}>
          <p><a href={activityLink(repository, 'pull', p.number)!} target="_blank" rel="noopener noreferrer">#{p.number} {p.title}</a> {p.draft ? '· Draft' : ''}</p>
          <p className="save-note">{p.headRepository ?? 'Head repository not reported'} · {p.headBranch} → {p.baseBranch}</p>
          <button type="button" className="button small secondary" disabled={!!controller.readReason({kind:'pull-request',number:p.number})} onClick={() => controller.readSelection(result,{kind:'pull-request',number:p.number})}>Read changes, reviews & checks</button>
        </div>)}
        <h4>Recent workflow runs</h4><Coverage value={data.workflowRuns} empty="No workflow runs were returned. This is not a successful build." />
        {data.workflowRuns.rows.map(r => <div className="review-item" key={r.id}>
          <p><a href={runLink(r)} target="_blank" rel="noopener noreferrer">{r.name}</a> · <ResultText row={r} /></p>
          <p className="save-note">{r.headRepository ?? 'Head repository not reported'} · {r.headBranch ?? 'No branch reported'} · Attempt {r.attempt}</p>
          <button type="button" className="button small secondary" disabled={!!controller.readReason({kind:'workflow-run',runId:r.id,attempt:r.attempt})} onClick={() => controller.readSelection(result,{kind:'workflow-run',runId:r.id,attempt:r.attempt})}>Read this attempt’s jobs</button>
        </div>)}
      </>}
      {data?.kind === 'pull-request' && <>
        <h4>#{data.pullRequest.number} {data.pullRequest.title}</h4>
        <p>{data.pullRequest.headRepository ?? 'Head repository not reported'} · {data.pullRequest.headBranch} → {data.pullRequest.baseBranch} · {data.pullRequest.state}{data.pullRequest.draft ? ' · Draft' : ''}</p>
        <p><a href={`${activityLink(repository,'pull',data.pullRequest.number)!}/files`} target="_blank" rel="noopener noreferrer">Open the full diff on GitHub</a></p>
        <h5>Changed files</h5><Coverage value={data.changedFiles} empty="No changed files were reported." />
        <ul>{data.changedFiles.rows.map(f => <li key={f.path}>{f.path} · {f.change} · +{f.additions} / −{f.deletions}</li>)}</ul>
        <h5>Review records</h5><p className="save-note">First chronological page, up to 30 records. A person’s later review may differ. These are not an overall approval or a branch-protection decision.</p>
        <Coverage value={data.reviews} empty="No review records were returned on this page." />
        <ul>{data.reviews.rows.map(r => <li key={r.id}>{r.reviewer ?? 'Deleted account'} · {r.state.toLowerCase().replaceAll('_',' ')}{r.commitSha !== data.pullRequest.headSha ? ' · not on this head commit' : ' · on this head commit'}</li>)}</ul>
        <h5>Checks on this head commit</h5><p className="review-caution">No checks, neutral or skipped results are not a pass. These lists do not prove that all required checks, merge rules or release requirements are met.</p>
        <Coverage value={data.commitStatuses} empty="No commit statuses were reported." />
        <ul>{data.commitStatuses.rows.map(s => <li key={s.id}>{s.name} · {s.state}</li>)}</ul>
        <Coverage value={data.checkRuns} empty="No check runs were reported." />
        <ul>{data.checkRuns.rows.map(j => <li key={j.id}>{j.name} · <ResultText row={j}/></li>)}</ul>
      </>}
      {data?.kind === 'workflow-run' && <>
        <h4>{data.run.name} · Attempt {data.run.attempt}</h4><p><ResultText row={data.run}/></p>
        <p className="save-note">{data.run.headRepository ?? 'Head repository not reported'} · {data.run.headBranch ?? 'No branch reported'}</p>
        <p><a href={runLink(data.run)} target="_blank" rel="noopener noreferrer">Open run details on GitHub</a></p>
        <Coverage value={data.jobs} empty="No jobs were returned. This is not a successful build." />
        <ul>{data.jobs.rows.map(j => <li key={j.id}>{j.name} · <ResultText row={j}/></li>)}</ul>
        <p className="save-note">This reads the selected attempt, not necessarily the latest attempt. Logs and artifact contents are not downloaded.</p>
      </>}
      <ProgressiveDisclosure title="Help: access, limits and separate write actions">
        <p>The connected account needs read access to this repository’s Pull requests, Actions, Checks and commit statuses. Organization SSO and token restrictions still apply. Missing access is not an empty or successful result.</p>
        <p>Each explicit read uses one bounded page per section. GitHub can change between reads; the selected head or attempt is checked again at the end. Provider links, raw bodies, patches, logs and artifact contents are not shown here.</p>
        <p>Creating a pull request and rerunning failed jobs are separate planned actions with their own review and authorization. Reading this view does not enable them. Existing toolkit publication and release tasks remain separate below.</p>
      </ProgressiveDisclosure>
    </>}
  </section>;
}
