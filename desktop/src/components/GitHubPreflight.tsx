import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubPreflightController } from '../githubPreflightController.ts';
import type { GitHubPreflightPlatform, GitHubPreflightView } from '../githubPreflightTypes.ts';
import { GITHUB_PREFLIGHT_REASON_HELP } from '../githubPreflightProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const HELP: Record<'branch' | 'platform' | 'access' | 'consent' | 'pending', HelpContent> = {
  branch: { label: 'Application branch', requiredness: 'required', requiredWhen: 'Before preparing a GitHub preflight.',
    what: 'The branch in your selected application repository whose saved source you want GitHub to check.',
    why: 'The app reviews its exact commit and supported workflow before asking for one dispatch. Local unsaved files are not uploaded.',
    where: 'In the branch selector on your repository’s GitHub Code page. Use a branch whose workflow changes are reviewed and protected.',
    format: 'A branch name such as main or release/next. Not a URL, tag, commit hash or refs/heads/ prefix.',
    failure: 'Missing branches or changed source are refused. GitHub dispatch is not an atomic commit lock: an authorized writer can replace the branch workflow after review.' },
  platform: { label: 'Platforms to check', requiredness: 'required', requiredWhen: 'For each new preflight review.',
    what: 'Which platform jobs the reviewed workflow should request.',
    why: 'Android uses a Linux GitHub-hosted runner; iOS uses a macOS runner. Both requests both jobs and may use more hosted minutes.',
    where: 'Choose the platforms that are configured in your application’s saved Mobile Release Kit settings.',
    format: 'Android, iOS or both. No platform is chosen automatically.',
    failure: 'A missing tool, project configuration or private dependency can fail or defer checks. A successful workflow is not release readiness.' },
  access: { label: 'GitHub preflight access', requiredness: 'conditional', requiredWhen: 'When explicitly dispatching the reviewed nonpublishing workflow.',
    what: 'The original session-only token from the GitHub connection above. This panel never asks you to enter another credential.',
    why: 'Prepare reads the selected repository; Dispatch additionally needs Actions write. No Store or signing secrets are sent.',
    where: 'GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens. Select only the application repository; organization approval or SSO may be required.',
    format: 'Selected-repository Contents: read and Actions: write, plus GitHub’s required Metadata: read. Enter the token only in the connection’s private token field, never in branch or workflow inputs.',
    failure: 'Insufficient access is refused; reported repository roles do not prove token grants. The app does not increase privileges, store the token on disk or extend its original session lifetime.' },
  consent: { label: 'One-use workflow confirmation', requiredness: 'required', requiredWhen: 'After Prepare succeeds and before Dispatch.',
    what: 'Permission for one reviewed nonpublishing workflow request, not for a release or general GitHub access.',
    why: 'It may run trusted project build code, download dependencies, consume runner minutes and upload diagnostic reports. The native short-lived review can be used only once.',
    where: 'Review the repository, branch, source commit, toolkit commit and workflow below, then select the confirmation checkbox.',
    format: 'An explicit confirmation of this exact review. Changing selection, refreshing the connection, expiry or use invalidates it.',
    failure: 'The app refuses stale reviews. GitHub accepts a mutable branch rather than an atomic commit condition; trust its authorized writers and protection. The reviewed canonical workflow does not sign or publish, but a writer could replace it.' },
  pending: { label: 'Pending requests and recovery', requiredness: 'optional', requiredWhen: 'After dispatch, response loss or an interrupted application session.',
    what: 'A small private local record of the exact request marker and any accepted run ID. It contains no token or Store data.',
    why: 'A missing response does not prove that GitHub did nothing. Track reads a known attempt; Reconcile looks for one exact matching original run, never the latest run.',
    where: 'Select Load this project’s pending requests after reconnecting the same local project, GitHub account and repository.',
    format: 'Use the button beside the original record. No run ID, API URL or retry command needs to be entered.',
    failure: 'Ambiguous, missing, changed or over-limit observations remain unresolved. Never repeat Dispatch as a retry. Stopping a local request does not cancel a remote workflow; remote cancel/rerun is not offered here.' },
};

export function GitHubPreflight({ state, controller, onHelp, compact = false, onShow }: {
  state: GitHubPreflightView; controller: GitHubPreflightController; onHelp: (help: HelpContent) => void;
  compact?: boolean; onShow?: () => void;
}) {
  const branchId = useId(), platformId = useId(), consentId = useId(), reasonId = useId();
  const status = state.status, op = status?.operation, prepared = controller.currentPrepared();
  const reason = controller.startReason(), prepareReason = controller.prepareReason(), dispatchReason = controller.dispatchReason();
  if (compact && !state.pending && !state.uncertain && (!op || op.phase === 'settled')) return null;
  const controls = <div className="button-row">
    <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.observing}
      onClick={() => void controller.checkStatus()}><Icon name="refresh" size={16} />Read local Status</button>
    <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Stop this local action</button>
  </div>;
  return <section className="card" aria-label="GitHub nonpublishing preflight">
    <SectionHeading title="GitHub nonpublishing preflight" description="One reviewed workflow. No automatic dispatch, polling, rerun or Store operation."><Icon name="github" size={24} /></SectionHeading>
    {op && <p className="save-note" role="status"><Badge tone={op.phase === 'cleanup-unknown' ? 'warning' : 'info'}>{op.kind} · {op.phase}</Badge>
      {' '}Original action <code>{op.id}</code>. {op.kind === 'dispatch' && <>Submission: <strong>{op.effect}</strong>. </>}
      {op.reason !== 'none' && GITHUB_PREFLIGHT_REASON_HELP[op.reason]}</p>}
    {state.uncertain && <p className="review-caution" role="alert">The original action is unacknowledged or its cleanup is unconfirmed. Keep its pending record and read local Status. Do not send a second dispatch to find out whether the first succeeded.</p>}
    {state.error && <p className="review-caution" role="alert">{GITHUB_PREFLIGHT_REASON_HELP[state.error]}</p>}
    {compact ? <>{controls}<button type="button" className="button small secondary" onClick={onShow}>Show GitHub preflight</button></> : <>
      <div className="notice notice-info"><Icon name="shield" size={18} /><div>
        <strong>{status?.available ? 'Explicit review and consent required' : 'Preflight execution is not available now'}</strong>
        <p id={reasonId}>{reason ?? 'Prepare only reads GitHub. Dispatch is a separate, explicit one-use action.'}</p>
        <p>The reviewed canonical workflow does not sign, upload to a Store or publish a release. It may build project code and upload diagnostic reports. Use a trusted protected branch: GitHub dispatch has no atomic commit lock, and authorized writers can replace the workflow after review.</p>
      </div></div>
      <div className="field-label-row"><label htmlFor={branchId}>Application branch</label><Badge>Required</Badge><HelpButton content={HELP.branch} onHelp={onHelp} /></div>
      <input id={branchId} type="text" value={state.branch} maxLength={200} autoComplete="off" autoCapitalize="none" spellCheck={false}
        placeholder="main or release/next" onChange={(event) => controller.setBranch(event.target.value)} aria-describedby={`${branchId}-help`} />
      <p id={`${branchId}-help`} className="save-note">Choose from the repository’s GitHub branch selector. Local drafts are not uploaded; only the reviewed remote commit is requested.</p>
      <div className="field-label-row"><label htmlFor={platformId}>Platforms to check</label><Badge>Required</Badge><HelpButton content={HELP.platform} onHelp={onHelp} /></div>
      <select id={platformId} value={state.platform ?? ''} onChange={(event) => controller.setPlatform(event.target.value === '' ? null : event.target.value as GitHubPreflightPlatform)}>
        <option value="">Choose platforms…</option><option value="android">Android · Linux runner</option><option value="ios">iOS · macOS runner</option><option value="both">Both platforms</option>
      </select>
      <p className="save-note">Uses the original connection’s account and selected repository. Contents read and Actions write access may be required.<HelpButton content={HELP.access} onHelp={onHelp} /></p>
      <div className="button-row"><button type="button" className="button primary" disabled={prepareReason !== null}
        onClick={() => controller.prepare()} aria-describedby={reasonId}>Prepare workflow review · read only</button></div>
      {prepareReason && <p className="save-note">{prepareReason}</p>}
      {prepared && <article className="github-environment" aria-label="Exact workflow review">
        <div className="inline-heading"><h3>Review this one workflow request</h3><HelpButton content={HELP.consent} onHelp={onHelp} /></div>
        <dl className="github-facts">
          <div><dt>Repository / immutable ID</dt><dd>{prepared.target.repository} · <code>{prepared.target.repositoryId}</code></dd></div>
          <div><dt>Account ID</dt><dd><code>{prepared.target.accountId}</code></dd></div>
          <div><dt>Branch / platform</dt><dd><code>{prepared.expectedRef}</code> · {prepared.target.platform}</dd></div>
          <div><dt>Exact source commit</dt><dd><code>{prepared.sourceSha}</code></dd></div>
          <div><dt>Publisher-bound toolkit commit</dt><dd><code>{prepared.target.toolingSha}</code></dd></div>
          <div><dt>Canonical caller / SHA256</dt><dd><code>{prepared.workflowPath}</code> · <code>{prepared.callerSha256}</code></dd></div>
          <div><dt>Exact request title</dt><dd><code>{prepared.displayTitle}</code></dd></div>
          <div><dt>Native consent ceiling · display only</dt><dd><time dateTime={status?.consentExpiresAt ?? undefined}>{status?.consentExpiresAt}</time></dd></div>
        </dl>
        <p>{prepared.confirmation}</p>
        <div className="field-label-row"><input id={consentId} type="checkbox" checked={state.confirmed} onChange={(event) => controller.setConfirmed(event.target.checked)} />
          <label htmlFor={consentId}>I reviewed this exact request and trust the selected branch’s authorized workflow writers.</label></div>
        <div className="button-row"><button type="button" className="button primary" disabled={dispatchReason !== null}
          onClick={() => controller.dispatch()}>Dispatch this preflight once</button></div>
        {dispatchReason && <p className="save-note">{dispatchReason}</p>}
      </article>}
      {op?.kind === 'dispatch' && op.effect === 'accepted' && <p className="save-note">GitHub returned an exact run ID. This is submission acknowledgement only, not an observed run or passing checks. Use Track below.</p>}
      {op?.kind === 'dispatch' && op.effect === 'potentially-applied' && <p className="review-caution">GitHub may have accepted this request. Reconcile its original marker below; no automatic retry is available.</p>}
      <div className="inline-heading"><h3>Pending requests and run observations</h3><HelpButton content={HELP.pending} onHelp={onHelp} /></div>
      <div className="button-row"><button type="button" className="button secondary" disabled={reason !== null}
        onClick={() => controller.loadPending()}>Load this project’s pending requests · local only</button></div>
      {status?.pending.length === 0 && <p className="save-note">No pending record is currently displayed. This does not prove that no remote workflow exists.</p>}
      {status?.pending.map((record) => <article className="github-environment" key={record.prepared.target.marker}>
        <h4>{record.prepared.target.repository} · {record.prepared.target.branch} · {record.prepared.target.platform}</h4>
        <p className="save-note">Source <code>{record.prepared.sourceSha}</code><br />Request <code>{record.prepared.displayTitle}</code><br />
          Run {record.runId ?? 'not yet resolved'} · original attempt 1 only.</p>
        <button type="button" className="button small secondary" disabled={controller.recordReason(record) !== null}
          onClick={() => controller.observe(record)}>{record.runId === null ? 'Reconcile exact request · read GitHub' : 'Track this run · read GitHub'}</button>
        {controller.recordReason(record) && <p className="save-note">{controller.recordReason(record)}</p>}
      </article>)}
      {status?.run && <article className="github-environment" aria-label="Original workflow run observation">
        <h4>Run {status.run.id} · attempt 1</h4><p><Badge tone={status.run.conclusion === 'failure' ? 'danger' : 'info'}>{status.run.status} · {status.run.conclusion ?? 'not concluded'}</Badge></p>
        <p className="save-note">Observed <time dateTime={status.run.observedAt}>{status.run.observedAt}</time>. This is a GitHub workflow observation, not signed artifact evidence or release readiness.</p>
        <ul>{status.run.jobs.map((job) => <li key={job.id}>{job.kind}: {job.status} · {job.conclusion ?? 'not concluded'} · job {job.id}</li>)}</ul>
        <p className="save-note">{status.run.jobs.length === 0 ? 'No jobs were observed yet. ' : ''}Missing, skipped or deferred checks are not passes. Reports are not downloaded or treated as attestations.</p>
        <p className="save-note">GitHub run URL · selectable text only<br /><code>{status.run.url}</code></p>
      </article>}
      {controls}<p className="save-note">Status reads local native state only. Track and Reconcile each perform one bounded GitHub read sequence on your click. Stop requests original local cleanup; it does not cancel a workflow already running on GitHub.</p>
    </>}
  </section>;
}
