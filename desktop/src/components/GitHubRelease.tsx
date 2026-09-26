import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubReleaseController } from '../githubReleaseController.ts';
import type { GitHubReleasePlatform, GitHubReleaseStage, GitHubReleaseView } from '../githubReleaseTypes.ts';
import { GITHUB_RELEASE_REASON_HELP } from '../githubReleaseProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const HELP: Record<'stage' | 'branch' | 'platform' | 'access' | 'original' | 'run' | 'recovery' | 'consent' | 'pending', HelpContent> = {
  stage: { label: 'Release step', requiredness: 'required', requiredWhen: 'For every workflow review.',
    what: 'The existing protected release workflow to request for one platform.',
    why: 'A candidate builds once; later steps reuse its authenticated release evidence rather than rebuilding a different artifact.',
    where: 'Start with an internal candidate. Choose external testing or production preparation only after the previous protected workflow produced the required evidence.',
    format: 'Internal candidate, external testing, or production submission. Nothing is selected automatically.',
    failure: 'Missing original evidence, signing inputs, environment approvals or Store prerequisites cause the protected core to stop. GitHub success alone is not evidence validation.' },
  branch: { label: 'Dispatch branch', requiredness: 'required', requiredWhen: 'Before Prepare.',
    what: 'The remote application branch containing the current reviewed workflow and configuration. Local unsaved changes are not uploaded.',
    why: 'Prepare checks its exact immutable source and regular-file Git tree entries. The committed candidate/production branch setting must match.',
    where: 'Your repository’s GitHub Code branch selector and saved Mobile Release Kit source settings.',
    format: 'For example main or release/next; not a URL, tag, commit hash or refs/heads/ prefix.',
    failure: 'A moved branch, unsupported caller, symlink/submodule in selected files, truncated or over-bound source tree is refused. GitHub dispatch uses a mutable branch: trust and protect its authorized workflow writers.' },
  platform: { label: 'Release platform', requiredness: 'required', requiredWhen: 'For each separate release review.',
    what: 'The Android or iOS release lane configured by this project.', why: 'Separate requests keep platform effects and partial success clear.',
    where: 'Choose a platform enabled in the committed project settings.', format: 'Android or iOS. iOS build work runs on macOS in the protected workflow.',
    failure: 'A disabled platform or missing platform inputs is refused; another platform is never selected as a fallback.' },
  access: { label: 'GitHub release access', requiredness: 'conditional', requiredWhen: 'For remote Prepare, Dispatch, Track and Reconcile.',
    what: 'The original session-only token from GitHub connection. This panel never asks for a second credential.',
    why: 'Prepare reads committed source; Dispatch additionally needs Actions write. Store credentials remain in the protected workflow environment, not in request fields.',
    where: 'GitHub Settings → Developer settings → Personal access tokens → Fine-grained tokens; select only this application repository.',
    format: 'Contents: read, Actions: write and GitHub’s required Metadata: read; organization approval or SSO may also apply. Enter the token only in GitHub connection.',
    failure: 'A displayed repository role does not prove token grants or environment access. The app never adds permissions or renews the original session automatically.' },
  original: { label: 'Original release source and version', requiredness: 'conditional', requiredWhen: 'For promotion or recovery, not a fresh candidate.',
    what: 'The source commit, marketing version and build number declared by the original release evidence.',
    why: 'Current dispatch source can differ from the artifact’s original source. Confirmation must name the original version, not silently switch to today’s version file.',
    where: 'Read the retained original release/provenance documents produced by the protected workflow. The local evidence inspector is useful for reading but does not authenticate them.',
    format: 'A lowercase 40-character source commit; original version such as 1.2.3; original positive build number up to 2100000000.',
    failure: 'The version is checked through the exact confirmation. The declared source is retained review data, not an extra workflow source check. The core authenticates the actual selected evidence and stops on invalid provenance or predecessor relationships.' },
  run: { label: 'Evidence-producing workflow run', requiredness: 'conditional', requiredWhen: 'Candidate ID for external testing; candidate and external IDs for production, unless recovering the exact failed step.',
    what: 'The exact original GitHub run that produced the required authenticated release evidence.',
    why: 'The core resolves the original artifact and predecessor lifecycle state. “Latest run”, a rerun alias or a successful status is not a substitute.',
    where: 'The retained release evidence’s evidenceProducer run ID and that original run’s GitHub Actions page. Preserve its attempt and artifacts.',
    format: 'The positive decimal run ID only. No URL, job ID, attempt alias or comma-separated list.',
    failure: 'An unrelated, missing, changed or expired producer is refused by the core. Supplying an ID does not prove that evidence or Store state exists.' },
  recovery: { label: 'Recover this same release step', requiredness: 'optional', requiredWhen: 'Only after assessing an interrupted or partially successful protected workflow.',
    what: 'Request the existing core’s evidence-based recovery for the exact original step, instead of treating it as a new release.',
    why: 'A timeout or lost response can follow successful Store effects. The core must preserve original operation identity and completed progress.',
    where: 'Use the original failed workflow’s retained recovery evidence and its evidence-producing run ID.',
    format: 'Enable recovery, enter that original run ID, source and version. Optional predecessor IDs, if supplied, must also be the original producers.',
    failure: 'This is not permission to retry blindly or undo effects. Advanced Apple ambiguous-operation confirmation grants are not available in this UI; the existing core will refuse when they are required.' },
  consent: { label: 'One-use Store-impacting workflow confirmation', requiredness: 'required', requiredWhen: 'After a successful Prepare, before Dispatch.',
    what: 'Permission to submit one exact protected release workflow that can sign, upload, change testing state or submit for review.',
    why: 'These are real remote effects, unlike offline checks. The short-lived native review is consumed once even if the acknowledgement is lost.',
    where: 'Review current dispatch source, original declarations, effects, and required environment below; then type the exact displayed confirmation.',
    format: 'Type stage:platform:version:build exactly and select the explicit consent checkbox.',
    failure: 'Changed selection, expired/reused consent or wrong text is refused. No automatic resend follows uncertainty. The workflow still enforces provenance, approvals and Store safeguards.' },
  pending: { label: 'Original requests and recovery observations', requiredness: 'optional', requiredWhen: 'After dispatch or a lost acknowledgement.',
    what: 'Private local request records, separated from nonpublishing preflight records. They contain no session token or private Store responses.',
    why: 'Track reads a known original attempt; Reconcile matches one exact original request. Neither resends, reruns, cancels remotely or changes a Store.',
    where: 'Reconnect the same local project, GitHub account and repository, then load original requests.',
    format: 'Use the button on the existing record. Only original attempt 1 is observed; there is no “latest” or automatic polling.',
    failure: 'Missing, ambiguous, changed or over-bound observations remain unresolved. A green GitHub run is not authenticated release evidence or production readiness.' },
};
const EFFECTS: Record<GitHubReleaseStage, { title: string; android: string; ios: string }> = {
  candidate: { title: 'Internal candidate', android: 'Build, sign and validate once, then upload to the Google Play internal track.', ios: 'Archive, export, sign and validate once, then upload for internal TestFlight testing.' },
  'external-testing': { title: 'External testing', android: 'Promote the original candidate to the configured external testing track without rebuilding it.', ios: 'Reuse the original TestFlight build, configure the external group and submit Beta App Review where required.' },
  'production-submit': { title: 'Production submission', android: 'Prepare the original release as a Google Play production draft. This workflow does not serve that draft to production users.', ios: 'Prepare the original App Store version and submit App Review with manual release. This workflow does not authorize automatic public release.' },
};

export function GitHubRelease({ state, controller, onHelp, compact = false, onShow, onGitHub }: {
  state: GitHubReleaseView; controller: GitHubReleaseController; onHelp: (help: HelpContent) => void;
  compact?: boolean; onShow?: () => void; onGitHub?: () => void;
}) {
  const id = useId(), status = state.status, op = status?.operation, prepared = controller.currentPrepared();
  const reason = controller.startReason(), prepareReason = controller.prepareReason(), dispatchReason = controller.dispatchReason();
  const original = state.stage !== null && (state.stage !== 'candidate' || state.recovery);
  const effects = state.stage && state.platform ? EFFECTS[state.stage][state.platform] : null;
  if (compact && !state.pending && !state.uncertain && (!op || op.phase === 'settled')) return null;
  const controls = <div className="button-row">
    <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={16} />Read local Status</button>
    <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Stop this local action</button>
  </div>;
  const field = (name: 'candidateRunId' | 'externalRunId' | 'recoveryRunId' | 'originalSourceSha' | 'originalVersionName' | 'originalVersionBuild', label: string, required: boolean, help: HelpContent, placeholder: string) => <div>
    <div className="field-label-row"><label htmlFor={`${id}-${name}`}>{label}</label><Badge>{required ? 'Required' : 'Optional'}</Badge><HelpButton content={help} onHelp={onHelp} /></div>
    <input id={`${id}-${name}`} type="text" value={state[name]} maxLength={name.endsWith('RunId') ? 20 : name === 'originalSourceSha' ? 40 : name === 'originalVersionBuild' ? 10 : 64}
      inputMode={name.endsWith('RunId') || name === 'originalVersionBuild' ? 'numeric' : 'text'} autoComplete="off" autoCapitalize="none" spellCheck={false}
      placeholder={placeholder} onChange={(event) => controller.setInput(name, event.target.value)} />
  </div>;
  return <section className="card" aria-label="Protected release workflows">
    <SectionHeading title="Protected release workflows" description="Guided release requests through the existing core. Preview first; one explicit dispatch; original evidence and Store safeguards stay in the workflow."><Icon name="rocket" size={24} /></SectionHeading>
    {op && <p className="save-note" role="status"><Badge tone={op.phase === 'cleanup-unknown' ? 'warning' : 'info'}>{op.kind} · {op.phase}</Badge> Original action <code>{op.id}</code>. {op.kind === 'dispatch' && <>Submission: <strong>{op.effect}</strong>. </>}{op.reason !== 'none' && GITHUB_RELEASE_REASON_HELP[op.reason]}</p>}
    {state.uncertain && <p className="review-caution" role="alert">The original action is unacknowledged or cleanup is unconfirmed. Keep the original record and read local Status. Do not send a second dispatch to find out if the first succeeded.</p>}
    {state.error && <p className="review-caution" role="alert">{GITHUB_RELEASE_REASON_HELP[state.error]}</p>}
    {compact ? <>{controls}<button type="button" className="button small secondary" onClick={onShow}>Show release management</button></> : <>
      <div className="notice notice-warning"><Icon name="shield" size={18} /><div><strong>{status?.available ? 'Real Store effects require explicit consent' : 'Release execution is not available now'}</strong>
        <p>{reason ?? 'Prepare reads GitHub only. Dispatch is a separate Store-impacting request and can consume hosted runner minutes.'}</p>
        <p>Use a trusted protected branch. GitHub accepts a mutable branch, not an atomic commit lock; authorized writers can replace workflow code after review. No automatic public release or remote cancellation is offered here.</p>
        {onGitHub && <button type="button" className="button small secondary" onClick={onGitHub}>Open GitHub connection and workflow setup</button>}
      </div></div>
      <h3>1. Choose one release step</h3>
      <div className="field-label-row"><label htmlFor={`${id}-stage`}>Release step</label><Badge>Required</Badge><HelpButton content={HELP.stage} onHelp={onHelp} /></div>
      <select id={`${id}-stage`} value={state.stage ?? ''} onChange={(event) => controller.setStage(event.target.value === '' ? null : event.target.value as GitHubReleaseStage)}>
        <option value="">Choose a release step…</option><option value="candidate">Internal candidate · build once</option><option value="external-testing">External testing · reuse candidate</option><option value="production-submit">Production submission · draft / manual release</option>
      </select>
      <div className="field-label-row"><label htmlFor={`${id}-platform`}>Release platform</label><Badge>Required</Badge><HelpButton content={HELP.platform} onHelp={onHelp} /></div>
      <select id={`${id}-platform`} value={state.platform ?? ''} onChange={(event) => controller.setPlatform(event.target.value === '' ? null : event.target.value as GitHubReleasePlatform)}>
        <option value="">Choose one platform…</option><option value="android">Android · Google Play</option><option value="ios">iOS · TestFlight / App Store</option>
      </select>
      {effects && <p className="review-caution">Requested effects: {effects}</p>}
      <div className="field-label-row"><label htmlFor={`${id}-branch`}>Dispatch branch</label><Badge>Required</Badge><HelpButton content={HELP.branch} onHelp={onHelp} /></div>
      <input id={`${id}-branch`} type="text" value={state.branch} maxLength={200} autoComplete="off" autoCapitalize="none" spellCheck={false} placeholder="main or release/next" onChange={(event) => controller.setBranch(event.target.value)} />
      <p className="save-note">Find the branch in GitHub’s Code selector. Use the committed candidate branch for candidate/external testing, production branch for production submission. Local drafts are not sent.</p>
      <p className="save-note">Uses the original GitHub connection; Store secrets remain in the protected workflow environment.<HelpButton content={HELP.access} onHelp={onHelp} /></p>
      <div className="field-label-row"><input id={`${id}-recovery`} type="checkbox" checked={state.recovery} onChange={(event) => controller.setRecovery(event.target.checked)} /><label htmlFor={`${id}-recovery`}>Recover an assessed original attempt of this same step</label><Badge>Optional</Badge><HelpButton content={HELP.recovery} onHelp={onHelp} /></div>
      {state.recovery && <>{field('recoveryRunId', 'Original recovery evidence producer run ID', true, HELP.recovery, '123456789')}
        <p className="save-note">Use the original step’s retained recovery evidence. Recovery is not a fresh release or a blind retry. Advanced Apple ambiguous-operation grants remain unavailable here.</p></>}
      {state.stage && state.stage !== 'candidate' && <>{field('candidateRunId', 'Candidate evidence producer run ID', !state.recovery, HELP.run, '123456789')}
        {state.stage === 'production-submit' && field('externalRunId', 'External-testing evidence producer run ID', !state.recovery, HELP.run, '123456790')}
        <p className="save-note">Find exact producer IDs in the retained release documents, not “latest run”. Recovery can derive predecessors from its authenticated original evidence.</p></>}
      {original && <article className="github-environment"><div className="inline-heading"><h4>Original artifact declarations</h4><HelpButton content={HELP.original} onHelp={onHelp} /></div>
        {field('originalSourceSha', 'Original artifact source commit', true, HELP.original, '40 lowercase hexadecimal characters')}
        {field('originalVersionName', 'Original marketing version', true, HELP.original, '1.2.3')}
        {field('originalVersionBuild', 'Original build number', true, HELP.original, '42')}
        <p className="review-caution">These are declarations, not authenticated release evidence. The original version enters the exact confirmation; the declared source is retained for review, not sent as another workflow source check. The core authenticates actual producer relationships and provenance before Store effects.</p>
      </article>}
      <h3>2. Prepare a read-only review</h3>
      <p className="save-note">Checks the canonical caller, committed configuration, selected regular-file Git entries and version. Complete trees over 1,000 entries or 256 KiB and truncated trees are unsupported, not ready.</p>
      <div className="button-row"><button type="button" className="button primary" disabled={prepareReason !== null} onClick={() => controller.prepare()}>Prepare release review · read GitHub only</button></div>
      {prepareReason && <p className="save-note">{prepareReason}</p>}
      {prepared && <article className="github-environment" aria-label="Exact protected release review"><div className="inline-heading"><h3>3. Review effects and confirm once</h3><HelpButton content={HELP.consent} onHelp={onHelp} /></div>
        <p className="review-caution">{EFFECTS[prepared.target.selection.stage][prepared.target.platform]}</p>
        <dl className="github-facts">
          <div><dt>Repository / account</dt><dd>{prepared.target.repository} · repository {prepared.target.repositoryId} · account {prepared.target.accountId}</dd></div>
          <div><dt>Current dispatch branch / source commit</dt><dd><code>{prepared.expectedRef}</code><br /><code>{prepared.sourceSha}</code></dd></div>
          <div><dt>Current immutable source tree</dt><dd><code>{prepared.sourceTree}</code></dd></div>
          <div><dt>Current configuration SHA256</dt><dd><code>{prepared.configSha256}</code></dd></div>
          <div><dt>Current committed version (not necessarily original artifact version)</dt><dd>{prepared.currentVersion.name} · build {prepared.currentVersion.build}<br /><code>{prepared.versionSource}</code> · <code>{prepared.versionSha256}</code></dd></div>
          <div><dt>Current destination configuration hint</dt><dd>{prepared.destination.applicationId} · {prepared.destination.destination}<br />Not an authenticated original artifact destination or live Store-state observation.</dd></div>
          <div><dt>Canonical caller / SHA256</dt><dd><code>{prepared.workflowPath}</code><br /><code>{prepared.callerSha256}</code></dd></div>
          <div><dt>Publisher-bound toolkit commit</dt><dd><code>{prepared.target.toolingSha}</code></dd></div>
          <div><dt>Declared original artifact</dt><dd>{prepared.target.selection.originalVersion ? <>{prepared.target.selection.originalVersion.name} · build {prepared.target.selection.originalVersion.build}<br /><code>{prepared.target.selection.originalSourceSha}</code></> : 'Fresh candidate: uses the current committed version.'}</dd></div>
          <div><dt>Declared original producer IDs</dt><dd>Candidate: {prepared.target.selection.candidateRunId ?? 'none'} · external: {prepared.target.selection.externalRunId ?? 'none'} · recovery: {prepared.target.selection.recoveryRunId ?? 'none'}</dd></div>
          <div><dt>Exact request title</dt><dd><code>{prepared.displayTitle}</code></dd></div>
          <div><dt>Consent ceiling · display only</dt><dd><time dateTime={status?.consentExpiresAt ?? undefined}>{status?.consentExpiresAt}</time></dd></div>
        </dl>
        <p className="save-note">Required GitHub environment: <strong>{prepared.environment}</strong>. This checklist describes the current configuration only; it does not prove effective secrets, permissions, approval protection or Store access. Reused artifact destination and original state are validated by the core, not by this review.</p>
        <ul>{prepared.checklist.map((row) => <li key={row.name}><code>{row.name}</code> · {row.kind}: {row.reason}</li>)}</ul>
        <p className="save-note">Review credential guidance and environment setup on the GitHub / Credentials screens before approving. No secret values are read or displayed here.</p>
        <div className="field-label-row"><label htmlFor={`${id}-confirmation`}>Type this exact release confirmation</label><Badge>Required</Badge><HelpButton content={HELP.consent} onHelp={onHelp} /></div>
        <p><code>{prepared.confirmation}</code></p>
        <input id={`${id}-confirmation`} type="text" value={state.confirmation} maxLength={160} autoComplete="off" autoCapitalize="none" spellCheck={false} onChange={(event) => controller.setConfirmation(event.target.value)} />
        <div className="field-label-row"><input id={`${id}-consent`} type="checkbox" checked={state.confirmed} onChange={(event) => controller.setConfirmed(event.target.checked)} /><label htmlFor={`${id}-consent`}>I reviewed these real Store effects, original declarations and configured environment, and trust the protected branch’s workflow writers. Submit this request once.</label></div>
        <div className="button-row"><button type="button" className="button primary" disabled={dispatchReason !== null} onClick={() => controller.dispatch()}>Dispatch this protected release request once</button></div>
        {dispatchReason && <p className="save-note">{dispatchReason}</p>}
      </article>}
      {op?.kind === 'dispatch' && op.effect === 'accepted' && <p className="save-note">GitHub returned an exact run ID. This is submission acknowledgement only, not completed Store effects, release evidence or a passing run.</p>}
      {op?.kind === 'dispatch' && op.effect === 'potentially-applied' && <p className="review-caution">This request may have applied. Reconcile the original record; do not repeat Dispatch as a retry.</p>}
      <div className="inline-heading"><h3>4. Original requests and observations</h3><HelpButton content={HELP.pending} onHelp={onHelp} /></div>
      <button type="button" className="button secondary" disabled={reason !== null} onClick={() => controller.loadPending()}>Load this project’s release requests · local only</button>
      {status?.pending.length === 0 && <p className="save-note">No record is currently displayed. This does not prove that no remote release or Store effect exists.</p>}
      {status?.pending.map((record) => <article className="github-environment" key={record.prepared.target.marker}>
        <h4>{EFFECTS[record.prepared.target.selection.stage].title} · {record.prepared.target.platform}</h4>
        <p className="save-note">{record.prepared.target.repository} · {record.prepared.target.branch}<br />Current dispatch source <code>{record.prepared.sourceSha}</code><br />Request <code>{record.prepared.displayTitle}</code><br />Run {record.runId ?? 'not yet resolved'} · original attempt 1.</p>
        <button type="button" className="button small secondary" disabled={controller.recordReason(record) !== null} onClick={() => controller.observe(record)}>{record.runId === null ? 'Reconcile exact request · read GitHub' : 'Track original run · read GitHub'}</button>
        {controller.recordReason(record) && <p className="save-note">{controller.recordReason(record)}</p>}
      </article>)}
      {status?.run && <article className="github-environment" aria-label="Original protected workflow observation"><h4>Run {status.run.id} · attempt 1</h4><Badge tone={status.run.conclusion === 'failure' ? 'danger' : 'info'}>{status.run.status} · {status.run.conclusion ?? 'not concluded'}</Badge>
        <p className="review-caution">This is a GitHub workflow observation, not authenticated artifact evidence, complete release history or production readiness. Reports and private Store data are not downloaded by this view.</p>
        <p className="save-note">Observed <time dateTime={status.run.observedAt}>{status.run.observedAt}</time>.</p>
        <ul>{status.run.jobs.map((job) => <li key={job.id}>{job.kind}: {job.status} · {job.conclusion ?? 'not concluded'}</li>)}</ul>
        <p className="save-note">A reused candidate can legitimately skip online/build jobs. A missing original resolve/Store result is not a pass. Preserve the actual workflow evidence for core verification.</p><code>{status.run.url}</code>
      </article>}
      {controls}<p className="save-note">Status reads local native state. Track/Reconcile make one bounded read sequence only when clicked. Stop requests local cleanup; it cannot cancel, roll back or undo a remote workflow or Store effect.</p>
    </>}
  </section>;
}
