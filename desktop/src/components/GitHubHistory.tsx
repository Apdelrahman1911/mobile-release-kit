import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubHistoryController } from '../githubHistoryController.ts';
import type { GitHubHistoryAuthority, GitHubHistoryPlatform, GitHubHistoryStage, GitHubHistoryView } from '../githubHistoryTypes.ts';
import { GITHUB_HISTORY_REASON_HELP } from '../githubHistoryProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const HELP: Record<'run' | 'attempt' | 'stage' | 'platform' | 'read' | 'recovery', HelpContent> = {
  run: { label: 'Exact GitHub run ID', requiredness: 'required', requiredWhen: 'Before starting an authenticated History read.',
    what: 'The numeric Actions run identity in the currently connected application repository.',
    why: 'The app verifies retained evidence from this exact run, not the latest release, a title match or an unrelated repository.',
    where: 'Open the selected repository’s Actions run page. In github.com/owner/repository/actions/runs/123456, copy only 123456.',
    format: 'A positive decimal integer, up to 20 digits. Do not paste a URL, name, commit or credential.',
    failure: 'Missing or inaccessible runs cannot establish absence. A mismatching run is not silently replaced.' },
  attempt: { label: 'Exact run attempt', requiredness: 'required', requiredWhen: 'For every History read, including a rerun.',
    what: 'Which execution attempt of that run produced the evidence you want to inspect.',
    why: 'A rerun can have a different producer and evidence; run ID alone does not select it.',
    where: 'Use the attempt selector on the GitHub Actions run page. The first execution is attempt 1; reruns increase it.',
    format: 'An integer from 1 through 100. Nothing defaults to the latest or first attempt.',
    failure: 'Wrong, missing or unfinished attempts are refused or unavailable. They are not promoted to a passing result.' },
  stage: { label: 'Release stage to observe', requiredness: 'required', requiredWhen: 'Before starting the read.',
    what: 'The canonical candidate, external-testing or production-submit evidence family.',
    why: 'Each stage has its own expected producer and artifact. Selecting a stage does not perform that Store operation.',
    where: 'Use the stage of the completed canonical workflow whose evidence you need.',
    format: 'Candidate, External testing or Production submit. Select exactly one.',
    failure: 'Evidence for a different stage is not accepted. History never dispatches, retries or promotes a release.' },
  platform: { label: 'Evidence platform', requiredness: 'required', requiredWhen: 'Before starting the read.',
    what: 'Android or iOS evidence within the selected run and stage.',
    why: 'Platform identity must agree with the saved project and authenticated evidence.',
    where: 'Choose the platform configured in this application’s saved project settings.',
    format: 'Exactly Android or iOS. No combined or inferred selection.',
    failure: 'Disabled or inconsistent platforms are refused. The app does not modify settings to make a read pass.' },
  read: { label: 'Authenticated read and access', requiredness: 'required', requiredWhen: 'When selecting Start.',
    what: 'One bounded read of retained workflow evidence using the original session-only GitHub connection and installed verifier.',
    why: 'It binds the selected run/attempt to authenticated evidence. It does not build, dispatch, upload, promote or change GitHub/Store settings.',
    where: 'Connect the same registered project’s repository above. Review selected-repository Contents and Actions read access, Metadata access and applicable organization/SSO requirements in GitHub.',
    format: 'Start is explicit read consent. No additional token, URL, toolkit pin, expected hash or local path is entered here.',
    failure: 'Unavailable runtime/provider, permissions, limits or missing artifacts remain explicit. Unsaved edits must be saved or discarded deliberately; there is no automatic repair or retry.' },
  recovery: { label: 'Local status, cancellation and previous observations', requiredness: 'optional', requiredWhen: 'During an interrupted, changed-context or unacknowledged read.',
    what: 'Status observes the original local operation; Cancel asks only that original read to stop.',
    why: 'A promise, cancellation request or page change is not proof that the original worker and resources settled.',
    where: 'Use Read local Status or Cancel this local read here, including the retained attention panel after navigation.',
    format: 'One original operation ID. Status never polls GitHub or extends the native deadline. Cancel never cancels a remote workflow.',
    failure: 'Unknown cleanup blocks another read. Previous results are historical observations, not current Store state; after known settlement a new explicit Start is required.' },
};
function Authority({ title, value }: { title: string; value: GitHubHistoryAuthority }) {
  return <div><dt>{title}</dt><dd>{value.workflow} · run <code>{value.runId}</code> · attempt {value.attempt}<br />
    <code>{value.callerPath}</code> → <code>{value.reusableRepository}/{value.reusablePath}</code><br />
    Toolkit <code>{value.reusableCommit}</code> · head <code>{value.headSha}</code> · <code>{value.ref}</code> · {value.event}</dd></div>;
}
export function GitHubHistory({ state, controller, onHelp, compact = false, onShow }: {
  state: GitHubHistoryView; controller: GitHubHistoryController; onHelp: (help: HelpContent) => void; compact?: boolean; onShow?: () => void;
}) {
  const runId = useId(), attemptId = useId(), stageId = useId(), platformId = useId(), reasonId = useId();
  const status = state.status, op = status?.operation, result = status?.result, current = controller.currentResult(), context = controller.contextSummary();
  const reason = controller.startReason();
  if (compact && !state.pending && !state.uncertain && !state.cancelling && (!op || op.phase === 'settled')) return null;
  const controls = <div className="button-row">
    <button type="button" className="button secondary" disabled={state.mode !== 'native' || state.observing}
      onClick={() => void controller.checkStatus()}><Icon name="refresh" size={16} />Read local Status</button>
    <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Cancel this local read</button>
  </div>;
  return <section className="card" aria-label="Authenticated release history">
    <SectionHeading title="Authenticated release history" description="Read retained workflow evidence for one exact run and attempt. No automatic requests or Store operations."><Icon name="github" size={24} /></SectionHeading>
    {op && <p className="save-note" role="status"><Badge tone={op.phase === 'cleanup-unknown' ? 'warning' : 'info'}>{op.phase}</Badge>{' '}
      Original <code>{op.id}</code> · run {op.selection.runId} · attempt {op.selection.attempt} · {op.selection.stage} · {op.selection.platform}.
      {op.reason !== 'none' && <> {GITHUB_HISTORY_REASON_HELP[op.reason]}</>}</p>}
    {state.uncertain && <p className="review-caution" role="alert">Original acknowledgement or cleanup is unconfirmed. Keep the original local Status; do not start a replacement read.</p>}
    {state.error && <p className="review-caution" role="alert">{GITHUB_HISTORY_REASON_HELP[state.error]}</p>}
    {compact ? <>{controls}<button type="button" className="button small secondary" onClick={onShow}>Show authenticated History</button></> : <>
      <p id={reasonId} className="save-note">{reason ?? 'Start performs one authenticated read. It never promotes a release or mutates GitHub or a Store.'}<HelpButton content={HELP.read} onHelp={onHelp} /></p>
      {context && <p className="save-note">Connected repository <strong>{context.repository}</strong> · account <code>{context.accountId}</code><br />
        Observed saved configuration SHA256 <code>{context.configSha256}</code>. Native independently rechecks the saved original.</p>}
      <div className="field-label-row"><label htmlFor={runId}>Exact GitHub run ID</label><Badge>Required</Badge><HelpButton content={HELP.run} onHelp={onHelp} /></div>
      <input id={runId} type="text" inputMode="numeric" maxLength={20} value={state.runId} autoComplete="off" spellCheck={false}
        placeholder="123456789" onChange={(event) => controller.setRunId(event.target.value)} aria-describedby={`${runId}-help`} />
      <p id={`${runId}-help`} className="save-note">Copy only the numeric ID after /actions/runs/ on the selected repository’s GitHub run page, not the full URL.</p>
      <div className="field-label-row"><label htmlFor={attemptId}>Exact run attempt</label><Badge>Required</Badge><HelpButton content={HELP.attempt} onHelp={onHelp} /></div>
      <input id={attemptId} type="text" inputMode="numeric" maxLength={3} value={state.attempt} autoComplete="off" placeholder="Choose 1–100"
        onChange={(event) => controller.setAttempt(event.target.value)} aria-describedby={`${attemptId}-help`} />
      <p id={`${attemptId}-help`} className="save-note">Use the attempt selector on that run’s page. A rerun is a different attempt; there is no automatic latest selection.</p>
      <div className="field-label-row"><label htmlFor={stageId}>Release stage to observe</label><Badge>Required</Badge><HelpButton content={HELP.stage} onHelp={onHelp} /></div>
      <select id={stageId} value={state.stage ?? ''} onChange={(event) => controller.setStage(event.target.value === '' ? null : event.target.value as GitHubHistoryStage)}>
        <option value="">Choose stage…</option><option value="candidate">Candidate</option><option value="external-testing">External testing</option><option value="production-submit">Production submit</option>
      </select>
      <div className="field-label-row"><label htmlFor={platformId}>Evidence platform</label><Badge>Required</Badge><HelpButton content={HELP.platform} onHelp={onHelp} /></div>
      <select id={platformId} value={state.platform ?? ''} onChange={(event) => controller.setPlatform(event.target.value === '' ? null : event.target.value as GitHubHistoryPlatform)}>
        <option value="">Choose platform…</option><option value="android">Android</option><option value="ios">iOS</option>
      </select>
      <div className="button-row"><button type="button" className="button primary" disabled={reason !== null} aria-describedby={reasonId}
        onClick={() => controller.start()}>Start authenticated history read</button></div>
      <p className="review-caution">Authenticated retained workflow evidence is NOT current Store state or permission to promote. It describes what the verified workflow recorded; it does not query the Store today.</p>
      {result && <article className="github-environment" aria-label="Retained history observation">
        <h3>{current ? 'Current selection’s observation' : 'Previous / retained observation — not current'} · {result.verification}</h3>
        <p>Observed <time dateTime={result.observedAt}>{result.observedAt}</time>. {GITHUB_HISTORY_REASON_HELP[result.reason]}</p>
        <dl className="github-facts">
          <div><dt>Original selection</dt><dd>{result.context.repository} · run {result.context.selection.runId} · attempt {result.context.selection.attempt} · {result.context.selection.stage} · {result.context.selection.platform}</dd></div>
          <div><dt>Saved context</dt><dd>Account <code>{result.context.accountId}</code> · repository ID <code>{result.context.repositoryId}</code><br />
            Project binding <code>{result.context.projectBinding}</code><br />Configuration SHA256 <code>{result.context.configSha256}</code></dd></div>
          {result.evidence && <>
            <div><dt>Recorded outcome</dt><dd>{result.evidence.outcome} — historical workflow outcome only</dd></div>
            <div><dt>Application / version</dt><dd>{result.evidence.applicationId} · {result.evidence.version.name} · build {result.evidence.version.build}</dd></div>
            <div><dt>Candidate source</dt><dd>Commit <code>{result.evidence.candidateSource.commit}</code><br />Tree <code>{result.evidence.candidateSource.tree}</code></dd></div>
            <div><dt>Operation source</dt><dd>Commit <code>{result.evidence.operationSource.commit}</code><br />Tree <code>{result.evidence.operationSource.tree}</code></dd></div>
            <Authority title="Evidence producer" value={result.evidence.producedBy} /><Authority title="Original authorization (may be older)" value={result.evidence.authorizedBy} />
            <div><dt>Retained evidence artifact</dt><dd>{result.evidence.artifactName} · ID <code>{result.evidence.artifactId}</code> · producer job <code>{result.evidence.producerJobId}</code></dd></div>
          </>}
        </dl>
        {result.evidence && <details><summary>Integrity labels from the verified observation · not standalone authority</summary><dl className="github-facts">
          <div><dt>Artifact SHA256</dt><dd><code>{result.evidence.artifactSha256}</code></dd></div>
          <div><dt>Candidate manifest SHA256</dt><dd><code>{result.evidence.candidateManifestSha256}</code></dd></div>
          <div><dt>Operation intent SHA256</dt><dd><code>{result.evidence.operationIntentSha256}</code></dd></div>
          <div><dt>Receipt SHA256</dt><dd><code>{result.evidence.receiptSha256}</code></dd></div>
          <div><dt>Provenance SHA256</dt><dd><code>{result.evidence.provenanceSha256}</code></dd></div>
        </dl></details>}
        {result.verification !== 'verified' && <p className="save-note">Unavailable or refused evidence is not a negative release-history proof. Missing artifacts do not prove that no release happened.</p>}
      </article>}
      {controls}<p className="save-note">Status reads local native state, not GitHub. Cancel requests original cleanup only; it never cancels a remote workflow. A new read requires known settlement and another explicit Start.<HelpButton content={HELP.recovery} onHelp={onHelp} /></p>
    </>}
  </section>;
}
