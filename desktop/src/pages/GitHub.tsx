import { useState } from 'react';
import type { ReactNode } from 'react';
import { getValue } from '../catalog.ts';
import type { ProjectSession } from '../drafts.ts';
import type { GitHubAssertionInput, GitHubSetupController, GitHubSetupState } from '../githubSetupController.ts';
import { GITHUB_WORKFLOWS } from '../githubSetupProtocol.ts';
import type { AppInfo, CredentialHelp, GitHubComparison, GitHubHelpText, GitHubSetupProposed, HelpContent, Page } from '../types.ts';
import { Badge, DisabledAction, ErrorNotice, HelpButton, Issues, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';
import { ProgressiveDisclosure } from '../components/ProgressiveDisclosure.tsx';

interface GitHubTaskSection {
  id: 'publication' | 'settings' | 'checks' | 'history' | 'counter';
  title: string;
  description: string;
  needsAttention: boolean;
  content: ReactNode;
}

const comparisonLabels: Record<GitHubComparison, string> = {
  'not-supplied': 'Not supplied · presence unknown',
  'reported-absent': 'Caller reports absent · unobserved',
  'supplied-digest-match': 'Supplied digest and size match · unobserved',
  'supplied-digest-differs': 'Supplied digest or size differs · unobserved',
};

function HelpDefinitions({ help }: { help: GitHubHelpText }) {
  return <dl className="help-definitions">
    <div><dt>What is this?</dt><dd>{help.what}</dd></div>
    <div><dt>Why it matters</dt><dd>{help.why}</dd></div>
    <div><dt>Where to find it</dt><dd>{help.where}</dd></div>
    <div><dt>Expected format</dt><dd>{help.format}</dd></div>
    <div><dt>If it is missing or incorrect</dt><dd>{help.failure}</dd></div>
  </dl>;
}

function InputHelpButton({ id, help, open, onToggle }: { id: string; help: GitHubHelpText | undefined; open: boolean; onToggle: () => void }) {
  return <button type="button" className="help-button" disabled={!help} aria-label={help ? `Help: ${help.label}` : 'Core help unavailable'} aria-controls={help ? `${id}-details` : undefined} aria-expanded={help ? open : undefined} onClick={onToggle}>?</button>;
}

function InputHelp({ id, help, open, onToggle }: { id: string; help: GitHubHelpText | undefined; open: boolean; onToggle: (open: boolean) => void }) {
  return <div id={id} className="github-input-help">{help ? <>
    <p>{help.what}</p><p><strong>Format:</strong> {help.format}</p>
    <details id={`${id}-details`} className="github-help" open={open} onToggle={(event) => onToggle(event.currentTarget.open)}><summary>Why, where and what can go wrong</summary><HelpDefinitions help={help} /></details>
  </> : <p>Core guidance is unavailable. Reload the packaged service; this screen does not supply a substitute policy.</p>}</div>;
}

function draftBranch(session: ProjectSession | null, path: string): string {
  const value = session?.draft ? getValue(session.draft, path) : undefined;
  return typeof value === 'string' ? value || 'Not set in this draft' : value === undefined ? 'Not set in this draft' : 'Not a text value — review Project settings';
}

function Proposal({ result, credentialHelp, onHelp }: { result: GitHubSetupProposed; credentialHelp: CredentialHelp[] | null; onHelp: (help: HelpContent) => void }) {
  return <section className="github-proposal" aria-label="Read-only GitHub setup proposal">
    <div className="card">
      <SectionHeading title="Passive proposal — nothing applied by this preview" description="Complete caller text from the shared core. This preview saves no files and observes no GitHub, Git or Store state. Local caller installation is reported in Local workflow files; remote settings use their separate card."><Badge tone="info">GitHub not contacted</Badge></SectionHeading>
      <dl className="github-facts">
        <div><dt>Toolkit repository</dt><dd><code>{result.tooling.repository}</code></dd></div>
        <div><dt>Toolkit commit · format-only</dt><dd><code>{result.tooling.sha}</code></dd></div>
        <div><dt>Installed core / resource version</dt><dd>{result.templateSet.coreVersion} / {result.templateSet.resourceVersion}</dd></div>
        <div><dt>Shipped resource SHA256 · identity only</dt><dd><code>{result.templateSet.resourceSha256}</code></dd></div>
        <div><dt>Remote ref / template compatibility</dt><dd>Not resolved / unknown</dd></div>
        <div><dt>Repository / release readiness</dt><dd>Not observed / unknown</dd></div>
        <div><dt>Draft assessment</dt><dd>Format-valid only · not saved by this preview</dd></div>
        <div className="github-fact-wide"><dt>Informational schema reference · not fetched or saved</dt><dd><code>{result.tooling.schemaReference}</code></dd></div>
      </dl>
      <p className="github-scope-note">No project code was executed, tools probed, credentials read, files written or workflow dispatched. This is not a full init configuration, metadata skeleton, .gitignore transaction or an Apply plan.</p>
    </div>
    <section className="card">
      <SectionHeading title="Four read-only workflow previews" description="Selectable text only. Paths and hashes identify proposed content, not existing repository files or permission to overwrite them." />
      <p className="github-scope-note">{result.facts.snapshotProvided ? 'Comparison uses only your supplied digest/size or absence assertions.' : 'No comparison summary was supplied; existing workflow presence is unknown.'} A match is not a verified no-op or an unchanged repository.</p>
      <div className="github-workflows">{result.workflows.map((workflow) => <details className="github-workflow" key={workflow.id}>
        <summary><code>{workflow.path}</code><Badge>{comparisonLabels[workflow.comparison]}</Badge></summary>
        <p className="github-workflow-meta">{workflow.byteLength} UTF-8 bytes · Core-reported SHA256 <code>{workflow.sha256}</code></p>
        <pre tabIndex={0} aria-label={`Read-only proposed content for ${workflow.path}`}><code>{workflow.content}</code></pre>
      </details>)}</div>
    </section>
    <section className="card">
      <SectionHeading title="Environment checklist · not observed by this preview" description="Desired policy only, not remote API requests. Use the separate remote setup card to review supported changes; this passive preview does not observe existing environments, approvals, permissions or values." />
      <dl className="github-facts">
        <div><dt>Caller configuration convention · not an observed file</dt><dd><code>{result.settings.configPath}</code></dd></div>
        <div><dt>Source basis</dt><dd>Configured policy only · protection unverified</dd></div>
        <div><dt>Candidate branch policy</dt><dd><code>{result.settings.sourcePolicy.candidateBranch}</code></dd></div>
        <div><dt>Production branch policy</dt><dd><code>{result.settings.sourcePolicy.productionBranch}</code></dd></div>
      </dl>
      <p className="github-scope-note">Requirement names, kinds and reasons below come only from the core’s validation result. Presence, correctness and access are unknown. Local _PATH alternatives are local guidance, not extra GitHub secret names. Do not enter values here.</p>
      {result.settings.environments.map((environment) => {
        const requirements = result.validation.requirements.filter((entry) => entry.environment === environment.name);
        return <article className="github-environment" key={environment.stage}>
          <div className="inline-heading"><h3><code>{environment.name}</code></h3><Badge>Unobserved</Badge></div>
          <p>Stage: {environment.stage} · approvals and protection unknown</p>
          {requirements.length === 0 ? <p>The core returned no requirement descriptors for this environment. Its configuration and readiness are still unknown.</p> :
            <ul className="github-requirements">{requirements.map((requirement) => {
              const help = credentialHelp?.find((entry) => entry.name === requirement.name);
              return <li key={`${requirement.name}-${requirement.stage}-${requirement.platform}`}>
                <div><strong><code>{requirement.name}</code></strong>{help && <HelpButton content={{ ...help, label: help.name }} onHelp={onHelp} />}<Badge>Presence unknown</Badge></div>
                <p>{requirement.kind} · {requirement.platform}</p><p>{requirement.reason}</p>
                {!help && <p className="save-note">Core field guidance is unavailable. No substitute credential policy is supplied here.</p>}
                {requirement.alternatives.length > 0 && <p>Local guidance only — not additional GitHub secret names: {requirement.alternatives.map((name, index) => <span key={`${name}-${index}`}>{index > 0 && ', '}<code>{name}</code></span>)}</p>}
              </li>;
            })}</ul>}
        </article>;
      })}
    </section>
  </section>;
}

export function GitHub({ session, state, controller, loading, onReload, onNavigate, credentialHelp, onHelp, nativeReview, connectionView, remoteTasks }: {
  info: AppInfo | null;
  session: ProjectSession | null;
  state: GitHubSetupState;
  controller: GitHubSetupController;
  loading: boolean;
  onReload: () => void;
  onNavigate: (page: Page) => void;
  credentialHelp: CredentialHelp[] | null;
  onHelp: (help: HelpContent) => void;
  nativeReview: ReactNode;
  connectionView: ReactNode;
  remoteTasks: readonly GitHubTaskSection[];
}) {
  const [inputHelpOpen, setInputHelpOpen] = useState({ repository: false, sha: false, snapshot: false });
  const helpOpened = (field: keyof typeof inputHelpOpen, open: boolean) => setInputHelpOpen((current) => current[field] === open ? current : { ...current, [field]: open });
  const reason = controller.startReason();
  const repositoryHelp = state.help?.inputs.find((entry) => entry.id === 'toolingRepository');
  const shaHelp = state.help?.inputs.find((entry) => entry.id === 'toolingSha');
  const snapshotHelp = state.help?.inputs.find((entry) => entry.id === 'suppliedSnapshot');
  const attention = remoteTasks.filter((task) => task.needsAttention);
  return <>
    <PageHeading eyebrow="GITHUB" title="Connect GitHub and prepare automation." description="Connect your account, review workflow files and choose which repository settings to apply. File changes and online actions have separate approvals. Nothing is published automatically." />
    {attention.length > 0 && <div className="notice notice-warning" role="status"><Icon name="info" /><div>
      <strong>GitHub tasks need your attention</strong><p>The original controls stay open below. Review their status before starting another task.</p>
      <ul>{attention.map((task) => <li key={task.id}><a href={`#github-task-${task.id}`}>{task.title}</a></li>)}</ul>
    </div></div>}
    {connectionView}
    <div className="notice notice-info"><Icon name="shield" /><div><strong>Prepare workflow files on this computer</strong><p>Choose the template source, then use <strong>Review local workflow files</strong> below. That review has its own confirmation before saving. The optional text preview does not save files or contact GitHub.</p></div></div>
    <form className="card github-form" onSubmit={(event) => { event.preventDefault(); void controller.propose(); }}>
      <SectionHeading title="Choose workflow templates" description="Enter the Mobile Release Kit repository and full commit to use for local workflow files. This is separate from your app’s repository above; the ? buttons explain where to find both values."><Badge>{state.pending ? 'Preparing optional preview…' : 'Not applied'}</Badge></SectionHeading>
      <div className="github-draft">
        <strong>{session?.project.name ?? 'No project selected'} · current draft</strong>
        <dl className="github-facts">
          <div><dt>Candidate branch</dt><dd><code>{draftBranch(session, 'source.candidateBranch')}</code></dd></div>
          <div><dt>Production branch</dt><dd><code>{draftBranch(session, 'source.productionBranch')}</code></dd></div>
        </dl>
        <p>These are your draft settings, not checked branch protections. Unsaved changes are kept.</p>
        <div className="button-row">
          <button type="button" className="button small secondary" onClick={() => onNavigate('settings')}>Review project settings<Icon name="arrow" size={15} /></button>
          <button type="button" className="button small secondary" onClick={() => onNavigate('credentials')}>Open Credentials &amp; Signing<Icon name="arrow" size={15} /></button>
        </div>
        <p className="github-scope-note">Credentials &amp; Signing shows current native input availability and scope. Local session assets are not automatically GitHub secrets. This passive preview never selects files or provisions secrets. The separate remote setup card can use eligible assigned inputs after explicit review and confirmation.</p>
      </div>
      {state.helpState !== 'current' && <div className="notice notice-warning" role="status"><Icon name="info" /><div><strong>{state.help ? 'Previously loaded core guidance' : 'Core setup guidance unavailable'}</strong><p>{state.help ? 'This admitted guidance is retained only in memory. It is not evidence that the latest service request succeeded or that the service is currently available.' : 'Restore the packaged service and reload guidance. No substitute policy, template source or proposal is generated in this screen.'}</p><button type="button" className="button small secondary" disabled={loading} onClick={onReload}>Reload service and guidance</button></div></div>}
      <div className="form-grid">
        <div className="form-field"><div className="field-label-row"><label htmlFor="github-toolkit-repository">{repositoryHelp?.label ?? 'Toolkit repository'}</label><InputHelpButton id="github-repository-help" help={repositoryHelp} open={inputHelpOpen.repository} onToggle={() => helpOpened('repository', !inputHelpOpen.repository)} />{repositoryHelp && <Badge>{repositoryHelp.requiredness}</Badge>}</div>
          <input id="github-toolkit-repository" type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} value={state.inputs.toolingRepository} aria-describedby="github-repository-help" onChange={(event) => controller.setCoordinate('toolingRepository', event.target.value)} />
          <InputHelp id="github-repository-help" help={repositoryHelp} open={inputHelpOpen.repository} onToggle={(open) => helpOpened('repository', open)} />
        </div>
        <div className="form-field"><div className="field-label-row"><label htmlFor="github-toolkit-sha">{shaHelp?.label ?? 'Full toolkit commit'}</label><InputHelpButton id="github-sha-help" help={shaHelp} open={inputHelpOpen.sha} onToggle={() => helpOpened('sha', !inputHelpOpen.sha)} />{shaHelp && <Badge>{shaHelp.requiredness}</Badge>}</div>
          <input id="github-toolkit-sha" type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} value={state.inputs.toolingSha} aria-describedby="github-sha-help" onChange={(event) => controller.setCoordinate('toolingSha', event.target.value)} />
          <InputHelp id="github-sha-help" help={shaHelp} open={inputHelpOpen.sha} onToggle={(open) => helpOpened('sha', open)} />
        </div>
      </div>
      <details className="github-help">
        <summary>Advanced: compare with a manually supplied file summary{state.inputs.snapshotEnabled ? ' (enabled)' : ' (optional)'}</summary>
        <p>You can skip this. Applying workflow files uses its own fresh review of the actual files; this optional summary is only for the preview.</p>
      <fieldset className="github-comparison"><legend><span className="github-legend-title">{snapshotHelp?.label ?? 'Optional supplied comparison'}<InputHelpButton id="github-snapshot-help" help={snapshotHelp} open={inputHelpOpen.snapshot} onToggle={() => helpOpened('snapshot', !inputHelpOpen.snapshot)} />{snapshotHelp && <Badge>{snapshotHelp.requiredness}</Badge>}</span></legend>
        <InputHelp id="github-snapshot-help" help={snapshotHelp} open={inputHelpOpen.snapshot} onToggle={(open) => helpOpened('snapshot', open)} />
        <label className="github-comparison-toggle"><input type="checkbox" checked={state.inputs.snapshotEnabled} aria-describedby="github-snapshot-help" onChange={(event) => controller.setSnapshotEnabled(event.target.checked)} />Use a caller-supplied summary — no files are read</label>
        <p>Comparison entries are cleared when switching projects or turning comparison off. Omitted callers are not supplied, never assumed absent.</p>
        {state.inputs.snapshotEnabled && <div className="github-assertions">{state.inputs.assertions.map((row) => <div className="github-assertion" key={row.id}>
          <div className="form-field"><div className="field-label-row"><label htmlFor={`github-assertion-${row.id}`}><code>{GITHUB_WORKFLOWS.find((entry) => entry.id === row.id)?.path}</code></label></div>
            <select id={`github-assertion-${row.id}`} value={row.state} onChange={(event) => controller.setAssertion(row.id, { state: event.target.value as GitHubAssertionInput['state'] })}>
              <option value="not-supplied">Not supplied · unknown</option><option value="absent">Reported absent</option><option value="present">Reported present · digest only</option>
            </select>
          </div>
          {row.state === 'present' && <div className="form-grid">
            <div className="form-field"><div className="field-label-row"><label htmlFor={`github-bytes-${row.id}`}>Reported byte length</label></div><input id={`github-bytes-${row.id}`} inputMode="numeric" type="text" autoComplete="off" value={row.byteLength} aria-describedby="github-snapshot-help" onChange={(event) => controller.setAssertion(row.id, { byteLength: event.target.value })} /></div>
            <div className="form-field"><div className="field-label-row"><label htmlFor={`github-digest-${row.id}`}>Reported lowercase SHA256</label></div><input id={`github-digest-${row.id}`} type="text" autoComplete="off" autoCapitalize="none" spellCheck={false} value={row.sha256} aria-describedby="github-snapshot-help" onChange={(event) => controller.setAssertion(row.id, { sha256: event.target.value })} /></div>
          </div>}
        </div>)}</div>}
      </fieldset>
      </details>
      {state.help && <section className="github-guidance" aria-label="Core setup guidance available before preview"><h3>Core setup guide · requirements to review</h3><p>Local, core-sourced text only. Links, paths and commands mentioned in guidance are never opened or executed here.</p>{state.help.guidance.map((entry) => <details className="github-help" key={entry.id}><summary>{entry.label}</summary><HelpDefinitions help={entry} /></details>)}</section>}
      <div className="github-propose-action"><button type="submit" className="button secondary" disabled={reason !== null} aria-describedby="github-propose-reason"><Icon name={state.pending ? 'refresh' : 'github'} size={17} />{state.pending ? 'Preparing preview…' : 'Preview without saving (optional)'}</button><p id="github-propose-reason">{reason ?? 'Optional text preview only. You can use the separate local workflow review without running this preview first.'}</p></div>
    </form>
    {state.invalidated && <div className="notice notice-warning" role="status"><Icon name="info" /><div><strong>Previous preview discarded</strong><p>The project, draft, toolkit inputs, comparison or service generation changed. Preview again; an older reply cannot restore stale output.</p></div></div>}
    {state.error && <ErrorNotice error={state.error} title="Setup preview unavailable" />}
    {state.result?.state === 'invalid' && <section className="card"><SectionHeading title="Draft needs correction" description="The passive core returned no workflow or settings proposal. This preview saved or applied nothing and did not contact GitHub."><Badge tone="danger">Format invalid</Badge></SectionHeading><Issues issues={state.result.validation.issues} /><button type="button" className="button secondary" onClick={() => onNavigate('settings')}>Review the draft and field guidance</button></section>}
    {nativeReview}
    <ProgressiveDisclosure title={`Optional preview: proposed files and checklist${state.result?.state === 'proposed' ? ' · available' : ''}`}
      description="Reference text only, not an Apply plan or proof that GitHub is ready. Opening this section does not run a preview.">
      {state.result?.state === 'proposed' ? <Proposal result={state.result} credentialHelp={credentialHelp} onHelp={onHelp} /> :
        <p>No current text preview is available. Use the optional preview button above if you want to read one; local workflow review is separate.</p>}
    </ProgressiveDisclosure>
    <section aria-label="Optional GitHub tasks">
      <SectionHeading title="Optional GitHub tasks" description="Open only the task you need. Each keeps its own checks, permissions and approval; saving local workflow files does not publish them." />
      {remoteTasks.map((task) => <section id={`github-task-${task.id}`} key={task.id} tabIndex={-1} aria-label={task.title}>
        <ProgressiveDisclosure title={task.title} description={task.description} needsAttention={task.needsAttention}>
          {task.content}
        </ProgressiveDisclosure>
      </section>)}
    </section>
    <details className="card progressive-disclosure"><summary>Help: what setup changes, and what it does not</summary><SectionHeading title="Saving workflows does not run them" description="Applying workflow files only changes your local repository. GitHub environments, secrets, checks and releases use the separate controls and approvals shown on this page or in Releases." /><div className="github-disabled-actions">
      <p className="save-note">For supported environment protections, secrets and variables, use the separate remote setup card above. It reports current native availability, requires an eligible connection and assigned inputs where needed, and shows a review before each confirmed change. Local file approval never grants remote authority.</p>
      <DisabledAction label="Dispatch from this setup preview" icon="rocket" reason="This preview cannot run checks or dispatch workflows. Use GitHub nonpublishing preflight on this page, or Protected release workflows in Releases; those separate actions may still be unavailable." />
    </div></details>
  </>;
}
