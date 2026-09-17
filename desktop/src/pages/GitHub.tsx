import { useState } from 'react';
import type { ReactNode } from 'react';
import { getValue } from '../catalog.ts';
import { futureReason } from '../certainty.ts';
import type { ProjectSession } from '../drafts.ts';
import { githubSetupStartReason } from '../githubSetupController.ts';
import type { GitHubAssertionInput, GitHubSetupController, GitHubSetupState } from '../githubSetupController.ts';
import { GITHUB_WORKFLOWS } from '../githubSetupProtocol.ts';
import type { AppInfo, GitHubComparison, GitHubHelpText, GitHubSetupProposed, Page } from '../types.ts';
import { Badge, DisabledAction, ErrorNotice, Issues, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

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

function Proposal({ result }: { result: GitHubSetupProposed }) {
  return <section className="github-proposal" aria-label="Read-only GitHub setup proposal">
    <div className="card">
      <SectionHeading title="Passive proposal — nothing applied by this preview" description="Complete caller text from the shared core. This preview saves no files and observes no GitHub, Git or Store state. Any separate native operation is reported in Local workflow files."><Badge tone="info">GitHub not contacted</Badge></SectionHeading>
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
      <SectionHeading title="Environment checklist · not configured" description="Desired policy and unresolved administrator work, not remote API requests. Existing environments, approvals, permissions and values remain unknown." />
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
            <ul className="github-requirements">{requirements.map((requirement) => <li key={`${requirement.name}-${requirement.stage}-${requirement.platform}`}>
              <div><strong><code>{requirement.name}</code></strong><Badge>Presence unknown</Badge></div>
              <p>{requirement.kind} · {requirement.platform}</p><p>{requirement.reason}</p>
              {requirement.alternatives.length > 0 && <p>Local guidance only — not additional GitHub secret names: {requirement.alternatives.map((name, index) => <span key={`${name}-${index}`}>{index > 0 && ', '}<code>{name}</code></span>)}</p>}
            </li>)}</ul>}
        </article>;
      })}
    </section>
  </section>;
}

export function GitHub({ info, session, state, controller, loading, onReload, onNavigate, nativeReview }: {
  info: AppInfo | null;
  session: ProjectSession | null;
  state: GitHubSetupState;
  controller: GitHubSetupController;
  loading: boolean;
  onReload: () => void;
  onNavigate: (page: Page) => void;
  nativeReview: ReactNode;
}) {
  const [inputHelpOpen, setInputHelpOpen] = useState({ repository: false, sha: false, snapshot: false });
  const helpOpened = (field: keyof typeof inputHelpOpen, open: boolean) => setInputHelpOpen((current) => current[field] === open ? current : { ...current, [field]: open });
  const reason = githubSetupStartReason(state);
  const repositoryHelp = state.help?.inputs.find((entry) => entry.id === 'toolingRepository');
  const shaHelp = state.help?.inputs.find((entry) => entry.id === 'toolingSha');
  const snapshotHelp = state.help?.inputs.find((entry) => entry.id === 'suppliedSnapshot');
  return <>
    <PageHeading eyebrow="GITHUB" title="Review the setup. Keep authority separate." description="Preview four caller files and a core-sourced checklist. Local installation needs its own fresh native review and confirmation; remote GitHub setup remains unavailable." />
    <section className="card connect-card"><div className="github-visual"><Icon name="github" size={45} /></div><div><Badge>Not connected</Badge><h2>A proposal is not repository access.</h2><p>Account login, repository setup, secret provisioning and guarded dispatch remain unavailable. This passive preview does not contact GitHub.</p><DisabledAction label="Connect GitHub" icon="github" reason={futureReason(info?.capabilities, 'github.authenticate', 'Publisher-registered GitHub App login and the secure token vault are not implemented.')} /></div></section>
    <div className="notice notice-info"><Icon name="shield" /><div><strong>GitHub not contacted · remote authority unavailable</strong><p>Remote repository state, toolkit ref existence, template compatibility and release readiness remain unknown. A passive proposal never authorizes local writes or a release. Separate local operation outcomes are shown below.</p></div></div>
    <form className="card github-form" onSubmit={(event) => { event.preventDefault(); void controller.propose(); }}>
      <SectionHeading title="Preview setup from your draft" description="Toolkit inputs are separate from the application’s source identity. No account or commit is preselected."><Badge>{state.pending ? 'Preparing preview…' : 'In-memory only'}</Badge></SectionHeading>
      <div className="github-draft">
        <strong>{session?.project.name ?? 'No project selected'} · current draft</strong>
        <dl className="github-facts">
          <div><dt>source.candidateBranch</dt><dd><code>{draftBranch(session, 'source.candidateBranch')}</code></dd></div>
          <div><dt>source.productionBranch</dt><dd><code>{draftBranch(session, 'source.productionBranch')}</code></dd></div>
        </dl>
        <p>Draft fields only, not validated here or observed branch protection. Your unsaved configuration is retained unchanged.</p>
        <button type="button" className="button small secondary" onClick={() => onNavigate('settings')}>Review project settings<Icon name="arrow" size={15} /></button>
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
      {state.help && <section className="github-guidance" aria-label="Core setup guidance available before preview"><h3>Core setup guide · unresolved administrator work</h3><p>Local, core-sourced text only. Links, paths and commands mentioned in guidance are never opened or executed here.</p>{state.help.guidance.map((entry) => <details className="github-help" key={entry.id}><summary>{entry.label}</summary><HelpDefinitions help={entry} /></details>)}</section>}
      <div className="github-propose-action"><button type="submit" className="button primary" disabled={reason !== null} aria-describedby="github-propose-reason"><Icon name={state.pending ? 'refresh' : 'github'} size={17} />{state.pending ? 'Preparing preview…' : 'Preview GitHub setup'}</button><p id="github-propose-reason">{reason ?? 'Uses the shared core only. No file write, GitHub call, credential access or workflow execution.'}</p></div>
    </form>
    {state.invalidated && <div className="notice notice-warning" role="status"><Icon name="info" /><div><strong>Previous preview discarded</strong><p>The project, draft, toolkit inputs, comparison or service generation changed. Preview again; an older reply cannot restore stale output.</p></div></div>}
    {state.error && <ErrorNotice error={state.error} title="Setup preview unavailable" />}
    {state.result?.state === 'invalid' && <section className="card"><SectionHeading title="Draft needs correction" description="The passive core returned no workflow or settings proposal. This preview saved or applied nothing and did not contact GitHub."><Badge tone="danger">Format invalid</Badge></SectionHeading><Issues issues={state.result.validation.issues} /><button type="button" className="button secondary" onClick={() => onNavigate('settings')}>Review the draft and field guidance</button></section>}
    {state.result?.state === 'proposed' && <Proposal result={state.result} />}
    {nativeReview}
    <section className="card"><SectionHeading title="Remote authority stays disabled" description="Neither a preview nor local caller installation enables Connect, remote setup, credential provisioning, checks or dispatch. Those operations need separate reviewed ownership and authorization." /><div className="github-disabled-actions">
      <DisabledAction label="Apply remote GitHub setup" icon="lock" reason={futureReason(info?.capabilities, 'github.setup', 'Authenticated repository setup and remote apply are not implemented. A local file plan has no remote authority.')} />
      <DisabledAction label="Provision GitHub secrets" icon="key" reason={futureReason(info?.capabilities, 'github.setup', 'Environment and secret provisioning are not implemented. No credential values are accepted.')} />
      <DisabledAction label="Run checks / dispatch" icon="rocket" reason={futureReason(info?.capabilities, 'release.candidate', 'Protected workflow dispatch and native release execution are not implemented.')} />
    </div></section>
  </>;
}
