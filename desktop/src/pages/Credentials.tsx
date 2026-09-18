import { useState } from 'react';
import type { Catalog, CredentialGuide, HelpContent } from '../types.ts';
import { Badge, DisabledAction, EmptyState, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';
import { CredentialSession } from '../components/CredentialSession.tsx';
import type { AssetDisplayState } from '../assetSessionTypes.ts';
import type { AssetSessionController } from '../assetSessionController.ts';
import type { ProjectSession } from '../drafts.ts';

function AssetGuide({ guide, sessionAvailable, onHelp }: { guide: CredentialGuide | null; sessionAvailable: boolean; onHelp: (help: HelpContent) => void }) {
  const [selected, setSelected] = useState('');
  const kind = guide?.kinds.find((entry) => entry.id === selected) ?? guide?.kinds[0];
  if (!guide || !kind) return <section className="card"><EmptyState compact icon="key" title="The guided asset catalogue is unavailable" description="Connect to a compatible core to see file-by-file instructions. The requirement list below remains guidance only; no private input can be collected on this screen." /></section>;
  return <section className="card asset-guide">
    <SectionHeading title="What do I need, and where do I find it?" description="Choose an item for practical instructions. These are preparation guides, not files or credentials discovered on your computer." />
    <div className="asset-guide-layout">
      <nav className="asset-guide-choices" aria-label="Credential and signing asset guides">{guide.kinds.map((entry) => <button type="button" className={entry.id === kind.id ? 'selected' : ''} aria-pressed={entry.id === kind.id} key={entry.id} onClick={() => setSelected(entry.id)}>{entry.label}<span>{entry.platform}</span></button>)}</nav>
      <div className="asset-guide-detail">
        <div className="credential-row-heading"><h3>{kind.label}</h3><Badge tone="info">Reference guide · not a result</Badge></div>
        <ul className="asset-guide-fields">{kind.fields.map((field) => <li key={field.id}>
          <div className="inline-heading"><h4>{field.label}</h4><HelpButton content={field} onHelp={onHelp} /></div>
          <p>{field.what}</p><dl className="asset-guide-definitions"><div><dt>Where to find it</dt><dd>{field.where}</dd></div><div><dt>Expected format</dt><dd>{field.format}</dd></div><div><dt>When you need it</dt><dd>{field.requiredWhen}</dd></div></dl>
          {field.input === 'file' && <p className="asset-guide-file-note"><Icon name="folder" size={16} /><span>{kind.id === 'android-keystore' || kind.id === 'android-firebase' ? sessionAvailable ? 'Use the session importer above for supported JKS or Android JSON files. It preserves your original; this guide itself does not read files.' : 'The session importer is currently unavailable. Read its status and reason above; no manual copying or renaming is needed.' : 'Native selection of this file type is not available in this build. No manual copying or renaming is needed for this guide.'}</span></p>}
        </li>)}</ul>
        <div className="asset-guide-checks"><h4>Format-check scope — not a result for your file</h4><ul>{kind.plannedChecks.map((check, index) => <li key={index}>{check}</li>)}</ul><h4>What format checks do not verify</h4><ul>{kind.notVerified.map((check, index) => <li key={index}>{check}</li>)}</ul></div>
      </div>
    </div>
    <details className="asset-guide-explainer"><summary>Understand selection, storage, and assignment</summary><p>{sessionAvailable ? 'The session importer above enables only its explicitly listed formats and in-memory actions. Persistent storage and the other file families remain unavailable.' : 'Session controls are not currently available; read the status and reason above. This reference guide does not itself import, store, assign, replace or delete anything.'}</p><div className="asset-guide-control-grid">{guide.controls.map((control) => <div key={control.id}><div className="inline-heading"><h4>{control.label}</h4><HelpButton content={control} onHelp={onHelp} /></div><p>{control.what}</p></div>)}</div></details>
    <details className="asset-guide-explainer"><summary>Understand credential statuses</summary><p>Definitions only — none of these statuses is a result for your project.</p><dl className="asset-guide-statuses">{guide.states.map((state) => <div key={state.id}><dt>{state.label}</dt><dd>{state.meaning}</dd></div>)}</dl></details>
  </section>;
}

export function Credentials({ catalog, state, controller, project, onHelp, nativeBusyReason = null }: { catalog: Catalog | null; state: AssetDisplayState; controller: AssetSessionController; project: ProjectSession | null; onHelp: (help: HelpContent) => void; nativeBusyReason?: string | null }) {
  const [filter, setFilter] = useState('');
  const credentials = catalog?.credentials.filter((entry) => `${entry.name} ${entry.platform} ${entry.what}`.toLocaleLowerCase().includes(filter.toLocaleLowerCase())) ?? [];
  return <>
    <PageHeading eyebrow="CREDENTIALS & SIGNING" title="Private by design." description="Understand each input, review its supported checks, and keep storage separate from assignment." />
    <div className="privacy-hero card"><div className="privacy-illustration"><Icon name="lock" size={42} /></div><div><Badge tone="info">Private inputs are not project settings</Badge><h2>Your credentials stay out of this draft.</h2><p>Use only the explicitly available private-input controls below. Persistent vault storage and account login remain unavailable. Do not paste tokens, passwords, private keys, or service-account JSON into project settings.</p></div></div>
    <div className="three-card-grid">{[{ icon: 'android' as const, title: 'Android signing', description: 'A keystore, signing policy, and the matching upload identity.' }, { icon: 'apple' as const, title: 'Apple signing', description: 'Certificates, provisioning, and protected App Store access.' }, { icon: 'github' as const, title: 'GitHub access', description: 'Reviewed repository access and protected release environments.' }].map((item) => <div className="card credential-summary" key={item.title}><span className="soft-icon"><Icon name={item.icon} size={23} /></span><h3>{item.title}</h3><p>{item.description}</p><Badge>Native / service verification not run</Badge></div>)}</div>
    {nativeBusyReason && <p className="review-caution" role="status">{nativeBusyReason} Private session controls cannot start conflicting work; original status, cancellation and discard remain separate.</p>}
    <CredentialSession state={state} controller={controller} project={project} guide={catalog?.credentialGuide ?? null} onHelp={onHelp} nativeBusyReason={nativeBusyReason} />
    <AssetGuide guide={catalog?.credentialGuide ?? null} sessionAvailable={state.mode === 'native' && state.status?.capability.available === true && !state.blocked && !state.observationFailed && nativeBusyReason === null} onHelp={onHelp} />
    <section className="card"><SectionHeading title="Core requirement catalogue" description="Conditional requirements are guidance, not proof that credentials exist or work."><label className="search-field"><Icon name="search" size={16} /><span className="sr-only">Find a credential requirement</span><input type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Find a requirement…" /></label></SectionHeading>
      {credentials.length ? <div className="credential-list">{credentials.map((credential, index) => <article key={`${credential.name}-${index}`}><div className="credential-row-heading"><div className="inline-heading"><h3>{credential.name}</h3><HelpButton content={{ ...credential, label: credential.name }} onHelp={onHelp} /></div><Badge>Not verified</Badge></div><p>{credential.what}</p><div className="credential-meta"><span>{credential.platform}</span><span>{credential.kind}</span><span>{credential.stages.join(' · ')}</span></div><p className="credential-when">{credential.requiredWhen}</p></article>)}</div> : <EmptyState compact icon="key" title={filter ? 'No matching requirement' : 'No native credential catalogue loaded'} description={filter ? 'Try a platform name or a different keyword.' : 'The connected core supplies exact credential names, conditional requiredness, formats, and recovery guidance. Browser examples never invent credential status.'} />}
    </section>
    <div className="two-card-grid"><section className="card"><SectionHeading title="Persistent encrypted vault" description="Session-only retention does not save credentials for a later launch." /><DisabledAction label="Enable persistent vault" icon="key" reason="Encrypted persistent storage and OS keyring integration are not available. There is no automatic fallback or silent persistence." /></section><section className="card"><SectionHeading title="Native and service verification" description="Configured and format-assessed are different from working signing keys or account access." /><DisabledAction label="Verify signing / account access" icon="shield" reason="Native signing and protected online credential checks are not implemented in this screen. Session assessment does not run them." /></section></div>
  </>;
}
