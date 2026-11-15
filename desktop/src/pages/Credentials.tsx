import { useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import type { Catalog, CredentialGuide, HelpContent } from '../types.ts';
import { Badge, EmptyState, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { TechnicalDetails } from '../components/TechnicalDetails.tsx';
import { Icon } from '../components/Icon.tsx';
import { CredentialSession } from '../components/CredentialSession.tsx';
import type { AssetDisplayState } from '../assetSessionTypes.ts';
import type { AssetSessionController } from '../assetSessionController.ts';
import type { ProjectSession } from '../drafts.ts';
import { ReleaseInputGuidance } from '../components/ReleaseInputGuidance.tsx';
import { sessionPreparationKind } from '../releaseInputGuidance.ts';
import { isAssetFileKind } from '../assetSessionProtocol.ts';
import type { ReleaseInputGuidanceController, ReleaseInputGuidanceState, ReleaseInputPreparationTarget } from '../releaseInputGuidance.ts';

function AssetGuide({ guide, selected, onSelect, sessionAvailable, onHelp }: { guide: CredentialGuide | null; selected: string; onSelect: (kind: string) => void; sessionAvailable: boolean; onHelp: (help: HelpContent) => void }) {
  const kind = guide?.kinds.find((entry) => entry.id === selected) ?? guide?.kinds[0];
  if (!guide || !kind) return <section className="card"><EmptyState compact icon="key" title="The guided asset catalogue is unavailable" description="Connect to a compatible core to see file-by-file instructions. The requirement list below remains guidance only; no private input can be collected on this screen." /></section>;
  return <section className="card asset-guide">
    <SectionHeading title="What do I need, and where do I find it?" description="Choose an item for practical instructions. These are preparation guides, not files or credentials discovered on your computer." />
    <div className="asset-guide-layout">
      <nav className="asset-guide-choices" aria-label="Credential and signing asset guides">{guide.kinds.map((entry) => <button type="button" className={entry.id === kind.id ? 'selected' : ''} aria-pressed={entry.id === kind.id} key={entry.id} onClick={() => onSelect(entry.id)}>{entry.label}<span>{entry.platform}</span></button>)}</nav>
      <div className="asset-guide-detail">
        <div className="credential-row-heading"><h3>{kind.label}</h3><Badge tone="info">Reference guide · not a result</Badge></div>
        <ul className="asset-guide-fields">{kind.fields.map((field) => <li key={field.id}>
          <div className="inline-heading"><h4>{field.label}</h4><HelpButton content={field} onHelp={onHelp} /></div>
          <p>{field.what}</p><dl className="asset-guide-definitions"><div><dt>Where to find it</dt><dd>{field.where}</dd></div><div><dt>Expected format</dt><dd>{field.format}</dd></div><div><dt>When you need it</dt><dd>{field.requiredWhen}</dd></div></dl>
          {field.input === 'file' && <p className="asset-guide-file-note"><Icon name="folder" size={16} /><span>{isAssetFileKind(kind.id) ? sessionAvailable ? 'Use the session importer above for its explicitly supported formats. Apple P12 and profile envelopes require separately admitted macOS; binary plist is not supported. It preserves your original. This guide itself does not read files or verify signing.' : 'The session importer is currently unavailable. Read its status and reason above; no manual copying or renaming is needed.' : 'Native selection of this file type is not available in this build. No manual copying or renaming is needed for this guide.'}</span></p>}
        </li>)}</ul>
        <div className="asset-guide-checks"><h4>Format-check scope — not a result for your file</h4><ul>{kind.plannedChecks.map((check, index) => <li key={index}>{check}</li>)}</ul><h4>What format checks do not verify</h4><ul>{kind.notVerified.map((check, index) => <li key={index}>{check}</li>)}</ul></div>
      </div>
    </div>
    <details className="asset-guide-explainer"><summary>Understand selection, storage, and assignment</summary><p>{sessionAvailable ? 'Use only the explicitly available formats and storage modes above. Its live status and contextual help describe what this build can actually do; this broader reference is not an availability or verification result.' : 'Session controls are not currently available; read the status and reason above. This reference guide does not itself import, store, assign, replace or delete anything.'}</p><div className="asset-guide-control-grid">{guide.controls.map((control) => <div key={control.id}><div className="inline-heading"><h4>{control.label}</h4><HelpButton content={control} onHelp={onHelp} /></div><p>{control.what}</p></div>)}</div></details>
    <details className="asset-guide-explainer"><summary>Understand credential statuses</summary><p>Definitions only — none of these statuses is a result for your project.</p><dl className="asset-guide-statuses">{guide.states.map((state) => <div key={state.id}><dt>{state.label}</dt><dd>{state.meaning}</dd></div>)}</dl></details>
  </section>;
}

export function Credentials({ catalog, state, controller, project, inputState, inputController, onSettings, onHelp, onOfflineChecks, onAndroidSigning, onStoreAccess, delegation, nativeBusyReason = null }: { catalog: Catalog | null; state: AssetDisplayState; controller: AssetSessionController; project: ProjectSession | null; inputState: ReleaseInputGuidanceState; inputController: ReleaseInputGuidanceController; onSettings: () => void; onHelp: (help: HelpContent) => void; onOfflineChecks: () => void; onAndroidSigning: () => void; onStoreAccess: () => void; delegation?: ReactNode; nativeBusyReason?: string | null }) {
  const [filter, setFilter] = useState('');
  const [selectedGuide, setSelectedGuide] = useState('');
  const [preparation, setPreparation] = useState<ReleaseInputPreparationTarget | null>(null);
  const activePreparation = useRef<ReleaseInputPreparationTarget | null>(null);
  const mounted = useRef(true);
  const guideRef = useRef<HTMLDivElement>(null);
  const referenceRef = useRef<HTMLDetailsElement>(null);
  const sessionRef = useRef<HTMLDivElement>(null);
  useLayoutEffect(() => { mounted.current = true; return () => { mounted.current = false; activePreparation.current = null; }; }, []);
  const currentHelp = (content: HelpContent) => { if (inputController.getSnapshot() === inputState) onHelp(content); };
  const isPreparationCurrent = (target: ReleaseInputPreparationTarget) => mounted.current && inputController.preparationCurrent(target, activePreparation.current);
  const dismissPreparation = (target: ReleaseInputPreparationTarget) => {
    if (!mounted.current || activePreparation.current !== target) return;
    activePreparation.current = null; setPreparation(null);
  };
  const takePreparation = (target: ReleaseInputPreparationTarget): boolean => {
    if (!isPreparationCurrent(target)) return false;
    // Retire this navigation hint before any explicit session choice changes.
    activePreparation.current = null; setPreparation(null); return true;
  };
  const openGuide = (target: ReleaseInputPreparationTarget) => {
    if (!mounted.current || !inputController.preparationCurrent(target, target)) return;
    setSelectedGuide(target.guideId);
    if (sessionPreparationKind(target.guideId)) {
      activePreparation.current = target; setPreparation(target); sessionRef.current?.focus();
    } else {
      activePreparation.current = null; setPreparation(null);
      // Reveal only on this explicit, still-current help request. Native
      // details keeps the guide mounted; no deferred focus or private action.
      if (referenceRef.current) referenceRef.current.open = true;
      guideRef.current?.focus();
    }
  };
  const credentials = inputState.help.credentials.filter((entry) => `${entry.name} ${entry.platform} ${entry.what}`.toLocaleLowerCase().includes(filter.toLocaleLowerCase()));
  return <>
    <PageHeading eyebrow="SIGNING & ACCOUNTS" title="Signing and Store accounts" description="Add the signing files and Store account keys you already use. Importing a file, keeping a copy and using it for a release each ask for your review." />
    <div className="notice notice-info"><Icon name="lock" /><div>
      <strong>Keep the key your app already uses</strong>
      <p>For an Android app update, use your existing upload key. Replacing it can prevent updates. Private files and passwords belong only in the supported controls below, never in project settings.</p>
      <p>Keep an encrypted backup and its recovery code separately. You need both to restore, including on another Mac. The controls below show which storage and backup actions are available.</p>
    </div></div>
    {nativeBusyReason && <p className="review-caution" role="status">{nativeBusyReason} Private session controls cannot start conflicting work; original status, cancellation and discard remain separate.</p>}
    <div ref={sessionRef} tabIndex={-1}><CredentialSession state={state} controller={controller} project={project} guide={catalog?.credentialGuide ?? null} onHelp={onHelp} nativeBusyReason={nativeBusyReason}
      preparation={preparation} isPreparationCurrent={isPreparationCurrent} takePreparation={takePreparation} dismissPreparation={dismissPreparation} /></div>
    {delegation}
    <ReleaseInputGuidance state={inputState} controller={inputController} onSettings={onSettings} onHelp={onHelp} onGuide={openGuide} />
    <details className="card progressive-disclosure" ref={referenceRef}>
      <summary>Help: where to find your signing files</summary>
      <div ref={guideRef} tabIndex={-1}><AssetGuide guide={inputState.help.guide} selected={selectedGuide} onSelect={setSelectedGuide} sessionAvailable={state.mode === 'native' && state.status?.capability.available === true && !state.blocked && !state.observationFailed && nativeBusyReason === null} onHelp={currentHelp} /></div>
      <div className="privacy-hero card"><div className="privacy-illustration"><Icon name="lock" size={42} /></div><div><Badge tone="info">Private inputs are not project settings</Badge><h2>Your credentials stay out of this draft.</h2><p>Use only the explicitly available private-input controls on this page. Memory-only and encrypted storage require separate consent and native availability; neither signs in to a Store account. Do not paste tokens, passwords, private keys, or service-account JSON into project settings.</p></div></div>
      <div className="three-card-grid">{[{ icon: 'android' as const, title: 'Android signing', description: 'A keystore, signing policy, and the matching upload identity.' }, { icon: 'apple' as const, title: 'Apple signing', description: 'Certificates, provisioning, and protected App Store access.' }, { icon: 'github' as const, title: 'GitHub access', description: 'Reviewed repository access and protected release environments.' }].map((item) => <div className="card credential-summary" key={item.title}><span className="soft-icon"><Icon name={item.icon} size={23} /></span><h3>{item.title}</h3><p>{item.description}</p><Badge>Reference · not a verification result</Badge></div>)}</div>
      <section className="card"><SectionHeading title="Storage is not assignment" description="Memory-only copies last for this launch. Explicitly saved encrypted copies can remain for later launches." /><p>Use the storage panel’s current native status. An encrypted vault needs a qualified filesystem and OS keyring. Missing or inaccessible keys are not replaced automatically; there is no plaintext or silent memory fallback. Each stored revision needs explicit assessment and assignment for the current draft.</p></section>
    </details>

    <details className="card progressive-disclosure">
      <summary>Help: every file and key the app can use</summary>
      <section className="card"><SectionHeading title="Core requirement catalogue" description="Conditional requirements are guidance, not proof that credentials exist or work."><label className="search-field"><Icon name="search" size={16} /><span className="sr-only">Find a credential requirement</span><input type="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Find a requirement…" /></label></SectionHeading>
        {credentials.length ? <div className="credential-list">{credentials.map((credential, index) => <article key={`${credential.name}-${index}`}><div className="credential-row-heading"><div className="inline-heading"><h3>{credential.name}</h3><HelpButton content={{ ...credential, label: credential.name }} onHelp={currentHelp} /></div><Badge>Not verified</Badge></div><p>{credential.what}</p><div className="credential-meta"><span>{credential.platform}</span><span>{credential.kind}</span><span>{credential.stages.join(' · ')}</span></div><p className="credential-when">{credential.requiredWhen}</p></article>)}</div> : <EmptyState compact icon="key" title={filter ? 'No matching requirement' : 'No native credential catalogue loaded'} description={filter ? 'Try a platform name or a different keyword.' : 'The connected core supplies exact credential names, conditional requiredness, formats, and recovery guidance. Browser examples never invent credential status.'} />}
      </section>
    </details>
    <section className="card"><SectionHeading title="Test that your keys work" description="Adding a file doesn’t prove it works. Each test below opens on the Build & release page, where you confirm before it starts." />
      <div className="test-row"><div><h3>Check your project</h3><p>Runs your project’s saved checks. Doesn’t use your keys.</p></div>
        <button type="button" className="button secondary" disabled={!project || nativeBusyReason !== null} onClick={onOfflineChecks}>Open local checks</button></div>
      <div className="test-row"><div><h3>Test Android signing</h3><p>Builds your app and signs a private copy with your upload key, then verifies it. Nothing is uploaded.</p></div>
        <button type="button" className="button secondary" disabled={!project || nativeBusyReason !== null} onClick={onAndroidSigning}>Open signing test</button></div>
      <div className="test-row"><div><h3>Test Store account access</h3><p>Checks that your Store account key can sign in. Nothing is published.</p></div>
        <button type="button" className="button secondary" disabled={!project || nativeBusyReason !== null} onClick={onStoreAccess}>Open Store access test</button></div>
      {!project && <p className="save-note">Choose a project first.</p>}
      <TechnicalDetails label="What each test does">
        <p>Saved offline checks: core builds and toolkit credential use are disabled, but configured project checks can run programs, change files or use the network. This does not verify signing or account access.</p>
        <p>Android signing: the existing tool provider checks the key, signs a private AAB copy and verifies its signature. Project code executes; this is not a read-only check. Gradle and project code may access the network or modify files. The toolkit does not request a Store operation. Opening the review does not start a build.</p>
        <p className="save-note">Use the build's status, Cancel and Recovery controls in Build &amp; release. Cancel is not rollback; an unknown cleanup state cannot be reset by reopening this page.</p>
        <p>Store access: opening the review makes no Store request; you give separate consent there to start a check. The Android check can create a temporary, uncommitted Google Play edit and attempts to delete it. It does not publish a release. Offline checks and signing do not verify Store account access.</p>
      </TechnicalDetails>
    </section>
  </>;
}
