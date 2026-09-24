import type { ReactNode } from 'react';
import { getValue, textValue } from '../catalog.ts';
import { configurationStatus } from '../certainty.ts';
import { isDirty } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import { releaseVersionHelp, releaseVersionPhase } from '../releaseVersion.ts';
import type { ReleaseVersionState } from '../releaseVersion.ts';
import type { AppInfo, HelpContent, Page } from '../types.ts';
import { Badge, DisabledAction, EmptyState, ErrorNotice, HelpButton, Issues, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

const projectHelp: HelpContent = {
  label: 'Static project observation', requiredness: 'required',
  requiredWhen: 'Select a project before requesting a static observation.',
  what: 'A bounded read of recognized configuration and source hints inside your selected folder.',
  why: 'Understand what is configured without running project code or assuming that an app is release-ready.',
  where: 'Choose the project’s actual root using the native folder picker. The app never searches parent repositories.',
  format: 'An explicitly selected local directory. Symbolic-link, unsupported, changed, or limited inputs may be refused or reported as partial.',
  failure: 'An incomplete read is not “no project found.” File observations are not atomic, may become stale, and never verify native tools, credentials, Git, or Store state.',
};

function SavedVersionCard({ state, reason, onRead, onHelp }: {
  state: ReleaseVersionState; reason: string | null; onRead: () => void; onHelp: (help: HelpContent) => void;
}) {
  const phase = releaseVersionPhase(state);
  const result = state.result;
  const labels = { 'not-read': 'Not read', reading: 'Reading…', observed: 'Observed', stale: 'Stale observation',
    missing: 'Saved input missing', invalid: 'Invalid saved input', unavailable: 'Unavailable' };
  const earlier = result !== null && phase !== 'observed';
  return <section className="card summary-card" aria-label="Saved version and build">
    <div className="summary-label"><span>Version & build</span><HelpButton content={releaseVersionHelp} onHelp={onHelp} /></div>
    <div aria-live="polite" aria-busy={phase === 'reading'}>
      <strong className="summary-value compact-value" style={{ overflowWrap: 'anywhere' }}>{phase === 'observed' && result ? result.version.name : labels[phase]}</strong>
      {phase === 'observed' && result && <><p>Build number {result.version.build}</p><Badge tone="info">Observed from saved version file</Badge></>}
      {earlier && result && <p style={{ overflowWrap: 'anywhere' }}>Earlier read: {result.version.name} · Build {result.version.build} — stale, not current.</p>}
      {result && <p>{earlier ? 'Earlier returned source' : 'Returned saved source'}:<br /><code style={{ overflowWrap: 'anywhere', whiteSpace: 'normal' }}>{result.source}</code></p>}
      {state.stale && <p>Known context changes retired the earlier read. Read again explicitly; returning to this view does not refresh it.</p>}
      {state.error && <p>{state.error.message}</p>}
      {reason && reason !== state.error?.message && <p>{reason}</p>}
    </div>
    {state.project?.dirtyDraft && <p><strong>Unsaved draft not applied.</strong> This reads saved configuration only and leaves your draft untouched.</p>}
    <p>One non-atomic read. External changes are not continuously monitored. No artifact check or full preflight; release readiness is not assessed.</p>
    <button type="button" className="button small secondary" disabled={reason !== null} title={reason ?? undefined} onClick={onRead}>
      <Icon name="refresh" size={15} className={phase === 'reading' ? 'spin' : ''} />Read saved version
    </button>
    <div className="summary-foot"><Icon name="metadata" size={14} /><code style={{ overflowWrap: 'anywhere', whiteSpace: 'normal' }}>Saved config: release/mobile-release.json</code></div>
  </section>;
}

export function Dashboard({ session, info, preview, chooseDisabled, chooseReason, refreshReason, releaseVersionState, releaseVersionReason, versionEditor, onReadVersion, onChoose, onRefresh, onNavigate, onHelp }: {
  session: ProjectSession | null; info: AppInfo | null; preview: boolean; chooseDisabled: boolean; chooseReason: string | null; refreshReason: string | null;
  versionEditor: ReactNode;
  releaseVersionState: ReleaseVersionState; releaseVersionReason: string | null; onReadVersion: () => void;
  onChoose: () => void; onRefresh: () => void; onNavigate: (page: Page) => void; onHelp: (help: HelpContent) => void;
}) {
  const status = configurationStatus(session, preview);
  const config = session?.snapshot?.config.data ?? null;
  const configName = session?.snapshot?.config.path ?? 'release/mobile-release.json';
  const partial = session?.snapshot?.discovery.partial;
  const observationDate = session?.snapshot?.observedAt ? new Date(session.snapshot.observedAt) : null;
  const observedLabel = observationDate && Number.isFinite(observationDate.valueOf()) ? observationDate.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : null;
  return <>
    <PageHeading eyebrow="YOUR RELEASE WORKSPACE" title={session ? `Let’s get ${session.project.name} ready.` : 'Good releases start here.'} description="A calmer place to prepare your mobile app. Understand the project first; release with evidence, not assumptions.">
      <button type="button" className="button secondary" disabled={chooseDisabled} aria-describedby={chooseReason ? 'project-choose-reason' : undefined} onClick={onChoose}><Icon name="folder" size={17} />{preview ? 'Load example workspace' : session ? 'Open another project' : 'Choose a project'}</button>
    </PageHeading>
    {chooseReason && <p id="project-choose-reason" className="toolbar-reason">{chooseReason}</p>}
    <section className="project-overview card">
      <div className="project-overview-main"><div className="project-art" aria-hidden="true"><div className="orbit orbit-one" /><div className="orbit orbit-two" /><div className="project-art-mark"><Icon name="rocket" size={32} /></div><span className="art-dot dot-one" /><span className="art-dot dot-two" /></div><div className="project-identity"><div className="inline-heading"><span className="eyebrow">{preview && session ? 'ILLUSTRATIVE PROJECT' : 'CURRENT PROJECT'}</span><HelpButton content={projectHelp} onHelp={onHelp} /></div><h2>{session?.project.name ?? 'Your next release, organized.'}</h2><p className="project-path">{session?.project.path ?? 'Select a project to see its configuration and discover static build hints.'}</p><div className="project-badges"><Badge tone={status.tone} dot>{status.label}</Badge>{config && getValue(config, 'android.enabled') === true && <span className="platform-chip"><Icon name="android" size={15} />Android</span>}{config && getValue(config, 'ios.enabled') === true && <span className="platform-chip"><Icon name="apple" size={15} />iOS</span>}{session && isDirty(session) && <Badge tone="warning">Unsaved draft</Badge>}</div></div></div>
      <div className="project-overview-action">{session ? <><button type="button" className="button primary" onClick={() => onNavigate('settings')}>Review project settings<Icon name="arrow" size={17} /></button><span>{preview ? 'Example values · not validated' : 'Configured is not verified'}</span></> : <><button type="button" className="button primary" disabled={chooseDisabled} onClick={onChoose}><Icon name="plus" size={17} />{preview ? 'Explore example workspace' : 'Open project folder'}</button><span>Folder selection does not write files</span></>}</div>
      {config && <div className="identity-strip"><div className="identity-detail"><Icon name="android" size={20} /><div><span>{preview ? 'Example Android application ID' : 'Configured Android application ID'}</span><strong>{textValue(getValue(config, 'android.applicationId'))}</strong><span className="identity-policy">Identity policy: {textValue(getValue(config, 'android.identityStatus'), 'not configured')} · not native-verified</span></div></div><div className="identity-detail"><Icon name="apple" size={20} /><div><span>{preview ? 'Example iOS bundle ID' : 'Configured iOS bundle ID'}</span><strong>{textValue(getValue(config, 'ios.bundleId'))}</strong><span className="identity-policy">Identity policy: {textValue(getValue(config, 'ios.identityStatus'), 'not configured')} · not service-verified</span></div></div></div>}
    </section>
    {session?.snapshotError && <ErrorNotice error={session.snapshotError} title="Static observation unavailable" />}
    {session?.snapshotPredatesSave && <div className="notice notice-info"><Icon name="info" /><div><strong>This static observation predates the last settled save check</strong><p>Saved draft state did not fabricate a new project observation. Refresh explicitly to inspect current files; your draft and baseline will be retained.</p></div></div>}
    {session && refreshReason && !session.snapshot && !preview && <div className="notice notice-warning"><Icon name="info" /><div><strong>The folder is selected, but it has not been read</strong><p>{refreshReason}</p></div></div>}
    {partial && <div className="notice notice-warning"><Icon name="info" /><div><strong>Only a partial static observation is available</strong><p>Some input was excluded, unreadable, changed, or limited. This is not a complete snapshot or a verification result.</p></div></div>}
    <div className="summary-grid">
      <SavedVersionCard state={releaseVersionState} reason={releaseVersionReason} onRead={onReadVersion} onHelp={onHelp} />
      <div className="card summary-card"><div className="summary-label"><span>Configuration</span><Icon name="settings" size={18} /></div><strong className="summary-value compact-value">{status.label}</strong><p>{preview && session ? 'Inert example · not core validated' : config ? 'Policy and syntax are not release evidence' : 'No configuration facts assumed'}</p><div className="summary-foot"><Icon name="metadata" size={14} /><span>{configName}</span></div></div>
      <div className="card summary-card"><div className="summary-label"><span>Release readiness</span><Icon name="shield" size={18} /></div><strong className="summary-value compact-value">Not assessed</strong><p>Native tools and services not verified</p><div className="summary-foot"><span className="neutral-dot" /><span>No release operations are enabled</span></div></div>
    </div>
    {versionEditor}
    <div className="dashboard-grid">
      <section className="card preparation-card"><SectionHeading title="Your preparation checklist" description="A clear next step, without pretending the checks are done."><Badge>Static foundation</Badge></SectionHeading>
        <div className="preparation-list">
          <button type="button" onClick={session ? () => onNavigate('settings') : onChoose} disabled={!session && chooseDisabled}><span className="step-number">01</span><div><strong>Review project configuration</strong><p>Confirm app identities, version source, and branch policy.</p></div><Badge tone={config ? 'info' : 'neutral'}>{session ? config ? 'Review draft' : 'Not loaded' : 'Choose project'}</Badge><Icon name="chevron" size={16} /></button>
          <button type="button" onClick={() => onNavigate('environment')}><span className="step-number">02</span><div><strong>Understand the environment</strong><p>See what this foundation can and cannot assess.</p></div><Badge>Static only</Badge><Icon name="chevron" size={16} /></button>
          <button type="button" onClick={() => onNavigate('credentials')}><span className="step-number">03</span><div><strong>Plan signing & credentials</strong><p>Read the requirements. Do not enter secrets here.</p></div><Badge>Not checked</Badge><Icon name="chevron" size={16} /></button>
          <button type="button" onClick={() => onNavigate('metadata')}><span className="step-number">04</span><div><strong>Prepare your Store presence</strong><p>Set locale policy; metadata and asset checks come later.</p></div><Badge>Not checked</Badge><Icon name="chevron" size={16} /></button>
        </div>
      </section>
      <aside className="foundation-card"><span className="foundation-icon"><Icon name="spark" size={24} /></span><span className="eyebrow">SMALL STEPS. HONEST STATUS.</span><h2>Know what’s configured.<br />Know what isn’t verified.</h2><p>Static observations, draft checks and separately gated configuration-only saving are preparation—not a completed release tool.</p><ul><li><span className="legend-dot configured" />Configured: a value is present</li><li><span className="legend-dot format" />Format-valid: policy only</li><li><span className="legend-dot unknown" />Verified: not established here</li></ul><button type="button" className="text-button" onClick={() => onNavigate('environment')}>Explore current capabilities<Icon name="arrow" size={16} /></button></aside>
    </div>
    <section className="card observation-card"><SectionHeading title="Latest static observation" description={session?.snapshot ? preview ? 'Example data only. No files have been read.' : `Independent file reads, not an atomic snapshot.${observedLabel ? ` Observed at ${observedLabel}; may become stale.` : ''}` : 'A selected folder is not evidence that its configuration or tools were checked.'}>
      <button type="button" className="button small secondary" disabled={!session || Boolean(refreshReason) || Boolean(session.snapshotRequest)} title={refreshReason ?? undefined} onClick={onRefresh}><Icon name="refresh" size={15} className={session?.snapshotRequest ? 'spin' : ''} />{session?.snapshotRequest ? 'Reading…' : 'Refresh static view'}</button>
    </SectionHeading>{session?.snapshot ? <><div className="observation-facts"><div><span>Inputs</span><strong>{preview ? 'None read' : `${session.snapshot.discovery.scan.sourceFiles} recognized files`}</strong></div><div><span>Git branch</span><strong>Not observed</strong></div><div><span>Credentials</span><strong>Not read</strong></div><div><span>Native / Store</span><strong>Not contacted</strong></div></div><Issues issues={[...session.snapshot.config.issues, ...session.snapshot.issues]} /></> : <EmptyState compact icon="folder" title={session?.snapshotRequest ? 'Reading recognized static files…' : 'No observation loaded'} description="No builds, signing tools, user hooks, Git commands, or Store requests are run." />}</section>
    <section className="card release-empty"><div><span className="eyebrow">RELEASE ACTIVITY</span><h2>Evidence belongs here. Not guesswork.</h2><p>No authenticated release history or artifacts have been loaded. This is not a claim that no releases exist.</p></div><DisabledAction label="Create release candidate" icon="rocket" reason={info?.capabilities?.actions.find((action) => action.id === 'release.candidate')?.reason ?? 'Builds and protected release dispatch are not implemented in this foundation.'} /></section>
  </>;
}
