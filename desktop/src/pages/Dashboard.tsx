import { useState } from 'react';
import type { ReactNode } from 'react';
import { getValue, textValue } from '../catalog.ts';
import { configurationStatus } from '../certainty.ts';
import type { ConfigEditState } from '../configEdit.ts';
import { isDirty } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import type { ProjectInitializationState } from '../projectInitialization.ts';
import { releaseVersionHelp } from '../releaseVersion.ts';
import type { ReleaseVersionState } from '../releaseVersion.ts';
import type { VersionEditState } from '../releaseVersionEditController.ts';
import { setupOverview } from '../setupOverview.ts';
import type { SetupAction, SetupActivity, SetupCheckObservation } from '../setupOverview.ts';
import type { AppInfo, HelpContent, Page } from '../types.ts';
import { Badge, EmptyState, ErrorNotice, HelpButton, Issues, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';
import type { IconName } from '../components/Icon.tsx';
import { ProgressiveDisclosure } from '../components/ProgressiveDisclosure.tsx';
import { SetupWizard } from '../components/SetupWizard.tsx';
import { TaskOverview } from '../components/TaskOverview.tsx';
import '../components/setupOverview.css';

const projectHelp: HelpContent = {
  label: 'Choose your app folder', requiredness: 'required',
  requiredWhen: 'Before reading or preparing your project.',
  what: 'The local folder containing the Android, iOS or Kotlin app you want to work on.',
  why: 'It keeps this project’s settings and drafts separate from other apps.',
  where: 'Use Choose project folder and select the root of your app with the native folder picker.',
  format: 'An explicitly selected local directory. Some linked, unreadable or unsupported files may not be included.',
  failure: 'An incomplete read is not proof that files are missing. Reading a project never builds it, checks signing, contacts a Store, or changes your draft.',
};

const laterTasks: readonly { page: Page; icon: IconName; title: string; description: string }[] = [
  { page: 'metadata', icon: 'metadata', title: 'Prepare Store text & images', description: 'Edit your listing locally. Review each save; nothing is sent to a Store.' },
  { page: 'github', icon: 'github', title: 'Connect GitHub automation', description: 'Optional: connect your repository, review workflows and see release history.' },
  { page: 'releases', icon: 'rocket', title: 'Prepare Store delivery', description: 'Review build and delivery requirements. Uploads require their own approval.' },
  { page: 'artifacts', icon: 'box', title: 'Inspect a build', description: 'Check a selected app package and its saved release evidence.' },
];

export function Dashboard({ session, preview, chooseDisabled, chooseReason, refreshReason, releaseVersionState, releaseVersionReason,
  versionEditor, versionEditState, initializationPanel, initializationState, configSaveState, checks, activities,
  onReadVersion, onChoose, onRefresh, onNavigate, onHelp }: {
  session: ProjectSession | null; info: AppInfo | null; preview: boolean;
  chooseDisabled: boolean; chooseReason: string | null; refreshReason: string | null;
  versionEditor: ReactNode; versionEditState: VersionEditState;
  initializationPanel: ReactNode; initializationState: ProjectInitializationState;
  configSaveState: ConfigEditState;
  releaseVersionState: ReleaseVersionState; releaseVersionReason: string | null;
  checks?: readonly SetupCheckObservation[]; activities?: readonly SetupActivity[];
  onReadVersion: () => void; onChoose: () => void; onRefresh: () => void;
  onNavigate: (page: Page) => void; onHelp: (help: HelpContent) => void;
}) {
  const [versionReveal, setVersionReveal] = useState(0);
  const [initializationReveal, setInitializationReveal] = useState(0);
  const overview = setupOverview({ session, preview, configSaveState, releaseVersionState, initializationState, versionEditState,
    chooseReason: chooseDisabled ? chooseReason ?? 'Finish the current task before choosing a project.' : null,
    refreshReason, releaseVersionReason, checks, activities });
  const act = (action: SetupAction) => {
    switch (action.kind) {
      case 'choose-project': if (!chooseDisabled) onChoose(); break;
      case 'refresh-project': if (session && !refreshReason && session.snapshotRequest === null) onRefresh(); break;
      case 'read-version': if (!releaseVersionReason) onReadVersion(); break;
      case 'open-version': setVersionReveal((revision) => revision + 1); break;
      case 'open-initialization': setInitializationReveal((revision) => revision + 1); break;
      case 'navigate': onNavigate(action.page); break;
    }
  };
  const config = session?.snapshot?.config.data ?? null;
  const status = configurationStatus(session, preview);
  const versionResult = session && releaseVersionState.resultBinding?.projectId === session.project.id ? releaseVersionState.result : null;
  const versionError = session && releaseVersionState.project?.projectId === session.project.id ? releaseVersionState.error : null;
  const observedAt = session?.snapshot?.observedAt ? new Date(session.snapshot.observedAt) : null;
  const observedLabel = observedAt && Number.isFinite(observedAt.valueOf()) ? observedAt.toLocaleString() : null;

  return <div className="guided-dashboard">
    <PageHeading eyebrow={preview ? 'EXAMPLE PROJECT' : 'YOUR APP'} title={session?.project.name ?? 'Get your app ready.'}
      description="Prepare a local build, one clear step at a time.">
      {session && <button type="button" className="button secondary" disabled={chooseDisabled}
        aria-describedby={chooseReason ? 'guided-project-choose-reason' : undefined} onClick={onChoose}>
        <Icon name="folder" size={17} />{preview ? 'Load example project' : 'Choose another project'}
      </button>}
      <HelpButton content={projectHelp} onHelp={onHelp} />
    </PageHeading>
    {chooseReason && <p id="guided-project-choose-reason" className="toolbar-reason">{chooseReason}</p>}

    {session?.snapshotError && <div className="notice notice-danger guided-notice" role="alert"><Icon name="info" />
      <div><strong>Project settings could not be read</strong><p>{session.snapshotError.message}</p><p>Your draft is kept. Check the problem before reading again.</p></div>
    </div>}
    {versionError && <div className="notice notice-warning guided-notice" role="alert"><Icon name="info" />
      <div><strong>Saved version could not be read</strong><p>{versionError.message}</p></div>
    </div>}
    {session?.snapshot?.discovery.partial && <div className="notice notice-warning guided-notice"><Icon name="info" />
      <div><strong>Some project files could not be checked</strong><p>This read is incomplete. Missing files and release readiness cannot be assumed; see Project details below.</p></div>
    </div>}
    {session && (session.snapshotPredatesSave || session.sourceChanged) && <div className="notice notice-info guided-notice"><Icon name="info" />
      <div><strong>Saved settings need another look</strong><p>Files have changed since the earlier read. Read them again when the current task finishes; your unsaved draft will stay intact.</p></div>
    </div>}
    {overview.otherProjectActivities.length > 0 && <div className="notice notice-warning guided-notice" role="status"><Icon name="info" />
      <div><strong>Another project has unfinished work</strong><p>Use that project’s original task controls shown on this page. Its result does not describe this project, and changing projects does not stop it.</p></div>
    </div>}
    {session && isDirty(session) && <p className="guided-blocker">Unsaved release settings are kept in this window. They are not applied to the saved version or a build.</p>}

    <TaskOverview overview={overview} preview={preview} onAction={act} />
    <SetupWizard overview={overview} onAction={act} onHelp={onHelp} />

    <ProgressiveDisclosure title="Edit version & build number" needsAttention={overview.versionEditorNeedsAttention} reveal={versionReveal}
      description="Manual by default. Open the saved values, choose a change and review it before saving. This does not build or release the app.">
      {versionEditor}
    </ProgressiveDisclosure>

    <section className="card" aria-label="Later release tasks">
      <SectionHeading title="When you’re ready for the next stage" description="GitHub and Store delivery are separate tasks, not prerequisites for exploring local setup." />
      <div className="guided-later-tasks">{laterTasks.map((task) => <button type="button" key={task.title} className="guided-task-link" onClick={() => onNavigate(task.page)}>
        <Icon name={task.icon} size={20} /><div><strong>{task.title}</strong><span>{task.description}</span></div>
      </button>)}</div>
      <div className="guided-inline-actions"><button type="button" className="text-button" onClick={() => onNavigate('recovery')}>
        <Icon name="recovery" size={17} />Recover interrupted work
      </button><span className="guided-safety">Keep original files and check what happened before repeating an action.</span></div>
    </section>

    <ProgressiveDisclosure title="Advanced: prepare release files together" needsAttention={overview.initializationNeedsAttention} reveal={initializationReveal}
      description="Optional: review the local configuration, GitHub workflow and empty metadata files as one setup. Existing files are checked; nothing is approved by opening this section.">
      {initializationPanel}
    </ProgressiveDisclosure>

    <ProgressiveDisclosure title="Project details & saved observations">
      <div className="guided-inline-actions"><Badge tone={status.tone}>{status.label}</Badge><HelpButton content={projectHelp} onHelp={onHelp} /></div>
      <dl className="guided-details-facts">
        <div><dt>Selected project folder</dt><dd>{session?.project.path ?? 'No folder selected'}</dd></div>
        <div><dt>Saved configuration path</dt><dd><code>{session?.snapshot?.config.path ?? 'release/mobile-release.json'}</code></dd></div>
        {config && <>
          <div><dt>Configured Android application ID</dt><dd>{textValue(getValue(config, 'android.applicationId'))}<br />Identity policy: {textValue(getValue(config, 'android.identityStatus'), 'not configured')} · not checked against the app or Store</dd></div>
          <div><dt>Configured iOS bundle ID</dt><dd>{textValue(getValue(config, 'ios.bundleId'))}<br />Identity policy: {textValue(getValue(config, 'ios.identityStatus'), 'not configured')} · not checked against the app or Store</dd></div>
        </>}
        <div><dt>Last file read</dt><dd>{preview ? 'Example data. No files read.' : observedLabel ?? 'No file read recorded'}</dd></div>
      </dl>
      <p>Independent file reads can become out of date. This view does not check Git, tools, credentials or Store state.</p>
      <div className="guided-inline-actions"><button type="button" className="button small secondary" disabled={!session || Boolean(refreshReason) || session.snapshotRequest !== null}
        aria-describedby={refreshReason ? 'guided-refresh-reason' : undefined} onClick={onRefresh}>
        <Icon name="refresh" size={15} className={session?.snapshotRequest ? 'spin' : ''} />{session?.snapshotRequest ? 'Reading…' : 'Read project settings again'}
      </button><button type="button" className="text-button" onClick={() => onNavigate('settings')}>Open all project settings</button></div>
      {refreshReason && <p id="guided-refresh-reason" className="guided-blocker">{refreshReason}</p>}
      {session?.snapshotError && <ErrorNotice error={session.snapshotError} title="Project read details" />}
      {session?.snapshot ? <Issues issues={[...session.snapshot.config.issues, ...session.snapshot.issues]} /> :
        <EmptyState compact icon="folder" title="No project files have been read" description="Choosing a folder does not verify its configuration, tools or release readiness." />}
    </ProgressiveDisclosure>

    <ProgressiveDisclosure title="Saved version details">
      <HelpButton content={releaseVersionHelp} onHelp={onHelp} />
      {versionResult && <p>{overview.version ? 'Saved values read for these settings' : 'Earlier read — not current for these settings'}: <strong>{versionResult.version.name} · Build {versionResult.version.build}</strong><br />Source: <code>{versionResult.source}</code></p>}
      {versionError && <ErrorNotice error={versionError} />}
      <p>This reads saved files, not the draft or Store state. Reads happen only when requested and are not continuously monitored.</p>
      <div className="guided-inline-actions"><button type="button" className="button small secondary" disabled={releaseVersionReason !== null}
        aria-describedby={releaseVersionReason ? 'guided-version-reason' : undefined} onClick={onReadVersion}>
        <Icon name="refresh" size={15} />Read saved version again
      </button></div>
      {releaseVersionReason && <p id="guided-version-reason" className="guided-blocker">{releaseVersionReason}</p>}
    </ProgressiveDisclosure>
  </div>;
}
