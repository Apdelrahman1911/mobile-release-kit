import type { AppInfo, HelpContent } from '../types.ts';
import type { ProjectSession } from '../drafts.ts';
import type { EnvironmentController, EnvironmentPlatform, EnvironmentOperation, EnvironmentState } from '../environment.ts';
import type { EnvironmentDiagnosticsController, EnvironmentDiagnosticsState } from '../environmentDiagnosticsController.ts';
import { EnvironmentDiagnostics } from '../components/EnvironmentDiagnostics.tsx';
import { Badge, ErrorNotice, HelpButton, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

const methodLabels: Record<string, string> = {
  capabilities: 'Read engine capabilities', catalog: 'Load schema & field help',
  'project.snapshot': 'Read a static project observation', 'config.validate': 'Validate a configuration draft',
  'config.suggest': 'Suggest an unverified configuration draft', 'config.preview': 'Review draft changes and field requirements',
  'github.setup.propose': 'Prepare a GitHub setup preview', 'credentials.assess': 'Assess explicitly supplied credential data',
  'metadata.text.observe': 'Read selected public metadata text', 'metadata.text.validate': 'Validate supplied public text',
  'environment.requirements': 'Explain project toolchain requirements',
};

// Control instructions remain useful before a valid draft/service response.
// Prerequisites and version policy are displayed only from connected core DATA.
const initialHelp: Record<'platform' | 'operation', HelpContent> = {
  platform: { label: 'Release platform', requiredness: 'required', requiredWhen: 'Choosing the guidance to display.',
    what: 'The release target you want to prepare for.', why: 'Different targets need different tools.',
    where: 'Choose the target you use in Project settings.', format: 'Android or iOS, not your computer operating system.',
    failure: 'A disabled project target will show no applicable prerequisites. Selecting it does not change project settings.' },
  operation: { label: 'Activity', requiredness: 'required', requiredWhen: 'Choosing the guidance to display.',
    what: 'Whether you are preparing to build or inspect an existing artifact.', why: 'These activities need different prerequisites.',
    where: 'Choose the activity you want to understand below.', format: 'Build/archive or artifact validation; no command will run.',
    failure: 'Choosing an activity only changes the guidance. It never proves the environment or starts a release.' },
};
const activity = (operation: EnvironmentOperation) => operation === 'build' ? 'Build / archive prerequisites' : 'Artifact-validation prerequisites';

export function Environment({ info, preview, session, state, controller, diagnosticsState, diagnosticsController, onRetry, onSettings, onHelp, loading }: {
  info: AppInfo | null; preview: boolean; session: ProjectSession | null; state: EnvironmentState; controller: EnvironmentController;
  diagnosticsState: EnvironmentDiagnosticsState; diagnosticsController: EnvironmentDiagnosticsController;
  onRetry: () => void; onSettings: () => void; onHelp: (help: HelpContent) => void; loading: boolean;
}) {
  const runtime = info?.runtime;
  const capabilities = info?.capabilities;
  const reason = controller.startReason();
  const result = state.resultBinding?.projectId === session?.project.id ? state.result : null;
  const resultPreview = state.resultBinding?.mode === 'preview';
  const guide = result?.help ?? initialHelp;
  const setContext = (platform: EnvironmentPlatform, operation: EnvironmentOperation) => {
    diagnosticsController.setContext(platform, operation);
    controller.setContext(platform, operation);
  };
  return <>
    <PageHeading eyebrow="ENVIRONMENT" title="Know what your project needs." description="Keep expected prerequisites separate from explicitly requested, bounded local tool observations."><button type="button" className="button secondary" disabled={loading} onClick={onRetry}><Icon name="refresh" size={17} className={loading ? 'spin' : ''} />{loading ? 'Loading…' : 'Reload connection'}</button></PageHeading>
    <div className="notice notice-info"><Icon name="info" /><div><strong>{preview ? 'Browser design preview — example data only' : 'Requirements are not verification'}</strong><p>{preview ? 'The example rows and baselines below are illustrative, not a core assessment. No host, draft or tool has been checked.' : 'Expected versions describe toolkit policy, not installed versions. Native observations have a separate section and capability; neither proves signing, accounts or release readiness.'}</p></div></div>
    <section className="card">
      <SectionHeading title="Prepare for your next activity" description={session ? `${session.project.name} · current in-memory configuration draft ${session.revision}` : 'Select a project before loading its prerequisites.'} />
      <div className="environment-controls">
        <div><label htmlFor="environment-platform">Release platform <HelpButton content={guide.platform} onHelp={onHelp} /></label>
          <select id="environment-platform" value={state.platform} disabled={loading || !session?.draft} onChange={(event) => setContext(event.target.value as EnvironmentPlatform, state.operation)}><option value="android">Android</option><option value="ios">iOS</option></select>
          <p>The target you want to prepare for, not the host operating system.</p></div>
        <div><label htmlFor="environment-operation">Activity <HelpButton content={guide.operation} onHelp={onHelp} /></label>
          <select id="environment-operation" value={state.operation} disabled={loading || !session?.draft} onChange={(event) => setContext(state.platform, event.target.value as EnvironmentOperation)}><option value="build">Build / archive</option><option value="artifact-validation">Validate an existing artifact</option></select>
          <p>Build guidance is not a complete signed-release checklist.</p></div>
      </div>
      <div className="button-row"><button type="button" className="button primary" disabled={loading || reason !== null} onClick={() => void controller.refresh()}><Icon name="list" size={17} />{state.pending ? 'Loading requirements…' : preview ? 'Show example requirements' : 'Load draft requirements'}</button><button type="button" className="button secondary" onClick={onSettings}>Project settings</button></div>
      {reason && <p className="save-note">{reason}</p>}
      {state.error && <ErrorNotice error={state.error} title="Requirements were not loaded" />}
      {state.error?.code === 'environment_draft_invalid' && <p>Correct the current draft in Project settings, then load requirements again. No files were saved.</p>}
    </section>
    {state.stale && <div className="notice notice-warning" role="status"><Icon name="refresh" /><div><strong>Earlier requirements are stale</strong><p>The selected project, draft, activity or core connection changed, or a refresh did not complete. {result ? 'The earlier rows below are retained only for reference.' : 'Rows from another project are not shown here.'} Load requirements again for the current context.</p></div></div>}
    {result && <section className="card" aria-busy={state.pending !== null}>
      <SectionHeading title={resultPreview ? 'Example prerequisite cards' : activity(result.context.operation)} description={`${result.context.platform === 'ios' ? 'iOS' : 'Android'} · draft ${state.resultBinding?.draftRevision ?? 'unknown'} · ${state.stale ? 'earlier context' : resultPreview ? 'illustration only' : 'requirements only'}`} />
      <div className="button-row"><Badge tone={state.stale || resultPreview ? 'warning' : 'neutral'}>{resultPreview ? 'Example only · not verified' : state.stale ? 'Stale · not verified' : 'Tools not checked'}</Badge><Badge>Release readiness unknown</Badge><span className="save-note">{resultPreview ? 'Host not observed in browser preview' : `${state.stale ? 'Earlier core host' : 'Core host'}: ${result.hostPlatform}`}</span></div>
      {result.state === 'platform-disabled' ? <p>This target is disabled in the supplied configuration draft. Change Project settings if you intend to release it; this screen does not enable it.</p> : <>
        {!resultPreview && result.context.platform === 'ios' && result.hostPlatform !== 'macos' && <p className="review-caution">This requirements response came from a non-macOS core. Native iOS steps require a suitable local Mac or a GitHub Actions macOS runner.</p>}
        {!resultPreview && result.context.platform === 'android' && result.hostPlatform === 'windows' && <p className="review-caution">Native Android execution on Windows is not qualified in this Desktop milestone.</p>}
        <div className="environment-requirements">{result.requirements.map((row) => <article className="tool-card" key={row.id}>
          <div className="environment-tool-heading"><h3>{row.help.label}</h3><HelpButton content={row.help} onHelp={onHelp} /></div><p>{row.help.what}</p>
          <div className="button-row"><Badge>Not checked</Badge>{row.help.requiredness === 'conditional' && <Badge>Conditional</Badge>}</div>
          {row.help.requiredWhen && <p className="save-note">{row.help.requiredWhen}</p>}
          <dl className="environment-baseline"><dt>{row.baseline.kind === 'workflow-reference' ? 'Workflow reference · not a local compatibility rule' : row.baseline.kind === 'exact-pin' ? 'Expected toolkit baseline · not observed' : row.baseline.kind === 'project-defined' ? 'Defined by your project' : 'Defined by the native platform'}</dt>
            <dd>{row.baseline.version ?? 'No universal version inferred'}{row.baseline.build && ` · build ${row.baseline.build}`}</dd>
            {row.baseline.sha256 && <><dt>Expected SHA-256</dt><dd><code>{row.baseline.sha256}</code></dd></>}
            {row.baseline.maxBytes !== null && <><dt>Maximum helper bytes</dt><dd>{row.baseline.maxBytes.toLocaleString()}</dd></>}
          </dl>
          <p><strong>Where to find it: </strong>{row.help.where}</p>
        </article>)}</div>
      </>}
      <ul className="plain-list">{result.limitations.map((item, index) => <li key={index}><Icon name="shield" size={16} /><span>{item}</span></li>)}</ul>
    </section>}
    <EnvironmentDiagnostics state={diagnosticsState} controller={diagnosticsController} loading={loading} />
    <div className="environment-summary">
      <section className="card runtime-card"><span className="eyebrow">CORE RUNTIME</span><h2>{preview ? 'Browser preview' : runtime?.state === 'available' ? runtime.mode === 'development' ? 'Development runtime' : 'Bundled runtime' : 'Runtime unavailable'}</h2><Badge tone={runtime?.state === 'available' && !preview ? 'info' : 'warning'}>{preview ? 'No native connection' : runtime?.state ?? 'Not loaded'}</Badge><p>{preview ? 'This page is a design preview. No platform or engine capability has been verified.' : runtime?.reason ?? (runtime?.state === 'available' ? 'A runtime is available for the listed static functions. This does not establish native process finality or packaged release readiness.' : 'No runtime availability has been established. Capabilities and environment state remain unassessed.')}</p>{runtime?.mode === 'development' && <p className="warning-text">An explicit developer runtime is not a standalone end-user distribution.</p>}<div className="runtime-versions"><span>Desktop <strong>{info?.appVersion ?? 'Not loaded'}</strong></span><span>Core <strong>{capabilities?.coreVersion ?? 'Not loaded'}</strong></span><span>Platform <strong>{capabilities?.hostPlatform ?? 'Not observed'}</strong></span></div></section>
      <section className="card platform-note"><div className="soft-icon"><Icon name="environment" size={24} /></div><h2>The right platform for the job</h2><p>The Desktop goal is Linux, macOS and Windows. Native iOS requires macOS; native Android Windows execution has separate unfinished qualification.</p><p>The finished app must bundle its runtime and non-SDK helpers, without manual Python, Rust or CLI setup. This milestone does not deliver installers or run builds.</p></section>
    </div>
    <section className="card"><SectionHeading title="Implemented passive functions" description="Availability comes from the core, not a guessed operating-system checklist." /><div className="capability-list">{(capabilities?.methods ?? []).map((capability) => {
      const available = capability.available && runtime?.state === 'available' && !preview;
      return <div key={capability.method}><span className="capability-icon"><Icon name="list" size={19} /></span><div><strong>{methodLabels[capability.method] ?? capability.method}</strong><p>{preview ? 'Illustration only; no core service is connected.' : capability.reason}</p></div><Badge tone={available ? 'info' : 'neutral'}>{available ? 'Available · passive' : 'Unavailable'}</Badge></div>;
    })}</div>{!capabilities && <p>No core capability inventory has been loaded.</p>}<p className="save-note">Native editing has separate owned-session capabilities. Passive functions never enable signing, builds or release operations.</p></section>
    {capabilities && capabilities.limitations.length > 0 && <section className="card"><SectionHeading title="Engine-reported boundaries" /><ul className="plain-list">{capabilities.limitations.map((limitation, index) => <li key={index}><Icon name="shield" size={16} /><span>{limitation}</span></li>)}</ul></section>}
  </>;
}
