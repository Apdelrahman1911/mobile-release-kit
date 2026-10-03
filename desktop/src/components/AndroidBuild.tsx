import { useId } from 'react';
import type { AndroidBuildController, AndroidBuildState } from '../androidBuild.ts';
import { androidToolchainCatalogHelp, androidBuildCancelHelp, androidBuildHelp, androidBuildInputHelp, androidBuildOutputHelp, androidBuildOwnerReason, androidBuildSignatureHelp } from '../androidBuild.ts';
import { ANDROID_BUILD_CORE_STATUSES, ANDROID_BUILD_SIGNER_MESSAGE, androidBuildAvailabilityText, androidBuildFindingText, androidBuildLimitationText, androidBuildReasonText } from '../androidBuildProtocol.ts';
import type { AndroidBuildCoreStatus, AndroidBuildPhase, AndroidBuildStage } from '../androidBuildTypes.ts';
import type { HelpContent } from '../types.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { androidCatalogActive, sameAndroidCatalogSelection } from '../androidToolchainCatalogProtocol.ts';
import { androidToolSourceHelp, androidToolSourcesActive } from '../androidToolSources.ts';
import type { AndroidToolSourceRole, AndroidToolSourcesStatus } from '../androidToolSources.ts';
import { androidToolRegistrationActive, androidToolRegistrationPrerequisiteText, androidToolRegistrationReasonText,
  sameAndroidToolRegistrationIdentity, androidToolServiceActive, sameAndroidToolServiceIdentity } from '../androidToolRegistration.ts';
import type { AndroidToolRegistrationProblem, AndroidToolRegistrationStatus, AndroidToolServiceStatus,
  AndroidToolServiceState, AndroidToolServiceOutcome } from '../androidToolRegistration.ts';

const phases: Record<AndroidBuildPhase, string> = { 'awaiting-consent': 'Awaiting your approval', starting: 'Starting build',
  running: 'Build running', stopping: 'Stopping · waiting for cleanup', terminal: 'Build request finished', unknown: 'Cleanup needs attention' };
const stages: Record<AndroidBuildStage, string> = { accepted: 'Request accepted', 'inputs-bound': 'Saved inputs bound', building: 'Building',
  capturing: 'Capturing post-run AAB', inspecting: 'Inspecting captured bytes', 'disposing-work': 'Disposing task-owned work' };
const negative = (status: AndroidBuildCoreStatus) => ['FAIL', 'MISSING', 'BLOCKED', 'INVALID'].includes(status);

// Shared by Releases and Artifacts. No arbitrary result prop, file opener or
// candidate-evidence shortcut: only the parsed native completed Status supplies
// a result. A provisional core terminal/progress event cannot populate it.
export function AndroidBuildResultView({ state, operationProjectName = null }: { state: AndroidBuildState; operationProjectName?: string | null }) {
  const op = state.status?.operation;
  if (state.mode !== 'native' || op?.phase !== 'terminal' || op.outcome !== 'complete' || !op.result) return null;
  const result = op.result, historical = state.historical || state.integrityFailed || state.nativeBlocked;
  return <section className="offline-report" aria-label="Completed local Android AAB observation">
    <div className="inline-heading"><h3>Local AAB observation · {operationProjectName ?? op.context.projectId}</h3><Badge tone={historical ? 'warning' : 'info'}>{historical ? 'Historical / retained context' : 'This build only'}</Badge></div>
    <p><strong>Complete is not PASS, a fresh build or release approval.</strong> Native completion permits this bounded observation to be shown. It does not establish that these are current source outputs or current-file authority.</p>
    <p>Saved version {result.usedVersion.name} · build {result.usedVersion.build} · module <code>{result.selection.module}</code> · variant <code>{result.selection.variant}</code> · application ID <code>{result.selection.applicationId}</code>.</p>
    <p>Known Gradle exit: {result.command.exitCode}. Structure: {result.assurances.structure}; native manifest: {result.assurances.nativeManifest}; application version: {result.assurances.applicationVersion}.</p>
    {result.artifactValidation.mode === 'upload-signature' ? <>
      <p><strong>Signature integrity:</strong> {result.assurances.signature}. <strong>Saved upload certificate:</strong> {result.assurances.signer === 'matches-saved-upload-certificate' ? 'matches saved upload certificate' : result.assurances.signer}.</p>
      <p>Saved upload-certificate SHA-256: <code>{result.artifactValidation.uploadCertificateSha256}</code>. This is not Play enrollment or comparison with Play’s app-signing key.</p>
    </> : <p>{ANDROID_BUILD_SIGNER_MESSAGE}</p>}
    <p>{result.summary.total} findings · {result.summary.shown} shown · {result.summary.omitted} omitted. Negative findings remain negative even though the task completed.</p>
    <dl className="offline-counts">{ANDROID_BUILD_CORE_STATUSES.map((status) => <div key={status}><dt>{status}</dt><dd>{result.summary.counts[status]}</dd></div>)}</dl>
    <ol className="offline-findings">{result.findings.map((finding) => <li key={finding.ordinal}><Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge><span>{finding.check === 'signer' && result.artifactValidation.mode === 'structure-and-version' ? ANDROID_BUILD_SIGNER_MESSAGE : androidBuildFindingText[finding.check]}</span></li>)}</ol>
    {result.artifacts.map((artifact) => <div key={artifact.logicalName} className="session-review">
      <h4>{artifact.fileName} · redacted local observation</h4>
      <p>{artifact.size} observed bytes · ABIs: {artifact.architectures.length ? artifact.architectures.join(', ') : 'none reported'}{artifact.unknownAbi ? ' · unrecognized ABI content was also observed' : ''}.</p>
      <p>SHA-256: <code>{artifact.sha256}</code></p>
      <p>Freshness: {artifact.freshness}. This is not a path, download link, publication input or permission to adopt/delete a current file.</p>
    </div>)}
    <h4>Limits of this result</h4><ul>{result.limitations.map((limitation) => <li key={limitation}>{androidBuildLimitationText[limitation]}</li>)}</ul>
  </section>;
}

export function AndroidBuild({ state, controller, projectName, operationProjectName, compact = false, onShow, onRefresh, onReadVersion,
  refreshReason = null, versionReason = null, onHelp }: {
  state: AndroidBuildState; controller: AndroidBuildController; projectName: string | null; operationProjectName: string | null;
  compact?: boolean; onShow?: () => void; onRefresh?: () => void; onReadVersion?: () => void;
  refreshReason?: string | null; versionReason?: string | null; onHelp?: (help: HelpContent) => void;
}) {
  const label = useId(), op = state.status?.operation, consent = state.consent, project = state.project;
  const owned = androidBuildOwnerReason(state);
  if (compact && !owned) return null;
  const prepareReason = controller.prepareReason(), startReason = controller.startReason();
  const cancelRequested = !!op && state.cancelClaimed?.operationId === op.operationId && state.cancelClaimed.ownerGeneration === op.ownerGeneration;
  const controls = <div className="button-row">
    <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={15} />{state.readPending ? 'Reading build status…' : 'Check build status'}</button>
    {op && op.phase !== 'terminal' && <button type="button" className="button secondary small" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>{cancelRequested ? 'Cancel requested · waiting for cleanup' : 'Cancel this Android build'}</button>}
    {state.catalogStatus?.availability !== 'unsupported-platform' && <>
      <button type="button" className="button secondary small" disabled={!controller.canCheckCatalogStatus()} onClick={() => void controller.checkCatalogStatus()}>{state.catalogReadPending ? 'Reading tool status…' : 'Check tool status'}</button>
      {androidCatalogActive(state.catalogStatus) && <button type="button" className="button secondary small" disabled={!controller.canCancelCatalog()} onClick={() => controller.cancelCatalog()}>{state.catalogCancelClaimed ? 'Tool cancellation requested' : 'Cancel tool read'}</button>}
    </>}
    {state.toolSources?.availability !== 'unsupported-platform' && state.sourcesListening && <>
      <button type="button" className="button secondary small" disabled={!controller.canCheckToolSources()} onClick={() => void controller.checkToolSources()}>{state.sourcesReadPending ? 'Reading folder status…' : 'Check folder status'}</button>
      {androidToolSourcesActive(state.toolSources) && <button type="button" className="button secondary small" disabled={!controller.canCancelToolSources()} onClick={() => controller.cancelToolSources()}>{state.sourcesCancelClaimed ? 'Folder cancellation requested' : 'Cancel folder selection'}</button>}
    </>}
    {state.toolRegistration?.availability !== 'unsupported-platform' && state.registrationListening && <>
      <button type="button" className="button secondary small" disabled={!controller.canCheckToolRegistration()} onClick={() => void controller.checkToolRegistration()}>{state.registrationReadPending ? 'Reading registration status…' : 'Check registration status'}</button>
      {(androidToolRegistrationActive(state.toolRegistration) || state.toolRegistration?.review) && <button type="button" className="button secondary small" disabled={!controller.canCancelToolRegistration()} onClick={() => controller.cancelToolRegistration()}>{sameAndroidToolRegistrationIdentity(state.registrationCancelClaimed, state.toolRegistration?.operation ?? null)
        ? 'Cancel / discard requested · waiting for settlement' : state.toolRegistration?.review ? 'Discard this source review' : 'Cancel this inspection / copy'}</button>}
    </>}
    {state.toolService?.availability !== 'unsupported-platform' && state.serviceListening && <>
      <button type="button" className="button secondary small" disabled={!controller.canCheckToolServiceStatus()}
        onClick={() => void controller.checkToolServiceStatus()}>{state.serviceReadPending ? 'Reading service status…' : 'Read service action status'}</button>
      {androidToolServiceActive(state.toolService) && <button type="button" className="button secondary small"
        disabled={!controller.canCancelToolService()} onClick={() => controller.cancelToolService()}>
        {sameAndroidToolServiceIdentity(state.serviceCancelClaimed, state.toolService?.operation ?? null)
          ? 'Service cancellation requested · waiting for cleanup' : 'Cancel this service action'}</button>}
    </>}
    {onHelp && <HelpButton content={androidBuildCancelHelp} onHelp={onHelp} />}
    {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>Show in Releases</button>}
  </div>;
  if (compact) return <section className="notice notice-warning offline-global" aria-label="Android build status">
    <Icon name="shield" size={20} /><div><strong>Android tools / build · {operationProjectName ?? projectName ?? 'original application'}</strong>
      <p>{androidToolServiceActive(state.toolService) ? 'Original service setup: ' + state.toolService?.phase + '.' : androidToolRegistrationActive(state.toolRegistration) || state.toolRegistration?.review ? 'Original inspection / registration: ' + state.toolRegistration?.phase + '.' : androidToolSourcesActive(state.toolSources) ? 'Original folder selection: ' + state.toolSources?.phase + '.' : androidCatalogActive(state.catalogStatus) ? 'Original protected-tool read: ' + state.catalogStatus?.phase + '.' : op ? phases[op.phase] : 'Waiting for confirmation of the original request.'} {owned}</p>{controls}
      <p>Cancel is not rollback. Protected copies, project changes, network effects or signed outputs may already exist.</p>
    </div>
  </section>;
  const selected = project?.selection;
  return <section className="card offline-preflight" aria-labelledby={label}>
    <SectionHeading title="Build Android app" description="Build the selected saved configuration, then inspect its AAB. This does not publish a release.">
      <Badge tone="warning">Project code executes</Badge>{onHelp && <HelpButton content={androidBuildHelp} onHelp={onHelp} />}
    </SectionHeading>
    <AndroidToolService state={state} controller={controller} onHelp={onHelp} />
    <AndroidToolSources state={state} controller={controller} onHelp={onHelp} />
    <AndroidToolRegistration state={state} controller={controller} onHelp={onHelp} />
    <AndroidToolchainCatalog state={state} controller={controller} onHelp={onHelp} />
    <h3 id={label}>Review the current saved inputs</h3>
    <p><strong>Selected source project:</strong> {projectName ?? 'No project selected'}. {onHelp && <HelpButton content={androidBuildInputHelp} onHelp={onHelp} />}</p>
    <div className="notice notice-warning"><Icon name="shield" /><p>Only build a project you trust. Gradle and project code can run other programs, modify files, read account files, access the network and sign outputs. The toolkit does not request signing, credential loading or Store operations; that does not constrain arbitrary project code. This is not network isolation or a sandbox. Cancel stops further owned work and waits for original cleanup; it does not undo prior effects.</p></div>
    {project?.dirtyDraft && <p className="review-caution"><strong>Unsaved draft changes are NOT used.</strong> Selection below comes from the current completed saved snapshot, not the editor’s possibly older baseline. Your draft is neither saved nor discarded.</p>}
    {selected && <p>Saved module: <code>{selected.module}</code> · variant (saved or core default): <code>{selected.variant}</code> · application ID: <code>{selected.applicationId}</code>.</p>}
    {project?.savedConfig && <p>Saved configuration: {project.savedConfig.bytes} bytes · SHA-256 <code>{project.savedConfig.sha256}</code>.</p>}
    {project?.savedVersion && <p>Saved version source: <code>{project.savedVersion.source}</code> · version {project.savedVersion.name} · build {project.savedVersion.build} · {project.savedVersion.bytes} bytes · SHA-256 <code>{project.savedVersion.sha256}</code>.</p>}
    {project?.inputIssue && <p className="review-caution">{project.inputIssue}</p>}
    <p className="save-note">Refresh saved configuration → Read saved version → Review saved inputs → Build. External changes remain possible; no atomic checkout, filesystem watcher, fresh output or source binding is promised.</p>
    <div className="button-row">
      {onRefresh && <button type="button" className="button secondary small" disabled={!project || !!refreshReason || project.snapshotPending} onClick={() => { if (project) controller.snapshotIntent(project.projectId); onRefresh(); }}>Refresh saved configuration</button>}
      {onReadVersion && <button type="button" className="button secondary small" disabled={!project || !!versionReason || project.versionPending} onClick={() => { controller.versionIntent(); onReadVersion(); }}>Read saved version</button>}
    </div>
    {refreshReason && <p className="save-note">Configuration refresh: {refreshReason}</p>}{versionReason && <p className="save-note">Version read: {versionReason}</p>}
    <label className="offline-ack"><input type="checkbox" checked={state.verifyUploadSignature}
      disabled={state.pending === 'start' || !!op && !['awaiting-consent', 'terminal'].includes(op.phase)}
      onChange={(event) => controller.setVerifyUploadSignature(event.target.checked)} />
      <span>Also verify upload signature</span></label>
    <p className="save-note">Optional and off by default. Inspects the same captured AAB; it does not sign or upload. Use the upload certificate, not Play’s app-signing certificate. {onHelp && <HelpButton content={androidBuildSignatureHelp} onHelp={onHelp} />}</p>
    {state.verifyUploadSignature && <p>Saved upload-certificate SHA-256: {project?.uploadCertificateSha256 ? <code>{project.uploadCertificateSha256}</code> : 'not available in the completed saved configuration; save the field and refresh first'}.</p>}
    <p className="save-note">{state.status ? androidBuildAvailabilityText[state.status.availability] : 'The separate native Android-build capability has not been observed. Passive checks do not enable it.'}</p>
    {!consent && <><button type="button" className="button" disabled={prepareReason !== null} onClick={() => void controller.prepare()}>Review saved inputs</button>{prepareReason && <p className="review-caution">{prepareReason}</p>}</>}
    {consent && <div className="session-review" role="group" aria-label="Confirm this saved Android-build intent">
      <h3>Build these saved inputs once?</h3>
      <p>Build project: <strong>{consent.binding.context.projectId}</strong>. Module <code>{consent.binding.selection.module}</code>, variant <code>{consent.binding.selection.variant}</code>, application ID <code>{consent.binding.selection.applicationId}</code>.</p>
      <p>Version <strong>{consent.binding.context.savedVersion.name}</strong>, build <strong>{consent.binding.context.savedVersion.build}</strong>, selected source <code>{consent.binding.context.savedVersion.source}</code>.</p>
      <p>Saved configuration SHA-256: <code>{consent.binding.context.savedConfig.sha256}</code>. Saved version SHA-256: <code>{consent.binding.context.savedVersion.sha256}</code>.</p>
      <p>Inspection: {consent.binding.context.artifactValidation.mode === 'upload-signature' ? <>structure, application version and upload signature; saved upload-certificate SHA-256 <code>{consent.binding.context.artifactValidation.uploadCertificateSha256}</code></> : 'structure and application version only; signer not inspected'}.</p>
      {consent.binding.toolchainSelection && <p>Protected Mac tool copy: <code>{consent.binding.toolchainSelection.instance}</code> · catalog generation {consent.binding.toolchainSelection.catalogGeneration}. Changing the tool copy retires this review; full native admission is still required at Build.</p>}
      <p>This review expires no later than five minutes after original preparation. Status refresh never renews it. Save, refresh, new version observation, selection change or leaving this unstarted review retires consent.</p>
      <label className="offline-ack"><input type="checkbox" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />
        <span>I trust this project and authorize one build of these saved Android inputs with the inspection choice above. I understand project-code effects, that my unsaved draft is not used, and that post-run bytes may be reused/stale. {consent.binding.context.artifactValidation.mode === 'upload-signature' ? 'Verify the captured upload signature against this saved certificate; do not sign or upload. ' : 'The signer is not inspected. '}Completion is not release approval.</span></label>
      <div className="button-row"><button type="button" className="button" disabled={startReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>Build Android app</button></div>
      {startReason && <p className="review-caution">{startReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new Android-build outcome was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution" role="status">The original request acknowledgement is unconfirmed. Do not repeat Start. Original Status may help cancel or settle that operation, but cannot create new consent.</p>}
    {op && <div className="session-progress" role="status" aria-live="polite">
      <div className="inline-heading"><h3>Build status · {operationProjectName ?? op.context.projectId}</h3><Badge tone={op.phase === 'unknown' ? 'warning' : 'neutral'}>{phases[op.phase]}</Badge></div>
      {op.stage && <p>Reached stage: {stages[op.stage]}. A stage is not a progress percentage or native completion.</p>}
      {op.outcome && <p><strong>Outcome:</strong> {op.outcome}</p>}<p>{androidBuildReasonText[op.reason]}</p>
      {op.activity && <p>Build command: {op.activity.command.outcome === 'exited' ? `known exit ${op.activity.command.exitCode}` : op.activity.command.outcome === 'not-dispatched' ? 'not dispatched' : 'no usable exit outcome'}.</p>}
      {op.disposition && <p>Task work: {op.disposition.work}. Local artifacts: {op.disposition.artifacts}. Disposition is not permission for blanket deletion or a rerun.</p>}
      {op.activity && op.outcome !== 'complete' && <ol className="offline-findings">{op.activity.findings.map((finding) => <li key={finding.ordinal}><Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge><span>{finding.check === 'signer' && op.context.artifactValidation.mode === 'structure-and-version' ? ANDROID_BUILD_SIGNER_MESSAGE : androidBuildFindingText[finding.check]}</span></li>)}</ol>}
      {state.historical && <p className="review-caution">Retained original-operation data is not permission for the current editor or selected project.</p>}
    </div>}
    {controls}
    <p className="save-note">Leaving Releases keeps a started run’s original Status and Cancel available throughout the app. Unknown cleanup stays blocked; reconnecting cannot reset the owner. {onHelp && <HelpButton content={androidBuildOutputHelp} onHelp={onHelp} />}</p>
    <AndroidBuildResultView state={state} operationProjectName={operationProjectName} />
  </section>;
}


const servicePhases: Record<AndroidToolServiceStatus['phase'], string> = {
  idle: 'Not checked this session', checking: 'Checking the installed service', requesting: 'Requesting system registration',
  'opening-settings': 'Opening the system approval page', settling: 'Waiting for original cleanup', stopping: 'Stopping the original action',
  complete: 'Service action completed', refused: 'Service action refused', cancelled: 'Service action cancelled', unknown: 'Service cleanup is unconfirmed',
};
const serviceStates: Record<AndroidToolServiceState, string> = {
  'not-registered': 'Not registered with macOS', enabled: 'Enabled in macOS', 'requires-approval': 'Approval required in System Settings',
  'not-found': 'The expected service was not found', unavailable: 'No usable service state', error: 'macOS could not provide a usable service state',
};
const serviceOutcomes: Record<AndroidToolServiceOutcome, string> = {
  'not-entered': 'No system action entered', observed: 'Read-only service observation returned',
  'registration-requested': 'Registration request returned', 'already-registered': 'Service was already registered',
  'needs-approval': 'macOS requires your approval', 'settings-requested': 'System Settings open request returned',
  'denied-by-user': 'macOS reported that registration was denied', stopped: 'Action stopped', refused: 'Request refused',
  error: 'System request failed', unknown: 'System outcome is unknown',
};
const serviceHelp: HelpContent = {
  label: 'Android system service on macOS', requiredness: 'conditional',
  requiredWhen: 'Before registering a protected Android tool copy on a supported Mac. Source folders are not required for this setup step.',
  what: 'A fixed helper supplied with the signed app creates protected tool copies. Check reads its installed identity and current macOS state. Registration and opening Settings each require a separate button click.',
  why: 'macOS controls permission for the helper. An enabled service still must authenticate each original copy request; it is not permission to read your selected folders or run a build.',
  where: 'Install a correctly signed Mobile Release Kit release from its publisher. If approval is required, use Open approval settings, then find Mobile Release Kit under General → Login Items (or Login Items & Extensions) and review the system request.',
  format: 'No service name, administrator command, path or certificate is entered here. Select the separate checkbox only when you want this installed helper registered with macOS. Afterwards choose Check installed service again.',
  failure: 'A missing shipping signature must be fixed by the publisher, not with local administrator commands or ad-hoc signing. Denied, awaiting approval and unavailable are different states. Cancel does not unregister or undo a completed system action; keep original Status until cleanup is confirmed.',
};
function AndroidToolService({ state, controller, onHelp }: {
  state: AndroidBuildState; controller: AndroidBuildController; onHelp?: (help: HelpContent) => void;
}) {
  const status = state.toolService, reason = controller.serviceActionReason(), registrationReason = controller.serviceRegistrationReason();
  if (status?.availability === 'unsupported-platform' || !state.serviceListening && !status) return null;
  return <section className="session-review" aria-label="Android system service setup">
    <div className="inline-heading"><h3>Set up the Android system service</h3>{onHelp && <HelpButton content={serviceHelp} onHelp={onHelp} />}</div>
    <p>Check the helper included with the installed Mac app. You can do this before choosing Java, SDK or Gradle folders. Nothing is registered automatically.</p>
    <div className="button-row">
      <button type="button" className="button secondary small" disabled={reason !== null}
        onClick={() => void controller.checkAndroidToolService()}>Check installed service</button>
      <button type="button" className="button secondary small" disabled={reason !== null}
        onClick={() => void controller.openAndroidToolServiceApprovalSettings()}>Open approval settings</button>
    </div>
    <p className="save-note">Check is read-only. Opening System Settings does not approve or register anything. Approve only after reviewing the macOS prompt, then explicitly Check again.</p>
    <label className="offline-ack"><input type="checkbox" checked={state.serviceConsent !== null} disabled={reason !== null}
      onChange={(event) => { if (status) controller.setServiceRegistrationAcknowledged(status.setupGeneration, event.target.checked); }} />
      <span>I authorize one registration request for the fixed Android helper supplied with this signed app. This is not approval to copy tools, accept vendor licenses, build, sign or publish a release.</span></label>
    <button type="button" className="button secondary" disabled={registrationReason !== null}
      onClick={() => void controller.requestAndroidToolServiceRegistration()}>Request system-service registration</button>
    {reason ? <p className="review-caution">{reason}</p> : registrationReason && <p className="save-note">{registrationReason}</p>}
    {status && <div role="status" aria-live="polite">
      <p><strong>{servicePhases[status.phase]}.</strong> {status.operation && <>Original project: {status.operation.context.projectId}.</>}</p>
      {status.observation && <p>{serviceStates[status.observation.state]}. {serviceOutcomes[status.observation.outcome]}.</p>}
      {status.reason !== 'none' && <p>{androidToolRegistrationReasonText[status.reason]}</p>}
      {status.observation?.mutationReturned && <p className="save-note">A system action actually returned. Cancellation cannot undo that action.</p>}
    </div>}
    <p className="save-note">A completed setup check is not protected-copy consent or proof that a future connection will work. Register tools performs its own fresh identity/service check and authentication.</p>
    {state.serviceUnconfirmed && <p className="review-caution">The original service reply is unconfirmed. Read service action status below; do not repeat registration. Cancel uses only that original action.</p>}
    {state.serviceError && <ErrorNotice error={state.serviceError} title="No new service outcome was confirmed" />}
  </section>;
}

const sourceRoles: AndroidToolSourceRole[] = ['jdk', 'sdk', 'gradle'];
const sourcePhase: Record<AndroidToolSourcesStatus['phase'], string> = {
  idle: 'No folder selected yet', picking: 'Choose a folder in the native dialog', checking: 'Checking the selected directory',
  selected: 'Original folder selection retained', refused: 'Folder selection could not be used', cancelled: 'Folder selection cancelled',
  stopping: 'Stopping · waiting for the original folder selection to close', unknown: 'Original folder cleanup could not be confirmed',
};
const sourceReason: Record<AndroidToolSourcesStatus['reason'], string> = {
  none: '', 'not-inspected': 'Folder selection alone is not supplier inspection or a protected copy. Check the separate original registration Status.',
  cancelled: 'The native folder dialog was closed without selecting a folder.',
  'source-refused': 'Choose a real, readable local folder, not an alias or archive. This check does not inspect the tools inside it.',
  'source-changed': 'The folder changed while it was being observed. Once cleanup is confirmed, browse again.',
  'timed-out': 'The original selection reached its time limit. Wait for cleanup before browsing again.',
  'context-changed': 'The selected project changed. Choose folders for the current project after the original selection settles.',
  'document-lost': 'The original app window is no longer available. Do not assume its work has finished.',
  shutdown: 'The app is closing the original selection before it exits.',
  'cleanup-unknown': 'Status cannot prove that the original work is closed. Further actions remain blocked; a retry does not resolve this.',
};
function AndroidToolSources({ state, controller, onHelp }: {
  state: AndroidBuildState; controller: AndroidBuildController; onHelp?: (help: HelpContent) => void;
}) {
  const sources = state.toolSources, reason = controller.sourceActionReason();
  if (sources?.availability === 'unsupported-platform') return null;
  const sameProject = sources?.projectId === state.project?.projectId;
  return <section className="session-review" aria-label="Set up Android tools">
    <h3>Set up Android tools</h3>
    <p>Choose the Java, Android SDK and Gradle folders already installed on this Mac. Use Browse; you do not need to copy, rename or move anything.</p>
    <p className="save-note">This step only remembers the selected directories for this app session. It does not execute, install or change them. Browsing alone neither inspects supplier contents nor registers a copy; separate inspection and protected-copy approval stay disabled until their actual prerequisites are available.</p>
    {sourceRoles.map((role) => {
      const help = androidToolSourceHelp[role], selected = sameProject ? sources?.selections.find((item) => item.role === role) : null;
      return <div className="session-review" key={role}>
        <div className="inline-heading"><h4>{help.label}</h4>{onHelp && <HelpButton content={help} onHelp={onHelp} />}</div>
        <p>{help.what}</p><p className="save-note">{help.where}</p>
        <p className="save-note">Required before registering Android tools. {selected ? <>Selected folder: <strong>{selected.displayName}</strong> · folder selection only.</> : 'No folder selected for this project.'}</p>
        <button type="button" className="button secondary small" disabled={reason !== null}
          onClick={() => void controller.chooseToolSource(role)}>{selected ? 'Choose a different folder' : 'Browse for folder'}</button>
      </div>;
    })}
    {reason && <p className="save-note">{reason}</p>}
    {sources && <p role="status" aria-live="polite"><strong>{sourcePhase[sources.phase]}.</strong> {sourceReason[sources.reason]}</p>}
    {sources?.projectId && !sameProject && <p className="review-caution">The retained folder status belongs to a different project; it is not a selection for this one.</p>}
    {state.sourcesUnconfirmed && <p className="review-caution">The original folder request is unconfirmed. Use Check folder status below; do not repeat Browse. Cancel becomes available when the original identity is known.</p>}
    {state.sourcesError && <ErrorNotice error={state.sourcesError} title="No new folder-selection outcome was confirmed" />}
  </section>;
}

const registrationPhases: Record<AndroidToolRegistrationStatus['phase'], string> = {
  idle: 'Sources not inspected', inspecting: 'Inspecting original sources', review: 'Source review ready',
  preparing: 'Checking the installed service · no files transferred yet',
  copying: 'Copying into protected storage', verifying: 'Verifying the protected copy',
  publishing: 'Publishing the registration', settling: 'Waiting for original cleanup',
  stopping: 'Stopping · waiting for original cleanup', complete: 'Protected copy published',
  refused: 'Inspection or registration refused', cancelled: 'Original operation cancelled',
  unknown: 'Original cleanup is unconfirmed',
};
const registrationProblems: Record<AndroidToolRegistrationProblem, string> = {
  binding: 'Original input binding changed', bounds: 'A fixed input or result limit was reached',
  'supplier-unavailable': 'Official supplier correspondence is unavailable', inventory: 'Content inventory was refused',
  ownership: 'Required file ownership was not established', collision: 'A protected destination already exists',
  native: 'Native operation failed', stopped: 'The original operation was stopped',
  unknown: 'An original native outcome is unconfirmed', transfer: 'Content transfer failed',
  persist: 'Protected output persistence failed', admission: 'Original admission was refused',
  unavailable: 'A required original service or resource is unavailable',
};
const registrationHelp: HelpContent = {
  label: 'Inspect and register Android tools', requiredness: 'conditional',
  requiredWhen: 'Before using new JDK, Android SDK and Gradle sources for a protected Mac tool copy.',
  what: 'Inspect the exact selected originals, review their compatible contents, then separately acknowledge vendor licenses and approve one protected copy. Inspection alone accepts no license and authorizes no copy.',
  why: 'Folder names, local hashes and version labels cannot replace official supplier correspondence or permission to use the genuinely installed service.',
  where: 'Use the three Browse controls for official JDK, SDK and Gradle installations. The app supplies its fixed bundletool and matching AAPT2 originals separately; ambient Gradle caches and extra picker folders are not substitutes.',
  format: 'The private review binds saved inputs, complete source observations, the exact proposal and original service prerequisites. Displayed source totals cover the three picked roles only, not the separate fixed support group.',
  failure: 'A changed, expired or incomplete review is refused. Missing supplier, signing, approval or fresh service prerequisites stay unavailable. Cancel is not rollback; retained partial output is not eligible for selection or permission to delete.',
};
function AndroidToolRegistration({ state, controller, onHelp }: {
  state: AndroidBuildState; controller: AndroidBuildController; onHelp?: (help: HelpContent) => void;
}) {
  const status = state.toolRegistration, consent = state.registrationConsent, review = status?.review;
  if (status?.availability === 'unsupported-platform') return null;
  const inspectReason = controller.inspectToolSourcesReason(), registerReason = controller.registerToolSourcesReason();
  const report = state.mode === 'native' && !state.integrityFailed && !state.nativeBlocked
    && status && ['complete', 'refused', 'cancelled'].includes(status.phase) ? status.report : null;
  return <section className="session-review" aria-label="Inspect and register Android tools">
    <div className="inline-heading"><h3>Inspect and register Android tools</h3>{onHelp && <HelpButton content={registrationHelp} onHelp={onHelp} />}</div>
    <p>Inspect the three selected source folders before approving a protected copy. Inspection does not run a build, accept vendor licenses or authorize registration.</p>
    <p className="save-note">The app also supplies its fixed bundletool 1.18.3 and matching AAPT2 support tools. Their original bytes and supplier correspondence must be available; no Gradle cache, extra picker folder or manual copy can replace them.</p>
    <p className="save-note">{status ? androidToolRegistrationPrerequisiteText[status.prerequisite]
      : 'Protected-copy prerequisites have not been observed. No supplier, signing, approval or service availability is assumed.'}</p>
    <button type="button" className="button secondary small" disabled={inspectReason !== null}
      onClick={() => void controller.inspectToolSources()}>{state.registrationPending === 'inspect' ? 'Requesting source inspection…' : 'Inspect selected sources'}</button>
    {inspectReason && <p className="save-note">{inspectReason}</p>}
    {status && <div className="session-progress" role="status" aria-live="polite">
      <div className="inline-heading"><h4>{registrationPhases[status.phase]}</h4><Badge tone={status.phase === 'unknown' ? 'warning' : 'neutral'}>{status.operation?.kind ?? 'not started'}</Badge></div>
      {status.operation && <p>Original project: <strong>{status.operation.context.projectId}</strong>. Saved version {status.operation.context.savedVersion.name} · build {status.operation.context.savedVersion.build}.</p>}
      <p>{androidToolRegistrationReasonText[status.reason]}</p>
    </div>}
    {review && <div className="session-review" role="group" aria-label="Confirm this exact protected-copy review">
      <h4>Register these inspected sources once?</h4>
      <p>Original source project: <strong>{review.context.projectId}</strong>. Saved configuration SHA-256: <code>{review.context.savedConfig.sha256}</code>. Saved version SHA-256: <code>{review.context.savedVersion.sha256}</code>.</p>
      <ul>{review.sources.map((source) => <li key={source.role}><strong>{androidToolSourceHelp[source.role].label}</strong>: {source.version} · {source.logicalBytes} logical bytes · {source.files} files · {source.aliases} aliases · {source.entries} entries · complete compatible role observation.</li>)}</ul>
      <p className="save-note">These are picked-role subtotals, not whole-copy or disk-usage totals. The private review also includes the separate fixed app-provided support originals within the same native limits.</p>
      <p>This copy includes the reviewed JDK and Gradle distributions, selected SDK platform/build-tools contents and fixed support tools. It does not modify the selected source folders. No project build, signing or upload is authorized by registration.</p>
      <p>Review expires no later than five minutes after this inspection request in this view; native finalized-review expiry is enforced separately. Status never renews it. Changed saved inputs, changed sources or leaving an unstarted review retires consent.</p>
      {consent ? <>
        <label className="offline-ack"><input type="checkbox" checked={consent.acknowledged}
          onChange={(event) => controller.setRegistrationAcknowledged(consent.operationId, consent.registrationGeneration, consent.reviewId, event.target.checked)} />
          <span>I acknowledge the applicable vendor licenses for these inspected tools, including the app-provided support tools, and approve one copy of this exact review into protected storage. I understand that Cancel is not rollback, partial files may remain, and a published copy is not yet selected or approved for Build.</span></label>
        <button type="button" className="button" disabled={registerReason !== null}
          onClick={() => void controller.registerToolSources(consent.operationId, consent.registrationGeneration, consent.reviewId)}>Register protected tool copy</button>
        {registerReason && <p className="review-caution">{registerReason}</p>}
      </> : <p className="review-caution">This view cannot adopt that review as consent. Use the original Status and Discard review below; inspect again only after original settlement.</p>}
    </div>}
    {state.registrationUnconfirmed && <p className="review-caution" role="status">The original inspection or copy reply is unconfirmed. Do not repeat the action. Keep original Status; Cancel becomes available when its exact identity is known.</p>}
    {state.registrationCancelPending && <p className="save-note">The original Cancel / Discard reply is still pending. A visible terminal event does not permit a new request before that reply settles.</p>}
    {state.registrationError && <ErrorNotice error={state.registrationError} title="No new source-inspection or protected-copy outcome was confirmed" />}
    {report && <section className="offline-report" aria-label="Final original protected-copy observation">
      <h4>Final original observation</h4>
      <p>Protected copy: <strong>{report.protectedCopy === 'published' ? 'published' : report.protectedCopy === 'retained-partial' ? 'retained partial output' : 'not created'}</strong>. This is not current-file authority, catalog eligibility, permission to delete, or a successful build.</p>
      {report.sources.length > 0 && <ul>{report.sources.map((source) => <li key={source.role}>{androidToolSourceHelp[source.role].label}: {source.version ?? 'version not established'} · {source.logicalBytes} observed logical bytes · {source.files} files · {source.aliases} aliases · {source.complete ? 'complete role observation' : 'partial observed subtotal; omitted input is not zero'} · {source.compatibility}.</li>)}</ul>}
      {report.accounting && <p>Helper observations: {report.accounting.writtenBytes} written bytes · {report.accounting.observedLogicalBytes} logical bytes · {report.accounting.observedAllocatedBytes} allocated bytes · {report.accounting.contentFiles} content files · {report.accounting.contentAliases} aliases. {report.accounting.complete ? 'The bounded accounting observation is complete for this original.' : 'Accounting is partial; it is not a census of all retained files or disk usage.'}</p>}
      <p>{report.problems.recorded} recorded problems · {report.problems.shown} shown · {report.problems.omitted} omitted. This is a bounded recorded prefix, not a census of all possible errors.</p>
      {report.problems.items.length > 0 && <ol>{report.problems.items.map((problem, index) => <li key={index}>{registrationProblems[problem]}</li>)}</ol>}
      {report.protectedCopy === 'published' && <p>After settlement, explicitly Refresh tool list, Recover the copy for full verification, then Choose it. Nothing is auto-recovered, selected or built.</p>}
      <p>Cancel does not undo a protected copy. Retained partial output is neither build-ready nor permission to remove shared directories or caches.</p>
    </section>}
  </section>;
}

function AndroidToolchainCatalog({ state, controller, onHelp }: {
  state: AndroidBuildState; controller: AndroidBuildController; onHelp?: (help: HelpContent) => void;
}) {
  const catalog = state.catalogStatus, reason = controller.catalogActionReason();
  if (catalog?.availability === 'unsupported-platform') return null;
  const rowText = {
    busy: 'Busy — another original is using or changing this instance. No selection is available.',
    interrupted: 'Interrupted — this instance has incomplete registration state. It grants no permission to repair or delete files.',
    refused: 'Refused — this original instance could not be authenticated. No selectable copy was established.',
    'recovery-required': 'Metadata only — use Recover for full original tool and registration verification in this session.',
    'verified-this-session': 'Full original readback verified in this session. Choose is still a separate action; Build admits the originals again.',
  };
  return <section className="session-review" aria-label="Protected Android tools on this Mac">
    <div className="inline-heading"><h3>Choose Android tools</h3>{onHelp && <HelpButton content={androidToolchainCatalogHelp} onHelp={onHelp} />}</div>
    <p>Refresh the metadata list, explicitly Recover one protected copy for full verification, then Choose that verified copy for your build.</p>
    <p className="save-note">Refresh alone never makes a copy selectable. Recover only reads and authenticates existing originals; it does not install, repair or delete tools or accept a license. Version labels describe a supported tuple, not compatibility with your project.</p>
    <button type="button" className="button secondary small" disabled={reason !== null} onClick={() => void controller.refreshCatalog()}>{state.catalogPending === 'refresh' ? 'Requesting tool list…' : 'Refresh tool list'}</button>
    {reason && <p className="save-note">{reason}</p>}
    {catalog && <p role="status">Tool catalog: {catalog.phase}. {catalog.reason === 'none' ? '' : catalog.reason.replaceAll('-', ' ')}.</p>}
    {catalog?.phase === 'ready' && catalog.entries.length === 0 && <p>No protected registration, destination or lease instance was found for this macOS account.</p>}
    {catalog?.entries.map((entry) => {
      const selected = entry.selection !== null && sameAndroidCatalogSelection(catalog.selected, entry.selection);
      return <div className="session-review" key={entry.instance}>
        <div className="inline-heading"><h4>{entry.versions ? entry.versions.jdkVendor + ' Java ' + entry.versions.jdkVersion : 'Protected tool instance'}</h4>
          {selected && <Badge tone="info">Selected</Badge>}</div>
        {entry.versions && <p>Gradle {entry.versions.gradleVersion} · Android plugin {entry.versions.agpVersion} · {entry.versions.sdkPlatform} · build tools {entry.versions.sdkBuildToolsVersion}.</p>}
        <p className="save-note">Instance <code>{entry.instance}</code> · observed catalog {catalog.catalogGeneration}.</p>
        <p>{rowText[entry.status]}</p>
        {entry.status === 'recovery-required' && <button type="button" className="button secondary small" disabled={reason !== null}
          onClick={() => void controller.recoverToolchain(entry.instance, entry.recovery.recordSha256)}>
          {state.catalogPending === 'recover' ? 'Requesting full recovery verification…' : 'Recover (full verification)'}</button>}
        {entry.status === 'verified-this-session' && <button type="button" className="button secondary small" disabled={selected || reason !== null}
          onClick={() => void controller.selectToolchain(entry.instance, entry.selection.recordSha256)}>{selected ? 'This copy is selected' : 'Choose this tool copy'}</button>}
      </div>;
    })}
    <p className="save-note">Browse above to choose source folders, inspect them, then explicitly approve protected registration when its prerequisites are available. A published copy is never selected automatically. Build still compares the project's original Gradle wrapper URL and SHA-256 and performs fresh runtime/tool admission.</p>
    {state.catalogCancelPending && <p className="review-caution">The original catalog cancellation invoke is still pending. A terminal event does not release that pending request.</p>}
    {state.catalogUnconfirmed && <p className="review-caution">The original catalog request is unconfirmed. Use Check tool status or Cancel tool read below; do not repeat the request.</p>}
    {state.catalogError && <ErrorNotice error={state.catalogError} title="No new tool-catalog outcome was confirmed" />}
  </section>;
}
