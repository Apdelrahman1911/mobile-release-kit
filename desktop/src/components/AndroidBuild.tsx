import { useId } from 'react';
import type { AndroidBuildController, AndroidBuildState } from '../androidBuild.ts';
import { androidBuildCancelHelp, androidBuildHelp, androidBuildInputHelp, androidBuildOutputHelp, androidBuildOwnerReason, androidBuildSignatureHelp } from '../androidBuild.ts';
import { ANDROID_BUILD_CORE_STATUSES, ANDROID_BUILD_SIGNER_MESSAGE, androidBuildAvailabilityText, androidBuildFindingText, androidBuildLimitationText, androidBuildReasonText } from '../androidBuildProtocol.ts';
import type { AndroidBuildCoreStatus, AndroidBuildPhase, AndroidBuildStage } from '../androidBuildTypes.ts';
import type { HelpContent } from '../types.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

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
    {onHelp && <HelpButton content={androidBuildCancelHelp} onHelp={onHelp} />}
    {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>Show in Releases</button>}
  </div>;
  if (compact) return <section className="notice notice-warning offline-global" aria-label="Android build status">
    <Icon name="shield" size={20} /><div><strong>Android build · {operationProjectName ?? 'build project'}</strong>
      <p>{op ? phases[op.phase] : 'Waiting for confirmation of this build request.'} {owned}</p>{controls}
      <p>Cancel is not rollback. Project changes, network effects or signed outputs may already exist.</p>
    </div>
  </section>;
  const selected = project?.selection;
  return <section className="card offline-preflight" aria-labelledby={label}>
    <SectionHeading title="Build Android app" description="Build the selected saved configuration, then inspect its AAB. This does not publish a release.">
      <Badge tone="warning">Project code executes</Badge>{onHelp && <HelpButton content={androidBuildHelp} onHelp={onHelp} />}
    </SectionHeading>
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
