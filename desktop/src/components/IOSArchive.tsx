import { useId } from 'react';
import type { IOSArchiveController, IOSArchiveState } from '../iosArchive.ts';
import { iosArchiveHelp, iosArchiveInputHelp, iosArchiveSelectionHelp, iosArchiveOutputHelp, iosArchiveCancelHelp, iosArchiveOwnerReason } from '../iosArchive.ts';
import { IOS_ARCHIVE_ROLES, iosArchiveAvailabilityText, iosArchiveFindingText, iosArchiveLimitationText, iosArchiveReasonText } from '../iosArchiveProtocol.ts';
import type { IOSArchiveCoreStatus, IOSArchivePhase, IOSArchiveRole, IOSArchiveStage } from '../iosArchiveTypes.ts';
import type { HelpContent } from '../types.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const phases: Record<IOSArchivePhase, string> = { 'awaiting-consent': 'Awaiting your approval', starting: 'Starting archive',
  running: 'Archive running', stopping: 'Stopping · waiting for cleanup', terminal: 'Archive request finished', unknown: 'Cleanup needs attention' };
const stages: Record<IOSArchiveStage, string> = { accepted: 'Request accepted', 'inputs-bound': 'Saved inputs bound',
  'checking-xcode': 'Checking full Xcode and iOS SDK', preparing: 'Running saved project preparation', archiving: 'Creating unsigned archive',
  inspecting: 'Inspecting archive identity and symbols', 'disposing-snapshot': 'Disposing inspection snapshot', 'disposing-work': 'Disposing task-owned work' };
const roles: Record<IOSArchiveRole, string> = { 'xcode-version': 'Xcode version', 'ios-sdk': 'iOS SDK selection', prepare: 'Saved preparation', archive: 'Unsigned archive' };
const negative = (status: IOSArchiveCoreStatus) => ['FAIL', 'MISSING', 'BLOCKED', 'INVALID'].includes(status);

// Only the original native completed status supplies this result. A selected
// folder, a path label or a provisional core terminal cannot populate it.
export function IOSArchiveResultView({ state, operationProjectName = null }: { state: IOSArchiveState; operationProjectName?: string | null }) {
  const op = state.status?.operation;
  if (state.mode !== 'native' || op?.phase !== 'terminal' || op.outcome !== 'complete' || !op.result || !op.activity) return null;
  const result = op.result, historical = state.historical || state.integrityFailed || state.nativeBlocked;
  return <section className="offline-report" aria-label="Completed local unsigned iOS archive observation">
    <div className="inline-heading"><h3>Unsigned iOS archive · {operationProjectName ?? op.context.projectId}</h3><Badge tone={historical ? 'warning' : 'info'}>{historical ? 'Historical / retained context' : 'This archive only'}</Badge></div>
    <p><strong>Archive created and structurally checked — not a signed release.</strong> Signing/profile authenticity, IPA export, Store readiness and authenticated source provenance were not assessed.</p>
    <p>Saved version {result.usedVersion.name} · build {result.usedVersion.build}. {result.entries} observed entries · {result.bytes} observed bytes.</p>
    <p>Retained location, relative to this run’s source project: <code>{result.archive}</code>.</p>
    <p>This location is a historical observation, not a file opener, current-file authority or permission to publish or delete.</p>
    <ol className="offline-findings">{op.activity.findings.map((finding, index) => <li key={index}><Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge><span>{iosArchiveFindingText[finding.check]}</span></li>)}</ol>
    <details><summary>What this result does and does not prove</summary><ul>{result.limitations.map((limitation) => <li key={limitation}>{iosArchiveLimitationText[limitation]}</li>)}</ul></details>
  </section>;
}

export function IOSArchive({ state, controller, projectName, operationProjectName, compact = false, onShow, onRefresh, onReadVersion,
  refreshReason = null, versionReason = null, onHelp }: {
  state: IOSArchiveState; controller: IOSArchiveController; projectName: string | null; operationProjectName: string | null;
  compact?: boolean; onShow?: () => void; onRefresh?: () => void; onReadVersion?: () => void;
  refreshReason?: string | null; versionReason?: string | null; onHelp?: (help: HelpContent) => void;
}) {
  const label = useId(), op = state.status?.operation, consent = state.consent, project = state.project;
  const owned = iosArchiveOwnerReason(state);
  if (compact && !owned) return null;
  const prepareReason = controller.prepareReason(), startReason = controller.startReason();
  const cancelRequested = !!op && state.cancelClaimed?.operationId === op.operationId && state.cancelClaimed.ownerGeneration === op.ownerGeneration;
  const controls = <div className="button-row">
    <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={15} />{state.readPending ? 'Reading archive status…' : 'Check archive status'}</button>
    {op && op.phase !== 'terminal' && <button type="button" className="button secondary small" data-mrk-ios-archive-action="cancel" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>{cancelRequested ? 'Cancel requested · waiting for cleanup' : 'Cancel this iOS archive'}</button>}
    {onHelp && <HelpButton content={iosArchiveCancelHelp} onHelp={onHelp} />}
    {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>Show in Releases</button>}
  </div>;
  if (compact) return <section className="notice notice-warning offline-global" aria-label="iOS archive status">
    <Icon name="shield" size={20} /><div><strong>iOS archive · {operationProjectName ?? 'archive project'}</strong>
      <p>{op ? phases[op.phase] : 'Waiting for confirmation of this archive request.'} {owned}</p>{controls}
      <p>Cancel is not rollback. Prior project or network effects are not undone.</p>
    </div>
  </section>;
  const selected = project?.selection;
  return <section className="card offline-preflight" aria-labelledby={label} data-mrk-ios-archive="status" data-phase={op?.phase ?? 'idle'} data-stage={op?.stage ?? ''} data-outcome={op?.outcome ?? ''}>
    <SectionHeading title="Create unsigned iOS archive" description="Archive the saved app with full Xcode, then check identity, version and symbols. No signing, IPA export or Store upload.">
      <Badge tone="warning">Project code executes</Badge>{onHelp && <HelpButton content={iosArchiveHelp} onHelp={onHelp} />}
    </SectionHeading>
    <h3 id={label}>Review the current saved inputs</h3>
    <p><strong>Selected source project:</strong> {projectName ?? 'No project selected'}. {onHelp && <HelpButton content={iosArchiveInputHelp} onHelp={onHelp} />}</p>
    <div className="notice notice-warning"><Icon name="shield" /><p>Only archive a project you trust. Xcode build phases and saved preparation code can run programs, modify files, read account files and use the network. This is not a sandbox. The toolkit requests an unsigned archive and no credentials or Store operation; that does not constrain arbitrary project code. Cancel does not undo prior effects.</p></div>
    {project?.dirtyDraft && <p className="review-caution"><strong>Unsaved draft changes are NOT used.</strong> Your draft is neither saved nor discarded. The saved snapshot below is the archive input.</p>}
    {selected && <div className="session-review"><h4>Saved Xcode selection {onHelp && <HelpButton content={iosArchiveSelectionHelp} onHelp={onHelp} />}</h4>
      <p>{selected.containerKind === 'workspace' ? 'Workspace' : 'Project'}: <code>{selected.container}</code> · scheme: <code>{selected.scheme}</code> · configuration: <code>{selected.configuration}</code>.</p>
      <p>Bundle ID: <code>{selected.bundleId}</code> · symbols policy: {selected.symbolsPolicy} · saved preparation: {selected.preparationConfigured ? 'will execute before archive' : 'not configured'}.</p>
    </div>}
    {project?.savedVersion && <p>Saved version <strong>{project.savedVersion.name}</strong> · build <strong>{project.savedVersion.build}</strong> · source <code>{project.savedVersion.source}</code>.</p>}
    {project?.savedConfig && <details><summary>Saved-input byte comparisons</summary><p>Configuration: {project.savedConfig.bytes} bytes · SHA-256 <code>{project.savedConfig.sha256}</code>.</p>
      {project.savedVersion && <p>Version: {project.savedVersion.bytes} bytes · SHA-256 <code>{project.savedVersion.sha256}</code>.</p>}</details>}
    {project?.inputIssue && <p className="review-caution">{project.inputIssue}</p>}
    <p className="save-note">Refresh saved configuration → Read saved version → Review saved inputs → Create archive. External changes remain possible; these comparisons are not an atomic source checkout.</p>
    <div className="button-row">
      {onRefresh && <button type="button" className="button secondary small" disabled={!project || !!refreshReason || project.snapshotPending} onClick={() => { if (project) controller.snapshotIntent(project.projectId); onRefresh(); }}>Refresh saved configuration</button>}
      {onReadVersion && <button type="button" className="button secondary small" data-mrk-ios-archive-action="observe-version" disabled={!project || !!versionReason || project.versionPending} onClick={() => { controller.versionIntent(); onReadVersion(); }}>Read saved version</button>}
    </div>
    {refreshReason && <p className="save-note">Configuration refresh: {refreshReason}</p>}{versionReason && <p className="save-note">Version read: {versionReason}</p>}
    <p className="save-note">{state.status ? iosArchiveAvailabilityText[state.status.availability] : 'The separate native iOS archive capability has not been observed. Passive checks do not enable it.'}</p>
    {!consent && <><button type="button" className="button" data-mrk-ios-archive-action="review" disabled={prepareReason !== null} onClick={() => void controller.prepare()}>Review saved iOS inputs</button>{prepareReason && <p className="review-caution">{prepareReason}</p>}</>}
    {consent && <div className="session-review" role="group" aria-label="Confirm this saved unsigned iOS archive intent">
      <h3>Create this unsigned archive once?</h3>
      <p>Project <strong>{consent.binding.context.projectId}</strong> · <code>{consent.binding.selection.container}</code> · scheme <code>{consent.binding.selection.scheme}</code> · configuration <code>{consent.binding.selection.configuration}</code>.</p>
      <p>Bundle ID <code>{consent.binding.selection.bundleId}</code> · saved version <strong>{consent.binding.context.savedVersion.name}</strong> · build <strong>{consent.binding.context.savedVersion.build}</strong>.</p>
      <p>Saved preparation {consent.binding.selection.preparationConfigured ? 'will execute' : 'is not configured'}. The resulting archive is retained; it is not a signed IPA.</p>
      <p>This review expires within five minutes of original preparation. Status does not renew it. Saving, refreshing, reading another version, changing selection or leaving an unstarted review retires consent.</p>
      <label className="offline-ack"><input type="checkbox" data-mrk-ios-archive-action="acknowledge" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />
        <span>I trust this project and authorize one unsigned archive of these saved inputs. I understand that project code runs with my account access, my unsaved draft is not used, and cancellation is not rollback. Do not sign, export an IPA or publish a release.</span></label>
      <div className="button-row"><button type="button" className="button" data-mrk-ios-archive-action="start" disabled={startReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>Create unsigned archive</button></div>
      {startReason && <p className="review-caution">{startReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new iOS archive outcome was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution" role="status">The original acknowledgement is unconfirmed. Do not repeat Start. Check original Status to cancel or settle that operation; it cannot create new consent.</p>}
    {op && <div className="session-progress" role="status" aria-live="polite">
      <div className="inline-heading"><h3>Archive status · {operationProjectName ?? op.context.projectId}</h3><Badge tone={op.phase === 'unknown' ? 'warning' : 'neutral'}>{phases[op.phase]}</Badge></div>
      {op.stage && <p>Reached stage: {stages[op.stage]}. A stage is not a completion percentage or proof that cleanup finished.</p>}
      {op.outcome && <p><strong>Outcome:</strong> {op.outcome}</p>}<p>{iosArchiveReasonText[op.reason]}</p>
      {op.activity && <ul>{IOS_ARCHIVE_ROLES.map((role) => { const command = op.activity!.commands[role]; return <li key={role}>{roles[role]}: {command.outcome === 'exited' ? `known exit ${command.exitCode}` : command.outcome === 'unknown' ? 'no usable original outcome' : command.outcome === 'not-configured' ? 'not configured' : 'not dispatched'}.</li>; })}</ul>}
      {op.disposition && <><p>Inspection snapshot: {op.disposition.snapshot}. Task work: {op.disposition.work}. Archive output: {op.disposition.output}.</p>
        {op.disposition.relativeDirectory && <p>Retained operation location: <code>{op.disposition.relativeDirectory}</code>. This is not permission for a blanket cleanup or rerun.</p>}</>}
      {op.activity && op.outcome !== 'complete' && <ol className="offline-findings">{op.activity.findings.map((finding, index) => <li key={index}><Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge><span>{iosArchiveFindingText[finding.check]}</span></li>)}</ol>}
      {state.historical && <p className="review-caution">This is retained original-operation data, not approval for the current editor or selected project.</p>}
    </div>}
    {controls}
    <p className="save-note">Started archives stay app-owned across pages. Unknown cleanup remains blocked; reconnecting cannot reset ownership. {onHelp && <HelpButton content={iosArchiveOutputHelp} onHelp={onHelp} />}</p>
    <IOSArchiveResultView state={state} operationProjectName={operationProjectName} />
  </section>;
}
