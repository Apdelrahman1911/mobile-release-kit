import { useId } from 'react';
import type { IOSArchiveController, IOSArchiveState } from '../iosArchive.ts';
import { iosArchiveHelp, iosArchiveInputHelp, iosArchiveSelectionHelp, iosArchiveOutputHelp, iosArchiveCancelHelp, iosSigningHelp, iosRecoveryHelp, iosArchiveOwnerReason } from '../iosArchive.ts';
import { isIOSRecoveryOperation, sameIOSArchiveData, sameIOSArchiveIdentity, sameIOSArchiveSavedPair, iosArchiveRoles, iosArchiveAvailabilityText, iosArchiveModeAvailability, iosArchiveFindingText, iosArchiveLimitationText, iosArchiveReasonText } from '../iosArchiveProtocol.ts';
import type { IOSArchiveCoreStatus, IOSArchivePhase, IOSArchiveRole, IOSArchiveStage, IOSRecoveryRowState } from '../iosArchiveTypes.ts';
import type { HelpContent } from '../types.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const phases: Record<IOSArchivePhase, string> = { 'awaiting-consent': 'Awaiting your approval', starting: 'Starting iOS operation',
  running: 'iOS operation running', stopping: 'Stopping · waiting for cleanup', terminal: 'iOS request finished', unknown: 'Cleanup needs attention' };
const stages: Record<IOSArchiveStage, string> = { accepted: 'Request accepted', 'inputs-bound': 'Saved inputs bound',
  'checking-xcode': 'Checking full Xcode and iOS SDK', preparing: 'Running saved project preparation', archiving: 'Creating the reviewed archive',
  'validating-signing': 'Validating original signing material and saved policy', 'materializing-signing': 'Preparing owned signing and build inputs',
  exporting: 'Exporting the local signed IPA', 'restoring-signing': 'Restoring original signing and build-input state',
  inspecting: 'Inspecting the original archive and any exported IPA', 'disposing-snapshot': 'Disposing inspection snapshot', 'disposing-work': 'Disposing task-owned work',
  'recovering-account': 'Inspecting or recovering the reviewed account signing state', 'recovering-project': 'Inspecting or recovering the reviewed project build-input state' };
const roles: Record<IOSArchiveRole, string> = { 'xcode-version': 'Xcode version', 'ios-sdk': 'iOS SDK selection', prepare: 'Saved preparation', archive: 'Archive', export: 'Local IPA export' };
const negative = (status: IOSArchiveCoreStatus) => ['FAIL', 'MISSING', 'BLOCKED', 'INVALID'].includes(status);

// Traceability of the parsed current unsigned original only. These visible IDs
// do not select files, grant consent or qualify an archive's current contents.
function UnsignedArchiveDetails({ state, review = false }: { state: IOSArchiveState; review?: boolean }) {
  const op = state.status?.operation, project = state.project;
  if (state.mode !== 'native' || state.archiveMode !== 'unsigned' || !op || isIOSRecoveryOperation(op) ||
      op.context.operation !== 'ios-unsigned-archive' || state.historical || state.integrityFailed || state.nativeBlocked ||
      state.originalUnconfirmed || state.generationLost || state.selectionPending || !project?.savedConfig || !project.savedVersion ||
      project.inputIssue !== null || op.context.projectId !== project.projectId || op.context.draftRevision !== project.draftRevision ||
      op.context.baselineGeneration !== project.baselineGeneration ||
      !sameIOSArchiveSavedPair(op.context, { savedConfig: project.savedConfig, savedVersion: project.savedVersion })) return null;
  if (review) {
    const consent = state.consent;
    if (!consent || op.phase !== 'awaiting-consent' || !op.intentUsable || !sameIOSArchiveIdentity(op, consent) ||
        !sameIOSArchiveData(op.context, consent.binding.context) || !sameIOSArchiveData(project.selection, consent.binding.selection) ||
        consent.binding.connectionGeneration !== state.connectionGeneration || consent.binding.selectionGeneration !== state.selectionGeneration ||
        consent.binding.contextGeneration !== state.contextGeneration || consent.binding.requestGeneration !== state.requestGeneration ||
        consent.binding.observationGeneration !== project.observationGeneration ||
        !sameIOSArchiveData(consent.binding.versionObservation, project.versionObservation)) return null;
  }
  return <div role="group" aria-label="Archive details">
    <h4>Archive details</h4>
    <p>Archive operation ID: {op.operationId}</p>
    <p>Archive owner generation: {op.ownerGeneration}</p>
  </div>;
}

// Only the original native completed status supplies this result. A selected
// folder, a path label or a provisional core terminal cannot populate it.
export function IOSArchiveResultView({ state, operationProjectName = null }: { state: IOSArchiveState; operationProjectName?: string | null }) {
  const op = state.status?.operation;
  if (state.mode !== 'native' || !op || isIOSRecoveryOperation(op) || op.phase !== 'terminal' || op.outcome !== 'complete' || !op.result || !op.activity) return null;
  const result = op.result, historical = state.historical || state.integrityFailed || state.nativeBlocked;
  const signed = result.scope === 'local-signed-ios-artifact-validation';
  return <section className="offline-report" aria-label={signed ? 'Completed local signed iOS artifact validation' : 'Completed local unsigned iOS archive observation'}>
    <div className="inline-heading"><h3>{signed ? 'Local signed iOS IPA' : 'Unsigned iOS archive'} · {operationProjectName ?? op.context.projectId}</h3><Badge tone={historical ? 'warning' : 'info'}>{historical ? 'Historical / retained context' : 'This local artifact only'}</Badge></div>
    {signed ? <p><strong>Signed IPA exported and validated against this retained archive.</strong> Review the core identity, signer, profile, entitlements and correspondence findings below. This is not Store readiness, authenticated source provenance or permission to publish.</p> : <p><strong>Archive created and structurally checked — not a signed release.</strong> Signing/profile authenticity, IPA export, Store readiness and authenticated source provenance were not assessed.</p>}
    <UnsignedArchiveDetails state={state} />
    <p>Saved version {result.usedVersion.name} · build {result.usedVersion.build}. {result.entries} observed entries · {result.bytes} observed bytes.</p>
    <p>Retained location, relative to this run’s source project: <code>{result.archive}</code>.</p>
    {result.scope === 'local-signed-ios-artifact-validation' && <><p>Retained IPA: <code>{result.ipa}</code> · {result.ipaBytes} observed bytes.</p>
      <p>Paired native paths: {result.pairing.nativePaths} · native identities: {result.pairing.nativeIdentities} · present symbol slices: {result.pairing.presentSymbolSlices}.</p>
      <p>The original native owner withheld this result until its required signing, build-input, material, inspection and worker lifetimes settled. A future recovery inspection remains a separate action.</p></>}
    <p>This location is a historical observation, not a file opener, current-file authority or permission to publish or delete.</p>
    <ol className="offline-findings">{op.activity.findings.map((finding, index) => <li key={index}><Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge><span>{iosArchiveFindingText[finding.check]}</span></li>)}</ol>
    <details><summary>What this result does and does not prove</summary><ul>{result.limitations.map((limitation) => <li key={limitation}>{iosArchiveLimitationText[limitation]}</li>)}</ul></details>
  </section>;
}

export function IOSArchive({ state, controller, projectName, operationProjectName, compact = false, onShow, onRefresh, onReadVersion, onCredentials, onSettings, onRecovery,
  refreshReason = null, versionReason = null, onHelp }: {
  state: IOSArchiveState; controller: IOSArchiveController; projectName: string | null; operationProjectName: string | null;
  compact?: boolean; onShow?: () => void; onRefresh?: () => void; onReadVersion?: () => void;
  onCredentials?: () => void; onSettings?: () => void; onRecovery?: () => void;
  refreshReason?: string | null; versionReason?: string | null; onHelp?: (help: HelpContent) => void;
}) {
  const label = useId(), op = state.status?.operation, consent = state.consent, project = state.project;
  const signed = state.archiveMode === 'signed';
  const owned = iosArchiveOwnerReason(state);
  if (compact && !owned) return null;
  const prepareReason = controller.prepareReason(), startReason = controller.startReason();
  const cancelRequested = !!op && state.cancelClaimed?.operationId === op.operationId && state.cancelClaimed.ownerGeneration === op.ownerGeneration;
  const controls = <div className="button-row">
    <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={15} />{state.readPending ? 'Reading archive status…' : 'Check archive status'}</button>
    {op && op.phase !== 'terminal' && <button type="button" className="button secondary small" data-mrk-ios-archive-action="cancel" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>{cancelRequested ? 'Cancel requested · waiting for cleanup' : 'Cancel this iOS archive'}</button>}
    {onHelp && <HelpButton content={iosArchiveCancelHelp} onHelp={onHelp} />}
    {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>{op && isIOSRecoveryOperation(op) ? 'Show in Recovery' : 'Show in Releases'}</button>}
  </div>;
  if (compact) return <section className="notice notice-warning offline-global" aria-label="iOS archive status">
    <Icon name="shield" size={20} /><div><strong>iOS archive · {operationProjectName ?? 'archive project'}</strong>
      <p>{op ? phases[op.phase] : 'Waiting for confirmation of this archive request.'} {owned}</p>{controls}
      <p>Cancel is not rollback. Prior project or network effects are not undone.</p>
    </div>
  </section>;
  const selected = project?.selection;
  return <section className="card offline-preflight" aria-labelledby={label} data-mrk-ios-archive="status" data-phase={op?.phase ?? 'idle'} data-stage={op?.stage ?? ''} data-outcome={op?.outcome ?? ''}>
    <SectionHeading title={signed ? 'Sign and export a local iOS IPA' : 'Create unsigned iOS archive'} description={signed ? 'Use assigned session inputs to archive, export and validate one local IPA. No Store upload or symbol uploader.' : 'Archive the saved app with full Xcode, then check identity, version and symbols. No signing, IPA export or Store upload.'}>
      <Badge tone="warning">Project code executes</Badge>{onHelp && <HelpButton content={iosArchiveHelp} onHelp={onHelp} />}
    </SectionHeading>
    <fieldset className="session-context" disabled={state.pending === 'start' || !!op && !['awaiting-consent', 'terminal'].includes(op.phase)}><legend>Choose this local operation</legend>
      <label className="offline-ack"><input type="radio" name={`${label}-mode`} checked={!signed} onChange={() => controller.setArchiveMode('unsigned')} /><span>Unsigned archive · no signing or IPA export</span></label>
      <label className="offline-ack"><input type="radio" name={`${label}-mode`} checked={signed} onChange={() => controller.setArchiveMode('signed')} /><span>Sign and export IPA · separately admitted local signing</span></label>
      <p>Changing modes retires any unstarted review. Neither mode publishes or authenticates source provenance.</p>
    </fieldset>
    <h3 id={label}>Review the current saved inputs</h3>
    <p><strong>Selected source project:</strong> {projectName ?? 'No project selected'}. {onHelp && <HelpButton content={iosArchiveInputHelp} onHelp={onHelp} />}</p>
    <div className="notice notice-warning"><Icon name="shield" /><p>Only archive a project you trust. Xcode build phases and saved preparation code can run programs, modify files, read account files and use the network. This is not a sandbox. {signed ? 'Signed export borrows the assigned P12/password/profile and the admitted account signing state. No toolkit Store upload, provisioning download or symbol uploader is requested.' : 'The toolkit requests an unsigned archive and no credentials or Store operation; that does not constrain arbitrary project code.'} Cancel does not undo prior effects.</p></div>
    {project?.dirtyDraft && <p className="review-caution"><strong>Unsaved draft changes are NOT used.</strong> {signed ? 'Signed review is blocked until the credential context and saved configuration agree. Save or explicitly revert the draft; the app does neither automatically.' : 'Your draft is neither saved nor discarded. The saved snapshot below is the archive input.'}</p>}
    {selected && <div className="session-review"><h4>Saved Xcode selection {onHelp && <HelpButton content={iosArchiveSelectionHelp} onHelp={onHelp} />}</h4>
      <p>{selected.containerKind === 'workspace' ? 'Workspace' : 'Project'}: <code>{selected.container}</code> · scheme: <code>{selected.scheme}</code> · configuration: <code>{selected.configuration}</code>.</p>
      <p>Bundle ID: <code>{selected.bundleId}</code> · symbols policy: {selected.symbolsPolicy} · saved preparation: {selected.preparationConfigured ? 'will execute before archive' : 'not configured'}.</p>
    </div>}
    {signed && <div className="session-review"><h4>Saved signing policy and current assignments {onHelp && <HelpButton content={iosSigningHelp} onHelp={onHelp} />}</h4>
      {project?.signingPolicy && <><p>Apple Team ID: <code>{project.signingPolicy.teamId}</code>.</p><p>Reviewed distribution certificate SHA-256: <code>{project.signingPolicy.distributionCertificateSha256}</code>.</p></>}
      {state.signing.policy && <ul>{state.signing.policy.assignments.map((row) => <li key={row.kind}>{row.kind} · record revision {row.recordRevision} · context revision {row.contextRevision}.</li>)}</ul>}
      {state.signing.issue && <p className="review-caution">{state.signing.issue}</p>}
      <p>Use Credentials → iOS → Candidate / internal testing → Build / signing only. Select the P12/profile, assess, keep, then assign each record. Any required Firebase or project-read input must be assigned in the same context; core decides its requiredness. Do not enter private inputs in Project settings.</p>
      <p>P12/CMS envelope assessment is not password, Apple authenticity, expiry or signing validation. This flow supports one primary App Store profile and manual signing; it does not guess extension profiles. A required symbols-upload policy remains BLOCKED here.</p>
      <div className="button-row">{onCredentials && <button type="button" className="button secondary small" onClick={onCredentials}>Prepare private inputs in Credentials</button>}{onSettings && <button type="button" className="button secondary small" onClick={onSettings}>Review public policy in Project settings</button>}</div>
    </div>}
    {project?.savedVersion && <p>Saved version <strong>{project.savedVersion.name}</strong> · build <strong>{project.savedVersion.build}</strong> · source <code>{project.savedVersion.source}</code>.</p>}
    {project?.savedConfig && <details><summary>Saved-input byte comparisons</summary><p>Configuration: {project.savedConfig.bytes} bytes · SHA-256 <code>{project.savedConfig.sha256}</code>.</p>
      {project.savedVersion && <p>Version: {project.savedVersion.bytes} bytes · SHA-256 <code>{project.savedVersion.sha256}</code>.</p>}</details>}
    {project?.inputIssue && <p className="review-caution">{project.inputIssue}</p>}
    <p className="save-note">Refresh saved configuration → Read saved version{signed ? ' → Assign exact signing inputs' : ''} → Review saved inputs → {signed ? 'Sign and export once' : 'Create archive'}. External changes remain possible; these comparisons are not an atomic source checkout.</p>
    <div className="button-row">
      {onRefresh && <button type="button" className="button secondary small" disabled={!project || !!refreshReason || project.snapshotPending} onClick={() => { if (project) controller.snapshotIntent(project.projectId); onRefresh(); }}>Refresh saved configuration</button>}
      {onReadVersion && <button type="button" className="button secondary small" data-mrk-ios-archive-action="observe-version" disabled={!project || !!versionReason || project.versionPending} onClick={() => { controller.versionIntent(); onReadVersion(); }}>Read saved version</button>}
    </div>
    {refreshReason && <p className="save-note">Configuration refresh: {refreshReason}</p>}{versionReason && <p className="save-note">Version read: {versionReason}</p>}
    <p className="save-note">{state.status ? iosArchiveAvailabilityText[iosArchiveModeAvailability(state.status, signed ? 'ios-signed-export' : 'ios-unsigned-archive')] : 'The separate native iOS archive capability has not been observed. Passive checks do not enable it.'}</p>
    {!consent && <><button type="button" className="button" data-mrk-ios-archive-action="review" disabled={prepareReason !== null} onClick={() => void controller.prepare()}>Review saved iOS inputs</button>{prepareReason && <p className="review-caution">{prepareReason}</p>}</>}
    {consent && consent.binding.selection && consent.binding.context.operation !== 'ios-local-recovery' && <div className="session-review" role="group" aria-label={signed ? 'Confirm this saved signed iOS export intent' : 'Confirm this saved unsigned iOS archive intent'}>
      <h3>{signed ? 'Sign and export this saved app once?' : 'Create this unsigned archive once?'}</h3>
      <UnsignedArchiveDetails state={state} review />
      <p>Project <strong>{consent.binding.context.projectId}</strong> · <code>{consent.binding.selection.container}</code> · scheme <code>{consent.binding.selection.scheme}</code> · configuration <code>{consent.binding.selection.configuration}</code>.</p>
      <p>Bundle ID <code>{consent.binding.selection.bundleId}</code> · saved version <strong>{consent.binding.context.savedVersion.name}</strong> · build <strong>{consent.binding.context.savedVersion.build}</strong>.</p>
      <p>Saved preparation {consent.binding.selection.preparationConfigured ? 'will execute' : 'is not configured'}. {signed ? 'The original archive and exported IPA are retained. Core must validate the exact signer/profile and artifact pair; failed or cancelled output remains incomplete.' : 'The resulting archive is retained; it is not a signed IPA.'}</p>
      {consent.binding.context.signing && <p>Team <code>{consent.binding.context.signing.teamId}</code> · certificate <code>{consent.binding.context.signing.distributionCertificateSha256}</code> · {consent.binding.context.signing.assignments.length} exact session input revisions.</p>}
      <p>This review expires within five minutes of original preparation. Status does not renew it. Saving, refreshing, reading another version, changing mode, policy, assignments or selection, or leaving an unstarted review retires consent.</p>
      <label className="offline-ack"><input type="checkbox" data-mrk-ios-archive-action="acknowledge" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />
        <span>{signed ? 'I trust this project and authorize one local signed archive, IPA export and paired validation with these exact saved inputs and assigned private records. Project code runs with my account access; signing state is borrowed. Cancellation is not rollback. Do not upload symbols, publish or promote this result.' : 'I trust this project and authorize one unsigned archive of these saved inputs. I understand that project code runs with my account access, my unsaved draft is not used, and cancellation is not rollback. Do not sign, export an IPA or publish a release.'}</span></label>
      <div className="button-row"><button type="button" className="button" data-mrk-ios-archive-action="start" disabled={startReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>{signed ? 'Sign and export local IPA' : 'Create unsigned archive'}</button></div>
      {startReason && <p className="review-caution">{startReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new iOS archive outcome was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution" role="status">The original acknowledgement is unconfirmed. Do not repeat Start. Check original Status to cancel or settle that operation; it cannot create new consent.</p>}
    {op && <div className="session-progress" role="status" aria-live="polite" aria-label="Original iOS archive status">
      <UnsignedArchiveDetails state={state} />
      <div className="inline-heading"><h3>Archive status · {operationProjectName ?? op.context.projectId}</h3><Badge tone={op.phase === 'unknown' ? 'warning' : 'neutral'}>{phases[op.phase]}</Badge></div>
      {op.stage && <p>Reached stage: {stages[op.stage]}. A stage is not a completion percentage or proof that cleanup finished.</p>}
      {op.outcome && <p><strong>Outcome:</strong> {op.outcome}</p>}<p>{iosArchiveReasonText[op.reason]}</p>
      {!isIOSRecoveryOperation(op) && op.activity && <ul>{iosArchiveRoles(op.context).map((role) => { const command = op.activity!.commands[role]!; return <li key={role}>{roles[role]}: {command.outcome === 'exited' ? `known exit ${command.exitCode}` : command.outcome === 'unknown' ? 'no usable original outcome' : command.outcome === 'not-configured' ? 'not configured' : 'not dispatched'}.</li>; })}</ul>}
      {op.disposition && <><p>Inspection snapshot: {op.disposition.snapshot}. Task work: {op.disposition.work}. Archive output: {op.disposition.output}.</p>
        {op.disposition.relativeDirectory && <p>Retained operation location: <code>{op.disposition.relativeDirectory}</code>. This is not permission for a blanket cleanup or rerun.</p>}</>}
      {!isIOSRecoveryOperation(op) && op.activity && op.outcome !== 'complete' && <ol className="offline-findings">{op.activity.findings.map((finding, index) => <li key={index}><Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge><span>{iosArchiveFindingText[finding.check]}</span></li>)}</ol>}
      {isIOSRecoveryOperation(op) && <p>This is a local recovery operation, not an archive or signing result. Read its account/project rows in Recovery.</p>}
      {state.historical && <p className="review-caution">This is retained original-operation data, not approval for the current editor or selected project.</p>}
    </div>}
    {controls}
    {onRecovery && <button type="button" className="button secondary small" onClick={onRecovery}>Local signing / build-input recovery</button>}
    <p className="save-note">Started archives stay app-owned across pages. Unknown cleanup remains blocked; reconnecting cannot reset ownership. {onHelp && <HelpButton content={iosArchiveOutputHelp} onHelp={onHelp} />}</p>
    <IOSArchiveResultView state={state} operationProjectName={operationProjectName} />
  </section>;
}

const recoveryStates: Record<IOSRecoveryRowState, string> = {
  idle: 'No pending owned state was observed. This does not establish that every account or project process is idle.',
  pending: 'The inspected session has retained owned state. Only an explicitly offered ordinary recovery action may be reviewed.',
  busy: 'The original account or project owner is busy. Wait for its own settlement; do not take over or reset it.',
  conflict: 'The existing core predicates found conflicting state. Preserve it; no forced recovery is offered.',
  'manual-required': 'This session needs the exceptional manual recheck path. That same-attempt interactive path is not supported in Desktop.',
  recovered: 'Ordinary recovery completed for this exact inspected session, not for arbitrary account or project state.',
  'recovered-with-conflict': 'The owned account recovery completed with a retained conflict. Do not interpret this as a clean signing environment.',
  absent: 'The exact inspected session was absent when recovery rechecked it. This is not evidence that another session was recovered.',
  'cleanup-only': 'The exact project session retains cleanup-only state. Review the offered ordinary action; do not delete its controls manually.',
  'not-inspected': 'Project inspection was not entered after account attention or failure. No project recovery state is established.',
};
export function IOSRecovery({ state, controller, projectName, operationProjectName, onHelp }: {
  state: IOSArchiveState; controller: IOSArchiveController; projectName: string | null; operationProjectName: string | null;
  onHelp?: (help: HelpContent) => void;
}) {
  const label = useId(), operation = state.status?.operation;
  const recovery = operation && isIOSRecoveryOperation(operation) ? operation : null;
  const report = state.mode === 'native' && recovery?.phase === 'terminal' ? recovery.report : null;
  const consent = state.consent, choice = consent?.binding.context.operation === 'ios-local-recovery' ? consent.binding.context.recovery : null;
  const inspectReason = controller.recoveryReason(), startReason = controller.startReason();
  return <section className="card offline-preflight" aria-labelledby={label} data-mrk-ios-recovery="status" data-phase={recovery?.phase ?? 'idle'}>
    <SectionHeading title="Local iOS signing and build-input recovery" description="Inspect first. Review only an exact session that the same original native owner has actually inspected.">
      <Badge tone="warning">No forced cleanup</Badge>{onHelp && <HelpButton content={iosRecoveryHelp} onHelp={onHelp} />}
    </SectionHeading>
    <h3 id={label}>Selected project: {projectName ?? 'Choose a registered source project'}</h3>
    <p>This uses the existing iOS operation owner and core recovery predicates, not a shell or an arbitrary path. No saved configuration, version, Xcode archive or private credential import is required. Account state is checked before project state; a failure does not start another inspection clock.</p>
    <p><strong>A live Unknown operation must retain its original Status and Cancel.</strong> An elapsed timeout or your confirmation is not worker finality. Do not disconnect to bypass ownership, reset keychains, delete profiles, or remove project recovery controls.</p>
    <p>{state.status ? iosArchiveAvailabilityText[iosArchiveModeAvailability(state.status, 'ios-local-recovery')] : 'A separately admitted native recovery capability has not been observed.'}</p>
    <button type="button" className="button" data-mrk-ios-recovery-action="review-inspect" disabled={inspectReason !== null} onClick={() => void controller.prepareRecovery('inspect')}>Review local recovery inspection</button>
    {inspectReason && <p className="review-caution">{inspectReason}</p>}
    {consent && choice && <div className="session-review" role="group" aria-label="Confirm this exact local recovery action">
      <h3>{choice.action === 'inspect' ? 'Inspect account and project state once?' : `Recover this exact ${choice.action} session once?`}</h3>
      <p>Project <strong>{consent.binding.context.projectId}</strong>. {choice.action !== 'inspect' && <>Inspected session: <code>{choice.session}</code>. This label is a comparison, not authority; native Start must still match its original inspection.</>}</p>
      <p>The one-use review lasts at most five minutes. Leaving it, changing project/context or losing the original acknowledgement retires consent. Status does not renew it.</p>
      <label className="offline-ack"><input type="checkbox" data-mrk-ios-recovery-action="acknowledge" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />
        <span>{choice.action === 'inspect' ? 'I authorize one local inspection of the account signing and selected project build-input recovery controls. Inspection does not recover or erase retained state.' : choice.action === 'account' ? 'I confirm this macOS account and signing services are idle and authorize ordinary restoration of only this inspected account session’s owned state. Do not override conflicts or treat my confirmation as worker finality.' : 'I confirm this project’s build inputs are idle and authorize ordinary restoration of only this inspected project session’s owned state. Do not override conflicts or treat my confirmation as worker finality.'}</span></label>
      <button type="button" className="button" data-mrk-ios-recovery-action="start" disabled={startReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>{choice.action === 'inspect' ? 'Inspect local state once' : `Recover inspected ${choice.action} session`}</button>
      {startReason && <p className="review-caution">{startReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new local recovery outcome was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution">Do not repeat Start. Check the original iOS owner status to settle or cancel the unconfirmed request; no observation can rearm its consent.</p>}
    {recovery && <div className="session-progress" role="status" aria-live="polite"><h3>{operationProjectName ?? recovery.context.projectId} · {phases[recovery.phase]}</h3>
      {recovery.stage && <p>{stages[recovery.stage]}. This is an actual phase, not proof that recovery or cleanup succeeded.</p>}
      {recovery.outcome && <p>Operation outcome: {recovery.outcome}. {recovery.context.recovery.action === 'inspect' && 'A complete inspection can still find pending state; it is not completed recovery.'}</p>}
      <p>{iosArchiveReasonText[recovery.reason]}</p>
    </div>}
    {report && recovery && <div className="session-review" aria-label="Original native local recovery report">
      {(['account', 'project'] as const).map((domain) => { const row = report[domain]; if (!row) return null;
        const actionReason = controller.recoveryReason(domain, recovery);
        return <div key={domain}><h4>{domain === 'account' ? 'Account signing state' : 'Project build-input state'} · {row.status}</h4><p>{recoveryStates[row.status]}</p>
          {row.session && <p>Exact inspected session: <code>{row.session}</code>.</p>}
          {recovery.context.recovery.action === 'inspect' && <><button type="button" className="button secondary small" disabled={actionReason !== null} onClick={() => void controller.prepareRecovery(domain, recovery)}>Review ordinary {domain} recovery</button>{actionReason && <p className="save-note">{actionReason}</p>}</>}
        </div>;
      })}
      {state.historical && <p className="review-caution">Historical original-operation data. It cannot authorize the current project or another recovery session.</p>}
      <p>Local recovery only. No Store action or release-readiness claim. Inspect again after an action; another session is never silently substituted.</p>
    </div>}
    <div className="button-row"><button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => void controller.checkStatus()}>Check original iOS owner status</button>
      {operation && operation.phase !== 'terminal' && <button type="button" className="button secondary small" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Cancel original iOS operation</button>}</div>
    <p className="save-note">Ordinary recovery is supported only when the existing core offers it. Exceptional interactive manual recheck is not implemented here; a manual-required or preserved conflict is an explicit limitation, not a successful recovery. Cancel never forces cleanup or undoes completed restoration.</p>
  </section>;
}
