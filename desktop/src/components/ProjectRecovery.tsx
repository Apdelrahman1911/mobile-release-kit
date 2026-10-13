import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import { projectRecoveryOwnerReason } from '../projectRecoveryController.ts';
import type { ProjectRecoveryController, ProjectRecoveryState } from '../projectRecoveryController.ts';
import { recoveryAvailabilityText, recoveryReasonText } from '../projectRecoveryProtocol.ts';
import type { ProjectRecoveryInspectionStatus, ProjectRecoveryObservation, ProjectRecoveryPhase, ProjectRecoveryQuiescence } from '../projectRecoveryTypes.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const phases: Record<ProjectRecoveryPhase, string> = {
  'awaiting-consent': 'Review prepared', starting: 'Starting original operation', running: 'Original operation running',
  stopping: 'Stopping · cleanup pending', terminal: 'Original operation settled', unknown: 'Original cleanup unknown',
};
const states: Record<ProjectRecoveryInspectionStatus, string> = {
  idle: 'No pending build-input record observed', busy: 'Another owner holds the project lock',
  conflict: 'Recovery state is conflicting or invalid', pending: 'Pending build-input session',
  'cleanup-only': 'Only terminal recovery metadata remains',
};
const quiescence: Record<ProjectRecoveryQuiescence, string> = {
  none: 'No original-worker finality is recorded. Recovery is disabled; the app cannot assume workers are idle.',
  original: 'The record contains the original consumer-finality observation. It permits a reviewed attempt, not a promise that current files are unchanged.',
  operator: 'A prior operator explicitly asserted that the original workers were idle. This is an operator assertion, NOT newly verified native worker finality.',
};
const scopeHelp: HelpContent = {
  label: 'Project build-input recovery', requiredness: 'conditional',
  what: 'Restores temporary Android or iOS service-configuration inputs recorded by the existing core, or retires already-completed recovery metadata.',
  why: 'An interrupted build can leave a recorded temporary input in the project. The original record tells the core what it may safely restore.',
  where: 'Choose the same source project in this app. Inspect reads its original record; you do not need to locate, copy or edit hidden files.',
  format: 'Nothing to enter. Review the recorded session and roles, then confirm only that exact recovery attempt.',
  requiredWhen: 'Only when inspection finds an eligible pending session. This is not signing-account, file-edit, Store or release recovery.',
  failure: 'If ownership, the checkpoint or files changed, recovery refuses rather than overwrite unrelated changes. Preserve the original files and status.',
};
const workerHelp: HelpContent = {
  label: 'Recorded worker finality', requiredness: 'required',
  what: 'Whether the original recovery record says its consumers finished using the temporary inputs.',
  why: 'Restoring files while a build still reads them would be unsafe. An empty process list or a stopped UI does not prove this contract.',
  where: 'This value comes from the core record during inspection, not from a setting or a checkbox you fill in here.',
  format: 'Original: original consumer-finality observation. Operator: an earlier explicit operator assertion. None: not established.',
  requiredWhen: 'Before any restoration attempt. None cannot be upgraded to proof by this screen.',
  failure: 'Keep the original operation and files. Manual original-worker investigation is outside this UI; there is no Force button.',
};
function Observation({ value, onHelp }: { value: ProjectRecoveryObservation; onHelp: (help: HelpContent) => void }) {
  return <div className="session-review">
    <div className="inline-heading"><h3>{states[value.status]}</h3><Badge tone={value.status === 'idle' ? 'neutral' : 'warning'}>{value.status}</Badge></div>
    {value.session && <p><strong>Recorded session:</strong> <code>{value.session}</code></p>}
    {value.roles.length > 0 && <p><strong>Recorded inputs:</strong> {value.roles.map((role) => role === 'android-services' ? 'Android service configuration' : 'iOS service configuration').join(', ')}.</p>}
    {value.status === 'pending' && <><div className="inline-heading"><strong>Recorded worker finality</strong><HelpButton content={workerHelp} onHelp={onHelp} /></div><p>{quiescence[value.quiescence]}</p></>}
    {value.status === 'cleanup-only' && <p><strong>This is metadata-only cleanup.</strong> The record says input restoration already finished. The remaining action retires that session’s terminal metadata; it does not restore application files. {quiescence[value.quiescence]}</p>}
    {value.status === 'idle' && <p>This is a build-input observation only. It does not mean the whole project, a previous file edit, signing account or Store release is clean.</p>}
    {value.status === 'busy' && <p>Let the original owner finish. This app will not take over its lock or stop another task’s workers.</p>}
    {value.status === 'conflict' && <p>No recovery attempt is available from this observation. Preserve original files and investigate the conflicting record; deleting it does not make retry safe.</p>}
  </div>;
}

export function ProjectRecovery({ state, controller, projectName, operationProjectName, compact = false, onShow, onHelp }: {
  state: ProjectRecoveryState; controller: ProjectRecoveryController; projectName: string | null; operationProjectName: string | null;
  compact?: boolean; onShow?: () => void; onHelp: (help: HelpContent) => void;
}) {
  const label = useId();
  const owned = projectRecoveryOwnerReason(state), op = state.status?.operation, consent = state.consent;
  if (compact && !owned) return null;
  const inspectReason = controller.prepareReason('inspect'), recoverReason = controller.prepareReason('recover'), runReason = controller.runReason();
  const cancelRequested = !!op && state.cancelClaimed?.operationId === op.operationId && state.cancelClaimed.ownerGeneration === op.ownerGeneration;
  const controls = <div className="button-row">
    <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={15} />{state.readPending ? 'Reading original status…' : 'Check original status'}</button>
    {op && op.phase !== 'terminal' && <button type="button" className="button secondary small" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>{cancelRequested ? 'Cancel requested · awaiting cleanup' : 'Cancel original operation'}</button>}
    {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>Show in Recovery</button>}
  </div>;
  if (compact) return <section className="notice notice-warning offline-global" aria-label="Original project-recovery operation">
    <Icon name="shield" /><div><strong>Project recovery · {operationProjectName ?? 'original selected project'}</strong>
      <p>{op ? phases[op.phase] : 'Original request acknowledgement is pending.'} {owned}</p>{controls}
      <p>Cancelling does not undo cleanup already performed. Keep original files while settlement is unknown.</p>
    </div>
  </section>;
  const inspected = op?.result?.action === 'inspect' ? op.result.observation : null;
  const reviewed = consent?.binding.context.action === 'recover' ? consent.binding.context.review : null;
  const possiblePartial = op?.context.action === 'recover' && op.phase !== 'awaiting-consent' && op.outcome !== 'complete' &&
    op.effect !== 'not-attempted'; // Missing effect DATA is uncertainty, never proof that no cleanup ran.
  return <section className="card offline-preflight" aria-labelledby={label}>
    <SectionHeading title="Recover project build inputs" description="One local core-managed session, not Store, signing-account or file-edit recovery.">
      <HelpButton content={scopeHelp} onHelp={onHelp} /><Badge tone="info">Local project only</Badge>
    </SectionHeading>
    <h3 id={label}>Inspect first, then review what can safely be recovered</h3>
    <p><strong>Selected source project:</strong> {projectName ?? 'No project selected'}</p>
    <p>Inspect reads the existing build-input record. It does not run project commands, contact a Store or claim that stopped workers are idle. You do not need to move or edit hidden files.</p>
    {state.project?.dirtyDraft && <p className="save-note">Your unsaved settings draft is preserved and is not used by this recovery action.</p>}
    <p className="save-note">{state.status ? recoveryAvailabilityText[state.status.availability] : 'The separate native recovery capability has not been observed.'}</p>
    {!consent && <><div className="button-row">
      <button type="button" className="button secondary" disabled={inspectReason !== null} onClick={() => void controller.prepare('inspect')}>Inspect build-input state</button>
      <button type="button" className="button" disabled={recoverReason !== null} onClick={() => void controller.prepare('recover')}>Review recovery attempt</button>
    </div>{inspectReason && <p className="review-caution">{inspectReason}</p>}{!inspectReason && recoverReason && <p className="save-note">{recoverReason}</p>}</>}
    {inspected && <><Observation value={inspected} onHelp={onHelp} />{state.historical && <p className="review-caution">This retained observation is historical; it is not recovery permission for the current context.</p>}</>}
    {consent && reviewed && <div className="session-review" role="group" aria-label="Confirm the exact build-input recovery attempt">
      <Observation value={reviewed} onHelp={onHelp} />
      <p>The core rechecks this same original project, session and checkpoint under its project lock before changing anything. Changed or foreign files are preserved. This review expires no later than five minutes after the original inspection; checking status or preparing again never renews it.</p>
      <label className="offline-ack"><input type="checkbox" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />
        <span>{reviewed.status === 'cleanup-only' ? 'Retire only this session’s remaining recovery metadata; do not restore application files.' : 'Attempt to restore only this recorded session’s build inputs and retire its completed metadata, preserving changed or unrelated files.'} I understand cancellation is not rollback and partial cleanup can remain.</span>
      </label>
      <div className="button-row"><button type="button" className="button" disabled={runReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>{reviewed.status === 'cleanup-only' ? 'Retire reviewed metadata' : 'Recover reviewed build inputs'}</button></div>
      {runReason && <p className="review-caution">{runReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new recovery outcome was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution" role="status">The original acknowledgement is unconfirmed. Do not repeat the recovery action. Check its original status; a status observation never creates consent.</p>}
    {op && <div className="session-progress" role="status" aria-live="polite">
      <div className="inline-heading"><h3>{op.context.action === 'inspect' ? 'Inspection' : 'Recovery'} · {operationProjectName ?? 'earlier selected project'}</h3><Badge tone={op.phase === 'unknown' ? 'warning' : 'neutral'}>{phases[op.phase]}</Badge></div>
      {op.outcome && <p><strong>Outcome:</strong> {op.outcome}</p>}<p>{recoveryReasonText[op.reason]}</p>
      {possiblePartial && <p className="review-caution">Cleanup may have partly completed. Cancellation, failure or a lost response does not mean no files changed. Keep the original state; no automatic retry is performed.</p>}
      {op.result?.action === 'recover' && <p><strong>{op.context.review?.status === 'cleanup-only' ? 'Reviewed terminal metadata retired.' : 'Reviewed build-input session recovered.'}</strong> Session <code>{op.result.recoveredSession}</code>. This does not clear other recovery alerts or establish project/release readiness. Inspect again explicitly if you need a new observation.</p>}
    </div>}
    {controls}
    <p className="save-note">Navigating away keeps a started operation’s original status and Cancel available throughout the app. Original cleanup must settle before conflicting work. There is no force, worker takeover, account cleanup or Store mutation in this flow.</p>
  </section>;
}
