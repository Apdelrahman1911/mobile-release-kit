import { useId } from 'react';
import type { OfflinePreflightController, OfflinePreflightState } from '../offlinePreflight.ts';
import { offlinePreflightOwnerReason } from '../offlinePreflight.ts';
import { OFFLINE_CORE_STATUSES, OFFLINE_PREFLIGHT_DISCLOSURE, offlineAvailabilityText, offlineFindingText,
  offlineLimitationText, offlineReasonText } from '../offlinePreflightProtocol.ts';
import type { OfflineCoreStatus, OfflinePreflightPhase, OfflinePreflightResult } from '../offlinePreflightTypes.ts';
import { Badge, ErrorNotice, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const phases: Record<OfflinePreflightPhase, string> = {
  'awaiting-consent': 'Awaiting explicit consent', starting: 'Starting original work', running: 'Original work running',
  stopping: 'Stopping · cleanup pending', terminal: 'Original operation settled', unknown: 'Original cleanup unknown',
};
const negative = (status: OfflineCoreStatus) => ['FAIL', 'MISSING', 'BLOCKED', 'INVALID'].includes(status);
function Report({ result, historical }: { result: OfflinePreflightResult; historical: boolean }) {
  const summary = result.summary;
  return <section className="offline-report" aria-label="Saved offline check findings">
    <div className="inline-heading"><h3>Returned offline-check report</h3><Badge tone={historical ? 'warning' : 'info'}>{historical ? 'Historical / stale context' : 'This invocation only'}</Badge></div>
    <p><strong>Complete is not PASS or release readiness.</strong> The shared preflight returned a report and original native cleanup settled. Some checks may legitimately fail, be skipped or not run. No release candidate was created by this action.</p>
    <p>{summary.total} total findings · {summary.shown} shown · {summary.omitted} omitted from the list. Counts below include every reported finding.</p>
    {summary.omitted > 0 && <p className="review-caution">Only the first 128 findings are displayed. Omitted findings can include negative statuses; use the complete status counts, not the visible rows alone.</p>}
    <dl className="offline-counts">{OFFLINE_CORE_STATUSES.map((status) => <div key={status}><dt>{status}</dt><dd>{summary.counts[status]}</dd></div>)}</dl>
    <ol className="offline-findings">{result.findings.map((finding) => <li key={finding.ordinal}>
      <Badge tone={negative(finding.status) ? 'warning' : 'neutral'}>{finding.status}</Badge>
      <span>{offlineFindingText[finding.message]}{finding.projectCheckIndex !== null ? ` Check ${finding.projectCheckIndex + 1}.` : ''}</span>
    </li>)}</ol>
    <h4>Limits of this result</h4><ul>{result.limitations.map((limitation) => <li key={limitation}>{offlineLimitationText[limitation]}</li>)}</ul>
  </section>;
}
export function OfflinePreflight({ state, controller, projectName, operationProjectName, compact = false, onShow, onRefresh, refreshReason = null }: {
  state: OfflinePreflightState; controller: OfflinePreflightController; projectName: string | null; operationProjectName: string | null;
  compact?: boolean; onShow?: () => void; onRefresh?: () => void; refreshReason?: string | null;
}) {
  const label = useId();
  const op = state.status?.operation, consent = state.consent;
  const owned = offlinePreflightOwnerReason(state);
  if (compact && !owned) return null;
  const prepareReason = controller.prepareReason(), runReason = controller.runReason();
  const cancelRequested = !!op && state.cancelClaimed?.operationId === op.operationId && state.cancelClaimed.ownerGeneration === op.ownerGeneration;
  const controls = <div className="button-row">
    <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={15} />{state.readPending ? 'Reading original status…' : 'Check original status'}</button>
    {op && op.phase !== 'terminal' && <button type="button" className="button secondary small" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>{cancelRequested ? 'Cancel requested · waiting for cleanup' : 'Cancel original offline checks'}</button>}
    {compact && onShow && <button type="button" className="button secondary small" onClick={onShow}>Show in Releases</button>}
  </div>;
  if (compact) return <section className="notice notice-warning offline-global" aria-label="Original saved offline-check operation">
    <Icon name="shield" size={20} /><div><strong>Saved offline checks · {operationProjectName ?? 'original selected project'}</strong>
      <p>{op ? phases[op.phase] : 'Original request acknowledgement is pending.'} {owned}</p>{controls}
      <p>Cancel does not undo file changes, builds or network effects already performed by project code.</p>
    </div>
  </section>;
  return <section className="card offline-preflight" aria-labelledby={label}>
    <SectionHeading title="Run offline checks (Android)" description="Saved project execution, separate from future release-candidate creation."><Badge tone="warning">Core builds are disabled</Badge></SectionHeading>
    <h3 id={label}>Review the saved inputs and project-code effects</h3>
    <p><strong>Selected source project:</strong> {projectName ?? 'No project selected'}</p>
    <div className="notice notice-warning"><Icon name="shield" /><p>{OFFLINE_PREFLIGHT_DISCLOSURE}</p></div>
    {state.project?.dirtyDraft && <div className="notice notice-warning" role="status"><Icon name="info" /><p><strong>Unsaved draft changes are NOT used.</strong> This action deliberately uses the last observed saved configuration. Your draft remains in memory and is neither saved nor discarded.</p></div>}
    <p>{state.project?.savedConfig ? `Saved configuration comparison available: ${state.project.savedConfig.bytes} observed bytes.` : 'No usable saved configuration comparison is available.'} A Save attempt retires this comparison; explicitly refresh afterward. Other project files remain live inputs, not an atomic checkout.</p>
    {onRefresh && <div className="button-row"><button type="button" className="button secondary small" disabled={!state.project || !!refreshReason || state.project.snapshotPending} onClick={onRefresh}>Refresh saved configuration observation</button>{refreshReason && <span className="save-note">{refreshReason}</span>}</div>}
    <p className="save-note">{state.status ? offlineAvailabilityText[state.status.availability] : 'The separate native offline-check capability has not been observed.'}</p>
    {!consent && <><button type="button" className="button" disabled={prepareReason !== null} onClick={() => void controller.prepare()}>Review offline checks</button>
      {prepareReason && <p className="review-caution">{prepareReason}</p>}</>}
    {consent && <div className="session-review" role="group" aria-label="Confirm this saved offline-check intent">
      <h3>Run this saved Android preflight?</h3>
      <p>Project: <strong>{projectName ?? 'Original selected project'}</strong>. Saved comparison: {consent.binding.context.savedConfig.bytes} bytes. This review expires no later than five minutes after its original preparation; checking status never extends it.</p>
      <label className="offline-ack"><input type="checkbox" checked={consent.acknowledged} onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />
        <span>I trust this project and understand that its saved checks may modify files, run programs, build, read account files or use the network; my unsaved draft is not used.</span></label>
      <div className="button-row"><button type="button" className="button" disabled={runReason !== null} onClick={() => void controller.start(consent.operationId, consent.ownerGeneration)}>Run saved offline checks</button></div>
      {runReason && <p className="review-caution">{runReason}</p>}
    </div>}
    {state.error && <ErrorNotice error={state.error} title="No new offline-check outcome was confirmed" />}
    {state.originalUnconfirmed && <p className="review-caution" role="status">The original command acknowledgement is unconfirmed. Do not repeat Start. A status observation can help cancel or settle that original operation, but cannot create consent.</p>}
    {op && <div className="session-progress" role="status" aria-live="polite">
      <div className="inline-heading"><h3>Original status · {operationProjectName ?? 'earlier selected project'}</h3><Badge tone={op.phase === 'unknown' ? 'warning' : 'neutral'}>{phases[op.phase]}</Badge></div>
      {op.outcome && <p><strong>Outcome:</strong> {op.outcome}</p>}
      <p>{offlineReasonText[op.reason]}</p>
      {state.historical && <p className="review-caution">This is retained original-operation data, not permission for the current editor or project context.</p>}
    </div>}
    {controls}
    <p className="save-note">Leaving Releases keeps a started run’s original status and Cancel accessible throughout the app. Cancellation is not rollback. Unknown cleanup is sticky; reconnecting cannot reset it.</p>
    {op?.result && <Report result={op.result} historical={state.historical} />}
  </section>;
}
