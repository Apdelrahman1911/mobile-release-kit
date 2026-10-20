import { useId, useSyncExternalStore } from 'react';
import type { VersionEnrollmentController } from '../versionEnrollmentController.ts';
import { versionEnrollmentHelp } from '../versionEnrollment.ts';
import { Badge, SectionHeading } from './Common.tsx';

// Root retains this controller across page changes. Rendering/opening this
// optional panel performs no read, connection, reservation or version change.
export function VersionEnrollmentPanel({ controller, compact = false }: { controller: VersionEnrollmentController; compact?: boolean }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const id = useId(), status = state.status, owner = controller.ownerReason();
  if (compact && !owner) return null;
  const reviewReason = controller.reviewReason(), confirmReason = controller.confirmReason();
  const checkReason = controller.checkReason(), stopReason = controller.stopReason();
  const phase = state.unknown ? 'Operation unconfirmed' : state.pending === 'confirm' || status?.phase === 'connecting' ? 'Connecting this computer…' :
    state.pending === 'review' || status?.phase === 'reading' ? 'Reading the shared counter…' : status?.phase === 'connected' ? 'Connection saved at last check' :
    status?.phase === 'reviewed' ? 'Counter reviewed — not connected by this review' : status?.phase === 'refused' ? 'Counter connection not confirmed' :
    status?.phase === 'stopping' ? 'Stopping the original operation…' : 'No current counter review';
  return <section className={compact ? 'notice notice-warning' : 'card'} aria-labelledby={`${id}-title`} aria-busy={owner !== null}>
    <div id={`${id}-title`}><SectionHeading title={compact ? 'Shared counter operation' : 'Connect a shared version counter'}
      description={compact ? 'Keep the original operation until it finishes.' : 'Optional · for a repository that already has a supported shared counter.'} /></div>
    {!compact && <p>Use the GitHub account and repository selected above. <strong>Manual versions remain the default.</strong> This only connects the counter on this computer; it does not create a counter, reserve a number, change project files or check either Store.</p>}
    <div role="status" aria-live="polite"><Badge tone={state.unknown || state.issue ? 'warning' : 'info'}>{phase}</Badge></div>
    {state.stale && status && <p className="save-note">This is an earlier observation, not a current connection or release-readiness check.</p>}
    {status?.projectId && owner && <p className="save-note">Original native project: <bdi>{status.projectId}</bdi>. Controls stay with that operation even if the selection changes.</p>}
    {!compact && status?.review && <div>
      <p>Repository: <strong><bdi>{status.review.repository}</bdi></strong><br />
        Counter’s latest version: <strong>{status.review.version.name} ({status.review.version.build})</strong><br />
        Recorded reservations: {status.review.reservations}</p>
      <p className="save-note">Connecting trusts the counter’s currently published history. Deleted earlier history cannot be checked, and repository protections can change later. This is not a Store release or a newly reserved version.</p>
    </div>}
    <p className="save-note" role={state.unknown || state.issue ? 'alert' : undefined}>
      {versionEnrollmentHelp(state.unknown ? 'cleanup-unknown' : state.issue ?? status?.reason ?? null)}
    </p>
    <div className="button-row">
      {!compact && <button type="button" className={status?.review ? 'button secondary' : 'button primary'} disabled={reviewReason !== null}
        aria-describedby={`${id}-action-reason`} onClick={() => void controller.review()}>Review shared counter</button>}
      {!compact && status?.review && <button type="button" className="button primary" disabled={confirmReason !== null}
        aria-describedby={`${id}-action-reason`} onClick={() => void controller.confirm()}>Connect on this computer</button>}
      <button type="button" className="button secondary" disabled={checkReason !== null} onClick={() => void controller.check()}>Check status</button>
      <button type="button" className="button secondary" disabled={stopReason !== null} onClick={() => void controller.stop()}>Stop</button>
    </div>
    <p id={`${id}-action-reason`} className="toolbar-reason">{owner ?? (status?.review ? confirmReason : reviewReason) ?? 'Review first, then explicitly connect this computer. No automatic retry.'}</p>
    {(state.pending !== null || state.unknown) && stopReason && <p className="save-note">{stopReason}</p>}
  </section>;
}
