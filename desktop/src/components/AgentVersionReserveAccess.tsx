import { useId, useSyncExternalStore } from 'react';
import { AGENT_VERSION_RESERVE_SCOPE, agentVersionReserveCommands } from '../agentVersionReserveAccess.ts';
import type { AgentVersionReserveAccessController } from '../agentVersionReserveAccessController.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

// Mounted inside the existing reservation panel. No mount query, timer,
// permission renewal, command execution or independent Reserve controller.
export function AgentVersionReserveAccess({ controller, check, compact = false }: {
  controller: AgentVersionReserveAccessController; check(): Promise<boolean>; compact?: boolean;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const id = useId(), access = state.access, remaining = controller.remainingSeconds(), busy = controller.ownerReason();
  if (compact && !busy) return null;
  const status = state.unknown ? 'CLI permission is unconfirmed' : state.revoking ? 'Turning off permission and requesting Stop…' :
    state.pending === 'allow' ? 'Allowing this one reservation…' : state.pending === 'status' ? 'Checking the original CLI permission…' :
      state.stale ? 'Check CLI permission before continuing' : access?.consumed ? access.completedOperationId ?
        'CLI reservation completed — the version file still needs its own review' : 'CLI request submitted — completion is not established by permission status' :
        access?.enabled ? 'One CLI reservation was allowed at the last check' : 'CLI reservation permission is off at the last check';
  const commands = access && !state.stale && !state.unknown ? agentVersionReserveCommands(access) : [];
  const contents = <section className={compact ? 'notice notice-warning' : 'credential-guidance'} aria-labelledby={`${id}-title`}>
    <h4 id={`${id}-title`}>CLI / AI reservation · optional</h4>
    {!compact && <>
      <p>{AGENT_VERSION_RESERVE_SCOPE}</p>
      <p className="save-note">Keep this app open. Permission is used once and expires with the original review, within two minutes. Checking never renews it. Normal in-app reservation needs no CLI permission.</p>
      {state.review && <p>Reviewed branch: <strong><bdi>{state.review.options.reference}</bdi></strong> · {state.review.options.increment} change.
        {state.review.options.newCandidate ? ' A different candidate was explicitly selected.' : ' Continue the existing candidate when available.'}</p>}
      <label><input type="checkbox" checked={state.acknowledged} disabled={controller.consentReason() !== null}
        onChange={(e) => controller.setAcknowledged(e.target.checked)} />Allow a trusted local tool to use this one reviewed reservation</label>
    </>}
    <p role={state.unknown ? 'alert' : 'status'}>{status}</p>
    {!state.stale && access?.enabled && <p className="save-note">{remaining === null || remaining === 0 ?
      'The last permission may have expired. Check again; this does not extend it.' : `Up to ${remaining} seconds remaining, estimated from the last check.`}</p>}
    {state.issue && <p className="toolbar-reason" role="alert">{state.issue}</p>}
    <div className="button-row">
      {!compact && <button type="button" className="button secondary" disabled={controller.allowReason() !== null}
        onClick={() => void controller.allow()}>Allow one CLI reservation</button>}
      <button type="button" className="button secondary" disabled={controller.statusReason() !== null} onClick={() => void check()}>Check CLI request</button>
      <button type="button" className="button secondary" disabled={controller.revokeReason() !== null} onClick={() => void controller.revoke()}>Turn off / Stop CLI request</button>
    </div>
    {!compact && <p className="toolbar-reason">{controller.allowReason() ?? 'Only these reviewed choices can be submitted. The native app checks them again.'}</p>}
    {access?.consumed && <p className="save-note">This permission cannot be used again. “Turn off / Stop” asks the original request to stop; it does not undo a reserved number or confirm cleanup.
      {controller.checkedCompletion() && ' Wait for the original status check, then use “Open reserved version for review” above when available. Saving the file remains a separate approval.'}</p>}
    {!compact && <details>
      <summary>How to use this permission and request details</summary>
      <p>After allowing, give the command below to a trusted local tool. The CLI prints its request ID before submitting; retain it to check or stop that exact request. No command runs from this panel.</p>
      {commands.map((command) => <pre key={command}><code>{command}</code></pre>)}
      {!commands.length && <p>No current command is offered. Review and allow explicitly, or check the existing request.</p>}
      {access?.grantId && <dl>
        <dt>Service project</dt><dd><code>{access.projectId}</code></dd>
        <dt>Running app service</dt><dd><code>{access.serviceInstance}</code></dd>
        <dt>Permission</dt><dd><code>{access.grantId}</code></dd>
        <dt>Reviewed choices</dt><dd><code>{access.reviewId}</code> · revision {access.reviewRevision}</dd>
        {access.requestId && <><dt>Original request</dt><dd><code>{access.requestId}</code></dd></>}
      </dl>}
      <p className="save-note">These are the original permission’s identifiers, not proof that another selected project is permitted or that a build or Store release is ready.</p>
    </details>}
  </section>;
  return compact ? contents : <ProgressiveDisclosure title="Let a CLI or AI tool reserve this version · optional"
    description="Keep using the in-app buttons unless a trusted local tool needs this one reservation."
    needsAttention={busy !== null || state.issue !== null || !state.stale && access?.consumed === true}>{contents}</ProgressiveDisclosure>;
}
