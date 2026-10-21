import { useSyncExternalStore } from 'react';
import { appleCliCommands, appleCliEffect } from '../agentAppleProvisioning.ts';
import type { AgentAppleProvisioningController } from '../agentAppleProvisioningController.ts';

// Optional delegation of ONE already prepared step. Normal Desktop Start is
// outside this collapsed section and remains the ordinary route.
export function AgentAppleProvisioningAccess({ controller }: { controller: AgentAppleProvisioningController }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const review = state.review, status = state.status ?? state.access?.status;
  const commands = status ? [
    `mrk apple-provisioning-status ${status.origin.projectId} ${status.origin.serviceInstance} ${status.origin.requestId}`,
    `mrk apple-provisioning-cancel ${status.origin.projectId} ${status.origin.serviceInstance} ${status.origin.requestId}`,
  ] : state.unknown || state.revoked || state.stale ? [] : appleCliCommands(state.access);
  return <details>
    <summary>Advanced · run this prepared step from the installed CLI</summary>
    <p>Usually, use the Start button above. Alternatively, prepare one step in this app, allow ordinary project Read access, then explicitly delegate just that step here. This does not enable unattended setup or the next step.</p>
    {review && <p><strong>{review.mode}</strong> · {appleCliEffect(review.mode)}<br />Prepared operation: <code>{review.operationId}</code></p>}
    <label><input type="checkbox" checked={state.acknowledged} disabled={!!controller.consentReason()}
      onChange={event => controller.acknowledge(event.target.checked)} /> Allow the installed CLI to Start this exact prepared Apple step once, with its existing credentials and limits.</label>
    <div className="actions">
      <button type="button" disabled={!!controller.allowReason()} onClick={() => void controller.allow()}>Allow this step once</button>
      <button type="button" disabled={!!controller.checkReason()} onClick={() => void controller.check()}>Check original CLI step</button>
      <button type="button" disabled={!!controller.revokeReason()} onClick={() => void controller.revoke()}>Withdraw exact permission</button>
    </div>
    {controller.allowReason() && <p className="save-note">{controller.allowReason()}</p>}
    {(state.pending || state.revoking) && <p role="status">The original permission caller is returning. Its status or cancellation does not finish native cleanup.</p>}
    {state.issue && <p role="alert">{state.issue}</p>}
    {state.stale && <p>These are the retained original controls, not permission for the currently selected project.</p>}
    {commands.map(command => <pre key={command}><code>{command}</code></pre>)}
    <p>Submit prints a request ID before sending. If its response is lost, use Status or Cancel with that ID; do not Submit again. Keep this Desktop session open. After completion, withdraw this permission before delegating a different prepared step.</p>
    {status && <p>Original CLI step: {status.state} · {status.settlement}. {status.result?.decision ? `Recorded decision: ${String(status.result.decision)}.` : ''}</p>}
    {status?.recordAtCompletion && <p>Encrypted record at completion: <code>{status.recordAtCompletion.reference.recordId}</code>. This historical reference is not a current credential loan, assignment, backup or signing-readiness proof.</p>}
    <p>No private key, CSR, P12 password, certificate bytes or credential path belongs in these commands. Account access, encrypted storage, runtime setup and any system prompts remain in the app. Assess, Assign and backup remain separate explicit actions.</p>
  </details>;
}
