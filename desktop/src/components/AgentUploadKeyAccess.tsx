import { useId, useSyncExternalStore } from 'react';
import { agentUploadKeyCommands } from '../agentUploadKeyAccess.ts';
import type { AgentUploadKeyKind } from '../agentUploadKeyAccess.ts';
import type { AgentUploadKeyAccessController } from '../agentUploadKeyAccessController.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

// No mount query, automatic Allow/Submit, password entry or second key owner.
export function AgentUploadKeyAccess({ controller }: { controller: AgentUploadKeyAccessController }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot), id = useId();
  const access = state.access, remaining = controller.remainingSeconds();
  const commands = access && (access.consumed || !state.stale && !state.unknown) ? agentUploadKeyCommands(access) : [];
  const status = state.unknown ? 'Permission is unconfirmed — do not repeat this action' : state.revoking ? 'Withdrawing the original permission…' :
    state.pending === 'allow' ? 'Allowing this one action…' : state.pending === 'status' ? 'Checking the original permission…' :
      access?.consumed ? 'Permission used — this is not proof that the key was saved or assigned' : state.stale ? 'Check permission before continuing' :
        access?.enabled ? 'One CLI action was allowed at the last check' : 'Permission is off at the last check';
  return <ProgressiveDisclosure title="Let a CLI or AI tool use one signing-key review · optional"
    description="Keep using Desktop unless a trusted local tool needs this one action. No private key or password is sent to the CLI."
    needsAttention={controller.ownerReason() !== null || state.issue !== null}>
    <section className="credential-guidance" aria-labelledby={`${id}-title`}>
      <h4 id={`${id}-title`}>Android upload key · one-use local permission</h4>
      <p>First use the ordinary controls above. Prefer the key your app already uses. This panel delegates only a completed new-app setup or the exact existing-key Assign review; it cannot select files, choose a tool or bypass an uncertain earlier key.</p>
      <label htmlFor={`${id}-kind`}>Action already reviewed in Desktop</label>
      <select id={`${id}-kind`} value={state.kind} disabled={controller.ownerReason() !== null}
        onChange={(e) => controller.setKind(e.target.value as AgentUploadKeyKind)}>
        <option value="bind-reviewed">Assign the reviewed existing Android key</option>
        <option value="generate-new">Generate and save one key for a new app</option>
      </select>
      {state.kind === 'generate-new' && <label><input type="checkbox" checked={state.newApplication}
        disabled={controller.selectionReason() !== null} onChange={(e) => controller.setNewApplication(e.target.checked)} />
        This is a new app, and I have never used an upload key for it. Do not replace an existing key.</label>}
      <label><input type="checkbox" checked={state.acknowledged} disabled={controller.selectionReason() !== null || state.kind === 'generate-new' && !state.newApplication}
        onChange={(e) => controller.setAcknowledged(e.target.checked)} />Allow a trusted local CLI or AI tool to perform only this one reviewed action</label>
      <p className="save-note">Keep Desktop open and explicitly allow its ordinary CLI read access first. This separate action permission lasts at most five minutes, never beyond the original review/read grant. Checking does not renew it.</p>
      <p role={state.unknown ? 'alert' : 'status'}>{status}</p>
      {!state.stale && access?.enabled && <p>{remaining === null || remaining === 0 ? 'The permission may have expired. Check again; do not resubmit.' :
        `At most ${remaining} seconds remain, estimated from the original permission check.`}</p>}
      {state.issue && <p className="review-caution" role="alert">{state.issue}</p>}
      <div className="button-row">
        <button type="button" className="button secondary" disabled={controller.allowReason() !== null} onClick={() => void controller.allow()}>Allow one CLI action</button>
        <button type="button" className="button secondary" disabled={controller.statusReason() !== null} onClick={() => void controller.check()}>Check original permission</button>
        <button type="button" className="button secondary" disabled={controller.revokeReason() !== null} onClick={() => void controller.revoke()}>Withdraw / request Stop</button>
      </div>
      <p className="toolbar-reason">{controller.allowReason() ?? 'Only this exact reviewed action can be submitted. Desktop checks its original source again.'}</p>
      <p>Generation saves an encrypted, unassigned key. Assigning an existing key applies only to the current Desktop context. Neither operation remembers the assignment for a later launch, makes a backup, signs a build or verifies Play access.</p>
      <p className="save-note">Withdrawal asks the same original request to stop; it does not undo a saved key or prove cleanup. Lost or unknown results must not be replayed. Use the original request’s Status/Cancel commands, and Desktop’s existing recovery controls when required.</p>
      <details><summary>Commands and original request details</summary>
        <p>These commands are instructions, not buttons that execute. The installed CLI prints its original request ID before sending Submit; keep that ID if a reply is lost.</p>
        {commands.map((command) => <pre key={command}><code>{command}</code></pre>)}
        {!commands.length && <p>No new submit command is offered. Check or withdraw an existing permission first.</p>}
        {access?.grantId && <dl><dt>Service project</dt><dd><code>{access.projectId}</code></dd><dt>Running service</dt><dd><code>{access.serviceInstance}</code></dd>
          <dt>Permission</dt><dd><code>{access.grantId}</code></dd><dt>Allowed action</dt><dd>{access.kind}</dd>
          {access.requestId && <><dt>Original request</dt><dd><code>{access.requestId}</code></dd></>}</dl>}
        <p>No CLI backup/import, private path, password, recovery acknowledgment or automatic second action is supported by this permission.</p>
      </details>
    </section>
  </ProgressiveDisclosure>;
}
