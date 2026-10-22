import { useId, useSyncExternalStore } from 'react';
import { agentUploadKeyCommands } from '../agentUploadKeyAccess.ts';
import type { AgentUploadKeyKind } from '../agentUploadKeyAccess.ts';
import type { AgentUploadKeyAccessController } from '../agentUploadKeyAccessController.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

// No mount query, automatic Allow/Submit, password entry or second key owner.
export function AgentUploadKeyAccess({ controller }: { controller: AgentUploadKeyAccessController }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot), id = useId();
  const access = state.access, remaining = controller.remainingSeconds();
  const backupOptions = state.kind === 'backup-encrypted' ? controller.backupOptions() : [];
  const assessing = state.kind === 'prepare-existing' || state.kind === 'credential-assess-existing';
  const prepareOptions = assessing ? controller.prepareOptions() : [];
  const commands = access && (access.consumed || !state.stale && !state.unknown) ? agentUploadKeyCommands(access) : [];
  const status = state.unknown ? 'Permission is unconfirmed — do not repeat this action' : state.revoking ? 'Withdrawing the original permission…' :
    state.pending === 'allow' ? 'Allowing this one action…' : state.pending === 'status' ? 'Checking the original permission…' :
      access?.consumed ? 'Permission used — this is not proof that the action completed' : state.stale ? 'Check permission before continuing' :
        access?.enabled ? 'One CLI action was allowed at the last check' : 'Permission is off at the last check';
  return <ProgressiveDisclosure title="Let a CLI or AI tool use one credential review · optional"
    description="Keep using Desktop unless a trusted local tool needs this one action. No private key or password is sent to the CLI."
    needsAttention={controller.ownerReason() !== null || state.issue !== null}>
    <section className="credential-guidance" aria-labelledby={`${id}-title`}>
      <h4 id={`${id}-title`}>Credentials · one-use local permission</h4>
      <p>Prefer the key your app already uses. A tool can load and assess your selected existing key, but assigning it always needs a separate review and permission. New-app generation and encrypted backup/restore remain separate actions. For other local credentials, prepare the source and private fields in Desktop first, then separately allow Save, fresh assessment, or Assign. This panel cannot choose files or tools, replace a key, or bypass an uncertain earlier action.</p>
      <label htmlFor={`${id}-kind`}>One action to allow in Desktop</label>
      <select id={`${id}-kind`} value={state.kind} disabled={controller.ownerReason() !== null}
        onChange={(e) => controller.setKind(e.target.value as AgentUploadKeyKind)}>
        <option value="credential-import-prepared">Save the prepared NEW encrypted credential</option>
        <option value="credential-assess-existing">Load and assess another existing encrypted credential</option>
        <option value="credential-assign-reviewed">Assign the reviewed encrypted credential</option>
        <option value="prepare-existing">Load and assess a selected existing Android key</option>
        <option value="bind-reviewed">Assign the reviewed existing Android key</option>
        <option value="generate-new">Generate and save one key for a new app</option>
        <option value="backup-encrypted">Back up a selected encrypted Android key</option>
        <option value="restore-encrypted">Restore an encrypted Android key as a new record</option>
      </select>
      {assessing && <>
        <label htmlFor={`${id}-prepare-record`}>{state.kind === 'prepare-existing' ? 'Existing encrypted Android key' : 'Existing encrypted credential'}</label>
        <select id={`${id}-prepare-record`} value={state.prepareRecord?.recordId ?? ''} disabled={controller.ownerReason() !== null}
          onChange={(e) => { const row = prepareOptions.find(r => r.recordId === e.target.value); controller.setPrepareRecord(row ?? null); }}>
          <option value="">Select the record to load and assess</option>
          {prepareOptions.map(r => <option key={r.recordId} value={r.recordId}>{r.label} · {r.recordId} · revision {r.expectedRevision}</option>)}
        </select>
        <p>Submit only loads and checks this existing encrypted record. When the original command reports review-ready, Check original permission here to read its current review. Then withdraw this permission, inspect the ordinary Assign review, and separately allow assignment. Nothing is generated, replaced or automatically assigned. Android keys retain their separate existing-key action.</p>
      </>}
      {state.kind === 'credential-import-prepared' && <p>First use Desktop’s normal Choose/private-fields/Prepare controls to open a NEW encrypted Save review. This permission saves only that exact prepared import. The saved descriptor is not a payload assessment or assignment: withdraw the used permission, explicitly load and assess the new record, then separately review Assign. CLI-triggered Choose, replacement and session-only import are not supported here.</p>}
      {state.kind === 'credential-assign-reviewed' && <p>This assigns only the exact current returned Bind review. A preceding Save result, record list, or permission status cannot stand in for a fresh authenticated Load and assessment. The assignment lasts only in this Desktop context.</p>}
      {state.kind === 'backup-encrypted' && <>
        <label htmlFor={`${id}-record`}>Existing encrypted Android key</label>
        <select id={`${id}-record`} value={state.backupRecord?.recordId ?? ''} disabled={controller.ownerReason() !== null}
          onChange={(e) => { const row = backupOptions.find((r) => r.recordId === e.target.value); controller.setBackupRecord(row ?? null); }}>
          <option value="">Select the key to back up</option>
          {backupOptions.map((r) => <option key={r.recordId} value={r.recordId}>{r.label} · {r.recordId} · revision {r.expectedRevision}</option>)}
        </select>
        <p>After the CLI submits this permission, Desktop asks for two separate new file locations: an encrypted backup and its recovery-code file. Keep both safe and apart. No file or code is returned to the CLI.</p>
      </>}
      {state.kind === 'restore-encrypted' && <p>After Submit, select the encrypted backup and its recovery-code file in Desktop’s two native dialogs. Restore adds a new, unassigned Android-key record; it never replaces or assigns an existing key. After completion, withdraw this permission, then use the ordinary Select/Assess and Assign review separately.</p>}
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
      <p>Prepared import, generation and restore save an encrypted, unassigned record. Assigning an existing key applies only to the current Desktop context. Backup requires its own separate permission and both native dialogs. No action remembers an assignment for a later launch, signs a build or verifies Apple/Play account access or certificate trust.</p>
      <p className="save-note">Withdrawal asks the same original request to stop; it does not undo a saved record or backup file, or prove cleanup. Files or a new record may already exist after a stopped or unknown result. Do not replay it. Keep the original request’s Status/Cancel commands and use Desktop’s existing recovery controls when required.</p>
      <details><summary>Commands and original request details</summary>
        <p>These commands are instructions, not buttons that execute. The installed CLI prints its original request ID before sending Submit; keep that ID if a reply is lost.</p>
        {commands.map((command) => <pre key={command}><code>{command}</code></pre>)}
        {!commands.length && <p>No new submit command is offered. Check or withdraw an existing permission first.</p>}
        {access?.grantId && <dl><dt>Service project</dt><dd><code>{access.projectId}</code></dd><dt>Running service</dt><dd><code>{access.serviceInstance}</code></dd>
          <dt>Permission</dt><dd><code>{access.grantId}</code></dd><dt>Allowed action</dt><dd>{access.kind}</dd>
          {access.requestId && <><dt>Original request</dt><dd><code>{access.requestId}</code></dd></>}</dl>}
        <p>No private path, key, password, recovery code or recovery acknowledgment is accepted by these CLI commands. Native backup availability is still required. There is no automatic second action or assignment after Save or restore. General credential delegation does not enable native availability or make this a headless import flow.</p>
      </details>
    </section>
  </ProgressiveDisclosure>;
}
