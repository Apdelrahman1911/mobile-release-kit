import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { appleP12Copy, isAppleP12Mode, type AppleP12Mode } from '../appleP12SetupProtocol.ts';

interface Props {
  controller: AppleProvisioningController; state: AppleProvisioningState;
  onSigningCredentials(): void; onCredentials(): void;
}
const labels: Record<AppleP12Mode, string> = {
  'p12-review': 'Check P12 setup', 'p12-reuse': 'Recheck the existing P12', 'p12-save': 'Save one encrypted P12',
};
const consent: Record<AppleP12Mode, string> = {
  'p12-review': 'Check the selected saved key, current assigned P12 if present, and Apple signing records. Do not assemble or save a P12, generate a key, issue a certificate or change an assignment.',
  'p12-reuse': 'Recheck the same reviewed, assigned P12 against the saved key and Apple signing records. Do not create, replace, save or assign anything.',
  'p12-save': 'Recheck the reviewed key and certificate, then assemble and save one new encrypted P12 and its password if still permitted. Do not replace an existing item, assign it, generate a key, issue a certificate or start a build.',
};

export function AppleP12Setup({ controller, state, onSigningCredentials, onCredentials }: Props) {
  const op = state.status?.operation;
  const outcome = op && isAppleP12Mode(op.context.mode) && state.p12TerminalRead ? op.outcome : null;
  const copy = appleP12Copy(state.p12Result, state.savedP12, outcome);
  const permission = state.consent && isAppleP12Mode(state.consent.mode) ? { ...state.consent, mode: state.consent.mode } : null;
  return <section aria-labelledby="apple-p12-setup-title">
    <h3 id="apple-p12-setup-title">Prepare your signing P12</h3>
    <p>Already have a distribution P12 and password? Keep them. Open saved credentials, assess and assign that P12 in <strong>Set up Apple signing</strong> first. Otherwise, this step can package the saved key selected above with its existing certificate.</p>
    <div className="actions">
      <button type="button" disabled={state.retained} onClick={onSigningCredentials}>Choose existing signing inputs</button>
      <button type="button" disabled={state.retained} onClick={onCredentials}>Open saved credentials</button>
      <button type="button" disabled={!state.ios || !!state.p12ReviewReason} onClick={() => void controller.prepare('p12-review')}>Review P12 setup</button>
    </div>
    {state.p12ReviewReason && <p className="save-note">{state.p12ReviewReason}</p>}
    {copy && <div role="status"><h4>{copy.title}</h4><p>{copy.detail}</p>
      {state.historical && <p>This is an earlier result, not a current selection or permission for this project.</p>}
    </div>}
    {state.issue && op && isAppleP12Mode(op.context.mode) && <p role="alert">Keep the original P12 operation and saved key. Use the original status and cancellation controls above. Do not repeat the save, reconnect to dismiss it, or generate a replacement.</p>}
    {state.p12ReviewReference && <div className="actions">
      {state.p12Result?.decision === 'reuse-review' ? <button type="button" disabled={!!state.p12ReuseReason}
        onClick={() => void controller.prepare('p12-reuse')}>Review reusing this P12</button> : <button type="button" disabled={!!state.p12SaveReason}
        onClick={() => void controller.prepare('p12-save')}>Review one encrypted save</button>}
      {(state.p12Result?.decision === 'reuse-review' ? state.p12ReuseReason : state.p12SaveReason) &&
        <p className="save-note">{state.p12Result?.decision === 'reuse-review' ? state.p12ReuseReason : state.p12SaveReason}</p>}
    </div>}
    {permission && <div className="notice">
      <h4>{labels[permission.mode]}</h4><p>{consent[permission.mode]}</p>
      {permission.mode === 'p12-save' && <p>The new copy is not assigned automatically. Cancellation cannot undo a completed save. Keep it and make a separate encrypted backup; do not repeat an unconfirmed operation.</p>}
      <label><input type="checkbox" checked={permission.acknowledged}
        onChange={event => controller.acknowledge(permission.operationId, permission.ownerGeneration, event.target.checked)} /> I authorize this operation once.</label>
      <button type="button" disabled={!!state.startReason} onClick={() => void controller.start(permission.operationId, permission.ownerGeneration)}>{labels[permission.mode]}</button>
      {state.startReason && <p className="save-note">{state.startReason}</p>}
    </div>}
    {state.savedP12 && <p className="save-note">Saved P12 record: <code>{state.savedP12.recordId}</code> · revision {state.savedP12.revisionCounter}. Find this record in saved credentials, then explicitly assess and assign it for the intended context.</p>}
    <details><summary>Assignment, backup and recovery are separate</summary>
      <p>A P12 packages a private signing key and its certificate. This view never displays the key, P12 bytes or password. The existing vault controls handle import, assessment, assignment and backup.</p>
      <p>Use <strong>Back up…</strong> on the intended encrypted record. Save its recovery code separately—you need both files to restore. <strong>Restore a backup…</strong> creates an unassigned copy; it does not replace a key or resolve an earlier uncertain save.</p>
      <p>This step does not create a provisioning profile, check live revocation, approve signing or release an app. There is no replay or reset button for an uncertain P12 save. Keep the original operation and any saved records; use manual Apple setup for unsupported layouts.</p>
    </details>
  </section>;
}
