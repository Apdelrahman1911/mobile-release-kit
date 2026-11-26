import { useState } from 'react';
import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { appleP12Copy, isAppleP12Mode, type AppleP12Mode } from '../appleP12SetupProtocol.ts';
import type { AppleP12FingerprintEdit, AppleP12FingerprintView } from '../appleP12Fingerprint.ts';

interface Props {
  controller: AppleProvisioningController; state: AppleProvisioningState;
  onSigningCredentials(): void; onCredentials(): void;
  fingerprint?: AppleP12FingerprintView; onUseFingerprint?(edit: AppleP12FingerprintEdit): boolean;
}
const labels: Record<AppleP12Mode, string> = {
  'p12-review': 'Check P12 setup', 'p12-reuse': 'Recheck this P12', 'p12-save': 'Save new P12 to encrypted vault',
};
const consent: Record<AppleP12Mode, string> = {
  'p12-review': 'Check the selected saved key, any assigned P12, and Apple’s signing records. This will not create or save a P12, generate a key, request a certificate or change assignments.',
  'p12-reuse': 'Check this same assigned P12 again against the saved key and Apple’s signing records. Nothing will be created, replaced, saved or assigned.',
  'p12-save': 'Recheck this existing key and certificate. If the checks pass, package them as one new P12 and save it with its password in the encrypted vault. Do not replace existing items, assign credentials, generate a key, request a certificate or start a build.',
};

export function AppleP12Setup({ controller, state, onSigningCredentials, onCredentials, fingerprint, onUseFingerprint }: Props) {
  const [fingerprintChanged, setFingerprintChanged] = useState(false);
  const op = state.status?.operation;
  const outcome = op && isAppleP12Mode(op.context.mode) && state.p12TerminalRead ? op.outcome : null;
  const copy = appleP12Copy(state.p12Result, state.savedP12, outcome);
  const permission = state.consent && isAppleP12Mode(state.consent.mode) ? { ...state.consent, mode: state.consent.mode } : null;
  return <section aria-labelledby="apple-p12-setup-title">
    <h3 id="apple-p12-setup-title">Set up your iOS signing file (P12)</h3>
    <p>A P12 contains a private signing key and its certificate. Already have a distribution P12 and password? Reuse them instead of creating a replacement: open signing credentials, check the P12, then explicitly assign it to this app.</p>
    <p>Otherwise, check whether the saved key selected above and its <strong>existing certificate</strong> can be packaged together. This step creates no replacement key or certificate.</p>
    <div className="actions">
      <button type="button" disabled={state.retained} onClick={onSigningCredentials}>Open signing credentials</button>
      <button type="button" disabled={state.retained} onClick={onCredentials}>Open saved credentials</button>
      <button type="button" disabled={!state.ios || !!state.p12ReviewReason} onClick={() => void controller.prepare('p12-review')}>Review signing file setup…</button>
    </div>
    {state.p12ReviewReason && <p className="save-note">{state.p12ReviewReason}</p>}
    {copy && <div role="status"><h4>{copy.title}</h4><p>{copy.detail}</p>
      {state.historical && <p>This is an earlier result, not a current selection or permission for this project.</p>}
    </div>}
    {state.issue && op && isAppleP12Mode(op.context.mode) && <p role="alert">The outcome is unclear. Keep this task and saved key; use Refresh original status or Cancel original operation above. Do not save again, reconnect to dismiss the warning, or generate a replacement.</p>}
    {state.p12ReviewReference && <div className="actions">
      {state.p12Result?.decision === 'reuse-review' ? <button type="button" disabled={!!state.p12ReuseReason}
        onClick={() => void controller.prepare('p12-reuse')}>Review reusing this P12…</button> : <button type="button" disabled={!!state.p12SaveReason}
        onClick={() => void controller.prepare('p12-save')}>Review saving a new P12…</button>}
      {(state.p12Result?.decision === 'reuse-review' ? state.p12ReuseReason : state.p12SaveReason) &&
        <p className="save-note">{state.p12Result?.decision === 'reuse-review' ? state.p12ReuseReason : state.p12SaveReason}</p>}
    </div>}
    {permission && <div className="notice">
      <h4>{labels[permission.mode]}</h4><p>{consent[permission.mode]}</p>
      {permission.mode === 'p12-save' && <p>Saving does not assign this P12 to an app or make a recoverable backup. Cancel cannot undo a completed save. Keep the saved copy, then back it up separately; do not save again if the outcome is unclear.</p>}
      <label><input type="checkbox" checked={permission.acknowledged}
        onChange={event => controller.acknowledge(permission.operationId, permission.ownerGeneration, event.target.checked)} /> I approve this one-time action.</label>
      <button type="button" disabled={!!state.startReason} onClick={() => void controller.start(permission.operationId, permission.ownerGeneration)}>{labels[permission.mode]}</button>
      {state.startReason && <p className="save-note">{state.startReason}</p>}
    </div>}
    {state.savedP12 && <div className="save-note"><p>Next: find this P12 in saved credentials. Check and assign it for the intended app, then make a separate encrypted backup.</p>
      <details><summary>Saved P12 record details</summary><p>Record: <code>{state.savedP12.recordId}</code> · revision {state.savedP12.revisionCounter}.</p></details>
    </div>}
    {fingerprint?.certificateSha256 && <div className="notice">
      <h4>Certificate fingerprint (SHA-256)</h4>
      <p>This public identifier belongs to the certificate in the saved P12 above.</p>
      <p><code>{fingerprint.certificateSha256}</code></p>
      <button type="button" disabled={!fingerprint.edit || !onUseFingerprint} onClick={() => {
        if (fingerprint.edit && onUseFingerprint) setFingerprintChanged(!onUseFingerprint(fingerprint.edit));
      }}>Add fingerprint to Settings draft</button>
      <p>Then review and save the draft in Settings. This does not assign the P12 or make signing ready.</p>
      {fingerprint.reason && <p className="save-note">{fingerprint.reason}</p>}
      {fingerprintChanged && <p role="alert">The project or result changed. Your draft was kept; check the current Settings before trying again.</p>}
    </div>}
    <details><summary>How to back up or restore a P12</summary>
      <p>This view never displays your private key or password. Use the existing saved-credential controls to import, check or assign a P12.</p>
      <p>Use <strong>Back up…</strong> on the intended encrypted record. Save its recovery code separately—you need both files to restore. <strong>Restore a backup…</strong> creates an unassigned copy; it does not replace a key or resolve an earlier uncertain save.</p>
      <p>A saved P12 alone does not mean signing is ready. This step does not create a provisioning profile, check whether Apple revoked a certificate, or release an app. If a save is uncertain, keep its task and saved records; do not repeat it. Unsupported setups need manual Apple setup.</p>
    </details>
  </section>;
}
