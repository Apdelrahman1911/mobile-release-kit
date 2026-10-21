import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { appleCertificateRecoveryCopy, appleDistributionCertificateCopy, isAppleDistributionCertificateMode,
  type AppleDistributionCertificateMode } from '../appleDistributionCertificateSetupProtocol.ts';

interface Props {
  controller: AppleProvisioningController;
  state: AppleProvisioningState;
  onKeyCredentials(): void;
  onCredentials(): void;
}
const labels: Record<AppleDistributionCertificateMode, string> = {
  'certificate-review': 'Check existing certificates',
  'certificate-create': 'Request one certificate',
  'certificate-reconcile': 'Check the earlier request',
};
const consent: Record<AppleDistributionCertificateMode, string> = {
  'certificate-review': 'Read the Apple signing records visible to my selected App Store Connect key and check the selected encrypted signing key. Do not request a certificate, create a key or save a P12.',
  'certificate-create': 'Recheck the reviewed saved key and Apple records. Only if still needed, record the attempt and send one certificate request for that same key. Do not retry an uncertain request, revoke a certificate, replace the key or save a P12.',
  'certificate-reconcile': 'Read the selected earlier certificate attempt without repeating its request, replacing the saved key or saving a P12. Preserve any unresolved earlier outcome.',
};

export function AppleDistributionCertificateSetup({ controller, state, onKeyCredentials, onCredentials }: Props) {
  const op = state.status?.operation;
  const outcome = op && isAppleDistributionCertificateMode(op.context.mode) && state.certificateTerminalRead ? op.outcome : null;
  const copy = appleDistributionCertificateCopy(state.certificateResult, outcome);
  const permission = state.consent && isAppleDistributionCertificateMode(state.consent.mode) ? { ...state.consent, mode: state.consent.mode } : null;
  const selected = state.certificateKeySelection;
  const listed = !!selected && state.certificateKeyChoices.some(row => row.recordId === selected.recordId && row.recordRevision === selected.recordRevision);
  return <section aria-labelledby="apple-distribution-certificate-title">
    <h3 id="apple-distribution-certificate-title">Get a certificate for your saved key</h3>
    <p>Already have a distribution P12 and password? Keep using the existing signing setup above. Otherwise, choose the local key you saved and check for an existing certificate before requesting one.</p>
    <div className="actions">
      <button type="button" disabled={state.retained} onClick={onKeyCredentials}>Choose App Store Connect key</button>
      <button type="button" disabled={state.retained} onClick={onCredentials}>Open saved credentials</button>
    </div>
    <label>Saved signing key
      <select value={selected?.recordId ?? ''} disabled={state.retained || !state.ios} onChange={event => {
        const row = state.certificateKeyChoices.find(choice => choice.recordId === event.target.value);
        controller.selectCertificateKey(row?.recordId ?? null, row?.recordRevision ?? null);
      }}>
        <option value="">Choose a saved key…</option>
        {selected && !listed && <option value={selected.recordId}>Earlier selection — check saved credentials</option>}
        {state.certificateKeyChoices.map((row, index) => <option key={row.recordId} value={row.recordId}>
          Saved key {index + 1} · {row.recordId.slice(0, 8)} · revision {row.recordRevision}
        </option>)}
      </select>
    </label>
    <p className="save-note">Only current encrypted signing-key records are listed. If the key is missing, open saved credentials and refresh them. Do not generate a replacement just to repeat setup.</p>
    <div className="actions">
      <button type="button" disabled={!state.ios || !!state.certificateReviewReason} onClick={() => void controller.prepare('certificate-review')}>Review certificate setup</button>
    </div>
    {state.certificateReviewReason && <p className="save-note">{state.certificateReviewReason}</p>}
    {copy && <div role="status"><h4>{copy.title}</h4><p>{copy.detail}</p>
      {state.historical && <p>This is an earlier result, not permission for the current project or selected key.</p>}
    </div>}
    {state.issue && op && isAppleDistributionCertificateMode(op.context.mode) && <p role="alert">
      Keep the saved key and this original request. Its outcome or cleanup is unconfirmed. Use the original status and cancellation controls; do not request again or reconnect to dismiss it.
    </p>}
    {state.certificateReviewReference && <div className="actions">
      <button type="button" disabled={!!state.certificateCreateReason} onClick={() => void controller.prepare('certificate-create')}>Review one certificate request</button>
      {state.certificateCreateReason && <p className="save-note">{state.certificateCreateReason}</p>}
    </div>}
    {permission && <div className="notice">
      <h4>{labels[permission.mode]}</h4><p>{consent[permission.mode]}</p>
      {permission.mode === 'certificate-create' && <p>Apple may require a suitable role, accepted agreements and an available certificate slot. Cancel cannot undo a request already sent. Keep an independent encrypted backup of the key and its recovery code separately.</p>}
      <label><input type="checkbox" checked={permission.acknowledged}
        onChange={event => controller.acknowledge(permission.operationId, permission.ownerGeneration, event.target.checked)} /> I authorize this operation once.</label>
      <button type="button" disabled={!!state.startReason} onClick={() => void controller.start(permission.operationId, permission.ownerGeneration)}>{labels[permission.mode]}</button>
      {state.startReason && <p className="save-note">{state.startReason}</p>}
    </div>}
    {state.previousCertificateAttempts && <section aria-label="Earlier certificate requests">
      <h4>Continue an earlier certificate request</h4>
      <p>Choose a recorded request to check it with Apple without issuing another certificate. A restored key must match the original key and certificate request. Only its earlier display name is reused; all current inputs are checked again.</p>
      <ul>{state.previousCertificateAttempts.attempts.map(row => <li key={`${row.reference.operationId}:${row.reference.ownerGeneration}`}>
        <strong>{row.displayName}</strong> — recorded {row.observedAt}
        <p>{appleCertificateRecoveryCopy(row)}</p>
        <button type="button" disabled={!!state.certificateContinueReason}
          onClick={() => void controller.continuePreviousCertificate(row.reference.operationId, row.reference.ownerGeneration)}>Check earlier request…</button>
      </li>)}</ul>
      {state.previousCertificateAttempts.attempts.length === 0 && <p>No matching request appears in this snapshot. That does not prove that Apple received nothing.</p>}
      {state.previousCertificateAttempts.hiddenUnresolved > 0 && <p>Other unresolved setup for this Apple account is not shown here. Keep its original records; another certificate request cannot bypass it.</p>}
      {state.certificateContinueReason && <p className="save-note">{state.certificateContinueReason}</p>}
    </section>}
    {state.certificateAttemptReference && <div className="actions">
      <button type="button" disabled={!!state.certificateReconcileReason}
        onClick={() => void controller.prepare('certificate-reconcile')}>Review a read-only check of the earlier request</button>
      {state.certificateReconcileReason && <p className="save-note">{state.certificateReconcileReason}</p>}
    </div>}
    <details><summary>Certificate, key and signing: what is separate?</summary>
      <p>The private key stays in encrypted storage. This view never displays a certificate request, private bytes or API token. The native operation checks the actual saved key; a listed record is not permission to use it.</p>
      <p>A certificate alone is not a P12, provisioning profile, signing assignment or release approval. After restoring an encrypted key backup, select the restored record and check existing certificates to find matching earlier requests. Checking one does not resolve its earlier uncertainty or permit another request. Existing P12/profile setup remains separate; unresolved account setup still blocks it.</p>
      <p>The check does not establish live revocation status. A missing or incomplete Apple response never authorizes another request.</p>
      {selected && <p>Selected saved record: <code>{selected.recordId}</code> · revision {selected.recordRevision}. This is a selection comparison, not a current native key loan.</p>}
      {state.certificateResult?.certificateId && <p>Recorded certificate: <code>{state.certificateResult.certificateId}</code>. This identifier is not a saved P12 or signing approval.</p>}
    </details>
  </section>;
}
