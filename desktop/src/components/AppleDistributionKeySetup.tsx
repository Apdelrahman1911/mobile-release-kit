import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { appleDistributionKeyResultCopy, isAppleDistributionKeyMode, type AppleDistributionKeyMode } from '../appleDistributionKeySetupProtocol.ts';

interface Props {
  controller: AppleProvisioningController;
  state: AppleProvisioningState;
  onKeyCredentials(): void;
  onCredentials(): void;
}
const consent: Record<AppleDistributionKeyMode, string> = {
  'key-review': 'Read the Apple signing records visible to my selected App Store Connect key and check my current encrypted key inventory. Do not generate a key or request a certificate.',
  'key-prepare': 'Create one local signing key only if the same review still permits it, and save a new encrypted copy. Never replace or revoke an existing key. If creation has started, preserve the key even if I stop setup. Do not request a certificate or assign signing credentials.',
};

export function AppleDistributionKeySetup({ controller, state, onKeyCredentials, onCredentials }: Props) {
  const op = state.status?.operation;
  const outcome = op && isAppleDistributionKeyMode(op.context.mode) && op.phase === 'terminal' && state.keyTerminalRead ? op.outcome : null;
  const copy = appleDistributionKeyResultCopy(state.keyResult, state.savedKey, outcome);
  const permission = state.consent && isAppleDistributionKeyMode(state.consent.mode) ? { ...state.consent, mode: state.consent.mode } : null;
  return <section aria-labelledby="apple-distribution-key-title">
    <h3 id="apple-distribution-key-title">Prepare a local signing key</h3>
    <p>Already have a distribution P12 and password? Use the existing signing setup above. Keep valid keys; do not replace them just to repeat setup.</p>
    <p>If a new local key is needed, first check the selected Apple account and encrypted storage. Creating and saving it requires a separate confirmation. This does not request an Apple certificate or make the app ready to sign.</p>
    <div className="actions">
      <button type="button" disabled={state.retained} onClick={onKeyCredentials}>Choose App Store Connect key</button>
      <button type="button" disabled={!state.ios || !!state.keyReviewReason} onClick={() => void controller.prepare('key-review')}>Prepare existing-key check</button>
    </div>
    {state.keyReviewReason && <p className="save-note">{state.keyReviewReason}</p>}
    {state.issue && op && isAppleDistributionKeyMode(op.context.mode) && <p role="alert">The original key setup is unconfirmed. Keep its status and recovery information; do not create another key or reconnect to dismiss the result.</p>}
    {copy && <div role="status"><h4>{copy.title}</h4><p>{copy.detail}</p>
      {state.historical && <p>This is an earlier result, not permission for the current app or selected key.</p>}
      {(state.savedKey || state.keyResult?.decision === 'recover-existing-key') &&
        <button type="button" disabled={state.retained} onClick={onCredentials}>Open saved credentials</button>}
    </div>}
    {state.keyReviewReference && <div className="actions">
      <button type="button" disabled={!!state.keyPrepareReason} onClick={() => void controller.prepare('key-prepare')}>Prepare local key creation</button>
      {state.keyPrepareReason && <p className="save-note">{state.keyPrepareReason}</p>}
    </div>}
    {permission && <div className="notice">
      <h4>{permission.mode === 'key-review' ? 'Check existing signing keys' : 'Create and save one local key'}</h4>
      <p>{consent[permission.mode]}</p>
      <label><input type="checkbox" checked={permission.acknowledged}
        onChange={event => controller.acknowledge(permission.operationId, permission.ownerGeneration, event.target.checked)} /> I authorize this operation once.</label>
      <button type="button" disabled={!!state.startReason} onClick={() => void controller.start(permission.operationId, permission.ownerGeneration)}>
        {permission.mode === 'key-review' ? 'Check existing keys' : 'Create and save key'}
      </button>
      {state.startReason && <p className="save-note">{state.startReason}</p>}
    </div>}
    <details><summary>What this local-key step does</summary>
      <p>Use the current App Store Connect P8, Key ID and Issuer ID in the dedicated This Mac · iOS · Candidate · Set up Apple signing context. No P12 is needed for this check. Changing the saved app, API key or display name invalidates the review.</p>
      <p>A new key is kept only in encrypted storage. Its private bytes and certificate request are not shown here. Certificate issuance below, P12 association and signing assignment are separate steps. No certificate is requested by these buttons.</p>
      <p>An independent encrypted backup is a separate action in saved credentials. Keep its recovery code separately. A displayed saved reference does not mean the key was backed up or can already sign a release.</p>
      {state.savedKey && <p>Saved record: <code>{state.savedKey.recordId}</code> · revision {state.savedKey.revisionCounter}. This is historical saved-record information, not a current assignment.</p>}
    </details>
  </section>;
}
