import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { appleProfileRecoveryCopy } from '../appleProfileRecoverySelection.ts';

interface Props {
  controller: AppleProvisioningController;
  state: AppleProvisioningState;
}
export function AppleProfileRecovery({ controller, state }: Props) {
  const history = state.previousProfileAttempts;
  return <section aria-label="Earlier Apple profile setup">
    <h4>Continue an earlier profile setup</h4>
    {!history ? <p className="save-note">After restarting, choose the same saved app, existing P12 and App Store Connect key, then use “Prepare signing check” above. Completed checks can show the matching saved attempts here.</p> : <>
      <p>Choose an earlier attempt to check with Apple. This will not create a profile, save another copy or replace a signing key.</p>
      {history.attempts.length === 0 && <p>No matching attempt was recorded for this selection. This does not prove that Apple received no earlier request.</p>}
      <ul>{history.attempts.map(row => {
        const copy = appleProfileRecoveryCopy(row);
        return <li key={`${row.reference.operationId}:${row.reference.ownerGeneration}`}>
          <strong>{row.displayName}</strong> — {row.action === 'create-profile' ? 'profile request' : 'reuse existing profile'}
          <p>{copy.provider}. {copy.storage}. {copy.detail}</p>
          {row.cancellationRequested && <p>Cancellation was recorded; it does not undo a request already sent.</p>}
          <button type="button" disabled={!!state.profileContinueReason}
            onClick={() => void controller.continuePreviousProfile(row.reference.operationId, row.reference.ownerGeneration)}>Review read-only check</button>
          <details><summary>Saved attempt details</summary>
            <p>Recorded: {row.observedAt}<br />Earlier native cleanup: {row.nativeSettlement === 'known' ? 'recorded as complete' : 'not confirmed'}</p>
            <p>Operation: <code>{row.reference.operationId}</code><br />Owner reference: <code>{row.reference.ownerGeneration}</code></p>
          </details>
        </li>;
      })}</ul>
      {history.hiddenUnresolved > 0 && <p>Another saved selection or setup task has an unresolved attempt for this Apple account. Keep the original records; do not create a new profile or key to bypass it.</p>}
      {state.profileContinueReason && <p className="save-note">{state.profileContinueReason}</p>}
    </>}
  </section>;
}
