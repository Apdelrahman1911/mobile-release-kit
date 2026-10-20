import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { appleProfileResultCopy, isAppleProfileMode, type AppleProfileMode } from '../appleProfileSetup.ts';

interface Props {
  controller: AppleProvisioningController;
  state: AppleProvisioningState;
  onSigningCredentials(): void;
  onCredentials(): void;
}
const labels: Record<AppleProfileMode, string> = {
  'profile-review': 'Check existing signing setup',
  'profile-reuse': 'Reuse and save profile',
  'profile-create': 'Create and save profile',
  'profile-reconcile': 'Check earlier profile request',
};
const consent: Record<AppleProfileMode, string> = {
  'profile-review': 'Check my selected P12/password and read the Apple records visible to my selected App Store Connect key. Do not create or save a profile.',
  'profile-reuse': 'Download the exact reviewed existing profile and save one new encrypted copy. Do not create a profile, replace a saved record or assign it automatically.',
  'profile-create': 'Recheck for a reusable profile, then send at most one matching profile request only if still needed. Download it and save one new encrypted copy. Do not create or revoke a key or certificate.',
  'profile-reconcile': 'Read the earlier profile request without repeating it or saving another copy. Keep any unresolved earlier outcome.',
};

export function AppleSigningSetup({ controller, state, onSigningCredentials, onCredentials }: Props) {
  const result = state.profileResult;
  const copy = result ? appleProfileResultCopy(result, state.savedProfile) : null;
  const permission = state.consent && isAppleProfileMode(state.consent.mode) ? { ...state.consent, mode: state.consent.mode } : null;
  return <section aria-labelledby="apple-signing-setup-title">
    <h3 id="apple-signing-setup-title">Set up Apple signing</h3>
    <p>Use your existing distribution P12 and password. MRK checks for a matching App Store profile before offering to create one.</p>
    <p>No new key or certificate, build, upload or release. Apps with extra capabilities may need manual setup in Apple’s portal.</p>
    <div className="actions">
      <button type="button" disabled={state.retained} onClick={onSigningCredentials}>Choose signing inputs</button>
      <button type="button" disabled={!state.ios || !!state.profileReviewReason} onClick={() => void controller.prepare('profile-review')}>Prepare signing check</button>
    </div>
    {state.profileReviewReason && <p className="save-note">{state.profileReviewReason}</p>}
    {copy && <div role="status"><h4>{copy.title}</h4><p>{copy.detail}</p>
      {state.historical && <p>This is an earlier result, not permission for the current selection.</p>}
      {state.savedProfile && <button type="button" disabled={state.retained} onClick={onCredentials}>Open saved credentials</button>}
    </div>}
    {state.profileReviewReference && <div className="actions">
      {result?.decision === 'reuse-available' && <button type="button" disabled={!!state.profileReuseReason}
        onClick={() => void controller.prepare('profile-reuse')}>Prepare reuse and save</button>}
      {result?.decision === 'create-available' && <button type="button" disabled={!!state.profileCreateReason}
        onClick={() => void controller.prepare('profile-create')}>Prepare one profile request</button>}
    </div>}
    {permission && <div className="notice">
      <h4>{labels[permission.mode]}</h4><p>{consent[permission.mode]}</p>
      <p>Cancel cannot undo a request already sent to Apple. An uncertain request is never retried automatically.</p>
      <label><input type="checkbox" checked={permission.acknowledged} onChange={event => controller.acknowledge(permission.operationId, permission.ownerGeneration, event.target.checked)} /> I authorize this operation once.</label>
      <button type="button" disabled={!!state.startReason} onClick={() => void controller.start(permission.operationId, permission.ownerGeneration)}>Start</button>
      {state.startReason && <p className="save-note">{state.startReason}</p>}
    </div>}
    {state.profileAttemptReference && <div className="actions">
      <button type="button" disabled={!!state.profileReconcileReason} onClick={() => void controller.prepare('profile-reconcile')}>Prepare read-only check of earlier request</button>
      {state.profileReconcileReason && <p className="save-note">{state.profileReconcileReason}</p>}
    </div>}
    <details><summary>What is checked and saved</summary>
      <p>The check uses the current encrypted P12/password and API key in the dedicated This Mac · iOS · Candidate · Set up Apple signing context. A previous Store or Signing assignment is not reused as permission.</p>
      <p>Complete Apple records, the exact certificate and private-key public key, offline certificate policy, and the authenticated profile must agree. Profile saving is separate from account requests and requires its own confirmed encrypted write and readback. A returned download alone is not a saved or assigned credential.</p>
      <p>The same original operation retains its deadlines, private inputs, journal and cleanup. A cancelled or uncertain result stays recorded; this view cannot clear it. New-key/CSR generation and certificate issuance are not part of this operation.</p>
      {state.savedProfile && <p>Saved record: <code>{state.savedProfile.recordId}</code> · revision {state.savedProfile.revisionCounter}. This historical reference is not a current assignment or signing approval.</p>}
    </details>
  </section>;
}
