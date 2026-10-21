import { AppleP12Setup } from './AppleP12Setup.tsx';
import { isAppleP12Mode } from '../appleP12SetupProtocol.ts';
import type { AppleP12FingerprintEdit, AppleP12FingerprintView } from '../appleP12Fingerprint.ts';
import type { AppleProvisioningController, AppleProvisioningState } from '../appleProvisioningController.ts';
import { AppleDistributionCertificateSetup } from './AppleDistributionCertificateSetup.tsx';
import { isAppleDistributionCertificateMode } from '../appleDistributionCertificateSetupProtocol.ts';
import { AppleDistributionKeySetup } from './AppleDistributionKeySetup.tsx';
import { isAppleDistributionKeyMode } from '../appleDistributionKeySetupProtocol.ts';
import { AppleSigningSetup } from './AppleSigningSetup.tsx';
import { isAppleProfileMode } from '../appleProfileSetup.ts';
import type { AppleProvisioningMode, AppleProvisioningResult } from '../appleProvisioningTypes.ts';

interface Props {
  controller: AppleProvisioningController; state: AppleProvisioningState;
  onCredentials(): void; onProjectIdentity(): void; onSigningCredentials?(): void;
  p12Fingerprint?: AppleP12FingerprintView; onUseP12Fingerprint?(edit: AppleP12FingerprintEdit): boolean;
  compact?: boolean; onShow?(): void;
  // Display-only saved-configuration labels, not account/team authority.
  savedBundleId?: string | null; configuredTeamId?: string | null;
}
const modeLabel: Record<AppleProvisioningMode, string> = { review: 'reuse-first review', register: 'Bundle ID registration', reconcile: 'read-only reconciliation', 'profile-review': 'signing setup check', 'profile-reuse': 'reuse and save profile', 'profile-create': 'create and save profile', 'profile-reconcile': 'read-only profile check', 'key-review': 'existing-key check', 'key-prepare': 'create and save local key', 'certificate-review': 'existing-certificate check', 'certificate-create': 'one certificate request', 'certificate-reconcile': 'earlier certificate check', 'p12-review': 'P12 setup check', 'p12-reuse': 'existing P12 check', 'p12-save': 'new encrypted P12 save' };
const consent: Record<'review' | 'register' | 'reconcile', string> = {
  review: 'Read Bundle ID registration visible to my selected App Store Connect key. Prepare or upgrade MRK’s private provisioning journal if needed. No registration write is authorized.',
  register: 'For this declared new app, recheck existing Bundle IDs, durably record the attempt, and send at most one registration request if still needed. Do not retry an uncertain write. No certificate, profile, build or release is authorized.',
  reconcile: 'Read back the exact prior registration attempt using my selected key and private journal. Do not repeat the write, adopt a new key, or clear unknown native settlement.',
};
function resultCopy(result: AppleProvisioningResult): { title: string; detail: string } {
  if (result.decision === 'registration-confirmed') return { title: 'Bundle ID registration confirmed', detail: 'The bounded provider response/readback matched this operation. This does not create an App Store listing or make signing or release ready.' };
  if (result.decision === 'registration-unconfirmed') return { title: 'Registration outcome needs reconciliation', detail: 'A request may already have reached Apple. Do not register again. Retain the original attempt and use read-only reconciliation when the native owner permits it.' };
  if (result.decision === 'comparison-only') {
    const comparisons = { 'same-response': 'The returned resource matches the recorded response.', 'different-response': 'The returned resource differs from the recorded response; review the original attempt.',
      unattributed: 'A resource was returned, but it cannot be attributed to this attempt.', 'not-returned': 'This selected key did not return the target. That does not prove absence or that a write never happened.',
      inconclusive: 'This readback cannot establish a resource comparison.' };
    return { title: 'Readback comparison only', detail: `${result.comparison ? comparisons[result.comparison] : 'No comparison is available.'} This never clears unknown native settlement or authorizes retry.` };
  }
  if (result.decision === 'reuse') return { title: 'Reuse the returned Bundle ID', detail: 'Apple returned the exact saved Bundle ID to this selected key. No registration is needed in this flow. Team ownership, signing credentials and profile suitability remain unverified.' };
  if (result.observation === 'not-permitted') return { title: 'This key cannot perform the read', detail: 'Check Apple’s role, key-type or account-agreement restrictions. A denial is not proof that the Bundle ID is absent. No different account is selected automatically.' };
  if (result.decision === 'review-required' && result.observation === 'not-returned') return { title: 'Not returned to this key', detail: 'This is not a global availability or team-ownership claim. Only a separately reviewed new-application registration may proceed; its original private review can expire.' };
  return { title: 'No registration decision is available', detail: 'The response, prerequisites or account-wide journal fence require attention. Do not create or revoke signing credentials to work around this result.' };
}

export function AppleBundleRegistration({ controller, state, onCredentials, onProjectIdentity, onSigningCredentials, p12Fingerprint, onUseP12Fingerprint, compact = false, onShow, savedBundleId, configuredTeamId }: Props) {
  const op = state.status?.operation, result = state.result, copy = result ? resultCopy(result) : null;
  if (compact) {
    if (!state.retained && !state.issue) return null;
    return <section className="card" aria-label="Original Apple setup operation">
      <h2>Apple setup · original operation retained</h2>
      <p>{op ? `${modeLabel[op.context.mode]} · ${op.phase} · project ${op.context.projectId}` : 'Waiting for the original operation reference.'}</p>
      <p>{state.issue ? 'The outcome or cleanup is unconfirmed. Do not repeat registration or reconnect to dismiss it.' : 'Keep the original controls available until its native cleanup is known. Navigating does not finish the operation.'}</p>
      <div className="actions">
        <button type="button" onClick={onShow}>Show Apple setup</button>
        <button type="button" disabled={!state.canRead} onClick={() => void controller.checkStatus()}>Refresh original status</button>
        <button type="button" disabled={!state.canCancel} onClick={() => void controller.cancel()}>Cancel original operation</button>
      </div>
      {state.cancelRequested && <p className="save-note">Cancellation was requested; the original operation remains retained.</p>}
    </section>;
  }
  return <section className="card" aria-labelledby="apple-bundle-registration-title">
    <h2 id="apple-bundle-registration-title">Apple setup</h2>
    <p>Reuse first. Review the saved Bundle ID with the selected API key before considering one new-app registration.</p>
    <p><strong>Separate steps:</strong> Bundle ID registration, existing-profile setup, local-key preparation, certificate requests and P12 setup each need their own confirmation below. None starts a build or release.</p>
    {(savedBundleId || configuredTeamId) && <p>Saved Bundle ID: <code>{savedBundleId ?? 'not available'}</code> · Configured team (not verified): <code>{configuredTeamId ?? 'not available'}</code></p>}
    <p>Prepare is an explicit local action: it may initialize or reuse MRK’s private state. It does not grant external agents access. Apple requests require the separate confirmation below.</p>
    <label>Apple setup display name
      <input type="text" value={state.displayName} maxLength={256} onChange={event => controller.setDisplayName(event.target.value)} autoComplete="off" />
    </label>
    <p className="save-note">Use an explicit name, unchanged through review and registration. Changing saved inputs, the key or this name invalidates consent.</p>
    <div className="actions">
      <button disabled={!state.ios || !!state.reviewReason} onClick={() => void controller.prepare('review')}>Prepare reuse-first review</button>
      <button onClick={onProjectIdentity}>Review project identity</button>
      <button onClick={onCredentials}>Open local credentials</button>
    </div>
    {state.reviewReason && <p className="save-note">{state.reviewReason}</p>}
    {!state.ios && <p className="save-note">Select This Mac → iOS. Earlier operation status and cancellation remain available below.</p>}
    <details open={!!state.reviewReference || state.consent?.mode === 'register'}>
      <summary>Register only a new application</summary>
      <p>Existing apps keep their store identity. A not-returned result is not permission to change or replace it. The native owner also checks retained release continuity and the issuer-wide unresolved-attempt journal.</p>
      <label><input type="checkbox" checked={state.newApplication} onChange={event => controller.setNewApplication(event.target.checked)} /> This is a new application, not a change to an existing store app.</label>
      <button disabled={!state.ios || !!state.registerReason} onClick={() => void controller.prepare('register')}>Prepare one registration</button>
      {state.registerReason && <p className="save-note">{state.registerReason}</p>}
    </details>
    {state.consent && !isAppleProfileMode(state.consent.mode) && !isAppleDistributionKeyMode(state.consent.mode) && !isAppleDistributionCertificateMode(state.consent.mode) && !isAppleP12Mode(state.consent.mode) && <div className="notice">
      <h3>Confirm {modeLabel[state.consent.mode]}</h3>
      <p>{consent[state.consent.mode as 'review' | 'register' | 'reconcile']}</p>
      <p>Apple may log or rate-limit requests. Cancel cannot undo a request already sent. The native operation keeps uncertain outcomes for read-only reconciliation.</p>
      <label><input type="checkbox" checked={state.consent.acknowledged} onChange={event => controller.acknowledge(state.consent!.operationId, state.consent!.ownerGeneration, event.target.checked)} /> I authorize this exact operation once.</label>
      <button disabled={!!state.startReason} onClick={() => void controller.start(state.consent!.operationId, state.consent!.ownerGeneration)}>Start {modeLabel[state.consent.mode]}</button>
      {state.startReason && <p className="save-note">{state.startReason}</p>}
    </div>}
    {state.pending && <p role="status">The original {state.pending === 'prepare' ? 'local preparation' : 'Start request'} is retained{state.requestPending ? '; waiting for its response' : '; checking the original native status'}. An event cannot finish an outstanding invocation.</p>}
    <div className="actions">
      <button disabled={!state.canRead} onClick={() => void controller.checkStatus()}>Refresh original status</button>
      <button disabled={!state.canCancel} onClick={() => void controller.cancel()}>Cancel original operation</button>
    </div>
    {state.cancelRequested && <p className="save-note">Cancellation was requested. The original operation and uncertain outcomes remain retained until their actual native cleanup is known.</p>}
    {state.issue && <p role="alert">The original operation is unconfirmed or its cleanup is unknown. Keep its status; do not repeat registration, switch accounts to bypass it, or dismiss the outcome by reconnecting.</p>}
    {op && <>
      <p>{state.historical ? 'Earlier or different saved/key context · ' : ''}{modeLabel[op.context.mode]} · {op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>
      <details><summary>Original operation reference</summary><p>Project: <code>{op.context.projectId}</code><br />Operation: <code>{op.operationId}</code><br />Owner generation: <code>{op.ownerGeneration}</code></p><p>These references identify an operation. They are not account, retry or native-settlement authority.</p></details>
    </>}
    {result && copy && <div role="status">
      <h3>{copy.title}</h3><p>{copy.detail}</p>
      {state.historical && <p>This is an earlier result, not authorization for the current selection.</p>}
      <p>Complete means the bounded native operation and cleanup finished—not that signing is ready. No private-key match or authenticated profile has been established.</p>
      {result.attempt && <p>Recorded attempt: {result.attempt.status.replaceAll('_', ' ')} · {result.attempt.reason.replaceAll('_', ' ')}. Retry and credential-ready flags remain false.</p>}
    </div>}
    {state.previousAttempts && <section aria-label="Previous Bundle ID setup">
      <h3>Continue previous setup</h3>
      <p>MRK found these saved attempts for this project and Bundle ID. Choose one to check with Apple again, without registering again.</p>
      {state.previousAttempts.attempts.length === 0 && <p>No matching attempt was recorded in this journal snapshot. This does not prove that Apple received no earlier request.</p>}
      <ul>{state.previousAttempts.attempts.map(row => <li key={`${row.reference.operationId}:${row.reference.ownerGeneration}`}>
        <strong>{row.displayName}</strong> — recorded {row.observedAt}
        <p>{row.nativeSettlement !== 'known' ? 'The earlier request or cleanup is still unconfirmed. Checking with Apple will not clear that uncertainty.' :
          row.status === 'succeeded' ? 'MRK recorded a confirmed registration. This check will not register it again.' : 'Review this earlier attempt with a read-only check.'}</p>
        <button disabled={!!state.continueReason} onClick={() => void controller.continuePrevious(row.reference.operationId, row.reference.ownerGeneration)}>Continue previous setup</button>
      </li>)}</ul>
      {state.previousAttempts.hiddenUnresolved > 0 && <p>Another saved context has an unresolved attempt for this App Store Connect account. Its details are not shown here. Do not start another registration to bypass it.</p>}
      <details><summary>What these saved records mean</summary><p>These are historical local records, not a new Apple result or permission to register. The selected key and current project are checked again. A missing, denied or incomplete response never clears an uncertain attempt.</p></details>
    </section>}
    <AppleSigningSetup controller={controller} state={state} onSigningCredentials={onSigningCredentials ?? onCredentials} onCredentials={onCredentials} />
    <AppleDistributionKeySetup controller={controller} state={state} onKeyCredentials={onSigningCredentials ?? onCredentials} onCredentials={onCredentials} />
    <AppleDistributionCertificateSetup controller={controller} state={state} onKeyCredentials={onSigningCredentials ?? onCredentials} onCredentials={onCredentials} />
    <AppleP12Setup controller={controller} state={state} onSigningCredentials={onSigningCredentials ?? onCredentials} onCredentials={onCredentials}
      fingerprint={p12Fingerprint} onUseFingerprint={onUseP12Fingerprint} />
    <details open={!!state.registrationReference}>
      <summary>Read back a prior registration without retrying</summary>
      <p>This checks the selected prior attempt without repeating its write. Missing history or uncertain cleanup never means it is safe to register again.</p>
      <button disabled={!state.ios || !!state.reconcileReason} onClick={() => void controller.prepare('reconcile')}>Prepare read-only reconciliation</button>
      {state.reconcileReason && <p className="save-note">{state.reconcileReason}</p>}
    </details>
  </section>;
}
