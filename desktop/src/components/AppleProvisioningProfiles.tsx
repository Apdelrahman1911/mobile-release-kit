import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import { APPLE_PROFILE_QUERY, APPLE_PROFILE_SCOPE, APPLE_BUNDLE_QUERY } from '../localStorePreflightProtocol.ts';
import type { BundleIdObservation, StoreCheck } from '../localStorePreflightTypes.ts';
import { sameOfflineData } from '../offlinePreflightProtocol.ts';

const descriptions: Record<BundleIdObservation, { title: string; detail: string }> = {
  found: { title: 'Matching profile metadata returned', detail: 'The selected key returned App Store profile metadata related to the saved Bundle ID. These are resources to inspect first, not verified profiles, usable certificates or matching private keys.' },
  'not-returned': { title: 'No matching profile metadata returned for this key', detail: 'This one fully parsed response contained no matching App Store profile metadata. It does not prove absence elsewhere, team ownership, certificate availability or permission to create a replacement.' },
  'not-permitted': { title: 'Apple did not permit this metadata read', detail: 'Review the selected team API key, permissions and account agreements manually. Unauthorized access is not evidence that a profile or certificate is missing.' },
  inconclusive: { title: 'Profile metadata comparison is inconclusive', detail: 'An incomplete page, missing relationship count, unsupported metadata or unconfirmed response cannot establish a reuse or absence conclusion. Review existing resources in Apple Developer rather than creating duplicates.' },
  'not-checked': { title: 'Profile metadata was not checked', detail: 'Resolve the saved-input, selected-key or bundled-runtime findings. No profile or certificate conclusion was made.' },
};
const labels: Partial<Record<StoreCheck, string>> = {
  'credential-format': 'Selected App Store Connect private-key format',
  'query-prerequisites': 'Saved iOS Bundle ID and selected API key',
  'runtime-unavailable': 'Bundled Store runtime',
  'bundle-unavailable': 'Bundled Store dependencies',
};

/** View of the SAME existing LocalStorePreflight controller/native operation. */
export function AppleProvisioningProfiles({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreState; controller: LocalStorePreflightController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op = state.status?.operation, reason = controller.prepareReason(), retained = localStoreOwnerReason(state);
  if (op?.context.query !== APPLE_PROFILE_QUERY) {
    if (compact || state.platform !== 'ios') return null;
    return <details><summary>Look for existing App Store profile metadata</summary>
      <p>Read one page of profiles visible to the selected App Store Connect key, then compare their related Bundle IDs locally. Only metadata is read; no profile or certificate is downloaded or changed.</p>
      <p>Existing resources should be inspected before creating replacements. This check cannot match a private key or establish usable signing credentials.</p>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare(APPLE_PROFILE_QUERY)}>Review profile metadata check</button>
      {reason && <p className="save-note">{reason}</p>}
    </details>;
  }
  if (compact && !retained) return null;
  const historical = state.historical || !state.request || !sameOfflineData(op.context, {
    ...state.request, platform: state.request.platform ?? 'android', query: APPLE_PROFILE_QUERY, operation: 'local-store-preflight',
  });
  const result = op.result?.scope === APPLE_PROFILE_SCOPE ? op.result : null;
  const summary = result?.profileReuse, copy = summary ? descriptions[summary.observation] : null;
  return <section className="card" aria-label="Existing App Store profile metadata check">
    <div className="inline-heading"><h2>Existing profile metadata · This Mac</h2>{compact && <button onClick={onShow}>Show check</button>}</div>
    {!compact && <>
      <p>Reuse first: look for App Store profile metadata related to the saved iOS Bundle ID. Uses the assigned App Store Connect team key and the existing local Store check owner.</p>
      <p><strong>Metadata only:</strong> no profile/certificate content or private signing key is read; no creation, replacement, revocation, assignment, build or release. This is not the account’s complete certificate inventory.</p>
      <details><summary>Prerequisites and next steps</summary><p>Save the iOS Bundle ID and read its saved version, then assign your original API P8, matching Key ID and Issuer ID. Apple may restrict these APIs by key type, role or account agreements. Unsupported, denied or incomplete responses require manual review, not a different account chosen automatically.</p><p>To use an existing profile, its actual signature, team, entitlements, certificate and current private-key custody must still be inspected together. Metadata and API-key format do not perform those checks. Do not create or revoke certificates just because this comparison is inconclusive.</p><button onClick={onCredentials}>Open local credentials</button></details>
      <button disabled={state.platform !== 'ios' || !!reason || state.pending} onClick={() => void controller.prepare(APPLE_PROFILE_QUERY)}>Review another metadata check</button>
      <button disabled={state.platform !== 'ios' || !!reason || state.pending} onClick={() => void controller.prepare(APPLE_BUNDLE_QUERY)}>Review Bundle ID check instead</button>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>Review saved-app access instead</button>
      {state.platform !== 'ios' && <p className="save-note">Select iOS to review another profile metadata or Bundle ID check. The original check and its controls remain available below.</p>}
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil !== null && <div className="notice">
      <p>Contact App Store Connect once to read profile and related Bundle ID/certificate metadata visible to this selected key. Compare it locally to the saved Bundle ID. Apple may log or rate-limit the request. No content download or provisioning change is authorized.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this read-only profile metadata check.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>Check existing profile metadata</button>
    </div>}
    {retained && <div role="status"><p>{op.phase === 'running' ? 'Reading original profile metadata. Cancel stops the original operation; its status remains until cleanup is confirmed.' : 'The original metadata check or its cleanup is retained. Finish or cancel it before other work.'}</p><button onClick={() => void controller.cancel()}>Cancel original metadata check</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh check status</button>
    {state.error && <p role="alert">{state.error}</p>}
    <p>{historical ? 'Earlier or different saved context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>
    {result && <>
      <h3>{copy?.title ?? 'Metadata observation unavailable'}</h3><p>{copy?.detail ?? 'No reuse or absence conclusion is available.'}</p>
      <p>Complete means this read and its cleanup finished, not that signing is ready. {historical && 'These counts belong to an earlier or different saved context, not the current selection.'}</p>
      {summary?.counts && <>
        <ul><li>Profiles with the saved Bundle ID: {summary.counts.matchingProfiles}</li><li>Marked ACTIVE in provider metadata: {summary.counts.activeProfiles}</li><li>Profiles meeting this conservative metadata/date comparison: {summary.counts.currentMetadataCandidates}</li><li>Distinct certificates referenced by these profiles: {summary.counts.relatedCertificates}</li></ul>
        <p>Worker comparison time (UTC): {summary.checkedAt}. A date candidate requires an ACTIVE profile within its metadata dates and <strong>all</strong> listed certificate metadata to have supported types and later expiry. Zero candidates does not mean existing credentials are unusable or that a new certificate should be created.</p>
      </>}
      <ul>{result.findings.map((finding, index) => <li key={index}><strong>{finding.status}</strong> — {labels[finding.check] ?? 'Prerequisite check'}</li>)}</ul>
      <p>These are only point-in-time metadata comparisons. No team ownership, authenticated profile, certificate trust, private-key match, assignment or release readiness is established.</p>
    </>}
  </section>;
}
