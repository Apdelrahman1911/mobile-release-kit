import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import { APPLE_BUNDLE_QUERY, APPLE_BUNDLE_SCOPE } from '../localStorePreflightProtocol.ts';
import type { BundleIdObservation, StoreCheck } from '../localStorePreflightTypes.ts';
import { sameOfflineData } from '../offlinePreflightProtocol.ts';
import { AppleProvisioningProfiles } from './AppleProvisioningProfiles.tsx';

const observations: Record<BundleIdObservation, { title: string; detail: string }> = {
  found: { title: 'Matching Bundle ID returned', detail: 'The selected App Store Connect key returned this saved iOS Bundle ID. This does not verify its team, certificate, provisioning profile or signing readiness.' },
  'not-returned': { title: 'No matching Bundle ID returned for this key', detail: 'The complete response to this one read contained no match. This does not mean the Bundle ID is globally available or that this account may create it. Check the selected key and Apple Developer account manually.' },
  'not-permitted': { title: 'Apple did not permit this read', detail: 'Check the selected key’s permissions, matching Key ID and Issuer ID, and any account requirements in Apple Developer or App Store Connect. This is not evidence that the Bundle ID is missing.' },
  inconclusive: { title: 'Bundle ID could not be confirmed', detail: 'An incomplete, unsupported or unconfirmed response cannot establish registration or availability. Review the original check status and your Apple account before another attempt.' },
  'not-checked': { title: 'Bundle ID was not checked', detail: 'Resolve the prerequisite findings below. No registration or availability conclusion was made.' },
};
const checks: Partial<Record<StoreCheck, { label: string; help: string }>> = {
  'credential-format': { label: 'Selected App Store Connect private-key format', help: 'Keep and assign the original private P8 with its matching Key ID and Issuer ID in This Mac → iOS → Store (or Full).' },
  'query-prerequisites': { label: 'Saved iOS Bundle ID', help: 'Save a valid iOS Bundle ID and read the current saved version. This read does not require a numeric App Store app ID or TestFlight group.' },
  'runtime-unavailable': { label: 'Bundled Store runtime', help: 'Repair or update the installed app; do not use an ambient Ruby or Fastlane as a workaround.' },
  'bundle-unavailable': { label: 'Bundled Store dependencies', help: 'Repair or update the app’s bundled dependencies; do not install global gems as a workaround.' },
};

/** A view of the existing LocalStorePreflight owner, not another controller. */
export function AppleProvisioning({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreState; controller: LocalStorePreflightController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op = state.status?.operation;
  const reason = controller.prepareReason();
  const retained = localStoreOwnerReason(state);
  if (op?.context.query !== APPLE_BUNDLE_QUERY) {
    if (compact || state.platform !== 'ios') return null;
    return <details><summary>Check Bundle ID registration instead</summary>
      <p>Read the saved iOS Bundle ID using your selected App Store Connect key. This separate check does not require an App Store app record or TestFlight group. Save your configuration and read its saved version first.</p>
      <p>No certificate or profile is created, downloaded, replaced or revoked. A missing match does not mean the Bundle ID is available to register.</p>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare(APPLE_BUNDLE_QUERY)}>Review Bundle ID check</button>
      {reason && <p className="save-note">{reason}</p>}
    </details>;
  }
  if (compact && !retained) return null;
  const historical = state.historical || !state.request || !sameOfflineData(op.context, {
    ...state.request, platform: state.request.platform ?? 'android', query: APPLE_BUNDLE_QUERY, operation: 'local-store-preflight',
  });
  const result = op.result?.scope === APPLE_BUNDLE_SCOPE ? op.result : null;
  const observation = result?.observation ? observations[result.observation] : null;
  return <section className="card" aria-label="Saved Bundle ID registration check">
    <div className="inline-heading"><h2>Bundle ID registration · This Mac</h2>{compact && <button onClick={onShow}>Show check</button>}</div>
    {!compact && <>
      <p>Read the saved iOS Bundle ID using the assigned App Store Connect key. This is a separate registration lookup, not an app-access or release-readiness check.</p>
      <p><strong>Read only:</strong> no Bundle ID, certificate or profile is created or changed; no build, signing, upload or release. No team ownership or global Bundle ID availability is established.</p>
      <details><summary>Key and account requirements</summary><p>Use your original App Store Connect team API private P8 with its matching Key ID and Issuer ID. Apple may restrict certificate, identifier and profile APIs by key type, role or account agreements. An unauthorized or incomplete response is not evidence of absence. Individual keys and unsupported account configurations may require manual use of Apple Developer.</p><button onClick={onCredentials}>Open local credentials</button></details>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare(APPLE_BUNDLE_QUERY)}>Review another Bundle ID check</button>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>Review saved-app access instead</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {!compact && <AppleProvisioningProfiles state={state} controller={controller} onCredentials={onCredentials} onShow={onShow}/>}
    {state.consentUntil !== null && <div className="notice">
      <p>Contact App Store Connect once to read the saved Bundle ID visible to the selected key. Apple may log or rate-limit this request. This does not create, replace or revoke any signing resource, and an empty result does not authorize creating one.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this read-only Bundle ID check.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>Check saved Bundle ID</button>
    </div>}
    {retained && <div role="status"><p>{op.phase === 'running' ? 'Checking the original saved Bundle ID. Cancel stops the original operation; its status remains until cleanup is confirmed.' : 'The original Bundle ID check or its cleanup is retained. Finish or cancel it before other work.'}</p><button onClick={() => void controller.cancel()}>Cancel original Bundle ID check</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh check status</button>
    {state.error && <p role="alert">{state.error}</p>}
    <p>{historical ? 'Earlier or different saved context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>
    {result && <>
      <h3>{observation?.title ?? 'Bundle ID observation unavailable'}</h3>
      <p>{observation?.detail ?? 'No registration conclusion can be drawn from this result.'}</p>
      <p>Complete means this query and its cleanup finished, not that signing is ready. {historical && 'This result belongs to an earlier or different saved context, not the current selection.'}</p>
      <ul>{result.findings.map((finding, index) => <li key={index}><strong>{finding.status}</strong> — {checks[finding.check]?.label ?? 'Prerequisite check'}{['FAIL', 'BLOCKED', 'MISSING', 'INVALID'].includes(finding.status) && <p>{checks[finding.check]?.help}</p>}</li>)}</ul>
      <p>This point-in-time observation cannot authorize provisioning, assignment or a release. Confirm team, current key custody and an authenticated matching profile separately.</p>
    </>}
  </section>;
}
