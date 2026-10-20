import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import { sameOfflineData } from '../offlinePreflightProtocol.ts';
import { IOS_VERSIONS_QUERY, IOS_VERSIONS_SCOPE, IOS_VERSIONS_COVERAGE, iosVersionDescriptions } from '../iosStoreVersions.ts';

/** The existing Store controller and original native read; no automatic action. */
export function IOSStoreVersions({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreState; controller: LocalStorePreflightController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op = state.status?.operation, reason = controller.prepareReason(), retained = localStoreOwnerReason(state);
  if (op?.context.query !== IOS_VERSIONS_QUERY) {
    if (compact || state.platform !== 'ios') return null;
    return <details><summary>Check the versions currently listed in App Store Connect</summary>
      <p>Read the saved app’s current builds, pending uploads and App Store versions. This helps check version numbers without uploading or changing the app.</p>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare(IOS_VERSIONS_QUERY)}>Review Store version check</button>
      {reason && <p className="save-note">{reason}</p>}
    </details>;
  }
  if (compact && !retained) return null;
  const historical = state.historical || !state.request || !sameOfflineData(op.context, {
    ...state.request, platform: state.request.platform ?? 'android', query: IOS_VERSIONS_QUERY, operation: 'local-store-preflight',
  });
  const result = op.result?.scope === IOS_VERSIONS_SCOPE ? op.result : null;
  const summary = result?.currentVersions?.coverage === IOS_VERSIONS_COVERAGE ? result.currentVersions : null, copy = summary ? iosVersionDescriptions[summary.observation] : null;
  return <section className="card" aria-label="Current App Store versions">
    <div className="inline-heading"><h2>Current App Store versions · This Mac</h2>{compact && <button onClick={onShow}>Show check</button>}</div>
    {!compact && <>
      <p>Read the current iOS records for your saved App Store app with the API key assigned in Credentials. No GitHub connection is needed for this check.</p>
      <p><strong>Read only:</strong> no upload, version-file edit, signing, testing-group change or release. Checking does not reserve a number or turn on version automation.</p>
      <details><summary>What this check can and cannot tell you</summary>
        <p>The app’s builds, pending uploads and App Store versions are checked separately, with up to 400 records per collection. A pending upload counts even if Apple has not created its build record yet. There is no filter for one version, expiry or processing state.</p>
        <p>Apple’s lists can change during the check and may no longer show historical uploads. Other uploaders can use another number later. A shared GitHub counter coordinates only clients using that same counter; it cannot prevent those outside uploads.</p>
        <p>Automatic versioning requires a separate explicit policy and a fresh original check at reservation time. Uploads still need their own current Store checks. Manual versioning remains the default.</p>
        <button onClick={onCredentials}>Open local credentials</button>
      </details>
      <button disabled={state.platform !== 'ios' || !!reason || state.pending} onClick={() => void controller.prepare(IOS_VERSIONS_QUERY)}>Review another Store version check</button>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>Review app access instead</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil !== null && <div className="notice">
      <p>Contact App Store Connect to read this app’s currently visible iOS versions, builds and pending uploads. At most eight requests; Apple may log or rate-limit them. Nothing will be uploaded or changed.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this read-only Store version check.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>Check current Store versions</button>
    </div>}
    {retained && <div role="status"><p>{op.phase === 'running' ? 'Reading Store versions. Cancel stops the original check; cleanup must finish before another operation.' : retained}</p><button onClick={() => void controller.cancel()}>Cancel original check</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh check status</button>
    {state.error && <p role="alert">{state.error}</p>}
    <p>{historical ? 'Earlier or different saved context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>
    {result && <>
      <h3>{copy?.title ?? 'Store versions unavailable'}</h3><p>{copy?.detail}</p>
      {historical && <p>These results belong to the earlier saved inputs, not the current selection. They cannot supply a new reservation.</p>}
      {summary?.counts && <ul>
        <li>iOS build records: {summary.counts.builds}</li><li>iOS upload records: {summary.counts.buildUploads}</li>
        <li>iOS App Store version records: {summary.counts.appStoreVersions}</li>
        <li>Highest visible build number: {summary.maxBuild === 0 ? 'No current build or upload record returned' : summary.maxBuild}</li>
        <li>Highest visible app version: {summary.marketingVersion ?? 'No current version record returned'}</li>
      </ul>}
      {result.findings.length > 0 && <ul>{result.findings.map((finding, index) => <li key={index}><strong>{finding.status}</strong> — {finding.check.replaceAll('-', ' ')}</li>)}</ul>}
      <p>A completed check is not a reservation, proof that a number was never used, or release readiness.</p>
    </>}
  </section>;
}
