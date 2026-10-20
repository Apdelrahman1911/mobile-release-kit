import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import { sameOfflineData } from '../offlinePreflightProtocol.ts';
import { ANDROID_VERSIONS_QUERY, ANDROID_VERSIONS_SCOPE, ANDROID_VERSIONS_COVERAGE, androidVersionDescriptions } from '../androidStoreVersions.ts';

/** Same original Store controller. No automatic query, edit, allocation or retry. */
export function AndroidStoreVersions({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreState; controller: LocalStorePreflightController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op = state.status?.operation, reason = controller.prepareReason(), retained = localStoreOwnerReason(state);
  if (op?.context.query !== ANDROID_VERSIONS_QUERY) {
    if (compact || state.platform !== 'android') return null;
    return <details><summary>Check the version codes currently listed in Google Play</summary>
      <p>This uses a temporary Play edit to read APKs, bundles and every returned track. It does not upload or publish, but can invalidate another in-progress Play edit.</p>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare(ANDROID_VERSIONS_QUERY)}>Review Play version check</button>
      {reason && <p className="save-note">{reason}</p>}
    </details>;
  }
  if (compact && !retained) return null;
  const historical = state.historical || !state.request || !sameOfflineData(op.context, {
    ...state.request, platform: 'android', query: ANDROID_VERSIONS_QUERY, operation: 'local-store-preflight',
  });
  const result = op.result?.scope === ANDROID_VERSIONS_SCOPE ? op.result : null;
  const summary = result?.currentVersions && 'coverage' in result.currentVersions && result.currentVersions.coverage === ANDROID_VERSIONS_COVERAGE ? result.currentVersions : null;
  const copy = summary ? androidVersionDescriptions[summary.observation] : null;
  return <section className="card" aria-label="Current Google Play versions">
    <div className="inline-heading"><h2>Current Play versions · This Mac</h2>{compact && <button onClick={onShow}>Show check</button>}</div>
    {!compact && <>
      <p>Read current version codes for your saved Android app using the Google service account assigned in Credentials.</p>
      <p><strong>No publishing, but not read-only:</strong> this creates one temporary Play edit, reads tracks, bundles and APKs, then attempts to delete that edit. No upload, track update, edit commit, signing or version-file change is made.</p>
      <p><strong>Coordinate with other editors first.</strong> Opening an edit can invalidate another in-progress edit for this app/account, including work outside Mobile Release Kit.</p>
      <details><summary>Limits of this check</summary>
        <p>All returned release statuses count. Duplicate codes on different tracks are normal. Up to 400 records per collection, 400 releases and 4,000 code references are supported; unknown pagination or partial results stop the check.</p>
        <p>These lists are not atomic or a complete historical record. The shared counter coordinates only clients using that counter. Other uploaders can still cause a conflict; a retry never silently chooses a new number.</p>
        <p>Android-only and iOS-only reservations are separate supported cases. For a shared Android+iOS source, choose Use shared-version credentials and run the single paired Store check instead. Two earlier independent results cannot be combined. Manual versioning stays the default.</p>
        <button onClick={onCredentials}>Open local credentials</button>
      </details>
      <button disabled={state.platform !== 'android' || !!reason || state.pending} onClick={() => void controller.prepare(ANDROID_VERSIONS_QUERY)}>Review another Play version check</button>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>Review app access instead</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil !== null && <div className="notice">
      <p>Authorize one token request and at most five Play API requests: create an uncommitted edit, read all three current inventories, then delete that exact edit. This may invalidate someone else’s in-progress edit. Failure or cancellation can leave the temporary edit until Google expires it.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this temporary Play edit and have coordinated with other editors.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>Check current Play versions</button>
    </div>}
    {retained && <div role="status"><p>{op.phase === 'running' ? 'Checking current Play versions. Cancel requests Stop on the original operation; remote edit deletion and local cleanup may remain unconfirmed.' : retained}</p><button onClick={() => void controller.cancel()}>Cancel original check</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh check status</button>
    {state.error && <p role="alert">{state.error}</p>}
    <p>{historical ? 'Earlier or different saved context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>
    {result && <>
      <h3>{copy?.title ?? 'Play versions unavailable'}</h3><p>{copy?.detail}</p>
      {historical && <p>This earlier result cannot supply a reservation for the current selection.</p>}
      {summary?.counts && <ul>
        <li>Tracks: {summary.counts.tracks} · Releases: {summary.counts.releases} · Code references: {summary.counts.versionCodes}</li>
        <li>Bundles: {summary.counts.bundles} · APKs: {summary.counts.apks}</li>
        <li>Highest visible version code: {summary.maxBuild === 0 ? 'No current code returned — not proof that none was ever used' : summary.maxBuild}</li>
      </ul>}
      {result.findings.length > 0 && <ul>{result.findings.map((finding, index) => <li key={index}><strong>{finding.status}</strong> — {finding.check.replaceAll('-', ' ')}</li>)}</ul>}
      <p>A completed current inventory is not a reservation, Store acceptance, proof of historical uniqueness or release readiness.</p>
    </>}
  </section>;
}
