import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import { PAIRED_VERSIONS_QUERY, parsePairedCurrentVersions, pairedVersionsObserved } from '../pairedStoreVersions.ts';
import { androidVersionDescriptions } from '../androidStoreVersions.ts';

// Shares the original Store controller; no mount probe or independent loan.
export function PairedStoreVersions({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreState; controller: LocalStorePreflightController; compact?: boolean; onCredentials: () => void; onShow: () => void;
}) {
  const retained = localStoreOwnerReason(state), reason = controller.prepareReason();
  const op = state.status?.operation?.context.query === PAIRED_VERSIONS_QUERY ? state.status.operation : null;
  const result = op?.result, pair = parsePairedCurrentVersions(result?.currentVersions);
  const historical = state.historical || state.platform !== 'both';
  if (compact && (!op || !retained)) return null;
  return <section className="card" aria-label="Shared Android and iOS current versions">
    <div className="inline-heading"><h2>Shared Android + iOS versions · This Mac</h2>{compact && <button onClick={onShow}>Show original check</button>}</div>
    {!compact && <>
      <p>For one saved version source used by both apps, check their current visible versions together. Apple is read first; Google is contacted only if that inventory is complete and supported.</p>
      <p>In Credentials choose <strong>Use shared-version credentials</strong>, then assess and assign both the Google service-account JSON and the App Store Connect P8 with its Key ID and Issuer ID. Both assignments must remain in that same context.</p>
      <button onClick={onCredentials}>Open local credentials</button>
      <p><strong>Google uses a temporary, uncommitted edit.</strong> Creating it may invalidate another editor’s in-progress Play edit. Coordinate with other editors first. No app is uploaded, signed or published.</p>
      <button disabled={state.platform !== 'both' || !!reason || state.pending} onClick={() => void controller.prepare(PAIRED_VERSIONS_QUERY)}>Review shared version check</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {op && state.consentUntil !== null && <div className="notice">
      <p>Authorize the bounded Apple reads, then one Google token request and at most five Play requests: create the edit, read APKs, bundles and all returned tracks, and delete that exact edit. Failed or cancelled cleanup may leave an edit until Google expires it.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize both checks and the temporary Play edit, and have coordinated with other editors.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>Check both Stores</button>
    </div>}
    {op && retained && <div role="status"><p>{retained}</p><button onClick={() => void controller.cancel()}>Cancel original check</button></div>}
    {op && <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh original status</button>}
    {state.error && <p role="alert">{state.error}</p>}
    {result && <>
      <h3>{pairedVersionsObserved(pair) ? 'Both current inventories checked' : 'Shared inventory unavailable'}</h3>
      {historical && <p>This earlier result cannot supply a reservation for the current context.</p>}
      {pair && <ul>
        <li>Google Play: {pair.android.observation === 'observed' ? `highest visible code ${pair.android.maxBuild}` : androidVersionDescriptions[pair.android.observation].title}</li>
        <li>App Store Connect: {pair.ios.observation === 'observed' ? `highest visible build ${pair.ios.maxBuild}; marketing version ${pair.ios.marketingVersion ?? 'none returned'}` : pair.ios.observation.replaceAll('-', ' ')}</li>
      </ul>}
      {result.findings.length > 0 && <ul>{result.findings.map((finding, i) => <li key={i}><strong>{finding.status}</strong> — {finding.check.replaceAll('-', ' ')}</li>)}</ul>}
    </>}
    {!compact && <p>Current listings are not complete history or an atomic snapshot. Zero means no current number was returned, not never used. External uploaders can still conflict. Shared automatic builds use the supported intersection, 1–9,999. A reservation and its separate saved-file review/Apply remain required; either failed or stale inventory stops the pair with no single-platform fallback. Manual versioning stays the default.</p>}
  </section>;
}
