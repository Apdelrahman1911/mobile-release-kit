import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import type { StoreCheck } from '../localStorePreflightTypes.ts';
import { APPLE_BUNDLE_QUERY, APPLE_PROFILE_QUERY } from '../localStorePreflightProtocol.ts';
import { AppleProvisioning } from './AppleProvisioning.tsx';
import { AppleProvisioningProfiles } from './AppleProvisioningProfiles.tsx';
const hints:Record<StoreCheck,string>={
 'credential-format':'In Credentials, reselect the service-account JSON, keep it and assign it to this exact This Mac context.',
 'query-prerequisites':'Check the saved Android application ID, version/build number and track configuration, then refresh the saved version.',
 'runtime-unavailable':'Repair or update the installed app. It does not use an ambient Ruby or Fastlane.',
 'bundle-unavailable':'Repair or update the app’s bundled Store dependencies; do not install global gems as a workaround.',
 'store-access':'Check this account’s Play Console app permissions, that the saved build number is unused, and network availability. This finding does not identify which of these failed.',
};
const appleHints:Record<StoreCheck,string>={...hints,
 'credential-format':'In Credentials, select the original App Store Connect private P8, enter its matching Key ID and Issuer ID, then keep and assign it to This Mac → iOS → Store (or Full). A public key or a certificate is not a substitute.',
 'query-prerequisites':'Check the saved iOS bundle ID, numeric App Store app ID, existing external TestFlight group and version/build number, then refresh the saved version.',
 'store-access':'Check the key’s App Store Connect permissions, the saved app and external TestFlight group, that this build number is unused, and network availability. This finding does not identify which of these failed.',
};
const labels:Record<StoreCheck,string>={
 'credential-format':'Service-account file format','query-prerequisites':'Saved app and query configuration',
 'runtime-unavailable':'Bundled Store runtime','bundle-unavailable':'Bundled Store dependencies','store-access':'Google Play account access',
};
export function LocalStorePreflight({state,controller,compact=false,onCredentials,onShow}:{state:LocalStoreState;controller:LocalStorePreflightController;compact?:boolean;onCredentials:()=>void;onShow:()=>void}){
 const op=state.status?.operation,retained=localStoreOwnerReason(state),reason=controller.prepareReason();
 const apple=state.platform==='ios',store=apple?'App Store Connect':'Google Play';
 const originalApple=op?.context.platform==='ios',resultHints=originalApple?appleHints:hints;
 const resultLabels=originalApple?{...labels,'credential-format':'App Store Connect private-key format','store-access':'App Store Connect account access'}:labels;
 if(op?.context.query===APPLE_BUNDLE_QUERY)return <AppleProvisioning state={state} controller={controller} compact={compact} onCredentials={onCredentials} onShow={onShow}/>;
 if(op?.context.query===APPLE_PROFILE_QUERY)return <AppleProvisioningProfiles state={state} controller={controller} compact={compact} onCredentials={onCredentials} onShow={onShow}/>;
 if(compact&&!retained)return null;
 return <section className="card" aria-label={`Local ${store} access check`}>
  <div className="inline-heading"><h2>{store} access · This Mac</h2>{compact&&<button onClick={onShow}>Show check</button>}</div>
  {!compact&&<>
   <p>Check that this Mac can access your saved {apple?'iOS app in App Store Connect':'Android app in Google Play'}. Uses your assigned {apple?'App Store Connect key':'service-account file'} and bundled release tools; no GitHub connection is needed.</p>
   {apple?<details><summary>Help: where do I get the Apple key and IDs?</summary>
    <p>In App Store Connect → Users and Access → Integrations → App Store Connect API, an Account Holder or Admin can create a team API key with permission to read this app. Download its private .p8 file and copy the Key ID and Issuer ID shown there. Apple allows the private-key download only once; keep your original safe.</p>
    <p>In Credentials choose This Mac → iOS → Store (or Full), use Select File for the P8, enter the matching Key ID (10 uppercase letters/digits) and Issuer ID (UUID), then keep and assign the key. All three are required. This is not your Developer ID certificate, notarization configuration or provisioning profile.</p>
    <p>Find the numeric app ID in App Store Connect → My Apps → your app → App Information. The bundle ID must match the same app. Configure the name of an existing external TestFlight group from the app’s TestFlight page. This check does not create a missing app or group. Incorrect IDs, permissions or a previously used build number produce findings, not an upload.</p>
   </details>:<details><summary>Help: where do I get the service-account file?</summary><p>In Google Cloud Console, select your project → IAM &amp; Admin → Service Accounts → the release account → Keys → Add key → JSON. In Play Console, give that account access to the app. In Credentials, choose This Mac, Android and Store, select the JSON file, then keep and assign it. This private file stays in the native credential session or encrypted vault; it is never uploaded to GitHub.</p><p>A format-valid file does not prove the account has Play permissions. This check contacts Google to test the required Play edit-based API access. Incorrect permissions produce a finding, not an automatic upload or release.</p></details>}
   <p><strong>No publishing:</strong> no upload, signing, project command, build or production release. {apple?'Apple requests only read app identity, the configured external TestFlight group and build inventory; no group change, submission or release is made.':'The Google check uses a temporary uncommitted edit; it is not a zero-write server operation.'} A successful check is point-in-time access only, not release readiness.</p>
   {!state.request&&<button onClick={onCredentials}>Configure local credentials</button>}
   <button disabled={!!reason||state.pending} onClick={()=>void controller.prepare()}>Review access check</button>{reason&&<p className="save-note">{reason}</p>}
   {apple&&<AppleProvisioning state={state} controller={controller} onCredentials={onCredentials} onShow={onShow}/>}
   {apple&&<AppleProvisioningProfiles state={state} controller={controller} onCredentials={onCredentials} onShow={onShow}/>}
  </>}
  {state.consentUntil!==null&&<div className="notice"><p>{originalApple?'Contact App Store Connect to read the saved app identity, existing external TestFlight group and build inventory. Apple may log or rate-limit requests. This does not upload, change testing groups, submit for review or publish a release.':'This creates a temporary, uncommitted Google Play edit, reads app inventory and attempts to delete the edit. It never commits the edit or publishes a release. A cancellation or network failure can leave an uncommitted edit until Google expires it.'}</p><label><input type="checkbox" checked={state.acknowledged} onChange={e=>controller.acknowledge(e.target.checked)}/> I authorize this nonpublishing {originalApple?'App Store Connect':'Google Play'} access check.</label><button disabled={!state.acknowledged||state.pending} onClick={()=>void controller.start()}>Check {originalApple?'App Store Connect':'Google Play'} access</button></div>}
  {retained&&<div role="status"><p>{op?.phase==='running'?'Checking access. Up to 20 minutes; Cancel stops the original operation.':retained}</p><button onClick={()=>void controller.cancel()}>Cancel original check</button></div>}
  <button disabled={state.mode!=='native'} onClick={()=>void controller.checkStatus()}>Refresh check status</button>
  {state.error&&<p role="alert">{state.error}</p>}
  {op&&<p>{state.historical?'Earlier context · ':''}{op.phase}{op.reason!=='none'?` · ${op.reason.replaceAll('-',' ')}`:''}</p>}
  {op?.result&&<><h3>{originalApple?'App Store Connect':'Google Play'} access-check findings</h3><p>Complete means the query and cleanup finished, not that every finding passed.</p><ul>{op.result.findings.map((f,i)=><li key={i}><strong>{f.status}</strong> — {resultLabels[f.check]}{['FAIL','BLOCKED','MISSING','INVALID'].includes(f.status)&&<p>{resultHints[f.check]}</p>}</li>)}</ul><p>Changes after this check may invalidate access. This result cannot authorize a release.</p></>}
 </section>;
}
