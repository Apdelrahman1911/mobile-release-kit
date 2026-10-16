import type { LocalStorePreflightController, LocalStoreState } from '../localStorePreflight.ts';
import { localStoreOwnerReason } from '../localStorePreflight.ts';
import type { StoreCheck } from '../localStorePreflightTypes.ts';
const hints:Record<StoreCheck,string>={
 'credential-format':'In Credentials, reselect the service-account JSON, keep it and assign it to this exact This Mac context.',
 'query-prerequisites':'Check the saved Android application ID, version/build number and track configuration, then refresh the saved version.',
 'runtime-unavailable':'Repair or update the installed app. It does not use an ambient Ruby or Fastlane.',
 'bundle-unavailable':'Repair or update the app’s bundled Store dependencies; do not install global gems as a workaround.',
 'store-access':'Check this account’s Play Console app permissions, that the saved build number is unused, and network availability. This finding does not identify which of these failed.',
};
const labels:Record<StoreCheck,string>={
 'credential-format':'Service-account file format','query-prerequisites':'Saved app and query configuration',
 'runtime-unavailable':'Bundled Store runtime','bundle-unavailable':'Bundled Store dependencies','store-access':'Google Play account access',
};
export function LocalStorePreflight({state,controller,compact=false,onCredentials,onShow}:{state:LocalStoreState;controller:LocalStorePreflightController;compact?:boolean;onCredentials:()=>void;onShow:()=>void}){
 const op=state.status?.operation,retained=localStoreOwnerReason(state),reason=controller.prepareReason();
 if(compact&&!retained)return null;
 return <section className="card" aria-label="Local Google Play access check">
  <div className="inline-heading"><h2>Google Play access · This Mac</h2>{compact&&<button onClick={onShow}>Show check</button>}</div>
  {!compact&&<><p>Check that this Mac can access your saved Android app in Google Play. Uses your assigned service-account file and bundled release tools; no GitHub connection is needed.</p>
   <details><summary>Help: where do I get the service-account file?</summary><p>In Google Cloud Console, select your project → IAM &amp; Admin → Service Accounts → the release account → Keys → Add key → JSON. In Play Console, give that account access to the app. In Credentials, choose This Mac, Android and Store, select the JSON file, then keep and assign it. This private file stays in the native credential session or encrypted vault; it is never uploaded to GitHub.</p><p>A format-valid file does not prove the account has Play permissions. This check contacts Google to test the required Play edit-based API access. Incorrect permissions produce a finding, not an automatic upload or release.</p></details>
   <p><strong>No publishing:</strong> no upload, committed track change, signing, project command, build or production release. The check uses a temporary uncommitted edit; it is not a zero-write server operation. A successful check is point-in-time access only, not release readiness.</p>
   {!state.request&&<button onClick={onCredentials}>Configure local credentials</button>}
   <button disabled={!!reason||state.pending} onClick={()=>void controller.prepare()}>Review access check</button>{reason&&<p className="save-note">{reason}</p>}
  </>}
  {state.consentUntil!==null&&<div className="notice"><p>This creates a temporary, uncommitted Google Play edit, reads app inventory and attempts to delete the edit. It never commits the edit or publishes a release. A cancellation or network failure can leave an uncommitted edit until Google expires it.</p><label><input type="checkbox" checked={state.acknowledged} onChange={e=>controller.acknowledge(e.target.checked)}/> I authorize this nonpublishing access check.</label><button disabled={!state.acknowledged||state.pending} onClick={()=>void controller.start()}>Check Google Play access</button></div>}
  {retained&&<div role="status"><p>{op?.phase==='running'?'Checking access. Up to 20 minutes; Cancel stops the original operation.':retained}</p><button onClick={()=>void controller.cancel()}>Cancel original check</button></div>}
  <button disabled={state.mode!=='native'} onClick={()=>void controller.checkStatus()}>Refresh check status</button>
  {state.error&&<p role="alert">{state.error}</p>}
  {op&&<p>{state.historical?'Earlier context · ':''}{op.phase}{op.reason!=='none'?` · ${op.reason.replaceAll('-',' ')}`:''}</p>}
  {op?.result&&<><h3>Access-check findings</h3><p>Complete means the query and cleanup finished, not that every finding passed.</p><ul>{op.result.findings.map((f,i)=><li key={i}><strong>{f.status}</strong> — {labels[f.check]}{['FAIL','BLOCKED','MISSING','INVALID'].includes(f.status)&&<p>{hints[f.check]}</p>}</li>)}</ul><p>Changes after this check may invalidate access. This result cannot authorize a release.</p></>}
 </section>;
}
