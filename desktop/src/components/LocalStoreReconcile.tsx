import { localStoreReconcileOwnerReason, type LocalStoreReconcileController, type LocalStoreReconcileState } from '../localStoreReconcile.ts';

export function LocalStoreReconcile({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreReconcileState; controller: LocalStoreReconcileController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op=state.status?.operation, retained=localStoreReconcileOwnerReason(state), reason=controller.prepareReason();
  const receipt=op?.result?.readinessReceipt??op?.result?.reconciliationReceipt;
  const originalReadiness=op?.context.action==='external-readiness';
  const readiness=retained&&op?originalReadiness:state.externalReadiness;
  const ios=(retained&&op?op.context.platform:state.platform)==='ios';
  const originalSettlement=op?.context.settlement==='record-current-target';
  if(compact&&!retained)return null;
  return <section className="card" aria-label={readiness?"Refresh external TestFlight availability":ios?"Check the previous TestFlight internal upload":"Check the previous Play internal release"}>
    <div className="inline-heading"><h2>{readiness?'Refresh external TestFlight availability':`Check previous ${ios?'TestFlight':'Play'} upload`} · This Mac</h2>{compact&&<button onClick={onShow}>Show original check</button>}</div>
    {!compact&&<>
      {ios&&<fieldset disabled={!!retained}><legend>What would you like to check?</legend>
        <label><input type="radio" name="testflight-check-action" checked={!state.externalReadiness} onChange={()=>controller.setExternalReadiness(false)}/> Previous internal upload</label>
        <label><input type="radio" name="testflight-check-action" checked={state.externalReadiness} onChange={()=>controller.setExternalReadiness(true)}/> External testing after Beta Review</label>
      </fieldset>}
      {readiness?<p>After Apple completes Beta App Review, read the original external TestFlight target again. A match records a separate local availability observation; the original upload and external execution receipt remain unchanged. This never notifies testers, uploads, submits or retries a release.</p>:<p>If an upload was interrupted, check whether {ios?'App Store Connect currently has the exact processed internal-testing build':'Play currently has the exact prepared internal-testing release'}. This does not upload, rebuild, re-sign, promote, submit for review or repair the earlier operation.</p>}
      <details><summary>Help: when should I use this check?</summary>
        {readiness?<><p>Choose Verify history → iOS → Review stage-execution receipt on the latest successful external-testing operation. A pending, failed or uncertain operation cannot use this action. Keep the original project and version unchanged.</p>
          <p>In Credentials choose This Mac → iOS → External testing → Store (or Full). Assign the same App Store Connect key, review contact and operation commitment, plus demo account if configured. The P8 key comes from App Store Connect → Users and Access → Integrations; select it using the file picker. The original contact and commitment are needed to check the complete intended target, not just Apple’s approval label.</p></>:<><p>First choose Verify history, then Review for Store check on the latest execution. This checks the retained files, including after an app restart. Keep the saved project, version and candidate unchanged.</p>
        {ios?<p>In Credentials choose This Mac → iOS → Candidate → Store (or Full). Select the same App Store Connect P8 key and enter its Key ID and Issuer ID. Find API keys in App Store Connect → Users and Access → Integrations. The key must have access to this app. Use Select File there; no copying to internal folders or Xcode selection is needed for this check.</p>:<p>In Credentials choose This Mac → Android → Candidate → Store (or Full) and assign the same Google service-account JSON used for preparation. Get that key in Google Cloud Console → IAM &amp; Admin → Service Accounts → Keys; grant it access to this app in Play Console. No Android tool selection is needed for this readback.</p>}</>}
        <p>A matching result confirms only the current target. A missing or different target is not permission to upload again. Keep all earlier receipts, attempt files and history. If the app still owns an uncertain operation, finish or cancel that original first; this check cannot override its cleanup.</p>
      </details>
      {!ios&&<fieldset disabled={!!retained}><legend>What should this check do?</legend>
        <label><input type="radio" name="play-recovery-action" checked={!state.settlement} onChange={()=>controller.setSettlement(false)}/> Check the target only</label>
        <label><input type="radio" name="play-recovery-action" checked={state.settlement} onChange={()=>controller.setSettlement(true)}/> Check and record a recovery checkpoint</label>
      </fieldset>}
      {!ios&&state.settlement&&<p>A matching target can be recorded as one new checkpoint in this project’s local release history and Mac Keychain. Earlier evidence stays unchanged. This is for an interrupted or failed execution, not an already successful one; a missing, partial or different target cannot be cleared this way.</p>}
      {state.request&&<p><strong>{state.applicationId}</strong> · Version {state.request.savedVersion.name} · Build {state.request.savedVersion.build} · {readiness?'External testing':'Internal testing'}</p>}
      {!state.request&&<button onClick={onCredentials}>Configure local credentials</button>}
      <button disabled={!!reason||state.pending} onClick={()=>void controller.prepare()}>{readiness?'Review external availability check':state.settlement&&!ios?'Review recovery checkpoint':ios?'Review current TestFlight check':'Review current Play check'}</button>
      {reason&&<p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil!==null&&<div className="notice">
      {originalReadiness?<p><strong>Read current external TestFlight availability and save one local observation.</strong> The app checks the same build, groups, metadata, review contact and commitments twice. Only a complete match available to testers can be recorded. No Store writes, upload, notification, retry or public release is authorized. A separate receipt and journal/Keychain checkpoint preserve the old evidence.</p>:op?.context.platform==='ios'?<p><strong>Contact App Store Connect to read the current internal build.</strong> This checks the prepared app and version, processed build and current internal-testing state. It does not upload, notify testers, distribute externally, submit for review, retry an earlier request or write a recovery checkpoint.</p>:<p><strong>Contact Google Play to read the current internal target.</strong> This creates a temporary uncommitted edit, reads its state and attempts to delete the edit. Cancellation or network failure may leave the edit to expire. It does not upload or commit a release.</p>}
      {originalSettlement&&<p><strong>Also write one new local recovery checkpoint.</strong> Preserve all earlier files and record this fresh target observation in the project journal and Mac Keychain. This does not establish the old process or HTTP request’s finality, retry that upload, or authorize promotion. Interrupted checkpoint writes remain unresolved; they are not silently rolled back.</p>}
      <p>{state.applicationId} · Version {op?.context.savedVersion.name} · Build {op?.context.savedVersion.build}.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event=>controller.acknowledge(event.target.checked)}/> {originalReadiness?'I authorize a read-only external availability check and one separate local readiness record.':originalSettlement?'I authorize this current-state check and one new local recovery checkpoint, not an upload or retry.':'I authorize this current-state check only, not an upload or retry.'}</label>
      <button disabled={!state.acknowledged||state.pending} onClick={()=>void controller.start()}>{originalReadiness?'Check external availability':originalSettlement?'Check and record recovery':op?.context.platform==='ios'?'Check current TestFlight build':'Check current Play target'}</button>
    </div>}
    {retained&&<div role="status"><p>{op?.phase==='running'?'Checking the original prepared target. Keep the app open until cleanup is confirmed.':retained}</p><button onClick={()=>void controller.cancel()}>Cancel original check</button></div>}
    <button disabled={state.mode!=='native'} onClick={()=>void controller.checkStatus()}>Refresh check status</button>
    {state.error&&<p role="alert">{state.error}</p>}
    {op&&<p>{state.historical?'Earlier context · ':''}{op.phase}{op.reason!=='none'?` · ${op.reason.replaceAll('-',' ')}`:''}</p>}
    {op&&(op.phase==='unknown'||op.phase==='terminal'&&op.outcome!=='complete')&&<p className="save-note">No matching current target is confirmed by this check. The upload might still be processing, incomplete, changed or unobservable; this result does not identify which or prove the upload failed. Preserve the earlier operation, project files and Keychain state; do not repeat the upload to clear this result.</p>}
    {receipt&&state.historical&&<p>This check belongs to an earlier project context, not your current selection.</p>}
    {receipt&&!state.historical&&<div className="notice">
      <h3>{originalReadiness?'External TestFlight target available to testers':originalSettlement?'Recovery checkpoint recorded':('bundleId' in receipt)?'Current processed internal build matches':'Current internal-testing target matches'}</h3>
      <p>{'bundleId' in receipt?receipt.bundleId:receipt.applicationId} · Version {receipt.version.name} · Build {receipt.version.build}. Observed at {receipt.observedAt}.</p>
      <p>This check’s receipt: <code>{receipt.receiptSha256}</code>. The earlier journal and evidence were preserved.</p>
      {originalReadiness&&<p>Next, Verify history → Review external readiness to inspect this separate record. Then select Production credentials to review a new App Store submission using the original uploaded build. This record is a point-in-time observation, not public availability or permission to resend the earlier release.</p>}
      {originalSettlement&&<p>Next, use Verify history to see the new checkpoint before preparing a distinct later candidate. This does not restart or resend the earlier release.</p>}
      <p>This does not establish the earlier execution’s cleanup, authorize a retry or promotion, or prove a public release. Store state can change after this observation.</p>
    </div>}
  </section>;
}
