import { localStoreReconcileOwnerReason, type LocalStoreReconcileController, type LocalStoreReconcileState } from '../localStoreReconcile.ts';

export function LocalStoreReconcile({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreReconcileState; controller: LocalStoreReconcileController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op=state.status?.operation, retained=localStoreReconcileOwnerReason(state), reason=controller.prepareReason();
  const receipt=op?.result?.reconciliationReceipt;
  if(compact&&!retained)return null;
  return <section className="card" aria-label="Check the previous Play internal release">
    <div className="inline-heading"><h2>Check previous Play upload · This Mac</h2>{compact&&<button onClick={onShow}>Show original check</button>}</div>
    {!compact&&<>
      <p>If an upload was interrupted, check whether Play currently has the exact prepared internal-testing release. This does not upload, rebuild, re-sign, promote, commit an edit or repair the earlier operation.</p>
      <details><summary>Help: when should I use this check?</summary>
        <p>First choose Verify history, then Review for Store check on the latest execution. This checks the retained files, including after an app restart. Keep the saved project, version and candidate unchanged.</p>
        <p>In Credentials choose This Mac → Android → Candidate → Store (or Full) and assign the same Google service-account JSON used for preparation. Get that key in Google Cloud Console → IAM &amp; Admin → Service Accounts → Keys; grant it access to this app in Play Console. No Android tool selection is needed for this readback.</p>
        <p>A matching result confirms only the current target. A missing or different target is not permission to upload again. Keep all earlier receipts, attempt files and history. If the app still owns an uncertain operation, finish or cancel that original first; this check cannot override its cleanup.</p>
      </details>
      {state.request&&<p><strong>{state.applicationId}</strong> · Version {state.request.savedVersion.name} · Build {state.request.savedVersion.build} · Internal testing</p>}
      {!state.request&&<button onClick={onCredentials}>Configure local credentials</button>}
      <button disabled={!!reason||state.pending} onClick={()=>void controller.prepare()}>Review current Play check</button>
      {reason&&<p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil!==null&&<div className="notice">
      <p><strong>Contact Google Play to read the current internal target.</strong> This creates a temporary uncommitted edit, reads its state and attempts to delete the edit. Cancellation or network failure may leave the edit to expire. It does not upload or commit a release.</p>
      <p>{state.applicationId} · Version {op?.context.savedVersion.name} · Build {op?.context.savedVersion.build}.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event=>controller.acknowledge(event.target.checked)}/> I authorize this current-state check only, not an upload or retry.</label>
      <button disabled={!state.acknowledged||state.pending} onClick={()=>void controller.start()}>Check current Play target</button>
    </div>}
    {retained&&<div role="status"><p>{op?.phase==='running'?'Checking the original prepared target. Keep the app open until cleanup is confirmed.':retained}</p><button onClick={()=>void controller.cancel()}>Cancel original check</button></div>}
    <button disabled={state.mode!=='native'} onClick={()=>void controller.checkStatus()}>Refresh check status</button>
    {state.error&&<p role="alert">{state.error}</p>}
    {op&&<p>{state.historical?'Earlier context · ':''}{op.phase}{op.reason!=='none'?` · ${op.reason.replaceAll('-',' ')}`:''}</p>}
    {op&&(op.phase==='unknown'||op.phase==='terminal'&&op.outcome!=='complete')&&<p className="save-note">No matching current target is confirmed by this check. That is not proof the upload failed. Preserve the earlier operation, project files and Keychain state; do not repeat the upload to clear this result.</p>}
    {receipt&&state.historical&&<p>This check belongs to an earlier project context, not your current selection.</p>}
    {receipt&&!state.historical&&<div className="notice">
      <h3>Current internal-testing target matches</h3>
      <p>{receipt.applicationId} · Version {receipt.version.name} · Build {receipt.version.build}. Observed at {receipt.observedAt}.</p>
      <p>This check’s receipt: <code>{receipt.receiptSha256}</code>. The earlier journal and evidence were preserved.</p>
      <p>This does not establish the earlier execution’s cleanup, authorize a retry or promotion, or prove a public release. Play can change after this observation.</p>
    </div>}
  </section>;
}
