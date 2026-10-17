import { localStoreExecuteOwnerReason, type LocalStoreExecuteController, type LocalStoreExecuteState } from '../localStoreExecute.ts';

export function LocalStoreExecute({ state, controller, compact = false, onCredentials, onShow }: {
  state: LocalStoreExecuteState; controller: LocalStoreExecuteController; compact?: boolean;
  onCredentials: () => void; onShow: () => void;
}) {
  const op=state.status?.operation, retained=localStoreExecuteOwnerReason(state), reason=controller.prepareReason();
  const receipt=op?.result?.executionReceipt;
  if(compact&&!retained)return null;
  return <section className="card" aria-label="Execute local Google Play internal release">
    <div className="inline-heading"><h2>Upload to Play internal testing · This Mac</h2>{compact&&<button onClick={onShow}>Show original execution</button>}</div>
    {!compact&&<>
      <p>This is a separate Store action, not preparation: upload the existing signed Android App Bundle and commit its prepared internal-testing target. It does not rebuild, re-sign, promote to another track or publish publicly.</p>
      <details><summary>Help: what do I need before uploading?</summary>
        <p>In Release history, review the current prepared intent. Keep its candidate, version and project unchanged. In Android build, select the protected Android tool copy for a fresh validation of the existing bundle; no new build is required.</p>
        <p>In Credentials choose This Mac → Android → Candidate → Store (or Full), then keep and assign the same Google service-account JSON used for preparation. Get it from Google Cloud Console → IAM &amp; Admin → Service Accounts → Keys → Add key → JSON, and grant that account access to this app in Play Console. Keep the private file out of Git and GitHub.</p>
        <p>Reviewing prepared files does not prove that Play is unchanged or that the earlier native preparation finished. Native admission rechecks current files, source, credentials, journal and tools before any send. Pending history, old attempts or changed Store state refuse; a new click does not repair them.</p>
      </details>
      {state.request&&<p><strong>{state.applicationId}</strong> · Version {state.request.savedVersion.name} · Build {state.request.savedVersion.build} · Internal testing</p>}
      {state.prepared&&<p>Prepared intent <code>{state.prepared.intentSha256}</code> · Store snapshot observed at {state.prepared.observedAt} (not a current Store check).</p>}
      {!state.request&&<button onClick={onCredentials}>Configure local credentials</button>}
      <button disabled={!!reason||state.pending} onClick={()=>void controller.prepare()}>Review internal upload</button>
      {reason&&<p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil!==null&&<div className="notice">
      <p><strong>Upload and commit to Play internal testing.</strong> This sends the existing signed AAB and makes the prepared release available to internal testers. It is not a public release.</p>
      <p>{state.applicationId} · Version {op?.context.savedVersion.name} · Build {op?.context.savedVersion.build}. Candidate <code>{op?.context.candidateOperationId}</code>.</p>
      <p>Cancellation or a lost response cannot undo an upload or committed edit. Keep the app open until original cleanup is confirmed. Do not repeat an uncertain upload.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event=>controller.acknowledge(event.target.checked)}/> I authorize this existing candidate’s upload and internal-testing commit only.</label>
      <button disabled={!state.acknowledged||state.pending} onClick={()=>void controller.start()}>Upload and commit internal release</button>
    </div>}
    {retained&&<div role="status"><p>{op?.phase==='running'?'Executing the original internal upload. This can take up to 20 minutes; keep the app open until cleanup is confirmed.':retained}</p><button onClick={()=>void controller.cancel()}>Cancel original execution</button></div>}
    <button disabled={state.mode!=='native'} onClick={()=>void controller.checkStatus()}>Refresh execution status</button>
    {state.error&&<p role="alert">{state.error}</p>}
    {op&&<p>{state.historical?'Earlier context · ':''}{op.phase}{op.reason!=='none'?` · ${op.reason.replaceAll('-',' ')}`:''}</p>}
    {op&&(op.phase==='unknown'||op.phase==='terminal'&&op.outcome!=='complete')&&<p className="save-note">No successful internal release is confirmed by this result. Preserve the project, receipt/attempt files, history and Mac Keychain entries. A failure may follow an actual Store change. Do not delete records, re-enroll or upload again to clear it. Read-only history review cannot repair a pending execution; recovery is not offered here.</p>}
    {receipt&&state.historical&&<p>The retained execution result belongs to an earlier context; it is not a release of your current selection.</p>}
    {receipt&&!state.historical&&<div className="notice">
      <h3>Internal-testing target confirmed · Not a public release</h3>
      <p>{receipt.applicationId} · Version {receipt.version.name} · Build {receipt.version.build} · {receipt.result==='accepted'?'Accepted in this execution':'Confirmed by this execution’s readback'}</p>
      <p>Observed at {receipt.observedAt}. Local checkpoint {op?.result?.headSequence}. Receipt <code>{receipt.receiptSha256}</code>.</p>
      <p>This is the original execution’s completed result, not permission to send again. It does not establish the earlier preparation’s finality, an atomic saved-input snapshot, or current Store state after this observation.</p>
    </div>}
  </section>;
}
