import { localStoreStageLabel } from '../localStoreStageProtocol.ts';
import { localStoreExecuteOwnerReason, type LocalStoreExecuteController, type LocalStoreExecuteState } from '../localStoreExecute.ts';

export function LocalStoreExecute({ state, controller, compact = false, onCredentials, onShow, agentReason = null }: {
  state: LocalStoreExecuteState; controller: LocalStoreExecuteController; compact?: boolean;
  onCredentials: () => void; onShow: () => void; agentReason?: string | null;
}) {
  const op=state.status?.operation, retained=localStoreExecuteOwnerReason(state), reason=agentReason??controller.prepareReason();
  const receipt=op?.result?.executionReceipt;
  const ios=(retained&&op?op.context.platform:state.platform)==='ios';
  const displayedRequest=retained&&op?op.context:state.request;
  const stage=displayedRequest&&'stage' in displayedRequest?displayedRequest.stage:null;
  const target=stage?localStoreStageLabel(stage,ios?'ios':'android'):ios?'TestFlight internal testing':'Play internal testing';
  const stageEffect=stage==='production-submit'?(ios?'Submit the existing version for App Review with manual release; approval does not publish it.':'Create a production draft from the original uploaded bundle; it is not served to production users.'):(ios?'Assign the original TestFlight build to external testing. Apple may require Beta App Review before testers can use it.':'Promote the original uploaded bundle to the configured external testing track.');
  const displayedApplication=retained&&state.historical?'Original retained candidate':state.applicationId;
  if(compact&&!retained)return null;
  return <section className="card" aria-label={`Execute local ${target} release`}>
    <div className="inline-heading"><h2>{stage?'Promote to':'Upload to'} {target} · This Mac</h2>{compact&&<button onClick={onShow}>Show original execution</button>}</div>
    {!compact&&<>
      <p>This is a separate Store action, not preparation: {stage?stageEffect:ios?'upload the existing signed IPA to its prepared TestFlight internal target.':'upload the existing signed Android App Bundle and commit its prepared internal-testing target.'} {stage?'It reuses the original uploaded binary without rebuilding, re-signing or uploading it again.':'It does not rebuild, re-sign, promote to another track or publish publicly.'}</p>
      <details><summary>Help: what do I need before {stage?'promoting':'uploading'}?</summary>
        {stage?<p>Review the current stage-prepared intent in Release history, keep the saved version and metadata unchanged, and assign the same Store credentials for this stage in Credentials → This Mac. iOS also needs review contact, operation commitment and any required demo account. No Java, Xcode, archive selection or new build is needed. A pending or failed stage cannot be resent here.</p>:<>
        <p>In Release history, review the current prepared intent. Keep its candidate, version and project unchanged. {ios?'Use full Xcode in the supported administrator-provisioned protected layout. Environment doctor observes selection/version; passing it does not prove protected tool admission. The app validates the existing IPA and uses that selected upload tool; it does not rebuild or re-sign.':'In Android build, select the protected Android tool copy for a fresh validation of the existing bundle; no new build is required.'}</p>
        {ios?<p>In Credentials choose This Mac → iOS → Candidate → Store (or Full). Select and assign the same App Store Connect API key (.p8) used for preparation. Get a team API key, key ID and issuer ID from App Store Connect → Users and Access → Integrations → App Store Connect API. The account needs access to this app. Keep the private key out of Git and GitHub.</p>:<p>In Credentials choose This Mac → Android → Candidate → Store (or Full), then keep and assign the same Google service-account JSON used for preparation. Get it from Google Cloud Console → IAM &amp; Admin → Service Accounts → Keys → Add key → JSON, and grant that account access to this app in Play Console. Keep the private file out of Git and GitHub.</p>}
        {ios&&<p>If tool checks refuse an ordinary Xcode installation, review Environment → Xcode prerequisites. If your release includes Prepare Xcode.pkg, open that companion in macOS Installer to prepare a separate protected copy. Keep setup errors and existing files if preparation fails. Do not recursively change Applications permissions or run the app as root.</p>}
        </>}<p>Reviewing prepared files does not prove that the Store is unchanged or that the earlier native preparation finished. Native admission rechecks current files, source, credentials, journal and tools before any send. Pending history, old attempts or changed Store state refuse; a new click does not repair them.</p>
      </details>
      {displayedRequest&&<p><strong>{displayedApplication}</strong> · Version {displayedRequest.savedVersion.name} · Build {displayedRequest.savedVersion.build} · {target}</p>}
      {state.prepared&&(!retained||!state.historical)&&<p>Prepared intent <code>{state.prepared.intentSha256}</code> · Store snapshot observed at {state.prepared.observedAt} (not a current Store check).</p>}
      {!state.request&&<button onClick={onCredentials}>Configure local credentials</button>}
      <button disabled={!!reason||state.pending} onClick={()=>void controller.prepare()}>{stage?'Review prepared promotion':'Review internal upload'}</button>
      {reason&&<p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil!==null&&<div className="notice">
      <p><strong>{stage?'Promote to':'Upload to'} {target}.</strong> {stage?stageEffect:ios?'This sends the existing signed IPA and waits for Apple processing. It does not invite external testers, enable automatic tester notifications, submit an App Store version, or publish publicly.':'This sends the existing signed AAB and makes the prepared release available to internal testers. It is not a public release.'}</p>
      <p>{displayedApplication} · Version {op?.context.savedVersion.name} · Build {op?.context.savedVersion.build}. Candidate <code>{op?.context.candidateOperationId}</code>.</p>
      <p>Cancellation or a lost response cannot undo an upload or committed edit. Keep the app open until original cleanup is confirmed. Do not repeat an uncertain upload.</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event=>controller.acknowledge(event.target.checked)}/> I authorize this existing candidate’s {stage?target:ios?'TestFlight internal upload':'upload and internal-testing commit'} only.</label>
      <button disabled={!state.acknowledged||state.pending} onClick={()=>void controller.start()}>{stage?'Execute prepared promotion':ios?'Upload to TestFlight internal':'Upload and commit internal release'}</button>
    </div>}
    {retained&&<div role="status"><p>{op?.phase==='running'?'Executing the original Store operation. This can take up to 20 minutes; keep the app open until cleanup is confirmed.':retained}</p><button onClick={()=>void controller.cancel()}>Cancel original execution</button></div>}
    <button disabled={state.mode!=='native'} onClick={()=>void controller.checkStatus()}>Refresh execution status</button>
    {state.error&&<p role="alert">{state.error}</p>}
    {op&&<p>{state.historical?'Earlier context · ':''}{op.phase}{op.reason!=='none'?` · ${op.reason.replaceAll('-',' ')}`:''}</p>}
    {op&&(op.phase==='unknown'||op.phase==='terminal'&&op.outcome!=='complete')&&<p className="save-note">No successful internal release is confirmed by this result. Preserve the project, receipt/attempt files, history and Mac Keychain entries. A failure may follow an actual Store change. Do not delete records, re-enroll or upload again to clear it. Use Verify history → Review for Store check to request a separate read-only observation of the current target when available. That observation does not resend a build, repair the earlier worker or prove its cleanup; keep original Status and Cancel for an unknown owner.</p>}
    {receipt&&state.historical&&<p>The retained execution result belongs to an earlier context; it is not a release of your current selection.</p>}
    {receipt&&!state.historical&&<div className="notice">
      <h3>{'stage' in receipt?'Prepared stage executed':'Internal-testing target confirmed'} · Not a public release</h3>
      {'stage' in receipt&&<p>{localStoreStageLabel(receipt.stage,'bundleId' in receipt?'ios':'android')} · Store state: {receipt.state.replaceAll('-',' ')}. A submitted or approved review does not mean the app is available publicly. The recorded original binary was reused.</p>}
      <p>{'bundleId' in receipt?receipt.bundleId:receipt.applicationId} · Version {receipt.version.name} · Build {receipt.version.build} · {receipt.result==='accepted'?'Accepted in this execution':'Confirmed by this execution’s readback'}</p>
      <p>Observed at {receipt.observedAt}. Local checkpoint {op?.result?.headSequence}. Receipt <code>{receipt.receiptSha256}</code>.</p>
      <p>This is the original execution’s completed result, not permission to send again. It does not establish the earlier preparation’s finality, an atomic saved-input snapshot, or current Store state after this observation.</p>
    </div>}
  </section>;
}
