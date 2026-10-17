import type { LocalReleaseHistoryController, LocalHistoryState } from '../localReleaseHistory.ts';
import { localHistoryOwnerReason } from '../localReleaseHistory.ts';
import type { LocalHistoryReason } from '../localReleaseHistoryTypes.ts';

const hints: Partial<Record<LocalHistoryReason, string>> = {
  'enrollment-exists': 'This project already has local history. Choose Verify existing history; do not delete its files or Keychain items.',
  'journal-unavailable': 'History could not be verified. Keep the original project and its Keychain items intact. Do not enroll again to replace missing or damaged history.',
  'recovery-required': 'An earlier operation needs reconciliation. Preserve its files and inspect the original operation before attempting another release.',
  'project-busy': 'Another operation holds this project. Finish or cancel that operation, then refresh status.',
  'runtime-unavailable': 'Repair or update the installed Mac application before trying again.',
  'cleanup-unknown': 'The original operation has not confirmed cleanup. Keep this application open and use Refresh status or Cancel original operation.',
};

export function LocalReleaseHistory({ state, controller, compact = false, onShow }: {
  state: LocalHistoryState; controller: LocalReleaseHistoryController; compact?: boolean; onShow: () => void;
}) {
  const retained = localHistoryOwnerReason(state), op = state.status?.operation;
  const action = state.request?.action ?? 'verify', reason = controller.prepareReason();
  const labels = { enroll: 'Enroll project', verify: 'Verify history', 'review-inputs': 'Review candidate inputs', 'abandon-inputs': 'Abandon input operation', 'review-prepared': 'Review prepared intent', 'review-execution': 'Review execution receipt', 'review-reconcile': 'Review for Store check' };
  const consent = {
    enroll: 'Enrollment creates local project history and private Keychain state on this Mac. It does not replace an existing enrollment, build, sign, upload or publish.',
    verify: 'Verify this project’s existing local history against its Mac Keychain state. This does not enroll a project, repair an interrupted release, or authorize publishing.',
    'review-reconcile': 'Read the latest execution’s retained prepared files against local history and Keychain. No network, Store action, history repair or retry is authorized. A separate consent is required to check Play.',
    'review-execution': 'Read this operation’s retained execution receipt and candidate/prepared files against project history and Mac Keychain. This makes no Store call, does not repair the earlier execution’s finality or authorize retrying, and does not confirm current Play state.',
    'review-prepared': 'Read this operation’s retained prepared intent and candidate files against project history and Mac Keychain. This makes no Store call and does not execute, recover or retry a release, or prove that the earlier preparation finished cleanly.',
    'review-inputs': 'Read this operation’s current local inputs and verify them against its project history and Mac Keychain. This does not build, submit or authorize a release, or prove that the earlier build completed cleanly.',
    'abandon-inputs': 'Record this pending or ready input operation as cancelled so another input operation can be prepared. Existing files stay untouched. This does not stop a running build, undo a Store action, delete files or repair uncertain history.',
  };
  const selectedAction = op?.context.action ?? action;
  const candidate = op?.result?.candidateInputs, prepared = op?.result?.preparedIntent, execution = op?.result?.executionReceipt;
  const choose = (action:'review-inputs'|'abandon-inputs'|'review-prepared'|'review-execution'|'review-reconcile',id:string) => {
    if(controller.selectCandidate(action,id))void controller.prepare();
  };
  if (compact && !retained) return null;
  return <section className="card" aria-label="Local release history">
    <div className="inline-heading"><h2>Release history · This Mac</h2>{compact && <button onClick={onShow}>Show history</button>}</div>
    {!compact && <>
      <p>Keep a verifiable record of local release operations for the selected project. This is separate from GitHub history and never authorizes a build or Store release.</p>
      <details><summary>Help: what is enrollment, and where does the key come from?</summary>
        <p>Enroll once to create this project's local history and a private key in your Mac Keychain. The application generates and manages the key; you do not need to enter a credential or copy a file. macOS may ask for Keychain access.</p>
        <p>Verify reads existing history without creating enrollment. Keep the project and its Keychain items together: copied, replaced or missing history may not verify. Verification can detect history rollback only while the matching Keychain state remains intact. Never delete these items to clear a failure.</p>
      </details>
      <label>History action <select value={action} disabled={!!retained} onChange={event => controller.setAction(event.target.value === 'enroll' ? 'enroll' : 'verify')}>
        <option value="verify">Verify existing history</option><option value="enroll">Enroll this project for the first time</option>
        {(action === 'review-inputs' || action === 'abandon-inputs' || action === 'review-prepared' || action === 'review-execution' || action === 'review-reconcile') && <option value={action}>{labels[action]}</option>}
      </select></label>
      <p>No Store credentials, network access, build tools or release version are required.</p>
      {state.request?.candidateOperationId && <p>Selected operation: <code>{state.request.candidateOperationId}</code>. {labels[action]}.</p>}
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>{action === 'enroll' ? 'Review enrollment' : action === 'verify' ? 'Review history verification' : labels[action]}</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil !== null && <div className="notice">
      <p>{consent[selectedAction]}</p>
      {op?.context.candidateOperationId && <p>Operation: <code>{op.context.candidateOperationId}</code></p>}
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this specific local action.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>{labels[selectedAction]}</button>
    </div>}
    {retained && <div role="status"><p>{op?.phase === 'running' ? 'Checking local history and Keychain. Keep the application open until the original operation finishes.' : retained}</p><button onClick={() => void controller.cancel()}>Cancel original operation</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh history status</button>
    {state.error && <p role="alert">{state.error}</p>}
    {op && <p>{state.historical ? 'Earlier project context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>}
    {op && hints[op.reason] && <p className="save-note">{hints[op.reason]}</p>}
    {op?.result && <>
      <h3>Verified local history</h3><p>Checkpoint {op.result.headSequence}. {op.result.history.length === 0 ? 'No release operations recorded.' : 'Latest recorded operation states (up to 64):'}</p>
      <ul>{op.result.history.map(row => <li key={row.operationId}>
        <code>{row.operationId}</code> — {row.phase.replaceAll('-', ' ')}{row.recoveryRequired && <strong> · Review before retrying</strong>}
        {!compact && !retained && !state.historical && ['inputs-pending','inputs-ready','settled-failure'].includes(row.phase) && <div className="button-row">
          <button onClick={() => choose('review-inputs',row.operationId)}>Review inputs</button>
          {op.result!.history.at(-1) === row && ['inputs-pending','inputs-ready'].includes(row.phase) && <button onClick={() => choose('abandon-inputs',row.operationId)}>Review abandonment</button>}
        </div>}
        {!compact && !retained && !state.historical && op.result!.history.at(-1) === row && ['execute-pending','settled-success','settled-failure','reconciliation-required'].includes(row.phase) && <button onClick={() => choose('review-reconcile',row.operationId)}>Review for Store check</button>}
        {!compact && !retained && !state.historical && row.phase === 'prepared' && <button onClick={() => choose('review-prepared',row.operationId)}>Review prepared intent</button>}
        {!compact && !retained && !state.historical && row.phase === 'settled-success' && <button onClick={() => choose('review-execution',row.operationId)}>Review execution receipt</button>}
      </li>)}</ul>
      {candidate && state.historical && <p>This bundle was reviewed for an earlier project context. Its current files have not been checked for the selected project.</p>}
      {candidate && !state.historical && <div className="notice">
        <h3>Inputs currently verified · Not submitted</h3>
        <p>{candidate.applicationId} · Version {candidate.version.name} · Build {candidate.version.build}</p>
        <ul>{candidate.files.map(file=><li key={file.fileName}>{file.fileName} — {file.bytes.toLocaleString()} bytes</li>)}</ul>
        <p>Saved inside your project at <code>.mobile-release/desktop-android-build/{candidate.operationId.replaceAll('-','')}/artifacts</code>. No copying or registration is needed.</p>
        <p>This review verifies the current bundle only. It does not establish that the earlier creation finished cleanly, authorize Store submission, or confirm any Store state.</p>
      </div>}
      {prepared && state.historical && <p>This intent was reviewed for an earlier project context. Its current prepared files have not been checked for the selected project.</p>}
      {prepared && !state.historical && <div className="notice">
        <h3>{selectedAction==='review-reconcile'?'Files ready for a separate Store check':'Prepared files currently verified · Not executed'}</h3>
        <p>{prepared.applicationId} · Version {prepared.version.name} · Build {prepared.version.build} · Play internal testing</p>
        <p>Candidate operation: <code>{prepared.operationId}</code></p>
        <p>Intent SHA-256: <code>{prepared.intentSha256}</code></p>
        <p>Store snapshot originally observed at {prepared.observedAt}. It is not a current Store check; the temporary edit may have expired.</p>
        <p>This verifies the current retained files only, not the earlier preparation’s finality or the current working tree. It grants no Execute, Recover, retry or Store authority. Keep all files and history intact.</p>
      </div>}
      {execution && state.historical && <p>This receipt was reviewed for an earlier project context. Its current files have not been checked for the selected project.</p>}
      {execution && !state.historical && <div className="notice">
        <h3>Execution receipt files currently verified</h3>
        <p>{execution.applicationId} · Version {execution.version.name} · Build {execution.version.build} · Play internal testing</p>
        <p>Operation: <code>{execution.operationId}</code> · Recorded result: {execution.result}</p>
        <p>Receipt SHA-256: <code>{execution.receiptSha256}</code></p>
        <p>Receipt originally observed at {execution.observedAt}. This is not a current Play check or proof of public release.</p>
        <p>This verifies the current retained files only. It does not establish that the earlier execution’s native cleanup finished, repair an uncertain tail, or grant retry, recovery or promotion authority. Keep all files and history intact.</p>
      </div>}
      {op.result.candidateInputs === null && <p>{op.context.action === 'abandon-inputs' ? 'The input operation was abandoned. Its files were preserved; no Store action was performed.' : 'No verified ready input bundle was returned. The operation is pending or abandoned; keep its files intact.'}</p>}
      {!compact && <details><summary>Help: review or abandon an input operation?</summary><p>Review checks the saved Android bundle without rebuilding or contacting a Store. If you no longer need a pending or ready input operation, review abandonment and confirm it. Abandonment records cancellation but keeps the files. Only the current pending or ready input operation can be abandoned; uncertain or changed history must be reconciled instead.</p></details>}
      {!compact && <p>After restarting, Verify history and select a prepared or completed execution row to inspect its retained intent or receipt without Store credentials or network access. For the latest execution, Review for Store check also reads the retained prepared files. Then use Check previous Play upload for a separate network check. Neither action repairs old cleanup or authorizes a retry.</p>}
      <p>This is a point-in-time local record, not Store access, publication proof, or permission to retry a release.</p>
    </>}
  </section>;
}
