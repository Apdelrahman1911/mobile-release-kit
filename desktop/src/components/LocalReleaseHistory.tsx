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
      </select></label>
      <p>No Store credentials, network access, build tools or release version are required.</p>
      <button disabled={!!reason || state.pending} onClick={() => void controller.prepare()}>{action === 'enroll' ? 'Review enrollment' : 'Review history verification'}</button>
      {reason && <p className="save-note">{reason}</p>}
    </>}
    {state.consentUntil !== null && <div className="notice">
      <p>{op?.context.action === 'enroll'
        ? 'Enrollment creates local project history and private Keychain state on this Mac. It does not replace an existing enrollment, build, sign, upload or publish.'
        : 'Verify this project’s existing local history against its Mac Keychain state. This does not enroll a project, repair an interrupted release, or authorize publishing.'}</p>
      <label><input type="checkbox" checked={state.acknowledged} onChange={event => controller.acknowledge(event.target.checked)} /> I authorize this local {op?.context.action === 'enroll' ? 'enrollment' : 'verification'}.</label>
      <button disabled={!state.acknowledged || state.pending} onClick={() => void controller.start()}>{op?.context.action === 'enroll' ? 'Enroll project' : 'Verify history'}</button>
    </div>}
    {retained && <div role="status"><p>{op?.phase === 'running' ? 'Checking local history and Keychain. Keep the application open until the original operation finishes.' : retained}</p><button onClick={() => void controller.cancel()}>Cancel original operation</button></div>}
    <button disabled={state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Refresh history status</button>
    {state.error && <p role="alert">{state.error}</p>}
    {op && <p>{state.historical ? 'Earlier project context · ' : ''}{op.phase}{op.reason !== 'none' ? ` · ${op.reason.replaceAll('-', ' ')}` : ''}</p>}
    {op && hints[op.reason] && <p className="save-note">{hints[op.reason]}</p>}
    {op?.result && <>
      <h3>Verified local history</h3><p>Checkpoint {op.result.headSequence}. {op.result.history.length === 0 ? 'No release operations recorded.' : 'Latest recorded operation states (up to 64):'}</p>
      <ul>{op.result.history.map(row => <li key={row.operationId}><code>{row.operationId}</code> — {row.phase.replaceAll('-', ' ')}{row.recoveryRequired && <strong> · Reconciliation required before retrying</strong>}</li>)}</ul>
      <p>This is a point-in-time local record, not Store access, publication proof, or permission to retry a release.</p>
    </>}
  </section>;
}
