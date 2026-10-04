
import { useEffect, useId, useRef, useState } from 'react';
import type { WorkflowRecoveryView } from '../githubWorkflowEditTypes.ts';
import type { WorkflowRecoveryApplyBinding } from '../githubWorkflowEdit.ts';

function summary(value: WorkflowRecoveryView['files'][number]['before']) {
  return value === null ? 'Absent / not staged' : <>{value.size.toLocaleString()} bytes · mode {value.mode.toString(8).padStart(4, '0')}<code>{value.sha256}</code></>;
}
export function WorkflowRecoveryReview({ view }: { view: WorkflowRecoveryView }) {
  return <div className="save-review workflow-review" aria-label="Inspected workflow recovery">
    <h3>{view.action === 'rollback' ? 'Roll back this interrupted workflow transaction' :
      view.action === 'committed_cleanup' ? 'Preserve the prior commit; clean its private journal only' :
      view.action === 'rolled_back_cleanup' ? 'Keep the completed rollback; clean its private journal only' : 'Clean a complete, uninstalled preparation journal'}</h3>
    <p>Current inspection <code>{view.transactionId}</code>. These are journal summaries, not a new Apply plan or assertions about later public edits. No raw private file contents are displayed.</p>
    <div className="review-table-wrap workflow-files"><table className="review-table">
      <caption>Fixed four-caller recovery roster</caption>
      <thead><tr><th scope="col">Destination</th><th scope="col">Recovery action</th><th scope="col">Journal original</th><th scope="col">Journal staged</th></tr></thead>
      <tbody>{view.files.map((file) => <tr key={file.id}>
        <th scope="row"><code>{file.path}</code></th>
        <td>{file.action === 'restore' ? 'Restore original caller' : file.action === 'remove' ? 'Remove transaction-created caller' : 'Preserve public caller'}</td>
        <td>{summary(file.before)}</td><td>{summary(file.after)}</td>
      </tr>)}</tbody>
    </table></div>
    <p>Inspected private cleanup: {view.privateCleanup.fileCount} files and {view.privateCleanup.directoryCount} directories, confined to this workflow journal.
      {view.action === 'rollback' && <> Rollback can also remove this transaction’s newly created, still-empty <code>.github/workflows</code> and <code>.github</code> directories; no other ancestor or sibling is authorized.</>}
    </p>
    <p className="review-caution">{view.action === 'committed_cleanup' || view.action === 'rolled_back_cleanup' ?
      'Terminal evidence authorizes private cleanup only. Later user changes to public callers are neither read for equality nor reversed.' :
      'Changed controls, private objects, callers or ancestors cause refusal. There is no force option or journal reset.'}
      {' '}Recovery does not validate or save a configuration draft, render templates, retry Apply, contact GitHub or launch a release.</p>
  </div>;
}
export function WorkflowRecoveryConfirmation({ view, binding, allowed, onCancel, onConfirm }: {
  view: WorkflowRecoveryView; binding: WorkflowRecoveryApplyBinding; allowed: boolean;
  onCancel: () => void; onConfirm: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId(); const checkboxId = useId();
  const [reviewed, setReviewed] = useState(false);
  useEffect(() => {
    const element = dialog.current;
    if (element && !element.open) element.showModal();
    return () => { if (element?.open) element.close(); };
  }, []);
  return <dialog ref={dialog} className="save-confirm-dialog workflow-confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}>
    <div className="dialog-content">
      <span className="eyebrow">EXPLICIT CURRENT-INSPECTION RECOVERY</span><h2 id={titleId}>Recover only this inspected journal?</h2>
      <p>This confirmation is bound to the original native recovery session and revision <code>{binding.revision}</code>. It is not an old Apply token. A changed inspection cannot silently replace it.</p>
      <WorkflowRecoveryReview view={view} />
      <label className="save-confirm-choice" htmlFor={checkboxId}><input id={checkboxId} type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />
        I reviewed the fixed paths, journal size/mode/SHA summaries and the rollback or private-cleanup action. I authorize one Recover, not Apply or a force reset.
      </label>
      {!allowed && <p className="review-caution" role="alert">This recovery confirmation is no longer current. Nothing can be submitted from it.</p>}
      <div className="button-row"><button type="button" autoFocus className="button secondary" onClick={onCancel}>Keep reviewing</button>
        <button type="button" className="button primary" disabled={!reviewed || !allowed} onClick={onConfirm}>Recover inspected workflow journal</button></div>
    </div>
  </dialog>;
}
