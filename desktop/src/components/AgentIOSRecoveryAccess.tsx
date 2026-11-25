import {useEffect, useState} from 'react';
import type {AgentIOSArchivePermission} from '../agentIOSArchive.ts';
import type {IOSArchiveController, IOSArchiveState} from '../iosArchive.ts';

/** One view of the App-owned iOS permission, not a second executor/queue. */
export function AgentIOSRecoveryAccess({controller, state, permission}: {
  controller: IOSArchiveController; state: IOSArchiveState; permission: AgentIOSArchivePermission;
}) {
  const [accessState, setAccessState] = useState(permission.getState());
  useEffect(() => permission.subscribe(setAccessState), [permission]);
  useEffect(() => { permission.syncContext(); });
  const selected=state.agentRecoverySelection, receipt=permission.acknowledgedInspection();
  const pending=!!accessState.pending||accessState.revokePending;
  const choose=(action:'inspect'|'account'|'project')=>{
    if(controller.selectAgentRecovery(action,permission.acknowledgedInspection())){
      permission.acknowledge(false); permission.syncContext();
    }
  };
  return <details className="session-review">
    <summary>Advanced: delegate one local iOS recovery action</summary>
    <p>The same CLI and Desktop owner can inspect local state, or restore only a session offered by that original inspection. This does not build, sign, contact a Store, force cleanup or accept a session supplied by the CLI.</p>
    <div className="button-row">
      {(['inspect','account','project'] as const).map(action=>{
        const reason=controller.agentRecoveryReason(action,receipt);
        return <button key={action} className="button secondary" type="button" disabled={pending||!!reason}
          title={reason??undefined} aria-pressed={selected?.action===action} onClick={()=>choose(action)}>
          {action==='inspect'?'Select Inspect':`Select ${action} restoration`}
        </button>;
      })}
    </div>
    {selected ? <>
      <p>Selected action: <strong>{selected.action==='inspect'?'Inspect local state':`Restore inspected ${selected.action} state`}</strong>.
        {selected.action!=='inspect'&&<> Original inspection <code>{selected.inspection.operationId}</code> · generation <code>{selected.inspection.ownerGeneration}</code>.</>}</p>
      <p>First Check permission, then explicitly acknowledge this action and Allow. CLI Prepare returns an original review; CLI Start is a separate one-use request. A later report never changes this selected inspection.</p>
      <label className="check-row"><input type="checkbox" checked={accessState.acknowledged} disabled={pending}
        onChange={event=>permission.acknowledge(event.target.checked)}/>
        {selected.action==='inspect'?'I authorize one agent inspection of local account signing and this project’s recovery state; inspection does not restore it.':
          selected.action==='account'?'I confirm the macOS account and signing services are idle and authorize ordinary restoration of only this inspected account session’s owned state.':
          'I confirm this project’s build inputs are idle and authorize ordinary restoration of only this inspected project session’s owned state.'}
      </label>
      <p>Confirmation is not worker finality. Busy, conflicting, manual-required or Unknown state cannot be bypassed.</p>
    </>:<p>Select an action above. Normal Desktop Review and Start remain available separately.</p>}
    <div className="button-row">
      <button className="button secondary" type="button" disabled={!selected||pending} onClick={()=>void permission.status()}>Check permission</button>
      <button className="button secondary" type="button" disabled={!selected||!permission.canAllow()} onClick={()=>void permission.allow()}>Allow selected action once</button>
      <button className="button secondary" type="button" disabled={accessState.revokePending} onClick={()=>void permission.revoke()}>Stop permission</button>
    </div>
    {accessState.access?.projectId&&<p>CLI project <code>{accessState.access.projectId}</code> · observation <code>{accessState.access.observationRevision}</code>.</p>}
    <p>Use <code>mrk ios-archive-prepare PROJECT_ID OBSERVATION_REVISION --json</code>; follow the returned separate Start, Status and Cancel addresses. Keep those IDs after a lost reply—do not submit a replacement.</p>
    <p>After a CLI inspection finishes, leave Inspect selected and Check permission for its actual caller/history acknowledgement before choosing restoration. After restoration, inspect again. Android, iOS builds and local recovery share the same finite permission/inbox; this adds no headless or forced-recovery mode.</p>
    {selected&&controller.agentRecoveryReason(selected.action,receipt)&&<p className="review-caution">{controller.agentRecoveryReason(selected.action,receipt)}</p>}
    {accessState.message&&<p className="review-caution" role="status">{accessState.message}</p>}
  </details>;
}
