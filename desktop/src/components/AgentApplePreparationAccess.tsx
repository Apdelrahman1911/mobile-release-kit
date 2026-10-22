import { useSyncExternalStore } from 'react';
import { appleCliModes } from '../agentAppleProvisioning.ts';
import { applePreparationCommands } from '../agentApplePreparation.ts';
import type { ApplePreparationMode } from '../agentApplePreparation.ts';
import type { AgentApplePreparationController } from '../agentApplePreparationController.ts';
export function AgentApplePreparationAccess({controller}:{controller:AgentApplePreparationController}) {
  const state=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  return <details>
    <summary>Advanced · let the installed CLI prepare a selected step</summary>
    <p>Usually, use the ordinary Prepare button. This option lets the CLI request that same local preparation once, using only the credentials, saved inputs and target already selected here. It does not Start the step.</p>
    <label>Selected step <select value={state.mode} disabled={!!controller.ownerReason()} onChange={e=>controller.setMode(e.target.value as ApplePreparationMode)}>
      {appleCliModes.map(mode=><option key={mode} value={mode}>{mode}</option>)}
    </select></label>
    {state.mode==='key-recover'&&<p>Use only the original durably saved key selected in this app. Start will verify it against the original setup record and may record a local verification association. Missing keys, backup-restored new references and uncertain saves cannot be recovered here; no replacement key is generated.</p>}
    <label><input type="checkbox" checked={state.acknowledged} disabled={!state.selection||!!controller.ownerReason()||!state.listening}
      onChange={e=>controller.acknowledge(e.target.checked)}/> Allow one CLI Prepare of this exact selected step. I will review and approve Start separately.</label>
    <div className="actions">
      <button type="button" disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>Allow Prepare once</button>
      <button type="button" disabled={!!controller.checkReason()} onClick={()=>void controller.check()}>Check original preparation</button>
      <button type="button" disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Withdraw preparation permission</button>
    </div>
    {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
    {(state.pending||state.revoking)&&<p role="status">Waiting for the original caller. A relay event does not finish preparation or history.</p>}
    {state.issue&&<p role="alert">{state.issue}</p>}
    {state.stale&&<p>These controls address the retained original selection, not the currently selected project.</p>}
    {applePreparationCommands(state.access).map(command=><pre key={command}><code>{command}</code></pre>)}
    {state.status&&<p>Original preparation: {state.status.phase} · {state.status.settlement}. {state.status.usable?'Review the new intent above, then use its normal Start or the separate Start delegation.':''}</p>}
    <p>Keep this Desktop session open. No credential paths, passwords, keys or provider options belong in these commands. Lost replies are checked using the original request ID, never by repeating Prepare. Account setup, assignment and backup remain explicit Desktop actions; key recovery supports only the original durably saved key.</p>
  </details>;
}
