import { useEffect, useState } from 'react';
import type { AgentIOSArchivePermission } from '../agentIOSArchive.ts';
import type { IOSArchiveState } from '../iosArchive.ts';
export function AgentIOSArchiveAccess({controller,archive}:{controller:AgentIOSArchivePermission;archive:IOSArchiveState}){
  const [state,setState]=useState(controller.getState());useEffect(()=>controller.subscribe(setState),[controller]);
  const access=state.access, signed=archive.archiveMode==='signed', candidate=signed&&archive.keepCandidate;
  const unsupported=archive.archiveMode==='signing-check';
  return <section className="session-review" aria-label="One agent iOS build permission">
    <h3>Let an AI or CLI agent {candidate?'build a local candidate':signed?'export a signed IPA':'archive this project'} once</h3>
    <p>New permission selection: {unsupported?'signing-input checks remain separate; choose unsigned archive, signed export or candidate inputs.':candidate?'journalled candidate Create using the assigned signing inputs and enrolled local history; not conversion of an earlier IPA.':signed?'signed export using the exact assigned Apple Distribution P12/password, profile and saved signing policy shown above.':'unsigned archive from the current saved inputs; MRK supplies no signing credentials.'}</p>
    <p>Refresh permission, then approve this selection once. The agent has at most 15 minutes to start; signed export also ends with the original agent read permission. This never grants Store publishing.</p>
    {signed&&<p className="review-caution">Signed export uses the existing account signing lease and private Keychain/profile setup, plus any selected Firebase file or project read token. Only owned temporary changes are restored; unresolved cleanup stays blocked. Valid Apple Distribution material and a qualified Mac/Xcode runtime are still required.</p>}
    <p className="review-caution">Xcode and project scripts may run programs, change files, use the network, or sign using the project’s own settings. This is not a sandbox or a guarantee that scripts cannot sign.</p>
    <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={!!state.pending||state.revokePending||unsupported}
      onChange={(e)=>controller.acknowledge(e.target.checked)}/>{candidate?'I approve one journalled candidate build with these assigned inputs, local history and account effects.':signed?'I approve one agent signed export with these assigned inputs and account effects.':'I approve one agent archive from these saved inputs, with these risks.'}</label>
    <div className="button-row"><button className="button secondary" type="button" disabled={!controller.canAllow()} onClick={()=>void controller.allow()}>Allow</button>
      <button className="button secondary" type="button" disabled={state.revokePending} onClick={()=>void controller.revoke()}>Stop</button>
      <button className="button secondary" type="button" disabled={!!state.pending||state.revokePending} onClick={()=>void controller.status()}>Refresh</button></div>
    <p>{access ? access.enabled ? 'Last checked: an original one-use permission is allowed.' : access.consumed ? 'Permission used. Follow the original build status above.' : 'Last checked: not allowed.' : 'Permission has not been checked.'} Changing the selection does not change an existing permission. Stop revokes the original permission and asks its build to stop; cleanup may take time.</p>
    <p>Android and iOS share one build permission. Explicitly allowing either replaces the other unused permission, never a running or unconfirmed build.</p>
    <details><summary>CLI details</summary>
      {access?.projectId&&<p>Project <code>{access.projectId}</code> · saved observation <code>{access.observationRevision}</code></p>}
      <p>Use <code>mrk ios-archive-prepare PROJECT_ID OBSERVATION_REVISION --json</code>, review its exact mode and response, then use its separate Start command. The CLI cannot choose a different signing mode or material. Keep the printed IDs for Status/Cancel and do not repeat after a lost reply.</p>
      <p>The same iOS panel observes and can stop the build. It cannot start the agent’s prepared build again. Preparation does not renew permission. Results describe the original local archive, signed export or explicitly selected journalled candidate. Only candidate mode reports candidate/source/primary digests; these historical comparisons require fresh candidate verification before a separate Store action. Local recovery has separate action controls in Recovery; this build permission cannot restore state.</p>
    </details>
    {state.message&&<p role="status" className="review-caution">{state.message}</p>}
  </section>;
}
