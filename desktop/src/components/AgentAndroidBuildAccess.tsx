import { useEffect, useState } from 'react';
import type { AgentAndroidBuildPermission } from '../agentAndroidBuild.ts';
export function AgentAndroidBuildAccess({controller}:{controller:AgentAndroidBuildPermission}){
  const [state,setState]=useState(controller.getState());useEffect(()=>controller.subscribe(setState),[controller]);
  const access=state.access, signed=controller.signingSelected(), candidate=controller.candidateSelected();
  return <section className="session-review" aria-label="One agent Android build permission">
    <h3>Let an AI or CLI agent build this project once</h3>
    <p>{candidate ? 'Allow one journalled local candidate build using the assigned existing upload key and the current enrolled local history. This creates candidate inputs; it does not upload or turn an earlier AAB into a candidate.' : signed ? 'Allow one local signed build using the existing upload key explicitly assigned in this Desktop. Key bytes, passwords and alias stay private; the CLI receives no credentials. No new key is generated.' : 'Allow one build and structure/version inspection from the current saved inputs. MRK supplies no signing credentials.'} No Store publishing permission is granted. The original read permission and five-minute native review may shorten the 15-minute start window.</p>
    <p className="review-caution">Gradle and project scripts may run programs, change files, use the network, or sign using the project’s own settings. This is not a sandbox or a guarantee that scripts cannot sign.</p>
    <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={!!state.pending||state.revokePending}
      onChange={(e)=>controller.acknowledge(e.target.checked)}/>{candidate ? 'I approve one journalled candidate build with these saved inputs, assigned key and project-code risks.' : signed ? 'I approve one local signed agent build with this assigned existing upload key and these project-code risks.' : 'I approve one agent build from these saved inputs, with these risks.'}</label>
    <div className="button-row"><button className="button secondary" type="button" disabled={!controller.canAllow()} onClick={()=>void controller.allow()}>Allow</button>
      <button className="button secondary" type="button" disabled={state.revokePending} onClick={()=>void controller.revoke()}>Stop</button>
      <button className="button secondary" type="button" disabled={!!state.pending||state.revokePending} onClick={()=>void controller.status()}>Refresh</button></div>
    <p>{access ? access.enabled ? 'Last checked: allowed for one request.' : access.consumed ? 'Permission used. Follow the build status above.' : 'Last checked: not allowed.' : 'Refresh permission before approving this exact selection.'} Stop revokes permission and asks a running build to stop; cleanup may take time.</p>
    <p>Android and iOS share one build permission. Explicitly allowing either replaces the other unused permission, never a running or unconfirmed build.</p>
    <details><summary>CLI details</summary>
      {access?.projectId&&<p>Project <code>{access.projectId}</code> · saved observation <code>{access.observationRevision}</code></p>}
      <p>Use <code>mrk android-build-prepare PROJECT_ID OBSERVATION_REVISION --json</code>, review its response, then use its separate Start command. Keep the printed IDs for Status/Cancel and do not repeat after a lost reply.</p>
      <p>The same Android panel observes and can stop the build. It cannot start the agent’s prepared build again. Preparation does not renew permission; an admitted build keeps its original execution deadline. Signed-mode results include validated signature comparisons only when actually returned; no result or cleanup uncertainty is not success. Candidate-mode results name only the original journalled candidate and source. A fresh candidate check is needed before a separate Store action. No mode grants release approval or automated recovery.</p>
    </details>
    {state.message&&<p role="status" className="review-caution">{state.message}</p>}
  </section>;
}
