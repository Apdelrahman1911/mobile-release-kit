import { useEffect, useState } from 'react';
import type { AgentAndroidBuildPermission } from '../agentAndroidBuild.ts';
export function AgentAndroidBuildAccess({controller}:{controller:AgentAndroidBuildPermission}){
  const [state,setState]=useState(controller.getState());useEffect(()=>controller.subscribe(setState),[controller]);
  const access=state.access;
  return <section className="session-review" aria-label="One agent Android build permission">
    <h3>Let an AI or CLI agent build this project once</h3>
    <p>Allow one build from the current saved inputs. The agent has 15 minutes to start. This does not grant MRK signing credentials or Store publishing permission.</p>
    <p className="review-caution">Gradle and project scripts may run programs, change files, use the network, or sign using the project’s own settings. This is not a sandbox or a guarantee that scripts cannot sign.</p>
    <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={!!state.pending||state.revokePending}
      onChange={(e)=>controller.acknowledge(e.target.checked)}/>I approve one agent build from these saved inputs, with these risks.</label>
    <div className="button-row"><button className="button secondary" type="button" disabled={!controller.canAllow()} onClick={()=>void controller.allow()}>Allow</button>
      <button className="button secondary" type="button" disabled={state.revokePending} onClick={()=>void controller.revoke()}>Stop</button>
      <button className="button secondary" type="button" disabled={!!state.pending||state.revokePending} onClick={()=>void controller.status()}>Refresh</button></div>
    <p>{access ? access.enabled ? 'Last checked: allowed for one request.' : access.consumed ? 'Permission used. Follow the build status above.' : 'Last checked: not allowed.' : 'Permission has not been checked.'} Stop revokes permission and asks a running build to stop; cleanup may take time.</p>
    <p>Android and iOS share one build permission. Explicitly allowing either replaces the other unused permission, never a running or unconfirmed build.</p>
    <details><summary>CLI details</summary>
      {access?.projectId&&<p>Project <code>{access.projectId}</code> · saved observation <code>{access.observationRevision}</code></p>}
      <p>Use <code>mrk android-build-prepare PROJECT_ID OBSERVATION_REVISION --json</code>, review its response, then use its separate Start command. Keep the printed IDs for Status/Cancel and do not repeat after a lost reply.</p>
      <p>The same Android panel observes and can stop the build. It cannot start the agent’s prepared build again. Preparation does not renew the permission; an admitted build keeps its existing execution deadline. Results describe artifact structure and version checks, not signing or release approval.</p>
    </details>
    {state.message&&<p role="status" className="review-caution">{state.message}</p>}
  </section>;
}
