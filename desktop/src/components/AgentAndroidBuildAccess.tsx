import { useEffect, useState } from 'react';
import type { AgentAndroidBuildPermission } from '../agentAndroidBuild.ts';
export function AgentAndroidBuildAccess({ controller }: { controller: AgentAndroidBuildPermission }) {
  const [state, setState] = useState(controller.getState());
  useEffect(() => controller.subscribe(setState), [controller]);
  const access = state.access;
  return <section className="session-review" aria-label="One CLI Android build permission">
    <h3>Allow one CLI build from these saved inputs</h3>
    <p>Choose structure/version inspection without toolkit signing or retained candidate inputs. This separate one-use permission lasts up to 15 minutes to START; preparing does not renew it. The original build keeps its existing execution deadline.</p>
    <p className="review-caution">Gradle and configured project code may execute programs, read or modify files, use the network, or sign with its own configuration. This is not an unsigned guarantee or a sandbox. MRK does not supply signing credentials or request Store publication.</p>
    <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={!!state.pending || state.revokePending}
      onChange={(e) => controller.acknowledge(e.target.checked)} />I approve one CLI Start for the current saved configuration, version and selected protected tools.</label>
    <div className="button-row"><button className="button secondary" type="button" disabled={!controller.canAllow()} onClick={() => void controller.allow()}>Allow one build Start · 15 minutes</button>
      <button className="button secondary" type="button" disabled={state.revokePending} onClick={() => void controller.revoke()}>Revoke and request original stop</button>
      <button className="button secondary" type="button" disabled={!!state.pending || state.revokePending} onClick={() => void controller.status()}>Check permission</button></div>
    <p>Last observed: {access ? access.enabled ? 'enabled for one request' : access.consumed ? 'request consumed; not a build/cleanup receipt' : 'disabled' : 'not checked'}.</p>
    {access?.projectId && <p>CLI project <code>{access.projectId}</code> · saved observation <code>{access.observationRevision}</code></p>}
    <p>Use <code>mrk android-build-prepare PROJECT_ID OBSERVATION_REVISION --json</code>, inspect that exact request, then use its separate Start command. Keep the printed IDs for Status/Cancel; never replay after a lost reply. The same Android panel observes the original build; do not run it again here.</p>
    {state.message && <p role="status" className="review-caution">{state.message}</p>}
  </section>;
}
