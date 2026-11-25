import { useEffect, useState } from 'react';
import type { AgentLocalCheckPermission } from '../agentLocalChecks';
export function AgentLocalCheckAccess({ controller, blocked }: { controller: AgentLocalCheckPermission; blocked: boolean }) {
  const [state, setState] = useState(controller.getState());
  useEffect(() => controller.subscribe(setState), [controller]);
  const access = state.access;
  return <section className="card"><h3>Let an agent run one local project check</h3>
    <p>Separate from read access and app-ID proposals. This permits one saved Android local-project check, for up to 15 minutes, in the running Desktop.</p>
    <p className="review-caution">Configured project checks may execute programs, modify files, build, read account files or use the network. This is not a sandbox. MRK does not request its signing, credentials, Store operations or release build.</p>
    <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={blocked || !!state.pending || state.revokePending}
      onChange={(event) => controller.acknowledge(event.target.checked)} />I trust the configured checks in this saved project and authorize one agent execution.</label>
    <div className="button-row"><button className="button secondary" type="button" disabled={blocked || !controller.canAllow()} onClick={() => void controller.allow()}>Allow one local check · 15 minutes</button>
      <button className="button secondary" type="button" disabled={state.revokePending} onClick={() => void controller.revoke()}>Revoke and request original stop</button>
      <button className="button secondary" type="button" disabled={!!state.pending || state.revokePending} onClick={() => void controller.status()}>Check permission</button></div>
    <p>Last observed permission: {access ? access.enabled ? 'enabled for one execution' : access.consumed ? 'consumed; not a completion receipt' : 'disabled' : 'not checked'}.</p>
    {access?.projectId && <p>CLI project <code>{access.projectId}</code> · saved observation <code>{access.observationRevision}</code></p>}
    {state.message && <p role="status" className="review-caution">{state.message}</p>}
    <p>Use <code>mrk local-check PROJECT_ID OBSERVATION_REVISION --json</code>. Keep its printed request ID to query or cancel without replaying. The same Offline checks panel shows the native operation; do not run it again in the GUI.</p>
  </section>;
}
