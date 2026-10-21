import { useSyncExternalStore } from 'react';
import type { AgentStoreAccessController } from '../agentStoreAccessController.ts';
import { storeCommands } from '../agentStoreAccess.ts';
export function AgentStoreAccess({controller}:{controller:AgentStoreAccessController}) {
  const state=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const r=state.review,access=state.access,commands=storeCommands(access),seconds=controller.remainingSeconds();
  return <section className="card" aria-label="Local CLI Store permission">
    <h2>Let a local CLI run one reviewed Store step</h2>
    <p>Uses the same native Store review, credentials and cleanup. It cannot Execute, upload, promote or Reconcile. Android access can create a temporary uncommitted Play edit; candidate preparation also writes a local snapshot and intent. iOS access only reads App Store Connect.</p>
    <label>Step <select value={state.selected} disabled={!!controller.ownerReason()} onChange={e=>controller.choose(e.target.value==='candidate-prepare'?'candidate-prepare':'access-check')}>
      <option value="access-check">Basic access check</option><option value="candidate-prepare">Prepare candidate intent</option>
    </select></label>
    {r&&<p>{r.platform==='ios'?'iOS':'Android'} · Version {r.savedVersion.name} · Build {r.savedVersion.build}. Native review <code>{r.operationId}</code>{r.candidate&&<> · Candidate <code>{r.candidate.operationId}</code></>}.</p>}
    <p>First use the original Store panel’s Review button. Allow then authorizes one submission before that same review expires; it does not start it or authorize publishing. Keep Desktop open.</p>
    <label><input type="checkbox" checked={state.acknowledged} disabled={!!controller.consentReason()} onChange={e=>controller.acknowledge(e.target.checked)}/> I allow one local CLI submission of this exact nonpublishing review.</label>
    <button disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>Allow this Store step once</button>
    {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
    <button disabled={!!controller.statusReason()} onClick={()=>void controller.status()}>Check original CLI permission/status</button>
    <button disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Revoke permission / request Stop</button>
    {state.pending&&<p role="status">The original permission caller is still returning.</p>}
    {state.revoking&&<p role="status">Waiting for original revocation. This does not prove the Store operation stopped.</p>}
    {state.issue&&<p role="alert">{state.issue}</p>}
    {access&&<p>{state.stale?'Earlier or unconfirmed context · ':''}{access.status?`${access.status.state} · ${access.status.settlement}`:access.enabled?'One-use permission observed':'No unused permission observed'}{seconds!==null?` · up to ${seconds}s remaining`:''}.</p>}
    {commands.length>0&&<><p>Run manually in your terminal. Keep the request ID printed before submission; after a lost response, use Status/Cancel for that ID, not Submit again.</p><pre>{commands.join('\n')}</pre></>}
    {access?.status?.state==='complete'&&<p>The same caller, native owner and service-history writer returned. Access findings may still fail; a prepared local intent is not an upload or release approval.</p>}
  </section>;
}
