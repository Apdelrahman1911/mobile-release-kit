import { useEffect,useState } from 'react';
import type { GitIndexPermission } from '../service_git_permission.ts';
export function ServiceGitIndexAccess({controller}:{controller:GitIndexPermission}){
 const [state,setState]=useState(controller.getState());useEffect(()=>controller.subscribe(setState),[controller]);
 const access=state.access;
 return <section className="session-review" aria-label="Agent Git index permission">
  <h3>Let an AI or CLI agent stage selected changes once</h3>
  <p>Check Git changes and select files above first. Allow gives the agent 15 minutes to prepare and start one Stage or Unstage of exactly those files.</p>
  <p className="review-caution">This changes the local Git index. It does not grant commit, branch switching, push, credentials, or arbitrary commands. This shares one permission with agent Commit; an explicit Allow replaces only an unused permission. Git may run configured clean filters; they can run project code or have file and network effects.</p>
  <label>Action <select value={controller.getAction()} disabled={!!state.pending||state.revokePending} onChange={e=>controller.chooseAction(e.target.value==='unstage'?'unstage':'stage')}>
   <option value="stage">Stage selected files</option><option value="unstage">Unstage selected files</option></select></label>
  <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={!!state.pending||state.revokePending} onChange={e=>controller.acknowledge(e.target.checked)}/>I approve this one local Git change to the selected files, with these risks.</label>
  <div className="button-row"><button className="button secondary" disabled={!controller.canAllow()} onClick={()=>void controller.allow()}>Allow</button>
   <button className="button secondary" disabled={state.revokePending} onClick={()=>void controller.revoke()}>Stop</button>
   <button className="button secondary" disabled={!!state.pending||state.revokePending} onClick={()=>void controller.status()}>Refresh</button></div>
  <p>{access?.enabled?'Last checked: allowed once.':access?.consumed?'Permission used. Follow the original Git operation above.':'Permission is not confirmed active.'} Stop in either this or the Commit panel revokes the shared permission and asks its original task to stop; it does not prove cleanup.</p>
  <details><summary>CLI details</summary><p>Use <code>mrk git-index-scope PROJECT_ID --json</code> for the approved paths and Prepare command. Prepare returns a separate, one-use Start command. Keep its instance/request IDs after a lost reply; do not repeat the change.</p>
   {access?.projectId&&<p>Project <code>{access.projectId}</code> · {access.selection?.summary.pathCount} files · {access.selection?.summary.action}</p>}
   <p>Only the original native joined review can start. The Desktop Git panel can observe, stop, or close an agent review, but cannot apply it a second way. No native availability or cleanup is inferred from this permission.</p></details>
  {state.message&&<p role="status" className="review-caution">{state.message}</p>}
 </section>;
}
