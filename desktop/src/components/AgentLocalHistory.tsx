import { useSyncExternalStore } from 'react';
import type { AgentLocalHistoryController } from '../agentLocalHistoryController.ts';
import { localHistoryCommands } from '../agentLocalHistoryProtocol.ts';
export function AgentLocalHistory({controller,onShow}:{controller:AgentLocalHistoryController;onShow:()=>void}) {
 const s=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot),r=s.review,a=s.access,seconds=controller.remainingSeconds(),commands=localHistoryCommands(a);
 const label=r?.kind==='enroll'?'Enroll this project':r?.kind==='verify'?'Verify existing history':r?.kind==='review-inputs'?`Review ${r.platform==='ios'?'iOS':'Android'} candidate inputs`:null;
 return <details className="card"><summary>Advanced: let a local CLI run one reviewed history step</summary>
  <p>First review Enrollment, Verify, or candidate inputs in Release history. Then approve that exact step here. No Store credentials, saved version or network access is required. Desktop must stay open.</p>
  <button onClick={onShow}>Show Release history</button>
  {r&&<><h3>{label}</h3>{r.kind==='enroll'?<p>Creates this project's local journal and private Mac Keychain items only if genuine enrollment is absent. Never deletes or replaces existing history to clear an error.</p>:<p>Reads the selected project's existing local history and Keychain. Candidate review checks current files only, not the earlier build's finality or any Store state.</p>}
   {r.candidateOperationId&&<p>Selected candidate: <code>{r.candidateOperationId}</code>.</p>}
  </>}
  <p>Allow does not start work. The CLI can submit once before the original permission expires. It cannot select another project, candidate or action, build, publish, repair history or repeat an uncertain operation.</p>
  <label><input type="checkbox" checked={s.acknowledged} disabled={!!controller.consentReason()} onChange={e=>controller.acknowledge(e.target.checked)}/> I allow this one reviewed local-history step.</label>
  <button disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>Allow once</button>
  {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
  <button disabled={!!controller.statusReason()} onClick={()=>void controller.status()}>Check original permission / result</button>
  <button disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Revoke permission / request Stop</button>
  {s.pending&&<p role="status">Waiting for the original permission reply.</p>}{s.revoking&&<p role="status">Revocation requested. Keep Desktop open until the original calls and cleanup return.</p>}
  {s.issue&&<p role="alert">{s.issue}</p>}
  {a&&<p>{s.stale?'Earlier or unconfirmed context · ':''}{a.status?`${a.status.state} · ${a.status.settlement}`:a.enabled?'One-use permission observed':'No unused permission observed'}{seconds!==null?` · at most ${seconds}s remaining`:''}.</p>}
  {commands.length>0&&<><p>Run manually. Keep the request ID printed before Submit; use its Status/Cancel after a lost reply, never Submit again.</p><pre>{commands.join('\n')}</pre></>}
  {a?.status?.state==='complete'&&<p>The original caller, native owner and history writer returned. This result grants no build, Store release, repair or retry authority.</p>}
  {a?.status?.result&&<details><summary>Recorded local-history result</summary><pre>{JSON.stringify(a.status.result,null,2)}</pre></details>}
 </details>;
}
