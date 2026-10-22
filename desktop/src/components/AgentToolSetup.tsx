import { useSyncExternalStore } from 'react';
import type { AgentToolSetupController } from '../agentToolSetupController.ts';
import { TOOL_SETUP_KINDS, toolSetupCommands, toolSetupEffect, toolSetupLabel } from '../agentToolSetup.ts';
import type { ToolSetupKind } from '../agentToolSetup.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
export function AgentToolSetup({controller}:{controller:AgentToolSetupController}){
  const s=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot),a=s.access,r=s.review;
  const commands=toolSetupCommands(a),remaining=controller.remainingSeconds();
  return <ProgressiveDisclosure title="Advanced · let a local CLI run one tool step" description="Optional one-use delegation. Keep Desktop open; the normal tool setup above is unchanged.">
    <section className="card" aria-label="One tool setup permission">
      <p>Desktop approves the current saved requirements, prepared draft or native review and chooses source folders. The CLI can start only the one step you approve here—not an unattended install, a build, or a release.</p>
      <label>Step <select value={s.selected} disabled={!!controller.ownerReason()} onChange={e=>controller.choose(e.target.value as ToolSetupKind)}>
        {TOOL_SETUP_KINDS.map(k=><option key={k} value={k}>{toolSetupLabel[k]}</option>)}
      </select></label>
      <p>{toolSetupEffect[s.selected]}</p>
      {s.selected==='inspect-requirements'&&<><button disabled={!!controller.prepareReason()} onClick={()=>void controller.prepareRequirements()}>Prepare requirements check for CLI</button>
        <p>This returns the original native review without starting it. The ordinary Check button above still runs its own inspection.</p>
        {controller.prepareReason()&&<p className="save-note">{controller.prepareReason()}</p>}</>}
      {s.selected==='inspect-saved-requirements'&&<p>This permission pins the saved project inputs shown now. CLI Submit prepares and inspects them once. It cannot read newer inputs, download or register tools automatically.</p>}
      {s.selected==='acquire-reviewed-missing'&&<p>First finish the current saved-requirements inspection above. This permission keeps that exact inspection and source selection; it cannot guess versions, choose another folder or replace working tools.</p>}
      {s.selected==='acquire-missing'&&<p>Use the original Review download control above first. This permission replaces only its GUI Start choice; it does not change the missing-component review or native expiry.</p>}
      {(s.selected==='inspect-picked-sources'||s.selected==='register-reviewed-sources')&&<p>First choose all three folders and check saved inputs in the existing controls. Protected copy also needs the current finalized inspection. Service registration, settings approval, catalogue recovery/selection and subsequent phases stay explicit Desktop actions.</p>}
      {r&&<p>{r.platform==='ios'?'iOS':'Android'} · Draft revision {r.draftRevision}, baseline {r.baselineGeneration}.
        {r.prepared&&<> Original review <code>{r.prepared.operationId}</code>.</>}{r.sources&&<> Chosen sources generation {r.sources.sourceGeneration}, registration {r.sources.registrationGeneration}.</>}</p>}
      {r?.acquisition&&<p>Original inspection <code>{r.acquisition.operationId}</code>, generation <code>{r.acquisition.ownerGeneration}</code>; requirements <code>{r.acquisition.requirementsSha256}</code>. Download/cache-reuse only: {r.acquisition.missing.join(', ')}. Keep compatible: {r.acquisition.compatible.join(', ')||'none observed'}.</p>}
      <label><input type="checkbox" checked={s.acknowledged} disabled={!!controller.consentReason()} onChange={e=>controller.acknowledge(e.target.checked)}/>
        {s.selected==='register-reviewed-sources'?' I acknowledge the vendor licenses and allow one local CLI to make this exact reviewed protected copy.':
          (s.selected==='acquire-missing'||s.selected==='acquire-reviewed-missing')?' I approve this reviewed missing-only public download for one local CLI submission.':
          s.selected==='doctor'?' I allow one local CLI check using this copied draft; later edits will not change it.':' I allow one local CLI submission of this exact inspection.'}</label>
      <button disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>Allow this step once</button>
      {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
      <div className="button-row"><button disabled={!!controller.checkReason()} onClick={()=>void controller.check()}>Check original permission and native status</button>
        <button disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Withdraw permission / request Stop</button></div>
      {s.pending&&<p role="status">The original {s.pending} call is still returning.</p>}
      {s.revoking&&<p role="status">Stop requested; neither that request nor a terminal event proves cleanup.</p>}
      {s.issue&&<p role="alert">{s.issue}</p>}
      {a&&<p>{s.stale?'Earlier context · ':''}{a.status?`${a.status.state} · ${a.status.settlement}`:a.enabled?'One unused permission observed':a.pending?'Original permission retirement is pending':'No unused permission observed'}{remaining!==null?` · up to ${remaining}s remaining`:''}.</p>}
      {commands.length>0&&<><p>Run manually. Keep the request ID printed before submission; after a lost response use that ID with Status/Cancel, not Submit again.</p><pre>{commands.join('\n')}</pre></>}
      {a?.status?.result&&<pre>{JSON.stringify(a.status.result,null,2)}</pre>}
      {a?.status?.state==='complete'&&<p>The original service caller, native operation and history writer returned. A failed doctor check can still be reported. Download means staged only; protected copy is not catalogue selection, compatibility or build readiness.</p>}
      {s.nativeReadJoined&&<p>The separately returned native status also matched. Any next step needs its own existing Desktop review and approval.</p>}
    </section>
  </ProgressiveDisclosure>;
}
