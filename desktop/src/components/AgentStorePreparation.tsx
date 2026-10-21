import {useSyncExternalStore} from 'react';
import type {StorePreparationController} from '../agentStorePreparationController.ts';
import {storePreparationCommands,storePreparationKinds,type PreparationKind} from '../agentStorePreparation.ts';
const labels:Record<PreparationKind,string>={'android-access':'Android access check','ios-access':'iOS access check','android-candidate':'Android candidate preparation','ios-candidate':'iOS candidate preparation','android-versions':'Current Play versions','ios-versions':'Current App Store versions','paired-versions':'Both current Store inventories'};
export function AgentStorePreparation({controller}:{controller:StorePreparationController}){
 const s=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot),a=s.access;
 const start=!!a?.status?.prepared&&a.status.phase==='prepared',k=a?.selection?.kind??s.selected;
 const mutates=k==='android-access'||k==='android-candidate'||k==='android-versions'||k==='paired-versions';
 const commands=storePreparationCommands(a),seconds=controller.remainingSeconds();
 return <section className="card" aria-label="CLI Store preparation and current inventory">
  <h2>Let the CLI prepare a Store step</h2>
  <p>Use saved inputs and currently assigned credentials. First allow native preparation; after it returns, separately review and allow Start. Nothing runs automatically. Keep this Desktop open.</p>
  <label>Step <select value={s.selected} disabled={!!controller.ownerReason()} onChange={e=>controller.choose(e.target.value as PreparationKind)}>{storePreparationKinds.map(k=><option key={k} value={k}>{labels[k]}</option>)}</select></label>
  <p>{start?'Start approval':'Preparation approval'} · {labels[k]}. {a?.selection&&<>Version {a.selection.savedVersion.name} · build {a.selection.savedVersion.build}.</>}</p>
  {start?<p>{mutates?'Start can create a temporary Google Play edit and delete that same edit. This may invalidate another edit; failed cleanup remains unconfirmed.':'Start reads the selected App Store account using the current native key.'} Candidate preparation may write its original local journal. No upload, promotion, release submission or version reservation is authorized.</p>:<p>This permission only constructs one genuine native Prepared. It does not authorize Store HTTP, a temporary edit or Start.</p>}
  {k==='paired-versions'&&<p>Both requires two current credentials in the same native Version inventory context. Two separate old results are not a paired observation.</p>}
  <label><input type="checkbox" checked={s.acknowledged} disabled={!!controller.consentReason()} onChange={e=>controller.acknowledge(e.target.checked)}/> I approve this one phase and these effects.</label>
  <button disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>{start?'Allow this Start once':'Allow native Prepare once'}</button>
  {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
  <button disabled={!!controller.statusReason()} onClick={()=>void controller.status()}>Check original permission/request</button>
  <button disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Revoke / request Stop</button>
  {(s.pending||s.revoking)&&<p role="status">An original permission caller is still returning. A native event cannot finish it.</p>}
  {s.issue&&<p role="alert">{s.issue}</p>}
  {a&&<p>{s.stale?'Earlier or unconfirmed context · ':''}{a.status?`${a.status.phase} · ${a.status.settlement}`:a.enabled?'One-use permission observed':'No unused permission observed'}{seconds!==null?` · up to ${seconds}s`:''}.</p>}
  {!!commands.length&&<><p>Run manually. Keep the printed request ID after any lost reply; do not resubmit.</p><pre>{commands.join('\n')}</pre></>}
  {a?.status?.result&&<><pre>{JSON.stringify(a.status.result,null,2)}</pre><p>A completed call can still be inconclusive or report failed findings. Current-visible inventories are not historical uniqueness, an atomic cross-store snapshot, a version reservation, or permission to retry.</p></>}
 </section>;
}
