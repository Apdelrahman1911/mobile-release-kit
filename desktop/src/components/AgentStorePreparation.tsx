import {useSyncExternalStore} from 'react';
import type {StorePreparationController} from '../agentStorePreparationController.ts';
import {storePreparationCommands,storePreparationKinds,storePreparationSelection,storePreparationStage,storePreparationExecutesCandidate,type PreparationKind} from '../agentStorePreparation.ts';
const labels:Record<PreparationKind,string>={'android-access':'Android access check','ios-access':'iOS access check','android-candidate':'Android candidate preparation','ios-candidate':'iOS candidate preparation','android-versions':'Current Play versions','ios-versions':'Current App Store versions','paired-versions':'Both current Store inventories',
 'android-external-testing':'Play external-testing preparation','ios-external-testing':'TestFlight external-testing preparation','android-production-submit':'Play production-draft preparation','ios-production-submit':'App Store submission preparation',
 'android-candidate-upload':'Upload reviewed Play candidate','ios-candidate-upload':'Upload reviewed TestFlight candidate'};
export function AgentStorePreparation({controller}:{controller:StorePreparationController}){
 const s=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot),a=s.access;
 const start=!!a?.status?.prepared&&a.status.phase==='prepared',k=a?.selection?.kind??s.selected;
 const mutates=k.startsWith('android-')||k==='paired-versions',later=storePreparationStage(k),upload=storePreparationExecutesCandidate(k);
 const selected=a?.selection??(s.input?storePreparationSelection(s.input):null);
 const captured=!s.stale&&!s.unknown?s.input?.prepare:null;
 const commands=storePreparationCommands(a),seconds=controller.remainingSeconds();
 return <section className="card" aria-label="CLI Store preparation and current inventory">
  <h2>Let the CLI prepare a Store step</h2>
  <p>Use saved inputs and currently assigned credentials. First allow native preparation; after it returns, separately review and allow Start. Nothing runs automatically. Keep this Desktop open.</p>
  <label>Step <select value={s.selected} disabled={!!controller.ownerReason()} onChange={e=>controller.choose(e.target.value as PreparationKind)}>{storePreparationKinds.map(k=><option key={k} value={k}>{labels[k]}</option>)}</select></label>
  <p>{start?'Start approval':'Preparation approval'} · {labels[k]}. {selected&&<>Version {selected.savedVersion.name} · build {selected.savedVersion.build}.</>}</p>
  {later&&selected?.later&&selected.candidate&&<>
   <p>Prepare only · {later}. Candidate <code>{selected.candidate.operationId}</code> · SHA-256 <code>{selected.candidate.sha256}</code>.</p>
   <p>Compared predecessor <code>{selected.later.predecessorOperationId}</code> · receipt SHA-256 <code>{selected.later.predecessorReceiptSha256}</code>. The original native worker must authenticate this lineage and the saved source again; displayed history does not establish earlier native finality.</p>
   {k.startsWith('ios-')&&<p>Requires the current App Store key, review contact, operation commitment, and the saved policy's demo assignment when required. Secret values are not sent to the CLI.</p>}
  </>}
  {upload&&selected?.execute&&selected.candidate&&<>
   <p>Candidate <code>{selected.candidate.operationId}</code> · SHA-256 <code>{selected.candidate.sha256}</code> · prepared intent SHA-256 <code>{selected.execute.intentSha256}</code>. Target: {k.startsWith('ios-')?'internal TestFlight':'Play internal testing'}.</p>
   {captured&&'recordId' in captured&&<p>Selected credential <code>{captured.recordId}</code> · revision {captured.recordRevision} · native context revision {captured.credentialContextRevision}. These references are compared again by the original native owner; no secret is sent to the CLI.</p>}
  </>}
  {start?upload?<p>{k.startsWith('ios-')?'Start uploads the reviewed signed IPA for internal TestFlight processing.':'Start uploads the reviewed signed AAB and commits its Play internal-testing release. It can create a temporary Play edit, invalidate another edit, and leave cleanup unconfirmed on failure.'} This writes the original local execution journal. No rebuild, signing, public release or version reservation is authorized. A lost reply or uncertain outcome must not be retried; keep the same request and native evidence.</p>:<p>{mutates?'Start can create a temporary Google Play edit and delete that same edit. This may invalidate another edit; failed cleanup remains unconfirmed.':'Start reads the selected App Store account using the current native key.'} Candidate or later-stage preparation may write its original local journal. No upload, promotion, release submission or version reservation is authorized.</p>:<p>This permission only constructs one genuine native Prepared. It does not authorize Store HTTP, a temporary edit or Start.{upload?' After that original Prepare returns, a fresh Check and separate Start confirmation are required before any upload.':later&&mutates?' A separate Start would permit a temporary Play edit and its cleanup; it may invalidate another edit, and failed cleanup remains unconfirmed.':''}</p>}
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
