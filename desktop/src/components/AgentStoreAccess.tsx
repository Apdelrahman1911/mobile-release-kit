import { useSyncExternalStore } from 'react';
import type { AgentStoreAccessController } from '../agentStoreAccessController.ts';
import { storeCommands } from '../agentStoreAccess.ts';
import type { StoreKind } from '../agentStoreAccess.ts';
import { storeEffectText, storeStepLabel } from '../agentStoreRelease.ts';
export function AgentStoreAccess({controller}:{controller:AgentStoreAccessController}) {
  const state=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const r=state.review,access=state.access,commands=storeCommands(access),seconds=controller.remainingSeconds();
  return <section className="card" aria-label="Local CLI Store permission">
    <h2>Let a local CLI run one reviewed Store step</h2>
    <p>Uses the same native Store review, credentials, original cleanup and history. Each exact mode needs its own one-use approval. An access/prepare grant cannot authorize an upload, promotion, submission or recovery check.</p>
    <label>Step <select value={state.selected} disabled={!!controller.ownerReason()} onChange={e=>controller.choose(e.target.value as StoreKind)}>
      {(['access-check','candidate-prepare','execute','reconcile'] as const).map(kind=><option key={kind} value={kind}>{storeStepLabel(kind)}</option>)}
    </select></label>
    {r&&<p>{r.platform==='ios'?'iOS':'Android'} · Version {r.savedVersion.name} · Build {r.savedVersion.build}. Native review <code>{r.operationId}</code>{r.candidate&&<> · Candidate <code>{r.candidate.operationId}</code></>}.</p>}
    {r&&<div className="notice"><strong>{r.release?.mode??storeStepLabel(r.kind)}</strong><p>{storeEffectText(r)}</p>
      {r.release&&<p>Intent <code>{r.release.intentSha256}</code>{r.release.stageOperationId&&<> · Stage <code>{r.release.stageOperationId}</code></>}{r.release.basis&&<> · Basis receipt <code>{r.release.basis.receiptSha256}</code></>}.</p>}</div>}
    <p>First use the original Store panel’s Review button. Allow authorizes one submission of exactly that review before its native expiry; it does not start it. Execute may perform the reviewed Store mutation; Reconcile performs only its separately reviewed mode. Keep Desktop open. No automatic retry, and no target/receipt is proof of public release.</p>
    <label><input type="checkbox" checked={state.acknowledged} disabled={!!controller.consentReason()} onChange={e=>controller.acknowledge(e.target.checked)}/> I allow one local CLI submission of this exact Store mode and its displayed effects.</label>
    <button disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>Allow this Store step once</button>
    {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
    <button disabled={!!controller.statusReason()} onClick={()=>void controller.status()}>Check original CLI permission/status</button>
    <button disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Revoke permission / request Stop</button>
    {state.pending&&<p role="status">The original permission caller is still returning.</p>}
    {state.revoking&&<p role="status">Waiting for original revocation. This does not prove the Store operation stopped.</p>}
    {state.issue&&<p role="alert">{state.issue}</p>}
    {access&&<p>{state.stale?'Earlier or unconfirmed context · ':''}{access.status?`${access.status.state} · ${access.status.settlement}`:access.enabled?'One-use permission observed':'No unused permission observed'}{seconds!==null?` · up to ${seconds}s remaining`:''}.</p>}
    {commands.length>0&&<><p>Run manually in your terminal. Keep the request ID printed before submission; after a lost response, use Status/Cancel for that ID, not Submit again.</p><pre>{commands.join('\n')}</pre></>}
    {access?.review?.release&&<p>Retained request mode: {access.review.release.mode}. {storeEffectText(access.review)}</p>}
    {access?.status?.result&&(access.review?.kind==='execute'||access.review?.kind==='reconcile')&&<pre>{JSON.stringify(access.status.result,null,2)}</pre>}
    {access?.status?.state==='complete'&&<p>The same caller, native owner and service-history writer returned. Access findings may still fail; preparation is not upload approval. Execute receipts retain their actual tester/review/draft state, not public availability. Reconcile/readiness/recovery records do not establish the earlier execution’s finality or authorize retry.</p>}
  </section>;
}
