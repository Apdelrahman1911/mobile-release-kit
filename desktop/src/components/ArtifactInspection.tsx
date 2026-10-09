import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { ArtifactInspectionController, ArtifactInspectionState } from '../artifactInspection.ts';
import { artifactInspectionOwnerReason } from '../artifactInspection.ts';
import { artifactAvailabilityText, artifactReasonText } from '../artifactInspectionProtocol.ts';
import { ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import type { ArtifactInspectionResult } from '../artifactInspectionTypes.ts';
import { artifactInspectionCheckRows, artifactInspectionHelp, artifactInspectionLimitationText } from '../artifactInspectionProtocol.ts';

// Presentation only. A later native-owner join decides whether a result exists
// and is current; this component never promotes a core reply to settled Status.
export function ArtifactInspectionGuidance() {
  return <div>
    <h3>Inspect files you already have</h3>
    <p>{artifactInspectionHelp.requiredWhen}</p>
    <p>{artifactInspectionHelp.what}</p>
    <p>{artifactInspectionHelp.where}</p>
    <p>{artifactInspectionHelp.format}</p>
    <p>{artifactInspectionHelp.failure}</p>
  </div>;
}
export function ArtifactInspectionResultView({result,historical}:{result:ArtifactInspectionResult;historical:boolean}) {
  return <section aria-label="Artifact byte inspection result">
    <h3>Recorded artifact checks</h3>
    {historical&&<p role="status">Historical result — the project, saved inputs or selection changed. This report is not a current inspection of the new context.</p>}
    <p>Completed observation does not mean every check passed. Bytes, structure, saved-context comparison, signature verification and signer policy are separate facts. No release readiness or source provenance is established.</p>
    <dl>
      <div><dt>Saved configuration used</dt><dd>{result.usedConfig.bytes} bytes · SHA256 <code>{result.usedConfig.sha256}</code></dd></div>
      <div><dt>Saved version used</dt><dd>{result.usedVersion.name} · build {result.usedVersion.build} · {result.usedVersion.bytes} bytes · SHA256 <code>{result.usedVersion.sha256}</code></dd></div>
    </dl>
    <h4>Selected inputs observed</h4>
    <ul>{result.artifacts.map(input=><li key={input.role}>
      <strong>{input.role==='artifact'?result.format.toUpperCase():input.role==='archive'?'Xcode archive':'Debug symbols'}</strong>: {input.label} · {input.kind} · {input.bytes} bytes · {input.entries} {input.entries===1?'entry':'entries'}
      <br/>{input.identity.method==='sha256-file'?'File byte SHA256':'Canonical directory inventory commitment (sha256-tree-v1), not a raw archive-file SHA256'}: <code>{input.identity.sha256}</code>
    </li>)}</ul>
    <h4>Observed metadata — not expected policy</h4>
    <dl>{([
      ['Android application ID',result.observed.applicationId],['Apple bundle ID',result.observed.bundleId],
      ['Version name',result.observed.versionName],['Version build',result.observed.versionBuild],
      ['Signer certificate SHA256',result.observed.signerSha256],['Apple team ID',result.observed.teamId],
    ] as const).map(([label,value])=><div key={label}><dt>{label}</dt><dd>{value===null?'Not observed':<code>{value}</code>}</dd></div>)}</dl>
    <table><caption>Independent checks of the selected bytes</caption><thead><tr><th>Check</th><th>Outcome</th><th>Meaning</th></tr></thead><tbody>
      {artifactInspectionCheckRows(result).map(row=><tr key={row.check}><th scope="row">{row.label}</th><td>{row.statusLabel}</td><td>{row.explanation}</td></tr>)}
    </tbody></table>
    <h4>What this report does not establish</h4>
    <ul>{result.limitations.map(value=><li key={value}>{artifactInspectionLimitationText[value]}</li>)}</ul>
  </section>;
}

export function ArtifactInspection({state,controller,projectName,onHelp,compact=false,onShow}:{
  state:ArtifactInspectionState;controller:ArtifactInspectionController;projectName:string|null;
  onHelp:(help:HelpContent)=>void;compact?:boolean;onShow?:()=>void;
}){
  const field=useId(),owner=artifactInspectionOwnerReason(state),op=state.status?.operation,selection=state.status?.selection,consent=state.consent;
  if(compact&&!owner)return null;
  const controls=<div className="button-row">
    <button type="button" className="button secondary small" disabled={!controller.canCheckStatus()} onClick={()=>void controller.checkStatus()}>{state.readPending?'Reading original status…':'Check original artifact status'}</button>
    {op&&op.phase!=='terminal'&&<button type="button" className="button secondary small" disabled={!controller.canCancel()} onClick={()=>controller.cancel()}>Cancel original inspection</button>}
    {compact&&onShow&&<button type="button" className="button secondary small" onClick={onShow}>Show in Artifacts</button>}
  </div>;
  if(compact)return <section className="notice notice-warning" aria-label="Original artifact inspection owner"><div>
    <strong>Artifact inspection owner retained</strong><p>{owner}</p>{controls}
    {state.pickerPending&&<p>Use Cancel in the original native file picker. Closing this view does not settle it.</p>}
  </div></section>;
  const prepareReason=controller.prepareReason(),runReason=controller.runReason(),discardReason=controller.discardReason();
  return <section className="card" aria-label="Inspect selected artifact bytes">
    <SectionHeading title="Inspect selected artifact bytes" description="Inspect an existing AAB or IPA without building, signing, uploading or performing a Store operation.">
      <HelpButton content={artifactInspectionHelp} onHelp={onHelp}/>
    </SectionHeading>
    <p><strong>Registered project:</strong> {projectName??'Choose a project first'}. Expected identity, version and signer policy come from its saved originals, not artifact metadata or an unsaved draft.</p>
    <p>A file selection has not yet been inspected. A completed report is not release readiness, Store approval or authenticated build provenance.</p>
    <div className="form-field"><label htmlFor={field}>Artifact format</label><select id={field} value={state.format} disabled={controller.pickReason('artifact')!==null}
      onChange={event=>{if(event.target.value==='aab'||event.target.value==='ipa')controller.setFormat(event.target.value);}}>
      <option value="aab">Android App Bundle (.aab)</option><option value="ipa">iOS app package (.ipa)</option>
    </select></div>
    <div className="button-row">{(['artifact','archive','dsyms'] as const).filter(role=>state.format==='ipa'||role==='artifact').map(role=>{
      const reason=controller.pickReason(role),label=role==='artifact'?`Choose ${state.format.toUpperCase()}`:role==='archive'?'Choose optional archive':'Choose optional debug symbols';
      return <div key={role}><button type="button" className="button secondary" disabled={reason!==null} onClick={()=>void controller.pick(role)}>{label}</button>{reason&&<p className="save-note">{reason}</p>}</div>;
    })}</div>
    <p className="save-note">IPA archives and debug symbols can be supported directories or packed ZIPs; symbols require the archive. No path is entered as text.</p>
    {selection&&<ul>{selection.items.map(item=><li key={item.selectionId}>{item.role}: <strong>{item.label}</strong> · {item.kind} · selected, not yet verified</li>)}</ul>}
    {state.pickerPending&&<p role="status">The original native picker or input probe is still active. Use the native panel’s Cancel; other actions stay disabled until original settlement.</p>}
    <div role="group" aria-label="Original artifact inspection status">
      <p>{state.status?artifactAvailabilityText[state.status.availability]:'Waiting for original native status.'}</p>
    </div>
    {!consent&&<><button type="button" className="button" disabled={prepareReason!==null} onClick={()=>void controller.prepare()}>Review artifact inspection</button>
      {prepareReason&&<p className="review-caution">{prepareReason}</p>}</>}
    {consent&&<div className="session-review" role="group" aria-label="Confirm selected artifact inspection">
      <h3>Inspect these selected inputs?</h3>
      <p>Project {projectName??consent.binding.context.projectId}; format {consent.binding.context.format.toUpperCase()}; saved configuration {consent.binding.context.savedConfig.bytes} bytes · SHA256 <code>{consent.binding.context.savedConfig.sha256}</code>.</p>
      <p>The original review expires within five minutes; checking status does not renew it. Byte, structure, expected-context, signature and signer-policy checks remain separate. Missing tools or policy are unavailable, not passed.</p>
      <label><input type="checkbox" checked={consent.acknowledged} onChange={event=>controller.setAcknowledged(consent.operationId,consent.ownerGeneration,event.target.checked)}/>
        I understand this inspects only the selected bytes using saved inputs, does not authenticate source provenance or authorize release, and Cancel waits for original cleanup.</label>
      <div className="button-row"><button type="button" className="button" disabled={runReason!==null} onClick={()=>void controller.start(consent.operationId,consent.ownerGeneration)}>Inspect selected bytes</button></div>
      {runReason&&<p className="review-caution">{runReason}</p>}
    </div>}
    {state.error&&<ErrorNotice error={state.error} title="No new artifact outcome confirmed"/>}
    {state.originalUnconfirmed&&<p role="status">The original action acknowledgement is unconfirmed. Check its status; do not repeat Start.</p>}
    {op&&<div role="status"><strong>Original inspection: {op.phase}{op.outcome?` · ${op.outcome}`:''}</strong><p>{artifactReasonText[op.reason]}</p></div>}
    {owner&&<p className="review-caution">{owner}</p>}{controls}
    <button type="button" className="button secondary small" disabled={discardReason!==null||!selection||selection.phase==='idle'&&!op} onClick={()=>void controller.discard()}>Discard selection and review</button>
    <p className="save-note">Discard does not delete your files. It requires known original settlement. Unknown cleanup keeps the native owner and conflicting actions blocked.</p>
    {op?.result&&<ArtifactInspectionResultView result={op.result} historical={state.historical}/>}
  </section>;
}
