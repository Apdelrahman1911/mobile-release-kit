import { useState } from 'react';
import type { ProjectInitializationController } from '../projectInitializationController.ts';
import { confirmedInitializationResult, currentInitializationApplyBinding, currentInitializationRecoveryBinding, initializationAttemptSettled, initializationRecoveryContextRows } from '../projectInitialization.ts';
import type { ProjectInitializationState } from '../projectInitialization.ts';
import type { GitHubSetupController, GitHubSetupState } from '../githubSetupController.ts';
import type { InitializationView, InitializationRecoveryView } from '../projectInitializationTypes.ts';

function Inventory({view}:{view:InitializationView}) {
  return <>
    <h3>Complete local file plan</h3>
    <p>{view.files.length} files; {view.createDirectories.length} new directories. Existing metadata text is preserved, not displayed or replaced. There is no overwrite option.</p>
    <table><thead><tr><th>Action</th><th>Kind</th><th>Relative path</th><th>Bytes before → after</th></tr></thead><tbody>
      {view.files.map(row=><tr key={row.index}><td>{row.action}</td><td>{row.kind}</td><td><code>{row.path}</code></td><td>{row.beforeBytes??'absent'} → {row.afterBytes}</td></tr>)}
    </tbody></table>
    {view.createDirectories.length>0&&<details><summary>All directories to create</summary><ul>{view.createDirectories.map(path=><li key={path}><code>{path}</code></li>)}</ul></details>}
    <details><summary>Configuration review — redacted, core-validated</summary><pre>{JSON.stringify(view.configurationPreview,null,2)}</pre></details>
    {view.workflows.map(row=><details key={row.id}><summary>{row.path} — complete generated caller</summary><pre>{row.content}</pre></details>)}
    <details><summary>Git ignore additions ({view.ignoreAdditions.length})</summary><pre>{view.ignoreAdditions.join('\n')||'No additions'}</pre></details>
    <p>Toolkit: <code>{view.tooling.repository}</code> at <code>{view.tooling.sha}</code>. Format checked only; no network verification. Bundled templates: {view.templateSet.coreVersion}.</p>
  </>;
}
function RecoveryInventory({view}:{view:InitializationRecoveryView}) {
  return <>
    <h3>Current initialization recovery inspection</h3>
    <p>State: {view.state}. Reason: {view.reason}. {view.action&&<>Proposed action: {view.action}.</>}</p>
    {view.state==='conflict'&&<p>Keep these controls and files. A missing, foreign, unsupported or incomplete descriptor is not permission to delete or reinitialize. This action cannot resolve another transaction domain.</p>}
    {view.state==='recoverable'&&<>
      <h4>Persisted initialization context</h4>
      <p>These exact facts belong to the inspected interrupted initialization, not your current draft. Toolkit coordinates are format-checked only, not network-verified. Configuration contents stay hidden.</p>
      <dl>{initializationRecoveryContextRows(view).map(row=><div key={row.label}><dt>{row.label}</dt><dd><code>{row.value}</code></dd></div>)}</dl>
      <p>{view.files.length===0?'Only the inspected terminal private journal remains; no public files will be changed.':'The complete currently inspected file effects are listed below. No initialization Apply is retried.'}</p>
      <table><thead><tr><th>Effect</th><th>Kind</th><th>Relative path</th></tr></thead><tbody>{view.files.map(row=><tr key={row.index}><td>{row.effect}</td><td>{row.kind}</td><td><code>{row.path}</code></td></tr>)}</tbody></table>
      <p>Private cleanup: {view.privateCleanup.fileCount} files, {view.privateCleanup.directoryCount} directories, inspected owned journal only. Stored configuration is never imported into your draft.</p>
    </>}
  </>;
}
function Confirm({recover,onConfirm,disabled}:{recover:boolean;onConfirm:()=>void;disabled:boolean}) {
  const [confirmed,setConfirmed]=useState(false);
  return <div className="notice notice-warning"><label><input type="checkbox" checked={confirmed} onChange={event=>setConfirmed(event.target.checked)}/> I reviewed the complete plan above and confirm {recover?'only these recovery effects':'these local file creations and ignore additions'}.</label>
    <button type="button" disabled={disabled||!confirmed} onClick={onConfirm}>{recover?'Confirm inspected recovery':'Initialize project'}</button>
  </div>;
}
export function ProjectInitialization({controller,state,setup,setupState,compact=false}:{controller:ProjectInitializationController;state:ProjectInitializationState;setup:GitHubSetupController;setupState:GitHubSetupState;compact?:boolean}) {
  const owner=state.attempt?.projection??state.unknownEvidence??state.status?.active??state.status?.lastTerminal;
  const apply=currentInitializationApplyBinding(state),recover=currentInitializationRecoveryBinding(state);
  const reason=controller.startReason(),recoveryReason=controller.recoveryStartReason();
  const result=confirmedInitializationResult(state);
  const prepared=owner?.prepared;
  const recovery=prepared?.intent==='recover'?prepared.recovery:owner?.checkout?.intent==='recover'?owner.checkout.recovery:null;
  const terminal=owner?.phase==='final'&&owner.nativeFinality==='settled';
  const repoHelp=setupState.help?.inputs.find(row=>row.id==='toolingRepository');
  const shaHelp=setupState.help?.inputs.find(row=>row.id==='toolingSha');
  return <section className="card" aria-label="Project initialization">
    <h2>Initialize release files</h2>
    {!compact&&<>
      <p>Use your current Project settings draft to create the release configuration, four GitHub callers and empty metadata skeleton files together. Review first: selecting a project or reviewing does not install these files. Identical existing files are preserved; differing configuration or callers refuse the entire plan.</p>
      <label>Toolkit repository (owner/repo)<input value={setupState.inputs.toolingRepository} autoComplete="off" autoCapitalize="none" spellCheck={false} onChange={event=>setup.setCoordinate('toolingRepository',event.target.value)}/></label>
      <p>Use the MobileReleaseKit toolkit repository from its GitHub URL, not your selected app repository. These are the same settings used on the GitHub page.{repoHelp&&<> {repoHelp.what}</>}</p>
      <label>Full toolkit commit (40 hexadecimal characters)<input value={setupState.inputs.toolingSha} autoComplete="off" autoCapitalize="none" spellCheck={false} onChange={event=>setup.setCoordinate('toolingSha',event.target.value)}/></label>
      <p>Open that toolkit repository’s commit page and copy its complete 40-character commit SHA. A branch name or shortened SHA is not a pin. The app does not guess or fetch this value.{shaHelp&&<> {shaHelp.what}</>}</p>
      <button type="button" disabled={reason!==null} onClick={()=>controller.start()}>Review initialization</button>
      {reason&&<p role="status">{reason}</p>}
      <button type="button" disabled={recoveryReason!==null} onClick={()=>controller.inspectRecovery()}>Inspect interrupted initialization</button>
      {recoveryReason&&<p>{recoveryReason}</p>}
    </>}
    {state.observationIssue&&<p role="alert">The original initialization status is unavailable or invalid. No success or cleanup is assumed; do not repeat Apply.</p>}
    {(state.nativeBlocked||state.generationLost)&&<p role="alert">Original ownership is unverified or the native document changed. Keep the original evidence; review authority cannot be reattached.</p>}
    {owner&&<div role="status"><p>Original operation: {owner.intent}; {owner.phase}. Native finality: {owner.nativeFinality}.</p>
      {owner.coreOutcome&&<p>Effect: {owner.coreOutcome.effect}; journal: {owner.coreOutcome.journal}; resources: {owner.coreOutcome.resources}; reason: {owner.coreOutcome.reason}.</p>}
      {owner.nativeReason!=='none'&&<p>Native reason: {owner.nativeReason}. A cancellation request or late result does not undo the first failure.</p>}
      {result&&<p>{result==='initialized'?'Initialization confirmed.':'All target files already matched and were preserved.'} This is a local-file result only, not build, signing, GitHub or release readiness. Your draft and baseline were retained, not marked saved: the core pins the toolkit schema in the saved configuration. Use Refresh on Dashboard to observe saved files. Refresh does not replace a draft. To adopt that saved configuration, use Project settings → Discard & load latest observation (or Discard draft changes) and explicitly confirm; this discards unsaved edits, including newer edits, so keep them if needed.</p>}
      {terminal&&!result&&owner.intent==='initialize'&&<p>This attempt did not confirm initialization. Keep the stated effects and recovery evidence; do not infer success from a commit marker alone.</p>}
    </div>}
    {!compact&&owner?.conflict&&<div role="alert"><h3>Existing targets differ — nothing overwritten</h3><ul>{owner.conflict.files.map(row=><li key={row.path}><code>{row.path}</code> ({row.kind}, {row.beforeBytes} bytes)</li>)}</ul><p>Resolve these originals deliberately outside this attempt, then request a fresh review after settlement. Existing contents are not exposed.</p></div>}
    {!compact&&prepared?.intent==='initialize'&&<Inventory view={prepared.view}/>}
    {!compact&&recovery&&<RecoveryInventory view={recovery}/>}
    {!compact&&apply&&<Confirm key={`${apply.sessionId}:${apply.planToken}`} recover={false} disabled={false} onConfirm={()=>controller.apply(apply)}/>}
    {!compact&&recover&&<Confirm key={`${recover.sessionId}:${recover.planToken}`} recover disabled={false} onConfirm={()=>controller.recover(recover)}/>}
    {!initializationAttemptSettled(state.attempt)&&<><button type="button" disabled={Boolean(state.attempt?.closeRequested)||owner?.phase==='unknown'} onClick={()=>controller.requestClose()}>{state.attempt?.applyClaimed?'Request cancellation':'Cancel review'}</button><p>Before Apply, cancellation retires consent and keeps your draft. After Apply it may be too late: wait for this original owner’s outcome; never resend the action.</p></>}
    <button type="button" disabled={state.readPending} onClick={()=>void controller.checkStatus()}>Check original status</button>
  </section>;
}
