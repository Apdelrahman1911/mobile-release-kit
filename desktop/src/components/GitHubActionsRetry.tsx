import { useId } from 'react';
import { SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { activityLink } from '../githubActivityProtocol.ts';
import { ACTIONS_RETRY_HELP } from '../githubActionsRetryProtocol.ts';
import type { ActionsRetryView, GitHubActionsRetryController } from '../githubActionsRetryController.ts';

// Mounted beside Activity, not inside its replaceable result. The same original
// request/status/Stop/Close controls remain visible after selection/navigation.
export function GitHubActionsRetry({controller,state,compact=false,onShow}: {
  controller:GitHubActionsRetryController;state:ActionsRetryView;compact?:boolean;onShow?:()=>void;
}) {
  const id=useId(),status=state.status,op=status?.operation,consent=controller.currentConsent(),shown=status?.consent;
  const busy=controller.ownerReason(),attention=state.uncertain||state.error!==null||op?.phase==='cleanup-unknown'||
    !!status?.pending.some(row=>!row.acknowledged)||!!op&&['potentially-applied','accepted-unconfirmed','unresolved','advanced-unattributed'].includes(op.effect);
  if(compact&&!busy&&!attention)return null;
  const prepareReason=controller.prepareReason(),retryReason=controller.retryReason();
  const original=op?.target.scope.repository??state.originalRepository;
  const selected=op?.target.selection,link=original&&selected?activityLink(original,'run',selected.runId):null;
  return <section className="card">
    <SectionHeading title={compact?'Original Actions retry':'Retry failed jobs'}
      description={original?`Original repository: ${original}`:'Review a failed workflow run from Activity, then approve its retry.'}><Icon name="github" size={24}/></SectionHeading>
    {!state.native&&<p className="save-note">The native GitHub operation is unavailable in this preview. No retry will be sent.</p>}
    {state.uncertain&&<p className="review-caution" role="alert">The original request or its cleanup is unconfirmed. Keep its task and attempt files. Checking status cannot repeat it, undo a sent retry or clear uncertain cleanup.</p>}
    {state.error&&<p className="review-caution" role="status">{ACTIONS_RETRY_HELP[state.error]}</p>}
    {op&&op.reason!=='none'&&op.reason!==state.error&&<p className="review-caution">{ACTIONS_RETRY_HELP[op.reason]}</p>}
    {op&&<p className="save-note">{op.kind==='retry'?'Retry request':op.kind==='prepare'?'Run review':op.kind==='pending'?'Saved-attempt check':'Read-only reconciliation'} · {op.phase.replaceAll('-',' ')}{selected?` · run ${selected.runId} · observed attempt ${selected.attempt}`:''}</p>}
    {link&&<p><a href={link} target="_blank" rel="noopener noreferrer">Open the original run on GitHub</a></p>}
    {status?.acknowledged&&<p className="save-note">GitHub’s 201 response accepted this retry request. This is not a successful job, build or release, and does not mean every dependent job has finished.</p>}
    {status?.observed&&<p className="save-note">Read back attempt {status.observed.attempt}: {status.observed.status.replaceAll('_',' ')}{status.observed.conclusion?` · ${status.observed.conclusion.replaceAll('_',' ')}`:''}. This is a bounded observation, not attribution after a lost reply or proof of release readiness.</p>}
    <div className="button-row">
      <button type="button" className="button small secondary" disabled={!controller.canCheck()} onClick={()=>controller.checkStatus()}>Check task status</button>
      {(state.pending||op&&op.phase!=='settled')&&<button type="button" className="button small secondary" disabled={!controller.canCancel()||state.cancelling} onClick={()=>controller.cancel()}>Stop original request</button>}
      {shown&&<button type="button" className="button small secondary" disabled={!controller.canDiscard()||state.discarding} onClick={()=>controller.discardReview()}>Close this review</button>}
      {compact&&onShow&&<button type="button" className="button small" onClick={onShow}>Show Actions retry</button>}
    </div>
    {!compact&&<>
      {!shown&&<>
        <p className="save-note">Read a completed failed or timed-out attempt’s jobs in Activity above. Review checks the current account, repository permissions and latest run again; it does not start a workflow.</p>
        {prepareReason&&<p className="save-note" role="status">{prepareReason}</p>}
        <button type="button" className="button" disabled={!!prepareReason} onClick={()=>controller.prepare()}>Review retry for selected run</button>
      </>}
      {shown&&<div className="review-item">
        <h4>{shown.prepared.run.name} · Run {shown.prepared.run.id}</h4>
        <p>{shown.prepared.target.scope.repository} · repository ID {shown.prepared.target.scope.repositoryId}</p>
        <p className="save-note">Account {shown.prepared.accountLogin} · ID {shown.prepared.target.scope.accountId}</p>
        <p className="save-note">Workflow {shown.prepared.run.workflowId} · {shown.prepared.run.workflowPath} · Event {shown.prepared.run.event}</p>
        <p className="save-note">Source {shown.prepared.run.headRepository??'repository not reported'} · {shown.prepared.run.headBranch??'branch not reported'} · {shown.prepared.run.headSha}</p>
        <p className="review-caution">{shown.prepared.confirmation}</p>
        <p className="save-note">Observed attempt {shown.prepared.run.attempt} · {shown.prepared.run.conclusion} · Review expires {shown.expiresAt}. Actions write permission and organization restrictions are still enforced by GitHub.</p>
        {!consent&&<p className="review-caution">This is the retained original review, not current approval. Close it or check the original task; it cannot authorize a new request.</p>}
        <label htmlFor={`${id}-confirm`} className="checkbox-label"><input id={`${id}-confirm`} type="checkbox" checked={state.confirmed} disabled={!consent||state.pending||state.uncertain}
          onChange={e=>controller.setConfirmed(e.target.checked)}/>I approve this run-specific retry, including dependent jobs and possible external workflow effects.</label>
        {retryReason&&<p className="save-note">{retryReason}</p>}
        <button type="button" className="button" disabled={!!retryReason} onClick={()=>controller.retry()}>Retry failed and dependent jobs</button>
      </div>}
      <ProgressiveDisclosure title="Previous attempts and recovery">
        <p>Each retry is recorded before it may be sent. There are at most 32 retained records. We do not delete them automatically, retry a lost request or treat an unchanged attempt as proof that nothing happened.</p>
        <button type="button" className="button small secondary" disabled={!!controller.pendingReason()} onClick={()=>controller.loadPending()}>Read saved retry attempts</button>
        {status?.pending.map(row=><div className="review-item" key={row.prepared.target.selection!.marker}>
          <p>{row.prepared.target.scope.repository} · run {row.prepared.run.id} · observed attempt {row.prepared.run.attempt}</p>
          <p className="save-note">{row.acknowledged?'GitHub acceptance was recorded.':'No verified acceptance receipt.'} {row.claimed?'Sending was claimed; it must not be replayed.':'Local intent is retained; do not bypass it with a new marker.'}</p>
          <button type="button" className="button small secondary" disabled={!!controller.reconcileReason(row.prepared.target.selection!.marker)} onClick={()=>controller.reconcile(row.prepared.target.selection!.marker)}>Check run without retrying</button>
        </div>)}
        <p>An acknowledged older attempt does not block a genuinely newer explicit retry. Read the newer completed failed attempt in Activity and review it separately. An unacknowledged send remains protected even if GitHub shows another attempt.</p>
      </ProgressiveDisclosure>
      <ProgressiveDisclosure title="Permissions, effects and limits">
        <p>This uses GitHub’s supported rerun-failed-jobs API. GitHub may also rerun dependent jobs and uses the original workflow’s privileges and source. A release workflow can publish or modify external services. This is not a sandbox or a separate toolkit release approval.</p>
        <p>GitHub does not offer an atomic expected-attempt precondition here. We recheck immediately before sending, but approval is for this immutable run/workflow/source and GitHub may select its latest attempt when the request arrives.</p>
        <p>No whole-run retry, arbitrary workflow dispatch, job scheduler, debug logging, automatic retry, log download or artifact download is enabled by this action. Fine-grained tokens need Actions write access; organization SSO, repository rules and provider availability still apply.</p>
      </ProgressiveDisclosure>
    </>}
  </section>;
}
