import { useId } from 'react';
import { SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { PLAY_CLEANUP_HELP } from '../githubPlayCleanupProtocol.ts';
import type { GitHubPlayCleanupController, PlayCleanupView } from '../githubPlayCleanupController.ts';

// This panel never owns a workflow or disappears with a replaceable result.
// Its compact copy keeps the same original Check/Stop/Close reachable elsewhere.
export function GitHubPlayCleanup({controller,state,compact=false,onShow}: {
  controller:GitHubPlayCleanupController;state:PlayCleanupView;compact?:boolean;onShow?:()=>void;
}) {
  const id=useId(),status=state.status,op=status?.operation,shown=status?.consent,consent=controller.currentConsent();
  const access=controller.currentAgentAccess(),busy=controller.ownerReason();
  const attention=state.uncertain||state.error!==null||!!status?.pending.length||!!op&&
    ['potentially-applied','acknowledged-unconfirmed','unresolved','observed-unconfirmed'].includes(op.effect);
  if(compact&&!busy&&!attention)return null;
  const original=op?.target.scope.repository??state.originalRepository;
  const prepareReason=controller.prepareReason(),dispatchReason=controller.dispatchReason();
  return <section className="card">
    <SectionHeading title={compact?'Previous Google Play cleanup':'Clean up a previous Google Play draft'}
      description={original?`Original repository: ${original}`:'For a draft left by a previous hosted candidate run. This does not publish a release.'}><Icon name="github" size={24}/></SectionHeading>
    {!state.native&&<p className="save-note">The native cleanup service is unavailable in this preview. No request will be sent.</p>}
    {state.uncertain&&<p className="review-caution" role="alert">The original request or permission response is unconfirmed. Keep this task and its records. Do not send it again. Check status, Stop the original request, or close its permission if available.</p>}
    {state.error&&<p className="review-caution" role="status">{PLAY_CLEANUP_HELP[state.error]}</p>}
    {op&&op.reason!=='none'&&op.reason!==state.error&&<p className="review-caution">{PLAY_CLEANUP_HELP[op.reason]}</p>}
    {op&&<p className="save-note">{op.kind==='prepare'?'Cleanup review':op.kind==='dispatch'?'Workflow request':op.kind==='pending'?'Saved-request check':'Later record check'} · {op.phase.replaceAll('-',' ')}</p>}
    {status?.acknowledged&&<p className="review-caution">GitHub acknowledged the workflow request. This is <strong>not confirmation that the Google Play draft was deleted</strong>, and no workflow run was identified. Do not send another request to find out.</p>}
    {status?.observed&&<p className="save-note">A later read found {status.observed.pendingTuple==='same-unclaimed'?'the same draft with no recorded cleanup claim':
      status.observed.pendingTuple==='same-claimed'?'the same draft with cleanup already claimed':status.observed.pendingTuple==='different'?'a different retained draft':'no matching retained draft'}.
      {' '}This is only a later record observation—not proof of deletion, permission to retry, or release readiness.</p>}
    <div className="button-row">
      <button type="button" className="button small secondary" disabled={!controller.canCheck()} onClick={()=>controller.checkStatus()}>Check task status</button>
      {(state.pending||state.allowing||state.uncertain||op&&op.phase!=='settled')&&<button type="button" className="button small secondary" disabled={!controller.canCancel()||state.cancelling} onClick={()=>controller.cancel()}>Stop original request</button>}
      {shown&&<button type="button" className="button small secondary" disabled={!controller.canDiscard()||state.discarding} onClick={()=>controller.discardReview()}>{shown.agentAllowed||state.allowing?'Revoke cleanup permission':'Close this review'}</button>}
      {compact&&onShow&&<button type="button" className="button small" onClick={onShow}>Show Google Play cleanup</button>}
    </div>
    {!compact&&<>
      {!shown&&<>
        <p className="save-note">Review looks for the one previous draft recorded for the saved project. It checks GitHub and the original candidate source; it does not create a draft, allocate a version or delete anything.</p>
        {prepareReason&&<p className="save-note" role="status">{prepareReason}</p>}
        <button type="button" className="button" disabled={!!prepareReason} onClick={()=>controller.prepare()}>Review previous Google Play draft</button>
      </>}
      {shown&&<div className="review-item">
        <h4>{shown.prepared.target.scope.repository}</h4>
        <p>Account: <strong>{shown.prepared.accountLogin}</strong> · Workflow branch: <strong>{shown.prepared.branch}</strong></p>
        <p className="save-note">Original version {shown.prepared.candidate.baseVersion.name} · build {shown.prepared.candidate.baseVersion.build}. Review expires {shown.expiresAt}. Checking status does not extend it.</p>
        <p className="review-caution">This sends one protected workflow request that may delete the retained Google Play draft. It does not reserve a version, build, sign or publish a release. <strong>Stopping cannot undo a sent request.</strong></p>
        <p className="review-caution">The workflow branch can change after this review. Repository writers can replace its workflow, and the actual run may use a different branch head. Only proceed if you trust this repository and its protected workflow.</p>
        {!consent&&!shown.agentAllowed&&<p className="review-caution">This is the retained original review, not current approval. Check the task or close the review; it cannot authorize another request.</p>}
        {shown.agentAllowed&&<p className="review-caution">This exact cleanup was delegated to the CLI. The app cannot start it as well. Revoke permission above to withdraw it; an already sent request cannot be undone.</p>}
        <label htmlFor={`${id}-confirm`} className="checkbox-label"><input id={`${id}-confirm`} type="checkbox" checked={state.confirmed}
          disabled={!consent||state.pending||state.allowing||state.uncertain} onChange={e=>controller.setConfirmed(e.target.checked)}/>
          I approve this one cleanup request and its workflow effects for the account, repository and branch shown above.</label>
        {dispatchReason&&<p className="save-note">{dispatchReason}</p>}
        <button type="button" className="button" disabled={!!dispatchReason} onClick={()=>controller.dispatch()}>Request draft cleanup</button>
        <ProgressiveDisclosure title="Use an agent or terminal instead" needsAttention={state.allowing||shown.agentAllowed}>
          <p>Allow the same reviewed cleanup once—not general workflow access. This does not start it. The original review expiry still applies; the CLI must explicitly submit it.</p>
          <button type="button" className="button small secondary" disabled={!!controller.allowAgentReason()} onClick={()=>controller.allowAgent()}>Allow this cleanup once in CLI</button>
          {state.allowing&&<p className="save-note">Waiting for the original permission response. Do not allow it again.</p>}
          {access&&<>
            <p className="save-note">Native permission reported {Math.ceil(access.remainingMs/1000)} seconds remaining. Copy this command only if you intend to submit this cleanup:</p>
            <pre><code>{`mrk play-cleanup-submit ${access.projectId} ${access.serviceInstance} ${access.consentId} --reviewed --json`}</code></pre>
            <p>The CLI prints a request ID before sending. Keep that original ID for status or cancellation:</p>
            <pre><code>{`mrk play-cleanup-status ${access.projectId} ${access.serviceInstance} REQUEST_ID --json\nmrk play-cleanup-cancel ${access.projectId} ${access.serviceInstance} REQUEST_ID --json`}</code></pre>
          </>}
          {shown.agentAllowed&&!access&&!state.allowing&&<p className="save-note">This is retained permission information, not a current CLI handoff. Check status or revoke it; do not reconstruct a new request from these details.</p>}
        </ProgressiveDisclosure>
        <ProgressiveDisclosure title="Exact review details">
          <p>{shown.prepared.confirmation}</p>
          <dl className="summary-grid"><div><dt>Candidate</dt><dd><code>{shown.prepared.candidate.candidateId}</code></dd></div>
            <div><dt>Original source</dt><dd><code>{shown.prepared.candidate.source.commit}</code></dd></div>
            <div><dt>Reviewed workflow head</dt><dd><code>{shown.prepared.sourceSha}</code></dd></div>
            <div><dt>Account / repository IDs</dt><dd><code>{shown.prepared.target.scope.accountId} / {shown.prepared.target.scope.repositoryId}</code></dd></div></dl>
        </ProgressiveDisclosure>
      </div>}
      <ProgressiveDisclosure title="Previous cleanup requests" needsAttention={!!status?.pending.length}>
        <p>Read saved requests without sending another workflow. Acknowledgement or a changed record does not prove that cleanup finished. Uncertain attempts stay protected; records are not deleted automatically.</p>
        <button type="button" className="button small secondary" disabled={!!controller.pendingReason()} onClick={()=>controller.loadPending()}>Read saved cleanup requests</button>
        {status?.pending.map(row=><div className="review-item" key={row.prepared.target.marker}>
          <p>{row.prepared.target.scope.repository} · {row.prepared.branch} · original build {row.prepared.candidate.baseVersion.build}</p>
          <p className="save-note">{row.acknowledged?'GitHub acknowledgement was recorded—not deletion.':'No verified acknowledgement was recorded.'} {row.claimed?'Sending was claimed; do not repeat it.':'The previous request remains recorded; do not bypass it with a new request.'}</p>
          <button type="button" className="button small secondary" disabled={!!controller.observeReason(row)} onClick={()=>controller.observe(row)}>Check later record without sending</button>
        </div>)}
      </ProgressiveDisclosure>
      <ProgressiveDisclosure title="What this needs">
        <p>Use the same saved project, verified GitHub account and repository as the previous hosted candidate. The supported candidate workflow, enrolled protected counter and its retained original source must still be available.</p>
        <p>The workflow needs its existing protected cleanup credentials and GitHub permissions. This view never receives a Google Play edit ID, private key or encrypted backup. It cannot clean up an arbitrary draft or publish a release.</p>
      </ProgressiveDisclosure>
    </>}
  </section>;
}
