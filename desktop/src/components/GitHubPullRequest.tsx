import { pullRequestMode, pullRequestModeLabel } from '../githubPullRequestMode.ts';
import { useId } from 'react';
import type { ReactNode } from 'react';
import { BROWSER_HELP } from '../githubPullRequestManagement.ts';
import { SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { PULL_REQUEST_HELP } from '../githubPullRequestProtocol.ts';
import type { GitHubPullRequestController, PullRequestView } from '../githubPullRequestController.ts';

export function GitHubPullRequest({ controller, state, repository = null, baseSuggestion = null, headSuggestion = null, compact = false, onShow, management }: {
  controller: GitHubPullRequestController; state: PullRequestView; repository?: string|null; baseSuggestion?: string|null; headSuggestion?: string|null;
  compact?: boolean; onShow?: () => void; management?:ReactNode;
}) {
  const id=useId(), status=state.status, op=status?.operation, review=controller.currentConsent();
  const mode=pullRequestMode(state.draft), modeLabel=pullRequestModeLabel(state.draft);
  const attention=!!controller.ownerReason()||state.uncertain||!!state.error||!!status?.pending.length||!!op&&['potentially-applied','acknowledged-unconfirmed','unresolved','found-unattributed'].includes(op.effect);
  if(compact&&!attention)return null;
  const busy=state.browserPending||state.pending||state.observing||state.discarding||state.cancelling||state.uncertain;
  const reason=review?controller.createReason():controller.prepareReason();
  const settled=op?.phase==='settled'&&!state.pending&&!state.uncertain;
  return <section className="card" aria-label="Create a pull request">
    <SectionHeading title="Create a pull request" description="Ask for feedback on changes already on GitHub. Nothing is pushed or merged here."><Icon name="github" size={24}/></SectionHeading>
    {repository&&!compact&&<p>Selected repository: <strong>{repository}</strong></p>}
    {state.originalRepository&&attention&&<p className="save-note">Original task: <strong>{state.originalRepository}</strong></p>}
    {op&&<p role="status">{op.phase==='cleanup-unknown'?'Cleanup needs attention':op.phase==='stopping'?'Stopping the original request…':!settled?'Waiting for the original task to finish…':
      op.effect==='created-observed'?'Pull request created and checked':op.effect==='acknowledged-unconfirmed'?'GitHub acknowledged creation; final details are not confirmed':
      op.effect==='closed-confirmed'?'Earlier acknowledged pull request confirmed closed':op.effect==='found-unattributed'?'Matching pull request found — original creation is not confirmed':op.kind==='prepare'&&status?.consent?'Review ready — nothing created yet':'Original check finished'}</p>}
    {state.uncertain&&<p className="review-caution" role="alert">The original request is unconfirmed. Keep the app and its files. Check status; do not repeat Create or reconnect to dismiss this warning.</p>}
    {state.error&&<p className="review-caution" role="status">{PULL_REQUEST_HELP[state.error]}</p>}
    {op&&op.reason!=='none'&&op.reason!==state.error&&<p className="review-caution">{PULL_REQUEST_HELP[op.reason]}</p>}    {state.browserPending&&<p role="status">{BROWSER_HELP.requesting}</p>}
    <div className="button-row">
      <button type="button" className="button small secondary" disabled={!controller.canCheck()} onClick={()=>controller.checkStatus()}>Check task status</button>
      {(state.pending||op&&op.phase!=='settled')&&<button type="button" className="button small secondary" disabled={!controller.canCancel()||state.cancelling} onClick={()=>controller.cancel()}>Stop original request</button>}
      {status?.consent&&<button type="button" className="button small secondary" disabled={!controller.canDiscard()} onClick={()=>controller.discardReview()}>Close review</button>}
      {compact&&onShow&&<button type="button" className="button small" onClick={onShow}>Show pull request</button>}
    </div>
    {!compact&&<>
      <p className="save-note">Both branches must already exist in this repository on GitHub. Local commits and pushing are separate tasks. A draft PR still may trigger the repository’s existing workflows.</p>
      <label htmlFor={`${id}-mode`}>Creation mode</label>
      <select id={`${id}-mode`} value={mode} disabled={busy} onChange={e=>controller.setCreationMode(e.target.value==='ready-for-review'?'ready-for-review':'draft')}>
        <option value="draft">Draft — ask for early feedback</option>
        <option value="ready-for-review">Ready for review — request normal review</option>
      </select>
      <p className="save-note">Ready-for-review creation may notify reviewers and run existing workflows. Neither mode approves or merges changes. This does not convert an existing draft.</p>
      <div className="form-grid">
        <div className="form-field"><label htmlFor={`${id}-base`}>Base branch — where changes should go</label>
          <input id={`${id}-base`} value={state.draft.base} maxLength={200} disabled={busy} autoComplete="off" spellCheck={false} placeholder="For example: main" onChange={e=>controller.setDraft('base',e.target.value)}/>
          <p className="save-note">Usually the repository’s main development branch.</p>
          {baseSuggestion&&<button type="button" className="button small secondary" disabled={busy} onClick={()=>controller.setDraft('base',baseSuggestion)}>Use last-read default: {baseSuggestion}</button>}
        </div>
        <div className="form-field"><label htmlFor={`${id}-head`}>Head branch — your changes</label>
          <input id={`${id}-head`} value={state.draft.head} maxLength={200} disabled={busy} autoComplete="off" spellCheck={false} placeholder="For example: feature/login" onChange={e=>controller.setDraft('head',e.target.value)}/>
          <p className="save-note">Choose a different branch that you have already pushed.</p>
          {headSuggestion&&<button type="button" className="button small secondary" disabled={busy} onClick={()=>controller.setDraft('head',headSuggestion)}>Use last-read local branch: {headSuggestion}</button>}
        </div>
      </div>
      {(baseSuggestion||headSuggestion)&&<p className="save-note">Suggestions are not fresh remote checks. Review checks the selected branches on GitHub; it never pushes them.</p>}
      <label htmlFor={`${id}-title`}>Title</label><input id={`${id}-title`} value={state.draft.title} maxLength={256} disabled={busy} autoComplete="off" placeholder="Briefly describe the change" onChange={e=>controller.setDraft('title',e.target.value)}/>
      <label htmlFor={`${id}-body`}>Description (optional)</label><textarea id={`${id}-body`} value={state.draft.body} maxLength={4096} disabled={busy} rows={4} onChange={e=>controller.setDraft('body',e.target.value)}/>
      <p className="save-note">Explain what changed and how you tested it. This exact text will be sent to GitHub only after Create. Do not include tokens, passwords or private signing material.</p>
      {review&&<div className="notice notice-info"><div>
        <strong>{pullRequestModeLabel(review.prepared.target.intent!)} · {review.prepared.target.intent!.head} → {review.prepared.target.intent!.base}</strong>
        <p>{review.prepared.comparison.aheadBy} commit(s) ahead · {review.prepared.comparison.behindBy} behind. Branches can change before the server accepts the request; they are checked again before sending.</p>
        <p>File-name sample (up to four; not a full diff):</p><ul>{review.prepared.comparison.files.map(f=><li key={f.path}>{f.path} · {f.change}</li>)}</ul>
        {!management&&<p className="save-note">Copy this comparison address into your browser: <span className="review-text">{`https://github.com/${review.prepared.target.scope.repository}/compare/${review.prepared.baseSha}...${review.prepared.headSha}`}</span></p>}
        <p><strong>{state.draft.title}</strong></p>{state.draft.body&&<pre className="review-text">{state.draft.body}</pre>}
        <label className="checkbox-row"><input type="checkbox" checked={state.confirmed} disabled={busy} onChange={e=>controller.setConfirmed(e.target.checked)}/><span>{review.prepared.confirmation}</span></label>
      </div></div>}
      {management}
      {reason&&<p className="save-note" role="status">{reason}</p>}
      <div className="button-row"><button type="button" className="button" disabled={!!reason} onClick={()=>review?controller.create():controller.prepare()}>{review?`Create ${modeLabel.toLowerCase()} pull request`:`Review ${modeLabel.toLowerCase()} pull request`}</button>
        <button type="button" className="button secondary" disabled={!!controller.pendingReason()} onClick={()=>controller.loadPending()}>Check previous attempts</button></div>
      {!management&&settled&&status?.acknowledged&&<p>Pull request #{status.acknowledged.number}: <span className="review-text">{status.acknowledged.url}</span>. {op?.effect==='created-observed'?'Its original creation ID and selected creation mode were checked. It is not approved or merged.':'The original creation ID was acknowledged, but the final details still need review. Do not create a duplicate.'}</p>}
      {!management&&settled&&op?.effect==='found-unattributed'&&status?.observed&&<p>Matching pull request #{status.observed.number}: <span className="review-text">{status.observed.url}</span>. It is not claimed as this app’s successful creation.</p>}
      {!!status?.pending.length&&<div><h4>Previous attempts</h4><p>Checking an attempt only reads GitHub. It never resends Create, closes a PR or changes your branches.</p>
        {status.pending.map(p=><div key={p.prepared.target.intent!.marker}><p><strong>{p.prepared.target.scope.repository}</strong> · {pullRequestModeLabel(p.prepared.target.intent!)} · {p.prepared.target.intent!.head} → {p.prepared.target.intent!.base}<br/>
          {p.closed?`Previously confirmed closed${p.closed.merged?' after merging':''}. A new explicit review still checks for an open PR.`:p.acknowledged?'Original creation ID saved; readback still required.':p.claimed?'A request may have been sent.':'Saved intent; do not start a replacement.'}</p>
          <button type="button" className="button small secondary" disabled={!!controller.reconcileReason(p.prepared.target.intent!.marker)} onClick={()=>controller.reconcile(p.prepared.target.intent!.marker)}>Check this attempt on GitHub</button>
          <details><summary>Advanced: select this original attempt for CLI Reconcile</summary>
            <p>Read saved attempts through this original panel or its CLI Pending action first. Selecting does not read GitHub, resend, or grant permission.</p>
            <button type="button" className="button small secondary" disabled={!controller.canSelectRecordForAgent(p.prepared.target.intent!.marker)} onClick={()=>controller.selectRecordForAgent(p.prepared.target.intent!.marker)}>Use this returned record</button>
            {state.agentReconcileMarker===p.prepared.target.intent!.marker&&<p>Selected for a separate explicit CLI Reconcile permission.</p>}
          </details></div>)}
      </div>}
      <ProgressiveDisclosure title="Help: branches, permissions and separate actions">
        <p>Find remote branch names in the repository’s Code tab → branch menu. Use names such as main or feature/login, not a URL or refs/heads/ path. This route supports two branches in the same repository; fork PRs remain a separate task.</p>
        <p>The existing verified GitHub account supplies its session privately. Repository write access and Pull requests permissions are required; organization rules and SSO still apply. A successful review is not a permission grant.</p>
        <p>Title and description stay in this local draft and the private original request; saved attempt records contain their fingerprints, not the text. GitHub receives an additional small correlation marker. A matching marker after a lost reply cannot prove which request created the PR.</p>
        <p>Converting an existing draft to ready-for-review, submitting reviews and merging are not supported here. Failed-job retry has its own separate review; none is authorized by creating a PR. Toolkit publication and release workflows retain their existing independent approvals.</p>
      </ProgressiveDisclosure>
    </>}
  </section>;
}
