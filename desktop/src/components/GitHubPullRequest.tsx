import { useId } from 'react';
import { SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { PULL_REQUEST_HELP } from '../githubPullRequestProtocol.ts';
import type { GitHubPullRequestController, PullRequestView } from '../githubPullRequestController.ts';

export function GitHubPullRequest({ controller, state, repository = null, baseSuggestion = null, headSuggestion = null, compact = false, onShow }: {
  controller: GitHubPullRequestController; state: PullRequestView; repository?: string|null; baseSuggestion?: string|null; headSuggestion?: string|null;
  compact?: boolean; onShow?: () => void;
}) {
  const id=useId(), status=state.status, op=status?.operation, review=controller.currentConsent();
  const attention=!!controller.ownerReason()||state.uncertain||!!state.error||!!status?.pending.length||!!op&&['potentially-applied','acknowledged-unconfirmed','unresolved','found-unattributed'].includes(op.effect);
  if(compact&&!attention)return null;
  const busy=state.pending||state.observing||state.discarding||state.cancelling||state.uncertain;
  const reason=review?controller.createReason():controller.prepareReason();
  const settled=op?.phase==='settled'&&!state.pending&&!state.uncertain;
  return <section className="card" aria-label="Create a draft pull request">
    <SectionHeading title="Create a draft pull request" description="Ask for feedback on changes already on GitHub. Nothing is pushed or merged here."><Icon name="github" size={24}/></SectionHeading>
    {repository&&!compact&&<p>Selected repository: <strong>{repository}</strong></p>}
    {state.originalRepository&&attention&&<p className="save-note">Original task: <strong>{state.originalRepository}</strong></p>}
    {op&&<p role="status">{op.phase==='cleanup-unknown'?'Cleanup needs attention':op.phase==='stopping'?'Stopping the original request…':!settled?'Waiting for the original task to finish…':
      op.effect==='created-observed'?'Draft pull request created and checked':op.effect==='acknowledged-unconfirmed'?'GitHub acknowledged creation; final details are not confirmed':
      op.effect==='found-unattributed'?'Matching draft found — original creation is not confirmed':op.kind==='prepare'&&status?.consent?'Review ready — nothing created yet':'Original check finished'}</p>}
    {state.uncertain&&<p className="review-caution" role="alert">The original request is unconfirmed. Keep the app and its files. Check status; do not repeat Create or reconnect to dismiss this warning.</p>}
    {state.error&&<p className="review-caution" role="status">{PULL_REQUEST_HELP[state.error]}</p>}
    {op&&op.reason!=='none'&&op.reason!==state.error&&<p className="review-caution">{PULL_REQUEST_HELP[op.reason]}</p>}
    <div className="button-row">
      <button type="button" className="button small secondary" disabled={!controller.canCheck()} onClick={()=>controller.checkStatus()}>Check task status</button>
      {(state.pending||op&&op.phase!=='settled')&&<button type="button" className="button small secondary" disabled={!controller.canCancel()||state.cancelling} onClick={()=>controller.cancel()}>Stop original request</button>}
      {status?.consent&&<button type="button" className="button small secondary" disabled={!controller.canDiscard()} onClick={()=>controller.discardReview()}>Close review</button>}
      {compact&&onShow&&<button type="button" className="button small" onClick={onShow}>Show draft pull request</button>}
    </div>
    {!compact&&<>
      <p className="save-note">Both branches must already exist in this repository on GitHub. Local commits and pushing are separate tasks. A draft PR still may trigger the repository’s existing workflows.</p>
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
        <strong>{review.prepared.target.intent!.head} → {review.prepared.target.intent!.base}</strong>
        <p>{review.prepared.comparison.aheadBy} commit(s) ahead · {review.prepared.comparison.behindBy} behind. Branches can change before the server accepts the request; they are checked again before sending.</p>
        <p>File-name sample (up to four; not a full diff):</p><ul>{review.prepared.comparison.files.map(f=><li key={f.path}>{f.path} · {f.change}</li>)}</ul>
        <p><a href={`https://github.com/${review.prepared.target.scope.repository}/compare/${review.prepared.baseSha}...${review.prepared.headSha}`} target="_blank" rel="noopener noreferrer">Review the full comparison on GitHub</a></p>
        <p><strong>{state.draft.title}</strong></p>{state.draft.body&&<pre className="review-text">{state.draft.body}</pre>}
        <label className="checkbox-row"><input type="checkbox" checked={state.confirmed} disabled={busy} onChange={e=>controller.setConfirmed(e.target.checked)}/><span>{review.prepared.confirmation}</span></label>
      </div></div>}
      {reason&&<p className="save-note" role="status">{reason}</p>}
      <div className="button-row"><button type="button" className="button" disabled={!!reason} onClick={()=>review?controller.create():controller.prepare()}>{review?'Create draft pull request':'Review draft pull request'}</button>
        <button type="button" className="button secondary" disabled={!!controller.pendingReason()} onClick={()=>controller.loadPending()}>Check previous attempts</button></div>
      {settled&&status?.acknowledged&&<p><a href={status.acknowledged.url} target="_blank" rel="noopener noreferrer">Open pull request #{status.acknowledged.number}</a>. {op?.effect==='created-observed'?'Its original creation ID and reviewed details were checked. It is still a draft, not approved or merged.':'The original creation ID was acknowledged, but the final details still need review. Do not create a duplicate.'}</p>}
      {settled&&op?.effect==='found-unattributed'&&status?.observed&&<p><a href={status.observed.url} target="_blank" rel="noopener noreferrer">Inspect matching draft #{status.observed.number}</a>. It is not claimed as this app’s successful creation.</p>}
      {!!status?.pending.length&&<div><h4>Previous attempts</h4><p>Checking an attempt only reads GitHub. It never resends Create, closes a PR or changes your branches.</p>
        {status.pending.map(p=><div key={p.prepared.target.intent!.marker}><p><strong>{p.prepared.target.scope.repository}</strong> · {p.prepared.target.intent!.head} → {p.prepared.target.intent!.base}<br/>
          {p.acknowledged?'Original creation ID saved; readback still required.':p.claimed?'A request may have been sent.':'Saved intent; do not start a replacement.'}</p>
          <button type="button" className="button small secondary" disabled={!!controller.reconcileReason(p.prepared.target.intent!.marker)} onClick={()=>controller.reconcile(p.prepared.target.intent!.marker)}>Check this attempt on GitHub</button></div>)}
      </div>}
      <ProgressiveDisclosure title="Help: branches, permissions and separate actions">
        <p>Find remote branch names in the repository’s Code tab → branch menu. Use names such as main or feature/login, not a URL or refs/heads/ path. This route supports two branches in the same repository; fork PRs remain a separate task.</p>
        <p>The existing verified GitHub account supplies its session privately. Repository write access and Pull requests permissions are required; organization rules and SSO still apply. A successful review is not a permission grant.</p>
        <p>Title and description stay in this local draft and the private original request; saved attempt records contain their fingerprints, not the text. GitHub receives an additional small correlation marker. A matching marker after a lost reply cannot prove which request created the PR.</p>
        <p>Marking a PR ready for review, regular non-draft PR creation, merging and rerunning failed jobs remain separate unfinished actions. None is authorized here. Toolkit publication and release workflows retain their existing independent approvals.</p>
      </ProgressiveDisclosure>
    </>}
  </section>;
}
