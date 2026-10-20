import { useId } from 'react';
import { SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';
import { REPOSITORY_CREATE_HELP } from '../githubRepositoryCreateProtocol.ts';
import type { GitHubRepositoryCreateController, RepositoryCreateView } from '../githubRepositoryCreateController.ts';

export function GitHubRepositoryCreate({ controller, state, compact = false, onShow }: {
  controller: GitHubRepositoryCreateController; state: RepositoryCreateView; compact?: boolean; onShow?: () => void;
}) {
  const id = useId(), status = state.status, op = status?.operation, review = controller.currentConsent();
  const attention = !!controller.ownerReason() || state.uncertain || !!state.error || !!status?.pending.length ||
    !!op && ['potentially-applied', 'unresolved', 'found-unattributed'].includes(op.effect);
  if (compact && !attention) return null;
  const busy = state.pending || state.observing || state.discarding || state.cancelling;
  const reason = review ? controller.createReason() : controller.prepareReason();
  const settled = op?.phase === 'settled' && !state.pending && !state.uncertain;
  return <section className="card" aria-label="Create a GitHub repository">
    <SectionHeading title="Create a GitHub repository" description="Optional · Make an empty home for this app on GitHub. Uploading your files is a separate task.">
      <Icon name="github" size={24} />
    </SectionHeading>
    {state.originalRepository && (busy || attention) && <p>Original repository: <strong>{state.originalRepository}</strong></p>}
    {op && <p role="status">{op.phase === 'cleanup-unknown' ? 'Cleanup needs attention' : op.phase === 'stopping' ? 'Stopping the original request…' :
      !settled ? 'Waiting for the original task to finish…' : op.effect === 'created-observed' ? 'Repository created and checked' :
      op.kind === 'prepare' && status?.consent ? 'Review ready — nothing created yet' : 'Original check finished'}</p>}
    {state.uncertain && <p className="review-caution" role="alert">The original request is unconfirmed. Keep the app and its files. Check status; do not repeat Create or reconnect to dismiss this warning.</p>}
    {state.error && <p className="review-caution" role="status">{REPOSITORY_CREATE_HELP[state.error]}</p>}
    {op && op.reason !== 'none' && op.reason !== state.error && <p className="review-caution" role="status">{REPOSITORY_CREATE_HELP[op.reason]}</p>}
    <div className="button-row">
      <button type="button" className="button small secondary" disabled={!state.native && !status || state.observing} onClick={() => controller.checkStatus()}>Check status</button>
      {(op && op.phase !== 'settled' || state.pending) && <button type="button" className="button small secondary" disabled={!controller.canCancel() && !state.pending || state.cancelling} onClick={() => controller.cancel()}>Stop original request</button>}
      {status?.consent && <button type="button" className="button small secondary" disabled={!controller.canDiscard()} onClick={() => controller.discardReview()}>Close review</button>}
      {compact && onShow && <button type="button" className="button small" onClick={onShow}>Show repository setup</button>}
    </div>
    {!compact && <>
      <p>Use the <strong>OWNER/REPO</strong> field in Connect GitHub above. OWNER is your verified username or an organization name; REPO is the new repository’s name. A GitHub account can be verified even when this repository does not exist yet.</p>
      <div className="field-label-row"><label htmlFor={`${id}-owner`}>Who will own the repository?</label></div>
      <select id={`${id}-owner`} value={state.ownerKind} disabled={busy} onChange={(e) => controller.setOwnerKind(e.target.value === 'organization' ? 'organization' : 'user')}>
        <option value="user">My verified GitHub account</option><option value="organization">A GitHub organization</option>
      </select>
      <div className="field-label-row"><label htmlFor={`${id}-visibility`}>Who can see it?</label></div>
      <select id={`${id}-visibility`} value={state.visibility} disabled={busy} onChange={(e) => controller.setVisibility(e.target.value === 'public' ? 'public' : 'private')}>
        <option value="private">Private (recommended)</option><option value="public">Public — visible to everyone</option>
      </select>
      {state.visibility === 'public' && <p className="review-caution">Anyone can see a public repository and any files you later upload. Choose Private if you are unsure.</p>}
      {state.ownerKind === 'organization' && <p className="save-note">Find the exact organization name on its GitHub page. Active membership alone does not permit creation; organization rules, SSO and token permissions still apply.</p>}
      {review && <div className="notice notice-info"><div><strong>{review.prepared.target.repository}</strong>
        <p>Verified account: {review.prepared.target.accountLogin} · Owner: {review.prepared.target.repository.split('/')[0]} · {review.prepared.target.visibility === 'private' ? 'Private' : 'Public'}</p>
        <p>The name was not found or was inaccessible. This is not proof of availability or permission; GitHub checks the exact Create request.</p>
        <label className="checkbox-row"><input type="checkbox" checked={state.confirmed} disabled={busy} onChange={(e) => controller.setConfirmed(e.target.checked)} />
          <span>{review.prepared.confirmation}</span></label>
      </div></div>}
      {reason && <p className="save-note" role="status">{reason}</p>}
      <div className="button-row">
        <button type="button" className="button" disabled={!!reason} onClick={() => review ? controller.create() : controller.prepare()}>{review ? 'Create repository' : 'Review new repository'}</button>
        <button type="button" className="button secondary" disabled={!!controller.pendingReason()} onClick={() => controller.loadPending()}>Check previous attempts</button>
      </div>
      {settled && op?.effect === 'created-observed' && status?.observed && <p>Created <a href={status.observed.url} target="_blank" rel="noopener noreferrer">{status.observed.fullName}</a>. Your local files, commits and remote settings are unchanged. Refresh the connection above before a separate setup or upload task.</p>}
      {!!status?.pending.length && <div><h4>Previous attempts</h4><p>Checking an attempt only reads GitHub. It never repeats Create, deletes a repository or uploads files.</p>
        {status.pending.map((p) => <div key={p.prepared.target.marker}><p><strong>{p.prepared.target.repository}</strong> · {p.prepared.target.visibility} ·
          {p.acknowledged ? ' Original creation ID saved; readback still required.' : p.claimed ? ' A request may have been sent.' : ' Saved intent; do not start a replacement.'}</p>
          <button type="button" className="button small secondary" disabled={!!controller.reconcileReason(p.prepared.target.marker)} onClick={() => controller.reconcile(p.prepared.target.marker)}>Check this attempt on GitHub</button>
        </div>)}
      </div>}
      <ProgressiveDisclosure title="Help: permissions and what stays unchanged">
        <p>The existing GitHub session supplies credentials privately. If GitHub refuses creation, review that account’s token permissions in GitHub Settings → Developer settings and any organization membership, repository-creation or SSO rules. Membership and a successful account check do not prove creation permission. This app does not request broader access automatically.</p>
        <p>No README, license, Git ignore file, template, workflow, Git initialization, commit, remote or push is added. No account switch, token entry or automatic retry is performed here. Stopping cannot undo a request already sent.</p>
        <p>If a repository is found without the saved original creation ID, it is not claimed as this app’s successful creation. Preserve the attempt record and inspect GitHub manually.</p>
      </ProgressiveDisclosure>
    </>}
  </section>;
}
