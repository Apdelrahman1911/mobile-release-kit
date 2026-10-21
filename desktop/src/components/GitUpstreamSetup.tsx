import { useId, useSyncExternalStore } from 'react';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { gitLocalIssueHelp } from '../gitLocalProtocol.ts';
import type { GitUpstreamMutationResult } from '../gitUpstreamProtocol.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

// The existing controllers own the calls, review and drafts. Rendering this
// form makes no native request and never borrows a GitHub connection/grant.
export function GitUpstreamSetup({ controller, repository, originalProjectName }: {
  controller: GitLocalController; repository: GitRepositoryController; originalProjectName?: string;
}) {
  const files = useSyncExternalStore(repository.subscribe, repository.getSnapshot, repository.getSnapshot);
  const writes = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const id = useId(), d = files.upstreamDraft, review = writes.review;
  const prepared = review?.prepared.review.action === 'set-upstream' ? review.prepared.review : null;
  const reason = controller.prepareUpstreamReason(), reviewReason = controller.reviewReason();
  return <ProgressiveDisclosure title="Set this branch’s local upstream" needsAttention={!!prepared}>
    <section aria-label="Local upstream setup">
      <p>Connect this already-committed local branch to a GitHub repository in local Git configuration. This does not sign in, fetch, push or create a repository or remote branch.</p>
      <p className="save-note">Close an active GitHub connection explicitly before this local change. Existing conflicting or partial settings are kept, not repaired or overwritten automatically.</p>
      <form onSubmit={e => { e.preventDefault(); void controller.prepareUpstream(); }}>
        <div className="form-grid">
          <div><label htmlFor={`${id}-remote`}>Remote alias</label><input id={`${id}-remote`} autoComplete="off" maxLength={64} value={d.remote}
            onChange={e => repository.editUpstreamDraft('remote', e.target.value)} /></div>
          <div><label htmlFor={`${id}-repository`}>GitHub owner/repository</label><input id={`${id}-repository`} autoComplete="off" maxLength={140} value={d.repository}
            placeholder="owner/repository" onChange={e => repository.editUpstreamDraft('repository', e.target.value)} /></div>
        </div>
        <p>Use this branch’s existing name on the remote. No tracking commit is invented; Fetch is a separate later action.</p>
        <details><summary>Repository-local identity, only if both fields are missing</summary>
          <p>Leave both blank to preserve an existing valid local name and email. If both are absent, enter both explicitly. These settings apply to this repository, not your account or global Git configuration.</p>
          <div className="form-grid">
            <div><label htmlFor={`${id}-name`}>Local Git name</label><input id={`${id}-name`} autoComplete="off" maxLength={128} value={d.name}
              onChange={e => repository.editUpstreamDraft('name', e.target.value)} /></div>
            <div><label htmlFor={`${id}-email`}>Local Git email</label><input id={`${id}-email`} autoComplete="off" type="email" maxLength={254} value={d.email}
              onChange={e => repository.editUpstreamDraft('email', e.target.value)} /></div>
          </div>
        </details>
        <button type="submit" className="button secondary" disabled={reason !== null}>Review local upstream setup</button>
        {reason && !prepared && <p className="save-note">{gitLocalIssueHelp(reason)}</p>}
      </form>
      {review && prepared && <section className="version-review" aria-label="Review local upstream settings">
        <h3>Upstream for <bdi>{prepared.branch.slice('refs/heads/'.length)}</bdi></h3>
        <p>Original project: <strong>{originalProjectName ?? 'the previously selected project'}</strong>.</p>
        <p>Remote <code><bdi>{prepared.remote}</bdi></code> → <code><bdi>https://github.com/{prepared.repository}.git</bdi></code>.</p>
        {prepared.additions.length ? <><p>Add only these currently absent settings:</p><ul>{prepared.additions.map(a =>
          <li key={a.key}><code><bdi>{a.key}</bdi></code>: <code><bdi>{a.value}</bdi></code></li>)}</ul></> : <p>The approved configuration is already present and stays unchanged.</p>}
        {prepared.missingDirectories.length > 0 && <details open><summary>Create {prepared.missingDirectories.length} missing local metadata directories</summary>
          <ul>{prepared.missingDirectories.map(p => <li key={p}><code><bdi>.git/{p}</bdi></code></li>)}</ul>
          <p>Directories only: no tracking reference, commit or reflog entry is created.</p></details>}
        {reviewReason && <p className="review-caution" role="status">{gitLocalIssueHelp(reviewReason)}</p>}
        {!prepared.unchanged && <>
          <label className="save-confirm-check"><input type="checkbox" checked={review.approved && reviewReason === null} disabled={reviewReason !== null}
            onChange={e => controller.approve(e.target.checked)} />I reviewed these exact local additions. Keep all other configuration, files and refs.</label>
          <button type="button" className="button primary" disabled={reviewReason !== null || !review.approved} onClick={() => void controller.apply()}>Apply this local upstream setup</button>
        </>}
        <p className="save-note">Use the original Check, Stop and Close review controls above. After success, refresh changes explicitly before a separate Fetch. Nothing here confirms remote access or publishes changes.</p>
      </section>}
    </section>
  </ProgressiveDisclosure>;
}
export function GitUpstreamRecovery({ result }: { result: GitUpstreamMutationResult }) {
  if (result.state !== 'recovery-required') return null;
  const steps = { 'not-published': 'a candidate or partial directory setup may be retained', 'directories-returned': 'the reviewed directory creation returned', 'config-returned': 'the local configuration replacement returned' };
  return <div className="review-caution" role="status"><p>Last reported step: {steps[result.effectPhase]}. This is not closure or permission to repeat the change.</p>
    <p>Keep the original Git metadata and candidate. Check the original action before manual recovery; no directories or settings are rolled back or deleted automatically.</p>
    {result.retainedCandidate && <p>The original private candidate is retained; its internal path is not displayed or adopted.</p>}
    {result.retainedPaths.length > 0 && <details><summary>Keep these relative metadata paths</summary><ul>{result.retainedPaths.map(p =>
      <li key={p}><code><bdi>{p}</bdi></code></li>)}</ul></details>}
  </div>;
}
