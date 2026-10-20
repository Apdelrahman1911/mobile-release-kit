import { useEffect, useState } from 'react';
import type { GitCommitPermission } from '../service_git_commit_permission.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';

export function ServiceGitCommitAccess({ controller, repository }: { controller: GitCommitPermission; repository: GitRepositoryController }) {
  const [state, setState] = useState(controller.getState());
  useEffect(() => controller.subscribe(setState), [controller]);
  useEffect(() => { controller.syncContext(); return repository.subscribe(() => controller.syncContext()); }, [controller, repository]);
  const access = state.access;
  return <section className="session-review" aria-label="Agent local commit permission">
    <h3>Let an AI or CLI agent commit once</h3>
    <p>Check Git changes, then review the commit message and author entered above. Allow gives the agent 15 minutes to prepare and start one local commit using exactly that draft.</p>
    <p>Editing those fields after Allow does not change the approved draft. Use Stop or explicitly Allow a replacement.</p>
    <p className="review-caution">This commits every staged change, including files staged by another Git client—not just selected rows. No hooks, signing, branch switching, push, credentials, or arbitrary command permission is granted. The existing native Git safety checks still apply.</p>
    <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={!!state.pending || state.revokePending}
      onChange={e => controller.acknowledge(e.target.checked)} />I approve the whole staged index and the exact message and author above.</label>
    <div className="button-row">
      <button className="button secondary" disabled={!controller.canAllow()} onClick={() => void controller.allow()}>Allow</button>
      <button className="button secondary" disabled={state.revokePending} onClick={() => void controller.revoke()}>Stop</button>
      <button className="button secondary" disabled={!!state.pending || state.revokePending} onClick={() => void controller.status()}>Refresh</button>
    </div>
    <p>{access?.enabled ? 'Last checked: one commit allowed.' : access?.consumed ? 'Permission used. Follow the original Git operation above.' : 'Commit permission is not confirmed active.'} This shares one permission with Stage/Unstage. Stop in either panel revokes that shared permission and asks its running task to stop. Only an explicit Allow replaces an unused permission; running or unknown work cannot be replaced.</p>
    <details><summary>CLI details</summary>
      <p><code>mrk git-commit-scope PROJECT_ID --json</code> shows the approved paths, never the private message or author. Prepare returns the original review and separate one-use Start command. Keep its instance/request IDs after a lost reply; do not repeat the commit.</p>
      {access?.projectId && <p>Project <code>{access.projectId}</code> · {access.selection?.summary.pathCount} staged paths</p>}
      <p>The Desktop Git panel can observe, stop, or close an agent review, but cannot apply it another way. Stop is a request, not proof of mutation or cleanup. No native availability is inferred from this permission.</p>
    </details>
    {state.message && <p role="status" className="review-caution">{state.message}</p>}
  </section>;
}
