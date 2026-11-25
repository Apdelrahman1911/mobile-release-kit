import { useEffect, useId, useState } from 'react';
import type { GitRepositoryPermission } from '../service_git_repository_permission.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import type { GitReadController } from '../gitReadController.ts';
import type { GitLocalController } from '../gitLocalController.ts';
import { GIT_REPOSITORY_PERMISSION_LABELS, gitRepositoryPermissionEffect } from '../gitRepositoryPermissionSelection.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

export function ServiceGitRepositoryAccess({ controller, repository, reader, local, projectName }: {
  controller: GitRepositoryPermission; repository: GitRepositoryController | null; reader: GitReadController; local: GitLocalController; projectName: string;
}) {
  const [state, setState] = useState(controller.getState()), selectId = useId();
  useEffect(() => controller.subscribe(setState), [controller]);
  useEffect(() => {
    const sync = () => controller.syncContext();
    const remove = [repository?.subscribe(sync), reader.subscribe(sync), local.subscribe(sync)]; sync();
    return () => { for (const unsubscribe of remove) unsubscribe?.(); };
  }, [controller, repository, reader, local]);
  const current = controller.getContext(), action = current.project?.action, access = state.access;
  const pending = !!state.pending || state.revokePending;
  return <ProgressiveDisclosure title="Let an AI or CLI agent make one local repository change"
    needsAttention={pending || state.uncertain || !!state.message || access?.enabled === true}>
    <section className="session-review" aria-label="Agent local repository permission">
      <p>Choose an action for <strong>{projectName}</strong>. Use the branch names or upstream settings already entered above; this does not grant general Git access.</p>
      <label htmlFor={selectId}>One permitted action</label>
      <select id={selectId} value={controller.getKind()} disabled={pending} onChange={e => controller.chooseKind(e.target.value)}>
        {Object.entries(GIT_REPOSITORY_PERMISSION_LABELS).map(([kind, label]) => <option key={kind} value={kind}>{label}</option>)}
      </select>
      {action && <p className="review-caution">{gitRepositoryPermissionEffect(action)}</p>}
      {current.reason && <p className="save-note" role="status">{current.reason}</p>}
      <p>Allow lasts at most 15 minutes. The agent must then prepare the native review and explicitly start it once. Nothing runs when you open this panel or choose an action.</p>
      <p className="save-note">No fetch, push, GitHub repository creation, commit, credentials or arbitrary commands. Unsupported layouts are refused by the original Git safety checks.</p>
      <p>Check permission for this selection, then acknowledge again before Allow. Every Check or selection change clears the previous acknowledgement.</p>
      <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={pending || !action || current.blocked}
        onChange={e => controller.acknowledge(e.target.checked)} />I approve exactly this one local action, with the names and target shown here.</label>
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!controller.canAllow() || current.blocked} onClick={() => void controller.allow()}>Allow once</button>
        <button type="button" className="button secondary" disabled={state.revokePending} onClick={() => void controller.revoke()}>Stop permission / task</button>
        <button type="button" className="button secondary" disabled={pending} onClick={() => void controller.status()}>Check permission</button>
      </div>
      <p role="status">{state.uncertain ? 'Permission is unconfirmed. Keep the original Desktop and project files; check or stop the original task. Do not repeat it.' :
        access?.enabled ? `Last checked: allowed once, with up to ${Math.ceil(access.remainingMs / 60000)} minute(s) remaining at that check.` :
          access?.consumed ? 'Permission used. Check the original Git operation above; this does not mean the change or cleanup finished.' : 'Permission is not confirmed active.'}</p>
      {access?.selection && <p>Last checked scope: {gitRepositoryPermissionEffect(access.selection.action)}</p>}
      <p className="save-note">This shares one permission with Stage/Unstage and Commit. Stop in any of these panels revokes it and asks its original task to stop; stopping is not proof of cleanup. Changing fields does not change an issued permission. Only an explicit Allow can replace an unused permission; running or unknown work cannot be replaced.</p>
      <details><summary>CLI instructions and last-checked IDs</summary>
        <p>Use <code>mrk git-repository-scope PROJECT_ID --json</code> for the exact permitted action and Prepare command. Prepare returns a separate Start command after the native review. The CLI cannot choose a different branch or operation.</p>
        {access?.projectId && <p>Permission project <code>{access.projectId}</code> · grant <code>{access.grantId}</code></p>}
        {access?.selection && <p>Selection comparison <code>{access.selection.selectionSha256}</code></p>}
        <p>Keep the service-instance and request IDs after a lost reply. Use that original request’s status or cancel command, not another Prepare or Start. The Desktop can inspect, stop or close its original review; it cannot apply it another way.</p>
        <p>Starting local Git tracking checks for a supported empty repository location; an empty UI is not proof that Git metadata is absent. Cached-upstream updates use previously fetched history, not a fresh remote check.</p>
      </details>
      {state.message && <p role="status" className="review-caution">{state.message}</p>}
    </section>
  </ProgressiveDisclosure>;
}
