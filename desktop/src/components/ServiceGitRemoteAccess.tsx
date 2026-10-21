import { useEffect, useId, useState } from 'react';
import type { GitRemotePermission } from '../service_git_remote_permission.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import type { GitReadController } from '../gitReadController.ts';
import type { GitLocalController } from '../gitLocalController.ts';
import type { GitHubConnectionController } from '../githubConnectionController.ts';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

export function ServiceGitRemoteAccess({ controller, repository, reader, local, connection, projectName }: {
  controller: GitRemotePermission; repository: GitRepositoryController | null; reader: GitReadController; local: GitLocalController;
  connection: GitHubConnectionController; projectName: string;
}) {
  const [state, setState] = useState(controller.getState()), selectId = useId();
  useEffect(() => controller.subscribe(setState), [controller]);
  useEffect(() => { const sync = () => controller.syncContext();
    const removers = [repository?.subscribe(sync), reader.subscribe(sync), local.subscribe(sync), connection.subscribe(sync)]; sync();
    return () => { for (const remove of removers) remove?.(); };
  }, [controller, repository, reader, local, connection]);
  const current = controller.getContext(), selected = current.project?.action, access = state.access, busy = !!state.pending || state.revokePending;
  return <ProgressiveDisclosure title="Let an AI or CLI agent fetch or push once"
    needsAttention={busy || state.uncertain || !!state.message || access?.enabled === true}>
    <section className="session-review" aria-label="Agent remote Git permission">
      <p>Delegate one exact action for <strong>{projectName}</strong>, using the account connected above. Your credential stays in the original Desktop owner.</p>
      <label htmlFor={selectId}>One permitted action</label>
      <select id={selectId} value={controller.getKind()} disabled={busy} onChange={e => controller.chooseKind(e.target.value)}>
        <option value="fetch">Fetch one branch into the local cache</option><option value="push">Push an existing configured branch</option>
        <option value="push-new-branch">Publish this committed branch for the first time</option>
      </select>
      {current.account && <p>{current.account.repository} · account {current.account.login} ({current.account.accountId})</p>}
      {selected?.kind === 'fetch' && <p className="review-caution">Fetch {selected.remote} / {selected.reference}. This downloads Git objects and updates only its tracking reference, not your branch or working files.</p>}
      {selected?.kind === 'push' && <p className="review-caution">Upload committed {selected.localRef} to {selected.remote} / {selected.remoteRef}: {selected.oldOid.slice(0, 12)} → {selected.newOid.slice(0, 12)}. This changes GitHub. Uncommitted files are not uploaded; committed secrets could be.</p>}
      {selected?.kind === 'push-new-branch' && <p className="review-caution">Create {selected.remoteRef} at {selected.newOid.slice(0, 12)} in the selected GitHub repository, only if that branch is absent. All reachable committed history may be uploaded; committed secrets could be included. Any occupied target refuses, even with an identical tip. This does not configure a remote or upstream.</p>}
      {current.reason && <p role="status" className="save-note">{current.reason}</p>}
      <p>The agent must prepare a fresh native review, then explicitly start it once. Allow lasts at most 15 minutes; the original review expires within five minutes. Opening this panel never starts Git or grants access.</p>
      <label className="check-row"><input type="checkbox" checked={state.acknowledged} disabled={busy || current.blocked || !selected}
        onChange={e => controller.acknowledge(e.target.checked)} />I approve this one {controller.getKind() === 'push-new-branch' ? 'create-only branch publication' : controller.getKind() === 'push' ? 'remote upload' : 'branch fetch'}, for the exact account, repository and references shown.</label>
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!controller.canAllow() || current.blocked} onClick={() => void controller.allow()}>Allow once</button>
        <button type="button" className="button secondary" disabled={state.revokePending} onClick={() => void controller.revoke()}>Stop permission / task</button>
        <button type="button" className="button secondary" disabled={busy} onClick={() => void controller.status()}>Check permission</button>
      </div>
      <p role="status">{state.uncertain ? 'Permission is unconfirmed. Keep the original Desktop request; check or stop it, never repeat an unconfirmed send.' : access?.enabled ?
        `Last checked: allowed once, with up to ${Math.ceil(access.remainingMs / 60000)} minute(s) remaining at that check.` : access?.consumed ?
          'Permission consumed. This is not proof that Git or cleanup completed.' : 'Permission is not confirmed active.'}</p>
      {access?.selection && <p>Last checked: {access.selection.action.kind} · {access.selection.account.repository} as {access.selection.account.login} · {access.selection.action.remote ?? 'no configured upstream'} / {access.selection.action.kind === 'fetch' ? access.selection.action.reference : access.selection.action.remoteRef}</p>}
      <p className="save-note">No force push, new upstream, arbitrary URL, credential export or automatic retry. This shares one permission with local Git actions. Stop asks the original task to stop; it does not prove cleanup or undo a remote effect. Unsupported native runtimes stay unavailable.</p>
      <details><summary>CLI instructions and original request IDs</summary>
        <p>Use <code>mrk git-remote-scope PROJECT_ID --json</code> for the exact permitted action. Keep its service-instance and request IDs. After a lost reply, use <code>mrk requests PROJECT_ID --json</code> and the original status/cancel commands, not another Prepare or Start.</p>
        {access?.projectId && <p>Project <code>{access.projectId}</code> · grant <code>{access.grantId}</code></p>}
        {access?.selection && <p>Selection comparison <code>{access.selection.selectionSha256}</code></p>}
        <p>Original terminal effects and retained names are diagnostics, not permission to delete files. Activity is a separate explicit Desktop read; it cannot settle or replay a Push. There is no CLI reconciliation shortcut.</p>
      </details>
      {state.message && <p role="status" className="review-caution">{state.message}</p>}
    </section>
  </ProgressiveDisclosure>;
}
