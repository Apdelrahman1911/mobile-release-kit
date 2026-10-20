import { useSyncExternalStore } from 'react';
import type { ReactNode } from 'react';
import type { GitReadController } from '../gitReadController.ts';
import type { GitRepositoryController } from '../gitRepositoryController.ts';
import { GIT_ISSUE_HELP } from '../gitRepositoryProtocol.ts';
import { SectionHeading } from './Common.tsx';
import { GitRepositoryPanel } from './GitRepositoryPanel.tsx';

// A rendering subscriber only. Root retains the one original controller and
// polls its memory-only status while a known native task is active. Navigation
// never closes, retries or replaces that original.
export function LocalGitReadControls({ controller, compact = false, originalProjectName, onShow }: {
  controller: GitReadController; compact?: boolean; originalProjectName?: string; onShow?: () => void;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const active = controller.ownerReason() !== null;
  if (compact && !active && !state.issue) return null;
  const operation = state.original;
  const title = state.uncertain ? 'Local Git read needs attention' : active ? 'Reading local Git files' :
    operation?.phase === 'settled' ? operation.outcome === 'ok' ? 'Local Git read finished' : 'Local Git read did not complete' :
      state.status?.available ? 'Local Git reader available' : 'Check local Git access';
  return <section className={compact ? 'notice notice-info' : 'card'} aria-label="Local Git read status">
    <div><SectionHeading title={title} description="Read-only on this computer. No fetch, push, staging, commit, hooks or build is included." />
      {operation && <p>Original project: <strong>{originalProjectName ?? 'a previously selected project'}</strong>.</p>}
      {state.uncertain && <p className="review-caution" role="alert">The original result or cleanup is unconfirmed. Keep the app and project files; do not repeat the read or reconnect to dismiss it.</p>}
      {state.issue && !state.uncertain && <p className="review-caution" role="status">{state.issue === 'stale-observation'
        ? 'The saved project or local Git files changed. Check local Git access, then refresh changes. Your draft is kept.' : GIT_ISSUE_HELP[state.issue]}</p>}
      {!active && controller.checkReason() && <p className="save-note">{controller.checkReason()}</p>}
      {!active && state.status && !state.status.available && <p className="save-note">This installed session cannot use the protected local Git reader. Use your Git client; no alternate executable is selected.</p>}
      <div className="button-row">
        <button type="button" className={`button ${state.status ? 'secondary' : 'primary'}`} disabled={!controller.canCheck()}
          onClick={() => void controller.checkStatus()}>{state.checking ? 'Checking…' : active ? 'Check original read' : 'Check local Git access'}</button>
        {active && <button type="button" className="button secondary" disabled={!controller.canCancel()}
          onClick={() => void controller.cancel()}>Stop original read</button>}
        {compact && onShow && <button type="button" className="button secondary" onClick={onShow}>Show local changes</button>}
      </div>
      {!state.status && !active && <p className="save-note">Check availability first, then use Refresh changes below. A GitHub connection is not required.</p>}
      {operation && <details><summary>Original read details</summary><p>Task: {operation.action.kind}. Status: {operation.phase}.</p>
        <p>Original operation: <code>{operation.operationId}</code>.</p></details>}
    </div>
  </section>;
}

export function LocalGitRead({ controller, repository, projectName, originalProjectName, localActions }: {
  controller: GitReadController; repository: GitRepositoryController | null; projectName: string; originalProjectName?: string; localActions?: ReactNode;
}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const observation = !state.stale && state.observationProject === repository?.getSnapshot().projectId ? state.observation : null;
  const history = state.historyCurrent && state.historyProject === repository?.getSnapshot().projectId ? state.history : null;
  const tracking = observation?.tracking;
  return <>
    <LocalGitReadControls controller={controller} originalProjectName={originalProjectName} />
    {repository ? <GitRepositoryPanel controller={repository} projectName={projectName} localActions={localActions} /> :
      <p className="save-note">Select a registered project to read its local changes. Existing drafts are kept; a different service session cannot adopt them.</p>}
    {repository && <section className="card" aria-label="Local branch and commit history">
      <SectionHeading title="Local branch and history" description="These are files and references already on this computer, not a fresh check of GitHub." />
      {tracking && <p>{tracking.state === 'complete' ? `${tracking.ahead} ahead · ${tracking.behind} behind the locally stored tracking branch.` :
        tracking.state === 'detached' ? 'This checkout is not on a branch.' : tracking.state === 'unborn' ? 'This branch has no commits yet.' :
          tracking.state === 'not-configured' ? 'No tracking branch is configured.' : 'A complete local branch comparison is unavailable.'}</p>}
      <p className="save-note">No fetch is performed. “Ahead” or “behind” can change after another Git client updates local references.</p>
      <button type="button" className="button secondary" disabled={!observation || controller.readReason(repository.getSnapshot().projectId) !== null}
        onClick={() => { if (observation) void controller.readHistory(repository.getSnapshot().projectId, observation.observation.revision); }}>Read recent local commits</button>
      {history && <details><summary>Previously read commit identifiers ({history.commits.length}{history.hasMore ? '+' : ''})</summary>
        <p>Commit messages, author names, emails and signatures are not included. This is retained local history, not a release or remote-branch approval.</p>
        {history.commits.length ? <ul>{history.commits.map((commit) => <li key={commit.oid}><code>{commit.oid}</code> · {commit.parents.length} parent(s)</li>)}</ul> : <p>No commits were observed.</p>}
        {history.shallow && <p>This is a shallow checkout; earlier history may be missing.</p>}
      </details>}
    </section>}
  </>;
}
