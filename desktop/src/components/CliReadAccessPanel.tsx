import { useId, useSyncExternalStore } from 'react';
import { CLI_READ_ACCESS_SCOPE } from '../cliReadAccess.ts';
import { CLI_READ_ACCESS_ISSUE_HELP } from '../cliReadAccessController.ts';
import type { CliReadAccessController } from '../cliReadAccessController.ts';
import { Badge, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

// Root mounts this under Advanced settings and retains the controller when the
// panel is hidden. Opening the panel never grants, renews or sends any request.
export function CliReadAccessPanel({ controller }: { controller: CliReadAccessController }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const id = useId(), summary = controller.summary();
  const allowReason = controller.allowReason(), checkReason = controller.statusReason(), revokeReason = controller.revokeReason();
  return <section className="card" aria-labelledby={`${id}-title`} aria-busy={state.pendingCount > 0}>
    <div id={`${id}-title`}><SectionHeading title="CLI / AI access" description="Let a local command-line or AI tool read limited saved information from this running app." /></div>
    <p>{CLI_READ_ACCESS_SCOPE}</p>
    <p><strong>Allow only tools you trust.</strong> Keep this app open. Permission lasts up to one hour and is not restored after the app closes.</p>
    <div className="button-row" role="status" aria-live="polite"><Badge tone={summary.tone}>{summary.title}</Badge></div>
    <p className="save-note">{summary.detail}</p>
    {state.pendingCount > 0 && <p className="context-refresh-note" role="status">
      {state.revoking ? 'Turning off access…' : state.pendingRetired ? 'Finishing an earlier access request…' : state.pending === 'allow' ? 'Allowing the selected project…' : 'Checking access…'}
      {state.revoking && state.pending && ' The earlier request is still finishing; its reply cannot turn access back on in this panel.'}
    </p>}
    {state.issue && <div className="notice notice-warning" role="alert"><Icon name="info" /><div><strong>Access is not confirmed</strong><p>{CLI_READ_ACCESS_ISSUE_HELP[state.issue]}</p></div></div>}
    <div className="button-row">
      <button type="button" className="button secondary" disabled={checkReason !== null} aria-describedby={`${id}-check-reason`} onClick={() => void controller.check()}>
        <Icon name="refresh" size={16} className={state.pending === 'status' ? 'spin' : ''} />Check access
      </button>
      <button type="button" className="button primary" disabled={allowReason !== null} aria-describedby={`${id}-allow-scope ${id}-allow-reason`} onClick={() => void controller.allowSelected()}>
        Allow selected project for 1 hour
      </button>
      <button type="button" className="button secondary" disabled={revokeReason !== null} aria-describedby={`${id}-revoke-reason`} onClick={() => void controller.revoke()}>
        Turn off access
      </button>
    </div>
    <p id={`${id}-allow-scope`} className="save-note">{state.selectedProject ? <>Selected project: <strong><bdi>{state.selectedProject.name}</bdi></strong>. </> : 'No native project selected. '}
      Allowing it replaces permission for every previously permitted project. Turning off access applies to all permitted projects, not just this selection.</p>
    <p id={`${id}-allow-reason`} className="toolbar-reason">{allowReason ?? 'This explicit permission allows reads only. It does not connect a tool or approve any other action.'}</p>
    <span id={`${id}-check-reason`} className="sr-only">{checkReason ?? 'Read the current permission without changing it.'}</span>
    <span id={`${id}-revoke-reason`} className="sr-only">{revokeReason ?? 'Turn off all CLI read permission in this running app, including while an earlier request finishes.'}</span>
  </section>;
}
