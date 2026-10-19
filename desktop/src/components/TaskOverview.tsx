import { setupActivitySummary } from '../setupOverview.ts';
import type { SetupAction, SetupOverview } from '../setupOverview.ts';
import { Badge } from './Common.tsx';
import { Icon } from './Icon.tsx';

export function TaskOverview({ overview, preview, onAction }: {
  overview: SetupOverview;
  preview: boolean;
  onAction: (action: SetupAction) => void;
}) {
  const current = overview.stages.find((stage) => stage.id === overview.currentStage)!;
  const activity = overview.currentActivity;
  const warning = activity && ['unknown', 'recovery-required', 'failed'].includes(activity.state);
  return <section className="card guided-overview" aria-label="Project release overview">
    <div className="guided-next-grid">
      <div className="guided-saved-version">
        <h2>Current release</h2>
        <strong className="guided-version-value">{overview.versionLabel}</strong>
        {overview.version && <p>Build {overview.version.build}</p>}
        <p>{preview ? 'Example mode — no project version has been read.' : 'Saved version only. Not the latest release in a Store.'}</p>
        <button type="button" className="text-button" onClick={() => onAction({ kind: 'open-version' })}>Review version &amp; build number<Icon name="chevron" size={15} /></button>
      </div>
      <div className="guided-next-step" aria-live="polite">
        <Badge tone={warning ? 'warning' : 'info'}>{activity ? warning ? 'Attention needed' : 'Current task' : preview ? 'Explore the example' : 'Your next step'}</Badge>
        <h2>{activity ? activity.task : current.title}</h2>
        <p role={warning ? 'alert' : undefined}>{activity ? setupActivitySummary(activity) : current.summary}</p>
        <button type="button" className="button primary" disabled={overview.next.disabledReason !== null}
          aria-describedby={overview.next.disabledReason ? 'guided-next-reason' : undefined} onClick={() => onAction(overview.next.action)}>
          {overview.next.label}<Icon name="arrow" size={17} />
        </button>
        {overview.next.disabledReason && <p id="guided-next-reason" className="guided-blocker">{overview.next.disabledReason}</p>}
        <p className="guided-safety">{activity ? 'Keep the original task until its outcome is known.' : 'Nothing is built, uploaded or published by opening a step.'}</p>
      </div>
    </div>
    <div className="guided-known" aria-label="What is ready and what remains">
      <div><h3>Known so far</h3><p>{overview.known.length ? overview.known.join(' · ') : 'No project checks completed yet.'}</p></div>
      <div><h3>Still to do</h3><p>{overview.remaining.slice(0, 2).join(' · ')}{overview.remaining.length > 2 ? ` · ${overview.remaining.length - 2} more steps below` : ''}</p></div>
    </div>
    <p className="guided-safety">Setup checks are not release approval. Each build and Store action checks its own requirements.</p>
  </section>;
}
