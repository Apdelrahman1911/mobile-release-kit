import type { RehearsalAction, RehearsalContext } from '../releaseRehearsal.ts';
import { releaseRehearsal } from '../releaseRehearsal.ts';
import { Badge, SectionHeading } from './Common.tsx';

export function ReleaseRehearsal({ context, onAction }: {
  context: RehearsalContext; onAction: (action: RehearsalAction) => void;
}) {
  const view = releaseRehearsal(context);
  return <section id="release-rehearsal" className="card" tabIndex={-1} aria-label="Nonpublishing release walkthrough">
    <SectionHeading title="Try the release steps without publishing" description="Continue from an existing result instead of starting again. Every operation below keeps its own review, consent and Stop controls." />
    <div className={view.attention ? 'notice notice-warning' : 'notice notice-info'} role="status">
      <p>{view.next.summary}</p>
      <button type="button" className="button" onClick={() => onAction(view.next.action)}>{view.next.label}</button>
    </div>
    <details><summary>Local build, candidate and Store checks are different steps</summary>
      <ol className="plain-list">{view.steps.map((step) => <li key={step.id}><div>
        <h3>{step.title} <Badge tone={step.status === 'attention' ? 'warning' : step.status === 'result-available' ? 'info' : 'neutral'}>
          {step.status === 'result-available' ? 'Result available — not approval' : step.status === 'attention' ? 'Review needed' : step.id === 'build' ? 'Not checked' : 'Optional — not checked'}
        </Badge></h3>
        <p>{step.summary}</p>
        {step.reason && <p className="save-note">{step.reason}</p>}
        <button type="button" className="button small secondary" onClick={() => onAction(step.action)}>{step.label}</button>
      </div></li>)}</ol>
      <p>Returning after a restart? Open Local release history and explicitly verify it. Missing history is not permission to enroll again, delete files or repeat a release. Choosing a candidate here only fills the original review form.</p>
      <button type="button" className="button small secondary" onClick={() => onAction({ kind: 'show', target: 'history' })}>Have an existing candidate? Open history verification</button>
      <p><strong>Store checks are separate.</strong> Google Play access creates a temporary uncommitted edit and attempts to delete it; it is not a zero-write operation and may affect another editor. Apple access reads the configured app. Both require their existing separate approval, and neither uploads or publishes. This guide calls neither.</p>
      <p>An ordinary local build needs no Store-account setup. A signed candidate additionally needs signing inputs, saved release policy, metadata, clean source and intact local history. No checkmark here grants readiness, Store consent or permission to retry.</p>
      <button type="button" className="text-button" onClick={() => onAction({ kind: 'setup', action: { kind: 'navigate', page: 'credentials' } })}>Where to prepare signing and Store inputs</button>
    </details>
  </section>;
}
