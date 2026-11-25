import type { ProjectSession } from '../drafts.ts';
import { setupGuidanceView, setupRequirementLabels, setupStageLabels, setupStateLabels } from '../smartSetup.ts';
import type { SetupStage } from '../smartSetup.ts';
import type { Page } from '../types.ts';
import { Badge, SectionHeading } from './Common.tsx';

// Navigation only; actual operation controllers own validation and consent.
export function LocalSetupReadiness({ session, preview, refreshReason, onNavigate }: {
  session: ProjectSession | null; preview: boolean; refreshReason: string | null; onNavigate: (page: Page) => void;
}) {
  const view = setupGuidanceView(session, preview, refreshReason);
  return <section className="card" aria-label="Local setup requirements">
    <SectionHeading title="Start locally; add Store setup later" description="Requirements from your saved settings and static project hints, not a build or release approval." />
    {view.reason && <p>{view.reason}</p>}
    {view.analysis && <>
      {view.savedOnly && <p className="notice notice-warning" role="status">Saved files only. Your unsaved draft is preserved and is not included in this guidance.</p>}
      {view.analysis.discoveryPartial && <p className="notice notice-warning">Some files were not read. Missing hints are unknown, not proof that a requirement is absent.</p>}
      {(Object.keys(setupStageLabels) as SetupStage[]).map((stage) => <details key={stage} open={stage === 'local'}>
        <summary>{setupStageLabels[stage]}</summary>
        <dl className="guided-details-facts">{view.analysis!.requirements.filter((row) => row.stage === stage).map((row) => <div key={row.id}>
          <dt>{setupRequirementLabels[row.id]} <Badge tone={row.state === 'blocked' ? 'danger' : row.state === 'ambiguous' || row.state === 'needs-input' || row.state === 'unsupported' ? 'warning' : 'neutral'}>{setupStateLabels[row.state]}</Badge></dt>
          <dd>{row.summary}{row.reference && <><br /><code>{row.reference}</code></>}</dd>
        </div>)}</dl>
      </details>)}
      <div className="button-row">
        <button type="button" className="button secondary" onClick={() => onNavigate('settings')}>Review local settings</button>
        <button type="button" className="button secondary" onClick={() => onNavigate('environment')}>Check build environment</button>
        <button type="button" className="button secondary" onClick={() => onNavigate('releases')}>Review build options</button>
      </div>
      <details><summary>What this guidance does not verify</summary><ul>{view.analysis.limitations.map((line) => <li key={line}>{line}</li>)}</ul></details>
    </>}
  </section>;
}
