import type { ReactNode } from 'react';
import type { AppInfo } from '../types.ts';
import { futureReason } from '../certainty.ts';
import { Badge, DisabledAction, EmptyState, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

export function Releases({ info, offlineChecks, androidBuild }: { info: AppInfo | null; offlineChecks: ReactNode; androidBuild: ReactNode }) {
  return <>
    <PageHeading eyebrow="RELEASES" title="One candidate. A traceable journey." description="Review saved checks and Android build inputs separately. Local output is not an authenticated release candidate; protected promotion remains a future stage." />
    {offlineChecks}
    {androidBuild}
    <section className="card"><SectionHeading title="Release lifecycle" description="Planned stages, not a completed timeline. No runs or authenticated release evidence have been loaded."><Badge>Not implemented</Badge></SectionHeading><div className="lifecycle">{[{ name: 'Candidate', description: 'Build, sign, validate, and retain immutable evidence.' }, { name: 'Internal testing', description: 'Distribute the same verified candidate to internal testers.' }, { name: 'External testing', description: 'Use protected promotion and authentic predecessor evidence.' }, { name: 'Production preparation', description: 'Prepare a reviewed submission. Never auto-publish publicly.' }].map((stage, index) => <div className="lifecycle-stage" key={stage.name}><div className="lifecycle-node">{index + 1}</div><strong>{stage.name}</strong><p>{stage.description}</p><Badge>Planned · unavailable</Badge></div>)}</div></section>
    <section className="card"><EmptyState icon="rocket" title="No release history loaded" description="This app has not retrieved or authenticated release records. An empty view does not mean the project has never released."><DisabledAction label="Create release candidate" icon="rocket" reason={futureReason(info?.capabilities, 'release.candidate', 'Native builds, signed artifacts, GitHub dispatch, and release evidence are not implemented.')} /></EmptyState></section>
  </>;
}

export function Recovery({ info }: { info: AppInfo | null }) {
  return <>
    <PageHeading eyebrow="RECOVERY" title="An interruption shouldn’t leave you guessing." description="Recovery must know what really happened, preserve original ownership, and never mistake partial success for a clean restart." />
    <div className="notice notice-warning"><Icon name="shield" /><div><strong>Recovery state is unknown</strong><p>No journals, local operations, or remote mutations have been assessed. This screen does not establish that the project is clean or that an operation can safely be retried.</p></div></div>
    <section className="card"><EmptyState icon="recovery" title="Recovery assessment is not implemented" description="A future reviewed core flow will supply session-bound recovery challenges and distinguish interrupted, partially completed, and settled operations."><DisabledAction label="Assess recovery state" icon="recovery" reason={futureReason(info?.capabilities, 'recovery.assess', 'Owned-operation recovery, authenticated journals, and session-bound decisions are not implemented.')} /></EmptyState></section>
    <p className="review-caution">Cancelling saved checks or an Android build cannot undo effects already performed by project code. A retained work folder is not a successful artifact or a safe retry. Project admission refusal does not establish a recoverable signing session or distinguish busy ownership from recovery need. Keep the original operation and its status; this page cannot inspect, clean or reset it.</p>
    <section className="card"><SectionHeading title="Until recovery is available" /><ul className="plain-list"><li><Icon name="shield" size={17} /><span>Do not infer a safe retry from a missing desktop record.</span></li><li><Icon name="box" size={17} /><span>Keep original files, artifacts, and existing release evidence intact.</span></li><li><Icon name="github" size={17} /><span>Check the actual protected workflow or Store operation before considering another mutation.</span></li></ul></section>
  </>;
}
