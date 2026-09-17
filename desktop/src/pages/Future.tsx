import type { AppInfo, Page } from '../types.ts';
import { futureReason } from '../certainty.ts';
import { Badge, DisabledAction, EmptyState, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

export function GitHub({ onNavigate, info }: { onNavigate: (page: Page) => void; info: AppInfo | null }) {
  return <>
    <PageHeading eyebrow="GITHUB" title="A protected path from source to Store." description="Release work belongs in reviewed workflows, with explicit source identity and protected environments." />
    <section className="card connect-card"><div className="github-visual"><Icon name="github" size={45} /></div><div><Badge>Not connected</Badge><h2>Connect the workflow, not just an account.</h2><p>GitHub device login, repository setup plans, secret configuration, and protected dispatch are not implemented yet. No repository, permission, or credential has been checked.</p><DisabledAction label="Connect GitHub" icon="github" reason={futureReason(info?.capabilities, 'github.login', 'Publisher-registered GitHub App login and the secure token vault are not implemented.')} /></div></section>
    <div className="three-card-grid">{[{ icon: 'branch' as const, title: 'Repository & source', detail: 'Select the repository and bind release work to an actual observed commit.' }, { icon: 'metadata' as const, title: 'Reviewed setup', detail: 'Review proposed workflow files and remote changes before anything is applied.' }, { icon: 'shield' as const, title: 'Protected environments', detail: 'Keep approvals, write-only secrets, and Store authority inside protected jobs.' }].map((step, index) => <section className="card setup-step" key={step.title}><span className="step-number">0{index + 1}</span><Icon name={step.icon} size={25} /><h3>{step.title}</h3><p>{step.detail}</p><Badge>Not implemented</Badge></section>)}</div>
    <section className="card"><SectionHeading title="Your source policy" description="You can review the configured candidate and production branches now. This does not query GitHub or verify branch protection." /><button className="button secondary" onClick={() => onNavigate('settings')}>Review project settings<Icon name="arrow" size={17} /></button></section>
    <div className="notice notice-info"><Icon name="lock" /><div><strong>No automatic public release</strong><p>Future release actions must preserve source binding, review, protected approvals, authentic evidence, and the core Store guards. Public release is never automated.</p></div></div>
  </>;
}

export function Releases({ info }: { info: AppInfo | null }) {
  return <>
    <PageHeading eyebrow="RELEASES" title="One candidate. A traceable journey." description="Build once, retain the evidence, and move the same candidate through explicit protected stages." />
    <section className="card"><SectionHeading title="Release lifecycle" description="Planned stages, not a completed timeline. No runs or authenticated release evidence have been loaded."><Badge>Not implemented</Badge></SectionHeading><div className="lifecycle">{[{ name: 'Candidate', description: 'Build, sign, validate, and retain immutable evidence.' }, { name: 'Internal testing', description: 'Distribute the same verified candidate to internal testers.' }, { name: 'External testing', description: 'Use protected promotion and authentic predecessor evidence.' }, { name: 'Production preparation', description: 'Prepare a reviewed submission. Never auto-publish publicly.' }].map((stage, index) => <div className="lifecycle-stage" key={stage.name}><div className="lifecycle-node">{index + 1}</div><strong>{stage.name}</strong><p>{stage.description}</p><Badge>Planned · unavailable</Badge></div>)}</div></section>
    <section className="card"><EmptyState icon="rocket" title="No release history loaded" description="This app has not retrieved or authenticated release records. An empty view does not mean the project has never released."><DisabledAction label="Create release candidate" icon="rocket" reason={futureReason(info?.capabilities, 'release.candidate', 'Native builds, signed artifacts, GitHub dispatch, and release evidence are not implemented.')} /></EmptyState></section>
  </>;
}

export function Artifacts({ info }: { info: AppInfo | null }) {
  return <>
    <PageHeading eyebrow="ARTIFACTS" title="The files. The provenance. The proof." description="Future artifact records will identify exactly what was built, how it was validated, and which candidate it belongs to." />
    <div className="three-card-grid">{[{ icon: 'android' as const, title: 'Android packages', detail: 'AABs, mappings, and native symbols' }, { icon: 'apple' as const, title: 'iOS packages', detail: 'IPAs, archives, and retained dSYMs' }, { icon: 'shield' as const, title: 'Release evidence', detail: 'Validation reports and authenticated receipts' }].map((item) => <div className="card artifact-type" key={item.title}><div className="soft-icon"><Icon name={item.icon} size={25} /></div><h3>{item.title}</h3><p>{item.detail}</p><Badge>Not loaded</Badge></div>)}</div>
    <section className="card"><EmptyState icon="box" title="No authenticated artifacts loaded" description="The desktop foundation does not build, discover, import, authenticate, or download release artifacts. No placeholder artifacts stand in for real evidence."><DisabledAction label="Load candidate artifacts" icon="folder" reason={futureReason(info?.capabilities, 'artifacts.list', 'Artifact custody, authenticated candidate records, and safe native file actions are not implemented.')} /></EmptyState></section>
  </>;
}

export function Recovery({ info }: { info: AppInfo | null }) {
  return <>
    <PageHeading eyebrow="RECOVERY" title="An interruption shouldn’t leave you guessing." description="Recovery must know what really happened, preserve original ownership, and never mistake partial success for a clean restart." />
    <div className="notice notice-warning"><Icon name="shield" /><div><strong>Recovery state is unknown</strong><p>No journals, local operations, or remote mutations have been assessed. This screen does not establish that the project is clean or that an operation can safely be retried.</p></div></div>
    <section className="card"><EmptyState icon="recovery" title="Recovery assessment is not implemented" description="A future reviewed core flow will supply session-bound recovery challenges and distinguish interrupted, partially completed, and settled operations."><DisabledAction label="Assess recovery state" icon="recovery" reason={futureReason(info?.capabilities, 'recovery.assess', 'Owned-operation recovery, authenticated journals, and session-bound decisions are not implemented.')} /></EmptyState></section>
    <section className="card"><SectionHeading title="Until recovery is available" /><ul className="plain-list"><li><Icon name="shield" size={17} /><span>Do not infer a safe retry from a missing desktop record.</span></li><li><Icon name="box" size={17} /><span>Keep original files, artifacts, and existing release evidence intact.</span></li><li><Icon name="github" size={17} /><span>Check the actual protected workflow or Store operation before considering another mutation.</span></li></ul></section>
  </>;
}
