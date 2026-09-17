import type { AppInfo } from '../types.ts';
import { Badge, DisabledAction, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

const methodLabels: Record<string, string> = {
  capabilities: 'Read engine capabilities', catalog: 'Load schema & field help',
  'project.snapshot': 'Read a static project observation', 'config.validate': 'Validate a configuration draft',
  'config.suggest': 'Suggest an unverified configuration draft', 'config.preview': 'Review draft changes and field requirements',
};

export function Environment({ info, preview, onRetry, loading }: { info: AppInfo | null; preview: boolean; onRetry: () => void; loading: boolean }) {
  const runtime = info?.runtime;
  const capabilities = info?.capabilities;
  return <>
    <PageHeading eyebrow="ENVIRONMENT" title="Understand your environment." description="A static capability assessment—not doctor, a toolchain probe, or a promise that your machine can build."><button type="button" className="button secondary" disabled={loading} onClick={onRetry}><Icon name="refresh" size={17} className={loading ? 'spin' : ''} />{loading ? 'Loading…' : 'Reload capabilities'}</button></PageHeading>
    <div className="notice notice-info"><Icon name="info" /><div><strong>Available is not the same as verified</strong><p>These rows describe implemented desktop functions. SDKs, signing identities, accounts, services, and project code have not been tested.</p></div></div>
    <div className="environment-summary">
      <section className="card runtime-card"><span className="eyebrow">CORE RUNTIME</span><h2>{preview ? 'Browser preview' : runtime?.state === 'available' ? runtime.mode === 'development' ? 'Development runtime' : 'Bundled runtime' : 'Runtime unavailable'}</h2><Badge tone={runtime?.state === 'available' && !preview ? 'info' : 'warning'}>{preview ? 'No native connection' : runtime?.state ?? 'Not loaded'}</Badge><p>{preview ? 'This page is a design preview. No platform or engine capability has been verified.' : runtime?.reason ?? (runtime?.state === 'available' ? 'A runtime is available for the listed static functions. This does not establish native process finality or packaged release readiness.' : 'No runtime availability has been established. Capabilities and environment state remain unassessed.')}</p>{runtime?.mode === 'development' && <p className="warning-text">An explicit developer runtime is not a standalone end-user distribution.</p>}<div className="runtime-versions"><span>Desktop <strong>{info?.appVersion ?? 'Not loaded'}</strong></span><span>Core <strong>{capabilities?.coreVersion ?? 'Not loaded'}</strong></span><span>Platform <strong>{capabilities?.hostPlatform ?? 'Not observed'}</strong></span></div></section>
      <section className="card platform-note"><div className="soft-icon"><Icon name="environment" size={24} /></div><h2>The right platform for the job</h2><p>Android local release support is part of the product plan for Linux, macOS, and Windows. Native iOS requires local or hosted macOS.</p><p>This milestone does not run native builds. Windows filesystem observations remain unavailable until a reviewed handle-bound reader is implemented.</p></section>
    </div>
    <section className="card"><SectionHeading title="Implemented read-only functions" description="Availability comes from the core, not a guessed operating-system checklist." /><div className="capability-list">{Object.entries(methodLabels).map(([method, label]) => {
      const capability = capabilities?.methods.find((item) => item.method === method);
      const available = Boolean(capability?.available) && runtime?.state === 'available' && !preview;
      return <div key={method}><span className="capability-icon"><Icon name={method === 'project.snapshot' ? 'folder' : method === 'config.validate' ? 'settings' : 'list'} size={19} /></span><div><strong>{label}</strong><p>{preview ? 'Illustration only; no core service is connected.' : capability?.reason ?? 'The engine has not provided this capability.'}</p></div><Badge tone={available ? 'info' : 'neutral'}>{available ? 'Available · read-only' : 'Unavailable'}</Badge></div>;
    })}</div></section>
    <section className="card"><SectionHeading title="Native toolchains" description="No executables are searched for, started, or version-probed in the static assessment." /><div className="tool-grid">{[{ name: 'Android SDK', detail: 'SDK packages, build tools, and device tooling', icon: 'android' as const }, { name: 'Java & Gradle', detail: 'Compatible JDK and the project build wrapper', icon: 'box' as const }, { name: 'Xcode & signing', detail: 'macOS toolchain, profiles, and certificates', icon: 'apple' as const }].map((tool) => <div className="tool-card" key={tool.name}><Icon name={tool.icon} size={24} /><h3>{tool.name}</h3><p>{tool.detail}</p><Badge>Not checked</Badge></div>)}</div><div className="card-action"><DisabledAction label="Run full doctor" icon="environment" reason="Native discovery and toolchain diagnostics are not implemented in the desktop foundation." /></div></section>
    {capabilities && capabilities.limitations.length > 0 && <section className="card"><SectionHeading title="Engine-reported boundaries" /><ul className="plain-list">{capabilities.limitations.map((limitation, index) => <li key={index}><Icon name="shield" size={16} /><span>{limitation}</span></li>)}</ul></section>}
  </>;
}
