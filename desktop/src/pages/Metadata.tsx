import type { ReactNode } from 'react';
import { localeRequirements } from '../catalog.ts';
import type { Catalog } from '../types.ts';
import { Badge, DisabledAction, EmptyState, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

export function Metadata({ catalog, children }: { catalog: Catalog | null; children: ReactNode }) {
  const rules = catalog?.metadata;
  const groups = localeRequirements(rules);
  const limits = rules ? Object.entries(rules.textLimits) : [];
  return <>
    <PageHeading eyebrow="STORE METADATA" title="Make every first impression count." description="Plan your Store locales and metadata location. File editing, screenshot import, and Store synchronization come in a later milestone." />
    {children}
    <div className="two-card-grid"><section className="card"><SectionHeading title="Locale content requirements" description="Format guidance from the core, not a review of your metadata files."><Badge>Not inspected</Badge></SectionHeading>{groups.length ? groups.map(({ platform, files }) => <div className="metadata-platform" key={platform}><h3>{platform === 'android' ? 'Android' : platform === 'ios' ? 'iOS' : platform}</h3><ul className="metadata-requirements">{files.map((name) => <li key={name}><Icon name="metadata" size={17} /><span>{name}</span><Badge>Required text</Badge></li>)}</ul></div>) : <EmptyState compact icon="metadata" title="No metadata requirements loaded" description="The native catalogue provides exact locale-file names and content limits." />}{limits.length > 0 && <dl className="limit-list">{limits.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value} characters</dd></div>)}</dl>}{rules && <><dl className="limit-list"><div><dt>Android release notes</dt><dd>{rules.androidReleaseNoteLimit} characters</dd></div><div><dt>Maximum file size</dt><dd>{(rules.maxFileBytes / 1024 / 1024).toLocaleString()} MiB</dd></div><div><dt>Maximum files</dt><dd>{rules.maxFiles.toLocaleString()}</dd></div><div><dt>Maximum archive size</dt><dd>{(rules.maxArchiveBytes / 1024 / 1024).toLocaleString()} MiB</dd></div></dl><p className="metadata-suffixes">Supported suffixes: {rules.supportedSuffixes.join(', ')}. Format rules only; no files inspected.</p></>}</section>
      <section className="card screenshot-card"><SectionHeading title="Screenshots & assets" description="Bring the real experience into your Store listing." /><div className="phone-preview" aria-hidden="true"><div className="mini-phone"><span /><div className="phone-placeholder"><Icon name="metadata" size={23} /></div></div><div className="mini-phone second"><span /><div className="phone-placeholder"><Icon name="spark" size={23} /></div></div></div><p>No screenshots or asset evidence have been loaded.</p><DisabledAction label="Import screenshots" icon="plus" reason="Native asset selection, safe registration, size validation, and metadata editing are not implemented." /></section></div>
  </>;
}
