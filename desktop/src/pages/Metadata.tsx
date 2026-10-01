import type { ReactNode } from 'react';
import { localeRequirements } from '../catalog.ts';
import type { Catalog } from '../types.ts';
import { Badge, EmptyState, PageHeading, SectionHeading } from '../components/Common.tsx';
import { Icon } from '../components/Icon.tsx';

export function Metadata({ catalog, children, validation, textEditor, imageEditor, notesEditor }: { catalog: Catalog | null; children: ReactNode; validation: ReactNode; textEditor: ReactNode; imageEditor: ReactNode; notesEditor: ReactNode }) {
  const rules = catalog?.metadata;
  const groups = localeRequirements(rules);
  const limits = rules ? Object.entries(rules.textLimits) : [];
  return <>
    <PageHeading eyebrow="STORE METADATA" title="Make every first impression count." description="Save your locale settings first, then edit public text or review a localized image copy. Header checks and local saving are not Store acceptance; nothing is sent to a Store." />
    {children}
    {validation}
    <div id="required-notes-editor">{notesEditor}</div>
    <div id="metadata-text-editor">{textEditor}</div>
    <div id="metadata-image-editor">{imageEditor}</div>
    <section className="card"><SectionHeading title="Locale content requirements" description="Format guidance from the core, not a review of your metadata files."><Badge>Not inspected</Badge></SectionHeading>{groups.length ? groups.map(({ platform, files }) => <div className="metadata-platform" key={platform}><h3>{platform === 'android' ? 'Android' : platform === 'ios' ? 'iOS' : platform}</h3><ul className="metadata-requirements">{files.map((name) => <li key={name}><Icon name="metadata" size={17} /><span>{name}</span><Badge>Required text</Badge></li>)}</ul></div>) : <EmptyState compact icon="metadata" title="No metadata requirements loaded" description="The native catalogue provides exact locale-file names and content limits." />}{limits.length > 0 && <dl className="limit-list">{limits.map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value} characters</dd></div>)}</dl>}{rules && <><dl className="limit-list"><div><dt>Android release notes</dt><dd>{rules.androidReleaseNoteLimit} characters</dd></div><div><dt>Maximum file size</dt><dd>{(rules.maxFileBytes / 1024 / 1024).toLocaleString()} MiB</dd></div><div><dt>Maximum files</dt><dd>{rules.maxFiles.toLocaleString()}</dd></div><div><dt>Maximum archive size</dt><dd>{(rules.maxArchiveBytes / 1024 / 1024).toLocaleString()} MiB</dd></div></dl><p className="metadata-suffixes">Supported suffixes: {rules.supportedSuffixes.join(', ')}. Format rules only; no files inspected.</p></>}</section>
  </>;
}
