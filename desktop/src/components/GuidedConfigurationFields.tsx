import { useEffect, useId, useRef, useState } from 'react';
import { GUIDED_CONFIG_STAGES, guidedConfiguration, guidedConfigFieldMatches, guidedConfigGroup, guidedConfigSelectStage, guidedConfigVisibleStage } from '../guidedConfiguration.ts';
import type { GuidedConfigGroup, GuidedConfigSection, GuidedConfigStage } from '../guidedConfiguration.ts';
import type { ProjectSession } from '../drafts.ts';
import type { ProjectPathControls } from '../projectPaths.ts';
import type { Catalog, HelpContent, JsonValue } from '../types.ts';
import { Badge, EmptyState, SectionHeading } from './Common.tsx';
import { DraftField } from './Fields.tsx';
import { Icon } from './Icon.tsx';
import './guidedConfiguration.css';

interface GuidedConfigurationProps {
  catalog: Catalog;
  session: ProjectSession;
  preview: boolean;
  pathPicker: ProjectPathControls;
  reviewReason: string | null;
  onReview: () => void;
  onProjectIdentity?: () => void;
  onEdit: (path: string, value: JsonValue | undefined) => void;
  onHelp: (help: HelpContent) => void;
}

// Presentation of the existing draft only. All fields stay mounted once when
// changing groups/search, and the original review/picker/save owners are reused.
export function GuidedConfigurationFields({ catalog, session, preview, pathPicker, reviewReason, onReview, onProjectIdentity, onEdit, onHelp }: GuidedConfigurationProps) {
  const [requestedStage, setRequestedStage] = useState<GuidedConfigStage>('app');
  const [search, setSearch] = useState('');
  const [advancedExpanded, setAdvancedExpanded] = useState(false);
  const [reveal, setReveal] = useState<{ group: GuidedConfigGroup } | null>(null);
  const sections = useRef(new Map<GuidedConfigGroup, HTMLElement>());
  const id = useId();
  const layout = guidedConfiguration(catalog, session, session.project.id, preview);
  const pendingField = pathPicker.pendingField;
  const pending = pendingField !== null;
  const stage = guidedConfigVisibleStage(requestedStage, pendingField);
  const searching = search.trim() !== '';
  const checking = session.reviewRequest !== null || session.validationRequest !== null;
  const advanced = layout.sections.find((section) => section.id === 'advanced')!;
  const matches = (section: GuidedConfigSection) => section.fields.filter((field) => guidedConfigFieldMatches(field, search, pendingField)).length;
  const matchingCount = layout.sections.reduce((total, section) => total + matches(section), 0);
  const advancedAttention = advanced.attentionCount !== null && advanced.attentionCount > 0;
  const advancedForced = advancedAttention || pendingField !== null && guidedConfigGroup(pendingField) === 'advanced' || searching && matches(advanced) > 0;

  useEffect(() => {
    if (!reveal) return;
    // Only an explicit navigation/attention click moves focus. A fresh review
    // may reveal required Advanced settings, but must not steal keyboard focus.
    const target = sections.current.get(reveal.group);
    target?.focus({ preventScroll: true });
    target?.scrollIntoView({ block: 'nearest' });
  }, [reveal]);

  const openGroup = (group: GuidedConfigGroup) => {
    if (pending) return;
    setSearch('');
    if (group === 'advanced') setAdvancedExpanded(true);
    else setRequestedStage(guidedConfigSelectStage(stage, group, pendingField));
    setReveal({ group });
  };
  const fields = (section: GuidedConfigSection) => <div className="form-grid">{section.fields.map((field) =>
    // Do not filter this map: hidden controls retain their React/native-facing
    // state and stable path keys even while another group or search is visible.
    <div key={field.path} className={`guided-config-field${['string-list', 'argv', 'commands'].includes(field.input) ? ' full-width' : ''}`}
      hidden={!guidedConfigFieldMatches(field, search, pendingField)}>
      <DraftField field={field} draft={session.draft!} context={layout.contexts.get(field.path)} contextFresh={layout.context === 'current'}
        pathPicker={pathPicker} onChange={onEdit} onHelp={onHelp} />
    </div>)}</div>;

  if (!session.draft) return null;
  return <div className="guided-configuration">
    <div className="guided-config-intro"><h2>Set up your project in four groups</h2><p>Start with your app, then its build inputs. Every group edits the same draft. Moving to the next group does not save or approve anything.</p></div>
    <div className="guided-config-review" aria-live="polite">
      <div><strong>{layout.context === 'example' ? 'Example only — no project checked' : layout.context !== 'current' ? 'Check which settings are needed' :
        layout.attentionCount ? `${layout.attentionCount} ${layout.attentionCount === 1 ? 'setting needs' : 'settings need'} review` :
        layout.format === 'invalid' ? 'This draft still needs correction' : layout.comparison === 'partial' ? 'Some draft changes need a separate review' : 'Field presence reviewed'}</strong>
      <p>{layout.context === 'example' ? 'You can explore the fields, but these values do not describe a real project.' : layout.context !== 'current' ?
        'Check this draft after editing to update required fields and conflicts. Your values are kept; nothing is removed automatically.' : layout.comparison === 'partial' ?
        'Some data is outside the known-field comparison. It remains in your draft. See the full review below; the listed fields are not a complete review.' : layout.format === 'invalid' ?
        'This draft did not pass configuration checks. Review missing fields and conflicts, then the full review below. Empty or incorrectly formatted values can also need correction.' :
        'These are field-presence checks, not a completed setup. Empty or invalid values can still need correction; see the full review below. Nothing was saved or checked for release.'}</p></div>
      <button type="button" className="button secondary" disabled={reviewReason !== null || checking || pending} aria-describedby={`${id}-review-reason`} onClick={onReview}>
        <Icon name={session.reviewRequest ? 'refresh' : 'search'} size={16} className={session.reviewRequest ? 'spin' : ''} />
        {session.reviewRequest ? 'Checking draft…' : 'Check what’s needed'}
      </button>
    </div>
    <p className="toolbar-reason" id={`${id}-review-reason`}>{reviewReason ?? (pending ? 'Finish the existing file selection before checking the draft.' :
      'Uses the existing draft review. No project files are saved and no tools or accounts are checked.')}</p>
    {layout.attention.length > 0 && <div className="guided-config-attention" aria-label="Settings needing attention across all groups">
      {layout.sections.filter((section) => section.attention.length > 0).map((section) => <button type="button" className="text-button" key={section.id}
        disabled={pending} aria-controls={`${id}-${section.id}`} onClick={() => openGroup(section.id)}>
        {section.label}: {section.attention.length} {section.attention.length === 1 ? 'setting needs' : 'settings need'} review<Icon name="arrow" size={14} />
      </button>)}
    </div>}
    <nav className="guided-config-stages" aria-label="Configuration groups">{layout.sections.filter((section) => section.id !== 'advanced').map((section, index) =>
      <button type="button" key={section.id} disabled={pending} className={section.id === stage && !searching ? 'active' : ''}
        aria-current={section.id === stage && !searching ? 'step' : undefined} aria-controls={`${id}-${section.id}`} onClick={() => openGroup(section.id)}>
        <span className="guided-config-stage-number">{index + 1}</span><span>{section.label}</span>
      </button>)}</nav>
    <div className="editor-controls guided-config-search"><label className="search-field"><Icon name="search" size={17} /><span className="sr-only">Search all configuration fields</span>
      <input type="search" value={search} disabled={pending} placeholder="Find any setting…" onChange={(event) => { if (!pending) setSearch(event.target.value); }} /></label>
      <span>{searching ? `${matchingCount} matching settings across all groups` : 'Choose a group, or search every setting'}</span>
    </div>
    {pending && <p className="context-refresh-note" role="status">Finish the existing file selection first. Its field stays visible; group navigation and search are paused.</p>}
    {layout.sections.map((section) => section.id === 'advanced' ? <div key={section.id} hidden={searching && matches(section) === 0}>
      <details className="guided-config-advanced" open={advancedExpanded || advancedForced}
        onToggle={(event) => {
          if (!event.currentTarget.open && advancedForced) event.currentTarget.open = true;
          else setAdvancedExpanded(event.currentTarget.open);
        }}>
        <summary id={`${id}-${section.id}`} ref={(node) => { if (node) sections.current.set(section.id, node); else sections.current.delete(section.id); }}
          onClick={(event) => { if (advancedForced) event.preventDefault(); }}>
          {section.label}{advancedAttention && <span className="guided-config-attention-label">{section.attentionCount} need review · kept open</span>}
          {!advancedAttention && searching && <span className="guided-config-attention-label">Matching settings shown</span>}
        </summary>
        <p>{section.description}</p>{fields(section)}
      </details>
    </div> : <section className="card form-card" key={section.id} hidden={searching ? matches(section) === 0 : section.id !== stage}>
      <div id={`${id}-${section.id}`} tabIndex={-1} ref={(node) => { if (node) sections.current.set(section.id, node); else sections.current.delete(section.id); }}>
        <SectionHeading title={section.title} description={section.description}>
          {section.attentionCount !== null && section.attentionCount > 0 && <Badge tone="warning">{section.attentionCount} need review</Badge>}
        </SectionHeading>
      </div>
      {section.id === 'app' && onProjectIdentity && <div className="notice notice-info">
        <div><strong>Want to change the app ID in your project?</strong>
          <p>The fields below change toolkit settings only. The guided app ID editor can review supported project files and their matching settings together. Opening it keeps your draft and changes no files.</p>
          <button type="button" className="button secondary" disabled={pending} onClick={onProjectIdentity}>Open app ID editor</button>
        </div>
      </div>}
      {fields(section)}
    </section>)}
    {searching && matchingCount === 0 && <div className="card"><EmptyState compact icon="search" title="No matching settings" description="Try another term. Search includes every group and Advanced settings." /></div>}
    {!searching && <div className="guided-config-navigation">
      <span>Group {GUIDED_CONFIG_STAGES.indexOf(stage) + 1} of 4 · changes remain in this draft</span>
      {stage !== 'delivery' && <button type="button" className="button secondary" disabled={pending}
        onClick={() => openGroup(GUIDED_CONFIG_STAGES[GUIDED_CONFIG_STAGES.indexOf(stage) + 1]!)}>
        Next: {layout.sections.find((section) => section.id === GUIDED_CONFIG_STAGES[GUIDED_CONFIG_STAGES.indexOf(stage) + 1])?.label}<Icon name="arrow" size={16} />
      </button>}
      {stage === 'delivery' && <span>Review and save the draft using the controls below.</span>}
    </div>}
  </div>;
}
