import { useState } from 'react';
import { fieldsFor } from '../catalog.ts';
import { draftStatus } from '../certainty.ts';
import { isDirty, reviewFresh, validationFresh } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import type { Catalog, HelpContent, JsonValue } from '../types.ts';
import { Badge, EmptyState, ErrorNotice, HelpButton, Issues, SectionHeading } from './Common.tsx';
import { DraftField } from './Fields.tsx';
import { Icon } from './Icon.tsx';
import { DraftReview, reviewHelp } from './DraftReview.tsx';
import { DraftSuggestions } from './DraftSuggestions.tsx';
import { RemovedFields } from './RemovedFields.tsx';

const validationHelp: HelpContent = {
  label: 'Validate draft', requiredness: 'optional',
  requiredWhen: 'Available when a draft and a compatible native core are loaded.',
  what: 'Check an in-memory draft against the bundled core’s configuration policy.',
  why: 'Find format and policy errors before a future, separately reviewed save operation.',
  where: 'Use Validate draft after editing the project settings or metadata fields.',
  format: 'The current structured draft is sent to the read-only core. Nothing is saved.',
  failure: 'An error leaves your draft intact. Format-valid does not verify files, commands, identities, credentials, tools, Git, or Store readiness.',
};

const tabs = [
  { id: 'general', label: 'General', groups: [{ title: 'Version source', description: 'One committed source for the app version and build number.', prefixes: ['version'] }, { title: 'Source policy', description: 'Configured branch policy. Git is not inspected in this foundation.', prefixes: ['source'] }] },
  { id: 'android', label: 'Android', groups: [{ title: 'Android configuration', description: 'Application identity, build hints, and Store policy. No native or service verification.', prefixes: ['android'] }] },
  { id: 'ios', label: 'iOS', groups: [{ title: 'iOS configuration', description: 'Application identity and Xcode policy. Native iOS work requires macOS.', prefixes: ['ios'] }] },
  { id: 'services', label: 'Services', groups: [{ title: 'Service policy', description: 'Record requirements, never secret values. Services are not contacted.', prefixes: ['services'] }] },
  { id: 'advanced', label: 'Checks & schema', groups: [{ title: 'Project checks', description: 'Argument-by-argument configuration. These commands are never executed by draft validation.', prefixes: ['projectChecks'] }, { title: 'Schema contract', description: 'Local core policy is authoritative. A schema reference is never fetched.', prefixes: ['$schema', 'schemaVersion'] }] },
] as const;

interface EditorProps {
  catalog: Catalog | null;
  session: ProjectSession | null;
  metadataOnly?: boolean;
  preview: boolean;
  validateReason: string | null;
  reviewReason: string | null;
  suggestReason: string | null;
  onChoose: () => void;
  onNewDraft: () => void;
  onEdit: (path: string, value: JsonValue | undefined) => void;
  onValidate: () => void;
  onReview: () => void;
  onSuggest: () => void;
  onAdoptSuggestion: (requestId: number) => void;
  onRemoveForbidden: (reviewId: number, paths: string[]) => void;
  onUndoRemoval: (id: number) => void;
  onForgetRemoval: (id: number) => void;
  onDiscard: () => void;
  onHelp: (help: HelpContent) => void;
}

export function DraftEditor({ catalog, session, metadataOnly = false, preview, validateReason, reviewReason, suggestReason, onChoose, onNewDraft, onEdit, onValidate, onReview, onSuggest, onAdoptSuggestion, onRemoveForbidden, onUndoRemoval, onForgetRemoval, onDiscard, onHelp }: EditorProps) {
  const [tab, setTab] = useState<string>('general');
  const [search, setSearch] = useState('');
  if (!session) return <div className="card"><EmptyState icon="folder" title="First, choose a project" description="The native folder picker establishes the project boundary. Drafts remain separate for every project you open."><button className="button primary" onClick={onChoose}><Icon name="folder" size={17} />{preview ? 'Load example workspace' : 'Choose project folder'}</button></EmptyState></div>;
  if (!catalog) return <div className="card"><EmptyState icon="settings" title="The field catalogue is unavailable" description="A compatible core must provide the schema and contextual help before configuration controls are enabled. No fallback policy is substituted." /></div>;
  if (!session.draft) return <>
    <div className="card"><EmptyState icon="metadata" title={session.snapshotRequest ? 'Reading the static configuration…' : 'No editable configuration loaded'} description={session.snapshotRequest ? 'The engine reads only a bounded selection of static files. No project code runs.' : 'Begin an empty draft or explicitly prepare a core suggestion below. Both stay in memory and create no files.'}>{!session.snapshotRequest && <button className="button secondary" onClick={onNewDraft}><Icon name="plus" size={17} />Start an empty draft</button>}</EmptyState></div>
    {session.snapshot?.config.state === 'invalid' && <div className="notice notice-warning"><Icon name="info" size={18} /><div><strong>The observed configuration is invalid or unsupported</strong><p>It remains read-only. A new in-memory draft is not permission to overwrite or repair that file.</p></div></div>}
    <DraftSuggestions session={session} reason={suggestReason} onSuggest={onSuggest} onAdopt={onAdoptSuggestion} onHelp={onHelp} />
  </>;

  const draft = session.draft;
  const dirty = isDirty(session);
  const status = draftStatus(session);
  const contextFresh = reviewFresh(session);
  const contexts = new Map(session.review?.result.fields.map((field) => [field.path, field] as const) ?? []);
  const checking = session.validationRequest !== null || session.reviewRequest !== null;
  const selected = tabs.find((item) => item.id === tab) ?? tabs[0];
  const groups = metadataOnly ? [{ title: 'Store metadata settings', description: 'Configure locations and locales. Files, text, screenshots, and Store listings are not inspected.', prefixes: ['metadata'] }] : selected.groups;
  const count = groups.reduce((total, group) => total + fieldsFor(catalog, group.prefixes, search).length, 0);
  return <>
    <div className="draft-banner"><Icon name="metadata" size={21} /><div><strong>{preview ? 'Example draft · never connected to a project' : 'A draft, not a saved configuration'}</strong><p>Drafts and undo copies stay in memory across project switches; closing the app loses them. Refresh never replaces this draft or its baseline. Save and all file mutations remain unavailable.</p></div><Badge tone={dirty ? 'warning' : 'neutral'} dot>{dirty ? 'Unsaved changes' : 'Unchanged draft'}</Badge></div>
    {session.sourceChanged && <div className="notice notice-warning"><Icon name="info" /><div><strong>A newer observation differs from the draft baseline</strong><p>Your draft and original JSON baseline were preserved—even if unchanged. Discard and load the latest observation only when you explicitly want to replace them; nothing has been merged or saved.</p></div></div>}
    {session.snapshotError && <ErrorNotice error={session.snapshotError} title="Refresh failed; your draft was preserved" />}
    {session.editError && <ErrorNotice error={session.editError} title="The draft was not changed" />}
    {!contextFresh && <p className="context-refresh-note">{session.review ? 'Field context is stale after your changes.' : 'Active field requirements have not been reviewed.'} Use <strong>Review draft changes</strong> for core-derived requirements and conflicts. No dependent values are automatically removed.</p>}
    <div className="editor-controls">
      {!metadataOnly && <div className="tabs" role="group" aria-label="Settings section">{tabs.map((item) => <button className={item.id === tab ? 'active' : ''} type="button" key={item.id} aria-pressed={item.id === tab} onClick={() => setTab(item.id)}>{item.label}</button>)}</div>}
      <label className="search-field"><Icon name="search" size={17} /><span className="sr-only">Search {metadataOnly ? 'metadata' : 'current section'} fields</span><input type="search" value={search} placeholder="Find a setting…" onChange={(event) => setSearch(event.target.value)} /></label>
    </div>
    {groups.map((group) => {
      const fields = fieldsFor(catalog, group.prefixes, search);
      return fields.length > 0 ? <section className="card form-card" key={group.title}><SectionHeading title={group.title} description={group.description} /><div className="form-grid">{fields.map((field) => <DraftField key={field.path} field={field} draft={draft} context={contexts.get(field.path)} contextFresh={contextFresh} onChange={onEdit} onHelp={onHelp} />)}</div></section> : null;
    })}
    {count === 0 && <div className="card"><EmptyState compact icon="search" title="No matching settings in this section" description="Try a different term or select another settings section." /></div>}
    <div className="draft-toolbar"><div className="draft-toolbar-status"><Badge tone={status.tone}>{status.label}</Badge><span>No files changed</span></div><div className="button-row">
      <button type="button" className="text-button" disabled={!dirty && !session.sourceChanged && session.removedFields.length === 0} onClick={onDiscard}>{session.sourceChanged ? 'Discard & load latest observation' : 'Discard changes'}</button>
      <button type="button" className="button secondary" disabled title="Transactional configuration saving is not implemented.">Save draft<Icon name="lock" size={14} /></button>
      <button type="button" className="button secondary" disabled={validateReason !== null || checking} aria-describedby="draft-validation-reason" onClick={onValidate}><Icon name={session.validationRequest ? 'refresh' : 'check'} size={17} className={session.validationRequest ? 'spin' : ''} />{session.validationRequest ? 'Validating…' : 'Validate only'}</button><HelpButton content={validationHelp} onHelp={onHelp} />
      <button type="button" className="button primary" disabled={reviewReason !== null || checking} aria-describedby="draft-review-reason" onClick={onReview}><Icon name={session.reviewRequest ? 'refresh' : 'search'} size={17} className={session.reviewRequest ? 'spin' : ''} />{session.reviewRequest ? 'Reviewing…' : 'Review draft changes'}</button><HelpButton content={reviewHelp} onHelp={onHelp} />
    </div><p id="draft-validation-reason" className="toolbar-reason">Validation: {validateReason ?? 'Core format and policy checks only; no file reads or execution.'}</p><p id="draft-review-reason" className="toolbar-reason">Draft review: {reviewReason ?? 'Pure comparison and field context against the retained JSON baseline, never a save plan.'} Saving is unavailable.</p></div>
    <RemovedFields session={session} onUndo={onUndoRemoval} onForget={onForgetRemoval} />
    {session.reviewError && <ErrorNotice error={session.reviewError} title="The draft review could not be prepared" />}
    <DraftReview session={session} catalog={catalog} onRemoveForbidden={onRemoveForbidden} onHelp={onHelp} />
    {session.validationError && <ErrorNotice error={session.validationError} title="The draft could not be validated" />}
    {session.validation && <section className="card validation-card" aria-live="polite"><SectionHeading title={validationFresh(session) ? session.validation.valid ? 'Format validation complete' : 'Review these configuration issues' : 'An earlier draft was validated'} description={validationFresh(session) ? 'Validation did not save your draft or check native tools, credentials, Git, metadata files, or Store state.' : 'This result no longer describes the current draft. Validate again before relying on it.'}><Badge tone={status.tone}>{status.label}</Badge></SectionHeading><Issues issues={session.validation.issues} /><div className="subtle-note"><Icon name="shield" size={16} />Release readiness remains unknown, regardless of the format result.</div></section>}
  </>;
}
