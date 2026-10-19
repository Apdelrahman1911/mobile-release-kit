import { useState } from 'react';
import { fieldsFor } from '../catalog.ts';
import { draftStatus } from '../certainty.ts';
import { saveHelp } from '../configEdit.ts';
import { isDirty, savedRevisionFresh, validationFresh } from '../drafts.ts';
import { guidedConfiguration, guidedConfigFieldMatches } from '../guidedConfiguration.ts';
import type { ProjectSession } from '../drafts.ts';
import type { ProjectPathControls } from '../projectPaths.ts';
import type { Catalog, HelpContent, JsonValue } from '../types.ts';
import { Badge, EmptyState, ErrorNotice, HelpButton, Issues, SectionHeading } from './Common.tsx';
import { DraftField } from './Fields.tsx';
import { Icon } from './Icon.tsx';
import { DraftReview, reviewHelp } from './DraftReview.tsx';
import { DraftSuggestions } from './DraftSuggestions.tsx';
import { GuidedConfigurationFields } from './GuidedConfigurationFields.tsx';
import { RemovedFields } from './RemovedFields.tsx';

const validationHelp: HelpContent = {
  label: 'Validate draft', requiredness: 'optional',
  requiredWhen: 'Available when a draft and a compatible native core are loaded.',
  what: 'Check an in-memory draft against the bundled core’s configuration policy.',
  why: 'Find format and policy errors before a separate native save review, when that capability is available.',
  where: 'Use Validate draft after editing the project settings or metadata fields.',
  format: 'The current structured draft is sent to the read-only core. Nothing is saved.',
  failure: 'An error leaves your draft intact. Format-valid does not verify files, commands, identities, credentials, tools, Git, or Store readiness.',
};

interface EditorProps {
  catalog: Catalog | null;
  session: ProjectSession | null;
  metadataOnly?: boolean;
  preview: boolean;
  chooseReason: string | null;
  pathPicker: ProjectPathControls;
  validateReason: string | null;
  reviewReason: string | null;
  suggestReason: string | null;
  saveReason: string | null;
  discardReason: string | null;
  onChoose: () => void;
  onNewDraft: () => void;
  onEdit: (path: string, value: JsonValue | undefined) => void;
  onValidate: () => void;
  onReview: () => void;
  onSuggest: () => void;
  onPrepareSave: () => void;
  onAdoptSuggestion: (requestId: number) => void;
  onRemoveForbidden: (reviewId: number, paths: string[]) => void;
  onUndoRemoval: (id: number) => void;
  onForgetRemoval: (id: number) => void;
  onDiscard: () => void;
  onHelp: (help: HelpContent) => void;
}

export function DraftEditor({ catalog, session, metadataOnly = false, preview, chooseReason, pathPicker, validateReason, reviewReason, suggestReason, saveReason, discardReason, onChoose, onNewDraft, onEdit, onValidate, onReview, onSuggest, onPrepareSave, onAdoptSuggestion, onRemoveForbidden, onUndoRemoval, onForgetRemoval, onDiscard, onHelp }: EditorProps) {
  const [search, setSearch] = useState('');
  if (!session) return <div className="card"><EmptyState icon="folder" title="First, choose a project" description="The native folder picker establishes the project boundary. Drafts remain separate for every project you open."><button className="button primary" disabled={chooseReason !== null} aria-describedby={chooseReason ? 'draft-choose-reason' : undefined} onClick={onChoose}><Icon name="folder" size={17} />{preview ? 'Load example workspace' : 'Choose project folder'}</button>{chooseReason && <p id="draft-choose-reason" className="toolbar-reason">{chooseReason}</p>}</EmptyState></div>;
  if (!catalog) return <div className="card"><EmptyState icon="settings" title="The field catalogue is unavailable" description="A compatible core must provide the schema and contextual help before configuration controls are enabled. No fallback policy is substituted." /></div>;
  if (!session.draft) return <>
    <div className="card"><EmptyState icon="metadata" title={session.snapshotRequest ? 'Reading the static configuration…' : 'No editable configuration loaded'} description={session.snapshotRequest ? 'The engine reads only a bounded selection of static files. No project code runs.' : 'Prepare a suggested draft below, review its defaults, then choose whether to use it. Or start empty. Neither choice saves files.'}>{!session.snapshotRequest && <button className="button secondary" onClick={onNewDraft}><Icon name="plus" size={17} />Start an empty draft</button>}</EmptyState></div>
    {session.snapshot?.config.state === 'invalid' && <div className="notice notice-warning"><Icon name="info" size={18} /><div><strong>The observed configuration is invalid or unsupported</strong><p>It remains read-only. A new in-memory draft is not permission to overwrite or repair that file.</p></div></div>}
    <DraftSuggestions session={session} reason={suggestReason} onSuggest={onSuggest} onAdopt={onAdoptSuggestion} onHelp={onHelp} />
  </>;

  const draft = session.draft;
  const dirty = isDirty(session);
  const saved = savedRevisionFresh(session);
  const status = draftStatus(session);
  const metadataContext = metadataOnly ? guidedConfiguration(catalog, session, session.project.id, preview) : null;
  const contextFresh = metadataContext?.context === 'current';
  const checking = session.validationRequest !== null || session.reviewRequest !== null;
  const statusText = saved && !checking ? 'Changes saved' : status.label;
  const metadataFields = metadataOnly ? fieldsFor(catalog, ['metadata']) : [];
  const count = metadataFields.filter((field) => guidedConfigFieldMatches(field, search, pathPicker.pendingField)).length;
  return <>
    <div className="draft-banner"><Icon name="metadata" size={21} /><div><strong>{preview ? 'Example draft · no project files' : saved ? 'Changes saved' : dirty ? 'Draft not saved yet' : 'No unsaved changes'}</strong><p>Switching projects keeps your edits. Closing the app loses unsaved drafts. Use <strong>Review &amp; save…</strong> to inspect changes before confirming.</p>
      <details className="context-details"><summary>How drafts and saving work</summary><p>Drafts and undo copies stay in memory. Refresh updates a separate file observation; it never replaces this draft or its retained comparison baseline. Native saving checks two destinations: <code>release/mobile-release.json</code> and <code>.gitignore</code>. Closing that review keeps the draft without saving. A confirmed save describes only the exact submitted revision; later edits need another review. A no-change result confirms the reviewed values were already saved, not build or release readiness.</p></details>
    </div><Badge tone={dirty ? 'warning' : 'neutral'} dot>{dirty ? 'Unsaved changes' : saved ? 'Saved' : 'No unsaved changes'}</Badge></div>
    {metadataOnly && <p className="metadata-config-prerequisite">Public-text saving uses only <code>release/mobile-release.json</code> already on disk. Use this separate configuration save to review root/locale changes and the fixed metadata journal rules in <code>.gitignore</code>, even when configuration JSON is unchanged. Conflicting ignore rules require explicit reconciliation. Configuration save never saves or discards a text draft; text save never changes configuration or ignore rules.</p>}
    {session.lastSave && !saved && <div className="notice notice-info"><Icon name="info" size={18} /><div><strong>{session.lastSave.result === 'saved' ? 'Earlier changes were saved' : 'An earlier save check found no changes'}</strong><p>Your newer edits are still in this draft; that earlier check did not save or replace them. Keep editing, then review and save when ready.</p></div></div>}
    {session.snapshotPredatesSave && <p className="context-refresh-note">The file check shown here is from before your last save. Refresh to check the saved files; your draft will be kept.</p>}
    {session.sourceChanged && <div className="notice notice-warning"><Icon name="info" /><div><strong>Project files changed outside this draft</strong><p>Your draft has been kept. Keep editing, or choose <strong>Discard draft &amp; reload…</strong> below to replace it with the last checked file contents. Nothing is merged automatically.</p></div></div>}
    {session.snapshotError && <ErrorNotice error={session.snapshotError} title="Refresh failed; your draft was preserved" />}
    {session.editError && <ErrorNotice error={session.editError} title="The draft was not changed" />}
    {metadataOnly && !contextFresh && <p className="context-refresh-note">Current field requirements have not been reviewed. Use <strong>Review draft changes</strong> for core-derived requirements and conflicts. No dependent values are automatically removed.</p>}
    <p className="context-refresh-note">{preview ? 'Example folder only: ' : 'Selected project folder: '}<code>{session.project.path}</code>. Browse existing items inside this folder. Choosing one only edits this draft; it does not create or save files.</p>
    {metadataOnly ? <div className="guided-configuration">
      <div className="editor-controls"><label className="search-field"><Icon name="search" size={17} /><span className="sr-only">Search metadata fields</span><input type="search" value={search} disabled={pathPicker.pendingField !== null} placeholder="Find a setting…" onChange={(event) => { if (pathPicker.pendingField === null) setSearch(event.target.value); }} /></label></div>
      <section className="card form-card" hidden={count === 0}><SectionHeading title="1. Configure the saved locale context" description="Configure the public metadata root and locales. These are configuration settings, not locale text; changing or removing a locale never deletes its files." />
        <div className="form-grid">{metadataFields.map((field) => <div key={field.path} className={`guided-config-field${['string-list', 'argv', 'commands'].includes(field.input) ? ' full-width' : ''}`} hidden={!guidedConfigFieldMatches(field, search, pathPicker.pendingField)}>
          <DraftField field={field} draft={draft} context={metadataContext?.contexts.get(field.path)} contextFresh={contextFresh} pathPicker={pathPicker} onChange={onEdit} onHelp={onHelp} />
        </div>)}</div>
      </section>
      {count === 0 && <div className="card"><EmptyState compact icon="search" title="No matching metadata settings" description="Try a different term." /></div>}
    </div> : <GuidedConfigurationFields catalog={catalog} session={session} preview={preview} pathPicker={pathPicker} reviewReason={reviewReason} onReview={onReview} onEdit={onEdit} onHelp={onHelp} />}
    <div className="draft-toolbar"><div className="draft-toolbar-status"><Badge tone={status.tone}>{statusText}</Badge><span>Changes stay in this draft</span></div><div className="button-row">
      <button type="button" className="text-button" disabled={discardReason !== null || (!dirty && !session.sourceChanged && session.removedFields.length === 0)} title={discardReason ?? undefined} onClick={onDiscard}>{session.sourceChanged ? 'Discard draft & reload…' : 'Discard draft changes'}</button>
      <button type="button" className="button secondary" disabled={saveReason !== null} aria-describedby="draft-save-reason" onClick={onPrepareSave}>Review &amp; save…<Icon name={saveReason === null ? 'search' : 'lock'} size={14} /></button><HelpButton content={saveHelp} onHelp={onHelp} />
      <button type="button" className="button secondary" disabled={validateReason !== null || checking} aria-describedby="draft-validation-reason" onClick={onValidate}><Icon name={session.validationRequest ? 'refresh' : 'check'} size={17} className={session.validationRequest ? 'spin' : ''} />{session.validationRequest ? 'Validating…' : 'Validate only'}</button><HelpButton content={validationHelp} onHelp={onHelp} />
      <button type="button" className="button primary" disabled={reviewReason !== null || checking} aria-describedby="draft-review-reason" onClick={onReview}><Icon name={session.reviewRequest ? 'refresh' : 'search'} size={17} className={session.reviewRequest ? 'spin' : ''} />{session.reviewRequest ? 'Reviewing…' : 'Review draft changes'}</button><HelpButton content={reviewHelp} onHelp={onHelp} />
    </div><p id="draft-save-reason" className="toolbar-reason">Saving: {saveReason ?? 'Opens a separate review of the files to be saved. Nothing is written until you confirm Apply in that review.'}</p>{discardReason && <p className="toolbar-reason">Before discarding: {discardReason}</p>}<p id="draft-validation-reason" className="toolbar-reason">Validation: {validateReason ?? 'Checks the draft’s format only. It does not save files or test a build.'}</p><p id="draft-review-reason" className="toolbar-reason">Draft review: {reviewReason ?? 'Shows changes and missing or conflicting settings. It does not save files.'}</p></div>
    <RemovedFields session={session} onUndo={onUndoRemoval} onForget={onForgetRemoval} />
    {session.reviewError && <ErrorNotice error={session.reviewError} title="The draft review could not be prepared" />}
    <DraftReview session={session} catalog={catalog} onRemoveForbidden={onRemoveForbidden} onHelp={onHelp} />
    {session.validationError && <ErrorNotice error={session.validationError} title="The draft could not be validated" />}
    {session.validation && <section className="card validation-card" aria-live="polite"><SectionHeading title={validationFresh(session) ? session.validation.valid ? 'Format validation complete' : 'Review these configuration issues' : 'An earlier draft was validated'} description={validationFresh(session) ? 'Validation did not save your draft or check native tools, credentials, Git, metadata files, or Store state.' : 'This result no longer describes the current draft. Validate again before relying on it.'}><Badge tone={status.tone}>{statusText}</Badge></SectionHeading><Issues issues={session.validation.issues} /><div className="subtle-note"><Icon name="shield" size={16} />Release readiness remains unknown, regardless of the format result.</div></section>}
  </>;
}
