import { useId, useState, useSyncExternalStore } from 'react';
import type { HelpContent } from '../types.ts';
import type { RequiredNotesGuide } from '../requiredNotes.ts';
import { requiredNoteByteLimit } from '../requiredNotes.ts';
import { metadataLineEndings } from '../metadataText.ts';
import { REQUIRED_NOTES_ERRORS } from '../requiredNotesController.ts';
import type { RequiredNotesController, RequiredNotesIntent } from '../requiredNotesController.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';

// The App coordinator binds separate genuine read/edit/import capabilities and
// dispatches only through the original native owner; never a CLI/path shim.
export function RequiredNotesEditor({ controller, guide, onRequest, onCloseReview, onHelp, readAvailable, writeAvailable,
  importAvailable, validateAvailable, readReason, writeReason, importReason, validateReason }: {
  controller: RequiredNotesController;
  guide: RequiredNotesGuide;
  onRequest: (request: RequiredNotesIntent) => void;
  onCloseReview: (sessionId: string) => void;
  onHelp: (help: HelpContent) => void;
  readAvailable: boolean;
  writeAvailable: boolean;
  importAvailable: boolean;
  validateAvailable: boolean;
  readReason: string | null;
  writeReason: string | null;
  importReason: string | null;
  validateReason: string | null;
}) {
  const id = useId(), state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const [confirmation, setConfirmation] = useState<'load' | 'import' | 'discard' | null>(null);
  const scope = state.scope, kind = scope?.context.kind;
  const field = guide.fields.find((row) => row.id === kind);
  const help = (action: string) => guide.actions.find((row) => row.id === action);
  const actionHelp = (action: string) => { const item = help(action); return item ? <HelpButton content={item} onHelp={onHelp} /> : null; };
  const send = (request: RequiredNotesIntent | null) => { if (request) onRequest(request); };
  const ownerBusy = controller.nativeBusy(), pending = state.pending !== null;
  const locked = pending || ownerBusy || state.stale;
  const loaded = state.loaded, review = state.prepared;
  const valid = state.validation?.valid === true && state.validationRevision === state.draftRevision;
  const selected = loaded?.selection;
  const normalTitle = state.result === 'saved' ? 'Save confirmed' : state.result === 'unchanged' ? 'No file changes needed' : ownerBusy ? 'Original operation active' : controller.dirty() ? 'Unsaved draft' : 'Local note editor';
  return <section className="card required-notes-editor" aria-labelledby={id + '-title'}>
    <SectionHeading title="Required release and review notes" description="Write instructions in the application; it selects the correct configured file. Saving here never uploads metadata or publishes a release.">
      <Badge tone={state.unsettled ? 'warning' : state.result ? 'info' : 'neutral'}>{normalTitle}</Badge>
    </SectionHeading>
    <h3 id={id + '-title'} className="sr-only">Required release and review notes</h3>
    {!scope || !field ? <p>Select a project and a required note above. Android notes also need a saved configured locale.</p> : <>
      <p><strong>{scope.projectName}</strong> · {field.label}{'locale' in scope.context && <> · {scope.context.locale}</>}
        {selected?.savedBuild !== null && selected?.savedBuild !== undefined && <> · Saved build {selected.savedBuild}</>}</p>
      {state.stale && <p className="review-caution">Earlier project/configuration context only. No new operation may use this draft until the original work settles and the current context is selected again.</p>}
      <p className="save-note">{field.what} <HelpButton content={field} onHelp={onHelp} /></p>
      <p className="save-note">Audience: {field.audience === 'public-play' ? 'People viewing the Google Play release' : field.audience === 'apple-review' ? 'Apple reviewers' : 'Configured TestFlight testers'}.
        {field.audience === 'apple-review' && ' The saved file is ordinary local repository text, not secure credential storage. Configure contact and demo credentials separately.'}</p>
      {!readAvailable && <p className="review-caution">Load: {readReason ?? 'The native saved-note reader is unavailable.'}</p>}
      {!writeAvailable && <p className="review-caution">Review and Save: {writeReason ?? 'The native note writer is unavailable.'}</p>}
      {!importAvailable && <p className="save-note">Select text file: {importReason ?? 'The native text picker is unavailable.'}</p>}
      {!validateAvailable && <p className="save-note">Check format: {validateReason ?? 'The core validator is unavailable.'}</p>}
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!readAvailable || locked} onClick={() => controller.dirty() ? setConfirmation('load') : send(controller.beginLoad())}>
          {state.needsReload ? 'Reload saved note' : 'Load saved note'}</button>{actionHelp('load')}
      </div>
      {selected && <>
        <p className="save-note">Selected file: <code>{selected.destination}</code>. {loaded?.original.state === 'absent' ? 'Missing; Save can create it after review.' : 'Loaded from the selected project.'}</p>
        {selected.effective && <p className={selected.effective.valid ? 'save-note' : 'review-caution'}>
          For saved build {selected.savedBuild}, the core selects {selected.effective.source === 'exact' ? 'the exact-build note' : selected.effective.source === 'default' ? 'the default note' : 'no existing note'}.
          {selected.effective.source !== 'missing' && !selected.effective.valid && ' That effective note needs correction; a different valid file does not hide the problem.'}
          {kind === 'android-default' && selected.effective.source === 'exact' && ' This default is shadowed. Saving it will not change the exact-build note.'}
        </p>}
      </>}
      {loaded && <>
        <label className="field-label" htmlFor={id + '-text'}>{field.label} <HelpButton content={field} onHelp={onHelp} /></label>
        <textarea id={id + '-text'} value={state.draft} disabled={locked || state.needsReload} rows={10} spellCheck={true}
          aria-describedby={id + '-format'} onChange={(event) => controller.edit(event.currentTarget.value)} />
        <p id={id + '-format'} className="save-note">{field.format} Editor byte cap: {requiredNoteByteLimit(kind!)}. Original line endings and whitespace are not silently changed on Save.</p>
        {state.needsReload && <p className="review-caution">The last operation does not provide a new observed baseline. Reload before another edit; your current text remains visible.</p>}
        <div className="button-row">
          <button type="button" className="button secondary" disabled={!validateAvailable || locked || state.needsReload} onClick={() => send(controller.beginValidate())}>Check format</button>{actionHelp('validate')}
          <button type="button" className="button secondary" disabled={!importAvailable || locked || state.needsReload}
            onClick={() => state.draft !== '' ? setConfirmation('import') : send(controller.beginImport())}>Select text file</button>{actionHelp('import')}
          <button type="button" className="button secondary" disabled={!writeAvailable || locked || state.needsReload || !valid} onClick={() => send(controller.beginPrepare())}>Review change</button>{actionHelp('review')}
          <button type="button" className="button secondary" disabled={pending || ownerBusy} onClick={() => setConfirmation('discard')}>Discard draft</button>{actionHelp('discard')}
        </div>
        {state.validation && state.validationRevision === state.draftRevision && <div aria-live="polite">
          <p><Badge tone={valid ? 'info' : 'warning'}>{valid ? 'Local format-valid' : 'Selected note needs text or corrections'}</Badge> No Store has accepted or published this note.</p>
          {state.validation.characterCount !== null && <p className="save-note">Core preflight count: {state.validation.characterCount}{state.validation.characterLimit !== null ? ' / ' + state.validation.characterLimit : ' (no field-specific character limit in the current core)'}.
            {state.validation.rawByteCount !== null && <> Original UTF-8: {state.validation.rawByteCount} bytes.</>}</p>}
          {state.validation.outboundCharacterCount !== null && <p className="save-note">Count after the existing Apple-bound whitespace trimming: {state.validation.outboundCharacterCount}. The file itself is not trimmed.</p>}
          <ul className="issues">{state.validation.issues.map((issue) => <li key={issue.code}><div>{issue.message}</div></li>)}</ul>
        </div>}
      </>}
      {pending && <p role="status">{state.pending === 'load' ? 'Reading the selected saved note' : state.pending === 'import' ? 'Waiting for the original native text selection and validation' : state.pending === 'prepare' ? 'Preparing the original-owner-bound review' : state.pending === 'apply' ? 'Waiting for the original Save outcome and finality' : state.pending === 'close' ? 'Closing the original review; keeping the draft' : 'Checking the draft with the core'}…</p>}
      {review && <section className="review-panel" aria-labelledby={id + '-review'}>
        <h4 id={id + '-review'}>Review one local note change</h4>
        <p><code>{review.selection.destination}</code> · {review.action}</p>
        <p className="review-caution">Only this selected note is writable. Config, version, other locales and signing inputs are not changed. Saving does not contact a Store.</p>
        {review.before.state === 'present' && metadataLineEndings(review.before.text) !== metadataLineEndings(review.after) && <p className="review-caution">Line endings change from {metadataLineEndings(review.before.text)} to {metadataLineEndings(review.after)}. The exact reviewed After bytes, not the old line endings, will be saved. Cancel if this was not intended.</p>}
        <div className="review-columns"><div><h5>Before</h5><pre>{review.before.state === 'absent' ? '(File absent)' : review.before.text}</pre></div>
          <div><h5>After</h5><pre>{review.after}</pre></div></div>
        {review.createDirectories.length > 0 && <p>Missing directories to create: {review.createDirectories.join(', ')}</p>}
        <div className="button-row"><button type="button" className="button primary" disabled={!writeAvailable || !controller.canApply()} onClick={() => send(controller.beginApply())}>Save this reviewed note</button>{actionHelp('save')}
          <button type="button" className="button secondary" disabled={!controller.canClose()}
            onClick={() => onCloseReview(review.sessionId)}>Cancel review; keep draft</button></div>
        {!state.status && <p role="status">Waiting for the matching original owner's content-free review status. Save is unavailable until it is accepted.</p>}
      </section>}
    </>}
    {state.error && <p className="review-caution" role="alert">{REQUIRED_NOTES_ERRORS[state.error]}</p>}
    {confirmation && <div className="review-caution" role="group" aria-label="Confirm draft replacement">
      <p>{confirmation === 'discard' ? 'Discard this in-memory note draft? Saved files and other editors are not deleted.' : confirmation === 'load' ?
        'Replace your unsaved draft with the saved note after a successful read? Cancel keeps this draft.' :
        'Replace this draft only if the selected text file is safely read and valid? The original file is not moved or changed; cancellation/failure keeps the draft.'}</p>
      <div className="button-row"><button type="button" className="button secondary" onClick={() => setConfirmation(null)}>Keep current draft</button>
        <button type="button" className="button danger" disabled={pending || ownerBusy || confirmation === 'load' && (!readAvailable || state.stale) || confirmation === 'import' && (!importAvailable || state.stale)} onClick={() => {
          const action = confirmation; setConfirmation(null);
          if (action === 'discard') controller.discardDraft(true);
          else send(action === 'load' ? controller.beginLoad(true) : controller.beginImport(true));
        }}>{confirmation === 'discard' ? 'Discard draft' : 'Confirm and continue'}</button></div>
    </div>}
  </section>;
}
