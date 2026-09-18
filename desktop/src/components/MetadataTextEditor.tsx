import { useEffect, useId, useRef, useState } from 'react';
import { metadataCacheBytes, metadataLineEndings, metadataNoOp, metadataTextDirty, metadataTextSavedFresh } from '../metadataText.ts';
import type { MetadataActionId, MetadataPreparedFile, MetadataTextEditProjection, PreparedMetadataTextView } from '../metadataText.ts';
import { currentMetadataApplyBinding } from '../metadataTextEditController.ts';
import type { MetadataApplyBinding, MetadataDiscardBinding, MetadataTextEditController, MetadataTextState } from '../metadataTextEditController.ts';
import { normalMetadataTextResult } from '../metadataTextProtocol.ts';
import type { ProjectSession } from '../drafts.ts';
import type { HelpContent } from '../types.ts';
import { Badge, EmptyState, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

function ActionHelp({ state, id, onHelp }: { state: MetadataTextState; id: MetadataActionId; onHelp: (help: HelpContent) => void }) {
  const help = state.help?.actions.find((action) => action.id === id);
  return help ? <HelpButton content={help} onHelp={onHelp} /> : null;
}
function RawText({ file, side }: { file: MetadataPreparedFile; side: 'before' | 'after' }) {
  const value = side === 'before' ? file.before.state === 'present' ? file.before : null : file.after;
  return <section className="metadata-raw"><h4>{side === 'before' ? 'Original bytes' : 'Reviewed replacement bytes'}</h4>
    {value ? <><p>{value.byteLength.toLocaleString()} UTF-8 bytes · {metadataLineEndings(value.text)} · {value.text.endsWith('\n') || value.text.endsWith('\r') ? 'Final line ending present' : 'No final line ending'}</p>
      <code className="metadata-digest">SHA256 {value.sha256}</code><pre tabIndex={0} aria-label={`${side === 'before' ? 'Complete original' : 'Complete reviewed'} public text for ${file.path}`}><code>{value.text}</code></pre></> : <p>Observed absent. No original text was fabricated.</p>}
  </section>;
}
function FileReview({ view }: { view: PreparedMetadataTextView }) {
  return <div className="metadata-native-review">
    <p className="review-caution">Review all {view.files.length} files for {view.platform} / {view.locale}. {metadataNoOp(view) ? 'No files need changing. Confirmation rechecks them before reporting success.' : 'Files are saved one at a time with recovery protection; the whole bundle does not change at once.'} Configuration and .gitignore are checked but never changed here.</p>
    <div className="review-table-wrap"><table className="review-table"><caption>Files in this review</caption><thead><tr><th scope="col">Destination</th><th scope="col">Action</th><th scope="col">Before → after</th><th scope="col">Line-ending styles</th></tr></thead>
      <tbody>{view.files.map((file) => <tr key={file.id}><th scope="row"><code>{file.path}</code></th><td>{file.action === 'preserve' ? 'Preserve exact original' : file.action === 'create' ? 'Create absent file' : 'Replace reviewed original'}</td>
        <td>{file.before.state === 'absent' ? 'Absent' : `${file.before.byteLength} bytes`} → {file.after.byteLength} bytes</td><td>{file.lineEndingsChanged ? 'Changed — inspect below' : 'Unchanged'}</td></tr>)}</tbody></table></div>
    <p className="save-note">{view.createDirectories.length ? <>Only these observed-missing directories may be created: {view.createDirectories.map((path) => <code key={path}>{path} </code>)}.</> : 'No missing directories need to be created.'} Exact-preserved files keep their bytes, mode and identity. No file is deleted or renamed.</p>
    {view.files.map((file) => <details className="metadata-file-review" key={file.id}><summary><code>{file.path}</code><Badge tone={file.action === 'preserve' ? 'neutral' : 'warning'}>{file.action}</Badge></summary>
      <p>Complete before/after text, not a truncated diff. Browser display cannot show CR/LF byte distinctions visually; the explicit style summaries, byte lengths and native digests describe the frozen payloads. No trimming or BOM removal is implied.</p>
      <div className="metadata-raw-grid"><RawText file={file} side="before" /><RawText file={file} side="after" /></div>
    </details>)}
    <p className="subtle-note">Only this required public-text bundle passed core format validation. Other locales, screenshots, hidden files, historical changelogs, private review/TestFlight data, archives and Store readiness remain uninspected.</p>
  </div>;
}
function SaveConfirmation({ view, allowed, onCancel, onConfirm }: { view: PreparedMetadataTextView; allowed: boolean; onCancel: () => void; onConfirm: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null); const titleId = useId(); const inputId = useId();
  const [confirmation, setConfirmation] = useState(''); const [reviewed, setReviewed] = useState(false);
  useEffect(() => { const element = dialog.current; element?.showModal(); return () => { if (element?.open) element.close(); }; }, []);
  return <dialog ref={dialog} className="confirm-dialog metadata-confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}><div className="dialog-content">
    <h2 id={titleId}>{metadataNoOp(view) ? 'Confirm this unchanged bundle?' : 'Save this reviewed locale bundle?'}</h2>
    <p>Save only the reviewed public text for <strong>{view.platform} / {view.locale}</strong>. Files are checked again before saving. Closing this dialog keeps your draft.</p>
    <ul className="metadata-confirm-files">{view.files.map((file) => <li key={file.id}><code>{file.path}</code> — {file.action}</li>)}</ul>
    <label className="save-confirm-check"><input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />I reviewed all exact paths, full original/replacement text, digests and line-ending changes.</label>
    <label htmlFor={inputId}>Type <strong>SAVE</strong> to confirm only this local text operation</label><input id={inputId} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="off" spellCheck={false} />
    <p>No configuration, credentials, screenshots, Git/index changes, Store synchronization or release operation is included. A save already submitted may finish after cancellation.</p>
    <details><summary>Save safeguards</summary><p>Only this original one-use native plan is submitted. There is no force, automatic rebase, replacement token or automatic retry. All original dependencies and targets must still match.</p></details>
    {!allowed && <p className="review-caution" role="alert">This review is no longer current. Your draft is kept. Check this operation’s status before starting a new review.</p>}
    <div className="button-row"><button autoFocus type="button" className="button secondary" onClick={onCancel}>Keep reviewing</button><button type="button" className="button primary" disabled={!allowed || !reviewed || confirmation !== 'SAVE'} onClick={onConfirm}>{metadataNoOp(view) ? 'Confirm unchanged text' : 'Save text'}</button></div>
  </div></dialog>;
}
function operationNotice(owner: MetadataTextEditProjection): { title: string; detail: string; technical?: string; danger: boolean } {
  const core = owner.coreOutcome;
  if (owner.phase === 'unknown' || owner.nativeFinality === 'unknown') return { title: core?.effect === 'committed' ? 'Text written; completion not confirmed' : 'Text save or cleanup is unconfirmed', danger: true,
    detail: `${core?.effect === 'committed' ? 'The reviewed text was written, but cleanup is not confirmed.' : owner.applySubmitted ? 'The save may already have happened.' : 'No save request is recorded, but cleanup is not confirmed.'} Keep recovery files and operation details. Do not save again, delete journals or assume changes were undone.`,
    technical: 'Known original outcome evidence is retained. Late native settlement does not clear earlier uncertainty or authorize another edit.' };
  if (core?.journal === 'recovery_required') return { title: core.effect === 'committed' ? 'Text written; recovery needs attention' : 'Text recovery needs attention', danger: true,
    detail: 'Keep the recovery files and any outside changes. Automatic recovery after closing or crashing is not available. Saving through another editor cannot bypass this block.',
    technical: 'Only the original in-session recovery attempt was available. Persisted/crash recovery is not implemented; the recovery_required journal remains protected across edit domains.' };
  const normal = normalMetadataTextResult(owner);
  if (normal) return { title: normal === 'saved' ? 'Text saved' : 'Text checked; no changes needed', danger: false,
    detail: normal === 'saved' ? 'The reviewed text was saved and cleanup completed. Any newer draft and your configuration are unchanged.' : 'All reviewed files were rechecked and left unchanged.',
    technical: normal === 'saved' ? 'The original native owner confirmed committed effect, a clean journal and full settlement. Only matching submitted text may advance its own baseline.' : 'The original owner created no journal and fully settled. Original bytes, modes and file identity were preserved.' };
  if (owner.phase === 'final') return { title: core?.effect === 'committed' ? 'Text written; completion needs attention' : core?.effect === 'rolled_back' ? 'This save’s changes were undone' : 'Text review ended; draft kept', danger: core?.effect === 'committed',
    detail: core?.reason === 'ignore_conflict' ? 'Required metadata journal ignore coverage is absent or ambiguous. Use the separate configuration save to review its fixed .gitignore additions; text save cannot modify or bypass ignore rules.' :
      core?.reason === 'stale_revision' ? 'A file, folder, saved configuration or ignore rule changed. Your draft was not merged or saved over it. Refresh and compare the new observation before another review.' :
      core?.reason === 'invalid_params' ? 'The text was refused. Use Validate text for field-specific guidance. Your draft is kept.' :
      core?.effect === 'committed' ? 'Do not save again. The reviewed text was written, but interruption or cleanup needs attention.' :
      core?.effect === 'rolled_back' ? 'Only this save’s changes were undone, not unrelated changes. Your text draft remains in memory.' : 'No successful save is confirmed. Closing or refusing the review did not discard text or save configuration.' };
  if (owner.phase === 'reviewing') return { title: 'Review text changes', danger: false, detail: 'Nothing has been saved. Check every file below, then confirm the whole bundle—or close the review and keep your draft.' };
  if (owner.phase === 'applying') return { title: 'Saving text…', danger: false, detail: 'Wait for confirmation before assuming the save succeeded. Newer draft changes are kept. Do not save again.', technical: 'Apply admission is not finality. The original core outcome and native resource settlement are still pending.' };
  if (owner.phase === 'finalizing') return { title: 'Finishing the text operation…', danger: false, detail: 'Cancellation may be too late to stop the save. Wait for the result; do not assume changes were undone or cleanup succeeded.', technical: 'Original core outcome and native resource settlement remain authoritative.' };
  return { title: owner.phase === 'opening' ? 'Checking the saved locale…' : 'Preparing text changes…', danger: false, detail: 'Checking the saved configuration, ignore rules and selected text files. No text or directories are written during review.', technical: 'The native owner captures the registered project and original config, ignore, ancestor and target bindings before Prepare.' };
}

export function MetadataTextSave({ state, controller, detailed, onShowProject, onHelp }: {
  state: MetadataTextState; controller: MetadataTextEditController; detailed: boolean;
  onShowProject: (projectId: string, key?: string) => void; onHelp: (help: HelpContent) => void;
}) {
  const [confirmation, setConfirmation] = useState<MetadataApplyBinding | null>(null);
  const [, refreshClock] = useState(0);
  const edit = state.edit; const attempt = edit.attempt;
  const owner = attempt?.projection ?? edit.unknownEvidence ?? edit.status?.active ?? edit.status?.lastTerminal;
  const binding = currentMetadataApplyBinding(state);
  const owned = Boolean(attempt && owner?.sessionId === attempt.sessionId);
  const terminal = owner?.phase === 'final' || owner?.phase === 'unknown';
  const showReview = detailed && state.projectId === owner?.projectId && owner?.prepared;
  const notice = owner ? operationNotice(owner) : null;
  useEffect(() => {
    if (owner?.phase !== 'reviewing') return;
    // UI estimate only. Samples can shorten this deadline, never renew it;
    // native admission independently checks the original absolute lifetime.
    const timer = setInterval(() => refreshClock((value) => value + 1), 1000);
    return () => clearInterval(timer);
  }, [owner?.phase, owner?.sessionId]);
  useEffect(() => { if (confirmation && (!detailed || !controller.canApply(confirmation))) setConfirmation(null); }, [confirmation, detailed, state, controller]);
  if (!notice && !attempt && !edit.observationIssue && !edit.nativeBlocked) return null;
  return <section className="card metadata-save-panel" aria-label="Original metadata file-save operation">
    <SectionHeading title={edit.integrityFailed ? 'Text status could not be verified' : notice?.title ?? 'Waiting for text review…'} description="Local text files only. This operation does not change configuration or Store listings.">
      <ActionHelp state={state} id="save" onHelp={onHelp} />
    </SectionHeading>
    {(edit.integrityFailed || edit.observationIssue) && <p className="review-caution" role="alert">This operation’s status is unavailable or contradictory. Keep your drafts and known result details. A missing reply does not mean it is safe to start or submit the save again.</p>}
    {notice && <div className={`notice notice-${notice.danger ? 'danger' : 'info'}`} role={notice.danger ? 'alert' : 'status'}><Icon name="shield" size={18} /><p>{notice.detail}</p></div>}
    {owner && !owned && <p className="save-note">Read-only summary. This view cannot confirm a save it did not start.</p>}
    {attempt?.invalidated && !terminal && <p className="review-caution">The selection, configuration, text or connection changed before saving. This review is closing; your draft is kept. A late reply cannot make the old review current again.</p>}
    {attempt?.closeRequested && !terminal && <p className="review-caution">{attempt.applyClaimed ? 'Cancellation requested; the save result is still pending.' : 'Closing the review, not deleting the draft. Wait for confirmation.'}</p>}
    {attempt?.applyClaimed && owner?.phase === 'reviewing' && <p role="status">Save was requested once. Wait for confirmation; do not submit it again.</p>}
    {edit.nativeBlocked && <p className="review-caution" role="alert">Native cleanup uncertainty blocks all edit domains even if an earlier result was saved. Preserve evidence; no generic journal reset or recovery retry is available.</p>}
    {owner && <p className="save-note">{state.entries[attempt?.binding.key ?? '']?.projectName ?? owner.projectId} · {owner.platform} / {owner.locale}</p>}
    {owner && <details className="metadata-outcome-details"><summary>Save and recovery details</summary>{notice?.technical && <p>{notice.technical}</p>}<dl className="save-outcome-facts"><div><dt>Original project / locale</dt><dd>{state.entries[attempt?.binding.key ?? '']?.projectName ?? owner.projectId} · {owner.platform} / {owner.locale}</dd></div>
      <div><dt>Effect / journal</dt><dd>{owner.coreOutcome?.effect ?? 'Not reported'} / {owner.coreOutcome?.journal ?? 'Not reported'}</dd></div><div><dt>Core / native resources</dt><dd>{owner.coreOutcome?.resources ?? 'Not reported'} / {owner.nativeFinality}{owner.lateSettled ? ' · late settled' : ''}</dd></div>
      <div><dt>Reason</dt><dd>{owner.coreOutcome?.reason !== 'none' ? owner.coreOutcome?.reason ?? owner.nativeReason : owner.nativeReason}</dd></div></dl>
      <p>Only the original session and one-use plan token can authorize this operation. Known effect, journal state, core resource status and native finality are separate facts. Review lifetime uses a local estimate; the original native deadline remains authoritative.</p></details>}
    {showReview && <FileReview view={showReview.view} />}
    <div className="button-row">
      {showReview && owned && !terminal && <button type="button" className="button primary" disabled={!binding || !controller.canApply(binding)} onClick={() => { if (binding && controller.canApply(binding)) setConfirmation(binding); }}>{metadataNoOp(showReview.view) ? 'Confirm unchanged text' : 'Save text…'}<Icon name="check" size={16} /></button>}
      {attempt && !attempt.handled && !attempt.closeRequested && !edit.generationLost && !edit.nativeBlocked && !terminal && <button type="button" className="button secondary" onClick={() => controller.requestClose()}>{attempt.applyClaimed ? 'Request cancellation' : 'Close review, keep draft'}</button>}
      {owner && (!detailed || state.projectId !== owner.projectId) && <button type="button" className="button secondary" onClick={() => onShowProject(owner.projectId, attempt?.binding.key)}>View text {terminal ? 'result' : 'review'}</button>}
      {edit.mode === 'native' && <button type="button" className="button small secondary" disabled={edit.readPending} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={15} />{edit.readPending ? 'Checking status…' : 'Check save status'}</button>}
    </div>
    {owned && owner?.phase === 'reviewing' && <p className="save-note">Review expires in about {Math.ceil(controller.remainingReviewMs() / 1000)} seconds. Changing the selection, configuration or text before saving closes this review and keeps your drafts.</p>}
    {confirmation && owner?.prepared && <SaveConfirmation key={confirmation.planToken} view={owner.prepared.view} allowed={detailed && controller.canApply(confirmation)} onCancel={() => setConfirmation(null)} onConfirm={() => { controller.apply(confirmation); setConfirmation(null); }} />}
  </section>;
}

function DiscardConfirmation({ label, blocked, onCancel, onConfirm }: { label: string; blocked: string | null; onCancel: () => void; onConfirm: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null); const title = useId();
  useEffect(() => { const element = dialog.current; element?.showModal(); return () => { if (element?.open) element.close(); }; }, []);
  return <dialog ref={dialog} className="confirm-dialog" aria-labelledby={title} onCancel={onCancel}><div className="dialog-content"><h2 id={title}>{label}?</h2>
    <p>Only this in-memory public-text bundle is affected. Configuration, other locale drafts and files on disk are unchanged. No native review is closed and no text is saved by discard.</p>
    {blocked && <p className="review-caution" role="alert">{blocked}</p>}<div className="button-row"><button autoFocus type="button" className="button secondary" onClick={onCancel}>Keep draft</button><button type="button" className="button danger" disabled={blocked !== null} onClick={onConfirm}>{label}</button></div></div></dialog>;
}
export function MetadataTextEditor({ state, controller, session, onShowProject, onHelp }: {
  state: MetadataTextState; controller: MetadataTextEditController; session: ProjectSession | null;
  onShowProject: (projectId: string, key?: string) => void; onHelp: (help: HelpContent) => void;
}) {
  const id = useId(); const entry = controller.selectedEntry();
  const [discard, setDiscard] = useState<{ binding: MetadataDiscardBinding; action: 'reset' | 'latest' | 'forget'; label: string } | null>(null);
  const retained = Object.values(state.entries);
  const oldContexts = retained.filter((item) => item.context.projectId === state.projectId && !state.choices.some((choice) => choice.key === item.context.key));
  const loadReason = controller.loadReason(); const validateReason = controller.validateReason(); const reviewReason = controller.startReason();
  const currentValidation = entry ? controller.validationCurrent(entry) : false;
  const askDiscard = (key: string, action: 'reset' | 'latest' | 'forget', label: string) => {
    const binding = controller.discardBinding(key); if (binding) setDiscard({ binding, action, label });
  };
  return <>
    <section className="card metadata-text-editor" aria-labelledby={`${id}-title`}>
      <SectionHeading title="2. Edit one locale’s public text" description="Load the required three Android or five iOS text files from the saved configuration. Text drafts are separate from the configuration form above."><Badge>{state.mode === 'preview' ? 'Browser preview · unavailable' : 'Selected text only'}</Badge></SectionHeading>
      <h3 id={`${id}-title`} className="sr-only">Configured public locale text</h3>
      <p className="metadata-public-note">Public Store copy only. Never paste credentials, private review contacts, demo accounts or TestFlight notes. Secret-pattern scanning is a heuristic, not proof that arbitrary prose is secret-free. Text stays in memory, never browser storage or telemetry.</p>
      <div className="metadata-context-row"><label htmlFor={`${id}-context`}>Saved platform / locale</label><select id={`${id}-context`} value={state.selectedKey ?? ''} disabled={!session || !state.choices.length && !oldContexts.length} onChange={(event) => controller.selectContext(event.target.value)}>
        <option value="" disabled>No enabled configured locale</option><optgroup label="Current saved configuration">{state.choices.map((choice) => <option key={choice.key} value={choice.key}>{choice.platform} / {choice.locale}</option>)}</optgroup>
        {oldContexts.length > 0 && <optgroup label="Retained earlier contexts · not retargeted">{oldContexts.map((item) => <option key={item.context.key} value={item.context.key}>{item.context.platform} / {item.context.locale} · earlier configuration {item.context.configBaselineGeneration}</option>)}</optgroup>}
      </select><button type="button" className="button secondary" disabled={loadReason !== null} aria-describedby={`${id}-load-reason`} onClick={() => void controller.load()}><Icon name="refresh" size={16} />{entry?.loadRequest ? 'Loading text…' : entry?.baseline ? 'Refresh text' : 'Load public text'}</button><ActionHelp state={state} id="load" onHelp={onHelp} /></div>
      <p id={`${id}-load-reason`} className="save-note">{loadReason ?? 'Read only this locale’s required public text. Refresh shows a separate observation; it never replaces your draft or its original comparison copy.'}</p>
      {!state.help && <p className="review-caution">The packaged text-field guide is unavailable. No fallback limits, validation, observation or save result has been invented.</p>}
      {state.cacheError && <ErrorNotice error={state.cacheError} title="Text cache full; existing drafts kept" />}
      {entry?.loadError && <ErrorNotice error={entry.loadError} title="Text could not be loaded; earlier draft kept" />}
      {entry?.editError && <ErrorNotice error={entry.editError} title="The previous text draft was kept" />}
      {entry?.stale && <p className="review-caution">The observed text/configuration no longer matches this original baseline, or its observation failed. Review the newer observation below and explicitly reconcile. No automatic rebase, blank fallback or overwrite permission was granted.</p>}
      {entry?.observationPredatesSave && <p className="save-note">The passive observation predates the original settled save check. Saved facts come from that exact native plan, not a fabricated fresh file read.</p>}
      {entry?.lastSave && !metadataTextSavedFresh(entry) && <p className="review-caution">An earlier submitted text revision was {entry.lastSave.result}. Your newer draft and baseline were kept and were not marked saved. Refresh and reconcile explicitly.</p>}
      {entry?.fields && entry.baseline ? <div className="metadata-text-fields">{entry.fields.map((field, index) => {
        const guide = state.help?.fields.find((row) => row.platform === entry.context.platform && row.id === field.id);
        const original = entry.baseline!.originals[index]; const assertion = entry.baseline!.assertion.fields[index]; const result = entry.validation?.result.fields[index];
        const changed = field.text !== (original?.text ?? ''); const fieldId = `${id}-field-${index}`;
        return <div className="metadata-text-field" key={field.id}><div className="inline-heading"><label htmlFor={fieldId}>{guide?.label ?? field.id}</label><Badge tone="info">Required</Badge>
          <Badge tone={changed ? 'warning' : 'neutral'}>{changed ? 'Unsaved text' : entry.baseline!.source === 'saved' ? 'Saved baseline' : assertion?.state === 'absent' ? 'Missing · observed' : 'Observed original'}</Badge>{guide && <HelpButton content={guide} onHelp={onHelp} />}</div>
          <code>{original?.path}</code><p id={`${fieldId}-guide`}>{guide?.what ?? 'Restore the core guide before editing.'}</p>
          <textarea id={fieldId} value={field.text} disabled={!guide} rows={field.id.includes('description') || field.id === 'release_notes.txt' ? 7 : 3}
            autoComplete="off" aria-describedby={`${fieldId}-guide ${fieldId}-count`} aria-invalid={currentValidation && result ? !result.valid : undefined}
            onChange={(event) => controller.editField(entry.context.key, field.id, event.target.value)} />
          <p id={`${fieldId}-count`} className="metadata-count">{result ? `${currentValidation ? 'Core' : 'Earlier, stale core'} count: ${result.characterCount.toLocaleString()} / ${result.limit.toLocaleString()} Unicode characters` : 'No core character count yet — use Validate text.'} · {new TextEncoder().encode(field.text).byteLength.toLocaleString()} UTF-8 bytes of the 32 KiB editor budget. {original?.text !== null && original?.text !== undefined ? `Original line endings: ${metadataLineEndings(original.text)}.` : 'No original bytes.'}</p>
          <p className="save-note">{guide?.format} Untouched originals retain raw bytes. After editing, browser newline normalization is part of the new draft and must be reviewed.</p>
          {result?.issues.length ? <ul className="issues">{result.issues.map((issue) => <li key={issue.code}><Badge tone={currentValidation ? 'danger' : 'warning'}>{currentValidation ? issue.status : 'Earlier result'}</Badge><div><strong>{issue.message}</strong><code>{issue.code}</code></div></li>)}</ul> : null}
        </div>;
      })}</div> : <EmptyState compact icon="metadata" title={entry?.loadRequest ? 'Reading only the selected public text…' : 'No public text has been loaded'} description="Nothing is read from another locale or inferred from an unsafe file. Missing known leaves are shown only after a successful bounded core observation." />}
      <div className="button-row metadata-text-actions"><button type="button" className="button secondary" disabled={validateReason !== null} aria-describedby={`${id}-validate-reason`} onClick={() => void controller.validate()}>{entry?.validationRequest ? 'Validating text…' : 'Validate text'}</button><ActionHelp state={state} id="validate" onHelp={onHelp} />
        <button type="button" className="button primary" disabled={reviewReason !== null} aria-describedby={`${id}-review-reason`} onClick={() => controller.start()}>Review changes<Icon name={reviewReason ? 'lock' : 'search'} size={16} /></button><ActionHelp state={state} id="review" onHelp={onHelp} />
        {entry && <><button type="button" className="text-button" disabled={!metadataTextDirty(entry) || controller.discardReason(entry.context.key) !== null} onClick={() => askDiscard(entry.context.key, 'reset', 'Discard text draft changes')}>Discard text changes</button><ActionHelp state={state} id="discard" onHelp={onHelp} /></>}
      </div><p id={`${id}-validate-reason`} className="save-note">Validation: {validateReason ?? 'Pure core format checks only, using the shared Unicode/newline rules. No files, URLs or Store services are contacted.'}</p>
      <p id={`${id}-review-reason`} className="save-note">Save review: {reviewReason ?? 'Check every destination and its full before/after text. Nothing is written before you type SAVE and confirm.'}</p>
      {entry?.validationError && <ErrorNotice error={entry.validationError} title="Text validation was not accepted" />}
      {entry?.validation && <p role="status" className="metadata-validation-status"><Badge tone={!currentValidation ? 'warning' : entry.validation.result.valid ? 'info' : 'danger'}>{!currentValidation ? 'Stale validation' : entry.validation.result.valid ? 'Format-valid selected text' : 'Text corrections required'}</Badge> Not a saved file, whole-metadata validation, native asset check, Store approval or release-readiness result.</p>}
      {entry?.stale && entry.observation && !entry.observationPredatesSave && <details className="metadata-latest-observation"><summary>Separate newer observation · original draft is still above</summary><code>Configuration SHA256 {entry.observation.baseline.config.sha256}</code>
        {entry.observation.fields.map((field) => <section key={field.id}><h4>{field.path}</h4>{field.state === 'present' ? <><code>{field.byteLength} bytes · SHA256 {field.sha256}</code><pre tabIndex={0}><code>{field.text}</code></pre></> : <p>Observed absent.</p>}</section>)}
        <button type="button" className="button secondary" disabled={controller.discardReason(entry.context.key) !== null || entry.loadRequest !== null || loadReason !== null} onClick={() => askDiscard(entry.context.key, 'latest', 'Discard draft and use latest observation')}>Discard draft & use this observation</button><ActionHelp state={state} id="discard" onHelp={onHelp} />
      </details>}
    </section>
    <MetadataTextSave state={state} controller={controller} detailed onShowProject={onShowProject} onHelp={onHelp} />
    {retained.length > 0 && <details className="card metadata-retained"><summary>Retained locale text · {retained.length} / 32 bundles · {(metadataCacheBytes(state.entries) / 1024 / 1024).toFixed(2)} / 8 MiB</summary>
      <p>Refresh, project switches and locale removal never evict these drafts or move their text. Old contexts must be reconciled explicitly. Closing the app loses all in-memory text; no automatic persistence or cache eviction is used.</p>
      <ul>{retained.map((item) => <li key={item.context.key}><div><strong>{item.projectName} · {item.context.platform} / {item.context.locale}</strong><code>{item.context.metadataRoot} · configuration baseline {item.context.configBaselineGeneration}</code><Badge tone={metadataTextDirty(item) ? 'warning' : 'neutral'}>{metadataTextDirty(item) ? 'Unsaved text' : 'Retained in memory'}</Badge></div>
        <button type="button" className="button small secondary" onClick={() => onShowProject(item.context.projectId, item.context.key)}>View original context</button><button type="button" className="text-button" disabled={controller.discardReason(item.context.key) !== null} onClick={() => askDiscard(item.context.key, 'forget', 'Forget this retained text bundle')}>Forget bundle…</button></li>)}</ul>
      <ActionHelp state={state} id="discard" onHelp={onHelp} />
    </details>}
    {discard && <DiscardConfirmation label={discard.label} blocked={controller.discardReason(discard.binding.key) ?? (JSON.stringify(controller.discardBinding(discard.binding.key)) !== JSON.stringify(discard.binding) ? 'The draft changed while confirmation was open. Cancel and inspect its current contents.' : null)}
      onCancel={() => setDiscard(null)} onConfirm={() => { controller.discard(discard.binding, discard.action); setDiscard(null); }} />}
  </>;
}
