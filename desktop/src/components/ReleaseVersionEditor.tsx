import { useEffect, useId, useRef, useState } from 'react';
import { isDirty } from '../drafts.ts';
import type { ProjectSession } from '../drafts.ts';
import { normalVersionEditResult, sameVersionData, versionNoOp } from '../releaseVersionEdit.ts';
import type { VersionEditProjection, VersionPreparedView } from '../releaseVersionEdit.ts';
import { currentVersionApplyBinding, versionDraftDirty, versionRetainsDraft } from '../releaseVersionEditController.ts';
import type { ReleaseVersionEditController, VersionApplyBinding, VersionEditState, VersionResetBinding } from '../releaseVersionEditController.ts';
import type { HelpContent } from '../types.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';

function RawVersion({ view, side }: { view: VersionPreparedView; side: 'before' | 'after' }) {
  const value = side === 'before' ? view.file.before.state === 'present' ? view.file.before : null : view.file.after;
  const styles = view.lineEndings[side];
  const final = side === 'before' ? view.lineEndings.finalNewlineBefore : view.lineEndings.finalNewlineAfter;
  return <section className="version-raw"><h4>{side === 'before' ? 'Complete original text' : 'Complete reviewed text'}</h4>
    {value ? <><p>{value.bytes} UTF-8 bytes · {styles.join(', ') || 'No line endings'} · {final ? 'Final line ending present' : 'No final line ending'}</p>
      <code className="version-digest">SHA256 {value.sha256}</code>
      <pre tabIndex={0} aria-label={(side === 'before' ? 'Complete original' : 'Complete reviewed') + ' version source'}><code>{value.text}</code></pre></> :
      <p>Observed absent. Empty or malformed files are not treated as absence.</p>}
  </section>;
}
function VersionReview({ view }: { view: VersionPreparedView }) {
  return <div className="version-review">
    <h3>{versionNoOp(view) ? 'Preserve the exact original' : view.intent === 'create' ? 'Create the observed-absent source' : 'Edit only the two selected value spans'}</h3>
    <p><code>{view.file.path}</code> — {view.file.action}. Saved name key <code>{view.nameKey}</code>; build key <code>{view.buildKey}</code>.
      {view.iosEnabled ? ' Saved iOS marketing-version policy applies.' : ' Saved iOS policy is disabled.'}</p>
    <p><strong>Reviewed values:</strong> {view.values.name} · Build {view.values.build}. Core format-valid only; Store acceptance and artifact agreement remain unknown.</p>
    <p>{view.lineEndings.preserved ? 'Unrelated bytes, spacing, quotes, comments, all separators and final-newline presence are preserved.' :
      'Creation emits exactly two KEY=VALUE lines, UTF-8/LF with a final newline.'} No serializer or automatic version bump is used.</p>
    <p>{view.file.preserveMode ? 'Preserve original mode ' : 'Request new-file mode '}{view.file.requestedMode.toString(8).padStart(4, '0')}.
      {!view.file.preserveMode && ' New-file and directory modes are subject to the native umask; parent directories request 0755.'}</p>
    <p>{view.createDirectories.length ? <>Only these observed-missing parent directories may be created: {view.createDirectories.map((path) => <code key={path}>{path} </code>)}.</> : 'No parent directories will be created.'}
      {' '}Saved configuration and .gitignore are rechecked read-only dependencies.</p>
    <p className="subtle-note">Complete bounded text, never a truncated diff. The browser may display separators similarly; the explicit styles, byte counts and native hashes describe the frozen bytes.</p>
    <div className="version-raw-grid"><RawVersion view={view} side="before" /><RawVersion view={view} side="after" /></div>
  </div>;
}
function Confirmation({ view, allowed, onCancel, onConfirm }: {
  view: VersionPreparedView; allowed: boolean; onCancel: () => void; onConfirm: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null), titleId = useId(), inputId = useId();
  const [reviewed, setReviewed] = useState(false), [confirmation, setConfirmation] = useState('');
  useEffect(() => { const element = dialog.current; element?.showModal(); return () => { if (element?.open) element.close(); }; }, []);
  return <dialog ref={dialog} className="confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}><div className="dialog-content">
    <h2 id={titleId}>{versionNoOp(view) ? 'Confirm this unchanged version file?' : view.intent === 'create' ? 'Create this saved version source?' : 'Save these reviewed version values?'}</h2>
    <p>Only <code>{view.source}</code>, with marketing version <strong>{view.values.name}</strong> and build <strong>{view.values.build}</strong>.
      The original configuration, ignore proof, source and parents must still match.</p>
    <label className="save-confirm-check"><input type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />
      I reviewed the full original/after text, exact destination, byte comparisons, mode and directory/line-ending facts.</label>
    <label htmlFor={inputId}>Type <strong>SAVE</strong> to confirm this local operation</label>
    <input id={inputId} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} autoComplete="off" spellCheck={false} />
    <p>No configuration Save, native-project rewrite, build, Git/index operation, Store request or release is included. A submitted save may finish after cancellation.</p>
    {!allowed && <p role="alert" className="review-caution">This review is no longer eligible. Keep your draft and check the original operation.</p>}
    <div className="button-row"><button autoFocus type="button" className="button secondary" onClick={onCancel}>Keep reviewing</button>
      <button type="button" className="button primary" disabled={!allowed || !reviewed || confirmation !== 'SAVE'} onClick={onConfirm}>
        {versionNoOp(view) ? 'Confirm unchanged values' : view.intent === 'create' ? 'Create version file' : 'Save version values'}</button></div>
  </div></dialog>;
}
function ResetConfirmation({ action, allowed, onCancel, onConfirm }: {
  action: 'reload' | 'discard'; allowed: boolean; onCancel: () => void; onConfirm: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null), titleId = useId();
  useEffect(() => { const element = dialog.current; element?.showModal(); return () => { if (element?.open) element.close(); }; }, []);
  return <dialog ref={dialog} className="confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}><div className="dialog-content">
    <h2 id={titleId}>{action === 'reload' ? 'Reload saved values and discard this draft?' : 'Discard these value changes?'}</h2>
    <p>{action === 'reload' ? 'Only a successful fresh Open replaces this exact draft and baseline. Failed or out-of-context reads keep the old draft.' :
      'Reset only the in-memory values to their retained original. This does not reread, recover or change any file.'} Submitted outcomes are retained.</p>
    {!allowed && <p role="alert">The draft or original operation changed. Close this dialog and review the current state.</p>}
    <div className="button-row"><button autoFocus type="button" className="button secondary" onClick={onCancel}>Keep draft</button>
      <button type="button" className="button secondary" disabled={!allowed} onClick={onConfirm}>{action === 'reload' ? 'Reload and discard draft' : 'Discard value changes'}</button></div>
  </div></dialog>;
}
function Outcome({ owner }: { owner: VersionEditProjection }) {
  const result = normalVersionEditResult(owner);
  return <div className="notice notice-info" role={owner.phase === 'unknown' || owner.coreOutcome?.journal === 'recovery_required' ? 'alert' : 'status'}>
    <div><strong>{result === 'saved' ? 'Submitted version values saved' : result === 'unchanged' ? 'Submitted version values unchanged and rechecked' :
      owner.phase === 'final' ? 'Original version operation settled — no success assumed' : owner.phase === 'unknown' ? 'Original version outcome or cleanup is unverified' : 'Original version operation: ' + owner.phase}</strong>
      {owner.prepared && <p>Submitted review: {owner.prepared.view.values.name} · Build {owner.prepared.view.values.build} · <code>{owner.prepared.view.source}</code>.</p>}
      <p>Core effect: {owner.coreOutcome?.effect ?? 'not returned'}; journal: {owner.coreOutcome?.journal ?? 'not returned'}; native finality: {owner.nativeFinality}.
        {' '}Reason: {owner.coreOutcome?.reason ?? owner.nativeReason}.</p>
      {owner.coreOutcome?.reason === 'ignore_conflict' && <p>Use Settings → Prepare save review to add the ten conservative ignore rules. This editor never repairs .gitignore.</p>}
      {owner.coreOutcome?.reason === 'invalid_params' && <p>Correct the two proposed strings, then review again after settlement. Empty, ambiguous or unsafe source files are unsupported, not Create permission.</p>}
      {owner.coreOutcome?.reason === 'stale_revision' && <p>The retained baseline changed. Close, then explicitly reload saved values and discard the earlier draft.</p>}
      {(owner.phase === 'unknown' || owner.coreOutcome?.journal === 'recovery_required') && <p>Keep the original evidence. Do not retry, delete control state or treat cancellation as rollback. Desktop recovery remains unavailable.</p>}
      {result && <p>This receipt is for the submitted revision only, not later edits. Read saved version again explicitly before using its new values for build consent.</p>}
    </div>
  </div>;
}
export function ReleaseVersionSave({ state, controller, onShowProject }: {
  state: VersionEditState; controller: ReleaseVersionEditController; onShowProject: (projectId: string) => void;
}) {
  const owner = state.edit.attempt?.projection ?? state.edit.status?.active ?? state.edit.status?.lastTerminal ?? state.edit.unknownEvidence;
  if (!owner && !state.edit.attempt) return null;
  const projectId = owner?.projectId ?? state.edit.attempt?.binding.projectId;
  return <section className="card version-status" aria-label="Retained version operation">
    {owner ? <Outcome owner={owner} /> : <p>Waiting for the original saved-version Open. No values were fabricated.</p>}
    <div className="button-row"><button type="button" className="button small secondary" disabled={state.edit.readPending} onClick={() => void controller.checkStatus()}>Check original version status</button>
      <button type="button" className="button small secondary" disabled={!state.edit.attempt || state.edit.attempt.handled || state.edit.attempt.closeClaimed || owner?.phase === 'unknown'} onClick={() => controller.requestClose()}>
        {state.edit.attempt?.applyClaimed ? 'Request cancellation' : 'Close editor, keep draft'}</button>
      {projectId && <button type="button" className="button small secondary" onClick={() => onShowProject(projectId)}>View version draft / review</button>}</div>
    {(state.edit.observationIssue || state.edit.integrityFailed || state.edit.generationLost) && <p role="alert">Original ownership is unverified. A later observer or missing reply cannot authorize another save.</p>}
  </section>;
}
export function ReleaseVersionEditor({ state, controller, session, onSettings, onHelp, onShowProject }: {
  state: VersionEditState; controller: ReleaseVersionEditController; session: ProjectSession | null;
  onSettings: () => void; onHelp: (help: HelpContent) => void; onShowProject: (projectId: string) => void;
}) {
  const [confirmation, setConfirmation] = useState<VersionApplyBinding | null>(null);
  const [reset, setReset] = useState<{ action: 'reload' | 'discard'; binding: VersionResetBinding } | null>(null);
  const [, tick] = useState(0), nameId = useId(), buildId = useId();
  useEffect(() => { const timer = setInterval(() => tick((n) => n + 1), 1000); return () => clearInterval(timer); }, []);
  const entry = controller.selectedEntry(), attempt = state.edit.attempt, owner = attempt?.projection;
  const current = currentVersionApplyBinding(state), prepared = owner?.prepared;
  const openReason = controller.openReason(), reviewReason = controller.reviewReason();
  const retained = entry ? versionRetainsDraft(state, entry.projectId) : false;
  const ownView = Boolean(entry && owner?.projectId === entry.projectId && prepared);
  const help = (id: string) => state.help?.fields.find((field) => field.id === id);
  return <section className="card version-editor" aria-label="Edit or create saved version values">
    <SectionHeading title={entry?.original.values === null ? 'Create saved version values' : 'Edit saved version values'} description="Two strings, one saved-config-derived file. Read saved version remains a separate read-only action.">
      <Badge>{state.edit.status?.capability.available ? 'Separate native writer' : 'Writer unavailable'}</Badge>
    </SectionHeading>
    <p>Project: <strong>{session?.project.name ?? 'No native project selected'}</strong>. No automatic bump, trimming or numeric coercion.</p>
    {session && isDirty(session) && <p className="review-caution"><strong>Unsaved Settings are not applied.</strong> The source, keys and iOS policy below come only from the saved configuration. Save Settings separately to change them; then explicitly reload this editor.</p>}
    <div className="button-row"><button type="button" className="button secondary" disabled={openReason !== null} title={openReason ?? undefined} onClick={() => controller.open()}>Open saved version editor</button>
      <button type="button" className="text-button" onClick={onSettings}>Project Settings / ignore prerequisite</button>
      <button type="button" className="text-button" disabled={state.edit.readPending} onClick={() => void controller.checkStatus()}>Check writer availability</button></div>
    {openReason && !entry && <p>{openReason}</p>}
    {state.error && <ErrorNotice error={state.error} />}
    {entry && <>
      <div className="version-selection"><p>Saved source: <code>{entry.original.source}</code></p>
        <p>Saved keys: <code>{entry.original.nameKey}</code> and <code>{entry.original.buildKey}</code>.
          {entry.original.iosEnabled ? ' iOS marketing-version policy applies.' : ' iOS policy is disabled.'}</p>
        <p>{entry.original.values === null ? 'Observed absent: creation is explicit. The empty fields below are not detected values.' :
          'Original values: ' + entry.original.values.name + ' · Build ' + entry.original.values.build + '. These may need policy correction.'}</p>
        <code className="version-digest">Saved config: {entry.original.baseline.savedConfig.bytes} bytes · SHA256 {entry.original.baseline.savedConfig.sha256}</code>
        {entry.original.baseline.savedVersion.state === 'present' && <code className="version-digest">Saved source: {entry.original.baseline.savedVersion.bytes} bytes · SHA256 {entry.original.baseline.savedVersion.sha256}</code>}
      </div>
      <div className="version-values"><div><label htmlFor={nameId}>Marketing version <span>Required</span>{help('name') && <HelpButton content={help('name')!} onHelp={onHelp} />}</label>
        <input id={nameId} type="text" inputMode="decimal" value={entry.values.name} maxLength={64} autoComplete="off" spellCheck={false} placeholder="Example: 1.2.3" onChange={(event) => controller.editField('name', event.target.value)} /></div>
        <div><label htmlFor={buildId}>Build number <span>Required</span>{help('build') && <HelpButton content={help('build')!} onHelp={onHelp} />}</label>
          <input id={buildId} type="text" inputMode="numeric" value={entry.values.build} maxLength={10} autoComplete="off" spellCheck={false} placeholder="Example: 42" onChange={(event) => controller.editField('build', event.target.value)} /></div></div>
      {entry.error && <ErrorNotice error={entry.error} />}
      {entry.stale && <p role="alert" className="review-caution">Earlier baseline retained. Close the original session, then explicitly reload saved values and discard this draft; no automatic rebase.</p>}
      <div className="button-row"><button type="button" className="button primary" disabled={reviewReason !== null} title={reviewReason ?? undefined} onClick={() => controller.review()}>Validate and review {entry.original.values === null ? 'creation' : 'values'}</button>
        <button type="button" className="button secondary" disabled={retained || !versionDraftDirty(entry)} onClick={() => { const binding = controller.resetBinding(); if (binding) setReset({ action: 'discard', binding }); }}>Discard value changes</button>
        <button type="button" className="button secondary" disabled={retained || openReason !== null} title={openReason ?? undefined} onClick={() => { const binding = controller.resetBinding(); if (binding) setReset({ action: 'reload', binding }); }}>Reload saved values</button></div>
      {reviewReason && <p className="subtle-note">{reviewReason}</p>}
      {entry.outcome && entry.outcome.sessionId !== owner?.sessionId && <><h3>Last submitted version attempt</h3><Outcome owner={entry.outcome} /></>}
    </>}
    <ReleaseVersionSave state={state} controller={controller} onShowProject={onShowProject} />
    {ownView && prepared && <><VersionReview view={prepared.view} />
      <p>Original review time remaining: {Math.ceil(controller.remainingReviewMs() / 1000)} seconds. Later draft changes cannot retarget this review.</p>
      <button type="button" className="button primary" disabled={!current || !controller.canApply(current)} onClick={() => { if (current) setConfirmation(current); }}>
        {versionNoOp(prepared.view) ? 'Confirm unchanged values…' : prepared.view.intent === 'create' ? 'Create version file…' : 'Save version values…'}</button></>}
    {confirmation && prepared && <Confirmation view={prepared.view} allowed={controller.canApply(confirmation)} onCancel={() => setConfirmation(null)}
      onConfirm={() => { if (controller.apply(confirmation)) setConfirmation(null); }} />}
    {reset && <ResetConfirmation action={reset.action} allowed={!retained && sameVersionData(reset.binding, controller.resetBinding()) && (reset.action === 'discard' || openReason === null)}
      onCancel={() => setReset(null)} onConfirm={() => { const accepted = reset.action === 'reload' ? controller.reload(reset.binding) : controller.discard(reset.binding); if (accepted) setReset(null); }} />}
    <p className="subtle-note">Local memory only; no draft/source text in app storage or telemetry. No Store account, JDK/SDK/Xcode or terminal is needed for the ordinary flow once the separately qualified native writer is available. Saving does not rebuild an app.</p>
  </section>;
}
