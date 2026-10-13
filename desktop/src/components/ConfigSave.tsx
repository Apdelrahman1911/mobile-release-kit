import { useEffect, useId, useRef, useState } from 'react';
import { canApplyEdit, currentApplyBinding, editNotice, nativeReviewPath, nativeStartReason, noOpPlan, saveHelp } from '../configEdit.ts';
import type { ConfigEditState, EditApplyBinding, ConfigRecoveryApplyBinding } from '../configEdit.ts';
import type { ProjectSession } from '../drafts.ts';
import { valueSummary } from '../preparation.ts';
import { sameJson } from '../catalog.ts';
import { savedSetupRevision } from '../setupGuidance.ts';
import type { Catalog, HelpContent, PreparedConfigView, ConfigRecoveryView } from '../types.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

function SaveFiles({ view }: { view: PreparedConfigView }) {
  const labels = { create: 'Create', replace: 'Replace document', append: 'Append fixed rules', preserve: 'Preserve original' };
  return <div className="review-table-wrap save-files"><table className="review-table"><caption>Exact native destination inventory</caption><thead><tr><th scope="col">Destination</th><th scope="col">Planned action</th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>{view.files.map((file) => <tr key={file.path}><th scope="row"><code>{file.path}</code></th><td>{labels[file.action]}</td><td>{file.beforeBytes === null ? 'Observed absent' : `${file.beforeBytes.toLocaleString()} bytes`}</td><td>{file.afterBytes.toLocaleString()} bytes</td></tr>)}</tbody></table></div>;
}

function SaveReview({ view, catalog }: { view: PreparedConfigView; catalog: Catalog | null }) {
  const comparison = view.preview.comparison;
  const noOp = noOpPlan(view);
  return <div className="save-review">
    <div className="review-basis"><Icon name="shield" size={18} /><div><strong>{noOp ? 'The native plan contains no file writes' : 'Only this reviewed native inventory can be applied'}</strong><p>{noOp ? 'Confirm this no-op plan to recheck the original bindings and settle its owner. “No changes needed” is not confirmed until finality.' : 'This is configuration-only create/save, not full project initialization or a release. Staleness is checked again before application.'}</p></div></div>
    <SaveFiles view={view} />
    {view.createReleaseDirectory && <p className="save-note"><Icon name="folder" size={15} />The transaction also creates the authoritatively missing <code>release</code> directory.</p>}
    {view.rewritesConfigFormatting && <div className="notice notice-warning"><Icon name="info" size={18} /><p>This real configuration change replaces the whole JSON document using core formatting. Original indentation, key order and number spelling may change; an unchanged config would instead preserve its raw bytes and inode.</p></div>}
    {view.files[0].action === 'preserve' && !noOp && <p className="review-caution">The configuration is unchanged, but the listed ignore additions make this an actual write plan—not a whole-operation no-op.</p>}
    {view.ignoreAdditions.length > 0 && <div className="save-ignore"><h3>Required fixed ignore additions</h3><ul>{view.ignoreAdditions.map((line) => <li key={line}><code>{line}</code></li>)}</ul><p>Only these core-derived rules are added. Existing unrelated rules are not rewritten; raw ignore contents are omitted.</p></div>}
    <div className="review-counts" aria-label="Native known-field change counts"><span><strong>{comparison.counts.added}</strong> added</span><span><strong>{comparison.counts.changed}</strong> changed</span><span><strong>{comparison.counts.removed}</strong> removed</span><Badge>{noOp ? 'No writes planned' : 'Explicit Apply required'}</Badge></div>
    {comparison.changes.length > 0 && <details className="save-change-details"><summary>Inspect safe field-path changes; raw values are omitted</summary><div className="review-table-wrap"><table className="review-table"><caption className="sr-only">Core-provided field changes for the captured draft.</caption><thead><tr><th scope="col">Field / structure</th><th scope="col">Change</th><th scope="col">Before</th><th scope="col">Submitted draft</th></tr></thead><tbody>{comparison.changes.map((change, index) => {
      const field = nativeReviewPath(catalog, change.path);
      return <tr key={index}><th scope="row"><span>{field.label}</span>{field.path && <code>{field.path}</code>}</th><td>{change.operation}</td><td>{valueSummary(change.before)}</td><td>{valueSummary(change.after)}</td></tr>;
    })}</tbody></table></div></details>}
    <p className="save-note">Preserved byte counts describe raw originals, not JavaScript serialization. Format-valid configuration does not verify commands, files, identities, credentials, native tools or release readiness.</p>
  </div>;
}

function ApplyConfirmation({ view, binding, projectPath, allowed, onCancel, onConfirm }: { view: PreparedConfigView; binding: EditApplyBinding; projectPath: string | null; allowed: boolean; onCancel: () => void; onConfirm: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const checkboxId = useId();
  const [reviewed, setReviewed] = useState(false);
  const noOp = noOpPlan(view);
  useEffect(() => { const element = dialog.current; if (element && !element.open) element.showModal(); return () => { if (element?.open) element.close(); }; }, []);
  return <dialog ref={dialog} className="save-confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}>
    <div className="dialog-content"><span className="eyebrow">EXPLICIT NATIVE REVIEW</span><h2 id={titleId}>{noOp ? 'Confirm the no-op plan?' : 'Apply this configuration save?'}</h2>
      <p>This confirms submitted draft revision {binding.draftRevision}, not any later edits. {noOp ? 'The native owner must recheck and settle before no changes can be confirmed.' : 'These two fixed destinations are the complete plan. No release, workflow or metadata-file setup is included.'}</p>
      <p className="save-project-path">Project folder: {projectPath ? <code>{projectPath}</code> : 'Not available — this review cannot be applied.'}</p>
      <SaveFiles view={view} />
      {view.createReleaseDirectory && <p>The missing <code>release</code> directory is included.</p>}
      {view.rewritesConfigFormatting && <p className="review-caution">The existing JSON document is replaced with core formatting.</p>}
      <label className="save-confirm-choice" htmlFor={checkboxId}><input id={checkboxId} type="checkbox" checked={reviewed} onChange={(event) => setReviewed(event.target.checked)} />I reviewed this exact inventory and understand that cancellation may be too late after Apply.</label>
      {!allowed && <p className="review-caution" role="alert">This binding is no longer current. Nothing will be applied from this confirmation.</p>}
      <div className="button-row"><button type="button" autoFocus className="button secondary" onClick={onCancel}>Keep reviewing</button><button type="button" className="button primary" disabled={!reviewed || !allowed} onClick={onConfirm}>{noOp ? 'Confirm no-op plan' : 'Apply reviewed save'}</button></div>
    </div>
  </dialog>;
}

interface SaveProps {
  state: ConfigEditState;
  projects: Record<string, ProjectSession>;
  catalog: Catalog | null;
  selectedId: string | null;
  detailed: boolean;
  onCheck: () => void;
  onClose: () => void;
  onApply: (binding: EditApplyBinding) => boolean;
  onInspectRecovery: (projectId: string) => boolean;
  onRecoveryApply: (binding: ConfigRecoveryApplyBinding) => boolean;
  onRecoveryClose: () => void;
  onRecoveryReload: (projectId: string) => void;
  recoveryReason: string | null;
  recoveryApplyBinding: ConfigRecoveryApplyBinding | null;
  onShowProject: (projectId: string) => void;
  onReviewVersion: (projectId: string) => void;
  onHelp: (help: HelpContent) => void;
}

export function ConfigSave(props: SaveProps) {
  const { state, projects, catalog, selectedId, detailed, onCheck, onClose, onApply, onShowProject, onReviewVersion, onHelp } = props;
  const [confirmation, setConfirmation] = useState<EditApplyBinding | null>(null);
  const attempt = state.attempt;
  const owner = state.unknownEvidence ?? attempt?.projection ?? state.status?.active ?? state.status?.lastTerminal ?? null;
  const projectId = owner?.projectId ?? attempt?.binding.projectId ?? null;
  const project = projectId && Object.hasOwn(projects, projectId) ? projects[projectId] ?? null : null;
  const notice = editNotice(state);
  const mayApply = canApplyEdit(state, project);
  const current = currentApplyBinding(state);
  const owned = Boolean(attempt && owner && attempt.sessionId === owner.sessionId &&
    owner.ownerGeneration === state.status?.windowGeneration && !state.generationLost);
  const showReview = detailed && selectedId === projectId && owner?.prepared !== null && owner?.prepared !== undefined;
  const terminal = owner?.phase === 'final' || owner?.phase === 'unknown';
  const mayClose = state.mode === 'native' && attempt !== null && !attempt.handled && !attempt.closeRequested && !state.generationLost &&
    !state.nativeBlocked && (!attempt.projection || (owned && !terminal));
  const applyPending = Boolean(attempt?.applyClaimed || owner?.applySubmitted);
  const setupRevision = savedSetupRevision(state, project, selectedId);
  useEffect(() => {
    if (confirmation && (!canApplyEdit(state, project, confirmation) || selectedId !== projectId || !detailed)) setConfirmation(null);
  }, [state, project, confirmation, selectedId, projectId, detailed]);
  if (!notice && !state.recovery && (!detailed || state.mode !== 'native')) return null;
  const reason = nativeStartReason(state);
  return <section className="card native-save-panel" aria-label="Native configuration save">
    <SectionHeading title={notice?.title ?? 'Native configuration saving'} description={project ? `Save session for ${project.project.name}. Drafts remain separate for each project.` : 'Native capability and original-owner status; never a browser simulation.'}>
      <HelpButton content={saveHelp} onHelp={onHelp} />
    </SectionHeading>
    <div className={`notice notice-${notice?.tone === 'danger' ? 'danger' : notice?.tone === 'warning' ? 'warning' : 'info'}`} role={notice?.tone === 'danger' ? 'alert' : 'status'} aria-live="polite"><Icon name="shield" size={18} /><div><p>{notice?.detail ?? reason ?? 'Configuration-only saving is available. Prepare a draft’s native review below; this capability alone performs no write.'}</p>{notice?.code && <span className="error-code">{notice.code}</span>}</div></div>
    {owner && !owned && <p className="review-caution">This is a read-only native session summary. Its tokens do not attach authority or mark the current draft saved.</p>}
    {owner && project?.lastSave?.sessionId === owner.sessionId && project.lastSave.resultingBaselineGeneration === null && <p className="review-caution">That completed operation describes an older submitted revision. Your newer draft and baseline were kept unchanged.</p>}
    {showReview && project && <p className="save-project-path save-note">Reviewing the project currently at <code>{project.project.path}</code>. Save checks this folder when the review opens; selecting it earlier does not lock it.</p>}
    {showReview && owner?.prepared && <SaveReview view={owner.prepared.view} catalog={catalog} />}
    {owner && (terminal || owner.phase === 'finalizing') && <dl className="save-outcome-facts" aria-label="Independent native outcome facts"><div><dt>Transaction effect</dt><dd>{owner.coreOutcome?.effect ?? 'Not reported'}</dd></div><div><dt>Journal</dt><dd>{owner.coreOutcome?.journal ?? 'Not reported'}</dd></div><div><dt>Core resources</dt><dd>{owner.coreOutcome?.resources ?? 'Not reported'}</dd></div><div><dt>Native finality</dt><dd>{owner.nativeFinality}{owner.lateSettled ? ' · late settlement recorded' : ''}</dd></div></dl>}
    <div className="button-row save-actions">
      {showReview && owned && !terminal && owner?.prepared && <button type="button" className="button primary" disabled={!mayApply || !current} onClick={() => { if (current && mayApply) setConfirmation(current); }}>{applyPending ? 'Apply already requested' : noOpPlan(owner.prepared.view) ? 'Review no-op confirmation' : 'Apply reviewed save'}<Icon name={mayApply ? 'check' : 'lock'} size={16} /></button>}
      {mayClose && <button type="button" className="button secondary" onClick={onClose}>{applyPending ? 'Request cancellation' : 'Close save review / keep draft'}</button>}
      {project && (!detailed || selectedId !== projectId) && <button type="button" className="button secondary" onClick={() => onShowProject(project.project.id)}>View {terminal ? 'submitted review' : 'save session'}<Icon name="arrow" size={16} /></button>}
      {state.mode === 'native' && <button type="button" className="button small secondary" disabled={state.readPending} onClick={onCheck}><Icon name="refresh" size={15} className={state.readPending ? 'spin' : ''} />{state.readPending ? 'Checking status…' : 'Check native status'}</button>}
    </div>
    {detailed && project && setupRevision !== null && <div className="review-basis"><Icon name="check" size={18} /><div>
      <strong>Continue setup</strong><p>Configuration draft revision {setupRevision} was saved. Next, review version values in the separate editor. This link only opens the Dashboard; it does not read or change version files.</p>
      <button type="button" className="button secondary" onClick={() => onReviewVersion(project.project.id)}>Next: review version values<Icon name="arrow" size={16} /></button>
    </div></div>}
    {showReview && !terminal && <p className="save-note">Editing this draft before Apply invalidates this review and closes its session. Newer edits after submission remain in memory. The native absolute lifetime is nonrenewable; a timer or status read never grants more authority.</p>}
    <ConfigurationRecovery {...props} />
    {confirmation && owner?.prepared && <ApplyConfirmation view={owner.prepared.view} binding={confirmation} projectPath={project?.project.path ?? null} allowed={canApplyEdit(state, project, confirmation)} onCancel={() => setConfirmation(null)} onConfirm={() => { onApply(confirmation); setConfirmation(null); }} />}
  </section>;
}

function RecoveryFiles({ view }: { view: ConfigRecoveryView }) {
  const fact = (row: ConfigRecoveryView['files'][number]['before']) => row === null ? 'Absent' : `${row.size} bytes · mode ${row.mode.toString(8)} · SHA-256 ${row.sha256}`;
  return <div className="review-table-wrap"><table className="review-table"><caption>Inspected fixed configuration recovery</caption><thead><tr><th>File</th><th>Effect</th><th>Original</th><th>Transaction content</th></tr></thead>
    <tbody>{view.files.map((file) => <tr key={file.id}><th><code>{file.path}</code></th><td>{file.action}</td><td><code>{fact(file.before)}</code></td><td><code>{fact(file.after)}</code></td></tr>)}</tbody></table>
    <p>Private cleanup: {view.privateCleanup.fileCount} inspected files and {view.privateCleanup.directoryCount} inspected directories. This is not authority over other files or incomplete legacy journals.</p></div>;
}
function RecoveryConfirmation({ view, binding, allowed, onCancel, onConfirm }: { view: ConfigRecoveryView; binding: ConfigRecoveryApplyBinding; allowed: boolean; onCancel: () => void; onConfirm: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null), title = useId(), checkbox = useId();
  const [checked, setChecked] = useState(false);
  useEffect(() => { const node = dialog.current; if (node && !node.open) node.showModal(); return () => { if (node?.open) node.close(); }; }, []);
  return <dialog ref={dialog} className="save-confirm-dialog" aria-labelledby={title} onCancel={onCancel}><div className="dialog-content">
    <h2 id={title}>Confirm configuration recovery?</h2><p>One inspected <strong>{binding.action}</strong> operation, not a Save of your draft. The original files and journal must still match.</p>
    <RecoveryFiles view={view} /><label htmlFor={checkbox}><input id={checkbox} type="checkbox" checked={checked} onChange={(event) => setChecked(event.target.checked)} />I reviewed these exact restore/remove/preserve effects and private cleanup. This does not save my draft.</label>
    {!allowed && <p role="alert">The project, observation, service or confirmation context changed. This review cannot be applied.</p>}
    <div className="button-row"><button type="button" autoFocus className="button secondary" onClick={onCancel}>Keep reviewing</button><button type="button" className="button primary" disabled={!checked || !allowed} onClick={onConfirm}>Apply inspected recovery once</button></div>
  </div></dialog>;
}
function ConfigurationRecovery({ state, projects, selectedId, detailed, onInspectRecovery, onRecoveryApply, onRecoveryClose, onRecoveryReload, recoveryReason, recoveryApplyBinding }: SaveProps) {
  const [confirmation, setConfirmation] = useState<{ binding: ConfigRecoveryApplyBinding; view: ConfigRecoveryView } | null>(null);
  const project = selectedId ? projects[selectedId] : null, recovery = state.recovery;
  const owner = recovery?.projection, selected = recovery?.binding.projectId === selectedId;
  const view = selected ? owner?.recovery?.prepared?.view ?? owner?.recovery?.checkout?.view : null;
  const allowed = !!confirmation && !!recoveryApplyBinding && sameJson(confirmation.binding as unknown as import('../types.ts').JsonValue, recoveryApplyBinding as unknown as import('../types.ts').JsonValue);
  useEffect(() => { if (confirmation && (!allowed || !detailed || !selected)) setConfirmation(null); }, [confirmation, allowed, detailed, selected]);
  if (!detailed || !project) return null;
  return <div className="save-review" aria-label="Configuration transaction recovery"><h3>Configuration recovery</h3>
    <p>Inspect only this registered project's complete two-file journal. Inspect and Prepare do not write. Shared journal names do not prove which app created them; incomplete, mixed or changed records are preserved, never guessed or deleted.</p>
    <button type="button" className="button secondary" disabled={recoveryReason !== null} title={recoveryReason ?? undefined} onClick={() => onInspectRecovery(project.project.id)}>Inspect configuration recovery</button>
    {recoveryReason && <p className="save-note">{recoveryReason}</p>}
    {view?.state === 'idle' && <p>No pending configuration journal was observed. This is not a Save or permission to erase earlier unknown evidence.</p>}
    {view?.state === 'conflict' && <p className="review-caution">The journal cannot be completely qualified for these two files. Keep it and the original files unchanged. No Apply, forced repair or automatic retry is offered.</p>}
    {view?.state === 'recoverable' && <><p>Inspected action: <strong>{view.action}</strong>. Closing keeps the journal; only Confirm can submit recovery.</p><RecoveryFiles view={view} /></>}
    {selected && owner && <dl className="save-outcome-facts"><div><dt>Effect</dt><dd>{owner.coreOutcome?.effect ?? 'Not reported'}</dd></div><div><dt>Journal</dt><dd>{owner.coreOutcome?.journal ?? 'Not reported'}</dd></div><div><dt>Core resources</dt><dd>{owner.coreOutcome?.resources ?? 'Not reported'}</dd></div><div><dt>Original finality</dt><dd>{owner.nativeFinality}</dd></div></dl>}
    {selected && recovery?.succeeded && <p>That submitted recovery completed. Your draft, baseline and undo copies were not saved or replaced. Only a current completion clears matching attention; newer or unknown evidence remains blocked.</p>}
    {selected && recoveryApplyBinding && view && <button type="button" className="button primary" onClick={() => setConfirmation({ binding: recoveryApplyBinding, view })}>Review recovery confirmation</button>}
    {selected && recovery && !recovery.handled && !recovery.closeRequested && owner?.phase !== 'unknown' && <button type="button" className="button secondary" onClick={onRecoveryClose}>{recovery.applyClaimed ? 'Request cancellation' : 'Close recovery review'}</button>}
    {project.saveRecoveryNeedsReload && <div className="notice notice-info"><p>Recovery is not Saved. Explicitly reload the saved observation before a new Save review. Reload keeps an existing draft and baseline; adopting a different baseline still requires the separate discard/reload action.</p>
      <button type="button" className="button secondary" disabled={project.saveRecoveryRequired || project.snapshotRequest !== null || !!state.status?.active || state.nativeBlocked || state.integrityFailed || state.generationLost} onClick={() => onRecoveryReload(project.project.id)}>Reload saved observation after recovery</button></div>}
    {confirmation && <RecoveryConfirmation view={confirmation.view} binding={confirmation.binding} allowed={allowed} onCancel={() => setConfirmation(null)} onConfirm={() => { onRecoveryApply(confirmation.binding); setConfirmation(null); }} />}
  </div>;
}
