import { useEffect, useId, useRef, useState } from 'react';
import { canApplyEdit, currentApplyBinding, editNotice, nativeReviewPath, nativeStartReason, noOpPlan, saveHelp } from '../configEdit.ts';
import type { ConfigEditState, EditApplyBinding } from '../configEdit.ts';
import type { ProjectSession } from '../drafts.ts';
import { valueSummary } from '../preparation.ts';
import type { Catalog, HelpContent, PreparedConfigView } from '../types.ts';
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

function ApplyConfirmation({ view, binding, allowed, onCancel, onConfirm }: { view: PreparedConfigView; binding: EditApplyBinding; allowed: boolean; onCancel: () => void; onConfirm: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const checkboxId = useId();
  const [reviewed, setReviewed] = useState(false);
  const noOp = noOpPlan(view);
  useEffect(() => { const element = dialog.current; if (element && !element.open) element.showModal(); return () => { if (element?.open) element.close(); }; }, []);
  return <dialog ref={dialog} className="save-confirm-dialog" aria-labelledby={titleId} onCancel={onCancel}>
    <div className="dialog-content"><span className="eyebrow">EXPLICIT NATIVE REVIEW</span><h2 id={titleId}>{noOp ? 'Confirm the no-op plan?' : 'Apply this configuration save?'}</h2>
      <p>This confirms submitted draft revision {binding.draftRevision}, not any later edits. {noOp ? 'The native owner must recheck and settle before no changes can be confirmed.' : 'These two fixed destinations are the complete plan. No release, workflow or metadata-file setup is included.'}</p>
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
  onShowProject: (projectId: string) => void;
  onHelp: (help: HelpContent) => void;
}

export function ConfigSave({ state, projects, catalog, selectedId, detailed, onCheck, onClose, onApply, onShowProject, onHelp }: SaveProps) {
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
  useEffect(() => {
    if (confirmation && (!canApplyEdit(state, project, confirmation) || selectedId !== projectId || !detailed)) setConfirmation(null);
  }, [state, project, confirmation, selectedId, projectId, detailed]);
  if (!notice && (!detailed || state.mode !== 'native')) return null;
  const reason = nativeStartReason(state);
  return <section className="card native-save-panel" aria-label="Native configuration save">
    <SectionHeading title={notice?.title ?? 'Native configuration saving'} description={project ? `Save session for ${project.project.name}. Drafts remain separate for each project.` : 'Native capability and original-owner status; never a browser simulation.'}>
      <HelpButton content={saveHelp} onHelp={onHelp} />
    </SectionHeading>
    <div className={`notice notice-${notice?.tone === 'danger' ? 'danger' : notice?.tone === 'warning' ? 'warning' : 'info'}`} role={notice?.tone === 'danger' ? 'alert' : 'status'} aria-live="polite"><Icon name="shield" size={18} /><div><p>{notice?.detail ?? reason ?? 'Configuration-only saving is available. Prepare a draft’s native review below; this capability alone performs no write.'}</p>{notice?.code && <span className="error-code">{notice.code}</span>}</div></div>
    {owner && !owned && <p className="review-caution">This is a read-only native session summary. Its tokens do not attach authority or mark the current draft saved.</p>}
    {owner && project?.lastSave?.sessionId === owner.sessionId && project.lastSave.resultingBaselineGeneration === null && <p className="review-caution">That completed operation describes an older submitted revision. Your newer draft and baseline were kept unchanged.</p>}
    {showReview && owner?.prepared && <SaveReview view={owner.prepared.view} catalog={catalog} />}
    {owner && (terminal || owner.phase === 'finalizing') && <dl className="save-outcome-facts" aria-label="Independent native outcome facts"><div><dt>Transaction effect</dt><dd>{owner.coreOutcome?.effect ?? 'Not reported'}</dd></div><div><dt>Journal</dt><dd>{owner.coreOutcome?.journal ?? 'Not reported'}</dd></div><div><dt>Core resources</dt><dd>{owner.coreOutcome?.resources ?? 'Not reported'}</dd></div><div><dt>Native finality</dt><dd>{owner.nativeFinality}{owner.lateSettled ? ' · late settlement recorded' : ''}</dd></div></dl>}
    <div className="button-row save-actions">
      {showReview && owned && !terminal && owner?.prepared && <button type="button" className="button primary" disabled={!mayApply || !current} onClick={() => { if (current && mayApply) setConfirmation(current); }}>{applyPending ? 'Apply already requested' : noOpPlan(owner.prepared.view) ? 'Review no-op confirmation' : 'Apply reviewed save'}<Icon name={mayApply ? 'check' : 'lock'} size={16} /></button>}
      {mayClose && <button type="button" className="button secondary" onClick={onClose}>{applyPending ? 'Request cancellation' : 'Close save review / keep draft'}</button>}
      {project && (!detailed || selectedId !== projectId) && <button type="button" className="button secondary" onClick={() => onShowProject(project.project.id)}>View {terminal ? 'submitted review' : 'save session'}<Icon name="arrow" size={16} /></button>}
      {state.mode === 'native' && <button type="button" className="button small secondary" disabled={state.readPending} onClick={onCheck}><Icon name="refresh" size={15} className={state.readPending ? 'spin' : ''} />{state.readPending ? 'Checking status…' : 'Check native status'}</button>}
    </div>
    {showReview && !terminal && <p className="save-note">Editing this draft before Apply invalidates this review and closes its session. Newer edits after submission remain in memory. The native absolute lifetime is nonrenewable; a timer or status read never grants more authority.</p>}
    {confirmation && owner?.prepared && <ApplyConfirmation view={owner.prepared.view} binding={confirmation} allowed={canApplyEdit(state, project, confirmation)} onCancel={() => setConfirmation(null)} onConfirm={() => { onApply(confirmation); setConfirmation(null); }} />}
  </section>;
}
