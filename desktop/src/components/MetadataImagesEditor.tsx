import { useEffect, useId, useState } from 'react';
import type { HelpContent } from '../types.ts';
import type { ProjectSession } from '../drafts.ts';
import type { ImageContentDigest, ImageSummary, MetadataImageHelpId, MetadataImageIssue, MetadataImagesImportView, MetadataImagesRecoveryView } from '../metadataImages.ts';
import type { MetadataImagesController, MetadataImagesState } from '../metadataImagesController.ts';
import { currentMetadataImagesApplyBinding, imageAttemptFinished, retainedMetadataImagesOperation } from '../metadataImagesController.ts';
import { imageCatalogLimits, imageCatalogTypes, imageFieldHelp, normalMetadataImagesResult } from '../metadataImagesProtocol.ts';
import { Badge, EmptyState, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';
import '../metadataImages.css';

type HelpProps = { state: MetadataImagesState; onHelp: (help: HelpContent) => void };
function FieldHelp({ state, id, onHelp }: HelpProps & { id: MetadataImageHelpId }) {
  const content = imageFieldHelp(state.catalog, id);
  return content ? <HelpButton content={content} onHelp={onHelp} /> : null;
}
function FieldHint({ state, id }: { state: MetadataImagesState; id: MetadataImageHelpId }) {
  const content = imageFieldHelp(state.catalog, id);
  return content ? <p className="image-field-hint">{content.what}</p> : null;
}
function ImageIssues({ issues }: { issues: MetadataImageIssue[] }) {
  return issues.length ? <ul className="issues image-issues">{issues.map((issue, index) => <li key={issue.code + '-' + index}>
    <Badge tone="danger">Needs correction</Badge><div><p>{issue.message}</p><code>{issue.code}</code></div>
  </li>)}</ul> : null;
}
function Digest({ value }: { value: ImageContentDigest | null }) {
  return value ? <><span>{value.byteLength.toLocaleString()} bytes</span><code className="metadata-digest">SHA256 {value.sha256}</code></> :
    <span>Proven absent / not present in the admitted original plan.</span>;
}
function Summary({ value, label }: { value: ImageSummary | null; label: string }) {
  return <section className="image-summary"><h4>{label}</h4>{value ? <>
    <p>{value.format?.toUpperCase() ?? 'Unrecognized format'} · {value.width !== null && value.height !== null ? value.width + ' × ' + value.height + ' pixels' : 'Dimensions unavailable'}</p>
    <Badge tone={value.headerChecked ? 'info' : 'warning'}>{value.headerChecked ? 'Header/dimensions checked' : 'Header/dimensions not checked'}</Badge>
    <Digest value={value} />
  </> : <p>Observed absent. No original image was fabricated.</p>}</section>;
}
function ImportPreview({ state, controller, view, onHelp }: HelpProps & {
  controller: MetadataImagesController; view: MetadataImagesImportView;
}) {
  const attempt = state.attempt; const prepared = Boolean(attempt?.projection?.details?.prepared);
  const changedChoice = !prepared && attempt?.choices?.some((row) => row.replaceExisting);
  return <div className="metadata-images-preview">
    <p><strong>{view.platform} / {view.locale} / {view.assetType}</strong> · public folder <code>{view.folder}</code></p>
    <Badge tone={view.valid ? 'info' : 'warning'}>{view.valid ? 'Header/dimensions checked' : 'Needs correction'}</Badge>
    <p className="review-caution">This is a {prepared ? 'prepared' : 'checked-out'} local-copy preview, not a current post-copy file observation.
      Source images are never moved. Files change one at a time with recovery protection; the whole set does not change at once.</p>
    {changedChoice && <p className="review-caution" role="status">Replacement choices changed. The results shown below are still the core checkout.
      Review the choices to obtain the exact resulting preview; selected bytes are not yet the resulting public copy.</p>}
    <ImageIssues issues={view.issues} />
    {view.files.map((file) => {
      const choice = attempt?.choices?.find((row) => row.itemId === file.itemId);
      const identical = file.before !== null && file.before.sha256 === file.selected.sha256 && file.before.byteLength === file.selected.byteLength;
      return <section className="image-file-card" key={file.itemId}>
        <h3>{file.displayName}</h3><p><code>{file.path}</code></p>
        <p>Core action: <strong>{file.action === 'preserve' ? 'Keep the existing public copy' : file.action === 'replace' ? 'Replace this exact public copy' : 'Create this absent public copy'}</strong>.</p>
        <div className="image-source-grid"><Summary label="Existing public image" value={file.before} /><Summary label="Newly selected source" value={file.selected} />
          <Summary label={prepared ? 'Result of this reviewed plan' : 'Result of the current core checkout'} value={file.after} /></div>
        {file.before !== null && <div className="image-replacement"><label><input type="checkbox" checked={choice?.replaceExisting ?? false}
          disabled={!file.canReplace || prepared || Boolean(attempt?.prepareClaimed || attempt?.invalidated || attempt?.closeRequested)}
          onChange={(event) => controller.setReplacement(file.itemId, event.target.checked)} />
          Replace only the existing public copy at <code>{file.path}</code></label><FieldHelp state={state} id="replaceExisting" onHelp={onHelp} />
          {identical && <p>Identical bytes are always preserved; no replacement is needed.</p>}
          {!identical && !file.canReplace && <p>Replacement is not admitted for this destination. Correct the source or choose the existing format; no conversion or cross-extension deletion is offered.</p>}
        </div>}
        {file.before === null && <p>There is no existing destination to replace. This row can only create the reviewed absent target.</p>}
        <ImageIssues issues={file.issues} />
      </section>;
    })}
    <section className="image-order"><h3>Final lexical Store input order</h3>
      <p>The core supplies this order for the resulting paths. It is not drag-and-drop order or a promise that a Store accepts the images.</p>
      {view.finalOrder.length ? <ol>{view.finalOrder.map((path) => <li key={path}><code>{path}</code></li>)}</ol> : <p>No resulting order was admitted for this invalid checkout.</p>}
    </section>
    <details className="image-existing"><summary>Complete relevant existing siblings ({view.existing.length})</summary>
      {view.existing.length ? view.existing.map((row) => <div key={row.path}><code>{row.path}</code><Summary label="Observed relevant sibling" value={row.summary} /></div>) :
        <p>No relevant existing siblings were observed.</p>}
    </details>
    <p className="subtle-note">Header checks are not full image decoding, content approval, secret scanning or Store acceptance. No Store was contacted.</p>
  </div>;
}
const recoveryAction = {
  rollback: 'Restore the inspected original public files or their original absence.',
  committed_cleanup: 'Keep the already-committed public images and clean only the original journal leftovers.',
  rolled_back_cleanup: 'Keep the already-restored public files and clean only the original journal leftovers.',
  preparing_cleanup: 'Clean only the positively inspected original preparation leftovers.',
} as const;
function RecoveryPreview({ view }: { view: MetadataImagesRecoveryView }) {
  return <div className="metadata-images-preview">
    <h3>{view.state === 'idle' ? 'No image recovery journal found' : view.state === 'conflict' ? 'Image recovery proof is conflicted' : 'Inspected image recovery action'}</h3>
    <p className="review-caution">This is a new restoration attempt, not a retry of image import and not an original completion receipt.
      An idle inspection is not a recovery pass. Partial or conflicting proof cannot be applied.</p>
    {view.action && <p><strong>{recoveryAction[view.action]}</strong></p>}
    <p>Positively bound listing context: {view.platform ?? 'platform not established'} / {view.locale ?? 'locale not established'} / {view.assetType ?? 'type not established'}.</p>
    <ImageIssues issues={view.issues} />
    {view.files.length > 0 && <div className="review-table-wrap"><table className="review-table"><caption>Only these inspected public paths may be affected</caption>
      <thead><tr><th scope="col">Public target</th><th scope="col">Inspected effect</th><th scope="col">Original plan image</th><th scope="col">New plan image</th></tr></thead>
      <tbody>{view.files.map((file) => <tr key={file.path}><th scope="row"><code>{file.path}</code></th>
        <td>{file.effect === 'restore_original' ? file.original === null ? 'Restore original absence; remove only this attempt’s created public copy' : 'Restore inspected original bytes' :
          file.effect === 'keep_committed' ? 'Keep the inspected committed result' : 'Preserve the inspected public target'}</td>
        <td><Digest value={file.original} /></td><td><Digest value={file.new} /></td></tr>)}</tbody>
    </table></div>}
    <p>Original image-journal-only cleanup: {view.privateCleanup.fileCount.toLocaleString()} private files and {view.privateCleanup.directoryCount.toLocaleString()} private directories.
      No private path, arbitrary deletion, process termination or force option is exposed.</p>
    <p className="subtle-note">Source files are unchanged. Nothing is sent to a Store. Null summaries mean proven absence or no entry in the admitted original plan—not unknown bytes assumed safe.</p>
  </div>;
}
function operationCopy(state: MetadataImagesState): { title: string; detail: string; danger: boolean } {
  const { owner, selection: selected } = retainedMetadataImagesOperation(state);
  if (state.integrityFailed || state.nativeBlocked || state.generationLost || state.unknownSelection || state.unknownEdit || state.selectionIssue || state.editIssue)
    return { title: 'Original image operation is unverified', danger: true,
      detail: 'Keep the original files and operation evidence. Unknown or late settlement does not mean success, undo, or permission to import again.' };
  if (state.attempt?.applyClaimed && owner && !owner.applySubmitted && owner.phase !== 'final')
    return { title: 'Image Apply submitted; awaiting original status', danger: false,
      detail: 'The original request may already be running. A stale review is not proof that no files changed. Observe the same owner; do not repeat Apply.' };
  if (owner) {
    const core = owner.coreOutcome; const normal = normalMetadataImagesResult(owner);
    if (owner.phase === 'unknown' || owner.nativeFinality === 'unknown') return { title: 'Image copy or cleanup is unconfirmed', danger: true,
      detail: 'The original operation may have changed public files. Do not repeat Apply, remove journals, or assume cancellation undid a copy.' };
    if (core?.journal === 'recovery_required') return { title: 'Image recovery needs attention', danger: true,
      detail: 'Preserve the original files and any outside changes. Once the native owner settles, inspect a new image recovery action below; another edit cannot bypass this journal.' };
    if (normal === 'copied') return { title: 'Reviewed public images copied locally', danger: false,
      detail: 'The original native owner confirmed the copy, a clean journal and resource settlement. This is not Store validation or a new filesystem observation.' };
    if (normal === 'unchanged') return { title: 'Existing public images kept unchanged', danger: false,
      detail: 'The original owner rechecked the reviewed set and settled without creating a journal. The newly selected sources were not copied over preserved images.' };
    if (normal === 'recovered') return { title: 'Reviewed image recovery completed', danger: false,
      detail: 'The new restoration attempt completed its exact inspected action with a clean journal and original native settlement. It did not retry the import.' };
    if (owner.phase === 'final') return { title: core?.effect === 'committed' ? 'Images written; completion needs attention' : 'Original image review ended', danger: core?.effect === 'committed',
      detail: core?.effect === 'rolled_back' ? 'The original owner reports its own changes rolled back. This is not a new observation of unrelated files.' :
        'No successful local copy or recovery is confirmed. Review the original outcome below before choosing a corrected batch.' };
    if (owner.phase === 'applying' || owner.phase === 'finalizing') return { title: 'Original image operation is running…', danger: false,
      detail: 'Wait for original native settlement. Stop may be too late to prevent writes and is never proof of undo. No automatic retry will be sent.' };
    if (owner.phase === 'reviewing') return { title: 'Review the exact local image action', danger: false,
      detail: 'Nothing has been copied by this review. Read every destination, preservation/replacement and resulting order, then provide fresh explicit acknowledgement.' };
    return { title: owner.phase === 'opening' ? 'Checking the original image context…' : 'Check images and choose exact replacements', danger: false,
      detail: 'The core checks saved settings, original image metadata, relevant siblings and recovery protection. No thumbnail or decoded image content is transported to this UI.' };
  }
  if (selected?.phase === 'selected') return { title: 'Source images captured, not imported', danger: false,
    detail: selected.selectionToken === null ? 'This selection was consumed once by its original edit. A cancelled selection cannot stop an active copy; use the edit’s original Stop action.' :
      'The original native capture settled. The one-use batch is awaiting core image checks; selection alone is not image validation or a local copy.' };
  if (selected?.phase === 'cancelled' || selected?.phase === 'failed') return { title: selected.phase === 'cancelled' ? 'Original image selection cancelled' : 'Original image selection refused', danger: selected.phase === 'failed',
    detail: 'This selection has no reusable token. Correct the source batch and choose again only after original settlement.' };
  return { title: 'Waiting for the original native image selection…', danger: false,
    detail: 'The original file dialog and bounded capture must join and settle. Navigation does not detach this operation or authorize a replacement dialog.' };
}

export function MetadataImagesOperation({ state, controller, detailed, onShowProject, onHelp }: HelpProps & {
  controller: MetadataImagesController; detailed: boolean; onShowProject: (projectId: string) => void;
}) {
  const [, refreshClock] = useState(0); const consentId = useId();
  const attempt = state.attempt; const { owner, selection: selected } = retainedMetadataImagesOperation(state);
  const projectId = attempt?.binding.projectId ?? owner?.projectId ?? selected?.projectId;
  const view = owner?.details?.prepared?.view ?? owner?.details?.checkout?.view;
  const binding = currentMetadataImagesApplyBinding(state);
  const notice = operationCopy(state);
  const showDetails = detailed && projectId === state.projectId;
  const owned = Boolean(attempt && !imageAttemptFinished(attempt) || state.selectionStatus?.active || state.editStatus?.active ||
    selected?.phase === 'selected' && selected.selectionToken !== null);
  const stopReason = state.generationLost || state.nativeBlocked || state.integrityFailed ? 'Original authority is unverified. Observe status without issuing a new action.' : null;
  useEffect(() => {
    if (owner?.phase !== 'reviewing') return;
    const timer = setInterval(() => refreshClock((value) => value + 1), 1000);
    return () => clearInterval(timer);
  }, [owner?.phase, owner?.sessionId]);
  if (!attempt && !owner && !selected && !state.nativeBlocked && !state.integrityFailed) return null;
  return <section className="card metadata-images-panel" aria-label="Original localized-image operation">
    <SectionHeading title={notice.title} description={notice.detail}><Badge tone={notice.danger ? 'danger' : 'info'}>
      {owner?.phase ?? selected?.phase ?? 'Waiting for native status'}</Badge></SectionHeading>
    <p><strong>{attempt?.binding.projectName ?? 'Original registered project'}</strong>{attempt?.binding.context &&
      <> · {attempt.binding.context.platform} / {attempt.binding.context.locale} / {attempt.binding.context.assetType}</>}</p>
    {state.error && <ErrorNotice error={state.error} title="Image operation status needs attention" />}
    {attempt?.invalidated && <p className="review-caution" role="status">The earlier project or selection context was retired. Its original operation remains visible until it settles; no earlier consent can be reused.</p>}
    {!showDetails && projectId && <button type="button" className="button small secondary" onClick={() => onShowProject(projectId)}>Show original image project</button>}
    {showDetails && selected && selected.items.length > 0 && <details className="image-capture-details"><summary>Native capture metadata ({selected.items.length} sources; not image approval)</summary>
      <ul>{selected.items.map((item) => <li key={item.itemId}><strong>{item.displayName}</strong><Digest value={item} /></li>)}</ul>
    </details>}
    {showDetails && view?.kind === 'import' && <ImportPreview state={state} controller={controller} view={view} onHelp={onHelp} />}
    {showDetails && view?.kind === 'recover' && <RecoveryPreview view={view} />}
    {showDetails && owner?.phase === 'editing' && <div className="image-review-actions">
      <button type="button" className="button primary" disabled={controller.prepareReason() !== null} onClick={() => controller.prepare()}>
        {view?.kind === 'recover' ? 'Review inspected recovery action' : 'Review exact copy choices'}</button>
      {controller.prepareReason() && <p className="save-note">{controller.prepareReason()}</p>}
    </div>}
    {showDetails && owner?.phase === 'reviewing' && view && <section className="image-copy-consent" aria-label="Fresh local action confirmation">
      <p>Original review time remaining: {Math.ceil(controller.remainingReviewMs() / 1000).toLocaleString()} seconds. A status check cannot renew this deadline.</p>
      <label htmlFor={consentId}><input id={consentId} type="checkbox" checked={Boolean(state.acknowledged && controller.canAcknowledge(binding))}
        disabled={!controller.canAcknowledge(binding)} onChange={(event) => controller.acknowledge(event.target.checked)} />
        {view.kind === 'recover' ? 'I reviewed the exact restoration/cleanup action and admitted public paths. Start only this new recovery attempt; do not retry image import.' :
          'I reviewed every destination, replacement and final order. Copy only these public images into version-controlled project metadata, leaving source files unchanged. Nothing is sent to a Store.'}
      </label><FieldHelp state={state} id={view.kind === 'recover' ? 'recoveryConfirmation' : 'copyConfirmation'} onHelp={onHelp} />
      <button type="button" className="button primary" disabled={!controller.canApply(binding)} onClick={() => { if (binding) controller.apply(binding); }}>
        {view.kind === 'recover' ? 'Apply reviewed recovery' : 'Confirm local image copy'}</button>
      {!controller.canAcknowledge(binding) && <p className="review-caution">This prepared view is no longer current or the native owner is unavailable. No acknowledgement or Apply can be reused.</p>}
    </section>}
    <div className="button-row"><button type="button" className="button secondary" disabled={state.mode !== 'native' || state.reading} onClick={() => void controller.checkStatus()}>
      <Icon name="refresh" size={15} />{state.reading ? 'Observing original status…' : 'Observe original status'}</button>
      {owned && <button type="button" className="button secondary" disabled={stopReason !== null || Boolean(attempt && !imageAttemptFinished(attempt) && (attempt.cancelClaimed || attempt.closeClaimed))}
        onClick={() => controller.requestStop()}>{owner?.applySubmitted || attempt?.applyClaimed ? 'Request original STOP' : 'Cancel / close original review'}</button>}
    </div>{stopReason && <p className="save-note">{stopReason}</p>}
    {owner && <details className="save-native-details"><summary>Original native outcome, not a retry receipt</summary>
      <dl className="limit-list"><div><dt>Native finality</dt><dd>{owner.nativeFinality}{owner.lateSettled ? ' (late; earlier uncertainty retained)' : ''}</dd></div>
        <div><dt>Native reason</dt><dd>{owner.nativeReason}</dd></div><div><dt>Effect</dt><dd>{owner.coreOutcome?.effect ?? 'Not reported'}</dd></div>
        <div><dt>Journal</dt><dd>{owner.coreOutcome?.journal ?? 'Not reported'}</dd></div><div><dt>Core resources</dt><dd>{owner.coreOutcome?.resources ?? 'Not reported'}</dd></div>
        <div><dt>Core reason</dt><dd>{owner.coreOutcome?.reason ?? 'Not reported'}</dd></div></dl>
    </details>}
    {!owner && selected && <p className="save-note">Original capture settlement: {selected.settlement}. Reason: {selected.reason}. Selection is not import, and cancellation is not proof of undo.</p>}
  </section>;
}

export function MetadataImagesEditor({ state, controller, session, onShowProject, onHelp }: HelpProps & {
  controller: MetadataImagesController; session: ProjectSession | null; onShowProject: (projectId: string) => void;
}) {
  const platformId = useId(), localeId = useId(), typeId = useId();
  const selected = state.choices.find((row) => row.key === state.selectedKey);
  const platforms = [...new Set(state.choices.map((row) => row.platform))];
  const locales = state.choices.filter((row) => row.platform === selected?.platform);
  const types = state.catalog && selected ? imageCatalogTypes(state.catalog, selected.platform) : [];
  const type = types.find((row) => row.id === state.selectedType);
  const limits = state.catalog ? imageCatalogLimits(state.catalog) : null;
  const chooseReason = controller.startReason(); const recoveryReason = controller.startReason('recover');
  return <>
    <section className="card metadata-images-panel" aria-label="Localized screenshot and image import">
      <SectionHeading title="Screenshots & listing images" description="Choose files with the native picker, inspect immediate core checks, then explicitly review and confirm a local public copy. No Store upload is included." />
      {state.mode !== 'native' && <p className="review-caution">Native image selection and writing are unavailable here. Browser preview has no file input, image-byte transport, CLI or raw-path escape.</p>}
      {state.catalogError && <ErrorNotice error={state.catalogError} title="Shared image guide unavailable" />}
      {!state.catalog && <div className="button-row"><button type="button" className="button small secondary" disabled={state.mode !== 'native' || state.catalogPending}
        onClick={() => void controller.loadCatalog()}>{state.catalogPending ? 'Loading shared image guide…' : 'Reload shared image guide'}</button>
        <span>Catalogue DATA does not qualify the native picker or writer.</span></div>}
      <div className="image-picker-grid">
        <div><label htmlFor={platformId}>Listing platform <FieldHelp state={state} id="platform" onHelp={onHelp} /></label>
          <select id={platformId} value={selected?.platform ?? ''} disabled={!platforms.length || state.mode !== 'native'}
            onChange={(event) => { if (event.target.value === 'android' || event.target.value === 'ios') controller.selectPlatform(event.target.value); }}>
            <option value="" disabled>Choose an enabled platform</option>{platforms.map((platform) => <option key={platform} value={platform}>
              {state.catalog?.platforms.find((row) => row.id === platform)?.label ?? platform}</option>)}</select><FieldHint state={state} id="platform" /></div>
        <div><label htmlFor={localeId}>Listing language / locale <FieldHelp state={state} id="locale" onHelp={onHelp} /></label>
          <select id={localeId} value={selected?.locale ?? ''} disabled={!locales.length || state.mode !== 'native'} onChange={(event) => controller.selectLocale(event.target.value)}>
            <option value="" disabled>Choose a saved locale</option>{locales.map((row) => <option value={row.locale} key={row.key}>{row.locale}</option>)}</select><FieldHint state={state} id="locale" /></div>
        <div><label htmlFor={typeId}>Image slot / Apple device size <FieldHelp state={state} id="assetType" onHelp={onHelp} /></label>
          <select id={typeId} value={state.selectedType ?? ''} disabled={!types.length || state.mode !== 'native'} onChange={(event) => controller.selectAssetType(event.target.value)}>
            <option value="" disabled>Choose a catalogue image type</option>{types.map((row) => <option key={row.id} value={row.id}>{row.label}</option>)}</select>
          <FieldHint state={state} id="assetType" />{type && <p>{type.description}</p>}</div>
      </div>
      <p className="save-note">These choices come from saved settings for {session?.project.name ?? 'the registered project'}, not the configuration draft.
        Add missing platforms/locales above and save them before selecting images.</p>
      {limits && <p>Native capture limit: {limits.maxFiles} files, {limits.maxFileBytes / 1024 / 1024} MiB per file, {limits.maxBatchBytes / 1024 / 1024} MiB total.
        No batch is truncated or partly imported to fit.</p>}
      <div className="button-row"><button type="button" className="button primary" disabled={chooseReason !== null} onClick={() => controller.choose()}>
        <Icon name="plus" size={16} />Choose image files…</button><FieldHelp state={state} id="files" onHelp={onHelp} /></div>
      <FieldHint state={state} id="files" />{chooseReason && <p className="save-note">{chooseReason}</p>}
      {!state.attempt && !state.editStatus?.active && !state.editStatus?.lastTerminal && !state.selectionStatus?.active && !state.selectionStatus?.lastTerminal && <EmptyState compact icon="metadata" title="No image batch reviewed"
        description="No thumbnail is fabricated. The native core supplies exact public paths, byte lengths, hashes, header dimensions and final lexical order before any copy." />}
      <section className="image-recovery-entry"><h3>Inspect image recovery</h3>
        <p>Inspect this project’s fixed image journals without modifying public files. Review a separate restoration or already-committed cleanup action only when the native core proves it.</p>
        <div className="button-row"><button type="button" className="button secondary" disabled={recoveryReason !== null} onClick={() => controller.inspectRecovery()}>Inspect image recovery</button>
          <FieldHelp state={state} id="recoveryConfirmation" onHelp={onHelp} /></div>{recoveryReason && <p className="save-note">{recoveryReason}</p>}
      </section>
    </section>
    <MetadataImagesOperation state={state} controller={controller} detailed onShowProject={onShowProject} onHelp={onHelp} />
  </>;
}
