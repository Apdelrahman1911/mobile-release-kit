import type { SavedMetadataState, SavedMetadataValidationController } from '../metadataValidationController.ts';
import type { SavedMetadataFile } from '../metadataValidation.ts';
import { savedMetadataRemediation } from '../metadataValidation.ts';
import { Badge, ErrorNotice, SectionHeading } from './Common.tsx';

function FileResult({ row }: { row: SavedMetadataFile }) {
  return <li>
    <Badge tone={row.state === 'checked' ? 'info' : row.state === 'missing' ? 'warning' : 'danger'}>
      {row.state === 'checked' ? 'Checked locally' : row.state === 'missing' ? 'Missing' : 'Needs correction'}
    </Badge>
    <div><strong>{row.id}{row.required ? ' · Required' : ' · Optional'}</strong>
      <p><code>{row.path ?? 'Configured Android version source'}</code></p>
      {row.issues.map((code) => <p key={code}>{savedMetadataRemediation(code)}</p>)}
    </div>
  </li>;
}
export function SavedMetadataValidation({ state, controller, onSettings, onVersion }: {
  state: SavedMetadataState; controller: SavedMetadataValidationController; onSettings: () => void; onVersion: () => void;
}) {
  const reason = controller.startReason(), report = state.report;
  const label = state.status === 'checking' ? 'Checking saved files…' : state.status === 'checked' ? 'Completed local checks' :
    state.status === 'issues' ? 'Needs attention' : state.status === 'incomplete' ? 'Check incomplete' : 'Not checked';
  return <section className="card" aria-label="Saved metadata validation">
    <SectionHeading title="Saved metadata validation" description="One explicit check of the saved project, selected platform and every configured locale. In-memory drafts are not validated or saved.">
      <Badge tone={state.status === 'issues' || state.status === 'incomplete' ? 'warning' : state.status === 'checked' ? 'info' : 'neutral'}>{label}</Badge>
    </SectionHeading>
    <div className="button-row">
      <label>Saved platform <select value={state.platform ?? ''} disabled={!state.platforms.length}
        onChange={(event) => { const selected = event.currentTarget.value; if (selected === 'android' || selected === 'ios') controller.selectPlatform(selected); }}>
        {!state.platform && <option value="">No configured platform</option>}
        {state.platforms.map((selected) => <option key={selected} value={selected}>{selected === 'android' ? 'Android' : 'iOS'}</option>)}
      </select></label>
      <button type="button" className="button primary" disabled={reason !== null} onClick={() => void controller.validate()}>Validate metadata</button>
    </div>
    <p>All saved locales: {state.locales.length ? state.locales.join(', ') : 'No configured locale list available.'}</p>
    {reason && <p className="review-caution">{reason}</p>}
    {state.pending && state.status !== 'checking' && <p role="status">The earlier display was retired. Its original passive request still has to settle; no new check or competing saved operation can start yet.</p>}
    {state.status === 'not-checked' && !state.pending && <p>Nothing runs automatically. Choose Validate metadata to inspect the selected saved scope.</p>}
    {state.status === 'checking' && <p role="status">Reading the bounded saved scope. Navigating away retires the display, not the original request.</p>}
    {state.error && <ErrorNotice error={state.error} title="No complete metadata report" />}
    {report && <>
      <p role="status">{report.valid ? 'The required files and observed optional images passed these local checks.' : 'Correct the saved files listed below, then run a new check.'} This is not Store readiness.</p>
      {report.locales.map((locale) => <div className="metadata-platform" key={locale}>
        <h3>{locale}</h3>
        <ul className="issues">{report.files.filter((row) => row.locale === locale).map((row) => <FileResult key={row.kind + ':' + (row.path ?? row.id)} row={row} />)}</ul>
        {report.imageSets.filter((group) => group.locale === locale).map((group) => <div key={group.id}>
          <p>{group.id}: {group.count} observed image{group.count === 1 ? '' : 's'}; optional group.</p>
          {group.issues.map((code) => <p className="review-caution" key={code}>{savedMetadataRemediation(code)}</p>)}
        </div>)}
      </div>)}
      {report.platform === 'ios' && <div className="metadata-platform"><h3>Fixed iOS review and TestFlight notes</h3>
        <p>Only the three named note files are checked. Their contents, lengths, summaries and hashes are never shown. Other review/TestFlight files are outside scope.</p>
        <ul className="issues">{report.files.filter((row) => row.kind === 'ios-note').map((row) => <FileResult key={row.id} row={row} />)}</ul>
      </div>}
    </>}
    <div className="button-row">
      <a className="button secondary" href="#metadata-text-editor">Public text editor</a>
      <a className="button secondary" href="#metadata-image-editor">Image editor</a>
      <button type="button" className="button secondary" onClick={onVersion}>Saved version</button>
      <button type="button" className="button secondary" onClick={onSettings}>Project settings</button>
    </div>
    <p>Required Android changelogs and the three fixed iOS notes must be corrected at their displayed saved paths; this report never writes them.</p>
    <details><summary>Scope and limits · not Store readiness</summary>
      <p>This is a single-request, non-atomic observation, not a filesystem snapshot. Refresh and check again after external edits. Unrelated sibling trees, other platforms, private contact/demo fields, credentials, signing material and key storage are not inspected.</p>
      <p>Images use existing PNG/JPEG header, dimension, duplicate and count checks. Pixels are not decoded or visually reviewed. Missing image slots are optional in this local policy; a completed report does not certify Store/device screenshot coverage.</p>
      <p>No URL reachability, account permissions, network, project-code execution or Store readiness is checked. Draft validation and local completion are not Store acceptance.</p>
      <p>Existing bounded reads: 128 files, 8 MiB aggregate, 10,000 directory entries, 12 path components, 32 KiB text, 5-second cooperative work limit and 10-second passive endpoint. Images also retain the core 10 MiB ceiling, subject to the smaller aggregate budget. Reports are limited to 256 KiB. Exhaustion, unsafe paths, changes or unconfirmed cleanup produce an incomplete check, never a partial success.</p>
    </details>
  </section>;
}
