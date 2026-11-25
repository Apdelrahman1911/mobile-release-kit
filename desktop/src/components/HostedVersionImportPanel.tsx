import { useId, useState } from 'react';
import { HOSTED_VERSION_IMPORT_LIMIT, parseHostedVersionProposal } from '../hostedVersionImport.ts';
import type { ReleaseVersionEditController, VersionEditState } from '../releaseVersionEditController.ts';

export function HostedVersionImportPanel({ state, controller, onGit }: {
  state: VersionEditState; controller: ReleaseVersionEditController; onGit?: () => void;
}) {
  const id = useId(), [raw, setRaw] = useState('');
  const parsed = parseHostedVersionProposal(raw), held = state.edit.attempt?.binding.proposal;
  const openReason = controller.hostedOpenReason(), commitReason = controller.hostedCommitReason();
  return <details open={held ? true : undefined} className="version-import">
    <summary>Use a version reserved by GitHub Actions</summary>
    <p>Already reserved a version in GitHub Actions? Refresh this project’s Changes in Git, then paste the result from that successful run. Otherwise, use the ordinary saved-version editor below.</p>
    <details><summary>Where to find the result</summary>
      <p>In GitHub → Actions, open the existing successful <strong>Mobile internal candidate</strong> run that used operation <code>reserve-version</code>. In its <code>version_reserve</code> job, open <strong>Reserve a version only; retain candidate and reviewed change data</strong>.</p>
      <p>Copy only the complete JSON result line, unchanged—not the whole log. Do not rerun the reservation just to recover missing output; ask whoever manages that workflow if the result is unavailable.</p>
    </details>
    <p><strong>Pasted values are not yet verified.</strong> You still review the local version file and confirm Save separately. This does not check the shared counter or Store records, reserve another number, or approve a build.</p>
    <label htmlFor={id}>Result copied from GitHub Actions (JSON)</label>
    <textarea id={id} rows={5} value={raw} maxLength={HOSTED_VERSION_IMPORT_LIMIT} spellCheck={false} autoComplete="off"
      onChange={event => { const value = event.target.value; if (new TextEncoder().encode(value).length <= HOSTED_VERSION_IMPORT_LIMIT) setRaw(value); }} />
    {raw && !parsed && <p role="alert">This is not a supported complete result. Copy the original JSON line without editing it (maximum 8 KiB). Older result formats need manual review; do not rerun the reservation to change the format.</p>}
    {parsed && <p>Proposed {parsed.name} · Build {parsed.build} · <code>{parsed.path}</code>. No file has been changed by pasting.</p>}
    <div className="button-row"><button type="button" className="button secondary" disabled={!parsed || openReason !== null}
      title={openReason ?? undefined} onClick={() => controller.openHostedProposal(raw)}>Open version editor with these values</button>
      <button type="button" className="text-button" disabled={!onGit} onClick={onGit}>Go to Git to refresh changes</button></div>
    {openReason && <p className="subtle-note">{openReason}</p>}
    {held && <p>Use <strong>Validate and review values</strong> below, inspect the complete file, then confirm <strong>Save version values</strong>.
      Editing these values keeps a manual draft, but stops using the imported result.</p>}
    {held && <><p>After Save succeeds, refresh Changes in Git again. You can then fill an empty commit-message field with the reservation note.
      You still choose the version file, review and commit it in Git. Nothing is committed or pushed automatically.</p>
      <button type="button" className="button secondary" disabled={commitReason !== null} title={commitReason ?? undefined}
        onClick={() => controller.prefillHostedCommitMessage()}>Fill in the commit message</button>
      {commitReason && <p className="subtle-note">{commitReason}</p>}</>}
    {state.hostedImportIssue && <p role="status">{state.hostedImportIssue}</p>}
    <details><summary>What is checked later?</summary>
      <p>Git and the version file are checked separately; either can change afterward. The later CI check verifies the reservation and the exact version-only commit. This panel does not change protected CI settings.</p>
    </details>
  </details>;
}
