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
    <p>Run the separate protected <code>reserve-version</code> workflow first. Refresh this project’s Changes in Git, then paste its complete JSON result below.</p>
    <p><strong>Unverified proposed values only.</strong> Pasting does not verify the shared counter or Store inventory, reserve again, or authorize a build.
      This project’s own saved-version editor must still open the file and show its full review.</p>
    <label htmlFor={id}>Reservation workflow result (one unmodified JSON line)</label>
    <textarea id={id} rows={5} value={raw} maxLength={HOSTED_VERSION_IMPORT_LIMIT} spellCheck={false} autoComplete="off"
      onChange={event => { const value = event.target.value; if (new TextEncoder().encode(value).length <= HOSTED_VERSION_IMPORT_LIMIT) setRaw(value); }} />
    {raw && !parsed && <p role="alert">Use the complete current workflow result, at most 8 KiB. Older results without branch and saved-config comparisons need manual review.</p>}
    {parsed && <p>Proposed {parsed.name} · Build {parsed.build} · <code>{parsed.path}</code>. No file has been changed by pasting.</p>}
    <div className="button-row"><button type="button" className="button secondary" disabled={!parsed || openReason !== null}
      title={openReason ?? undefined} onClick={() => controller.openHostedProposal(raw)}>Open and prefill version values</button>
      <button type="button" className="text-button" disabled={!onGit} onClick={onGit}>Open Git / refresh Changes</button></div>
    {openReason && <p className="subtle-note">{openReason}</p>}
    {held && <p>Use <strong>Validate and review values</strong> below, inspect the complete file, then confirm <strong>Save version values</strong>.
      Changing these proposed strings retires the import and keeps a manual draft.</p>}
    {held && <><p>After a successful Save, refresh Changes in Git again. Then this optional shortcut can prepare an empty commit message.
      You must still stage the version file and review the complete commit in Git; no commit or push is automatic.</p>
      <button type="button" className="button secondary" disabled={commitReason !== null} title={commitReason ?? undefined}
        onClick={() => controller.prefillHostedCommitMessage()}>Prefill the commit message</button>
      {commitReason && <p className="subtle-note">{commitReason}</p>}</>}
    {state.hostedImportIssue && <p role="status">{state.hostedImportIssue}</p>}
    <p className="subtle-note">Git and file observations are separate, not an atomic snapshot. The later CI check verifies the actual ledger row and exact version-only commit.
      Protected CI settings are not changed here.</p>
  </details>;
}
