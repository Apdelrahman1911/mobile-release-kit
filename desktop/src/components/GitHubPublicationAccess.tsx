import type { GitHubPublicationController } from '../githubPublicationController.ts';
import type { GithubPublicationAction } from '../githubPublicationDelegation.ts';
import type { PublicationView } from '../githubPublicationTypes.ts';
import { publicationPurpose } from '../versionCounterSetup.ts';

/** Selection only. The ONE shared GitHub permission panel owns its separate
 * unchecked Allow and retained callers; this component cannot submit a task. */
export function GitHubPublicationAccess({ state, controller, blockedReason, onChoose }: {
  state: PublicationView;
  controller: GitHubPublicationController;
  blockedReason: string | null;
  onChoose: (kind: GithubPublicationAction) => void;
}) {
  const publish = controller.agentSelection('setup-publish');
  const chosen = controller.selectedPendingForAgent();
  const rows = state.status?.pending.filter(row => publicationPurpose(row.summary) === 'setup-pr') ?? [];
  return <div className="review-panel">
    <h4>Use this original review from the local CLI</h4>
    <p>First review the complete five-file change or choose one freshly loaded original intent below. Choosing does not prepare, publish, load, reconcile or grant permission. The shared GitHub access panel requires a separate unchecked, one-use approval.</p>
    <button type="button" className="button small secondary" disabled={!!blockedReason || !publish}
      title={blockedReason ?? undefined} onClick={() => { if (controller.agentSelection('setup-publish')) onChoose('setup-publish'); }}>
      Choose reviewed five-file Publish for CLI
    </button>
    {rows.map(row => <div key={row.summary.target.marker}>
      <p>Original <code>{row.summary.target.marker}</code> · {row.summary.target.repository} · <code>{row.summary.target.base}</code> at <code>{row.summary.baseCommit}</code>.<br />
        Claimed: {row.claimed.join(', ') || 'none'}. Confirmed: {Object.entries(row.confirmed).map(([step, value]) => `${step}: ${value}`).join(', ') || 'none'}.</p>
      <details><summary>Full original intent metadata (identities and file hashes)</summary><pre tabIndex={0}>{JSON.stringify(row, null, 2)}</pre></details>
      <button type="button" className="button small secondary" disabled={!!blockedReason || !controller.currentPending(row.summary.target.marker)}
        title={blockedReason ?? undefined} onClick={() => { if (controller.selectPendingForAgent(row.summary.target.marker)) onChoose('setup-reconcile'); }}>
        {chosen?.summary.target.marker === row.summary.target.marker ? 'Selected' : 'Choose'} this original intent for GET-only CLI reconciliation
      </button>
    </div>)}
    <p>Reconcile only compares the original saved intent with GitHub using GET requests. It never repeats a write or proves who sent an earlier request. Displayed rows from an older session are not a new permission: explicitly Load saved publication intents first. First-counter setup is not included.</p>
    {blockedReason && <p role="status">{blockedReason}</p>}
  </div>;
}
