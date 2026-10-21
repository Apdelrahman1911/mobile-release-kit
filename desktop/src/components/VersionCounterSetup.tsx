import type { GitHubPublicationController } from '../githubPublicationController.ts';
import { githubPublicationOwnerReason } from '../githubPublicationController.ts';
import { PUBLICATION_HELP } from '../githubPublicationProtocol.ts';
import type { PublicationView } from '../githubPublicationTypes.ts';
import { COUNTER_PURPOSE, COUNTER_BRANCH, COUNTER_PATH, counterPrepared, counterSummary } from '../versionCounterSetup.ts';
// Presentation of the SAME publication original. No on-mount action, token,
// native state receipt, allocation, protection update or enrollment handoff.
export function VersionCounterSetup({ state, controller, readReason, onReadSaved }: {
  state: PublicationView; controller: GitHubPublicationController; readReason: string | null; onReadSaved: () => void;
}) {
  const selected = state.purpose === COUNTER_PURPOSE, current = controller.currentConsent();
  const review = current && counterPrepared(current.prepared) ? current.prepared : null;
  const op = state.status?.operation, ownOperation = op?.purpose === COUNTER_PURPOSE ? op : null;
  const owner = githubPublicationOwnerReason(state), prepare = controller.prepareReason(), publish = controller.publishReason();
  const pending = state.status?.pending.filter((p) => counterSummary(p.summary)) ?? [];
  return <section className="panel" aria-label="Create a first shared version counter">
    <h3>Create a first shared version counter</h3>
    <p>Optional, for a repository that has no counter. This creates only <code>{COUNTER_PATH}</code> on the fixed new <code>{COUNTER_BRANCH}</code> branch. It does not publish application files, allocate or change a version, contact Stores, protect the branch or connect this computer.</p>
    <p>The saved initial version is data, <strong>not a verified Store floor</strong>. For an already-published app, reconcile Store history and current floors before reservation. Never reset a missing counter to zero. Known prior local state or creation intents refuse; a fresh computer cannot prove that someone never deleted older remote history.</p>
    {!selected && <button type="button" className="button secondary" disabled={!!owner && !current} onClick={() => controller.setPurpose(COUNTER_PURPOSE)}>Choose first-counter setup</button>}
    {ownOperation && <p role="status">Original {ownOperation.kind}: {ownOperation.phase} · {ownOperation.effect}. {PUBLICATION_HELP[ownOperation.reason]}</p>}
    {selected && <>
      {(state.error || state.status && !state.status.available) && <p role="status">{PUBLICATION_HELP[state.error ?? state.status!.reason]}</p>}
      <div className="button-row">
        <button type="button" className="button secondary" disabled={!!readReason} title={readReason ?? undefined} onClick={onReadSaved}>Read saved version inputs</button>
        <button type="button" className="button secondary" disabled={state.observing || state.mode !== 'native'} onClick={() => void controller.checkStatus()}>Read local publication status</button>
        <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Stop original publication</button>
      </div>
      <label>Existing source branch<input aria-label="Counter setup source branch" maxLength={200} value={state.base} disabled={!!owner && !current} onChange={(e) => controller.setBase(e.target.value)} placeholder="Commit and push the source first" /></label>
      <p>Use the current connected repository account with Contents read/write access. Creating the ref may start existing repository automation. The source branch is compared, never changed; an empty repository is not supported here.</p>
      <button type="button" className="button secondary" disabled={!!prepare} title={prepare ?? undefined} onClick={() => controller.prepare()}>Review first counter</button>
      {prepare && !review && <p>{prepare}</p>}
      {review && <div className="review-panel">
        <p>Repository <strong>{review.target.repository}</strong> · repository ID {review.target.repositoryId} · account {review.target.accountId}</p>
        <p>Saved initial version <strong>{review.target.initialVersion.name} ({review.target.initialVersion.build})</strong>; not Store-verified. Source <code>{review.target.base}</code> at <code>{review.baseCommit}</code>.</p>
        <p>New ledger <code>{review.target.ledgerId}</code> · genesis <code>{review.genesisSha256}</code>. This exact native review expires at {current!.expiresAt}.</p>
        <details><summary>Exact new ledger contents</summary><pre tabIndex={0}>{review.ledger}</pre></details>
        <label><input type="checkbox" checked={state.confirmed} onChange={(e) => controller.setConfirmed(e.target.checked)} />{review.confirmation}</label>
        <div className="button-row"><button type="button" className="button" disabled={!!publish} title={publish ?? undefined} onClick={() => controller.publish()}>Create first counter once</button>
          <button type="button" className="button secondary" disabled={state.discarding} onClick={() => controller.discardReview()}>Discard this review</button></div>
      </div>}
      <button type="button" className="button secondary" disabled={!!controller.pendingReason()} title={controller.pendingReason() ?? undefined} onClick={() => controller.loadPending()}>Load original publication intents</button>
    </>}
    {pending.map((p) => <div key={p.summary.target.marker}><p>Original counter for {p.summary.target.repository} · marker <code>{p.summary.target.marker}</code>. Claimed: {p.claimed.join(', ') || 'none'}; confirmed: {Object.keys(p.confirmed).join(', ') || 'none'}.</p>
      <button type="button" className="button small secondary" disabled={!!controller.reconcileReason(p.summary.target.marker)} onClick={() => controller.reconcile(p.summary.target.marker)}>Read-only reconcile this original</button></div>)}
    {state.status?.counter && <p role="status">Counter observed at <code>{state.status.counter.commit}</code>. <strong>Protection and connection are still required.</strong> This is not a reservation, verified Store floor, build or release.</p>}
    <p>After creation, the repository owner must explicitly configure supported classic protection for <code>{COUNTER_BRANCH}</code>: enforce administrators; disallow force pushes and deletions. Then use the separate existing <em>Review shared counter</em> and <em>Connect on this computer</em> controls below. Reading that protection may require Administration:read. Inaccessible or ruleset-only protection is not silently accepted.</p>
    <p>Unknown outcomes retain the original intent. Status and reconciliation never retry Create. Cancellation cannot undo sent GitHub requests.</p>
  </section>;
}
