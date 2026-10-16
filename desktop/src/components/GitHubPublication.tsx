import type { GitHubPublicationController } from '../githubPublicationController.ts';
import { githubPublicationOwnerReason } from '../githubPublicationController.ts';
import { PUBLICATION_HELP } from '../githubPublicationProtocol.ts';
import type { PublicationView } from '../githubPublicationTypes.ts';
export function GitHubPublication({ state, controller, compact = false, onShow }: { state: PublicationView; controller: GitHubPublicationController; compact?: boolean; onShow?: () => void }) {
  const status = state.status, op = status?.operation, consent = controller.currentConsent();
  const prepareReason = controller.prepareReason(), publishReason = controller.publishReason(), pendingReason = controller.pendingReason();
  const owner = githubPublicationOwnerReason(state);
  if (compact && !owner && !state.error && !op) return null;
  const controls = <div className="button-row">
    <button type="button" className="button small secondary" onClick={() => void controller.checkStatus()} disabled={state.observing || state.mode !== 'native'}>Read local publication status</button>
    <button type="button" className="button small secondary" onClick={() => controller.cancel()} disabled={!controller.canCancel()}>Stop original publication</button>
    {compact && <button type="button" className="button small secondary" onClick={onShow}>Show setup publication</button>}
  </div>;
  return <section className="panel" aria-label="Publish setup draft pull request">
    <h3>Publish setup as a draft pull request</h3>
    {op && <p role="status">Original {op.kind}: {op.phase} · {op.effect}. {PUBLICATION_HELP[op.reason]}</p>}
    {state.originalTarget && <p>Original repository: <strong>{state.originalTarget.repository}</strong> · account {state.originalTarget.accountId} · repository ID {state.originalTarget.repositoryId}</p>}
    {(state.error || status && !status.available) && <p role="status">{PUBLICATION_HELP[state.error ?? status!.reason]}</p>}
    {controls}
    {!compact && <>
      <p>Publishes only the saved <code>release/mobile-release.json</code> and four toolkit-generated workflow callers. Applying files locally is not publication. Unsaved settings, release versions, metadata, images and application source are excluded.</p>
      <p>Use an authorized GitHub account with Contents, Workflows and Pull requests write access. Prepare and reconcile are remote reads; Publish creates Git objects, a new branch and a draft PR. Existing push/PR workflows may execute. No signing, Store submission, merge or automatic workflow dispatch is requested.</p>
      <label>Existing base branch<input aria-label="Setup publication base branch" maxLength={200} value={state.base} onChange={(e) => controller.setBase(e.target.value)} disabled={!!owner && !consent} placeholder="Choose an existing branch" /></label>
      <div className="button-row"><button type="button" className="button secondary" disabled={!!prepareReason} title={prepareReason ?? undefined} onClick={() => controller.prepare()}>Prepare exact five-file review</button>
        <button type="button" className="button secondary" disabled={!!pendingReason} title={pendingReason ?? undefined} onClick={() => controller.loadPending()}>Load saved publication intents</button></div>
      {prepareReason && !consent && <p>{prepareReason}</p>}
      {consent && <div className="review-panel">
        <h4>Review all five files before publishing</h4>
        <p>Repository <strong>{consent.prepared.target.repository}</strong> · account {consent.prepared.target.accountId} · repository ID {consent.prepared.target.repositoryId}</p>
        <p>Base <code>{consent.prepared.target.base}</code> at <code>{consent.prepared.baseCommit}</code><br />New branch <code>{consent.prepared.head}</code><br />Toolkit <code>{consent.prepared.target.toolingRepository}@{consent.prepared.target.toolingSha}</code></p>
        <p>These are complete before/after contents, not a full-project diff. The base can move after observation; no atomic remote lock or rollback is promised. Review expires at {consent.expiresAt}.</p>
        {consent.prepared.files.map((file) => <details key={file.path}><summary>{file.path} — {file.before === null ? 'new file' : file.before === file.after ? 'unchanged' : 'replace'}</summary>
          <h5>Before on selected GitHub base</h5>{file.before === null ? <p>Absent</p> : <pre tabIndex={0}>{file.before}</pre>}
          <h5>After publication</h5><pre tabIndex={0}>{file.after}</pre></details>)}
        <label><input type="checkbox" checked={state.confirmed} onChange={(e) => controller.setConfirmed(e.target.checked)} />{consent.prepared.confirmation}</label>
        <div className="button-row"><button type="button" className="button" disabled={!!publishReason} title={publishReason ?? undefined} onClick={() => controller.publish()}>Create new branch and draft PR</button>
          <button type="button" className="button secondary" onClick={() => controller.discardReview()} disabled={state.discarding}>Discard this review</button></div>
      </div>}
      {!!status?.pending.length && <div><h4>Durable original intents</h4><p>These records preserve attempted steps, including unknown effects. Reconcile makes GET requests only; it never repeats a write, repairs a branch or creates another PR.</p>
        {status.pending.map((entry) => <div key={entry.summary.target.marker}><p><code>mrk/setup-{entry.summary.target.marker}</code> → <code>{entry.summary.target.base}</code> at <code>{entry.summary.baseCommit}</code></p>
          <p>Claimed: {entry.claimed.join(', ') || 'none'}. Confirmed: {Object.keys(entry.confirmed).join(', ') || 'none'}.</p>
          <button type="button" className="button small secondary" disabled={!!controller.reconcileReason(entry.summary.target.marker)} onClick={() => controller.reconcile(entry.summary.target.marker)}>Read-only reconcile original</button></div>)}</div>}
      {status?.pull && <p>Observed original draft PR: <a href={status.pull.url} target="_blank" rel="noopener noreferrer">#{status.pull.number}</a> at <code>{status.pull.commit}</code>. This is a repository observation, not a successful build or release.</p>}
      <p>No automatic retries. After an uncertain Publish, first read local Status; once the original settles, load its saved intent and reconcile. Cancellation does not undo a sent request.</p>
    </>}
  </section>;
}
