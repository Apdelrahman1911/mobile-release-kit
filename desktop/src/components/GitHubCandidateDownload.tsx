import { useId, useState } from 'react';
import type { GitHubHistoryController } from '../githubHistoryController.ts';
import type { GitHubHistoryView } from '../githubHistoryTypes.ts';
import { candidateDownloadExported } from '../githubCandidateDownload.ts';

export function GitHubCandidateDownload({ controller, state }: { controller: GitHubHistoryController; state: GitHubHistoryView }) {
  const id = useId(), review = controller.downloadReview(), reason = controller.downloadReason();
  const [consent, setConsent] = useState<object | null>(null);
  const op = state.status?.operation, effect = op?.download;
  const exported = !!effect && candidateDownloadExported(effect) && op?.phase === 'settled' && op.reason === 'none'
    && state.status?.result?.verification === 'verified' && !state.uncertain;
  return <section className="github-environment" aria-label="Download verified candidate binary">
    <h3>Download verified candidate binary</h3>
    <p className="save-note">Freshly authenticate the exact candidate and save only its AAB or IPA and a provenance receipt in this project.
      This does not import, open, upload, promote or release it. Handoff ZIP and expanded contents must each fit 1 GiB.</p>
    {review && <p>Destination: <code>{review.relativePath}/{review.primary}</code> and <code>download-receipt.json</code>.</p>}
    <p className="review-caution">No overwrite or automatic retry. An occupied final or pending directory requires manual inspection.
      Verified historical bytes do not establish current signing, installability or Store state.</p>
    <label htmlFor={id}><input id={id} type="checkbox" checked={review !== null && consent === review.scope} disabled={reason !== null}
      onChange={(event) => setConsent(event.target.checked && review ? review.scope : null)} /> I approve this exact selection and fixed local destination.</label>
    <div className="button-row"><button type="button" className="button secondary" disabled={reason !== null || !review || consent !== review.scope}
      onClick={() => { if (!review || consent !== review.scope) return; setConsent(null); controller.downloadCandidate(true, review.scope); }}>
      Download candidate binary</button></div>
    {reason && <p className="save-note">{reason}</p>}
    {effect && <div role="status"><p>{exported ? 'Original download settled and the local publication was durable.' : 'Retained local-effect diagnostics — not successful export or permission to retry.'}</p>
      <p>Publication: {effect.publication}; durability: {effect.durability}; original source closes: {effect.closed ? 'returned' : 'not confirmed'}.</p>
      <p>Final: <code>{effect.relativePath}</code><br />Pending: <code>{effect.pendingPath}</code>.</p>
      {!exported && <p>Use the same Status / Cancel controls. Do not infer success from a matching file or receipt.</p>}</div>}
  </section>;
}
