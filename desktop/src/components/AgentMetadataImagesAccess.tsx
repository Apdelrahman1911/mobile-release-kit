import { useState, useSyncExternalStore } from 'react';
import type { ServiceMetadataImagesController } from '../serviceMetadataImagesController.ts';

// Ordinary picker, full preview and local-copy confirmation stay the default.
export function AgentMetadataImagesAccess({ controller }: { controller: ServiceMetadataImagesController }) {
  const state = useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const [reviewed,setReviewed] = useState<string | null>(null);
  const key = controller.approvalKey(), a = state.access, q = a?.request;
  if (!controller.available() && !state.retained && !a) return null;
  return <>
    {state.issue && <p className="review-caution" role="alert">{state.issue}</p>}
    {q && <p role="status">CLI image copy: {q.phase === 'final' && !state.retained && q.result?.completed ? 'completed locally' :
      q.phase === 'unknown' || state.unknown ? 'outcome unconfirmed — do not resend' :
      q.phase === 'final' && state.retained ? 'waiting for the original Desktop call to return' : q.phase === 'final' ? 'ended; review the outcome' : 'original request retained'}.
      {' '}Nothing is uploaded to a Store. Stop cannot undo a copy.</p>}
    <details className="advanced-settings"><summary>Advanced: let the installed CLI apply this image review</summary>
      <p>First review every destination and replacement above. This allowance permits one local copy of that same batch only.
        The CLI cannot choose files, prepare another batch, recover a journal or upload images.</p>
      <label><input type="checkbox" checked={key !== null && reviewed === key} disabled={!controller.canAllow()}
        onChange={e => setReviewed(e.target.checked ? key : null)} /> I reviewed the complete local-copy preview and allow the CLI to apply it once.</label>
      <div className="button-row"><button type="button" disabled={key === null || reviewed !== key || !controller.canAllow()}
        onClick={() => { const same = key !== null && reviewed === controller.approvalKey(); setReviewed(null); if (same) void controller.allow(); }}>Allow this copy once</button>
        <button type="button" disabled={!controller.hasAllowance()} onClick={() => void controller.revoke()}>Revoke / stop this allowance</button>
        <button type="button" disabled={state.pending || !controller.available()} onClick={() => void controller.check()}>Check original request</button></div>
      {!key && !state.retained && <p>Use the native picker and finish the image review first. Wait for its original calls to return.</p>}
      {a?.review && <p>{a.review.platform} · {a.review.locale} · {a.review.assetType}: {a.review.createCount} new, {a.review.replaceCount} replaced,
        {' '}{a.review.preserveCount} kept. This summary is not a new preview or file observation.</p>}
      {a?.live && !state.unknown && <><p>One use, at most {Math.ceil(a.remainingMs/1000)} seconds as last observed. Checking does not extend it.</p>
        <pre><code>{`mrk metadata-images-submit ${a.projectId} ${a.serviceInstance} ${a.grantId} --reviewed --json`}</code></pre></>}
      {q && <pre><code>{`mrk metadata-images-status ${q.origin.projectId} ${q.origin.serviceInstance} ${q.origin.requestId} --json`}</code></pre>}
      <p>Keep this Desktop session open. Revoke removes only this CLI allowance; close an unused image review with its original controls.
        After an unconfirmed response, check or stop the same request—never submit the copy again.</p>
    </details>
  </>;
}
