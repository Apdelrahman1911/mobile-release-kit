import { useState, useSyncExternalStore } from 'react';
import type { ServiceVersionEditController } from '../serviceVersionEditController.ts';
// Deliberately collapsed; the ordinary review and Save remain the default.
export function AgentVersionEditAccess({controller}:{controller:ServiceVersionEditController}) {
  const state = useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const [reviewed,setReviewed] = useState<string | null>(null), a = state.access, key = controller.approvalKey();
  return <details className="advanced-settings"><summary>Advanced: allow installed CLI to save this review</summary>
    <p>Desktop must first Open and review these exact version values. This allows one CLI Save only—not allocation, enrollment, Git commit, upload, or CLI Open/Prepare.</p>
    <label><input type="checkbox" checked={key !== null && reviewed === key} onChange={e => setReviewed(e.target.checked ? key : null)} /> I reviewed the complete original/after file, exact values, destination and mode above, and allow this one Save.</label>
    <div className="button-row"><button type="button" disabled={key === null || reviewed !== key || !controller.canAllow()} onClick={() => { const same = key !== null && reviewed === controller.approvalKey(); setReviewed(null); if (same) void controller.allow(); }}>Allow this version Save once</button>
      <button type="button" disabled={!a && !state.busy} onClick={() => controller.revoke()}>Revoke this allowance</button>
      <button type="button" onClick={() => void controller.check()}>Check original request</button></div>
    {a?.live && a.review && <><p>Only {a.review.name} · Build {a.review.build}, <code>{a.review.source}</code>. Use the installed CLI in this running Desktop session:</p>
      <pre><code>{`mrk version-edit-submit ${a.projectId} ${a.serviceInstance} ${a.grantId} ${a.review.original.sessionId} ${a.review.original.planToken} --reviewed --json`}</code></pre></>}
    {a?.request && <p>Original request <code>{a.request.origin.requestId}</code>: {a.request.phase}; {a.request.settlement}. Cancel cannot undo a submitted Save. Never resend Apply after a lost response.</p>}
    {state.issue && <p role="alert">{state.issue}</p>}
  </details>;
}
