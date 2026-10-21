import { useSyncExternalStore } from 'react';
import type { ConfigurationServiceController } from '../serviceConfigurationController.ts';
export function ServiceConfigurationAccess({controller, detailed, onShow}: {controller: ConfigurationServiceController; detailed: boolean; onShow: () => void}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const request = state.status?.request, review = request?.review, reason = controller.allowReason();
  if (!detailed && !request && !state.pending && !state.unknown) return null;
  return <section className="card" aria-label="CLI configuration review">
    <h3>CLI project settings</h3>
    <p>Existing project READ access permits a saved-settings read and preview. Only your approval of this exact preview permits one Apply. A running Desktop is required.</p>
    {request && <p><strong>{request.phase}</strong> · registered project <code>{request.runtimeProjectId}</code> · request <code>{request.origin.requestId}</code></p>}
    {state.message && <p role="status">{state.message}</p>}
    {detailed && review && <>
      <h4>Native comparison</h4>
      <div className="form-grid"><div><strong>Saved values</strong><pre>{JSON.stringify(review.before, null, 2)}</pre></div><div><strong>Proposed values</strong><pre>{JSON.stringify(review.after, null, 2)}</pre></div></div>
      <ul>{review.files.map(file => <li key={file.path}><code>{file.path}</code>: {file.action}; {file.beforeBytes === null ? 'absent' : `${file.beforeBytes} bytes`} → {file.afterBytes} bytes</li>)}</ul>
      {review.createReleaseDirectory && <p>The original plan creates the release directory.</p>}
      {review.rewritesConfigFormatting && <p>The original plan also rewrites configuration formatting.</p>}
      {review.ignoreAdditions.length > 0 && <p>Root ignore additions: {review.ignoreAdditions.map(s => <code key={s}>{s} </code>)}</p>}
      <label><input type="checkbox" checked={state.acknowledged} disabled={reason !== null} onChange={e => controller.acknowledge(e.target.checked)} />I reviewed these values and all listed file effects; allow this CLI Apply once.</label>
      {reason && <p>{reason}</p>}
      <button className="button primary" type="button" disabled={reason !== null || !state.acknowledged} onClick={() => void controller.allow()}>Allow this Apply once</button>
    </>}
    <div className="button-row">
      <button className="button secondary" type="button" disabled={state.pending !== null || state.revokePending} onClick={() => void controller.check()}>Check original request</button>
      <button className="button secondary" type="button" disabled={!request || state.revokePending} onClick={() => void controller.revoke()}>Stop original request</button>
      {!detailed && <button className="button secondary" type="button" onClick={onShow}>Show configuration review</button>}
    </div>
    {detailed && <details><summary>Supported CLI settings</summary><p>Candidate/production branches, enabled Android module/variant, or enabled iOS container/scheme/archive configuration. No application identity, versions, platform enablement, commands, signing, credentials or recovery. Other fields stay unchanged.</p>
      <p><code>mrk configuration-read PROJECT_ID OBSERVATION_REVISION --json</code> returns the original IDs. Then use <code>mrk configuration-prepare … --stdin --json</code> with one closed change. Apply uses the same reviewed IDs. See <code>mrk --help</code>.</p>
      <p>No unattended/headless writer. Dirty or newer forms are preserved after a completed CLI save; inspect saved files before continuing. A missing acknowledgement never permits a retry.</p>
      <p>Large or unusually complex configurations may exceed this bounded CLI path. Keep your draft and use the ordinary editor only after the original work settles; Unknown still needs its existing recovery.</p></details>}
  </section>;
}
