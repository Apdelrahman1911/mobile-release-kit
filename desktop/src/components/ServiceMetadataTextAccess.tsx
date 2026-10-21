import { useSyncExternalStore } from 'react';
import type { MetadataServiceController } from '../serviceMetadataTextController.ts';
// This is a permission review on the existing full native text preview above,
// not another form, Load action, writer or source authority.
export function ServiceMetadataTextAccess({controller}: {controller: MetadataServiceController}) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const request = state.status?.request, reason = controller.allowReason();
  return <details className="card"><summary>Advanced: let the installed CLI edit this locale’s public text</summary>
    <p>Enable project READ access first. The CLI can Load and propose one complete Android or iOS text bundle for an already configured locale. Review every file in the native before/after preview above before granting Apply once.</p>
    <p>No locale creation, automatic translation, image picking, configuration changes or Store upload. This requires the running Desktop; it is not headless file access.</p>
    {request && <p>Original request: <code>{request.origin.requestId}</code> · {request.platform} / {request.locale} · {request.phase}. A missing reply is not permission to submit again.</p>}
    <label><input type="checkbox" checked={state.acknowledged} disabled={reason !== null} onChange={event => controller.acknowledge(event.currentTarget.checked)} /> I reviewed all files in this exact native preview and allow one CLI Apply.</label>
    {reason && <p className="save-note">{reason}</p>}
    <div className="button-row">
      <button type="button" className="button primary" disabled={reason !== null || !state.acknowledged} onClick={() => void controller.allow()}>Allow this preview once</button>
      <button type="button" className="button secondary" disabled={!!state.pending || state.revokePending} onClick={() => void controller.check()}>Check original request</button>
      <button type="button" className="button secondary" disabled={!request || state.revokePending} onClick={() => void controller.revoke()}>Withdraw / stop original</button>
    </div>
    {state.message && <p role={state.unknown ? 'alert' : 'status'}>{state.message}</p>}
    <p>Loaded text is public comparison data, not a saved result. Native source/READ deadlines and original joins still decide. Any existing draft is kept; a completed CLI save makes its earlier baseline stale, not automatically Saved.</p>
  </details>;
}
