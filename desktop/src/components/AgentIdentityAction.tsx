import { useId, useSyncExternalStore } from 'react';
import type { AgentIdentityActionController } from '../agentIdentityActions.ts';

export function AgentIdentityAction({ controller }: { controller: AgentIdentityActionController }) {
  const id = useId(), state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const { analysis, change, status } = state;
  return <div className="review-panel" aria-labelledby={`${id}-title`}>
    <h3 id={`${id}-title`}>Let the agent finish this exact change</h3>
    <p>Optional. After you read and review the source here, the CLI can preview and start this one change. It cannot choose another ID, target or source revision.</p>
    {analysis && change && <>
      <p><code>{analysis.identity}</code> → <code>{change.desiredIdentity}</code></p>
      <details><summary>Source files covered by this permission</summary><ul>{analysis.locations.map((row, i) =>
        <li key={`${row.path}-${row.line}-${i}`}><code>{row.path}:{row.line}:{row.column}</code></li>)}</ul>
        <p>Only the app ID and matching saved setting may change. Namespaces, source packages and reserved versions stay unchanged. This is not a Store availability or built-app check.</p>
      </details>
      {!state.claimed && <label className="checkbox-row"><input type="checkbox" checked={state.reviewed}
        disabled={state.pending > 0} onChange={e => controller.acknowledge(e.target.checked)} />
        I reviewed this source and exact ID change. Allow the agent to preview and start it once.</label>}
    </>}
    <p role="status" className={state.attention ? 'review-caution' : 'subtle-note'}>{state.message}</p>
    <div className="button-row">
      {!state.claimed && <button type="button" className="button primary" disabled={!state.canAllow} onClick={() => controller.allow()}>Allow this exact change once</button>}
      <button type="button" className="button secondary" disabled={!state.canCheck} onClick={() => controller.check()}>Check agent edit status</button>
      <button type="button" className="button secondary" disabled={!state.canRevoke} onClick={() => controller.revoke()}>Revoke and request Stop</button>
    </div>
    {status && <details><summary>Original CLI request</summary>
      <p>Prepare/start permission is separate from proposal permission. It expires with this original review and is never renewed by status checks.</p>
      <code>mrk identity-status {status.origin.projectId} {status.origin.serviceInstance} {status.origin.intentId} --json</code>
      <p>{status.observation?.state ?? 'No original operation update yet'} · {status.observation?.settlement ?? 'not observed'}</p>
      <p>Do not repeat Apply here. If the original operation needs recovery, use the existing interrupted-change review below. Missing history never proves completion.</p>
    </details>}
  </div>;
}
