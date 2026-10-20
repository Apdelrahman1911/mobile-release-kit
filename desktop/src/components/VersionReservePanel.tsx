import { useId, useSyncExternalStore } from 'react';
import type { VersionReserveController } from '../versionReserveController.ts';
import type { VersionIncrement } from '../versionReserve.ts';
import { versionReserveHelp } from '../versionReserve.ts';
import { AgentVersionReserveAccess } from './AgentVersionReserveAccess.tsx';

// No effect/mount API calls. Root retains this original controller on navigation.
export function VersionReservePanel({ controller, compact = false }: { controller: VersionReserveController; compact?: boolean }) {
  const state = useSyncExternalStore(controller.subscribe, controller.getSnapshot, controller.getSnapshot);
  const id = useId(), busy = controller.ownerReason(), status = state.status;
  if (compact && !busy) return null;
  const configure = (value: Partial<typeof state.options>) => controller.configure({ ...state.options, ...value });
  return <section className={compact ? 'notice notice-warning' : 'card'} aria-labelledby={`${id}-title`}>
    <h3 id={`${id}-title`}>{compact ? 'Original version reservation' : 'Automatic version · optional'}</h3>
    {!compact && <>
      <p>Manual editing stays the default. This option uses the connected shared counter and current Store inventories for every enabled platform; it does not build or upload an app.</p>
      <label><input type="checkbox" checked={state.enabled} disabled={!!busy} onChange={(e) => controller.setEnabled(e.target.checked)} /> Use a shared reservation for this version</label>
      {state.enabled && <fieldset disabled={!!busy}>
        <legend>What should change?</legend>
        <label htmlFor={`${id}-branch`}>Checked-out branch</label>
        <input id={`${id}-branch`} value={state.options.reference} placeholder="refs/heads/main" maxLength={211} autoComplete="off" spellCheck={false}
          onChange={(e) => configure({ reference: e.target.value })} />
        <label htmlFor={`${id}-increment`}>Version change</label>
        <select id={`${id}-increment`} value={state.options.increment} onChange={(e) => configure({ increment: e.target.value as VersionIncrement })}>
          <option value="build">Build only — keep the marketing version</option><option value="patch">Patch — for example 1.2.3 → 1.2.4</option>
          <option value="minor">Minor — for example 1.2.3 → 1.3.0</option><option value="major">Major — for example 1.2.3 → 2.0.0</option>
        </select>
        <label><input type="checkbox" checked={state.options.newCandidate} onChange={(e) => configure({ newCandidate: e.target.checked })} /> Start a different candidate after reviewing the previous one</label>
        <p className="save-note">Leave this unchecked to resume the same candidate. Failed or uncertain requests never get a new number automatically. Earlier numbers are never recycled.</p>
        <label><input type="checkbox" checked={state.options.acknowledgeLimitations} onChange={(e) => configure({ acknowledgeLimitations: e.target.checked })} />
          I understand that current Store listings are not a complete history and that uploaders outside this shared counter can still conflict.</label>
        <p className="save-note">Check “Current Play versions” or “Current App Store versions” first and connect the shared counter in GitHub. For a shared Android+iOS source, use “Shared Android + iOS versions” under the dedicated paired credential context. A checked-out branch is required. Android-only builds support up to 2,100,000,000; iOS and shared builds up to 9,999. Missing, stale, partial or unsupported Store data stops this action; it never falls back to a guessed floor.</p>
      </fieldset>}
    </>}
    <p role={state.unknown ? 'alert' : 'status'}>{state.unknown ? 'Original outcome or cleanup unconfirmed' : state.pending === 'review' ? 'Reading the exact saved source…' :
      state.pending === 'reserve' ? 'Reserving on the shared counter…' : status?.phase === 'reserved' ? 'Number reserved — not yet saved to the project' :
      status?.phase === 'reviewed' ? 'Choices reviewed — no number reserved by this review' : 'No current usable reservation'}</p>
    {state.stale && status && <p>This earlier observation is not permission to reserve or edit.</p>}
    {status?.reservation && <p>Candidate version: <strong>{status.reservation.name} · Build {status.reservation.build}</strong>. This is not a Store acceptance or a saved-file receipt.</p>}
    <p className="save-note">{state.issue ?? versionReserveHelp(status?.reason ?? null)}</p>
    <div className="button-row">
      {!compact && state.enabled && <><button type="button" className="button secondary" disabled={controller.reviewReason() !== null} onClick={() => void controller.review()}>Review version choices</button>
        <button type="button" className="button primary" disabled={controller.reserveReason() !== null} onClick={() => void controller.reserve()}>Reserve this candidate</button>
        <button type="button" className="button secondary" disabled={controller.editReason() !== null} onClick={() => controller.edit()}>Open reserved version for review</button></>}
      <button type="button" className="button secondary" disabled={controller.checkReason() !== null} onClick={() => void controller.check()}>Check original status</button>
      <button type="button" className="button secondary" disabled={controller.stopReason() !== null} onClick={() => void controller.stop()}>Stop</button>
    </div>
    {!compact && state.enabled && <p className="toolbar-reason">{busy ?? (status?.phase === 'reserved' ? controller.editReason() : status?.phase === 'reviewed' ? controller.reserveReason() : controller.reviewReason()) ??
      'The original reservation has a short, fixed deadline. Open the editor promptly, then review and confirm its separate Save.'}</p>}
    {state.editHandedOff && <p>Continue in the saved-version editor below. Its original status and recovery controls own the file operation.</p>}
    <AgentVersionReserveAccess controller={controller.cliAccess} check={controller.checkCliAccess} compact={compact} />
  </section>;
}
