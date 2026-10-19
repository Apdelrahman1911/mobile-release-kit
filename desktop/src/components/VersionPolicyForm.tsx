import { useId, useSyncExternalStore } from 'react';
import { versionAutomationUnavailable, versionPolicyFromDraft } from '../versionAutomation.ts';
import type { VersionIncrement, VersionPolicyDraft, VersionReservationIntentController } from '../versionAutomation.ts';

const noSubscribe = () => () => {};
const noSnapshot = () => 0;

export function VersionPolicyForm({ draft, onDraftChange, controller }: {
  draft: VersionPolicyDraft; onDraftChange: (draft: VersionPolicyDraft) => void;
  controller?: VersionReservationIntentController;
}) {
  const id = useId();
  useSyncExternalStore(controller?.subscribe ?? noSubscribe, controller?.getSnapshot ?? noSnapshot);
  const change = (next: VersionPolicyDraft) => { controller?.retire(); onDraftChange(next); };
  const policy = versionPolicyFromDraft(draft);
  const blocked = controller?.startReason() ?? (controller ? null : versionAutomationUnavailable);
  const modeId = id + '-mode';
  return <section className="card" aria-label="Optional version policy draft">
    <h3>Optional version automation</h3>
    <p>Manual is the default. These are draft rules only. They do not save settings, change your version file or reserve a number.</p>
    <label htmlFor={modeId}>Version policy</label>
    <select id={modeId} value={draft.mode} onChange={(event) => {
      const mode = event.target.value === 'automatic' ? 'automatic' : 'manual';
      change({ ...draft, mode, rules: mode === 'automatic' && draft.rules.length === 0 ? [{ ref: '', increment: 'build' }] : draft.rules });
    }}>
      <option value="manual">Manual (default)</option>
      <option value="automatic">Shared version numbers (GitHub)</option>
    </select>
    {draft.mode === 'manual' ? <p>Use the separate saved-version editor. Returning to Manual does not cancel, delete or recycle earlier reservations.</p> : <>
      <p>Desktop, CLI and GitHub must share the same enrolled repository ledger. Automatic allocation refuses disconnected authority or stale/incomplete Store observations; it never guesses a local next build.</p>
      {draft.rules.map((rule, index) => <fieldset key={index}>
        <legend>Branch or tag rule {index + 1}</legend>
        <label htmlFor={id + '-ref-' + index}>Branch or tag ref</label>
        <input id={id + '-ref-' + index} value={rule.ref} maxLength={220} spellCheck={false} autoComplete="off"
          placeholder="refs/heads/main" onChange={(event) => change({ ...draft,
            rules: draft.rules.map((item, current) => current === index ? { ...item, ref: event.target.value } : item) })} />
        <p>Use <code>refs/heads/main</code> for branch <code>main</code>, or <code>refs/tags/v1.2.3</code> for a tag. Wildcards are not supported.</p>
        <label htmlFor={id + '-increment-' + index}>Increment</label>
        <select id={id + '-increment-' + index} value={rule.increment} onChange={(event) => change({ ...draft,
          rules: draft.rules.map((item, current) => current === index ? { ...item, increment: event.target.value as VersionIncrement } : item) })}>
          <option value="build">Build only</option><option value="patch">Patch</option><option value="minor">Minor</option><option value="major">Major</option>
        </select>
        <button type="button" className="text-button" onClick={() => change({ ...draft, rules: draft.rules.filter((_, current) => current !== index) })}>Remove rule</button>
      </fieldset>)}
      <button type="button" className="button secondary" disabled={draft.rules.length >= 32}
        onClick={() => change({ ...draft, rules: [...draft.rules, { ref: '', increment: 'build' }] })}>Add branch or tag rule</button>
      <details><summary>Allocation bounds</summary>
        <label htmlFor={id + '-ceiling'}>Build ceiling</label>
        <input id={id + '-ceiling'} value={draft.buildCeiling} inputMode="numeric" maxLength={10}
          onChange={(event) => change({ ...draft, buildCeiling: event.target.value })} />
        <label htmlFor={id + '-age'}>Maximum Store observation age (seconds)</label>
        <input id={id + '-age'} value={draft.storeMaxAgeSeconds} inputMode="numeric" maxLength={4}
          onChange={(event) => change({ ...draft, storeMaxAgeSeconds: event.target.value })} />
        <p>The native policy also enforces platform limits. The current iOS path uses a shared integer build up to 9999; it does not silently convert to a dotted build. Manual input rules are unchanged.</p>
      </details>
      {!policy && <p role="alert">Policy draft is incomplete or invalid. Use unique exact refs; no globs, trimming or inferred branch rules.</p>}
      <button type="button" className="button primary" disabled={!policy || blocked !== null} title={blocked ?? undefined}
        onClick={() => { const intent = controller?.prepare(); if (intent) controller?.submit(intent); }}>Reserve version numbers</button>
      {blocked && <p>{blocked}</p>}
      <p>A reservation holds numbers for this release attempt. It does not save files, build the app or submit anything to a Store. Saving still needs a separate review; uploads need their own checks and approval. A tag rule never authorizes moving a tag.</p>
    </>}
  </section>;
}
