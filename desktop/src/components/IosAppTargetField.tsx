import type { IosAppTargetHints } from '../iosAppTargetHints.ts';

export function IosAppTargetField({ value, hints, choiceDisabled, onChange, onChoose }: {
  value: string; hints: IosAppTargetHints; choiceDisabled: boolean;
  onChange: (value: string) => void; onChoose: (name: string) => void;
}) {
  return <>
    {hints.state === 'available' && <label className="field">
      <span className="field-label">Targets read from your project</span>
      <select value="" disabled={choiceDisabled} onChange={event => { if (event.target.value) onChoose(event.target.value); }}>
        <option value="">Choose a target name…</option>
        {hints.targets.map(target => <option key={target.name} value={target.name}>{target.name}</option>)}
      </select>
      <span className="field-help">This only fills the local field below. No target is selected automatically.</span>
    </label>}
    <label className="field"><span className="field-label">iOS app target</span>
      <input type="text" autoComplete="off" spellCheck={false} maxLength={255} value={value}
        onChange={event => onChange(event.target.value)} />
      <span className="field-help">Or copy the app’s exact name from Targets in Xcode. A scheme name may be different. This choice is local, not a saved setting.</span>
    </label>
    <p className="subtle-note">{hints.message}</p>
    {hints.source && <details><summary>Target source</summary><p><code>{hints.source}{hints.diagnosticLine ? `:${hints.diagnosticLine}` : ''}</code></p></details>}
  </>;
}
