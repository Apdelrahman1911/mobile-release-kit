import type { AndroidToolSourceRole } from '../androidToolSources.ts';
import { stagedToolSourceGuidance } from '../toolAcquisitionGuidance.ts';
import type { StagedToolPresentation } from '../toolAcquisitionGuidance.ts';

export interface StagedToolSourcesProps {
  report: unknown; presentation: StagedToolPresentation; busy: boolean;
  // The existing source controller rechecks its original context and launches
  // the actual picker. It may not turn a cache path/report into SourceSnapshot.
  chooseSource(role: AndroidToolSourceRole): void | Promise<void>;
}
// No download button/automatic callback: native acquisition admission has not
// yet been installed. Root wires this only for an accepted original native run.
export function StagedToolSources({ report, presentation, busy, chooseSource }: StagedToolSourcesProps) {
  const guidance = stagedToolSourceGuidance(report, presentation);
  return <div className="notice notice-info" role="status">
    <div><strong>{guidance.title}</strong><p>{guidance.body}</p>
      {guidance.pickers.length > 0 && <div className="button-row">{guidance.pickers.map((picker) =>
        <button type="button" className="button secondary" key={picker.role} disabled={busy}
          onClick={() => void chooseSource(picker.role)}>{picker.label}</button>)}</div>}
      {guidance.steps.length > 0 && <details><summary>Finish tool setup safely</summary><ol>{guidance.steps.map((step) => <li key={step}>{step}</li>)}</ol></details>}
    </div>
  </div>;
}
