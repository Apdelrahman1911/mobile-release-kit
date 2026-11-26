import type { ToolPreparationController, ToolPreparationState } from '../toolPreparationController.ts';
import { toolPreparationGuidance } from '../toolPreparationGuidance.ts';
import { SectionHeading } from './Common.tsx';

// The application retains the controller. This view owns no native lifecycle
// and cannot install, settle or approve a privileged operation.
export function ToolPreparationGuide({ state, controller }: { state: ToolPreparationState; controller: ToolPreparationController }) {
  const plan = state.plan, guidance = plan ? toolPreparationGuidance(plan) : null;
  return <section className="card" aria-label="Tool preparation guidance" aria-busy={state.pending}>
    <SectionHeading title="Use existing tools first" description="Check registered copies and local installations before preparing anything new." />
    {guidance && <><p><strong>{guidance.title}</strong></p><p>{guidance.body}</p></>}
    {state.stale && <p className="review-caution">Check the current project and tool status before continuing. Earlier guidance cannot authorize setup.</p>}
    {state.error && <p className="review-caution" role="alert">{state.error}</p>}
    <div className="button-row">
      <button type="button" className="button secondary" disabled={state.pending} onClick={() => void controller.refresh()}>{state.pending ? 'Checking…' : 'Check tool preparation'}</button>
      {plan?.action === 'choose-registered-copy' ? plan.reusable.map((copy, index) =>
        <button key={copy.instance} type="button" className="button primary" disabled={state.pending || state.stale} onClick={() => void controller.continue(copy)}>Choose existing copy {index + 1}</button>)
        : guidance?.nextLabel && <button type="button" className="button primary" disabled={state.pending || state.stale} onClick={() => void controller.continue()}>{guidance.nextLabel}</button>}
    </div>
    {guidance && <details><summary>Manual setup and safe recovery</summary><ol>{guidance.steps.map((step) => <li key={step}>{step}</li>)}</ol></details>}
    <p className="save-note">No download, installation, license acceptance or build authorization is performed by this plan.</p>
  </section>;
}
