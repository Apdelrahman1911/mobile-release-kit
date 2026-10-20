import type { SetupAction, SetupOverview } from '../setupOverview.ts';
import type { HelpContent } from '../types.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

export const setupWizardHelp: HelpContent = {
  label: 'Prepare your app, one step at a time', requiredness: 'optional',
  what: 'A guide to the existing project, version, tool and signing controls. Start by preparing a local build.',
  why: 'You can see what is known and what still needs attention without learning the internal release machinery.',
  where: 'Choose your app folder. Open the highlighted step, review its fields and use its existing file pickers and help.',
  format: 'No commands or secret values to enter here. Saved results determine the next suggestion; there is no “mark complete” shortcut.',
  requiredWhen: 'Use it when setting up a project or returning to unfinished work. GitHub and Store delivery are separate later tasks.',
  failure: 'A missing or old result stays unchecked. Draft edits are retained. An interrupted change must be checked or recovered before repeating it; a cancellation request does not mean it has stopped.',
};

export function SetupWizard({ overview, onAction, onHelp }: {
  overview: SetupOverview;
  onAction: (action: SetupAction) => void;
  onHelp: (help: HelpContent) => void;
}) {
  return <section className="card guided-steps" aria-label="Guided project setup">
    <SectionHeading title="Setup steps" description="Start locally, then add signing and Store setup when your chosen action needs them. Opening a step does not approve a change.">
      <HelpButton content={setupWizardHelp} onHelp={onHelp} />
    </SectionHeading>
    <ol>
      {overview.stages.map((stage, index) => {
        const current = stage.id === overview.currentStage && !overview.attentionActivity;
        const reasonId = `guided-step-${stage.id}-reason`;
        return <li key={stage.id} aria-current={current ? 'step' : undefined} className={current ? 'guided-current-step' : undefined}>
          <span className="guided-step-number" aria-hidden="true">{stage.state === 'observed' ? <Icon name="check" size={16} /> : index + 1}</span>
          <div>
            <button type="button" className="guided-step-link" disabled={stage.next.disabledReason !== null}
              aria-describedby={stage.next.disabledReason ? reasonId : undefined} onClick={() => onAction(stage.next.action)}>
              {stage.title}<Icon name="chevron" size={15} />
            </button>
            {(current || stage.id === 'signing') && <p>{stage.summary}</p>}
            {stage.next.disabledReason && <p id={reasonId} className="guided-blocker">{stage.next.disabledReason}</p>}
          </div>
          <Badge tone={stage.state === 'observed' ? 'info' : stage.state === 'needs-action' || stage.state === 'unavailable' ? 'warning' : 'neutral'}>{stage.statusLabel}</Badge>
        </li>;
      })}
    </ol>
  </section>;
}
