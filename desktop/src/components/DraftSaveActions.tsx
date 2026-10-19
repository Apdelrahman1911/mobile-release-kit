import { useId } from 'react';
import { saveHelp } from '../configEdit.ts';
import { beginDraftSaveFromClick, draftSaveActions, revealConfigurationSaveReview } from '../draftSaveActions.ts';
import type { Tone } from '../certainty.ts';
import type { ProjectSession } from '../drafts.ts';
import type { HelpContent } from '../types.ts';
import { Badge, HelpButton } from './Common.tsx';
import { Icon } from './Icon.tsx';
import { reviewHelp } from './DraftReview.tsx';
import { ProgressiveDisclosure } from './ProgressiveDisclosure.tsx';

const validationHelp: HelpContent = {
  label: 'Validate draft', requiredness: 'optional',
  requiredWhen: 'Available when a draft and a compatible native core are loaded.',
  what: 'Check an in-memory draft against the bundled core’s configuration policy.',
  why: 'Find format and policy errors before a separate native save review, when that capability is available.',
  where: 'Open Check without saving and choose Validate only after editing project settings or metadata fields.',
  format: 'The current structured draft is sent to the read-only core. Nothing is saved.',
  failure: 'An error leaves your draft intact. Format-valid does not verify files, commands, identities, credentials, tools, Git, or Store readiness.',
};

export function DraftSaveActions({ session, status, saveReason, discardReason, validateReason, reviewReason,
  onPrepareSave, onDiscard, onValidate, onReview, onHelp }: {
  session: ProjectSession; status: { tone: Tone; label: string };
  saveReason: string | null; discardReason: string | null; validateReason: string | null; reviewReason: string | null;
  onPrepareSave: () => void; onDiscard: () => void; onValidate: () => void; onReview: () => void; onHelp: (help: HelpContent) => void;
}) {
  const id = useId();
  const actions = draftSaveActions(session, { save: saveReason, discard: discardReason, validate: validateReason, review: reviewReason });
  return <>
    <div className="draft-toolbar"><div className="draft-toolbar-status"><Badge tone={status.tone}>{status.label}</Badge><span>Changes stay in this draft</span></div>
      <div className="button-row">
        <button type="button" className="text-button" disabled={actions.discardDisabled} title={discardReason ?? undefined} onClick={onDiscard}>
          {session.sourceChanged ? 'Discard draft & reload…' : 'Discard draft changes'}</button>
        <button type="button" className="button primary" disabled={actions.saveDisabled} aria-describedby={`${id}-save-reason`}
          onClick={() => beginDraftSaveFromClick(saveReason, onPrepareSave, () => { revealConfigurationSaveReview((target) => document.getElementById(target)); })}>
          Review &amp; save…<Icon name={actions.saveDisabled ? 'lock' : 'search'} size={14} /></button>
        <HelpButton content={saveHelp} onHelp={onHelp} />
      </div>
      <p id={`${id}-save-reason`} className="toolbar-reason">{saveReason ?? 'Opens the project’s save review above. Nothing is written until you confirm in that review.'}</p>
      {discardReason && <p className="toolbar-reason">Before discarding: {discardReason}</p>}
    </div>
    <ProgressiveDisclosure title="Check without saving" needsAttention={actions.checksForcedOpen}
      description="Optional: inspect draft changes or check its format without opening a save review. These checks never save files or test a build.">
      <div className="button-row">
        <button type="button" className="button secondary" disabled={actions.validateDisabled} aria-describedby={`${id}-validation-reason`} onClick={onValidate}>
          <Icon name={session.validationRequest ? 'refresh' : 'check'} size={17} className={session.validationRequest ? 'spin' : ''} />
          {session.validationRequest ? 'Validating…' : 'Validate only'}</button><HelpButton content={validationHelp} onHelp={onHelp} />
        <button type="button" className="button secondary" disabled={actions.reviewDisabled} aria-describedby={`${id}-review-reason`} onClick={onReview}>
          <Icon name={session.reviewRequest ? 'refresh' : 'search'} size={17} className={session.reviewRequest ? 'spin' : ''} />
          {session.reviewRequest ? 'Reviewing…' : 'Review draft changes'}</button><HelpButton content={reviewHelp} onHelp={onHelp} />
      </div>
      <p id={`${id}-validation-reason`} className="toolbar-reason">Validation: {validateReason ?? 'Checks the draft’s format only. It does not save files or test a build.'}</p>
      <p id={`${id}-review-reason`} className="toolbar-reason">Draft review: {reviewReason ?? 'Shows changes and missing or conflicting settings. It does not save files.'}</p>
    </ProgressiveDisclosure>
  </>;
}
