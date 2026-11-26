import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';

// Root places this unique landmark on the EXISTING ConfigSave section. It is
// navigation only, never a second native owner or an Apply target.
export const CONFIGURATION_SAVE_REVIEW_ID = 'configuration-save-review';
export interface DraftActionReasons {
  save: string | null;
  discard: string | null;
  validate: string | null;
  review: string | null;
}
export function draftSaveActions(session: ProjectSession, reasons: DraftActionReasons) {
  const checking = session.validationRequest !== null || session.reviewRequest !== null;
  return {
    saveDisabled: reasons.save !== null,
    discardDisabled: reasons.discard !== null || (!isDirty(session) && !session.sourceChanged && session.removedFields.length === 0),
    validateDisabled: reasons.validate !== null || checking,
    reviewDisabled: reasons.review !== null || checking,
    checksForcedOpen: checking || session.validationError !== null || session.reviewError !== null,
  };
}

// Only an explicit enabled click calls this. Root's original callback rechecks
// native admission. Do not await, schedule a later focus, invoke Apply, or turn
// a callback return value into a save-success/readiness claim.
export function beginDraftSaveFromClick(reason: string | null, prepare: () => void, reveal: () => void): void {
  if (reason !== null) return;
  prepare();
  reveal();
}
interface SaveLandmark {
  focus(options: { preventScroll: boolean }): void;
  scrollIntoView(options: { block: 'start' }): void;
}
export function revealConfigurationSaveReview(find: (id: string) => SaveLandmark | null): boolean {
  const target = find(CONFIGURATION_SAVE_REVIEW_ID);
  if (!target) return false; // No fallback selector, new dialog, or invented outcome.
  target.focus({ preventScroll: true });
  target.scrollIntoView({ block: 'start' });
  return true; // Landmark found, NOT a native operation result.
}
