// Closed comparison helpers; the existing controllers retain the actual calls.
import { parseToolAcquisitionContext } from './toolAcquisitionProtocol.ts';
import type { ToolAcquisitionContext, ToolAcquisitionIdentity } from './toolAcquisitionProtocol.ts';
import type { ToolSetupReview, ToolSetupStatus } from './agentToolSetup.ts';

export const SAVED_REQUIREMENTS_KIND = 'inspect-saved-requirements' as const;
export function savedRequirementsContext(raw: unknown, review: ToolSetupReview, project: string): ToolAcquisitionContext | null {
  const c = parseToolAcquisitionContext(raw);
  return c && review.kind === SAVED_REQUIREMENTS_KIND && review.platform === 'android' && review.prepared === null && review.sources === null &&
    c.projectId === project && c.draftRevision === review.draftRevision && c.baselineGeneration === review.baselineGeneration &&
    c.action === 'inspect' && c.review === null ? c : null;
}
export function savedRequirementsReview(raw: unknown): ToolSetupReview | null {
  const c = parseToolAcquisitionContext(raw);
  return c && c.action === 'inspect' && c.review === null ? Object.freeze({ kind: SAVED_REQUIREMENTS_KIND, platform: 'android',
    draftRevision: c.draftRevision, baselineGeneration: c.baselineGeneration, prepared: null, sources: null }) : null;
}
// This lives in the SAME ToolAcquisition Attempt; none of these fields is a
// native Prepare/Start promise or a replacement permission/custody owner.
export interface SavedRequirementsOrigin {
  readonly review: ToolSetupReview;
  allowJoined: boolean;
  allowConfirmed: boolean;
  candidate: ToolAcquisitionIdentity | null;
  service: ToolSetupStatus | null;
}
