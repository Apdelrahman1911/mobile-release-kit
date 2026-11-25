// Two closed siblings of the existing GitHub permission pool. These are
// comparison DATA only: never a renderer-created Consent or Pending-load.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys } from './githubConnectionProtocol.ts';

export const GITHUB_PUBLICATION_ACTIONS = ['setup-publish', 'setup-reconcile'] as const;
export type GithubPublicationAction = typeof GITHUB_PUBLICATION_ACTIONS[number];
interface Original { readonly sessionId: string; readonly expectedRevision: number }
export interface GithubSetupPublishSelection extends Original { readonly kind: 'setup-publish'; readonly consentId: string }
export interface GithubSetupReconcileSelection extends Original { readonly kind: 'setup-reconcile'; readonly marker: string }
export type GithubPublicationSelection = GithubSetupPublishSelection | GithubSetupReconcileSelection;
export type GithubPublicationReference = (GithubSetupPublishSelection & { readonly preparedSha256: string }) |
  (GithubSetupReconcileSelection & { readonly recordSha256: string });

const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && !/[^a-f0-9]/.test(v);
const original = (v: Record<string, unknown>): boolean =>
  typeof v.sessionId === 'string' && v.sessionId.length >= 1 && v.sessionId.length <= 64 && !/[^A-Za-z0-9_-]/.test(v.sessionId) &&
  typeof v.expectedRevision === 'number' && Number.isSafeInteger(v.expectedRevision) && v.expectedRevision >= 1 && v.expectedRevision <= 0xffff_fffe;
function parse(raw: unknown, reference: boolean): GithubPublicationSelection | GithubPublicationReference | null {
  try {
    const v = copyBoundedComparisonData(raw, 512, 16);
    if (keys(v, ['kind', 'sessionId', 'expectedRevision', 'consentId', ...(reference ? ['preparedSha256'] : [])]) &&
        v.kind === 'setup-publish' && original(v) && hex(v.consentId, 32) && (!reference || hex(v.preparedSha256, 64))) {
      return Object.freeze(v) as unknown as GithubPublicationSelection | GithubPublicationReference;
    }
    if (keys(v, ['kind', 'sessionId', 'expectedRevision', 'marker', ...(reference ? ['recordSha256'] : [])]) &&
        v.kind === 'setup-reconcile' && original(v) && hex(v.marker, 32) && (!reference || hex(v.recordSha256, 64))) {
      return Object.freeze(v) as unknown as GithubPublicationSelection | GithubPublicationReference;
    }
  } catch { /* No property getter, private field or unbounded copy is accepted. */ }
  return null;
}
export const parseGithubPublicationSelection = (raw: unknown): GithubPublicationSelection | null => parse(raw, false) as GithubPublicationSelection | null;
export const parseGithubPublicationReference = (raw: unknown): GithubPublicationReference | null => parse(raw, true) as GithubPublicationReference | null;
export function sameGithubPublicationSelection(a: GithubPublicationSelection | null, b: GithubPublicationSelection | null): boolean {
  return !!a && !!b && a.kind === b.kind && a.sessionId === b.sessionId && a.expectedRevision === b.expectedRevision &&
    (a.kind === 'setup-publish' && b.kind === 'setup-publish' ? a.consentId === b.consentId :
      a.kind === 'setup-reconcile' && b.kind === 'setup-reconcile' && a.marker === b.marker);
}
export function sameGithubPublicationReference(a: GithubPublicationReference | null, b: GithubPublicationReference | null): boolean {
  return sameGithubPublicationSelection(a, b) && !!a && !!b &&
    (a.kind === 'setup-publish' && b.kind === 'setup-publish' ? a.preparedSha256 === b.preparedSha256 :
      a.kind === 'setup-reconcile' && b.kind === 'setup-reconcile' && a.recordSha256 === b.recordSha256);
}
// Preserve the original publication's effect, including historical observations.
// A read GO is `none`, never PotentiallyApplied or CreatedObserved; neither
// branch/PR observation proves who sent the old request. Counter is not this grant.
export function githubPublicationEffect(kind: GithubPublicationAction, value: unknown): boolean {
  return typeof value === 'string' && (kind === 'setup-publish'
    ? ['not-sent', 'potentially-applied', 'draft-pr-observed'].includes(value)
    : kind === 'setup-reconcile' && ['none', 'unresolved', 'branch-observed', 'draft-pr-observed'].includes(value));
}
