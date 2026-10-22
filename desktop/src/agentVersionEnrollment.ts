import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { VERSION_ENROLLMENT_REASONS, enrollmentProjectId } from './versionEnrollment.ts';
import type { VersionEnrollmentReason, VersionEnrollmentReview, VersionEnrollmentStatus } from './versionEnrollment.ts';
import type { GithubActionQuery, GithubActionStatus } from './agentGithubActionAccess.ts';
import type { VersionEnrollmentContext } from './versionEnrollmentController.ts';

// Comparison DATA and a retained delegation record for the EXISTING enrollment
// controller. Nothing here creates a native review, authority or state writer.
export const ENROLLMENT_ACTION_KINDS = ['counter-enrollment-review', 'counter-enrollment-connect'] as const;
export type EnrollmentActionKind = typeof ENROLLMENT_ACTION_KINDS[number];
interface SelectionBase {
  readonly sessionId: string;
  readonly expectedRevision: number;
  readonly expectedConnectionRevision: number;
}
export type EnrollmentActionSelection =
  | (SelectionBase & { readonly kind: 'counter-enrollment-review' })
  | (SelectionBase & { readonly kind: 'counter-enrollment-connect'; readonly reviewId: string });
export type EnrollmentActionReference =
  | (Extract<EnrollmentActionSelection, { kind: 'counter-enrollment-review' }> & { readonly requestSha256: string })
  | (Extract<EnrollmentActionSelection, { kind: 'counter-enrollment-connect' }> & { readonly reviewSha256: string });
export interface EnrollmentActionResult {
  readonly type: 'enrollment';
  readonly operation: 'review' | 'connect';
  readonly phase: 'reviewed' | 'connected' | 'refused';
  readonly reason: VersionEnrollmentReason;
  readonly review: VersionEnrollmentReview | null;
}
export interface AgentVersionEnrollmentPort {
  review(origin: GithubActionQuery, projectId: string): Promise<unknown>;
  confirm(origin: GithubActionQuery, projectId: string, reviewId: string): Promise<unknown>;
}
export interface EnrollmentDelegateRecord {
  readonly context: VersionEnrollmentContext;
  readonly epoch: object;
  readonly selection: EnrollmentActionSelection;
  readonly status: VersionEnrollmentStatus;
  readonly reviewEpoch: object | null;
  readonly port: AgentVersionEnrollmentPort;
  allowReturned: boolean;
  started: boolean;
  sent: boolean;
  returned: boolean;
  original: Promise<boolean> | null;
  reference: EnrollmentActionReference | null;
  query: GithubActionQuery | null;
  grantId: string | null;
  native: VersionEnrollmentStatus | null;
  terminal: GithubActionStatus | null;
  unused: boolean;
  noAllow: boolean;
  unknown: boolean;
  released: boolean;
}

const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) &&
  Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && !/[^a-f0-9]/.test(v);
export const enrollmentActionId = (v: unknown): v is string => hex(v, 32) && v !== '0'.repeat(32);
const count = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min && v <= max;
const session = (v: unknown): v is string => typeof v === 'string' && v.length >= 1 && v.length <= 64 && !/[^A-Za-z0-9_-]/.test(v);
export const isEnrollmentActionKind = (v: unknown): v is EnrollmentActionKind => v === 'counter-enrollment-review' || v === 'counter-enrollment-connect';
function selected(v: unknown, reference: boolean): boolean {
  if (!record(v) || !isEnrollmentActionKind(v.kind)) return false;
  const connect = v.kind === 'counter-enrollment-connect';
  return keys(v, ['kind', 'sessionId', 'expectedRevision', 'expectedConnectionRevision', ...(connect ? ['reviewId'] : []),
    ...(reference ? [connect ? 'reviewSha256' : 'requestSha256'] : [])]) && session(v.sessionId) &&
    count(v.expectedRevision, 1, 0xffff_fffe) && count(v.expectedConnectionRevision, 1, 0xffff_fffe) &&
    (!connect || enrollmentActionId(v.reviewId)) && (!reference || hex(v[connect ? 'reviewSha256' : 'requestSha256'], 64));
}
export function parseEnrollmentActionSelection(raw: unknown): EnrollmentActionSelection | null {
  try { const v = copyBoundedComparisonData(raw, 1024, 16); return selected(v, false) ? Object.freeze(v) as unknown as EnrollmentActionSelection : null; } catch { return null; }
}
export function parseEnrollmentActionReference(raw: unknown): EnrollmentActionReference | null {
  try { const v = copyBoundedComparisonData(raw, 1024, 18); return selected(v, true) ? Object.freeze(v) as unknown as EnrollmentActionReference : null; } catch { return null; }
}
export function sameEnrollmentActionSelection(a: EnrollmentActionSelection | EnrollmentActionReference, b: EnrollmentActionSelection | EnrollmentActionReference): boolean {
  return a.kind === b.kind && a.sessionId === b.sessionId && a.expectedRevision === b.expectedRevision &&
    a.expectedConnectionRevision === b.expectedConnectionRevision &&
    (a.kind === 'counter-enrollment-review' || b.kind === 'counter-enrollment-connect' && a.reviewId === b.reviewId);
}
export function sameEnrollmentActionReference(a: EnrollmentActionReference, b: EnrollmentActionReference): boolean {
  return sameEnrollmentActionSelection(a, b) && (a.kind === 'counter-enrollment-review'
    ? b.kind === a.kind && a.requestSha256 === b.requestSha256 : b.kind === a.kind && a.reviewSha256 === b.reviewSha256);
}
function review(v: unknown, operationId: string): v is VersionEnrollmentReview {
  if (!keys(v, ['id', 'repository', 'version', 'reservations']) || !enrollmentActionId(v.id) || v.id !== operationId ||
      typeof v.repository !== 'string' || v.repository.length > 140 || !count(v.reservations, 0, 64) ||
      !keys(v.version, ['name', 'build']) || typeof v.version.name !== 'string' || v.version.name.length < 1 ||
      v.version.name.length > 64 || /[^A-Za-z0-9.+-]/.test(v.version.name) || !count(v.version.build, 1, 2_100_000_000)) return false;
  const parts = v.repository.split('/');
  return parts.length === 2 && parts.every((p, i) => p.length >= 1 && p.length <= (i === 0 ? 39 : 100) &&
    /^[A-Za-z0-9]/.test(p) && /[A-Za-z0-9]$/.test(p) && !(i === 0 ? /[^A-Za-z0-9-]/ : /[^A-Za-z0-9._-]/).test(p));
}
export function parseEnrollmentActionResult(raw: unknown, kind: EnrollmentActionKind, operationId: string | null): EnrollmentActionResult | null {
  try {
    const v = copyBoundedComparisonData(raw, 4096, 40), operation = kind === 'counter-enrollment-review' ? 'review' : 'connect';
    if (!enrollmentActionId(operationId) || !keys(v, ['type', 'operation', 'phase', 'reason', 'review']) || v.type !== 'enrollment' ||
        v.operation !== operation || typeof v.reason !== 'string' || !(VERSION_ENROLLMENT_REASONS as readonly string[]).includes(v.reason)) return null;
    if (v.phase === 'reviewed') {
      if (operation !== 'review' || v.reason !== 'none' || !review(v.review, operationId)) return null;
      Object.freeze(v.review.version); Object.freeze(v.review);
    } else if (v.phase === 'connected') {
      if (operation !== 'connect' || v.reason !== 'connected' || v.review !== null) return null;
    } else if (v.phase !== 'refused' || ['none', 'connected', 'cleanup-unknown'].includes(v.reason) || v.review !== null) return null;
    return Object.freeze(v) as unknown as EnrollmentActionResult;
  } catch { return null; }
}
export function enrollmentResultMatchesNative(result: EnrollmentActionResult, native: VersionEnrollmentStatus): boolean {
  return result.phase === native.phase && result.reason === native.reason && (result.review === null ? native.review === null :
    !!native.review && result.review.id === native.review.id && result.review.repository === native.review.repository &&
    result.review.version.name === native.review.version.name && result.review.version.build === native.review.version.build &&
    result.review.reservations === native.review.reservations);
}
export function createAgentVersionEnrollmentPort(invoke: (name: string, body: Uint8Array) => Promise<unknown>): AgentVersionEnrollmentPort {
  const send = (name: string, raw: GithubActionQuery, projectId: string, reviewId?: string) => {
    const q = copyBoundedComparisonData(raw, 512, 8);
    if (!keys(q, ['projectId', 'serviceInstance', 'requestId']) || !Object.values(q).every(enrollmentActionId) ||
        !enrollmentProjectId(projectId) || reviewId !== undefined && !enrollmentActionId(reviewId)) throw new Error('Invalid enrollment delegation address');
    const bytes = new TextEncoder().encode(JSON.stringify({ origin: q, input: { projectId, ...(reviewId === undefined ? {} : { reviewId }) } }));
    if (bytes.length > 1024) throw new Error('Enrollment delegation input exceeds its fixed bound');
    return invoke(name, bytes);
  };
  return Object.freeze({ review: (q: GithubActionQuery, p: string) => send('agent_version_enrollment_review', q, p),
    confirm: (q: GithubActionQuery, p: string, r: string) => send('agent_version_enrollment_confirm', q, p, r) });
}
