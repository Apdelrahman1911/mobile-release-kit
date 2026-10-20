import type { LocalStoreProject } from './localStorePreflight.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';

// Public DATA only. Actual source/account/Store/candidate/namespace originals
// are selected by native code; these strings cannot construct a handoff.
export type VersionIncrement = 'build' | 'patch' | 'minor' | 'major';
export interface VersionReserveOptions { readonly reference: string; readonly increment: VersionIncrement;
  readonly newCandidate: boolean; readonly acknowledgeLimitations: boolean }
export interface ReservedVersion { readonly id: string; readonly candidateId: string; readonly name: string; readonly build: number }
export interface VersionReserveStatus {
  readonly schemaVersion: 1; readonly revision: number; readonly projectId: string | null; readonly operationId: string | null;
  readonly phase: 'idle' | 'reading' | 'reviewed' | 'reserving' | 'reserved' | 'refused' | 'cleanup-unknown';
  readonly reason: 'none' | 'source-refused' | 'review-unavailable' | 'review-expired' | 'state-unavailable' | 'reservation-refused' | 'cleanup-unknown';
  readonly review: ({ readonly id: string } & Omit<VersionReserveOptions, 'acknowledgeLimitations'>) | null;
  readonly reservation: ReservedVersion | null;
}
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === keys.length && keys.every((k) => Object.hasOwn(v, k));
export const reserveProject = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v) && !/\s/.test(v);
export const reserveId = (v: unknown): v is string => typeof v === 'string' && v.length === 32 && /^[0-9a-f]+$/.test(v) && v !== '0'.repeat(32);
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const increment = (v: unknown): v is VersionIncrement => ['build', 'patch', 'minor', 'major'].includes(v as string);
export function reserveBranch(v: unknown): v is string {
  if (typeof v !== 'string' || !v.startsWith('refs/heads/')) return false;
  const n = v.slice(11), parts = n.split('/');
  return n.length > 0 && n.length <= 200 && /^[A-Za-z0-9]/.test(n) && !/[^A-Za-z0-9._/-]/.test(n) &&
    !n.includes('..') && !n.startsWith('refs/') && parts.length <= 16 &&
    parts.every((p) => !!p && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
export function parseReserveOptions(raw: unknown): VersionReserveOptions | null {
  try {
    const v = copyBoundedComparisonData(raw, 1024, 16);
    return exact(v, ['reference', 'increment', 'newCandidate', 'acknowledgeLimitations']) && reserveBranch(v.reference) &&
      increment(v.increment) && typeof v.newCandidate === 'boolean' && v.acknowledgeLimitations === true ?
      Object.freeze({ reference: v.reference, increment: v.increment, newCandidate: v.newCandidate, acknowledgeLimitations: true }) : null;
  } catch { return null; }
}
export function parseReservedVersion(raw: unknown): ReservedVersion | null {
  try {
    const v = copyBoundedComparisonData(raw, 1024, 16);
    return exact(v, ['id', 'candidateId', 'name', 'build']) && reserveId(v.id) && typeof v.candidateId === 'string' &&
      v.candidateId.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v.candidateId) &&
      typeof v.name === 'string' && v.name.length <= 64 && !/[^0-9.]/.test(v.name) && /^[0-9]+\.[0-9]+\.[0-9]+$/.test(v.name) &&
      integer(v.build, 2_100_000_000) && v.build > 0 ? Object.freeze({ id: v.id, candidateId: v.candidateId, name: v.name, build: v.build }) : null;
  } catch { return null; }
}
export const reserveActive = (s: VersionReserveStatus | null): boolean => !!s && ['reading', 'reserving', 'cleanup-unknown'].includes(s.phase);
export function parseVersionReserveStatus(raw: unknown): VersionReserveStatus | null {
  try {
    const v = copyBoundedComparisonData(raw, 8192, 128);
    if (!exact(v, ['schemaVersion', 'revision', 'projectId', 'operationId', 'phase', 'reason', 'review', 'reservation']) || v.schemaVersion !== 1 ||
        !integer(v.revision, 0xffff_ffff) || !(v.projectId === null || reserveProject(v.projectId)) || !(v.operationId === null || reserveId(v.operationId)) ||
        (v.projectId === null) !== (v.operationId === null) || !['idle', 'reading', 'reviewed', 'reserving', 'reserved', 'refused', 'cleanup-unknown'].includes(v.phase as string) ||
        !['none', 'source-refused', 'review-unavailable', 'review-expired', 'state-unavailable', 'reservation-refused', 'cleanup-unknown'].includes(v.reason as string)) return null;
    const phase = v.phase as VersionReserveStatus['phase'], reason = v.reason as VersionReserveStatus['reason'];
    if (v.revision === 0xffff_ffff && phase !== 'cleanup-unknown' || phase !== 'idle' && v.revision === 0 ||
        (phase === 'idle' ? v.projectId !== null : ['reading', 'reviewed', 'reserving', 'reserved'].includes(phase) && v.projectId === null) ||
        (phase === 'refused' ? reason === 'none' || reason === 'cleanup-unknown' : phase === 'cleanup-unknown' ? reason !== 'cleanup-unknown' : reason !== 'none')) return null;
    let review: VersionReserveStatus['review'] = null;
    if (phase === 'reviewed') {
      const r = v.review;
      if (!exact(r, ['id', 'reference', 'increment', 'newCandidate']) || !reserveId(r.id) || r.id !== v.operationId ||
          !reserveBranch(r.reference) || !increment(r.increment) || typeof r.newCandidate !== 'boolean') return null;
      review = Object.freeze({ id: r.id, reference: r.reference, increment: r.increment, newCandidate: r.newCandidate });
    } else if (v.review !== null) return null;
    const reservation = phase === 'reserved' ? parseReservedVersion(v.reservation) : null;
    if (phase === 'reserved' ? !reservation || reservation.id !== v.operationId : v.reservation !== null) return null;
    return Object.freeze({ schemaVersion: 1, revision: v.revision, projectId: v.projectId, operationId: v.operationId, phase, reason, review, reservation });
  } catch { return null; }
}
export interface VersionReservePort {
  status(): Promise<unknown>;
  review(projectId: string, options: VersionReserveOptions): Promise<unknown>;
  reserve(projectId: string, reviewId: string): Promise<unknown>;
  cancel(operationId: string): Promise<unknown>;
}
export function createVersionReservePort(invoke: (name: string, bytes: Uint8Array) => Promise<unknown>): VersionReservePort {
  const send = (name: string, v: object) => invoke(name, new TextEncoder().encode(JSON.stringify(v)));
  const invalid = () => Promise.reject({ code: 'version_reserve_invalid_request' });
  return Object.freeze({
    status: () => send('version_reserve_status', {}),
    review: (projectId: string, raw: VersionReserveOptions) => {
      const options = parseReserveOptions(raw);
      return reserveProject(projectId) && options ? send('version_reserve_review', { projectId, ...options }) : invalid();
    },
    reserve: (projectId: string, reviewId: string) => reserveProject(projectId) && reserveId(reviewId) ? send('version_reserve_start', { projectId, reviewId }) : invalid(),
    cancel: (operationId: string) => reserveId(operationId) ? send('version_reserve_cancel', { operationId }) : invalid(),
  });
}
// UI refusal/help only; native still proves the same saved source and original Store receipt.
export function versionReserveProjectIssue(project: LocalStoreProject | null): string | null {
  if (!project) return 'Choose a saved native Android or iOS project.';
  if (project.inputIssue) return project.inputIssue;
  if (project.dirtyDraft || project.snapshotPending || project.versionPending || project.saveRecoveryRequired) return 'Finish the saved-input review before reserving a version.';
  const platforms = project.versionPlatforms;
  if (platforms?.length === 2 && platforms[0] === 'android' && platforms[1] === 'ios') return 'Shared Android+iOS version sources need paired current Store observations and are not supported here yet. Keep manual versioning.';
  return platforms?.length === 1 && (platforms[0] === 'android' || platforms[0] === 'ios') ? null :
    'Read the current saved configuration and version for exactly one enabled platform.';
}
export function versionReserveHelp(reason: VersionReserveStatus['reason'] | null): string {
  switch (reason) {
    case 'cleanup-unknown': return 'The original operation or cleanup is unconfirmed. Keep this app and its state. Check the original status; do not repeat the reservation or delete its journal.';
    case 'state-unavailable': return 'Saved counter state is unavailable. Earlier reservations were kept, not reset. Use manual versions only after the original operation settles.';
    case 'source-refused': case 'review-unavailable': case 'review-expired': return 'The saved project, current Store inventory, account or review changed or expired. Wait for the original operation to settle, then review again. Its candidate is never silently replaced.';
    case 'reservation-refused': return 'No usable reservation was returned. An already reserved number stays attached to its candidate; retry does not request a new number.';
    default: return 'Reserve writes only the shared counter and local candidate state. Opening the version editor, reviewing the file and applying it are separate actions.';
  }
}
