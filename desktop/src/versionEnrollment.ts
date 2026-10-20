import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';

// Redacted DATA from the original native Document. No ledger bytes, hashes,
// paths, account credentials, version reservation or Store readiness here.
export const VERSION_ENROLLMENT_REASONS = ['none', 'counter-missing', 'protection-unavailable', 'protection-unsupported',
  'authority-changed', 'authority-rewound', 'ledger-invalid', 'review-changed', 'invalid-input', 'unauthorized', 'forbidden',
  'not-found-or-inaccessible', 'target-changed', 'rate-limited', 'network-unavailable', 'tls-failed', 'response-invalid',
  'response-limit', 'expired', 'cancelled', 'busy', 'not-connected', 'runtime-unavailable', 'cleanup-unknown',
  'state-unavailable', 'state-too-large', 'connected'] as const;
export type VersionEnrollmentReason = typeof VERSION_ENROLLMENT_REASONS[number];
export type VersionEnrollmentPhase = 'idle' | 'reading' | 'connecting' | 'reviewed' | 'connected' | 'refused' | 'stopping' | 'cleanup-unknown';
export interface VersionEnrollmentReview {
  readonly id: string;
  readonly repository: string;
  readonly version: { readonly name: string; readonly build: number };
  readonly reservations: number;
}
export interface VersionEnrollmentStatus {
  readonly schemaVersion: 1;
  readonly revision: number;
  readonly projectId: string | null;
  readonly operationId: string | null;
  readonly phase: VersionEnrollmentPhase;
  readonly reason: VersionEnrollmentReason;
  readonly review: VersionEnrollmentReview | null;
}
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const exact = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) &&
  Object.keys(v).length === names.length && names.every((name) => Object.hasOwn(v, name));
export const enrollmentProjectId = (v: unknown): v is string => typeof v === 'string' && v.length >= 1 && v.length <= 64 && !/[^A-Za-z0-9_-]/.test(v);
const id = (v: unknown): v is string => typeof v === 'string' && v.length === 32 && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
const coordinate = (v: string): boolean => {
  const parts = v.split('/');
  return parts.length === 2 && parts.every((p, i) => p.length >= 1 && p.length <= (i === 0 ? 39 : 100) &&
    /^[A-Za-z0-9]/.test(p) && /[A-Za-z0-9]$/.test(p) && !(i === 0 ? /[^A-Za-z0-9-]/ : /[^A-Za-z0-9._-]/).test(p));
};
const count = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
export const enrollmentActive = (v: VersionEnrollmentStatus | null): boolean => v !== null && ['reading', 'connecting', 'stopping', 'cleanup-unknown'].includes(v.phase);
export function parseVersionEnrollmentStatus(input: unknown): VersionEnrollmentStatus | null {
  try {
    const v = copyBoundedComparisonData(input, 8192, 128);
    if (!exact(v, ['schemaVersion', 'revision', 'projectId', 'operationId', 'phase', 'reason', 'review']) || v.schemaVersion !== 1 ||
        !count(v.revision, 0xffff_ffff) || v.revision === 0 || typeof v.phase !== 'string' ||
        !['idle', 'reading', 'connecting', 'reviewed', 'connected', 'refused', 'stopping', 'cleanup-unknown'].includes(v.phase) ||
        typeof v.reason !== 'string' || !(VERSION_ENROLLMENT_REASONS as readonly string[]).includes(v.reason) ||
        !(v.projectId === null || enrollmentProjectId(v.projectId)) || !(v.operationId === null || id(v.operationId)) ||
        (v.projectId === null) !== (v.operationId === null)) return null;
    const reason = v.reason as VersionEnrollmentReason, phase = v.phase as VersionEnrollmentPhase;
    if (v.revision === 0xffff_ffff && phase !== 'cleanup-unknown') return null;
    if (phase === 'idle' ? reason !== 'none' || v.projectId !== null :
        phase === 'connected' ? reason !== 'connected' : phase === 'stopping' ? reason !== 'cancelled' :
        phase === 'cleanup-unknown' ? reason !== 'cleanup-unknown' : phase === 'refused' ?
        ['none', 'connected', 'cleanup-unknown'].includes(reason) : reason !== 'none') return null;
    if (['reading', 'connecting', 'reviewed', 'connected', 'stopping'].includes(phase) && v.projectId === null) return null;
    let review: VersionEnrollmentReview | null = null;
    if (phase === 'reviewed') {
      const r = v.review;
      if (!exact(r, ['id', 'repository', 'version', 'reservations']) || !id(r.id) || r.id !== v.operationId ||
          typeof r.repository !== 'string' || r.repository.length > 140 ||
          !coordinate(r.repository) ||
          !count(r.reservations, 64) || !exact(r.version, ['name', 'build']) || typeof r.version.name !== 'string' ||
          r.version.name.length < 1 || r.version.name.length > 64 || /[^A-Za-z0-9.+-]/.test(r.version.name) ||
          !count(r.version.build, 2_100_000_000) || r.version.build === 0) return null;
      review = Object.freeze({ id: r.id, repository: r.repository, reservations: r.reservations,
        version: Object.freeze({ name: r.version.name, build: r.version.build }) });
    } else if (v.review !== null) return null;
    return Object.freeze({ schemaVersion: 1, revision: v.revision, projectId: v.projectId, operationId: v.operationId,
      phase, reason, review });
  } catch { return null; } // No getters, toJSON, raw error or partial success.
}

export interface VersionEnrollmentPort {
  status(): Promise<unknown>;
  review(projectId: string): Promise<unknown>;
  confirm(projectId: string, reviewId: string): Promise<unknown>;
  cancel(operationId: string): Promise<unknown>;
}
type Invoke = (command: string, args: Uint8Array) => Promise<unknown>;
export function createVersionEnrollmentPort(invoke: Invoke): VersionEnrollmentPort {
  const send = (command: string, value: object) => invoke(command, new TextEncoder().encode(JSON.stringify(value)));
  const invalid = () => Promise.reject({ code: 'version_enrollment_invalid_request' });
  return Object.freeze({
    status: () => send('version_enrollment_status', {}),
    review: (projectId: string) => enrollmentProjectId(projectId) ? send('version_enrollment_review', { projectId }) : invalid(),
    confirm: (projectId: string, reviewId: string) => enrollmentProjectId(projectId) && id(reviewId) ?
      send('version_enrollment_confirm', { projectId, reviewId }) : invalid(),
    cancel: (operationId: string) => id(operationId) ? send('version_enrollment_cancel', { operationId }) : invalid(),
  });
}

export function versionEnrollmentHelp(reason: VersionEnrollmentReason | null): string {
  switch (reason) {
    case 'connected': return 'This computer saved the reviewed counter connection. No version was reserved or changed; Store readiness was not checked.';
    case 'counter-missing': return 'This repository has no supported shared version counter. Keep using manual versions; this action does not create a counter.';
    case 'protection-unavailable': case 'protection-unsupported': return 'The counter branch needs readable protection against deletion and force pushes. Ask the repository administrator; keep using manual versions.';
    case 'state-too-large': return "Saved counter state exceeds this connection path's size or complexity limit (256 KiB / 4,096 nodes). All records were kept. Use manual versions; do not delete or reset state.";
    case 'state-unavailable': return 'The original private state is unavailable. Existing connections and reservations were not reset. Keep using manual versions.';
    case 'authority-rewound': case 'authority-changed': case 'ledger-invalid': return 'The counter could not be verified against its retained history. Do not reset it or reuse its numbers; keep using manual versions.';
    case 'cleanup-unknown': return 'The original operation has not confirmed cleanup. Keep this app and its retained state; do not retry or reconnect to bypass it.';
    case 'review-changed': case 'target-changed': case 'expired': return 'The saved project, account or reviewed counter changed or expired. Wait for the original operation to finish, then review again.';
    case 'not-connected': case 'unauthorized': return 'Connect the intended GitHub account and repository first. No account is selected automatically.';
    case 'rate-limited': return 'GitHub asked this connection to wait. No automatic retry was started.';
    case 'cancelled': return 'The original operation stopped. Existing saved state was kept; this does not undo a connection already written.';
    case 'none': case null: return 'Manual versions remain unchanged. Reviewing reads the selected repository; connecting saves only this computer’s counter mapping.';
    default: return 'The shared counter could not be connected. Existing state was kept; manual version editing is unchanged.';
  }
}
