import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { reserveId, reserveProject } from './versionReserve.ts';

// Permission/comparison DATA only. These identifiers are not source, Store,
// candidate, native finality or permission to apply a version-file edit.
export interface AgentVersionReserveAccess {
  readonly allowRevision: string; // MAIN-issued comparison, never a CLI grant.
  readonly serviceInstance: string | null;
  readonly projectId: string | null; // Native service ID, NOT the runtime project ID.
  readonly grantId: string | null;
  readonly reviewId: string | null;
  readonly reviewRevision: number | null;
  readonly enabled: boolean;
  readonly remainingMs: number;
  readonly consumed: boolean;
  readonly requestId: string | null;
  readonly completedOperationId: string | null;
}
export interface AgentVersionReserveAccessPort {
  status(): Promise<unknown>;
  allow(projectId: string, reviewId: string, expectedReserveRevision: number, expectedAllowRevision: string): Promise<unknown>;
  revoke(): Promise<unknown>;
}
export const AGENT_VERSION_RESERVE_CONSENT = 'agent-version-reserve-once-v1';
export const AGENT_VERSION_RESERVE_MAX_MS = 120_000;
export const AGENT_VERSION_RESERVE_SCOPE = 'Let a local CLI or AI tool reserve this one reviewed candidate. It cannot choose different source or Store inputs, edit your version file, build or publish a release.';

const fields = ['allowRevision', 'serviceInstance', 'projectId', 'grantId', 'reviewId', 'reviewRevision', 'enabled', 'remainingMs', 'consumed', 'requestId', 'completedOperationId'] as const;
export const validAllowRevision = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{16}$(?![\s\S])/.test(v) && v !== 'ffffffffffffffff';
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
export const reserveReviewRevision = (v: unknown): v is number => integer(v, 0xffff_fffe) && v > 0;

export function parseAgentVersionReserveAccess(raw: unknown): AgentVersionReserveAccess | null {
  try {
    const v = copyBoundedComparisonData(raw, 2048, 32);
    if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== fields.length || !fields.every((k) => Object.hasOwn(v, k))) return null;
    const d = v as Record<string, unknown>;
    if (!validAllowRevision(d.allowRevision) || typeof d.enabled !== 'boolean' || typeof d.consumed !== 'boolean' || !integer(d.remainingMs, AGENT_VERSION_RESERVE_MAX_MS) ||
        !(d.requestId === null || reserveId(d.requestId)) || !(d.completedOperationId === null || reserveId(d.completedOperationId)) ||
        d.consumed !== (d.requestId !== null) || d.enabled && (d.consumed || d.remainingMs === 0) || !d.enabled && d.remainingMs !== 0 ||
        d.completedOperationId !== null && !d.consumed) return null;
    if (d.grantId === null) {
      if (d.serviceInstance !== null || d.projectId !== null || d.reviewId !== null || d.reviewRevision !== null ||
          d.enabled || d.remainingMs !== 0 || d.consumed || d.requestId !== null || d.completedOperationId !== null) return null;
      return Object.freeze({ allowRevision: d.allowRevision, serviceInstance: null, projectId: null, grantId: null, reviewId: null, reviewRevision: null,
        enabled: false, remainingMs: 0, consumed: false, requestId: null, completedOperationId: null });
    }
    if (!reserveId(d.serviceInstance) || !reserveId(d.projectId) || !reserveId(d.grantId) || !reserveId(d.reviewId) || !reserveReviewRevision(d.reviewRevision)) return null;
    // Native reports a rounded-zero remainder as disabled. The UI never starts
    // a new deadline or renews that original review from this observation.
    return Object.freeze({ allowRevision: d.allowRevision, serviceInstance: d.serviceInstance, projectId: d.projectId, grantId: d.grantId, reviewId: d.reviewId,
      reviewRevision: d.reviewRevision, enabled: d.enabled, remainingMs: d.remainingMs, consumed: d.consumed,
      requestId: d.requestId, completedOperationId: d.completedOperationId });
  } catch { return null; } // No getters, toJSON, raw errors or secret projection.
}

export function createAgentVersionReserveAccessPort(invoke: (command: string, body: Uint8Array) => Promise<unknown>): AgentVersionReserveAccessPort {
  const invalid = () => Promise.reject({ code: 'cli_access_invalid_request' });
  const send = (command: string, body: object) => {
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    return bytes.length + 96 <= 1024 ? invoke(command, bytes) : invalid();
  };
  return Object.freeze({
    status: () => send('agent_version_reserve_access', {}),
    allow: (projectId: string, reviewId: string, expectedReserveRevision: number, expectedAllowRevision: string) => reserveProject(projectId) && reserveId(reviewId) && reserveReviewRevision(expectedReserveRevision) && validAllowRevision(expectedAllowRevision) ?
      send('allow_agent_version_reserve', { projectId, reviewId, expectedReserveRevision, expectedAllowRevision, consentVersion: AGENT_VERSION_RESERVE_CONSENT }) : invalid(),
    revoke: () => send('revoke_agent_version_reserve', {}),
  });
}

// Literal commands for this closed permission only; never executed by the UI.
export function agentVersionReserveCommands(access: AgentVersionReserveAccess): readonly string[] {
  const s = parseAgentVersionReserveAccess(access);
  if (!s?.grantId) return [];
  const origin = `${s.projectId} ${s.serviceInstance}`;
  return s.requestId ? [
    `mrk version-reserve-status ${origin} ${s.requestId}`,
    `mrk version-reserve-cancel ${origin} ${s.requestId}`,
  ] : s.enabled ? [`mrk version-reserve-submit ${origin} ${s.grantId} ${s.reviewId} --reviewed`] : [];
}
