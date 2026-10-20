// Native Projection DATA only. This marker permits display/STOP adoption, not
// Prepare/Start, a worker terminal, native finality or a renderer-made grant.
import type { OfflinePreflightStatus } from './offlinePreflightTypes.ts';
export interface AgentLocalCheckOrigin { serviceInstance: string; projectId: string; requestId: string }
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
// The existing protocol's bounded descriptor-safe copy runs before this test.
export function validAgentLocalCheckOrigin(v: unknown): v is AgentLocalCheckOrigin {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  return Object.keys(r).length === 3 && id(r.serviceInstance) && id(r.projectId) && id(r.requestId);
}
export function sameAgentLocalCheckOrigin(a: AgentLocalCheckOrigin | undefined, b: AgentLocalCheckOrigin | undefined): boolean {
  return a === undefined || b === undefined ? a === b : a.serviceInstance === b.serviceInstance && a.projectId === b.projectId && a.requestId === b.requestId;
}
export function canObserveAgentLocalCheck(previous: OfflinePreflightStatus | null, next: OfflinePreflightStatus, guiPending: boolean): boolean {
  const before = previous?.operation, after = next.operation;
  return !guiPending && !!after && after.context.operation === 'local-project-checks' && !!after.agentLocalCheck &&
    validAgentLocalCheckOrigin(after.agentLocalCheck) && (!previous || next.statusRevision > previous.statusRevision) &&
    (!before || before.phase === 'terminal') && (!before || before.operationId !== after.operationId || before.ownerGeneration !== after.ownerGeneration);
}
