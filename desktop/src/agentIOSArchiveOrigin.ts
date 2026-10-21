// Native Projection DATA only: observe/STOP, never permission to Prepare/Start.
import type { IOSArchiveStatus } from './iosArchiveTypes.ts';
export interface AgentIOSArchiveOrigin { serviceInstance: string; projectId: string; requestId: string }
const id = (v: unknown): v is string => typeof v === 'string' && v.length === 32 && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
// Called only after the existing protocol's descriptor-safe bounded copy.
export function validAgentIOSArchiveOrigin(value: unknown): value is AgentIOSArchiveOrigin {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return Object.keys(v).length === 3 && id(v.serviceInstance) && id(v.projectId) && id(v.requestId);
}
export function sameAgentIOSArchiveOrigin(a: AgentIOSArchiveOrigin | undefined, b: AgentIOSArchiveOrigin | undefined): boolean {
  return !a || !b ? a === b : a.serviceInstance === b.serviceInstance && a.projectId === b.projectId && a.requestId === b.requestId;
}
export function canObserveAgentIOSArchive(previous: IOSArchiveStatus | null, next: IOSArchiveStatus, guiPending: boolean): boolean {
  const a = previous?.operation, b = next.operation;
  return !guiPending && !!b && (b.context.operation === 'ios-unsigned-archive' || b.context.operation === 'ios-signed-export' || b.context.operation === 'ios-local-recovery') &&
    !!b.agentIosArchive && validAgentIOSArchiveOrigin(b.agentIosArchive) && (!previous || next.statusRevision > previous.statusRevision) &&
    (!a || a.phase === 'terminal') && (!a || a.operationId !== b.operationId || a.ownerGeneration !== b.ownerGeneration);
}
