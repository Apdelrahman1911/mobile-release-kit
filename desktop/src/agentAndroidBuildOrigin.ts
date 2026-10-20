// Native Projection DATA only: observe/STOP, never permission to Prepare/Start.
import type { AndroidBuildStatus } from './androidBuildTypes.ts';
export interface AgentAndroidBuildOrigin { serviceInstance: string; projectId: string; requestId: string }
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
// Called only after the existing protocol's descriptor-safe bounded copy.
export function validAgentAndroidBuildOrigin(value: unknown): value is AgentAndroidBuildOrigin {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return Object.keys(v).length === 3 && id(v.serviceInstance) && id(v.projectId) && id(v.requestId);
}
export function sameAgentAndroidBuildOrigin(a: AgentAndroidBuildOrigin | undefined, b: AgentAndroidBuildOrigin | undefined): boolean {
  return !a || !b ? a === b : a.serviceInstance === b.serviceInstance && a.projectId === b.projectId && a.requestId === b.requestId;
}
export function canObserveAgentAndroidBuild(previous: AndroidBuildStatus | null, next: AndroidBuildStatus, guiPending: boolean): boolean {
  const a = previous?.operation, b = next.operation;
  return !guiPending && !!b && b.context.operation === 'android-build-inspect' && b.context.artifactValidation.mode === 'structure-and-version' &&
    !!b.agentAndroidBuild && validAgentAndroidBuildOrigin(b.agentAndroidBuild) && (!previous || next.statusRevision > previous.statusRevision) &&
    (!a || a.phase === 'terminal') && (!a || a.operationId !== b.operationId || a.ownerGeneration !== b.ownerGeneration);
}
