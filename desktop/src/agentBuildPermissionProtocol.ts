// Build-only MAIN revision DATA. LocalCheckAccess and installed CLI wire stay unchanged.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseLocalCheckAccess } from './agentLocalChecks.ts';
import type { LocalCheckAccess } from './agentLocalChecks.ts';
export interface BuildPermissionAccess extends LocalCheckAccess { permissionRevision: string }
const MAX = '18446744073709551615';
export function buildPermissionRevision(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 20 && /^(?:0|[1-9][0-9]*)(?![\s\S])/.test(value) &&
    (value.length < MAX.length || value <= MAX);
}
export function parseBuildPermissionAccess(value: unknown): BuildPermissionAccess | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 32);
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    const row = v as Record<string, unknown>;
    const fields = ['enabled', 'remainingMs', 'projectId', 'observationRevision', 'consumed', 'permissionRevision'];
    if (Object.keys(row).length !== fields.length || !fields.every((f) => Object.hasOwn(row, f)) ||
        !buildPermissionRevision(row.permissionRevision)) return null;
    const access = parseLocalCheckAccess({ enabled: row.enabled, remainingMs: row.remainingMs,
      projectId: row.projectId, observationRevision: row.observationRevision, consumed: row.consumed });
    return access ? Object.freeze({ ...access, permissionRevision: row.permissionRevision }) : null;
  } catch { return null; }
}
export function nextBuildPermissionRevision(value: string): string | null {
  return buildPermissionRevision(value) && value !== MAX ? (BigInt(value) + 1n).toString() : null;
}
