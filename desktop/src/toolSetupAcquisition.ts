// Closed comparison DATA. Only the original native Inspection can authorize
// this missing-only acquisition; these fields never nominate a source path.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseToolAcquisitionContext } from './toolAcquisitionProtocol.ts';
import { parseToolComponentPartition } from './toolAcquisitionComponents.ts';
import type { ToolAcquisitionContext, ToolAcquisitionIdentity } from './toolAcquisitionProtocol.ts';
import type { ToolSetupReview } from './agentToolSetup.ts';

export const REVIEWED_ACQUISITION_KIND = 'acquire-reviewed-missing' as const;
const native = { jdk: 'jdk', 'android-platform': 'sdk-platform', 'android-build-tools': 'sdk-build-tools', gradle: 'gradle' } as const;
export const acquisitionComponents = ['jdk', 'android-platform', 'android-build-tools', 'gradle'] as const;
type Component = typeof acquisitionComponents[number];
export interface ToolSetupAcquisition {
  readonly operationId: string;
  readonly ownerGeneration: string;
  readonly requirementsSha256: string;
  readonly missing: readonly Component[];
  readonly compatible: readonly Component[];
}
const hex = (v: unknown, size: number): v is string => typeof v === 'string' && v.length === size && !/[^0-9a-f]/.test(v);
const id = (v: unknown): v is string => hex(v, 32) && v !== '0'.repeat(32);
export function parseToolSetupAcquisition(raw: unknown): ToolSetupAcquisition | null {
  try {
    const v = copyBoundedComparisonData(raw, 512, 32);
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    const r = v as Record<string, unknown>;
    const keys = ['operationId', 'ownerGeneration', 'requirementsSha256', 'missing', 'compatible'];
    if (Object.keys(r).length !== keys.length || !keys.every(k => Object.hasOwn(r, k)) || !id(r.operationId) || !id(r.ownerGeneration) ||
        !hex(r.requirementsSha256, 64) || !Array.isArray(r.missing) || !Array.isArray(r.compatible)) return null;
    const ordered = (parts: unknown[]): parts is Component[] => parts.length <= 4 && parts.every((p, i) =>
      typeof p === 'string' && acquisitionComponents.includes(p as Component) &&
      (i === 0 || acquisitionComponents.indexOf(parts[i - 1] as Component) < acquisitionComponents.indexOf(p as Component)));
    const missing = r.missing, compatible = r.compatible;
    if (!ordered(missing) || !ordered(compatible) || !missing.length || missing.length + compatible.length !== 4 ||
        missing.some(p => compatible.includes(p))) return null;
    return Object.freeze({ operationId: r.operationId, ownerGeneration: r.ownerGeneration, requirementsSha256: r.requirementsSha256,
      missing: Object.freeze(missing), compatible: Object.freeze(compatible) });
  } catch { return null; }
}
export function reviewedAcquisitionReview(raw: unknown, original: ToolAcquisitionIdentity, hash: string, partition: unknown): ToolSetupReview | null {
  const c = parseToolAcquisitionContext(raw), parts = parseToolComponentPartition(partition);
  if (!c || c.action !== 'inspect' || c.review !== null || !parts) return null;
  const acquisition = parseToolSetupAcquisition({ ...original, requirementsSha256: hash,
    missing: acquisitionComponents.filter(part => parts.missing.includes(native[part])),
    compatible: acquisitionComponents.filter(part => parts.compatible.includes(native[part])) });
  return acquisition ? Object.freeze({ kind: REVIEWED_ACQUISITION_KIND, platform: 'android', draftRevision: c.draftRevision,
    baselineGeneration: c.baselineGeneration, prepared: null, sources: null, acquisition }) : null;
}
export function reviewedAcquisitionContext(raw: unknown, review: ToolSetupReview, project: string): ToolAcquisitionContext | null {
  const c = parseToolAcquisitionContext(raw), a = parseToolSetupAcquisition(review.acquisition);
  return c && a && review.kind === REVIEWED_ACQUISITION_KIND && review.platform === 'android' && review.prepared === null && review.sources === null &&
    c.projectId === project && c.draftRevision === review.draftRevision && c.baselineGeneration === review.baselineGeneration &&
    c.action === 'acquire' && c.review?.operationId === a.operationId && c.review.ownerGeneration === a.ownerGeneration &&
    c.review.requirementsSha256 === a.requirementsSha256 ? c : null;
}
