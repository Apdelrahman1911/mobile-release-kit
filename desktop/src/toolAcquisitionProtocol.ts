// Closed comparison DATA for the original native tool-acquisition owner.
// Parsing a status never supplies source/catalogue leases or qualifies a host.
import { copyBoundedComparisonData, offlineCounter, parseSavedConfigContent, sameOfflineData } from './offlinePreflightProtocol.ts';
import type { SavedConfigContent } from './offlinePreflightTypes.ts';
import { parseStagedToolSources } from './toolAcquisitionGuidance.ts';
import type { StagedToolSourcesData } from './toolAcquisitionGuidance.ts';
import { parseToolComponentPartition } from './toolAcquisitionComponents.ts';
import type { ToolComponentPartition } from './toolAcquisitionComponents.ts';

import { parseToolSourceDiscovery } from './toolSourceDiscovery.ts';
import type { ToolSourceDiscovery } from './toolSourceDiscovery.ts';

export const TOOL_ACQUISITION_EVENT = 'tool-acquisition-state-changed';
export const TOOL_ACQUISITION_CONSENT = 'pinned-public-tool-sources-v1';
export const TOOL_ACQUISITION_REQUEST_LIMIT = 8192;
export const TOOL_ACQUISITION_STATUS_LIMIT = 64 * 1024;
export type ToolAcquisitionCommand = 'prepare_tool_acquisition' | 'start_tool_acquisition' |
  'tool_acquisition_status' | 'cancel_tool_acquisition';
export interface ToolAcquisitionIdentity { operationId: string; ownerGeneration: string }
export interface ToolAcquisitionContext {
  projectId: string; draftRevision: number; baselineGeneration: number; savedConfig: SavedConfigContent;
  action: 'inspect' | 'acquire';
  review: (ToolAcquisitionIdentity & { requirementsSha256: string }) | null;
}
export type ToolAcquisitionStart = ToolAcquisitionIdentity & { consentVersion: typeof TOOL_ACQUISITION_CONSENT };
export type ToolRequirementHint = { state: 'literal'; value: string } | { state: 'unspecified' | 'unknown'; value: null };
export type ProtectedToolsFinding = 'reuse-selected' | 'none-in-supported-catalogue' | 'manual-check-required';
export interface ToolRequirementsObservation {
  kind: 'tool-requirements-observation';
  // Only native post-join publication adds this comparison. It is not a tool
  // lease or build-readiness claim; null never permits a download review.
  protectedTools: ProtectedToolsFinding | null;
  components: ToolComponentPartition | null;
  discoveredSources?: ToolSourceDiscovery | null;
  requirements: {
    schemaVersion: 1; basis: 'unverified-static-source-hints'; sourcesSha256: string;
    complete: true; platform: 'android'; projectCodeExecuted: false;
    xcode: { version: string; build: string };
    android: {
      jdk: ToolRequirementHint; agp: ToolRequirementHint; sdkPlatform: ToolRequirementHint; sdkBuildTools: ToolRequirementHint;
      gradle: { state: 'literal'; version: string; distributionUrl: string; sha256: string | null } |
        { state: 'unknown'; version: null; distributionUrl: null; sha256: null };
    };
  };
}
const availabilities = ['available', 'busy', 'shutdown', 'cleanup-unknown', 'document-lost', 'unsupported-platform', 'runtime-unqualified'] as const;
const phases = ['awaiting-consent', 'starting', 'running', 'stopping', 'terminal', 'unknown'] as const;
const reasons = ['none', 'cancelled', 'timed-out', 'context-changed', 'document-lost', 'shutdown', 'runtime-unavailable',
  'protocol-error', 'intent-expired', 'stale-intent', 'cleanup-unknown', 'input-limit', 'result-limit', 'input', 'unsupported',
  'stale', 'census-incomplete', 'existing-tools-incompatible', 'existing-tools-unreadable', 'recovery-required', 'cache-conflict', 'disk-space', 'network', 'redirect', 'framing',
  'archive-digest', 'archive-layout', 'archive-member', 'limit', 'already-used', 'unknown'] as const;
export interface ToolAcquisitionOperation extends ToolAcquisitionIdentity {
  context: ToolAcquisitionContext; phase: typeof phases[number]; intentUsable: boolean;
  outcome: 'complete' | 'refused' | 'cancelled' | 'timed-out' | 'failed' | 'unknown' | null;
  reason: typeof reasons[number]; result: ToolRequirementsObservation | StagedToolSourcesData | null;
}
export interface ToolAcquisitionStatus {
  schemaVersion: 1; statusRevision: number; availability: typeof availabilities[number]; operation: ToolAcquisitionOperation | null;
}
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === names.length && names.every((name) => Object.hasOwn(v, name));
const oneOf = <T extends string>(v: unknown, values: readonly T[]): v is T => typeof v === 'string' && values.includes(v as T);
const token = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v);
const sha = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const literal = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9._+-]{1,128}$/.test(v);
function context(v: unknown): v is ToolAcquisitionContext {
  if (!keys(v, ['projectId', 'draftRevision', 'baselineGeneration', 'savedConfig', 'action', 'review']) ||
      typeof v.projectId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(v.projectId) ||
      !offlineCounter(v.draftRevision) || !offlineCounter(v.baselineGeneration) || !parseSavedConfigContent(v.savedConfig)) return false;
  return v.action === 'inspect' ? v.review === null : v.action === 'acquire' &&
    keys(v.review, ['operationId', 'ownerGeneration', 'requirementsSha256']) && token(v.review.operationId) &&
    token(v.review.ownerGeneration) && sha(v.review.requirementsSha256);
}
export function parseToolAcquisitionContext(value: unknown): ToolAcquisitionContext | null {
  try { const safe = copyBoundedComparisonData(value, TOOL_ACQUISITION_REQUEST_LIMIT, 128); return context(safe) ? safe : null; }
  catch { return null; }
}
export function encodeToolAcquisitionRequest(command: ToolAcquisitionCommand, value: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(value, TOOL_ACQUISITION_REQUEST_LIMIT, 128);
    const valid = command === 'prepare_tool_acquisition' ? context(v) : command === 'tool_acquisition_status' ? keys(v, []) :
      command === 'cancel_tool_acquisition' ? keys(v, ['operationId', 'ownerGeneration']) && token(v.operationId) && token(v.ownerGeneration) :
      command === 'start_tool_acquisition' && keys(v, ['operationId', 'ownerGeneration', 'consentVersion']) &&
        token(v.operationId) && token(v.ownerGeneration) && v.consentVersion === TOOL_ACQUISITION_CONSENT;
    return valid ? new TextEncoder().encode(JSON.stringify(v)) : null;
  } catch { return null; }
}
function hint(v: unknown, optional: boolean): boolean {
  return keys(v, ['state', 'value']) && (v.state === 'literal' ? literal(v.value) :
    v.value === null && (v.state === 'unknown' || optional && v.state === 'unspecified'));
}
function requirements(v: unknown): v is ToolRequirementsObservation {
  // The native public result deliberately omits its private source footprint.
  const withDiscovery = !!v && typeof v === 'object' && Object.hasOwn(v, 'discoveredSources');
  if (!keys(v, ['kind', 'requirements', 'protectedTools', 'components', ...(withDiscovery ? ['discoveredSources'] : [])]) || v.kind !== 'tool-requirements-observation' ||
      v.protectedTools !== null && !oneOf(v.protectedTools, ['reuse-selected', 'none-in-supported-catalogue', 'manual-check-required'])) return false;
  const parts = v.components === null ? null : parseToolComponentPartition(v.components);
  if (v.components !== null && (!parts || !['reuse-selected', 'none-in-supported-catalogue'].includes(v.protectedTools as string) ||
      v.protectedTools === 'reuse-selected' && parts.missing.length !== 0)) return false;
  if (withDiscovery && v.discoveredSources !== null && (!parts || v.protectedTools !== 'none-in-supported-catalogue' ||
      !parseToolSourceDiscovery(v.discoveredSources, parts))) return false;
  const r = v.requirements;
  if (!keys(r, ['schemaVersion', 'basis', 'sourcesSha256', 'complete', 'platform', 'projectCodeExecuted', 'xcode', 'android']) ||
      r.schemaVersion !== 1 || r.basis !== 'unverified-static-source-hints' || !sha(r.sourcesSha256) || r.complete !== true ||
      r.platform !== 'android' || r.projectCodeExecuted !== false || !keys(r.xcode, ['version', 'build']) ||
      !literal(r.xcode.version) || !literal(r.xcode.build) || !keys(r.android, ['jdk', 'agp', 'sdkPlatform', 'sdkBuildTools', 'gradle'])) return false;
  const a = r.android, g = a.gradle;
  if (!hint(a.jdk, true) || !hint(a.agp, false) || !hint(a.sdkPlatform, false) || !hint(a.sdkBuildTools, true) ||
      !keys(g, ['state', 'version', 'distributionUrl', 'sha256'])) return false;
  if (g.state === 'unknown') return g.version === null && g.distributionUrl === null && g.sha256 === null;
  return g.state === 'literal' && typeof g.version === 'string' && g.version.length <= 64 && /^\d+\.\d+(?:\.\d+)?$/.test(g.version) &&
    typeof g.distributionUrl === 'string' && g.distributionUrl.length <= 256 &&
    ['https://services.gradle.org/distributions/', 'https://downloads.gradle.org/distributions/'].some((prefix) =>
      g.distributionUrl === `${prefix}gradle-${g.version}-bin.zip`) && (g.sha256 === null || sha(g.sha256));
}
function completedResult(v: unknown, op: ToolAcquisitionOperation): boolean {
  if (op.context.action === 'inspect') return requirements(v);
  const report = parseStagedToolSources(v);
  return report !== null && report.operationId === op.operationId && report.cacheJob === `tool-${op.operationId}` &&
    report.reusedArchives.length + report.downloadedArchives.length > 0; // Exact native missing-set match is separate.
}
export function parseToolAcquisitionStatus(value: unknown): ToolAcquisitionStatus | null {
  try {
    const v = copyBoundedComparisonData(value, TOOL_ACQUISITION_STATUS_LIMIT, 512);
    if (!keys(v, ['schemaVersion', 'statusRevision', 'availability', 'operation']) || v.schemaVersion !== 1 ||
        !offlineCounter(v.statusRevision) || !oneOf(v.availability, availabilities)) return null;
    const op = v.operation;
    if (op === null) return v as unknown as ToolAcquisitionStatus;
    if (!keys(op, ['operationId', 'ownerGeneration', 'context', 'phase', 'intentUsable', 'outcome', 'reason', 'result']) ||
        !token(op.operationId) || !token(op.ownerGeneration) || !context(op.context) || !oneOf(op.phase, phases) ||
        typeof op.intentUsable !== 'boolean' || !oneOf(op.reason, reasons)) return null;
    if (op.phase === 'awaiting-consent') {
      if (op.outcome !== null || op.result !== null || op.reason !== 'none') return null;
    } else if (op.phase === 'unknown') {
      if (op.intentUsable || op.outcome !== 'unknown' || op.reason !== 'cleanup-unknown' || op.result !== null) return null;
    } else if (op.phase === 'terminal') {
      if (op.intentUsable || !oneOf(op.outcome, ['complete', 'refused', 'cancelled', 'timed-out', 'failed']) ||
          (op.outcome === 'complete') !== (op.reason === 'none')) return null;
      if (op.outcome === 'complete' ? !completedResult(op.result, op as unknown as ToolAcquisitionOperation) : op.result !== null) return null;
    } else if (op.intentUsable || op.outcome !== null || op.result !== null) return null;
    return v as unknown as ToolAcquisitionStatus;
  } catch { return null; }
}
// Reuse equality only on our bounded copies, not arbitrary bridge objects.
export const sameToolAcquisitionData = sameOfflineData;
export function sameToolAcquisitionIdentity(a: ToolAcquisitionIdentity | null | undefined, b: ToolAcquisitionIdentity | null | undefined): boolean {
  return !!a && !!b && a.operationId === b.operationId && a.ownerGeneration === b.ownerGeneration;
}
export function toolAcquisitionProgress(a: ToolAcquisitionOperation, b: ToolAcquisitionOperation): boolean {
  if (!sameToolAcquisitionIdentity(a, b) || !sameOfflineData(a.context, b.context)) return false;
  if (a.phase === 'terminal' || a.phase === 'unknown') return sameOfflineData(a, b);
  return !(!a.intentUsable && b.intentUsable) && phases.indexOf(b.phase) >= phases.indexOf(a.phase);
}

export const toolAcquisitionAvailabilityText: Record<ToolAcquisitionStatus['availability'], string> = {
  available: 'Check saved requirements before reviewing a download.',
  busy: 'Another tool operation is still active. Keep its original status and cancel control.',
  shutdown: 'The app is stopping. Keep the original tool status until it has finished.',
  'cleanup-unknown': 'Tool cleanup is unconfirmed. Keep the files and original status; do not repeat setup.',
  'document-lost': 'The original app session is no longer available. Its unfinished tool operation cannot be replaced.',
  'unsupported-platform': 'Guided downloads are not available on this computer. Use existing tools or the manual setup route.',
  'runtime-unqualified': 'Guided downloads are not enabled in this app build. Existing tool selection and manual setup remain available.',
};
