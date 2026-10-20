// Closed display/comparison DATA, never a native missing-tool proof or consent.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { componentList, components } from './toolAcquisitionGuidance.ts';
import type { Component, StagedToolSourcesData } from './toolAcquisitionGuidance.ts';

export interface ToolComponentPartition { missing: Component[]; compatible: Component[] }
export function parseToolComponentPartition(value: unknown): ToolComponentPartition | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 32);
    if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== 2 ||
        !Object.hasOwn(v, 'missing') || !Object.hasOwn(v, 'compatible')) return null;
    const row = v as Record<string, unknown>;
    const missing = componentList(row.missing), compatible = componentList(row.compatible);
    return missing && compatible && missing.length + compatible.length === components.length &&
      missing.every((part) => !compatible.includes(part)) ? { missing, compatible } : null;
  } catch { return null; }
}
export function stagedMatchesComponents(report: StagedToolSourcesData, partition: ToolComponentPartition | null): boolean {
  if (!partition || !partition.missing.length) return false;
  const all = [...report.reusedArchives, ...report.downloadedArchives];
  return all.length === partition.missing.length && partition.missing.every((part) => all.includes(part));
}
const labels: Record<Component, string> = {
  jdk: 'Java JDK', 'sdk-platform': 'Android API 35 platform',
  'sdk-build-tools': 'Android Build-Tools 35.0.0', gradle: 'Gradle',
};
export const toolComponentLabel = (part: Component): string => labels[part];
export function hasIncompleteSdk(partition: ToolComponentPartition): boolean {
  return partition.missing.filter((part) => part === 'sdk-platform' || part === 'sdk-build-tools').length === 1;
}
export const MANUAL_ANDROID_SDK_STEPS = [
  'Open Android Studio’s SDK Manager (Settings → Languages & Frameworks → Android SDK). Keep your existing SDK location and packages.',
  'Under SDK Platforms choose Android 15 (API 35). Under SDK Tools turn on Show Package Details and choose Android SDK Build-Tools 35.0.0. Review and accept any vendor license there.',
  'Choose that complete SDK folder in this app and inspect it again. The exact supported platform revision is 2; a different revision needs manual review, not an automatic upgrade or downgrade.',
] as const;
