// Public fixed-location observation only. Native paths/originals never cross
// this boundary; choosing a found folder still uses the original source picker.
import { components as TOOL_COMPONENTS } from './toolAcquisitionGuidance.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import type { ToolComponentPartition } from './toolAcquisitionComponents.ts';
import type { Component as ToolComponent } from './toolAcquisitionGuidance.ts';
import type { AndroidToolSourceRole } from './androidToolSources.ts';

export const TOOL_DISCOVERY_SCOPE = 'fixed-macos-locations-v1';
const ROLES: readonly AndroidToolSourceRole[] = ['jdk', 'sdk', 'gradle'];
const roleOf = (component: ToolComponent): AndroidToolSourceRole =>
  component === 'jdk' ? 'jdk' : component === 'gradle' ? 'gradle' : 'sdk';
export interface ToolSourceDiscovery {
  scope: typeof TOOL_DISCOVERY_SCOPE;
  searched: readonly AndroidToolSourceRole[];
  present: readonly AndroidToolSourceRole[];
  compatibleComponents: readonly ToolComponent[];
}
function canonical<T extends string>(v: unknown, roster: readonly T[]): v is T[] {
  return Array.isArray(v) && v.length <= roster.length && v.every((item, i) =>
    typeof item === 'string' && roster.includes(item as T) && (i === 0 || roster.indexOf(v[i - 1]) < roster.indexOf(item as T)));
}
export function parseToolSourceDiscovery(value: unknown, parts: ToolComponentPartition): ToolSourceDiscovery | null {
  try { value = copyBoundedComparisonData(value, 1024, 64); } catch { return null; }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  if (Object.keys(v).length !== 4 || !['scope', 'searched', 'present', 'compatibleComponents'].every((k) => Object.hasOwn(v, k)) ||
      v.scope !== TOOL_DISCOVERY_SCOPE || !canonical(v.searched, ROLES) || !v.searched.length ||
      !canonical(v.present, ROLES) ||
      !canonical(v.compatibleComponents, TOOL_COMPONENTS)) return null;
  const searched = v.searched, present = v.present, compatible = v.compatibleComponents;
  if (!present.every((role) => searched.includes(role))) return null;
  const expected = parts.compatible.filter((component) => searched.includes(roleOf(component)));
  if (compatible.length !== expected.length || compatible.some((component, i) => component !== expected[i] || !present.includes(roleOf(component)))) return null;
  return { scope: TOOL_DISCOVERY_SCOPE, searched: [...searched], present: [...present], compatibleComponents: [...compatible] };
}
export function foundToolRoles(value: ToolSourceDiscovery | null | undefined): readonly AndroidToolSourceRole[] {
  return value ? ROLES.filter((role) => value.compatibleComponents.some((part) => roleOf(part) === role)) : [];
}
export const TOOL_DISCOVERY_HELP = 'This check covers the selected protected tools, your chosen folders, and three fixed Mac locations: the Temurin 17 system JDK, your account’s Library/Android/sdk, and /opt/gradle/gradle-8.14.5. It does not scan your computer, Homebrew, SDKMAN or project-wrapper caches.';
