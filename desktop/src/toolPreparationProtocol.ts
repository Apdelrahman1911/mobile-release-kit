import { encodeAndroidCatalogRequest } from './androidToolchainCatalogProtocol.ts';
import type { SelectAndroidToolchain } from './androidToolchainCatalogTypes.ts';
import type { ToolPreparationContext, ToolPreparationPlan, ToolPreparationRequest } from './toolPreparationTypes.ts';

function fields(value: unknown, names: readonly string[]): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length || keys.some((key) => typeof key !== 'string' || !names.includes(key))) return null;
  const copy: Record<string, unknown> = {};
  for (const name of names) {
    const field = Object.getOwnPropertyDescriptor(value, name);
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) return null;
    copy[name] = field.value;
  }
  return copy;
}
function list(value: unknown, max: number): unknown[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max || Reflect.ownKeys(value).length !== value.length + 1) return null;
  const copy: unknown[] = [];
  for (let i = 0; i < value.length; i++) {
    const entry = Object.getOwnPropertyDescriptor(value, String(i));
    if (!entry?.enumerable || !Object.hasOwn(entry, 'value')) return null;
    copy.push(entry.value);
  }
  return copy;
}
const counter = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < 0xffffffff;
const sha = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const label = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(v);
const projectId = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v);
const version = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9 ._+-]{1,128}$/.test(v);
const hosts = ['macos-arm64', 'macos-x86_64', 'linux-x86_64', 'unsupported'];
const actions = ['check-project-requirements', 'refresh-registered-tools', 'choose-registered-copy', 'use-selected-copy',
  'choose-jdk', 'choose-sdk', 'choose-gradle', 'inspect-sources', 'review-protected-copy', 'review-source-problem',
  'check-tool-service', 'register-tool-service', 'open-tool-service-settings', 'reconcile-setup', 'wait-for-setup',
  'check-xcode', 'install-xcode-manually', 'inspect-xcode-copy', 'unsupported-host'];
const reasons = ['not-checked', 'requirements-unknown', 'policy-mismatch', 'existing-selected', 'existing-unselected',
  'existing-sources', 'selection-missing', 'source-problem', 'service-required', 'original-unsettled', 'original-busy',
  'host-unavailable', 'xcode-missing', 'xcode-mismatch', 'xcode-needs-native-check'];
export function parseToolPreparationPlan(value: unknown): ToolPreparationPlan | null {
  try {
    const v = fields(value, ['schemaVersion', 'basis', 'context', 'stamp', 'platform', 'state', 'action', 'reason', 'reusable', 'unselectedSources', 'policy', 'xcode', 'assurance']);
    if (!v || v.schemaVersion !== 1 || v.basis !== 'tool-preparation-guidance' || !['android', 'ios'].includes(v.platform as string) ||
        !['needs-check', 'needs-review', 'can-reuse', 'needs-preparation', 'recovery-required', 'busy', 'unsupported'].includes(v.state as string) ||
        !actions.includes(v.action as string) || !reasons.includes(v.reason as string)) return null;
    const context = fields(v.context, ['projectId', 'sessionId', 'observationRevision', 'savedConfigSha256', 'requirementsSha256', 'host']);
    if (!context || !projectId(context.projectId) || !label(context.sessionId) || !counter(context.observationRevision) || context.observationRevision === 0 ||
        !sha(context.savedConfigSha256) || !sha(context.requirementsSha256) || !hosts.includes(context.host as string)) return null;
    const stamp = fields(v.stamp, ['catalogGeneration', 'catalogRevision', 'sourceGeneration', 'sourceRevision', 'registrationGeneration',
      'registrationRevision', 'serviceGeneration', 'serviceRevision', 'diagnosticsRevision']);
    if (!stamp || !Object.values(stamp).every(counter)) return null;
    const rows = list(v.reusable, 32), roles = list(v.unselectedSources, 3);
    if (!rows || !roles || roles.some((role) => !['jdk', 'sdk', 'gradle'].includes(role as string)) || new Set(roles).size !== roles.length) return null;
    const reusable = rows.map((row) => {
      const bytes = encodeAndroidCatalogRequest('select_android_toolchain', row);
      return bytes ? JSON.parse(new TextDecoder().decode(bytes)) as ToolPreparationPlan['reusable'][number] : null;
    });
    if (reusable.some((row) => !row || row.catalogGeneration !== stamp.catalogGeneration) ||
        new Set(reusable.map((row) => row?.instance)).size !== reusable.length) return null;
    const xcode = fields(v.xcode, ['version', 'build']);
    if (!xcode || !version(xcode.version) || !version(xcode.build)) return null;
    const assurance = fields(v.assurance, ['writesPerformed', 'projectCodeExecuted', 'downloadsPlanned', 'executionAuthorized', 'releaseReadiness']);
    if (!assurance || assurance.writesPerformed !== false || assurance.projectCodeExecuted !== false || assurance.downloadsPlanned !== 0 ||
        assurance.executionAuthorized !== false || assurance.releaseReadiness !== 'not-assessed') return null;
    const policy = v.policy === null ? null : fields(v.policy, ['host', 'jdkVendor', 'jdk', 'gradle', 'agp', 'sdkPlatform', 'sdkBuildTools', 'distributionUrl', 'distributionSha256']);
    if (v.policy !== null && (!policy || policy.host !== context.host || !['macos-arm64', 'macos-x86_64'].includes(policy.host as string) ||
        !['jdkVendor', 'jdk', 'gradle', 'agp', 'sdkPlatform', 'sdkBuildTools'].every((key) => version(policy[key])) ||
        !sha(policy.distributionSha256) || typeof policy.distributionUrl !== 'string' || policy.distributionUrl.length > 256 ||
        !/^https:\/\/(services|downloads)\.gradle\.org\/distributions\/gradle-[0-9.]+-bin\.zip$/.test(policy.distributionUrl))) return null;
    if (v.state === 'can-reuse' && (v.platform !== 'android' || v.action !== 'use-selected-copy' || v.reason !== 'existing-selected' || !policy || !reusable.length || roles.length) ||
        v.action === 'use-selected-copy' && v.state !== 'can-reuse' ||
        v.action === 'choose-registered-copy' && (!reusable.length || !policy || v.platform !== 'android') ||
        v.state === 'recovery-required' && (v.action !== 'reconcile-setup' || v.reason !== 'original-unsettled') ||
        v.state === 'busy' && (v.action !== 'wait-for-setup' || v.reason !== 'original-busy') ||
        v.state === 'unsupported' && v.action !== 'unsupported-host' ||
        v.platform === 'ios' && (policy !== null || reusable.length || roles.length ||
          !['check-project-requirements', 'reconcile-setup', 'wait-for-setup', 'unsupported-host', 'check-xcode', 'install-xcode-manually', 'inspect-xcode-copy'].includes(v.action as string))) return null;
    const parsed = { ...v, context, stamp, reusable, unselectedSources: roles, policy, xcode, assurance } as unknown as ToolPreparationPlan;
    return new TextEncoder().encode(JSON.stringify(parsed)).length <= 32 * 1024 ? parsed : null;
  } catch { return null; }
}
export function encodeToolPreparationRequest(value: unknown): Uint8Array | null {
  try {
    const v = fields(value, ['schemaVersion', 'projectId', 'expectedObservationRevision']);
    if (!v || v.schemaVersion !== 1 || !projectId(v.projectId) || !counter(v.expectedObservationRevision) || v.expectedObservationRevision === 0) return null;
    return new TextEncoder().encode(JSON.stringify(v as unknown as ToolPreparationRequest));
  } catch { return null; }
}
export function sameToolPreparationContext(a: ToolPreparationContext, b: ToolPreparationContext): boolean {
  return a.projectId === b.projectId && a.sessionId === b.sessionId && a.observationRevision === b.observationRevision &&
    a.savedConfigSha256 === b.savedConfigSha256 && a.requirementsSha256 === b.requirementsSha256 && a.host === b.host;
}
export function sameToolPreparationCopy(a: SelectAndroidToolchain, b: SelectAndroidToolchain): boolean {
  return a.schemaVersion === b.schemaVersion && a.catalogGeneration === b.catalogGeneration && a.instance === b.instance &&
    a.recordSha256 === b.recordSha256 && a.inventorySha256 === b.inventorySha256 && a.osProviderSha256 === b.osProviderSha256;
}
export function sameToolPreparationDecision(a: ToolPreparationPlan, b: ToolPreparationPlan): boolean {
  // Both inputs were parsed into fixed field order above. No arbitrary caller
  // object, path, getter or executable is compared or forwarded here.
  return sameToolPreparationContext(a.context, b.context) && JSON.stringify(a.stamp) === JSON.stringify(b.stamp) && a.platform === b.platform &&
    a.state === b.state && a.action === b.action && a.reason === b.reason && a.reusable.length === b.reusable.length &&
    a.reusable.every((copy, at) => b.reusable[at] !== undefined && sameToolPreparationCopy(copy, b.reusable[at]!)) &&
    JSON.stringify(a.unselectedSources) === JSON.stringify(b.unselectedSources) && JSON.stringify(a.policy) === JSON.stringify(b.policy) &&
    a.xcode.version === b.xcode.version && a.xcode.build === b.xcode.build;
}
