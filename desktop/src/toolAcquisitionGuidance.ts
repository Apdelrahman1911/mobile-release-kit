// Staged download DATA only. Parsing never grants native completion, a picker
// original, installation consent, a protected tool lease or build readiness.
import type { AndroidToolSourceRole } from './androidToolSources.ts';

export type Component = 'jdk' | 'sdk-platform' | 'sdk-build-tools' | 'gradle';
export const components: readonly Component[] = ['jdk', 'sdk-platform', 'sdk-build-tools', 'gradle'];
const roles: readonly AndroidToolSourceRole[] = ['jdk', 'sdk', 'gradle'];
interface StagedToolSourcesBase {
  kind: 'staged-tool-sources'; operationId: string; contextSha256: string;
  referenceSha256: string; projectionSha256: string; cacheJob: string; lookupScope: 'registered-selected-known';
  reusedArchives: Component[]; downloadedArchives: Component[];
  groups: { group: AndroidToolSourceRole; components: Component[]; allRequiredComponentsStaged: boolean;
    next: 'choose-native-source' | 'complete-sdk-manually' }[];
  assurance: { nativeFinality: false; registered: false; readyToBuild: false };
}
export type StagedToolSourcesData = StagedToolSourcesBase & (
  { schemaVersion: 1; copiedSourceComponents?: never } |
  { schemaVersion: 2; copiedSourceComponents: ['sdk-platform' | 'sdk-build-tools'] });
function fields(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== 'string' || !keys.includes(key))) return null;
  const copy: Record<string, unknown> = {};
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) return null;
    copy[key] = field.value;
  }
  return copy;
}
function list(value: unknown, max: number): unknown[] | null {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max || Reflect.ownKeys(value).length !== value.length + 1) return null;
  const copy = [];
  for (let i = 0; i < value.length; i++) {
    const field = Object.getOwnPropertyDescriptor(value, String(i));
    if (!field?.enumerable || !Object.hasOwn(field, 'value')) return null;
    copy.push(field.value);
  }
  return copy;
}
export function componentList(value: unknown): Component[] | null {
  const result = list(value, 4);
  return result && result.every((part) => components.includes(part as Component)) &&
    JSON.stringify(result) === JSON.stringify(components.filter((part) => result.includes(part))) ? result as Component[] : null;
}
const groupOf = (part: Component): AndroidToolSourceRole => part === 'sdk-platform' || part === 'sdk-build-tools' ? 'sdk' : part;
const sha = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export function parseStagedToolSources(value: unknown): StagedToolSourcesData | null {
  try {
    const schema = value && typeof value === 'object' ? Object.getOwnPropertyDescriptor(value, 'schemaVersion')?.value : null;
    const v = fields(value, ['schemaVersion', 'kind', 'operationId', 'contextSha256', 'referenceSha256', 'projectionSha256',
      'cacheJob', 'lookupScope', 'reusedArchives', 'downloadedArchives', 'groups', 'assurance', ...(schema === 2 ? ['copiedSourceComponents'] : [])]);
    if (!v || ![1, 2].includes(v.schemaVersion as number) || v.kind !== 'staged-tool-sources' || typeof v.operationId !== 'string' ||
        !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(v.operationId) || !sha(v.contextSha256) || !sha(v.referenceSha256) || !sha(v.projectionSha256) ||
        v.lookupScope !== 'registered-selected-known') return null;
    const reused = componentList(v.reusedArchives), downloaded = componentList(v.downloadedArchives), groups = list(v.groups, 3);
    const assurance = fields(v.assurance, ['nativeFinality', 'registered', 'readyToBuild']);
    if (!reused || !downloaded || !groups || reused.some((part) => downloaded.includes(part)) ||
        !assurance || Object.values(assurance).some((fact) => fact !== false)) return null;
    const archives = components.filter((part) => reused.includes(part) || downloaded.includes(part));
    const copied = schema === 2 ? componentList(v.copiedSourceComponents) : [];
    if (!copied) return null;
    if (schema === 2) {
      const part = copied[0];
      if (copied.length !== 1 || (part !== 'sdk-platform' && part !== 'sdk-build-tools') ||
          archives.includes(part) || !archives.includes(part === 'sdk-platform' ? 'sdk-build-tools' : 'sdk-platform')) return null;
    }
    const selected = components.filter((part) => archives.includes(part) || copied.includes(part));
    if (v.cacheJob !== (archives.length ? `tool-${v.operationId}` : '') || groups.length !== roles.filter((role) => selected.some((part) => groupOf(part) === role)).length) return null;
    const parsedGroups: StagedToolSourcesData['groups'] = [];
    for (const role of roles) {
      const parts = selected.filter((part) => groupOf(part) === role);
      if (!parts.length) continue;
      const row = fields(groups[parsedGroups.length], ['group', 'components', 'allRequiredComponentsStaged', 'next']);
      const actual = row && componentList(row.components), complete = parts.length === components.filter((part) => groupOf(part) === role).length;
      if (!row || row.group !== role || !actual || JSON.stringify(actual) !== JSON.stringify(parts) || row.allRequiredComponentsStaged !== complete ||
          row.next !== (complete ? 'choose-native-source' : 'complete-sdk-manually')) return null;
      parsedGroups.push({ group: role, components: actual, allRequiredComponentsStaged: complete,
        next: complete ? 'choose-native-source' : 'complete-sdk-manually' });
    }
    return { ...v, reusedArchives: reused, downloadedArchives: downloaded, groups: parsedGroups, assurance } as StagedToolSourcesData;
  } catch { return null; }
}

export interface StagedToolGuidance {
  title: string; body: string; steps: string[];
  pickers: { role: AndroidToolSourceRole; label: string }[];
}
// The ORIGINAL native owner supplies this state AFTER accepting its actual
// child/driver/joins and current context. Never derive it from the DATA parser,
// result.json, a timer, capability or a successful Start response.
export type StagedToolPresentation = 'settling' | 'current-staged' | 'recovery-required' | 'stale';
export function stagedToolSourceGuidance(value: unknown, presentation: StagedToolPresentation): StagedToolGuidance {
  const none = (title: string, body: string): StagedToolGuidance => ({ title, body, steps: [], pickers: [] });
  if (presentation === 'recovery-required') return none('Tool download needs attention',
    'Keep the existing files and review the original download status. Completion is unconfirmed; do not retry or delete the staging folder.');
  if (presentation === 'settling') return none('Finishing tool download',
    'Wait for the original download operation to finish, or use its existing cancel control. Downloaded bytes alone do not establish completion.');
  if (presentation !== 'current-staged') return none('Check the current tool status',
    'This report belongs to an earlier or unconfirmed context. Recheck existing tools before deciding anything is missing.');
  const report = parseStagedToolSources(value);
  if (!report) return none('Tool download report needs attention', 'The report could not be checked. Read native status; do not use it to repeat setup.');
  if (!report.groups.length) return none('Use the tools you already have', 'No missing tools were selected for this operation. Nothing was downloaded or installed.');
  const steps = ['Open the staged source folder shown by this download operation, then choose its JDK bundle, Android SDK or Gradle folder using the ordinary native picker.',
    'Run Inspect selected tools. Review all three sources and the setup service before explicitly approving a protected copy. The download has not registered anything.',
    'Keep existing installations and global settings. The search covered registered copies, selected folders and known supported locations, not every folder on this computer.'];
  if (report.groups.some((group) => !group.allRequiredComponentsStaged)) steps.unshift(
    'Only the missing Android SDK package was staged; the other required package was checked in your chosen SDK. This staged SDK is incomplete. Choose an existing complete supported SDK or finish manual SDK preparation without overwriting working tools.');
  if (report.schemaVersion === 2) steps.unshift(
    'The prepared SDK combines a verified copy of your matching package with the missing package. Your original SDK and its other packages were not changed. Inspect the complete candidate and review licenses before approving a protected copy.');
  const pickers = report.groups.map((group) => ({ role: group.group,
    label: group.group === 'jdk' ? 'Choose JDK' : group.group === 'gradle' ? 'Choose Gradle' :
      group.allRequiredComponentsStaged ? 'Choose Android SDK' : 'Choose complete Android SDK' }));
  return { title: 'Choose the prepared tool folders', body: 'Required files are staged. Source inspection and protected-copy approval still remain; this is not automatic installation or build readiness.', steps, pickers };
}

export function toolAcquisitionFailureGuidance(reason: string): { title: string; body: string } {
  if (['unknown', 'recovery-required', 'already-used'].includes(reason)) return { title: 'Review the previous download',
    body: 'Preserve the existing files and read the original status. An absent folder or a late result does not authorize a retry.' };
  if (reason === 'disk-space') return { title: 'More free space is needed',
    body: 'Allow room for missing archives, extracted sources and the download reserve. A later protected copy needs its own space. Keep working tools; no automatic cleanup is performed.' };
  if (['stale', 'census-incomplete', 'unsupported'].includes(reason)) return { title: 'Check existing tools first',
    body: 'Refresh the current supported tool check or choose an existing installation elsewhere. A missing selection is not proof that a download is needed.' };
  if (['network', 'redirect', 'framing'].includes(reason)) return { title: 'The vendor download could not be checked',
    body: 'Review the original status and your connection. Do not disable TLS checks, provide credentials or use an alternate unverified URL. Manual setup with the exact supported release remains available.' };
  return { title: 'The staged files need attention',
    body: 'The archive, layout or cache did not pass verification. Keep existing tools and the failed operation for review; nothing has been registered.' };
}
