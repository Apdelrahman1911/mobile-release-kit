// Passive shared-core guidance only. These rows never grant or start an action.
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import { copyBoundedComparisonData, parseSavedConfigContent, sameSavedConfig, savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';
import type { Assurance } from './types.ts';

export type SetupStage = 'local' | 'signing' | 'store' | 'automation';
export type SetupRequirementState = 'configured' | 'detected' | 'needs-input' | 'ambiguous' | 'unverified' |
  'unsupported' | 'blocked' | 'deferred' | 'not-checked';
export type SetupConfigurationState = 'missing' | 'invalid' | 'format-valid' | 'unavailable';
const specification = {
  'project-layout': ['local', null], 'release-settings': ['local', null], 'version-source': ['local', 'version.source'],
  'android-identity': ['local', 'android.applicationId'], 'android-module': ['local', 'android.module'],
  'android-variant': ['local', 'android.variant'], 'android-tools': ['local', null],
  'android-signing': ['signing', 'android.uploadCertificateSha256'], 'android-store': ['store', 'android.identityStatus'],
  'android-testing': ['store', 'android.externalTrack'], 'ios-identity': ['local', 'ios.bundleId'],
  'ios-container': ['local', ['ios.project', 'ios.workspace']], 'ios-scheme': ['local', 'ios.scheme'],
  'ios-configuration': ['local', 'ios.archiveConfiguration'], 'ios-tools': ['local', null],
  'ios-signing': ['signing', 'ios.teamId'], 'ios-store': ['store', 'ios.appStoreAppId'],
  'ios-testing': ['store', 'ios.externalTestFlightGroup'], 'store-metadata': ['store', 'metadata.root'],
  'github-automation': ['automation', null],
} as const;
export type SetupRequirementId = keyof typeof specification;
export interface SetupRequirement {
  id: SetupRequirementId; stage: SetupStage; state: SetupRequirementState;
  field: string | null; reference: string | null; summary: string;
}
export interface SetupAnalysis {
  schemaVersion: 1; scope: 'local-setup-guidance'; configurationState: SetupConfigurationState;
  discoveryPartial: boolean; platforms: ('android' | 'ios')[]; requirements: SetupRequirement[];
  limitations: string[]; assurance: Assurance & { basis: 'static-text' };
}
const states: readonly string[] = ['configured', 'detected', 'needs-input', 'ambiguous', 'unverified', 'unsupported', 'blocked', 'deferred', 'not-checked'];
const configStates: readonly string[] = ['missing', 'invalid', 'format-valid', 'unavailable'];
const encoder = new TextEncoder();
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const text = (value: unknown, max: number): value is string => typeof value === 'string' && value.length > 0 &&
  encoder.encode(value).byteLength <= max && !/[\u0000-\u001f\u007f]/.test(value);
const reference = (value: unknown): boolean => value === null || (text(value, 512) &&
  !value.startsWith('/') && !value.includes('\\') && !/^[A-Za-z]:/.test(value) &&
  value.split('/').every((part) => part !== '' && part !== '.' && part !== '..'));

export function parseSetupAnalysis(input: unknown): SetupAnalysis | null {
  try {
    const value = copyBoundedComparisonData(input, 16 * 1024, 2048);
    if (!keys(value, ['schemaVersion', 'scope', 'configurationState', 'discoveryPartial', 'platforms', 'requirements', 'limitations', 'assurance']) ||
        value.schemaVersion !== 1 || value.scope !== 'local-setup-guidance' || !configStates.includes(value.configurationState as string) ||
        typeof value.discoveryPartial !== 'boolean' || !Array.isArray(value.platforms) || value.platforms.length > 2 ||
        value.platforms.some((item) => item !== 'android' && item !== 'ios') || new Set(value.platforms).size !== value.platforms.length ||
        (value.platforms.length === 2 && value.platforms[0] !== 'android') ||
        !Array.isArray(value.requirements) || value.requirements.length > 32 || !Array.isArray(value.limitations) ||
        value.limitations.length !== 6 || !value.limitations.every((item) => text(item, 512)) ||
        !keys(value.assurance, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) ||
        value.assurance.basis !== 'static-text' || value.assurance.releaseReadiness !== 'unknown') return null;
    const platforms = value.platforms, claims = value.assurance;
    if (['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].some((key) => claims[key] !== false)) return null;
    const expected = Object.keys(specification).filter((id) => !id.startsWith('android-') && !id.startsWith('ios-') &&
      (id !== 'store-metadata' || platforms.length > 0) || id.startsWith('android-') && platforms.includes('android') ||
      id.startsWith('ios-') && platforms.includes('ios'));
    if (value.requirements.length !== expected.length) return null;
    for (let index = 0; index < expected.length; index++) {
      const row = value.requirements[index];
      if (!keys(row, ['id', 'stage', 'state', 'field', 'reference', 'summary']) || row.id !== expected[index] ||
          !states.includes(row.state as string) || !text(row.summary, 1024) || !reference(row.reference)) return null;
      const [stage, field] = specification[row.id as SetupRequirementId];
      if (row.stage !== stage || (Array.isArray(field) ? !field.includes(row.field as never) : row.field !== field)) return null;
      if (['android-tools', 'ios-tools', 'android-signing', 'ios-signing'].includes(row.id as string) && row.state !== 'not-checked') return null;
      if (row.state === 'configured' && value.configurationState !== 'format-valid') return null;
    }
    return value as unknown as SetupAnalysis;
  } catch { return null; }
}

export interface SetupGuidanceView { analysis: SetupAnalysis | null; savedOnly: boolean; reason: string | null }
export function setupGuidanceView(session: ProjectSession | null, preview: boolean, refreshReason: string | null): SetupGuidanceView {
  const unavailable = (reason: string): SetupGuidanceView => ({ analysis: null, savedOnly: false, reason });
  if (preview) return unavailable('Example only. Choose your project to read its setup requirements.');
  if (refreshReason !== null) return unavailable('The original project operation prevents a current read. Finish it before using setup guidance.');
  if (!session?.snapshot || session.observedAt === null) return unavailable('Read the selected project to see its local setup requirements.');
  if (session.snapshot.root !== session.project.path || session.snapshotRequest !== null || session.snapshotError ||
      session.snapshotPredatesSave || session.sourceChanged || session.saveRecoveryRequired || session.saveRecoveryNeedsReload) {
    return unavailable('The saved observation is not current. Keep your draft and finish or refresh the original operation first.');
  }
  // An optional old snapshot is unavailable, not an empty/completed checklist.
  const descriptor = Object.getOwnPropertyDescriptor(session.snapshot, 'setupAnalysis');
  const analysis = descriptor?.enumerable && Object.hasOwn(descriptor, 'value') ? parseSetupAnalysis(descriptor.value) : null;
  if (!analysis || analysis.configurationState !== session.snapshot.config.state || analysis.discoveryPartial !== session.snapshot.discovery.partial) {
    return unavailable('Setup guidance is unavailable for this saved observation. Read the project again when safe.');
  }
  if (analysis.configurationState === 'format-valid') {
    const original = savedConfigFromSnapshot(session.snapshot), retained = parseSavedConfigContent(session.savedConfigContent);
    if (!original || !retained || !sameSavedConfig(original, retained)) {
      return unavailable('The saved configuration comparison has been retired or changed. Keep the draft and refresh after the original operation settles.');
    }
  }
  return { analysis, savedOnly: isDirty(session), reason: null };
}

export const setupStageLabels: Record<SetupStage, string> = {
  local: '1. Local setup', signing: '2. Signing, when needed', store: '3. Store delivery, later', automation: '4. Optional automation',
};
export const setupStateLabels: Record<SetupRequirementState, string> = {
  configured: 'Setting present — not verified', detected: 'Static hint', 'needs-input': 'Needs input', ambiguous: 'Choose explicitly',
  unverified: 'Unknown', unsupported: 'Unsupported automatic setup', blocked: 'Blocked', deferred: 'Later', 'not-checked': 'Not checked',
};
export const setupRequirementLabels: Record<SetupRequirementId, string> = {
  'project-layout': 'Application target', 'release-settings': 'Release settings', 'version-source': 'Version source',
  'android-identity': 'Android Application ID', 'android-module': 'Android app module', 'android-variant': 'Android variant',
  'android-tools': 'Android build tools', 'android-signing': 'Android upload key', 'android-store': 'Google Play identity',
  'android-testing': 'Play testing track', 'ios-identity': 'iOS Bundle ID', 'ios-container': 'Xcode project or workspace',
  'ios-scheme': 'Xcode shared scheme', 'ios-configuration': 'Xcode configuration', 'ios-tools': 'Xcode tools',
  'ios-signing': 'Apple signing inputs', 'ios-store': 'App Store identity', 'ios-testing': 'TestFlight delivery',
  'store-metadata': 'Store text and images', 'github-automation': 'GitHub automation',
};
