// One paired observation DATA shape; never two independent native receipts.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseAndroidCurrentVersions, type AndroidCurrentVersions } from './androidStoreVersions.ts';
import { parseIOSCurrentVersions, type IOSCurrentVersions } from './iosStoreVersions.ts';
import type { AssetScope, CredentialAssessment } from './assetSessionTypes.ts';

export const PAIRED_VERSIONS_QUERY = 'paired-current-versions' as const;
export const PAIRED_VERSIONS_CONSENT = 'local-paired-current-versions-edit-v1' as const;
export const PAIRED_VERSIONS_SCOPE = 'local-shared-current-version-inventory' as const;
export interface PairedCurrentVersions { android: AndroidCurrentVersions; ios: IOSCurrentVersions }
export function parsePairedCurrentVersions(input: unknown): PairedCurrentVersions | null {
  try {
    const value = copyBoundedComparisonData(input, 4096, 160);
    if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 2
      || !('android' in value) || !('ios' in value) || !Object.hasOwn(value, 'android') || !Object.hasOwn(value, 'ios')) return null;
    const android = parseAndroidCurrentVersions(value.android), ios = parseIOSCurrentVersions(value.ios);
    return android && ios ? { android, ios } : null;
  } catch { return null; }
}
export function pairedVersionsObserved(input: unknown): boolean {
  const pair = parsePairedCurrentVersions(input);
  return pair?.android.observation === 'observed' && pair.ios.observation === 'observed';
}
export function pairedVersionScope(scope: AssetScope): boolean {
  return scope.platform === 'both' && scope.stage === 'candidate'
    && scope.purpose === 'version-inventory' && scope.executionMode === 'local';
}
// Core still assesses each exact key under its original single-platform Store
// purpose. Never relabel that result as a Both/core assessment or a Bind grant.
export function assessmentMatchesNative(assessment: CredentialAssessment, native: AssetScope): boolean {
  if (pairedVersionScope(native)) {
    const platform = assessment.kind === 'google-service-account' ? 'android' : assessment.kind === 'asc-p8' ? 'ios' : null;
    return platform !== null && assessment.context.platform === platform
      && assessment.context.purpose === 'store' && assessment.context.stage === 'candidate'
      && assessment.context.executionMode === 'local';
  }
  return assessment.context.platform === native.platform && assessment.context.purpose === native.purpose
    && assessment.context.stage === native.stage && (assessment.context.executionMode ?? 'github') === (native.executionMode ?? 'github');
}
