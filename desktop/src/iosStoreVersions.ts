// Current-visible Store DATA, not a native observation/assignment or reservation.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
export const IOS_VERSIONS_QUERY = 'ios-current-versions' as const;
export const IOS_VERSIONS_CONSENT = 'local-ios-current-versions-read-v1' as const;
export const IOS_VERSIONS_SCOPE = 'local-ios-current-version-inventory' as const;
export const IOS_VERSIONS_COVERAGE = 'asc-ios-current-inventory/1' as const;
export const iosVersionsLimitations = ['non-publishing', 'no-project-commands', 'no-build-or-signing', 'no-release-readiness',
  'point-in-time-account-access', 'saved-inputs-not-atomic', 'current-visible-only', 'not-atomic-store-snapshot',
  'historical-uniqueness-not-established', 'external-uploaders-not-coordinated'] as const;
export type IOSVersionObservation = 'observed' | 'not-checked' | 'not-permitted' | 'inconclusive' | 'too-many' | 'unsupported-format';
export interface IOSCurrentVersions {
  observation: IOSVersionObservation; coverage: typeof IOS_VERSIONS_COVERAGE; revision: string | null;
  counts: { builds: number; buildUploads: number; appStoreVersions: number } | null;
  maxBuild: number | null; marketingVersion: string | null; historicalUniqueness: 'not-established';
}
const observations = ['observed', 'not-checked', 'not-permitted', 'inconclusive', 'too-many', 'unsupported-format'];
function record(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
function integer(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;
}
export function parseIOSCurrentVersions(input: unknown): IOSCurrentVersions | null {
  try {
    const value = copyBoundedComparisonData(input, 2048, 64);
    if (!record(value, ['observation', 'coverage', 'revision', 'counts', 'maxBuild', 'marketingVersion', 'historicalUniqueness'])
      || typeof value.observation !== 'string' || !observations.includes(value.observation)
      || value.coverage !== IOS_VERSIONS_COVERAGE || value.historicalUniqueness !== 'not-established') return null;
    if (value.observation !== 'observed') return ['revision', 'counts', 'maxBuild', 'marketingVersion'].every(key => value[key] === null)
      ? value as unknown as IOSCurrentVersions : null;
    const counts = value.counts;
    if (!record(counts, ['builds', 'buildUploads', 'appStoreVersions']) || !Object.values(counts).every(n => integer(n, 400))
      || typeof value.revision !== 'string' || !/^[a-f0-9]{64}(?![\s\S])/.test(value.revision)
      || !integer(value.maxBuild, 2_100_000_000)
      || value.marketingVersion !== null && (typeof value.marketingVersion !== 'string' || value.marketingVersion.length > 64
        || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?(?![\s\S])/.test(value.marketingVersion))
      || ((counts.builds === 0 && counts.buildUploads === 0) !== (value.maxBuild === 0))
      || ((counts.builds === 0 && counts.buildUploads === 0 && counts.appStoreVersions === 0) !== (value.marketingVersion === null))) return null;
    return value as unknown as IOSCurrentVersions;
  } catch { return null; }
}
export const iosVersionDescriptions: Record<IOSVersionObservation, { title: string; detail: string }> = {
  observed: { title: 'Current Store versions checked', detail: 'All pages within this check’s limits were read for the saved iOS app. These are currently visible records, not a complete history of every number ever used.' },
  'not-checked': { title: 'Store versions were not checked', detail: 'Check the saved numeric App Store app ID, bundle ID, selected API key and bundled Store tools. No number was assumed available.' },
  'not-permitted': { title: 'Apple did not allow this read', detail: 'Review the selected key’s app access and account agreements. A permission failure does not mean this app has no builds.' },
  inconclusive: { title: 'Store version check was incomplete', detail: 'An unconfirmed response, missing app relationship or changed page count prevented a reliable current inventory. Nothing was reserved or changed.' },
  'too-many': { title: 'This app exceeds the current check’s limits', detail: 'This check supports up to 400 records in each of three collections. It does not use a partial list. Keep manual versioning and review App Store Connect.' },
  'unsupported-format': { title: 'Some Store version numbers need manual review', detail: 'The current automatic policy supports integer build numbers and numeric two- or three-part versions. It does not convert dotted, suffixed or other unsupported numbers.' },
};
