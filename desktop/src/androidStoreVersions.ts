// Current Play inventory DATA, not credential, cleanup or reservation authority.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { iosVersionsLimitations } from './iosStoreVersions.ts';

export const ANDROID_VERSIONS_QUERY = 'android-current-versions' as const;
export const ANDROID_VERSIONS_CONSENT = 'local-android-current-versions-edit-v1' as const;
export const ANDROID_VERSIONS_SCOPE = 'local-android-current-version-inventory' as const;
export const ANDROID_VERSIONS_COVERAGE = 'play-android-current-inventory/1' as const;
export const androidVersionsLimitations = [...iosVersionsLimitations, 'temporary-play-edit', 'may-invalidate-another-play-edit'] as const;
export type AndroidVersionObservation = 'observed' | 'not-checked' | 'not-permitted' | 'inconclusive' | 'too-many' | 'unsupported-format' | 'temporary-edit-unconfirmed';
export interface AndroidCurrentVersions {
  observation: AndroidVersionObservation; coverage: typeof ANDROID_VERSIONS_COVERAGE; revision: string | null;
  counts: { tracks: number; releases: number; versionCodes: number; bundles: number; apks: number } | null;
  maxBuild: number | null; marketingVersion: null; temporaryEdit: 'not-started' | 'deleted' | 'unconfirmed';
  historicalUniqueness: 'not-established';
}
const observations = ['observed', 'not-checked', 'not-permitted', 'inconclusive', 'too-many', 'unsupported-format', 'temporary-edit-unconfirmed'];
function record(value: unknown, fields: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
function integer(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;
}
export function parseAndroidCurrentVersions(input: unknown): AndroidCurrentVersions | null {
  try {
    const value = copyBoundedComparisonData(input, 2048, 64);
    if (!record(value, ['observation', 'coverage', 'revision', 'counts', 'maxBuild', 'marketingVersion', 'temporaryEdit', 'historicalUniqueness'])
      || typeof value.observation !== 'string' || !observations.includes(value.observation)
      || value.coverage !== ANDROID_VERSIONS_COVERAGE || value.historicalUniqueness !== 'not-established' || value.marketingVersion !== null
      || !['not-started', 'deleted', 'unconfirmed'].includes(value.temporaryEdit as string)) return null;
    if (value.observation !== 'observed') return ['revision', 'counts', 'maxBuild'].every(key => value[key] === null)
      && ((value.observation === 'temporary-edit-unconfirmed') === (value.temporaryEdit === 'unconfirmed'))
      ? value as unknown as AndroidCurrentVersions : null;
    const counts = value.counts;
    if (value.temporaryEdit !== 'deleted' || !record(counts, ['tracks', 'releases', 'versionCodes', 'bundles', 'apks'])
      || !['tracks', 'releases', 'bundles', 'apks'].every(key => integer(counts[key], 400)) || !integer(counts.versionCodes, 4000)
      || typeof value.revision !== 'string' || !/^[a-f0-9]{64}(?![\s\S])/.test(value.revision)
      || !integer(value.maxBuild, 2_100_000_000)
      || ((counts.versionCodes === 0 && counts.bundles === 0 && counts.apks === 0) !== (value.maxBuild === 0))) return null;
    return value as unknown as AndroidCurrentVersions;
  } catch { return null; }
}

export const androidVersionDescriptions: Record<AndroidVersionObservation, { title: string; detail: string }> = {
  observed: { title: 'Current Play version codes checked', detail: 'The current APKs, bundles and all returned tracks were read, then that exact temporary edit was deleted. This is not a complete history or a guarantee that another uploader will not use a number.' },
  'not-checked': { title: 'Play versions were not checked', detail: 'Check the saved application ID, assigned service-account file and bundled Store tools. No empty inventory or unused number was assumed.' },
  'not-permitted': { title: 'Google did not allow this inventory read', detail: 'Review the assigned account’s app permissions and account requirements. Permission failure is not evidence that the app has no uploads.' },
  inconclusive: { title: 'Play inventory could not be established', detail: 'The fixed current inventories were incomplete, changed or unsupported. No version number was reserved.' },
  'too-many': { title: 'This app exceeds the current check’s limits', detail: 'Up to 400 tracks, bundles and APKs, 400 releases and 4,000 code references are supported. A partial list is never used. Keep manual versioning and review Play Console.' },
  'unsupported-format': { title: 'Some Play version codes need manual review', detail: 'Automatic Android versions require whole-number codes from 1 to 2,100,000,000. Track release names are labels, not a marketing-version floor.' },
  'temporary-edit-unconfirmed': { title: 'Temporary Play edit cleanup is unconfirmed', detail: 'A request or its delete response was lost or failed. An uncommitted edit may remain until Google expires it. Inspect Play Console before another explicit check; this result cannot supply a version floor.' },
};
