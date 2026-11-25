// Closed first-counter DATA and saved-input comparison only. The existing
// publication controller/Connection/Source/NativeUse remain all the owners.
import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId,
  connectionRepository as repository, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { githubPreflightBranch as branch } from './githubPreflightProtocol.ts';
import { parseAndroidBuildSavedVersion } from './androidBuildProtocol.ts';
import { localStoreProjectObservation } from './localStorePreflight.ts';
import type { ProjectSession } from './drafts.ts';
import type { ReleaseVersionState } from './releaseVersion.ts';
export const COUNTER_PURPOSE = 'version-counter' as const;
export const COUNTER_PROTOCOL = 'mrk-version-counter-setup/1' as const;
export const COUNTER_BRANCH = 'mrk-version-allocations';
export const COUNTER_PATH = 'release/.mrk-version-allocations-v1.json';
export const COUNTER_CONFIRMATION = 'Create the FIRST shared version counter on the fixed NEW mrk-version-allocations branch? The initial version is saved project data, NOT a verified Store floor. Existing repository automation may run. No allocation, protection change, enrollment, reset or Store request is authorized. Known prior counters refuse; deleted history on another computer cannot be ruled out. Cancellation does not undo a sent request.';
export type PublicationPurpose = 'setup-pr' | typeof COUNTER_PURPOSE;
export interface CounterFingerprint { bytes: number; sha256: string }
export interface CounterInitialVersion { name: string; build: number }
export interface CounterTarget {
  purpose: typeof COUNTER_PURPOSE; projectBinding: string; repository: string; accountId: string; repositoryId: string;
  base: string; marker: string; projectId: string; ledgerId: string; initialVersion: CounterInitialVersion;
  savedConfig: CounterFingerprint; savedVersion: CounterFingerprint & { path: string };
}
export interface CounterPrepared {
  protocol: typeof COUNTER_PROTOCOL; target: CounterTarget; baseCommit: string; baseTree: string; desiredTree: string;
  ledgerBlob: string; genesisSha256: string; ledger: string; head: typeof COUNTER_BRANCH; confirmation: typeof COUNTER_CONFIRMATION;
}
export interface CounterSummary extends Omit<CounterPrepared, 'ledger' | 'head' | 'confirmation'> { ledger: CounterFingerprint }
export interface CounterObserved { commit: string; ledgerId: string; genesisSha256: string }
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && !/[^0-9a-f]/.test(v);
const utf8 = (v: string) => new TextEncoder().encode(v).byteLength;
const uuid = (v: unknown): v is string => typeof v === 'string' && v.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(v);
function fingerprint(v: unknown, max: number): v is CounterFingerprint {
  return keys(v, ['bytes', 'sha256']) && Number.isSafeInteger(v.bytes) && typeof v.bytes === 'number' && v.bytes > 0 && v.bytes <= max && hex(v.sha256, 64);
}
export function counterInitialVersion(v: unknown): v is CounterInitialVersion {
  // Secondary display policy, byte-for-byte the existing automatic numeric
  // Genesis grammar. Never normalizes a manual name or substitutes build zero.
  return bounded(v, 256, 16, 2) && keys(v, ['name', 'build']) && typeof v.name === 'string' && v.name.length <= 64 &&
    /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?$(?![\s\S])/.test(v.name) &&
    Number.isSafeInteger(v.build) && typeof v.build === 'number' && v.build >= 1 && v.build <= 2_100_000_000;
}
function versionSource(v: unknown, version: CounterInitialVersion): v is CounterTarget['savedVersion'] {
  return keys(v, ['path', 'bytes', 'sha256']) && parseAndroidBuildSavedVersion({ source: v.path, bytes: v.bytes, sha256: v.sha256,
    name: version.name, build: version.build }) !== null;
}
export function counterTarget(v: unknown): v is CounterTarget {
  return bounded(v, 8192, 128, 6) && keys(v, ['purpose', 'projectBinding', 'repository', 'accountId', 'repositoryId', 'base', 'marker', 'projectId', 'ledgerId', 'initialVersion', 'savedConfig', 'savedVersion']) &&
    v.purpose === COUNTER_PURPOSE && hex(v.projectBinding, 64) && repository(v.repository) && numericId(v.accountId) && numericId(v.repositoryId) &&
    branch(v.base) && v.base !== COUNTER_BRANCH && hex(v.marker, 32) && hex(v.projectId, 32) && /[1-9a-f]/.test(v.projectId) && uuid(v.ledgerId) &&
    counterInitialVersion(v.initialVersion) && fingerprint(v.savedConfig, 65536) && versionSource(v.savedVersion, v.initialVersion);
}
function common(v: Record<string, unknown>): boolean {
  return v.protocol === COUNTER_PROTOCOL && counterTarget(v.target) && hex(v.baseCommit, 40) && hex(v.baseTree, 40) &&
    hex(v.desiredTree, 40) && hex(v.ledgerBlob, 40) && hex(v.genesisSha256, 64);
}
function ledgerFor(t: CounterTarget): string {
  // Existing Ledger v1 canonical empty object shape, only for display
  // correlation. Core/native own its hash and actual remote readback.
  return JSON.stringify({ genesis: { branch: COUNTER_BRANCH, initialVersion: { build: t.initialVersion.build, name: t.initialVersion.name },
    ledgerId: t.ledgerId, path: COUNTER_PATH, projectId: t.projectId, repositoryId: t.repositoryId },
    protocol: 'mrk-version-allocation/1', reservations: [], schemaVersion: 1 }) + '\n';
}
export function counterPrepared(v: unknown): v is CounterPrepared {
  return bounded(v, 16384, 256, 8) && keys(v, ['protocol', 'target', 'baseCommit', 'baseTree', 'desiredTree', 'ledgerBlob', 'genesisSha256', 'ledger', 'head', 'confirmation']) &&
    common(v) && counterTarget(v.target) && v.head === COUNTER_BRANCH && v.confirmation === COUNTER_CONFIRMATION && typeof v.ledger === 'string' &&
    utf8(v.ledger) <= 8192 && v.ledger === ledgerFor(v.target) && bounded(v, 16384, 256, 8);
}
export function counterSummary(v: unknown): v is CounterSummary {
  return bounded(v, 16384, 256, 8) && keys(v, ['protocol', 'target', 'baseCommit', 'baseTree', 'desiredTree', 'ledgerBlob', 'genesisSha256', 'ledger']) && common(v) && fingerprint(v.ledger, 8192);
}
export function counterObserved(v: unknown): v is CounterObserved {
  return bounded(v, 512, 16, 2) && keys(v, ['commit', 'ledgerId', 'genesisSha256']) && hex(v.commit, 40) && uuid(v.ledgerId) && hex(v.genesisSha256, 64);
}
export function publicationPurpose(v: { protocol: string }): PublicationPurpose { return v.protocol === COUNTER_PROTOCOL ? COUNTER_PURPOSE : 'setup-pr'; }

// These are retained UI identities/comparisons, NEVER NativeState or release
// readiness. Reuse the existing platform-neutral saved-observation comparison;
// no Store controller/credential/request is constructed by this helper.
export interface CounterSavedWitness {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  draft: object; baseline: object; snapshot: object; result: object; resultBinding: object;
  readEpoch: number; connectionGeneration: number; selectionGeneration: number;
  initialVersion: CounterInitialVersion; savedConfig: CounterFingerprint; savedVersion: CounterTarget['savedVersion'];
}
export function captureCounterSaved(session: ProjectSession | null, version: ReleaseVersionState | null): CounterSavedWitness | null {
  if (!session || !version || !session.draft || !session.baseline || !session.snapshot || !version.result || !version.resultBinding ||
      session.sourceChanged || session.saveRecoveryRequired || session.saveRecoveryNeedsReload || session.recoveryReloadRequest !== null) return null;
  const p = localStoreProjectObservation(session, version);
  if (p.inputIssue || p.dirtyDraft || p.snapshotPending || p.versionPending || p.saveRecoveryRequired || !p.savedConfig || !p.savedVersion ||
      p.savedConfig.bytes > 65536) return null;
  const initialVersion = { name: p.savedVersion.name, build: p.savedVersion.build };
  if (!counterInitialVersion(initialVersion)) return null;
  return { projectId: p.projectId, draftRevision: p.draftRevision, baselineGeneration: p.baselineGeneration, observationGeneration: p.observationGeneration,
    draft: session.draft, baseline: session.baseline, snapshot: session.snapshot, result: version.result, resultBinding: version.resultBinding,
    readEpoch: version.readEpoch, connectionGeneration: version.connectionGeneration, selectionGeneration: version.selectionGeneration,
    initialVersion, savedConfig: { ...p.savedConfig }, savedVersion: { path: p.savedVersion.source, bytes: p.savedVersion.bytes, sha256: p.savedVersion.sha256 } };
}
export function sameCounterSaved(a: CounterSavedWitness | null, b: CounterSavedWitness | null): boolean {
  if (!a || !b) return a === b;
  const refs = ['draft', 'baseline', 'snapshot', 'result', 'resultBinding'] as const;
  const scalars = ['projectId', 'draftRevision', 'baselineGeneration', 'observationGeneration', 'readEpoch', 'connectionGeneration', 'selectionGeneration'] as const;
  return refs.every((k) => a[k] === b[k]) && scalars.every((k) => a[k] === b[k]) && same(a.initialVersion, b.initialVersion) &&
    same(a.savedConfig, b.savedConfig) && same(a.savedVersion, b.savedVersion);
}
export function counterSourceMatches(review: CounterPrepared | CounterSummary, source: CounterSavedWitness): boolean {
  return same(review.target.initialVersion, source.initialVersion) && same(review.target.savedConfig, source.savedConfig) && same(review.target.savedVersion, source.savedVersion);
}
