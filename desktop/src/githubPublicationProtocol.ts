import { COUNTER_BRANCH, COUNTER_PURPOSE, counterPrepared, counterSummary, counterObserved, publicationPurpose } from './versionCounterSetup.ts';
import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId, connectionOpaqueId as opaqueId,
  connectionRepository as repository, connectionRevision as revision, connectionUtc as utc } from './githubConnectionProtocol.ts';
import { githubPreflightBranch as branch } from './githubPreflightProtocol.ts';
import type { PublicationPrepared, PublicationPending, PublicationReason, PublicationStatus, PublicationTarget } from './githubPublicationTypes.ts';
export const PUBLICATION_EVENT = 'github-setup-publication-status';
export const PUBLICATION_PROTOCOL = 'mrk-github-setup-publication/1';
export const PUBLICATION_PATHS = ['release/mobile-release.json', '.github/workflows/mobile-preflight.yml', '.github/workflows/mobile-candidate.yml', '.github/workflows/mobile-external-testing.yml', '.github/workflows/mobile-production-submit.yml'] as const;
export const PUBLICATION_CONFIRMATION = "Create this five-file setup commit on a NEW branch and open a draft pull request? Only release/mobile-release.json and four canonical workflow callers are included. Version, metadata and application source changes are NOT uploaded. Local Git/index/HEAD are unchanged. Push and pull-request events can start the repository's existing CI. No merge, existing-branch update, workflow dispatch or release is requested. Cancellation does not undo a sent request.";
export const PUBLICATION_REASONS = ['none', 'target-changed', 'source-changed', 'caller-mismatch', 'source-unsupported', 'configuration-invalid', 'response-invalid', 'response-limit', 'no-change', 'branch-exists', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'rate-limited', 'network-unavailable', 'tls-failed', 'expired', 'cancelled', 'journal-unavailable', 'unresolved', 'ambiguous', 'configuration-changed', 'resources-unavailable', 'runtime-unavailable', 'unqualified', 'publisher-unconfigured', 'not-connected', 'busy', 'invalid-input', 'cleanup-unknown', 'consent-expired', 'saved-inputs-required', 'counter-exists', 'counter-intent-exists', 'counter-state-unavailable', 'counter-state-changed', 'counter-known-authority', 'counter-version-unsupported'] as const;
export const PUBLICATION_HELP: Readonly<Record<PublicationReason, string>> = Object.freeze({
  none: 'No remote action is started automatically. Prepare reads the saved configuration and selected GitHub base; Publish needs a separate exact review.',
  'target-changed': 'The original project, account, repository or base changed. The old review cannot authorize a new target.',
  'source-changed': 'The saved bytes or remote base changed after review. Nothing is silently substituted; prepare again only after the original settles.',
  'caller-mismatch': 'An existing workflow caller is customized or unsupported. It was not overwritten. Review it in GitHub and choose a supported base.',
  'source-unsupported': 'The exact five-file source has unsupported modes, sizes or structure. No other project files are uploaded.',
  'configuration-invalid': 'Save a valid project release/mobile-release.json first. Unsaved drafts are not uploaded.',
  'response-invalid': 'The acknowledgement is incomplete or invalid. Read local Status; never repeat an uncertain Publish.',
  'response-limit': 'The bounded remote response cannot be completely checked. No partial view is treated as complete.',
  'no-change': 'The selected base already contains these exact five files. No branch or pull request was created.',
  'branch-exists': 'The new branch already exists. It is not updated or force-pushed; inspect the durable original intent.',
  unauthorized: 'The GitHub credential was refused. Settle the original before reconnecting.', forbidden: 'GitHub denied this action. Check Contents, Workflows and Pull requests write permissions and repository policy.',
  'not-found-or-inaccessible': 'The exact remote object was not found or is not accessible to this account.',
  'rate-limited': 'GitHub requested a pause. The original session retains its cooldown; no automatic retry is sent.',
  'network-unavailable': 'The remote result is unavailable. A sent request may have applied; use the original read-only reconciliation.',
  'tls-failed': 'The authenticated GitHub connection failed. No alternate endpoint or insecure transport is used.',
  expired: 'The original operation or credential expired. Read retained Status and pending intents before starting new work.',
  cancelled: 'Cancellation stops remaining work but cannot undo a request already sent. Inspect the original intent.',
  'journal-unavailable': 'The owned local publication journal could not be read or settled. No replacement journal or write retry is used.',
  unresolved: 'The original effect remains unresolved. Reconciliation is read-only and never repeats a write.',
  ambiguous: 'Remote observations do not uniquely identify the original draft pull request. Nothing was adopted.',
  'configuration-changed': 'The original saved configuration or its held file changed. The old review is retired.',
  'resources-unavailable': 'The original source or journal could not be safely retained. No alternate path is accepted.',
  'runtime-unavailable': 'This installed runtime cannot execute the publication helper. Browser preview never publishes.',
  unqualified: 'The installed runtime has not admitted this capability.',
  'publisher-unconfigured': 'This build has no configured toolkit commit for the canonical callers; publication is unavailable.',
  'not-connected': 'Connect the selected project repository and observe its account and repository identity first.',
  busy: 'An original operation is still running or retiring. Status and Stop original remain available.',
  'invalid-input': 'Choose a valid existing base branch and the current original review; arbitrary files, credentials and endpoints are not accepted.',
  'cleanup-unknown': 'The original process or resource cleanup is unknown. Do not start another operation or replay Publish.',
  'saved-inputs-required': 'Read the current saved configuration and version first. Neither drafts nor an earlier observation can create a counter.',
  'counter-exists': 'The fixed counter branch already exists. Use the existing protection and enrollment review; never reset or create a replacement counter.',
  'counter-intent-exists': 'An original counter-creation intent already exists for this repository or project. Read its retained status and reconcile; another marker cannot repeat creation.',
  'counter-state-unavailable': 'The original local version state could not be completely read or retired. Missing or unreadable state is not proof of first use.',
  'counter-state-changed': 'The original saved inputs or local version authority changed after review. The old counter consent cannot be reused.',
  'counter-known-authority': 'This computer already knows a counter or allocation for this repository/project. Do not reset it, even if the remote branch was deleted.',
  'counter-version-unsupported': 'The saved name must use the existing numeric automatic-version format. Keep manual versions otherwise. For a published app reconcile real Store history/floors; do not substitute zero.',
  'consent-expired': 'The one-use review expired or was retired. It cannot be reused.'
});
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && !/[^0-9a-f]/.test(v);
const oneOf = (v: unknown, values: readonly string[]): v is string => typeof v === 'string' && values.includes(v);
const rev = (v: unknown) => revision(v) && v < 0xffff_ffff;
const steps = ['tree', 'commit', 'branch', 'pull'] as const;
function target(v: unknown): v is PublicationTarget {
  return keys(v, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'base', 'toolingRepository', 'toolingSha', 'marker']) &&
    hex(v.projectBinding, 64) && repository(v.repository) && numericId(v.accountId) && numericId(v.repositoryId) && branch(v.base) &&
    v.toolingRepository === 'Apdelrahman1911/mobile-release-kit' && hex(v.toolingSha, 40) && hex(v.marker, 32);
}
const text = (v: unknown, limit: number): v is string => typeof v === 'string' && v.length > 0 && new TextEncoder().encode(v).byteLength <= limit;
function common(v: Record<string, unknown>): boolean { return v.protocol === PUBLICATION_PROTOCOL && target(v.target) && hex(v.baseCommit, 40) && hex(v.baseTree, 40) && hex(v.desiredTree, 40) && v.baseTree !== v.desiredTree; }
function prepared(v: unknown): v is PublicationPrepared {
  return keys(v, ['protocol', 'target', 'baseCommit', 'baseTree', 'desiredTree', 'files', 'head', 'confirmation']) && common(v) && target(v.target) &&
    v.head === `mrk/setup-${v.target.marker}` && v.confirmation === PUBLICATION_CONFIRMATION && Array.isArray(v.files) && v.files.length === 5 &&
    v.files.every((f, i) => keys(f, ['path', 'before', 'after']) && f.path === PUBLICATION_PATHS[i] && text(f.after, i ? 16384 : 65536) && (f.before === null || text(f.before, i ? 16384 : 65536))) && bounded(v, 384 * 1024, 256, 8);
}
function fingerprint(v: unknown, limit: number): boolean { return keys(v, ['bytes', 'sha256']) && typeof v.bytes === 'number' && Number.isInteger(v.bytes) && v.bytes > 0 && v.bytes <= limit && hex(v.sha256, 64); }
function pending(v: unknown): v is PublicationPending {
  if (!keys(v, ['summary', 'claimed', 'confirmed'])) return false;
  const counter = counterSummary(v.summary);
  if (!counter && (!keys(v.summary, ['protocol', 'target', 'baseCommit', 'baseTree', 'desiredTree', 'files']) || !common(v.summary) ||
      !Array.isArray(v.summary.files) || v.summary.files.length !== 5 || !v.summary.files.every((f, i) => keys(f, ['path', 'before', 'after']) && f.path === PUBLICATION_PATHS[i] && fingerprint(f.after, i ? 16384 : 65536) && (f.before === null || fingerprint(f.before, i ? 16384 : 65536))))) return false;
  if (!Array.isArray(v.claimed) || v.claimed.length > (counter ? 3 : 4) || !v.claimed.every((s, i) => s === steps[i])) return false;
  const n = v.confirmed && typeof v.confirmed === 'object' ? Object.keys(v.confirmed).length : -1;
  if (n < 0 || n > v.claimed.length || n + 1 < v.claimed.length || !keys(v.confirmed, steps.slice(0, n))) return false;
  const c = v.confirmed, summary = v.summary as PublicationPending['summary'];
  return steps.slice(0, n).every((s) => s === 'pull' ? numericId(c[s]) : hex(c[s], 40)) &&
    (c.tree === undefined || c.tree === summary.desiredTree) && (c.branch === undefined || c.branch === c.commit);
}
export function parsePublicationStatus(value: unknown): PublicationStatus | null {
  try {
    if (!bounded(value, 512 * 1024, 16384, 12) || !keys(value, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason', 'operation', 'consent', 'pending', 'pull', ...(Object.hasOwn((value ?? {}) as object, 'counter') ? ['counter'] : [])]) ||
        value.schemaVersion !== 1 || !rev(value.revision) || value.sessionId !== null && !opaqueId(value.sessionId) || typeof value.available !== 'boolean' || !oneOf(value.reason, PUBLICATION_REASONS) ||
        !Array.isArray(value.pending) || value.pending.length > 64 || !value.pending.every(pending) || new Set(value.pending.map((p) => p.summary.target.marker)).size !== value.pending.length) return null;
    const op = value.operation;
    if (op !== null && (!keys(op, ['id', 'kind', 'phase', 'reason', 'effect', ...(Object.hasOwn(op as object, 'purpose') ? ['purpose'] : [])]) || Object.hasOwn(op, 'purpose') && op.purpose !== COUNTER_PURPOSE || !opaqueId(op.id) || !oneOf(op.kind, ['prepare', 'publish', 'pending', 'reconcile']) || !oneOf(op.phase, ['running', 'stopping', 'settled', 'cleanup-unknown']) ||
        !oneOf(op.reason, PUBLICATION_REASONS) || !oneOf(op.effect, ['none', 'not-sent', 'potentially-applied', 'draft-pr-observed', 'unresolved', 'branch-observed', 'counter-observed']) ||
        (op.kind === 'prepare' || op.kind === 'pending') && op.effect !== 'none' || op.kind === 'publish' && op.effect === 'none')) return null;
    if (value.consent !== null && (!keys(value.consent, ['id', 'expiresAt', 'prepared']) || !hex(value.consent.id, 32) || !utc(value.consent.expiresAt) || !(prepared(value.consent.prepared) || counterPrepared(value.consent.prepared)) ||
        !value.sessionId || !op || publicationPurpose(value.consent.prepared) !== (op.purpose ?? 'setup-pr') || op.kind !== 'prepare' || op.phase !== 'settled' || op.reason !== 'none')) return null;
    if (value.pull !== null) {
      if (!keys(value.pull, ['number', 'url', 'commit']) || !numericId(value.pull.number) || !hex(value.pull.commit, 40) || typeof value.pull.url !== 'string' ||
          !/^https:\/\/github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/pull\/[1-9][0-9]*$(?![\s\S])/.test(value.pull.url) || !value.pull.url.endsWith(`/pull/${value.pull.number}`)) return null;
    }
    const hasCounter = Object.hasOwn(value, 'counter');
    if (hasCounter && !counterObserved(value.counter)) return null;
    if (op?.purpose === COUNTER_PURPOSE && (op.kind === 'pending' || ['draft-pr-observed', 'branch-observed'].includes(String(op.effect)) || value.pull !== null)) return null;
    if (op?.effect === 'counter-observed' && (op.purpose !== COUNTER_PURPOSE || op.phase !== 'settled' || op.reason !== 'none' ||
        op.kind !== 'publish' && op.kind !== 'reconcile' || !hasCounter || value.pull !== null)) return null;
    if (hasCounter && (!op || op.effect !== 'counter-observed')) return null;
    if (op?.effect === 'draft-pr-observed' && (op.phase !== 'settled' || op.reason !== 'none' || op.kind !== 'publish' && op.kind !== 'reconcile' || value.pull === null)) return null;
    if (op?.effect === 'branch-observed' && (op.phase !== 'settled' || op.reason === 'none' || op.kind !== 'reconcile' || value.pull !== null)) return null;
    if (value.pull !== null && (!op || op.effect !== 'draft-pr-observed')) return null;
    if (value.available && (!value.sessionId || value.reason !== 'none' || op && op.phase !== 'settled') || value.reason === 'cleanup-unknown' && value.available) return null;
    return value as unknown as PublicationStatus;
  } catch { return null; }
}
export type PublicationCommand = `github_setup_publication_${'status' | 'prepare' | 'publish' | 'pending' | 'reconcile' | 'discard' | 'cancel'}`;
export function publicationRequestFits(command: PublicationCommand, value: unknown): value is Record<string, unknown> {
  if (!bounded(value, 4096, 64, 4)) return false;
  switch (command) {
    case 'github_setup_publication_status': return keys(value, []);
    case 'github_setup_publication_cancel': return keys(value, ['operationId']) && opaqueId(value.operationId);
    case 'github_setup_publication_prepare': return keys(value, ['sessionId', 'expectedRevision', 'expectedConnectionRevision', 'base', ...(Object.hasOwn((value ?? {}) as object, 'purpose') ? ['purpose'] : [])]) && (!Object.hasOwn(value, 'purpose') || value.purpose === COUNTER_PURPOSE && value.base !== COUNTER_BRANCH) && opaqueId(value.sessionId) && rev(value.expectedRevision) && rev(value.expectedConnectionRevision) && branch(value.base);
    case 'github_setup_publication_pending': return keys(value, ['sessionId', 'expectedRevision', 'expectedConnectionRevision']) && opaqueId(value.sessionId) && rev(value.expectedRevision) && rev(value.expectedConnectionRevision);
    case 'github_setup_publication_publish': return keys(value, ['sessionId', 'expectedRevision', 'consentId', 'confirm']) && opaqueId(value.sessionId) && rev(value.expectedRevision) && hex(value.consentId, 32) && value.confirm === true;
    case 'github_setup_publication_discard': return keys(value, ['sessionId', 'expectedRevision', 'consentId']) && opaqueId(value.sessionId) && rev(value.expectedRevision) && hex(value.consentId, 32);
    case 'github_setup_publication_reconcile': return keys(value, ['sessionId', 'expectedRevision', 'marker']) && opaqueId(value.sessionId) && rev(value.expectedRevision) && hex(value.marker, 32);
    default: return false;
  }
}
export function publicationError(error: unknown): { code: string; reason: PublicationReason; admission: 'not-admitted' | 'unknown'; message: string } {
  try {
    const field = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const code = field && Object.hasOwn(field, 'value') ? field.value : null;
    if (typeof code === 'string') {
      const reason = PUBLICATION_REASONS.find((r) => r !== 'none' && code === `github_setup_publication_refused_${r.replaceAll('-', '_')}`);
      if (reason) return { code, reason, admission: 'not-admitted', message: PUBLICATION_HELP[reason] };
    }
  } catch { /* Never render error getters, raw remote data or credentials. */ }
  return { code: 'github_setup_publication_unknown', reason: 'response-invalid', admission: 'unknown', message: PUBLICATION_HELP['response-invalid'] };
}
