// Only closed display/request DATA. No verifier, network, clock lease or native authority.
import { connectionBounded as bounded, connectionKeys as keys, connectionOpaqueId as id,
  connectionNumericId as numericId, sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubHistoryContext, GitHubHistoryError, GitHubHistoryReason, GitHubHistoryResult,
  GitHubHistorySelection, GitHubHistoryStatus } from './githubHistoryTypes.ts';
export const GITHUB_HISTORY_EVENT = 'github-history-status';
export const GITHUB_HISTORY_ASSURANCE = 'authenticated-retained-workflow-evidence-not-current-store-state';
export const GITHUB_HISTORY_STAGES = ['candidate', 'external-testing', 'production-submit'] as const;
export const GITHUB_HISTORY_PLATFORMS = ['android', 'ios'] as const;
export const GITHUB_HISTORY_REASONS = ['none', 'unqualified', 'not-connected', 'busy', 'invalid-input', 'target-changed',
  'config-invalid', 'platform-disabled', 'publisher-unconfigured', 'unsupported-tooling', 'provider-unavailable',
  'provider-mismatch', 'runtime-unavailable', 'resources-unavailable', 'unauthorized', 'forbidden', 'not-found-or-inaccessible',
  'rate-limited', 'network-unavailable', 'tls-failed', 'response-invalid', 'response-limit', 'artifact-missing', 'artifact-expired',
  'evidence-invalid', 'attestation-not-confirmed', 'producer-pending', 'cancelled', 'expired', 'cleanup-unknown'] as const;
export const GITHUB_HISTORY_REASON_HELP: Readonly<Record<GitHubHistoryReason, string>> = Object.freeze({
  none: 'The last local observation is available. It is not current Store state or permission to promote.',
  unqualified: 'Authenticated history is not qualified for this installed application. No alternate verifier is used.',
  'not-connected': 'Connect the selected project’s repository using the existing GitHub connection first.',
  busy: 'An original operation is still running or retiring. Read local Status or cancel that exact local read.',
  'invalid-input': 'Enter an exact numeric run ID, attempt, release stage and platform. No latest run is guessed.',
  'target-changed': 'The project, saved settings, selection or original account/repository changed. The old result is not current.',
  'config-invalid': 'Review and save valid project settings, then refresh the saved observation. No implicit save is performed.',
  'platform-disabled': 'The selected platform is not enabled in the actual saved project configuration.',
  'publisher-unconfigured': 'This application lacks its publisher-reviewed immutable toolkit binding. A user-entered pin cannot replace it.',
  'unsupported-tooling': 'The retained workflow uses an unsupported toolkit binding. No compatible proof was assumed.',
  'provider-unavailable': 'The required bounded attestation provider is unavailable. No stock tool or browser fallback is used.',
  'provider-mismatch': 'The actual provider did not match the required identity. Do not bypass its verification.',
  'runtime-unavailable': 'The installed native runtime is unavailable. Preview cannot read authenticated history.',
  'resources-unavailable': 'The fixed resource budget could not be admitted. Nothing was treated as a partial successful history.',
  unauthorized: 'GitHub refused authentication. Retire this original before explicitly reconnecting.',
  forbidden: 'GitHub refused access. Review the selected repository’s read permissions and organization/SSO requirements; permissions are never increased automatically.',
  'not-found-or-inaccessible': 'The requested object was absent or inaccessible. This does not establish absence.',
  'rate-limited': 'GitHub limited the read. Native cooldown remains authoritative; there is no automatic retry.',
  'network-unavailable': 'The bounded network read did not complete. It did not mutate GitHub or the Store.',
  'tls-failed': 'TLS verification failed. Do not disable certificate or trust checks.',
  'response-invalid': 'The response failed the closed protocol. No successful observation was inferred.',
  'response-limit': 'A finite response or resource limit was reached. Truncated evidence is not accepted.',
  'artifact-missing': 'The exact retained evidence artifact was not available. Missing evidence is not proof that no release happened.',
  'artifact-expired': 'The selected artifact is expired. This observation cannot replace the missing evidence.',
  'evidence-invalid': 'The retained evidence did not satisfy the required consistency checks. It was not accepted.',
  'attestation-not-confirmed': 'The required attestation was not confirmed. This is not an accusation of a forged signature.',
  'producer-pending': 'The exact evidence producer has not reached the required final state. No pending producer is a pass.',
  cancelled: 'Local cancellation was requested. Original cleanup must still settle; no remote workflow is cancelled.',
  expired: 'The original session or read deadline expired. Reading Status does not extend it.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the original Status; no new read is enabled by a late response.',
});
const UNAVAILABLE = ['unqualified', 'publisher-unconfigured', 'unsupported-tooling', 'provider-unavailable', 'runtime-unavailable',
  'resources-unavailable', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'rate-limited', 'network-unavailable',
  'tls-failed', 'artifact-missing', 'artifact-expired', 'producer-pending'];
const REFUSED = ['invalid-input', 'target-changed', 'config-invalid', 'platform-disabled', 'provider-mismatch', 'response-invalid',
  'response-limit', 'evidence-invalid', 'attestation-not-confirmed'];
const OUTCOMES = ['mutated', 'reconciled', 'already-present', 'operator-authorized-reconciliation', 'operator-authorized-retry', 'operator-authorized-create-retry'];
function one(value: unknown, values: readonly string[]): value is string { return typeof value === 'string' && values.includes(value); }
function integer(value: unknown, minimum: number, maximum: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= minimum && value <= maximum;
}
function revision(value: unknown): value is number { return integer(value, 1, 4294967294); }
function hex(value: unknown, length: number): value is string { return typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value); }
// Match Python's codepoint bound; overall serialized UTF8 cap is checked separately.
function text(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum * 2 &&
    !/[\p{Cc}\p{Cs}]/u.test(value) && [...value].length <= maximum;
}
function coordinate(value: unknown): value is string { return text(value, 255) && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$(?![\s\S])/.test(value); }
function utc(value: unknown): value is string {
  if (!text(value, 32) || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$(?![\s\S])/.test(value) || value.startsWith('0000')) return false;
  const seconds = value.slice(0, 19), parsed = new Date(seconds + 'Z'); // DATA only; never samples a clock.
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === seconds + '.000Z';
}
export function githubHistorySelection(value: unknown): value is GitHubHistorySelection {
  try { return bounded(value, 512, 16, 2) && keys(value, ['runId', 'attempt', 'stage', 'platform']) && numericId(value.runId)
    && integer(value.attempt, 1, 100) && one(value.stage, GITHUB_HISTORY_STAGES) && one(value.platform, GITHUB_HISTORY_PLATFORMS); }
  catch { return false; }
}
function context(value: unknown): value is GitHubHistoryContext {
  return keys(value, ['schemaVersion', 'projectBinding', 'configSha256', 'repository', 'repositoryId', 'accountId',
    'toolingRepository', 'toolingSha', 'selection']) && value.schemaVersion === 1 && hex(value.projectBinding, 64) && hex(value.configSha256, 64)
    && coordinate(value.repository) && numericId(value.repositoryId) && numericId(value.accountId)
    && value.toolingRepository === 'Apdelrahman1911/mobile-release-kit' && hex(value.toolingSha, 40) && githubHistorySelection(value.selection);
}
function authority(value: unknown, c: GitHubHistoryContext): boolean {
  return keys(value, ['workflow', 'callerPath', 'reusableRepository', 'reusablePath', 'reusableCommit', 'runId', 'attempt', 'headSha', 'ref', 'event'])
    && text(value.workflow, 255) && value.callerPath === `.github/workflows/mobile-${c.selection.stage}.yml`
    && value.reusablePath === `.github/workflows/reusable-${c.selection.stage}.yml` && value.reusableRepository === c.toolingRepository
    && value.reusableCommit === c.toolingSha && numericId(value.runId) && integer(value.attempt, 1, 100) && hex(value.headSha, 40)
    && text(value.ref, 512) && value.ref.startsWith('refs/heads/') && value.ref.length > 11 && value.event === 'workflow_dispatch';
}
function source(value: unknown): boolean { return keys(value, ['commit', 'tree']) && hex(value.commit, 40) && hex(value.tree, 40); }
function evidence(value: unknown, c: GitHubHistoryContext): boolean {
  if (!keys(value, ['artifactId', 'artifactSha256', 'artifactName', 'producerJobId', 'producedBy', 'authorizedBy', 'candidateSource',
    'operationSource', 'version', 'applicationId', 'outcome', 'candidateManifestSha256', 'operationIntentSha256', 'receiptSha256', 'provenanceSha256'])
      || !keys(value.version, ['name', 'build']) || !text(value.version.name, 64)
      || !/^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?$(?![\s\S])/.test(value.version.name)
      || c.selection.platform === 'ios' && !/^[0-9]+(?:\.[0-9]+){1,2}$(?![\s\S])/.test(value.version.name)
      || !integer(value.version.build, 1, 2100000000) || !authority(value.producedBy, c) || !authority(value.authorizedBy, c)
      || !keys(value.producedBy, ['workflow', 'callerPath', 'reusableRepository', 'reusablePath', 'reusableCommit', 'runId', 'attempt', 'headSha', 'ref', 'event'])) return false;
  const stage = c.selection.stage === 'external-testing' ? 'external' : c.selection.stage === 'production-submit' ? 'production' : 'candidate';
  return numericId(value.artifactId) && numericId(value.producerJobId) && value.artifactName === `mobile-release-${stage}-evidence-${c.selection.platform}`
    && text(value.applicationId, 255) && source(value.candidateSource) && source(value.operationSource) && one(value.outcome, OUTCOMES)
    && value.producedBy.runId === c.selection.runId && value.producedBy.attempt === c.selection.attempt
    && ['artifactSha256', 'candidateManifestSha256', 'operationIntentSha256', 'receiptSha256', 'provenanceSha256'].every((key) => hex(value[key], 64));
}
export function parseGitHubHistoryResult(value: unknown): GitHubHistoryResult | null {
  try {
    if (!bounded(value, 16384, 4096, 16) || !keys(value, ['schemaVersion', 'context', 'observedAt', 'verification', 'reason', 'evidence', 'assurance'])
        || value.schemaVersion !== 1 || !context(value.context) || !utc(value.observedAt) || value.assurance !== GITHUB_HISTORY_ASSURANCE) return null;
    if (value.verification === 'verified') { if (value.reason !== 'none' || !evidence(value.evidence, value.context)) return null; }
    else if (!(value.verification === 'unavailable' && one(value.reason, UNAVAILABLE) || value.verification === 'refused' && one(value.reason, REFUSED)) || value.evidence !== null) return null;
    return JSON.parse(JSON.stringify(value)) as GitHubHistoryResult;
  } catch { return null; }
}
export function parseGitHubHistoryStatus(value: unknown): GitHubHistoryStatus | null {
  try {
    if (!bounded(value, 65536, 4096, 16) || !keys(value, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason', 'operation', 'result'])
        || value.schemaVersion !== 1 || !revision(value.revision) || !(value.sessionId === null || id(value.sessionId))
        || typeof value.available !== 'boolean' || !one(value.reason, GITHUB_HISTORY_REASONS) || value.available !== (value.reason === 'none')) return null;
    const op = value.operation;
    if (op !== null) {
      if (!keys(op, ['id', 'phase', 'reason', 'selection']) || !id(op.id) || value.sessionId === null || !githubHistorySelection(op.selection)
          || !one(op.phase, ['running', 'stopping', 'settled', 'cleanup-unknown']) || !one(op.reason, GITHUB_HISTORY_REASONS)) return null;
      if (op.phase !== 'settled') {
        const reasons = { running: 'none', stopping: 'cancelled', 'cleanup-unknown': 'cleanup-unknown' };
        if (op.reason !== reasons[op.phase as keyof typeof reasons] || value.available || value.result !== null
            || op.phase === 'cleanup-unknown' && value.reason !== 'cleanup-unknown') return null;
      } else if (op.reason === 'busy' || op.reason === 'cleanup-unknown') return null;
    }
    if (value.available && (value.sessionId === null || op !== null && op.phase !== 'settled')) return null;
    if (value.result !== null && (op === null || op.phase !== 'settled' || op.reason !== 'none'
        || !parseGitHubHistoryResult(value.result) || !keys(value.result, ['schemaVersion', 'context', 'observedAt', 'verification', 'reason', 'evidence', 'assurance'])
        || !context(value.result.context) || !same(value.result.context.selection, op.selection))) return null;
    return JSON.parse(JSON.stringify(value)) as GitHubHistoryStatus;
  } catch { return null; }
}
export type GitHubHistoryCommand = 'github_history_status' | 'github_history_start' | 'github_history_cancel';
export function githubHistoryRequestFits(command: GitHubHistoryCommand, value: unknown): value is Record<string, unknown> {
  try {
    if (!bounded(value, 4096, 64, 4)) return false;
    if (command === 'github_history_status') return keys(value, []);
    if (command === 'github_history_cancel') return keys(value, ['operationId']) && id(value.operationId);
    return command === 'github_history_start' && keys(value, ['sessionId', 'expectedRevision', 'expectedConnectionRevision', 'selection'])
      && id(value.sessionId) && revision(value.expectedRevision) && revision(value.expectedConnectionRevision) && githubHistorySelection(value.selection);
  } catch { return false; }
}
export function githubHistoryError(value: unknown): GitHubHistoryError {
  try {
    if (value !== null && typeof value === 'object') {
      const field = Object.getOwnPropertyDescriptor(value, 'code');
      const code: unknown = field && Object.hasOwn(field, 'value') ? field.value : null;
      const reason = GITHUB_HISTORY_REASONS.find((r) => r !== 'none' && code === `github_history_refused_${r.replaceAll('-', '_')}`);
      if (reason) return { code: String(code), reason, admission: 'not-admitted', message: GITHUB_HISTORY_REASON_HELP[reason] };
    }
  } catch { /* Never render raw error data or invoke its accessors. */ }
  return { code: 'github_history_unknown', reason: 'response-invalid', admission: 'unknown',
    message: 'No conclusive acknowledgement was received. Read the original local Status; do not repeat an uncertain read.' };
}
