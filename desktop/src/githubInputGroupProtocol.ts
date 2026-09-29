// Closed public DATA only. No native gate, credential value or destination
// authority is granted by these presentation checks.
import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId,
  connectionOpaqueId as opaqueId, connectionRepository as repository, connectionRevision as revision,
  connectionUtc as utc, GITHUB_CONNECTION_REASONS, GITHUB_CONNECTION_REASON_HELP } from './githubConnectionProtocol.ts';
import { ASSET_KINDS, ASSET_PLATFORMS, ASSET_STAGES, ASSET_PURPOSES, SESSION_FIELDS, assetCounter, isAssetFileKind } from './assetSessionProtocol.ts';
import { githubPreflightBranch } from './githubPreflightProtocol.ts';
import type { AssetKind } from './assetSessionTypes.ts';
import type { GitHubInputGroupAssignment, GitHubInputGroupCommand, GitHubInputGroupError, GitHubInputGroupMetadata,
  GitHubInputGroupPrepared, GitHubInputGroupReason, GitHubInputGroupRecord, GitHubInputGroupStatus, GitHubInputGroupTarget, GitHubInputRunnerSummary } from './githubInputGroupTypes.ts';

export const GITHUB_INPUT_GROUP_EVENT = 'github-input-group-status';
// Existing action journal/DTO ceilings: _github_preflight_journal.MAX_RECORDS,
// github_preflight_protocol::{RECORD_LIMIT, RESPONSE_LIMIT}. No wider history.
export const GITHUB_INPUT_GROUP_RECORD_LIMIT = 64;
export const GITHUB_INPUT_GROUP_REASONS = [...GITHUB_CONNECTION_REASONS,
  'context-stale', 'assignment-unavailable', 'config-mismatch', 'caller-incompatible', 'environment-unready', 'runner-unverified', 'runner-collision',
  'input-invalid', 'destination-limit', 'sealing-unavailable', 'consent-expired', 'source-changed', 'metadata-changed', 'journal-incomplete'] as const;
export const GITHUB_INPUT_GROUP_REASON_HELP: Readonly<Record<GitHubInputGroupReason, string>> = Object.freeze({
  ...GITHUB_CONNECTION_REASON_HELP,
  none: 'The observation is available. It does not prove credential validity or release readiness.',
  unqualified: 'Input-group upload is not qualified for this installed runtime. You can still prepare project settings and manage inputs.',
  busy: 'Original work is running or retiring. Read local Status or stop that exact local operation; do not repeat it.',
  forbidden: 'GitHub refused access. Check the selected repository and Environments write permission, organization approval and SSO. The app does not increase permissions.',
  cancelled: 'The original local action was stopped. An update already accepted by GitHub is not undone.',
  'network-unavailable': 'The operation did not complete. An update may have applied; inspect its original result instead of repeating it.',
  'rate-limited': 'GitHub requested a waiting period. The original native cooldown still applies; no automatic retry is performed.',
  'context-stale': 'The project or credential release context changed. Review the saved project and current assigned inputs again.',
  'assignment-unavailable': 'The selected private input is not currently assigned and available. Use Credentials to review and assign it.',
  'config-mismatch': 'The saved local configuration does not match the reviewed remote configuration. Save or review project settings and workflow source first.',
  'caller-incompatible': 'This branch does not use the reviewed input-group-aware toolkit and canonical caller. Review workflow changes; an older workflow cannot use this upload.',
  'environment-unready': 'The selected GitHub environment or its required protection could not be verified. Review repository Settings → Environments with its administrator.',
  'runner-unverified': 'Runner safety is not currently verified. Check administrator access and effective Actions/organization runner visibility, then explicitly check again. No input is uploaded by the check.',
  'runner-collision': 'A self-hosted runner uses ubuntu-24.04 or macos-26, including an offline or busy runner. Ask its administrator to remove the conflicting label, then explicitly check again. No input upload is permitted by this observation.',
  'input-invalid': 'The native input group is incomplete or invalid. Review its file and companion fields in Credentials; no values are displayed here.',
  'destination-limit': 'This complete input exceeds GitHub’s 48,000-byte envelope limit. It may still be valid locally; the original is preserved and nothing is split or omitted.',
  'sealing-unavailable': 'The reviewed native encryption or randomness path is unavailable. No unencrypted fallback or alternative destination is used.',
  'consent-expired': 'This one-use review expired or was consumed. Read original Status; a new deliberate update needs a fresh review.',
  'source-changed': 'The reviewed branch or caller changed. No replacement source was silently adopted. Start a fresh review after original settlement.',
  'metadata-changed': 'The observed environment, key or input metadata changed since preview. Review the current target again; GitHub has no compare-and-swap guarantee.',
  'journal-incomplete': 'Local intent or outcome recording did not finish. Preserve the original remote acknowledgement separately and inspect local Status.',
});
const refusals: readonly GitHubInputGroupReason[] = ['unqualified', 'publisher-unconfigured', 'not-connected', 'busy', 'invalid-input',
  'target-changed', 'expired', 'rate-limited', 'cancelled', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired'];
export function githubInputGroupError(value: unknown): GitHubInputGroupError {
  try {
    if (value !== null && typeof value === 'object') {
      const field = Object.getOwnPropertyDescriptor(value, 'code');
      const code: unknown = field && Object.hasOwn(field, 'value') ? field.value : null;
      const reason = refusals.find((r) => code === `github_input_group_refused_${r.replaceAll('-', '_')}`);
      if (reason) return { code: String(code), reason, admission: 'not-admitted', message: GITHUB_INPUT_GROUP_REASON_HELP[reason] };
    }
  } catch { /* Do not inspect getters or render arbitrary exception data. */ }
  return { code: 'github_input_group_unknown', reason: 'response-invalid', admission: 'unknown',
    message: 'No conclusive acknowledgement was received. Read original local Status; do not repeat an uncertain update.' };
}
function one(value: unknown, values: readonly string[]): value is string { return typeof value === 'string' && values.includes(value); }
function hex(value: unknown, length: number): value is string { return typeof value === 'string' && value.length === length && !/[^0-9a-f]/u.test(value); }
function reason(value: unknown): value is GitHubInputGroupReason { return one(value, GITHUB_INPUT_GROUP_REASONS); }
// Fixed response-name grammar only; never used to construct a request/route.
const NAMES: Readonly<Record<AssetKind, string>> = Object.freeze({
  'android-keystore': 'MOBILE_RELEASE_INPUT_ANDROID_KEYSTORE_V1', 'android-firebase': 'MOBILE_RELEASE_INPUT_ANDROID_FIREBASE_V1',
  'apple-p12': 'MOBILE_RELEASE_INPUT_APPLE_P12_V1', 'apple-profile': 'MOBILE_RELEASE_INPUT_APPLE_PROFILE_V1',
  'asc-p8': 'MOBILE_RELEASE_INPUT_ASC_P8_V1', 'ios-firebase': 'MOBILE_RELEASE_INPUT_IOS_FIREBASE_V1',
  'google-wif': 'MOBILE_RELEASE_INPUT_GOOGLE_WIF_V1', 'project-read-token': 'MOBILE_RELEASE_INPUT_PROJECT_READ_TOKEN_V1',
  'apple-review-contact': 'MOBILE_RELEASE_INPUT_APPLE_REVIEW_CONTACT_V1', 'apple-review-demo-account': 'MOBILE_RELEASE_INPUT_APPLE_REVIEW_DEMO_ACCOUNT_V1',
  'apple-operation-commitment': 'MOBILE_RELEASE_INPUT_APPLE_OPERATION_COMMITMENT_V1',
});
const ENVIRONMENTS = { candidate: 'mobile-candidate', 'external-testing': 'mobile-external-testing', production: 'mobile-production' } as const;
const CALLERS = { candidate: '.github/workflows/mobile-candidate.yml', 'external-testing': '.github/workflows/mobile-external-testing.yml', production: '.github/workflows/mobile-production-submit.yml' } as const;
export function githubInputGroupAssignment(value: unknown): value is GitHubInputGroupAssignment {
  return keys(value, ['kind', 'recordId', 'recordRevision', 'contextRevision']) && one(value.kind, ASSET_KINDS) &&
    hex(value.recordId, 32) && assetCounter(value.recordRevision) && assetCounter(value.contextRevision);
}
function target(value: unknown): value is GitHubInputGroupTarget {
  if (!keys(value, ['projectBinding', 'repository', 'repositoryId', 'accountId', 'environment', 'environmentId', 'branch', 'sourceSha',
    'toolingSha', 'callerPath', 'callerSha256', 'configSha256', 'scope', 'kind', 'secretName', 'protocol']) ||
    !keys(value.scope, ['platform', 'stage', 'purpose']) || !one(value.scope.platform, ASSET_PLATFORMS) ||
    !one(value.scope.stage, ASSET_STAGES) || !one(value.scope.purpose, ASSET_PURPOSES) || !one(value.kind, ASSET_KINDS)) return false;
  const stage = value.scope.stage as keyof typeof ENVIRONMENTS;
  return hex(value.projectBinding, 64) && repository(value.repository) && numericId(value.repositoryId) && numericId(value.accountId) &&
    value.environment === ENVIRONMENTS[stage] && numericId(value.environmentId) && githubPreflightBranch(value.branch) &&
    hex(value.sourceSha, 40) && hex(value.toolingSha, 40) && value.callerPath === CALLERS[stage] && hex(value.callerSha256, 64) &&
    hex(value.configSha256, 64) && value.secretName === NAMES[value.kind as AssetKind] && value.protocol === 'mrk-github-input-group/1';
}
function metadata(value: unknown): value is GitHubInputGroupMetadata {
  return keys(value, ['state', 'createdAt', 'updatedAt', 'observedAt']) && value.state === 'present' && utc(value.createdAt) &&
    utc(value.updatedAt) && utc(value.observedAt) && value.createdAt <= value.updatedAt ||
    keys(value, ['state', 'observedAt']) && value.state === 'missing-or-inaccessible' && utc(value.observedAt);
}
function prepared(value: unknown): value is GitHubInputGroupPrepared {
  if (!keys(value, ['consentId', 'target', 'assignment', 'fields', 'metadata', 'destination', 'effect', 'observedAt', 'consentExpiresAt']) ||
    !hex(value.consentId, 32) || !target(value.target) || !githubInputGroupAssignment(value.assignment) ||
    value.assignment.kind !== value.target.kind || !Array.isArray(value.fields) || !metadata(value.metadata) ||
    !keys(value.destination, ['state', 'plaintextLimitBytes']) || value.destination.state !== 'fits' || value.destination.plaintextLimitBytes !== 48000 ||
    value.effect !== 'upsert-one-complete-group' || !utc(value.observedAt) || !utc(value.consentExpiresAt) || value.observedAt >= value.consentExpiresAt) return false;
  const fields = [...(isAssetFileKind(value.target.kind) ? ['file'] : []), ...SESSION_FIELDS[value.target.kind]];
  const actualFields = value.fields;
  return actualFields.length === fields.length && fields.every((field, index) => actualFields[index] === field);
}
function record(value: unknown): value is GitHubInputGroupRecord {
  if (!keys(value, ['originalOperationId', 'target', 'write', 'completion', 'reason']) || !hex(value.originalOperationId, 32) ||
    !target(value.target) || !reason(value.reason) || !keys(value.completion, ['journal', 'cleanup', 'finality']) ||
    !one(value.completion.journal, ['not-run', 'pending', 'confirmed', 'unknown']) ||
    !one(value.completion.cleanup, ['pending', 'confirmed', 'unknown']) || !one(value.completion.finality, ['pending', 'settled', 'unknown']) ||
    value.completion.finality === 'settled' && value.completion.cleanup !== 'confirmed' ||
    value.completion.cleanup === 'unknown' && value.completion.finality !== 'unknown') return false;
  const write = value.write;
  return keys(write, ['state']) && one(write.state, ['not-attempted', 'attempted-outcome-unknown']) ||
    keys(write, ['state', 'statusCode']) && (write.state === 'acknowledged-created' && write.statusCode === 201 || write.state === 'acknowledged-updated' && write.statusCode === 204) ||
    keys(write, ['state', 'reason']) && write.state === 'explicitly-rejected' && reason(write.reason) && write.reason !== 'none';
}
export function githubInputGroupCompleted(row: GitHubInputGroupRecord): boolean {
  return (row.write.state === 'acknowledged-created' || row.write.state === 'acknowledged-updated') && row.reason === 'none' &&
    row.completion.journal === 'confirmed' && row.completion.cleanup === 'confirmed' && row.completion.finality === 'settled';
}
function runnerSummary(value: unknown): value is GitHubInputRunnerSummary {
  if (!keys(value, ['result', 'checkedAt', 'expiresAt', 'groupCount', 'runnerCount', 'scope', 'reason']) || !reason(value.reason)) return false;
  if (value.result === 'refused') return value.reason !== 'none' && value.checkedAt === null && value.expiresAt === null &&
    value.groupCount === null && value.runnerCount === null && value.scope === null;
  return (value.result === 'safe' && value.reason === 'none' || value.result === 'expired' && value.reason !== 'none') &&
    utc(value.checkedAt) && utc(value.expiresAt) && value.checkedAt < value.expiresAt &&
    typeof value.groupCount === 'number' && Number.isInteger(value.groupCount) && value.groupCount >= 0 && value.groupCount <= 8 &&
    typeof value.runnerCount === 'number' && Number.isInteger(value.runnerCount) && value.runnerCount >= 0 && value.runnerCount <= 900 &&
    value.runnerCount <= 100 * (value.groupCount + 1) &&
    (value.scope === 'repository' && value.groupCount === 0 || value.scope === 'organization-wide');
}
export function parseGitHubInputGroupStatus(value: unknown): GitHubInputGroupStatus | null {
  try {
    if (!bounded(value, 256 * 1024, 20000, 16) || !keys(value, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason', 'operation', 'runner', 'prepared', 'records', 'observation']) ||
      value.schemaVersion !== 1 || !revision(value.revision) || !(value.sessionId === null || opaqueId(value.sessionId)) ||
      typeof value.available !== 'boolean' || !reason(value.reason) || value.available !== (value.reason === 'none') ||
      !Array.isArray(value.records) || value.records.length > GITHUB_INPUT_GROUP_RECORD_LIMIT || !value.records.every(record) ||
      value.runner !== null && !runnerSummary(value.runner)) return null;
    const op = value.operation;
    if (op !== null && (!keys(op, ['id', 'kind', 'phase', 'reason']) || !opaqueId(op.id) || !one(op.kind, ['prepare', 'apply', 'reconcile', 'pending', 'runner-check']) ||
      !one(op.phase, ['running', 'settled', 'cleanup-unknown']) || !reason(op.reason) ||
      (op.phase === 'cleanup-unknown') !== (op.reason === 'cleanup-unknown'))) return null;
    // Historical journal uncertainty is immutable evidence, not a live worker.
    if (value.available && (value.sessionId === null || op && op.phase !== 'settled')) return null;
    if (value.runner?.result === 'safe' && (value.sessionId === null || op?.kind === 'runner-check' &&
      (op.phase !== 'settled' || op.reason !== 'none'))) return null;
    if (value.prepared !== null && (!prepared(value.prepared) || !op || op.kind !== 'prepare' || op.phase !== 'settled' ||
      op.reason !== 'none' || !value.available || value.sessionId === null || value.runner?.result !== 'safe' ||
      value.prepared.consentExpiresAt > value.runner.expiresAt)) return null;
    const markers = new Set(value.records.map((row) => row.originalOperationId));
    if (markers.size !== value.records.length || value.prepared && markers.has(value.prepared.consentId)) return null;
    if (value.observation !== null && (!keys(value.observation, ['originalOperationId', 'metadata', 'assurance']) ||
      !hex(value.observation.originalOperationId, 32) || !markers.has(value.observation.originalOperationId) || !metadata(value.observation.metadata) ||
      value.observation.assurance !== 'metadata-only-not-secret-value-or-write-confirmation' || !op || op.kind !== 'reconcile' ||
      op.phase !== 'settled' || op.reason !== 'none')) return null;
    return structuredClone(value) as unknown as GitHubInputGroupStatus;
  } catch { return null; }
}
export function githubInputGroupRequestFits(command: GitHubInputGroupCommand, value: unknown): value is Record<string, unknown> {
  try {
    // Same2KiB/32-node public action cap; one extra level only for assignment.
    if (!bounded(value, 2048, 32, 3)) return false;
    if (command === 'github_input_group_status') return keys(value, []);
    if (command === 'github_input_group_cancel') return keys(value, ['operationId']) && opaqueId(value.operationId);
    const fields = ['sessionId', 'expectedRevision'];
    if (command === 'github_input_runner_check') fields.push('expectedConnectionRevision', 'expectedAssetStatusRevision', 'contextRevision');
    else if (command === 'github_input_group_prepare') fields.push('expectedConnectionRevision', 'expectedAssetStatusRevision', 'branch', 'assignment');
    else if (command === 'github_input_group_apply') fields.push('consentId', 'confirmUpsertWholeGroup');
    else if (command === 'github_input_group_reconcile') fields.push('originalOperationId');
    else if (command !== 'github_input_group_pending') return false;
    if (!keys(value, fields) || !opaqueId(value.sessionId) || !revision(value.expectedRevision)) return false;
    switch (command) {
      case 'github_input_runner_check': return revision(value.expectedConnectionRevision) &&
        assetCounter(value.expectedAssetStatusRevision) && value.expectedAssetStatusRevision > 0 &&
        assetCounter(value.contextRevision) && value.contextRevision > 0;
      case 'github_input_group_prepare': return revision(value.expectedConnectionRevision) && assetCounter(value.expectedAssetStatusRevision) &&
        githubPreflightBranch(value.branch) && githubInputGroupAssignment(value.assignment);
      case 'github_input_group_apply': return hex(value.consentId, 32) && value.confirmUpsertWholeGroup === true;
      case 'github_input_group_reconcile': return hex(value.originalOperationId, 32);
      case 'github_input_group_pending': return true;
      default: return false;
    }
  } catch { return false; }
}
