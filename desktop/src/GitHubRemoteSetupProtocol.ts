import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId,
  connectionOpaqueId as opaqueId, connectionRepository as repository, connectionRevision as revision,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubRemoteSetupError, GitHubRemoteSetupPolicy, GitHubRemoteSetupPrepared,
  GitHubRemoteSetupReason, GitHubRemoteSetupSelection, GitHubRemoteSetupStatus } from './GitHubRemoteSetupTypes.ts';
export const GITHUB_REMOTE_SETUP_EVENT = 'github-remote-setup-status';
export const GITHUB_REMOTE_SETUP_REASONS = ['none', 'no-change', 'policy-unsupported', 'policy-changed', 'organization-restricted',
  'repository-archived', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'target-changed', 'rate-limited',
  'network-unavailable', 'tls-failed', 'response-invalid', 'response-limit', 'expired', 'cancelled', 'unqualified',
  'not-connected', 'busy', 'invalid-input', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired'] as const;
export const GITHUB_REMOTE_SETUP_HELP: Readonly<Record<GitHubRemoteSetupReason, string>> = Object.freeze({
  none: 'The last settings observation is available. It is not workflow, secret, Store or release qualification.',
  'no-change': 'The selected values were already observed. No write or consent was created.',
  'policy-unsupported': 'GitHub returned a policy this fixed editor cannot preserve safely. No replacement defaults were guessed.',
  'policy-changed': 'The policy changed since review. Prepare a fresh review after the original operation settles; do not replay Apply.',
  'organization-restricted': 'Repository or organization policy refused the setting. Review the organization rules; the app does not bypass them.',
  'repository-archived': 'The repository is archived. This editor does not unarchive it or change unrelated settings.',
  unauthorized: 'GitHub refused authentication. Retire the original session before explicitly connecting again.',
  forbidden: 'GitHub refused access. Settings previews need repository Administration read; applying needs Administration write. Connection success does not prove those permissions.',
  'not-found-or-inaccessible': 'The repository or setting was absent or inaccessible. This is not proof that it does not exist.',
  'target-changed': 'The selected project, account, repository or review changed. Select the intended context and prepare again.',
  'rate-limited': 'GitHub requested a waiting period. The native cooldown remains in force; nothing retries automatically.',
  'network-unavailable': 'The request did not complete. A settings write may have occurred; read original Status before considering a fresh preview.',
  'tls-failed': 'TLS verification failed. Do not disable certificate verification or substitute a trust source.',
  'response-invalid': 'The response did not match the fixed protocol. No success or retry permission was inferred.',
  'response-limit': 'A bounded response exceeded its limit. Partial data was not treated as a complete policy.',
  expired: 'The original session expired. Status never extends its lifetime. Retire it before explicitly connecting again.',
  cancelled: 'Stopping the local operation does not undo a possible remote write. Read its original outcome.',
  unqualified: 'Repository-setting operations are not qualified for this installed platform/runtime. Browser preview never performs them.',
  'not-connected': 'Connect the selected project’s explicit repository first. This panel never collects a token.',
  busy: 'An original operation is still running or retiring. Status and Stop original remain available.',
  'invalid-input': 'The fixed selection or original request was refused. No arbitrary endpoint or extra policy field is supported.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the application open; no new operation or late success replaces that uncertainty.',
  'runtime-unavailable': 'The fixed native runtime is unavailable. There is no browser or command-line fallback here.',
  'consent-expired': 'The one-use review expired or was consumed. Prepare again only after the original operation is settled.',
});
const oneOf = (v: unknown, values: readonly string[]): v is string => typeof v === 'string' && values.includes(v);
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && !/[^0-9a-f]/.test(v);
export function githubRemoteSetupSelection(value: unknown): value is GitHubRemoteSetupSelection {
  return keys(value, ['kind', 'enabled']) && value.kind === 'actions_enabled' && typeof value.enabled === 'boolean' ||
    keys(value, ['kind', 'defaultWorkflowPermissions', 'canApprovePullRequestReviews']) && value.kind === 'workflow_token_policy' &&
    oneOf(value.defaultWorkflowPermissions, ['read', 'write']) && typeof value.canApprovePullRequestReviews === 'boolean';
}
function policy(value: unknown, kind?: GitHubRemoteSetupSelection['kind']): value is GitHubRemoteSetupPolicy {
  return kind !== 'workflow_token_policy' && keys(value, ['enabled', 'allowed_actions', 'sha_pinning_required']) &&
    typeof value.enabled === 'boolean' && oneOf(value.allowed_actions, ['all', 'local_only', 'selected']) && typeof value.sha_pinning_required === 'boolean' ||
    kind !== 'actions_enabled' && keys(value, ['default_workflow_permissions', 'can_approve_pull_request_reviews']) &&
    oneOf(value.default_workflow_permissions, ['read', 'write']) && typeof value.can_approve_pull_request_reviews === 'boolean';
}
export function githubRemoteSetupConfirmation(kind: GitHubRemoteSetupSelection['kind'], repo: string): string {
  return `Change ${kind} for ${repo}? Review the exact before and after values. Enabling Actions can allow configured workflows to run; write tokens or review approvals grant additional privileges. GitHub does not provide an atomic compare-and-set here: another administrator can change settings after this review. This does not configure secrets, change local workflows, or qualify a release.`;
}
function prepared(value: unknown): value is GitHubRemoteSetupPrepared {
  if (!keys(value, ['target', 'before', 'after', 'observedAt', 'confirmation']) ||
      !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'selection'])) return false;
  const t = value.target;
  if (!hex(t.projectBinding, 64) || !repository(t.repository) || !numericId(t.accountId) || !numericId(t.repositoryId) ||
      !githubRemoteSetupSelection(t.selection) || !policy(value.before, t.selection.kind) || !policy(value.after, t.selection.kind) ||
      !utc(value.observedAt) || same(value.before, value.after) || value.confirmation !== githubRemoteSetupConfirmation(t.selection.kind, t.repository)) return false;
  const wanted = t.selection.kind === 'actions_enabled' ? { ...value.before, enabled: t.selection.enabled } :
    { default_workflow_permissions: t.selection.defaultWorkflowPermissions, can_approve_pull_request_reviews: t.selection.canApprovePullRequestReviews };
  return same(value.after, wanted);
}
export function parseGitHubRemoteSetupStatus(value: unknown): GitHubRemoteSetupStatus | null {
  try {
    if (!bounded(value, 65536, 1024, 12) || !keys(value, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason', 'operation', 'consent', 'observed']) ||
        value.schemaVersion !== 1 || !revision(value.revision) || !(value.sessionId === null || opaqueId(value.sessionId)) ||
        typeof value.available !== 'boolean' || !oneOf(value.reason, GITHUB_REMOTE_SETUP_REASONS) ||
        !(value.observed === null || policy(value.observed))) return null;
    const op = value.operation;
    if (op !== null) {
      if (!keys(op, ['id', 'kind', 'phase', 'reason', 'effect', 'writeClaimed', 'writeAcknowledged']) || !opaqueId(op.id) ||
          !oneOf(op.kind, ['prepare', 'apply']) || !oneOf(op.phase, ['running', 'stopping', 'settled', 'cleanup-unknown']) ||
          !oneOf(op.reason, GITHUB_REMOTE_SETUP_REASONS) || !oneOf(op.effect, ['not-started', 'unknown', 'readback-confirmed']) ||
          !(op.writeClaimed === null || typeof op.writeClaimed === 'boolean') || !(op.writeAcknowledged === null || typeof op.writeAcknowledged === 'boolean') ||
          (op.writeClaimed === null) !== (op.writeAcknowledged === null) || op.writeAcknowledged === true && op.writeClaimed !== true ||
          op.phase !== 'settled' && (op.writeClaimed !== null || op.effect === 'readback-confirmed') ||
          op.kind === 'prepare' && (op.effect !== 'not-started' || op.writeClaimed === true || op.writeAcknowledged === true) ||
          op.phase === 'cleanup-unknown' && op.reason !== 'cleanup-unknown' ||
          op.effect === 'readback-confirmed' && (op.kind !== 'apply' || op.reason !== 'none' || op.writeClaimed !== true || op.writeAcknowledged !== true || value.observed === null) ||
          op.writeClaimed === true && op.effect === 'not-started' || op.writeClaimed === false && op.effect !== 'not-started') return null;
    }
    if (value.available && (value.sessionId === null || op && op.phase !== 'settled' || value.reason === 'cleanup-unknown')) return null;
    if (value.revision === 4294967294 && (value.available || value.reason !== 'cleanup-unknown')) return null;
    if (value.consent !== null) {
      const c = value.consent;
      if (!keys(c, ['id', 'expiresAt', 'prepared']) || !hex(c.id, 32) || !utc(c.expiresAt) || !prepared(c.prepared) ||
          value.sessionId === null || !op || op.kind !== 'prepare' || op.phase !== 'settled' || op.reason !== 'none' ||
          op.writeClaimed !== false || op.writeAcknowledged !== false || !same(value.observed, c.prepared.before)) return null;
    }
    return value as unknown as GitHubRemoteSetupStatus;
  } catch { return null; }
}
export type GitHubRemoteSetupCommand = 'github_remote_setup_status' | 'github_remote_setup_prepare' | 'github_remote_setup_apply' |
  'github_remote_setup_discard' | 'github_remote_setup_cancel';
export function githubRemoteSetupRequestFits(command: GitHubRemoteSetupCommand, value: unknown): value is Record<string, unknown> {
  try {
    if (!bounded(value, 4096, 64, 4)) return false;
    if (command === 'github_remote_setup_status') return keys(value, []);
    if (command === 'github_remote_setup_cancel') return keys(value, ['operationId']) && opaqueId(value.operationId);
    const fields = ['sessionId', 'expectedRevision'];
    if (command === 'github_remote_setup_prepare') fields.push('expectedConnectionRevision', 'selection');
    else if (command === 'github_remote_setup_apply') fields.push('consentId', 'confirm');
    else if (command === 'github_remote_setup_discard') fields.push('consentId');
    else return false;
    if (!keys(value, fields) || !opaqueId(value.sessionId) || !revision(value.expectedRevision)) return false;
    if (command === 'github_remote_setup_prepare') return revision(value.expectedConnectionRevision) && githubRemoteSetupSelection(value.selection);
    return hex(value.consentId, 32) && (command !== 'github_remote_setup_apply' || value.confirm === true);
  } catch { return false; }
}
export function githubRemoteSetupError(value: unknown): GitHubRemoteSetupError {
  try {
    if (value && typeof value === 'object') {
      const d = Object.getOwnPropertyDescriptor(value, 'code'); const code: unknown = d && Object.hasOwn(d, 'value') ? d.value : null;
      const reason = GITHUB_REMOTE_SETUP_REASONS.find((r) => code === `github_remote_setup_refused_${r.replaceAll('-', '_')}`);
      if (reason && reason !== 'none' && reason !== 'no-change') return { code: String(code), reason, admission: 'not-admitted', message: GITHUB_REMOTE_SETUP_HELP[reason] };
    }
  } catch { /* Do not evaluate exception getters or render service strings. */ }
  return { code: 'github_remote_setup_unknown', reason: 'response-invalid', admission: 'unknown',
    message: 'The original acknowledgement is unconfirmed. Read local Status or stop that original; never retry Apply automatically.' };
}
