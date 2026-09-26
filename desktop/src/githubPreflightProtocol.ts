import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId,
  connectionOpaqueId as opaqueId, connectionRepository as repository, connectionRevision as revision,
  connectionUtc as utc } from './githubConnectionProtocol.ts';
import type { GitHubPreflightError, GitHubPreflightPrepared, GitHubPreflightReason, GitHubPreflightStatus } from './githubPreflightTypes.ts';

export const GITHUB_PREFLIGHT_EVENT = 'github-preflight-status';
export const GITHUB_PREFLIGHT_REASONS = ['none', 'unqualified', 'publisher-unconfigured', 'not-connected', 'busy', 'invalid-input',
  'target-changed', 'expired', 'rate-limited', 'cancelled', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired',
  'caller-mismatch', 'workflow-unavailable', 'source-changed', 'unresolved-run', 'ambiguous-run', 'run-changed', 'jobs-incomplete',
  'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'network-unavailable', 'tls-failed', 'response-invalid', 'response-limit'] as const;
export const GITHUB_PREFLIGHT_REASON_HELP: Readonly<Record<GitHubPreflightReason, string>> = Object.freeze({
  none: 'The last observation is available. It is not a release approval.',
  unqualified: 'GitHub preflight execution is not yet qualified for this installed platform/runtime. No action is enabled.',
  'publisher-unconfigured': 'This application needs its publisher-reviewed immutable toolkit workflow binding. A custom commit entered elsewhere cannot enable this action.',
  'not-connected': 'Select this project’s repository and connect to GitHub first. The preflight reuses only that original session.',
  busy: 'An original operation is still running or retiring. Read local Status or stop that exact local operation.',
  'invalid-input': 'Review the selected branch, platform and original request; the submitted values were not admitted.',
  'target-changed': 'The selected project, account, repository or original review changed. Review the correct project again.',
  expired: 'The original session expired. Disconnect and authenticate again; checking Status never extends its lifetime.',
  'rate-limited': 'GitHub requested a waiting period. The original native cooldown remains in force; there is no automatic retry.',
  cancelled: 'The local action was stopped. A workflow already accepted by GitHub may still be running.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the application open; no new work is authorized by a late response.',
  'runtime-unavailable': 'The fixed runtime or private per-account pending-record directory was unavailable. Nothing is repaired or overwritten automatically.',
  'consent-expired': 'This one-use review expired or was consumed. Prepare again only when there is no uncertain dispatch to reconcile.',
  'caller-mismatch': 'The branch does not contain this application’s exact supported nonpublishing caller. Review local workflow files and the publisher’s toolkit pin; custom workflows are not dispatched.',
  'workflow-unavailable': 'The expected preflight workflow is missing, disabled, archived or different. Review the repository’s Actions configuration.',
  'source-changed': 'The branch moved since review. No replacement source was silently accepted. Prepare a fresh review.',
  'unresolved-run': 'The exact run could not be identified from one complete bounded listing. Do not submit another dispatch as a retry.',
  'ambiguous-run': 'More than one or a duplicate run identity matched. Nothing was guessed from “latest” or a partial title.',
  'run-changed': 'The run, actor, branch, source, workflow or attempt no longer matches the original intent. It was not adopted.',
  'jobs-incomplete': 'A complete supported job observation was not available. A missing or skipped job is not a pass.',
  unauthorized: 'GitHub refused authentication. Disconnect before explicitly authenticating again.',
  forbidden: 'GitHub refused this operation. Check selected-repository Contents read and Actions write access, organization approval and SSO; the app never increases permissions.',
  'not-found-or-inaccessible': 'The requested repository, caller or exact run was absent or inaccessible. Absence was not proved.',
  'network-unavailable': 'The bounded operation did not complete. A dispatch may have applied; check its exact intent rather than repeating it.',
  'tls-failed': 'TLS verification failed. Do not disable certificate checks or provide alternate trust.',
  'response-invalid': 'The response did not match the closed protocol. Keep any pending intent; no successful result or automatic retry was inferred.',
  'response-limit': 'The finite response/page limit was exceeded. Incomplete observations were not treated as success.',
});
const refusalReasons: readonly GitHubPreflightReason[] = ['unqualified', 'publisher-unconfigured', 'not-connected', 'busy', 'invalid-input',
  'target-changed', 'expired', 'rate-limited', 'cancelled', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired'];
export function githubPreflightError(value: unknown): GitHubPreflightError {
  try {
    if (value && typeof value === 'object') {
      const field = Object.getOwnPropertyDescriptor(value, 'code');
      const code: unknown = field && Object.hasOwn(field, 'value') ? field.value : null;
      const reason = refusalReasons.find((r) => code === `github_preflight_refused_${r.replaceAll('-', '_')}`);
      if (reason) return { code: String(code), reason, admission: 'not-admitted', message: GITHUB_PREFLIGHT_REASON_HELP[reason] };
    }
  } catch { /* Never render arbitrary service data or invoke an error getter. */ }
  return { code: 'github_preflight_unknown', reason: 'response-invalid', admission: 'unknown', message: 'No conclusive acknowledgement was received. Read the original local Status; never repeat an uncertain dispatch.' };
}
function oneOf(value: unknown, values: readonly string[]): value is string { return typeof value === 'string' && values.includes(value); }
function hex(value: unknown, length: number): value is string { return typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value); }
export function githubPreflightBranch(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 200 && /^[A-Za-z0-9]/.test(value) && !/[^A-Za-z0-9._/-]/.test(value)
    && !value.startsWith('refs/') && !value.includes('..') && value.split('/').length <= 16
    && value.split('/').every((part) => part && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
}
function prepared(value: unknown): value is GitHubPreflightPrepared {
  if (!keys(value, ['target', 'sourceSha', 'workflowId', 'workflowPath', 'callerSha256', 'observedAt', 'expectedRef', 'displayTitle', 'confirmation'])
      || !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'branch', 'toolingRepository', 'toolingSha', 'platform', 'marker'])) return false;
  const t = value.target;
  return hex(t.projectBinding, 64) && repository(t.repository) && numericId(t.accountId) && numericId(t.repositoryId)
    && githubPreflightBranch(t.branch) && t.toolingRepository === 'Apdelrahman1911/mobile-release-kit' && hex(t.toolingSha, 40)
    && oneOf(t.platform, ['android', 'ios', 'both']) && hex(t.marker, 32) && hex(value.sourceSha, 40) && numericId(value.workflowId)
    && value.workflowPath === '.github/workflows/mobile-preflight.yml' && hex(value.callerSha256, 64) && utc(value.observedAt)
    && value.expectedRef === `refs/heads/${t.branch}` && value.displayTitle === `MRK Desktop preflight [${t.marker}]`
    && value.confirmation === `Run credential-free ${t.platform} preflight for ${t.repository} at ${value.sourceSha}? This may build project code, download dependencies, use GitHub-hosted minutes and upload diagnostic reports. The reviewed canonical workflow does not sign, upload to a Store or publish a release. GitHub dispatch uses this mutable branch, not an atomic commit lock. Authorized writers can replace its workflow after review; use a trusted protected branch.`;
}
const runStates = ['queued', 'in_progress', 'completed', 'waiting', 'pending', 'requested'];
const conclusions = ['success', 'failure', 'neutral', 'cancelled', 'skipped', 'timed_out', 'action_required', 'stale', 'startup_failure'];
function disposition(status: unknown, conclusion: unknown): boolean {
  return oneOf(status, runStates) && (conclusion === null || oneOf(conclusion, conclusions)) && (status === 'completed') === (conclusion !== null);
}
export function parseGitHubPreflightStatus(value: unknown): GitHubPreflightStatus | null {
  try {
    if (!bounded(value, 256 * 1024, 20000, 16) || !keys(value, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason',
      'operation', 'prepared', 'consentExpiresAt', 'pending', 'run']) || value.schemaVersion !== 1 || !revision(value.revision)
        || !(value.sessionId === null || opaqueId(value.sessionId)) || typeof value.available !== 'boolean'
        || !oneOf(value.reason, GITHUB_PREFLIGHT_REASONS) || value.available !== (value.reason === 'none')
        || !Array.isArray(value.pending) || value.pending.length > 64) return null;
    const op = value.operation;
    if (op !== null && (!keys(op, ['id', 'kind', 'phase', 'reason', 'effect']) || !opaqueId(op.id)
        || !oneOf(op.kind, ['prepare', 'dispatch', 'track', 'reconcile', 'pending']) || !oneOf(op.phase, ['running', 'settled', 'cleanup-unknown'])
        || !oneOf(op.reason, GITHUB_PREFLIGHT_REASONS) || !oneOf(op.effect, ['none', 'not-sent', 'potentially-applied', 'accepted'])
        || (op.kind === 'dispatch') === (op.effect === 'none') || (op.phase === 'cleanup-unknown') !== (op.reason === 'cleanup-unknown')
        || op.phase === 'running' && !['none', 'cancelled'].includes(String(op.reason))
        || op.effect === 'accepted' && (op.phase !== 'settled' || op.reason !== 'none'))) return null;
    if (value.available && (value.sessionId === null || op && op.phase !== 'settled')) return null;
    if (value.prepared !== null && (!prepared(value.prepared) || !utc(value.consentExpiresAt) || !op
        || op.kind !== 'prepare' || op.phase !== 'settled' || op.reason !== 'none' || value.sessionId === null)) return null;
    if (value.prepared === null && value.consentExpiresAt !== null) return null;
    const markers = new Set<string>();
    for (const record of value.pending) {
      if (!keys(record, ['prepared', 'runId']) || !prepared(record.prepared) || !(record.runId === null || numericId(record.runId))
          || markers.has(record.prepared.target.marker)) return null;
      markers.add(record.prepared.target.marker);
    }
    if (value.run !== null) {
      const run = value.run;
      if (!keys(run, ['id', 'attempt', 'status', 'conclusion', 'observedAt', 'jobs', 'url', 'assurance']) || !numericId(run.id)
          || run.attempt !== 1 || !disposition(run.status, run.conclusion) || !utc(run.observedAt)
          || run.assurance !== 'github-workflow-observation-not-release-evidence' || !Array.isArray(run.jobs) || run.jobs.length > 3) return null;
      const matches = value.pending.filter((v) => v.runId === run.id);
      if (matches.length !== 1 || run.url !== `https://github.com/${matches[0]!.prepared.target.repository}/actions/runs/${run.id}`
          || !op || !['track', 'reconcile'].includes(String(op.kind)) || op.phase !== 'settled' || op.reason !== 'none') return null;
      const ids = new Set<string>(); const kinds = new Set<string>(); const succeeded = new Set<string>();
      for (const job of run.jobs) {
        if (!keys(job, ['id', 'kind', 'status', 'conclusion']) || !numericId(job.id) || ids.has(job.id)
            || !oneOf(job.kind, ['input-guard', 'android', 'ios']) || kinds.has(job.kind) || !disposition(job.status, job.conclusion)) return null;
        ids.add(job.id); kinds.add(job.kind);
        if (job.status === 'completed' && job.conclusion === 'success') succeeded.add(job.kind);
      }
      if (run.conclusion === 'success') {
        const platform = matches[0]!.prepared.target.platform;
        const required = ['input-guard', ...(platform === 'both' ? ['android', 'ios'] : [platform])];
        if (!required.every((kind) => succeeded.has(kind))) return null;
      }
    }
    return JSON.parse(JSON.stringify(value)) as GitHubPreflightStatus;
  } catch { return null; }
}
export type GitHubPreflightCommand = 'github_preflight_status' | 'github_preflight_prepare' | 'github_preflight_dispatch' |
  'github_preflight_track' | 'github_preflight_reconcile' | 'github_preflight_pending' | 'github_preflight_cancel';
export function githubPreflightRequestFits(command: GitHubPreflightCommand, value: unknown): value is Record<string, unknown> {
  try {
    if (!bounded(value, 2048, 32, 2)) return false;
    if (command === 'github_preflight_status') return keys(value, []);
    if (command === 'github_preflight_cancel') return keys(value, ['operationId']) && opaqueId(value.operationId);
    const names = ['sessionId', 'expectedRevision'];
    if (command === 'github_preflight_prepare') names.push('expectedConnectionRevision', 'branch', 'platform');
    else if (command === 'github_preflight_dispatch') names.push('consentId', 'confirm');
    else if (command === 'github_preflight_track' || command === 'github_preflight_reconcile') names.push('marker');
    else if (command !== 'github_preflight_pending') return false;
    if (!keys(value, names) || !opaqueId(value.sessionId) || !revision(value.expectedRevision)) return false;
    switch (command) {
      case 'github_preflight_prepare': return revision(value.expectedConnectionRevision) && githubPreflightBranch(value.branch) && oneOf(value.platform, ['android', 'ios', 'both']);
      case 'github_preflight_dispatch': return hex(value.consentId, 32) && value.confirm === true;
      case 'github_preflight_track': case 'github_preflight_reconcile': return hex(value.marker, 32);
      case 'github_preflight_pending': return true;
      default: return false;
    }
  } catch { return false; }
}
