import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId,
  connectionOpaqueId as opaqueId, connectionRepository as repository, connectionRevision as revision,
  connectionUtc as utc } from './githubConnectionProtocol.ts';
import type { GitHubReleaseError, GitHubReleasePrepared, GitHubReleaseReason, GitHubReleaseStatus, GitHubReleaseSelection } from './githubReleaseTypes.ts';

export const GITHUB_RELEASE_EVENT = 'github-release-status';
export const GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES = 342;
export const GITHUB_RELEASE_REASONS = ['none', 'unqualified', 'publisher-unconfigured', 'not-connected', 'busy', 'invalid-input',
  'target-changed', 'expired', 'rate-limited', 'cancelled', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired',
  'caller-mismatch', 'workflow-unavailable', 'source-changed', 'unresolved-run', 'ambiguous-run', 'run-changed', 'jobs-incomplete',
  'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'network-unavailable', 'tls-failed', 'response-invalid', 'response-limit', 'config-invalid', 'version-invalid', 'platform-disabled', 'branch-mismatch', 'source-tree-unavailable'] as const;
export const GITHUB_RELEASE_REASON_HELP: Readonly<Record<GitHubReleaseReason, string>> = Object.freeze({
  none: 'The last observation is available. It is not a release approval.',
  unqualified: 'Protected release workflow execution is not yet qualified for this installed platform/runtime. No action is enabled.',
  'publisher-unconfigured': 'This application needs its publisher-reviewed immutable toolkit workflow binding. A custom commit entered elsewhere cannot enable this action.',
  'not-connected': 'Select this project’s repository and connect to GitHub first. Release actions reuse only that original session.',
  busy: 'An original operation is still running or retiring. Read local Status or stop that exact local operation.',
  'invalid-input': 'Review the selected branch, platform and original request; the submitted values were not admitted.',
  'target-changed': 'The selected project, account, repository or original review changed. Review the correct project again.',
  expired: 'The original session expired. Disconnect and authenticate again; checking Status never extends its lifetime.',
  'rate-limited': 'GitHub requested a waiting period. The original native cooldown remains in force; there is no automatic retry.',
  cancelled: 'The local action was stopped. A workflow already accepted by GitHub may still be running.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the application open; no new work is authorized by a late response.',
  'runtime-unavailable': 'The fixed runtime or private per-account pending-record directory was unavailable. Nothing is repaired or overwritten automatically.',
  'consent-expired': 'This one-use review expired or was consumed. Prepare again only when there is no uncertain dispatch to reconcile.',
  'caller-mismatch': 'The branch does not contain this application’s exact supported protected release caller. Review local workflow files and the publisher’s toolkit pin; custom workflows are not dispatched.',
  'workflow-unavailable': 'The expected release workflow is missing, disabled, archived or different. Review the repository’s Actions configuration.',
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
  'config-invalid': 'The committed release configuration is invalid, too large, or missing. Correct and review the selected branch configuration before preparing again.',
  'version-invalid': 'The committed or declared release version does not meet the core version policy. Check the marketing version and positive build number; this does not change the original evidence.',
  'platform-disabled': 'The selected platform is not enabled in the committed configuration. Choose an enabled platform or review the saved configuration first.',
  'branch-mismatch': 'The selected branch differs from the committed candidate/production branch configuration. No different branch was substituted.',
  'source-tree-unavailable': 'The repository tree is truncated, exceeds the supported 1,000-entry/256 KiB bound, changed, or includes a selected symlink/submodule. A complete immutable regular-file source check was not possible; no dispatch review is available.',
});
const refusalReasons: readonly GitHubReleaseReason[] = ['unqualified', 'publisher-unconfigured', 'not-connected', 'busy', 'invalid-input',
  'target-changed', 'expired', 'rate-limited', 'cancelled', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired'];
export function githubReleaseError(value: unknown): GitHubReleaseError {
  try {
    if (value && typeof value === 'object') {
      const field = Object.getOwnPropertyDescriptor(value, 'code');
      const code: unknown = field && Object.hasOwn(field, 'value') ? field.value : null;
      const reason = refusalReasons.find((r) => code === `github_release_refused_${r.replaceAll('-', '_')}`);
      if (reason) return { code: String(code), reason, admission: 'not-admitted', message: GITHUB_RELEASE_REASON_HELP[reason] };
    }
  } catch { /* Never render arbitrary service data or invoke an error getter. */ }
  return { code: 'github_release_unknown', reason: 'response-invalid', admission: 'unknown', message: 'No conclusive acknowledgement was received. Read the original local Status; never repeat an uncertain dispatch.' };
}
function oneOf(value: unknown, values: readonly string[]): value is string { return typeof value === 'string' && values.includes(value); }
function hex(value: unknown, length: number): value is string { return typeof value === 'string' && value.length === length && !/[^0-9a-f]/.test(value); }
export function githubReleaseBranch(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 200 && /^[A-Za-z0-9]/.test(value) && !/[^A-Za-z0-9._/-]/.test(value)
    && !value.startsWith('refs/') && !value.includes('..') && value.split('/').length <= 16
    && value.split('/').every((part) => part && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
}
function version(value: unknown): value is { name: string; build: number } {
  return keys(value, ['name', 'build']) && typeof value.name === 'string' && value.name.length > 0 && value.name.length <= 64
    && !/[^A-Za-z0-9.+-]/.test(value.name) && Number.isSafeInteger(value.build) && Number(value.build) >= 1 && Number(value.build) <= 2_100_000_000;
}
// Desktop admission profile only; hashes/IDs remain unauthenticated declarations.
// Reject non-ASCII/whitespace before parsing; JS end anchors must not admit a final newline.
export function githubReleaseRecoveryConfirmation(value: unknown, stage: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > GITHUB_RELEASE_RECOVERY_CONFIRMATION_MAX_BYTES
      || /[^A-Za-z0-9_.:-]/.test(value)) return false;
  const parts = value.split(':');
  if (parts.length !== 3 || !hex(parts[1], 64)) return false;
  const prefix = parts[0], detail = parts[2]!;
  if (stage === 'candidate') return prefix === 'recover-ios-candidate'
    ? detail.length >= 1 && detail.length <= 255 && !/[^A-Za-z0-9_.-]/.test(detail)
    : prefix === 'retry-ios-candidate-upload' && hex(detail, 64);
  return (stage === 'external-testing' || stage === 'production-submit')
    && prefix === 'retry-ios-operation-creates' && hex(detail, 64);
}
export function githubReleaseSelection(value: unknown, platform?: unknown): value is GitHubReleaseSelection {
  const names = ['stage', 'candidateRunId', 'externalRunId', 'recoveryRunId', 'originalSourceSha', 'originalVersion'];
  if (!(keys(value, names) || keys(value, [...names, 'recoveryConfirmation']))
      || !oneOf(value.stage, ['candidate', 'external-testing', 'production-submit'])
      || ![value.candidateRunId, value.externalRunId, value.recoveryRunId].every((id) => id === null || numericId(id))) return false;
  const original = value.stage !== 'candidate' || value.recoveryRunId !== null;
  return original === (value.originalSourceSha !== null) && original === (value.originalVersion !== null)
    && (value.originalSourceSha === null || hex(value.originalSourceSha, 40)) && (value.originalVersion === null || version(value.originalVersion))
    && (value.stage !== 'candidate' || value.candidateRunId === null && value.externalRunId === null)
    && (value.stage === 'production-submit' || value.externalRunId === null)
    && (value.stage === 'candidate' || value.recoveryRunId !== null || value.candidateRunId !== null)
    && (value.stage !== 'production-submit' || value.recoveryRunId !== null || value.externalRunId !== null)
    && (!Object.hasOwn(value, 'recoveryConfirmation') || platform === 'ios' && value.recoveryRunId !== null
      && githubReleaseRecoveryConfirmation(value.recoveryConfirmation, value.stage));
}
function plain(value: unknown, maximum: number): value is string {
  return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).byteLength <= maximum && !/[\x00-\x1f\x7f]/.test(value);
}
function prepared(value: unknown): value is GitHubReleasePrepared {
  if (!keys(value, ['target', 'sourceSha', 'sourceTree', 'workflowId', 'workflowPath', 'callerSha256', 'observedAt', 'expectedRef',
      'displayTitle', 'configSha256', 'versionSource', 'versionSha256', 'currentVersion', 'destination', 'checklist', 'environment', 'confirmation', 'originalAssurance'])
      || !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'branch', 'toolingRepository', 'toolingSha', 'platform', 'marker', 'selection'])
      || !githubReleaseSelection(value.target.selection, value.target.platform) || !version(value.currentVersion)
      || !keys(value.destination, ['applicationId', 'destination', 'assurance']) || !Array.isArray(value.checklist) || value.checklist.length > 16) return false;
  const t = value.target, selected = value.target.selection, original = selected.originalVersion ?? value.currentVersion;
  const names = new Set<string>();
  return hex(t.projectBinding, 64) && repository(t.repository) && numericId(t.accountId) && numericId(t.repositoryId)
    && githubReleaseBranch(t.branch) && t.toolingRepository === 'Apdelrahman1911/mobile-release-kit' && hex(t.toolingSha, 40)
    && oneOf(t.platform, ['android', 'ios']) && hex(t.marker, 32) && hex(value.sourceSha, 40) && hex(value.sourceTree, 40) && numericId(value.workflowId)
    && value.workflowPath === `.github/workflows/mobile-${selected.stage}.yml` && hex(value.callerSha256, 64) && utc(value.observedAt)
    && value.expectedRef === `refs/heads/${t.branch}` && value.displayTitle === `MRK Desktop ${selected.stage} [${t.marker}]`
    && hex(value.configSha256, 64) && hex(value.versionSha256, 64) && plain(value.versionSource, 512)
    && value.versionSource.split('/').length <= 12 && value.versionSource.split('/').every((part) => part.length > 0 && part !== '.' && part !== '..')
    && plain(value.destination.applicationId, 255) && plain(value.destination.destination, 256)
    && value.destination.assurance === 'current-dispatch-config-not-authenticated-original-destination'
    && value.originalAssurance === 'declared-original-references-not-authenticated-release-evidence'
    && value.environment === (selected.stage === 'production-submit' ? 'mobile-production' : `mobile-${selected.stage}`)
    && value.checklist.every((row) => keys(row, ['name', 'kind', 'reason']) && typeof row.name === 'string'
      && /^MOBILE_RELEASE_[A-Z0-9_]{1,96}$/.test(row.name) && !names.has(row.name) && !!names.add(row.name)
      && oneOf(row.kind, ['secret', 'variable', 'file', 'manual']) && plain(row.reason, 192))
    && value.confirmation === `${selected.stage}:${t.platform}:${original.name}:${original.build}`
    && new TextEncoder().encode(JSON.stringify(value)).byteLength <= 3900;
}
const runStates = ['queued', 'in_progress', 'completed', 'waiting', 'pending', 'requested'];
const conclusions = ['success', 'failure', 'neutral', 'cancelled', 'skipped', 'timed_out', 'action_required', 'stale', 'startup_failure'];
function disposition(status: unknown, conclusion: unknown): boolean {
  return oneOf(status, runStates) && (conclusion === null || oneOf(conclusion, conclusions)) && (status === 'completed') === (conclusion !== null);
}
export function parseGitHubReleaseStatus(value: unknown): GitHubReleaseStatus | null {
  try {
    if (!bounded(value, 256 * 1024, 20000, 16) || !keys(value, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason',
      'operation', 'prepared', 'consentExpiresAt', 'pending', 'run']) || value.schemaVersion !== 1 || !revision(value.revision)
        || !(value.sessionId === null || opaqueId(value.sessionId)) || typeof value.available !== 'boolean'
        || !oneOf(value.reason, GITHUB_RELEASE_REASONS) || value.available !== (value.reason === 'none')
        || !Array.isArray(value.pending) || value.pending.length > 64) return null;
    const op = value.operation;
    if (op !== null && (!keys(op, ['id', 'kind', 'phase', 'reason', 'effect']) || !opaqueId(op.id)
        || !oneOf(op.kind, ['prepare', 'dispatch', 'track', 'reconcile', 'pending']) || !oneOf(op.phase, ['running', 'settled', 'cleanup-unknown'])
        || !oneOf(op.reason, GITHUB_RELEASE_REASONS) || !oneOf(op.effect, ['none', 'not-sent', 'potentially-applied', 'accepted'])
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
          || run.assurance !== 'github-workflow-observation-not-release-evidence' || !Array.isArray(run.jobs) || run.jobs.length > 9
          || new TextEncoder().encode(JSON.stringify(run)).byteLength > 4096) return null;
      const matches = value.pending.filter((v) => v.runId === run.id);
      if (matches.length !== 1 || run.url !== `https://github.com/${matches[0]!.prepared.target.repository}/actions/runs/${run.id}`
          || !op || !['track', 'reconcile'].includes(String(op.kind)) || op.phase !== 'settled' || op.reason !== 'none') return null;
      const candidate = matches[0]!.prepared.target.selection.stage === 'candidate';
      const allowedJobs = candidate ? ['input-guard', 'android-resolve', 'android-online', 'android-build', 'android-store', 'ios-resolve', 'ios-online', 'ios-build', 'ios-store'] : ['input-guard', 'android', 'ios'];
      if (run.jobs.length > allowedJobs.length) return null;
      const ids = new Set<string>(); const kinds = new Set<string>(); const succeeded = new Set<string>();
      for (const job of run.jobs) {
        if (!keys(job, ['id', 'kind', 'status', 'conclusion']) || !numericId(job.id) || ids.has(job.id)
            || !oneOf(job.kind, allowedJobs) || kinds.has(job.kind) || !disposition(job.status, job.conclusion)) return null;
        ids.add(job.id); kinds.add(job.kind);
        if (job.status === 'completed' && job.conclusion === 'success') succeeded.add(job.kind);
      }
      if (run.conclusion === 'success') {
        const platform = matches[0]!.prepared.target.platform;
        const required = ['input-guard', ...(candidate ? [`${platform}-resolve`, `${platform}-store`] : [platform])];
        if (!required.every((kind) => succeeded.has(kind))) return null;
      }
    }
    return JSON.parse(JSON.stringify(value)) as GitHubReleaseStatus;
  } catch { return null; }
}
export type GitHubReleaseCommand = 'github_release_status' | 'github_release_prepare' | 'github_release_dispatch' |
  'github_release_track' | 'github_release_reconcile' | 'github_release_pending' | 'github_release_cancel';
export function githubReleaseRequestFits(command: GitHubReleaseCommand, value: unknown): value is Record<string, unknown> {
  try {
    if (!bounded(value, 4096, 64, 4)) return false;
    if (command === 'github_release_status') return keys(value, []);
    if (command === 'github_release_cancel') return keys(value, ['operationId']) && opaqueId(value.operationId);
    const names = ['sessionId', 'expectedRevision'];
    if (command === 'github_release_prepare') names.push('expectedConnectionRevision', 'branch', 'platform', 'selection');
    else if (command === 'github_release_dispatch') names.push('consentId', 'confirm', 'confirmation');
    else if (command === 'github_release_track' || command === 'github_release_reconcile') names.push('marker');
    else if (command !== 'github_release_pending') return false;
    if (!keys(value, names) || !opaqueId(value.sessionId) || !revision(value.expectedRevision)) return false;
    switch (command) {
      case 'github_release_prepare': return revision(value.expectedConnectionRevision) && githubReleaseBranch(value.branch) && oneOf(value.platform, ['android', 'ios']) && githubReleaseSelection(value.selection, value.platform);
      case 'github_release_dispatch': return hex(value.consentId, 32) && value.confirm === true && plain(value.confirmation, 160);
      case 'github_release_track': case 'github_release_reconcile': return hex(value.marker, 32);
      case 'github_release_pending': return true;
      default: return false;
    }
  } catch { return false; }
}
