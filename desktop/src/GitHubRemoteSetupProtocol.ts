import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId,
  connectionOpaqueId as opaqueId, connectionRepository as repository, connectionRevision as revision,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { GitHubRemoteSetupVariableSelection, GitHubRemoteSetupVariableFacts, GitHubRemoteSetupVariablePrepared, GitHubRemoteSetupSecretSelection, GitHubRemoteSetupSecretFacts, GitHubRemoteSetupSecretPrepared, GitHubRemoteSetupEnvironmentFacts, GitHubRemoteSetupEnvironmentPolicy, GitHubRemoteSetupEnvironmentPrepared,
  GitHubRemoteSetupError, GitHubRemoteSetupObservation, GitHubRemoteSetupPolicy, GitHubRemoteSetupPrepared,
  GitHubRemoteSetupReason, GitHubRemoteSetupSelection, GitHubRemoteSetupStatus } from './GitHubRemoteSetupTypes.ts';
export const GITHUB_REMOTE_SETUP_EVENT = 'github-remote-setup-status';
export const GITHUB_REMOTE_SETUP_REASONS = ['none', 'no-change', 'policy-unsupported', 'policy-changed', 'organization-restricted',
  'repository-archived', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'target-changed', 'rate-limited',
  'network-unavailable', 'tls-failed', 'response-invalid', 'response-limit', 'expired', 'cancelled', 'unqualified',
  'not-connected', 'busy', 'invalid-input', 'cleanup-unknown', 'runtime-unavailable', 'consent-expired',
  'material-unavailable', 'material-changed', 'material-too-large', 'requirement-unsupported', 'configuration-changed', 'secret-exists', 'secret-missing', 'secret-key-changed', 'sealing-failed', 'resources-unavailable', 'variable-exists', 'variable-missing', 'variable-changed'] as const;
export const GITHUB_REMOTE_SETUP_HELP: Readonly<Record<GitHubRemoteSetupReason, string>> = Object.freeze({
  'variable-exists': 'The exact variable was observed present. Create was refused; replacement requires a fresh explicit choice and review.',
  'variable-missing': 'The exact variable was observed absent. Replace was refused; creating requires a fresh explicit choice and review.',
  'variable-changed': 'The destination variable or environment changed after review. Read the original outcome and explicitly prepare again after settlement; never replay Apply.',
  'material-unavailable': 'The assigned credential is not currently available. Open Credentials and assess/assign the intended record for this project and stage.',
  'material-changed': 'The assigned credential or its context changed. Retire the old review and explicitly prepare again after the original settles.',
  'material-too-large': 'The selected field exceeds its fixed bound. Nonsecret variable identifiers must fit 4 KiB and their field format; secret files must fit 36 KiB before Base64 and secret values 48 KiB, with smaller field limits retained.',
  'requirement-unsupported': 'This required input has no supported assigned-record mapping, or is not required by the saved configuration. It remains incomplete; no arbitrary name, field or value is accepted.',
  'configuration-changed': 'The saved configuration no longer matches this credential context or review. Refresh and explicitly review the intended saved configuration; no automatic save is performed.',
  'secret-exists': 'The exact secret metadata was observed present. Create-if-absent was refused; replacement needs a new explicit selection and review.',
  'secret-missing': 'The exact secret metadata was observed absent. Replace-if-present was refused; creating needs a new explicit selection and review.',
  'secret-key-changed': 'The GitHub encryption key changed. A fresh explicit Prepare is required; nothing automatically reseals or retries.',
  'resources-unavailable': 'The fixed operation resource budget was unavailable or exhausted. No new consent was created; read the original outcome before a fresh explicit review.',
  'sealing-failed': 'The fixed sealing helper did not produce an admitted result. No consent was created; read the original outcome before starting again.',
  none: 'The last settings observation is available. It is not workflow, secret, Store or release qualification.',
  'no-change': 'The selected values were already observed. No write or consent was created.',
  'policy-unsupported': 'GitHub returned a policy this fixed editor cannot preserve safely. No replacement defaults were guessed.',
  'policy-changed': 'The policy changed since review. Prepare a fresh review after the original operation settles; do not replay Apply.',
  'organization-restricted': 'Repository or organization policy refused the setting. Review the organization rules; the app does not bypass them.',
  'repository-archived': 'The repository is archived. This editor does not unarchive it or change unrelated settings.',
  unauthorized: 'GitHub refused authentication. Retire the original session before explicitly connecting again.',
  forbidden: 'GitHub refused access. Repository-setting previews need Administration read and Apply needs Administration write. Secret/variable previews instead need Environments read and Apply needs Environments write. Existing Actions read and Metadata read remain required. GitHub plan or organization restrictions may apply; connection success does not prove those permissions.',
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
export const GITHUB_REMOTE_SETUP_ENVIRONMENTS = Object.freeze({ candidate: 'mobile-candidate', 'external-testing': 'mobile-external-testing', production: 'mobile-production' });
export const GITHUB_REMOTE_SETUP_ENVIRONMENT_CONFIRMATION = 'Send these exact GitHub create-or-update environment fields? A concurrent edit can be overwritten, a deleted environment recreated, or a newly created environment updated. There is no atomic compare-and-set. Protected-branches mode allows all branches if none are protected. Administrator bypass is not observed or configured here; review it on GitHub. This does not provision secrets or prove complete environment protection. Cancel does not undo a sent request.';
function environmentId(value: unknown): value is string {
  return numericId(value) && (value.length < 19 || value.length === 19 && value <= '9223372036854775807');
}
// Candidate guidance only. The native saved-configuration catalogue and same
// assigned material determine actual eligibility; no values are present here.
export const GITHUB_REMOTE_SETUP_SECRET_FIELDS = Object.freeze({
  "MOBILE_RELEASE_ANDROID_KEYSTORE_BASE64": { kind: 'android-keystore', platform: 'android', encoding: 'base64' },
  "MOBILE_RELEASE_ANDROID_KEYSTORE_PASSWORD": { kind: 'android-keystore', platform: 'android', encoding: 'utf8' },
  "MOBILE_RELEASE_ANDROID_KEY_PASSWORD": { kind: 'android-keystore', platform: 'android', encoding: 'utf8' },
  "MOBILE_RELEASE_ANDROID_GOOGLE_SERVICES_JSON_BASE64": { kind: 'android-firebase', platform: 'android', encoding: 'base64' },
  "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_BASE64": { kind: 'apple-p12', platform: 'ios', encoding: 'base64' },
  "MOBILE_RELEASE_APPLE_DISTRIBUTION_P12_PASSWORD": { kind: 'apple-p12', platform: 'ios', encoding: 'utf8' },
  "MOBILE_RELEASE_APPLE_PROVISIONING_PROFILE_BASE64": { kind: 'apple-profile', platform: 'ios', encoding: 'base64' },
  "MOBILE_RELEASE_IOS_GOOGLE_SERVICE_INFO_PLIST_BASE64": { kind: 'ios-firebase', platform: 'ios', encoding: 'base64' },
  "MOBILE_RELEASE_ASC_PRIVATE_KEY_P8_BASE64": { kind: 'asc-p8', platform: 'ios', encoding: 'base64' },
  "MOBILE_RELEASE_PROJECT_READ_TOKEN": { kind: 'project-read-token', platform: 'project', encoding: 'utf8' }
} as const);
export const GITHUB_REMOTE_SETUP_VARIABLE_FIELDS = Object.freeze({
  MOBILE_RELEASE_ANDROID_KEY_ALIAS: { kind: 'android-keystore', field: 'keyAlias', platform: 'android' },
  MOBILE_RELEASE_GOOGLE_WIF_PROVIDER: { kind: 'google-wif', field: 'provider', platform: 'android' },
  MOBILE_RELEASE_GOOGLE_SERVICE_ACCOUNT: { kind: 'google-wif', field: 'serviceAccount', platform: 'android' },
  MOBILE_RELEASE_ASC_KEY_ID: { kind: 'asc-p8', field: 'keyId', platform: 'ios' },
  MOBILE_RELEASE_ASC_ISSUER_ID: { kind: 'asc-p8', field: 'issuerId', platform: 'ios' },
} as const);
export const GITHUB_REMOTE_SETUP_VARIABLE_CONFIRMATION = "Send this exact required variable to GitHub? Variables are not secrets and can be read by permitted GitHub users and workflows. This action uses the selected assigned field. There is no atomic compare-and-set: another actor can change or delete the variable after these observations. Cancel does not undo a sent request. Readback confirms the observed value only; it does not prove a build or release works.";
export const GITHUB_REMOTE_SETUP_VARIABLE_PREVIOUS = 'Previous value is not displayed; this is not a full before-value diff.';
export const GITHUB_REMOTE_SETUP_VARIABLE_ACCEPTANCE = 'The bounded request observed the intended nonsecret identifier after an acknowledged write. Another actor can change or delete it later. This does not prove a build or release works.';
export const GITHUB_REMOTE_SETUP_SECRET_CONFIRMATION = "Send this exact required secret to GitHub? GitHub cannot show or compare the existing value. This create-or-update request can overwrite a concurrent change or recreate a deleted secret; there is no atomic compare-and-set. A returned acceptance does not verify the secret value or prove a build or release works. Cancel does not undo a sent request.";
export const GITHUB_REMOTE_SETUP_SECRET_ACCEPTANCE = 'GitHub accepted the request; the secret value was not verified. This does not prove a build or release works.';
function u32(value: unknown): value is number { return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 4294967295; }
function secretName(value: unknown): value is GitHubRemoteSetupSecretSelection['requirement'] {
  return typeof value === 'string' && Object.hasOwn(GITHUB_REMOTE_SETUP_SECRET_FIELDS, value);
}
function variableName(value: unknown): value is GitHubRemoteSetupVariableSelection['requirement'] {
  return typeof value === 'string' && Object.hasOwn(GITHUB_REMOTE_SETUP_VARIABLE_FIELDS, value);
}
// Current public references only, never native borrower authority or a key-store.
export function githubRemoteSetupSecretReferences(view: AssetDisplayState | null, projectId: string, requirement: GitHubRemoteSetupSecretSelection['requirement'], stage: GitHubRemoteSetupSecretSelection['stage']) {
  return assignedReferences(view, projectId, GITHUB_REMOTE_SETUP_SECRET_FIELDS[requirement], stage);
}
export function githubRemoteSetupVariableReferences(view: AssetDisplayState | null, projectId: string, requirement: GitHubRemoteSetupVariableSelection['requirement'], stage: GitHubRemoteSetupVariableSelection['stage']) {
  return assignedReferences(view, projectId, GITHUB_REMOTE_SETUP_VARIABLE_FIELDS[requirement], stage);
}
function assignedReferences(view: AssetDisplayState | null, projectId: string, field: { kind: string; platform: string } | undefined, stage: string) {
  const s = view?.status, c = s?.context;
  if (!view || !field || !s || !c || view.mode !== 'native' || !view.contextCurrent || view.busy || view.updatingContext || view.observationFailed ||
      view.blocked || view.error || view.originPending || s.mode === 'closed' || !s.capability.available || c.projectId !== projectId || c.platform !== field.platform || c.stage !== stage ||
      s.persistence && s.persistence.state !== 'unlocked' || s.operation && (s.operation.settlement !== 'known' && s.operation.settlement !== 'late-known' || s.operation.phase === 'stopping' || s.operation.phase === 'unknown')) return [];
  return s.assignments.filter((a) => a.kind === field.kind && a.availability === 'available' && a.contextRevision === c.revision).flatMap((a) => {
    const records = s.records.filter((r) => r.recordId === a.recordId && r.revision === a.recordRevision && r.kind === a.kind && r.availability === 'assigned' && r.payloadState === 'assessed');
    const record = records[0];
    return records.length === 1 && record ? [{ source: { recordId: a.recordId, recordRevision: a.recordRevision, contextRevision: a.contextRevision },
      label: record.label, kind: a.kind, context: { ...c }, mode: s.mode, storage: record.storage }] : [];
  });
}
function secretFacts(value: unknown): value is GitHubRemoteSetupSecretFacts {
  if (!keys(value, ['environmentName', 'environmentId', 'name', 'metadata']) || !oneOf(value.environmentName, Object.values(GITHUB_REMOTE_SETUP_ENVIRONMENTS)) ||
      !environmentId(value.environmentId) || !secretName(value.name) || !bounded(value, 2048, 1024, 12)) return false;
  return value.metadata === null || keys(value.metadata, ['createdAt', 'updatedAt']) && utc(value.metadata.createdAt) && utc(value.metadata.updatedAt);
}
function secretPrepared(value: unknown): value is GitHubRemoteSetupSecretPrepared {
  if (!keys(value, ['target', 'before', 'after', 'configuration', 'observedAt', 'confirmation']) ||
      !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'selection']) || !bounded(value, 8192, 1024, 12)) return false;
  const t = value.target, selected = t.selection, after = value.after, config = value.configuration;
  if (!hex(t.projectBinding, 64) || !repository(t.repository) || !environmentId(t.accountId) || !environmentId(t.repositoryId) ||
      !githubRemoteSetupSelection(selected) || selected.kind !== 'environment_secret' || !secretFacts(value.before) ||
      value.before.environmentName !== GITHUB_REMOTE_SETUP_ENVIRONMENTS[selected.stage] || value.before.name !== selected.requirement ||
      (selected.mode === 'create') !== (value.before.metadata === null) || !keys(after, ['name', 'encoding', 'plaintextBytes']) || after.name !== selected.requirement ||
      after.encoding !== GITHUB_REMOTE_SETUP_SECRET_FIELDS[selected.requirement].encoding || typeof after.plaintextBytes !== 'number' || !Number.isInteger(after.plaintextBytes) || after.plaintextBytes < 1 || after.plaintextBytes > 49152 ||
      !keys(config, ['savedConfig', 'canonicalConfig']) || !utc(value.observedAt) || value.confirmation !== GITHUB_REMOTE_SETUP_SECRET_CONFIRMATION) return false;
  return [config.savedConfig, config.canonicalConfig].every((d) => keys(d, ['bytes', 'sha256']) && typeof d.bytes === 'number' && Number.isInteger(d.bytes) && d.bytes >= 1 && d.bytes <= 524288 && hex(d.sha256, 64));
}
function variableDigest(value: unknown, maximum: number): value is { bytes: number; sha256: string } {
  return keys(value, ['bytes', 'sha256']) && typeof value.bytes === 'number' && Number.isInteger(value.bytes) && value.bytes >= 0 && value.bytes <= maximum &&
    hex(value.sha256, 64) && (value.bytes !== 0 || value.sha256 === 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
}
function variableFacts(value: unknown): value is GitHubRemoteSetupVariableFacts {
  if (!keys(value, ['environmentName', 'environmentId', 'name', 'value', 'metadata']) || !oneOf(value.environmentName, Object.values(GITHUB_REMOTE_SETUP_ENVIRONMENTS)) ||
      !environmentId(value.environmentId) || !variableName(value.name) || !bounded(value, 2048, 1024, 12)) return false;
  return value.value === null && value.metadata === null || variableDigest(value.value, 49152) &&
    keys(value.metadata, ['createdAt', 'updatedAt']) && utc(value.metadata.createdAt) && utc(value.metadata.updatedAt);
}
function variablePrepared(value: unknown): value is GitHubRemoteSetupVariablePrepared {
  if (!keys(value, ['target', 'before', 'after', 'configuration', 'observedAt', 'confirmation']) ||
      !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'selection']) || !bounded(value, 8192, 1024, 12)) return false;
  const t = value.target, selected = t.selection, after = value.after, config = value.configuration;
  if (!hex(t.projectBinding, 64) || !repository(t.repository) || !environmentId(t.accountId) || !environmentId(t.repositoryId) ||
      !githubRemoteSetupSelection(selected) || selected.kind !== 'environment_variable' || !variableFacts(value.before) ||
      value.before.environmentName !== GITHUB_REMOTE_SETUP_ENVIRONMENTS[selected.stage] || value.before.name !== selected.requirement ||
      (selected.mode === 'create') !== (value.before.value === null) || !keys(after, ['name', 'value']) || after.name !== selected.requirement ||
      !keys(after.value, ['text', 'bytes', 'sha256']) || typeof after.value.text !== 'string' || after.value.text.length < 1 || after.value.text.length > 4096 ||
      /[^\x20-\x7e]/.test(after.value.text) || typeof after.value.bytes !== 'number' || !Number.isInteger(after.value.bytes) ||
      after.value.bytes < 1 || after.value.bytes > 4096 || new TextEncoder().encode(after.value.text).byteLength !== after.value.bytes || !hex(after.value.sha256, 64) ||
      same(value.before.value, { bytes: after.value.bytes, sha256: after.value.sha256 }) ||
      !keys(config, ['savedConfig', 'canonicalConfig']) || !utc(value.observedAt) || value.confirmation !== GITHUB_REMOTE_SETUP_VARIABLE_CONFIRMATION) return false;
  // Native validates the actual field format/hash. Like existing workflow previews,
  // this synchronous public decoder admits bounded text, byte count and digest syntax.
  return [config.savedConfig, config.canonicalConfig].every((d) => keys(d, ['bytes', 'sha256']) && typeof d.bytes === 'number' && Number.isInteger(d.bytes) && d.bytes >= 1 && d.bytes <= 524288 && hex(d.sha256, 64));
}
function environmentLogin(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$(?![\s\S])/.test(value) && !value.includes('--');
}
function timer(value: unknown): value is number { return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 43200; }
export function githubRemoteSetupSelection(value: unknown): value is GitHubRemoteSetupSelection {
  return keys(value, ['kind', 'mode', 'stage', 'requirement', 'source']) && value.kind === 'environment_variable' &&
    oneOf(value.mode, ['create', 'replace']) && oneOf(value.stage, ['candidate', 'external-testing', 'production']) && variableName(value.requirement) &&
    keys(value.source, ['recordId', 'recordRevision', 'contextRevision']) && hex(value.source.recordId, 32) && u32(value.source.recordRevision) && u32(value.source.contextRevision) ||
    keys(value, ['kind', 'mode', 'stage', 'requirement', 'source']) && value.kind === 'environment_secret' &&
    oneOf(value.mode, ['create', 'replace']) && oneOf(value.stage, ['candidate', 'external-testing', 'production']) && secretName(value.requirement) &&
    keys(value.source, ['recordId', 'recordRevision', 'contextRevision']) && hex(value.source.recordId, 32) && u32(value.source.recordRevision) && u32(value.source.contextRevision) ||
    keys(value, ['kind', 'enabled']) && value.kind === 'actions_enabled' && typeof value.enabled === 'boolean' ||
    keys(value, ['kind', 'defaultWorkflowPermissions', 'canApprovePullRequestReviews']) && value.kind === 'workflow_token_policy' &&
    oneOf(value.defaultWorkflowPermissions, ['read', 'write']) && typeof value.canApprovePullRequestReviews === 'boolean' ||
    keys(value, ['kind', 'mode', 'stage', 'waitTimerMinutes', 'preventSelfReview', 'reviewerLogin', 'branches']) &&
    value.kind === 'environment_protection' && oneOf(value.stage, ['candidate', 'external-testing', 'production']) && timer(value.waitTimerMinutes) &&
    (value.mode === 'configure' && (value.preventSelfReview === null || typeof value.preventSelfReview === 'boolean') && value.reviewerLogin === null && value.branches === null ||
     value.mode === 'create' && value.preventSelfReview === true && environmentLogin(value.reviewerLogin) && oneOf(value.branches, ['all', 'protected']));
}
function policy(value: unknown, kind?: GitHubRemoteSetupSelection['kind']): value is GitHubRemoteSetupPolicy {
  return (kind === undefined || kind === 'actions_enabled') && keys(value, ['enabled', 'allowed_actions', 'sha_pinning_required']) &&
    typeof value.enabled === 'boolean' && oneOf(value.allowed_actions, ['all', 'local_only', 'selected']) && typeof value.sha_pinning_required === 'boolean' ||
    (kind === undefined || kind === 'workflow_token_policy') && keys(value, ['default_workflow_permissions', 'can_approve_pull_request_reviews']) &&
    oneOf(value.default_workflow_permissions, ['read', 'write']) && typeof value.can_approve_pull_request_reviews === 'boolean';
}
function environmentPolicy(value: unknown): value is GitHubRemoteSetupEnvironmentPolicy {
  if (!keys(value, ['waitTimerMinutes', 'protectedBranches', 'requiredReviewers']) || !timer(value.waitTimerMinutes) ||
      typeof value.protectedBranches !== 'boolean' || !bounded(value, 1024, 1024, 12)) return false;
  const r = value.requiredReviewers;
  if (r === null) return true;
  if (!keys(r, ['preventSelfReview', 'reviewers']) || typeof r.preventSelfReview !== 'boolean' || !Array.isArray(r.reviewers) || r.reviewers.length < 1 || r.reviewers.length > 6) return false;
  let previous: string | null = null;
  for (const row of r.reviewers) {
    if (!keys(row, ['type', 'id']) || !oneOf(row.type, ['User', 'Team']) || !environmentId(row.id)) return false;
    const key = `${row.type}:${row.id}`;
    if (previous !== null && previous >= key) return false;
    previous = key;
  }
  return true;
}
function environmentFacts(value: unknown): value is GitHubRemoteSetupEnvironmentFacts {
  return keys(value, ['name', 'id', 'policy']) && oneOf(value.name, Object.values(GITHUB_REMOTE_SETUP_ENVIRONMENTS)) &&
    (value.id === null && value.policy === null || environmentId(value.id) && environmentPolicy(value.policy)) && bounded(value, 1536, 1024, 12);
}
function environmentPrepared(value: unknown): value is GitHubRemoteSetupEnvironmentPrepared {
  if (!keys(value, ['target', 'before', 'after', 'reviewer', 'observedAt', 'confirmation']) ||
      !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'selection']) || !bounded(value, 4096, 1024, 12)) return false;
  const t = value.target, selected = t.selection;
  if (!hex(t.projectBinding, 64) || !repository(t.repository) || !environmentId(t.accountId) || !environmentId(t.repositoryId) ||
      !githubRemoteSetupSelection(selected) || selected.kind !== 'environment_protection' || !environmentFacts(value.before) ||
      value.before.name !== GITHUB_REMOTE_SETUP_ENVIRONMENTS[selected.stage] || !environmentPolicy(value.after) ||
      !utc(value.observedAt) || value.confirmation !== GITHUB_REMOTE_SETUP_ENVIRONMENT_CONFIRMATION) return false;
  let wanted: GitHubRemoteSetupEnvironmentPolicy;
  if (selected.mode === 'create') {
    const reviewer = value.reviewer;
    if (value.before.id !== null || !keys(reviewer, ['id', 'login', 'permission']) || !environmentId(reviewer.id) ||
        !environmentLogin(reviewer.login) || reviewer.login.toLowerCase() !== selected.reviewerLogin!.toLowerCase() || !oneOf(reviewer.permission, ['read', 'write', 'admin'])) return false;
    wanted = { waitTimerMinutes: selected.waitTimerMinutes, protectedBranches: selected.branches === 'protected',
      requiredReviewers: { preventSelfReview: true, reviewers: [{ type: 'User', id: reviewer.id }] } };
  } else {
    const before = value.before.policy;
    if (before === null || value.reviewer !== null || selected.preventSelfReview !== null && before.requiredReviewers === null) return false;
    wanted = { ...before, waitTimerMinutes: selected.waitTimerMinutes, requiredReviewers: before.requiredReviewers === null ? null :
      { ...before.requiredReviewers, preventSelfReview: selected.preventSelfReview ?? before.requiredReviewers.preventSelfReview } };
  }
  return !same(value.before.policy, wanted) && same(value.after, wanted);
}
// Only compares an already-admitted public observation with the same retained review.
// Actual write acknowledgement and original settlement remain native authority.
export function githubRemoteSetupObservationMatches(prepared: GitHubRemoteSetupPrepared, observed: GitHubRemoteSetupObservation | null): boolean {
  if ('configuration' in prepared) {
    if ('value' in prepared.after) return variableFacts(observed) && observed.value !== null && observed.metadata !== null &&
      observed.environmentName === prepared.before.environmentName && observed.environmentId === prepared.before.environmentId && observed.name === prepared.before.name &&
      same(observed.value, { bytes: prepared.after.value.bytes, sha256: prepared.after.value.sha256 });
    return secretFacts(observed) && observed.metadata !== null && observed.environmentName === prepared.before.environmentName &&
      observed.environmentId === prepared.before.environmentId && observed.name === prepared.before.name;
  }
  if ('reviewer' in prepared) return environmentFacts(observed) && observed.id !== null && observed.name === prepared.before.name &&
    (prepared.before.id === null || observed.id === prepared.before.id) && same(observed.policy, prepared.after);
  return policy(observed, prepared.target.selection.kind) && same(observed, prepared.after);
}
export function githubRemoteSetupConfirmation(kind: GitHubRemoteSetupSelection['kind'], repo: string): string {
  if (kind === 'environment_variable') return GITHUB_REMOTE_SETUP_VARIABLE_CONFIRMATION;
  if (kind === 'environment_secret') return GITHUB_REMOTE_SETUP_SECRET_CONFIRMATION;
  if (kind === 'environment_protection') return GITHUB_REMOTE_SETUP_ENVIRONMENT_CONFIRMATION;
  return `Change ${kind} for ${repo}? Review the exact before and after values. Enabling Actions can allow configured workflows to run; write tokens or review approvals grant additional privileges. GitHub does not provide an atomic compare-and-set here: another administrator can change settings after this review. This does not configure secrets, change local workflows, or qualify a release.`;
}
function prepared(value: unknown): value is GitHubRemoteSetupPrepared {
  if (keys(value, ['target', 'before', 'after', 'configuration', 'observedAt', 'confirmation'])) return secretPrepared(value) || variablePrepared(value);
  if (keys(value, ['target', 'before', 'after', 'reviewer', 'observedAt', 'confirmation'])) return environmentPrepared(value);
  if (!keys(value, ['target', 'before', 'after', 'observedAt', 'confirmation']) ||
      !keys(value.target, ['projectBinding', 'repository', 'accountId', 'repositoryId', 'selection'])) return false;
  const t = value.target;
  if (!hex(t.projectBinding, 64) || !repository(t.repository) || !numericId(t.accountId) || !numericId(t.repositoryId) ||
      !githubRemoteSetupSelection(t.selection) || (t.selection.kind === 'environment_protection' || t.selection.kind === 'environment_secret' || t.selection.kind === 'environment_variable') || !policy(value.before, t.selection.kind) || !policy(value.after, t.selection.kind) ||
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
        !(value.observed === null || policy(value.observed) || environmentFacts(value.observed) || secretFacts(value.observed) || variableFacts(value.observed))) return null;
    const op = value.operation;
    if (op !== null) {
      if (!keys(op, ['id', 'kind', 'phase', 'reason', 'effect', 'writeClaimed', 'writeAcknowledged']) || !opaqueId(op.id) ||
          !oneOf(op.kind, ['prepare', 'apply']) || !oneOf(op.phase, ['running', 'stopping', 'settled', 'cleanup-unknown']) ||
          !oneOf(op.reason, GITHUB_REMOTE_SETUP_REASONS) || !oneOf(op.effect, ['not-started', 'unknown', 'readback-confirmed', 'accepted-not-value-verified']) ||
          !(op.writeClaimed === null || typeof op.writeClaimed === 'boolean') || !(op.writeAcknowledged === null || typeof op.writeAcknowledged === 'boolean') ||
          (op.writeClaimed === null) !== (op.writeAcknowledged === null) || op.writeAcknowledged === true && op.writeClaimed !== true ||
          op.phase !== 'settled' && (op.writeClaimed !== null || op.effect === 'readback-confirmed' || op.effect === 'accepted-not-value-verified') ||
          op.kind === 'prepare' && (op.effect !== 'not-started' || op.writeClaimed === true || op.writeAcknowledged === true) ||
          op.phase === 'cleanup-unknown' && op.reason !== 'cleanup-unknown' ||
          op.effect === 'accepted-not-value-verified' && (op.kind !== 'apply' || op.reason !== 'none' || op.writeClaimed !== true || op.writeAcknowledged !== true || !secretFacts(value.observed) || value.observed.metadata === null) ||
          op.effect === 'readback-confirmed' && (secretFacts(value.observed) || op.kind !== 'apply' || op.reason !== 'none' || op.writeClaimed !== true || op.writeAcknowledged !== true || value.observed === null || environmentFacts(value.observed) && value.observed.id === null || variableFacts(value.observed) && value.observed.value === null) ||
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
