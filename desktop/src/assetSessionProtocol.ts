// Closed presentation/wire checks. Core alone judges credential policy. These
// limits apply to already-materialized JS data, not upstream IPC allocations.
import type { ApiError } from './types.ts';
import type { AssetKind, AssetReason, AssetStatus, CredentialAssessment } from './assetSessionTypes.ts';

export const ASSET_KINDS = ['android-keystore', 'android-firebase', 'google-wif', 'project-read-token'] as const;
export const ASSET_REASONS = ['none', 'closed', 'unqualified', 'unsupported-platform', 'unsupported-filesystem', 'unsupported-format', 'invalid-request', 'busy', 'source-refused', 'source-changed', 'material-limit', 'parser-limit', 'project-overlap', 'exclusion-unconfirmed', 'capacity', 'context-stale', 'user-cancelled', 'review-expired', 'deadline', 'document-lost', 'shutdown', 'cleanup-unknown'] as const;
export const ASSET_PLATFORMS = ['android', 'ios', 'project'] as const;
export const ASSET_STAGES = ['candidate', 'external-testing', 'production'] as const;
export const ASSET_PURPOSES = ['full', 'signing', 'store'] as const;
export const SESSION_FIELDS = {
  'android-keystore': ['storePassword', 'keyAlias', 'keyPassword'],
  'android-firebase': [],
  'google-wif': ['provider', 'serviceAccount'],
  'project-read-token': ['token'],
} as const;
const fieldLayout: Record<AssetKind, readonly (readonly [string, string])[]> = {
  'android-keystore': [['file', 'ANDROID_KEYSTORE_BASE64'], ['storePassword', 'ANDROID_KEYSTORE_PASSWORD'], ['keyAlias', 'ANDROID_KEY_ALIAS'], ['keyPassword', 'ANDROID_KEY_PASSWORD']],
  'android-firebase': [['file', 'ANDROID_GOOGLE_SERVICES_JSON_BASE64']],
  'google-wif': [['provider', 'GOOGLE_WIF_PROVIDER'], ['serviceAccount', 'GOOGLE_SERVICE_ACCOUNT']],
  'project-read-token': [['token', 'PROJECT_READ_TOKEN']],
};
const states = ['not-applicable', 'missing', 'unknown', 'invalid', 'configured', 'format-valid'];
const issues = ['not-run', 'incomplete', 'unsupported-format', 'unsupported-variant', 'material-limit', 'parser-limit', 'empty-file', 'suffix-conflict', 'malformed-container', 'required-missing', 'value-nul', 'scalar-format', 'pkcs8-algorithm', 'firebase-shape', 'identity-mismatch'];
const scopes = ['value-admission', 'identifier-format', 'file-nonempty', 'suffix-consistency', 'container-parse', 'jks-header', 'pfx-envelope', 'cms-signed-data-envelope', 'pkcs8-envelope', 'json-document', 'plist-document', 'ec-p256-identifiers', 'firebase-shape', 'application-identity'];
const encoder = new TextEncoder();
type ObjectValue = Record<string, unknown>;
function object(value: unknown): value is ObjectValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
}
function keys(value: unknown, names: readonly string[]): value is ObjectValue {
  return object(value) && Object.keys(value).length === names.length && names.every((key) => Object.hasOwn(value, key));
}
function one(value: unknown, values: readonly string[]): boolean { return typeof value === 'string' && values.includes(value); }
export function assetCounter(value: unknown): value is number { return Number.isInteger(value) && (value as number) >= 0 && (value as number) <= 0xffff_ffff; }
function token(value: unknown): value is string { return typeof value === 'string' && value.length === 32 && /^[0-9a-f]{32}$/u.test(value); }
function projectId(value: unknown): value is string { return typeof value === 'string' && value.length >= 1 && value.length <= 64 && /^[A-Za-z0-9_-]+$/u.test(value); }
function scope(value: unknown): boolean {
  return keys(value, ['platform', 'stage', 'purpose']) && one(value.platform, ASSET_PLATFORMS) && one(value.stage, ASSET_STAGES) && one(value.purpose, ASSET_PURPOSES);
}
function list(value: unknown, maximum: number, check: (value: unknown) => boolean): value is unknown[] {
  return Array.isArray(value) && value.length <= maximum && value.every(check);
}
// Count bytes while walking, before cloning/JSON.stringify. Strings remain
// immutable caller values; no secret copy is retained by this validator.
export function assetJsonFits(value: unknown, limit: number): boolean {
  let nodes = 0; let bytes = 0;
  const seen = new Set<object>();
  const charge = (count: number): boolean => { bytes += count; return bytes <= limit; };
  const string = (text: string): boolean => {
    if (text.length > limit || /[\ud800-\udfff]/u.test(text)) return false;
    let size = 2;
    for (const character of text) {
      const code = character.codePointAt(0)!;
      size += code < 32 ? ([8, 9, 10, 12, 13].includes(code) ? 2 : 6) : code === 34 || code === 92 ? 2 : code < 128 ? 1 : code < 2048 ? 2 : code < 65536 ? 3 : 4;
      if (size > limit) return false;
    }
    return charge(size);
  };
  const visit = (item: unknown, depth: number): boolean => {
    if (++nodes > 20000 || depth > 32) return false;
    if (item === null) return charge(4);
    if (typeof item === 'boolean') return charge(item ? 4 : 5);
    if (typeof item === 'number') return Number.isFinite(item) && charge(String(item).length);
    if (typeof item === 'string') return string(item);
    if (typeof item !== 'object' || seen.has(item)) return false;
    seen.add(item);
    if (Array.isArray(item)) {
      if (item.length > 20000 || Object.keys(item).length !== item.length || !charge(2 + Math.max(0, item.length - 1))) return false;
      for (let index = 0; index < item.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(item, index);
        if (!descriptor || !('value' in descriptor) || !visit(descriptor.value, depth + 1)) return false;
      }
      return true;
    }
    if (!object(item)) return false;
    const names = Object.keys(item);
    return names.length <= 20000 && charge(2 + Math.max(0, names.length - 1) + names.length) && names.every((name) => {
      const descriptor = Object.getOwnPropertyDescriptor(item, name);
      return !!descriptor && 'value' in descriptor && ++nodes <= 20000 && string(name) && visit(descriptor.value, depth + 1);
    });
  };
  try { return visit(value, 0); } catch { return false; }
}

function assessment(value: unknown): value is CredentialAssessment {
  if (!keys(value, ['schemaVersion', 'policyVersion', 'kind', 'context', 'applicability', 'state', 'fields', 'identity', 'assurance']) ||
      value.schemaVersion !== 1 || value.policyVersion !== 'credential-policy-v1' || !one(value.kind, ASSET_KINDS) ||
      !scope(value.context) || !one(value.state, states) || !one(value.identity, ['not-applicable', 'not-assessed', 'match', 'mismatch']) ||
      !keys(value.applicability, ['state', 'reason']) || !one(value.applicability.state, ['required', 'not-applicable']) ||
      !one(value.applicability.reason, ['selected', 'wrong-platform', 'platform-disabled', 'not-required'])) return false;
  const layout = fieldLayout[value.kind as AssetKind];
  if (!Array.isArray(value.fields) || value.fields.length !== layout.length || !value.fields.every((field, index) => {
    const expected = layout[index];
    return !!expected && keys(field, ['id', 'requirement', 'presence', 'state', 'issues', 'checks']) &&
      field.id === expected[0] && field.requirement === `MOBILE_RELEASE_${expected[1]}` && one(field.presence, ['missing', 'supplied']) && one(field.state, states) &&
      list(field.issues, 15, (item) => one(item, issues)) && new Set(field.issues).size === field.issues.length &&
      list(field.checks, 14, (check) => keys(check, ['scope', 'outcome']) && one(check.scope, scopes) && one(check.outcome, ['passed', 'failed', 'asserted-pass', 'asserted-fail']));
  })) return false;
  const a = value.assurance;
  return keys(a, ['basis', 'scalarValuesProcessed', 'fileObservationsProcessed', 'selectedFilesRead', 'keyringAccessed', 'storageWritesPerformed', 'projectCodeExecuted', 'sourceCustody', 'nativeValidation', 'serviceValidation', 'releaseReadiness']) &&
    a.basis === 'supplied-input-only' && typeof a.scalarValuesProcessed === 'boolean' && typeof a.fileObservationsProcessed === 'boolean' &&
    a.selectedFilesRead === false && a.keyringAccessed === false && a.storageWritesPerformed === false && a.projectCodeExecuted === false &&
    a.sourceCustody === 'not-established' && a.nativeValidation === 'not-run' && a.serviceValidation === 'not-run' && a.releaseReadiness === 'unknown';
}

export function parseAssetStatus(value: unknown): AssetStatus | null {
  try {
    if (!assetJsonFits(value, 32768) || !keys(value, ['schemaVersion', 'statusRevision', 'mode', 'capability', 'context', 'operation', 'records', 'assignments']) ||
        value.schemaVersion !== 1 || !assetCounter(value.statusRevision) || !one(value.mode, ['closed', 'session']) ||
        !keys(value.capability, ['available', 'reason']) || typeof value.capability.available !== 'boolean' || !one(value.capability.reason, ASSET_REASONS) ||
        (value.capability.available && value.capability.reason !== 'none')) return null;
    if (value.context !== null && (!keys(value.context, ['revision', 'projectId', 'platform', 'stage', 'purpose']) || !assetCounter(value.context.revision) ||
        !projectId(value.context.projectId) || !scope({ platform: value.context.platform, stage: value.context.stage, purpose: value.context.purpose }))) return null;
    if (!list(value.records, 32, (record) => keys(record, ['recordId', 'revision', 'kind', 'availability']) && token(record.recordId) &&
        assetCounter(record.revision) && one(record.kind, ASSET_KINDS) && one(record.availability, ['unassigned', 'assigned', 'mutation-pending'])) ||
        new Set(value.records.map((record) => (record as ObjectValue).recordId)).size !== value.records.length) return null;
    if (!list(value.assignments, 8, (assignment) => keys(assignment, ['kind', 'recordId', 'recordRevision', 'contextRevision', 'availability']) &&
        one(assignment.kind, ASSET_KINDS) && token(assignment.recordId) && assetCounter(assignment.recordRevision) && assetCounter(assignment.contextRevision) &&
        one(assignment.availability, ['available', 'unavailable'])) || new Set(value.assignments.map((assignment) => (assignment as ObjectValue).kind)).size !== value.assignments.length) return null;
    const operation = value.operation;
    if (operation !== null) {
      if (!keys(operation, ['operationId', 'operation', 'phase', 'reason', 'source', 'settlement', 'selectionToken', 'assessment', 'preview']) ||
          !assetCounter(operation.operationId) || !one(operation.operation, ['choose-file', 'choose-project', 'prepare', 'prepare-delete', 'commit', 'bind', 'discard', 'lock']) ||
          !one(operation.phase, ['idle', 'admitting', 'picking', 'capturing', 'selected', 'assessing', 'preview', 'mutating', 'stopping', 'unknown']) ||
          !one(operation.reason, ASSET_REASONS) || !one(operation.source, ['not-run', 'pending', 'captured', 'refused', 'unknown']) ||
          !one(operation.settlement, ['pending', 'known', 'unknown', 'late-known']) || (operation.selectionToken !== null && !token(operation.selectionToken)) ||
          (operation.assessment !== null && !assessment(operation.assessment))) return null;
      if (operation.preview !== null && (!keys(operation.preview, ['token', 'action', 'expiresInMs', 'subject']) || !token(operation.preview.token) ||
          !one(operation.preview.action, ['save', 'bind', 'delete']) || !assetCounter(operation.preview.expiresInMs) || operation.preview.expiresInMs > 300000 ||
          operation.phase !== 'preview' || operation.settlement !== 'known' || operation.selectionToken !== null ||
          !keys(operation.preview.subject, ['kind', 'change', 'recordId', 'recordRevision']) || !one(operation.preview.subject.kind, ASSET_KINDS) ||
          !one(operation.preview.subject.change, ['new', 'replace', 'assign', 'delete']))) return null;
      if (operation.selectionToken !== null && (operation.phase !== 'selected' || operation.settlement !== 'known' || operation.source !== 'captured')) return null;
      if ((operation.phase === 'unknown' || operation.settlement === 'unknown' || operation.settlement === 'late-known' || operation.reason === 'document-lost') &&
          (operation.preview !== null || operation.selectionToken !== null)) return null;
    }
    // Cross-links protect display from a mismatched record/context. They do not
    // select requirements, validate values, or confer native assignment authority.
    const typed = value as unknown as AssetStatus;
    const evaluated = typed.operation?.assessment;
    if (evaluated && (!typed.context || !['platform', 'stage', 'purpose'].every((key) => evaluated.context[key as keyof typeof evaluated.context] === typed.context![key as keyof typeof evaluated.context]))) return null;
    const preview = typed.operation?.preview;
    if (preview && preview.action !== 'delete' && (!evaluated || evaluated.applicability.state !== 'required' || !['configured', 'format-valid'].includes(evaluated.state))) return null;
    if (preview) {
      const subject = preview.subject;
      if (evaluated && evaluated.kind !== subject.kind) return null;
      if (preview.action === 'save' && subject.change === 'new') {
        if (subject.recordId !== null || subject.recordRevision !== null) return null;
      } else {
        if (!(preview.action === 'save' && subject.change === 'replace') && !(preview.action === 'bind' && subject.change === 'assign') &&
            !(preview.action === 'delete' && subject.change === 'delete')) return null;
        if (!token(subject.recordId) || !assetCounter(subject.recordRevision) || !typed.records.some((record) => record.kind === subject.kind &&
            record.recordId === subject.recordId && record.revision === subject.recordRevision && (preview.action !== 'bind' || record.availability !== 'mutation-pending'))) return null;
      }
    }
    for (const assignment of typed.assignments) {
      if (assignment.availability === 'available' && (typed.mode !== 'session' || !typed.context || typed.context.revision !== assignment.contextRevision ||
          !typed.records.some((record) => record.recordId === assignment.recordId && record.revision === assignment.recordRevision && record.kind === assignment.kind && record.availability === 'assigned') ||
          typed.operation?.phase === 'unknown' || typed.operation?.settlement === 'unknown' || typed.operation?.settlement === 'late-known')) return null;
    }
    if ((typed.capability.reason === 'document-lost' || typed.operation?.reason === 'document-lost') && (typed.context !== null || typed.records.length || typed.assignments.length ||
        typed.operation?.selectionToken || typed.operation?.assessment || typed.operation?.preview)) return null;
    return structuredClone(typed);
  } catch { return null; }
}

function recordRef(value: unknown): boolean { return keys(value, ['recordId', 'expectedRevision']) && token(value.recordId) && assetCounter(value.expectedRevision); }
function fields(value: unknown, names: readonly string[]): boolean {
  return keys(value, names) && names.every((key) => value[key] === null || (typeof value[key] === 'string' && value[key].length <= 4096 &&
    !/[\ud800-\udfff]/u.test(value[key]) && encoder.encode(value[key]).byteLength <= 4096));
}
export type AssetCommand = 'vault_status' | 'vault_open' | 'asset_context' | 'asset_choose' | 'credential_prepare' | 'vault_prepare_delete' | 'vault_commit' | 'vault_bind' | 'vault_discard' | 'vault_lock';
export function assetRequestFits(command: AssetCommand, value: unknown): boolean {
  const limit = command === 'asset_context' ? 1048576 : command === 'credential_prepare' ? 131072 : 1024;
  if (!assetJsonFits(value, limit)) return false;
  switch (command) {
    case 'vault_status': return keys(value, []);
    case 'vault_open': return keys(value, ['mode']) && value.mode === 'session';
    case 'vault_lock': return keys(value, ['discardSession']) && value.discardSession === true;
    case 'vault_commit': case 'vault_bind': return keys(value, ['previewToken']) && token(value.previewToken);
    case 'vault_discard': return keys(value, ['operationId']) && assetCounter(value.operationId);
    case 'vault_prepare_delete': return recordRef(value);
    case 'asset_context': return keys(value, ['projectId', 'draft', 'platform', 'stage', 'purpose']) && projectId(value.projectId) && object(value.draft) &&
      assetJsonFits(value.draft, 524288) && scope({ platform: value.platform, stage: value.stage, purpose: value.purpose });
    case 'asset_choose': return keys(value, ['contextRevision', 'kind', 'replacement']) && assetCounter(value.contextRevision) && one(value.kind, ['android-keystore', 'android-firebase']) &&
      (value.replacement === null || recordRef(value.replacement));
    case 'credential_prepare': {
      if (!object(value) || !assetCounter(value.contextRevision) || !object(value.source)) return false;
      const source = value.source;
      if (source.type === 'record') return keys(value, ['contextRevision', 'source']) && keys(source, ['type', 'recordId', 'expectedRevision']) && token(source.recordId) && assetCounter(source.expectedRevision);
      if (!keys(value, ['contextRevision', 'source', 'fields'])) return false;
      if (source.type === 'selection') return keys(source, ['type', 'selectionToken']) && token(source.selectionToken) &&
        (fields(value.fields, []) || fields(value.fields, SESSION_FIELDS['android-keystore']));
      return keys(source, ['type', 'kind', 'replacement']) && source.type === 'scalar' && one(source.kind, ['google-wif', 'project-read-token']) &&
        (source.replacement === null || recordRef(source.replacement)) && fields(value.fields, SESSION_FIELDS[source.kind as 'google-wif' | 'project-read-token']);
    }
  }
}

const errorMessages: Record<string, string> = {
  assessment_invalid_request: 'The assessment request has an unsupported shape or value type.',
  assessment_limit: 'The assessment request exceeds a supported interface bound.',
  assessment_version: 'This assessment schema version is unavailable.',
  assessment_policy_stale: 'Credential policy changed; prepare the context again.',
  assessment_context_invalid: 'The submitted draft is not valid for assessment.',
  assessment_unavailable: 'Credential assessment is unavailable; no credential was verified.',
  assessment_context_stale: 'Assessment context changed; prepare again.',
  busy: 'Two read-only queries already own the available slots.',
  shutting_down: 'The application is stopping its owned queries.',
  query_timeout: 'The read-only query exceeded its operation deadline.',
  cleanup_unknown: 'Original query cleanup is unconfirmed. Further queries are disabled; the owner is retained.',
  AssetStatusInvalid: 'The session service returned an unsupported status. No action or cleanup is confirmed. Check the original session status.',
  AssetSessionUnavailable: 'Session import is unavailable. No private input was accepted or verified.',
};
export function assetError(error: unknown): ApiError {
  const code = object(error) && typeof error.code === 'string' ? error.code : '';
  if (code.startsWith('asset_') && ASSET_REASONS.filter((reason) => reason !== 'none').some((reason) => code === `asset_${reason.replaceAll('-', '_')}`)) {
    return { code, message: 'This session action was not completed. See its status reason.', retryable: false };
  }
  const safe = Object.hasOwn(errorMessages, code) ? code : 'AssetSessionUnavailable';
  return { code: safe, message: errorMessages[safe]!, retryable: false };
}

export const ASSET_REASON_HELP: Record<AssetReason, string> = {
  none: 'The last observed step has no reported refusal. This is not release or Store verification.',
  closed: 'Start a session to consent to keeping private inputs only in this running application.',
  unqualified: 'Native session import has not completed its required qualification. You can read the guides, but this build cannot collect private inputs.',
  'unsupported-platform': 'This session importer currently targets qualified Linux x86_64 systems. macOS, Windows and browser previews remain guide-only.',
  'unsupported-filesystem': 'This first importer supports a qualified local ext-family filesystem, not network, overlay or FUSE locations. Your original file was not changed.',
  'unsupported-format': 'This first importer supports JKS headers, Android Firebase JSON, Google WIF values and project read tokens. Other formats are not yet enabled.',
  'invalid-request': 'The submitted input does not fit the supported interface. Review the field guide; no repair or retry was performed.',
  busy: 'The original session operation still owns its slot. Wait for its status or request Cancel; do not start a replacement operation.',
  'source-refused': 'The original file could not be safely captured. It must be a supported private regular file outside registered projects, without symbolic-link traversal. The app will not change its permissions or contents.',
  'source-changed': 'An original file, directory or registered project changed during observation. No changed source was silently substituted.',
  'material-limit': 'The file exceeds this importer’s material-size limit. Select a supported original; the app does not truncate files.',
  'parser-limit': 'The file exceeds the supported parser’s size or complexity limits. This does not prove the original file is malformed.',
  'project-overlap': 'The selected file entry is inside a registered project. Select the private original outside project folders; the app will not move or delete it.',
  'exclusion-unconfirmed': 'A later project selection could not confirm every retained file’s original location. Discard or reselect the affected session record explicitly before trying another project.',
  capacity: 'This session permits at most 32 records and 64 MiB of retained material. Explicitly remove an unneeded session record; original files are never deleted.',
  'context-stale': 'The project, draft or release scope changed. Submit the current context and prepare again before keeping or assigning anything.',
  'user-cancelled': 'Cancellation was requested. Old record bytes may remain, but old assignments are not automatically restored. Wait for the original cleanup status.',
  'review-expired': 'The original five-minute review expired. It cannot be extended by refreshing. Discard the review and prepare explicitly again.',
  deadline: 'The operation exceeded its work deadline. Its original owners must still settle; a timeout is not successful cleanup.',
  'document-lost': 'The original application view was lost. Assignment authority is revoked and only redacted cleanup status remains available.',
  shutdown: 'The application is stopping its original owners. No new input or assignment can be accepted.',
  'cleanup-unknown': 'Original cleanup could not be confirmed. Do not retry, replace or assume private buffers are gone. Keep the application open while its original owners report any late settlement.',
};
