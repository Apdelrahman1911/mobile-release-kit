// Layout only. Shared core configuration policy and the existing save/review
// owners remain authoritative; visiting a group is not completing a stage.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import type { ProjectSession } from './drafts.ts';
import type { Catalog, FieldContext, FieldHelp } from './types.ts';

export const GUIDED_CONFIG_STAGES = ['app', 'build', 'defaults', 'delivery'] as const;
export type GuidedConfigStage = typeof GUIDED_CONFIG_STAGES[number];
export type GuidedConfigGroup = GuidedConfigStage | 'advanced';
export interface GuidedConfigAttention {
  field: FieldHelp;
  kind: 'missing' | 'conflict' | 'unknown';
  group: GuidedConfigGroup;
}
export interface GuidedConfigSection {
  id: GuidedConfigGroup;
  label: string;
  title: string;
  description: string;
  fields: FieldHelp[];
  attention: GuidedConfigAttention[];
  attentionCount: number | null;
}
export interface GuidedConfigLayout {
  context: 'current' | 'needs-review' | 'example';
  format: 'invalid' | 'format-valid' | null;
  comparison: 'complete' | 'partial' | null;
  contexts: ReadonlyMap<string, FieldContext>;
  sections: GuidedConfigSection[];
  attention: GuidedConfigAttention[];
  attentionCount: number | null;
}

const appFields = new Set(['android.enabled', 'ios.enabled', 'android.applicationId', 'ios.bundleId', 'android.identityStatus', 'ios.identityStatus']);
const buildFields = new Set(['version.source', 'version.nameKey', 'version.buildKey', 'android.module', 'android.variant',
  'ios.project', 'ios.workspace', 'ios.scheme', 'ios.archiveConfiguration']);
const defaultFields = new Set(['source.candidateBranch', 'source.productionBranch', 'metadata.root', 'metadata.androidLocales', 'metadata.iosLocales',
  'services.androidFirebase', 'services.iosFirebase']);
const deliveryFields = new Set(['source.projectReadTokenRequired', 'source.localStoreEnabled', 'android.externalTrack.name', 'android.externalTrack.kind',
  'android.uploadCertificateSha256', 'ios.appStoreAppId', 'ios.teamId', 'ios.externalTestFlightGroup', 'ios.distributionCertificateSha256',
  'ios.symbols.policy', 'ios.review.usesNonExemptEncryption', 'ios.review.demoAccountRequired']);

export function guidedConfigGroup(path: string): GuidedConfigGroup {
  if (appFields.has(path)) return 'app';
  if (buildFields.has(path)) return 'build';
  if (defaultFields.has(path)) return 'defaults';
  if (deliveryFields.has(path)) return 'delivery';
  // Commands, schema fields and any future catalogue additions remain visible
  // under Advanced. Grouping never rejects, rewrites or silently drops a field.
  return 'advanced';
}

const descriptions: Record<GuidedConfigGroup, Pick<GuidedConfigSection, 'label' | 'title' | 'description'>> = {
  app: { label: 'App & platforms', title: '1. Choose the app you are preparing',
    description: 'Use the real identity of your existing app. Editing these settings does not rename native project files. Identity approval is your declared policy, not a Store verification.' },
  build: { label: 'Version & build', title: '2. Point to the app’s build inputs',
    description: 'Choose the version file and build target. The version keys name lines in that file; they are not the app’s version number. These settings do not create a version file or start a build.' },
  defaults: { label: 'Project defaults', title: '3. Review the project defaults',
    description: 'The current configuration format also needs branch policy, listing languages and app-service choices before it can be saved. Review suggested defaults; they are not discovered or verified values.' },
  delivery: { label: 'Signing & Store', title: '4. Configure signing and delivery when needed',
    description: 'Declaring an identity approved makes additional signing and Store fields required. Keep existing app and signing identities. This form does not connect an account or issue a certificate.' },
  advanced: { label: 'Advanced settings', title: 'Advanced settings',
    description: 'Custom commands, schema details and other catalogue settings. These are part of the same draft; a required field here still needs attention before saving.' },
};
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
const counter = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && !Object.is(value, -0);
const text = (value: unknown): value is string => typeof value === 'string' && value.length <= 4096 && !/[\u0000-\u001f\u007f]/.test(value);
const list = (value: unknown, check: (item: unknown) => boolean): value is unknown[] => Array.isArray(value) && value.length <= 64 && value.every(check);
function fieldAssurance(value: unknown): boolean {
  return keys(value, ['basis', 'releaseReadiness', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed']) &&
    value.basis === 'schema-policy' && value.releaseReadiness === 'unknown' &&
    ['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].every((key) => value[key] === false);
}

function summary(value: unknown): boolean {
  if (!record(value)) return false;
  if (value.present === false) return keys(value, ['present']);
  if (value.present !== true || typeof value.type !== 'string' || !['null', 'boolean', 'number', 'string', 'array', 'object'].includes(value.type)) return false;
  return value.type === 'array' || value.type === 'object' ? keys(value, ['present', 'type', 'count']) && counter(value.count) : keys(value, ['present', 'type']);
}
interface CurrentGuidedReview {
  contexts: Map<string, FieldContext>;
  format: 'invalid' | 'format-valid';
  comparison: 'complete' | 'partial';
}
function currentReview(catalog: Pick<Catalog, 'fields'>, session: ProjectSession, selectedProjectId: string | null): CurrentGuidedReview | null {
  if (selectedProjectId !== session.project.id || session.draft === null || session.reviewRequest !== null || session.reviewError !== null) return null;
  try {
    // Same revision/baseline binding as reviewFresh, after copying descriptors
    // so malformed response/binding getters are not executed by presentation.
    const review = copyBoundedComparisonData(session.review, 128 * 1024 + 512, 16_384);
    if (!keys(review, ['result', 'binding']) || !keys(review.binding, ['id', 'revision', 'baselineGeneration']) ||
        !Object.values(review.binding).every(counter) || review.binding.revision !== session.revision ||
        review.binding.baselineGeneration !== session.baselineGeneration) return null;
    const result = review.result;
    if (!keys(result, ['schemaVersion', 'validation', 'comparison', 'fields', 'assurance']) || result.schemaVersion !== 1 ||
        !Array.isArray(result.fields) || result.fields.length > 64 || !fieldAssurance(result.assurance)) return null;
    // Inspect the context envelope, not configuration values. Invalid drafts
    // must still expose their real missing/conflicting fields. The save-only
    // isConfigPreview predicate deliberately accepts only valid prepared saves
    // and cannot be reused as a gate for this repair/editing presentation.
    const validation = result.validation, comparison = result.comparison;
    if (!keys(validation, ['valid', 'state', 'issues', 'requirements', 'assurance']) || typeof validation.valid !== 'boolean' ||
        validation.state !== (validation.valid ? 'format-valid' : 'invalid') ||
        !list(validation.issues, (issue) => keys(issue, ['code', 'status', 'message', 'remediation']) && text(issue.code) && text(issue.message) &&
          text(issue.remediation) && (issue.status === 'INVALID' || issue.status === 'SKIP')) ||
        validation.valid && validation.issues.length !== 0 ||
        !list(validation.requirements, (requirement) => keys(requirement, ['name', 'kind', 'stage', 'platform', 'environment', 'alternatives', 'reason', 'state']) &&
          ['name', 'kind', 'stage', 'platform', 'environment', 'reason'].every((key) => text(requirement[key])) &&
          list(requirement.alternatives, text) && requirement.state === 'unknown') || !fieldAssurance(validation.assurance) ||
        !keys(comparison, ['baseProvided', 'kind', 'state', 'semanticallyChanged', 'counts', 'changes', 'unreviewedCount']) ||
        typeof comparison.baseProvided !== 'boolean' || comparison.kind !== (comparison.baseProvided ? 'compare' : 'proposed-create') ||
        typeof comparison.semanticallyChanged !== 'boolean' || !counter(comparison.unreviewedCount) ||
        comparison.state !== (comparison.unreviewedCount === 0 ? 'complete' : 'partial') ||
        !list(comparison.changes, (change) => keys(change, ['path', 'operation', 'before', 'after']) && text(change.path) &&
          typeof change.operation === 'string' && ['add', 'change', 'remove'].includes(change.operation) && summary(change.before) && summary(change.after)) ||
        !keys(comparison.counts, ['added', 'changed', 'removed']) || !Object.values(comparison.counts).every(counter)) return null;
    for (const [operation, count] of [['add', 'added'], ['change', 'changed'], ['remove', 'removed']] as const) {
      if (comparison.counts[count] !== comparison.changes.filter((change) => record(change) && change.operation === operation).length) return null;
    }
    const expected = new Set(catalog.fields.map((field) => field.path));
    if (expected.size !== catalog.fields.length || result.fields.length !== expected.size) return null;
    const contexts = new Map<string, FieldContext>();
    for (const row of result.fields as unknown[]) {
      if (!keys(row, ['path', 'state', 'present', 'reason']) ||
          typeof row.path !== 'string' || !expected.has(row.path) || contexts.has(row.path) ||
          typeof row.state !== 'string' || !['required', 'optional', 'forbidden', 'unknown'].includes(row.state) ||
          typeof row.present !== 'boolean' || !text(row.reason)) return null;
      contexts.set(row.path, { path: row.path, state: row.state as FieldContext['state'], present: row.present, reason: row.reason });
    }
    return { contexts, format: validation.valid ? 'format-valid' : 'invalid', comparison: comparison.unreviewedCount === 0 ? 'complete' : 'partial' };
  } catch { return null; }
}

export function guidedConfiguration(catalog: Pick<Catalog, 'fields'>, session: ProjectSession, selectedProjectId: string | null,
  preview = false): GuidedConfigLayout {
  const review = preview ? null : currentReview(catalog, session, selectedProjectId);
  const contexts = review?.contexts;
  const sections = [...GUIDED_CONFIG_STAGES, 'advanced' as const].map((id): GuidedConfigSection => ({ id, ...descriptions[id],
    fields: [], attention: [], attentionCount: contexts ? 0 : null }));
  const byId = new Map(sections.map((section) => [section.id, section]));
  const attention: GuidedConfigAttention[] = [];
  for (const field of catalog.fields) {
    const group = guidedConfigGroup(field.path), section = byId.get(group)!;
    section.fields.push(field);
    const context = contexts?.get(field.path);
    const kind = context?.state === 'required' && !context.present ? 'missing' :
      context?.state === 'forbidden' && context.present ? 'conflict' : context?.state === 'unknown' ? 'unknown' : null;
    if (kind) {
      const item: GuidedConfigAttention = { field, group, kind };
      section.attention.push(item); attention.push(item);
    }
  }
  for (const section of sections) section.attentionCount = contexts ? section.attention.length : null;
  return { context: preview ? 'example' : contexts ? 'current' : 'needs-review', format: review?.format ?? null, comparison: review?.comparison ?? null,
    contexts: contexts ?? new Map(), sections, attention,
    attentionCount: contexts ? attention.length : null };
}

export function guidedConfigVisibleStage(requested: GuidedConfigStage, pendingField: string | null): GuidedConfigStage {
  const pending = pendingField ? guidedConfigGroup(pendingField) : null;
  return pending && pending !== 'advanced' ? pending : requested;
}
export function guidedConfigSelectStage(current: GuidedConfigStage, requested: GuidedConfigStage, pendingField: string | null): GuidedConfigStage {
  return pendingField ? current : requested;
}
export function guidedConfigFieldMatches(field: FieldHelp, query: string, pendingField: string | null): boolean {
  if (field.path === pendingField) return true;
  const search = query.trim().toLocaleLowerCase();
  return !search || `${field.label} ${field.path} ${field.what}`.toLocaleLowerCase().includes(search);
}
