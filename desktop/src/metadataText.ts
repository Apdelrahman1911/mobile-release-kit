// Public text stays in memory, outside the configuration draft. These renderer
// identities correlate views only; native/core owns paths, bytes and authority.
import { getValue, sameJson } from './catalog.ts';
import { isDirty } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import type { ApiError, Assurance, CoreEditOutcome, EditAvailability, HelpContent, NativeEditReason } from './types.ts';

export type MetadataPlatform = 'android' | 'ios';
export const METADATA_TEXT_IDS = {
  android: ['title.txt', 'short_description.txt', 'full_description.txt'],
  ios: ['description.txt', 'keywords.txt', 'privacy_url.txt', 'support_url.txt', 'release_notes.txt'],
} as const;
export type MetadataFieldId = (typeof METADATA_TEXT_IDS)[MetadataPlatform][number];
export interface MetadataTextField { id: MetadataFieldId; text: string }
export interface MetadataTextDigest { byteLength: number; sha256: string }
export type MetadataTextAssertion = { id: MetadataFieldId; state: 'absent' } |
  ({ id: MetadataFieldId; state: 'present' } & MetadataTextDigest);
export interface MetadataTextBaseline { config: MetadataTextDigest; fields: MetadataTextAssertion[] }
export type MetadataObservedField = { id: MetadataFieldId; path: string; state: 'absent' } |
  ({ id: MetadataFieldId; path: string; state: 'present'; text: string } & MetadataTextDigest);
export interface MetadataTextObservation {
  schemaVersion: 1;
  platform: MetadataPlatform;
  locale: string;
  metadataRoot: string;
  observationScope: 'single-request-non-atomic';
  baseline: MetadataTextBaseline;
  fields: MetadataObservedField[];
  assurance: Assurance & { basis: 'static-text' };
}
export type MetadataIssueCode = 'metadata.empty-text' | 'metadata.nul' | 'metadata.placeholder' | 'metadata.secret-pattern' | 'metadata.url' | 'metadata.length';
export interface MetadataTextIssue { code: MetadataIssueCode; status: 'INVALID' | 'FAIL'; message: string }
export interface MetadataTextValidation {
  schemaVersion: 1;
  platform: MetadataPlatform;
  valid: boolean;
  state: 'format-valid' | 'invalid';
  fields: { id: MetadataFieldId; valid: boolean; characterCount: number; limit: number; issues: MetadataTextIssue[] }[];
  assurance: Assurance & { basis: 'schema-policy' };
}
export type MetadataActionId = 'load' | 'validate' | 'review' | 'save' | 'discard';
export interface MetadataTextGuide {
  schemaVersion: 1;
  fields: (HelpContent & { id: MetadataFieldId; platform: MetadataPlatform; requiredness: 'required' })[];
  actions: (HelpContent & { id: MetadataActionId; requiredness: 'optional' })[];
  limits: { maxTextBytes: 32768; maxCachedLocales: 32; maxCachedTextBytes: 8388608 };
}
export interface MetadataPreparedFile {
  id: MetadataFieldId;
  path: string;
  action: 'create' | 'replace' | 'preserve';
  before: { state: 'absent' } | ({ state: 'present'; text: string } & MetadataTextDigest);
  after: { text: string } & MetadataTextDigest;
  lineEndingsChanged: boolean;
}
export interface PreparedMetadataTextView {
  schemaVersion: 1;
  platform: MetadataPlatform;
  locale: string;
  metadataRoot: string;
  files: MetadataPreparedFile[];
  createDirectories: string[];
  validation: MetadataTextValidation;
}
export interface MetadataTextEditProjection {
  domain: 'metadata_text';
  projectId: string;
  sessionId: string;
  ownerGeneration: string;
  platform: MetadataPlatform;
  locale: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number;
  checkout: { revision: string; metadataRoot: string; baseline: MetadataTextBaseline } | null;
  prepared: { revision: string; planToken: string; draftRevision: number; baselineGeneration: number; view: PreparedMetadataTextView } | null;
  applySubmitted: boolean;
  coreOutcome: CoreEditOutcome | null;
  nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown';
  lateSettled: boolean;
}
export interface MetadataTextEditStatus {
  schemaVersion: 1;
  domain: 'metadata_text';
  windowGeneration: string;
  statusRevision: number;
  capability: { available: boolean; reason: EditAvailability };
  active: MetadataTextEditProjection | null;
  lastTerminal: MetadataTextEditProjection | null;
}
export interface PrepareMetadataTextEditRequest {
  sessionId: string;
  revision: string;
  expectedBaseline: MetadataTextBaseline;
  fields: MetadataTextField[];
  draftRevision: number;
  baselineGeneration: number;
}
export interface MetadataTextApi {
  observeMetadataText(input: { projectId: string; platform: MetadataPlatform; locale: string }): Promise<MetadataTextObservation>;
  validateMetadataText(input: { platform: MetadataPlatform; fields: MetadataTextField[] }): Promise<MetadataTextValidation>;
  openMetadataTextEdit(input: { projectId: string; platform: MetadataPlatform; locale: string }): Promise<MetadataTextEditStatus>;
  prepareMetadataTextEdit(input: PrepareMetadataTextEditRequest): Promise<MetadataTextEditStatus>;
  applyMetadataTextEdit(sessionId: string, planToken: string): Promise<MetadataTextEditStatus>;
  closeMetadataTextEdit(sessionId: string): Promise<MetadataTextEditStatus>;
  metadataTextEditStatus(): Promise<MetadataTextEditStatus>;
  subscribeMetadataTextEdit(onStatus: (status: unknown) => void): Promise<() => void>;
}

export const METADATA_TEXT_CACHE_BUNDLES = 32;
export const METADATA_TEXT_CACHE_BYTES = 8 * 1024 * 1024;
export const METADATA_TEXT_FIELD_BYTES = 32 * 1024;

export interface MetadataConfiguredContext {
  key: string;
  projectId: string;
  metadataRoot: string;
  platform: MetadataPlatform;
  locale: string;
  configBaselineGeneration: number;
}

export interface MetadataDraftBaseline {
  assertion: MetadataTextBaseline;
  originals: { id: MetadataFieldId; path: string; text: string | null }[];
  source: 'observed' | 'saved';
}
export interface MetadataDisplayBinding {
  requestId: number;
  key: string;
  projectId: string;
  configRevision: number;
  configBaselineGeneration: number;
  configObservationGeneration: number;
  serviceGeneration: number;
  selectionGeneration: number;
  draftRevision: number;
  baselineGeneration: number;
  observationGeneration: number;
}
export interface MetadataSavedRevision {
  sessionId: string;
  statusRevision: number;
  draftRevision: number;
  baselineGeneration: number;
  resultingBaselineGeneration: number | null;
  result: 'saved' | 'unchanged';
}
export interface MetadataTextDraft {
  context: MetadataConfiguredContext;
  projectName: string;
  revision: number;
  baselineGeneration: number;
  observationGeneration: number;
  baseline: MetadataDraftBaseline | null;
  fields: MetadataTextField[] | null;
  observation: MetadataTextObservation | null;
  stale: boolean;
  observationPredatesSave: boolean;
  loadRequest: MetadataDisplayBinding | null;
  loadError: ApiError | null;
  editError: ApiError | null;
  validation: { result: MetadataTextValidation; binding: MetadataDisplayBinding } | null;
  validationRequest: MetadataDisplayBinding | null;
  validationError: ApiError | null;
  lastSave: MetadataSavedRevision | null;
}

export function metadataTextDirty(entry: MetadataTextDraft): boolean {
  return Boolean(entry.fields && entry.baseline && entry.fields.some((field) => field.text !== (entry.baseline!.originals.find((row) => row.id === field.id)?.text ?? '')));
}
export function metadataProjectDirty(entries: Readonly<Record<string, MetadataTextDraft>>, projectId?: string): boolean {
  return Object.values(entries).some((entry) => (projectId === undefined || entry.context.projectId === projectId) && metadataTextDirty(entry));
}
export function metadataTextSavedFresh(entry: MetadataTextDraft): boolean {
  return entry.lastSave !== null && entry.lastSave.resultingBaselineGeneration === entry.baselineGeneration && entry.lastSave.draftRevision === entry.revision;
}

// The textarea may display browser-normalized line endings. Its onChange value
// is a new draft, not an excuse to normalize the independently retained original.
export function metadataDraftFields(baseline: MetadataDraftBaseline): MetadataTextField[] {
  return baseline.originals.map(({ id, text }) => ({ id, text: text ?? '' }));
}

export function metadataObservedBaseline(observation: MetadataTextObservation): MetadataDraftBaseline {
  return { assertion: structuredClone(observation.baseline), source: 'observed',
    originals: observation.fields.map((field) => ({ id: field.id, path: field.path, text: field.state === 'present' ? field.text : null })) };
}
export function metadataValidationFresh(entry: MetadataTextDraft): boolean {
  const binding = entry.validation?.binding;
  return Boolean(binding && binding.key === entry.context.key && binding.draftRevision === entry.revision &&
    binding.baselineGeneration === entry.baselineGeneration && binding.observationGeneration === entry.observationGeneration);
}
export function metadataCacheBytes(entries: Readonly<Record<string, MetadataTextDraft>>): number {
  const encoder = new TextEncoder();
  let bytes = 0;
  for (const entry of Object.values(entries)) {
    for (const field of entry.fields ?? []) bytes += encoder.encode(field.text).byteLength;
    for (const field of entry.baseline?.originals ?? []) if (field.text !== null) bytes += encoder.encode(field.text).byteLength;
    for (const field of entry.observation?.fields ?? []) if (field.state === 'present') bytes += encoder.encode(field.text).byteLength;
  }
  return bytes;
}
export function metadataNoOp(view: PreparedMetadataTextView): boolean { return view.files.every((file) => file.action === 'preserve'); }

// Display of raw line-ending styles only, not shared metadata validation. A
// changed textarea can normalize CRLF/CR; this is always reviewed as a change.
export function metadataLineEndings(text: string): string {
  const endings = new Set<string>();
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\r') {
      if (text[index + 1] === '\n') { endings.add('CRLF'); index += 1; }
      else endings.add('CR');
    } else if (text[index] === '\n') endings.add('LF');
  }
  return ['CRLF', 'CR', 'LF'].filter((name) => endings.has(name)).join(' + ') || 'No line endings';
}

// Display saved choices, not a second locale/root validator. The observe and
// native Open requests contain only platform/locale, never this root or a path.
export function metadataConfiguredChoices(session: ProjectSession | null): MetadataConfiguredContext[] {
  if (!session?.baseline) return [];
  const root = getValue(session.baseline, 'metadata.root');
  if (typeof root !== 'string') return [];
  const result: MetadataConfiguredContext[] = [];
  for (const platform of ['android', 'ios'] as const) {
    if (getValue(session.baseline, `${platform}.enabled`) !== true) continue;
    const locales = getValue(session.baseline, `metadata.${platform}Locales`);
    if (!Array.isArray(locales) || locales.length > 250 || !locales.every((locale) => typeof locale === 'string')) continue;
    for (const locale of new Set(locales as string[])) {
      result.push({ key: JSON.stringify([session.project.id, session.baselineGeneration, root, platform, locale]),
        projectId: session.project.id, metadataRoot: root, platform, locale, configBaselineGeneration: session.baselineGeneration });
    }
  }
  return result;
}

export function metadataConfigReason(session: ProjectSession | null): string | null {
  if (!session) return 'Choose a native project, then configure and save its metadata root and enabled locales above.';
  if (session.saveRecoveryRequired) return 'This project needs separate transaction recovery. A text edit cannot clear that block.';
  if (session.snapshotRequest !== null) return 'The configuration observation is changing. Existing text drafts are kept.';
  if (session.sourceChanged) return 'The observed configuration differs from its retained baseline. Reconcile it explicitly in the configuration editor; text drafts are kept in their original contexts.';
  if (!session.baseline || session.snapshot?.config.state !== 'format-valid' && session.lastSave?.resultingBaselineGeneration !== session.baselineGeneration)
    return 'A saved, format-valid release/mobile-release.json is required. Prepare its separate configuration save above; no text save can create configuration.';
  if (isDirty(session) || !sameJson(session.draft, session.baseline)) return 'Save or explicitly discard the configuration draft first. Text operations never implicitly save root, locale or other configuration changes.';
  if (!metadataConfiguredChoices(session).length) return 'Enable a platform and configure at least one locale, then save configuration. No locale or filename is guessed.';
  return null;
}
