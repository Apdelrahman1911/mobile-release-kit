// App-retained observer/draft orchestration. This class never owns a child,
// filesystem handle, journal or write token independently of the native owner.
import { sameJson } from './catalog.ts';
import { methodReason } from './certainty.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { METADATA_TEXT_CACHE_BUNDLES, METADATA_TEXT_CACHE_BYTES, METADATA_TEXT_FIELD_BYTES,
  metadataCacheBytes, metadataConfiguredChoices, metadataConfigReason, metadataDraftFields, metadataObservedBaseline, metadataValidationFresh } from './metadataText.ts';
import type { MetadataConfiguredContext, MetadataDisplayBinding, MetadataDraftBaseline, MetadataFieldId, MetadataTextBaseline, MetadataTextDraft,
  MetadataTextEditProjection, MetadataTextEditStatus, MetadataTextField, MetadataTextGuide } from './metadataText.ts';
import { metadataProjectionProgress, metadataStatusProgress, metadataTextError, metadataTextRequestFits,
  normalMetadataTextResult, parseMetadataTextEditStatus, parseMetadataTextGuide, parseMetadataTextObservation, parseMetadataTextValidation } from './metadataTextProtocol.ts';
import type { ProjectSession } from './drafts.ts';
import type { ApiError, AppInfo, BridgeMode, DesktopApi, EditAvailability, JsonValue } from './types.ts';

export interface MetadataReviewBinding extends MetadataDisplayBinding {
  context: MetadataConfiguredContext;
  windowGeneration: string;
  startStatusRevision: number;
  previousTerminalId: string | null;
  expectedBaseline: MetadataTextBaseline;
  originals: MetadataDraftBaseline['originals'];
  fields: MetadataTextField[];
}
export interface MetadataApplyBinding { sessionId: string; planToken: string; draftRevision: number; baselineGeneration: number }
export interface MetadataDiscardBinding { key: string; revision: number; baselineGeneration: number; observationGeneration: number }
export interface MetadataAttempt {
  binding: MetadataReviewBinding;
  sessionId: string | null;
  projection: MetadataTextEditProjection | null;
  projectionRevision: number;
  prepareClaimed: boolean;
  applyClaimed: boolean;
  submittedPlanToken: string | null;
  closeRequested: boolean;
  closeClaimed: boolean;
  invalidated: boolean;
  handled: boolean;
}
interface MetadataOwnerState {
  mode: BridgeMode;
  listening: boolean;
  initialized: boolean;
  readPending: boolean;
  status: MetadataTextEditStatus | null;
  buffered: MetadataTextEditStatus | null;
  observationIssue: 'bridge' | 'protocol' | null;
  integrityFailed: boolean;
  generationLost: boolean;
  nativeBlocked: boolean;
  unknownEvidence: MetadataTextEditProjection | null;
  recoveryProjects: readonly string[];
  attempt: MetadataAttempt | null;
}
export interface MetadataTextState {
  mode: BridgeMode;
  serviceGeneration: number;
  selectionGeneration: number;
  projectId: string | null;
  choices: MetadataConfiguredContext[];
  selectedKey: string | null;
  entries: Readonly<Record<string, MetadataTextDraft>>;
  observeReason: string | null;
  validateReason: string | null;
  help: MetadataTextGuide | null;
  cacheError: ApiError | null;
  edit: MetadataOwnerState;
}
interface Context {
  selectedProject: () => ProjectSession | null;
  otherEditReason: (projectId: string) => string | null;
  otherOperationReason?: () => string | null;
  now?: () => number;
}
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function same(first: unknown, next: unknown): boolean { return sameJson(first as JsonValue | undefined, next as JsonValue | undefined); }
function uncertain(owner: MetadataTextEditProjection | null): boolean { return owner?.phase === 'unknown' || owner?.nativeFinality === 'unknown'; }
function settled(attempt: MetadataAttempt | null): boolean { return !attempt || attempt.projection?.phase === 'final' && attempt.projection.nativeFinality === 'settled'; }
function usable(state: MetadataOwnerState): boolean {
  return state.mode === 'native' && state.listening && state.initialized && state.status?.capability.available === true &&
    !state.observationIssue && !state.integrityFailed && !state.generationLost && !state.nativeBlocked;
}
const availabilityCopy: Record<EditAvailability, string> = {
  available: 'The separate native metadata writer is available; only explicit confirmation can submit the reviewed bundle.',
  unsupported_platform: 'Text saving needs the separately qualified Linux x86_64 GNU writer. Windows and macOS text mutation are unavailable.',
  runtime_unqualified: 'Text saving is disabled in this build. Loading, editing and validation do not mean the separate text-file writer has been verified.',
  cleanup_unknown: 'Original native cleanup is unverified. Keep the draft and operation evidence; no competing edit or repeated Apply is permitted.',
  shutdown: 'The native application is stopping. No new text edit can be opened.',
  other_edit_active: 'A configuration or workflow edit owns the shared native service. Finish or close that original session first.',
};
export function metadataOwnerReason(state: MetadataTextState, projectId: string): string | null {
  const owner = state.edit;
  if (owner.nativeBlocked || owner.integrityFailed || owner.generationLost || owner.observationIssue) return 'Metadata edit ownership is unverified. Observe the original native status, not a competing edit.';
  if (owner.status?.active || !settled(owner.attempt) || owner.attempt && !owner.attempt.handled) return 'A metadata-text edit is still owned or awaiting settlement. Finish or close that original session before another file edit.';
  if (owner.recoveryProjects.includes(projectId)) return 'This project needs separate metadata transaction recovery. Another edit domain cannot reset or bypass its journal.';
  return null;
}
export function metadataRetainsDraft(state: MetadataTextState, projectId: string): boolean {
  const edit = state.edit;
  return edit.attempt?.binding.projectId === projectId && (!settled(edit.attempt) || edit.integrityFailed || edit.nativeBlocked || edit.observationIssue !== null) ||
    edit.status?.active?.projectId === projectId || edit.unknownEvidence?.projectId === projectId;
}
export function metadataPreparedMatches(attempt: MetadataAttempt): boolean {
  const owner = attempt.projection; const prepared = owner?.prepared; const binding = attempt.binding;
  return Boolean(owner?.checkout && prepared && owner.domain === 'metadata_text' && owner.projectId === binding.projectId && owner.sessionId === attempt.sessionId &&
    owner.ownerGeneration === binding.windowGeneration && owner.platform === binding.context.platform && owner.locale === binding.context.locale &&
    owner.checkout.metadataRoot === binding.context.metadataRoot && same(owner.checkout.baseline, binding.expectedBaseline) &&
    prepared.revision === owner.checkout.revision && prepared.draftRevision === binding.draftRevision && prepared.baselineGeneration === binding.baselineGeneration &&
    prepared.view.files.every((file, index) => file.id === binding.fields[index]?.id && file.after.text === binding.fields[index]?.text &&
      file.path === binding.originals[index]?.path && (file.before.state === 'present' ? file.before.text : null) === binding.originals[index]?.text));
}
export function currentMetadataApplyBinding(state: MetadataTextState): MetadataApplyBinding | null {
  const edit = state.edit; const attempt = edit.attempt; const owner = attempt?.projection;
  if (!usable(edit) || !attempt || !owner?.prepared || !attempt.prepareClaimed || attempt.applyClaimed || attempt.closeRequested || attempt.invalidated || attempt.handled ||
      owner.phase !== 'reviewing' || owner.nativeReason !== 'none' || owner.nativeFinality !== 'pending' || owner.reviewRemainingMs === 0 || owner.applySubmitted ||
      !metadataPreparedMatches(attempt) || edit.status?.active?.sessionId !== owner.sessionId || owner.ownerGeneration !== edit.status.windowGeneration) return null;
  return { sessionId: owner.sessionId, planToken: owner.prepared.planToken, draftRevision: attempt.binding.draftRevision, baselineGeneration: attempt.binding.baselineGeneration };
}

export class MetadataTextEditController {
  private state: MetadataTextState = freeze<MetadataTextState>({
    mode: 'unavailable', serviceGeneration: 0, selectionGeneration: 0, projectId: null, choices: [], selectedKey: null, entries: {},
    observeReason: 'Desktop capabilities are not loaded.', validateReason: 'Desktop capabilities are not loaded.', help: null, cacheError: null,
    edit: { mode: 'unavailable', listening: false, initialized: false, readPending: false, status: null, buffered: null, observationIssue: null,
      integrityFailed: false, generationLost: false, nativeBlocked: false, unknownEvidence: null, recoveryProjects: [], attempt: null },
  });
  private readonly context: Context;
  private api: DesktopApi | null = null;
  private passiveApi: DesktopApi | null = null;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private fingerprint = '';
  private nextRequest = 0;
  private passivePending = 0;
  private processing = false;
  private processAgain = false;
  private disposed = false;
  private selectionPending = false;
  private deadline: { sessionId: string; at: number } | null = null;

  constructor(context: Context) { this.context = context; }
  getSnapshot = (): MetadataTextState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(next: MetadataTextState): void {
    if (this.disposed || next === this.state) return;
    this.state = freeze(next);
    for (const listener of this.listeners) listener();
  }
  private edit(next: MetadataOwnerState): void { this.publish({ ...this.state, edit: next }); }
  private attempt(patch: Partial<MetadataAttempt>): void {
    if (this.state.edit.attempt) this.edit({ ...this.state.edit, attempt: { ...this.state.edit.attempt, ...patch } });
  }
  private put(entry: MetadataTextDraft): boolean {
    const entries = { ...this.state.entries, [entry.context.key]: entry };
    if (Object.keys(entries).length > METADATA_TEXT_CACHE_BUNDLES || metadataCacheBytes(entries) > METADATA_TEXT_CACHE_BYTES) {
      this.publish({ ...this.state, cacheError: metadataTextError({ code: 'MetadataTextCacheFull' }) }); return false;
    }
    this.publish({ ...this.state, entries, cacheError: null }); return true;
  }
  private now(): number { return this.context.now?.() ?? performance.now(); }
  remainingReviewMs(): number {
    const owner = this.state.edit.attempt?.projection;
    return owner && this.deadline?.sessionId === owner.sessionId ? Math.max(0, Math.min(owner.reviewRemainingMs, this.deadline.at - this.now())) : 0;
  }
  private counter(): number | null {
    if (this.nextRequest >= U32_MAX) return null;
    this.nextRequest += 1; return this.nextRequest;
  }
  private retirePassive(): void {
    const entries = { ...this.state.entries };
    for (const [key, entry] of Object.entries(entries)) if (entry.loadRequest || entry.validationRequest) entries[key] = {
      ...entry, loadRequest: null, validationRequest: null,
      loadError: entry.loadRequest ? metadataTextError({ code: 'MetadataTextContextChanged' }) : entry.loadError,
      validationError: entry.validationRequest ? metadataTextError({ code: 'MetadataTextContextChanged' }) : entry.validationError,
    };
    this.publish({ ...this.state, entries });
  }
  beginConnection(): void {
    this.passiveApi = null;
    this.publish({ ...this.state, mode: 'unavailable', help: null,
      serviceGeneration: Math.min(U32_MAX, this.state.serviceGeneration + 1), observeReason: 'The service context is being reloaded.', validateReason: 'The service context is being reloaded.' });
    this.retirePassive(); this.process();
  }
  setConnection(api: DesktopApi, info: AppInfo): void {
    if (this.disposed) return;
    this.passiveApi = api;
    this.publish({ ...this.state, mode: api.mode, observeReason: methodReason(info, 'metadata.text.observe', api.mode), validateReason: methodReason(info, 'metadata.text.validate', api.mode) });
    this.syncProject(); this.process();
  }
  setHelp(guide: unknown): void {
    const help = parseMetadataTextGuide(guide);
    this.publish({ ...this.state, help: help ? structuredClone(help) : null });
    this.process();
  }
  setSelectionPending(value: boolean): void {
    if (this.disposed || value === this.selectionPending) return;
    this.selectionPending = value;
    this.publish({ ...this.state, selectionGeneration: Math.min(U32_MAX, this.state.selectionGeneration + 1) });
    this.retirePassive(); this.process();
  }
  syncProject = (): void => {
    if (this.disposed) return;
    const session = this.context.selectedProject(); const choices = metadataConfiguredChoices(session);
    const fingerprint = JSON.stringify([session?.project.id, session?.revision, session?.baselineGeneration, session?.observationGeneration,
      session?.snapshotRequest, session?.sourceChanged, session?.saveRecoveryRequired, metadataConfigReason(session), choices]);
    if (fingerprint !== this.fingerprint) {
      this.fingerprint = fingerprint;
      const sameProject = session?.project.id === this.state.projectId;
      const old = this.state.selectedKey;
      const selectedKey = sameProject && old && (choices.some((choice) => choice.key === old) || Object.hasOwn(this.state.entries, old)) ? old : choices[0]?.key ?? null;
      this.publish({ ...this.state, projectId: session?.project.id ?? null, choices, selectedKey,
        selectionGeneration: Math.min(U32_MAX, this.state.selectionGeneration + 1) });
      this.retirePassive();
    }
    this.process();
  };
  selectContext(key: string): boolean {
    if (this.disposed || key === this.state.selectedKey || !this.state.choices.some((choice) => choice.key === key) &&
        (!Object.hasOwn(this.state.entries, key) || this.state.entries[key]?.context.projectId !== this.state.projectId)) return false;
    this.publish({ ...this.state, selectedKey: key, selectionGeneration: Math.min(U32_MAX, this.state.selectionGeneration + 1), cacheError: null });
    this.retirePassive(); this.process(); return true;
  }
  selectedEntry(): MetadataTextDraft | null { return this.state.selectedKey ? this.state.entries[this.state.selectedKey] ?? null : null; }
  private selectedContext(): MetadataConfiguredContext | null {
    return this.state.choices.find((choice) => choice.key === this.state.selectedKey) ?? this.selectedEntry()?.context ?? null;
  }
  private liveContextReason(): string | null {
    if (this.selectionPending) return 'A native project selection is pending. Earlier metadata authority is retired; drafts remain in memory.';
    const config = metadataConfigReason(this.context.selectedProject());
    if (config) return config;
    if (!this.state.selectedKey || !this.state.choices.some((choice) => choice.key === this.state.selectedKey)) return 'This is a retained earlier configuration/locale context. Its draft has not moved. Select a currently saved locale to load or save text.';
    if ([this.state.serviceGeneration, this.state.selectionGeneration, this.nextRequest].some((counter) => counter >= U32_MAX)) return 'A metadata binding counter is exhausted. No generation or request ID will be reused.';
    return null;
  }
  passiveBusyReason(): string | null { return this.passivePending > 0 ? 'An original public-text observation or validation is still pending.' : null; }
  loadReason(): string | null {
    const other = this.context.otherOperationReason?.(); if (other) return other;
    return this.state.mode !== 'native' ? metadataTextError(null).message : this.state.observeReason ?? (!this.state.help ? metadataTextError({ code: 'MetadataTextHelpUnavailable' }).message : null) ??
      this.liveContextReason() ?? (this.passivePending >= 2 ? 'Two bounded passive requests are already in flight. Wait for them to settle; no queue or replacement request is created.' : null) ??
      (this.selectedEntry()?.loadRequest ? 'The original text observation is still pending.' : null);
  }
  validateReason(): string | null {
    const other = this.context.otherOperationReason?.(); if (other) return other;
    if (this.state.mode !== 'native') return metadataTextError(null).message;
    if (this.state.validateReason) return this.state.validateReason;
    if (!this.state.help) return metadataTextError({ code: 'MetadataTextHelpUnavailable' }).message;
    const entry = this.selectedEntry();
    if (!entry?.fields || !entry.baseline) return 'Load the selected locale’s public text first. Unsafe or withheld files never become blank replacement permission.';
    if (this.passivePending >= 2 || entry.validationRequest) return 'A bounded validation/observation is pending. Keep editing or wait; no duplicate validation is sent.';
    return null;
  }
  private binding(entry: MetadataTextDraft): MetadataDisplayBinding | null {
    const project = this.context.selectedProject(); const requestId = this.counter();
    if (!project || requestId === null || ![entry.revision, entry.baselineGeneration, entry.observationGeneration, project.revision, project.baselineGeneration, project.observationGeneration,
      this.state.serviceGeneration, this.state.selectionGeneration].every((counter) => isU32(counter) && counter < U32_MAX)) return null;
    return { requestId, key: entry.context.key, projectId: project.project.id, configRevision: project.revision,
      configBaselineGeneration: project.baselineGeneration, configObservationGeneration: project.observationGeneration,
      serviceGeneration: this.state.serviceGeneration, selectionGeneration: this.state.selectionGeneration,
      draftRevision: entry.revision, baselineGeneration: entry.baselineGeneration, observationGeneration: entry.observationGeneration };
  }
  private matches(binding: MetadataDisplayBinding): boolean {
    const project = this.context.selectedProject(); const entry = this.state.entries[binding.key];
    return this.state.mode === 'native' && Boolean(project && entry && this.state.selectedKey === binding.key && project.project.id === binding.projectId &&
      project.revision === binding.configRevision && project.baselineGeneration === binding.configBaselineGeneration && project.observationGeneration === binding.configObservationGeneration &&
      this.state.serviceGeneration === binding.serviceGeneration && this.state.selectionGeneration === binding.selectionGeneration &&
      entry.revision === binding.draftRevision && entry.baselineGeneration === binding.baselineGeneration && entry.observationGeneration === binding.observationGeneration);
  }
  validationCurrent(entry: MetadataTextDraft): boolean { return metadataValidationFresh(entry) && Boolean(entry.validation && this.matches(entry.validation.binding)); }
  async load(): Promise<boolean> {
    if (this.disposed || !this.passiveApi || this.loadReason() !== null) return false;
    const context = this.selectedContext(); const project = this.context.selectedProject();
    if (!context || !project) return false;
    const previous = this.state.entries[context.key];
    const entry: MetadataTextDraft = previous ? { ...previous, observationGeneration: previous.observationGeneration + 1 } : {
      context, projectName: project.project.name, revision: 0, baselineGeneration: 0, observationGeneration: 1,
      baseline: null, fields: null, observation: null, stale: false, observationPredatesSave: false, loadRequest: null, loadError: null,
      editError: null, validation: null, validationRequest: null, validationError: null, lastSave: null,
    };
    const binding = this.binding(entry); if (!binding) return false;
    const api = this.passiveApi; this.passivePending += 1;
    try {
      // Claim before publication: subscribers may retire the display binding,
      // but cannot erase this original request from reciprocal admission.
      if (!this.put({ ...entry, loadRequest: binding, loadError: null, validationRequest: null })) return false;
      this.process();
      const value = parseMetadataTextObservation(await api.observeMetadataText({ projectId: context.projectId, platform: context.platform, locale: context.locale }));
      if (this.disposed || this.state.entries[context.key]?.loadRequest?.requestId !== binding.requestId) return false;
      if (!this.matches(binding)) throw { code: 'MetadataTextContextChanged' };
      if (!value || value.platform !== context.platform || value.locale !== context.locale) throw { code: 'MetadataTextResponseInvalid' };
      if (value.metadataRoot !== context.metadataRoot) throw { code: 'MetadataTextContextChanged' };
      const current = this.state.entries[context.key]!;
      const baseline = current.baseline ?? metadataObservedBaseline(value);
      const accepted = this.put({ ...current, baseline, fields: current.fields ?? metadataDraftFields(baseline), observation: structuredClone(value),
        stale: !same(baseline.assertion, value.baseline), observationPredatesSave: false, loadRequest: null, loadError: null });
      if (!accepted) this.put({ ...current, loadRequest: null, loadError: metadataTextError({ code: 'MetadataTextCacheFull' }) });
      return accepted;
    } catch (error) {
      const current = this.state.entries[context.key];
      if (!this.disposed && current?.loadRequest?.requestId === binding.requestId) this.put({ ...current, loadRequest: null, loadError: metadataTextError(error), stale: current.baseline !== null });
      return false;
    } finally { this.passivePending -= 1; if (!this.disposed) { this.publish({ ...this.state }); this.process(); } }
  }
  editField(key: string, id: MetadataFieldId, text: string): boolean {
    const entry = this.state.entries[key];
    if (this.disposed || !entry?.fields || entry.revision >= U32_MAX - 1 || !entry.fields.some((field) => field.id === id)) return false;
    if (typeof text !== 'string' || /[\ud800-\udfff]/u.test(text) || new TextEncoder().encode(text).byteLength > METADATA_TEXT_FIELD_BYTES) {
      this.put({ ...entry, editError: metadataTextError({ code: 'MetadataTextDraftLimit' }) }); return false;
    }
    if (entry.fields.find((field) => field.id === id)?.text === text) return false;
    const accepted = this.put({ ...entry, revision: entry.revision + 1, fields: entry.fields.map((field) => field.id === id ? { id, text } : field), editError: null,
      loadRequest: null, validationRequest: null, validationError: null });
    this.process(); return accepted;
  }
  async validate(): Promise<boolean> {
    if (this.disposed || !this.passiveApi || this.validateReason() !== null) return false;
    const entry = this.selectedEntry(); if (!entry?.fields) return false;
    const binding = this.binding(entry); if (!binding) return false;
    const api = this.passiveApi; const fields = structuredClone(entry.fields);
    this.passivePending += 1;
    try {
      if (!this.put({ ...entry, validationRequest: binding, validationError: null })) return false;
      const result = parseMetadataTextValidation(await api.validateMetadataText({ platform: entry.context.platform, fields }));
      const current = this.state.entries[entry.context.key];
      if (this.disposed || current?.validationRequest?.requestId !== binding.requestId) return false;
      if (!this.matches(binding)) throw { code: 'MetadataTextContextChanged' };
      if (!result || result.platform !== entry.context.platform) throw { code: 'MetadataTextResponseInvalid' };
      return this.put({ ...current, validation: { result: structuredClone(result), binding }, validationRequest: null, validationError: null });
    } catch (error) {
      const current = this.state.entries[entry.context.key];
      if (!this.disposed && current?.validationRequest?.requestId === binding.requestId) this.put({ ...current, validationRequest: null, validationError: metadataTextError(error) });
      return false;
    } finally { this.passivePending -= 1; if (!this.disposed) this.publish({ ...this.state }); }
  }
  discardBinding(key: string): MetadataDiscardBinding | null {
    const entry = this.state.entries[key];
    return entry ? { key, revision: entry.revision, baselineGeneration: entry.baselineGeneration, observationGeneration: entry.observationGeneration } : null;
  }
  discardReason(key: string): string | null {
    const entry = this.state.entries[key];
    if (!entry) return 'The retained draft no longer exists.';
    if (metadataRetainsDraft(this.state, entry.context.projectId)) return 'Keep text drafts until the original metadata owner is settled. Close review is separate from discarding text.';
    return null;
  }
  discard(binding: MetadataDiscardBinding, action: 'forget' | 'latest' | 'reset'): boolean {
    const entry = this.state.entries[binding.key];
    if (this.disposed || !entry || this.discardReason(binding.key) || !same(this.discardBinding(binding.key), binding)) return false;
    if (action === 'forget') {
      const entries = { ...this.state.entries }; delete entries[binding.key];
      const selectedKey = this.state.selectedKey === binding.key && !this.state.choices.some((choice) => choice.key === binding.key) ? this.state.choices[0]?.key ?? null : this.state.selectedKey;
      this.publish({ ...this.state, entries, selectedKey, cacheError: null, selectionGeneration: Math.min(U32_MAX, this.state.selectionGeneration + 1) });
      this.process(); return true;
    }
    if (entry.revision >= U32_MAX - 1 || entry.baselineGeneration >= U32_MAX - 1 || entry.loadRequest ||
        action === 'latest' && (!entry.observation || entry.observationPredatesSave || this.liveContextReason())) return false;
    const baseline = action === 'latest' && entry.observation ? metadataObservedBaseline(entry.observation) : entry.baseline;
    if (!baseline) return false;
    const accepted = this.put({ ...entry, baseline, baselineGeneration: entry.baselineGeneration + 1, revision: entry.revision + 1,
      fields: metadataDraftFields(baseline), stale: action === 'latest' ? false : entry.stale, editError: null,
      validation: null, validationRequest: null, validationError: null, loadRequest: null, loadError: null });
    this.process(); return accepted;
  }

  async connect(api: DesktopApi): Promise<void> {
    if (this.disposed || this.api) return;
    this.api = api; this.edit({ ...this.state.edit, mode: api.mode });
    if (api.mode === 'native') await this.checkStatus();
  }
  async checkStatus(): Promise<void> {
    if (this.disposed || !this.api || this.api.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api;
    const work = Promise.resolve().then(async () => {
      try {
        if (!this.unlisten) {
          const unlisten = await api.subscribeMetadataTextEdit((value) => this.receive(value, 'event'));
          if (this.disposed) { unlisten(); return; }
          this.unlisten = unlisten; this.edit({ ...this.state.edit, listening: true });
        }
        if (!this.disposed) this.receive(await api.metadataTextEditStatus(), 'read');
      } catch (error) {
        if (!this.disposed) this.observationFailed(metadataTextError(error).code === 'MetadataTextStatusInvalid');
      }
    });
    this.reading = work; this.edit({ ...this.state.edit, readPending: true });
    try { await work; } finally { if (this.reading === work) this.reading = null; }
  }
  private observationFailed(protocol: boolean): void {
    this.edit({ ...this.state.edit, readPending: false, integrityFailed: this.state.edit.integrityFailed || protocol,
      observationIssue: protocol || this.state.edit.integrityFailed ? 'protocol' : 'bridge' });
    if (protocol) this.requestRetire('invoke_failed');
    this.process();
  }
  private receive(value: unknown, source: 'read' | 'event' | 'reply'): void {
    if (this.disposed) return;
    const parsed = parseMetadataTextEditStatus(value);
    if (!parsed) { this.observationFailed(true); return; }
    let status = freeze(structuredClone(parsed)); let edit = this.state.edit;
    for (const owner of [status.active, status.lastTerminal]) {
      if (owner && uncertain(owner)) edit = { ...edit, nativeBlocked: true, unknownEvidence: edit.unknownEvidence ?? owner };
      if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && owner.coreOutcome?.journal === 'recovery_required' && !edit.recoveryProjects.includes(owner.projectId)) {
        if (edit.recoveryProjects.length >= 64) { this.observationFailed(true); return; }
        edit = { ...edit, recoveryProjects: [...edit.recoveryProjects, owner.projectId] };
      }
    }
    if (status.capability.reason === 'cleanup_unknown') edit = { ...edit, nativeBlocked: true };
    edit = { ...edit, readPending: source === 'read' ? false : edit.readPending };
    if (!edit.initialized && source !== 'read') {
      this.edit({ ...edit, buffered: !edit.buffered || status.statusRevision >= edit.buffered.statusRevision ? status : edit.buffered }); return;
    }
    if (!edit.initialized && edit.buffered) {
      if (edit.buffered.windowGeneration !== status.windowGeneration) edit = { ...edit, generationLost: true };
      else {
        const first = edit.buffered.statusRevision <= status.statusRevision ? edit.buffered : status;
        const next = first === status ? edit.buffered : status;
        if (!metadataStatusProgress(first, next)) { this.observationFailed(true); return; }
        if (edit.buffered.statusRevision > status.statusRevision) status = edit.buffered;
      }
    }
    edit = { ...edit, generationLost: edit.generationLost || Boolean(edit.status && edit.status.windowGeneration !== status.windowGeneration) };
    let attempt = edit.attempt;
    if (attempt) {
      const retained = attempt;
      const owner = [status.active, status.lastTerminal].find((row) => row && row.projectId === retained.binding.projectId && row.ownerGeneration === retained.binding.windowGeneration &&
        row.platform === retained.binding.context.platform && row.locale === retained.binding.context.locale &&
        (retained.sessionId ? row.sessionId === retained.sessionId : status.statusRevision > retained.binding.startStatusRevision && row.sessionId !== retained.binding.previousTerminalId));
      if (owner) {
        const older = status.statusRevision < attempt.projectionRevision;
        if (attempt.projection && !(older ? metadataProjectionProgress(owner, attempt.projection) : metadataProjectionProgress(attempt.projection, owner))) { this.observationFailed(true); return; }
        if (!older) {
          const projection = attempt.projection ? { ...owner, reviewRemainingMs: Math.min(attempt.projection.reviewRemainingMs, owner.reviewRemainingMs) } : owner;
          attempt = { ...attempt, sessionId: owner.sessionId, projectionRevision: status.statusRevision, projection };
          const at = this.now() + projection.reviewRemainingMs;
          this.deadline = { sessionId: owner.sessionId, at: this.deadline?.sessionId === owner.sessionId ? Math.min(this.deadline.at, at) : at };
        }
      }
    }
    if (edit.status && status.statusRevision < edit.status.statusRevision) {
      if (!metadataStatusProgress(status, edit.status)) { this.observationFailed(true); return; }
      this.edit({ ...edit, attempt }); this.process(); return;
    }
    if (edit.status && !metadataStatusProgress(edit.status, status)) { this.observationFailed(true); return; }
    this.edit({ ...edit, attempt, initialized: true, status, buffered: null, observationIssue: edit.integrityFailed ? 'protocol' : null });
    this.process();
  }
  startReason(): string | null {
    const edit = this.state.edit;
    if (edit.mode !== 'native') return metadataTextError(null).message;
    if (edit.integrityFailed || edit.generationLost || edit.nativeBlocked || edit.observationIssue) return 'Native metadata authority or settlement is unverified. Check the original status; do not open a replacement review.';
    if (!edit.listening || !edit.initialized || !edit.status) return 'Loading the separate native metadata capability and original-owner status…';
    if (!edit.status.capability.available) return availabilityCopy[edit.status.capability.reason];
    if (edit.status.statusRevision >= U32_MAX) return 'The native status counter is exhausted; no sequence will be reused.';
    const project = this.context.selectedProject();
    const other = project ? this.context.otherEditReason(project.project.id) : null;
    if (other) return other;
    const owned = metadataOwnerReason(this.state, project?.project.id ?? ''); if (owned) return owned;
    if (this.state.mode !== 'native' || this.state.observeReason || this.state.validateReason || !this.state.help) return 'Reload the compatible native service and public-text guide before starting a save review.';
    const live = this.liveContextReason(); if (live) return live;
    const entry = this.selectedEntry();
    if (!entry?.baseline || !entry.fields) return 'Load the selected public locale text before preparing its native save review.';
    if (entry.stale || entry.loadError || entry.loadRequest) return 'The text baseline is stale, unavailable or being observed. Load and explicitly reconcile it without replacing your draft automatically.';
    if (!this.validationCurrent(entry) || !entry.validation?.result.valid) return 'Validate this exact text revision with the core and correct every field before requesting a save review.';
    return null;
  }
  start(): boolean {
    if (this.disposed || !this.api || this.startReason() !== null) return false;
    const entry = this.selectedEntry(); const status = this.state.edit.status;
    if (!entry?.baseline || !entry.fields || !status) return false;
    const display = this.binding(entry); if (!display) return false;
    const binding: MetadataReviewBinding = freeze({ ...display, context: structuredClone(entry.context), windowGeneration: status.windowGeneration,
      startStatusRevision: status.statusRevision, previousTerminalId: status.lastTerminal?.sessionId ?? null,
      expectedBaseline: structuredClone(entry.baseline.assertion), originals: structuredClone(entry.baseline.originals), fields: structuredClone(entry.fields) });
    this.edit({ ...this.state.edit, attempt: { binding, sessionId: null, projection: null, projectionRevision: status.statusRevision,
      prepareClaimed: false, applyClaimed: false, submittedPlanToken: null, closeRequested: false, closeClaimed: false, invalidated: false, handled: false } });
    // Synchronous claim precedes invoke, blocking both other edit domains.
    if (this.state.edit.attempt?.binding !== binding) return false;
    void this.command('open', binding, () => this.api!.openMetadataTextEdit({ projectId: binding.projectId, platform: binding.context.platform, locale: binding.context.locale }));
    return true;
  }
  canApply(binding?: MetadataApplyBinding): boolean {
    const current = currentMetadataApplyBinding(this.state); const attempt = this.state.edit.attempt;
    return Boolean(current && attempt && this.remainingReviewMs() > 0 && this.matches(attempt.binding) && !this.liveContextReason() &&
      !this.context.otherEditReason(attempt.binding.projectId) && (!binding || same(current, binding)) && same(this.selectedEntry()?.fields, attempt.binding.fields));
  }
  apply(binding: MetadataApplyBinding): boolean {
    if (this.disposed || !this.api || !this.canApply(binding)) return false;
    const original = this.state.edit.attempt!.binding;
    this.attempt({ applyClaimed: true, submittedPlanToken: binding.planToken });
    if (this.state.edit.attempt?.binding === original && !this.state.edit.attempt.closeRequested)
      void this.command('apply', original, () => this.api!.applyMetadataTextEdit(binding.sessionId, binding.planToken));
    return true;
  }
  requestClose(): void { if (!this.disposed) { this.requestRetire('user'); this.process(); } }
  private requestRetire(reason: 'user' | 'context_changed' | 'invoke_failed'): void {
    const attempt = this.state.edit.attempt;
    if (!attempt || attempt.handled || settled(attempt) || attempt.closeRequested || attempt.applyClaimed && reason !== 'user') return;
    this.attempt({ closeRequested: true, invalidated: attempt.invalidated || reason === 'context_changed' });
  }
  private adoptSave(attempt: MetadataAttempt): void {
    const owner = attempt.projection; const entry = this.state.entries[attempt.binding.key]; const result = owner ? normalMetadataTextResult(owner) : null;
    if (!owner?.prepared || !entry || !result || !attempt.applyClaimed || attempt.submittedPlanToken !== owner.prepared.planToken || !metadataPreparedMatches(attempt) ||
        this.state.edit.integrityFailed || this.state.edit.observationIssue || entry.lastSave && (entry.lastSave.sessionId === owner.sessionId || entry.lastSave.statusRevision >= attempt.projectionRevision)) return;
    const matches = entry.revision === attempt.binding.draftRevision && entry.baselineGeneration === attempt.binding.baselineGeneration &&
      entry.observationGeneration === attempt.binding.observationGeneration && same(entry.fields, attempt.binding.fields) && same(entry.baseline?.assertion, attempt.binding.expectedBaseline);
    const generation = matches && result === 'saved' ? entry.baselineGeneration + 1 : entry.baselineGeneration;
    const baseline: MetadataDraftBaseline | null = matches ? { source: 'saved', assertion: {
      config: structuredClone(attempt.binding.expectedBaseline.config),
      fields: owner.prepared.view.files.map((file) => ({ id: file.id, state: 'present' as const, byteLength: file.after.byteLength, sha256: file.after.sha256 })),
    }, originals: owner.prepared.view.files.map((file) => ({ id: file.id, path: file.path, text: file.after.text })) } : entry.baseline;
    // Only exact submitted text can advance its own baseline. Newer drafts and
    // all configuration JSON are untouched; this is not a fabricated read.
    const candidate: MetadataTextDraft = { ...entry, baseline, baselineGeneration: generation, observationPredatesSave: true, stale: !matches,
      loadRequest: null, validationRequest: null, lastSave: { sessionId: owner.sessionId, statusRevision: attempt.projectionRevision,
        draftRevision: attempt.binding.draftRevision, baselineGeneration: attempt.binding.baselineGeneration,
        resultingBaselineGeneration: matches ? generation : null, result } };
    if (!this.put(candidate)) {
      // A real commit must not silently evict other cached text just to retain
      // a larger baseline. Keep its outcome and old draft for reconciliation.
      this.put({ ...entry, observationPredatesSave: true, stale: true, loadRequest: null, validationRequest: null,
        lastSave: { ...candidate.lastSave!, resultingBaselineGeneration: null }, editError: metadataTextError({ code: 'MetadataTextCacheFull' }) });
    }
  }
  private process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.processAgain = true; return; }
    this.processing = true;
    try {
      do {
        this.processAgain = false;
        let attempt = this.state.edit.attempt; if (!attempt) continue;
        let owner = attempt.projection;
        if (!attempt.applyClaimed && !attempt.handled && !['final', 'unknown'].includes(owner?.phase ?? '') &&
            (this.state.edit.generationLost || !this.matches(attempt.binding) || this.liveContextReason() || !this.state.help)) this.requestRetire('context_changed');
        if (owner?.prepared && !metadataPreparedMatches(attempt) && !this.state.edit.integrityFailed) this.observationFailed(true);
        attempt = this.state.edit.attempt; if (!attempt) continue;
        owner = attempt.projection;
        if (owner?.phase === 'final' && owner.nativeFinality === 'settled' && !attempt.handled) {
          this.adoptSave(attempt); this.attempt({ handled: true });
        }
        attempt = this.state.edit.attempt;
        if (!attempt || attempt.handled || !attempt.sessionId || !attempt.projection || this.state.edit.generationLost ||
            attempt.projection.ownerGeneration !== this.state.edit.status?.windowGeneration || ['final', 'unknown'].includes(attempt.projection.phase)) continue;
        const sessionId = attempt.sessionId; const binding = attempt.binding;
        if (attempt.closeRequested && !attempt.closeClaimed) {
          this.attempt({ closeClaimed: true });
          void this.command('close', binding, () => this.api!.closeMetadataTextEdit(sessionId)); continue;
        }
        if (attempt.projection.phase === 'editing' && attempt.projection.checkout && !attempt.prepareClaimed && !attempt.applyClaimed && !attempt.closeRequested && !attempt.invalidated && usable(this.state.edit)) {
          const revision = attempt.projection.checkout.revision;
          const request = { sessionId, revision, expectedBaseline: binding.expectedBaseline, fields: binding.fields,
            draftRevision: binding.draftRevision, baselineGeneration: binding.baselineGeneration };
          if (!metadataTextRequestFits('metadata_text_edit_prepare', request)) { this.observationFailed(true); continue; }
          this.attempt({ prepareClaimed: true });
          if (this.state.edit.attempt?.binding === binding && !this.state.edit.attempt.closeRequested)
            void this.command('prepare', binding, () => this.api!.prepareMetadataTextEdit(request));
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }
  private async command(kind: 'open' | 'prepare' | 'apply' | 'close', binding: MetadataReviewBinding, call: () => Promise<MetadataTextEditStatus>): Promise<void> {
    try { this.receive(await call(), 'reply'); }
    catch (error) {
      const attempt = this.state.edit.attempt;
      if (this.disposed || attempt?.binding !== binding || settled(attempt)) return;
      const protocol = metadataTextError(error).code === 'MetadataTextStatusInvalid';
      this.observationFailed(protocol);
      if (kind === 'open' || kind === 'prepare' || protocol) this.requestRetire('invoke_failed');
      this.process();
      // One status observation only: a missing reply never resends a mutation.
      await this.checkStatus();
    }
  }
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    const attempt = this.state.edit.attempt;
    if (this.api?.mode === 'native' && attempt?.sessionId && attempt.projection && !attempt.closeClaimed && !this.state.edit.generationLost &&
        attempt.projection.ownerGeneration === this.state.edit.status?.windowGeneration && !['final', 'unknown'].includes(attempt.projection.phase)) {
      try { void this.api.closeMetadataTextEdit(attempt.sessionId).catch(() => { /* Original native owner retains cleanup/finality. */ }); }
      catch { /* No retry or successful completion claim on renderer disposal. */ }
    }
    try { this.unlisten?.(); } catch { /* Observer disposal is not native settlement. */ }
    this.unlisten = null; this.listeners.clear(); this.passiveApi = null;
  }
}
