// One app-retained image selection/review. This orchestrates existing native
// owners; it never creates a transaction, owns source bytes or retries a write.
import { sameJson } from './catalog.ts';
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { imageConfigReason, imageConfiguredChoices, imageProjectBinding } from './metadataImagesContext.ts';
import type { ImageConfiguredContext, ImageProjectBinding } from './metadataImagesContext.ts';
import type { MetadataConfiguredContext, MetadataPlatform } from './metadataText.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { ApiError, BridgeMode, JsonValue } from './types.ts';
import type { MetadataImagesApi, MetadataImagesCatalog, MetadataImagesEditProjection, MetadataImagesEditStatus,
  MetadataImagesSelection, MetadataImagesSelectionStatus, MetadataImageChoice, PrepareMetadataImagesRequest } from './metadataImages.ts';
import { imageCatalogTypes, imageSelectionSettled, imagePreparedMatches, metadataImagesEditProgress,
  metadataImagesSelectionProgress, metadataImagesError, metadataImagesRequestFits, normalMetadataImagesResult,
  parseMetadataImagesCatalog, parseMetadataImagesEditStatus, parseMetadataImagesSelectionStatus } from './metadataImagesProtocol.ts';

interface ImageAttemptBinding extends ImageProjectBinding {
  serial: number;
  projectName: string;
  intent: 'import' | 'recover';
  context: ImageConfiguredContext | null;
  contextGeneration: number;
  serviceGeneration: number;
  windowGeneration: string;
  selectionStartRevision: number;
  editStartRevision: number;
  previousSelectionId: string | null;
  previousSessionId: string | null;
}
export interface MetadataImagesAttempt {
  binding: ImageAttemptBinding;
  selection: MetadataImagesSelection | null;
  projection: MetadataImagesEditProjection | null;
  choices: MetadataImageChoice[] | null;
  draftRevision: number;
  prepareRequest: PrepareMetadataImagesRequest | null;
  openClaimed: boolean;
  prepareClaimed: boolean;
  applyClaimed: boolean;
  submittedPlanToken: string | null;
  cancelRequested: boolean;
  cancelClaimed: boolean;
  closeRequested: boolean;
  closeClaimed: boolean;
  invalidated: boolean;
}
export interface MetadataImagesApplyBinding {
  sessionId: string;
  planToken: string;
  revision: string;
  draftRevision: number;
  baselineGeneration: number;
  contextGeneration: number;
  serviceGeneration: number;
}
export interface MetadataImagesState {
  mode: BridgeMode;
  projectId: string | null;
  choices: MetadataConfiguredContext[];
  selectedKey: string | null;
  selectedType: string | null;
  contextGeneration: number;
  serviceGeneration: number;
  visible: boolean;
  selectionPending: boolean;
  catalog: MetadataImagesCatalog | null;
  catalogPending: boolean;
  catalogError: ApiError | null;
  selectionListening: boolean;
  editListening: boolean;
  selectionInitialized: boolean;
  editInitialized: boolean;
  selectionStatus: MetadataImagesSelectionStatus | null;
  editStatus: MetadataImagesEditStatus | null;
  selectionBuffered: MetadataImagesSelectionStatus | null;
  editBuffered: MetadataImagesEditStatus | null;
  reading: boolean;
  selectionIssue: boolean;
  editIssue: boolean;
  integrityFailed: boolean;
  generationLost: boolean;
  nativeBlocked: boolean;
  unknownSelection: MetadataImagesSelection | null;
  unknownEdit: MetadataImagesEditProjection | null;
  recoveryProjects: readonly string[];
  attempt: MetadataImagesAttempt | null;
  acknowledged: MetadataImagesApplyBinding | null;
  error: ApiError | null;
}
interface Context {
  selectedProject: () => ProjectSession | null;
  otherOperationReason: (step?: 'open-held-selection') => string | null;
  now?: () => number;
}
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}
function same(first: unknown, next: unknown): boolean { return sameJson(first as JsonValue, next as JsonValue); }
function heldSelection(state: MetadataImagesState): MetadataImagesSelection | null {
  const terminal = state.selectionStatus?.lastTerminal;
  return state.selectionStatus?.active ?? (terminal?.phase === 'selected' && terminal.selectionToken !== null ? terminal : null);
}
function terminal(owner: MetadataImagesEditProjection | null): boolean {
  return owner?.phase === 'final' && owner.nativeFinality === 'settled';
}
export function imageAttemptFinished(attempt: MetadataImagesAttempt | null): boolean {
  if (!attempt) return true;
  if (attempt.openClaimed) return terminal(attempt.projection);
  return Boolean(attempt.selection && imageSelectionSettled(attempt.selection) && ['cancelled', 'failed'].includes(attempt.selection.phase));
}
// This only removes the generic slot's self-deadlock for a requested Open.
// The caller must already hold its exact settled image selection/token and
// current project/context. Numeric asset IDs and image IDs are NOT correlated;
// native admission alone matches that one token, original Binding and root.
export function metadataImagesAssetSessionReason(state: AssetDisplayState, step?: 'open-held-selection'): string | null {
  const operation = state.status?.operation;
  const ownSelectedSlot = step === 'open-held-selection' && operation?.operation === 'choose-images' &&
    operation.phase === 'selected' && operation.reason === 'none' && operation.source === 'captured' && operation.settlement === 'known';
  if (state.blocked || state.observationFailed || state.originPending || state.busy || state.updatingContext ||
      step === 'open-held-selection' && (state.mode !== 'native' || !state.status) ||
      operation && !(operation.phase === 'idle' && operation.settlement === 'known') && !ownSelectedSlot)
    return 'An original asset-session operation is active or unverified. Settle it through its original controls first.';
  return null;
}

export function metadataImagesOwnerReason(state: MetadataImagesState, projectId = state.projectId ?? ''): string | null {
  const owns = Boolean(heldSelection(state) || state.editStatus?.active || !imageAttemptFinished(state.attempt) ||
    state.unknownSelection || state.unknownEdit || state.nativeBlocked);
  if (state.integrityFailed || state.generationLost || state.nativeBlocked || state.selectionIssue || state.editIssue)
    return 'Original image ownership or cleanup is unverified. Observe that original operation; do not start a competing one.';
  if (owns) return 'An original image selection or local-copy review is retained. Finish or stop that operation first.';
  if (state.recoveryProjects.includes(projectId)) return 'This project needs a separate image recovery inspection. Another edit cannot bypass its journal.';
  return null;
}
export function currentMetadataImagesApplyBinding(state: MetadataImagesState): MetadataImagesApplyBinding | null {
  const attempt = state.attempt; const owner = attempt?.projection; const prepared = owner?.details?.prepared;
  if (state.integrityFailed || state.generationLost || state.nativeBlocked || state.selectionIssue || state.editIssue ||
      !attempt?.prepareRequest || !owner || !prepared || !attempt.prepareClaimed || attempt.applyClaimed || attempt.invalidated ||
      attempt.cancelRequested || attempt.closeRequested || owner.phase !== 'reviewing' || owner.nativeReason !== 'none' ||
      owner.nativeFinality !== 'pending' || owner.applySubmitted || !prepared.view.valid || owner.reviewRemainingMs === 0 ||
      state.editStatus?.active?.sessionId !== owner.sessionId || owner.ownerGeneration !== state.editStatus.windowGeneration ||
      !imagePreparedMatches(owner, attempt.prepareRequest)) return null;
  return { sessionId: owner.sessionId, planToken: prepared.planToken, revision: prepared.revision,
    draftRevision: prepared.draftRevision, baselineGeneration: prepared.baselineGeneration,
    contextGeneration: attempt.binding.contextGeneration, serviceGeneration: attempt.binding.serviceGeneration };
}

function reconciledObservationError(state: MetadataImagesState): ApiError | null {
  if (state.error?.code !== 'metadata_images_reply_lost' || state.integrityFailed || state.generationLost || state.nativeBlocked ||
      state.selectionIssue || state.editIssue) return state.error;
  const attempt = state.attempt; const owner = attempt?.projection;
  if (attempt && (attempt.binding.intent === 'import' && !attempt.selection || attempt.openClaimed && !owner ||
      attempt.applyClaimed && !owner?.applySubmitted && !terminal(owner ?? null) ||
      attempt.prepareClaimed && !owner?.details?.prepared && !terminal(owner ?? null) ||
      attempt.cancelClaimed && (!attempt.selection || !imageSelectionSettled(attempt.selection)) ||
      attempt.closeClaimed && !terminal(owner ?? null))) return state.error;
  return null;
}
// A newer local selection must never inherit an earlier edit's success copy or
// source provenance merely because that edit is still the native lastTerminal.
export function retainedMetadataImagesOperation(state: MetadataImagesState): {
  owner: MetadataImagesEditProjection | null; selection: MetadataImagesSelection | null;
} {
  if (state.attempt) return { owner: state.attempt.projection, selection: state.attempt.selection };
  const owner = state.unknownEdit ?? state.editStatus?.active ?? null;
  const selection = state.unknownSelection ?? heldSelection(state);
  if (owner || selection) return { owner, selection: owner ? null : selection };
  const previous = state.editStatus?.lastTerminal ?? null;
  return { owner: previous, selection: previous ? null : state.selectionStatus?.lastTerminal ?? null };
}

export class MetadataImagesController {
  private state: MetadataImagesState = freeze<MetadataImagesState>({
    mode: 'unavailable', projectId: null, choices: [], selectedKey: null, selectedType: null,
    contextGeneration: 0, serviceGeneration: 0, visible: false, selectionPending: false,
    catalog: null, catalogPending: false, catalogError: null,
    selectionListening: false, editListening: false, selectionInitialized: false, editInitialized: false,
    selectionStatus: null, editStatus: null, selectionBuffered: null, editBuffered: null, reading: false,
    selectionIssue: false, editIssue: false, integrityFailed: false, generationLost: false, nativeBlocked: false,
    unknownSelection: null, unknownEdit: null, recoveryProjects: [], attempt: null, acknowledged: null, error: null,
  });
  private readonly context: Context;
  private api: MetadataImagesApi | null = null;
  private listeners = new Set<() => void>();
  private unlistenSelection: (() => void) | null = null;
  private unlistenEdit: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private catalogRead: Promise<void> | null = null;
  private fingerprint = '';
  private sequence = 0;
  private processing = false;
  private processAgain = false;
  private disposed = false;
  private deadline: { sessionId: string; at: number } | null = null;
  private orphanClose: string | null = null;
  private orphanCancel: string | null = null;
  private rejectedOpenAwaitingRead: number | null = null;

  constructor(context: Context) { this.context = context; }
  getSnapshot = (): MetadataImagesState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(next: MetadataImagesState): void {
    if (this.disposed) return;
    this.state = freeze(next);
    for (const listener of this.listeners) listener();
  }
  private attempt(patch: Partial<MetadataImagesAttempt>): void {
    if (this.state.attempt) {
      this.publish({ ...this.state, attempt: { ...this.state.attempt, ...patch } });
      if (this.processing) this.processAgain = true;
    }
  }
  private now(): number { return this.context.now?.() ?? performance.now(); }
  remainingReviewMs(): number {
    const owner = this.state.attempt?.projection;
    return owner && this.deadline?.sessionId === owner.sessionId
      ? Math.max(0, Math.min(owner.reviewRemainingMs, this.deadline.at - this.now())) : 0;
  }
  private nextContext(): number {
    return Math.min(U32_MAX, this.state.contextGeneration + 1);
  }
  selectedContext(): ImageConfiguredContext | null {
    const selected = this.state.choices.find((row) => row.key === this.state.selectedKey);
    return selected && this.state.selectedType ? { ...selected, assetType: this.state.selectedType } : null;
  }
  private matches(attempt: MetadataImagesAttempt): boolean {
    const project = this.context.selectedProject();
    return same(imageProjectBinding(project), {
      projectId: attempt.binding.projectId, configRevision: attempt.binding.configRevision,
      configBaselineGeneration: attempt.binding.configBaselineGeneration, configObservationGeneration: attempt.binding.configObservationGeneration,
    }) && !this.state.selectionPending && project?.snapshotRequest === null &&
      attempt.binding.contextGeneration === this.state.contextGeneration && attempt.binding.serviceGeneration === this.state.serviceGeneration &&
      (attempt.binding.intent === 'recover' || same(this.selectedContext(), attempt.binding.context) && imageConfigReason(project) === null);
  }
  syncProject(): void {
    if (this.disposed) return;
    const project = this.context.selectedProject(); const choices = imageConfiguredChoices(project);
    const fingerprint = JSON.stringify([imageProjectBinding(project), project?.snapshotRequest ?? null, project?.sourceChanged ?? false,
      project?.saveRecoveryRequired ?? false, imageConfigReason(project), choices]);
    if (this.fingerprint === fingerprint) return;
    this.fingerprint = fingerprint;
    this.retire();
    const selectedKey = choices.some((row) => row.key === this.state.selectedKey) ? this.state.selectedKey : choices[0]?.key ?? null;
    this.publish({ ...this.state, projectId: project?.project.id ?? null, choices, selectedKey,
      selectedType: selectedKey === this.state.selectedKey ? this.state.selectedType : null,
      contextGeneration: this.nextContext(), acknowledged: null });
    this.process();
  }
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (this.disposed) return;
    if (action.type === 'select' || action.type === 'switch' || 'projectId' in action &&
        (action.projectId === this.state.projectId || action.projectId === this.state.attempt?.binding.projectId)) {
      // Retire on intent even if the reducer returns its original object.
      this.retire(); this.publish({ ...this.state, contextGeneration: this.nextContext(), acknowledged: null }); this.process();
    }
  }
  selectPlatform(platform: MetadataPlatform): void {
    const choice = this.state.choices.find((row) => row.platform === platform);
    if (choice) this.select(choice.key, null);
  }
  selectLocale(locale: string): void {
    const current = this.state.choices.find((row) => row.key === this.state.selectedKey);
    const choice = this.state.choices.find((row) => row.platform === current?.platform && row.locale === locale);
    if (choice) this.select(choice.key, this.state.selectedType);
  }
  selectAssetType(assetType: string): void {
    const current = this.state.choices.find((row) => row.key === this.state.selectedKey);
    if (current && this.state.catalog && imageCatalogTypes(this.state.catalog, current.platform).some((row) => row.id === assetType))
      this.select(current.key, assetType);
  }
  private select(key: string, assetType: string | null): void {
    if (this.disposed || key === this.state.selectedKey && assetType === this.state.selectedType) return;
    this.retire();
    this.publish({ ...this.state, selectedKey: key, selectedType: assetType, contextGeneration: this.nextContext(), acknowledged: null });
    this.process();
  }
  setVisible(visible: boolean): void {
    if (this.disposed || visible === this.state.visible) return;
    if (!visible) this.retire();
    this.publish({ ...this.state, visible, acknowledged: null }); this.process();
  }
  setSelectionPending(selectionPending: boolean): void {
    if (this.disposed || selectionPending === this.state.selectionPending) return;
    if (selectionPending) this.retire();
    this.publish({ ...this.state, selectionPending, contextGeneration: this.nextContext(), acknowledged: null }); this.process();
  }
  selectionIntent(): void { this.shutdownIntent(); }
  snapshotIntent(projectId: string): void {
    if (projectId === this.state.projectId || projectId === this.state.attempt?.binding.projectId) this.shutdownIntent();
  }
  shutdownIntent(): void {
    if (this.disposed) return;
    // Invalidate pre-submit consent even when an unload/project-pick is later
    // cancelled. An already submitted original operation stays app-owned.
    this.retire(); this.publish({ ...this.state, contextGeneration: this.nextContext(), acknowledged: null }); this.process();
  }
  beginConnection(): void {
    if (this.disposed) return;
    this.retire(); this.publish({ ...this.state, acknowledged: null }); this.process();
  }
  async connect(api: MetadataImagesApi): Promise<void> {
    if (this.disposed) return;
    if (this.api === api) return this.checkStatus();
    if (this.api && (metadataImagesOwnerReason(this.state) !== null || this.reading || this.catalogRead)) {
      this.publish({ ...this.state, generationLost: true, acknowledged: null, error: metadataImagesError({ code: 'metadata_images_context_changed' }) });
      this.retire(); this.process(); return;
    }
    if (this.state.serviceGeneration >= U32_MAX) { this.fail('edit', true); return; }
    try { this.unlistenSelection?.(); this.unlistenEdit?.(); } catch { /* Observer closure is not native settlement. */ }
    this.unlistenSelection = null; this.unlistenEdit = null; this.api = api;
    this.publish({ ...this.state, mode: api.mode, serviceGeneration: this.state.serviceGeneration + 1,
      catalog: null, catalogError: null, selectionListening: false, editListening: false, selectionInitialized: false, editInitialized: false,
      selectionBuffered: null, editBuffered: null, acknowledged: null });
    this.syncProject();
    if (api.mode === 'native') await Promise.all([this.loadCatalog(), this.checkStatus()]);
  }
  async loadCatalog(): Promise<void> {
    if (this.disposed || this.api?.mode !== 'native') return;
    if (this.catalogRead) return this.catalogRead;
    const api = this.api;
    const work = Promise.resolve().then(async () => {
      try {
        const catalog = parseMetadataImagesCatalog(await api.metadataImagesCatalog());
        if (this.disposed || this.api !== api) return;
        if (!catalog) throw { code: 'metadata_images_catalog_invalid' };
        if (this.state.catalog && !same(this.state.catalog, catalog)) this.retire();
        this.publish({ ...this.state, catalog: structuredClone(catalog), catalogError: null, acknowledged: null });
        this.process();
      } catch (error) {
        if (!this.disposed && this.api === api) {
          this.retire(); this.publish({ ...this.state, catalog: null, catalogError: metadataImagesError(error), acknowledged: null }); this.process();
        }
      }
    });
    this.catalogRead = work; this.publish({ ...this.state, catalogPending: true });
    try { await work; } finally {
      if (this.catalogRead === work) { this.catalogRead = null; this.publish({ ...this.state, catalogPending: false }); }
    }
  }
  // The existing generic asset watcher can settle after the image event. This
  // rechecks the same pending Open; it creates no query, owner, timer or retry.
  syncAssetSession = (): void => { this.process(); };

  passiveBusyReason(): string | null {
    return this.reading || this.catalogRead ? 'An original image status or catalogue query is still pending.' : null;
  }
  async checkStatus(): Promise<void> {
    if (this.disposed || this.api?.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api;
    const work = Promise.resolve().then(async () => {
      try {
        if (!this.unlistenSelection) {
          const unlisten = await api.subscribeMetadataImagesSelection((value) => {
            if (this.api === api) this.receiveSelection(value, 'event');
          });
          if (this.disposed || this.api !== api) { unlisten(); return; }
          this.unlistenSelection = unlisten; this.publish({ ...this.state, selectionListening: true });
        }
        this.receiveSelection(await api.metadataImagesSelectionStatus(), 'read');
      } catch (error) { if (!this.disposed && this.api === api) this.fail('selection', metadataImagesError(error).code === 'metadata_images_status_invalid'); }
      if (this.disposed || this.api !== api) return;
      try {
        if (!this.unlistenEdit) {
          const unlisten = await api.subscribeMetadataImagesEdit((value) => {
            if (this.api === api) this.receiveEdit(value, 'event');
          });
          if (this.disposed || this.api !== api) { unlisten(); return; }
          this.unlistenEdit = unlisten; this.publish({ ...this.state, editListening: true });
        }
        this.receiveEdit(await api.metadataImagesEditStatus(), 'read');
      } catch (error) { if (!this.disposed && this.api === api) this.fail('edit', metadataImagesError(error).code === 'metadata_images_status_invalid'); }
    });
    this.reading = work; this.publish({ ...this.state, reading: true, acknowledged: null });
    try { await work; } finally {
      if (this.reading === work) { this.reading = null; this.publish({ ...this.state, reading: false }); this.process(); }
    }
  }
  private fail(stream: 'selection' | 'edit', protocol: boolean): void {
    if (this.disposed) return;
    this.publish({ ...this.state, selectionIssue: stream === 'selection' || this.state.selectionIssue,
      editIssue: stream === 'edit' || this.state.editIssue, integrityFailed: this.state.integrityFailed || protocol,
      acknowledged: null, error: metadataImagesError({ code: protocol ? 'metadata_images_status_invalid' : 'metadata_images_reply_lost' }) });
    if (protocol) this.retire();
    this.process();
  }
  private receiveSelection(value: unknown, source: 'event' | 'read' | 'reply'): void {
    if (this.disposed) return;
    const parsed = parseMetadataImagesSelectionStatus(value);
    if (!parsed) { this.fail('selection', true); return; }
    let status = freeze(structuredClone(parsed)); const previous = this.state.selectionInitialized ? this.state.selectionStatus : this.state.selectionBuffered ?? this.state.selectionStatus;
    if (previous) {
      if (previous.windowGeneration !== status.windowGeneration) { this.publish({ ...this.state, generationLost: true, acknowledged: null }); this.retire(); this.process(); return; }
      const [first, next] = previous.statusRevision <= status.statusRevision ? [previous, status] : [status, previous];
      if (!metadataImagesSelectionProgress(first, next)) { this.fail('selection', true); return; }
      if (previous.statusRevision > status.statusRevision) status = previous;
    }
    if (this.state.editStatus && this.state.editStatus.windowGeneration !== status.windowGeneration) {
      this.publish({ ...this.state, generationLost: true, acknowledged: null }); this.retire(); this.process(); return;
    }
    const unknown = [status.active, status.lastTerminal].find((row) => row?.phase === 'unknown' || row?.settlement === 'unknown' || row?.settlement === 'late-known') ?? null;
    let nextState = { ...this.state, nativeBlocked: this.state.nativeBlocked || Boolean(unknown) || status.capability.reason === 'cleanup_unknown',
      unknownSelection: this.state.unknownSelection ?? unknown };
    if (!this.state.selectionInitialized && source !== 'read') {
      this.publish({ ...nextState, selectionBuffered: status }); return;
    }
    let attempt = this.state.attempt;
    if (attempt?.binding.intent === 'import') {
      const retained = attempt;
      const selected = [status.active, status.lastTerminal].find((row) => row && retained.binding.context && row.projectId === retained.binding.projectId &&
        row.platform === retained.binding.context.platform && row.locale === retained.binding.context.locale && row.assetType === retained.binding.context.assetType &&
        (retained.selection ? row.operationId === retained.selection.operationId :
          status.statusRevision > retained.binding.selectionStartRevision && row.operationId !== retained.binding.previousSelectionId));
      if (selected) attempt = { ...attempt, selection: selected };
    }
    // A rejected Open still retains its original selection. Only a valid
    // original status read releases its pending native-cancel route; generic
    // asset events cannot skip this observation barrier.
    if (source === 'read' && attempt?.binding.serial === this.rejectedOpenAwaitingRead) this.rejectedOpenAwaitingRead = null;
    nextState = { ...nextState, attempt, selectionStatus: status, selectionBuffered: null, selectionInitialized: true,
      selectionIssue: this.state.integrityFailed };
    nextState.error = reconciledObservationError(nextState);
    this.publish(nextState); this.process();
  }
  private receiveEdit(value: unknown, source: 'event' | 'read' | 'reply'): void {
    if (this.disposed) return;
    const parsed = parseMetadataImagesEditStatus(value);
    if (!parsed) { this.fail('edit', true); return; }
    let status = freeze(structuredClone(parsed)); const previous = this.state.editInitialized ? this.state.editStatus : this.state.editBuffered ?? this.state.editStatus;
    if (previous) {
      if (previous.windowGeneration !== status.windowGeneration) { this.publish({ ...this.state, generationLost: true, acknowledged: null }); this.retire(); this.process(); return; }
      const [first, next] = previous.statusRevision <= status.statusRevision ? [previous, status] : [status, previous];
      if (!metadataImagesEditProgress(first, next)) { this.fail('edit', true); return; }
      if (previous.statusRevision > status.statusRevision) status = previous;
    }
    if (this.state.selectionStatus && this.state.selectionStatus.windowGeneration !== status.windowGeneration) {
      this.publish({ ...this.state, generationLost: true, acknowledged: null }); this.retire(); this.process(); return;
    }
    const unknown = [status.active, status.lastTerminal].find((row) => row?.phase === 'unknown' || row?.nativeFinality === 'unknown') ?? null;
    const recoveryProjects = [...this.state.recoveryProjects];
    for (const row of [status.active, status.lastTerminal]) {
      if (row?.coreOutcome?.journal === 'recovery_required' && !recoveryProjects.includes(row.projectId)) {
        if (recoveryProjects.length >= 64) { this.fail('edit', true); return; }
        recoveryProjects.push(row.projectId);
      }
    }
    const nextState = { ...this.state, recoveryProjects, nativeBlocked: this.state.nativeBlocked || Boolean(unknown) || status.capability.reason === 'cleanup_unknown',
      unknownEdit: this.state.unknownEdit ?? unknown };
    if (!this.state.editInitialized && source !== 'read') { this.publish({ ...nextState, editBuffered: status }); return; }
    let attempt = this.state.attempt;
    if (attempt?.openClaimed) {
      const retained = attempt;
      const owner = [status.active, status.lastTerminal].find((row) => row && row.projectId === retained.binding.projectId &&
        row.ownerGeneration === retained.binding.windowGeneration &&
        (retained.projection ? row.sessionId === retained.projection.sessionId :
          status.statusRevision > retained.binding.editStartRevision && row.sessionId !== retained.binding.previousSessionId));
      if (owner) {
        attempt = { ...attempt, projection: owner };
        if (owner.details?.prepared) {
          const at = this.now() + owner.reviewRemainingMs;
          this.deadline = { sessionId: owner.sessionId, at: this.deadline?.sessionId === owner.sessionId ? Math.min(this.deadline.at, at) : at };
        }
      }
    }
    const next = { ...nextState, attempt, editStatus: status, editBuffered: null, editInitialized: true, editIssue: this.state.integrityFailed };
    const current = currentMetadataImagesApplyBinding(next);
    if (!same(current, next.acknowledged)) next.acknowledged = null;
    next.error = reconciledObservationError(next);
    this.publish(next); this.process();
  }
  private usable(): boolean {
    const state = this.state;
    return state.mode === 'native' && state.selectionListening && state.editListening && state.selectionInitialized && state.editInitialized &&
      Boolean(state.selectionStatus && state.editStatus && state.selectionStatus.windowGeneration === state.editStatus.windowGeneration) &&
      !state.reading && !state.integrityFailed && !state.generationLost && !state.nativeBlocked && !state.selectionIssue && !state.editIssue;
  }
  startReason(intent: 'import' | 'recover' = 'import'): string | null {
    if (this.state.mode !== 'native') return metadataImagesError({ code: 'metadata_images_unavailable' }).message;
    if (!this.usable()) return 'Image capability or original-owner status is unavailable or unverified. Check the native status without retrying an operation.';
    if (!this.state.catalog) return 'The shared image catalogue and field guide are unavailable. No Store policy was invented.';
    if (!this.state.visible || this.state.selectionPending) return 'Return to Metadata after the original project selection settles.';
    const project = this.context.selectedProject();
    if (!project) return 'Choose the registered project whose local image files you want to inspect.';
    const other = this.context.otherOperationReason(); if (other) return other;
    if (heldSelection(this.state) || this.state.editStatus?.active || !imageAttemptFinished(this.state.attempt))
      return 'Finish or cancel the original image operation and wait for its settlement before starting another.';
    const caps = [this.state.selectionStatus!.capability, this.state.editStatus!.capability];
    if (caps.some((cap) => !cap.available))
      return 'Native image selection or editing is not qualified or is blocked on this platform. No browser or raw-path alternative is enabled.';
    if ([this.state.contextGeneration, this.state.serviceGeneration, this.sequence, this.state.selectionStatus!.statusRevision, this.state.editStatus!.statusRevision,
      project.revision, project.baselineGeneration, project.observationGeneration].some((counter) => !isU32(counter) || counter >= U32_MAX))
      return 'An original binding counter is exhausted. No identifier or generation will be reused.';
    if (project.snapshotRequest !== null) return 'Wait for the original saved-configuration observation.';
    if (intent === 'recover') return null; // Inspect may honestly return conflict or idle; neither is a recovery pass.
    if (this.state.recoveryProjects.includes(project.project.id)) return 'Inspect image recovery before starting a new import for this project.';
    const configured = imageConfigReason(project); if (configured) return configured;
    const selected = this.selectedContext();
    if (!selected || !imageCatalogTypes(this.state.catalog, selected.platform).some((row) => row.id === selected.assetType))
      return 'Select an enabled platform, a saved listing locale, and a catalogue image or device-size type.';
    return null;
  }
  private newAttempt(intent: 'import' | 'recover'): MetadataImagesAttempt | null {
    const project = this.context.selectedProject(); const binding = imageProjectBinding(project);
    if (!project || !binding || this.sequence >= U32_MAX || !this.state.selectionStatus || !this.state.editStatus) return null;
    const serial = ++this.sequence;
    return freeze({ binding: { ...binding, serial, projectName: project.project.name, intent,
      context: intent === 'import' ? this.selectedContext() : null, contextGeneration: this.state.contextGeneration,
      serviceGeneration: this.state.serviceGeneration, windowGeneration: this.state.editStatus.windowGeneration,
      selectionStartRevision: this.state.selectionStatus.statusRevision, editStartRevision: this.state.editStatus.statusRevision,
      previousSelectionId: this.state.selectionStatus.lastTerminal?.operationId ?? null, previousSessionId: this.state.editStatus.lastTerminal?.sessionId ?? null },
      selection: null, projection: null, choices: null, draftRevision: 0, prepareRequest: null, openClaimed: intent === 'recover',
      prepareClaimed: false, applyClaimed: false, submittedPlanToken: null, cancelRequested: false, cancelClaimed: false,
      closeRequested: false, closeClaimed: false, invalidated: false });
  }
  choose(): boolean {
    this.syncProject();
    if (this.disposed || !this.api || this.startReason() !== null) return false;
    const attempt = this.newAttempt('import'); const selected = attempt?.binding.context;
    if (!attempt || !selected) return false;
    this.deadline = null; this.publish({ ...this.state, attempt, acknowledged: null, error: null });
    if (this.state.attempt?.binding.serial !== attempt.binding.serial || this.state.attempt.invalidated) {
      this.publish({ ...this.state, attempt: null }); return false;
    }
    void this.command('choose', attempt.binding.serial, () => this.api!.chooseMetadataImages({
      projectId: selected.projectId, platform: selected.platform, locale: selected.locale, assetType: selected.assetType,
    }));
    return true;
  }
  inspectRecovery(): boolean {
    this.syncProject();
    if (this.disposed || !this.api || this.startReason('recover') !== null) return false;
    const attempt = this.newAttempt('recover'); if (!attempt) return false;
    this.deadline = null; this.publish({ ...this.state, attempt, acknowledged: null, error: null });
    if (this.state.attempt?.binding.serial !== attempt.binding.serial || this.state.attempt.invalidated) {
      this.publish({ ...this.state, attempt: null }); return false;
    }
    void this.command('recover', attempt.binding.serial, () => this.api!.openMetadataImagesRecovery(attempt.binding.projectId));
    return true;
  }
  setReplacement(itemId: string, replaceExisting: boolean): boolean {
    const attempt = this.state.attempt; const checkout = attempt?.projection?.details?.checkout;
    if (this.disposed || !attempt || !checkout || checkout.view.kind !== 'import' || !attempt.choices ||
        attempt.prepareClaimed || attempt.invalidated || attempt.closeRequested || !this.matches(attempt) || attempt.draftRevision >= U32_MAX - 1) return false;
    const row = checkout.view.files.find((file) => file.itemId === itemId);
    const choice = attempt.choices.find((item) => item.itemId === itemId);
    if (!row || !choice || replaceExisting && (!row.canReplace || row.before === null) || choice.replaceExisting === replaceExisting) return false;
    this.publish({ ...this.state, acknowledged: null, attempt: { ...attempt, draftRevision: attempt.draftRevision + 1,
      choices: attempt.choices.map((item) => item.itemId === itemId ? { itemId, replaceExisting } : item) } });
    return true;
  }
  prepareReason(): string | null {
    const attempt = this.state.attempt; const owner = attempt?.projection; const opened = owner?.details?.checkout;
    if (!this.usable() || !attempt || !opened || !this.state.visible || !this.matches(attempt) || this.context.otherOperationReason())
      return 'The original image context or native status is no longer ready for review.';
    if (attempt.invalidated || attempt.closeRequested || attempt.cancelRequested || attempt.prepareClaimed || owner?.phase !== 'editing' ||
        owner.nativeReason !== 'none' || owner.reviewRemainingMs === 0 || this.state.editStatus?.active?.sessionId !== owner.sessionId)
      return 'This original checkout cannot be prepared again. Close it before choosing a new batch or inspecting recovery again.';
    if (opened.view.kind === 'recover' && (opened.view.state !== 'recoverable' || !opened.view.valid || opened.view.action === null))
      return opened.view.state === 'idle' ? 'No image journal was found. An idle inspection is not a recovery pass.' : 'Recovery proof is incomplete or conflicted. Preserve the original files; no force action is available.';
    if (!attempt.choices) return 'Wait for the exact original file roster.';
    return null;
  }
  prepare(): boolean {
    if (this.disposed || !this.api || this.prepareReason() !== null) return false;
    const attempt = this.state.attempt!; const owner = attempt.projection!; const opened = owner.details!.checkout!;
    const request: PrepareMetadataImagesRequest = { sessionId: owner.sessionId, revision: opened.revision,
      draftRevision: attempt.draftRevision, baselineGeneration: attempt.binding.serial,
      expectedBaseline: structuredClone(opened.baseline), choices: structuredClone(attempt.choices!) };
    if (!metadataImagesRequestFits('metadata_images_edit_prepare', request)) { this.fail('edit', true); return false; }
    this.publish({ ...this.state, acknowledged: null, attempt: { ...attempt, prepareClaimed: true, prepareRequest: request } });
    if (this.state.attempt?.binding.serial === attempt.binding.serial && !this.state.attempt.closeRequested)
      void this.command('prepare', attempt.binding.serial, () => this.api!.prepareMetadataImagesEdit(request));
    return true;
  }
  canAcknowledge(binding = currentMetadataImagesApplyBinding(this.state)): boolean {
    const attempt = this.state.attempt;
    return Boolean(binding && attempt && this.usable() && this.state.visible && this.matches(attempt) && this.remainingReviewMs() > 0 &&
      this.state.editStatus?.capability.available && !this.context.otherOperationReason() && same(binding, currentMetadataImagesApplyBinding(this.state)));
  }
  acknowledge(checked: boolean): void {
    const binding = currentMetadataImagesApplyBinding(this.state);
    this.publish({ ...this.state, acknowledged: checked && this.canAcknowledge(binding) ? binding : null });
  }
  canApply(binding = currentMetadataImagesApplyBinding(this.state)): boolean {
    return Boolean(binding && this.canAcknowledge(binding) && same(binding, this.state.acknowledged));
  }
  apply(binding: MetadataImagesApplyBinding): boolean {
    if (this.disposed || !this.api || !this.canApply(binding)) return false;
    const attempt = this.state.attempt!;
    this.publish({ ...this.state, acknowledged: null, attempt: { ...attempt, applyClaimed: true, submittedPlanToken: binding.planToken } });
    if (this.state.attempt?.binding.serial === attempt.binding.serial && !this.state.attempt.closeRequested)
      void this.command('apply', attempt.binding.serial, () => this.api!.applyMetadataImagesEdit(binding.sessionId, binding.planToken));
    return true;
  }
  private retire(user = false): void {
    const attempt = this.state.attempt;
    if (!attempt || imageAttemptFinished(attempt) || attempt.applyClaimed && !user) {
      if (this.state.acknowledged) this.publish({ ...this.state, acknowledged: null });
      return;
    }
    this.publish({ ...this.state, acknowledged: null, attempt: { ...attempt, invalidated: attempt.invalidated || !user,
      cancelRequested: !attempt.openClaimed || attempt.cancelRequested, closeRequested: attempt.openClaimed || attempt.closeRequested } });
  }
  requestStop(): void {
    if (this.disposed || !this.api) return;
    this.retire(true); this.process();
    if (!this.state.attempt || imageAttemptFinished(this.state.attempt)) {
      const edit = this.state.editStatus?.active;
      const selection = heldSelection(this.state);
      if (!this.state.generationLost && edit && edit.phase !== 'unknown' && edit.ownerGeneration === this.state.editStatus?.windowGeneration && this.orphanClose !== edit.sessionId) {
        this.orphanClose = edit.sessionId; void this.command('close', null, () => this.api!.closeMetadataImagesEdit(edit.sessionId));
      } else if (!this.state.generationLost && selection && selection.phase !== 'unknown' && this.orphanCancel !== selection.operationId) {
        this.orphanCancel = selection.operationId; void this.command('cancel', null, () => this.api!.cancelMetadataImagesSelection(selection.operationId));
      }
    }
  }
  private process(): void {
    if (this.disposed || !this.api) return;
    if (this.processing) { this.processAgain = true; return; }
    this.processing = true;
    try {
      do {
        this.processAgain = false;
        let attempt = this.state.attempt; if (!attempt) continue;
        if (!attempt.applyClaimed && !imageAttemptFinished(attempt) &&
            (!this.matches(attempt) || !this.state.catalog || this.state.generationLost)) this.retire();
        attempt = this.state.attempt; if (!attempt) continue;
        const owner = attempt.projection; const opened = owner?.details?.checkout;
        if (opened && attempt.choices === null && !this.state.integrityFailed) {
          const selected = attempt.selection; const view = opened.view;
          if (view.kind !== attempt.binding.intent || view.kind === 'import' &&
              (!selected || !attempt.binding.context || view.platform !== attempt.binding.context.platform || view.locale !== attempt.binding.context.locale ||
               view.assetType !== attempt.binding.context.assetType || view.metadataRoot !== attempt.binding.context.metadataRoot ||
               view.files.length !== selected.items.length || !view.files.every((row, index) => {
                 const item = selected.items[index];
                 return item && row.itemId === item.itemId && row.displayName === item.displayName &&
                   row.selected.byteLength === item.byteLength && row.selected.sha256 === item.sha256;
               }))) { this.fail('edit', true); continue; }
          this.attempt({ choices: view.kind === 'import' ? view.files.map((row) => ({ itemId: row.itemId, replaceExisting: false })) : [] });
          continue;
        }
        if (owner?.details && owner.details.intent !== attempt.binding.intent ||
            owner?.details?.prepared && (!attempt.prepareRequest || !imagePreparedMatches(owner, attempt.prepareRequest)) ||
            owner?.applySubmitted && !attempt.applyClaimed) {
          if (!this.state.integrityFailed) this.fail('edit', true);
        }
        if (owner && terminal(owner) && attempt.applyClaimed && !this.state.integrityFailed && !this.state.generationLost && !this.state.nativeBlocked && !this.state.editIssue && !this.state.selectionIssue &&
            attempt.submittedPlanToken === owner.details?.prepared?.planToken && normalMetadataImagesResult(owner) === 'recovered' &&
            this.state.recoveryProjects.includes(owner.projectId)) {
          this.publish({ ...this.state, recoveryProjects: this.state.recoveryProjects.filter((id) => id !== owner.projectId) });
        }
        attempt = this.state.attempt; if (!attempt || this.state.generationLost) continue;
        if (attempt.cancelRequested && !attempt.cancelClaimed && this.rejectedOpenAwaitingRead !== attempt.binding.serial &&
            attempt.selection && attempt.selection.phase !== 'unknown' &&
            !['cancelled', 'failed'].includes(attempt.selection.phase)) {
          const operationId = attempt.selection.operationId; const serial = attempt.binding.serial;
          this.attempt({ cancelClaimed: true }); void this.command('cancel', serial, () => this.api!.cancelMetadataImagesSelection(operationId)); continue;
        }
        if (attempt.closeRequested && !attempt.closeClaimed && attempt.projection && !['final', 'unknown'].includes(attempt.projection.phase) &&
            attempt.projection.ownerGeneration === this.state.editStatus?.windowGeneration) {
          const sessionId = attempt.projection.sessionId; const serial = attempt.binding.serial;
          this.attempt({ closeClaimed: true }); void this.command('close', serial, () => this.api!.closeMetadataImagesEdit(sessionId)); continue;
        }
        const selection = attempt.selection;
        if (attempt.binding.intent === 'import' && !attempt.openClaimed && !attempt.cancelRequested && !attempt.invalidated &&
            selection?.phase === 'selected' && imageSelectionSettled(selection) && selection.selectionToken && this.usable() &&
            this.state.editStatus?.capability.available && this.matches(attempt) && !this.context.otherOperationReason('open-held-selection')) {
          const serial = attempt.binding.serial; const selectionToken = selection.selectionToken; const projectId = attempt.binding.projectId;
          this.attempt({ openClaimed: true });
          if (this.state.attempt?.binding.serial === serial && !this.state.attempt.closeRequested)
            void this.command('open', serial, () => this.api!.openMetadataImagesEdit({ projectId, selectionToken }));
          else { this.attempt({ openClaimed: false, cancelRequested: true }); this.processAgain = true; }
        }
      } while (this.processAgain);
    } finally { this.processing = false; }
  }
  private rejectBeforeOwner(kind: string, serial: number | null, error: ApiError): boolean {
    const attempt = this.state.attempt;
    if (serial === null || !attempt || attempt.binding.serial !== serial || attempt.projection || attempt.prepareClaimed || attempt.applyClaimed) return false;
    // These closed native markers are method-scoped negative admission facts.
    // No ordinary busy/refused/transport error proves that an owner was absent.
    // Never clear another owner, an observed projection or sticky unknown state.
    const chooseRejected = kind === 'choose' && error.code === 'metadata_images_selection_not_admitted' &&
      attempt.binding.intent === 'import' && !attempt.openClaimed && !attempt.selection;
    const recoveryRejected = kind === 'recover' && error.code === 'metadata_images_recovery_not_admitted' &&
      attempt.binding.intent === 'recover' && !attempt.selection;
    if (chooseRejected || recoveryRejected) {
      this.deadline = null;
      this.publish({ ...this.state, attempt: null, acknowledged: null, error,
        selectionIssue: chooseRejected || this.state.selectionIssue, editIssue: recoveryRejected || this.state.editIssue });
      return true;
    }
    if (kind === 'open' && ['metadata_images_import_not_matched', 'metadata_images_import_not_admitted'].includes(error.code) &&
        attempt.binding.intent === 'import' && attempt.openClaimed && attempt.selection) {
      // Only THIS Open is proved not to have claimed an edit. Not-matched did
      // not consume a token; not-admitted matched and permanently retired it.
      // Neither fact is selection cleanup or global idle. Keep its original
      // selection/Stop route behind an observation barrier; never retry Open.
      this.rejectedOpenAwaitingRead = serial;
      this.publish({ ...this.state, acknowledged: null, error, selectionIssue: true, editIssue: true,
        attempt: { ...attempt, openClaimed: false, invalidated: true, cancelRequested: true, closeRequested: false } });
      return true;
    }
    return false;
  }
  private async command(kind: 'choose' | 'cancel' | 'open' | 'recover' | 'prepare' | 'apply' | 'close', serial: number | null,
    call: () => Promise<MetadataImagesSelectionStatus | MetadataImagesEditStatus>): Promise<void> {
    const api = this.api;
    try {
      const status = await call();
      if (this.disposed || this.api !== api) return;
      if (kind === 'choose' || kind === 'cancel') this.receiveSelection(status, 'reply'); else this.receiveEdit(status, 'reply');
    } catch (error) {
      if (this.disposed || this.api !== api) return;
      const safe = metadataImagesError(error);
      if (this.rejectBeforeOwner(kind, serial, safe)) {
        // Refresh existing status once before accepting another explicit action.
        // This negative admission fact is not a global idle or cleanup receipt.
        await this.checkStatus(); return;
      }
      const stream = kind === 'choose' || kind === 'cancel' ? 'selection' : 'edit';
      this.fail(stream, safe.code === 'metadata_images_status_invalid');
      if (serial !== null && this.state.attempt?.binding.serial === serial && ['choose', 'open', 'recover', 'prepare'].includes(kind)) this.retire();
      this.process();
      // Observe the same owner once. Never repeat Choose, Open, Prepare, Apply,
      // Cancel or Close to turn a lost reply into a fabricated successful retry.
      await this.checkStatus();
    }
  }
  dispose(): void {
    if (this.disposed) return;
    // At most the one original STOP. Disposing listeners is not undo/finality.
    this.requestStop(); this.disposed = true;
    try { this.unlistenSelection?.(); } catch { /* Not native settlement. */ }
    try { this.unlistenEdit?.(); } catch { /* Not native settlement. */ }
    this.unlistenSelection = null; this.unlistenEdit = null; this.listeners.clear();
  }
}
