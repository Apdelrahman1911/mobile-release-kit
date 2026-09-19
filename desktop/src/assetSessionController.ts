// UI coordination only. Native document/task/file owners outlive an abandoned
// invoke or view. This controller never claims to cancel by dropping a Promise.
import type { ProjectSession } from './drafts.ts';
import type { DesktopApi } from './types.ts';
import type { AssetDisplayState, AssetFileKind, AssetIntent, AssetKind, AssetOperationName, AssetRecordRef, AssetScope, AssetStatus, CredentialPrepareRequest, KeystoreFields, TokenFields, WifFields } from './assetSessionTypes.ts';
import { ASSET_REASON_HELP, assetError, assetRequestFits, parseAssetStatus } from './assetSessionProtocol.ts';

function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}
function sameScope(a: AssetScope, b: AssetScope): boolean { return a.platform === b.platform && a.stage === b.stage && a.purpose === b.purpose; }
function sameRevision(a: ProjectSession | null, b: { id: string; revision: number; baseline: number } | null): boolean {
  return a === null ? b === null : !!b && a.project.id === b.id && a.revision === b.revision && a.baselineGeneration === b.baseline;
}
function sameStatus(left: AssetStatus, right: AssetStatus): boolean {
  // Remaining time changes without a semantic status revision; all other fields
  // at an equal revision must agree. Refresh can only shorten our local deadline.
  // Object key order is not semantic and can differ across IPC/event transports.
  const same = (a: unknown, b: unknown): boolean => {
    if (a === b) return true;
    if (!a || !b || typeof a !== 'object' || typeof b !== 'object' || Array.isArray(a) !== Array.isArray(b)) return false;
    const keys = Object.keys(a);
    return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) &&
      (key === 'expiresInMs' || same((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key])));
  };
  return same(left, right);
}
function cancellationPending(state: AssetDisplayState): boolean {
  const operation = state.status?.operation;
  return !!operation && operation.operationId === state.cancelledOperationId && !(operation.phase === 'idle' && operation.settlement === 'known');
}

interface IntentPhase {
  intent: AssetIntent;
  localRevision: number;
  contextRevision: number | null;
  previousOperationId: number | null;
  afterStatusRevision: number;
  operation: AssetOperationName;
  expectedPreview: 'save' | 'bind' | 'delete' | null;
  afterSave: boolean;
  existingRecordIds: readonly string[];
  operationId: number | null;
  reviewBinding: string | null;
  uncertain: boolean;
}

export function assetIntentPending(state: AssetDisplayState): boolean {
  const operation = state.status?.operation;
  // Native admission can still be in flight while the last observation says
  // idle. A remounted page must display that original intent, not new defaults.
  return state.intent !== null && (!!state.busy || state.observationFailed || state.blocked ||
    (!!operation && !(operation.phase === 'idle' && operation.settlement === 'known')));
}

export function assetCancellationReason(state: AssetDisplayState): string | null {
  if (state.originPending) return 'The new action has not supplied a usable acknowledgement of its original operation. Wait for its reply or check status; no cancellation has been sent for it. Cancelling the previous step would not cancel this action.';
  if (cancellationPending(state)) return 'Cancellation has already been requested for the original operation. Wait for its cleanup status.';
  return null;
}

export function assetSessionReason(state: AssetDisplayState): string | null {
  if (state.mode !== 'native') return 'Open the native application. Browser previews cannot collect private input.';
  if (state.blocked) return 'This original session is no longer usable. Check its cleanup status; do not start another operation.';
  if (state.observationFailed || !state.status) return 'A current native session status is required. Check status before continuing.';
  if (!state.status.capability.available) return ASSET_REASON_HELP[state.status.capability.reason];
  if (cancellationPending(state)) return 'Cancellation was requested for this original operation. Its old selection and review cannot be used; wait for cleanup status.';
  if (state.busy || state.updatingContext) return 'The original action or context update is still pending.';
  return null;
}
export function assetContextReason(state: AssetDisplayState): string | null {
  return assetSessionReason(state) ?? (state.status?.mode !== 'session' ? 'Start a session first. Nothing is stored persistently.' :
    !state.contextCurrent ? 'Choose a project, prepare a draft, and submit this release context before importing or assigning an item.' : null);
}

export class AssetSessionController {
  private state: AssetDisplayState = freeze({
    mode: 'unavailable', status: null, scope: { platform: 'android', stage: 'candidate', purpose: 'full' },
    contextCurrent: false, busy: null, updatingContext: false, observing: false,
    observationFailed: false, blocked: false, error: null, previewDeadline: null, entryGeneration: 0, selectionKind: null, cancelledOperationId: null, originPending: false, intent: null, reviewReady: false,
  });
  private api: DesktopApi | null = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  private unlisten: (() => void) | null = null;
  private reading: Promise<void> | null = null;
  private contextTask: Promise<void> | null = null;
  private contextDirty = false;
  private localRevision = 0;
  private failureRevision = 0;
  private contextAcknowledged: { localRevision: number; nativeRevision: number } | null = null;
  private projectBinding: { id: string; revision: number; baseline: number } | null = null;
  private spentPreview: string | null = null;
  private spentSelection: string | null = null;
  private reviewCeiling: number | null = null;
  private cancelling: number | null = null;
  private intentPhase: IntentPhase | null = null;
  private selectedProject: () => ProjectSession | null;
  private now: () => number;
  private otherOperationReason: () => string | null;

  constructor(project: () => ProjectSession | null, now: () => number = () => performance.now(), otherOperationReason: () => string | null = () => null) {
    this.selectedProject = project; this.now = now; this.otherOperationReason = otherOperationReason;
  }
  getSnapshot = (): AssetDisplayState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<AssetDisplayState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    this.listeners.forEach((listener) => listener());
  }
  private current(status = this.state.status): boolean {
    const project = this.selectedProject();
    return !!project?.draft && sameRevision(project, this.projectBinding) && !!status?.context && !!this.contextAcknowledged &&
      this.contextAcknowledged.localRevision === this.localRevision && this.contextAcknowledged.nativeRevision === status.context.revision &&
      status.context.projectId === project.project.id && sameScope(status.context, this.state.scope) && status.mode === 'session';
  }
  private fail(error: unknown, protocol = false): void {
    this.failureRevision += 1;
    const safe = assetError(error);
    this.update({ error: safe, observationFailed: true, contextCurrent: false, reviewReady: false,
      blocked: this.state.blocked || protocol || ['cleanup_unknown', 'asset_cleanup_unknown', 'asset_document_lost', 'shutting_down', 'asset_shutdown'].includes(safe.code),
      entryGeneration: this.state.entryGeneration + 1 });
  }
  private reviewMatches(status: AssetStatus | null, observationFailed = this.state.observationFailed, blocked = this.state.blocked): boolean {
    const phase = this.intentPhase;
    const operation = status?.operation;
    const preview = operation?.preview;
    if (!phase || phase.uncertain || phase.localRevision !== this.localRevision || !operation || !preview || status?.mode !== 'session' ||
        phase.operationId !== operation.operationId || operation.operationId === this.cancelling || preview.action !== phase.expectedPreview || observationFailed || blocked) return false;
    const subject = preview.subject;
    if (subject.kind !== phase.intent.kind || (preview.action !== 'delete' && (!this.current(status) || status.context?.revision !== phase.contextRevision))) return false;
    let matches: boolean;
    if (phase.afterSave) {
      if (preview.action !== 'bind' || subject.change !== 'assign' || !subject.recordId || subject.recordRevision === null) return false;
      const original = phase.intent.record;
      matches = original ? subject.recordId === original.recordId && subject.recordRevision === original.expectedRevision + 1 :
        subject.recordRevision === 1 && !phase.existingRecordIds.includes(subject.recordId);
    } else {
      const target = phase.intent.record;
      matches = subject.change === phase.intent.change && (target ? subject.recordId === target.recordId && subject.recordRevision === target.expectedRevision :
        subject.recordId === null && subject.recordRevision === null);
    }
    if (!matches) return false;
    // A phase may return pending before it has a preview. Once the originating
    // operation's first matching review is known, later events cannot replace
    // its token or target. This is bounded presentation correlation, not authority.
    const binding = JSON.stringify([preview.token, preview.action, subject.kind, subject.change, subject.recordId, subject.recordRevision]);
    if (phase.reviewBinding === null) phase.reviewBinding = binding;
    return phase.reviewBinding === binding;
  }
  private phase(intent: AssetIntent, operation: AssetOperationName, expectedPreview: IntentPhase['expectedPreview'], previous: IntentPhase | null = null, afterSave = false): IntentPhase {
    // Only bounded nonsecret identity/intent is retained. Fields and file data
    // never become part of the application-level review model.
    return { intent: structuredClone(intent), localRevision: this.localRevision, contextRevision: this.state.status?.context?.revision ?? null,
      previousOperationId: this.state.status?.operation?.operationId ?? null, afterStatusRevision: this.state.status?.statusRevision ?? 0,
      operation, expectedPreview, afterSave, existingRecordIds: previous?.existingRecordIds ?? this.state.status?.records.map((record) => record.recordId) ?? [],
      operationId: null, reviewBinding: null, uncertain: false };
  }
  private recordIntent(record: AssetRecordRef, change: 'assign' | 'delete'): AssetIntent | null {
    const actual = this.state.status?.records.find((entry) => entry.recordId === record.recordId && entry.revision === record.expectedRevision && entry.availability !== 'mutation-pending');
    return actual ? { kind: actual.kind, change, record: { ...record } } : null;
  }
  private receive(value: unknown, originatingPhase?: IntentPhase): AssetStatus | null {
    if (this.disposed) return null;
    const status = parseAssetStatus(value);
    if (!status) { this.fail({ code: 'AssetStatusInvalid' }, true); return null; }
    if (originatingPhase && this.intentPhase === originatingPhase) {
      // Only this command's own reply establishes its newly admitted native ID.
      // A greater ID from an event/status poll is never an origin receipt.
      const operation = status.operation;
      if (!operation || operation.operation !== originatingPhase.operation || status.statusRevision <= originatingPhase.afterStatusRevision ||
          (originatingPhase.previousOperationId !== null && operation.operationId <= originatingPhase.previousOperationId)) {
        originatingPhase.uncertain = true;
        this.fail({ code: 'assessment_context_stale' });
      } else {
        originatingPhase.operationId = operation.operationId;
        // A newer event may already be displayed. Pin any review in this own
        // reply FIRST, so that overtaking event cannot choose a different token
        // or new-record target merely because it has a greater status revision.
        if (operation.preview && !this.reviewMatches(status, false)) {
          originatingPhase.uncertain = true;
          this.fail({ code: 'assessment_context_stale' });
        }
      }
    }
    const originPending = this.intentPhase !== null && (this.intentPhase.operationId === null || this.intentPhase.uncertain);
    const old = this.state.status;
    if (old && status.statusRevision < old.statusRevision) {
      this.update({ originPending, reviewReady: this.reviewMatches(old) });
      return status;
    }
    if (old && status.statusRevision === old.statusRevision && !sameStatus(status, old)) {
      this.fail({ code: 'AssetStatusInvalid' }, true); return null;
    }
    const cancelled = !!status.operation && status.operation.operationId === this.cancelling;
    const preview = cancelled ? null : status.operation?.preview;
    const previewDeadline = preview ? Math.min(this.reviewCeiling ?? Infinity, this.now() + preview.expiresInMs) : null;
    if (previewDeadline !== null) this.reviewCeiling = previewDeadline;
    const blocked = this.state.blocked || ['cleanup-unknown', 'document-lost', 'shutdown'].includes(status.capability.reason) ||
      status.operation?.phase === 'unknown' || status.operation?.settlement === 'unknown' || status.operation?.settlement === 'late-known';
    this.update({ status, previewDeadline, blocked, originPending, reviewReady: this.reviewMatches(status, this.state.observationFailed, blocked), contextCurrent: !blocked && !this.state.observationFailed && !cancellationPending({ ...this.state, status }) && this.current(status),
      entryGeneration: blocked && !this.state.blocked ? this.state.entryGeneration + 1 : this.state.entryGeneration });
    return status;
  }
  async connect(api: DesktopApi): Promise<void> {
    if (this.disposed || this.api) return;
    this.api = api;
    this.update({ mode: api.mode });
    this.syncProject();
    if (api.mode === 'native') await this.checkStatus();
  }
  async checkStatus(): Promise<void> {
    if (this.disposed || !this.api || this.api.mode !== 'native') return;
    if (this.reading) return this.reading;
    const api = this.api;
    const work = Promise.resolve().then(async () => {
      try {
        if (!this.unlisten) {
          const unlisten = await api.subscribeAssets((value) => { this.receive(value); });
          if (this.disposed) { unlisten(); return; }
          this.unlisten = unlisten;
        }
        if (this.disposed) return;
        const failureRevision = this.failureRevision;
        const status = this.receive(await api.assetStatus());
        if (status && status.statusRevision >= (this.state.status?.statusRevision ?? 0) && failureRevision === this.failureRevision && !this.state.blocked) {
          this.update({ observationFailed: false, error: null, reviewReady: this.reviewMatches(this.state.status, false), contextCurrent: !cancellationPending(this.state) && this.current() });
        }
      } catch (error) { this.fail(error); }
    });
    this.reading = work;
    this.update({ observing: true });
    try { await work; }
    finally { if (this.reading === work) this.reading = null; this.update({ observing: false }); }
  }
  // Called synchronously by the workspace reducer, even when this page is not
  // mounted. Late responses cannot make a prior project/draft look assigned.
  syncProject(): void {
    if (this.disposed) return;
    const project = this.selectedProject();
    if (sameRevision(project, this.projectBinding)) return;
    this.projectBinding = project ? { id: project.project.id, revision: project.revision, baseline: project.baselineGeneration } : null;
    this.invalidateContext();
  }
  setScope(scope: AssetScope): void {
    if (this.disposed || sameScope(scope, this.state.scope)) return;
    this.invalidateContext({ ...scope });
  }
  private invalidateContext(scope = this.state.scope): void {
    this.localRevision += 1;
    if (!Number.isSafeInteger(this.localRevision)) { this.fail({ code: 'AssetStatusInvalid' }, true); return; }
    this.contextAcknowledged = null;
    this.contextDirty = true;
    this.update({ scope, contextCurrent: false, reviewReady: false, selectionKind: null, previewDeadline: null, entryGeneration: this.state.entryGeneration + 1 });
    this.submitContext();
  }
  submitContext(): void {
    const project = this.selectedProject();
    if (this.disposed || !this.api || this.contextTask || this.otherOperationReason() || this.api.mode !== 'native' || this.state.blocked || this.state.observationFailed ||
        this.state.status?.mode !== 'session' || !this.state.status.capability.available || !project?.draft) return;
    // One in-flight context submission; keystrokes coalesce into the latest
    // context, not a queued list of draft copies. No failed request is retried.
    this.contextDirty = false;
    const api = this.api;
    const localRevision = this.localRevision;
    const proposed = { projectId: project.project.id, draft: project.draft, ...this.state.scope };
    if (!assetRequestFits('asset_context', proposed)) { this.fail({ code: 'asset_invalid_request' }); return; }
    const input = structuredClone(proposed);
    const work = Promise.resolve().then(async () => {
      try {
        if (this.otherOperationReason()) { this.contextDirty = true; return; }
        const reply = this.receive(await api.setAssetContext(input));
        if (!this.disposed && reply?.context && localRevision === this.localRevision && reply.context.projectId === input.projectId && sameScope(reply.context, input)) {
          this.contextAcknowledged = { localRevision, nativeRevision: reply.context.revision };
          this.update({ contextCurrent: !this.state.blocked && !this.state.observationFailed && !cancellationPending(this.state) && this.current() });
        }
      } catch (error) { this.fail(error); }
    });
    this.contextTask = work;
    this.update({ updatingContext: true, contextCurrent: false });
    void work.finally(() => {
      if (this.contextTask === work) this.contextTask = null;
      this.update({ updatingContext: false });
      if (this.contextDirty) this.submitContext();
    });
  }
  private run(action: NonNullable<AssetDisplayState['busy']>, invoke: () => Promise<AssetStatus>, phase?: IntentPhase): boolean {
    if (this.disposed || this.state.busy || action !== 'lock' && this.otherOperationReason()) return false;
    if (phase) this.intentPhase = phase;
    this.update({ busy: action, error: null, originPending: phase ? true : this.state.originPending, reviewReady: false, intent: phase?.intent ?? this.state.intent, entryGeneration: this.state.entryGeneration + 1 });
    void (async () => {
      try { this.receive(await invoke(), phase); }
      catch (error) { if (phase) phase.uncertain = true; this.fail(error); }
      finally {
        this.update({ busy: null });
        if (action === 'open') this.submitContext();
      }
    })();
    return true;
  }
  open(): boolean {
    if (!this.api || assetSessionReason(this.state) || this.state.status?.mode !== 'closed') return false;
    return this.run('open', () => this.api!.openAssetSession());
  }
  private contextReady(): boolean { this.syncProject(); return !!this.api && !this.otherOperationReason() && !assetContextReason(this.state) && this.current(); }
  private idle(): boolean { const op = this.state.status?.operation; return !op || (op.phase === 'idle' && op.settlement === 'known'); }
  choose(kind: AssetFileKind, replacement: AssetRecordRef | null = null): boolean {
    if (!this.contextReady() || !this.idle()) return false;
    const request = { contextRevision: this.state.status!.context!.revision, kind, replacement };
    if (replacement && this.replacement(kind, replacement.recordId)?.expectedRevision !== replacement.expectedRevision) return false;
    this.reviewCeiling = null;
    this.update({ selectionKind: kind });
    return this.run('choose-file', () => this.api!.chooseAsset(request), this.phase({ kind, change: replacement ? 'replace' : 'new', record: replacement }, 'choose-file', null));
  }
  prepareSelection(fields: KeystoreFields | Record<string, never>): boolean {
    const operation = this.state.status?.operation;
    const phase = this.intentPhase;
    if (!this.contextReady() || !operation?.selectionToken || operation.selectionToken === this.spentSelection || !this.state.selectionKind ||
        !phase || phase.uncertain || phase.operationId !== operation.operationId || phase.localRevision !== this.localRevision || phase.intent.kind !== this.state.selectionKind) return false;
    const request: CredentialPrepareRequest = { contextRevision: this.state.status!.context!.revision, source: { type: 'selection', selectionToken: operation.selectionToken }, fields };
    if (!assetRequestFits('credential_prepare', request)) { this.update({ error: assetError({ code: 'asset_invalid_request' }) }); return false; }
    this.spentSelection = operation.selectionToken;
    return this.run('prepare', () => this.api!.prepareCredential(request), this.phase(phase.intent, 'prepare', 'save', phase));
  }
  prepareScalar(kind: 'google-wif', fields: WifFields, replacement?: AssetRecordRef | null): boolean;
  prepareScalar(kind: 'project-read-token', fields: TokenFields, replacement?: AssetRecordRef | null): boolean;
  prepareScalar(kind: 'google-wif' | 'project-read-token', fields: WifFields | TokenFields, replacement: AssetRecordRef | null = null): boolean {
    if (!this.contextReady() || !this.idle()) return false;
    const request = { contextRevision: this.state.status!.context!.revision, source: { type: 'scalar', kind, replacement }, fields } as CredentialPrepareRequest;
    if (!assetRequestFits('credential_prepare', request)) { this.update({ error: assetError({ code: 'asset_invalid_request' }) }); return false; }
    if (replacement && this.replacement(kind, replacement.recordId)?.expectedRevision !== replacement.expectedRevision) return false;
    this.reviewCeiling = null;
    return this.run('prepare', () => this.api!.prepareCredential(request), this.phase({ kind, change: replacement ? 'replace' : 'new', record: replacement }, 'prepare', 'save'));
  }
  prepareRecord(record: AssetRecordRef): boolean {
    if (!this.contextReady() || !this.idle()) return false;
    const intent = this.recordIntent(record, 'assign');
    if (!intent) return false;
    const request: CredentialPrepareRequest = { contextRevision: this.state.status!.context!.revision, source: { type: 'record', ...record } };
    this.reviewCeiling = null;
    return this.run('prepare', () => this.api!.prepareCredential(request), this.phase(intent, 'prepare', 'bind'));
  }
  prepareDelete(record: AssetRecordRef): boolean {
    if (!this.api || assetSessionReason(this.state) || this.state.status?.mode !== 'session' || !this.idle()) return false;
    const intent = this.recordIntent(record, 'delete');
    if (!intent) return false;
    this.reviewCeiling = null;
    return this.run('prepare-delete', () => this.api!.prepareAssetDelete(record), this.phase(intent, 'prepare-delete', 'delete'));
  }
  confirmPreview(expectedToken: string, expectedAction: 'save' | 'bind' | 'delete'): boolean {
    this.syncProject();
    const preview = this.state.status?.operation?.preview;
    if (!this.api || assetSessionReason(this.state) || !preview || preview.token !== expectedToken || preview.action !== expectedAction ||
        !this.intentPhase || !this.reviewMatches(this.state.status) || this.spentPreview === expectedToken || this.state.previewDeadline === null || this.now() >= this.state.previewDeadline ||
        (expectedAction !== 'delete' && !this.current())) return false;
    this.spentPreview = expectedToken; // Single-use locally before any invoke.
    const next = this.phase(this.intentPhase.intent, expectedAction === 'bind' ? 'bind' : 'commit', expectedAction === 'save' ? 'bind' : null, this.intentPhase, expectedAction === 'save');
    return this.run(expectedAction === 'bind' ? 'bind' : 'commit', () => expectedAction === 'bind' ? this.api!.bindAsset(expectedToken) : this.api!.commitAsset(expectedToken), next);
  }
  discard(): boolean {
    const operation = this.state.status?.operation;
    if (!this.api || this.state.mode !== 'native' || !operation || (operation.phase === 'idle' && operation.settlement === 'known') || this.cancelling === operation.operationId || this.disposed) return false;
    if (operation.operation === 'choose-evidence-folder' || operation.operation === 'inspect-evidence') return false;
    // Each explicit phase has a fresh native ID. A prior selected/preview
    // status cannot identify a new in-flight operation, even if an event has
    // overtaken its originating acknowledgement. Never fake accepting Cancel.
    if (this.intentPhase && (this.intentPhase.uncertain || this.intentPhase.operationId !== operation.operationId)) return false;
    const operationId = operation.operationId;
    this.cancelling = operationId;
    this.update({ contextCurrent: false, reviewReady: false, previewDeadline: null, selectionKind: null, cancelledOperationId: operationId, entryGeneration: this.state.entryGeneration + 1 });
    void this.api.discardAsset(operationId).then((status) => { this.receive(status); }, (error: unknown) => { this.fail(error); });
    return true;
  }
  lock(): boolean {
    if (!this.api || this.state.mode !== 'native' || this.state.busy || this.disposed || this.state.status?.mode !== 'session') return false;
    this.contextAcknowledged = null;
    this.intentPhase = null;
    this.update({ contextCurrent: false, reviewReady: false, originPending: false, intent: null, selectionKind: null, previewDeadline: null });
    return this.run('lock', () => this.api!.lockAssetSession());
  }
  replacement(kind: AssetKind, recordId: string | null): AssetRecordRef | null | undefined {
    if (recordId === null) return null;
    const record = this.state.status?.records.find((record) => record.kind === kind && record.recordId === recordId && record.availability !== 'mutation-pending');
    return record ? { recordId: record.recordId, expectedRevision: record.revision } : undefined;
  }
  dispose(): void {
    this.disposed = true;
    this.unlisten?.(); this.unlisten = null;
    this.listeners.clear();
    // No process, task, selection or file owner is discarded by renderer teardown.
  }
}
