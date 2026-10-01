// Transient selected-form state; no subprocess, timer, file handle or native
// owner. App routes closed intents through the ORIGINAL native owner. Private
// replies and content-free original progress are separate, even after caller loss.
import { isU32, U32_MAX } from './configEditProtocol.ts';
import { requiredNoteByteLimit, sameRequiredNoteContext } from './requiredNotes.ts';
import type { RequiredNoteContext, RequiredNoteValidation, RequiredNotesLoaded, RequiredNotesPrepared,
  RequiredNotesPrepareInput, RequiredNotesRoutineStatus, RequiredNotesScope } from './requiredNotes.ts';
import { parseRequiredNoteContext, parseRequiredNoteValidation, parseRequiredNotesImportEnvelope, parseRequiredNotesImportReply, parseRequiredNotesLoaded,
  parseRequiredNotesPreparedReply, parseRequiredNotesRoutineEnvelope, requiredNotesImportProgress, requiredNotesStatusProgress } from './requiredNotesProtocol.ts';
import type { RequiredNotesCorrelation, RequiredNotesImportStatus } from './requiredNotesProtocol.ts';

export type RequiredNotesError = 'unavailable' | 'invalid-response' | 'context-changed' | 'operation-unsettled' | 'reload-required' | 'import-refused' | 'request-failed';
export const REQUIRED_NOTES_ERRORS: Record<RequiredNotesError, string> = {
  unavailable: 'This native required-note operation is not available. No alternative CLI or filesystem path was used.',
  'invalid-response': 'The original response could not be accepted. No note contents or diagnostic transcript are shown.',
  'context-changed': 'The selected project, configuration, service or note changed. A previous response cannot replace this draft.',
  'operation-unsettled': 'The original note operation is not fully settled. Do not retry or start another write; check its native status and recovery guidance.',
  'reload-required': 'Reload the saved note before another edit. The last Save result is not a newly observed file baseline.',
  'import-refused': 'The selected file was cancelled, invalid or could not be read safely. Your existing draft was kept.',
  'request-failed': 'The requested operation did not complete. Your draft was kept; no private error details were copied into status.',
};
export type RequiredNotesIntent = {
  id: number; kind: 'load'; scope: RequiredNotesScope; draftRevision: number;
  input: { projectId: string; context: RequiredNoteContext };
} | {
  id: number; kind: 'validate'; scope: RequiredNotesScope; draftRevision: number;
  input: { context: RequiredNoteContext; text: string };
} | {
  id: number; kind: 'prepare'; scope: RequiredNotesScope; draftRevision: number;
  input: RequiredNotesPrepareInput;
} | {
  id: number; kind: 'import'; scope: RequiredNotesScope; draftRevision: number;
  input: { kind: RequiredNoteContext['kind'] };
} | {
  id: number; kind: 'apply'; scope: RequiredNotesScope; draftRevision: number;
  input: { sessionId: string; planToken: string };
} | {
  id: number; kind: 'close'; scope: RequiredNotesScope; draftRevision: number;
  input: { sessionId: string };
};
export interface RequiredNotesState {
  scope: RequiredNotesScope | null;
  loaded: RequiredNotesLoaded | null;
  draft: string;
  draftRevision: number;
  validation: RequiredNoteValidation | null;
  validationRevision: number | null;
  prepared: RequiredNotesPrepared | null;
  status: RequiredNotesRoutineStatus | null;
  importStatus: RequiredNotesImportStatus | null;
  pending: RequiredNotesIntent['kind'] | null;
  error: RequiredNotesError | null;
  unsettled: boolean;
  stale: boolean;
  needsReload: boolean;
  result: 'saved' | 'unchanged' | null;
}
function same(a: unknown, b: unknown): boolean { return JSON.stringify(a) === JSON.stringify(b); }
function scopeEqual(a: RequiredNotesScope | null, b: RequiredNotesScope): boolean {
  return a !== null && a.projectId === b.projectId && a.windowGeneration === b.windowGeneration &&
    a.configGeneration === b.configGeneration && a.serviceGeneration === b.serviceGeneration && sameRequiredNoteContext(a.context, b.context);
}
function empty(scope: RequiredNotesScope | null): RequiredNotesState {
  return { scope, loaded: null, draft: '', draftRevision: 0, validation: null, validationRevision: null,
    prepared: null, status: null, importStatus: null, pending: null, error: null, unsettled: false, stale: false, needsReload: false, result: null };
}
const copy = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;
const encoder = new TextEncoder();
interface OriginalAdmission { requestId: number; scope: RequiredNotesScope; draftRevision: number }

export class RequiredNotesController {
  private current: RequiredNotesState = empty(null);
  private listeners = new Set<() => void>();
  private request: RequiredNotesIntent | null = null;
  private requestClaimed = false;
  // Keep the original Prepare id after its promise fails or the private DTO is
  // lost. A later Apply/Close intent has a NEW UI id, never a new native owner.
  private editAdmission: OriginalAdmission | null = null;
  private importAdmission: OriginalAdmission | null = null;
  private sequence = 0;
  private applyClaimed = false;
  private savedDraft: string | null = null;

  snapshot = (): RequiredNotesState => this.current;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private change(next: Partial<RequiredNotesState>): void {
    this.current = { ...this.current, ...next };
    for (const listener of this.listeners) listener();
  }
  dirty(): boolean {
    if (this.savedDraft === this.current.draft) return false;
    const original = this.current.loaded?.original;
    return !!original && (original.state === 'absent' ? this.current.draft !== '' : original.text !== this.current.draft);
  }
  // Recovery attention is retained on the original content-free status. There
  // is no truthful persisted-note recovery command: Load/discard/scope changes
  // must not erase recovery_required/unknown or manufacture native settlement.
  nativeBusy(): boolean {
    const state = this.current;
    return state.unsettled || this.editAdmission !== null && state.status?.phase !== 'final' ||
      this.importAdmission !== null && state.importStatus?.phase !== 'settled';
  }
  ownerReason(): string | null {
    return this.current.pending ? 'An original required-note request is still pending.' : this.nativeBusy() ?
      'The original required-note operation is active or unverified. Check that original operation before starting another.' : null;
  }
  originalEdit(): RequiredNotesCorrelation | null {
    const original = this.editAdmission;
    return original ? { requestId: original.requestId, windowGeneration: original.scope.windowGeneration } : null;
  }
  originalImport(): RequiredNotesCorrelation | null {
    const original = this.importAdmission;
    return original ? { requestId: original.requestId, windowGeneration: original.scope.windowGeneration } : null;
  }
  claimRequest(request: RequiredNotesIntent): boolean {
    if (!this.matches(request) || this.requestClaimed || this.current.stale && request.kind !== 'close') return false;
    this.requestClaimed = true;
    return true;
  }
  // Caller must confirm discarding an unsaved draft BEFORE changing scope. A
  // native request/owner cannot be detached by switching projects or unmounting.
  setScope(scope: RequiredNotesScope | null, discardConfirmed = false): boolean {
    if (this.request || this.nativeBusy() || this.dirty() && !discardConfirmed) return false;
    if (scope && (!/^[A-Za-z0-9_-]{1,64}$/.test(scope.projectId) || !/^[0-9a-f]{32}$/.test(scope.windowGeneration) ||
      !isU32(scope.configGeneration) || !isU32(scope.serviceGeneration) || !parseRequiredNoteContext(scope.context))) return false;
    this.request = null; this.requestClaimed = false; this.applyClaimed = false; this.savedDraft = null;
    this.editAdmission = null; this.importAdmission = null;
    this.current = empty(scope ? copy(scope) : null);
    for (const listener of this.listeners) listener();
    return true;
  }
  invalidateContext(): void {
    // Config/service/project invalidation freezes the old form without stopping
    // an owner or permitting a late result to replace a newer draft.
    if (!this.current.stale) this.change({ stale: true, error: 'context-changed' });
  }
  edit(text: string): boolean {
    if (!this.current.loaded || this.request || this.nativeBusy() || this.current.needsReload || this.current.stale ||
      typeof text !== 'string' || text.length > 65537 || this.current.draftRevision === U32_MAX) return false;
    this.savedDraft = null; this.editAdmission = null; this.importAdmission = null;
    this.change({ draft: text, draftRevision: this.current.draftRevision + 1, validation: null, validationRevision: null,
      prepared: null, status: null, importStatus: null, result: null, error: null });
    return true;
  }
  private admit(): RequiredNotesScope | null {
    if (!this.current.scope || this.request || this.nativeBusy() || this.current.stale || this.sequence === U32_MAX) return null;
    return copy(this.current.scope);
  }
  private start(request: RequiredNotesIntent): RequiredNotesIntent {
    this.request = request; this.requestClaimed = false;
    const next: Partial<RequiredNotesState> = { pending: request.kind, error: null, result: null };
    if (request.kind === 'prepare') {
      this.editAdmission = { requestId: request.id, scope: copy(request.scope), draftRevision: request.draftRevision };
      Object.assign(next, { prepared: null, status: null });
    } else if (request.kind === 'import') {
      this.importAdmission = { requestId: request.id, scope: copy(request.scope), draftRevision: request.draftRevision };
      next.importStatus = null;
    }
    this.change(next);
    return request;
  }
  beginLoad(replaceDraftConfirmed = false): RequiredNotesIntent | null {
    const scope = this.admit();
    if (!scope || this.dirty() && !replaceDraftConfirmed) return null;
    return this.start({ id: ++this.sequence, kind: 'load', scope, draftRevision: this.current.draftRevision,
      input: { projectId: scope.projectId, context: copy(scope.context) } });
  }
  beginValidate(): RequiredNotesIntent | null {
    const scope = this.admit();
    if (!scope || !this.current.loaded || this.current.needsReload) return null;
    return this.start({ id: ++this.sequence, kind: 'validate', scope, draftRevision: this.current.draftRevision,
      input: { context: copy(scope.context), text: this.current.draft } });
  }
  beginPrepare(): RequiredNotesIntent | null {
    const scope = this.admit(), state = this.current;
    if (!scope || !state.loaded || !state.validation?.valid || state.validationRevision !== state.draftRevision || state.needsReload) return null;
    this.applyClaimed = false;
    return this.start({ id: ++this.sequence, kind: 'prepare', scope, draftRevision: state.draftRevision,
      input: { projectId: scope.projectId, context: copy(scope.context), expectedBaseline: copy(state.loaded.baseline), text: state.draft, draftRevision: state.draftRevision } });
  }
  beginImport(replaceDraftConfirmed = false): RequiredNotesIntent | null {
    const scope = this.admit();
    if (!scope || !this.current.loaded || this.current.needsReload || this.current.draft !== '' && !replaceDraftConfirmed) return null;
    return this.start({ id: ++this.sequence, kind: 'import', scope, draftRevision: this.current.draftRevision, input: { kind: scope.context.kind } });
  }
  canApply(): boolean {
    const s = this.current, p = s.prepared, status = s.status;
    return !!p && !!status && !this.request && !s.unsettled && !s.needsReload && !s.stale && !this.applyClaimed &&
      status.phase === 'reviewing' && status.nativeReason === 'none' && status.nativeFinality === 'pending' && !status.lateSettled && !status.applySubmitted &&
      status.coreOutcome === null && p.draftRevision === s.draftRevision && p.after === s.draft;
  }
  beginApply(): RequiredNotesIntent | null {
    const scope = this.current.scope, prepared = this.current.prepared;
    if (!scope || !prepared || !this.canApply() || this.sequence === U32_MAX) return null;
    this.applyClaimed = true; // Latch BEFORE handing anything to the native caller.
    return this.start({ id: ++this.sequence, kind: 'apply', scope: copy(scope), draftRevision: this.current.draftRevision,
      input: { sessionId: prepared.sessionId, planToken: prepared.planToken } });
  }
  // A refused, UNDISPATCHED Apply consumes its UI claim, not the original
  // review. Permit explicit original Close; never enable an automatic retry.
  canClose(): boolean {
    const state = this.current, original = this.editAdmission;
    const session = state.status?.sessionId ?? state.prepared?.sessionId;
    return !!original && !!session && !this.request && !state.unsettled && !state.status?.applySubmitted &&
      state.status?.phase !== 'final' && state.status?.phase !== 'unknown' && state.status?.nativeFinality !== 'unknown';
  }
  beginClose(sessionId?: string): RequiredNotesIntent | null {
    if (!this.canClose() || this.sequence === U32_MAX || !this.current.scope) return null;
    const originalSession = this.current.status?.sessionId ?? this.current.prepared?.sessionId;
    if (!originalSession || sessionId !== undefined && sessionId !== originalSession) return null;
    return this.start({ id: ++this.sequence, kind: 'close', scope: copy(this.current.scope), draftRevision: this.current.draftRevision,
      input: { sessionId: originalSession } });
  }
  private matches(request: RequiredNotesIntent): boolean {
    return this.request === request && scopeEqual(this.current.scope, request.scope) && this.current.draftRevision === request.draftRevision;
  }
  complete(request: RequiredNotesIntent, value: unknown): boolean {
    if (!this.matches(request)) return false;
    if (request.kind === 'apply' || request.kind === 'close') return this.acceptStatus(value, request);
    // Import may carry original settlement even after context invalidation; its
    // text is never published in that case. A stale Load/Prepare is not a route
    // to a new selected project or a replacement native session.
    if (request.kind === 'import') return this.completeImport(request, value);
    if (this.current.stale) return this.refuse(request, request.kind === 'prepare', 'context-changed');
    if (request.kind === 'load') {
      const loaded = parseRequiredNotesLoaded(value);
      if (!loaded || loaded.projectId !== request.scope.projectId || loaded.windowGeneration !== request.scope.windowGeneration ||
        !sameRequiredNoteContext(loaded.selection.context, request.scope.context)) return this.refuse(request, false);
      this.request = null; this.requestClaimed = false; this.applyClaimed = false; this.savedDraft = null;
      this.editAdmission = null; this.importAdmission = null;
      this.change({ loaded, draft: loaded.original.state === 'absent' ? '' : loaded.original.text, draftRevision: 0,
        validation: loaded.validation, validationRevision: 0, pending: null, prepared: null, status: null, importStatus: null,
        unsettled: false, error: null, needsReload: false, result: null });
      return true;
    }
    if (request.kind === 'validate') {
      const validation = parseRequiredNoteValidation(value);
      if (!validation || validation.kind !== request.scope.context.kind || validation.rawByteCount !== encoder.encode(request.input.text).byteLength) return this.refuse(request, false);
      this.request = null; this.requestClaimed = false;
      this.change({ validation, validationRevision: request.draftRevision, pending: null }); return true;
    }
    const reply = parseRequiredNotesPreparedReply(value), loaded = this.current.loaded, original = this.editAdmission;
    const prepared = reply?.prepared, previous = this.current.status;
    if (!reply || reply.requestId !== request.id || !original || original.requestId !== request.id || !prepared || !loaded ||
      prepared.projectId !== request.scope.projectId || prepared.windowGeneration !== request.scope.windowGeneration ||
      prepared.draftRevision !== request.draftRevision || prepared.after !== request.input.text || !same(prepared.baseline, request.input.expectedBaseline) ||
      !same(prepared.selection, loaded.selection) || !same(prepared.before, loaded.original) ||
      previous && (previous.ownerGeneration !== prepared.ownerGeneration || previous.sessionId !== prepared.sessionId ||
        previous.revision !== null && previous.revision !== prepared.revision || previous.planToken !== null && previous.planToken !== prepared.planToken)) {
      return this.refuse(request, true);
    }
    // A direct private reply can arrive after the ORIGINAL terminal/unknown
    // event. Acknowledge it without restoring a preview or downgrading finality.
    this.request = null; this.requestClaimed = false;
    if (previous && (previous.phase === 'final' || previous.phase === 'unknown' || previous.nativeFinality !== 'pending' ||
      previous.nativeReason !== 'none' || previous.lateSettled || previous.applySubmitted || previous.coreOutcome !== null)) {
      this.change({ pending: null }); return true;
    }
    this.change({ prepared, pending: null, unsettled: false, error: null });
    return true;
  }
  private importMatches(status: RequiredNotesImportStatus): boolean {
    const original = this.importAdmission;
    return !!original && status.requestId === original.requestId && status.windowGeneration === original.scope.windowGeneration &&
      status.projectId === original.scope.projectId && sameRequiredNoteContext(status.context, original.scope.context);
  }
  private completeImport(request: Extract<RequiredNotesIntent, { kind: 'import' }>, value: unknown): boolean {
    const reply = parseRequiredNotesImportReply(value);
    if (!reply || reply.requestId !== request.id || !this.importMatches(reply.status) ||
      this.current.importStatus && !requiredNotesImportProgress(this.current.importStatus, reply.status)) return this.refuse(request, true, 'import-refused');
    const status = reply.status, imported = reply.result;
    this.request = null; this.requestClaimed = false;
    if (status.phase === 'unknown') {
      this.change({ pending: null, importStatus: status, unsettled: true, error: 'operation-unsettled' }); return true;
    }
    if (this.current.stale) {
      this.change({ pending: null, importStatus: status, unsettled: false, error: 'context-changed' }); return true;
    }
    if (status.outcome === 'refused' || !imported) {
      this.change({ pending: null, importStatus: status, unsettled: false, error: 'import-refused' }); return true;
    }
    if (imported.state === 'cancelled') {
      this.change({ pending: null, importStatus: status, unsettled: false, error: null }); return true;
    }
    if (request.draftRevision === U32_MAX || imported.kind !== request.scope.context.kind ||
        encoder.encode(imported.text).byteLength > requiredNoteByteLimit(imported.kind)) {
      this.change({ pending: null, importStatus: status, unsettled: false, error: 'import-refused' }); return false;
    }
    // Complete ALL state and private bookkeeping before notifying subscribers.
    // Reentrant discard/switch/edit/new requests cannot be overwritten later.
    this.savedDraft = null; this.editAdmission = null;
    this.change({ draft: imported.text, draftRevision: request.draftRevision + 1, validation: imported.validation,
      validationRevision: request.draftRevision + 1, pending: null, prepared: null, status: null, importStatus: status,
      unsettled: false, result: null, error: null });
    return true;
  }
  acceptImportStatus(value: unknown): boolean {
    const envelope = parseRequiredNotesImportEnvelope(value), previous = this.current.importStatus;
    if (!envelope || !this.importMatches(envelope.status) || previous && !requiredNotesImportProgress(previous, envelope.status)) return false;
    const status = envelope.status;
    if (previous && same(previous, status)) return true;
    // Original settlement may release a lost-call gate; it NEVER recreates lost
    // private imported text, validates this draft or changes its baseline.
    this.change({ importStatus: status, unsettled: status.phase === 'unknown' || status.phase === 'pending' && this.current.unsettled,
      ...(status.phase === 'unknown' ? { error: 'operation-unsettled' as const } : {}),
      ...(status.phase === 'settled' && status.outcome === 'refused' ? { error: 'import-refused' as const } : {}) });
    return true;
  }
  private originalSettled(request: RequiredNotesIntent): boolean {
    if (request.kind === 'import') return this.current.importStatus?.phase === 'settled';
    const status = this.current.status;
    return !!status && status.phase === 'final' && status.nativeFinality === 'settled' && status.coreOutcome?.resources === 'settled' &&
      (status.coreOutcome.journal === 'not_created' || status.coreOutcome.journal === 'clean');
  }
  private refuse(request: RequiredNotesIntent, unsettled: boolean, error: RequiredNotesError = 'invalid-response'): false {
    if (this.request === request) {
      this.request = null; this.requestClaimed = false;
      // An observer rejection is weaker than already accepted ORIGINAL finality.
      // It cannot undo a saved result or revive an already retired private view.
      if (unsettled && this.originalSettled(request)) this.change({ pending: null, ...(this.current.result ? {} : { error }) });
      else if (request.kind === 'prepare' && this.current.status?.phase === 'reviewing' &&
          this.current.status.nativeFinality === 'pending' && this.current.status.nativeReason === 'none' &&
          !this.current.status.applySubmitted && !this.current.status.lateSettled && this.current.status.coreOutcome === null) {
        // A matching original review event can precede loss/rejection of the
        // private Prepare reply. Keep that owner (and no preview), but permit
        // explicit original Close; this is neither Save nor cleanup evidence.
        this.change({ pending: null, prepared: null, unsettled: false, error });
      } else this.change({ pending: null, unsettled: this.current.unsettled || unsettled, error });
    }
    return false;
  }
  fail(request: RequiredNotesIntent): void {
    if (!this.matches(request)) return;
    // Failed invokes may already be admitted. Keep the ORIGINAL correlation for
    // both native edits and OriginalWork import; never infer cleanup from loss.
    this.refuse(request, ['prepare', 'apply', 'close', 'import'].includes(request.kind), 'request-failed');
  }
  unavailable(request: RequiredNotesIntent): void {
    // Capability refusal BEFORE native dispatch only; claimed requests cannot
    // use this to manufacture non-admission or clear an original owner's gate.
    if (!this.matches(request) || this.requestClaimed) return;
    if (request.kind === 'prepare' && this.editAdmission?.requestId === request.id) this.editAdmission = null;
    if (request.kind === 'import' && this.importAdmission?.requestId === request.id) this.importAdmission = null;
    this.refuse(request, false, 'unavailable');
  }
  acceptRoutineStatus(value: unknown): boolean { return this.acceptStatus(value); }
  private acceptStatus(value: unknown, complete?: RequiredNotesIntent): boolean {
    const envelope = parseRequiredNotesRoutineEnvelope(value), original = this.editAdmission;
    const status = envelope?.status, p = this.current.prepared, previous = this.current.status;
    if (!envelope || !status || !original || envelope.requestId !== original.requestId ||
      status.projectId !== original.scope.projectId || status.windowGeneration !== original.scope.windowGeneration ||
      status.draftRevision !== original.draftRevision || !sameRequiredNoteContext(status.context, original.scope.context)) {
      if (complete) this.refuse(complete, true, 'operation-unsettled');
      return false;
    }
    // Match original request FIRST, including when private Prepare was lost.
    if (previous && status.statusRevision <= previous.statusRevision && requiredNotesStatusProgress(status, previous)) {
      if (complete) { this.request = null; this.requestClaimed = false; this.change({ pending: null }); }
      return true;
    }
    if (previous && !requiredNotesStatusProgress(previous, status) || p &&
      (status.ownerGeneration !== p.ownerGeneration || status.sessionId !== p.sessionId ||
       status.planToken !== p.planToken || status.revision !== p.revision)) {
      if (complete) this.refuse(complete, true, 'operation-unsettled');
      return false;
    }
    const core = status.coreOutcome;
    const unexpectedApply = status.applySubmitted && !this.applyClaimed;
    const next: Partial<RequiredNotesState> = { ...(complete ? { pending: null } : {}), status,
      unsettled: unexpectedApply || status.phase === 'unknown' || status.nativeFinality === 'unknown' || core?.resources === 'unknown' ||
        core?.journal === 'recovery_required' || core?.journal === 'unknown' };
    if (unexpectedApply) Object.assign(next, { prepared: null, error: 'operation-unsettled', needsReload: true });
    if (status.phase === 'unknown') Object.assign(next, { prepared: null, error: 'operation-unsettled' });
    if (status.phase === 'final') {
      const normal = status.nativeReason === 'none' && status.nativeFinality === 'settled' && !status.lateSettled &&
        status.applySubmitted && this.applyClaimed && core?.resources === 'settled' && core.reason === 'none';
      const result = normal && p && core?.effect === 'committed' && core.journal === 'clean' && p.action !== 'preserve' ? 'saved' :
        normal && p && core?.effect === 'unchanged' && core.journal === 'not_created' && p.action === 'preserve' ? 'unchanged' : null;
      if (result && p) {
        this.savedDraft = p.after;
        Object.assign(next, { result, needsReload: true, error: null, prepared: null });
      } else if (core?.effect === 'not_started' && core.journal === 'not_created' && core.resources === 'settled' && !status.applySubmitted) {
        this.applyClaimed = false;
        Object.assign(next, { prepared: null, result: null, error: 'request-failed' });
      } else {
        Object.assign(next, { prepared: null, needsReload: true, error: 'operation-unsettled' });
      }
    }
    // Preserve SOURCE02 atomicity: all original bookkeeping precedes the sole
    // notification; no later write relabels a subscriber's new draft/project.
    if (complete) { this.request = null; this.requestClaimed = false; }
    this.change(next);
    return true;
  }
  discardDraft(confirmed: boolean): boolean {
    if (!confirmed || this.request || this.nativeBusy()) return false;
    const scope = this.current.scope;
    this.savedDraft = null; this.applyClaimed = false; this.requestClaimed = false;
    this.editAdmission = null; this.importAdmission = null; this.current = empty(scope);
    for (const listener of this.listeners) listener();
    return true;
  }
}
