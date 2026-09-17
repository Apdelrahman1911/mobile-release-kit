import { blockingAncestor, getValue, sameJson, setValue } from './catalog.ts';
import { pathsOverlap } from './preparation.ts';
import type { PreparationRequest } from './preparation.ts';
import type { ApiError, ConfigPreview, ConfigSuggestion, JsonObject, JsonValue, ProjectReference, ProjectSnapshot, ValidationResult } from './types.ts';

export interface SuggestionRequest extends PreparationRequest {
  observationGeneration: number;
  observedHints: boolean;
  partial: boolean;
  omittedStrings: number;
}

export interface RemovedField {
  id: number;
  path: string;
  value: JsonValue;
  blocked: boolean;
}

export interface ProjectSession {
  project: ProjectReference;
  snapshot: ProjectSnapshot | null;
  snapshotRequest: number | null;
  snapshotError: ApiError | null;
  observedAt: number | null;
  observationGeneration: number;
  baseline: JsonObject | null;
  baselineGeneration: number;
  draft: JsonObject | null;
  draftOrigin: 'observation' | 'empty' | 'suggestion' | null;
  revision: number;
  sourceChanged: boolean;
  validation: ValidationResult | null;
  validatedRevision: number | null;
  validatedBaselineGeneration: number | null;
  validationRequest: PreparationRequest | null;
  validationError: ApiError | null;
  review: { result: ConfigPreview; binding: PreparationRequest } | null;
  reviewRequest: PreparationRequest | null;
  reviewError: ApiError | null;
  suggestion: { result: ConfigSuggestion; binding: SuggestionRequest } | null;
  suggestionRequest: SuggestionRequest | null;
  suggestionError: ApiError | null;
  removedFields: RemovedField[];
  nextRemovalId: number;
  editError: ApiError | null;
}

export interface WorkspaceState {
  selectedId: string | null;
  projects: Record<string, ProjectSession>;
}

export const initialWorkspace: WorkspaceState = { selectedId: null, projects: {} };

export type WorkspaceAction =
  | { type: 'select'; project: ProjectReference }
  | { type: 'switch'; projectId: string }
  | { type: 'snapshot-start'; projectId: string; requestId: number }
  | { type: 'snapshot-done'; projectId: string; requestId: number; snapshot: ProjectSnapshot; observedAt: number }
  | { type: 'snapshot-failed'; projectId: string; requestId: number; error: ApiError }
  | { type: 'new-draft'; projectId: string; draft: JsonObject }
  | { type: 'edit'; projectId: string; path: string; value: JsonValue | undefined }
  | { type: 'remove-forbidden'; projectId: string; reviewId: number; paths: string[] }
  | { type: 'undo-removal'; projectId: string; removalId: number }
  | { type: 'forget-removal'; projectId: string; removalId: number }
  | { type: 'reset'; projectId: string }
  | { type: 'validate-start'; projectId: string; requestId: number; revision: number; baselineGeneration: number }
  | { type: 'validate-done'; projectId: string; requestId: number; result: ValidationResult }
  | { type: 'validate-failed'; projectId: string; requestId: number; error: ApiError }
  | { type: 'review-start'; projectId: string; binding: PreparationRequest }
  | { type: 'review-done'; projectId: string; requestId: number; result: ConfigPreview }
  | { type: 'review-failed'; projectId: string; requestId: number; error: ApiError }
  | { type: 'suggest-start'; projectId: string; binding: SuggestionRequest }
  | { type: 'suggest-done'; projectId: string; requestId: number; result: ConfigSuggestion }
  | { type: 'suggest-failed'; projectId: string; requestId: number; error: ApiError }
  | { type: 'adopt-suggestion'; projectId: string; requestId: number };

export function isDirty(session: ProjectSession): boolean {
  return session.draft !== null && !sameJson(session.draft, session.baseline);
}

export function validationFresh(session: ProjectSession): boolean {
  return session.validation !== null && session.validatedRevision === session.revision &&
    session.validatedBaselineGeneration === session.baselineGeneration;
}

function bindingMatches(session: ProjectSession, binding: PreparationRequest): boolean {
  return binding.revision === session.revision && binding.baselineGeneration === session.baselineGeneration;
}

export function reviewFresh(session: ProjectSession): boolean {
  return session.review !== null && bindingMatches(session, session.review.binding);
}

export function suggestionFresh(session: ProjectSession): boolean {
  return session.suggestion !== null && bindingMatches(session, session.suggestion.binding) &&
    session.suggestion.binding.observationGeneration === session.observationGeneration && session.snapshotRequest === null;
}

export function canUndoRemoval(session: ProjectSession, removal: RemovedField): boolean {
  return session.draft !== null && !removal.blocked &&
    blockingAncestor(session.draft, removal.path) === null && getValue(session.draft, removal.path) === undefined;
}

function editFailure(session: ProjectSession, message: string): ProjectSession {
  return { ...session, editError: { code: 'DraftUnchanged', message, retryable: false } };
}

function edited(session: ProjectSession, draft: JsonObject, paths: string[]): ProjectSession {
  return {
    ...session, draft, revision: session.revision + 1, validationError: null, reviewError: null, editError: null,
    removedFields: session.removedFields.map((entry) => paths.some((path) => pathsOverlap(path, entry.path)) ? { ...entry, blocked: true } : entry),
  };
}

function removeFields(session: ProjectSession, paths: string[]): ProjectSession {
  if (!session.draft) return session;
  const present = [...new Set(paths)].filter((path) => getValue(session.draft, path) !== undefined);
  if (present.length === 0) return session;
  // Never silently evict an undo copy. All retained values stay in this project's
  // memory until restored, explicitly forgotten, or the draft is discarded.
  if (session.removedFields.length + present.length > 64) {
    return editFailure(session, 'The in-memory undo list is full. Explicitly forget an old removal before unsetting more fields. No draft values changed.');
  }
  let draft = session.draft;
  const removals: RemovedField[] = [];
  for (const path of present) {
    const value = getValue(draft, path);
    if (value === undefined || blockingAncestor(draft, path) !== null) continue;
    removals.push({ id: session.nextRemovalId + removals.length, path, value: structuredClone(value), blocked: false });
    draft = setValue(draft, path, undefined);
  }
  if (removals.length === 0) return session;
  const next = edited(session, draft, present);
  return { ...next, removedFields: [...next.removedFields, ...removals], nextRemovalId: session.nextRemovalId + removals.length };
}

export function workspaceReducer(state: WorkspaceState, action: WorkspaceAction): WorkspaceState {
  if (action.type === 'select') {
    if (Object.hasOwn(state.projects, action.project.id)) {
      return { ...state, selectedId: action.project.id };
    }
    const session: ProjectSession = {
      project: action.project, snapshot: null, snapshotRequest: null, snapshotError: null,
      observedAt: null, observationGeneration: 0, baseline: null, baselineGeneration: 0,
      draft: null, draftOrigin: null, revision: 0, sourceChanged: false,
      validation: null, validatedRevision: null, validatedBaselineGeneration: null, validationRequest: null, validationError: null,
      review: null, reviewRequest: null, reviewError: null,
      suggestion: null, suggestionRequest: null, suggestionError: null,
      removedFields: [], nextRemovalId: 1, editError: null,
    };
    return { selectedId: action.project.id, projects: { ...state.projects, [action.project.id]: session } };
  }
  if (action.type === 'switch') {
    return Object.hasOwn(state.projects, action.projectId) ? { ...state, selectedId: action.projectId } : state;
  }
  const session = Object.hasOwn(state.projects, action.projectId) ? state.projects[action.projectId] : undefined;
  if (!session) return state;
  let next: ProjectSession;
  switch (action.type) {
    case 'snapshot-start':
      next = { ...session, snapshotRequest: action.requestId, snapshotError: null };
      break;
    case 'snapshot-done': {
      if (session.snapshotRequest !== action.requestId) return state;
      const incoming = action.snapshot.config.data;
      // Once a draft exists, refresh is observation only, even if the draft is
      // clean. Accepting a different baseline needs the explicit discard flow.
      const keepDraft = session.draft !== null;
      const changed = !sameJson(session.baseline, incoming);
      next = {
        ...session, snapshot: action.snapshot, snapshotRequest: null, snapshotError: null,
        observedAt: action.observedAt, sourceChanged: keepDraft && changed,
        observationGeneration: session.observationGeneration + 1,
        baseline: keepDraft ? session.baseline : incoming,
        baselineGeneration: keepDraft ? session.baselineGeneration : session.baselineGeneration + 1,
        draft: keepDraft ? session.draft : incoming,
        draftOrigin: keepDraft ? session.draftOrigin : incoming ? 'observation' : null,
        revision: !keepDraft && changed ? session.revision + 1 : session.revision,
      };
      break;
    }
    case 'snapshot-failed':
      if (session.snapshotRequest !== action.requestId) return state;
      next = { ...session, snapshotRequest: null, snapshotError: action.error };
      break;
    case 'new-draft':
      if (session.draft !== null) return state;
      next = { ...session, draft: action.draft, draftOrigin: 'empty', revision: session.revision + 1, validationError: null, editError: null };
      break;
    case 'edit': {
      if (session.draft === null) return state;
      if (blockingAncestor(session.draft, action.path) !== null) {
        next = editFailure(session, 'A parent field has a non-object value. It was preserved; a child control cannot replace it.');
      } else if (action.value === undefined) {
        next = removeFields(session, [action.path]);
      } else {
        const draft = setValue(session.draft, action.path, action.value);
        if (draft === session.draft) return state;
        next = edited(session, draft, [action.path]);
      }
      break;
    }
    case 'remove-forbidden': {
      if (!reviewFresh(session) || session.review?.binding.id !== action.reviewId) return state;
      const allowed = new Set(session.review.result.fields.filter((field) => field.state === 'forbidden' && field.present).map((field) => field.path));
      if (action.paths.some((path) => !allowed.has(path))) return state;
      next = removeFields(session, action.paths);
      break;
    }
    case 'undo-removal': {
      const removal = session.removedFields.find((entry) => entry.id === action.removalId);
      if (!removal || !session.draft) return state;
      if (!canUndoRemoval(session, removal)) {
        next = editFailure(session, 'That field or its parent changed after removal. Undo will not overwrite subsequent edits. The earlier value remains in memory until you forget it.');
      } else {
        next = edited(session, setValue(session.draft, removal.path, structuredClone(removal.value)), [removal.path]);
        next.removedFields = next.removedFields.filter((entry) => entry.id !== action.removalId);
      }
      break;
    }
    case 'forget-removal':
      next = { ...session, removedFields: session.removedFields.filter((entry) => entry.id !== action.removalId), editError: null };
      break;
    case 'reset': {
      const data = session.snapshot?.config.data ?? null;
      next = {
        ...session, baseline: data, baselineGeneration: session.baselineGeneration + 1,
        draft: data, draftOrigin: data ? 'observation' : null, revision: session.revision + 1,
        sourceChanged: false, validation: null, validatedRevision: null, validationError: null,
        validatedBaselineGeneration: null, validationRequest: null,
        review: null, reviewRequest: null, reviewError: null,
        suggestion: null, suggestionRequest: null, suggestionError: null,
        removedFields: [], editError: null,
      };
      break;
    }
    case 'validate-start':
      if (session.draft === null || action.revision !== session.revision || action.baselineGeneration !== session.baselineGeneration) return state;
      next = { ...session, validationRequest: { id: action.requestId, revision: action.revision, baselineGeneration: action.baselineGeneration }, validationError: null };
      break;
    case 'validate-done':
      if (session.validationRequest?.id !== action.requestId) return state;
      next = {
        ...session, validation: action.result, validatedRevision: session.validationRequest.revision,
        validatedBaselineGeneration: session.validationRequest.baselineGeneration,
        validationRequest: null, validationError: null,
      };
      break;
    case 'validate-failed':
      if (session.validationRequest?.id !== action.requestId) return state;
      next = { ...session, validationRequest: null, validationError: action.error };
      break;
    case 'review-start':
      if (!session.draft || !bindingMatches(session, action.binding)) return state;
      next = { ...session, reviewRequest: action.binding, reviewError: null };
      break;
    case 'review-done':
      if (session.reviewRequest?.id !== action.requestId) return state;
      next = { ...session, review: { result: action.result, binding: session.reviewRequest }, reviewRequest: null, reviewError: null };
      break;
    case 'review-failed':
      if (session.reviewRequest?.id !== action.requestId) return state;
      next = { ...session, reviewRequest: null, reviewError: action.error };
      break;
    case 'suggest-start':
      if (session.draft !== null || !bindingMatches(session, action.binding) || action.binding.observationGeneration !== session.observationGeneration || session.snapshotRequest !== null) return state;
      next = { ...session, suggestionRequest: action.binding, suggestionError: null };
      break;
    case 'suggest-done':
      if (session.suggestionRequest?.id !== action.requestId) return state;
      next = { ...session, suggestion: { result: action.result, binding: session.suggestionRequest }, suggestionRequest: null, suggestionError: null };
      break;
    case 'suggest-failed':
      if (session.suggestionRequest?.id !== action.requestId) return state;
      next = { ...session, suggestionRequest: null, suggestionError: action.error };
      break;
    case 'adopt-suggestion':
      if (session.draft !== null || !suggestionFresh(session) || session.suggestion?.binding.id !== action.requestId) return state;
      next = { ...session, draft: structuredClone(session.suggestion.result.draft), draftOrigin: 'suggestion', revision: session.revision + 1, editError: null };
      break;
  }
  return { ...state, projects: { ...state.projects, [action.projectId]: next } };
}
