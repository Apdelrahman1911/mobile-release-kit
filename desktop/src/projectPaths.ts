// UI binding/display checks only. Native code owns registered-root containment,
// leaf metadata and original cleanup. No path here authorizes a read or a save.
import { blockingAncestor, getValue, isObject } from './catalog.ts';
import type { WorkspaceState } from './drafts.ts';
import type { ApiError, AppInfo, BridgeMode, FieldHelp, HelpContent, JsonObject, ProjectPathField, ProjectPathRequest, ProjectPathSelection } from './types.ts';

export const PROJECT_PATH_FIELDS = ['version.source', 'ios.project', 'ios.workspace', 'metadata.root'] as const;
export function isProjectPathField(value: unknown): value is ProjectPathField {
  return typeof value === 'string' && PROJECT_PATH_FIELDS.some((field) => field === value);
}
const encoder = new TextEncoder();
function fields(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  if (!isObject(value)) return null;
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const names = Reflect.ownKeys(value);
  if (names.length !== keys.length) return null;
  const copy: Record<string, unknown> = {};
  for (const name of names) {
    if (typeof name !== 'string' || !keys.includes(name)) return null;
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return null;
    copy[name] = descriptor.value;
  }
  return copy;
}
function projectId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 64 && !/[^A-Za-z0-9_-]/.test(value);
}
export function parseProjectPathRequest(value: unknown): ProjectPathRequest | null {
  try {
    const input = fields(value, ['projectId', 'field']);
    if (!input || !projectId(input.projectId) || !isProjectPathField(input.field)) return null;
    const result = { projectId: input.projectId, field: input.field };
    return encoder.encode(JSON.stringify(result)).byteLength <= 1024 ? result : null;
  } catch { return null; }
}
function relativeDisplayPath(value: unknown): value is string {
  if (typeof value !== 'string' || !value || value.length > 512 || /[\ud800-\udfff]/u.test(value) || encoder.encode(value).byteLength > 512) return false;
  const parts = value.split('/');
  // Match release_version_protocol's conservative display restrictions. Do not
  // trim, normalize, truncate, resolve '..', or invent an absolute-path prefix.
  return parts.length <= 12 && parts.every((part) => part.length > 0 && encoder.encode(part).byteLength <= 255 &&
    !part.startsWith('.') && !/[. ]$/.test(part) && !/[\u0000-\u001f\u007f\\:<>"|?*]/u.test(part) &&
    !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part) &&
    !['private', 'secrets', 'credentials', 'review', 'testflight', 'build', 'deriveddata', 'pods', 'node_modules', 'venv', 'dist', 'target', '__pycache__'].includes(part.toLowerCase()));
}
// Undefined is a malformed/unknown outcome, not the native settled Cancel null.
export function parseProjectPathSelection(value: unknown, request: ProjectPathRequest): ProjectPathSelection | null | undefined {
  if (value === null) return null;
  try {
    const input = fields(value, ['projectId', 'field', 'relativePath']);
    if (!input || !projectId(input.projectId) || !isProjectPathField(input.field) || !relativeDisplayPath(input.relativePath) ||
        input.projectId !== request.projectId || input.field !== request.field ||
        input.field === 'ios.project' && !input.relativePath.endsWith('.xcodeproj') ||
        input.field === 'ios.workspace' && !input.relativePath.endsWith('.xcworkspace')) return undefined;
    const result = { projectId: input.projectId, field: input.field, relativePath: input.relativePath };
    return encoder.encode(JSON.stringify(result)).byteLength <= 1024 ? result : undefined;
  } catch { return undefined; }
}

export function projectPathAvailabilityReason(info: AppInfo | null, mode: BridgeMode): string | null {
  if (mode === 'preview') return 'Browser preview cannot browse project files. Text entry remains available.';
  if (mode !== 'native') return 'Open the installed desktop application to browse existing project paths.';
  try {
    const descriptor = info && Object.getOwnPropertyDescriptor(info, 'projectPathSelection');
    const selection = fields(descriptor?.enumerable && Object.hasOwn(descriptor, 'value') ? descriptor.value : null, ['available', 'reason']);
    if (selection?.available === true && selection.reason === null) return null;
  } catch { /* Missing or malformed additive DATA never enables the picker. */ }
  // Do not echo arbitrary native reason text or borrow projectSelection's gate.
  return 'Project-path browsing is unavailable in this native profile. Text entry remains available.';
}

const errors: Record<string, string> = {
  project_path_invalid: 'This project-path request was refused. No draft or baseline was changed.',
  project_path_unavailable: 'Project-path browsing is unavailable in this native profile. No path was selected.',
  project_path_busy: 'Finish the original conflicting native operation before browsing. No path was selected.',
  project_path_stale: 'The registered project changed. The selection was not applied to the draft.',
  project_path_unsafe: 'Choose a supported existing item inside the current project. Outside paths, links and unsupported item kinds are refused.',
  project_path_changed: 'The selected item or project changed during selection. No draft or baseline was changed.',
  project_path_limit: 'The selection exceeded the supported path or operation limits. No draft or baseline was changed.',
  project_path_deadline: 'The original selection ended at its deadline. No draft or baseline was changed.',
  project_path_cleanup_unknown: 'Original project-path cleanup is unconfirmed. Conflicting native operations remain blocked; do not retry the selection.',
  project_path_unknown: 'The original project-path outcome is unverified. Conflicting native operations remain blocked; no selection or cleanup is assumed.',
};
export function projectPathError(error: unknown): ApiError {
  let code = 'project_path_unknown';
  try {
    const descriptor = isObject(error) ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const value: unknown = descriptor && Object.hasOwn(descriptor, 'value') ? descriptor.value : null;
    if (typeof value === 'string' && Object.hasOwn(errors, value)) code = value;
  } catch { /* No native exception, path, getter or rejection text is displayed. */ }
  return { code, message: errors[code]!, retryable: false };
}

export function projectPathDraftReason(draft: JsonObject | null, field: unknown): string | null {
  if (!isProjectPathField(field)) return 'Browsing is available only for the four project-path fields.';
  if (!isObject(draft)) return 'Load or start an editable draft before browsing.';
  if (blockingAncestor(draft, field)) return 'The parent has a non-object value. It is preserved; browsing cannot replace it.';
  const value = getValue(draft, field);
  return value === undefined || typeof value === 'string' ? null : 'This field has a non-text value. It is preserved; browsing cannot replace it.';
}

// The binding object itself is the one request identity; it never crosses IPC.
export interface ProjectPathBinding extends ProjectPathRequest {
  readonly revision: number;
  readonly baselineGeneration: number;
  readonly serviceGeneration: object;
}
export interface ProjectPathState {
  pending: ProjectPathBinding | null;
  eligible: ProjectPathBinding | null;
  unverified: ProjectPathBinding | null;
  message: string | null;
}
export const initialProjectPathState: ProjectPathState = { pending: null, eligible: null, unverified: null, message: null };
export function projectPathOwnerReason(state: ProjectPathState): string | null {
  return state.unverified ? 'The original project-path outcome or cleanup is unverified. Conflicting native operations remain blocked.'
    : state.pending ? 'Finish the original project-path selection. Changing drafts or projects does not cancel it.' : null;
}
function selected(workspace: WorkspaceState) {
  const id = workspace.selectedId;
  const session = id && Object.hasOwn(workspace.projects, id) ? workspace.projects[id] : null;
  return session && session.project.id === id ? session : null;
}
export function beginProjectPath(state: ProjectPathState, workspace: WorkspaceState, field: unknown, serviceGeneration: object): ProjectPathState {
  const session = selected(workspace);
  if (projectPathOwnerReason(state) || !session || !projectId(session.project.id) || !isProjectPathField(field) || projectPathDraftReason(session.draft, field) ||
      ![session.revision, session.baselineGeneration].every((value) => Number.isSafeInteger(value) && value >= 0 && value <= 0xffff_ffff)) return state;
  const binding: ProjectPathBinding = { projectId: session.project.id, field, revision: session.revision, baselineGeneration: session.baselineGeneration, serviceGeneration };
  return { pending: binding, eligible: binding, unverified: null, message: null };
}
export function retireProjectPath(state: ProjectPathState): ProjectPathState {
  if (!state.eligible && (!state.message || state.unverified)) return state;
  // Display retirement never releases the original pending/unverified binding.
  return { ...state, eligible: null, message: state.unverified ? state.message : null };
}
export function finishProjectPath(state: ProjectPathState, binding: ProjectPathBinding, workspace: WorkspaceState, serviceGeneration: object,
  outcome: { reply: unknown } | { error: unknown }): { state: ProjectPathState; edit: { field: ProjectPathField; value: string } | null } {
  if (state.pending !== binding) return { state, edit: null };
  const reply = 'reply' in outcome ? parseProjectPathSelection(outcome.reply, binding) : undefined;
  const error = 'error' in outcome ? projectPathError(outcome.error) : reply === undefined ? projectPathError(null) : null;
  // An unrecognized result is not Cancel or evidence of native settlement.
  const unverified = error && ['project_path_cleanup_unknown', 'project_path_unknown'].includes(error.code) ? binding : null;
  const next: ProjectPathState = { pending: null, eligible: null, unverified, message: error?.message ?? null };
  if (error) return { state: next, edit: null };
  if (reply === null) return { state: { ...next, message: 'Selection cancelled. No draft or baseline was changed.' }, edit: null };
  const session = selected(workspace);
  if (!reply || state.eligible !== binding || binding.serviceGeneration !== serviceGeneration || !session || session.project.id !== binding.projectId ||
      session.revision !== binding.revision || session.baselineGeneration !== binding.baselineGeneration || projectPathDraftReason(session.draft, binding.field))
    return { state: { ...next, message: 'The selection arrived after its draft or context changed and was not applied.' }, edit: null };
  // Caller publishes the consumed binding before the ordinary one-field edit.
  return { state: next, edit: { field: binding.field, value: reply.relativePath } };
}

export interface ProjectPathControls {
  reason: string | null;
  pendingField: ProjectPathField | null;
  onBrowse: (field: ProjectPathField) => void;
}
const browseHelp: Record<ProjectPathField, string> = {
  'version.source': 'Browse existing… selects an existing ordinary single-link version file; no extension is invented.',
  'ios.project': 'Browse existing… selects an existing directory ending exactly .xcodeproj. Selecting it does not validate Xcode.',
  'ios.workspace': 'Browse existing… selects an existing directory ending exactly .xcworkspace. Selecting it does not validate Xcode.',
  'metadata.root': 'Browse existing… selects an existing ordinary metadata directory, not locale text or a credential folder.',
};
export function projectPathHelp(field: FieldHelp): HelpContent {
  if (!isProjectPathField(field.path)) return field;
  // Append desktop guidance; keep the bundled core's policy, requiredness and
  // project/workspace exclusion text verbatim. Never mutate the catalogue DATA.
  return { ...field,
    where: `${field.where} ${browseHelp[field.path]} Choose inside the current project boundary shown above the fields. Browsing is optional; keep typing paths for items not yet present.`,
    format: `${field.format} A selection supplies only a project-relative slash-separated path (up to 512 UTF-8 bytes and 12 components); it creates no file or directory and never clears another field.`,
    failure: `${field.failure} Cancel or a refused outside-project selection leaves all drafts and baselines unchanged. Selection checks path metadata only: it does not read file contents, save the draft, or validate the resource. Saving and core policy review remain separate.`,
  };
}
