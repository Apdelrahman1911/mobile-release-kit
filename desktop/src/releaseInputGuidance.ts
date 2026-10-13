// Current-draft requirements are passive core data, never credential presence,
// input custody, save authority or readiness. No private/native action lives here.
import { methodReason } from './certainty.ts';
import { parseCredentialGuide } from './credentialGuide.ts';
import { isDirty } from './drafts.ts';
import { assetIntentPending, assetSessionReason } from './assetSessionController.ts';
import { ASSET_KINDS } from './assetSessionProtocol.ts';
import type { AssetDisplayState, AssetKind, AssetScope } from './assetSessionTypes.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import { ENVIRONMENTS, assurance, boundedJson, keys, oneOf, record, requirement, requirementName, text } from './requirementProtocol.ts';
import type { AppInfo, BridgeMode, CredentialGuide, CredentialHelp, CredentialKindId, DesktopApi, HelpContent, JsonObject, RequirementDescriptor } from './types.ts';

export const RELEASE_INPUT_STAGES = [
  { id: 'candidate', label: 'Candidate / internal' },
  { id: 'external-testing', label: 'External testing' },
  { id: 'production', label: 'Production preparation' },
] as const;
export type ReleaseInputStage = typeof RELEASE_INPUT_STAGES[number]['id'];
export interface ReleaseInputResult { state: 'invalid' | 'format-valid'; requirements: RequirementDescriptor[] }
export interface ReleaseInputHelp { guide: CredentialGuide | null; credentials: CredentialHelp[] }
const helpFields = ['requiredWhen', 'what', 'why', 'where', 'format', 'failure'] as const;
function displayText(value: unknown, limit = 4096): value is string {
  return text(value, limit) && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value);
}
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
const emptyHelp: ReleaseInputHelp = freeze({ guide: null, credentials: [] });

export function parseReleaseInputResult(raw: unknown): ReleaseInputResult | null {
  try {
    if (!boundedJson(raw, 262144, 8000, 16)) return null;
    const value: unknown = structuredClone(raw);
    if (!boundedJson(value, 262144, 8000, 16) || !keys(value, ['valid', 'state', 'issues', 'requirements', 'assurance']) ||
        !assurance(value.assurance) || !Array.isArray(value.issues) || !Array.isArray(value.requirements)) return null;
    if (value.valid === false && value.state === 'invalid') {
      const issue: unknown = value.issues[0];
      // config.validate legitimately returns a reflective ConfigurationError,
      // unlike GitHub's fixed issue literal. Admit its shape, never its display.
      return value.requirements.length === 0 && value.issues.length === 1 &&
        keys(issue, ['code', 'status', 'message', 'remediation']) && issue.code === 'config.invalid' && issue.status === 'INVALID' &&
        text(issue.message, 8192) && text(issue.remediation, 8192) ? freeze({ state: 'invalid', requirements: [] }) : null;
    }
    if (value.valid !== true || value.state !== 'format-valid' || value.issues.length !== 0 || value.requirements.length > 128) return null;
    const identities = new Set<string>();
    for (const row of value.requirements) {
      if (!requirement(row) || !displayText(row.reason, 1024)) return null;
      const identity = JSON.stringify([row.name, row.stage, row.platform]);
      if (identities.has(identity)) return null;
      identities.add(identity);
    }
    return freeze({ state: 'format-valid', requirements: value.requirements as RequirementDescriptor[] });
  } catch { return null; }
}

// Inspect only these data properties, not the rest of a potentially large
// catalogue. Bound before copying and validate the detached objects we retain.
export function parseReleaseInputHelp(raw: unknown): ReleaseInputHelp {
  try {
    if (!record(raw)) return emptyHelp;
    const data = (key: string): unknown => {
      const descriptor = Object.getOwnPropertyDescriptor(raw, key);
      return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value') ? descriptor.value : undefined;
    };
    const rawGuide = data('credentialGuide'), rawCredentials = data('credentials');
    const guide = boundedJson(rawGuide, 262144, 8000, 16) ? parseCredentialGuide(structuredClone(rawGuide)) : null;
    let credentials: CredentialHelp[] = [];
    if (boundedJson(rawCredentials, 262144, 8000, 16)) {
      const copy: unknown = structuredClone(rawCredentials);
      const names = new Set<string>();
      if (boundedJson(copy, 262144, 8000, 16) && Array.isArray(copy) && copy.length <= 128 && copy.every((row: unknown) => {
        if (!keys(row, ['name', 'kind', 'platform', 'stages', 'alternatives', 'requiredness', ...helpFields]) ||
            !requirementName(row.name) || names.has(row.name) || !oneOf(row.kind, ['secret', 'variable', 'file', 'manual']) ||
            !oneOf(row.platform, ['android', 'ios', 'project']) || !Array.isArray(row.stages) || row.stages.length < 1 || row.stages.length > 3 ||
            !row.stages.every((stage: unknown) => ENVIRONMENTS.some((entry) => stage === entry.stage)) || new Set(row.stages).size !== row.stages.length ||
            !Array.isArray(row.alternatives) || row.alternatives.length > 2 || !row.alternatives.every(requirementName) ||
            !oneOf(row.requiredness, ['required', 'optional', 'conditional']) || !helpFields.every((key) => displayText(row[key]))) return false;
        names.add(row.name); return true;
      })) credentials = copy as CredentialHelp[];
    }
    return freeze({ guide, credentials });
  } catch { return emptyHelp; }
}

export interface ReleaseInputRow {
  requirement: RequirementDescriptor;
  help: HelpContent | null;
  guideId: CredentialKindId | null;
  file: { maxBytes: number; suffixes: string[] } | null;
}
export function releaseInputRows(result: ReleaseInputResult | null, stage: ReleaseInputStage, help: ReleaseInputHelp): ReleaseInputRow[] {
  if (result?.state !== 'format-valid') return [];
  return result.requirements.filter((row) => row.stage === stage).map((row) => {
    const names = new Set([row.name, ...row.alternatives]);
    const matches = help.guide?.kinds.filter((kind) => kind.platform === row.platform).flatMap((kind) => kind.fields
      .filter((field) => names.has(field.requirement) || field.alternatives.some((name) => names.has(name)))
      .map((field) => ({ kind, field }))) ?? [];
    const match = matches.length === 1 ? matches[0] : undefined;
    const reference = help.credentials.find((entry) => entry.name === row.name && entry.platform === row.platform && entry.stages.includes(row.stage));
    const source = match?.field ?? reference;
    const content: HelpContent | null = source ? { label: row.name, requiredness: source.requiredness,
      requiredWhen: source.requiredWhen, what: source.what, why: source.why, where: source.where, format: source.format, failure: source.failure } : null;
    return { requirement: row, help: content, guideId: match?.kind.id ?? null,
      file: match?.field.input === 'file' && match.field.maxBytes !== null ? { maxBytes: match.field.maxBytes, suffixes: match.field.suffixes } : null };
  });
}
export function releaseInputGroups(state: ReleaseInputGuidanceState): { platform: string; label: string; rows: ReleaseInputRow[] }[] {
  const rows = state.pending ? [] : releaseInputRows(state.result, state.stage, state.help);
  return [{ platform: 'android', label: 'Android' }, { platform: 'ios', label: 'iOS' }, { platform: 'project', label: 'Project' }]
    .map((group) => ({ ...group, rows: rows.filter((row) => row.requirement.platform === group.platform) })).filter((group) => group.rows.length > 0);
}

interface ProjectBinding {
  projectId: string; draftRevision: number; baselineGeneration: number; observationGeneration: number;
  hasDraft: boolean; dirtyDraft: boolean; snapshotPending: boolean; snapshotFailed: boolean; sourceChanged: boolean;
  validationPending: boolean; reviewPending: boolean; saveRecoveryRequired: boolean;
}
export interface ReleaseInputGuidanceState {
  mode: BridgeMode; reason: string | null; loading: boolean; selectionPending: boolean; project: ProjectBinding | null;
  stage: ReleaseInputStage; pending: boolean; result: ReleaseInputResult | null; help: ReleaseInputHelp; notice: string | null;
}
// Navigation-only data. The exact frozen source/row, not matching strings or
// cached counters, binds a hint to the requirements the user actually opened.
export interface ReleaseInputPreparationTarget {
  readonly source: ReleaseInputGuidanceState;
  readonly requirement: RequirementDescriptor;
  readonly guideId: CredentialKindId;
  readonly scope: Readonly<AssetScope>;
}
export interface ReleaseInputPreparationLocal {
  kindId: AssetKind; replacementId: string | null; confirmLock: boolean; writeOnlyFormMounted: boolean;
}
export function sessionPreparationKind(kind: CredentialKindId): AssetKind | null {
  return ASSET_KINDS.find((entry) => entry === kind) ?? null;
}
export function preparationScopeChanged(target: ReleaseInputPreparationTarget, scope: AssetScope): boolean {
  return target.scope.platform !== scope.platform || target.scope.stage !== scope.stage || target.scope.purpose !== scope.purpose;
}
// Pure UI protection only; existing native/core admission still owns context,
// collection and assignment. No action or private field value enters this helper.
export function preparationSessionReason(target: ReleaseInputPreparationTarget, state: AssetDisplayState,
  local: ReleaseInputPreparationLocal, otherReason: string | null = null): string | null {
  const kind = sessionPreparationKind(target.guideId);
  if (!kind) return 'This input has a reference guide only. Its session importer is not available.';
  if (otherReason !== null) return otherReason || 'Other original work must settle before continuing.';
  const reason = assetSessionReason(state);
  if (reason !== null) return reason;
  if (state.observing) return 'Wait for the original session status check to settle.';
  if (state.originPending || assetIntentPending(state)) return 'The original requested action is still pending or unconfirmed. Keep its existing target and status.';
  const operation = state.status?.operation;
  if (operation && (operation.phase !== 'idle' || operation.settlement !== 'known')) return 'Finish the original operation before changing preparation context.';
  if (operation?.selectionToken || operation?.preview || state.reviewReady || state.previewDeadline !== null)
    return 'Keep the original selection or review. Guidance cannot replace its target or extend its deadline.';
  if (state.status?.records.some((record) => record.availability === 'mutation-pending')) return 'A session record change is still pending. Keep its original status.';
  if (local.replacementId !== null) return 'A replacement target is already selected. Use its existing controls before changing preparation context.';
  if (local.confirmLock) return 'Finish the open session-discard confirmation before continuing.';
  if (local.writeOnlyFormMounted && (kind !== local.kindId || preparationScopeChanged(target, state.scope)))
    return 'A private-input form is already open. Continue with it, or use its existing controls before changing preparation context. Its values have not been changed.';
  return null;
}
type GuidanceApi = Pick<DesktopApi, 'mode' | 'validate'>;
interface RequestBinding {
  service: object; selection: object; context: object; help: object; api: GuidanceApi;
  project: ProjectBinding; sourceDraft: JsonObject;
}
const unavailable = 'Current-draft requirements need an available compatible native core. No inputs have been checked.';
const previewReason = 'Browser preview cannot validate this draft or fabricate current-draft core requirements.';
const retired = 'The earlier requirements view was retired. Show current draft requirements again when this context is available.';
const invalidDraft = 'This draft does not satisfy the core format/policy rules. Correct it in Project settings, then request its requirements again. No inputs were checked.';
const failed = 'Current draft requirements could not be read safely. No earlier rows were reused. Review the service or draft and retry explicitly.';
function projectBinding(session: ProjectSession | null): ProjectBinding | null {
  return session ? { projectId: session.project.id, draftRevision: session.revision, baselineGeneration: session.baselineGeneration,
    observationGeneration: session.observationGeneration, hasDraft: session.draft !== null, dirtyDraft: isDirty(session),
    snapshotPending: session.snapshotRequest !== null, snapshotFailed: session.snapshotError !== null, sourceChanged: session.sourceChanged,
    validationPending: session.validationRequest !== null, reviewPending: session.reviewRequest !== null, saveRecoveryRequired: session.saveRecoveryRequired } : null;
}
function sameProject(a: ProjectBinding | null, b: ProjectBinding | null): boolean {
  return a === null || b === null ? a === b : (Object.keys(a) as (keyof ProjectBinding)[]).every((key) => a[key] === b[key]);
}

export class ReleaseInputGuidanceController {
  private state: ReleaseInputGuidanceState = freeze<ReleaseInputGuidanceState>({ mode: 'unavailable', reason: unavailable, loading: false, selectionPending: false,
    project: null, stage: 'candidate', pending: false, result: null, help: emptyHelp, notice: null });
  private readonly selectedProject: () => ProjectSession | null;
  private readonly configurationBusy: (projectId: string) => boolean;
  private readonly retireHelp: () => void;
  private readonly otherOperationReason: () => string | null;
  private api: GuidanceApi | null = null;
  private draft: JsonObject | null = null;
  // Nonreusable identities have no wrapping generation counter. Only the private
  // in-flight binding references the source draft; published state never does.
  private service: object = {}; private selection: object = {}; private context: object = {}; private help: object = {};
  private attempt: RequestBinding | null = null;
  private passivePending = 0;
  private disposed = false;
  private listeners = new Set<() => void>();
  constructor(selectedProject: () => ProjectSession | null, configurationBusy: (projectId: string) => boolean = () => false, retireHelp: () => void = () => {}, otherOperationReason: () => string | null = () => null) {
    this.selectedProject = selectedProject; this.configurationBusy = configurationBusy; this.retireHelp = retireHelp; this.otherOperationReason = otherOperationReason;
  }
  getSnapshot = (): ReleaseInputGuidanceState => this.state;
  passiveBusyReason = (): string | null => this.passivePending > 0 ? 'An original draft-requirements query is still pending.' : null;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<ReleaseInputGuidanceState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    for (const listener of this.listeners) listener();
  }
  private retire(patch: Partial<ReleaseInputGuidanceState> = {}): void {
    if (this.disposed) return;
    this.attempt = null;
    this.update({ notice: retired, ...patch, pending: false, result: null });
    this.retireHelp();
    // UI retirement only: the passive supervisor still owns any original call.
  }
  beginConnection(): void {
    this.service = {}; this.help = {}; this.api = null;
    this.retire({ mode: 'unavailable', reason: 'Core capabilities and guidance are loading.', loading: true, help: emptyHelp });
  }
  setConnection(api: GuidanceApi, info: AppInfo): void {
    if (this.disposed) return;
    this.service = {}; this.help = {}; this.api = api;
    this.retire({ mode: api.mode, reason: api.mode === 'preview' ? previewReason :
      api.mode === 'native' && methodReason(info, 'config.validate', api.mode) === null ? null : unavailable, help: emptyHelp });
  }
  connectionUnavailable(): void {
    this.service = {}; this.help = {}; this.api = null;
    this.retire({ mode: 'unavailable', reason: unavailable, loading: false, help: emptyHelp });
  }
  setCatalog(raw: unknown): void {
    const service = this.service, generation = {};
    this.help = generation;
    this.retire({ help: emptyHelp });
    const admitted = parseReleaseInputHelp(raw);
    if (!this.disposed && this.service === service && this.help === generation) this.update({ help: admitted, loading: false });
  }
  setStage(stage: string): void {
    if (RELEASE_INPUT_STAGES.some((entry) => entry.id === stage) && stage !== this.state.stage) this.update({ stage: stage as ReleaseInputStage });
  }
  setSelectionPending(pending: boolean): void {
    if (pending) { this.selection = {}; this.retire({ selectionPending: true }); }
    else if (this.state.selectionPending) this.update({ selectionPending: false });
  }
  saveIntent(): void { this.context = {}; this.retire(); }
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (action.type === 'select' || action.type === 'switch') { this.selection = {}; this.context = {}; this.retire(); return; }
    if (action.projectId !== this.state.project?.projectId) return;
    if (['snapshot-start', 'snapshot-done', 'snapshot-failed', 'validate-start', 'validate-done', 'validate-failed',
      'new-draft', 'edit', 'reset', 'remove-forbidden', 'undo-removal', 'forget-removal', 'adopt-suggestion',
      'config-save-final', 'config-save-recovery'].includes(action.type)) { this.context = {}; this.retire(); }
  }
  syncProject(): void {
    if (this.disposed) return;
    const session = this.selectedProject(), next = projectBinding(session), draft = session?.draft ?? null;
    if (sameProject(this.state.project, next) && this.draft === draft) return;
    if (this.state.project?.projectId !== next?.projectId) this.selection = {};
    this.context = {}; this.draft = draft;
    this.retire({ project: next });
  }
  private blocked(includePending: boolean): string | null {
    const other = this.otherOperationReason(); if (other) return other;
    if (this.disposed) return unavailable;
    if (this.state.loading) return 'Wait for the current core connection and catalogue attempt to settle.';
    if (this.state.mode === 'preview') return previewReason;
    if (this.state.reason || !this.api || this.state.mode !== 'native') return this.state.reason ?? unavailable;
    if (!this.state.project) return 'Choose a project before requesting its draft requirements.';
    if (!this.state.project.hasDraft) return 'Create or load an in-memory draft in Project settings first.';
    if (this.state.selectionPending) return 'Finish choosing a project; cancelled selection does not restore earlier requirements.';
    if (this.state.project.saveRecoveryRequired) return 'This project needs separate configuration recovery attention. Requirements guidance cannot resolve it.';
    if (this.configurationBusy(this.state.project.projectId)) return 'A configuration save is active or unverified. Keep its original attention and settle it first.';
    if (this.state.project.snapshotPending || this.state.project.validationPending || this.state.project.reviewPending) return 'Wait for the current snapshot, validation or review attempt to settle, then request requirements explicitly.';
    return includePending && this.state.pending ? 'Reading requirements for this in-memory draft…' : null;
  }
  startReason = (): string | null => this.blocked(true);
  private preparationRow(source: ReleaseInputGuidanceState, input: RequirementDescriptor): ReleaseInputRow | null {
    if (this.disposed || this.state !== source || this.blocked(true) !== null) return null;
    const selected = this.selectedProject();
    if (this.state !== source || source.pending || source.result?.state !== 'format-valid' ||
        !source.project || !this.draft || selected?.draft !== this.draft || !sameProject(source.project, projectBinding(selected)) ||
        !source.result.requirements.includes(input)) return null;
    return releaseInputRows(source.result, source.stage, source.help).find((row) => row.requirement === input && row.guideId !== null) ?? null;
  }
  preparationTarget(source: ReleaseInputGuidanceState, input: RequirementDescriptor): ReleaseInputPreparationTarget | null {
    const row = this.preparationRow(source, input);
    const kind = source.help.guide?.kinds.find((entry) => entry.id === row?.guideId);
    if (!row?.guideId || !kind) return null;
    return Object.freeze({ source, requirement: input, guideId: row.guideId,
      scope: Object.freeze({ platform: kind.platform, stage: source.stage, purpose: 'full' as const }) });
  }
  preparationCurrent(target: ReleaseInputPreparationTarget, activeTarget: ReleaseInputPreparationTarget | null): boolean {
    if (activeTarget !== target) return false;
    const row = this.preparationRow(target.source, target.requirement);
    return !!row && row.guideId === target.guideId && target.scope.platform === row.requirement.platform &&
      target.scope.stage === target.source.stage && target.scope.purpose === 'full';
  }
  private current(binding: RequestBinding): boolean {
    return !this.disposed && this.attempt === binding && this.api === binding.api && this.service === binding.service &&
      this.selection === binding.selection && this.context === binding.context && this.help === binding.help &&
      this.draft === binding.sourceDraft && sameProject(this.state.project, binding.project);
  }
  private admitReply(binding: RequestBinding): boolean {
    this.syncProject();
    if (!this.current(binding)) return false;
    if (this.blocked(false) !== null) { this.retire(); return false; }
    return this.current(binding);
  }
  async refresh(): Promise<void> {
    this.syncProject();
    // Retire even a refused attempt. Never fall back to cached workspace validation.
    this.retire({ notice: null });
    const reason = this.blocked(false);
    if (reason !== null || !this.api || !this.draft || !this.state.project) { this.update({ notice: reason }); return; }
    const binding: RequestBinding = Object.freeze({ service: this.service, selection: this.selection, context: this.context, help: this.help,
      api: this.api, project: this.state.project, sourceDraft: this.draft });
    this.attempt = binding;
    this.update({ pending: true });
    if (!this.admitReply(binding)) return;
    this.passivePending += 1;
    try {
      // Transport bounds only; configuration/service/requiredness policy stays core-owned.
      if (!boundedJson(binding.sourceDraft, 524288, 8000, 28) || !record(binding.sourceDraft)) throw new Error();
      const draft = structuredClone(binding.sourceDraft);
      if (!this.admitReply(binding)) return;
      const raw: unknown = await binding.api.validate(draft);
      if (!this.admitReply(binding)) return;
      const result = parseReleaseInputResult(raw);
      if (!this.admitReply(binding)) return;
      if (!result) throw new Error();
      this.attempt = null;
      this.update({ pending: false, result, notice: result.state === 'invalid' ? invalidDraft : null });
    } catch {
      if (!this.admitReply(binding)) return;
      this.attempt = null;
      this.update({ pending: false, result: null, notice: failed });
    } finally { this.passivePending -= 1; this.update({}); }
    // Finally releases only this original Promise's accounting, never a newer display binding.
  }
  dispose(): void { this.connectionUnavailable(); this.disposed = true; this.listeners.clear(); this.draft = null; }
}
