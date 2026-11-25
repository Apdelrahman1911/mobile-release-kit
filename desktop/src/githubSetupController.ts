// In-memory display orchestration only. Renderer generations are not file/Git
// revisions, and no proposal can be submitted as Apply or dispatch authority.
import { methodReason } from './certainty.ts';
import type { ProjectSession } from './drafts.ts';
import { GITHUB_WORKFLOWS, githubSetupError, githubSetupRequestFits, githubSetupResultMatches, parseGitHubSetupHelp, parseGitHubSetupResult } from './githubSetupProtocol.ts';
import type { ApiError, AppInfo, BridgeMode, DesktopApi, GitHubSetupHelp, GitHubSetupRequest, GitHubSetupResult, GitHubSuppliedSnapshot, GitHubWorkflowAssertion, GitHubWorkflowId, JsonObject } from './types.ts';

export interface GitHubAssertionInput {
  id: GitHubWorkflowId;
  state: 'not-supplied' | 'absent' | 'present';
  byteLength: string;
  sha256: string;
}
export interface GitHubSetupInputs {
  toolingRepository: string;
  toolingSha: string;
  snapshotEnabled: boolean;
  assertions: GitHubAssertionInput[];
}
interface ProjectBinding {
  projectId: string;
  draftRevision: number;
  baselineGeneration: number;
  hasDraft: boolean;
}
export interface GitHubDisplayBinding extends ProjectBinding {
  requestId: number;
  serviceGeneration: number;
  selectionGeneration: number;
  coordinateGeneration: number;
  comparisonGeneration: number;
}
export interface GitHubSetupState {
  mode: BridgeMode;
  reason: string | null;
  serviceGeneration: number;
  selectionGeneration: number;
  coordinateGeneration: number;
  comparisonGeneration: number;
  project: ProjectBinding | null;
  inputs: GitHubSetupInputs;
  help: GitHubSetupHelp | null;
  helpState: 'unavailable' | 'current' | 'previous';
  pending: GitHubDisplayBinding | null;
  result: GitHubSetupResult | null;
  resultBinding: GitHubDisplayBinding | null;
  error: ApiError | null;
  invalidated: boolean;
}

function emptyAssertions(): GitHubAssertionInput[] {
  return GITHUB_WORKFLOWS.map(({ id }) => ({ id, state: 'not-supplied', byteLength: '', sha256: '' }));
}

function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

// UI-only conversion of explicitly entered digest/size assertions to the fixed
// transport union. Undefined means malformed, never an implicit null/absence.
export function githubSnapshotFromInputs(inputs: GitHubSetupInputs): GitHubSuppliedSnapshot | null | undefined {
  if (!inputs.snapshotEnabled) return null;
  const workflows: GitHubWorkflowAssertion[] = [];
  for (const row of inputs.assertions) {
    if (row.state === 'not-supplied') continue;
    if (row.state === 'absent') workflows.push({ id: row.id, state: 'absent' });
    else if (row.state === 'present' && row.byteLength.length >= 1 && row.byteLength.length <= 7 && !/[^0-9]/.test(row.byteLength) && row.sha256.length === 64 && /^[0-9a-f]{64}$/.test(row.sha256)) {
      const byteLength = Number(row.byteLength);
      if (!Number.isInteger(byteLength) || byteLength > 1048576) return undefined;
      workflows.push({ id: row.id, state: 'present', byteLength, sha256: row.sha256 });
    } else return undefined;
  }
  return { workflows };
}

export function githubSetupStartReason(state: GitHubSetupState): string | null {
  if (state.reason !== null) return state.reason;
  if (state.help === null) return 'Core setup guidance is unavailable. Restore the packaged service and reload guidance before requesting a preview.';
  if (!state.project?.hasDraft) return 'Choose a project and prepare an in-memory configuration draft in Project settings. Nothing will be saved by this preview.';
  if (state.pending !== null) return 'The core is preparing a read-only proposal for these inputs.';
  if (!state.inputs.toolingRepository || !state.inputs.toolingSha) return 'Enter the toolkit repository and full toolkit commit. There is no account or commit default.';
  // This checks finite transport shape, not configuration/ref validity. Bad pin
  // spellings within the shape budget still go to the core for safe rejection.
  const suppliedSnapshot = githubSnapshotFromInputs(state.inputs);
  if (suppliedSnapshot === undefined) return 'A supplied file assertion needs a whole byte length from 0 to 1048576 and a 64-character lowercase SHA256. No file is read.';
  if (!githubSetupRequestFits({ draft: {}, toolingRepository: state.inputs.toolingRepository, toolingSha: state.inputs.toolingSha, suppliedSnapshot })) {
    return 'Toolkit inputs exceed the supported text size or Unicode shape. Review the core guidance; no request has been sent.';
  }
  return null;
}

export class GitHubSetupController {
  private state: GitHubSetupState = freeze<GitHubSetupState>({
    mode: 'unavailable', reason: 'Desktop capabilities and core setup guidance have not been loaded.',
    serviceGeneration: 0, selectionGeneration: 0, coordinateGeneration: 0, comparisonGeneration: 0,
    project: null, inputs: { toolingRepository: '', toolingSha: '', snapshotEnabled: false, assertions: emptyAssertions() },
    help: null, helpState: 'unavailable', pending: null, result: null, resultBinding: null, error: null, invalidated: false,
  });
  private api: DesktopApi | null = null;
  private draft: JsonObject | null = null;
  private nextRequest = 0;
  private passivePending = 0;
  private disposed = false;
  private listeners = new Set<() => void>();
  private readonly selectedProject: () => ProjectSession | null;
  private readonly onContextChange: (() => void) | undefined;
  private readonly otherOperationReason: () => string | null;

  constructor(selectedProject: () => ProjectSession | null, onContextChange?: () => void, otherOperationReason: () => string | null = () => null) {
    this.selectedProject = selectedProject;
    this.onContextChange = onContextChange; this.otherOperationReason = otherOperationReason;
  }

  startReason = (): string | null => this.otherOperationReason() ?? githubSetupStartReason(this.state);
  getSnapshot = (): GitHubSetupState => this.state;
  passiveBusyReason = (): string | null => this.passivePending > 0 ? 'An original workflow-proposal query is still pending.' : null;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };

  private update(patch: Partial<GitHubSetupState>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch });
    // This notification only revokes a separate native review's stale input
    // binding. A passive result or supplied assertion never grants authority.
    this.onContextChange?.();
    for (const listener of this.listeners) listener();
  }

  private invalidate(patch: Partial<GitHubSetupState>): void {
    this.update({
      ...patch, pending: null, result: null, resultBinding: null, error: null,
      invalidated: this.state.invalidated || this.state.pending !== null || this.state.result !== null,
    });
  }

  beginConnection(): void {
    this.api = null;
    this.invalidate({
      mode: 'unavailable', reason: 'Desktop capabilities and core setup guidance are loading.',
      serviceGeneration: this.state.serviceGeneration + 1,
      helpState: this.state.help ? 'previous' : 'unavailable',
    });
  }

  setConnection(api: DesktopApi, info: AppInfo): void {
    if (this.disposed) return;
    this.api = api;
    this.invalidate({
      mode: api.mode, reason: methodReason(info, 'github.setup.propose', api.mode),
      serviceGeneration: this.state.serviceGeneration + 1,
      helpState: this.state.help ? 'previous' : 'unavailable',
    });
  }

  connectionUnavailable(): void {
    this.api = null;
    this.invalidate({
      mode: 'unavailable', reason: 'The packaged proposal service is unavailable. Restore it and reload capabilities and core guidance.',
      serviceGeneration: this.state.serviceGeneration + 1,
      helpState: this.state.help ? 'previous' : 'unavailable',
    });
  }

  admitHelp(value: unknown): boolean {
    if (this.disposed) return false;
    const help = parseGitHubSetupHelp(value);
    if (!help) { this.helpUnavailable(); return false; }
    this.update({ help: freeze(structuredClone(help)), helpState: 'current' });
    return true;
  }

  helpUnavailable(): void { this.update({ helpState: this.state.help ? 'previous' : 'unavailable' }); }

  // App calls this synchronously with workspace dispatch, not in a render
  // effect. A switch/edit away and back cannot resurrect a late response.
  syncProject(): void {
    if (this.disposed) return;
    const session = this.selectedProject();
    const next: ProjectBinding | null = session ? {
      projectId: session.project.id, draftRevision: session.revision,
      baselineGeneration: session.baselineGeneration, hasDraft: session.draft !== null,
    } : null;
    const old = this.state.project;
    const draft = session?.draft ?? null;
    if (old?.projectId === next?.projectId && old?.draftRevision === next?.draftRevision &&
        old?.baselineGeneration === next?.baselineGeneration && old?.hasDraft === next?.hasDraft && this.draft === draft) return;
    const switched = old?.projectId !== next?.projectId;
    this.draft = draft;
    this.invalidate({
      project: next, selectionGeneration: this.state.selectionGeneration + 1,
      // These are application-file assertions, not toolkit preferences. Never
      // silently carry a prior project's supplied comparison into another one.
      ...(switched ? {
        comparisonGeneration: this.state.comparisonGeneration + 1,
        inputs: { ...this.state.inputs, snapshotEnabled: false, assertions: emptyAssertions() },
      } : {}),
    });
  }

  setCoordinate(field: 'toolingRepository' | 'toolingSha', value: string): void {
    if (this.disposed || this.state.inputs[field] === value) return;
    this.invalidate({ inputs: { ...this.state.inputs, [field]: value }, coordinateGeneration: this.state.coordinateGeneration + 1 });
  }

  setSnapshotEnabled(enabled: boolean): void {
    if (this.disposed || this.state.inputs.snapshotEnabled === enabled) return;
    this.invalidate({
      inputs: { ...this.state.inputs, snapshotEnabled: enabled, assertions: enabled ? this.state.inputs.assertions : emptyAssertions() },
      comparisonGeneration: this.state.comparisonGeneration + 1,
    });
  }

  setAssertion(id: GitHubWorkflowId, patch: Partial<Pick<GitHubAssertionInput, 'state' | 'byteLength' | 'sha256'>>): void {
    if (this.disposed) return;
    const old = this.state.inputs.assertions.find((entry) => entry.id === id);
    if (!old) return;
    const next = { ...old, ...patch };
    if (next.state !== 'present') { next.byteLength = ''; next.sha256 = ''; }
    if (old.state === next.state && old.byteLength === next.byteLength && old.sha256 === next.sha256) return;
    this.invalidate({
      inputs: { ...this.state.inputs, assertions: this.state.inputs.assertions.map((entry) => entry.id === id ? next : entry) },
      comparisonGeneration: this.state.comparisonGeneration + 1,
    });
  }

  private current(binding: GitHubDisplayBinding): boolean {
    const project = this.state.project;
    return !this.disposed && this.state.pending === binding &&
      binding.serviceGeneration === this.state.serviceGeneration && binding.selectionGeneration === this.state.selectionGeneration &&
      binding.coordinateGeneration === this.state.coordinateGeneration && binding.comparisonGeneration === this.state.comparisonGeneration &&
      project !== null && binding.projectId === project.projectId && binding.draftRevision === project.draftRevision &&
      binding.baselineGeneration === project.baselineGeneration;
  }

  async propose(): Promise<void> {
    this.syncProject();
    if (this.disposed || !this.api || this.api.mode !== 'native' || !this.draft || !this.state.project || this.startReason() !== null) return;
    const suppliedSnapshot = githubSnapshotFromInputs(this.state.inputs);
    if (suppliedSnapshot === undefined) return;
    const input = {
      draft: this.draft, toolingRepository: this.state.inputs.toolingRepository,
      toolingSha: this.state.inputs.toolingSha, suppliedSnapshot,
    };
    if (!githubSetupRequestFits(input)) {
      this.update({ error: githubSetupError({ code: 'invalid_request' }), pending: null, result: null, resultBinding: null });
      return;
    }
    const request: GitHubSetupRequest = freeze(structuredClone(input));
    const api = this.api;
    const binding: GitHubDisplayBinding = freeze({
      ...this.state.project, requestId: ++this.nextRequest, serviceGeneration: this.state.serviceGeneration,
      selectionGeneration: this.state.selectionGeneration, coordinateGeneration: this.state.coordinateGeneration,
      comparisonGeneration: this.state.comparisonGeneration,
    });
    this.update({ pending: binding, result: null, resultBinding: null, error: null, invalidated: false });
    // A synchronous subscriber can invalidate before invocation as well.
    if (!this.current(binding)) return;
    if (this.otherOperationReason()) { this.invalidate({}); return; }
    this.passivePending += 1;
    try {
      const raw: unknown = await api.proposeGitHubSetup(request);
      this.syncProject();
      if (!this.current(binding)) return;
      const result = parseGitHubSetupResult(raw);
      if (!result || !githubSetupResultMatches(result, request)) throw { code: 'GitHubSetupResponseInvalid' };
      this.update({ pending: null, result: freeze(structuredClone(result)), resultBinding: binding, error: null });
    } catch (error) {
      this.syncProject();
      if (!this.current(binding)) return;
      const safe = githubSetupError(error);
      const unavailable = ['NativeBridgeRequired', 'runtime_unavailable', 'cleanup_unknown', 'shutting_down', 'protocol_error', 'GitHubSetupResponseInvalid', 'GitHubSetupUnavailable'].includes(safe.code);
      this.update({
        pending: null, result: null, resultBinding: null, error: safe,
        reason: unavailable ? safe.message : this.state.reason,
        helpState: this.state.help ? 'previous' : 'unavailable',
      });
    } finally { this.passivePending -= 1; this.update({}); }
  }

  dispose(): void {
    this.disposed = true;
    this.api = null;
    this.listeners.clear();
  }
}
