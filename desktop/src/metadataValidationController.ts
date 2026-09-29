// App-retained display orchestration, never a child/resource owner. Retiring a
// view does not cancel or settle its original DocumentBinding passive request.
import { getValue } from './catalog.ts';
import { methodReason } from './certainty.ts';
import { metadataConfiguredChoices, metadataConfigReason } from './metadataText.ts';
import type { MetadataPlatform } from './metadataText.ts';
import { parseSavedConfigContent, sameSavedConfig } from './offlinePreflightProtocol.ts';
import type { SavedConfigContent } from './offlinePreflightTypes.ts';
import { parseSavedMetadataReport, savedMetadataError, savedMetadataRequestFits } from './metadataValidation.ts';
import type { SavedMetadataApi, SavedMetadataReport } from './metadataValidation.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import type { ApiError, AppInfo, BridgeMode } from './types.ts';

type Connection = SavedMetadataApi & { mode: BridgeMode };
interface Scope { metadataRoot: string; locales: string[] }
interface Binding extends Scope {
  projectId: string; platform: MetadataPlatform; revision: number; baselineGeneration: number;
  observationGeneration: number; savedConfig: SavedConfigContent;
}
export interface SavedMetadataState {
  projectId: string | null; platform: MetadataPlatform | null; platforms: MetadataPlatform[]; locales: string[];
  status: 'not-checked' | 'checking' | 'incomplete' | 'checked' | 'issues';
  pending: boolean; report: SavedMetadataReport | null; error: ApiError | null;
}
interface Context { selectedProject: () => ProjectSession | null; otherOperationReason: () => string | null }
const BUSY = 'The original saved metadata request is still pending. Wait for its passive owner to settle before another operation.';

// The display convenience may omit malformed lists; require a complete selected
// roster as well. Never send this root/locale list across the native command.
function scope(project: ProjectSession | null, selected: MetadataPlatform): Scope | null {
  if (!project?.baseline || getValue(project.baseline, selected + '.enabled') !== true) return null;
  const metadataRoot = getValue(project.baseline, 'metadata.root');
  const locales = getValue(project.baseline, 'metadata.' + selected + 'Locales');
  if (typeof metadataRoot !== 'string' || !Array.isArray(locales) || !locales.length || locales.length > 250 ||
    !locales.every((locale) => typeof locale === 'string') || new Set(locales).size !== locales.length) return null;
  const expected = [...locales as string[]].sort();
  const choices = metadataConfiguredChoices(project).filter((choice) => choice.platform === selected);
  if (choices.length !== expected.length || choices.some((choice) => choice.metadataRoot !== metadataRoot ||
    choice.projectId !== project.project.id || !expected.includes(choice.locale))) return null;
  return { metadataRoot, locales: expected };
}
function freeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
export class SavedMetadataValidationController {
  private api: Connection | null = null;
  private info: AppInfo | null = null;
  private visible = false;
  private selectionPending = false;
  private epoch: object = {};
  private original: object | null = null;
  private signature = '';
  private listeners = new Set<() => void>();
  private state: SavedMetadataState = freeze({ projectId: null, platform: null, platforms: [], locales: [],
    status: 'not-checked', pending: false, report: null, error: null });
  private context: Context;
  constructor(context: Context) { this.context = context; }
  getSnapshot = (): SavedMetadataState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private publish(change: Partial<SavedMetadataState>): void {
    this.state = freeze({ ...this.state, ...change });
    for (const listener of this.listeners) listener();
  }
  invalidate = (): void => {
    this.epoch = {};
    // original/pending is intentionally untouched here.
    if (this.state.status !== 'not-checked' || this.state.report || this.state.error)
      this.publish({ status: 'not-checked', report: null, error: null });
  };
  beginConnection = (): void => { this.invalidate(); this.api = null; this.info = null; };
  setConnection = (api: Connection | null, info: AppInfo | null): void => {
    this.invalidate(); this.api = api; this.info = info; this.syncProject();
  };
  connectionUnavailable = (): void => { this.setConnection(null, null); };
  setVisible = (visible: boolean): void => { this.invalidate(); this.visible = visible; };
  selectionIntent = (): void => { this.invalidate(); };
  setSelectionPending = (pending: boolean): void => { this.invalidate(); this.selectionPending = pending; };
  snapshotIntent = (projectId: string): void => { if (projectId === this.context.selectedProject()?.project.id) this.invalidate(); };
  beforeWorkspaceAction = (action: WorkspaceAction): void => {
    if (action.type === 'select' || action.type === 'switch' || action.projectId === this.context.selectedProject()?.project.id) this.invalidate();
  };
  syncProject = (): void => {
    const project = this.context.selectedProject();
    const platforms = (['android', 'ios'] as const).filter((selected) => scope(project, selected) !== null);
    const selected = this.state.platform && platforms.includes(this.state.platform) ? this.state.platform : platforms[0] ?? null;
    const current = selected ? scope(project, selected) : null;
    const savedConfig = parseSavedConfigContent(project?.savedConfigContent);
    const signature = JSON.stringify([project?.project.id, project?.revision, project?.baselineGeneration,
      project?.observationGeneration, project?.snapshotRequest, project?.sourceChanged, project?.saveRecoveryRequired,
      metadataConfigReason(project), savedConfig, platforms, selected, current]);
    if (signature === this.signature) return;
    this.signature = signature; this.invalidate();
    this.publish({ projectId: project?.project.id ?? null, platforms: [...platforms], platform: selected, locales: current?.locales ?? [] });
  };
  selectPlatform = (selected: MetadataPlatform): void => {
    this.invalidate();
    if (!this.state.platforms.includes(selected)) return;
    this.publish({ platform: selected }); this.signature = ''; this.syncProject();
  };
  passiveBusyReason = (): string | null => this.original ? BUSY : null;
  startReason = (): string | null => {
    if (this.original) return BUSY;
    if (!this.visible) return 'Open the Metadata page to run an explicit saved-file check.';
    if (this.selectionPending) return 'Finish the original project selection first.';
    const unavailable = methodReason(this.info, 'metadata.validate', this.api?.mode ?? 'unavailable');
    if (unavailable) return unavailable;
    const project = this.context.selectedProject(), reason = metadataConfigReason(project);
    if (reason) return reason;
    if (!this.state.platform || !scope(project, this.state.platform)) return 'Select an enabled platform with a complete saved locale list.';
    if (!parseSavedConfigContent(project?.savedConfigContent)) return 'Refresh the saved configuration before checking metadata; exact saved bytes are not currently available.';
    return this.context.otherOperationReason();
  };
  private capture(): Binding | null {
    const project = this.context.selectedProject(), selected = this.state.platform;
    if (!project || !selected || metadataConfigReason(project) || !this.visible || this.selectionPending) return null;
    const current = scope(project, selected), savedConfig = parseSavedConfigContent(project.savedConfigContent);
    return current && savedConfig ? { ...current, projectId: project.project.id, platform: selected, revision: project.revision,
      baselineGeneration: project.baselineGeneration, observationGeneration: project.observationGeneration,
      savedConfig: { ...savedConfig } } : null;
  }
  private current(binding: Binding, epoch: object, api: Connection): boolean {
    if (this.epoch !== epoch || this.api !== api) return false;
    const current = this.capture();
    return current !== null && current.projectId === binding.projectId && current.platform === binding.platform &&
      current.revision === binding.revision && current.baselineGeneration === binding.baselineGeneration &&
      current.observationGeneration === binding.observationGeneration && current.metadataRoot === binding.metadataRoot &&
      sameSavedConfig(current.savedConfig, binding.savedConfig) && JSON.stringify(current.locales) === JSON.stringify(binding.locales);
  }
  validate = (): Promise<void> => {
    if (this.startReason()) return Promise.resolve();
    const api = this.api, binding = this.capture();
    if (!api || !binding) return Promise.resolve();
    const request = { projectId: binding.projectId, platform: binding.platform };
    if (!savedMetadataRequestFits(request)) { this.publish({ status: 'incomplete', report: null, error: savedMetadataError(null) }); return Promise.resolve(); }
    // Reserve before the sole synchronous publication. A subscriber can retire
    // this context or attempt reentry; neither can dispatch a stale admission.
    const epoch = {}, original = {};
    this.epoch = epoch; this.original = original;
    this.publish({ pending: true, status: 'checking', report: null, error: null });
    if (!this.current(binding, epoch, api) || methodReason(this.info, 'metadata.validate', api.mode) ||
      this.context.otherOperationReason()) {
      // No API promise exists yet. Only this never-dispatched reservation may
      // settle here; an issued original still releases solely in its finally.
      if (this.original === original) {
        this.original = null; this.publish({ pending: false, status: 'not-checked', report: null, error: null });
      }
      return Promise.resolve();
    }
    let promise: Promise<unknown>;
    try { promise = Promise.resolve(api.validateMetadata(request)); }
    catch (error) { promise = Promise.reject(error); }
    return promise.then((value) => {
      if (!this.current(binding, epoch, api)) return;
      const report = parseSavedMetadataReport(value);
      if (!report || report.platform !== binding.platform || report.metadataRoot !== binding.metadataRoot ||
        JSON.stringify(report.locales) !== JSON.stringify(binding.locales) || !sameSavedConfig(report.savedConfig, binding.savedConfig)) {
        this.publish({ status: 'incomplete', report: null, error: savedMetadataError({ code: 'metadata_validation_changed' }) });
        return;
      }
      this.publish({ status: report.valid ? 'checked' : 'issues', report: structuredClone(report), error: null });
    }, (error: unknown) => {
      if (this.current(binding, epoch, api)) this.publish({ status: 'incomplete', report: null, error: savedMetadataError(error) });
    }).finally(() => {
      // Only settlement of this original promise releases the renderer barrier.
      // Navigation, dirty drafts, reconnection and late replies never do.
      if (this.original === original) { this.original = null; this.publish({ pending: false }); }
    });
  };
}
