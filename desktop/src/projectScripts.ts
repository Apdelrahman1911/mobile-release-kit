// Static hints -> explicit local draft edit only. No script runner or save API.
import { blockingAncestor, getValue, sameJson } from './catalog.ts';
import { reviewFresh } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import { copyBoundedComparisonData, parseSavedConfigContent, sameSavedConfig, savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';
import type { Assurance, Catalog, HelpContent, JsonValue } from './types.ts';

const names: Record<string, 'prepare' | 'check' | 'build'> = {
  'prepare.sh': 'prepare', 'prepare-ios.sh': 'prepare', 'generate.sh': 'prepare', 'generate-project.sh': 'prepare',
  'check.sh': 'check', 'preflight.sh': 'check', 'check-project.sh': 'check',
  'check-android-artifact.sh': 'check', 'check-ios-artifact.sh': 'check',
  'build.sh': 'build', 'build-android.sh': 'build', 'build-ios.sh': 'build',
};
const directories = new Set(['', 'scripts', 'app', 'app/scripts', 'androidApp', 'androidApp/scripts',
  'composeApp', 'composeApp/scripts', 'shared', 'shared/scripts', 'ios', 'ios/scripts', 'iosApp', 'iosApp/scripts']);
export type ProjectScriptStatus = 'direct-candidate' | 'not-executable' | 'unsupported-shebang' | 'permissions-unavailable' | 'unsupported-mode';
export interface ProjectScriptCandidate { path: string; purposeHint: 'prepare' | 'check' | 'build'; status: ProjectScriptStatus; shell: 'sh' | 'bash' | null }
export interface ProjectScriptDiscovery {
  schemaVersion: 1; scope: 'project-script-hints'; coverage: 'conventional-paths-only'; sourcePartial: boolean; truncated: boolean;
  platforms: ('android' | 'ios')[]; candidates: ProjectScriptCandidate[]; assurance: Assurance & { basis: 'static-text' };
}
const statuses: readonly string[] = ['direct-candidate', 'not-executable', 'unsupported-shebang', 'permissions-unavailable', 'unsupported-mode'];
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const keys = (value: unknown, names: readonly string[]): value is Record<string, unknown> => record(value) &&
  Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
function conventional(path: unknown): path is string {
  if (typeof path !== 'string' || path.startsWith('/')) return false;
  const slash = path.lastIndexOf('/'), directory = path.slice(0, slash < 0 ? 0 : slash), name = path.slice(slash + 1);
  return directories.has(directory) && Object.hasOwn(names, name);
}
export function parseProjectScriptDiscovery(input: unknown): ProjectScriptDiscovery | null {
  try {
    const value = copyBoundedComparisonData(input, 16 * 1024, 2048);
    if (!keys(value, ['schemaVersion', 'scope', 'coverage', 'sourcePartial', 'truncated', 'platforms', 'candidates', 'assurance']) ||
        value.schemaVersion !== 1 || value.scope !== 'project-script-hints' || value.coverage !== 'conventional-paths-only' ||
        typeof value.sourcePartial !== 'boolean' || typeof value.truncated !== 'boolean' ||
        !Array.isArray(value.platforms) || value.platforms.length > 2 || new Set(value.platforms).size !== value.platforms.length ||
        value.platforms.some((platform) => platform !== 'android' && platform !== 'ios') || value.platforms.length === 2 && value.platforms[0] !== 'android' ||
        !Array.isArray(value.candidates) || value.candidates.length > 16 || value.truncated && value.candidates.length !== 16 ||
        !keys(value.assurance, ['basis', 'projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed', 'releaseReadiness']) ||
        value.assurance.basis !== 'static-text' || value.assurance.releaseReadiness !== 'unknown') return null;
    const claims = value.assurance;
    if (['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed'].some((key) => claims[key] !== false)) return null;
    let previous = '';
    for (const row of value.candidates) {
      if (!keys(row, ['path', 'purposeHint', 'status', 'shell']) || !conventional(row.path) || row.path <= previous ||
          row.purposeHint !== names[row.path.slice(row.path.lastIndexOf('/') + 1)] || !statuses.includes(row.status as string) ||
          row.shell !== null && row.shell !== 'sh' && row.shell !== 'bash' ||
          row.status === 'direct-candidate' && row.shell === null || row.status === 'unsupported-shebang' && row.shell !== null) return null;
      previous = row.path;
    }
    return value as unknown as ProjectScriptDiscovery;
  } catch { return null; }
}

export const PROJECT_SCRIPT_STAGES = ['projectChecks.preflight', 'ios.prepareCommand', 'projectChecks.androidArtifact', 'projectChecks.iosArtifact'] as const;
export type ProjectScriptStage = typeof PROJECT_SCRIPT_STAGES[number];
export const projectScriptStageLabels: Record<ProjectScriptStage, string> = {
  'projectChecks.preflight': 'During project checks', 'ios.prepareCommand': 'Before iOS preparation / archive',
  'projectChecks.androidArtifact': 'During Android artifact checks', 'projectChecks.iosArtifact': 'During iOS artifact checks',
};
export const projectScriptStageHelp: Record<ProjectScriptStage, string> = {
  'projectChecks.preflight': 'Runs during explicit local-project checks or release preflight, not every standalone build.',
  'ios.prepareCommand': 'Runs in the existing iOS preparation flow, including archive. It is not a general Android build hook.',
  'projectChecks.androidArtifact': 'Runs when the existing Android artifact-check stage is requested, not simply when a local build finishes.',
  'projectChecks.iosArtifact': 'Runs when the existing iOS artifact-check stage is requested, not simply when a local archive finishes.',
};
export const projectScriptStatusHelp: Record<ProjectScriptStatus, string> = {
  'direct-candidate': 'Executable-bit and shell-header hints only; not run or approved.',
  'not-executable': 'Not executable for the observed user. Review permissions yourself, then refresh; this app does not change them.',
  'unsupported-shebang': 'No supported direct shell header. Review the file yourself; no shell command is guessed or inserted.',
  'permissions-unavailable': 'Executable permissions were not observed on this platform. Configure a reviewed command manually in Advanced.',
  'unsupported-mode': 'Special or shared-writable file mode. Review permissions yourself; the app will not change them.',
};
export const projectScriptHelp: HelpContent = {
  label: 'Existing project scripts', requiredness: 'optional', requiredWhen: 'Only if your project needs an extra preparation or check command.',
  what: 'A small list of conventional project-owned .sh files from the same passive project read. Names suggest a purpose; they do not prove what a script does.',
  why: 'You can add a direct command to the current draft without typing its path. Nothing is executed or saved by this action.',
  where: 'Review the file in your editor first. This helper checks conventional root/scripts, app, androidApp, composeApp, shared, ios and iosApp locations. Other layouts remain editable in Advanced.',
  format: 'The preset is one argv entry, such as ./scripts/check.sh. Only observed executable bits and an exact /bin/sh or /bin/bash header qualify. Additional arguments must be reviewed and entered in the existing command fields.',
  failure: 'Partial/stale reads, unsupported headers or permissions do not enable a preset. Refresh after fixing the source, or configure a reviewed command manually. Later execution still requires its original checks and explicit operation approval.',
};
export interface ProjectScriptContext { session: ProjectSession | null; catalog: Catalog | null; service: object | null; epoch: number; preview: boolean; reason: string | null }
export interface ProjectScriptsView { discovery: ProjectScriptDiscovery | null; reason: string | null }
export function projectScriptsView(context: ProjectScriptContext): ProjectScriptsView {
  const unavailable = (reason: string): ProjectScriptsView => ({ discovery: null, reason });
  const { session, catalog } = context;
  if (context.preview || !context.service) return unavailable('Choose a real project to look for its existing scripts.');
  if (context.reason !== null) return unavailable(context.reason);
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0 || context.epoch >= Number.MAX_SAFE_INTEGER) return unavailable('The project context is unavailable. Keep the draft.');
  if (!session?.draft || !session.snapshot || !catalog || session.observedAt === null) return unavailable('Read the project and open a configuration draft first.');
  if (session.snapshot.root !== session.project.path || session.snapshotRequest !== null || session.snapshotError || session.snapshotPredatesSave || session.sourceChanged ||
      session.saveRecoveryRequired || session.saveRecoveryNeedsReload || session.reviewRequest !== null || session.validationRequest !== null || session.suggestionRequest !== null) {
    return unavailable('Finish the original operation or refresh this project first. Your draft is kept.');
  }
  if (session.snapshot.config.state === 'format-valid') {
    const saved = savedConfigFromSnapshot(session.snapshot), retained = parseSavedConfigContent(session.savedConfigContent);
    if (!saved || !retained || !sameSavedConfig(saved, retained)) return unavailable('The saved-file comparison is no longer current. Refresh first; your draft is kept.');
  } else if (session.snapshot.config.state !== 'missing') return unavailable('Repair the saved configuration before adding a script preset. Existing files and draft values are kept.');
  const descriptor = Object.getOwnPropertyDescriptor(session.snapshot, 'scriptDiscovery');
  const discovery = descriptor?.enumerable && Object.hasOwn(descriptor, 'value') ? parseProjectScriptDiscovery(descriptor.value) : null;
  if (!discovery || discovery.sourcePartial !== session.snapshot.discovery.partial) return unavailable('Script hints are unavailable for this read. Refresh when safe, or use the existing command fields in Advanced.');
  return { discovery, reason: discovery.sourcePartial || discovery.truncated ? 'This list is incomplete. Refresh before adding a preset, or review a command manually in Advanced.' :
    discovery.platforms.length === 0 ? 'No supported Android or Xcode layout was observed. Configure your project layout, or use a reviewed command in Advanced.' : null };
}
export interface ProjectScriptEdit {
  context: ProjectScriptContext; candidate: string; stage: ProjectScriptStage; path: ProjectScriptStage; value: JsonValue;
}
export function prepareProjectScriptEdit(context: ProjectScriptContext, candidate: string, stage: ProjectScriptStage): { edit: ProjectScriptEdit | null; reason: string | null } {
  const view = projectScriptsView(context);
  const refuse = (reason: string) => ({ edit: null, reason });
  if (view.reason || !view.discovery || !context.session?.draft || !context.catalog) return refuse(view.reason ?? 'Read the selected project first.');
  if (!PROJECT_SCRIPT_STAGES.includes(stage)) return refuse('Choose one supported existing stage.');
  const source = view.discovery.candidates.find((row) => row.path === candidate);
  if (!source || source.status !== 'direct-candidate') return refuse(source ? projectScriptStatusHelp[source.status] : 'Choose an observed script first.');
  const { session, catalog } = context;
  const draft = session.draft!;
  const platform = stage === 'projectChecks.preflight' ? null : stage === 'projectChecks.androidArtifact' ? 'android' : 'ios';
  const enabled = (value: 'android' | 'ios') => view.discovery!.platforms.includes(value) && getValue(draft, `${value}.enabled`) === true;
  if (platform ? !enabled(platform) : !view.discovery.platforms.some(enabled)) return refuse('Enable and review the matching platform in this draft before choosing that stage.');
  if (!catalog.fields.some((field) => field.path === stage && field.input === (stage === 'ios.prepareCommand' ? 'argv' : 'commands')) ||
      reviewFresh(session) && session.review?.result.fields.some((field) => field.path === stage && field.state === 'forbidden')) return refuse('This stage is not available in the current configuration fields.');
  if (blockingAncestor(draft, stage) !== null) return refuse('A parent setting has an unsupported value. Repair it in the existing editor; no value was replaced.');
  const current = getValue(draft, stage), argv = [`./${source.path}`];
  let value: JsonValue;
  if (stage === 'ios.prepareCommand') {
    if (current !== undefined) return refuse('An iOS preparation command already exists. Review it in Advanced; this helper never replaces it.');
    value = argv;
  } else {
    if (current !== undefined && (!Array.isArray(current) || current.length >= 32 || current.some((row) => !Array.isArray(row) || row.length === 0 || row.length > 64 ||
      row.some((arg) => typeof arg !== 'string' || arg.length === 0 || arg.length > 4096 || arg.includes('\0'))))) return refuse('Review the existing command list in Advanced first. Its values were kept.');
    const previous = current as JsonValue[] | undefined;
    if (previous?.some((row) => Array.isArray(row) && row[0] === argv[0])) return refuse('This script is already in that stage. Review its arguments in Advanced instead of adding it twice.');
    value = [...(previous ?? []), argv];
  }
  return { edit: { context: { ...context }, candidate, stage, path: stage, value }, reason: null };
}
export interface ProjectScriptDraftAction { type: 'edit'; projectId: string; path: ProjectScriptStage; value: JsonValue; expectedSession: ProjectSession }
export function applyProjectScriptEdit(edit: ProjectScriptEdit, current: () => ProjectScriptContext, commit: (action: ProjectScriptDraftAction) => boolean): boolean {
  const now = current(), original = edit.context;
  if (now.session !== original.session || now.service !== original.service || now.catalog !== original.catalog || now.epoch !== original.epoch) return false;
  const fresh = prepareProjectScriptEdit(now, edit.candidate, edit.stage).edit;
  if (!fresh || fresh.path !== edit.path || !sameJson(fresh.value, edit.value) || !now.session) return false;
  // The original reducer also compares expectedSession AFTER its synchronous
  // owner-retirement listeners, preventing a reentrant newer draft overwrite.
  return commit({ type: 'edit', projectId: now.session.project.id, path: fresh.path, value: fresh.value, expectedSession: now.session });
}
