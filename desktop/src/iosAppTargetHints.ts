// Optional passive source DATA. A choice copies a target name into the local
// selector; only the original ProjectIdentity owner can read/preview/apply it.
import type { ProjectSession } from './drafts.ts';
import { copyBoundedComparisonData, sameOfflineData, sameSavedConfig, savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';

interface Target { readonly name: string; readonly line: number }
type DiagnosticCode = 'missing-source' | 'source-limit' | 'unsupported-source' | 'ambiguous-target' | 'generated-project';
interface ProjectTargets {
  readonly project: string; readonly source: string; readonly targets: readonly Target[];
  readonly diagnostic: { readonly code: DiagnosticCode; readonly line: number } | null;
}
export interface IosAppTargetHints {
  readonly state: 'available' | 'manual' | 'refresh';
  readonly project: string | null; readonly source: string | null;
  readonly targets: readonly Target[]; readonly message: string; readonly diagnosticLine: number | null;
}
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) &&
  Object.keys(v).length === names.length && names.every(name => Object.hasOwn(v, name));
const line = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 1 && v <= 512 * 1024 + 1;
const name = (v: unknown): v is string => typeof v === 'string' && v.length >= 1 && v.length <= 255 && /^[A-Za-z0-9_. :()-]+$/.test(v);
const codes: readonly DiagnosticCode[] = ['missing-source', 'source-limit', 'unsupported-source', 'ambiguous-target', 'generated-project'];
function path(v: unknown): v is string {
  if (typeof v !== 'string' || v.length === 0 || v.length > 512 || !/^[A-Za-z0-9_.+ @()/-]+$/.test(v)) return false;
  const parts = v.split('/');
  return parts.length <= 16 && parts.every(part => part !== '' && part !== '.' && part !== '..' &&
    !['.git', '.gradle', '.idea', '.mobile-release', 'build', 'deriveddata', 'pods', 'node_modules', 'private', 'secrets', 'credentials', 'xcuserdata'].includes(part.toLowerCase()) &&
    !/^(\.mobile-release-|\.private-|\.codex-private-)/i.test(part));
}
const projectPath = (v: unknown): v is string => path(v) && v.endsWith('.xcodeproj') && path(`${v}/project.pbxproj`);

export function parseIosAppTargets(value: unknown): readonly ProjectTargets[] | null {
  try {
    const rows = copyBoundedComparisonData(value, 256 * 1024, 4096);
    if (!Array.isArray(rows) || rows.length > 16) return null;
    const projects = new Set<string>(), result: ProjectTargets[] = [];
    for (const row of rows) {
      if (!(keys(row, ['project', 'source', 'targets']) || keys(row, ['project', 'source', 'targets', 'diagnostic'])) ||
          !projectPath(row.project) || projects.has(row.project) ||
          typeof row.source !== 'string' || row.source !== `${row.project}/project.pbxproj` || !Array.isArray(row.targets) || row.targets.length > 32) return null;
      projects.add(row.project);
      const names = new Set<string>(), targets: Target[] = [];
      for (const target of row.targets) {
        if (!keys(target, ['name', 'line']) || !name(target.name) || !line(target.line) || names.has(target.name)) return null;
        names.add(target.name); targets.push(Object.freeze({ name: target.name, line: target.line }));
      }
      const diagnostic = Object.hasOwn(row, 'diagnostic') ? row.diagnostic : null;
      if (Object.hasOwn(row, 'diagnostic') && diagnostic === null) return null;
      if (diagnostic !== null && (!keys(diagnostic, ['code', 'line']) || !codes.some(code => code === diagnostic.code) ||
          !line(diagnostic.line) || targets.length !== 0)) return null;
      result.push(Object.freeze({ project: row.project, source: row.source, targets: Object.freeze(targets),
        diagnostic: diagnostic === null ? null : Object.freeze({ code: diagnostic.code as DiagnosticCode, line: diagnostic.line as number }) }));
    }
    return Object.freeze(result);
  } catch { return null; }
}

const manualMessage: Record<DiagnosticCode, string> = {
  'missing-source': 'The last check did not read this Xcode project. Check saved project files again, or enter its exact app target below.',
  'source-limit': 'This project is too large for target suggestions. Enter its exact app target from Xcode.',
  'unsupported-source': 'Targets could not be read safely from this project. Check the source location in Xcode; keep using the manual field if needed.',
  'ambiguous-target': 'This project has overlapping target names. Choose the intended app in Xcode; automatic name suggestions are unavailable.',
  'generated-project': 'This Xcode project appears generated. Change its generator configuration instead of editing the generated project.',
};
function view(state: IosAppTargetHints['state'], message: string, project: string | null = null,
  targets: readonly Target[] = [], diagnosticLine: number | null = null): IosAppTargetHints {
  return Object.freeze({ state, message, project, source: project ? `${project}/project.pbxproj` : null,
    targets: Object.freeze([...targets]), diagnosticLine });
}

export function iosAppTargetHints(session: ProjectSession | null): IosAppTargetHints {
  const refresh = () => view('refresh', 'Check saved project files to see target suggestions. Your manual target is kept.');
  try {
    const snapshot = session?.snapshot, saved = savedConfigFromSnapshot(snapshot);
    if (!session || !snapshot || snapshot.root !== session.project.path || !saved || !sameSavedConfig(saved, session.savedConfigContent) ||
        session.snapshotRequest !== null || session.snapshotError || session.snapshotPredatesSave || session.sourceChanged ||
        session.saveRecoveryRequired || session.saveRecoveryNeedsReload || snapshot.discovery.state !== 'unverified' || snapshot.discovery.partial) return refresh();
    const config = copyBoundedComparisonData(snapshot.config.data, 512 * 1024, 32768);
    const ios = record(config) && record(config.ios) ? config.ios : null;
    if (!ios || ios.enabled !== true || !projectPath(ios.project))
      return view('manual', 'Choose and save an iOS .xcodeproj in project settings before using target suggestions.');
    if (Object.hasOwn(ios, 'workspace'))
      return view('manual', 'This editor does not select targets through a workspace. Keep the workspace and update this layout in Xcode.', ios.project);
    const hints = snapshot.discovery.hints.ios;
    const rows = parseIosAppTargets(record(hints) ? hints.appTargets : null);
    const found = rows?.find(row => row.project === ios.project);
    if (!found) return view('manual', 'No target suggestions were included for this saved project. Enter its exact app target from Xcode.', ios.project);
    if (found.diagnostic) return view('manual', manualMessage[found.diagnostic.code], found.project, [], found.diagnostic.line);
    if (!found.targets.length) return view('manual', 'The last check did not list an app target in this project. Check Targets in Xcode and enter the exact name below.', found.project);
    return view('available', 'Names from the last file check, not a build check. Choose a name, then read and review its app ID separately.', found.project, found.targets);
  } catch { return refresh(); }
}

// Recheck the same saved observation at an explicit click. Root additionally
// fences API/project/intent-epoch changes before AND after retiring the old
// identity review. This helper neither calls an API nor changes an input.
export function canUseIosAppTarget(shown: IosAppTargetHints, original: ProjectSession | null,
  current: ProjectSession | null, target: string): boolean {
  return original !== null && current === original && shown.state === 'available' &&
    shown.targets.some(row => row.name === target) && sameOfflineData(shown, iosAppTargetHints(current));
}

export interface IosTargetChoiceContext {
  readonly session: ProjectSession | null; readonly service: object | null; readonly binding: object | null;
  readonly epoch: number; readonly platform: 'android' | 'ios'; readonly blocked: boolean;
}
// A synchronous local-field action, not native admission or a second controller.
// Root supplies its EXISTING retireIdentity and local selector setter. A reply,
// promise, source hint, or copied name cannot cause Open/Prepare/Apply here.
export function copyIosAppTarget(shown: IosAppTargetHints, captured: IosTargetChoiceContext, target: string,
  current: () => IosTargetChoiceContext, retire: () => void, setLocalTarget: (target: string) => void): boolean {
  if (captured.blocked || captured.platform !== 'ios' || !captured.service || !captured.binding ||
      !Number.isSafeInteger(captured.epoch) || captured.epoch < 0 || captured.epoch >= Number.MAX_SAFE_INTEGER) return false;
  const matches = (epoch: number) => {
    const now = current();
    return !now.blocked && now.platform === 'ios' && now.service === captured.service && now.binding === captured.binding &&
      now.epoch === epoch && canUseIosAppTarget(shown, captured.session, now.session, target);
  };
  try {
    if (!matches(captured.epoch)) return false;
    retire();
    if (!matches(captured.epoch + 1)) return false;
    setLocalTarget(target);
    return true;
  } catch { return false; } // No retry or guessed local success.
}
