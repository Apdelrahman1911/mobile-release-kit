// Navigation and local selection only. Existing owners still perform every
// check, build, history read and separately approved Store action.
import type { ProjectSession } from './drafts.ts';
import type { ReleaseVersionState } from './releaseVersion.ts';
import type { SetupAction } from './setupOverview.ts';
import { setupResume } from './setupResume.ts';
import type { SetupResumeSource } from './setupResume.ts';
import { localHistoryOwnerReason, localHistoryRequest } from './localReleaseHistory.ts';
import type { LocalHistoryState, LocalReleaseHistoryController } from './localReleaseHistory.ts';
import type { LocalHistoryResult, LocalHistoryStatus } from './localReleaseHistoryTypes.ts';
import { parseLocalHistoryStatus } from './localReleaseHistoryProtocol.ts';
import { localStoreOwnerReason, localStoreProjectObservation, localStoreRequest } from './localStorePreflight.ts';
import type { LocalStoreState } from './localStorePreflight.ts';
import { parseLocalStoreStatus } from './localStorePreflightProtocol.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';

export type RehearsalTarget = 'local-checks' | 'android-build' | 'ios-build' | 'history' | 'store-access' | 'original-controls';
type Row = LocalHistoryResult['history'][number];
export interface RehearsalContext {
  session: ProjectSession | null;
  nativeSession: object | null; // Retained application connection; comparison only.
  epoch: number;
  preview: boolean;
  readReason: string | null;
  resume: SetupResumeSource;
  version: ReleaseVersionState;
  history: LocalHistoryState;
  historyController: LocalReleaseHistoryController;
  historyReason: string | null;
  store: LocalStoreState;
  storeReason: string | null;
}
interface CandidateSelection {
  kind: 'select-candidate';
  session: ProjectSession;
  nativeSession: object;
  epoch: number;
  controller: LocalReleaseHistoryController;
  status: LocalHistoryStatus;
  result: LocalHistoryResult;
  row: Row;
  platform: 'android' | 'ios'; // Explicitly named on the button, never inferred from a row.
}
export type RehearsalAction = { kind: 'show'; target: RehearsalTarget } | { kind: 'setup'; action: SetupAction } | CandidateSelection;
export interface RehearsalStep {
  id: 'build' | 'candidate' | 'store';
  title: string;
  summary: string;
  status: 'not-checked' | 'result-available' | 'attention';
  label: string;
  action: RehearsalAction;
  reason: string | null;
}
export interface ReleaseRehearsalView {
  next: Pick<RehearsalStep, 'label' | 'action' | 'summary'>;
  attention: boolean;
  steps: readonly RehearsalStep[];
}
const show = (target: RehearsalTarget): RehearsalAction => ({ kind: 'show', target });
const page = (name: 'dashboard' | 'credentials'): RehearsalAction => ({ kind: 'setup', action: { kind: 'navigate', page: name } });

function currentHistory(c: RehearsalContext): LocalHistoryResult | null {
  const s = c.history, op = s.status?.operation;
  if (!c.session || !c.nativeSession || c.preview || c.resume.otherOwnerReason || s.mode !== 'native' || s.callersPending !== false ||
      localHistoryOwnerReason(s) || s.historical || s.error || !op || op.phase !== 'terminal' ||
      op.outcome !== 'complete' || op.reason !== 'none' || op.context.projectId !== c.session.project.id ||
      !parseLocalHistoryStatus(s.status) || c.historyController.getSnapshot() !== s) return null;
  return op.result;
}
function candidateSelection(c: RehearsalContext, result: LocalHistoryResult, row: Row): CandidateSelection | null {
  if (!c.session || !c.nativeSession || !c.history.status || c.historyReason || c.resume.otherOwnerReason ||
      !Number.isSafeInteger(c.epoch) || c.epoch < 0 || c.epoch === Number.MAX_SAFE_INTEGER ||
      row.phase !== 'inputs-ready' || result.history.at(-1) !== row) return null;
  return { kind: 'select-candidate', session: c.session, nativeSession: c.nativeSession, epoch: c.epoch,
    controller: c.historyController, status: c.history.status, result, row, platform: c.history.inputPlatform };
}
function storeStep(c: RehearsalContext): RehearsalStep {
  const platform = c.resume.platform, s = c.store, op = s.status?.operation;
  const title = platform === 'ios' ? 'App Store Connect' : 'Google Play';
  const result: RehearsalStep = { id: 'store', title: `Check ${title} access (optional)`, status: 'not-checked',
    summary: `Only needed for later Store work. Use your existing ${platform === 'ios' ? 'App Store Connect P8 and matching Key ID / Issuer ID' : 'Google service-account JSON'} in Credentials → This Mac → ${platform === 'ios' ? 'iOS' : 'Android'} → Store. This is separate from your signing key.`,
    label: c.storeReason ? 'Review Store check requirements' : 'Open the separate access check', action: show('store-access'), reason: c.storeReason };
  // Only the existing ordinary access query counts here. Bundle/profile and
  // single/paired version inventories are different observations on this owner.
  if (!c.session || !c.nativeSession || c.preview || c.resume.otherOwnerReason || s.mode !== 'native' || s.callersPending !== false ||
      localStoreOwnerReason(s) || s.historical || s.error || !op || op.phase !== 'terminal' || op.outcome !== 'complete' ||
      op.reason !== 'none' || op.context.query !== undefined || op.context.platform !== platform ||
      op.result?.scope !== `local-${platform}-store-access-no-publishing` || !parseLocalStoreStatus(s.status)) return result;
  const expected = localStoreRequest(localStoreProjectObservation(c.session, c.version), c.resume.credentials);
  if (!expected || expected.query !== undefined || !sameOfflineData(s.request, expected) ||
      !sameOfflineData(op.context, { ...expected, platform: expected.platform ?? 'android', operation: 'local-store-preflight' })) return result;
  const negative = op.result.findings.some((f) => ['FAIL', 'BLOCKED', 'INVALID', 'MISSING'].includes(f.status));
  return { ...result, status: negative ? 'attention' : 'result-available', label: 'Read the access-check findings',
    summary: negative ? 'The original access check returned findings needing attention. Review them; do not repeat an upload or replace a credential to dismiss a failure.' :
      'An access-check result is available for these saved inputs. It is a point-in-time observation, not release readiness; no upload or public release was approved.' };
}

export function releaseRehearsal(c: RehearsalContext): ReleaseRehearsalView {
  const resume = setupResume(c.session, c.preview, c.readReason, c.resume);
  const buildTarget = c.resume.platform === 'ios' ? 'ios-build' : 'android-build';
  const build: RehearsalStep = { id: 'build', title: 'Try a local build', status: resume.completedBuild ? 'result-available' : 'not-checked',
    summary: resume.build?.summary ?? 'Start with the ordinary local build options. Store-account setup is not required for those options; signing has its own separate requirements.',
    label: resume.completedBuild ? 'View the local build result' : 'Review local build options', action: show(buildTarget), reason: null };
  const candidate: RehearsalStep = { id: 'candidate', title: 'Keep a signed candidate (optional)', status: 'not-checked',
    summary: 'For a later release, use the existing signed-build option and explicitly choose Keep local candidate inputs. This additionally needs saved local-release opt-in, the configured clean candidate branch, metadata and enrolled Local release history. Nothing uploads.',
    label: 'Review signed candidate options', action: show(buildTarget), reason: null };
  const store = storeStep(c), steps = [build, candidate, store];
  let next: ReleaseRehearsalView['next'] = build;
  const history = currentHistory(c), row = history?.history.at(-1);
  if (history && row) {
    if (row.phase === 'inputs-ready') {
      const inputs = history.candidateInputs;
      const reviewed = c.history.status?.operation?.context.action === 'review-inputs' && inputs?.operationId === row.operationId &&
        (c.history.status.operation.context.platform ?? 'android') === c.history.inputPlatform;
      if (reviewed) {
        Object.assign(candidate, { status: 'result-available', label: 'View the reviewed candidate files', action: show('history'),
          summary: 'The retained candidate files were checked against local history. This did not rebuild them, prove the earlier build’s cleanup or authorize a Store action.' });
        next = store;
      } else {
        const selection = candidateSelection(c, history, row);
        Object.assign(candidate, { label: selection ? `Review ${selection.platform === 'ios' ? 'iOS' : 'Android'} candidate files` : 'Open candidate history',
          action: selection ?? show('history'), reason: c.historyReason,
          summary: 'A retained candidate is listed. Select its original platform in Local release history, then review those files rather than rebuilding. History rows alone do not identify a platform or confirm old cleanup.' });
        next = candidate;
      }
    } else {
      Object.assign(candidate, { status: 'attention', label: 'Inspect the previous local release record', action: show('history'),
        summary: 'The latest record is not an unused candidate ready for this walkthrough. Inspect its original status and files before considering another operation. A saved record cannot establish current Store state or a safe retry.' });
      next = candidate;
    }
  } else if (resume.completedBuild === 'candidate') {
    Object.assign(candidate, { label: 'Open local history verification', action: show('history'), reason: c.historyReason,
      summary: 'This original build retained a local candidate. Verify local history and review its files next; do not rerun the build to recover its result.' });
    next = candidate;
  } else if (resume.completedBuild === 'local') {
    candidate.summary = 'Your ordinary local build result is already available; it is not a retained release candidate. Stop here if you only wanted a local build. Signing and Keep candidate are separate optional choices, never automatic reruns.';
    next = candidate;
  } else if (resume.configuration) {
    next = { label: 'Continue local setup', summary: resume.configuration.summary, action: page('dashboard') };
  }
  // Original ownership wins over every superficially complete result. A
  // foreign project is named as such; this guide never switches projects.
  const owned = [
    { state: c.history, reason: localHistoryOwnerReason(c.history), name: 'local history', target: 'history' as const },
    { state: c.store, reason: localStoreOwnerReason(c.store), name: 'Store access check', target: 'store-access' as const },
  ].map((item) => ({ ...item, recovery: item.state.status?.operation?.reason === 'recovery-required',
    rank: item.state.blocked || item.state.status?.operation?.phase === 'unknown' || item.state.status?.operation?.reason === 'recovery-required' ? 0 :
      item.state.status?.operation?.phase === 'stopping' ? 1 : 2 }))
    .filter((item) => item.reason || item.recovery).sort((a, b) => a.rank - b.rank);
  const rank = (state: string) => state === 'unknown' || state === 'recovery-required' ? 0 : state === 'cancellation-requested' ? 1 : 2;
  const own = owned[0], activity = [...resume.activities].sort((a, b) => rank(a.state) - rank(b.state))[0];
  if (own && (!activity || own.rank <= rank(activity.state))) {
    const op = own.state.status?.operation;
    // An older terminal cannot identify a new, unacknowledged caller after a
    // project switch. Never attribute that call to the selected project.
    const project = op && (op.phase !== 'terminal' || own.recovery) ? op.context.projectId : null;
    next = { label: 'Show the original task', action: show(own.target), summary:
      `${project && project !== c.session?.project.id ? 'An earlier project’s' : 'The original'} ${own.name} still needs attention. ${own.state.callersPending ? 'Its original call has not returned yet, even if a result is visible. ' : ''}Keep the app and files; use that task’s existing status and ${own.recovery ? 'recovery guidance' : 'Cancel controls'}.` };
  } else if (activity) next = { label: 'Show the original task', action: activity.action.kind === 'navigate' && activity.action.page === 'releases'
    ? show('local-checks') : { kind: 'setup', action: activity.action },
    summary: `${activity.projectId && activity.projectId !== c.session?.project.id ? 'An earlier project’s task' : activity.task} must finish or be reviewed before continuing. Changing projects does not settle it.` };
  else if (!c.session || c.preview || !c.nativeSession) next = { label: 'Open project setup', action: page('dashboard'),
    summary: c.preview ? 'Example data cannot establish a rehearsal result. Use the native app and your own project.' : 'Choose your project and read its saved settings first. This guide does not run anything.' };
  return { next, attention: !!own || !!activity, steps };
}

// This handoff selects DATA in the original history form. It cannot call
// Prepare, Start, enroll, rebuild or access a Store. The original form still
// needs a fresh review and its own separate consent.
export function selectRehearsalCandidate(action: CandidateSelection, current: () => RehearsalContext,
  reveal: (target: RehearsalTarget) => void): boolean {
  const matches = (c: RehearsalContext) => !c.preview && Number.isSafeInteger(c.epoch) && c.epoch >= 0 && c.epoch < Number.MAX_SAFE_INTEGER &&
    c.session === action.session && c.nativeSession === action.nativeSession &&
    c.epoch === action.epoch && c.historyController === action.controller && c.historyController.getSnapshot() === c.history &&
    c.history.status === action.status && action.status.operation?.result === action.result && action.result.history.at(-1) === action.row &&
    c.history.inputPlatform === action.platform && !localHistoryOwnerReason(c.history) && !c.resume.otherOwnerReason && !c.historyReason;
  let c = current();
  if (!matches(c) || currentHistory(c) !== action.result || action.row.phase !== 'inputs-ready') return false;
  if (!action.controller.setInputPlatform(action.platform)) return false;
  c = current(); if (!matches(c) || currentHistory(c) !== action.result) return false;
  if (!action.controller.selectCandidate('review-inputs', action.row.operationId)) return false;
  c = current();
  // The selection intentionally retires the old display context. Keep the
  // EXACT original returned row, not a replacement with the same operation ID.
  if (!matches(c) || !sameOfflineData(c.history.request, localHistoryRequest(action.session.project.id,
    'review-inputs', action.row.operationId, action.platform === 'ios' ? 'ios' : undefined))) return false;
  reveal('history'); return true;
}
