// Display/correlation DATA only. A cached remote-tracking ref is NOT a fresh
// remote observation, a fetch request, native source custody or permission.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { gitReadPathOrder } from './gitReadProtocol.ts';
import { GIT_REASONS, parseGitObservation } from './gitRepositoryProtocol.ts';
import type { GitObservation, GitReason } from './gitRepositoryProtocol.ts';
import { isGitSwitchFile, isGitSwitchLog, isGitSwitchReason } from './gitSwitchProtocol.ts';
import type { GitSwitchFile, GitSwitchLog, GitSwitchReason } from './gitSwitchProtocol.ts';

export const GIT_FAST_FORWARD_REASONS = ['ff-target', 'ff-not-descendant', 'ff-layout', 'ff-log-limit'] as const;
export type GitFastForwardReason = typeof GIT_FAST_FORWARD_REASONS[number] | GitSwitchReason;
export type GitFastForwardIssue = GitFastForwardReason | 'ff-observation-required';
export interface GitFastForwardAction { readonly kind: 'fast-forward'; readonly expectedRevision: string;
  readonly expectedReferenceRevision: string; readonly targetRef: string; readonly targetOid: string }
export interface GitFastForwardReview { readonly action: 'fast-forward'; readonly targetRef: string; readonly targetOid: string;
  readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly head: string; readonly branch: string;
  readonly expectedIndex: string; readonly paths: readonly string[]; readonly trackedCount: number; readonly contentOnly: true;
  readonly basis: 'local-refs-no-fetch'; readonly files: readonly GitSwitchFile[]; readonly headLog: GitSwitchLog;
  readonly branchLog: GitSwitchLog; readonly reviewDigest: string }
export interface GitFastForwardIntent { readonly action: 'fast-forward'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly expectedRef: string; readonly expectedHead: string; readonly expectedIndex: string; readonly targetRef: string; readonly targetOid: string;
  readonly candidateIndex: string; readonly originalHead: string; readonly originalHeadLog: string; readonly originalBranchLog: string;
  readonly headLogEnabled: boolean; readonly branchLogEnabled: boolean; readonly footprint: string }
export type GitFastForwardEffect = 'not-published' | 'worktree-returned' | 'index-returned' | 'ref-returned';
export interface GitFastForwardMutationResult { readonly operationId: string; readonly action: 'fast-forward'; readonly state: 'succeeded' | 'failed' | 'recovery-required';
  readonly settlement: 'settled'; readonly reason: GitReason | GitFastForwardReason | null; readonly observation: GitObservation | null;
  readonly intent: GitFastForwardIntent | null; readonly effectPhase: GitFastForwardEffect; readonly retainedPaths: readonly string[] }
const utf8 = new TextEncoder();
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/.test(v);
const uint = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
function reference(v: unknown, prefix: string): v is string {
  return typeof v === 'string' && v.length <= 1024 && utf8.encode(v).length <= 1024 && v.startsWith(prefix) &&
    !/[\x00-\x20\x7f\p{Cs}~^:?*\[\\]/u.test(v) && !v.includes('..') && !v.includes('@{') &&
    v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
export function gitFastForwardTrackingRef(v: unknown): v is string {
  return reference(v, 'refs/remotes/') && v.split('/').length >= 4 && v.split('/').length <= 32 && v.split('/').at(-1) !== 'HEAD';
}
export function isGitFastForwardReason(v: unknown): v is GitFastForwardReason {
  return isGitSwitchReason(v) || typeof v === 'string' && GIT_FAST_FORWARD_REASONS.includes(v as typeof GIT_FAST_FORWARD_REASONS[number]);
}
export function isGitFastForwardAction(v: unknown): v is GitFastForwardAction {
  return connectionBounded(v, 4096, 32, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'targetRef', 'targetOid']) &&
    v.kind === 'fast-forward' && digest(v.expectedRevision) && digest(v.expectedReferenceRevision) && gitFastForwardTrackingRef(v.targetRef) && oid(v.targetOid);
}
export function isGitFastForwardReview(v: unknown, expected: GitFastForwardAction): v is GitFastForwardReview {
  if (!isGitFastForwardAction(expected) || !connectionBounded(v, 32 * 1024, 512, 5) ||
      !connectionKeys(v, ['action', 'targetRef', 'targetOid', 'expectedRevision', 'expectedReferenceRevision', 'head', 'branch', 'expectedIndex',
        'paths', 'trackedCount', 'contentOnly', 'basis', 'files', 'headLog', 'branchLog', 'reviewDigest']) || v.action !== 'fast-forward' ||
      v.expectedRevision !== expected.expectedRevision || v.expectedReferenceRevision !== expected.expectedReferenceRevision ||
      v.targetRef !== expected.targetRef || v.targetOid !== expected.targetOid || !reference(v.branch, 'refs/heads/') ||
      !oid(v.head) || !oid(v.targetOid) || v.head === v.targetOid || v.head.length !== v.targetOid.length ||
      !digest(v.expectedIndex) || !digest(v.reviewDigest) || v.contentOnly !== true || v.basis !== 'local-refs-no-fetch' ||
      !uint(v.trackedCount, 256) || !Array.isArray(v.files) || v.files.length > 8 || v.files.length > v.trackedCount ||
      !Array.isArray(v.paths) || v.paths.length !== v.files.length || !isGitSwitchLog(v.headLog) || !isGitSwitchLog(v.branchLog)) return false;
  const width = v.head.length, files = v.files, paths = v.paths;
  if (!files.every((f): f is GitSwitchFile => isGitSwitchFile(f, width))) return false;
  return files.every((f, i) => paths[i] === f.path && (i === 0 || gitReadPathOrder(files[i - 1]!.path, f.path) < 0)) &&
    files.reduce((n, f) => n + f.targetSize, 0) <= 8 * 1024 * 1024;
}
export function isGitFastForwardIntent(v: unknown, expected: GitFastForwardAction): v is GitFastForwardIntent {
  return isGitFastForwardAction(expected) && connectionBounded(v, 8192, 64, 2) &&
    connectionKeys(v, ['action', 'expectedRevision', 'expectedReferenceRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'targetRef', 'targetOid',
      'candidateIndex', 'originalHead', 'originalHeadLog', 'originalBranchLog', 'headLogEnabled', 'branchLogEnabled', 'footprint']) &&
    v.action === 'fast-forward' && v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision &&
    reference(v.expectedRef, 'refs/heads/') && v.targetRef === expected.targetRef && v.targetOid === expected.targetOid && oid(v.expectedHead) && oid(v.targetOid) &&
    v.expectedHead !== v.targetOid && v.expectedHead.length === v.targetOid.length &&
    [v.expectedIndex, v.candidateIndex, v.originalHead, v.originalHeadLog, v.originalBranchLog, v.footprint].every(digest) &&
    typeof v.headLogEnabled === 'boolean' && typeof v.branchLogEnabled === 'boolean';
}
export function fastForwardIntentMatchesReview(v: GitFastForwardIntent, r: GitFastForwardReview): boolean {
  return v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision && v.expectedRef === r.branch &&
    v.expectedHead === r.head && v.expectedIndex === r.expectedIndex && v.targetRef === r.targetRef && v.targetOid === r.targetOid &&
    v.originalHeadLog === r.headLog.originalSha256 && v.originalBranchLog === r.branchLog.originalSha256 &&
    v.headLogEnabled === r.headLog.enabled && v.branchLogEnabled === r.branchLog.enabled;
}
function retained(v: unknown): v is string[] {
  return Array.isArray(v) && v.length <= 5 && v.every((p) => typeof p === 'string' &&
    /^\.git\/mrk-git-[A-Za-z0-9_-]{1,64}\/(?:index|execution-index|checkout-mode)$(?![\s\S])/.test(p)) &&
    v.every((p, i) => i === 0 || gitReadPathOrder(v[i - 1]!, p) < 0);
}
export function isGitFastForwardMutation(v: unknown, expected: GitFastForwardAction, operationId: string): v is GitFastForwardMutationResult {
  if (!isGitFastForwardAction(expected) || !connectionBounded(v, 2 * 1024 * 1024, 25000, 10) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths']) ||
      v.operationId !== operationId || v.action !== 'fast-forward' || v.settlement !== 'settled' ||
      !(v.intent === null || isGitFastForwardIntent(v.intent, expected)) || !retained(v.retainedPaths) ||
      !['not-published', 'worktree-returned', 'index-returned', 'ref-returned'].includes(v.effectPhase as string) ||
      v.effectPhase !== 'not-published' && !v.intent) return false;
  if (v.state === 'succeeded') {
    const observation = parseGitObservation(v.observation);
    return v.reason === null && v.intent !== null && v.effectPhase === 'ref-returned' && v.retainedPaths.length === 0 &&
      !!observation && observation.head === v.intent.targetOid && observation.branch === v.intent.expectedRef;
  }
  return v.reason !== 'unknown' && (isGitFastForwardReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason)) &&
    v.observation === null && (v.state === 'recovery-required' ? v.intent !== null :
      v.state === 'failed' && v.effectPhase === 'not-published' && v.retainedPaths.length === 0);
}
const HELP: Readonly<Record<typeof GIT_FAST_FORWARD_REASONS[number] | 'ff-observation-required', string>> = Object.freeze({
  'ff-observation-required': 'Refresh changes to read this branch’s cached upstream. A historical summary or local branch list cannot authorize this update.',
  'ff-target': 'This update needs a current local branch and its configured, already-fetched tracking tip. It never fetches or selects another remote.',
  'ff-not-descendant': 'The cached tip is not a complete, strictly ahead history within this check. Nothing is merged, rebased, reset or forced; use your Git client.',
  'ff-layout': 'This bounded update requires a clean regular checkout, loose branch and tracking refs, existing log folders, the same file names and modes, and at most 8 changed files. Use your Git client for other layouts.',
  'ff-log-limit': 'A required Git log exceeds this bounded update. The app will not truncate it; use your Git client.',
});
export function gitFastForwardIssueHelp(issue: string): string | null {
  return Object.hasOwn(HELP, issue) ? HELP[issue as keyof typeof HELP] : null;
}
export const GIT_FAST_FORWARD_EFFECT_LABELS: Readonly<Record<GitFastForwardEffect, string>> = Object.freeze({
  'not-published': 'No completed publication was reported; this does not prove no files changed',
  'worktree-returned': 'The reviewed working-file changes returned', 'index-returned': 'Working-file and exact index publication returned',
  'ref-returned': 'Working-file, index and original branch/log publication returned',
});
