// Finite display/correlation DATA only; not source, consent or native finality.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { gitBranchName } from './gitBranchesProtocol.ts';
import { GIT_REASONS, parseGitObservation } from './gitRepositoryProtocol.ts';
import type { GitObservation, GitReason } from './gitRepositoryProtocol.ts';

export const GIT_RENAME_REASONS = ['rename-layout', 'rename-target', 'rename-config', 'rename-log', 'rename-log-missing',
  'rename-identity-required', 'rename-packed'] as const;
export type GitRenameReason = typeof GIT_RENAME_REASONS[number];
export type GitRenameIssue = GitRenameReason | 'rename-name-required';
export interface GitRenameAction { readonly kind: 'branch-rename'; readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly name: string }
export interface GitRenameReview { readonly action: 'branch-rename'; readonly name: string; readonly targetRef: string;
  readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly head: string; readonly branch: string;
  readonly expectedIndex: string; readonly configMoved: boolean; readonly logging: boolean; readonly originalConfig: string;
  readonly originalLog: string; readonly originalHeadLog: string; readonly reviewDigest: string }
export interface GitRenameIntent { readonly action: 'branch-rename'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly expectedRef: string; readonly expectedHead: string; readonly expectedIndex: string; readonly targetRef: string; readonly expectedTargetAbsent: true;
  readonly originalConfig: string; readonly candidateConfig: string; readonly originalLog: string; readonly candidateLog: string;
  readonly originalHeadLog: string; readonly candidateHeadLog: string; readonly configMoved: boolean; readonly logging: boolean }
export type GitRenameEffect = 'not-published' | 'new-log-returned' | 'old-log-returned' | 'ref-returned' | 'head-log-returned' | 'head-returned' | 'config-returned';
export interface GitRenameMutationResult { readonly operationId: string; readonly action: 'branch-rename'; readonly state: 'succeeded' | 'failed' | 'recovery-required';
  readonly settlement: 'settled'; readonly reason: GitReason | GitRenameReason | null; readonly observation: GitObservation | null;
  readonly intent: GitRenameIntent | null; readonly effectPhase: GitRenameEffect; readonly retainedPaths: readonly string[] }

const ABSENT = '5ad38304b535c2987dbd24657c1a11b884984ff600d9f389deb0d4e634fee792';
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/.test(v);
const reference = (v: unknown): v is string => typeof v === 'string' && v.startsWith('refs/heads/') && gitBranchName(v.slice('refs/heads/'.length));
export function sameRenameParent(old: unknown, next: unknown): boolean {
  return reference(old) && reference(next) && old.toLowerCase() !== next.toLowerCase() && old.slice(0, old.lastIndexOf('/')) === next.slice(0, next.lastIndexOf('/'));
}
function logHashes(logging: boolean, a: unknown, b: unknown): boolean { return digest(a) && digest(b) && (logging || a === ABSENT && b === ABSENT); }
export function isGitRenameReason(v: unknown): v is GitRenameReason { return typeof v === 'string' && GIT_RENAME_REASONS.includes(v as GitRenameReason); }
export function isGitRenameAction(v: unknown): v is GitRenameAction {
  return connectionBounded(v, 2048, 32, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'name']) &&
    v.kind === 'branch-rename' && digest(v.expectedRevision) && digest(v.expectedReferenceRevision) && gitBranchName(v.name);
}
export function isGitRenameReview(v: unknown, expected: GitRenameAction): v is GitRenameReview {
  return isGitRenameAction(expected) && connectionBounded(v, 8192, 64, 2) && connectionKeys(v, ['action', 'name', 'targetRef', 'expectedRevision',
    'expectedReferenceRevision', 'head', 'branch', 'expectedIndex', 'configMoved', 'logging', 'originalConfig', 'originalLog', 'originalHeadLog', 'reviewDigest']) &&
    v.action === 'branch-rename' && v.name === expected.name && v.targetRef === `refs/heads/${expected.name}` && sameRenameParent(v.branch, v.targetRef) &&
    v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision && oid(v.head) &&
    digest(v.expectedIndex) && digest(v.reviewDigest) && digest(v.originalConfig) && typeof v.configMoved === 'boolean' && typeof v.logging === 'boolean' &&
    logHashes(v.logging, v.originalLog, v.originalHeadLog);
}
export function isGitRenameIntent(v: unknown, expected: GitRenameAction): v is GitRenameIntent {
  return isGitRenameAction(expected) && connectionBounded(v, 8192, 64, 2) && connectionKeys(v, ['action', 'expectedRevision', 'expectedReferenceRevision',
    'expectedRef', 'expectedHead', 'expectedIndex', 'targetRef', 'expectedTargetAbsent', 'originalConfig', 'candidateConfig', 'originalLog', 'candidateLog',
    'originalHeadLog', 'candidateHeadLog', 'configMoved', 'logging']) && v.action === 'branch-rename' && v.expectedRevision === expected.expectedRevision &&
    v.expectedReferenceRevision === expected.expectedReferenceRevision && v.targetRef === `refs/heads/${expected.name}` && sameRenameParent(v.expectedRef, v.targetRef) &&
    oid(v.expectedHead) && digest(v.expectedIndex) && v.expectedTargetAbsent === true && digest(v.originalConfig) && digest(v.candidateConfig) &&
    typeof v.configMoved === 'boolean' && (v.configMoved || v.originalConfig === v.candidateConfig) && typeof v.logging === 'boolean' &&
    logHashes(v.logging, v.originalLog, v.originalHeadLog) && logHashes(v.logging, v.candidateLog, v.candidateHeadLog);
}
export function renameIntentMatchesReview(v: GitRenameIntent, r: GitRenameReview): boolean {
  return v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision && v.expectedRef === r.branch &&
    v.expectedHead === r.head && v.expectedIndex === r.expectedIndex && v.targetRef === r.targetRef && v.originalConfig === r.originalConfig &&
    v.originalLog === r.originalLog && v.originalHeadLog === r.originalHeadLog && v.configMoved === r.configMoved && v.logging === r.logging;
}
function phases(i: GitRenameIntent): readonly string[] { return [...(i.logging ? ['new-log-returned', 'old-log-returned'] : []), 'ref-returned',
  ...(i.logging ? ['head-log-returned'] : []), 'head-returned', ...(i.configMoved ? ['config-returned'] : [])]; }
export function isGitRenameMutation(v: unknown, expected: GitRenameAction, operationId: string): v is GitRenameMutationResult {
  if (!isGitRenameAction(expected) || !connectionBounded(v, 2 * 1024 * 1024, 25000, 10) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths']) ||
      v.operationId !== operationId || v.action !== 'branch-rename' || v.settlement !== 'settled' || !(v.intent === null || isGitRenameIntent(v.intent, expected)) ||
      !Array.isArray(v.retainedPaths) || v.retainedPaths.length > 1 || !v.retainedPaths.every((p) => typeof p === 'string' &&
        /^\.git\/mrk-git-[A-Za-z0-9_-]{1,64}\/index$(?![\s\S])/.test(p)) ||
      !(v.effectPhase === 'not-published' || v.intent && phases(v.intent).includes(v.effectPhase as string))) return false;
  if (v.state === 'succeeded') {
    const observation = parseGitObservation(v.observation);
    return v.intent !== null && v.reason === null && v.effectPhase === (v.intent.configMoved ? 'config-returned' : 'head-returned') &&
      v.retainedPaths.length === 0 && !!observation && observation.branch === v.intent.targetRef && observation.head === v.intent.expectedHead;
  }
  return v.reason !== 'unknown' && (isGitRenameReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason)) &&
    v.observation === null && (v.state === 'recovery-required' ? v.intent !== null :
      v.state === 'failed' && v.effectPhase === 'not-published' && v.retainedPaths.length === 0);
}
const HELP: Readonly<Record<GitRenameIssue, string>> = Object.freeze({
  'rename-name-required': 'Enter a new name for the current local branch, then review it. Typing a name changes nothing.',
  'rename-target': 'Use a different, unused name in the same branch folder (for example feature/old → feature/new). Refresh changes and branches first. Existing or case-conflicting names are never replaced.',
  'rename-layout': 'This rename supports a regular checkout on an attached branch with a commit and a small existing index. Use your Git client for other layouts; no reset or permission changes are attempted.',
  'rename-config': 'The local branch settings are ambiguous or outside this bounded editor. Use your Git client. The app will not discard upstream settings, comments or unrelated configuration.',
  'rename-log': 'The existing branch logs cannot be preserved by this bounded rename. Use your Git client; the app will not truncate or rebuild them.',
  'rename-log-missing': 'The branch and HEAD logs do not match the repository’s logging policy. Use your Git client; the app will not assume a missing log is safe to replace.',
  'rename-identity-required': 'Set repository-local user.name and user.email in your Git client, then refresh and review again. The app will not invent a name for the rename log.',
  'rename-packed': 'The selected branch has a packed reference as well as a loose reference. Rename it in your Git client; the app will not rewrite packed references.',
});
export function gitRenameIssueHelp(issue: string): string | null { return Object.hasOwn(HELP, issue) ? HELP[issue as GitRenameIssue] : null; }
export const GIT_RENAME_EFFECT_LABELS: Readonly<Record<GitRenameEffect, string>> = Object.freeze({
  'not-published': 'No completed publication was reported; this does not prove nothing changed',
  'new-log-returned': 'New branch log published', 'old-log-returned': 'Old branch log retired', 'ref-returned': 'Local reference moved',
  'head-log-returned': 'HEAD log updated', 'head-returned': 'Current branch name updated', 'config-returned': 'Branch settings moved with values preserved',
});
