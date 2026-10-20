// Closed display/correlation DATA for the original GitLocal owner. Absence,
// source custody, authorization and cleanup remain native—not inferred here.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { GIT_REASONS } from './gitRepositoryProtocol.ts';
import type { GitReason } from './gitRepositoryProtocol.ts';

export const GIT_INIT_REASONS = ['git-already-present', 'git-init-layout', 'git-init-candidate'] as const;
export type GitInitReason = typeof GIT_INIT_REASONS[number];
export interface GitInitAction { readonly kind: 'initialize' }
export interface GitInitReview { readonly action: 'initialize'; readonly expectedRevision: string;
  readonly initialBranch: 'main'; readonly objectFormat: 'sha1'; readonly reviewDigest: string }
export interface GitInitIntent { readonly action: 'initialize'; readonly expectedRevision: string;
  readonly initialBranch: 'main'; readonly objectFormat: 'sha1'; readonly candidateManifest: string;
  readonly candidateHead: string; readonly candidateConfig: string }
export interface GitInitMutationResult { readonly operationId: string; readonly action: 'initialize';
  readonly state: 'succeeded' | 'failed' | 'recovery-required'; readonly settlement: 'settled';
  readonly reason: GitReason | GitInitReason | null; readonly observation: null; readonly intent: GitInitIntent | null }

const HEAD = '28d25bf82af4c0e2b72f50959b2beb859e3e60b9630a5e8c603dad4ddb2b6e80';
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
export function isGitInitAction(v: unknown): v is GitInitAction {
  return connectionBounded(v, 128, 4, 1) && connectionKeys(v, ['kind']) && v.kind === 'initialize';
}
export function isGitInitReason(v: unknown): v is GitInitReason { return typeof v === 'string' && GIT_INIT_REASONS.includes(v as GitInitReason); }
export function isGitInitReview(v: unknown, expected: GitInitAction): v is GitInitReview {
  return isGitInitAction(expected) && connectionBounded(v, 1024, 16, 1) &&
    connectionKeys(v, ['action', 'expectedRevision', 'initialBranch', 'objectFormat', 'reviewDigest']) &&
    v.action === 'initialize' && digest(v.expectedRevision) && v.initialBranch === 'main' && v.objectFormat === 'sha1' && digest(v.reviewDigest);
}
export function isGitInitIntent(v: unknown, expected: GitInitAction): v is GitInitIntent {
  return isGitInitAction(expected) && connectionBounded(v, 2048, 20, 1) &&
    connectionKeys(v, ['action', 'expectedRevision', 'initialBranch', 'objectFormat', 'candidateManifest', 'candidateHead', 'candidateConfig']) &&
    v.action === 'initialize' && digest(v.expectedRevision) && v.initialBranch === 'main' && v.objectFormat === 'sha1' &&
    digest(v.candidateManifest) && v.candidateHead === HEAD && digest(v.candidateConfig);
}
export function initIntentMatchesReview(v: GitInitIntent, r: GitInitReview): boolean {
  return v.expectedRevision === r.expectedRevision && v.initialBranch === r.initialBranch && v.objectFormat === r.objectFormat;
}
export function isGitInitMutation(v: unknown, expected: GitInitAction, operationId: string): v is GitInitMutationResult {
  if (!isGitInitAction(expected) || !connectionBounded(v, 4096, 40, 2) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent']) ||
      v.operationId !== operationId || v.action !== 'initialize' || v.settlement !== 'settled' || v.observation !== null ||
      !(v.intent === null || isGitInitIntent(v.intent, expected))) return false;
  if (v.state === 'succeeded') return v.reason === null && v.intent !== null;
  return (v.state === 'failed' || v.state === 'recovery-required') && v.reason !== 'unknown' &&
    (isGitInitReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason));
}
const HELP: Readonly<Record<GitInitReason, string>> = Object.freeze({
  'git-already-present': 'This folder already has Git metadata or is inside another repository. Refresh local changes or use your Git client; initialization never replaces an existing repository.',
  'git-init-layout': 'This folder layout cannot be initialized safely here. Use your Git client for nested repositories, worktrees, submodules or unusual metadata. Your project files are not rewritten.',
  'git-init-candidate': 'The new Git metadata did not match this bounded setup. Keep the original task and any retained metadata; do not delete folders or repeat an unconfirmed initialization.',
});
export function gitInitIssueHelp(issue: string): string | null { return Object.hasOwn(HELP, issue) ? HELP[issue as GitInitReason] : null; }
