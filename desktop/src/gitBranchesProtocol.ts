// Branch-only comparison DATA. The existing GitRead/GitLocal owners perform
// admission, repository policy checks, publication and all actual settlement.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { GIT_ISSUE_HELP, GIT_REASONS, parseGitObservation } from './gitRepositoryProtocol.ts';
import type { GitIssue, GitObservation, GitReason } from './gitRepositoryProtocol.ts';

export const GIT_BRANCH_REASONS = ['branch-exists', 'branch-parent-missing', 'branch-identity-required', 'unborn-head'] as const;
export type GitBranchReason = typeof GIT_BRANCH_REASONS[number];
export type GitBranchIssue = GitBranchReason | 'branch-list-required' | 'branch-name-required';
export interface GitBranches { readonly revision: string; readonly referenceRevision: string; readonly head: string | null;
  readonly branch: string | null; readonly branches: readonly { readonly ref: string; readonly oid: string }[]; readonly basis: 'local-refs-no-fetch' }
export interface GitBranchAction { readonly kind: 'branch-create'; readonly expectedRevision: string;
  readonly expectedReferenceRevision: string; readonly name: string }
export interface GitBranchReview { readonly action: 'branch-create'; readonly name: string; readonly targetRef: string;
  readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly head: string; readonly branch: string | null;
  readonly expectedIndex: string; readonly reviewDigest: string }
export interface GitBranchIntent { readonly action: 'branch-create'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly expectedRef: string | null; readonly expectedHead: string; readonly expectedIndex: string; readonly targetRef: string;
  readonly expectedTargetAbsent: true; readonly candidateRefOid: string }
export interface GitBranchMutationResult { readonly operationId: string; readonly action: 'branch-create';
  readonly state: 'succeeded' | 'failed' | 'recovery-required'; readonly settlement: 'settled'; readonly reason: GitReason | GitBranchReason | null;
  readonly observation: GitObservation | null; readonly intent: GitBranchIntent | null }

const utf8 = new TextEncoder();
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/.test(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max && utf8.encode(v).length <= max && !/[\x00-\x1f\x7f\p{Cs}]/u.test(v);
function ref(v: unknown): v is string {
  return text(v, 1024) && v.startsWith('refs/heads/') && !/[\x00-\x20\x7f~^:?*\[\\]/.test(v) && !v.includes('..') && !v.includes('@{') &&
    v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
// Same UTF-8 scalar order as the core and native String; never locale order.
function ordered(a: string, b: string): boolean {
  const left = utf8.encode(a), right = utf8.encode(b);
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) if (left[i] !== right[i]) return left[i]! < right[i]!;
  return left.length < right.length;
}
export function gitBranchName(v: unknown): v is string {
  return typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$(?![\s\S])/.test(v) && v.split('/').length <= 16 && ref(`refs/heads/${v}`);
}
// Incomplete names remain local drafts; they are not admitted actions.
export function gitBranchDraftFits(v: unknown): v is string { return text(v, 255); }
export function isGitBranchReason(v: unknown): v is GitBranchReason { return typeof v === 'string' && GIT_BRANCH_REASONS.includes(v as GitBranchReason); }
export function isGitBranchAction(v: unknown): v is GitBranchAction {
  return connectionBounded(v, 2048, 32, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'name']) &&
    v.kind === 'branch-create' && digest(v.expectedRevision) && digest(v.expectedReferenceRevision) && gitBranchName(v.name);
}
export function isGitBranches(v: unknown, expectedRevision: string | null): v is GitBranches {
  if (!connectionBounded(v, 384 * 1024, 4096, 4) || !connectionKeys(v, ['revision', 'referenceRevision', 'head', 'branch', 'branches', 'basis']) ||
      !digest(expectedRevision) || v.revision !== expectedRevision || !digest(v.referenceRevision) || v.basis !== 'local-refs-no-fetch' ||
      !(v.head === null || oid(v.head)) || !(v.branch === null || ref(v.branch)) || v.head === null && v.branch === null ||
      !Array.isArray(v.branches) || v.branches.length > 256) return false;
  let previous: string | null = null, width: number | null = typeof v.head === 'string' ? v.head.length : null, current: string | null = null;
  for (const row of v.branches) {
    if (!connectionKeys(row, ['ref', 'oid']) || !ref(row.ref) || row.ref.split('/').length > 32 || !oid(row.oid) ||
        previous !== null && !ordered(previous, row.ref) || width !== null && width !== row.oid.length) return false;
    previous = row.ref; width = row.oid.length;
    if (row.ref === v.branch) current = row.oid;
  }
  return v.branch === null || current === v.head;
}
export function isGitBranchReview(v: unknown, expected: GitBranchAction): v is GitBranchReview {
  return isGitBranchAction(expected) && connectionBounded(v, 4096, 64, 2) && connectionKeys(v, ['action', 'name', 'targetRef', 'expectedRevision', 'expectedReferenceRevision', 'head', 'branch', 'expectedIndex', 'reviewDigest']) &&
    v.action === 'branch-create' && v.name === expected.name && v.targetRef === `refs/heads/${expected.name}` && v.expectedRevision === expected.expectedRevision &&
    v.expectedReferenceRevision === expected.expectedReferenceRevision && oid(v.head) && (v.branch === null || ref(v.branch)) && v.branch !== v.targetRef &&
    digest(v.expectedIndex) && digest(v.reviewDigest);
}
export function isGitBranchIntent(v: unknown, expected: GitBranchAction): v is GitBranchIntent {
  return isGitBranchAction(expected) && connectionBounded(v, 4096, 64, 2) && connectionKeys(v, ['action', 'expectedRevision', 'expectedReferenceRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'targetRef', 'expectedTargetAbsent', 'candidateRefOid']) &&
    v.action === 'branch-create' && v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision &&
    v.targetRef === `refs/heads/${expected.name}` && v.expectedTargetAbsent === true && oid(v.expectedHead) && v.candidateRefOid === v.expectedHead &&
    (v.expectedRef === null || ref(v.expectedRef)) && v.expectedRef !== v.targetRef && digest(v.expectedIndex);
}
export function branchIntentMatchesReview(v: GitBranchIntent, r: GitBranchReview): boolean {
  return v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision && v.expectedRef === r.branch &&
    v.expectedHead === r.head && v.expectedIndex === r.expectedIndex && v.targetRef === r.targetRef && v.expectedTargetAbsent && v.candidateRefOid === r.head;
}
export function isGitBranchMutation(v: unknown, expected: GitBranchAction, operationId: string): v is GitBranchMutationResult {
  if (!connectionBounded(v, 2 * 1024 * 1024, 25000, 10) || !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent']) ||
      v.operationId !== operationId || v.action !== 'branch-create' || v.settlement !== 'settled' || !(v.intent === null || isGitBranchIntent(v.intent, expected))) return false;
  if (v.state === 'succeeded') {
    const observation = parseGitObservation(v.observation);
    return v.reason === null && v.intent !== null && !!observation && observation.head === v.intent.expectedHead && observation.branch === v.intent.expectedRef;
  }
  return (v.state === 'failed' || v.state === 'recovery-required') && v.reason !== 'unknown' && v.observation === null &&
    (isGitBranchReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason));
}

const HELP: Readonly<Record<GitBranchIssue, string>> = Object.freeze({
  'branch-exists': 'That branch name or a conflicting name already exists. Nothing is overwritten; choose another name and read local branches again.',
  'branch-parent-missing': 'Use a top-level branch name or a namespace already created by your Git client. This action will not create missing reference or log folders.',
  'branch-identity-required': 'Set a repository-local user.name and user.email with your Git client, then refresh and review again. The app will not invent an identity or disable the branch log.',
  'unborn-head': 'Create the first local commit before creating another branch.',
  'branch-list-required': 'Read local branches for the current changes first. A cached list from another project or observation cannot be used.',
  'branch-name-required': 'Enter a new branch name using letters, numbers, dots, hyphens, underscores or slashes; start with a letter or number.',
});
export function gitLocalIssueHelp(issue: GitIssue | GitBranchIssue): string {
  return Object.hasOwn(HELP, issue) ? HELP[issue as GitBranchIssue] : GIT_ISSUE_HELP[issue as GitIssue];
}
