// Closed display DATA for git_service/GitCommands. No process, invoke, token,
// filesystem, policy implementation or native qualification lives here.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';

export const GIT_REASONS = ['invalid-input', 'not-repository', 'unsupported-repository', 'unsupported-path',
  'unsupported-filter', 'required-hooks', 'required-signing', 'conflicts', 'nothing-staged', 'sensitive-content',
  'stale-observation', 'locked', 'authorization', 'deadline', 'limit', 'command-failed', 'response-invalid',
  'recovery-required', 'unknown', 'already-used', 'operation-in-progress'] as const;
export type GitReason = typeof GIT_REASONS[number];
export type GitAction = 'stage' | 'unstage' | 'commit';
export type GitIssue = GitReason | 'unavailable' | 'inactive' | 'busy' | 'no-observation' | 'no-selection' |
  'selection-changed' | 'review-first' | 'review-changed' | 'draft-incomplete' | 'acknowledgement-missing';
export const GIT_ISSUE_HELP: Readonly<Record<GitIssue, string>> = Object.freeze({
  'invalid-input': 'Check the selected files and commit details, then make a new review.',
  'not-repository': 'This project is not a supported Git working folder.',
  'unsupported-repository': 'This repository setup is not supported by these safe Git actions. Use your Git client instead.',
  'unsupported-path': 'One selected entry is unsupported. Links, nested repositories and submodules need your Git client.',
  'unsupported-filter': 'This repository uses a Git filter. MRK will not run it or bypass its requirements.',
  'required-hooks': 'This repository requires Git hooks. Use your Git client; MRK will not bypass them.',
  'required-signing': 'This repository requires signed commits. Use your configured Git client to commit.',
  conflicts: 'Resolve Git conflicts in your editor or Git client, then refresh.',
  'nothing-staged': 'Stage the files you want to commit first.',
  'sensitive-content': 'Potential credential content was withheld. Review it privately; do not paste it here.',
  'stale-observation': 'The repository changed. Refresh and make a new review; your commit draft is kept.',
  locked: 'Another Git operation holds the repository. Wait for it; do not delete its lock files.',
  authorization: 'The original project session no longer permits this action. Reopen it through the application.',
  deadline: 'The bounded Git operation reached its time limit. Check its original status before continuing.',
  limit: 'This action exceeds a safe size limit. Select fewer files or use your Git client.',
  'command-failed': 'Git did not complete this action. No raw command output is displayed.',
  'response-invalid': 'The original response could not be verified. Keep its state; do not repeat the action.',
  'recovery-required': 'The operation needs recovery. Keep its original state; do not retry or remove locks.',
  unknown: 'The original outcome or cleanup is unknown. Keep its state; a refresh cannot authorize another write.',
  'already-used': 'This review has already been submitted. Check its original outcome instead of sending it again.',
  'operation-in-progress': 'A merge, rebase or similar Git operation is in progress. Finish it in your Git client, then refresh.',
  unavailable: 'Local Git actions are not available in this application session.',
  inactive: 'Return to this project before starting a new Git action.',
  busy: 'Wait for the current Git request to finish.',
  'no-observation': 'Refresh this project’s changes first.',
  'no-selection': 'Select only the files you want to stage or unstage.',
  'selection-changed': 'A selected file is no longer in this list. Clear the selection and choose again.',
  'review-first': 'Prepare a review before applying any change.',
  'review-changed': 'This review is no longer current. Close it and prepare a new one; your draft is kept.',
  'draft-incomplete': 'Enter a commit message, author name and author email.',
  'acknowledgement-missing': 'No conclusive reply arrived. Check the original operation; do not submit it again.',
});

export interface GitChange {
  readonly path: string; readonly index: string; readonly worktree: string;
  readonly kind: 'absent' | 'file' | 'symlink' | 'directory' | 'other' | 'submodule'; readonly conflict: boolean;
}
export interface GitObservation {
  readonly revision: string; readonly head: string | null; readonly branch: string | null;
  readonly unborn: boolean; readonly detached: boolean; readonly changes: readonly GitChange[];
  readonly remotes: readonly string[]; readonly restrictions: readonly GitReason[];
}
export interface GitDiff {
  readonly revision: string; readonly staged: boolean; readonly paths: readonly string[];
  readonly text: string | null; readonly withheld: 'sensitive-content' | 'untracked' | 'non-text' | null;
}
export interface GitPlan {
  readonly planId: string; readonly action: GitAction; readonly expectedRevision: string;
  readonly paths: readonly string[]; readonly wholeIndex: boolean;
  readonly head: string | null; readonly branch: string | null;
}
export interface GitIntent {
  readonly action: GitAction; readonly expectedRevision: string; readonly expectedRef: string | null;
  readonly expectedHead: string | null; readonly expectedIndex: string;
  readonly candidateIndex: string | null; readonly candidateCommit: string | null;
}
export interface GitMutationResult {
  readonly operationId: string; readonly action: GitAction;
  readonly state: 'succeeded' | 'failed' | 'recovery-required' | 'unknown';
  readonly settlement: 'settled' | 'unknown'; readonly reason: GitReason | null;
  readonly observation: GitObservation | null; readonly intent: GitIntent | null;
}
// Root's original native adapter adds this envelope AFTER checking its original
// owner. A core result or current ref/index read is not native settlement. These
// strings are presentation only, never an authorization/custody replacement.
export interface GitApplyReceipt {
  readonly planId: string; readonly nativeFinality: 'pending' | 'settled' | 'unknown';
  readonly result: GitMutationResult | null;
}
export interface GitCommitDraft {
  readonly message: string; readonly authorName: string; readonly authorEmail: string;
}

const encoder = new TextEncoder();
const exact = (expression: RegExp, value: unknown): value is string => typeof value === 'string' && expression.test(value);
const digest = (value: unknown): value is string => exact(/^[a-f0-9]{64}$(?![\s\S])/, value);
const oid = (value: unknown): value is string => exact(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/, value);
const action = (value: unknown): value is GitAction => value === 'stage' || value === 'unstage' || value === 'commit';
const reason = (value: unknown): value is GitReason => typeof value === 'string' && GIT_REASONS.includes(value as GitReason);
function text(value: unknown, bytes: number, multiline = false): value is string {
  return typeof value === 'string' && value.length <= bytes && !/\p{Cs}/u.test(value) &&
    !(multiline ? /[\x00-\x08\x0b-\x1f\x7f]/ : /[\x00-\x1f\x7f]/).test(value) && encoder.encode(value).byteLength <= bytes;
}
function path(value: unknown): value is string {
  return text(value, 1024) && !value.includes('\\') && value.split('/').every((part) =>
    part !== '' && part !== '.' && part !== '..' && part !== '.git' && encoder.encode(part).byteLength <= 255);
}
function branch(value: unknown): value is string {
  return text(value, 1024) && value.startsWith('refs/heads/') && !/[\x00-\x20\x7f~^:?*\[\\]/.test(value) &&
    !value.includes('..') && !value.includes('@{') && value.split('/').every((part) =>
      part !== '' && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
}
function paths(value: unknown, limit: number): value is string[] {
  return Array.isArray(value) && value.length > 0 && value.length <= limit && value.every(path) && new Set(value).size === value.length;
}
const planId = (value: unknown): value is string => exact(/^git-plan-[a-f0-9]{32}$(?![\s\S])/, value);
const nullable = (value: unknown, check: (v: unknown) => boolean): boolean => value === null || check(value);

// Copy once after bounded admission so a caller cannot mutate a retained review
// through the input object. The parsed graph is finite, plain, accessor-free DATA.
function immutable<T>(value: unknown): T {
  const copy: unknown = structuredClone(value);
  const freeze = (item: unknown): void => {
    if (item !== null && typeof item === 'object') { Object.values(item).forEach(freeze); Object.freeze(item); }
  };
  freeze(copy); return copy as T;
}
function observation(value: unknown): boolean {
  if (!connectionKeys(value, ['revision', 'head', 'branch', 'unborn', 'detached', 'changes', 'remotes', 'restrictions']) ||
      !digest(value.revision) || !nullable(value.head, oid) || !nullable(value.branch, branch) ||
      value.unborn !== (value.head === null) || value.detached !== (value.branch === null) ||
      value.head === null && value.branch === null || !Array.isArray(value.changes) || value.changes.length > 512 ||
      !Array.isArray(value.remotes) || value.remotes.length > 4096 || !value.remotes.every((v) => text(v, 128) && v.length > 0) ||
      new Set(value.remotes).size !== value.remotes.length || !Array.isArray(value.restrictions) ||
      !value.restrictions.every(reason) || new Set(value.restrictions).size !== value.restrictions.length) return false;
  const names = new Set<string>();
  return value.changes.every((row) => {
    if (!connectionKeys(row, ['path', 'index', 'worktree', 'kind', 'conflict']) || !path(row.path) || names.has(row.path) ||
        typeof row.index !== 'string' || row.index.length !== 1 || !' MTADRCU?!'.includes(row.index) ||
        typeof row.worktree !== 'string' || row.worktree.length !== 1 || !' MTADRCU?!'.includes(row.worktree) ||
        typeof row.kind !== 'string' || !['absent', 'file', 'symlink', 'directory', 'other', 'submodule'].includes(row.kind) ||
        row.conflict !== ['DD', 'AU', 'UD', 'UA', 'DU', 'AA', 'UU'].includes(row.index + row.worktree)) return false;
    names.add(row.path); return true;
  });
}
export function parseGitObservation(value: unknown): GitObservation | null {
  try { return connectionBounded(value, 1024 * 1024, 20000, 8) && observation(value) ? immutable(value) : null; } catch { return null; }
}
export function parseGitDiff(value: unknown): GitDiff | null {
  try {
    if (!connectionBounded(value, 1024 * 1024, 1000, 4) || !connectionKeys(value, ['revision', 'staged', 'paths', 'text', 'withheld']) ||
        !digest(value.revision) || typeof value.staged !== 'boolean' || !paths(value.paths, 64)) return null;
    if (value.withheld === null) {
      if (typeof value.text !== 'string' || encoder.encode(value.text).byteLength > 256 * 1024 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value.text)) return null;
    } else if (value.text !== null || typeof value.withheld !== 'string' || !['sensitive-content', 'untracked', 'non-text'].includes(value.withheld)) return null;
    return immutable(value);
  } catch { return null; }
}
export function parseGitPlan(value: unknown): GitPlan | null {
  try {
    return connectionBounded(value, 96 * 1024, 1000, 4) &&
      connectionKeys(value, ['planId', 'action', 'expectedRevision', 'paths', 'wholeIndex', 'head', 'branch']) &&
      planId(value.planId) && action(value.action) && digest(value.expectedRevision) && paths(value.paths, 64) &&
      value.wholeIndex === (value.action === 'commit') && nullable(value.head, oid) && nullable(value.branch, branch) &&
      !(value.head === null && value.branch === null) && (value.action !== 'commit' || value.branch !== null) ? immutable(value) : null;
  } catch { return null; }
}
function intent(value: unknown): boolean {
  if (!connectionKeys(value, ['action', 'expectedRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'candidateIndex', 'candidateCommit']) ||
      !action(value.action) || !digest(value.expectedRevision) || !nullable(value.expectedRef, branch) ||
      !nullable(value.expectedHead, oid) || !digest(value.expectedIndex)) return false;
  return value.action === 'commit' ? value.expectedRef !== null && value.candidateIndex === null && oid(value.candidateCommit) &&
    (value.expectedHead === null || String(value.expectedHead).length === value.candidateCommit.length) :
    digest(value.candidateIndex) && value.candidateCommit === null;
}
function mutation(value: unknown): boolean {
  if (!connectionKeys(value, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent']) ||
      !text(value.operationId, 128) || !value.operationId || !action(value.action) || !nullable(value.reason, reason) ||
      !nullable(value.observation, observation) || !nullable(value.intent, intent) ||
      value.intent !== null && (value.intent as Record<string, unknown>).action !== value.action) return false;
  if (value.state === 'unknown') return value.settlement === 'unknown' && value.reason === 'unknown' && value.observation === null;
  if (value.settlement !== 'settled') return false;
  if (value.state === 'succeeded') return value.reason === null && value.observation !== null && value.intent !== null;
  return (value.state === 'failed' || value.state === 'recovery-required') && value.reason !== null && value.reason !== 'unknown' &&
    value.observation === null && (value.state !== 'failed' || value.intent === null);
}
export function parseGitApplyReceipt(value: unknown): GitApplyReceipt | null {
  try {
    return connectionBounded(value, 1024 * 1024, 21000, 10) && connectionKeys(value, ['planId', 'nativeFinality', 'result']) &&
      planId(value.planId) && typeof value.nativeFinality === 'string' && ['pending', 'settled', 'unknown'].includes(value.nativeFinality) && nullable(value.result, mutation) &&
      (value.nativeFinality !== 'settled' || value.result !== null) ? immutable(value) : null;
  } catch { return null; }
}
// Only an exact native-owned failure envelope distinguishes a settled refusal
// from a lost reply. Never expose rejection text or accept a generic retry flag.
export function parseGitFailure(value: unknown): { reason: GitReason; nativeFinality: 'settled' | 'unknown' } | null {
  try {
    return connectionBounded(value, 512, 10, 2) && connectionKeys(value, ['reason', 'nativeFinality']) &&
      reason(value.reason) && (value.nativeFinality === 'settled' || value.nativeFinality === 'unknown') ? immutable(value) : null;
  } catch { return null; }
}
export function gitDiscardAcknowledged(value: unknown): boolean {
  try { return connectionBounded(value, 64, 4, 2) && connectionKeys(value, ['discarded']) && value.discarded === true; } catch { return false; }
}
export function gitSamePaths(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((item) => b.includes(item));
}
export function gitStagedPaths(value: GitObservation): readonly string[] {
  return value.changes.filter((row) => ![' ', '?', '!'].includes(row.index)).map((row) => row.path);
}
export function gitDraftFieldFits(field: keyof GitCommitDraft, value: unknown): value is string {
  return text(value, field === 'message' ? 4096 : field === 'authorName' ? 128 : 254, field === 'message');
}
