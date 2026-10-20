import { fastForwardIntentMatchesReview, gitFastForwardIssueHelp, isGitFastForwardAction, isGitFastForwardIntent, isGitFastForwardMutation, isGitFastForwardReason, isGitFastForwardReview } from './gitFastForwardProtocol.ts';
import type { GitFastForwardAction, GitFastForwardReview, GitFastForwardIntent, GitFastForwardMutationResult, GitFastForwardReason, GitFastForwardIssue } from './gitFastForwardProtocol.ts';
// Closed DATA for the original GitLocal native owner. No command line, tool
// path, remote transport, serialized plan capability or availability override.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { GIT_REASONS, parseGitDiff, parseGitObservation } from './gitRepositoryProtocol.ts';
import { gitReadPathOrder } from './gitReadProtocol.ts';
import { branchIntentMatchesReview, gitLocalIssueHelp as previousIssueHelp, isGitBranchAction, isGitBranchIntent, isGitBranchMutation, isGitBranchReason, isGitBranchReview } from './gitBranchesProtocol.ts';
import type { GitBranchAction, GitBranchIntent, GitBranchIssue, GitBranchMutationResult, GitBranchReason, GitBranchReview } from './gitBranchesProtocol.ts';
import { gitSwitchIssueHelp, isGitSwitchAction, isGitSwitchIntent, isGitSwitchMutation, isGitSwitchReason, isGitSwitchReview, switchIntentMatchesReview } from './gitSwitchProtocol.ts';
import type { GitSwitchAction, GitSwitchIntent, GitSwitchIssue, GitSwitchMutationResult, GitSwitchReason, GitSwitchReview } from './gitSwitchProtocol.ts';
import { gitRenameIssueHelp, isGitRenameAction, isGitRenameReview, isGitRenameIntent, isGitRenameMutation, isGitRenameReason, renameIntentMatchesReview } from './gitRenameProtocol.ts';
import type { GitRenameAction, GitRenameReview, GitRenameIntent, GitRenameMutationResult, GitRenameReason, GitRenameIssue } from './gitRenameProtocol.ts';
import type { GitAction, GitDiff, GitIntent, GitMutationResult, GitReason, GitIssue } from './gitRepositoryProtocol.ts';
import type { GitReadContext } from './gitReadProtocol.ts';
import { isGitInitAction, isGitInitReview, isGitInitIntent, isGitInitMutation, isGitInitReason, initIntentMatchesReview, gitInitIssueHelp } from './gitInitProtocol.ts';
import type { GitInitAction, GitInitReview, GitInitIntent, GitInitMutationResult, GitInitReason } from './gitInitProtocol.ts';
import { fetchIntentMatchesReview, gitFetchIssueHelp, isGitFetchAction, isGitFetchIntent, isGitFetchMutation, isGitFetchReason, isGitFetchReview } from './gitFetchProtocol.ts';
import type { GitFetchAction, GitFetchReview, GitFetchIntent, GitFetchMutationResult, GitFetchReason, GitFetchIssue } from './gitFetchProtocol.ts';

export type GitLocalCommand = 'prepare' | 'apply' | 'discard' | 'status' | 'cancel';
export interface GitLocalApi {
  prepare(raw: Uint8Array): Promise<unknown>; apply(raw: Uint8Array): Promise<unknown>;
  discard(raw: Uint8Array): Promise<unknown>; status(raw: Uint8Array): Promise<unknown>; cancel(raw: Uint8Array): Promise<unknown>;
}
export function createGitLocalApi(mode: string, invoke: (command: string, raw: Uint8Array) => Promise<unknown>): GitLocalApi | null {
  if (mode !== 'native') return null;
  const call = (name: GitLocalCommand, raw: Uint8Array) => {
    const command = `git_local_${name}`;
    if (!(raw instanceof Uint8Array) || raw.length + command.length + 32 > (name === 'prepare' ? 96 * 1024 : 1024))
      return Promise.reject(new Error('Invalid local Git request.'));
    return invoke(command, raw.slice());
  };
  return Object.freeze({ prepare: (raw: Uint8Array) => call('prepare', raw), apply: (raw: Uint8Array) => call('apply', raw),
    discard: (raw: Uint8Array) => call('discard', raw), status: (raw: Uint8Array) => call('status', raw), cancel: (raw: Uint8Array) => call('cancel', raw) });
}
export interface GitLocalFileAction { readonly kind: GitAction; readonly expectedRevision: string; readonly paths: readonly string[] }
export type GitLocalAction = GitLocalFileAction | GitBranchAction | GitSwitchAction | GitRenameAction | GitFastForwardAction | GitInitAction | GitFetchAction;
export interface GitLocalFileInput extends GitLocalFileAction { readonly message: string | null; readonly identity: { readonly name: string; readonly email: string } | null }
export type GitLocalInput = GitLocalFileInput | GitBranchAction | GitSwitchAction | GitRenameAction | GitFastForwardAction | GitInitAction | GitFetchAction;
export interface GitLocalFileReview { readonly action: GitAction; readonly expectedRevision: string; readonly paths: readonly string[];
  readonly wholeIndex: boolean; readonly head: string | null; readonly branch: string | null; readonly expectedIndex: string; readonly reviewDigest: string }
export type GitLocalReview = GitLocalFileReview | GitBranchReview | GitSwitchReview | GitRenameReview | GitFastForwardReview | GitInitReview | GitFetchReview;
export type GitLocalIntent = GitIntent | GitBranchIntent | GitSwitchIntent | GitRenameIntent | GitFastForwardIntent | GitInitIntent | GitFetchIntent;
export type GitLocalMutationResult = GitMutationResult | GitBranchMutationResult | GitSwitchMutationResult | GitRenameMutationResult | GitFastForwardMutationResult | GitInitMutationResult | GitFetchMutationResult;
export type GitLocalReason = GitReason | GitBranchReason | GitSwitchReason | GitRenameReason | GitFastForwardReason | GitInitReason | GitFetchReason;
export type GitLocalIssue = GitIssue | GitBranchIssue | GitSwitchIssue | GitRenameIssue | GitFastForwardIssue | GitInitReason | GitFetchIssue;
export type GitLocalPrepareResult = { readonly review: GitLocalFileReview; readonly diff: GitDiff } | { readonly review: GitBranchReview } | { readonly review: GitSwitchReview } | { readonly review: GitRenameReview } | { readonly review: GitFastForwardReview } | { readonly review: GitInitReview } | { readonly review: GitFetchReview; readonly diff: null };
export type GitLocalPrepared = { readonly reviewId: string; readonly context: GitReadContext } &
  ({ readonly action: GitLocalFileAction; readonly review: GitLocalFileReview; readonly diff: GitDiff } |
   { readonly action: GitBranchAction; readonly review: GitBranchReview } | { readonly action: GitSwitchAction; readonly review: GitSwitchReview } | { readonly action: GitRenameAction; readonly review: GitRenameReview } | { readonly action: GitFastForwardAction; readonly review: GitFastForwardReview } | { readonly action: GitInitAction; readonly review: GitInitReview } | { readonly action: GitFetchAction; readonly review: GitFetchReview });
export interface GitLocalOperation { readonly operationId: string; readonly context: GitReadContext; readonly phase: 'prepare' | 'apply';
  readonly action: GitLocalAction; readonly stage: 'starting' | 'running' | 'stopping' | 'settled' | 'cleanup-unknown';
  readonly outcome: 'ok' | 'refused' | 'cancelled' | 'timed-out' | 'cleanup-unknown' | null; readonly reason: GitLocalReason | null;
  readonly result: GitLocalPrepareResult | GitLocalMutationResult | null }
export interface GitLocalStatus { readonly schemaVersion: 1; readonly documentRevision: number; readonly available: boolean;
  readonly review: GitLocalPrepared | null; readonly operation: GitLocalOperation | null }
export interface GitLocalStartRequest { readonly phase: 'prepare' | 'apply'; readonly projectId: string; readonly expectedDocumentRevision: number;
  readonly action: GitLocalAction | null; readonly reviewId: string | null }
export type GitLocalStartResult = { readonly schemaVersion: 1; readonly admission: 'started'; readonly request: GitLocalStartRequest;
  readonly status: GitLocalStatus; readonly reason: null } | { readonly schemaVersion: 1; readonly admission: 'refused';
  readonly request: GitLocalStartRequest; readonly status: GitLocalStatus; readonly reason: 'invalid-input' | 'stale-observation' | 'unavailable' | 'busy' };

const utf8 = new TextEncoder();
const id = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$(?![\s\S])/.test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/.test(v);
const u32 = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
const revision = (v: unknown): v is number => u32(v) && v > 0 && v < 0xffffffff;
const kind = (v: unknown): v is GitAction => v === 'stage' || v === 'unstage' || v === 'commit';
const nullable = (v: unknown, check: (value: unknown) => boolean) => v === null || check(v);
const reason = (v: unknown, expected: GitLocalAction): v is GitLocalReason => typeof v === 'string' &&
  (GIT_REASONS.includes(v as GitReason) || expected.kind === 'fetch' && isGitFetchReason(v) || expected.kind === 'branch-create' && isGitBranchReason(v) || expected.kind === 'branch-switch' && isGitSwitchReason(v) || expected.kind === 'branch-rename' && isGitRenameReason(v) || expected.kind === 'fast-forward' && isGitFastForwardReason(v) || expected.kind === 'initialize' && isGitInitReason(v));
function text(v: unknown, max: number, multiline = false): v is string {
  return typeof v === 'string' && v.length <= max && utf8.encode(v).length <= max && !/\p{Cs}/u.test(v) &&
    !(multiline ? /[\x00-\x08\x0b-\x1f\x7f]/ : /[\x00-\x1f\x7f]/).test(v);
}
function path(v: unknown): v is string { return text(v, 1024) && !v.includes('\\') && v.split('/').length <= 32 &&
  v.split('/').every((p) => !['', '.', '..', '.git'].includes(p) && utf8.encode(p).length <= 255); }
function paths(v: unknown): v is string[] { return Array.isArray(v) && v.length > 0 && v.length <= 64 && v.every(path) &&
  v.every((p, i) => i === 0 || gitReadPathOrder(v[i - 1]!, p) < 0); }
function branch(v: unknown): v is string { return text(v, 1024) && v.startsWith('refs/heads/') && !/[\x00-\x20\x7f~^:?*\[\\]/.test(v) &&
  !v.includes('..') && !v.includes('@{') && v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock')); }
function context(v: unknown): v is GitReadContext {
  return connectionKeys(v, ['projectId', 'generation', 'revision']) && id(v.projectId) && u32(v.generation) &&
    typeof v.revision === 'string' && /^document-[1-9][0-9]*$(?![\s\S])/.test(v.revision) && revision(Number(v.revision.slice(9)));
}
function fileAction(v: unknown): v is GitLocalFileAction {
  return connectionKeys(v, ['kind', 'expectedRevision', 'paths']) && kind(v.kind) && digest(v.expectedRevision) &&
    (v.kind === 'commit' ? Array.isArray(v.paths) && v.paths.length === 0 : paths(v.paths));
}
function action(v: unknown): v is GitLocalAction { return isGitFetchAction(v) || isGitInitAction(v) || isGitFastForwardAction(v) || isGitBranchAction(v) || isGitSwitchAction(v) || isGitRenameAction(v) || fileAction(v); }
function input(v: unknown): v is GitLocalInput {
  if (isGitFetchAction(v) || isGitInitAction(v) || isGitFastForwardAction(v) || isGitBranchAction(v) || isGitSwitchAction(v) || isGitRenameAction(v)) return true;
  if (!connectionKeys(v, ['kind', 'expectedRevision', 'paths', 'message', 'identity']) ||
      !fileAction({ kind: v.kind, expectedRevision: v.expectedRevision, paths: v.paths })) return false;
  if (v.kind !== 'commit') return v.message === null && v.identity === null;
  return text(v.message, 4096, true) && v.message.trim().length > 0 && !v.message.includes('\r') &&
    connectionKeys(v.identity, ['name', 'email']) && text(v.identity.name, 128) && v.identity.name.length > 0 && !/[<>]/.test(v.identity.name) &&
    text(v.identity.email, 254) && !/[\s<>]/u.test(v.identity.email) && v.identity.email.split('@').length === 2 && v.identity.email.split('@').every(Boolean);
}
function fileReview(v: unknown, expected: GitLocalFileAction): v is GitLocalFileReview {
  return connectionKeys(v, ['action', 'expectedRevision', 'paths', 'wholeIndex', 'head', 'branch', 'expectedIndex', 'reviewDigest']) &&
    v.action === expected.kind && v.expectedRevision === expected.expectedRevision && paths(v.paths) &&
    (expected.kind === 'commit' || samePaths(v.paths, expected.paths)) && v.wholeIndex === (expected.kind === 'commit') &&
    nullable(v.head, oid) && nullable(v.branch, branch) && !(v.head === null && v.branch === null) &&
    (expected.kind !== 'commit' || v.branch !== null) && digest(v.expectedIndex) && digest(v.reviewDigest);
}
function reviewed(v: unknown, expected: GitLocalAction): boolean {
  if (expected.kind === 'fetch') return connectionKeys(v, ['review', 'diff']) && v.diff === null && isGitFetchReview(v.review, expected);
  if (expected.kind === 'initialize') return connectionKeys(v, ['review']) && isGitInitReview(v.review, expected);
  if (expected.kind === 'fast-forward') return connectionKeys(v, ['review']) && isGitFastForwardReview(v.review, expected);
  if (expected.kind === 'branch-rename') return connectionKeys(v, ['review']) && isGitRenameReview(v.review, expected);
  if (expected.kind === 'branch-switch') return connectionKeys(v, ['review']) && isGitSwitchReview(v.review, expected);
  if (expected.kind === 'branch-create') return connectionKeys(v, ['review']) && isGitBranchReview(v.review, expected);
  if (!connectionKeys(v, ['review', 'diff']) || !fileReview(v.review, expected)) return false;
  const diff = parseGitDiff(v.diff);
  return !!diff && diff.revision === expected.expectedRevision && diff.staged === (expected.kind !== 'stage') && samePaths(diff.paths, v.review.paths);
}
function intent(v: unknown, expected: GitLocalAction): v is GitLocalIntent {
  if (expected.kind === 'fetch') return isGitFetchIntent(v, expected);
  if (expected.kind === 'initialize') return isGitInitIntent(v, expected);
  if (expected.kind === 'fast-forward') return isGitFastForwardIntent(v, expected);
  if (expected.kind === 'branch-rename') return isGitRenameIntent(v, expected);
  if (expected.kind === 'branch-switch') return isGitSwitchIntent(v, expected);
  if (expected.kind === 'branch-create') return isGitBranchIntent(v, expected);
  if (!connectionKeys(v, ['action', 'expectedRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'candidateIndex', 'candidateCommit']) ||
      v.action !== expected.kind || v.expectedRevision !== expected.expectedRevision || !nullable(v.expectedRef, branch) || !nullable(v.expectedHead, oid) ||
      v.expectedRef === null && v.expectedHead === null || !digest(v.expectedIndex)) return false;
  return expected.kind === 'commit' ? v.expectedRef !== null && v.candidateIndex === null && oid(v.candidateCommit) &&
    (v.expectedHead === null || (v.expectedHead as string).length === v.candidateCommit.length) : digest(v.candidateIndex) && v.candidateCommit === null;
}
function mutation(v: unknown, expected: GitLocalAction, operationId: string): boolean {
  if (expected.kind === 'fetch') return isGitFetchMutation(v, expected, operationId);
  if (expected.kind === 'initialize') return isGitInitMutation(v, expected, operationId);
  if (expected.kind === 'fast-forward') return isGitFastForwardMutation(v, expected, operationId);
  if (expected.kind === 'branch-rename') return isGitRenameMutation(v, expected, operationId);
  if (expected.kind === 'branch-switch') return isGitSwitchMutation(v, expected, operationId);
  if (expected.kind === 'branch-create') return isGitBranchMutation(v, expected, operationId);
  if (!connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent']) || v.operationId !== operationId ||
      v.action !== expected.kind || v.settlement !== 'settled' || !nullable(v.intent, (i) => intent(i, expected))) return false;
  if (v.state === 'succeeded') {
    const observation = parseGitObservation(v.observation), i = v.intent as GitIntent | null;
    return v.reason === null && !!i && !!observation && observation.branch === i.expectedRef &&
      observation.head === (expected.kind === 'commit' ? i.candidateCommit : i.expectedHead);
  }
  return (v.state === 'failed' || v.state === 'recovery-required') && reason(v.reason, expected) && v.reason !== 'unknown' && v.observation === null;
}
function operation(v: unknown): v is GitLocalOperation {
  if (!connectionKeys(v, ['operationId', 'context', 'phase', 'action', 'stage', 'outcome', 'reason', 'result']) || !id(v.operationId) ||
      !context(v.context) || !action(v.action) || v.phase !== 'prepare' && v.phase !== 'apply') return false;
  if (v.stage === 'cleanup-unknown') return v.outcome === 'cleanup-unknown' && v.reason === 'unknown' && v.result === null;
  if (['starting', 'running', 'stopping'].includes(v.stage as string)) return v.outcome === null && v.reason === null && v.result === null;
  if (v.stage !== 'settled') return false;
  return v.outcome === 'ok' ? v.reason === null && (v.phase === 'prepare' ? reviewed(v.result, v.action) : mutation(v.result, v.action, v.operationId)) :
    ['refused', 'cancelled', 'timed-out'].includes(v.outcome as string) && reason(v.reason, v.action) && v.reason !== 'unknown' && v.result === null;
}
function prepared(v: unknown): boolean {
  if (connectionKeys(v, ['reviewId', 'context', 'action', 'review'])) return id(v.reviewId) && context(v.context) &&
    (isGitFetchAction(v.action) ? isGitFetchReview(v.review, v.action) :
      (isGitInitAction(v.action) || isGitFastForwardAction(v.action) || isGitBranchAction(v.action) || isGitSwitchAction(v.action) || isGitRenameAction(v.action)) && reviewed({ review: v.review }, v.action));
  return connectionKeys(v, ['reviewId', 'context', 'action', 'review', 'diff']) && id(v.reviewId) && context(v.context) && fileAction(v.action) &&
    reviewed({ review: v.review, diff: v.diff }, v.action);
}
export function gitLocalPreparedResult(v: GitLocalPrepared): GitLocalPrepareResult {
  return 'diff' in v ? { review: v.review, diff: v.diff } :
    v.review.action === 'fetch' ? { review: v.review, diff: null } : v.review.action === 'initialize' ? { review: v.review } : v.review.action === 'fast-forward' ? { review: v.review } : v.review.action === 'branch-switch' ? { review: v.review } : v.review.action === 'branch-rename' ? { review: v.review } : { review: v.review };
}
export function gitLocalIntentMatchesReview(v: GitLocalIntent, r: GitLocalReview): boolean {
  if (v.action === 'fetch') return r.action === 'fetch' && fetchIntentMatchesReview(v, r);
  if (v.action === 'fast-forward') return r.action === 'fast-forward' && fastForwardIntentMatchesReview(v, r);
  if (v.action === 'initialize') return r.action === 'initialize' && initIntentMatchesReview(v, r);
  if (v.action === 'branch-rename') return r.action === 'branch-rename' && renameIntentMatchesReview(v, r);
  if (v.action === 'branch-switch') return r.action === 'branch-switch' && switchIntentMatchesReview(v, r);
  if (v.action === 'branch-create') return r.action === 'branch-create' && branchIntentMatchesReview(v, r);
  return r.action !== 'fetch' && r.action !== 'fast-forward' && r.action !== 'initialize' && r.action !== 'branch-create' && r.action !== 'branch-switch' && r.action !== 'branch-rename' && v.action === r.action && v.expectedRevision === r.expectedRevision &&
    v.expectedIndex === r.expectedIndex && v.expectedHead === r.head && v.expectedRef === r.branch;
}
function immutable<T>(v: unknown): T {
  const result = structuredClone(v);
  const freeze = (p: unknown): void => { if (p && typeof p === 'object') { Object.values(p).forEach(freeze); Object.freeze(p); } };
  freeze(result); return result as T;
}
export function parseGitLocalStatus(v: unknown): GitLocalStatus | null {
  try {
    return connectionBounded(v, 2 * 1024 * 1024, 27000, 12) && connectionKeys(v, ['schemaVersion', 'documentRevision', 'available', 'review', 'operation']) &&
      v.schemaVersion === 1 && u32(v.documentRevision) && typeof v.available === 'boolean' && nullable(v.review, prepared) && nullable(v.operation, operation) ? immutable(v) : null;
  } catch { return null; }
}
export function parseGitLocalStartResult(v: unknown): GitLocalStartResult | null {
  try {
    if (!connectionBounded(v, 2 * 1024 * 1024 + 96 * 1024, 28500, 13) ||
        !connectionKeys(v, ['schemaVersion', 'admission', 'request', 'status', 'reason']) || v.schemaVersion !== 1 ||
        !connectionKeys(v.request, ['phase', 'projectId', 'expectedDocumentRevision', 'action', 'reviewId']) || !id(v.request.projectId) ||
        !revision(v.request.expectedDocumentRevision) || !(v.request.phase === 'prepare' ? action(v.request.action) && v.request.reviewId === null :
          v.request.phase === 'apply' && v.request.action === null && id(v.request.reviewId))) return null;
    const status = parseGitLocalStatus(v.status);
    if (!status || (v.admission === 'started' ? v.reason !== null || !status.operation :
      v.admission !== 'refused' || !['invalid-input', 'stale-observation', 'unavailable', 'busy'].includes(v.reason as string))) return null;
    return immutable(v);
  } catch { return null; }
}
export function gitLocalRequest(name: GitLocalCommand, v: unknown): Uint8Array | null {
  try {
    if (!connectionBounded(v, 96 * 1024, 1000, 5)) return null;
    const valid = name === 'status' ? connectionKeys(v, []) : name === 'cancel' ? connectionKeys(v, ['operationId']) && id(v.operationId) :
      name === 'discard' ? connectionKeys(v, ['reviewId']) && id(v.reviewId) : name === 'apply' ?
        connectionKeys(v, ['projectId', 'expectedDocumentRevision', 'reviewId']) && id(v.projectId) && revision(v.expectedDocumentRevision) && id(v.reviewId) :
        name === 'prepare' && connectionKeys(v, ['projectId', 'expectedDocumentRevision', 'action']) && id(v.projectId) && revision(v.expectedDocumentRevision) && input(v.action);
    if (!valid) return null;
    const raw = utf8.encode(JSON.stringify(v));
    return raw.length + `git_local_${name}`.length + 32 <= (name === 'prepare' ? 96 * 1024 : 1024) ? raw : null;
  } catch { return null; }
}
export function samePaths(a: readonly string[], b: readonly string[]): boolean { return a.length === b.length && a.every((p, i) => p === b[i]); }
export function sameGitLocalAction(a: GitLocalAction, b: GitLocalAction): boolean {
  if (a.kind === 'fetch') return b.kind === 'fetch' && a.expectedRevision === b.expectedRevision && a.expectedReferenceRevision === b.expectedReferenceRevision &&
    a.remote === b.remote && a.reference === b.reference && a.connectionSessionId === b.connectionSessionId && a.expectedConnectionRevision === b.expectedConnectionRevision;
  if (a.kind === 'initialize') return b.kind === 'initialize';
  if (a.kind === 'fast-forward') return b.kind === 'fast-forward' && a.expectedRevision === b.expectedRevision &&
    a.expectedReferenceRevision === b.expectedReferenceRevision && a.targetRef === b.targetRef && a.targetOid === b.targetOid;
  if (a.kind === 'branch-rename') return b.kind === 'branch-rename' && a.expectedRevision === b.expectedRevision &&
    a.expectedReferenceRevision === b.expectedReferenceRevision && a.name === b.name;
  if (a.kind === 'branch-switch') return b.kind === 'branch-switch' && a.expectedRevision === b.expectedRevision &&
    a.expectedReferenceRevision === b.expectedReferenceRevision && a.name === b.name;
  if (a.kind === 'branch-create') return b.kind === 'branch-create' && a.expectedRevision === b.expectedRevision &&
    a.expectedReferenceRevision === b.expectedReferenceRevision && a.name === b.name;
  return b.kind !== 'fetch' && b.kind !== 'fast-forward' && b.kind !== 'initialize' && b.kind !== 'branch-create' && b.kind !== 'branch-switch' && b.kind !== 'branch-rename' && a.kind === b.kind && a.expectedRevision === b.expectedRevision && samePaths(a.paths, b.paths);
}
export function gitLocalIssueHelp(issue: GitLocalIssue): string {
  return gitFetchIssueHelp(issue) ?? gitInitIssueHelp(issue) ?? gitFastForwardIssueHelp(issue) ?? gitRenameIssueHelp(issue) ?? gitSwitchIssueHelp(issue) ?? previousIssueHelp(issue as GitIssue | GitBranchIssue);
}
// Only finite decoded immutable DATA is passed here, never caller getters.
export function sameGitLocalData(a: unknown, b: unknown): boolean {
  const ordered = (v: unknown): unknown => Array.isArray(v) ? v.map(ordered) : v !== null && typeof v === 'object' ?
    Object.fromEntries(Object.keys(v).sort().map((k) => [k, ordered((v as Record<string, unknown>)[k])])) : v;
  return JSON.stringify(ordered(a)) === JSON.stringify(ordered(b));
}
