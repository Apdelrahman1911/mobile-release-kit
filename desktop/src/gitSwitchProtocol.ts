// Bounded display/correlation DATA for the existing GitLocal owner. No path,
// digest or publication phase below is consent, native custody or finality.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { gitBranchName } from './gitBranchesProtocol.ts';
import { gitReadPathOrder } from './gitReadProtocol.ts';
import { GIT_REASONS, parseGitObservation } from './gitRepositoryProtocol.ts';
import type { GitObservation, GitReason } from './gitRepositoryProtocol.ts';

export const GIT_SWITCH_REASONS = ['switch-dirty', 'switch-layout', 'switch-target', 'switch-conversion',
  'switch-identity-required', 'switch-log-limit', 'switch-file-mode'] as const;
export type GitSwitchReason = typeof GIT_SWITCH_REASONS[number];
export type GitSwitchIssue = GitSwitchReason | 'switch-name-required';
export interface GitSwitchAction { readonly kind: 'branch-switch'; readonly expectedRevision: string;
  readonly expectedReferenceRevision: string; readonly name: string }
export interface GitSwitchFile { readonly path: string; readonly mode: '100644' | '100755'; readonly sourceOid: string;
  readonly targetOid: string; readonly sourceSha256: string; readonly targetSha256: string; readonly targetSize: number }
export interface GitSwitchLog { readonly enabled: boolean; readonly originalKind: 'absent' | 'file'; readonly originalSha256: string }
export interface GitSwitchReview { readonly action: 'branch-switch'; readonly name: string; readonly targetRef: string; readonly targetOid: string;
  readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly head: string; readonly branch: string;
  readonly expectedIndex: string; readonly paths: readonly string[]; readonly trackedCount: number; readonly contentOnly: true;
  readonly files: readonly GitSwitchFile[]; readonly log: GitSwitchLog; readonly reviewDigest: string }
export interface GitSwitchIntent { readonly action: 'branch-switch'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly expectedRef: string; readonly expectedHead: string; readonly expectedIndex: string; readonly targetRef: string; readonly targetOid: string;
  readonly candidateIndex: string; readonly originalHead: string; readonly candidateHead: string; readonly originalLog: string;
  readonly candidateLog: string; readonly logEnabled: boolean; readonly footprint: string }
export type GitSwitchEffect = 'not-published' | 'worktree-returned' | 'head-log-returned' | 'head-returned' | 'index-returned';
export interface GitSwitchMutationResult { readonly operationId: string; readonly action: 'branch-switch'; readonly state: 'succeeded' | 'failed' | 'recovery-required';
  readonly settlement: 'settled'; readonly reason: GitReason | GitSwitchReason | null; readonly observation: GitObservation | null;
  readonly intent: GitSwitchIntent | null; readonly effectPhase: GitSwitchEffect; readonly retainedPaths: readonly string[] }

const utf8 = new TextEncoder();
const ABSENT = '5ad38304b535c2987dbd24657c1a11b884984ff600d9f389deb0d4e634fee792';
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/.test(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length <= max && utf8.encode(v).length <= max && !/[\x00-\x1f\x7f\p{Cs}]/u.test(v);
const uint = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
function reference(v: unknown): v is string {
  return text(v, 1024) && v.startsWith('refs/heads/') && !/[\x00-\x20\x7f~^:?*\[\\]/.test(v) && !v.includes('..') && !v.includes('@{') &&
    v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
function path(v: unknown): v is string {
  return text(v, 1024) && !v.includes('\\') && v.split('/').length <= 32 &&
    v.split('/').every((p) => !['', '.', '..', '.git'].includes(p) && utf8.encode(p).length <= 255);
}
function file(v: unknown, width: number): v is GitSwitchFile {
  return connectionKeys(v, ['path', 'mode', 'sourceOid', 'targetOid', 'sourceSha256', 'targetSha256', 'targetSize']) && path(v.path) &&
    (v.mode === '100644' || v.mode === '100755') && oid(v.sourceOid) && oid(v.targetOid) && v.sourceOid.length === width && v.targetOid.length === width &&
    v.sourceOid !== v.targetOid && digest(v.sourceSha256) && digest(v.targetSha256) && uint(v.targetSize, 4 * 1024 * 1024);
}
function log(v: unknown): v is GitSwitchLog {
  return connectionKeys(v, ['enabled', 'originalKind', 'originalSha256']) && typeof v.enabled === 'boolean' && digest(v.originalSha256) &&
    (v.originalKind === 'absent' ? v.originalSha256 === ABSENT : v.originalKind === 'file' && v.enabled);
}
export function isGitSwitchReason(v: unknown): v is GitSwitchReason { return typeof v === 'string' && GIT_SWITCH_REASONS.includes(v as GitSwitchReason); }
export function isGitSwitchAction(v: unknown): v is GitSwitchAction {
  return connectionBounded(v, 2048, 32, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'name']) &&
    v.kind === 'branch-switch' && digest(v.expectedRevision) && digest(v.expectedReferenceRevision) && gitBranchName(v.name);
}
export function isGitSwitchReview(v: unknown, expected: GitSwitchAction): v is GitSwitchReview {
  if (!isGitSwitchAction(expected) || !connectionBounded(v, 32 * 1024, 512, 5) ||
      !connectionKeys(v, ['action', 'name', 'targetRef', 'targetOid', 'expectedRevision', 'expectedReferenceRevision', 'head', 'branch', 'expectedIndex',
        'paths', 'trackedCount', 'contentOnly', 'files', 'log', 'reviewDigest']) || v.action !== 'branch-switch' || v.name !== expected.name ||
      v.expectedRevision !== expected.expectedRevision || v.expectedReferenceRevision !== expected.expectedReferenceRevision ||
      v.targetRef !== `refs/heads/${expected.name}` || !reference(v.branch) || v.branch === v.targetRef || !oid(v.head) || !oid(v.targetOid) ||
      v.head.length !== v.targetOid.length || !digest(v.expectedIndex) || !digest(v.reviewDigest) || v.contentOnly !== true ||
      !uint(v.trackedCount, 256) || !Array.isArray(v.files) || v.files.length > 8 || v.files.length > v.trackedCount ||
      !Array.isArray(v.paths) || v.paths.length !== v.files.length || !log(v.log)) return false;
  const width = v.head.length, files = v.files, paths = v.paths;
  if (!files.every((f): f is GitSwitchFile => file(f, width))) return false;
  return files.every((f, i) => paths[i] === f.path && (i === 0 || gitReadPathOrder(files[i - 1]!.path, f.path) < 0)) &&
    files.reduce((n, f) => n + f.targetSize, 0) <= 8 * 1024 * 1024;
}
export function isGitSwitchIntent(v: unknown, expected: GitSwitchAction): v is GitSwitchIntent {
  // The original native codec, not this display parser, hashes exact symbolic
  // HEAD bytes. Renderer-computed digests could never authorize publication.
  return isGitSwitchAction(expected) && connectionBounded(v, 8192, 64, 2) &&
    connectionKeys(v, ['action', 'expectedRevision', 'expectedReferenceRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'targetRef', 'targetOid',
      'candidateIndex', 'originalHead', 'candidateHead', 'originalLog', 'candidateLog', 'logEnabled', 'footprint']) &&
    v.action === 'branch-switch' && v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision &&
    reference(v.expectedRef) && v.targetRef === `refs/heads/${expected.name}` && v.expectedRef !== v.targetRef && oid(v.expectedHead) && oid(v.targetOid) &&
    v.expectedHead.length === v.targetOid.length && [v.expectedIndex, v.candidateIndex, v.originalHead, v.candidateHead, v.originalLog, v.candidateLog, v.footprint].every(digest) &&
    typeof v.logEnabled === 'boolean' && (v.logEnabled || v.candidateLog === ABSENT);
}
export function switchIntentMatchesReview(v: GitSwitchIntent, r: GitSwitchReview): boolean {
  return v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision && v.expectedRef === r.branch &&
    v.expectedHead === r.head && v.expectedIndex === r.expectedIndex && v.targetRef === r.targetRef && v.targetOid === r.targetOid &&
    v.originalLog === r.log.originalSha256 && v.logEnabled === r.log.enabled;
}
function retained(v: unknown): v is string[] {
  return Array.isArray(v) && v.length <= 5 && v.every((p) => typeof p === 'string' &&
    /^\.git\/mrk-git-[A-Za-z0-9_-]{1,64}\/(?:index|execution-index|HEAD|HEAD-log|checkout-mode)$(?![\s\S])/.test(p)) &&
    v.every((p, i) => i === 0 || gitReadPathOrder(v[i - 1]!, p) < 0);
}
export function isGitSwitchMutation(v: unknown, expected: GitSwitchAction, operationId: string): v is GitSwitchMutationResult {
  if (!isGitSwitchAction(expected) || !connectionBounded(v, 2 * 1024 * 1024, 25000, 10) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths']) ||
      v.operationId !== operationId || v.action !== 'branch-switch' || v.settlement !== 'settled' ||
      !(v.intent === null || isGitSwitchIntent(v.intent, expected)) || !retained(v.retainedPaths) ||
      !['not-published', 'worktree-returned', 'head-log-returned', 'head-returned', 'index-returned'].includes(v.effectPhase as string) ||
      v.effectPhase !== 'not-published' && !v.intent || v.effectPhase === 'head-log-returned' && !v.intent?.logEnabled) return false;
  if (v.state === 'succeeded') {
    const observation = parseGitObservation(v.observation);
    return v.reason === null && v.intent !== null && v.effectPhase === 'index-returned' && v.retainedPaths.length === 0 &&
      !!observation && observation.head === v.intent.targetOid && observation.branch === v.intent.targetRef;
  }
  return v.reason !== 'unknown' && (isGitSwitchReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason)) &&
    v.observation === null && (v.state === 'recovery-required' ? v.intent !== null :
      v.state === 'failed' && v.effectPhase === 'not-published' && v.retainedPaths.length === 0);
}

const HELP: Readonly<Record<GitSwitchIssue, string>> = Object.freeze({
  'switch-name-required': 'Choose an existing local branch from the current list. Reading the list does not switch branches.',
  'switch-target': 'Start from an attached local branch with a commit. The target must exist, differ from the current branch and match the current list. Refresh changes and local branches before a new review; use your Git client for detached or empty checkouts.',
  'switch-dirty': 'Commit or otherwise preserve your local changes in your Git client first. This switch never discards, stashes, stages or overwrites untracked or ignored files.',
  'switch-layout': 'This switch supports a clean regular checkout with the same file names and modes on both branches, at most 8 content changes, and ordinary file ownership. Use your Git client for other layouts; do not change ownership just to bypass this check.',
  'switch-conversion': 'This repository needs an unsupported checkout conversion, filter or LFS step. Use your Git client; the app will not execute it or silently bypass its policy.',
  'switch-identity-required': 'Set a repository-local user.name and user.email in your Git client, then refresh and review again. The app will not invent an identity or disable required logging.',
  'switch-log-limit': 'The existing branch log exceeds this bounded switch. Use your Git client; the app will not truncate the log.',
  'switch-file-mode': 'The current file-creation mode is unsupported. No checkout was started. Use your Git client; the app will not change the process mask or rewrite file permissions.',
});
export function gitSwitchIssueHelp(issue: string): string | null {
  return Object.hasOwn(HELP, issue) ? HELP[issue as GitSwitchIssue] : null;
}
export const GIT_SWITCH_EFFECT_LABELS: Readonly<Record<GitSwitchEffect, string>> = Object.freeze({
  'not-published': 'No completed publication was reported; this does not prove no files changed',
  'worktree-returned': 'Checkout file changes returned', 'head-log-returned': 'Checkout and HEAD log returned',
  'head-returned': 'Checkout and current-branch update returned', 'index-returned': 'Checkout, current branch and index returned',
});
