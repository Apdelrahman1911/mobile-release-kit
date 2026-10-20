// Closed Fetch DATA on the existing GitLocal five-call owner. Native admission,
// token custody, publication and real joins are never established by this file.
import { connectionBounded, connectionKeys, connectionNumericId, connectionOpaqueId, connectionRepository } from './githubConnectionProtocol.ts';
import { GIT_REASONS } from './gitRepositoryProtocol.ts';
import type { GitReason } from './gitRepositoryProtocol.ts';
import { gitReadPathOrder } from './gitReadProtocol.ts';

export const GIT_FETCH_REASONS = ['fetch-remote', 'fetch-layout', 'fetch-identity-required', 'fetch-ref-parent',
  'fetch-output', 'fetch-object-limit', 'fetch-target-changed', 'fetch-up-to-date', 'unsupported-protocol', 'target-changed',
  'network-unavailable', 'tls-failed', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'rate-limited', 'expired', 'cancelled', 'cleanup-unknown'] as const;
export type GitFetchReason = typeof GIT_FETCH_REASONS[number];
export type GitFetchIssue = GitFetchReason | 'fetch-read-required' | 'fetch-connection-required' | 'fetch-selection-required';
export interface GitFetchAction { readonly kind: 'fetch'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly remote: string; readonly reference: string; readonly connectionSessionId: string; readonly expectedConnectionRevision: number }
export interface GitFetchReview { readonly action: 'fetch'; readonly remote: string; readonly repository: string; readonly reference: string;
  readonly targetRef: string; readonly expectedTarget: string | null; readonly candidateRefOid: string; readonly expectedRevision: string;
  readonly expectedReferenceRevision: string; readonly head: string | null; readonly branch: string | null; readonly expectedIndex: string;
  readonly accountId: string; readonly repositoryId: string; readonly login: string; readonly reviewDigest: string }
export interface GitFetchIntent { readonly action: 'fetch'; readonly reviewDigest: string; readonly expectedRevision: string;
  readonly expectedReferenceRevision: string; readonly expectedRef: string | null; readonly expectedHead: string | null;
  readonly expectedIndex: string; readonly targetRef: string; readonly expectedTarget: string | null; readonly candidateRefOid: string;
  readonly packOid: string; readonly packSha256: string; readonly packBytes: number; readonly indexSha256: string; readonly indexBytes: number }
export type GitFetchEffect = 'not-published' | 'pack-link-entered' | 'pack-linked' | 'index-link-entered' | 'objects-linked' | 'ref-send-entered' | 'ref-published';
export interface GitFetchMutationResult { readonly operationId: string; readonly action: 'fetch'; readonly state: 'succeeded' | 'failed' | 'recovery-required';
  readonly settlement: 'settled'; readonly reason: GitReason | GitFetchReason | null; readonly observation: null;
  readonly intent: GitFetchIntent | null; readonly effectPhase: GitFetchEffect; readonly retainedPaths: readonly string[] }

const encoder = new TextEncoder();
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{40}$(?![\s\S])/.test(v) && v !== '0'.repeat(40);
const text = (v: unknown, size: number): v is string => typeof v === 'string' && v.length <= size && encoder.encode(v).length <= size && !/[\x00-\x1f\x7f\p{Cs}]/u.test(v);
const branch = (v: unknown): v is string => text(v, 1024) && v.startsWith('refs/heads/') && !/[\x00-\x20\x7f~^:?*\[\\]/.test(v) &&
  !v.includes('..') && !v.includes('@{') && v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
const nullable = (v: unknown, check: (value: unknown) => boolean) => v === null || check(v);
const fileBytes = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 32 * 1024 * 1024;
export const gitFetchRemote = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$(?![\s\S])/.test(v);
export const gitFetchReference = (v: unknown): v is string => branch(v) && v.length <= 255 && /^[\x00-\x7f]*$(?![\s\S])/.test(v) && v.split('/').length <= 32;
const login = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$(?![\s\S])/.test(v);
const target = (a: GitFetchAction) => `refs/remotes/${a.remote}/${a.reference.slice('refs/heads/'.length)}`;
function tracking(v: unknown): v is string {
  if (typeof v !== 'string' || !v.startsWith('refs/remotes/')) return false;
  const tail = v.slice('refs/remotes/'.length), slash = tail.indexOf('/');
  return slash > 0 && gitFetchRemote(tail.slice(0, slash)) && gitFetchReference(`refs/heads/${tail.slice(slash + 1)}`);
}
export function isGitFetchReason(v: unknown): v is GitFetchReason { return typeof v === 'string' && GIT_FETCH_REASONS.includes(v as GitFetchReason); }
export function isGitFetchAction(v: unknown): v is GitFetchAction {
  return connectionBounded(v, 2048, 32, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'remote', 'reference', 'connectionSessionId', 'expectedConnectionRevision']) &&
    v.kind === 'fetch' && digest(v.expectedRevision) && digest(v.expectedReferenceRevision) && gitFetchRemote(v.remote) && gitFetchReference(v.reference) &&
    connectionOpaqueId(v.connectionSessionId) && typeof v.expectedConnectionRevision === 'number' && Number.isInteger(v.expectedConnectionRevision) &&
    v.expectedConnectionRevision > 0 && v.expectedConnectionRevision < 0xffffffff;
}
export function isGitFetchReview(v: unknown, expected: GitFetchAction): v is GitFetchReview {
  return isGitFetchAction(expected) && connectionBounded(v, 8192, 64, 2) && connectionKeys(v, ['action', 'remote', 'repository', 'reference', 'targetRef',
    'expectedTarget', 'candidateRefOid', 'expectedRevision', 'expectedReferenceRevision', 'head', 'branch', 'expectedIndex', 'accountId', 'repositoryId', 'login', 'reviewDigest']) &&
    v.action === 'fetch' && v.remote === expected.remote && v.reference === expected.reference && v.targetRef === target(expected) &&
    v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision && connectionRepository(v.repository) &&
    oid(v.candidateRefOid) && nullable(v.expectedTarget, oid) && nullable(v.head, oid) && nullable(v.branch, branch) && (v.head !== null || v.branch !== null) &&
    digest(v.expectedIndex) && digest(v.reviewDigest) && connectionNumericId(v.accountId) && connectionNumericId(v.repositoryId) && login(v.login);
}
export function isGitFetchIntent(v: unknown, expected: GitFetchAction): v is GitFetchIntent {
  return isGitFetchAction(expected) && connectionBounded(v, 8192, 64, 2) && connectionKeys(v, ['action', 'reviewDigest', 'expectedRevision',
    'expectedReferenceRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'targetRef', 'expectedTarget', 'candidateRefOid', 'packOid', 'packSha256', 'packBytes', 'indexSha256', 'indexBytes']) &&
    v.action === 'fetch' && digest(v.reviewDigest) && v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision &&
    nullable(v.expectedRef, branch) && nullable(v.expectedHead, oid) && (v.expectedRef !== null || v.expectedHead !== null) && digest(v.expectedIndex) &&
    tracking(v.targetRef) && v.targetRef === target(expected) && nullable(v.expectedTarget, oid) && oid(v.candidateRefOid) && v.expectedTarget !== v.candidateRefOid &&
    oid(v.packOid) && digest(v.packSha256) && fileBytes(v.packBytes) && digest(v.indexSha256) && fileBytes(v.indexBytes);
}
export function fetchIntentMatchesReview(v: GitFetchIntent, r: GitFetchReview): boolean {
  return v.reviewDigest === r.reviewDigest && v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision &&
    v.expectedRef === r.branch && v.expectedHead === r.head && v.expectedIndex === r.expectedIndex && v.targetRef === r.targetRef &&
    v.expectedTarget === r.expectedTarget && v.candidateRefOid === r.candidateRefOid;
}
export const GIT_FETCH_EFFECT_LABELS: Readonly<Record<GitFetchEffect, string>> = Object.freeze({
  'not-published': 'No completed publication reported — not proof that nothing changed',
  'pack-link-entered': 'Git pack publication was entered', 'pack-linked': 'Git pack publication returned',
  'index-link-entered': 'Pack index publication was entered', 'objects-linked': 'Object publication returned',
  'ref-send-entered': 'Tracking-reference update was entered', 'ref-published': 'Tracking-reference update returned',
});
function retained(v: unknown, intent: GitFetchIntent | null): v is string[] {
  return Array.isArray(v) && v.length <= 5 && v.every((p, i) => typeof p === 'string' &&
    (/^mrk-git-fetch-[a-z0-9_]{1,32}$(?![\s\S])/.test(p) || !!intent && ['pack', 'idx', 'keep'].some((suffix) => p === `objects/pack/pack-${intent.packOid}.${suffix}`)) &&
    (i === 0 || gitReadPathOrder(v[i - 1]!, p) < 0));
}
export function isGitFetchMutation(v: unknown, expected: GitFetchAction, operationId: string): v is GitFetchMutationResult {
  if (!isGitFetchAction(expected) || !connectionOpaqueId(operationId) || !connectionBounded(v, 16 * 1024, 128, 4) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths']) ||
      v.operationId !== operationId || v.action !== 'fetch' || v.settlement !== 'settled' || v.observation !== null ||
      !(v.intent === null || isGitFetchIntent(v.intent, expected)) || !retained(v.retainedPaths, v.intent) ||
      typeof v.effectPhase !== 'string' || !Object.hasOwn(GIT_FETCH_EFFECT_LABELS, v.effectPhase)) return false;
  return v.state === 'succeeded' ? v.intent !== null && v.reason === null && v.effectPhase === 'ref-published' && v.retainedPaths.length === 0 :
    (v.state === 'failed' || v.state === 'recovery-required') && (isGitFetchReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason)) &&
    (v.intent !== null || v.effectPhase === 'not-published');
}
const HELP: Readonly<Record<GitFetchIssue, string>> = Object.freeze({
  'fetch-read-required': 'Refresh changes to read this project’s current local Git references. No GitHub read is included in that refresh.',
  'fetch-connection-required': 'Connect the intended GitHub account and repository first. Fetch uses that account privately; a listed account or old connection is not enough.',
  'fetch-selection-required': 'Choose an observed remote name and enter one GitHub branch, such as main or release/test. Do not enter a URL or a Git command.',
  'fetch-remote': 'This remote must point directly to the selected GitHub repository with an ordinary HTTPS fetch mapping. Use your Git client for other remote settings; nothing is rewritten here.',
  'fetch-layout': 'This checkout or its Git policy is outside the bounded Fetch support. Use your Git client; the app does not bypass hooks, filters, LFS or repository policy.',
  'fetch-identity-required': 'Configure this repository’s Git user name and email in your Git client, then refresh and review again. Fetch preserves its required reference logging.',
  'fetch-ref-parent': 'The required remote-tracking or log folder is missing or conflicts. Use your Git client for the initial fetch or layout repair; do not remove locks or change permissions to bypass this check.',
  'fetch-output': 'The fetched output could not be verified. Keep the original task and any retained files; do not repeat it to dismiss this warning.',
  'fetch-object-limit': 'This fetch exceeds the supported object or staging limits. Use your Git client after the original task has settled.',
  'fetch-target-changed': 'The selected branch or local references changed. Keep the original result, then explicitly refresh and review again only after it settles.',
  'fetch-up-to-date': 'This tracking copy matched the observed GitHub commit. Close this review; it does not check future remote changes.',
  'unsupported-protocol': 'This server response is outside the supported Git protocol. No alternate transport or account is tried automatically.',
  'target-changed': 'The account, repository or branch changed. A new explicit review is needed after the original task finishes.',
  'network-unavailable': 'The GitHub request could not finish. Check the original task; a network error is not proof that no local changes occurred.',
  'tls-failed': 'The protected connection could not be verified. The app will not disable TLS checks or try an unverified connection.',
  unauthorized: 'The connected account could not authenticate this request. Check the original task, then reconnect explicitly if needed.',
  forbidden: 'The connected account lacks access for this request. Check repository access; the app will not switch accounts automatically.',
  'not-found-or-inaccessible': 'The repository or branch could not be found with this account, or access is restricted. This does not prove it is absent.',
  'rate-limited': 'GitHub limited the request. Preserve the original task; no automatic retry is scheduled.',
  expired: 'The original connection or review expired. Close an unused review and create a new one explicitly; never repeat an uncertain fetch.',
  cancelled: 'Stopping was requested. Wait for the original task and all cleanup to settle; cancellation alone is not completion.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the app and files and use the original status and Stop controls; do not retry or delete retained files.',
});
export function gitFetchIssueHelp(issue: string): string | null { return Object.hasOwn(HELP, issue) ? HELP[issue as GitFetchIssue] : null; }
