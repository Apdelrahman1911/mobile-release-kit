// Closed display/correlation DATA. Native source, selected account, durable ACK
// and the original command/HTTP joins remain the only authority to send.
import { connectionBounded, connectionKeys, connectionNumericId, connectionOpaqueId, connectionRepository } from './githubConnectionProtocol.ts';
import { GIT_REASONS } from './gitRepositoryProtocol.ts';
import type { GitReason } from './gitRepositoryProtocol.ts';

export const GIT_PUSH_REASONS = ['push-upstream', 'push-history', 'push-policy', 'push-output', 'push-target-changed',
  'push-remote-refused', 'remote-rejected', 'unsupported-protocol', 'target-changed', 'network-unavailable', 'tls-failed',
  'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'rate-limited', 'expired', 'cancelled', 'cleanup-unknown'] as const;
export type GitPushReason = typeof GIT_PUSH_REASONS[number];
export type GitPushIssue = GitPushReason | 'push-read-required' | 'push-connection-required';
export interface GitPushAction { readonly kind: 'push'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly remote: string; readonly localRef: string; readonly remoteRef: string; readonly oldOid: string; readonly newOid: string;
  readonly connectionSessionId: string; readonly expectedConnectionRevision: number }
export interface GitPushReview { readonly action: 'push'; readonly remote: string; readonly repository: string;
  readonly accountId: string; readonly repositoryId: string; readonly login: string; readonly branch: string; readonly head: string;
  readonly upstreamRef: string; readonly expectedRemoteOid: string; readonly trackingRef: string; readonly commits: readonly string[];
  readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly expectedIndex: string;
  readonly basis: 'existing-configured-upstream'; readonly withheld: readonly ['messages', 'authors', 'emails', 'signatures', 'objects']; readonly reviewDigest: string }
export interface GitPushIntent { readonly action: 'push'; readonly reviewDigest: string; readonly expectedRevision: string;
  readonly expectedReferenceRevision: string; readonly expectedIndex: string; readonly remote: string; readonly repository: string;
  readonly accountId: string; readonly repositoryId: string; readonly localRef: string; readonly remoteRef: string;
  readonly oldOid: string; readonly newOid: string; readonly commitsSha256: string }
export type GitPushEffect = 'not-sent' | 'candidate-entered' | 'candidate-acknowledged' | 'send-entered' | 'send-consumed' | 'remote-returned';
export interface GitPushMutationResult { readonly operationId: string; readonly action: 'push'; readonly state: 'succeeded' | 'failed' | 'recovery-required';
  readonly settlement: 'settled'; readonly reason: GitReason | GitPushReason | null; readonly observation: null;
  readonly intent: GitPushIntent | null; readonly effectPhase: GitPushEffect; readonly retainedPaths: readonly string[] }
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
export const gitPushOid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{40}$(?![\s\S])/.test(v) && v !== '0'.repeat(40);
export const gitPushRemote = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$(?![\s\S])/.test(v);
export function gitPushReference(v: unknown): v is string {
  return typeof v === 'string' && v.length <= 255 && v.startsWith('refs/heads/') && /^[\x21-\x7e]*$(?![\s\S])/.test(v) &&
    !/[~^:?*\[\\]/.test(v) && !v.includes('..') && !v.includes('@{') && v.split('/').length <= 32 &&
    v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
const login = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$(?![\s\S])/.test(v);
export const gitPushTracking = (remote: string, ref: string): string => `refs/remotes/${remote}/${ref.slice('refs/heads/'.length)}`;
export function isGitPushReason(v: unknown): v is GitPushReason { return typeof v === 'string' && GIT_PUSH_REASONS.includes(v as GitPushReason); }
export function isGitPushAction(v: unknown): v is GitPushAction {
  return connectionBounded(v, 4096, 40, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'remote', 'localRef', 'remoteRef',
    'oldOid', 'newOid', 'connectionSessionId', 'expectedConnectionRevision']) && v.kind === 'push' && digest(v.expectedRevision) && digest(v.expectedReferenceRevision) &&
    gitPushRemote(v.remote) && gitPushReference(v.localRef) && gitPushReference(v.remoteRef) && gitPushOid(v.oldOid) && gitPushOid(v.newOid) && v.oldOid !== v.newOid &&
    connectionOpaqueId(v.connectionSessionId) && typeof v.expectedConnectionRevision === 'number' && Number.isInteger(v.expectedConnectionRevision) &&
    v.expectedConnectionRevision > 0 && v.expectedConnectionRevision < 0xffffffff;
}
export function isGitPushReview(v: unknown, expected: GitPushAction): v is GitPushReview {
  if (!isGitPushAction(expected) || !connectionBounded(v, 16 * 1024, 200, 3) || !connectionKeys(v, ['action', 'remote', 'repository', 'accountId', 'repositoryId',
      'login', 'branch', 'head', 'upstreamRef', 'expectedRemoteOid', 'trackingRef', 'commits', 'expectedRevision', 'expectedReferenceRevision', 'expectedIndex',
      'basis', 'withheld', 'reviewDigest']) || v.action !== 'push' || v.remote !== expected.remote || v.branch !== expected.localRef || v.upstreamRef !== expected.remoteRef ||
      v.head !== expected.newOid || v.expectedRemoteOid !== expected.oldOid || v.expectedRevision !== expected.expectedRevision ||
      v.expectedReferenceRevision !== expected.expectedReferenceRevision || v.trackingRef !== gitPushTracking(expected.remote, expected.remoteRef) ||
      !connectionRepository(v.repository) || !connectionNumericId(v.accountId) || !connectionNumericId(v.repositoryId) || !login(v.login) ||
      !digest(v.expectedIndex) || !digest(v.reviewDigest) || v.basis !== 'existing-configured-upstream' ||
      !Array.isArray(v.withheld) || v.withheld.join('|') !== 'messages|authors|emails|signatures|objects' || v.withheld.length !== 5 ||
      !Array.isArray(v.commits) || v.commits.length < 1 || v.commits.length > 64 || v.commits.at(-1) !== expected.newOid) return false;
  return v.commits.every((oid, i, all) => gitPushOid(oid) && oid !== expected.oldOid && !all.slice(0, i).includes(oid));
}
export function isGitPushIntent(v: unknown, expected: GitPushAction): v is GitPushIntent {
  return isGitPushAction(expected) && connectionBounded(v, 8192, 64, 2) && connectionKeys(v, ['action', 'reviewDigest', 'expectedRevision', 'expectedReferenceRevision',
    'expectedIndex', 'remote', 'repository', 'accountId', 'repositoryId', 'localRef', 'remoteRef', 'oldOid', 'newOid', 'commitsSha256']) && v.action === 'push' &&
    v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision && v.remote === expected.remote &&
    v.localRef === expected.localRef && v.remoteRef === expected.remoteRef && v.oldOid === expected.oldOid && v.newOid === expected.newOid &&
    connectionRepository(v.repository) && connectionNumericId(v.accountId) && connectionNumericId(v.repositoryId) &&
    digest(v.reviewDigest) && digest(v.expectedIndex) && digest(v.commitsSha256);
}
export function pushIntentMatchesReview(v: GitPushIntent, r: GitPushReview): boolean {
  // The native decoder additionally recomputes commitsSha256 from the complete
  // original reviewed list. UI comparisons do not manufacture a hash receipt.
  return v.reviewDigest === r.reviewDigest && v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision &&
    v.expectedIndex === r.expectedIndex && v.remote === r.remote && v.repository === r.repository && v.accountId === r.accountId && v.repositoryId === r.repositoryId &&
    v.localRef === r.branch && v.remoteRef === r.upstreamRef && v.oldOid === r.expectedRemoteOid && v.newOid === r.head;
}
export const GIT_PUSH_EFFECT_LABELS: Readonly<Record<GitPushEffect, string>> = Object.freeze({
  'not-sent': 'No completed send was reported; this is not proof that no send began', 'candidate-entered': 'The original pending update was entered',
  'candidate-acknowledged': 'The original pending update was acknowledged', 'send-entered': 'The upload path was entered',
  'send-consumed': 'The one-send request was consumed', 'remote-returned': 'The original remote response and readback returned',
});
export function isGitPushMutation(v: unknown, expected: GitPushAction, operationId: string): v is GitPushMutationResult {
  if (!isGitPushAction(expected) || !connectionBounded(v, 16 * 1024, 100, 3) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths']) ||
      v.operationId !== operationId || v.action !== 'push' || v.settlement !== 'settled' || v.observation !== null ||
      !(v.intent === null || isGitPushIntent(v.intent, expected)) || typeof v.effectPhase !== 'string' || !Object.hasOwn(GIT_PUSH_EFFECT_LABELS, v.effectPhase) ||
      !Array.isArray(v.retainedPaths) || v.retainedPaths.length > 1 || !v.retainedPaths.every((p) => typeof p === 'string' && /^(?:mrk-git-[a-z0-9_]{1,32}\/)?mrk-git-push-[a-z0-9_]{1,32}$(?![\s\S])/.test(p))) return false;
  if (v.state === 'succeeded') return v.intent !== null && v.reason === null && v.effectPhase === 'remote-returned' && v.retainedPaths.length === 0;
  return (v.state === 'failed' || v.state === 'recovery-required') && (v.intent !== null || v.effectPhase === 'not-sent') &&
    (isGitPushReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason));
}
const HELP: Readonly<Record<GitPushIssue, string>> = Object.freeze({
  'push-read-required': 'Refresh changes first to read this branch and its cached upstream. A historical summary or branch name is not a current selection.',
  'push-connection-required': 'Connect the intended GitHub account and repository with reported read and push access. A previous account or unknown permission is not enough.',
  'push-upstream': 'This first Push supports an existing configured upstream in the selected GitHub repository. Set up a new branch or remote in your Git client; MRK does not rewrite those settings.',
  'push-history': 'The cached upstream must be strictly behind this branch, with 1–64 outgoing commits and complete history. Fetch and review first if it is behind, diverged or uncertain; no reset or force is offered.',
  'push-policy': 'This checkout or Git policy is outside bounded Push support. MRK does not bypass repository hooks, signing, LFS, submodules or transport policy.',
  'push-output': 'The original push output could not be verified. Preserve the task and files; do not repeat Push to dismiss the warning.',
  'push-target-changed': 'The branch, account or remote tip changed. Preserve the original result, then explicitly refresh and review only after it settles.',
  'push-remote-refused': 'The server did not accept this ordinary update. Check the original result and repository policy; MRK will not force or retry the push.',
  'remote-rejected': 'The server rejected the update. No force-push, alternate ref or automatic retry is attempted.',
  'unsupported-protocol': 'The response is outside the supported Git protocol. No alternate transport is tried automatically.',
  'target-changed': 'The selected repository, account or branch no longer matches. Check the original task before any new review.',
  'network-unavailable': 'The request could not finish. The remote may have changed even when the reply was lost; do not blindly retry.',
  'tls-failed': 'The protected connection could not be verified. MRK will not disable TLS checks.',
  unauthorized: 'The original account could not authenticate this request. Check the original task before reconnecting.',
  forbidden: 'The connected account or repository policy refused this request. MRK will not switch accounts or override policy.',
  'not-found-or-inaccessible': 'This account could not read the target. That does not prove the repository or branch is absent.',
  'rate-limited': 'GitHub limited the request. Keep the original task; no automatic retry is scheduled.',
  expired: 'The original connection or review expired. An uncertain push cannot be renewed or retried.',
  cancelled: 'Stop was requested. Wait for the original task and cleanup; cancellation is not proof that the remote stayed unchanged.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the app and retained files; use the original Check and Stop controls, not another Push.',
});
export function gitPushIssueHelp(issue: string): string | null { return Object.hasOwn(HELP, issue) ? HELP[issue as GitPushIssue] : null; }
