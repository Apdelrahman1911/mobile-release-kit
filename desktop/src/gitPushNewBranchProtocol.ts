// First-publication DATA is a distinct kind all the way to the original native
// owner. ZERO is an expected-old server condition, never absence evidence.
import { connectionBounded, connectionKeys, connectionNumericId, connectionOpaqueId, connectionRepository } from './githubConnectionProtocol.ts';
import { gitPushOid, gitPushReference, GIT_PUSH_EFFECT_LABELS, isGitPushReason } from './gitPushProtocol.ts';
import type { GitPushAction, GitPushReview, GitPushIntent, GitPushMutationResult } from './gitPushProtocol.ts';
import { GIT_REASONS } from './gitRepositoryProtocol.ts';
import type { GitReason } from './gitRepositoryProtocol.ts';
import type { GitReadObservation } from './gitReadProtocol.ts';
import type { GitPushAccount } from './gitPushSelection.ts';

export const GIT_PUSH_ZERO = '0'.repeat(40);
export interface GitPushNewBranchAction extends Omit<GitPushAction, 'kind' | 'remote'> {
  readonly kind: 'push-new-branch'; readonly remote: null;
}
export interface GitPushNewBranchReview extends Omit<GitPushReview, 'action' | 'remote' | 'trackingRef' | 'basis'> {
  readonly action: 'push-new-branch'; readonly remote: null; readonly trackingRef: null;
  readonly basis: 'first-publication-no-upstream';
}
export interface GitPushNewBranchIntent extends Omit<GitPushIntent, 'action' | 'remote'> {
  readonly action: 'push-new-branch'; readonly remote: null;
}
export interface GitPushNewBranchMutation extends Omit<GitPushMutationResult, 'action' | 'intent'> {
  readonly action: 'push-new-branch'; readonly intent: GitPushNewBranchIntent | null;
}
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const login = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$(?![\s\S])/.test(v);

export function isGitPushNewBranchAction(v: unknown): v is GitPushNewBranchAction {
  return connectionBounded(v, 4096, 40, 2) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'remote',
    'localRef', 'remoteRef', 'oldOid', 'newOid', 'connectionSessionId', 'expectedConnectionRevision']) && v.kind === 'push-new-branch' &&
    digest(v.expectedRevision) && digest(v.expectedReferenceRevision) && v.remote === null && gitPushReference(v.localRef) &&
    v.remoteRef === v.localRef && v.oldOid === GIT_PUSH_ZERO && gitPushOid(v.newOid) && connectionOpaqueId(v.connectionSessionId) &&
    typeof v.expectedConnectionRevision === 'number' && Number.isInteger(v.expectedConnectionRevision) &&
    v.expectedConnectionRevision > 0 && v.expectedConnectionRevision < 0xffffffff;
}
export function isGitPushNewBranchReview(v: unknown, expected: GitPushNewBranchAction): v is GitPushNewBranchReview {
  if (!isGitPushNewBranchAction(expected) || !connectionBounded(v, 16 * 1024, 200, 3) ||
      !connectionKeys(v, ['action', 'remote', 'repository', 'accountId', 'repositoryId', 'login', 'branch', 'head', 'upstreamRef',
        'expectedRemoteOid', 'trackingRef', 'commits', 'expectedRevision', 'expectedReferenceRevision', 'expectedIndex', 'basis', 'withheld', 'reviewDigest']) ||
      v.action !== 'push-new-branch' || v.remote !== null || v.trackingRef !== null || v.branch !== expected.localRef || v.upstreamRef !== expected.remoteRef ||
      v.head !== expected.newOid || v.expectedRemoteOid !== GIT_PUSH_ZERO || v.expectedRevision !== expected.expectedRevision ||
      v.expectedReferenceRevision !== expected.expectedReferenceRevision || !connectionRepository(v.repository) || !connectionNumericId(v.accountId) ||
      !connectionNumericId(v.repositoryId) || !login(v.login) || !digest(v.expectedIndex) || !digest(v.reviewDigest) || v.basis !== 'first-publication-no-upstream' ||
      !Array.isArray(v.withheld) || v.withheld.length !== 5 || v.withheld.join('|') !== 'messages|authors|emails|signatures|objects' ||
      !Array.isArray(v.commits) || v.commits.length < 1 || v.commits.length > 64 || v.commits.at(-1) !== expected.newOid) return false;
  return v.commits.every((oid, i, all) => gitPushOid(oid) && !all.slice(0, i).includes(oid));
}
export function isGitPushNewBranchIntent(v: unknown, expected: GitPushNewBranchAction): v is GitPushNewBranchIntent {
  return isGitPushNewBranchAction(expected) && connectionBounded(v, 8192, 64, 2) && connectionKeys(v, ['action', 'reviewDigest',
    'expectedRevision', 'expectedReferenceRevision', 'expectedIndex', 'remote', 'repository', 'accountId', 'repositoryId',
    'localRef', 'remoteRef', 'oldOid', 'newOid', 'commitsSha256']) && v.action === 'push-new-branch' && v.remote === null &&
    v.expectedRevision === expected.expectedRevision && v.expectedReferenceRevision === expected.expectedReferenceRevision &&
    v.localRef === expected.localRef && v.remoteRef === expected.remoteRef && v.oldOid === GIT_PUSH_ZERO && v.newOid === expected.newOid &&
    connectionRepository(v.repository) && connectionNumericId(v.accountId) && connectionNumericId(v.repositoryId) &&
    digest(v.reviewDigest) && digest(v.expectedIndex) && digest(v.commitsSha256);
}
export function pushNewBranchIntentMatchesReview(v: GitPushNewBranchIntent, r: GitPushNewBranchReview): boolean {
  return v.action === r.action && v.reviewDigest === r.reviewDigest && v.expectedRevision === r.expectedRevision &&
    v.expectedReferenceRevision === r.expectedReferenceRevision && v.expectedIndex === r.expectedIndex && v.remote === r.remote &&
    v.repository === r.repository && v.accountId === r.accountId && v.repositoryId === r.repositoryId && v.localRef === r.branch &&
    v.remoteRef === r.upstreamRef && v.oldOid === r.expectedRemoteOid && v.newOid === r.head;
}
export function isGitPushNewBranchMutation(v: unknown, expected: GitPushNewBranchAction, id: string): v is GitPushNewBranchMutation {
  if (!isGitPushNewBranchAction(expected) || !connectionBounded(v, 16 * 1024, 100, 3) ||
      !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths']) ||
      v.operationId !== id || v.action !== 'push-new-branch' || v.settlement !== 'settled' || v.observation !== null ||
      !(v.intent === null || isGitPushNewBranchIntent(v.intent, expected)) || typeof v.effectPhase !== 'string' ||
      !Object.hasOwn(GIT_PUSH_EFFECT_LABELS, v.effectPhase) || !Array.isArray(v.retainedPaths) || v.retainedPaths.length > 1 ||
      !v.retainedPaths.every((p) => typeof p === 'string' && /^(?:mrk-git-[a-z0-9_]{1,32}\/)?mrk-git-push-[a-z0-9_]{1,32}$(?![\s\S])/.test(p))) return false;
  if (v.state === 'succeeded') return v.intent !== null && v.reason === null && v.effectPhase === 'remote-returned' && v.retainedPaths.length === 0;
  return (v.state === 'failed' || v.state === 'recovery-required') && (v.intent !== null || v.effectPhase === 'not-sent') &&
    (isGitPushReason(v.reason) || typeof v.reason === 'string' && GIT_REASONS.includes(v.reason as GitReason));
}

export function gitPushNewBranchActionFor(local: GitReadObservation, account: GitPushAccount): GitPushNewBranchAction | null {
  const o = local.observation;
  // The native fresh parsed config independently requires BOTH branch.remote
  // and branch.merge absent. This read label alone is not that authority.
  if (o.unborn || o.detached || !o.head || !o.branch || local.tracking.state !== 'not-configured') return null;
  const action = { kind: 'push-new-branch' as const, expectedRevision: o.revision, expectedReferenceRevision: local.referenceRevision,
    remote: null, localRef: o.branch, remoteRef: o.branch, oldOid: GIT_PUSH_ZERO, newOid: o.head,
    connectionSessionId: account.sessionId, expectedConnectionRevision: account.revision };
  return isGitPushNewBranchAction(action) ? Object.freeze(action) : null;
}
