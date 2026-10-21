// Closed local configuration DATA. None of these objects grants Git, creates a
// tracking ref or proves a remote is reachable; the original native review does.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { gitBranchName } from './gitBranchesProtocol.ts';
import { GIT_REASONS } from './gitRepositoryProtocol.ts';
import type { GitReason } from './gitRepositoryProtocol.ts';

const hash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{40}$(?![\s\S])/.test(v) && v !== '0'.repeat(40);
const branch = (v: unknown): v is string => typeof v === 'string' && v.startsWith('refs/heads/') && gitBranchName(v.slice(11));
export const gitUpstreamRemote = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$(?![\s\S])/.test(v);
export const gitUpstreamRepository = (v: unknown): v is string => typeof v === 'string' &&
  /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$(?![\s\S])/.test(v);
const bytes = (v: string) => new TextEncoder().encode(v).length;
export interface GitUpstreamIdentity { readonly name: string; readonly email: string }
export function isGitUpstreamIdentity(v: unknown): v is GitUpstreamIdentity {
  return connectionBounded(v, 2048, 8, 2) && connectionKeys(v, ['name', 'email']) && typeof v.name === 'string' && bytes(v.name) <= 128 &&
    /^[\p{L}\p{N}](?:[^\x00-\x1f\x7f<>"'\\#;\p{Cs}]*[\p{L}\p{N}])?$(?![\s\S])/u.test(v.name) &&
    typeof v.email === 'string' && bytes(v.email) <= 254 &&
    /^[A-Za-z0-9][A-Za-z0-9._+%-]*@[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$(?![\s\S])/.test(v.email);
}
export interface GitUpstreamDraft { readonly remote: string; readonly repository: string; readonly name: string; readonly email: string }
export const emptyGitUpstreamDraft = (): GitUpstreamDraft => Object.freeze({ remote: 'origin', repository: '', name: '', email: '' });
export function gitUpstreamDraftFits(field: keyof GitUpstreamDraft, value: unknown): value is string {
  const limits = { remote: 64, repository: 140, name: 128, email: 254 };
  return Object.hasOwn(limits, field) && typeof value === 'string' && bytes(value) <= limits[field] && !/[\x00-\x1f\x7f\p{Cs}]/u.test(value);
}
export interface GitUpstreamAction {
  readonly kind: 'set-upstream'; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly branch: string; readonly head: string; readonly remote: string; readonly repository: string; readonly identity: GitUpstreamIdentity | null;
}
export function isGitUpstreamAction(v: unknown): v is GitUpstreamAction {
  return connectionBounded(v, 4096, 24, 3) && connectionKeys(v, ['kind', 'expectedRevision', 'expectedReferenceRevision', 'branch', 'head', 'remote', 'repository', 'identity']) &&
    v.kind === 'set-upstream' && hash(v.expectedRevision) && hash(v.expectedReferenceRevision) && branch(v.branch) && oid(v.head) &&
    gitUpstreamRemote(v.remote) && gitUpstreamRepository(v.repository) && (v.identity === null || isGitUpstreamIdentity(v.identity));
}
export function gitUpstreamAction(d: GitUpstreamDraft, source: { revision: string; head: string | null; branch: string | null }, referenceRevision: string): GitUpstreamAction | null {
  const a = { kind: 'set-upstream', expectedRevision: source.revision, expectedReferenceRevision: referenceRevision,
    head: source.head, branch: source.branch, remote: d.remote, repository: d.repository,
    identity: d.name === '' && d.email === '' ? null : { name: d.name, email: d.email } };
  return isGitUpstreamAction(a) ? Object.freeze({ ...a, identity: a.identity && Object.freeze(a.identity) }) : null;
}
export function sameUpstreamAction(a: GitUpstreamAction, b: GitUpstreamAction): boolean {
  return a.expectedRevision === b.expectedRevision && a.expectedReferenceRevision === b.expectedReferenceRevision &&
    a.branch === b.branch && a.head === b.head && a.remote === b.remote && a.repository === b.repository &&
    (a.identity === null ? b.identity === null : b.identity !== null && a.identity.name === b.identity.name && a.identity.email === b.identity.email);
}
export interface GitUpstreamAddition { readonly key: string; readonly value: string }
export interface GitUpstreamReview {
  readonly action: 'set-upstream'; readonly remote: string; readonly repository: string; readonly expectedRevision: string; readonly expectedReferenceRevision: string;
  readonly branch: string; readonly head: string; readonly expectedIndex: string; readonly originalConfig: string;
  readonly additions: readonly GitUpstreamAddition[]; readonly missingDirectories: readonly string[]; readonly unchanged: boolean; readonly reviewDigest: string;
}
export function upstreamParents(remote: string, current: string): string[] {
  const names = new Set<string>();
  for (const path of [`refs/remotes/${remote}/${current.slice(11)}`, `logs/refs/remotes/${remote}/${current.slice(11)}`]) {
    let p = path;
    while (p.includes('/')) { p = p.slice(0, p.lastIndexOf('/')); names.add(p); }
  }
  return [...names].sort((a, b) => a.split('/').length - b.split('/').length || (a < b ? -1 : a > b ? 1 : 0));
}
function missing(v: unknown, a: Pick<GitUpstreamAction, 'remote' | 'branch'>): v is readonly string[] {
  if (!Array.isArray(v) || v.length > 64 || !v.every((p) => typeof p === 'string')) return false;
  const allowed = upstreamParents(a.remote, a.branch), ordered = allowed.filter((p) => v.includes(p));
  return v.reduce((n, p) => n + bytes(p), 0) <= 2048 && v.length === ordered.length && v.every((p, i) => p === ordered[i]);
}
function additions(v: unknown, a: GitUpstreamAction): v is readonly GitUpstreamAddition[] {
  if (!Array.isArray(v) || v.length > 6 || !v.every((r) => connectionKeys(r, ['key', 'value']) && typeof r.key === 'string' && typeof r.value === 'string')) return false;
  const name = a.branch.slice(11), expected: { key: string; value: string }[] = [];
  const groups = [[{ key: `remote.${a.remote}.url`, value: `https://github.com/${a.repository}.git` },
    { key: `remote.${a.remote}.fetch`, value: `+refs/heads/*:refs/remotes/${a.remote}/*` }],
  [{ key: `branch.${name}.remote`, value: a.remote }, { key: `branch.${name}.merge`, value: a.branch }]];
  for (const group of groups) if (v.some((r) => group.some((e) => e.key === r.key))) expected.push(...group);
  if (v.some((r) => r.key.startsWith('user.'))) {
    if (!a.identity) return false;
    expected.push({ key: 'user.name', value: a.identity.name }, { key: 'user.email', value: a.identity.email });
  }
  return v.length === expected.length && v.every((r, i) => r.key === expected[i]!.key && r.value === expected[i]!.value);
}
export function isGitUpstreamReview(v: unknown, a: GitUpstreamAction): v is GitUpstreamReview {
  return isGitUpstreamAction(a) && connectionBounded(v, 32768, 512, 5) && connectionKeys(v, ['action', 'remote', 'repository', 'expectedRevision', 'expectedReferenceRevision', 'branch', 'head', 'expectedIndex', 'originalConfig', 'additions', 'missingDirectories', 'unchanged', 'reviewDigest']) &&
    v.action === a.kind && v.remote === a.remote && v.repository === a.repository && v.expectedRevision === a.expectedRevision &&
    v.expectedReferenceRevision === a.expectedReferenceRevision && v.branch === a.branch && v.head === a.head &&
    hash(v.expectedIndex) && hash(v.originalConfig) && hash(v.reviewDigest) && missing(v.missingDirectories, a) && additions(v.additions, a) &&
    v.unchanged === (v.additions.length === 0 && v.missingDirectories.length === 0);
}
export interface GitUpstreamIntent {
  readonly action: 'set-upstream'; readonly expectedRevision: string; readonly expectedReferenceRevision: string; readonly expectedRef: string; readonly expectedHead: string;
  readonly expectedIndex: string; readonly originalConfig: string; readonly candidateConfig: string; readonly remote: string; readonly repository: string;
  readonly missingDirectories: readonly string[]; readonly workingSha256: string; readonly configChanged: boolean;
}
export function isGitUpstreamIntent(v: unknown, a: GitUpstreamAction): v is GitUpstreamIntent {
  return isGitUpstreamAction(a) && connectionBounded(v, 8192, 128, 3) && connectionKeys(v, ['action', 'expectedRevision', 'expectedReferenceRevision', 'expectedRef', 'expectedHead', 'expectedIndex', 'originalConfig', 'candidateConfig', 'remote', 'repository', 'missingDirectories', 'workingSha256', 'configChanged']) &&
    v.action === a.kind && v.expectedRevision === a.expectedRevision && v.expectedReferenceRevision === a.expectedReferenceRevision &&
    v.expectedRef === a.branch && v.expectedHead === a.head && v.remote === a.remote && v.repository === a.repository &&
    hash(v.expectedIndex) && hash(v.originalConfig) && hash(v.candidateConfig) && hash(v.workingSha256) && missing(v.missingDirectories, a) &&
    typeof v.configChanged === 'boolean' && (v.configChanged || v.missingDirectories.length > 0) && (v.configChanged || v.originalConfig === v.candidateConfig);
}
export function upstreamIntentMatchesReview(v: GitUpstreamIntent, r: GitUpstreamReview): boolean {
  return !r.unchanged && v.expectedRevision === r.expectedRevision && v.expectedReferenceRevision === r.expectedReferenceRevision &&
    v.expectedRef === r.branch && v.expectedHead === r.head && v.expectedIndex === r.expectedIndex && v.originalConfig === r.originalConfig &&
    v.remote === r.remote && v.repository === r.repository && v.configChanged === (r.additions.length > 0) &&
    v.missingDirectories.length === r.missingDirectories.length && v.missingDirectories.every((p, i) => p === r.missingDirectories[i]);
}
export const UPSTREAM_REASONS = ['upstream-config', 'upstream-conflict', 'upstream-identity-required', 'upstream-layout', 'upstream-unchanged', 'upstream-parent-changed'] as const;
export type GitUpstreamReason = typeof UPSTREAM_REASONS[number];
export type GitUpstreamIssue = GitUpstreamReason | 'upstream-draft-required' | 'upstream-read-required';
export const isGitUpstreamReason = (v: unknown): v is GitUpstreamReason => typeof v === 'string' && UPSTREAM_REASONS.includes(v as GitUpstreamReason);
export interface GitUpstreamMutationResult {
  readonly operationId: string; readonly action: 'set-upstream'; readonly state: 'succeeded' | 'failed' | 'recovery-required'; readonly settlement: 'settled';
  readonly reason: GitReason | GitUpstreamReason | null; readonly observation: null; readonly intent: GitUpstreamIntent | null;
  readonly effectPhase: 'not-published' | 'directories-returned' | 'config-returned'; readonly retainedPaths: readonly string[]; readonly retainedCandidate: boolean;
}
export function isGitUpstreamMutation(v: unknown, a: GitUpstreamAction, id: string): v is GitUpstreamMutationResult {
  if (!isGitUpstreamAction(a) || !connectionBounded(v, 32768, 512, 5) || !connectionKeys(v, ['operationId', 'action', 'state', 'settlement', 'reason', 'observation', 'intent', 'effectPhase', 'retainedPaths', 'retainedCandidate']) ||
      v.operationId !== id || v.action !== a.kind || v.settlement !== 'settled' || v.observation !== null || typeof v.retainedCandidate !== 'boolean' ||
      !['not-published', 'directories-returned', 'config-returned'].includes(v.effectPhase as string) ||
      !(v.intent === null || isGitUpstreamIntent(v.intent, a)) || !Array.isArray(v.retainedPaths)) return false;
  const allowed = upstreamParents(a.remote, a.branch).map((p) => `.git/${p}`).concat('.git/config');
  const retained = v.retainedPaths;
  if (retained.length > 65 || !retained.every((p, i) => typeof p === 'string' && allowed.includes(p) && (i === 0 || retained[i - 1] < p))) return false;
  const i = v.intent as GitUpstreamIntent | null;
  if (v.effectPhase === 'config-returned' && !i?.configChanged) return false;
  if (v.state === 'succeeded') return !!i && v.reason === null && !v.retainedCandidate && v.retainedPaths.length === 0 &&
    v.effectPhase === (i.configChanged ? 'config-returned' : 'directories-returned');
  const reason = typeof v.reason === 'string' && v.reason !== 'unknown' && (GIT_REASONS.includes(v.reason as GitReason) || isGitUpstreamReason(v.reason));
  return reason && (i ? v.state === 'recovery-required' : v.state === 'failed' && v.effectPhase === 'not-published' && v.retainedPaths.length === 0 && !v.retainedCandidate);
}
export function gitUpstreamIssueHelp(v: string): string | null {
  const messages: Record<GitUpstreamIssue, string> = {
    'upstream-config': 'This local Git configuration is outside the supported safe setup. Review it manually; nothing is overwritten.',
    'upstream-conflict': 'Existing remote, branch mapping or identity conflicts with this choice. Keep it and review it manually.',
    'upstream-identity-required': 'Supply both repository-local name and email only if both are missing. Existing valid identity is preserved.',
    'upstream-layout': 'Use an attached, already committed local branch and supported protected Git directories.',
    'upstream-unchanged': 'This exact upstream and its local parent directories are already configured. Close the review; no Apply is needed.',
    'upstream-parent-changed': 'A reviewed local directory changed. Keep the original operation and files; do not retry an uncertain change.',
    'upstream-draft-required': 'Enter the GitHub owner/repository, remote alias and either both local identity fields or neither.',
    'upstream-read-required': 'Refresh local changes or read local branches before reviewing upstream setup.',
  };
  return Object.hasOwn(messages, v) ? messages[v as GitUpstreamIssue] : null;
}
