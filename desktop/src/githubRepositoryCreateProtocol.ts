// Empty repository creation DATA only. Account observation is not permission to
// create, and a name-only lookup is never evidence that our POST succeeded.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numeric, connectionOpaqueId as id,
  connectionUtc as utc, sameConnectionData as same } from './githubConnectionProtocol.ts';

export const REPOSITORY_CREATE_EVENT = 'github-repository-create-status';
export const REPOSITORY_CREATE_REASONS = ['none', 'invalid-input', 'target-changed', 'repository-exists', 'membership-unconfirmed',
  'permission-unconfirmed', 'unauthorized', 'forbidden', 'not-found-or-inaccessible', 'rate-limited', 'network-unavailable',
  'tls-failed', 'response-invalid', 'response-limit', 'expired', 'cancelled', 'journal-unavailable', 'previous-attempt',
  'unresolved', 'unattributed', 'resources-unavailable', 'runtime-unavailable', 'unqualified', 'not-connected', 'busy',
  'cleanup-unknown', 'consent-expired'] as const;
export type RepositoryCreateReason = typeof REPOSITORY_CREATE_REASONS[number];
export type RepositoryCreateKind = 'prepare' | 'create' | 'pending' | 'reconcile';
export type RepositoryVisibility = 'private' | 'public';
export type RepositoryOwnerKind = 'user' | 'organization';
export interface RepositoryCreateTarget {
  projectBinding: string; repository: string; accountId: string; accountLogin: string;
  ownerKind: RepositoryOwnerKind; visibility: RepositoryVisibility; marker: string;
}
export interface RepositoryCreatePrepared {
  target: RepositoryCreateTarget; ownerId: string; membership: 'self' | 'active-member' | 'active-admin';
  repositoryObservation: 'not-found-or-inaccessible'; creationPermission: 'not-proven'; autoInit: false; confirmation: string;
}
export interface CreatedRepository { id: string; fullName: string; ownerId: string; visibility: RepositoryVisibility; url: string }
export interface RepositoryCreatePending { prepared: RepositoryCreatePrepared; claimed: boolean; acknowledged: CreatedRepository | null }
export interface RepositoryCreateConsent { id: string; expiresAt: string; prepared: RepositoryCreatePrepared }
export interface RepositoryCreateOperation {
  id: string; projectId: string; kind: RepositoryCreateKind; target: RepositoryCreateTarget;
  phase: 'running' | 'stopping' | 'settled' | 'cleanup-unknown'; reason: RepositoryCreateReason;
  effect: 'none' | 'not-sent' | 'potentially-applied' | 'created-observed' | 'unresolved' | 'found-unattributed';
}
export interface RepositoryCreateStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: RepositoryCreateReason;
  operation: RepositoryCreateOperation | null; consent: RepositoryCreateConsent | null; pending: RepositoryCreatePending[]; observed: CreatedRepository | null;
}
export interface RepositoryCreateBase { sessionId: string; expectedRevision: number }
export interface RepositoryCreatePrepare extends RepositoryCreateBase { expectedConnectionRevision: number; ownerKind: RepositoryOwnerKind; visibility: RepositoryVisibility }
export interface RepositoryCreateApply extends RepositoryCreateBase { consentId: string; confirm: true }
export interface RepositoryCreateList extends RepositoryCreateBase { expectedConnectionRevision: number }
export interface RepositoryCreateReconcile extends RepositoryCreateBase { marker: string }
export interface RepositoryCreateDiscard extends RepositoryCreateBase { consentId: string }
export interface RepositoryCreatePort {
  readonly mode: 'native';
  status(): Promise<unknown>;
  prepare(args: RepositoryCreatePrepare): Promise<unknown>;
  create(args: RepositoryCreateApply): Promise<unknown>;
  pending(args: RepositoryCreateList): Promise<unknown>;
  reconcile(args: RepositoryCreateReconcile): Promise<unknown>;
  discard(args: RepositoryCreateDiscard): Promise<unknown>;
  cancel(args: { operationId: string }): Promise<unknown>;
  subscribe(listener: (value: unknown) => void): Promise<() => void>;
}
export type RepositoryCreateCommand = `github_repository_create_${'status' | 'prepare' | 'create' | 'pending' | 'reconcile' | 'discard' | 'cancel'}`;
const oneOf = <T extends string>(v: unknown, values: readonly T[]): v is T => typeof v === 'string' && (values as readonly string[]).includes(v);
const hex = (v: unknown, n: number): v is string => typeof v === 'string' && v.length === n && !/[^0-9a-f]/.test(v);
const rev = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v > 0 && v <= 0xffff_fffe;
export const repositoryCreateLogin = (v: unknown): v is string => typeof v === 'string' && v.length <= 39 && !v.includes('--') &&
  /^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$(?![\s\S])/.test(v);
export function repositoryCreateCoordinate(v: unknown): v is string {
  if (typeof v !== 'string') return false;
  const pieces = v.split('/'), [owner, name] = pieces;
  return pieces.length === 2 && repositoryCreateLogin(owner) && typeof name === 'string' && name.length <= 100 &&
    name !== '.' && name !== '..' && !name.toLowerCase().endsWith('.git') && /^[A-Za-z0-9._-]+$(?![\s\S])/.test(name);
}
export const repositoryCreateConfirmation = (t: RepositoryCreateTarget): string => `Create ${t.repository} as a ${t.visibility.toUpperCase()} GitHub repository? ` +
  (t.visibility === 'public' ? 'Anyone can see a public repository and files you later upload. ' : '') +
  'No local files, Git commits, remotes, pushes or workflows are added. Organization rules and token permissions still apply. Stopping cannot undo a sent request.';
function target(v: unknown): v is RepositoryCreateTarget {
  return keys(v, ['projectBinding', 'repository', 'accountId', 'accountLogin', 'ownerKind', 'visibility', 'marker']) &&
    hex(v.projectBinding, 64) && repositoryCreateCoordinate(v.repository) && numeric(v.accountId) && repositoryCreateLogin(v.accountLogin) &&
    oneOf(v.ownerKind, ['user', 'organization']) && oneOf(v.visibility, ['private', 'public']) && hex(v.marker, 32) &&
    (v.ownerKind !== 'user' || v.repository.split('/')[0]?.toLowerCase() === v.accountLogin.toLowerCase());
}
function prepared(v: unknown): v is RepositoryCreatePrepared {
  return keys(v, ['target', 'ownerId', 'membership', 'repositoryObservation', 'creationPermission', 'autoInit', 'confirmation']) &&
    target(v.target) && numeric(v.ownerId) && (v.target.ownerKind === 'user' ? v.membership === 'self' && v.ownerId === v.target.accountId :
      oneOf(v.membership, ['active-member', 'active-admin'])) && v.repositoryObservation === 'not-found-or-inaccessible' &&
    v.creationPermission === 'not-proven' && v.autoInit === false && v.confirmation === repositoryCreateConfirmation(v.target);
}
function repository(v: unknown, t: RepositoryCreateTarget, ownerId?: string): v is CreatedRepository {
  return keys(v, ['id', 'fullName', 'ownerId', 'visibility', 'url']) && numeric(v.id) && numeric(v.ownerId) &&
    (ownerId === undefined || v.ownerId === ownerId) && repositoryCreateCoordinate(v.fullName) &&
    v.fullName.toLowerCase() === t.repository.toLowerCase() && v.visibility === t.visibility && v.url === `https://github.com/${v.fullName}`;
}
export function parseRepositoryCreateStatus(raw: unknown): RepositoryCreateStatus | null {
  try {
    const v = copyBoundedComparisonData(raw, 128 * 1024, 8192);
    if (!keys(v, ['schemaVersion', 'revision', 'sessionId', 'available', 'reason', 'operation', 'consent', 'pending', 'observed']) ||
      v.schemaVersion !== 1 || !rev(v.revision) || !(v.sessionId === null || id(v.sessionId)) || typeof v.available !== 'boolean' ||
      !oneOf(v.reason, REPOSITORY_CREATE_REASONS) || v.available !== (v.reason === 'none') || !Array.isArray(v.pending) || v.pending.length > 32) return null;
    const markers = new Set<string>();
    for (const row of v.pending) {
      if (!keys(row, ['prepared', 'claimed', 'acknowledged']) || !prepared(row.prepared) || typeof row.claimed !== 'boolean' ||
        row.acknowledged !== null && (!row.claimed || !repository(row.acknowledged, row.prepared.target, row.prepared.ownerId)) ||
        markers.has(row.prepared.target.marker)) return null;
      markers.add(row.prepared.target.marker);
    }
    const o = v.operation;
    if (o !== null && (!keys(o, ['id', 'projectId', 'kind', 'target', 'phase', 'reason', 'effect']) || !id(o.id) || !id(o.projectId) ||
      !oneOf(o.kind, ['prepare', 'create', 'pending', 'reconcile']) || !target(o.target) || !oneOf(o.phase, ['running', 'stopping', 'settled', 'cleanup-unknown']) ||
      !oneOf(o.reason, REPOSITORY_CREATE_REASONS) || !oneOf(o.effect, ['none', 'not-sent', 'potentially-applied', 'created-observed', 'unresolved', 'found-unattributed']) ||
      v.sessionId === null || o.phase !== 'settled' && v.available || o.phase === 'cleanup-unknown' && o.reason !== 'cleanup-unknown' ||
      ['prepare', 'pending'].includes(o.kind) && o.effect !== 'none' || o.kind === 'create' && !['not-sent', 'potentially-applied', 'created-observed'].includes(o.effect) ||
      o.phase !== 'settled' && ['created-observed', 'found-unattributed', 'unresolved'].includes(o.effect))) return null;
    if (v.consent !== null && (!keys(v.consent, ['id', 'expiresAt', 'prepared']) || !hex(v.consent.id, 32) || !utc(v.consent.expiresAt) ||
      !prepared(v.consent.prepared) || !keys(o, ['id', 'projectId', 'kind', 'target', 'phase', 'reason', 'effect']) || o.kind !== 'prepare' ||
      o.phase !== 'settled' || o.reason !== 'none' || !same(o.target, v.consent.prepared.target))) return null;
    if (v.observed !== null && (!keys(o, ['id', 'projectId', 'kind', 'target', 'phase', 'reason', 'effect']) || !target(o.target) ||
      o.phase !== 'settled' || !oneOf(o.effect, ['created-observed', 'found-unattributed']) || !repository(v.observed, o.target))) return null;
    if (o && typeof o === 'object' && 'effect' in o && (o.effect === 'created-observed' && (v.observed === null || o.reason !== 'none') ||
      o.effect === 'found-unattributed' && (v.observed === null || o.reason !== 'unattributed'))) return null;
    return v as unknown as RepositoryCreateStatus;
  } catch { return null; }
}
export function encodeRepositoryCreateRequest(command: RepositoryCreateCommand, raw: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(raw, 1024, 32);
    const base = (v: Record<string, unknown>) => id(v.sessionId) && rev(v.expectedRevision);
    const valid = command === 'github_repository_create_status' ? keys(v, []) : command === 'github_repository_create_cancel' ?
      keys(v, ['operationId']) && id(v.operationId) : command === 'github_repository_create_prepare' ?
      keys(v, ['sessionId', 'expectedRevision', 'expectedConnectionRevision', 'ownerKind', 'visibility']) && base(v) && rev(v.expectedConnectionRevision) &&
        oneOf(v.ownerKind, ['user', 'organization']) && oneOf(v.visibility, ['private', 'public']) : command === 'github_repository_create_create' ?
      keys(v, ['sessionId', 'expectedRevision', 'consentId', 'confirm']) && base(v) && hex(v.consentId, 32) && v.confirm === true :
      command === 'github_repository_create_pending' ? keys(v, ['sessionId', 'expectedRevision', 'expectedConnectionRevision']) && base(v) && rev(v.expectedConnectionRevision) :
      command === 'github_repository_create_reconcile' ? keys(v, ['sessionId', 'expectedRevision', 'marker']) && base(v) && hex(v.marker, 32) :
      command === 'github_repository_create_discard' && keys(v, ['sessionId', 'expectedRevision', 'consentId']) && base(v) && hex(v.consentId, 32);
    if (!valid) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.byteLength <= 1024 ? bytes : null;
  } catch { return null; }
}
export const REPOSITORY_CREATE_HELP: Readonly<Record<RepositoryCreateReason, string>> = Object.freeze({
  none: 'Review an empty GitHub repository, then choose Create. No local files are uploaded.',
  'invalid-input': 'Use an account or organization name and repository name, not a URL, path or credential.',
  'target-changed': 'The project, account or review changed. Keep the previous result; review the intended repository again only after it settles.',
  'repository-exists': 'That repository already exists or the name conflicts. It is not overwritten.',
  'membership-unconfirmed': 'An active organization membership could not be confirmed. Check your organization invitation and account.',
  'permission-unconfirmed': 'GitHub did not permit this creation. Organization rules or token permissions may apply.',
  unauthorized: 'GitHub rejected this account session. Finish the original task before reconnecting.',
  forbidden: 'GitHub denied access. Check the selected account, token permissions and organization rules; access is not upgraded automatically.',
  'not-found-or-inaccessible': 'GitHub did not return this repository. It may be missing or inaccessible; this does not prove the name is free.',
  'rate-limited': 'GitHub requested a pause. No automatic retry or cooldown bypass is used.',
  'network-unavailable': 'The reply was unavailable. A sent Create may have applied; check the saved attempt rather than repeating it.',
  'tls-failed': 'The secure GitHub connection failed. No insecure or alternate endpoint is used.',
  'response-invalid': 'The original reply could not be verified. Check status; do not repeat Create.',
  'response-limit': 'The bounded response could not be completely checked. Partial data does not authorize creation.',
  expired: 'The original session or review expired. Check previous attempts before starting again.',
  cancelled: 'Stopping prevents remaining work but cannot undo a sent Create. Check the saved attempt.',
  'journal-unavailable': 'The protected local attempt record could not be read or settled. Keep the app and its files; do not repeat creation.',
  'previous-attempt': 'This owner and repository name already have a saved attempt. Check that attempt; another Create is blocked.',
  unresolved: 'The previous request remains unresolved. Checking again is read-only and never repeats Create.',
  unattributed: 'A repository with that name was found, but there is no confirmed original creation ID. It was not adopted as our successful Create.',
  'resources-unavailable': 'The original operation could not be safely retained. No replacement operation is started.',
  'runtime-unavailable': 'Repository creation is unavailable in this installed runtime.',
  unqualified: 'This installed build has not admitted repository creation. Browser preview cannot create repositories.',
  'not-connected': 'Connect and verify the intended GitHub account above. An existing repository is not required for this task.',
  busy: 'An original task is still running or closing. Check status and Stop remain available.',
  'cleanup-unknown': 'Original cleanup is unconfirmed. Keep the app and its files; do not reconnect or repeat Create to dismiss this warning.',
  'consent-expired': 'This one-use review expired or was closed. It cannot be reused.',
});
export function repositoryCreateError(raw: unknown): { reason: RepositoryCreateReason; notAdmitted: boolean } {
  try {
    const d = raw && typeof raw === 'object' ? Object.getOwnPropertyDescriptor(raw, 'code') : null;
    const code: unknown = d && Object.hasOwn(d, 'value') ? d.value : null;
    if (typeof code === 'string' && code.startsWith('github_repository_create_refused_')) {
      const reason = code.slice('github_repository_create_refused_'.length).replaceAll('_', '-');
      if (oneOf(reason, REPOSITORY_CREATE_REASONS)) return { reason, notAdmitted: oneOf(reason, ['invalid-input', 'target-changed',
        'unqualified', 'not-connected', 'busy', 'consent-expired', 'expired', 'rate-limited', 'resources-unavailable', 'runtime-unavailable']) };
    }
  } catch { /* Do not read getters, raw messages or private diagnostics. */ }
  return { reason: 'response-invalid', notAdmitted: false };
}
