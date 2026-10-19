// Closed public DATA for the original native GitRead profile. No absolute
// repository paths, executable paths, tokens or generic command capability.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { GIT_REASONS, parseGitDiff, parseGitObservation } from './gitRepositoryProtocol.ts';
import type { GitDiff, GitObservation, GitReason } from './gitRepositoryProtocol.ts';

export interface GitReadApi {
  start(raw: Uint8Array): Promise<unknown>;
  status(raw: Uint8Array): Promise<unknown>;
  cancel(raw: Uint8Array): Promise<unknown>;
}
// Root supplies only the actual retained native invoke. Preview has no port;
// neither a successful status nor this factory manufactures qualification.
export function createGitReadApi(mode: string, invoke: (command: string, raw: Uint8Array) => Promise<unknown>): GitReadApi | null {
  if (mode !== 'native') return null;
  const call = (name: 'start' | 'status' | 'cancel', raw: Uint8Array): Promise<unknown> => {
    const command = `git_read_${name}`;
    if (!(raw instanceof Uint8Array) || raw.length + command.length + 32 > (name === 'start' ? 96 * 1024 : 1024)) {
      return Promise.reject(new Error('Invalid local Git request.'));
    }
    return invoke(command, raw.slice());
  };
  return Object.freeze({ start: (raw: Uint8Array) => call('start', raw), status: (raw: Uint8Array) => call('status', raw),
    cancel: (raw: Uint8Array) => call('cancel', raw) });
}
export interface GitReadAction { readonly kind: 'observe' | 'diff' | 'history'; readonly expectedRevision: string | null;
  readonly paths: readonly string[]; readonly staged: boolean }
export interface GitReadContext { readonly projectId: string; readonly generation: number; readonly revision: string }
export interface GitTracking { readonly state: 'detached' | 'not-configured' | 'unborn' | 'unsupported' | 'gone' | 'shallow' | 'limit' | 'complete';
  readonly remote: string | null; readonly mergeRef: string | null; readonly localRef: string | null; readonly head: string | null;
  readonly ahead: number | null; readonly behind: number | null }
export interface GitReadObservation { readonly observation: GitObservation; readonly referenceRevision: string;
  readonly tracking: GitTracking; readonly basis: 'local-refs-no-fetch' }
export interface GitReadHistory { readonly revision: string; readonly referenceRevision: string; readonly head: string | null;
  readonly commits: readonly { readonly oid: string; readonly parents: readonly string[]; readonly committedAt: number }[];
  readonly hasMore: boolean; readonly shallow: boolean; readonly withheld: readonly ['message', 'author', 'email', 'signature']; readonly basis: 'local-refs-no-fetch' }
export type GitReadResult = GitReadObservation | GitReadHistory | GitDiff;
export interface GitReadOperation { readonly operationId: string; readonly context: GitReadContext; readonly action: GitReadAction;
  readonly phase: 'starting' | 'running' | 'stopping' | 'settled' | 'cleanup-unknown';
  readonly outcome: 'ok' | 'refused' | 'cancelled' | 'timed-out' | 'cleanup-unknown' | null;
  readonly reason: GitReason | null; readonly result: GitReadResult | null }
export interface GitReadStatus { readonly schemaVersion: 1; readonly documentRevision: number; readonly available: boolean;
  readonly operation: GitReadOperation | null }

export interface GitReadStartRequest { readonly projectId: string; readonly expectedDocumentRevision: number; readonly action: GitReadAction }
export type GitReadStartRefusal = 'invalid-input' | 'stale-observation' | 'unavailable' | 'busy';
export type GitReadStartResult = { readonly schemaVersion: 1; readonly admission: 'started'; readonly request: GitReadStartRequest;
  readonly status: GitReadStatus; readonly reason: null } | { readonly schemaVersion: 1; readonly admission: 'refused';
  readonly request: GitReadStartRequest; readonly status: GitReadStatus; readonly reason: GitReadStartRefusal };

const utf8 = new TextEncoder();
const id = (v: unknown): v is string => typeof v === 'string' && /^[a-zA-Z0-9_-]{1,64}$(?![\s\S])/.test(v);
const digest = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$(?![\s\S])/.test(v);
const u32 = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
const string = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max &&
  !/[\x00-\x1f\x7f\p{Cs}]/u.test(v) && utf8.encode(v).length <= max;
const nullable = (v: unknown, check: (v: unknown) => boolean) => v === null || check(v);
const reference = (v: unknown): v is string => string(v, 1024) && v.startsWith('refs/') && !/[\x00-\x20\x7f~^:?*\[\\]/.test(v) &&
  !v.includes('..') && !v.includes('@{') && v.split('/').every((p) => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
function path(v: unknown): v is string { return string(v, 1024) && !v.includes('\\') && v.split('/').length <= 32 &&
  v.split('/').every((p) => !['', '.', '..', '.git'].includes(p) && utf8.encode(p).length <= 255); }
// Match Python scalar/UTF-8 and Rust String order, not locale or UTF-16 order.
export function gitReadPathOrder(a: string, b: string): number {
  const left = utf8.encode(a), right = utf8.encode(b);
  for (let i = 0; i < Math.min(left.length, right.length); i += 1) if (left[i] !== right[i]) return left[i]! - right[i]!;
  return left.length - right.length;
}
function action(v: unknown): v is GitReadAction {
  if (!connectionKeys(v, ['kind', 'expectedRevision', 'paths', 'staged']) || !Array.isArray(v.paths) ||
      typeof v.staged !== 'boolean' || v.paths.length > 64 || !v.paths.every(path)) return false;
  const paths = v.paths;
  if (!paths.every((p, i) => i === 0 || gitReadPathOrder(paths[i - 1] as string, p) < 0)) return false;
  return v.kind === 'observe' ? v.expectedRevision === null && !v.paths.length && !v.staged :
    digest(v.expectedRevision) && (v.kind === 'history' ? !v.paths.length && !v.staged : v.kind === 'diff' && v.paths.length > 0);
}
function tracking(v: unknown, observed: GitObservation): boolean {
  if (!connectionKeys(v, ['state', 'remote', 'mergeRef', 'localRef', 'head', 'ahead', 'behind']) ||
      !nullable(v.remote, (s) => string(s, 128)) || !nullable(v.mergeRef, reference) || !nullable(v.localRef, reference) || !nullable(v.head, oid)) return false;
  const allEmpty = ['remote', 'mergeRef', 'localRef', 'head', 'ahead', 'behind'].every((k) => v[k] === null);
  const pair = v.remote !== null && v.mergeRef !== null;
  if ((v.state === 'detached') !== observed.detached || observed.unborn && !['unborn', 'unsupported'].includes(v.state as string) ||
      v.state === 'unborn' && !observed.unborn || v.head !== null && (v.head as string).length !== observed.head?.length) return false;
  switch (v.state) {
    case 'detached': case 'not-configured': return allEmpty;
    case 'unborn': case 'unsupported': return (allEmpty || pair) && ['localRef', 'head', 'ahead', 'behind'].every((k) => v[k] === null);
    case 'gone': return pair && v.localRef !== null && ['head', 'ahead', 'behind'].every((k) => v[k] === null);
    case 'shallow': case 'limit': return pair && v.localRef !== null && v.head !== null && v.ahead === null && v.behind === null;
    case 'complete': return pair && v.localRef !== null && v.head !== null && u32(v.ahead) && u32(v.behind) && v.ahead + v.behind <= 10000;
    default: return false;
  }
}
function result(v: unknown, expected: GitReadAction): boolean {
  if (expected.kind === 'observe') {
    if (!connectionKeys(v, ['observation', 'referenceRevision', 'tracking', 'basis'])) return false;
    const observed = parseGitObservation(v.observation);
    return !!observed && digest(v.referenceRevision) && v.basis === 'local-refs-no-fetch' && tracking(v.tracking, observed);
  }
  if (expected.kind === 'diff') {
    const diff = parseGitDiff(v);
    return !!diff && diff.revision === expected.expectedRevision && diff.staged === expected.staged &&
      diff.paths.length === expected.paths.length && diff.paths.every((p, i) => p === expected.paths[i]);
  }
  if (!connectionKeys(v, ['revision', 'referenceRevision', 'head', 'commits', 'hasMore', 'shallow', 'withheld', 'basis']) ||
      v.revision !== expected.expectedRevision || !digest(v.referenceRevision) || !nullable(v.head, oid) ||
      !Array.isArray(v.commits) || v.commits.length > 25 || typeof v.hasMore !== 'boolean' || typeof v.shallow !== 'boolean' ||
      v.basis !== 'local-refs-no-fetch' || JSON.stringify(v.withheld) !== '["message","author","email","signature"]' ||
      (v.commits.length === 0) !== (v.head === null) || v.commits.length !== 25 && v.hasMore ||
      v.commits.length && v.commits[0]?.oid !== v.head) return false;
  const seen = new Set<string>();
  return v.commits.every((c) => {
    if (!connectionKeys(c, ['oid', 'parents', 'committedAt']) || !oid(c.oid) || seen.has(c.oid) || c.oid.length !== (v.head as string).length ||
        !Array.isArray(c.parents) || c.parents.length > 16 || new Set(c.parents).size !== c.parents.length ||
        !c.parents.every((p) => oid(p) && p !== c.oid && p.length === (c.oid as string).length) ||
        typeof c.committedAt !== 'number' || !Number.isSafeInteger(c.committedAt) || c.committedAt < 0) return false;
    seen.add(c.oid); return true;
  });
}
function operation(v: unknown): boolean {
  if (!connectionKeys(v, ['operationId', 'context', 'action', 'phase', 'outcome', 'reason', 'result']) || !id(v.operationId) ||
      !connectionKeys(v.context, ['projectId', 'generation', 'revision']) || !id(v.context.projectId) || !u32(v.context.generation) ||
      !id(v.context.revision) || !action(v.action)) return false;
  if (v.phase === 'cleanup-unknown') return v.outcome === 'cleanup-unknown' && v.reason === 'unknown' && v.result === null;
  if (['starting', 'running', 'stopping'].includes(v.phase as string)) return v.outcome === null && v.reason === null && v.result === null;
  if (v.phase !== 'settled') return false;
  return v.outcome === 'ok' ? v.reason === null && result(v.result, v.action) :
    ['refused', 'cancelled', 'timed-out'].includes(v.outcome as string) && typeof v.reason === 'string' &&
    GIT_REASONS.includes(v.reason as GitReason) && v.reason !== 'unknown' && v.result === null;
}
export function parseGitReadStatus(value: unknown): GitReadStatus | null {
  try {
    if (!connectionBounded(value, 2 * 1024 * 1024, 25000, 12) ||
        !connectionKeys(value, ['schemaVersion', 'documentRevision', 'available', 'operation']) || value.schemaVersion !== 1 ||
        !u32(value.documentRevision) || typeof value.available !== 'boolean' || value.operation !== null && !operation(value.operation)) return null;
    const copy = structuredClone(value);
    const freeze = (v: unknown): void => { if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); } };
    freeze(copy); return copy as unknown as GitReadStatus;
  } catch { return null; }
}
export function parseGitReadStartResult(value: unknown): GitReadStartResult | null {
  try {
    if (!connectionBounded(value, 2 * 1024 * 1024 + 96 * 1024, 27000, 13) ||
        !connectionKeys(value, ['schemaVersion', 'admission', 'request', 'status', 'reason']) || value.schemaVersion !== 1 ||
        !gitReadRequest('start', value.request)) return null;
    const status = parseGitReadStatus(value.status);
    if (!status) return null;
    if (value.admission === 'started') {
      if (value.reason !== null || !status.operation) return null;
    } else if (value.admission !== 'refused' || !['invalid-input', 'stale-observation', 'unavailable', 'busy'].includes(value.reason as string)) return null;
    const copy = structuredClone(value);
    const freeze = (v: unknown): void => { if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); } };
    freeze(copy); return copy as unknown as GitReadStartResult;
  } catch { return null; }
}
export function gitReadRequest(name: 'start' | 'status' | 'cancel', value: unknown): Uint8Array | null {
  try {
    if (!connectionBounded(value, 96 * 1024, 1000, 5)) return null;
    const valid = name === 'status' ? connectionKeys(value, []) : name === 'cancel' ?
      connectionKeys(value, ['operationId']) && id(value.operationId) : connectionKeys(value, ['projectId', 'expectedDocumentRevision', 'action']) &&
      id(value.projectId) && u32(value.expectedDocumentRevision) && value.expectedDocumentRevision > 0 && value.expectedDocumentRevision < 0xffffffff && action(value.action);
    if (!valid) return null;
    const raw = utf8.encode(JSON.stringify(value));
    return raw.length + `git_read_${name}`.length + 32 <= (name === 'start' ? 96 * 1024 : 1024) ? raw : null;
  } catch { return null; }
}
export function sameGitReadAction(a: GitReadAction, b: GitReadAction): boolean {
  return a.kind === b.kind && a.expectedRevision === b.expectedRevision && a.staged === b.staged &&
    a.paths.length === b.paths.length && a.paths.every((p, i) => p === b.paths[i]);
}
export function sameGitReadContext(a: GitReadContext, b: GitReadContext): boolean {
  return a.projectId === b.projectId && a.generation === b.generation && a.revision === b.revision;
}
// Only already-decoded, bounded, immutable DATA enters this comparison. Wire
// object-key order is not terminal evidence; every actual field/value still is.
export function sameGitReadOperation(a: GitReadOperation, b: GitReadOperation): boolean {
  const canonical = (value: unknown): unknown => Array.isArray(value) ? value.map(canonical) :
    value !== null && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort()
      .map((key) => [key, canonical((value as Record<string, unknown>)[key])])) : value;
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}
