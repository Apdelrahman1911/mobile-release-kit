// Pasted workflow output is UNVERIFIED proposed DATA. These comparisons do not
// inspect a ledger, reserve a number, grant a native edit, or establish CI use.
import { connectionBounded, connectionKeys } from './githubConnectionProtocol.ts';
import { sameGitLocalData } from './gitLocalProtocol.ts';
import type { GitReadController, GitReadView } from './gitReadController.ts';
import type { GitRepositoryController, GitRepositoryView } from './gitRepositoryController.ts';
import type { VersionCheckout, VersionPreparedView } from './releaseVersionEdit.ts';

export const HOSTED_VERSION_IMPORT_LIMIT = 8192;
export interface HostedVersionProposal {
  readonly candidateId: string; readonly rowSha256: string;
  readonly sourceCommit: string; readonly sourceRef: string; readonly configSha256: string;
  readonly path: string; readonly beforeSha256: string; readonly afterSha256: string;
  readonly name: string; readonly build: string; readonly commitTrailer: string;
}
export interface HostedImportGitSource {
  readonly session: object | null; readonly projectId: string | null; readonly epoch: number;
  readonly repository: GitRepositoryController | null; readonly reader: GitReadController | null;
}
// Retained only in the existing controller's private field, never in its
// recursively frozen public state. These are the actual App-owned instances.
export interface HostedImportGitCapture {
  readonly source: HostedImportGitSource;
  readonly repository: GitRepositoryView; readonly read: GitReadView;
}
const utf8 = new TextEncoder();
const hash = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{64}$(?![\s\S])/.test(v);
const oid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{40}$(?![\s\S])/.test(v);
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max &&
  !/[\p{Cc}\p{Cs}]/u.test(v) && utf8.encode(v).length <= max;
const integer = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= min && v <= max;
function branch(v: unknown): v is string {
  if (!text(v, 220) || !/^refs\/heads\/[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$(?![\s\S])/.test(v)) return false;
  const name = v.slice(11), parts = name.split('/');
  return parts.length <= 16 && !name.includes('..') && !name.startsWith('refs/') &&
    parts.every(p => p !== '' && !p.startsWith('.') && !p.endsWith('.') && !p.endsWith('.lock'));
}
function path(v: unknown): v is string {
  return text(v, 1024) && !v.includes('\\') && v.split('/').length <= 32 &&
    v.split('/').every(p => !['', '.', '..', '.git'].includes(p) && utf8.encode(p).length <= 255);
}
// Only the bounded, closed worker envelope reaches this canonical comparison.
// Comparing original bytes rejects duplicate keys/alternate encodings without
// introducing a second JSON parser. Python's worker uses ensure_ascii=True.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  if (v !== null && typeof v === 'object') return '{' + Object.keys(v).sort().map(k =>
    canonical(k) + ':' + canonical((v as Record<string, unknown>)[k])).join(',') + '}';
  return JSON.stringify(v)!.replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}
export function parseHostedVersionProposal(raw: unknown): HostedVersionProposal | null {
  try {
    if (typeof raw !== 'string' || raw.length > HOSTED_VERSION_IMPORT_LIMIT || utf8.encode(raw).length > HOSTED_VERSION_IMPORT_LIMIT) return null;
    const body = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    const v: unknown = JSON.parse(body);
    if (!connectionBounded(v, HOSTED_VERSION_IMPORT_LIMIT, 128, 6) || !connectionKeys(v, ['schemaVersion', 'status', 'candidateId', 'rowSha256',
      'sourceCommit', 'sourceRef', 'configSha256', 'version', 'releaseEligibility', 'historicalUniqueness', 'sourceWrite',
      'authorityVariable', 'commitTrailer', 'versionFile']) || v.schemaVersion !== 1 || v.status !== 'reserved' ||
      v.releaseEligibility !== 'not-established' || v.historicalUniqueness !== 'not-established' || v.sourceWrite !== 'not-performed' ||
      typeof v.candidateId !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$(?![\s\S])/.test(v.candidateId) ||
      !hash(v.rowSha256) || !oid(v.sourceCommit) || !branch(v.sourceRef) || !hash(v.configSha256) || !text(v.authorityVariable, 4096) ||
      v.commitTrailer !== `MRK-Version-Reservation: ${v.candidateId} ${v.rowSha256}` ||
      !connectionKeys(v.version, ['name', 'build']) || !text(v.version.name, 64) ||
      !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?$(?![\s\S])/.test(v.version.name) ||
      !integer(v.version.build, 1, 2_100_000_000) || !connectionKeys(v.versionFile, ['path', 'beforeSha256', 'afterSha256', 'replacements']) ||
      !path(v.versionFile.path) || !hash(v.versionFile.beforeSha256) || !hash(v.versionFile.afterSha256) ||
      !Array.isArray(v.versionFile.replacements) || v.versionFile.replacements.length !== 2) return null;
    const [name, build] = v.versionFile.replacements;
    for (const r of [name, build]) if (!connectionKeys(r, ['start', 'end', 'value']) || !integer(r.start, 0, 65536) ||
      !integer(r.end, r.start + 1, 65536) || !text(r.value, 64)) return null;
    if (name.value !== v.version.name || build.value !== String(v.version.build) ||
      !(name.end <= build.start || build.end <= name.start) || canonical(v) !== body) return null;
    // Offsets and the protected-variable text are deliberately NOT retained.
    return Object.freeze({ candidateId: v.candidateId, rowSha256: v.rowSha256, sourceCommit: v.sourceCommit, sourceRef: v.sourceRef,
      configSha256: v.configSha256, path: v.versionFile.path, beforeSha256: v.versionFile.beforeSha256,
      afterSha256: v.versionFile.afterSha256, name: v.version.name, build: String(v.version.build), commitTrailer: v.commitTrailer });
  } catch { return null; }
}
export function hostedProposalCheckoutMatches(p: HostedVersionProposal, c: VersionCheckout): boolean {
  return c.source === p.path && c.baseline.savedConfig.sha256 === p.configSha256 && c.baseline.savedVersion.state === 'present' &&
    c.baseline.savedVersion.sha256 === p.beforeSha256 && c.values !== null;
}
export function hostedProposalViewMatches(p: HostedVersionProposal, v: VersionPreparedView): boolean {
  return v.intent === 'edit' && v.source === p.path && v.file.path === p.path && v.file.before.state === 'present' &&
    v.file.before.sha256 === p.beforeSha256 && v.file.after.sha256 === p.afterSha256 && v.values.name === p.name && v.values.build === p.build;
}
export function sameHostedImportService(a: HostedImportGitSource, b: HostedImportGitSource | null | undefined): boolean {
  return !!b && a.session !== null && b.session === a.session && b.projectId === a.projectId &&
    b.repository === a.repository && b.reader === a.reader;
}
export function hostedImportGitUnchanged(c: HostedImportGitCapture, source: HostedImportGitSource | null | undefined): boolean {
  return sameHostedImportService(c.source, source) && source!.epoch === c.source.epoch &&
    source!.repository?.getSnapshot() === c.repository && source!.reader?.getSnapshot() === c.read;
}
export function captureHostedImportGit(source: HostedImportGitSource | null | undefined, p: HostedVersionProposal,
  phase: 'before-open' | 'after-save'): HostedImportGitCapture | null {
  try {
    if (!source?.session || !source.projectId || !source.repository || !source.reader || !Number.isSafeInteger(source.epoch) || source.epoch < 0) return null;
    const r = source.repository.getSnapshot(), read = source.reader.getSnapshot(), op = read.original, o = r.observation;
    if (r.projectId !== source.projectId || !r.active || r.stale || r.busy || r.checkingStatus || r.blocked || !o ||
      source.repository.readReason() !== null || source.reader.ownerReason() || source.reader.readReason(source.projectId) !== null ||
      read.stale || read.busy || read.checking || read.uncertain || !read.status?.available || !op || op.action.kind !== 'observe' ||
      op.phase !== 'settled' || op.outcome !== 'ok' || op.reason !== null || op.context.projectId !== source.projectId ||
      op.context.revision !== `document-${read.status.documentRevision}` || read.status.operation?.operationId !== op.operationId ||
      !sameGitLocalData(read.status.operation, op) || !read.observation || read.observationProject !== source.projectId ||
      read.observation.basis !== 'local-refs-no-fetch' || !sameGitLocalData(op.result, read.observation) ||
      !sameGitLocalData(read.observation.observation, o) || o.restrictions.length || o.detached || o.unborn ||
      o.head !== p.sourceCommit || o.branch !== p.sourceRef || o.changes.some(c => c.conflict)) return null;
    if (phase === 'before-open' ? o.changes.length !== 0 : o.changes.length !== 1 || !o.changes.every(c =>
      c.path === p.path && c.kind === 'file' && (c.index === 'M' && c.worktree === ' ' || c.index === ' ' && c.worktree === 'M'))) return null;
    return Object.freeze({ source: Object.freeze({ ...source }), repository: r, read });
  } catch { return null; }
}
export function hostedImportCommitMessage(p: HostedVersionProposal): string {
  return `Update version to ${p.name} (build ${p.build})\n\n${p.commitTrailer}`;
}
