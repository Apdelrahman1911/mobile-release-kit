import type { AssetDisplayState, AssetRecordRef, AssetStatus } from './assetSessionTypes.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { reserveId } from './versionReserve.ts';

// Fixed MAIN-only comparison from the original returned Load, not a public
// credential, native permission or a replacement Prepare/Bind invocation.
export interface AgentUploadKeyPrepared {
  readonly assetOperationId: number;
  readonly statusRevision: number;
  readonly contextRevision: number;
  readonly recordId: string;
  readonly expectedRevision: number;
  readonly previewToken: string;
  readonly remainingMs: number;
}
export interface AgentUploadKeyPreparation {
  current(): boolean;
  observe(stamp: AgentUploadKeyPrepared, current: () => boolean, reviewEnd: number | null): Promise<boolean>;
  invalidate(): void;
}
export interface AgentUploadKeyReuseOption extends Readonly<AssetRecordRef> { readonly label: string }
export type AgentUploadKeyReuseSelection = { readonly kind: 'prepare-existing'; readonly recordId: string; readonly expectedRevision: number };
const revision = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0 && v < 0xffff_ffff;
const fields = ['assetOperationId', 'statusRevision', 'contextRevision', 'recordId', 'expectedRevision', 'previewToken', 'remainingMs'];
export function parseAgentUploadKeyPrepared(value: unknown): AgentUploadKeyPrepared | null {
  let d: Record<string, unknown> | null;
  try { d = copyBoundedComparisonData(value, 1024, 16) as Record<string, unknown> | null; } catch { return null; }
  if (!d || typeof d !== 'object' || Array.isArray(d) || Object.keys(d).length !== fields.length || !fields.every(k => Object.hasOwn(d, k)) ||
      !revision(d.assetOperationId) || !revision(d.statusRevision) || !revision(d.contextRevision) || !revision(d.expectedRevision) ||
      !reserveId(d.recordId) || !reserveId(d.previewToken) || typeof d.remainingMs !== 'number' || !Number.isSafeInteger(d.remainingMs) ||
      d.remainingMs < 1 || d.remainingMs > 300_000) return null;
  return Object.freeze({ assetOperationId: d.assetOperationId, statusRevision: d.statusRevision, contextRevision: d.contextRevision,
    recordId: d.recordId, expectedRevision: d.expectedRevision, previewToken: d.previewToken, remainingMs: d.remainingMs });
}
export function sameAgentUploadKeyPrepared(a: AgentUploadKeyPrepared, b: AgentUploadKeyPrepared): boolean {
  return fields.filter(k => k !== 'remainingMs').every(k => a[k as keyof AgentUploadKeyPrepared] === b[k as keyof AgentUploadKeyPrepared]);
}
export function agentUploadKeyReuseReason(a: AssetDisplayState | null): string | null {
  const s = a?.status, c = s?.context, o = s?.operation;
  if (!a || a.mode !== 'native' || a.blocked || a.observationFailed || !a.contextCurrent || a.busy || a.updatingContext || a.originPending ||
      !s || s.mode !== 'encrypted' || s.persistence?.state !== 'unlocked' || s.persistence.keyAccess !== 'read-write' ||
      !s.capability.available || !s.modes.encrypted.available || c?.platform !== 'android' || c.executionMode !== 'local' ||
      !revision(c.revision) || !revision(s.statusRevision)) return 'Open and unlock this Android project’s encrypted vault and submit its current local context first.';
  return o && (o.phase !== 'idle' || o.settlement !== 'known') ? 'Finish or discard the original credential review before preparing another existing key.' : null;
}
export function agentUploadKeyReuseOptions(a: AssetDisplayState | null): readonly AgentUploadKeyReuseOption[] {
  if (!a || agentUploadKeyReuseReason(a)) return Object.freeze([]);
  const rows = a.status!.records;
  return Object.freeze(rows.filter(r => r.kind === 'android-keystore' && r.storage === 'encrypted' && r.availability !== 'mutation-pending' &&
    reserveId(r.recordId) && revision(r.revision) && rows.filter(other => other.recordId === r.recordId).length === 1)
    .map(r => Object.freeze({ recordId: r.recordId, expectedRevision: r.revision, label: r.label ?? 'Android upload key' })));
}
export function agentUploadKeyReuseSelection(a: AssetDisplayState, record: Readonly<AssetRecordRef> | null): AgentUploadKeyReuseSelection | null {
  return record && agentUploadKeyReuseOptions(a).some(r => r.recordId === record.recordId && r.expectedRevision === record.expectedRevision)
    ? Object.freeze({ kind: 'prepare-existing', recordId: record.recordId, expectedRevision: record.expectedRevision }) : null;
}
export function agentUploadKeyPreparedMatches(s: AssetStatus, p: AgentUploadKeyPrepared): boolean {
  const o = s.operation, v = o?.preview, subject = v?.subject;
  return s.statusRevision >= p.statusRevision && s.context?.revision === p.contextRevision && s.context.platform === 'android' &&
    s.context.executionMode === 'local' && s.mode === 'encrypted' && s.persistence?.state === 'unlocked' && s.persistence.keyAccess === 'read-write' &&
    o?.operationId === p.assetOperationId && o.operation === 'prepare' && o.phase === 'preview' && o.settlement === 'known' && o.reason === 'none' &&
    v?.token === p.previewToken && v.action === 'bind' && v.expiresInMs > 0 && subject?.type === 'record' && subject.kind === 'android-keystore' &&
    subject.change === 'assign' && subject.recordId === p.recordId && subject.recordRevision === p.expectedRevision &&
    s.records.filter(r => r.recordId === p.recordId && r.revision === p.expectedRevision && r.kind === 'android-keystore' && r.storage === 'encrypted' &&
      r.availability !== 'mutation-pending' && r.payloadState === 'assessed').length === 1;
}
