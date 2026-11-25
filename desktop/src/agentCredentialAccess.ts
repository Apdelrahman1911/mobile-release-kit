// Closed ordinary-vault comparison DATA. Pickers/private fields and every
// native credential operation remain in the original Asset controller.
import type { AssetDisplayState, AssetKind, AssetRecordRef, AssetStatus } from './assetSessionTypes.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { reserveId } from './versionReserve.ts';
import { parseAgentUploadKeyPrepared, sameAgentUploadKeyPrepared } from './agentUploadKeyReuse.ts';
import type { AgentUploadKeyPrepared, AgentUploadKeyReuseOption } from './agentUploadKeyReuse.ts';

export type AgentCredentialKind = Exclude<AssetKind, 'google-wif'>;
export type AgentCredentialAction = 'credential-import-prepared' | 'credential-assess-existing' | 'credential-assign-reviewed';
export type AgentCredentialSelection =
  | { readonly kind: 'credential-import-prepared' | 'credential-assign-reviewed'; readonly credentialKind: AgentCredentialKind;
      readonly previewOperationId: number; readonly previewToken: string }
  | { readonly kind: 'credential-assess-existing'; readonly credentialKind: AgentCredentialKind; readonly recordId: string; readonly expectedRevision: number };
export interface AgentCredentialPrepared extends AgentUploadKeyPrepared { readonly credentialKind: AgentCredentialKind }
const kinds: readonly string[] = ['android-keystore', 'android-firebase', 'apple-p12', 'apple-profile', 'asc-p8', 'ios-firebase',
  'google-service-account', 'project-read-token', 'apple-review-contact', 'apple-review-demo', 'operation-commitment'];
const revision = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v > 0 && v < 0xffff_ffff;
export const agentCredentialKind = (v: unknown): v is AgentCredentialKind => typeof v === 'string' && kinds.includes(v);
export const agentCredentialAction = (v: unknown): v is AgentCredentialAction => v === 'credential-import-prepared' || v === 'credential-assess-existing' || v === 'credential-assign-reviewed';
export function parseAgentCredentialSelection(raw: unknown): AgentCredentialSelection | null {
  try {
    const d = copyBoundedComparisonData(raw, 256, 10) as Record<string, unknown>;
    if (!d || typeof d !== 'object' || Array.isArray(d) || Object.keys(d).length !== 4 || !agentCredentialKind(d.credentialKind)) return null;
    if (d.kind === 'credential-assess-existing' && d.credentialKind !== 'android-keystore' && reserveId(d.recordId) && revision(d.expectedRevision))
      return Object.freeze({ kind: d.kind, credentialKind: d.credentialKind, recordId: d.recordId, expectedRevision: d.expectedRevision });
    if ((d.kind === 'credential-import-prepared' || d.kind === 'credential-assign-reviewed' && d.credentialKind !== 'android-keystore') &&
        revision(d.previewOperationId) && reserveId(d.previewToken))
      return Object.freeze({ kind: d.kind, credentialKind: d.credentialKind, previewOperationId: d.previewOperationId, previewToken: d.previewToken });
    return null;
  } catch { return null; }
}
export function parseAgentCredentialPrepared(raw: unknown): AgentCredentialPrepared | null {
  try {
    const d = copyBoundedComparisonData(raw, 1024, 18) as Record<string, unknown>;
    if (!d || typeof d !== 'object' || Array.isArray(d) || !agentCredentialKind(d.credentialKind) || d.credentialKind === 'android-keystore') return null;
    const { credentialKind, ...fields } = d, p = parseAgentUploadKeyPrepared(fields);
    return p ? Object.freeze({ ...p, credentialKind }) : null;
  } catch { return null; }
}
export function sameCredentialPrepared(a: AgentUploadKeyPrepared, b: AgentUploadKeyPrepared): boolean {
  return sameAgentUploadKeyPrepared(a, b) && ('credentialKind' in a ? a.credentialKind : undefined) === ('credentialKind' in b ? b.credentialKind : undefined);
}
export function agentCredentialReason(a: AssetDisplayState | null): string | null {
  const s = a?.status, c = s?.context;
  return !a || a.mode !== 'native' || a.blocked || a.observationFailed || !a.contextCurrent || a.busy || a.updatingContext || a.originPending ||
    !s || s.mode !== 'encrypted' || s.persistence?.state !== 'unlocked' || s.persistence.keyAccess !== 'read-write' ||
    !s.capability.available || !s.modes.encrypted.available || c?.executionMode !== 'local' || !revision(c.revision) || !revision(s.statusRevision)
    ? 'Open and unlock the current project’s encrypted vault, then submit its local credential context in Desktop.' : null;
}
export function agentCredentialOptions(a: AssetDisplayState | null): readonly AgentUploadKeyReuseOption[] {
  if (!a || agentCredentialReason(a)) return Object.freeze([]);
  const s = a.status!, o = s.operation;
  if (o && (o.phase !== 'idle' || o.settlement !== 'known')) return Object.freeze([]);
  return Object.freeze(s.records.filter(r => agentCredentialKind(r.kind) && r.kind !== 'android-keystore' && r.storage === 'encrypted' &&
    r.availability !== 'mutation-pending' && reserveId(r.recordId) && revision(r.revision) && s.records.filter(other => other.recordId === r.recordId).length === 1)
    .map(r => Object.freeze({ recordId: r.recordId, expectedRevision: r.revision, label: r.label ?? r.kind })));
}
export function agentCredentialSelection(a: AssetDisplayState, action: AgentCredentialAction, now: number,
  record: Readonly<AssetRecordRef> | null = null): AgentCredentialSelection | null {
  if (!Number.isFinite(now) || now < 0 || agentCredentialReason(a)) return null;
  const s = a.status!, o = s.operation, p = o?.preview, subject = p?.subject, i = a.intent;
  if (action === 'credential-assess-existing') {
    const option = record && agentCredentialOptions(a).find(r => r.recordId === record.recordId && r.expectedRevision === record.expectedRevision);
    const row = option && s.records.find(r => r.recordId === option.recordId && r.revision === option.expectedRevision);
    return row && agentCredentialKind(row.kind) && row.kind !== 'android-keystore' ? Object.freeze({ kind: action,
      credentialKind: row.kind, recordId: row.recordId, expectedRevision: row.revision }) : null;
  }
  if (!o || o.phase !== 'preview' || o.reason !== 'none' || o.settlement !== 'known' || !a.reviewReady ||
      a.previewDeadline === null || now >= a.previewDeadline || !p || !reserveId(p.token) || !revision(o.operationId) ||
      subject?.type !== 'record' || !agentCredentialKind(subject.kind) || i?.type !== 'record' || i.kind !== subject.kind) return null;
  if (action === 'credential-import-prepared') {
    if (p.action !== 'save' || subject.change !== 'new' || subject.recordId !== null || subject.recordRevision !== null ||
        i.change !== 'new' || i.record !== null) return null;
  } else if (p.action !== 'bind' || subject.kind === 'android-keystore' || subject.change !== 'assign' || i.change !== 'assign' ||
      !reserveId(subject.recordId) || !revision(subject.recordRevision) || i.record?.recordId !== subject.recordId ||
      i.record.expectedRevision !== subject.recordRevision || s.records.filter(r => r.recordId === subject.recordId && r.revision === subject.recordRevision &&
        r.kind === subject.kind && r.storage === 'encrypted' && r.availability !== 'mutation-pending' && r.payloadState === 'assessed').length !== 1) return null;
  return Object.freeze({ kind: action, credentialKind: subject.kind, previewOperationId: o.operationId, previewToken: p.token });
}
export function agentCredentialPreparedMatches(s: AssetStatus, p: AgentCredentialPrepared): boolean {
  const o = s.operation, v = o?.preview, subject = v?.subject;
  return s.statusRevision >= p.statusRevision && s.context?.revision === p.contextRevision && s.context.executionMode === 'local' &&
    s.mode === 'encrypted' && s.persistence?.state === 'unlocked' && s.persistence.keyAccess === 'read-write' &&
    o?.operationId === p.assetOperationId && o.operation === 'prepare' && o.phase === 'preview' && o.settlement === 'known' && o.reason === 'none' &&
    v?.token === p.previewToken && v.action === 'bind' && v.expiresInMs > 0 && subject?.type === 'record' && subject.kind === p.credentialKind &&
    subject.change === 'assign' && subject.recordId === p.recordId && subject.recordRevision === p.expectedRevision &&
    s.records.filter(r => r.recordId === p.recordId && r.revision === p.expectedRevision && r.kind === p.credentialKind && r.storage === 'encrypted' &&
      r.availability !== 'mutation-pending' && r.payloadState === 'assessed').length === 1;
}
