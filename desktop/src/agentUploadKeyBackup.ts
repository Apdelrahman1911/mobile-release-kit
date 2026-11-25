import type { AssetDisplayState, AssetRecordRef } from './assetSessionTypes.ts';
import { reserveId } from './versionReserve.ts';

// Selection/display DATA only. Native captures its own full reference and
// starts the existing two genuine pickers; this helper supplies neither.
export type AgentUploadKeyBackupKind = 'backup-encrypted' | 'restore-encrypted';
export type AgentUploadKeyBackupSelection =
  | { readonly kind: 'backup-encrypted'; readonly recordId: string; readonly expectedRevision: number }
  | { readonly kind: 'restore-encrypted'; readonly declaration: 'restore-as-new-unassigned' };
export interface AgentUploadKeyBackupOption extends Readonly<AssetRecordRef> { readonly label: string }
export const AGENT_UPLOAD_KEY_RESTORE_DECLARATION = 'restore-as-new-unassigned' as const;
const revision = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n > 0 && n < 0xffff_ffff;

export function agentUploadKeyBackupReason(assets: AssetDisplayState | null): string | null {
  const s = assets?.status, c = s?.context;
  if (!assets || assets.mode !== 'native' || assets.blocked || assets.observationFailed || !assets.contextCurrent ||
      assets.busy || assets.updatingContext || assets.originPending || !s || c?.platform !== 'android' || c.executionMode !== 'local' ||
      !revision(c.revision) || !revision(s.statusRevision) || s.mode !== 'encrypted' || s.persistence?.state !== 'unlocked' ||
      s.persistence.keyAccess !== 'read-write') return 'Open and unlock the current Android project’s encrypted vault in Desktop first.';
  if (s.backup?.available !== true || !s.capability.available || !s.modes.encrypted.available)
    return 'The native two-file backup route is not available. CLI permission cannot enable or bypass it.';
  const o = s.operation;
  if (o && (o.phase !== 'idle' || o.settlement !== 'known' || o.reason !== 'none'))
    return 'Finish the original credential action in Desktop before reviewing a backup or restore.';
  return null;
}

export function agentUploadKeyBackupOptions(assets: AssetDisplayState | null): readonly AgentUploadKeyBackupOption[] {
  if (!assets || agentUploadKeyBackupReason(assets)) return Object.freeze([]);
  const rows = assets.status!.records;
  return Object.freeze(rows.filter((r) => r.kind === 'android-keystore' && r.storage === 'encrypted' &&
    r.availability !== 'mutation-pending' && reserveId(r.recordId) && revision(r.revision) &&
    rows.filter((same) => same.recordId === r.recordId).length === 1).map((r) => Object.freeze({
      recordId: r.recordId, expectedRevision: r.revision, label: r.label ?? 'Android upload key',
    })));
}

export function agentUploadKeyBackupSelection(assets: AssetDisplayState, kind: AgentUploadKeyBackupKind,
  record: Readonly<AssetRecordRef> | null): AgentUploadKeyBackupSelection | null {
  if (agentUploadKeyBackupReason(assets)) return null;
  if (kind === 'restore-encrypted') return Object.freeze({ kind, declaration: AGENT_UPLOAD_KEY_RESTORE_DECLARATION });
  if (kind !== 'backup-encrypted' || !record || !reserveId(record.recordId) || !revision(record.expectedRevision)) return null;
  return agentUploadKeyBackupOptions(assets).some((r) => r.recordId === record.recordId && r.expectedRevision === record.expectedRevision)
    ? Object.freeze({ kind, recordId: record.recordId, expectedRevision: record.expectedRevision }) : null;
}
