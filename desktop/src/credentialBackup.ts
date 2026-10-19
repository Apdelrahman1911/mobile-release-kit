// Presentation and closed request DATA only. No paths, recovery codes, private
// bytes or file/credential authority enter the renderer. The existing native
// document, vault and two original pickers independently admit every action.
import type { AssetBackupExportRequest, AssetBackupImportRequest, AssetDisplayState, AssetRecordRef } from './assetSessionTypes.ts';

export const BACKUP_EXPORT_OPERATION = 'prepare-backup-export';
export const BACKUP_IMPORT_OPERATION = 'import-backup';
export type CredentialBackupCommand = 'vault_backup_export' | 'vault_backup_import';

function exact(value: unknown, names: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === names.length && names.every((name) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    return !!descriptor && descriptor.enumerable && 'value' in descriptor;
  });
}
function revision(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) > 0 && (value as number) <= 0xffff_ffff;
}
function recordRef(value: unknown): value is AssetRecordRef {
  return exact(value, ['recordId', 'expectedRevision']) && typeof value.recordId === 'string' &&
    /^[0-9a-f]{32}$/u.test(value.recordId) && value.recordId !== '0'.repeat(32) && revision(value.expectedRevision);
}
export function credentialBackupRequestFits(command: CredentialBackupCommand, value: unknown): boolean {
  try {
    if (command === 'vault_backup_import') return exact(value, ['contextRevision']) && revision(value.contextRevision);
    return command === 'vault_backup_export' && exact(value, ['contextRevision', 'record']) &&
      revision(value.contextRevision) && recordRef(value.record);
  } catch { return false; }
}
export function isCredentialBackupOperation(value: unknown): boolean {
  return value === BACKUP_EXPORT_OPERATION || value === BACKUP_IMPORT_OPERATION;
}

// A missing capability on an older host is unavailable, not an invitation to
// discover support by invoking a private operation. Vault support alone does
// not qualify the new native backup route.
export function credentialBackupReason(state: AssetDisplayState): string | null {
  if (state.mode !== 'native') return 'Backup and restore require the native app.';
  if (state.blocked) return 'Keep any backup and recovery-code files unchanged. Check the original operation status; do not retry it.';
  if (state.observationFailed || !state.status) return 'Check status before backing up or restoring an item.';
  if (state.originPending) return 'Wait for the original action to be acknowledged. Checking status does not start a new backup.';
  if (!state.status.backup?.available || !state.status.capability.available || !state.status.modes.encrypted.available)
    return 'Backup and restore are unavailable in this build. No new backup action can be started here.';
  if (state.status.mode !== 'encrypted' || state.status.persistence?.state !== 'unlocked' || state.status.persistence.keyAccess !== 'read-write')
    return 'Open and unlock the encrypted vault to back up or restore an item.';
  if (state.busy || state.updatingContext) return 'Wait for the current action to finish.';
  if (!state.contextCurrent || !state.status.context || !revision(state.status.context.revision))
    return 'Choose a project and submit its current context first.';
  const operation = state.status.operation;
  if (operation && (operation.phase !== 'idle' || operation.settlement !== 'known'))
    return 'Wait for the original operation to finish. An uncertain result must not be retried.';
  return null;
}
export function credentialBackupExportRequest(state: AssetDisplayState, record: AssetRecordRef): AssetBackupExportRequest | null {
  if (credentialBackupReason(state) !== null) return null;
  const request = { contextRevision: state.status!.context!.revision, record };
  if (!credentialBackupRequestFits('vault_backup_export', request) || !state.status!.records.some((row) =>
    row.recordId === record.recordId && row.revision === record.expectedRevision && row.storage === 'encrypted' && row.availability !== 'mutation-pending')) return null;
  return { contextRevision: request.contextRevision, record: { recordId: record.recordId, expectedRevision: record.expectedRevision } };
}
export function credentialBackupImportRequest(state: AssetDisplayState): AssetBackupImportRequest | null {
  if (credentialBackupReason(state) !== null) return null;
  return { contextRevision: state.status!.context!.revision };
}

// The controller supplies `exportCompleted` only after matching this action's
// own native reply, current context and explicit native publication marker.
// Phase/record counts/storage effects alone never produce completion copy.
export function credentialBackupMessage(state: AssetDisplayState, exportCompleted: boolean): { title: string; text: string } | null {
  const operation = state.status?.operation;
  const intent = state.intent?.type === 'backup' ? state.intent : null;
  if (!intent && !isCredentialBackupOperation(operation?.operation)) return null;
  const exporting = intent ? intent.change === 'export' : operation?.operation === BACKUP_EXPORT_OPERATION;
  if (state.blocked || state.observationFailed || operation?.phase === 'unknown' ||
      operation?.settlement === 'unknown' || operation?.settlement === 'late-known') return {
    title: 'Backup status needs attention',
    text: 'Keep both chosen locations and any files unchanged. Check the original status; do not retry, replace or delete them.',
  };
  if (exporting && exportCompleted) return {
    title: 'Backup saved',
    text: 'The encrypted backup and its recovery code were saved in the two folders you chose. Keep them separately; you need both to restore. No signing key was changed.',
  };
  if (state.originPending || state.busy && !isCredentialBackupOperation(operation?.operation)) return {
    title: exporting ? 'Starting backup…' : 'Starting restore…',
    text: 'Wait for the original native request. Do not start it again if its acknowledgement is delayed.',
  };
  if (operation?.phase === 'picking') return exporting ? {
    title: 'Choose two separate locations',
    text: 'Choose a private folder for the encrypted backup, then a different private folder for its recovery code. Keep both outside your projects.',
  } : {
    title: 'Choose your backup and recovery code',
    text: 'Choose the encrypted backup file, then its matching recovery-code file. Restore creates a separate, unassigned copy; it never replaces an existing key.',
  };
  if (operation && (operation.phase !== 'idle' || operation.settlement !== 'known')) return {
    title: exporting ? 'Saving encrypted backup…' : 'Restoring a separate copy…',
    text: 'Keep the app open until the original operation finishes. Cancelling may leave files to preserve; it does not undo an uncertain save.',
  };
  return exporting ? {
    title: 'No completed backup confirmed',
    text: 'Check the original status. Keep any files in the folders you chose; do not assume the pair was saved or removed.',
  } : {
    title: 'Restore status',
    text: 'A restored item is always a new, unassigned copy. Review any newly listed item, then explicitly assess and assign it if appropriate. No existing key or assignment is replaced.',
  };
}
