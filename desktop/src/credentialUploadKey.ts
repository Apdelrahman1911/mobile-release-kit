// Public comparison DATA only. No private fields, paths, tool selections,
// fingerprints or declarations about an existing app are inferred here.
import type { AssetDisplayState, AssetReason, AssetStatus } from './assetSessionTypes.ts';
import { ASSET_REASON_HELP, parseAssetStatus } from './assetSessionProtocol.ts';

export const NEW_UPLOAD_KEY_DECLARATION = 'new-application-no-existing-upload-key' as const;
export const UPLOAD_KEY_OPERATION = 'generate-upload-key' as const;
export const RECOVER_UPLOAD_KEY_OPERATION = 'recover-upload-key' as const;
export type UploadKeyCommand = 'upload_key_status' | 'upload_key_prepare' | 'upload_key_create' | 'upload_key_recover';
export interface UploadKeyContextRequest { contextRevision: number }
export interface UploadKeyCreateRequest extends UploadKeyContextRequest {
  expectedStatusRevision: number;
  declaration: typeof NEW_UPLOAD_KEY_DECLARATION;
}
export type UploadKeyRecoveryAction = 'acknowledge-unstarted' | 'remember-bound';
export interface UploadKeyRecoverRequest extends UploadKeyContextRequest {
  expectedStatusRevision: number;
  expectedPreferenceRevision: string;
  action: UploadKeyRecoveryAction;
}
export interface UploadKeyRecoveryStatus {
  preferenceRevision: string | null;
  state: 'none' | 'recovery-required' | 'acknowledge-unstarted' | 'check-saved-key' | 'remember-bound';
  record: UploadKeyReference | null;
  operation: { operationId: number; action: UploadKeyRecoveryAction; phase: 'pending' | 'completed' | 'recovery-required'; preferenceRevision: string | null } | null;
}
export type UploadKeyPlan = 'unavailable' | 'unlock-storage' | 'recovery-required' | 'reuse-ready' |
  'assessment-needed' | 'select-existing' | 'existing-key-required' | 'conflict' | 'confirm-application-history';
export interface UploadKeyReference {
  vaultId: string; generationId: string; recordId: string; revisionId: string; revisionCounter: number;
}
export interface UploadKeyStatus {
  schemaVersion: 1;
  assets: AssetStatus;
  capability: { available: boolean; reason: AssetReason };
  setup: 'required' | 'checking' | 'ready' | 'attempted' | 'failed';
  plan: UploadKeyPlan;
  operation: { operationId: number; phase: 'generating' | 'saving' | 'finishing' | 'saved' | 'recovery-required'; reason: AssetReason } | null;
  saved: UploadKeyReference | null;
  // Missing on an older native host means unavailable, not an empty journal.
  recovery?: UploadKeyRecoveryStatus;
}
export interface UploadKeyApi {
  uploadKeyStatus(request: UploadKeyContextRequest): Promise<UploadKeyStatus>;
  prepareUploadKey(request: UploadKeyContextRequest): Promise<UploadKeyStatus>;
  createUploadKey(request: UploadKeyCreateRequest): Promise<UploadKeyStatus>;
  recoverUploadKey(request: UploadKeyRecoverRequest): Promise<UploadKeyStatus>;
}
function object(value: unknown, names: readonly string[]): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length === names.length && names.every((name) => {
    const field = Object.getOwnPropertyDescriptor(value, name);
    return !!field && field.enumerable && 'value' in field;
  });
}
function revision(value: unknown): value is number {
  return Number.isInteger(value) && (value as number) > 0 && (value as number) < 0xffff_ffff;
}
function id(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{32}$/u.test(value) && value !== '0'.repeat(32);
}
function reason(value: unknown): value is AssetReason {
  return typeof value === 'string' && Object.hasOwn(ASSET_REASON_HELP, value);
}
function reference(value: unknown): value is UploadKeyReference {
  if (!object(value, ['vaultId', 'generationId', 'recordId', 'revisionId', 'revisionCounter']) ||
      !revision(value.revisionCounter)) return false;
  const ids = [value.vaultId, value.generationId, value.recordId, value.revisionId];
  return ids.every(id) && new Set(ids).size === 4;
}
function preferenceRevision(value: unknown): value is string {
  return typeof value === 'string' && /^(0|[1-9][0-9]{0,19})$/u.test(value) &&
    (value.length < 20 || value <= '18446744073709551615');
}
function recoveryAction(value: unknown): value is UploadKeyRecoveryAction {
  return value === 'acknowledge-unstarted' || value === 'remember-bound';
}
function recoveryStatus(value: unknown, assets: AssetStatus, available: boolean): value is UploadKeyRecoveryStatus {
  if (!object(value, ['preferenceRevision', 'state', 'record', 'operation']) ||
      value.preferenceRevision !== null && !preferenceRevision(value.preferenceRevision) ||
      !['none', 'recovery-required', 'acknowledge-unstarted', 'check-saved-key', 'remember-bound'].includes(value.state as string)) return false;
  const row = value.record;
  if (row !== null && (!reference(row) || !assets.records.some((actual) => actual.kind === 'android-keystore' &&
      actual.storage === 'encrypted' && actual.recordId === row.recordId && actual.revision === row.revisionCounter &&
      actual.availability !== 'mutation-pending'))) return false;
  if (['check-saved-key', 'remember-bound'].includes(value.state as string) && row === null ||
      ['none', 'acknowledge-unstarted'].includes(value.state as string) && row !== null ||
      value.state !== 'recovery-required' && value.preferenceRevision === null) return false;
  const original = value.operation;
  if (original === null) return true;
  if (!object(original, ['operationId', 'action', 'phase', 'preferenceRevision']) || !revision(original.operationId) ||
      !recoveryAction(original.action) || !['pending', 'completed', 'recovery-required'].includes(original.phase as string) ||
      assets.operation?.operation !== RECOVER_UPLOAD_KEY_OPERATION || assets.operation.operationId !== original.operationId ||
      (original.phase === 'completed' ? !preferenceRevision(original.preferenceRevision) : original.preferenceRevision !== null)) return false;
  return original.phase !== 'completed' || available && assets.mode === 'encrypted' && assets.persistence?.state === 'unlocked' &&
    assets.persistence.keyAccess === 'read-write' && assets.operation.phase === 'idle' && assets.operation.settlement === 'known' &&
    assets.operation.reason === 'none' && assets.operation.storageOutcome === null;
}
export function uploadKeyRequestFits(command: UploadKeyCommand, value: unknown): boolean {
  try {
    if (command === 'upload_key_status' || command === 'upload_key_prepare')
      return object(value, ['contextRevision']) && revision(value.contextRevision);
    if (command === 'upload_key_recover') return object(value, ['contextRevision', 'expectedStatusRevision', 'expectedPreferenceRevision', 'action']) &&
      revision(value.contextRevision) && revision(value.expectedStatusRevision) && preferenceRevision(value.expectedPreferenceRevision) && recoveryAction(value.action);
    return command === 'upload_key_create' && object(value, ['contextRevision', 'expectedStatusRevision', 'declaration']) &&
      revision(value.contextRevision) && revision(value.expectedStatusRevision) && value.declaration === NEW_UPLOAD_KEY_DECLARATION;
  } catch { return false; }
}
export function parseUploadKeyStatus(value: unknown): UploadKeyStatus {
  const invalid = () => { throw new Error('Upload-key status is unavailable. Check the original action; do not create another key.'); };
  try {
    if (!(object(value, ['schemaVersion', 'assets', 'capability', 'setup', 'plan', 'operation', 'saved']) ||
        object(value, ['schemaVersion', 'assets', 'capability', 'setup', 'plan', 'operation', 'saved', 'recovery'])) || value.schemaVersion !== 1 ||
        !object(value.capability, ['available', 'reason']) || typeof value.capability.available !== 'boolean' || !reason(value.capability.reason) ||
        value.capability.available !== (value.capability.reason === 'none') ||
        !['required', 'checking', 'ready', 'attempted', 'failed'].includes(value.setup as string) ||
        !['unavailable', 'unlock-storage', 'recovery-required', 'reuse-ready', 'assessment-needed', 'select-existing', 'existing-key-required', 'conflict', 'confirm-application-history'].includes(value.plan as string)) return invalid();
    const assets = parseAssetStatus(value.assets);
    if (!assets || !assets.context || assets.context.platform !== 'android') return invalid();
    const operation = value.operation;
    if (operation !== null && (!object(operation, ['operationId', 'phase', 'reason']) ||
        !revision(operation.operationId) || !reason(operation.reason) ||
        !['generating', 'saving', 'finishing', 'saved', 'recovery-required'].includes(operation.phase as string) ||
        (operation.phase === 'recovery-required') === (operation.reason === 'none') ||
        assets.operation?.operation !== UPLOAD_KEY_OPERATION || assets.operation.operationId !== operation.operationId)) return invalid();
    const saved = value.saved;
    if (saved !== null && (!reference(saved) || !object(operation, ['operationId', 'phase', 'reason']) ||
        operation.phase !== 'saved' || operation.reason !== 'none' || value.capability.available !== true ||
        assets.mode !== 'encrypted' || assets.persistence?.state !== 'unlocked' || assets.persistence.keyAccess !== 'read-write' ||
        assets.operation?.phase !== 'idle' || assets.operation.settlement !== 'known' || assets.operation.reason !== 'none' ||
        assets.operation.storageOutcome?.effect !== 'known-applied' || assets.operation.storageOutcome.durability !== 'confirmed' ||
        assets.operation.storageOutcome.cleanup !== 'known' ||
        !assets.records.some((row) => row.recordId === saved.recordId && row.revision === saved.revisionCounter &&
          row.kind === 'android-keystore' && row.storage === 'encrypted' && row.availability !== 'mutation-pending'))) return invalid();
    if (object(operation, ['operationId', 'phase', 'reason']) && operation.phase === 'saved' && saved === null) return invalid();
    if (Object.hasOwn(value, 'recovery') && !recoveryStatus(value.recovery, assets, value.capability.available)) return invalid();
    // The parser checks shape/consistency only. Native publication, reference,
    // disposal and joins are independently proved by the original parent.
    return { schemaVersion: 1, assets, capability: { ...value.capability }, setup: value.setup,
      plan: value.plan, operation: operation === null ? null : { ...operation as Record<string, unknown> },
      saved: saved === null ? null : { ...saved as UploadKeyReference },
      ...(Object.hasOwn(value, 'recovery') ? { recovery: structuredClone(value.recovery) } : {}) } as UploadKeyStatus;
  } catch { return invalid(); }
}
export function uploadKeyContext(state: AssetDisplayState): string | null {
  const context = state.status?.context;
  return state.contextCurrent && context?.platform === 'android' && revision(context.revision)
    ? `${context.projectId}:${context.revision}` : null;
}
export function uploadKeyBaseReason(state: AssetDisplayState): string | null {
  if (state.mode !== 'native') return 'Set up signing in the native app.';
  if (state.blocked || state.observationFailed) return 'Check the original action. Do not create another key while its result is uncertain.';
  if (!state.status || !uploadKeyContext(state)) return 'Choose an Android project and submit its current signing context first.';
  if (state.busy || state.updatingContext || state.originPending) return 'Wait for the current action to finish.';
  if (state.status.mode !== 'encrypted' || state.status.persistence?.state !== 'unlocked' || state.status.persistence.keyAccess !== 'read-write')
    return 'Open and unlock the encrypted vault first.';
  if (state.status.operation && (state.status.operation.phase !== 'idle' || state.status.operation.settlement !== 'known'))
    return 'Wait for the original action to finish. An uncertain result must not be retried.';
  return null;
}
export function uploadKeyPlanHelp(plan: UploadKeyPlan): string {
  switch (plan) {
    case 'reuse-ready': return 'Your existing key is assigned for this context. Keep using it for this app.';
    case 'assessment-needed': return 'A saved key is already linked to this app. Assess that key below, then explicitly assign it.';
    case 'select-existing': return 'An Android key is already in this vault. Select and assess the correct existing key below; do not create a replacement.';
    case 'existing-key-required': return 'Use the upload key already used for this app. Import it or restore its encrypted backup; a different key can prevent updates.';
    case 'conflict': return 'The saved app or key no longer matches. Keep existing keys unchanged and resolve that mismatch first.';
    case 'recovery-required': return 'The earlier signing setup needs attention. Preserve its key and files, check status, and do not generate another key.';
    case 'unlock-storage': return 'Open and unlock the encrypted vault first.';
    case 'confirm-application-history': return 'No existing key is known in this checked setup. Only create one if this is a new app and you have never used an upload key for it.';
    default: return 'Signing-key creation is unavailable in this build. You can still use the existing import and assessment controls when available.';
  }
}
