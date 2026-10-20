// P12 comparison DATA only. The existing native owner supplies the private
// key/assigned P12 loans, save permission, authenticated readback and joins.
import { copyBoundedComparisonData, sameOfflineData } from './offlinePreflightProtocol.ts';
import { appleDistributionCertificateInputBase } from './appleDistributionCertificateSetupProtocol.ts';
import type { AppleCertificateKeySelection, AppleDistributionCertificateInputBase } from './appleDistributionCertificateSetupProtocol.ts';
import { retainedAppleP12KeyInput } from './appleDistributionKeySetupProtocol.ts';
import type { AppleDistributionKeyInputBase } from './appleDistributionKeySetupProtocol.ts';
import { parseAppleProfileSavedReference } from './appleProfileSetup.ts';
import type { AppleProfileSavedReference } from './appleProfileSetup.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import type { LocalStoreProject } from './localStorePreflight.ts';
import type { OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

export const APPLE_P12_MODES = Object.freeze(['p12-review', 'p12-reuse', 'p12-save'] as const);
export type AppleP12Mode = typeof APPLE_P12_MODES[number];
export const isAppleP12Mode = (mode: unknown): mode is AppleP12Mode =>
  mode === 'p12-review' || mode === 'p12-reuse' || mode === 'p12-save';
export type AppleP12Decision = 'assemble-review' | 'reuse-review' | 'assembled' | 'reused' | 'blocked';
export type AppleP12Reason = 'new-package-review' | 'current-package-review' | 'producer-returned' | 'existing-package' |
  'account-pending' | 'inventory-unavailable' | 'certificate-required' | 'select-existing-package' | 'selection-changed';
export interface AppleP12Output {
  frameBytes: number; frameSha256: string; p12Bytes: number; p12Sha256: string;
  certificateSha256: string; publicKeySha256: string;
}
export interface AppleP12Reuse {
  sourceP12: AppleProfileSavedReference; p12Sha256: string; certificateSha256: string;
  publicKeySha256: string; policyAckSha256: string;
}
export interface AppleP12Result {
  schemaVersion: 1; scope: 'local-ios-p12-setup'; mode: AppleP12Mode;
  decision: AppleP12Decision; reason: AppleP12Reason;
  certificateId: string | null; certificateSha256: string | null; publicKeySha256: string | null;
  output: AppleP12Output | null; reused: AppleP12Reuse | null;
  p12Saved: false; profileSaved: false; credentialReady: false; revocationChecked: false;
}
export type AppleP12InputBase = AppleDistributionCertificateInputBase & { p12RecordId: string | null; p12RecordRevision: number | null };
type Context = { mode: unknown; recordId?: unknown; keyRecordId?: unknown; p12RecordId?: unknown; p12RecordRevision?: unknown };
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' &&
  !Array.isArray(v) && Object.keys(v).length === names.length && names.every(name => Object.hasOwn(v, name));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
const revision = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) > 0 && (v as number) < 0xffffffff;
const sha = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const certificateId = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(v);
const blocked = ['account-pending', 'inventory-unavailable', 'certificate-required', 'select-existing-package', 'selection-changed'];
function output(v: unknown): v is AppleP12Output {
  return keys(v, ['frameBytes', 'frameSha256', 'p12Bytes', 'p12Sha256', 'certificateSha256', 'publicKeySha256']) &&
    Number.isSafeInteger(v.p12Bytes) && (v.p12Bytes as number) > 0 && (v.p12Bytes as number) <= 1048576 &&
    v.frameBytes === (v.p12Bytes as number) + 84 && sha(v.frameSha256) && sha(v.p12Sha256) && sha(v.certificateSha256) && sha(v.publicKeySha256);
}
export function parseAppleP12SavedReference(value: unknown): AppleProfileSavedReference | null {
  const ref = parseAppleProfileSavedReference(value);
  return ref?.revisionCounter === 1 ? ref : null;
}
export function parseAppleP12Result(value: unknown, context: Context): AppleP12Result | null {
  try {
    const v = copyBoundedComparisonData(value, 4096), mode = context.mode;
    if (!isAppleP12Mode(mode) || !keys(v, ['schemaVersion', 'scope', 'mode', 'decision', 'reason', 'certificateId',
        'certificateSha256', 'publicKeySha256', 'output', 'reused', 'p12Saved', 'profileSaved', 'credentialReady', 'revocationChecked']) ||
        v.schemaVersion !== 1 || v.scope !== 'local-ios-p12-setup' || v.mode !== mode || v.p12Saved !== false ||
        v.profileSaved !== false || v.credentialReady !== false || v.revocationChecked !== false) return null;
    const absent = context.p12RecordId === null && context.p12RecordRevision === null ||
      context.p12RecordId === undefined && context.p12RecordRevision === undefined;
    if (!absent && (!id(context.p12RecordId) || !revision(context.p12RecordRevision))) return null;
    if (v.decision === 'blocked') return typeof v.reason === 'string' && blocked.includes(v.reason) &&
      v.certificateId === null && v.certificateSha256 === null && v.publicKeySha256 === null && v.output === null && v.reused === null ?
      v as unknown as AppleP12Result : null;
    if (!certificateId(v.certificateId) || !sha(v.certificateSha256) || !sha(v.publicKeySha256)) return null;
    if (v.decision === 'assemble-review') {
      if (mode !== 'p12-review' || v.reason !== 'new-package-review' || !absent || v.output !== null || v.reused !== null) return null;
    } else if (v.decision === 'assembled') {
      if (mode !== 'p12-save' || v.reason !== 'producer-returned' || !absent || !output(v.output) || v.reused !== null ||
          v.output.certificateSha256 !== v.certificateSha256 || v.output.publicKeySha256 !== v.publicKeySha256) return null;
    } else if (v.decision === 'reuse-review' || v.decision === 'reused') {
      if (v.decision === 'reuse-review' ? mode !== 'p12-review' || v.reason !== 'current-package-review' : mode !== 'p12-reuse' || v.reason !== 'existing-package') return null;
      const reuse = v.reused;
      if (absent || v.output !== null || !keys(reuse, ['sourceP12', 'p12Sha256', 'certificateSha256', 'publicKeySha256', 'policyAckSha256'])) return null;
      const ref = parseAppleProfileSavedReference(reuse.sourceP12); // Existing source revisions need not be NEW/revision 1.
      if (!ref || ref.recordId !== context.p12RecordId || ref.revisionCounter !== context.p12RecordRevision ||
          ref.recordId === context.recordId || ref.recordId === context.keyRecordId || !sha(reuse.p12Sha256) || !sha(reuse.policyAckSha256) ||
          reuse.certificateSha256 !== v.certificateSha256 || reuse.publicKeySha256 !== v.publicKeySha256) return null;
    } else return null;
    return v as unknown as AppleP12Result;
  } catch { return null; }
}

// Null means no current assignment in THIS context, not no P12/key anywhere.
// Undefined means invalid/unavailable: never fall back from that to assembly.
function assignedP12(assets: AssetDisplayState, contextRevision: number, retained: boolean): { p12RecordId: string | null; p12RecordRevision: number | null } | undefined {
  const assignments = copyBoundedComparisonData(assets.status?.assignments, 65536), records = copyBoundedComparisonData(assets.status?.records, 65536);
  if (!Array.isArray(assignments) || assignments.length > 128 || !Array.isArray(records) || records.length > 128) return undefined;
  const rows = assignments.filter(row => row && typeof row === 'object' && !Array.isArray(row) && row.kind === 'apple-p12' && row.contextRevision === contextRevision);
  if (rows.length === 0) return { p12RecordId: null, p12RecordRevision: null };
  if (rows.length !== 1) return undefined;
  const row = rows[0];
  if (!row || typeof row !== 'object' || Array.isArray(row) || !id(row.recordId) || !revision(row.recordRevision) ||
      !retained && row.availability !== 'available') return undefined;
  const matches = records.filter(record => record && typeof record === 'object' && !Array.isArray(record) && record.recordId === row.recordId);
  const record = matches[0];
  if (matches.length !== 1 || !record || typeof record !== 'object' || Array.isArray(record) || record.kind !== 'apple-p12' ||
      record.revision !== row.recordRevision || record.storage !== 'encrypted' ||
      (retained ? record.availability === 'mutation-pending' : record.availability !== 'assigned')) return undefined;
  return { p12RecordId: row.recordId, p12RecordRevision: row.recordRevision };
}
export function appleP12InputBase(project: LocalStoreProject | null, assets: AssetDisplayState | null,
  key: AppleCertificateKeySelection | null): AppleP12InputBase | null {
  try {
    const base = appleDistributionCertificateInputBase(project, assets, key);
    if (!base || !assets) return null;
    const p12 = assignedP12(assets, base.credentialContextRevision, false);
    if (!p12 || p12.p12RecordId !== null && [base.keyRecordId, base.recordId].includes(p12.p12RecordId)) return null;
    return { ...base, ...p12 };
  } catch { return null; }
}
export function retainedAppleP12Input(project: LocalStoreProject | null, assets: AssetDisplayState | null,
  key: AppleCertificateKeySelection | null, original: AppleDistributionKeyInputBase & { keyRecordId?: string; keyRecordRevision?: number;
    p12RecordId?: string | null; p12RecordRevision?: number | null }, mode: AppleP12Mode): AppleP12InputBase | null {
  try {
    if (!assets || !key || !id(original.keyRecordId) || !revision(original.keyRecordRevision) ||
        key.recordId !== original.keyRecordId || key.recordRevision !== original.keyRecordRevision) return null;
    const { keyRecordId, keyRecordRevision, p12RecordId: _p12, p12RecordRevision: _p12Revision, ...p8 } = original;
    const base = retainedAppleP12KeyInput(project, assets, p8, mode === 'p12-save' ? 'assemble-apple-p12' : 'use-apple-distribution-key');
    if (!base) return null;
    const records = copyBoundedComparisonData(assets.status?.records, 65536);
    if (!Array.isArray(records) || records.length > 128) return null;
    const rows = records.filter(row => row && typeof row === 'object' && !Array.isArray(row) && row.recordId === keyRecordId), row = rows[0];
    if (rows.length !== 1 || !row || typeof row !== 'object' || Array.isArray(row) || row.revision !== keyRecordRevision ||
        row.kind !== 'apple-distribution-key' || row.storage !== 'encrypted' || row.availability !== 'unassigned' ||
        row.payloadState !== 'not-checked' || row.label !== null) return null;
    const p12 = assignedP12(assets, base.credentialContextRevision, true);
    const current = p12 && { ...base, keyRecordId, keyRecordRevision, ...p12 };
    return current && sameOfflineData(current, original) ? current : null;
  } catch { return null; }
}

export function appleP12Copy(result: AppleP12Result | null, saved: AppleProfileSavedReference | null,
  outcome: OfflinePreflightOutcome | null): { title: string; detail: string } | null {
  if (saved) return outcome === 'complete' ? {
    title: 'Signing P12 saved, not assigned', detail: 'The new encrypted P12 and its password were saved and read back. Open saved credentials to assess and assign this exact record. Back it up separately; no profile, signing test or release is approved.',
  } : { title: 'Setup stopped; the P12 was saved', detail: 'Keep this encrypted record and the original stopped operation. No successful setup is claimed. Do not assemble another copy; review this record in saved credentials before any assignment or backup.' };
  if (result?.decision === 'assembled') return { title: 'P12 output returned; saved copy not confirmed',
    detail: 'Keep the original operation and any saved records. Returned output or a withdrawn saved-record display is not permission to assemble again. Check original status; do not repeat the save.' };
  if (result?.decision === 'assemble-review') return { title: 'Review saving one signing P12',
    detail: 'The check matched an existing certificate to your selected saved key. Nothing has been assembled or saved. A separate confirmation below may save one new encrypted P12; it will not replace or assign anything.' };
  if (result?.decision === 'reuse-review') return { title: 'Use the P12 already assigned here',
    detail: 'The check matched your current assigned P12 to this saved key and certificate. Review the separate reuse check below; no replacement or new encrypted copy is needed.' };
  if (result?.decision === 'reused') return { title: 'Existing P12 rechecked',
    detail: 'The original assigned P12 matched this bounded check. No new file was saved or assigned. Profile setup and the actual signed build remain separate; this is not release readiness.' };
  if (result?.decision === 'blocked') {
    const details: Partial<Record<AppleP12Reason, string>> = {
      'account-pending': 'Earlier Apple setup or a local save is unresolved. Keep the original operation and saved key. Use its existing status and cancellation controls; do not repeat assembly or replace the key.',
      'inventory-unavailable': 'The required Apple records could not be checked. Check account access and supported setup; an incomplete response does not mean a certificate or P12 is missing.',
      'certificate-required': 'Finish or check certificate setup for this saved key first. This step cannot issue a certificate or generate another key.',
      'select-existing-package': 'A previous signing P12 needs review. Open saved credentials, assess and explicitly assign the intended P12 in Set up Apple signing. Restore an existing encrypted backup there if needed; do not replace it with a new assembly.',
      'selection-changed': 'The saved app, key or assigned P12 changed. Keep the original operation; after it has settled, review the current inputs again without repeating an uncertain save.',
    };
    return { title: 'P12 setup needs attention', detail: details[result.reason] ?? 'No P12 action was approved.' };
  }
  if (outcome && outcome !== 'complete') return { title: 'P12 setup did not finish',
    detail: 'Keep the original operation and saved key. A stopped or unconfirmed result does not prove that no P12 was saved. Use original status and cancellation; never repeat assembly to dismiss uncertainty.' };
  return null;
}
