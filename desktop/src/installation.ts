import type { ApiError, HelpContent } from './types.ts';

// Fixed presentation contract. No value here grants native admission, verifies
// an installation, chooses a runtime, or enables maintenance.
export interface InstallationDescription {
  layout: 'fixed-macos';
  expectedLocation: string;
  runtimeRelease: string;
  installMode: 'verified-package-required';
  maintenance: 'unavailable';
  revealAvailable: boolean;
  assurance: 'profile-description-only';
}
export interface InstallationRevealResult {
  state: 'request-sent';
  finderVisibility: 'unconfirmed';
}

function record(value: unknown, keys: readonly string[]): Record<string, unknown> | null {
  try {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return null;
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).length !== keys.length) return null;
    const result: Record<string, unknown> = {};
    for (const key of keys) {
      const descriptor = descriptors[key];
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) return null;
      result[key] = descriptor.value;
    }
    return result;
  } catch { return null; }
}
export function parseInstallationDescription(value: unknown): InstallationDescription | null {
  const row = record(value, ['layout', 'expectedLocation', 'runtimeRelease', 'installMode', 'maintenance', 'revealAvailable', 'assurance']);
  if (!row || row.layout !== 'fixed-macos'
    || row.expectedLocation !== '/Library/Application Support/MobileReleaseKit/Mobile Release Kit.app'
    || typeof row.runtimeRelease !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(row.runtimeRelease)
    || row.installMode !== 'verified-package-required' || row.maintenance !== 'unavailable'
    || typeof row.revealAvailable !== 'boolean' || row.assurance !== 'profile-description-only') return null;
  return { layout: 'fixed-macos', expectedLocation: row.expectedLocation, runtimeRelease: row.runtimeRelease,
    installMode: 'verified-package-required', maintenance: 'unavailable', revealAvailable: row.revealAvailable, assurance: 'profile-description-only' };
}
export function parseInstallationReveal(value: unknown): InstallationRevealResult | null {
  const row = record(value, ['state', 'finderVisibility']);
  return row?.state === 'request-sent' && row.finderVisibility === 'unconfirmed'
    ? { state: 'request-sent', finderVisibility: 'unconfirmed' } : null;
}
export function installationError(error: unknown): ApiError {
  let code: unknown;
  try {
    if (typeof error === 'object' && error !== null) {
      const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
      if (descriptor && 'value' in descriptor) code = descriptor.value;
    }
  } catch { /* Never retain raw rejection data. */ }
  if (code === 'installation_reveal_unavailable') return { code, message: 'Show in Finder is available only in the normal installed macOS app, not browser preview or this runtime profile.', retryable: false };
  if (code === 'busy' || code === 'quit_pending' || code === 'installation_reveal_busy') return { code: 'installation_reveal_busy', message: 'Finish or cancel the current native action or quit confirmation before requesting Finder.', retryable: false };
  if (code === 'shutting_down' || code === 'installation_document_unavailable') return { code: 'installation_document_unavailable', message: 'The original app window is closing or unavailable. No new Finder request was admitted.', retryable: false };
  if (code === 'cleanup_unknown') return { code: 'cleanup_unknown', message: 'An earlier operation has unconfirmed cleanup. No new Finder request was admitted.', retryable: false };
  return { code: 'installation_reveal_unconfirmed', message: 'The Finder request could not be confirmed. Check Finder before requesting it again; the app does not retry automatically.', retryable: false };
}
export const installationLocationHelp: HelpContent = {
  label: 'Application location', requiredness: 'optional', requiredWhen: 'Information only; there is no location to configure.',
  what: 'The protected location used by the macOS Installer for this application.',
  why: 'The app and bundled runtime must remain under the protected installation path.',
  where: 'Use Show in Finder, or Finder → Go → Go to Folder and enter the displayed location.',
  format: 'A fixed folder location, not a project path. Do not move or copy the app to select another runtime.',
  failure: 'A moved or copied app cannot use this installed runtime. This card describes the layout; it does not check installation integrity or signing.',
};


export type InstallationCheckPhase = 'not-checked' | 'checking' | 'stopping' | 'observed' | 'refused' | 'unknown';
export type InstallationCheckReason = 'none' | 'unavailable-profile' | 'busy' | 'document-unavailable' | 'wrong-location'
  | 'missing' | 'incomplete' | 'record-mismatch' | 'payload-mismatch' | 'protection' | 'bounds' | 'native'
  | 'cancelled' | 'deadline' | 'cleanup-unknown';
export interface InstallationMatching {
  files: number; bytes: number; assurance: 'read-only-correspondence'; maintenance: 'unavailable';
}
export interface InstallationStatus {
  schemaVersion: 1; statusRevision: number; available: boolean; canStart: boolean; operationId: number | null;
  phase: InstallationCheckPhase; reason: InstallationCheckReason;
  settlement: 'not-started' | 'pending' | 'known' | 'unknown' | 'late-known';
  assessment: InstallationMatching | null;
}
const CHECK_REASONS: readonly InstallationCheckReason[] = ['none', 'unavailable-profile', 'busy', 'document-unavailable',
  'wrong-location', 'missing', 'incomplete', 'record-mismatch', 'payload-mismatch', 'protection', 'bounds', 'native',
  'cancelled', 'deadline', 'cleanup-unknown'];
function counter(value: unknown, positive = false): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= (positive ? 1 : 0) && value <= 0xffffffff;
}
export function parseInstallationCancel(value: unknown): { operationId: number } | null {
  const row = record(value, ['operationId']);
  return row && counter(row.operationId, true) ? { operationId: row.operationId } : null;
}
export function parseInstallationStatus(value: unknown): InstallationStatus | null {
  const row = record(value, ['schemaVersion', 'statusRevision', 'available', 'canStart', 'operationId', 'phase', 'reason', 'settlement', 'assessment']);
  if (!row || row.schemaVersion !== 1 || !counter(row.statusRevision)
    || typeof row.available !== 'boolean' || typeof row.canStart !== 'boolean' || (!row.available && row.canStart)
    || (row.operationId !== null && !counter(row.operationId, true))
    || !['not-checked', 'checking', 'stopping', 'observed', 'refused', 'unknown'].includes(row.phase as string)
    || !CHECK_REASONS.includes(row.reason as InstallationCheckReason)
    || !['not-started', 'pending', 'known', 'unknown', 'late-known'].includes(row.settlement as string)) return null;
  let assessment: InstallationMatching | null = null;
  if (row.assessment !== null) {
    const matching = record(row.assessment, ['files', 'bytes', 'assurance', 'maintenance']);
    if (!matching || !counter(matching.files, true) || matching.files > 2048
      || !counter(matching.bytes) || matching.bytes > 512 * 1024 * 1024
      || matching.assurance !== 'read-only-correspondence' || matching.maintenance !== 'unavailable') return null;
    assessment = { files: matching.files, bytes: matching.bytes, assurance: matching.assurance, maintenance: matching.maintenance };
  }
  if ((row.phase === 'not-checked') !== (row.operationId === null)
    || (row.phase === 'not-checked') !== (row.settlement === 'not-started')
    || (row.phase === 'observed') !== (assessment !== null)
    || row.phase === 'observed' && (row.reason !== 'none' || row.settlement !== 'known')
    || row.phase === 'refused' && (row.reason === 'none' || row.settlement !== 'known')
    || ['checking', 'stopping'].includes(row.phase as string) && row.settlement !== 'pending'
    || row.phase === 'checking' && row.reason !== 'none'
    || ['stopping', 'unknown'].includes(row.phase as string) && row.reason === 'none'
    || row.phase === 'unknown' && !['unknown', 'late-known'].includes(row.settlement as string)
    || ['checking', 'stopping', 'unknown'].includes(row.phase as string) && row.canStart) return null;
  return { schemaVersion: 1, statusRevision: row.statusRevision, available: row.available, canStart: row.canStart,
    operationId: row.operationId as number | null, phase: row.phase as InstallationCheckPhase, reason: row.reason as InstallationCheckReason,
    settlement: row.settlement as InstallationStatus['settlement'], assessment };
}
export function sameInstallationStatus(a: InstallationStatus, b: InstallationStatus): boolean {
  return a.schemaVersion === b.schemaVersion && a.statusRevision === b.statusRevision
    && a.available === b.available && a.canStart === b.canStart && a.operationId === b.operationId
    && a.phase === b.phase && a.reason === b.reason && a.settlement === b.settlement
    && (a.assessment === null ? b.assessment === null : b.assessment !== null
      && a.assessment.files === b.assessment.files && a.assessment.bytes === b.assessment.bytes
      && a.assessment.assurance === b.assessment.assurance && a.assessment.maintenance === b.assessment.maintenance);
}
export function installationCheckActive(status: InstallationStatus | null): boolean {
  return !!status && (status.phase === 'checking' || status.phase === 'stopping'
    || status.phase === 'unknown' && status.settlement !== 'late-known');
}
export function installationCheckError(error: unknown): ApiError {
  let code: unknown;
  try {
    const descriptor = typeof error === 'object' && error !== null ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
    if (descriptor && 'value' in descriptor) code = descriptor.value;
  } catch { /* Do not retain arbitrary rejection details. */ }
  if (code === 'installation_check_unavailable') return { code, message: 'Installation checking is available only in the normal installed macOS app. This is not evidence that an installation is missing.', retryable: false };
  if (code === 'installation_check_busy' || code === 'busy') return { code: 'installation_check_busy', message: 'Finish or cancel the current native action or quit confirmation, then check again.', retryable: false };
  if (code === 'installation_check_bounds') return { code, message: 'The retained session cannot safely fit this check. Finish active work, lock the credential session, and clear retained Android tool selections, then try again.', retryable: false };
  if (code === 'installation_check_stale') return { code, message: 'That check is no longer current. Refresh the installation status; no other operation was cancelled.', retryable: false };
  if (code === 'cleanup_unknown') return { code, message: 'Cleanup is unconfirmed. Keep the app open to observe the original check; do not start a replacement or delete installed files.', retryable: false };
  if (code === 'installation_document_unavailable' || code === 'shutting_down') return { code: 'installation_document_unavailable', message: 'The original app window is closing or unavailable. No new installation check was admitted.', retryable: false };
  return { code: 'installation_check_unconfirmed', message: 'The installation-check reply could not be confirmed. Refresh status before taking another action; the app has not automatically started another check.', retryable: false };
}
export const installationCheckHelp: HelpContent = {
  label: 'Check installation', requiredness: 'optional', requiredWhen: 'Use when troubleshooting this installed macOS application.',
  what: 'A read-only comparison of the installed app and bundled runtime against this package’s protected installation records.',
  why: 'It can identify missing records, incomplete installation or changed payload without changing the installation.',
  where: 'Open the normal installed app in the fixed location shown above, then choose Check installation. No project or credential is required.',
  format: 'No paths, signing inputs or commands to enter. The check reads only this fixed installation, with a 30-second work limit.',
  failure: 'Keep partial-installation evidence and the existing protected files. A mismatch does not authorize repair, deletion, another administrator run or a public release. This check is not signing/notarization verification or release readiness.',
};
export const INSTALLATION_CHECK_GUIDANCE: Record<InstallationCheckReason, string> = {
  none: 'This is a point-in-time read-only observation, not an update, signing check or release-readiness decision.',
  'unavailable-profile': 'Use the normal installed macOS app. Browser preview and other runtime profiles cannot perform this check.',
  busy: 'Finish or cancel the original native operation before checking again.',
  'document-unavailable': 'The original app window is unavailable. Do not treat its previous result as current.',
  'wrong-location': 'Open the original app at the displayed fixed location. A moved or copied app cannot select a different runtime.',
  missing: 'The protected installation root was not present. Keep available installer evidence; this card does not install or recover files.',
  incomplete: 'A required installed component or record is missing. Keep the partial installation intact for diagnosis; do not delete it to make a retry pass.',
  'record-mismatch': 'The installation records do not match this app’s package bindings. Preserve them and obtain a matching supported package; this app cannot adopt or overwrite the tree.',
  'payload-mismatch': 'An installed file or directory does not match the package inventory. Preserve the installation and evidence; do not use this result to approve a release.',
  protection: 'The installation’s location, ownership, permissions or filesystem protection could not be accepted. Do not change permissions to bypass this check.',
  bounds: 'The check reached a safe size or resource limit. Finish other session work before retrying; if it persists, preserve the installation for diagnosis.',
  native: 'A native read or filesystem observation failed. Keep the original result; check status before starting another operation.',
  cancelled: 'The original check was cancelled. Known cleanup means its resources settled, not that the installation passed.',
  deadline: 'The original check exceeded its fixed work limit. Cleanup is separate; a late result cannot turn this into a pass.',
  'cleanup-unknown': 'Resource cleanup is unconfirmed. Keep the app open to observe the original owner; no new check or maintenance is authorized.',
};

export const PREPARE_QUIT_CONFIRMATION = 'Stop the installed Android helper and prepare this application to quit';
export type InstallationPreparationPhase = 'not-started' | 'preparing' | 'unregistering' | 'settling' | 'prepared' | 'refused' | 'unknown';
export type InstallationPreparationReason = 'none' | 'unavailable-profile' | 'busy' | 'document-unavailable'
  | 'context-changed' | 'cancelled' | 'deadline' | 'native' | 'cleanup-unknown';
export interface InstallationPreparationStatus {
  schemaVersion: 1; available: boolean; canStart: boolean; operationId: string | null; generation: number | null;
  phase: InstallationPreparationPhase; reason: InstallationPreparationReason; newWorkClosed: boolean;
  assurance: 'preparation-status-only';
}
const PREPARATION_PHASES: readonly InstallationPreparationPhase[] = ['not-started', 'preparing', 'unregistering', 'settling', 'prepared', 'refused', 'unknown'];
const PREPARATION_REASONS: readonly InstallationPreparationReason[] = ['none', 'unavailable-profile', 'busy', 'document-unavailable', 'context-changed', 'cancelled', 'deadline', 'native', 'cleanup-unknown'];
export function parseInstallationPreparationRequest(value: unknown): { confirmation: typeof PREPARE_QUIT_CONFIRMATION } | null {
  const row = record(value, ['confirmation']);
  return row?.confirmation === PREPARE_QUIT_CONFIRMATION ? { confirmation: PREPARE_QUIT_CONFIRMATION } : null;
}
export function parseInstallationPreparationStatus(value: unknown): InstallationPreparationStatus | null {
  const row = record(value, ['schemaVersion', 'available', 'canStart', 'operationId', 'generation', 'phase', 'reason', 'newWorkClosed', 'assurance']);
  if (!row || row.schemaVersion !== 1 || typeof row.available !== 'boolean' || typeof row.canStart !== 'boolean'
    || typeof row.newWorkClosed !== 'boolean' || row.assurance !== 'preparation-status-only'
    || typeof row.phase !== 'string' || !PREPARATION_PHASES.includes(row.phase as InstallationPreparationPhase)
    || typeof row.reason !== 'string' || !PREPARATION_REASONS.includes(row.reason as InstallationPreparationReason)
    || row.operationId !== null && (typeof row.operationId !== 'string' || !/^[0-9a-f]{32}$/.test(row.operationId) || /^0+$/.test(row.operationId))
    || row.generation !== null && (!counter(row.generation, true) || row.generation === 0xffffffff)
    || (row.operationId === null) !== (row.generation === null)
    || (row.phase === 'not-started') !== (row.operationId === null)
    || row.canStart && (!row.available || row.newWorkClosed)
    || row.phase === 'not-started' && (row.newWorkClosed || row.canStart && row.reason !== 'none')
    || row.phase !== 'not-started' && row.phase !== 'refused' && (!row.newWorkClosed || row.canStart)
    || row.phase === 'refused' && row.reason === 'none'
    || row.phase === 'prepared' && row.reason !== 'none'
    || row.phase === 'unknown' && row.reason !== 'cleanup-unknown') return null;
  return { schemaVersion: 1, available: row.available, canStart: row.canStart, operationId: row.operationId as string | null,
    generation: row.generation as number | null, phase: row.phase as InstallationPreparationPhase,
    reason: row.reason as InstallationPreparationReason, newWorkClosed: row.newWorkClosed, assurance: 'preparation-status-only' };
}
export function installationPreparationActive(status: InstallationPreparationStatus | null): boolean {
  return status !== null && ['preparing', 'unregistering', 'settling'].includes(status.phase);
}
export function installationPreparationError(error: unknown): ApiError {
  let code: unknown;
  try {
    const descriptor = typeof error === 'object' && error !== null ? Object.getOwnPropertyDescriptor(error, 'code') : undefined;
    if (descriptor && 'value' in descriptor) code = descriptor.value;
  } catch { /* Raw native/provider rejection data is never retained. */ }
  if (code === 'macos_maintenance_unavailable') return { code,
    message: 'Preparation requires the normal installed app, its configured Android helper and settled work. Refresh status before trying again. Project signing settings cannot enable an unavailable app profile.', retryable: false };
  if (code === 'busy' || code === 'quit_pending' || code === 'macos_maintenance_busy') return { code: 'macos_maintenance_busy',
    message: 'Finish or cancel the existing operation or quit question, then refresh. No replacement preparation was started automatically.', retryable: false };
  if (code === 'cleanup_unknown') return { code,
    message: 'An original operation has unconfirmed cleanup. Keep the app open; do not delete installed files, terminate other processes or start another preparation.', retryable: false };
  if (code === 'shutting_down' || code === 'installation_document_unavailable') return { code: 'installation_document_unavailable',
    message: 'The original app window is closing or unavailable. Preserve the original status; no replacement preparation was started.', retryable: false };
  if (code === 'invalid_request' || code === 'installation_preparation_invalid') return { code: 'installation_preparation_invalid',
    message: 'Preparation needs the explicit confirmation shown here. No paths, commands or Installer choices are accepted.', retryable: false };
  return { code: 'installation_preparation_unconfirmed',
    message: 'The preparation reply could not be confirmed. Refresh the original status; the app does not retry preparation or treat a lost reply as completion.', retryable: false };
}
export const installationPreparationHelp: HelpContent = {
  label: 'Prepare app to quit', requiredness: 'optional', requiredWhen: 'Use only when you want to stop the installed Android helper and close this app.',
  what: 'An explicit request to stop new work, settle the original helper operation and then use the app’s normal Quit flow.',
  why: 'Closing a window alone does not establish that the installed helper and its original work have settled.',
  where: 'Use the normal app in the protected location above. Finish active work, review the explanation, and select the confirmation checkbox.',
  format: 'No paths, passwords, project signing inputs or terminal commands. The checkbox applies to one explicit preparation request.',
  failure: 'A failure or unconfirmed cleanup is not safe completion. Keep the app and evidence intact; do not kill unrelated processes or delete installed files. This does not install, repair, update or uninstall the app and makes no Store changes.',
};
export const INSTALLATION_PREPARATION_GUIDANCE: Record<InstallationPreparationReason, string> = {
  none: 'Preparation is separate from installation checking. This status does not authorize an Installer operation or prove the app has exited.',
  'unavailable-profile': 'This build does not currently expose the required installed helper for this original window. Project signing credentials cannot enable it.',
  busy: 'Finish or cancel the current native work and dismiss any quit question, then refresh before confirming preparation.',
  'document-unavailable': 'The original app window is closing or unavailable. Do not use an old status as permission to replace files.',
  'context-changed': 'The original context changed. Keep the retained result and refresh; no automatic replacement request is made.',
  cancelled: 'The original request was cancelled. A cancelled result is not successful preparation.',
  deadline: 'The original operation reached its fixed deadline. A later reply cannot turn this into successful preparation.',
  native: 'The original native helper operation was refused or failed. Retain its result and refresh status; do not bypass it by changing installed files.',
  'cleanup-unknown': 'The original cleanup is unconfirmed. Keep the app open and retain evidence. New preparation, automatic helper registration and file removal are not authorized.',
};
