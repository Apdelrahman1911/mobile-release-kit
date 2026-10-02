import type { ApiError, HelpContent } from './types.ts';

// Fixed presentation contract. No value here grants native admission, verifies
// an installation, chooses a runtime, or enables maintenance.
export interface InstallationDescription {
  layout: 'fixed-macos';
  expectedLocation: string;
  runtimeRelease: string;
  installMode: 'fresh-only';
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
    || row.installMode !== 'fresh-only' || row.maintenance !== 'unavailable'
    || typeof row.revealAvailable !== 'boolean' || row.assurance !== 'profile-description-only') return null;
  return { layout: 'fixed-macos', expectedLocation: row.expectedLocation, runtimeRelease: row.runtimeRelease,
    installMode: 'fresh-only', maintenance: 'unavailable', revealAvailable: row.revealAvailable, assurance: 'profile-description-only' };
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
