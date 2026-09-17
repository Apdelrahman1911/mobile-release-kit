import { reviewFresh, savedRevisionFresh, validationFresh } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import type { AppInfo, BridgeMode, Capabilities } from './types.ts';

export type Tone = 'neutral' | 'info' | 'warning' | 'danger';
export interface StatusLabel { label: string; tone: Tone }

export function configurationStatus(session: ProjectSession | null, preview: boolean): StatusLabel {
  if (preview && session?.snapshot) return { label: 'Example only', tone: 'warning' };
  if (session?.snapshotError && session.snapshot) return { label: 'Stale observation', tone: 'warning' };
  if (session?.snapshotPredatesSave && session.snapshot) return { label: 'Earlier static observation', tone: 'warning' };
  if (!session?.snapshot) return { label: 'Not assessed', tone: 'neutral' };
  if (session.snapshot.config.state === 'format-valid') return { label: 'Format-valid only', tone: 'info' };
  if (session.snapshot.config.state === 'invalid') return { label: 'Needs attention', tone: 'danger' };
  if (session.snapshot.config.state === 'missing') return { label: 'Not configured', tone: 'neutral' };
  return { label: 'Unavailable', tone: 'warning' };
}

export function draftStatus(session: ProjectSession): StatusLabel {
  if (session.validationRequest) return { label: 'Validating format…', tone: 'info' };
  if (session.reviewRequest) return { label: 'Reviewing draft…', tone: 'info' };
  if (savedRevisionFresh(session)) return { label: session.lastSave?.result === 'unchanged' ? 'No changes needed · not verified' : 'Saved revision · not verified', tone: 'info' };
  if (session.validation && validationFresh(session)) {
    return session.validation.valid && session.validation.state === 'format-valid'
      ? { label: 'Format-valid · not saved', tone: 'info' }
      : { label: 'Needs correction', tone: 'danger' };
  }
  if (session.review && reviewFresh(session)) {
    return session.review.result.validation.valid && session.review.result.validation.state === 'format-valid'
      ? { label: 'Format-valid · not saved', tone: 'info' }
      : { label: 'Needs correction', tone: 'danger' };
  }
  if (session.review) return { label: 'Draft review is stale', tone: 'warning' };
  if (session.validation) return { label: 'Validation is stale', tone: 'warning' };
  return { label: 'Not validated', tone: 'neutral' };
}

export function methodReason(info: AppInfo | null, method: string, mode: BridgeMode): string | null {
  if (mode === 'preview') return 'Browser preview cannot perform native operations or core validation.';
  if (mode !== 'native') return 'The native desktop bridge is unavailable.';
  if (!info) return 'Application capabilities have not been loaded.';
  if (info.runtime.state !== 'available') return info.runtime.reason ?? 'The bundled engine is unavailable.';
  const capability = info.capabilities?.methods.find((entry) => entry.method === method);
  return capability?.available ? null : capability?.reason ?? 'This operation is not available in the current engine.';
}

export function futureReason(capabilities: Capabilities | null | undefined, action: string, fallback: string): string {
  return capabilities?.actions.find((entry) => entry.id === action)?.reason ?? fallback;
}
