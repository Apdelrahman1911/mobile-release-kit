import { invoke, isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { bridgeMode, createNativeApi } from './bridge.ts';
import type { DesktopApi } from './types.ts';

export async function desktopApi(): Promise<DesktopApi> {
  if (import.meta.env.VITE_MRK_BROWSER_PREVIEW === '1') {
    // Deliberate, compile-time preview only; never reached after a bridge error.
    const { previewApi } = await import('./preview.ts');
    return previewApi;
  }
  const mode = bridgeMode(undefined, isTauri());
  return createNativeApi(mode === 'native' ? 'native' : 'unavailable', invoke,
    (event, onStatus) => listen<unknown>(event, ({ payload }) => onStatus(payload)));
}
