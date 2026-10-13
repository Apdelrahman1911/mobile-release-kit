import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { createMetadataImagesApi } from './metadataImagesBridge.ts';
import type { MetadataImagesApi } from './metadataImages.ts';
import type { BridgeMode } from './types.ts';

// Mode comes from the existing application connection. No error can select a
// browser picker, mock writer, CLI command or a second native document.
export function metadataImagesApi(mode: BridgeMode): MetadataImagesApi {
  return createMetadataImagesApi(mode, invoke,
    (event, receive) => listen<unknown>(event, ({ payload }) => receive(payload)));
}
