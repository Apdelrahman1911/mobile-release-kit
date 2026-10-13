// The same Tauri invoke/listen seam as the other edit domains, with a closed
// image-only DTO. This adapter never accepts browser Files, paths or image bytes.
import type { BridgeMode } from './types.ts';
import type { MetadataImagesApi, MetadataImagesCommand, MetadataImagesEditStatus, MetadataImagesSelectionStatus } from './metadataImages.ts';
import { metadataImagesError, metadataImagesRequestFits, parseMetadataImagesCatalog, parseMetadataImagesEditStatus,
  parseMetadataImagesSelectionStatus, METADATA_IMAGES_EDIT_EVENT, METADATA_IMAGES_SELECTION_EVENT } from './metadataImagesProtocol.ts';

export type MetadataImagesInvoke = <T>(command: string, args?: Record<string, unknown>) => Promise<T>;
export type MetadataImagesListen = (event: typeof METADATA_IMAGES_EDIT_EVENT | typeof METADATA_IMAGES_SELECTION_EVENT,
  onStatus: (status: unknown) => void) => Promise<() => void>;

export function createMetadataImagesApi(mode: BridgeMode, invoke: MetadataImagesInvoke, listen?: MetadataImagesListen): MetadataImagesApi {
  const call = async <T>(command: MetadataImagesCommand, input: unknown, parse: (value: unknown) => T | null): Promise<T> => {
    try {
      if (mode !== 'native') throw { code: 'metadata_images_unavailable' };
      if (!metadataImagesRequestFits(command, input)) throw { code: 'metadata_images_request_invalid' };
      const args = structuredClone(input) as Record<string, unknown>;
      const result = parse(await invoke<unknown>(command, args));
      if (!result) throw { code: command === 'metadata_images_catalog' ? 'metadata_images_catalog_invalid' : 'metadata_images_status_invalid' };
      return structuredClone(result);
    } catch (error) { throw metadataImagesError(error); }
  };
  const selection = (command: MetadataImagesCommand, input: unknown): Promise<MetadataImagesSelectionStatus> =>
    call(command, input, parseMetadataImagesSelectionStatus);
  const edit = (command: MetadataImagesCommand, input: unknown): Promise<MetadataImagesEditStatus> =>
    call(command, input, parseMetadataImagesEditStatus);
  const subscribe = async (event: typeof METADATA_IMAGES_EDIT_EVENT | typeof METADATA_IMAGES_SELECTION_EVENT,
    receive: (value: unknown) => void): Promise<() => void> => {
    try {
      if (mode !== 'native' || !listen) throw { code: 'metadata_images_unavailable' };
      // The retained controller reconciles complete events with original reads.
      return await listen(event, receive);
    } catch (error) { throw metadataImagesError(error); }
  };
  return {
    mode,
    metadataImagesCatalog: () => call('metadata_images_catalog', {}, parseMetadataImagesCatalog),
    chooseMetadataImages: (input) => selection('metadata_images_choose', input),
    metadataImagesSelectionStatus: () => selection('metadata_images_selection_status', {}),
    cancelMetadataImagesSelection: (operationId) => selection('metadata_images_selection_cancel', { operationId }),
    openMetadataImagesEdit: (input) => edit('metadata_images_edit_open', input),
    openMetadataImagesRecovery: (projectId) => edit('metadata_images_recovery_open', { projectId }),
    prepareMetadataImagesEdit: (input) => edit('metadata_images_edit_prepare', input),
    applyMetadataImagesEdit: (sessionId, planToken) => edit('metadata_images_edit_apply', { sessionId, planToken }),
    closeMetadataImagesEdit: (sessionId) => edit('metadata_images_edit_close', { sessionId }),
    metadataImagesEditStatus: () => edit('metadata_images_edit_status', {}),
    subscribeMetadataImagesSelection: (receive) => subscribe(METADATA_IMAGES_SELECTION_EVENT, receive),
    subscribeMetadataImagesEdit: (receive) => subscribe(METADATA_IMAGES_EDIT_EVENT, receive),
  };
}
