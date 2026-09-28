// Bounded, public image-summary DATA. Tokens correlate an original native owner;
// none of these types authorizes a renderer path, byte buffer or transaction.
import type { BridgeMode, CoreEditOutcome, EditAvailability, HelpContent, NativeEditReason } from './types.ts';
import type { MetadataPlatform } from './metadataText.ts';

export interface ImageContentDigest { byteLength: number; sha256: string }
export interface ImageSummary extends ImageContentDigest {
  format: 'png' | 'jpeg' | null;
  width: number | null;
  height: number | null;
  headerChecked: boolean;
}
export interface MetadataImagesBaseline {
  config: ImageContentDigest;
  ignore: ImageContentDigest;
  inventorySha256: string;
}
export interface MetadataImageIssue { code: string; message: string; severity: 'error' }
export interface MetadataImagesAssurance {
  localCopyOnly: true;
  sourceFilesUnchanged: true;
  storeContacted: false;
  fullDecode: false;
  contentApproved: false;
  storeAccepted: false;
}
export interface MetadataImageFile {
  itemId: string;
  displayName: string;
  path: string;
  action: 'create' | 'replace' | 'preserve';
  before: ImageSummary | null;
  selected: ImageSummary;
  after: ImageSummary;
  canReplace: boolean;
  issues: MetadataImageIssue[];
}
export interface MetadataImagesImportView {
  kind: 'import';
  policy: 'metadata-images-v1';
  platform: MetadataPlatform;
  locale: string;
  assetType: string;
  metadataRoot: string;
  folder: string;
  files: MetadataImageFile[];
  existing: { path: string; summary: ImageSummary }[];
  finalOrder: string[];
  valid: boolean;
  issues: MetadataImageIssue[];
  assurance: MetadataImagesAssurance;
}
export type MetadataImagesView = MetadataImagesImportView | MetadataImagesRecoveryView;
export interface MetadataImagesCheckout { revision: string; baseline: MetadataImagesBaseline; view: MetadataImagesView }
export interface MetadataImagesPrepared {
  revision: string;
  planToken: string;
  draftRevision: number;
  baselineGeneration: number;
  view: MetadataImagesView;
}
export interface MetadataImagesDetails {
  intent: 'import' | 'recover';
  checkout: MetadataImagesCheckout | null;
  prepared: MetadataImagesPrepared | null;
}
export interface MetadataImagesEditProjection {
  domain: 'metadata_images';
  projectId: string;
  sessionId: string;
  ownerGeneration: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number;
  applySubmitted: boolean;
  coreOutcome: CoreEditOutcome | null;
  nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown';
  lateSettled: boolean;
  details: MetadataImagesDetails | null;
}
export interface MetadataImagesEditStatus {
  schemaVersion: 1;
  domain: 'metadata_images';
  windowGeneration: string;
  statusRevision: number;
  capability: { available: boolean; reason: EditAvailability };
  active: MetadataImagesEditProjection | null;
  lastTerminal: MetadataImagesEditProjection | null;
}
export interface MetadataImageSelectionItem extends ImageContentDigest { itemId: string; displayName: string }
export type MetadataImagesSelectionReason = 'none' | 'cancelled' | 'dialog_failed' | 'unsupported_platform' | 'runtime_unqualified' |
  'invalid_selection' | 'source_changed' | 'source_unavailable' | 'selection_limit' | 'busy' | 'caller_lost' | 'window_lost' |
  'shutdown' | 'active_timeout' | 'cleanup_unknown';
export interface MetadataImagesSelection {
  operationId: string;
  projectId: string;
  platform: MetadataPlatform;
  locale: string;
  assetType: string;
  phase: 'selecting' | 'capturing' | 'selected' | 'cancelled' | 'failed' | 'unknown';
  reason: MetadataImagesSelectionReason;
  settlement: 'pending' | 'known' | 'unknown' | 'late-known';
  selectionToken: string | null;
  items: MetadataImageSelectionItem[];
}
export interface MetadataImagesSelectionStatus {
  schemaVersion: 1;
  domain: 'metadata_images_selection';
  windowGeneration: string;
  statusRevision: number;
  capability: { available: boolean; reason: EditAvailability };
  active: MetadataImagesSelection | null;
  lastTerminal: MetadataImagesSelection | null;
}
export interface ChooseMetadataImagesRequest { projectId: string; platform: MetadataPlatform; locale: string; assetType: string }
export interface MetadataImageChoice { itemId: string; replaceExisting: boolean }
export interface PrepareMetadataImagesRequest {
  sessionId: string;
  revision: string;
  draftRevision: number;
  baselineGeneration: number;
  expectedBaseline: MetadataImagesBaseline;
  choices: MetadataImageChoice[];
}
export type MetadataImageHelpId = 'platform' | 'locale' | 'assetType' | 'files' | 'replaceExisting' | 'copyConfirmation' | 'recoveryConfirmation';
export interface MetadataImagesHelp {
  schemaVersion: 1;
  fields: (HelpContent & { id: MetadataImageHelpId; requiredness: 'required' | 'optional' })[];
}
// Normalized display options come only from the admitted shared catalogue.
export interface MetadataImageTypeChoice { id: string; label: string; description: string }
export interface MetadataImagesLimits { maxFiles: number; maxFileBytes: number; maxBatchBytes: number }
export type MetadataImagesCommand = 'metadata_images_catalog' | 'metadata_images_choose' | 'metadata_images_selection_status' |
  'metadata_images_selection_cancel' | 'metadata_images_edit_open' | 'metadata_images_recovery_open' | 'metadata_images_edit_prepare' |
  'metadata_images_edit_apply' | 'metadata_images_edit_close' | 'metadata_images_edit_status';
export interface MetadataImagesApi {
  mode: BridgeMode;
  metadataImagesCatalog(): Promise<MetadataImagesCatalog>;
  chooseMetadataImages(input: ChooseMetadataImagesRequest): Promise<MetadataImagesSelectionStatus>;
  metadataImagesSelectionStatus(): Promise<MetadataImagesSelectionStatus>;
  cancelMetadataImagesSelection(operationId: string): Promise<MetadataImagesSelectionStatus>;
  openMetadataImagesEdit(input: { projectId: string; selectionToken: string }): Promise<MetadataImagesEditStatus>;
  openMetadataImagesRecovery(projectId: string): Promise<MetadataImagesEditStatus>;
  prepareMetadataImagesEdit(input: PrepareMetadataImagesRequest): Promise<MetadataImagesEditStatus>;
  applyMetadataImagesEdit(sessionId: string, planToken: string): Promise<MetadataImagesEditStatus>;
  closeMetadataImagesEdit(sessionId: string): Promise<MetadataImagesEditStatus>;
  metadataImagesEditStatus(): Promise<MetadataImagesEditStatus>;
  subscribeMetadataImagesSelection(receive: (value: unknown) => void): Promise<() => void>;
  subscribeMetadataImagesEdit(receive: (value: unknown) => void): Promise<() => void>;
}

export interface MetadataImagesCatalog {
  schemaVersion: 1;
  policy: 'metadata-images-v1';
  platforms: { id: MetadataPlatform; label: string }[];
  types: { platform: MetadataPlatform; id: string; label: string; singleton: boolean; maxCount: number; dimensions: [number, number][] }[];
  limits: {
    maxFiles: 10; maxFileBytes: 10485760; maxBatchBytes: 25165824; maxTransactionBytes: 67108864;
    maxDimension: 16384; maxPixels: 67108864; formats: ['png', 'jpeg'];
  };
  help: MetadataImagesHelp['fields'];
}
export interface MetadataImagesRecoveryView {
  kind: 'recover';
  state: 'idle' | 'recoverable' | 'conflict';
  action: 'rollback' | 'committed_cleanup' | 'rolled_back_cleanup' | 'preparing_cleanup' | null;
  transactionId: string | null;
  platform: MetadataPlatform | null;
  locale: string | null;
  assetType: string | null;
  files: { path: string; effect: 'restore_original' | 'keep_committed' | 'preserve'; original: ImageContentDigest | null; new: ImageContentDigest | null }[];
  privateCleanup: { fileCount: number; directoryCount: number; scope: 'original-image-journal-only' };
  valid: boolean;
  issues: MetadataImageIssue[];
  assurance: { newRestorationAttempt: true; sourceFilesUnchanged: true; storeContacted: false; importRetried: false };
}
