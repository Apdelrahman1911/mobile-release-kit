import type { ApiError, JsonObject } from './types.ts';

// Native session DTOs, not a renderer file API or a second credential policy.
export type AssetFileKind = 'android-keystore' | 'android-firebase' | 'ios-firebase' | 'apple-p12' | 'apple-profile' | 'asc-p8';
export type AssetScalarKind = 'google-wif' | 'project-read-token';
export type AssetKind = AssetFileKind | AssetScalarKind;
export type AssetPlatform = 'android' | 'ios' | 'project';
export type AssetStage = 'candidate' | 'external-testing' | 'production';
export type AssetPurpose = 'full' | 'signing' | 'store';
export interface AssetScope { platform: AssetPlatform; stage: AssetStage; purpose: AssetPurpose }
export interface AssetContextRequest extends AssetScope { projectId: string; draft: JsonObject }
export interface AssetRecordRef { recordId: string; expectedRevision: number }
export interface AssetRecordPreviewSubject {
  type: 'record';
  kind: AssetKind;
  change: 'new' | 'replace' | 'assign' | 'delete';
  recordId: string | null;
  recordRevision: number | null;
}
export type AssetPreviewSubject = AssetRecordPreviewSubject | { type: 'vault'; change: 'initialize' };
export type AssetPreviewAction = 'save' | 'bind' | 'delete' | 'initialize';
export interface AssetRecordIntent {
  type: 'record';
  kind: AssetKind;
  change: AssetRecordPreviewSubject['change'];
  record: AssetRecordRef | null;
}
export type AssetIntent = AssetRecordIntent | { type: 'vault'; change: 'open' | 'initialize' | 'unlock' };
export interface AssetChooseRequest { contextRevision: number; kind: AssetFileKind; replacement: AssetRecordRef | null }
export interface KeystoreFields { storePassword: string | null; keyAlias: string | null; keyPassword: string | null }
export interface P12Fields { password: string | null }
export interface AscP8Fields { keyId: string | null; issuerId: string | null }
export interface WifFields { provider: string | null; serviceAccount: string | null }
export interface TokenFields { token: string | null }
export type AssetFields = KeystoreFields | P12Fields | AscP8Fields | WifFields | TokenFields | Record<string, never>;
export type CredentialPrepareRequest =
  | { contextRevision: number; source: { type: 'selection'; selectionToken: string }; fields: KeystoreFields | P12Fields | AscP8Fields | Record<string, never>; label?: string | null }
  | { contextRevision: number; source: { type: 'record'; recordId: string; expectedRevision: number } }
  | { contextRevision: number; source: { type: 'scalar'; kind: 'google-wif'; replacement: AssetRecordRef | null }; fields: WifFields; label?: string | null }
  | { contextRevision: number; source: { type: 'scalar'; kind: 'project-read-token'; replacement: AssetRecordRef | null }; fields: TokenFields; label?: string | null };

export type AssetReason = 'none' | 'closed' | 'unqualified' | 'unsupported-platform' | 'unsupported-filesystem' | 'unsupported-format' | 'invalid-request' | 'busy' | 'source-refused' | 'source-changed' | 'material-limit' | 'parser-limit' | 'project-overlap' | 'exclusion-unconfirmed' | 'capacity' | 'context-stale' | 'user-cancelled' | 'review-expired' | 'deadline' | 'document-lost' | 'shutdown' | 'cleanup-unknown' |
  'vault-uninitialized' | 'vault-key-missing' | 'vault-keyring-locked' | 'vault-keyring-denied' | 'vault-keyring-unavailable' | 'vault-provider-unsupported' | 'vault-corrupt' | 'vault-interrupted' | 'vault-durability-unknown';
export type AssetPhase = 'idle' | 'admitting' | 'picking' | 'capturing' | 'selected' | 'assessing' | 'preview' | 'mutating' | 'stopping' | 'unknown';
export type AssetOperationName = 'choose-file' | 'choose-images' | 'choose-project' | 'choose-project-path' | 'choose-evidence-folder' | 'inspect-evidence' | 'prepare' | 'prepare-delete' | 'commit' | 'bind' | 'discard' | 'lock' | 'open-vault' | 'prepare-initialize' | 'initialize' | 'unlock';
export type CredentialState = 'not-applicable' | 'missing' | 'unknown' | 'invalid' | 'configured' | 'format-valid';
export type CredentialFieldId = 'file' | 'storePassword' | 'keyAlias' | 'keyPassword' | 'password' | 'keyId' | 'issuerId' | 'provider' | 'serviceAccount' | 'token';
export type CredentialIssue = 'not-run' | 'incomplete' | 'unsupported-format' | 'unsupported-variant' | 'material-limit' | 'parser-limit' | 'empty-file' | 'suffix-conflict' | 'malformed-container' | 'required-missing' | 'value-nul' | 'scalar-format' | 'pkcs8-algorithm' | 'firebase-shape' | 'identity-mismatch';
export type CredentialCheckScope = 'value-admission' | 'identifier-format' | 'file-nonempty' | 'suffix-consistency' | 'container-parse' | 'jks-header' | 'pfx-envelope' | 'cms-signed-data-envelope' | 'pkcs8-envelope' | 'json-document' | 'plist-document' | 'ec-p256-identifiers' | 'firebase-shape' | 'application-identity';
export interface CredentialAssessment {
  schemaVersion: 1;
  policyVersion: 'credential-policy-v1';
  kind: AssetKind;
  context: AssetScope;
  applicability: { state: 'required' | 'not-applicable'; reason: 'selected' | 'wrong-platform' | 'platform-disabled' | 'not-required' };
  state: CredentialState;
  fields: { id: CredentialFieldId; requirement: string; presence: 'missing' | 'supplied'; state: CredentialState; issues: CredentialIssue[]; checks: { scope: CredentialCheckScope; outcome: 'passed' | 'failed' | 'asserted-pass' | 'asserted-fail' }[] }[];
  identity: 'not-applicable' | 'not-assessed' | 'match' | 'mismatch';
  assurance: {
    basis: 'supplied-input-only'; scalarValuesProcessed: boolean; fileObservationsProcessed: boolean;
    selectedFilesRead: false; keyringAccessed: false; storageWritesPerformed: false; projectCodeExecuted: false;
    sourceCustody: 'not-established'; nativeValidation: 'not-run'; serviceValidation: 'not-run'; releaseReadiness: 'unknown';
  };
}
export interface AssetStatus {
  schemaVersion: 2;
  statusRevision: number;
  mode: 'closed' | 'session' | 'encrypted';
  persistence: { state: 'uninitialized' | 'locked' | 'unlocked' | 'initializing' | 'mutating' | 'interrupted' | 'unknown'; reason: AssetReason; keyAccess: 'locked' | 'read-only' | 'read-write' } | null;
  capability: { available: boolean; reason: AssetReason };
  context: ({ revision: number; projectId: string } & AssetScope) | null;
  operation: {
    operationId: number; operation: AssetOperationName; phase: AssetPhase; reason: AssetReason;
    source: 'not-run' | 'pending' | 'captured' | 'refused' | 'unknown';
    settlement: 'pending' | 'known' | 'unknown' | 'late-known';
    storageOutcome: { effect: 'not-started' | 'known-none' | 'known-applied' | 'unknown'; durability: 'not-run' | 'confirmed' | 'unknown'; cleanup: 'pending' | 'known' | 'unknown' } | null;
    selectionToken: string | null; assessment: CredentialAssessment | null;
    preview: { token: string; action: AssetPreviewAction; expiresInMs: number; subject: AssetPreviewSubject } | null;
  } | null;
  records: { recordId: string; revision: number; kind: AssetKind; availability: 'unassigned' | 'assigned' | 'mutation-pending'; storage: 'session' | 'encrypted'; label: string | null; payloadState: 'not-checked' | 'assessed' }[];
  assignments: { kind: AssetKind; recordId: string; recordRevision: number; contextRevision: number; availability: 'available' | 'unavailable' }[];
}

export interface AssetSessionApi {
  assetStatus(): Promise<AssetStatus>;
  openAssetSession(mode?: 'session' | 'encrypted'): Promise<AssetStatus>;
  prepareVaultInitialize(): Promise<AssetStatus>;
  unlockVault(): Promise<AssetStatus>;
  setAssetContext(request: AssetContextRequest): Promise<AssetStatus>;
  chooseAsset(request: AssetChooseRequest): Promise<AssetStatus>;
  prepareCredential(request: CredentialPrepareRequest): Promise<AssetStatus>;
  prepareAssetDelete(record: AssetRecordRef): Promise<AssetStatus>;
  commitAsset(previewToken: string): Promise<AssetStatus>;
  bindAsset(previewToken: string): Promise<AssetStatus>;
  discardAsset(operationId: number): Promise<AssetStatus>;
  lockAssetSession(): Promise<AssetStatus>;
  subscribeAssets(onStatus: (status: unknown) => void): Promise<() => void>;
}
export interface AssetDisplayState {
  mode: 'native' | 'preview' | 'unavailable';
  status: AssetStatus | null;
  scope: AssetScope;
  contextCurrent: boolean;
  busy: AssetOperationName | 'open' | null;
  updatingContext: boolean;
  observing: boolean;
  observationFailed: boolean;
  blocked: boolean;
  error: ApiError | null;
  previewDeadline: number | null;
  entryGeneration: number;
  selectionKind: AssetFileKind | null;
  cancelledOperationId: number | null;
  originPending: boolean;
  intent: AssetIntent | null;
  reviewReady: boolean;
}
