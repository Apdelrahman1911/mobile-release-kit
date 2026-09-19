import type { ApiError, JsonObject } from './types.ts';

// Native session DTOs, not a renderer file API or a second credential policy.
export type AssetFileKind = 'android-keystore' | 'android-firebase';
export type AssetScalarKind = 'google-wif' | 'project-read-token';
export type AssetKind = AssetFileKind | AssetScalarKind;
export type AssetPlatform = 'android' | 'ios' | 'project';
export type AssetStage = 'candidate' | 'external-testing' | 'production';
export type AssetPurpose = 'full' | 'signing' | 'store';
export interface AssetScope { platform: AssetPlatform; stage: AssetStage; purpose: AssetPurpose }
export interface AssetContextRequest extends AssetScope { projectId: string; draft: JsonObject }
export interface AssetRecordRef { recordId: string; expectedRevision: number }
export interface AssetPreviewSubject {
  kind: AssetKind;
  change: 'new' | 'replace' | 'assign' | 'delete';
  recordId: string | null;
  recordRevision: number | null;
}
export interface AssetIntent {
  kind: AssetKind;
  change: AssetPreviewSubject['change'];
  record: AssetRecordRef | null;
}
export interface AssetChooseRequest { contextRevision: number; kind: AssetFileKind; replacement: AssetRecordRef | null }
export interface KeystoreFields { storePassword: string | null; keyAlias: string | null; keyPassword: string | null }
export interface WifFields { provider: string | null; serviceAccount: string | null }
export interface TokenFields { token: string | null }
export type AssetFields = KeystoreFields | WifFields | TokenFields | Record<string, never>;
export type CredentialPrepareRequest =
  | { contextRevision: number; source: { type: 'selection'; selectionToken: string }; fields: KeystoreFields | Record<string, never> }
  | { contextRevision: number; source: { type: 'record'; recordId: string; expectedRevision: number } }
  | { contextRevision: number; source: { type: 'scalar'; kind: 'google-wif'; replacement: AssetRecordRef | null }; fields: WifFields }
  | { contextRevision: number; source: { type: 'scalar'; kind: 'project-read-token'; replacement: AssetRecordRef | null }; fields: TokenFields };

export type AssetReason = 'none' | 'closed' | 'unqualified' | 'unsupported-platform' | 'unsupported-filesystem' | 'unsupported-format' | 'invalid-request' | 'busy' | 'source-refused' | 'source-changed' | 'material-limit' | 'parser-limit' | 'project-overlap' | 'exclusion-unconfirmed' | 'capacity' | 'context-stale' | 'user-cancelled' | 'review-expired' | 'deadline' | 'document-lost' | 'shutdown' | 'cleanup-unknown';
export type AssetPhase = 'idle' | 'admitting' | 'picking' | 'capturing' | 'selected' | 'assessing' | 'preview' | 'mutating' | 'stopping' | 'unknown';
export type AssetOperationName = 'choose-file' | 'choose-project' | 'choose-evidence-folder' | 'inspect-evidence' | 'prepare' | 'prepare-delete' | 'commit' | 'bind' | 'discard' | 'lock';
export type CredentialState = 'not-applicable' | 'missing' | 'unknown' | 'invalid' | 'configured' | 'format-valid';
export type CredentialFieldId = 'file' | 'storePassword' | 'keyAlias' | 'keyPassword' | 'provider' | 'serviceAccount' | 'token';
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
  schemaVersion: 1;
  statusRevision: number;
  mode: 'closed' | 'session';
  capability: { available: boolean; reason: AssetReason };
  context: ({ revision: number; projectId: string } & AssetScope) | null;
  operation: {
    operationId: number; operation: AssetOperationName; phase: AssetPhase; reason: AssetReason;
    source: 'not-run' | 'pending' | 'captured' | 'refused' | 'unknown';
    settlement: 'pending' | 'known' | 'unknown' | 'late-known';
    selectionToken: string | null; assessment: CredentialAssessment | null;
    preview: { token: string; action: 'save' | 'bind' | 'delete'; expiresInMs: number; subject: AssetPreviewSubject } | null;
  } | null;
  records: { recordId: string; revision: number; kind: AssetKind; availability: 'unassigned' | 'assigned' | 'mutation-pending' }[];
  assignments: { kind: AssetKind; recordId: string; recordRevision: number; contextRevision: number; availability: 'available' | 'unavailable' }[];
}

export interface AssetSessionApi {
  assetStatus(): Promise<AssetStatus>;
  openAssetSession(): Promise<AssetStatus>;
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
