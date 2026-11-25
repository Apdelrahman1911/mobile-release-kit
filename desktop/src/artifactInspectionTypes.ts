// Closed observation DATA, not a native input loan, successful signature,
// source-provenance claim, consent token or original-lifetime receipt.
export type ArtifactFormat = 'aab' | 'ipa';
export type ArtifactRole = 'artifact' | 'archive' | 'dsyms';
export type ArtifactKind = 'file' | 'directory';
export type ArtifactCheck = 'byte-identity' | 'structure' | 'manifest' | 'expected-identity' | 'expected-version' |
  'signature' | 'profile-entitlements' | 'current-validity' | 'signer-policy' | 'archive-pair' | 'symbols';
export type ArtifactCheckStatus = 'pass' | 'fail' | 'unavailable' | 'not_applicable';
export type ArtifactCheckReason = 'none' | 'unsupported-format' | 'input-limit' | 'malformed-structure' |
  'identity-mismatch' | 'version-mismatch' | 'tools-unavailable' | 'signature-invalid' | 'signer-unobserved' |
  'saved-policy-missing' | 'signer-mismatch' | 'profile-invalid' | 'signing-time-invalid' |
  'archive-not-selected' | 'pair-mismatch' | 'symbols-not-selected' | 'symbols-mismatch' | 'prerequisite-not-run';
export type ArtifactLimitation = 'byte-observation-not-source-provenance' | 'current-signature-not-store-or-release-authority' |
  'saved-inputs-not-unsaved-draft' | 'no-build-sign-upload-or-store-operation' | 'external-changes-can-make-results-stale';
export interface ArtifactContent { bytes: number; sha256: string }
export interface ArtifactObservedInput {
  role: ArtifactRole; selectionId: string; label: string; kind: ArtifactKind; bytes: number; entries: number;
  identity: { method: 'sha256-file' | 'sha256-tree-v1'; sha256: string };
}
export interface ArtifactCheckResult { check: ArtifactCheck; status: ArtifactCheckStatus; reason: ArtifactCheckReason }
export interface ArtifactInspectionResult {
  schemaVersion: 1; scope: 'selected-artifact-bytes-only'; format: ArtifactFormat;
  usedConfig: ArtifactContent; usedVersion: ArtifactContent & { name: string; build: number };
  artifacts: ArtifactObservedInput[];
  observed: { applicationId: string | null; bundleId: string | null; versionName: string | null;
    versionBuild: string | null; signerSha256: string | null; teamId: string | null };
  checks: ArtifactCheckResult[]; limitations: ArtifactLimitation[];
}

// Same SavedCommand lifecycle vocabulary, not a renderer-created owner.
export type { SavedConfigContent } from './offlinePreflightTypes.ts';
import type { SavedConfigContent, OfflinePreflightAvailability, OfflinePreflightPhase,
  OfflinePreflightOutcome, OfflinePreflightReason } from './offlinePreflightTypes.ts';
export interface ArtifactInspectionIdentity { operationId:string; ownerGeneration:string }
export interface PrepareArtifactInspection {
  projectId:string;draftRevision:number;baselineGeneration:number;savedConfig:SavedConfigContent;
  format:ArtifactFormat;selections:{artifact:string;archive:string|null;dsyms:string|null};
}
export type ArtifactInspectionContext = PrepareArtifactInspection;
export interface PickArtifactInspection {projectId:string;format:ArtifactFormat;role:ArtifactRole}
export interface StartArtifactInspection extends ArtifactInspectionIdentity {consentVersion:'selected-artifact-inspection-v1'}
export interface DiscardArtifactInspection {selectionGeneration:number;operationId:string|null;ownerGeneration:string|null}
export type ArtifactInspectionReason = OfflinePreflightReason | 'saved-version-missing'|'saved-version-invalid'|'saved-version-changed'|
  'saved-version-unsafe'|'saved-version-too-large'|'selection-missing'|'selection-changed'|'selection-unsafe'|
  'toolchain-unavailable'|'toolchain-mismatch'|'resources-unavailable';
export interface ArtifactInspectionSelection {
  generation:number;projectId:string|null;format:ArtifactFormat|null;
  phase:'idle'|'picking'|'ready'|'stopping'|'unknown';
  reason:'none'|'cancelled'|'context-changed'|'document-lost'|'shutdown'|'source-refused'|'source-changed'|'unsupported-format'|'input-limit'|'cleanup-unknown';
  operation:null|{operationId:number;role:ArtifactRole};
  items:{selectionId:string;role:ArtifactRole;label:string;kind:ArtifactKind}[];
}
export interface ArtifactInspectionOperation extends ArtifactInspectionIdentity {
  context:ArtifactInspectionContext;phase:OfflinePreflightPhase;intentUsable:boolean;
  outcome:OfflinePreflightOutcome|null;reason:ArtifactInspectionReason;result:ArtifactInspectionResult|null;
}
export interface ArtifactInspectionStatus {
  schemaVersion:1;statusRevision:number;availability:OfflinePreflightAvailability;
  selection:ArtifactInspectionSelection;operation:ArtifactInspectionOperation|null;
}
export interface ArtifactInspectionApi {
  pickArtifactInspection(request:PickArtifactInspection):Promise<ArtifactInspectionStatus>;
  prepareArtifactInspection(request:PrepareArtifactInspection):Promise<ArtifactInspectionStatus>;
  startArtifactInspection(request:StartArtifactInspection):Promise<ArtifactInspectionStatus>;
  cancelArtifactInspection(operationId:string,ownerGeneration:string):Promise<ArtifactInspectionStatus>;
  artifactInspectionStatus():Promise<ArtifactInspectionStatus>;
  discardArtifactInspection(request:DiscardArtifactInspection):Promise<ArtifactInspectionStatus>;
  subscribeArtifactInspection(onStatus:(status:unknown)=>void):Promise<()=>void>;
}
