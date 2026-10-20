// Public comparison/status DATA. Native owns the selected P8, issuer-wide
// journal, consent, single provider write and every original cleanup join.
import type { AppleDistributionCertificateMode, AppleDistributionCertificateResult, AppleCertificateRecoveryHistory } from './appleDistributionCertificateSetupProtocol.ts';
import type { AppleP12Mode, AppleP12Result } from './appleP12SetupProtocol.ts';
import type { AppleProfileRecoveryHistory } from './appleProfileRecoverySelection.ts';
import type { AndroidBuildSavedVersion } from './androidBuildTypes.ts';
import type { SavedConfigContent, OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome } from './offlinePreflightTypes.ts';

import type { AppleDistributionKeyMode, AppleDistributionKeyResult, AppleDistributionKeySavedReference } from './appleDistributionKeySetupProtocol.ts';
import type { AppleProfileMode, AppleProfileSetupResult, AppleProfileSavedReference } from './appleProfileSetup.ts';
export type AppleProvisioningMode = 'review' | 'register' | 'reconcile' | AppleProfileMode | AppleDistributionKeyMode | AppleDistributionCertificateMode | AppleP12Mode;
export interface AppleProvisioningIdentity { operationId: string; ownerGeneration: string }
export interface PrepareAppleProvisioning {
  projectId: string; draftRevision: number; baselineGeneration: number;
  savedConfig: SavedConfigContent; savedVersion: AndroidBuildSavedVersion;
  credentialContextRevision: number; recordId: string; recordRevision: number;
  executionMode: 'local'; platform: 'ios'; mode: AppleProvisioningMode;
  reference: AppleProvisioningIdentity | null; newApplication: boolean; displayName: string;
  p12RecordId?: string | null; p12RecordRevision?: number | null;
  keyRecordId?: string; keyRecordRevision?: number;
}
export interface AppleProvisioningContext extends PrepareAppleProvisioning { operation: 'apple-bundle-provisioning' }
export type AppleProvisioningConsent = 'local-ios-bundle-review-v1' | 'local-ios-bundle-register-v1' | 'local-ios-bundle-reconcile-v1' | 'local-ios-profile-review-v1' | 'local-ios-profile-reuse-v1' | 'local-ios-profile-create-v1' | 'local-ios-profile-reconcile-v1' | 'local-ios-key-review-v1' | 'local-ios-key-prepare-v1' | 'local-ios-certificate-review-v1' | 'local-ios-certificate-create-v1' | 'local-ios-certificate-reconcile-v1' | 'local-ios-p12-review-v1' | 'local-ios-p12-reuse-v1' | 'local-ios-p12-save-v1';
export interface StartAppleProvisioning extends AppleProvisioningIdentity { consentVersion: AppleProvisioningConsent }
export type AppleProvisioningReason = 'none' | 'cancelled' | 'context-changed' | 'document-lost' | 'shutdown' | 'timed-out' |
  'protocol-error' | 'runtime-unavailable' | 'intent-expired' | 'stale-intent' | 'saved-source-changed' | 'saved-source-invalid' |
  'credentials-unavailable' | 'query-prerequisites' | 'command-incomplete' | 'cleanup-unknown' | 'journal-unavailable' |
  'review-expired' | 'registration-blocked';
export type AppleBundleObservation = 'found' | 'not-returned' | 'not-permitted' | 'inconclusive' | 'not-checked';
export type AppleBundleDecision = 'reuse' | 'review-required' | 'blocked' | 'registration-unconfirmed' | 'registration-confirmed' | 'comparison-only';
export type AppleBundleComparison = 'same-response' | 'different-response' | 'unattributed' | 'not-returned' | 'inconclusive';
export type AppleAttemptStatus = 'running' | 'cancellation_requested' | 'succeeded' | 'failed' | 'cancelled' | 'recovery_required' | 'unknown';
export type AppleAttemptReason = 'readback_required' | 'journal_settlement_required' | 'authorization_changed' | 'cancelled_before_send' |
  'provider_outcome_unknown' | 'original_transport_unsettled' | 'authorization_changed_after_send' | 'provider_rejected_request' |
  'provider_result_requires_reconciliation' | 'reconciliation_read_unavailable' | 'reconciliation_context_changed' |
  'resource_validation_required' | 'provider_outcome_still_unknown' | 'ambiguous_recovery_resources' | 'resource_found_review_required' |
  'response_readback_disagrees' | 'provider_resource_confirmed' | 'cancelled_after_settlement';
export interface AppleAttemptSummary {
  operationId: string; action: 'register_bundle_id'; status: AppleAttemptStatus; reason: AppleAttemptReason;
  retryAllowed: false; credentialReady: false; cancellationRequested: boolean;
}
export interface AppleProvisioningResult {
  schemaVersion: 1; scope: 'local-ios-bundle-provisioning'; mode: AppleProvisioningMode;
  observation: AppleBundleObservation; decision: AppleBundleDecision; attempt: AppleAttemptSummary | null;
  comparison: AppleBundleComparison | null; limitations: readonly string[];
}
// Local historical records only, not an adopted operation or current account
// disposition. Readback does not change any recorded settlement below.
export interface AppleRecoveryAttempt {
  reference: AppleProvisioningIdentity; displayName: string; observedAt: string;
  status: AppleAttemptStatus; reason: AppleAttemptReason;
  nativeSettlement: 'pending' | 'known' | 'unknown'; cancellationRequested: boolean;
}
export interface AppleRecoveryHistory {
  schemaVersion: 1; scope: 'local-ios-bundle-attempts';
  attempts: readonly AppleRecoveryAttempt[]; hiddenUnresolved: number;
}
export interface AppleProvisioningOperation extends AppleProvisioningIdentity {
  context: AppleProvisioningContext; phase: OfflinePreflightPhase; intentUsable: boolean;
  outcome: OfflinePreflightOutcome | null; reason: AppleProvisioningReason; result: AppleProvisioningResult | AppleProfileSetupResult | AppleDistributionKeyResult | AppleDistributionCertificateResult | AppleP12Result | null;
  savedProfile?: AppleProfileSavedReference;
  savedKey?: AppleDistributionKeySavedReference;
  savedP12?: AppleProfileSavedReference;
  profileRecovery?: AppleProfileRecoveryHistory;
  certificateRecovery?: AppleCertificateRecoveryHistory;
  recovery: AppleRecoveryHistory | null;
}
export interface AppleProvisioningStatus {
  schemaVersion: 1; statusRevision: number; availability: OfflinePreflightAvailability;
  operation: AppleProvisioningOperation | null;
}
