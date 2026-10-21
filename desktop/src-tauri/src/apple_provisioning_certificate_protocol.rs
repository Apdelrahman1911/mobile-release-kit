//! Closed certificate phases on the existing Apple request/reader. All values
//! here are DATA. Only the same native loan, command/IO joins and original
//! journal jobs can grant a reply or mint a volatile certificate binding.
use super::*;
use crate::{
    apple_provisioning_journal::{certificate_phase_sha256, profile_entitlements_sha256,
        profile_unix_micros, CertificateAttemptRecord, CertificateCreationReceipt,
        CertificateIssuanceIntent, CertificateJournalAck, CertificateUpdate, ProfileBundle,
        ProfileTarget},
    credential_setup::KeyReference,
};

pub(crate) const CERTIFICATE_EVENTS: u32 = 12;
pub(crate) const CERTIFICATE_IDENTITY_LIMIT: usize = 256 * 1024;
pub(crate) const CERTIFICATE_IDENTITIES_LIMIT: usize = 512 * 1024;
pub(crate) const CERTIFICATE_JSON_LIMIT: usize = 768 * 1024;
pub(crate) const CERTIFICATE_BATCH_DER: usize = 128 * 1024;
pub(crate) const CERTIFICATE_ROOT: &str = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024";
pub(crate) const CERTIFICATE_INTERMEDIATE: &str = "dcf21878c77f4198e4b4614f03d696d89c66c66008d4244e1b99161aac91601f";

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateChoice {
    pub(crate) bundle: ProfileBundle,
    pub(crate) before_sha256: String,
    pub(crate) plan_sha256: String,
    pub(crate) csr_sha256: String,
    pub(crate) public_key_sha256: String,
}
impl CertificateChoice {
    fn valid(&self, target: &BundleTarget) -> bool {
        resource_id(&self.bundle.resource_id) && self.bundle.identifier == target.bundle_id
            && matches!(self.bundle.platform.as_str(), "IOS" | "UNIVERSAL")
            && self.bundle.seed_id == target.app_id_prefix && sha(&self.before_sha256)
            && sha(&self.plan_sha256) && sha(&self.csr_sha256) && sha(&self.public_key_sha256)
    }
    pub(crate) fn same_assets(&self, other: &Self) -> bool {
        self.bundle == other.bundle && self.csr_sha256 == other.csr_sha256
            && self.public_key_sha256 == other.public_key_sha256
    }
}
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateReviewData {
    pub(crate) reference: Reference,
    pub(crate) observed_at: String,
    pub(crate) valid_until: String,
    pub(crate) selection: CertificateChoice,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateKeyPreparation {
    pub(crate) reference: Reference,
    pub(crate) source_key: KeyReference,
    pub(crate) account_ref: crate::apple_provisioning_journal::AccountRef,
    pub(crate) team_id: String,
    pub(crate) csr_sha256: String,
    pub(crate) public_key_sha256: String,
    pub(crate) update_sha256: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificatePriorData {
    pub(crate) reference: Reference,
    pub(crate) source_key: KeyReference,
    pub(crate) target: ProfileTarget,
    pub(crate) csr_sha256: String,
    pub(crate) public_key_sha256: String,
    pub(crate) record: CertificateAttemptRecord,
    pub(crate) receipt: Option<CertificateCreationReceipt>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificateScopeData {
    pub(crate) source_p8: KeyReference,
    pub(crate) source_key: KeyReference,
    pub(crate) entitlements: Value,
    pub(crate) key_preparation: Option<CertificateKeyPreparation>,
    pub(crate) review: Option<CertificateReviewData>,
    pub(crate) prior: Option<CertificatePriorData>,
}
fn interval(before: &str, after: &str) -> bool {
    profile_unix_micros(before).zip(profile_unix_micros(after))
        .is_some_and(|(before, after)| after.checked_sub(before) == Some(300_000_000))
}
impl CertificateScopeData {
    pub(crate) fn target(&self, base: &BundleTarget) -> Result<ProfileTarget, BridgeError> {
        Ok(ProfileTarget { bundle_id: base.bundle_id.clone(), team_id: base.team_id.clone(),
            app_id_prefix: base.app_id_prefix.clone(), display_name: base.display_name.clone(),
            existing_application: base.existing_application,
            entitlements_sha256: profile_entitlements_sha256(&self.entitlements).map_err(|_| invalid())? })
    }
    pub(super) fn valid(&self, context: &Context, scope: &ScopeData) -> bool {
        let Ok(target) = self.target(&scope.target) else { return false; };
        if !(context.mode.certificate() || context.mode.p12()) || self.source_key.validate().is_err() || self.source_p8.validate().is_err()
            || context.key_record_id.as_deref() != Some(&self.source_key.record_id)
            || context.key_record_revision != Some(self.source_key.revision_counter)
            || self.source_p8.record_id != context.record_id || self.source_p8.revision_counter != context.record_revision
            || self.source_key.vault_id != self.source_p8.vault_id || self.source_key.generation_id != self.source_p8.generation_id
            || self.source_key.record_id == self.source_p8.record_id || target.team_id != target.app_id_prefix {
            return false;
        }
        if context.mode.p12() {
            return self.key_preparation.is_none() && self.review.is_none() && self.prior.is_none();
        }
        if let Some(key) = &self.key_preparation {
            if !key.reference.valid() || key.source_key != self.source_key || key.account_ref != scope.provisioning.account_ref
                || key.team_id != target.team_id || !sha(&key.csr_sha256) || !sha(&key.public_key_sha256) || !sha(&key.update_sha256) { return false; }
        }
        if context.mode == Mode::CertificateCreate {
            let (Some(review), Some(key)) = (&self.review, &self.key_preparation) else { return false; };
            if context.reference.as_ref() != Some(&review.reference) || scope.reviewed_at.as_ref() != Some(&review.observed_at)
                || !interval(&review.observed_at, &review.valid_until) || !review.selection.valid(&scope.target)
                || review.selection.csr_sha256 != key.csr_sha256 || review.selection.public_key_sha256 != key.public_key_sha256 { return false; }
        } else if self.review.is_some() || scope.reviewed_at.is_some() { return false; }
        match (&self.prior, context.mode) {
            // The prior keeps its original full reference after a NEW-only
            // backup restore. This is read-only selection DATA, not a current
            // loan: key_ack must compare both old hashes before any GET.
            (Some(prior), Mode::CertificateReconcile) => prior.source_key.validate().is_ok() && prior.target == target
                && context.reference.as_ref() == Some(&prior.reference) && sha(&prior.csr_sha256) && sha(&prior.public_key_sha256)
                && prior.record.context.account_ref == scope.provisioning.account_ref
                && prior.record.context.operation_id == prior.reference.operation_id
                && receipt_matches(&prior.receipt, &prior.record),
            (None, mode) => mode != Mode::CertificateReconcile,
            _ => false,
        }
    }
    /// Comparison only, called after the actual current loan/public-key check.
    /// No other mode may carry a prior, and no changed-ref history grants POST.
    pub(crate) fn prior_key_matches(&self, mode: Mode, csr: &str, spki: &str) -> bool {
        match (&self.prior, mode) {
            (Some(prior), Mode::CertificateReconcile) => sha(csr) && sha(spki)
                && prior.csr_sha256 == csr && prior.public_key_sha256 == spki,
            (None, mode) => mode != Mode::CertificateReconcile,
            _ => false,
        }
    }
}
fn receipt_matches(receipt: &Option<CertificateCreationReceipt>, record: &CertificateAttemptRecord) -> bool {
    match receipt {
        None => record.response_resource_id.is_none() && record.response_resource_sha256.is_none(),
        Some(receipt) => record.response_resource_id.as_ref() == Some(&receipt.resource_id)
            && receipt.sha256().is_ok_and(|hash| record.response_resource_sha256.as_ref() == Some(&hash)),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeyInput {
    source_key: KeyReference, csr_pem: String, public_key_spki_der: String,
    csr_sha256: String, public_key_sha256: String,
}
pub(crate) struct CertificateKeyInput {
    pub(crate) csr: String, pub(crate) spki: Vec<u8>, pub(crate) csr_sha256: String,
    pub(crate) public_key_sha256: String, pub(crate) payload_sha256: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Candidate {
    resource_id: String, certificate_type: String, platform: String, expires_at: String, certificate_der: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Identities {
    batch: u32, source_key: KeyReference, public_key_sha256: String, certificates: Vec<Candidate>,
}
pub(crate) struct CertificateCandidateInput {
    pub(crate) resource_id: String, pub(crate) certificate_type: String,
    pub(crate) expires_at: u64, pub(crate) der: Vec<u8>,
}
pub(crate) struct CertificateIdentityInput {
    pub(crate) batch: u32, pub(crate) payload_sha256: String,
    pub(crate) certificates: Vec<CertificateCandidateInput>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificatePolicyInput {
    schema_version: u32, scope: String,
    pub(crate) request_binding_sha256: String, pub(crate) identity_ack_sha256: String,
    pub(crate) certificate_sha256: String, pub(crate) public_key_sha256: String,
    pub(crate) team_id: String, pub(crate) checked_at: String, chain_sha256: Vec<String>, revocation_checked: bool,
}
impl CertificatePolicyInput {
    fn valid(&self, binding: &RequestBinding) -> bool {
        self.schema_version == 1 && self.scope == "offline-apple-distribution-certificate" && !self.revocation_checked
            && self.request_binding_sha256 == binding.sha256 && sha(&self.identity_ack_sha256)
            && sha(&self.certificate_sha256) && sha(&self.public_key_sha256)
            && self.team_id == binding.scope.target.team_id && profile_unix_micros(&self.checked_at).is_some()
            && self.chain_sha256 == [self.certificate_sha256.as_str(), CERTIFICATE_INTERMEDIATE, CERTIFICATE_ROOT]
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateObserved {
    pub(crate) observed_at: String, pub(crate) valid_until: String, pub(crate) before_sha256: String,
    pub(crate) decision: String, pub(crate) reason: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) selection: Option<CertificateChoice>,
}
pub(crate) enum CertificateEvent {
    Key(CertificateKeyInput), Identities(CertificateIdentityInput),
    Policy { input: CertificatePolicyInput, payload_sha256: String }, Observed(CertificateObserved),
    Pending { intent: CertificateIssuanceIntent, update: CertificateUpdate }, Attempt(CertificateUpdate),
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Pending {
    observed_at: String, valid_until: String, selection: CertificateChoice,
    request_body_sha256: String, update: CertificateUpdate,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Updated { update: CertificateUpdate }

fn pair(mode: Mode, decision: &str, reason: &str) -> bool {
    let allowed = match mode {
        Mode::CertificateReview => matches!(decision, "reuse" | "request-review" | "blocked"),
        Mode::CertificateCreate => matches!(decision, "reuse" | "blocked" | "request-confirmed" | "request-unconfirmed"),
        Mode::CertificateReconcile => decision == "comparison-only", _ => false,
    };
    allowed && match decision {
        "reuse" => reason == "existing-certificate", "request-review" => reason == "certificate-required",
        "blocked" => matches!(reason, "account-pending" | "inventory-unavailable" | "key-history-unavailable" |
            "policy-unavailable" | "existing-certificate-needs-key" | "bundle-registration-required"),
        "request-unconfirmed" => matches!(reason, "provider-outcome-unconfirmed" | "provider-rejected"),
        "request-confirmed" => reason == "certificate-confirmed", "comparison-only" => reason == "comparison-only", _ => false,
    }
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateAttemptSummary {
    operation_id: String, action: crate::apple_provisioning_journal::CertificateCreateAction,
    status: AttemptStatus, reason: AttemptReason, retry_allowed: bool, credential_ready: bool, cancellation_requested: bool,
}
impl CertificateAttemptSummary {
    fn matches(&self, record: &CertificateAttemptRecord) -> bool {
        self.operation_id == record.context.operation_id && self.action == record.action
            && self.status == record.status && self.reason == record.reason && !self.retry_allowed && !self.credential_ready
            && self.cancellation_requested == record.cancel_requested
    }
}
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CertificateResult {
    schema_version: u32, scope: String, mode: Mode, pub(crate) decision: String, pub(crate) reason: String,
    #[serde(deserialize_with = "required_option")]
    pub(crate) certificate_id: Option<String>,
    #[serde(deserialize_with = "required_option")]
    attempt: Option<CertificateAttemptSummary>,
    #[serde(deserialize_with = "required_option")]
    comparison: Option<Comparison>,
    p12_saved: bool, profile_saved: bool, credential_ready: bool, revocation_checked: bool,
}
impl CertificateResult {
    pub(crate) fn positive_identity(&self) -> bool {
        self.certificate_id.is_some()
            && (matches!(self.decision.as_str(), "reuse" | "request-confirmed")
                || self.decision == "comparison-only"
                    && matches!(self.comparison, Some(Comparison::SameResponse | Comparison::DifferentResponse | Comparison::Unattributed)))
    }
}

#[derive(Default)]
pub(super) struct CertificateDecoder {
    key: Option<(String, String)>, batches: u32, identity_bytes: usize,
    policy: Option<CertificatePolicyInput>, observed: Option<CertificateObserved>,
    intent: Option<CertificateIssuanceIntent>, update: Option<CertificateUpdate>,
}
impl CertificateDecoder {
    pub(super) fn event(&mut self, binding: &RequestBinding, sequence: u32, kind: &str, value: Value)
        -> Result<CertificateEvent, BridgeError> {
        need((binding.context.mode.certificate() || binding.context.mode.p12() && matches!(kind,"certificate-key"|"certificate-identities"|"certificate-policy")) && sequence > 0 && sequence <= binding.context.mode.events())?;
        let scope = binding.scope.certificate.as_ref().ok_or_else(invalid)?;
        let digest = certificate_phase_sha256(&value).map_err(|_| invalid())?;
        match kind {
            "certificate-key" => {
                need(sequence == 1 && self.key.is_none())?;
                let value = KeyInput::deserialize(value).map_err(|_| invalid())?;
                need(value.source_key == scope.source_key && value.csr_pem.is_ascii() && value.csr_pem.len() <= 4096
                    && value.csr_pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n")
                    && value.csr_pem.ends_with("-----END CERTIFICATE REQUEST-----\n")
                    && hex(&Sha256::digest(value.csr_pem.as_bytes())) == value.csr_sha256)?;
                let spki = profile::unbase64(&value.public_key_spki_der, 1024)?;
                need(hex(&Sha256::digest(&spki)) == value.public_key_sha256)?;
                self.key = Some((value.csr_sha256.clone(), value.public_key_sha256.clone()));
                Ok(CertificateEvent::Key(CertificateKeyInput { csr: value.csr_pem, spki,
                    csr_sha256: value.csr_sha256, public_key_sha256: value.public_key_sha256, payload_sha256: digest }))
            }
            "certificate-identities" => {
                let (_, public_key) = self.key.as_ref().ok_or_else(invalid)?;
                self.identity_bytes = self.identity_bytes.checked_add(bounded(&value, CERTIFICATE_IDENTITY_LIMIT).map_err(|_| invalid())?.len()).ok_or_else(invalid)?;
                need(self.identity_bytes <= CERTIFICATE_IDENTITIES_LIMIT && self.batches < 2)?;
                let value = Identities::deserialize(value).map_err(|_| invalid())?;
                need(value.batch == self.batches + 1 && value.source_key == scope.source_key && value.public_key_sha256 == *public_key
                    && value.certificates.len() <= 32 && (value.batch == 1 || binding.context.mode == Mode::CertificateCreate
                        && self.update.as_ref().is_some_and(|update| update.sequence == 2 && update.receipt.is_some())))?;
                let mut seen = std::collections::BTreeSet::new();
                let mut total = 0usize;
                let mut certificates = Vec::new();
                certificates.try_reserve_exact(value.certificates.len()).map_err(|_| invalid())?;
                for row in value.certificates {
                    need(resource_id(&row.resource_id) && seen.insert(row.resource_id.clone())
                        && matches!(row.certificate_type.as_str(), "DISTRIBUTION" | "IOS_DISTRIBUTION")
                        && matches!(row.platform.as_str(), "IOS" | "UNIVERSAL"))?;
                    let time = profile_unix_micros(&row.expires_at).ok_or_else(invalid)?;
                    need(time % 1_000_000 == 0)?;
                    let der = profile::unbase64(&row.certificate_der, 64 * 1024)?;
                    total = total.checked_add(der.len()).ok_or_else(invalid)?;
                    need(total <= CERTIFICATE_BATCH_DER)?;
                    certificates.push(CertificateCandidateInput { resource_id: row.resource_id,
                        certificate_type: row.certificate_type, expires_at: time / 1_000_000, der });
                }
                self.batches = value.batch;
                Ok(CertificateEvent::Identities(CertificateIdentityInput { batch: value.batch, payload_sha256: digest, certificates }))
            }
            "certificate-policy" => {
                let (_, public_key) = self.key.as_ref().ok_or_else(invalid)?;
                need(self.batches > 0 && self.policy.is_none())?;
                let input = CertificatePolicyInput::deserialize(value).map_err(|_| invalid())?;
                need(input.valid(binding) && input.public_key_sha256 == *public_key)?;
                self.policy = Some(input.clone());
                Ok(CertificateEvent::Policy { input, payload_sha256: digest })
            }
            "certificate-observed" => {
                need(binding.context.mode == Mode::CertificateReview && self.key.is_some() && self.observed.is_none())?;
                let value = CertificateObserved::deserialize(value).map_err(|_| invalid())?;
                need(interval(&value.observed_at, &value.valid_until) && sha(&value.before_sha256)
                    && pair(binding.context.mode, &value.decision, &value.reason))?;
                if value.decision == "request-review" {
                    let choice = value.selection.as_ref().ok_or_else(invalid)?;
                    need(choice.valid(&binding.scope.target) && choice.before_sha256 == value.before_sha256
                        && self.key.as_ref() == Some(&(choice.csr_sha256.clone(), choice.public_key_sha256.clone()))
                        && self.batches == 1 && self.policy.is_none() && scope.key_preparation.is_some())?;
                } else { need(value.selection.is_none())?; }
                self.observed = Some(value.clone());
                Ok(CertificateEvent::Observed(value))
            }
            "certificate-pending" => {
                need(binding.context.mode == Mode::CertificateCreate && self.intent.is_none() && self.update.is_none()
                    && self.batches == 1 && self.policy.is_none())?;
                let value = Pending::deserialize(value).map_err(|_| invalid())?;
                let review = scope.review.as_ref().ok_or_else(invalid)?;
                need(value.selection.valid(&binding.scope.target) && value.selection.same_assets(&review.selection)
                    && self.key.as_ref() == Some(&(value.selection.csr_sha256.clone(), value.selection.public_key_sha256.clone()))
                    && value.update.sequence == 1 && value.update.receipt.is_none()
                    && value.update.record.status == AttemptStatus::Running && value.update.record.reason == AttemptReason::ReadbackRequired
                    && value.update.record.possible_send && !value.update.record.cancel_requested
                    && value.update.record.observed_resource_id.is_none())?;
                let intent = CertificateIssuanceIntent { context: binding.scope.provisioning.clone(),
                    provenance: binding.scope.provenance.clone(), target: scope.target(&binding.scope.target)?,
                    source_key: scope.source_key.clone(), source_p8: scope.source_p8.clone(), bundle: value.selection.bundle,
                    csr_sha256: value.selection.csr_sha256, public_key_sha256: value.selection.public_key_sha256,
                    observed_at: value.observed_at, valid_until: value.valid_until,
                    before_sha256: value.selection.before_sha256, plan_sha256: value.selection.plan_sha256,
                    request_body_sha256: value.request_body_sha256 };
                intent.validate().map_err(|_| invalid())?;
                value.update.validate(&intent).map_err(|_| invalid())?;
                self.intent = Some(intent.clone()); self.update = Some(value.update.clone());
                Ok(CertificateEvent::Pending { intent, update: value.update })
            }
            "certificate-attempt" => {
                let intent = self.intent.as_ref().ok_or_else(invalid)?;
                let old = self.update.as_ref().ok_or_else(invalid)?;
                let update = Updated::deserialize(value).map_err(|_| invalid())?.update;
                need(binding.context.mode == Mode::CertificateCreate && update.sequence <= 3 && update.sequence == old.sequence + 1
                    && old.receipt.as_ref().is_none_or(|receipt| update.receipt.as_ref() == Some(receipt))
                    && (!old.record.cancel_requested || update.record.cancel_requested))?;
                update.validate(intent).map_err(|_| invalid())?;
                self.update = Some(update.clone());
                Ok(CertificateEvent::Attempt(update)) // Original durable journal independently enforces full transitions.
            }
            _ => Err(invalid()),
        }
    }
    pub(super) fn valid_terminal(&self, value: &CertificateResult, binding: &RequestBinding) -> bool {
        if value.schema_version != 1 || value.scope != "local-ios-distribution-certificate" || value.mode != binding.context.mode
            || !pair(value.mode, &value.decision, &value.reason) || self.key.is_none()
            || value.p12_saved || value.profile_saved || value.credential_ready || value.revocation_checked
            || value.certificate_id.as_ref().is_some_and(|id| !resource_id(id))
            || bounded(value, 4096).is_err() { return false; }
        let Some(scope) = &binding.scope.certificate else { return false; };
        if value.mode == Mode::CertificateReview {
            let Some(observed) = &self.observed else { return false; };
            if value.decision != observed.decision || value.reason != observed.reason { return false; }
        }
        let needed = matches!(value.decision.as_str(), "request-confirmed" | "request-unconfirmed" | "comparison-only");
        if value.attempt.is_some() != needed { return false; }
        if let Some(summary) = &value.attempt {
            let record = if value.mode == Mode::CertificateReconcile {
                scope.prior.as_ref().map(|prior| &prior.record)
            } else { self.update.as_ref().map(|update| &update.record) };
            if record.is_none_or(|record| !summary.matches(record)) { return false; }
            if value.decision == "request-confirmed" && (summary.status != AttemptStatus::Succeeded
                || summary.reason != AttemptReason::ProviderResourceConfirmed || summary.cancellation_requested) { return false; }
            if value.decision == "request-unconfirmed" && (summary.status == AttemptStatus::Succeeded
                || value.reason == "provider-rejected" && (summary.status != AttemptStatus::Failed
                    || summary.reason != AttemptReason::ProviderRejectedRequest)) { return false; }
        }
        if value.mode == Mode::CertificateReconcile {
            return match value.comparison {
                Some(Comparison::SameResponse | Comparison::DifferentResponse | Comparison::Unattributed) => value.certificate_id.is_some() && self.policy.is_some(),
                Some(Comparison::NotReturned | Comparison::Inconclusive) => value.certificate_id.is_none(), None => false,
            };
        }
        if value.comparison.is_some() { return false; }
        match value.decision.as_str() {
            "reuse" | "request-confirmed" => value.certificate_id.is_some() && self.policy.is_some(),
            "request-review" | "blocked" => value.certificate_id.is_none(),
            "request-unconfirmed" => value.reason != "provider-rejected" || value.certificate_id.is_none(),
            _ => false,
        }
    }
}

pub(crate) fn certificate_reply(binding: &RequestBinding, sequence: u32, kind: &str, payload: Value)
    -> Result<(Vec<u8>, String), BridgeError> {
    let mode = binding.context.mode;
    need(mode.certificate() && (1..=CERTIFICATE_EVENTS).contains(&sequence)
        && matches!(kind, "certificate-key" | "certificate-identities" | "certificate-policy" | "certificate-pending" | "certificate-attempt")
        || mode.p12() && matches!((kind, sequence),
            ("certificate-key", 1) | ("certificate-identities", 2) | ("certificate-policy", 3))
        || mode == Mode::P12Save && matches!((kind, sequence), ("p12-pending", 4) | ("p12-output", 5)))?;
    let value = json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
        "nonce":binding.nonce,"requestSha256":binding.sha256,"kind":format!("{kind}-ack"),"step":sequence,"payload":payload});
    let digest = certificate_phase_sha256(&value).map_err(|_| invalid())?;
    let mut bytes = bounded(&value, ACK_LIMIT - 1).map_err(|_| invalid())?; bytes.push(b'\n');
    Ok((bytes, digest))
}
pub(crate) fn certificate_journal_ack(binding: &RequestBinding, phase: u32, kind: &str,
    ack: &CertificateJournalAck, update: &CertificateUpdate, previous: crate::application_state_store::Revision,
    stopped: bool)
    -> Result<Vec<u8>, BridgeError> {
    need(binding.context.mode == Mode::CertificateCreate && ack.row.update == *update
        && ack.row.intent.context == binding.scope.provisioning && ack.row.intent.provenance == binding.scope.provenance
        && ack.original.intent() == &ack.row.intent && ack.row.send_armed
        && ack.row.native_settlement == crate::apple_provisioning_journal::NativeSettlement::Pending
        && ack.revision.0 == previous.0.checked_add(1).ok_or_else(invalid)?
        && (kind == "certificate-pending") == (update.sequence == 1)
        && (!stopped || kind == "certificate-attempt"))?;
    let mut payload=json!({"revision":ack.revision.0,"sequence":update.sequence,
        "recordSha256":update.sha256().map_err(|_| invalid())?});
    if kind == "certificate-attempt" {
        payload.as_object_mut().ok_or_else(invalid)?.insert("stopped".into(),Value::Bool(stopped));
    }
    Ok(certificate_reply(binding, phase, kind, payload)?.0)
}

#[cfg(test)]
pub(in crate::apple_provisioning_protocol) mod tests {
    use super::*;
    use crate::apple_provisioning_journal::{CertificateCreateAction, NativeSettlement};
    const CSR: &str = "-----BEGIN CERTIFICATE REQUEST-----\nZmFrZQ==\n-----END CERTIFICATE REQUEST-----\n";

    // Reuse original reference-only fixture. Fake CSR/DER and stream summaries
    // are parser DATA, not a native loan, policy result, ACK or joined witness.
    pub(in crate::apple_provisioning_protocol) fn binding(mode: Mode) -> Arc<RequestBinding> {
        let (_, mut scope) = recovery_comparison_fixture();
        scope.provisioning.operation_id = "1".repeat(32);
        scope.provenance.operation_id = Id::parse(&"1".repeat(32)).unwrap();
        scope.provenance.owner_generation = Id::parse(&"5".repeat(32)).unwrap();
        let p8 = KeyReference { vault_id:"1".repeat(32), generation_id:"2".repeat(32),
            record_id:scope.provisioning.credential_record_id.clone(), revision_id:"3".repeat(32), revision_counter:1 };
        let key = KeyReference { record_id:"4".repeat(32),revision_id:"5".repeat(32),..p8.clone() };
        let mut input=json!({"projectId":scope.provisioning.project_id,"draftRevision":1,"baselineGeneration":1,
            "savedConfig":scope.provenance.saved_config,"savedVersion":scope.provenance.saved_version,
            "credentialContextRevision":1,"recordId":p8.record_id,"recordRevision":1,
            "executionMode":"local","platform":"ios","mode":mode,
            "reference":if mode==Mode::CertificateReview || mode==Mode::Review { Value::Null }
                else { json!({"operationId":"8".repeat(32),"ownerGeneration":"9".repeat(32)}) },
            "newApplication":false,"displayName":scope.target.display_name});
        if mode.certificate() {
            input["keyRecordId"]=json!(key.record_id); input["keyRecordRevision"]=json!(1);
            scope.certificate=Some(CertificateScopeData { source_p8:p8,source_key:key.clone(),entitlements:json!({}),
                key_preparation:Some(CertificateKeyPreparation { reference:Reference { operation_id:"6".repeat(32),owner_generation:"7".repeat(32) },
                    source_key:key,account_ref:scope.provisioning.account_ref.clone(),team_id:scope.target.team_id.clone(),
                    csr_sha256:hex(&Sha256::digest(CSR.as_bytes())),public_key_sha256:hex(&Sha256::digest(b"spki")),update_sha256:"a".repeat(64) }),
                review:None,prior:None });
        }
        let context=prepare(&input).unwrap().context;
        let mut result=RequestBinding { operation:"1".repeat(32),generation:"5".repeat(32),context,scope,
            nonce:"6".repeat(32),sha256:"7".repeat(64),revision:crate::application_state_store::Revision(0) };
        if mode==Mode::CertificateCreate {
            let intent=intent(&result);
            result.scope.reviewed_at=Some(intent.observed_at.clone());
            result.scope.certificate.as_mut().unwrap().review=Some(CertificateReviewData {
                reference:result.context.reference.clone().unwrap(),observed_at:intent.observed_at.clone(),
                valid_until:intent.valid_until.clone(),selection:choice(&intent) });
        }
        Arc::new(result)
    }
    pub(in crate::apple_provisioning_protocol) fn intent(binding:&RequestBinding)->CertificateIssuanceIntent {
        let certificate=binding.scope.certificate.as_ref().unwrap();
        let mut intent=CertificateIssuanceIntent { context:binding.scope.provisioning.clone(),provenance:binding.scope.provenance.clone(),
            target:certificate.target(&binding.scope.target).unwrap(),source_key:certificate.source_key.clone(),source_p8:certificate.source_p8.clone(),
            bundle:ProfileBundle { resource_id:"bundle-one".into(),identifier:binding.scope.target.bundle_id.clone(),
                platform:"IOS".into(),seed_id:binding.scope.target.app_id_prefix.clone() },
            csr_sha256:hex(&Sha256::digest(CSR.as_bytes())),public_key_sha256:hex(&Sha256::digest(b"spki")),
            observed_at:"2026-10-20T10:00:00+00:00".into(),valid_until:"2026-10-20T10:05:00+00:00".into(),
            before_sha256:"b".repeat(64),plan_sha256:String::new(),request_body_sha256:"c".repeat(64) };
        intent.plan_sha256=intent.plan_hash().unwrap(); intent.validate().unwrap(); intent
    }
    fn choice(intent:&CertificateIssuanceIntent)->CertificateChoice { CertificateChoice {
        bundle:intent.bundle.clone(),before_sha256:intent.before_sha256.clone(),plan_sha256:intent.plan_sha256.clone(),
        csr_sha256:intent.csr_sha256.clone(),public_key_sha256:intent.public_key_sha256.clone() } }
    pub(in crate::apple_provisioning_protocol) fn row(binding:&RequestBinding)->crate::apple_provisioning_journal::CertificateIssuanceRow {
        let intent=intent(binding);
        let record=CertificateAttemptRecord { context:intent.context.clone(),plan_sha256:intent.plan_sha256.clone(),
            action:CertificateCreateAction::CreateCertificate,status:AttemptStatus::Running,reason:AttemptReason::ReadbackRequired,
            possible_send:true,response_resource_id:None,response_resource_sha256:None,observed_resource_id:None,cancel_requested:false };
        crate::apple_provisioning_journal::CertificateIssuanceRow { intent,send_armed:true,
            update:CertificateUpdate { sequence:1,record,receipt:None },native_settlement:NativeSettlement::Pending }
    }
    fn frame(binding:&RequestBinding,sequence:u32,kind:&str,payload:Value)->Vec<u8> {
        let mut bytes=serde_json::to_vec(&json!({"protocol":PROTOCOL,"operationId":binding.operation,"ownerGeneration":binding.generation,
            "nonce":binding.nonce,"requestSha256":binding.sha256,"sequence":sequence,"kind":kind,"payload":payload})).unwrap();
        bytes.push(b'\n');bytes
    }
    fn key(binding:&RequestBinding)->Value { json!({"sourceKey":binding.scope.certificate.as_ref().unwrap().source_key,
        "csrPem":CSR,"publicKeySpkiDer":"c3BraQ==","csrSha256":hex(&Sha256::digest(CSR.as_bytes())),
        "publicKeySha256":hex(&Sha256::digest(b"spki"))}) }
    fn identities(binding:&RequestBinding,batch:u32,rows:Value)->Value { json!({"batch":batch,
        "sourceKey":binding.scope.certificate.as_ref().unwrap().source_key,"publicKeySha256":hex(&Sha256::digest(b"spki")),"certificates":rows}) }
    fn accepted(decoder:&mut Decoder,binding:&RequestBinding) {
        assert!(matches!(decoder.push(&frame(binding,0,"accepted",json!({"schemaVersion":1,"context":binding.context}))).unwrap(),Frame::Accepted));
    }
    fn begin(decoder:&mut Decoder,binding:&RequestBinding) {
        accepted(decoder,binding); assert!(decoder.push(&frame(binding,1,"certificate-key",key(binding))).is_ok());
    }
    fn pending(row:&crate::apple_provisioning_journal::CertificateIssuanceRow)->Value { json!({
        "observedAt":row.intent.observed_at,"validUntil":row.intent.valid_until,"selection":choice(&row.intent),
        "requestBodySha256":row.intent.request_body_sha256,"update":row.update}) }
    fn result(binding:&RequestBinding,record:&CertificateAttemptRecord)->Value { json!({"schemaVersion":1,
        "scope":"local-ios-distribution-certificate","mode":binding.context.mode,"decision":"request-confirmed","reason":"certificate-confirmed",
        "certificateId":"certificate-one","attempt":{"operationId":record.context.operation_id,"action":"create_certificate",
            "status":record.status,"reason":record.reason,"retryAllowed":false,"credentialReady":false,"cancellationRequested":record.cancel_requested},
        "comparison":null,"p12Saved":false,"profileSaved":false,"credentialReady":false,"revocationChecked":false}) }

    #[test]
    fn certificate_full_stream_retains_sparse_receipt_then_policy_without_native_authority() {
        let binding=binding(Mode::CertificateCreate); let mut decoder=Decoder::new(binding.clone());
        assert!(binding.scope.certificate.as_ref().unwrap().valid(&binding.context,&binding.scope));
        begin(&mut decoder,&binding);
        assert!(decoder.push(&frame(&binding,2,"certificate-identities",identities(&binding,1,json!([])))).is_ok());
        let mut row=row(&binding);
        assert!(decoder.push(&frame(&binding,3,"certificate-pending",pending(&row))).is_ok());
        let receipt=CertificateCreationReceipt { schema_version:1,resource_id:"certificate-one".into(),certificate_type:None,expires_at:None,certificate_sha256:None };
        row.update.sequence=2; row.update.record.status=AttemptStatus::RecoveryRequired;
        row.update.record.response_resource_id=Some(receipt.resource_id.clone());
        row.update.record.response_resource_sha256=Some(receipt.sha256().unwrap());row.update.receipt=Some(receipt);
        assert!(decoder.push(&frame(&binding,4,"certificate-attempt",json!({"update":row.update}))).is_ok());
        assert!(decoder.push(&frame(&binding,5,"certificate-identities",identities(&binding,2,json!([{
            "resourceId":"certificate-one","certificateType":"DISTRIBUTION","platform":"UNIVERSAL",
            "expiresAt":"2027-01-01T00:00:00+00:00","certificateDer":"ZGVy"}])))).is_ok());
        let leaf=hex(&Sha256::digest(b"der"));
        assert!(decoder.push(&frame(&binding,6,"certificate-policy",json!({"schemaVersion":1,"scope":"offline-apple-distribution-certificate",
            "requestBindingSha256":binding.sha256,"identityAckSha256":"d".repeat(64),"certificateSha256":leaf,
            "publicKeySha256":hex(&Sha256::digest(b"spki")),"teamId":binding.scope.target.team_id,
            "checkedAt":"2026-10-20T10:00:01+00:00","chainSha256":[leaf,CERTIFICATE_INTERMEDIATE,CERTIFICATE_ROOT],"revocationChecked":false}))).is_ok());
        row.update.sequence=3;row.update.record.status=AttemptStatus::Succeeded;
        row.update.record.reason=AttemptReason::ProviderResourceConfirmed;row.update.record.observed_resource_id=Some("certificate-one".into());
        assert!(decoder.push(&frame(&binding,7,"certificate-attempt",json!({"update":row.update}))).is_ok());
        let terminal=json!({"schemaVersion":1,"context":binding.context,"outcome":"complete","reason":"none",
            "result":result(&binding,&row.update.record),"lifetime":{"complete":true,"fatal":false,"contained":true,
                "commandDispatched":true,"commands":15,"profileCalls":0,"inputClosed":true,"handlersRestored":true,
                "invocationClosed":true,"stopObserved":"none"}});
        assert!(matches!(decoder.push(&frame(&binding,8,"terminal",terminal.clone())).unwrap(),Frame::Terminal(value) if value.settled()));
        assert!(decoder.settled());
        assert!(decoder.push(&frame(&binding,9,"terminal",terminal)).is_err());
        assert!(!decoder.settled());
    }

    #[test]
    fn certificate_identity_needs_key_once_and_second_batch_needs_original_receipt() {
        let binding=binding(Mode::CertificateCreate);
        let mut decoder=Decoder::new(binding.clone());accepted(&mut decoder,&binding);
        assert!(decoder.push(&frame(&binding,1,"certificate-identities",identities(&binding,1,json!([])))).is_err());
        let mut decoder=Decoder::new(binding.clone());begin(&mut decoder,&binding);
        assert!(decoder.push(&frame(&binding,2,"certificate-key",key(&binding))).is_err());
        let mut decoder=Decoder::new(binding.clone());begin(&mut decoder,&binding);
        assert!(decoder.push(&frame(&binding,2,"certificate-identities",identities(&binding,1,json!([])))).is_ok());
        assert!(decoder.push(&frame(&binding,3,"certificate-identities",identities(&binding,2,json!([])))).is_err());
    }

    #[test]
    fn certificate_identity_caps_duplicates_and_request_binding_are_closed() {
        let binding=binding(Mode::CertificateReview);
        let candidate=json!({"resourceId":"cert","certificateType":"DISTRIBUTION","platform":"IOS",
            "expiresAt":"2027-01-01T00:00:00+00:00","certificateDer":"ZGVy"});
        let huge:Vec<_>=(0..3).map(|i| { let mut value=candidate.clone();value["resourceId"]=json!(format!("cert-{i}"));
            value["certificateDer"]=json!("A".repeat(65536)); value }).collect();
        for rows in [json!([candidate.clone(),candidate.clone()]),json!(vec![candidate.clone();33]),json!(huge)] {
            let mut decoder=Decoder::new(binding.clone());begin(&mut decoder,&binding);
            assert!(decoder.push(&frame(&binding,2,"certificate-identities",identities(&binding,1,rows))).is_err());
        }
        let mut decoder=Decoder::new(binding.clone());accepted(&mut decoder,&binding);
        let mut foreign=key(&binding);foreign["sourceKey"]["revisionId"]=json!("f".repeat(32));
        assert!(decoder.push(&frame(&binding,1,"certificate-key",foreign)).is_err());
        let old=self::binding(Mode::Review);let mut decoder=Decoder::new(old.clone());accepted(&mut decoder,&old);
        assert!(decoder.push(&frame(&old,1,"certificate-key",key(&binding))).is_err());
    }

    #[test]
    fn certificate_public_consent_and_lifetime_cannot_borrow_local_key_or_profile_grammar() {
        let binding=binding(Mode::CertificateCreate);
        let correct=start(&json!({"operationId":binding.operation,"ownerGeneration":binding.generation,"consentVersion":Mode::CertificateCreate.consent()})).unwrap();
        let wrong=start(&json!({"operationId":binding.operation,"ownerGeneration":binding.generation,"consentVersion":Mode::KeyPrepare.consent()})).unwrap();
        assert!(correct.matches_context(&binding.context));assert!(!wrong.matches_context(&binding.context));
        let life:Lifetime=serde_json::from_value(json!({"complete":true,"fatal":false,"contained":true,
            "commandDispatched":true,"commands":15,"profileCalls":1,"inputClosed":true,"handlersRestored":true,
            "invocationClosed":true,"stopObserved":"none"})).unwrap();
        assert!(!life.settled_for(Mode::CertificateCreate));assert!(life.settled_for(Mode::ProfileCreate));
        assert_eq!((Mode::CertificateReview.commands(),Mode::CertificateCreate.commands(),Mode::CertificateReconcile.commands()),(14,21,14));
        assert_eq!((Mode::Register.commands(),Mode::KeyPrepare.commands(),Mode::ProfileCreate.commands()),(9,7,15));
        assert_eq!((Mode::CertificateCreate.events(),Mode::CertificateCreate.response_limit()),(12,768*1024));
    }
}
